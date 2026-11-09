//! 构建脚本：构建模块 `modules/demo`，用 `jaso::pack` 打包成 `.jaso`，并生成验收用的不合格变体；
//! 同时指定本程序的链接脚本。
//! Build script: builds and packs the demo module (plus deliberately invalid variants) for the acceptance program.
//!
//! 产物（写入 OUT_DIR，由 src/main.rs 以 include_bytes! 内嵌）：
//! * `demo.jaso`：合格的模块（本程序的目标指令集、runtime）
//! * `demo-otherarch.jaso`：同一内容、指令集字段换成另一种指令集（完整性校验正确）⇒ 应因指令集不符被拒
//! * `demo-boot.jaso`：装载阶段为 boot ⇒ 运行时装载器应拒绝
//! * `demo-noinit.jaso`：去掉 `jaso_init` 导出 ⇒ 声明了宿主接口却没有初始化入口，应被拒
//! * `demo-morecaps.jaso`：清单多要求一项能力 ⇒ 未授予时应被拒
//! * `demo-runtime.jaso`：清单要求宿主运行时 `>=9.0` ⇒ 运行时版本不符
//! * `demo-depends.jaso`：清单声明依赖 `jaso-base` ⇒ 依赖未满足
//! * `demo-oldabi.jaso`：平台记录与清单的调用约定为旧的 `c.v0` ⇒ 平台不符（字段 abi）
//!
//! 以上全部以开发用发布者签名（来源检查在其它检查之前，变体须先通过它才能验证各自的拒绝原因）。签名相关的变体：
//! * `demo-unsigned.jaso`：同一内容、不带签名 ⇒ 强制模式拒绝；开发模式放行并留下审计事件
//! * `demo-otherpub.jaso`：清单改称另一个受信发布者，签名仍是开发用发布者的 ⇒ 公钥不符
//! * `demo-resigned.jaso`：另一个发布者把本模块原样重签（仍声称开发用发布者）⇒ 公钥不符
//! * `demo-claimed.jaso`：另一个发布者重签并改称自己 ⇒ 模块名不在其命名空间
//! * `trust-dev.key` / `trust-other.key`：两个发布者的公钥（受信发布者表用）
//!
//! L1 全流程（模块 `modules/l1demo`，同一映像打包为两种）：
//! * `l1-native.jaso`：签名的 Native 模块；`l1-hybrid.jaso`：签名的 Hybrid 模块，带 `jasper.import`，依赖前者
//! * `l1-native-startfail.jaso`：`jaso_start` 指向恒返回 7 的函数 ⇒ 启动失败，不留映射
//! * `l1-hybrid-otherarch` / `-morecaps` / `-range`：平台不符、缺能力、依赖版本不在区间内
//! * `l1-hybrid-bind-*`：绑定缺函数、多函数、能力超出清单、含裸指针

use std::path::{Path, PathBuf};

use jaso::build::{Builder, Signer};
use jaso::{Arch, Jaso, Stage};

/// 验收用的「另一个发布者」：种子公开、只用于验收。
const OTHER_PUBLISHER_SEED: &[u8] = b"jasper-os acceptance: other publisher seed v0";

fn build_container(root: &Path, target_dir: &Path, triple: &str) -> Vec<u8> {
    let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".into());
    let status = std::process::Command::new(cargo)
        .current_dir(root)
        .env_remove("CARGO_ENCODED_RUSTFLAGS")
        .env_remove("RUSTFLAGS")
        .env_remove("CARGO_TARGET_DIR")
        .args(["build", "--release", "--target", triple, "-p", "user-modbox", "--target-dir"])
        .arg(target_dir)
        .status()
        .expect("无法启动 cargo 构建容器程序");
    assert!(status.success(), "容器程序 user-modbox 构建失败");
    let elf = target_dir.join(triple).join("release").join("user-modbox");
    std::fs::read(&elf).unwrap_or_else(|e| panic!("读取 {} 失败：{}", elf.display(), e))
}

/// 由合格模块改出一个变体：指令集、装载阶段（清单的 `core.stage` 随之改写）、清单、去掉一个导出、签名者。
fn rebuild(img: &Jaso<'_>, arch: Arch, stage: Stage, manifest: &str, drop_export: Option<&str>, signer: Option<&Signer>) -> Vec<u8> {
    let mut b = Builder::from_file(img, 0).expect("合格模块至少有一个镜像");
    b.platform.isa = Some(arch);
    b.stage = stage;
    let manifest = manifest.replace("core.stage = runtime", &format!("core.stage = {}", stage.name()));
    b.platform.abi = jaso::Manifest::parse(&manifest).ok().map(|m| m.abi.as_bytes().to_vec());
    b.manifest = manifest.into_bytes();
    b.exports.retain(|(name, _)| Some(name.as_slice()) != drop_export.map(str::as_bytes));
    match signer {
        Some(s) => b.finish_signed(s),
        None => b.finish(),
    }
    .expect("变体自检失败")
}

/// L1 变体：由 Native 文件改写清单、绑定（给了就是 Hybrid）与构建输入，再以 `signer` 签名。
fn l1_variant(native: &[u8], manifest: &str, import: Option<&[u8]>, edit: impl FnOnce(&mut Builder), signer: &Signer) -> Vec<u8> {
    let f = Jaso::parse(native).expect("L1 模块未通过校验");
    let mut b = Builder::from_file(&f, 0).expect("合格模块至少有一个镜像");
    b.manifest = manifest.as_bytes().to_vec();
    edit(&mut b);
    let bytes = b.finish().expect("L1 变体自检失败");
    let bytes = match import {
        // 绑定不一致的变体无法经 to_hybrid（它会拒绝），这里直接写段
        Some(text) => {
            let f = Jaso::parse(&bytes).expect("L1 变体未通过校验");
            let mut b = Builder::from_file(&f, 0).expect("合格模块至少有一个镜像");
            b.kind = jaso::ModuleKind::Hybrid;
            b.extensions.push(jaso::build::ExtensionIn { name: jaso::EXT_JASPER_IMPORT.as_bytes().to_vec(), version: 1, critical: true, content: text.to_vec() });
            b.finish().expect("Hybrid 变体自检失败")
        }
        None => bytes,
    };
    jaso::pack::sign(&bytes, signer).expect("签名失败")
}

/// 打包 L1 验收模块及其变体。
fn l1_modules(root: &Path, out: &Path, arch: Arch, other: Arch, dev: &Signer) {
    let dir = root.join("modules/l1demo");
    let manifest = std::fs::read_to_string(dir.join("jaso.manifest")).expect("读取 L1 模块清单失败");
    let import = std::fs::read(dir.join("jaso.import")).expect("读取 L1 模块绑定失败");
    let packed = jaso::pack::build_module(root, "jaso-l1demo", &dir, &out.join("module-target"), arch).unwrap_or_else(|e| panic!("{}", e));
    let write = |name: &str, bytes: &[u8]| std::fs::write(out.join(name), bytes).expect("写入失败");
    let native = jaso::pack::sign(&packed, dev).expect("签名失败");
    write("l1-native.jaso", &native);
    let hybrid = manifest.replace("core.name = jaso-l1-native", "core.name = jaso-l1-hybrid") + "core.lifecycle = system\ncore.depends = jaso-l1-native@>=0.1,<0.2\n";
    assert_ne!(hybrid, manifest + "core.lifecycle = system\ncore.depends = jaso-l1-native@>=0.1,<0.2\n", "清单中找不到模块名");
    // 正式的 Hybrid 文件走工具链入口（to_hybrid 判定绑定与清单一致）
    let plain = l1_variant(&native, &hybrid, None, |_| {}, dev);
    write("l1-hybrid.jaso", &jaso::pack::sign(&jaso::pack::to_hybrid(&plain, &import).expect("绑定与清单不一致"), dev).expect("签名失败"));
    let start_fails = |b: &mut Builder| {
        let fail = b.exports.iter().find(|(n, _)| n == b"l1_fail").expect("l1_fail").1;
        b.exports.iter_mut().find(|(n, _)| n == b"jaso_start").expect("jaso_start").1 = fail;
    };
    let startfail = std::fs::read_to_string(dir.join("jaso.manifest")).expect("读取 L1 模块清单失败").replace("core.name = jaso-l1-native", "core.name = jaso-l1-startfail");
    write("l1-native-startfail.jaso", &l1_variant(&native, &startfail, None, start_fails, dev));
    let imp = Some(&import[..]);
    write("l1-hybrid-otherarch.jaso", &l1_variant(&native, &hybrid, imp, |b| b.platform.isa = Some(other), dev));
    let more = hybrid.clone() + "core.requires = system.channel.send\n";
    write("l1-hybrid-morecaps.jaso", &l1_variant(&native, &more, imp, |_| {}, dev));
    write("l1-hybrid-range.jaso", &l1_variant(&native, &hybrid.replace(">=0.1,<0.2", ">=9.0"), imp, |_| {}, dev));
    let bad_binding = |name: &str, from: &str, to: &str| {
        let text = String::from_utf8(import.clone()).expect("绑定是 UTF-8");
        let edited = text.replace(from, to);
        assert_ne!(edited, text, "绑定中找不到 {}", from);
        write(name, &l1_variant(&native, &hybrid, Some(edited.as_bytes()), |_| {}, dev));
    };
    bad_binding("l1-hybrid-bind-missing.jaso", "fn l1_fail(): Int32\n", "");
    bad_binding("l1-hybrid-bind-extra.jaso", "fn l1_fail(): Int32\n", "fn l1_fail(): Int32\nfn l1_nope(): Int32\n");
    bad_binding("l1-hybrid-bind-cap.jaso", "cap system.console.write", "cap system.channel.send");
    bad_binding("l1-hybrid-bind-raw.jaso", "fn l1_add(a: UInt64, b: UInt64)", "fn l1_add(a: *u8, b: UInt64)");
}

fn main() {
    let dir = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap());
    println!("cargo:rerun-if-changed={}", dir.join("../../abi/abi-version.txt").display());
    // 原生 ABI 世代由 abi/abi-version.txt 唯一声明；链接脚本把它写成 .note.jasper.abi 章。
    let abi = kernel_core::abi_version::NATIVE;
    println!("cargo:rustc-link-arg-bins=--defsym=JSR_ABI_MAJOR={}", abi.major);
    println!("cargo:rustc-link-arg-bins=--defsym=JSR_ABI_MINOR={}", abi.minor);
    println!("cargo:rustc-link-arg-bins=--defsym=JSR_ABI_PATCH={}", abi.patch);
    let root = dir.join("../..");
    println!("cargo:rerun-if-changed={}", dir.join("link.ld").display());
    println!("cargo:rerun-if-env-changed=JSR_JASO1_MULTI");
    for f in ["modules/demo/src/main.rs", "modules/demo/Cargo.toml", "modules/demo/build.rs", "modules/demo/jaso.manifest", "modules/l1demo/src/main.rs", "modules/l1demo/Cargo.toml", "modules/l1demo/build.rs", "modules/l1demo/jaso.manifest", "modules/l1demo/jaso.import", "jaso/src"] {
        println!("cargo:rerun-if-changed={}", root.join(f).display());
    }
    println!("cargo:rustc-link-arg-bins=-T{}", dir.join("link.ld").display());
    // 装载地址按目标指令集取私有窗口起点 + 固定偏移（链接脚本以 JSR_IMAGE_BASE 取用）
    let arch = std::env::var("CARGO_CFG_TARGET_ARCH").unwrap_or_default();
    let base = kernel_core::user_layout::image_base(&arch).unwrap_or_else(|| panic!("用户程序尚不支持该指令集：{}", arch));
    println!("cargo:rustc-link-arg-bins=--defsym=JSR_IMAGE_BASE={:#x}", base);
    println!("cargo:rustc-link-arg-bins=--no-pie");
    println!("cargo:rustc-link-arg-bins=-static");

    let out = PathBuf::from(std::env::var("OUT_DIR").unwrap());
    let manifest = std::fs::read_to_string(root.join("modules/demo/jaso.manifest")).expect("读取模块清单失败");
    let arch = jaso::pack::build_target_arch().unwrap_or_else(|e| panic!("{}", e));
    // 「指令集不符」变体：取一个与本目标不同的指令集
    let other = if arch == Arch::X86_64 { Arch::Aarch64 } else { Arch::X86_64 };
    let packed = jaso::pack::build_module(&root, "jaso-demo", &root.join("modules/demo"), &out.join("module-target"), arch)
        .unwrap_or_else(|e| panic!("{}", e));
    let dev = jaso::pack::development_signer();
    let other_pub = jaso::pack::signer_from_phrase(OTHER_PUBLISHER_SEED);
    let good = jaso::pack::sign(&packed, &dev).expect("签名失败");
    let img = Jaso::parse(&good).expect("打包结果未通过校验");
    let write = |name: &str, bytes: &[u8]| std::fs::write(Path::new(&out).join(name), bytes).expect("写入失败");
    write("demo.jaso", &good);
    let multi = match std::env::var_os("JSR_JASO1_MULTI") {
        Some(path) => {
            let path = PathBuf::from(path);
            println!("cargo:rerun-if-changed={}", path.display());
            std::fs::read(&path).unwrap_or_else(|e| panic!("读取多架构容器 {} 失败：{}", path.display(), e))
        }
        None => good.clone(),
    };
    write("demo-multi.jaso", &multi);
    write("trust-dev.key", &dev.public_key());
    write("trust-other.key", &other_pub.public_key());
    let d = Some(&dev);
    write("demo-otherarch.jaso", &rebuild(&img, other, Stage::Runtime, &manifest, None, d));
    write("demo-boot.jaso", &rebuild(&img, arch, Stage::Boot, &manifest, None, d));
    // 去掉 jaso_init：导出表与清单的 core.exports 必须一致，所以清单里也一并去掉
    let noinit = manifest.replace("core.exports = jaso_init, ", "core.exports = ");
    assert_ne!(noinit, manifest, "清单中找不到 jaso_init 的导出声明");
    write("demo-noinit.jaso", &rebuild(&img, arch, Stage::Runtime, &noinit, Some("jaso_init"), d));
    let more = format!("{}core.requires = system.channel.send\n", manifest);
    write("demo-morecaps.jaso", &rebuild(&img, arch, Stage::Runtime, &more, None, d));
    write("demo-runtime.jaso", &rebuild(&img, arch, Stage::Runtime, &format!("{}core.runtime = >=9.0\n", manifest), None, d));
    write("demo-depends.jaso", &rebuild(&img, arch, Stage::Runtime, &format!("{}core.depends = jaso-base@>=1.0,<2.0\n", manifest), None, d));
    let old = manifest.replace("core.abi = c.v1", "core.abi = c.v0");
    assert_ne!(old, manifest, "清单中找不到 core.abi = c.v1");
    write("demo-oldabi.jaso", &rebuild(&img, arch, Stage::Runtime, &old, None, d));
    // 签名相关变体
    let dev_name = format!("core.publisher = {}", jaso::trust::DEVELOPMENT_PUBLISHER);
    let claims_other = manifest.replace(&dev_name, "core.publisher = jasper.other");
    assert_ne!(claims_other, manifest, "清单中找不到开发用发布者的声明");
    write("demo-unsigned.jaso", &rebuild(&img, arch, Stage::Runtime, &manifest, None, None));
    write("demo-otherpub.jaso", &rebuild(&img, arch, Stage::Runtime, &claims_other, None, d));
    write("demo-resigned.jaso", &rebuild(&img, arch, Stage::Runtime, &manifest, None, Some(&other_pub)));
    write("demo-claimed.jaso", &rebuild(&img, arch, Stage::Runtime, &claims_other, None, Some(&other_pub)));
    let container = build_container(&root, &out.join("container-target"), jaso::pack::target_triple(arch));
    write("modbox.elf", &container);
    l1_modules(&root, &out, arch, other, &dev);
}
