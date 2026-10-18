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
//!
//! 以上全部以开发用发布者签名（来源检查在其它检查之前，变体须先通过它才能验证各自的拒绝原因）。签名相关的变体：
//! * `demo-unsigned.jaso`：同一内容、不带签名 ⇒ 强制模式拒绝；开发模式放行并留下审计事件
//! * `demo-otherpub.jaso`：清单改称另一个受信发布者，签名仍是开发用发布者的 ⇒ 公钥不符
//! * `demo-resigned.jaso`：另一个发布者把本模块原样重签（仍声称开发用发布者）⇒ 公钥不符
//! * `demo-claimed.jaso`：另一个发布者重签并改称自己 ⇒ 模块名不在其命名空间
//! * `trust-dev.key` / `trust-other.key`：两个发布者的公钥（受信发布者表用）

use std::path::{Path, PathBuf};

use jaso::build::{Builder, Signer};
use jaso::{Arch, Image, Stage};

/// 验收用的「另一个发布者」：种子公开、只用于验收。
const OTHER_PUBLISHER_SEED: &[u8] = b"jasper-os acceptance: other publisher seed v0";

fn rebuild(img: &Image<'_>, arch: Arch, stage: Stage, manifest: &str, drop_export: Option<&str>, signer: Option<&Signer>) -> Vec<u8> {
    let mut b = Builder::from_image(img);
    b.arch = arch;
    b.stage = stage;
    b.manifest = manifest.as_bytes().to_vec();
    b.exports.retain(|(name, _)| Some(name.as_slice()) != drop_export.map(str::as_bytes));
    match signer {
        Some(s) => b.finish_signed(s),
        None => b.finish(),
    }
    .expect("变体自检失败")
}

fn main() {
    let dir = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap());
    let root = dir.join("../..");
    println!("cargo:rerun-if-changed={}", dir.join("link.ld").display());
    for f in ["modules/demo/src/main.rs", "modules/demo/Cargo.toml", "modules/demo/build.rs", "modules/demo/jaso.manifest", "jaso/src"] {
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
    let img = Image::parse(&good).expect("打包结果未通过校验");
    let write = |name: &str, bytes: &[u8]| std::fs::write(Path::new(&out).join(name), bytes).expect("写入失败");
    write("demo.jaso", &good);
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
    // 签名相关变体
    let dev_name = format!("core.publisher = {}", jaso::trust::DEVELOPMENT_PUBLISHER);
    let claims_other = manifest.replace(&dev_name, "core.publisher = jasper.other");
    assert_ne!(claims_other, manifest, "清单中找不到开发用发布者的声明");
    write("demo-unsigned.jaso", &rebuild(&img, arch, Stage::Runtime, &manifest, None, None));
    write("demo-otherpub.jaso", &rebuild(&img, arch, Stage::Runtime, &claims_other, None, d));
    write("demo-resigned.jaso", &rebuild(&img, arch, Stage::Runtime, &manifest, None, Some(&other_pub)));
    write("demo-claimed.jaso", &rebuild(&img, arch, Stage::Runtime, &claims_other, None, Some(&other_pub)));
}
