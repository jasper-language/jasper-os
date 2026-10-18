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

use std::path::{Path, PathBuf};

use jaso::build::{Builder, SegmentIn};
use jaso::{Arch, Image, Stage};

fn rebuild(img: &Image<'_>, arch: Arch, stage: Stage, manifest: &str, drop_export: Option<&str>) -> Vec<u8> {
    Builder {
        arch,
        stage,
        manifest: manifest.as_bytes().to_vec(),
        segments: img.segments().map(|s| SegmentIn { vaddr: s.vaddr, mem_size: s.mem_size, flags: s.flags, data: s.data.to_vec() }).collect(),
        exports: img.exports().filter(|e| Some(e.name) != drop_export).map(|e| (e.name.as_bytes().to_vec(), e.value)).collect(),
        relocs: img.relocs().map(|r| (r.offset, r.addend)).collect(),
    }
    .finish()
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
    println!("cargo:rustc-link-arg-bins=--no-pie");
    println!("cargo:rustc-link-arg-bins=-static");

    let out = PathBuf::from(std::env::var("OUT_DIR").unwrap());
    let manifest = std::fs::read_to_string(root.join("modules/demo/jaso.manifest")).expect("读取模块清单失败");
    let arch = jaso::pack::build_target_arch().unwrap_or_else(|e| panic!("{}", e));
    // 「指令集不符」变体：取一个与本目标不同的指令集
    let other = if arch == Arch::X86_64 { Arch::Aarch64 } else { Arch::X86_64 };
    let good = jaso::pack::build_module(&root, "jaso-demo", &root.join("modules/demo"), &out.join("module-target"), arch)
        .unwrap_or_else(|e| panic!("{}", e));
    let img = Image::parse(&good).expect("打包结果未通过校验");
    let write = |name: &str, bytes: &[u8]| std::fs::write(Path::new(&out).join(name), bytes).expect("写入失败");
    write("demo.jaso", &good);
    write("demo-otherarch.jaso", &rebuild(&img, other, Stage::Runtime, &manifest, None));
    write("demo-boot.jaso", &rebuild(&img, arch, Stage::Boot, &manifest, None));
    // 去掉 jaso_init：导出表与清单的 core.exports 必须一致，所以清单里也一并去掉
    let noinit = manifest.replace("core.exports = jaso_init, ", "core.exports = ");
    assert_ne!(noinit, manifest, "清单中找不到 jaso_init 的导出声明");
    write("demo-noinit.jaso", &rebuild(&img, arch, Stage::Runtime, &noinit, Some("jaso_init")));
    let more = format!("{}core.requires = system.channel.send\n", manifest);
    write("demo-morecaps.jaso", &rebuild(&img, arch, Stage::Runtime, &more, None));
}
