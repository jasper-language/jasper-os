//! 构建脚本：构建模块 `modules/demo`，用 `jaso::pack` 打包成 `.jaso`，并生成验收用的不合格变体；
//! 同时指定本程序的链接脚本。
//! Build script: builds and packs the demo module (plus deliberately invalid variants) for the acceptance program.
//!
//! 产物（写入 OUT_DIR，由 src/main.rs 以 include_bytes! 内嵌）：
//! * `demo.jaso`：合格的模块（x86_64、runtime）
//! * `demo-aarch64.jaso`：同一内容、指令集字段为 aarch64（完整性校验正确）⇒ 应因指令集不符被拒
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

    // 用独立的 target 目录构建模块，避免与外层构建争用同一目录的锁
    let out = PathBuf::from(std::env::var("OUT_DIR").unwrap());
    let target_dir = out.join("module-target");
    let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".into());
    let status = std::process::Command::new(cargo)
        .current_dir(&root)
        .env_remove("CARGO_ENCODED_RUSTFLAGS")
        .env_remove("RUSTFLAGS")
        .env_remove("CARGO_TARGET_DIR")
        .args(["build", "--release", "--target", "x86_64-unknown-none", "-p", "jaso-demo", "--target-dir"])
        .arg(&target_dir)
        .status()
        .expect("无法启动 cargo 构建模块");
    assert!(status.success(), "模块构建失败");
    let elf = std::fs::read(target_dir.join("x86_64-unknown-none/release/jaso-demo")).expect("找不到模块产物");
    let manifest = std::fs::read_to_string(root.join("modules/demo/jaso.manifest")).expect("读取模块清单失败");

    let good = jaso::pack::from_elf(&elf, &manifest, Arch::X86_64, Stage::Runtime).expect("打包失败");
    let img = Image::parse(&good).expect("打包结果未通过校验");
    let write = |name: &str, bytes: &[u8]| std::fs::write(Path::new(&out).join(name), bytes).expect("写入失败");
    write("demo.jaso", &good);
    write("demo-aarch64.jaso", &rebuild(&img, Arch::Aarch64, Stage::Runtime, &manifest, None));
    write("demo-boot.jaso", &rebuild(&img, Arch::X86_64, Stage::Boot, &manifest, None));
    write("demo-noinit.jaso", &rebuild(&img, Arch::X86_64, Stage::Runtime, &manifest, Some("jaso_init")));
    let more = format!("{}core.requires = system.channel.send\n", manifest);
    write("demo-morecaps.jaso", &rebuild(&img, Arch::X86_64, Stage::Runtime, &more, None));
}
