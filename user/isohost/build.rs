//! 构建脚本：构建并以开发用发布者签名探测模块（modules/probe），构建容器程序（user/modbox），
//! 一并写入 OUT_DIR 供 src/main.rs 内嵌（连同该发布者的公钥）；同时指定本程序的链接脚本。
//! Build script: packs and signs the probe module, builds the container program, and sets the link script.

use std::path::{Path, PathBuf};

/// 用独立的 target 目录构建容器程序（与本程序同一目标三元组），返回其 ELF 字节。
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

fn main() {
    let dir = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap());
    let root = dir.join("../..");
    println!("cargo:rerun-if-changed={}", dir.join("link.ld").display());
    for d in ["modules/support/src/lib.rs", "jaso/src", "user/rt/src", "user/modbox/src/main.rs", "user/modbox/Cargo.toml", "user/modbox/link.ld"] {
        println!("cargo:rerun-if-changed={}", root.join(d).display());
    }
    println!("cargo:rustc-link-arg-bins=-T{}", dir.join("link.ld").display());
    let target_arch = std::env::var("CARGO_CFG_TARGET_ARCH").unwrap_or_default();
    let base = kernel_core::user_layout::image_base(&target_arch).unwrap_or_else(|| panic!("用户程序尚不支持该指令集：{}", target_arch));
    println!("cargo:rustc-link-arg-bins=--defsym=JSR_IMAGE_BASE={:#x}", base);
    println!("cargo:rustc-link-arg-bins=--no-pie");
    println!("cargo:rustc-link-arg-bins=-static");

    let out = PathBuf::from(std::env::var("OUT_DIR").unwrap());
    let arch = jaso::pack::build_target_arch().unwrap_or_else(|e| panic!("{}", e));
    let mdir = root.join("modules/probe");
    for f in ["src/main.rs", "Cargo.toml", "build.rs", "jaso.manifest"] {
        println!("cargo:rerun-if-changed={}", mdir.join(f).display());
    }
    let signer = jaso::pack::development_signer();
    let bytes = jaso::pack::build_module(&root, "jaso-probe", &mdir, &out.join("module-target"), arch).unwrap_or_else(|e| panic!("{}", e));
    let signed = jaso::pack::sign(&bytes, &signer).unwrap_or_else(|e| panic!("签名 jaso-probe 失败：{:?}", e));
    std::fs::write(out.join("probe.jaso"), signed).expect("写入失败");
    std::fs::write(out.join("trust-dev.key"), signer.public_key()).expect("写入失败");
    let container = build_container(&root, &out.join("container-target"), jaso::pack::target_triple(arch));
    std::fs::write(out.join("modbox.elf"), container).expect("写入失败");
}
