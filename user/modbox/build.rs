//! 构建脚本：指定本程序的链接脚本与装载地址（私有窗口起点 + 固定偏移，按目标指令集）。
//! Build script: link script and image base for the container program.

use std::path::PathBuf;

fn main() {
    let dir = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap());
    println!("cargo:rerun-if-changed={}", dir.join("link.ld").display());
    println!("cargo:rustc-link-arg-bins=-T{}", dir.join("link.ld").display());
    let arch = std::env::var("CARGO_CFG_TARGET_ARCH").unwrap_or_default();
    let base = kernel_core::user_layout::image_base(&arch).unwrap_or_else(|| panic!("用户程序尚不支持该指令集：{}", arch));
    println!("cargo:rustc-link-arg-bins=--defsym=JSR_IMAGE_BASE={:#x}", base);
    println!("cargo:rustc-link-arg-bins=--no-pie");
    println!("cargo:rustc-link-arg-bins=-static");
}
