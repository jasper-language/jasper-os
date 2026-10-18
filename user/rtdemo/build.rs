//! 构建脚本：指定链接脚本（固定地址、非 PIE 的静态可执行文件，装载器只接受 ET_EXEC）。
//! Build script: selects the linker script for a fixed-address static executable.

use std::path::PathBuf;

fn main() {
    let dir = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap());
    println!("cargo:rerun-if-changed={}", dir.join("link.ld").display());
    println!("cargo:rustc-link-arg-bins=-T{}", dir.join("link.ld").display());
    // 装载地址按目标指令集取私有窗口起点 + 固定偏移（链接脚本以 JSR_IMAGE_BASE 取用）
    let arch = std::env::var("CARGO_CFG_TARGET_ARCH").unwrap_or_default();
    let base = kernel_core::user_layout::image_base(&arch).unwrap_or_else(|| panic!("用户程序尚不支持该指令集：{}", arch));
    println!("cargo:rustc-link-arg-bins=--defsym=JSR_IMAGE_BASE={:#x}", base);
    println!("cargo:rustc-link-arg-bins=--no-pie");
    println!("cargo:rustc-link-arg-bins=-static");
}
