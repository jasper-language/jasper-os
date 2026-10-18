//! 构建脚本：指定链接脚本（固定地址、非 PIE 的静态可执行文件，装载器只接受 ET_EXEC）。
//! Build script: selects the linker script for a fixed-address static executable.

use std::path::PathBuf;

fn main() {
    let dir = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap());
    println!("cargo:rerun-if-changed={}", dir.join("link.ld").display());
    println!("cargo:rustc-link-arg-bins=-T{}", dir.join("link.ld").display());
    println!("cargo:rustc-link-arg-bins=--no-pie");
    println!("cargo:rustc-link-arg-bins=-static");
}
