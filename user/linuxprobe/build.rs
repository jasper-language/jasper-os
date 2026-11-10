use std::path::PathBuf;

fn main() {
    let dir = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap());
    let arch = std::env::var("CARGO_CFG_TARGET_ARCH").unwrap_or_default();
    let base = kernel_core::user_layout::image_base(&arch)
        .unwrap_or_else(|| panic!("linuxprobe does not support target architecture {arch}"));
    println!("cargo:rerun-if-changed={}", dir.join("link.ld").display());
    println!("cargo:rustc-link-arg-bins=-T{}", dir.join("link.ld").display());
    println!(
        "cargo:rustc-link-arg-bins=--defsym=JSR_LINUX_IMAGE_BASE={base:#x}"
    );
    println!("cargo:rustc-link-arg-bins=--no-pie");
    println!("cargo:rustc-link-arg-bins=-static");
}
