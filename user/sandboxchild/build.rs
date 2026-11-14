use std::fmt::Write as _;
use std::path::PathBuf;

fn main() {
    let dir = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap());
    println!(
        "cargo:rerun-if-changed={}",
        dir.join("../../abi/abi-version.txt").display()
    );
    let abi = kernel_core::abi_version::NATIVE;
    println!(
        "cargo:rustc-link-arg-bins=--defsym=JSR_ABI_MAJOR={}",
        abi.major
    );
    println!(
        "cargo:rustc-link-arg-bins=--defsym=JSR_ABI_MINOR={}",
        abi.minor
    );
    println!(
        "cargo:rustc-link-arg-bins=--defsym=JSR_ABI_PATCH={}",
        abi.patch
    );
    let registry = dir.join("../../abi/system-ids.txt");
    println!("cargo:rerun-if-changed={}", registry.display());
    println!("cargo:rerun-if-changed={}", dir.join("link.ld").display());
    let source = std::fs::read_to_string(&registry).expect("read system interface registry");
    let mut generated = String::from("// Generated from abi/system-ids.txt.\n");
    kernel_core::abi::validate(&source, |entry| {
        let _ = writeln!(
            generated,
            "pub const {}: u64 = {};",
            entry.name.to_ascii_uppercase().replace('.', "_"),
            entry.id
        );
    })
    .expect("validate system interface registry");
    std::fs::write(
        PathBuf::from(std::env::var("OUT_DIR").unwrap()).join("ids.rs"),
        generated,
    )
    .unwrap();
    println!(
        "cargo:rustc-link-arg-bins=-T{}",
        dir.join("link.ld").display()
    );
    let arch = std::env::var("CARGO_CFG_TARGET_ARCH").unwrap_or_default();
    let base = kernel_core::user_layout::image_base(&arch)
        .unwrap_or_else(|| panic!("unsupported user architecture: {arch}"));
    println!("cargo:rustc-link-arg-bins=--defsym=JSR_IMAGE_BASE={base:#x}");
    println!("cargo:rustc-link-arg-bins=--no-pie");
    println!("cargo:rustc-link-arg-bins=-static");
}
