//! Link the UI service as a non-PIE ELF with Jasper's ABI and capability notes.

use std::fmt::Write as _;
use std::path::PathBuf;

fn main() {
    let dir = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap());
    let abi = kernel_core::abi_version::NATIVE;
    println!(
        "cargo:rerun-if-changed={}",
        dir.join("../../abi/abi-version.txt").display()
    );
    println!(
        "cargo:rerun-if-changed={}",
        dir.join("../../abi/system-ids.txt").display()
    );
    println!("cargo:rerun-if-changed={}", dir.join("link.ld").display());
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
    let registry =
        std::fs::read_to_string(dir.join("../../abi/system-ids.txt")).expect("read system IDs");
    let mut generated =
        String::from("// Generated from abi/system-ids.txt for the UI service binary.\n");
    kernel_core::abi::validate(&registry, |record| {
        let _ = writeln!(
            generated,
            "pub const {}: u64 = {};",
            record.name.to_ascii_uppercase().replace('.', "_"),
            record.id
        );
    })
    .expect("validate system IDs");
    std::fs::write(
        PathBuf::from(std::env::var("OUT_DIR").unwrap()).join("ids.rs"),
        generated,
    )
    .expect("write generated IDs");
    println!(
        "cargo:rustc-link-arg-bins=-T{}",
        dir.join("link.ld").display()
    );
    let arch = std::env::var("CARGO_CFG_TARGET_ARCH").unwrap_or_default();
    let base = kernel_core::user_layout::image_base(&arch)
        .unwrap_or_else(|| panic!("unsupported UI service target: {arch}"));
    println!("cargo:rustc-link-arg-bins=--defsym=JSR_IMAGE_BASE={base:#x}");
    println!("cargo:rustc-link-arg-bins=--no-pie");
    println!("cargo:rustc-link-arg-bins=-static");
}
