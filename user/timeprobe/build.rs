use std::path::{Path, PathBuf};

fn build_daemon(root: &Path, target_dir: &Path, triple: &str) -> Vec<u8> {
    let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".into());
    let status = std::process::Command::new(cargo)
        .current_dir(root)
        .env_remove("CARGO_ENCODED_RUSTFLAGS")
        .env_remove("RUSTFLAGS")
        .env_remove("CARGO_TARGET_DIR")
        .args([
            "build",
            "--release",
            "--target",
            triple,
            "-p",
            "user-timed",
            "--target-dir",
        ])
        .arg(target_dir)
        .status()
        .expect("failed to start Time Service build");
    assert!(status.success(), "user-timed build failed");
    let elf = target_dir.join(triple).join("release").join("user-timed");
    std::fs::read(&elf).unwrap_or_else(|error| panic!("read {}: {error}", elf.display()))
}

fn main() {
    let dir = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap());
    let root = dir.join("../..");
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
    println!("cargo:rerun-if-changed={}", dir.join("link.ld").display());
    for path in [
        "user/rt/src",
        "user/timed/src/main.rs",
        "user/timed/Cargo.toml",
        "user/timed/build.rs",
        "user/timed/link.ld",
        "kernel-core/src/service_time.rs",
        "kernel-core/src/service_protocol.rs",
        "kernel-core/src/time128.rs",
    ] {
        println!("cargo:rerun-if-changed={}", root.join(path).display());
    }
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

    let out = PathBuf::from(std::env::var("OUT_DIR").unwrap());
    let triple = match arch.as_str() {
        "x86_64" => "x86_64-unknown-none",
        "aarch64" => "aarch64-unknown-none-softfloat",
        "riscv64" => "riscv64gc-unknown-none-elf",
        "riscv32" => "riscv32imac-unknown-none-elf",
        other => panic!("unsupported Time probe architecture: {other}"),
    };
    let daemon = build_daemon(&root, &out.join("daemon-target"), triple);
    std::fs::write(out.join("timed.elf"), daemon).expect("write Time Service ELF");
}
