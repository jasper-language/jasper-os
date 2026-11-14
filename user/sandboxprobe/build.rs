use std::fmt::Write as _;
use std::path::{Path, PathBuf};

fn user_triple(arch: &str) -> &'static str {
    match arch {
        "x86_64" => "x86_64-unknown-none",
        "aarch64" => "aarch64-unknown-none-softfloat",
        "riscv64" => "riscv64imac-unknown-none-elf",
        "riscv32" => "riscv32imac-unknown-none-elf",
        other => panic!("unsupported Sandbox child architecture: {other}"),
    }
}

fn build_sandbox_child(root: &Path, out: &Path, triple: &str) {
    let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".into());
    let target_dir = out.join("sandbox-child-target");
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
            "user-sandboxchild",
            "--target-dir",
        ])
        .arg(&target_dir)
        .status()
        .expect("cannot start Sandbox child build");
    assert!(status.success(), "user-sandboxchild build failed");
    let elf = target_dir
        .join(triple)
        .join("release")
        .join("user-sandboxchild");
    let bytes = std::fs::read(&elf)
        .unwrap_or_else(|error| panic!("cannot read {}: {error}", elf.display()));
    std::fs::write(out.join("sandbox-child.elf"), bytes).unwrap();
}

fn main() {
    let dir = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap());
    let root = dir.join("../..");
    println!(
        "cargo:rerun-if-changed={}",
        dir.join("../../abi/abi-version.txt").display()
    );
    let abi = kernel_core::abi_version::NATIVE;
    println!("cargo:rustc-link-arg-bins=--defsym=JSR_ABI_MAJOR={}", abi.major);
    println!("cargo:rustc-link-arg-bins=--defsym=JSR_ABI_MINOR={}", abi.minor);
    println!("cargo:rustc-link-arg-bins=--defsym=JSR_ABI_PATCH={}", abi.patch);
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
    println!("cargo:rustc-link-arg-bins=-T{}", dir.join("link.ld").display());
    let arch = std::env::var("CARGO_CFG_TARGET_ARCH").unwrap_or_default();
    let base = kernel_core::user_layout::image_base(&arch)
        .unwrap_or_else(|| panic!("unsupported user architecture: {arch}"));
    println!("cargo:rustc-link-arg-bins=--defsym=JSR_IMAGE_BASE={base:#x}");
    println!("cargo:rustc-link-arg-bins=--no-pie");
    println!("cargo:rustc-link-arg-bins=-static");
    for path in [
        "user/sandboxchild/src/main.rs",
        "user/sandboxchild/Cargo.toml",
        "user/sandboxchild/link.ld",
        "user/sandboxchild/build.rs",
    ] {
        println!("cargo:rerun-if-changed={}", root.join(path).display());
    }
    let out = PathBuf::from(std::env::var("OUT_DIR").unwrap());
    build_sandbox_child(&root, &out, user_triple(&arch));
}
