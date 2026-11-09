use std::fmt::Write as _;
use std::path::PathBuf;

fn main() {
    let dir = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap());
    println!("cargo:rerun-if-changed={}", dir.join("../../abi/abi-version.txt").display());
    let abi = kernel_core::abi_version::NATIVE;
    println!("cargo:rustc-link-arg-bins=--defsym=JSR_ABI_MAJOR={}", abi.major);
    println!("cargo:rustc-link-arg-bins=--defsym=JSR_ABI_MINOR={}", abi.minor);
    println!("cargo:rustc-link-arg-bins=--defsym=JSR_ABI_PATCH={}", abi.patch);
    let reg_path = dir.join("../../abi/system-ids.txt");
    println!("cargo:rerun-if-changed={}", reg_path.display());
    println!("cargo:rerun-if-changed={}", dir.join("link.ld").display());
    let reg = std::fs::read_to_string(&reg_path).expect("读取 abi/system-ids.txt 失败");
    let mut out = String::from("// generated from abi/system-ids.txt\n");
    kernel_core::abi::validate(&reg, |r| {
        let _ = writeln!(
            out,
            "pub const {}: u64 = {};",
            r.name.to_ascii_uppercase().replace('.', "_"),
            r.id
        );
    })
    .expect("登记表校验失败");
    std::fs::write(
        PathBuf::from(std::env::var("OUT_DIR").unwrap()).join("ids.rs"),
        out,
    )
    .unwrap();
    println!("cargo:rustc-link-arg-bins=-T{}", dir.join("link.ld").display());
    let arch = std::env::var("CARGO_CFG_TARGET_ARCH").unwrap_or_default();
    let base = kernel_core::user_layout::image_base(&arch)
        .unwrap_or_else(|| panic!("用户程序尚不支持该指令集：{}", arch));
    println!("cargo:rustc-link-arg-bins=--defsym=JSR_IMAGE_BASE={:#x}", base);
    println!("cargo:rustc-link-arg-bins=--no-pie");
    println!("cargo:rustc-link-arg-bins=-static");
}
