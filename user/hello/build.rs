//! 构建脚本：从内核的系统接口登记表生成调用号常量，并指定链接脚本。
//! Build script: generates syscall-ID constants from the registry and sets the linker script.

use std::fmt::Write as _;
use std::path::PathBuf;

fn main() {
    let dir = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap());
    let reg_path = dir.join("../../abi/system-ids.txt");
    println!("cargo:rerun-if-changed={}", reg_path.display());
    println!("cargo:rerun-if-changed={}", dir.join("link.ld").display());
    let reg = std::fs::read_to_string(&reg_path).expect("读取 abi/system-ids.txt 失败");
    let mut out = String::from("// 由 user/hello/build.rs 依据 abi/system-ids.txt 生成，请勿手改。\n");
    kernel_core::abi::validate(&reg, |r| {
        let _ = writeln!(out, "pub const {}: u64 = {};", r.name.to_ascii_uppercase().replace('.', "_"), r.id);
    })
    .expect("登记表校验失败");
    std::fs::write(PathBuf::from(std::env::var("OUT_DIR").unwrap()).join("ids.rs"), out).unwrap();
    // 固定地址、非 PIE 的静态可执行文件（装载器只接受 ET_EXEC）。
    println!("cargo:rustc-link-arg-bins=-T{}", dir.join("link.ld").display());
    println!("cargo:rustc-link-arg-bins=--no-pie");
    println!("cargo:rustc-link-arg-bins=-static");
}
