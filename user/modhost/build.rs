//! 构建脚本：构建并打包四个库模块（modules/sha2、crc、deflate、net），以开发用发布者签名后写入 OUT_DIR 供 src/main.rs 内嵌
//! （连同该发布者的公钥）；
//! 同时指定本程序的链接脚本。
//! Build script: builds and packs the four library modules for embedding.

use std::path::PathBuf;

const MODULES: [(&str, &str); 4] = [("jaso-sha2", "sha2"), ("jaso-crc", "crc"), ("jaso-deflate", "deflate"), ("jaso-net", "net")];

fn main() {
    let dir = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap());
    let root = dir.join("../..");
    println!("cargo:rerun-if-changed={}", dir.join("link.ld").display());
    for d in ["modules/support/src/lib.rs", "jaso/src"] {
        println!("cargo:rerun-if-changed={}", root.join(d).display());
    }
    println!("cargo:rustc-link-arg-bins=-T{}", dir.join("link.ld").display());
    // 装载地址按目标指令集取私有窗口起点 + 固定偏移（链接脚本以 JSR_IMAGE_BASE 取用）
    let arch = std::env::var("CARGO_CFG_TARGET_ARCH").unwrap_or_default();
    let base = kernel_core::user_layout::image_base(&arch).unwrap_or_else(|| panic!("用户程序尚不支持该指令集：{}", arch));
    println!("cargo:rustc-link-arg-bins=--defsym=JSR_IMAGE_BASE={:#x}", base);
    println!("cargo:rustc-link-arg-bins=--no-pie");
    println!("cargo:rustc-link-arg-bins=-static");

    let out = PathBuf::from(std::env::var("OUT_DIR").unwrap());
    let arch = jaso::pack::build_target_arch().unwrap_or_else(|e| panic!("{}", e));
    let signer = jaso::pack::development_signer();
    for (package, sub) in MODULES {
        let mdir = root.join("modules").join(sub);
        for f in ["src/main.rs", "Cargo.toml", "build.rs", "jaso.manifest"] {
            println!("cargo:rerun-if-changed={}", mdir.join(f).display());
        }
        // 各模块共用一个独立的 target 目录（依次构建，不并发）
        let bytes = jaso::pack::build_module(&root, package, &mdir, &out.join("module-target"), arch).unwrap_or_else(|e| panic!("{}", e));
        let signed = jaso::pack::sign(&bytes, &signer).unwrap_or_else(|e| panic!("签名 {} 失败：{:?}", package, e));
        std::fs::write(out.join(format!("{}.jaso", sub)), signed).expect("写入失败");
    }
    // 受信发布者表所需的公钥（开发用发布者）
    std::fs::write(out.join("trust-dev.key"), signer.public_key()).expect("写入失败");
}
