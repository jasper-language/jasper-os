//! 构建脚本：构建并打包四个库模块（modules/sha2、crc、deflate、net），写入 OUT_DIR 供 src/main.rs 内嵌；
//! 同时指定本程序的链接脚本。
//! Build script: builds and packs the four library modules for embedding.

use std::path::PathBuf;

use jaso::Arch;

const MODULES: [(&str, &str); 4] = [("jaso-sha2", "sha2"), ("jaso-crc", "crc"), ("jaso-deflate", "deflate"), ("jaso-net", "net")];

fn main() {
    let dir = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap());
    let root = dir.join("../..");
    println!("cargo:rerun-if-changed={}", dir.join("link.ld").display());
    for d in ["modules/support/src/lib.rs", "jaso/src"] {
        println!("cargo:rerun-if-changed={}", root.join(d).display());
    }
    println!("cargo:rustc-link-arg-bins=-T{}", dir.join("link.ld").display());
    println!("cargo:rustc-link-arg-bins=--no-pie");
    println!("cargo:rustc-link-arg-bins=-static");

    let out = PathBuf::from(std::env::var("OUT_DIR").unwrap());
    for (package, sub) in MODULES {
        let mdir = root.join("modules").join(sub);
        for f in ["src/main.rs", "Cargo.toml", "build.rs", "jaso.manifest"] {
            println!("cargo:rerun-if-changed={}", mdir.join(f).display());
        }
        // 各模块共用一个独立的 target 目录（依次构建，不并发）
        let bytes = jaso::pack::build_module(&root, package, &mdir, &out.join("module-target"), Arch::X86_64).unwrap_or_else(|e| panic!("{}", e));
        std::fs::write(out.join(format!("{}.jaso", sub)), bytes).expect("写入失败");
    }
}
