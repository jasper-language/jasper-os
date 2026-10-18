//! 构建脚本：把模块链接成位置无关、无入口的静态映像（static-pie），供 `jaso::pack` 打包。
//! Build script: links the module as an entry-less static-pie image exporting only the declared symbols.
//!
//! * `-pie --no-dynamic-linker`：位置无关，但不需要动态链接器（重定位只剩「基址 + 加数」一种）
//! * `--export-dynamic-symbol=<名字>`：只把清单 `core.exports` 声明的函数放进动态符号表——
//!   导出是声明出来的；其余符号不进入动态符号表，也就不占映像空间
//! * `-z separate-loadable-segments`：各可装入段各占独立的页，装载器可以分别设置权限
//! * `-e 0`：没有入口；模块只经导出被调用

use std::path::PathBuf;

fn main() {
    let dir = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap());
    let manifest = dir.join("jaso.manifest");
    println!("cargo:rerun-if-changed={}", manifest.display());
    let text = std::fs::read_to_string(&manifest).expect("读取 jaso.manifest 失败");
    let mut n = 0;
    for line in text.lines() {
        if let Some((k, v)) = line.split_once('=') {
            if k.trim() == "core.exports" {
                for sym in v.split(',').map(str::trim).filter(|s| !s.is_empty()) {
                    println!("cargo:rustc-link-arg-bins=--export-dynamic-symbol={}", sym);
                    n += 1;
                }
            }
        }
    }
    assert!(n > 0, "jaso.manifest 没有声明任何导出（core.exports）");
    for a in ["-pie", "--no-dynamic-linker", "-zseparate-loadable-segments", "-e0"] {
        println!("cargo:rustc-link-arg-bins={}", a);
    }
}
