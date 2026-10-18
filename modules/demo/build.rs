//! 构建脚本：把模块链接成位置无关、无入口、导出动态符号的静态映像（static-pie），供 `jaso::pack` 打包。
//! Build script: links the module as an entry-less static-pie image with exported dynamic symbols.
//!
//! * `-pie --no-dynamic-linker`：位置无关，但不需要动态链接器（重定位只剩「基址 + 加数」一种）
//! * `--export-dynamic`：`#[no_mangle] extern "C"` 函数进入动态符号表，成为导出
//! * `-z separate-loadable-segments`：各可装入段各占独立的页，装载器可以分别设置权限
//! * `-e 0`：没有入口；模块只经导出被调用

fn main() {
    for a in ["-pie", "--no-dynamic-linker", "--export-dynamic", "-zseparate-loadable-segments", "-e0"] {
        println!("cargo:rustc-link-arg-bins={}", a);
    }
}
