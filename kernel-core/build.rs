//! 构建脚本：把 `abi/abi-version.txt`（原生 ABI 世代的唯一真源）编译成常量。
//! Build script: compiles the single source of the native ABI generation into constants.
//!
//! # 为什么要生成
//! ABI 主版本必须随内核产物声明，并且必须能被真实装载检查使用。把版本写死在多个 Rust 文件里迟早会失配，
//! 所以这里只读取真源、生成 `OUT_DIR/abi_version_generated.rs`，再由 `kernel_core::abi_version` 引用。
//!
//! # 边界
//! 本脚本只做严格的文本解析与代码生成，不猜测默认值：缺键、重复键、未知键、越界值一律让构建失败。
//! `kernel/build.rs` 会再用 `kernel_core::abi_version::parse_source` 解析同一文件并与此处生成的常量比对，
//! 因此两套解析器不一致也会在构建期暴露。

use std::fmt::Write as _;
use std::path::PathBuf;

fn main() {
    let root = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap()).join("..");
    let path = root.join("abi/abi-version.txt");
    println!("cargo:rerun-if-changed={}", path.display());
    let text = std::fs::read_to_string(&path).expect("读取 abi/abi-version.txt 失败");
    let (major, minor, patch) = parse(&text);
    let mut out = String::from("// 由 kernel-core/build.rs 依据 abi/abi-version.txt 生成，请勿手改。\n");
    out.push_str("// Generated from abi/abi-version.txt by kernel-core/build.rs. Do not edit.\n");
    writeln!(out, "pub const ABI_MAJOR: u16 = {};", major).unwrap();
    writeln!(out, "pub const ABI_MINOR: u16 = {};", minor).unwrap();
    writeln!(out, "pub const ABI_PATCH: u16 = {};", patch).unwrap();
    let dest = PathBuf::from(std::env::var("OUT_DIR").unwrap()).join("abi_version_generated.rs");
    std::fs::write(dest, out).expect("写入 abi_version_generated.rs 失败");
}

/// 严格解析真源：只接受 `major` / `minor` / `patch` 三个键各一次，值必须能放进 `u16`。
fn parse(text: &str) -> (u16, u16, u16) {
    let mut values: [Option<u16>; 3] = [None; 3];
    for (line_no, raw) in text.lines().enumerate() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let (key, value) = line
            .split_once('=')
            .unwrap_or_else(|| panic!("abi/abi-version.txt 第 {} 行缺少 `=`", line_no + 1));
        let slot = match key.trim() {
            "major" => 0,
            "minor" => 1,
            "patch" => 2,
            other => panic!("abi/abi-version.txt 第 {} 行含未知键 `{}`", line_no + 1, other),
        };
        let parsed: u16 = value
            .trim()
            .parse()
            .unwrap_or_else(|_| panic!("abi/abi-version.txt 第 {} 行的值不是 0..=65535", line_no + 1));
        if values[slot].replace(parsed).is_some() {
            panic!("abi/abi-version.txt 第 {} 行重复定义键", line_no + 1);
        }
    }
    (
        values[0].expect("abi/abi-version.txt 缺少 major"),
        values[1].expect("abi/abi-version.txt 缺少 minor"),
        values[2].expect("abi/abi-version.txt 缺少 patch"),
    )
}
