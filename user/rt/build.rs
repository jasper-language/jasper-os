//! 构建脚本：从系统接口登记表生成调用号常量、错误常量与错误名查表。
//! Build script: generates syscall IDs, error constants and the error-name table from the registry.

use std::fmt::Write as _;
use std::path::PathBuf;

fn main() {
    let dir = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap());
    let reg_path = dir.join("../../abi/system-ids.txt");
    println!("cargo:rerun-if-changed={}", reg_path.display());
    let reg = std::fs::read_to_string(&reg_path).expect("读取 abi/system-ids.txt 失败");

    let mut ids = String::from("// 由 user/rt/build.rs 依据 abi/system-ids.txt 生成，请勿手改。\n");
    let mut consts = String::from("// 由 user/rt/build.rs 依据 abi/system-ids.txt 生成，请勿手改。\nimpl Error {\n");
    let mut names = String::from("/// 错误 ID → 规范名（未登记返回 `None`）。\npub(crate) fn error_name(id: u64) -> Option<&'static str> {\n    match id {\n");
    kernel_core::abi::validate(&reg, |r| {
        let _ = writeln!(ids, "pub const {}: u64 = {};", r.name.to_ascii_uppercase().replace('.', "_"), r.id);
        if r.kind == "error" {
            // 常量名去掉根与 `error` 段：system.handle.error.invalid → HANDLE_INVALID，system.error.unsupported → UNSUPPORTED
            let short: Vec<&str> = r.name.split('.').skip(1).filter(|s| *s != "error").collect();
            let _ = writeln!(
                consts,
                "    /// `{}`（{}）。\n    pub const {}: Error = Error({});",
                r.name,
                r.display_zh,
                short.join("_").to_ascii_uppercase(),
                r.id
            );
            let _ = writeln!(names, "        {} => Some(\"{}\"),", r.id, r.name);
        }
    })
    .expect("登记表校验失败");
    consts.push_str("}\n");
    names.push_str("        _ => None,\n    }\n}\n");
    let out = PathBuf::from(std::env::var("OUT_DIR").unwrap());
    std::fs::write(out.join("ids.rs"), ids).unwrap();
    std::fs::write(out.join("errors.rs"), consts + &names).unwrap();
}
