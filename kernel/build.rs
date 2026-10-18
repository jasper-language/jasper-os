//! 构建脚本：读取系统接口登记表，校验后生成「名字 ↔ 稳定 ID」查表代码。
//! Build script: validates the system-interface registry and generates the name/ID table.
//!
//! 只读取与校验，绝不分配或重排编号（编号由人写在 `abi/system-ids.txt` 里）。
//! 以下任一情况都会让构建失败：
//! * 登记表格式错误、ID 重复、名字重复、名字违反命名约定（`kernel_core::abi::validate`）
//! * 已冻结（`abi/system-ids.lock`）的条目被删除、改号、改名或改种类（`kernel_core::abi::check_frozen`）
//!
//! 另外构建内嵌的用户程序（`user/hello`），产物以 `include_bytes!` 装进内核镜像。

use std::fmt::Write as _;
use std::path::PathBuf;

fn main() {
    let root = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap()).join("..");
    let reg_path = root.join("abi/system-ids.txt");
    let lock_path = root.join("abi/system-ids.lock");
    println!("cargo:rerun-if-changed={}", reg_path.display());
    println!("cargo:rerun-if-changed={}", lock_path.display());

    let reg = std::fs::read_to_string(&reg_path).expect("读取 abi/system-ids.txt 失败");
    let lock = std::fs::read_to_string(&lock_path).expect("读取 abi/system-ids.lock 失败");

    let mut out = String::new();
    let mut entries = String::new();
    out.push_str("// 由 kernel/build.rs 依据 abi/system-ids.txt 生成，请勿手改。\n");
    out.push_str("// Generated from abi/system-ids.txt by kernel/build.rs. Do not edit.\n\n");
    let result = kernel_core::abi::validate(&reg, |r| {
        let const_name = r.name.to_ascii_uppercase().replace('.', "_");
        let _ = writeln!(out, "/// `{}`（{}）。\npub const {}: u32 = {};", r.name, r.display_zh, const_name, r.id);
        let kind = if r.kind == "op" { "AbiKind::Op" } else { "AbiKind::Error" };
        let effects = match r.effects {
            "none" => "Effects::None",
            "read" => "Effects::Read",
            "write" => "Effects::Write",
            _ => "Effects::Irreversible",
        };
        let _ = writeln!(
            entries,
            "    AbiEntry {{ id: {}, kind: {}, name: \"{}\", version: {}, effects: {}, display_zh: \"{}\" }},",
            r.id, kind, r.name, r.version, effects, r.display_zh
        );
    });
    match result {
        Ok(_) => {}
        Err(e) => panic!("abi/system-ids.txt 校验失败：{:?}", e),
    }
    if let Err(e) = kernel_core::abi::check_frozen(&reg, &lock) {
        panic!("已冻结的系统接口被破坏（abi/system-ids.lock）：{:?}", e);
    }
    out.push_str("\n/// 全部登记条目（按登记表顺序）。\npub static ENTRIES: &[AbiEntry] = &[\n");
    out.push_str(&entries);
    out.push_str("];\n");

    let dest = PathBuf::from(std::env::var("OUT_DIR").unwrap()).join("abi_generated.rs");
    std::fs::write(dest, out).expect("写入生成代码失败");

    build_user_programs(&root);
}

/// 构建内嵌的用户程序：用独立的 target 目录调用 cargo，避免与外层构建争用同一目录的锁；
/// 产物路径经环境变量（`JSR_USER_HELLO`、`JSR_USER_RING`、`JSR_USER_IPC`、`JSR_USER_PROG`、`JSR_USER_RTDEMO`、`JSR_USER_LIBCHECK`）交给内核源码 `include_bytes!`。
/// Builds the embedded user programs with a separate target dir and exposes their paths to the kernel.
fn build_user_programs(root: &std::path::Path) {
    const PROGRAMS: [(&str, &str, &str); 6] = [
        ("user/hello", "user-hello", "JSR_USER_HELLO"),
        ("user/ring", "user-ring", "JSR_USER_RING"),
        ("user/ipc", "user-ipc", "JSR_USER_IPC"),
        ("user/prog", "user-prog", "JSR_USER_PROG"),
        ("user/rtdemo", "user-rtdemo", "JSR_USER_RTDEMO"),
        ("user/libcheck", "user-libcheck", "JSR_USER_LIBCHECK"),
    ];
    for (dir, _, _) in PROGRAMS {
        for f in ["src/main.rs", "Cargo.toml", "link.ld", "build.rs"] {
            println!("cargo:rerun-if-changed={}", root.join(dir).join(f).display());
        }
    }
    // 用户态运行时（库）的源文件：任何一个变化都要重建依赖它的程序
    println!("cargo:rerun-if-changed={}", root.join("user/rt/Cargo.toml").display());
    println!("cargo:rerun-if-changed={}", root.join("user/rt/build.rs").display());
    if let Ok(dir) = std::fs::read_dir(root.join("user/rt/src")) {
        for f in dir.flatten() {
            println!("cargo:rerun-if-changed={}", f.path().display());
        }
    }
    // 用户程序共享 kernel-core 的记录布局：它变化时也要重建
    println!("cargo:rerun-if-changed={}", root.join("kernel-core/src/ring_abi.rs").display());
    let out_dir = PathBuf::from(std::env::var("OUT_DIR").unwrap());
    let target_dir = out_dir.join("user-target");
    let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".into());
    let mut cmd = std::process::Command::new(cargo);
    cmd.current_dir(root)
        .env_remove("CARGO_ENCODED_RUSTFLAGS")
        .env_remove("RUSTFLAGS")
        .env_remove("CARGO_TARGET_DIR")
        .args(["build", "--release", "--target", "x86_64-unknown-none"]);
    for (_, pkg, _) in PROGRAMS {
        cmd.args(["-p", pkg]);
    }
    let status = cmd.arg("--target-dir").arg(&target_dir).status().expect("无法启动 cargo 构建用户程序");
    assert!(status.success(), "用户程序构建失败");
    for (_, pkg, env) in PROGRAMS {
        let elf = target_dir.join("x86_64-unknown-none/release").join(pkg);
        assert!(elf.exists(), "找不到用户程序产物 {}", elf.display());
        println!("cargo:rustc-env={}={}", env, elf.display());
    }
}
