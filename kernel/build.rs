//! 构建脚本：读取系统接口登记表，校验后生成「名字 ↔ 稳定 ID」查表代码。
//! Build script: validates the system-interface registry and generates the name/ID table.
//!
//! 只读取与校验，绝不分配或重排编号（编号由人写在 `abi/system-ids.txt` 里）。
//! 以下任一情况都会让构建失败：
//! * 登记表格式错误、ID 重复、名字重复、名字违反命名约定（`kernel_core::abi::validate`）
//! * 已冻结（`abi/system-ids.lock`）的条目被删除、改号、改名或改种类（`kernel_core::abi::check_frozen`）
//!
//! 另外（特性 `user-programs` 开启时）以内核的目标指令集构建内嵌的用户程序，产物以 `include_bytes!` 装进内核镜像；
//! 目标为 AArch64 或 RISC-V 时为内核二进制指定链接脚本（没有引导器，装载地址与段布局由脚本固定）。

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
    // (ID, 规范名, 中文显示名, 英文显示名)：只收集错误码，稍后按 ID 排序生成渲染表。
    let mut error_texts: Vec<(u32, &str, &str, &str)> = Vec::new();
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
            "    AbiEntry {{ id: {}, kind: {}, name: \"{}\", version: {}, effects: {}, display_zh: \"{}\", display_en: \"{}\" }},",
            r.id, kind, r.name, r.version, effects, r.display_zh, r.display_en
        );
        if r.kind == "error" {
            error_texts.push((r.id, r.name, r.display_zh, r.display_en));
        }
    });
    match result {
        Ok(_) => {}
        Err(kernel_core::abi::AbiError::MissingDisplayEn { line }) => {
            panic!("abi/system-ids.txt 第 {} 行缺少英文显示名", line)
        }
        Err(kernel_core::abi::AbiError::BadDisplayEn { line, reason }) => {
            panic!("abi/system-ids.txt 第 {} 行的英文显示名不合法：{}", line, reason)
        }
        Err(e) => panic!("abi/system-ids.txt 校验失败：{:?}", e),
    }
    if let Err(e) = kernel_core::abi::check_frozen(&reg, &lock) {
        panic!("已冻结的系统接口被破坏（abi/system-ids.lock）：{:?}", e);
    }
    out.push_str("\n/// 全部登记条目（按登记表顺序）。\npub static ENTRIES: &[AbiEntry] = &[\n");
    out.push_str(&entries);
    out.push_str("];\n");

    // 错误渲染表：生成器排序（登记表本身按发布顺序追加，ID 并不保证单调），渲染时才能二分查找。
    error_texts.sort_by_key(|e| e.0);
    out.push_str("\n/// 错误码 → 人类可读文本（只含 `error` 种类，按 ID 升序）。\npub static ERROR_TEXTS: &[kernel_core::l10n::ErrorText] = &[\n");
    for (id, name, zh, en) in &error_texts {
        let _ = writeln!(
            out,
            "    kernel_core::l10n::ErrorText {{ id: {}, name: \"{}\", zh: \"{}\", en: \"{}\" }},",
            id, name, zh, en
        );
    }
    out.push_str("];\n");

    let dest = PathBuf::from(std::env::var("OUT_DIR").unwrap()).join("abi_generated.rs");
    std::fs::write(dest, out).expect("写入生成代码失败");

    if std::env::var_os("CARGO_FEATURE_USER_PROGRAMS").is_some() {
        build_user_programs(&root);
    }
    // AArch64 / RISC-V 没有引导器，内核 ELF 由固件或仿真器直接装载：用本仓库的链接脚本固定装载地址与段布局。
    let script = match std::env::var("CARGO_CFG_TARGET_ARCH").as_deref() {
        Ok("aarch64") => Some("kernel/link-aarch64.ld"),
        Ok("riscv64") => Some("kernel/link-riscv64.ld"),
        Ok("riscv32") => Some("kernel/link-riscv32.ld"),
        _ => None,
    };
    if let Some(script) = script {
        let script = root.join(script);
        println!("cargo:rerun-if-changed={}", script.display());
        println!("cargo:rustc-link-arg-bins=-T{}", script.display());
    }
}

/// 构建内嵌的用户程序：用独立的 target 目录调用 cargo，避免与外层构建争用同一目录的锁；
/// 产物路径经环境变量（`JSR_USER_HELLO`、`JSR_USER_RING`、`JSR_USER_IPC`、`JSR_USER_PROG`、`JSR_USER_ROBUST`、
/// `JSR_USER_RTDEMO`、`JSR_USER_LIBCHECK`、`JSR_USER_JASODEMO`、`JSR_USER_MODHOST`、`JSR_USER_SCHEDTEST`、
/// `JSR_USER_BENCH`、`JSR_USER_ISOHOST`）交给内核源码 `include_bytes!`。
/// Builds the embedded user programs with a separate target dir and exposes their paths to the kernel.
fn build_user_programs(root: &std::path::Path) {
    let mut programs: Vec<(&str, &str, &str)> = vec![
        ("user/hello", "user-hello", "JSR_USER_HELLO"),
        ("user/ring", "user-ring", "JSR_USER_RING"),
        ("user/ipc", "user-ipc", "JSR_USER_IPC"),
        ("user/prog", "user-prog", "JSR_USER_PROG"),
        ("user/robust", "user-robust", "JSR_USER_ROBUST"),
        ("user/rtdemo", "user-rtdemo", "JSR_USER_RTDEMO"),
        ("user/libcheck", "user-libcheck", "JSR_USER_LIBCHECK"),
        ("user/jasodemo", "user-jasodemo", "JSR_USER_JASODEMO"),
        ("user/modhost", "user-modhost", "JSR_USER_MODHOST"),
        ("user/schedtest", "user-schedtest", "JSR_USER_SCHEDTEST"),
        ("user/bench", "user-bench", "JSR_USER_BENCH"),
        ("user/isohost", "user-isohost", "JSR_USER_ISOHOST"),
    ];
    // DRV-1C / DRV-2C 的用户态演练在 x86_64 与 AArch64 上构建与内嵌（其它指令集冻结，不写对应代码）。
    if matches!(std::env::var("CARGO_CFG_TARGET_ARCH").as_deref(), Ok("x86_64") | Ok("aarch64")) {
        programs.push(("user/devprobe", "user-devprobe", "JSR_USER_DEVPROBE"));
        programs.push(("user/irqprobe", "user-irqprobe", "JSR_USER_IRQPROBE"));
    }
    for (dir, _, _) in &programs {
        for f in ["src/main.rs", "Cargo.toml", "link.ld", "build.rs"] {
            println!("cargo:rerun-if-changed={}", root.join(dir).join(f).display());
        }
    }
    // 用户程序依赖的库（运行时、`.jaso` 格式）与内嵌的模块：任何一个源文件变化都要重建
    for lib in ["user/rt", "jaso", "modules/demo", "modules/support", "modules/sha2", "modules/crc", "modules/deflate", "modules/net", "modules/probe", "user/modbox"] {
        for f in ["Cargo.toml", "build.rs", "jaso.manifest"] {
            println!("cargo:rerun-if-changed={}", root.join(lib).join(f).display());
        }
        if let Ok(dir) = std::fs::read_dir(root.join(lib).join("src")) {
            for f in dir.flatten() {
                println!("cargo:rerun-if-changed={}", f.path().display());
            }
        }
    }
    // 用户程序共享 kernel-core 的记录布局：它变化时也要重建
    println!("cargo:rerun-if-changed={}", root.join("kernel-core/src/ring_abi.rs").display());
    println!("cargo:rerun-if-changed={}", root.join("kernel-core/src/bench.rs").display());
    println!("cargo:rerun-if-changed={}", root.join("kernel-core/src/device.rs").display());
    let out_dir = PathBuf::from(std::env::var("OUT_DIR").unwrap());
    let target_dir = out_dir.join("user-target");
    let triple = user_triple();
    let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".into());
    let mut cmd = std::process::Command::new(cargo);
    cmd.current_dir(root)
        .env_remove("CARGO_ENCODED_RUSTFLAGS")
        .env_remove("RUSTFLAGS")
        .env_remove("CARGO_TARGET_DIR")
        .args(["build", "--release", "--target", triple]);
    for (_, pkg, _) in &programs {
        cmd.args(["-p", *pkg]);
    }
    let status = cmd.arg("--target-dir").arg(&target_dir).status().expect("无法启动 cargo 构建用户程序");
    assert!(status.success(), "用户程序构建失败");
    for (_, pkg, env) in &programs {
        let elf = target_dir.join(triple).join("release").join(pkg);
        assert!(elf.exists(), "找不到用户程序产物 {}", elf.display());
        println!("cargo:rustc-env={}={}", env, elf.display());
    }
}

/// 用户程序的目标三元组：与内核相同的指令集。AArch64 与 RISC-V64 用软浮点目标——内核不保存浮点 / SIMD 寄存器，
/// 并让用户态的任何浮点 / SIMD 访问陷入（RISC-V：sstatus.FS 保持关闭）。
/// The user-program target triple (same ISA as the kernel).
fn user_triple() -> &'static str {
    match std::env::var("CARGO_CFG_TARGET_ARCH").as_deref() {
        Ok("x86_64") => "x86_64-unknown-none",
        Ok("aarch64") => "aarch64-unknown-none-softfloat",
        Ok("riscv64") => "riscv64imac-unknown-none-elf",
        Ok("riscv32") => "riscv32imac-unknown-none-elf",
        other => panic!("内嵌用户程序尚不支持该指令集：{:?}", other),
    }
}
