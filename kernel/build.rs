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

use kernel_core::elf::ElfClass;

fn main() {
    let root = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap()).join("..");
    let reg_path = root.join("abi/system-ids.txt");
    let lock_path = root.join("abi/system-ids.lock");
    let version_path = root.join("abi/abi-version.txt");
    let snapshots_path = root.join("abi/snapshots");
    println!("cargo:rerun-if-changed={}", reg_path.display());
    println!("cargo:rerun-if-changed={}", lock_path.display());
    println!("cargo:rerun-if-changed={}", version_path.display());
    println!("cargo:rerun-if-changed={}", snapshots_path.display());

    let reg = std::fs::read_to_string(&reg_path).expect("读取 abi/system-ids.txt 失败");
    let lock = std::fs::read_to_string(&lock_path).expect("读取 abi/system-ids.lock 失败");
    let version_source = std::fs::read_to_string(&version_path).expect("读取 abi/abi-version.txt 失败");
    let native = kernel_core::abi_version::parse_source(&version_source)
        .unwrap_or_else(|e| panic!("abi/abi-version.txt 解析失败：{:?}", e));
    // 两套解析器（kernel-core/build.rs 与 kernel-core::abi_version）必须对同一份真源得到同一结果。
    assert_eq!(
        native,
        kernel_core::abi_version::NATIVE,
        "abi/abi-version.txt 与 kernel-core 生成的常量不一致（构建缓存未刷新或解析器分歧）"
    );

    let mut out = String::new();
    let mut entries = String::new();
    // (ID, 规范名, 中文显示名, 英文显示名)：只收集错误码，稍后按 ID 排序生成渲染表。
    let mut error_texts: Vec<(u32, &str, &str, &str)> = Vec::new();
    // 已登记操作 ID：生成唯一的能力集合常量，spawn 授权与分发自检共用。
    let mut op_ids: Vec<(u32, &str)> = Vec::new();
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
        } else {
            op_ids.push((r.id, r.name));
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
    if let Err(e) = kernel_core::abi::check_frozen_generation(&reg, &lock, native) {
        panic!("已冻结的系统接口或 ABI 世代被破坏（abi/system-ids.lock）：{:?}", e);
    }
    // 完整契约快照门槛：当前源码必须与当前版本的不可变快照逐行一致；同主版本旧快照
    // 只能被新增条目扩展，Patch 升级则要求契约完全不变。主版本换代必须随新内核提交新快照。
    let mut current_contract = String::new();
    if let Err(e) = kernel_core::abi_contract::render_current(&reg, &mut current_contract) {
        panic!("无法从当前 ABI 真源渲染契约快照：{:?}", e);
    }
    let snapshot_entries = std::fs::read_dir(&snapshots_path)
        .unwrap_or_else(|e| panic!("读取 {} 失败：{}", snapshots_path.display(), e));
    let mut snapshot_paths: Vec<PathBuf> = snapshot_entries
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| path.extension().and_then(|s| s.to_str()) == Some("contract"))
        .collect();
    snapshot_paths.sort();
    let mut snapshot_texts: Vec<(kernel_core::abi_version::AbiVersion, String)> = Vec::new();
    for path in snapshot_paths {
        let text = std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("读取 ABI 快照 {} 失败：{}", path.display(), e));
        let version = kernel_core::abi_contract::snapshot_version(&text)
            .unwrap_or_else(|e| panic!("ABI 快照 {} 的世代头不合法：{:?}", path.display(), e));
        let expected = format!("{}.{}.{}.contract", version.major, version.minor, version.patch);
        assert_eq!(
            path.file_name().and_then(|s| s.to_str()),
            Some(expected.as_str()),
            "ABI 快照文件名与 `abi=` 世代不一致：{}",
            path.display()
        );
        snapshot_texts.push((version, text));
    }
    let snapshot_refs: Vec<kernel_core::abi_contract::Snapshot<'_>> = snapshot_texts
        .iter()
        .map(|(version, text)| kernel_core::abi_contract::Snapshot { version: *version, text })
        .collect();
    if let Err(e) = kernel_core::abi_contract::check_snapshot_set(&current_contract, &snapshot_refs) {
        panic!(
            "ABI 契约快照门槛失败：{:?}；契约变化必须提升 abi/abi-version.txt 并新增 abi/snapshots/<Major.Minor.Patch>.contract",
            e
        );
    }
    // 能力集合的容量是 ABI 契约的一部分：登记表里的操作 ID 必须都能被 256 位集合表示。
    // 越界即构建失败，不允许出现「登记表承认、权限位却放不下」的操作。
    let max_ids = kernel_core::syscall_set::MAX_IDS;
    if let Some((id, name)) = op_ids.iter().find(|(id, _)| *id as usize >= max_ids) {
        panic!(
            "abi/system-ids.txt 中的操作 `{}` ID={} 超出 SyscallSet 容量 {}；请先扩大 kernel-core::syscall_set::MAX_IDS",
            name, id, max_ids
        );
    }
    out.push_str("\n/// 全部已登记操作 ID（唯一真源：abi/system-ids.txt）。\npub const REGISTERED_OPS: &[u32] = &[");
    for (i, (id, _)) in op_ids.iter().enumerate() {
        if i > 0 {
            out.push_str(", ");
        }
        let _ = write!(out, "{}", id);
    }
    out.push_str("];\n");
    out.push_str("\n/// 全部已登记操作构成的权限集合（spawn 的 `known` 与启动自检共用）。\npub const REGISTERED_OPS_SET: kernel_core::syscall_set::SyscallSet = kernel_core::syscall_set::SyscallSet::of(REGISTERED_OPS);\n");
    out.push_str("\n/// 当前登记表中最大的操作 ID。\npub const MAX_REGISTERED_OP_ID: u32 = ");
    let _ = writeln!(out, "{};", op_ids.iter().map(|(id, _)| *id).max().unwrap_or(0));
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
        build_user_programs(&root, native);
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
/// Builds the embedded user programs with a separate target dir, verifies their ABI stamps, and exposes their paths.
fn build_user_programs(root: &std::path::Path, native: kernel_core::abi_version::AbiVersion) {
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
    // DRV-1C / DRV-2C 的用户态演练只在 x86_64 上构建与内嵌（其它指令集冻结，不写对应代码）。
    if std::env::var("CARGO_CFG_TARGET_ARCH").as_deref() == Ok("x86_64") {
        programs.push(("user/devprobe", "user-devprobe", "JSR_USER_DEVPROBE"));
        programs.push(("user/irqprobe", "user-irqprobe", "JSR_USER_IRQPROBE"));
    }
    for (dir, _, _) in &programs {
        for f in ["src/main.rs", "Cargo.toml", "link.ld", "build.rs"] {
            println!("cargo:rerun-if-changed={}", root.join(dir).join(f).display());
        }
    }
    // 用户程序依赖的库（运行时、`.jaso` 格式）与内嵌的模块：任何一个源文件变化都要重建
    for lib in ["user/rt", "jaso", "modules/demo", "modules/support", "modules/sha2", "modules/crc", "modules/deflate", "modules/net", "modules/probe", "modules/l1demo", "user/modbox"] {
        for f in ["Cargo.toml", "build.rs", "jaso.manifest", "jaso.import"] {
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
    let (machine, class) = elf_target();
    // 期望的章直接由构建脚本解析出的真源构造，避免「校验值来自另一份生成常量」的循环自证。
    let expected = kernel_core::abi_version::ProgramAbi {
        major: native.major,
        min_minor: native.minor,
        patch: native.patch,
    };
    for (dir, pkg, env) in &programs {
        let elf = target_dir.join(triple).join("release").join(pkg);
        assert!(elf.exists(), "找不到用户程序产物 {}", elf.display());
        // 构建期一致性：每个内嵌程序都必须携带与当前真源完全一致的 ABI 章，
        // 否则内核启动后会在装载阶段拒绝自己的程序——这类失配必须在这里就失败。
        let bytes = std::fs::read(&elf).unwrap_or_else(|e| panic!("读取用户程序 {} 失败：{}", elf.display(), e));
        let parsed = kernel_core::elf::parse(&bytes, machine, class)
            .unwrap_or_else(|e| panic!("用户程序 {} 的 ELF 不合法：{:?}", dir, e));
        assert_eq!(
            parsed.abi(),
            Some(expected),
            "用户程序 {} 的 ABI 章与 abi/abi-version.txt 不一致",
            dir
        );
        let required = parsed.required_capabilities();
        if *dir == "user/hello" {
            assert_eq!(required.iter().collect::<Vec<_>>(), vec!["kernel.core"], "user-hello capability note differs");
        }
        println!("cargo:rustc-env={}={}", env, elf.display());
    }
}

/// 当前内核目标指令集的 `(e_machine, ELF 类别)`，用于构建期校验用户程序。
fn elf_target() -> (u16, ElfClass) {
    match std::env::var("CARGO_CFG_TARGET_ARCH").as_deref() {
        Ok("x86_64") => (62, ElfClass::Elf64),
        Ok("aarch64") => (183, ElfClass::Elf64),
        Ok("riscv64") => (243, ElfClass::Elf64),
        Ok("riscv32") => (243, ElfClass::Elf32),
        other => panic!("内嵌用户程序尚不支持该指令集：{:?}", other),
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
