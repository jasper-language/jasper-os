//! 原生 ABI 世代演练（issue #8 第一片）：声明唯一、盖章可验、装载前拒绝。
//! Native ABI generation drill: one declaration, verifiable stamps, rejection before mapping.
//!
//! # 覆盖
//! 1. 版本真源 `abi/abi-version.txt` 能解析，且与构建期生成的 [`kernel_core::abi_version::NATIVE`] 一致
//! 2. 真实内嵌的 `user-hello` 携带 `.note.jasper.abi`，章内容与本构建的原生要求逐字段相等
//! 3. 真实镜像可以装载（正例）；随后回收，页帧回到基线
//! 4. 缺少章、章损坏、跨主版本、次版本高于内核四类负例都在**任何页映射之前**被拒绝：
//!    错误名符合登记表，且拒绝后进程一页未映射
//!
//! 每项打印 `[JSR-ABI]` 标记；最后输出 `checks=<n> failed=<m> reclaimed=<bool>`，
//! 验收要求 `failed=0` 且 `reclaimed=true`。
//!
//! # 边界
//! 本演练只覆盖「版本号 + 章 + 装载门槛 + 查询通道」。发布快照、轮换与能力要求属于后续切片，不在本文件假装完成。

#[cfg(feature = "user-programs")]
use core::sync::atomic::{AtomicU32, Ordering};

use crate::kprintln;
#[cfg(feature = "user-programs")]
use kernel_core::abi_version::{self, AbiReject, ProgramAbi};
#[cfg(feature = "user-programs")]
use kernel_core::elf::ElfError;
#[cfg(feature = "user-programs")]
use crate::mm::frame;
#[cfg(feature = "user-programs")]
use crate::proc::{self, LoadError};
#[cfg(feature = "user-programs")]
use crate::syscall::SyscallSet;
#[cfg(feature = "user-programs")]
use crate::kobj;

#[cfg(feature = "user-programs")]
static CHECKS: AtomicU32 = AtomicU32::new(0);
#[cfg(feature = "user-programs")]
static FAILED: AtomicU32 = AtomicU32::new(0);

/// 断言：失败时打印 `[JSR-ABI-FAIL]` 而不是 panic，让其余用例继续运行。
#[cfg(feature = "user-programs")]
fn check(ok: bool, what: &str) {
    CHECKS.fetch_add(1, Ordering::Relaxed);
    if !ok {
        FAILED.fetch_add(1, Ordering::Relaxed);
        kprintln!("[JSR-ABI-FAIL] {}", what);
    }
}

/// 失败断言数。
#[cfg(feature = "user-programs")]
pub fn failed() -> u32 {
    FAILED.load(Ordering::Relaxed)
}

/// 内嵌的用户程序 `user-hello`（与 `user_demo::run_elf` 使用同一份构建产物）。
#[cfg(feature = "user-programs")]
static USER_HELLO: &[u8] = include_bytes!(env!("JSR_USER_HELLO"));

/// 在真实镜像里定位 ABI 章的字节偏移（构建期已保证章存在；找不到说明内嵌产物被换过）。
#[cfg(feature = "user-programs")]
fn note_offset(image: &[u8], note: &[u8; abi_version::NOTE_BYTES]) -> Option<usize> {
    image.windows(note.len()).position(|w| w == note)
}
/// 装载一次并立即回收：返回装载结果与本次装载消耗的页帧数。
///
/// 页帧数用于证明负例「拒绝发生在映射之前」：地址空间新建可能占用页表帧，因此在建好进程之后取基线，
/// 只看 `load_elf` 本身是否消耗了页帧。
#[cfg(feature = "user-programs")]
fn load_once(image: &[u8]) -> Option<(Result<u64, LoadError>, usize)> {
    let Ok(pid) = proc::create("abi-probe", SyscallSet::EMPTY) else {
        check(false, "ABI 演练进程创建失败");
        return None;
    };
    let free_before = frame::free_frames();
    let result = proc::load_elf(pid, image);
    let mapped = free_before.saturating_sub(frame::free_frames());
    let _ = proc::exit_idle(pid, 0);
    proc::reap(pid);
    kobj::run_cleanup(usize::MAX);
    Some((result, mapped))
}

/// 断言一条负例：期望的错误名 + 一页未映射。
#[cfg(feature = "user-programs")]
fn expect_rejected(case: &str, image: &[u8], want: &str, expected: LoadError) {
    match load_once(image) {
        Some((Err(err), mapped)) => {
            check(err == expected, &alloc::format!("{} 的错误类别不符：期望 {:?}，实际 {:?}", case, expected, err));
            check(err.name() == want, &alloc::format!("{} 的错误名不符：期望 {}，实际 {}", case, want, err.name()));
            check(mapped == 0, &alloc::format!("{} 在拒绝前映射了 {} 页", case, mapped));
            kprintln!("[JSR-ABI] case={} reject={} mapped={}", case, err.name(), mapped);
        }
        Some((Ok(entry), _)) => {
            check(false, &alloc::format!("{} 本应被拒绝，却装载成功 entry={:#x}", case, entry));
            kprintln!("[JSR-ABI] case={} reject=accepted mapped=unknown", case);
        }
        None => {}
    }
}

/// 运行 ABI 世代演练。
#[cfg(feature = "user-programs")]
pub fn run() {
    let free_before = frame::free_frames();
    let native = abi_version::NATIVE;

    // 1. 单一真源：运行时读到的文本必须与构建期生成的常量逐字段一致。
    let source = include_str!("../../abi/abi-version.txt");
    let parsed = abi_version::parse_source(source);
    check(parsed == Ok(native), "abi/abi-version.txt 与构建期常量不一致");
    check(native.packed() >> 48 == 0, "打包的 ABI 世代占用了保留高位");
    check(abi_version::AbiVersion::unpack(native.packed()) == Some(native), "ABI 世代打包/解包不是双射");
    kprintln!(
        "[JSR-ABI] native={}.{}.{} packed={:#x} single_source={}",
        native.major,
        native.minor,
        native.patch,
        native.packed(),
        parsed == Ok(native)
    );

    // 2. 真实内嵌镜像必须携带本构建的原生章；这是构建期检查的运行期复核。
    let Some((image, note_at)) = (|| {
        let note = abi_version::encode_note(ProgramAbi::native_requirement());
        let copy = USER_HELLO.to_vec();
        let at = note_offset(&copy, &note)?;
        Some((copy, at))
    })() else {
        check(false, "内嵌 user-hello 未找到原生 ABI 章");
        kprintln!("[JSR-ABI] summary checks={} failed={} reclaimed=false", CHECKS.load(Ordering::Relaxed), failed());
        return;
    };
    let stamp = abi_version::parse_note(&image[note_at..note_at + abi_version::NOTE_BYTES]);
    check(stamp == Ok(ProgramAbi::native_requirement()), "内嵌镜像的 ABI 章与原生要求不一致");
    kprintln!(
        "[JSR-ABI] case=stamp major={} min_minor={} patch={} matches_native={}",
        stamp.map(|s| s.major).unwrap_or(u16::MAX),
        stamp.map(|s| s.min_minor).unwrap_or(u16::MAX),
        stamp.map(|s| s.patch).unwrap_or(u16::MAX),
        stamp == Ok(ProgramAbi::native_requirement())
    );

    // 3. 正例：真实镜像装载成功，入口非 0，装载过程确实映射了页。
    match load_once(&image) {
        Some((Ok(entry), mapped)) => {
            check(entry != 0, "真实镜像的入口为 0");
            check(mapped > 0, "真实镜像装载没有映射任何页");
            kprintln!("[JSR-ABI] case=accepted entry={:#x} mapped={}", entry, mapped);
        }
        Some((Err(err), _)) => {
            check(false, &alloc::format!("真实镜像装载失败：{}", err.name()));
            kprintln!("[JSR-ABI] case=accepted reject={}", err.name());
        }
        None => {}
    }

    // 4a. 缺少 ABI 章：清空节头表偏移（e_shoff）后解析器看到「没有章」，由装载策略以 Missing 拒绝。
    let mut no_note = image.clone();
    let shoff = match crate::arch::ELF_CLASS {
        kernel_core::elf::ElfClass::Elf64 => 40,
        kernel_core::elf::ElfClass::Elf32 => 32,
    };
    let width = match crate::arch::ELF_CLASS {
        kernel_core::elf::ElfClass::Elf64 => 8,
        kernel_core::elf::ElfClass::Elf32 => 4,
    };
    no_note[shoff..shoff + width].fill(0);
    expect_rejected("missing", &no_note, "system.error.abi_metadata", LoadError::Abi(AbiReject::Missing));

    // 4b. 章损坏：改掉名字的首字节；解析层直接拒绝，不会当成「没有章」。
    let mut malformed = image.clone();
    malformed[note_at + 12] = b'X';
    expect_rejected(
        "malformed",
        &malformed,
        "system.error.abi_metadata",
        LoadError::Elf(ElfError::BadAbiNote),
    );

    // 4c. 跨主版本：章本身合法，但主版本不同 ⇒ 明确拒绝，绝不按旧编号猜测语义。
    if let Some(next) = native.major.checked_add(1) {
        let mut major_mismatch = image.clone();
        major_mismatch[note_at + 20..note_at + 22].copy_from_slice(&next.to_le_bytes());
        expect_rejected(
            "major_mismatch",
            &major_mismatch,
            "system.error.abi_mismatch",
            LoadError::Abi(AbiReject::MajorMismatch { program: next, kernel: native.major }),
        );
    }

    // 4d. 同主版本但要求的次版本高于内核：同样在映射前拒绝。
    if let Some(next) = native.minor.checked_add(1) {
        let mut minor_too_new = image.clone();
        minor_too_new[note_at + 22..note_at + 24].copy_from_slice(&next.to_le_bytes());
        expect_rejected(
            "minor_too_new",
            &minor_too_new,
            "system.error.abi_mismatch",
            LoadError::Abi(AbiReject::MinorTooNew { required: next, kernel: native.minor }),
        );
    }

    // 5. 全部负例与正例回收后，页帧回到基线。
    let reclaimed = frame::free_frames() == free_before;
    check(reclaimed, "ABI 演练结束后页帧未回到基线");
    kprintln!(
        "[JSR-ABI] summary checks={} failed={} reclaimed={}",
        CHECKS.load(Ordering::Relaxed),
        failed(),
        reclaimed
    );
}

/// 未内嵌用户程序时如实说明本演练没有运行（不产生假 PASS）。
#[cfg(not(feature = "user-programs"))]
pub fn run() {
    kprintln!("[JSR-STAGE] abi_demo=absent skipped=stamp,loader");
}
