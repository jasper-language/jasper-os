//! L10N-1 演练：登记表的中英显示名与由登记表生成的错误渲染表。
//! L10N-1 drill: bilingual display names in the registry and the generated error-text table.
//!
//! # 职责
//! 在真实内核里验证构建期生成的两份数据彼此一致，并且错误渲染按预期工作：
//! 1. 错误渲染表与登记表中的 `error` 条目数量一致、按 ID 严格升序、每条中英文本都非空；
//! 2. 同一个错误码分别渲染中文与英文，文本与登记表（`ENTRIES`）逐字一致；
//! 3. 非错误返回值（`ret >= 0`）被拒绝；
//! 4. 未登记的 ID（[`UNKNOWN_ID`]）被拒绝，并先断言它确实不在登记表中；
//! 5. 每个操作条目都带非空英文显示名。
//!
//! # 边界
//! 只做查找与比对：不打印手写的期望英文文本，期望值一律从生成表按 ID 取出。
//! 演练没有全局可变状态；计数只用于本模块内部的成功/失败汇总。
//!
//! # 为什么单独成演练
//! 错误文本表由构建脚本生成，只有真实启动一次才能证明「登记表 → 生成代码 → 运行时渲染」整条链路一致。
//! This drill proves the registry → generated table → runtime rendering chain inside a real boot.

use core::sync::atomic::{AtomicU32, Ordering};

use kernel_core::l10n::{render_error, table_is_sorted_unique, Lang, RenderError};

use crate::kprintln;
use crate::syscall::table::{self as abi, AbiKind, ERROR_TEXTS};

/// 一个刻意不登记的 ID：用于验证未知错误码被拒绝。
const UNKNOWN_ID: u32 = 4095;

static CHECKS: AtomicU32 = AtomicU32::new(0);
static FAILED: AtomicU32 = AtomicU32::new(0);

/// 记录一次断言；失败时打印原因并计数。
fn check(ok: bool, what: &str) {
    CHECKS.fetch_add(1, Ordering::Relaxed);
    if !ok {
        FAILED.fetch_add(1, Ordering::Relaxed);
        kprintln!("[JSR-L10N-FAIL] {}", what);
    }
}

/// 本演练的失败断言数。
pub fn failed() -> u32 {
    FAILED.load(Ordering::Relaxed)
}

/// 登记表中 `error` 条目的数量。
fn error_count() -> usize {
    abi::ENTRIES.iter().filter(|e| e.kind == AbiKind::Error).count()
}

/// 渲染一个错误码，并把它与登记表里的期望文本（按 ID 取出）比对，然后打印一行结果。
fn render_case(code: u32) {
    let expected = abi::entry(code);
    let (ok, zh, en) = match (
        expected,
        render_error(ERROR_TEXTS, -(code as i64), Lang::Zh),
        render_error(ERROR_TEXTS, -(code as i64), Lang::En),
    ) {
        (Some(e), Ok(zh), Ok(en)) => (zh == e.display_zh && en == e.display_en, zh, en),
        _ => (false, "", ""),
    };
    check(ok, "错误码的中英渲染必须与登记表一致");
    kprintln!("[JSR-L10N] render code={} zh={} en={} ok={}", code, zh, en, ok);
}

/// 演练入口。
pub fn run() {
    let errors = error_count();
    let sorted = table_is_sorted_unique(ERROR_TEXTS);
    let complete = ERROR_TEXTS.iter().all(|e| !e.zh.is_empty() && !e.en.is_empty());
    check(errors > 0, "登记表必须至少有一个错误条目");
    check(errors == ERROR_TEXTS.len(), "错误渲染表必须覆盖登记表中的全部错误条目");
    check(sorted, "错误渲染表必须按 ID 严格升序且无重复");
    check(complete, "每条错误文本的中文与英文都必须非空");
    kprintln!("[JSR-L10N] table errors={} sorted={} complete={}", errors, sorted, complete);

    // 同一个错误码分别渲染两种语言；期望文本从生成表按 ID 取出，不手写英文。
    render_case(4098);
    render_case(4101);

    let not_error = render_error(ERROR_TEXTS, 0, Lang::Zh) == Err(RenderError::NotAnError);
    check(not_error, "返回值 0 不是错误，必须被拒绝");
    kprintln!("[JSR-L10N] reject case=not_error ret=0 ok={}", not_error);

    let absent = abi::entry(UNKNOWN_ID).is_none() && !ERROR_TEXTS.iter().any(|e| e.id == UNKNOWN_ID);
    check(absent, "未知错误码的探针 ID 必须不在登记表中");
    let unknown = render_error(ERROR_TEXTS, -(UNKNOWN_ID as i64), Lang::En) == Err(RenderError::Unknown { id: UNKNOWN_ID });
    check(unknown, "未登记的错误码必须被拒绝");
    kprintln!("[JSR-L10N] reject case=unknown id={} ok={}", UNKNOWN_ID, unknown);

    let mut named = 0usize;
    let mut all_en = true;
    for e in abi::ENTRIES.iter().filter(|e| e.kind == AbiKind::Op) {
        named += 1;
        if e.display_en.is_empty() {
            all_en = false;
        }
    }
    check(named > 0, "登记表必须至少有一个操作条目");
    check(all_en, "每个操作条目都必须有英文显示名");
    kprintln!("[JSR-L10N] ops named={} all_en={}", named, all_en);

    kprintln!("[JSR-L10N] summary checks={} failed={}", CHECKS.load(Ordering::Relaxed), failed());
}
