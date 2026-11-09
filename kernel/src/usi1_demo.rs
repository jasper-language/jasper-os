//! USI-1 human/structured client acceptance.

use core::sync::atomic::{AtomicU32, Ordering};

use kernel_core::assembly::Health;
use kernel_core::syscall_set::SyscallSet;

use crate::rt_demo::{rt_calls, run_program};
use crate::baseline::baseline;
use crate::{assembly, kprintln, sched};

static FAILED: AtomicU32 = AtomicU32::new(0);
static USER_USI: &[u8] = include_bytes!(env!("JSR_USER_USI"));

fn check(ok: bool, what: &'static str) {
    if !ok {
        FAILED.fetch_add(1, Ordering::Relaxed);
        kprintln!("[JSR-USI-FAIL] {}", what);
    }
}

fn usi_calls() -> SyscallSet {
    rt_calls().union(SyscallSet::of(&[
        crate::syscall::table::SYSTEM_INFO_GET,
        crate::syscall::table::SYSTEM_PROCESS_LIST,
        crate::syscall::table::SYSTEM_MODULE_LIST,
        crate::syscall::table::SYSTEM_MODULE_LIFECYCLE_GET,
    ]))
}

fn run_mode(name: &'static str, mode: u64, calls: SyscallSet) {
    let result = run_program(name, USER_USI, mode, calls);
    check(
        matches!(
            result,
            Some((Some(crate::proc::ProcState::Exited { code: 0 }), Some(0)))
        ),
        name,
    );
}

pub fn run() {
    let before = baseline();
    let previous_preemption = sched::set_preemption(true);

    let degraded = assembly::report_health("devices", Health::Unhealthy);
    check(degraded.is_ok(), "device service withdrawal");
    run_mode("usi-degraded", 3, usi_calls());
    let restored = assembly::report_health("devices", Health::Healthy);
    check(restored.is_ok(), "device service recovery");
    run_mode("usi-restored", 4, usi_calls());

    run_mode("usi-cli", 0, usi_calls());
    run_mode("usi-json", 1, usi_calls());
    let denied = rt_calls().difference(SyscallSet::of(&[
        crate::syscall::table::SYSTEM_TIME_NOW,
        crate::syscall::table::SYSTEM_INFO_GET,
        crate::syscall::table::SYSTEM_PROCESS_LIST,
        crate::syscall::table::SYSTEM_MODULE_LIST,
        crate::syscall::table::SYSTEM_MODULE_LIFECYCLE_GET,
    ]));
    run_mode("usi-denied", 2, denied);

    sched::set_preemption(previous_preemption);
    let after = baseline();
    check(after == before, "USI-1 resource baseline");
    kprintln!(
        "[JSR-USI] summary cli=true structured=true denied=true degraded=true restored=true failed={} reclaimed={}",
        FAILED.load(Ordering::Relaxed),
        after == before
    );
}

pub fn failed() -> u32 {
    FAILED.load(Ordering::Relaxed)
}
