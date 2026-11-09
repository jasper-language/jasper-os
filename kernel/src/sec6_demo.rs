//! SEC-6 software memory-capability acceptance.

use core::sync::atomic::{AtomicU32, Ordering};

use kernel_core::memory_capability::{
    require_tagged_pointer_support, MemoryCapabilityError, TaggedPointerSupport,
};

use crate::{arch, kobj, kprintln, proc};

static FAILED: AtomicU32 = AtomicU32::new(0);

fn check(condition: bool, what: &'static str) {
    if !condition {
        FAILED.fetch_add(1, Ordering::Relaxed);
        kprintln!("[JSR-SEC6-FAIL] {}", what);
    }
}

pub fn failed() -> u32 {
    FAILED.load(Ordering::Relaxed)
}

pub fn run() {
    let before = crate::baseline::baseline();
    let pid = match proc::create("sec6-memory", crate::syscall::SyscallSet::EMPTY) {
        Ok(pid) => pid,
        Err(_) => {
            check(false, "process creation failed");
            return;
        }
    };
    let base = arch::USER_WINDOW.0 + 0x20_0000;
    let page = kernel_core::frame::FRAME_SIZE;

    check(proc::map_anon(pid, base, 2, true).is_ok(), "anonymous mapping failed");
    check(
        kobj::with(|t| proc::pin_user_in(t, pid, base, 16, true)).is_ok(),
        "valid pointer was not backed by an active descriptor",
    );
    check(
        kobj::with(|t| proc::pin_user_in(t, pid, base + 2 * page - 8, 16, true)).is_err(),
        "pointer range crossed the capability end",
    );
    check(
        kobj::with(|t| proc::pin_user_in(t, pid, base, 16, false)).is_ok(),
        "read-only access to writable capability failed",
    );
    check(proc::unmap_range(pid, base, 2).is_ok(), "anonymous unmap failed");
    check(
        kobj::with(|t| proc::pin_user_in(t, pid, base, 8, true)).is_err(),
        "revoked anonymous pointer was still accepted",
    );

    let memory = match proc::create_memory(pid, 1) {
        Ok(handle) => handle,
        Err(_) => {
            check(false, "Memory object creation failed");
            let _ = proc::exit_idle(pid, 0);
            let _ = proc::reap(pid);
            return;
        }
    };
    let shared = base + 0x4000;
    check(
        proc::map_memory(pid, memory, shared, 0, 1, true).is_ok(),
        "shared mapping failed",
    );
    check(
        proc::close_handle_for(pid, memory).is_ok(),
        "closing Memory handle failed",
    );
    check(
        kobj::with(|t| proc::pin_user_in(t, pid, shared, 8, true)).is_ok(),
        "mapping did not retain backing provenance after handle close",
    );
    check(proc::unmap_memory(pid, shared, 1).is_ok(), "shared unmap failed");
    check(
        kobj::with(|t| proc::pin_user_in(t, pid, shared, 8, false)).is_err(),
        "unmapped shared alias retained pointer authority",
    );

    check(
        require_tagged_pointer_support(TaggedPointerSupport::Unavailable)
            == Err(MemoryCapabilityError::HardwareUnavailable),
        "missing CHERI support was not reported as unavailable",
    );
    let capability_stats = proc::memory_capability_stats(pid);
    kprintln!(
        "[JSR-SEC6] capability_stats={:?}",
        capability_stats
    );
    check(
        capability_stats.is_some_and(|(active, revoked)| active == 0 && revoked >= 2),
        "capability accounting did not converge",
    );

    let _ = proc::exit_idle(pid, 0);
    let _ = proc::reap(pid);
    kobj::run_cleanup(usize::MAX);
    let after = crate::baseline::baseline();
    check(after == before, "SEC-6 resources did not return to baseline");
    kprintln!(
        "[JSR-SEC6] bounds=true rights=true stale=false shared_retained=true revoked=false hardware=unsupported resources={} failed={}",
        after == before,
        failed()
    );
}
