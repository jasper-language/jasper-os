//! Feature-gated native Workload runtime verification.
//!
//! 原生 Workload 运行时验收：真实 Process/Task、私有页、CPU group 和 Ring。

use core::sync::atomic::{AtomicU32, Ordering};

use kernel_core::paging::MapFlags;
use kernel_core::security_domain::DomainKey;
use kernel_core::workload::{ResourceLimits, ResourceUsage, WorkloadState};

use crate::proc::{self, ProcState};
use crate::syscall::{table as abi, SyscallSet};
use crate::{kprintln, sched};

const CODE_OFF: u64 = 0x40_0000;
const EXTRA_OFF: u64 = 0x80_0000;
const STACK_OFF: u64 = 0xC0_0000;

static FAILED: AtomicU32 = AtomicU32::new(0);

fn check(ok: bool, message: &str) {
    if !ok {
        FAILED.fetch_add(1, Ordering::Relaxed);
        kprintln!("[JSR-WORKLOAD] CHECK FAILED: {}", message);
    }
}

pub fn failed() -> u32 {
    FAILED.load(Ordering::Relaxed)
}

fn exit_code() -> [u8; 11] {
    let id = abi::SYSTEM_PROCESS_EXIT as u32;
    let mut code = [0x90; 11];
    code[0] = 0xb8;
    code[1..5].copy_from_slice(&id.to_le_bytes());
    code[5..7].copy_from_slice(&[0x31, 0xff]);
    code[7..9].copy_from_slice(&[0x0f, 0x05]);
    code[9..11].copy_from_slice(&[0x0f, 0x0b]);
    code
}

pub fn run() {
    let base = crate::arch::USER_WINDOW.0;
    let page = kernel_core::frame::FRAME_SIZE as u64;
    let groups_before = sched::live_cpu_groups();
    let frames_before = crate::mm::frame::free_frames();
    let domain = DomainKey {
        id: 0x574f,
        generation: 1,
    };
    let limits = ResourceLimits {
        cpu_permille: 500,
        memory_bytes: 3 * page,
        threads: 1,
        ring_entries: 4,
    };
    let workload = match crate::workload::create(domain, limits) {
        Ok(key) => key,
        Err(error) => {
            check(false, error.name());
            return;
        }
    };
    check(
        crate::workload::transition(workload, WorkloadState::Ready).is_ok(),
        "workload ready",
    );
    check(
        crate::workload::transition(workload, WorkloadState::Running).is_ok(),
        "workload running",
    );
    let calls = SyscallSet::of(&[
        abi::SYSTEM_PROCESS_EXIT as u32,
        abi::SYSTEM_ASYNC_RING_CREATE as u32,
    ]);
    let pid = match proc::create("workload-verify", calls) {
        Ok(pid) => pid,
        Err(error) => {
            kprintln!("[JSR-WORKLOAD] process create failed: {:?}", error);
            check(false, "process create");
            return;
        }
    };
    check(proc::bind_workload(pid, workload), "bind workload");
    check(
        proc::map_new(pid, base + CODE_OFF, MapFlags::USER | MapFlags::EXECUTE).is_ok(),
        "map code",
    );
    check(
        proc::map_new(pid, base + STACK_OFF - page, MapFlags::USER | MapFlags::WRITE).is_ok(),
        "map stack",
    );
    check(
        proc::map_new(pid, base + EXTRA_OFF, MapFlags::USER | MapFlags::WRITE).is_ok(),
        "map third page",
    );
    let before_reject = crate::workload::usage(workload).unwrap_or_default();
    let fourth = proc::map_new(pid, base + EXTRA_OFF + page, MapFlags::USER | MapFlags::WRITE);
    check(fourth.is_err(), "fourth page must exceed memory quota");
    check(
        crate::workload::usage(workload) == Some(before_reject),
        "memory rejection must be atomic",
    );
    check(proc::write(pid, base + CODE_OFF, &exit_code()).is_ok(), "write exit code");

    let ring = crate::ring::create_for(pid, 4);
    check(ring.is_ok(), "first ring fits");
    check(crate::ring::create_for(pid, 1).is_err(), "second ring exceeds quota");
    check(
        crate::workload::usage(workload).is_some_and(|usage| usage.ring_entries == 4),
        "ring usage",
    );
    let first = proc::spawn_thread(
        pid,
        "workload-main",
        base + CODE_OFF,
        base + STACK_OFF,
        0,
        0,
    );
    check(first.is_ok(), "first task");
    check(
        proc::spawn_thread(
            pid,
            "workload-over-limit",
            base + CODE_OFF,
            base + STACK_OFF,
            0,
            0,
        )
        .is_err(),
        "second task exceeds quota",
    );
    if first.is_ok() && ring.is_ok() {
        let settled = sched::run_until(sched::timer_ticks().saturating_add(1000));
        check(settled, "workload process settles");
    }
    check(
        matches!(proc::state(pid), Some(ProcState::Exited { code: 0 })),
        "workload process exits zero",
    );
    let _ = proc::reap(pid);
    crate::kobj::run_cleanup(usize::MAX);
    check(
        crate::workload::usage(workload) == Some(ResourceUsage::default()),
        "all workload usage returns to zero",
    );
    check(
        crate::workload::transition(workload, WorkloadState::Stopping).is_ok(),
        "workload stopping",
    );
    check(
        crate::workload::transition(workload, WorkloadState::Stopped).is_ok(),
        "workload stopped",
    );
    check(crate::workload::destroy(workload).is_ok(), "workload destroy with member unbound");
    check(
        crate::mm::frame::free_frames() == frames_before,
        "frame baseline",
    );
    check(
        sched::live_cpu_groups() == groups_before,
        "CPU group baseline",
    );
    kprintln!(
        "[JSR-WORKLOAD] runtime=true checks_failed={} ring={} task={}",
        failed(),
        ring.map(|handle| handle.raw()).unwrap_or(0),
        first.map(|(task, _)| task.0).unwrap_or(0)
    );
}
