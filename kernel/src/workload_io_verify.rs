//! Real guest acceptance for Workload-bound Linux file and console I/O.
//!
//! A CPL3 Linux task enters through the normal `int 0x80` path. The kernel
//! charges the Process's bound Workload before user bytes are copied, rolls
//! back failed requests, and rejects the next request after the lifetime
//! byte/op budget is exhausted.

use alloc::vec::Vec;
use core::sync::atomic::{AtomicU32, Ordering};

use compat_core::syscall::{LinuxSyscall, LinuxSyscallSet};
use kernel_core::paging::MapFlags;
use kernel_core::security_domain::DomainKey;
use kernel_core::workload::{IoRateLimits, IoUsage, ResourceLimits, ResourceUsage, WorkloadState};

use crate::proc::{self, ProcState};
use crate::{kprintln, sched};

const CODE_OFF: u64 = 0x40_0000;
const DATA_OFF: u64 = 0x80_0000;
const STACK_OFF: u64 = 0xC0_0000;
const PATH_OFF: u64 = 0x100;
const PAYLOAD_OFF: u64 = 0x200;
const READ_BUFFER_OFF: u64 = 0x400;
const RATE_TIMESPEC_OFF: u64 = 0x300;

const IO_BYTES: u64 = 11;
const IO_OPS: u64 = 3;
const RATE_IO_BYTES: u64 = 4;
const RATE_IO_OPS: u64 = 3;
const RATE_WINDOW_NS: u64 = 100_000_000;

static FAILED: AtomicU32 = AtomicU32::new(0);

pub fn failed() -> u32 {
    FAILED.load(Ordering::Relaxed)
}

fn check(ok: bool, stage: &'static str) {
    if !ok {
        FAILED.fetch_add(1, Ordering::Relaxed);
        kprintln!("[JSR-WORKLOAD-IO-FAIL] stage={}", stage);
    }
}

fn imm32(code: &mut Vec<u8>, opcode: u8, value: u32) {
    code.push(opcode);
    code.extend_from_slice(&value.to_le_bytes());
}

fn imm64(code: &mut Vec<u8>, opcode: u8, value: u64) {
    code.extend_from_slice(&[0x48, opcode]);
    code.extend_from_slice(&value.to_le_bytes());
}

fn syscall(code: &mut Vec<u8>) {
    code.extend_from_slice(&[0x0f, 0x05]);
}

fn cmp_rax(code: &mut Vec<u8>, value: i32) {
    code.extend_from_slice(&[0x48, 0x3d]);
    code.extend_from_slice(&value.to_le_bytes());
}

fn jne_failure(code: &mut Vec<u8>, patches: &mut Vec<usize>) {
    code.extend_from_slice(&[0x0f, 0x85, 0, 0, 0, 0]);
    patches.push(code.len() - 4);
}

fn guest_code(base: u64) -> Vec<u8> {
    let path = base + DATA_OFF + PATH_OFF;
    let payload = base + DATA_OFF + PAYLOAD_OFF;
    let buffer = base + DATA_OFF + READ_BUFFER_OFF;
    let mut code = Vec::new();
    let mut patches = Vec::new();

    // openat(AT_FDCWD, path, O_RDONLY)
    imm32(&mut code, 0xb8, 257);
    imm64(&mut code, 0xbf, (-100i64) as u64);
    imm64(&mut code, 0xbe, path);
    code.extend_from_slice(&[0x31, 0xd2]); // xor edx, edx
    syscall(&mut code);
    imm32(&mut code, 0xbf, 0x81);
    cmp_rax(&mut code, 3);
    jne_failure(&mut code, &mut patches);
    code.extend_from_slice(&[0x41, 0x89, 0xc4]); // mov r12d, eax

    // read(fd, buffer, 8) must consume eight bytes and one operation.
    code.extend_from_slice(&[0x31, 0xc0]); // xor eax, eax
    code.extend_from_slice(&[0x44, 0x89, 0xe7]); // mov edi, r12d
    imm64(&mut code, 0xbe, buffer);
    imm32(&mut code, 0xba, 8);
    syscall(&mut code);
    imm32(&mut code, 0xbf, 0x82);
    cmp_rax(&mut code, 8);
    jne_failure(&mut code, &mut patches);

    // A failed copy still reserves first; EFAULT must roll the reservation back.
    code.extend_from_slice(&[0x31, 0xc0]);
    code.extend_from_slice(&[0x44, 0x89, 0xe7]);
    imm64(&mut code, 0xbe, 1);
    imm32(&mut code, 0xba, 1);
    syscall(&mut code);
    imm32(&mut code, 0xbf, 0x83);
    cmp_rax(&mut code, -14);
    jne_failure(&mut code, &mut patches);

    // Failed console copy from an unmapped source, likewise with rollback.
    imm32(&mut code, 0xb8, 1);
    imm32(&mut code, 0xbf, 1);
    imm64(&mut code, 0xbe, 1);
    imm32(&mut code, 0xba, 2);
    syscall(&mut code);
    imm32(&mut code, 0xbf, 0x84);
    cmp_rax(&mut code, -14);
    jne_failure(&mut code, &mut patches);

    // Two successful console writes reach the exact 11-byte, 3-op budget.
    imm32(&mut code, 0xb8, 1);
    imm32(&mut code, 0xbf, 1);
    imm64(&mut code, 0xbe, payload);
    imm32(&mut code, 0xba, 2);
    syscall(&mut code);
    imm32(&mut code, 0xbf, 0x85);
    cmp_rax(&mut code, 2);
    jne_failure(&mut code, &mut patches);

    imm32(&mut code, 0xb8, 1);
    imm32(&mut code, 0xbf, 1);
    imm64(&mut code, 0xbe, payload + 2);
    imm32(&mut code, 0xba, 1);
    syscall(&mut code);
    imm32(&mut code, 0xbf, 0x86);
    cmp_rax(&mut code, 1);
    jne_failure(&mut code, &mut patches);

    // The next two operations must both fail with ENOSPC and have no side effects.
    for stage in 0x87..=0x88 {
        imm32(&mut code, 0xb8, 1);
        imm32(&mut code, 0xbf, 1);
        imm64(&mut code, 0xbe, payload + 3);
        imm32(&mut code, 0xba, 1);
        syscall(&mut code);
        imm32(&mut code, 0xbf, stage);
        cmp_rax(&mut code, -28);
        jne_failure(&mut code, &mut patches);
    }

    // close(fd)
    imm32(&mut code, 0xb8, 3);
    code.extend_from_slice(&[0x44, 0x89, 0xe7]);
    syscall(&mut code);
    imm32(&mut code, 0xbf, 0x89);
    cmp_rax(&mut code, 0);
    jne_failure(&mut code, &mut patches);

    // exit_group(0)
    imm32(&mut code, 0xb8, 231);
    code.extend_from_slice(&[0x31, 0xff]); // xor edi, edi
    syscall(&mut code);
    code.extend_from_slice(&[0x0f, 0x0b]);

    let failure = code.len();
    imm32(&mut code, 0xb8, 231);
    syscall(&mut code);
    code.extend_from_slice(&[0x0f, 0x0b]);
    for patch in patches {
        let end = patch + 4;
        let displacement = (failure as i64 - end as i64) as i32;
        code[patch..end].copy_from_slice(&displacement.to_le_bytes());
    }
    code
}

fn rate_guest_code(base: u64) -> Vec<u8> {
    let payload = base + DATA_OFF + PAYLOAD_OFF;
    let timespec = base + DATA_OFF + RATE_TIMESPEC_OFF;
    let mut code = Vec::new();
    let mut patches = Vec::new();

    // First two bytes consume the entire first-window byte allowance.
    imm32(&mut code, 0xb8, 1);
    imm32(&mut code, 0xbf, 1);
    imm64(&mut code, 0xbe, payload);
    imm32(&mut code, 0xba, 2);
    syscall(&mut code);
    imm32(&mut code, 0xbf, 0x91);
    cmp_rax(&mut code, 2);
    jne_failure(&mut code, &mut patches);

    // The same window rejects a third byte without consuming lifetime budget.
    imm32(&mut code, 0xb8, 1);
    imm32(&mut code, 0xbf, 1);
    imm64(&mut code, 0xbe, payload + 2);
    imm32(&mut code, 0xba, 1);
    syscall(&mut code);
    imm32(&mut code, 0xbf, 0x92);
    cmp_rax(&mut code, -28);
    jne_failure(&mut code, &mut patches);

    // Wait beyond one bounded window on the kernel monotonic clock.
    imm32(&mut code, 0xb8, 230); // clock_nanosleep
    imm32(&mut code, 0xbf, 1); // CLOCK_MONOTONIC
    code.extend_from_slice(&[0x31, 0xf6]); // xor esi, esi
    imm64(&mut code, 0xba, timespec);
    code.extend_from_slice(&[0x45, 0x31, 0xd2]); // xor r10d, r10d
    syscall(&mut code);
    imm32(&mut code, 0xbf, 0x93);
    cmp_rax(&mut code, 0);
    jne_failure(&mut code, &mut patches);

    // A new window admits two bytes in separate syscalls.
    for stage in 0x94..=0x95 {
        imm32(&mut code, 0xb8, 1);
        imm32(&mut code, 0xbf, 1);
        imm64(&mut code, 0xbe, payload + 2);
        imm32(&mut code, 0xba, 1);
        syscall(&mut code);
        imm32(&mut code, 0xbf, stage);
        cmp_rax(&mut code, 1);
        jne_failure(&mut code, &mut patches);
    }

    // The lifetime operation budget, not the rate window, now rejects.
    imm32(&mut code, 0xb8, 1);
    imm32(&mut code, 0xbf, 1);
    imm64(&mut code, 0xbe, payload + 2);
    imm32(&mut code, 0xba, 1);
    syscall(&mut code);
    imm32(&mut code, 0xbf, 0x96);
    cmp_rax(&mut code, -28);
    jne_failure(&mut code, &mut patches);

    imm32(&mut code, 0xb8, 231);
    code.extend_from_slice(&[0x31, 0xff]);
    syscall(&mut code);
    code.extend_from_slice(&[0x0f, 0x0b]);

    let failure = code.len();
    imm32(&mut code, 0xb8, 231);
    syscall(&mut code);
    code.extend_from_slice(&[0x0f, 0x0b]);
    for patch in patches {
        let end = patch + 4;
        let displacement = (failure as i64 - end as i64) as i32;
        code[patch..end].copy_from_slice(&displacement.to_le_bytes());
    }
    code
}

fn cleanup(pid: kernel_core::objtable::ObjId) {
    let _ = proc::exit_idle(pid, -1);
    let _ = proc::reap(pid);
    crate::kobj::run_cleanup(usize::MAX);
}

fn run_rate_window(base: u64, page: u64) {
    let frames_before = crate::mm::frame::free_frames();
    let rollback_failures_before = crate::workload::io_rollback_failures();
    let workload = match crate::workload::create(
        DomainKey {
            id: 0x574f_1a1,
            generation: 1,
        },
        ResourceLimits {
            cpu_permille: 100,
            memory_bytes: 8 * page,
            threads: 1,
            ring_entries: 1,
            io_bytes: RATE_IO_BYTES,
            io_ops: RATE_IO_OPS,
        },
    ) {
        Ok(workload) => workload,
        Err(error) => {
            check(false, error.name());
            return;
        }
    };
    let rate = IoRateLimits {
        bytes_per_window: 2,
        ops_per_window: 2,
        window_ns: RATE_WINDOW_NS,
    };
    check(
        crate::workload::configure_io_rate(workload, rate).is_ok(),
        "rate_config",
    );
    check(
        crate::workload::transition(workload, WorkloadState::Ready).is_ok()
            && crate::workload::transition(workload, WorkloadState::Running).is_ok(),
        "rate_workload_start",
    );
    let calls = LinuxSyscallSet::of(&[
        LinuxSyscall::Write,
        LinuxSyscall::ClockNanosleep,
        LinuxSyscall::ExitGroup,
    ]);
    let pid = match proc::create_linux("workload-rate-guest", calls) {
        Ok(pid) => pid,
        Err(_) => {
            check(false, "rate_process_create");
            return;
        }
    };
    check(proc::bind_workload(pid, workload), "rate_bind_workload");
    check(
        proc::map_new(pid, base + CODE_OFF, MapFlags::USER | MapFlags::EXECUTE).is_ok()
            && proc::map_new(pid, base + DATA_OFF, MapFlags::USER | MapFlags::WRITE).is_ok()
            && proc::map_new(
                pid,
                base + STACK_OFF - page,
                MapFlags::USER | MapFlags::WRITE,
            )
            .is_ok(),
        "rate_map_guest",
    );
    let code = rate_guest_code(base);
    check(
        proc::write(pid, base + CODE_OFF, &code).is_ok(),
        "rate_write_code",
    );
    let mut data = [0u8; 4096];
    data[PAYLOAD_OFF as usize..PAYLOAD_OFF as usize + 3].copy_from_slice(b"RST");
    data[RATE_TIMESPEC_OFF as usize + 8..RATE_TIMESPEC_OFF as usize + 16]
        .copy_from_slice(&(2 * RATE_WINDOW_NS).to_le_bytes());
    check(
        proc::write(pid, base + DATA_OFF, &data).is_ok(),
        "rate_write_data",
    );
    let task = proc::spawn_thread(
        pid,
        "workload-rate-guest",
        base + CODE_OFF,
        base + STACK_OFF,
        0,
        0,
    );
    check(task.is_ok(), "rate_task_start");
    if task.is_ok() {
        check(
            sched::run_until(sched::timer_ticks().saturating_add(2000)),
            "rate_task_settles",
        );
    }
    check(
        matches!(proc::state(pid), Some(ProcState::Exited { code: 0 })),
        "rate_guest_exit_zero",
    );
    let lifetime_usage = crate::workload::snapshot(workload)
        .ok()
        .map(|snapshot| snapshot.io_usage)
        .unwrap_or_default();
    let lifetime_ok = lifetime_usage
        == IoUsage {
            bytes: RATE_IO_BYTES,
            ops: RATE_IO_OPS,
        };
    check(lifetime_ok, "rate_exact_lifetime_usage");
    let rate_snapshot = crate::workload::io_rate_snapshot(workload).ok();
    let window_bytes = rate_snapshot
        .as_ref()
        .map_or(0, |snapshot| snapshot.usage.bytes);
    let window_ops = rate_snapshot
        .as_ref()
        .map_or(0, |snapshot| snapshot.usage.ops);
    let window_active = rate_snapshot
        .as_ref()
        .is_some_and(|snapshot| snapshot.limits == Some(rate) && snapshot.window_active);
    let window_ok = window_active && window_bytes == 2 && window_ops == 2;
    check(window_ok, "rate_window_usage");
    kprintln!(
        "[JSR-WORKLOAD-IO-RATE] runtime={} window_elapsed_recovery={} lifetime_enforced={} bytes={} ops={} window_bytes={} window_ops={} failed={}",
        lifetime_ok && window_ok,
        window_ok,
        lifetime_ok,
        lifetime_usage.bytes,
        lifetime_usage.ops,
        window_bytes,
        window_ops,
        failed()
    );
    cleanup(pid);
    check(
        crate::workload::usage(workload) == Some(ResourceUsage::default()),
        "rate_held_resources_reclaimed",
    );
    check(
        crate::workload::io_rollback_failures() == rollback_failures_before,
        "rate_rollback_accounting",
    );
    check(
        crate::workload::transition(workload, WorkloadState::Stopping).is_ok()
            && crate::workload::transition(workload, WorkloadState::Stopped).is_ok()
            && crate::workload::destroy(workload).is_ok(),
        "rate_workload_destroy",
    );
    check(
        crate::mm::frame::free_frames() == frames_before,
        "rate_frame_baseline",
    );
}

pub fn run() {
    let base = crate::arch::USER_WINDOW.0;
    let page = kernel_core::frame::FRAME_SIZE as u64;
    let frames_before = crate::mm::frame::free_frames();
    let rollback_failures_before = crate::workload::io_rollback_failures();
    let domain = DomainKey {
        id: 0x574f_1a0,
        generation: 1,
    };
    let workload = match crate::workload::create(
        domain,
        ResourceLimits {
            cpu_permille: 100,
            memory_bytes: 8 * page,
            threads: 1,
            ring_entries: 1,
            io_bytes: IO_BYTES,
            io_ops: IO_OPS,
        },
    ) {
        Ok(workload) => workload,
        Err(error) => {
            check(false, error.name());
            return report(frames_before);
        }
    };
    check(
        crate::workload::transition(workload, WorkloadState::Ready).is_ok()
            && crate::workload::transition(workload, WorkloadState::Running).is_ok(),
        "workload_start",
    );
    let calls = LinuxSyscallSet::of(&[
        LinuxSyscall::OpenAt,
        LinuxSyscall::Read,
        LinuxSyscall::Write,
        LinuxSyscall::Close,
        LinuxSyscall::ExitGroup,
    ]);
    let pid = match proc::create_linux("workload-io-guest", calls) {
        Ok(pid) => pid,
        Err(_) => {
            check(false, "process_create");
            return report(frames_before);
        }
    };
    check(proc::bind_workload(pid, workload), "bind_workload");
    check(
        proc::map_new(pid, base + CODE_OFF, MapFlags::USER | MapFlags::EXECUTE).is_ok()
            && proc::map_new(pid, base + DATA_OFF, MapFlags::USER | MapFlags::WRITE).is_ok()
            && proc::map_new(
                pid,
                base + STACK_OFF - page,
                MapFlags::USER | MapFlags::WRITE,
            )
            .is_ok(),
        "map_guest",
    );

    let code = guest_code(base);
    check(
        proc::write(pid, base + CODE_OFF, &code).is_ok(),
        "write_code",
    );
    let mut data = [0u8; 4096];
    let path = b"/io-probe\0";
    data[PATH_OFF as usize..PATH_OFF as usize + path.len()].copy_from_slice(path);
    data[PAYLOAD_OFF as usize..PAYLOAD_OFF as usize + 3].copy_from_slice(b"JQx");
    check(
        proc::write(pid, base + DATA_OFF, &data).is_ok(),
        "write_data",
    );
    let task = proc::spawn_thread(
        pid,
        "workload-io-guest",
        base + CODE_OFF,
        base + STACK_OFF,
        0,
        0,
    );
    check(task.is_ok(), "task_start");
    if task.is_ok() {
        check(
            sched::run_until(sched::timer_ticks().saturating_add(2000)),
            "task_settles",
        );
    }
    check(
        matches!(proc::state(pid), Some(ProcState::Exited { code: 0 })),
        "guest_exit_zero",
    );
    let mut file_bytes = [0u8; 8];
    check(
        proc::read(pid, base + DATA_OFF + READ_BUFFER_OFF, &mut file_bytes).is_ok()
            && file_bytes == *b"JASPERIO",
        "file_bytes",
    );
    let io_usage = crate::workload::snapshot(workload)
        .ok()
        .map(|snapshot| snapshot.io_usage);
    check(
        io_usage
            == Some(IoUsage {
                bytes: IO_BYTES,
                ops: IO_OPS,
            }),
        "exact_io_usage",
    );
    cleanup(pid);
    check(
        crate::workload::usage(workload) == Some(ResourceUsage::default()),
        "held_resources_reclaimed",
    );
    check(
        crate::workload::io_rollback_failures() == rollback_failures_before,
        "rollback_accounting",
    );
    check(
        crate::workload::transition(workload, WorkloadState::Stopping).is_ok()
            && crate::workload::transition(workload, WorkloadState::Stopped).is_ok()
            && crate::workload::destroy(workload).is_ok(),
        "workload_destroy",
    );
    run_rate_window(base, page);
    report(frames_before);
}

fn report(frames_before: usize) {
    let frames = crate::mm::frame::free_frames() == frames_before;
    check(frames, "frame_baseline");
    kprintln!(
        "[JSR-WORKLOAD-IO] runtime=true file_read=true console_write=true quota_rejected=true rollback=true io_bytes={} io_ops={} frames_before={} resources={} failed={}",
        IO_BYTES,
        IO_OPS,
        frames_before,
        frames,
        failed()
    );
}
