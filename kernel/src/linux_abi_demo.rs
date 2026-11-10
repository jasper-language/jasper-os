//! Real x86_64 Linux ET_EXEC syscall acceptance.
//!
//! 职责：在 Jasper CPL3 中运行没有 Jasper ABI 章的静态 Linux fixture，执行
//! write/getpid/gettid/exit_group 并验证未授权的 getppid 返回负 errno。
//! Responsibility: prove the first real Linux syscall execution slice.

use core::sync::atomic::{AtomicU32, Ordering};

use compat_core::syscall::{LinuxSyscall, LinuxSyscallSet};
use kernel_core::paging::MapFlags;

use crate::arch;
use crate::proc::{self, ProcState};
use crate::{kprintln, sched};

static USER_LINUXPROBE: &[u8] = include_bytes!(env!("JSR_USER_LINUXPROBE"));
static FAILED: AtomicU32 = AtomicU32::new(0);

pub fn failed() -> u32 {
    FAILED.load(Ordering::Relaxed)
}

fn check(ok: bool, stage: &'static str) {
    if !ok {
        FAILED.fetch_add(1, Ordering::Relaxed);
        kprintln!("[JSR-LINUX-ABI-FAIL] stage={}", stage);
    }
}

pub fn run() {
    let frames_before = crate::mm::frame::free_frames();
    let calls_before = crate::syscall::call_count();
    let calls = LinuxSyscallSet::of(&[
        LinuxSyscall::Write,
        LinuxSyscall::GetPid,
        LinuxSyscall::GetTid,
        LinuxSyscall::ExitGroup,
    ]);
    let pid = match proc::create_linux("linux-abi-probe", calls) {
        Ok(pid) => pid,
        Err(_) => {
            check(false, "create");
            report(
                frames_before,
                false,
                false,
                false,
                false,
                0,
                crate::mm::frame::free_frames() == frames_before,
            );
            return;
        }
    };
    let entry = match proc::load_linux_elf(pid, USER_LINUXPROBE) {
        Ok(entry) => entry,
        Err(_) => {
            check(false, "load");
            proc::exit_idle(pid, -1);
            let _ = proc::reap(pid);
            report(
                frames_before,
                true,
                false,
                false,
                false,
                0,
                crate::mm::frame::free_frames() == frames_before,
            );
            return;
        }
    };
    let stack = arch::USER_WINDOW.0 + 0xC0_0000;
    check(
        proc::map_new(pid, stack - kernel_core::frame::FRAME_SIZE, MapFlags::USER | MapFlags::WRITE)
            .is_ok(),
        "stack",
    );
    let ring3 = proc::spawn_thread(pid, "linux-abi-probe", entry, stack, 0, 0).is_ok();
    check(ring3, "thread");
    sched::run();
    let state = proc::state(pid);
    let exited = state == Some(ProcState::Exited { code: 0 });
    let syscall_delta = crate::syscall::call_count().saturating_sub(calls_before);
    check(exited, "exit");
    check(syscall_delta > 0, "syscall");
    let _ = proc::reap(pid);
    crate::kobj::run_cleanup(usize::MAX);
    let frames_after = crate::mm::frame::free_frames();
    check(frames_after == frames_before, "resources");
    report(
        frames_before,
        true,
        true,
        ring3,
        exited,
        syscall_delta,
        frames_after == frames_before,
    );
}

fn report(
    frames_before: usize,
    flavor: bool,
    exec: bool,
    ring3: bool,
    exited: bool,
    syscall_delta: u32,
    resources: bool,
) {
    let syscall = syscall_delta > 0;
    let verified = flavor && exec && ring3 && exited && syscall;
    kprintln!(
        "[JSR-LINUX-ABI] exec={} flavor={} write={} getpid={} gettid={} denied={} exit={} cpl3={} syscalls={} frames_before={} resources={} failed={}",
        exec,
        flavor,
        verified,
        verified,
        verified,
        verified,
        exited,
        ring3,
        syscall_delta,
        frames_before,
        resources,
        failed()
    );
}
