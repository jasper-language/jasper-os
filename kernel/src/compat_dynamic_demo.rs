//! Real unmodified Ubuntu dynamic ELF execution through `ld-linux`.
//!
//! 职责：把真实 Ubuntu `/usr/bin/true` 与未修改的 `ld-linux` 映射到 Jasper 页表，
//! 经 Ring 3 进入解释器，由解释器自行装载 libc、重定位和初始化，最终以退出码 0 结束。
//! Responsibility: map a real Ubuntu PIE and its unmodified interpreter, then transfer to the
//! interpreter itself. The kernel never invokes target constructors or substitutes host execution.

use core::sync::atomic::{AtomicU32, Ordering};

use compat_core::syscall::{LinuxSyscall, LinuxSyscallSet};
use jasper_compat_loader::{
    build_initial_stack, map_image, plan_dynamic_program, run_process_entry,
    stack_input_for_program, ProgramStackInput,
};

use crate::compat_elf::{JasperExecutionBackend, JasperLoaderMemory};
use crate::mm::frame::free_frames;
use crate::proc::{self, ProcState};
use crate::{arch, kobj, kprintln, sched};

static EXECUTABLE: &[u8] = include_bytes!(env!("JSR_UBUNTU_TRUE"));
static INTERPRETER: &[u8] = include_bytes!(env!("JSR_UBUNTU_LD_LINUX"));
static FAILED: AtomicU32 = AtomicU32::new(0);

const EXECUTABLE_BASE: u64 = arch::USER_WINDOW.0 + 0x40_0000;
const INTERPRETER_BASE: u64 = arch::USER_WINDOW.0 + 0x20_0000_0000;
const STACK_TOP: u64 = arch::USER_WINDOW.0 + 0xc0_0000;
const STACK_RESERVE_BYTES: u64 = 64 * kernel_core::frame::FRAME_SIZE;

pub fn failed() -> u32 {
    FAILED.load(Ordering::Relaxed)
}

fn check(ok: bool, stage: &'static str) {
    if !ok {
        FAILED.fetch_add(1, Ordering::Relaxed);
        kprintln!("[JSR-COMPAT-DYNAMIC-FAIL] stage={}", stage);
    }
}

fn cleanup(pid: kernel_core::objtable::ObjId) {
    let _ = proc::reap(pid);
    kobj::run_cleanup(usize::MAX);
}

pub fn run() {
    let frames_before = free_frames();
    let calls_before = crate::syscall::call_count();
    let calls = LinuxSyscallSet::of(&[
        LinuxSyscall::Read,
        LinuxSyscall::Pread64,
        LinuxSyscall::Write,
        LinuxSyscall::WriteV,
        LinuxSyscall::Close,
        LinuxSyscall::OpenAt,
        LinuxSyscall::Fstat,
        LinuxSyscall::NewFstatAt,
        LinuxSyscall::Brk,
        LinuxSyscall::Access,
        LinuxSyscall::ArchPrctl,
        LinuxSyscall::ClockGettime,
        LinuxSyscall::Mmap,
        LinuxSyscall::Munmap,
        LinuxSyscall::Mprotect,
        LinuxSyscall::Futex,
        LinuxSyscall::Exit,
        LinuxSyscall::ExitGroup,
        LinuxSyscall::GetPid,
        LinuxSyscall::GetPpid,
        LinuxSyscall::GetTid,
    ]);
    let Ok(pid) = proc::create_linux("ubuntu-dynamic-true", calls) else {
        check(false, "create");
        report(frames_before, 0, false, false, false, false, false);
        return;
    };

    let executable_plan = match jasper_compat_loader::parse(EXECUTABLE) {
        Ok(plan) => plan,
        Err(_) => {
            check(false, "parse_executable");
            cleanup(pid);
            report(frames_before, 0, false, false, false, false, false);
            return;
        }
    };
    let interpreter_plan = match jasper_compat_loader::parse(INTERPRETER) {
        Ok(plan) => plan,
        Err(_) => {
            check(false, "parse_interpreter");
            cleanup(pid);
            report(frames_before, 0, false, false, false, false, false);
            return;
        }
    };
    check(
        executable_plan.interpreter.as_deref() == Some("/lib64/ld-linux-x86-64.so.2"),
        "pt_interp",
    );
    let dynamic = match plan_dynamic_program(
        &executable_plan,
        &interpreter_plan,
        EXECUTABLE_BASE,
        INTERPRETER_BASE,
        kernel_core::frame::FRAME_SIZE,
    ) {
        Ok(plan) => plan,
        Err(_) => {
            check(false, "dynamic_layout");
            cleanup(pid);
            report(frames_before, 0, false, false, false, false, false);
            return;
        }
    };

    let mut memory = JasperLoaderMemory::new(pid);
    check(
        map_image(&mut memory, EXECUTABLE, &dynamic.executable).is_ok(),
        "map_executable",
    );
    check(
        map_image(&mut memory, INTERPRETER, &dynamic.interpreter).is_ok(),
        "map_interpreter",
    );
    check(crate::linux_vfs::fixture_nonempty(), "libc_fixture");

    let argv0 = b"/usr/bin/true".as_slice();
    let argv = [argv0];
    let random = [0x5au8; 16];
    let stack = stack_input_for_program(ProgramStackInput {
        plan: &executable_plan,
        image: &dynamic.executable,
        interpreter_base: dynamic.interpreter.load_bias,
        stack_top: STACK_TOP,
        argv: &argv,
        envp: &[],
        auxv: &[],
        random: Some(&random),
    })
    .and_then(build_initial_stack);
    check(stack.is_ok(), "initial_stack");

    let mut backend =
        JasperExecutionBackend::with_stack_reserve(pid, "ubuntu-dynamic-true", STACK_RESERVE_BYTES);
    if let Ok(stack) = stack {
        check(
            run_process_entry(&mut backend, &dynamic.execution, stack).is_ok(),
            "transfer_interpreter",
        );
        check(backend.task().is_some(), "thread");
        sched::run();
    }

    let state = proc::state(pid);
    let exited_zero = state == Some(ProcState::Exited { code: 0 });
    let syscall_delta = crate::syscall::call_count().saturating_sub(calls_before);
    let interpreter_entered = syscall_delta > 0;
    check(interpreter_entered, "interpreter_syscall");
    check(exited_zero, "exit_zero");
    cleanup(pid);
    let resources = free_frames() == frames_before;
    check(resources, "resources");
    report(
        frames_before,
        syscall_delta,
        true,
        true,
        interpreter_entered,
        exited_zero,
        resources,
    );
}

fn report(
    frames_before: usize,
    syscall_delta: u32,
    mapped: bool,
    entry_is_interpreter: bool,
    interpreter_entered: bool,
    exited_zero: bool,
    resources: bool,
) {
    kprintln!(
        "[JSR-COMPAT-DYNAMIC] fixture=ubuntu-x86_64 executable=true ld_linux=true libc=true mapped={} entry=interpreter {} interpreter_syscalls={} syscall_delta={} exit_zero={} frames_before={} resources={} failed={}",
        mapped,
        entry_is_interpreter,
        interpreter_entered,
        syscall_delta,
        exited_zero,
        frames_before,
        resources,
        failed()
    );
}
