//! Real unmodified Ubuntu dynamic ELF execution through `ld-linux`.
//!
//! 职责：运行未修改的 Ubuntu `true` 与 `getconf`，由上游 `ld-linux` 装载真实
//! libc，完成重定位、TLS 和初始化。
//! Responsibility: run unmodified Ubuntu fixtures through the upstream interpreter,
//! Jasper page tables, Ring 3 and Linux syscall compatibility.

use core::sync::atomic::{AtomicU32, Ordering};

use compat_core::syscall::{LinuxSyscall, LinuxSyscallSet};
use jasper_compat_loader::{
    build_initial_stack, map_image, plan_dynamic_program, run_process_entry,
    stack_input_for_program, ProgramStackInput,
};
use kernel_core::objtable::ObjId;

use crate::compat_elf::{JasperExecutionBackend, JasperLoaderMemory};
use crate::mm::frame::free_frames;
use crate::proc::{self, ProcState};
use crate::{arch, kobj, kprintln, sched};

static TRUE: &[u8] = include_bytes!(env!("JSR_UBUNTU_TRUE"));
static GETCONF: &[u8] = include_bytes!(env!("JSR_UBUNTU_GETCONF"));
static INTERPRETER: &[u8] = include_bytes!(env!("JSR_UBUNTU_LD_LINUX"));
static FAILED: AtomicU32 = AtomicU32::new(0);

const EXECUTABLE_BASE: u64 = arch::USER_WINDOW.0 + 0x40_0000;
const INTERPRETER_BASE: u64 = arch::USER_WINDOW.0 + 0x20_0000_0000;
const STACK_TOP: u64 = arch::USER_WINDOW.0 + 0x10_0000_0000;
const STACK_RESERVE_BYTES: u64 = 64 * kernel_core::frame::FRAME_SIZE;

#[derive(Clone, Copy)]
struct ProgramResult {
    mapped: bool,
    interpreter_entered: bool,
    exited_zero: bool,
    resources: bool,
    syscalls: u32,
}

impl ProgramResult {
    const FAILED: Self = Self {
        mapped: false,
        interpreter_entered: false,
        exited_zero: false,
        resources: false,
        syscalls: 0,
    };
}

pub fn failed() -> u32 {
    FAILED.load(Ordering::Relaxed)
}

fn check(ok: bool, stage: &'static str) {
    if !ok {
        FAILED.fetch_add(1, Ordering::Relaxed);
        kprintln!("[JSR-COMPAT-DYNAMIC-FAIL] stage={}", stage);
    }
}

fn cleanup(pid: ObjId) {
    let _ = proc::reap(pid);
    kobj::run_cleanup(usize::MAX);
}

fn allowed_calls() -> LinuxSyscallSet {
    LinuxSyscallSet::of(&[
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
    ])
}

pub fn run() {
    let frames_before = free_frames();
    check(crate::linux_vfs::fixture_nonempty(), "libc_fixture");

    let true_argv: [&[u8]; 1] = [b"/usr/bin/true"];
    let true_result = run_program("ubuntu-dynamic-true", TRUE, &true_argv, frames_before);
    kprintln!(
        "[JSR-COMPAT-DYNAMIC] fixture=ubuntu-x86_64 executable=true ld_linux=true libc=true mapped={} entry=interpreter true interpreter_syscalls={} syscall_delta={} exit_zero={} frames_before={} resources={} failed={}",
        true_result.mapped,
        true_result.interpreter_entered,
        true_result.syscalls,
        true_result.exited_zero,
        frames_before,
        true_result.resources,
        failed()
    );

    let getconf_argv: [&[u8]; 2] = [b"/usr/bin/getconf", b"GNU_LIBC_VERSION"];
    let getconf_result =
        run_program("ubuntu-dynamic-getconf", GETCONF, &getconf_argv, frames_before);
    kprintln!(
        "[JSR-COMPAT-DYNAMIC-GETCONF] fixture=ubuntu-x86_64 executable=getconf mapped={} entry=interpreter true interpreter_syscalls={} syscall_delta={} exit_zero={} resources={} failed={}",
        getconf_result.mapped,
        getconf_result.interpreter_entered,
        getconf_result.syscalls,
        getconf_result.exited_zero,
        getconf_result.resources,
        failed()
    );

    let resources = free_frames() == frames_before;
    check(resources, "final_resources");
    check(
        true_result.exited_zero && getconf_result.exited_zero && resources,
        "program_summary",
    );
    kprintln!(
        "[JSR-COMPAT-DYNAMIC-SUMMARY] true={} getconf={} resources={} failed={}",
        true_result.exited_zero,
        getconf_result.exited_zero,
        resources,
        failed()
    );
}

fn run_program(
    name: &'static str,
    executable: &[u8],
    argv: &[&[u8]],
    frames_before: usize,
) -> ProgramResult {
    let calls_before = crate::syscall::call_count();
    let Ok(pid) = proc::create_linux(name, allowed_calls()) else {
        check(false, "create");
        return ProgramResult::FAILED;
    };
    let executable_plan = match jasper_compat_loader::parse(executable) {
        Ok(plan) => plan,
        Err(_) => {
            check(false, "parse_executable");
            cleanup(pid);
            return ProgramResult::FAILED;
        }
    };
    let interpreter_plan = match jasper_compat_loader::parse(INTERPRETER) {
        Ok(plan) => plan,
        Err(_) => {
            check(false, "parse_interpreter");
            cleanup(pid);
            return ProgramResult::FAILED;
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
            return ProgramResult::FAILED;
        }
    };

    let mut memory = JasperLoaderMemory::new(pid);
    let executable_mapped = map_image(&mut memory, executable, &dynamic.executable).is_ok();
    let interpreter_mapped =
        map_image(&mut memory, INTERPRETER, &dynamic.interpreter).is_ok();
    check(executable_mapped, "map_executable");
    check(interpreter_mapped, "map_interpreter");
    if !executable_mapped || !interpreter_mapped {
        cleanup(pid);
        return ProgramResult::FAILED;
    }

    let random = [0x5au8; 16];
    let stack = stack_input_for_program(ProgramStackInput {
        plan: &executable_plan,
        image: &dynamic.executable,
        interpreter_base: dynamic.interpreter.load_bias,
        stack_top: STACK_TOP,
        argv,
        envp: &[],
        auxv: &[],
        random: Some(&random),
    })
    .and_then(build_initial_stack);
    check(stack.is_ok(), "initial_stack");

    let mut backend =
        JasperExecutionBackend::with_stack_reserve(pid, name, STACK_RESERVE_BYTES);
    let mut entered = false;
    let mut thread = false;
    if let Ok(stack) = stack {
        match run_process_entry(&mut backend, &dynamic.execution, stack) {
            Ok(()) => entered = true,
            Err(error) => kprintln!(
                "[JSR-COMPAT-DYNAMIC-ERROR] program={} stage=transfer error={:?}",
                name,
                error
            ),
        }
        check(entered, "transfer_interpreter");
        thread = backend.task().is_some();
        check(thread, "thread");
        sched::run();
    }

    let exited_zero = proc::state(pid) == Some(ProcState::Exited { code: 0 });
    let syscalls = crate::syscall::call_count().saturating_sub(calls_before);
    let interpreter_entered = entered && thread && syscalls > 0;
    check(interpreter_entered, "interpreter_syscall");
    check(exited_zero, "exit_zero");
    cleanup(pid);
    let resources = free_frames() == frames_before;
    check(resources, "resources");
    ProgramResult {
        mapped: true,
        interpreter_entered,
        exited_zero,
        resources,
        syscalls,
    }
}
