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
static PRINTF: &[u8] = include_bytes!(env!("JSR_UBUNTU_PRINTF"));
#[cfg(feature = "compat-pthread-verify")]
static PTHREAD: &[u8] = include_bytes!(env!("JSR_UBUNTU_PTHREAD"));
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
    heap_used_before: usize,
    heap_used_after: usize,
}

impl ProgramResult {
    const FAILED: Self = Self {
        mapped: false,
        interpreter_entered: false,
        exited_zero: false,
        resources: false,
        syscalls: 0,
        heap_used_before: 0,
        heap_used_after: 0,
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
        LinuxSyscall::Fcntl,
        LinuxSyscall::Poll,
        LinuxSyscall::StatFs,
        LinuxSyscall::ReadLink,
        LinuxSyscall::Brk,
        LinuxSyscall::Access,
        LinuxSyscall::ArchPrctl,
        LinuxSyscall::ClockGettime,
        LinuxSyscall::RtSigAction,
        LinuxSyscall::RtSigProcMask,
        LinuxSyscall::Mmap,
        LinuxSyscall::Munmap,
        LinuxSyscall::Mprotect,
        LinuxSyscall::Madvise,
        LinuxSyscall::Clone,
        LinuxSyscall::Futex,
        LinuxSyscall::Exit,
        LinuxSyscall::ExitGroup,
        LinuxSyscall::GetPid,
        LinuxSyscall::GetPpid,
        LinuxSyscall::GetTid,
        LinuxSyscall::SetTidAddress,
    ])
}

pub fn run() {
    let frames_before = free_frames();
    check(crate::linux_vfs::fixture_nonempty(), "libc_fixture");

    let true_argv: [&[u8]; 1] = [b"/usr/bin/true"];
    let true_warm = run_program(
        "ubuntu-dynamic-true-warm",
        TRUE,
        &true_argv,
        frames_before,
        false,
    );
    check(
        true_warm.interpreter_entered && true_warm.exited_zero,
        "true_warm",
    );
    let true_baseline = free_frames();
    let true_result = run_program("ubuntu-dynamic-true", TRUE, &true_argv, true_baseline, true);
    kprintln!(
        "[JSR-COMPAT-DYNAMIC] fixture=ubuntu-x86_64 executable=true ld_linux=true libc=true mapped={} entry=interpreter true interpreter_syscalls={} syscall_delta={} exit_zero={} frames_before={} resources={} failed={}",
        true_result.mapped,
        true_result.interpreter_entered,
        true_result.syscalls,
        true_result.exited_zero,
        true_baseline,
        true_result.resources,
        failed()
    );

    let getconf_argv: [&[u8]; 2] = [b"/usr/bin/getconf", b"GNU_LIBC_VERSION"];
    let getconf_result = run_program(
        "ubuntu-dynamic-getconf",
        GETCONF,
        &getconf_argv,
        frames_before,
        true,
    );
    kprintln!(
        "[JSR-COMPAT-DYNAMIC-GETCONF] fixture=ubuntu-x86_64 executable=getconf mapped={} entry=interpreter true interpreter_syscalls={} syscall_delta={} exit_zero={} resources={} failed={}",
        getconf_result.mapped,
        getconf_result.interpreter_entered,
        getconf_result.syscalls,
        getconf_result.exited_zero,
        getconf_result.resources,
        failed()
    );

    let printf_argv: [&[u8]; 3] = [b"/usr/bin/printf", b"jasper-%s\n", b"dynamic"];
    let printf_warm = run_program(
        "ubuntu-dynamic-printf-warm",
        PRINTF,
        &printf_argv,
        frames_before,
        false,
    );
    check(
        printf_warm.interpreter_entered && printf_warm.exited_zero,
        "printf_warm",
    );
    let printf_baseline = free_frames();
    let printf_result = run_program(
        "ubuntu-dynamic-printf",
        PRINTF,
        &printf_argv,
        printf_baseline,
        true,
    );
    kprintln!(
        "[JSR-COMPAT-DYNAMIC-PRINTF] fixture=ubuntu-x86_64 executable=printf libraries=6 mapped={} entry=interpreter true interpreter_syscalls={} syscall_delta={} exit_zero={} resources={} failed={}",
        printf_result.mapped,
        printf_result.interpreter_entered,
        printf_result.syscalls,
        printf_result.exited_zero,
        printf_result.resources,
        failed()
    );

    #[cfg(feature = "compat-pthread-verify")]
    let pthread_result = {
        let pthread_argv: [&[u8]; 1] = [b"/usr/bin/jasper-pthread-basic"];
        let pthread_baseline = free_frames();
        let result = run_program(
            "ubuntu-dynamic-pthread",
            PTHREAD,
            &pthread_argv,
            pthread_baseline,
            true,
        );
        kprintln!(
            "[JSR-COMPAT-PTHREAD] fixture=ubuntu-x86_64 executable=pthread-basic mapped={} entry=interpreter true interpreter_syscalls={} syscall_delta={} exit_zero={} resources={} failed={}",
            result.mapped,
            result.interpreter_entered,
            result.syscalls,
            result.exited_zero,
            result.resources,
            failed()
        );
        result
    };

    let frames_after = free_frames();
    let resources = true_result.resources && getconf_result.resources && printf_result.resources
        && {
            #[cfg(feature = "compat-pthread-verify")]
            {
                pthread_result.resources && pthread_result.exited_zero
            }
            #[cfg(not(feature = "compat-pthread-verify"))]
            {
                true
            }
        };
    check(
        true_result.exited_zero
            && getconf_result.exited_zero
            && printf_result.exited_zero
            && resources,
        "program_summary",
    );
    kprintln!(
        "[JSR-COMPAT-DYNAMIC-SUMMARY] true={} getconf={} printf={} resources={} cold_heap_delta={} free_frames_before={} free_frames_after={} heap_used_true={}/{} heap_used_getconf={}/{} heap_used_printf={}/{} failed={}",
        true_result.exited_zero,
        getconf_result.exited_zero,
        printf_result.exited_zero,
        resources,
        true_warm
            .heap_used_after
            .saturating_sub(true_warm.heap_used_before),
        frames_before,
        frames_after,
        true_result.heap_used_before,
        true_result.heap_used_after,
        getconf_result.heap_used_before,
        getconf_result.heap_used_after,
        printf_result.heap_used_before,
        printf_result.heap_used_after,
        failed()
    );
}

fn run_program(
    name: &'static str,
    executable: &[u8],
    argv: &[&[u8]],
    frames_before: usize,
    enforce_resources: bool,
) -> ProgramResult {
    let calls_before = crate::syscall::call_count();
    let heap_before = crate::mm::heap::stats();
    let Ok(pid) = proc::create_linux(name, allowed_calls()) else {
        check(false, "create");
        return ProgramResult::FAILED;
    };
    if argv
        .first()
        .is_none_or(|path| !proc::linux_set_exec_path(pid, path))
    {
        check(false, "exec_path");
        cleanup(pid);
        return ProgramResult::FAILED;
    }
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
    let interpreter_mapped = map_image(&mut memory, INTERPRETER, &dynamic.interpreter).is_ok();
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

    let mut backend = JasperExecutionBackend::with_stack_reserve(pid, name, STACK_RESERVE_BYTES);
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

    // Drop the complete loader transaction before measuring steady-state heap usage.
    // 在测量稳态堆占用前释放整次装载事务，避免把仍在作用域的临时计划误报为泄漏。
    drop(backend);
    drop(memory);
    drop(dynamic);
    drop(interpreter_plan);
    drop(executable_plan);

    let exited_zero = proc::state(pid) == Some(ProcState::Exited { code: 0 });
    let syscalls = crate::syscall::call_count().saturating_sub(calls_before);
    let interpreter_entered = entered && thread && syscalls > 0;
    check(interpreter_entered, "interpreter_syscall");
    check(exited_zero, "exit_zero");
    if let Some((pages, references, max)) = proc::frame_reference_stats(pid) {
        kprintln!(
            "[JSR-COMPAT-DYNAMIC-REFS] program={} pages={} references={} max={}",
            name,
            pages,
            references,
            max
        );
    }
    cleanup(pid);
    let frames_after = free_frames();
    let heap_after = crate::mm::heap::stats();
    let heap_used_before = heap_before.0.saturating_sub(heap_before.1);
    let heap_used_after = heap_after.0.saturating_sub(heap_after.1);
    let resources = frames_after == frames_before && heap_used_after == heap_used_before;
    if !resources {
        let (pins, orphaned) = crate::mm::pin::stats();
        kprintln!(
            "[JSR-COMPAT-DYNAMIC-RESOURCE] program={} frames_before={} frames_after={} retained={} heap_used_before={} heap_used_after={} heap_mapped_delta={} pins={} orphaned={} failed_frees={} released={}",
            name,
            frames_before,
            frames_after,
            frames_before.saturating_sub(frames_after),
            heap_used_before,
            heap_used_after,
            heap_after.3.saturating_sub(heap_before.3),
            pins,
            orphaned,
            crate::mm::memory_object::failed_page_frees(),
            crate::mm::memory_object::released_pages()
        );
    }
    if enforce_resources {
        check(resources, "resources");
    }
    ProgramResult {
        mapped: true,
        interpreter_entered,
        exited_zero,
        resources,
        syscalls,
        heap_used_before,
        heap_used_after,
    }
}
