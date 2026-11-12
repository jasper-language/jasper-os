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
#[cfg(feature = "compat-signal-verify")]
static SIGNAL: &[u8] = include_bytes!(env!("JSR_UBUNTU_SIGNAL"));
static INTERPRETER: &[u8] = include_bytes!(env!("JSR_UBUNTU_LD_LINUX"));
static FAILED: AtomicU32 = AtomicU32::new(0);

const EXECUTABLE_BASE: u64 = arch::USER_WINDOW.0 + 0x40_0000;
const INTERPRETER_BASE: u64 = arch::USER_WINDOW.0 + 0x20_0000_0000;
const STACK_TOP: u64 = arch::USER_WINDOW.0 + 0x10_0000_0000;
const STACK_RESERVE_BYTES: u64 = 64 * kernel_core::frame::FRAME_SIZE;
const PROGRAM_DEADLINE_TICKS: u64 = 3000;

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
        LinuxSyscall::ReadV,
        LinuxSyscall::ReadLinkAt,
        LinuxSyscall::Write,
        LinuxSyscall::WriteV,
        LinuxSyscall::GetDents64,
        LinuxSyscall::Close,
        LinuxSyscall::Dup,
        LinuxSyscall::Dup2,
        LinuxSyscall::Dup3,
        LinuxSyscall::Pipe2,
        LinuxSyscall::Socket,
        LinuxSyscall::Bind,
        LinuxSyscall::Listen,
        LinuxSyscall::Connect,
        LinuxSyscall::Accept,
        LinuxSyscall::Accept4,
        LinuxSyscall::SocketPair,
        LinuxSyscall::SendMsg,
        LinuxSyscall::RecvMsg,
        LinuxSyscall::SendTo,
        LinuxSyscall::RecvFrom,
        LinuxSyscall::Shutdown,
        LinuxSyscall::GetSockName,
        LinuxSyscall::GetPeerName,
        LinuxSyscall::GetSockOpt,
        LinuxSyscall::SetSockOpt,
        LinuxSyscall::Chdir,
        LinuxSyscall::OpenAt,
        LinuxSyscall::Fchdir,
        LinuxSyscall::Fstat,
        LinuxSyscall::Fstatfs,
        LinuxSyscall::Fsync,
        LinuxSyscall::Fdatasync,
        LinuxSyscall::Sync,
        LinuxSyscall::Syncfs,
        LinuxSyscall::NewFstatAt,
        LinuxSyscall::Statx,
        LinuxSyscall::Fcntl,
        LinuxSyscall::Poll,
        LinuxSyscall::PPoll,
        LinuxSyscall::Select,
        LinuxSyscall::PSelect6,
        LinuxSyscall::Ioctl,
        LinuxSyscall::StatFs,
        LinuxSyscall::ReadLink,
        LinuxSyscall::Brk,
        LinuxSyscall::Access,
        LinuxSyscall::ArchPrctl,
        LinuxSyscall::ClockGettime,
        LinuxSyscall::ClockGetres,
        LinuxSyscall::Nanosleep,
        LinuxSyscall::ClockNanosleep,
        LinuxSyscall::RtSigAction,
        LinuxSyscall::RtSigProcMask,
        LinuxSyscall::RtSigReturn,
        LinuxSyscall::Tgkill,
        LinuxSyscall::SchedYield,
        LinuxSyscall::Sigaltstack,
        LinuxSyscall::Kill,
        LinuxSyscall::Uname,
        LinuxSyscall::Mmap,
        LinuxSyscall::Munmap,
        LinuxSyscall::Mprotect,
        LinuxSyscall::Madvise,
        LinuxSyscall::Clone,
        LinuxSyscall::Clone3,
        LinuxSyscall::Vfork,
        LinuxSyscall::Execve,
        LinuxSyscall::Futex,
        LinuxSyscall::Exit,
        LinuxSyscall::ExitGroup,
        LinuxSyscall::GetPid,
        LinuxSyscall::GetPpid,
        LinuxSyscall::GetTid,
        LinuxSyscall::GetRandom,
        LinuxSyscall::GetTimeOfDay,
        LinuxSyscall::Time,
        LinuxSyscall::Getcwd,
        LinuxSyscall::GetUid,
        LinuxSyscall::GetEuid,
        LinuxSyscall::GetGid,
        LinuxSyscall::GetEgid,
        LinuxSyscall::GetGroups,
        LinuxSyscall::Lseek,
        LinuxSyscall::GetCpu,
        LinuxSyscall::Sysinfo,
        LinuxSyscall::SchedGetAffinity,
        LinuxSyscall::SchedGetScheduler,
        LinuxSyscall::SetTidAddress,
        LinuxSyscall::SetRobustList,
        LinuxSyscall::Rseq,
        LinuxSyscall::Prlimit64,
        LinuxSyscall::Wait4,
    ])
}

pub fn run() {
    let frames_before = free_frames();
    check(crate::linux_vfs::fixture_nonempty(), "libc_fixture");

    let true_argv: [&[u8]; 1] = [b"/usr/bin/true"];
    let true_warm = run_program(
        "ubuntu-dynamic-true-warm",
        TRUE,
        INTERPRETER,
        &true_argv,
        frames_before,
        false,
    );
    check(
        true_warm.interpreter_entered && true_warm.exited_zero,
        "true_warm",
    );
    let true_baseline = free_frames();
    let true_result = run_program(
        "ubuntu-dynamic-true",
        TRUE,
        INTERPRETER,
        &true_argv,
        true_baseline,
        true,
    );
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
        INTERPRETER,
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
        INTERPRETER,
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
        INTERPRETER,
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
            INTERPRETER,
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

    #[cfg(feature = "compat-signal-verify")]
    let signal_result = {
        let signal_argv: [&[u8]; 1] = [b"/usr/bin/jasper-signal-basic"];
        let signal_baseline = free_frames();
        let result = run_program(
            "ubuntu-dynamic-signal",
            SIGNAL,
            INTERPRETER,
            &signal_argv,
            signal_baseline,
            true,
        );
        kprintln!(
            "[JSR-COMPAT-SIGNAL] fixture=ubuntu-x86_64 executable=signal-basic mapped={} entry=interpreter true interpreter_syscalls={} syscall_delta={} exit_zero={} resources={} failed={}",
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
    let resources = true_result.resources
        && getconf_result.resources
        && printf_result.resources
        && {
            #[cfg(feature = "compat-pthread-verify")]
            {
                pthread_result.resources && pthread_result.exited_zero
            }
            #[cfg(not(feature = "compat-pthread-verify"))]
            {
                true
            }
        }
        && {
            #[cfg(feature = "compat-signal-verify")]
            {
                signal_result.resources && signal_result.exited_zero
            }
            #[cfg(not(feature = "compat-signal-verify"))]
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
    interpreter: &[u8],
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
    let interpreter_plan = match jasper_compat_loader::parse(interpreter) {
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
    let interpreter_mapped = map_image(&mut memory, interpreter, &dynamic.interpreter).is_ok();
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
    let mut completed = false;
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
        let deadline = sched::timer_ticks().saturating_add(PROGRAM_DEADLINE_TICKS);
        completed = sched::run_until(deadline);
        if !completed {
            kprintln!(
                "[JSR-COMPAT-DYNAMIC-FAIL] program={} stage=deadline_exceeded deadline={}",
                name,
                deadline
            );
            check(false, "deadline");
            let _ = proc::begin_exit(pid, 124);
            let cleanup_deadline = sched::timer_ticks().saturating_add(100);
            let _ = sched::run_until(cleanup_deadline);
        }
    }

    // Drop the complete loader transaction before measuring steady-state heap usage.
    // 在测量稳态堆占用前释放整次装载事务，避免把仍在作用域的临时计划误报为泄漏。
    drop(backend);
    drop(memory);
    drop(dynamic);
    drop(interpreter_plan);
    drop(executable_plan);

    let exited_zero = completed && proc::state(pid) == Some(ProcState::Exited { code: 0 });
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

#[cfg(all(
    feature = "linux-abi",
    feature = "lifecycle-root-exec-verify",
    target_arch = "x86_64"
))]
fn prepare_exec_image(
    pid: ObjId,
    executable: &[u8],
    interpreter: &[u8],
    argv: &[&[u8]],
    envp: &[&[u8]],
) -> Result<(u64, u64), &'static str> {
    let executable_plan =
        jasper_compat_loader::parse(executable).map_err(|_| "parse_executable")?;
    let interpreter_plan =
        jasper_compat_loader::parse(interpreter).map_err(|_| "parse_interpreter")?;
    if executable_plan.interpreter.as_deref() != Some("/lib64/ld-linux-x86-64.so.2") {
        return Err("pt_interp");
    }
    let dynamic = plan_dynamic_program(
        &executable_plan,
        &interpreter_plan,
        EXECUTABLE_BASE,
        INTERPRETER_BASE,
        kernel_core::frame::FRAME_SIZE,
    )
    .map_err(|_| "dynamic_layout")?;
    let mut memory = JasperLoaderMemory::new(pid);
    map_image(&mut memory, executable, &dynamic.executable).map_err(|_| "map_executable")?;
    map_image(&mut memory, interpreter, &dynamic.interpreter).map_err(|_| "map_interpreter")?;
    let random = [0x5au8; 16];
    let stack = stack_input_for_program(ProgramStackInput {
        plan: &executable_plan,
        image: &dynamic.executable,
        interpreter_base: dynamic.interpreter.load_bias,
        stack_top: STACK_TOP,
        argv,
        envp,
        auxv: &[],
        random: Some(&random),
    })
    .and_then(build_initial_stack)
    .map_err(|_| "initial_stack")?;
    let stack_pointer = map_exec_stack(pid, &stack)?;
    Ok((dynamic.execution.entry(), stack_pointer))
}

#[cfg(all(
    feature = "linux-abi",
    feature = "lifecycle-root-exec-verify",
    target_arch = "x86_64"
))]
fn map_exec_stack(
    pid: ObjId,
    stack: &jasper_compat_loader::InitialStackPlan,
) -> Result<u64, &'static str> {
    use kernel_core::frame::FRAME_SIZE;
    use kernel_core::paging::MapFlags;
    if stack.stack_pointer() == 0
        || stack.stack_top() <= stack.stack_pointer()
        || stack.stack_top() != stack.stack_pointer() + stack.bytes().len() as u64
    {
        return Err("stack");
    }
    let pointer_start = stack.stack_pointer() - stack.stack_pointer() % FRAME_SIZE;
    let start = stack
        .stack_top()
        .checked_sub(STACK_RESERVE_BYTES)
        .ok_or("stack")?
        & !(FRAME_SIZE - 1);
    if start < crate::arch::USER_WINDOW.0 || start > pointer_start {
        return Err("stack");
    }
    let end = stack
        .stack_top()
        .checked_add(FRAME_SIZE - 1)
        .ok_or("stack")?
        & !(FRAME_SIZE - 1);
    let mut mapped = alloc::vec::Vec::new();
    for address in (start..end).step_by(FRAME_SIZE as usize) {
        if proc::map_new(pid, address, MapFlags::USER.union(MapFlags::WRITE)).is_err() {
            for rollback in mapped.iter().rev().copied() {
                let _ = proc::unmap_page(pid, rollback);
            }
            return Err("stack_map");
        }
        mapped.push(address);
    }
    if proc::write(pid, stack.stack_pointer(), stack.bytes()).is_err() {
        for rollback in mapped.iter().rev().copied() {
            let _ = proc::unmap_page(pid, rollback);
        }
        return Err("stack_write");
    }
    Ok(stack.stack_pointer())
}

/// Replaces the current Linux image while preserving Process and Linux PID identity.
/// 在保留 Process 与 Linux PID 身份的前提下替换当前 Linux 映像。
#[cfg(all(
    feature = "linux-abi",
    feature = "lifecycle-root-exec-verify",
    target_arch = "x86_64"
))]
pub(crate) fn exec_dynamic_program(
    pid: ObjId,
    path: alloc::vec::Vec<u8>,
    executable: alloc::vec::Vec<u8>,
    interpreter: alloc::vec::Vec<u8>,
    argv: alloc::vec::Vec<alloc::vec::Vec<u8>>,
    envp: alloc::vec::Vec<alloc::vec::Vec<u8>>,
) -> Option<(u64, u64)> {
    let saved = match proc::begin_exec_address_space(pid) {
        Ok(saved) => saved,
        Err(error) => {
            kprintln!(
                "[JSR-LINUX-EXEC-FAIL] stage=address_space error={:?}",
                error
            );
            return None;
        }
    };
    if !proc::linux_set_exec_path(pid, &path) {
        let _ = proc::rollback_exec_address_space(pid, saved);
        return None;
    }
    let prepared = {
        let argv_refs = argv
            .iter()
            .map(|value| value.as_slice())
            .collect::<alloc::vec::Vec<_>>();
        let envp_refs = envp
            .iter()
            .map(|value| value.as_slice())
            .collect::<alloc::vec::Vec<_>>();
        prepare_exec_image(pid, &executable, &interpreter, &argv_refs, &envp_refs)
    };
    let (entry, stack) = match prepared {
        Ok(prepared) => prepared,
        Err(stage) => {
            kprintln!("[JSR-LINUX-EXEC-FAIL] stage={}", stage);
            let _ = proc::rollback_exec_address_space(pid, saved);
            return None;
        }
    };
    let Some(space) = proc::current_space_root(pid) else {
        return None;
    };
    // The replacement image is fully built at this point. Publish vfork exec
    // completion before switching CR3 so the suspended parent does not resume
    // across the child's address-space activation boundary.
    let _ = proc::vfork_commit_exec(pid);
    sched::set_current_space(Some(space));
    drop(saved);
    drop(argv);
    drop(envp);
    drop(executable);
    drop(interpreter);
    drop(path);
    let _ = crate::arch::set_user_fs_base(0);
    Some((entry, stack))
}

/// Executes one bounded program image through the root-backed dynamic namespace.
/// 通过根卷动态文件命名空间执行一个有界程序镜像。
#[cfg(feature = "lifecycle-root-exec-verify")]
pub(crate) fn run_root_dynamic_program(
    name: &'static str,
    path: &'static str,
    executable: &[u8],
    interpreter: &[u8],
    argv: &[&[u8]],
    frames_before: usize,
    enforce_resources: bool,
) -> bool {
    let result = run_program(
        name,
        executable,
        interpreter,
        argv,
        frames_before,
        enforce_resources,
    );
    let verified = result.mapped
        && result.interpreter_entered
        && result.exited_zero
        && (!enforce_resources || result.resources)
        && result.syscalls != 0;
    kprintln!(
        "[JSR-LIFE-ROOT-DYNAMIC] program={} path={} interpreter=/lib64/ld-linux-x86-64.so.2 mapped={} interpreter_syscalls={} syscalls={} exit_zero={} frames_before={} resources={} failed={}",
        name,
        path,
        result.mapped,
        result.interpreter_entered,
        result.syscalls,
        result.exited_zero,
        frames_before,
        result.resources,
        failed()
    );
    verified
}
