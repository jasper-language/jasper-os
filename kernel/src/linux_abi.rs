//! Linux x86_64 system-interface service for explicitly flavored processes.
//!
//! 职责：把已识别的 Linux syscall 映射到 Jasper fd、任务、内存和受控只读文件机制；
//! 所有调用先经过兼容进程的显式 Linux 调用集合，不能借用 Jasper 原生 SyscallSet。
//! Responsibility: execute Linux syscalls through explicit compatibility authority while
//! preserving Jasper Handle/Rights, memory ownership, bounds and resource cleanup.

use compat_core::syscall::{
    compat_result, dispatch, CompatErrno, LinuxCall, LinuxSyscall, SyscallDispatch, SyscallRequest,
    LINUX_NR_FUTEX,
};

use core::sync::atomic::{AtomicU32, Ordering};

use kernel_core::objtable::ObjId;
use kernel_core::paging::MapFlags;

use crate::mm::user::{copy_from_user, copy_to_user, copy_to_user_vectored, UserPtrError};
use crate::sync::IrqSpinLock;
use crate::syscall::{ExecReturn, SyscallArgs, SyscallOutcome, UserReturn, CONSOLE_WRITE_MAX};
use crate::{console, proc, sched};

#[cfg(any(
    feature = "compat-dynamic-libc-verify",
    feature = "workload-io-verify"
))]
static SYSCALL_TRACE_REMAINING: AtomicU32 = AtomicU32::new(512);
#[cfg(feature = "compat-dynamic-libc-verify")]
static PATH_TRACE_REMAINING: AtomicU32 = AtomicU32::new(24);

const MAX_LINUX_THREADS: usize = 64;
const MAX_FUTEX_WORDS: usize = 32;
const MAX_PROCESS_SIGNAL_SETS: usize = 16;
static NEXT_LINUX_TID: AtomicU32 = AtomicU32::new(0x10_0000);

#[derive(Clone, Copy)]
struct LinuxThread {
    process: ObjId,
    task: crate::task::TaskId,
    tid: u32,
    clear_child_tid: u64,
    robust_list: u64,
    robust_list_len: u64,
    rseq: u64,
    rseq_len: u32,
    /// Blocked standard-signal mask for this Linux TID.
    /// 当前 Linux TID 的标准信号阻塞位图。
    signal_mask: u64,
    /// Standard-signal pending bits for this Linux TID.
    /// 当前 Linux TID 的标准信号 pending 位图。
    pending_signals: u64,
    /// Per-thread alternate signal stack.
    /// 当前 Linux 线程的备用信号栈。
    altstack_sp: u64,
    altstack_size: u64,
    altstack_flags: u32,
    altstack_depth: u8,
    altstack_disarm_depth: u8,
}

#[derive(Clone, Copy)]
struct FutexWord {
    process: ObjId,
    address: u64,
    generation: u64,
    waiters: u16,
}

#[derive(Clone, Copy)]
struct ProcessSignalSet {
    process: ObjId,
    pending: u64,
}

struct CompatState {
    threads: [Option<LinuxThread>; MAX_LINUX_THREADS],
    futexes: [Option<FutexWord>; MAX_FUTEX_WORDS],
    process_signals: [Option<ProcessSignalSet>; MAX_PROCESS_SIGNAL_SETS],
}

impl CompatState {
    const fn new() -> Self {
        Self {
            threads: [None; MAX_LINUX_THREADS],
            futexes: [None; MAX_FUTEX_WORDS],
            process_signals: [None; MAX_PROCESS_SIGNAL_SETS],
        }
    }
}

static COMPAT: IrqSpinLock<CompatState> =
    IrqSpinLock::ranked(crate::lockorder::LINUX_COMPAT, CompatState::new());

#[cfg(any(
    feature = "compat-dynamic-libc-verify",
    feature = "workload-io-verify"
))]
fn trace_request(args: &SyscallArgs) {
    let remaining = SYSCALL_TRACE_REMAINING.load(Ordering::Relaxed);
    if remaining == 0 {
        return;
    }
    let index = 512 - remaining;
    if SYSCALL_TRACE_REMAINING
        .compare_exchange(
            remaining,
            remaining - 1,
            Ordering::Relaxed,
            Ordering::Relaxed,
        )
        .is_ok()
    {
        crate::kprintln!(
            "[JSR-LINUX-SYSCALL] index={} nr={} a0={:#x} a1={:#x} a2={:#x} a3={:#x} a4={:#x} a5={:#x}",
            index,
            args.id,
            args.args[0],
            args.args[1],
            args.args[2],
            args.args[3],
            args.args[4],
            args.args[5]
        );
    }
}

#[cfg(feature = "compat-dynamic-libc-verify")]
fn trace_path(kind: &str, path: &[u8]) {
    let remaining = PATH_TRACE_REMAINING.load(Ordering::Relaxed);
    if remaining == 0
        || PATH_TRACE_REMAINING
            .compare_exchange(
                remaining,
                remaining - 1,
                Ordering::Relaxed,
                Ordering::Relaxed,
            )
            .is_err()
    {
        return;
    }
    let path = path
        .iter()
        .position(|byte| *byte == 0)
        .map(|end| &path[..end])
        .unwrap_or(path);
    let mut escaped = [0u8; 256];
    let mut len = 0usize;
    for byte in path.iter().copied().take(escaped.len()) {
        let printable = byte.is_ascii_graphic() || byte == b' ';
        if len == escaped.len() {
            break;
        }
        escaped[len] = if printable { byte } else { b'?' };
        len += 1;
    }
    let text = core::str::from_utf8(&escaped[..len]).unwrap_or("<non-utf8>");
    crate::kprintln!("[JSR-LINUX-PATH] kind={} path={}", kind, text);
}

#[cfg(feature = "compat-dynamic-libc-verify")]
fn trace_path_address(pid: ObjId, kind: &str, address: u64) {
    let mut bytes = [0u8; 160];
    match proc::read(pid, address, &mut bytes) {
        Ok(()) => trace_path(kind, &bytes),
        Err(_) => crate::kprintln!(
            "[JSR-LINUX-PATH] kind={} address={:#x} readable=false",
            kind,
            address
        ),
    }
}

/// Registers the first task of a Linux process as leader and later tasks with unique TIDs.
///
/// 将 Linux 进程首个任务登记为 leader，并为后续任务分配唯一 TID。
#[cfg(all(feature = "linux-abi", target_arch = "x86_64"))]
pub(crate) fn register_linux_thread(
    process: ObjId,
    task: crate::task::TaskId,
    clear_child_tid: u64,
) -> bool {
    if !proc::is_linux_process(process) {
        return true;
    }
    let Some(pid) = proc::linux_pid(process) else {
        return false;
    };
    let tid = {
        let mut state = COMPAT.lock();
        let inherited_mask = state
            .threads
            .iter()
            .flatten()
            .find(|entry| entry.process == process && entry.task == task)
            .map(|entry| entry.signal_mask)
            .unwrap_or(0);
        let has_leader = state
            .threads
            .iter()
            .flatten()
            .any(|entry| entry.process == process);
        let tid = if has_leader {
            let tid = NEXT_LINUX_TID.fetch_add(1, Ordering::Relaxed);
            if tid == 0 || tid == u32::MAX {
                return false;
            }
            tid
        } else {
            pid
        };
        let Some(slot) = state.threads.iter().position(Option::is_none) else {
            return false;
        };
        state.threads[slot] = Some(LinuxThread {
            process,
            task,
            tid,
            clear_child_tid,
            robust_list: 0,
            robust_list_len: 0,
            rseq: 0,
            rseq_len: 0,
            signal_mask: inherited_mask,
            pending_signals: 0,
            altstack_sp: 0,
            altstack_size: 0,
            altstack_flags: 2,
            altstack_depth: 0,
            altstack_disarm_depth: 0,
        });
        tid
    };
    if clear_child_tid != 0 && proc::write(process, clear_child_tid, &tid.to_le_bytes()).is_err() {
        unregister_linux_thread(task);
        return false;
    }
    true
}

#[cfg(all(feature = "linux-abi", target_arch = "x86_64"))]
pub(crate) fn unregister_linux_thread(task: crate::task::TaskId) {
    let mut state = COMPAT.lock();
    if let Some(slot) = state
        .threads
        .iter()
        .position(|entry| entry.is_some_and(|entry| entry.task == task))
    {
        state.threads[slot] = None;
    }
}

fn linux_tid(process: ObjId) -> Option<u32> {
    let (task, _) = sched::current();
    COMPAT
        .lock()
        .threads
        .iter()
        .flatten()
        .find(|entry| entry.process == process && entry.task == task)
        .map(|entry| entry.tid)
}

fn linux_tid_for_task(task: crate::task::TaskId) -> Option<(ObjId, u32)> {
    COMPAT
        .lock()
        .threads
        .iter()
        .flatten()
        .find(|entry| entry.task == task)
        .map(|entry| (entry.process, entry.tid))
}

/// Queues one standard signal on a target Linux thread in the same process.
/// 在同一进程的目标 Linux 线程上登记一个标准信号。
fn queue_thread_signal(process: ObjId, tid: u32, signal: u32) -> bool {
    if !(1..=64).contains(&signal) {
        return false;
    }
    let target = {
        let mut state = COMPAT.lock();
        let Some(entry) = state
            .threads
            .iter_mut()
            .flatten()
            .find(|entry| entry.process == process && entry.tid == tid)
        else {
            return false;
        };
        entry.pending_signals |= 1u64 << (signal - 1);
        crate::kprintln!(
            "[JSR-LINUX-SIGNAL] queued target_tid={} signal={} mask={:#x} pending={:#x}",
            tid,
            signal,
            entry.signal_mask,
            entry.pending_signals
        );
        entry.task
    };
    sched::wake(target);
    true
}

/// Returns whether a target Linux TID exists in the process.
/// 判断目标 Linux TID 是否存在于该进程。
fn has_linux_thread(process: ObjId, tid: u32) -> bool {
    COMPAT
        .lock()
        .threads
        .iter()
        .flatten()
        .any(|entry| entry.process == process && entry.tid == tid)
}

/// Queues one process-directed standard signal and wakes all eligible threads.
/// 登记一个进程定向标准信号，并唤醒该进程的全部线程。
fn queue_process_signal(process: ObjId, signal: u32) -> bool {
    if !(1..=64).contains(&signal) {
        return false;
    }
    let mut targets = [None; MAX_LINUX_THREADS];
    let mut target_count = 0usize;
    {
        let mut state = COMPAT.lock();
        let slot = if let Some(slot) = state
            .process_signals
            .iter()
            .position(|entry| entry.is_some_and(|entry| entry.process == process))
        {
            slot
        } else {
            let Some(slot) = state.process_signals.iter().position(Option::is_none) else {
                return false;
            };
            state.process_signals[slot] = Some(ProcessSignalSet {
                process,
                pending: 0,
            });
            slot
        };
        let Some(entry) = state.process_signals[slot].as_mut() else {
            return false;
        };
        entry.pending |= 1u64 << (signal - 1);
        crate::kprintln!(
            "[JSR-LINUX-SIGNAL] queued_process process={:#x} signal={} pending={:#x}",
            process.raw(),
            signal,
            entry.pending
        );
        for thread in state.threads.iter().flatten() {
            if thread.process == process && target_count < targets.len() {
                targets[target_count] = Some(thread.task);
                target_count += 1;
            }
        }
    }
    for task in targets[..target_count].iter().flatten() {
        sched::wake(*task);
    }
    true
}

/// Removes process-directed pending signals once the last thread exits.
/// 最后一个线程退出后移除进程定向 pending 信号。
fn remove_process_signals(process: ObjId) {
    let mut state = COMPAT.lock();
    if let Some(slot) = state
        .process_signals
        .iter()
        .position(|entry| entry.is_some_and(|entry| entry.process == process))
    {
        state.process_signals[slot] = None;
    }
}

/// Returns the blocked signal mask for the current Linux thread.
/// 返回当前 Linux 线程的信号阻塞位图。
fn current_signal_mask(process: ObjId) -> Option<u64> {
    let (task, _) = sched::current();
    COMPAT
        .lock()
        .threads
        .iter()
        .flatten()
        .find(|entry| entry.process == process && entry.task == task)
        .map(|entry| entry.signal_mask)
}

/// Updates the current thread mask while preserving unmaskable signals.
/// 更新当前线程 mask，并强制保持 SIGKILL/SIGSTOP 不可阻塞。
fn set_current_signal_mask(process: ObjId, mask: u64) -> bool {
    const UNMASKABLE: u64 = (1u64 << (9 - 1)) | (1u64 << (19 - 1));
    let (task, _) = sched::current();
    let mut state = COMPAT.lock();
    let Some(entry) = state
        .threads
        .iter_mut()
        .flatten()
        .find(|entry| entry.process == process && entry.task == task)
    else {
        return false;
    };
    entry.signal_mask = mask & !UNMASKABLE;
    true
}

/// Returns the current thread alternate signal stack and active depth.
/// 返回当前线程的备用信号栈及活动深度。
fn current_altstack(process: ObjId) -> Option<(u64, u64, u32, u8, u8)> {
    let (task, _) = sched::current();
    COMPAT
        .lock()
        .threads
        .iter()
        .flatten()
        .find(|entry| entry.process == process && entry.task == task)
        .map(|entry| {
            (
                entry.altstack_sp,
                entry.altstack_size,
                entry.altstack_flags,
                entry.altstack_depth,
                entry.altstack_disarm_depth,
            )
        })
}

/// Queries or updates the current thread alternate signal stack.
/// 查询或更新当前线程的备用信号栈。
fn linux_sigaltstack(process: ObjId, args: [u64; 6]) -> Result<u64, CompatErrno> {
    const STACK_T_BYTES: usize = 24;
    const SS_DISABLE: u32 = 2;
    const SS_AUTODISARM: u32 = 0x8000_0000;
    const MIN_ALTSTACK: u64 = 2048;
    let (sp, size, configured_flags, active_depth, disarm_depth) =
        current_altstack(process).ok_or(CompatErrno::NoSys)?;
    let flags = if configured_flags & SS_DISABLE != 0 || disarm_depth != 0 {
        SS_DISABLE
    } else if active_depth != 0 {
        1
    } else {
        configured_flags
    };
    if args[1] != 0 {
        if active_depth != 0 || disarm_depth != 0 {
            crate::kprintln!(
                "[JSR-LINUX-ALTSTACK] query active=true depth={} flags={:#x}",
                active_depth,
                flags
            );
        }
        let mut old = [0u8; STACK_T_BYTES];
        old[..8].copy_from_slice(&sp.to_le_bytes());
        old[8..12].copy_from_slice(&flags.to_le_bytes());
        old[16..24].copy_from_slice(&size.to_le_bytes());
        copy_to_user(args[1], &old, STACK_T_BYTES).map_err(|_| CompatErrno::Fault)?;
    }
    if args[0] != 0 {
        if active_depth != 0 {
            crate::kprintln!(
                "[JSR-LINUX-ALTSTACK] change_denied active=true depth={}",
                active_depth
            );
            return Err(CompatErrno::Perm);
        }
        let mut value = [0u8; STACK_T_BYTES];
        copy_from_user(&mut value, args[0], STACK_T_BYTES).map_err(|_| CompatErrno::Fault)?;
        let requested_sp = u64::from_le_bytes(value[..8].try_into().unwrap());
        let requested_flags = u32::from_le_bytes(value[8..12].try_into().unwrap());
        let requested_size = u64::from_le_bytes(value[16..24].try_into().unwrap());
        let (new_sp, new_size, new_flags) = if requested_flags == SS_DISABLE {
            (0, 0, SS_DISABLE)
        } else {
            if requested_flags != 0 && requested_flags != SS_AUTODISARM
                || requested_size < MIN_ALTSTACK
                || requested_sp % 16 != 0
                || requested_sp < crate::arch::USER_WINDOW.0
                || requested_sp
                    .checked_add(requested_size)
                    .is_none_or(|end| end > crate::arch::USER_WINDOW.1)
            {
                return Err(CompatErrno::Invalid);
            }
            (requested_sp, requested_size, requested_flags)
        };
        let (task, _) = sched::current();
        let mut state = COMPAT.lock();
        let Some(entry) = state
            .threads
            .iter_mut()
            .flatten()
            .find(|entry| entry.process == process && entry.task == task)
        else {
            return Err(CompatErrno::NoProcess);
        };
        entry.altstack_sp = new_sp;
        entry.altstack_size = new_size;
        entry.altstack_flags = new_flags;
    }
    Ok(0)
}

/// Marks one signal frame as executing on the alternate stack.
/// 标记一个信号帧正在备用栈上执行。
fn enter_altstack(process: ObjId, autodisarm: bool) -> bool {
    let (task, _) = sched::current();
    let mut state = COMPAT.lock();
    let Some(entry) = state
        .threads
        .iter_mut()
        .flatten()
        .find(|entry| entry.process == process && entry.task == task)
    else {
        return false;
    };
    let Some(next) = entry.altstack_depth.checked_add(1) else {
        return false;
    };
    entry.altstack_depth = next;
    if autodisarm {
        let Some(disarmed) = entry.altstack_disarm_depth.checked_add(1) else {
            entry.altstack_depth = next - 1;
            return false;
        };
        entry.altstack_disarm_depth = disarmed;
    }
    crate::kprintln!(
        "[JSR-LINUX-ALTSTACK] enter depth={} autodisarm={}",
        next,
        autodisarm
    );
    true
}

/// Leaves one signal frame that was marked as using the alternate stack.
/// 离开一个标记为使用备用栈的信号帧。
fn leave_altstack(process: ObjId, autodisarm: bool) -> bool {
    let (task, _) = sched::current();
    let mut state = COMPAT.lock();
    let Some(entry) = state
        .threads
        .iter_mut()
        .flatten()
        .find(|entry| entry.process == process && entry.task == task)
    else {
        return false;
    };
    let Some(next) = entry.altstack_depth.checked_sub(1) else {
        return false;
    };
    entry.altstack_depth = next;
    if autodisarm {
        let Some(armed) = entry.altstack_disarm_depth.checked_sub(1) else {
            entry.altstack_depth = next + 1;
            return false;
        };
        entry.altstack_disarm_depth = armed;
    }
    crate::kprintln!(
        "[JSR-LINUX-ALTSTACK] leave depth={} autodisarm={}",
        next,
        autodisarm
    );
    true
}

/// Takes the lowest unmasked pending signal for the current thread.
/// 取出当前线程编号最低且未被屏蔽的 pending 信号。
fn take_deliverable_signal(process: ObjId) -> Option<u32> {
    let (task, _) = sched::current();
    let mut state = COMPAT.lock();
    let (blocked, thread_deliverable) = {
        let entry = state
            .threads
            .iter()
            .flatten()
            .find(|entry| entry.process == process && entry.task == task)?;
        (
            entry.signal_mask,
            entry.pending_signals & !entry.signal_mask,
        )
    };
    let (deliverable, process_directed) = if thread_deliverable != 0 {
        (thread_deliverable, false)
    } else {
        let process_deliverable = state
            .process_signals
            .iter()
            .flatten()
            .find(|entry| entry.process == process)
            .map(|entry| entry.pending & !blocked)
            .unwrap_or(0);
        (process_deliverable, true)
    };
    if deliverable == 0 {
        return None;
    }
    let index = deliverable.trailing_zeros();
    let bit = 1u64 << index;
    if process_directed {
        let entry = state
            .process_signals
            .iter_mut()
            .flatten()
            .find(|entry| entry.process == process)?;
        entry.pending &= !bit;
    } else {
        let entry = state
            .threads
            .iter_mut()
            .flatten()
            .find(|entry| entry.process == process && entry.task == task)?;
        entry.pending_signals &= !bit;
    }
    Some(index + 1)
}

/// Reports whether the current thread has an unmasked pending signal.
/// 判断当前线程是否存在未被 mask 的 pending 信号。
fn current_signal_pending(process: ObjId) -> bool {
    let (task, _) = sched::current();
    let state = COMPAT.lock();
    let Some(thread) = state
        .threads
        .iter()
        .flatten()
        .find(|entry| entry.process == process && entry.task == task)
    else {
        return false;
    };
    thread.pending_signals & !thread.signal_mask != 0
        || state
            .process_signals
            .iter()
            .flatten()
            .find(|entry| entry.process == process)
            .is_some_and(|entry| entry.pending & !thread.signal_mask != 0)
}

const SIGNAL_FRAME_BYTES: usize = 8 + 968 + 128 + crate::syscall::XSAVE_BYTES;
const SIGNAL_UC_OFFSET: usize = 8;
const SIGNAL_UC_GREGS: usize = 40;
const SIGNAL_UC_SIGMASK: usize = 296;
const SIGNAL_UC_FPREGS: usize = 224;
const SIGNAL_INFO_OFFSET: usize = SIGNAL_UC_OFFSET + 968;
const SIGNAL_FPSTATE_OFFSET: usize = SIGNAL_INFO_OFFSET + 128;
const JASPER_UC_FLAG_ALTSTACK: u64 = 1u64 << 63;
const JASPER_UC_FLAG_ALTSTACK_AUTODISARM: u64 = 1u64 << 62;

fn write_frame_u64(frame: &mut [u8], offset: usize, value: u64) {
    if let Some(field) = frame.get_mut(offset..offset + 8) {
        field.copy_from_slice(&value.to_le_bytes());
    }
}

fn user_register(register: u64) -> bool {
    let window = crate::arch::USER_WINDOW;
    let Some(last) = register.checked_sub(1) else {
        return false;
    };
    register < window.1 && last >= window.0
}

/// Copies the kernel-owned syscall FP state image into a signal frame.
/// 把 syscall 入口保存的内核侧浮点状态映像复制到信号帧。
fn copy_fxstate_to_frame(args: &SyscallArgs, frame: &mut [u8]) -> bool {
    let Some(source) = args.fxstate else {
        return false;
    };
    let Some(destination) = frame.get_mut(
        SIGNAL_FPSTATE_OFFSET..SIGNAL_FPSTATE_OFFSET.saturating_add(crate::syscall::XSAVE_BYTES),
    ) else {
        return false;
    };
    // SAFETY: the x86_64 syscall entry owns this aligned XSAVE image for the
    // duration of dispatch; the frame destination is a separate fixed buffer.
    destination.copy_from_slice(unsafe { &*source });
    true
}

/// Builds the bounded Linux x86_64 signal frame on the interrupted user stack.
/// 在被打断的用户栈上构造有界 Linux x86_64 信号帧。
fn build_signal_frame(
    process: ObjId,
    signal: u32,
    args: &SyscallArgs,
    user_ip: (u64, u64),
    interrupted_result: i64,
) -> Result<UserReturn, CompatErrno> {
    const SA_SIGINFO: u64 = 0x0000_0004;
    const SA_RESTORER: u64 = 0x0400_0000;
    const SA_RESTART: u64 = 0x1000_0000;
    const SA_NODEFER: u64 = 0x4000_0000;
    const SA_RESETHAND: u64 = 0x8000_0000;
    const SA_ONSTACK: u64 = 0x0800_0000;
    const SS_DISABLE: u32 = 2;
    const SS_AUTODISARM: u32 = 0x8000_0000;
    const SIG_DFL: u64 = 0;
    const SIG_IGN: u64 = 1;
    let action = proc::linux_signal_action(process, signal).ok_or(CompatErrno::Invalid)?;
    let handler = action[0];
    if handler == SIG_IGN {
        return Err(CompatErrno::Interrupted);
    }
    if handler == SIG_DFL {
        let _ = proc::begin_exit(process, 128 + i64::from(signal));
        return Err(CompatErrno::Interrupted);
    }
    if action[1] & !(SA_SIGINFO | SA_RESTORER | SA_RESTART | SA_NODEFER | SA_RESETHAND | SA_ONSTACK)
        != 0
        || !user_register(handler)
        || !user_register(action[2])
        || !user_register(user_ip.0)
        || !user_register(user_ip.1)
    {
        return Err(CompatErrno::Invalid);
    }
    let old_mask = current_signal_mask(process).ok_or(CompatErrno::Invalid)?;
    let altstack = if action[1] & SA_ONSTACK != 0 {
        current_altstack(process).ok_or(CompatErrno::Invalid)?
    } else {
        (0, 0, SS_DISABLE, 0, 0)
    };
    let uses_altstack = action[1] & SA_ONSTACK != 0
        && altstack.2 & SS_DISABLE == 0
        && altstack.4 == 0
        && altstack.1 >= SIGNAL_FRAME_BYTES as u64
        && user_register(altstack.0);
    let autodisarm = uses_altstack && altstack.2 & SS_AUTODISARM != 0;
    let (stack_top, red_zone) = if uses_altstack {
        (
            altstack
                .0
                .checked_add(altstack.1)
                .filter(|top| *top <= crate::arch::USER_WINDOW.1)
                .ok_or(CompatErrno::Fault)?,
            0,
        )
    } else {
        (user_ip.1, 128)
    };
    let frame_address = stack_top
        .checked_sub(red_zone + SIGNAL_FRAME_BYTES as u64)
        .map(|value| value & !0xf)
        .filter(|value| {
            *value >= crate::arch::USER_WINDOW.0
                && value
                    .checked_add(SIGNAL_FRAME_BYTES as u64)
                    .is_some_and(|end| end <= crate::arch::USER_WINDOW.1)
        })
        .ok_or(CompatErrno::Fault)?;
    let info_address = frame_address
        .checked_add(SIGNAL_INFO_OFFSET as u64)
        .ok_or(CompatErrno::Fault)?;
    let context_address = frame_address
        .checked_add(SIGNAL_UC_OFFSET as u64)
        .ok_or(CompatErrno::Fault)?;
    let fpstate_address = frame_address
        .checked_add(SIGNAL_FPSTATE_OFFSET as u64)
        .ok_or(CompatErrno::Fault)?;
    let mut frame = [0u8; SIGNAL_FRAME_BYTES];
    write_frame_u64(&mut frame, 0, action[2]);
    if !copy_fxstate_to_frame(args, &mut frame) {
        return Err(CompatErrno::Fault);
    }
    write_frame_u64(
        &mut frame,
        SIGNAL_UC_OFFSET + SIGNAL_UC_FPREGS,
        fpstate_address,
    );
    if uses_altstack {
        let mut flags = JASPER_UC_FLAG_ALTSTACK;
        if autodisarm {
            flags |= JASPER_UC_FLAG_ALTSTACK_AUTODISARM;
        }
        write_frame_u64(&mut frame, SIGNAL_UC_OFFSET, flags);
    }
    let gregs = SIGNAL_UC_OFFSET + SIGNAL_UC_GREGS;
    let restart_futex = action[1] & SA_RESTART != 0
        && args.id == LINUX_NR_FUTEX
        && interrupted_result == -i64::from(CompatErrno::Interrupted as i32);
    let resume_rip = if restart_futex {
        user_ip.0.checked_sub(2).ok_or(CompatErrno::Fault)?
    } else {
        user_ip.0
    };
    if !user_register(resume_rip) {
        return Err(CompatErrno::Fault);
    }
    write_frame_u64(&mut frame, gregs, args.args[4]);
    write_frame_u64(&mut frame, gregs + 8, args.args[5]);
    write_frame_u64(&mut frame, gregs + 16, args.args[3]);
    write_frame_u64(&mut frame, gregs + 64, args.args[0]);
    write_frame_u64(&mut frame, gregs + 72, args.args[1]);
    write_frame_u64(&mut frame, gregs + 96, args.args[2]);
    write_frame_u64(
        &mut frame,
        gregs + 104,
        if restart_futex {
            args.id
        } else {
            interrupted_result as u64
        },
    );
    write_frame_u64(&mut frame, gregs + 112, 0);
    write_frame_u64(&mut frame, gregs + 120, user_ip.1);
    write_frame_u64(&mut frame, gregs + 128, resume_rip);
    write_frame_u64(&mut frame, gregs + 136, 0x202);
    write_frame_u64(&mut frame, SIGNAL_UC_OFFSET + SIGNAL_UC_SIGMASK, old_mask);
    write_frame_u64(&mut frame, SIGNAL_INFO_OFFSET, u64::from(signal));
    write_frame_u64(
        &mut frame,
        SIGNAL_INFO_OFFSET + 16,
        u64::from(proc::linux_pid(process).ok_or(CompatErrno::NoProcess)?),
    );
    let nodefer = action[1] & (SA_NODEFER | SA_RESETHAND) != 0;
    let reset_hand = action[1] & SA_RESETHAND != 0;
    let handler_mask = if nodefer {
        old_mask | action[3]
    } else {
        old_mask | action[3] | (1u64 << (signal - 1))
    };
    if !set_current_signal_mask(process, handler_mask) {
        return Err(CompatErrno::Invalid);
    }
    if reset_hand && !proc::set_linux_signal_action(process, signal, [0; 4]) {
        let _ = set_current_signal_mask(process, old_mask);
        return Err(CompatErrno::Invalid);
    }
    if proc::write(process, frame_address, &frame).is_err() {
        let _ = set_current_signal_mask(process, old_mask);
        return Err(CompatErrno::Fault);
    }
    if uses_altstack && !enter_altstack(process, autodisarm) {
        let _ = set_current_signal_mask(process, old_mask);
        return Err(CompatErrno::Invalid);
    }
    crate::kprintln!(
        "[JSR-LINUX-SIGNAL] delivered tid={} signal={} interrupted_result={} restart_futex={} nodefer={} reset_hand={} altstack={} autodisarm={} fxstate={} handler={:#x} frame={:#x} info={:#x} context={:#x} fpstate={:#x}",
        linux_tid(process).unwrap_or(0),
        signal,
        interrupted_result,
        restart_futex,
        nodefer,
        reset_hand,
        uses_altstack,
        autodisarm,
        args.fxstate.is_some(),
        handler,
        frame_address,
        info_address,
        context_address,
        fpstate_address
    );
    Ok(UserReturn {
        rax: 0,
        rdi: u64::from(signal),
        rsi: info_address,
        rdx: context_address,
        r10: 0,
        r8: 0,
        r9: 0,
        r11: 0,
        rcx: handler,
        user_rsp: frame_address,
    })
}

/// Delivers at most one pending signal at a syscall return point.
/// 在 syscall 返回点最多投递一个 pending 信号。
fn deliver_pending_signal(
    process: ObjId,
    args: &SyscallArgs,
    user_ip: Option<(u64, u64)>,
    interrupted_result: i64,
) -> Option<UserReturn> {
    let signal = take_deliverable_signal(process)?;
    let action = proc::linux_signal_action(process, signal)?;
    if action[0] == 1 {
        crate::kprintln!("[JSR-LINUX-SIGNAL] ignored signal={}", signal);
        return None;
    }
    let user_ip = user_ip?;
    match build_signal_frame(process, signal, args, user_ip, interrupted_result) {
        Ok(user) => Some(user),
        Err(error) => {
            crate::kprintln!(
                "[JSR-LINUX-SIGNAL] complete=false signal={} error={}",
                signal,
                error as i32
            );
            let _ = proc::begin_exit(process, 128 + i64::from(signal));
            None
        }
    }
}

/// Validates and queues a same-process `tgkill` request.
/// 校验并在同进程目标线程登记 `tgkill` 请求。
fn linux_tgkill(process: ObjId, args: [u64; 6]) -> Result<(), CompatErrno> {
    let tgid = u32::try_from(args[0]).map_err(|_| CompatErrno::Invalid)?;
    let tid = u32::try_from(args[1]).map_err(|_| CompatErrno::Invalid)?;
    let signal = u32::try_from(args[2]).map_err(|_| CompatErrno::Invalid)?;
    if tgid == 0 || tid == 0 || signal > 64 {
        return Err(CompatErrno::Invalid);
    }
    if proc::linux_pid(process) != Some(tgid) {
        return Err(CompatErrno::NoProcess);
    }
    if signal == 0 {
        return has_linux_thread(process, tid)
            .then_some(())
            .ok_or(CompatErrno::NoProcess);
    }
    if matches!(signal, 9 | 19) {
        return Err(CompatErrno::Invalid);
    }
    if queue_thread_signal(process, tid, signal) {
        Ok(())
    } else {
        Err(CompatErrno::NoProcess)
    }
}

/// Queues a process-directed `kill` for the current compatibility process.
/// 为当前兼容进程登记一个进程定向 `kill`。
fn linux_kill(process: ObjId, args: [u64; 6]) -> Result<(), CompatErrno> {
    let pid = u32::try_from(args[0]).map_err(|_| CompatErrno::Invalid)?;
    let signal = u32::try_from(args[1]).map_err(|_| CompatErrno::Invalid)?;
    if pid == 0 || pid != proc::linux_pid(process).ok_or(CompatErrno::NoProcess)? {
        return Err(CompatErrno::NoProcess);
    }
    if signal == 0 {
        return Ok(());
    }
    if signal > 64 || matches!(signal, 9 | 19) {
        return Err(CompatErrno::Invalid);
    }
    if queue_process_signal(process, signal) {
        Ok(())
    } else {
        Err(CompatErrno::NoSpace)
    }
}

/// Restores the interrupted register and signal-mask context from `rt_sigreturn`.
/// 从 `rt_sigreturn` 恢复被打断的寄存器和信号屏蔽上下文。
fn linux_rt_sigreturn(
    process: ObjId,
    user_rsp: u64,
    args: &SyscallArgs,
) -> Result<UserReturn, CompatErrno> {
    if user_rsp < crate::arch::USER_WINDOW.0
        || user_rsp
            .checked_add(968)
            .is_none_or(|end| end > crate::arch::USER_WINDOW.1)
    {
        return Err(CompatErrno::Fault);
    }
    let mut context = [0u8; 968];
    proc::read(process, user_rsp, &mut context).map_err(|_| CompatErrno::Fault)?;
    let uc_flags = u64::from_le_bytes(context[..8].try_into().expect("fixed uc_flags field"));
    let greg = |index: usize| {
        u64::from_le_bytes(
            context[SIGNAL_UC_GREGS + index * 8..SIGNAL_UC_GREGS + index * 8 + 8]
                .try_into()
                .expect("fixed greg field"),
        )
    };
    let rip = greg(16);
    let rsp = greg(15);
    if !user_register(rip) || !user_register(rsp) {
        return Err(CompatErrno::Fault);
    }
    let old_mask = u64::from_le_bytes(
        context[SIGNAL_UC_SIGMASK..SIGNAL_UC_SIGMASK + 8]
            .try_into()
            .expect("fixed signal-mask field"),
    );
    if !set_current_signal_mask(process, old_mask) {
        return Err(CompatErrno::Invalid);
    }
    let fpstate_address = u64::from_le_bytes(
        context[SIGNAL_UC_FPREGS..SIGNAL_UC_FPREGS + 8]
            .try_into()
            .expect("fixed fpregs field"),
    );
    if fpstate_address < crate::arch::USER_WINDOW.0
        || fpstate_address
            .checked_add(crate::syscall::XSAVE_BYTES as u64)
            .is_none_or(|end| end > crate::arch::USER_WINDOW.1)
    {
        return Err(CompatErrno::Fault);
    }
    let mut fxstate = [0u8; crate::syscall::XSAVE_BYTES];
    proc::read(process, fpstate_address, &mut fxstate).map_err(|_| CompatErrno::Fault)?;
    let Some(destination) = args.fxstate else {
        return Err(CompatErrno::Fault);
    };
    // SAFETY: the syscall entry owns this aligned FP state buffer until return;
    // rt_sigreturn can replace it with the validated userspace signal state.
    unsafe {
        *destination = fxstate;
    }
    if uc_flags & JASPER_UC_FLAG_ALTSTACK != 0
        && !leave_altstack(process, uc_flags & JASPER_UC_FLAG_ALTSTACK_AUTODISARM != 0)
    {
        return Err(CompatErrno::Invalid);
    }
    crate::kprintln!(
        "[JSR-LINUX-SIGNAL] restored rip={:#x} rsp={:#x} mask={:#x}",
        rip,
        rsp,
        old_mask
    );
    Ok(UserReturn {
        rax: greg(13),
        rdi: greg(8),
        rsi: greg(9),
        rdx: greg(12),
        r10: greg(2),
        r8: greg(0),
        r9: greg(1),
        r11: greg(3),
        rcx: rip,
        user_rsp: rsp,
    })
}

fn set_clear_child_tid(process: ObjId, address: u64) -> Option<u32> {
    let (task, _) = sched::current();
    let mut state = COMPAT.lock();
    let entry = state
        .threads
        .iter_mut()
        .flatten()
        .find(|entry| entry.process == process && entry.task == task)?;
    entry.clear_child_tid = address;
    Some(entry.tid)
}

fn register_robust_list(process: ObjId, address: u64, length: u64) -> bool {
    if length != 24 || address < crate::arch::USER_WINDOW.0 || address >= crate::arch::USER_WINDOW.1
    {
        return false;
    }
    let (task, _) = sched::current();
    let mut state = COMPAT.lock();
    let Some(entry) = state
        .threads
        .iter_mut()
        .flatten()
        .find(|entry| entry.process == process && entry.task == task)
    else {
        return false;
    };
    entry.robust_list = address;
    entry.robust_list_len = length;
    true
}

fn register_rseq(process: ObjId, address: u64, length: u64, flags: u64, signature: u64) -> bool {
    if flags != 0
        || signature != 0x5305_3053
        || length == 0
        || length > 32
        || address < crate::arch::USER_WINDOW.0
        || address
            .checked_add(length)
            .is_none_or(|end| end > crate::arch::USER_WINDOW.1)
    {
        return false;
    }
    let (task, _) = sched::current();
    {
        let mut state = COMPAT.lock();
        let Some(entry) = state
            .threads
            .iter_mut()
            .flatten()
            .find(|entry| entry.process == process && entry.task == task)
        else {
            return false;
        };
        entry.rseq = address;
        entry.rseq_len = length as u32;
    }
    let cpu = crate::arch::cpu_index() as u32;
    let mut initial = [0u8; 16];
    initial[..4].copy_from_slice(&cpu.to_le_bytes());
    initial[4..8].copy_from_slice(&cpu.to_le_bytes());
    if proc::write(process, address, &initial).is_err() {
        unregister_linux_thread(task);
        return false;
    }
    true
}

/// Clears `clear_child_tid` and wakes a joining Linux thread.
///
/// 在线程退出时清零 `clear_child_tid` 并唤醒 Linux join 等待者。
#[cfg(all(feature = "linux-abi", target_arch = "x86_64"))]
pub(crate) fn linux_thread_exit(process: ObjId, task: crate::task::TaskId) {
    let (clear, tid, robust_list, rseq, rseq_len, last_thread) = {
        let mut state = COMPAT.lock();
        let Some(slot) = state
            .threads
            .iter()
            .position(|entry| entry.is_some_and(|entry| entry.task == task))
        else {
            return;
        };
        let entry = state.threads[slot].take().expect("live Linux thread");
        let last_thread = !state
            .threads
            .iter()
            .flatten()
            .any(|entry| entry.process == process);
        (
            entry.clear_child_tid,
            entry.tid,
            entry.robust_list,
            entry.rseq,
            entry.rseq_len,
            last_thread,
        )
    };
    if robust_list != 0 {
        let handled = process_robust_list(process, tid, robust_list);
        crate::kprintln!("[JSR-LINUX-ROBUST] handled={handled} tid={tid}");
    }
    if rseq != 0 && rseq_len >= 16 {
        let mut unregister = [0u8; 16];
        unregister[..8].fill(0xff);
        let _ = proc::write(process, rseq, &unregister);
    }
    if clear != 0 {
        let _ = proc::write(process, clear, &0u32.to_le_bytes());
        let _ = futex_wake(process, clear, usize::MAX);
    }
    if last_thread {
        remove_process_signals(process);
    }
}

fn process_robust_list(process: ObjId, tid: u32, head: u64) -> usize {
    const MAX_NODES: usize = 64;
    const FUTEX_OWNER_DIED: u32 = 0x4000_0000;
    let window = crate::arch::USER_WINDOW;
    let Some(first) = proc::read_u64(process, head) else {
        return 0;
    };
    let Some(offset) = proc::read_u64(process, head + 8) else {
        return 0;
    };
    let Some(pending) = proc::read_u64(process, head + 16) else {
        return 0;
    };
    let offset = offset as i64;
    let mut visited = [0u64; MAX_NODES];
    let mut visited_len = 0usize;
    let mut handled = 0usize;
    for node in [pending, first] {
        let mut current = node;
        while current != 0 && current != head && visited_len < MAX_NODES {
            if current < window.0
                || current + 8 > window.1
                || visited[..visited_len].contains(&current)
            {
                break;
            }
            visited[visited_len] = current;
            visited_len += 1;
            let futex = current as i128 + i128::from(offset);
            if futex >= i128::from(window.0)
                && futex + 4 <= i128::from(window.1)
                && futex as u64 % 4 == 0
            {
                let address = futex as u64;
                let mut value = [0u8; 4];
                if proc::read(process, address, &mut value).is_ok()
                    && u32::from_le_bytes(value) == tid
                    && proc::write(process, address, &(tid | FUTEX_OWNER_DIED).to_le_bytes())
                        .is_ok()
                {
                    let _ = futex_wake(process, address, 1);
                    handled += 1;
                }
            }
            let Some(next) = proc::read_u64(process, current) else {
                break;
            };
            current = next;
        }
        if node == pending && first != 0 {
            // Pending is not part of the circular list; visit it once, then walk `first`.
            continue;
        }
    }
    handled
}

fn futex_value(process: ObjId, address: u64) -> Result<u32, CompatErrno> {
    let mut bytes = [0u8; 4];
    proc::read(process, address, &mut bytes).map_err(|_| CompatErrno::Fault)?;
    Ok(u32::from_le_bytes(bytes))
}

fn futex_wait(
    process: ObjId,
    address: u64,
    expected: u32,
    deadline_ns: Option<u64>,
) -> Result<u64, CompatErrno> {
    if address % 4 != 0 {
        return Err(CompatErrno::Invalid);
    }
    if futex_value(process, address)? != expected {
        return Err(CompatErrno::TryAgain);
    }
    let generation = {
        let mut state = COMPAT.lock();
        let slot = if let Some(slot) = state.futexes.iter().position(|entry| {
            entry.is_some_and(|entry| entry.process == process && entry.address == address)
        }) {
            slot
        } else {
            let slot = state
                .futexes
                .iter()
                .position(Option::is_none)
                .ok_or(CompatErrno::NoSpace)?;
            state.futexes[slot] = Some(FutexWord {
                process,
                address,
                generation: 1,
                waiters: 0,
            });
            slot
        };
        let word = state.futexes[slot].as_mut().ok_or(CompatErrno::NoSpace)?;
        word.waiters = word.waiters.checked_add(1).ok_or(CompatErrno::NoSpace)?;
        word.generation
    };
    let result = loop {
        if proc::current_exiting() {
            break Err(CompatErrno::Interrupted);
        }
        if current_signal_pending(process) {
            crate::kprintln!(
                "[JSR-LINUX-FUTEX] interrupted process={:#x} address={:#x} signal_pending=true",
                process.raw(),
                address
            );
            break Err(CompatErrno::Interrupted);
        }
        if deadline_ns.is_some_and(|deadline| sched::now_ns() >= deadline) {
            break Err(CompatErrno::TimedOut);
        }
        let woke = {
            let state = COMPAT.lock();
            state
                .futexes
                .iter()
                .flatten()
                .find(|word| word.process == process && word.address == address)
                .is_none_or(|word| word.generation != generation)
        };
        if woke {
            break Ok(0);
        }
        sched::pause();
    };
    if let Some(word) = COMPAT
        .lock()
        .futexes
        .iter_mut()
        .flatten()
        .find(|word| word.process == process && word.address == address)
    {
        word.waiters = word.waiters.saturating_sub(1);
    }
    result
}

fn futex_wake(process: ObjId, address: u64, count: usize) -> Result<u64, CompatErrno> {
    if address % 4 != 0 {
        return Err(CompatErrno::Invalid);
    }
    let mut state = COMPAT.lock();
    let Some(word) = state
        .futexes
        .iter_mut()
        .flatten()
        .find(|word| word.process == process && word.address == address)
    else {
        return Ok(0);
    };
    let count = count.min(usize::from(word.waiters));
    if count != 0 {
        word.generation = word.generation.wrapping_add(1).max(1);
    }
    Ok(count as u64)
}

fn futex_timeout(pointer: u64, realtime: bool) -> Result<Option<u64>, CompatErrno> {
    if pointer == 0 {
        return Ok(None);
    }
    if realtime {
        return Err(CompatErrno::Invalid);
    }
    let mut bytes = [0u8; 16];
    copy_from_user(&mut bytes, pointer, 16).map_err(|_| CompatErrno::Fault)?;
    let seconds = u64::from_le_bytes(bytes[..8].try_into().unwrap());
    let nanos = u64::from_le_bytes(bytes[8..].try_into().unwrap());
    if nanos >= 1_000_000_000 {
        return Err(CompatErrno::Invalid);
    }
    let duration = seconds
        .checked_mul(1_000_000_000)
        .and_then(|value| value.checked_add(nanos))
        .ok_or(CompatErrno::Invalid)?;
    Ok(Some(sched::now_ns().saturating_add(duration)))
}

/// Dispatches one x86_64 Linux syscall for the current process.
///
/// 执行当前 Linux flavor 进程的一次 syscall；未映射调用返回 `ENOSYS`，未授权调用
/// 返回 `EPERM`，所有错误使用 Linux 负 errno 返回约定。
pub fn on_syscall(a: &SyscallArgs) -> SyscallOutcome {
    if proc::current_exiting() {
        proc::thread_exit(0, "killed linux process");
    }
    #[cfg(any(
        feature = "compat-dynamic-libc-verify",
        feature = "workload-io-verify"
    ))]
    trace_request(a);
    let Some(pid) = proc::current_process() else {
        return SyscallOutcome::value(-i64::from(CompatErrno::NoSys as i32));
    };
    let dispatched = dispatch(SyscallRequest {
        number: a.id,
        args: a.args,
    });
    let SyscallDispatch::Mapped(call) = dispatched else {
        #[cfg(any(
            feature = "compat-dynamic-libc-verify",
            feature = "lifecycle-root-exec-verify"
        ))]
        crate::kprintln!("[JSR-LINUX-UNSUPPORTED] nr={}", a.id);
        return SyscallOutcome::value(-i64::from(CompatErrno::NoSys as i32));
    };
    if !proc::linux_syscall_allowed(pid, call.syscall) {
        return SyscallOutcome::value(-i64::from(CompatErrno::Perm as i32));
    }
    if call.syscall == LinuxSyscall::Execve {
        return match linux_execve(pid, call.args) {
            Ok((entry, user_rsp)) => {
                let _ = proc::vfork_commit_exec(pid);
                SyscallOutcome {
                    value: 0,
                    redirect: None,
                    exec_redirect: Some(ExecReturn { entry, user_rsp }),
                }
            }
            Err(error) => {
                crate::kprintln!("[JSR-LINUX-EXEC-FAIL] errno={:?}", error);
                SyscallOutcome::value(-i64::from(error as i32))
            }
        };
    }
    if call.syscall == LinuxSyscall::RtSigReturn {
        let Some((_, user_rsp)) = a.user_ip else {
            return SyscallOutcome::value(-i64::from(CompatErrno::Fault as i32));
        };
        return match linux_rt_sigreturn(pid, user_rsp, a) {
            Ok(user) => SyscallOutcome {
                value: 0,
                redirect: Some(user),
                exec_redirect: None,
            },
            Err(error) => SyscallOutcome::value(-i64::from(error as i32)),
        };
    }
    let value = execute(pid, call, a.user_ip, a.user_preserved);
    #[cfg(any(
        feature = "compat-dynamic-libc-verify",
        feature = "lifecycle-root-exec-verify"
    ))]
    if value == -i64::from(CompatErrno::NoSys as i32) {
        crate::kprintln!("[JSR-LINUX-ENOSYS] call={:?}", call.syscall);
    }
    let redirect = deliver_pending_signal(pid, a, a.user_ip, value);
    if proc::current_exiting() {
        proc::thread_exit(0, "linux signal default action");
    }
    SyscallOutcome {
        value,
        redirect,
        exec_redirect: None,
    }
}

fn execute(
    pid: ObjId,
    call: LinuxCall,
    user_ip: Option<(u64, u64)>,
    user_preserved: [u64; 6],
) -> i64 {
    match call.syscall {
        LinuxSyscall::Write => compat_result(linux_write(pid, call.args)),
        LinuxSyscall::WriteV => compat_result(linux_writev(pid, call.args)),
        LinuxSyscall::GetDents64 => compat_result(linux_getdents64(pid, call.args)),
        LinuxSyscall::Read => compat_result(linux_read(pid, call.args)),
        LinuxSyscall::Pread64 => compat_result(linux_pread64(pid, call.args)),
        LinuxSyscall::ReadV => compat_result(linux_readv(pid, call.args)),
        LinuxSyscall::ReadLinkAt => compat_result(linux_readlinkat(pid, call.args)),
        LinuxSyscall::Close => compat_result(linux_close(pid, call.args[0])),
        LinuxSyscall::Dup => compat_result(linux_dup(pid, call.args)),
        LinuxSyscall::Dup2 => compat_result(linux_dup2(pid, call.args)),
        LinuxSyscall::Dup3 => compat_result(linux_dup3(pid, call.args)),
        LinuxSyscall::Pipe2 => compat_result(linux_pipe2(pid, call.args)),
        LinuxSyscall::Socket => compat_result(linux_socket(pid, call.args)),
        LinuxSyscall::Bind => compat_result(linux_bind(pid, call.args)),
        LinuxSyscall::Listen => compat_result(linux_listen(pid, call.args)),
        LinuxSyscall::Connect => compat_result(linux_connect(pid, call.args)),
        LinuxSyscall::Accept => compat_result(linux_accept(pid, call.args, false)),
        LinuxSyscall::Accept4 => compat_result(linux_accept(pid, call.args, true)),
        LinuxSyscall::SocketPair => compat_result(linux_socketpair(pid, call.args)),
        LinuxSyscall::SendMsg => compat_result(linux_sendmsg(pid, call.args)),
        LinuxSyscall::RecvMsg => compat_result(linux_recvmsg(pid, call.args)),
        LinuxSyscall::SendTo => compat_result(linux_sendto(pid, call.args)),
        LinuxSyscall::RecvFrom => compat_result(linux_recvfrom(pid, call.args)),
        LinuxSyscall::Shutdown => compat_result(linux_shutdown(pid, call.args)),
        LinuxSyscall::GetSockName => compat_result(linux_sockname(pid, call.args, false)),
        LinuxSyscall::GetPeerName => compat_result(linux_sockname(pid, call.args, true)),
        LinuxSyscall::Chdir => compat_result(linux_chdir(pid, call.args[0])),
        LinuxSyscall::OpenAt => compat_result(linux_openat(pid, call.args)),
        LinuxSyscall::Fchdir => compat_result(linux_fchdir(pid, call.args[0])),
        LinuxSyscall::Fstat => compat_result(linux_fstat(pid, call.args)),
        LinuxSyscall::Fstatfs => compat_result(linux_fstatfs(pid, call.args)),
        LinuxSyscall::NewFstatAt => compat_result(linux_newfstatat(pid, call.args)),
        LinuxSyscall::Statx => compat_result(linux_statx(pid, call.args)),
        LinuxSyscall::Fcntl => compat_result(linux_fcntl(pid, call.args)),
        LinuxSyscall::Poll => compat_result(linux_poll(pid, call.args)),
        LinuxSyscall::Ioctl => compat_result(linux_ioctl(pid, call.args)),
        LinuxSyscall::StatFs => compat_result(linux_statfs(call.args)),
        LinuxSyscall::ReadLink => compat_result(linux_readlink(pid, call.args)),
        LinuxSyscall::Mmap => compat_result(linux_mmap(pid, call.args)),
        LinuxSyscall::Munmap => compat_result(linux_munmap(pid, call.args)),
        LinuxSyscall::Mprotect => compat_result(linux_mprotect(pid, call.args)),
        LinuxSyscall::Madvise => compat_result(linux_madvise(pid, call.args)),
        LinuxSyscall::Clone => compat_result(linux_clone(pid, call.args, user_ip, user_preserved)),
        LinuxSyscall::Clone3 => {
            compat_result(linux_clone3(pid, call.args, user_ip, user_preserved))
        }
        LinuxSyscall::Vfork => compat_result(linux_vfork(pid, call.args, user_ip, user_preserved)),
        LinuxSyscall::Brk => compat_result(linux_brk(pid, call.args[0])),
        LinuxSyscall::Access => compat_result(linux_access(call.args[0])),
        LinuxSyscall::ArchPrctl => compat_result(linux_arch_prctl(call.args)),
        LinuxSyscall::ClockGettime => compat_result(linux_clock_gettime(call.args)),
        LinuxSyscall::ClockGetres => compat_result(linux_clock_getres(call.args)),
        LinuxSyscall::Nanosleep => compat_result(linux_nanosleep(pid, call.args)),
        LinuxSyscall::ClockNanosleep => compat_result(linux_clock_nanosleep(pid, call.args)),
        LinuxSyscall::RtSigAction => compat_result(linux_rt_sigaction(pid, call.args)),
        LinuxSyscall::RtSigProcMask => compat_result(linux_rt_sigprocmask(pid, call.args)),
        LinuxSyscall::Tgkill => compat_result(linux_tgkill(pid, call.args).map(|()| 0)),
        LinuxSyscall::SchedYield => {
            sched::yield_with_cause(crate::sched::scheduler::Cause::YIELD);
            0
        }
        LinuxSyscall::Sigaltstack => compat_result(linux_sigaltstack(pid, call.args)),
        LinuxSyscall::Kill => compat_result(linux_kill(pid, call.args).map(|()| 0)),
        LinuxSyscall::Uname => compat_result(linux_uname(call.args)),
        LinuxSyscall::GetPid => proc::linux_pid(pid)
            .map(i64::from)
            .ok_or(CompatErrno::NoSys)
            .unwrap_or_else(|error| -i64::from(error as i32)),
        LinuxSyscall::GetTid => linux_tid(pid)
            .map(i64::from)
            .ok_or(CompatErrno::NoSys)
            .unwrap_or_else(|error| -i64::from(error as i32)),
        LinuxSyscall::GetRandom => compat_result(linux_getrandom(call.args)),
        LinuxSyscall::GetTimeOfDay => compat_result(linux_gettimeofday(call.args)),
        LinuxSyscall::Time => compat_result(linux_time(call.args)),
        LinuxSyscall::Getcwd => compat_result(linux_getcwd(pid, call.args)),
        LinuxSyscall::GetUid | LinuxSyscall::GetEuid => {
            compat_core::syscall::LINUX_COMPAT_UID as i64
        }
        LinuxSyscall::GetGid | LinuxSyscall::GetEgid => {
            compat_core::syscall::LINUX_COMPAT_GID as i64
        }
        LinuxSyscall::GetPpid => proc::linux_ppid(pid)
            .map(i64::from)
            .ok_or(CompatErrno::NoSys)
            .unwrap_or_else(|error| -i64::from(error as i32)),
        // The compatibility identity has no supplementary groups.
        // 兼容身份没有附加组，因此 size 查询和写入都返回 0。
        LinuxSyscall::GetGroups => 0,
        LinuxSyscall::Lseek => compat_result(linux_lseek(pid, call.args)),
        LinuxSyscall::GetCpu => compat_result(linux_getcpu(call.args)),
        LinuxSyscall::Sysinfo => compat_result(linux_sysinfo(call.args[0])),
        LinuxSyscall::SchedGetAffinity => compat_result(linux_sched_getaffinity(pid, call.args)),
        LinuxSyscall::SchedGetScheduler => {
            compat_result(linux_sched_getscheduler(pid, call.args[0]))
        }
        LinuxSyscall::SetTidAddress => set_clear_child_tid(pid, call.args[0])
            .map(i64::from)
            .ok_or(CompatErrno::NoSys)
            .unwrap_or_else(|error| -i64::from(error as i32)),
        LinuxSyscall::SetRobustList => {
            if register_robust_list(pid, call.args[0], call.args[1]) {
                0
            } else {
                -i64::from(CompatErrno::Invalid as i32)
            }
        }
        LinuxSyscall::Rseq => {
            if register_rseq(pid, call.args[0], call.args[1], call.args[2], call.args[3]) {
                0
            } else {
                -i64::from(CompatErrno::Invalid as i32)
            }
        }
        LinuxSyscall::Prlimit64 => compat_result(linux_prlimit(pid, call.args)),
        LinuxSyscall::Futex => compat_result(linux_futex(pid, call.args)),
        LinuxSyscall::Exit | LinuxSyscall::ExitGroup => {
            let code = call.args[0] as i64;
            proc::thread_exit(code, "linux process exit")
        }
        LinuxSyscall::Wait4 => compat_result(linux_wait4(pid, call.args)),
        _ => -i64::from(CompatErrno::NoSys as i32),
    }
}

/// Writes the Linux x86_64 `struct utsname` compatibility identity.
/// 写入 Linux x86_64 `struct utsname` 兼容身份。
fn linux_uname(args: [u64; 6]) -> Result<u64, CompatErrno> {
    let utsname = compat_core::linux_utsname();
    copy_to_user(args[0], &utsname, utsname.len()).map_err(|_| CompatErrno::Fault)?;
    Ok(0)
}

fn linux_write(pid: ObjId, args: [u64; 6]) -> Result<u64, CompatErrno> {
    let fd = u32::try_from(args[0]).map_err(|_| CompatErrno::BadFd)?;
    let len = usize::try_from(args[2]).map_err(|_| CompatErrno::Invalid)?;
    if let Some(entry) = proc::linux_fd(pid, fd) {
        if entry.kind == compat_core::fd::CompatKind::Pipe {
            if !entry.rights.contains(kernel_core::object::Rights::WRITE) {
                return Err(CompatErrno::BadFd);
            }
            return linux_pipe_write(pid, fd, entry.handle, args[1], len);
        }
        if entry.kind == compat_core::fd::CompatKind::Socket {
            if !entry.rights.contains(kernel_core::object::Rights::WRITE) {
                return Err(CompatErrno::BadFd);
            }
            return linux_socket_write(pid, fd, entry.handle, args[1], len, false, false);
        }
    }
    authorize_console(pid, fd, true)?;
    if len > CONSOLE_WRITE_MAX {
        return Err(CompatErrno::Invalid);
    }
    if len == 0 {
        return Ok(0);
    }
    let io = admit_process_io(pid, len as u64, 1)?;
    let mut bytes = alloc::vec![0u8; len];
    copy_from_user(&mut bytes, args[1], len).map_err(|_| CompatErrno::Fault)?;
    console::write_bytes(&bytes);
    io.commit();
    Ok(len as u64)
}

/// Returns the compatibility process's current directory.
///
/// 返回兼容进程的当前目录；当前装载命名空间只提供 System A 根。
fn linux_getcwd(pid: ObjId, args: [u64; 6]) -> Result<u64, CompatErrno> {
    let cwd = proc::linux_cwd(pid).ok_or(CompatErrno::NoSys)?;
    let mut output = alloc::vec::Vec::with_capacity(cwd.path().len() + 1);
    output.extend_from_slice(cwd.path());
    output.push(0);
    let size = usize::try_from(args[1]).map_err(|_| CompatErrno::Invalid)?;
    if size == 0 {
        return Err(CompatErrno::Invalid);
    }
    if size < output.len() {
        return Err(CompatErrno::Range);
    }
    copy_to_user(args[0], &output, output.len()).map_err(|_| CompatErrno::Fault)?;
    Ok(output.len() as u64)
}

/// Writes one Linux iovec array to an authorized console descriptor.
///
/// 写入受权限保护的 Linux 控制台 fd；iovec 数量、总长度和每个用户区间都有界检查。
fn linux_writev(pid: ObjId, args: [u64; 6]) -> Result<u64, CompatErrno> {
    const MAX_IOVECS: usize = 16;
    const IOVEC_BYTES: usize = 16;
    let fd = u32::try_from(args[0]).map_err(|_| CompatErrno::BadFd)?;
    let count = usize::try_from(args[2]).map_err(|_| CompatErrno::Invalid)?;
    if count > MAX_IOVECS {
        return Err(CompatErrno::Invalid);
    }
    authorize_console(pid, fd, true)?;
    let mut total = 0usize;
    let mut bytes = alloc::vec::Vec::new();
    for index in 0..count {
        let vector = args[1]
            .checked_add((index * IOVEC_BYTES) as u64)
            .ok_or(CompatErrno::Fault)?;
        let mut iovec = [0u8; IOVEC_BYTES];
        copy_from_user(&mut iovec, vector, IOVEC_BYTES).map_err(|_| CompatErrno::Fault)?;
        let base = u64::from_le_bytes(iovec[0..8].try_into().unwrap());
        let len = usize::try_from(u64::from_le_bytes(iovec[8..16].try_into().unwrap()))
            .map_err(|_| CompatErrno::Invalid)?;
        total = total.checked_add(len).ok_or(CompatErrno::Invalid)?;
        if total > CONSOLE_WRITE_MAX {
            return Err(CompatErrno::Invalid);
        }
        let start = bytes.len();
        bytes.resize(start + len, 0);
        copy_from_user(&mut bytes[start..], base, len).map_err(|_| CompatErrno::Fault)?;
    }
    let io = admit_process_io(pid, total as u64, 1)?;
    if !bytes.is_empty() {
        console::write_bytes(&bytes);
    }
    io.commit();
    Ok(total as u64)
}

/// Reads bounded `linux_dirent64` records from one compatibility directory.
///
/// 从兼容目录读取有界 `linux_dirent64`；`.` 与 `..` 动态生成，游标只在全部记录
/// 成功写入用户缓冲区后推进。过小缓冲区不会返回半条记录。
fn linux_getdents64(pid: ObjId, args: [u64; 6]) -> Result<u64, CompatErrno> {
    const MAX_GETDENTS: usize = 64 * 1024;
    const DT_DIR: u8 = 4;
    const DT_REG: u8 = 8;
    let fd = u32::try_from(args[0]).map_err(|_| CompatErrno::BadFd)?;
    let capacity = usize::try_from(args[2]).map_err(|_| CompatErrno::Invalid)?;
    if capacity > MAX_GETDENTS {
        return Err(CompatErrno::Invalid);
    }
    let (handle, start) = proc::linux_dir_state(pid, fd).ok_or(CompatErrno::BadFd)?;
    let directory = crate::linux_vfs::DirectoryId::from_handle(handle).ok_or(CompatErrno::BadFd)?;
    let children = crate::linux_vfs::directory_entries(directory);
    let count = 2usize
        .checked_add(children.len())
        .ok_or(CompatErrno::Invalid)?;
    let start = usize::try_from(start).map_err(|_| CompatErrno::Invalid)?;
    if start > count {
        return Err(CompatErrno::Invalid);
    }
    let mut output = alloc::vec::Vec::new();
    let mut index = start;
    while index < count {
        let (name, inode, kind) = if index == 0 {
            (b".".as_slice(), directory.inode(), DT_DIR)
        } else if index == 1 {
            (b"..".as_slice(), directory.inode(), DT_DIR)
        } else {
            let entry = &children[index - 2];
            (
                entry.name,
                entry.node.inode(),
                if entry.node.is_directory() {
                    DT_DIR
                } else {
                    DT_REG
                },
            )
        };
        let record_len = align_up(
            19usize.saturating_add(name.len()).saturating_add(1) as u64,
            8,
        ) as usize;
        if output.len().saturating_add(record_len) > capacity {
            if output.is_empty() {
                return Err(CompatErrno::Invalid);
            }
            break;
        }
        let base = output.len();
        output.resize(base + record_len, 0);
        output[base..base + 8].copy_from_slice(&inode.to_le_bytes());
        output[base + 8..base + 16].copy_from_slice(&((index + 1) as i64).to_le_bytes());
        output[base + 16..base + 18].copy_from_slice(&(record_len as u16).to_le_bytes());
        output[base + 18] = kind;
        output[base + 19..base + 19 + name.len()].copy_from_slice(name);
        index += 1;
    }
    let io = admit_process_io(pid, output.len() as u64, 1)?;
    if !output.is_empty() {
        copy_to_user(args[1], &output, output.len()).map_err(|_| CompatErrno::Fault)?;
    }
    io.commit();
    if !proc::set_linux_dir_offset(pid, fd, index as u64) {
        return Err(CompatErrno::BadFd);
    }
    Ok(output.len() as u64)
}

fn authorize_console(pid: ObjId, fd: u32, write: bool) -> Result<(), CompatErrno> {
    let entry = proc::linux_fd(pid, fd).ok_or(CompatErrno::BadFd)?;
    let rights = if write {
        kernel_core::object::Rights::WRITE
    } else {
        kernel_core::object::Rights::READ
    };
    if !entry.rights.contains(rights)
        || entry.kind != compat_core::fd::CompatKind::Other
        || entry.handle != proc::LINUX_CONSOLE_HANDLE
    {
        return Err(CompatErrno::BadFd);
    }
    Ok(())
}

fn admit_process_io(pid: ObjId, bytes: u64, ops: u64) -> Result<crate::workload::IoPermit, CompatErrno> {
    crate::workload::begin_process_io(pid, bytes, ops).map_err(|error| match error {
        kernel_core::workload::WorkloadError::Quota
        | kernel_core::workload::WorkloadError::InvalidState => CompatErrno::NoSpace,
        kernel_core::workload::WorkloadError::InvalidKey => CompatErrno::NoProcess,
        _ => CompatErrno::Perm,
    })
}

/// Implements bounded Linux `read(2)` for stdin and virtual read-only files.
///
/// 标准输入当前没有数据源并返回 EOF；文件读取在全部用户页校验通过后才提交游标。
fn linux_read(pid: ObjId, args: [u64; 6]) -> Result<u64, CompatErrno> {
    const MAX_READ: usize = 1024 * 1024;
    let fd = u32::try_from(args[0]).map_err(|_| CompatErrno::BadFd)?;
    let len = usize::try_from(args[2]).map_err(|_| CompatErrno::Invalid)?;
    if len > MAX_READ {
        return Err(CompatErrno::Invalid);
    }
    if let Some(entry) = proc::linux_fd(pid, fd) {
        if entry.kind == compat_core::fd::CompatKind::Pipe {
            if !entry.rights.contains(kernel_core::object::Rights::READ) {
                return Err(CompatErrno::BadFd);
            }
            return linux_pipe_read(pid, fd, entry.handle, args[1], len);
        }
        if entry.kind == compat_core::fd::CompatKind::Socket {
            if !entry.rights.contains(kernel_core::object::Rights::READ) {
                return Err(CompatErrno::BadFd);
            }
            return linux_socket_read(pid, fd, entry.handle, args[1], len, false);
        }
    }
    if fd == 0 {
        authorize_console(pid, fd, false)?;
        return Ok(0);
    }
    if proc::linux_fd(pid, fd)
        .is_some_and(|entry| entry.kind == compat_core::fd::CompatKind::Directory)
    {
        return Err(CompatErrno::IsDirectory);
    }
    let (handle, offset) = proc::linux_file_state(pid, fd).ok_or(CompatErrno::BadFd)?;
    let file = crate::linux_vfs::FileId::from_handle(handle).ok_or(CompatErrno::BadFd)?;
    let source = file.bytes();
    let offset = usize::try_from(offset).map_err(|_| CompatErrno::Invalid)?;
    let available = source.len().saturating_sub(offset).min(len);
    let io = admit_process_io(pid, available as u64, 1)?;
    if available != 0 {
        copy_to_user(args[1], &source[offset..offset + available], available)
            .map_err(|_| CompatErrno::Fault)?;
    }
    io.commit();
    if !proc::set_linux_file_offset(pid, fd, (offset + available) as u64) {
        return Err(CompatErrno::BadFd);
    }
    Ok(available as u64)
}

/// Implements bounded `pread64(2)` without changing the descriptor cursor.
///
/// 从显式文件偏移读取真实虚拟文件字节；非法 fd、越界长度或用户页错误均失败关闭。
fn linux_pread64(pid: ObjId, args: [u64; 6]) -> Result<u64, CompatErrno> {
    const MAX_READ: usize = 1024 * 1024;
    let fd = u32::try_from(args[0]).map_err(|_| CompatErrno::BadFd)?;
    let len = usize::try_from(args[2]).map_err(|_| CompatErrno::Invalid)?;
    if len > MAX_READ {
        return Err(CompatErrno::Invalid);
    }
    let (handle, _) = proc::linux_file_state(pid, fd).ok_or(CompatErrno::BadFd)?;
    let file = crate::linux_vfs::FileId::from_handle(handle).ok_or(CompatErrno::BadFd)?;
    let offset = usize::try_from(args[3]).map_err(|_| CompatErrno::Invalid)?;
    let source = file.bytes();
    let available = source.len().saturating_sub(offset).min(len);
    let io = admit_process_io(pid, available as u64, 1)?;
    if available != 0 {
        copy_to_user(args[1], &source[offset..offset + available], available)
            .map_err(|_| CompatErrno::Fault)?;
    }
    io.commit();
    Ok(available as u64)
}

/// Implements bounded Linux `readv(2)` with all-or-nothing user-range validation.
///
/// 有界读取虚拟文件到多个用户区间；先固定全部目标页，失败时不写入且不推进游标。
fn linux_readv(pid: ObjId, args: [u64; 6]) -> Result<u64, CompatErrno> {
    const MAX_IOVECS: usize = 16;
    const MAX_READ: usize = 1024 * 1024;
    const IOVEC_BYTES: usize = 16;
    let fd = u32::try_from(args[0]).map_err(|_| CompatErrno::BadFd)?;
    let count = usize::try_from(args[2]).map_err(|_| CompatErrno::Invalid)?;
    if count > MAX_IOVECS {
        return Err(CompatErrno::Invalid);
    }
    let mut vectors = alloc::vec::Vec::with_capacity(count);
    let mut total = 0usize;
    for index in 0..count {
        let address = args[1]
            .checked_add((index * IOVEC_BYTES) as u64)
            .ok_or(CompatErrno::Fault)?;
        let mut iovec = [0u8; IOVEC_BYTES];
        copy_from_user(&mut iovec, address, IOVEC_BYTES).map_err(|_| CompatErrno::Fault)?;
        let base = u64::from_le_bytes(iovec[..8].try_into().unwrap());
        let len = usize::try_from(u64::from_le_bytes(iovec[8..].try_into().unwrap()))
            .map_err(|_| CompatErrno::Invalid)?;
        base.checked_add(u64::try_from(len).map_err(|_| CompatErrno::Invalid)?)
            .ok_or(CompatErrno::Fault)?;
        total = total.checked_add(len).ok_or(CompatErrno::Invalid)?;
        if total > MAX_READ {
            return Err(CompatErrno::Invalid);
        }
        vectors.push((base, len));
    }
    if fd == 0 {
        authorize_console(pid, fd, false)?;
        return Ok(0);
    }
    let (handle, offset) = proc::linux_file_state(pid, fd).ok_or(CompatErrno::BadFd)?;
    let file = crate::linux_vfs::FileId::from_handle(handle).ok_or(CompatErrno::BadFd)?;
    let source = file.bytes();
    let offset = usize::try_from(offset).map_err(|_| CompatErrno::Invalid)?;
    let available = source.len().saturating_sub(offset).min(total);
    let io = admit_process_io(pid, available as u64, 1)?;
    let mut source_offset = offset;
    let mut remaining = available;
    let mut ranges = alloc::vec::Vec::with_capacity(vectors.len());
    for (base, len) in vectors {
        let take = remaining.min(len);
        if take != 0 {
            ranges.push((base, &source[source_offset..source_offset + take]));
            source_offset += take;
            remaining -= take;
        }
        if remaining == 0 {
            break;
        }
    }
    if !ranges.is_empty() {
        copy_to_user_vectored(&ranges).map_err(|error| match error {
            UserPtrError::Quota | UserPtrError::OutOfMemory => CompatErrno::NoMemory,
            _ => CompatErrno::Fault,
        })?;
    }
    io.commit();
    if !proc::set_linux_file_offset(pid, fd, (offset + available) as u64) {
        return Err(CompatErrno::BadFd);
    }
    Ok(available as u64)
}

/// Repositions one virtual compatibility file or directory using Linux seek origins.
///
/// 按 Linux 的 `SEEK_SET/CUR/END` 更新虚拟文件或目录游标；控制台不是可定位流。
fn linux_lseek(pid: ObjId, args: [u64; 6]) -> Result<u64, CompatErrno> {
    let fd = u32::try_from(args[0]).map_err(|_| CompatErrno::BadFd)?;
    let entry = proc::linux_fd(pid, fd).ok_or(CompatErrno::BadFd)?;
    if entry.handle == proc::LINUX_CONSOLE_HANDLE {
        return Err(CompatErrno::Pipe);
    }
    if entry.kind == compat_core::fd::CompatKind::Directory {
        let (handle, current) = proc::linux_dir_state(pid, fd).ok_or(CompatErrno::BadFd)?;
        let directory =
            crate::linux_vfs::DirectoryId::from_handle(handle).ok_or(CompatErrno::BadFd)?;
        let count = 2usize
            .checked_add(crate::linux_vfs::directory_entries(directory).len())
            .ok_or(CompatErrno::Invalid)?;
        let target =
            compat_core::syscall::seek_target(current, count as u64, args[1] as i64, args[2])
                .ok_or(CompatErrno::Invalid)?;
        if target > count as u64 {
            return Err(CompatErrno::Invalid);
        }
        if !proc::set_linux_dir_offset(pid, fd, target) {
            return Err(CompatErrno::BadFd);
        }
        return Ok(target);
    }
    let (handle, current) = proc::linux_file_state(pid, fd).ok_or(CompatErrno::BadFd)?;
    let file = crate::linux_vfs::FileId::from_handle(handle).ok_or(CompatErrno::BadFd)?;
    let size = file.bytes().len() as u64;
    let target = compat_core::syscall::seek_target(current, size, args[1] as i64, args[2])
        .ok_or(CompatErrno::Invalid)?;
    if !proc::set_linux_file_offset(pid, fd, target) {
        return Err(CompatErrno::BadFd);
    }
    Ok(target)
}

/// Returns the current logical CPU and single compatibility NUMA domain.
///
/// 返回当前逻辑 CPU；当前内存模型是单域 UMA，因此兼容节点稳定为 0。
fn linux_getcpu(args: [u64; 6]) -> Result<u64, CompatErrno> {
    let cpu_bytes = (crate::arch::cpu_index() as u32).to_le_bytes();
    let node_bytes = 0u32.to_le_bytes();
    let mut ranges = alloc::vec::Vec::with_capacity(2);
    if args[0] != 0 {
        ranges.push((args[0], cpu_bytes.as_slice()));
    }
    if args[1] != 0 {
        ranges.push((args[1], node_bytes.as_slice()));
    }
    if !ranges.is_empty() {
        copy_to_user_vectored(&ranges).map_err(|error| match error {
            UserPtrError::Quota | UserPtrError::OutOfMemory => CompatErrno::NoMemory,
            _ => CompatErrno::Fault,
        })?;
    }
    Ok(0)
}

/// Writes a truthful, bounded Linux `sysinfo(2)` snapshot.
///
/// 写入有界且不伪造的 Linux 系统信息快照：时间取真实单调时钟，内存取页帧
/// 分配器，进程数取对象表中的活动 Process。负载平均值当前不可观测，因此保持 0。
fn linux_sysinfo(destination: u64) -> Result<u64, CompatErrno> {
    const SYSINFO_BYTES: usize = 112;
    const PAGE_BYTES: u64 = kernel_core::frame::FRAME_SIZE as u64;

    let uptime_ns = crate::hrtime::now()
        .unwrap_or_else(|| sched::timer_ticks().saturating_mul(crate::hrtime::tick_ns()));
    let uptime = (uptime_ns / 1_000_000_000).min(i64::MAX as u64) as i64;
    let totalram = u64::try_from(crate::mm::frame::usable_frames())
        .map_err(|_| CompatErrno::NoMemory)?
        .checked_mul(PAGE_BYTES)
        .ok_or(CompatErrno::NoMemory)?;
    let freeram = u64::try_from(crate::mm::frame::free_frames())
        .map_err(|_| CompatErrno::NoMemory)?
        .checked_mul(PAGE_BYTES)
        .ok_or(CompatErrno::NoMemory)?;
    if freeram > totalram {
        return Err(CompatErrno::NoMemory);
    }
    let processes = crate::kobj::with(|table| {
        let mut count = 0u16;
        table.for_each_live(|_, object| {
            if matches!(object, crate::kobj::KObject::Process(_)) {
                count = count.saturating_add(1);
            }
            true
        });
        count
    });

    let mut bytes = [0u8; SYSINFO_BYTES];
    bytes[0..8].copy_from_slice(&uptime.to_le_bytes());
    for offset in [8usize, 16, 24] {
        bytes[offset..offset + 8].copy_from_slice(&0u64.to_le_bytes());
    }
    bytes[32..40].copy_from_slice(&totalram.to_le_bytes());
    bytes[40..48].copy_from_slice(&freeram.to_le_bytes());
    bytes[48..56].copy_from_slice(&0u64.to_le_bytes());
    bytes[56..64].copy_from_slice(&0u64.to_le_bytes());
    bytes[64..72].copy_from_slice(&0u64.to_le_bytes());
    bytes[72..80].copy_from_slice(&0u64.to_le_bytes());
    bytes[80..82].copy_from_slice(&processes.to_le_bytes());
    // The x86_64 UAPI aligns totalhigh/freehigh after the two 16-bit fields.
    // x86_64 UAPI 在两个 16 位字段之后按 8 字节对齐 totalhigh/freehigh。
    bytes[88..96].copy_from_slice(&0u64.to_le_bytes());
    bytes[96..104].copy_from_slice(&0u64.to_le_bytes());
    bytes[104..108].copy_from_slice(&1u32.to_le_bytes());
    copy_to_user(destination, &bytes, SYSINFO_BYTES).map_err(|_| CompatErrno::Fault)?;
    Ok(0)
}

/// Returns a Linux thread's effective CPU affinity mask.
///
/// 查询当前 Linux 进程内线程的实际亲和位图；短缓冲、伪造 TID 和坏用户指针失败关闭。
fn linux_sched_getaffinity(pid: ObjId, args: [u64; 6]) -> Result<u64, CompatErrno> {
    const KERNEL_MASK_BYTES: usize = 8;
    let size = usize::try_from(args[1]).map_err(|_| CompatErrno::Invalid)?;
    if size < KERNEL_MASK_BYTES {
        return Err(CompatErrno::Invalid);
    }
    let task = if args[0] == 0 {
        sched::current().0
    } else {
        let tid = u32::try_from(args[0]).map_err(|_| CompatErrno::NoProcess)?;
        linux_task_for_tid(pid, tid).ok_or(CompatErrno::NoProcess)?
    };
    let affinity = sched::task_affinity(task)
        .ok_or(CompatErrno::NoProcess)?
        .intersect(sched::online_cpus());
    let mask = u64::from(affinity.bits());
    copy_to_user(args[2], &mask.to_le_bytes(), KERNEL_MASK_BYTES)
        .map_err(|_| CompatErrno::Fault)?;
    Ok(KERNEL_MASK_BYTES as u64)
}

/// Reports the compatibility scheduling policy for the current Linux process.
///
/// 兼容进程没有 Linux RT 策略，因此自身稳定报告 `SCHED_OTHER`；其他 PID 明确
/// 返回 `ESRCH`，不猜测 Jasper 调度类别与 Linux 策略的等价关系。
fn linux_sched_getscheduler(pid: ObjId, requested: u64) -> Result<u64, CompatErrno> {
    let current = u64::from(proc::linux_pid(pid).ok_or(CompatErrno::NoProcess)?);
    if requested == 0 || requested == current {
        Ok(0)
    } else {
        Err(CompatErrno::NoProcess)
    }
}

fn linux_task_for_tid(process: ObjId, tid: u32) -> Option<crate::task::TaskId> {
    COMPAT
        .lock()
        .threads
        .iter()
        .flatten()
        .find(|entry| entry.process == process && entry.tid == tid)
        .map(|entry| entry.task)
}

/// Maps a bounded file-backed or anonymous private compatibility region.
///
/// 支持真实 libc 文件和匿名私有映射；拒绝写执行同开、越界、未对齐文件偏移、
/// 未知非私有标志和与已有映射冲突的 `MAP_FIXED`。失败会撤销本次全部页。
fn linux_mmap(pid: ObjId, args: [u64; 6]) -> Result<u64, CompatErrno> {
    const PAGE: u64 = kernel_core::frame::FRAME_SIZE;
    const MAX_MAP_BYTES: u64 = 64 * 1024 * 1024;
    const MAP_PRIVATE: u64 = 0x02;
    const MAP_FIXED: u64 = 0x10;
    const MAP_ANONYMOUS: u64 = 0x20;
    const MAP_DENYWRITE: u64 = 0x800;
    const MAP_NORESERVE: u64 = 0x4000;
    const MAP_STACK: u64 = 0x20000;
    const PROT_READ: u64 = 0x1;
    const PROT_WRITE: u64 = 0x2;
    const PROT_EXEC: u64 = 0x4;

    let bytes = args[1];
    if bytes == 0 || bytes > MAX_MAP_BYTES || args[2] & !(PROT_READ | PROT_WRITE | PROT_EXEC) != 0 {
        return Err(CompatErrno::Invalid);
    }
    if args[2] & PROT_WRITE != 0 && args[2] & PROT_EXEC != 0 {
        return Err(CompatErrno::Perm);
    }
    if args[3] & MAP_PRIVATE == 0
        || args[3]
            & !(MAP_PRIVATE | MAP_FIXED | MAP_ANONYMOUS | MAP_DENYWRITE | MAP_NORESERVE | MAP_STACK)
            != 0
        || args[5] % PAGE != 0
    {
        return Err(CompatErrno::Invalid);
    }

    let anonymous = args[3] & MAP_ANONYMOUS != 0;
    let file = if anonymous {
        None
    } else {
        let fd = u32::try_from(args[4]).map_err(|_| CompatErrno::BadFd)?;
        let (handle, _) = proc::linux_file_state(pid, fd).ok_or(CompatErrno::BadFd)?;
        Some(crate::linux_vfs::FileId::from_handle(handle).ok_or(CompatErrno::BadFd)?)
    };
    let io = if let Some(file) = file {
        let offset = usize::try_from(args[5]).map_err(|_| CompatErrno::Invalid)?;
        let requested_bytes = usize::try_from(bytes).map_err(|_| CompatErrno::Invalid)?;
        let available = file
            .bytes()
            .len()
            .saturating_sub(offset)
            .min(requested_bytes);
        Some(admit_process_io(pid, available as u64, 1)?)
    } else {
        None
    };
    let rounded = bytes.checked_add(PAGE - 1).ok_or(CompatErrno::Invalid)? & !(PAGE - 1);
    let cursor = proc::linux_mmap_cursor(pid).ok_or(CompatErrno::NoSys)?;
    let requested = if args[0] == 0 {
        cursor
    } else {
        align_down(args[0], PAGE)
    };
    if requested < crate::arch::USER_WINDOW.0
        || requested
            .checked_add(rounded)
            .is_none_or(|end| end > crate::arch::USER_WINDOW.1)
    {
        return Err(CompatErrno::NoMemory);
    }
    if args[3] & MAP_FIXED != 0 {
        // MAP_FIXED replaces prior mappings by contract. The source bytes remain available
        // in the immutable virtual file, so a later mapping failure cannot expose stale pages.
        let mut page = requested;
        while page < requested + rounded {
            let _ = proc::unmap_page(pid, page);
            page += PAGE;
        }
    }
    let mut start = requested;
    while start < crate::arch::USER_WINDOW.1.saturating_sub(rounded) {
        let mut page = start;
        let mut free = true;
        while page < start + rounded {
            if proc::page_flags(pid, page).is_some() {
                free = false;
                break;
            }
            page += PAGE;
        }
        if free {
            break;
        }
        if args[3] & MAP_FIXED != 0 {
            return Err(CompatErrno::NoMemory);
        }
        start = start.checked_add(rounded).ok_or(CompatErrno::NoMemory)?;
    }
    if start + rounded > crate::arch::USER_WINDOW.1 {
        return Err(CompatErrno::NoMemory);
    }
    let writable = args[2] & PROT_WRITE != 0;
    let executable = args[2] & PROT_EXEC != 0;
    let mut flags = kernel_core::paging::MapFlags::USER;
    if writable {
        flags = flags.union(kernel_core::paging::MapFlags::WRITE);
    }
    if executable {
        flags = flags.union(kernel_core::paging::MapFlags::EXECUTE);
    }
    let mut mapped = alloc::vec::Vec::new();
    let mut page = start;
    while page < start + rounded {
        if proc::map_new(pid, page, flags).is_err() {
            for address in mapped.iter().rev().copied() {
                let _ = proc::unmap_page(pid, address);
            }
            return Err(CompatErrno::NoMemory);
        }
        mapped.push(page);
        page += PAGE;
    }
    if let Some(file) = file {
        let source = file.bytes();
        let offset = usize::try_from(args[5]).map_err(|_| CompatErrno::Invalid)?;
        let copy_bytes = usize::try_from(bytes).map_err(|_| CompatErrno::Invalid)?;
        if offset < source.len() {
            let end = source.len().min(offset.saturating_add(copy_bytes));
            let mut copied = 0usize;
            while offset + copied < end {
                let chunk = (end - offset - copied).min(PAGE as usize);
                if proc::write(
                    pid,
                    start + copied as u64,
                    &source[offset + copied..offset + copied + chunk],
                )
                .is_err()
                {
                    for address in mapped.iter().rev().copied() {
                        let _ = proc::unmap_page(pid, address);
                    }
                    return Err(CompatErrno::Fault);
                }
                copied += chunk;
            }
        }
    }
    if !proc::set_linux_mmap_cursor(pid, start + rounded) {
        for address in mapped.iter().rev().copied() {
            let _ = proc::unmap_page(pid, address);
        }
        return Err(CompatErrno::NoSys);
    }
    if let Some(io) = io {
        io.commit();
    }
    Ok(start)
}

fn linux_munmap(pid: ObjId, args: [u64; 6]) -> Result<u64, CompatErrno> {
    const PAGE: u64 = kernel_core::frame::FRAME_SIZE;
    if args[0] % PAGE != 0 || args[1] == 0 || args[1] % PAGE != 0 {
        return Err(CompatErrno::Invalid);
    }
    let end = args[0].checked_add(args[1]).ok_or(CompatErrno::Invalid)?;
    if end > crate::arch::USER_WINDOW.1 {
        return Err(CompatErrno::Invalid);
    }
    let mut page = args[0];
    while page < end {
        proc::unmap_page(pid, page).map_err(|_| CompatErrno::NoMemory)?;
        page += PAGE;
    }
    Ok(0)
}

fn linux_mprotect(pid: ObjId, args: [u64; 6]) -> Result<u64, CompatErrno> {
    const PAGE: u64 = kernel_core::frame::FRAME_SIZE;
    const PROT_READ: u64 = 0x1;
    const PROT_WRITE: u64 = 0x2;
    const PROT_EXEC: u64 = 0x4;
    if args[0] % PAGE != 0
        || args[1] == 0
        || args[1] % PAGE != 0
        || args[2] & !(PROT_READ | PROT_WRITE | PROT_EXEC) != 0
        || (args[2] & PROT_WRITE != 0 && args[2] & PROT_EXEC != 0)
    {
        return Err(CompatErrno::Invalid);
    }
    let end = args[0].checked_add(args[1]).ok_or(CompatErrno::Invalid)?;
    if end > crate::arch::USER_WINDOW.1 {
        return Err(CompatErrno::Invalid);
    }
    proc::protect_range(
        pid,
        args[0],
        args[1] / PAGE,
        args[2] & PROT_WRITE != 0,
        args[2] & PROT_EXEC != 0,
    )
    .map_err(|_| CompatErrno::NoMemory)?;
    Ok(0)
}

/// Implements the two `madvise(2)` operations required by glibc thread stacks.
///
/// 实现 glibc 线程栈所需的 guard 安装与 DONTNEED；其他 advice 仅接受已知安全集合。
fn linux_madvise(pid: ObjId, args: [u64; 6]) -> Result<u64, CompatErrno> {
    const PAGE: u64 = kernel_core::frame::FRAME_SIZE;
    const MADV_NORMAL: u64 = 0;
    const MADV_RANDOM: u64 = 1;
    const MADV_SEQUENTIAL: u64 = 2;
    const MADV_WILLNEED: u64 = 3;
    const MADV_DONTNEED: u64 = 4;
    const MADV_GUARD_INSTALL: u64 = 102;
    let address = args[0];
    let length = args[1];
    let advice = args[2];
    if address % PAGE != 0
        || length == 0
        || address < crate::arch::USER_WINDOW.0
        || address
            .checked_add(length)
            .is_none_or(|end| end > crate::arch::USER_WINDOW.1)
    {
        return Err(CompatErrno::Invalid);
    }
    match advice {
        MADV_NORMAL | MADV_RANDOM | MADV_SEQUENTIAL | MADV_WILLNEED => Ok(0),
        MADV_GUARD_INSTALL => {
            let pages = length.div_ceil(PAGE);
            for page in 0..pages {
                let _ = proc::unmap_page(pid, address + page * PAGE);
            }
            Ok(0)
        }
        MADV_DONTNEED => {
            let pages = length.div_ceil(PAGE);
            for page in 0..pages {
                let va = address + page * PAGE;
                let flags = proc::page_flags(pid, va).unwrap_or(MapFlags::USER);
                let _ = proc::unmap_page(pid, va);
                proc::map_new(pid, va, flags).map_err(|_| CompatErrno::NoMemory)?;
            }
            Ok(0)
        }
        _ => Err(CompatErrno::Invalid),
    }
}

/// Implements the x86_64 Linux `clone(2)` thread subset used by glibc pthreads.
///
/// 实现 glibc pthread 使用的 x86_64 Linux `clone(2)` 线程子集；共享同一 Jasper 地址空间、
/// fd 与信号状态，并为子任务分配独立 Linux TID。
fn linux_clone(
    pid: ObjId,
    args: [u64; 6],
    user_ip: Option<(u64, u64)>,
    user_preserved: [u64; 6],
) -> Result<u64, CompatErrno> {
    const CLONE_VM: u64 = 0x0000_0100;
    if args[0] & CLONE_VM == 0 {
        return linux_fork_clone(pid, args, user_ip, user_preserved);
    }
    linux_spawn_clone(
        pid, args[0], args[1], args[2], args[3], args[4], user_ip, args[2], args[4],
    )
}

/// Executes one root-backed dynamic image in the current Linux Process.
/// 在当前 Linux Process 中执行一个根卷支持的动态映像。
fn linux_execve(pid: ObjId, args: [u64; 6]) -> Result<(u64, u64), CompatErrno> {
    let path = linux_c_string(args[0], 4096)?;
    let resolved = if path.starts_with(b"/") {
        path.clone()
    } else {
        if path == b".."
            || path.starts_with(b"../")
            || path.windows(4).any(|window| window == b"/../")
        {
            return Err(CompatErrno::Invalid);
        }
        let base = proc::linux_cwd(pid).ok_or(CompatErrno::NoSys)?.path();
        let mut resolved = alloc::vec::Vec::with_capacity(base.len() + path.len() + 1);
        resolved.extend_from_slice(base);
        if !base.ends_with(b"/") {
            resolved.push(b'/');
        }
        resolved.extend_from_slice(&path);
        resolved
    };
    drop(path);
    let argv = linux_string_vector(args[1], 64, 64 * 1024)?;
    let envp = linux_string_vector(args[2], 64, 64 * 1024)?;
    #[cfg(all(
        feature = "lifecycle-root-exec-verify",
        target_arch = "x86_64"
    ))]
    {
        let (executable, interpreter) = crate::linux_vfs::root_executable(pid, &resolved).map_err(
            |error| match error {
                crate::linux_vfs::RootExecutableError::NotFound => CompatErrno::NoEntry,
                crate::linux_vfs::RootExecutableError::Quota => CompatErrno::NoSpace,
                crate::linux_vfs::RootExecutableError::Io => CompatErrno::Invalid,
            },
        )?;
        match crate::compat_dynamic_demo::exec_dynamic_program(
            pid,
            resolved,
            executable,
            interpreter,
            argv,
            envp,
        ) {
            Some((entry, stack)) => Ok((entry, stack)),
            None => Err(CompatErrno::NoSys),
        }
    }
    #[cfg(not(all(feature = "lifecycle-root-exec-verify", target_arch = "x86_64")))]
    {
        let _ = (resolved, argv, envp);
        Err(CompatErrno::NoSys)
    }
}

/// Reads a bounded NULL-terminated vector of NUL-terminated user strings.
/// 读取有界的 NULL 结尾用户字符串向量。
fn linux_string_vector(
    address: u64,
    max_entries: usize,
    max_bytes: usize,
) -> Result<alloc::vec::Vec<alloc::vec::Vec<u8>>, CompatErrno> {
    if address == 0 {
        return Ok(alloc::vec::Vec::new());
    }
    let mut output = alloc::vec::Vec::new();
    let mut total = 0usize;
    for index in 0..max_entries {
        let slot = address
            .checked_add((index * 8) as u64)
            .ok_or(CompatErrno::Fault)?;
        let mut raw = [0u8; 8];
        copy_from_user(&mut raw, slot, 8).map_err(|_| CompatErrno::Fault)?;
        let string_address = u64::from_le_bytes(raw);
        if string_address == 0 {
            return Ok(output);
        }
        let string = linux_c_string(string_address, 4096)?;
        total = total
            .checked_add(string.len() + 1)
            .ok_or(CompatErrno::Invalid)?;
        if total > max_bytes {
            return Err(CompatErrno::Invalid);
        }
        output.push(string);
    }
    Err(CompatErrno::Invalid)
}

/// Implements the glibc `fork()` clone subset with a private copied address space.
/// 实现 glibc `fork()` 使用的独立地址空间复制子集。
fn linux_fork_clone(
    pid: ObjId,
    args: [u64; 6],
    user_ip: Option<(u64, u64)>,
    preserved_regs: [u64; 6],
) -> Result<u64, CompatErrno> {
    const SIGCHLD: u64 = 17;
    const CLONE_CHILD_CLEARTID: u64 = 0x0020_0000;
    const CLONE_CHILD_SETTID: u64 = 0x0100_0000;
    const CLONE_FLAGS: u64 = CLONE_CHILD_CLEARTID | CLONE_CHILD_SETTID;
    let flags = args[0];
    let signal = flags & 0xff;
    if args[1] != 0 || signal != SIGCHLD || flags & !(CLONE_FLAGS | 0xff) != 0 || args[2] != 0 {
        return Err(CompatErrno::Invalid);
    }
    let (user_rip, user_stack) = user_ip.ok_or(CompatErrno::NoSys)?;
    let clear_child_tid = if flags & CLONE_CHILD_CLEARTID != 0 {
        args[3]
    } else {
        0
    };
    let child = proc::fork_linux_process(
        pid,
        user_rip,
        user_stack,
        crate::arch::user_fs_base(),
        preserved_regs,
        args,
        clear_child_tid,
    )
    .map_err(|error| match error {
        proc::ProcError::NotTransferable => CompatErrno::NoSys,
        _ => CompatErrno::NoMemory,
    })?;
    proc::linux_pid(child)
        .map(u64::from)
        .ok_or(CompatErrno::NoSys)
}

/// Implements `vfork(2)` as shared-memory execution with a suspended parent.
///
/// 实现 `vfork(2)`：子进程共享父进程物理页；父线程睡眠到子进程成功 exec
/// 或退出。参数寄存器必须原样恢复给子进程，glibc 在 `syscall` 前暂存返回地址
/// 到 `rdi`，调用后再压回栈。
fn linux_vfork(
    pid: ObjId,
    args: [u64; 6],
    user_ip: Option<(u64, u64)>,
    preserved_regs: [u64; 6],
) -> Result<u64, CompatErrno> {
    let (user_rip, user_stack) = user_ip.ok_or(CompatErrno::NoSys)?;
    let parent_space = proc::current_space_root(pid).ok_or(CompatErrno::NoSys)?;
    let (parent_task, _) = sched::current();
    let child = proc::vfork_linux_process(
        pid,
        user_rip,
        user_stack,
        crate::arch::user_fs_base(),
        preserved_regs,
        args,
        parent_task,
    )
    .map_err(|error| match error {
        proc::ProcError::NotTransferable => CompatErrno::NoSys,
        _ => CompatErrno::NoMemory,
    })?;
    let child_pid = proc::linux_pid(child).ok_or(CompatErrno::NoSys)?;
    loop {
        if proc::vfork_parent_may_resume(child) {
            sched::set_current_space(Some(parent_space));
            return Ok(u64::from(child_pid));
        }
        if proc::current_exiting() {
            let _ = proc::begin_exit(child, -1);
            return Err(CompatErrno::Interrupted);
        }
        sched::sleep_until(sched::timer_ticks().saturating_add(5));
    }
}

/// Blocks until one specific Linux child exits, then writes its encoded wait status.
/// 阻塞到一个指定 Linux 子进程退出，再写入编码后的 wait 状态。
fn linux_wait4(_pid: ObjId, args: [u64; 6]) -> Result<u64, CompatErrno> {
    const WNOHANG: u64 = 1;
    let target = args[0] as i32;
    let target = match target {
        -1 => None,
        value if value > 0 => Some(value as u32),
        _ => return Err(CompatErrno::Invalid),
    };
    if args[2] & !WNOHANG != 0 || args[3] != 0 {
        return Err(CompatErrno::NoSys);
    }
    loop {
        match proc::take_linux_child_exit(_pid, target) {
            Ok(Some((child_pid, status))) => {
                if args[1] != 0 {
                    copy_to_user(args[1], &status.to_le_bytes(), 4)
                        .map_err(|_| CompatErrno::Fault)?;
                }
                return Ok(u64::from(child_pid));
            }
            Ok(None) if args[2] & WNOHANG != 0 => return Ok(0),
            Ok(None) => proc::block_step().map_err(|_| CompatErrno::Interrupted)?,
            Err(_) => return Err(CompatErrno::NoChild),
        }
    }
}

/// Implements the structured `clone3(2)` layout used by modern glibc.
///
/// 解析现代 glibc 使用的 88 字节 `clone3` 参数结构，并复用同一线程创建路径。
fn linux_clone3(
    pid: ObjId,
    args: [u64; 6],
    user_ip: Option<(u64, u64)>,
    _user_preserved: [u64; 6],
) -> Result<u64, CompatErrno> {
    const CLONE_ARGS_BYTES: usize = 88;
    let size = usize::try_from(args[1]).map_err(|_| CompatErrno::Invalid)?;
    if size < CLONE_ARGS_BYTES || size > 256 {
        return Err(CompatErrno::Invalid);
    }
    let mut bytes = [0u8; 256];
    copy_from_user(&mut bytes[..size], args[0], size).map_err(|_| CompatErrno::Fault)?;
    let read = |offset: usize| u64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap());
    let flags = read(0);
    let pidfd = read(8);
    let child_tid = read(16);
    let parent_tid = read(24);
    let exit_signal = read(32);
    let stack = read(40);
    let stack_size = read(48);
    let tls = read(56);
    let set_tid = read(64);
    let set_tid_size = read(72);
    let cgroup = read(80);
    #[cfg(feature = "compat-dynamic-libc-verify")]
    crate::kprintln!(
        "[JSR-LINUX-CLONE3-ARGS] flags={:#x} pidfd={:#x} child_tid={:#x} parent_tid={:#x} exit_signal={:#x} stack={:#x} size={:#x} tls={:#x} set_tid={:#x} set_tid_size={} cgroup={:#x}",
        flags,
        pidfd,
        child_tid,
        parent_tid,
        exit_signal,
        stack,
        stack_size,
        tls,
        set_tid,
        set_tid_size,
        cgroup
    );
    let _ = (pidfd, set_tid, set_tid_size, cgroup);
    if exit_signal != 0 || stack_size == 0 {
        return Err(CompatErrno::Invalid);
    }
    let child_stack = stack
        .checked_add(stack_size)
        .filter(|top| *top <= crate::arch::USER_WINDOW.1)
        .ok_or(CompatErrno::Invalid)?;
    #[cfg(feature = "compat-dynamic-libc-verify")]
    crate::kprintln!(
        "[JSR-LINUX-CLONE3] flags={:#x} stack={:#x} size={:#x} top={:#x} tls={:#x} child_tid={:#x} parent_tid={:#x} rip={:#x}",
        flags,
        stack,
        stack_size,
        child_stack,
        tls,
        child_tid,
        parent_tid,
        user_ip.map_or(0, |value| value.0)
    );
    linux_spawn_clone(
        pid,
        flags,
        child_stack,
        parent_tid,
        child_tid,
        tls,
        user_ip,
        args[2],
        args[4],
    )
}

fn linux_spawn_clone(
    pid: ObjId,
    flags: u64,
    child_stack: u64,
    parent_tid: u64,
    child_tid: u64,
    tls: u64,
    user_ip: Option<(u64, u64)>,
    clone_rdx: u64,
    clone_r8: u64,
) -> Result<u64, CompatErrno> {
    const CLONE_VM: u64 = 0x0000_0100;
    const CLONE_FS: u64 = 0x0000_0200;
    const CLONE_FILES: u64 = 0x0000_0400;
    const CLONE_SIGHAND: u64 = 0x0000_0800;
    const CLONE_THREAD: u64 = 0x0001_0000;
    const CLONE_SYSVSEM: u64 = 0x0004_0000;
    const CLONE_SETTLS: u64 = 0x0008_0000;
    const CLONE_PARENT_SETTID: u64 = 0x0010_0000;
    const CLONE_CHILD_CLEARTID: u64 = 0x0020_0000;
    const CLONE_CHILD_SETTID: u64 = 0x0100_0000;
    const SUPPORTED: u64 = CLONE_VM
        | CLONE_FS
        | CLONE_FILES
        | CLONE_SIGHAND
        | CLONE_THREAD
        | CLONE_SYSVSEM
        | CLONE_SETTLS
        | CLONE_PARENT_SETTID
        | CLONE_CHILD_CLEARTID
        | CLONE_CHILD_SETTID;
    let required = CLONE_VM | CLONE_FS | CLONE_FILES | CLONE_SIGHAND | CLONE_THREAD | CLONE_SYSVSEM;
    if flags & !SUPPORTED != 0
        || flags & required != required
        || child_stack < crate::arch::USER_WINDOW.0
        || child_stack > crate::arch::USER_WINDOW.1
    {
        return Err(CompatErrno::Invalid);
    }
    let (user_rip, _) = user_ip.ok_or(CompatErrno::NoSys)?;
    let fs_base = if flags & CLONE_SETTLS != 0 {
        if tls < crate::arch::USER_WINDOW.0 || tls >= crate::arch::USER_WINDOW.1 {
            return Err(CompatErrno::Invalid);
        }
        Some(tls)
    } else {
        None
    };
    let clear_child_tid = if flags & CLONE_CHILD_CLEARTID != 0 {
        child_tid
    } else {
        0
    };
    let (task, _) = proc::spawn_linux_clone(
        pid,
        "linux-clone",
        user_rip,
        child_stack,
        fs_base,
        None,
        None,
        clear_child_tid,
        clone_rdx,
        clone_r8,
    )
    .map_err(|_| CompatErrno::NoMemory)?;
    let (_, tid) = linux_tid_for_task(task).ok_or(CompatErrno::NoSys)?;
    let tid_bytes = tid.to_le_bytes();
    if flags & CLONE_PARENT_SETTID != 0 {
        copy_to_user(parent_tid, &tid_bytes, tid_bytes.len()).map_err(|_| CompatErrno::Fault)?;
    }
    if flags & CLONE_CHILD_SETTID != 0 {
        copy_to_user(child_tid, &tid_bytes, tid_bytes.len()).map_err(|_| CompatErrno::Fault)?;
    }
    Ok(u64::from(tid))
}

/// Implements the futex wait/wake subset used by glibc mutexes and condition variables.
///
/// 实现 glibc mutex/condvar 使用的 futex wait/wake 子集；等待使用内核调度暂停，
/// 失去唤醒在兼容锁内判定，避免 compare 与 sleep 之间丢失通知。
fn linux_futex(pid: ObjId, args: [u64; 6]) -> Result<u64, CompatErrno> {
    const FUTEX_WAIT: u64 = 0;
    const FUTEX_WAKE: u64 = 1;
    const FUTEX_WAIT_BITSET: u64 = 9;
    const FUTEX_WAKE_BITSET: u64 = 10;
    const FUTEX_PRIVATE_FLAG: u64 = 128;
    const FUTEX_CLOCK_REALTIME: u64 = 256;
    let operation = args[1] & !(FUTEX_PRIVATE_FLAG | FUTEX_CLOCK_REALTIME);
    match operation {
        FUTEX_WAIT => futex_wait(
            pid,
            args[0],
            u32::try_from(args[2]).map_err(|_| CompatErrno::Invalid)?,
            futex_timeout(args[3], false)?,
        ),
        FUTEX_WAIT_BITSET => futex_wait(
            pid,
            args[0],
            u32::try_from(args[2]).map_err(|_| CompatErrno::Invalid)?,
            futex_timeout(args[3], args[1] & FUTEX_CLOCK_REALTIME != 0)?,
        ),
        FUTEX_WAKE => futex_wake(
            pid,
            args[0],
            usize::try_from(args[2]).map_err(|_| CompatErrno::Invalid)?,
        ),
        FUTEX_WAKE_BITSET => futex_wake(
            pid,
            args[0],
            usize::try_from(args[2]).map_err(|_| CompatErrno::Invalid)?,
        ),
        _ => Err(CompatErrno::NoSys),
    }
}

/// Reports the compatibility service's read-only resource limits.
///
/// 返回兼容服务的只读资源上限；本切片不伪造 `prlimit64` 写操作。
fn linux_prlimit(pid: ObjId, args: [u64; 6]) -> Result<u64, CompatErrno> {
    const RLIMIT_STACK: u64 = 3;
    const RLIMIT_NOFILE: u64 = 7;
    const RLIM_INFINITY: u64 = u64::MAX;
    if args[1] != 0 || args[2] != 0 || proc::linux_pid(pid).is_none() {
        return Err(CompatErrno::Invalid);
    }
    let (current, maximum): (u64, u64) = match args[0] {
        RLIMIT_STACK => (8 * 1024 * 1024, RLIM_INFINITY),
        RLIMIT_NOFILE => (64, 64),
        _ => return Err(CompatErrno::Invalid),
    };
    if args[3] != 0 {
        let mut bytes = [0u8; 16];
        bytes[..8].copy_from_slice(&current.to_le_bytes());
        bytes[8..].copy_from_slice(&maximum.to_le_bytes());
        copy_to_user(args[3], &bytes, bytes.len()).map_err(|_| CompatErrno::Fault)?;
    }
    Ok(0)
}

/// Fills a bounded userspace buffer from x86_64 RDRAND.
///
/// 从 CPUID 验证过的 RDRAND 填充有界用户缓冲区；没有硬件熵源时明确返回 EAGAIN。
fn linux_getrandom(args: [u64; 6]) -> Result<u64, CompatErrno> {
    const GRND_NONBLOCK: u64 = 1;
    const GRND_RANDOM: u64 = 2;
    const GRND_INSECURE: u64 = 4;
    const MAX_RANDOM: usize = 1024 * 1024;
    let length = usize::try_from(args[1]).map_err(|_| CompatErrno::Invalid)?;
    if length > MAX_RANDOM || args[2] & !(GRND_NONBLOCK | GRND_RANDOM | GRND_INSECURE) != 0 {
        return Err(CompatErrno::Invalid);
    }
    if length == 0 {
        return Ok(0);
    }
    let mut output = alloc::vec![0u8; length];
    let mut offset = 0usize;
    while offset < output.len() {
        match crate::arch::x86_64::hardware_random_u64() {
            Some(value) => {
                let bytes = value.to_le_bytes();
                let count = (output.len() - offset).min(bytes.len());
                output[offset..offset + count].copy_from_slice(&bytes[..count]);
                offset += count;
            }
            None => {
                #[cfg(feature = "lifecycle-root-exec-verify")]
                if crate::compat_rng::fill(&mut output[offset..]) {
                    offset = output.len();
                    continue;
                }
                return Err(CompatErrno::TryAgain);
            }
        }
    }
    copy_to_user(args[0], &output, output.len()).map_err(|_| CompatErrno::Fault)?;
    Ok(length as u64)
}

/// Implements the x86_64 `arch_prctl(2)` TLS base operation.
///
/// 当前切片仅接受 `ARCH_SET_FS`，地址必须位于本架构用户私有窗口。线程级 FS_BASE 随
/// 任务上下文保存和恢复，不能把值泄漏给下一任务。
fn linux_arch_prctl(args: [u64; 6]) -> Result<u64, CompatErrno> {
    const ARCH_SET_FS: u64 = 0x1002;
    if args[0] != ARCH_SET_FS {
        return Err(CompatErrno::Invalid);
    }
    if args[1] < crate::arch::USER_WINDOW.0
        || args[1] >= crate::arch::USER_WINDOW.1
        || !crate::arch::set_user_fs_base(args[1])
    {
        return Err(CompatErrno::Invalid);
    }
    Ok(0)
}

/// Implements `clock_gettime(2)` for trusted realtime and Jasper monotonic clocks.
///
/// `CLOCK_MONOTONIC` 使用高精度内核单调时钟；`CLOCK_REALTIME` 只能取自信任的
/// 硬件 RTC。没有可信 RTC 时返回 `ENOSYS`，不会用单调时钟伪造时间。
fn linux_clock_gettime(args: [u64; 6]) -> Result<u64, CompatErrno> {
    const CLOCK_REALTIME: u64 = 0;
    const CLOCK_MONOTONIC: u64 = 1;
    let now = match args[0] {
        CLOCK_MONOTONIC => crate::sched::now_ns(),
        CLOCK_REALTIME => crate::arch::wall_clock_ns().ok_or(CompatErrno::NoSys)?,
        _ => return Err(CompatErrno::Invalid),
    };
    write_linux_timespec(args[1], now)
}

/// Implements the legacy `gettimeofday(2)` view over the trusted RTC.
///
/// 从可信 RTC 写入 x86_64 `struct timeval`；时区参数明确拒绝，不伪造宿主时区。
fn linux_gettimeofday(args: [u64; 6]) -> Result<u64, CompatErrno> {
    if args[1] != 0 {
        return Err(CompatErrno::Invalid);
    }
    let now = crate::arch::wall_clock_ns().ok_or(CompatErrno::NoSys)?;
    let mut value = [0u8; 16];
    value[0..8].copy_from_slice(&(now / 1_000_000_000).to_le_bytes());
    value[8..16].copy_from_slice(&((now % 1_000_000_000) / 1_000).to_le_bytes());
    copy_to_user(args[0], &value, value.len()).map_err(|_| CompatErrno::Fault)?;
    Ok(0)
}

/// Implements `time(2)` using the trusted RTC.
///
/// 使用可信 RTC 返回 Unix 秒；非空输出指针收到同样的 `time_t`。
fn linux_time(args: [u64; 6]) -> Result<u64, CompatErrno> {
    let seconds = crate::arch::wall_clock_ns().ok_or(CompatErrno::NoSys)? / 1_000_000_000;
    if args[0] != 0 {
        copy_to_user(args[0], &seconds.to_le_bytes(), 8).map_err(|_| CompatErrno::Fault)?;
    }
    Ok(seconds)
}

/// Reports the compatibility clock's conservative timer resolution.
///
/// 报告兼容时钟的保守定时器分辨率；RTC 当前只有一秒分辨率，`NULL` 查询合法。
fn linux_clock_getres(args: [u64; 6]) -> Result<u64, CompatErrno> {
    const CLOCK_REALTIME: u64 = 0;
    const CLOCK_MONOTONIC: u64 = 1;
    let resolution = match args[0] {
        CLOCK_MONOTONIC => crate::hrtime::tick_ns().max(1),
        CLOCK_REALTIME => {
            crate::arch::wall_clock_ns().ok_or(CompatErrno::NoSys)?;
            1_000_000_000
        }
        _ => return Err(CompatErrno::Invalid),
    };
    if args[1] == 0 {
        return Ok(0);
    }
    write_linux_timespec(args[1], resolution)
}

/// Sleeps for a relative monotonic duration.
///
/// 按单调时钟睡眠；被信号或进程终止唤醒时返回 `EINTR` 并写回剩余时间。
fn linux_nanosleep(pid: ObjId, args: [u64; 6]) -> Result<u64, CompatErrno> {
    let duration = read_linux_timespec(args[0])?;
    let deadline = crate::sched::now_ns().saturating_add(duration);
    let result = sleep_until_with_signal_check(pid, deadline);
    match result {
        Ok(()) => Ok(0),
        Err(CompatErrno::Interrupted) => {
            if args[1] != 0 {
                let remaining = deadline.saturating_sub(crate::sched::now_ns());
                write_linux_timespec(args[1], remaining)?;
            }
            Err(CompatErrno::Interrupted)
        }
        Err(error) => Err(error),
    }
}

/// Implements relative realtime/monotonic sleep and absolute realtime/monotonic sleep.
///
/// 相对等待统一使用单调截止期；绝对 realtime 期限先与可信 RTC 当前值作差，再转换为
/// 单调截止期，因此 RTC 只在进入等待时读取，不参与调度器计时。
fn linux_clock_nanosleep(pid: ObjId, args: [u64; 6]) -> Result<u64, CompatErrno> {
    const CLOCK_REALTIME: u64 = 0;
    const CLOCK_MONOTONIC: u64 = 1;
    const TIMER_ABSTIME: u64 = 1;
    let absolute = args[1] & TIMER_ABSTIME != 0;
    if args[0] != CLOCK_MONOTONIC && args[0] != CLOCK_REALTIME || args[1] & !TIMER_ABSTIME != 0 {
        return Err(CompatErrno::Invalid);
    }
    let requested = read_linux_timespec(args[2])?;
    let deadline = if absolute {
        if args[0] == CLOCK_REALTIME {
            let wall = crate::arch::wall_clock_ns().ok_or(CompatErrno::NoSys)?;
            crate::sched::now_ns().saturating_add(requested.saturating_sub(wall))
        } else {
            requested
        }
    } else {
        crate::sched::now_ns().saturating_add(requested)
    };
    match sleep_until_with_signal_check(pid, deadline) {
        Ok(()) => Ok(0),
        Err(CompatErrno::Interrupted) if !absolute && args[3] != 0 => {
            let remaining = deadline.saturating_sub(crate::sched::now_ns());
            write_linux_timespec(args[3], remaining)?;
            Err(CompatErrno::Interrupted)
        }
        Err(error) => Err(error),
    }
}

/// Reads one bounded signed Linux `timespec`.
///
/// 读取一个有界 Linux `timespec`；负秒、越界纳秒和溢出均被拒绝。
fn read_linux_timespec(address: u64) -> Result<u64, CompatErrno> {
    const TIMESPEC_BYTES: usize = 16;
    let mut bytes = [0u8; TIMESPEC_BYTES];
    copy_from_user(&mut bytes, address, TIMESPEC_BYTES).map_err(|_| CompatErrno::Fault)?;
    let seconds = i64::from_le_bytes(bytes[0..8].try_into().unwrap());
    let nanos = i64::from_le_bytes(bytes[8..16].try_into().unwrap());
    if seconds < 0 || !(0..1_000_000_000).contains(&nanos) {
        return Err(CompatErrno::Invalid);
    }
    (seconds as u64)
        .checked_mul(1_000_000_000)
        .and_then(|value| value.checked_add(nanos as u64))
        .ok_or(CompatErrno::Invalid)
}

/// Writes one Linux `timespec` using an all-or-nothing user copy.
///
/// 将纳秒时刻写为 Linux `timespec`；一次固定目标用户区间，失败不产生部分写。
fn write_linux_timespec(address: u64, nanoseconds: u64) -> Result<u64, CompatErrno> {
    let mut timespec = [0u8; 16];
    timespec[0..8].copy_from_slice(&(nanoseconds / 1_000_000_000).to_le_bytes());
    timespec[8..16].copy_from_slice(&(nanoseconds % 1_000_000_000).to_le_bytes());
    copy_to_user(address, &timespec, timespec.len()).map_err(|_| CompatErrno::Fault)?;
    Ok(0)
}

/// Blocks until an absolute monotonic deadline and handles wake-up rechecks.
///
/// 阻塞到绝对单调期限；每次提前返回都重新检查期限、进程终止和待决信号。
fn sleep_until_with_signal_check(pid: ObjId, deadline: u64) -> Result<(), CompatErrno> {
    loop {
        if proc::current_exiting() || current_signal_pending(pid) {
            return Err(CompatErrno::Interrupted);
        }
        let now = crate::sched::now_ns();
        if now >= deadline {
            return Ok(());
        }
        if sched::sleep_until_ns(deadline).is_err() {
            let ticks = deadline
                .saturating_sub(now)
                .div_ceil(crate::hrtime::tick_ns().max(1))
                .max(1);
            sched::sleep_until(sched::timer_ticks().saturating_add(ticks));
        }
    }
}

/// Closes a Linux descriptor through the compatibility fd table.
///
/// 经兼容 fd 表关闭描述符；重复关闭返回 `EBADF`，不会影响其他世代。
fn linux_close(pid: ObjId, fd: u64) -> Result<u64, CompatErrno> {
    let fd = u32::try_from(fd).map_err(|_| CompatErrno::BadFd)?;
    if proc::linux_close_fd(pid, fd) {
        Ok(0)
    } else {
        Err(CompatErrno::BadFd)
    }
}

/// Implements `dup(2)` by selecting the lowest free descriptor.
///
/// 复制一个描述符到最低可用 fd，并保留共享的文件游标。
fn linux_dup(pid: ObjId, args: [u64; 6]) -> Result<u64, CompatErrno> {
    let source = u32::try_from(args[0]).map_err(|_| CompatErrno::BadFd)?;
    proc::linux_fd(pid, source).ok_or(CompatErrno::BadFd)?;
    proc::linux_duplicate_fd(pid, source, 0, false)
        .map(u64::from)
        .ok_or(CompatErrno::NoSpace)
}

/// Implements `dup2(2)`, including same-fd and exact-target replacement semantics.
///
/// 实现精确目标 fd 的复制；同一 fd 成功返回，目标已占用时原子替换且清除 CLOEXEC。
fn linux_dup2(pid: ObjId, args: [u64; 6]) -> Result<u64, CompatErrno> {
    let source = u32::try_from(args[0]).map_err(|_| CompatErrno::BadFd)?;
    let target = u32::try_from(args[1]).map_err(|_| CompatErrno::BadFd)?;
    proc::linux_fd(pid, source).ok_or(CompatErrno::BadFd)?;
    if source == target {
        return Ok(u64::from(target));
    }
    proc::linux_duplicate_fd_to(pid, source, target, false)
        .map(u64::from)
        .ok_or(CompatErrno::BadFd)
}

/// Implements `dup3(2)` with only the Linux `O_CLOEXEC` flag accepted.
///
/// 实现 `dup3(2)`；只接受 `O_CLOEXEC`，同一 fd 和未知标志均返回 EINVAL。
fn linux_dup3(pid: ObjId, args: [u64; 6]) -> Result<u64, CompatErrno> {
    const O_CLOEXEC: u64 = 0x80000;
    let source = u32::try_from(args[0]).map_err(|_| CompatErrno::BadFd)?;
    let target = u32::try_from(args[1]).map_err(|_| CompatErrno::BadFd)?;
    let flags = args[2];
    proc::linux_fd(pid, source).ok_or(CompatErrno::BadFd)?;
    if source == target || flags & !O_CLOEXEC != 0 {
        return Err(CompatErrno::Invalid);
    }
    proc::linux_duplicate_fd_to(pid, source, target, flags & O_CLOEXEC != 0)
        .map(u64::from)
        .ok_or(CompatErrno::BadFd)
}

/// Implements `pipe2(2)` with CLOEXEC and nonblocking status flags.
///
/// 创建有界匿名管道，并以 all-or-nothing 方式返回两个 fd。
fn linux_pipe2(pid: ObjId, args: [u64; 6]) -> Result<u64, CompatErrno> {
    const O_NONBLOCK: u64 = 0x800;
    const O_CLOEXEC: u64 = 0x80000;
    let flags = args[1];
    if flags & !(O_NONBLOCK | O_CLOEXEC) != 0 {
        return Err(CompatErrno::Invalid);
    }
    let (reader, writer) = proc::linux_pipe2(pid, flags & O_CLOEXEC != 0, flags & O_NONBLOCK != 0)
        .ok_or(CompatErrno::NoSpace)?;
    let mut output = [0u8; 8];
    output[0..4].copy_from_slice(&reader.to_le_bytes());
    output[4..8].copy_from_slice(&writer.to_le_bytes());
    if copy_to_user(args[0], &output, output.len()).is_err() {
        let _ = proc::linux_close_fd(pid, reader);
        let _ = proc::linux_close_fd(pid, writer);
        return Err(CompatErrno::Fault);
    }
    Ok(0)
}

/// Creates one unconnected AF_UNIX stream socket.
fn linux_socket(pid: ObjId, args: [u64; 6]) -> Result<u64, CompatErrno> {
    const AF_UNIX: u64 = 1;
    const SOCK_STREAM: u64 = 1;
    const SOCK_NONBLOCK: u64 = 0x800;
    const SOCK_CLOEXEC: u64 = 0x80000;
    let socket_type = args[1];
    if args[0] != AF_UNIX
        || socket_type & 0xf != SOCK_STREAM
        || socket_type & !(0xf | SOCK_NONBLOCK | SOCK_CLOEXEC) != 0
        || args[2] != 0
    {
        return Err(CompatErrno::Invalid);
    }
    proc::linux_socket_create(
        pid,
        socket_type & SOCK_CLOEXEC != 0,
        socket_type & SOCK_NONBLOCK != 0,
    )
    .map(u64::from)
    .map_err(socket_compat_error)
}

/// Binds one AF_UNIX stream socket to an abstract or pathname address.
fn linux_bind(pid: ObjId, args: [u64; 6]) -> Result<u64, CompatErrno> {
    let fd = u32::try_from(args[0]).map_err(|_| CompatErrno::BadFd)?;
    let entry = proc::linux_fd(pid, fd).ok_or(CompatErrno::BadFd)?;
    if entry.kind != compat_core::fd::CompatKind::Socket {
        return Err(CompatErrno::NotConnected);
    }
    let name = read_unix_socket_name(pid, args[1], args[2])?;
    proc::linux_socket_bind(pid, entry.handle, name).map_err(socket_compat_error)?;
    Ok(0)
}

/// Marks a bound AF_UNIX stream socket as accepting connections.
fn linux_listen(pid: ObjId, args: [u64; 6]) -> Result<u64, CompatErrno> {
    let fd = u32::try_from(args[0]).map_err(|_| CompatErrno::BadFd)?;
    let entry = proc::linux_fd(pid, fd).ok_or(CompatErrno::BadFd)?;
    if entry.kind != compat_core::fd::CompatKind::Socket {
        return Err(CompatErrno::NotConnected);
    }
    let backlog = i64::from(args[1] as i32);
    proc::linux_socket_listen(pid, entry.handle, backlog.max(0) as usize)
        .map_err(socket_compat_error)?;
    Ok(0)
}

/// Connects one AF_UNIX stream socket to a bound listener.
fn linux_connect(pid: ObjId, args: [u64; 6]) -> Result<u64, CompatErrno> {
    let fd = u32::try_from(args[0]).map_err(|_| CompatErrno::BadFd)?;
    let entry = proc::linux_fd(pid, fd).ok_or(CompatErrno::BadFd)?;
    if entry.kind != compat_core::fd::CompatKind::Socket {
        return Err(CompatErrno::NotConnected);
    }
    let name = read_unix_socket_name(pid, args[1], args[2])?;
    proc::linux_socket_connect(pid, entry.handle, name).map_err(socket_compat_error)?;
    Ok(0)
}

/// Accepts one AF_UNIX stream connection, blocking unless the listening
/// descriptor is nonblocking.
fn linux_accept(pid: ObjId, args: [u64; 6], accept4: bool) -> Result<u64, CompatErrno> {
    const SOCK_NONBLOCK: u32 = 0x800;
    const SOCK_CLOEXEC: u32 = 0x80000;
    let fd = u32::try_from(args[0]).map_err(|_| CompatErrno::BadFd)?;
    let entry = proc::linux_fd(pid, fd).ok_or(CompatErrno::BadFd)?;
    if entry.kind != compat_core::fd::CompatKind::Socket {
        return Err(CompatErrno::NotConnected);
    }
    let flags = if accept4 {
        u32::try_from(args[3]).map_err(|_| CompatErrno::Invalid)?
    } else {
        0
    };
    if flags & !(SOCK_NONBLOCK | SOCK_CLOEXEC) != 0 {
        return Err(CompatErrno::Invalid);
    }
    let listener_nonblocking =
        proc::linux_fd_status_flags(pid, fd).ok_or(CompatErrno::BadFd)? & 0x800 != 0;
    loop {
        match proc::linux_socket_accept(
            pid,
            entry.handle,
            flags & SOCK_CLOEXEC != 0,
            flags & SOCK_NONBLOCK != 0,
        ) {
            Ok(accepted) => {
                if args[1] != 0 {
                    let accepted_entry = proc::linux_fd(pid, accepted).ok_or(CompatErrno::BadFd)?;
                    let endpoint = proc::linux_socket_endpoint(pid, accepted_entry.handle)
                        .ok_or(CompatErrno::BadFd)?;
                    let peer = endpoint
                        .peer_name()
                        .unwrap_or_else(compat_core::UnixSocketName::empty);
                    if write_unix_sockaddr(args[1], args[2], peer).is_err() {
                        let _ = proc::linux_close_fd(pid, accepted);
                        return Err(CompatErrno::Fault);
                    }
                }
                return Ok(u64::from(accepted));
            }
            Err(proc::LinuxSocketError::WouldBlock) if listener_nonblocking => {
                return Err(CompatErrno::TryAgain)
            }
            Err(proc::LinuxSocketError::WouldBlock) => {
                if proc::current_exiting() || current_signal_pending(pid) {
                    return Err(CompatErrno::Interrupted);
                }
                sched::pause();
            }
            Err(error) => return Err(socket_compat_error(error)),
        }
    }
}

/// Maps bounded socket-state failures to Linux x86_64 errno values.
fn socket_compat_error(error: proc::LinuxSocketError) -> CompatErrno {
    match error {
        proc::LinuxSocketError::Invalid => CompatErrno::Invalid,
        proc::LinuxSocketError::IsConnected => CompatErrno::IsConnected,
        proc::LinuxSocketError::AddressInUse => CompatErrno::AddressInUse,
        proc::LinuxSocketError::NotBound => CompatErrno::Invalid,
        proc::LinuxSocketError::NotConnected => CompatErrno::NotConnected,
        proc::LinuxSocketError::ConnectionRefused => CompatErrno::ConnectionRefused,
        proc::LinuxSocketError::WouldBlock => CompatErrno::TryAgain,
        proc::LinuxSocketError::NoSpace => CompatErrno::NoSpace,
    }
}

/// Reads one bounded `sockaddr_un`, trimming the pathname terminator while
/// preserving all bytes of an abstract name.
fn read_unix_socket_name(
    pid: ObjId,
    address: u64,
    length: u64,
) -> Result<compat_core::UnixSocketName, CompatErrno> {
    let length = usize::try_from(length).map_err(|_| CompatErrno::Invalid)?;
    if !(3..=110).contains(&length) {
        return Err(CompatErrno::Invalid);
    }
    let mut raw = [0u8; 110];
    proc::read(pid, address, &mut raw[..length]).map_err(|_| CompatErrno::Fault)?;
    if u16::from_le_bytes(raw[..2].try_into().unwrap()) != 1 {
        return Err(CompatErrno::Invalid);
    }
    let mut name = &raw[2..length];
    if name[0] != 0 {
        let end = name
            .iter()
            .position(|byte| *byte == 0)
            .unwrap_or(name.len());
        if end == 0 {
            return Err(CompatErrno::Invalid);
        }
        name = &name[..end];
    }
    compat_core::UnixSocketName::new(name).ok_or(CompatErrno::Invalid)
}

/// Implements the x86_64 `socketpair(2)` AF_UNIX stream subset.
fn linux_socketpair(pid: ObjId, args: [u64; 6]) -> Result<u64, CompatErrno> {
    const AF_UNIX: u64 = 1;
    const SOCK_STREAM: u64 = 1;
    const SOCK_NONBLOCK: u64 = 0x800;
    const SOCK_CLOEXEC: u64 = 0x80000;
    let domain = args[0];
    let socket_type = args[1];
    let protocol = args[2];
    if domain != AF_UNIX
        || socket_type & 0xf != SOCK_STREAM
        || socket_type & !(0xf | SOCK_NONBLOCK | SOCK_CLOEXEC) != 0
        || protocol != 0
    {
        return Err(CompatErrno::Invalid);
    }
    let (first, second) = proc::linux_socketpair(
        pid,
        socket_type & SOCK_CLOEXEC != 0,
        socket_type & SOCK_NONBLOCK != 0,
    )
    .ok_or(CompatErrno::NoSpace)?;
    let mut output = [0u8; 8];
    output[0..4].copy_from_slice(&first.to_le_bytes());
    output[4..8].copy_from_slice(&second.to_le_bytes());
    if copy_to_user(args[3], &output, output.len()).is_err() {
        let _ = proc::linux_close_fd(pid, first);
        let _ = proc::linux_close_fd(pid, second);
        return Err(CompatErrno::Fault);
    }
    Ok(0)
}

/// Implements `sendto(2)` on an already connected AF_UNIX stream.
fn linux_sendto(pid: ObjId, args: [u64; 6]) -> Result<u64, CompatErrno> {
    const MSG_DONTWAIT: u64 = 0x40;
    const MSG_NOSIGNAL: u64 = 0x4000;
    let fd = u32::try_from(args[0]).map_err(|_| CompatErrno::BadFd)?;
    let len = usize::try_from(args[2]).map_err(|_| CompatErrno::Invalid)?;
    let flags = args[3];
    if flags & !(MSG_DONTWAIT | MSG_NOSIGNAL) != 0 {
        return Err(CompatErrno::Invalid);
    }
    if args[4] != 0 || args[5] != 0 {
        return Err(CompatErrno::IsConnected);
    }
    let entry = proc::linux_fd(pid, fd).ok_or(CompatErrno::BadFd)?;
    if entry.kind != compat_core::fd::CompatKind::Socket
        || !entry.rights.contains(kernel_core::object::Rights::WRITE)
    {
        return Err(CompatErrno::NotConnected);
    }
    linux_socket_write(
        pid,
        fd,
        entry.handle,
        args[1],
        len,
        flags & MSG_DONTWAIT != 0,
        flags & MSG_NOSIGNAL != 0,
    )
}

/// Implements `recvfrom(2)` on an already connected AF_UNIX stream.
fn linux_recvfrom(pid: ObjId, args: [u64; 6]) -> Result<u64, CompatErrno> {
    const MSG_DONTWAIT: u64 = 0x40;
    let fd = u32::try_from(args[0]).map_err(|_| CompatErrno::BadFd)?;
    let len = usize::try_from(args[2]).map_err(|_| CompatErrno::Invalid)?;
    let flags = args[3];
    if flags & !MSG_DONTWAIT != 0 {
        return Err(CompatErrno::Invalid);
    }
    let entry = proc::linux_fd(pid, fd).ok_or(CompatErrno::BadFd)?;
    if entry.kind != compat_core::fd::CompatKind::Socket
        || !entry.rights.contains(kernel_core::object::Rights::READ)
    {
        return Err(CompatErrno::NotConnected);
    }
    let received = linux_socket_read(
        pid,
        fd,
        entry.handle,
        args[1],
        len,
        flags & MSG_DONTWAIT != 0,
    )?;
    if args[4] != 0 {
        write_unix_sockaddr(args[4], args[5], compat_core::UnixSocketName::empty())?;
    }
    Ok(received)
}

struct LinuxMessageHeader {
    name: u64,
    name_len: usize,
    iov: u64,
    iov_len: usize,
    control: u64,
    control_len: usize,
    flags: u64,
}

/// Reads the fixed x86_64 `struct msghdr` ABI without trusting array lengths.
fn read_message_header(pid: ObjId, address: u64) -> Result<LinuxMessageHeader, CompatErrno> {
    const MSGHDR_BYTES: usize = 56;
    let mut raw = [0u8; MSGHDR_BYTES];
    proc::read(pid, address, &mut raw).map_err(|_| CompatErrno::Fault)?;
    Ok(LinuxMessageHeader {
        name: u64::from_le_bytes(raw[0..8].try_into().unwrap()),
        name_len: u32::from_le_bytes(raw[8..12].try_into().unwrap()) as usize,
        iov: u64::from_le_bytes(raw[16..24].try_into().unwrap()),
        iov_len: usize::try_from(u64::from_le_bytes(raw[24..32].try_into().unwrap()))
            .map_err(|_| CompatErrno::Invalid)?,
        control: u64::from_le_bytes(raw[32..40].try_into().unwrap()),
        control_len: usize::try_from(u64::from_le_bytes(raw[40..48].try_into().unwrap()))
            .map_err(|_| CompatErrno::Invalid)?,
        flags: u64::from(u32::from_le_bytes(raw[48..52].try_into().unwrap())),
    })
}

/// Reads and validates one bounded x86_64 iovec array.
fn read_message_iovecs(
    pid: ObjId,
    address: u64,
    count: usize,
    maximum: usize,
) -> Result<alloc::vec::Vec<(u64, usize)>, CompatErrno> {
    const MAX_IOVECS: usize = 1024;
    const IOVEC_BYTES: usize = 16;
    if count > MAX_IOVECS {
        return Err(CompatErrno::Invalid);
    }
    let mut vectors = alloc::vec::Vec::new();
    vectors
        .try_reserve(count)
        .map_err(|_| CompatErrno::NoMemory)?;
    let mut total = 0usize;
    for index in 0..count {
        let vector = address
            .checked_add((index * IOVEC_BYTES) as u64)
            .ok_or(CompatErrno::Fault)?;
        let mut iovec = [0u8; IOVEC_BYTES];
        proc::read(pid, vector, &mut iovec).map_err(|_| CompatErrno::Fault)?;
        let base = u64::from_le_bytes(iovec[..8].try_into().unwrap());
        let len = usize::try_from(u64::from_le_bytes(iovec[8..].try_into().unwrap()))
            .map_err(|_| CompatErrno::Invalid)?;
        base.checked_add(u64::try_from(len).map_err(|_| CompatErrno::Invalid)?)
            .ok_or(CompatErrno::Fault)?;
        total = total.checked_add(len).ok_or(CompatErrno::Invalid)?;
        if total > maximum {
            return Err(CompatErrno::Invalid);
        }
        vectors.push((base, len));
    }
    Ok(vectors)
}

/// Implements plain-data `sendmsg(2)` on a connected AF_UNIX stream.
fn linux_sendmsg(pid: ObjId, args: [u64; 6]) -> Result<u64, CompatErrno> {
    const MSG_DONTWAIT: u64 = 0x40;
    const MSG_EOR: u64 = 0x80;
    const MSG_NOSIGNAL: u64 = 0x4000;
    const MSG_MORE: u64 = 0x8000;
    let fd = u32::try_from(args[0]).map_err(|_| CompatErrno::BadFd)?;
    let header = read_message_header(pid, args[1])?;
    if header.flags & !(MSG_DONTWAIT | MSG_EOR | MSG_NOSIGNAL | MSG_MORE) != 0 {
        return Err(CompatErrno::Invalid);
    }
    if header.name != 0 || header.name_len != 0 {
        return Err(CompatErrno::IsConnected);
    }
    if header.control != 0 || header.control_len != 0 {
        return Err(CompatErrno::NoSys);
    }
    let entry = proc::linux_fd(pid, fd).ok_or(CompatErrno::BadFd)?;
    if entry.kind != compat_core::fd::CompatKind::Socket
        || !entry
            .rights
            .contains(kernel_core::object::Rights::WRITE)
    {
        return Err(CompatErrno::NotConnected);
    }
    let vectors =
        read_message_iovecs(pid, header.iov, header.iov_len, compat_core::PIPE_CAPACITY)?;
    let mut bytes = alloc::vec::Vec::new();
    bytes
        .try_reserve(vectors.iter().map(|(_, len)| *len).sum())
        .map_err(|_| CompatErrno::NoMemory)?;
    for (base, len) in vectors {
        let start = bytes.len();
        bytes.resize(start + len, 0);
        proc::read(pid, base, &mut bytes[start..]).map_err(|_| CompatErrno::Fault)?;
    }
    linux_socket_write_buffer(
        pid,
        fd,
        entry.handle,
        &bytes,
        header.flags & MSG_DONTWAIT != 0,
        header.flags & MSG_NOSIGNAL != 0,
    )
}

/// Implements plain-data `recvmsg(2)` on a connected AF_UNIX stream.
fn linux_recvmsg(pid: ObjId, args: [u64; 6]) -> Result<u64, CompatErrno> {
    const MSG_DONTWAIT: u64 = 0x40;
    const MSG_WAITALL: u64 = 0x100;
    const MSG_CMSG_CLOEXEC: u64 = 0x4000_0000;
    let fd = u32::try_from(args[0]).map_err(|_| CompatErrno::BadFd)?;
    let header = read_message_header(pid, args[1])?;
    if header.flags & !(MSG_DONTWAIT | MSG_WAITALL | MSG_CMSG_CLOEXEC) != 0 {
        return Err(CompatErrno::Invalid);
    }
    if header.control != 0 || header.control_len != 0 {
        return Err(CompatErrno::NoSys);
    }
    let entry = proc::linux_fd(pid, fd).ok_or(CompatErrno::BadFd)?;
    if entry.kind != compat_core::fd::CompatKind::Socket
        || !entry.rights.contains(kernel_core::object::Rights::READ)
    {
        return Err(CompatErrno::NotConnected);
    }
    let vectors =
        read_message_iovecs(pid, header.iov, header.iov_len, compat_core::PIPE_CAPACITY)?;
    let total = vectors.iter().map(|(_, len)| *len).sum::<usize>();
    let mut bytes = alloc::vec![0u8; total];
    let count = linux_socket_read_buffer(
        pid,
        fd,
        entry.handle,
        &mut bytes,
        header.flags & MSG_DONTWAIT != 0,
    )?;
    let mut offset = 0usize;
    for (base, len) in vectors {
        let take = count.saturating_sub(offset).min(len);
        if take != 0 {
            copy_to_user(base, &bytes[offset..offset + take], take)
                .map_err(|_| CompatErrno::Fault)?;
            offset += take;
        }
    }
    if header.name != 0 {
        let endpoint = proc::linux_socket_endpoint(pid, entry.handle)
            .ok_or(CompatErrno::NotConnected)?;
        let name = endpoint
            .peer_name()
            .unwrap_or_else(compat_core::UnixSocketName::empty);
        write_unix_sockaddr_with_capacity(header.name, header.name_len, name)?;
    }
    let mut raw = [0u8; 4];
    raw.copy_from_slice(&0u32.to_le_bytes());
    proc::write(pid, args[1] + 8, &raw).map_err(|_| CompatErrno::Fault)?;
    proc::write(pid, args[1] + 48, &raw).map_err(|_| CompatErrno::Fault)?;
    Ok(count as u64)
}

/// Applies one directional AF_UNIX stream shutdown.
fn linux_shutdown(pid: ObjId, args: [u64; 6]) -> Result<u64, CompatErrno> {
    let fd = u32::try_from(args[0]).map_err(|_| CompatErrno::BadFd)?;
    let how = u32::try_from(args[1]).map_err(|_| CompatErrno::Invalid)?;
    let entry = proc::linux_fd(pid, fd).ok_or(CompatErrno::BadFd)?;
    if entry.kind != compat_core::fd::CompatKind::Socket {
        return Err(CompatErrno::NotConnected);
    }
    let socket = proc::linux_socket_endpoint(pid, entry.handle).ok_or(CompatErrno::NotConnected)?;
    if !socket.is_connected() {
        return Err(CompatErrno::NotConnected);
    }
    if socket.shutdown(how) {
        Ok(0)
    } else {
        Err(CompatErrno::Invalid)
    }
}

/// Writes one AF_UNIX address and updates its caller length.
fn write_unix_sockaddr(
    address: u64,
    length_address: u64,
    name: compat_core::UnixSocketName,
) -> Result<(), CompatErrno> {
    if address == 0 || length_address == 0 {
        return Err(CompatErrno::Fault);
    }
    let mut raw_len = [0u8; 4];
    copy_from_user(&mut raw_len, length_address, 4).map_err(|_| CompatErrno::Fault)?;
    let capacity = u32::from_le_bytes(raw_len) as usize;
    write_unix_sockaddr_with_capacity(address, capacity, name)?;
    let actual = 2 + name.as_bytes().len();
    copy_to_user(length_address, &(actual as u32).to_le_bytes(), 4)
        .map_err(|_| CompatErrno::Fault)?;
    Ok(())
}

/// Writes one AF_UNIX address to a caller-provided capacity.
fn write_unix_sockaddr_with_capacity(
    address: u64,
    capacity: usize,
    name: compat_core::UnixSocketName,
) -> Result<(), CompatErrno> {
    if address == 0 {
        return Err(CompatErrno::Fault);
    }
    let mut sockaddr = [0u8; 110];
    sockaddr[0..2].copy_from_slice(&1u16.to_le_bytes());
    let name = name.as_bytes();
    sockaddr[2..2 + name.len()].copy_from_slice(name);
    let actual = 2 + name.len();
    let copied = capacity.min(actual);
    if copied != 0 {
        copy_to_user(address, &sockaddr[..copied], copied).map_err(|_| CompatErrno::Fault)?;
    }
    Ok(())
}

/// Implements `getsockname(2)` and `getpeername(2)` for Unix streams.
fn linux_sockname(pid: ObjId, args: [u64; 6], peer: bool) -> Result<u64, CompatErrno> {
    let fd = u32::try_from(args[0]).map_err(|_| CompatErrno::BadFd)?;
    let entry = proc::linux_fd(pid, fd).ok_or(CompatErrno::BadFd)?;
    if entry.kind != compat_core::fd::CompatKind::Socket {
        return Err(CompatErrno::NotConnected);
    }
    let endpoint =
        proc::linux_socket_endpoint(pid, entry.handle).ok_or(CompatErrno::NotConnected)?;
    let name = if peer {
        if !endpoint.is_connected() {
            return Err(CompatErrno::NotConnected);
        }
        endpoint.peer_name().ok_or(CompatErrno::NotConnected)?
    } else {
        endpoint
            .local_name()
            .unwrap_or_else(compat_core::UnixSocketName::empty)
    };
    write_unix_sockaddr(args[1], args[2], name)?;
    Ok(0)
}

/// Reads a pipe using blocking or nonblocking descriptior status.
fn linux_pipe_read(
    pid: ObjId,
    fd: u32,
    handle: u64,
    address: u64,
    len: usize,
) -> Result<u64, CompatErrno> {
    if len == 0 {
        return Ok(0);
    }
    let endpoint = proc::linux_pipe_endpoint(pid, handle).ok_or(CompatErrno::BadFd)?;
    let nonblocking = proc::linux_fd_status_flags(pid, fd).ok_or(CompatErrno::BadFd)? & 0x800 != 0;
    let mut output = alloc::vec![0u8; len];
    loop {
        match endpoint.read(&mut output) {
            compat_core::PipeRead::Data(0) => return Ok(0),
            compat_core::PipeRead::Data(count) => {
                copy_to_user(address, &output[..count], count).map_err(|_| CompatErrno::Fault)?;
                return Ok(count as u64);
            }
            compat_core::PipeRead::Eof => return Ok(0),
            compat_core::PipeRead::WouldBlock if nonblocking => return Err(CompatErrno::TryAgain),
            compat_core::PipeRead::WouldBlock => {
                if proc::current_exiting() || current_signal_pending(pid) {
                    return Err(CompatErrno::Interrupted);
                }
                sched::pause();
            }
        }
    }
}

/// Writes a bounded pipe byte stream and preserves `PIPE_BUF` atomic writes.
fn linux_pipe_write(
    pid: ObjId,
    fd: u32,
    handle: u64,
    address: u64,
    len: usize,
) -> Result<u64, CompatErrno> {
    if len == 0 {
        return Ok(0);
    }
    if len > compat_core::PIPE_CAPACITY {
        return Err(CompatErrno::Invalid);
    }
    let endpoint = proc::linux_pipe_endpoint(pid, handle).ok_or(CompatErrno::BadFd)?;
    let nonblocking = proc::linux_fd_status_flags(pid, fd).ok_or(CompatErrno::BadFd)? & 0x800 != 0;
    let mut input = alloc::vec![0u8; len];
    copy_from_user(&mut input, address, len).map_err(|_| CompatErrno::Fault)?;
    let mut written = 0usize;
    while written < input.len() {
        match endpoint.write(&input[written..]) {
            compat_core::PipeWrite::Data(0) => {
                raise_sigpipe(pid);
                return Err(CompatErrno::BrokenPipe);
            }
            compat_core::PipeWrite::Data(count) => written += count,
            compat_core::PipeWrite::Broken => {
                raise_sigpipe(pid);
                return Err(CompatErrno::BrokenPipe);
            }
            compat_core::PipeWrite::WouldBlock if nonblocking => {
                return if written == 0 {
                    Err(CompatErrno::TryAgain)
                } else {
                    Ok(written as u64)
                }
            }
            compat_core::PipeWrite::WouldBlock => {
                if proc::current_exiting() || current_signal_pending(pid) {
                    return if written == 0 {
                        Err(CompatErrno::Interrupted)
                    } else {
                        Ok(written as u64)
                    };
                }
                sched::pause();
            }
        }
    }
    Ok(written as u64)
}

/// Reads one connected AF_UNIX stream endpoint.
fn linux_socket_read(
    pid: ObjId,
    fd: u32,
    handle: u64,
    address: u64,
    len: usize,
    force_nonblocking: bool,
) -> Result<u64, CompatErrno> {
    let mut output = alloc::vec![0u8; len];
    let count = linux_socket_read_buffer(pid, fd, handle, &mut output, force_nonblocking)?;
    copy_to_user(address, &output[..count], count).map_err(|_| CompatErrno::Fault)?;
    Ok(count as u64)
}

/// Reads an already validated socket buffer with shared blocking semantics.
fn linux_socket_read_buffer(
    pid: ObjId,
    fd: u32,
    handle: u64,
    output: &mut [u8],
    force_nonblocking: bool,
) -> Result<usize, CompatErrno> {
    if output.is_empty() {
        return Ok(0);
    }
    let endpoint = proc::linux_socket_endpoint(pid, handle).ok_or(CompatErrno::BadFd)?;
    if !endpoint.is_connected() {
        return Err(CompatErrno::NotConnected);
    }
    let nonblocking = force_nonblocking
        || proc::linux_fd_status_flags(pid, fd).ok_or(CompatErrno::BadFd)? & 0x800 != 0;
    loop {
        match endpoint.read(output) {
            compat_core::PipeRead::Data(count) => return Ok(count),
            compat_core::PipeRead::Eof => return Ok(0),
            compat_core::PipeRead::WouldBlock if nonblocking => return Err(CompatErrno::TryAgain),
            compat_core::PipeRead::WouldBlock => {
                if proc::current_exiting() || current_signal_pending(pid) {
                    return Err(CompatErrno::Interrupted);
                }
                sched::pause();
            }
        }
    }
}

/// Writes one connected AF_UNIX stream endpoint.
fn linux_socket_write(
    pid: ObjId,
    fd: u32,
    handle: u64,
    address: u64,
    len: usize,
    force_nonblocking: bool,
    suppress_sigpipe: bool,
) -> Result<u64, CompatErrno> {
    let mut input = alloc::vec![0u8; len];
    copy_from_user(&mut input, address, len).map_err(|_| CompatErrno::Fault)?;
    linux_socket_write_buffer(
        pid,
        fd,
        handle,
        &input,
        force_nonblocking,
        suppress_sigpipe,
    )
}

/// Writes an already validated socket buffer with the shared blocking and
/// SIGPIPE semantics used by all socket write entry points.
fn linux_socket_write_buffer(
    pid: ObjId,
    fd: u32,
    handle: u64,
    input: &[u8],
    force_nonblocking: bool,
    suppress_sigpipe: bool,
) -> Result<u64, CompatErrno> {
    if input.is_empty() {
        return Ok(0);
    }
    if input.len() > compat_core::PIPE_CAPACITY {
        return Err(CompatErrno::Invalid);
    }
    let endpoint = proc::linux_socket_endpoint(pid, handle).ok_or(CompatErrno::BadFd)?;
    if !endpoint.is_connected() {
        return Err(CompatErrno::NotConnected);
    }
    let nonblocking = force_nonblocking
        || proc::linux_fd_status_flags(pid, fd).ok_or(CompatErrno::BadFd)? & 0x800 != 0;
    let mut written = 0usize;
    while written < input.len() {
        match endpoint.write(&input[written..]) {
            compat_core::PipeWrite::Data(count) => written += count,
            compat_core::PipeWrite::Broken => {
                if !suppress_sigpipe {
                    raise_sigpipe(pid);
                }
                return Err(CompatErrno::BrokenPipe);
            }
            compat_core::PipeWrite::WouldBlock if nonblocking => {
                return if written == 0 {
                    Err(CompatErrno::TryAgain)
                } else {
                    Ok(written as u64)
                }
            }
            compat_core::PipeWrite::WouldBlock => {
                if proc::current_exiting() || current_signal_pending(pid) {
                    return if written == 0 {
                        Err(CompatErrno::Interrupted)
                    } else {
                        Ok(written as u64)
                    };
                }
                sched::pause();
            }
        }
    }
    Ok(written as u64)
}

/// Applies the process's disposition for SIGPIPE after a broken pipe write.
fn raise_sigpipe(pid: ObjId) {
    const SIGPIPE: u32 = 13;
    let Some(action) = proc::linux_signal_action(pid, SIGPIPE) else {
        return;
    };
    match action[0] {
        1 => {}
        0 => {
            let _ = proc::begin_exit(pid, 128 + i64::from(SIGPIPE));
        }
        _ => {
            if let Some(tid) = linux_tid(pid) {
                let _ = queue_thread_signal(pid, tid, SIGPIPE);
            }
        }
    }
}

/// Opens one exact virtual read-only path through `openat(2)`.
///
/// 仅接受绝对路径与只读标志；`O_CLOEXEC` 被保留，写模式、路径穿越和未知路径失败关闭。
fn linux_openat(pid: ObjId, args: [u64; 6]) -> Result<u64, CompatErrno> {
    const O_CLOEXEC: u64 = 0x80000;
    const O_DIRECTORY: u64 = 0x10000;
    const O_NONBLOCK: u64 = 0x800;
    const O_NOCTTY: u64 = 0x100;
    const O_NOFOLLOW: u64 = 0x20000;
    #[cfg(feature = "compat-dynamic-libc-verify")]
    trace_path_address(pid, "openat-address", args[1]);
    let flags = args[2];
    if flags & 3 != 0
        || flags & !(O_CLOEXEC | O_DIRECTORY | O_NONBLOCK | O_NOCTTY | O_NOFOLLOW) != 0
    {
        return Err(CompatErrno::Perm);
    }
    let path = linux_c_string(args[1], 4096)?;
    #[cfg(feature = "compat-dynamic-libc-verify")]
    trace_path("openat", &path);
    let resolved = if path.starts_with(b"/") {
        if !is_at_fdcwd(args[0]) {
            return Err(CompatErrno::Invalid);
        }
        path
    } else {
        if path == b".."
            || path.starts_with(b"../")
            || path.windows(4).any(|window| window == b"/../")
        {
            return Err(CompatErrno::Invalid);
        }
        let base = if is_at_fdcwd(args[0]) {
            proc::linux_cwd(pid).ok_or(CompatErrno::NoSys)?.path()
        } else {
            let fd = u32::try_from(args[0]).map_err(|_| CompatErrno::BadFd)?;
            let (handle, _) = proc::linux_dir_state(pid, fd).ok_or(CompatErrno::NotDirectory)?;
            crate::linux_vfs::DirectoryId::from_handle(handle)
                .ok_or(CompatErrno::BadFd)?
                .path()
        };
        if path == b"." {
            base.to_vec()
        } else {
            let mut resolved = alloc::vec::Vec::with_capacity(base.len() + path.len() + 1);
            resolved.extend_from_slice(base);
            if !base.ends_with(b"/") {
                resolved.push(b'/');
            }
            resolved.extend_from_slice(&path);
            resolved
        }
    };
    let node = crate::linux_vfs::lookup_node(&resolved).ok_or(CompatErrno::NoEntry)?;
    let close_on_exec = flags & O_CLOEXEC != 0;
    let fd = match node {
        crate::linux_vfs::Node::File(file) => {
            if flags & O_DIRECTORY != 0 {
                return Err(CompatErrno::NotDirectory);
            }
            proc::linux_install_file(pid, file.handle(), close_on_exec)
        }
        crate::linux_vfs::Node::Directory(directory) => {
            proc::linux_install_dir(pid, directory.handle(), close_on_exec)
        }
        crate::linux_vfs::Node::Executable(_) => {
            // The compatibility namespace exposes executable metadata for
            // directory/stat probes. Its bytes come only from the selected
            // trusted root and must not become readable through generic VFS
            // descriptors.
            // 兼容命名空间只为目录/stat 探测暴露可执行文件元数据。其字节只来自
            // 选定的可信根卷，不能经通用 VFS 描述符变成任意可读文件。
            return if flags & O_DIRECTORY != 0 {
                Err(CompatErrno::NotDirectory)
            } else {
                Err(CompatErrno::Access)
            };
        }
    }
    .ok_or(CompatErrno::NoSpace)?;
    Ok(u64::from(fd))
}

/// Changes the compatibility working directory to one authorized directory.
///
/// `fchdir` 只接受已验证的目录 fd，并把同一目录身份提交为进程 cwd。
fn linux_fchdir(pid: ObjId, fd: u64) -> Result<u64, CompatErrno> {
    let fd = u32::try_from(fd).map_err(|_| CompatErrno::BadFd)?;
    let (handle, _) = proc::linux_dir_state(pid, fd).ok_or(CompatErrno::BadFd)?;
    let directory = crate::linux_vfs::DirectoryId::from_handle(handle).ok_or(CompatErrno::BadFd)?;
    if proc::set_linux_cwd(pid, directory) {
        Ok(0)
    } else {
        Err(CompatErrno::NoSys)
    }
}

/// Changes the Linux compatibility current directory within the static namespace.
///
/// 绝对路径从兼容根解析，相对路径从进程当前目录解析；仅目录节点可提交为 cwd。
fn linux_chdir(pid: ObjId, address: u64) -> Result<u64, CompatErrno> {
    let path = linux_c_string(address, 4096)?;
    let resolved = if path.starts_with(b"/") {
        path
    } else {
        if path == b".."
            || path.starts_with(b"../")
            || path.windows(4).any(|window| window == b"/../")
        {
            return Err(CompatErrno::Invalid);
        }
        let current = proc::linux_cwd(pid).ok_or(CompatErrno::NoSys)?;
        if path == b"." {
            return if proc::set_linux_cwd(pid, current) {
                Ok(0)
            } else {
                Err(CompatErrno::NoSys)
            };
        }
        let base = current.path();
        let mut resolved = alloc::vec::Vec::with_capacity(base.len() + path.len() + 1);
        resolved.extend_from_slice(base);
        if !base.ends_with(b"/") {
            resolved.push(b'/');
        }
        resolved.extend_from_slice(&path);
        resolved
    };
    let directory = match crate::linux_vfs::lookup_node(&resolved) {
        Some(crate::linux_vfs::Node::Directory(directory)) => directory,
        Some(crate::linux_vfs::Node::File(_) | crate::linux_vfs::Node::Executable(_)) => {
            return Err(CompatErrno::NotDirectory);
        }
        None => return Err(CompatErrno::NoEntry),
    };
    if proc::set_linux_cwd(pid, directory) {
        Ok(0)
    } else {
        Err(CompatErrno::NoSys)
    }
}

/// Reads a bounded NUL-terminated Linux path from user memory.
///
/// 逐字节固定并复制，避免要求未映射的整页同时有效；缺失 NUL 或空路径失败关闭。
fn linux_c_string(address: u64, max: usize) -> Result<alloc::vec::Vec<u8>, CompatErrno> {
    let mut path = alloc::vec::Vec::new();
    for offset in 0..max {
        let current = address
            .checked_add(offset as u64)
            .ok_or(CompatErrno::Fault)?;
        let mut byte = [0u8; 1];
        copy_from_user(&mut byte, current, 1).map_err(|_| CompatErrno::Fault)?;
        if byte[0] == 0 {
            return if path.is_empty() {
                Err(CompatErrno::NoEntry)
            } else {
                Ok(path)
            };
        }
        path.push(byte[0]);
    }
    Err(CompatErrno::Invalid)
}

/// Implements `fstat(2)` for the virtual file namespace.
///
/// 填充 x86_64 Linux `struct stat`，只报告普通只读文件；控制台和其他 fd 不属于本切片。
fn linux_fstat(pid: ObjId, args: [u64; 6]) -> Result<u64, CompatErrno> {
    let fd = u32::try_from(args[0]).map_err(|_| CompatErrno::BadFd)?;
    let entry = proc::linux_fd(pid, fd).ok_or(CompatErrno::BadFd)?;
    let node = crate::linux_vfs::FileId::from_handle(entry.handle)
        .map(crate::linux_vfs::Node::File)
        .or_else(|| {
            crate::linux_vfs::DirectoryId::from_handle(entry.handle)
                .map(crate::linux_vfs::Node::Directory)
        })
        .ok_or(CompatErrno::BadFd)?;
    write_linux_stat(args[1], node)?;
    Ok(0)
}

/// Implements `newfstatat(2)` for exact virtual paths or an open file descriptor.
///
/// 支持精确虚拟路径和 `AT_EMPTY_PATH` 下的已打开文件；其他目录 fd、路径和 flags 失败关闭。
fn linux_newfstatat(pid: ObjId, args: [u64; 6]) -> Result<u64, CompatErrno> {
    const AT_EMPTY_PATH: u64 = 0x1000;
    const AT_SYMLINK_NOFOLLOW: u64 = 0x100;
    const AT_NO_AUTOMOUNT: u64 = 0x800;
    const ALLOWED_FLAGS: u64 = AT_EMPTY_PATH | AT_SYMLINK_NOFOLLOW | AT_NO_AUTOMOUNT;
    if args[3] & !ALLOWED_FLAGS != 0 {
        return Err(CompatErrno::Invalid);
    }
    #[cfg(feature = "compat-dynamic-libc-verify")]
    trace_path_address(pid, "newfstatat-address", args[1]);
    let raw_path = linux_c_string(args[1], 4096);
    let path = match raw_path {
        Ok(path) => path,
        Err(CompatErrno::NoEntry) if args[3] & AT_EMPTY_PATH != 0 => {
            let fd = u32::try_from(args[0]).map_err(|_| CompatErrno::BadFd)?;
            let entry = proc::linux_fd(pid, fd).ok_or(CompatErrno::BadFd)?;
            let node = crate::linux_vfs::FileId::from_handle(entry.handle)
                .map(crate::linux_vfs::Node::File)
                .or_else(|| {
                    crate::linux_vfs::DirectoryId::from_handle(entry.handle)
                        .map(crate::linux_vfs::Node::Directory)
                })
                .ok_or(CompatErrno::BadFd)?;
            write_linux_stat(args[2], node)?;
            return Ok(0);
        }
        Err(error) => return Err(error),
    };
    #[cfg(feature = "compat-dynamic-libc-verify")]
    trace_path("newfstatat", &path);
    let resolved = if path.starts_with(b"/") {
        if !is_at_fdcwd(args[0]) {
            return Err(CompatErrno::Invalid);
        }
        path
    } else {
        if path == b".."
            || path.starts_with(b"../")
            || path.windows(4).any(|window| window == b"/../")
        {
            return Err(CompatErrno::Invalid);
        }
        let base = if is_at_fdcwd(args[0]) {
            proc::linux_cwd(pid).ok_or(CompatErrno::NoSys)?.path()
        } else {
            let fd = u32::try_from(args[0]).map_err(|_| CompatErrno::BadFd)?;
            let (handle, _) = proc::linux_dir_state(pid, fd).ok_or(CompatErrno::NotDirectory)?;
            crate::linux_vfs::DirectoryId::from_handle(handle)
                .ok_or(CompatErrno::BadFd)?
                .path()
        };
        if path == b"." {
            base.to_vec()
        } else {
            let mut resolved = alloc::vec::Vec::with_capacity(base.len() + path.len() + 1);
            resolved.extend_from_slice(base);
            if !base.ends_with(b"/") {
                resolved.push(b'/');
            }
            resolved.extend_from_slice(&path);
            resolved
        }
    };
    let node = crate::linux_vfs::lookup_node(&resolved).ok_or(CompatErrno::NoEntry)?;
    write_linux_stat(args[2], node)?;
    Ok(0)
}

/// Implements bounded `statx(2)` over the virtual Linux namespace.
///
/// 返回稳定类型、权限、链接数、身份、inode、大小和块数；不支持的时间、挂载 ID
/// 和 I/O 对齐字段不会出现在 `stx_mask` 中，而不是写入伪造值。
fn linux_statx(pid: ObjId, args: [u64; 6]) -> Result<u64, CompatErrno> {
    const AT_SYMLINK_NOFOLLOW: u64 = 0x100;
    const AT_NO_AUTOMOUNT: u64 = 0x800;
    const AT_EMPTY_PATH: u64 = 0x1000;
    const AT_STATX_SYNC_TYPE: u64 = 0x6000;
    const STATX_BASIC_STATS: u64 = 0x7ff;
    const STATX_BTIME: u64 = 0x800;
    const STATX_MNT_ID: u64 = 0x1000;
    const STATX_DIOALIGN: u64 = 0x2000;
    const SUPPORTED_MASK: u64 = STATX_BASIC_STATS | STATX_BTIME | STATX_MNT_ID | STATX_DIOALIGN;
    const RETURNED_MASK: u32 = 0x71f;
    if args[2] & !(AT_SYMLINK_NOFOLLOW | AT_NO_AUTOMOUNT | AT_EMPTY_PATH | AT_STATX_SYNC_TYPE) != 0
        || args[3] & !SUPPORTED_MASK != 0
    {
        return Err(CompatErrno::Invalid);
    }
    #[cfg(feature = "compat-dynamic-libc-verify")]
    trace_path_address(pid, "statx-address", args[1]);
    let raw_path = linux_c_string(args[1], 4096);
    let (node, size) = match raw_path {
        Ok(path) => {
            #[cfg(feature = "compat-dynamic-libc-verify")]
            trace_path("statx", &path);
            let resolved = if path.starts_with(b"/") {
                if !is_at_fdcwd(args[0]) {
                    return Err(CompatErrno::Invalid);
                }
                path
            } else {
                if path == b".."
                    || path.starts_with(b"../")
                    || path.windows(4).any(|window| window == b"/../")
                {
                    return Err(CompatErrno::Invalid);
                }
                let base = if is_at_fdcwd(args[0]) {
                    proc::linux_cwd(pid).ok_or(CompatErrno::NoSys)?.path()
                } else {
                    let fd = u32::try_from(args[0]).map_err(|_| CompatErrno::BadFd)?;
                    let (handle, _) =
                        proc::linux_dir_state(pid, fd).ok_or(CompatErrno::NotDirectory)?;
                    crate::linux_vfs::DirectoryId::from_handle(handle)
                        .ok_or(CompatErrno::BadFd)?
                        .path()
                };
                if path == b"." {
                    base.to_vec()
                } else {
                    let mut resolved = alloc::vec::Vec::with_capacity(base.len() + path.len() + 1);
                    resolved.extend_from_slice(base);
                    if !base.ends_with(b"/") {
                        resolved.push(b'/');
                    }
                    resolved.extend_from_slice(&path);
                    resolved
                }
            };
            let node = crate::linux_vfs::lookup_node(&resolved).ok_or(CompatErrno::NoEntry)?;
            let size = if node.is_directory() {
                4096
            } else {
                node.stat_metadata().0
            };
            (node, size)
        }
        Err(CompatErrno::NoEntry) if args[2] & AT_EMPTY_PATH != 0 => {
            let fd = u32::try_from(args[0]).map_err(|_| CompatErrno::BadFd)?;
            let entry = proc::linux_fd(pid, fd).ok_or(CompatErrno::BadFd)?;
            if let Some(file) = crate::linux_vfs::FileId::from_handle(entry.handle) {
                (
                    crate::linux_vfs::Node::File(file),
                    file.bytes().len() as u64,
                )
            } else if let Some(directory) = crate::linux_vfs::DirectoryId::from_handle(entry.handle)
            {
                (crate::linux_vfs::Node::Directory(directory), 4096)
            } else {
                return Err(CompatErrno::BadFd);
            }
        }
        Err(error) => return Err(error),
    };
    let (_, links, mode) = node.stat_metadata();
    let mut output = [0u8; 256];
    output[0..4].copy_from_slice(&RETURNED_MASK.to_le_bytes());
    output[4..8].copy_from_slice(&4096u32.to_le_bytes());
    output[16..20].copy_from_slice(&(links as u32).to_le_bytes());
    output[20..24].copy_from_slice(&0u32.to_le_bytes());
    output[24..28].copy_from_slice(&0u32.to_le_bytes());
    output[28..30].copy_from_slice(&(mode as u16).to_le_bytes());
    output[32..40].copy_from_slice(&node.inode().to_le_bytes());
    output[40..48].copy_from_slice(&size.to_le_bytes());
    output[48..56].copy_from_slice(&size.div_ceil(512).to_le_bytes());
    copy_to_user(args[4], &output, output.len()).map_err(|_| CompatErrno::Fault)?;
    Ok(0)
}

/// Implements `fcntl(2)` descriptor flag operations.
///
/// 当前支持 `F_GETFD` 与 `F_SETFD`；未知命令和未知 fd 标志失败关闭。
fn linux_fcntl(pid: ObjId, args: [u64; 6]) -> Result<u64, CompatErrno> {
    const F_DUPFD: u64 = 0;
    const F_DUPFD_CLOEXEC: u64 = 1030;
    const F_GETFD: u64 = 1;
    const F_SETFD: u64 = 2;
    const F_GETFL: u64 = 3;
    const F_SETFL: u64 = 4;
    const FD_CLOEXEC: u64 = 1;
    const O_NONBLOCK: u64 = 0x800;
    const O_DIRECTORY: u64 = 0x10000;
    let fd = u32::try_from(args[0]).map_err(|_| CompatErrno::BadFd)?;
    let entry = proc::linux_fd(pid, fd).ok_or(CompatErrno::BadFd)?;
    match args[1] {
        F_GETFD => Ok(u64::from(entry.close_on_exec)),
        F_GETFL => {
            let status = u64::from(proc::linux_fd_status_flags(pid, fd).ok_or(CompatErrno::BadFd)?);
            Ok(status
                | if entry.kind == compat_core::fd::CompatKind::Directory {
                    O_DIRECTORY
                } else {
                    0
                })
        }
        F_SETFL if args[2] & !O_NONBLOCK == 0 => {
            if proc::linux_set_fd_status_flags(pid, fd, args[2] as u32) {
                Ok(0)
            } else {
                Err(CompatErrno::BadFd)
            }
        }
        F_SETFD if args[2] & !FD_CLOEXEC == 0 => {
            if proc::linux_set_fd_cloexec(pid, fd, args[2] & FD_CLOEXEC != 0) {
                Ok(0)
            } else {
                Err(CompatErrno::BadFd)
            }
        }
        F_DUPFD | F_DUPFD_CLOEXEC => {
            let minimum = u32::try_from(args[2]).map_err(|_| CompatErrno::Invalid)?;
            let duplicate = proc::linux_duplicate_fd(pid, fd, minimum, args[1] == F_DUPFD_CLOEXEC)
                .ok_or(CompatErrno::NoSpace)?;
            Ok(u64::from(duplicate))
        }
        F_SETFD | F_SETFL => Err(CompatErrno::Invalid),
        _ => Err(CompatErrno::NoSys),
    }
}

/// Implements the terminal-probing subset of `ioctl(2)`.
///
/// 当前标准流不是 TerminalSession；常见 TTY 查询明确返回 `ENOTTY`，其他设备
/// 控制请求返回 `ENOSYS`，不会把普通控制台描述符伪装成终端。
fn linux_ioctl(pid: ObjId, args: [u64; 6]) -> Result<u64, CompatErrno> {
    const TCGETS: u64 = 0x5401;
    const TCSETS: u64 = 0x5402;
    const TCSETSW: u64 = 0x5403;
    const TCSETSF: u64 = 0x5404;
    const TIOCGWINSZ: u64 = 0x5413;
    const TIOCSWINSZ: u64 = 0x5414;
    const FIONREAD: u64 = 0x541b;
    const TCGETS2: u64 = 0x802c_542a;
    let fd = u32::try_from(args[0]).map_err(|_| CompatErrno::BadFd)?;
    let entry = proc::linux_fd(pid, fd).ok_or(CompatErrno::BadFd)?;
    if args[1] == FIONREAD && entry.kind == compat_core::fd::CompatKind::Pipe {
        if !entry.rights.contains(kernel_core::object::Rights::READ) {
            return Err(CompatErrno::BadFd);
        }
        let pipe = proc::linux_pipe_endpoint(pid, entry.handle).ok_or(CompatErrno::BadFd)?;
        let available = i32::try_from(pipe.buffered_bytes()).unwrap_or(i32::MAX);
        copy_to_user(args[2], &available.to_le_bytes(), 4).map_err(|_| CompatErrno::Fault)?;
        return Ok(0);
    }
    if args[1] == FIONREAD && entry.kind == compat_core::fd::CompatKind::Socket {
        if !entry.rights.contains(kernel_core::object::Rights::READ) {
            return Err(CompatErrno::BadFd);
        }
        let socket = proc::linux_socket_endpoint(pid, entry.handle).ok_or(CompatErrno::BadFd)?;
        let available = i32::try_from(socket.buffered_bytes()).unwrap_or(i32::MAX);
        copy_to_user(args[2], &available.to_le_bytes(), 4).map_err(|_| CompatErrno::Fault)?;
        return Ok(0);
    }
    if matches!(
        args[1],
        TCGETS | TCSETS | TCSETSW | TCSETSF | TIOCGWINSZ | TIOCSWINSZ | TCGETS2
    ) {
        Err(CompatErrno::NotTty)
    } else {
        Err(CompatErrno::NoSys)
    }
}

/// Implements a bounded non-blocking `poll(2)` over Jasper compatibility fds.
///
/// 只接受零超时；常规文件按其请求的读写事件就绪，控制台当前无输入。无效 fd
/// 返回 `POLLNVAL`，调用不会因未实现的阻塞等待而伪装成功。
fn linux_poll(pid: ObjId, args: [u64; 6]) -> Result<u64, CompatErrno> {
    const POLLIN: u16 = 0x001;
    const POLLOUT: u16 = 0x004;
    const POLLERR: u16 = 0x008;
    const POLLHUP: u16 = 0x010;
    const POLLNVAL: u16 = 0x020;
    const MAX_POLLFDS: usize = 64;
    let count = usize::try_from(args[1]).map_err(|_| CompatErrno::Invalid)?;
    let timeout = args[2] as u32 as i32;
    if count > MAX_POLLFDS || timeout != 0 {
        return Err(CompatErrno::NoSys);
    }
    for index in 0..count {
        let address = args[0]
            .checked_add((index * 8) as u64)
            .ok_or(CompatErrno::Fault)?;
        let mut pollfd = [0u8; 8];
        copy_from_user(&mut pollfd, address, 8).map_err(|_| CompatErrno::Fault)?;
        let fd = i32::from_le_bytes(pollfd[0..4].try_into().unwrap());
        let events = u16::from_le_bytes(pollfd[4..6].try_into().unwrap());
        let revents = if fd < 0 {
            0
        } else {
            match proc::linux_fd(pid, fd as u32) {
                None => POLLNVAL,
                Some(entry) if entry.kind == compat_core::fd::CompatKind::File => {
                    events & (POLLIN | POLLOUT)
                }
                Some(entry) if entry.kind == compat_core::fd::CompatKind::Pipe => {
                    let Some(pipe) = proc::linux_pipe_endpoint(pid, entry.handle) else {
                        continue;
                    };
                    let mut ready = 0;
                    if events & POLLIN != 0 && pipe.is_readable() {
                        ready |= POLLIN;
                    }
                    if events & POLLOUT != 0 && pipe.is_writable() {
                        ready |= POLLOUT;
                    }
                    if pipe.readers_gone()
                        && entry.rights.contains(kernel_core::object::Rights::WRITE)
                    {
                        ready |= POLLERR;
                    }
                    if pipe.writers_gone()
                        && entry.rights.contains(kernel_core::object::Rights::READ)
                    {
                        ready |= POLLHUP;
                    }
                    ready
                }
                Some(entry) if entry.kind == compat_core::fd::CompatKind::Socket => {
                    let Some(socket) = proc::linux_socket_endpoint(pid, entry.handle) else {
                        continue;
                    };
                    let mut ready = 0;
                    if events & POLLIN != 0
                        && entry.rights.contains(kernel_core::object::Rights::READ)
                        && socket.is_readable()
                    {
                        ready |= POLLIN;
                    }
                    if events & POLLOUT != 0
                        && entry.rights.contains(kernel_core::object::Rights::WRITE)
                        && socket.is_writable()
                    {
                        ready |= POLLOUT;
                    }
                    if socket.peer_read_gone() {
                        ready |= POLLERR;
                    }
                    if socket.peer_write_gone() {
                        ready |= POLLHUP;
                    }
                    ready
                }
                Some(_) => 0,
            }
        };
        pollfd[6..8].copy_from_slice(&revents.to_le_bytes());
        copy_to_user(address, &pollfd, pollfd.len()).map_err(|_| CompatErrno::Fault)?;
    }
    Ok(0)
}

/// Implements `statfs(2)` over the exact read-only verification namespace.
///
/// 已知虚拟文件返回 ext4 形态的只读统计；未知路径返回 `ENOENT`，不泄漏宿主挂载。
fn linux_statfs(args: [u64; 6]) -> Result<u64, CompatErrno> {
    let path = linux_c_string(args[0], 4096)?;
    let node = crate::linux_vfs::lookup_node(&path).ok_or(CompatErrno::NoEntry)?;
    let size = if node.is_directory() {
        4096
    } else {
        crate::linux_vfs::lookup(&path)
            .map(|file| file.bytes().len() as u64)
            .unwrap_or(0)
    };
    write_linux_statfs(args[1], size)
}

/// Implements `fstatfs(2)` over an open virtual file or directory.
///
/// 对已校验的兼容 fd 返回同一 ext4 形态统计；控制台和未知对象不被冒充分区。
fn linux_fstatfs(pid: ObjId, args: [u64; 6]) -> Result<u64, CompatErrno> {
    let fd = u32::try_from(args[0]).map_err(|_| CompatErrno::BadFd)?;
    let entry = proc::linux_fd(pid, fd).ok_or(CompatErrno::BadFd)?;
    let size = match entry.kind {
        compat_core::fd::CompatKind::File => {
            let file =
                crate::linux_vfs::FileId::from_handle(entry.handle).ok_or(CompatErrno::BadFd)?;
            file.bytes().len() as u64
        }
        compat_core::fd::CompatKind::Directory => 4096,
        _ => return Err(CompatErrno::BadFd),
    };
    write_linux_statfs(args[1], size)
}

fn write_linux_statfs(address: u64, size: u64) -> Result<u64, CompatErrno> {
    const STATFS_BYTES: usize = 120;
    let blocks = size.div_ceil(4096);
    let mut statfs = [0u8; STATFS_BYTES];
    statfs[0..8].copy_from_slice(&0xef53u64.to_le_bytes());
    statfs[8..16].copy_from_slice(&4096u64.to_le_bytes());
    statfs[16..24].copy_from_slice(&blocks.to_le_bytes());
    statfs[24..32].copy_from_slice(&0u64.to_le_bytes());
    statfs[32..40].copy_from_slice(&blocks.to_le_bytes());
    statfs[40..48].copy_from_slice(&1u64.to_le_bytes());
    statfs[48..56].copy_from_slice(&1u64.to_le_bytes());
    statfs[64..72].copy_from_slice(&255u64.to_le_bytes());
    statfs[72..80].copy_from_slice(&4096u64.to_le_bytes());
    copy_to_user(address, &statfs, statfs.len()).map_err(|_| CompatErrno::Fault)?;
    Ok(0)
}

/// Implements `readlink(2)` for `/proc/self/exe`.
///
/// 返回本进程真实执行路径；其他虚拟路径返回 `ENOENT`。结果按 Linux 语义不加 NUL，
/// 并返回放入用户缓冲区的字节数。
fn linux_readlink(pid: ObjId, args: [u64; 6]) -> Result<u64, CompatErrno> {
    let path = linux_c_string(args[0], 4096)?;
    if path != b"/proc/self/exe" {
        return Err(CompatErrno::NoEntry);
    }
    let capacity = usize::try_from(args[2]).map_err(|_| CompatErrno::Invalid)?;
    if capacity > 4096 {
        return Err(CompatErrno::Invalid);
    }
    let mut target = [0u8; 128];
    let take = capacity.min(target.len());
    let copied = proc::linux_exec_path(pid, &mut target[..take]).ok_or(CompatErrno::NoEntry)?;
    if copied != 0 {
        copy_to_user(args[1], &target[..copied], copied).map_err(|_| CompatErrno::Fault)?;
    }
    Ok(copied as u64)
}

/// Implements `readlinkat(AT_FDCWD, "/proc/self/exe")`.
///
/// 仅支持兼容根下的执行路径查询；其他目录 fd、flags 或路径失败关闭。
fn linux_readlinkat(pid: ObjId, args: [u64; 6]) -> Result<u64, CompatErrno> {
    if !is_at_fdcwd(args[0]) {
        return Err(CompatErrno::Invalid);
    }
    linux_readlink(pid, [args[1], args[2], args[3], 0, 0, 0])
}

/// Stores or queries one x86_64 Linux signal action.
///
/// 只保存线程库的同步处置配置；信号生成、排队和用户栈帧投递尚未接入，因此该
/// 接口不会把“已登记处置”冒充为“已投递信号”。
fn linux_rt_sigaction(pid: ObjId, args: [u64; 6]) -> Result<u64, CompatErrno> {
    const SIGKILL: u64 = 9;
    const SIGSTOP: u64 = 19;
    const SIGACTION_BYTES: usize = 32;
    if args[3] != 8 || !(1..=64).contains(&args[0]) {
        return Err(CompatErrno::Invalid);
    }
    let signal = args[0] as u32;
    let old = proc::linux_signal_action(pid, signal).ok_or(CompatErrno::NoSys)?;
    if args[1] != 0 {
        if args[0] == SIGKILL || args[0] == SIGSTOP {
            return Err(CompatErrno::Perm);
        }
        let mut action = [0u8; SIGACTION_BYTES];
        copy_from_user(&mut action, args[1], SIGACTION_BYTES).map_err(|_| CompatErrno::Fault)?;
        let disposition = [
            u64::from_le_bytes(action[0..8].try_into().unwrap()),
            u64::from_le_bytes(action[8..16].try_into().unwrap()),
            u64::from_le_bytes(action[16..24].try_into().unwrap()),
            u64::from_le_bytes(action[24..32].try_into().unwrap()),
        ];
        if !proc::set_linux_signal_action(pid, signal, disposition) {
            return Err(CompatErrno::NoSys);
        }
    }
    if args[2] != 0 {
        let mut action = [0u8; SIGACTION_BYTES];
        for (index, value) in old.iter().copied().enumerate() {
            action[index * 8..index * 8 + 8].copy_from_slice(&value.to_le_bytes());
        }
        copy_to_user(args[2], &action, SIGACTION_BYTES).map_err(|_| CompatErrno::Fault)?;
    }
    Ok(0)
}

/// Queries or updates the current thread blocked-signal mask.
///
/// SIGKILL 和 SIGSTOP 始终保持不可阻塞；mask 是 Linux TID 私有状态。
fn linux_rt_sigprocmask(pid: ObjId, args: [u64; 6]) -> Result<u64, CompatErrno> {
    const SIG_BLOCK: u64 = 0;
    const SIG_UNBLOCK: u64 = 1;
    const SIG_SETMASK: u64 = 2;
    if args[3] != 8 || args[0] > SIG_SETMASK {
        return Err(CompatErrno::Invalid);
    }
    let old = current_signal_mask(pid).ok_or(CompatErrno::NoSys)?;
    if args[1] != 0 {
        let mut value = [0u8; 8];
        copy_from_user(&mut value, args[1], 8).map_err(|_| CompatErrno::Fault)?;
        let requested = u64::from_le_bytes(value);
        let new = match args[0] {
            SIG_BLOCK => old | requested,
            SIG_UNBLOCK => old & !requested,
            SIG_SETMASK => requested,
            _ => unreachable!(),
        };
        if !set_current_signal_mask(pid, new) {
            return Err(CompatErrno::NoSys);
        }
    }
    if args[2] != 0 {
        copy_to_user(args[2], &old.to_le_bytes(), 8).map_err(|_| CompatErrno::Fault)?;
    }
    Ok(0)
}

/// Writes the x86_64 Linux `struct stat` fields required by the loader.
///
/// 写入 144 字节、版本稳定的 x86_64 stat；时间和设备字段只表达当前虚拟快照，
/// 不伪造宿主设备身份。
fn write_linux_stat(address: u64, node: crate::linux_vfs::Node) -> Result<(), CompatErrno> {
    const STAT_BYTES: usize = 144;
    let (size, links, mode) = node.stat_metadata();
    let mut stat = [0u8; STAT_BYTES];
    stat[0..8].copy_from_slice(&1u64.to_le_bytes()); // st_dev
    stat[8..16].copy_from_slice(&node.inode().to_le_bytes()); // st_ino
    stat[16..24].copy_from_slice(&links.to_le_bytes());
    stat[24..28].copy_from_slice(&mode.to_le_bytes());
    stat[48..56].copy_from_slice(&size.to_le_bytes());
    stat[56..64].copy_from_slice(&4096i64.to_le_bytes());
    let blocks = size.div_ceil(512) as i64;
    stat[64..72].copy_from_slice(&blocks.to_le_bytes());
    copy_to_user(address, &stat, STAT_BYTES).map_err(|_| CompatErrno::Fault)
}

/// Applies Linux `brk(2)` to the process compatibility heap.
///
/// 只调整本进程兼容堆的匿名页；请求必须留在 Jasper 私有窗口和兼容堆上限内。
/// 部分映射失败会撤销本次已建立的全部页，旧 `brk` 保持不变。
fn linux_brk(pid: ObjId, requested: u64) -> Result<u64, CompatErrno> {
    const BRK_WINDOW_BYTES: u64 = 64 * 1024 * 1024;
    let current = proc::linux_brk_value(pid).ok_or(CompatErrno::NoSys)?;
    if requested == 0 {
        return Ok(current);
    }
    let floor = crate::arch::USER_WINDOW.0 + 0x1000_0000;
    let page = kernel_core::frame::FRAME_SIZE;
    if requested < floor
        || requested.checked_add(page - 1).is_none()
        || requested > floor + BRK_WINDOW_BYTES
        || requested >= crate::arch::USER_WINDOW.1
    {
        return Err(CompatErrno::NoMemory);
    }
    let old_end = align_up(current, page);
    let new_end = align_up(requested, page);
    if new_end > old_end {
        let mut mapped = alloc::vec::Vec::new();
        let mut address = old_end;
        while address < new_end {
            if proc::map_new(
                pid,
                address,
                kernel_core::paging::MapFlags::USER.union(kernel_core::paging::MapFlags::WRITE),
            )
            .is_err()
            {
                for mapped in mapped.iter().rev().copied() {
                    let _ = proc::unmap_page(pid, mapped);
                }
                return Err(CompatErrno::NoMemory);
            }
            mapped.push(address);
            address += page;
        }
    } else if new_end < old_end {
        let mut address = new_end;
        while address < old_end {
            proc::unmap_page(pid, address).map_err(|_| CompatErrno::NoMemory)?;
            address += page;
        }
    }
    if !proc::set_linux_brk(pid, requested) {
        return Err(CompatErrno::NoSys);
    }
    Ok(requested)
}

/// Implements `access(2)` over the exact verification namespace.
///
/// 已知虚拟文件返回成功，其他合法绝对路径返回 `ENOENT`；非法用户指针返回
/// `EFAULT`。不得把宿主文件系统可见性泄漏给 Linux 兼容进程。
fn linux_access(path: u64) -> Result<u64, CompatErrno> {
    let bytes = linux_c_string(path, 4096)?;
    #[cfg(feature = "compat-dynamic-libc-verify")]
    trace_path("access", &bytes);
    if crate::linux_vfs::lookup_node(&bytes).is_some() {
        Ok(0)
    } else {
        Err(CompatErrno::NoEntry)
    }
}

const fn align_up(value: u64, align: u64) -> u64 {
    (value + align - 1) & !(align - 1)
}

const fn align_down(value: u64, align: u64) -> u64 {
    value & !(align - 1)
}

/// Accepts both sign-extended and zero-extended encodings of `AT_FDCWD`.
///
/// x86_64 callers commonly load the 32-bit value `-100` into `edi`, which zero-extends
/// to `0x0000_0000_ffff_ff9c`; libc may also use the full 64-bit sign extension.
const fn is_at_fdcwd(value: u64) -> bool {
    value == (-100i64) as u64 || value == 0xffff_ff9c
}
