//! Linux x86_64 system-interface service for explicitly flavored processes.
//! JASPER-ISA-MODULE: this optional service is compiled only for x86_64.
//!
//! 职责：把已识别的 Linux syscall 映射到 Jasper fd、任务、内存和受控只读文件机制；
//! 所有调用先经过兼容进程的显式 Linux 调用集合，不能借用 Jasper 原生 SyscallSet。
//! Responsibility: execute Linux syscalls through explicit compatibility authority while
//! preserving Jasper Handle/Rights, memory ownership, bounds and resource cleanup.

use compat_core::syscall::{
    compat_result, dispatch, CompatErrno, LinuxCall, LinuxSyscall, SyscallDispatch, SyscallRequest,
    LINUX_NR_FUTEX,
};

use core::sync::atomic::{fence, AtomicU32, AtomicU64, Ordering};

use sha2::{Digest as _, Sha256};

use kernel_core::objtable::ObjId;
use kernel_core::paging::MapFlags;

use crate::mm::user::{copy_from_user, copy_to_user, copy_to_user_vectored, UserPtrError};
use crate::sync::IrqSpinLock;
use crate::syscall::{ExecReturn, SyscallArgs, SyscallOutcome, UserReturn, CONSOLE_WRITE_MAX};
use crate::{console, proc, sched};

#[cfg(any(
    feature = "compat-dynamic-libc-verify",
    feature = "workload-io-verify",
    feature = "vulkan-metal2vulkan-verify"
))]
const SYSCALL_TRACE_BUDGET: u32 = 1024;
#[cfg(any(
    feature = "compat-dynamic-libc-verify",
    feature = "workload-io-verify",
    feature = "vulkan-metal2vulkan-verify"
))]
static SYSCALL_TRACE_REMAINING: AtomicU32 = AtomicU32::new(SYSCALL_TRACE_BUDGET);
#[cfg(any(
    feature = "compat-dynamic-libc-verify",
    feature = "android-art-verify",
    feature = "vulkan-metal2vulkan-verify"
))]
static PATH_TRACE_REMAINING: AtomicU32 = AtomicU32::new(512);
#[cfg(any(
    feature = "android-art-verify",
    feature = "vulkan-metal2vulkan-verify"
))]
static ART_TLS_TRACE_REMAINING: AtomicU32 = AtomicU32::new(0);
const LINUX_PROC_MAPS_HANDLE: u64 = 0x4a53_5052_4f43_4d50;
const LINUX_PROC_STAT_HANDLE: u64 = 0x4a53_5052_4f43_5354;

const MAX_LINUX_THREADS: usize = 64;
const MAX_FUTEX_WORDS: usize = 32;
const MAX_PROCESS_SIGNAL_SETS: usize = 16;
const MAX_POSIX_TIMERS: usize = 32;
const MAX_INTERVAL_TIMER_SETS: usize = 16;
const MAX_PENDING_SIGNAL_RECORDS: usize = 256;
const MAX_SYSV_MESSAGE_QUEUES: usize = 16;
const MAX_SYSV_MESSAGES_PER_QUEUE: usize = 64;
const SYSV_MSGMAX: usize = 8192;
const SYSV_MSGMNB: usize = 16384;
const MAX_SYSV_SEM_SETS: usize = 16;
const MAX_SYSV_SEMS_PER_SET: usize = 16;
const MAX_SYSV_SEM_OPS: usize = 32;
const MAX_SYSV_SEM_WAITERS: usize = 64;
const MAX_SYSV_SEM_UNDOS: usize = 64;
const SYSV_SEMVMX: i32 = 32767;
const MAX_SYSV_SHARED_SEGMENTS: usize = 16;
const MAX_SYSV_SHARED_ATTACHMENTS: usize = 32;
const MAX_LINUX_KEYS: usize = 16;
static NEXT_LINUX_TID: AtomicU32 = AtomicU32::new(0x10_0000);
static NEXT_POSIX_TIMER_ID: AtomicU64 = AtomicU64::new(0x7000_0000_0000_0001);

#[derive(Clone, Copy)]
struct SignalOrigin {
    pid: u32,
    uid: u32,
    code: i32,
    value: u64,
}

#[derive(Clone, Copy)]
struct SignalFdRecord {
    signal: u32,
    sender_pid: u32,
    sender_uid: u32,
    code: i32,
    value: u64,
}

#[derive(Clone, Copy)]
struct QueuedSignalRecord {
    process: ObjId,
    /// Zero selects the process-directed queue; otherwise this is the target TID.
    target_tid: u32,
    sequence: u64,
    record: SignalFdRecord,
}

#[derive(Clone, Copy)]
struct LinuxThread {
    process: ObjId,
    task: crate::task::TaskId,
    tid: u32,
    /// Linux task-command name exposed by `PR_GET_NAME`.
    /// 通过 `PR_GET_NAME` 暴露的 Linux 任务命令名。
    name: [u8; 16],
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
    /// Source metadata for each coalesced standard signal.
    /// 每个已合并标准信号的来源元数据。
    signal_origins: [SignalOrigin; 64],
    /// Per-thread alternate signal stack.
    /// 当前 Linux 线程的备用信号栈。
    altstack_sp: u64,
    altstack_size: u64,
    altstack_flags: u32,
    altstack_depth: u8,
    altstack_disarm_depth: u8,
    sigsuspend_restore_mask: Option<u64>,
}

fn linux_comm_from_task_name(task_name: &str) -> [u8; 16] {
    let base = task_name.rsplit('/').next().unwrap_or(task_name);
    let mut name = [0u8; 16];
    for (slot, byte) in name.iter_mut().take(15).zip(base.bytes()) {
        *slot = byte;
    }
    name
}

#[derive(Clone, Copy)]
struct FutexWaiter {
    task: crate::task::TaskId,
    key: Option<FutexKey>,
    bitset: u32,
    active: bool,
    woken: bool,
}

impl FutexWaiter {
    const EMPTY: Self = Self {
        task: crate::task::TaskId(0),
        key: None,
        bitset: 0,
        active: false,
        woken: false,
    };
}

const MAX_FUTEX_WAITERS: usize = 16;

#[derive(Clone, Copy, PartialEq, Eq)]
enum FutexKey {
    Private { process: ObjId, address: u64 },
    Shared(u64),
}

#[derive(Clone, Copy)]
struct FutexWord {
    key: FutexKey,
    waiters: [FutexWaiter; MAX_FUTEX_WAITERS],
}

const MAX_FLOCK_LOCKS: usize = 64;

#[derive(Clone, Copy)]
struct FlockLock {
    backing: u64,
    owner: u64,
    exclusive: bool,
}

#[derive(Clone, Copy)]
struct FlockWaiter {
    task: crate::task::TaskId,
}

#[derive(Clone, Copy)]
struct ProcessSignalSet {
    process: ObjId,
    pending: u64,
    origins: [SignalOrigin; 64],
}

#[derive(Clone, Copy)]
struct PosixTimer {
    process: ObjId,
    id: u64,
    clock: u32,
    notify: u32,
    signal: u32,
    next: u64,
    interval: u64,
    overrun: u64,
    active: bool,
}

#[derive(Clone, Copy)]
struct IntervalTimer {
    process: ObjId,
    next: u64,
    interval: u64,
    active: bool,
}

struct MessageQueueName {
    name: [u8; 256],
    name_len: u8,
    queue: alloc::sync::Arc<proc::LinuxMqShared>,
    uid: u32,
    gid: u32,
    mode: u16,
}

#[derive(Clone)]
struct SysVMessage {
    id: u64,
    mtype: i64,
    bytes: alloc::vec::Vec<u8>,
    reserved: bool,
}

struct SysVMessageQueue {
    id: i32,
    key: i32,
    application: kernel_core::security::ApplicationIdentity,
    uid: u32,
    gid: u32,
    cuid: u32,
    cgid: u32,
    mode: u16,
    qbytes: usize,
    cbytes: usize,
    messages: alloc::collections::VecDeque<SysVMessage>,
    next_message_id: u64,
    send_time: i64,
    receive_time: i64,
    change_time: i64,
    last_send_pid: i32,
    last_receive_pid: i32,
}

#[derive(Clone, Copy)]
struct SysVSemaphoreSet {
    id: i32,
    key: i32,
    application: kernel_core::security::ApplicationIdentity,
    uid: u32,
    gid: u32,
    cuid: u32,
    cgid: u32,
    mode: u16,
    values: [i32; MAX_SYSV_SEMS_PER_SET],
    nsems: usize,
    operation_time: i64,
    change_time: i64,
    last_pid: i32,
    positive_waiters: [u16; MAX_SYSV_SEMS_PER_SET],
    zero_waiters: [u16; MAX_SYSV_SEMS_PER_SET],
}

#[derive(Clone, Copy)]
struct SysVSemaphoreOperation {
    number: usize,
    operation: i16,
    flags: i16,
}

#[derive(Clone, Copy)]
struct SysVSemaphoreWaiter {
    process: ObjId,
    task: crate::task::TaskId,
    semid: i32,
    semnum: usize,
    zero: bool,
}

#[derive(Clone, Copy)]
struct SysVSemaphoreUndo {
    process: ObjId,
    semid: i32,
    semnum: usize,
    adjustment: i32,
}

#[derive(Clone, Copy)]
struct SysVSharedAttachment {
    process: ObjId,
    address: u64,
    length: u64,
    writable: bool,
}

struct SysVSharedMemory {
    id: i32,
    key: i32,
    application: kernel_core::security::ApplicationIdentity,
    uid: u32,
    gid: u32,
    cuid: u32,
    cgid: u32,
    mode: u16,
    size: u64,
    object: proc::LinuxSharedMemoryObject,
    creator_pid: i32,
    last_pid: i32,
    attach_time: i64,
    detach_time: i64,
    change_time: i64,
    deleted: bool,
    attachments: alloc::vec::Vec<SysVSharedAttachment>,
}

struct LinuxKey {
    serial: i32,
    application: kernel_core::security::ApplicationIdentity,
    key_type: [u8; 16],
    type_len: u8,
    description: [u8; 64],
    description_len: u8,
    payload: alloc::vec::Vec<u8>,
    revoked: bool,
    linked: bool,
    uid: u32,
    gid: u32,
    permissions: u32,
}

#[derive(Clone, Copy)]
struct LinuxProcessKeyring {
    process: ObjId,
    serial: i32,
}

struct LinuxCacheFile {
    id: u32,
    path: alloc::vec::Vec<u8>,
    bytes: alloc::vec::Vec<u8>,
}

struct LinuxCacheDir {
    id: u32,
    path: alloc::vec::Vec<u8>,
}

struct CompatState {
    threads: [Option<LinuxThread>; MAX_LINUX_THREADS],
    thread_landlock_domains: [Option<
        alloc::vec::Vec<alloc::sync::Arc<proc::LinuxLandlockRuleset>>,
    >; MAX_LINUX_THREADS],
    futexes: [Option<FutexWord>; MAX_FUTEX_WORDS],
    process_signals: [Option<ProcessSignalSet>; MAX_PROCESS_SIGNAL_SETS],
    flock_locks: [Option<FlockLock>; MAX_FLOCK_LOCKS],
    flock_waiters: [Option<FlockWaiter>; MAX_FLOCK_LOCKS],
    posix_timers: [Option<PosixTimer>; MAX_POSIX_TIMERS],
    interval_timers: [Option<IntervalTimer>; MAX_INTERVAL_TIMER_SETS],
    message_queue_names: alloc::vec::Vec<MessageQueueName>,
    pending_signal_records: [Option<QueuedSignalRecord>; MAX_PENDING_SIGNAL_RECORDS],
    next_signal_sequence: u64,
    sysv_message_queues: alloc::vec::Vec<SysVMessageQueue>,
    next_sysv_message_queue_id: i32,
    sysv_semaphore_sets: alloc::vec::Vec<SysVSemaphoreSet>,
    sysv_semaphore_waiters: [Option<SysVSemaphoreWaiter>; MAX_SYSV_SEM_WAITERS],
    sysv_semaphore_undos: alloc::vec::Vec<SysVSemaphoreUndo>,
    next_sysv_semaphore_id: i32,
    sysv_shared_segments: alloc::vec::Vec<SysVSharedMemory>,
    next_sysv_shared_id: i32,
    keys: alloc::vec::Vec<LinuxKey>,
    process_keyrings: alloc::vec::Vec<LinuxProcessKeyring>,
    next_key_serial: i32,
    cache_files: alloc::vec::Vec<LinuxCacheFile>,
    cache_dirs: alloc::vec::Vec<LinuxCacheDir>,
    next_cache_node_id: u32,
}

impl CompatState {
    const fn new() -> Self {
        Self {
            threads: [None; MAX_LINUX_THREADS],
            thread_landlock_domains: [const { None }; MAX_LINUX_THREADS],
            futexes: [None; MAX_FUTEX_WORDS],
            process_signals: [None; MAX_PROCESS_SIGNAL_SETS],
            flock_locks: [None; MAX_FLOCK_LOCKS],
            flock_waiters: [None; MAX_FLOCK_LOCKS],
            posix_timers: [None; MAX_POSIX_TIMERS],
            interval_timers: [None; MAX_INTERVAL_TIMER_SETS],
            message_queue_names: alloc::vec::Vec::new(),
            pending_signal_records: [None; MAX_PENDING_SIGNAL_RECORDS],
            next_signal_sequence: 0,
            sysv_message_queues: alloc::vec::Vec::new(),
            next_sysv_message_queue_id: 1,
            sysv_semaphore_sets: alloc::vec::Vec::new(),
            sysv_semaphore_waiters: [None; MAX_SYSV_SEM_WAITERS],
            sysv_semaphore_undos: alloc::vec::Vec::new(),
            next_sysv_semaphore_id: 1,
            sysv_shared_segments: alloc::vec::Vec::new(),
            next_sysv_shared_id: 1,
            keys: alloc::vec::Vec::new(),
            process_keyrings: alloc::vec::Vec::new(),
            next_key_serial: 1,
            cache_files: alloc::vec::Vec::new(),
            cache_dirs: alloc::vec::Vec::new(),
            next_cache_node_id: 1,
        }
    }
}

static COMPAT: IrqSpinLock<CompatState> =
    IrqSpinLock::ranked(crate::lockorder::LINUX_COMPAT, CompatState::new());

const LINUX_CACHE_ROOT: &[u8] = b"/data/.cache/metal2vulkan";
const LINUX_CACHE_FILE_HANDLE_BASE: u64 = 0x4a53_4346_0000_0000;
const LINUX_CACHE_DIR_HANDLE_BASE: u64 = 0x4a53_4344_0000_0000;

#[cfg(any(
    feature = "compat-dynamic-libc-verify",
    feature = "workload-io-verify",
    feature = "vulkan-metal2vulkan-verify"
))]
fn trace_request(args: &SyscallArgs) {
    let remaining = SYSCALL_TRACE_REMAINING.load(Ordering::Relaxed);
    if remaining == 0 {
        return;
    }
    let index = SYSCALL_TRACE_BUDGET - remaining;
    let process = proc::current_process();
    let tid = process.and_then(current_linux_tid).unwrap_or(0);
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
            "[JSR-LINUX-SYSCALL] index={} tid={} ip={:#x} nr={} a0={:#x} a1={:#x} a2={:#x} a3={:#x} a4={:#x} a5={:#x}",
            index,
            tid,
            args.user_ip.map_or(0, |ip| ip.0),
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

#[cfg(any(
    feature = "compat-dynamic-libc-verify",
    feature = "android-art-verify",
    feature = "vulkan-metal2vulkan-verify"
))]
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

#[cfg(any(
    feature = "compat-dynamic-libc-verify",
    feature = "android-art-verify",
    feature = "vulkan-metal2vulkan-verify"
))]
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

#[cfg(feature = "vulkan-metal2vulkan-verify")]
pub(crate) fn reset_vulkan_trace_budget() {
    SYSCALL_TRACE_REMAINING.store(0, Ordering::Relaxed);
    PATH_TRACE_REMAINING.store(0, Ordering::Relaxed);
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
    let (current_task, current_name) = sched::current();
    {
        let mut state = COMPAT.lock();
        let has_leader = state
            .threads
            .iter()
            .flatten()
            .any(|entry| entry.process == process);
        let inherits_current = |entry: &LinuxThread| {
            entry.task == current_task && (entry.process == process || !has_leader)
        };
        let inherited_slot = state.threads.iter().position(|entry| {
            entry.as_ref().is_some_and(inherits_current)
        });
        let inherited = inherited_slot.and_then(|slot| state.threads[slot]);
        let inherited_mask = inherited.map(|entry| entry.signal_mask).unwrap_or(0);
        let inherited_name = inherited
            .map(|entry| entry.name)
            .unwrap_or_else(|| linux_comm_from_task_name(current_name));
        let inherited_domains = inherited_slot
            .and_then(|slot| state.thread_landlock_domains[slot].clone())
            .unwrap_or_default();
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
            name: inherited_name,
            clear_child_tid,
            robust_list: 0,
            robust_list_len: 0,
            rseq: 0,
            rseq_len: 0,
            signal_mask: inherited_mask,
            pending_signals: 0,
            signal_origins: [SignalOrigin {
                pid: 0,
                uid: 0,
                code: 0,
                value: 0,
            }; 64],
            altstack_sp: 0,
            altstack_size: 0,
            altstack_flags: 2,
            altstack_depth: 0,
            altstack_disarm_depth: 0,
            sigsuspend_restore_mask: None,
        });
        state.thread_landlock_domains[slot] = Some(inherited_domains);
        tid
    };
    // CLONE_CHILD_CLEARTID only names the word the kernel clears at thread exit. A
    // CLONE_CHILD_SETTID request is written separately by the clone caller after setup.
    // Writing the TID here would overwrite glibc's joinstate and turn detach into join.
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
        state.thread_landlock_domains[slot] = None;
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

pub(crate) fn current_linux_tid(process: ObjId) -> Option<u32> {
    linux_tid(process)
}

fn linux_process_for_tid(tid: u32) -> Option<ObjId> {
    COMPAT
        .lock()
        .threads
        .iter()
        .flatten()
        .find(|entry| entry.tid == tid)
        .map(|entry| entry.process)
}

fn linux_tid_owned_by_process(process: ObjId, tid: u64) -> bool {
    u32::try_from(tid).is_ok_and(|tid| {
        COMPAT
            .lock()
            .threads
            .iter()
            .flatten()
            .any(|entry| entry.process == process && entry.tid == tid)
    })
}

/// Returns the full security application identity, falling back to the
/// process's native application projection when older metadata is unavailable.
fn linux_application_identity(pid: ObjId) -> Option<kernel_core::security::ApplicationIdentity> {
    crate::security::process_application(pid).or_else(|| {
        proc::app(pid).map(|id| kernel_core::security::ApplicationIdentity::migrated(u64::from(id)))
    })
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

/// Appends one realtime signal record in bounded FIFO order.
fn enqueue_signal_record(
    state: &mut CompatState,
    process: ObjId,
    target_tid: u32,
    record: SignalFdRecord,
) -> bool {
    let Some(slot) = state
        .pending_signal_records
        .iter()
        .position(Option::is_none)
    else {
        return false;
    };
    let sequence = state.next_signal_sequence;
    state.next_signal_sequence = sequence.wrapping_add(1);
    state.pending_signal_records[slot] = Some(QueuedSignalRecord {
        process,
        target_tid,
        sequence,
        record,
    });
    true
}

/// Removes the oldest queued record for one process/thread and signal.
fn take_queued_signal_record(
    state: &mut CompatState,
    process: ObjId,
    target_tid: u32,
    signal: u32,
) -> Option<SignalFdRecord> {
    let slot = state
        .pending_signal_records
        .iter()
        .enumerate()
        .filter(|(_, entry)| {
            entry.is_some_and(|entry| {
                entry.process == process
                    && entry.target_tid == target_tid
                    && entry.record.signal == signal
            })
        })
        .min_by_key(|(_, entry)| entry.map(|entry| entry.sequence).unwrap_or(u64::MAX))
        .map(|(slot, _)| slot)?;
    let record = state.pending_signal_records[slot].take()?.record;
    let still_pending = state.pending_signal_records.iter().any(|entry| {
        entry.is_some_and(|entry| {
            entry.process == process
                && entry.target_tid == target_tid
                && entry.record.signal == signal
        })
    });
    if !still_pending {
        let bit = 1u64 << (signal - 1);
        if target_tid == 0 {
            if let Some(entry) = state
                .process_signals
                .iter_mut()
                .flatten()
                .find(|entry| entry.process == process)
            {
                entry.pending &= !bit;
            }
        } else if let Some(entry) = state.threads.iter_mut().flatten().find(|entry| {
            entry.process == process && entry.tid == target_tid
        }) {
            entry.pending_signals &= !bit;
        }
    }
    Some(record)
}

/// Queues one standard signal on a target Linux thread in the same process.
/// 在同一进程的目标 Linux 线程上登记一个标准信号。
fn queue_thread_signal(
    process: ObjId,
    tid: u32,
    signal: u32,
    sender_pid: u32,
    code: i32,
) -> bool {
    queue_thread_signal_info(
        process,
        tid,
        signal,
        sender_pid,
        if code == 128 {
            0
        } else {
            compat_core::syscall::LINUX_COMPAT_UID as u32
        },
        code,
        0,
    )
}

/// Queues one thread-directed signal with complete bounded siginfo metadata.
fn queue_thread_signal_info(
    process: ObjId,
    tid: u32,
    signal: u32,
    sender_pid: u32,
    sender_uid: u32,
    code: i32,
    value: u64,
) -> bool {
    if !(1..=64).contains(&signal) {
        return false;
    }
    let target = {
        let mut state = COMPAT.lock();
        let Some(target) = state
            .threads
            .iter()
            .flatten()
            .find(|entry| entry.process == process && entry.tid == tid)
            .map(|entry| entry.task)
        else {
            return false;
        };
        let record = SignalFdRecord {
            signal,
            sender_pid,
            sender_uid,
            code,
            value,
        };
        if signal >= 32 && !enqueue_signal_record(&mut state, process, tid, record) {
            return false;
        }
        let Some(entry) = state
            .threads
            .iter_mut()
            .flatten()
            .find(|entry| entry.process == process && entry.tid == tid)
        else {
            return false;
        };
        entry.pending_signals |= 1u64 << (signal - 1);
        entry.signal_origins[signal as usize - 1] = SignalOrigin {
            pid: sender_pid,
            uid: sender_uid,
            code,
            value,
        };
        crate::kprintln!(
            "[JSR-LINUX-SIGNAL] queued target_tid={} signal={} mask={:#x} pending={:#x}",
            tid,
            signal,
            entry.signal_mask,
            entry.pending_signals
        );
        target
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
fn queue_process_signal(process: ObjId, signal: u32, sender_pid: u32, code: i32) -> bool {
    queue_process_signal_info(
        process,
        signal,
        sender_pid,
        if code == 128 {
            0
        } else {
            compat_core::syscall::LINUX_COMPAT_UID as u32
        },
        code,
        0,
    )
}

/// Queues one process-directed signal with complete bounded siginfo metadata.
fn queue_process_signal_info(
    process: ObjId,
    signal: u32,
    sender_pid: u32,
    sender_uid: u32,
    code: i32,
    value: u64,
) -> bool {
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
                origins: [SignalOrigin {
                    pid: 0,
                    uid: 0,
                    code: 0,
                    value: 0,
                }; 64],
            });
            slot
        };
        let record = SignalFdRecord {
            signal,
            sender_pid,
            sender_uid,
            code,
            value,
        };
        if signal >= 32 && !enqueue_signal_record(&mut state, process, 0, record) {
            return false;
        }
        let Some(entry) = state.process_signals[slot].as_mut() else {
            return false;
        };
        entry.pending |= 1u64 << (signal - 1);
        entry.origins[signal as usize - 1] = SignalOrigin {
            pid: sender_pid,
            uid: sender_uid,
            code,
            value,
        };
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

/// Delivers one configured parent-death signal to a surviving child.
#[cfg(all(feature = "linux-abi", target_arch = "x86_64"))]
pub(crate) fn notify_parent_death(process: ObjId, signal: u32) {
    if (1..=64).contains(&signal) {
        let _ = queue_process_signal(process, signal, 0, LINUX_SI_KERNEL);
    }
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
    state.pending_signal_records.iter_mut().for_each(|entry| {
        if entry.is_some_and(|entry| entry.process == process) {
            *entry = None;
        }
    });
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

/// Temporarily replaces the current thread mask for `ppoll`/`pselect6`.
///
/// The guard restores the previous mask on every return path, including EINTR.
/// Signal delivery happens after the compatibility syscall returns, so the
/// restored mask is the one captured in the Linux signal frame.
struct TemporarySignalMask {
    process: ObjId,
    previous: u64,
    restore_on_drop: bool,
}

impl Drop for TemporarySignalMask {
    fn drop(&mut self) {
        if self.restore_on_drop {
            let _ = set_current_signal_mask(self.process, self.previous);
        }
    }
}

impl TemporarySignalMask {
    /// Keep the temporary mask active until the delivered handler returns.
    fn defer_restore_to_signal_frame(&mut self) -> bool {
        if !set_current_sigsuspend_restore_mask(self.process, Some(self.previous)) {
            return false;
        }
        self.restore_on_drop = false;
        true
    }
}

fn temporary_signal_mask(
    process: ObjId,
    address: u64,
    size: u64,
) -> Result<Option<TemporarySignalMask>, CompatErrno> {
    if address == 0 {
        return Ok(None);
    }
    let requested = read_linux_sigset(address, size)?;
    let previous = current_signal_mask(process).ok_or(CompatErrno::NoSys)?;
    if !set_current_signal_mask(process, requested) {
        return Err(CompatErrno::NoSys);
    }
    Ok(Some(TemporarySignalMask {
        process,
        previous,
        restore_on_drop: true,
    }))
}

/// Stores the mask `rt_sigsuspend` must restore after its signal handler returns.
fn set_current_sigsuspend_restore_mask(process: ObjId, mask: Option<u64>) -> bool {
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
    entry.sigsuspend_restore_mask = mask;
    true
}

/// Takes the pending `rt_sigsuspend` restore mask for signal-frame construction.
fn take_current_sigsuspend_restore_mask(process: ObjId) -> Option<u64> {
    let (task, _) = sched::current();
    COMPAT
        .lock()
        .threads
        .iter_mut()
        .flatten()
        .find(|entry| entry.process == process && entry.task == task)
        .and_then(|entry| entry.sigsuspend_restore_mask.take())
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

/// Atomically restores the signal mask and leaves one alternate-stack frame.
///
/// Every fallible state transition is validated while holding the same lock;
/// a malformed `rt_sigreturn` frame therefore cannot publish a partial signal
/// mask or altstack-depth change.
/// 原子恢复信号 mask，并在同一次事务中离开备用栈信号帧。
fn commit_rt_sigreturn(
    process: ObjId,
    mask: u64,
    leave_altstack: bool,
    autodisarm: bool,
) -> bool {
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
    let next_depth = if leave_altstack {
        let Some(next) = entry.altstack_depth.checked_sub(1) else {
            return false;
        };
        next
    } else {
        entry.altstack_depth
    };
    let next_disarm = if leave_altstack && autodisarm {
        let Some(armed) = entry.altstack_disarm_depth.checked_sub(1) else {
            return false;
        };
        armed
    } else {
        entry.altstack_disarm_depth
    };

    entry.signal_mask = mask & !UNMASKABLE;
    entry.altstack_depth = next_depth;
    entry.altstack_disarm_depth = next_disarm;
    if leave_altstack {
        crate::kprintln!(
            "[JSR-LINUX-ALTSTACK] leave depth={} autodisarm={}",
            next_depth,
            autodisarm
        );
    }
    true
}

/// Takes the lowest unmasked pending signal and its siginfo metadata.
/// 取出当前线程编号最低且未被屏蔽的 pending 信号及其 siginfo 元数据。
fn take_deliverable_signal(process: ObjId) -> Option<SignalFdRecord> {
    let (task, _) = sched::current();
    let mut state = COMPAT.lock();
    let record = (|| {
        let (blocked, thread_deliverable, thread_tid) = {
            let entry = state
                .threads
                .iter()
                .flatten()
                .find(|entry| entry.process == process && entry.task == task)?;
            (
                entry.signal_mask,
                entry.pending_signals & !entry.signal_mask,
                entry.tid,
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
        let signal = index + 1;
        if signal >= 32 {
            let target_tid = if process_directed { 0 } else { thread_tid };
            if let Some(record) =
                take_queued_signal_record(&mut state, process, target_tid, signal)
            {
                return Some(record);
            }
        }
        if process_directed {
            let entry = state
                .process_signals
                .iter_mut()
                .flatten()
                .find(|entry| entry.process == process)?;
            entry.pending &= !bit;
            let origin = entry.origins[index as usize];
            Some(SignalFdRecord {
                signal,
                sender_pid: origin.pid,
                sender_uid: origin.uid,
                code: origin.code,
                value: origin.value,
            })
        } else {
            let entry = state
                .threads
                .iter_mut()
                .flatten()
                .find(|entry| entry.process == process && entry.task == task)?;
            entry.pending_signals &= !bit;
            let origin = entry.signal_origins[index as usize];
            Some(SignalFdRecord {
                signal,
                sender_pid: origin.pid,
                sender_uid: origin.uid,
                code: origin.code,
                value: origin.value,
            })
        }
    })();
    drop(state);
    record
}

fn signalfd_pending_mask(process: ObjId, requested: u64) -> u64 {
    let (task, _) = sched::current();
    let state = COMPAT.lock();
    let thread = state
        .threads
        .iter()
        .flatten()
        .find(|entry| entry.process == process && entry.task == task)
        .map(|entry| entry.pending_signals)
        .unwrap_or(0);
    let shared = state
        .process_signals
        .iter()
        .flatten()
        .find(|entry| entry.process == process)
        .map(|entry| entry.pending)
        .unwrap_or(0);
    (thread | shared) & requested
}

fn take_signalfd_record(process: ObjId, requested: u64) -> Option<SignalFdRecord> {
    let (task, _) = sched::current();
    let mut state = COMPAT.lock();
    let thread_index = state
        .threads
        .iter()
        .position(|entry| {
            entry.is_some_and(|entry| entry.process == process && entry.task == task)
        })?;
    let process_index = state
        .process_signals
        .iter()
        .position(|entry| entry.is_some_and(|entry| entry.process == process));
    let thread = state.threads[thread_index]?;
    let process_pending = process_index
        .and_then(|index| state.process_signals[index])
        .map(|entry| entry.pending)
        .unwrap_or(0);
    let available = (thread.pending_signals | process_pending) & requested;
    if available == 0 {
        return None;
    }
    let signal = available.trailing_zeros() + 1;
    let bit = 1u64 << (signal - 1);
    let thread_directed = thread.pending_signals & bit != 0;
    if signal >= 32 {
        let target_tid = if thread_directed { thread.tid } else { 0 };
        if let Some(record) = take_queued_signal_record(&mut state, process, target_tid, signal) {
            return Some(record);
        }
    }
    if thread_directed {
        let entry = state.threads[thread_index].as_mut()?;
        entry.pending_signals &= !bit;
        let origin = entry.signal_origins[signal as usize - 1];
        Some(SignalFdRecord {
            signal,
            sender_pid: origin.pid,
            sender_uid: origin.uid,
            code: origin.code,
            value: origin.value,
        })
    } else {
        let entry = process_index.and_then(|index| state.process_signals[index].as_mut())?;
        entry.pending &= !bit;
        let origin = entry.origins[signal as usize - 1];
        Some(SignalFdRecord {
            signal,
            sender_pid: origin.pid,
            sender_uid: origin.uid,
            code: origin.code,
            value: origin.value,
        })
    }
}

/// Reports whether the current thread has an unmasked pending signal.
/// 判断当前线程是否存在未被 mask 的 pending 信号。
pub(crate) fn current_signal_pending(process: ObjId) -> bool {
    pending_signal_mask(process) != 0
}

pub(crate) fn pending_signal_mask(process: ObjId) -> u64 {
    let (task, _) = sched::current();
    let state = COMPAT.lock();
    let Some(thread) = state
        .threads
        .iter()
        .flatten()
        .find(|entry| entry.process == process && entry.task == task)
    else {
        return 0;
    };
    let shared = state
        .process_signals
        .iter()
        .flatten()
        .find(|entry| entry.process == process)
        .map(|entry| entry.pending)
        .unwrap_or(0);
    (thread.pending_signals | shared) & !thread.signal_mask
}

fn blocked_pending_signal_mask(process: ObjId) -> u64 {
    let (task, _) = sched::current();
    let state = COMPAT.lock();
    let Some(thread) = state
        .threads
        .iter()
        .flatten()
        .find(|entry| entry.process == process && entry.task == task)
    else {
        return 0;
    };
    let shared = state
        .process_signals
        .iter()
        .flatten()
        .find(|entry| entry.process == process)
        .map(|entry| entry.pending)
        .unwrap_or(0);
    (thread.pending_signals | shared) & thread.signal_mask
}

const SIGNAL_UC_OFFSET: usize = 8;
const SIGNAL_UC_GREGS: usize = 40;
const SIGNAL_UC_SIGMASK: usize = 296;
const SIGNAL_UC_FPREGS: usize = 224;
const SIGNAL_INFO_OFFSET: usize = SIGNAL_UC_OFFSET + 968;
const SIGNAL_FPSTATE_OFFSET: usize = SIGNAL_INFO_OFFSET + 128;
const JASPER_UC_FLAG_ALTSTACK: u64 = 1u64 << 63;
const JASPER_UC_FLAG_ALTSTACK_AUTODISARM: u64 = 1u64 << 62;

fn signal_frame_bytes() -> usize {
    SIGNAL_FPSTATE_OFFSET + crate::arch::x86_64::xstate::save_size()
}

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
    let state_bytes = crate::arch::x86_64::xstate::save_size();
    let Some(destination) =
        frame.get_mut(SIGNAL_FPSTATE_OFFSET..SIGNAL_FPSTATE_OFFSET.saturating_add(state_bytes))
    else {
        return false;
    };
    // SAFETY: the x86_64 syscall entry owns this aligned XSAVE image for the
    // duration of dispatch; the frame destination is a separate fixed buffer.
    destination.copy_from_slice(unsafe { core::slice::from_raw_parts(source, state_bytes) });
    true
}

/// Builds the bounded Linux x86_64 signal frame on the interrupted user stack.
/// 在被打断的用户栈上构造有界 Linux x86_64 信号帧。
fn build_signal_frame(
    process: ObjId,
    record: SignalFdRecord,
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
    let signal = record.signal;
    let action = proc::linux_signal_action(process, signal).ok_or(CompatErrno::Invalid)?;
    let handler = action[0];
    if handler == SIG_IGN {
        return Err(CompatErrno::Interrupted);
    }
    if handler == SIG_DFL {
        let _ = proc::set_linux_termination_signal(process, signal);
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
    let current_mask = current_signal_mask(process).ok_or(CompatErrno::Invalid)?;
    let old_mask = take_current_sigsuspend_restore_mask(process).unwrap_or(current_mask);
    let altstack = if action[1] & SA_ONSTACK != 0 {
        current_altstack(process).ok_or(CompatErrno::Invalid)?
    } else {
        (0, 0, SS_DISABLE, 0, 0)
    };
    let uses_altstack = action[1] & SA_ONSTACK != 0
        && altstack.2 & SS_DISABLE == 0
        && altstack.4 == 0
        && altstack.1 >= signal_frame_bytes() as u64
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
        .checked_sub(red_zone + signal_frame_bytes() as u64)
        .map(|value| value & !0xf)
        .filter(|value| {
            *value >= crate::arch::USER_WINDOW.0
                && value
                    .checked_add(signal_frame_bytes() as u64)
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
    let mut frame = alloc::vec![0u8; signal_frame_bytes()];
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
    write_frame_u64(&mut frame, SIGNAL_INFO_OFFSET, u64::from(record.signal));
    write_frame_u64(
        &mut frame,
        SIGNAL_INFO_OFFSET + 8,
        u64::from(record.code as u32),
    );
    write_frame_u64(
        &mut frame,
        SIGNAL_INFO_OFFSET + 16,
        u64::from(record.sender_pid) | (u64::from(record.sender_uid) << 32),
    );
    write_frame_u64(&mut frame, SIGNAL_INFO_OFFSET + 24, record.value);
    let nodefer = action[1] & (SA_NODEFER | SA_RESETHAND) != 0;
    let reset_hand = action[1] & SA_RESETHAND != 0;
    let handler_mask = if nodefer {
        current_mask | action[3]
    } else {
        current_mask | action[3] | (1u64 << (signal - 1))
    };
    if !set_current_signal_mask(process, handler_mask) {
        return Err(CompatErrno::Invalid);
    }
    if reset_hand && !proc::set_linux_signal_action(process, signal, [0; 4]) {
        let _ = set_current_signal_mask(process, current_mask);
        return Err(CompatErrno::Invalid);
    }
    if proc::write(process, frame_address, &frame).is_err() {
        let _ = set_current_signal_mask(process, current_mask);
        return Err(CompatErrno::Fault);
    }
    if uses_altstack && !enter_altstack(process, autodisarm) {
        let _ = set_current_signal_mask(process, current_mask);
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
    let record = match take_deliverable_signal(process) {
        Some(record) => record,
        None => return None,
    };
    let signal = record.signal;
    let action = proc::linux_signal_action(process, signal)?;
    if action[0] == 1 {
        if let Some(mask) = take_current_sigsuspend_restore_mask(process) {
            let _ = set_current_signal_mask(process, mask);
        }
        crate::kprintln!("[JSR-LINUX-SIGNAL] ignored signal={}", signal);
        return None;
    }
    let user_ip = user_ip?;
    match build_signal_frame(process, record, args, user_ip, interrupted_result) {
        Ok(user) => Some(user),
        Err(error) => {
            crate::kprintln!(
                "[JSR-LINUX-SIGNAL] complete=false signal={} error={}",
                signal,
                error as i32
            );
            let _ = proc::set_linux_termination_signal(process, signal);
            let _ = proc::begin_exit(process, 128 + i64::from(signal));
            None
        }
    }
}

/// Reads the bounded x86-64 siginfo layout used by the sigqueue syscalls.
fn read_linux_queued_siginfo(signal: u32, address: u64) -> Result<SignalOrigin, CompatErrno> {
    let mut info = [0u8; 128];
    copy_from_user(&mut info, address, 128).map_err(|_| CompatErrno::Fault)?;
    if !(1..=64).contains(&signal) {
        return Err(CompatErrno::Invalid);
    }
    if u32::from_le_bytes(info[..4].try_into().unwrap()) != signal {
        return Err(CompatErrno::Invalid);
    }
    Ok(SignalOrigin {
        pid: u32::from_le_bytes(info[16..20].try_into().unwrap()),
        uid: u32::from_le_bytes(info[20..24].try_into().unwrap()),
        code: i32::from_le_bytes(info[8..12].try_into().unwrap()),
        value: u64::from_le_bytes(info[24..32].try_into().unwrap()),
    })
}

/// Rejects forged SI_USER/SI_TKILL metadata from a different task.
fn check_linux_sigqueue_source(
    process: ObjId,
    target_tid: u32,
    code: i32,
) -> Result<(), CompatErrno> {
    const SI_TKILL: i32 = -6;
    let sender_tid = linux_tid(process).ok_or(CompatErrno::NoSys)?;
    if (code >= 0 || code == SI_TKILL) && sender_tid != target_tid {
        return Err(CompatErrno::Perm);
    }
    Ok(())
}

/// Implements process-directed `rt_sigqueueinfo(2)`.
fn linux_rt_sigqueueinfo(process: ObjId, args: [u64; 6]) -> Result<(), CompatErrno> {
    const SIGSTOP: u32 = 19;
    let pid = u32::try_from(args[0]).map_err(|_| CompatErrno::Invalid)?;
    let signal = u32::try_from(args[1]).map_err(|_| CompatErrno::Invalid)?;
    let info = read_linux_queued_siginfo(signal, args[2])?;
    if pid == 0 {
        return Err(CompatErrno::NoProcess);
    }
    if signal == SIGSTOP {
        return Err(CompatErrno::NotSupported);
    }
    let target = proc::linux_process_for_pid(pid).ok_or(CompatErrno::NoProcess)?;
    check_linux_sigqueue_source(process, pid, info.code)?;
    if queue_process_signal_info(target, signal, info.pid, info.uid, info.code, info.value) {
        Ok(())
    } else {
        Err(CompatErrno::TryAgain)
    }
}

/// Implements thread-directed `rt_tgsigqueueinfo(2)`.
fn linux_rt_tgsigqueueinfo(process: ObjId, args: [u64; 6]) -> Result<(), CompatErrno> {
    const SIGSTOP: u32 = 19;
    let tgid = u32::try_from(args[0]).map_err(|_| CompatErrno::Invalid)?;
    let tid = u32::try_from(args[1]).map_err(|_| CompatErrno::Invalid)?;
    let signal = u32::try_from(args[2]).map_err(|_| CompatErrno::Invalid)?;
    let info = read_linux_queued_siginfo(signal, args[3])?;
    if tgid == 0 || tid == 0 {
        return Err(CompatErrno::Invalid);
    }
    if signal == SIGSTOP {
        return Err(CompatErrno::NotSupported);
    }
    let target = proc::linux_process_for_pid(tgid).ok_or(CompatErrno::NoProcess)?;
    if !has_linux_thread(target, tid) {
        return Err(CompatErrno::NoProcess);
    }
    check_linux_sigqueue_source(process, tid, info.code)?;
    if queue_thread_signal_info(target, tid, signal, info.pid, info.uid, info.code, info.value) {
        Ok(())
    } else {
        Err(CompatErrno::TryAgain)
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
    if signal == 19 {
        return Err(CompatErrno::NotSupported);
    }
    if queue_thread_signal(process, tid, signal, tgid, -6) {
        Ok(())
    } else {
        Err(CompatErrno::NoProcess)
    }
}

/// Queues a thread-directed `tkill` in the current compatibility process.
fn linux_tkill(process: ObjId, args: [u64; 6]) -> Result<(), CompatErrno> {
    let tgid = proc::linux_pid(process).ok_or(CompatErrno::NoProcess)?;
    linux_tgkill(process, [u64::from(tgid), args[0], args[1], 0, 0, 0])
}

/// Resolves either a process leader PID or a Linux thread TID.
fn linux_task_process(task_id: u32) -> Option<ObjId> {
    if let Some(process) = COMPAT
        .lock()
        .threads
        .iter()
        .flatten()
        .find(|entry| entry.tid == task_id)
        .map(|entry| entry.process)
    {
        return Some(process);
    }
    proc::linux_process_for_pid(task_id)
}

/// Returns Linux's stable equality/ordering result for two object identities.
fn kcmp_identity_order(first: u64, second: u64) -> u64 {
    if first == second {
        0
    } else if first < second {
        1
    } else {
        2
    }
}

/// Compares compatibility process resources using the same-application boundary.
fn linux_kcmp(process: ObjId, args: [u64; 6]) -> Result<u64, CompatErrno> {
    const KCMP_FILE: u32 = 0;
    const KCMP_VM: u32 = 1;
    const KCMP_FILES: u32 = 3;
    const KCMP_FS: u32 = 2;
    const KCMP_SIGHAND: u32 = 4;
    const KCMP_IO: u32 = 5;
    const KCMP_SYSVSEM: u32 = 6;
    const KCMP_EPOLL_TFD: u32 = 7;
    let pid1 = u32::try_from(args[0]).map_err(|_| CompatErrno::Invalid)?;
    let pid2 = u32::try_from(args[1]).map_err(|_| CompatErrno::Invalid)?;
    let kind = u32::try_from(args[2]).map_err(|_| CompatErrno::Invalid)?;
    let first = linux_task_process(pid1).ok_or(CompatErrno::NoProcess)?;
    let second = linux_task_process(pid2).ok_or(CompatErrno::NoProcess)?;
    let caller_app = proc::app(process).ok_or(CompatErrno::Perm)?;
    let first_app = proc::app(first).ok_or(CompatErrno::Perm)?;
    let second_app = proc::app(second).ok_or(CompatErrno::Perm)?;
    if caller_app != first_app || caller_app != second_app {
        return Err(CompatErrno::Perm);
    }
    match kind {
        KCMP_FILE => {
            let first_fd = u32::try_from(args[3]).map_err(|_| CompatErrno::BadFd)?;
            let second_fd = u32::try_from(args[4]).map_err(|_| CompatErrno::BadFd)?;
            let first_id =
                proc::linux_fd_description_identity(first, first_fd).ok_or(CompatErrno::BadFd)?;
            let second_id =
                proc::linux_fd_description_identity(second, second_fd).ok_or(CompatErrno::BadFd)?;
            Ok(kcmp_identity_order(first_id, second_id))
        }
        KCMP_VM
        | KCMP_FS
        | KCMP_FILES
        | KCMP_SIGHAND
        | KCMP_IO
        | KCMP_SYSVSEM => Ok(
            kcmp_identity_order(first.raw(), second.raw()),
        ),
        KCMP_EPOLL_TFD => {
            let first_fd = u32::try_from(args[3]).map_err(|_| CompatErrno::BadFd)?;
            let first_id =
                proc::linux_fd_description_identity(first, first_fd).ok_or(CompatErrno::BadFd)?;
            let mut slot = [0u8; 12];
            copy_from_user(&mut slot, args[4], 12).map_err(|_| CompatErrno::Fault)?;
            let epoll_fd = u32::from_le_bytes(slot[0..4].try_into().unwrap());
            let target_fd = u32::from_le_bytes(slot[4..8].try_into().unwrap());
            let target_offset = u32::from_le_bytes(slot[8..12].try_into().unwrap());
            let second_id = proc::linux_epoll_registration_identity(
                second,
                epoll_fd,
                target_fd,
                target_offset,
            )
            .ok_or(CompatErrno::BadFd)?;
            Ok(kcmp_identity_order(first_id, second_id))
        }
        _ => Err(CompatErrno::Invalid),
    }
}

/// Queues a process-directed `kill` for a live compatibility process.
/// 为存活的兼容进程登记一个进程定向 `kill`。
fn linux_kill(process: ObjId, args: [u64; 6]) -> Result<(), CompatErrno> {
    let pid = u32::try_from(args[0]).map_err(|_| CompatErrno::Invalid)?;
    let signal = u32::try_from(args[1]).map_err(|_| CompatErrno::Invalid)?;
    if pid == 0 {
        return Err(CompatErrno::NoProcess);
    }
    let target = proc::linux_process_for_pid(pid).ok_or(CompatErrno::NoProcess)?;
    if signal == 0 {
        return Ok(());
    }
    if signal > 64 {
        return Err(CompatErrno::Invalid);
    }
    if signal == 19 {
        return Err(CompatErrno::NotSupported);
    }
    let sender_pid = proc::linux_pid(process).ok_or(CompatErrno::NoProcess)?;
    if queue_process_signal(target, signal, sender_pid, 0) {
        Ok(())
    } else {
        Err(CompatErrno::TryAgain)
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
    let fpstate_address = u64::from_le_bytes(
        context[SIGNAL_UC_FPREGS..SIGNAL_UC_FPREGS + 8]
            .try_into()
            .expect("fixed fpregs field"),
    );
    if fpstate_address < crate::arch::USER_WINDOW.0
        || fpstate_address
            .checked_add(crate::arch::x86_64::xstate::save_size() as u64)
            .is_none_or(|end| end > crate::arch::USER_WINDOW.1)
    {
        return Err(CompatErrno::Fault);
    }
    let state_bytes = crate::arch::x86_64::xstate::save_size();
    let mut fxstate = alloc::vec![0u8; state_bytes];
    proc::read(process, fpstate_address, &mut fxstate).map_err(|_| CompatErrno::Fault)?;
    let state_mask = crate::arch::x86_64::xstate::mask();
    let state_valid = if state_mask == 0 {
        kernel_core::xsave::validate_legacy_fxsave(&fxstate).is_ok()
    } else {
        kernel_core::xsave::validate_standard_image(&fxstate, state_mask).is_ok()
    };
    if !state_valid {
        return Err(CompatErrno::Invalid);
    }
    let Some(destination) = args.fxstate else {
        return Err(CompatErrno::Fault);
    };
    let leave_altstack =
        uc_flags & JASPER_UC_FLAG_ALTSTACK != 0;
    let autodisarm =
        uc_flags & JASPER_UC_FLAG_ALTSTACK_AUTODISARM != 0;
    if !commit_rt_sigreturn(process, old_mask, leave_altstack, autodisarm) {
        return Err(CompatErrno::Invalid);
    }
    // SAFETY: the syscall entry owns this aligned FP state buffer until return;
    // rt_sigreturn can replace it with the validated userspace signal state.
    unsafe {
        core::ptr::copy_nonoverlapping(fxstate.as_ptr(), destination, state_bytes);
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

/// Reads one same-process Linux thread's robust-list head and length.
fn linux_get_robust_list(pid: ObjId, args: [u64; 6]) -> Result<u64, CompatErrno> {
    let requested = u32::try_from(args[0]).map_err(|_| CompatErrno::Invalid)?;
    let current = linux_tid(pid).ok_or(CompatErrno::NoProcess)?;
    let tid = if requested == 0 { current } else { requested };
    let (head, length) = COMPAT
        .lock()
        .threads
        .iter()
        .flatten()
        .find(|entry| entry.process == pid && entry.tid == tid)
        .map(|entry| (entry.robust_list, entry.robust_list_len))
        .ok_or(CompatErrno::NoProcess)?;
    copy_to_user(args[1], &head.to_le_bytes(), 8).map_err(|_| CompatErrno::Fault)?;
    copy_to_user(args[2], &length.to_le_bytes(), 8).map_err(|_| CompatErrno::Fault)?;
    Ok(0)
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
        state.thread_landlock_domains[slot] = None;
        state.pending_signal_records.iter_mut().for_each(|pending| {
            if pending.is_some_and(|pending| {
                pending.process == process && pending.target_tid == entry.tid
            }) {
                *pending = None;
            }
        });
        remove_all_sysv_semaphore_waiters(&mut state, process, task);
        let last_thread = !state
            .threads
            .iter()
            .flatten()
            .any(|entry| entry.process == process);
        drop(state);
        (
            entry.clear_child_tid,
            entry.tid,
            entry.robust_list,
            entry.rseq,
            entry.rseq_len,
            last_thread,
        )
    };
    if let Some(ticks) = sched::cpu_ticks(task) {
        let _ = proc::linux_account_exited_thread_cpu(process, ticks);
    }
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
        let _ = futex_wake(process, clear, usize::MAX, u32::MAX);
    }
    if last_thread {
        release_posix_timers(process);
        release_mq_notifications(process);
        remove_process_signals(process);
        release_sysv_semaphore_undos(process);
        release_sysv_shared_process(process);
        crate::binder::release_process(process);
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
                    let _ = futex_wake(process, address, 1, u32::MAX);
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

fn futex_key(process: ObjId, address: u64) -> FutexKey {
    match proc::linux_shared_futex_key(process, address) {
        Some(key) => FutexKey::Shared(key),
        None => FutexKey::Private { process, address },
    }
}

fn remove_futex_waiter(task: crate::task::TaskId) {
    let mut state = COMPAT.lock();
    for word in state.futexes.iter_mut().flatten() {
        for waiter in word.waiters.iter_mut() {
            if waiter.active && waiter.task == task {
                *waiter = FutexWaiter::EMPTY;
            }
        }
    }
    prune_empty_futex_words(&mut state);
}

fn futex_wait(
    process: ObjId,
    address: u64,
    expected: u32,
    bitset: u32,
    deadline_ns: Option<u64>,
) -> Result<u64, CompatErrno> {
    if address % 4 != 0 {
        return Err(CompatErrno::Invalid);
    }
    if futex_value(process, address)? != expected {
        return Err(CompatErrno::TryAgain);
    }
    if bitset == 0 {
        return Err(CompatErrno::Invalid);
    }
    let key = futex_key(process, address);
    let task = sched::current().0;
    {
        let mut state = COMPAT.lock();
        let slot = if let Some(slot) = state.futexes.iter().position(|entry| {
            entry.is_some_and(|entry| entry.key == key)
        }) {
            slot
        } else {
            let slot = state
                .futexes
                .iter()
                .position(Option::is_none)
                .ok_or(CompatErrno::NoSpace)?;
            state.futexes[slot] = Some(FutexWord {
                key,
                waiters: [FutexWaiter::EMPTY; MAX_FUTEX_WAITERS],
            });
            slot
        };
        let word = state.futexes[slot].as_mut().ok_or(CompatErrno::NoSpace)?;
        let waiter_slot = word
            .waiters
            .iter()
            .position(|waiter| !waiter.active)
            .ok_or(CompatErrno::NoSpace)?;
        word.waiters[waiter_slot] = FutexWaiter {
            task,
            key: Some(key),
            bitset,
            active: true,
            woken: false,
        };
    }
    // Close the check/register lost-wake window. A writer may change the
    // word and wake between the first value check and waiter publication;
    // Linux reports EAGAIN in that case instead of sleeping forever.
    if futex_value(process, address)? != expected {
        remove_futex_waiter(task);
        return Err(CompatErrno::TryAgain);
    }
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
        let waiter_state = {
            let state = COMPAT.lock();
            state
                .futexes
                .iter()
                .flatten()
                .flat_map(|word| word.waiters.iter())
                .find(|waiter| waiter.active && waiter.task == task)
                .map(|waiter| waiter.woken)
        };
        if waiter_state.is_none_or(|woken| woken) {
            break Ok(0);
        }
        if let Some(deadline) = deadline_ns {
            if sched::sleep_until_ns(deadline).is_err() {
                sched::pause();
            }
        } else {
            sched::pause();
        }
    };
    remove_futex_waiter(task);
    result
}

fn futex_wake(
    process: ObjId,
    address: u64,
    count: usize,
    bitset: u32,
) -> Result<u64, CompatErrno> {
    if address % 4 != 0 {
        return Err(CompatErrno::Invalid);
    }
    if bitset == 0 {
        return Err(CompatErrno::Invalid);
    }
    let key = futex_key(process, address);
    let mut tasks = [crate::task::TaskId(0); MAX_FUTEX_WAITERS];
    let mut woken = 0usize;
    {
        let mut state = COMPAT.lock();
        let Some(word) = state.futexes.iter_mut().flatten().find(|word| word.key == key) else {
            return Ok(0);
        };
        for waiter in word.waiters.iter_mut() {
            if woken == count {
                break;
            }
            if waiter.active && !waiter.woken && waiter.bitset & bitset != 0 {
                waiter.woken = true;
                tasks[woken] = waiter.task;
                woken += 1;
            }
        }
    }
    for task in tasks[..woken].iter().copied() {
        sched::wake(task);
    }
    Ok(woken as u64)
}

fn futex_requeue(
    process: ObjId,
    source_address: u64,
    target_address: u64,
    wake_count: usize,
    requeue_count: usize,
    expected: Option<u32>,
) -> Result<u64, CompatErrno> {
    if source_address % 4 != 0
        || target_address % 4 != 0
        || source_address == target_address
    {
        return Err(CompatErrno::Invalid);
    }
    if expected.is_some_and(|value| futex_value(process, source_address).ok() != Some(value)) {
        return Err(CompatErrno::TryAgain);
    }
    let source_key = futex_key(process, source_address);
    let target_key = futex_key(process, target_address);
    if source_key == target_key {
        return Err(CompatErrno::Invalid);
    }
    let mut woken_tasks = [crate::task::TaskId(0); MAX_FUTEX_WAITERS];
    let mut moved = [FutexWaiter::EMPTY; MAX_FUTEX_WAITERS];
    let mut woken = 0usize;
    let mut requeued = 0usize;
    let mut state = COMPAT.lock();
    let target_slot = state
        .futexes
        .iter()
        .position(|word| word.is_some_and(|word| word.key == target_key));
    let target_capacity = target_slot
        .map(|slot| {
            state.futexes[slot]
                .expect("futex target slot")
                .waiters
                .iter()
                .filter(|waiter| !waiter.active)
                .count()
        })
        .unwrap_or(MAX_FUTEX_WAITERS);
    let requeue_limit = requeue_count.min(target_capacity);
    let Some(source_slot) = state
        .futexes
        .iter()
        .position(|word| word.is_some_and(|word| word.key == source_key))
    else {
        return Ok(0);
    };
    for waiter in state.futexes[source_slot]
        .as_mut()
        .expect("futex source slot")
        .waiters
        .iter_mut()
    {
        if !waiter.active || waiter.woken {
            continue;
        }
        if woken < wake_count {
            waiter.woken = true;
            woken_tasks[woken] = waiter.task;
            woken += 1;
        } else if requeued < requeue_limit {
            moved[requeued] = *waiter;
            moved[requeued].key = Some(target_key);
            *waiter = FutexWaiter::EMPTY;
            requeued += 1;
        } else {
            break;
        }
    }
    if requeued != 0 {
        let target_slot = if let Some(slot) = target_slot {
            slot
        } else {
            let slot = state
                .futexes
                .iter()
                .position(Option::is_none)
                .ok_or(CompatErrno::NoSpace)?;
            state.futexes[slot] = Some(FutexWord {
                key: target_key,
                waiters: [FutexWaiter::EMPTY; MAX_FUTEX_WAITERS],
            });
            slot
        };
        let target = state.futexes[target_slot]
            .as_mut()
            .expect("futex target slot");
        for installed in 0..requeued {
            let slot = target
                .waiters
                .iter()
                .position(|waiter| !waiter.active)
                .expect("preflighted futex target capacity");
            target.waiters[slot] = moved[installed];
        }
    }
    prune_empty_futex_words(&mut state);
    drop(state);
    for task in woken_tasks[..woken].iter().copied() {
        sched::wake(task);
    }
    Ok((woken + requeued) as u64)
}

fn futex_timeout(
    pointer: u64,
    realtime: bool,
    absolute: bool,
) -> Result<Option<u64>, CompatErrno> {
    if pointer == 0 {
        return Ok(None);
    }
    let mut bytes = [0u8; 16];
    copy_from_user(&mut bytes, pointer, 16).map_err(|_| CompatErrno::Fault)?;
    let seconds = i64::from_le_bytes(bytes[..8].try_into().unwrap());
    let nanos = i64::from_le_bytes(bytes[8..].try_into().unwrap());
    if seconds < 0 || !(0..1_000_000_000).contains(&nanos) {
        return Err(CompatErrno::Invalid);
    }
    let requested = (seconds as u64)
        .checked_mul(1_000_000_000)
        .and_then(|value| value.checked_add(nanos as u64))
        .ok_or(CompatErrno::Invalid)?;
    if !absolute {
        return Ok(Some(sched::now_ns().saturating_add(requested)));
    }
    if realtime {
        let wall = crate::arch::wall_clock_ns().ok_or(CompatErrno::NoSys)?;
        let monotonic = sched::now_ns();
        return Ok(Some(if requested <= wall {
            monotonic
        } else {
            monotonic.saturating_add(requested - wall)
        }));
    }
    Ok(Some(requested))
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
        feature = "workload-io-verify",
        feature = "vulkan-metal2vulkan-verify"
    ))]
    trace_request(a);
    let Some(pid) = proc::current_process() else {
        return SyscallOutcome::value(-i64::from(CompatErrno::NoSys as i32));
    };
    let mut seccomp_data = [0u8; compat_core::seccomp::SECCOMP_DATA_BYTES];
    seccomp_data[..4].copy_from_slice(&(a.id as u32).to_le_bytes());
    seccomp_data[4..8].copy_from_slice(&0xc000_003eu32.to_le_bytes());
    let instruction_pointer = a.user_ip.map(|ip| ip.0).unwrap_or(0);
    seccomp_data[8..16].copy_from_slice(&instruction_pointer.to_le_bytes());
    for (index, argument) in a.args.iter().enumerate() {
        let offset = 16 + index * 8;
        seccomp_data[offset..offset + 8].copy_from_slice(&argument.to_le_bytes());
    }
    match proc::linux_seccomp_action(pid, &seccomp_data) {
        compat_core::seccomp::SeccompAction::Allow => {}
        compat_core::seccomp::SeccompAction::Log => {
            crate::kprintln!("[JSR-LINUX-SECCOMP] action=log nr={}", a.id);
        }
        compat_core::seccomp::SeccompAction::Errno(error) => {
            return SyscallOutcome::value(-i64::from(error));
        }
        compat_core::seccomp::SeccompAction::Trap => {
            let _ = queue_process_signal(pid, 31, 0, 128);
            let value = -i64::from(CompatErrno::NoSys as i32);
            let redirect = deliver_pending_signal(pid, a, a.user_ip, value);
            if proc::current_exiting() {
                proc::thread_exit(128 + 31, "linux seccomp trap");
            }
            return SyscallOutcome {
                value,
                redirect,
                exec_redirect: None,
            };
        }
        compat_core::seccomp::SeccompAction::KillThread => {
            proc::thread_exit(128 + 31, "linux seccomp kill thread");
        }
        compat_core::seccomp::SeccompAction::KillProcess => {
            let _ = proc::set_linux_termination_signal(pid, 31);
            let _ = proc::begin_exit(pid, 128 + 31);
            proc::thread_exit(128 + 31, "linux seccomp kill process");
        }
        compat_core::seccomp::SeccompAction::Trace(_)
        | compat_core::seccomp::SeccompAction::UserNotify => {
            return SyscallOutcome::value(-i64::from(CompatErrno::NoSys as i32));
        }
    }
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
    #[cfg(any(
        feature = "android-ecosystem-verify",
        feature = "android-art-verify",
        feature = "vulkan-metal2vulkan-verify"
    ))]
    {
        let mut executable = [0u8; 128];
        if let Some(length) = proc::linux_exec_path(pid, &mut executable) {
            if executable[..length].starts_with(b"/system/bin/") {
                crate::kprintln!(
                    "[JSR-ANDROID-SYSCALL] phase=enter call={:?} args={:?}",
                    call.syscall,
                    call.args
                );
                if ART_TLS_TRACE_REMAINING.load(Ordering::Relaxed) != 0 {
                    ART_TLS_TRACE_REMAINING.fetch_sub(1, Ordering::Relaxed);
                    crate::kprintln!(
                        "[JSR-ANDROID-ART] syscall={:?} tid={} fs_base={:#x} gs_base={:#x}",
                        call.syscall,
                        current_linux_tid(pid).unwrap_or(0),
                        crate::arch::user_fs_base(),
                        crate::arch::user_gs_base()
                    );
                }
            }
        }
    }
    if matches!(call.syscall, LinuxSyscall::Execve | LinuxSyscall::Execveat) {
        let executed = if call.syscall == LinuxSyscall::Execve {
            linux_execve(pid, call.args)
        } else {
            linux_execveat(pid, call.args)
        };
        return match executed {
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
        feature = "android-ecosystem-verify",
        feature = "android-art-verify",
        feature = "vulkan-metal2vulkan-verify"
    ))]
    {
        let mut executable = [0u8; 128];
        if let Some(length) = proc::linux_exec_path(pid, &mut executable) {
            if executable[..length].starts_with(b"/system/bin/") {
                crate::kprintln!(
                    "[JSR-ANDROID-SYSCALL] phase=exit call={:?} value={}",
                    call.syscall,
                    value
                );
            }
        }
    }
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
        LinuxSyscall::GetDents => compat_result(linux_getdents(pid, call.args)),
        LinuxSyscall::GetDents64 => compat_result(linux_getdents64(pid, call.args)),
        LinuxSyscall::Read => compat_result(linux_read(pid, call.args)),
        LinuxSyscall::Pread64 => compat_result(linux_pread64(pid, call.args)),
        LinuxSyscall::Pwrite64 => compat_result(linux_pwrite64(pid, call.args)),
        LinuxSyscall::ReadV => compat_result(linux_readv(pid, call.args)),
        LinuxSyscall::PreadV => {
            compat_result(linux_vectored_file_io(pid, call.args, false, true, false))
        }
        LinuxSyscall::PwriteV => {
            compat_result(linux_vectored_file_io(pid, call.args, true, true, false))
        }
        LinuxSyscall::PreadV2 => {
            compat_result(linux_vectored_file_io(pid, call.args, false, true, true))
        }
        LinuxSyscall::PwriteV2 => {
            compat_result(linux_vectored_file_io(pid, call.args, true, true, true))
        }
        LinuxSyscall::ProcessVmReadV => compat_result(linux_process_vm_io(pid, call.args, false)),
        LinuxSyscall::ProcessVmWriteV => compat_result(linux_process_vm_io(pid, call.args, true)),
        LinuxSyscall::ReadLinkAt => compat_result(linux_readlinkat(pid, call.args)),
        LinuxSyscall::Close => compat_result(linux_close(pid, call.args[0])),
        LinuxSyscall::CloseRange => compat_result(linux_close_range(pid, call.args)),
        LinuxSyscall::Dup => compat_result(linux_dup(pid, call.args)),
        LinuxSyscall::Dup2 => compat_result(linux_dup2(pid, call.args)),
        LinuxSyscall::Dup3 => compat_result(linux_dup3(pid, call.args)),
        LinuxSyscall::Pipe => compat_result(linux_pipe(pid, call.args)),
        LinuxSyscall::Pipe2 => compat_result(linux_pipe2(pid, call.args)),
        LinuxSyscall::Socket => compat_result(linux_socket(pid, call.args)),
        LinuxSyscall::Bind => compat_result(linux_bind(pid, call.args)),
        LinuxSyscall::Listen => compat_result(linux_listen(pid, call.args)),
        LinuxSyscall::Connect => compat_result(linux_connect(pid, call.args)),
        LinuxSyscall::Accept => compat_result(linux_accept(pid, call.args, false)),
        LinuxSyscall::Accept4 => compat_result(linux_accept(pid, call.args, true)),
        LinuxSyscall::SocketPair => compat_result(linux_socketpair(pid, call.args)),
        LinuxSyscall::EventFd => compat_result(linux_eventfd(pid, call.args, false)),
        LinuxSyscall::EventFd2 => compat_result(linux_eventfd(pid, call.args, true)),
        LinuxSyscall::TimerFdCreate => compat_result(linux_timerfd_create(pid, call.args)),
        LinuxSyscall::TimerFdSettime => compat_result(linux_timerfd_settime(pid, call.args)),
        LinuxSyscall::TimerFdGettime => compat_result(linux_timerfd_gettime(pid, call.args)),
        LinuxSyscall::TimerCreate => compat_result(linux_timer_create(pid, call.args)),
        LinuxSyscall::TimerSettime => compat_result(linux_timer_settime(pid, call.args)),
        LinuxSyscall::TimerGettime => compat_result(linux_timer_gettime(pid, call.args)),
        LinuxSyscall::TimerGetoverrun => compat_result(linux_timer_getoverrun(pid, call.args)),
        LinuxSyscall::TimerDelete => compat_result(linux_timer_delete(pid, call.args)),
        LinuxSyscall::SendMsg => compat_result(linux_sendmsg(pid, call.args)),
        LinuxSyscall::RecvMsg => compat_result(linux_recvmsg(pid, call.args)),
        LinuxSyscall::Sendmmsg => compat_result(linux_sendmmsg(pid, call.args)),
        LinuxSyscall::Recvmmsg => compat_result(linux_recvmmsg(pid, call.args)),
        LinuxSyscall::SendTo => compat_result(linux_sendto(pid, call.args)),
        LinuxSyscall::RecvFrom => compat_result(linux_recvfrom(pid, call.args)),
        LinuxSyscall::Shutdown => compat_result(linux_shutdown(pid, call.args)),
        LinuxSyscall::GetSockName => compat_result(linux_sockname(pid, call.args, false)),
        LinuxSyscall::GetPeerName => compat_result(linux_sockname(pid, call.args, true)),
        LinuxSyscall::GetSockOpt => compat_result(linux_getsockopt(pid, call.args)),
        LinuxSyscall::SetSockOpt => compat_result(linux_setsockopt(pid, call.args)),
        LinuxSyscall::Chdir => compat_result(linux_chdir(pid, call.args[0])),
        LinuxSyscall::Open => compat_result(linux_open(pid, call.args)),
        LinuxSyscall::OpenAt => compat_result(linux_openat(pid, call.args)),
        LinuxSyscall::OpenAt2 => compat_result(linux_openat2(pid, call.args)),
        LinuxSyscall::Creat => compat_result(linux_creat(pid, call.args)),
        LinuxSyscall::Fchdir => compat_result(linux_fchdir(pid, call.args[0])),
        LinuxSyscall::Chmod => {
            compat_result(linux_fchmodat(pid, legacy_chmod_args(call.args), false))
        }
        LinuxSyscall::Fchmod => compat_result(linux_fchmod(pid, call.args)),
        LinuxSyscall::FchmodAt => compat_result(linux_fchmodat(pid, call.args, false)),
        LinuxSyscall::FchmodAt2 => compat_result(linux_fchmodat(pid, call.args, true)),
        LinuxSyscall::Fchown => compat_result(linux_fchown(pid, call.args)),
        LinuxSyscall::Chown => {
            compat_result(linux_fchownat(pid, legacy_chown_args(call.args)))
        }
        LinuxSyscall::FchownAt => compat_result(linux_fchownat(pid, call.args)),
        LinuxSyscall::Lchown => compat_result(linux_lchown(pid, call.args)),
        LinuxSyscall::Mkdir => compat_result(linux_mkdirat(pid, legacy_path_at_args(call.args))),
        LinuxSyscall::MkdirAt => compat_result(linux_mkdirat(pid, call.args)),
        LinuxSyscall::Mknod => compat_result(linux_mknodat(pid, legacy_path_at_args(call.args))),
        LinuxSyscall::MknodAt => compat_result(linux_mknodat(pid, call.args)),
        LinuxSyscall::Unlink => compat_result(linux_unlinkat(pid, [(-100i64) as u64, call.args[0], 0, 0, 0, 0])),
        LinuxSyscall::UnlinkAt => compat_result(linux_unlinkat(pid, call.args)),
        LinuxSyscall::Rmdir => compat_result(linux_unlinkat(pid, [(-100i64) as u64, call.args[0], 0x200, 0, 0, 0])),
        LinuxSyscall::Rename => compat_result(linux_renameat(pid, legacy_rename_args(call.args))),
        LinuxSyscall::RenameAt => compat_result(linux_renameat(pid, call.args)),
        LinuxSyscall::RenameAt2 => compat_result(linux_renameat2(pid, call.args)),
        LinuxSyscall::Link => compat_result(linux_linkat(pid, legacy_link_args(call.args))),
        LinuxSyscall::LinkAt => compat_result(linux_linkat(pid, call.args)),
        LinuxSyscall::Symlink => compat_result(linux_symlinkat(pid, [call.args[0], (-100i64) as u64, call.args[1], 0, 0, 0])),
        LinuxSyscall::SymlinkAt => compat_result(linux_symlinkat(pid, call.args)),
        LinuxSyscall::Umask => compat_result(linux_umask(pid, call.args[0])),
        LinuxSyscall::Setxattr => compat_result(linux_setxattr(pid, call.args, false, false)),
        LinuxSyscall::LSetxattr => compat_result(linux_setxattr(pid, call.args, false, true)),
        LinuxSyscall::FSetxattr => compat_result(linux_setxattr(pid, call.args, true, false)),
        LinuxSyscall::Getxattr => compat_result(linux_getxattr(pid, call.args, false, false)),
        LinuxSyscall::LGetxattr => compat_result(linux_getxattr(pid, call.args, false, true)),
        LinuxSyscall::FGetxattr => compat_result(linux_getxattr(pid, call.args, true, false)),
        LinuxSyscall::Listxattr => compat_result(linux_listxattr(pid, call.args, false, false)),
        LinuxSyscall::LListxattr => compat_result(linux_listxattr(pid, call.args, false, true)),
        LinuxSyscall::FListxattr => compat_result(linux_listxattr(pid, call.args, true, false)),
        LinuxSyscall::Removexattr => compat_result(linux_removexattr(pid, call.args, false, false)),
        LinuxSyscall::LRemovexattr => compat_result(linux_removexattr(pid, call.args, false, true)),
        LinuxSyscall::FRemovexattr => compat_result(linux_removexattr(pid, call.args, true, false)),
        LinuxSyscall::Setxattrat => compat_result(linux_setxattrat(pid, call.args)),
        LinuxSyscall::Getxattrat => compat_result(linux_getxattrat(pid, call.args)),
        LinuxSyscall::Listxattrat => compat_result(linux_listxattrat(pid, call.args)),
        LinuxSyscall::Removexattrat => compat_result(linux_removexattrat(pid, call.args)),
        LinuxSyscall::Fstat => compat_result(linux_fstat(pid, call.args)),
        LinuxSyscall::Stat => {
            compat_result(linux_newfstatat(pid, legacy_stat_args(call.args, false)))
        }
        LinuxSyscall::Lstat => {
            compat_result(linux_newfstatat(pid, legacy_stat_args(call.args, true)))
        }
        LinuxSyscall::Fstatfs => compat_result(linux_fstatfs(pid, call.args)),
        LinuxSyscall::Fsync => compat_result(linux_sync_fd(pid, call.args[0], false)),
        LinuxSyscall::Utime => compat_result(linux_utime(pid, call.args[0])),
        LinuxSyscall::Utimes => compat_result(linux_utime(pid, call.args[0])),
        LinuxSyscall::UtimensAt => compat_result(linux_utimensat(pid, call.args, true)),
        LinuxSyscall::FutimesAt => {
            compat_result(linux_utimensat(pid, legacy_futimesat_args(call.args), false))
        }
        LinuxSyscall::Fdatasync => compat_result(linux_sync_fd(pid, call.args[0], true)),
        LinuxSyscall::Ftruncate => compat_result(linux_ftruncate(pid, call.args)),
        LinuxSyscall::Truncate => compat_result(linux_truncate(pid, call.args)),
        LinuxSyscall::Fallocate => compat_result(linux_fallocate(pid, call.args)),
        LinuxSyscall::ReadAhead => compat_result(linux_readahead(pid, call.args)),
        LinuxSyscall::Fadvise64 => compat_result(linux_fadvise64(pid, call.args)),
        LinuxSyscall::SyncFileRange => {
            compat_result(linux_sync_file_range(pid, call.args))
        }
        LinuxSyscall::MemfdCreate => compat_result(linux_memfd_create(pid, call.args)),
        LinuxSyscall::MemfdSecret => compat_result(linux_memfd_secret(pid, call.args)),
        LinuxSyscall::Sync => 0,
        LinuxSyscall::Syncfs => compat_result(linux_syncfs(pid, call.args[0])),
        LinuxSyscall::NewFstatAt => compat_result(linux_newfstatat(pid, call.args)),
        LinuxSyscall::Statx => compat_result(linux_statx(pid, call.args)),
        LinuxSyscall::Fcntl => compat_result(linux_fcntl(pid, call.args)),
        LinuxSyscall::Flock => compat_result(linux_flock(pid, call.args)),
        LinuxSyscall::Poll => compat_result(linux_poll(pid, call.args)),
        LinuxSyscall::PPoll => compat_result(linux_ppoll(pid, call.args)),
        LinuxSyscall::Select => compat_result(linux_select(pid, call.args, false)),
        LinuxSyscall::PSelect6 => compat_result(linux_select(pid, call.args, true)),
        LinuxSyscall::Ioctl => compat_result(linux_ioctl(pid, call.args)),
        LinuxSyscall::StatFs => compat_result(linux_statfs(call.args)),
        LinuxSyscall::ReadLink => compat_result(linux_readlink(pid, call.args)),
        LinuxSyscall::SendFile => compat_result(linux_sendfile(pid, call.args)),
        LinuxSyscall::CopyFileRange => compat_result(linux_copy_file_range(pid, call.args)),
        LinuxSyscall::Splice => compat_result(linux_splice(pid, call.args)),
        LinuxSyscall::Vmsplice => compat_result(linux_vmsplice(pid, call.args)),
        LinuxSyscall::Tee => compat_result(linux_tee(pid, call.args)),
        LinuxSyscall::Mmap => compat_result(linux_mmap(pid, call.args)),
        LinuxSyscall::Munmap => compat_result(linux_munmap(pid, call.args)),
        LinuxSyscall::Mprotect => compat_result(linux_mprotect(pid, call.args)),
        LinuxSyscall::Mremap => compat_result(linux_mremap(pid, call.args)),
        LinuxSyscall::Mseal => compat_result(linux_mseal(pid, call.args)),
        LinuxSyscall::Msync => compat_result(linux_msync(pid, call.args)),
        LinuxSyscall::MsgGet => compat_result(linux_msgget(pid, call.args)),
        LinuxSyscall::MsgSend => compat_result(linux_msgsnd(pid, call.args)),
        LinuxSyscall::MsgReceive => compat_result(linux_msgrcv(pid, call.args)),
        LinuxSyscall::MsgCtl => compat_result(linux_msgctl(pid, call.args)),
        LinuxSyscall::SemGet => compat_result(linux_semget(pid, call.args)),
        LinuxSyscall::SemOp => compat_result(linux_semop(pid, call.args, false)),
        LinuxSyscall::SemTimedOp => compat_result(linux_semop(pid, call.args, true)),
        LinuxSyscall::SemCtl => compat_result(linux_semctl(pid, call.args)),
        LinuxSyscall::ShmGet => compat_result(linux_shmget(pid, call.args)),
        LinuxSyscall::ShmAt => compat_result(linux_shmat(pid, call.args)),
        LinuxSyscall::ShmDt => compat_result(linux_shmdt(pid, call.args)),
        LinuxSyscall::ShmCtl => compat_result(linux_shmctl(pid, call.args)),
        LinuxSyscall::MqOpen => compat_result(linux_mq_open(pid, call.args)),
        LinuxSyscall::MqUnlink => compat_result(linux_mq_unlink(pid, call.args)),
        LinuxSyscall::MqTimedsend => compat_result(linux_mq_send(pid, call.args, true)),
        LinuxSyscall::MqTimedreceive => compat_result(linux_mq_receive(pid, call.args, true)),
        LinuxSyscall::MqNotify => compat_result(linux_mq_notify(pid, call.args)),
        LinuxSyscall::MqGetsetattr => compat_result(linux_mq_getsetattr(pid, call.args)),
        LinuxSyscall::MinCore => compat_result(linux_mincore(pid, call.args)),
        LinuxSyscall::Madvise => compat_result(linux_madvise(pid, call.args)),
        LinuxSyscall::Membarrier => compat_result(linux_membarrier(call.args)),
        LinuxSyscall::Mlock => compat_result(linux_mlock(pid, call.args, false)),
        LinuxSyscall::Mlock2 => compat_result(linux_mlock(pid, call.args, true)),
        LinuxSyscall::Mlockall => compat_result(linux_mlockall(call.args)),
        LinuxSyscall::Munlock => compat_result(linux_munlock(pid, call.args)),
        LinuxSyscall::Munlockall => 0,
        LinuxSyscall::Clone => compat_result(linux_clone(pid, call.args, user_ip, user_preserved)),
        LinuxSyscall::Fork => {
            compat_result(linux_fork(pid, call.args, user_ip, user_preserved))
        }
        LinuxSyscall::Clone3 => {
            compat_result(linux_clone3(pid, call.args, user_ip, user_preserved))
        }
        LinuxSyscall::Vfork => compat_result(linux_vfork(pid, call.args, user_ip, user_preserved)),
        LinuxSyscall::Brk => compat_result(linux_brk(pid, call.args[0])),
        LinuxSyscall::Access => compat_result(linux_access(call.args[0])),
        LinuxSyscall::FaccessAt => compat_result(linux_faccessat(pid, call.args, false)),
        LinuxSyscall::FaccessAt2 => compat_result(linux_faccessat(pid, call.args, true)),
        LinuxSyscall::Prctl => compat_result(linux_prctl(pid, call.args)),
        LinuxSyscall::ArchPrctl => compat_result(linux_arch_prctl(call.args)),
        LinuxSyscall::CapGet => compat_result(linux_capget(pid, call.args)),
        LinuxSyscall::CapSet => compat_result(linux_capset(pid, call.args)),
        LinuxSyscall::IoprioGet => compat_result(linux_ioprio_get(pid, call.args)),
        LinuxSyscall::IoprioSet => compat_result(linux_ioprio_set(pid, call.args)),
        LinuxSyscall::Personality => compat_result(linux_personality(pid, call.args[0])),
        LinuxSyscall::RestartSyscall => -(CompatErrno::Interrupted as i32 as i64),
        LinuxSyscall::RemapFilePages => compat_result(linux_remap_file_pages(pid, call.args)),
        LinuxSyscall::GetThreadArea
        | LinuxSyscall::SetThreadArea
        | LinuxSyscall::ModifyLdt
        | LinuxSyscall::LegacySysctl
        | LinuxSyscall::LegacyAfs
        | LinuxSyscall::LegacyCreateModule
        | LinuxSyscall::LegacyGetKernelSyms
        | LinuxSyscall::LegacyQueryModule
        | LinuxSyscall::LegacyNfsservctl
        | LinuxSyscall::LegacyGetpmsg
        | LinuxSyscall::LegacyPutpmsg
        | LinuxSyscall::LegacyEpollCtlOld
        | LinuxSyscall::LegacyEpollWaitOld
        | LinuxSyscall::LegacyTuxcall
        | LinuxSyscall::LegacyVserver
        | LinuxSyscall::LegacySecurity
        | LinuxSyscall::LegacyUstat
        | LinuxSyscall::LegacyUselib
        | LinuxSyscall::LegacySysfs => -(CompatErrno::NoSys as i32 as i64),
        LinuxSyscall::RseqSliceYield => {
            sched::yield_with_cause(crate::sched::scheduler::Cause::YIELD);
            0
        }
        LinuxSyscall::LookupDcookie => -(CompatErrno::NoEntry as i32 as i64),
        LinuxSyscall::Listmount => compat_result(linux_listmount(pid, call.args)),
        LinuxSyscall::Statmount => compat_result(linux_statmount(pid, call.args)),
        LinuxSyscall::Seccomp => compat_result(linux_seccomp(pid, call.args)),
        LinuxSyscall::Cachestat => compat_result(linux_cachestat(pid, call.args)),
        LinuxSyscall::LsmListModules => compat_result(linux_lsm_list_modules(call.args)),
        LinuxSyscall::ProcessMadvise => compat_result(linux_process_madvise(pid, call.args)),
        LinuxSyscall::FileGetattr => compat_result(linux_file_getattr(pid, call.args)),
        LinuxSyscall::FileSetattr => compat_result(linux_file_setattr(pid, call.args)),
        LinuxSyscall::ProcessMrelease => compat_result(linux_process_mrelease(pid, call.args)),
        LinuxSyscall::PkeyAlloc => compat_result(linux_pkey_alloc(call.args)),
        LinuxSyscall::PkeyFree => compat_result(linux_pkey_free(call.args)),
        LinuxSyscall::PkeyMprotect => compat_result(linux_pkey_mprotect(pid, call.args)),
        LinuxSyscall::NameToHandleAt => compat_result(linux_name_to_handle_at(pid, call.args)),
        LinuxSyscall::OpenByHandleAt => compat_result(linux_open_by_handle_at(pid, call.args)),
        LinuxSyscall::LsmGetSelfAttr => compat_result(linux_lsm_get_self_attr(pid, call.args)),
        LinuxSyscall::LsmSetSelfAttr => compat_result(linux_lsm_set_self_attr(pid, call.args)),
        LinuxSyscall::OpenTree => compat_result(linux_open_tree(pid, call.args)),
        LinuxSyscall::OpenTreeAttr => compat_result(linux_open_tree_attr(pid, call.args)),
        LinuxSyscall::Listns => compat_result(linux_listns(call.args)),
        LinuxSyscall::MoveMount => compat_result(linux_move_mount(pid, call.args)),
        LinuxSyscall::MountSetattr => compat_result(linux_mount_setattr(pid, call.args)),
        LinuxSyscall::FsOpen => compat_result(linux_fsopen(pid, call.args)),
        LinuxSyscall::FsConfig => compat_result(linux_fsconfig(pid, call.args)),
        LinuxSyscall::FsMount => compat_result(linux_fsmount(pid, call.args)),
        LinuxSyscall::FsPick => compat_result(linux_fspick(pid, call.args)),
        LinuxSyscall::AddKey => compat_result(linux_add_key(pid, call.args)),
        LinuxSyscall::RequestKey => compat_result(linux_request_key(pid, call.args)),
        LinuxSyscall::Keyctl => compat_result(linux_keyctl(pid, call.args)),
        LinuxSyscall::GetMempolicy => compat_result(linux_get_mempolicy(pid, call.args)),
        LinuxSyscall::SetMempolicy => compat_result(linux_set_mempolicy(call.args)),
        LinuxSyscall::Mbind => compat_result(linux_mbind(pid, call.args)),
        LinuxSyscall::SetMempolicyHomeNode => {
            compat_result(linux_set_mempolicy_home_node(pid, call.args))
        }
        LinuxSyscall::MigratePages => compat_result(linux_migrate_pages(pid, call.args)),
        LinuxSyscall::MovePages => compat_result(linux_move_pages(pid, call.args)),
        LinuxSyscall::MapShadowStack => -(CompatErrno::NotSupported as i32 as i64),
        LinuxSyscall::LandlockCreateRuleset => {
            compat_result(linux_landlock_create_ruleset(pid, call.args))
        }
        LinuxSyscall::LandlockAddRule => {
            compat_result(linux_landlock_add_rule(pid, call.args))
        }
        LinuxSyscall::LandlockRestrictSelf => {
            compat_result(linux_landlock_restrict_self(pid, call.args))
        }
        LinuxSyscall::Adjtimex
        | LinuxSyscall::ClockAdjtime
        | LinuxSyscall::ClockSettime
        | LinuxSyscall::Settimeofday
        | LinuxSyscall::Sethostname
        | LinuxSyscall::Setdomainname
        | LinuxSyscall::Reboot
        | LinuxSyscall::Mount
        | LinuxSyscall::Umount2
        | LinuxSyscall::PivotRoot
        | LinuxSyscall::Chroot
        | LinuxSyscall::Swapon
        | LinuxSyscall::Swapoff
        | LinuxSyscall::InitModule
        | LinuxSyscall::FinitModule
        | LinuxSyscall::DeleteModule
        | LinuxSyscall::Acct
        | LinuxSyscall::Iopl
        | LinuxSyscall::Ioperm
        | LinuxSyscall::KexecLoad
        | LinuxSyscall::KexecFileLoad
        | LinuxSyscall::Quotactl
        | LinuxSyscall::QuotactlFd
        | LinuxSyscall::Bpf
        | LinuxSyscall::PerfEventOpen
        | LinuxSyscall::Ptrace
        | LinuxSyscall::Setns
        | LinuxSyscall::Unshare
        | LinuxSyscall::Syslog
        | LinuxSyscall::Vhangup => -(CompatErrno::Perm as i32 as i64),
        LinuxSyscall::ClockGettime => compat_result(linux_clock_gettime(call.args)),
        LinuxSyscall::ClockGetres => compat_result(linux_clock_getres(call.args)),
        LinuxSyscall::Nanosleep => compat_result(linux_nanosleep(pid, call.args)),
        LinuxSyscall::Pause => compat_result(linux_pause(pid)),
        LinuxSyscall::ClockNanosleep => compat_result(linux_clock_nanosleep(pid, call.args)),
        LinuxSyscall::RtSigAction => compat_result(linux_rt_sigaction(pid, call.args)),
        LinuxSyscall::RtSigPending => compat_result(linux_rt_sigpending(pid, call.args)),
        LinuxSyscall::RtSigqueueinfo => {
            compat_result(linux_rt_sigqueueinfo(pid, call.args).map(|()| 0))
        }
        LinuxSyscall::RtSigProcMask => compat_result(linux_rt_sigprocmask(pid, call.args)),
        LinuxSyscall::RtSigsuspend => compat_result(linux_rt_sigsuspend(pid, call.args)),
        LinuxSyscall::RtSigtimedwait => compat_result(linux_rt_sigtimedwait(pid, call.args)),
        LinuxSyscall::RtTgsigqueueinfo => {
            compat_result(linux_rt_tgsigqueueinfo(pid, call.args).map(|()| 0))
        }
        LinuxSyscall::Tkill => compat_result(linux_tkill(pid, call.args).map(|()| 0)),
        LinuxSyscall::Tgkill => compat_result(linux_tgkill(pid, call.args).map(|()| 0)),
        LinuxSyscall::SchedYield => {
            sched::yield_with_cause(crate::sched::scheduler::Cause::YIELD);
            0
        }
        LinuxSyscall::Sigaltstack => compat_result(linux_sigaltstack(pid, call.args)),
        LinuxSyscall::Signalfd => compat_result(linux_signalfd(pid, call.args, false)),
        LinuxSyscall::Signalfd4 => compat_result(linux_signalfd(pid, call.args, true)),
        LinuxSyscall::InotifyInit => compat_result(linux_inotify_init(pid, call.args, false)),
        LinuxSyscall::InotifyInit1 => compat_result(linux_inotify_init(pid, call.args, true)),
        LinuxSyscall::InotifyAddWatch => compat_result(linux_inotify_add_watch(pid, call.args)),
        LinuxSyscall::InotifyRmWatch => compat_result(linux_inotify_rm_watch(pid, call.args)),
        LinuxSyscall::FanotifyInit => compat_result(linux_fanotify_init(pid, call.args)),
        LinuxSyscall::FanotifyMark => compat_result(linux_fanotify_mark(pid, call.args)),
        LinuxSyscall::Userfaultfd => compat_result(linux_userfaultfd(pid, call.args)),
        LinuxSyscall::Uprobe => -(CompatErrno::Protocol as i32 as i64),
        LinuxSyscall::Uretprobe => {
            if let Some(tid) = linux_tid(pid) {
                let _ = queue_thread_signal(pid, tid, 4, 0, 128);
            }
            -1
        }
        LinuxSyscall::Kill => compat_result(linux_kill(pid, call.args).map(|()| 0)),
        LinuxSyscall::Kcmp => compat_result(linux_kcmp(pid, call.args)),
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
        LinuxSyscall::Getrusage => compat_result(linux_getrusage(pid, call.args)),
        LinuxSyscall::GetItimer => compat_result(linux_getitimer(pid, call.args)),
        LinuxSyscall::Time => compat_result(linux_time(call.args)),
        LinuxSyscall::Times => compat_result(linux_times(pid, call.args)),
        LinuxSyscall::Alarm => compat_result(linux_alarm(pid, call.args)),
        LinuxSyscall::SetItimer => compat_result(linux_setitimer(pid, call.args)),
        LinuxSyscall::Getcwd => compat_result(linux_getcwd(pid, call.args)),
        LinuxSyscall::GetUid => compat_result(linux_get_identity(pid, false, false)),
        LinuxSyscall::GetEuid => compat_result(linux_get_identity(pid, false, true)),
        LinuxSyscall::GetGid => compat_result(linux_get_identity(pid, true, false)),
        LinuxSyscall::GetEgid => compat_result(linux_get_identity(pid, true, true)),
        LinuxSyscall::SetUid => compat_result(linux_set_single_identity(pid, call.args[0], false)),
        LinuxSyscall::SetGid => compat_result(linux_set_single_identity(pid, call.args[0], true)),
        LinuxSyscall::SetReUid => compat_result(linux_set_real_effective_identity(pid, call.args, false)),
        LinuxSyscall::SetReGid => compat_result(linux_set_real_effective_identity(pid, call.args, true)),
        LinuxSyscall::SetResUid => compat_result(linux_set_reserved_identity(pid, call.args, false)),
        LinuxSyscall::SetResGid => compat_result(linux_set_reserved_identity(pid, call.args, true)),
        LinuxSyscall::SetFsuid => linux_set_fs_identity(pid, call.args[0], false),
        LinuxSyscall::SetFsgid => linux_set_fs_identity(pid, call.args[0], true),
        LinuxSyscall::GetPpid => proc::linux_ppid(pid)
            .map(i64::from)
            .ok_or(CompatErrno::NoSys)
            .unwrap_or_else(|error| -i64::from(error as i32)),
        LinuxSyscall::GetPgid => compat_result(linux_get_pgid(pid, call.args[0])),
        LinuxSyscall::GetPgrp => compat_result(linux_get_pgrp(pid)),
        LinuxSyscall::GetSid => compat_result(linux_get_sid(pid, call.args[0])),
        LinuxSyscall::SetPgid => compat_result(linux_setpgid(pid, call.args)),
        LinuxSyscall::SetSid => compat_result(linux_setsid(pid)),
        LinuxSyscall::GetGroups => compat_result(linux_getgroups(pid, call.args)),
        LinuxSyscall::SetGroups => compat_result(linux_setgroups(pid, call.args)),
        LinuxSyscall::GetResUid => compat_result(linux_getres(pid, call.args, false)),
        LinuxSyscall::GetResGid => compat_result(linux_getres(pid, call.args, true)),
        LinuxSyscall::GetPriority => compat_result(linux_getpriority(pid, call.args)),
        LinuxSyscall::SetPriority => compat_result(linux_setpriority(pid, call.args)),
        LinuxSyscall::Lseek => compat_result(linux_lseek(pid, call.args)),
        LinuxSyscall::GetCpu => compat_result(linux_getcpu(call.args)),
        LinuxSyscall::Sysinfo => compat_result(linux_sysinfo(call.args[0])),
        LinuxSyscall::SchedGetAffinity => compat_result(linux_sched_getaffinity(pid, call.args)),
        LinuxSyscall::SchedGetParam => compat_result(linux_sched_getparam(pid, call.args)),
        LinuxSyscall::SchedSetAffinity => compat_result(linux_sched_setaffinity(pid, call.args)),
        LinuxSyscall::SchedSetScheduler => {
            compat_result(linux_sched_setscheduler(pid, call.args))
        }
        LinuxSyscall::SchedGetScheduler => {
            compat_result(linux_sched_getscheduler(pid, call.args[0]))
        }
        LinuxSyscall::SchedSetParam => compat_result(linux_sched_setparam(pid, call.args)),
        LinuxSyscall::SchedGetPriorityMax => {
            compat_result(linux_sched_priority(call.args[0], true))
        }
        LinuxSyscall::SchedGetPriorityMin => {
            compat_result(linux_sched_priority(call.args[0], false))
        }
        LinuxSyscall::SchedRrGetInterval => {
            compat_result(linux_sched_rr_get_interval(pid, call.args))
        }
        LinuxSyscall::SchedGetAttr => compat_result(linux_sched_getattr(pid, call.args)),
        LinuxSyscall::SchedSetAttr => compat_result(linux_sched_setattr(pid, call.args)),
        LinuxSyscall::SetTidAddress => set_clear_child_tid(pid, call.args[0])
            .map(i64::from)
            .ok_or(CompatErrno::NoSys)
            .unwrap_or_else(|error| -i64::from(error as i32)),
        LinuxSyscall::GetRobustList => compat_result(linux_get_robust_list(pid, call.args)),
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
        LinuxSyscall::Getrlimit => compat_result(linux_getrlimit(pid, call.args)),
        LinuxSyscall::Setrlimit => compat_result(linux_setrlimit(pid, call.args)),
        LinuxSyscall::Futex => compat_result(linux_futex(pid, call.args)),
        LinuxSyscall::FutexWait => compat_result(linux_futex_wait(pid, call.args)),
        LinuxSyscall::FutexWake => compat_result(linux_futex_wake(pid, call.args)),
        LinuxSyscall::FutexRequeue => compat_result(linux_futex_requeue(pid, call.args)),
        LinuxSyscall::FutexWaitv => compat_result(linux_futex_waitv(pid, call.args)),
        LinuxSyscall::EpollCreate => compat_result(linux_epoll_create(pid, call.args)),
        LinuxSyscall::EpollCreate1 => compat_result(linux_epoll_create1(pid, call.args)),
        LinuxSyscall::EpollCtl => compat_result(linux_epoll_ctl(pid, call.args)),
        LinuxSyscall::EpollWait => compat_result(linux_epoll_wait(pid, call.args, false, false)),
        LinuxSyscall::EpollPWait => compat_result(linux_epoll_wait(pid, call.args, true, false)),
        LinuxSyscall::EpollPWait2 => compat_result(linux_epoll_wait(pid, call.args, true, true)),
        LinuxSyscall::IoUringSetup => compat_result(linux_io_uring_setup(pid, call.args)),
        LinuxSyscall::IoUringEnter => compat_result(linux_io_uring_enter(pid, call.args)),
        LinuxSyscall::IoUringRegister => {
            compat_result(linux_io_uring_register(pid, call.args))
        }
        LinuxSyscall::IoSetup => compat_result(linux_io_setup(pid, call.args)),
        LinuxSyscall::IoDestroy => compat_result(linux_io_destroy(pid, call.args)),
        LinuxSyscall::IoSubmit => compat_result(linux_io_submit(pid, call.args)),
        LinuxSyscall::IoCancel => compat_result(linux_io_cancel(pid, call.args)),
        LinuxSyscall::IoGetevents => compat_result(linux_io_getevents(pid, call.args, false)),
        LinuxSyscall::IoPgetevents => compat_result(linux_io_getevents(pid, call.args, true)),
        LinuxSyscall::Exit => {
            let code = call.args[0] as i64;
            proc::thread_exit(code, "linux thread exit")
        }
        LinuxSyscall::ExitGroup => {
            let code = call.args[0] as i64;
            let _ = proc::begin_exit(pid, code);
            proc::thread_exit(code, "linux process exit")
        }
        LinuxSyscall::Wait4 => compat_result(linux_wait4(pid, call.args)),
        LinuxSyscall::WaitId => compat_result(linux_waitid(pid, call.args)),
        LinuxSyscall::PidfdOpen => compat_result(linux_pidfd_open(pid, call.args)),
        LinuxSyscall::PidfdSendSignal => {
            compat_result(linux_pidfd_send_signal(pid, call.args))
        }
        LinuxSyscall::PidfdGetFd => compat_result(linux_pidfd_getfd(pid, call.args)),
        _ => -i64::from(CompatErrno::NoSys as i32),
    }
}

/// Returns one real or effective Linux ABI identity.
fn linux_get_identity(pid: ObjId, gid: bool, effective: bool) -> Result<u64, CompatErrno> {
    let credentials = proc::linux_credentials(pid).ok_or(CompatErrno::NoProcess)?;
    Ok(u64::from(if gid {
        if effective {
            credentials.egid
        } else {
            credentials.gid
        }
    } else if effective {
        credentials.euid
    } else {
        credentials.uid
    }))
}

/// Commits one validated Linux ABI credential state.
fn commit_credentials(pid: ObjId, credentials: proc::LinuxCredentials) -> Result<u64, CompatErrno> {
    if proc::set_linux_credentials(pid, credentials) {
        Ok(0)
    } else {
        Err(CompatErrno::NoProcess)
    }
}

/// Implements `setuid(2)` and `setgid(2)`.
fn linux_set_single_identity(
    pid: ObjId,
    raw_requested: u64,
    gid: bool,
) -> Result<u64, CompatErrno> {
    let requested = raw_requested as u32;
    if requested == u32::MAX {
        return Err(CompatErrno::Invalid);
    }
    let mut credentials = proc::linux_credentials(pid).ok_or(CompatErrno::NoProcess)?;
    if gid {
        if credentials.egid != 0 && requested != credentials.gid && requested != credentials.sgid {
            return Err(CompatErrno::Perm);
        }
        credentials.gid = requested;
        credentials.egid = requested;
        credentials.sgid = requested;
        credentials.fsgid = requested;
    } else {
        if credentials.euid != 0 && requested != credentials.uid && requested != credentials.suid {
            return Err(CompatErrno::Perm);
        }
        credentials.uid = requested;
        credentials.euid = requested;
        credentials.suid = requested;
        credentials.fsuid = requested;
    }
    commit_credentials(pid, credentials)
}

/// Implements `setreuid(2)` and `setregid(2)`.
fn linux_set_real_effective_identity(
    pid: ObjId,
    args: [u64; 6],
    gid: bool,
) -> Result<u64, CompatErrno> {
    let real_requested = args[0] as u32;
    let effective_requested = args[1] as u32;
    let mut credentials = proc::linux_credentials(pid).ok_or(CompatErrno::NoProcess)?;
    let (real, effective, saved) = if gid {
        (credentials.gid, credentials.egid, credentials.sgid)
    } else {
        (credentials.uid, credentials.euid, credentials.suid)
    };
    let privileged = (if gid { credentials.egid } else { credentials.euid }) == 0;
    let allowed = |value: u32| {
        value == u32::MAX || privileged || value == real || value == effective || value == saved
    };
    if !allowed(real_requested) || !allowed(effective_requested) {
        return Err(CompatErrno::Perm);
    }
    let new_real = if real_requested == u32::MAX {
        real
    } else {
        real_requested
    };
    let new_effective = if effective_requested == u32::MAX {
        effective
    } else {
        effective_requested
    };
    let new_saved = if privileged || new_real != real || new_effective != effective {
        new_effective
    } else {
        saved
    };
    if gid {
        credentials.gid = new_real;
        credentials.egid = new_effective;
        credentials.sgid = new_saved;
        if credentials.fsgid == effective {
            credentials.fsgid = new_effective;
        }
    } else {
        credentials.uid = new_real;
        credentials.euid = new_effective;
        credentials.suid = new_saved;
        if credentials.fsuid == effective {
            credentials.fsuid = new_effective;
        }
    }
    commit_credentials(pid, credentials)
}

/// Implements `setresuid(2)` and `setresgid(2)`.
fn linux_set_reserved_identity(
    pid: ObjId,
    args: [u64; 6],
    gid: bool,
) -> Result<u64, CompatErrno> {
    let requested = [args[0] as u32, args[1] as u32, args[2] as u32];
    let mut credentials = proc::linux_credentials(pid).ok_or(CompatErrno::NoProcess)?;
    let current = if gid {
        [credentials.gid, credentials.egid, credentials.sgid]
    } else {
        [credentials.uid, credentials.euid, credentials.suid]
    };
    let privileged = (if gid { credentials.egid } else { credentials.euid }) == 0;
    if requested.iter().any(|value| {
        *value != u32::MAX && !privileged && !current.contains(value)
    }) {
        return Err(CompatErrno::Perm);
    }
    let next = [
        if requested[0] == u32::MAX { current[0] } else { requested[0] },
        if requested[1] == u32::MAX { current[1] } else { requested[1] },
        if requested[2] == u32::MAX { current[2] } else { requested[2] },
    ];
    if gid {
        credentials.gid = next[0];
        credentials.egid = next[1];
        credentials.sgid = next[2];
        if credentials.fsgid == current[1] {
            credentials.fsgid = next[1];
        }
    } else {
        credentials.uid = next[0];
        credentials.euid = next[1];
        credentials.suid = next[2];
        if credentials.fsuid == current[1] {
            credentials.fsuid = next[1];
        }
    }
    commit_credentials(pid, credentials)
}

/// Implements `setfsuid(2)` and `setfsgid(2)`, returning the previous identity.
fn linux_set_fs_identity(pid: ObjId, raw_requested: u64, gid: bool) -> i64 {
    let requested = raw_requested as u32;
    let Some(mut credentials) = proc::linux_credentials(pid) else {
        return -(CompatErrno::NoProcess as i32 as i64);
    };
    let (old_fs, effective, real, saved) = if gid {
        (
            credentials.fsgid,
            credentials.egid,
            credentials.gid,
            credentials.sgid,
        )
    } else {
        (
            credentials.fsuid,
            credentials.euid,
            credentials.uid,
            credentials.suid,
        )
    };
    if requested == u32::MAX
        || requested == old_fs
        || effective == 0
        || requested == effective
        || requested == real
        || requested == saved
    {
        if requested != u32::MAX {
            if gid {
                credentials.fsgid = requested;
            } else {
                credentials.fsuid = requested;
            }
            if !proc::set_linux_credentials(pid, credentials) {
                return -(CompatErrno::NoProcess as i32 as i64);
            }
        }
    }
    i64::from(old_fs)
}

/// Writes the real, effective and saved Linux ABI uid or gid triple.
fn linux_getres(pid: ObjId, args: [u64; 6], gid: bool) -> Result<u64, CompatErrno> {
    let credentials = proc::linux_credentials(pid).ok_or(CompatErrno::NoProcess)?;
    let values = if gid {
        [credentials.gid, credentials.egid, credentials.sgid]
    } else {
        [credentials.uid, credentials.euid, credentials.suid]
    };
    for (index, pointer) in [args[0], args[1], args[2]].into_iter().enumerate() {
        if pointer != 0 {
            copy_to_user(pointer, &values[index].to_le_bytes(), 4)
                .map_err(|_| CompatErrno::Fault)?;
        }
    }
    Ok(0)
}

/// Returns the bounded supplementary group list.
fn linux_getgroups(pid: ObjId, args: [u64; 6]) -> Result<u64, CompatErrno> {
    let size = args[0] as u32 as i32;
    if size < 0 {
        return Err(CompatErrno::Invalid);
    }
    let groups = proc::linux_supplementary_groups(pid).ok_or(CompatErrno::NoProcess)?;
    if size == 0 {
        return Ok(groups.len() as u64);
    }
    if args[1] == 0 {
        return Err(CompatErrno::Fault);
    }
    if (size as usize) < groups.len() {
        return Err(CompatErrno::Invalid);
    }
    let mut output = [0u8; 32 * 4];
    for (index, group) in groups.iter().copied().enumerate() {
        output[index * 4..index * 4 + 4].copy_from_slice(&group.to_le_bytes());
    }
    proc::write(pid, args[1], &output[..groups.len() * 4])
        .map_err(|_| CompatErrno::Fault)?;
    Ok(groups.len() as u64)
}

/// Replaces the supplementary group list when the ABI credential permits it.
fn linux_setgroups(pid: ObjId, args: [u64; 6]) -> Result<u64, CompatErrno> {
    const CAP_SETGID: u64 = 1 << 6;
    const MAX_GROUPS: usize = 32;
    let credentials = proc::linux_credentials(pid).ok_or(CompatErrno::NoProcess)?;
    let capabilities = proc::linux_capabilities(pid).ok_or(CompatErrno::NoProcess)?;
    if credentials.euid != 0 && capabilities.effective & CAP_SETGID == 0 {
        return Err(CompatErrno::Perm);
    }
    let count = usize::try_from(args[0]).map_err(|_| CompatErrno::Invalid)?;
    if count > MAX_GROUPS {
        return Err(CompatErrno::Invalid);
    }
    let mut groups = alloc::vec![0u32; count];
    if count != 0 {
        let mut raw = [0u8; MAX_GROUPS * 4];
        proc::read(pid, args[1], &mut raw[..count * 4])
            .map_err(|_| CompatErrno::Fault)?;
        for (index, group) in groups.iter_mut().enumerate() {
            *group = u32::from_le_bytes(raw[index * 4..index * 4 + 4].try_into().unwrap());
        }
        groups.sort_unstable();
        groups.dedup();
    }
    if proc::set_linux_supplementary_groups(pid, &groups) {
        Ok(0)
    } else {
        Err(CompatErrno::NoProcess)
    }
}

fn linux_resolve_pid(pid: ObjId, requested: u64) -> Result<ObjId, CompatErrno> {
    let current_pid = proc::linux_pid(pid).ok_or(CompatErrno::NoProcess)?;
    if requested == 0 || requested == u64::from(current_pid) {
        return Ok(pid);
    }
    let target = u32::try_from(requested).map_err(|_| CompatErrno::Invalid)?;
    proc::linux_process_for_pid(target).ok_or(CompatErrno::NoProcess)
}

fn linux_get_pgid(pid: ObjId, requested: u64) -> Result<u64, CompatErrno> {
    let target = linux_resolve_pid(pid, requested)?;
    proc::linux_process_group_state(target)
        .map(|(pgid, _)| u64::from(pgid))
        .ok_or(CompatErrno::NoProcess)
}

fn linux_get_pgrp(pid: ObjId) -> Result<u64, CompatErrno> {
    proc::linux_process_group_state(pid)
        .map(|(pgid, _)| u64::from(pgid))
        .ok_or(CompatErrno::NoProcess)
}

fn linux_get_sid(pid: ObjId, requested: u64) -> Result<u64, CompatErrno> {
    let target = linux_resolve_pid(pid, requested)?;
    proc::linux_process_group_state(target)
        .map(|(_, sid)| u64::from(sid))
        .ok_or(CompatErrno::NoProcess)
}

fn linux_setpgid(pid: ObjId, args: [u64; 6]) -> Result<u64, CompatErrno> {
    let current_pid = proc::linux_pid(pid).ok_or(CompatErrno::NoProcess)?;
    let target_pid = if args[0] == 0 {
        current_pid
    } else {
        u32::try_from(args[0]).map_err(|_| CompatErrno::Invalid)?
    };
    if target_pid != current_pid {
        return if proc::linux_process_for_pid(target_pid).is_some() {
            Err(CompatErrno::Perm)
        } else {
            Err(CompatErrno::NoProcess)
        };
    }
    let group = if args[1] == 0 {
        target_pid
    } else {
        u32::try_from(args[1]).map_err(|_| CompatErrno::Invalid)?
    };
    let (_, session) =
        proc::linux_process_group_state(pid).ok_or(CompatErrno::NoProcess)?;
    if session == current_pid {
        return Err(CompatErrno::Perm);
    }
    if group != target_pid && proc::linux_process_group_session(group) != Some(session) {
        return Err(CompatErrno::Perm);
    }
    if proc::linux_set_process_group_state(pid, group, session) {
        Ok(0)
    } else {
        Err(CompatErrno::NoProcess)
    }
}

fn linux_setsid(pid: ObjId) -> Result<u64, CompatErrno> {
    let process_id = proc::linux_pid(pid).ok_or(CompatErrno::NoProcess)?;
    let (group, _) =
        proc::linux_process_group_state(pid).ok_or(CompatErrno::NoProcess)?;
    if group == process_id {
        return Err(CompatErrno::Perm);
    }
    if proc::linux_set_process_group_state(pid, process_id, process_id) {
        Ok(u64::from(process_id))
    } else {
        Err(CompatErrno::NoProcess)
    }
}

fn legacy_chmod_args(args: [u64; 6]) -> [u64; 6] {
    [(-100i64) as u64, args[0], args[1], 0, 0, 0]
}

fn legacy_chown_args(args: [u64; 6]) -> [u64; 6] {
    [(-100i64) as u64, args[0], args[1], args[2], 0, 0]
}

fn legacy_stat_args(args: [u64; 6], nofollow: bool) -> [u64; 6] {
    [
        (-100i64) as u64,
        args[0],
        args[1],
        if nofollow { 0x100 } else { 0 },
        0,
        0,
    ]
}

fn legacy_futimesat_args(args: [u64; 6]) -> [u64; 6] {
    [args[0], args[1], args[2], 0, 0, 0]
}

fn legacy_path_at_args(args: [u64; 6]) -> [u64; 6] {
    [(-100i64) as u64, args[0], args[1], 0, 0, 0]
}

fn legacy_rename_args(args: [u64; 6]) -> [u64; 6] {
    [
        (-100i64) as u64,
        args[0],
        (-100i64) as u64,
        args[1],
        0,
        0,
    ]
}

fn legacy_link_args(args: [u64; 6]) -> [u64; 6] {
    [
        (-100i64) as u64,
        args[0],
        (-100i64) as u64,
        args[1],
        0,
        0,
    ]
}

fn linux_uname(args: [u64; 6]) -> Result<u64, CompatErrno> {
    let utsname = compat_core::linux_utsname();
    copy_to_user(args[0], &utsname, utsname.len()).map_err(|_| CompatErrno::Fault)?;
    Ok(0)
}

fn linux_write(pid: ObjId, args: [u64; 6]) -> Result<u64, CompatErrno> {
    const MAX_WRITE: usize = 1024 * 1024;
    let fd = u32::try_from(args[0]).map_err(|_| CompatErrno::BadFd)?;
    let len = usize::try_from(args[2])
        .map_err(|_| CompatErrno::Invalid)?
        .min(MAX_WRITE); // JASPER-HARDCODE-REVIEW: issue=35 source=linux-batch-partial-policy reason=return-bounded-write-prefix
    if let Some(entry) = proc::linux_fd(pid, fd) {
        if linux_cache_file_id(entry.handle).is_some() {
            if !entry.rights.contains(kernel_core::object::Rights::WRITE) {
                return Err(CompatErrno::BadFd);
            }
            return linux_cache_write(pid, fd, entry.handle, args[1], len);
        }
        if entry.kind == compat_core::fd::CompatKind::Pipe {
            if !entry.rights.contains(kernel_core::object::Rights::WRITE) {
                return Err(CompatErrno::BadFd);
            }
            return linux_pipe_write(pid, fd, entry.handle, args[1], len);
        }
        if entry.kind == compat_core::fd::CompatKind::Event {
            return linux_eventfd_write(pid, fd, entry.handle, args[1], len);
        }
        if entry.kind == compat_core::fd::CompatKind::Timer {
            return Err(CompatErrno::Invalid);
        }
        if entry.kind == compat_core::fd::CompatKind::Signal {
            return Err(CompatErrno::Invalid);
        }
        if entry.kind == compat_core::fd::CompatKind::Socket {
            if !entry.rights.contains(kernel_core::object::Rights::WRITE) {
                return Err(CompatErrno::BadFd);
            }
            return linux_socket_write(pid, fd, entry.handle, args[1], len, false, false);
        }
        if entry.kind == compat_core::fd::CompatKind::Device
            && proc::linux_ashmem_is_regular(pid, entry.handle) == Some(true)
        {
            if !entry.rights.contains(kernel_core::object::Rights::WRITE) {
                return Err(CompatErrno::BadFd);
            }
            let offset = proc::linux_fd_offset(pid, fd).ok_or(CompatErrno::BadFd)?;
            if len == 0 {
                return Ok(0);
            }
            let mut bytes = alloc::vec![0u8; len];
            copy_from_user(&mut bytes, args[1], len).map_err(|_| CompatErrno::Fault)?;
            let written =
                proc::linux_ashmem_write_from(pid, entry.handle, offset, &bytes)
                    .map_err(ashmem_compat_error)?;
            if written != 0 && !proc::set_linux_fd_offset(pid, fd, offset + written as u64) {
                return Err(CompatErrno::BadFd);
            }
            return Ok(written as u64);
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
    if proc::linux_fd(pid, fd).is_some_and(|entry| {
        entry.kind == compat_core::fd::CompatKind::Device
            && proc::linux_ashmem_is_regular(pid, entry.handle) == Some(true)
    }) {
        return linux_vectored_file_io(pid, args, true, false, false);
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
fn linux_cache_getdents64(
    pid: ObjId,
    fd: u32,
    handle: u64,
    destination: u64,
    capacity: usize,
    start: u64,
) -> Result<u64, CompatErrno> {
    let children = linux_cache_children(handle).ok_or(CompatErrno::BadFd)?;
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
            (b".".as_slice(), 1u64, 4u8)
        } else if index == 1 {
            (b"..".as_slice(), 1u64, 4u8)
        } else {
            let (name, inode, kind) = &children[index - 2];
            (name.as_slice(), *inode, *kind)
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
        copy_to_user(destination, &output, output.len()).map_err(|_| CompatErrno::Fault)?;
    }
    io.commit();
    if !proc::set_linux_dir_offset(pid, fd, index as u64) {
        return Err(CompatErrno::BadFd);
    }
    Ok(output.len() as u64)
}

fn linux_getdents64(pid: ObjId, args: [u64; 6]) -> Result<u64, CompatErrno> {
    const MAX_GETDENTS: usize = 64 * 1024;
    const DT_DIR: u8 = 4;
    const DT_REG: u8 = 8;
    let fd = u32::try_from(args[0]).map_err(|_| CompatErrno::BadFd)?;
    let capacity = usize::try_from(args[2]).map_err(|_| CompatErrno::Invalid)?;
    let capacity = capacity.min(MAX_GETDENTS); // JASPER-HARDCODE-REVIEW: issue=35 source=linux-batch-partial-policy reason=return-bounded-directory-prefix
    let (handle, start) = proc::linux_dir_state(pid, fd).ok_or(CompatErrno::BadFd)?;
    if linux_cache_dir_id(handle).is_some() {
        return linux_cache_getdents64(pid, fd, handle, args[1], capacity, start);
    }
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

/// Reads bounded legacy `linux_dirent` records from one compatibility directory.
fn linux_getdents(pid: ObjId, args: [u64; 6]) -> Result<u64, CompatErrno> {
    const MAX_GETDENTS: usize = 64 * 1024;
    const DT_DIR: u8 = 4;
    const DT_REG: u8 = 8;
    let fd = u32::try_from(args[0]).map_err(|_| CompatErrno::BadFd)?;
    let capacity = usize::try_from(args[2]).map_err(|_| CompatErrno::Invalid)?;
    let capacity = capacity.min(MAX_GETDENTS); // JASPER-HARDCODE-REVIEW: issue=35 source=linux-batch-partial-policy reason=return-bounded-directory-prefix
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
        let record_len = align_up(19usize.saturating_add(name.len()) as u64, 8) as usize;
        if record_len == 0 || record_len > u16::MAX as usize {
            return Err(CompatErrno::Invalid);
        }
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
        output[base + 18..base + 18 + name.len()].copy_from_slice(name);
        output[base + record_len - 1] = kind;
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

fn read_console_input(pid: ObjId, len: usize) -> Result<([u8; 4096], usize), CompatErrno> {
    const O_NONBLOCK: u64 = 0x800;
    let nonblocking = proc::linux_fd_status_flags(pid, 0)
        .is_some_and(|flags| u64::from(flags) & O_NONBLOCK != 0);
    let mut input = [0u8; 4096];
    let requested = len.min(input.len());
    match crate::terminal::read_input(&mut input[..requested], nonblocking) {
        Ok(count) => Ok((input, count)),
        Err(kernel_core::terminal_session::TerminalError::Eof) => Ok((input, 0)),
        Err(kernel_core::terminal_session::TerminalError::WouldBlock) => {
            Err(CompatErrno::TryAgain)
        }
        Err(kernel_core::terminal_session::TerminalError::Closed)
        | Err(kernel_core::terminal_session::TerminalError::Failed) => {
            Err(CompatErrno::Canceled)
        }
        Err(_) => Err(CompatErrno::Invalid),
    }
}

/// Implements bounded Linux `read(2)` for stdin and virtual read-only files.
///
/// 标准输入来自有界原生终端会话；文件读取在全部用户页校验通过后才提交游标。
fn linux_read(pid: ObjId, args: [u64; 6]) -> Result<u64, CompatErrno> {
    const MAX_READ: usize = 1024 * 1024;
    const TERMINAL_READ: usize = 4096;
    let fd = u32::try_from(args[0]).map_err(|_| CompatErrno::BadFd)?;
    let len = usize::try_from(args[2]).map_err(|_| CompatErrno::Invalid)?;
    if len > MAX_READ {
        return Err(CompatErrno::Invalid);
    }
    if let Some(entry) = proc::linux_fd(pid, fd) {
        if linux_cache_file_id(entry.handle).is_some() {
            if !entry.rights.contains(kernel_core::object::Rights::READ) {
                return Err(CompatErrno::BadFd);
            }
            return linux_cache_read(pid, fd, entry.handle, args[1], len);
        }
        if entry.handle == LINUX_PROC_MAPS_HANDLE {
            if !entry.rights.contains(kernel_core::object::Rights::READ) {
                return Err(CompatErrno::BadFd);
            }
            return linux_proc_maps_read(pid, fd, args[1], len, None);
        }
        if entry.handle == LINUX_PROC_STAT_HANDLE {
            if !entry.rights.contains(kernel_core::object::Rights::READ) {
                return Err(CompatErrno::BadFd);
            }
            return linux_proc_stat_read(pid, fd, args[1], len, None);
        }
        if entry.kind == compat_core::fd::CompatKind::Pipe {
            if !entry.rights.contains(kernel_core::object::Rights::READ) {
                return Err(CompatErrno::BadFd);
            }
            return linux_pipe_read(pid, fd, entry.handle, args[1], len);
        }
        if entry.kind == compat_core::fd::CompatKind::Event {
            return linux_eventfd_read(pid, fd, entry.handle, args[1], len);
        }
        if entry.kind == compat_core::fd::CompatKind::Timer {
            return linux_timerfd_read(pid, fd, entry.handle, args[1], len);
        }
        if entry.kind == compat_core::fd::CompatKind::Signal {
            return linux_signalfd_read(pid, fd, entry.handle, args[1], len);
        }
        if entry.kind == compat_core::fd::CompatKind::Inotify {
            if proc::linux_inotify_state(pid, entry.handle)
                .is_some_and(|state| state.lock().fanotify)
            {
                return linux_fanotify_read(pid, fd, args[1], len);
            }
            return linux_inotify_read(pid, fd, args[1], len);
        }
        if entry.kind == compat_core::fd::CompatKind::Other {
            if let Some(state) = proc::linux_userfault_state(pid, entry.handle) {
                return linux_userfault_read(pid, fd, state, args[1], len);
            }
        }
        if entry.kind == compat_core::fd::CompatKind::Socket {
            if !entry.rights.contains(kernel_core::object::Rights::READ) {
                return Err(CompatErrno::BadFd);
            }
            return linux_socket_read(pid, fd, entry.handle, args[1], len, false);
        }
        if entry.kind == compat_core::fd::CompatKind::Device
            && proc::linux_ashmem_is_regular(pid, entry.handle) == Some(true)
        {
            if !entry.rights.contains(kernel_core::object::Rights::READ) {
                return Err(CompatErrno::BadFd);
            }
            let offset = proc::linux_fd_offset(pid, fd).ok_or(CompatErrno::BadFd)?;
            if len == 0 {
                return Ok(0);
            }
            let mut bytes = alloc::vec![0u8; len];
            let read = proc::linux_ashmem_read_from(pid, entry.handle, offset, &mut bytes)
                .map_err(ashmem_compat_error)?;
            if read != 0 {
                copy_to_user(args[1], &bytes[..read], read)
                    .map_err(|_| CompatErrno::Fault)?;
                if !proc::set_linux_fd_offset(pid, fd, offset + read as u64) {
                    return Err(CompatErrno::BadFd);
                }
            }
            return Ok(read as u64);
        }
    }
    if fd == 0 {
        authorize_console(pid, fd, false)?;
        if len == 0 {
            return Ok(0);
        }
        let requested = len.min(TERMINAL_READ);
        let destination = crate::kobj::with(|table| {
            proc::pin_user_in(table, pid, args[1], requested, true)
        })
        .map_err(|error| match error {
            proc::ProcError::OutOfFrames | proc::ProcError::MemoryQuota => {
                CompatErrno::NoMemory
            }
            _ => CompatErrno::Fault,
        })?;
        let (input, count) = read_console_input(pid, requested)?;
        if count != 0 {
            if !destination.write_at(0, &input[..count]) {
                return Err(CompatErrno::Fault);
            }
        }
        return Ok(count as u64);
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
    proc::linux_fanotify_notify(
        crate::linux_vfs::Node::File(file),
        0x1,
        proc::linux_pid(pid).unwrap_or(0),
    );
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
    let entry = proc::linux_fd(pid, fd).ok_or(CompatErrno::BadFd)?;
    if entry.handle == LINUX_PROC_MAPS_HANDLE {
        if !entry.rights.contains(kernel_core::object::Rights::READ) {
            return Err(CompatErrno::BadFd);
        }
        return linux_proc_maps_read(pid, fd, args[1], len, Some(args[3]));
    }
    if entry.handle == LINUX_PROC_STAT_HANDLE {
        if !entry.rights.contains(kernel_core::object::Rights::READ) {
            return Err(CompatErrno::BadFd);
        }
        return linux_proc_stat_read(pid, fd, args[1], len, Some(args[3]));
    }
    if entry.kind == compat_core::fd::CompatKind::Device
        && proc::linux_ashmem_is_regular(pid, entry.handle) == Some(true)
    {
        if !entry.rights.contains(kernel_core::object::Rights::READ) {
            return Err(CompatErrno::BadFd);
        }
        let mut bytes = alloc::vec![0u8; len];
        let read = proc::linux_ashmem_read_from(pid, entry.handle, args[3], &mut bytes)
            .map_err(ashmem_compat_error)?;
        let io = admit_process_io(pid, read as u64, 1)?;
        if read != 0 {
            copy_to_user(args[1], &bytes[..read], read)
                .map_err(|_| CompatErrno::Fault)?;
        }
        io.commit();
        return Ok(read as u64);
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
    proc::linux_fanotify_notify(
        crate::linux_vfs::Node::File(file),
        0x1,
        proc::linux_pid(pid).unwrap_or(0),
    );
    Ok(available as u64)
}

fn linux_proc_maps_read(
    pid: ObjId,
    fd: u32,
    destination: u64,
    len: usize,
    explicit_offset: Option<u64>,
) -> Result<u64, CompatErrno> {
    let maps = proc::linux_proc_maps(pid).ok_or(CompatErrno::NoProcess)?;
    let offset = explicit_offset
        .unwrap_or_else(|| proc::linux_fd_offset(pid, fd).unwrap_or(0));
    let offset = usize::try_from(offset).map_err(|_| CompatErrno::Invalid)?;
    let available = maps.len().saturating_sub(offset).min(len);
    let io = admit_process_io(pid, available as u64, 1)?;
    if available != 0 {
        copy_to_user(destination, &maps[offset..offset + available], available)
            .map_err(|_| CompatErrno::Fault)?;
    }
    io.commit();
    if explicit_offset.is_none()
        && !proc::set_linux_file_offset(pid, fd, (offset + available) as u64)
    {
        return Err(CompatErrno::BadFd);
    }
    Ok(available as u64)
}

fn linux_proc_stat_read(
    pid: ObjId,
    fd: u32,
    destination: u64,
    len: usize,
    explicit_offset: Option<u64>,
) -> Result<u64, CompatErrno> {
    let stat = proc::linux_proc_stat(pid).ok_or(CompatErrno::NoProcess)?;
    let offset = explicit_offset
        .unwrap_or_else(|| proc::linux_fd_offset(pid, fd).unwrap_or(0));
    let offset = usize::try_from(offset).map_err(|_| CompatErrno::Invalid)?;
    let available = stat.len().saturating_sub(offset).min(len);
    let io = admit_process_io(pid, available as u64, 1)?;
    if available != 0 {
        copy_to_user(destination, &stat[offset..offset + available], available)
            .map_err(|_| CompatErrno::Fault)?;
    }
    io.commit();
    if explicit_offset.is_none()
        && !proc::set_linux_file_offset(pid, fd, (offset + available) as u64)
    {
        return Err(CompatErrno::BadFd);
    }
    Ok(available as u64)
}

/// Implements bounded `pwrite64(2)` for a memfd regular file.
fn linux_pwrite64(pid: ObjId, args: [u64; 6]) -> Result<u64, CompatErrno> {
    const MAX_WRITE: usize = 1024 * 1024;
    let fd = u32::try_from(args[0]).map_err(|_| CompatErrno::BadFd)?;
    let len = usize::try_from(args[2])
        .map_err(|_| CompatErrno::Invalid)?
        .min(MAX_WRITE); // JASPER-HARDCODE-REVIEW: issue=35 source=linux-batch-partial-policy reason=return-bounded-pwrite-prefix
    let entry = proc::linux_fd(pid, fd).ok_or(CompatErrno::BadFd)?;
    if entry.kind != compat_core::fd::CompatKind::Device
        || proc::linux_ashmem_is_regular(pid, entry.handle) != Some(true)
        || !entry.rights.contains(kernel_core::object::Rights::WRITE)
    {
        return Err(CompatErrno::BadFd);
    }
    if len == 0 {
        return Ok(0);
    }
    let mut bytes = alloc::vec![0u8; len];
    copy_from_user(&mut bytes, args[1], len).map_err(|_| CompatErrno::Fault)?;
    let written = proc::linux_ashmem_write_from(pid, entry.handle, args[3], &bytes)
        .map_err(ashmem_compat_error)?;
    Ok(written as u64)
}

/// Implements `preadv(2)`, `pwritev(2)`, `preadv2(2)` and `pwritev2(2)` for a
/// memfd regular file. All iovec metadata and user ranges are validated before
/// the backing bytes or descriptor cursor can change.
fn linux_vectored_file_io(
    pid: ObjId,
    args: [u64; 6],
    write: bool,
    positioned: bool,
    version_two: bool,
) -> Result<u64, CompatErrno> {
    const MAX_IOVECS: usize = 16;
    const MAX_BYTES: usize = 1024 * 1024;
    const IOVEC_BYTES: usize = 16;
    const RWF_SUPPORTED: u64 = 0x1 | 0x2 | 0x4 | 0x8;

    let fd = u32::try_from(args[0]).map_err(|_| CompatErrno::BadFd)?;
    let count = usize::try_from(args[2]).map_err(|_| CompatErrno::Invalid)?;
    if count > MAX_IOVECS {
        return Err(CompatErrno::Invalid);
    }
    let flags = if version_two { args[4] } else { 0 };
    if flags & !RWF_SUPPORTED != 0 {
        return Err(CompatErrno::Invalid);
    }
    let entry = proc::linux_fd(pid, fd).ok_or(CompatErrno::BadFd)?;
    if entry.kind != compat_core::fd::CompatKind::Device
        || proc::linux_ashmem_is_regular(pid, entry.handle) != Some(true)
    {
        return Err(CompatErrno::BadFd);
    }
    let required = if write {
        kernel_core::object::Rights::WRITE
    } else {
        kernel_core::object::Rights::READ
    };
    if !entry.rights.contains(required) {
        return Err(CompatErrno::BadFd);
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
        if total > MAX_BYTES {
            return Err(CompatErrno::Invalid);
        }
        vectors.push((base, len));
    }
    let signed_offset = if positioned { args[3] as i64 } else { -1 };
    let uses_cursor = !positioned || signed_offset == -1;
    if positioned && signed_offset == -1 && !version_two {
        return Err(CompatErrno::Invalid);
    }
    let offset = if uses_cursor {
        proc::linux_fd_offset(pid, fd).ok_or(CompatErrno::BadFd)?
    } else if signed_offset < 0 {
        return Err(CompatErrno::Invalid);
    } else {
        args[3]
    };
    if total == 0 {
        return Ok(0);
    }
    if write {
        let mut bytes = alloc::vec![0u8; total];
        let mut input_offset = 0usize;
        for (base, len) in vectors {
            copy_from_user(&mut bytes[input_offset..input_offset + len], base, len)
                .map_err(|_| CompatErrno::Fault)?;
            input_offset += len;
        }
        let io = admit_process_io(pid, total as u64, 1)?;
        let written = proc::linux_ashmem_write_from(pid, entry.handle, offset, &bytes)
            .map_err(ashmem_compat_error)?;
        io.commit();
        if uses_cursor
            && written != 0
            && !proc::set_linux_fd_offset(pid, fd, offset + written as u64)
        {
            return Err(CompatErrno::BadFd);
        }
        return Ok(written as u64);
    }

    let mut bytes = alloc::vec![0u8; total];
    let read = proc::linux_ashmem_read_from(pid, entry.handle, offset, &mut bytes)
        .map_err(ashmem_compat_error)?;
    let io = admit_process_io(pid, read as u64, 1)?;
    let mut input_offset = 0usize;
    let mut remaining = read;
    let mut ranges = alloc::vec::Vec::with_capacity(vectors.len());
    for (base, len) in vectors {
        let take = remaining.min(len);
        if take != 0 {
            ranges.push((base, &bytes[input_offset..input_offset + take]));
            input_offset += take;
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
    if uses_cursor
        && read != 0
        && !proc::set_linux_fd_offset(pid, fd, offset + read as u64)
    {
        return Err(CompatErrno::BadFd);
    }
    Ok(read as u64)
}

/// Implements same-application `process_vm_readv/writev` without ptrace authority.
fn linux_process_vm_io(
    pid: ObjId,
    args: [u64; 6],
    write: bool,
) -> Result<u64, CompatErrno> {
    const MAX_PROCESS_VM: usize = 1024 * 1024;
    if args[5] != 0 {
        return Err(CompatErrno::Invalid);
    }
    let target_pid = u32::try_from(args[0]).map_err(|_| CompatErrno::Invalid)?;
    let target = proc::linux_process_for_pid(target_pid).ok_or(CompatErrno::NoProcess)?;
    let caller_application = proc::app(pid).ok_or(CompatErrno::Perm)?;
    let target_application = proc::app(target).ok_or(CompatErrno::NoProcess)?;
    if target != pid && caller_application != target_application {
        return Err(CompatErrno::Perm);
    }
    let local_count = usize::try_from(args[2]).map_err(|_| CompatErrno::Invalid)?;
    let remote_count = usize::try_from(args[4]).map_err(|_| CompatErrno::Invalid)?;
    let local = read_message_iovecs(pid, args[1], local_count, MAX_PROCESS_VM)?;
    let remote = read_message_iovecs(pid, args[3], remote_count, MAX_PROCESS_VM)?;
    let local_total = local.iter().map(|(_, length)| *length).sum::<usize>();
    let remote_total = remote.iter().map(|(_, length)| *length).sum::<usize>();
    let total = local_total.min(remote_total);
    let (source, destination, source_process, destination_process) = if write {
        (&local, &remote, pid, target)
    } else {
        (&remote, &local, target, pid)
    };
    let mut bytes = alloc::vec![0u8; total];
    let mut offset = 0usize;
    for (address, length) in source {
        if offset == total {
            break;
        }
        let take = (*length).min(total - offset);
        proc::read(
            source_process,
            *address,
            &mut bytes[offset..offset + take],
        )
            .map_err(|_| CompatErrno::Fault)?;
        offset += take;
    }
    offset = 0;
    for (address, length) in destination {
        if offset == total {
            break;
        }
        let take = (*length).min(total - offset);
        proc::write(
            destination_process,
            *address,
            &bytes[offset..offset + take],
        )
            .map_err(|_| CompatErrno::Fault)?;
        offset += take;
    }
    Ok(total as u64)
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
    if proc::linux_fd(pid, fd).is_some_and(|entry| {
        entry.kind == compat_core::fd::CompatKind::Device
            && proc::linux_ashmem_is_regular(pid, entry.handle) == Some(true)
    }) {
        return linux_vectored_file_io(pid, args, false, false, false);
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
        if total == 0 {
            return Ok(0);
        }
        let mut pinned = alloc::vec::Vec::with_capacity(vectors.len());
        for (base, len) in &vectors {
            let range = crate::kobj::with(|table| {
                proc::pin_user_in(table, pid, *base, *len, true)
            })
            .map_err(|error| match error {
                proc::ProcError::OutOfFrames | proc::ProcError::MemoryQuota => {
                    CompatErrno::NoMemory
                }
                _ => CompatErrno::Fault,
            })?;
            pinned.push((range, *len));
        }
        let (input, read_count) = read_console_input(pid, total)?;
        let mut input_offset = 0usize;
        for (range, len) in &pinned {
            let take = (read_count - input_offset).min(*len);
            if take != 0 {
                if !range.write_at(0, &input[input_offset..input_offset + take]) {
                    return Err(CompatErrno::Fault);
                }
                input_offset += take;
            }
            if input_offset == read_count {
                break;
            }
        }
        return Ok(read_count as u64);
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
    if entry.kind == compat_core::fd::CompatKind::Device
        && proc::linux_ashmem_is_regular(pid, entry.handle) == Some(true)
    {
        let current = proc::linux_fd_offset(pid, fd).ok_or(CompatErrno::BadFd)?;
        let (size, _, _) =
            proc::linux_ashmem_state(pid, entry.handle).ok_or(CompatErrno::BadFd)?;
        let target =
            compat_core::syscall::seek_target(current, size, args[1] as i64, args[2])
                .ok_or(CompatErrno::Invalid)?;
        if !proc::set_linux_fd_offset(pid, fd, target) {
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
    let mask = affinity.bits_u64().ok_or(CompatErrno::Invalid)?;
    copy_to_user(args[2], &mask.to_le_bytes(), KERNEL_MASK_BYTES)
        .map_err(|_| CompatErrno::Fault)?;
    Ok(KERNEL_MASK_BYTES as u64)
}

fn linux_sched_setaffinity(pid: ObjId, args: [u64; 6]) -> Result<u64, CompatErrno> {
    const KERNEL_MASK_BYTES: usize = 8;
    let size = usize::try_from(args[1]).map_err(|_| CompatErrno::Invalid)?;
    if size < KERNEL_MASK_BYTES {
        return Err(CompatErrno::Invalid);
    }
    let mut raw = [0u8; KERNEL_MASK_BYTES];
    copy_from_user(&mut raw, args[2], KERNEL_MASK_BYTES)
        .map_err(|_| CompatErrno::Fault)?;
    let mask = u64::from_le_bytes(raw);
    let online = sched::online_cpus();
    let mut set = kernel_core::smp::CpuSet::EMPTY;
    for cpu in 0..64 {
        if mask & (1u64 << cpu) == 0 {
            continue;
        }
        if cpu >= kernel_core::smp::MAX_CPUS || !online.contains(cpu) || !set.insert(cpu) {
            return Err(CompatErrno::Invalid);
        }
    }
    if set.is_empty() {
        return Err(CompatErrno::Invalid);
    }
    let task = if args[0] == 0 {
        sched::current().0
    } else {
        let tid = u32::try_from(args[0]).map_err(|_| CompatErrno::NoProcess)?;
        linux_task_for_tid(pid, tid).ok_or(CompatErrno::NoProcess)?
    };
    sched::set_affinity(task, set).map_err(|_| CompatErrno::Invalid)?;
    Ok(0)
}

/// Reports the compatibility scheduling policy for the current Linux process.
///
/// 兼容进程没有 Linux RT 策略，因此自身稳定报告 `SCHED_OTHER`；其他 PID 明确
/// 返回 `ESRCH`，不猜测 Jasper 调度类别与 Linux 策略的等价关系。
fn linux_sched_getscheduler(pid: ObjId, requested: u64) -> Result<u64, CompatErrno> {
    let current = u64::from(proc::linux_pid(pid).ok_or(CompatErrno::NoProcess)?);
    if requested == 0
        || requested == current
        || requested
            == u64::from(current_linux_tid(pid).ok_or(CompatErrno::NoProcess)?)
        || linux_tid_owned_by_process(pid, requested)
    {
        Ok(0)
    } else {
        Err(CompatErrno::NoProcess)
    }
}

fn linux_sched_getparam(pid: ObjId, args: [u64; 6]) -> Result<u64, CompatErrno> {
    let current = u64::from(proc::linux_pid(pid).ok_or(CompatErrno::NoProcess)?);
    if args[0] != 0
        && args[0] != current
        && args[0] != u64::from(current_linux_tid(pid).ok_or(CompatErrno::NoProcess)?)
        && !linux_tid_owned_by_process(pid, args[0])
    {
        return Err(CompatErrno::NoProcess);
    }
    copy_to_user(args[1], &0i32.to_le_bytes(), 4).map_err(|_| CompatErrno::Fault)?;
    Ok(0)
}

fn linux_priority_target(
    current: ObjId,
    which: u64,
    who: u64,
) -> Result<ObjId, CompatErrno> {
    const PRIO_PROCESS: u64 = 0;
    const PRIO_PGRP: u64 = 1;
    const PRIO_USER: u64 = 2;
    let current_pid = u64::from(proc::linux_pid(current).ok_or(CompatErrno::NoProcess)?);
    match which {
        PRIO_PROCESS if who == 0 || who == current_pid => Ok(current),
        PRIO_PROCESS => {
            let pid = u32::try_from(who).map_err(|_| CompatErrno::NoProcess)?;
            proc::linux_process_for_pid(pid)
                .or_else(|| linux_process_for_tid(pid))
                .ok_or(CompatErrno::NoProcess)
        }
        PRIO_PGRP if who == 0 || who == current_pid => Ok(current),
        PRIO_PGRP => Err(CompatErrno::NoProcess),
        PRIO_USER if who == 0 || who == compat_core::syscall::LINUX_COMPAT_UID => Ok(current),
        PRIO_USER => Err(CompatErrno::NoProcess),
        _ => Err(CompatErrno::Invalid),
    }
}

fn linux_getpriority(pid: ObjId, args: [u64; 6]) -> Result<u64, CompatErrno> {
    let target = linux_priority_target(pid, args[0], args[1])?;
    let nice = proc::linux_nice(target).ok_or(CompatErrno::NoProcess)?;
    Ok((20 - nice) as u64)
}

fn linux_setpriority(pid: ObjId, args: [u64; 6]) -> Result<u64, CompatErrno> {
    let target = linux_priority_target(pid, args[0], args[1])?;
    let nice = i32::try_from(args[2] as i32).map_err(|_| CompatErrno::Invalid)?;
    if !(-20..=19).contains(&nice) {
        return Err(CompatErrno::Invalid);
    }
    if proc::linux_set_nice(target, nice) {
        Ok(0)
    } else {
        Err(CompatErrno::NoProcess)
    }
}

fn linux_sched_priority(policy: u64, maximum: bool) -> Result<u64, CompatErrno> {
    const SCHED_OTHER: u64 = 0;
    const SCHED_FIFO: u64 = 1;
    const SCHED_RR: u64 = 2;
    const SCHED_BATCH: u64 = 3;
    const SCHED_IDLE: u64 = 5;
    match policy {
        SCHED_OTHER | SCHED_BATCH | SCHED_IDLE => Ok(0),
        SCHED_FIFO | SCHED_RR => Ok(if maximum { 99 } else { 1 }),
        _ => Err(CompatErrno::Invalid),
    }
}

fn linux_sched_setparam(pid: ObjId, args: [u64; 6]) -> Result<u64, CompatErrno> {
    let current = u64::from(proc::linux_pid(pid).ok_or(CompatErrno::NoProcess)?);
    if args[0] != 0 && args[0] != current {
        return Err(CompatErrno::NoProcess);
    }
    let mut priority = [0u8; 4];
    copy_from_user(&mut priority, args[1], 4).map_err(|_| CompatErrno::Fault)?;
    if i32::from_le_bytes(priority) != 0 {
        return Err(CompatErrno::Invalid);
    }
    Ok(0)
}

fn linux_sched_rr_get_interval(pid: ObjId, args: [u64; 6]) -> Result<u64, CompatErrno> {
    let current = u64::from(proc::linux_pid(pid).ok_or(CompatErrno::NoProcess)?);
    if args[0] != 0 && args[0] != current {
        return Err(CompatErrno::NoProcess);
    }
    let mut timespec = [0u8; 16];
    timespec[8..16].copy_from_slice(&2_000_000i64.to_le_bytes());
    copy_to_user(args[1], &timespec, timespec.len()).map_err(|_| CompatErrno::Fault)?;
    Ok(0)
}

fn linux_sched_target(pid: ObjId, requested: u64) -> Result<ObjId, CompatErrno> {
    let current = u64::from(proc::linux_pid(pid).ok_or(CompatErrno::NoProcess)?);
    if requested == 0 || requested == current {
        Ok(pid)
    } else {
        let target = u32::try_from(requested).map_err(|_| CompatErrno::NoProcess)?;
        proc::linux_process_for_pid(target).ok_or(CompatErrno::NoProcess)
    }
}

fn linux_sched_getattr(pid: ObjId, args: [u64; 6]) -> Result<u64, CompatErrno> {
    const SCHED_ATTR_BYTES: usize = 48;
    const SCHED_ATTR_BYTES_V2: usize = 56;
    const SCHED_OTHER: u32 = 0;
    const SCHED_FLAG_RESET_ON_FORK: u64 = 0x01;
    const SCHED_FLAG_UTIL_CLAMP_MIN: u64 = 0x20;
    const SCHED_FLAG_UTIL_CLAMP_MAX: u64 = 0x40;
    let target = linux_sched_target(pid, args[0])?;
    let size = usize::try_from(args[2]).map_err(|_| CompatErrno::Invalid)?;
    if size < SCHED_ATTR_BYTES || size > 4096 || args[3] != 0 {
        return Err(CompatErrno::Invalid);
    }
    let mut output = alloc::vec![0u8; size];
    output[0..4].copy_from_slice(&(size as u32).to_le_bytes());
    output[4..8].copy_from_slice(&SCHED_OTHER.to_le_bytes());
    let nice = proc::linux_nice(target).ok_or(CompatErrno::NoProcess)?;
    output[16..20].copy_from_slice(&nice.to_le_bytes());
    if size >= SCHED_ATTR_BYTES_V2 {
        let (reset_on_fork, util_min, util_max) =
            proc::linux_sched_attributes(target).ok_or(CompatErrno::NoProcess)?;
        let mut flags = 0u64;
        if reset_on_fork {
            flags |= SCHED_FLAG_RESET_ON_FORK;
        }
        if util_min != 0 {
            flags |= SCHED_FLAG_UTIL_CLAMP_MIN;
        }
        if util_max != 1024 {
            flags |= SCHED_FLAG_UTIL_CLAMP_MAX;
        }
        output[8..16].copy_from_slice(&flags.to_le_bytes());
        output[48..52].copy_from_slice(&u32::from(util_min).to_le_bytes());
        output[52..56].copy_from_slice(&u32::from(util_max).to_le_bytes());
    }
    copy_to_user(args[1], &output, output.len()).map_err(|_| CompatErrno::Fault)?;
    Ok(0)
}

fn linux_sched_setattr(pid: ObjId, args: [u64; 6]) -> Result<u64, CompatErrno> {
    const SCHED_ATTR_BYTES: usize = 48;
    const SCHED_ATTR_BYTES_V2: usize = 56;
    const SCHED_OTHER: u32 = 0;
    const SCHED_FLAG_RESET_ON_FORK: u64 = 0x01;
    const SCHED_FLAG_KEEP_PARAMS: u64 = 0x10;
    const SCHED_FLAG_UTIL_CLAMP_MIN: u64 = 0x20;
    const SCHED_FLAG_UTIL_CLAMP_MAX: u64 = 0x40;
    let target = linux_sched_target(pid, args[0])?;
    if args[2] != 0 {
        return Err(CompatErrno::Invalid);
    }
    let mut raw = [0u8; SCHED_ATTR_BYTES_V2];
    copy_from_user(&mut raw[..8], args[1], 8).map_err(|_| CompatErrno::Fault)?;
    let size = u32::from_le_bytes(raw[0..4].try_into().unwrap()) as usize;
    if !(SCHED_ATTR_BYTES..=4096).contains(&size) {
        return Err(CompatErrno::Invalid);
    }
    let copied = size.min(SCHED_ATTR_BYTES_V2);
    copy_from_user(&mut raw[..copied], args[1], copied).map_err(|_| CompatErrno::Fault)?;
    let policy = u32::from_le_bytes(raw[4..8].try_into().unwrap());
    let attr_flags = u64::from_le_bytes(raw[8..16].try_into().unwrap());
    let nice = i32::from_le_bytes(raw[16..20].try_into().unwrap());
    let priority = u32::from_le_bytes(raw[20..24].try_into().unwrap());
    let runtime = u64::from_le_bytes(raw[24..32].try_into().unwrap());
    let deadline = u64::from_le_bytes(raw[32..40].try_into().unwrap());
    let period = u64::from_le_bytes(raw[40..48].try_into().unwrap());
    let supported_flags = SCHED_FLAG_RESET_ON_FORK
        | SCHED_FLAG_KEEP_PARAMS
        | SCHED_FLAG_UTIL_CLAMP_MIN
        | SCHED_FLAG_UTIL_CLAMP_MAX;
    let keep_params = attr_flags & SCHED_FLAG_KEEP_PARAMS != 0;
    if policy != SCHED_OTHER
        || attr_flags & !supported_flags != 0
        || !keep_params && priority != 0
        || !keep_params && (runtime != 0 || deadline != 0 || period != 0)
        || !(-20..=19).contains(&nice)
    {
        return if policy != SCHED_OTHER
            || attr_flags & !supported_flags != 0
        {
            Err(CompatErrno::NotSupported)
        } else {
            Err(CompatErrno::Invalid)
        };
    }
    let (_, previous_util_min, previous_util_max) =
        proc::linux_sched_attributes(target).ok_or(CompatErrno::NoProcess)?;
    let util_min = if size >= SCHED_ATTR_BYTES_V2
        && attr_flags & SCHED_FLAG_UTIL_CLAMP_MIN != 0
    {
        u16::try_from(u32::from_le_bytes(raw[48..52].try_into().unwrap()))
            .map_err(|_| CompatErrno::Invalid)?
    } else {
        previous_util_min
    };
    let util_max = if size >= SCHED_ATTR_BYTES_V2
        && attr_flags & SCHED_FLAG_UTIL_CLAMP_MAX != 0
    {
        u16::try_from(u32::from_le_bytes(raw[52..56].try_into().unwrap()))
            .map_err(|_| CompatErrno::Invalid)?
    } else {
        previous_util_max
    };
    if util_min > 1024 || util_max > 1024 || util_min > util_max {
        return Err(CompatErrno::Invalid);
    }
    let reset_on_fork = attr_flags & SCHED_FLAG_RESET_ON_FORK != 0;
    if proc::linux_set_sched_attributes(target, reset_on_fork, util_min, util_max)
        && (keep_params || proc::linux_set_nice(target, nice))
    {
        Ok(0)
    } else {
        Err(CompatErrno::NoProcess)
    }
}

fn linux_sched_setscheduler(pid: ObjId, args: [u64; 6]) -> Result<u64, CompatErrno> {
    let current = u64::from(proc::linux_pid(pid).ok_or(CompatErrno::NoProcess)?);
    if args[0] != 0 && args[0] != current {
        return Err(CompatErrno::NoProcess);
    }
    if args[1] != 0 {
        return Err(CompatErrno::Perm);
    }
    let mut priority = [0u8; 4];
    copy_from_user(&mut priority, args[2], 4).map_err(|_| CompatErrno::Fault)?;
    if i32::from_le_bytes(priority) != 0 {
        return Err(CompatErrno::Invalid);
    }
    Ok(0)
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

fn linux_user_range_valid(start: u64, end: u64) -> bool {
    (start >= crate::arch::USER_WINDOW.0 && end <= crate::arch::USER_WINDOW.1)
        || (crate::arch::LOW_USER_WINDOW.1 > crate::arch::LOW_USER_WINDOW.0
            && start >= crate::arch::LOW_USER_WINDOW.0
            && end <= crate::arch::LOW_USER_WINDOW.1)
}

/// Maps a bounded file-backed or anonymous private compatibility region.
///
/// 支持真实 libc 文件和匿名私有映射；拒绝写执行同开、越界、未对齐文件偏移、
/// 未知非私有标志和与已有映射冲突的 `MAP_FIXED`。失败会撤销本次全部页。
fn linux_mmap(pid: ObjId, args: [u64; 6]) -> Result<u64, CompatErrno> {
    const PAGE: u64 = kernel_core::frame::FRAME_SIZE;
    // Bionic's linker reserves a large address-space arena before it maps
    // individual DSOs with MAP_FIXED.  Keep the reservation bounded while
    // accepting the 70+ MiB range used by Android 14.
    const MAX_MAP_BYTES: u64 = 16 * 1024 * 1024 * 1024;
    const MAP_SHARED: u64 = 0x01;
    const MAP_PRIVATE: u64 = 0x02;
    const MAP_FIXED: u64 = 0x10;
    const MAP_ANONYMOUS: u64 = 0x20;
    const MAP_32BIT: u64 = 0x40;
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
    let sharing = args[3] & (MAP_SHARED | MAP_PRIVATE);
    if sharing == 0
        || sharing == (MAP_SHARED | MAP_PRIVATE)
        || args[3]
            & !(MAP_SHARED
                | MAP_PRIVATE
                | MAP_FIXED
                | MAP_ANONYMOUS
                | MAP_32BIT
                | MAP_DENYWRITE
                | MAP_NORESERVE
                | MAP_STACK)
            != 0
        || args[5] % PAGE != 0
    {
        return Err(CompatErrno::Invalid);
    }

    let anonymous = args[3] & MAP_ANONYMOUS != 0;
    let map32 = args[3] & MAP_32BIT != 0;
    let explicit_low = args[0] != 0
        && args[0] >= crate::arch::LOW_USER_WINDOW.0
        && args[0] < crate::arch::LOW_USER_WINDOW.1;
    let use_low_window = map32 || explicit_low;
    let mut ashmem_handle = None;
    let mut ashmem_regular = false;
    let file = if anonymous {
        None
    } else {
        let fd = u32::try_from(args[4]).map_err(|_| CompatErrno::BadFd)?;
        let entry = proc::linux_fd(pid, fd).ok_or(CompatErrno::BadFd)?;
        if entry.kind == compat_core::fd::CompatKind::Device
            && proc::linux_ashmem_state(pid, entry.handle).is_some()
        {
            ashmem_handle = Some(entry.handle);
            ashmem_regular =
                proc::linux_ashmem_is_regular(pid, entry.handle).unwrap_or(false);
            None
        } else {
        let (handle, _) = proc::linux_file_state(pid, fd).ok_or(CompatErrno::BadFd)?;
            Some(crate::linux_vfs::FileId::from_handle(handle).ok_or(CompatErrno::BadFd)?)
        }
    };
    if ashmem_handle.is_some() && !ashmem_regular && args[3] & MAP_SHARED == 0 {
        return Err(CompatErrno::Invalid);
    }
    if !anonymous
        && ashmem_handle.is_none()
        && args[3] & MAP_SHARED != 0
        && args[2] & PROT_WRITE != 0
    {
        return Err(CompatErrno::Access);
    }
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
    let (window_start, window_end) = if use_low_window {
        crate::arch::LOW_USER_WINDOW
    } else {
        crate::arch::USER_WINDOW
    };
    let cursor = if use_low_window {
        proc::linux_mmap32_cursor(pid)
    } else {
        proc::linux_mmap_cursor(pid)
    }
    .ok_or(CompatErrno::NoSys)?;
    let mut requested = if args[0] == 0 {
        cursor
    } else {
        align_down(args[0], PAGE)
    };
    if requested < window_start
        || requested
            .checked_add(rounded)
            .is_none_or(|end| end > window_end)
    {
        return Err(CompatErrno::NoMemory);
    }
    if args[0] == 0 {
        requested = proc::linux_next_free_start(pid, requested, rounded)
            .ok_or(CompatErrno::NoMemory)?;
        if requested < window_start
            || requested
                .checked_add(rounded)
                .is_none_or(|end| end > window_end)
        {
            return Err(CompatErrno::NoMemory);
        }
    }
    if anonymous && args[2] == 0 {
        let end = requested
            .checked_add(rounded)
            .ok_or(CompatErrno::NoMemory)?;
        if args[3] & MAP_FIXED != 0 {
            let _ = proc::linux_remove_reserved_range(pid, requested, end);
        }
        if proc::linux_reserve_range(pid, requested, end).is_err() {
            #[cfg(any(
                feature = "android-ecosystem-verify",
                feature = "android-art-verify"
            ))]
            crate::kprintln!(
                "[JSR-ANDROID-MMAP] reserve-fail start={} end={} debug={:?}",
                requested,
                end,
                proc::linux_range_debug(pid)
            );
            #[cfg(any(
                feature = "android-ecosystem-verify",
                feature = "android-art-verify"
            ))]
            crate::kprintln!(
                "[JSR-ANDROID-MMAP] reservation-overlap={:?}",
                proc::linux_reservation_overlap(pid, requested, end)
            );
            return Err(CompatErrno::NoMemory);
        }
        let advanced = if use_low_window {
            proc::set_linux_mmap32_cursor(pid, end)
        } else {
            proc::set_linux_mmap_cursor(pid, end)
        };
        if !advanced {
            let _ = proc::linux_remove_reserved_range(pid, requested, end);
            return Err(CompatErrno::NoSys);
        }
        return Ok(requested);
    }
    if args[3] & MAP_FIXED != 0 {
        // MAP_FIXED replaces prior mappings by contract. The source bytes remain available
        // in the immutable virtual file, so a later mapping failure cannot expose stale pages.
        let _ = proc::linux_remove_reserved_range(
            pid,
            requested,
            requested + rounded,
        );
        let mut page = requested;
        while page < requested + rounded {
            if proc::page_flags(pid, page).is_some() {
                if !proc::unmap_shared_page(pid, page).map_err(|_| CompatErrno::NoMemory)? {
                    proc::unmap_page(pid, page).map_err(|_| CompatErrno::NoMemory)?;
                }
            }
            page += PAGE;
        }
    }
    let mut start = requested;
    while start < window_end.saturating_sub(rounded) {
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
    if start + rounded > window_end {
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
    if let Some(handle) = ashmem_handle {
        if args[2] & PROT_WRITE != 0
            && proc::linux_ashmem_get_seals(pid, handle)
                .is_some_and(|seals| seals & (8 | 16) != 0)
        {
            return Err(CompatErrno::Perm);
        }
        let backing_offset =
            if proc::linux_io_uring_state(pid, handle).is_some() {
                proc::linux_io_uring_mmap_offset(pid, handle, args[5])
                    .ok_or(CompatErrno::Invalid)?
            } else {
                args[5]
            };
        proc::linux_ashmem_map(
            pid,
            handle,
            start,
            rounded,
            args[2] as u32,
            backing_offset,
        )
        .map_err(|error| match error {
            proc::LinuxAshmemError::Permission => CompatErrno::Perm,
            proc::LinuxAshmemError::Busy => CompatErrno::Busy,
            proc::LinuxAshmemError::Invalid => CompatErrno::Invalid,
            proc::LinuxAshmemError::NoMemory => CompatErrno::NoMemory,
            proc::LinuxAshmemError::NotAshmem => CompatErrno::BadFd,
            proc::LinuxAshmemError::Exists => CompatErrno::Exists,
            proc::LinuxAshmemError::NoKey => CompatErrno::NoKey,
            proc::LinuxAshmemError::NotSupported => CompatErrno::NotSupported,
        })?;
        let advanced = if use_low_window {
            proc::set_linux_mmap32_cursor(pid, start + rounded)
        } else {
            proc::set_linux_mmap_cursor(pid, start + rounded)
        };
        if !advanced {
            return Err(CompatErrno::NoSys);
        }
        return Ok(start);
    }
    if anonymous && args[3] & MAP_SHARED != 0 {
        let object =
            proc::linux_create_shared_memory(pid, rounded).ok_or(CompatErrno::NoMemory)?;
        proc::linux_shared_memory_map(pid, &object, start, rounded, writable)
            .map_err(|_| CompatErrno::NoMemory)?;
        let advanced = if use_low_window {
            proc::set_linux_mmap32_cursor(pid, start + rounded)
        } else {
            proc::set_linux_mmap_cursor(pid, start + rounded)
        };
        if !advanced {
            let mut page = start;
            while page < start + rounded {
                let _ = proc::unmap_shared_page(pid, page);
                page += PAGE;
            }
            return Err(CompatErrno::NoSys);
        }
        return Ok(start);
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
        for (index, address) in mapped.iter().copied().enumerate() {
            let file_offset = args[5]
                .checked_add((index as u64) * PAGE)
                .ok_or(CompatErrno::Invalid)?;
            if !proc::set_linux_mapping_file(
                pid,
                address,
                file,
                file_offset,
                args[3] & MAP_SHARED != 0,
            ) {
                for address in mapped.iter().rev().copied() {
                    let _ = proc::unmap_page(pid, address);
                }
                return Err(CompatErrno::NoSys);
            }
        }
    }
    let advanced = if use_low_window {
        proc::set_linux_mmap32_cursor(pid, start + rounded)
    } else {
        proc::set_linux_mmap_cursor(pid, start + rounded)
    };
    if !advanced {
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

fn install_linux_file_page(
    pid: ObjId,
    address: u64,
    file: crate::linux_vfs::FileId,
    file_offset: u64,
    flags: MapFlags,
    shared: bool,
) -> Result<(), CompatErrno> {
    const PAGE: u64 = kernel_core::frame::FRAME_SIZE;
    if proc::map_new(pid, address, flags).is_err() {
        return Err(CompatErrno::NoMemory);
    }
    let source = file.bytes();
    let offset = usize::try_from(file_offset).map_err(|_| CompatErrno::Invalid)?;
    if offset < source.len() {
        let count = (source.len() - offset).min(PAGE as usize);
        if proc::write(pid, address, &source[offset..offset + count]).is_err() {
            let _ = proc::unmap_page(pid, address);
            return Err(CompatErrno::Fault);
        }
    }
    if !proc::set_linux_mapping_file(pid, address, file, file_offset, shared) {
        let _ = proc::unmap_page(pid, address);
        return Err(CompatErrno::NoSys);
    }
    Ok(())
}

/// Remaps a read-only `MAP_SHARED` regular-file window onto a different file
/// page offset. The bounded virtual filesystem keeps a stable file identity,
/// so each destination page can be rebuilt transactionally.
fn linux_remap_file_pages(pid: ObjId, args: [u64; 6]) -> Result<u64, CompatErrno> {
    const PAGE: u64 = kernel_core::frame::FRAME_SIZE;
    const MAX_REMAP_BYTES: u64 = 64 * 1024 * 1024;
    let start = args[0];
    let size = args[1];
    let flags = args[4];
    let file_page = args[3];
    if start % PAGE != 0
        || size == 0
        || size > MAX_REMAP_BYTES
        || flags != 0
        || start < crate::arch::USER_WINDOW.0
    {
        return Err(CompatErrno::Invalid);
    }
    let rounded = size.checked_add(PAGE - 1).ok_or(CompatErrno::Invalid)? & !(PAGE - 1);
    let end = start.checked_add(rounded).ok_or(CompatErrno::Invalid)?;
    if end > crate::arch::USER_WINDOW.1 {
        return Err(CompatErrno::Invalid);
    }
    if proc::linux_range_is_sealed(pid, start, end) {
        return Err(CompatErrno::Perm);
    }
    let (file, _, shared) =
        proc::linux_mapping_file(pid, start).ok_or(CompatErrno::Invalid)?;
    if !shared {
        return Err(CompatErrno::Invalid);
    }
    let mapping_flags =
        proc::linux_mapping_flags(pid, start).ok_or(CompatErrno::Invalid)?;
    let mut previous = alloc::vec::Vec::new();
    previous
        .try_reserve((rounded / PAGE) as usize)
        .map_err(|_| CompatErrno::NoMemory)?;
    let mut page = start;
    while page < end {
        let current_flags =
            proc::linux_mapping_flags(pid, page).ok_or(CompatErrno::Invalid)?;
        let (current_file, current_offset, current_shared) =
            proc::linux_mapping_file(pid, page).ok_or(CompatErrno::Invalid)?;
        if current_file != file
            || !current_shared
            || current_flags != mapping_flags
            || proc::page_flags(pid, page).is_none()
        {
            return Err(CompatErrno::Invalid);
        }
        previous.push((page, current_offset));
        page += PAGE;
    }

    let mut index = 0u64;
    let mut page = start;
    while page < end {
        let new_offset = file_page
            .checked_mul(PAGE)
            .and_then(|offset| offset.checked_add(index.checked_mul(PAGE)?))
            .ok_or(CompatErrno::Invalid)?;
        if proc::unmap_page(pid, page).is_err()
            || install_linux_file_page(pid, page, file, new_offset, mapping_flags, true).is_err()
        {
            for (restore_page, restore_offset) in previous.iter().copied() {
                let _ = proc::unmap_page(pid, restore_page);
                let _ = install_linux_file_page(
                    pid,
                    restore_page,
                    file,
                    restore_offset,
                    mapping_flags,
                    true,
                );
            }
            return Err(CompatErrno::NoMemory);
        }
        index += 1;
        page += PAGE;
    }
    Ok(0)
}

fn linux_munmap(pid: ObjId, args: [u64; 6]) -> Result<u64, CompatErrno> {
    const PAGE: u64 = kernel_core::frame::FRAME_SIZE;
    if args[0] % PAGE != 0 || args[1] == 0 {
        return Err(CompatErrno::Invalid);
    }
    let rounded = args[1]
        .checked_add(PAGE - 1)
        .ok_or(CompatErrno::Invalid)?
        & !(PAGE - 1);
    let end = args[0].checked_add(rounded).ok_or(CompatErrno::Invalid)?;
    if end > crate::arch::USER_WINDOW.1 {
        return Err(CompatErrno::Invalid);
    }
    if proc::linux_range_is_sealed(pid, args[0], end) {
        return Err(CompatErrno::Perm);
    }
    let was_reserved = proc::linux_range_is_reserved(pid, args[0], end);
    if args[2] == 0 && was_reserved {
        return Ok(0);
    }
    let _ = proc::linux_remove_reserved_range(pid, args[0], end);
    if proc::linux_unmap_private_range(pid, args[0], end).map_err(|_| CompatErrno::NoMemory)? {
        return Ok(0);
    }
    let mut page = args[0];
    while page < end {
        if proc::page_flags(pid, page).is_none() {
            page += PAGE;
            continue;
        }
        if !proc::unmap_shared_page(pid, page).map_err(|_| CompatErrno::NoMemory)? {
            proc::unmap_page(pid, page).map_err(|_| CompatErrno::NoMemory)?;
        }
        page += PAGE;
    }
    Ok(0)
}

/// Resizes or moves one anonymous private Linux mapping. Shared/device
/// mappings and MREMAP_DONTUNMAP require backing-specific semantics and fail
/// closed until those paths are implemented.
fn linux_mremap(pid: ObjId, args: [u64; 6]) -> Result<u64, CompatErrno> {
    const PAGE: u64 = kernel_core::frame::FRAME_SIZE;
    const MREMAP_MAYMOVE: u64 = 0x1;
    const MREMAP_FIXED: u64 = 0x2;
    const MREMAP_DONTUNMAP: u64 = 0x4;

    let old_address = args[0];
    let old_size = args[1];
    let new_size = args[2];
    let flags = args[3];
    let new_address = args[4];
    if old_address % PAGE != 0
        || old_size == 0
        || new_size == 0
        || flags & !(MREMAP_MAYMOVE | MREMAP_FIXED | MREMAP_DONTUNMAP) != 0
        || flags & MREMAP_DONTUNMAP != 0
        || flags & MREMAP_FIXED != 0
            && (flags & MREMAP_MAYMOVE == 0 || new_address % PAGE != 0)
    {
        return Err(CompatErrno::Invalid);
    }
    let old_rounded = old_size
        .checked_add(PAGE - 1)
        .ok_or(CompatErrno::Invalid)?
        & !(PAGE - 1);
    let new_rounded = new_size
        .checked_add(PAGE - 1)
        .ok_or(CompatErrno::Invalid)?
        & !(PAGE - 1);
    let old_end = old_address
        .checked_add(old_rounded)
        .ok_or(CompatErrno::Invalid)?;
    if proc::linux_range_is_sealed(pid, old_address, old_end) {
        return Err(CompatErrno::Perm);
    }
    let new_end = old_address
        .checked_add(new_rounded)
        .ok_or(CompatErrno::Invalid)?;
    if !linux_user_range_valid(old_address, new_end)
        || proc::linux_page_is_shared(pid, old_address)
    {
        return Err(CompatErrno::NoMemory);
    }
    let mapping_flags =
        proc::linux_mapping_flags(pid, old_address).ok_or(CompatErrno::Invalid)?;
    let mut page = old_address;
    while page < old_end {
        if proc::page_flags(pid, page).is_none()
            || proc::linux_page_is_shared(pid, page)
        {
            return Err(CompatErrno::Invalid);
        }
        page += PAGE;
    }

    let in_place = new_address == 0 || new_address == old_address;
    if in_place {
        if new_rounded <= old_rounded {
            let mut page = old_address + new_rounded;
            while page < old_end {
                proc::unmap_page(pid, page).map_err(|_| CompatErrno::NoMemory)?;
                page += PAGE;
            }
            return Ok(old_address);
        }
        let mut free = true;
        let mut page = old_end;
        while page < new_end {
            if proc::page_flags(pid, page).is_some() {
                free = false;
                break;
            }
            page += PAGE;
        }
        if free {
            let mut mapped = alloc::vec::Vec::new();
            let mut page = old_end;
            while page < new_end {
                if proc::map_new(pid, page, mapping_flags).is_err() {
                    for address in mapped.into_iter().rev() {
                        let _ = proc::unmap_page(pid, address);
                    }
                    return Err(CompatErrno::NoMemory);
                }
                mapped.push(page);
                page += PAGE;
            }
            if new_end < crate::arch::LOW_USER_WINDOW.1 {
                let _ = proc::set_linux_mmap32_cursor(
                    pid,
                    new_end.max(proc::linux_mmap32_cursor(pid).unwrap_or(0)),
                );
            } else {
                let _ = proc::set_linux_mmap_cursor(
                    pid,
                    new_end.max(proc::linux_mmap_cursor(pid).unwrap_or(0)),
                );
            }
            return Ok(old_address);
        }
        if flags & MREMAP_MAYMOVE == 0 {
            return Err(CompatErrno::NoMemory);
        }
    }

    let mut target = if flags & MREMAP_FIXED != 0 {
        new_address
    } else if new_address != 0 {
        align_down(new_address, PAGE)
    } else {
        proc::linux_mmap_cursor(pid).ok_or(CompatErrno::NoSys)?
    };
    loop {
        let target_end = target
            .checked_add(new_rounded)
            .ok_or(CompatErrno::NoMemory)?;
        let overlaps_old = target < old_end && old_address < target_end;
        if linux_user_range_valid(target, target_end) && !overlaps_old {
            if flags & MREMAP_FIXED != 0 {
                break;
            }
            let mut free = true;
            let mut page = target;
            while page < target_end {
                if proc::page_flags(pid, page).is_some() {
                    free = false;
                    break;
                }
                page += PAGE;
            }
            if free {
                break;
            }
        }
        if flags & MREMAP_FIXED != 0 {
            return Err(CompatErrno::NoMemory);
        }
        target = target.checked_add(new_rounded).ok_or(CompatErrno::NoMemory)?;
    }

    let target_end = target
        .checked_add(new_rounded)
        .ok_or(CompatErrno::NoMemory)?;
    let target_was_reserved = proc::linux_range_is_reserved(pid, target, target_end);
    if flags & MREMAP_FIXED != 0 {
        let _ = proc::linux_remove_reserved_range(pid, target, target_end);
        let mut page = target;
        while page < target_end {
            if proc::page_flags(pid, page).is_some() {
                if !proc::unmap_shared_page(pid, page).map_err(|_| CompatErrno::NoMemory)? {
                    proc::unmap_page(pid, page).map_err(|_| CompatErrno::NoMemory)?;
                }
            }
            page += PAGE;
        }
    }
    let mut mapped = alloc::vec::Vec::new();
    let mut page = target;
    while page < target_end {
        if let Err(_error) = proc::map_new(pid, page, mapping_flags) {
            #[cfg(any(
                feature = "android-ecosystem-verify",
                feature = "android-art-verify"
            ))]
            crate::kprintln!(
                "[JSR-ANDROID-MREMAP] map-fail source={} target={} pages={} error={:?}",
                old_address,
                target,
                new_rounded / PAGE,
                _error
            );
            for address in mapped.into_iter().rev() {
                let _ = proc::unmap_page(pid, address);
            }
            if target_was_reserved {
                let _ = proc::linux_reserve_range(pid, target, target_end);
            }
            return Err(CompatErrno::NoMemory);
        }
        mapped.push(page);
        page += PAGE;
    }
    let copy_size = old_rounded.min(new_rounded);
    let mut copied = 0u64;
    let mut buffer = [0u8; 4096];
    while copied < copy_size {
        let chunk = (copy_size - copied).min(4096) as usize;
        if proc::read(pid, old_address + copied, &mut buffer[..chunk]).is_err()
            || proc::write(pid, target + copied, &buffer[..chunk]).is_err()
        {
            for address in mapped.into_iter().rev() {
                let _ = proc::unmap_page(pid, address);
            }
            if target_was_reserved {
                let _ = proc::linux_reserve_range(pid, target, target_end);
            }
            return Err(CompatErrno::Fault);
        }
        copied += chunk as u64;
    }
    let mut page = old_address;
    while page < old_end {
        if proc::unmap_page(pid, page).is_err() {
            for address in mapped.into_iter().rev() {
                let _ = proc::unmap_page(pid, address);
            }
            if target_was_reserved {
                let _ = proc::linux_reserve_range(pid, target, target_end);
            }
            return Err(CompatErrno::NoMemory);
        }
        page += PAGE;
    }
    if target < crate::arch::LOW_USER_WINDOW.1 {
        let _ = proc::set_linux_mmap32_cursor(
            pid,
            (target + new_rounded).max(proc::linux_mmap32_cursor(pid).unwrap_or(0)),
        );
    } else {
        let _ = proc::set_linux_mmap_cursor(
            pid,
            (target + new_rounded).max(proc::linux_mmap_cursor(pid).unwrap_or(0)),
        );
    }
    Ok(target)
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
    {
        return Err(CompatErrno::Invalid);
    }
    let end = args[0].checked_add(args[1]).ok_or(CompatErrno::Invalid)?;
    if end > crate::arch::USER_WINDOW.1 {
        return Err(CompatErrno::Invalid);
    }
    if proc::linux_range_is_sealed(pid, args[0], end) {
        return Err(CompatErrno::Perm);
    }
    let materialized = if args[2] != 0 {
        proc::linux_materialize_reserved(
            pid,
            args[0],
            end,
            args[2] & PROT_WRITE != 0,
        )
        .map_err(|error| {
            #[cfg(any(
                feature = "android-ecosystem-verify",
                feature = "android-art-verify",
                feature = "vulkan-metal2vulkan-verify"
            ))]
            crate::kprintln!(
                "[JSR-ANDROID-MPROTECT] materialize-fail start={} end={} error={:?} free_frames={} usable_frames={} memory_caps={:?}",
                args[0],
                end,
                error,
                crate::mm::frame::free_frames(),
                crate::mm::frame::usable_frames(),
                proc::memory_capability_stats(pid)
            );
            CompatErrno::NoMemory
        })?
    } else {
        false
    };
    if materialized {
        if args[2] & PROT_EXEC != 0 {
            proc::protect_linux_range_access(
                pid,
                args[0],
                args[1] / PAGE,
                true,
                args[2] & PROT_WRITE != 0,
                true,
            )
            .map_err(|_| CompatErrno::NoMemory)?;
        }
        return Ok(0);
    }
    let pages = args[1] / PAGE;
    let mut done = 0;
    while done < pages {
        let chunk = (pages - done).min(proc::MAX_MAP_PAGES);
        proc::protect_linux_range_access(
            pid,
            args[0] + done * PAGE,
            chunk,
            args[2] != 0,
            args[2] & PROT_WRITE != 0,
            args[2] & PROT_EXEC != 0,
        )
        .map_err(|error| {
        #[cfg(any(
            feature = "android-ecosystem-verify",
            feature = "android-art-verify",
            feature = "vulkan-metal2vulkan-verify"
        ))]
        crate::kprintln!(
            "[JSR-ANDROID-MPROTECT] protect-fail start={:#x} end={:#x} flags={} error={:?} page_flags={:?} mapping_flags={:?} shared={}",
            args[0],
            end,
            args[2],
            error,
            proc::page_flags(pid, args[0]),
            proc::linux_mapping_flags(pid, args[0]),
            proc::linux_page_is_shared(pid, args[0])
        );
        CompatErrno::NoMemory
        })?;
        done += chunk;
    }
    Ok(0)
}

/// Implements page-range sealing for compatibility mappings.
fn linux_mseal(pid: ObjId, args: [u64; 6]) -> Result<u64, CompatErrno> {
    const PAGE: u64 = kernel_core::frame::FRAME_SIZE;
    if args[0] % PAGE != 0 || args[1] == 0 || args[2] != 0 {
        return Err(CompatErrno::Invalid);
    }
    let end = args[0]
        .checked_add(args[1])
        .filter(|end| args[0] >= crate::arch::USER_WINDOW.0 && *end <= crate::arch::USER_WINDOW.1)
        .ok_or(CompatErrno::NoMemory)?;
    let mut page = args[0];
    while page < end {
        if proc::page_flags(pid, page).is_none() {
            return Err(CompatErrno::NoMemory);
        }
        page += PAGE;
    }
    if proc::seal_linux_range(pid, args[0], end) {
        Ok(0)
    } else {
        Err(CompatErrno::NoSpace)
    }
}

fn linux_msync(pid: ObjId, args: [u64; 6]) -> Result<u64, CompatErrno> {
    const PAGE: u64 = kernel_core::frame::FRAME_SIZE;
    const MS_ASYNC: u64 = 0x1;
    const MS_INVALIDATE: u64 = 0x2;
    const MS_SYNC: u64 = 0x4;
    let address = args[0];
    let length = args[1];
    let flags = args[2];
    let mode = flags & (MS_ASYNC | MS_SYNC);
    if address % PAGE != 0
        || length == 0
        || flags & !(MS_ASYNC | MS_INVALIDATE | MS_SYNC) != 0
        || (mode != MS_ASYNC && mode != MS_SYNC)
    {
        return Err(CompatErrno::Invalid);
    }
    let end = address.checked_add(length).ok_or(CompatErrno::Invalid)?;
    if address < crate::arch::USER_WINDOW.0 || end > crate::arch::USER_WINDOW.1 {
        return Err(CompatErrno::NoMemory);
    }
    let rounded = length.checked_add(PAGE - 1).ok_or(CompatErrno::Invalid)? & !(PAGE - 1);
    let end = address.checked_add(rounded).ok_or(CompatErrno::Invalid)?;
    let mut page = address;
    while page < end {
        if proc::page_flags(pid, page).is_none() {
            return Err(CompatErrno::NoMemory);
        }
        page += PAGE;
    }
    Ok(0)
}

fn linux_mincore(pid: ObjId, args: [u64; 6]) -> Result<u64, CompatErrno> {
    const PAGE: u64 = kernel_core::frame::FRAME_SIZE;
    let address = args[0];
    let length = args[1];
    if address % PAGE != 0 || length == 0 || args[2] == 0 {
        return Err(CompatErrno::Invalid);
    }
    let rounded = length.checked_add(PAGE - 1).ok_or(CompatErrno::Invalid)? & !(PAGE - 1);
    let end = address
        .checked_add(rounded)
        .filter(|end| address >= crate::arch::USER_WINDOW.0 && *end <= crate::arch::USER_WINDOW.1)
        .ok_or(CompatErrno::NoMemory)?;
    let pages = rounded / PAGE;
    let mut residency = alloc::vec::Vec::new();
    residency
        .try_reserve(pages as usize)
        .map_err(|_| CompatErrno::NoMemory)?;
    let mut page = address;
    while page < end {
        if proc::page_flags(pid, page).is_none() {
            return Err(CompatErrno::NoMemory);
        }
        residency.push(1);
        page += PAGE;
    }
    copy_to_user(args[2], &residency, residency.len()).map_err(|_| CompatErrno::Fault)?;
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
    const MADV_FREE: u64 = 8;
    const MADV_DOFORK: u64 = 11;
    const MADV_HUGEPAGE: u64 = 14;
    const MADV_NOHUGEPAGE: u64 = 15;
    const MADV_DONTDUMP: u64 = 16;
    const MADV_DODUMP: u64 = 17;
    const MADV_KEEPONFORK: u64 = 19;
    const MADV_COLD: u64 = 20;
    const MADV_PAGEOUT: u64 = 21;
    const MADV_POPULATE_READ: u64 = 22;
    const MADV_POPULATE_WRITE: u64 = 23;
    const MADV_GUARD_INSTALL: u64 = 102;
    let address = args[0];
    let length = args[1];
    let advice = args[2];
    if address % PAGE != 0 || length == 0 {
        return Err(CompatErrno::Invalid);
    }
    let end = address.checked_add(length).ok_or(CompatErrno::Invalid)?;
    if !linux_user_range_valid(address, end) {
        return Err(CompatErrno::Invalid);
    }
    if matches!(advice, MADV_DONTNEED | MADV_GUARD_INSTALL)
        && proc::linux_range_is_sealed(pid, address, end)
    {
        return Err(CompatErrno::Perm);
    }
    match advice {
        MADV_NORMAL
        | MADV_RANDOM
        | MADV_SEQUENTIAL
        | MADV_WILLNEED
        | MADV_FREE
        | MADV_DOFORK
        | MADV_HUGEPAGE
        | MADV_NOHUGEPAGE
        | MADV_DONTDUMP
        | MADV_DODUMP
        | MADV_KEEPONFORK
        | MADV_COLD
        | MADV_PAGEOUT => Ok(0),
        MADV_POPULATE_READ | MADV_POPULATE_WRITE => {
            let require_write = advice == MADV_POPULATE_WRITE;
            let mut page = address;
            while page < end {
                let Some(flags) = proc::page_flags(pid, page) else {
                    return Err(CompatErrno::NoMemory);
                };
                if require_write && !flags.contains(MapFlags::WRITE) {
                    return Err(CompatErrno::Access);
                }
                page = page.saturating_add(PAGE);
            }
            Ok(0)
        }
        MADV_GUARD_INSTALL => {
            let pages = length.div_ceil(PAGE);
            for page in 0..pages {
                let _ = proc::unmap_page(pid, address + page * PAGE);
            }
            Ok(0)
        }
        MADV_DONTNEED => {
            let pages = length.div_ceil(PAGE);
            if proc::linux_userfault_registered(pid, address)
                && proc::linux_userfault_registered(pid, end.saturating_sub(1))
            {
                for page in 0..pages {
                    proc::unmap_page(pid, address + page * PAGE)
                        .map_err(|_| CompatErrno::NoMemory)?;
                }
                return Ok(0);
            }
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

/// Applies an iovec batch of memory advice through a same-process pidfd.
fn linux_process_madvise(pid: ObjId, args: [u64; 6]) -> Result<u64, CompatErrno> {
    const IOV_MAX: usize = 64;
    const MADV_COLD: u64 = 20;
    const MADV_PAGEOUT: u64 = 21;
    const MADV_COLLAPSE: u64 = 25;
    if args[4] != 0 {
        return Err(CompatErrno::Invalid);
    }
    let count = usize::try_from(args[2]).map_err(|_| CompatErrno::Invalid)?;
    if count == 0 || count > IOV_MAX {
        return Err(CompatErrno::Invalid);
    }
    let pidfd = u32::try_from(args[0]).map_err(|_| CompatErrno::BadFd)?;
    let entry = proc::linux_fd(pid, pidfd).ok_or(CompatErrno::BadFd)?;
    if entry.kind != compat_core::fd::CompatKind::Pidfd {
        return Err(CompatErrno::BadFd);
    }
    let target = ObjId::from_raw(entry.handle).ok_or(CompatErrno::NoProcess)?;
    let caller_application = proc::app(pid).ok_or(CompatErrno::Perm)?;
    let target_application = proc::app(target).ok_or(CompatErrno::NoProcess)?;
    if target != pid && caller_application != target_application {
        return Err(CompatErrno::Perm);
    }
    let bytes = count.checked_mul(16).ok_or(CompatErrno::Invalid)?;
    let mut raw = alloc::vec![0u8; bytes];
    copy_from_user(&mut raw, args[1], bytes).map_err(|_| CompatErrno::Fault)?;
    let mut vector = alloc::vec::Vec::new();
    vector
        .try_reserve_exact(count)
        .map_err(|_| CompatErrno::NoMemory)?;
    let mut total = 0u64;
    for iovec in raw.chunks_exact(16) {
        let address = u64::from_le_bytes(iovec[..8].try_into().unwrap());
        let length = u64::from_le_bytes(iovec[8..].try_into().unwrap());
        if length == 0 || address % kernel_core::frame::FRAME_SIZE != 0 {
            return Err(CompatErrno::Invalid);
        }
        total = total
            .checked_add(length)
            .filter(|total| *total <= i64::MAX as u64)
            .ok_or(CompatErrno::Invalid)?;
        vector.push((address, length));
    }
    let advice = i32::try_from(args[3]).map_err(|_| CompatErrno::Invalid)? as u64;
    let mut advised = 0u64;
    for (address, length) in vector {
        if matches!(advice, MADV_COLD | MADV_PAGEOUT | MADV_COLLAPSE) {
            advised = advised.saturating_add(length);
            continue;
        }
        let call = [address, length, advice, 0, 0, 0];
        if let Err(error) = linux_madvise(target, call) {
            return if advised == 0 { Err(error) } else { Ok(advised) };
        }
        advised = advised.saturating_add(length);
    }
    Ok(advised.min(total))
}

/// Reports that an exited pidfd target has already released its address space.
fn linux_process_mrelease(pid: ObjId, args: [u64; 6]) -> Result<u64, CompatErrno> {
    if args[1] != 0 {
        return Err(CompatErrno::Invalid);
    }
    let fd = u32::try_from(args[0]).map_err(|_| CompatErrno::BadFd)?;
    let entry = proc::linux_fd(pid, fd).ok_or(CompatErrno::BadFd)?;
    if entry.kind != compat_core::fd::CompatKind::Pidfd {
        return Err(CompatErrno::BadFd);
    }
    let target = ObjId::from_raw(entry.handle).ok_or(CompatErrno::NoProcess)?;
    let caller_app = proc::app(pid).ok_or(CompatErrno::Perm)?;
    let target_app = proc::app(target).ok_or(CompatErrno::NoProcess)?;
    if caller_app != target_app {
        return Err(CompatErrno::Perm);
    }
    let deadline = sched::timer_ticks().saturating_add(100);
    loop {
        match proc::state(target) {
            Some(proc::ProcState::Exited { .. }) | None => return Ok(0),
            Some(proc::ProcState::Exiting { .. }) | Some(proc::ProcState::Running) => {
                if proc::current_exiting() {
                    return Err(CompatErrno::Interrupted);
                }
                if sched::timer_ticks() >= deadline {
                    return Err(CompatErrno::TryAgain);
                }
                sched::sleep_until(sched::timer_ticks().saturating_add(5));
            }
        }
    }
}

/// Reports exhaustion because Jasper does not currently enable hardware PKU slots.
fn linux_pkey_alloc(args: [u64; 6]) -> Result<u64, CompatErrno> {
    if args[0] != 0 || args[1] & !3 != 0 {
        return Err(CompatErrno::Invalid);
    }
    Err(CompatErrno::NoSpace)
}

fn linux_pkey_free(_args: [u64; 6]) -> Result<u64, CompatErrno> {
    Err(CompatErrno::Invalid)
}

/// Key zero retains normal mprotect behavior without claiming PKU enforcement.
fn linux_pkey_mprotect(pid: ObjId, args: [u64; 6]) -> Result<u64, CompatErrno> {
    if args[3] as u32 as i32 != 0 {
        return Err(CompatErrno::Invalid);
    }
    linux_mprotect(pid, [args[0], args[1], args[2], 0, 0, 0])
}

/// Implements the process-scope memory barrier command subset.
fn linux_membarrier(args: [u64; 6]) -> Result<u64, CompatErrno> {
    const CMD_QUERY: u64 = 0;
    const CMD_GLOBAL: u64 = 1;
    const CMD_GLOBAL_EXPEDITED: u64 = 2;
    const CMD_REGISTER_GLOBAL_EXPEDITED: u64 = 4;
    const CMD_PRIVATE_EXPEDITED: u64 = 8;
    const CMD_REGISTER_PRIVATE_EXPEDITED: u64 = 16;
    const SUPPORTED: u64 =
        CMD_GLOBAL | CMD_GLOBAL_EXPEDITED | CMD_REGISTER_GLOBAL_EXPEDITED | CMD_PRIVATE_EXPEDITED
            | CMD_REGISTER_PRIVATE_EXPEDITED;
    if args[1] != 0 || args[2] != 0 && args[2] != u64::MAX {
        return Err(CompatErrno::Invalid);
    }
    match args[0] {
        CMD_QUERY => Ok(SUPPORTED),
        CMD_GLOBAL | CMD_GLOBAL_EXPEDITED | CMD_PRIVATE_EXPEDITED => {
            fence(Ordering::SeqCst);
            Ok(0)
        }
        CMD_REGISTER_GLOBAL_EXPEDITED | CMD_REGISTER_PRIVATE_EXPEDITED => Ok(0),
        _ => Err(CompatErrno::NotSupported),
    }
}

/// Validates one page-aligned resident-memory range.
fn linux_lock_range(pid: ObjId, args: [u64; 6]) -> Result<(), CompatErrno> {
    const PAGE: u64 = kernel_core::frame::FRAME_SIZE;
    const MAX_LOCK_BYTES: u64 = 64 * 1024 * 1024;
    let address = args[0];
    let length = args[1];
    if length == 0 {
        return Ok(());
    }
    if address % PAGE != 0 || length > MAX_LOCK_BYTES {
        return Err(CompatErrno::Invalid);
    }
    let rounded = length.checked_add(PAGE - 1).ok_or(CompatErrno::Invalid)? & !(PAGE - 1);
    let end = address
        .checked_add(rounded)
        .filter(|end| address >= crate::arch::USER_WINDOW.0 && *end <= crate::arch::USER_WINDOW.1)
        .ok_or(CompatErrno::NoMemory)?;
    let mut page = address;
    while page < end {
        if proc::page_flags(pid, page).is_none() {
            return Err(CompatErrno::NoMemory);
        }
        page += PAGE;
    }
    Ok(())
}

/// Implements `mlock(2)` and `mlock2(2)` over the non-reclaimable resident memory model.
fn linux_mlock(
    pid: ObjId,
    args: [u64; 6],
    mlock2: bool,
) -> Result<u64, CompatErrno> {
    const MLOCK_ONFAULT: u64 = 0x1;
    if mlock2 && args[2] & !MLOCK_ONFAULT != 0 {
        return Err(CompatErrno::Invalid);
    }
    linux_lock_range(pid, args)?;
    Ok(0)
}

/// Implements process-wide current/future memory locking.
fn linux_mlockall(args: [u64; 6]) -> Result<u64, CompatErrno> {
    const MCL_CURRENT: u64 = 0x1;
    const MCL_FUTURE: u64 = 0x2;
    const MCL_ONFAULT: u64 = 0x4;
    if args[0] == 0
        || args[0] & !(MCL_CURRENT | MCL_FUTURE | MCL_ONFAULT) != 0
        || args[0] & (MCL_CURRENT | MCL_FUTURE) == 0
    {
        return Err(CompatErrno::Invalid);
    }
    Ok(0)
}

/// Implements `munlock(2)`; the resident-memory model needs no page state change.
fn linux_munlock(_pid: ObjId, args: [u64; 6]) -> Result<u64, CompatErrno> {
    const PAGE: u64 = kernel_core::frame::FRAME_SIZE;
    if args[1] == 0 {
        return Ok(0);
    }
    if args[0] % PAGE != 0 {
        return Err(CompatErrno::Invalid);
    }
    args[0]
        .checked_add(args[1])
        .filter(|end| args[0] >= crate::arch::USER_WINDOW.0 && *end <= crate::arch::USER_WINDOW.1)
        .ok_or(CompatErrno::Invalid)?;
    Ok(0)
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
    const CLONE_VFORK: u64 = 0x0000_4000;
    if args[0] & CLONE_VM != 0 && args[0] & CLONE_VFORK != 0 {
        return linux_vfork(pid, args, user_ip, user_preserved);
    }
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
    #[cfg(feature = "vulkan-metal2vulkan-verify")]
    trace_path("execve", &resolved);
    let argv = linux_string_vector(args[1], 64, 64 * 1024)?;
    let envp = linux_string_vector(args[2], 64, 64 * 1024)?;
    let node = crate::linux_vfs::lookup_node(&resolved)
        .unwrap_or(crate::linux_vfs::Node::Executable(0));
    if !landlock_path_allows(
        pid,
        node,
        &resolved,
        LANDLOCK_ACCESS_FS_EXECUTE,
    ) {
        return Err(CompatErrno::Access);
    }
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
        let replaced = if jasper_compat_loader::parse(&executable)
            .ok()
            .is_some_and(|plan| plan.interpreter.is_none())
        {
            crate::compat_dynamic_demo::exec_static_program(
                pid,
                resolved,
                executable,
                argv,
                envp,
            )
        } else {
            crate::compat_dynamic_demo::exec_dynamic_program(
                pid,
                resolved,
                executable,
                interpreter,
                argv,
                envp,
            )
        };
        match replaced {
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

/// Implements the `AT_FDCWD` and no-flag `execveat(2)` subset.
fn linux_execveat(pid: ObjId, args: [u64; 6]) -> Result<(u64, u64), CompatErrno> {
    if !is_at_fdcwd(args[0]) || args[4] != 0 {
        return Err(CompatErrno::NotSupported);
    }
    linux_execve(pid, [args[1], args[2], args[3], 0, 0, 0])
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
    const CLONE_CLEAR_SIGHAND: u64 = 0x0000_0001_0000_0000;
    const CLONE_CHILD_CLEARTID: u64 = 0x0020_0000;
    const CLONE_CHILD_SETTID: u64 = 0x0100_0000;
    const CLONE_FLAGS: u64 = CLONE_CHILD_CLEARTID | CLONE_CHILD_SETTID;
    let flags = args[0];
    let signal = flags & 0xff;
    if args[1] != 0
        || signal != SIGCHLD
        || flags & !(CLONE_FLAGS | CLONE_CLEAR_SIGHAND | 0xff) != 0
        || args[2] != 0
    {
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
    .map_err(|error| {
        match error {
            proc::ProcError::NotTransferable => CompatErrno::NoSys,
            _ => CompatErrno::NoMemory,
        }
    })?;
    proc::linux_pid(child)
        .map(u64::from)
        .ok_or(CompatErrno::NoSys)
}

/// Implements legacy x86_64 `fork(2)` as a private address-space copy.
fn linux_fork(
    pid: ObjId,
    _args: [u64; 6],
    user_ip: Option<(u64, u64)>,
    preserved_regs: [u64; 6],
) -> Result<u64, CompatErrno> {
    const SIGCHLD: u64 = 17;
    linux_fork_clone(
        pid,
        [SIGCHLD, 0, 0, 0, 0, 0],
        user_ip,
        preserved_regs,
    )
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
    .map_err(|error| {
        match error {
            proc::ProcError::NotTransferable => CompatErrno::NoSys,
            _ => CompatErrno::NoMemory,
        }
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
    #[derive(Clone, Copy)]
    enum Target {
        Pid(Option<u32>),
        Group(u32),
    }
    let target = args[0] as i32;
    let target = match target {
        -1 => Target::Pid(None),
        0 => Target::Group(
            proc::linux_process_group_state(_pid)
                .ok_or(CompatErrno::NoProcess)?
                .0,
        ),
        value if value > 0 => Target::Pid(Some(value as u32)),
        value if value < -1 => Target::Group(value.unsigned_abs()),
        _ => return Err(CompatErrno::Invalid),
    };
    if args[2] & !WNOHANG != 0 || args[3] != 0 {
        return Err(CompatErrno::NoSys);
    }
    loop {
        let result = match target {
            Target::Pid(target) => proc::take_linux_child_exit(_pid, target),
            Target::Group(pgid) => proc::take_linux_child_exit_group(_pid, pgid),
        };
        match result {
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

/// Implements `waitid(2)` for exited children and the `WNOHANG` probe.
fn linux_waitid(pid: ObjId, args: [u64; 6]) -> Result<u64, CompatErrno> {
    const P_ALL: u32 = 0;
    const P_PID: u32 = 1;
    const P_PGID: u32 = 2;
    const P_PIDFD: u32 = 3;
    const WNOHANG: u64 = 0x1;
    const WEXITED: u64 = 0x4;
    const WNOWAIT: u64 = 0x0100_0000;
    #[derive(Clone, Copy)]
    enum Target {
        Pid(Option<u32>),
        Group(u32),
    }
    let id_type = u32::try_from(args[0]).map_err(|_| CompatErrno::Invalid)?;
    let target = match id_type {
        P_ALL => Target::Pid(None),
        P_PID => {
            let target = u32::try_from(args[1]).map_err(|_| CompatErrno::NoProcess)?;
            if target == 0 {
                return Err(CompatErrno::NoProcess);
            }
            Target::Pid(Some(target))
        }
        P_PGID => {
            let requested = u32::try_from(args[1]).map_err(|_| CompatErrno::NoProcess)?;
            Target::Group(if requested == 0 {
                proc::linux_process_group_state(pid)
                    .ok_or(CompatErrno::NoProcess)?
                    .0
            } else {
                requested
            })
        }
        P_PIDFD => {
            let fd = u32::try_from(args[1]).map_err(|_| CompatErrno::BadFd)?;
            let entry = proc::linux_fd(pid, fd).ok_or(CompatErrno::BadFd)?;
            if entry.kind != compat_core::fd::CompatKind::Pidfd {
                return Err(CompatErrno::BadFd);
            }
            let target = ObjId::from_raw(entry.handle).ok_or(CompatErrno::NoProcess)?;
            Target::Pid(Some(
                proc::linux_pid(target).ok_or(CompatErrno::NoProcess)?,
            ))
        }
        _ => return Err(CompatErrno::Invalid),
    };
    let options = args[3];
    if args[4] != 0 {
        return Err(CompatErrno::NotSupported);
    }
    if options & !(WNOHANG | WEXITED | WNOWAIT) != 0 || options & WEXITED == 0 {
        return Err(CompatErrno::NotSupported);
    }
    if args[2] != 0 {
        let zero = [0u8; 128];
        copy_to_user(args[2], &zero, zero.len()).map_err(|_| CompatErrno::Fault)?;
    }
    loop {
        let observed = match (target, options & WNOWAIT != 0) {
            (Target::Pid(target), false) => proc::take_linux_child_exit(pid, target),
            (Target::Pid(target), true) => proc::peek_linux_child_exit(pid, target),
            (Target::Group(pgid), false) => {
                proc::take_linux_child_exit_group(pid, pgid)
            }
            (Target::Group(pgid), true) => {
                proc::peek_linux_child_exit_group(pid, pgid)
            }
        };
        match observed {
            Ok(Some((child_pid, status))) => {
                if args[2] != 0 {
                    let mut info = [0u8; 128];
                    let status_value = status & 0x7f;
                    info[0..4].copy_from_slice(&17u32.to_le_bytes());
                    info[8..12].copy_from_slice(
                        &(if status_value == 0 { 1i32 } else { 2i32 }).to_le_bytes(),
                    );
                    info[16..20].copy_from_slice(&child_pid.to_le_bytes());
                    info[24..28].copy_from_slice(
                        &(if status_value == 0 {
                            (status >> 8) & 0xff
                        } else {
                            status_value
                        })
                        .to_le_bytes(),
                    );
                    copy_to_user(args[2], &info, info.len()).map_err(|_| CompatErrno::Fault)?;
                }
                return Ok(0);
            }
            Ok(None) if options & WNOHANG != 0 => return Ok(0),
            Ok(None) => proc::block_step().map_err(|_| CompatErrno::Interrupted)?,
            Err(_) => return Err(CompatErrno::NoChild),
        }
    }
}

/// Reports whether a pidfd target has exited or is exiting.
fn pidfd_target_ready(target: ObjId) -> bool {
    matches!(
        proc::state(target),
        None
            | Some(proc::ProcState::Exiting { .. })
            | Some(proc::ProcState::Exited { .. })
    )
}

/// Implements `pidfd_open(2)` for process identities.
fn linux_pidfd_open(pid: ObjId, args: [u64; 6]) -> Result<u64, CompatErrno> {
    const PIDFD_NONBLOCK: u64 = 0x800;
    if args[1] & !PIDFD_NONBLOCK != 0 {
        return Err(CompatErrno::Invalid);
    }
    let target_pid = u32::try_from(args[0]).map_err(|_| CompatErrno::Invalid)?;
    if target_pid == 0 {
        return Err(CompatErrno::NoProcess);
    }
    let target = proc::linux_process_for_pid(target_pid).ok_or(CompatErrno::NoProcess)?;
    let fd = proc::linux_install_pidfd(pid, target, true).ok_or(CompatErrno::NoSpace)?;
    if args[1] & PIDFD_NONBLOCK != 0 {
        let flags = proc::linux_fd_status_flags(pid, fd).ok_or(CompatErrno::BadFd)?;
        if !proc::linux_set_fd_status_flags(
            pid,
            fd,
            flags | PIDFD_NONBLOCK as u32,
        ) {
            let _ = proc::linux_close_fd(pid, fd);
            return Err(CompatErrno::BadFd);
        }
    }
    Ok(u64::from(fd))
}

/// Implements signal delivery through an existing pidfd.
fn linux_pidfd_send_signal(
    pid: ObjId,
    args: [u64; 6],
) -> Result<u64, CompatErrno> {
    let fd = u32::try_from(args[0]).map_err(|_| CompatErrno::BadFd)?;
    let entry = proc::linux_fd(pid, fd).ok_or(CompatErrno::BadFd)?;
    if entry.kind != compat_core::fd::CompatKind::Pidfd || args[3] != 0 {
        return Err(CompatErrno::Invalid);
    }
    let target = ObjId::from_raw(entry.handle).ok_or(CompatErrno::NoProcess)?;
    let signal = u32::try_from(args[1]).map_err(|_| CompatErrno::Invalid)?;
    if signal > 64 {
        return Err(CompatErrno::Invalid);
    }
    if signal == 0 {
        return proc::state(target)
            .map(|_| 0)
            .ok_or(CompatErrno::NoProcess);
    }
    if signal == 19 {
        return Err(CompatErrno::NotSupported);
    }
    let sender = proc::linux_pid(pid).ok_or(CompatErrno::NoProcess)?;
    let queued = if args[2] == 0 {
        queue_process_signal(target, signal, sender, 0)
    } else {
        let target_pid = proc::linux_pid(target).ok_or(CompatErrno::NoProcess)?;
        let info = read_linux_queued_siginfo(signal, args[2])?;
        check_linux_sigqueue_source(pid, target_pid, info.code)?;
        queue_process_signal_info(
            target,
            signal,
            info.pid,
            info.uid,
            info.code,
            info.value,
        )
    };
    if queued {
        Ok(0)
    } else {
        Err(CompatErrno::NoProcess)
    }
}

/// Duplicates a same-application descriptor through a pidfd reference.
fn linux_pidfd_getfd(pid: ObjId, args: [u64; 6]) -> Result<u64, CompatErrno> {
    if args[2] != 0 {
        return Err(CompatErrno::Invalid);
    }
    let pidfd = u32::try_from(args[0]).map_err(|_| CompatErrno::BadFd)?;
    let entry = proc::linux_fd(pid, pidfd).ok_or(CompatErrno::BadFd)?;
    if entry.kind != compat_core::fd::CompatKind::Pidfd {
        return Err(CompatErrno::BadFd);
    }
    let target = ObjId::from_raw(entry.handle).ok_or(CompatErrno::NoProcess)?;
    let caller_application = proc::app(pid).ok_or(CompatErrno::Perm)?;
    let target_application = proc::app(target).ok_or(CompatErrno::NoProcess)?;
    if target != pid && caller_application != target_application {
        return Err(CompatErrno::Perm);
    }
    let target_fd = u32::try_from(args[1]).map_err(|_| CompatErrno::BadFd)?;
    let transfer = proc::linux_capture_fd_transfer(target, target_fd).map_err(|error| match error {
        proc::LinuxFdTransferError::Invalid => CompatErrno::BadFd,
        proc::LinuxFdTransferError::NoSpace => CompatErrno::NoSpace,
    })?;
    proc::linux_install_fd_transfer(pid, transfer, true)
        .map(u64::from)
        .map_err(|error| match error {
            proc::LinuxFdTransferError::Invalid => CompatErrno::BadFd,
            proc::LinuxFdTransferError::NoSpace => CompatErrno::NoSpace,
        })
}

/// Implements the structured `clone3(2)` layout used by modern glibc.
///
/// 解析现代 glibc 使用的 88 字节 `clone3` 参数结构，并复用同一线程创建路径。
fn linux_clone3(
    pid: ObjId,
    args: [u64; 6],
    user_ip: Option<(u64, u64)>,
    user_preserved: [u64; 6],
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
    #[cfg(any(
        feature = "compat-dynamic-libc-verify",
        feature = "vulkan-metal2vulkan-verify"
    ))]
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
    const CLONE_VM: u64 = 0x0000_0100;
    const CLONE_VFORK: u64 = 0x0000_4000;
    if flags & CLONE_VM != 0 && flags & CLONE_VFORK != 0 {
        return linux_vfork(pid, args, user_ip, user_preserved);
    }
    if flags & CLONE_VM == 0 {
        return linux_fork_clone(
            pid,
            [flags, stack, parent_tid, child_tid, tls, 0],
            user_ip,
            user_preserved,
        );
    }
    if exit_signal != 0 || stack_size == 0 {
        return Err(CompatErrno::Invalid);
    }
    let child_stack = stack
        .checked_add(stack_size)
        .filter(|top| *top <= crate::arch::USER_WINDOW.1)
        .ok_or(CompatErrno::Invalid)?;
    #[cfg(any(
        feature = "compat-dynamic-libc-verify",
        feature = "vulkan-metal2vulkan-verify"
    ))]
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
    #[cfg(feature = "android-art-verify")]
    {
        ART_TLS_TRACE_REMAINING.store(24, Ordering::Relaxed);
        crate::kprintln!(
            "[JSR-ANDROID-ART] clone parent_tid={} child_tid={} tls={:#x} fs_base={:#x} gs_base={:#x}",
            current_linux_tid(pid).unwrap_or(0),
            linux_tid_for_task(task).map(|(_, tid)| tid).unwrap_or(0),
            tls,
            crate::arch::user_fs_base(),
            crate::arch::user_gs_base()
        );
    }
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
    const FUTEX_REQUEUE: u64 = 3;
    const FUTEX_CMP_REQUEUE: u64 = 4;
    const FUTEX_WAIT_BITSET: u64 = 9;
    const FUTEX_WAKE_BITSET: u64 = 10;
    const FUTEX_PRIVATE_FLAG: u64 = 128;
    const FUTEX_CLOCK_REALTIME: u64 = 256;
    let operation = args[1] & !(FUTEX_PRIVATE_FLAG | FUTEX_CLOCK_REALTIME);
    match operation {
        FUTEX_WAIT => futex_wait(
            pid,
            args[0],
            args[2] as u32,
            u32::MAX,
            futex_timeout(args[3], false, false)?,
        ),
        FUTEX_WAIT_BITSET => futex_wait(
            pid,
            args[0],
            args[2] as u32,
            args[5] as u32,
            futex_timeout(
                args[3],
                args[1] & FUTEX_CLOCK_REALTIME != 0,
                true,
            )?,
        ),
        FUTEX_WAKE => futex_wake(
            pid,
            args[0],
            usize::try_from(args[2]).map_err(|_| CompatErrno::Invalid)?,
            u32::MAX,
        ),
        FUTEX_REQUEUE => futex_requeue(
            pid,
            args[0],
            args[4],
            usize::try_from(args[2]).map_err(|_| CompatErrno::Invalid)?,
            usize::try_from(args[3]).map_err(|_| CompatErrno::Invalid)?,
            None,
        ),
        FUTEX_CMP_REQUEUE => futex_requeue(
            pid,
            args[0],
            args[4],
            usize::try_from(args[2]).map_err(|_| CompatErrno::Invalid)?,
            usize::try_from(args[3]).map_err(|_| CompatErrno::Invalid)?,
            Some(args[5] as u32),
        ),
        FUTEX_WAKE_BITSET => futex_wake(
            pid,
            args[0],
            usize::try_from(args[2]).map_err(|_| CompatErrno::Invalid)?,
            args[5] as u32,
        ),
        _ => Err(CompatErrno::NoSys),
    }
}

#[derive(Clone, Copy)]
struct Futex2Waiter {
    address: u64,
    expected: u32,
    flags: u32,
    key: FutexKey,
}

/// Validates one futex2 waiter flag word.
fn validate_futex2_flags(flags: u32) -> Result<(), CompatErrno> {
    const FUTEX2_SIZE_MASK: u32 = 0x3;
    const FUTEX2_SIZE_U32: u32 = 0x2;
    const FUTEX2_NUMA: u32 = 0x4;
    const FUTEX2_MPOL: u32 = 0x8;
    const FUTEX2_PRIVATE: u32 = 128;
    if flags & !(FUTEX2_SIZE_MASK | FUTEX2_NUMA | FUTEX2_MPOL | FUTEX2_PRIVATE) != 0
        || flags & FUTEX2_SIZE_MASK != FUTEX2_SIZE_U32
        || flags & (FUTEX2_NUMA | FUTEX2_MPOL) != 0
    {
        return Err(CompatErrno::Invalid);
    }
    Ok(())
}

/// Reads one bounded futex2 waiter array.
fn read_futex2_waiters(
    pid: ObjId,
    address: u64,
    count: usize,
) -> Result<alloc::vec::Vec<Futex2Waiter>, CompatErrno> {
    const FUTEX2_WAITER_BYTES: usize = 24;
    let mut waiters = alloc::vec::Vec::new();
    waiters
        .try_reserve(count)
        .map_err(|_| CompatErrno::NoMemory)?;
    for index in 0..count {
        let entry = address
            .checked_add((index * FUTEX2_WAITER_BYTES) as u64)
            .ok_or(CompatErrno::Fault)?;
        let mut raw = [0u8; FUTEX2_WAITER_BYTES];
        proc::read(pid, entry, &mut raw).map_err(|_| CompatErrno::Fault)?;
        let expected = u32::try_from(u64::from_le_bytes(raw[0..8].try_into().unwrap()))
            .map_err(|_| CompatErrno::Invalid)?;
        let futex_address = u64::from_le_bytes(raw[8..16].try_into().unwrap());
        let flags = u32::from_le_bytes(raw[16..20].try_into().unwrap());
        if u32::from_le_bytes(raw[20..24].try_into().unwrap()) != 0
            || futex_address % 4 != 0
            || waiters
                .iter()
                .any(|waiter: &Futex2Waiter| waiter.address == futex_address)
        {
            return Err(CompatErrno::Invalid);
        }
        validate_futex2_flags(flags)?;
        waiters.push(Futex2Waiter {
            address: futex_address,
            expected,
            flags,
            key: futex_key(pid, futex_address),
        });
    }
    Ok(waiters)
}

/// Converts one absolute futex2 timeout to Jasper monotonic nanoseconds.
fn futex2_deadline(timeout: u64, clockid: u64) -> Result<Option<u64>, CompatErrno> {
    if timeout == 0 {
        return Ok(None);
    }
    let requested = read_linux_timespec(timeout)?;
    match clockid {
        0 => {
            let wall = crate::arch::wall_clock_ns().ok_or(CompatErrno::NoSys)?;
            Ok(Some(
                sched::now_ns().saturating_add(requested.saturating_sub(wall)),
            ))
        }
        1 => Ok(Some(requested)),
        _ => Err(CompatErrno::Invalid),
    }
}

/// Removes every futex waiter owned by one task.
fn clear_task_futex_waiters(task: crate::task::TaskId) {
    let mut state = COMPAT.lock();
    for word in state.futexes.iter_mut().flatten() {
        for waiter in word.waiters.iter_mut() {
            if waiter.active && waiter.task == task {
                *waiter = FutexWaiter::EMPTY;
            }
        }
    }
    prune_empty_futex_words(&mut state);
}

fn prune_empty_futex_words(state: &mut CompatState) {
    for slot in &mut state.futexes {
        if slot
            .as_ref()
            .is_some_and(|word| word.waiters.iter().all(|waiter| !waiter.active))
        {
            *slot = None;
        }
    }
}

/// Implements `futex_wait(2)` from the futex2 family.
fn linux_futex_wait(pid: ObjId, args: [u64; 6]) -> Result<u64, CompatErrno> {
    let flags = u32::try_from(args[3]).map_err(|_| CompatErrno::Invalid)?;
    validate_futex2_flags(flags)?;
    let deadline = futex2_deadline(args[4], args[5])?;
    futex_wait(
        pid,
        args[0],
        u32::try_from(args[1]).map_err(|_| CompatErrno::Invalid)?,
        u32::try_from(args[2]).map_err(|_| CompatErrno::Invalid)?,
        deadline,
    )
}

/// Implements `futex_wake(2)` from the futex2 family.
fn linux_futex_wake(pid: ObjId, args: [u64; 6]) -> Result<u64, CompatErrno> {
    let mask = u32::try_from(args[1]).map_err(|_| CompatErrno::Invalid)?;
    let count = i32::try_from(args[2]).map_err(|_| CompatErrno::Invalid)?;
    let flags = u32::try_from(args[3]).map_err(|_| CompatErrno::Invalid)?;
    if count < 0 {
        return Err(CompatErrno::Invalid);
    }
    validate_futex2_flags(flags)?;
    futex_wake(pid, args[0], count as usize, mask)
}

/// Implements `futex_requeue(2)` from the futex2 family.
fn linux_futex_requeue(pid: ObjId, args: [u64; 6]) -> Result<u64, CompatErrno> {
    if args[1] != 0 {
        return Err(CompatErrno::Invalid);
    }
    let wake = i32::try_from(args[2]).map_err(|_| CompatErrno::Invalid)?;
    let requeue = i32::try_from(args[3]).map_err(|_| CompatErrno::Invalid)?;
    if wake < 0 || requeue < 0 {
        return Err(CompatErrno::Invalid);
    }
    let waiters = read_futex2_waiters(pid, args[0], 2)?;
    if waiters[0].flags != waiters[1].flags {
        return Err(CompatErrno::Invalid);
    }
    futex_requeue(
        pid,
        waiters[0].address,
        waiters[1].address,
        wake as usize,
        requeue as usize,
        Some(waiters[0].expected),
    )
}

/// Implements vectorized `futex_waitv(2)`.
fn linux_futex_waitv(pid: ObjId, args: [u64; 6]) -> Result<u64, CompatErrno> {
    const MAX_WAITV: usize = 16;
    if args[2] != 0 {
        return Err(CompatErrno::Invalid);
    }
    let count = usize::try_from(args[1]).map_err(|_| CompatErrno::Invalid)?;
    if count == 0 || count > MAX_WAITV || args[0] == 0 {
        return Err(CompatErrno::Invalid);
    }
    let waiters = read_futex2_waiters(pid, args[0], count)?;
    for (index, waiter) in waiters.iter().enumerate() {
        if futex_value(pid, waiter.address)? != waiter.expected {
            return Ok(index as u64);
        }
    }
    let deadline = futex2_deadline(args[3], args[4])?;
    let task = sched::current().0;
    {
        let mut state = COMPAT.lock();
        for waiter in &waiters {
            let slot = if let Some(slot) = state
                .futexes
                .iter()
                .position(|entry| entry.is_some_and(|entry| entry.key == waiter.key))
            {
                slot
            } else {
                let Some(slot) = state.futexes.iter().position(Option::is_none) else {
                    for word in state.futexes.iter_mut().flatten() {
                        for entry in word.waiters.iter_mut() {
                            if entry.active && entry.task == task {
                                *entry = FutexWaiter::EMPTY;
                            }
                        }
                    }
                    return Err(CompatErrno::NoSpace);
                };
                state.futexes[slot] = Some(FutexWord {
                    key: waiter.key,
                    waiters: [FutexWaiter::EMPTY; MAX_FUTEX_WAITERS],
                });
                slot
            };
            let word = state.futexes[slot].as_mut().ok_or(CompatErrno::NoSpace)?;
            let Some(entry) = word.waiters.iter_mut().find(|entry| !entry.active) else {
                for word in state.futexes.iter_mut().flatten() {
                    for entry in word.waiters.iter_mut() {
                        if entry.active && entry.task == task {
                            *entry = FutexWaiter::EMPTY;
                        }
                    }
                }
                return Err(CompatErrno::NoSpace);
            };
            *entry = FutexWaiter {
                task,
                key: Some(waiter.key),
                bitset: u32::MAX,
                active: true,
                woken: false,
            };
        }
    }
    let result = loop {
        if proc::current_exiting() || current_signal_pending(pid) {
            break Err(CompatErrno::Interrupted);
        }
        if let Some(deadline) = deadline {
            if sched::now_ns() >= deadline {
                break Err(CompatErrno::TimedOut);
            }
        }
        let woken = {
            let state = COMPAT.lock();
            waiters.iter().position(|waiter| {
                state
                    .futexes
                    .iter()
                    .flatten()
                    .find(|word| word.key == waiter.key)
                    .is_some_and(|word| {
                        word.waiters
                            .iter()
                            .any(|entry| entry.active && entry.task == task && entry.woken)
                    })
            })
        };
        if let Some(index) = woken {
            break Ok(index as u64);
        }
        if let Some(deadline) = deadline {
            if sched::sleep_until_ns(deadline).is_err() {
                sched::pause();
            }
        } else {
            sched::pause();
        }
    };
    clear_task_futex_waiters(task);
    result
}

/// Queries or updates process-local compatibility resource limits.
fn linux_prlimit(pid: ObjId, args: [u64; 6]) -> Result<u64, CompatErrno> {
    let current_pid = u64::from(proc::linux_pid(pid).ok_or(CompatErrno::NoProcess)?);
    if args[0] != 0 && args[0] != current_pid {
        return Err(CompatErrno::Perm);
    }
    let old = linux_limit(pid, args[1])?;
    if args[3] != 0 {
        let mut bytes = [0u8; 16];
        bytes[..8].copy_from_slice(&old.0.to_le_bytes());
        bytes[8..].copy_from_slice(&old.1.to_le_bytes());
        copy_to_user(args[3], &bytes, bytes.len()).map_err(|_| CompatErrno::Fault)?;
    }
    if args[2] != 0 {
        let mut bytes = [0u8; 16];
        copy_from_user(&mut bytes, args[2], 16)
            .map_err(|_| CompatErrno::Fault)?;
        let current = u64::from_le_bytes(bytes[..8].try_into().unwrap());
        let maximum = u64::from_le_bytes(bytes[8..].try_into().unwrap());
        update_linux_limit(pid, args[1], current, maximum)?;
    }
    Ok(0)
}

fn linux_limit(pid: ObjId, resource: u64) -> Result<(u64, u64), CompatErrno> {
    const RLIMIT_STACK: u64 = 3;
    const RLIMIT_NOFILE: u64 = 7;
    let limits = proc::linux_rlimits(pid).ok_or(CompatErrno::Invalid)?;
    match resource {
        RLIMIT_STACK => Ok((limits.stack_current, limits.stack_maximum)),
        RLIMIT_NOFILE => Ok((limits.nofile_current, limits.nofile_maximum)),
        _ => Err(CompatErrno::Invalid),
    }
}

fn update_linux_limit(
    pid: ObjId,
    resource: u64,
    current: u64,
    maximum: u64,
) -> Result<(), CompatErrno> {
    const RLIMIT_STACK: u64 = 3;
    const RLIMIT_NOFILE: u64 = 7;
    if current > maximum {
        return Err(CompatErrno::Invalid);
    }
    let old = proc::linux_rlimits(pid).ok_or(CompatErrno::NoProcess)?;
    let mut next = old;
    match resource {
        RLIMIT_STACK => {
            if maximum > old.stack_maximum {
                return Err(CompatErrno::Perm);
            }
            next.stack_current = current;
            next.stack_maximum = maximum;
        }
        RLIMIT_NOFILE => {
            if maximum > old.nofile_maximum {
                return Err(CompatErrno::Perm);
            }
            if current != old.nofile_current || maximum != old.nofile_maximum {
                return Err(CompatErrno::NotSupported);
            }
        }
        _ => return Err(CompatErrno::Invalid),
    }
    if proc::set_linux_rlimits(pid, next) {
        Ok(())
    } else {
        Err(CompatErrno::NoProcess)
    }
}

fn linux_getrlimit(pid: ObjId, args: [u64; 6]) -> Result<u64, CompatErrno> {
    let (current, maximum) = linux_limit(pid, args[0])?;
    let mut bytes = [0u8; 16];
    bytes[..8].copy_from_slice(&current.to_le_bytes());
    bytes[8..].copy_from_slice(&maximum.to_le_bytes());
    copy_to_user(args[1], &bytes, bytes.len()).map_err(|_| CompatErrno::Fault)?;
    Ok(0)
}

fn linux_setrlimit(pid: ObjId, args: [u64; 6]) -> Result<u64, CompatErrno> {
    let _ = linux_limit(pid, args[0])?;
    let mut bytes = [0u8; 16];
    copy_from_user(&mut bytes, args[1], 16).map_err(|_| CompatErrno::Fault)?;
    let current = u64::from_le_bytes(bytes[..8].try_into().unwrap());
    let maximum = u64::from_le_bytes(bytes[8..].try_into().unwrap());
    update_linux_limit(pid, args[0], current, maximum)?;
    Ok(0)
}

/// Fills a bounded userspace buffer from x86_64 RDRAND or virtio-rng.
///
/// 优先使用 CPUID 验证过的 RDRAND；硬件随机指令不可用或验收强制关闭时，使用有界
/// virtio-rng 队列。两个来源都不可用时明确返回 EAGAIN。
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
        let hardware = if cfg!(feature = "compat-rng-force") {
            None
        } else {
            crate::arch::x86_64::hardware_random_u64()
        };
        match hardware {
            Some(value) => {
                let bytes = value.to_le_bytes();
                let count = (output.len() - offset).min(bytes.len());
                output[offset..offset + count].copy_from_slice(&bytes[..count]);
                offset += count;
            }
            None => {
                #[cfg(any(
                    feature = "lifecycle-root-exec-verify",
                    feature = "compat-dynamic-libc-verify"
                ))]
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

/// Implements the bounded task-name operations of `prctl(2)`.
///
/// 仅实现当前 Linux 任务的 `PR_SET_NAME`/`PR_GET_NAME`；名称固定为 Linux 的
/// 16 字节任务命令名。其他 option 明确返回 EINVAL，不把未实现的安全策略当作成功。
fn linux_prctl(pid: ObjId, args: [u64; 6]) -> Result<u64, CompatErrno> {
    const PR_SET_PDEATHSIG: u64 = 1;
    const PR_GET_PDEATHSIG: u64 = 2;
    const PR_SET_NAME: u64 = 15;
    const PR_GET_NAME: u64 = 16;
    const PR_GET_SECCOMP: u64 = 21;
    const PR_SET_SECCOMP: u64 = 22;
    const PR_SET_CHILD_SUBREAPER: u64 = 36;
    const PR_GET_CHILD_SUBREAPER: u64 = 37;
    const PR_SET_NO_NEW_PRIVS: u64 = 38;
    const PR_GET_NO_NEW_PRIVS: u64 = 39;
    const ARCH_SHSTK_ENABLE: u64 = 0x5001;
    const ARCH_SHSTK_DISABLE: u64 = 0x5002;
    const ARCH_SHSTK_LOCK: u64 = 0x5003;
    const ARCH_SHSTK_UNLOCK: u64 = 0x5004;
    const ARCH_SHSTK_STATUS: u64 = 0x5005;
    let (task, _) = sched::current();
    match args[0] {
        PR_SET_PDEATHSIG => {
            let signal = u32::try_from(args[1]).map_err(|_| CompatErrno::Invalid)?;
            if signal > 64 {
                return Err(CompatErrno::Invalid);
            }
            if proc::set_linux_pdeathsig(pid, signal) {
                Ok(0)
            } else {
                Err(CompatErrno::NoProcess)
            }
        }
        PR_GET_PDEATHSIG => {
            let signal = proc::linux_pdeathsig(pid).ok_or(CompatErrno::NoProcess)?;
            copy_to_user(args[1], &signal.to_le_bytes(), 4).map_err(|_| CompatErrno::Fault)?;
            Ok(0)
        }
        PR_SET_NAME => {
            let mut name = [0u8; 16];
            for offset in 0..15 {
                let address = args[1]
                    .checked_add(offset as u64)
                    .ok_or(CompatErrno::Fault)?;
                let mut byte = [0u8; 1];
                copy_from_user(&mut byte, address, 1).map_err(|_| CompatErrno::Fault)?;
                if byte[0] == 0 {
                    break;
                }
                name[offset] = byte[0];
            }
            let mut state = COMPAT.lock();
            let thread = state
                .threads
                .iter_mut()
                .flatten()
                .find(|entry| entry.process == pid && entry.task == task)
                .ok_or(CompatErrno::NoProcess)?;
            #[cfg(feature = "vulkan-metal2vulkan-verify")]
            crate::kprintln!(
                "[JSR-VULKAN-THREAD] tid={} name={}",
                thread.tid,
                core::str::from_utf8(&name[..name.iter().position(|b| *b == 0).unwrap_or(16)])
                    .unwrap_or("<non-utf8>")
            );
            thread.name = name;
            Ok(0)
        }
        PR_GET_NAME => {
            let name = COMPAT
                .lock()
                .threads
                .iter()
                .flatten()
                .find(|entry| entry.process == pid && entry.task == task)
                .map(|entry| entry.name)
                .ok_or(CompatErrno::NoProcess)?;
            copy_to_user(args[1], &name, name.len()).map_err(|_| CompatErrno::Fault)?;
            Ok(0)
        }
        PR_SET_SECCOMP => {
            const SECCOMP_MODE_STRICT: u64 = 1;
            const SECCOMP_MODE_FILTER: u64 = 2;
            match args[1] {
                SECCOMP_MODE_STRICT
                    if proc::linux_seccomp_mode(pid).ok_or(CompatErrno::NoProcess)? == 0 =>
                {
                    linux_seccomp(pid, [0, 0, 0, 0, 0, 0])
                }
                SECCOMP_MODE_FILTER => {
                    linux_seccomp(pid, [1, 0, args[2], 0, 0, 0])
                }
                SECCOMP_MODE_STRICT => Err(CompatErrno::Invalid),
                _ => Err(CompatErrno::Invalid),
            }
        }
        PR_GET_SECCOMP => Ok(u64::from(
            proc::linux_seccomp_mode(pid).ok_or(CompatErrno::NoProcess)?,
        )),
        PR_SET_CHILD_SUBREAPER => {
            if proc::set_linux_subreaper(pid, args[1] != 0) {
                Ok(0)
            } else {
                Err(CompatErrno::NoProcess)
            }
        }
        PR_GET_CHILD_SUBREAPER => {
            let subreaper =
                proc::linux_subreaper(pid).ok_or(CompatErrno::NoProcess)?;
            copy_to_user(args[1], &(u32::from(subreaper)).to_le_bytes(), 4)
                .map_err(|_| CompatErrno::Fault)?;
            Ok(0)
        }
        PR_SET_NO_NEW_PRIVS => {
            if args[1] != 1 || args[2] != 0 || args[3] != 0 || args[4] != 0 {
                return Err(CompatErrno::Invalid);
            }
            if proc::linux_set_no_new_privs(pid) {
                Ok(0)
            } else {
                Err(CompatErrno::NoProcess)
            }
        }
        PR_GET_NO_NEW_PRIVS => Ok(u64::from(
            proc::linux_no_new_privs(pid).ok_or(CompatErrno::NoProcess)?,
        )),
        ARCH_SHSTK_STATUS => {
            let features = proc::linux_shstk_status(pid).ok_or(CompatErrno::NoProcess)?;
            copy_to_user(args[1], &features.to_le_bytes(), 8).map_err(|_| CompatErrno::Fault)?;
            Ok(0)
        }
        ARCH_SHSTK_LOCK => {
            if proc::linux_lock_shstk_features(pid, args[1]) {
                Ok(0)
            } else {
                Err(CompatErrno::Invalid)
            }
        }
        ARCH_SHSTK_ENABLE | ARCH_SHSTK_DISABLE => Err(CompatErrno::NotSupported),
        ARCH_SHSTK_UNLOCK => Err(CompatErrno::Perm),
        _ => Err(CompatErrno::Invalid),
    }
}

/// Implements `seccomp(2)` filter installation and introspection.
fn linux_seccomp(pid: ObjId, args: [u64; 6]) -> Result<u64, CompatErrno> {
    use compat_core::seccomp::{
        SeccompAction, SeccompInsn, MAX_FILTER_INSNS,
    };

    const SECCOMP_SET_MODE_STRICT: u64 = 0;
    const SECCOMP_SET_MODE_FILTER: u64 = 1;
    const SECCOMP_GET_ACTION_AVAIL: u64 = 2;
    const SECCOMP_GET_NOTIF_SIZES: u64 = 3;
    const FILTER_FLAG_TSYNC: u64 = 1;
    const FILTER_FLAG_LOG: u64 = 2;
    const FILTER_FLAG_SPEC_ALLOW: u64 = 4;
    const FILTER_FLAG_NEW_LISTENER: u64 = 8;
    const FILTER_FLAG_TSYNC_ESRCH: u64 = 16;
    const FILTER_FLAG_WAIT_KILLABLE_RECV: u64 = 32;
    let operation = args[0];
    match operation {
        SECCOMP_SET_MODE_STRICT => {
            if args[1] != 0 || args[2] != 0 {
                return Err(CompatErrno::Invalid);
            }
            if !proc::linux_no_new_privs(pid).ok_or(CompatErrno::NoProcess)? {
                return Err(CompatErrno::Access);
            }
            if proc::linux_set_seccomp_strict(pid) {
                Ok(0)
            } else {
                Err(CompatErrno::NoProcess)
            }
        }
        SECCOMP_SET_MODE_FILTER => {
            let flags = args[1];
            if flags
                & !(FILTER_FLAG_TSYNC
                    | FILTER_FLAG_LOG
                    | FILTER_FLAG_SPEC_ALLOW
                    | FILTER_FLAG_TSYNC_ESRCH)
                != 0
            {
                return Err(if flags & (FILTER_FLAG_NEW_LISTENER | FILTER_FLAG_WAIT_KILLABLE_RECV) != 0
                {
                    CompatErrno::NotSupported
                } else {
                    CompatErrno::Invalid
                });
            }
            if !proc::linux_no_new_privs(pid).ok_or(CompatErrno::NoProcess)? {
                return Err(CompatErrno::Access);
            }
            let mut program = [0u8; 16];
            copy_from_user(&mut program, args[2], 16).map_err(|_| CompatErrno::Fault)?;
            let length = usize::from(u16::from_le_bytes(program[..2].try_into().unwrap()));
            if length == 0 || length > MAX_FILTER_INSNS {
                return Err(CompatErrno::Invalid);
            }
            let filter_pointer = u64::from_le_bytes(program[8..16].try_into().unwrap());
            let bytes = length.checked_mul(8).ok_or(CompatErrno::Invalid)?;
            let mut raw = alloc::vec![0u8; bytes];
            copy_from_user(&mut raw, filter_pointer, bytes).map_err(|_| CompatErrno::Fault)?;
            let mut filter = alloc::vec::Vec::new();
            filter
                .try_reserve_exact(length)
                .map_err(|_| CompatErrno::NoMemory)?;
            for instruction in raw.chunks_exact(8) {
                filter.push(SeccompInsn {
                    code: u16::from_le_bytes(instruction[..2].try_into().unwrap()),
                    jt: instruction[2],
                    jf: instruction[3],
                    k: u32::from_le_bytes(instruction[4..8].try_into().unwrap()),
                });
            }
            if compat_core::seccomp::validate(&filter).is_err() {
                return Err(CompatErrno::Invalid);
            }
            if proc::linux_install_seccomp_filter(pid, filter) {
                Ok(0)
            } else {
                Err(CompatErrno::NoSpace)
            }
        }
        SECCOMP_GET_ACTION_AVAIL => {
            if args[1] != 0 {
                return Err(CompatErrno::Invalid);
            }
            let mut raw = [0u8; 4];
            copy_from_user(&mut raw, args[2], 4).map_err(|_| CompatErrno::Fault)?;
            if SeccompAction::action_available(u32::from_le_bytes(raw)) {
                Ok(0)
            } else {
                Err(CompatErrno::Invalid)
            }
        }
        SECCOMP_GET_NOTIF_SIZES => {
            if args[1] != 0 {
                return Err(CompatErrno::Invalid);
            }
            let sizes = [80u16, 24, 64];
            let mut output = [0u8; 6];
            for (index, size) in sizes.iter().enumerate() {
                output[index * 2..index * 2 + 2].copy_from_slice(&size.to_le_bytes());
            }
            copy_to_user(args[2], &output, output.len()).map_err(|_| CompatErrno::Fault)?;
            Ok(0)
        }
        _ => Err(CompatErrno::Invalid),
    }
}

const LANDLOCK_ACCESS_FS_EXECUTE: u64 = 1 << 0;
const LANDLOCK_ACCESS_FS_WRITE_FILE: u64 = 1 << 1;
const LANDLOCK_ACCESS_FS_READ_FILE: u64 = 1 << 2;
const LANDLOCK_ACCESS_FS_READ_DIR: u64 = 1 << 3;
const LANDLOCK_HANDLED_FS: u64 = (1 << 15) - 1;

fn landlock_rule_contains(rule: proc::LinuxLandlockRule, node: crate::linux_vfs::Node, path: &[u8]) -> bool {
    if rule.node == node {
        return true;
    }
    let crate::linux_vfs::Node::Directory(directory) = rule.node else {
        return false;
    };
    let root = directory.path();
    root == b"/"
        || path == root
        || path
            .strip_prefix(root)
            .is_some_and(|suffix| suffix.starts_with(b"/"))
}

fn landlock_path_allows(
    pid: ObjId,
    node: crate::linux_vfs::Node,
    path: &[u8],
    access: u64,
) -> bool {
    let domains = current_landlock_domains(pid);
    let allowed = domains
        .iter()
        .all(|domain| {
            if domain.handled_access_fs & access == 0 {
                return true;
            }
            domain.rules.iter().any(|rule| {
                rule.allowed_access & access == access
                    && landlock_rule_contains(*rule, node, path)
            })
        });
    allowed
}

fn current_landlock_domains(
    pid: ObjId,
) -> alloc::vec::Vec<alloc::sync::Arc<proc::LinuxLandlockRuleset>> {
    let (task, _) = sched::current();
    let state = COMPAT.lock();
    state
        .threads
        .iter()
        .position(|entry| {
            entry.is_some_and(|entry| entry.process == pid && entry.task == task)
        })
        .and_then(|slot| state.thread_landlock_domains[slot].clone())
        .unwrap_or_default()
}

/// Creates one stackable Landlock ruleset.
fn linux_landlock_create_ruleset(
    pid: ObjId,
    args: [u64; 6],
) -> Result<u64, CompatErrno> {
    const CREATE_RULESET_VERSION: u64 = 1;
    if args[2] & CREATE_RULESET_VERSION != 0 {
        if args[2] != CREATE_RULESET_VERSION || args[0] != 0 || args[1] != 0 {
            return Err(CompatErrno::Invalid);
        }
        return Ok(4);
    }
    if args[2] != 0 || !(8..=24).contains(&args[1]) {
        return Err(CompatErrno::Invalid);
    }
    let mut raw = [0u8; 24];
    copy_from_user(&mut raw, args[0], args[1] as usize).map_err(|_| CompatErrno::Fault)?;
    let handled = u64::from_le_bytes(raw[..8].try_into().unwrap());
    let handled_net = if args[1] >= 16 {
        u64::from_le_bytes(raw[8..16].try_into().unwrap())
    } else {
        0
    };
    let scoped = if args[1] >= 24 {
        u64::from_le_bytes(raw[16..24].try_into().unwrap())
    } else {
        0
    };
    if handled == 0 || handled & !LANDLOCK_HANDLED_FS != 0 {
        return Err(CompatErrno::Invalid);
    }
    if handled_net != 0 || scoped != 0 {
        return Err(CompatErrno::NotSupported);
    }
    proc::linux_install_landlock_ruleset(pid, handled, true)
        .map(u64::from)
        .ok_or(CompatErrno::NoSpace)
}

/// Adds one path-beneath rule to a Landlock ruleset.
fn linux_landlock_add_rule(pid: ObjId, args: [u64; 6]) -> Result<u64, CompatErrno> {
    const RULE_PATH_BENEATH: u64 = 1;
    if args[1] != RULE_PATH_BENEATH {
        return Err(if args[1] == 2 {
            CompatErrno::NotSupported
        } else {
            CompatErrno::Invalid
        });
    }
    if args[3] != 0 {
        return Err(CompatErrno::Invalid);
    }
    let fd = u32::try_from(args[0]).map_err(|_| CompatErrno::BadFd)?;
    let entry = proc::linux_fd(pid, fd).ok_or(CompatErrno::BadFd)?;
    if entry.kind != compat_core::fd::CompatKind::Sandbox {
        return Err(CompatErrno::BadFd);
    }
    let ruleset = proc::linux_landlock_ruleset(pid, entry.handle).ok_or(CompatErrno::BadFd)?;
    let mut raw = [0u8; 12];
    copy_from_user(&mut raw, args[2], 12).map_err(|_| CompatErrno::Fault)?;
    let allowed = u64::from_le_bytes(raw[..8].try_into().unwrap());
    let parent_fd = i32::from_le_bytes(raw[8..12].try_into().unwrap());
    if parent_fd < 0 {
        return Err(CompatErrno::BadFd);
    }
    let node = proc::linux_path_node(pid, parent_fd as u32).ok_or(CompatErrno::BadFd)?;
    let mut ruleset = ruleset.lock();
    if allowed == 0 || allowed & !ruleset.handled_access_fs != 0 {
        return Err(CompatErrno::Invalid);
    }
    if ruleset.rules.iter().any(|rule| rule.node == node) {
        return Err(CompatErrno::Exists);
    }
    if ruleset.rules.len() >= 64 {
        return Err(CompatErrno::NoMemory);
    }
    ruleset
        .rules
        .try_reserve(1)
        .map_err(|_| CompatErrno::NoMemory)?;
    ruleset.rules.push(proc::LinuxLandlockRule {
        node,
        allowed_access: allowed,
    });
    Ok(0)
}

/// Enforces one ruleset as a new Landlock domain.
fn linux_landlock_restrict_self(
    pid: ObjId,
    args: [u64; 6],
) -> Result<u64, CompatErrno> {
    const RESTRICT_FLAGS: u64 = 0x8 | 0x4 | 0x2 | 0x1;
    if args[1] & !RESTRICT_FLAGS != 0 {
        return Err(CompatErrno::Invalid);
    }
    if !proc::linux_no_new_privs(pid).ok_or(CompatErrno::NoProcess)? {
        return Err(CompatErrno::Perm);
    }
    if args[0] == u64::MAX {
        return Ok(0);
    }
    let fd = u32::try_from(args[0]).map_err(|_| CompatErrno::BadFd)?;
    let entry = proc::linux_fd(pid, fd).ok_or(CompatErrno::BadFd)?;
    if entry.kind != compat_core::fd::CompatKind::Sandbox {
        return Err(CompatErrno::BadFd);
    }
    let ruleset = proc::linux_landlock_ruleset(pid, entry.handle).ok_or(CompatErrno::BadFd)?;
    let domain = alloc::sync::Arc::new(ruleset.lock().clone());
    let (task, _) = sched::current();
    let mut state = COMPAT.lock();
    let sync_threads = args[1] & 0x8 != 0;
    let mut slots = [0usize; MAX_LINUX_THREADS];
    let mut count = 0usize;
    for (slot, entry) in state.threads.iter().enumerate() {
        if entry.is_some_and(|entry| {
            entry.process == pid && (sync_threads || entry.task == task)
        }) {
            slots[count] = slot;
            count += 1;
        }
    }
    if count == 0 {
        return Err(CompatErrno::NoProcess);
    }
    if slots[..count].iter().any(|slot| {
        state.thread_landlock_domains[*slot]
            .as_ref()
            .is_some_and(|domains| domains.len() >= 16)
    }) {
        return Err(CompatErrno::NoSpace);
    }
    for slot in &slots[..count] {
        state.thread_landlock_domains[*slot]
            .get_or_insert_with(alloc::vec::Vec::new)
            .try_reserve(1)
            .map_err(|_| CompatErrno::NoSpace)?;
    }
    for slot in &slots[..count] {
        state.thread_landlock_domains[*slot]
            .as_mut()
            .expect("reserved Landlock domain slot")
            .push(alloc::sync::Arc::clone(&domain));
    }
    Ok(0)
}

/// Implements the x86_64 `arch_prctl(2)` FS/GS base operations.
fn linux_arch_prctl(args: [u64; 6]) -> Result<u64, CompatErrno> {
    const ARCH_SET_GS: u64 = 0x1001;
    const ARCH_SET_FS: u64 = 0x1002;
    const ARCH_GET_FS: u64 = 0x1003;
    const ARCH_GET_GS: u64 = 0x1004;
    match args[0] {
        ARCH_SET_FS | ARCH_SET_GS => {
            if args[1] != 0 && !linux_user_range_valid(args[1], args[1] + 1) {
                return Err(CompatErrno::Invalid);
            }
            let set = if args[0] == ARCH_SET_FS {
                crate::arch::set_user_fs_base(args[1])
            } else {
                crate::arch::set_user_gs_base(args[1])
            };
            if !set {
                return Err(CompatErrno::Invalid);
            }
        }
        ARCH_GET_FS | ARCH_GET_GS => {
            let base = if args[0] == ARCH_GET_FS {
                crate::arch::user_fs_base()
            } else {
                crate::arch::user_gs_base()
            };
            copy_to_user(args[1], &base.to_le_bytes(), 8).map_err(|_| CompatErrno::Fault)?;
        }
        _ => return Err(CompatErrno::Invalid),
    }
    Ok(0)
}

/// Parses the 64-bit capability header used by `capget/capset`.
fn linux_capability_header(pid: ObjId, address: u64) -> Result<(), CompatErrno> {
    const CAP_VERSION_3: u32 = 0x2008_0522;
    let mut raw = [0u8; 8];
    copy_from_user(&mut raw, address, 8).map_err(|_| CompatErrno::Fault)?;
    let version = u32::from_le_bytes(raw[..4].try_into().unwrap());
    if version != CAP_VERSION_3 {
        copy_to_user(address, &CAP_VERSION_3.to_le_bytes(), 4)
            .map_err(|_| CompatErrno::Fault)?;
        return Err(CompatErrno::Invalid);
    }
    let requested = i32::from_le_bytes(raw[4..8].try_into().unwrap());
    let current = proc::linux_pid(pid).ok_or(CompatErrno::NoProcess)? as i32;
    if requested != 0 && requested != current {
        return Err(CompatErrno::Perm);
    }
    Ok(())
}

/// Reports the Linux ABI capability view without changing native authority.
fn linux_capget(pid: ObjId, args: [u64; 6]) -> Result<u64, CompatErrno> {
    linux_capability_header(pid, args[0])?;
    let capabilities = proc::linux_capabilities(pid).ok_or(CompatErrno::NoProcess)?;
    let mut data = [0u8; 24];
    data[0..4].copy_from_slice(&(capabilities.effective as u32).to_le_bytes());
    data[4..8].copy_from_slice(&(capabilities.permitted as u32).to_le_bytes());
    data[8..12].copy_from_slice(&(capabilities.inheritable as u32).to_le_bytes());
    data[12..16].copy_from_slice(&((capabilities.effective >> 32) as u32).to_le_bytes());
    data[16..20].copy_from_slice(&((capabilities.permitted >> 32) as u32).to_le_bytes());
    data[20..24].copy_from_slice(&((capabilities.inheritable >> 32) as u32).to_le_bytes());
    copy_to_user(args[1], &data, data.len()).map_err(|_| CompatErrno::Fault)?;
    Ok(0)
}

/// Updates the Linux ABI capability view while preserving native authorization.
fn linux_capset(pid: ObjId, args: [u64; 6]) -> Result<u64, CompatErrno> {
    const CAP_FULL_MASK: u64 = (1u64 << 41) - 1;
    linux_capability_header(pid, args[0])?;
    let mut data = [0u8; 24];
    copy_from_user(&mut data, args[1], 24).map_err(|_| CompatErrno::Fault)?;
    let effective = u64::from(u32::from_le_bytes(data[0..4].try_into().unwrap()))
        | (u64::from(u32::from_le_bytes(data[12..16].try_into().unwrap())) << 32);
    let permitted = u64::from(u32::from_le_bytes(data[4..8].try_into().unwrap()))
        | (u64::from(u32::from_le_bytes(data[16..20].try_into().unwrap())) << 32);
    let inheritable = u64::from(u32::from_le_bytes(data[8..12].try_into().unwrap()))
        | (u64::from(u32::from_le_bytes(data[20..24].try_into().unwrap())) << 32);
    if effective & !permitted != 0
        || effective & !CAP_FULL_MASK != 0
        || permitted & !CAP_FULL_MASK != 0
        || inheritable & !CAP_FULL_MASK != 0
    {
        return Err(CompatErrno::Perm);
    }
    if !proc::set_linux_capabilities(
        pid,
        proc::LinuxCapabilities {
            effective,
            permitted,
            inheritable,
        },
    ) {
        return Err(CompatErrno::NoProcess);
    }
    Ok(0)
}

#[derive(Clone, Copy)]
enum LinuxIoprioTarget {
    Process,
    Group(u32),
}

/// Resolves one I/O priority target to the current process or one process group.
fn linux_ioprio_target(pid: ObjId, args: [u64; 6]) -> Result<LinuxIoprioTarget, CompatErrno> {
    const IOPRIO_WHO_PROCESS: u64 = 1;
    const IOPRIO_WHO_PGRP: u64 = 2;
    let current = proc::linux_pid(pid).ok_or(CompatErrno::NoProcess)?;
    match args[0] {
        IOPRIO_WHO_PROCESS => {
            let requested = args[1] as u32 as i32;
            if requested != 0 && requested as u32 != current {
                return Err(CompatErrno::Perm);
            }
            Ok(LinuxIoprioTarget::Process)
        }
        IOPRIO_WHO_PGRP => {
            let requested = args[1] as u32 as i32;
            let caller_group = proc::linux_process_group_state(pid)
                .ok_or(CompatErrno::NoProcess)?
                .0;
            let group = if requested == 0 {
                caller_group
            } else if requested > 0 {
                requested as u32
            } else {
                return Err(CompatErrno::Invalid);
            };
            let credentials = proc::linux_credentials(pid).ok_or(CompatErrno::NoProcess)?;
            if group != caller_group && credentials.euid != 0 {
                return Err(CompatErrno::Perm);
            }
            Ok(LinuxIoprioTarget::Group(group))
        }
        _ => Err(CompatErrno::NotSupported),
    }
}

/// Returns the process Linux I/O priority.
fn linux_ioprio_get(pid: ObjId, args: [u64; 6]) -> Result<u64, CompatErrno> {
    match linux_ioprio_target(pid, args)? {
        LinuxIoprioTarget::Process => proc::linux_ioprio(pid)
            .map(u64::from)
            .ok_or(CompatErrno::NoProcess),
        LinuxIoprioTarget::Group(group) => proc::linux_ioprio_group(group)
            .map(|(value, _)| u64::from(value))
            .ok_or(CompatErrno::NoProcess),
    }
}

/// Sets the process Linux I/O priority class and level.
fn linux_ioprio_set(pid: ObjId, args: [u64; 6]) -> Result<u64, CompatErrno> {
    const IOPRIO_CLASS_MASK: u32 = 0x7;
    const IOPRIO_CLASS_SHIFT: u32 = 13;
    const IOPRIO_PRIO_MASK: u32 = (1 << IOPRIO_CLASS_SHIFT) - 1;
    let target = linux_ioprio_target(pid, args)?;
    let requested = args[2] as u32;
    let class = (requested >> IOPRIO_CLASS_SHIFT) & IOPRIO_CLASS_MASK;
    let data = requested & IOPRIO_PRIO_MASK;
    let value = match class {
        0 => (2 << IOPRIO_CLASS_SHIFT) | 4,
        1 | 2 if data <= 7 => requested,
        3 if data == 0 => requested,
        _ => return Err(CompatErrno::Invalid),
    };
    let updated = match target {
        LinuxIoprioTarget::Process => proc::set_linux_ioprio(pid, value),
        LinuxIoprioTarget::Group(group) => proc::set_linux_ioprio_group(group, value),
    };
    if updated {
        Ok(0)
    } else {
        Err(CompatErrno::NoProcess)
    }
}

/// Implements `personality(2)` for the standard Linux execution domain.
fn linux_personality(pid: ObjId, requested: u64) -> Result<u64, CompatErrno> {
    const PERSONALITY_QUERY: u32 = u32::MAX;
    let current = proc::linux_personality(pid).ok_or(CompatErrno::NoProcess)?;
    let requested = requested as u32;
    if requested == PERSONALITY_QUERY {
        return Ok(u64::from(current));
    }
    if requested != 0 {
        return Err(CompatErrno::Invalid);
    }
    if !proc::set_linux_personality(pid, requested) {
        return Err(CompatErrno::NoProcess);
    }
    Ok(u64::from(current))
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

/// Reports scheduler-accounted CPU time for the process or current thread.
///
/// 返回进程、当前线程或已等待直接子进程的调度器 CPU 时间。
fn linux_getrusage(pid: ObjId, args: [u64; 6]) -> Result<u64, CompatErrno> {
    const RUSAGE_SELF: i32 = 0;
    const RUSAGE_CHILDREN: i32 = -1;
    const RUSAGE_THREAD: i32 = 1;
    const RUSAGE_BYTES: usize = 144;
    let ticks = match args[0] as u32 as i32 {
        RUSAGE_SELF => proc::linux_process_cpu_ticks(pid).ok_or(CompatErrno::NoProcess)?,
        RUSAGE_THREAD => {
            let (task, _) = sched::current();
            linux_tid(pid).ok_or(CompatErrno::NoProcess)?;
            sched::cpu_ticks(task).ok_or(CompatErrno::NoProcess)?
        }
        RUSAGE_CHILDREN => proc::linux_children_cpu_ticks(pid).ok_or(CompatErrno::NoProcess)?,
        _ => return Err(CompatErrno::Invalid),
    };
    let nanoseconds = ticks.saturating_mul(crate::hrtime::tick_ns());
    let mut usage = [0u8; RUSAGE_BYTES];
    usage[0..8].copy_from_slice(&(nanoseconds / 1_000_000_000).to_le_bytes());
    usage[8..16].copy_from_slice(&((nanoseconds % 1_000_000_000) / 1_000).to_le_bytes());
    copy_to_user(args[1], &usage, usage.len()).map_err(|_| CompatErrno::Fault)?;
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

/// Reports process and waited-child CPU ticks in the legacy `tms` layout.
/// 以传统 `tms` 布局报告进程与已等待子进程 CPU ticks。
fn linux_times(pid: ObjId, args: [u64; 6]) -> Result<u64, CompatErrno> {
    let self_ticks = proc::linux_process_cpu_ticks(pid).ok_or(CompatErrno::NoProcess)?;
    let child_ticks = proc::linux_children_cpu_ticks(pid).ok_or(CompatErrno::NoProcess)?;
    if args[0] != 0 {
        let mut times = [0u8; 32];
        times[0..8].copy_from_slice(&self_ticks.to_le_bytes());
        times[16..24].copy_from_slice(&child_ticks.to_le_bytes());
        copy_to_user(args[0], &times, times.len()).map_err(|_| CompatErrno::Fault)?;
    }
    Ok(sched::timer_ticks())
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

/// Implements `pause(2)`, returning after one unmasked signal wakes the task.
fn linux_pause(pid: ObjId) -> Result<u64, CompatErrno> {
    loop {
        if proc::current_exiting() || current_signal_pending(pid) {
            return Err(CompatErrno::Interrupted);
        }
        sched::pause();
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

const LINUX_SIGALRM: u32 = 14;
const LINUX_SI_KERNEL: i32 = 128;
const ITIMER_REAL: u32 = 0;
const ITIMER_VIRTUAL: u32 = 1;
const ITIMER_PROF: u32 = 2;

/// Decodes one x86_64 `timeval` represented in a fixed little-endian buffer.
fn decode_linux_timeval(bytes: &[u8]) -> Result<u64, CompatErrno> {
    let seconds = i64::from_le_bytes(bytes[0..8].try_into().unwrap());
    let micros = i64::from_le_bytes(bytes[8..16].try_into().unwrap());
    if seconds < 0 || !(0..1_000_000).contains(&micros) {
        return Err(CompatErrno::Invalid);
    }
    (seconds as u64)
        .checked_mul(1_000_000_000)
        .and_then(|value| value.checked_add((micros as u64) * 1_000))
        .ok_or(CompatErrno::Invalid)
}

/// Reads x86_64 `struct itimerval` as `(interval, value)` nanoseconds.
fn read_linux_itimerval(address: u64) -> Result<(u64, u64), CompatErrno> {
    const ITIMERVAL_BYTES: usize = 32;
    if address == 0 {
        return Err(CompatErrno::Fault);
    }
    let mut bytes = [0u8; ITIMERVAL_BYTES];
    copy_from_user(&mut bytes, address, ITIMERVAL_BYTES).map_err(|_| CompatErrno::Fault)?;
    let interval = decode_linux_timeval(&bytes[..16])?;
    let value = decode_linux_timeval(&bytes[16..])?;
    Ok((interval, value))
}

/// Encodes x86_64 `struct itimerval`; `next` is an absolute monotonic deadline.
fn encode_linux_itimerval(interval: u64, next: u64, now: u64) -> [u8; 32] {
    let remaining = if next == 0 {
        0
    } else {
        next.saturating_sub(now)
    };
    let mut bytes = [0u8; 32];
    bytes[0..8].copy_from_slice(&(interval / 1_000_000_000).to_le_bytes());
    bytes[8..16].copy_from_slice(&((interval % 1_000_000_000) / 1_000).to_le_bytes());
    bytes[16..24].copy_from_slice(&(remaining / 1_000_000_000).to_le_bytes());
    bytes[24..32].copy_from_slice(&((remaining % 1_000_000_000) / 1_000).to_le_bytes());
    bytes
}

/// Advances one expired real interval timer and reports whether it fired.
fn settle_interval_timer(timer: &mut IntervalTimer, now: u64) -> bool {
    if !timer.active || now < timer.next {
        return false;
    }
    let expired = if timer.interval == 0 {
        1
    } else {
        (now - timer.next) / timer.interval + 1
    };
    timer.next = if timer.interval == 0 {
        0
    } else {
        timer
            .next
            .saturating_add(expired.saturating_mul(timer.interval))
    };
    timer.active = timer.next != 0;
    true
}

/// Validates one interval-timer selector.
fn validate_itimer_which(which: u64) -> Result<u32, CompatErrno> {
    let which = u32::try_from(which).map_err(|_| CompatErrno::Invalid)?;
    match which {
        ITIMER_REAL => Ok(which),
        ITIMER_VIRTUAL | ITIMER_PROF => Err(CompatErrno::NotSupported),
        _ => Err(CompatErrno::Invalid),
    }
}

/// Returns the settled REAL timer snapshot and whether it just fired.
fn interval_timer_snapshot(pid: ObjId, now: u64) -> (u64, u64, bool) {
    let mut state = COMPAT.lock();
    let Some(timer) = state
        .interval_timers
        .iter_mut()
        .flatten()
        .find(|timer| timer.process == pid)
    else {
        return (0, 0, false);
    };
    let fired = settle_interval_timer(timer, now);
    (timer.next, timer.interval, fired)
}

/// Replaces the process REAL interval timer, allocating its bounded state slot on demand.
fn replace_interval_timer(
    pid: ObjId,
    next: u64,
    interval: u64,
) -> Result<(), CompatErrno> {
    let mut state = COMPAT.lock();
    if let Some(timer) = state
        .interval_timers
        .iter_mut()
        .flatten()
        .find(|timer| timer.process == pid)
    {
        *timer = IntervalTimer {
            process: pid,
            next,
            interval,
            active: next != 0,
        };
        return Ok(());
    }
    if next == 0 {
        return Ok(());
    }
    let slot = state
        .interval_timers
        .iter()
        .position(Option::is_none)
        .ok_or(CompatErrno::NoSpace)?;
    state.interval_timers[slot] = Some(IntervalTimer {
        process: pid,
        next,
        interval,
        active: true,
    });
    Ok(())
}

/// Implements `getitimer(2)` for the monotonic real timer.
fn linux_getitimer(pid: ObjId, args: [u64; 6]) -> Result<u64, CompatErrno> {
    validate_itimer_which(args[0])?;
    if args[1] == 0 {
        return Err(CompatErrno::Fault);
    }
    let now = sched::now_ns();
    let (next, interval, fired) = interval_timer_snapshot(pid, now);
    if fired {
        let _ = queue_process_signal(pid, LINUX_SIGALRM, 0, LINUX_SI_KERNEL);
    }
    let output = encode_linux_itimerval(interval, next, now);
    copy_to_user(args[1], &output, output.len()).map_err(|_| CompatErrno::Fault)?;
    Ok(0)
}

/// Implements `setitimer(2)` and writes the prior value before replacement.
fn linux_setitimer(pid: ObjId, args: [u64; 6]) -> Result<u64, CompatErrno> {
    validate_itimer_which(args[0])?;
    let (interval, value) = if args[1] == 0 {
        (0, 0)
    } else {
        read_linux_itimerval(args[1])?
    };
    let now = sched::now_ns();
    let next = if value == 0 {
        0
    } else {
        now.checked_add(value).ok_or(CompatErrno::Invalid)?
    };
    let (old_next, old_interval, fired) = interval_timer_snapshot(pid, now);
    replace_interval_timer(pid, next, interval)?;
    if fired {
        let _ = queue_process_signal(pid, LINUX_SIGALRM, 0, LINUX_SI_KERNEL);
    }
    if args[2] != 0 {
        let old = encode_linux_itimerval(old_interval, old_next, now);
        copy_to_user(args[2], &old, old.len()).map_err(|_| CompatErrno::Fault)?;
    }
    Ok(0)
}

/// Implements legacy `alarm(2)` over the REAL interval timer.
fn linux_alarm(pid: ObjId, args: [u64; 6]) -> Result<u64, CompatErrno> {
    let seconds = u64::from(args[0] as u32);
    let now = sched::now_ns();
    let (old_next, _, fired) = interval_timer_snapshot(pid, now);
    let old_seconds = if old_next == 0 {
        0
    } else {
        old_next
            .saturating_sub(now)
            .div_ceil(1_000_000_000)
    };
    if fired {
        let _ = queue_process_signal(pid, LINUX_SIGALRM, 0, LINUX_SI_KERNEL);
    }
    let next = if seconds == 0 {
        0
    } else {
        now.checked_add(
            seconds
                .checked_mul(1_000_000_000)
                .ok_or(CompatErrno::Invalid)?,
        )
        .ok_or(CompatErrno::Invalid)?
    };
    replace_interval_timer(pid, next, 0)?;
    Ok(old_seconds)
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
    let node = proc::linux_fd(pid, fd).and_then(|entry| match entry.kind {
        compat_core::fd::CompatKind::File => crate::linux_vfs::FileId::from_handle(entry.handle)
            .map(crate::linux_vfs::Node::File),
        compat_core::fd::CompatKind::Directory => {
            crate::linux_vfs::DirectoryId::from_handle(entry.handle)
                .map(crate::linux_vfs::Node::Directory)
        }
        compat_core::fd::CompatKind::Path => proc::linux_path_node(pid, fd),
        _ => None,
    });
    if proc::linux_close_fd(pid, fd) {
        if let Some(node) = node {
            proc::linux_fanotify_notify(
                node,
                0x10u64
                    | if node.is_directory() {
                        0x4000_0000u64
                    } else {
                        0
                    },
                proc::linux_pid(pid).unwrap_or(0),
            );
        }
        Ok(0)
    } else {
        Err(CompatErrno::BadFd)
    }
}

fn linux_close_range(pid: ObjId, args: [u64; 6]) -> Result<u64, CompatErrno> {
    const CLOSE_RANGE_UNSHARE: u64 = 0x2;
    const CLOSE_RANGE_CLOEXEC: u64 = 0x4;
    let first = u32::try_from(args[0]).map_err(|_| CompatErrno::BadFd)?;
    let last = u32::try_from(args[1]).map_err(|_| CompatErrno::BadFd)?;
    if first > last {
        return Err(CompatErrno::Invalid);
    }
    if args[2] & !(CLOSE_RANGE_UNSHARE | CLOSE_RANGE_CLOEXEC) != 0 {
        return Err(CompatErrno::Invalid);
    }
    if proc::linux_close_range(
        pid,
        first,
        last,
        args[2] & CLOSE_RANGE_CLOEXEC != 0,
        args[2] & CLOSE_RANGE_UNSHARE != 0,
    ) {
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

/// Converts an x86_64 syscall argument to a non-negative Linux `int` fd.
///
/// x86_64 zero-extends negative `int` arguments into a 64-bit register. Values
/// outside `0..=i32::MAX` therefore cannot name a valid descriptor.
fn linux_fd_argument(value: u64) -> Result<u32, CompatErrno> {
    let fd = u32::try_from(value).map_err(|_| CompatErrno::BadFd)?;
    if fd > i32::MAX as u32 {
        return Err(CompatErrno::BadFd);
    }
    Ok(fd)
}

/// Implements `dup2(2)`, including same-fd and exact-target replacement semantics.
///
/// 实现精确目标 fd 的复制；同一 fd 成功返回，目标已占用时原子替换且清除 CLOEXEC。
fn linux_dup2(pid: ObjId, args: [u64; 6]) -> Result<u64, CompatErrno> {
    let source = linux_fd_argument(args[0])?;
    let target = linux_fd_argument(args[1])?;
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
    let source = linux_fd_argument(args[0])?;
    let target = linux_fd_argument(args[1])?;
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

/// Implements legacy `pipe(2)` through the bounded `pipe2(2)` path.
fn linux_pipe(pid: ObjId, args: [u64; 6]) -> Result<u64, CompatErrno> {
    linux_pipe2(pid, [args[0], 0, 0, 0, 0, 0])
}

fn linux_memfd_create(pid: ObjId, args: [u64; 6]) -> Result<u64, CompatErrno> {
    const MFD_CLOEXEC: u64 = 0x1;
    const MFD_ALLOW_SEALING: u64 = 0x2;
    if args[1] & !(MFD_CLOEXEC | MFD_ALLOW_SEALING) != 0 {
        return Err(CompatErrno::NoSys);
    }
    let name = linux_c_string(args[0], 249)?;
    let fd = proc::linux_create_memfd(
        pid,
        args[1] & MFD_CLOEXEC != 0,
        args[1] & MFD_ALLOW_SEALING != 0,
    )
    .ok_or(CompatErrno::NoSpace)?;
    let entry = proc::linux_fd(pid, fd).ok_or(CompatErrno::BadFd)?;
    if proc::linux_ashmem_set_name(pid, entry.handle, &name).is_err() {
        let _ = proc::linux_close_fd(pid, fd);
        return Err(CompatErrno::NoMemory);
    }
    Ok(u64::from(fd))
}

/// Creates one close-on-exec anonymous resident memory file.
fn linux_memfd_secret(pid: ObjId, args: [u64; 6]) -> Result<u64, CompatErrno> {
    const O_CLOEXEC: u64 = 0x80000;
    if args[0] & !O_CLOEXEC != 0 {
        return Err(CompatErrno::Invalid);
    }
    let fd = proc::linux_create_memfd(pid, true, false).ok_or(CompatErrno::NoSpace)?;
    let entry = proc::linux_fd(pid, fd).ok_or(CompatErrno::BadFd)?;
    if proc::linux_ashmem_set_name(pid, entry.handle, b"secretmem").is_err() {
        let _ = proc::linux_close_fd(pid, fd);
        return Err(CompatErrno::NoMemory);
    }
    Ok(u64::from(fd))
}

const LINUX_MQ_ATTR_BYTES: usize = 32;
const LINUX_MQ_MSG_MAX: i64 = 10;
const LINUX_MQ_MSGSIZE_MAX: i64 = 8192;

/// Reads and validates the slash-free name consumed by Linux's raw syscall.
fn read_linux_mq_name(address: u64) -> Result<([u8; 256], u8), CompatErrno> {
    let name = linux_c_string(address, 256)?;
    if name.len() > 255 || name.contains(&b'/') {
        return Err(CompatErrno::Invalid);
    }
    let mut output = [0u8; 256];
    output[..name.len()].copy_from_slice(&name);
    Ok((output, name.len() as u8))
}

/// Reads one x86-64 Linux message-queue attribute block.
fn read_linux_mq_attr(address: u64) -> Result<[u8; LINUX_MQ_ATTR_BYTES], CompatErrno> {
    let mut attr = [0u8; LINUX_MQ_ATTR_BYTES];
    copy_from_user(&mut attr, address, LINUX_MQ_ATTR_BYTES)
        .map_err(|_| CompatErrno::Fault)?;
    Ok(attr)
}

/// Parses the creation-only limits, ignoring flags and current message count.
fn parse_linux_mq_limits(
    attr: [u8; LINUX_MQ_ATTR_BYTES],
) -> Result<(usize, usize), CompatErrno> {
    let max_messages = i64::from_le_bytes(attr[8..16].try_into().unwrap());
    let message_size = i64::from_le_bytes(attr[16..24].try_into().unwrap());
    if !(1..=LINUX_MQ_MSG_MAX).contains(&max_messages)
        || !(1..=LINUX_MQ_MSGSIZE_MAX).contains(&message_size)
    {
        return Err(CompatErrno::Invalid);
    }
    Ok((max_messages as usize, message_size as usize))
}

/// Applies one POSIX message-queue inode permission check.
fn message_queue_access(
    credentials: proc::LinuxCredentials,
    supplementary_groups: &[u32],
    uid: u32,
    gid: u32,
    mode: u16,
    rights: kernel_core::object::Rights,
) -> bool {
    if credentials.euid == 0 {
        return true;
    }
    let shift = if credentials.fsuid == uid {
        6
    } else if credentials.fsgid == gid || supplementary_groups.contains(&gid) {
        3
    } else {
        0
    };
    let mut required = 0u16;
    if rights.contains(kernel_core::object::Rights::READ) {
        required |= 0o4;
    }
    if rights.contains(kernel_core::object::Rights::WRITE) {
        required |= 0o2;
    }
    (mode >> shift) & required == required
}

/// Resolves one message-queue descriptor and verifies its access right.
fn open_message_queue(
    pid: ObjId,
    raw_fd: u64,
    write: bool,
) -> Result<(u32, alloc::sync::Arc<proc::LinuxMqShared>), CompatErrno> {
    let fd = u32::try_from(raw_fd).map_err(|_| CompatErrno::BadFd)?;
    let entry = proc::linux_fd(pid, fd).ok_or(CompatErrno::BadFd)?;
    if entry.kind != compat_core::fd::CompatKind::MessageQueue
        || !entry.rights.contains(if write {
            kernel_core::object::Rights::WRITE
        } else {
            kernel_core::object::Rights::READ
        })
    {
        return Err(CompatErrno::BadFd);
    }
    let queue = proc::linux_mq_state(pid, entry.handle).ok_or(CompatErrno::BadFd)?;
    Ok((fd, queue))
}

/// Resolves one message-queue descriptor without imposing an I/O direction.
fn open_message_queue_any(
    pid: ObjId,
    raw_fd: u64,
) -> Result<(u32, alloc::sync::Arc<proc::LinuxMqShared>), CompatErrno> {
    let fd = u32::try_from(raw_fd).map_err(|_| CompatErrno::BadFd)?;
    let entry = proc::linux_fd(pid, fd).ok_or(CompatErrno::BadFd)?;
    if entry.kind != compat_core::fd::CompatKind::MessageQueue {
        return Err(CompatErrno::BadFd);
    }
    let queue = proc::linux_mq_state(pid, entry.handle).ok_or(CompatErrno::BadFd)?;
    Ok((fd, queue))
}

/// Wakes Linux threads so blocked queue senders and receivers can recheck.
pub(crate) fn wake_message_queue_waiters() {
    let mut tasks = [None; MAX_LINUX_THREADS];
    let mut count = 0usize;
    {
        let state = COMPAT.lock();
        for thread in state.threads.iter().flatten() {
            if count < tasks.len() {
                tasks[count] = Some(thread.task);
                count += 1;
            }
        }
    }
    for task in tasks[..count].iter().flatten() {
        sched::wake(*task);
    }
}

/// Implements `mq_open(2)` with bounded names and queue storage.
fn linux_mq_open(pid: ObjId, args: [u64; 6]) -> Result<u64, CompatErrno> {
    const O_ACCMODE: u64 = 0x3;
    const O_CREAT: u64 = 0x40;
    const O_EXCL: u64 = 0x80;
    const O_NONBLOCK: u64 = 0x800;
    const O_CLOEXEC: u64 = 0x80000;
    let requested_attr = if args[3] == 0 {
        None
    } else {
        Some(read_linux_mq_attr(args[3])?)
    };
    let flags = args[1];
    if flags & !(O_ACCMODE | O_CREAT | O_EXCL | O_NONBLOCK | O_CLOEXEC) != 0
        || flags & O_ACCMODE == O_ACCMODE
    {
        return Err(CompatErrno::Invalid);
    }
    let (name, name_len) = read_linux_mq_name(args[0])?;
    let credentials = proc::linux_credentials(pid).ok_or(CompatErrno::NoProcess)?;
    let supplementary_groups =
        proc::linux_supplementary_groups(pid).ok_or(CompatErrno::NoProcess)?;
    let rights = match flags & O_ACCMODE {
        0 => kernel_core::object::Rights::READ,
        1 => kernel_core::object::Rights::WRITE,
        _ => kernel_core::object::Rights::READ.union(kernel_core::object::Rights::WRITE),
    };
    let install = |queue: alloc::sync::Arc<proc::LinuxMqShared>| {
        proc::linux_mq_install(
            pid,
            queue,
            rights,
            true,
            flags & O_NONBLOCK != 0,
        )
        .ok_or(CompatErrno::NoSpace)
    };
    let existing = {
        let state = COMPAT.lock();
        state
            .message_queue_names
            .iter()
            .find(|entry| entry.name == name && entry.name_len == name_len)
            .map(|entry| {
                (
                    alloc::sync::Arc::clone(&entry.queue),
                    entry.uid,
                    entry.gid,
                    entry.mode,
                )
            })
    };
    if let Some((queue, uid, gid, mode)) = existing {
        if flags & (O_CREAT | O_EXCL) == (O_CREAT | O_EXCL) {
            return Err(CompatErrno::Exists);
        }
        if !message_queue_access(
            credentials,
            &supplementary_groups,
            uid,
            gid,
            mode,
            rights,
        ) {
            return Err(CompatErrno::Access);
        }
        return install(queue).map(u64::from);
    }
    if flags & O_CREAT == 0 {
        return Err(CompatErrno::NoEntry);
    }
    let (max_messages, message_size) = if let Some(attr) = requested_attr {
        parse_linux_mq_limits(attr)?
    } else {
        (LINUX_MQ_MSG_MAX as usize, LINUX_MQ_MSGSIZE_MAX as usize)
    };
    let candidate = alloc::sync::Arc::new(proc::LinuxMqShared {
        state: kernel_core::sync::SpinLock::new(proc::LinuxMqState {
            max_messages,
            message_size,
            messages: alloc::collections::VecDeque::new(),
            blocked_receivers: 0,
            notification: None,
        }),
    });
    let mode = ((args[2] as u16) & 0o777)
        & !(proc::linux_umask(pid).ok_or(CompatErrno::NoProcess)? as u16);
    let candidate_fd = install(alloc::sync::Arc::clone(&candidate))?;
    let registration = {
        let mut state = COMPAT.lock();
        if let Some(queue) = state
            .message_queue_names
            .iter()
            .find(|entry| entry.name == name && entry.name_len == name_len)
        {
            Ok(Some((
                alloc::sync::Arc::clone(&queue.queue),
                queue.uid,
                queue.gid,
                queue.mode,
            )))
        } else if state.message_queue_names.len() >= 16 {
            Err(CompatErrno::NoSpace)
        } else {
            match state.message_queue_names.try_reserve(1) {
                Ok(()) => {
                    state.message_queue_names.push(MessageQueueName {
                        name,
                        name_len,
                        queue: candidate,
                        uid: credentials.fsuid,
                        gid: credentials.fsgid,
                        mode,
                    });
                    Ok(None)
                }
                Err(_) => Err(CompatErrno::NoMemory),
            }
        }
    };
    match registration {
        Ok(None) => Ok(u64::from(candidate_fd)),
        Ok(Some((queue, uid, gid, mode))) => {
            let _ = proc::linux_close_fd(pid, candidate_fd);
            if flags & O_EXCL != 0 {
                return Err(CompatErrno::Exists);
            }
            if !message_queue_access(
                credentials,
                &supplementary_groups,
                uid,
                gid,
                mode,
                rights,
            ) {
                return Err(CompatErrno::Perm);
            }
            install(queue).map(u64::from)
        }
        Err(error) => {
            let _ = proc::linux_close_fd(pid, candidate_fd);
            Err(error)
        }
    }
}

/// Removes one POSIX message-queue name while existing descriptors retain the queue.
fn linux_mq_unlink(pid: ObjId, args: [u64; 6]) -> Result<u64, CompatErrno> {
    let (name, name_len) = read_linux_mq_name(args[0])?;
    let credentials = proc::linux_credentials(pid).ok_or(CompatErrno::NoProcess)?;
    let mut state = COMPAT.lock();
    let Some(index) = state
        .message_queue_names
        .iter()
        .position(|entry| entry.name == name && entry.name_len == name_len)
    else {
        return Err(CompatErrno::NoEntry);
    };
    if credentials.euid != 0 && credentials.euid != state.message_queue_names[index].uid {
        return Err(CompatErrno::Access);
    }
    state.message_queue_names.remove(index);
    Ok(0)
}

/// Parses one optional absolute CLOCK_REALTIME message-queue timeout.
fn mq_deadline(pointer: u64) -> Result<Option<u64>, CompatErrno> {
    if pointer == 0 {
        return Ok(None);
    }
    let requested = read_linux_timespec(pointer)?;
    let wall = crate::arch::wall_clock_ns().ok_or(CompatErrno::NoSys)?;
    Ok(Some(
        sched::now_ns().saturating_add(requested.saturating_sub(wall)),
    ))
}

/// Implements `mq_timedsend(2)`.
fn linux_mq_send(pid: ObjId, args: [u64; 6], timed: bool) -> Result<u64, CompatErrno> {
    const MQ_PRIO_MAX: u32 = 32768;
    const SIGEV_SIGNAL: u32 = 0;
    const SI_MESGQ: i32 = -3;
    let deadline = if timed { mq_deadline(args[4])? } else { None };
    let priority = u32::try_from(args[3]).map_err(|_| CompatErrno::Invalid)?;
    if priority >= MQ_PRIO_MAX {
        return Err(CompatErrno::Invalid);
    }
    let (fd, queue) = open_message_queue(pid, args[0], true)?;
    let length = usize::try_from(args[2]).map_err(|_| CompatErrno::Invalid)?;
    if length > queue.state.lock().message_size {
        return Err(CompatErrno::MessageSize);
    }
    let mut bytes = alloc::vec![0u8; length];
    if length != 0 {
        copy_from_user(&mut bytes, args[1], length).map_err(|_| CompatErrno::Fault)?;
    }
    let notification = loop {
        if proc::current_exiting() || current_signal_pending(pid) {
            return Err(CompatErrno::Interrupted);
        }
        let nonblocking = proc::linux_fd_status_flags(pid, fd).unwrap_or(0) & 0x800 != 0;
        {
            let mut state = queue.state.lock();
            if state.messages.len() < state.max_messages {
                let was_empty = state.messages.is_empty();
                let blocked_receivers = state.blocked_receivers;
                state
                    .messages
                    .try_reserve(1)
                    .map_err(|_| CompatErrno::NoMemory)?;
                let notify = (was_empty && blocked_receivers == 0)
                    .then(|| state.notification.take())
                    .flatten();
                let position = state
                    .messages
                    .iter()
                    .position(|message| message.priority < priority)
                    .unwrap_or(state.messages.len());
                state
                    .messages
                    .insert(position, proc::LinuxMqMessage { priority, bytes });
                break notify;
            }
            if nonblocking {
                return Err(CompatErrno::TryAgain);
            }
        }
        if deadline.is_some_and(|deadline| sched::now_ns() >= deadline) {
            return Err(CompatErrno::TimedOut);
        }
        if let Some(deadline) = deadline {
            if sched::sleep_until_ns(deadline).is_err() {
                sched::pause();
            }
        } else {
            sched::pause();
        }
    };
    if let Some(notification) = notification {
        if notification.notify == SIGEV_SIGNAL {
            let sender_pid = proc::linux_pid(pid).ok_or(CompatErrno::NoProcess)?;
            let sender_uid = proc::linux_credentials(pid)
                .ok_or(CompatErrno::NoProcess)?
                .uid;
            let _ = queue_process_signal_info(
                notification.process,
                notification.signal,
                sender_pid,
                sender_uid,
                SI_MESGQ,
                notification.value,
            );
        }
    }
    wake_message_queue_waiters();
    Ok(0)
}

/// Implements `mq_timedreceive(2)`.
fn linux_mq_receive(pid: ObjId, args: [u64; 6], timed: bool) -> Result<u64, CompatErrno> {
    let deadline = if timed { mq_deadline(args[4])? } else { None };
    let (fd, queue) = open_message_queue(pid, args[0], false)?;
    let capacity = usize::try_from(args[2]).map_err(|_| CompatErrno::Invalid)?;
    if capacity < queue.state.lock().message_size {
        return Err(CompatErrno::MessageSize);
    }
    let mut registered_waiter = false;
    let message = (|| {
        loop {
            if proc::current_exiting() || current_signal_pending(pid) {
                return Err(CompatErrno::Interrupted);
            }
            let nonblocking = proc::linux_fd_status_flags(pid, fd).unwrap_or(0) & 0x800 != 0;
            {
                let mut state = queue.state.lock();
                if let Some(message) = state.messages.pop_front() {
                    return Ok(message);
                }
                if nonblocking {
                    return Err(CompatErrno::TryAgain);
                }
                if !registered_waiter {
                    state.blocked_receivers = state.blocked_receivers.saturating_add(1);
                    registered_waiter = true;
                }
            }
            if deadline.is_some_and(|deadline| sched::now_ns() >= deadline) {
                return Err(CompatErrno::TimedOut);
            }
            if let Some(deadline) = deadline {
                if sched::sleep_until_ns(deadline).is_err() {
                    sched::pause();
                }
            } else {
                sched::pause();
            }
        }
    })();
    if registered_waiter {
        let mut state = queue.state.lock();
        state.blocked_receivers = state.blocked_receivers.saturating_sub(1);
    }
    let message = message?;
    if !message.bytes.is_empty() {
        copy_to_user(args[1], &message.bytes, message.bytes.len())
            .map_err(|_| CompatErrno::Fault)?;
    }
    if args[3] != 0 {
        copy_to_user(args[3], &message.priority.to_le_bytes(), 4)
            .map_err(|_| CompatErrno::Fault)?;
    }
    wake_message_queue_waiters();
    Ok(message.bytes.len() as u64)
}

/// Registers or cancels one one-shot message-arrival notification.
fn linux_mq_notify(pid: ObjId, args: [u64; 6]) -> Result<u64, CompatErrno> {
    const SIGEV_SIGNAL: u32 = 0;
    const SIGEV_NONE: u32 = 1;
    let requested = if args[1] == 0 {
        None
    } else {
        let mut notification = [0u8; 64];
        copy_from_user(&mut notification, args[1], 64).map_err(|_| CompatErrno::Fault)?;
        let value = u64::from_le_bytes(notification[..8].try_into().unwrap());
        let signal = u32::from_le_bytes(notification[8..12].try_into().unwrap());
        let notify = u32::from_le_bytes(notification[12..16].try_into().unwrap());
        if !matches!(notify, SIGEV_SIGNAL | SIGEV_NONE)
            || notify == SIGEV_SIGNAL
                && (signal == 0 || signal > 64 || matches!(signal, 9 | 19))
        {
            return Err(CompatErrno::Invalid);
        }
        Some(proc::LinuxMqNotification {
            process: pid,
            notify,
            signal,
            value,
        })
    };
    let (_, queue) = open_message_queue_any(pid, args[0])?;
    let mut state = queue.state.lock();
    if let Some(requested) = requested {
        if state.notification.is_some() {
            return Err(CompatErrno::Busy);
        }
        state.notification = Some(requested);
        Ok(0)
    } else {
        if state
            .notification
            .is_some_and(|notification| notification.process == pid)
        {
            state.notification = None;
            Ok(0)
        } else {
            Err(CompatErrno::Invalid)
        }
    }
}

/// Queries or updates one message-queue attribute block.
fn linux_mq_getsetattr(pid: ObjId, args: [u64; 6]) -> Result<u64, CompatErrno> {
    let requested = if args[1] == 0 {
        None
    } else {
        Some(read_linux_mq_attr(args[1])?)
    };
    if requested
        .is_some_and(|attr| i64::from_le_bytes(attr[0..8].try_into().unwrap()) & !0x800 != 0)
    {
        return Err(CompatErrno::Invalid);
    }
    let (fd, queue) = open_message_queue_any(pid, args[0])?;
    let (max_messages, message_size, current_messages) = {
        let state = queue.state.lock();
        (
            state.max_messages,
            state.message_size,
            state.messages.len(),
        )
    };
    let old = [
        i64::from(proc::linux_fd_status_flags(pid, fd).ok_or(CompatErrno::BadFd)? & 0x800),
        max_messages as i64,
        message_size as i64,
        current_messages as i64,
    ];
    if let Some(attr) = requested {
        let flags = i64::from_le_bytes(attr[0..8].try_into().unwrap()) as u32;
        if !proc::linux_set_fd_status_flags(pid, fd, flags) {
            return Err(CompatErrno::BadFd);
        }
    }
    if args[2] != 0 {
        let mut attr = [0u8; LINUX_MQ_ATTR_BYTES];
        for (index, value) in old.iter().enumerate() {
            attr[index * 8..index * 8 + 8].copy_from_slice(&value.to_le_bytes());
        }
        copy_to_user(args[2], &attr, attr.len()).map_err(|_| CompatErrno::Fault)?;
    }
    Ok(0)
}

const SYSV_IPC_CREAT: u32 = 0o1000;
const SYSV_IPC_EXCL: u32 = 0o2000;
const SYSV_IPC_NOWAIT: u32 = 0o4000;
const SYSV_MSG_NOERROR: u32 = 0o10000;
const SYSV_MSG_EXCEPT: u32 = 0o20000;
const SYSV_MSG_COPY: u32 = 0o40000;
const SYSV_MSG_DS_BYTES: usize = 120;

fn sysv_message_queue_index(
    state: &CompatState,
    application: kernel_core::security::ApplicationIdentity,
    id: i32,
) -> Option<usize> {
    state
        .sysv_message_queues
        .iter()
        .position(|queue| queue.application == application && queue.id == id)
}

fn sysv_message_access(
    queue: &SysVMessageQueue,
    credentials: proc::LinuxCredentials,
    groups: &[u32],
    write: bool,
) -> bool {
    if credentials.euid == 0 {
        return true;
    }
    let shift = if credentials.euid == queue.uid {
        6
    } else if credentials.egid == queue.gid || groups.contains(&queue.gid) {
        3
    } else {
        0
    };
    let required = if write { 0o2 } else { 0o4 };
    queue.mode >> shift & required == required
}

fn sysv_time_seconds() -> i64 {
    crate::arch::wall_clock_ns()
        .map(|time| (time / 1_000_000_000) as i64)
        .unwrap_or_else(|| (sched::now_ns() / 1_000_000_000) as i64)
}

fn sysv_msg_ds_bytes(queue: &SysVMessageQueue) -> [u8; SYSV_MSG_DS_BYTES] {
    let mut output = [0u8; SYSV_MSG_DS_BYTES];
    output[0..4].copy_from_slice(&(queue.key as u32).to_le_bytes());
    output[4..8].copy_from_slice(&queue.uid.to_le_bytes());
    output[8..12].copy_from_slice(&queue.gid.to_le_bytes());
    output[12..16].copy_from_slice(&queue.cuid.to_le_bytes());
    output[16..20].copy_from_slice(&queue.cgid.to_le_bytes());
    output[20..24].copy_from_slice(&u32::from(queue.mode).to_le_bytes());
    output[24..26].copy_from_slice(&(queue.id as u16).to_le_bytes());
    output[48..56].copy_from_slice(&queue.send_time.to_le_bytes());
    output[56..64].copy_from_slice(&queue.receive_time.to_le_bytes());
    output[64..72].copy_from_slice(&queue.change_time.to_le_bytes());
    output[72..80].copy_from_slice(&(queue.cbytes as u64).to_le_bytes());
    output[80..88].copy_from_slice(&(queue.messages.len() as u64).to_le_bytes());
    output[88..96].copy_from_slice(&(queue.qbytes as u64).to_le_bytes());
    output[96..100].copy_from_slice(&queue.last_send_pid.to_le_bytes());
    output[100..104].copy_from_slice(&queue.last_receive_pid.to_le_bytes());
    output
}

fn sysv_select_message(queue: &SysVMessageQueue, msgtyp: i64, flags: u32) -> Option<usize> {
    if flags & SYSV_MSG_COPY != 0 {
        let ordinal = usize::try_from(msgtyp).ok()?;
        return queue
            .messages
            .iter()
            .enumerate()
            .filter(|(_, message)| !message.reserved)
            .nth(ordinal)
            .map(|(index, _)| index);
    }
    if msgtyp == 0 {
        return queue
            .messages
            .iter()
            .position(|message| !message.reserved);
    }
    if msgtyp > 0 {
        return queue.messages.iter().position(|message| {
            !message.reserved
                && if flags & SYSV_MSG_EXCEPT != 0 {
                    message.mtype != msgtyp
                } else {
                    message.mtype == msgtyp
                }
        });
    }
    let maximum = msgtyp.unsigned_abs();
    queue
        .messages
        .iter()
        .enumerate()
        .filter(|(_, message)| !message.reserved && message.mtype.unsigned_abs() <= maximum)
        .min_by_key(|(index, message)| (message.mtype, *index))
        .map(|(index, _)| index)
}

/// Implements `msgget(2)` over the compatibility application's IPC namespace.
fn linux_msgget(pid: ObjId, args: [u64; 6]) -> Result<u64, CompatErrno> {
    let key = args[0] as u32 as i32;
    let flags = u32::try_from(args[1]).map_err(|_| CompatErrno::Invalid)?;
    if flags & !(0o777 | SYSV_IPC_CREAT | SYSV_IPC_EXCL | SYSV_IPC_NOWAIT) != 0 {
        return Err(CompatErrno::Invalid);
    }
    let application =
        linux_application_identity(pid).ok_or(CompatErrno::Perm)?;
    let credentials = proc::linux_credentials(pid).ok_or(CompatErrno::NoProcess)?;
    // Linux System V IPC creation modes are used verbatim; unlike open(2),
    // msgget(2) does not apply the process umask.
    let mode = flags & 0o777;
    let mut state = COMPAT.lock();
    if key != 0 {
        if let Some(queue) = state
            .sysv_message_queues
            .iter()
            .find(|queue| queue.application == application && queue.key == key)
        {
            if flags & (SYSV_IPC_CREAT | SYSV_IPC_EXCL)
                == (SYSV_IPC_CREAT | SYSV_IPC_EXCL)
            {
                return Err(CompatErrno::Exists);
            }
            return Ok(queue.id as u32 as u64);
        }
    }
    if flags & SYSV_IPC_CREAT == 0 {
        return Err(CompatErrno::NoEntry);
    }
    if state.sysv_message_queues.len() >= MAX_SYSV_MESSAGE_QUEUES {
        return Err(CompatErrno::NoSpace);
    }
    state
        .sysv_message_queues
        .try_reserve(1)
        .map_err(|_| CompatErrno::NoMemory)?;
    let id = state.next_sysv_message_queue_id;
    state.next_sysv_message_queue_id = id.checked_add(1).ok_or(CompatErrno::NoSpace)?;
    let now = sysv_time_seconds();
    state.sysv_message_queues.push(SysVMessageQueue {
        id,
        key,
        application,
        uid: credentials.euid,
        gid: credentials.egid,
        cuid: credentials.euid,
        cgid: credentials.egid,
        mode: mode as u16,
        qbytes: SYSV_MSGMNB,
        cbytes: 0,
        messages: alloc::collections::VecDeque::new(),
        next_message_id: 1,
        send_time: 0,
        receive_time: 0,
        change_time: now,
        last_send_pid: 0,
        last_receive_pid: 0,
    });
    Ok(id as u32 as u64)
}

/// Implements `msgsnd(2)` with typed, bounded messages.
fn linux_msgsnd(pid: ObjId, args: [u64; 6]) -> Result<u64, CompatErrno> {
    let id = args[0] as i32;
    let length = usize::try_from(args[2]).map_err(|_| CompatErrno::Invalid)?;
    let flags = args[4] as u32;
    if flags & !SYSV_IPC_NOWAIT != 0 || length > SYSV_MSGMAX {
        return Err(CompatErrno::Invalid);
    }
    let mut message_type = [0u8; 8];
    copy_from_user(&mut message_type, args[1], 8).map_err(|_| CompatErrno::Fault)?;
    let mtype = i64::from_le_bytes(message_type);
    if mtype <= 0 {
        return Err(CompatErrno::Invalid);
    }
    let mut bytes = alloc::vec![0u8; length];
    if length != 0 {
        let address = args[1].checked_add(8).ok_or(CompatErrno::Fault)?;
        copy_from_user(&mut bytes, address, length).map_err(|_| CompatErrno::Fault)?;
    }
    let mut pending_bytes = Some(bytes);
    let application =
        linux_application_identity(pid).ok_or(CompatErrno::Perm)?;
    let credentials = proc::linux_credentials(pid).ok_or(CompatErrno::NoProcess)?;
    let supplementary_groups =
        proc::linux_supplementary_groups(pid).ok_or(CompatErrno::NoProcess)?;
    let sender_pid = proc::linux_pid(pid).ok_or(CompatErrno::NoProcess)? as i32;
    let mut waited = false;
    loop {
        let mut inserted = false;
        {
            let mut state = COMPAT.lock();
            let queue_index = sysv_message_queue_index(&state, application, id).ok_or(
                if waited {
                    CompatErrno::Removed
                } else {
                    CompatErrno::Invalid
                },
            )?;
            let queue = &mut state.sysv_message_queues[queue_index];
            if !sysv_message_access(queue, credentials, &supplementary_groups, true) {
                return Err(CompatErrno::Access);
            }
            if length > queue.qbytes {
                return Err(CompatErrno::MessageSize);
            }
            if queue.messages.len() < MAX_SYSV_MESSAGES_PER_QUEUE
                && queue.cbytes.saturating_add(length) <= queue.qbytes
            {
                let message_id = queue.next_message_id;
                queue.next_message_id =
                    message_id.checked_add(1).ok_or(CompatErrno::NoSpace)?;
                queue.messages.push_back(SysVMessage {
                    id: message_id,
                    mtype,
                    bytes: pending_bytes.take().expect("message bytes consumed once"),
                    reserved: false,
                });
                queue.cbytes += length;
                queue.send_time = sysv_time_seconds();
                queue.last_send_pid = sender_pid;
                inserted = true;
            } else if flags & SYSV_IPC_NOWAIT != 0 {
                return Err(CompatErrno::TryAgain);
            }
        }
        if inserted {
            wake_message_queue_waiters();
            return Ok(0);
        }
        if proc::current_exiting() || current_signal_pending(pid) {
            return Err(CompatErrno::Interrupted);
        }
        waited = true;
        sched::pause();
    }
}

/// Implements `msgrcv(2)` with typed selection, copy mode and reservation.
fn linux_msgrcv(pid: ObjId, args: [u64; 6]) -> Result<u64, CompatErrno> {
    let id = args[0] as i32;
    let capacity = usize::try_from(args[2]).map_err(|_| CompatErrno::Invalid)?;
    let msgtyp = args[3] as i64;
    let flags = args[4] as u32;
    if flags & !(SYSV_IPC_NOWAIT | SYSV_MSG_NOERROR | SYSV_MSG_EXCEPT | SYSV_MSG_COPY) != 0
        || (flags & SYSV_MSG_COPY != 0
            && (msgtyp < 0 || flags & SYSV_IPC_NOWAIT == 0 || flags & SYSV_MSG_EXCEPT != 0))
        || (flags & SYSV_MSG_EXCEPT != 0 && msgtyp <= 0)
    {
        return Err(CompatErrno::Invalid);
    }
    let application =
        linux_application_identity(pid).ok_or(CompatErrno::Perm)?;
    let credentials = proc::linux_credentials(pid).ok_or(CompatErrno::NoProcess)?;
    let supplementary_groups =
        proc::linux_supplementary_groups(pid).ok_or(CompatErrno::NoProcess)?;
    let receiver_pid = proc::linux_pid(pid).ok_or(CompatErrno::NoProcess)? as i32;
    let mut waited = false;
    let message = loop {
        let selected = {
            let mut state = COMPAT.lock();
            let queue_index = sysv_message_queue_index(&state, application, id)
                .ok_or(if waited {
                    CompatErrno::Removed
                } else {
                    CompatErrno::Invalid
                })?;
            let queue = &mut state.sysv_message_queues[queue_index];
            if !sysv_message_access(queue, credentials, &supplementary_groups, false) {
                return Err(CompatErrno::Access);
            }
            match sysv_select_message(queue, msgtyp, flags) {
                Some(message_index) => {
                    if flags & SYSV_MSG_COPY == 0 {
                        queue.messages[message_index].reserved = true;
                    }
                    Some(queue.messages[message_index].clone())
                }
                None => {
                    if flags & SYSV_MSG_COPY != 0 {
                        return Err(CompatErrno::NoMessage);
                    }
                    if flags & SYSV_IPC_NOWAIT != 0 {
                        return Err(CompatErrno::NoMessage);
                    }
                    None
                }
            }
        };
        if let Some(message) = selected {
            break message;
        }
        if proc::current_exiting() || current_signal_pending(pid) {
            return Err(CompatErrno::Interrupted);
        }
        waited = true;
        sched::pause();
    };
    let returned = if message.bytes.len() > capacity {
        if flags & SYSV_MSG_NOERROR == 0 {
            if flags & SYSV_MSG_COPY == 0 {
                let mut state = COMPAT.lock();
                if let Some(queue_index) = sysv_message_queue_index(&state, application, id) {
                    if let Some(queued) = state.sysv_message_queues[queue_index]
                        .messages
                        .iter_mut()
                        .find(|queued| queued.id == message.id)
                    {
                        queued.reserved = false;
                    }
                }
            }
            return Err(CompatErrno::ArgumentTooLong);
        }
        capacity
    } else {
        message.bytes.len()
    };
    let mut output = alloc::vec![0u8; 8 + returned];
    output[..8].copy_from_slice(&message.mtype.to_le_bytes());
    output[8..].copy_from_slice(&message.bytes[..returned]);
    if copy_to_user(args[1], &output, output.len()).is_err() {
        if flags & SYSV_MSG_COPY == 0 {
            let mut state = COMPAT.lock();
            if let Some(queue_index) = sysv_message_queue_index(&state, application, id) {
                if let Some(queued) = state.sysv_message_queues[queue_index]
                    .messages
                    .iter_mut()
                    .find(|queued| queued.id == message.id)
                {
                    queued.reserved = false;
                }
            }
        }
        return Err(CompatErrno::Fault);
    }
    if flags & SYSV_MSG_COPY == 0 {
        {
            let mut state = COMPAT.lock();
            let queue_index =
                sysv_message_queue_index(&state, application, id).ok_or(CompatErrno::Removed)?;
            let queue = &mut state.sysv_message_queues[queue_index];
            let Some(message_index) = queue.messages.iter().position(|queued| {
                queued.id == message.id && queued.reserved
            }) else {
                return Err(CompatErrno::Removed);
            };
            let queued = queue.messages.remove(message_index).unwrap();
            queue.cbytes = queue.cbytes.saturating_sub(queued.bytes.len());
            queue.receive_time = sysv_time_seconds();
            queue.last_receive_pid = receiver_pid;
        }
        wake_message_queue_waiters();
    }
    Ok(returned as u64)
}

fn write_sysv_msginfo(address: u64) -> Result<(), CompatErrno> {
    let mut info = [0u8; 32];
    info[8..12].copy_from_slice(&(SYSV_MSGMAX as i32).to_le_bytes());
    info[12..16].copy_from_slice(&(SYSV_MSGMNB as i32).to_le_bytes());
    info[16..20].copy_from_slice(&(MAX_SYSV_MESSAGE_QUEUES as i32).to_le_bytes());
    info[20..24].copy_from_slice(&16i32.to_le_bytes());
    info[24..28].copy_from_slice(&(SYSV_MSGMNB as i32).to_le_bytes());
    info[28..30].copy_from_slice(&u16::MAX.to_le_bytes());
    copy_to_user(address, &info, info.len()).map_err(|_| CompatErrno::Fault)?;
    Ok(())
}

/// Implements `msgctl(2)` for attributes, removal and bounded introspection.
fn linux_msgctl(pid: ObjId, args: [u64; 6]) -> Result<u64, CompatErrno> {
    const IPC_RMID: u32 = 0;
    const IPC_SET: u32 = 1;
    const IPC_STAT: u32 = 2;
    const IPC_INFO: u32 = 3;
    const MSG_STAT: u32 = 11;
    const MSG_INFO: u32 = 12;
    const MSG_STAT_ANY: u32 = 13;
    let command = u32::try_from(args[1]).map_err(|_| CompatErrno::Invalid)?;
    if command == IPC_INFO || command == MSG_INFO {
        return write_sysv_msginfo(args[2]).map(|()| 0);
    }
    let application =
        linux_application_identity(pid).ok_or(CompatErrno::Perm)?;
    let credentials = proc::linux_credentials(pid).ok_or(CompatErrno::NoProcess)?;
    let supplementary_groups =
        proc::linux_supplementary_groups(pid).ok_or(CompatErrno::NoProcess)?;
    let update = if command == IPC_SET {
        let mut update = [0u8; SYSV_MSG_DS_BYTES];
        copy_from_user(&mut update, args[2], SYSV_MSG_DS_BYTES)
            .map_err(|_| CompatErrno::Fault)?;
        Some(update)
    } else {
        None
    };
    let id = args[0] as i32;
    let mut state = COMPAT.lock();
    let selected_index = match command {
        MSG_STAT | MSG_STAT_ANY => {
            let index = usize::try_from(args[0]).map_err(|_| CompatErrno::Invalid)?;
            state
                .sysv_message_queues
                .iter()
                .enumerate()
                .filter(|(_, queue)| queue.application == application)
                .nth(index)
                .map(|(index, _)| index)
                .ok_or(CompatErrno::Invalid)?
        }
        _ => sysv_message_queue_index(&state, application, id).ok_or(CompatErrno::Invalid)?,
    };
    let queue = &mut state.sysv_message_queues[selected_index];
    match command {
        IPC_RMID => {
            if credentials.euid != 0 && credentials.euid != queue.uid {
                return Err(CompatErrno::Perm);
            }
            let removed = state.sysv_message_queues.remove(selected_index);
            drop(state);
            drop(removed);
            wake_message_queue_waiters();
            Ok(0)
        }
        IPC_SET => {
            if credentials.euid != 0 && credentials.euid != queue.uid {
                return Err(CompatErrno::Perm);
            }
            let update = update.expect("IPC_SET input");
            let mode = u32::from_le_bytes(update[20..24].try_into().unwrap()) as u16;
            let qbytes = u64::from_le_bytes(update[88..96].try_into().unwrap());
            if mode & !0o777 != 0 || qbytes > SYSV_MSGMNB as u64 {
                return Err(CompatErrno::Invalid);
            }
            queue.uid = u32::from_le_bytes(update[4..8].try_into().unwrap());
            queue.gid = u32::from_le_bytes(update[8..12].try_into().unwrap());
            queue.mode = mode;
            queue.qbytes = qbytes as usize;
            queue.change_time = sysv_time_seconds();
            Ok(0)
        }
        IPC_STAT | MSG_STAT | MSG_STAT_ANY => {
            if command != MSG_STAT_ANY
                && !sysv_message_access(
                    queue,
                    credentials,
                    &supplementary_groups,
                    false,
                )
            {
                return Err(CompatErrno::Access);
            }
            let output = sysv_msg_ds_bytes(queue);
            let returned_id = queue.id;
            drop(state);
            copy_to_user(args[2], &output, output.len()).map_err(|_| CompatErrno::Fault)?;
            if command == MSG_STAT {
                Ok(returned_id as u32 as u64)
            } else {
                Ok(0)
            }
        }
        _ => Err(CompatErrno::Invalid),
    }
}

const SYSV_SEM_UNDO: u16 = 0x1000;
const SYSV_SEM_DS_BYTES: usize = 104;

fn sysv_semaphore_set_index(
    state: &CompatState,
    application: kernel_core::security::ApplicationIdentity,
    id: i32,
) -> Option<usize> {
    state
        .sysv_semaphore_sets
        .iter()
        .position(|set| set.application == application && set.id == id)
}

fn sysv_semaphore_access(
    set: &SysVSemaphoreSet,
    credentials: proc::LinuxCredentials,
    groups: &[u32],
    write: bool,
) -> bool {
    if credentials.euid == 0 {
        return true;
    }
    let shift = if credentials.euid == set.uid {
        6
    } else if credentials.egid == set.gid || groups.contains(&set.gid) {
        3
    } else {
        0
    };
    let required = if write { 0o2 } else { 0o4 };
    set.mode >> shift & required == required
}

fn sysv_sem_ds_bytes(set: &SysVSemaphoreSet) -> [u8; SYSV_SEM_DS_BYTES] {
    let mut output = [0u8; SYSV_SEM_DS_BYTES];
    output[0..4].copy_from_slice(&(set.key as u32).to_le_bytes());
    output[4..8].copy_from_slice(&set.uid.to_le_bytes());
    output[8..12].copy_from_slice(&set.gid.to_le_bytes());
    output[12..16].copy_from_slice(&set.cuid.to_le_bytes());
    output[16..20].copy_from_slice(&set.cgid.to_le_bytes());
    output[20..24].copy_from_slice(&u32::from(set.mode).to_le_bytes());
    output[24..26].copy_from_slice(&(set.id as u16).to_le_bytes());
    output[48..56].copy_from_slice(&set.operation_time.to_le_bytes());
    output[56..64].copy_from_slice(&set.change_time.to_le_bytes());
    output[80..88].copy_from_slice(&(set.nsems as u64).to_le_bytes());
    output
}

fn write_sysv_seminfo(address: u64) -> Result<(), CompatErrno> {
    let mut info = [0u8; 40];
    info[4..8].copy_from_slice(&(MAX_SYSV_SEM_SETS as i32).to_le_bytes());
    info[8..12].copy_from_slice(
        &((MAX_SYSV_SEM_SETS * MAX_SYSV_SEMS_PER_SET) as i32).to_le_bytes(),
    );
    info[12..16].copy_from_slice(&(MAX_SYSV_SEM_UNDOS as i32).to_le_bytes());
    info[16..20].copy_from_slice(&(MAX_SYSV_SEMS_PER_SET as i32).to_le_bytes());
    info[20..24].copy_from_slice(&(MAX_SYSV_SEM_OPS as i32).to_le_bytes());
    info[24..28].copy_from_slice(&(MAX_SYSV_SEM_UNDOS as i32).to_le_bytes());
    info[28..32].copy_from_slice(&(MAX_SYSV_SEM_UNDOS as i32).to_le_bytes());
    info[32..36].copy_from_slice(&SYSV_SEMVMX.to_le_bytes());
    info[36..40].copy_from_slice(&SYSV_SEMVMX.to_le_bytes());
    copy_to_user(address, &info, info.len()).map_err(|_| CompatErrno::Fault)?;
    Ok(())
}

fn read_sysv_semaphore_ops(
    address: u64,
    count: usize,
) -> Result<([SysVSemaphoreOperation; MAX_SYSV_SEM_OPS], usize), CompatErrno> {
    if count == 0 || count > MAX_SYSV_SEM_OPS {
        return Err(CompatErrno::Invalid);
    }
    let mut raw = [0u8; MAX_SYSV_SEM_OPS * 6];
    if copy_from_user(&mut raw[..count * 6], address, count * 6).is_err() {
        return Err(CompatErrno::Fault);
    }
    let mut operations = [SysVSemaphoreOperation {
        number: 0,
        operation: 0,
        flags: 0,
    }; MAX_SYSV_SEM_OPS];
    for (index, output) in operations[..count].iter_mut().enumerate() {
        let base = index * 6;
        let flags = i16::from_le_bytes(raw[base + 4..base + 6].try_into().unwrap()) as u16;
        if flags & !(SYSV_IPC_NOWAIT as u16 | SYSV_SEM_UNDO) != 0 {
            return Err(CompatErrno::Invalid);
        }
        *output = SysVSemaphoreOperation {
            number: usize::from(u16::from_le_bytes(raw[base..base + 2].try_into().unwrap())),
            operation: i16::from_le_bytes(raw[base + 2..base + 4].try_into().unwrap()),
            flags: flags as i16,
        };
    }
    Ok((operations, count))
}

enum SysVSemaphoreEvaluation {
    Ready([i32; MAX_SYSV_SEMS_PER_SET]),
    Blocked {
        semnum: usize,
        zero: bool,
        nowait: bool,
    },
}

fn evaluate_sysv_semaphore_ops(
    set: &SysVSemaphoreSet,
    operations: &[SysVSemaphoreOperation],
) -> Result<SysVSemaphoreEvaluation, CompatErrno> {
    let mut values = set.values;
    for operation in operations {
        if operation.number >= set.nsems {
            return Err(CompatErrno::Invalid);
        }
        let nowait = operation.flags as u16 & SYSV_IPC_NOWAIT as u16 != 0;
        if operation.operation == 0 {
            if values[operation.number] != 0 {
                return Ok(SysVSemaphoreEvaluation::Blocked {
                    semnum: operation.number,
                    zero: true,
                    nowait,
                });
            }
        } else if operation.operation < 0 {
            let amount = -i32::from(operation.operation);
            if values[operation.number] < amount {
                return Ok(SysVSemaphoreEvaluation::Blocked {
                    semnum: operation.number,
                    zero: false,
                    nowait,
                });
            }
            values[operation.number] -= amount;
        } else {
            let amount = i32::from(operation.operation);
            if values[operation.number].saturating_add(amount) > SYSV_SEMVMX {
                return Err(CompatErrno::TryAgain);
            }
            values[operation.number] += amount;
        }
    }
    Ok(SysVSemaphoreEvaluation::Ready(values))
}

fn remove_sysv_semaphore_waiter(
    state: &mut CompatState,
    process: ObjId,
    task: crate::task::TaskId,
    semid: i32,
) {
    let Some(slot) = state.sysv_semaphore_waiters.iter().position(|waiter| {
        waiter.is_some_and(|waiter| {
            waiter.process == process && waiter.task == task && waiter.semid == semid
        })
    }) else {
        return;
    };
    let Some(waiter) = state.sysv_semaphore_waiters[slot].take() else {
        return;
    };
    if let Some(set) = state
        .sysv_semaphore_sets
        .iter_mut()
        .find(|set| set.id == semid)
    {
        let counts = if waiter.zero {
            &mut set.zero_waiters
        } else {
            &mut set.positive_waiters
        };
        if let Some(count) = counts.get_mut(waiter.semnum) {
            *count = count.saturating_sub(1);
        }
    }
}

fn remove_all_sysv_semaphore_waiters(
    state: &mut CompatState,
    process: ObjId,
    task: crate::task::TaskId,
) {
    loop {
        let Some(semid) = state
            .sysv_semaphore_waiters
            .iter()
            .flatten()
            .find(|waiter| waiter.process == process && waiter.task == task)
            .map(|waiter| waiter.semid)
        else {
            break;
        };
        remove_sysv_semaphore_waiter(state, process, task, semid);
    }
}

fn register_sysv_semaphore_waiter(
    state: &mut CompatState,
    process: ObjId,
    task: crate::task::TaskId,
    semid: i32,
    semnum: usize,
    zero: bool,
) -> bool {
    if state.sysv_semaphore_waiters.iter().flatten().any(|waiter| {
        waiter.process == process
            && waiter.task == task
            && waiter.semid == semid
            && waiter.semnum == semnum
            && waiter.zero == zero
    }) {
        return true;
    }
    remove_sysv_semaphore_waiter(state, process, task, semid);
    let Some(slot) = state
        .sysv_semaphore_waiters
        .iter()
        .position(Option::is_none)
    else {
        return false;
    };
    state.sysv_semaphore_waiters[slot] = Some(SysVSemaphoreWaiter {
        process,
        task,
        semid,
        semnum,
        zero,
    });
    if let Some(set) = state
        .sysv_semaphore_sets
        .iter_mut()
        .find(|set| set.id == semid)
    {
        let counts = if zero {
            &mut set.zero_waiters
        } else {
            &mut set.positive_waiters
        };
        if let Some(count) = counts.get_mut(semnum) {
            *count = count.saturating_add(1);
        }
    }
    true
}

fn update_sysv_semaphore_undo(
    state: &mut CompatState,
    process: ObjId,
    semid: i32,
    semnum: usize,
    operation: i16,
) -> bool {
    if let Some(undo) = state.sysv_semaphore_undos.iter_mut().find(|undo| {
        undo.process == process && undo.semid == semid && undo.semnum == semnum
    }) {
        undo.adjustment = undo.adjustment.saturating_sub(i32::from(operation));
        if undo.adjustment == 0 {
            let process = undo.process;
            let semid = undo.semid;
            let semnum = undo.semnum;
            state.sysv_semaphore_undos.retain(|undo| {
                !(undo.process == process && undo.semid == semid && undo.semnum == semnum)
            });
        }
        return true;
    }
    if state.sysv_semaphore_undos.len() >= MAX_SYSV_SEM_UNDOS {
        return false;
    }
    state
        .sysv_semaphore_undos
        .try_reserve(1)
        .is_ok_and(|()| {
            state.sysv_semaphore_undos.push(SysVSemaphoreUndo {
                process,
                semid,
                semnum,
                adjustment: -i32::from(operation),
            });
            true
        })
}

/// Applies and drops all SEM_UNDO adjustments owned by an exiting process.
fn release_sysv_semaphore_undos(process: ObjId) {
    let mut state = COMPAT.lock();
    let mut remaining = alloc::vec::Vec::new();
    for undo in core::mem::take(&mut state.sysv_semaphore_undos) {
        if undo.process != process {
            remaining.push(undo);
            continue;
        }
        if let Some(set) = state
            .sysv_semaphore_sets
            .iter_mut()
            .find(|set| set.id == undo.semid)
        {
            if let Some(value) = set.values.get_mut(undo.semnum) {
                *value = value.saturating_add(undo.adjustment).clamp(0, SYSV_SEMVMX);
                set.change_time = sysv_time_seconds();
            }
        }
    }
    state.sysv_semaphore_undos = remaining;
    drop(state);
    wake_message_queue_waiters();
}

/// Implements `semget(2)` with bounded per-application semaphore sets.
fn linux_semget(pid: ObjId, args: [u64; 6]) -> Result<u64, CompatErrno> {
    let key = args[0] as u32 as i32;
    let nsems = usize::try_from(args[1]).map_err(|_| CompatErrno::Invalid)?;
    let flags = u32::try_from(args[2]).map_err(|_| CompatErrno::Invalid)?;
    if flags & !(0o777 | SYSV_IPC_CREAT | SYSV_IPC_EXCL | SYSV_IPC_NOWAIT) != 0 {
        return Err(CompatErrno::Invalid);
    }
    let application =
        linux_application_identity(pid).ok_or(CompatErrno::Perm)?;
    let credentials = proc::linux_credentials(pid).ok_or(CompatErrno::NoProcess)?;
    // System V IPC ignores the process umask for the requested mode bits.
    let mode = flags & 0o777;
    let mut state = COMPAT.lock();
    if key != 0 {
        if let Some(set) = state
            .sysv_semaphore_sets
            .iter()
            .find(|set| set.application == application && set.key == key)
        {
            if flags & (SYSV_IPC_CREAT | SYSV_IPC_EXCL)
                == (SYSV_IPC_CREAT | SYSV_IPC_EXCL)
            {
                return Err(CompatErrno::Exists);
            }
            return Ok(set.id as u32 as u64);
        }
    }
    if flags & SYSV_IPC_CREAT == 0 {
        return Err(CompatErrno::NoEntry);
    }
    if !(1..=MAX_SYSV_SEMS_PER_SET).contains(&nsems) {
        return Err(CompatErrno::Invalid);
    }
    if state.sysv_semaphore_sets.len() >= MAX_SYSV_SEM_SETS {
        return Err(CompatErrno::NoSpace);
    }
    state
        .sysv_semaphore_sets
        .try_reserve(1)
        .map_err(|_| CompatErrno::NoMemory)?;
    let id = state.next_sysv_semaphore_id;
    state.next_sysv_semaphore_id = id.checked_add(1).ok_or(CompatErrno::NoSpace)?;
    let now = sysv_time_seconds();
    state.sysv_semaphore_sets.push(SysVSemaphoreSet {
        id,
        key,
        application,
        uid: credentials.euid,
        gid: credentials.egid,
        cuid: credentials.euid,
        cgid: credentials.egid,
        mode: mode as u16,
        values: [0; MAX_SYSV_SEMS_PER_SET],
        nsems,
        operation_time: 0,
        change_time: now,
        last_pid: 0,
        positive_waiters: [0; MAX_SYSV_SEMS_PER_SET],
        zero_waiters: [0; MAX_SYSV_SEMS_PER_SET],
    });
    Ok(id as u32 as u64)
}

/// Implements `semop(2)` and `semtimedop(2)` atomically.
fn linux_semop(pid: ObjId, args: [u64; 6], timed: bool) -> Result<u64, CompatErrno> {
    let deadline = if timed && args[3] != 0 {
        Some(
            sched::now_ns()
                .checked_add(read_linux_timespec(args[3])?)
                .ok_or(CompatErrno::Invalid)?,
        )
    } else {
        None
    };
    let id = args[0] as i32;
    let count = usize::try_from(args[2]).map_err(|_| CompatErrno::Invalid)?;
    let (operations, operation_count) = read_sysv_semaphore_ops(args[1], count)?;
    let operations = &operations[..operation_count];
    let application =
        linux_application_identity(pid).ok_or(CompatErrno::Perm)?;
    let credentials = proc::linux_credentials(pid).ok_or(CompatErrno::NoProcess)?;
    let supplementary_groups =
        proc::linux_supplementary_groups(pid).ok_or(CompatErrno::NoProcess)?;
    let process_pid = proc::linux_pid(pid).ok_or(CompatErrno::NoProcess)? as i32;
    let (task, _) = sched::current();
    let mut waited = false;
    loop {
        let evaluation = {
            let mut state = COMPAT.lock();
            let set_index = sysv_semaphore_set_index(&state, application, id).ok_or(
                if waited {
                    CompatErrno::Removed
                } else {
                    CompatErrno::Invalid
                },
            )?;
            let requires_write = operations.iter().any(|operation| operation.operation != 0);
            if !sysv_semaphore_access(
                &state.sysv_semaphore_sets[set_index],
                credentials,
                &supplementary_groups,
                requires_write,
            ) {
                remove_sysv_semaphore_waiter(&mut state, pid, task, id);
                return Err(CompatErrno::Access);
            }
            match evaluate_sysv_semaphore_ops(&state.sysv_semaphore_sets[set_index], operations) {
                Ok(SysVSemaphoreEvaluation::Ready(values)) => {
                    let mut new_undos = 0usize;
                    for (index, operation) in operations.iter().enumerate() {
                        if operation.flags as u16 & SYSV_SEM_UNDO == 0 {
                            continue;
                        }
                        let existing = state.sysv_semaphore_undos.iter().any(|undo| {
                            undo.process == pid
                                && undo.semid == id
                                && undo.semnum == operation.number
                        });
                        let repeated = operations[..index].iter().any(|previous| {
                            previous.flags as u16 & SYSV_SEM_UNDO != 0
                                && previous.number == operation.number
                        });
                        if !existing && !repeated {
                            new_undos += 1;
                        }
                    }
                    if state.sysv_semaphore_undos.len().saturating_add(new_undos)
                        > MAX_SYSV_SEM_UNDOS
                        || state
                            .sysv_semaphore_undos
                            .try_reserve(new_undos)
                            .is_err()
                    {
                        remove_sysv_semaphore_waiter(&mut state, pid, task, id);
                        return Err(CompatErrno::NoSpace);
                    }
                    {
                        let set = &mut state.sysv_semaphore_sets[set_index];
                        set.values = values;
                        set.operation_time = sysv_time_seconds();
                        set.last_pid = process_pid;
                    }
                    for operation in operations {
                        if operation.flags as u16 & SYSV_SEM_UNDO != 0
                            && !update_sysv_semaphore_undo(
                                &mut state,
                                pid,
                                id,
                                operation.number,
                                operation.operation,
                            )
                        {
                            return Err(CompatErrno::NoSpace);
                        }
                    }
                    remove_sysv_semaphore_waiter(&mut state, pid, task, id);
                    Ok(None)
                }
                Ok(SysVSemaphoreEvaluation::Blocked {
                    semnum,
                    zero,
                    nowait,
                }) => {
                    if nowait {
                        remove_sysv_semaphore_waiter(&mut state, pid, task, id);
                        Err(CompatErrno::TryAgain)
                    } else {
                        Ok(Some((semnum, zero)))
                    }
                }
                Err(error) => {
                    remove_sysv_semaphore_waiter(&mut state, pid, task, id);
                    Err(error)
                }
            }
        }?;
        let Some((semnum, zero)) = evaluation else {
            wake_message_queue_waiters();
            return Ok(0);
        };
        {
            let mut state = COMPAT.lock();
            if !register_sysv_semaphore_waiter(&mut state, pid, task, id, semnum, zero) {
                return Err(CompatErrno::NoSpace);
            }
        }
        if proc::current_exiting() || current_signal_pending(pid) {
            let mut state = COMPAT.lock();
            remove_sysv_semaphore_waiter(&mut state, pid, task, id);
            return Err(CompatErrno::Interrupted);
        }
        if deadline.is_some_and(|deadline| sched::now_ns() >= deadline) {
            let mut state = COMPAT.lock();
            remove_sysv_semaphore_waiter(&mut state, pid, task, id);
            return Err(CompatErrno::TryAgain);
        }
        waited = true;
        if let Some(deadline) = deadline {
            if sched::sleep_until_ns(deadline).is_err() {
                sched::pause();
            }
        } else {
            sched::pause();
        }
    }
}

/// Implements `semctl(2)` for values, counts, metadata and removal.
fn linux_semctl(pid: ObjId, args: [u64; 6]) -> Result<u64, CompatErrno> {
    const IPC_RMID: u32 = 0;
    const IPC_SET: u32 = 1;
    const IPC_STAT: u32 = 2;
    const IPC_INFO: u32 = 3;
    const GETPID: u32 = 11;
    const GETVAL: u32 = 12;
    const GETALL: u32 = 13;
    const GETNCNT: u32 = 14;
    const GETZCNT: u32 = 15;
    const SETVAL: u32 = 16;
    const SETALL: u32 = 17;
    const SEM_STAT: u32 = 18;
    const SEM_INFO: u32 = 19;
    const SEM_STAT_ANY: u32 = 20;
    let command = u32::try_from(args[2]).map_err(|_| CompatErrno::Invalid)?;
    if command == IPC_INFO || command == SEM_INFO {
        return write_sysv_seminfo(args[3]).map(|()| 0);
    }
    let application =
        linux_application_identity(pid).ok_or(CompatErrno::Perm)?;
    let credentials = proc::linux_credentials(pid).ok_or(CompatErrno::NoProcess)?;
    let supplementary_groups =
        proc::linux_supplementary_groups(pid).ok_or(CompatErrno::NoProcess)?;
    let update = if command == IPC_SET {
        let mut update = [0u8; SYSV_SEM_DS_BYTES];
        copy_from_user(&mut update, args[3], SYSV_SEM_DS_BYTES)
            .map_err(|_| CompatErrno::Fault)?;
        Some(update)
    } else {
        None
    };
    let id = args[0] as i32;
    let mut state = COMPAT.lock();
    let selected_index = match command {
        SEM_STAT | SEM_STAT_ANY => {
            let index = usize::try_from(args[0]).map_err(|_| CompatErrno::Invalid)?;
            state
                .sysv_semaphore_sets
                .iter()
                .enumerate()
                .filter(|(_, set)| set.application == application)
                .nth(index)
                .map(|(index, _)| index)
                .ok_or(CompatErrno::Invalid)?
        }
        _ => sysv_semaphore_set_index(&state, application, id).ok_or(CompatErrno::Invalid)?,
    };
    let set = &mut state.sysv_semaphore_sets[selected_index];
    let semnum = usize::try_from(args[1]).map_err(|_| CompatErrno::Invalid);
    let require_sem = |set: &SysVSemaphoreSet| {
        let semnum = semnum?;
        if semnum >= set.nsems {
            return Err(CompatErrno::Invalid);
        }
        Ok(semnum)
    };
    if matches!(command, GETPID | GETVAL | GETALL | GETNCNT | GETZCNT)
        && !sysv_semaphore_access(
            set,
            credentials,
            &supplementary_groups,
            false,
        )
    {
        return Err(CompatErrno::Access);
    }
    match command {
        IPC_RMID => {
            if credentials.euid != 0 && credentials.euid != set.uid {
                return Err(CompatErrno::Perm);
            }
            let removed_id = set.id;
            let removed = state.sysv_semaphore_sets.remove(selected_index);
            state
                .sysv_semaphore_waiters
                .iter_mut()
                .filter(|waiter| waiter.is_some_and(|waiter| waiter.semid == removed_id))
                .for_each(|waiter| *waiter = None);
            state
                .sysv_semaphore_undos
                .retain(|undo| undo.semid != removed_id);
            drop(state);
            let _ = removed;
            wake_message_queue_waiters();
            Ok(0)
        }
        IPC_SET => {
            if credentials.euid != 0 && credentials.euid != set.uid {
                return Err(CompatErrno::Perm);
            }
            let update = update.expect("IPC_SET input");
            let mode = u32::from_le_bytes(update[20..24].try_into().unwrap()) as u16;
            if mode & !0o777 != 0 {
                return Err(CompatErrno::Invalid);
            }
            set.uid = u32::from_le_bytes(update[4..8].try_into().unwrap());
            set.gid = u32::from_le_bytes(update[8..12].try_into().unwrap());
            set.mode = mode;
            set.change_time = sysv_time_seconds();
            Ok(0)
        }
        IPC_STAT | SEM_STAT | SEM_STAT_ANY => {
            if command != SEM_STAT_ANY
                && !sysv_semaphore_access(
                    set,
                    credentials,
                    &supplementary_groups,
                    false,
                )
            {
                return Err(CompatErrno::Access);
            }
            let output = sysv_sem_ds_bytes(set);
            let returned_id = set.id;
            drop(state);
            copy_to_user(args[3], &output, output.len()).map_err(|_| CompatErrno::Fault)?;
            if command == SEM_STAT {
                Ok(returned_id as u32 as u64)
            } else {
                Ok(0)
            }
        }
        GETPID => {
            require_sem(set)?;
            Ok(set.last_pid as u32 as u64)
        }
        GETVAL => {
            let semnum = require_sem(set)?;
            Ok(set.values[semnum] as u64)
        }
        GETNCNT => {
            let semnum = require_sem(set)?;
            Ok(u64::from(set.positive_waiters[semnum]))
        }
        GETZCNT => {
            let semnum = require_sem(set)?;
            Ok(u64::from(set.zero_waiters[semnum]))
        }
        GETALL => {
            let output: alloc::vec::Vec<u8> = set.values[..set.nsems]
                .iter()
                .flat_map(|value| (*value as u16).to_le_bytes())
                .collect();
            drop(state);
            copy_to_user(args[3], &output, output.len()).map_err(|_| CompatErrno::Fault)?;
            Ok(0)
        }
        SETVAL => {
            if !sysv_semaphore_access(
                set,
                credentials,
                &supplementary_groups,
                true,
            ) {
                return Err(CompatErrno::Access);
            }
            let semnum = require_sem(set)?;
            let value = u32::try_from(args[3]).map_err(|_| CompatErrno::Invalid)?;
            if value > SYSV_SEMVMX as u32 {
                return Err(CompatErrno::Invalid);
            }
            set.values[semnum] = value as i32;
            set.change_time = sysv_time_seconds();
            state
                .sysv_semaphore_undos
                .retain(|undo| !(undo.semid == id && undo.semnum == semnum));
            drop(state);
            wake_message_queue_waiters();
            Ok(0)
        }
        SETALL => {
            if !sysv_semaphore_access(
                set,
                credentials,
                &supplementary_groups,
                true,
            ) {
                return Err(CompatErrno::Access);
            }
            let nsems = set.nsems;
            drop(state);
            let mut values = [0u8; MAX_SYSV_SEMS_PER_SET * 2];
            copy_from_user(&mut values, args[3], nsems * 2).map_err(|_| CompatErrno::Fault)?;
            let mut parsed = [0i32; MAX_SYSV_SEMS_PER_SET];
            for (index, value) in parsed[..nsems].iter_mut().enumerate() {
                let raw = u16::from_le_bytes(values[index * 2..index * 2 + 2].try_into().unwrap());
                if i32::from(raw) > SYSV_SEMVMX {
                    return Err(CompatErrno::Invalid);
                }
                *value = i32::from(raw);
            }
            let mut state = COMPAT.lock();
            let set_index = sysv_semaphore_set_index(&state, application, id)
                .ok_or(CompatErrno::Removed)?;
            let set = &mut state.sysv_semaphore_sets[set_index];
            set.values[..nsems].copy_from_slice(&parsed[..nsems]);
            set.change_time = sysv_time_seconds();
            state.sysv_semaphore_undos.retain(|undo| undo.semid != id);
            drop(state);
            wake_message_queue_waiters();
            Ok(0)
        }
        _ => Err(CompatErrno::Invalid),
    }
}

const SYSV_SHM_DS_BYTES: usize = 120;

fn sysv_shared_segment_index(
    state: &CompatState,
    application: kernel_core::security::ApplicationIdentity,
    id: i32,
) -> Option<usize> {
    state.sysv_shared_segments.iter().position(|segment| {
        !segment.deleted && segment.application == application && segment.id == id
    })
}

fn sysv_shared_access(
    segment: &SysVSharedMemory,
    credentials: proc::LinuxCredentials,
    groups: &[u32],
    write: bool,
) -> bool {
    if credentials.euid == 0 {
        return true;
    }
    let shift = if credentials.euid == segment.uid {
        6
    } else if credentials.egid == segment.gid || groups.contains(&segment.gid) {
        3
    } else {
        0
    };
    let required = if write { 0o2 } else { 0o4 };
    segment.mode >> shift & required == required
}

fn sysv_shm_ds_bytes(segment: &SysVSharedMemory) -> [u8; SYSV_SHM_DS_BYTES] {
    let mut output = [0u8; SYSV_SHM_DS_BYTES];
    output[0..4].copy_from_slice(&(segment.key as u32).to_le_bytes());
    output[4..8].copy_from_slice(&segment.uid.to_le_bytes());
    output[8..12].copy_from_slice(&segment.gid.to_le_bytes());
    output[12..16].copy_from_slice(&segment.cuid.to_le_bytes());
    output[16..20].copy_from_slice(&segment.cgid.to_le_bytes());
    output[20..24].copy_from_slice(&u32::from(segment.mode).to_le_bytes());
    output[24..26].copy_from_slice(&(segment.id as u16).to_le_bytes());
    output[48..56].copy_from_slice(&segment.size.to_le_bytes());
    output[56..64].copy_from_slice(&segment.attach_time.to_le_bytes());
    output[64..72].copy_from_slice(&segment.detach_time.to_le_bytes());
    output[72..80].copy_from_slice(&segment.change_time.to_le_bytes());
    output[80..84].copy_from_slice(&segment.creator_pid.to_le_bytes());
    output[84..88].copy_from_slice(&segment.last_pid.to_le_bytes());
    output[88..96].copy_from_slice(&(segment.attachments.len() as u64).to_le_bytes());
    output
}

fn sysv_shm_info_bytes(state: &CompatState) -> [u8; 48] {
    let mut info = [0u8; 48];
    let active = state
        .sysv_shared_segments
        .iter()
        .filter(|segment| !segment.deleted)
        .count();
    let bytes: u64 = state
        .sysv_shared_segments
        .iter()
        .filter(|segment| !segment.deleted)
        .map(|segment| segment.size)
        .sum();
    info[0..4].copy_from_slice(&(active as i32).to_le_bytes());
    info[8..16].copy_from_slice(&bytes.to_le_bytes());
    info[16..24].copy_from_slice(&bytes.to_le_bytes());
    info
}

/// Implements `shmget(2)` with application-scoped bounded segments.
fn linux_shmget(pid: ObjId, args: [u64; 6]) -> Result<u64, CompatErrno> {
    let key = args[0] as u32 as i32;
    let size = args[1];
    let flags = u32::try_from(args[2]).map_err(|_| CompatErrno::Invalid)?;
    if flags & !(0o777 | SYSV_IPC_CREAT | SYSV_IPC_EXCL) != 0 {
        return Err(CompatErrno::NotSupported);
    }
    let application =
        linux_application_identity(pid).ok_or(CompatErrno::Perm)?;
    let credentials = proc::linux_credentials(pid).ok_or(CompatErrno::NoProcess)?;
    // System V IPC ignores the process umask for the requested mode bits.
    let mode = flags & 0o777;
    if key != 0 {
        let existing = {
            let state = COMPAT.lock();
            state
                .sysv_shared_segments
                .iter()
                .find(|segment| {
                    !segment.deleted
                        && segment.application == application
                        && segment.key == key
                })
                .map(|segment| (segment.id, segment.size))
        };
        if let Some((id, existing_size)) = existing {
            if flags & (SYSV_IPC_CREAT | SYSV_IPC_EXCL)
                == (SYSV_IPC_CREAT | SYSV_IPC_EXCL)
            {
                return Err(CompatErrno::Exists);
            }
            if size > existing_size && size != 0 {
                return Err(CompatErrno::Invalid);
            }
            return Ok(id as u32 as u64);
        }
    }
    if flags & SYSV_IPC_CREAT == 0 {
        return Err(CompatErrno::NoEntry);
    }
    if size == 0 {
        return Err(CompatErrno::Invalid);
    }
    let object =
        proc::linux_create_shared_memory(pid, size).ok_or(CompatErrno::NoMemory)?;
    let current_pid = proc::linux_pid(pid).ok_or(CompatErrno::NoProcess)? as i32;
    let mut state = COMPAT.lock();
    if key != 0 {
        if let Some(segment) = state.sysv_shared_segments.iter().find(|segment| {
            !segment.deleted && segment.application == application && segment.key == key
        }) {
            if flags & (SYSV_IPC_CREAT | SYSV_IPC_EXCL)
                == (SYSV_IPC_CREAT | SYSV_IPC_EXCL)
            {
                return Err(CompatErrno::Exists);
            }
            if size > segment.size && size != 0 {
                return Err(CompatErrno::Invalid);
            }
            return Ok(segment.id as u32 as u64);
        }
    }
    if state
        .sysv_shared_segments
        .iter()
        .filter(|segment| !segment.deleted)
        .count()
        >= MAX_SYSV_SHARED_SEGMENTS
    {
        return Err(CompatErrno::NoSpace);
    }
    state
        .sysv_shared_segments
        .try_reserve(1)
        .map_err(|_| CompatErrno::NoMemory)?;
    let id = state.next_sysv_shared_id;
    state.next_sysv_shared_id = id.checked_add(1).ok_or(CompatErrno::NoSpace)?;
    let now = sysv_time_seconds();
    state.sysv_shared_segments.push(SysVSharedMemory {
        id,
        key,
        application,
        uid: credentials.euid,
        gid: credentials.egid,
        cuid: credentials.euid,
        cgid: credentials.egid,
        mode: mode as u16,
        size,
        object,
        creator_pid: current_pid,
        last_pid: 0,
        attach_time: 0,
        detach_time: 0,
        change_time: now,
        deleted: false,
        attachments: alloc::vec::Vec::new(),
    });
    Ok(id as u32 as u64)
}

/// Implements `shmat(2)` and records the process attachment lifecycle.
fn linux_shmat(pid: ObjId, args: [u64; 6]) -> Result<u64, CompatErrno> {
    const PAGE: u64 = kernel_core::frame::FRAME_SIZE;
    const SHM_RDONLY: u64 = 0o10000;
    const SHM_RND: u64 = 0o20000;
    const SHM_REMAP: u64 = 0o40000;
    const SHM_EXEC: u64 = 0o100000;
    let id = args[0] as i32;
    let flags = args[2];
    if flags & !(SHM_RDONLY | SHM_RND | SHM_REMAP | SHM_EXEC) != 0
        || flags & (SHM_REMAP | SHM_EXEC) != 0
        || args[1] != 0 && flags & SHM_RND == 0 && args[1] % PAGE != 0
    {
        return Err(if flags & SHM_REMAP != 0 {
            CompatErrno::Perm
        } else {
            CompatErrno::NotSupported
        });
    }
    let application =
        linux_application_identity(pid).ok_or(CompatErrno::Perm)?;
    let credentials = proc::linux_credentials(pid).ok_or(CompatErrno::NoProcess)?;
    let supplementary_groups =
        proc::linux_supplementary_groups(pid).ok_or(CompatErrno::NoProcess)?;
    let segment = {
        let state = COMPAT.lock();
        let index =
            sysv_shared_segment_index(&state, application, id).ok_or(CompatErrno::Invalid)?;
        let segment = &state.sysv_shared_segments[index];
        if !sysv_shared_access(
            segment,
            credentials,
            &supplementary_groups,
            flags & SHM_RDONLY == 0,
        ) {
            return Err(CompatErrno::Access);
        }
        (
            segment.object.clone(),
            segment.size,
            segment.attachments.len(),
        )
    };
    if segment.2 >= MAX_SYSV_SHARED_ATTACHMENTS {
        return Err(CompatErrno::NoSpace);
    }
    let length = segment
        .1
        .checked_add(PAGE - 1)
        .ok_or(CompatErrno::Invalid)?
        & !(PAGE - 1);
    let requested = args[1];
    let mut candidate = if requested == 0 {
        proc::linux_mmap_cursor(pid).ok_or(CompatErrno::NoSys)?
    } else if flags & SHM_RND != 0 {
        requested & !(PAGE - 1)
    } else {
        requested
    };
    if candidate < crate::arch::USER_WINDOW.0
        || candidate
            .checked_add(length)
            .is_none_or(|end| end > crate::arch::USER_WINDOW.1)
    {
        return Err(CompatErrno::NoMemory);
    }
    let mut mapped = None;
    while candidate
        .checked_add(length)
        .is_some_and(|end| end <= crate::arch::USER_WINDOW.1)
    {
        if proc::linux_shared_memory_map(
            pid,
            &segment.0,
            candidate,
            length,
            flags & SHM_RDONLY == 0,
        )
        .is_ok()
        {
            mapped = Some(candidate);
            break;
        }
        candidate = candidate
            .checked_add(length)
            .ok_or(CompatErrno::NoMemory)?;
    }
    let address = mapped.ok_or(CompatErrno::NoMemory)?;
    let _ = proc::set_linux_mmap_cursor(
        pid,
        address
            .checked_add(length)
            .ok_or(CompatErrno::NoMemory)?,
    );
    let current_pid = proc::linux_pid(pid).ok_or(CompatErrno::NoProcess)? as i32;
    let mut state = COMPAT.lock();
    let Some(index) = sysv_shared_segment_index(&state, application, id) else {
        drop(state);
        let _ = linux_munmap(pid, [address, length, 0, 0, 0, 0]);
        return Err(CompatErrno::Removed);
    };
    let segment = &mut state.sysv_shared_segments[index];
    if segment.attachments.len() >= MAX_SYSV_SHARED_ATTACHMENTS
        || segment
            .attachments
            .try_reserve(1)
            .map_err(|_| CompatErrno::NoSpace)
            .is_err()
    {
        drop(state);
        let _ = linux_munmap(pid, [address, length, 0, 0, 0, 0]);
        return Err(CompatErrno::NoSpace);
    }
    segment.attachments.push(SysVSharedAttachment {
        process: pid,
        address,
        length,
        writable: flags & SHM_RDONLY == 0,
    });
    segment.attach_time = sysv_time_seconds();
    segment.last_pid = current_pid;
    Ok(address)
}

/// Implements `shmdt(2)` after validating this process's exact attachment.
fn linux_shmdt(pid: ObjId, args: [u64; 6]) -> Result<u64, CompatErrno> {
    const PAGE: u64 = kernel_core::frame::FRAME_SIZE;
    let address = args[0];
    if address % PAGE != 0 {
        return Err(CompatErrno::Invalid);
    }
    let application =
        linux_application_identity(pid).ok_or(CompatErrno::Perm)?;
    let (id, length) = {
        let state = COMPAT.lock();
        state
            .sysv_shared_segments
            .iter()
            .find(|segment| segment.application == application)
            .and_then(|segment| {
                segment
                    .attachments
                    .iter()
                    .find(|attachment| attachment.process == pid && attachment.address == address)
                    .map(|attachment| (segment.id, attachment.length))
            })
            .ok_or(CompatErrno::Invalid)?
    };
    linux_munmap(pid, [address, length, 0, 0, 0, 0])?;
    let current_pid = proc::linux_pid(pid).ok_or(CompatErrno::NoProcess)? as i32;
    let mut state = COMPAT.lock();
    let index = state
        .sysv_shared_segments
        .iter()
        .position(|segment| {
            segment.id == id
                && segment.application == application
                && segment.attachments.iter().any(|attachment| {
                    attachment.process == pid && attachment.address == address
                })
        })
        .ok_or(CompatErrno::Removed)?;
    let segment = &mut state.sysv_shared_segments[index];
    segment
        .attachments
        .retain(|attachment| !(attachment.process == pid && attachment.address == address));
    segment.detach_time = sysv_time_seconds();
    segment.last_pid = current_pid;
    let remove = segment.deleted && segment.attachments.is_empty();
    let removed = remove.then(|| state.sysv_shared_segments.remove(index));
    drop(state);
    drop(removed);
    Ok(0)
}

/// Drops process attachment records after process address-space teardown.
fn release_sysv_shared_process(process: ObjId) {
    let mut state = COMPAT.lock();
    // Removing the final segment drops its page-backed object. Page/account
    // teardown takes the lower-ranked memory-pin lock, so defer every such
    // destructor until the COMPAT lock has been released.
    let mut removed = [const { None }; MAX_SYSV_SHARED_SEGMENTS];
    let mut removed_len = 0usize;
    let now = sysv_time_seconds();
    let mut index = 0usize;
    while index < state.sysv_shared_segments.len() {
        let segment = &mut state.sysv_shared_segments[index];
        let before = segment.attachments.len();
        segment
            .attachments
            .retain(|attachment| attachment.process != process);
        if segment.attachments.len() != before {
            segment.detach_time = now;
        }
        if segment.deleted && segment.attachments.is_empty() {
            removed[removed_len] = Some(state.sysv_shared_segments.swap_remove(index));
            removed_len += 1;
        } else {
            index += 1;
        }
    }
    drop(state);
    for segment in removed.into_iter().take(removed_len).flatten() {
        drop(segment);
    }
}

/// Copies one forked process's pre-existing System V shared attachments.
pub(crate) fn inherit_sysv_shared_process(parent: ObjId, child: ObjId) -> bool {
    let inherited = {
        let state = COMPAT.lock();
        let mut inherited = alloc::vec::Vec::new();
        for segment in &state.sysv_shared_segments {
            for attachment in &segment.attachments {
                if attachment.process == parent
                    && inherited
                        .try_reserve(1)
                        .map_err(|_| ())
                        .and_then(|_| {
                            inherited.push((
                                segment.id,
                                segment.application,
                                SysVSharedAttachment {
                                    process: child,
                                    ..*attachment
                                },
                            ));
                            Ok(())
                        })
                        .is_err()
                {
                    return false;
                }
            }
        }
        inherited
    };
    let mut state = COMPAT.lock();
    for (id, application, attachment) in &inherited {
        let Some(segment) = state
            .sysv_shared_segments
            .iter_mut()
            .find(|segment| segment.id == *id && segment.application == *application)
        else {
            return false;
        };
        if segment.attachments.try_reserve(1).is_err() {
            return false;
        }
        segment.attachments.push(*attachment);
    }
    true
}

/// Implements `shmctl(2)` for metadata, locking and removal.
fn linux_shmctl(pid: ObjId, args: [u64; 6]) -> Result<u64, CompatErrno> {
    const IPC_RMID: u32 = 0;
    const IPC_SET: u32 = 1;
    const IPC_STAT: u32 = 2;
    const IPC_INFO: u32 = 3;
    const SHM_LOCK: u32 = 3;
    const SHM_UNLOCK: u32 = 4;
    const SHM_STAT: u32 = 11;
    const SHM_INFO: u32 = 14;
    const SHM_STAT_ANY: u32 = 15;
    let command = u32::try_from(args[1]).map_err(|_| CompatErrno::Invalid)?;
    let application =
        linux_application_identity(pid).ok_or(CompatErrno::Perm)?;
    let credentials = proc::linux_credentials(pid).ok_or(CompatErrno::NoProcess)?;
    let supplementary_groups =
        proc::linux_supplementary_groups(pid).ok_or(CompatErrno::NoProcess)?;
    if command == SHM_INFO || command == IPC_INFO && args[0] == 0 {
        let info = {
            let state = COMPAT.lock();
            sysv_shm_info_bytes(&state)
        };
        copy_to_user(args[2], &info, info.len()).map_err(|_| CompatErrno::Fault)?;
        return Ok(0);
    }
    if command == SHM_LOCK || command == SHM_UNLOCK {
        return Err(CompatErrno::Perm);
    }
    let update = if command == IPC_SET {
        let mut update = [0u8; SYSV_SHM_DS_BYTES];
        copy_from_user(&mut update, args[2], SYSV_SHM_DS_BYTES)
            .map_err(|_| CompatErrno::Fault)?;
        Some(update)
    } else {
        None
    };
    let mut state = COMPAT.lock();
    let selected = match command {
        SHM_STAT | SHM_STAT_ANY => {
            let index = usize::try_from(args[0]).map_err(|_| CompatErrno::Invalid)?;
            state
                .sysv_shared_segments
                .iter()
                .enumerate()
                .filter(|(_, segment)| !segment.deleted && segment.application == application)
                .nth(index)
                .map(|(index, _)| index)
                .ok_or(CompatErrno::Invalid)?
        }
        _ => sysv_shared_segment_index(&state, application, args[0] as i32)
            .ok_or(CompatErrno::Invalid)?,
    };
    let segment = &mut state.sysv_shared_segments[selected];
    match command {
        IPC_RMID => {
            if credentials.euid != 0 && credentials.euid != segment.uid {
                return Err(CompatErrno::Perm);
            }
            segment.deleted = true;
            segment.change_time = sysv_time_seconds();
            let remove = segment.attachments.is_empty();
            let removed = if remove {
                Some(state.sysv_shared_segments.remove(selected))
            } else {
                None
            };
            drop(state);
            drop(removed);
            Ok(0)
        }
        IPC_SET => {
            if credentials.euid != 0 && credentials.euid != segment.uid {
                return Err(CompatErrno::Perm);
            }
            let update = update.expect("IPC_SET input");
            let mode = u32::from_le_bytes(update[20..24].try_into().unwrap()) as u16;
            if mode & !0o777 != 0 {
                return Err(CompatErrno::Invalid);
            }
            segment.uid = u32::from_le_bytes(update[4..8].try_into().unwrap());
            segment.gid = u32::from_le_bytes(update[8..12].try_into().unwrap());
            segment.mode = mode;
            segment.change_time = sysv_time_seconds();
            Ok(0)
        }
        IPC_STAT | SHM_STAT | SHM_STAT_ANY => {
            if command != SHM_STAT_ANY
                && !sysv_shared_access(
                    segment,
                    credentials,
                    &supplementary_groups,
                    false,
                )
            {
                return Err(CompatErrno::Access);
            }
            let output = sysv_shm_ds_bytes(segment);
            let returned_id = segment.id;
            drop(state);
            copy_to_user(args[2], &output, output.len()).map_err(|_| CompatErrno::Fault)?;
            if command == SHM_STAT {
                Ok(returned_id as u32 as u64)
            } else {
                Ok(0)
            }
        }
        _ => Err(CompatErrno::Invalid),
    }
}

const MNT_ID_REQ_MIN_BYTES: usize = 24;
const STATMOUNT_FIXED_BYTES: usize = 512;

fn read_mnt_id_req(address: u64) -> Result<(u64, u64, u64), CompatErrno> {
    let mut size_bytes = [0u8; 4];
    copy_from_user(&mut size_bytes, address, 4).map_err(|_| CompatErrno::Fault)?;
    let size = u32::from_le_bytes(size_bytes) as usize;
    if size < MNT_ID_REQ_MIN_BYTES {
        return Err(CompatErrno::Invalid);
    }
    if size > 4096 {
        return Err(CompatErrno::ArgumentTooLong);
    }
    let mut request = [0u8; 32];
    copy_from_user(&mut request, address, size.min(32)).map_err(|_| CompatErrno::Fault)?;
    Ok((
        u64::from_le_bytes(request[8..16].try_into().unwrap()),
        u64::from_le_bytes(request[16..24].try_into().unwrap()),
        if size >= MNT_ID_REQ_MIN_BYTES + 8 {
            u64::from_le_bytes(request[24..32].try_into().unwrap())
        } else {
            0
        },
    ))
}

/// Implements bounded `listmount(2)` over the single synthetic root mount.
fn linux_listmount(_pid: ObjId, args: [u64; 6]) -> Result<u64, CompatErrno> {
    const LISTMOUNT_REVERSE: u64 = 1;
    const ROOT_MOUNT_ID: u64 = 1;
    let flags = args[3];
    if flags & !LISTMOUNT_REVERSE != 0 {
        return Err(CompatErrno::Invalid);
    }
    let (parent, start, namespace) = read_mnt_id_req(args[0])?;
    if parent != u64::MAX && parent != ROOT_MOUNT_ID {
        return Err(CompatErrno::NoEntry);
    }
    if namespace != 0 && namespace != ROOT_MOUNT_ID {
        return Err(CompatErrno::NoEntry);
    }
    if parent == ROOT_MOUNT_ID {
        return Ok(0);
    }
    let count = usize::try_from(args[2]).map_err(|_| CompatErrno::Invalid)?;
    if count == 0 || start >= ROOT_MOUNT_ID {
        return Ok(0);
    }
    copy_to_user(args[1], &ROOT_MOUNT_ID.to_le_bytes(), 8)
        .map_err(|_| CompatErrno::Fault)?;
    Ok(1)
}

fn linux_listns(args: [u64; 6]) -> Result<u64, CompatErrno> {
    if args[3] != 0 {
        return Err(CompatErrno::Invalid);
    }
    let mut size = [0u8; 4];
    copy_from_user(&mut size, args[0], 4).map_err(|_| CompatErrno::Fault)?;
    let size = u32::from_le_bytes(size) as usize;
    if size < 32 {
        return Err(CompatErrno::Invalid);
    }
    if size > 4096 {
        return Err(CompatErrno::ArgumentTooLong);
    }
    let mut request = [0u8; 32];
    copy_from_user(&mut request, args[0], size.min(32))
        .map_err(|_| CompatErrno::Fault)?;
    let cursor = u64::from_le_bytes(request[8..16].try_into().unwrap());
    let type_mask = u32::from_le_bytes(request[16..20].try_into().unwrap());
    let user_ns = u64::from_le_bytes(request[24..32].try_into().unwrap());
    if user_ns != 0 && user_ns != 3 && user_ns != u64::MAX {
        return Err(CompatErrno::NoEntry);
    }
    const NAMESPACES: [(u64, u32); 8] = [
        (1, 1 << 27),
        (2, 1 << 26),
        (3, 1 << 28),
        (4, 1 << 29),
        (5, 1 << 25),
        (6, 1 << 7),
        (7, 1 << 30),
        (8, 1 << 17),
    ];
    let capacity = usize::try_from(args[2]).map_err(|_| CompatErrno::Invalid)?;
    let mut output = [0u8; 8 * 8];
    let mut count = 0usize;
    for (id, namespace_type) in NAMESPACES {
        if id <= cursor || type_mask != 0 && type_mask & namespace_type == 0 || count >= capacity {
            continue;
        }
        output[count * 8..count * 8 + 8].copy_from_slice(&id.to_le_bytes());
        count += 1;
    }
    if count != 0 {
        copy_to_user(args[1], &output[..count * 8], count * 8)
            .map_err(|_| CompatErrno::Fault)?;
    }
    Ok(count as u64)
}

fn append_statmount_string(
    fixed: &mut [u8; STATMOUNT_FIXED_BYTES],
    strings: &mut alloc::vec::Vec<u8>,
    field_offset: usize,
    value: &[u8],
) -> Result<(), CompatErrno> {
    let offset = u32::try_from(strings.len()).map_err(|_| CompatErrno::Overflow)?;
    fixed[field_offset..field_offset + 4].copy_from_slice(&offset.to_le_bytes());
    strings.extend_from_slice(value);
    strings.push(0);
    Ok(())
}

/// Implements read-only `statmount(2)` for the namespace's synthetic root.
fn linux_statmount(_pid: ObjId, args: [u64; 6]) -> Result<u64, CompatErrno> {
    const ROOT_MOUNT_ID: u64 = 1;
    const STATMOUNT_SB_BASIC: u64 = 0x1;
    const STATMOUNT_MNT_BASIC: u64 = 0x2;
    const STATMOUNT_MNT_ROOT: u64 = 0x8;
    const STATMOUNT_MNT_POINT: u64 = 0x10;
    const STATMOUNT_FS_TYPE: u64 = 0x20;
    const STATMOUNT_MNT_NS_ID: u64 = 0x40;
    const STATMOUNT_MNT_OPTS: u64 = 0x80;
    const SUPPORTED: u64 = STATMOUNT_SB_BASIC
        | STATMOUNT_MNT_BASIC
        | STATMOUNT_MNT_ROOT
        | STATMOUNT_MNT_POINT
        | STATMOUNT_FS_TYPE
        | STATMOUNT_MNT_NS_ID
        | STATMOUNT_MNT_OPTS;
    if args[3] != 0 {
        return Err(CompatErrno::Invalid);
    }
    let (mount_id, requested, namespace_id) = read_mnt_id_req(args[0])?;
    if mount_id != ROOT_MOUNT_ID {
        return Err(CompatErrno::NoEntry);
    }
    if namespace_id != 0 && namespace_id != ROOT_MOUNT_ID {
        return Err(CompatErrno::NoEntry);
    }
    let mut fixed = [0u8; STATMOUNT_FIXED_BYTES];
    let mut strings = alloc::vec::Vec::new();
    append_statmount_string(&mut fixed, &mut strings, 4, b"ro")?;
    append_statmount_string(&mut fixed, &mut strings, 36, b"jasperfs")?;
    append_statmount_string(&mut fixed, &mut strings, 104, b"/")?;
    append_statmount_string(&mut fixed, &mut strings, 108, b"/")?;
    let total = STATMOUNT_FIXED_BYTES
        .checked_add(strings.len())
        .ok_or(CompatErrno::Overflow)?;
    let capacity = usize::try_from(args[2]).map_err(|_| CompatErrno::Invalid)?;
    if capacity < total {
        return Err(CompatErrno::Overflow);
    }
    fixed[0..4].copy_from_slice(&(total as u32).to_le_bytes());
    fixed[8..16].copy_from_slice(&(requested & SUPPORTED).to_le_bytes());
    fixed[16..20].copy_from_slice(&0u32.to_le_bytes());
    fixed[20..24].copy_from_slice(&1u32.to_le_bytes());
    fixed[24..32].copy_from_slice(&0x4a41_5350u64.to_le_bytes());
    fixed[32..36].copy_from_slice(&1u32.to_le_bytes());
    fixed[40..48].copy_from_slice(&ROOT_MOUNT_ID.to_le_bytes());
    fixed[48..56].copy_from_slice(&ROOT_MOUNT_ID.to_le_bytes());
    fixed[56..60].copy_from_slice(&(ROOT_MOUNT_ID as u32).to_le_bytes());
    fixed[60..64].copy_from_slice(&(ROOT_MOUNT_ID as u32).to_le_bytes());
    fixed[72..80].copy_from_slice(&(1u64 << 18).to_le_bytes());
    fixed[112..120].copy_from_slice(&ROOT_MOUNT_ID.to_le_bytes());
    fixed[144..152].copy_from_slice(&SUPPORTED.to_le_bytes());
    let mut output = alloc::vec::Vec::new();
    output
        .try_reserve_exact(total)
        .map_err(|_| CompatErrno::NoMemory)?;
    output.extend_from_slice(&fixed);
    output.extend_from_slice(&strings);
    copy_to_user(args[1], &output, output.len()).map_err(|_| CompatErrno::Fault)?;
    Ok(0)
}

/// Implements `cachestat(2)` for the synthetic resident file namespace.
fn linux_cachestat(pid: ObjId, args: [u64; 6]) -> Result<u64, CompatErrno> {
    const PAGE: u64 = kernel_core::frame::FRAME_SIZE;
    if args[3] != 0 {
        return Err(CompatErrno::Invalid);
    }
    let fd = u32::try_from(args[0]).map_err(|_| CompatErrno::BadFd)?;
    let mut range = [0u8; 16];
    copy_from_user(&mut range, args[1], 16).map_err(|_| CompatErrno::Fault)?;
    let offset = u64::from_le_bytes(range[..8].try_into().unwrap());
    let length = u64::from_le_bytes(range[8..].try_into().unwrap());
    let entry = proc::linux_fd(pid, fd).ok_or(CompatErrno::BadFd)?;
    let file_size = if entry.kind == compat_core::fd::CompatKind::File {
        let (handle, _) = proc::linux_file_state(pid, fd).ok_or(CompatErrno::BadFd)?;
        crate::linux_vfs::FileId::from_handle(handle)
            .ok_or(CompatErrno::BadFd)?
            .bytes()
            .len() as u64
    } else if entry.kind == compat_core::fd::CompatKind::Device {
        proc::linux_ashmem_state(pid, entry.handle)
            .map(|(size, _, _)| size)
            .ok_or(CompatErrno::BadFd)?
    } else {
        return Err(CompatErrno::BadFd);
    };
    let end = if length == 0 {
        file_size
    } else {
        offset
            .checked_add(length)
            .ok_or(CompatErrno::Invalid)?
            .min(file_size)
    };
    let cached_pages = if offset < file_size && end > offset {
        end.saturating_sub(offset).div_ceil(PAGE)
    } else {
        0
    };
    let mut output = [0u8; 40];
    output[..8].copy_from_slice(&cached_pages.to_le_bytes());
    copy_to_user(args[2], &output, output.len()).map_err(|_| CompatErrno::Fault)?;
    Ok(0)
}

/// Implements the active-LSM list for Jasper's capability hook.
fn linux_lsm_list_modules(args: [u64; 6]) -> Result<u64, CompatErrno> {
    const LSM_ID_CAPABILITY: u64 = 100;
    if args[2] != 0 {
        return Err(CompatErrno::Invalid);
    }
    let mut size = [0u8; 4];
    copy_from_user(&mut size, args[1], 4).map_err(|_| CompatErrno::Fault)?;
    let available = u32::from_le_bytes(size);
    let required = 8u32;
    copy_to_user(args[1], &required.to_le_bytes(), 4).map_err(|_| CompatErrno::Fault)?;
    if available < required {
        return Err(CompatErrno::ArgumentTooLong);
    }
    copy_to_user(args[0], &LSM_ID_CAPABILITY.to_le_bytes(), 8)
        .map_err(|_| CompatErrno::Fault)?;
    Ok(1)
}

/// Returns the process's current Jasper MAC label through the LSM context ABI.
fn linux_lsm_get_self_attr(pid: ObjId, args: [u64; 6]) -> Result<u64, CompatErrno> {
    const LSM_ATTR_CURRENT: u32 = 100;
    const LSM_FLAG_SINGLE: u32 = 1;
    const JASPER_LSM_ID: u64 = 0x4a53_0001;
    let attribute = u32::try_from(args[0]).map_err(|_| CompatErrno::Invalid)?;
    let flags = u32::try_from(args[3]).map_err(|_| CompatErrno::Invalid)?;
    if attribute != LSM_ATTR_CURRENT || flags & !LSM_FLAG_SINGLE != 0 {
        return Err(CompatErrno::NotSupported);
    }
    let label = crate::kobj::with(|table| crate::security::process_mac_label_in(table, pid))
        .ok_or(CompatErrno::Perm)?;
    let context = alloc::format!(
        "jasper:v{}:domain={}:secrecy={}:integrity={}:classes={:#x}\0",
        label.version,
        label.domain.0,
        label.secrecy,
        label.integrity,
        label.object_classes
    );
    let total = 32usize
        .checked_add(context.len())
        .and_then(|size| size.checked_add(7))
        .map(|size| size & !7)
        .ok_or(CompatErrno::Overflow)?;
    let mut available = [0u8; 4];
    copy_from_user(&mut available, args[2], 4).map_err(|_| CompatErrno::Fault)?;
    let available = usize::try_from(u32::from_le_bytes(available))
        .map_err(|_| CompatErrno::Invalid)?;
    copy_to_user(
        args[2],
        &(total as u32).to_le_bytes(),
        4,
    )
    .map_err(|_| CompatErrno::Fault)?;
    if available < total {
        return Err(CompatErrno::ArgumentTooLong);
    }
    let mut record = alloc::vec![0u8; total];
    record[..8].copy_from_slice(&JASPER_LSM_ID.to_le_bytes());
    record[16..24].copy_from_slice(&(total as u64).to_le_bytes());
    record[24..32].copy_from_slice(&(context.len() as u64).to_le_bytes());
    record[32..32 + context.len()].copy_from_slice(context.as_bytes());
    if flags & LSM_FLAG_SINGLE != 0 {
        let mut requested = [0u8; 8];
        copy_from_user(&mut requested, args[1], 8).map_err(|_| CompatErrno::Fault)?;
        if u64::from_le_bytes(requested) != JASPER_LSM_ID {
            return Err(CompatErrno::NoSys);
        }
    }
    copy_to_user(args[1], &record, record.len()).map_err(|_| CompatErrno::Fault)?;
    Ok(1)
}

/// Applies one bounded Jasper LSM self-label without allowing privilege
/// escalation. The context is the same versioned form exposed by get-self-attr.
fn linux_lsm_set_self_attr(pid: ObjId, args: [u64; 6]) -> Result<u64, CompatErrno> {
    use kernel_core::mac::{Integrity, MacLabel, Secrecy};
    use kernel_core::security::SecurityDomain;

    const LSM_ATTR_CURRENT: u32 = 100;
    const LSM_FLAG_SINGLE: u32 = 1;
    const JASPER_LSM_ID: u64 = 0x4a53_0001;
    const RECORD_FIXED: usize = 32;
    const MAX_CONTEXT: usize = 4096;

    let attribute = u32::try_from(args[0]).map_err(|_| CompatErrno::Invalid)?;
    let flags = u32::try_from(args[3]).map_err(|_| CompatErrno::Invalid)?;
    if attribute != LSM_ATTR_CURRENT || flags & !LSM_FLAG_SINGLE != 0 {
        return Err(CompatErrno::NotSupported);
    }
    let mut available = [0u8; 4];
    copy_from_user(&mut available, args[2], 4).map_err(|_| CompatErrno::Fault)?;
    let available = usize::try_from(u32::from_le_bytes(available))
        .map_err(|_| CompatErrno::Invalid)?;
    if available < RECORD_FIXED {
        return Err(CompatErrno::Invalid);
    }
    if available > MAX_CONTEXT {
        return Err(CompatErrno::ArgumentTooLong);
    }
    let mut record = alloc::vec![0u8; available];
    copy_from_user(&mut record, args[1], available).map_err(|_| CompatErrno::Fault)?;
    let id = u64::from_le_bytes(record[0..8].try_into().unwrap());
    let record_flags = u64::from_le_bytes(record[8..16].try_into().unwrap());
    let length = usize::try_from(u64::from_le_bytes(record[16..24].try_into().unwrap()))
        .map_err(|_| CompatErrno::Invalid)?;
    let context_len = usize::try_from(u64::from_le_bytes(record[24..32].try_into().unwrap()))
        .map_err(|_| CompatErrno::Invalid)?;
    if id != JASPER_LSM_ID || record_flags != 0 || context_len == 0 {
        return Err(CompatErrno::Invalid);
    }
    let expected_length = RECORD_FIXED
        .checked_add(context_len)
        .and_then(|value| value.checked_add(7))
        .map(|value| value & !7)
        .ok_or(CompatErrno::Overflow)?;
    if length != expected_length || length > available {
        return Err(CompatErrno::Invalid);
    }
    let context_end = RECORD_FIXED
        .checked_add(context_len)
        .ok_or(CompatErrno::Overflow)?;
    let context = &record[RECORD_FIXED..context_end];
    if context.last() != Some(&0) || context[..context_len - 1].contains(&0) {
        return Err(CompatErrno::Invalid);
    }
    let text = core::str::from_utf8(&context[..context_len - 1])
        .map_err(|_| CompatErrno::Invalid)?;
    let rest = text
        .strip_prefix("jasper:v1:domain=")
        .ok_or(CompatErrno::Invalid)?;
    let (domain, rest) = rest
        .split_once(":secrecy=")
        .ok_or(CompatErrno::Invalid)?;
    let (secrecy, rest) = rest
        .split_once(":integrity=")
        .ok_or(CompatErrno::Invalid)?;
    let (integrity, classes) = rest
        .split_once(":classes=")
        .ok_or(CompatErrno::Invalid)?;
    let domain = u32::from_str_radix(domain, 10).map_err(|_| CompatErrno::Invalid)?;
    let secrecy = Secrecy::from_raw(
        u8::from_str_radix(secrecy, 10).map_err(|_| CompatErrno::Invalid)?,
    )
    .ok_or(CompatErrno::Invalid)?;
    let integrity = Integrity::from_raw(
        u8::from_str_radix(integrity, 10).map_err(|_| CompatErrno::Invalid)?,
    )
    .ok_or(CompatErrno::Invalid)?;
    let classes = classes
        .strip_prefix("0x")
        .ok_or(CompatErrno::Invalid)
        .and_then(|value| u16::from_str_radix(value, 16).map_err(|_| CompatErrno::Invalid))?;
    let replacement = MacLabel::new(SecurityDomain(domain), secrecy, integrity, classes);
    crate::security::attenuate_process_mac_label(pid, replacement)
        .map_err(|_| CompatErrno::Perm)?;
    Ok(0)
}

fn linux_file_attr_validate(
    pid: ObjId,
    args: &[u64; 6],
) -> Result<(), CompatErrno> {
    const AT_SYMLINK_NOFOLLOW: u64 = 0x100;
    const AT_EMPTY_PATH: u64 = 0x1000;
    if args[4] & !(AT_SYMLINK_NOFOLLOW | AT_EMPTY_PATH) != 0 {
        return Err(CompatErrno::Invalid);
    }
    let size = usize::try_from(args[3]).map_err(|_| CompatErrno::Invalid)?;
    if size < 24 {
        return Err(CompatErrno::Invalid);
    }
    if size > 4096 {
        return Err(CompatErrno::ArgumentTooLong);
    }
    let path = if args[1] == 0 {
        None
    } else {
        Some(linux_c_string(args[1], 4096)?)
    };
    if path.is_none() || path.as_ref().is_some_and(|path| path.is_empty()) {
        if args[4] & AT_EMPTY_PATH == 0 || path.is_none() {
            if args[4] & AT_EMPTY_PATH == 0 {
                return Err(CompatErrno::NoEntry);
            }
        }
        let fd = u32::try_from(args[0]).map_err(|_| CompatErrno::BadFd)?;
        proc::linux_fd(pid, fd).ok_or(CompatErrno::BadFd)?;
        return Ok(());
    }
    let path = path.expect("nonempty path");
    let resolved = if path.starts_with(b"/") {
        if !is_at_fdcwd(args[0]) {
            return Err(CompatErrno::Invalid);
        }
        path
    } else {
        if path == b".." || path.starts_with(b"../") || path.windows(4).any(|window| window == b"/../")
        {
            return Err(CompatErrno::Invalid);
        }
        let base = if is_at_fdcwd(args[0]) {
            proc::linux_cwd(pid).ok_or(CompatErrno::NoSys)?.path()
        } else {
            let fd = u32::try_from(args[0]).map_err(|_| CompatErrno::BadFd)?;
            if let Some(crate::linux_vfs::Node::Directory(directory)) =
                proc::linux_path_node(pid, fd)
            {
                directory.path()
            } else {
                let (handle, _) =
                    proc::linux_dir_state(pid, fd).ok_or(CompatErrno::NotDirectory)?;
                crate::linux_vfs::DirectoryId::from_handle(handle)
                    .ok_or(CompatErrno::BadFd)?
                    .path()
            }
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
    crate::linux_vfs::lookup_node(&resolved)
        .map(|_| ())
        .ok_or(CompatErrno::NoEntry)
}

/// Implements `file_getattr(2)` for files without extended attributes.
fn linux_file_getattr(pid: ObjId, args: [u64; 6]) -> Result<u64, CompatErrno> {
    linux_file_attr_validate(pid, &args)?;
    let size = usize::try_from(args[3]).map_err(|_| CompatErrno::Invalid)?;
    let output = alloc::vec![0u8; size];
    copy_to_user(args[2], &output, size).map_err(|_| CompatErrno::Fault)?;
    Ok(0)
}

/// Implements `file_setattr(2)`, failing before a write on the read-only root.
fn linux_file_setattr(pid: ObjId, args: [u64; 6]) -> Result<u64, CompatErrno> {
    let size = usize::try_from(args[3]).map_err(|_| CompatErrno::Invalid)?;
    if size < 24 {
        return Err(CompatErrno::Invalid);
    }
    if size > 4096 {
        return Err(CompatErrno::ArgumentTooLong);
    }
    let mut input = alloc::vec![0u8; size];
    copy_from_user(&mut input, args[2], size).map_err(|_| CompatErrno::Fault)?;
    if input.get(24..).is_some_and(|padding| padding.iter().any(|byte| *byte != 0)) {
        return Err(CompatErrno::ArgumentTooLong);
    }
    let xflags = u64::from_le_bytes(input[..8].try_into().unwrap());
    if xflags != 0 {
        return Err(CompatErrno::NotSupported);
    }
    linux_file_attr_validate(pid, &args)?;
    Err(CompatErrno::ReadOnly)
}

fn linux_node_for_path_or_fd(
    pid: ObjId,
    raw_dfd: u64,
    path_pointer: u64,
    empty_allowed: bool,
) -> Result<crate::linux_vfs::Node, CompatErrno> {
    let path = if path_pointer == 0 {
        None
    } else {
        Some(linux_c_string(path_pointer, 4096)?)
    };
    if path.is_none() || path.as_ref().is_some_and(|path| path.is_empty()) {
        if !empty_allowed {
            return Err(CompatErrno::NoEntry);
        }
        let fd = u32::try_from(raw_dfd).map_err(|_| CompatErrno::BadFd)?;
        let entry = proc::linux_fd(pid, fd).ok_or(CompatErrno::BadFd)?;
        if entry.kind == compat_core::fd::CompatKind::File {
            return crate::linux_vfs::FileId::from_handle(entry.handle)
                .map(crate::linux_vfs::Node::File)
                .ok_or(CompatErrno::BadFd);
        }
        if entry.kind == compat_core::fd::CompatKind::Directory {
            return crate::linux_vfs::DirectoryId::from_handle(entry.handle)
                .map(crate::linux_vfs::Node::Directory)
                .ok_or(CompatErrno::BadFd);
        }
        return Err(CompatErrno::BadFd);
    }
    let path = path.expect("nonempty path");
    let resolved = if path.starts_with(b"/") {
        if !is_at_fdcwd(raw_dfd) {
            return Err(CompatErrno::Invalid);
        }
        path
    } else {
        if path == b".." || path.starts_with(b"../") || path.windows(4).any(|window| window == b"/../")
        {
            return Err(CompatErrno::Invalid);
        }
        let base = if is_at_fdcwd(raw_dfd) {
            proc::linux_cwd(pid).ok_or(CompatErrno::NoSys)?.path()
        } else {
            let fd = u32::try_from(raw_dfd).map_err(|_| CompatErrno::BadFd)?;
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
    crate::linux_vfs::lookup_node(&resolved).ok_or(CompatErrno::NoEntry)
}

/// Implements `name_to_handle_at(2)` with stable virtual inode handles.
fn linux_name_to_handle_at(pid: ObjId, args: [u64; 6]) -> Result<u64, CompatErrno> {
    const AT_HANDLE_FID: u64 = 0x200;
    const AT_SYMLINK_FOLLOW: u64 = 0x400;
    const AT_EMPTY_PATH: u64 = 0x1000;
    if args[4] & !(AT_HANDLE_FID | AT_SYMLINK_FOLLOW | AT_EMPTY_PATH) != 0 {
        return Err(CompatErrno::Invalid);
    }
    let node = linux_node_for_path_or_fd(
        pid,
        args[0],
        args[1],
        args[4] & AT_EMPTY_PATH != 0,
    )?;
    let mut capacity = [0u8; 4];
    copy_from_user(&mut capacity, args[2], 4).map_err(|_| CompatErrno::Fault)?;
    let required = 8u32;
    copy_to_user(args[2], &required.to_le_bytes(), 4).map_err(|_| CompatErrno::Fault)?;
    if u32::from_le_bytes(capacity) < required {
        return Err(CompatErrno::Overflow);
    }
    let mut handle = [0u8; 16];
    handle[..4].copy_from_slice(&required.to_le_bytes());
    handle[4..8].copy_from_slice(&0x4a41_5348i32.to_le_bytes());
    handle[8..16].copy_from_slice(&node.inode().to_le_bytes());
    copy_to_user(args[2], &handle, handle.len()).map_err(|_| CompatErrno::Fault)?;
    if args[3] != 0 {
        copy_to_user(args[3], &1i32.to_le_bytes(), 4).map_err(|_| CompatErrno::Fault)?;
    }
    Ok(0)
}

/// Implements `open_by_handle_at(2)` over stable read-only virtual identities.
fn linux_open_by_handle_at(pid: ObjId, args: [u64; 6]) -> Result<u64, CompatErrno> {
    const O_ACCMODE: u64 = 0x3;
    const O_CLOEXEC: u64 = 0x80000;
    const O_DIRECTORY: u64 = 0x10000;
    let flags = args[2];
    if flags & !(O_ACCMODE | O_CLOEXEC | O_DIRECTORY) != 0 || flags & O_ACCMODE != 0 {
        return Err(CompatErrno::Invalid);
    }
    if !is_at_fdcwd(args[0]) {
        let fd = u32::try_from(args[0]).map_err(|_| CompatErrno::BadFd)?;
        proc::linux_fd(pid, fd).ok_or(CompatErrno::BadFd)?;
    }
    let mut raw = [0u8; 16];
    copy_from_user(&mut raw, args[1], 16).map_err(|_| CompatErrno::Fault)?;
    if u32::from_le_bytes(raw[..4].try_into().unwrap()) != 8
        || i32::from_le_bytes(raw[4..8].try_into().unwrap()) != 0x4a41_5348
    {
        return Err(CompatErrno::Invalid);
    }
    let inode = u64::from_le_bytes(raw[8..16].try_into().unwrap());
    let node = crate::linux_vfs::node_from_inode(inode).ok_or(CompatErrno::NoEntry)?;
    let close_on_exec = flags & O_CLOEXEC != 0;
    match node {
        crate::linux_vfs::Node::File(file) if flags & O_DIRECTORY == 0 => {
            if !landlock_path_allows(
                pid,
                node,
                file.path(),
                LANDLOCK_ACCESS_FS_READ_FILE,
            ) {
                return Err(CompatErrno::Access);
            }
            proc::linux_install_file(pid, file.handle(), close_on_exec)
                .map(u64::from)
                .ok_or(CompatErrno::NoSpace)
        }
        crate::linux_vfs::Node::Directory(directory) => {
            if !landlock_path_allows(
                pid,
                node,
                directory.path(),
                LANDLOCK_ACCESS_FS_READ_DIR,
            ) {
                return Err(CompatErrno::Access);
            }
            proc::linux_install_dir(pid, directory.handle(), close_on_exec)
                .map(u64::from)
                .ok_or(CompatErrno::NoSpace)
        }
        crate::linux_vfs::Node::File(_) => Err(CompatErrno::NotDirectory),
        crate::linux_vfs::Node::Executable(_) => Err(CompatErrno::Access),
    }
}

/// Opens a controlled descriptor for the read-only synthetic mount tree.
fn linux_open_tree(pid: ObjId, args: [u64; 6]) -> Result<u64, CompatErrno> {
    const OPEN_TREE_CLONE: u64 = 0x1;
    const AT_SYMLINK_NOFOLLOW: u64 = 0x100;
    const AT_NO_AUTOMOUNT: u64 = 0x800;
    const AT_EMPTY_PATH: u64 = 0x1000;
    const OPEN_TREE_CLOEXEC: u64 = 0x80000;
    const AT_RECURSIVE: u64 = 0x8000;
    let flags = args[2];
    if flags
        & !(OPEN_TREE_CLONE
            | AT_SYMLINK_NOFOLLOW
            | AT_NO_AUTOMOUNT
            | AT_EMPTY_PATH
            | OPEN_TREE_CLOEXEC
            | AT_RECURSIVE)
        != 0
    {
        return Err(CompatErrno::Invalid);
    }
    let _ = linux_node_for_path_or_fd(
        pid,
        args[0],
        args[1],
        flags & AT_EMPTY_PATH != 0,
    )?;
    proc::linux_install_mount_tree(pid, flags & OPEN_TREE_CLOEXEC != 0)
        .map(u64::from)
        .ok_or(CompatErrno::NoSpace)
}

fn linux_open_tree_attr(pid: ObjId, args: [u64; 6]) -> Result<u64, CompatErrno> {
    const KNOWN_ATTRIBUTES: u64 = 0x0020_03bf;
    if args[3] == 0 {
        if args[4] != 0 {
            return Err(CompatErrno::Invalid);
        }
        return linux_open_tree(pid, args);
    }
    if args[4] < 32 {
        return Err(CompatErrno::Invalid);
    }
    let mut attributes = [0u8; 32];
    copy_from_user(&mut attributes, args[3], 32).map_err(|_| CompatErrno::Fault)?;
    let set = u64::from_le_bytes(attributes[..8].try_into().unwrap());
    let clear = u64::from_le_bytes(attributes[8..16].try_into().unwrap());
    if set & !KNOWN_ATTRIBUTES != 0 || clear & !KNOWN_ATTRIBUTES != 0 {
        return Err(CompatErrno::Invalid);
    }
    if set != 0 || clear != 0 {
        return Err(CompatErrno::ReadOnly);
    }
    linux_open_tree(pid, args)
}

fn linux_validate_mount_tree_target(pid: ObjId, raw_fd: u64) -> Result<(), CompatErrno> {
    let fd = u32::try_from(raw_fd).map_err(|_| CompatErrno::BadFd)?;
    let entry = proc::linux_fd(pid, fd).ok_or(CompatErrno::BadFd)?;
    if entry.kind != compat_core::fd::CompatKind::MountTree {
        return Err(CompatErrno::BadFd);
    }
    Ok(())
}

fn linux_move_mount(pid: ObjId, args: [u64; 6]) -> Result<u64, CompatErrno> {
    const F_SYMLINKS: u64 = 0x1;
    const F_AUTOMOUNTS: u64 = 0x2;
    const F_EMPTY_PATH: u64 = 0x4;
    const T_SYMLINKS: u64 = 0x10;
    const T_AUTOMOUNTS: u64 = 0x20;
    const T_EMPTY_PATH: u64 = 0x40;
    const SET_GROUP: u64 = 0x100;
    const BENEATH: u64 = 0x200;
    let flags = args[4];
    if flags
        & !(F_SYMLINKS
            | F_AUTOMOUNTS
            | F_EMPTY_PATH
            | T_SYMLINKS
            | T_AUTOMOUNTS
            | T_EMPTY_PATH
            | SET_GROUP
            | BENEATH)
        != 0
    {
        return Err(CompatErrno::Invalid);
    }
    if flags & F_EMPTY_PATH != 0 {
        linux_validate_mount_tree_target(pid, args[0])?;
    } else {
        linux_node_for_path_or_fd(pid, args[0], args[1], false)?;
    }
    linux_node_for_path_or_fd(
        pid,
        args[2],
        args[3],
        flags & T_EMPTY_PATH != 0,
    )?;
    Err(CompatErrno::ReadOnly)
}

fn linux_mount_setattr(pid: ObjId, args: [u64; 6]) -> Result<u64, CompatErrno> {
    const AT_EMPTY_PATH: u64 = 0x1000;
    const AT_RECURSIVE: u64 = 0x8000;
    const KNOWN_ATTRIBUTES: u64 = 0x0020_03bf;
    if args[2] & !(AT_EMPTY_PATH | AT_RECURSIVE) != 0
        || args[4] < 32
    {
        return Err(CompatErrno::Invalid);
    }
    let mut attributes = [0u8; 32];
    copy_from_user(&mut attributes, args[3], 32).map_err(|_| CompatErrno::Fault)?;
    let set = u64::from_le_bytes(attributes[..8].try_into().unwrap());
    let clear = u64::from_le_bytes(attributes[8..16].try_into().unwrap());
    if set & !KNOWN_ATTRIBUTES != 0 || clear & !KNOWN_ATTRIBUTES != 0 {
        return Err(CompatErrno::Invalid);
    }
    linux_node_for_path_or_fd(
        pid,
        args[0],
        args[1],
        args[2] & AT_EMPTY_PATH != 0,
    )?;
    Err(CompatErrno::ReadOnly)
}

fn linux_fsopen(pid: ObjId, args: [u64; 6]) -> Result<u64, CompatErrno> {
    const FSOPEN_CLOEXEC: u64 = 1;
    if args[1] & !FSOPEN_CLOEXEC != 0 {
        return Err(CompatErrno::Invalid);
    }
    let name = linux_c_string(args[0], 16)?;
    if name != b"jasperfs" {
        return Err(CompatErrno::NotSupported);
    }
    let mut fs_name = [0u8; 16];
    fs_name[..name.len()].copy_from_slice(&name);
    proc::linux_install_fs_context(
        pid,
        fs_name,
        name.len() as u8,
        args[1] & FSOPEN_CLOEXEC != 0,
    )
    .map(u64::from)
    .ok_or(CompatErrno::NoSpace)
}

fn linux_fsconfig(pid: ObjId, args: [u64; 6]) -> Result<u64, CompatErrno> {
    const FSCONFIG_CMD_CREATE: u64 = 6;
    const FSCONFIG_CMD_CREATE_EXCL: u64 = 8;
    let fd = u32::try_from(args[0]).map_err(|_| CompatErrno::BadFd)?;
    let entry = proc::linux_fd(pid, fd).ok_or(CompatErrno::BadFd)?;
    if entry.kind != compat_core::fd::CompatKind::FsContext {
        return Err(CompatErrno::BadFd);
    }
    match args[1] {
        FSCONFIG_CMD_CREATE | FSCONFIG_CMD_CREATE_EXCL => {
            if args[2] != 0 || args[3] != 0 || args[4] != 0 {
                return Err(CompatErrno::Invalid);
            }
            if proc::linux_fs_context_create(pid, fd) {
                Ok(0)
            } else {
                Err(CompatErrno::BadFd)
            }
        }
        0..=5 | 7 => Err(CompatErrno::NotSupported),
        _ => Err(CompatErrno::Invalid),
    }
}

fn linux_fsmount(pid: ObjId, args: [u64; 6]) -> Result<u64, CompatErrno> {
    const FSMOUNT_CLOEXEC: u64 = 1;
    if args[1] & !FSMOUNT_CLOEXEC != 0 || args[2] != 0 {
        return Err(CompatErrno::Invalid);
    }
    let fd = u32::try_from(args[0]).map_err(|_| CompatErrno::BadFd)?;
    if !proc::linux_fs_context_ready(pid, fd) {
        return Err(CompatErrno::BadFd);
    }
    proc::linux_install_mount_tree(pid, args[1] & FSMOUNT_CLOEXEC != 0)
        .map(u64::from)
        .ok_or(CompatErrno::NoSpace)
}

fn linux_fspick(pid: ObjId, args: [u64; 6]) -> Result<u64, CompatErrno> {
    const CLOEXEC: u64 = 1;
    const SYMLINK_NOFOLLOW: u64 = 2;
    const NO_AUTOMOUNT: u64 = 4;
    const EMPTY_PATH: u64 = 8;
    if args[2] & !(CLOEXEC | SYMLINK_NOFOLLOW | NO_AUTOMOUNT | EMPTY_PATH) != 0 {
        return Err(CompatErrno::Invalid);
    }
    linux_node_for_path_or_fd(
        pid,
        args[0],
        args[1],
        args[2] & EMPTY_PATH != 0,
    )?;
    proc::linux_install_mount_tree(pid, args[2] & CLOEXEC != 0)
        .map(u64::from)
        .ok_or(CompatErrno::NoSpace)
}

fn linux_get_mempolicy(_pid: ObjId, args: [u64; 6]) -> Result<u64, CompatErrno> {
    const MPOL_F_MEMS_ALLOWED: u64 = 1 << 2;
    let mode = args[0];
    let nodemask = args[1];
    let maxnode = args[2];
    let address = args[3];
    let flags = args[4];
    if flags & !MPOL_F_MEMS_ALLOWED != 0 || flags != 0 && address != 0 {
        return Err(CompatErrno::Invalid);
    }
    if flags == 0 && address != 0 {
        return Err(CompatErrno::Invalid);
    }
    if nodemask != 0 {
        if maxnode == 0 {
            return Err(CompatErrno::Invalid);
        }
        let available = if flags & MPOL_F_MEMS_ALLOWED != 0 {
            1u64
        } else {
            0u64
        };
        copy_to_user(nodemask, &available.to_le_bytes(), 8)
            .map_err(|_| CompatErrno::Fault)?;
    }
    if mode != 0 && flags & MPOL_F_MEMS_ALLOWED == 0 {
        copy_to_user(mode, &0i32.to_le_bytes(), 4).map_err(|_| CompatErrno::Fault)?;
    }
    Ok(0)
}

fn linux_set_mempolicy(args: [u64; 6]) -> Result<u64, CompatErrno> {
    let mode = i32::try_from(args[0]).map_err(|_| CompatErrno::Invalid)?;
    if mode != 0 || args[1] != 0 && args[2] != 0 {
        return Err(CompatErrno::Invalid);
    }
    Ok(0)
}

fn linux_mempolicy_range(pid: ObjId, start: u64, length: u64) -> Result<(), CompatErrno> {
    const PAGE: u64 = kernel_core::frame::FRAME_SIZE;
    if start % PAGE != 0 || length == 0 {
        return Err(CompatErrno::Invalid);
    }
    let rounded = length
        .checked_add(PAGE - 1)
        .ok_or(CompatErrno::Invalid)?
        & !(PAGE - 1);
    let end = start
        .checked_add(rounded)
        .filter(|end| start >= crate::arch::USER_WINDOW.0 && *end <= crate::arch::USER_WINDOW.1)
        .ok_or(CompatErrno::NoMemory)?;
    let mut page = start;
    while page < end {
        if proc::page_flags(pid, page).is_none() {
            return Err(CompatErrno::NoMemory);
        }
        page += PAGE;
    }
    Ok(())
}

fn linux_mbind(pid: ObjId, args: [u64; 6]) -> Result<u64, CompatErrno> {
    const SUPPORTED_FLAGS: u64 = 0xf;
    let mode = i32::try_from(args[2]).map_err(|_| CompatErrno::Invalid)?;
    if mode != 0 || args[3] != 0 || args[5] & !SUPPORTED_FLAGS != 0 {
        return Err(CompatErrno::Invalid);
    }
    linux_mempolicy_range(pid, args[0], args[1])?;
    Ok(0)
}

fn linux_set_mempolicy_home_node(pid: ObjId, args: [u64; 6]) -> Result<u64, CompatErrno> {
    if args[3] != 0 {
        return Err(CompatErrno::Invalid);
    }
    let home_node = i32::try_from(args[2]).map_err(|_| CompatErrno::Invalid)?;
    if home_node != 0 {
        return Err(CompatErrno::NoEntry);
    }
    linux_mempolicy_range(pid, args[0], args[1])?;
    Ok(0)
}

fn linux_mempolicy_target(pid: ObjId, raw_pid: u64) -> Result<ObjId, CompatErrno> {
    let target_pid = u32::try_from(raw_pid).map_err(|_| CompatErrno::Invalid)?;
    let target = if target_pid == 0 {
        pid
    } else {
        proc::linux_process_for_pid(target_pid).ok_or(CompatErrno::NoProcess)?
    };
    let caller = linux_application_identity(pid).ok_or(CompatErrno::Perm)?;
    let target_app = linux_application_identity(target).ok_or(CompatErrno::NoProcess)?;
    if caller != target_app {
        return Err(CompatErrno::Perm);
    }
    Ok(target)
}

fn linux_migrate_pages(pid: ObjId, args: [u64; 6]) -> Result<u64, CompatErrno> {
    let maxnode = args[1];
    if maxnode == 0 || maxnode > 64 || args[2] == 0 || args[3] == 0 {
        return Err(CompatErrno::Invalid);
    }
    let _ = linux_mempolicy_target(pid, args[0])?;
    let mut old_nodes = [0u8; 8];
    let mut new_nodes = [0u8; 8];
    copy_from_user(&mut old_nodes, args[2], 8).map_err(|_| CompatErrno::Fault)?;
    copy_from_user(&mut new_nodes, args[3], 8).map_err(|_| CompatErrno::Fault)?;
    if u64::from_le_bytes(old_nodes) & 1 == 0 || u64::from_le_bytes(new_nodes) & 1 == 0 {
        return Err(CompatErrno::Invalid);
    }
    Ok(0)
}

fn linux_move_pages(pid: ObjId, args: [u64; 6]) -> Result<u64, CompatErrno> {
    const MAX_PAGES: usize = 1024;
    const MPOL_MF_MOVE: u64 = 2;
    const MPOL_MF_MOVE_ALL: u64 = 4;
    let count = usize::try_from(args[1]).map_err(|_| CompatErrno::Invalid)?;
    if count == 0 || count > MAX_PAGES || args[5] & !(MPOL_MF_MOVE | MPOL_MF_MOVE_ALL) != 0 {
        return Err(CompatErrno::Invalid);
    }
    let target = linux_mempolicy_target(pid, args[0])?;
    let mut pages_raw = alloc::vec![0u8; count * 8];
    let mut statuses = alloc::vec![0i32; count];
    copy_from_user(&mut pages_raw, args[2], count * 8).map_err(|_| CompatErrno::Fault)?;
    let mut nodes = alloc::vec![0i32; count];
    if args[3] != 0 {
        let mut raw = alloc::vec![0u8; count * 4];
        copy_from_user(&mut raw, args[3], count * 4).map_err(|_| CompatErrno::Fault)?;
        for (index, node) in nodes.iter_mut().enumerate() {
            *node = i32::from_le_bytes(raw[index * 4..index * 4 + 4].try_into().unwrap());
        }
    }
    let mut errors = 0u64;
    for (index, page) in pages_raw.chunks_exact(8).enumerate() {
        let address = u64::from_le_bytes(page.try_into().unwrap());
        if proc::page_flags(target, address).is_none() {
            statuses[index] = -(CompatErrno::NoEntry as i32);
            errors += 1;
        } else if args[3] != 0 {
            if nodes[index] != 0 {
                statuses[index] = -(CompatErrno::Invalid as i32);
                errors += 1;
            } else {
                statuses[index] = 0;
            }
        } else {
            statuses[index] = 0;
        }
    }
    let mut status_raw = alloc::vec![0u8; count * 4];
    for (index, status) in statuses.iter().enumerate() {
        status_raw[index * 4..index * 4 + 4].copy_from_slice(&status.to_le_bytes());
    }
    copy_to_user(args[4], &status_raw, status_raw.len()).map_err(|_| CompatErrno::Fault)?;
    Ok(errors)
}

fn linux_process_keyring(
    state: &mut CompatState,
    process: ObjId,
    application: kernel_core::security::ApplicationIdentity,
) -> Result<i32, CompatErrno> {
    if let Some(binding) = state
        .process_keyrings
        .iter()
        .find(|binding| binding.process == process)
    {
        return Ok(binding.serial);
    }
    if state.keys.len() >= MAX_LINUX_KEYS || state.process_keyrings.len() >= MAX_LINUX_KEYS {
        return Err(CompatErrno::NoSpace);
    }
    state.keys.try_reserve(1).map_err(|_| CompatErrno::NoMemory)?;
    state
        .process_keyrings
        .try_reserve(1)
        .map_err(|_| CompatErrno::NoMemory)?;
    let serial = state.next_key_serial;
    state.next_key_serial = serial.checked_add(1).ok_or(CompatErrno::NoSpace)?;
    let mut key_type = [0u8; 16];
    key_type[..7].copy_from_slice(b"keyring");
    state.keys.push(LinuxKey {
        serial,
        application,
        key_type,
        type_len: 7,
        description: [0; 64],
        description_len: 0,
        payload: alloc::vec::Vec::new(),
        revoked: false,
        linked: true,
        uid: 0,
        gid: 0,
        permissions: 0x3f3f_3f3f,
    });
    state.process_keyrings.push(LinuxProcessKeyring {
        process,
        serial,
    });
    Ok(serial)
}

fn linux_add_key(pid: ObjId, args: [u64; 6]) -> Result<u64, CompatErrno> {
    let key_type = linux_c_string(args[0], 16)?;
    if key_type != b"user" && key_type != b"logon" && key_type != b"keyring" {
        return Err(CompatErrno::NotSupported);
    }
    let description = linux_c_string(args[1], 64)?;
    if description.is_empty() || description.len() > 64 {
        return Err(CompatErrno::Invalid);
    }
    let payload_len = usize::try_from(args[3]).map_err(|_| CompatErrno::Invalid)?;
    if payload_len > 1024 {
        return Err(CompatErrno::ArgumentTooLong);
    }
    let mut payload = alloc::vec![0u8; payload_len];
    if payload_len != 0 {
        copy_from_user(&mut payload, args[2], payload_len).map_err(|_| CompatErrno::Fault)?;
    }
    let application =
        linux_application_identity(pid).ok_or(CompatErrno::Perm)?;
    let mut type_name = [0u8; 16];
    type_name[..key_type.len()].copy_from_slice(&key_type);
    let mut desc_name = [0u8; 64];
    desc_name[..description.len()].copy_from_slice(&description);
    let mut state = COMPAT.lock();
    let keyring = args[4] as i32;
    let process_ring = linux_process_keyring(&mut state, pid, application)?;
    if keyring != -2 && keyring != process_ring {
        if !state
            .keys
            .iter()
            .any(|key| key.application == application && key.serial == keyring)
        {
            return Err(CompatErrno::NoEntry);
        }
    }
    if let Some(key) = state.keys.iter_mut().find(|key| {
        key.application == application
            && key.key_type[..usize::from(key.type_len)] == key_type[..]
            && key.description[..usize::from(key.description_len)] == description[..]
    }) {
        key.payload = payload;
        key.revoked = false;
        key.linked = true;
        return Ok(key.serial as u32 as u64);
    }
    if state.keys.len() >= MAX_LINUX_KEYS {
        return Err(CompatErrno::NoSpace);
    }
    state.keys.try_reserve(1).map_err(|_| CompatErrno::NoMemory)?;
    let serial = state.next_key_serial;
    state.next_key_serial = serial.checked_add(1).ok_or(CompatErrno::NoSpace)?;
    state.keys.push(LinuxKey {
        serial,
        application,
        key_type: type_name,
        type_len: key_type.len() as u8,
        description: desc_name,
        description_len: description.len() as u8,
        payload,
        revoked: false,
        linked: true,
        uid: 0,
        gid: 0,
        permissions: 0x3f3f_3f3f,
    });
    Ok(serial as u32 as u64)
}

fn linux_request_key(pid: ObjId, args: [u64; 6]) -> Result<u64, CompatErrno> {
    let key_type = linux_c_string(args[0], 16)?;
    let description = linux_c_string(args[1], 64)?;
    let application =
        linux_application_identity(pid).ok_or(CompatErrno::Perm)?;
    COMPAT
        .lock()
        .keys
        .iter()
        .find(|key| {
            !key.revoked
                && key.linked
                && key.application == application
                && key.key_type[..usize::from(key.type_len)] == key_type[..]
                && key.description[..usize::from(key.description_len)] == description[..]
        })
        .map(|key| key.serial as u32 as u64)
        .ok_or(CompatErrno::NoKey)
}

fn linux_key_allows(
    key: &LinuxKey,
    credentials: proc::LinuxCredentials,
    permission: u32,
) -> bool {
    if credentials.euid == 0 {
        return true;
    }
    let shift = if credentials.euid == key.uid {
        8
    } else if credentials.egid == key.gid {
        16
    } else {
        24
    };
    (key.permissions >> shift) & permission == permission
}

fn linux_keyctl(pid: ObjId, args: [u64; 6]) -> Result<u64, CompatErrno> {
    const GET_KEYRING_ID: u64 = 0;
    const UPDATE: u64 = 2;
    const REVOKE: u64 = 3;
    const CHOWN: u64 = 4;
    const SETPERM: u64 = 5;
    const DESCRIBE: u64 = 6;
    const CLEAR: u64 = 7;
    const LINK: u64 = 8;
    const UNLINK: u64 = 9;
    const SEARCH: u64 = 10;
    const READ: u64 = 11;
    const GET_SECURITY: u64 = 17;
    const INVALIDATE: u64 = 21;
    const CAPABILITIES: u64 = 31;
    let application =
        linux_application_identity(pid).ok_or(CompatErrno::Perm)?;
    let credentials = proc::linux_credentials(pid).ok_or(CompatErrno::NoProcess)?;
    match args[0] {
        GET_KEYRING_ID => {
            if args[1] as i32 != -2 && args[1] as i32 != -1 {
                return Err(CompatErrno::NoEntry);
            }
            let mut state = COMPAT.lock();
            linux_process_keyring(&mut state, pid, application)
                .map(|serial| serial as u32 as u64)
        }
        UPDATE => {
            let serial = args[1] as i32;
            let length = usize::try_from(args[3]).map_err(|_| CompatErrno::Invalid)?;
            if length > 1024 {
                return Err(CompatErrno::ArgumentTooLong);
            }
            let mut payload = alloc::vec![0u8; length];
            if length != 0 {
                copy_from_user(&mut payload, args[2], length).map_err(|_| CompatErrno::Fault)?;
            }
            let mut state = COMPAT.lock();
            let key = state
                .keys
                .iter_mut()
                .find(|key| key.application == application && key.serial == serial)
                .ok_or(CompatErrno::NoEntry)?;
            if key.revoked {
                return Err(CompatErrno::Access);
            }
            if !linux_key_allows(key, credentials, 0x02) {
                return Err(CompatErrno::Access);
            }
            key.payload = payload;
            Ok(0)
        }
        REVOKE | INVALIDATE => {
            let serial = args[1] as i32;
            let mut state = COMPAT.lock();
            let key = state
                .keys
                .iter_mut()
                .find(|key| key.application == application && key.serial == serial)
                .ok_or(CompatErrno::NoEntry)?;
            if !linux_key_allows(key, credentials, 0x20) {
                return Err(CompatErrno::Access);
            }
            key.revoked = true;
            Ok(0)
        }
        CHOWN => {
            let serial = args[1] as i32;
            let mut state = COMPAT.lock();
            let key = state
                .keys
                .iter_mut()
                .find(|key| key.application == application && key.serial == serial)
                .ok_or(CompatErrno::NoKey)?;
            if !linux_key_allows(key, credentials, 0x20) {
                return Err(CompatErrno::Access);
            }
            if args[2] as u32 != u32::MAX {
                key.uid = args[2] as u32;
            }
            if args[3] as u32 != u32::MAX {
                key.gid = args[3] as u32;
            }
            Ok(0)
        }
        SETPERM => {
            const VALID_PERMISSIONS: u32 = 0x3f3f_3f3f;
            let permissions = args[2] as u32;
            if permissions & !VALID_PERMISSIONS != 0 {
                return Err(CompatErrno::Invalid);
            }
            let serial = args[1] as i32;
            let mut state = COMPAT.lock();
            let key = state
                .keys
                .iter_mut()
                .find(|key| key.application == application && key.serial == serial)
                .ok_or(CompatErrno::NoKey)?;
            if !linux_key_allows(key, credentials, 0x20) {
                return Err(CompatErrno::Access);
            }
            key.permissions = permissions;
            Ok(0)
        }
        DESCRIBE => {
            let serial = args[1] as i32;
            let (description, length) = {
                let state = COMPAT.lock();
                let key = state
                    .keys
                    .iter()
                    .find(|key| key.application == application && key.serial == serial)
                    .ok_or(CompatErrno::NoEntry)?;
                if !linux_key_allows(key, credentials, 0x01) {
                    return Err(CompatErrno::Access);
                }
                (
                    key.description,
                    usize::from(key.description_len) + 1,
                )
            };
            if args[2] != 0 {
                if args[3] < length as u64 {
                    return Err(CompatErrno::Range);
                }
                copy_to_user(args[2], &description[..length - 1], length - 1)
                    .map_err(|_| CompatErrno::Fault)?;
                copy_to_user(args[2] + length as u64 - 1, &[0u8], 1)
                    .map_err(|_| CompatErrno::Fault)?;
            }
            Ok(length as u64)
        }
        READ => {
            let serial = args[1] as i32;
            let payload = {
                let state = COMPAT.lock();
                let key = state
                    .keys
                    .iter()
                    .find(|key| key.application == application && key.serial == serial)
                    .ok_or(CompatErrno::NoEntry)?;
                if key.revoked {
                    return Err(CompatErrno::Access);
                }
                if !linux_key_allows(key, credentials, 0x02) {
                    return Err(CompatErrno::Access);
                }
                key.payload.clone()
            };
            if args[2] == 0 {
                return Ok(payload.len() as u64);
            }
            if args[3] < payload.len() as u64 {
                return Err(CompatErrno::Range);
            }
            copy_to_user(args[2], &payload, payload.len()).map_err(|_| CompatErrno::Fault)?;
            Ok(payload.len() as u64)
        }
        LINK | UNLINK => {
            let key_serial = args[1] as i32;
            let keyring = args[2] as i32;
            let mut state = COMPAT.lock();
            if !state.keys.iter().any(|key| {
                key.application == application && key.serial == keyring
                    && key.key_type[..usize::from(key.type_len)] == b"keyring"[..]
            }) {
                return Err(CompatErrno::NoKey);
            }
            let key = state
                .keys
                .iter_mut()
                .find(|key| key.application == application && key.serial == key_serial)
                .ok_or(CompatErrno::NoKey)?;
            if !linux_key_allows(key, credentials, 0x10) {
                return Err(CompatErrno::Access);
            }
            key.linked = args[0] == LINK;
            Ok(0)
        }
        CLEAR => {
            let keyring = args[1] as i32;
            let mut state = COMPAT.lock();
            if !state.keys.iter().any(|key| {
                key.application == application && key.serial == keyring
                    && key.key_type[..usize::from(key.type_len)] == b"keyring"[..]
            }) {
                return Err(CompatErrno::NoKey);
            }
            for key in state
                .keys
                .iter_mut()
                .filter(|key| key.application == application)
            {
                key.linked = false;
            }
            Ok(0)
        }
        SEARCH => {
            let key_type = linux_c_string(args[2], 16)?;
            let description = linux_c_string(args[3], 64)?;
            let state = COMPAT.lock();
            if !state
                .keys
                .iter()
                .any(|key| key.application == application && key.serial == args[1] as i32)
            {
                return Err(CompatErrno::NoKey);
            }
            state
                .keys
                .iter()
                .find(|key| {
                    !key.revoked
                        && key.linked
                        && key.application == application
                        && key.key_type[..usize::from(key.type_len)] == key_type[..]
                        && key.description[..usize::from(key.description_len)] == description[..]
                })
                .map(|key| key.serial as u32 as u64)
                .ok_or(CompatErrno::NoKey)
        }
        GET_SECURITY => {
            let serial = args[1] as i32;
            let context = {
                let state = COMPAT.lock();
                let key = state
                    .keys
                    .iter()
                    .find(|key| key.application == application && key.serial == serial)
                    .ok_or(CompatErrno::NoKey)?;
                if !linux_key_allows(key, credentials, 0x01) {
                    return Err(CompatErrno::Access);
                }
                alloc::format!(
                    "jasper-key:{:016x}\0",
                    application.stable_id
                )
            };
            if args[2] == 0 {
                return Ok(context.len() as u64);
            }
            if args[3] < context.len() as u64 {
                return Err(CompatErrno::Overflow);
            }
            copy_to_user(args[2], context.as_bytes(), context.len())
                .map_err(|_| CompatErrno::Fault)?;
            Ok(context.len() as u64)
        }
        CAPABILITIES => {
            if args[2] < 2 {
                return Err(CompatErrno::ArgumentTooLong);
            }
            let capabilities = [0x21u8, 0u8];
            copy_to_user(args[1], &capabilities, capabilities.len())
                .map_err(|_| CompatErrno::Fault)?;
            Ok(0)
        }
        _ => Err(CompatErrno::NotSupported),
    }
}

fn linux_eventfd(pid: ObjId, args: [u64; 6], eventfd2: bool) -> Result<u64, CompatErrno> {
    const EFD_SEMAPHORE: u64 = 0x1;
    const EFD_NONBLOCK: u64 = 0x800;
    const EFD_CLOEXEC: u64 = 0x80000;
    let initial = u32::try_from(args[0]).map_err(|_| CompatErrno::Invalid)?;
    let flags = if eventfd2 {
        if args[1] & !(EFD_SEMAPHORE | EFD_NONBLOCK | EFD_CLOEXEC) != 0 {
            return Err(CompatErrno::Invalid);
        }
        args[1]
    } else {
        0
    };
    proc::linux_eventfd_create(
        pid,
        initial,
        flags & EFD_CLOEXEC != 0,
        flags & EFD_NONBLOCK != 0,
        flags & EFD_SEMAPHORE != 0,
    )
    .map(u64::from)
    .ok_or(CompatErrno::NoSpace)
}

fn linux_eventfd_read(
    pid: ObjId,
    fd: u32,
    handle: u64,
    address: u64,
    len: usize,
) -> Result<u64, CompatErrno> {
    if len < 8 {
        return Err(CompatErrno::Invalid);
    }
    let (counter, semaphore) =
        proc::linux_eventfd_state(pid, handle).ok_or(CompatErrno::BadFd)?;
    let nonblocking = proc::linux_fd_status_flags(pid, fd).ok_or(CompatErrno::BadFd)? & 0x800 != 0;
    loop {
        let value = {
            let mut value = counter.lock();
            if *value == 0 {
                None
            } else if semaphore {
                *value -= 1;
                Some(1)
            } else {
                Some(core::mem::replace(&mut *value, 0))
            }
        };
        if let Some(value) = value {
            copy_to_user(address, &value.to_le_bytes(), 8).map_err(|_| CompatErrno::Fault)?;
            return Ok(8);
        }
        if nonblocking {
            return Err(CompatErrno::TryAgain);
        }
        if proc::current_exiting() || current_signal_pending(pid) {
            return Err(CompatErrno::Interrupted);
        }
        sched::pause();
    }
}

fn linux_eventfd_write(
    pid: ObjId,
    fd: u32,
    handle: u64,
    address: u64,
    len: usize,
) -> Result<u64, CompatErrno> {
    const MAX_COUNTER: u64 = u64::MAX - 1;
    if len < 8 {
        return Err(CompatErrno::Invalid);
    }
    let mut raw = [0u8; 8];
    copy_from_user(&mut raw, address, 8).map_err(|_| CompatErrno::Fault)?;
    let increment = u64::from_le_bytes(raw);
    if increment == 0 || increment == u64::MAX {
        return Err(CompatErrno::Invalid);
    }
    let (counter, _) = proc::linux_eventfd_state(pid, handle).ok_or(CompatErrno::BadFd)?;
    let nonblocking = proc::linux_fd_status_flags(pid, fd).ok_or(CompatErrno::BadFd)? & 0x800 != 0;
    loop {
        let available = {
            let mut value = counter.lock();
            if *value > MAX_COUNTER - increment {
                None
            } else {
                *value += increment;
                Some(())
            }
        };
        if available.is_some() {
            return Ok(8);
        }
        if nonblocking {
            return Err(CompatErrno::TryAgain);
        }
        if proc::current_exiting() || current_signal_pending(pid) {
            return Err(CompatErrno::Interrupted);
        }
        sched::pause();
    }
}

fn linux_timerfd_clock_now(clock: u32) -> Result<u64, CompatErrno> {
    const CLOCK_REALTIME: u32 = 0;
    const CLOCK_MONOTONIC: u32 = 1;
    match clock {
        CLOCK_MONOTONIC => Ok(sched::now_ns()),
        CLOCK_REALTIME => crate::arch::wall_clock_ns().ok_or(CompatErrno::NoSys),
        _ => Err(CompatErrno::Invalid),
    }
}

fn linux_timerfd_settle(
    state: &mut proc::LinuxTimerFdState,
) -> Result<u64, CompatErrno> {
    let now = linux_timerfd_clock_now(state.clock)?;
    if state.next == 0 || now < state.next {
        return Ok(now);
    }
    let expired = if state.interval == 0 {
        1
    } else {
        (now - state.next) / state.interval + 1
    };
    state.expirations = state.expirations.saturating_add(expired);
    state.next = if state.interval == 0 {
        0
    } else {
        state
            .next
            .saturating_add(expired.saturating_mul(state.interval))
    };
    Ok(now)
}

fn linux_timerfd_create(pid: ObjId, args: [u64; 6]) -> Result<u64, CompatErrno> {
    const TFD_NONBLOCK: u64 = 0x800;
    const TFD_CLOEXEC: u64 = 0x80000;
    let clock = u32::try_from(args[0]).map_err(|_| CompatErrno::Invalid)?;
    if !matches!(clock, 0 | 1) {
        return Err(CompatErrno::Invalid);
    }
    let flags = args[1];
    if flags & !(TFD_NONBLOCK | TFD_CLOEXEC) != 0 {
        return Err(CompatErrno::Invalid);
    }
    proc::linux_timerfd_create(
        pid,
        clock,
        flags & TFD_CLOEXEC != 0,
        flags & TFD_NONBLOCK != 0,
    )
    .map(u64::from)
    .ok_or(CompatErrno::NoSpace)
}

fn linux_timerfd_write_state(
    address: u64,
    next: u64,
    interval: u64,
    now: u64,
) -> Result<(), CompatErrno> {
    let remaining = if next == 0 {
        0
    } else {
        next.saturating_sub(now)
    };
    let mut output = [0u8; 32];
    output[0..8].copy_from_slice(&(interval / 1_000_000_000).to_le_bytes());
    output[8..16].copy_from_slice(&(interval % 1_000_000_000).to_le_bytes());
    output[16..24].copy_from_slice(&(remaining / 1_000_000_000).to_le_bytes());
    output[24..32].copy_from_slice(&(remaining % 1_000_000_000).to_le_bytes());
    copy_to_user(address, &output, output.len()).map_err(|_| CompatErrno::Fault)?;
    Ok(())
}

fn linux_timerfd_settime(pid: ObjId, args: [u64; 6]) -> Result<u64, CompatErrno> {
    const TFD_TIMER_ABSTIME: u64 = 0x1;
    const TFD_TIMER_CANCEL_ON_SET: u64 = 0x2;
    let fd = u32::try_from(args[0]).map_err(|_| CompatErrno::BadFd)?;
    let entry = proc::linux_fd(pid, fd).ok_or(CompatErrno::BadFd)?;
    if entry.kind != compat_core::fd::CompatKind::Timer {
        return Err(CompatErrno::BadFd);
    }
    let flags = args[1];
    if flags & TFD_TIMER_CANCEL_ON_SET != 0 {
        return Err(CompatErrno::NotSupported);
    }
    if flags & !TFD_TIMER_ABSTIME != 0 {
        return Err(CompatErrno::Invalid);
    }
    let interval = read_linux_timespec(args[2])?;
    let value_address = args[2].checked_add(16).ok_or(CompatErrno::Fault)?;
    let value = read_linux_timespec(value_address)?;
    let state = proc::linux_timerfd_state(pid, entry.handle).ok_or(CompatErrno::BadFd)?;
    let (now, old_next, old_interval) = {
        let mut state = state.lock();
        let now = linux_timerfd_settle(&mut state)?;
        (now, state.next, state.interval)
    };
    if args[3] != 0 {
        linux_timerfd_write_state(args[3], old_next, old_interval, now)?;
    }
    let next = if value == 0 {
        0
    } else if flags & TFD_TIMER_ABSTIME != 0 {
        value
    } else {
        now.checked_add(value).ok_or(CompatErrno::Invalid)?
    };
    let mut state = state.lock();
    state.next = next;
    state.interval = interval;
    state.expirations = 0;
    Ok(0)
}

fn linux_timerfd_gettime(pid: ObjId, args: [u64; 6]) -> Result<u64, CompatErrno> {
    let fd = u32::try_from(args[0]).map_err(|_| CompatErrno::BadFd)?;
    let entry = proc::linux_fd(pid, fd).ok_or(CompatErrno::BadFd)?;
    if entry.kind != compat_core::fd::CompatKind::Timer {
        return Err(CompatErrno::BadFd);
    }
    let state = proc::linux_timerfd_state(pid, entry.handle).ok_or(CompatErrno::BadFd)?;
    let (now, next, interval) = {
        let mut state = state.lock();
        let now = linux_timerfd_settle(&mut state)?;
        (now, state.next, state.interval)
    };
    linux_timerfd_write_state(args[1], next, interval, now)?;
    Ok(0)
}

fn linux_timerfd_read(
    pid: ObjId,
    fd: u32,
    handle: u64,
    address: u64,
    len: usize,
) -> Result<u64, CompatErrno> {
    if len < 8 {
        return Err(CompatErrno::Invalid);
    }
    let state = proc::linux_timerfd_state(pid, handle).ok_or(CompatErrno::BadFd)?;
    let nonblocking = proc::linux_fd_status_flags(pid, fd).ok_or(CompatErrno::BadFd)? & 0x800 != 0;
    loop {
        let (value, next) = {
            let mut state = state.lock();
            linux_timerfd_settle(&mut state)?;
            (core::mem::take(&mut state.expirations), state.next)
        };
        if value != 0 {
            if copy_to_user(address, &value.to_le_bytes(), 8).is_err() {
                let mut timer = state.lock();
                timer.expirations = timer.expirations.saturating_add(value);
                return Err(CompatErrno::Fault);
            }
            return Ok(8);
        }
        if nonblocking {
            return Err(CompatErrno::TryAgain);
        }
        if proc::current_exiting() || current_signal_pending(pid) {
            return Err(CompatErrno::Interrupted);
        }
        if next == 0 {
            sched::pause();
        } else {
            sleep_until_with_signal_check(pid, next)?;
        }
    }
}

fn linux_signalfd(pid: ObjId, args: [u64; 6], modern: bool) -> Result<u64, CompatErrno> {
    const SFD_NONBLOCK: u64 = 0x800;
    const SFD_CLOEXEC: u64 = 0x80000;
    let size = if modern {
        usize::try_from(args[2]).map_err(|_| CompatErrno::Invalid)?
    } else {
        8
    };
    if size != 8 {
        return Err(CompatErrno::Invalid);
    }
    let flags = if modern { args[3] } else { 0 };
    if flags & !(SFD_NONBLOCK | SFD_CLOEXEC) != 0 {
        return Err(CompatErrno::Invalid);
    }
    let mut raw = [0u8; 8];
    copy_from_user(&mut raw, args[1], 8).map_err(|_| CompatErrno::Fault)?;
    let mask = u64::from_le_bytes(raw);
    let fd = args[0] as u32 as i32;
    if fd == -1 {
        return proc::linux_signalfd_create(
            pid,
            mask,
            flags & SFD_CLOEXEC != 0,
            flags & SFD_NONBLOCK != 0,
        )
        .map(u64::from)
        .ok_or(CompatErrno::NoSpace);
    }
    if fd < 0 {
        return Err(CompatErrno::Invalid);
    }
    let fd = fd as u32;
    let entry = proc::linux_fd(pid, fd).ok_or(CompatErrno::BadFd)?;
    if entry.kind != compat_core::fd::CompatKind::Signal {
        return Err(CompatErrno::BadFd);
    }
    let state = proc::linux_signalfd_state(pid, entry.handle).ok_or(CompatErrno::BadFd)?;
    *state.lock() = mask;
    if flags & SFD_CLOEXEC != 0 && !proc::linux_set_fd_cloexec(pid, fd, true) {
        return Err(CompatErrno::BadFd);
    }
    if flags & SFD_NONBLOCK != 0 {
        let current = proc::linux_fd_status_flags(pid, fd).ok_or(CompatErrno::BadFd)?;
        if !proc::linux_set_fd_status_flags(pid, fd, current | SFD_NONBLOCK as u32) {
            return Err(CompatErrno::BadFd);
        }
    }
    Ok(u64::from(fd))
}

fn linux_signalfd_read(
    pid: ObjId,
    fd: u32,
    handle: u64,
    address: u64,
    len: usize,
) -> Result<u64, CompatErrno> {
    const RECORD_BYTES: usize = 128;
    const MAX_RECORDS: usize = 16;
    if len < RECORD_BYTES {
        return Err(CompatErrno::Invalid);
    }
    let limit = (len / RECORD_BYTES).min(MAX_RECORDS);
    let mask_state = proc::linux_signalfd_state(pid, handle).ok_or(CompatErrno::BadFd)?;
    let nonblocking = proc::linux_fd_status_flags(pid, fd).ok_or(CompatErrno::BadFd)? & 0x800 != 0;
    loop {
        let requested = *mask_state.lock();
        let mut records = [SignalFdRecord {
            signal: 0,
            sender_pid: 0,
            sender_uid: 0,
            code: 0,
            value: 0,
        }; MAX_RECORDS];
        let mut count = 0usize;
        while count < limit {
            let Some(record) = take_signalfd_record(pid, requested) else {
                break;
            };
            records[count] = record;
            count += 1;
        }
        if count != 0 {
            let mut output = [0u8; RECORD_BYTES * MAX_RECORDS];
            for (index, record) in records[..count].iter().enumerate() {
                let base = index * RECORD_BYTES;
                output[base..base + 4].copy_from_slice(&record.signal.to_le_bytes());
                output[base + 8..base + 12]
                    .copy_from_slice(&record.code.to_le_bytes());
                output[base + 12..base + 16]
                    .copy_from_slice(&record.sender_pid.to_le_bytes());
                output[base + 16..base + 20].copy_from_slice(&record.sender_uid.to_le_bytes());
                output[base + 44..base + 48]
                    .copy_from_slice(&(record.value as u32).to_le_bytes());
                output[base + 48..base + 56].copy_from_slice(&record.value.to_le_bytes());
            }
            copy_to_user(address, &output[..count * RECORD_BYTES], count * RECORD_BYTES)
                .map_err(|_| CompatErrno::Fault)?;
            return Ok((count * RECORD_BYTES) as u64);
        }
        if nonblocking {
            return Err(CompatErrno::TryAgain);
        }
        if proc::current_exiting() || current_signal_pending(pid) {
            return Err(CompatErrno::Interrupted);
        }
        sched::pause();
    }
}

/// Resolves one bounded path to a node in the process compatibility namespace.
fn resolve_linux_path_node(pid: ObjId, address: u64) -> Result<crate::linux_vfs::Node, CompatErrno> {
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
        let base = proc::linux_cwd(pid).ok_or(CompatErrno::NoSys)?.path();
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
    crate::linux_vfs::lookup_node(&resolved).ok_or(CompatErrno::NoEntry)
}

/// Creates one bounded inotify instance.
fn linux_inotify_init(
    pid: ObjId,
    args: [u64; 6],
    modern: bool,
) -> Result<u64, CompatErrno> {
    const IN_NONBLOCK: u64 = 0x800;
    const IN_CLOEXEC: u64 = 0x80000;
    let flags = if modern { args[0] } else { 0 };
    if flags & !(IN_NONBLOCK | IN_CLOEXEC) != 0 {
        return Err(CompatErrno::Invalid);
    }
    proc::linux_inotify_create(
        pid,
        flags & IN_CLOEXEC != 0,
        flags & IN_NONBLOCK != 0,
    )
    .map(u64::from)
    .ok_or(CompatErrno::NoSpace)
}

/// Creates a classic fanotify notification group.
fn linux_fanotify_init(pid: ObjId, args: [u64; 6]) -> Result<u64, CompatErrno> {
    const FAN_CLOEXEC: u32 = 0x1;
    const FAN_NONBLOCK: u32 = 0x2;
    const FAN_CLASS_CONTENT: u32 = 0x4;
    const FAN_CLASS_PRE_CONTENT: u32 = 0x8;
    const FAN_UNLIMITED_QUEUE: u32 = 0x10;
    const FAN_UNLIMITED_MARKS: u32 = 0x20;
    const FAN_ENABLE_AUDIT: u32 = 0x40;
    const O_NONBLOCK: u32 = 0x800;
    const O_CLOEXEC: u32 = 0x80000;
    const O_LARGEFILE: u32 = 0x8000;
    let flags = u32::try_from(args[0]).map_err(|_| CompatErrno::Invalid)?;
    let event_flags = u32::try_from(args[1]).map_err(|_| CompatErrno::Invalid)?;
    if flags & (FAN_CLASS_CONTENT | FAN_CLASS_PRE_CONTENT) != 0
        || flags
            & !(FAN_CLOEXEC
                | FAN_NONBLOCK
                | FAN_CLASS_CONTENT
                | FAN_CLASS_PRE_CONTENT
                | FAN_UNLIMITED_QUEUE
                | FAN_UNLIMITED_MARKS
                | FAN_ENABLE_AUDIT)
            != 0
        || event_flags & !(O_NONBLOCK | O_CLOEXEC | O_LARGEFILE) != 0
    {
        return Err(CompatErrno::NotSupported);
    }
    proc::linux_fanotify_create(
        pid,
        flags & FAN_CLOEXEC != 0,
        flags & FAN_NONBLOCK != 0,
        event_flags & O_CLOEXEC != 0,
    )
    .map(u64::from)
    .ok_or(CompatErrno::NoSpace)
}

fn linux_userfaultfd(pid: ObjId, args: [u64; 6]) -> Result<u64, CompatErrno> {
    const UFFD_USER_MODE_ONLY: u64 = 1;
    if args[0] & !UFFD_USER_MODE_ONLY != 0 {
        return Err(CompatErrno::Invalid);
    }
    proc::linux_userfault_create(pid, false)
        .map(u64::from)
        .ok_or(CompatErrno::NoSpace)
}

fn linux_userfault_ioctl(
    pid: ObjId,
    state: alloc::sync::Arc<crate::sync::SpinLock<proc::LinuxUserfaultState>>,
    command: u64,
    argument: u64,
) -> Result<u64, CompatErrno> {
    const UFFD_API: u64 = 0xAA;
    const UFFD_FEATURE_THREAD_ID: u64 = 1 << 8;
    const UFFDIO_REGISTER_MODE_MISSING: u64 = 1;
    const UFFDIO_API: u64 = 0xc018_aa3f;
    const UFFDIO_REGISTER: u64 = 0xc020_aa00;
    const UFFDIO_UNREGISTER: u64 = 0x8010_aa01;
    const UFFDIO_WAKE: u64 = 0x8010_aa02;
    const UFFDIO_COPY: u64 = 0xc028_aa03;
    const UFFDIO_ZEROPAGE: u64 = 0xc020_aa04;
    const UFFD_IOCTLS: u64 = 0x1f;
    const PAGE: u64 = kernel_core::frame::FRAME_SIZE;
    match command {
        UFFDIO_API => {
            let mut raw = [0u8; 24];
            copy_from_user(&mut raw, argument, 24).map_err(|_| CompatErrno::Fault)?;
            let api = u64::from_le_bytes(raw[0..8].try_into().unwrap());
            let requested = u64::from_le_bytes(raw[8..16].try_into().unwrap());
            if api != UFFD_API || requested & !UFFD_FEATURE_THREAD_ID != 0 {
                return Err(CompatErrno::Invalid);
            }
            let mut state = state.lock();
            state.api = true;
            state.features = UFFD_FEATURE_THREAD_ID;
            drop(state);
            raw[8..16].copy_from_slice(&UFFD_FEATURE_THREAD_ID.to_le_bytes());
            raw[16..24].copy_from_slice(&UFFD_IOCTLS.to_le_bytes());
            copy_to_user(argument, &raw, raw.len()).map_err(|_| CompatErrno::Fault)?;
            Ok(0)
        }
        UFFDIO_REGISTER => {
            let mut raw = [0u8; 32];
            copy_from_user(&mut raw, argument, 32).map_err(|_| CompatErrno::Fault)?;
            let start = u64::from_le_bytes(raw[0..8].try_into().unwrap());
            let len = u64::from_le_bytes(raw[8..16].try_into().unwrap());
            let mode = u64::from_le_bytes(raw[16..24].try_into().unwrap());
            if start % PAGE != 0
                || len == 0
                || mode != UFFDIO_REGISTER_MODE_MISSING
                || start < crate::arch::USER_WINDOW.0
            {
                return Err(CompatErrno::Invalid);
            }
            let end = start.checked_add(len).ok_or(CompatErrno::Invalid)?;
            if end > crate::arch::USER_WINDOW.1 {
                return Err(CompatErrno::Invalid);
            }
            let flags = proc::page_flags(pid, start).ok_or(CompatErrno::NoMemory)?;
            let mut cursor = start;
            while cursor < end {
                if proc::page_flags(pid, cursor) != Some(flags) {
                    return Err(CompatErrno::NoMemory);
                }
                cursor = cursor.saturating_add(PAGE);
            }
            let mut state = state.lock();
            if !state.api {
                return Err(CompatErrno::Invalid);
            }
            if state
                .ranges
                .iter()
                .any(|range| start < range.end && range.start < end)
            {
                return Err(CompatErrno::Busy);
            }
            state
                .ranges
                .try_reserve(1)
                .map_err(|_| CompatErrno::NoMemory)?;
            state.ranges.push(proc::LinuxUserfaultRange { start, end, flags });
            drop(state);
            raw[24..32].copy_from_slice(&UFFD_IOCTLS.to_le_bytes());
            copy_to_user(argument, &raw, raw.len()).map_err(|_| CompatErrno::Fault)?;
            Ok(0)
        }
        UFFDIO_UNREGISTER | UFFDIO_WAKE => {
            let mut raw = [0u8; 16];
            copy_from_user(&mut raw, argument, 16).map_err(|_| CompatErrno::Fault)?;
            let start = u64::from_le_bytes(raw[0..8].try_into().unwrap());
            let len = u64::from_le_bytes(raw[8..16].try_into().unwrap());
            if start % PAGE != 0 || len == 0 {
                return Err(CompatErrno::Invalid);
            }
            let end = start.checked_add(len).ok_or(CompatErrno::Invalid)?;
            if command == UFFDIO_WAKE {
                return Ok(0);
            }
            let mut state = state.lock();
            let before = state.ranges.len();
            state
                .ranges
                .retain(|range| !(start <= range.start && range.end <= end));
            if before == state.ranges.len() {
                return Err(CompatErrno::Invalid);
            }
            Ok(0)
        }
        UFFDIO_COPY | UFFDIO_ZEROPAGE => {
            let (dst, src, len, mode, bytes) = if command == UFFDIO_COPY {
                let mut raw = [0u8; 32];
                copy_from_user(&mut raw, argument, 32).map_err(|_| CompatErrno::Fault)?;
                let dst = u64::from_le_bytes(raw[0..8].try_into().unwrap());
                let src = u64::from_le_bytes(raw[8..16].try_into().unwrap());
                let len = u64::from_le_bytes(raw[16..24].try_into().unwrap());
                let mode = u64::from_le_bytes(raw[24..32].try_into().unwrap());
                if mode & !1 != 0 {
                    return Err(CompatErrno::Invalid);
                }
                let count = usize::try_from(len).map_err(|_| CompatErrno::Invalid)?;
                let mut bytes = alloc::vec![0u8; count];
                copy_from_user(&mut bytes, src, count).map_err(|_| CompatErrno::Fault)?;
                (dst, src, len, mode, bytes)
            } else {
                let mut raw = [0u8; 24];
                copy_from_user(&mut raw, argument, 24)
                    .map_err(|_| CompatErrno::Fault)?;
                let dst = u64::from_le_bytes(raw[0..8].try_into().unwrap());
                let len = u64::from_le_bytes(raw[8..16].try_into().unwrap());
                let mode = u64::from_le_bytes(raw[16..24].try_into().unwrap());
                if mode & !1 != 0 {
                    return Err(CompatErrno::Invalid);
                }
                (dst, 0, len, mode, alloc::vec::Vec::new())
            };
            let _ = (src, mode);
            if dst % PAGE != 0 || len == 0 || len % PAGE != 0 || len > 64 * PAGE {
                return Err(CompatErrno::Invalid);
            }
            let end = dst.checked_add(len).ok_or(CompatErrno::Invalid)?;
            let flags = {
                let state = state.lock();
                let selected = state
                    .ranges
                    .iter()
                    .find(|range| dst >= range.start && end <= range.end)
                    .map(|range| range.flags)
                    .ok_or(CompatErrno::Invalid)?;
                selected
            };
            let mut mapped = alloc::vec::Vec::new();
            let mut offset = 0usize;
            while (offset as u64) < len {
                let address = dst + offset as u64;
                if proc::page_flags(pid, address).is_some() {
                    for address in mapped.into_iter().rev() {
                        let _ = proc::unmap_page(pid, address);
                    }
                    return Err(CompatErrno::Exists);
                }
                if let Err(error) = proc::map_new(pid, address, flags) {
                    let _ = error;
                    for address in mapped.into_iter().rev() {
                        let _ = proc::unmap_page(pid, address);
                    }
                    return Err(CompatErrno::NoMemory);
                }
                mapped.push(address);
                if command == UFFDIO_COPY {
                    if let Err(error) =
                        proc::write(pid, address, &bytes[offset..offset + PAGE as usize])
                    {
                        let _ = error;
                        for address in mapped.into_iter().rev() {
                            let _ = proc::unmap_page(pid, address);
                        }
                        return Err(CompatErrno::Fault);
                    }
                }
                offset += PAGE as usize;
            }
            let result_offset = if command == UFFDIO_COPY { 32 } else { 24 };
            let mut result = alloc::vec![0u8; result_offset + 8];
            copy_from_user(&mut result[..result_offset], argument, result_offset)
                .map_err(|_| CompatErrno::Fault)?;
            result[result_offset..].copy_from_slice(&(len as i64).to_le_bytes());
            copy_to_user(argument, &result, result.len()).map_err(|_| CompatErrno::Fault)?;
            Ok(0)
        }
        _ => Err(CompatErrno::NotSupported),
    }
}

fn linux_userfault_read(
    pid: ObjId,
    fd: u32,
    state: alloc::sync::Arc<crate::sync::SpinLock<proc::LinuxUserfaultState>>,
    address: u64,
    len: usize,
) -> Result<u64, CompatErrno> {
    const EVENT_BYTES: usize = 32;
    if len < EVENT_BYTES {
        return Err(CompatErrno::Invalid);
    }
    let nonblocking =
        proc::linux_fd_status_flags(pid, fd).ok_or(CompatErrno::BadFd)? & 0x800 != 0;
    loop {
        let batch = {
            let mut state = state.lock();
            let count = (len / EVENT_BYTES).min(64).min(state.events.len());
            state.events.drain(..count).collect::<alloc::vec::Vec<_>>()
        };
        if batch.is_empty() {
            if nonblocking {
                return Err(CompatErrno::TryAgain);
            }
            if proc::current_exiting() || current_signal_pending(pid) {
                return Err(CompatErrno::Interrupted);
            }
            sched::pause();
            continue;
        }
        let mut output = alloc::vec![0u8; batch.len() * EVENT_BYTES];
        for (index, event) in batch.iter().enumerate() {
            let base = index * EVENT_BYTES;
            output[base] = 0x12;
            output[base + 8..base + 16].copy_from_slice(&event.flags.to_le_bytes());
            output[base + 16..base + 24].copy_from_slice(&event.address.to_le_bytes());
            output[base + 24..base + 28].copy_from_slice(&event.tid.to_le_bytes());
        }
        copy_to_user(address, &output, output.len()).map_err(|_| CompatErrno::Fault)?;
        return Ok(output.len() as u64);
    }
}

/// Adds or removes one inode, mount, or filesystem fanotify mark.
fn linux_fanotify_mark(pid: ObjId, args: [u64; 6]) -> Result<u64, CompatErrno> {
    const FAN_MARK_ADD: u32 = 0x1;
    const FAN_MARK_REMOVE: u32 = 0x2;
    const FAN_MARK_DONT_FOLLOW: u32 = 0x4;
    const FAN_MARK_ONLYDIR: u32 = 0x8;
    const FAN_MARK_MOUNT: u32 = 0x10;
    const FAN_MARK_FILESYSTEM: u32 = 0x100;
    const FAN_ACCESS: u64 = 0x1;
    const FAN_MODIFY: u64 = 0x2;
    const FAN_CLOSE_WRITE: u64 = 0x8;
    const FAN_CLOSE_NOWRITE: u64 = 0x10;
    const FAN_OPEN: u64 = 0x20;
    const FAN_OPEN_EXEC: u64 = 0x1000;
    const FAN_EVENT_ON_CHILD: u64 = 0x0800_0000;
    const FAN_ONDIR: u64 = 0x4000_0000;
    const NOTIFICATION_MASK: u64 =
        FAN_ACCESS | FAN_MODIFY | FAN_CLOSE_WRITE | FAN_CLOSE_NOWRITE | FAN_OPEN | FAN_OPEN_EXEC;
    let fd = u32::try_from(args[0]).map_err(|_| CompatErrno::BadFd)?;
    let entry = proc::linux_fd(pid, fd).ok_or(CompatErrno::BadFd)?;
    if entry.kind != compat_core::fd::CompatKind::Inotify {
        return Err(CompatErrno::BadFd);
    }
    let flags = u32::try_from(args[1]).map_err(|_| CompatErrno::Invalid)?;
    let mask = args[2];
    let scope_flags = flags & (FAN_MARK_MOUNT | FAN_MARK_FILESYSTEM);
    if flags & !(FAN_MARK_ADD
        | FAN_MARK_REMOVE
        | FAN_MARK_DONT_FOLLOW
        | FAN_MARK_ONLYDIR
        | FAN_MARK_MOUNT
        | FAN_MARK_FILESYSTEM)
        != 0
        || flags & (FAN_MARK_ADD | FAN_MARK_REMOVE)
            != FAN_MARK_ADD
                && flags & (FAN_MARK_ADD | FAN_MARK_REMOVE) != FAN_MARK_REMOVE
        || scope_flags == (FAN_MARK_MOUNT | FAN_MARK_FILESYSTEM)
        || mask & !(NOTIFICATION_MASK | FAN_EVENT_ON_CHILD | FAN_ONDIR) != 0
    {
        return Err(CompatErrno::NotSupported);
    }
    if !is_at_fdcwd(args[3]) || args[4] == 0 {
        return Err(CompatErrno::NotSupported);
    }
    let node = resolve_linux_path_node(pid, args[4])?;
    if flags & FAN_MARK_ONLYDIR != 0 && !node.is_directory() {
        return Err(CompatErrno::NotDirectory);
    }
    if scope_flags != 0
        && node
            != crate::linux_vfs::Node::Directory(crate::linux_vfs::DirectoryId::Root)
    {
        return Err(CompatErrno::NotSupported);
    }
    let scope = if scope_flags == FAN_MARK_FILESYSTEM {
        2
    } else if scope_flags == FAN_MARK_MOUNT {
        1
    } else {
        0
    };
    let state = proc::linux_inotify_state(pid, entry.handle).ok_or(CompatErrno::BadFd)?;
    let mut state = state.lock();
    if !state.fanotify {
        return Err(CompatErrno::BadFd);
    }
    if flags & FAN_MARK_REMOVE != 0 {
        let before = state.fanotify_marks.len();
        state
            .fanotify_marks
            .retain(|mark| !(mark.node == node && mark.scope == scope));
        return if state.fanotify_marks.len() == before {
            Err(CompatErrno::NoEntry)
        } else {
            Ok(0)
        };
    }
    if let Some(mark) = state
        .fanotify_marks
        .iter_mut()
        .find(|mark| mark.node == node && mark.scope == scope)
    {
        mark.mask = mask;
        return Ok(0);
    }
    if state.fanotify_marks.len() >= 64 {
        return Err(CompatErrno::NoSpace);
    }
    state
        .fanotify_marks
        .try_reserve(1)
        .map_err(|_| CompatErrno::NoMemory)?;
    state.fanotify_marks.push(proc::LinuxFanotifyMark {
        node,
        mask,
        scope,
    });
    Ok(0)
}

/// Adds or updates one inotify watch on a static compatibility node.
fn linux_inotify_add_watch(pid: ObjId, args: [u64; 6]) -> Result<u64, CompatErrno> {
    const IN_ONLYDIR: u32 = 0x0100_0000;
    const IN_DONT_FOLLOW: u32 = 0x0200_0000;
    const IN_EXCL_UNLINK: u32 = 0x0400_0000;
    const IN_MASK_CREATE: u32 = 0x1000_0000;
    const IN_MASK_ADD: u32 = 0x2000_0000;
    const IN_ONESHOT: u32 = 0x8000_0000;
    const IN_ALL_EVENTS: u32 = 0x0fff;
    const IN_CONTROL: u32 = IN_ONLYDIR
        | IN_DONT_FOLLOW
        | IN_EXCL_UNLINK
        | IN_MASK_CREATE
        | IN_MASK_ADD
        | IN_ONESHOT;
    let fd = u32::try_from(args[0]).map_err(|_| CompatErrno::BadFd)?;
    let entry = proc::linux_fd(pid, fd).ok_or(CompatErrno::BadFd)?;
    if entry.kind != compat_core::fd::CompatKind::Inotify {
        return Err(CompatErrno::BadFd);
    }
    let mask = u32::try_from(args[2]).map_err(|_| CompatErrno::Invalid)?;
    if mask == 0
        || mask & !(IN_ALL_EVENTS | IN_CONTROL) != 0
        || mask & IN_ALL_EVENTS == 0
        || mask & IN_MASK_CREATE != 0 && mask & IN_MASK_ADD != 0
    {
        return Err(CompatErrno::Invalid);
    }
    let node = resolve_linux_path_node(pid, args[1])?;
    if mask & IN_ONLYDIR != 0 && !node.is_directory() {
        return Err(CompatErrno::NotDirectory);
    }
    let state = proc::linux_inotify_state(pid, entry.handle).ok_or(CompatErrno::BadFd)?;
    let mut state = state.lock();
    if state.fanotify {
        return Err(CompatErrno::BadFd);
    }
    if let Some(watch) = state.watches.iter_mut().find(|watch| watch.node == node) {
        if mask & IN_MASK_CREATE != 0 {
            return Err(CompatErrno::Exists);
        }
        let stored_mask = mask & !(IN_MASK_CREATE | IN_MASK_ADD);
        watch.mask = if mask & IN_MASK_ADD != 0 {
            watch.mask | stored_mask
        } else {
            stored_mask
        };
        return Ok(watch.wd as u64);
    }
    if state.watches.len() >= 64 {
        return Err(CompatErrno::NoSpace);
    }
    let wd = (1..=64)
        .find(|candidate| !state.watches.iter().any(|watch| watch.wd == *candidate))
        .ok_or(CompatErrno::NoSpace)?;
    state
        .watches
        .try_reserve(1)
        .map_err(|_| CompatErrno::NoMemory)?;
    state.watches.push(proc::LinuxInotifyWatch {
        wd,
        node,
        mask: mask & !(IN_MASK_CREATE | IN_MASK_ADD),
    });
    Ok(wd as u64)
}

/// Removes one watch descriptor from an inotify instance.
fn linux_inotify_rm_watch(pid: ObjId, args: [u64; 6]) -> Result<u64, CompatErrno> {
    let fd = u32::try_from(args[0]).map_err(|_| CompatErrno::BadFd)?;
    let entry = proc::linux_fd(pid, fd).ok_or(CompatErrno::BadFd)?;
    if entry.kind != compat_core::fd::CompatKind::Inotify {
        return Err(CompatErrno::BadFd);
    }
    let wd = i32::try_from(args[1]).map_err(|_| CompatErrno::Invalid)?;
    if wd <= 0 {
        return Err(CompatErrno::Invalid);
    }
    let state = proc::linux_inotify_state(pid, entry.handle).ok_or(CompatErrno::BadFd)?;
    let mut state = state.lock();
    if state.fanotify {
        return Err(CompatErrno::BadFd);
    }
    let Some(index) = state.watches.iter().position(|watch| watch.wd == wd) else {
        return Err(CompatErrno::Invalid);
    };
    state.watches.remove(index);
    state
        .events
        .try_reserve(1)
        .map_err(|_| CompatErrno::NoMemory)?;
    state.events.push_back(proc::LinuxInotifyEvent {
        wd,
        mask: 0x8000,
        cookie: 0,
        name: [0; 256],
        name_len: 0,
    });
    drop(state);
    wake_message_queue_waiters();
    Ok(0)
}

/// Reads classic fanotify event metadata and installs one file descriptor per
/// delivered event.
fn linux_fanotify_read(
    pid: ObjId,
    fd: u32,
    address: u64,
    len: usize,
) -> Result<u64, CompatErrno> {
    const EVENT_BYTES: usize = 24;
    const MAX_EVENTS: usize = 8;
    if len < EVENT_BYTES {
        return Err(CompatErrno::Invalid);
    }
    let entry = proc::linux_fd(pid, fd).ok_or(CompatErrno::BadFd)?;
    if entry.kind != compat_core::fd::CompatKind::Inotify {
        return Err(CompatErrno::BadFd);
    }
    let state = proc::linux_inotify_state(pid, entry.handle).ok_or(CompatErrno::BadFd)?;
    let nonblocking =
        proc::linux_fd_status_flags(pid, fd).ok_or(CompatErrno::BadFd)? & 0x800 != 0;
    loop {
        let (batch, event_cloexec) = {
            let mut state = state.lock();
            if !state.fanotify {
                return Err(CompatErrno::BadFd);
            }
            let count = (len / EVENT_BYTES).min(MAX_EVENTS).min(state.fanotify_events.len());
            let batch = state.fanotify_events.drain(..count).collect::<alloc::vec::Vec<_>>();
            (batch, state.fanotify_event_cloexec)
        };
        if batch.is_empty() {
            if nonblocking {
                return Err(CompatErrno::TryAgain);
            }
            if proc::current_exiting() || current_signal_pending(pid) {
                return Err(CompatErrno::Interrupted);
            }
            sched::pause();
            continue;
        }
        let mut output = alloc::vec![0u8; batch.len() * EVENT_BYTES];
        let mut installed = alloc::vec::Vec::new();
        let mut failed = false;
        for (index, event) in batch.iter().enumerate() {
            let event_fd = match event.node {
                crate::linux_vfs::Node::File(file) => {
                    proc::linux_install_file(pid, file.handle(), event_cloexec)
                }
                crate::linux_vfs::Node::Directory(directory) => {
                    proc::linux_install_dir(pid, directory.handle(), event_cloexec)
                }
                crate::linux_vfs::Node::Executable(_) => {
                    proc::linux_install_path(pid, event.node, event_cloexec)
                }
            };
            let Some(event_fd) = event_fd else {
                failed = true;
                break;
            };
            installed.push(event_fd);
            let base = index * EVENT_BYTES;
            output[base..base + 4].copy_from_slice(&(EVENT_BYTES as u32).to_le_bytes());
            output[base + 4] = 3;
            output[base + 5] = 0;
            output[base + 6..base + 8].copy_from_slice(&(EVENT_BYTES as u16).to_le_bytes());
            output[base + 8..base + 16].copy_from_slice(&event.mask.to_le_bytes());
            output[base + 16..base + 20]
                .copy_from_slice(&(event_fd as i32).to_le_bytes());
            output[base + 20..base + 24].copy_from_slice(&event.pid.to_le_bytes());
        }
        if failed || copy_to_user(address, &output, output.len()).is_err() {
            for event_fd in installed {
                let _ = proc::linux_close_fd(pid, event_fd);
            }
            let mut state = state.lock();
            for event in batch.into_iter().rev() {
                state.fanotify_events.push_front(event);
            }
            return Err(if failed {
                CompatErrno::NoSpace
            } else {
                CompatErrno::Fault
            });
        }
        return Ok(output.len() as u64);
    }
}

/// Reads queued inotify control events.
fn linux_inotify_read(
    pid: ObjId,
    fd: u32,
    address: u64,
    len: usize,
) -> Result<u64, CompatErrno> {
    const EVENT_HEADER: usize = 16;
    const MAX_EVENTS: usize = 64;
    const MAX_NAME: usize = 256;
    if len < EVENT_HEADER {
        return Err(CompatErrno::Invalid);
    }
    let entry = proc::linux_fd(pid, fd).ok_or(CompatErrno::BadFd)?;
    if entry.kind != compat_core::fd::CompatKind::Inotify {
        return Err(CompatErrno::BadFd);
    }
    let state = proc::linux_inotify_state(pid, entry.handle).ok_or(CompatErrno::BadFd)?;
    let nonblocking = proc::linux_fd_status_flags(pid, fd).ok_or(CompatErrno::BadFd)? & 0x800 != 0;
    loop {
        let capacity = len.min(MAX_EVENTS * (EVENT_HEADER + MAX_NAME));
        let mut output = alloc::vec![0u8; capacity];
        let mut written = 0usize;
        let mut consumed = 0usize;
        let mut taken = alloc::vec::Vec::new();
        {
            let mut state = state.lock();
            for event in state.events.iter().take(MAX_EVENTS) {
                let name_len = usize::from(event.name_len);
                let event_len = EVENT_HEADER
                    .checked_add(name_len)
                    .and_then(|length| length.checked_add(7))
                    .map(|length| length & !7)
                    .ok_or(CompatErrno::Invalid)?;
                if written + event_len > output.len() {
                    break;
                }
                let base = written;
                output[base..base + 4].copy_from_slice(&event.wd.to_le_bytes());
                output[base + 4..base + 8].copy_from_slice(&event.mask.to_le_bytes());
                output[base + 8..base + 12].copy_from_slice(&event.cookie.to_le_bytes());
                output[base + 12..base + 16].copy_from_slice(&(name_len as u32).to_le_bytes());
                output[base + 16..base + 16 + name_len]
                    .copy_from_slice(&event.name[..name_len]);
                written += event_len;
                consumed += 1;
            }
            taken
                .try_reserve(consumed)
                .map_err(|_| CompatErrno::NoMemory)?;
            for _ in 0..consumed {
                if let Some(event) = state.events.pop_front() {
                    taken.push(event);
                }
            }
        }
        if written != 0 {
            if proc::write(pid, address, &output[..written]).is_err() {
                let mut state = state.lock();
                for event in taken.into_iter().rev() {
                    state.events.push_front(event);
                }
                return Err(CompatErrno::Fault);
            }
            return Ok(written as u64);
        }
        if nonblocking {
            return Err(CompatErrno::TryAgain);
        }
        if proc::current_exiting() || current_signal_pending(pid) {
            return Err(CompatErrno::Interrupted);
        }
        sched::pause();
    }
}

fn linux_posix_timer_settle_one(
    timer: &mut PosixTimer,
) -> Result<u64, CompatErrno> {
    let now = linux_timerfd_clock_now(timer.clock)?;
    if !timer.active || timer.next == 0 || now < timer.next {
        return Ok(now);
    }
    let expired = if timer.interval == 0 {
        1
    } else {
        (now - timer.next) / timer.interval + 1
    };
    if timer.notify == 0 && expired > 1 {
        timer.overrun = timer.overrun.saturating_add(expired - 1);
    }
    timer.next = if timer.interval == 0 {
        0
    } else {
        timer
            .next
            .saturating_add(expired.saturating_mul(timer.interval))
    };
    timer.active = timer.next != 0;
    Ok(now)
}

/// Settles process timers from the periodic clock interrupt.
/// 从周期时钟中断结算进程计时器。
pub(crate) fn settle_posix_timers(now: u64) {
    let mut pending = [None; MAX_POSIX_TIMERS + MAX_INTERVAL_TIMER_SETS];
    let mut pending_count = 0usize;
    {
        let mut state = COMPAT.lock();
        let mut process_pending = [None; MAX_PROCESS_SIGNAL_SETS];
        for (slot, signals) in process_pending
            .iter_mut()
            .zip(state.process_signals.iter().flatten())
        {
            *slot = Some((signals.process, signals.pending));
        }
        for timer in state.posix_timers.iter_mut().flatten() {
            if !timer.active {
                continue;
            }
            let current = if timer.clock == 0 {
                match crate::arch::wall_clock_ns() {
                    Some(value) => value,
                    None => continue,
                }
            } else {
                now
            };
            if current < timer.next {
                continue;
            }
            let expired = if timer.interval == 0 {
                1
            } else {
                (current - timer.next) / timer.interval + 1
            };
            let already_pending = timer.notify == 0
                && process_pending
                    .iter()
                    .flatten()
                    .find(|(process, _)| *process == timer.process)
                    .is_some_and(|(_, pending)| {
                        timer.signal >= 1
                            && timer.signal <= 64
                            && pending & (1u64 << (timer.signal - 1)) != 0
                    });
            if timer.notify == 0 {
                if already_pending {
                    timer.overrun = timer.overrun.saturating_add(expired);
                } else {
                    timer.overrun = timer.overrun.saturating_add(expired - 1);
                }
            }
            timer.next = if timer.interval == 0 {
                0
            } else {
                timer
                    .next
                    .saturating_add(expired.saturating_mul(timer.interval))
            };
            timer.active = timer.next != 0;
            if timer.notify == 0 && !already_pending && pending_count < pending.len() {
                pending[pending_count] = Some((timer.process, timer.signal, -2));
                pending_count += 1;
            }
        }
        for timer in state.interval_timers.iter_mut().flatten() {
            if settle_interval_timer(timer, now) && pending_count < pending.len() {
                pending[pending_count] = Some((timer.process, 14, 128));
                pending_count += 1;
            }
        }
    }
    for (process, signal, code) in pending.into_iter().flatten() {
        let _ = queue_process_signal(process, signal, 0, code);
    }
}

fn release_posix_timers(process: ObjId) {
    let mut state = COMPAT.lock();
    for timer in state.posix_timers.iter_mut() {
        if timer.is_some_and(|timer| timer.process == process) {
            *timer = None;
        }
    }
    for timer in state.interval_timers.iter_mut() {
        if timer.is_some_and(|timer| timer.process == process) {
            *timer = None;
        }
    }
}

/// Removes one dead process's one-shot POSIX message-queue registrations.
fn release_mq_notifications(process: ObjId) {
    for queue in proc::linux_mq_queues(process) {
        let mut state = queue.state.lock();
        if state
            .notification
            .is_some_and(|notification| notification.process == process)
        {
            state.notification = None;
        }
    }
}

fn linux_timer_create(pid: ObjId, args: [u64; 6]) -> Result<u64, CompatErrno> {
    const SIGEV_SIGNAL: u32 = 0;
    const SIGEV_NONE: u32 = 1;
    const SIGALRM: u32 = 14;
    let clock = u32::try_from(args[0]).map_err(|_| CompatErrno::Invalid)?;
    let _ = linux_timerfd_clock_now(clock)?;
    let mut notify = SIGEV_SIGNAL;
    let mut signal = SIGALRM;
    if args[1] != 0 {
        let mut event = [0u8; 64];
        copy_from_user(&mut event, args[1], 64).map_err(|_| CompatErrno::Fault)?;
        signal = u32::from_le_bytes(event[8..12].try_into().unwrap());
        notify = u32::from_le_bytes(event[12..16].try_into().unwrap());
        if !matches!(notify, SIGEV_SIGNAL | SIGEV_NONE) {
            return Err(CompatErrno::NotSupported);
        }
    }
    if notify == SIGEV_SIGNAL && (signal == 0 || signal > 64 || matches!(signal, 9 | 19)) {
        return Err(CompatErrno::Invalid);
    }
    let id = NEXT_POSIX_TIMER_ID.fetch_add(1, Ordering::AcqRel);
    if id == 0 || id == u64::MAX {
        return Err(CompatErrno::NoSpace);
    }
    {
        let mut state = COMPAT.lock();
        let Some(slot) = state.posix_timers.iter().position(Option::is_none) else {
            return Err(CompatErrno::NoSpace);
        };
        state.posix_timers[slot] = Some(PosixTimer {
            process: pid,
            id,
            clock,
            notify,
            signal,
            next: 0,
            interval: 0,
            overrun: 0,
            active: false,
        });
    }
    if copy_to_user(args[2], &id.to_le_bytes(), 8).is_err() {
        let _ = linux_timer_delete(pid, [id, 0, 0, 0, 0, 0]);
        return Err(CompatErrno::Fault);
    }
    Ok(0)
}

fn linux_timer_settime(pid: ObjId, args: [u64; 6]) -> Result<u64, CompatErrno> {
    const TIMER_ABSTIME: u64 = 1;
    if args[1] & !TIMER_ABSTIME != 0 {
        return Err(CompatErrno::Invalid);
    }
    let interval = read_linux_timespec(args[2])?;
    let value_address = args[2].checked_add(16).ok_or(CompatErrno::Fault)?;
    let value = read_linux_timespec(value_address)?;
    let (now, old_next, old_interval) = {
        let mut state = COMPAT.lock();
        let timer = state
            .posix_timers
            .iter_mut()
            .flatten()
            .find(|timer| timer.process == pid && timer.id == args[0])
            .ok_or(CompatErrno::Invalid)?;
        let now = linux_posix_timer_settle_one(timer)?;
        (now, timer.next, timer.interval)
    };
    if args[3] != 0 {
        linux_timerfd_write_state(args[3], old_next, old_interval, now)?;
    }
    let next = if value == 0 {
        0
    } else if args[1] & TIMER_ABSTIME != 0 {
        value
    } else {
        now.checked_add(value).ok_or(CompatErrno::Invalid)?
    };
    let mut state = COMPAT.lock();
    let timer = state
        .posix_timers
        .iter_mut()
        .flatten()
        .find(|timer| timer.process == pid && timer.id == args[0])
        .ok_or(CompatErrno::Invalid)?;
    timer.next = next;
    timer.interval = interval;
    timer.overrun = 0;
    timer.active = next != 0;
    Ok(0)
}

fn linux_timer_gettime(pid: ObjId, args: [u64; 6]) -> Result<u64, CompatErrno> {
    let (now, next, interval) = {
        let mut state = COMPAT.lock();
        let timer = state
            .posix_timers
            .iter_mut()
            .flatten()
            .find(|timer| timer.process == pid && timer.id == args[0])
            .ok_or(CompatErrno::Invalid)?;
        let now = linux_posix_timer_settle_one(timer)?;
        (now, timer.next, timer.interval)
    };
    linux_timerfd_write_state(args[1], next, interval, now)?;
    Ok(0)
}

fn linux_timer_getoverrun(pid: ObjId, args: [u64; 6]) -> Result<u64, CompatErrno> {
    let mut state = COMPAT.lock();
    let timer = state
        .posix_timers
        .iter_mut()
        .flatten()
        .find(|timer| timer.process == pid && timer.id == args[0])
        .ok_or(CompatErrno::Invalid)?;
    let _ = linux_posix_timer_settle_one(timer)?;
    Ok(timer.overrun)
}

fn linux_timer_delete(pid: ObjId, args: [u64; 6]) -> Result<u64, CompatErrno> {
    let mut state = COMPAT.lock();
    let Some(slot) = state
        .posix_timers
        .iter()
        .position(|timer| timer.is_some_and(|timer| timer.process == pid && timer.id == args[0]))
    else {
        return Err(CompatErrno::Invalid);
    };
    state.posix_timers[slot] = None;
    Ok(0)
}

fn linux_ftruncate(pid: ObjId, args: [u64; 6]) -> Result<u64, CompatErrno> {
    let fd = u32::try_from(args[0]).map_err(|_| CompatErrno::BadFd)?;
    let size = args[1];
    let entry = proc::linux_fd(pid, fd).ok_or(CompatErrno::BadFd)?;
    let Some((current, _, _)) = proc::linux_ashmem_state(pid, entry.handle) else {
        return match entry.kind {
            compat_core::fd::CompatKind::File | compat_core::fd::CompatKind::Directory => {
                Err(CompatErrno::ReadOnly)
            }
            _ => Err(CompatErrno::Invalid),
        };
    };
    let seals = proc::linux_ashmem_get_seals(pid, entry.handle).ok_or(CompatErrno::Invalid)?;
    if (size > current && seals & 4 != 0) || (size < current && seals & 2 != 0) {
        return Err(CompatErrno::Perm);
    }
    if current == size {
        return Ok(0);
    }
    proc::linux_ashmem_set_size(pid, entry.handle, size)
        .map_err(ashmem_compat_error)?;
    Ok(0)
}

fn linux_truncate(pid: ObjId, args: [u64; 6]) -> Result<u64, CompatErrno> {
    linux_faccessat(
        pid,
        [(-100i64) as u64, args[0], 0, 0, 0, 0],
        false,
    )?;
    Err(CompatErrno::ReadOnly)
}

fn linux_fallocate(pid: ObjId, args: [u64; 6]) -> Result<u64, CompatErrno> {
    const FALLOC_FL_KEEP_SIZE: u64 = 0x01;
    const FALLOC_FL_PUNCH_HOLE: u64 = 0x02;
    const MAX_BYTES: u64 = 16 * 1024 * 1024;
    let fd = u32::try_from(args[0]).map_err(|_| CompatErrno::BadFd)?;
    let mode = args[1];
    let offset = args[2];
    let length = args[3];
    if length == 0 {
        return Err(CompatErrno::Invalid);
    }
    if mode & !(FALLOC_FL_KEEP_SIZE | FALLOC_FL_PUNCH_HOLE) != 0
        || mode & FALLOC_FL_PUNCH_HOLE != 0 && mode & FALLOC_FL_KEEP_SIZE == 0
    {
        return Err(CompatErrno::NotSupported);
    }
    let end = offset
        .checked_add(length)
        .filter(|end| *end <= MAX_BYTES)
        .ok_or(CompatErrno::Invalid)?;
    let entry = proc::linux_fd(pid, fd).ok_or(CompatErrno::BadFd)?;
    if entry.kind == compat_core::fd::CompatKind::Directory {
        return Err(CompatErrno::IsDirectory);
    }
    let Some((current_size, _, _)) = proc::linux_ashmem_state(pid, entry.handle) else {
        return match entry.kind {
            compat_core::fd::CompatKind::File => Err(CompatErrno::ReadOnly),
            _ => Err(CompatErrno::NotSupported),
        };
    };
    if proc::linux_ashmem_is_regular(pid, entry.handle) != Some(true) {
        return Err(CompatErrno::NotSupported);
    }
    let seals = proc::linux_ashmem_get_seals(pid, entry.handle).ok_or(CompatErrno::Invalid)?;
    if mode & FALLOC_FL_PUNCH_HOLE != 0 {
        if end > current_size {
            return Err(CompatErrno::Invalid);
        }
        if seals & (8 | 16) != 0 {
            return Err(CompatErrno::Perm);
        }
        let zeroes = [0u8; 4096];
        let mut cursor = offset;
        while cursor < end {
            let take = (end - cursor).min(zeroes.len() as u64) as usize;
            proc::linux_ashmem_write_from(pid, entry.handle, cursor, &zeroes[..take])
                .map_err(ashmem_compat_error)?;
            cursor += take as u64;
        }
        return Ok(0);
    }
    if mode & FALLOC_FL_KEEP_SIZE != 0 {
        return if end <= current_size {
            Ok(0)
        } else {
            Err(CompatErrno::NotSupported)
        };
    }
    if end > current_size {
        if seals & 4 != 0 {
            return Err(CompatErrno::Perm);
        }
        proc::linux_ashmem_set_size(pid, entry.handle, end)
            .map_err(ashmem_compat_error)?;
    }
    Ok(0)
}

fn linux_file_range_advice(pid: ObjId, args: [u64; 6]) -> Result<(), CompatErrno> {
    let fd = u32::try_from(args[0]).map_err(|_| CompatErrno::BadFd)?;
    let offset = args[1] as i64;
    let length = args[2] as i64;
    if offset < 0 || length < 0 {
        return Err(CompatErrno::Invalid);
    }
    let entry = proc::linux_fd(pid, fd).ok_or(CompatErrno::BadFd)?;
    match entry.kind {
        compat_core::fd::CompatKind::File => Ok(()),
        compat_core::fd::CompatKind::Directory => Err(CompatErrno::IsDirectory),
        compat_core::fd::CompatKind::Device
            if proc::linux_ashmem_is_regular(pid, entry.handle) == Some(true) =>
        {
            Ok(())
        }
        _ => Err(CompatErrno::Invalid),
    }
}

fn linux_readahead(pid: ObjId, args: [u64; 6]) -> Result<u64, CompatErrno> {
    linux_file_range_advice(pid, args)?;
    Ok(0)
}

fn linux_fadvise64(pid: ObjId, args: [u64; 6]) -> Result<u64, CompatErrno> {
    const POSIX_FADV_NORMAL: u64 = 0;
    const POSIX_FADV_RANDOM: u64 = 1;
    const POSIX_FADV_SEQUENTIAL: u64 = 2;
    const POSIX_FADV_WILLNEED: u64 = 3;
    const POSIX_FADV_DONTNEED: u64 = 4;
    const POSIX_FADV_NOREUSE: u64 = 5;
    if args[3] > POSIX_FADV_NOREUSE {
        return Err(CompatErrno::Invalid);
    }
    let _ = (
        POSIX_FADV_NORMAL,
        POSIX_FADV_RANDOM,
        POSIX_FADV_SEQUENTIAL,
        POSIX_FADV_WILLNEED,
        POSIX_FADV_DONTNEED,
    );
    linux_file_range_advice(pid, args)?;
    Ok(0)
}

fn linux_sync_file_range(pid: ObjId, args: [u64; 6]) -> Result<u64, CompatErrno> {
    const VALID_FLAGS: u64 = 0x1 | 0x2 | 0x4;
    if args[3] & !VALID_FLAGS != 0 {
        return Err(CompatErrno::Invalid);
    }
    linux_file_range_advice(pid, args)?;
    Ok(0)
}

fn linux_utime(pid: ObjId, path: u64) -> Result<u64, CompatErrno> {
    linux_faccessat(
        pid,
        [(-100i64) as u64, path, 0, 0, 0, 0],
        false,
    )?;
    Err(CompatErrno::ReadOnly)
}

fn linux_utimensat(
    pid: ObjId,
    args: [u64; 6],
    has_flags: bool,
) -> Result<u64, CompatErrno> {
    const AT_EMPTY_PATH: u64 = 0x1000;
    let flags = if has_flags { args[3] } else { 0 };
    if args[1] == 0 {
        if has_flags && flags & AT_EMPTY_PATH == 0 {
            return Err(CompatErrno::Fault);
        }
        let fd = u32::try_from(args[0]).map_err(|_| CompatErrno::BadFd)?;
        proc::linux_fd(pid, fd).ok_or(CompatErrno::BadFd)?;
        return Err(CompatErrno::ReadOnly);
    }
    linux_faccessat(pid, [args[0], args[1], 0, flags, 0, 0], has_flags)?;
    Err(CompatErrno::ReadOnly)
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

struct ScmControl {
    transfers: alloc::vec::Vec<proc::LinuxFdTransfer>,
    credentials: bool,
}

/// Parses SCM_RIGHTS descriptors and SCM_CREDENTIALS markers from one bounded
/// control buffer.
fn capture_scm_control(
    pid: ObjId,
    header: &LinuxMessageHeader,
) -> Result<ScmControl, CompatErrno> {
    const CMSG_HEADER_BYTES: usize = 16;
    const MAX_CONTROL_BYTES: usize = 16 * 1024;
    const MAX_SCM_FDS: usize = 32;
    const SOL_SOCKET: i32 = 1;
    const SCM_RIGHTS: i32 = 1;
    const SCM_CREDENTIALS: i32 = 2;
    if header.control == 0 || header.control_len == 0 {
        return Ok(ScmControl {
            transfers: alloc::vec::Vec::new(),
            credentials: false,
        });
    }
    if header.control_len > MAX_CONTROL_BYTES {
        return Err(CompatErrno::Invalid);
    }
    let mut control = alloc::vec![0u8; header.control_len];
    proc::read(pid, header.control, &mut control).map_err(|_| CompatErrno::Fault)?;
    let mut offset = 0usize;
    let mut transfers = alloc::vec::Vec::new();
    let mut credentials = false;
    while offset < control.len() {
        if control.len() - offset < CMSG_HEADER_BYTES {
            return Err(CompatErrno::Invalid);
        }
        let length = usize::try_from(u64::from_le_bytes(
            control[offset..offset + 8].try_into().unwrap(),
        ))
        .map_err(|_| CompatErrno::Invalid)?;
        if length < CMSG_HEADER_BYTES || length > control.len() - offset {
            return Err(CompatErrno::Invalid);
        }
        let level = i32::from_le_bytes(control[offset + 8..offset + 12].try_into().unwrap());
        let kind = i32::from_le_bytes(control[offset + 12..offset + 16].try_into().unwrap());
        if level != SOL_SOCKET {
            return Err(CompatErrno::NoSys);
        }
        let payload = length - CMSG_HEADER_BYTES;
        let start = offset + CMSG_HEADER_BYTES;
        match kind {
            SCM_RIGHTS => {
                if payload == 0 || payload % 4 != 0 {
                    return Err(CompatErrno::Invalid);
                }
                for raw_fd in control[start..start + payload].chunks_exact(4) {
                    if transfers.len() >= MAX_SCM_FDS {
                        return Err(CompatErrno::Invalid);
                    }
                    let fd = i32::from_le_bytes(raw_fd.try_into().unwrap());
                    if fd < 0 {
                        return Err(CompatErrno::BadFd);
                    }
                    let transfer = proc::linux_capture_fd_transfer(pid, fd as u32).map_err(
                        |error| match error {
                            proc::LinuxFdTransferError::Invalid => CompatErrno::BadFd,
                            proc::LinuxFdTransferError::NoSpace => CompatErrno::NoSpace,
                        },
                    )?;
                    transfers.push(transfer);
                }
            }
            SCM_CREDENTIALS => {
                if payload != 12 {
                    return Err(CompatErrno::Invalid);
                }
                credentials = true;
            }
            _ => {
                return Err(CompatErrno::NoSys);
            }
        }
        if payload == 0 {
            return Err(CompatErrno::Invalid);
        }
        offset = offset
            .checked_add((length + 7) & !7)
            .ok_or(CompatErrno::Invalid)?;
    }
    Ok(ScmControl {
        transfers,
        credentials,
    })
}

/// Implements `sendmsg(2)` on a connected AF_UNIX stream, including
/// SCM_RIGHTS descriptor transfer.
fn linux_sendmsg(pid: ObjId, args: [u64; 6]) -> Result<u64, CompatErrno> {
    const MSG_DONTWAIT: u64 = 0x40;
    const MSG_EOR: u64 = 0x80;
    const MSG_NOSIGNAL: u64 = 0x4000;
    const MSG_MORE: u64 = 0x8000;
    let fd = u32::try_from(args[0]).map_err(|_| CompatErrno::BadFd)?;
    let header = read_message_header(pid, args[1])?;
    let flags = args[2];
    if flags & !(MSG_DONTWAIT | MSG_EOR | MSG_NOSIGNAL | MSG_MORE) != 0 {
        return Err(CompatErrno::Invalid);
    }
    if header.name != 0 || header.name_len != 0 {
        return Err(CompatErrno::IsConnected);
    }
    let control = capture_scm_control(pid, &header)?;
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
    let has_control = !control.transfers.is_empty() || control.credentials;
    let written = linux_socket_write_buffer(
        pid,
        fd,
        entry.handle,
        &bytes,
        flags & MSG_DONTWAIT != 0,
        flags & MSG_NOSIGNAL != 0,
        !has_control,
    )?;
    if has_control {
        if written == 0 {
            return Err(CompatErrno::Invalid);
        }
        proc::linux_socket_queue_control(
            pid,
            entry.handle,
            written as usize,
            control.transfers,
            control.credentials,
        )
        .map_err(socket_compat_error)?;
    }
    Ok(written)
}

fn write_control_message(
    control: &mut [u8],
    offset: &mut usize,
    kind: i32,
    payload: &[u8],
) -> Result<(), CompatErrno> {
    const CMSG_HEADER_BYTES: usize = 16;
    let cmsg_len = CMSG_HEADER_BYTES
        .checked_add(payload.len())
        .ok_or(CompatErrno::Invalid)?;
    let space = (cmsg_len + 7) & !7;
    let end = offset
        .checked_add(space)
        .filter(|end| *end <= control.len())
        .ok_or(CompatErrno::Invalid)?;
    control[*offset..*offset + 8].copy_from_slice(&(cmsg_len as u64).to_le_bytes());
    control[*offset + 8..*offset + 12].copy_from_slice(&1i32.to_le_bytes());
    control[*offset + 12..*offset + 16].copy_from_slice(&kind.to_le_bytes());
    control[*offset + CMSG_HEADER_BYTES..*offset + cmsg_len].copy_from_slice(payload);
    *offset = end;
    Ok(())
}

/// Installs received SCM_RIGHTS descriptors and writes SCM_RIGHTS and
/// SCM_CREDENTIALS control records.
fn receive_socket_control(
    pid: ObjId,
    handle: u64,
    header: &LinuxMessageHeader,
    data_bytes: usize,
    close_on_exec: bool,
) -> Result<(usize, u64), CompatErrno> {
    const MSG_CTRUNC: u64 = 0x20;
    const CMSG_HEADER_BYTES: usize = 16;
    const SO_PASSCRED_ENABLED: u32 = 1;
    const SCM_RIGHTS: i32 = 1;
    const SCM_CREDENTIALS: i32 = 2;
    if header.control == 0 || header.control_len == 0 {
        return Ok((0, 0));
    }
    let delivery = proc::linux_socket_consume_control(pid, handle, data_bytes, true);
    let endpoint =
        proc::linux_socket_endpoint(pid, handle).ok_or(CompatErrno::NotConnected)?;
    let passcred = proc::linux_socket_option_flags(pid, handle)
        .is_some_and(|flags| flags & SO_PASSCRED_ENABLED != 0);
    let include_credentials = passcred && (delivery.credentials || !delivery.fds.is_empty());
    if delivery.fds.is_empty() && !include_credentials {
        return Ok((0, 0));
    }
    let rights_payload = delivery
        .fds
        .len()
        .checked_mul(4)
        .ok_or(CompatErrno::Invalid)?;
    let rights_space = if rights_payload == 0 {
        0
    } else {
        (CMSG_HEADER_BYTES + rights_payload + 7) & !7
    };
    let credentials_space = if include_credentials {
        (CMSG_HEADER_BYTES + 12 + 7) & !7
    } else {
        0
    };
    let required = rights_space
        .checked_add(credentials_space)
        .ok_or(CompatErrno::Invalid)?;
    if required > header.control_len {
        return Ok((0, MSG_CTRUNC));
    }
    let mut installed = alloc::vec::Vec::new();
    installed
        .try_reserve(delivery.fds.len())
        .map_err(|_| CompatErrno::NoMemory)?;
    for transfer in delivery.fds {
        match proc::linux_install_fd_transfer(pid, transfer, close_on_exec) {
            Ok(fd) => installed.push(fd),
            Err(_) => {
                for fd in installed {
                    let _ = proc::linux_close_fd(pid, fd);
                }
                return Err(CompatErrno::NoMemory);
            }
        }
    }
    let mut control = alloc::vec![0u8; required];
    let mut control_offset = 0usize;
    if !installed.is_empty() {
        let mut payload = alloc::vec::Vec::new();
        payload
            .try_reserve(installed.len() * 4)
            .map_err(|_| CompatErrno::NoMemory)?;
        for fd in &installed {
            payload.extend_from_slice(&(*fd as i32).to_le_bytes());
        }
        write_control_message(
            &mut control,
            &mut control_offset,
            SCM_RIGHTS,
            &payload,
        )?;
    }
    if include_credentials {
        let credentials = endpoint
            .peer_credentials()
            .ok_or(CompatErrno::NotConnected)?;
        let mut payload = [0u8; 12];
        payload[0..4].copy_from_slice(&(credentials.pid as i32).to_le_bytes());
        payload[4..8].copy_from_slice(&credentials.uid.to_le_bytes());
        payload[8..12].copy_from_slice(&credentials.gid.to_le_bytes());
        write_control_message(
            &mut control,
            &mut control_offset,
            SCM_CREDENTIALS,
            &payload,
        )?;
    }
    proc::write(pid, header.control, &control).map_err(|_| CompatErrno::Fault)?;
    Ok((required, 0))
}

/// Implements `recvmsg(2)` on a connected AF_UNIX stream, including
/// SCM_RIGHTS descriptor receipt.
fn linux_recvmsg(pid: ObjId, args: [u64; 6]) -> Result<u64, CompatErrno> {
    const MSG_DONTWAIT: u64 = 0x40;
    const MSG_WAITALL: u64 = 0x100;
    const MSG_CMSG_CLOEXEC: u64 = 0x4000_0000;
    let fd = u32::try_from(args[0]).map_err(|_| CompatErrno::BadFd)?;
    let header = read_message_header(pid, args[1])?;
    let flags = args[2];
    if flags & !(MSG_DONTWAIT | MSG_WAITALL | MSG_CMSG_CLOEXEC) != 0 {
        return Err(CompatErrno::Invalid);
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
        flags & MSG_DONTWAIT != 0,
        header.control != 0 && header.control_len != 0,
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
    let endpoint =
        proc::linux_socket_endpoint(pid, entry.handle).ok_or(CompatErrno::NotConnected)?;
    let mut name_len = 0usize;
    if header.name != 0 {
        let name = endpoint
            .peer_name()
            .unwrap_or_else(compat_core::UnixSocketName::empty);
        name_len = 2 + name.as_bytes().len();
        write_unix_sockaddr_with_capacity(header.name, header.name_len, name)?;
    }
    let (control_len, message_flags) = receive_socket_control(
        pid,
        entry.handle,
        &header,
        count,
        flags & MSG_CMSG_CLOEXEC != 0,
    )?;
    proc::write(pid, args[1] + 8, &(name_len as u32).to_le_bytes())
        .map_err(|_| CompatErrno::Fault)?;
    proc::write(pid, args[1] + 40, &(control_len as u64).to_le_bytes())
        .map_err(|_| CompatErrno::Fault)?;
    proc::write(
        pid,
        args[1] + 48,
        &(message_flags as u32).to_le_bytes(),
    )
    .map_err(|_| CompatErrno::Fault)?;
    Ok(count as u64)
}

/// Implements bounded `sendmmsg(2)` over the existing `sendmsg(2)` path.
fn linux_sendmmsg(pid: ObjId, args: [u64; 6]) -> Result<u64, CompatErrno> {
    const MMSGHDR_BYTES: u64 = 64;
    const MSG_LEN_OFFSET: u64 = 56;
    const MAX_MESSAGES: u32 = 16;
    let fd = u32::try_from(args[0]).map_err(|_| CompatErrno::BadFd)?;
    proc::linux_fd(pid, fd).ok_or(CompatErrno::BadFd)?;
    let count = u32::try_from(args[2]).map_err(|_| CompatErrno::Invalid)?;
    if count > MAX_MESSAGES {
        return Err(CompatErrno::Invalid);
    }
    let mut sent = 0u32;
    while sent < count {
        let base = args[1]
            .checked_add(u64::from(sent) * MMSGHDR_BYTES)
            .ok_or(CompatErrno::Fault)?;
        match linux_sendmsg(pid, [args[0], base, args[3], 0, 0, 0]) {
            Ok(length) => {
                let length = u32::try_from(length).map_err(|_| CompatErrno::Invalid)?;
                copy_to_user(
                    base.checked_add(MSG_LEN_OFFSET).ok_or(CompatErrno::Fault)?,
                    &length.to_le_bytes(),
                    4,
                )
                .map_err(|_| CompatErrno::Fault)?;
                sent += 1;
            }
            Err(error) if sent == 0 => return Err(error),
            Err(_) => break,
        }
    }
    Ok(u64::from(sent))
}

/// Implements bounded `recvmmsg(2)` over the existing `recvmsg(2)` path.
fn linux_recvmmsg(pid: ObjId, args: [u64; 6]) -> Result<u64, CompatErrno> {
    const MMSGHDR_BYTES: u64 = 64;
    const MSG_LEN_OFFSET: u64 = 56;
    const MAX_MESSAGES: u32 = 16;
    const MSG_DONTWAIT: u64 = 0x40;
    const MSG_WAITFORONE: u64 = 0x10000;
    if args[4] != 0 {
        return Err(CompatErrno::NotSupported);
    }
    let fd = u32::try_from(args[0]).map_err(|_| CompatErrno::BadFd)?;
    proc::linux_fd(pid, fd).ok_or(CompatErrno::BadFd)?;
    let count = u32::try_from(args[2]).map_err(|_| CompatErrno::Invalid)?;
    if count > MAX_MESSAGES {
        return Err(CompatErrno::Invalid);
    }
    let wait_for_one = args[3] & MSG_WAITFORONE != 0;
    let flags = args[3] & !MSG_WAITFORONE;
    let mut received = 0u32;
    while received < count {
        let base = args[1]
            .checked_add(u64::from(received) * MMSGHDR_BYTES)
            .ok_or(CompatErrno::Fault)?;
        let message_flags = if wait_for_one && received != 0 {
            flags | MSG_DONTWAIT
        } else {
            flags
        };
        match linux_recvmsg(pid, [args[0], base, message_flags, 0, 0, 0]) {
            Ok(0) => break,
            Ok(length) => {
                let length = u32::try_from(length).map_err(|_| CompatErrno::Invalid)?;
                copy_to_user(
                    base.checked_add(MSG_LEN_OFFSET).ok_or(CompatErrno::Fault)?,
                    &length.to_le_bytes(),
                    4,
                )
                .map_err(|_| CompatErrno::Fault)?;
                received += 1;
            }
            Err(error) if received == 0 => return Err(error),
            Err(_) => break,
        }
    }
    Ok(u64::from(received))
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

/// Implements the bounded SOL_SOCKET `getsockopt(2)` identity surface.
fn linux_getsockopt(pid: ObjId, args: [u64; 6]) -> Result<u64, CompatErrno> {
    const SOL_SOCKET: u64 = 1;
    const SO_TYPE: u64 = 3;
    const SO_ERROR: u64 = 4;
    const SO_PASSCRED: u64 = 16;
    const SO_PEERCRED: u64 = 17;
    const SO_ACCEPTCONN: u64 = 30;
    const SO_PROTOCOL: u64 = 38;
    const SO_DOMAIN: u64 = 39;
    const SO_PASSCRED_ENABLED: u32 = 1;
    let fd = u32::try_from(args[0]).map_err(|_| CompatErrno::BadFd)?;
    if args[1] != SOL_SOCKET {
        return Err(CompatErrno::NoProtocolOption);
    }
    let entry = proc::linux_fd(pid, fd).ok_or(CompatErrno::BadFd)?;
    if entry.kind != compat_core::fd::CompatKind::Socket {
        return Err(CompatErrno::NotSocket);
    }
    let value = match args[2] {
        SO_TYPE => (1i32).to_le_bytes().to_vec(),
        SO_ERROR => (0i32).to_le_bytes().to_vec(),
        SO_PASSCRED => {
            let flags = proc::linux_socket_option_flags(pid, entry.handle)
                .ok_or(CompatErrno::NotSocket)?;
            (i32::from(flags & SO_PASSCRED_ENABLED != 0)).to_le_bytes().to_vec()
        }
        SO_PEERCRED => {
            let endpoint = proc::linux_socket_endpoint(pid, entry.handle)
                .ok_or(CompatErrno::NotSocket)?;
            if !endpoint.is_connected() {
                return Err(CompatErrno::NotConnected);
            }
            let credentials = endpoint.peer_credentials().ok_or(CompatErrno::NotConnected)?;
            let mut output = [0u8; 12];
            output[0..4].copy_from_slice(&(credentials.pid as i32).to_le_bytes());
            output[4..8].copy_from_slice(&credentials.uid.to_le_bytes());
            output[8..12].copy_from_slice(&credentials.gid.to_le_bytes());
            output.to_vec()
        }
        SO_ACCEPTCONN => {
            let listening =
                proc::linux_socket_is_listening(pid, entry.handle).ok_or(CompatErrno::NotSocket)?;
            (i32::from(listening)).to_le_bytes().to_vec()
        }
        SO_PROTOCOL => (0i32).to_le_bytes().to_vec(),
        SO_DOMAIN => (1i32).to_le_bytes().to_vec(),
        _ => return Err(CompatErrno::NoProtocolOption),
    };
    let mut raw_length = [0u8; 4];
    copy_from_user(&mut raw_length, args[4], 4).map_err(|_| CompatErrno::Fault)?;
    let capacity = u32::from_le_bytes(raw_length) as usize;
    let copied = capacity.min(value.len());
    if copied != 0 {
        copy_to_user(args[3], &value[..copied], copied).map_err(|_| CompatErrno::Fault)?;
    }
    copy_to_user(args[4], &(value.len() as u32).to_le_bytes(), 4)
        .map_err(|_| CompatErrno::Fault)?;
    Ok(0)
}

/// Implements the currently supported SOL_SOCKET `setsockopt(2)` options.
fn linux_setsockopt(pid: ObjId, args: [u64; 6]) -> Result<u64, CompatErrno> {
    const SOL_SOCKET: u64 = 1;
    const SO_PASSCRED: u64 = 16;
    const SO_PASSCRED_ENABLED: u32 = 1;
    let fd = u32::try_from(args[0]).map_err(|_| CompatErrno::BadFd)?;
    if args[1] != SOL_SOCKET || args[2] != SO_PASSCRED {
        return Err(CompatErrno::NoProtocolOption);
    }
    let length = usize::try_from(args[4]).map_err(|_| CompatErrno::Invalid)?;
    if length < 4 {
        return Err(CompatErrno::Invalid);
    }
    let entry = proc::linux_fd(pid, fd).ok_or(CompatErrno::BadFd)?;
    if entry.kind != compat_core::fd::CompatKind::Socket {
        return Err(CompatErrno::NotSocket);
    }
    let mut raw = [0u8; 4];
    copy_from_user(&mut raw, args[3], 4).map_err(|_| CompatErrno::Fault)?;
    let enabled = i32::from_le_bytes(raw);
    if !matches!(enabled, 0 | 1) {
        return Err(CompatErrno::Invalid);
    }
    let mut flags =
        proc::linux_socket_option_flags(pid, entry.handle).ok_or(CompatErrno::NotSocket)?;
    if enabled != 0 {
        flags |= SO_PASSCRED_ENABLED;
    } else {
        flags &= !SO_PASSCRED_ENABLED;
    }
    if !proc::linux_set_socket_option_flags(pid, entry.handle, flags) {
        return Err(CompatErrno::NotSocket);
    }
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
    let mut output = alloc::vec![0u8; len];
    let count = linux_pipe_read_buffer(pid, fd, handle, &mut output, false)?;
    if count != 0 {
        copy_to_user(address, &output[..count], count).map_err(|_| CompatErrno::Fault)?;
    }
    Ok(count as u64)
}

/// Reads one bounded bytes slice from a pipe with optional forced nonblocking mode.
fn linux_pipe_read_buffer(
    pid: ObjId,
    fd: u32,
    handle: u64,
    output: &mut [u8],
    force_nonblocking: bool,
) -> Result<usize, CompatErrno> {
    if output.is_empty() {
        return Ok(0);
    }
    let endpoint = proc::linux_pipe_endpoint(pid, handle).ok_or(CompatErrno::BadFd)?;
    let nonblocking = force_nonblocking
        || proc::linux_fd_status_flags(pid, fd).ok_or(CompatErrno::BadFd)? & 0x800 != 0;
    loop {
        match endpoint.read(&mut *output) {
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
    let mut input = alloc::vec![0u8; len];
    copy_from_user(&mut input, address, len).map_err(|_| CompatErrno::Fault)?;
    linux_pipe_write_buffer(pid, fd, handle, &input).map(|written| written as u64)
}

/// Writes an already validated byte slice into a bounded pipe.
fn linux_pipe_write_buffer(
    pid: ObjId,
    fd: u32,
    handle: u64,
    input: &[u8],
) -> Result<usize, CompatErrno> {
    linux_pipe_write_buffer_mode(pid, fd, handle, input, false)
}

/// Writes a pipe buffer with optional forced nonblocking mode.
fn linux_pipe_write_buffer_mode(
    pid: ObjId,
    fd: u32,
    handle: u64,
    input: &[u8],
    force_nonblocking: bool,
) -> Result<usize, CompatErrno> {
    if input.is_empty() {
        return Ok(0);
    }
    let endpoint = proc::linux_pipe_endpoint(pid, handle).ok_or(CompatErrno::BadFd)?;
    let nonblocking = force_nonblocking
        || proc::linux_fd_status_flags(pid, fd).ok_or(CompatErrno::BadFd)? & 0x800 != 0;
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
                    Ok(written)
                }
            }
            compat_core::PipeWrite::WouldBlock => {
                if proc::current_exiting() || current_signal_pending(pid) {
                    return if written == 0 {
                        Err(CompatErrno::Interrupted)
                    } else {
                        Ok(written)
                    };
                }
                sched::pause();
            }
        }
    }
    Ok(written)
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
    let count =
        linux_socket_read_buffer(pid, fd, handle, &mut output, force_nonblocking, false)?;
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
    capture_control: bool,
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
            compat_core::PipeRead::Data(count) => {
                if count != 0 && !capture_control {
                    let _ = proc::linux_socket_consume_control(pid, handle, count, false);
                }
                return Ok(count);
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
        true,
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
    record_data: bool,
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
                if written == 0 {
                    return Err(CompatErrno::BrokenPipe);
                }
                if record_data {
                    proc::linux_socket_record_data(pid, handle, written);
                }
                return Ok(written as u64);
            }
            compat_core::PipeWrite::WouldBlock if nonblocking => {
                if written != 0 && record_data {
                    proc::linux_socket_record_data(pid, handle, written);
                }
                return if written == 0 {
                    Err(CompatErrno::TryAgain)
                } else {
                    Ok(written as u64)
                }
            }
            compat_core::PipeWrite::WouldBlock => {
                if proc::current_exiting() || current_signal_pending(pid) {
                    if written != 0 && record_data {
                        proc::linux_socket_record_data(pid, handle, written);
                    }
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
    if record_data {
        proc::linux_socket_record_data(pid, handle, written);
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
            let _ = proc::set_linux_termination_signal(pid, SIGPIPE);
            let _ = proc::begin_exit(pid, 128 + i64::from(SIGPIPE));
        }
        _ => {
            if let Some(tid) = linux_tid(pid) {
                let _ = queue_thread_signal(pid, tid, SIGPIPE, 0, 128);
            }
        }
    }
}

fn linux_cache_path(path: &[u8]) -> bool {
    path == LINUX_CACHE_ROOT
        || path
            .strip_prefix(LINUX_CACHE_ROOT)
            .is_some_and(|suffix| suffix.starts_with(b"/"))
}

fn linux_cache_file_id(handle: u64) -> Option<u32> {
    handle
        .checked_sub(LINUX_CACHE_FILE_HANDLE_BASE)
        .and_then(|id| u32::try_from(id).ok())
}

fn linux_cache_dir_id(handle: u64) -> Option<u32> {
    handle
        .checked_sub(LINUX_CACHE_DIR_HANDLE_BASE)
        .and_then(|id| u32::try_from(id).ok())
}

fn linux_cache_dir_path(handle: u64) -> Option<alloc::vec::Vec<u8>> {
    let id = linux_cache_dir_id(handle)?;
    COMPAT
        .lock()
        .cache_dirs
        .iter()
        .find(|directory| directory.id == id)
        .map(|directory| directory.path.clone())
}

fn linux_cache_children(
    handle: u64,
) -> Option<alloc::vec::Vec<(alloc::vec::Vec<u8>, u64, u8)>> {
    let id = linux_cache_dir_id(handle)?;
    let state = COMPAT.lock();
    let path = &state
        .cache_dirs
        .iter()
        .find(|directory| directory.id == id)?
        .path;
    let mut children = alloc::vec::Vec::new();
    for directory in &state.cache_dirs {
        if let Some(name) = directory.path.strip_prefix(path.as_slice()) {
            if let Some(name) = name.strip_prefix(b"/") {
                if !name.is_empty() && !name.contains(&b'/') {
                    children.push((
                        name.to_vec(),
                        LINUX_CACHE_DIR_HANDLE_BASE | u64::from(directory.id),
                        4,
                    ));
                }
            }
        }
    }
    for file in &state.cache_files {
        if let Some(name) = file.path.strip_prefix(path.as_slice()) {
            if let Some(name) = name.strip_prefix(b"/") {
                if !name.is_empty() && !name.contains(&b'/') {
                    children.push((
                        name.to_vec(),
                        LINUX_CACHE_FILE_HANDLE_BASE | u64::from(file.id),
                        8,
                    ));
                }
            }
        }
    }
    Some(children)
}

fn linux_cache_ensure_root(state: &mut CompatState) -> Option<u32> {
    if let Some(directory) = state
        .cache_dirs
        .iter()
        .find(|directory| directory.path == LINUX_CACHE_ROOT)
    {
        return Some(directory.id);
    }
    // Keep the virtual cache's metadata capacity stable before the first
    // workload. Metal2Vulkan creates and removes several small cache entries;
    // allowing a later Vec growth would make otherwise complete executions fail
    // the steady-state heap check.
    state.cache_dirs.try_reserve(16).ok()?;
    state.cache_files.try_reserve(64).ok()?;
    let id = state.next_cache_node_id;
    state.next_cache_node_id = state.next_cache_node_id.checked_add(1)?;
    state.cache_dirs.try_reserve(1).ok()?;
    state.cache_dirs.push(LinuxCacheDir {
        id,
        path: LINUX_CACHE_ROOT.to_vec(),
    });
    Some(id)
}

fn linux_cache_parent(path: &[u8]) -> Option<alloc::vec::Vec<u8>> {
    let path = path.strip_suffix(b"/").unwrap_or(path);
    let slash = path.iter().rposition(|byte| *byte == b'/')?;
    if slash < LINUX_CACHE_ROOT.len() {
        None
    } else {
        Some(path[..slash].to_vec())
    }
}

fn linux_cache_open(
    pid: ObjId,
    path: &[u8],
    flags: u64,
    close_on_exec: bool,
) -> Result<u64, CompatErrno> {
    const O_ACCMODE: u64 = 3;
    const O_CREAT: u64 = 0x40;
    const O_EXCL: u64 = 0x80;
    const O_TRUNC: u64 = 0x200;
    const O_DIRECTORY: u64 = 0x10000;
    let readable = flags & O_ACCMODE != 1;
    let writable = flags & O_ACCMODE != 0;
    let handle = {
        let mut state = COMPAT.lock();
        linux_cache_ensure_root(&mut state).ok_or(CompatErrno::NoSpace)?;
        if let Some(directory) = state
            .cache_dirs
            .iter()
            .find(|directory| directory.path == path)
        {
            if writable {
                return Err(CompatErrno::IsDirectory);
            }
            LINUX_CACHE_DIR_HANDLE_BASE | u64::from(directory.id)
        } else {
            let existing = state
                .cache_files
                .iter()
                .position(|file| file.path == path);
            let index = if let Some(index) = existing {
                if flags & O_CREAT != 0 && flags & O_EXCL != 0 {
                    return Err(CompatErrno::Exists);
                }
                index
            } else {
                if flags & O_CREAT == 0 {
                    return Err(CompatErrno::NoEntry);
                }
                if flags & O_DIRECTORY != 0 {
                    return Err(CompatErrno::NotDirectory);
                }
                let parent = linux_cache_parent(path).ok_or(CompatErrno::NoEntry)?;
                if !state
                    .cache_dirs
                    .iter()
                    .any(|directory| directory.path == parent)
                {
                    return Err(CompatErrno::NoEntry);
                }
                let id = state.next_cache_node_id;
                state.next_cache_node_id =
                    state.next_cache_node_id.checked_add(1).ok_or(CompatErrno::NoSpace)?;
                state.cache_files.try_reserve(1).map_err(|_| CompatErrno::NoSpace)?;
                state.cache_files.push(LinuxCacheFile {
                    id,
                    path: path.to_vec(),
                    bytes: alloc::vec::Vec::new(),
                });
                state.cache_files.len() - 1
            };
            if flags & O_TRUNC != 0 {
                state.cache_files[index].bytes.clear();
            }
            let id = state.cache_files[index].id;
            LINUX_CACHE_FILE_HANDLE_BASE | u64::from(id)
        }
    };
    let installed = if linux_cache_dir_id(handle).is_some() {
        proc::linux_install_dir(pid, handle, close_on_exec)
    } else {
        proc::linux_install_rw_file(pid, handle, readable, writable, close_on_exec)
    };
    installed.map(u64::from).ok_or(CompatErrno::NoSpace)
}

fn linux_cache_create_dir(path: &[u8]) -> Result<(), CompatErrno> {
    let mut state = COMPAT.lock();
    linux_cache_ensure_root(&mut state).ok_or(CompatErrno::NoSpace)?;
    if state.cache_dirs.iter().any(|directory| directory.path == path)
        || state.cache_files.iter().any(|file| file.path == path)
    {
        return Ok(());
    }
    let parent = linux_cache_parent(path).ok_or(CompatErrno::NoEntry)?;
    if !state
        .cache_dirs
        .iter()
        .any(|directory| directory.path == parent)
    {
        return Err(CompatErrno::NoEntry);
    }
    let id = state.next_cache_node_id;
    state.next_cache_node_id = state.next_cache_node_id.checked_add(1).ok_or(CompatErrno::NoSpace)?;
    state.cache_dirs.try_reserve(1).map_err(|_| CompatErrno::NoSpace)?;
    state.cache_dirs.push(LinuxCacheDir {
        id,
        path: path.to_vec(),
    });
    Ok(())
}

fn linux_cache_unlink(path: &[u8], remove_dir: bool) -> Result<(), CompatErrno> {
    let mut state = COMPAT.lock();
    if remove_dir {
        if path == LINUX_CACHE_ROOT {
            return Err(CompatErrno::Perm);
        }
        if state.cache_files.iter().any(|file| {
            file.path.starts_with(path)
                && file.path.get(path.len()) == Some(&b'/')
        }) || state.cache_dirs.iter().any(|directory| {
            directory.path.starts_with(path)
                && directory.path.get(path.len()) == Some(&b'/')
        }) {
            return Err(CompatErrno::Busy);
        }
        let Some(index) = state
            .cache_dirs
            .iter()
            .position(|directory| directory.path == path)
        else {
            return Err(CompatErrno::NoEntry);
        };
        state.cache_dirs.swap_remove(index);
        return Ok(());
    }
    if state.cache_dirs.iter().any(|directory| directory.path == path) {
        return Err(CompatErrno::IsDirectory);
    }
    let Some(index) = state.cache_files.iter().position(|file| file.path == path) else {
        return Err(CompatErrno::NoEntry);
    };
    state.cache_files.swap_remove(index);
    Ok(())
}

fn linux_cache_rename(old_path: &[u8], new_path: &[u8]) -> Result<(), CompatErrno> {
    let mut state = COMPAT.lock();
    if state
        .cache_files
        .iter()
        .any(|file| file.path == new_path)
    {
        return Err(CompatErrno::Exists);
    }
    let parent = linux_cache_parent(new_path).ok_or(CompatErrno::NoEntry)?;
    if !state
        .cache_dirs
        .iter()
        .any(|directory| directory.path == parent)
    {
        return Err(CompatErrno::NoEntry);
    }
    let Some(file) = state
        .cache_files
        .iter_mut()
        .find(|file| file.path == old_path)
    else {
        return Err(CompatErrno::NoEntry);
    };
    file.path.clear();
    file.path.try_reserve(new_path.len()).map_err(|_| CompatErrno::NoSpace)?;
    file.path.extend_from_slice(new_path);
    Ok(())
}

fn linux_cache_read(
    pid: ObjId,
    fd: u32,
    handle: u64,
    destination: u64,
    len: usize,
) -> Result<u64, CompatErrno> {
    let id = linux_cache_file_id(handle).ok_or(CompatErrno::BadFd)?;
    let offset = proc::linux_fd_offset(pid, fd).ok_or(CompatErrno::BadFd)?;
    let offset = usize::try_from(offset).map_err(|_| CompatErrno::Invalid)?;
    let bytes = {
        let state = COMPAT.lock();
        let file = state
            .cache_files
            .iter()
            .find(|file| file.id == id)
            .ok_or(CompatErrno::BadFd)?;
        let available = file.bytes.len().saturating_sub(offset).min(len);
        file.bytes[offset..offset + available].to_vec()
    };
    if !bytes.is_empty() {
        copy_to_user(destination, &bytes, bytes.len()).map_err(|_| CompatErrno::Fault)?;
    }
    if !proc::set_linux_file_offset(pid, fd, (offset + bytes.len()) as u64) {
        return Err(CompatErrno::BadFd);
    }
    Ok(bytes.len() as u64)
}

fn linux_cache_write(
    pid: ObjId,
    fd: u32,
    handle: u64,
    source: u64,
    len: usize,
) -> Result<u64, CompatErrno> {
    if len == 0 {
        return Ok(0);
    }
    let mut bytes = alloc::vec![0u8; len];
    copy_from_user(&mut bytes, source, len).map_err(|_| CompatErrno::Fault)?;
    let id = linux_cache_file_id(handle).ok_or(CompatErrno::BadFd)?;
    let offset = proc::linux_fd_offset(pid, fd).ok_or(CompatErrno::BadFd)?;
    let offset = usize::try_from(offset).map_err(|_| CompatErrno::Invalid)?;
    let end = offset.checked_add(len).ok_or(CompatErrno::Invalid)?;
    {
        let mut state = COMPAT.lock();
        let file = state
            .cache_files
            .iter_mut()
            .find(|file| file.id == id)
            .ok_or(CompatErrno::BadFd)?;
        if end > 16 * 1024 * 1024 {
            return Err(CompatErrno::NoSpace);
        }
        file.bytes.try_reserve(end.saturating_sub(file.bytes.len()))
            .map_err(|_| CompatErrno::NoSpace)?;
        file.bytes.resize(end, 0);
        file.bytes[offset..end].copy_from_slice(&bytes);
    }
    if !proc::set_linux_file_offset(pid, fd, end as u64) {
        return Err(CompatErrno::BadFd);
    }
    Ok(len as u64)
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
    const O_PATH: u64 = 0x20_0000;
    const O_CREAT: u64 = 0x40;
    const O_EXCL: u64 = 0x80;
    const O_TRUNC: u64 = 0x200;
    const O_APPEND: u64 = 0x400;
    #[cfg(any(
        feature = "compat-dynamic-libc-verify",
        feature = "android-art-verify",
        feature = "vulkan-metal2vulkan-verify"
    ))]
    trace_path_address(pid, "openat-address", args[1]);
    let flags = args[2];
    let path_only = flags & O_PATH != 0;
    if flags & 3 == 3
        || flags
            & !(3
                | O_CLOEXEC
                | O_DIRECTORY
                | O_NONBLOCK
                | O_NOCTTY
                | O_NOFOLLOW
                | O_PATH
                | O_CREAT
                | O_EXCL
                | O_TRUNC
                | O_APPEND)
            != 0
    {
        return Err(CompatErrno::Perm);
    }
    let path = linux_c_string(args[1], 4096)?;
    #[cfg(any(
        feature = "compat-dynamic-libc-verify",
        feature = "android-art-verify",
        feature = "vulkan-metal2vulkan-verify"
    ))]
    trace_path("openat", &path);
    if linux_cache_path(&path) {
        return linux_cache_open(pid, &path, flags, flags & O_CLOEXEC != 0);
    }
    if !path.starts_with(b"/") && !is_at_fdcwd(args[0]) {
        let candidate = resolve_linux_at_path(pid, args[0], args[1])?;
        if linux_cache_path(&candidate) {
            return linux_cache_open(pid, &candidate, flags, flags & O_CLOEXEC != 0);
        }
    }
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
            if let Some(crate::linux_vfs::Node::Directory(directory)) =
                proc::linux_path_node(pid, fd)
            {
                directory.path()
            } else {
                let (handle, _) =
                    proc::linux_dir_state(pid, fd).ok_or(CompatErrno::NotDirectory)?;
                crate::linux_vfs::DirectoryId::from_handle(handle)
                    .ok_or(CompatErrno::BadFd)?
                    .path()
            }
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
    if !path_only && resolved == b"/proc/self/maps" {
        if flags & 3 != 0 {
            return Err(CompatErrno::Perm);
        }
        return proc::linux_install_file(pid, LINUX_PROC_MAPS_HANDLE, flags & O_CLOEXEC != 0)
            .map(u64::from)
            .ok_or(CompatErrno::NoSpace);
    }
    if !path_only && linux_cache_path(&resolved) {
        return linux_cache_open(pid, &resolved, flags, flags & O_CLOEXEC != 0);
    }
    if !path_only && resolved == b"/proc/self/stat" {
        if flags & 3 != 0 {
            return Err(CompatErrno::Perm);
        }
        return proc::linux_install_file(pid, LINUX_PROC_STAT_HANDLE, flags & O_CLOEXEC != 0)
            .map(u64::from)
            .ok_or(CompatErrno::NoSpace);
    }
    if !path_only && resolved == b"/dev/ashmem" {
        if flags & 3 != 2 {
            return Err(CompatErrno::Perm);
        }
        return proc::linux_open_ashmem(pid, flags & O_CLOEXEC != 0)
            .map(u64::from)
            .ok_or(CompatErrno::NoSpace);
    }
    if !path_only && resolved == b"/dev/binder" {
        if flags & 3 != 2 {
            return Err(CompatErrno::Perm);
        }
        return proc::linux_open_binder(
            pid,
            flags & O_CLOEXEC != 0,
            flags & O_NONBLOCK != 0,
        )
            .map(u64::from)
            .ok_or(CompatErrno::NoSpace);
    }
    if !path_only && resolved == b"/dev/null" {
        return proc::linux_open_null(pid, flags)
            .map(u64::from)
            .ok_or(CompatErrno::NoSpace);
    }
    if !path_only && resolved == b"/dev/ion" {
        if flags & 3 != 2 {
            return Err(CompatErrno::Perm);
        }
        return proc::linux_open_ion(pid, flags & O_CLOEXEC != 0)
            .map(u64::from)
            .ok_or(CompatErrno::NoSpace);
    }
    if !path_only && resolved == b"/dev/dma_heap/system" {
        if flags & 3 != 2 {
            return Err(CompatErrno::Perm);
        }
        return proc::linux_open_dma_heap(pid, flags & O_CLOEXEC != 0)
            .map(u64::from)
            .ok_or(CompatErrno::NoSpace);
    }
    if !path_only && flags & 3 != 0 {
        return Err(CompatErrno::Perm);
    }
    let node = crate::linux_vfs::lookup_node(&resolved).ok_or(CompatErrno::NoEntry)?;
    let close_on_exec = flags & O_CLOEXEC != 0;
    if path_only {
        if flags & O_DIRECTORY != 0 && !node.is_directory() {
            return Err(CompatErrno::NotDirectory);
        }
        return proc::linux_install_path(pid, node, close_on_exec)
            .map(u64::from)
            .ok_or(CompatErrno::NoSpace);
    }
    let access = if flags & 3 == 0 {
        if node.is_directory() {
            LANDLOCK_ACCESS_FS_READ_DIR
        } else {
            LANDLOCK_ACCESS_FS_READ_FILE
        }
    } else {
        LANDLOCK_ACCESS_FS_WRITE_FILE
    };
    if !landlock_path_allows(pid, node, &resolved, access) {
        return Err(CompatErrno::Access);
    }
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
    let event_mask = 0x20u64
        | if node.is_directory() {
            0x4000_0000u64
        } else {
            0
        };
    proc::linux_fanotify_notify(
        node,
        event_mask,
        proc::linux_pid(pid).unwrap_or(0),
    );
    Ok(u64::from(fd))
}

/// Implements the fixed-size x86_64 `openat2(2)` structure.
fn linux_openat2(pid: ObjId, args: [u64; 6]) -> Result<u64, CompatErrno> {
    const OPEN_HOW_BYTES: usize = 24;
    const RESOLVE_NO_XDEV: u64 = 0x1;
    const RESOLVE_NO_MAGICLINKS: u64 = 0x2;
    const RESOLVE_NO_SYMLINKS: u64 = 0x4;
    const RESOLVE_BENEATH: u64 = 0x8;
    const RESOLVE_IN_ROOT: u64 = 0x10;
    const RESOLVE_CACHED: u64 = 0x20;
    const SUPPORTED_RESOLVE: u64 = RESOLVE_NO_XDEV
        | RESOLVE_NO_MAGICLINKS
        | RESOLVE_NO_SYMLINKS
        | RESOLVE_BENEATH
        | RESOLVE_IN_ROOT
        | RESOLVE_CACHED;
    if args[3] != OPEN_HOW_BYTES as u64 {
        return Err(CompatErrno::Invalid);
    }
    let mut how = [0u8; OPEN_HOW_BYTES];
    copy_from_user(&mut how, args[2], OPEN_HOW_BYTES).map_err(|_| CompatErrno::Fault)?;
    let flags = u64::from_le_bytes(how[0..8].try_into().unwrap());
    let mode = u64::from_le_bytes(how[8..16].try_into().unwrap());
    let resolve = u64::from_le_bytes(how[16..24].try_into().unwrap());
    if resolve & !SUPPORTED_RESOLVE != 0
        || resolve & RESOLVE_BENEATH != 0 && resolve & RESOLVE_IN_ROOT != 0
        || mode & !0o7777 != 0
    {
        return Err(CompatErrno::Invalid);
    }
    let path = linux_c_string(args[1], 4096)?;
    let escapes = path.starts_with(b"/")
        || path
            .split(|byte| *byte == b'/')
            .any(|component| component == b"..");
    if resolve & RESOLVE_BENEATH != 0 && escapes {
        return Err(CompatErrno::CrossDevice);
    }
    if resolve & RESOLVE_IN_ROOT != 0
        && path.starts_with(b"/")
        && !is_at_fdcwd(args[0])
    {
        return Err(CompatErrno::NotSupported);
    }
    linux_openat(pid, [args[0], args[1], flags, mode, 0, 0])
}

/// Implements legacy x86_64 `open(2)` relative to the current directory.
fn linux_open(pid: ObjId, args: [u64; 6]) -> Result<u64, CompatErrno> {
    linux_openat(
        pid,
        [(-100i64) as u64, args[0], args[1], args[2], 0, 0],
    )
}

/// Implements `creat(2)` as a write-open denied by the immutable compatibility root.
fn linux_creat(pid: ObjId, args: [u64; 6]) -> Result<u64, CompatErrno> {
    if args[1] & !0o7777 != 0 {
        return Err(CompatErrno::Invalid);
    }
    linux_faccessat(pid, [(-100i64) as u64, args[0], 0, 0, 0, 0], false)?;
    Err(CompatErrno::ReadOnly)
}

/// Changes the compatibility working directory to one authorized directory.
///
/// `fchdir` 只接受已验证的目录 fd，并把同一目录身份提交为进程 cwd。
fn linux_fchdir(pid: ObjId, fd: u64) -> Result<u64, CompatErrno> {
    let fd = u32::try_from(fd).map_err(|_| CompatErrno::BadFd)?;
    if let Some(node) = proc::linux_path_node(pid, fd) {
        let crate::linux_vfs::Node::Directory(directory) = node else {
            return Err(CompatErrno::NotDirectory);
        };
        return if proc::set_linux_cwd(pid, directory) {
            Ok(0)
        } else {
            Err(CompatErrno::NoSys)
        };
    }
    let (handle, _) = proc::linux_dir_state(pid, fd).ok_or(CompatErrno::BadFd)?;
    let directory = crate::linux_vfs::DirectoryId::from_handle(handle).ok_or(CompatErrno::BadFd)?;
    if proc::set_linux_cwd(pid, directory) {
        Ok(0)
    } else {
        Err(CompatErrno::NoSys)
    }
}

fn linux_fchmod(pid: ObjId, args: [u64; 6]) -> Result<u64, CompatErrno> {
    if args[1] & !0o7777 != 0 {
        return Err(CompatErrno::Invalid);
    }
    let fd = u32::try_from(args[0]).map_err(|_| CompatErrno::BadFd)?;
    proc::linux_fd(pid, fd).ok_or(CompatErrno::BadFd)?;
    Err(CompatErrno::ReadOnly)
}

fn linux_fchmodat(
    pid: ObjId,
    args: [u64; 6],
    fchmodat2: bool,
) -> Result<u64, CompatErrno> {
    if args[2] & !0o7777 != 0 {
        return Err(CompatErrno::Invalid);
    }
    linux_faccessat(
        pid,
        [args[0], args[1], 0, if fchmodat2 { args[3] } else { 0 }, 0, 0],
        fchmodat2,
    )?;
    Err(CompatErrno::ReadOnly)
}

fn valid_compat_owner(owner: u64) -> bool {
    owner == 0 || owner == u32::MAX as u64
}

fn linux_fchown(pid: ObjId, args: [u64; 6]) -> Result<u64, CompatErrno> {
    if !valid_compat_owner(args[1]) || !valid_compat_owner(args[2]) {
        return Err(CompatErrno::Perm);
    }
    let fd = u32::try_from(args[0]).map_err(|_| CompatErrno::BadFd)?;
    proc::linux_fd(pid, fd).ok_or(CompatErrno::BadFd)?;
    Err(CompatErrno::ReadOnly)
}

fn linux_fchownat(pid: ObjId, args: [u64; 6]) -> Result<u64, CompatErrno> {
    if !valid_compat_owner(args[2]) || !valid_compat_owner(args[3]) {
        return Err(CompatErrno::Perm);
    }
    linux_faccessat(
        pid,
        [args[0], args[1], 0, args[4], 0, 0],
        true,
    )?;
    Err(CompatErrno::ReadOnly)
}

fn linux_lchown(pid: ObjId, args: [u64; 6]) -> Result<u64, CompatErrno> {
    if !valid_compat_owner(args[1]) || !valid_compat_owner(args[2]) {
        return Err(CompatErrno::Perm);
    }
    linux_faccessat(
        pid,
        [(-100i64) as u64, args[0], 0, 0, 0, 0],
        false,
    )?;
    Err(CompatErrno::ReadOnly)
}

/// Resolves one pathname relative to an explicit directory fd or AT_FDCWD.
fn resolve_linux_at_path(
    pid: ObjId,
    dirfd: u64,
    address: u64,
) -> Result<alloc::vec::Vec<u8>, CompatErrno> {
    let path = linux_c_string(address, 4096)?;
    if path.starts_with(b"/") {
        return Ok(path);
    }
    if path == b".."
        || path.starts_with(b"../")
        || path.windows(4).any(|window| window == b"/../")
    {
        return Err(CompatErrno::Invalid);
    }
    let base = if is_at_fdcwd(dirfd) {
        proc::linux_cwd(pid).ok_or(CompatErrno::NoSys)?.path().to_vec()
    } else {
        let fd = u32::try_from(dirfd).map_err(|_| CompatErrno::BadFd)?;
        if let Some(crate::linux_vfs::Node::Directory(directory)) =
            proc::linux_path_node(pid, fd)
        {
            directory.path().to_vec()
        } else {
            let (handle, _) = proc::linux_dir_state(pid, fd).ok_or(CompatErrno::NotDirectory)?;
            if let Some(path) = linux_cache_dir_path(handle) {
                path
            } else {
                crate::linux_vfs::DirectoryId::from_handle(handle)
                    .ok_or(CompatErrno::BadFd)?
                    .path()
                    .to_vec()
            }
        }
    };
    if path == b"." {
        return Ok(base);
    }
    let mut resolved = alloc::vec::Vec::with_capacity(base.len() + path.len() + 1);
    resolved.extend_from_slice(&base);
    if !base.ends_with(b"/") {
        resolved.push(b'/');
    }
    resolved.extend_from_slice(&path);
    Ok(resolved)
}

/// Returns the parent directory path for one resolved absolute path.
fn linux_parent_path(path: &[u8]) -> Option<alloc::vec::Vec<u8>> {
    if path == b"/" {
        return None;
    }
    let path = path.strip_suffix(b"/").unwrap_or(path);
    let slash = path.iter().rposition(|byte| *byte == b'/')?;
    if slash == 0 {
        Some(b"/".to_vec())
    } else {
        Some(path[..slash].to_vec())
    }
}

/// Validates a new path's parent and reports whether the target already exists.
fn validate_linux_creation_path(
    pid: ObjId,
    dirfd: u64,
    address: u64,
) -> Result<bool, CompatErrno> {
    let path = resolve_linux_at_path(pid, dirfd, address)?;
    let exists = crate::linux_vfs::lookup_node(&path).is_some();
    let parent = linux_parent_path(&path).ok_or(CompatErrno::Exists)?;
    let node = crate::linux_vfs::lookup_node(&parent).ok_or(CompatErrno::NoEntry)?;
    if !node.is_directory() {
        return Err(CompatErrno::NotDirectory);
    }
    Ok(exists)
}

/// Validates an existing pathname in the compatibility namespace.
fn validate_linux_existing_path(
    pid: ObjId,
    dirfd: u64,
    address: u64,
) -> Result<crate::linux_vfs::Node, CompatErrno> {
    let path = resolve_linux_at_path(pid, dirfd, address)?;
    crate::linux_vfs::lookup_node(&path).ok_or(CompatErrno::NoEntry)
}

/// Implements `mkdirat(2)` against the immutable compatibility root.
fn linux_mkdirat(pid: ObjId, args: [u64; 6]) -> Result<u64, CompatErrno> {
    if args[2] & !0o7777 != 0 {
        return Err(CompatErrno::Invalid);
    }
    let path = resolve_linux_at_path(pid, args[0], args[1])?;
    if linux_cache_path(&path) {
        linux_cache_create_dir(&path)?;
        return Ok(0);
    }
    if validate_linux_creation_path(pid, args[0], args[1])? {
        return Err(CompatErrno::Exists);
    }
    Err(CompatErrno::ReadOnly)
}

/// Implements `mknodat(2)` against the immutable compatibility root.
fn linux_mknodat(pid: ObjId, args: [u64; 6]) -> Result<u64, CompatErrno> {
    if validate_linux_creation_path(pid, args[0], args[1])? {
        return Err(CompatErrno::Exists);
    }
    Err(CompatErrno::ReadOnly)
}

/// Implements `unlinkat(2)` and validates directory/removal type.
fn linux_unlinkat(pid: ObjId, args: [u64; 6]) -> Result<u64, CompatErrno> {
    const AT_REMOVEDIR: u64 = 0x200;
    if args[2] & !AT_REMOVEDIR != 0 {
        return Err(CompatErrno::Invalid);
    }
    let path = resolve_linux_at_path(pid, args[0], args[1])?;
    if linux_cache_path(&path) {
        linux_cache_unlink(&path, args[2] & AT_REMOVEDIR != 0)?;
        return Ok(0);
    }
    let node = validate_linux_existing_path(pid, args[0], args[1])?;
    if args[2] & AT_REMOVEDIR != 0 && !node.is_directory() {
        return Err(CompatErrno::NotDirectory);
    }
    if args[2] & AT_REMOVEDIR == 0 && node.is_directory() {
        return Err(CompatErrno::IsDirectory);
    }
    Err(CompatErrno::ReadOnly)
}

/// Implements `renameat(2)` with source and destination parent validation.
fn linux_renameat(pid: ObjId, args: [u64; 6]) -> Result<u64, CompatErrno> {
    let old_path = resolve_linux_at_path(pid, args[0], args[1])?;
    let new_path = resolve_linux_at_path(pid, args[2], args[3])?;
    if linux_cache_path(&old_path) || linux_cache_path(&new_path) {
        if !linux_cache_path(&old_path) || !linux_cache_path(&new_path) {
            return Err(CompatErrno::CrossDevice);
        }
        linux_cache_rename(&old_path, &new_path)?;
        return Ok(0);
    }
    validate_linux_existing_path(pid, args[0], args[1])?;
    validate_linux_creation_path(pid, args[2], args[3])?;
    Err(CompatErrno::ReadOnly)
}

/// Implements `renameat2(2)` and rejects flags that need mutable-filesystem support.
fn linux_renameat2(pid: ObjId, args: [u64; 6]) -> Result<u64, CompatErrno> {
    if args[4] != 0 {
        return Err(CompatErrno::NotSupported);
    }
    linux_renameat(pid, [args[0], args[1], args[2], args[3], 0, 0])
}

/// Implements `linkat(2)` against the immutable compatibility root.
fn linux_linkat(pid: ObjId, args: [u64; 6]) -> Result<u64, CompatErrno> {
    const AT_SYMLINK_FOLLOW: u64 = 0x400;
    if args[4] & !AT_SYMLINK_FOLLOW != 0 {
        return Err(CompatErrno::Invalid);
    }
    let node = validate_linux_existing_path(pid, args[0], args[1])?;
    if node.is_directory() {
        return Err(CompatErrno::Perm);
    }
    if validate_linux_creation_path(pid, args[2], args[3])? {
        return Err(CompatErrno::Exists);
    }
    Err(CompatErrno::ReadOnly)
}

/// Implements `symlinkat(2)` after validating the destination parent and target string.
fn linux_symlinkat(pid: ObjId, args: [u64; 6]) -> Result<u64, CompatErrno> {
    let _target = linux_c_string(args[0], 4096)?;
    if validate_linux_creation_path(pid, args[1], args[2])? {
        return Err(CompatErrno::Exists);
    }
    Err(CompatErrno::ReadOnly)
}

/// Implements process-local `umask(2)`.
fn linux_umask(pid: ObjId, requested: u64) -> Result<u64, CompatErrno> {
    let old = proc::linux_umask(pid).ok_or(CompatErrno::NoProcess)?;
    if !proc::set_linux_umask(pid, requested as u32) {
        return Err(CompatErrno::NoProcess);
    }
    Ok(u64::from(old))
}

/// Validates one xattr pathname and optional symlink-follow policy.
fn validate_xattr_path(
    pid: ObjId,
    path: u64,
    nofollow: bool,
) -> Result<(), CompatErrno> {
    linux_faccessat(
        pid,
        [
            (-100i64) as u64,
            path,
            0,
            if nofollow { 0x100 } else { 0 },
            0,
            0,
        ],
        true,
    )?;
    Ok(())
}

/// Validates a non-empty bounded xattr name.
fn validate_xattr_name(address: u64) -> Result<(), CompatErrno> {
    if linux_c_string(address, 255)?.is_empty() {
        return Err(CompatErrno::Invalid);
    }
    Ok(())
}

/// Validates an xattr file descriptor.
fn validate_xattr_fd(pid: ObjId, raw_fd: u64) -> Result<u32, CompatErrno> {
    let fd = u32::try_from(raw_fd).map_err(|_| CompatErrno::BadFd)?;
    proc::linux_fd(pid, fd).ok_or(CompatErrno::BadFd)?;
    Ok(fd)
}

/// Implements path and fd variants of `setxattr(2)`.
fn linux_setxattr(
    pid: ObjId,
    args: [u64; 6],
    fd: bool,
    nofollow: bool,
) -> Result<u64, CompatErrno> {
    const XATTR_CREATE: u64 = 0x1;
    const XATTR_REPLACE: u64 = 0x2;
    let name = args[1];
    let value = args[2];
    let size = args[3];
    let flags = args[4];
    if flags & !(XATTR_CREATE | XATTR_REPLACE) != 0
        || flags & XATTR_CREATE != 0 && flags & XATTR_REPLACE != 0
    {
        return Err(CompatErrno::Invalid);
    }
    validate_xattr_name(name)?;
    if size != 0 && value == 0 {
        return Err(CompatErrno::Fault);
    }
    if fd {
        validate_xattr_fd(pid, args[0])?;
    } else {
        validate_xattr_path(pid, args[0], nofollow)?;
    }
    Err(CompatErrno::ReadOnly)
}

/// Implements path and fd variants of `getxattr(2)` over a namespace with no xattrs.
fn linux_getxattr(
    pid: ObjId,
    args: [u64; 6],
    fd: bool,
    nofollow: bool,
) -> Result<u64, CompatErrno> {
    let name = args[1];
    validate_xattr_name(name)?;
    if fd {
        validate_xattr_fd(pid, args[0])?;
    } else {
        validate_xattr_path(pid, args[0], nofollow)?;
    }
    Err(CompatErrno::NoData)
}

/// Implements path and fd variants of `listxattr(2)` over a namespace with no xattrs.
fn linux_listxattr(
    pid: ObjId,
    args: [u64; 6],
    fd: bool,
    nofollow: bool,
) -> Result<u64, CompatErrno> {
    let list = args[1];
    let size = args[2];
    if fd {
        validate_xattr_fd(pid, args[0])?;
    } else {
        validate_xattr_path(pid, args[0], nofollow)?;
    }
    if size != 0 && list == 0 {
        return Err(CompatErrno::Fault);
    }
    Ok(0)
}

/// Implements path and fd variants of `removexattr(2)` over a namespace with no xattrs.
fn linux_removexattr(
    pid: ObjId,
    args: [u64; 6],
    fd: bool,
    nofollow: bool,
) -> Result<u64, CompatErrno> {
    let name = args[1];
    validate_xattr_name(name)?;
    if fd {
        validate_xattr_fd(pid, args[0])?;
    } else {
        validate_xattr_path(pid, args[0], nofollow)?;
    }
    Err(CompatErrno::NoData)
}

/// Validates the dfd/path target used by the xattrat family.
fn validate_xattrat_target(
    pid: ObjId,
    dfd: u64,
    path: u64,
    at_flags: u64,
) -> Result<(), CompatErrno> {
    const AT_SYMLINK_NOFOLLOW: u64 = 0x100;
    const AT_EMPTY_PATH: u64 = 0x1000;
    if at_flags & !(AT_SYMLINK_NOFOLLOW | AT_EMPTY_PATH) != 0 {
        return Err(CompatErrno::Invalid);
    }
    if at_flags & AT_EMPTY_PATH != 0 {
        let fd = u32::try_from(dfd).map_err(|_| CompatErrno::BadFd)?;
        proc::linux_fd(pid, fd).ok_or(CompatErrno::BadFd)?;
        return Ok(());
    }
    let resolved = resolve_linux_at_path(pid, dfd, path)?;
    crate::linux_vfs::lookup_node(&resolved).ok_or(CompatErrno::NoEntry)?;
    Ok(())
}

/// Reads one fixed-version `struct xattr_args`.
fn read_xattr_args(address: u64, size: u64) -> Result<(u64, u32, u32), CompatErrno> {
    const XATTR_ARGS_SIZE: usize = 16;
    if size < XATTR_ARGS_SIZE as u64 || size > 4096 || address == 0 {
        return Err(CompatErrno::Invalid);
    }
    let mut raw = [0u8; XATTR_ARGS_SIZE];
    copy_from_user(&mut raw, address, XATTR_ARGS_SIZE).map_err(|_| CompatErrno::Fault)?;
    Ok((
        u64::from_le_bytes(raw[0..8].try_into().unwrap()),
        u32::from_le_bytes(raw[8..12].try_into().unwrap()),
        u32::from_le_bytes(raw[12..16].try_into().unwrap()),
    ))
}

/// Implements `setxattrat(2)` against the immutable compatibility root.
fn linux_setxattrat(pid: ObjId, args: [u64; 6]) -> Result<u64, CompatErrno> {
    let (value, size, flags) = read_xattr_args(args[4], args[5])?;
    validate_xattr_name(args[3])?;
    validate_xattrat_target(pid, args[0], args[1], args[2])?;
    if flags & !0x3 != 0 || flags & 0x3 == 0x3 {
        return Err(CompatErrno::Invalid);
    }
    if size != 0 && value == 0 {
        return Err(CompatErrno::Fault);
    }
    Err(CompatErrno::ReadOnly)
}

/// Implements `getxattrat(2)` over a namespace with no xattrs.
fn linux_getxattrat(pid: ObjId, args: [u64; 6]) -> Result<u64, CompatErrno> {
    let (_value, _size, flags) = read_xattr_args(args[4], args[5])?;
    if flags != 0 {
        return Err(CompatErrno::Invalid);
    }
    validate_xattr_name(args[3])?;
    validate_xattrat_target(pid, args[0], args[1], args[2])?;
    Err(CompatErrno::NoData)
}

/// Implements `listxattrat(2)` over a namespace with no xattrs.
fn linux_listxattrat(pid: ObjId, args: [u64; 6]) -> Result<u64, CompatErrno> {
    validate_xattrat_target(pid, args[0], args[1], args[2])?;
    if args[4] != 0 && args[3] == 0 {
        return Err(CompatErrno::Fault);
    }
    Ok(0)
}

/// Implements `removexattrat(2)` over a namespace with no xattrs.
fn linux_removexattrat(pid: ObjId, args: [u64; 6]) -> Result<u64, CompatErrno> {
    validate_xattr_name(args[3])?;
    validate_xattrat_target(pid, args[0], args[1], args[2])?;
    Err(CompatErrno::NoData)
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
    if entry.kind == compat_core::fd::CompatKind::Path {
        let node = proc::linux_path_node(pid, fd).ok_or(CompatErrno::BadFd)?;
        write_linux_stat(args[1], node)?;
        return Ok(0);
    }
    if entry.kind == compat_core::fd::CompatKind::Device {
        let (size, regular) = proc::linux_ashmem_state(pid, entry.handle)
            .map(|(size, _, _)| {
                (
                    size,
                    proc::linux_ashmem_is_regular(pid, entry.handle).unwrap_or(false),
                )
            })
            .unwrap_or((0, false));
        write_synthetic_stat(
            args[1],
            entry.handle,
            1,
            size,
            if regular { 0o100600 } else { 0o020666 },
        )?;
        return Ok(0);
    }
    if entry.handle == LINUX_PROC_MAPS_HANDLE {
        let size = proc::linux_proc_maps(pid)
            .map(|maps| maps.len() as u64)
            .unwrap_or(0);
        write_synthetic_stat(args[1], entry.handle, 1, size, 0o100444)?;
        return Ok(0);
    }
    if entry.handle == LINUX_PROC_STAT_HANDLE {
        let size = proc::linux_proc_stat(pid)
            .map(|stat| stat.len() as u64)
            .unwrap_or(0);
        write_synthetic_stat(args[1], entry.handle, 1, size, 0o100444)?;
        return Ok(0);
    }
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
            if entry.kind == compat_core::fd::CompatKind::Device {
                let (size, regular) = proc::linux_ashmem_state(pid, entry.handle)
                    .map(|(size, _, _)| {
                        (
                            size,
                            proc::linux_ashmem_is_regular(pid, entry.handle).unwrap_or(false),
                        )
                    })
                    .unwrap_or((0, false));
                write_synthetic_stat(
                    args[2],
                    entry.handle,
                    1,
                    size,
                    if regular { 0o100600 } else { 0o020666 },
                )?;
                return Ok(0);
            }
            let node = if entry.kind == compat_core::fd::CompatKind::Path {
                proc::linux_path_node(pid, fd)
            } else {
                crate::linux_vfs::FileId::from_handle(entry.handle)
                    .map(crate::linux_vfs::Node::File)
                    .or_else(|| {
                        crate::linux_vfs::DirectoryId::from_handle(entry.handle)
                            .map(crate::linux_vfs::Node::Directory)
                    })
            }
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
                    if let Some(crate::linux_vfs::Node::Directory(directory)) =
                        proc::linux_path_node(pid, fd)
                    {
                        directory.path()
                    } else {
                        let (handle, _) =
                            proc::linux_dir_state(pid, fd).ok_or(CompatErrno::NotDirectory)?;
                        crate::linux_vfs::DirectoryId::from_handle(handle)
                            .ok_or(CompatErrno::BadFd)?
                            .path()
                    }
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
            if entry.kind == compat_core::fd::CompatKind::Device {
                let (size, regular) = proc::linux_ashmem_state(pid, entry.handle)
                    .map(|(size, _, _)| {
                        (
                            size,
                            proc::linux_ashmem_is_regular(pid, entry.handle).unwrap_or(false),
                        )
                    })
                    .unwrap_or((0, false));
                write_synthetic_statx(
                    args[4],
                    entry.handle,
                    1,
                    size,
                    if regular { 0o100600 } else { 0o020666 },
                )?;
                return Ok(0);
            }
            if let Some(node) = proc::linux_path_node(pid, fd) {
                (
                    node,
                    if node.is_directory() {
                        4096
                    } else {
                        node.stat_metadata().0
                    },
                )
            } else if let Some(file) = crate::linux_vfs::FileId::from_handle(entry.handle) {
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
fn linux_flock(pid: ObjId, args: [u64; 6]) -> Result<u64, CompatErrno> {
    const LOCK_SH: u64 = 0x1;
    const LOCK_EX: u64 = 0x2;
    const LOCK_NB: u64 = 0x4;
    const LOCK_UN: u64 = 0x8;
    let fd = u32::try_from(args[0]).map_err(|_| CompatErrno::BadFd)?;
    let operation = args[1];
    if operation & !(LOCK_SH | LOCK_EX | LOCK_NB | LOCK_UN) != 0
        || [LOCK_SH, LOCK_EX, LOCK_UN]
            .iter()
            .filter(|flag| operation & **flag != 0)
            .count()
            != 1
    {
        return Err(CompatErrno::Invalid);
    }
    let entry = proc::linux_fd(pid, fd).ok_or(CompatErrno::BadFd)?;
    if entry.kind != compat_core::fd::CompatKind::File
        && (entry.kind != compat_core::fd::CompatKind::Device
            || proc::linux_ashmem_state(pid, entry.handle).is_none())
    {
        return Err(CompatErrno::BadFd);
    }
    let (backing, owner) = proc::linux_file_lock_key(pid, fd).ok_or(CompatErrno::BadFd)?;
    let exclusive = operation & LOCK_EX != 0;
    let task = sched::current().0;
    let mut registered = false;
    loop {
        let mut wake = [crate::task::TaskId(0); MAX_FLOCK_LOCKS];
        let mut wake_count = 0usize;
        let acquired = {
            let mut state = COMPAT.lock();
            let conflict = state.flock_locks.iter().flatten().any(|lock| {
                lock.backing == backing
                    && lock.owner != owner
                    && (exclusive || lock.exclusive)
            });
            if operation & LOCK_UN != 0 {
                state
                    .flock_locks
                    .iter_mut()
                    .filter(|lock| {
                        lock.is_some_and(|lock| {
                            lock.backing == backing && lock.owner == owner
                        })
                    })
                    .for_each(|lock| *lock = None);
                for waiter in state.flock_waiters.iter_mut().flatten() {
                    wake[wake_count] = waiter.task;
                    wake_count += 1;
                }
                state.flock_waiters.fill(None);
                drop(state);
                for task in wake[..wake_count].iter().copied() {
                    sched::wake(task);
                }
                return Ok(0);
            }
            if !conflict {
                state
                    .flock_locks
                    .iter_mut()
                    .filter(|lock| {
                        lock.is_some_and(|lock| {
                            lock.backing == backing && lock.owner == owner
                        })
                    })
                    .for_each(|lock| *lock = None);
                let Some(slot) = state.flock_locks.iter().position(Option::is_none) else {
                    return Err(CompatErrno::NoSpace);
                };
                state.flock_locks[slot] = Some(FlockLock {
                    backing,
                    owner,
                    exclusive,
                });
                if registered {
                    if let Some(index) = state
                        .flock_waiters
                        .iter()
                        .position(|waiter| waiter.is_some_and(|waiter| waiter.task == task))
                    {
                        state.flock_waiters[index] = None;
                    }
                }
                true
            } else {
                if operation & LOCK_NB != 0 {
                    return Err(CompatErrno::TryAgain);
                }
                if !registered {
                    let Some(slot) = state.flock_waiters.iter().position(Option::is_none) else {
                        return Err(CompatErrno::NoSpace);
                    };
                    state.flock_waiters[slot] = Some(FlockWaiter { task });
                    registered = true;
                }
                false
            }
        };
        if acquired {
            return Ok(0);
        }
        if proc::current_exiting() || current_signal_pending(pid) {
            if registered {
                if let Some(index) = COMPAT
                    .lock()
                    .flock_waiters
                    .iter()
                    .position(|waiter| waiter.is_some_and(|waiter| waiter.task == task))
                {
                    COMPAT.lock().flock_waiters[index] = None;
                }
            }
            return Err(CompatErrno::Interrupted);
        }
        sched::pause();
    }
}

/// Releases flock state after the final descriptor of one open-file
/// description closes and wakes every blocked flock waiter.
pub(crate) fn release_flock_description(owner: u64) {
    let mut tasks = [crate::task::TaskId(0); MAX_FLOCK_LOCKS];
    let mut count = 0usize;
    let mut state = COMPAT.lock();
    state
        .flock_locks
        .iter_mut()
        .filter(|lock| lock.is_some_and(|lock| lock.owner == owner))
        .for_each(|lock| *lock = None);
    if state
        .flock_locks
        .iter()
        .any(|lock| lock.is_some_and(|lock| lock.owner == owner))
    {
        return;
    }
    for waiter in state.flock_waiters.iter_mut().flatten() {
        tasks[count] = waiter.task;
        count += 1;
    }
    state.flock_waiters.fill(None);
    drop(state);
    for task in tasks[..count].iter().copied() {
        sched::wake(task);
    }
}

fn linux_fcntl(pid: ObjId, args: [u64; 6]) -> Result<u64, CompatErrno> {
    const F_DUPFD: u64 = 0;
    const F_DUPFD_CLOEXEC: u64 = 1030;
    const F_SETPIPE_SZ: u64 = 1031;
    const F_GETPIPE_SZ: u64 = 1032;
    const F_ADD_SEALS: u64 = 1033;
    const F_GET_SEALS: u64 = 1034;
    const F_GETFD: u64 = 1;
    const F_SETFD: u64 = 2;
    const F_GETFL: u64 = 3;
    const F_SETFL: u64 = 4;
    const FD_CLOEXEC: u64 = 1;
    const O_NONBLOCK: u64 = 0x800;
    const O_DIRECTORY: u64 = 0x10000;
    const O_PATH: u64 = 0x20_0000;
    let fd = u32::try_from(args[0]).map_err(|_| CompatErrno::BadFd)?;
    let entry = proc::linux_fd(pid, fd).ok_or(CompatErrno::BadFd)?;
    match args[1] {
        F_GETFD => Ok(u64::from(entry.close_on_exec)),
        F_GETFL => {
            let status = u64::from(proc::linux_fd_status_flags(pid, fd).ok_or(CompatErrno::BadFd)?);
            let path_node = proc::linux_path_node(pid, fd);
            Ok(status
                | if entry.kind == compat_core::fd::CompatKind::Directory
                    || path_node.is_some_and(|node| node.is_directory())
                {
                    O_DIRECTORY
                } else {
                    0
                }
                | if path_node.is_some() { O_PATH } else { 0 })
        }
        F_SETFL if args[2] & !O_NONBLOCK == 0 => {
            if entry.kind == compat_core::fd::CompatKind::Path {
                return Err(CompatErrno::Invalid);
            }
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
        F_GETPIPE_SZ => {
            if entry.kind != compat_core::fd::CompatKind::Pipe {
                return Err(CompatErrno::Invalid);
            }
            proc::linux_pipe_endpoint(pid, entry.handle)
                .map(|pipe| pipe.capacity() as u64)
                .ok_or(CompatErrno::BadFd)
        }
        F_SETPIPE_SZ => {
            if entry.kind != compat_core::fd::CompatKind::Pipe {
                return Err(CompatErrno::Invalid);
            }
            let page = kernel_core::frame::FRAME_SIZE as u64;
            let requested = args[2];
            if requested == 0 || requested > compat_core::pipe::PIPE_CAPACITY as u64 {
                return Err(CompatErrno::Perm);
            }
            let rounded = requested.div_ceil(page) * page;
            let pipe = proc::linux_pipe_endpoint(pid, entry.handle).ok_or(CompatErrno::BadFd)?;
            if !pipe.set_capacity(rounded as usize) {
                return Err(CompatErrno::Busy);
            }
            Ok(pipe.capacity() as u64)
        }
        F_ADD_SEALS => {
            let seals = u32::try_from(args[2]).map_err(|_| CompatErrno::Invalid)?;
            proc::linux_ashmem_add_seals(pid, entry.handle, seals)
                .map(|_| 0)
                .map_err(ashmem_compat_error)
        }
        F_GET_SEALS => proc::linux_ashmem_get_seals(pid, entry.handle)
            .map(u64::from)
            .ok_or(CompatErrno::Invalid),
        F_SETFD | F_SETFL => Err(CompatErrno::Invalid),
        _ => Err(CompatErrno::NoSys),
    }
}

/// Implements the terminal-probing subset of `ioctl(2)`.
///
/// 当前标准流不是 TerminalSession；常见 TTY 查询明确返回 `ENOTTY`，其他设备
/// 控制请求返回 `ENOSYS`，不会把普通控制台描述符伪装成终端。
fn fsverity_file_bytes(pid: ObjId, fd: u32) -> Result<alloc::vec::Vec<u8>, CompatErrno> {
    const MAX_VERITY_BYTES: u64 = 64 * 1024 * 1024;
    let entry = proc::linux_fd(pid, fd).ok_or(CompatErrno::BadFd)?;
    if entry.kind == compat_core::fd::CompatKind::Device
        && proc::linux_ashmem_is_regular(pid, entry.handle) == Some(true)
    {
        let (size, _, _) = proc::linux_ashmem_state(pid, entry.handle)
            .ok_or(CompatErrno::BadFd)?;
        if size > MAX_VERITY_BYTES {
            return Err(CompatErrno::NoMemory);
        }
        let mut bytes = alloc::vec![0u8; size as usize];
        let read = proc::linux_ashmem_read_from(pid, entry.handle, 0, &mut bytes)
            .map_err(ashmem_compat_error)?;
        bytes.truncate(read);
        return Ok(bytes);
    }
    if entry.kind == compat_core::fd::CompatKind::File {
        let (handle, _) = proc::linux_file_state(pid, fd).ok_or(CompatErrno::BadFd)?;
        let file = crate::linux_vfs::FileId::from_handle(handle)
            .ok_or(CompatErrno::BadFd)?;
        return Ok(file.bytes().to_vec());
    }
    Err(CompatErrno::NotTty)
}

fn fsverity_sha256_block(salt: &[u8], block: &[u8]) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(salt);
    hash.update(block);
    hash.finalize().into()
}

/// Builds the SHA-256 Merkle root and fs-verity descriptor. The descriptor is
/// the value returned by FS_IOC_MEASURE_VERITY's file digest.
fn fsverity_descriptor(
    data: &[u8],
    salt: &[u8],
) -> Result<([u8; 256], [u8; 32]), CompatErrno> {
    const BLOCK: usize = 4096;
    let mut level = alloc::vec::Vec::new();
    let blocks = data.len().div_ceil(BLOCK).max(1);
    level
        .try_reserve_exact(blocks)
        .map_err(|_| CompatErrno::NoMemory)?;
    for index in 0..blocks {
        let start = index.saturating_mul(BLOCK);
        let end = data.len().min(start.saturating_add(BLOCK));
        let mut block = [0u8; BLOCK];
        if start < end {
            block[..end - start].copy_from_slice(&data[start..end]);
        }
        level.push(fsverity_sha256_block(salt, &block));
    }
    while level.len() > 1 {
        let mut next = alloc::vec::Vec::new();
        next.try_reserve_exact(level.len().div_ceil(BLOCK / 32))
            .map_err(|_| CompatErrno::NoMemory)?;
        for children in level.chunks(BLOCK / 32) {
            let mut block = [0u8; BLOCK];
            for (index, child) in children.iter().enumerate() {
                block[index * 32..index * 32 + 32].copy_from_slice(child);
            }
            next.push(fsverity_sha256_block(salt, &block));
        }
        level = next;
    }
    let root = level.first().copied().ok_or(CompatErrno::NoMemory)?;
    let mut descriptor = [0u8; 256];
    descriptor[0] = 1;
    descriptor[1] = 1;
    descriptor[2] = 12;
    descriptor[3] = salt.len() as u8;
    descriptor[8..16].copy_from_slice(&(data.len() as u64).to_le_bytes());
    descriptor[16..48].copy_from_slice(&root);
    descriptor[48..48 + salt.len()].copy_from_slice(salt);
    let digest: [u8; 32] = Sha256::digest(descriptor).into();
    Ok((descriptor, digest))
}

fn linux_fsverity_enable(pid: ObjId, fd: u32, request: u64) -> Result<u64, CompatErrno> {
    const ARG_BYTES: usize = 128;
    let entry = proc::linux_fd(pid, fd).ok_or(CompatErrno::BadFd)?;
    if entry.kind != compat_core::fd::CompatKind::Device
        || proc::linux_ashmem_is_regular(pid, entry.handle) != Some(true)
    {
        return if entry.kind == compat_core::fd::CompatKind::File {
            Err(CompatErrno::ReadOnly)
        } else {
            Err(CompatErrno::NotTty)
        };
    }
    let mut raw = [0u8; ARG_BYTES];
    copy_from_user(&mut raw, request, ARG_BYTES).map_err(|_| CompatErrno::Fault)?;
    let version = u32::from_le_bytes(raw[0..4].try_into().unwrap());
    let algorithm = u32::from_le_bytes(raw[4..8].try_into().unwrap());
    let block_size = u32::from_le_bytes(raw[8..12].try_into().unwrap());
    let salt_size = u32::from_le_bytes(raw[12..16].try_into().unwrap());
    let salt_ptr = u64::from_le_bytes(raw[16..24].try_into().unwrap());
    let signature_size = u32::from_le_bytes(raw[24..28].try_into().unwrap());
    if version != 1
        || algorithm != 1
        || !block_size.is_power_of_two()
        || !(4096..=65536).contains(&block_size)
        || salt_size > 32
        || signature_size != 0
        || raw[28..].iter().any(|byte| *byte != 0)
    {
        return Err(CompatErrno::Invalid);
    }
    let mut salt = [0u8; 32];
    if salt_size != 0 {
        copy_from_user(&mut salt[..salt_size as usize], salt_ptr, salt_size as usize)
            .map_err(|_| CompatErrno::Fault)?;
    }
    let data = fsverity_file_bytes(pid, fd)?;
    let (descriptor, digest) =
        fsverity_descriptor(&data, &salt[..salt_size as usize])?;
    if proc::linux_ashmem_set_verity(pid, entry.handle, digest, descriptor) {
        Ok(0)
    } else {
        Err(CompatErrno::NoMemory)
    }
}

fn linux_fsverity_measure(pid: ObjId, fd: u32, request: u64) -> Result<u64, CompatErrno> {
    let mut header = [0u8; 4];
    copy_from_user(&mut header, request, 4).map_err(|_| CompatErrno::Fault)?;
    let algorithm = u16::from_le_bytes(header[0..2].try_into().unwrap());
    let capacity = u16::from_le_bytes(header[2..4].try_into().unwrap());
    if algorithm != 0 && algorithm != 1 {
        return Err(CompatErrno::NotSupported);
    }
    if capacity < 32 {
        return Err(CompatErrno::Overflow);
    }
    let entry = proc::linux_fd(pid, fd).ok_or(CompatErrno::BadFd)?;
    let (enabled, digest, _) = proc::linux_ashmem_verity_state(pid, entry.handle)
        .ok_or(CompatErrno::NoData)?;
    if !enabled {
        return Err(CompatErrno::NoData);
    }
    let mut output = [0u8; 36];
    output[0..2].copy_from_slice(&1u16.to_le_bytes());
    output[2..4].copy_from_slice(&32u16.to_le_bytes());
    output[4..36].copy_from_slice(&digest);
    copy_to_user(request, &output, output.len()).map_err(|_| CompatErrno::Fault)?;
    Ok(0)
}

fn linux_fsverity_read_metadata(
    pid: ObjId,
    fd: u32,
    request: u64,
) -> Result<u64, CompatErrno> {
    let mut raw = [0u8; 40];
    copy_from_user(&mut raw, request, 40).map_err(|_| CompatErrno::Fault)?;
    let metadata_type = u64::from_le_bytes(raw[0..8].try_into().unwrap());
    let offset = usize::try_from(u64::from_le_bytes(raw[8..16].try_into().unwrap()))
        .map_err(|_| CompatErrno::Overflow)?;
    let length =
        usize::try_from(u64::from_le_bytes(raw[16..24].try_into().unwrap()))
            .map_err(|_| CompatErrno::Overflow)?;
    let buffer = u64::from_le_bytes(raw[24..32].try_into().unwrap());
    let reserved = u64::from_le_bytes(raw[32..40].try_into().unwrap());
    offset
        .checked_add(length)
        .ok_or(CompatErrno::Overflow)?;
    if reserved != 0 {
        return Err(CompatErrno::Invalid);
    }
    if metadata_type != 2 {
        return Err(CompatErrno::NoData);
    }
    let entry = proc::linux_fd(pid, fd).ok_or(CompatErrno::BadFd)?;
    let (enabled, _, descriptor) = proc::linux_ashmem_verity_state(pid, entry.handle)
        .ok_or(CompatErrno::NoData)?;
    if !enabled {
        return Err(CompatErrno::NoData);
    }
    let start = offset.min(descriptor.len());
    let count = length.min(descriptor.len().saturating_sub(start));
    if count != 0 {
        copy_to_user(buffer, &descriptor[start..start + count], count)
            .map_err(|_| CompatErrno::Fault)?;
    }
    Ok(count as u64)
}

fn fscrypt_compat_error(error: crate::fscrypt::FscryptError) -> CompatErrno {
    match error {
        crate::fscrypt::FscryptError::Invalid => CompatErrno::Invalid,
        crate::fscrypt::FscryptError::Permission => CompatErrno::Access,
        crate::fscrypt::FscryptError::NoKey => CompatErrno::NoKey,
        crate::fscrypt::FscryptError::NoSpace => CompatErrno::NoSpace,
    }
}

fn fscrypt_ashmem_error(error: proc::LinuxAshmemError) -> CompatErrno {
    match error {
        proc::LinuxAshmemError::Invalid => CompatErrno::Invalid,
        proc::LinuxAshmemError::Permission => CompatErrno::Access,
        proc::LinuxAshmemError::Busy => CompatErrno::Busy,
        proc::LinuxAshmemError::NoMemory => CompatErrno::NoMemory,
        proc::LinuxAshmemError::NotAshmem => CompatErrno::NotTty,
        proc::LinuxAshmemError::Exists => CompatErrno::Exists,
        proc::LinuxAshmemError::NoKey => CompatErrno::NoKey,
        proc::LinuxAshmemError::NotSupported => CompatErrno::NotSupported,
    }
}

fn parse_fscrypt_key_specifier(
    raw: &[u8],
) -> Result<crate::fscrypt::KeySpecifier, CompatErrno> {
    if raw.len() < 40 {
        return Err(CompatErrno::Invalid);
    }
    let kind = u32::from_le_bytes(raw[..4].try_into().unwrap());
    let reserved = u32::from_le_bytes(raw[4..8].try_into().unwrap());
    if reserved != 0 {
        return Err(CompatErrno::Invalid);
    }
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(&raw[8..40]);
    let spec = crate::fscrypt::KeySpecifier { kind, bytes };
    spec.is_valid()
        .then_some(spec)
        .ok_or(CompatErrno::Invalid)
}

fn parse_fscrypt_policy(raw: &[u8]) -> Result<crate::fscrypt::Policy, CompatErrno> {
    let version = *raw.first().ok_or(CompatErrno::Invalid)?;
    let policy = match version {
        0 => {
            if raw.len() < 12 {
                return Err(CompatErrno::Invalid);
            }
            let mut descriptor = [0u8; 8];
            descriptor.copy_from_slice(&raw[4..12]);
            crate::fscrypt::Policy::V1 {
                contents_mode: raw[1],
                filenames_mode: raw[2],
                flags: raw[3],
                descriptor,
            }
        }
        2 => {
            if raw.len() < 24 || raw[5..8].iter().any(|byte| *byte != 0) {
                return Err(CompatErrno::Invalid);
            }
            let mut identifier = [0u8; 16];
            identifier.copy_from_slice(&raw[8..24]);
            crate::fscrypt::Policy::V2 {
                contents_mode: raw[1],
                filenames_mode: raw[2],
                flags: raw[3],
                log2_data_unit_size: raw[4],
                identifier,
            }
        }
        _ => return Err(CompatErrno::Invalid),
    };
    policy.validate().map_err(fscrypt_compat_error)?;
    Ok(policy)
}

fn encode_fscrypt_policy(policy: crate::fscrypt::Policy) -> alloc::vec::Vec<u8> {
    match policy {
        crate::fscrypt::Policy::V1 {
            contents_mode,
            filenames_mode,
            flags,
            descriptor,
        } => {
            let mut raw = alloc::vec![0u8; 12];
            raw[0] = 0;
            raw[1] = contents_mode;
            raw[2] = filenames_mode;
            raw[3] = flags;
            raw[4..12].copy_from_slice(&descriptor);
            raw
        }
        crate::fscrypt::Policy::V2 {
            contents_mode,
            filenames_mode,
            flags,
            log2_data_unit_size,
            identifier,
        } => {
            let mut raw = alloc::vec![0u8; 24];
            raw[0] = 2;
            raw[1] = contents_mode;
            raw[2] = filenames_mode;
            raw[3] = flags;
            raw[4] = log2_data_unit_size;
            raw[8..24].copy_from_slice(&identifier);
            raw
        }
    }
}

fn fscrypt_caller(pid: ObjId) -> Result<(u32, bool), CompatErrno> {
    let credentials = proc::linux_credentials(pid).ok_or(CompatErrno::NoProcess)?;
    let capabilities = proc::linux_capabilities(pid).ok_or(CompatErrno::NoProcess)?;
    Ok((
        credentials.fsuid,
        credentials.euid == 0 || capabilities.effective & (1u64 << 21) != 0,
    ))
}

fn linux_fscrypt_set_policy(pid: ObjId, fd: u32, request: u64) -> Result<u64, CompatErrno> {
    let mut version = [0u8; 1];
    copy_from_user(&mut version, request, 1).map_err(|_| CompatErrno::Fault)?;
    let size = match version[0] {
        0 => 12,
        2 => 24,
        _ => return Err(CompatErrno::Invalid),
    };
    let mut raw = [0u8; 24];
    copy_from_user(&mut raw[..size], request, size).map_err(|_| CompatErrno::Fault)?;
    let policy = parse_fscrypt_policy(&raw[..size])?;
    let entry = proc::linux_fd(pid, fd).ok_or(CompatErrno::BadFd)?;
    let (uid, _) = fscrypt_caller(pid)?;
    proc::linux_ashmem_fscrypt_set_policy(pid, entry.handle, policy, uid)
        .map_err(fscrypt_ashmem_error)?;
    Ok(0)
}

fn linux_fscrypt_get_policy(pid: ObjId, fd: u32, request: u64) -> Result<u64, CompatErrno> {
    let entry = proc::linux_fd(pid, fd).ok_or(CompatErrno::BadFd)?;
    let policy = proc::linux_ashmem_fscrypt_policy(pid, entry.handle)
        .map_err(fscrypt_ashmem_error)?
        .ok_or(CompatErrno::NoData)?;
    if !matches!(policy, crate::fscrypt::Policy::V1 { .. }) {
        return Err(CompatErrno::Invalid);
    }
    let encoded = encode_fscrypt_policy(policy);
    copy_to_user(request, &encoded, encoded.len()).map_err(|_| CompatErrno::Fault)?;
    Ok(0)
}

fn linux_fscrypt_get_policy_ex(
    pid: ObjId,
    fd: u32,
    request: u64,
) -> Result<u64, CompatErrno> {
    let mut capacity = [0u8; 8];
    copy_from_user(&mut capacity, request, 8).map_err(|_| CompatErrno::Fault)?;
    let capacity = usize::try_from(u64::from_le_bytes(capacity))
        .map_err(|_| CompatErrno::Invalid)?;
    let entry = proc::linux_fd(pid, fd).ok_or(CompatErrno::BadFd)?;
    let policy = proc::linux_ashmem_fscrypt_policy(pid, entry.handle)
        .map_err(fscrypt_ashmem_error)?
        .ok_or(CompatErrno::NoData)?;
    let encoded = encode_fscrypt_policy(policy);
    if capacity < encoded.len() {
        return Err(CompatErrno::Overflow);
    }
    let mut output = alloc::vec![0u8; 8 + encoded.len()];
    output[..8].copy_from_slice(&(encoded.len() as u64).to_le_bytes());
    output[8..].copy_from_slice(&encoded);
    copy_to_user(request, &output, output.len()).map_err(|_| CompatErrno::Fault)?;
    Ok(0)
}

fn linux_fscrypt_get_pwsalt(pid: ObjId, fd: u32, request: u64) -> Result<u64, CompatErrno> {
    let entry = proc::linux_fd(pid, fd).ok_or(CompatErrno::BadFd)?;
    let salt = proc::linux_ashmem_fscrypt_pwsalt(pid, entry.handle)
        .map_err(fscrypt_ashmem_error)?;
    copy_to_user(request, &salt, salt.len()).map_err(|_| CompatErrno::Fault)?;
    Ok(0)
}

fn linux_fscrypt_add_key(pid: ObjId, fd: u32, request: u64) -> Result<u64, CompatErrno> {
    const ADD_KEY_BYTES: usize = 80;
    const HW_WRAPPED: u32 = 1;
    const MAX_RAW_KEY: usize = 64;
    let mut raw = [0u8; ADD_KEY_BYTES];
    copy_from_user(&mut raw, request, ADD_KEY_BYTES).map_err(|_| CompatErrno::Fault)?;
    let spec = parse_fscrypt_key_specifier(&raw[..40])?;
    let raw_size =
        usize::try_from(u32::from_le_bytes(raw[40..44].try_into().unwrap()))
            .map_err(|_| CompatErrno::Invalid)?;
    let key_id = u32::from_le_bytes(raw[44..48].try_into().unwrap());
    let flags = u32::from_le_bytes(raw[48..52].try_into().unwrap());
    if raw[52..].iter().any(|byte| *byte != 0) || flags & !HW_WRAPPED != 0 {
        return Err(CompatErrno::Invalid);
    }
    if flags & HW_WRAPPED != 0 {
        return Err(CompatErrno::NotSupported);
    }
    if key_id != 0 {
        return Err(CompatErrno::NoKey);
    }
    if raw_size == 0 || raw_size > MAX_RAW_KEY {
        return Err(CompatErrno::Invalid);
    }
    let entry = proc::linux_fd(pid, fd).ok_or(CompatErrno::BadFd)?;
    if proc::linux_ashmem_is_regular(pid, entry.handle) != Some(true) {
        return Err(CompatErrno::NotSupported);
    }
    let mut key = alloc::vec![0u8; raw_size];
    copy_from_user(&mut key, request + ADD_KEY_BYTES as u64, raw_size)
        .map_err(|_| CompatErrno::Fault)?;
    let (uid, has_sys_admin) = fscrypt_caller(pid)?;
    let returned = crate::fscrypt::add_key(spec, &key, uid, has_sys_admin);
    key.fill(0);
    let returned = returned.map_err(fscrypt_compat_error)?;
    if returned.kind == crate::fscrypt::KEY_SPEC_TYPE_IDENTIFIER {
        copy_to_user(request + 8, &returned.bytes[..16], 16)
            .map_err(|_| CompatErrno::Fault)?;
    }
    Ok(0)
}

fn linux_fscrypt_remove_key(
    pid: ObjId,
    fd: u32,
    request: u64,
    all_users: bool,
) -> Result<u64, CompatErrno> {
    let mut raw = [0u8; 64];
    let request_size = raw.len();
    copy_from_user(&mut raw, request, request_size).map_err(|_| CompatErrno::Fault)?;
    let spec = parse_fscrypt_key_specifier(&raw[..40])?;
    if raw[44..].iter().any(|byte| *byte != 0) {
        return Err(CompatErrno::Invalid);
    }
    let entry = proc::linux_fd(pid, fd).ok_or(CompatErrno::BadFd)?;
    if proc::linux_ashmem_is_regular(pid, entry.handle) != Some(true) {
        return Err(CompatErrno::NotSupported);
    }
    let (uid, has_sys_admin) = fscrypt_caller(pid)?;
    let flags = crate::fscrypt::remove_key(spec, uid, all_users, has_sys_admin)
        .map_err(fscrypt_compat_error)?;
    raw[40..44].copy_from_slice(&flags.to_le_bytes());
    raw[44..].fill(0);
    copy_to_user(request, &raw, raw.len()).map_err(|_| CompatErrno::Fault)?;
    Ok(0)
}

fn linux_fscrypt_key_status(
    pid: ObjId,
    fd: u32,
    request: u64,
) -> Result<u64, CompatErrno> {
    let mut raw = [0u8; 128];
    let request_size = raw.len();
    copy_from_user(&mut raw, request, request_size).map_err(|_| CompatErrno::Fault)?;
    let spec = parse_fscrypt_key_specifier(&raw[..40])?;
    if raw[40..64].iter().any(|byte| *byte != 0) {
        return Err(CompatErrno::Invalid);
    }
    let entry = proc::linux_fd(pid, fd).ok_or(CompatErrno::BadFd)?;
    if proc::linux_ashmem_is_regular(pid, entry.handle) != Some(true) {
        return Err(CompatErrno::NotSupported);
    }
    let (uid, _) = fscrypt_caller(pid)?;
    let (status, status_flags, user_count) = crate::fscrypt::key_status(spec, uid)
        .map_err(fscrypt_compat_error)?;
    raw[64..68].copy_from_slice(&status.to_le_bytes());
    raw[68..72].copy_from_slice(&status_flags.to_le_bytes());
    raw[72..76].copy_from_slice(&user_count.to_le_bytes());
    raw[76..].fill(0);
    copy_to_user(request, &raw, raw.len()).map_err(|_| CompatErrno::Fault)?;
    Ok(0)
}

fn linux_fscrypt_get_nonce(pid: ObjId, fd: u32, request: u64) -> Result<u64, CompatErrno> {
    let entry = proc::linux_fd(pid, fd).ok_or(CompatErrno::BadFd)?;
    let nonce = proc::linux_ashmem_fscrypt_nonce(pid, entry.handle)
        .map_err(fscrypt_ashmem_error)?
        .ok_or(CompatErrno::NoData)?;
    copy_to_user(request, &nonce, nonce.len()).map_err(|_| CompatErrno::Fault)?;
    Ok(0)
}

fn linux_ioctl(pid: ObjId, args: [u64; 6]) -> Result<u64, CompatErrno> {
    // Linux ioctl requests are an unsigned 32-bit command word.  The x86-64
    // ABI leaves the upper half of RSI unspecified for variadic callers, and
    // Go/Clang-generated userspace (including AOSP's Binder tests) commonly
    // sign-extends commands whose direction bit is set.  Normalize exactly as
    // the real ioctl syscall does before dispatching.
    let mut args = args;
    args[1] = u64::from(args[1] as u32);
    const TCGETS: u64 = 0x5401;
    const TCSETS: u64 = 0x5402;
    const TCSETSW: u64 = 0x5403;
    const TCSETSF: u64 = 0x5404;
    const TIOCGWINSZ: u64 = 0x5413;
    const TIOCSWINSZ: u64 = 0x5414;
    const FIONREAD: u64 = 0x541b;
    const FIONBIO: u64 = 0x5421;
    const TCGETS2: u64 = 0x802c_542a;
    const ASHMEM_SET_NAME: u64 = 0x4100_6101;
    const ASHMEM_SET_PROT_MASK: u64 = 0x4004_6102;
    const ASHMEM_SET_SIZE: u64 = 0x4008_6103;
    const ASHMEM_GET_SIZE: u64 = 0x8008_6104;
    const ASHMEM_PIN: u64 = 0x4008_6105;
    const ASHMEM_UNPIN: u64 = 0x4008_6106;
    const ASHMEM_GET_NAME: u64 = 0x8100_6107;
    const ASHMEM_GET_PROT_MASK: u64 = 0x8008_6108;
    const ASHMEM_GET_PIN_STATUS: u64 = 0x6109;
    const ASHMEM_PURGE_ALL_CACHES: u64 = 0x610a;
    const BINDER_SET_MAX_THREADS: u64 = 0x4004_6205;
    const BINDER_SET_IDLE_TIMEOUT: u64 = 0x4008_6203;
    const BINDER_SET_IDLE_PRIORITY: u64 = 0x4004_6206;
    const BINDER_SET_CONTEXT_MGR: u64 = 0x4004_6207;
    const BINDER_SET_CONTEXT_MGR_EXT: u64 = 0x4018_620d;
    const BINDER_THREAD_EXIT: u64 = 0x4004_6208;
    const BINDER_VERSION: u64 = 0xc004_6209;
    const BINDER_WRITE_READ: u64 = 0xc030_6201;
    const BINDER_FREEZE: u64 = 0x400c_620e;
    const BINDER_GET_FROZEN_INFO: u64 = 0xc00c_620f;
    const BINDER_ENABLE_ONEWAY_SPAM_DETECTION: u64 = 0x4004_6210;
    const BINDER_GET_EXTENDED_ERROR: u64 = 0xc00c_6211;
    const FS_IOC_GETFLAGS: u64 = 0x8008_6601;
    const FS_IOC_SETFLAGS: u64 = 0x4008_6602;
    const FS_IOC_ENABLE_VERITY: u64 = 0x4080_6685;
    const FS_IOC_MEASURE_VERITY: u64 = 0xc004_6686;
    const FS_IOC_READ_VERITY_METADATA: u64 = 0xc028_6687;
    const FS_IOC_SET_ENCRYPTION_POLICY: u64 = 0x800c_6613;
    const FS_IOC_GET_ENCRYPTION_PWSALT: u64 = 0x4010_6614;
    const FS_IOC_GET_ENCRYPTION_POLICY: u64 = 0x400c_6615;
    const FS_IOC_GET_ENCRYPTION_POLICY_EX: u64 = 0xc009_6616;
    const FS_IOC_ADD_ENCRYPTION_KEY: u64 = 0xc050_6617;
    const FS_IOC_REMOVE_ENCRYPTION_KEY: u64 = 0xc040_6618;
    const FS_IOC_REMOVE_ENCRYPTION_KEY_ALL_USERS: u64 = 0xc040_6619;
    const FS_IOC_GET_ENCRYPTION_KEY_STATUS: u64 = 0xc080_661a;
    const FS_IOC_GET_ENCRYPTION_NONCE: u64 = 0x8010_661b;
    const ION_IOC_ALLOC: u64 = 0xc020_4900;
    const ION_IOC_FREE: u64 = 0xc004_4901;
    const ION_IOC_MAP: u64 = 0xc008_4902;
    const ION_IOC_SHARE: u64 = 0xc008_4904;
    const ION_IOC_IMPORT: u64 = 0xc008_4905;
    const ION_IOC_SYNC: u64 = 0xc008_4907;
    const DMA_HEAP_IOCTL_ALLOC: u64 = 0xc018_4800;
    const DMA_BUF_IOCTL_SYNC: u64 = 0x4008_6200;
    const DMA_BUF_SET_NAME: u64 = 0x4008_6201;
    const DMA_BUF_IOCTL_EXPORT_SYNC_FILE: u64 = 0xc008_6202;
    const DMA_BUF_IOCTL_IMPORT_SYNC_FILE: u64 = 0x4008_6203;
    const SYNC_IOC_MERGE: u64 = 0xc030_3e03;
    const SYNC_IOC_FILE_INFO: u64 = 0xc038_3e04;
    const SYNC_IOC_SET_DEADLINE: u64 = 0x4010_3e05;
    let fd = u32::try_from(args[0]).map_err(|_| CompatErrno::BadFd)?;
    let entry = proc::linux_fd(pid, fd).ok_or(CompatErrno::BadFd)?;
    if let Some(state) = proc::linux_userfault_state(pid, entry.handle) {
        return linux_userfault_ioctl(pid, state, args[1], args[2]);
    }
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
    if args[1] == FIONBIO {
        let mut raw = [0u8; 4];
        copy_from_user(&mut raw, args[2], 4).map_err(|_| CompatErrno::Fault)?;
        let nonblocking = u32::from_le_bytes(raw) != 0;
        let current = proc::linux_fd_status_flags(pid, fd).ok_or(CompatErrno::BadFd)?;
        let updated = if nonblocking {
            current | 0x800
        } else {
            current & !0x800
        };
        return if proc::linux_set_fd_status_flags(pid, fd, updated) {
            Ok(0)
        } else {
            Err(CompatErrno::BadFd)
        };
    }
    if entry.kind == compat_core::fd::CompatKind::Device
        && proc::linux_is_binder(pid, entry.handle)
    {
        return match args[1] {
            BINDER_VERSION => {
                copy_to_user(args[2], &8i32.to_le_bytes(), 4)
                    .map_err(|_| CompatErrno::Fault)?;
                Ok(0)
            }
            BINDER_SET_MAX_THREADS => {
                let mut raw = [0u8; 4];
                copy_from_user(&mut raw, args[2], 4).map_err(|_| CompatErrno::Fault)?;
                let value = u32::from_le_bytes(raw);
                if value > 64 {
                    return Err(CompatErrno::Invalid);
                }
                if proc::linux_set_binder_max_threads(pid, entry.handle, value) {
                    Ok(0)
                } else {
                    Err(CompatErrno::BadFd)
                }
            }
            BINDER_SET_CONTEXT_MGR => {
                // Android's binder driver normally already has servicemanager
                // installed, so this legacy ioctl reports EBUSY.  Jasper has no
                // separate userspace servicemanager in the verification guest;
                // install the caller as the in-process context manager so the
                // subsequent handle-0 transaction tests retain their meaning,
                // while preserving Android's observable EBUSY result.
                let _ = crate::binder::set_context_manager(pid);
                Err(CompatErrno::Busy)
            }
            BINDER_SET_CONTEXT_MGR_EXT => {
                const BINDER_TYPE_BINDER: u32 = 0x7362_2a85;
                const FLAT_BINDER_OBJECT_BYTES: usize = 24;
                let mut raw = [0u8; FLAT_BINDER_OBJECT_BYTES];
                copy_from_user(&mut raw, args[2], FLAT_BINDER_OBJECT_BYTES)
                    .map_err(|_| CompatErrno::Fault)?;
                let object_type = u32::from_le_bytes(raw[0..4].try_into().unwrap());
                let pointer = u64::from_le_bytes(raw[8..16].try_into().unwrap());
                let cookie = u64::from_le_bytes(raw[16..24].try_into().unwrap());
                if object_type != BINDER_TYPE_BINDER {
                    return Err(CompatErrno::Invalid);
                }
                if crate::binder::set_context_manager_ext(pid, pointer, cookie) {
                    Ok(0)
                } else {
                    Err(CompatErrno::Busy)
                }
            }
            BINDER_SET_IDLE_TIMEOUT | BINDER_SET_IDLE_PRIORITY => Err(CompatErrno::Invalid),
            BINDER_THREAD_EXIT => {
                crate::binder::thread_exit(pid);
                Ok(0)
            }
            BINDER_FREEZE => {
                let mut raw = [0u8; 12];
                copy_from_user(&mut raw, args[2], 12)
                    .map_err(|_| CompatErrno::Fault)?;
                let target_pid = u32::from_le_bytes(raw[0..4].try_into().unwrap());
                let enable = u32::from_le_bytes(raw[4..8].try_into().unwrap());
                if enable > 1 {
                    return Err(CompatErrno::Invalid);
                }
                crate::binder::set_frozen(pid, target_pid, enable != 0)?;
                Ok(0)
            }
            BINDER_GET_FROZEN_INFO => {
                let mut raw = [0u8; 12];
                copy_from_user(&mut raw, args[2], 12)
                    .map_err(|_| CompatErrno::Fault)?;
                let target_pid = u32::from_le_bytes(raw[0..4].try_into().unwrap());
                let (pid_out, sync_recv, async_recv) =
                    crate::binder::get_frozen_status(pid, target_pid)?;
                raw = [0u8; 12];
                raw[0..4].copy_from_slice(&pid_out.to_le_bytes());
                raw[4..8].copy_from_slice(&sync_recv.to_le_bytes());
                raw[8..12].copy_from_slice(&async_recv.to_le_bytes());
                copy_to_user(args[2], &raw, raw.len()).map_err(|_| CompatErrno::Fault)?;
                Ok(0)
            }
            BINDER_ENABLE_ONEWAY_SPAM_DETECTION => {
                let mut raw = [0u8; 4];
                copy_from_user(&mut raw, args[2], 4).map_err(|_| CompatErrno::Fault)?;
                if crate::binder::set_oneway_spam_detection(
                    pid,
                    u32::from_le_bytes(raw) != 0,
                ) {
                    Ok(0)
                } else {
                    Err(CompatErrno::NoSpace)
                }
            }
            BINDER_GET_EXTENDED_ERROR => crate::binder::get_extended_error(pid, args[2]),
            BINDER_WRITE_READ => crate::binder::write_read(pid, fd, args),
            _ => Err(CompatErrno::NoSys),
        };
    }
    if matches!(
        args[1],
        FS_IOC_GETFLAGS
            | FS_IOC_SETFLAGS
            | FS_IOC_ENABLE_VERITY
            | FS_IOC_MEASURE_VERITY
            | FS_IOC_READ_VERITY_METADATA
    ) {
        return match args[1] {
            FS_IOC_GETFLAGS => {
                let enabled = proc::linux_ashmem_verity_state(pid, entry.handle)
                    .is_some_and(|(enabled, _, _)| enabled);
                let flags = if enabled { 0x0010_0000u64 } else { 0 };
                copy_to_user(args[2], &flags.to_le_bytes(), 8)
                    .map_err(|_| CompatErrno::Fault)?;
                Ok(0)
            }
            FS_IOC_SETFLAGS => Err(CompatErrno::Perm),
            FS_IOC_ENABLE_VERITY => linux_fsverity_enable(pid, fd, args[2]),
            FS_IOC_MEASURE_VERITY => linux_fsverity_measure(pid, fd, args[2]),
            FS_IOC_READ_VERITY_METADATA => {
                linux_fsverity_read_metadata(pid, fd, args[2])
            }
            _ => unreachable!(),
        };
    }
    if matches!(
        args[1],
        FS_IOC_SET_ENCRYPTION_POLICY
            | FS_IOC_GET_ENCRYPTION_PWSALT
            | FS_IOC_GET_ENCRYPTION_POLICY
            | FS_IOC_GET_ENCRYPTION_POLICY_EX
            | FS_IOC_ADD_ENCRYPTION_KEY
            | FS_IOC_REMOVE_ENCRYPTION_KEY
            | FS_IOC_REMOVE_ENCRYPTION_KEY_ALL_USERS
            | FS_IOC_GET_ENCRYPTION_KEY_STATUS
            | FS_IOC_GET_ENCRYPTION_NONCE
    ) {
        return match args[1] {
            FS_IOC_SET_ENCRYPTION_POLICY => {
                linux_fscrypt_set_policy(pid, fd, args[2])
            }
            FS_IOC_GET_ENCRYPTION_PWSALT => {
                linux_fscrypt_get_pwsalt(pid, fd, args[2])
            }
            FS_IOC_GET_ENCRYPTION_POLICY => {
                linux_fscrypt_get_policy(pid, fd, args[2])
            }
            FS_IOC_GET_ENCRYPTION_POLICY_EX => {
                linux_fscrypt_get_policy_ex(pid, fd, args[2])
            }
            FS_IOC_ADD_ENCRYPTION_KEY => {
                linux_fscrypt_add_key(pid, fd, args[2])
            }
            FS_IOC_REMOVE_ENCRYPTION_KEY => {
                linux_fscrypt_remove_key(pid, fd, args[2], false)
            }
            FS_IOC_REMOVE_ENCRYPTION_KEY_ALL_USERS => {
                linux_fscrypt_remove_key(pid, fd, args[2], true)
            }
            FS_IOC_GET_ENCRYPTION_KEY_STATUS => {
                linux_fscrypt_key_status(pid, fd, args[2])
            }
            FS_IOC_GET_ENCRYPTION_NONCE => {
                linux_fscrypt_get_nonce(pid, fd, args[2])
            }
            _ => unreachable!(),
        };
    }
    if proc::linux_is_sync_file(pid, entry.handle) {
        return match args[1] {
            SYNC_IOC_MERGE => {
                let mut raw = [0u8; 48];
                copy_from_user(&mut raw, args[2], 48).map_err(|_| CompatErrno::Fault)?;
                let other_fd = i32::from_le_bytes(raw[32..36].try_into().unwrap());
                let flags = u32::from_le_bytes(raw[40..44].try_into().unwrap());
                let pad = u32::from_le_bytes(raw[44..48].try_into().unwrap());
                if other_fd < 0 || flags != 0 || pad != 0 {
                    return Err(CompatErrno::Invalid);
                }
                let other = proc::linux_fd(pid, other_fd as u32).ok_or(CompatErrno::BadFd)?;
                if !proc::linux_is_sync_file(pid, other.handle) {
                    return Err(CompatErrno::Invalid);
                }
                let name_len = raw[..32]
                    .iter()
                    .position(|byte| *byte == 0)
                    .unwrap_or(32);
                let fence = proc::linux_create_sync_file(pid, &raw[..name_len], true)
                    .ok_or(CompatErrno::NoSpace)?;
                raw[36..40].copy_from_slice(&(fence as i32).to_le_bytes());
                copy_to_user(args[2], &raw, raw.len()).map_err(|_| CompatErrno::Fault)?;
                Ok(0)
            }
            SYNC_IOC_FILE_INFO => {
                let mut raw = [0u8; 56];
                copy_from_user(&mut raw, args[2], 56).map_err(|_| CompatErrno::Fault)?;
                let capacity = u32::from_le_bytes(raw[40..44].try_into().unwrap());
                let buffer = u64::from_le_bytes(raw[48..56].try_into().unwrap());
                let mut name = [0u8; 32];
                proc::linux_sync_file_name(pid, entry.handle, &mut name)
                    .ok_or(CompatErrno::BadFd)?;
                raw[..32].copy_from_slice(&name);
                raw[32..36].copy_from_slice(&1i32.to_le_bytes());
                raw[40..44].copy_from_slice(&1u32.to_le_bytes());
                if capacity != 0 && buffer != 0 {
                    let mut info = [0u8; 80];
                    info[..32].copy_from_slice(&name);
                    info[32..48].copy_from_slice(b"jasper-sync-file");
                    info[64..68].copy_from_slice(&1i32.to_le_bytes());
                    let now = sched::now_ns();
                    info[72..80].copy_from_slice(&now.to_le_bytes());
                    copy_to_user(buffer, &info, info.len())
                        .map_err(|_| CompatErrno::Fault)?;
                }
                copy_to_user(args[2], &raw, raw.len()).map_err(|_| CompatErrno::Fault)?;
                Ok(0)
            }
            SYNC_IOC_SET_DEADLINE => {
                let mut raw = [0u8; 16];
                copy_from_user(&mut raw, args[2], 16).map_err(|_| CompatErrno::Fault)?;
                if u64::from_le_bytes(raw[8..16].try_into().unwrap()) != 0 {
                    return Err(CompatErrno::Invalid);
                }
                Ok(0)
            }
            _ => Err(CompatErrno::NoSys),
        };
    }
    if entry.kind == compat_core::fd::CompatKind::Device
        && proc::linux_is_dma_heap(pid, entry.handle)
    {
        if args[1] != DMA_HEAP_IOCTL_ALLOC {
            return Err(CompatErrno::NoSys);
        }
        let mut raw = [0u8; 24];
        copy_from_user(&mut raw, args[2], 24).map_err(|_| CompatErrno::Fault)?;
        let size = u64::from_le_bytes(raw[0..8].try_into().unwrap());
        let fd_flags = u32::from_le_bytes(raw[12..16].try_into().unwrap());
        let heap_flags = u64::from_le_bytes(raw[16..24].try_into().unwrap());
        if size == 0
            || size % kernel_core::frame::FRAME_SIZE != 0
            || fd_flags & !(0x3 | 0x80000) != 0
            || heap_flags != 0
        {
            return Err(CompatErrno::Invalid);
        }
        let buffer_fd = proc::linux_create_memfd(pid, fd_flags & 0x80000 != 0, false)
            .ok_or(CompatErrno::NoSpace)?;
        let result = (|| {
            let buffer = proc::linux_fd(pid, buffer_fd).ok_or(CompatErrno::BadFd)?;
            proc::linux_ashmem_set_size(pid, buffer.handle, size)
                .map_err(ashmem_compat_error)?;
            if !proc::linux_register_dmabuf(pid, buffer.handle)
                || proc::linux_ashmem_set_name(pid, buffer.handle, b"dma_heap_system")
                    .is_err()
            {
                return Err(CompatErrno::NoSpace);
            }
            raw[8..12].copy_from_slice(&buffer_fd.to_le_bytes());
            copy_to_user(args[2], &raw, raw.len()).map_err(|_| CompatErrno::Fault)?;
            Ok(0)
        })();
        if result.is_err() {
            let _ = proc::linux_close_fd(pid, buffer_fd);
        }
        return result;
    }
    if entry.kind == compat_core::fd::CompatKind::Device
        && proc::linux_is_ion_device(pid, entry.handle)
    {
        return match args[1] {
            ION_IOC_ALLOC => {
                let mut raw = [0u8; 32];
                copy_from_user(&mut raw, args[2], 32)
                    .map_err(|_| CompatErrno::Fault)?;
                let size = u64::from_le_bytes(raw[0..8].try_into().unwrap());
                let alignment = u64::from_le_bytes(raw[8..16].try_into().unwrap());
                let heap_mask = u32::from_le_bytes(raw[16..20].try_into().unwrap());
                let flags = u32::from_le_bytes(raw[20..24].try_into().unwrap());
                let handle =
                    proc::linux_ion_alloc(pid, size, alignment, heap_mask, flags)
                        .map_err(ashmem_compat_error)?;
                copy_to_user(args[2] + 24, &handle.to_le_bytes(), 4)
                    .map_err(|_| CompatErrno::Fault)?;
                Ok(0)
            }
            ION_IOC_FREE => {
                let mut raw = [0u8; 4];
                copy_from_user(&mut raw, args[2], 4).map_err(|_| CompatErrno::Fault)?;
                proc::linux_ion_free(pid, u32::from_le_bytes(raw))
                    .map_err(ashmem_compat_error)?;
                Ok(0)
            }
            ION_IOC_MAP | ION_IOC_SHARE => {
                let mut raw = [0u8; 8];
                copy_from_user(&mut raw, args[2], 8)
                    .map_err(|_| CompatErrno::Fault)?;
                let handle = u32::from_le_bytes(raw[0..4].try_into().unwrap());
                let fd = proc::linux_ion_share(pid, handle, false)
                    .map_err(ashmem_compat_error)?;
                copy_to_user(args[2] + 4, &(fd as i32).to_le_bytes(), 4)
                    .map_err(|_| CompatErrno::Fault)?;
                Ok(0)
            }
            ION_IOC_IMPORT => {
                let mut raw = [0u8; 8];
                copy_from_user(&mut raw, args[2], 8)
                    .map_err(|_| CompatErrno::Fault)?;
                let fd = i32::from_le_bytes(raw[4..8].try_into().unwrap());
                if fd < 0 {
                    return Err(CompatErrno::BadFd);
                }
                let handle =
                    proc::linux_ion_import(pid, fd as u32).map_err(ashmem_compat_error)?;
                copy_to_user(args[2], &handle.to_le_bytes(), 4)
                    .map_err(|_| CompatErrno::Fault)?;
                Ok(0)
            }
            ION_IOC_SYNC => Ok(0),
            _ => Err(CompatErrno::NoSys),
        };
    }
    if entry.kind == compat_core::fd::CompatKind::Device
        && proc::linux_is_dmabuf(pid, entry.handle)
    {
        return match args[1] {
            DMA_BUF_IOCTL_SYNC => {
                let mut raw = [0u8; 8];
                copy_from_user(&mut raw, args[2], 8).map_err(|_| CompatErrno::Fault)?;
                let flags = u32::from_le_bytes(raw[..4].try_into().unwrap());
                if flags & !0xf != 0 {
                    return Err(CompatErrno::Invalid);
                }
                Ok(0)
            }
            DMA_BUF_SET_NAME => {
                let name = linux_c_string(args[2], 32)?;
                proc::linux_ashmem_set_name(pid, entry.handle, &name)
                    .map_err(ashmem_compat_error)?;
                Ok(0)
            }
            DMA_BUF_IOCTL_EXPORT_SYNC_FILE => {
                let mut raw = [0u8; 8];
                copy_from_user(&mut raw, args[2], 8).map_err(|_| CompatErrno::Fault)?;
                let flags = u32::from_le_bytes(raw[..4].try_into().unwrap());
                if flags == 0 || flags & !3 != 0 {
                    return Err(CompatErrno::Invalid);
                }
                let fence = proc::linux_create_sync_file(pid, b"dma-buf-export", true)
                    .ok_or(CompatErrno::NoSpace)?;
                raw[4..8].copy_from_slice(&(fence as i32).to_le_bytes());
                copy_to_user(args[2], &raw, raw.len()).map_err(|_| CompatErrno::Fault)?;
                Ok(0)
            }
            DMA_BUF_IOCTL_IMPORT_SYNC_FILE => {
                let mut raw = [0u8; 8];
                copy_from_user(&mut raw, args[2], 8).map_err(|_| CompatErrno::Fault)?;
                let flags = u32::from_le_bytes(raw[..4].try_into().unwrap());
                let fence_fd = i32::from_le_bytes(raw[4..8].try_into().unwrap());
                if flags == 0 || flags & !3 != 0 || fence_fd < 0 {
                    return Err(CompatErrno::Invalid);
                }
                let fence = proc::linux_fd(pid, fence_fd as u32).ok_or(CompatErrno::BadFd)?;
                if !proc::linux_is_sync_file(pid, fence.handle) {
                    return Err(CompatErrno::Invalid);
                }
                Ok(0)
            }
            _ => Err(CompatErrno::NoSys),
        };
    }
    if entry.kind == compat_core::fd::CompatKind::Device
        && proc::linux_ashmem_state(pid, entry.handle).is_some()
        && !proc::linux_ashmem_is_regular(pid, entry.handle).unwrap_or(false)
    {
        match args[1] {
            ASHMEM_SET_NAME => {
                let name = linux_c_string(args[2], 256)?;
                proc::linux_ashmem_set_name(pid, entry.handle, &name)
                    .map_err(ashmem_compat_error)?;
                return Ok(0);
            }
            ASHMEM_SET_PROT_MASK => {
                let mut protection = [0u8; 4];
                copy_from_user(&mut protection, args[2], 4)
                    .map_err(|_| CompatErrno::Fault)?;
                proc::linux_ashmem_set_protection(
                    pid,
                    entry.handle,
                    u32::from_le_bytes(protection),
                )
                .map_err(ashmem_compat_error)?;
                return Ok(0);
            }
            ASHMEM_SET_SIZE => {
                let mut size = [0u8; 8];
                copy_from_user(&mut size, args[2], 8).map_err(|_| CompatErrno::Fault)?;
                proc::linux_ashmem_set_size(pid, entry.handle, u64::from_le_bytes(size))
                    .map_err(ashmem_compat_error)?;
                return Ok(0);
            }
            ASHMEM_PIN | ASHMEM_UNPIN => {
                let mut pin = [0u8; 8];
                copy_from_user(&mut pin, args[2], 8).map_err(|_| CompatErrno::Fault)?;
                let pins =
                    proc::linux_ashmem_pin(pid, entry.handle, args[1] == ASHMEM_PIN)
                        .map_err(ashmem_compat_error)?;
                return Ok(u64::from(pins));
            }
            ASHMEM_GET_SIZE => {
                let (size, _, _) = proc::linux_ashmem_state(pid, entry.handle)
                    .ok_or(CompatErrno::NotSocket)?;
                copy_to_user(args[2], &size.to_le_bytes(), 8)
                    .map_err(|_| CompatErrno::Fault)?;
                return Ok(0);
            }
            ASHMEM_GET_NAME => {
                let name = proc::linux_ashmem_name(pid, entry.handle)
                    .map_err(ashmem_compat_error)?;
                copy_to_user(args[2], &name, name.len()).map_err(|_| CompatErrno::Fault)?;
                return Ok(0);
            }
            ASHMEM_GET_PROT_MASK => {
                let (_, protection, _) = proc::linux_ashmem_state(pid, entry.handle)
                    .ok_or(CompatErrno::NotSocket)?;
                copy_to_user(args[2], &protection.to_le_bytes(), 4)
                    .map_err(|_| CompatErrno::Fault)?;
                return Ok(0);
            }
            ASHMEM_GET_PIN_STATUS => {
                let (_, _, pins) = proc::linux_ashmem_state(pid, entry.handle)
                    .ok_or(CompatErrno::NotSocket)?;
                copy_to_user(args[2], &pins.to_le_bytes(), 4)
                    .map_err(|_| CompatErrno::Fault)?;
                return Ok(0);
            }
            ASHMEM_PURGE_ALL_CACHES => return Ok(0),
            _ => return Err(CompatErrno::NotTty),
        }
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

fn ashmem_compat_error(error: proc::LinuxAshmemError) -> CompatErrno {
    match error {
        proc::LinuxAshmemError::Invalid => CompatErrno::Invalid,
        proc::LinuxAshmemError::Permission => CompatErrno::Perm,
        proc::LinuxAshmemError::Busy => CompatErrno::Busy,
        proc::LinuxAshmemError::NoMemory => CompatErrno::NoMemory,
        proc::LinuxAshmemError::NotAshmem => CompatErrno::NotTty,
        proc::LinuxAshmemError::Exists => CompatErrno::Exists,
        proc::LinuxAshmemError::NoKey => CompatErrno::NoKey,
        proc::LinuxAshmemError::NotSupported => CompatErrno::NotSupported,
    }
}

const IO_URING_RING_BYTES: u64 = 3 * 4096;
const IO_URING_SQ_ARRAY: u64 = 0x80;
const IO_URING_CQ_HEAD: u64 = 0x100;
const IO_URING_CQ_TAIL: u64 = 0x104;
const IO_URING_CQ_MASK: u64 = 0x108;
const IO_URING_CQ_ENTRIES: u64 = 0x10c;
const IO_URING_CQES: u64 = 0x1000;
const IO_URING_SQES: u64 = 0x2000;

fn io_uring_read(
    pid: ObjId,
    handle: u64,
    offset: u64,
    output: &mut [u8],
) -> Result<(), CompatErrno> {
    proc::linux_ashmem_read_from(pid, handle, offset, output)
        .map(|_| ())
        .map_err(ashmem_compat_error)
}

fn io_uring_write(
    pid: ObjId,
    handle: u64,
    offset: u64,
    input: &[u8],
) -> Result<(), CompatErrno> {
    proc::linux_ashmem_write_from(pid, handle, offset, input)
        .map(|_| ())
        .map_err(ashmem_compat_error)
}

/// Executes one regular-file operation through a retained fixed-file
/// description. `positioned` requests use the SQE offset; otherwise the shared
/// open-file cursor is consumed.
fn linux_io_uring_fixed_file_io(
    pid: ObjId,
    file: &compat_core::fd::FdDescription,
    write: bool,
    address: u64,
    len: usize,
    offset: u64,
) -> Result<u64, CompatErrno> {
    const MAX_IO_URING_FILE_BYTES: usize = 1024 * 1024;
    if len > MAX_IO_URING_FILE_BYTES {
        return Err(CompatErrno::Invalid);
    }
    let required = if write {
        kernel_core::object::Rights::WRITE
    } else {
        kernel_core::object::Rights::READ
    };
    if !file.entry.rights.contains(required) {
        return Err(CompatErrno::BadFd);
    }
    let positioned = offset != u64::MAX;
    let effective_offset = if positioned {
        offset
    } else {
        file.offset()
    };
    if len == 0 {
        return Ok(0);
    }
    match file.entry.kind {
        compat_core::fd::CompatKind::Device
            if proc::linux_ashmem_is_regular(pid, file.entry.handle) == Some(true) =>
        {
            if write {
                let mut bytes = alloc::vec![0u8; len];
                copy_from_user(&mut bytes, address, len).map_err(|_| CompatErrno::Fault)?;
                let io = admit_process_io(pid, len as u64, 1)?;
                let written = proc::linux_ashmem_write_from(
                    pid,
                    file.entry.handle,
                    effective_offset,
                    &bytes,
                )
                .map_err(ashmem_compat_error)?;
                io.commit();
                if !positioned && written != 0 {
                    file.set_offset(effective_offset + written as u64);
                }
                Ok(written as u64)
            } else {
                let mut bytes = alloc::vec![0u8; len];
                let read = proc::linux_ashmem_read_from(
                    pid,
                    file.entry.handle,
                    effective_offset,
                    &mut bytes,
                )
                .map_err(ashmem_compat_error)?;
                let io = admit_process_io(pid, read as u64, 1)?;
                if read != 0 {
                    copy_to_user(address, &bytes[..read], read)
                        .map_err(|_| CompatErrno::Fault)?;
                }
                io.commit();
                if !positioned && read != 0 {
                    file.set_offset(effective_offset + read as u64);
                }
                Ok(read as u64)
            }
        }
        compat_core::fd::CompatKind::File if !write => {
            let backing =
                crate::linux_vfs::FileId::from_handle(file.entry.handle)
                    .ok_or(CompatErrno::BadFd)?;
            let offset = usize::try_from(effective_offset).map_err(|_| CompatErrno::Invalid)?;
            let source = backing.bytes();
            let available = source.len().saturating_sub(offset).min(len);
            let io = admit_process_io(pid, available as u64, 1)?;
            if available != 0 {
                copy_to_user(address, &source[offset..offset + available], available)
                    .map_err(|_| CompatErrno::Fault)?;
            }
            io.commit();
            if !positioned && available != 0 {
                file.set_offset(effective_offset + available as u64);
            }
            Ok(available as u64)
        }
        _ => Err(CompatErrno::NoSys),
    }
}

/// Returns whether a retained fixed file supports fsync/fdatasync.
fn linux_io_uring_fixed_file_sync(
    pid: ObjId,
    file: &compat_core::fd::FdDescription,
) -> Result<u64, CompatErrno> {
    match file.entry.kind {
        compat_core::fd::CompatKind::File | compat_core::fd::CompatKind::Directory => Ok(0),
        compat_core::fd::CompatKind::Device
            if proc::linux_ashmem_is_regular(pid, file.entry.handle) == Some(true) =>
        {
            Ok(0)
        }
        _ => Err(CompatErrno::Invalid),
    }
}

/// Creates a shared SQ/CQ/SQE backing object and publishes the Linux
/// `io_uring_params` geometry with single-mmap support.
fn linux_io_uring_setup(pid: ObjId, args: [u64; 6]) -> Result<u64, CompatErrno> {
    const PARAMS_BYTES: usize = 120;
    const IORING_SETUP_CLAMP: u32 = 1 << 4;
    const IORING_SETUP_SINGLE_ISSUER: u32 = 1 << 12;
    const IORING_FEAT_SINGLE_MMAP: u32 = 1;
    const MAX_ENTRIES: u32 = 64;

    let requested = u32::try_from(args[0]).map_err(|_| CompatErrno::Invalid)?;
    if requested == 0 {
        return Err(CompatErrno::Invalid);
    }
    let mut input = [0u8; PARAMS_BYTES];
    copy_from_user(&mut input, args[1], PARAMS_BYTES).map_err(|_| CompatErrno::Fault)?;
    let flags = u32::from_le_bytes(input[8..12].try_into().unwrap());
    if flags & !(IORING_SETUP_CLAMP | IORING_SETUP_SINGLE_ISSUER) != 0 {
        return Err(CompatErrno::Invalid);
    }
    let rounded = requested
        .checked_next_power_of_two()
        .ok_or(CompatErrno::Invalid)?;
    let entries = if rounded > MAX_ENTRIES {
        if flags & IORING_SETUP_CLAMP == 0 {
            return Err(CompatErrno::Invalid);
        }
        MAX_ENTRIES
    } else {
        rounded
    };
    let cq_entries = entries
        .checked_mul(2)
        .ok_or(CompatErrno::Invalid)?;
    let fd = proc::linux_create_memfd(pid, false, false).ok_or(CompatErrno::NoSpace)?;
    let result = (|| {
        let entry = proc::linux_fd(pid, fd).ok_or(CompatErrno::BadFd)?;
        proc::linux_ashmem_set_size(pid, entry.handle, IO_URING_RING_BYTES)
            .map_err(ashmem_compat_error)?;
        if !proc::linux_io_uring_register(pid, entry.handle, entries, cq_entries) {
            return Err(CompatErrno::NoSpace);
        }
        let mut ring = alloc::vec![0u8; IO_URING_RING_BYTES as usize];
        let put_u32 = |ring: &mut [u8], offset: usize, value: u32| {
            ring[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
        };
        put_u32(&mut ring, 0x08, entries - 1);
        put_u32(&mut ring, 0x0c, entries);
        put_u32(&mut ring, IO_URING_SQ_ARRAY as usize - 8, 0);
        put_u32(&mut ring, IO_URING_CQ_MASK as usize, cq_entries - 1);
        put_u32(&mut ring, IO_URING_CQ_ENTRIES as usize, cq_entries);
        io_uring_write(pid, entry.handle, 0, &ring)?;

        let mut params = [0u8; PARAMS_BYTES];
        params[0..4].copy_from_slice(&entries.to_le_bytes());
        params[4..8].copy_from_slice(&cq_entries.to_le_bytes());
        params[8..12].copy_from_slice(&flags.to_le_bytes());
        params[20..24].copy_from_slice(&IORING_FEAT_SINGLE_MMAP.to_le_bytes());
        // struct io_sqring_offsets
        params[40..44].copy_from_slice(&0u32.to_le_bytes());
        params[44..48].copy_from_slice(&4u32.to_le_bytes());
        params[48..52].copy_from_slice(&8u32.to_le_bytes());
        params[52..56].copy_from_slice(&12u32.to_le_bytes());
        params[56..60].copy_from_slice(&16u32.to_le_bytes());
        params[60..64].copy_from_slice(&20u32.to_le_bytes());
        params[64..68].copy_from_slice(&(IO_URING_SQ_ARRAY as u32).to_le_bytes());
        // struct io_cqring_offsets
        params[80..84].copy_from_slice(&(IO_URING_CQ_HEAD as u32).to_le_bytes());
        params[84..88].copy_from_slice(&(IO_URING_CQ_TAIL as u32).to_le_bytes());
        params[88..92].copy_from_slice(&(IO_URING_CQ_MASK as u32).to_le_bytes());
        params[92..96].copy_from_slice(&(IO_URING_CQ_ENTRIES as u32).to_le_bytes());
        params[96..100].copy_from_slice(&0x110u32.to_le_bytes());
        params[100..104].copy_from_slice(&(IO_URING_CQES as u32).to_le_bytes());
        copy_to_user(args[1], &params, PARAMS_BYTES).map_err(|_| CompatErrno::Fault)?;
        Ok(u64::from(fd))
    })();
    if result.is_err() {
        let _ = proc::linux_close_fd(pid, fd);
    }
    result
}

/// Consumes ring SQEs and posts synchronous completions into the shared CQ.
fn linux_io_uring_enter(pid: ObjId, args: [u64; 6]) -> Result<u64, CompatErrno> {
    const IORING_ENTER_GETEVENTS: u64 = 1;
    const IORING_ENTER_SQ_WAKEUP: u64 = 2;
    const IOSQE_FIXED_FILE: u8 = 1 << 0;
    const IORING_OP_NOP: u8 = 0;
    const IORING_OP_FSYNC: u8 = 3;
    const IORING_OP_READ: u8 = 22;
    const IORING_OP_WRITE: u8 = 23;

    let fd = u32::try_from(args[0]).map_err(|_| CompatErrno::BadFd)?;
    let to_submit = usize::try_from(args[1]).map_err(|_| CompatErrno::Invalid)?;
    let flags = args[3];
    if flags & !(IORING_ENTER_GETEVENTS | IORING_ENTER_SQ_WAKEUP) != 0
        || args[4] != 0
    {
        return Err(CompatErrno::NoSys);
    }
    let entry = proc::linux_fd(pid, fd).ok_or(CompatErrno::BadFd)?;
    let (entries, cq_entries) =
        proc::linux_io_uring_state(pid, entry.handle).ok_or(CompatErrno::BadFd)?;
    let mask = entries - 1;
    let cq_mask = cq_entries - 1;
    let mut bytes = [0u8; 8];
    io_uring_read(pid, entry.handle, 0, &mut bytes)?;
    let mut sq_head = u32::from_le_bytes(bytes[..4].try_into().unwrap());
    let sq_tail = u32::from_le_bytes(bytes[4..8].try_into().unwrap());
    let pending = sq_tail.wrapping_sub(sq_head);
    if pending > entries {
        return Err(CompatErrno::Invalid);
    }
    let submit = to_submit.min(pending as usize);
    let mut completion = [0u8; 8];
    io_uring_read(pid, entry.handle, IO_URING_CQ_HEAD, &mut completion)?;
    let cq_head = u32::from_le_bytes(completion[..4].try_into().unwrap());
    let mut cq_tail = u32::from_le_bytes(completion[4..].try_into().unwrap());
    let queued = cq_tail.wrapping_sub(cq_head);
    if queued > cq_entries
        || queued
            .checked_add(submit as u32)
            .is_none_or(|total| total > cq_entries)
    {
        return Err(CompatErrno::NoSpace);
    }
    if args[2] != 0 && queued == 0 && submit == 0 {
        // There is no independent asynchronous producer yet. Do not report
        // completion for a request that would have blocked in Linux.
        return Err(CompatErrno::NoSys);
    }
    for index in 0..submit {
        let position = sq_head.wrapping_add(index as u32);
        let mut array = [0u8; 4];
        io_uring_read(
            pid,
            entry.handle,
            IO_URING_SQ_ARRAY + u64::from(position & mask) * 4,
            &mut array,
        )?;
        let sqe_index = u32::from_le_bytes(array);
        let mut sqe = [0u8; 64];
        io_uring_read(
            pid,
            entry.handle,
            IO_URING_SQES + u64::from(sqe_index & mask) * 64,
            &mut sqe,
        )?;
        let opcode = sqe[0];
        let sqe_flags = sqe[1];
        let target_fd = i32::from_le_bytes(sqe[4..8].try_into().unwrap());
        let offset = u64::from_le_bytes(sqe[8..16].try_into().unwrap());
        let address = u64::from_le_bytes(sqe[16..24].try_into().unwrap());
        let length = u32::from_le_bytes(sqe[24..28].try_into().unwrap());
        let operation_flags = u32::from_le_bytes(sqe[28..32].try_into().unwrap());
        let user_data = u64::from_le_bytes(sqe[32..40].try_into().unwrap());
        let invalid_operation_flags = if opcode == IORING_OP_FSYNC {
            operation_flags & !1 != 0
        } else {
            operation_flags != 0
        };
        let fixed_file = sqe_flags & IOSQE_FIXED_FILE != 0;
        let result = if sqe_flags & !IOSQE_FIXED_FILE != 0
            || invalid_operation_flags
            || sqe_index >= entries
            || target_fd < 0 && opcode != IORING_OP_NOP
        {
            Err(CompatErrno::Invalid)
        } else if fixed_file && opcode != IORING_OP_NOP {
            (|| {
                let file =
                    proc::linux_io_uring_fixed_file(pid, entry.handle, target_fd as u32)
                        .ok_or(CompatErrno::BadFd)?;
                match opcode {
                    IORING_OP_FSYNC => {
                        linux_io_uring_fixed_file_sync(pid, &file)?;
                        Ok(0)
                    }
                    IORING_OP_READ => linux_io_uring_fixed_file_io(
                        pid,
                        &file,
                        false,
                        address,
                        length as usize,
                        offset,
                    ),
                    IORING_OP_WRITE => linux_io_uring_fixed_file_io(
                        pid,
                        &file,
                        true,
                        address,
                        length as usize,
                        offset,
                    ),
                    _ => Err(CompatErrno::NoSys),
                }
            })()
        } else {
            match opcode {
                IORING_OP_NOP => Ok(0),
                IORING_OP_FSYNC => linux_sync_fd(
                    pid,
                    u64::from(target_fd as u32),
                    operation_flags & 1 != 0,
                ),
                IORING_OP_READ => {
                    let call = [target_fd as u64, address, u64::from(length), offset, 0, 0];
                    if offset == u64::MAX {
                        linux_read(pid, call)
                    } else {
                        linux_pread64(pid, call)
                    }
                }
                IORING_OP_WRITE => {
                    let call = [target_fd as u64, address, u64::from(length), offset, 0, 0];
                    if offset == u64::MAX {
                        linux_write(pid, call)
                    } else {
                        linux_pwrite64(pid, call)
                    }
                }
                _ => Err(CompatErrno::NoSys),
            }
        };
        let result = match result {
            Ok(value) => value.min(i64::MAX as u64) as i64,
            Err(error) => -i64::from(error as i32),
        };
        let mut cqe = [0u8; 16];
        cqe[..8].copy_from_slice(&user_data.to_le_bytes());
        cqe[8..12].copy_from_slice(&(result as i32).to_le_bytes());
        io_uring_write(
            pid,
            entry.handle,
            IO_URING_CQES + u64::from(cq_tail & cq_mask) * 16,
            &cqe,
        )?;
        cq_tail = cq_tail.wrapping_add(1);
        io_uring_write(
            pid,
            entry.handle,
            IO_URING_CQ_TAIL,
            &cq_tail.to_le_bytes(),
        )?;
    }
    sq_head = sq_head.wrapping_add(submit as u32);
    io_uring_write(pid, entry.handle, 0, &sq_head.to_le_bytes())?;
    Ok(submit as u64)
}

/// Implements the fixed-file registration table. Every slot captures the
/// descriptor's open-file description; replacement is atomic after all new
/// descriptors and user memory have been validated.
fn linux_io_uring_register(pid: ObjId, args: [u64; 6]) -> Result<u64, CompatErrno> {
    const IORING_REGISTER_FILES: u32 = 2;
    const IORING_UNREGISTER_FILES: u32 = 3;
    const IORING_REGISTER_FILES_UPDATE: u32 = 6;

    let fd = u32::try_from(args[0]).map_err(|_| CompatErrno::BadFd)?;
    let entry = proc::linux_fd(pid, fd).ok_or(CompatErrno::BadFd)?;
    let (entries, _) =
        proc::linux_io_uring_state(pid, entry.handle).ok_or(CompatErrno::BadFd)?;
    let opcode = u32::try_from(args[1]).map_err(|_| CompatErrno::Invalid)?;
    let count = usize::try_from(args[3]).map_err(|_| CompatErrno::Invalid)?;
    let read_descriptions =
        |address: u64, count: usize| -> Result<
            alloc::vec::Vec<Option<compat_core::fd::FdDescription>>,
            CompatErrno,
        > {
            if count > entries as usize {
                return Err(CompatErrno::Invalid);
            }
            if count != 0 && address == 0 {
                return Err(CompatErrno::Fault);
            }
            let mut files = alloc::vec::Vec::new();
            files
                .try_reserve(count)
                .map_err(|_| CompatErrno::NoMemory)?;
            for index in 0..count {
                let slot = address
                    .checked_add((index * 4) as u64)
                    .ok_or(CompatErrno::Fault)?;
                let mut raw = [0u8; 4];
                copy_from_user(&mut raw, slot, 4).map_err(|_| CompatErrno::Fault)?;
                let raw_fd = i32::from_le_bytes(raw);
                if raw_fd == -1 {
                    files.push(None);
                } else if raw_fd < 0 {
                    return Err(CompatErrno::BadFd);
                } else {
                    files.push(Some(
                        proc::linux_fd_description(pid, raw_fd as u32)
                            .ok_or(CompatErrno::BadFd)?,
                    ));
                }
            }
            Ok(files)
        };

    match opcode {
        IORING_REGISTER_FILES => {
            let files = read_descriptions(args[2], count)?;
            if proc::linux_io_uring_replace_fixed_files(pid, entry.handle, files) {
                Ok(0)
            } else {
                Err(CompatErrno::Invalid)
            }
        }
        IORING_UNREGISTER_FILES => {
            if count != 0 || args[2] != 0 {
                return Err(CompatErrno::Invalid);
            }
            if proc::linux_io_uring_clear_fixed_files(pid, entry.handle) {
                Ok(0)
            } else {
                Err(CompatErrno::Invalid)
            }
        }
        IORING_REGISTER_FILES_UPDATE => {
            if args[2] == 0 || count == 0 {
                return Err(CompatErrno::Invalid);
            }
            let mut header = [0u8; 16];
            copy_from_user(&mut header, args[2], 16).map_err(|_| CompatErrno::Fault)?;
            let offset = u32::from_le_bytes(header[0..4].try_into().unwrap()) as usize;
            let reserved = u32::from_le_bytes(header[4..8].try_into().unwrap());
            let fds = u64::from_le_bytes(header[8..16].try_into().unwrap());
            let registered =
                proc::linux_io_uring_fixed_file_count(pid, entry.handle)
                    .ok_or(CompatErrno::BadFd)?;
            if reserved != 0
                || offset > registered
                || offset.checked_add(count).is_none_or(|end| end > registered)
            {
                return Err(CompatErrno::Invalid);
            }
            let files = read_descriptions(fds, count)?;
            if proc::linux_io_uring_update_fixed_files(pid, entry.handle, offset, files) {
                Ok(0)
            } else {
                Err(CompatErrno::Invalid)
            }
        }
        _ => Err(CompatErrno::NoSys),
    }
}

/// Creates one bounded legacy AIO context.
fn linux_io_setup(pid: ObjId, args: [u64; 6]) -> Result<u64, CompatErrno> {
    let max_events = usize::try_from(args[0]).map_err(|_| CompatErrno::Invalid)?;
    if !(1..=1024).contains(&max_events) || args[1] == 0 {
        return Err(CompatErrno::Invalid);
    }
    let context = proc::linux_aio_create(pid, max_events).ok_or(CompatErrno::NoSpace)?;
    copy_to_user(args[1], &context.to_le_bytes(), 8).map_err(|_| CompatErrno::Fault)?;
    Ok(0)
}

/// Destroys one legacy AIO context and all queued completions.
fn linux_io_destroy(pid: ObjId, args: [u64; 6]) -> Result<u64, CompatErrno> {
    if proc::linux_aio_destroy(pid, args[0]) {
        Ok(0)
    } else {
        Err(CompatErrno::Invalid)
    }
}

/// Reports that no pending operation can be cancelled in the synchronous AIO model.
fn linux_io_cancel(pid: ObjId, args: [u64; 6]) -> Result<u64, CompatErrno> {
    let _ = proc::linux_aio_state(pid, args[0]).ok_or(CompatErrno::Invalid)?;
    Err(CompatErrno::Invalid)
}

/// Submits legacy AIO requests, completing supported operations synchronously.
fn linux_io_submit(pid: ObjId, args: [u64; 6]) -> Result<u64, CompatErrno> {
    const IOCB_BYTES: usize = 64;
    const MAX_REQUESTS: usize = 32;
    let state = proc::linux_aio_state(pid, args[0]).ok_or(CompatErrno::Invalid)?;
    let count = usize::try_from(args[1]).map_err(|_| CompatErrno::Invalid)?;
    if count > MAX_REQUESTS || count != 0 && args[2] == 0 {
        return Err(CompatErrno::Invalid);
    }
    let mut submitted = 0usize;
    while submitted < count {
        let pointer_address = args[2]
            .checked_add((submitted * 8) as u64)
            .ok_or(CompatErrno::Fault)?;
        let mut pointer = [0u8; 8];
        if proc::read(pid, pointer_address, &mut pointer).is_err() {
            if submitted == 0 {
                return Err(CompatErrno::Fault);
            }
            break;
        }
        let iocb_address = u64::from_le_bytes(pointer);
        let mut iocb = [0u8; IOCB_BYTES];
        if iocb_address == 0 || proc::read(pid, iocb_address, &mut iocb).is_err() {
            if submitted == 0 {
                return Err(CompatErrno::Fault);
            }
            break;
        }
        let data = u64::from_le_bytes(iocb[0..8].try_into().unwrap());
        let opcode = u16::from_le_bytes(iocb[16..18].try_into().unwrap());
        let fd = u32::from_le_bytes(iocb[20..24].try_into().unwrap());
        let buffer = u64::from_le_bytes(iocb[24..32].try_into().unwrap());
        let bytes = u64::from_le_bytes(iocb[32..40].try_into().unwrap());
        let offset = i64::from_le_bytes(iocb[40..48].try_into().unwrap());
        let result = if offset < 0 {
            -(i64::from(CompatErrno::Invalid as i32))
        } else {
            match opcode {
                0 => compat_result(linux_pread64(
                    pid,
                    [u64::from(fd), buffer, bytes, offset as u64, 0, 0],
                )),
                1 => compat_result(linux_pwrite64(
                    pid,
                    [u64::from(fd), buffer, bytes, offset as u64, 0, 0],
                )),
                2 | 3 => compat_result(linux_sync_fd(pid, u64::from(fd), opcode == 3)),
                6 => 0,
                _ => -(i64::from(CompatErrno::Invalid as i32)),
            }
        };
        let mut state = state.lock();
        if state.events.len() >= state.max_events {
            if submitted == 0 {
                return Err(CompatErrno::TryAgain);
            }
            break;
        }
        state.events.push_back(proc::LinuxAioEvent {
            data,
            object: iocb_address,
            result,
            result2: 0,
        });
        submitted += 1;
    }
    Ok(submitted as u64)
}

/// Returns completed legacy AIO events, optionally waiting for a minimum count.
fn linux_io_getevents(
    pid: ObjId,
    args: [u64; 6],
    pgetevents: bool,
) -> Result<u64, CompatErrno> {
    const EVENT_BYTES: usize = 32;
    const MAX_EVENTS: usize = 32;
    if pgetevents && args[5] != 0 {
        return Err(CompatErrno::NotSupported);
    }
    let state = proc::linux_aio_state(pid, args[0]).ok_or(CompatErrno::Invalid)?;
    let minimum = usize::try_from(args[1]).map_err(|_| CompatErrno::Invalid)?;
    let maximum = usize::try_from(args[2]).map_err(|_| CompatErrno::Invalid)?;
    if maximum > MAX_EVENTS || minimum > maximum || maximum != 0 && args[3] == 0 {
        return Err(CompatErrno::Invalid);
    }
    let deadline = if args[4] == 0 {
        None
    } else {
        Some(
            sched::now_ns()
                .checked_add(read_linux_timespec(args[4])?)
                .ok_or(CompatErrno::Invalid)?,
        )
    };
    let events = loop {
        let mut ready = alloc::vec::Vec::new();
        {
            let mut state = state.lock();
            while ready.len() < maximum {
                let Some(event) = state.events.pop_front() else {
                    break;
                };
                ready.push(event);
            }
        }
        if ready.len() >= minimum {
            break ready;
        }
        if let Some(deadline) = deadline {
            if sched::now_ns() >= deadline {
                break ready;
            }
            let wake = deadline.min(sched::now_ns().saturating_add(10_000_000));
            if sched::sleep_until_ns(wake).is_err() {
                sched::pause();
            }
        } else {
            sched::pause();
        }
    };
    if events.is_empty() {
        return Ok(0);
    }
    let mut output = alloc::vec![0u8; events.len() * EVENT_BYTES];
    for (index, event) in events.iter().enumerate() {
        let base = index * EVENT_BYTES;
        output[base..base + 8].copy_from_slice(&event.data.to_le_bytes());
        output[base + 8..base + 16].copy_from_slice(&event.object.to_le_bytes());
        output[base + 16..base + 24].copy_from_slice(&event.result.to_le_bytes());
        output[base + 24..base + 32].copy_from_slice(&event.result2.to_le_bytes());
    }
    copy_to_user(args[3], &output, output.len()).map_err(|_| CompatErrno::Fault)?;
    Ok(events.len() as u64)
}

/// Creates a bounded Linux epoll instance.
fn linux_epoll_create1(pid: ObjId, args: [u64; 6]) -> Result<u64, CompatErrno> {
    const EPOLL_CLOEXEC: u64 = 0x80000;
    if args[0] & !EPOLL_CLOEXEC != 0 {
        return Err(CompatErrno::Invalid);
    }
    proc::linux_epoll_create(pid, args[0] & EPOLL_CLOEXEC != 0)
        .map(u64::from)
        .ok_or(CompatErrno::NoSpace)
}

/// Implements legacy `epoll_create(2)`; Linux ignores a positive legacy size hint.
fn linux_epoll_create(pid: ObjId, args: [u64; 6]) -> Result<u64, CompatErrno> {
    if (args[0] as u32 as i32) <= 0 {
        return Err(CompatErrno::Invalid);
    }
    proc::linux_epoll_create(pid, false)
        .map(u64::from)
        .ok_or(CompatErrno::NoSpace)
}

/// Adds, removes or modifies one epoll interest by the target open-file handle.
fn linux_epoll_ctl(pid: ObjId, args: [u64; 6]) -> Result<u64, CompatErrno> {
    const EPOLL_CTL_ADD: u64 = 1;
    const EPOLL_CTL_DEL: u64 = 2;
    const EPOLL_CTL_MOD: u64 = 3;
    const EPOLLIN: u32 = 0x001;
    const EPOLLOUT: u32 = 0x004;
    const EPOLLERR: u32 = 0x008;
    const EPOLLHUP: u32 = 0x010;
    const EPOLLRDHUP: u32 = 0x2000;
    const EPOLLONESHOT: u32 = 1 << 30;
    const EPOLLET: u32 = 1 << 31;
    const EVENT_BYTES: usize = 12;
    const MAX_REGISTRATIONS: usize = 64;

    let epfd = u32::try_from(args[0]).map_err(|_| CompatErrno::BadFd)?;
    let target_fd = u32::try_from(args[2]).map_err(|_| CompatErrno::BadFd)?;
    if !matches!(args[1], EPOLL_CTL_ADD | EPOLL_CTL_DEL | EPOLL_CTL_MOD) {
        return Err(CompatErrno::Invalid);
    }
    let epoll_entry = proc::linux_fd(pid, epfd).ok_or(CompatErrno::BadFd)?;
    let registrations = proc::linux_epoll_registrations(pid, epoll_entry.handle)
        .ok_or(CompatErrno::BadFd)?;
    let target = proc::linux_fd(pid, target_fd).ok_or(CompatErrno::BadFd)?;
    let target_description =
        proc::linux_fd_description_identity(pid, target_fd).ok_or(CompatErrno::BadFd)?;
    if target.handle == epoll_entry.handle || proc::linux_is_epoll(pid, target.handle) {
        return Err(CompatErrno::Invalid);
    }
    let mut registrations = registrations.lock();
    let existing = registrations
        .iter()
        .position(|registration| {
            registration.handle == target.handle
                && registration.description_id == target_description
        });
    if args[1] == EPOLL_CTL_DEL {
        let index = existing.ok_or(CompatErrno::NoEntry)?;
        registrations.remove(index);
        return Ok(0);
    }
    if args[1] == EPOLL_CTL_ADD && existing.is_some() {
        return Err(CompatErrno::Exists);
    }
    if args[1] == EPOLL_CTL_MOD && existing.is_none() {
        return Err(CompatErrno::NoEntry);
    }
    let mut raw = [0u8; EVENT_BYTES];
    copy_from_user(&mut raw, args[3], EVENT_BYTES).map_err(|_| CompatErrno::Fault)?;
    let events = u32::from_le_bytes(raw[..4].try_into().unwrap());
    let supported =
        EPOLLIN | EPOLLOUT | EPOLLERR | EPOLLHUP | EPOLLRDHUP | EPOLLONESHOT | EPOLLET;
    if events & supported == 0 || events & !supported != 0 {
        return Err(CompatErrno::Invalid);
    }
    let data = u64::from_le_bytes(raw[4..12].try_into().unwrap());
    let registration = proc::LinuxEpollRegistration {
        handle: target.handle,
        description_id: target_description,
        kind: target.kind,
        rights: target.rights,
        events,
        data,
        armed: true,
        edge_seen: 0,
    };
    if let Some(index) = existing {
        registrations[index] = registration;
        return Ok(0);
    }
    if registrations.len() >= MAX_REGISTRATIONS {
        return Err(CompatErrno::NoSpace);
    }
    registrations
        .try_reserve(1)
        .map_err(|_| CompatErrno::NoSpace)?;
    registrations.push(registration);
    Ok(0)
}

/// Evaluates one registered source without taking the epoll set lock again.
fn linux_epoll_readiness(
    pid: ObjId,
    registration: proc::LinuxEpollRegistration,
) -> Option<u32> {
    const EPOLLIN: u32 = 0x001;
    const EPOLLOUT: u32 = 0x004;
    const EPOLLERR: u32 = 0x008;
    const EPOLLHUP: u32 = 0x010;
    const EPOLLRDHUP: u32 = 0x2000;

    if proc::linux_handle_fd_count(pid, registration.handle) == 0 {
        return None;
    }
    let requested = registration.events & (EPOLLIN | EPOLLOUT | EPOLLERR | EPOLLHUP | EPOLLRDHUP);
    let ready = match registration.kind {
        compat_core::fd::CompatKind::Other
            if registration.handle == proc::LINUX_CONSOLE_HANDLE =>
        {
            let (pending, ended, failed) = crate::terminal::input_status();
            let mut ready = 0;
            if requested & EPOLLIN != 0 && (pending || ended) {
                ready |= EPOLLIN;
            }
            if requested & EPOLLOUT != 0 {
                ready |= EPOLLOUT;
            }
            if ended {
                ready |= EPOLLHUP;
            }
            if failed {
                ready |= EPOLLERR;
            }
            ready
        }
        compat_core::fd::CompatKind::Other
            if proc::linux_is_sync_file(pid, registration.handle) =>
        {
            if requested & EPOLLIN != 0 {
                EPOLLIN
            } else {
                0
            }
        }
        compat_core::fd::CompatKind::Event => {
            let (counter, _) = proc::linux_eventfd_state(pid, registration.handle)?;
            let value = *counter.lock();
            let mut ready = 0;
            if requested & EPOLLIN != 0 && value != 0 {
                ready |= EPOLLIN;
            }
            if requested & EPOLLOUT != 0 && value < u64::MAX - 1 {
                ready |= EPOLLOUT;
            }
            ready
        }
        compat_core::fd::CompatKind::Timer => {
            let state = proc::linux_timerfd_state(pid, registration.handle)?;
            let mut state = state.lock();
            if linux_timerfd_settle(&mut state).is_ok()
                && requested & EPOLLIN != 0
                && state.expirations != 0
            {
                EPOLLIN
            } else {
                0
            }
        }
        compat_core::fd::CompatKind::Signal => {
            let mask = proc::linux_signalfd_state(pid, registration.handle)?;
            if requested & EPOLLIN != 0 && signalfd_pending_mask(pid, *mask.lock()) != 0 {
                EPOLLIN
            } else {
                0
            }
        }
        compat_core::fd::CompatKind::MessageQueue => {
            let queue = proc::linux_mq_state(pid, registration.handle)?;
            let state = queue.state.lock();
            let mut ready = 0;
            if requested & EPOLLIN != 0
                && registration
                    .rights
                    .contains(kernel_core::object::Rights::READ)
                && !state.messages.is_empty()
            {
                ready |= EPOLLIN;
            }
            if requested & EPOLLOUT != 0
                && registration
                    .rights
                    .contains(kernel_core::object::Rights::WRITE)
                && state.messages.len() < state.max_messages
            {
                ready |= EPOLLOUT;
            }
            ready
        }
        compat_core::fd::CompatKind::Pipe => {
            let pipe = proc::linux_pipe_endpoint(pid, registration.handle)?;
            let mut ready = 0;
            if requested & EPOLLIN != 0
                && registration
                    .rights
                    .contains(kernel_core::object::Rights::READ)
                && pipe.is_readable()
            {
                ready |= EPOLLIN;
            }
            if requested & EPOLLOUT != 0
                && registration
                    .rights
                    .contains(kernel_core::object::Rights::WRITE)
                && pipe.is_writable()
            {
                ready |= EPOLLOUT;
            }
            if pipe.readers_gone() {
                ready |= EPOLLERR;
            }
            if pipe.writers_gone() {
                ready |= EPOLLHUP | EPOLLRDHUP;
            }
            ready
        }
        compat_core::fd::CompatKind::Socket => {
            let socket = proc::linux_socket_endpoint(pid, registration.handle)?;
            let mut ready = 0;
            if requested & EPOLLIN != 0
                && registration
                    .rights
                    .contains(kernel_core::object::Rights::READ)
                && socket.is_readable()
            {
                ready |= EPOLLIN;
            }
            if requested & EPOLLOUT != 0
                && registration
                    .rights
                    .contains(kernel_core::object::Rights::WRITE)
                && socket.is_writable()
            {
                ready |= EPOLLOUT;
            }
            if socket.peer_read_gone() {
                ready |= EPOLLERR;
            }
            if socket.peer_write_gone() {
                ready |= EPOLLHUP | EPOLLRDHUP;
            }
            ready
        }
        compat_core::fd::CompatKind::File => {
            let mut ready = 0;
            if requested & EPOLLIN != 0
                && registration
                    .rights
                    .contains(kernel_core::object::Rights::READ)
            {
                ready |= EPOLLIN;
            }
            if requested & EPOLLOUT != 0
                && registration
                    .rights
                    .contains(kernel_core::object::Rights::WRITE)
            {
                ready |= EPOLLOUT;
            }
            ready
        }
        compat_core::fd::CompatKind::Device
            if proc::linux_ashmem_is_regular(pid, registration.handle) == Some(true) =>
        {
            let mut ready = 0;
            if requested & EPOLLIN != 0
                && registration
                    .rights
                    .contains(kernel_core::object::Rights::READ)
            {
                ready |= EPOLLIN;
            }
            if requested & EPOLLOUT != 0
                && registration
                    .rights
                    .contains(kernel_core::object::Rights::WRITE)
            {
                ready |= EPOLLOUT;
            }
            ready
        }
        compat_core::fd::CompatKind::Inotify => {
            if requested & EPOLLIN != 0
                && proc::linux_notification_ready(pid, registration.handle)? {
                EPOLLIN
            } else {
                0
            }
        }
        compat_core::fd::CompatKind::Other
            if proc::linux_userfault_state(pid, registration.handle).is_some() =>
        {
            let state = proc::linux_userfault_state(pid, registration.handle)?;
            if requested & EPOLLIN != 0 && !state.lock().events.is_empty() {
                EPOLLIN
            } else {
                0
            }
        }
        compat_core::fd::CompatKind::Pidfd => {
            if requested & EPOLLIN != 0
                && ObjId::from_raw(registration.handle)
                    .is_none_or(pidfd_target_ready)
            {
                EPOLLIN
            } else {
                0
            }
        }
        _ => 0,
    };
    Some(ready)
}

/// Parses an epoll wait timeout without allowing overflow or negative nanos.
fn linux_epoll_deadline(args: [u64; 6], pwait2: bool) -> Result<Option<u64>, CompatErrno> {
    let timeout_ns = if pwait2 {
        if args[3] == 0 {
            None
        } else {
            let mut raw = [0u8; 16];
            copy_from_user(&mut raw, args[3], 16).map_err(|_| CompatErrno::Fault)?;
            let seconds = i64::from_le_bytes(raw[..8].try_into().unwrap());
            let nanos = i64::from_le_bytes(raw[8..].try_into().unwrap());
            if seconds < 0 || !(0..1_000_000_000).contains(&nanos) {
                return Err(CompatErrno::Invalid);
            }
            Some(
                (seconds as u64)
                    .checked_mul(1_000_000_000)
                    .and_then(|value| value.checked_add(nanos as u64))
                    .ok_or(CompatErrno::Invalid)?,
            )
        }
    } else {
        let timeout = args[3] as u32 as i32;
        (timeout >= 0).then_some((timeout as u64).saturating_mul(1_000_000))
    };
    Ok(timeout_ns.map(|duration| sched::now_ns().saturating_add(duration)))
}

/// Waits on one epoll set with level, edge and oneshot semantics.
fn linux_epoll_wait(
    pid: ObjId,
    args: [u64; 6],
    pwait: bool,
    pwait2: bool,
) -> Result<u64, CompatErrno> {
    const EPOLLERR: u32 = 0x008;
    const EPOLLHUP: u32 = 0x010;
    const EPOLLONESHOT: u32 = 1 << 30;
    const EPOLLET: u32 = 1 << 31;
    const MAX_EVENTS: usize = 64;

    let epfd = u32::try_from(args[0]).map_err(|_| CompatErrno::BadFd)?;
    let requested_events = usize::try_from(args[2]).map_err(|_| CompatErrno::Invalid)?;
    if requested_events == 0 {
        return Err(CompatErrno::Invalid);
    }
    // The kernel ring and user copy are bounded. Accept every Linux-valid
    // positive maxevents value and report at most the capacity in one call.
    let max_events = requested_events.min(MAX_EVENTS);
    let deadline = linux_epoll_deadline(args, pwait2)?;
    let old_mask = current_signal_mask(pid).ok_or(CompatErrno::NoSys)?;
    let mut restore_mask = false;
    if pwait && args[4] != 0 {
        if args[5] != 8 {
            return Err(CompatErrno::Invalid);
        }
        let mut raw = [0u8; 8];
        copy_from_user(&mut raw, args[4], 8).map_err(|_| CompatErrno::Fault)?;
        if !set_current_signal_mask(pid, u64::from_le_bytes(raw)) {
            return Err(CompatErrno::NoSys);
        }
        restore_mask = true;
    }
    let result = (|| {
        let epoll_entry = proc::linux_fd(pid, epfd).ok_or(CompatErrno::BadFd)?;
        let registrations = proc::linux_epoll_registrations(pid, epoll_entry.handle)
            .ok_or(CompatErrno::BadFd)?;
        loop {
            let mut output = [0u8; MAX_EVENTS * 12];
            let mut ready = 0usize;
            {
                let mut registrations = registrations.lock();
                registrations.retain(|registration| {
                    proc::linux_handle_fd_count(pid, registration.handle) != 0
                });
                for registration in registrations.iter_mut() {
                    if !registration.armed || ready == max_events {
                        continue;
                    }
                    let Some(selected) = linux_epoll_readiness(pid, *registration) else {
                        registration.armed = false;
                        continue;
                    };
                    let always = selected & (EPOLLERR | EPOLLHUP);
                    let relevant = selected & registration.events & !(EPOLLONESHOT | EPOLLET);
                    let selected = relevant | always;
                    let deliver = if registration.events & EPOLLET != 0 {
                        selected & !registration.edge_seen != 0
                    } else {
                        selected != 0
                    };
                    if deliver {
                        let base = ready * 12;
                        output[base..base + 4]
                            .copy_from_slice(&selected.to_le_bytes());
                        output[base + 4..base + 12]
                            .copy_from_slice(&registration.data.to_le_bytes());
                        ready += 1;
                        registration.edge_seen |= selected;
                        if registration.events & EPOLLONESHOT != 0 {
                            registration.armed = false;
                        }
                    } else if selected == 0 {
                        registration.edge_seen = 0;
                    }
                }
            }
            if ready != 0 {
                copy_to_user(args[1], &output[..ready * 12], ready * 12)
                    .map_err(|_| CompatErrno::Fault)?;
                return Ok(ready as u64);
            }
            if proc::current_exiting() || current_signal_pending(pid) {
                return Err(CompatErrno::Interrupted);
            }
            if let Some(deadline) = deadline {
                if sched::now_ns() >= deadline {
                    return Ok(0);
                }
                let wake = deadline.min(sched::now_ns().saturating_add(10_000_000));
                if sched::sleep_until_ns(wake).is_err() {
                    sched::pause();
                }
            } else {
                sched::pause();
            }
        }
    })();
    if restore_mask && !set_current_signal_mask(pid, old_mask) {
        return Err(CompatErrno::NoSys);
    }
    result
}

/// Implements bounded blocking and timeout `poll(2)` over compatibility fds.
fn linux_poll(pid: ObjId, args: [u64; 6]) -> Result<u64, CompatErrno> {
    const POLLIN: u16 = 0x001;
    const POLLOUT: u16 = 0x004;
    const POLLERR: u16 = 0x008;
    const POLLHUP: u16 = 0x010;
    const POLLNVAL: u16 = 0x020;
    // Bound one scan to 64 pollfd records (512 bytes). This is an explicit
    // compatibility-service DoS policy, not a Linux kernel ABI fact; exceeding
    // it reports ENOMEM instead of the invalid-argument error used for a bad
    // user pointer or count that cannot be represented.
    // 单次扫描限制为 64 条 pollfd（512 字节）；这是兼容服务显式 DoS 策略，
    // 不是 Linux 内核 ABI 事实。超限返回 ENOMEM，不把合法大请求误报为 EINVAL。
    const MAX_POLLFDS: usize = 64; // JASPER-HARDCODE-REVIEW: issue=35 source=linux-poll-scan-policy reason=bounded-user-copy-and-readiness-scan
    let count = usize::try_from(args[1]).map_err(|_| CompatErrno::Invalid)?;
    let timeout = args[2] as u32 as i32;
    if count > MAX_POLLFDS {
        return Err(CompatErrno::NoSpace);
    }
    let deadline = if timeout < 0 {
        None
    } else {
        Some(
            sched::now_ns().saturating_add((timeout as u64).saturating_mul(1_000_000)),
        )
    };
    loop {
        let mut ready_count = 0usize;
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
                Some(entry) if entry.kind == compat_core::fd::CompatKind::Event => {
                    let Some((counter, _)) = proc::linux_eventfd_state(pid, entry.handle) else {
                        continue;
                    };
                    let value = *counter.lock();
                    let mut ready = 0;
                    if events & POLLIN != 0 && value != 0 {
                        ready |= POLLIN;
                    }
                    if events & POLLOUT != 0 && value < u64::MAX - 1 {
                        ready |= POLLOUT;
                    }
                    ready
                }
                Some(entry) if entry.kind == compat_core::fd::CompatKind::Timer => {
                    let Some(state) = proc::linux_timerfd_state(pid, entry.handle) else {
                        continue;
                    };
                    let mut state = state.lock();
                    if linux_timerfd_settle(&mut state).is_ok()
                        && events & POLLIN != 0
                        && state.expirations != 0
                    {
                        POLLIN
                    } else {
                        0
                    }
                }
                Some(entry) if entry.kind == compat_core::fd::CompatKind::Signal => {
                    let Some(mask) = proc::linux_signalfd_state(pid, entry.handle) else {
                        continue;
                    };
                    if events & POLLIN != 0 && signalfd_pending_mask(pid, *mask.lock()) != 0 {
                        POLLIN
                    } else {
                        0
                    }
                }
                Some(entry) if entry.kind == compat_core::fd::CompatKind::MessageQueue => {
                    let Some(queue) = proc::linux_mq_state(pid, entry.handle) else {
                        continue;
                    };
                    let state = queue.state.lock();
                    let mut ready = 0;
                    if events & POLLIN != 0
                        && entry.rights.contains(kernel_core::object::Rights::READ)
                        && !state.messages.is_empty()
                    {
                        ready |= POLLIN;
                    }
                    if events & POLLOUT != 0
                        && entry.rights.contains(kernel_core::object::Rights::WRITE)
                        && state.messages.len() < state.max_messages
                    {
                        ready |= POLLOUT;
                    }
                    ready
                }
                Some(entry) if entry.kind == compat_core::fd::CompatKind::Pidfd => {
                    if events & POLLIN != 0
                        && ObjId::from_raw(entry.handle)
                            .is_none_or(pidfd_target_ready)
                    {
                        POLLIN
                    } else {
                        0
                    }
                }
                Some(entry) if entry.kind == compat_core::fd::CompatKind::Inotify => {
                    if events & POLLIN != 0
                        && proc::linux_notification_ready(pid, entry.handle)
                            == Some(true)
                    {
                        POLLIN
                    } else {
                        0
                    }
                }
                Some(entry) if proc::linux_userfault_state(pid, entry.handle).is_some() => {
                    let state = proc::linux_userfault_state(pid, entry.handle).unwrap();
                    if events & POLLIN != 0 && !state.lock().events.is_empty() {
                        POLLIN
                    } else {
                        0
                    }
                }
                Some(entry) if entry.handle == proc::LINUX_CONSOLE_HANDLE => {
                    let (pending, ended, failed) = crate::terminal::input_status();
                    let mut ready = 0;
                    if events & POLLIN != 0 && (pending || ended) {
                        ready |= POLLIN;
                    }
                    if events & POLLOUT != 0 {
                        ready |= POLLOUT;
                    }
                    if ended {
                        ready |= POLLHUP;
                    }
                    if failed {
                        ready |= POLLERR;
                    }
                    ready
                }
                Some(entry) if proc::linux_is_sync_file(pid, entry.handle) => {
                    if events & POLLIN != 0 {
                        POLLIN
                    } else {
                        0
                    }
                }
                Some(entry) if entry.kind == compat_core::fd::CompatKind::Event => {
                    let Some((counter, _)) = proc::linux_eventfd_state(pid, entry.handle) else {
                        continue;
                    };
                    let value = *counter.lock();
                    let mut ready = 0;
                    if events & POLLIN != 0 && value != 0 {
                        ready |= POLLIN;
                    }
                    if events & POLLOUT != 0 && value < u64::MAX - 1 {
                        ready |= POLLOUT;
                    }
                    ready
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
        if revents != 0 {
            ready_count += 1;
        }
        pollfd[6..8].copy_from_slice(&revents.to_le_bytes());
        copy_to_user(address, &pollfd, pollfd.len()).map_err(|_| CompatErrno::Fault)?;
        }
        if ready_count != 0 || timeout == 0 {
            return Ok(ready_count as u64);
        }
        if proc::current_exiting() || current_signal_pending(pid) {
            return Err(CompatErrno::Interrupted);
        }
        if let Some(deadline) = deadline {
            if sched::now_ns() >= deadline {
                return Ok(0);
            }
            if sched::sleep_until_ns(deadline).is_err() {
                sched::pause();
            }
        } else {
            sched::pause();
        }
    }
}

/// Implements `ppoll(2)` with a bounded timespec timeout and atomic temporary
/// signal-mask replacement.
fn linux_ppoll(pid: ObjId, args: [u64; 6]) -> Result<u64, CompatErrno> {
    if args[4] != 0 && args[4] != 8 {
        return Err(CompatErrno::Invalid);
    }
    let timeout = if args[2] == 0 {
        u32::MAX as u64
    } else {
        let mut raw = [0u8; 16];
        copy_from_user(&mut raw, args[2], 16).map_err(|_| CompatErrno::Fault)?;
        let seconds = i64::from_le_bytes(raw[0..8].try_into().unwrap());
        let nanos = i64::from_le_bytes(raw[8..16].try_into().unwrap());
        if seconds < 0 || !(0..1_000_000_000).contains(&nanos) {
            return Err(CompatErrno::Invalid);
        }
        (seconds as u64)
            .checked_mul(1_000)
            .and_then(|millis| {
                millis.checked_add((nanos as u64).div_ceil(1_000_000))
            })
            .filter(|millis| *millis <= i32::MAX as u64)
            .ok_or(CompatErrno::Invalid)?
    };
    let mut temporary_mask = temporary_signal_mask(pid, args[3], args[4])?;
    let result = linux_poll(
        pid,
        [args[0], args[1], timeout, 0, 0, 0],
    );
    if matches!(result, Err(CompatErrno::Interrupted)) {
        if temporary_mask
            .as_mut()
            .is_some_and(|mask| !mask.defer_restore_to_signal_frame())
        {
            return Err(CompatErrno::NoSys);
        }
    }
    result
}

/// Implements `select(2)`/`pselect6(2)` by translating bounded fd sets through
/// the validated poll readiness path.
fn linux_select(
    pid: ObjId,
    args: [u64; 6],
    pselect: bool,
) -> Result<u64, CompatErrno> {
    const FDSET_BYTES: usize = 128;
    const POLLIN: u16 = 0x001;
    const POLLOUT: u16 = 0x004;
    const POLLERR: u16 = 0x008;
    const POLLHUP: u16 = 0x010;
    let nfds = usize::try_from(args[0]).map_err(|_| CompatErrno::Invalid)?;
    if nfds > FDSET_BYTES * 8 {
        return Err(CompatErrno::Invalid);
    }
    let mut pselect_mask = None;
    if pselect && args[5] != 0 {
        let mut raw = [0u8; 16];
        copy_from_user(&mut raw, args[5], 16).map_err(|_| CompatErrno::Fault)?;
        let mask_address = u64::from_le_bytes(raw[0..8].try_into().unwrap());
        let size = u64::from_le_bytes(raw[8..16].try_into().unwrap());
        if mask_address != 0 && size != 8 {
            return Err(CompatErrno::Invalid);
        }
        pselect_mask = (mask_address != 0).then_some((mask_address, size));
    }
    let mut read_set = [0u8; FDSET_BYTES];
    let mut write_set = [0u8; FDSET_BYTES];
    let mut except_set = [0u8; FDSET_BYTES];
    let mut have_read = false;
    let mut have_write = false;
    let mut have_except = false;
    if args[1] != 0 {
        copy_from_user(&mut read_set, args[1], FDSET_BYTES)
            .map_err(|_| CompatErrno::Fault)?;
        have_read = true;
    }
    if args[2] != 0 {
        copy_from_user(&mut write_set, args[2], FDSET_BYTES)
            .map_err(|_| CompatErrno::Fault)?;
        have_write = true;
    }
    if args[3] != 0 {
        copy_from_user(&mut except_set, args[3], FDSET_BYTES)
            .map_err(|_| CompatErrno::Fault)?;
        have_except = true;
    }
    let mut poll_entries = alloc::vec::Vec::new();
    for fd in 0..nfds {
        let bit = 1u8 << (fd % 8);
        let byte = fd / 8;
        let mut events = 0u16;
        if have_read && read_set[byte] & bit != 0 {
            events |= POLLIN;
        }
        if have_write && write_set[byte] & bit != 0 {
            events |= POLLOUT;
        }
        if events != 0 || (have_except && except_set[byte] & bit != 0) {
            poll_entries.push((fd as i32, events));
        }
    }
    let timeout = if args[4] == 0 {
        u32::MAX as u64
    } else {
        let size = if pselect { 16 } else { 16 };
        let mut raw = [0u8; 16];
        copy_from_user(&mut raw, args[4], size).map_err(|_| CompatErrno::Fault)?;
        let seconds = u64::from_le_bytes(raw[0..8].try_into().unwrap());
        let fraction = u64::from_le_bytes(raw[8..16].try_into().unwrap());
        let limit = if pselect { 1_000_000_000 } else { 1_000_000 };
        if fraction >= limit {
            return Err(CompatErrno::Invalid);
        }
        seconds
            .checked_mul(1_000)
            .and_then(|millis| {
                millis.checked_add(if pselect {
                    fraction.div_ceil(1_000_000)
                } else {
                    fraction.div_ceil(1_000)
                })
            })
            .filter(|millis| *millis <= i32::MAX as u64)
            .ok_or(CompatErrno::Invalid)?
    };
    let mut temporary_mask = match pselect_mask {
        Some((address, size)) => temporary_signal_mask(pid, address, size)?,
        None => None,
    };
    if poll_entries.is_empty() {
        let result = linux_poll(pid, [0, 0, timeout, 0, 0, 0]);
        if matches!(result, Err(CompatErrno::Interrupted)) {
            if temporary_mask
                .as_mut()
                .is_some_and(|mask| !mask.defer_restore_to_signal_frame())
            {
                return Err(CompatErrno::NoSys);
            }
        }
        return result;
    }
    let mut bytes = alloc::vec![0u8; poll_entries.len() * 8];
    for (index, (fd, events)) in poll_entries.iter().enumerate() {
        let start = index * 8;
        bytes[start..start + 4].copy_from_slice(&fd.to_le_bytes());
        bytes[start + 4..start + 6].copy_from_slice(&events.to_le_bytes());
    }
    let address = proc::linux_alloc_transaction_buffer(pid, &bytes)
        .ok_or(CompatErrno::NoMemory)?;
    let result = linux_poll(
        pid,
        [address, poll_entries.len() as u64, timeout, 0, 0, 0],
    );
    if matches!(result, Err(CompatErrno::Interrupted)) {
        if temporary_mask
            .as_mut()
            .is_some_and(|mask| !mask.defer_restore_to_signal_frame())
        {
            let _ = proc::linux_free_transaction_buffer(pid, address, bytes.len());
            return Err(CompatErrno::NoSys);
        }
    }
    let readback = if result.is_ok() {
        let mut output = alloc::vec![0u8; bytes.len()];
        copy_from_user(&mut output, address, bytes.len()).map_err(|_| CompatErrno::Fault)?;
        Some(output)
    } else {
        None
    };
    let _ = proc::linux_free_transaction_buffer(pid, address, bytes.len());
    let readback = readback.ok_or_else(|| result.unwrap_err())?;
    let mut ready_read = [0u8; FDSET_BYTES];
    let mut ready_write = [0u8; FDSET_BYTES];
    let mut ready_except = [0u8; FDSET_BYTES];
    for (index, (fd, _)) in poll_entries.iter().enumerate() {
        let revents = u16::from_le_bytes(
            readback[index * 8 + 6..index * 8 + 8].try_into().unwrap(),
        );
        let bit = 1u8 << (*fd as usize % 8);
        let byte = *fd as usize / 8;
        if revents & (POLLIN | POLLHUP | POLLERR) != 0 {
            ready_read[byte] |= bit;
        }
        if revents & (POLLOUT | POLLERR) != 0 {
            ready_write[byte] |= bit;
        }
        if revents & (POLLERR | POLLHUP) != 0 {
            ready_except[byte] |= bit;
        }
    }
    if args[1] != 0 {
        copy_to_user(args[1], &ready_read, FDSET_BYTES).map_err(|_| CompatErrno::Fault)?;
    }
    if args[2] != 0 {
        copy_to_user(args[2], &ready_write, FDSET_BYTES).map_err(|_| CompatErrno::Fault)?;
    }
    if args[3] != 0 {
        copy_to_user(args[3], &ready_except, FDSET_BYTES).map_err(|_| CompatErrno::Fault)?;
    }
    result
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
        compat_core::fd::CompatKind::Device => proc::linux_ashmem_state(pid, entry.handle)
            .map(|(size, _, _)| size)
            .unwrap_or(0),
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

fn linux_sync_fd(pid: ObjId, raw_fd: u64, _data_only: bool) -> Result<u64, CompatErrno> {
    let fd = u32::try_from(raw_fd).map_err(|_| CompatErrno::BadFd)?;
    let entry = proc::linux_fd(pid, fd).ok_or(CompatErrno::BadFd)?;
    match entry.kind {
        compat_core::fd::CompatKind::File | compat_core::fd::CompatKind::Directory => Ok(0),
        compat_core::fd::CompatKind::Device
            if proc::linux_ashmem_is_regular(pid, entry.handle).unwrap_or(false) =>
        {
            Ok(0)
        }
        _ => Err(CompatErrno::Invalid),
    }
}

fn linux_syncfs(pid: ObjId, raw_fd: u64) -> Result<u64, CompatErrno> {
    linux_sync_fd(pid, raw_fd, false)
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

/// Implements bounded `sendfile(2)` from one virtual file to a writable stream.
fn linux_sendfile(pid: ObjId, args: [u64; 6]) -> Result<u64, CompatErrno> {
    const MAX_SENDFILE: u64 = 1024 * 1024;
    let output_fd = u32::try_from(args[0]).map_err(|_| CompatErrno::BadFd)?;
    let input_fd = u32::try_from(args[1]).map_err(|_| CompatErrno::BadFd)?;
    let (input_handle, file_offset) =
        proc::linux_file_state(pid, input_fd).ok_or(CompatErrno::BadFd)?;
    let file = crate::linux_vfs::FileId::from_handle(input_handle).ok_or(CompatErrno::BadFd)?;
    let (start, explicit_offset) = if args[2] == 0 {
        (file_offset, false)
    } else {
        let mut raw = [0u8; 8];
        copy_from_user(&mut raw, args[2], 8).map_err(|_| CompatErrno::Fault)?;
        let requested = i64::from_le_bytes(raw);
        if requested < 0 {
            return Err(CompatErrno::Invalid);
        }
        (requested as u64, true)
    };
    let start = usize::try_from(start).map_err(|_| CompatErrno::Invalid)?;
    let bytes = file.bytes();
    let available = bytes.len().saturating_sub(start);
    let take = args[3]
        .min(MAX_SENDFILE)
        .min(compat_core::PIPE_CAPACITY as u64)
        .min(available as u64) as usize;
    if take == 0 {
        return Ok(0);
    }
    let output = proc::linux_fd(pid, output_fd).ok_or(CompatErrno::BadFd)?;
    let io = admit_process_io(pid, take as u64, 1)?;
    let written = match output.kind {
        compat_core::fd::CompatKind::Pipe => {
            if !output
                .rights
                .contains(kernel_core::object::Rights::WRITE)
            {
                return Err(CompatErrno::BadFd);
            }
            linux_pipe_write_buffer(pid, output_fd, output.handle, &bytes[start..start + take])?
        }
        compat_core::fd::CompatKind::Socket => {
            if !output
                .rights
                .contains(kernel_core::object::Rights::WRITE)
            {
                return Err(CompatErrno::BadFd);
            }
            linux_socket_write_buffer(
                pid,
                output_fd,
                output.handle,
                &bytes[start..start + take],
                false,
                false,
                true,
            )? as usize
        }
        compat_core::fd::CompatKind::Device
            if proc::linux_ashmem_is_regular(pid, output.handle) == Some(true) =>
        {
            if !output
                .rights
                .contains(kernel_core::object::Rights::WRITE)
            {
                return Err(CompatErrno::BadFd);
            }
            let output_offset = proc::linux_fd_offset(pid, output_fd).ok_or(CompatErrno::BadFd)?;
            let written = proc::linux_ashmem_write_from(
                pid,
                output.handle,
                output_offset,
                &bytes[start..start + take],
            )
            .map_err(ashmem_compat_error)?;
            if written != 0
                && !proc::set_linux_fd_offset(pid, output_fd, output_offset + written as u64)
            {
                return Err(CompatErrno::BadFd);
            }
            written
        }
        compat_core::fd::CompatKind::File => return Err(CompatErrno::ReadOnly),
        _ => return Err(CompatErrno::Invalid),
    };
    io.commit();
    if written == 0 {
        return Ok(0);
    }
    if explicit_offset {
        copy_to_user(args[2], &(start as u64 + written as u64).to_le_bytes(), 8)
            .map_err(|_| CompatErrno::Fault)?;
    } else if !proc::set_linux_file_offset(pid, input_fd, start as u64 + written as u64) {
        return Err(CompatErrno::BadFd);
    }
    Ok(written as u64)
}

/// Implements bounded `copy_file_range(2)` between virtual files and memfds.
fn linux_copy_file_range(pid: ObjId, args: [u64; 6]) -> Result<u64, CompatErrno> {
    const MAX_COPY: u64 = 1024 * 1024;
    if args[5] != 0 {
        return Err(CompatErrno::Invalid);
    }
    let input_fd = u32::try_from(args[0]).map_err(|_| CompatErrno::BadFd)?;
    let output_fd = u32::try_from(args[2]).map_err(|_| CompatErrno::BadFd)?;
    let input = proc::linux_fd(pid, input_fd).ok_or(CompatErrno::BadFd)?;
    let output = proc::linux_fd(pid, output_fd).ok_or(CompatErrno::BadFd)?;
    let input_offset = if args[1] == 0 {
        proc::linux_fd_offset(pid, input_fd).ok_or(CompatErrno::BadFd)?
    } else {
        let mut raw = [0u8; 8];
        copy_from_user(&mut raw, args[1], 8).map_err(|_| CompatErrno::Fault)?;
        let value = i64::from_le_bytes(raw);
        if value < 0 {
            return Err(CompatErrno::Invalid);
        }
        value as u64
    };
    let output_offset = if args[3] == 0 {
        proc::linux_fd_offset(pid, output_fd).ok_or(CompatErrno::BadFd)?
    } else {
        let mut raw = [0u8; 8];
        copy_from_user(&mut raw, args[3], 8).map_err(|_| CompatErrno::Fault)?;
        let value = i64::from_le_bytes(raw);
        if value < 0 {
            return Err(CompatErrno::Invalid);
        }
        value as u64
    };
    let requested = args[4].min(MAX_COPY);
    let (bytes, available) = match input.kind {
        compat_core::fd::CompatKind::File => {
            if !input
                .rights
                .contains(kernel_core::object::Rights::READ)
            {
                return Err(CompatErrno::BadFd);
            }
            let file =
                crate::linux_vfs::FileId::from_handle(input.handle).ok_or(CompatErrno::BadFd)?;
            let bytes = file.bytes();
            let start = usize::try_from(input_offset).map_err(|_| CompatErrno::Invalid)?;
            let available = bytes.len().saturating_sub(start);
            (
                bytes[start..start + available.min(requested as usize)].to_vec(),
                available,
            )
        }
        compat_core::fd::CompatKind::Device
            if proc::linux_ashmem_is_regular(pid, input.handle) == Some(true) =>
        {
            if !input
                .rights
                .contains(kernel_core::object::Rights::READ)
            {
                return Err(CompatErrno::BadFd);
            }
            let (size, _, _) =
                proc::linux_ashmem_state(pid, input.handle).ok_or(CompatErrno::BadFd)?;
            let available = size.saturating_sub(input_offset);
            let mut bytes = alloc::vec![0u8; available.min(requested) as usize];
            let copied = proc::linux_ashmem_read_from(
                pid,
                input.handle,
                input_offset,
                &mut bytes,
            )
            .map_err(ashmem_compat_error)?;
            bytes.truncate(copied);
            (bytes, available as usize)
        }
        _ => return Err(CompatErrno::Invalid),
    };
    let _ = available;
    if bytes.is_empty() {
        return Ok(0);
    }
    if input.handle == output.handle
        && input_offset < output_offset.saturating_add(bytes.len() as u64)
        && output_offset < input_offset.saturating_add(bytes.len() as u64)
    {
        return Err(CompatErrno::Invalid);
    }
    let io = admit_process_io(pid, bytes.len() as u64, 1)?;
    let written = match output.kind {
        compat_core::fd::CompatKind::Device
            if proc::linux_ashmem_is_regular(pid, output.handle) == Some(true) =>
        {
            if !output
                .rights
                .contains(kernel_core::object::Rights::WRITE)
            {
                return Err(CompatErrno::BadFd);
            }
            proc::linux_ashmem_write_from(pid, output.handle, output_offset, &bytes)
                .map_err(ashmem_compat_error)?
        }
        compat_core::fd::CompatKind::File => return Err(CompatErrno::ReadOnly),
        _ => return Err(CompatErrno::Invalid),
    };
    io.commit();
    if written == 0 {
        return Ok(0);
    }
    if args[1] == 0 {
        if !proc::set_linux_fd_offset(pid, input_fd, input_offset + written as u64) {
            return Err(CompatErrno::BadFd);
        }
    } else {
        copy_to_user(
            args[1],
            &(input_offset + written as u64).to_le_bytes(),
            8,
        )
        .map_err(|_| CompatErrno::Fault)?;
    }
    if args[3] == 0 {
        if !proc::set_linux_fd_offset(pid, output_fd, output_offset + written as u64) {
            return Err(CompatErrno::BadFd);
        }
    } else {
        copy_to_user(
            args[3],
            &(output_offset + written as u64).to_le_bytes(),
            8,
        )
        .map_err(|_| CompatErrno::Fault)?;
    }
    Ok(written as u64)
}

/// Implements `splice(2)` for virtual-file and pipe copy paths.
fn linux_splice(pid: ObjId, args: [u64; 6]) -> Result<u64, CompatErrno> {
    const SPLICE_F_NONBLOCK: u64 = 0x2;
    const SPLICE_F_MOVE: u64 = 0x1;
    const SPLICE_F_MORE: u64 = 0x4;
    const SPLICE_F_GIFT: u64 = 0x8;
    if args[5]
        & !(SPLICE_F_NONBLOCK | SPLICE_F_MOVE | SPLICE_F_MORE | SPLICE_F_GIFT)
        != 0
    {
        return Err(CompatErrno::Invalid);
    }
    let input_fd = u32::try_from(args[0]).map_err(|_| CompatErrno::BadFd)?;
    let output_fd = u32::try_from(args[2]).map_err(|_| CompatErrno::BadFd)?;
    let input = proc::linux_fd(pid, input_fd).ok_or(CompatErrno::BadFd)?;
    let output = proc::linux_fd(pid, output_fd).ok_or(CompatErrno::BadFd)?;
    match output.kind {
        compat_core::fd::CompatKind::Pipe => {}
        compat_core::fd::CompatKind::Device
            if proc::linux_ashmem_is_regular(pid, output.handle) == Some(true) => {}
        compat_core::fd::CompatKind::File => return Err(CompatErrno::ReadOnly),
        _ => return Err(CompatErrno::Invalid),
    }
    if !output
        .rights
        .contains(kernel_core::object::Rights::WRITE)
    {
        return Err(CompatErrno::BadFd);
    }
    let limit = args[4]
        .min(compat_core::PIPE_CAPACITY as u64)
        .min(1024 * 1024) as usize;
    let force_nonblocking = args[5] & SPLICE_F_NONBLOCK != 0;
    let (input_offset, explicit_input_offset, bytes) = match input.kind {
        compat_core::fd::CompatKind::Pipe => {
            if args[1] != 0 {
                return Err(CompatErrno::Invalid);
            }
            if !input
                .rights
                .contains(kernel_core::object::Rights::READ)
            {
                return Err(CompatErrno::BadFd);
            }
            let mut bytes = alloc::vec![0u8; limit];
            let count = linux_pipe_read_buffer(
                pid,
                input_fd,
                input.handle,
                &mut bytes,
                force_nonblocking,
            )?;
            bytes.truncate(count);
            (0, false, bytes)
        }
        compat_core::fd::CompatKind::File => {
            if !input
                .rights
                .contains(kernel_core::object::Rights::READ)
            {
                return Err(CompatErrno::BadFd);
            }
            let file =
                crate::linux_vfs::FileId::from_handle(input.handle).ok_or(CompatErrno::BadFd)?;
            let cursor = proc::linux_fd_offset(pid, input_fd).ok_or(CompatErrno::BadFd)?;
            let explicit = args[1] != 0;
            let offset = if explicit {
                let mut raw = [0u8; 8];
                copy_from_user(&mut raw, args[1], 8).map_err(|_| CompatErrno::Fault)?;
                let value = i64::from_le_bytes(raw);
                if value < 0 {
                    return Err(CompatErrno::Invalid);
                }
                value as u64
            } else {
                cursor
            };
            let start = usize::try_from(offset).map_err(|_| CompatErrno::Invalid)?;
            let bytes = file.bytes();
            let available = bytes.len().saturating_sub(start).min(limit);
            (offset, explicit, bytes[start..start + available].to_vec())
        }
        _ => return Err(CompatErrno::Invalid),
    };
    if bytes.is_empty() {
        return Ok(0);
    }
    let written = match output.kind {
        compat_core::fd::CompatKind::Pipe => {
            if args[3] != 0 {
                return Err(CompatErrno::Invalid);
            }
            if !output
                .rights
                .contains(kernel_core::object::Rights::WRITE)
            {
                return Err(CompatErrno::BadFd);
            }
            linux_pipe_write_buffer_mode(
                pid,
                output_fd,
                output.handle,
                &bytes,
                force_nonblocking,
            )?
        }
        compat_core::fd::CompatKind::Device
            if proc::linux_ashmem_is_regular(pid, output.handle) == Some(true) =>
        {
            if !output
                .rights
                .contains(kernel_core::object::Rights::WRITE)
            {
                return Err(CompatErrno::BadFd);
            }
            let cursor = proc::linux_fd_offset(pid, output_fd).ok_or(CompatErrno::BadFd)?;
            let explicit = args[3] != 0;
            let offset = if explicit {
                let mut raw = [0u8; 8];
                copy_from_user(&mut raw, args[3], 8).map_err(|_| CompatErrno::Fault)?;
                let value = i64::from_le_bytes(raw);
                if value < 0 {
                    return Err(CompatErrno::Invalid);
                }
                value as u64
            } else {
                cursor
            };
            let written =
                proc::linux_ashmem_write_from(pid, output.handle, offset, &bytes)
                    .map_err(ashmem_compat_error)?;
            if written != 0 && explicit {
                copy_to_user(args[3], &(offset + written as u64).to_le_bytes(), 8)
                    .map_err(|_| CompatErrno::Fault)?;
            } else if written != 0
                && !proc::set_linux_fd_offset(pid, output_fd, offset + written as u64)
            {
                return Err(CompatErrno::BadFd);
            }
            written
        }
        compat_core::fd::CompatKind::File => return Err(CompatErrno::ReadOnly),
        _ => return Err(CompatErrno::Invalid),
    };
    if written == 0 {
        return Ok(0);
    }
    if input.kind == compat_core::fd::CompatKind::File {
        if explicit_input_offset {
            copy_to_user(args[1], &(input_offset + written as u64).to_le_bytes(), 8)
                .map_err(|_| CompatErrno::Fault)?;
        } else if !proc::set_linux_fd_offset(pid, input_fd, input_offset + written as u64) {
            return Err(CompatErrno::BadFd);
        }
    }
    Ok(written as u64)
}

/// Implements `vmsplice(2)` from a bounded user iovec array into a pipe.
fn linux_vmsplice(pid: ObjId, args: [u64; 6]) -> Result<u64, CompatErrno> {
    const SPLICE_F_NONBLOCK: u64 = 0x2;
    const SPLICE_F_MOVE: u64 = 0x1;
    const SPLICE_F_MORE: u64 = 0x4;
    const SPLICE_F_GIFT: u64 = 0x8;
    let flags = args[3];
    if flags & !(SPLICE_F_NONBLOCK | SPLICE_F_MOVE | SPLICE_F_MORE | SPLICE_F_GIFT) != 0 {
        return Err(CompatErrno::Invalid);
    }
    let fd = u32::try_from(args[0]).map_err(|_| CompatErrno::BadFd)?;
    let entry = proc::linux_fd(pid, fd).ok_or(CompatErrno::BadFd)?;
    if entry.kind != compat_core::fd::CompatKind::Pipe {
        return Err(CompatErrno::BadFd);
    }
    if !entry
        .rights
        .contains(kernel_core::object::Rights::WRITE)
    {
        return Err(CompatErrno::BadFd);
    }
    let count = usize::try_from(args[2]).map_err(|_| CompatErrno::Invalid)?;
    let vectors = read_message_iovecs(pid, args[1], count, compat_core::PIPE_CAPACITY)?;
    let total = vectors.iter().map(|(_, length)| *length).sum::<usize>();
    let mut bytes = alloc::vec![0u8; total];
    let mut offset = 0usize;
    for (address, length) in vectors {
        proc::read(pid, address, &mut bytes[offset..offset + length])
            .map_err(|_| CompatErrno::Fault)?;
        offset += length;
    }
    linux_pipe_write_buffer_mode(
        pid,
        fd,
        entry.handle,
        &bytes,
        flags & SPLICE_F_NONBLOCK != 0,
    )
    .map(|written| written as u64)
}

/// Duplicates pipe data into another pipe without consuming the source.
fn linux_tee(pid: ObjId, args: [u64; 6]) -> Result<u64, CompatErrno> {
    const SPLICE_F_NONBLOCK: u64 = 0x2;
    const SPLICE_F_MOVE: u64 = 0x1;
    const SPLICE_F_MORE: u64 = 0x4;
    const SPLICE_F_GIFT: u64 = 0x8;
    let flags = args[3];
    if flags & !(SPLICE_F_NONBLOCK | SPLICE_F_MOVE | SPLICE_F_MORE | SPLICE_F_GIFT) != 0 {
        return Err(CompatErrno::Invalid);
    }
    let input_fd = u32::try_from(args[0]).map_err(|_| CompatErrno::BadFd)?;
    let output_fd = u32::try_from(args[1]).map_err(|_| CompatErrno::BadFd)?;
    let input = proc::linux_fd(pid, input_fd).ok_or(CompatErrno::BadFd)?;
    let output = proc::linux_fd(pid, output_fd).ok_or(CompatErrno::BadFd)?;
    if input.kind != compat_core::fd::CompatKind::Pipe
        || output.kind != compat_core::fd::CompatKind::Pipe
        || !input
            .rights
            .contains(kernel_core::object::Rights::READ)
        || !output
            .rights
            .contains(kernel_core::object::Rights::WRITE)
    {
        return Err(CompatErrno::BadFd);
    }
    let limit = args[2]
        .min(compat_core::PIPE_CAPACITY as u64)
        .min(1024 * 1024) as usize;
    let mut bytes = alloc::vec![0u8; limit];
    let endpoint = proc::linux_pipe_endpoint(pid, input.handle).ok_or(CompatErrno::BadFd)?;
    let force_nonblocking = flags & SPLICE_F_NONBLOCK != 0;
    let count = loop {
        match endpoint.peek(&mut bytes) {
            compat_core::PipeRead::Data(count) => break count,
            compat_core::PipeRead::Eof => return Ok(0),
            compat_core::PipeRead::WouldBlock if force_nonblocking => {
                return Err(CompatErrno::TryAgain);
            }
            compat_core::PipeRead::WouldBlock => {
                if proc::current_exiting() || current_signal_pending(pid) {
                    return Err(CompatErrno::Interrupted);
                }
                sched::pause();
            }
        }
    };
    bytes.truncate(count);
    linux_pipe_write_buffer_mode(
        pid,
        output_fd,
        output.handle,
        &bytes,
        force_nonblocking,
    )
    .map(|written| written as u64)
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
            return Err(CompatErrno::Invalid);
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

fn linux_rt_sigpending(pid: ObjId, args: [u64; 6]) -> Result<u64, CompatErrno> {
    if args[1] != 8 {
        return Err(CompatErrno::Invalid);
    }
    let mask = blocked_pending_signal_mask(pid);
    copy_to_user(args[0], &mask.to_le_bytes(), 8).map_err(|_| CompatErrno::Fault)?;
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

/// Reads one fixed-size x86_64 Linux signal mask.
fn read_linux_sigset(address: u64, size: u64) -> Result<u64, CompatErrno> {
    if size != 8 {
        return Err(CompatErrno::Invalid);
    }
    let mut value = [0u8; 8];
    copy_from_user(&mut value, address, 8).map_err(|_| CompatErrno::Fault)?;
    Ok(u64::from_le_bytes(value))
}

/// Writes the signal metadata represented by one pending record.
fn write_linux_siginfo(address: u64, record: SignalFdRecord) -> Result<(), CompatErrno> {
    if address == 0 {
        return Ok(());
    }
    let mut info = [0u8; 128];
    info[0..4].copy_from_slice(&record.signal.to_le_bytes());
    info[8..12].copy_from_slice(&record.code.to_le_bytes());
    info[16..20].copy_from_slice(&record.sender_pid.to_le_bytes());
    info[20..24].copy_from_slice(&record.sender_uid.to_le_bytes());
    info[24..32].copy_from_slice(&record.value.to_le_bytes());
    copy_to_user(address, &info, info.len()).map_err(|_| CompatErrno::Fault)
}

/// Implements `rt_sigsuspend(2)` with temporary mask replacement.
fn linux_rt_sigsuspend(pid: ObjId, args: [u64; 6]) -> Result<u64, CompatErrno> {
    const UNMASKABLE: u64 = (1u64 << 8) | (1u64 << 18);
    let requested = read_linux_sigset(args[0], args[1])?;
    if requested & UNMASKABLE != 0 {
        return Err(CompatErrno::Invalid);
    }
    let old = current_signal_mask(pid).ok_or(CompatErrno::NoSys)?;
    if !set_current_signal_mask(pid, requested)
        || !set_current_sigsuspend_restore_mask(pid, Some(old))
    {
        let _ = set_current_signal_mask(pid, old);
        let _ = set_current_sigsuspend_restore_mask(pid, None);
        return Err(CompatErrno::NoSys);
    }
    loop {
        if proc::current_exiting() {
            let _ = set_current_signal_mask(pid, old);
            let _ = set_current_sigsuspend_restore_mask(pid, None);
            return Err(CompatErrno::Interrupted);
        }
        if current_signal_pending(pid) {
            return Err(CompatErrno::Interrupted);
        }
        sched::pause();
    }
}

/// Implements `rt_sigtimedwait(2)` over the standard-signal pending set.
fn linux_rt_sigtimedwait(pid: ObjId, args: [u64; 6]) -> Result<u64, CompatErrno> {
    const UNMASKABLE: u64 = (1u64 << 8) | (1u64 << 18);
    let requested = read_linux_sigset(args[0], args[3])?;
    if requested & UNMASKABLE != 0 {
        return Err(CompatErrno::Invalid);
    }
    let timeout = if args[2] == 0 {
        None
    } else {
        Some(
            sched::now_ns()
                .checked_add(read_linux_timespec(args[2])?)
                .ok_or(CompatErrno::Invalid)?,
        )
    };
    let old_mask = current_signal_mask(pid).ok_or(CompatErrno::NoSys)?;
    if !set_current_signal_mask(pid, old_mask | requested) {
        return Err(CompatErrno::NoSys);
    }
    let result = loop {
        if proc::current_exiting() {
            break Err(CompatErrno::Interrupted);
        }
        if let Some(record) = take_signalfd_record(pid, requested) {
            break Ok(record);
        }
        if current_signal_pending(pid) {
            break Err(CompatErrno::Interrupted);
        }
        if let Some(deadline) = timeout {
            if sched::now_ns() >= deadline {
                break Err(CompatErrno::TryAgain);
            }
            if sched::sleep_until_ns(deadline).is_err() {
                let ticks = deadline
                    .saturating_sub(sched::now_ns())
                    .div_ceil(crate::hrtime::tick_ns().max(1))
                    .max(1);
                sched::sleep_until(sched::timer_ticks().saturating_add(ticks));
            }
        } else {
            sched::pause();
        }
    };
    if !set_current_signal_mask(pid, old_mask) {
        return Err(CompatErrno::NoSys);
    }
    match result {
        Ok(record) => {
            write_linux_siginfo(args[1], record)?;
            Ok(u64::from(record.signal))
        }
        Err(error) => Err(error),
    }
}

/// Writes the x86_64 Linux `struct stat` fields required by the loader.
///
/// 写入 144 字节、版本稳定的 x86_64 stat；时间和设备字段只表达当前虚拟快照，
/// 不伪造宿主设备身份。
fn write_linux_stat(address: u64, node: crate::linux_vfs::Node) -> Result<(), CompatErrno> {
    let (size, links, mode) = node.stat_metadata();
    write_synthetic_stat(address, node.inode(), links, size, mode)?;
    Ok(())
}

/// Writes x86_64 `stat` for one synthetic file or device identity.
fn write_synthetic_stat(
    address: u64,
    inode: u64,
    links: u64,
    size: u64,
    mode: u32,
) -> Result<(), CompatErrno> {
    const STAT_BYTES: usize = 144;
    let mut stat = [0u8; STAT_BYTES];
    stat[0..8].copy_from_slice(&1u64.to_le_bytes()); // st_dev
    stat[8..16].copy_from_slice(&inode.to_le_bytes()); // st_ino
    stat[16..24].copy_from_slice(&links.to_le_bytes());
    stat[24..28].copy_from_slice(&mode.to_le_bytes());
    stat[48..56].copy_from_slice(&size.to_le_bytes());
    stat[56..64].copy_from_slice(&4096i64.to_le_bytes());
    let blocks = size.div_ceil(512) as i64;
    stat[64..72].copy_from_slice(&blocks.to_le_bytes());
    copy_to_user(address, &stat, STAT_BYTES).map_err(|_| CompatErrno::Fault)
}

fn write_synthetic_statx(
    address: u64,
    inode: u64,
    links: u32,
    size: u64,
    mode: u32,
) -> Result<(), CompatErrno> {
    let mut output = [0u8; 256];
    output[0..4].copy_from_slice(&0x71fu32.to_le_bytes());
    output[4..8].copy_from_slice(&4096u32.to_le_bytes());
    output[16..20].copy_from_slice(&links.to_le_bytes());
    output[28..30].copy_from_slice(&(mode as u16).to_le_bytes());
    output[32..40].copy_from_slice(&inode.to_le_bytes());
    output[40..48].copy_from_slice(&size.to_le_bytes());
    output[48..56].copy_from_slice(&size.div_ceil(512).to_le_bytes());
    copy_to_user(address, &output, output.len()).map_err(|_| CompatErrno::Fault)
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

fn linux_faccessat(
    pid: ObjId,
    args: [u64; 6],
    faccessat2: bool,
) -> Result<u64, CompatErrno> {
    const AT_SYMLINK_NOFOLLOW: u64 = 0x100;
    const AT_EACCESS: u64 = 0x200;
    const AT_EMPTY_PATH: u64 = 0x1000;
    let flags = if faccessat2 { args[3] } else { 0 };
    let mode = args[2];
    if mode & !7 != 0
        || flags & !(AT_SYMLINK_NOFOLLOW | AT_EACCESS | AT_EMPTY_PATH) != 0
        || mode & 2 != 0
    {
        return Err(if mode & 2 != 0 {
            CompatErrno::Access
        } else {
            CompatErrno::Invalid
        });
    }
    let path = linux_c_string(args[1], 4096);
    let node = match path {
        Ok(path) => {
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
            crate::linux_vfs::lookup_node(&resolved).ok_or(CompatErrno::NoEntry)?
        }
        Err(CompatErrno::NoEntry) if flags & AT_EMPTY_PATH != 0 => {
            linux_node_from_fd(pid, args[0])?
        }
        Err(error) => return Err(error),
    };
    if mode & 1 != 0 && matches!(node, crate::linux_vfs::Node::Executable(_)) {
        return Err(CompatErrno::Access);
    }
    Ok(0)
}

fn linux_node_from_fd(pid: ObjId, raw_fd: u64) -> Result<crate::linux_vfs::Node, CompatErrno> {
    let fd = u32::try_from(raw_fd).map_err(|_| CompatErrno::BadFd)?;
    let entry = proc::linux_fd(pid, fd).ok_or(CompatErrno::BadFd)?;
    match entry.kind {
        compat_core::fd::CompatKind::File => crate::linux_vfs::FileId::from_handle(entry.handle)
            .map(crate::linux_vfs::Node::File)
            .ok_or(CompatErrno::BadFd),
        compat_core::fd::CompatKind::Directory => {
            crate::linux_vfs::DirectoryId::from_handle(entry.handle)
                .map(crate::linux_vfs::Node::Directory)
                .ok_or(CompatErrno::BadFd)
        }
        _ => Err(CompatErrno::Access),
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
