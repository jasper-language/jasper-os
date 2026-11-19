//! 进程与线程对象（M3.4 引入，M4.1 接入对象表；架构无关）。
//! Process and thread objects, managed through the kernel object table.
//!
//! # 模型
//! * **进程** = 地址空间（[`VmSpace`]）+ 句柄表 + 它拥有的物理帧 + 线程表 + 退出码 + 可用系统调用集合。资源归进程所有。
//! * **线程** = 调度器里的一个任务 + 对象表中的一个 Task 对象（句柄可见），记着所属进程（带世代的弱回指）。
//!
//! # 引用关系（M4.0 规范 v0.6 第 1、2 节）
//! | 持有者 | 对象 | 种类 |
//! |---|---|---|
//! | 创建者（内核或父进程） | Process | 外部所有权（[`reap`] 时释放） |
//! | 进程句柄表中的句柄 | 所指对象 | 外部所有权（关闭句柄或进程退出时释放） |
//! | 线程执行上下文 | 自己的 Task、所属 Process | 内部引用（线程停止时释放） |
//! | 进程线程表 | 其中的 Task | 内部引用（进程销毁时释放） |
//!
//! # 生命周期
//! 创建 → 运行 → **exited**（最后一个线程停止：确定退出码、关闭整张句柄表）→ 创建者 [`reap`]（释放其所有权）→
//! 全部强引用归零后由清理过程 [`crate::kobj::run_cleanup`] 调用 [`destroy_object`] 或
//! [`destroy_task_object`]：销毁地址空间、归还帧、释放线程表引用（级联）。

use alloc::boxed::Box;
#[cfg(feature = "linux-abi")]
use alloc::collections::VecDeque;
#[cfg(feature = "linux-abi")]
use alloc::sync::Weak;
use alloc::sync::Arc;
use alloc::vec::Vec;

#[cfg(feature = "linux-abi")]
use core::sync::atomic::{AtomicU64, AtomicUsize};
use core::sync::atomic::{AtomicU32, Ordering};

use kernel_core::capability::{CapabilityId, CapabilityLink};
use kernel_core::frame::{PhysFrame, FRAME_SIZE};
use kernel_core::kobj_type::{check_grant, GrantCheck, Kind};
use kernel_core::memory_capability::{
    plan_memory_capability_capacity, BackingIdentity, DynamicMemoryCapabilityTable, MemoryKind,
    MemoryRights,
};
use kernel_core::object::{
    HandleError, HandleId, HandleTable, ObjectId, ObjectRef, ObjectType, Rights,
};
use kernel_core::objtable::ObjId;
use kernel_core::paging::{MapError, MapFlags, VirtPage};
use kernel_core::security::{ApplicationIdentity, IdentityClass};
use kernel_core::security_domain::DomainKey;
#[cfg(feature = "linux-abi")]
use kernel_core::sync::SpinLock;
use kernel_core::usi_request::{Begin as UsiRequestBegin, Ledger as UsiRequestLedger};

use crate::kobj::{self, KObject, TaskObj};
use crate::mm::phys_to_virt;
use crate::mm::space::{in_private_window, VmSpace};
use crate::sync::IrqSpinLock;
use crate::syscall::SyscallSet;
use crate::task::TaskId;
use crate::{arch, kprintln, sched};
#[cfg(feature = "linux-abi")]
use compat_core::fd::{FdDescription, FdTable};
#[cfg(feature = "linux-abi")]
use compat_core::seccomp::{evaluate as evaluate_seccomp, SeccompAction, SeccompInsn};
#[cfg(feature = "linux-abi")]
use compat_core::syscall::{LinuxSyscall, LinuxSyscallSet};
#[cfg(feature = "linux-abi")]
use crate::fscrypt::{FileCipher, FscryptError, Policy as FscryptPolicy};

pub mod spawn;

/// 每个进程句柄表的容量。
pub const HANDLES_PER_PROCESS: usize = crate::config::ACTIVE.objects.handles_per_process;
const USI_REQUEST_SLOTS: usize = 16;
#[cfg(feature = "linux-abi")]
static LINUX_PID_NEXT: AtomicU32 = AtomicU32::new(1);
#[cfg(feature = "linux-abi")]
static NEXT_LINUX_AIO_CONTEXT: AtomicU64 = AtomicU64::new(0x9000_0000_0000_0001);
#[cfg(feature = "linux-abi")]
static NEXT_LINUX_SYSV_SHMEM_ID: AtomicU64 = AtomicU64::new(0x0000_8d00_0000_0001);
static NEXT_WORKLOAD_DOMAIN: AtomicU32 = AtomicU32::new(1);
/// Opaque sentinel used only by the Linux standard-stream compatibility table.
///
/// 仅用于 Linux 标准流兼容表的受控控制台哨兵；它不是可解析的 Jasper 句柄。
#[cfg(feature = "linux-abi")]
pub(crate) const LINUX_CONSOLE_HANDLE: u64 = u64::MAX;
#[cfg(feature = "linux-abi")]
const LINUX_PIPE_HANDLE_BASE: u64 = 0x0000_8000_0000_0000;
#[cfg(feature = "linux-abi")]
const LINUX_SOCKET_HANDLE_BASE: u64 = 0x0000_8100_0000_0000;
#[cfg(feature = "linux-abi")]
const LINUX_ASHMEM_HANDLE_BASE: u64 = 0x0000_8200_0000_0000;
#[cfg(feature = "linux-abi")]
const LINUX_BINDER_HANDLE_BASE: u64 = 0x0000_8300_0000_0000;
#[cfg(feature = "linux-abi")]
const LINUX_ION_DEVICE_HANDLE_BASE: u64 = 0x0000_8400_0000_0000;
#[cfg(feature = "linux-abi")]
const LINUX_EVENTFD_HANDLE_BASE: u64 = 0x0000_8500_0000_0000;
#[cfg(feature = "linux-abi")]
const LINUX_EPOLL_HANDLE_BASE: u64 = 0x0000_8600_0000_0000;
#[cfg(feature = "linux-abi")]
const LINUX_DMA_HEAP_HANDLE_BASE: u64 = 0x0000_8700_0000_0000;
#[cfg(feature = "linux-abi")]
const LINUX_SYNC_FILE_HANDLE_BASE: u64 = 0x0000_8800_0000_0000;
#[cfg(feature = "linux-abi")]
const LINUX_TIMERFD_HANDLE_BASE: u64 = 0x0000_8900_0000_0000;
#[cfg(feature = "linux-abi")]
const LINUX_SIGNALFD_HANDLE_BASE: u64 = 0x0000_8a00_0000_0000;
#[cfg(feature = "linux-abi")]
const LINUX_INOTIFY_HANDLE_BASE: u64 = 0x0000_8b00_0000_0000;
#[cfg(feature = "linux-abi")]
const LINUX_USERFAULT_HANDLE_BASE: u64 = 0x0000_8b80_0000_0000;
#[cfg(feature = "linux-abi")]
const LINUX_MQ_HANDLE_BASE: u64 = 0x0000_8c00_0000_0000;
#[cfg(feature = "linux-abi")]
const LINUX_MOUNT_TREE_HANDLE_BASE: u64 = 0x0000_8e00_0000_0000;
#[cfg(feature = "linux-abi")]
const LINUX_FS_CONTEXT_HANDLE_BASE: u64 = 0x0000_8f00_0000_0000;
const LINUX_LANDLOCK_HANDLE_BASE: u64 = 0x0000_9000_0000_0000;

/// Compatibility-only process state installed by the optional Linux service.
///
/// 可选 Linux 服务安装的进程兼容状态。原生 Jasper 进程不携带 fd 表、
/// Linux pid 或 Linux syscall 权限位。
#[derive(Clone)]
#[cfg(feature = "linux-abi")]
struct LinuxProcessState {
    calls: LinuxSyscallSet,
    fds: FdTable,
    pid: u32,
    ppid: u32,
    pgid: u32,
    sid: u32,
    nice: i32,
    sched_reset_on_fork: bool,
    sched_util_clamp_min: u16,
    sched_util_clamp_max: u16,
    /// CPU ticks from direct children already waited and reaped.
    /// 已等待并回收的直接子进程累计 CPU ticks。
    child_cpu_ticks: u64,
    /// CPU ticks retained from threads that have already exited.
    /// 已退出线程保留的累计 CPU ticks。
    exited_cpu_ticks: u64,
    /// Authorized directory view used for relative AT_FDCWD resolution.
    cwd: crate::linux_vfs::DirectoryId,
    brk: u64,
    mmap_next: u64,
    mmap32_next: u64,
    stack_range: Option<(u64, u64)>,
    /// Linux process-wide signal dispositions.
    signal_actions: [[u64; 4]; 64],
    /// Exact executable path exposed through `/proc/self/exe`.
    exec_path: [u8; 128],
    exec_path_len: usize,
    cap_effective: u64,
    cap_permitted: u64,
    cap_inheritable: u64,
    uid: u32,
    euid: u32,
    suid: u32,
    fsuid: u32,
    gid: u32,
    egid: u32,
    sgid: u32,
    fsgid: u32,
    supplementary_groups: Vec<u32>,
    membarrier_flags: u8,
    umask: u32,
    ioprio: u32,
    personality: u32,
    pdeathsig: u32,
    subreaper: bool,
    termination_signal: u32,
    rlimits: LinuxRlimits,
    aio_contexts: Vec<LinuxAioContext>,
    seccomp_filters: Vec<Vec<SeccompInsn>>,
    seccomp_strict: bool,
    no_new_privs: bool,
    shstk_features: u64,
    shstk_locked: u64,
    mappings: Vec<LinuxMapping>,
    reservations: Vec<LinuxReservation>,
    sealed_ranges: Vec<(u64, u64)>,
    pipes: Vec<LinuxPipeHandle>,
    next_pipe_handle: u64,
    sockets: Vec<LinuxSocketHandle>,
    next_socket_handle: u64,
    ashmem: Vec<LinuxAshmemHandle>,
    next_ashmem_handle: u64,
    binder: Vec<Arc<LinuxBinderHandle>>,
    next_binder_handle: u64,
    ion_devices: Vec<u64>,
    next_ion_device_handle: u64,
    ion_allocations: Vec<LinuxIonAllocation>,
    next_ion_user_handle: u32,
    eventfds: Vec<LinuxEventFdHandle>,
    next_eventfd_handle: u64,
    timerfds: Vec<LinuxTimerFdHandle>,
    next_timerfd_handle: u64,
    signalfds: Vec<LinuxSignalFdHandle>,
    next_signalfd_handle: u64,
    inotifies: Vec<LinuxInotifyHandle>,
    next_inotify_handle: u64,
    userfaultfds: Vec<LinuxUserfaultHandle>,
    next_userfault_handle: u64,
    message_queues: Vec<LinuxMqHandle>,
    next_mq_handle: u64,
    mount_trees: Vec<u64>,
    next_mount_tree_handle: u64,
    fs_contexts: Vec<LinuxFsContextHandle>,
    next_fs_context_handle: u64,
    landlock_rulesets: Vec<LinuxLandlockRulesetHandle>,
    next_landlock_handle: u64,
    epolls: Vec<LinuxEpollHandle>,
    next_epoll_handle: u64,
    iourings: Vec<LinuxIoUringHandle>,
    dma_heaps: Vec<u64>,
    next_dma_heap_handle: u64,
    dmabufs: Vec<u64>,
    sync_files: Vec<LinuxSyncFileHandle>,
    next_sync_file_handle: u64,
    /// Set only on the child side of vfork. The parent task sleeps until the
    /// child commits exec or leaves `Running`.
    /// 仅 vfork 子进程携带；父任务睡眠到子进程提交 exec 或离开 Running。
    vfork_parent: Option<VforkParent>,
}

#[cfg(feature = "linux-abi")]
#[derive(Clone, Copy)]
struct LinuxMapping {
    va: u64,
    flags: MapFlags,
    file: Option<crate::linux_vfs::FileId>,
    file_offset: u64,
    shared_file: bool,
}

#[derive(Clone, Copy)]
#[cfg(feature = "linux-abi")]
struct LinuxReservation {
    start: u64,
    end: u64,
}

#[cfg(feature = "linux-abi")]
#[derive(Clone, Copy)]
pub(crate) struct LinuxCapabilities {
    pub(crate) effective: u64,
    pub(crate) permitted: u64,
    pub(crate) inheritable: u64,
}

#[cfg(feature = "linux-abi")]
#[derive(Clone, Copy)]
pub(crate) struct LinuxCredentials {
    pub(crate) uid: u32,
    pub(crate) euid: u32,
    pub(crate) suid: u32,
    pub(crate) fsuid: u32,
    pub(crate) gid: u32,
    pub(crate) egid: u32,
    pub(crate) sgid: u32,
    pub(crate) fsgid: u32,
}

#[cfg(feature = "linux-abi")]
#[derive(Clone, Copy)]
pub(crate) struct LinuxRlimits {
    pub(crate) stack_current: u64,
    pub(crate) stack_maximum: u64,
    pub(crate) nofile_current: u64,
    pub(crate) nofile_maximum: u64,
}

#[cfg(feature = "linux-abi")]
struct LinuxPipeHandle {
    handle: u64,
    endpoint: Arc<compat_core::PipeEndpoint>,
}

#[cfg(feature = "linux-abi")]
impl Clone for LinuxPipeHandle {
    fn clone(&self) -> Self {
        Self {
            handle: self.handle,
            // `PipeEndpoint::clone` increments the reader/writer census shared by
            // all descriptors. Cloning only the outer `Arc` would make another
            // process closing its copy look like the last endpoint closing.
            endpoint: Arc::new((*self.endpoint).clone()),
        }
    }
}

#[cfg(feature = "linux-abi")]
#[derive(Clone)]
struct LinuxSocketHandle {
    handle: u64,
    endpoint: Arc<compat_core::UnixSocketEndpoint>,
    listener: Option<Arc<UnixListener>>,
    controls: Arc<LinuxSocketControls>,
}

#[cfg(feature = "linux-abi")]
#[derive(Clone)]
struct LinuxAshmemHandle {
    handle: u64,
    buffer: Arc<AshmemBuffer>,
}

#[cfg(feature = "linux-abi")]
struct AshmemBuffer {
    id: u64,
    regular_file: bool,
    size: AtomicU64,
    protection: AtomicU32,
    pins: AtomicU32,
    allow_sealing: AtomicU32,
    seals: AtomicU32,
    verity_enabled: AtomicU32,
    verity_digest: SpinLock<[u8; 32]>,
    verity_descriptor: SpinLock<[u8; 256]>,
    fscrypt: SpinLock<Option<FscryptFileState>>,
    name: SpinLock<([u8; 256], usize)>,
    pages: SpinLock<Vec<Arc<crate::mm::memory_object::Page>>>,
}

#[cfg(feature = "linux-abi")]
#[derive(Clone, Copy)]
struct FscryptFileState {
    policy: FscryptPolicy,
    nonce: [u8; crate::fscrypt::FILE_NONCE_BYTES],
}

/// One bounded shared-page object used by the System V `shm*` ABI.
#[cfg(feature = "linux-abi")]
#[derive(Clone)]
pub(crate) struct LinuxSharedMemoryObject {
    buffer: Arc<AshmemBuffer>,
}

#[cfg(feature = "linux-abi")]
struct LinuxBinderHandle {
    handle: u64,
    max_threads: AtomicU32,
}

#[cfg(feature = "linux-abi")]
#[derive(Clone)]
struct LinuxIonAllocation {
    user_handle: u32,
    buffer: Arc<AshmemBuffer>,
}

#[cfg(feature = "linux-abi")]
#[derive(Clone)]
struct LinuxEventFdHandle {
    handle: u64,
    counter: Arc<SpinLock<u64>>,
    semaphore: bool,
}

#[cfg(feature = "linux-abi")]
#[derive(Clone, Copy)]
pub(crate) struct LinuxTimerFdState {
    pub(crate) clock: u32,
    pub(crate) next: u64,
    pub(crate) interval: u64,
    pub(crate) expirations: u64,
}

#[cfg(feature = "linux-abi")]
#[derive(Clone)]
struct LinuxTimerFdHandle {
    handle: u64,
    state: Arc<SpinLock<LinuxTimerFdState>>,
}

#[cfg(feature = "linux-abi")]
#[derive(Clone)]
struct LinuxSignalFdHandle {
    handle: u64,
    mask: Arc<SpinLock<u64>>,
}

#[cfg(feature = "linux-abi")]
#[derive(Clone, Copy)]
pub(crate) struct LinuxInotifyWatch {
    pub(crate) wd: i32,
    pub(crate) node: crate::linux_vfs::Node,
    pub(crate) mask: u32,
}

#[cfg(feature = "linux-abi")]
#[derive(Clone, Copy)]
pub(crate) struct LinuxInotifyEvent {
    pub(crate) wd: i32,
    pub(crate) mask: u32,
    pub(crate) cookie: u32,
    pub(crate) name: [u8; 256],
    pub(crate) name_len: u8,
}

#[cfg(feature = "linux-abi")]
pub(crate) struct LinuxInotifyState {
    pub(crate) watches: Vec<LinuxInotifyWatch>,
    pub(crate) events: VecDeque<LinuxInotifyEvent>,
    pub(crate) fanotify: bool,
    pub(crate) fanotify_marks: Vec<LinuxFanotifyMark>,
    pub(crate) fanotify_events: VecDeque<LinuxFanotifyEvent>,
    pub(crate) fanotify_event_cloexec: bool,
}

#[cfg(feature = "linux-abi")]
#[derive(Clone, Copy)]
pub(crate) struct LinuxFanotifyMark {
    pub(crate) node: crate::linux_vfs::Node,
    pub(crate) mask: u64,
    pub(crate) scope: u8,
}

#[cfg(feature = "linux-abi")]
#[derive(Clone, Copy)]
pub(crate) struct LinuxFanotifyEvent {
    pub(crate) node: crate::linux_vfs::Node,
    pub(crate) mask: u64,
    pub(crate) pid: i32,
}

#[cfg(feature = "linux-abi")]
#[derive(Clone)]
struct LinuxInotifyHandle {
    handle: u64,
    state: Arc<SpinLock<LinuxInotifyState>>,
}

#[cfg(feature = "linux-abi")]
#[derive(Clone, Copy)]
pub(crate) struct LinuxUserfaultRange {
    pub(crate) start: u64,
    pub(crate) end: u64,
    pub(crate) flags: MapFlags,
}

#[cfg(feature = "linux-abi")]
#[derive(Clone, Copy)]
pub(crate) struct LinuxUserfaultEvent {
    pub(crate) address: u64,
    pub(crate) flags: u64,
    pub(crate) tid: u32,
}

#[cfg(feature = "linux-abi")]
pub(crate) struct LinuxUserfaultState {
    pub(crate) api: bool,
    pub(crate) features: u64,
    pub(crate) ranges: Vec<LinuxUserfaultRange>,
    pub(crate) events: VecDeque<LinuxUserfaultEvent>,
}

#[cfg(feature = "linux-abi")]
#[derive(Clone)]
struct LinuxUserfaultHandle {
    handle: u64,
    state: Arc<SpinLock<LinuxUserfaultState>>,
}

#[cfg(feature = "linux-abi")]
pub(crate) struct LinuxMqMessage {
    pub(crate) priority: u32,
    pub(crate) bytes: Vec<u8>,
}

#[cfg(feature = "linux-abi")]
#[derive(Clone, Copy)]
pub(crate) struct LinuxMqNotification {
    pub(crate) process: ObjId,
    pub(crate) notify: u32,
    pub(crate) signal: u32,
    pub(crate) value: u64,
}

#[cfg(feature = "linux-abi")]
pub(crate) struct LinuxMqState {
    pub(crate) max_messages: usize,
    pub(crate) message_size: usize,
    pub(crate) messages: VecDeque<LinuxMqMessage>,
    pub(crate) blocked_receivers: usize,
    pub(crate) notification: Option<LinuxMqNotification>,
}

#[cfg(feature = "linux-abi")]
pub(crate) struct LinuxMqShared {
    pub(crate) state: SpinLock<LinuxMqState>,
}

#[cfg(feature = "linux-abi")]
#[derive(Clone)]
struct LinuxMqHandle {
    handle: u64,
    queue: Arc<LinuxMqShared>,
}

#[cfg(feature = "linux-abi")]
#[derive(Clone)]
struct LinuxFsContextHandle {
    handle: u64,
    fs_name: [u8; 16],
    fs_name_len: u8,
    created: bool,
}

#[cfg(feature = "linux-abi")]
#[derive(Clone, Copy)]
pub(crate) struct LinuxLandlockRule {
    pub(crate) node: crate::linux_vfs::Node,
    pub(crate) allowed_access: u64,
}

#[cfg(feature = "linux-abi")]
#[derive(Clone)]
pub(crate) struct LinuxLandlockRuleset {
    pub(crate) handled_access_fs: u64,
    pub(crate) rules: Vec<LinuxLandlockRule>,
}

#[cfg(feature = "linux-abi")]
#[derive(Clone)]
struct LinuxLandlockRulesetHandle {
    handle: u64,
    ruleset: Arc<SpinLock<LinuxLandlockRuleset>>,
}

#[cfg(feature = "linux-abi")]
#[derive(Clone, Copy)]
pub(crate) struct LinuxAioEvent {
    pub(crate) data: u64,
    pub(crate) object: u64,
    pub(crate) result: i64,
    pub(crate) result2: i64,
}

#[cfg(feature = "linux-abi")]
pub(crate) struct LinuxAioState {
    pub(crate) max_events: usize,
    pub(crate) events: VecDeque<LinuxAioEvent>,
}

#[cfg(feature = "linux-abi")]
#[derive(Clone)]
struct LinuxAioContext {
    id: u64,
    state: Arc<SpinLock<LinuxAioState>>,
}

#[cfg(feature = "linux-abi")]
#[derive(Clone)]
struct LinuxEpollHandle {
    handle: u64,
    registrations: Arc<SpinLock<Vec<LinuxEpollRegistration>>>,
}

#[cfg(feature = "linux-abi")]
#[derive(Clone, Copy)]
pub(crate) struct LinuxEpollRegistration {
    pub(crate) handle: u64,
    pub(crate) description_id: u64,
    pub(crate) kind: compat_core::fd::CompatKind,
    pub(crate) rights: kernel_core::object::Rights,
    pub(crate) events: u32,
    pub(crate) data: u64,
    pub(crate) armed: bool,
    pub(crate) edge_seen: u32,
}

#[cfg(feature = "linux-abi")]
#[derive(Clone)]
struct LinuxIoUringHandle {
    handle: u64,
    entries: u32,
    cq_entries: u32,
    fixed_files: Vec<Option<FdDescription>>,
}

#[cfg(feature = "linux-abi")]
#[derive(Clone)]
struct LinuxSyncFileHandle {
    handle: u64,
    name: [u8; 32],
    name_len: usize,
}

#[cfg(feature = "linux-abi")]
pub(crate) struct LinuxFdTransfer {
    description: compat_core::FdDescription,
    resource: LinuxFdResource,
}

#[cfg(feature = "linux-abi")]
enum LinuxFdResource {
    Generic,
    Pipe(Arc<compat_core::PipeEndpoint>),
    Ashmem(Arc<AshmemBuffer>),
    Binder(Arc<LinuxBinderHandle>),
    IonDevice,
    EventFd(LinuxEventFdHandle),
    TimerFd(LinuxTimerFdHandle),
    SignalFd(LinuxSignalFdHandle),
    Inotify(Arc<SpinLock<LinuxInotifyState>>),
    MessageQueue(Arc<LinuxMqShared>),
    Socket {
        endpoint: Arc<compat_core::UnixSocketEndpoint>,
        listener: Option<Arc<UnixListener>>,
        controls: Arc<LinuxSocketControls>,
    },
}

#[cfg(feature = "linux-abi")]
struct LinuxControlMessage {
    start: usize,
    fds: Vec<LinuxFdTransfer>,
    credentials: bool,
}

#[cfg(feature = "linux-abi")]
#[derive(Default)]
pub(crate) struct LinuxControlDelivery {
    pub fds: Vec<LinuxFdTransfer>,
    pub credentials: bool,
}

#[cfg(feature = "linux-abi")]
struct LinuxSocketControlQueue {
    messages: SpinLock<VecDeque<LinuxControlMessage>>,
    written: AtomicUsize,
    read: AtomicUsize,
}

#[cfg(feature = "linux-abi")]
struct LinuxSocketControls {
    rx: SpinLock<Option<Arc<LinuxSocketControlQueue>>>,
    tx: SpinLock<Option<Arc<LinuxSocketControlQueue>>>,
    flags: AtomicU32,
}

#[cfg(feature = "linux-abi")]
impl LinuxSocketControls {
    fn empty() -> Arc<Self> {
        Arc::new(Self {
            rx: SpinLock::new(None),
            tx: SpinLock::new(None),
            flags: AtomicU32::new(0),
        })
    }

    fn pair() -> (Arc<Self>, Arc<Self>) {
        let first = Self::empty();
        let second = Self::empty();
        let first_to_second = Arc::new(LinuxSocketControlQueue {
            messages: SpinLock::new(VecDeque::new()),
            written: AtomicUsize::new(0),
            read: AtomicUsize::new(0),
        });
        let second_to_first = Arc::new(LinuxSocketControlQueue {
            messages: SpinLock::new(VecDeque::new()),
            written: AtomicUsize::new(0),
            read: AtomicUsize::new(0),
        });
        *first.tx.lock() = Some(Arc::clone(&first_to_second));
        *second.rx.lock() = Some(Arc::clone(&first_to_second));
        *first.rx.lock() = Some(Arc::clone(&second_to_first));
        *second.tx.lock() = Some(second_to_first);
        (first, second)
    }

    fn attach_peer(&self) -> Option<Arc<Self>> {
        let mut tx = self.tx.lock();
        let mut rx = self.rx.lock();
        if tx.is_some() || rx.is_some() {
            return None;
        }
        let peer = Self::empty();
        let first_to_second = Arc::new(LinuxSocketControlQueue {
            messages: SpinLock::new(VecDeque::new()),
            written: AtomicUsize::new(0),
            read: AtomicUsize::new(0),
        });
        let second_to_first = Arc::new(LinuxSocketControlQueue {
            messages: SpinLock::new(VecDeque::new()),
            written: AtomicUsize::new(0),
            read: AtomicUsize::new(0),
        });
        *tx = Some(Arc::clone(&first_to_second));
        *rx = Some(Arc::clone(&second_to_first));
        *peer.tx.lock() = Some(second_to_first);
        *peer.rx.lock() = Some(first_to_second);
        Some(peer)
    }
}

#[cfg(feature = "linux-abi")]
struct PendingSocketConnection {
    endpoint: Arc<compat_core::UnixSocketEndpoint>,
    controls: Arc<LinuxSocketControls>,
}

#[cfg(feature = "linux-abi")]
struct UnixListener {
    name: compat_core::UnixSocketName,
    owner: compat_core::UnixCredentials,
    listening: AtomicU32,
    backlog: AtomicU32,
    pending: SpinLock<VecDeque<PendingSocketConnection>>,
}

#[cfg(feature = "linux-abi")]
static UNIX_LISTENERS: IrqSpinLock<Vec<Weak<UnixListener>>> =
    IrqSpinLock::ranked(crate::lockorder::LINUX_SOCKET, Vec::new());

#[cfg(feature = "linux-abi")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum LinuxSocketError {
    Invalid,
    IsConnected,
    AddressInUse,
    NotBound,
    NotConnected,
    ConnectionRefused,
    WouldBlock,
    NoSpace,
}

#[cfg(feature = "linux-abi")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum LinuxFdTransferError {
    Invalid,
    NoSpace,
}

#[cfg(feature = "linux-abi")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum LinuxAshmemError {
    Invalid,
    Permission,
    Busy,
    NoMemory,
    NotAshmem,
    Exists,
    NoKey,
    NotSupported,
}

#[cfg(feature = "linux-abi")]
#[derive(Clone, Copy)]
struct VforkParent {
    task: TaskId,
    exec_committed: bool,
}

/// 进程状态。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProcState {
    /// 至少有一个线程存活。
    Running,
    /// 已发起终止（`system.process.exit` 或故障）：句柄表与子进程表已关闭，之后的提交原子失败；
    /// 其余线程在下一个调度点（系统调用入口、从用户态被时钟中断时）停止。退出码已确定。
    Exiting {
        /// 退出码。
        code: i64,
    },
    /// 最后一个线程已停止。
    Exited {
        /// 退出码（最后停止的线程给出；故障终止记为 -1）。
        code: i64,
    },
}

/// 进程对象（存放在内核对象表中）。
pub struct Process {
    name: &'static str,
    space: VmSpace,
    handles: HandleTable<ObjectRef, HANDLES_PER_PROCESS>,
    /// Private mapping references to canonical Memory pages (including ELF and stack pages).
    frames: Vec<Arc<crate::mm::memory_object::Page>>,
    /// SHM mappings retain backing pages independently of the Memory handle.
    shared_maps: Vec<SharedMapping>,
    /// SEC-6 software capabilities bound to this address space.  This is a
    /// provenance mirror, not a second page table.
    memory_caps: DynamicMemoryCapabilityTable,
    memory_account: Arc<crate::mm::memory_quota::Account>,
    /// Optional hard limits for the ordinary process account (`u64::MAX` = no fixed cap).
    memory_owned_limit: u64,
    memory_pin_limit: u64,
    /// Guest RAM ownership is a separate VM budget from ordinary process memory.
    vm_guest_account: Arc<crate::mm::memory_quota::Account>,
    subscription_account: Arc<crate::mm::memory_quota::Account>,
    /// Present only when this process explicitly belongs to the Linux profile.
    /// 仅当进程显式属于 Linux Profile 时存在。
    #[cfg(feature = "linux-abi")]
    linux: Option<LinuxProcessState>,
    /// 页表修改已生效但击落未确认时被永久隔离的帧：不再归还分配器，避免旧 TLB 继续引用后复用。
    /// Frames permanently withheld from the allocator after an unconfirmed shootdown.
    quarantined: Vec<PhysFrame>,
    /// 设备 BAR 映射（不是 RAM：不进入 `frames`，也不由页帧分配器记账）。
    /// Device BAR mappings (not RAM; never entered into `frames`).
    device_maps: Vec<DeviceMapping>,
    /// 线程表：每项持有对应 Task 对象的一个内部引用。
    threads: Vec<ObjId>,
    syscalls: SyscallSet,
    /// 资源配额记账（Ring、在飞请求、Channel 端点）。
    ring_quota: ResourceQuota,
    /// USI request IDs are scoped to this process; completed read-only entries are
    /// bounded and evicted oldest-first.
    usi_requests: UsiRequestLedger<USI_REQUEST_SLOTS>,
    /// 本进程的退出状态（持有一个内部引用）。
    exit_state: ObjId,
    /// 子进程表：每项持有子进程的一个内部引用（父 → 子单向）；本进程退出时释放。
    children: Vec<ObjId>,
    threads_live: u32,
    threads_total: u32,
    state: ProcState,
    /// CPU 组（设置过 CPU 上限时有值；进程的全部线程受同一份上限约束，进程销毁时归还）。
    cpu_group: Option<sched::scheduler::CpuGroupId>,
    /// Workload-bound processes borrow the group owned by the workload registry.
    /// 绑定 Workload 的进程借用工作负载注册表持有的 CPU 组。
    cpu_group_owned: bool,
    /// Native workload membership; quota is charged before each Task is created.
    /// 原生 Workload 归属；创建每个 Task 前先申请配额。
    workload: Option<kernel_core::workload::WorkloadKey>,
    workload_member: Option<u64>,
    /// Authority boundary for user-created native Workload objects. It is
    /// assigned by the kernel and never accepted from the user ABI.
    workload_domain: Option<DomainKey>,
    /// 由用户进程经 `system.process.spawn` 创建：最后一份外部所有权（父进程中的句柄）释放时若仍在运行即被终止。
    kill_on_release: bool,
    /// 创建它的父进程（弱回指，仅用于父进程释放句柄时归还其子进程配额；归还后清空）。
    spawned_by: Option<ObjId>,
    /// 本进程经 `system.process.spawn` 创建、仍持有其句柄的子进程数（配额见 `spawn_abi::MAX_CHILDREN`）。
    spawned_live: u32,
    /// 应用身份（装载时由内核写入，进程不可改；0 = 尚未绑定）。
    ///
    /// 为什么放在进程而不是句柄：身份是"这个进程代表哪个应用"的事实，
    /// 与谁持有它的句柄无关；子进程继承父进程的身份，不能自行更改。
    /// English: application identity, written once by the kernel at load time.
    app: u32,
}

/// 进程的资源配额记账（开发默认值见 `crate::ring`、`crate::ipc` 中的常量）。
/// Per-process resource quota accounting.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ResourceQuota {
    /// 尚未销毁的 Ring 数。
    pub rings: u32,
    /// 跨所有 Ring、尚未销毁（X）的请求控制块数。
    pub in_flight: u32,
    /// 尚未销毁的 Channel 端点数。
    pub endpoints: u32,
    /// 本进程发出、仍在接收队列中的消息体总字节数。
    pub ipc_bytes: u32,
}

struct SharedMapping {
    va: u64,
    page: Arc<crate::mm::memory_object::Page>,
    source: BackingIdentity,
    flags: MapFlags,
}

/// 一次成功的设备 BAR 映射：把创建它的句柄、虚拟区间与物理 BAR 起始地址记在一起。
///
/// 关闭该句柄时只撤销它创建的映射；进程退出时撤销全部映射。物理 BAR 不属于 RAM，
/// 因此撤销映射时不调用页帧分配器。
/// One device BAR mapping owned by a handle; revoked on handle close or process exit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct DeviceMapping {
    /// 创建映射的句柄（含代次；关闭后同值永久无效）。
    handle: HandleId,
    /// 设备 BAR 号。
    bar: u8,
    /// 用户虚拟区间起点（页对齐）。
    va: u64,
    /// 页数。
    pages: u64,
    /// 物理 BAR 起始地址（用于识别同一 BAR 的重复映射）。
    phys: u64,
}

#[cfg(feature = "linux-abi")]
pub(crate) struct ExecAddressSpace {
    space: VmSpace,
    frames: Vec<Arc<crate::mm::memory_object::Page>>,
    shared_maps: Vec<SharedMapping>,
    memory_caps: DynamicMemoryCapabilityTable,
    memory_account: Arc<crate::mm::memory_quota::Account>,
    device_maps: Vec<DeviceMapping>,
}

/// 线程的启动参数（线程首次被调度时读取）。
#[derive(Clone, Copy)]
struct ThreadStart {
    task: TaskId,
    entry: u64,
    stack: u64,
    arg0: u64,
    arg1: u64,
    linux_clone: bool,
    fs_base: Option<u64>,
    linux_fork_regs: Option<[u64; 6]>,
    linux_fork_args: Option<[u64; 6]>,
    clone_rdx: u64,
    clone_r8: u64,
}

/// 运行中线程的身份：任务 → (所属进程, 自己的 Task 对象)。
#[derive(Clone, Copy)]
struct Member {
    task: TaskId,
    process: ObjId,
    task_obj: ObjId,
}

struct Registry {
    starts: Vec<ThreadStart>,
    members: Vec<Member>,
}

static REG: IrqSpinLock<Registry> = IrqSpinLock::ranked(
    crate::lockorder::PROC_REGISTRY,
    Registry {
        starts: Vec::new(),
        members: Vec::new(),
    },
);

/// Reserve process-thread registry storage during boot capacity admission.
///
/// The registry retains its capacity when a thread exits. Pre-admitting both
/// vectors avoids a hidden first-spawn heap growth and keeps the first-program
/// resource baseline exact.
pub fn init_runtime(tasks: usize) -> bool {
    if tasks == 0 {
        return false;
    }
    let mut starts = Vec::new();
    if starts.try_reserve_exact(tasks).is_err() {
        return false;
    }
    let mut members = Vec::new();
    if members.try_reserve_exact(tasks).is_err() {
        return false;
    }
    let mut registry = REG.lock();
    if !registry.starts.is_empty() || !registry.members.is_empty() {
        return false;
    }
    registry.starts = starts;
    registry.members = members;
    true
}
/// 线程任务 ID 分配（与其它演示任务的 ID 区分开）。
static TASK_IDS: kernel_core::object::IdAllocator = kernel_core::object::IdAllocator::new();

/// 进程操作错误。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProcError {
    /// 进程不存在、已死亡或已销毁。
    NoSuchProcess,
    /// 应用身份非法（为 0）或已经绑定过。
    BadApp,
    /// 进程已退出，不能再创建线程。
    Exited,
    /// 地址不在私有窗口或映射失败。
    Map(MapError),
    /// 没有空闲物理帧。
    OutOfFrames,
    /// Allocation or fixed-page reference quota exceeded.
    MemoryQuota,
    /// 调度器槽位已满或对象表已满。
    NoTaskSlot,
    /// 句柄错误。
    Handle(HandleError),
    /// 对象在 v1 不可经 IPC 传递（非叶子对象，M4.0 规范 v0.6 §2.1）。
    NotTransferable,
    /// Revocation committed but its mandatory EventSource notice could not be
    /// published. Callers must treat the security transition as failed closed.
    CapabilityNotice,
}

/// 回收时返回的退出信息。
#[derive(Debug, Clone, Copy)]
pub struct ExitInfo {
    /// 退出码。
    pub code: i64,
    /// 生命周期内创建过的线程数。
    pub threads: u32,
    /// 进程拥有的数据帧数（销毁时归还）。
    pub frames: usize,
    /// 击落超时后永久隔离、不再归还分配器的数据帧数。
    pub quarantined: usize,
}

/// 累计因击落超时而永久隔离的帧数（诊断与验收用）。
static QUARANTINED_FRAMES: AtomicU32 = AtomicU32::new(0);

/// Total frames permanently quarantined after an unconfirmed shootdown.
pub fn quarantined_frames() -> u32 {
    QUARANTINED_FRAMES.load(Ordering::Relaxed)
}

impl Process {
    /// Move frames from the releasable set into the permanent quarantine set.
    /// The handles may be dropped on allocation failure: dropping a frame never returns it to the allocator.
    fn quarantine(&mut self, mut frames: Vec<PhysFrame>) {
        if frames.is_empty() {
            return;
        }
        let n = frames.len() as u32;
        QUARANTINED_FRAMES.fetch_add(n, Ordering::Relaxed);
        if self.quarantined.try_reserve(frames.len()).is_ok() {
            self.quarantined.append(&mut frames);
        }
    }

    fn quarantine_one(&mut self, frame: PhysFrame) {
        QUARANTINED_FRAMES.fetch_add(1, Ordering::Relaxed);
        if self.quarantined.try_reserve(1).is_ok() {
            self.quarantined.push(frame);
        }
    }
}

/// 新建进程（还没有线程）。调用者获得一份外部所有权，最终须经 [`reap`] 释放。
/// 在装载时绑定应用身份；已绑定过则拒绝（身份一经写入不可更改）。
///
/// 只有内核侧的装载路径可以调用；用户态没有对应系统调用，因此"应用自报身份"不成立。
/// English: bind the app identity once at load time; a second bind is refused.
pub fn set_app(pid: ObjId, app: u32) -> Result<(), ProcError> {
    if app == 0 {
        return Err(ProcError::BadApp);
    }
    set_application(pid, ApplicationIdentity::migrated(u64::from(app)))
}

/// 绑定完整应用身份（安装身份 + 内容测量）。内核装载路径专用；用户态无入口。
pub fn set_application(pid: ObjId, application: ApplicationIdentity) -> Result<(), ProcError> {
    if application.stable_id == 0 || application.generation == 0 {
        return Err(ProcError::BadApp);
    }
    crate::kobj::with(|t| {
        match t.get(pid) {
            Ok(crate::kobj::KObject::Process(p))
                if p.app == 0
                    && t.security(pid)
                        .ok()
                        .is_some_and(|context| context.application.is_none()) => {}
            Ok(crate::kobj::KObject::Process(_)) => return Err(ProcError::BadApp),
            _ => return Err(ProcError::NoSuchProcess),
        }
        crate::security::bind_process_application_in(t, pid, application)
            .map_err(|_| ProcError::BadApp)?;
        match t.get_mut(pid) {
            Ok(crate::kobj::KObject::Process(p)) => {
                p.app = crate::security::legacy_app_id(Some(application));
                Ok(())
            }
            _ => Err(ProcError::NoSuchProcess),
        }
    })
}

/// 读取进程的应用身份（0 表示尚未绑定）。
pub fn app(pid: ObjId) -> Option<u32> {
    crate::kobj::with(|t| match t.get(pid) {
        Ok(crate::kobj::KObject::Process(p)) => Some(p.app),
        _ => None,
    })
}

/// 锁内版本：调用者已持有对象表锁时读取进程 `pid` 的应用身份（0 = 未绑定；进程不存在为 `None`）。
///
/// 为什么需要它：发送方身份必须在消息入队的同一把表锁内读取，否则发送方可能在读取与入队之间退出，
/// 接收方看到的就是"另一个时刻"的身份。这里不新增锁、不新增全局状态。
/// In-lock variant of [`app`]; used to stamp the sender identity atomically at enqueue time.
pub(crate) fn app_in(t: &mut kobj::Table, pid: ObjId) -> Option<u32> {
    match t.get(pid) {
        Ok(KObject::Process(p)) => Some(p.app),
        _ => None,
    }
}

/// Returns whether `pid` explicitly belongs to the optional Linux profile.
///
/// 返回进程是否显式属于可选 Linux Profile；进程不存在或已退出时返回 `false`。
#[cfg(feature = "linux-abi")]
pub fn is_linux_process(pid: ObjId) -> bool {
    crate::kobj::with(|t| match t.get(pid) {
        Ok(KObject::Process(p)) => p.linux.is_some(),
        _ => false,
    })
}

/// Checks that `pid` explicitly authorized one Linux syscall.
///
/// 检查进程是否显式授权某个 Linux syscall；权限集合不授予任何 Jasper 原生操作。
#[cfg(feature = "linux-abi")]
pub(crate) fn linux_syscall_allowed(pid: ObjId, call: LinuxSyscall) -> bool {
    crate::kobj::with(|t| {
        matches!(
            t.get(pid),
            Ok(KObject::Process(p))
                if p.linux.as_ref().is_some_and(|linux| linux.calls.contains(call))
        )
    })
}

/// Resolves one Linux fd through the process compatibility table.
///
/// 通过兼容 fd 表解析描述符；返回副本，后续 Handle/Rights 验证仍须执行。
#[cfg(feature = "linux-abi")]
pub(crate) fn linux_fd(pid: ObjId, fd: u32) -> Option<compat_core::fd::FdEntry> {
    crate::kobj::with(|t| match t.get(pid) {
        Ok(KObject::Process(p)) => p.linux.as_ref()?.fds.get_fd(fd),
        _ => None,
    })
}

/// Returns the process-local Linux current directory view.
///
/// 返回进程级 Linux cwd 视图；它只是可选兼容 namespace 中的目录身份。
#[cfg(feature = "linux-abi")]
pub(crate) fn linux_cwd(pid: ObjId) -> Option<crate::linux_vfs::DirectoryId> {
    crate::kobj::with(|t| match t.get(pid) {
        Ok(KObject::Process(p)) => p.linux.as_ref().map(|linux| linux.cwd),
        _ => None,
    })
}

/// Commits a validated Linux current directory.
///
/// 仅提交已解析到兼容 namespace 的目录身份；进程退出后不存在可更新状态。
#[cfg(feature = "linux-abi")]
pub(crate) fn set_linux_cwd(pid: ObjId, cwd: crate::linux_vfs::DirectoryId) -> bool {
    with_proc(pid, |p| {
        let linux = p.linux.as_mut().ok_or(ProcError::Exited)?;
        linux.cwd = cwd;
        Ok(())
    })
    .is_ok()
}

/// Duplicates one current Linux descriptor at or above `minimum`.
///
/// 按当前世代复制 Linux 描述符；新描述符继承 Handle、Rights 与兼容类型。
#[cfg(feature = "linux-abi")]
pub(crate) fn linux_duplicate_fd(
    pid: ObjId,
    fd: u32,
    minimum: u32,
    close_on_exec: bool,
) -> Option<u32> {
    with_proc(pid, |p| {
        let linux = p.linux.as_mut().ok_or(ProcError::Exited)?;
        let duplicate = linux
            .fds
            .duplicate_fd(fd, minimum, close_on_exec)
            .map_err(|_| ProcError::NoTaskSlot)?;
        Ok(duplicate.fd())
    })
    .ok()
}

/// Duplicates one current Linux descriptor onto an exact target descriptor.
///
/// 把当前世代描述符精确复制到目标 fd；目标已占用时原子替换。
#[cfg(feature = "linux-abi")]
pub(crate) fn linux_duplicate_fd_to(
    pid: ObjId,
    fd: u32,
    target: u32,
    close_on_exec: bool,
) -> Option<u32> {
    with_proc(pid, |p| {
        let linux = p.linux.as_mut().ok_or(ProcError::Exited)?;
        let old_target_handle = linux.fds.get_fd(target).map(|entry| entry.handle);
        let duplicate = linux
            .fds
            .duplicate_fd_to(fd, target, close_on_exec)
            .map_err(|_| ProcError::NoTaskSlot)?;
        if let Some(handle) = old_target_handle {
            release_unreferenced_pipe(linux, handle);
        }
        Ok(duplicate.fd())
    })
    .ok()
}

/// Creates a bounded Linux pipe with independently addressable endpoints.
#[cfg(feature = "linux-abi")]
pub(crate) fn linux_pipe2(
    pid: ObjId,
    close_on_exec: bool,
    nonblocking: bool,
) -> Option<(u32, u32)> {
    with_proc(pid, |p| {
        let linux = p.linux.as_mut().ok_or(ProcError::Exited)?;
        let reader_handle = linux.next_pipe_handle;
        let writer_handle = reader_handle.checked_add(1).ok_or(ProcError::NoTaskSlot)?;
        linux.next_pipe_handle = writer_handle.checked_add(1).ok_or(ProcError::NoTaskSlot)?;
        let (reader, writer) = compat_core::PipeEndpoint::pair();
        let reader_fd = linux
            .fds
            .install(
                reader_handle,
                kernel_core::object::Rights::READ,
                compat_core::fd::CompatKind::Pipe,
                close_on_exec,
            )
            .map_err(|_| ProcError::NoTaskSlot)?;
        let writer_fd = match linux.fds.install(
            writer_handle,
            kernel_core::object::Rights::WRITE,
            compat_core::fd::CompatKind::Pipe,
            close_on_exec,
        ) {
            Ok(fd) => fd,
            Err(_) => {
                let _ = linux.fds.close(reader_fd);
                return Err(ProcError::NoTaskSlot);
            }
        };
        if nonblocking {
            const O_NONBLOCK: u32 = 0x800;
            if !linux.fds.set_fd_status_flags(reader_fd.fd(), O_NONBLOCK)
                || !linux.fds.set_fd_status_flags(writer_fd.fd(), O_NONBLOCK)
            {
                let _ = linux.fds.close(reader_fd);
                let _ = linux.fds.close(writer_fd);
                return Err(ProcError::NoTaskSlot);
            }
        }
        linux.pipes.push(LinuxPipeHandle {
            handle: reader_handle,
            endpoint: Arc::new(reader),
        });
        linux.pipes.push(LinuxPipeHandle {
            handle: writer_handle,
            endpoint: Arc::new(writer),
        });
        Ok((reader_fd.fd(), writer_fd.fd()))
    })
    .ok()
}

/// Creates a connected AF_UNIX stream pair with two socket descriptors.
#[cfg(feature = "linux-abi")]
pub(crate) fn linux_socketpair(
    pid: ObjId,
    close_on_exec: bool,
    nonblocking: bool,
) -> Option<(u32, u32)> {
    with_proc(pid, |p| {
        let linux = p.linux.as_mut().ok_or(ProcError::Exited)?;
        if linux.sockets.len() >= 32 {
            return Err(ProcError::NoTaskSlot);
        }
        let first_handle = linux.next_socket_handle;
        let second_handle = first_handle.checked_add(1).ok_or(ProcError::NoTaskSlot)?;
        linux.next_socket_handle = second_handle.checked_add(1).ok_or(ProcError::NoTaskSlot)?;
        let (first, second) = compat_core::UnixSocketEndpoint::pair();
        let credentials = compat_core::UnixCredentials {
            pid: linux.pid,
            uid: compat_core::syscall::LINUX_COMPAT_UID as u32,
            gid: compat_core::syscall::LINUX_COMPAT_GID as u32,
        };
        let _ = first.set_credentials(credentials, credentials);
        let _ = second.set_credentials(credentials, credentials);
        let (first_controls, second_controls) = LinuxSocketControls::pair();
        let rights = kernel_core::object::Rights::READ.union(kernel_core::object::Rights::WRITE);
        let first_fd = linux
            .fds
            .install(
                first_handle,
                rights,
                compat_core::fd::CompatKind::Socket,
                close_on_exec,
            )
            .map_err(|_| ProcError::NoTaskSlot)?;
        let second_fd = match linux.fds.install(
            second_handle,
            rights,
            compat_core::fd::CompatKind::Socket,
            close_on_exec,
        ) {
            Ok(fd) => fd,
            Err(_) => {
                let _ = linux.fds.close(first_fd);
                return Err(ProcError::NoTaskSlot);
            }
        };
        if nonblocking {
            const O_NONBLOCK: u32 = 0x800;
            if !linux.fds.set_fd_status_flags(first_fd.fd(), O_NONBLOCK)
                || !linux.fds.set_fd_status_flags(second_fd.fd(), O_NONBLOCK)
            {
                let _ = linux.fds.close(first_fd);
                let _ = linux.fds.close(second_fd);
                return Err(ProcError::NoTaskSlot);
            }
        }
        linux.sockets.push(LinuxSocketHandle {
            handle: first_handle,
            endpoint: Arc::new(first),
            listener: None,
            controls: first_controls,
        });
        linux.sockets.push(LinuxSocketHandle {
            handle: second_handle,
            endpoint: Arc::new(second),
            listener: None,
            controls: second_controls,
        });
        Ok((first_fd.fd(), second_fd.fd()))
    })
    .ok()
}

/// Creates one unconnected AF_UNIX stream endpoint.
#[cfg(feature = "linux-abi")]
pub(crate) fn linux_socket_create(
    pid: ObjId,
    close_on_exec: bool,
    nonblocking: bool,
) -> Result<u32, LinuxSocketError> {
    with_proc(pid, |p| {
        let linux = p.linux.as_mut().ok_or(ProcError::Exited)?;
        if linux.sockets.len() >= 32 {
            return Err(ProcError::NoTaskSlot);
        }
        linux
            .sockets
            .try_reserve(1)
            .map_err(|_| ProcError::NoTaskSlot)?;
        let handle = linux.next_socket_handle;
        linux.next_socket_handle = handle.checked_add(1).ok_or(ProcError::NoTaskSlot)?;
        let endpoint = Arc::new(compat_core::UnixSocketEndpoint::unconnected());
        let fd = linux
            .fds
            .install(
                handle,
                Rights::READ.union(Rights::WRITE),
                compat_core::fd::CompatKind::Socket,
                close_on_exec,
            )
            .map_err(|_| ProcError::NoTaskSlot)?;
        if nonblocking
            && !linux
                .fds
                .set_fd_status_flags(fd.fd(), compat_core::syscall::LINUX_O_NONBLOCK)
        {
            let _ = linux.fds.close(fd);
            return Err(ProcError::NoTaskSlot);
        }
        linux.sockets.push(LinuxSocketHandle {
            handle,
            endpoint,
            listener: None,
            controls: LinuxSocketControls::empty(),
        });
        Ok(fd.fd())
    })
    .map_err(|_| LinuxSocketError::NoSpace)
}

/// Binds one unconnected AF_UNIX endpoint to a bounded abstract or pathname
/// identity in the Linux compatibility namespace.
#[cfg(feature = "linux-abi")]
pub(crate) fn linux_socket_bind(
    pid: ObjId,
    handle: u64,
    name: compat_core::UnixSocketName,
) -> Result<(), LinuxSocketError> {
    crate::kobj::with(|t| match t.get_mut(pid) {
        Ok(KObject::Process(p)) => {
            let linux = p.linux.as_mut().ok_or(LinuxSocketError::Invalid)?;
            let socket = linux
                .sockets
                .iter_mut()
                .find(|socket| socket.handle == handle)
                .ok_or(LinuxSocketError::NotConnected)?;
            if socket.listener.is_some() {
                return Err(LinuxSocketError::Invalid);
            }
            if socket.endpoint.is_connected() {
                return Err(LinuxSocketError::IsConnected);
            }
            let mut listeners = UNIX_LISTENERS.lock();
            listeners.retain(|listener| listener.strong_count() != 0);
            if listeners
                .iter()
                .filter_map(Weak::upgrade)
                .any(|listener| listener.name == name)
            {
                return Err(LinuxSocketError::AddressInUse);
            }
            listeners
                .try_reserve(1)
                .map_err(|_| LinuxSocketError::NoSpace)?;
            let listener = Arc::new(UnixListener {
                name,
                owner: compat_core::UnixCredentials {
                    pid: linux.pid,
                    uid: compat_core::syscall::LINUX_COMPAT_UID as u32,
                    gid: compat_core::syscall::LINUX_COMPAT_GID as u32,
                },
                listening: AtomicU32::new(0),
                backlog: AtomicU32::new(1),
                pending: SpinLock::new(VecDeque::new()),
            });
            listeners.push(Arc::downgrade(&listener));
            socket.listener = Some(listener);
            Ok(())
        }
        _ => Err(LinuxSocketError::Invalid),
    })
}

/// Enables accept processing for one bound AF_UNIX endpoint.
#[cfg(feature = "linux-abi")]
pub(crate) fn linux_socket_listen(
    pid: ObjId,
    handle: u64,
    backlog: usize,
) -> Result<(), LinuxSocketError> {
    crate::kobj::with(|t| match t.get_mut(pid) {
        Ok(KObject::Process(p)) => {
            let linux = p.linux.as_mut().ok_or(LinuxSocketError::Invalid)?;
            let socket = linux
                .sockets
                .iter()
                .find(|socket| socket.handle == handle)
                .ok_or(LinuxSocketError::NotConnected)?;
            if socket.endpoint.is_connected() {
                return Err(LinuxSocketError::IsConnected);
            }
            let listener = socket.listener.as_ref().ok_or(LinuxSocketError::NotBound)?;
            let backlog = backlog.clamp(1, 128);
            listener
                .pending
                .lock()
                .try_reserve(backlog)
                .map_err(|_| LinuxSocketError::NoSpace)?;
            listener.backlog.store(backlog as u32, Ordering::Release);
            listener.listening.store(1, Ordering::Release);
            Ok(())
        }
        _ => Err(LinuxSocketError::Invalid),
    })
}

/// Connects one unconnected client endpoint to a bound listing endpoint.
#[cfg(feature = "linux-abi")]
pub(crate) fn linux_socket_connect(
    pid: ObjId,
    handle: u64,
    name: compat_core::UnixSocketName,
) -> Result<(), LinuxSocketError> {
    crate::kobj::with(|t| match t.get_mut(pid) {
        Ok(KObject::Process(p)) => {
            let linux = p.linux.as_mut().ok_or(LinuxSocketError::Invalid)?;
            let socket = linux
                .sockets
                .iter()
                .find(|socket| socket.handle == handle)
                .ok_or(LinuxSocketError::NotConnected)?;
            if socket.endpoint.is_connected() {
                return Err(LinuxSocketError::IsConnected);
            }
            if socket
                .listener
                .as_ref()
                .is_some_and(|listener| listener.listening.load(Ordering::Acquire) != 0)
            {
                return Err(LinuxSocketError::Invalid);
            }
            let local_name = socket
                .listener
                .as_ref()
                .map(|listener| listener.name)
                .unwrap_or_else(compat_core::UnixSocketName::empty);
            let listener = {
                let mut listeners = UNIX_LISTENERS.lock();
                listeners.retain(|listener| listener.strong_count() != 0);
                listeners
                    .iter()
                    .filter_map(Weak::upgrade)
                    .find(|listener| listener.name == name)
            }
            .ok_or(LinuxSocketError::ConnectionRefused)?;
            if listener.listening.load(Ordering::Acquire) == 0 {
                return Err(LinuxSocketError::ConnectionRefused);
            }
            let mut pending = listener.pending.lock();
            if pending.len() >= listener.backlog.load(Ordering::Acquire) as usize {
                return Err(LinuxSocketError::ConnectionRefused);
            }
            pending
                .try_reserve(1)
                .map_err(|_| LinuxSocketError::NoSpace)?;
            let accepted = Arc::new(compat_core::UnixSocketEndpoint::unconnected());
            if !compat_core::UnixSocketEndpoint::connect_pair(&socket.endpoint, &accepted) {
                return Err(LinuxSocketError::Invalid);
            }
            if !socket.endpoint.set_names(local_name, name) || !accepted.set_names(name, local_name)
            {
                return Err(LinuxSocketError::Invalid);
            }
            let client_credentials = compat_core::UnixCredentials {
                pid: linux.pid,
                uid: compat_core::syscall::LINUX_COMPAT_UID as u32,
                gid: compat_core::syscall::LINUX_COMPAT_GID as u32,
            };
            if !socket
                .endpoint
                .set_credentials(client_credentials, listener.owner)
                || !accepted.set_credentials(listener.owner, client_credentials)
            {
                return Err(LinuxSocketError::Invalid);
            }
            let accepted_controls = socket
                .controls
                .attach_peer()
                .ok_or(LinuxSocketError::Invalid)?;
            pending.push_back(PendingSocketConnection {
                endpoint: accepted,
                controls: accepted_controls,
            });
            Ok(())
        }
        _ => Err(LinuxSocketError::Invalid),
    })
}

/// Removes one completed connection from a listening socket and installs the
/// server endpoint as a new descriptor.
#[cfg(feature = "linux-abi")]
pub(crate) fn linux_socket_accept(
    pid: ObjId,
    handle: u64,
    close_on_exec: bool,
    nonblocking: bool,
) -> Result<u32, LinuxSocketError> {
    crate::kobj::with(|t| match t.get_mut(pid) {
        Ok(KObject::Process(p)) => {
            let linux = p.linux.as_mut().ok_or(LinuxSocketError::Invalid)?;
            if linux.sockets.len() >= 32 {
                return Err(LinuxSocketError::NoSpace);
            }
            let listener = linux
                .sockets
                .iter()
                .find(|socket| socket.handle == handle)
                .and_then(|socket| socket.listener.as_ref())
                .cloned()
                .ok_or(LinuxSocketError::NotBound)?;
            if listener.listening.load(Ordering::Acquire) == 0 {
                return Err(LinuxSocketError::Invalid);
            }
            let PendingSocketConnection {
                endpoint: accepted,
                controls: accepted_controls,
            } = listener
                .pending
                .lock()
                .pop_front()
                .ok_or(LinuxSocketError::WouldBlock)?;
            linux
                .sockets
                .try_reserve(1)
                .map_err(|_| LinuxSocketError::NoSpace)?;
            let handle = linux
                .next_socket_handle
                .checked_add(1)
                .ok_or(LinuxSocketError::NoSpace)?;
            let installed_handle = linux.next_socket_handle;
            let fd = linux
                .fds
                .install(
                    installed_handle,
                    Rights::READ.union(Rights::WRITE),
                    compat_core::fd::CompatKind::Socket,
                    close_on_exec,
                )
                .map_err(|_| LinuxSocketError::NoSpace)?;
            if nonblocking
                && !linux
                    .fds
                    .set_fd_status_flags(fd.fd(), compat_core::syscall::LINUX_O_NONBLOCK)
            {
                let _ = linux.fds.close(fd);
                return Err(LinuxSocketError::NoSpace);
            }
            linux.next_socket_handle = handle;
            linux.sockets.push(LinuxSocketHandle {
                handle: installed_handle,
                endpoint: accepted,
                listener: None,
                controls: accepted_controls,
            });
            Ok(fd.fd())
        }
        _ => Err(LinuxSocketError::Invalid),
    })
}

/// Resolves one pipe endpoint without incrementing its process-lifetime reference.
#[cfg(feature = "linux-abi")]
pub(crate) fn linux_pipe_endpoint(
    pid: ObjId,
    handle: u64,
) -> Option<Arc<compat_core::PipeEndpoint>> {
    crate::kobj::with(|t| match t.get(pid) {
        Ok(KObject::Process(p)) => p
            .linux
            .as_ref()?
            .pipes
            .iter()
            .find(|pipe| pipe.handle == handle)
            .map(|pipe| Arc::clone(&pipe.endpoint)),
        _ => None,
    })
}

/// Resolves one AF_UNIX stream endpoint without changing its lifetime.
#[cfg(feature = "linux-abi")]
pub(crate) fn linux_socket_endpoint(
    pid: ObjId,
    handle: u64,
) -> Option<Arc<compat_core::UnixSocketEndpoint>> {
    crate::kobj::with(|t| match t.get(pid) {
        Ok(KObject::Process(p)) => p
            .linux
            .as_ref()?
            .sockets
            .iter()
            .find(|socket| socket.handle == handle)
            .map(|socket| Arc::clone(&socket.endpoint)),
        _ => None,
    })
}

/// Returns the per-socket compatibility option flags.
#[cfg(feature = "linux-abi")]
pub(crate) fn linux_socket_option_flags(pid: ObjId, handle: u64) -> Option<u32> {
    crate::kobj::with(|t| match t.get(pid) {
        Ok(KObject::Process(p)) => p
            .linux
            .as_ref()?
            .sockets
            .iter()
            .find(|socket| socket.handle == handle)
            .map(|socket| socket.controls.flags.load(Ordering::Acquire)),
        _ => None,
    })
}

/// Updates the per-socket compatibility option flags.
#[cfg(feature = "linux-abi")]
pub(crate) fn linux_set_socket_option_flags(pid: ObjId, handle: u64, flags: u32) -> bool {
    crate::kobj::with(|t| match t.get(pid) {
        Ok(KObject::Process(p)) => p
            .linux
            .as_ref()
            .and_then(|linux| {
                linux
                    .sockets
                    .iter()
                    .find(|socket| socket.handle == handle)
            })
            .is_some_and(|socket| {
                socket.controls.flags.store(flags, Ordering::Release);
                true
            }),
        _ => false,
    })
}

/// Reports whether one socket accepts connections.
#[cfg(feature = "linux-abi")]
pub(crate) fn linux_socket_is_listening(pid: ObjId, handle: u64) -> Option<bool> {
    crate::kobj::with(|t| match t.get(pid) {
        Ok(KObject::Process(p)) => p
            .linux
            .as_ref()?
            .sockets
            .iter()
            .find(|socket| socket.handle == handle)
            .map(|socket| {
                socket
                    .listener
                    .as_ref()
                    .is_some_and(|listener| listener.listening.load(Ordering::Acquire) != 0)
            }),
        _ => None,
    })
}

/// Captures one descriptor for an SCM_RIGHTS handoff, retaining the shared
/// open-file description and any process-owned stream resource it references.
#[cfg(feature = "linux-abi")]
pub(crate) fn linux_capture_fd_transfer(
    pid: ObjId,
    fd: u32,
) -> Result<LinuxFdTransfer, LinuxFdTransferError> {
    crate::kobj::with(|t| match t.get(pid) {
        Ok(KObject::Process(p)) => {
            let linux = p.linux.as_ref().ok_or(LinuxFdTransferError::Invalid)?;
            let entry = linux
                .fds
                .get_fd(fd)
                .ok_or(LinuxFdTransferError::Invalid)?;
            let description = linux
                .fds
                .description_fd(fd)
                .ok_or(LinuxFdTransferError::Invalid)?;
            let resource = match entry.kind {
                compat_core::fd::CompatKind::Pipe => {
                    let endpoint = linux
                        .pipes
                        .iter()
                        .find(|pipe| pipe.handle == entry.handle)
                        .map(|pipe| Arc::clone(&pipe.endpoint))
                        .ok_or(LinuxFdTransferError::Invalid)?;
                    LinuxFdResource::Pipe(endpoint)
                }
                compat_core::fd::CompatKind::Socket => {
                    let socket = linux
                        .sockets
                        .iter()
                        .find(|socket| socket.handle == entry.handle)
                        .ok_or(LinuxFdTransferError::Invalid)?;
                    LinuxFdResource::Socket {
                        endpoint: Arc::clone(&socket.endpoint),
                        listener: socket.listener.as_ref().map(Arc::clone),
                        controls: Arc::clone(&socket.controls),
                    }
                }
                compat_core::fd::CompatKind::Event => {
                    let eventfd = linux
                        .eventfds
                        .iter()
                        .find(|eventfd| eventfd.handle == entry.handle)
                        .cloned()
                        .ok_or(LinuxFdTransferError::Invalid)?;
                    LinuxFdResource::EventFd(eventfd)
                }
                compat_core::fd::CompatKind::Timer => {
                    let timerfd = linux
                        .timerfds
                        .iter()
                        .find(|timerfd| timerfd.handle == entry.handle)
                        .cloned()
                        .ok_or(LinuxFdTransferError::Invalid)?;
                    LinuxFdResource::TimerFd(timerfd)
                }
                compat_core::fd::CompatKind::Signal => {
                    let signalfd = linux
                        .signalfds
                        .iter()
                        .find(|signalfd| signalfd.handle == entry.handle)
                        .cloned()
                        .ok_or(LinuxFdTransferError::Invalid)?;
                    LinuxFdResource::SignalFd(signalfd)
                }
                compat_core::fd::CompatKind::Inotify => {
                    let inotify = linux
                        .inotifies
                        .iter()
                        .find(|inotify| inotify.handle == entry.handle)
                        .map(|inotify| Arc::clone(&inotify.state))
                        .ok_or(LinuxFdTransferError::Invalid)?;
                    LinuxFdResource::Inotify(inotify)
                }
                compat_core::fd::CompatKind::MessageQueue => {
                    let queue = linux
                        .message_queues
                        .iter()
                        .find(|queue| queue.handle == entry.handle)
                        .map(|queue| Arc::clone(&queue.queue))
                        .ok_or(LinuxFdTransferError::Invalid)?;
                    LinuxFdResource::MessageQueue(queue)
                }
                compat_core::fd::CompatKind::Device
                    if entry.handle >= LINUX_ASHMEM_HANDLE_BASE =>
                {
                    let buffer = linux
                        .ashmem
                        .iter()
                        .find(|ashmem| ashmem.handle == entry.handle)
                        .map(|ashmem| Arc::clone(&ashmem.buffer))
                        .ok_or(LinuxFdTransferError::Invalid)?;
                    LinuxFdResource::Ashmem(buffer)
                }
                compat_core::fd::CompatKind::Device
                    if entry.handle >= LINUX_BINDER_HANDLE_BASE =>
                {
                    let binder = linux
                        .binder
                        .iter()
                        .find(|binder| binder.handle == entry.handle)
                        .map(Arc::clone)
                        .ok_or(LinuxFdTransferError::Invalid)?;
                    LinuxFdResource::Binder(binder)
                }
                compat_core::fd::CompatKind::Device
                    if entry.handle >= LINUX_ION_DEVICE_HANDLE_BASE
                        && linux.ion_devices.contains(&entry.handle) =>
                {
                    LinuxFdResource::IonDevice
                }
                _ => LinuxFdResource::Generic,
            };
            Ok(LinuxFdTransfer {
                description,
                resource,
            })
        }
        _ => Err(LinuxFdTransferError::Invalid),
    })
}

/// Installs one SCM_RIGHTS transfer into a fresh descriptor generation while
/// retaining the original open-file offset and status flags.
#[cfg(feature = "linux-abi")]
pub(crate) fn linux_install_fd_transfer(
    pid: ObjId,
    transfer: LinuxFdTransfer,
    close_on_exec: bool,
) -> Result<u32, LinuxFdTransferError> {
    crate::kobj::with(|t| match t.get_mut(pid) {
        Ok(KObject::Process(p)) => {
            let linux = p.linux.as_mut().ok_or(LinuxFdTransferError::Invalid)?;
            let LinuxFdTransfer {
                description,
                resource,
            } = transfer;
            let pending_inotify = match &resource {
                LinuxFdResource::Inotify(watches) => Some(Arc::clone(watches)),
                _ => None,
            };
            let inotify_handle = if pending_inotify.is_some() {
                linux
                    .inotifies
                    .try_reserve(1)
                    .map_err(|_| LinuxFdTransferError::NoSpace)?;
                Some(linux.next_inotify_handle)
            } else {
                None
            };
            let pending_mq = match &resource {
                LinuxFdResource::MessageQueue(queue) => Some(Arc::clone(queue)),
                _ => None,
            };
            let mq_handle = if pending_mq.is_some() {
                linux
                    .message_queues
                    .try_reserve(1)
                    .map_err(|_| LinuxFdTransferError::NoSpace)?;
                Some(linux.next_mq_handle)
            } else {
                None
            };
            let (
                handle,
                pending_pipe,
                pending_ashmem,
                pending_binder,
                pending_ion_device,
                pending_eventfd,
                pending_timerfd,
                pending_signalfd,
                pending_socket,
            ) = match resource {
                LinuxFdResource::Generic => {
                    (
                        description.entry.handle,
                        None,
                        None,
                        None,
                        false,
                        None,
                        None,
                        None,
                        None,
                    )
                }
                LinuxFdResource::Pipe(endpoint) => {
                    linux
                        .pipes
                        .try_reserve(1)
                        .map_err(|_| LinuxFdTransferError::NoSpace)?;
                    (
                        linux.next_pipe_handle,
                        Some(endpoint),
                        None,
                        None,
                        false,
                        None,
                        None,
                        None,
                        None,
                    )
                }
                LinuxFdResource::Ashmem(buffer) => {
                    linux
                        .ashmem
                        .try_reserve(1)
                        .map_err(|_| LinuxFdTransferError::NoSpace)?;
                    (
                        linux.next_ashmem_handle,
                        None,
                        Some(buffer),
                        None,
                        false,
                        None,
                        None,
                        None,
                        None,
                    )
                }
                LinuxFdResource::Binder(binder) => {
                    linux
                        .binder
                        .try_reserve(1)
                        .map_err(|_| LinuxFdTransferError::NoSpace)?;
                    (
                        linux.next_binder_handle,
                        None,
                        None,
                        Some(binder),
                        false,
                        None,
                        None,
                        None,
                        None,
                    )
                }
                LinuxFdResource::IonDevice => {
                    linux
                        .ion_devices
                        .try_reserve(1)
                        .map_err(|_| LinuxFdTransferError::NoSpace)?;
                    (
                        linux.next_ion_device_handle,
                        None,
                        None,
                        None,
                        true,
                        None,
                        None,
                        None,
                        None,
                    )
                }
                LinuxFdResource::EventFd(eventfd) => {
                    linux
                        .eventfds
                        .try_reserve(1)
                        .map_err(|_| LinuxFdTransferError::NoSpace)?;
                    (
                        linux.next_eventfd_handle,
                        None,
                        None,
                        None,
                        false,
                        Some(eventfd),
                        None,
                        None,
                        None,
                    )
                }
                LinuxFdResource::TimerFd(timerfd) => {
                    linux
                        .timerfds
                        .try_reserve(1)
                        .map_err(|_| LinuxFdTransferError::NoSpace)?;
                    (
                        linux.next_timerfd_handle,
                        None,
                        None,
                        None,
                        false,
                        None,
                        Some(timerfd),
                        None,
                        None,
                    )
                }
                LinuxFdResource::SignalFd(signalfd) => {
                    linux
                        .signalfds
                        .try_reserve(1)
                        .map_err(|_| LinuxFdTransferError::NoSpace)?;
                    (
                        linux.next_signalfd_handle,
                        None,
                        None,
                        None,
                        false,
                        None,
                        None,
                        Some(signalfd),
                        None,
                    )
                }
                LinuxFdResource::Inotify(_) => {
                    (
                        inotify_handle.ok_or(LinuxFdTransferError::NoSpace)?,
                        None,
                        None,
                        None,
                        false,
                        None,
                        None,
                        None,
                        None,
                    )
                }
                LinuxFdResource::MessageQueue(_) => {
                    (
                        mq_handle.ok_or(LinuxFdTransferError::NoSpace)?,
                        None,
                        None,
                        None,
                        false,
                        None,
                        None,
                        None,
                        None,
                    )
                }
                LinuxFdResource::Socket {
                    endpoint,
                    listener,
                    controls,
                } => {
                    linux
                        .sockets
                        .try_reserve(1)
                        .map_err(|_| LinuxFdTransferError::NoSpace)?;
                    (
                        linux.next_socket_handle,
                        None,
                        None,
                        None,
                        false,
                        None,
                        None,
                        None,
                        Some((endpoint, listener, controls)),
                    )
                }
            };
            if handle == 0 {
                return Err(LinuxFdTransferError::NoSpace);
            }
            let fd = linux
                .fds
                .install_description(description.with_handle(handle), close_on_exec)
                .map_err(|_| LinuxFdTransferError::NoSpace)?;
            if let Some(endpoint) = pending_pipe {
                let next = handle
                    .checked_add(1)
                    .ok_or(LinuxFdTransferError::NoSpace)?;
                linux.next_pipe_handle = next;
                linux.pipes.push(LinuxPipeHandle { handle, endpoint });
            }
            if let Some(buffer) = pending_ashmem {
                let next = handle
                    .checked_add(1)
                    .ok_or(LinuxFdTransferError::NoSpace)?;
                linux.next_ashmem_handle = next;
                linux.ashmem.push(LinuxAshmemHandle { handle, buffer });
            }
            if let Some(binder) = pending_binder {
                let next = handle
                    .checked_add(1)
                    .ok_or(LinuxFdTransferError::NoSpace)?;
                linux.next_binder_handle = next;
                linux.binder.push(Arc::new(LinuxBinderHandle {
                    handle,
                    max_threads: AtomicU32::new(binder.max_threads.load(Ordering::Acquire)),
                }));
            }
            if pending_ion_device {
                let next = handle
                    .checked_add(1)
                    .ok_or(LinuxFdTransferError::NoSpace)?;
                linux.next_ion_device_handle = next;
                linux.ion_devices.push(handle);
            }
            if let Some(mut eventfd) = pending_eventfd {
                let next = handle
                    .checked_add(1)
                    .ok_or(LinuxFdTransferError::NoSpace)?;
                eventfd.handle = handle;
                linux.next_eventfd_handle = next;
                linux.eventfds.push(eventfd);
            }
            if let Some(mut timerfd) = pending_timerfd {
                let next = handle
                    .checked_add(1)
                    .ok_or(LinuxFdTransferError::NoSpace)?;
                timerfd.handle = handle;
                linux.next_timerfd_handle = next;
                linux.timerfds.push(timerfd);
            }
            if let Some(mut signalfd) = pending_signalfd {
                let next = handle
                    .checked_add(1)
                    .ok_or(LinuxFdTransferError::NoSpace)?;
                signalfd.handle = handle;
                linux.next_signalfd_handle = next;
                linux.signalfds.push(signalfd);
            }
            if let Some(state) = pending_inotify {
                let next = handle
                    .checked_add(1)
                    .ok_or(LinuxFdTransferError::NoSpace)?;
                linux.next_inotify_handle = next;
                linux.inotifies.push(LinuxInotifyHandle { handle, state });
            }
            if let Some(queue) = pending_mq {
                let next = handle
                    .checked_add(1)
                    .ok_or(LinuxFdTransferError::NoSpace)?;
                linux.next_mq_handle = next;
                linux.message_queues.push(LinuxMqHandle { handle, queue });
            }
            if let Some((endpoint, listener, controls)) = pending_socket {
                let next = handle
                    .checked_add(1)
                    .ok_or(LinuxFdTransferError::NoSpace)?;
                linux.next_socket_handle = next;
                linux.sockets.push(LinuxSocketHandle {
                    handle,
                    endpoint,
                    listener,
                    controls,
                });
            }
            Ok(fd.fd())
        }
        _ => Err(LinuxFdTransferError::Invalid),
    })
}

/// Queues ancillary descriptors to the peer after a data-bearing sendmsg.
#[cfg(feature = "linux-abi")]
pub(crate) fn linux_socket_queue_control(
    pid: ObjId,
    handle: u64,
    bytes: usize,
    fds: Vec<LinuxFdTransfer>,
    credentials: bool,
) -> Result<(), LinuxSocketError> {
    if bytes == 0 || (fds.is_empty() && !credentials) {
        return Err(LinuxSocketError::Invalid);
    }
    let controls = crate::kobj::with(|t| match t.get(pid) {
        Ok(KObject::Process(p)) => p
            .linux
            .as_ref()?
            .sockets
            .iter()
            .find(|socket| socket.handle == handle)
            .map(|socket| Arc::clone(&socket.controls)),
        _ => None,
    })
    .ok_or(LinuxSocketError::NotConnected)?;
    let queue = controls
        .tx
        .lock()
        .as_ref()
        .map(Arc::clone)
        .ok_or(LinuxSocketError::NotConnected)?;
    let mut messages = queue.messages.lock();
    messages
        .try_reserve(1)
        .map_err(|_| LinuxSocketError::NoSpace)?;
    let start = queue.written.fetch_add(bytes, Ordering::AcqRel);
    messages.push_back(LinuxControlMessage {
        start,
        fds,
        credentials,
    });
    Ok(())
}

/// Advances the directional stream offset for data written without ancillary
/// descriptors so later SCM_RIGHTS records retain their exact byte position.
#[cfg(feature = "linux-abi")]
pub(crate) fn linux_socket_record_data(pid: ObjId, handle: u64, bytes: usize) {
    if bytes == 0 {
        return;
    }
    let Some(controls) = crate::kobj::with(|t| match t.get(pid) {
        Ok(KObject::Process(p)) => p
            .linux
            .as_ref()?
            .sockets
            .iter()
            .find(|socket| socket.handle == handle)
            .map(|socket| Arc::clone(&socket.controls)),
        _ => None,
    }) else {
        return;
    };
    let queue = controls.tx.lock().as_ref().map(Arc::clone);
    if let Some(queue) = queue {
        queue.written.fetch_add(bytes, Ordering::AcqRel);
    }
}

/// Consumes ancillary records crossed by a socket read. A non-capturing read
/// discards the descriptors, matching Linux semantics when control is not
/// requested by the caller.
#[cfg(feature = "linux-abi")]
pub(crate) fn linux_socket_consume_control(
    pid: ObjId,
    handle: u64,
    bytes: usize,
    capture: bool,
) -> LinuxControlDelivery {
    if bytes == 0 {
        return LinuxControlDelivery::default();
    }
    let Some(controls) = crate::kobj::with(|t| match t.get(pid) {
        Ok(KObject::Process(p)) => p
            .linux
            .as_ref()?
            .sockets
            .iter()
            .find(|socket| socket.handle == handle)
            .map(|socket| Arc::clone(&socket.controls)),
        _ => None,
    }) else {
        return LinuxControlDelivery::default();
    };
    let Some(queue) = controls.rx.lock().as_ref().map(Arc::clone) else {
        return LinuxControlDelivery::default();
    };
    let end = queue
        .read
        .fetch_add(bytes, Ordering::AcqRel)
        .saturating_add(bytes);
    let mut messages = queue.messages.lock();
    if capture {
        return if messages.front().is_some_and(|message| message.start < end) {
            messages
                .pop_front()
                .map(|message| LinuxControlDelivery {
                    fds: message.fds,
                    credentials: message.credentials,
                })
                .unwrap_or_default()
        } else {
            LinuxControlDelivery::default()
        };
    }
    while messages.front().is_some_and(|message| message.start < end) {
        let _ = messages.pop_front();
    }
    LinuxControlDelivery::default()
}

/// Returns the shared status flags for one Linux descriptor.
#[cfg(feature = "linux-abi")]
pub(crate) fn linux_fd_status_flags(pid: ObjId, fd: u32) -> Option<u32> {
    crate::kobj::with(|t| match t.get(pid) {
        Ok(KObject::Process(p)) => p.linux.as_ref()?.fds.fd_status_flags(fd),
        _ => None,
    })
}

/// Returns the open-file-description identity compared by `kcmp(2)`.
#[cfg(feature = "linux-abi")]
pub(crate) fn linux_fd_description_identity(pid: ObjId, fd: u32) -> Option<u64> {
    crate::kobj::with(|t| match t.get(pid) {
        Ok(KObject::Process(p)) => p.linux.as_ref()?.fds.description_identity(fd),
        _ => None,
    })
}

/// Updates shared Linux status flags for one descriptor generation.
#[cfg(feature = "linux-abi")]
pub(crate) fn linux_set_fd_status_flags(pid: ObjId, fd: u32, flags: u32) -> bool {
    with_proc(pid, |p| {
        let linux = p.linux.as_ref().ok_or(ProcError::Exited)?;
        if linux.fds.set_fd_status_flags(fd, flags) {
            Ok(())
        } else {
            Err(ProcError::NoTaskSlot)
        }
    })
    .is_ok()
}

#[cfg(feature = "linux-abi")]
fn linux_handle_in_use(linux: &LinuxProcessState, handle: u64) -> bool {
    linux.fds.handle_fd_count(handle) != 0
        || linux.iourings.iter().any(|ring| {
            ring.fixed_files
                .iter()
                .flatten()
                .any(|file| file.entry.handle == handle)
        })
}

#[cfg(feature = "linux-abi")]
fn release_unreferenced_pipe(linux: &mut LinuxProcessState, handle: u64) {
    if handle >= LINUX_PIPE_HANDLE_BASE && !linux_handle_in_use(linux, handle) {
        linux.pipes.retain(|pipe| pipe.handle != handle);
    }
    if handle >= LINUX_SOCKET_HANDLE_BASE && !linux_handle_in_use(linux, handle) {
        linux.sockets.retain(|socket| socket.handle != handle);
    }
    if handle >= LINUX_ASHMEM_HANDLE_BASE && !linux_handle_in_use(linux, handle) {
        linux.ashmem.retain(|ashmem| ashmem.handle != handle);
    }
    if handle >= LINUX_BINDER_HANDLE_BASE && !linux_handle_in_use(linux, handle) {
        linux.binder.retain(|binder| binder.handle != handle);
    }
    if handle >= LINUX_ION_DEVICE_HANDLE_BASE && !linux_handle_in_use(linux, handle) {
        linux.ion_devices.retain(|device| *device != handle);
    }
    if handle >= LINUX_EVENTFD_HANDLE_BASE && !linux_handle_in_use(linux, handle) {
        linux.eventfds.retain(|eventfd| eventfd.handle != handle);
    }
    if handle >= LINUX_TIMERFD_HANDLE_BASE && !linux_handle_in_use(linux, handle) {
        linux.timerfds.retain(|timerfd| timerfd.handle != handle);
    }
    if handle >= LINUX_SIGNALFD_HANDLE_BASE && !linux_handle_in_use(linux, handle) {
        linux.signalfds.retain(|signalfd| signalfd.handle != handle);
    }
    if handle >= LINUX_INOTIFY_HANDLE_BASE
        && handle < LINUX_USERFAULT_HANDLE_BASE
        && !linux_handle_in_use(linux, handle)
    {
        linux.inotifies.retain(|inotify| inotify.handle != handle);
    }
    if handle >= LINUX_USERFAULT_HANDLE_BASE
        && handle < LINUX_MQ_HANDLE_BASE
        && !linux_handle_in_use(linux, handle)
    {
        linux.userfaultfds.retain(|userfault| userfault.handle != handle);
    }
    if handle >= LINUX_MQ_HANDLE_BASE && !linux_handle_in_use(linux, handle) {
        linux.message_queues.retain(|queue| queue.handle != handle);
    }
    if handle >= LINUX_MOUNT_TREE_HANDLE_BASE && !linux_handle_in_use(linux, handle) {
        linux.mount_trees.retain(|mount| *mount != handle);
    }
    if handle >= LINUX_FS_CONTEXT_HANDLE_BASE && !linux_handle_in_use(linux, handle) {
        linux.fs_contexts.retain(|context| context.handle != handle);
    }
    if handle >= LINUX_EPOLL_HANDLE_BASE && !linux_handle_in_use(linux, handle) {
        linux.epolls.retain(|epoll| epoll.handle != handle);
    }
    let mut released_fixed = Vec::new();
    if !linux_handle_in_use(linux, handle) {
        linux.iourings.retain(|ring| {
            if ring.handle != handle {
                return true;
            }
            released_fixed.extend(
                ring.fixed_files
                    .iter()
                    .flatten()
                    .map(|file| file.entry.handle),
            );
            false
        });
    }
    if !linux_handle_in_use(linux, handle) {
        linux.dma_heaps.retain(|heap| *heap != handle);
        linux.dmabufs.retain(|buffer| *buffer != handle);
        linux.sync_files.retain(|file| file.handle != handle);
    }
    for fixed_handle in released_fixed {
        if fixed_handle != handle {
            release_unreferenced_pipe(linux, fixed_handle);
        }
    }
}

/// Opens one anonymous ashmem buffer descriptor.
#[cfg(feature = "linux-abi")]
pub(crate) fn linux_open_ashmem(pid: ObjId, close_on_exec: bool) -> Option<u32> {
    linux_open_ashmem_kind(pid, close_on_exec, false, false)
}

/// Creates one anonymous regular-file descriptor backed by the same bounded
/// shared-page mechanism used by ashmem.
#[cfg(feature = "linux-abi")]
pub(crate) fn linux_create_memfd(
    pid: ObjId,
    close_on_exec: bool,
    allow_sealing: bool,
) -> Option<u32> {
    linux_open_ashmem_kind(pid, close_on_exec, true, allow_sealing)
}

/// Allocates one anonymous shared-page object for System V shared memory.
#[cfg(feature = "linux-abi")]
pub(crate) fn linux_create_shared_memory(
    pid: ObjId,
    size: u64,
) -> Option<LinuxSharedMemoryObject> {
    if size == 0 {
        return None;
    }
    let pages_count = usize::try_from(size.div_ceil(FRAME_SIZE)).ok()?;
    let id = NEXT_LINUX_SYSV_SHMEM_ID.fetch_add(1, Ordering::Relaxed);
    with_proc(pid, |p| {
        let mut charge = p
            .memory_account
            .reserve(pages_count as u64, 0, p.memory_owned_limit, p.memory_pin_limit)
            .ok_or(ProcError::MemoryQuota)?;
        let mut pages = Vec::new();
        pages
            .try_reserve_exact(pages_count)
            .map_err(|_| ProcError::OutOfFrames)?;
        for _ in 0..pages_count {
            let page_charge = charge.take_page().ok_or(ProcError::OutOfFrames)?;
            pages.push(
                crate::mm::memory_object::Page::zeroed(page_charge)
                    .ok_or(ProcError::OutOfFrames)?,
            );
        }
        Ok(LinuxSharedMemoryObject {
            buffer: Arc::new(AshmemBuffer {
                id,
                regular_file: false,
                size: AtomicU64::new(size),
                protection: AtomicU32::new(3),
                pins: AtomicU32::new(0),
                allow_sealing: AtomicU32::new(0),
                seals: AtomicU32::new(0),
                verity_enabled: AtomicU32::new(0),
                verity_digest: SpinLock::new([0; 32]),
                verity_descriptor: SpinLock::new([0; 256]),
                fscrypt: SpinLock::new(None),
                name: SpinLock::new(([0; 256], 0)),
                pages: SpinLock::new(pages),
            }),
        })
    })
    .ok()
}

#[cfg(feature = "linux-abi")]
fn linux_open_ashmem_kind(
    pid: ObjId,
    close_on_exec: bool,
    regular_file: bool,
    allow_sealing: bool,
) -> Option<u32> {
    with_proc(pid, |p| {
        let linux = p.linux.as_mut().ok_or(ProcError::Exited)?;
        linux
            .ashmem
            .try_reserve(1)
            .map_err(|_| ProcError::NoTaskSlot)?;
        let handle = linux.next_ashmem_handle;
        let next = handle.checked_add(1).ok_or(ProcError::NoTaskSlot)?;
        let fd = linux
            .fds
            .install(
                handle,
                Rights::READ.union(Rights::WRITE),
                compat_core::fd::CompatKind::Device,
                close_on_exec,
            )
            .map_err(|_| ProcError::NoTaskSlot)?;
        linux.next_ashmem_handle = next;
        linux.ashmem.push(LinuxAshmemHandle {
            handle,
            buffer: Arc::new(AshmemBuffer {
                id: handle,
                regular_file,
                size: AtomicU64::new(0),
                protection: AtomicU32::new(3),
                pins: AtomicU32::new(0),
                allow_sealing: AtomicU32::new(u32::from(allow_sealing)),
                seals: AtomicU32::new(0),
                verity_enabled: AtomicU32::new(0),
                verity_digest: SpinLock::new([0; 32]),
                verity_descriptor: SpinLock::new([0; 256]),
                fscrypt: SpinLock::new(None),
                name: SpinLock::new(([0; 256], 0)),
                pages: SpinLock::new(Vec::new()),
            }),
        });
        Ok(fd.fd())
    })
    .ok()
}

/// Reports whether one shared-page device descriptor represents a regular
/// memfd rather than the char-device ashmem ABI.
#[cfg(feature = "linux-abi")]
pub(crate) fn linux_ashmem_is_regular(pid: ObjId, handle: u64) -> Option<bool> {
    crate::kobj::with(|t| match t.get(pid) {
        Ok(KObject::Process(p)) => p
            .linux
            .as_ref()?
            .ashmem
            .iter()
            .find(|ashmem| ashmem.handle == handle)
            .map(|ashmem| ashmem.buffer.regular_file),
        _ => None,
    })
}

#[cfg(feature = "linux-abi")]
fn fscrypt_ashmem_error(error: FscryptError) -> LinuxAshmemError {
    match error {
        FscryptError::Invalid => LinuxAshmemError::Invalid,
        FscryptError::Permission => LinuxAshmemError::Permission,
        FscryptError::NoKey => LinuxAshmemError::NoKey,
        FscryptError::NoSpace => LinuxAshmemError::NoMemory,
    }
}

#[cfg(feature = "linux-abi")]
fn linux_ashmem_buffer_for(
    pid: ObjId,
    handle: u64,
) -> Result<Arc<AshmemBuffer>, LinuxAshmemError> {
    crate::kobj::with(|table| match table.get(pid) {
        Ok(KObject::Process(process)) => process
            .linux
            .as_ref()?
            .ashmem
            .iter()
            .find(|ashmem| ashmem.handle == handle)
            .map(|ashmem| Arc::clone(&ashmem.buffer)),
        _ => None,
    })
    .ok_or(LinuxAshmemError::NotAshmem)
}

/// Installs or validates an fscrypt policy on one empty regular compatibility
/// file. A matching repeated SET is idempotent; a different policy is EEXIST.
#[cfg(feature = "linux-abi")]
pub(crate) fn linux_ashmem_fscrypt_set_policy(
    pid: ObjId,
    handle: u64,
    policy: FscryptPolicy,
    uid: u32,
) -> Result<(), LinuxAshmemError> {
    policy.validate().map_err(fscrypt_ashmem_error)?;
    let buffer = linux_ashmem_buffer_for(pid, handle)?;
    if !buffer.regular_file {
        return Err(LinuxAshmemError::NotSupported);
    }
    let mut current = buffer.fscrypt.lock();
    if let Some(existing) = *current {
        return if existing.policy == policy {
            Ok(())
        } else {
            Err(LinuxAshmemError::Exists)
        };
    }
    if buffer.size.load(Ordering::Acquire) != 0 {
        return Err(LinuxAshmemError::Invalid);
    }
    if matches!(policy, FscryptPolicy::V2 { .. })
        && !crate::fscrypt::key_added_by(policy.key_specifier(), uid)
    {
        return Err(LinuxAshmemError::NoKey);
    }
    let nonce = crate::fscrypt::next_file_nonce(crate::security::boot_id(), buffer.id);
    *current = Some(FscryptFileState { policy, nonce });
    Ok(())
}

#[cfg(feature = "linux-abi")]
pub(crate) fn linux_ashmem_fscrypt_policy(
    pid: ObjId,
    handle: u64,
) -> Result<Option<FscryptPolicy>, LinuxAshmemError> {
    Ok(linux_ashmem_buffer_for(pid, handle)?
        .fscrypt
        .lock()
        .map(|state| state.policy))
}

#[cfg(feature = "linux-abi")]
pub(crate) fn linux_ashmem_fscrypt_nonce(
    pid: ObjId,
    handle: u64,
) -> Result<Option<[u8; crate::fscrypt::FILE_NONCE_BYTES]>, LinuxAshmemError> {
    Ok(linux_ashmem_buffer_for(pid, handle)?
        .fscrypt
        .lock()
        .map(|state| state.nonce))
}

#[cfg(feature = "linux-abi")]
pub(crate) fn linux_ashmem_fscrypt_pwsalt(
    pid: ObjId,
    handle: u64,
) -> Result<[u8; 16], LinuxAshmemError> {
    let buffer = linux_ashmem_buffer_for(pid, handle)?;
    if !buffer.regular_file {
        return Err(LinuxAshmemError::NotSupported);
    }
    Ok(crate::fscrypt::pwsalt(crate::security::boot_id()))
}

/// Opens one bounded Android binder device descriptor.
#[cfg(feature = "linux-abi")]
pub(crate) fn linux_open_binder(
    pid: ObjId,
    close_on_exec: bool,
    nonblocking: bool,
) -> Option<u32> {
    with_proc(pid, |p| {
        let linux = p.linux.as_mut().ok_or(ProcError::Exited)?;
        if linux.binder.len() >= 8 {
            return Err(ProcError::NoTaskSlot);
        }
        linux
            .binder
            .try_reserve(1)
            .map_err(|_| ProcError::NoTaskSlot)?;
        let handle = linux.next_binder_handle;
        let next = handle.checked_add(1).ok_or(ProcError::NoTaskSlot)?;
        let fd = linux
            .fds
            .install(
                handle,
                Rights::READ.union(Rights::WRITE),
                compat_core::fd::CompatKind::Device,
                close_on_exec,
            )
            .map_err(|_| ProcError::NoTaskSlot)?;
        if nonblocking
            && !linux
                .fds
                .set_fd_status_flags(fd.fd(), compat_core::syscall::LINUX_O_NONBLOCK)
        {
            return Err(ProcError::NoTaskSlot);
        }
        linux.next_binder_handle = next;
        linux.binder.push(Arc::new(LinuxBinderHandle {
            handle,
            max_threads: AtomicU32::new(0),
        }));
        Ok(fd.fd())
    })
    .ok()
}

/// Opens the Linux null device as a bounded compatibility descriptor.
///
/// 为 Bionic 的早期启动路径提供 `/dev/null`，避免 libc 因为标准描述符的
/// fallback 不存在而在 `__early_abort` 中崩溃。
#[cfg(feature = "linux-abi")]
pub(crate) fn linux_open_null(pid: ObjId, flags: u64) -> Option<u32> {
    if flags & 3 == 3 {
        return None;
    }
    with_proc(pid, |p| {
        let linux = p.linux.as_mut().ok_or(ProcError::Exited)?;
        let mut rights = Rights::READ;
        if flags & 3 != 0 {
            rights = rights.union(Rights::WRITE);
        }
        linux
            .fds
            .install(
                LINUX_CONSOLE_HANDLE,
                rights,
                compat_core::fd::CompatKind::Other,
                flags & 0x80000 != 0,
            )
            .map(|fd| fd.fd())
            .map_err(|_| ProcError::NoTaskSlot)
    })
    .ok()
}

#[cfg(feature = "linux-abi")]
pub(crate) fn linux_eventfd_create(
    pid: ObjId,
    initial: u32,
    close_on_exec: bool,
    nonblocking: bool,
    semaphore: bool,
) -> Option<u32> {
    with_proc(pid, |p| {
        let linux = p.linux.as_mut().ok_or(ProcError::Exited)?;
        linux
            .eventfds
            .try_reserve(1)
            .map_err(|_| ProcError::NoTaskSlot)?;
        let handle = linux.next_eventfd_handle;
        linux.next_eventfd_handle = handle.checked_add(1).ok_or(ProcError::NoTaskSlot)?;
        let fd = linux
            .fds
            .install(
                handle,
                Rights::READ.union(Rights::WRITE),
                compat_core::fd::CompatKind::Event,
                close_on_exec,
            )
            .map_err(|_| ProcError::NoTaskSlot)?;
        if nonblocking
            && !linux
                .fds
                .set_fd_status_flags(fd.fd(), compat_core::syscall::LINUX_O_NONBLOCK)
        {
            let _ = linux.fds.close(fd);
            return Err(ProcError::NoTaskSlot);
        }
        linux.eventfds.push(LinuxEventFdHandle {
            handle,
            counter: Arc::new(SpinLock::new(u64::from(initial))),
            semaphore,
        });
        Ok(fd.fd())
    })
    .ok()
}

#[cfg(feature = "linux-abi")]
pub(crate) fn linux_eventfd_state(
    pid: ObjId,
    handle: u64,
) -> Option<(Arc<SpinLock<u64>>, bool)> {
    crate::kobj::with(|t| match t.get(pid) {
        Ok(KObject::Process(p)) => p
            .linux
            .as_ref()?
            .eventfds
            .iter()
            .find(|eventfd| eventfd.handle == handle)
            .map(|eventfd| (Arc::clone(&eventfd.counter), eventfd.semaphore)),
        _ => None,
    })
}

/// Creates one shared timer state and installs its readable descriptor.
/// 创建一个共享计时器状态并安装其可读描述符。
#[cfg(feature = "linux-abi")]
pub(crate) fn linux_timerfd_create(
    pid: ObjId,
    clock: u32,
    close_on_exec: bool,
    nonblocking: bool,
) -> Option<u32> {
    with_proc(pid, |process| {
        let linux = process.linux.as_mut().ok_or(ProcError::Exited)?;
        linux
            .timerfds
            .try_reserve(1)
            .map_err(|_| ProcError::NoTaskSlot)?;
        let handle = linux.next_timerfd_handle;
        linux.next_timerfd_handle = handle.checked_add(1).ok_or(ProcError::NoTaskSlot)?;
        let fd = linux
            .fds
            .install(
                handle,
                Rights::READ,
                compat_core::fd::CompatKind::Timer,
                close_on_exec,
            )
            .map_err(|_| ProcError::NoTaskSlot)?;
        if nonblocking
            && !linux
                .fds
                .set_fd_status_flags(fd.fd(), compat_core::syscall::LINUX_O_NONBLOCK)
        {
            let _ = linux.fds.close(fd);
            return Err(ProcError::NoTaskSlot);
        }
        linux.timerfds.push(LinuxTimerFdHandle {
            handle,
            state: Arc::new(SpinLock::new(LinuxTimerFdState {
                clock,
                next: 0,
                interval: 0,
                expirations: 0,
            })),
        });
        Ok(fd.fd())
    })
    .ok()
}

/// Returns the shared timer state referenced by one descriptor.
/// 返回一个描述符引用的共享计时器状态。
#[cfg(feature = "linux-abi")]
pub(crate) fn linux_timerfd_state(
    pid: ObjId,
    handle: u64,
) -> Option<Arc<SpinLock<LinuxTimerFdState>>> {
    crate::kobj::with(|table| match table.get(pid) {
        Ok(KObject::Process(process)) => process
            .linux
            .as_ref()?
            .timerfds
            .iter()
            .find(|timerfd| timerfd.handle == handle)
            .map(|timerfd| Arc::clone(&timerfd.state)),
        _ => None,
    })
}

/// Creates one signalfd whose mask is shared by duplicated descriptions.
/// 创建一个由重复描述共享 mask 的 signalfd。
#[cfg(feature = "linux-abi")]
pub(crate) fn linux_signalfd_create(
    pid: ObjId,
    mask: u64,
    close_on_exec: bool,
    nonblocking: bool,
) -> Option<u32> {
    with_proc(pid, |process| {
        let linux = process.linux.as_mut().ok_or(ProcError::Exited)?;
        linux
            .signalfds
            .try_reserve(1)
            .map_err(|_| ProcError::NoTaskSlot)?;
        let handle = linux.next_signalfd_handle;
        linux.next_signalfd_handle = handle.checked_add(1).ok_or(ProcError::NoTaskSlot)?;
        let fd = linux
            .fds
            .install(
                handle,
                Rights::READ,
                compat_core::fd::CompatKind::Signal,
                close_on_exec,
            )
            .map_err(|_| ProcError::NoTaskSlot)?;
        if nonblocking
            && !linux
                .fds
                .set_fd_status_flags(fd.fd(), compat_core::syscall::LINUX_O_NONBLOCK)
        {
            let _ = linux.fds.close(fd);
            return Err(ProcError::NoTaskSlot);
        }
        linux.signalfds.push(LinuxSignalFdHandle {
            handle,
            mask: Arc::new(SpinLock::new(mask)),
        });
        Ok(fd.fd())
    })
    .ok()
}

/// Returns the shared signal mask for one signalfd handle.
/// 返回一个 signalfd handle 的共享信号 mask。
#[cfg(feature = "linux-abi")]
pub(crate) fn linux_signalfd_state(
    pid: ObjId,
    handle: u64,
) -> Option<Arc<SpinLock<u64>>> {
    crate::kobj::with(|table| match table.get(pid) {
        Ok(KObject::Process(process)) => process
            .linux
            .as_ref()?
            .signalfds
            .iter()
            .find(|signalfd| signalfd.handle == handle)
            .map(|signalfd| Arc::clone(&signalfd.mask)),
        _ => None,
    })
}

/// Creates one bounded inotify instance shared across inherited descriptors.
#[cfg(feature = "linux-abi")]
pub(crate) fn linux_inotify_create(
    pid: ObjId,
    close_on_exec: bool,
    nonblocking: bool,
) -> Option<u32> {
    linux_notification_create(pid, close_on_exec, nonblocking, false, false)
}

/// Creates one bounded fanotify notification instance.
#[cfg(feature = "linux-abi")]
pub(crate) fn linux_fanotify_create(
    pid: ObjId,
    close_on_exec: bool,
    nonblocking: bool,
    event_cloexec: bool,
) -> Option<u32> {
    linux_notification_create(pid, close_on_exec, nonblocking, true, event_cloexec)
}

#[cfg(feature = "linux-abi")]
fn linux_notification_create(
    pid: ObjId,
    close_on_exec: bool,
    nonblocking: bool,
    fanotify: bool,
    fanotify_event_cloexec: bool,
) -> Option<u32> {
    with_proc(pid, |process| {
        let linux = process.linux.as_mut().ok_or(ProcError::Exited)?;
        if linux.inotifies.len() >= 8 {
            return Err(ProcError::NoTaskSlot);
        }
        linux
            .inotifies
            .try_reserve(1)
            .map_err(|_| ProcError::NoTaskSlot)?;
        let handle = linux.next_inotify_handle;
        linux.next_inotify_handle = handle.checked_add(1).ok_or(ProcError::NoTaskSlot)?;
        let fd = linux
            .fds
            .install(
                handle,
                Rights::READ,
                compat_core::fd::CompatKind::Inotify,
                close_on_exec,
            )
            .map_err(|_| ProcError::NoTaskSlot)?;
        if nonblocking
            && !linux
                .fds
                .set_fd_status_flags(fd.fd(), compat_core::syscall::LINUX_O_NONBLOCK)
        {
            let _ = linux.fds.close(fd);
            return Err(ProcError::NoTaskSlot);
        }
        linux.inotifies.push(LinuxInotifyHandle {
            handle,
            state: Arc::new(SpinLock::new(LinuxInotifyState {
                watches: Vec::new(),
                events: VecDeque::new(),
                fanotify,
                fanotify_marks: Vec::new(),
                fanotify_events: VecDeque::new(),
                fanotify_event_cloexec,
            })),
        });
        Ok(fd.fd())
    })
    .ok()
}

/// Returns the shared watch and event state for one inotify handle.
#[cfg(feature = "linux-abi")]
pub(crate) fn linux_inotify_state(
    pid: ObjId,
    handle: u64,
) -> Option<Arc<SpinLock<LinuxInotifyState>>> {
    crate::kobj::with(|table| match table.get(pid) {
        Ok(KObject::Process(process)) => process
            .linux
            .as_ref()?
            .inotifies
            .iter()
            .find(|inotify| inotify.handle == handle)
            .map(|inotify| Arc::clone(&inotify.state)),
        _ => None,
    })
}

/// Reports whether an inotify/fanotify descriptor has readable events.
#[cfg(feature = "linux-abi")]
pub(crate) fn linux_notification_ready(pid: ObjId, handle: u64) -> Option<bool> {
    let state = linux_inotify_state(pid, handle)?;
    let state = state.lock();
    Some(if state.fanotify {
        !state.fanotify_events.is_empty()
    } else {
        !state.events.is_empty()
    })
}

/// Creates one bounded userfaultfd missing-page handler.
#[cfg(feature = "linux-abi")]
pub(crate) fn linux_userfault_create(pid: ObjId, close_on_exec: bool) -> Option<u32> {
    with_proc(pid, |process| {
        let linux = process.linux.as_mut().ok_or(ProcError::Exited)?;
        if linux.userfaultfds.len() >= 8 {
            return Err(ProcError::NoTaskSlot);
        }
        linux
            .userfaultfds
            .try_reserve(1)
            .map_err(|_| ProcError::NoTaskSlot)?;
        let handle = linux.next_userfault_handle;
        linux.next_userfault_handle = handle.checked_add(1).ok_or(ProcError::NoTaskSlot)?;
        let fd = linux
            .fds
            .install(
                handle,
                Rights::READ,
                compat_core::fd::CompatKind::Other,
                close_on_exec,
            )
            .map_err(|_| ProcError::NoTaskSlot)?;
        linux.userfaultfds.push(LinuxUserfaultHandle {
            handle,
            state: Arc::new(SpinLock::new(LinuxUserfaultState {
                api: false,
                features: 0,
                ranges: Vec::new(),
                events: VecDeque::new(),
            })),
        });
        Ok(fd.fd())
    })
    .ok()
}

#[cfg(feature = "linux-abi")]
pub(crate) fn linux_userfault_state(
    pid: ObjId,
    handle: u64,
) -> Option<Arc<SpinLock<LinuxUserfaultState>>> {
    crate::kobj::with(|table| match table.get(pid) {
        Ok(KObject::Process(process)) => process
            .linux
            .as_ref()?
            .userfaultfds
            .iter()
            .find(|entry| entry.handle == handle)
            .map(|entry| Arc::clone(&entry.state)),
        _ => None,
    })
}

#[cfg(feature = "linux-abi")]
pub(crate) fn linux_userfault_registered(pid: ObjId, address: u64) -> bool {
    let states = crate::kobj::with(|table| match table.get(pid) {
        Ok(KObject::Process(process)) => process
            .linux
            .as_ref()
            .map(|linux| {
                linux
                    .userfaultfds
                    .iter()
                    .map(|entry| Arc::clone(&entry.state))
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default(),
        _ => Vec::new(),
    });
    states.into_iter().any(|state| {
        state
            .lock()
            .ranges
            .iter()
            .any(|range| address >= range.start && address < range.end)
    })
}

/// Parks a missing-page fault until user space resolves or unregisters it.
/// Returns `false` when the fault is not covered by a userfaultfd range.
#[cfg(feature = "linux-abi")]
pub(crate) fn linux_userfault_wait(pid: ObjId, address: u64, write: bool) -> bool {
    let states = crate::kobj::with(|table| match table.get(pid) {
        Ok(KObject::Process(process)) => process
            .linux
            .as_ref()
            .map(|linux| {
                linux
                    .userfaultfds
                    .iter()
                    .map(|entry| Arc::clone(&entry.state))
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default(),
        _ => Vec::new(),
    });
    let page = address - address % kernel_core::frame::FRAME_SIZE;
    let mut queued = false;
    let tid = crate::linux_abi::current_linux_tid(pid).unwrap_or(0);
    for state in states {
        let mut state = state.lock();
        if !state.api
            || !state
                .ranges
                .iter()
                .any(|range| address >= range.start && address < range.end)
        {
            continue;
        }
        if state.events.len() < 64 {
            state.events.push_back(LinuxUserfaultEvent {
                address: page,
                flags: if write { 1 } else { 0 },
                tid,
            });
            queued = true;
        }
    }
    if !queued {
        return false;
    }
    crate::linux_abi::wake_message_queue_waiters();
    loop {
        if crate::proc::page_flags(pid, page).is_some() {
            return true;
        }
        if !linux_userfault_registered(pid, page) {
            return false;
        }
        sched::pause();
    }
}

/// Delivers one real compatibility VFS event to every matching fanotify mark.
#[cfg(feature = "linux-abi")]
pub(crate) fn linux_fanotify_notify(
    node: crate::linux_vfs::Node,
    mask: u64,
    source_pid: u32,
) {
    let mut states = Vec::new();
    kobj::with(|table| {
        table.for_each_live(|_, object| {
            if let KObject::Process(process) = object {
                if let Some(linux) = process.linux.as_ref() {
                    states.extend(linux.inotifies.iter().map(|entry| Arc::clone(&entry.state)));
                }
            }
            true
        });
    });
    let mut delivered = false;
    for state in states {
        let mut state = state.lock();
        if !state.fanotify || state.fanotify_events.len() >= 64 {
            continue;
        }
        let selected = state.fanotify_marks.iter().any(|mark| {
            let in_scope = mark.node == node
                || mark.scope != 0
                    && matches!(
                        mark.node,
                        crate::linux_vfs::Node::Directory(
                            crate::linux_vfs::DirectoryId::Root
                        )
                    );
            in_scope && mark.mask & mask != 0
        });
        if selected && state.fanotify_events.len() < 64 {
            state.fanotify_events.push_back(LinuxFanotifyEvent {
                node,
                mask,
                pid: source_pid as i32,
            });
            delivered = true;
        }
    }
    if delivered {
        crate::linux_abi::wake_message_queue_waiters();
    }
}

/// Installs one descriptor sharing a POSIX message queue object.
#[cfg(feature = "linux-abi")]
pub(crate) fn linux_mq_install(
    pid: ObjId,
    queue: Arc<LinuxMqShared>,
    rights: Rights,
    close_on_exec: bool,
    nonblocking: bool,
) -> Option<u32> {
    with_proc(pid, |process| {
        let linux = process.linux.as_mut().ok_or(ProcError::Exited)?;
        if linux.message_queues.len() >= 32 {
            return Err(ProcError::NoTaskSlot);
        }
        linux
            .message_queues
            .try_reserve(1)
            .map_err(|_| ProcError::NoTaskSlot)?;
        let handle = linux.next_mq_handle;
        linux.next_mq_handle = handle.checked_add(1).ok_or(ProcError::NoTaskSlot)?;
        let fd = linux
            .fds
            .install(
                handle,
                rights,
                compat_core::fd::CompatKind::MessageQueue,
                close_on_exec,
            )
            .map_err(|_| ProcError::NoTaskSlot)?;
        if nonblocking
            && !linux
                .fds
                .set_fd_status_flags(fd.fd(), compat_core::syscall::LINUX_O_NONBLOCK)
        {
            let _ = linux.fds.close(fd);
            return Err(ProcError::NoTaskSlot);
        }
        linux.message_queues.push(LinuxMqHandle { handle, queue });
        Ok(fd.fd())
    })
    .ok()
}

/// Returns the shared queue object for one message-queue descriptor.
#[cfg(feature = "linux-abi")]
pub(crate) fn linux_mq_state(pid: ObjId, handle: u64) -> Option<Arc<LinuxMqShared>> {
    crate::kobj::with(|table| match table.get(pid) {
        Ok(KObject::Process(process)) => process
            .linux
            .as_ref()?
            .message_queues
            .iter()
            .find(|queue| queue.handle == handle)
            .map(|queue| Arc::clone(&queue.queue)),
        _ => None,
    })
}

/// Returns every message-queue object currently referenced by a process.
#[cfg(feature = "linux-abi")]
pub(crate) fn linux_mq_queues(pid: ObjId) -> Vec<Arc<LinuxMqShared>> {
    crate::kobj::with(|table| match table.get(pid) {
        Ok(KObject::Process(process)) => process
            .linux
            .as_ref()
            .map(|linux| {
                linux
                    .message_queues
                    .iter()
                    .map(|queue| Arc::clone(&queue.queue))
                    .collect()
            })
            .unwrap_or_default(),
        _ => Vec::new(),
    })
}

/// Installs one read-only mount-tree descriptor for the synthetic root namespace.
#[cfg(feature = "linux-abi")]
pub(crate) fn linux_install_mount_tree(pid: ObjId, close_on_exec: bool) -> Option<u32> {
    with_proc(pid, |process| {
        let linux = process.linux.as_mut().ok_or(ProcError::Exited)?;
        linux
            .mount_trees
            .try_reserve(1)
            .map_err(|_| ProcError::NoTaskSlot)?;
        let handle = linux.next_mount_tree_handle;
        linux.next_mount_tree_handle = handle.checked_add(1).ok_or(ProcError::NoTaskSlot)?;
        let fd = linux
            .fds
            .install(
                handle,
                Rights::READ,
                compat_core::fd::CompatKind::MountTree,
                close_on_exec,
            )
            .map_err(|_| ProcError::NoTaskSlot)?;
        linux.mount_trees.push(handle);
        Ok(fd.fd())
    })
    .ok()
}

/// Installs one new filesystem configuration context.
#[cfg(feature = "linux-abi")]
pub(crate) fn linux_install_fs_context(
    pid: ObjId,
    fs_name: [u8; 16],
    fs_name_len: u8,
    close_on_exec: bool,
) -> Option<u32> {
    with_proc(pid, |process| {
        let linux = process.linux.as_mut().ok_or(ProcError::Exited)?;
        if linux.fs_contexts.len() >= 16 {
            return Err(ProcError::NoTaskSlot);
        }
        linux
            .fs_contexts
            .try_reserve(1)
            .map_err(|_| ProcError::NoTaskSlot)?;
        let handle = linux.next_fs_context_handle;
        linux.next_fs_context_handle = handle.checked_add(1).ok_or(ProcError::NoTaskSlot)?;
        let fd = linux
            .fds
            .install(
                handle,
                Rights::READ.union(Rights::WRITE),
                compat_core::fd::CompatKind::FsContext,
                close_on_exec,
            )
            .map_err(|_| ProcError::NoTaskSlot)?;
        linux.fs_contexts.push(LinuxFsContextHandle {
            handle,
            fs_name,
            fs_name_len,
            created: false,
        });
        Ok(fd.fd())
    })
    .ok()
}

/// Installs one Landlock ruleset whose rules are shared by duplicated FDs.
#[cfg(feature = "linux-abi")]
pub(crate) fn linux_install_landlock_ruleset(
    pid: ObjId,
    handled_access_fs: u64,
    close_on_exec: bool,
) -> Option<u32> {
    with_proc(pid, |process| {
        let linux = process.linux.as_mut().ok_or(ProcError::Exited)?;
        if linux.landlock_rulesets.len() >= 16 {
            return Err(ProcError::NoTaskSlot);
        }
        linux
            .landlock_rulesets
            .try_reserve(1)
            .map_err(|_| ProcError::NoTaskSlot)?;
        let handle = linux.next_landlock_handle;
        linux.next_landlock_handle = handle.checked_add(1).ok_or(ProcError::NoTaskSlot)?;
        let fd = linux
            .fds
            .install(
                handle,
                Rights::READ.union(Rights::WRITE),
                compat_core::fd::CompatKind::Sandbox,
                close_on_exec,
            )
            .map_err(|_| ProcError::NoTaskSlot)?;
        linux.landlock_rulesets.push(LinuxLandlockRulesetHandle {
            handle,
            ruleset: Arc::new(SpinLock::new(LinuxLandlockRuleset {
                handled_access_fs,
                rules: Vec::new(),
            })),
        });
        Ok(fd.fd())
    })
    .ok()
}

#[cfg(feature = "linux-abi")]
pub(crate) fn linux_landlock_ruleset(
    pid: ObjId,
    handle: u64,
) -> Option<Arc<SpinLock<LinuxLandlockRuleset>>> {
    crate::kobj::with(|table| match table.get(pid) {
        Ok(KObject::Process(process)) => process
            .linux
            .as_ref()?
            .landlock_rulesets
            .iter()
            .find(|ruleset| ruleset.handle == handle)
            .map(|ruleset| Arc::clone(&ruleset.ruleset)),
        _ => None,
    })
}

#[cfg(feature = "linux-abi")]
pub(crate) fn linux_fs_context_create(pid: ObjId, fd: u32) -> bool {
    with_proc(pid, |process| {
        let linux = process.linux.as_mut().ok_or(ProcError::Exited)?;
        let entry = linux.fds.get_fd(fd).ok_or(ProcError::NoTaskSlot)?;
        let context = linux
            .fs_contexts
            .iter_mut()
            .find(|context| context.handle == entry.handle)
            .ok_or(ProcError::NoTaskSlot)?;
        context.created = true;
        Ok(())
    })
    .is_ok()
}

#[cfg(feature = "linux-abi")]
pub(crate) fn linux_fs_context_ready(pid: ObjId, fd: u32) -> bool {
    with_proc(pid, |process| {
        let linux = process.linux.as_ref().ok_or(ProcError::Exited)?;
        let entry = linux.fds.get_fd(fd).ok_or(ProcError::NoTaskSlot)?;
        linux
            .fs_contexts
            .iter()
            .find(|context| context.handle == entry.handle)
            .is_some_and(|context| {
                context.created
                    && context.fs_name_len == 8
                    && context.fs_name[..8] == b"jasperfs"[..]
            })
            .then_some(())
            .ok_or(ProcError::NoTaskSlot)
    })
    .is_ok()
}

/// Creates one epoll instance backed by a bounded per-instance registration set.
#[cfg(feature = "linux-abi")]
pub(crate) fn linux_epoll_create(pid: ObjId, close_on_exec: bool) -> Option<u32> {
    with_proc(pid, |process| {
        let linux = process.linux.as_mut().ok_or(ProcError::Exited)?;
        linux
            .epolls
            .try_reserve(1)
            .map_err(|_| ProcError::NoTaskSlot)?;
        let handle = linux.next_epoll_handle;
        linux.next_epoll_handle = handle.checked_add(1).ok_or(ProcError::NoTaskSlot)?;
        let fd = linux
            .fds
            .install(
                handle,
                Rights::READ.union(Rights::WRITE),
                compat_core::fd::CompatKind::Other,
                close_on_exec,
            )
            .map_err(|_| ProcError::NoTaskSlot)?;
        linux.epolls.push(LinuxEpollHandle {
            handle,
            registrations: Arc::new(SpinLock::new(Vec::new())),
        });
        Ok(fd.fd())
    })
    .ok()
}

/// Returns the registration set for one live epoll instance.
#[cfg(feature = "linux-abi")]
pub(crate) fn linux_epoll_registrations(
    pid: ObjId,
    handle: u64,
) -> Option<Arc<SpinLock<Vec<LinuxEpollRegistration>>>> {
    crate::kobj::with(|table| match table.get(pid) {
        Ok(KObject::Process(process)) => process
            .linux
            .as_ref()?
            .epolls
            .iter()
            .find(|epoll| epoll.handle == handle)
            .map(|epoll| Arc::clone(&epoll.registrations)),
        _ => None,
    })
}

/// Returns the open-file identity registered in one epoll target slot.
#[cfg(feature = "linux-abi")]
pub(crate) fn linux_epoll_registration_identity(
    pid: ObjId,
    epoll_fd: u32,
    target_fd: u32,
    target_offset: u32,
) -> Option<u64> {
    if target_offset != 0 {
        return None;
    }
    crate::kobj::with(|table| {
        let process = match table.get(pid) {
            Ok(KObject::Process(process)) => process,
            _ => return None,
        };
        let linux = process.linux.as_ref()?;
        let epoll = linux.fds.get_fd(epoll_fd)?;
        let registrations = linux
            .epolls
            .iter()
            .find(|epoll_handle| epoll_handle.handle == epoll.handle)?
            .registrations
            .lock();
        let target = linux.fds.get_fd(target_fd)?;
        let description_id = linux.fds.description_identity(target_fd)?;
        registrations
            .iter()
            .any(|registration| {
                registration.handle == target.handle
                    && registration.description_id == description_id
            })
            .then_some(description_id)
    })
}

/// Returns true when a compatibility handle identifies an epoll instance.
#[cfg(feature = "linux-abi")]
pub(crate) fn linux_is_epoll(pid: ObjId, handle: u64) -> bool {
    crate::kobj::with(|table| match table.get(pid) {
        Ok(KObject::Process(process)) => process
            .linux
            .as_ref()
            .is_some_and(|linux| linux.epolls.iter().any(|epoll| epoll.handle == handle)),
        _ => false,
    })
}

/// Associates one regular memfd descriptor with a bounded io_uring ring.
#[cfg(feature = "linux-abi")]
pub(crate) fn linux_io_uring_register(
    pid: ObjId,
    handle: u64,
    entries: u32,
    cq_entries: u32,
) -> bool {
    with_proc(pid, |process| {
        let linux = process.linux.as_mut().ok_or(ProcError::Exited)?;
        if linux.iourings.len() >= 8
            || linux
                .iourings
                .iter()
                .any(|ring| ring.handle == handle)
        {
            return Err(ProcError::NoTaskSlot);
        }
        linux
            .iourings
            .try_reserve(1)
            .map_err(|_| ProcError::NoTaskSlot)?;
        linux.iourings.push(LinuxIoUringHandle {
            handle,
            entries,
            cq_entries,
            fixed_files: Vec::new(),
        });
        Ok(())
    })
    .is_ok()
}

/// Returns the fixed queue geometry of one io_uring instance.
#[cfg(feature = "linux-abi")]
pub(crate) fn linux_io_uring_state(pid: ObjId, handle: u64) -> Option<(u32, u32)> {
    crate::kobj::with(|table| match table.get(pid) {
        Ok(KObject::Process(process)) => process
            .linux
            .as_ref()?
            .iourings
            .iter()
            .find(|ring| ring.handle == handle)
            .map(|ring| (ring.entries, ring.cq_entries)),
        _ => None,
    })
}

/// Captures one descriptor's open-file description for a fixed io_uring slot.
#[cfg(feature = "linux-abi")]
pub(crate) fn linux_fd_description(pid: ObjId, fd: u32) -> Option<FdDescription> {
    crate::kobj::with(|table| match table.get(pid) {
        Ok(KObject::Process(process)) => process.linux.as_ref()?.fds.description_fd(fd),
        _ => None,
    })
}

/// Replaces a ring's fixed-file table after all slot descriptors were validated.
#[cfg(feature = "linux-abi")]
pub(crate) fn linux_io_uring_replace_fixed_files(
    pid: ObjId,
    handle: u64,
    files: Vec<Option<FdDescription>>,
) -> bool {
    with_proc(pid, |process| {
        let linux = process.linux.as_mut().ok_or(ProcError::Exited)?;
        let old_files = {
            let ring = linux
                .iourings
                .iter_mut()
                .find(|ring| ring.handle == handle)
                .ok_or(ProcError::NoTaskSlot)?;
            if files.len() > ring.entries as usize {
                return Err(ProcError::NoTaskSlot);
            }
            core::mem::replace(&mut ring.fixed_files, files)
        };
        for file in old_files.into_iter().flatten() {
            release_unreferenced_pipe(linux, file.entry.handle);
        }
        Ok(())
    })
    .is_ok()
}

/// Atomically applies one validated fixed-file update range.
#[cfg(feature = "linux-abi")]
pub(crate) fn linux_io_uring_update_fixed_files(
    pid: ObjId,
    handle: u64,
    offset: usize,
    files: Vec<Option<FdDescription>>,
) -> bool {
    with_proc(pid, |process| {
        let linux = process.linux.as_mut().ok_or(ProcError::Exited)?;
        let old_files = {
            let ring = linux
                .iourings
                .iter_mut()
                .find(|ring| ring.handle == handle)
                .ok_or(ProcError::NoTaskSlot)?;
            let end = offset
                .checked_add(files.len())
                .ok_or(ProcError::NoTaskSlot)?;
            if offset > ring.fixed_files.len() || end > ring.fixed_files.len() {
                return Err(ProcError::NoTaskSlot);
            }
            let mut old_files = Vec::new();
            old_files
                .try_reserve(files.len())
                .map_err(|_| ProcError::NoTaskSlot)?;
            for (slot, file) in ring.fixed_files[offset..end].iter_mut().zip(files) {
                old_files.push(core::mem::replace(slot, file));
            }
            old_files
        };
        for file in old_files.into_iter().flatten() {
            release_unreferenced_pipe(linux, file.entry.handle);
        }
        Ok(())
    })
    .is_ok()
}

/// Returns the current registered fixed-file count, including sparse slots.
#[cfg(feature = "linux-abi")]
pub(crate) fn linux_io_uring_fixed_file_count(pid: ObjId, handle: u64) -> Option<usize> {
    crate::kobj::with(|table| match table.get(pid) {
        Ok(KObject::Process(process)) => process
            .linux
            .as_ref()?
            .iourings
            .iter()
            .find(|ring| ring.handle == handle)
            .map(|ring| ring.fixed_files.len()),
        _ => None,
    })
}

/// Resolves one fixed-file slot to its retained open-file description.
#[cfg(feature = "linux-abi")]
pub(crate) fn linux_io_uring_fixed_file(
    pid: ObjId,
    handle: u64,
    index: u32,
) -> Option<FdDescription> {
    crate::kobj::with(|table| match table.get(pid) {
        Ok(KObject::Process(process)) => process
            .linux
            .as_ref()?
            .iourings
            .iter()
            .find(|ring| ring.handle == handle)?
            .fixed_files
            .get(index as usize)?
            .clone(),
        _ => None,
    })
}

/// Clears a ring's fixed-file table.
#[cfg(feature = "linux-abi")]
pub(crate) fn linux_io_uring_clear_fixed_files(pid: ObjId, handle: u64) -> bool {
    linux_io_uring_replace_fixed_files(pid, handle, Vec::new())
}

/// Translates the three Linux io_uring mmap pseudo-offsets to backing offsets.
#[cfg(feature = "linux-abi")]
pub(crate) fn linux_io_uring_mmap_offset(
    pid: ObjId,
    handle: u64,
    requested: u64,
) -> Option<u64> {
    let _ = linux_io_uring_state(pid, handle)?;
    match requested {
        0x0000_0000 | 0x0800_0000 => Some(0),
        0x1000_0000 => Some(0x2000),
        _ => None,
    }
}

#[cfg(feature = "linux-abi")]
pub(crate) fn linux_set_binder_max_threads(pid: ObjId, handle: u64, value: u32) -> bool {
    crate::kobj::with(|t| match t.get(pid) {
        Ok(KObject::Process(p)) => p
            .linux
            .as_ref()
            .and_then(|linux| linux.binder.iter().find(|binder| binder.handle == handle))
            .is_some_and(|binder| {
                binder.max_threads.store(value, Ordering::Release);
                true
            }),
        _ => false,
    })
}

/// Returns the process-wide Binder thread-pool limit for one binder descriptor.
#[cfg(feature = "linux-abi")]
pub(crate) fn linux_binder_max_threads(pid: ObjId) -> Option<u32> {
    crate::kobj::with(|t| match t.get(pid) {
        Ok(KObject::Process(p)) => p
            .linux
            .as_ref()?
            .binder
            .iter()
            .map(|binder| binder.max_threads.load(Ordering::Acquire))
            .max(),
        _ => None,
    })
}

#[cfg(feature = "linux-abi")]
pub(crate) fn linux_is_binder(pid: ObjId, handle: u64) -> bool {
    crate::kobj::with(|t| match t.get(pid) {
        Ok(KObject::Process(p)) => p
            .linux
            .as_ref()
            .is_some_and(|linux| linux.binder.iter().any(|binder| binder.handle == handle)),
        _ => false,
    })
}

/// Opens the legacy Android ION control device.
#[cfg(feature = "linux-abi")]
pub(crate) fn linux_open_ion(pid: ObjId, close_on_exec: bool) -> Option<u32> {
    with_proc(pid, |p| {
        let linux = p.linux.as_mut().ok_or(ProcError::Exited)?;
        if linux.ion_devices.len() >= 8 {
            return Err(ProcError::NoTaskSlot);
        }
        linux
            .ion_devices
            .try_reserve(1)
            .map_err(|_| ProcError::NoTaskSlot)?;
        let handle = linux.next_ion_device_handle;
        let next = handle.checked_add(1).ok_or(ProcError::NoTaskSlot)?;
        let fd = linux
            .fds
            .install(
                handle,
                Rights::READ.union(Rights::WRITE),
                compat_core::fd::CompatKind::Device,
                close_on_exec,
            )
            .map_err(|_| ProcError::NoTaskSlot)?;
        linux.next_ion_device_handle = next;
        linux.ion_devices.push(handle);
        Ok(fd.fd())
    })
    .ok()
}

#[cfg(feature = "linux-abi")]
pub(crate) fn linux_is_ion_device(pid: ObjId, handle: u64) -> bool {
    crate::kobj::with(|t| match t.get(pid) {
        Ok(KObject::Process(p)) => p
            .linux
            .as_ref()
            .is_some_and(|linux| linux.ion_devices.contains(&handle)),
        _ => false,
    })
}

/// Opens one modern Android dma-heap control descriptor.
#[cfg(feature = "linux-abi")]
pub(crate) fn linux_open_dma_heap(pid: ObjId, close_on_exec: bool) -> Option<u32> {
    with_proc(pid, |process| {
        let linux = process.linux.as_mut().ok_or(ProcError::Exited)?;
        if linux.dma_heaps.len() >= 8 {
            return Err(ProcError::NoTaskSlot);
        }
        linux
            .dma_heaps
            .try_reserve(1)
            .map_err(|_| ProcError::NoTaskSlot)?;
        let handle = linux.next_dma_heap_handle;
        linux.next_dma_heap_handle =
            handle.checked_add(1).ok_or(ProcError::NoTaskSlot)?;
        let fd = linux
            .fds
            .install(
                handle,
                Rights::READ.union(Rights::WRITE),
                compat_core::fd::CompatKind::Device,
                close_on_exec,
            )
            .map_err(|_| ProcError::NoTaskSlot)?;
        linux.dma_heaps.push(handle);
        Ok(fd.fd())
    })
    .ok()
}

/// Reports whether a descriptor is an Android dma-heap control device.
#[cfg(feature = "linux-abi")]
pub(crate) fn linux_is_dma_heap(pid: ObjId, handle: u64) -> bool {
    crate::kobj::with(|table| match table.get(pid) {
        Ok(KObject::Process(process)) => process
            .linux
            .as_ref()
            .is_some_and(|linux| linux.dma_heaps.contains(&handle)),
        _ => false,
    })
}

/// Associates one shared-page memfd with the Android dma-buf ioctl surface.
#[cfg(feature = "linux-abi")]
pub(crate) fn linux_register_dmabuf(pid: ObjId, handle: u64) -> bool {
    with_proc(pid, |process| {
        let linux = process.linux.as_mut().ok_or(ProcError::Exited)?;
        if linux.dmabufs.len() >= 32 || linux.dmabufs.contains(&handle) {
            return Err(ProcError::NoTaskSlot);
        }
        linux
            .dmabufs
            .try_reserve(1)
            .map_err(|_| ProcError::NoTaskSlot)?;
        linux.dmabufs.push(handle);
        Ok(())
    })
    .is_ok()
}

/// Reports whether a descriptor exposes the Android dma-buf ioctl surface.
#[cfg(feature = "linux-abi")]
pub(crate) fn linux_is_dmabuf(pid: ObjId, handle: u64) -> bool {
    crate::kobj::with(|table| match table.get(pid) {
        Ok(KObject::Process(process)) => process
            .linux
            .as_ref()
            .is_some_and(|linux| linux.dmabufs.contains(&handle)),
        _ => false,
    })
}

/// Creates one immediate-signaled Android sync_file compatible descriptor.
#[cfg(feature = "linux-abi")]
pub(crate) fn linux_create_sync_file(
    pid: ObjId,
    name: &[u8],
    close_on_exec: bool,
) -> Option<u32> {
    if name.len() > 32 {
        return None;
    }
    with_proc(pid, |process| {
        let linux = process.linux.as_mut().ok_or(ProcError::Exited)?;
        if linux.sync_files.len() >= 32 {
            return Err(ProcError::NoTaskSlot);
        }
        linux
            .sync_files
            .try_reserve(1)
            .map_err(|_| ProcError::NoTaskSlot)?;
        let handle = linux.next_sync_file_handle;
        linux.next_sync_file_handle =
            handle.checked_add(1).ok_or(ProcError::NoTaskSlot)?;
        let fd = linux
            .fds
            .install(
                handle,
                Rights::READ.union(Rights::WRITE),
                compat_core::fd::CompatKind::Other,
                close_on_exec,
            )
            .map_err(|_| ProcError::NoTaskSlot)?;
        let mut stored = [0u8; 32];
        stored[..name.len()].copy_from_slice(name);
        linux.sync_files.push(LinuxSyncFileHandle {
            handle,
            name: stored,
            name_len: name.len(),
        });
        Ok(fd.fd())
    })
    .ok()
}

/// Reports whether a descriptor is an Android sync_file.
#[cfg(feature = "linux-abi")]
pub(crate) fn linux_is_sync_file(pid: ObjId, handle: u64) -> bool {
    crate::kobj::with(|table| match table.get(pid) {
        Ok(KObject::Process(process)) => process
            .linux
            .as_ref()
            .is_some_and(|linux| linux.sync_files.iter().any(|file| file.handle == handle)),
        _ => false,
    })
}

/// Copies the bounded sync_file name into the caller's fixed-size buffer.
#[cfg(feature = "linux-abi")]
pub(crate) fn linux_sync_file_name(
    pid: ObjId,
    handle: u64,
    output: &mut [u8; 32],
) -> Option<usize> {
    crate::kobj::with(|table| match table.get(pid) {
        Ok(KObject::Process(process)) => {
            let file = process
                .linux
                .as_ref()?
                .sync_files
                .iter()
                .find(|file| file.handle == handle)?;
            *output = file.name;
            Some(file.name_len)
        }
        _ => None,
    })
}

/// Allocates one ION system-heap buffer and returns its per-process user
/// handle without creating a userspace descriptor yet.
#[cfg(feature = "linux-abi")]
pub(crate) fn linux_ion_alloc(
    pid: ObjId,
    size: u64,
    alignment: u64,
    heap_mask: u32,
    flags: u32,
) -> Result<u32, LinuxAshmemError> {
    const PAGE: u64 = kernel_core::frame::FRAME_SIZE;
    if size == 0
        || alignment > PAGE
        || heap_mask & 1 == 0
        || flags & !3 != 0
    {
        return Err(LinuxAshmemError::Invalid);
    }
    with_proc(pid, |p| {
        let linux = p.linux.as_mut().ok_or(ProcError::Exited)?;
        let linux_pid = linux.pid;
        linux
            .ion_allocations
            .try_reserve(1)
            .map_err(|_| ProcError::NoTaskSlot)?;
        let user_handle = linux
            .next_ion_user_handle
            .checked_add(1)
            .ok_or(ProcError::NoTaskSlot)?;
        let current = linux.next_ion_user_handle;
        let pages_count =
            usize::try_from(size.div_ceil(PAGE)).map_err(|_| ProcError::OutOfFrames)?;
        let mut charge = p
            .memory_account
            .reserve(
                pages_count as u64,
                0,
                p.memory_owned_limit,
                p.memory_pin_limit,
            )
            .ok_or(ProcError::MemoryQuota)?;
        let mut pages = Vec::new();
        pages
            .try_reserve_exact(pages_count)
            .map_err(|_| ProcError::OutOfFrames)?;
        for _ in 0..pages_count {
            let page_charge = charge.take_page().ok_or(ProcError::OutOfFrames)?;
            pages.push(
                crate::mm::memory_object::Page::zeroed(page_charge)
                    .ok_or(ProcError::OutOfFrames)?,
            );
        }
        let buffer = Arc::new(AshmemBuffer {
            id: (u64::from(current) << 32) | u64::from(linux_pid),
            regular_file: false,
            size: AtomicU64::new(size),
            protection: AtomicU32::new(3),
            pins: AtomicU32::new(0),
            allow_sealing: AtomicU32::new(0),
            seals: AtomicU32::new(0),
            verity_enabled: AtomicU32::new(0),
            verity_digest: SpinLock::new([0; 32]),
            verity_descriptor: SpinLock::new([0; 256]),
            fscrypt: SpinLock::new(None),
            name: SpinLock::new(([0; 256], 0)),
            pages: SpinLock::new(pages),
        });
        linux.next_ion_user_handle = user_handle;
        linux.ion_allocations.push(LinuxIonAllocation {
            user_handle: current,
            buffer,
        });
        Ok(current)
    })
    .map_err(|_| LinuxAshmemError::NoMemory)
}

/// Installs a userspace mapping fd for one ION allocation.
#[cfg(feature = "linux-abi")]
pub(crate) fn linux_ion_share(
    pid: ObjId,
    user_handle: u32,
    close_on_exec: bool,
) -> Result<u32, LinuxAshmemError> {
    with_proc(pid, |p| {
        let linux = p.linux.as_mut().ok_or(ProcError::Exited)?;
        let buffer = linux
            .ion_allocations
            .iter()
            .find(|allocation| allocation.user_handle == user_handle)
            .map(|allocation| Arc::clone(&allocation.buffer))
            .ok_or(ProcError::NoTaskSlot)?;
        linux
            .ashmem
            .try_reserve(1)
            .map_err(|_| ProcError::NoTaskSlot)?;
        let handle = linux.next_ashmem_handle;
        let next = handle.checked_add(1).ok_or(ProcError::NoTaskSlot)?;
        let fd = linux
            .fds
            .install(
                handle,
                Rights::READ.union(Rights::WRITE),
                compat_core::fd::CompatKind::Device,
                close_on_exec,
            )
            .map_err(|_| ProcError::NoTaskSlot)?;
        linux.next_ashmem_handle = next;
        linux.ashmem.push(LinuxAshmemHandle { handle, buffer });
        Ok(fd.fd())
    })
    .map_err(|_| LinuxAshmemError::NoMemory)
}

/// Imports one existing ION mapping fd as a new user handle.
#[cfg(feature = "linux-abi")]
pub(crate) fn linux_ion_import(pid: ObjId, fd: u32) -> Result<u32, LinuxAshmemError> {
    with_proc(pid, |p| {
        let linux = p.linux.as_mut().ok_or(ProcError::Exited)?;
        let entry = linux.fds.get_fd(fd).ok_or(ProcError::NoTaskSlot)?;
        let buffer = linux
            .ashmem
            .iter()
            .find(|ashmem| ashmem.handle == entry.handle)
            .map(|ashmem| Arc::clone(&ashmem.buffer))
            .ok_or(ProcError::NoTaskSlot)?;
        linux
            .ion_allocations
            .try_reserve(1)
            .map_err(|_| ProcError::NoTaskSlot)?;
        let user = linux.next_ion_user_handle;
        linux.next_ion_user_handle = user.checked_add(1).ok_or(ProcError::NoTaskSlot)?;
        linux.ion_allocations.push(LinuxIonAllocation {
            user_handle: user,
            buffer,
        });
        Ok(user)
    })
    .map_err(|_| LinuxAshmemError::Invalid)
}

/// Releases one ION user handle while existing mapping fds retain the backing.
#[cfg(feature = "linux-abi")]
pub(crate) fn linux_ion_free(pid: ObjId, user_handle: u32) -> Result<(), LinuxAshmemError> {
    with_proc(pid, |p| {
        let linux = p.linux.as_mut().ok_or(ProcError::Exited)?;
        let index = linux
            .ion_allocations
            .iter()
            .position(|allocation| allocation.user_handle == user_handle)
            .ok_or(ProcError::NoTaskSlot)?;
        linux.ion_allocations.remove(index);
        Ok(())
    })
    .map_err(|_| LinuxAshmemError::Invalid)
}

/// Allocates a private transaction buffer in the recipient's user address space
/// and returns its page-aligned address.
#[cfg(feature = "linux-abi")]
pub(crate) fn linux_alloc_transaction_buffer(pid: ObjId, data: &[u8]) -> Option<u64> {
    const PAGE: u64 = kernel_core::frame::FRAME_SIZE;
    let length = u64::try_from(data.len()).ok()?;
    let rounded = length.checked_add(PAGE - 1)? & !(PAGE - 1);
    let start = linux_mmap_cursor(pid)?;
    if start < crate::arch::USER_WINDOW.0
        || start.checked_add(rounded)? > crate::arch::USER_WINDOW.1
    {
        return None;
    }
    let flags = MapFlags::USER.union(MapFlags::WRITE);
    let mut mapped = Vec::new();
    let mut page = start;
    while page < start + rounded {
        if map_new(
            pid,
            page,
            flags,
        )
        .is_err()
        {
            for address in mapped.iter().rev().copied() {
                let _ = unmap_page(pid, address);
            }
            return None;
        }
        mapped.push(page);
        page += PAGE;
    }
    if !data.is_empty() && write(pid, start, data).is_err() {
        for address in mapped.iter().rev().copied() {
            let _ = unmap_page(pid, address);
        }
        return None;
    }
    if !set_linux_mmap_cursor(pid, start + rounded) {
        for address in mapped.iter().rev().copied() {
            let _ = unmap_page(pid, address);
        }
        return None;
    }
    Some(start)
}

/// Releases one private binder transaction buffer.
#[cfg(feature = "linux-abi")]
pub(crate) fn linux_free_transaction_buffer(pid: ObjId, address: u64, length: usize) -> bool {
    const PAGE: u64 = kernel_core::frame::FRAME_SIZE;
    let Some(rounded) = u64::try_from(length)
        .ok()
        .and_then(|length| length.checked_add(PAGE - 1))
        .map(|length| length & !(PAGE - 1))
    else {
        return false;
    };
    let mut page = address;
    while page < address.saturating_add(rounded) {
        if unmap_page(pid, page).is_err() {
            return false;
        }
        page += PAGE;
    }
    true
}

/// Resizes one shared-page buffer and commits its page accounting
/// all-or-nothing. Growing allocates zeroed pages; shrinking retains pages
/// through any existing mappings before releasing their buffer references.
#[cfg(feature = "linux-abi")]
pub(crate) fn linux_ashmem_set_size(
    pid: ObjId,
    handle: u64,
    size: u64,
) -> Result<(), LinuxAshmemError> {
    const PAGE: u64 = kernel_core::frame::FRAME_SIZE;
    let pages_count =
        usize::try_from(size.div_ceil(PAGE)).map_err(|_| LinuxAshmemError::NoMemory)?;
    with_proc(pid, |p| {
        let linux = p.linux.as_mut().ok_or(ProcError::Exited)?;
        let buffer = linux
            .ashmem
            .iter()
            .find(|ashmem| ashmem.handle == handle)
            .map(|ashmem| Arc::clone(&ashmem.buffer))
            .ok_or(ProcError::NoTaskSlot)?;
        if !buffer.regular_file && buffer.size.load(Ordering::Acquire) != 0 {
            return Err(ProcError::NoTaskSlot);
        }
        let fscrypt = *buffer.fscrypt.lock();
        let cipher = fscrypt
            .map(|state| FileCipher::new(state.policy, state.nonce))
            .transpose()
            .map_err(|_| ProcError::Handle(HandleError::RightsDenied))?;
        let mut pages = buffer.pages.lock();
        let current_pages = pages.len();
        if pages_count > current_pages {
            let additional = pages_count - current_pages;
            let mut charge = p
                .memory_account
                .reserve(
                    additional as u64,
                    0,
                    p.memory_owned_limit,
                    p.memory_pin_limit,
                )
                .ok_or(ProcError::MemoryQuota)?;
            let mut allocated = Vec::new();
            allocated
                .try_reserve_exact(additional)
                .map_err(|_| ProcError::OutOfFrames)?;
            for _ in 0..additional {
                let page_charge = charge.take_page().ok_or(ProcError::OutOfFrames)?;
                allocated.push(
                    crate::mm::memory_object::Page::zeroed(page_charge)
                        .ok_or(ProcError::OutOfFrames)?,
                );
            }
            pages
                .try_reserve_exact(additional)
                .map_err(|_| ProcError::OutOfFrames)?;
            pages.append(&mut allocated);
            if let Some(cipher) = cipher {
                let mut data_unit = [0u8; FRAME_SIZE as usize];
                for index in current_pages..pages_count {
                    let page = pages
                        .get(index)
                        .ok_or(ProcError::OutOfFrames)?;
                    cipher.encrypt(index as u64, &mut data_unit);
                    let pointer = crate::mm::phys_to_virt(page.frame().start())
                        .ok_or(ProcError::OutOfFrames)?;
                    // SAFETY: the retained page owns one writable frame.
                    unsafe {
                        core::ptr::copy_nonoverlapping(
                            data_unit.as_ptr(),
                            pointer,
                            data_unit.len(),
                        )
                    };
                }
            }
        } else {
            pages.truncate(pages_count);
        }
        buffer.size.store(size, Ordering::Release);
        Ok(())
    })
    .map_err(|error| match error {
        ProcError::Handle(HandleError::RightsDenied) => LinuxAshmemError::NoKey,
        _ => LinuxAshmemError::NoMemory,
    })
}

/// Copies a byte range out of one memfd backing object without changing its
/// logical size or descriptor cursor.
#[cfg(feature = "linux-abi")]
pub(crate) fn linux_ashmem_read_from(
    pid: ObjId,
    handle: u64,
    offset: u64,
    output: &mut [u8],
) -> Result<usize, LinuxAshmemError> {
    let buffer = crate::kobj::with(|table| match table.get(pid) {
        Ok(KObject::Process(process)) => process
            .linux
            .as_ref()?
            .ashmem
            .iter()
            .find(|ashmem| ashmem.handle == handle)
            .map(|ashmem| Arc::clone(&ashmem.buffer)),
        _ => None,
    })
    .ok_or(LinuxAshmemError::NotAshmem)?;
    let size = buffer.size.load(Ordering::Acquire);
    if offset >= size || output.is_empty() {
        return Ok(0);
    }
    let available = usize::try_from(size - offset)
        .map_err(|_| LinuxAshmemError::Invalid)?
        .min(output.len());
    let page_bytes = kernel_core::frame::FRAME_SIZE as usize;
    let fscrypt = *buffer.fscrypt.lock();
    let cipher = fscrypt
        .map(|state| FileCipher::new(state.policy, state.nonce))
        .transpose()
        .map_err(fscrypt_ashmem_error)?;
    let pages = buffer.pages.lock();
    let mut copied = 0usize;
    while copied < available {
        let absolute = offset
            .checked_add(copied as u64)
            .ok_or(LinuxAshmemError::Invalid)?;
        let index = usize::try_from(absolute / page_bytes as u64)
            .map_err(|_| LinuxAshmemError::Invalid)?;
        let inner = (absolute % page_bytes as u64) as usize;
        let take = (available - copied).min(page_bytes - inner);
        let page = pages.get(index).ok_or(LinuxAshmemError::Invalid)?;
        let pointer = crate::mm::phys_to_virt(page.frame().start() + inner as u64)
            .ok_or(LinuxAshmemError::NoMemory)?;
        if let Some(cipher) = cipher.as_ref() {
            let frame = crate::mm::phys_to_virt(page.frame().start())
                .ok_or(LinuxAshmemError::NoMemory)?;
            let mut data_unit = [0u8; FRAME_SIZE as usize];
            // SAFETY: the retained Page owns one complete frame.
            unsafe {
                core::ptr::copy_nonoverlapping(
                    frame as *const u8,
                    data_unit.as_mut_ptr(),
                    data_unit.len(),
                )
            };
            cipher.decrypt(index as u64, &mut data_unit);
            output[copied..copied + take]
                .copy_from_slice(&data_unit[inner..inner + take]);
        } else {
            // SAFETY: the retained Page owns this live frame and the range is
            // bounded to one page. The caller-side buffer is a distinct allocation.
            unsafe {
                core::ptr::copy_nonoverlapping(
                    pointer as *const u8,
                    output[copied..].as_mut_ptr(),
                    take,
                )
            };
        }
        copied += take;
    }
    Ok(available)
}

/// Writes bytes into one memfd backing object. A write past EOF grows the
/// logical file by allocating every additional page before publishing the new
/// size. Seal checks are performed before any observable size change.
#[cfg(feature = "linux-abi")]
pub(crate) fn linux_ashmem_write_from(
    pid: ObjId,
    handle: u64,
    offset: u64,
    input: &[u8],
) -> Result<usize, LinuxAshmemError> {
    if input.is_empty() {
        return Ok(0);
    }
    let buffer = crate::kobj::with(|table| match table.get(pid) {
        Ok(KObject::Process(process)) => process
            .linux
            .as_ref()?
            .ashmem
            .iter()
            .find(|ashmem| ashmem.handle == handle)
            .map(|ashmem| {
                (
                    Arc::clone(&ashmem.buffer),
                    ashmem.buffer.seals.load(Ordering::Acquire),
                )
            }),
        _ => None,
    })
    .ok_or(LinuxAshmemError::NotAshmem)?;
    let (buffer, seals) = buffer;
    if seals & (8 | 16) != 0 {
        return Err(LinuxAshmemError::Permission);
    }
    let fscrypt = *buffer.fscrypt.lock();
    let cipher = fscrypt
        .map(|state| FileCipher::new(state.policy, state.nonce))
        .transpose()
        .map_err(fscrypt_ashmem_error)?;
    let length = u64::try_from(input.len()).map_err(|_| LinuxAshmemError::Invalid)?;
    let end = offset
        .checked_add(length)
        .ok_or(LinuxAshmemError::Invalid)?;
    if end > buffer.size.load(Ordering::Acquire) {
        if seals & 4 != 0 {
            return Err(LinuxAshmemError::Permission);
        }
        linux_ashmem_set_size(pid, handle, end)?;
    }
    let page_bytes = kernel_core::frame::FRAME_SIZE as usize;
    let pages = buffer.pages.lock();
    let mut copied = 0usize;
    while copied < input.len() {
        let absolute = offset
            .checked_add(copied as u64)
            .ok_or(LinuxAshmemError::Invalid)?;
        let index = usize::try_from(absolute / page_bytes as u64)
            .map_err(|_| LinuxAshmemError::Invalid)?;
        let inner = (absolute % page_bytes as u64) as usize;
        let take = (input.len() - copied).min(page_bytes - inner);
        let page = pages.get(index).ok_or(LinuxAshmemError::Invalid)?;
        if let Some(cipher) = cipher.as_ref() {
            let frame = crate::mm::phys_to_virt(page.frame().start())
                .ok_or(LinuxAshmemError::NoMemory)?;
            let mut data_unit = [0u8; FRAME_SIZE as usize];
            // SAFETY: the retained Page owns one complete frame.
            unsafe {
                core::ptr::copy_nonoverlapping(
                    frame as *const u8,
                    data_unit.as_mut_ptr(),
                    data_unit.len(),
                )
            };
            cipher.decrypt(index as u64, &mut data_unit);
            data_unit[inner..inner + take]
                .copy_from_slice(&input[copied..copied + take]);
            cipher.encrypt(index as u64, &mut data_unit);
            // SAFETY: the retained page owns the complete writable frame.
            unsafe {
                core::ptr::copy_nonoverlapping(
                    data_unit.as_ptr(),
                    frame,
                    data_unit.len(),
                )
            };
        } else {
            let pointer = crate::mm::phys_to_virt(page.frame().start() + inner as u64)
                .ok_or(LinuxAshmemError::NoMemory)?;
            // SAFETY: the retained Page owns this live frame and the range is
            // bounded to one page. The source allocation cannot alias the frame.
            unsafe {
                core::ptr::copy_nonoverlapping(
                    input[copied..].as_ptr(),
                    pointer,
                    take,
                )
            };
        }
        copied += take;
    }
    Ok(input.len())
}

/// Returns one ashmem buffer's size, protection and pin count.
#[cfg(feature = "linux-abi")]
pub(crate) fn linux_ashmem_state(
    pid: ObjId,
    handle: u64,
) -> Option<(u64, u32, u32)> {
    crate::kobj::with(|t| match t.get(pid) {
        Ok(KObject::Process(p)) => p
            .linux
            .as_ref()?
            .ashmem
            .iter()
            .find(|ashmem| ashmem.handle == handle)
            .map(|ashmem| {
                (
                    ashmem.buffer.size.load(Ordering::Acquire),
                    ashmem.buffer.protection.load(Ordering::Acquire),
                    ashmem.buffer.pins.load(Ordering::Acquire),
                )
            }),
        _ => None,
    })
}

#[cfg(feature = "linux-abi")]
pub(crate) fn linux_ashmem_verity_state(
    pid: ObjId,
    handle: u64,
) -> Option<(bool, [u8; 32], [u8; 256])> {
    crate::kobj::with(|table| match table.get(pid) {
        Ok(KObject::Process(process)) => {
            let ashmem = process
                .linux
                .as_ref()?
                .ashmem
                .iter()
                .find(|ashmem| ashmem.handle == handle)?;
            Some((
                ashmem.buffer.verity_enabled.load(Ordering::Acquire) != 0,
                *ashmem.buffer.verity_digest.lock(),
                *ashmem.buffer.verity_descriptor.lock(),
            ))
        }
        _ => None,
    })
}

#[cfg(feature = "linux-abi")]
pub(crate) fn linux_ashmem_set_verity(
    pid: ObjId,
    handle: u64,
    digest: [u8; 32],
    descriptor: [u8; 256],
) -> bool {
    with_proc(pid, |process| {
        let ashmem = process
            .linux
            .as_ref()
            .ok_or(ProcError::Exited)?
            .ashmem
            .iter()
            .find(|ashmem| ashmem.handle == handle)
            .ok_or(ProcError::NoSuchProcess)?;
        *ashmem.buffer.verity_digest.lock() = digest;
        *ashmem.buffer.verity_descriptor.lock() = descriptor;
        ashmem
            .buffer
            .verity_enabled
            .store(1, Ordering::Release);
        Ok(())
    })
    .is_ok()
}

#[cfg(feature = "linux-abi")]
pub(crate) fn linux_ashmem_add_seals(
    pid: ObjId,
    handle: u64,
    seals: u32,
) -> Result<u32, LinuxAshmemError> {
    if seals == 0 || seals & !0x1f != 0 {
        return Err(LinuxAshmemError::Invalid);
    }
    with_proc(pid, |p| {
        let linux = p.linux.as_ref().ok_or(ProcError::Exited)?;
        let buffer = linux
            .ashmem
            .iter()
            .find(|ashmem| ashmem.handle == handle)
            .map(|ashmem| Arc::clone(&ashmem.buffer))
            .ok_or(ProcError::NoTaskSlot)?;
        if buffer.allow_sealing.load(Ordering::Acquire) == 0 {
            return Err(ProcError::Handle(HandleError::RightsDenied));
        }
        let current = buffer.seals.load(Ordering::Acquire);
        if current & 1 != 0 {
            return Err(ProcError::Handle(HandleError::RightsDenied));
        }
        if seals & 8 != 0
            && p.shared_maps
                .iter()
                .any(|mapping| {
                    mapping.source.object_id == buffer.id
                        && mapping.flags.contains(MapFlags::WRITE)
                })
        {
            return Err(ProcError::Map(MapError::Busy));
        }
        let next = current | seals;
        buffer.seals.store(next, Ordering::Release);
        Ok(next)
    })
    .map_err(|error| match error {
        ProcError::Handle(HandleError::RightsDenied) => LinuxAshmemError::Permission,
        ProcError::Map(MapError::Busy) => LinuxAshmemError::Busy,
        ProcError::NoTaskSlot => LinuxAshmemError::NotAshmem,
        _ => LinuxAshmemError::NoMemory,
    })
}

#[cfg(feature = "linux-abi")]
pub(crate) fn linux_ashmem_get_seals(
    pid: ObjId,
    handle: u64,
) -> Option<u32> {
    crate::kobj::with(|t| match t.get(pid) {
        Ok(KObject::Process(p)) => p
            .linux
            .as_ref()?
            .ashmem
            .iter()
            .find(|ashmem| ashmem.handle == handle)
            .map(|ashmem| ashmem.buffer.seals.load(Ordering::Acquire)),
        _ => None,
    })
}

/// Sets an ashmem name and returns the bounded diagnostic name.
#[cfg(feature = "linux-abi")]
pub(crate) fn linux_ashmem_set_name(
    pid: ObjId,
    handle: u64,
    name: &[u8],
) -> Result<(), LinuxAshmemError> {
    if name.len() > 256 {
        return Err(LinuxAshmemError::Invalid);
    }
    let buffer = crate::kobj::with(|t| match t.get(pid) {
        Ok(KObject::Process(p)) => p
            .linux
            .as_ref()?
            .ashmem
            .iter()
            .find(|ashmem| ashmem.handle == handle)
            .map(|ashmem| Arc::clone(&ashmem.buffer)),
        _ => None,
    })
    .ok_or(LinuxAshmemError::NotAshmem)?;
    let mut stored = buffer.name.lock();
    stored.0.fill(0);
    stored.0[..name.len()].copy_from_slice(name);
    stored.1 = name.len();
    Ok(())
}

#[cfg(feature = "linux-abi")]
pub(crate) fn linux_ashmem_name(
    pid: ObjId,
    handle: u64,
) -> Result<alloc::vec::Vec<u8>, LinuxAshmemError> {
    let buffer = crate::kobj::with(|t| match t.get(pid) {
        Ok(KObject::Process(p)) => p
            .linux
            .as_ref()?
            .ashmem
            .iter()
            .find(|ashmem| ashmem.handle == handle)
            .map(|ashmem| Arc::clone(&ashmem.buffer)),
        _ => None,
    })
    .ok_or(LinuxAshmemError::NotAshmem)?;
    let stored = buffer.name.lock();
    let mut name = alloc::vec::Vec::new();
    name.try_reserve(stored.1 + 1)
        .map_err(|_| LinuxAshmemError::NoMemory)?;
    name.extend_from_slice(&stored.0[..stored.1]);
    name.push(0);
    Ok(name)
}

#[cfg(feature = "linux-abi")]
pub(crate) fn linux_ashmem_pin(
    pid: ObjId,
    handle: u64,
    pin: bool,
) -> Result<u32, LinuxAshmemError> {
    let buffer = crate::kobj::with(|t| match t.get(pid) {
        Ok(KObject::Process(p)) => p
            .linux
            .as_ref()?
            .ashmem
            .iter()
            .find(|ashmem| ashmem.handle == handle)
            .map(|ashmem| Arc::clone(&ashmem.buffer)),
        _ => None,
    })
    .ok_or(LinuxAshmemError::NotAshmem)?;
    if buffer.size.load(Ordering::Acquire) == 0 {
        return Err(LinuxAshmemError::Invalid);
    }
    if pin {
        let mut current = buffer.pins.load(Ordering::Acquire);
        loop {
            let next = current
                .checked_add(1)
                .ok_or(LinuxAshmemError::Invalid)?;
            match buffer.pins.compare_exchange(
                current,
                next,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => return Ok(next),
                Err(observed) => current = observed,
            }
        }
    } else {
        let mut current = buffer.pins.load(Ordering::Acquire);
        loop {
            let next = current
                .checked_sub(1)
                .ok_or(LinuxAshmemError::Invalid)?;
            match buffer.pins.compare_exchange(
                current,
                next,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => return Ok(next),
                Err(observed) => current = observed,
            }
        }
    }
}

#[cfg(feature = "linux-abi")]
pub(crate) fn linux_ashmem_set_protection(
    pid: ObjId,
    handle: u64,
    protection: u32,
) -> Result<(), LinuxAshmemError> {
    if protection == 0 || protection & !3 != 0 {
        return Err(LinuxAshmemError::Invalid);
    }
    let buffer = crate::kobj::with(|t| match t.get(pid) {
        Ok(KObject::Process(p)) => p
            .linux
            .as_ref()?
            .ashmem
            .iter()
            .find(|ashmem| ashmem.handle == handle)
            .map(|ashmem| Arc::clone(&ashmem.buffer)),
        _ => None,
    })
    .ok_or(LinuxAshmemError::NotAshmem)?;
    buffer.protection.store(protection, Ordering::Release);
    Ok(())
}

/// Maps an ashmem buffer range into a Linux process with retained page
/// references and a shared-memory capability at the exact virtual range.
#[cfg(feature = "linux-abi")]
pub(crate) fn linux_ashmem_map(
    pid: ObjId,
    handle: u64,
    address: u64,
    length: u64,
    protection: u32,
    offset: u64,
) -> Result<(), LinuxAshmemError> {
    const PAGE: u64 = kernel_core::frame::FRAME_SIZE;
    if address % PAGE != 0
        || length == 0
        || length % PAGE != 0
        || offset % PAGE != 0
        || protection == 0
        || protection & !3 != 0
    {
        return Err(LinuxAshmemError::Invalid);
    }
    if linux_ashmem_buffer_for(pid, handle)?
        .fscrypt
        .lock()
        .is_some()
    {
        // Mapping ciphertext directly would violate fscrypt's plaintext mmap
        // contract. Fail closed until page faults can transform mapped data.
        return Err(LinuxAshmemError::NotSupported);
    }
    let (buffer, pages) = crate::kobj::with(|t| match t.get(pid) {
        Ok(KObject::Process(p)) => {
            let ashmem = p
                .linux
                .as_ref()?
                .ashmem
                .iter()
                .find(|ashmem| ashmem.handle == handle)?;
            let size = ashmem.buffer.size.load(Ordering::Acquire);
            let end = offset.checked_add(length)?;
            if end > size.div_ceil(PAGE) * PAGE
                || ashmem.buffer.protection.load(Ordering::Acquire) & protection != protection
                || (protection & 2 != 0
                    && ashmem.buffer.seals.load(Ordering::Acquire) & (8 | 16) != 0)
            {
                return None;
            }
            let start = usize::try_from(offset / PAGE).ok()?;
            let count = usize::try_from(length / PAGE).ok()?;
            let guard = ashmem.buffer.pages.lock();
            let source = guard.get(start..start.checked_add(count)?)?;
            let mut retained = Vec::new();
            retained.try_reserve_exact(count).ok()?;
            retained.extend(source.iter().cloned());
            Some((Arc::clone(&ashmem.buffer), retained))
        }
        _ => None,
    })
    .ok_or(LinuxAshmemError::Invalid)?;
    let pages_count = length / PAGE;
    let backing = kernel_core::memory_capability::BackingIdentity::new(buffer.id, 1)
        .ok_or(LinuxAshmemError::Invalid)?;
    with_proc(pid, |p| {
        if protection & 2 != 0 && buffer.seals.load(Ordering::Acquire) & (8 | 16) != 0 {
            return Err(ProcError::Handle(HandleError::RightsDenied));
        }
        if p.frames
            .len()
            .checked_add(p.shared_maps.len())
            .and_then(|count| count.checked_add(pages.len()))
            .is_none_or(|count| count > MAX_PROCESS_FRAMES)
        {
            return Err(ProcError::MemoryQuota);
        }
        p.shared_maps
            .try_reserve(pages.len())
            .map_err(|_| ProcError::NoTaskSlot)?;
        if !p.memory_caps.can_grant(address, pages_count, MemoryKind::Shared) {
            return Err(ProcError::MemoryQuota);
        }
        for index in 0..pages_count {
            if p.space
                .translate(VirtPage::containing(address + index * PAGE))
                .is_some()
            {
                return Err(ProcError::Map(MapError::InvalidAddress));
            }
        }
        if !p.space.begin_shootdown() {
            return Err(ProcError::Map(MapError::Busy));
        }
        let mut flags = MapFlags::USER;
        if protection & 2 != 0 {
            flags = flags.union(MapFlags::WRITE);
        }
        let mut published = 0u64;
        for page in &pages {
            if p.space
                .map_raw(
                    VirtPage::containing(address + published * PAGE),
                    page.frame(),
                    flags,
                )
                .is_err()
            {
                for index in 0..published {
                    let _ = p
                        .space
                        .unmap_raw(VirtPage::containing(address + index * PAGE));
                }
                p.space.end_shootdown();
                return Err(ProcError::Map(MapError::NotMapped));
            }
            published += 1;
        }
        let rights = MemoryRights::READ
            .union(MemoryRights::MAP)
            .union(if protection & 2 != 0 {
                MemoryRights::WRITE
            } else {
                MemoryRights::NONE
            });
        if p.memory_caps
            .grant(address, pages_count, rights, MemoryKind::Shared, backing)
            .is_err()
        {
            for index in 0..published {
                let _ = p
                    .space
                    .unmap_raw(VirtPage::containing(address + index * PAGE));
            }
            p.space.end_shootdown();
            return Err(ProcError::MemoryQuota);
        }
        for (index, page) in pages.iter().enumerate() {
            p.shared_maps.push(SharedMapping {
                va: address + index as u64 * PAGE,
                page: Arc::clone(page),
                source: backing,
                flags,
            });
        }
        p.space.end_shootdown();
        Ok(())
    })
    .map_err(|error| match error {
        ProcError::Handle(HandleError::RightsDenied) => LinuxAshmemError::Permission,
        _ => LinuxAshmemError::NoMemory,
    })
}

/// Maps one System V shared-memory object at an exact page-aligned range.
#[cfg(feature = "linux-abi")]
pub(crate) fn linux_shared_memory_map(
    pid: ObjId,
    object: &LinuxSharedMemoryObject,
    address: u64,
    length: u64,
    writable: bool,
) -> Result<(), LinuxAshmemError> {
    const PAGE: u64 = kernel_core::frame::FRAME_SIZE;
    if address % PAGE != 0 || length == 0 || length % PAGE != 0 {
        return Err(LinuxAshmemError::Invalid);
    }
    let pages_count = length / PAGE;
    let retained = {
        let guard = object.buffer.pages.lock();
        let count = usize::try_from(pages_count).map_err(|_| LinuxAshmemError::Invalid)?;
        let mut retained = Vec::new();
        retained
            .try_reserve_exact(count)
            .map_err(|_| LinuxAshmemError::NoMemory)?;
        retained.extend(
            guard
                .get(..count)
                .ok_or(LinuxAshmemError::Invalid)?
                .iter()
                .cloned(),
        );
        retained
    };
    let backing = kernel_core::memory_capability::BackingIdentity::new(object.buffer.id, 1)
        .ok_or(LinuxAshmemError::Invalid)?;
    with_proc(pid, |p| {
        if p.frames
            .len()
            .checked_add(p.shared_maps.len())
            .and_then(|count| count.checked_add(retained.len()))
            .is_none_or(|count| count > MAX_PROCESS_FRAMES)
        {
            return Err(ProcError::MemoryQuota);
        }
        p.shared_maps
            .try_reserve(retained.len())
            .map_err(|_| ProcError::NoTaskSlot)?;
        if !p
            .memory_caps
            .can_grant(address, pages_count, MemoryKind::Shared)
        {
            return Err(ProcError::MemoryQuota);
        }
        for index in 0..pages_count {
            if p.space
                .translate(VirtPage::containing(address + index * PAGE))
                .is_some()
            {
                return Err(ProcError::Map(MapError::InvalidAddress));
            }
        }
        if !p.space.begin_shootdown() {
            return Err(ProcError::Map(MapError::Busy));
        }
        let mut flags = MapFlags::USER;
        if writable {
            flags = flags.union(MapFlags::WRITE);
        }
        let mut published = 0u64;
        for page in &retained {
            if p.space
                .map_raw(
                    VirtPage::containing(address + published * PAGE),
                    page.frame(),
                    flags,
                )
                .is_err()
            {
                for index in 0..published {
                    let _ = p
                        .space
                        .unmap_raw(VirtPage::containing(address + index * PAGE));
                }
                p.space.end_shootdown();
                return Err(ProcError::Map(MapError::NotMapped));
            }
            published += 1;
        }
        let rights = MemoryRights::READ
            .union(MemoryRights::MAP)
            .union(if writable {
                MemoryRights::WRITE
            } else {
                MemoryRights::NONE
            });
        if p.memory_caps
            .grant(address, pages_count, rights, MemoryKind::Shared, backing)
            .is_err()
        {
            for index in 0..published {
                let _ = p
                    .space
                    .unmap_raw(VirtPage::containing(address + index * PAGE));
            }
            p.space.end_shootdown();
            return Err(ProcError::MemoryQuota);
        }
        for (index, page) in retained.iter().enumerate() {
            p.shared_maps.push(SharedMapping {
                va: address + index as u64 * PAGE,
                page: Arc::clone(page),
                source: backing,
                flags,
            });
        }
        p.space.end_shootdown();
        Ok(())
    })
    .map_err(|error| match error {
        ProcError::Handle(HandleError::RightsDenied) => LinuxAshmemError::Permission,
        _ => LinuxAshmemError::NoMemory,
    })
}

/// Installs a read-only Linux virtual file and initializes its offset.
///
/// 安装只读 Linux 虚拟文件；失败不留下部分 fd 状态。
#[cfg(feature = "linux-abi")]
pub(crate) fn linux_install_file(pid: ObjId, handle: u64, close_on_exec: bool) -> Option<u32> {
    with_proc(pid, |p| {
        let linux = p.linux.as_mut().ok_or(ProcError::Exited)?;
        if handle == 0 {
            return Err(ProcError::Exited);
        }
        let fd = linux
            .fds
            .install(
                handle,
                kernel_core::object::Rights::READ,
                compat_core::fd::CompatKind::File,
                close_on_exec,
            )
            .map_err(|_| ProcError::NoTaskSlot)?;
        Ok(fd.fd())
    })
    .ok()
}

/// Installs a writable virtual file with explicit read/write rights.
#[cfg(feature = "linux-abi")]
pub(crate) fn linux_install_rw_file(
    pid: ObjId,
    handle: u64,
    readable: bool,
    writable: bool,
    close_on_exec: bool,
) -> Option<u32> {
    with_proc(pid, |p| {
        let linux = p.linux.as_mut().ok_or(ProcError::Exited)?;
        if handle == 0 || !readable && !writable {
            return Err(ProcError::Exited);
        }
        let rights = if readable {
            kernel_core::object::Rights::READ
        } else {
            kernel_core::object::Rights::NONE
        }
        .union(if writable {
            kernel_core::object::Rights::WRITE
        } else {
            kernel_core::object::Rights::NONE
        });
        let fd = linux
            .fds
            .install(
                handle,
                rights,
                compat_core::fd::CompatKind::File,
                close_on_exec,
            )
            .map_err(|_| ProcError::NoTaskSlot)?;
        Ok(fd.fd())
    })
    .ok()
}

/// Installs one pidfd retaining the target process identity.
#[cfg(feature = "linux-abi")]
pub(crate) fn linux_install_pidfd(
    pid: ObjId,
    target: ObjId,
    close_on_exec: bool,
) -> Option<u32> {
    with_proc(pid, |p| {
        let linux = p.linux.as_mut().ok_or(ProcError::Exited)?;
        let fd = linux
            .fds
            .install(
                target.raw(),
                kernel_core::object::Rights::READ,
                compat_core::fd::CompatKind::Pidfd,
                close_on_exec,
            )
            .map_err(|_| ProcError::NoTaskSlot)?;
        Ok(fd.fd())
    })
    .ok()
}

/// Installs a read-only Linux directory and initializes its entry cursor.
///
/// 安装只读 Linux 目录；失败不留下部分 fd 状态。
#[cfg(feature = "linux-abi")]
pub(crate) fn linux_install_dir(pid: ObjId, handle: u64, close_on_exec: bool) -> Option<u32> {
    with_proc(pid, |p| {
        let linux = p.linux.as_mut().ok_or(ProcError::Exited)?;
        if handle == 0 {
            return Err(ProcError::Exited);
        }
        let fd = linux
            .fds
            .install(
                handle,
                kernel_core::object::Rights::READ,
                compat_core::fd::CompatKind::Directory,
                close_on_exec,
            )
            .map_err(|_| ProcError::NoTaskSlot)?;
        Ok(fd.fd())
    })
    .ok()
}

/// Installs one path-only descriptor without granting stream read/write access.
#[cfg(feature = "linux-abi")]
pub(crate) fn linux_install_path(
    pid: ObjId,
    node: crate::linux_vfs::Node,
    close_on_exec: bool,
) -> Option<u32> {
    with_proc(pid, |p| {
        let linux = p.linux.as_mut().ok_or(ProcError::Exited)?;
        let fd = linux
            .fds
            .install(
                node.inode(),
                kernel_core::object::Rights::READ,
                compat_core::fd::CompatKind::Path,
                close_on_exec,
            )
            .map_err(|_| ProcError::NoTaskSlot)?;
        Ok(fd.fd())
    })
    .ok()
}

/// Resolves the namespace node referenced by one path-only descriptor.
#[cfg(feature = "linux-abi")]
pub(crate) fn linux_path_node(pid: ObjId, fd: u32) -> Option<crate::linux_vfs::Node> {
    let entry = linux_fd(pid, fd)?;
    if entry.kind != compat_core::fd::CompatKind::Path {
        return None;
    }
    crate::linux_vfs::node_from_inode(entry.handle)
}

/// Returns `(handle, offset)` for an open read-only Linux file.
///
/// 返回已打开只读 Linux 文件的虚拟句柄与游标。
#[cfg(feature = "linux-abi")]
pub(crate) fn linux_file_state(pid: ObjId, fd: u32) -> Option<(u64, u64)> {
    crate::kobj::with(|t| match t.get(pid) {
        Ok(KObject::Process(p)) => {
            let linux = p.linux.as_ref()?;
            let entry = linux.fds.get_fd(fd)?;
            let offset = linux.fds.fd_offset(fd)?;
            (entry.kind == compat_core::fd::CompatKind::File
                && entry.rights.contains(kernel_core::object::Rights::READ))
            .then_some((entry.handle, offset))
        }
        _ => None,
    })
}

/// Commits a Linux file cursor after a successful operation.
///
/// 仅在成功操作后提交文件游标。
#[cfg(feature = "linux-abi")]
pub(crate) fn set_linux_file_offset(pid: ObjId, fd: u32, offset: u64) -> bool {
    with_proc(pid, |p| {
        let linux = p.linux.as_mut().ok_or(ProcError::Exited)?;
        let entry = linux.fds.get_fd(fd).ok_or(ProcError::NoTaskSlot)?;
        if entry.kind != compat_core::fd::CompatKind::File {
            return Err(ProcError::NoTaskSlot);
        }
        if !linux.fds.set_fd_offset(fd, offset) {
            return Err(ProcError::NoTaskSlot);
        }
        Ok(())
    })
    .is_ok()
}

/// Returns the shared open-file cursor for any Linux descriptor kind.
#[cfg(feature = "linux-abi")]
pub(crate) fn linux_fd_offset(pid: ObjId, fd: u32) -> Option<u64> {
    crate::kobj::with(|table| match table.get(pid) {
        Ok(KObject::Process(process)) => process.linux.as_ref()?.fds.fd_offset(fd),
        _ => None,
    })
}

/// Returns how many live descriptors in this process reference a handle.
#[cfg(feature = "linux-abi")]
pub(crate) fn linux_handle_fd_count(pid: ObjId, handle: u64) -> usize {
    crate::kobj::with(|table| match table.get(pid) {
        Ok(KObject::Process(process)) => process
            .linux
            .as_ref()
            .map(|linux| linux.fds.handle_fd_count(handle))
            .unwrap_or(0),
        _ => 0,
    })
}

/// Commits a shared open-file cursor for any Linux descriptor kind.
#[cfg(feature = "linux-abi")]
pub(crate) fn set_linux_fd_offset(pid: ObjId, fd: u32, offset: u64) -> bool {
    with_proc(pid, |process| {
        process
            .linux
            .as_mut()
            .ok_or(ProcError::Exited)?
            .fds
            .set_fd_offset(fd, offset)
            .then_some(())
            .ok_or(ProcError::NoTaskSlot)
    })
    .is_ok()
}

/// Returns `(backing identity, open-file-description identity)` for a flock.
#[cfg(feature = "linux-abi")]
pub(crate) fn linux_file_lock_key(pid: ObjId, fd: u32) -> Option<(u64, u64)> {
    crate::kobj::with(|table| match table.get(pid) {
        Ok(KObject::Process(process)) => {
            let linux = process.linux.as_ref()?;
            let entry = linux.fds.get_fd(fd)?;
            let description = linux.fds.description_identity(fd)?;
            let backing = linux
                .ashmem
                .iter()
                .find(|ashmem| ashmem.handle == entry.handle)
                .map(|ashmem| ashmem.buffer.id)
                .unwrap_or(entry.handle);
            Some((backing, description))
        }
        _ => None,
    })
}

/// Returns `(handle, next_entry)` for an open compatibility directory.
///
/// 返回已打开兼容目录的虚拟句柄与下一个目录项序号。
#[cfg(feature = "linux-abi")]
pub(crate) fn linux_dir_state(pid: ObjId, fd: u32) -> Option<(u64, u64)> {
    crate::kobj::with(|t| match t.get(pid) {
        Ok(KObject::Process(p)) => {
            let linux = p.linux.as_ref()?;
            let entry = linux.fds.get_fd(fd)?;
            let offset = linux.fds.fd_offset(fd)?;
            (entry.kind == compat_core::fd::CompatKind::Directory
                && entry.rights.contains(kernel_core::object::Rights::READ))
            .then_some((entry.handle, offset))
        }
        _ => None,
    })
}

/// Commits a directory entry cursor after a successful `getdents64`.
///
/// 仅在成功返回目录项后提交目录游标。
#[cfg(feature = "linux-abi")]
pub(crate) fn set_linux_dir_offset(pid: ObjId, fd: u32, offset: u64) -> bool {
    with_proc(pid, |p| {
        let linux = p.linux.as_mut().ok_or(ProcError::Exited)?;
        let entry = linux.fds.get_fd(fd).ok_or(ProcError::NoTaskSlot)?;
        if entry.kind != compat_core::fd::CompatKind::Directory {
            return Err(ProcError::NoTaskSlot);
        }
        if !linux.fds.set_fd_offset(fd, offset) {
            return Err(ProcError::NoTaskSlot);
        }
        Ok(())
    })
    .is_ok()
}

/// Closes one Linux fd and resets its retired cursor.
///
/// 关闭 Linux fd；后续访问必须经过新的 fd 世代。
#[cfg(feature = "linux-abi")]
pub(crate) fn linux_close_fd(pid: ObjId, fd: u32) -> bool {
    with_proc(pid, |p| {
        let linux = p.linux.as_mut().ok_or(ProcError::Exited)?;
        let handle = linux.fds.get_fd(fd).map(|entry| entry.handle);
        let description = linux.fds.description_identity(fd);
        linux.fds.close_fd(fd).map_err(|_| ProcError::NoTaskSlot)?;
        if let Some(description) = description {
            if linux.fds.description_ref_count(description) == 0 {
                crate::linux_abi::release_flock_description(description);
            }
        }
        if let Some(handle) = handle {
            release_unreferenced_pipe(linux, handle);
        }
        Ok(())
    })
    .is_ok()
}

#[cfg(feature = "linux-abi")]
pub(crate) fn linux_close_range(
    pid: ObjId,
    first: u32,
    last: u32,
    close_on_exec: bool,
    unshare: bool,
) -> bool {
    if first > last {
        return false;
    }
    with_proc(pid, |p| {
        let linux = p.linux.as_mut().ok_or(ProcError::Exited)?;
        if unshare {
            let fds = linux.fds.clone();
            linux.fds = fds;
        }
        let mut released = Vec::new();
        let mut descriptions = Vec::new();
        let allocated_upper = linux
            .fds
            .allocated_capacity()
            .saturating_sub(1)
            .min(linux.fds.soft_limit().saturating_sub(1)) as u32;
        let upper = last.min(allocated_upper);
        if first <= upper {
            for fd in first..=upper {
                if close_on_exec {
                    let _ = linux.fds.set_close_on_exec_fd(fd, true);
                } else if let Some(handle) = linux.fds.get_fd(fd).map(|entry| entry.handle) {
                    if let Some(description) = linux.fds.description_identity(fd) {
                        if !descriptions.contains(&description) {
                            descriptions.try_reserve(1).map_err(|_| ProcError::NoTaskSlot)?;
                            descriptions.push(description);
                        }
                    }
                    if linux.fds.close_fd(fd).is_ok() {
                        released.push(handle);
                    }
                }
            }
        }
        for handle in released {
            release_unreferenced_pipe(linux, handle);
        }
        for description in descriptions {
            if linux.fds.description_ref_count(description) == 0 {
                crate::linux_abi::release_flock_description(description);
            }
        }
        Ok(())
    })
    .is_ok()
}

/// Updates close-on-exec for one Linux descriptor.
///
/// 更新 Linux fd 的 close-on-exec；只作用于当前有效世代。
#[cfg(feature = "linux-abi")]
pub(crate) fn linux_set_fd_cloexec(pid: ObjId, fd: u32, enabled: bool) -> bool {
    with_proc(pid, |p| {
        p.linux
            .as_mut()
            .ok_or(ProcError::Exited)?
            .fds
            .set_close_on_exec_fd(fd, enabled)
            .map_err(|_| ProcError::NoTaskSlot)
    })
    .is_ok()
}

/// Returns one Linux signal disposition as `(handler, flags, restorer, mask)`.
///
/// 返回 Linux 信号处置；当前保存启动配置，信号队列与用户栈帧投递仍为 pending。
#[cfg(feature = "linux-abi")]
pub(crate) fn linux_signal_action(pid: ObjId, signal: u32) -> Option<[u64; 4]> {
    crate::kobj::with(|t| match t.get(pid) {
        Ok(KObject::Process(p)) if (1..=64).contains(&signal) => {
            Some(p.linux.as_ref()?.signal_actions[signal as usize - 1])
        }
        _ => None,
    })
}

/// Commits one validated Linux signal disposition.
///
/// 提交已验证的 Linux 信号处置；实际信号生成、排队与用户栈帧投递尚未实现。
#[cfg(feature = "linux-abi")]
pub(crate) fn set_linux_signal_action(pid: ObjId, signal: u32, action: [u64; 4]) -> bool {
    with_proc(pid, |p| {
        if !(1..=64).contains(&signal) {
            return Err(ProcError::Exited);
        }
        p.linux.as_mut().ok_or(ProcError::Exited)?.signal_actions[signal as usize - 1] = action;
        Ok(())
    })
    .is_ok()
}

/// Returns the non-zero Linux pid namespace identity for one compatibility process.
///
/// 返回 Linux 兼容进程在兼容 pid 命名空间中的非零身份。
#[cfg(feature = "linux-abi")]
pub(crate) fn linux_pid(pid: ObjId) -> Option<u32> {
    crate::kobj::with(|t| match t.get(pid) {
        Ok(KObject::Process(p)) => p.linux.as_ref().map(|linux| linux.pid),
        _ => None,
    })
}

/// Returns the Linux process-group and session identities for one process.
/// 返回一个进程的 Linux 进程组与会话身份。
#[cfg(feature = "linux-abi")]
pub(crate) fn linux_process_group_state(pid: ObjId) -> Option<(u32, u32)> {
    crate::kobj::with(|t| match t.get(pid) {
        Ok(KObject::Process(process)) => process
            .linux
            .as_ref()
            .map(|linux| (linux.pgid, linux.sid)),
        _ => None,
    })
}

/// Returns the session owning a live Linux process group.
/// 返回存活 Linux 进程组所属的会话。
#[cfg(feature = "linux-abi")]
pub(crate) fn linux_process_group_session(pgid: u32) -> Option<u32> {
    crate::kobj::with(|table| {
        let mut session = None;
        table.for_each_live(|_, object| {
            if let KObject::Process(process) = object {
                if let Some(linux) = process.linux.as_ref() {
                    if linux.pgid == pgid {
                        session = Some(linux.sid);
                        return false;
                    }
                }
            }
            true
        });
        session
    })
}

/// Commits process-group and session identities after ABI validation.
/// 在 ABI 校验后提交进程组与会话身份。
#[cfg(feature = "linux-abi")]
pub(crate) fn linux_set_process_group_state(pid: ObjId, pgid: u32, sid: u32) -> bool {
    with_proc(pid, |process| {
        let linux = process.linux.as_mut().ok_or(ProcError::Exited)?;
        linux.pgid = pgid;
        linux.sid = sid;
        Ok(())
    })
    .is_ok()
}

/// Returns the Linux ABI capability view for one compatibility process.
#[cfg(feature = "linux-abi")]
pub(crate) fn linux_capabilities(pid: ObjId) -> Option<LinuxCapabilities> {
    with_proc(pid, |process| {
        let linux = process.linux.as_ref().ok_or(ProcError::Exited)?;
        Ok(LinuxCapabilities {
            effective: linux.cap_effective,
            permitted: linux.cap_permitted,
            inheritable: linux.cap_inheritable,
        })
    })
    .ok()
}

/// Replaces the Linux ABI capability view without changing native authority.
#[cfg(feature = "linux-abi")]
pub(crate) fn set_linux_capabilities(pid: ObjId, capabilities: LinuxCapabilities) -> bool {
    with_proc(pid, |process| {
        let linux = process.linux.as_mut().ok_or(ProcError::Exited)?;
        linux.cap_effective = capabilities.effective;
        linux.cap_permitted = capabilities.permitted;
        linux.cap_inheritable = capabilities.inheritable;
        Ok(())
    })
    .is_ok()
}

/// Returns the Linux ABI credential state for one compatibility process.
#[cfg(feature = "linux-abi")]
pub(crate) fn linux_credentials(pid: ObjId) -> Option<LinuxCredentials> {
    with_proc(pid, |process| {
        let linux = process.linux.as_ref().ok_or(ProcError::Exited)?;
        Ok(LinuxCredentials {
            uid: linux.uid,
            euid: linux.euid,
            suid: linux.suid,
            fsuid: linux.fsuid,
            gid: linux.gid,
            egid: linux.egid,
            sgid: linux.sgid,
            fsgid: linux.fsgid,
        })
    })
    .ok()
}

/// Replaces Linux ABI credentials without changing native Jasper authority.
#[cfg(feature = "linux-abi")]
pub(crate) fn set_linux_credentials(pid: ObjId, credentials: LinuxCredentials) -> bool {
    with_proc(pid, |process| {
        let linux = process.linux.as_mut().ok_or(ProcError::Exited)?;
        linux.uid = credentials.uid;
        linux.euid = credentials.euid;
        linux.suid = credentials.suid;
        linux.fsuid = credentials.fsuid;
        linux.gid = credentials.gid;
        linux.egid = credentials.egid;
        linux.sgid = credentials.sgid;
        linux.fsgid = credentials.fsgid;
        Ok(())
    })
    .is_ok()
}

/// Copies the process supplementary group list for Linux `getgroups`.
#[cfg(feature = "linux-abi")]
pub(crate) fn linux_supplementary_groups(pid: ObjId) -> Option<Vec<u32>> {
    with_proc(pid, |process| {
        Ok(process
            .linux
            .as_ref()
            .ok_or(ProcError::Exited)?
            .supplementary_groups
            .clone())
    })
    .ok()
}

/// Replaces the bounded supplementary group list.
#[cfg(feature = "linux-abi")]
pub(crate) fn set_linux_supplementary_groups(pid: ObjId, groups: &[u32]) -> bool {
    with_proc(pid, |process| {
        let linux = process.linux.as_mut().ok_or(ProcError::Exited)?;
        linux.supplementary_groups.clear();
        linux
            .supplementary_groups
            .try_reserve(groups.len())
            .map_err(|_| ProcError::NoTaskSlot)?;
        linux.supplementary_groups.extend_from_slice(groups);
        Ok(())
    })
    .is_ok()
}

/// Returns the process-local membarrier registration bits.
#[cfg(feature = "linux-abi")]
pub(crate) fn linux_membarrier_flags(pid: ObjId) -> Option<u8> {
    with_proc(pid, |process| {
        Ok(process
            .linux
            .as_ref()
            .ok_or(ProcError::Exited)?
            .membarrier_flags)
    })
    .ok()
}

/// Atomically adds process-local membarrier registration bits.
#[cfg(feature = "linux-abi")]
pub(crate) fn register_linux_membarrier(pid: ObjId, flags: u8) -> bool {
    with_proc(pid, |process| {
        let linux = process.linux.as_mut().ok_or(ProcError::Exited)?;
        linux.membarrier_flags |= flags;
        Ok(())
    })
    .is_ok()
}

/// Returns the process-local Linux umask.
#[cfg(feature = "linux-abi")]
pub(crate) fn linux_umask(pid: ObjId) -> Option<u32> {
    with_proc(pid, |process| {
        Ok(process.linux.as_ref().ok_or(ProcError::Exited)?.umask)
    })
    .ok()
}

/// Replaces the process-local Linux umask.
#[cfg(feature = "linux-abi")]
pub(crate) fn set_linux_umask(pid: ObjId, value: u32) -> bool {
    with_proc(pid, |process| {
        process.linux.as_mut().ok_or(ProcError::Exited)?.umask = value & 0o777;
        Ok(())
    })
    .is_ok()
}

/// Returns the Linux ABI I/O priority.
#[cfg(feature = "linux-abi")]
pub(crate) fn linux_ioprio(pid: ObjId) -> Option<u32> {
    with_proc(pid, |process| {
        Ok(process.linux.as_ref().ok_or(ProcError::Exited)?.ioprio)
    })
    .ok()
}

/// Replaces the Linux ABI I/O priority.
#[cfg(feature = "linux-abi")]
pub(crate) fn set_linux_ioprio(pid: ObjId, value: u32) -> bool {
    with_proc(pid, |process| {
        process.linux.as_mut().ok_or(ProcError::Exited)?.ioprio = value;
        Ok(())
    })
    .is_ok()
}

#[cfg(feature = "linux-abi")]
pub(crate) fn linux_ioprio_group(pgid: u32) -> Option<(u32, Vec<ObjId>)> {
    let mut value = None;
    let mut members = Vec::new();
    crate::kobj::with(|table| {
        table.for_each_live(|id, object| {
            if let KObject::Process(process) = object {
                if let Some(linux) = process.linux.as_ref() {
                    if linux.pgid == pgid {
                        value.get_or_insert(linux.ioprio);
                        members.push(id);
                    }
                }
            }
            true
        });
    });
    value.map(|value| (value, members))
}

#[cfg(feature = "linux-abi")]
pub(crate) fn set_linux_ioprio_group(pgid: u32, value: u32) -> bool {
    let Some((_, members)) = linux_ioprio_group(pgid) else {
        return false;
    };
    members
        .into_iter()
        .all(|member| set_linux_ioprio(member, value))
}

/// Records the irreversible Linux `no_new_privs` process flag.
#[cfg(feature = "linux-abi")]
pub(crate) fn linux_set_no_new_privs(pid: ObjId) -> bool {
    with_proc(pid, |process| {
        process
            .linux
            .as_mut()
            .ok_or(ProcError::Exited)?
            .no_new_privs = true;
        Ok(())
    })
    .is_ok()
}

#[cfg(feature = "linux-abi")]
pub(crate) fn linux_no_new_privs(pid: ObjId) -> Option<bool> {
    crate::kobj::with(|t| match t.get(pid) {
        Ok(KObject::Process(p)) => Some(p.linux.as_ref()?.no_new_privs),
        _ => None,
    })
}

#[cfg(feature = "linux-abi")]
pub(crate) fn linux_shstk_status(pid: ObjId) -> Option<u64> {
    with_proc(pid, |process| {
        Ok(process.linux.as_ref().ok_or(ProcError::Exited)?.shstk_features)
    })
    .ok()
}

#[cfg(feature = "linux-abi")]
pub(crate) fn linux_lock_shstk_features(pid: ObjId, features: u64) -> bool {
    if features & !3 != 0 {
        return false;
    }
    with_proc(pid, |process| {
        process
            .linux
            .as_mut()
            .ok_or(ProcError::Exited)?
            .shstk_locked |= features;
        Ok(())
    })
    .is_ok()
}

/// Enables Linux seccomp strict mode for the compatibility process.
#[cfg(feature = "linux-abi")]
pub(crate) fn linux_set_seccomp_strict(pid: ObjId) -> bool {
    with_proc(pid, |process| {
        let linux = process.linux.as_mut().ok_or(ProcError::Exited)?;
        if !linux.no_new_privs {
            return Err(ProcError::NoTaskSlot);
        }
        linux.seccomp_strict = true;
        Ok(())
    })
    .is_ok()
}

/// Appends one prevalidated filter to the process's ordered seccomp stack.
#[cfg(feature = "linux-abi")]
pub(crate) fn linux_install_seccomp_filter(pid: ObjId, filter: Vec<SeccompInsn>) -> bool {
    with_proc(pid, |process| {
        let linux = process.linux.as_mut().ok_or(ProcError::Exited)?;
        if !linux.no_new_privs
            || linux.seccomp_filters.len() >= compat_core::seccomp::MAX_FILTER_DEPTH
        {
            return Err(ProcError::NoTaskSlot);
        }
        linux
            .seccomp_filters
            .try_reserve(1)
            .map_err(|_| ProcError::NoTaskSlot)?;
        linux.seccomp_filters.push(filter);
        Ok(())
    })
    .is_ok()
}

/// Reports the Linux seccomp mode: disabled, strict, or filter.
#[cfg(feature = "linux-abi")]
pub(crate) fn linux_seccomp_mode(pid: ObjId) -> Option<u32> {
    crate::kobj::with(|table| match table.get(pid) {
        Ok(KObject::Process(process)) => {
            let linux = process.linux.as_ref()?;
            Some(if !linux.seccomp_filters.is_empty() {
                2
            } else if linux.seccomp_strict {
                1
            } else {
                0
            })
        }
        _ => None,
    })
}

/// Evaluates strict mode and every installed filter for one syscall.
#[cfg(feature = "linux-abi")]
pub(crate) fn linux_seccomp_action(
    pid: ObjId,
    data: &[u8; compat_core::seccomp::SECCOMP_DATA_BYTES],
) -> SeccompAction {
    crate::kobj::with(|t| match t.get(pid) {
        Ok(KObject::Process(p)) => {
            let Some(linux) = p.linux.as_ref() else {
                return SeccompAction::Allow;
            };
            if linux.seccomp_strict {
                let number = i32::from_le_bytes(data[..4].try_into().unwrap());
                return if matches!(number, 0 | 1 | 15 | 60 | 231) {
                    SeccompAction::Allow
                } else {
                    SeccompAction::KillProcess
                };
            }
            linux
                .seccomp_filters
                .iter()
                .fold(SeccompAction::Allow, |combined, filter| {
                    evaluate_seccomp(filter, data)
                        .map_or(SeccompAction::KillProcess, |action| {
                            combined.combine(action)
                        })
                })
        }
        _ => SeccompAction::Allow,
    })
}

/// Returns the Linux execution personality.
#[cfg(feature = "linux-abi")]
pub(crate) fn linux_personality(pid: ObjId) -> Option<u32> {
    with_proc(pid, |process| {
        Ok(process.linux.as_ref().ok_or(ProcError::Exited)?.personality)
    })
    .ok()
}

/// Replaces the Linux execution personality.
#[cfg(feature = "linux-abi")]
pub(crate) fn set_linux_personality(pid: ObjId, value: u32) -> bool {
    with_proc(pid, |process| {
        process.linux.as_mut().ok_or(ProcError::Exited)?.personality = value;
        Ok(())
    })
    .is_ok()
}

/// Returns the parent-death signal configured for one Linux process.
#[cfg(feature = "linux-abi")]
pub(crate) fn linux_pdeathsig(pid: ObjId) -> Option<u32> {
    with_proc(pid, |process| {
        Ok(process.linux.as_ref().ok_or(ProcError::Exited)?.pdeathsig)
    })
    .ok()
}

/// Replaces the parent-death signal configured for one Linux process.
#[cfg(feature = "linux-abi")]
pub(crate) fn set_linux_pdeathsig(pid: ObjId, signal: u32) -> bool {
    with_proc(pid, |process| {
        process.linux.as_mut().ok_or(ProcError::Exited)?.pdeathsig = signal;
        Ok(())
    })
    .is_ok()
}

/// Returns whether one Linux process is a child subreaper.
#[cfg(feature = "linux-abi")]
pub(crate) fn linux_subreaper(pid: ObjId) -> Option<bool> {
    with_proc(pid, |process| {
        Ok(process.linux.as_ref().ok_or(ProcError::Exited)?.subreaper)
    })
    .ok()
}

/// Replaces one process's child-subreaper property.
#[cfg(feature = "linux-abi")]
pub(crate) fn set_linux_subreaper(pid: ObjId, enabled: bool) -> bool {
    with_proc(pid, |process| {
        process.linux.as_mut().ok_or(ProcError::Exited)?.subreaper = enabled;
        Ok(())
    })
    .is_ok()
}

/// Records the signal that terminates one Linux process.
#[cfg(feature = "linux-abi")]
pub(crate) fn set_linux_termination_signal(pid: ObjId, signal: u32) -> bool {
    if !(1..=64).contains(&signal) {
        return false;
    }
    with_proc(pid, |process| {
        let linux = process.linux.as_mut().ok_or(ProcError::Exited)?;
        if linux.termination_signal == 0 {
            linux.termination_signal = signal;
        }
        Ok(())
    })
    .is_ok()
}

/// Returns the process-local Linux resource limits.
#[cfg(feature = "linux-abi")]
pub(crate) fn linux_rlimits(pid: ObjId) -> Option<LinuxRlimits> {
    with_proc(pid, |process| {
        Ok(process.linux.as_ref().ok_or(ProcError::Exited)?.rlimits)
    })
    .ok()
}

/// Replaces the process-local Linux resource limits.
#[cfg(feature = "linux-abi")]
pub(crate) fn set_linux_rlimits(pid: ObjId, limits: LinuxRlimits) -> bool {
    with_proc(pid, |process| {
        let linux = process.linux.as_mut().ok_or(ProcError::Exited)?;
        let current = usize::try_from(limits.nofile_current).unwrap_or(usize::MAX);
        let maximum = usize::try_from(limits.nofile_maximum).unwrap_or(usize::MAX);
        if !linux.fds.set_limits(current, maximum) {
            return Err(ProcError::NoTaskSlot);
        }
        linux.rlimits = limits;
        Ok(())
    })
    .is_ok()
}

/// Creates one bounded legacy AIO context.
#[cfg(feature = "linux-abi")]
pub(crate) fn linux_aio_create(pid: ObjId, max_events: usize) -> Option<u64> {
    with_proc(pid, |process| {
        let linux = process.linux.as_mut().ok_or(ProcError::Exited)?;
        if linux.aio_contexts.len() >= 8 {
            return Err(ProcError::NoTaskSlot);
        }
        let id = NEXT_LINUX_AIO_CONTEXT.fetch_add(1, Ordering::AcqRel);
        if id == 0 || id == u64::MAX {
            return Err(ProcError::NoTaskSlot);
        }
        linux
            .aio_contexts
            .try_reserve(1)
            .map_err(|_| ProcError::NoTaskSlot)?;
        linux.aio_contexts.push(LinuxAioContext {
            id,
            state: Arc::new(SpinLock::new(LinuxAioState {
                max_events,
                events: VecDeque::new(),
            })),
        });
        Ok(id)
    })
    .ok()
}

/// Returns one legacy AIO context state by opaque context id.
#[cfg(feature = "linux-abi")]
pub(crate) fn linux_aio_state(
    pid: ObjId,
    id: u64,
) -> Option<Arc<SpinLock<LinuxAioState>>> {
    crate::kobj::with(|table| match table.get(pid) {
        Ok(KObject::Process(process)) => process
            .linux
            .as_ref()?
            .aio_contexts
            .iter()
            .find(|context| context.id == id)
            .map(|context| Arc::clone(&context.state)),
        _ => None,
    })
}

/// Destroys one legacy AIO context.
#[cfg(feature = "linux-abi")]
pub(crate) fn linux_aio_destroy(pid: ObjId, id: u64) -> bool {
    with_proc(pid, |process| {
        let linux = process.linux.as_mut().ok_or(ProcError::Exited)?;
        let Some(index) = linux
            .aio_contexts
            .iter()
            .position(|context| context.id == id)
        else {
            return Err(ProcError::NoSuchProcess);
        };
        linux.aio_contexts.remove(index);
        Ok(())
    })
    .is_ok()
}

/// Sums scheduler CPU ticks over every live thread in one Linux process.
/// 汇总一个 Linux 进程全部存活线程的调度器 CPU ticks。
#[cfg(feature = "linux-abi")]
pub(crate) fn linux_process_cpu_ticks(pid: ObjId) -> Option<u64> {
    let tasks = {
        let registry = REG.lock();
        registry
            .members
            .iter()
            .filter(|member| member.process == pid)
            .map(|member| member.task)
            .collect::<Vec<_>>()
    };
    let exited = crate::kobj::with(|table| match table.get(pid) {
        Ok(KObject::Process(process)) => {
            process.linux.as_ref().map(|linux| linux.exited_cpu_ticks)
        }
        _ => None,
    })?;
    Some(tasks.into_iter().filter_map(sched::cpu_ticks).fold(
        exited,
        u64::saturating_add,
    ))
}

/// Returns the accumulated CPU ticks of direct children already reaped.
/// 返回已回收直接子进程的累计 CPU ticks。
#[cfg(feature = "linux-abi")]
pub(crate) fn linux_children_cpu_ticks(pid: ObjId) -> Option<u64> {
    crate::kobj::with(|table| match table.get(pid) {
        Ok(KObject::Process(process)) => process.linux.as_ref().map(|linux| linux.child_cpu_ticks),
        _ => None,
    })
}

/// Adds one reaped direct child's CPU time to the waiting parent.
/// 将一个已回收直接子进程的 CPU 时间累加到等待父进程。
#[cfg(feature = "linux-abi")]
pub(crate) fn linux_account_child_cpu(pid: ObjId, ticks: u64) -> bool {
    with_proc(pid, |process| {
        let linux = process.linux.as_mut().ok_or(ProcError::Exited)?;
        linux.child_cpu_ticks = linux.child_cpu_ticks.saturating_add(ticks);
        Ok(())
    })
    .is_ok()
}

/// Retains one exiting thread's CPU ticks in its Linux process state.
/// 将一个退出线程的 CPU ticks 保留到所属 Linux 进程状态。
#[cfg(feature = "linux-abi")]
pub(crate) fn linux_account_exited_thread_cpu(pid: ObjId, ticks: u64) -> bool {
    with_proc(pid, |process| {
        let linux = process.linux.as_mut().ok_or(ProcError::Exited)?;
        linux.exited_cpu_ticks = linux.exited_cpu_ticks.saturating_add(ticks);
        Ok(())
    })
    .is_ok()
}

/// Resolves one ABI-visible Linux PID to the owning Jasper process object.
#[cfg(feature = "linux-abi")]
pub(crate) fn linux_process_for_pid(linux_pid: u32) -> Option<ObjId> {
    crate::kobj::with(|table| {
        let mut found = None;
        table.for_each_live(|id, object| {
            if let KObject::Process(process) = object {
                if process
                    .linux
                    .as_ref()
                    .is_some_and(|linux| linux.pid == linux_pid)
                {
                    found = Some(id);
                    return false;
                }
            }
            true
        });
        found
    })
}

/// Returns one Linux process's nice value.
#[cfg(feature = "linux-abi")]
pub(crate) fn linux_nice(pid: ObjId) -> Option<i32> {
    crate::kobj::with(|table| match table.get(pid) {
        Ok(KObject::Process(process)) => process.linux.as_ref().map(|linux| linux.nice),
        _ => None,
    })
}

/// Updates one Linux process's nice value.
#[cfg(feature = "linux-abi")]
pub(crate) fn linux_set_nice(pid: ObjId, nice: i32) -> bool {
    with_proc(pid, |process| {
        let linux = process.linux.as_mut().ok_or(ProcError::Exited)?;
        linux.nice = nice;
        Ok(())
    })
    .is_ok()
}

/// Returns Linux scheduler attributes represented by the compatibility profile.
#[cfg(feature = "linux-abi")]
pub(crate) fn linux_sched_attributes(pid: ObjId) -> Option<(bool, u16, u16)> {
    crate::kobj::with(|table| match table.get(pid) {
        Ok(KObject::Process(process)) => process.linux.as_ref().map(|linux| {
            (
                linux.sched_reset_on_fork,
                linux.sched_util_clamp_min,
                linux.sched_util_clamp_max,
            )
        }),
        _ => None,
    })
}

/// Updates Linux scheduler attributes represented by the compatibility profile.
#[cfg(feature = "linux-abi")]
pub(crate) fn linux_set_sched_attributes(
    pid: ObjId,
    reset_on_fork: bool,
    util_min: u16,
    util_max: u16,
) -> bool {
    with_proc(pid, |process| {
        let linux = process.linux.as_mut().ok_or(ProcError::Exited)?;
        linux.sched_reset_on_fork = reset_on_fork;
        linux.sched_util_clamp_min = util_min;
        linux.sched_util_clamp_max = util_max;
        Ok(())
    })
    .is_ok()
}

/// Returns the Linux parent identity for this compatibility process.
/// 返回兼容进程的 Linux 父身份；内核创建的根进程没有父进程。
#[cfg(feature = "linux-abi")]
pub(crate) fn linux_ppid(pid: ObjId) -> Option<u32> {
    crate::kobj::with(|t| match t.get(pid) {
        Ok(KObject::Process(p)) => p.linux.as_ref().map(|linux| linux.ppid),
        _ => None,
    })
}

/// Records the exact executable path used for Linux `/proc/self/exe`.
///
/// 记录 Linux 程序的实际执行路径；超长、空或带 NUL 的路径失败关闭。
#[cfg(feature = "linux-abi")]
pub(crate) fn linux_set_exec_path(pid: ObjId, path: &[u8]) -> bool {
    if path.is_empty() || path.len() > 128 || path.contains(&0) {
        return false;
    }
    with_proc(pid, |p| {
        let linux = p.linux.as_mut().ok_or(ProcError::Exited)?;
        linux.exec_path[..path.len()].copy_from_slice(path);
        linux.exec_path_len = path.len();
        Ok(())
    })
    .is_ok()
}

/// Copies the executable path into a bounded caller buffer.
///
/// 将可执行路径复制到调用者缓冲区并返回实际长度。
#[cfg(feature = "linux-abi")]
pub(crate) fn linux_exec_path(pid: ObjId, output: &mut [u8]) -> Option<usize> {
    crate::kobj::with(|t| match t.get(pid) {
        Ok(KObject::Process(p)) => {
            let linux = p.linux.as_ref()?;
            if linux.exec_path_len == 0 {
                return None;
            }
            let len = linux.exec_path_len.min(output.len());
            output[..len].copy_from_slice(&linux.exec_path[..len]);
            Some(len)
        }
        _ => None,
    })
}

/// Returns the Linux compatibility program break.
///
/// 返回 Linux 兼容进程当前的 `brk` 地址。
#[cfg(feature = "linux-abi")]
pub(crate) fn linux_brk_value(pid: ObjId) -> Option<u64> {
    crate::kobj::with(|t| match t.get(pid) {
        Ok(KObject::Process(p)) => p
            .linux
            .as_ref()
            .map(|linux| linux.brk)
            .filter(|brk| *brk != 0),
        _ => None,
    })
}

/// Commits a fully validated Linux `brk` value.
///
/// 映射完成后提交 Linux `brk`。
#[cfg(feature = "linux-abi")]
pub(crate) fn set_linux_brk(pid: ObjId, value: u64) -> bool {
    value != 0
        && with_proc(pid, |p| {
            let linux = p.linux.as_mut().ok_or(ProcError::Exited)?;
            if linux.brk == 0 {
                return Err(ProcError::Exited);
            }
            linux.brk = value;
            Ok(())
        })
        .is_ok()
}

/// Returns the next candidate address for Linux `mmap`.
///
/// 返回 Linux `mmap` 的下一个候选地址，不预留映射。
#[cfg(feature = "linux-abi")]
pub(crate) fn linux_mmap_cursor(pid: ObjId) -> Option<u64> {
    crate::kobj::with(|t| match t.get(pid) {
        Ok(KObject::Process(p)) => p
            .linux
            .as_ref()
            .map(|linux| linux.mmap_next)
            .filter(|next| *next != 0),
        _ => None,
    })
}

/// Advances the Linux `mmap` cursor after all mappings succeed.
///
/// 仅在映射全部成功后推进 Linux `mmap` 游标。
#[cfg(feature = "linux-abi")]
pub(crate) fn set_linux_mmap_cursor(pid: ObjId, value: u64) -> bool {
    value != 0
        && with_proc(pid, |p| {
            let linux = p.linux.as_mut().ok_or(ProcError::Exited)?;
            if linux.mmap_next == 0 {
                return Err(ProcError::Exited);
            }
            linux.mmap_next = value;
            Ok(())
        })
        .is_ok()
}

/// Returns the next candidate address for Linux `MAP_32BIT`.
#[cfg(feature = "linux-abi")]
pub(crate) fn linux_mmap32_cursor(pid: ObjId) -> Option<u64> {
    crate::kobj::with(|t| match t.get(pid) {
        Ok(KObject::Process(p)) => p
            .linux
            .as_ref()
            .map(|linux| linux.mmap32_next)
            .filter(|next| *next != 0),
        _ => None,
    })
}

/// Advances the Linux `MAP_32BIT` cursor after all mappings succeed.
#[cfg(feature = "linux-abi")]
pub(crate) fn set_linux_mmap32_cursor(pid: ObjId, value: u64) -> bool {
    value != 0
        && with_proc(pid, |p| {
            let linux = p.linux.as_mut().ok_or(ProcError::Exited)?;
            if linux.mmap32_next == 0 {
                return Err(ProcError::Exited);
            }
            linux.mmap32_next = value;
            Ok(())
        })
        .is_ok()
}

/// Records the main user stack range exposed through procfs.
#[cfg(feature = "linux-abi")]
pub(crate) fn set_linux_stack_range(pid: ObjId, start: u64, end: u64) -> bool {
    start < end
        && with_proc(pid, |p| {
            p.linux
                .as_mut()
                .ok_or(ProcError::Exited)?
                .stack_range = Some((start, end));
            Ok(())
        })
        .is_ok()
}

/// Reserves a large PROT_NONE address range without allocating physical frames.
#[cfg(feature = "linux-abi")]
pub(crate) fn linux_reserve_range(pid: ObjId, start: u64, end: u64) -> Result<(), MemError> {
    if start % FRAME_SIZE != 0
        || end <= start
        || !((start >= arch::USER_WINDOW.0 && end <= arch::USER_WINDOW.1)
            || (arch::LOW_USER_WINDOW.1 > arch::LOW_USER_WINDOW.0
                && start >= arch::LOW_USER_WINDOW.0
                && end <= arch::LOW_USER_WINDOW.1))
    {
        return Err(MemError::InvalidRange);
    }
    with_proc(pid, |p| {
        let linux = p.linux.as_mut().ok_or(ProcError::Exited)?;
        if linux
            .mappings
            .iter()
            .any(|mapping| mapping.va < end && mapping.va + FRAME_SIZE > start)
            || linux
                .reservations
                .iter()
                .any(|reservation| reservation.start < end && reservation.end > start)
        {
            return Err(ProcError::Map(MapError::InvalidAddress));
        }
        linux
            .reservations
            .try_reserve(1)
            .map_err(|_| ProcError::MemoryQuota)?;
        linux.reservations.push(LinuxReservation { start, end });
        Ok(())
    })
    .map_err(|_| MemError::AlreadyMapped)
}

#[cfg(feature = "linux-abi")]
pub(crate) fn linux_range_debug(pid: ObjId) -> Option<(u64, usize, usize)> {
    crate::kobj::with(|t| match t.get(pid) {
        Ok(KObject::Process(p)) => p.linux.as_ref().map(|linux| {
            (
                linux.mmap_next,
                linux.reservations.len(),
                linux.mappings.len(),
            )
        }),
        _ => None,
    })
}

#[cfg(feature = "linux-abi")]
pub(crate) fn linux_reservation_overlap(
    pid: ObjId,
    start: u64,
    end: u64,
) -> Option<(u64, u64)> {
    crate::kobj::with(|t| match t.get(pid) {
        Ok(KObject::Process(p)) => p.linux.as_ref().and_then(|linux| {
            linux
                .reservations
                .iter()
                .find(|reservation| reservation.start < end && reservation.end > start)
                .map(|reservation| (reservation.start, reservation.end))
        }),
        _ => None,
    })
}

#[cfg(feature = "linux-abi")]
pub(crate) fn linux_next_free_start(pid: ObjId, start: u64, size: u64) -> Option<u64> {
    crate::kobj::with(|t| {
        let p = match t.get(pid) {
            Ok(KObject::Process(p)) => p,
            _ => return None,
        };
        let linux = p.linux.as_ref()?;
        let alignment = kernel_core::frame::FRAME_SIZE;
        let mut candidate = start;
        for _ in 0..linux.reservations.len().saturating_add(linux.mappings.len()).saturating_add(1) {
            let end = candidate.checked_add(size)?;
            if end > arch::USER_WINDOW.1 {
                return None;
            }
            let reservation_end = linux
                .reservations
                .iter()
                .filter(|reservation| reservation.start < end && reservation.end > candidate)
                .map(|reservation| reservation.end)
                .max();
            let mapping_end = linux
                .mappings
                .iter()
                .filter(|mapping| mapping.va < end && mapping.va + alignment > candidate)
                .map(|mapping| mapping.va + alignment)
                .max();
            let Some(next) = reservation_end.into_iter().chain(mapping_end).max() else {
                return Some(candidate);
            };
            candidate = next.checked_add(alignment - 1)? & !(alignment - 1);
        }
        None
    })
}

/// Renders this process's actual Linux mappings, lazy reservations, shared
/// mappings and device mappings for `/proc/self/maps`.
#[cfg(feature = "linux-abi")]
pub(crate) fn linux_proc_maps(pid: ObjId) -> Option<Vec<u8>> {
    use core::fmt::Write as _;

    crate::kobj::with(|t| {
        let Ok(KObject::Process(p)) = t.get(pid) else {
            return None;
        };
        let linux = p.linux.as_ref()?;
        const SOURCE_MAPPING: u32 = 0;
        const SOURCE_RESERVATION: u32 = 1;
        const SOURCE_SHARED: u32 = 2;
        const SOURCE_DEVICE: u32 = 3;
        let mut order = Vec::new();
        let source_rows = linux
            .mappings
            .len()
            .saturating_add(linux.reservations.len())
            .saturating_add(p.shared_maps.len())
            .saturating_add(p.device_maps.len());
        if order.try_reserve(source_rows).is_err() {
            #[cfg(feature = "android-art-verify")]
            crate::kprintln!(
                "[JSR-PROC-MAPS] order-reserve-fail rows={} heap={:?}",
                source_rows,
                crate::mm::heap::stats()
            );
            return None;
        }
        for (index, mapping) in linux.mappings.iter().enumerate() {
            order.push(((index as u32) << 2) | SOURCE_MAPPING);
        }
        for (index, reservation) in linux.reservations.iter().enumerate() {
            order.push(((index as u32) << 2) | SOURCE_RESERVATION);
        }
        for (index, mapping) in p.shared_maps.iter().enumerate() {
            order.push(((index as u32) << 2) | SOURCE_SHARED);
        }
        for (index, mapping) in p.device_maps.iter().enumerate() {
            order.push(((index as u32) << 2) | SOURCE_DEVICE);
        }
        let row_data =
            |code: u32| -> Option<(u64, u64, MapFlags, Option<crate::linux_vfs::FileId>)> {
                let index = (code >> 2) as usize;
                match code & 3 {
                    SOURCE_MAPPING => {
                        let mapping = *linux.mappings.get(index)?;
                        let flags = p
                            .space
                            .translate(VirtPage::containing(mapping.va))
                            .map_or(mapping.flags, |(_, flags)| flags);
                        Some((mapping.va, mapping.va + FRAME_SIZE, flags, mapping.file))
                    }
                    SOURCE_RESERVATION => {
                        let reservation = *linux.reservations.get(index)?;
                        Some((
                            reservation.start,
                            reservation.end,
                            MapFlags::READ_ONLY,
                            None,
                        ))
                    }
                    SOURCE_SHARED => {
                        let mapping = p.shared_maps.get(index)?;
                        Some((mapping.va, mapping.va + FRAME_SIZE, mapping.flags, None))
                    }
                    SOURCE_DEVICE => {
                        let mapping = p.device_maps.get(index)?;
                        Some((
                            mapping.va,
                            mapping.va + mapping.pages * FRAME_SIZE,
                            MapFlags::USER.union(MapFlags::WRITE).union(MapFlags::NO_CACHE),
                            None,
                        ))
                    }
                    _ => None,
                }
            };
        order.sort_unstable_by_key(|code| row_data(*code).map_or(u64::MAX, |row| row.0));

        // ART can create >200k page records. Compute the exact merged output
        // size without allocating a second row set, then reserve once. Letting
        // String grow geometrically can require a larger transient allocation
        // than the final maps text and fail near the bounded kernel-heap limit.
        let mut text_len = 0usize;
        let mut cursor = 0usize;
        while cursor < order.len() {
            let code = order[cursor];
            let Some((start, mut end, flags, file)) = row_data(code) else {
                #[cfg(feature = "android-art-verify")]
                crate::kprintln!("[JSR-PROC-MAPS] size-row-fail code={} rows={}", code, order.len());
                return None;
            };
            cursor += 1;
            while cursor < order.len() {
                let next_code = order[cursor];
                let Some((next_start, next_end, next_flags, next_file)) = row_data(next_code) else {
                    #[cfg(feature = "android-art-verify")]
                    crate::kprintln!(
                        "[JSR-PROC-MAPS] size-next-fail code={} rows={}",
                        next_code,
                        order.len()
                    );
                    return None;
                };
                let stack_boundary = linux.stack_range.is_some_and(|(stack_start, stack_end)| {
                    end == stack_start
                        || next_start == stack_start
                        || end == stack_end
                        || next_start == stack_end
                });
                if next_start != end || flags != next_flags || file != next_file || stack_boundary {
                    break;
                }
                end = next_end;
                cursor += 1;
            }
            let path_len = if linux
                .stack_range
                .is_some_and(|(stack_start, stack_end)| start >= stack_start && end <= stack_end)
            {
                b"[stack]".len()
            } else {
                file.and_then(|file| core::str::from_utf8(file.path()).ok())
                    .map_or(b"[anon]".len(), str::len)
            };
            text_len = text_len.saturating_add(57 + path_len);
        }
        #[cfg(feature = "android-art-verify")]
        crate::kprintln!(
            "[JSR-PROC-MAPS] rows={} text_len={} heap={:?}",
            order.len(),
            text_len,
            crate::mm::heap::stats()
        );
        let mut text = alloc::string::String::new();
        if text.try_reserve_exact(text_len).is_err() {
            #[cfg(feature = "android-art-verify")]
            crate::kprintln!(
                "[JSR-PROC-MAPS] text-reserve-fail text_len={} heap={:?}",
                text_len,
                crate::mm::heap::stats()
            );
            return None;
        }
        let mut cursor = 0usize;
        while cursor < order.len() {
            let code = order[cursor];
            let Some((start, mut end, flags, file)) = row_data(code) else {
                #[cfg(feature = "android-art-verify")]
                crate::kprintln!("[JSR-PROC-MAPS] emit-row-fail code={} rows={}", code, order.len());
                return None;
            };
            cursor += 1;
            while cursor < order.len() {
                let next_code = order[cursor];
                let Some((next_start, next_end, next_flags, next_file)) = row_data(next_code) else {
                    #[cfg(feature = "android-art-verify")]
                    crate::kprintln!(
                        "[JSR-PROC-MAPS] emit-next-fail code={} rows={}",
                        next_code,
                        order.len()
                    );
                    return None;
                };
                let stack_boundary = linux.stack_range.is_some_and(|(stack_start, stack_end)| {
                    end == stack_start
                        || next_start == stack_start
                        || end == stack_end
                        || next_start == stack_end
                });
                if next_start != end || flags != next_flags || file != next_file || stack_boundary {
                    break;
                }
                end = next_end;
                cursor += 1;
            }
            let read = if flags.contains(MapFlags::USER) {
                'r'
            } else {
                '-'
            };
            let write = if flags.contains(MapFlags::WRITE) {
                'w'
            } else {
                '-'
            };
            let execute = if flags.contains(MapFlags::EXECUTE) {
                'x'
            } else {
                '-'
            };
            let is_stack = linux
                .stack_range
                .is_some_and(|(stack_start, stack_end)| {
                    start >= stack_start && end <= stack_end
                });
            let path = if is_stack {
                "[stack]"
            } else {
                file.and_then(|file| core::str::from_utf8(file.path()).ok())
                    .unwrap_or("[anon]")
            };
            if write!(
                text,
                "{:016x}-{:016x} {}{}{}p 00000000 00:00 0 {}\n",
                start, end, read, write, execute, path
            )
            .is_err()
            {
                #[cfg(feature = "android-art-verify")]
                crate::kprintln!(
                    "[JSR-PROC-MAPS] write-fail text_len={} actual={} heap={:?}",
                    text_len,
                    text.len(),
                    crate::mm::heap::stats()
                );
                return None;
            }
        }
        #[cfg(feature = "android-art-verify")]
        {
            let stack_line = text
                .lines()
                .find(|line| line.ends_with("[stack]"))
                .unwrap_or("<missing>");
            crate::kprintln!(
                "[JSR-ANDROID-ART] maps stack_range={:?} stack_line={}",
                linux.stack_range,
                stack_line
            );
        }
        Some(text.into_bytes())
    })
}

/// Renders one Linux `/proc/self/stat` record from the live process state.
#[cfg(feature = "linux-abi")]
pub(crate) fn linux_proc_stat(pid: ObjId) -> Option<Vec<u8>> {
    use core::fmt::Write as _;

    let cpu_ticks = linux_process_cpu_ticks(pid).unwrap_or(0);
    crate::kobj::with(|t| {
        let Ok(KObject::Process(p)) = t.get(pid) else {
            return None;
        };
        let linux = p.linux.as_ref()?;
        let mut comm = [b'_'; 64];
        let mut length = 0usize;
        let count = linux.exec_path_len.min(linux.exec_path.len());
        if count != 0 {
            let path = &linux.exec_path;
            let start = path[..count]
                .iter()
                .rposition(|byte| *byte == b'/')
                .map_or(0, |index| index + 1);
            for byte in path[start..count].iter().copied().take(comm.len()) {
                comm[length] = if byte.is_ascii_graphic() && !matches!(byte, b'(' | b')') {
                    byte
                } else {
                    b'_'
                };
                length += 1;
            }
        }
        if length == 0 {
            comm[0] = b'?';
            length = 1;
        }
        let reservations = linux
            .reservations
            .iter()
            .map(|range| range.end.saturating_sub(range.start) / FRAME_SIZE)
            .sum::<u64>();
        let virtual_pages = p
            .frames
            .len()
            .saturating_add(p.shared_maps.len())
            .saturating_add(p.device_maps.iter().map(|mapping| mapping.pages as usize).sum())
            .saturating_add(reservations as usize) as u64;
        let resident_pages = p.frames.len().saturating_add(p.shared_maps.len()) as u64;
        let startstack = linux
            .stack_range
            .map(|(_, end)| end.saturating_sub(16))
            .unwrap_or(0);
        let mut text = alloc::string::String::new();
        text.try_reserve(512).ok()?;
        write!(
            text,
            "{} ({}) R {} {} {} 0 -1 4194560 0 0 0 0 {} {} 0 0 20 0 {} 0 1 {} {} 18446744073709551615 0 0 {} 0 0 0 0 0 0 0 0 0 17 0 0 0 0 0 0 0 0 0 0 0 0 0\n",
            linux.pid,
            core::str::from_utf8(&comm[..length]).unwrap_or("?"),
            linux.ppid,
            linux.pgid,
            linux.sid,
            cpu_ticks,
            0,
            p.threads_live.max(1),
            virtual_pages * FRAME_SIZE,
            resident_pages,
            startstack,
        )
        .ok()?;
        #[cfg(feature = "android-art-verify")]
        crate::kprintln!("[JSR-ANDROID-ART] stat={}", text);
        Some(text.into_bytes())
    })
}

/// Returns whether a range is fully covered by one lazy reservation.
#[cfg(feature = "linux-abi")]
pub(crate) fn linux_range_is_reserved(pid: ObjId, start: u64, end: u64) -> bool {
    with_proc(pid, |p| {
        Ok(p.linux.as_ref().is_some_and(|linux| {
            linux
                .reservations
                .iter()
                .any(|reservation| reservation.start <= start && reservation.end >= end)
        }))
    })
    .unwrap_or(false)
}

/// Removes or splits lazy reservations overlapping one address range.
#[cfg(feature = "linux-abi")]
pub(crate) fn linux_remove_reserved_range(pid: ObjId, start: u64, end: u64) -> bool {
    with_proc(pid, |p| {
        let linux = p.linux.as_mut().ok_or(ProcError::Exited)?;
        let mut changed = false;
        let mut retained = Vec::new();
        retained
            .try_reserve(linux.reservations.len().saturating_add(1))
            .map_err(|_| ProcError::MemoryQuota)?;
        for reservation in linux.reservations.iter().copied() {
            if reservation.end <= start || reservation.start >= end {
                retained.push(reservation);
                continue;
            }
            changed = true;
            if reservation.start < start {
                retained.push(LinuxReservation {
                    start: reservation.start,
                    end: start,
                });
            }
            if reservation.end > end {
                retained.push(LinuxReservation {
                    start: end,
                    end: reservation.end,
                });
            }
        }
        linux.reservations = retained;
        Ok(changed)
    })
    .unwrap_or(false)
}

/// Materializes a reserved subrange as zero-filled anonymous pages.
#[cfg(feature = "linux-abi")]
pub(crate) fn linux_materialize_reserved(
    pid: ObjId,
    start: u64,
    end: u64,
    writable: bool,
) -> Result<bool, MemError> {
    if !linux_range_is_reserved(pid, start, end) {
        return Ok(false);
    }
    if !linux_remove_reserved_range(pid, start, end) {
        return Ok(false);
    }
    let pages = (end - start) / FRAME_SIZE;
    if pages > MAX_MAP_PAGES {
        let _ = linux_reserve_range(pid, start, end);
        return Err(MemError::Quota);
    }
    if let Err(error) = map_anon(pid, start, pages, writable) {
        let _ = linux_reserve_range(pid, start, end);
        return Err(error);
    }
    Ok(true)
}

/// Reports whether any sealed range overlaps `[start, end)`.
#[cfg(feature = "linux-abi")]
pub(crate) fn linux_range_is_sealed(pid: ObjId, start: u64, end: u64) -> bool {
    with_proc(pid, |process| {
        Ok(process
            .linux
            .as_ref()
            .ok_or(ProcError::Exited)?
            .sealed_ranges
            .iter()
            .any(|(range_start, range_end)| start < *range_end && *range_start < end))
    })
    .unwrap_or(false)
}

/// Adds one bounded, merged sealed range.
#[cfg(feature = "linux-abi")]
pub(crate) fn seal_linux_range(pid: ObjId, start: u64, end: u64) -> bool {
    if start >= end {
        return false;
    }
    with_proc(pid, |process| {
        let linux = process.linux.as_mut().ok_or(ProcError::Exited)?;
        if linux.sealed_ranges.len() >= 32 {
            return Err(ProcError::NoTaskSlot);
        }
        linux
            .sealed_ranges
            .try_reserve(1)
            .map_err(|_| ProcError::NoTaskSlot)?;
        linux.sealed_ranges.push((start, end));
        linux.sealed_ranges.sort_unstable();
        let mut merged: Vec<(u64, u64)> = Vec::new();
        for (range_start, range_end) in linux.sealed_ranges.iter().copied() {
            if let Some(last) = merged.last_mut() {
                if range_start <= last.1 {
                    last.1 = last.1.max(range_end);
                    continue;
                }
            }
            merged.push((range_start, range_end));
        }
        linux.sealed_ranges = merged;
        Ok(())
    })
    .is_ok()
}

pub fn create(name: &'static str, syscalls: SyscallSet) -> Result<ObjId, ProcError> {
    create_process(name, syscalls, |_| {})
}

/// Creates a process whose x86_64 syscall entry uses the Linux compatibility flavor.
///
/// 创建使用 Linux x86_64 syscall 编号的进程。Jasper 原生 SyscallSet 保持为空；
/// Linux 调用权限由独立集合控制，标准输入输出仅映射到受控控制台哨兵。
#[cfg(feature = "linux-abi")]
pub fn create_linux(name: &'static str, calls: LinuxSyscallSet) -> Result<ObjId, ProcError> {
    let pid = allocate_linux_pid().ok_or(ProcError::NoTaskSlot)?;
    let fd_budget = FdTable::capacity_for_bytes(
        (MAX_PROCESS_FRAMES as u64).saturating_mul(FRAME_SIZE as u64),
    );
    let mut fds = FdTable::with_limits(fd_budget as usize, fd_budget as usize);
    for (fd, rights) in [(0, Rights::READ), (1, Rights::WRITE), (2, Rights::WRITE)] {
        fds.install_at(
            fd,
            LINUX_CONSOLE_HANDLE,
            rights,
            compat_core::fd::CompatKind::Other,
            false,
        )
        .map_err(|_| ProcError::NoTaskSlot)?;
    }
    let linux = LinuxProcessState {
        calls,
        fds,
        pid,
        ppid: compat_core::syscall::LINUX_COMPAT_ROOT_PPID as u32,
        pgid: pid,
        sid: pid,
        nice: 0,
        sched_reset_on_fork: false,
        sched_util_clamp_min: 0,
        sched_util_clamp_max: 1024,
        child_cpu_ticks: 0,
        exited_cpu_ticks: 0,
        cwd: crate::linux_vfs::DirectoryId::Root,
        brk: crate::arch::USER_WINDOW.0 + 0x1000_0000,
        mmap_next: crate::arch::USER_WINDOW.0 + 0x4000_0000,
        mmap32_next: crate::arch::LOW_USER_WINDOW.0 + 0x1000_0000,
        stack_range: None,
        signal_actions: [[0; 4]; 64],
        exec_path: [0; 128],
        exec_path_len: 0,
        cap_effective: (1u64 << 41) - 1,
        cap_permitted: (1u64 << 41) - 1,
        cap_inheritable: 0,
        uid: 0,
        euid: 0,
        suid: 0,
        fsuid: 0,
        gid: 0,
        egid: 0,
        sgid: 0,
        fsgid: 0,
        supplementary_groups: Vec::new(),
        membarrier_flags: 0,
        umask: 0o022,
        ioprio: (2 << 13) | 4,
        personality: 0,
        pdeathsig: 0,
        subreaper: false,
        termination_signal: 0,
        rlimits: LinuxRlimits {
            stack_current: 8 * 1024 * 1024,
            stack_maximum: u64::MAX,
            nofile_current: fd_budget,
            nofile_maximum: fd_budget,
        },
        aio_contexts: Vec::new(),
        seccomp_filters: Vec::new(),
        seccomp_strict: false,
        no_new_privs: false,
        shstk_features: 0,
        shstk_locked: 0,
        mappings: Vec::new(),
        reservations: Vec::new(),
        sealed_ranges: Vec::new(),
        pipes: Vec::new(),
        next_pipe_handle: LINUX_PIPE_HANDLE_BASE,
        sockets: Vec::new(),
        next_socket_handle: LINUX_SOCKET_HANDLE_BASE,
        ashmem: Vec::new(),
        next_ashmem_handle: LINUX_ASHMEM_HANDLE_BASE,
        binder: Vec::new(),
        next_binder_handle: LINUX_BINDER_HANDLE_BASE,
        ion_devices: Vec::new(),
        next_ion_device_handle: LINUX_ION_DEVICE_HANDLE_BASE,
        ion_allocations: Vec::new(),
        next_ion_user_handle: 1,
        eventfds: Vec::new(),
        next_eventfd_handle: LINUX_EVENTFD_HANDLE_BASE,
        timerfds: Vec::new(),
        next_timerfd_handle: LINUX_TIMERFD_HANDLE_BASE,
        signalfds: Vec::new(),
        next_signalfd_handle: LINUX_SIGNALFD_HANDLE_BASE,
        inotifies: Vec::new(),
        next_inotify_handle: LINUX_INOTIFY_HANDLE_BASE,
        userfaultfds: Vec::new(),
        next_userfault_handle: LINUX_USERFAULT_HANDLE_BASE,
        message_queues: Vec::new(),
        next_mq_handle: LINUX_MQ_HANDLE_BASE,
        mount_trees: Vec::new(),
        next_mount_tree_handle: LINUX_MOUNT_TREE_HANDLE_BASE,
        fs_contexts: Vec::new(),
        next_fs_context_handle: LINUX_FS_CONTEXT_HANDLE_BASE,
        landlock_rulesets: Vec::new(),
        next_landlock_handle: LINUX_LANDLOCK_HANDLE_BASE,
        epolls: Vec::new(),
        next_epoll_handle: LINUX_EPOLL_HANDLE_BASE,
        iourings: Vec::new(),
        dma_heaps: Vec::new(),
        next_dma_heap_handle: LINUX_DMA_HEAP_HANDLE_BASE,
        dmabufs: Vec::new(),
        sync_files: Vec::new(),
        next_sync_file_handle: LINUX_SYNC_FILE_HANDLE_BASE,
        vfork_parent: None,
    };
    create_process(name, SyscallSet::EMPTY, move |process| {
        process.linux = Some(linux);
    })
}

/// Swaps one single-threaded Linux process onto a fresh address space for exec.
/// 为 exec 将单线程 Linux 进程切换到新的空地址空间，并返回可回滚的旧状态。
#[cfg(feature = "linux-abi")]
pub(crate) fn begin_exec_address_space(pid: ObjId) -> Result<ExecAddressSpace, ProcError> {
    let capability_capacity = kobj::with(|t| match t.get(pid) {
        Ok(KObject::Process(p))
            if p.state == ProcState::Running && p.threads_live == 1 && p.linux.is_some() =>
        {
            Ok(p.memory_caps.capacity())
        }
        Ok(KObject::Process(_)) => Err(ProcError::Exited),
        _ => Err(ProcError::NoSuchProcess),
    })?;
    let empty_caps =
        DynamicMemoryCapabilityTable::new(capability_capacity).ok_or(ProcError::OutOfFrames)?;
    let space = VmSpace::new().map_err(ProcError::Map)?;
    let memory_account = crate::mm::memory_quota::Account::new().ok_or(ProcError::OutOfFrames)?;
    crate::mm::space::activate_kernel();
    kobj::with(|t| match t.get_mut(pid) {
        Ok(KObject::Process(p))
            if p.state == ProcState::Running && p.threads_live == 1 && p.linux.is_some() =>
        {
            revoke_all_device_mappings(p);
            let linux = p.linux.as_mut().expect("checked Linux process");
            let close_on_exec = linux
                .fds
                .take_close_on_exec()
                .map_err(|_| ProcError::NoTaskSlot)?;
            for handle in close_on_exec.handles().iter().copied() {
                release_unreferenced_pipe(linux, handle);
            }
            linux
                .pipes
                .retain(|pipe| linux.fds.handle_fd_count(pipe.handle) != 0);
            linux
                .sockets
                .retain(|socket| linux.fds.handle_fd_count(socket.handle) != 0);
            linux
                .ashmem
                .retain(|ashmem| linux.fds.handle_fd_count(ashmem.handle) != 0);
            linux
                .binder
                .retain(|binder| linux.fds.handle_fd_count(binder.handle) != 0);
            linux
                .ion_devices
                .retain(|device| linux.fds.handle_fd_count(*device) != 0);
            linux
                .eventfds
                .retain(|eventfd| linux.fds.handle_fd_count(eventfd.handle) != 0);
            linux
                .timerfds
                .retain(|timerfd| linux.fds.handle_fd_count(timerfd.handle) != 0);
            linux
                .signalfds
                .retain(|signalfd| linux.fds.handle_fd_count(signalfd.handle) != 0);
            linux.mappings.clear();
            linux.sealed_ranges.clear();
            linux.aio_contexts.clear();
            linux.brk = crate::arch::USER_WINDOW.0 + 0x1000_0000;
            linux.mmap_next = crate::arch::USER_WINDOW.0 + 0x4000_0000;
            linux.mmap32_next = crate::arch::LOW_USER_WINDOW.0 + 0x1000_0000;
            linux.stack_range = None;
            linux.signal_actions = [[0; 4]; 64];
            linux.exec_path.fill(0);
            linux.exec_path_len = 0;
            Ok(ExecAddressSpace {
                space: core::mem::replace(&mut p.space, space),
                frames: core::mem::take(&mut p.frames),
                shared_maps: core::mem::take(&mut p.shared_maps),
                memory_caps: core::mem::replace(&mut p.memory_caps, empty_caps),
                memory_account: core::mem::replace(&mut p.memory_account, memory_account),
                device_maps: core::mem::take(&mut p.device_maps),
            })
        }
        Ok(KObject::Process(_)) => Err(ProcError::Exited),
        _ => Err(ProcError::NoSuchProcess),
    })
}

/// Restores the saved address space after a failed exec transaction.
/// exec 事务失败后恢复保存的地址空间。
#[cfg(feature = "linux-abi")]
pub(crate) fn rollback_exec_address_space(
    pid: ObjId,
    saved: ExecAddressSpace,
) -> Result<(), ProcError> {
    crate::mm::space::activate_kernel();
    let replacement = kobj::with(|t| match t.get_mut(pid) {
        Ok(KObject::Process(p)) if p.state == ProcState::Running && p.linux.is_some() => {
            Ok(ExecAddressSpace {
                space: core::mem::replace(&mut p.space, saved.space),
                frames: core::mem::replace(&mut p.frames, saved.frames),
                shared_maps: core::mem::replace(&mut p.shared_maps, saved.shared_maps),
                memory_caps: core::mem::replace(&mut p.memory_caps, saved.memory_caps),
                memory_account: core::mem::replace(&mut p.memory_account, saved.memory_account),
                device_maps: core::mem::replace(&mut p.device_maps, saved.device_maps),
            })
        }
        Ok(KObject::Process(_)) => Err(ProcError::Exited),
        _ => Err(ProcError::NoSuchProcess),
    })?;
    drop(replacement.device_maps);
    drop(replacement.shared_maps);
    drop(replacement.frames);
    drop(replacement.memory_caps);
    drop(replacement.memory_account);
    drop(replacement.space);
    kobj::with(|t| match t.get_mut(pid) {
        Ok(KObject::Process(p)) => {
            p.space.activate();
            Ok(())
        }
        _ => Err(ProcError::NoSuchProcess),
    })
}

fn create_process(
    name: &'static str,
    syscalls: SyscallSet,
    initialize: impl FnOnce(&mut Process),
) -> Result<ObjId, ProcError> {
    let memory_budget = crate::mm::heap::limit();
    let process_slots = sched::slots();
    let Some(capability_plan) =
        plan_memory_capability_capacity(memory_budget, process_slots)
    else {
        kprintln!(
            "[JSR-PROC] reject=memory_capability_capacity budget={} process_slots={}",
            memory_budget,
            process_slots
        );
        return Err(ProcError::MemoryQuota);
    };
    let memory_caps =
        DynamicMemoryCapabilityTable::new(capability_plan.per_process)
            .ok_or(ProcError::OutOfFrames)?;
    let space = VmSpace::new().map_err(ProcError::Map)?;
    let memory_account = crate::mm::memory_quota::Account::new().ok_or(ProcError::OutOfFrames)?;
    let vm_guest_account = crate::mm::memory_quota::Account::new().ok_or(ProcError::OutOfFrames)?;
    let subscription_account =
        crate::mm::memory_quota::Account::new().ok_or(ProcError::OutOfFrames)?;
    let exit_state = kobj::with(|t| {
        crate::exit_state::create_in_with_security(
            t,
            kernel_core::security::SecuritySeed::active(
                crate::security::boot_id(),
                IdentityClass::KernelObject,
            ),
        )
    })
    .ok_or(ProcError::NoTaskSlot)?;
    let mut process = Process {
        name,
        space,
        handles: HandleTable::new(),
        frames: Vec::new(),
        shared_maps: Vec::new(),
        memory_caps,
        memory_account,
        memory_owned_limit: MAX_PROCESS_FRAMES as u64,
        memory_pin_limit: MAX_PROCESS_FRAMES as u64,
        vm_guest_account,
        subscription_account,
        #[cfg(feature = "linux-abi")]
        linux: None,
        quarantined: Vec::new(),
        device_maps: Vec::new(),
        threads: Vec::new(),
        syscalls,
        ring_quota: ResourceQuota::default(),
        usi_requests: UsiRequestLedger::new(),
        exit_state,
        children: Vec::new(),
        threads_live: 0,
        threads_total: 0,
        state: ProcState::Running,
        cpu_group: None,
        cpu_group_owned: false,
        workload: None,
        workload_member: None,
        workload_domain: None,
        kill_on_release: false,
        spawned_by: None,
        spawned_live: 0,
        app: 0,
    };
    initialize(&mut process);
    let p = Box::new(process);
    let id = match kobj::insert_classified(KObject::Process(p), 1, 0, IdentityClass::Process, None)
    {
        Ok(id) => id,
        Err(_) => {
            let _ = kobj::release_internal(exit_state); // 回滚：退出状态随之死亡
            return Err(ProcError::NoTaskSlot);
        }
    };
    kprintln!(
        "[JSR-PROC] event=system.process.created id={:#x} name={} memory_cap_capacity={} memory_cap_metadata_budget={} memory_budget={} process_slots={} dynamic=true",
        id.raw(),
        name,
        capability_plan.per_process,
        capability_plan.metadata_budget,
        memory_budget,
        process_slots
    );
    Ok(id)
}

#[cfg(feature = "linux-abi")]
fn allocate_linux_pid() -> Option<u32> {
    loop {
        let current = LINUX_PID_NEXT.load(Ordering::Acquire);
        if current == 0 {
            return None;
        }
        let next = current.checked_add(1).unwrap_or(0);
        if LINUX_PID_NEXT
            .compare_exchange(current, next, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
        {
            return Some(current);
        }
    }
}

/// 在对象表锁内对进程执行 `f`。
fn with_proc<R>(
    id: ObjId,
    f: impl FnOnce(&mut Process) -> Result<R, ProcError>,
) -> Result<R, ProcError> {
    kobj::with(|t| match t.get_mut(id) {
        Ok(KObject::Process(p)) => f(p),
        _ => Err(ProcError::NoSuchProcess),
    })
}

/// Create a private mapping of a zeroed Memory page (ELF/stack loader path).
pub fn map_new(id: ObjId, va: u64, flags: MapFlags) -> Result<PhysFrame, ProcError> {
    const PAGE_BYTES: u64 = kernel_core::frame::FRAME_SIZE as u64;
    let workload = kobj::with(|t| Ok(receiver(t, id)?.workload))?;
    if let Some(workload) = workload {
        crate::workload::reserve_memory(workload, PAGE_BYTES)
            .map_err(|_| ProcError::MemoryQuota)?;
    }
    let charge = match kobj::with(|t| {
        let p = receiver(t, id)?;
        p.memory_account
            .reserve(1, 0, p.memory_owned_limit, p.memory_pin_limit)
            .ok_or(ProcError::MemoryQuota)
    }) {
        Ok(charge) => charge,
        Err(error) => {
            if let Some(workload) = workload {
                crate::workload::release_memory(workload, PAGE_BYTES);
            }
            return Err(error);
        }
    };
    let page = match crate::mm::memory_object::Page::zeroed(charge) {
        Some(page) => page,
        None => {
            if let Some(workload) = workload {
                crate::workload::release_memory(workload, PAGE_BYTES);
            }
            return Err(ProcError::OutOfFrames);
        }
    };
    let f = page.frame();
    let result = with_proc(id, |p| {
        if p.state != ProcState::Running {
            return Err(ProcError::Exited);
        }
        if p.frames.len() + p.shared_maps.len() >= MAX_PROCESS_FRAMES {
            return Err(ProcError::MemoryQuota);
        }
        if !p.memory_caps.can_grant(va, 1, MemoryKind::Image) {
            return Err(ProcError::MemoryQuota);
        }
        p.frames
            .try_reserve(1)
            .map_err(|_| ProcError::OutOfFrames)?;
        #[cfg(feature = "linux-abi")]
        if let Some(linux) = p.linux.as_mut() {
            linux
                .mappings
                .try_reserve(1)
                .map_err(|_| ProcError::OutOfFrames)?;
        }
        p.space
            .map(VirtPage::containing(va), f, flags)
            .map_err(ProcError::Map)?;
        let rights = MemoryRights::READ
            .union(if flags.contains(MapFlags::WRITE) {
                MemoryRights::WRITE
            } else {
                MemoryRights::NONE
            })
            .union(if flags.contains(MapFlags::EXECUTE) {
                MemoryRights::EXECUTE
            } else {
                MemoryRights::NONE
            });
        if p.memory_caps
            .grant(
                va,
                1,
                rights,
                MemoryKind::Image,
                BackingIdentity::new(0, 1).expect("fixed valid generation"),
            )
            .is_err()
        {
            let _ = p.space.unmap_raw(VirtPage::containing(va));
            return Err(ProcError::MemoryQuota);
        }
        #[cfg(feature = "linux-abi")]
        if let Some(linux) = p.linux.as_mut() {
            linux.mappings.push(LinuxMapping {
                va,
                flags,
                file: None,
                file_offset: 0,
                shared_file: false,
            });
        }
        p.frames.push(Arc::clone(&page));
        Ok(f)
    });
    if result.is_err() {
        if let Some(workload) = workload {
            crate::workload::release_memory(workload, PAGE_BYTES);
        }
    }
    result
}

/// 取消进程中一页的映射并放弃该页的数据帧（仍被在飞请求固定时，帧延后到最后一次解除固定才归还）。
/// Unmaps one page of a process; its frame is returned now or, if pinned, after the last unpin.
pub fn unmap_page(id: ObjId, va: u64) -> Result<(), ProcError> {
    let frame = with_proc(id, |p| {
        if is_shared_page(p, va) {
            return Err(ProcError::Map(MapError::InvalidAddress));
        }
        if !p.space.begin_shootdown() {
            return Err(ProcError::Map(MapError::Busy));
        }
        match p.space.unmap_raw(VirtPage::containing(va)) {
            Ok(f) => {
                let _ = p.memory_caps.revoke_range(va, 1);
                #[cfg(feature = "linux-abi")]
                if let Some(linux) = p.linux.as_mut() {
                    linux.mappings.retain(|mapping| mapping.va != va);
                }
                Ok(f)
            }
            Err(e) => {
                p.space.end_shootdown();
                Err(ProcError::Map(e))
            }
        }
    })?;
    let active = with_proc(id, |p| Ok(p.space.active_cpus()))?;
    if crate::smp::tlb_shootdown_on(active, va, 1).is_err() {
        with_proc(id, |p| {
            for page in &p.frames {
                if page.frame() == frame {
                    page.quarantine();
                }
            }
            p.frames.retain(|x| x.frame() != frame);
            p.quarantine_one(frame);
            Ok(())
        })
        .ok();
        return Err(ProcError::Map(MapError::Busy));
    }
    let workload = with_proc(id, |p| {
        crate::mm::pin::mapping_released(frame);
        p.frames.retain(|x| x.frame() != frame);
        p.space.end_shootdown();
        Ok(p.workload)
    })?;
    if let Some(workload) = workload {
        crate::workload::release_memory(workload, kernel_core::frame::FRAME_SIZE as u64);
    }
    Ok(())
}

/// Unmaps one Linux shared-backing page without releasing the backing page.
/// Returns `false` when the address is not a shared mapping.
#[cfg(feature = "linux-abi")]
pub(crate) fn unmap_shared_page(id: ObjId, va: u64) -> Result<bool, ProcError> {
    let active = kobj::with(|t| match t.get_mut(id) {
        Ok(KObject::Process(p)) => {
            if !p.shared_maps.iter().any(|mapping| mapping.va == va) {
                return Ok(None);
            }
            if !p.space.begin_shootdown() {
                return Err(ProcError::Map(MapError::Busy));
            }
            if let Err(error) = p.space.unmap_raw(VirtPage::containing(va)) {
                p.space.end_shootdown();
                return Err(ProcError::Map(error));
            }
            let _ = p.memory_caps.revoke_range(va, 1);
            p.shared_maps.retain(|mapping| mapping.va != va);
            let active = p.space.active_cpus();
            Ok(Some(active))
        }
        _ => Err(ProcError::NoSuchProcess),
    })?;
    let Some(active) = active else {
        return Ok(false);
    };
    let shootdown = crate::smp::tlb_shootdown_on(active, va, 1);
    with_proc(id, |p| {
        p.space.end_shootdown();
        Ok(())
    })?;
    if shootdown.is_err() {
        return Err(ProcError::Map(MapError::Busy));
    }
    Ok(true)
}

/// 每个进程最多拥有的数据帧数（ELF 段、栈与匿名映射合计）。
/// Upper bound on data frames owned by one process (image, stacks and anonymous mappings together).
pub const MAX_PROCESS_FRAMES: usize = {
    let configured = crate::config::ACTIVE.memory.max_process_frames;
    if configured == 0 {
        usize::MAX
    } else {
        configured
    }
};
/// Per-process VM guest RAM limit, independent from the ordinary process account.
pub const MAX_VM_GUEST_FRAMES: u64 = crate::config::ACTIVE.memory.max_vm_guest_frames as u64;
/// 单次 `system.memory.map` / `unmap` 最多涉及的页数。
pub const MAX_MAP_PAGES: u64 = crate::config::ACTIVE.memory.max_map_pages;
/// 匿名映射 / 取消映射的失败原因。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MemError {
    /// Memory handle missing/wrong type.
    InvalidHandle,
    /// Handle does not grant the requested shared mapping permissions.
    RightsDenied,
    /// 同一地址空间的另一次跨核页表修改尚未完成。
    Busy,
    /// 起点未按页对齐、页数为 0 或超限、区间越出私有窗口。
    InvalidRange,
    /// 区间内已有映射（映射时）。
    AlreadyMapped,
    /// 区间内有未映射的页（取消映射时）。
    NotMapped,
    /// 超出进程的帧配额。
    Quota,
    /// 内存压力下按请求者的服务质量档位拒绝（低档先被拒，保证高档与内核仍有内存可用）。
    Pressure,
    /// 物理帧或页表帧不足。
    OutOfMemory,
    /// 进程不存在或已退出。
    NoSuchProcess,
}

/// 检查 `[va, va + pages × 页)` 是否是私有窗口内、按页对齐、页数在限额内的区间。
fn checked_range(va: u64, pages: u64) -> Result<(), MemError> {
    if va % FRAME_SIZE != 0 || pages == 0 || pages > MAX_MAP_PAGES {
        return Err(MemError::InvalidRange);
    }
    let end = pages
        .checked_mul(FRAME_SIZE)
        .and_then(|len| va.checked_add(len))
        .ok_or(MemError::InvalidRange)?;
    if !in_private_window(va) || end > arch::USER_WINDOW.1 {
        return Err(MemError::InvalidRange);
    }
    Ok(())
}

/// 在进程 `pid` 的 `[va, va + pages 页)` 映射清零的匿名页（`writable` 决定可写；匿名页永不可执行）。
///
/// **全有或全无**：先在锁外分配并清零全部数据帧，再在锁内复核配额、确认区间内无映射、逐页建立映射；
/// 任何一步失败都撤销已建立的映射并归还全部数据帧，进程地址空间与帧记账保持调用前的样子
/// （建页表时新分配的中间页表帧归地址空间所有，随地址空间销毁回收）。
/// Maps zeroed anonymous pages, all-or-nothing.
pub fn map_anon(pid: ObjId, va: u64, pages: u64, writable: bool) -> Result<(), MemError> {
    checked_range(va, pages)?;
    let n = pages as usize;
    let requested_workload = kobj::with(|t| {
        let p = receiver(t, pid).map_err(|_| MemError::NoSuchProcess)?;
        let bytes = pages
            .checked_mul(FRAME_SIZE)
            .ok_or(MemError::InvalidRange)?;
        Ok(p.workload.map(|workload| (workload, bytes)))
    })?;
    let workload_charge = if let Some((workload, bytes)) = requested_workload {
        crate::workload::reserve_memory(workload, bytes).map_err(|_| MemError::Quota)?;
        Some((workload, bytes))
    } else {
        None
    };
    let charge = match kobj::with(|t| {
        let p = receiver(t, pid).map_err(|_| MemError::NoSuchProcess)?;
        if p.frames.len() + p.shared_maps.len() + n > MAX_PROCESS_FRAMES {
            return Err(MemError::Quota);
        }
        p.memory_account
            .reserve(pages, 0, p.memory_owned_limit, p.memory_pin_limit)
            .ok_or(MemError::Quota)
    }) {
        Ok(charge) => charge,
        Err(error) => {
            if let Some((workload, bytes)) = workload_charge {
                crate::workload::release_memory(workload, bytes);
            }
            return Err(error);
        }
    };
    if crate::mm::pressure::admit(sched::current_effective_qos(), n).is_err() {
        if let Some((workload, bytes)) = workload_charge {
            crate::workload::release_memory(workload, bytes);
        }
        return Err(MemError::Pressure);
    }
    let backing = match crate::mm::memory_object::MemoryObject::zeroed(
        pages,
        MAX_PROCESS_FRAMES as u64,
        charge,
    ) {
        Some(backing) => backing,
        None => {
            if let Some((workload, bytes)) = workload_charge {
                crate::workload::release_memory(workload, bytes);
            }
            return Err(MemError::OutOfMemory);
        }
    };
    let range = kernel_core::memory_object::MapRange {
        offset_pages: 0,
        pages,
        va,
        end: va + pages * FRAME_SIZE,
    };
    let fresh = match backing.retain_range(range) {
        Some(fresh) => fresh,
        None => {
            if let Some((workload, bytes)) = workload_charge {
                crate::workload::release_memory(workload, bytes);
            }
            return Err(MemError::OutOfMemory);
        }
    };
    let flags = if writable {
        MapFlags::USER.union(MapFlags::WRITE)
    } else {
        MapFlags::USER
    };
    let mut published = 0u64;
    let mut rollback_uncertain = false;
    let mut active = kernel_core::smp::CpuSet::EMPTY;
    let result = kobj::with(|t| {
        let p = receiver(t, pid).map_err(|_| MemError::NoSuchProcess)?;
        if p.frames.len() + p.shared_maps.len() + n > MAX_PROCESS_FRAMES {
            return Err(MemError::Quota);
        }
        p.frames.try_reserve(n).map_err(|_| MemError::OutOfMemory)?;
        for i in 0..pages {
            if p.space
                .translate(VirtPage::containing(va + i * FRAME_SIZE))
                .is_some()
            {
                return Err(MemError::AlreadyMapped);
            }
        }
        if !p.space.begin_shootdown() {
            return Err(MemError::Busy);
        }
        if !p.memory_caps.can_grant(va, pages, MemoryKind::Anonymous) {
            #[cfg(feature = "android-art-verify")]
            crate::kprintln!(
                "[JSR-ANDROID-CAP] grant-conflict start={} end={} overlap={:?}",
                va,
                va + pages * FRAME_SIZE,
                p.memory_caps.overlapping(va, pages)
            );
            return Err(MemError::Quota);
        }
        active = p.space.active_cpus();
        for page in &fresh {
            if p.space
                .map_raw(
                    VirtPage::containing(va + published * FRAME_SIZE),
                    page.frame(),
                    flags,
                )
                .is_err()
            {
                for i in 0..published {
                    if p.space
                        .unmap_raw(VirtPage::containing(va + i * FRAME_SIZE))
                        .is_err()
                    {
                        rollback_uncertain = true;
                    }
                }
                if published == 0 {
                    p.space.end_shootdown();
                }
                return Err(MemError::OutOfMemory);
            }
            published += 1;
        }
        p.memory_caps
            .grant(
                va,
                pages,
                MemoryRights::READ.union(if writable {
                    MemoryRights::WRITE
                } else {
                    MemoryRights::NONE
                }),
                MemoryKind::Anonymous,
                BackingIdentity::new(0, 1).expect("fixed valid generation"),
            )
            .map_err(|_| MemError::Quota)?;
        p.frames.extend(fresh.iter().cloned());
        p.space.end_shootdown();
        Ok(())
    });
    if result.is_err() {
        if published > 0 {
            if crate::smp::tlb_shootdown_on(active, va, published).is_err() || rollback_uncertain {
                for page in fresh.iter().take(published as usize) {
                    page.quarantine();
                }
                // Quarantined pages remain physically charged, so retain the Workload charge too.
                return Err(MemError::Busy);
            }
            let _ = with_proc(pid, |p| {
                p.space.end_shootdown();
                Ok(())
            });
        }
        if let Some((workload, bytes)) = workload_charge {
            crate::workload::release_memory(workload, bytes);
        }
    }
    result
}

/// SHM-1 creation candidate. No user ABI is exposed until full quota/lifecycle integration.
pub fn create_memory(pid: ObjId, pages: u64) -> Result<HandleId, ProcError> {
    create_accounted_memory(pid, pages, false)
}

/// Create Memory backing charged to the VM guest budget rather than the ordinary process budget.
pub fn create_guest_memory(pid: ObjId, pages: u64) -> Result<HandleId, ProcError> {
    create_accounted_memory(pid, pages, true)
}

fn create_accounted_memory(pid: ObjId, pages: u64, guest: bool) -> Result<HandleId, ProcError> {
    if pages == 0 {
        return Err(ProcError::MemoryQuota);
    }
    let limit = if guest {
        MAX_VM_GUEST_FRAMES
    } else {
        MAX_PROCESS_FRAMES as u64
    };
    if pages > limit {
        return Err(ProcError::MemoryQuota);
    }
    let requested_workload = if guest {
        None
    } else {
        kobj::with(|t| {
            let p = receiver(t, pid)?;
            let bytes = pages
                .checked_mul(kernel_core::frame::FRAME_SIZE as u64)
                .ok_or(ProcError::MemoryQuota)?;
            Ok(p.workload.map(|workload| (workload, bytes)))
        })?
    };
    let workload_owner = if let Some((workload, bytes)) = requested_workload {
        Some(
            crate::workload::MemoryCharge::reserve(workload, bytes)
                .map_err(|_| ProcError::MemoryQuota)?,
        )
    } else {
        None
    };
    let charge = kobj::with(|t| {
        let p = receiver(t, pid)?;
        if guest {
            p.vm_guest_account
                .reserve(pages, 0, limit, limit)
                .ok_or(ProcError::MemoryQuota)
        } else {
            p.memory_account
                .reserve(pages, 0, p.memory_owned_limit, p.memory_pin_limit)
                .ok_or(ProcError::MemoryQuota)
        }
    })?;
    if crate::mm::pressure::admit(sched::current_effective_qos(), pages as usize).is_err() {
        return Err(ProcError::OutOfFrames);
    }
    let backing = crate::mm::memory_object::MemoryObject::zeroed_with_workload(
        pages,
        limit,
        charge,
        workload_owner,
    )
    .ok_or(ProcError::OutOfFrames)?;
    grant_new(
        pid,
        KObject::Memory(backing),
        ObjectType::Memory,
        Rights::READ
            .union(Rights::WRITE)
            .union(Rights::MAP)
            .union(Rights::DUPLICATE)
            .union(Rights::TRANSFER),
    )
}
fn is_shared_page(p: &Process, va: u64) -> bool {
    p.shared_maps.iter().any(|m| m.va == va - va % FRAME_SIZE)
}

/// Normalize a valid object generation for the memory-capability layer.
///
/// 对象首代 generation 0 合法，而内存能力层把 0 保留为无效哨兵，因此映射为 1。
fn memory_backing_identity(id: ObjId) -> BackingIdentity {
    BackingIdentity::new(id.raw(), id.generation().max(1))
        .expect("normalized object generation is always nonzero")
}

/// Maps retained Memory pages; failed partial publication waits for TLB acknowledgement before dropping refs.
pub fn map_memory(
    pid: ObjId,
    h: HandleId,
    va: u64,
    offset: u64,
    pages: u64,
    writable: bool,
) -> Result<(), MemError> {
    let mut retained = Vec::new();
    let mut published = 0u64;
    let mut workload_charge = None;
    let mut rollback_uncertain = false;
    let mut active = kernel_core::smp::CpuSet::EMPTY;
    let result = kobj::with(|t| {
        let need = Rights::READ.union(Rights::MAP).union(if writable {
            Rights::WRITE
        } else {
            Rights::NONE
        });
        let id = resolve_in(t, pid, h, ObjectType::Memory, need).map_err(|e| match e {
            ProcError::Handle(HandleError::RightsDenied) => MemError::RightsDenied,
            ProcError::NoSuchProcess | ProcError::Exited => MemError::NoSuchProcess,
            _ => MemError::InvalidHandle,
        })?;
        let (_, have) = handle_in(t, pid, h).map_err(|_| MemError::InvalidRange)?;
        let page_count = match t.get(id) {
            Ok(KObject::Memory(memory)) => memory.page_count(),
            _ => return Err(MemError::InvalidRange),
        };
        let range = kernel_core::memory_object::MapRange::checked(
            page_count,
            offset,
            pages,
            va,
            arch::USER_WINDOW,
            MAX_MAP_PAGES,
            have,
            writable,
        )
        .map_err(|_| MemError::InvalidRange)?;
        let Ok(KObject::Memory(memory)) = t.get(id) else {
            return Err(MemError::InvalidRange);
        };
        retained = memory.retain_range(range).ok_or(MemError::OutOfMemory)?;
        #[cfg(all(target_arch = "x86_64", feature = "iommu-dma-verify"))]
        if writable && pages <= 4 {
            crate::kprintln!(
                "[JSR-QUEUE] memory_map va=0x{:x} pages={} frame=0x{:x}",
                va,
                pages,
                retained.first().map(|page| page.frame().start()).unwrap_or(0)
            );
        }
        let Ok(KObject::Process(p)) = t.get_mut(pid) else {
            return Err(MemError::NoSuchProcess);
        };
        if !p.memory_caps.can_grant(va, pages, MemoryKind::Shared) {
            return Err(MemError::Quota);
        }
        if p.frames
            .len()
            .checked_add(p.shared_maps.len())
            .and_then(|n| n.checked_add(retained.len()))
            .filter(|&n| n <= MAX_PROCESS_FRAMES)
            .is_none()
        {
            return Err(MemError::Quota);
        }
        let workload_bytes = pages
            .checked_mul(FRAME_SIZE)
            .ok_or(MemError::InvalidRange)?;
        if let Some(workload) = p.workload {
            crate::workload::reserve_memory(workload, workload_bytes)
                .map_err(|_| MemError::Quota)?;
            workload_charge = Some((workload, workload_bytes));
        }
        p.shared_maps
            .try_reserve(retained.len())
            .map_err(|_| MemError::OutOfMemory)?;
        for i in 0..pages {
            if p.space
                .translate(VirtPage::containing(va + i * FRAME_SIZE))
                .is_some()
            {
                return Err(MemError::AlreadyMapped);
            }
        }
        if !p.space.begin_shootdown() {
            return Err(MemError::Busy);
        }
        active = p.space.active_cpus();
        let flags = if writable {
            MapFlags::USER.union(MapFlags::WRITE)
        } else {
            MapFlags::USER
        };
        for page in &retained {
            match p.space.map_raw(
                VirtPage::containing(va + published * FRAME_SIZE),
                page.frame(),
                flags,
            ) {
                Ok(()) => published += 1,
                Err(_) => {
                    for i in 0..published {
                        if p.space
                            .unmap_raw(VirtPage::containing(va + i * FRAME_SIZE))
                            .is_err()
                        {
                            rollback_uncertain = true;
                        }
                    }
                    if published == 0 {
                        p.space.end_shootdown();
                    }
                    return Err(MemError::OutOfMemory);
                }
            }
        }
        for (i, page) in retained.iter().enumerate() {
            p.shared_maps.push(SharedMapping {
                va: va + i as u64 * FRAME_SIZE,
                page: Arc::clone(page),
                source: memory_backing_identity(id),
                flags,
            });
        }
        p.memory_caps
            .grant(
                va,
                pages,
                MemoryRights::READ
                    .union(MemoryRights::MAP)
                    .union(if writable {
                        MemoryRights::WRITE
                    } else {
                        MemoryRights::NONE
                    }),
                MemoryKind::Shared,
                memory_backing_identity(id),
            )
            .map_err(|_| MemError::Quota)?;
        p.space.end_shootdown();
        Ok(())
    });
    if result.is_err() {
        if let Some((workload, bytes)) = workload_charge {
            crate::workload::release_memory(workload, bytes);
        }
    }
    if result.is_err() && published > 0 {
        #[cfg(feature = "shm1-verify")]
        crate::shm_demo::record_mapping_rollback(published);
        if crate::smp::tlb_shootdown_on(active, va, published).is_err() || rollback_uncertain {
            for page in retained.iter().take(published as usize) {
                page.quarantine();
            }
            return Err(MemError::Busy);
        }
        let _ = with_proc(pid, |p| {
            p.space.end_shootdown();
            Ok(())
        });
    }
    result
}

/// Revokes only complete SHM page ranges. References survive until all active CPUs acknowledge.
pub fn unmap_memory(pid: ObjId, va: u64, pages: u64) -> Result<(), MemError> {
    checked_range(va, pages)?;
    let active = kobj::with(|t| {
        let Ok(KObject::Process(p)) = t.get_mut(pid) else {
            return Err(MemError::NoSuchProcess);
        };
        if p.state != ProcState::Running {
            return Err(MemError::NoSuchProcess);
        }
        for i in 0..pages {
            let addr = va + i * FRAME_SIZE;
            if !is_shared_page(p, addr) || p.space.translate(VirtPage::containing(addr)).is_none() {
                return Err(MemError::NotMapped);
            }
        }
        if !p.space.begin_shootdown() {
            return Err(MemError::Busy);
        }
        for i in 0..pages {
            // Prevalidated under the same object transaction; failure leaves refs and busy state intact.
            if p.space
                .unmap_raw(VirtPage::containing(va + i * FRAME_SIZE))
                .is_err()
            {
                for m in &p.shared_maps {
                    if m.va >= va && m.va < va + pages * FRAME_SIZE {
                        m.page.quarantine();
                    }
                }
                return Err(MemError::Busy);
            }
        }
        let _ = p.memory_caps.revoke_range(va, pages);
        Ok(p.space.active_cpus())
    })?;
    #[cfg(feature = "shm1-verify")]
    crate::shm_demo::record_revoke_targets(active);
    let confirmed = crate::smp::tlb_shootdown_on(active, va, pages).is_ok();
    let workload = kobj::with(|t| {
        let Ok(KObject::Process(p)) = t.get_mut(pid) else {
            return Err(MemError::NoSuchProcess);
        };
        let end = va + pages * FRAME_SIZE;
        if !confirmed {
            for m in &p.shared_maps {
                if m.va >= va && m.va < end {
                    m.page.quarantine();
                }
            }
            return Err(MemError::Busy);
        }
        p.shared_maps.retain(|m| m.va < va || m.va >= end);
        p.space.end_shootdown();
        Ok(p.workload.map(|workload| {
            (
                workload,
                pages
                    .checked_mul(FRAME_SIZE)
                    .expect("validated page range cannot overflow"),
            )
        }))
    })?;
    if let Some((workload, bytes)) = workload {
        crate::workload::release_memory(workload, bytes);
    }
    Ok(())
}

/// 在进程 `pid` 的 `[va, va + size)` 建立设备 BAR 映射（`phys` 为 BAR 物理基址）。
///
/// 页属性固定为 `USER | WRITE | NO_CACHE`，且**不含 EXECUTE**；BAR 不是 RAM，映射与撤销都不经过
/// 页帧分配器（只有建立中间页表时才可能分配页表帧，随地址空间销毁回收）。`size` 必须页对齐、
/// 非零且落在用户地址空间及 MMIO capability 预算内。同一进程内同一物理 BAR 范围只允许一个映射（重复请求
/// 返回 [`MemError::AlreadyMapped`]）；目标虚拟区间已有任何映射也返回同一错误。失败时撤销本次已建立
/// 的映射，不留残留。
/// Maps a device BAR window into `pid` with uncached, non-executable user pages (writable for drivers).
pub fn map_device_bar(
    pid: ObjId,
    handle: HandleId,
    bar: u8,
    va: u64,
    phys: u64,
    size: u64,
) -> Result<(), MemError> {
    // MMIO is device-address space, not owned RAM: it is governed by device
    // capabilities, IOMMU/DMA rules and memory_caps, never by memory_bytes.
    // 设备 MMIO 属于设备地址空间而非自有 RAM；不得伪装成普通内存额度。
    if va % FRAME_SIZE != 0 || size == 0 || size % FRAME_SIZE != 0 || phys % FRAME_SIZE != 0 {
        return Err(MemError::InvalidRange);
    }
    let pages = size / FRAME_SIZE;
    if pages == 0 || phys.checked_add(size).is_none() {
        return Err(MemError::InvalidRange);
    }
    let end = pages
        .checked_mul(FRAME_SIZE)
        .and_then(|len| va.checked_add(len))
        .ok_or(MemError::InvalidRange)?;
    if !in_private_window(va) || end > arch::USER_WINDOW.1 {
        return Err(MemError::InvalidRange);
    }
    let flags = MapFlags::USER
        .union(MapFlags::WRITE)
        .union(MapFlags::NO_CACHE);
    kobj::with(|t| {
        let Ok(KObject::Process(p)) = t.get_mut(pid) else {
            return Err(MemError::NoSuchProcess);
        };
        if p.state != ProcState::Running {
            return Err(MemError::NoSuchProcess);
        }
        if !p.memory_caps.can_grant(va, pages, MemoryKind::DeviceMmio) {
            return Err(MemError::Quota);
        }
        for i in 0..pages {
            if p.space
                .translate(VirtPage::containing(va + i * FRAME_SIZE))
                .is_some()
            {
                return Err(MemError::AlreadyMapped);
            }
        }
        if p.device_maps
            .iter()
            .any(|m| m.phys == phys && m.pages == pages)
        {
            return Err(MemError::AlreadyMapped);
        }
        if p.device_maps.try_reserve(1).is_err() {
            return Err(MemError::OutOfMemory);
        }
        if !p.space.begin_shootdown() {
            return Err(MemError::Busy);
        }
        let mut mapped = 0u64;
        while mapped < pages {
            let page = VirtPage::containing(va + mapped * FRAME_SIZE);
            let mapped_ok = match PhysFrame::from_start(phys + mapped * FRAME_SIZE) {
                Some(frame) => p.space.map_raw(page, frame, flags),
                None => Err(MapError::InvalidAddress),
            };
            if let Err(e) = mapped_ok {
                for undo in 0..mapped {
                    let _ = p
                        .space
                        .unmap_raw(VirtPage::containing(va + undo * FRAME_SIZE));
                }
                p.space.end_shootdown();
                return Err(match e {
                    MapError::AlreadyMapped => MemError::AlreadyMapped,
                    MapError::OutOfFrames => MemError::OutOfMemory,
                    _ => MemError::InvalidRange,
                });
            }
            mapped += 1;
        }
        // 复核实际权限：设备窗口必须不可缓存、不可执行；否则撤销全部本次映射并拒绝。
        let ok = (0..pages).all(|i| {
            p.space
                .translate(VirtPage::containing(va + i * FRAME_SIZE))
                .map_or(false, |(_, f)| {
                    f.contains(MapFlags::USER)
                        && f.contains(MapFlags::WRITE)
                        && f.contains(MapFlags::NO_CACHE)
                        && !f.contains(MapFlags::EXECUTE)
                })
        });
        if !ok {
            for undo in 0..pages {
                let _ = p
                    .space
                    .unmap_raw(VirtPage::containing(va + undo * FRAME_SIZE));
            }
            p.space.end_shootdown();
            return Err(MemError::InvalidRange);
        }
        p.device_maps.push(DeviceMapping {
            handle,
            bar,
            va,
            pages,
            phys,
        });
        p.memory_caps
            .grant(
                va,
                pages,
                MemoryRights::READ
                    .union(MemoryRights::WRITE)
                    .union(MemoryRights::MMIO),
                MemoryKind::DeviceMmio,
                BackingIdentity::new(phys, 1).expect("fixed valid generation"),
            )
            .map_err(|_| MemError::Quota)?;
        p.space.end_shootdown();
        Ok(())
    })
}

/// 撤销一条设备映射（只改页表，不归还任何数据帧）。
/// Revokes one device mapping (page tables only; no data frames are returned).
fn unmap_device_mapping(p: &mut Process, mapping: &DeviceMapping) {
    for i in 0..mapping.pages {
        let _ = p
            .space
            .unmap(VirtPage::containing(mapping.va + i * FRAME_SIZE));
    }
    let _ = p.memory_caps.revoke_range(mapping.va, mapping.pages);
}

/// `va` 所在页是否属于设备映射（匿名映射 / 取消映射 / 改权限不得触碰设备窗口）。
/// Whether the page containing `va` belongs to a device mapping.
fn is_device_page(p: &Process, va: u64) -> bool {
    let page = va - va % FRAME_SIZE;
    p.device_maps
        .iter()
        .any(|m| page >= m.va && page < m.va + m.pages * FRAME_SIZE)
}

/// 撤销进程 `pid` 中由 `handle` 创建的全部设备映射（关闭句柄时调用）。
/// Revokes every device mapping created through `handle`.
fn revoke_device_mappings_for_handle(p: &mut Process, handle: HandleId) {
    let mut i = 0;
    while i < p.device_maps.len() {
        if p.device_maps[i].handle == handle {
            let mapping = p.device_maps.swap_remove(i);
            unmap_device_mapping(p, &mapping);
        } else {
            i += 1;
        }
    }
}

/// 撤销进程的全部设备映射（进程退出 / 销毁时调用）。
/// Revokes all device mappings of a process.
fn revoke_all_device_mappings(p: &mut Process) {
    let maps = core::mem::take(&mut p.device_maps);
    for mapping in &maps {
        unmap_device_mapping(p, mapping);
    }
}

/// 取消进程 `pid` 中 `[va, va + pages 页)` 的映射并放弃这些页的数据帧。
///
/// **全有或全无**：区间内任一页未映射 ⇒ 什么也不做，返回 [`MemError::NotMapped`]。
/// 仍被在飞请求固定的帧延后到最后一次解除固定时归还（与 [`unmap_page`] 相同）。
/// Unmaps a range of pages, all-or-nothing.
pub fn unmap_range(pid: ObjId, va: u64, pages: u64) -> Result<(), MemError> {
    checked_range(va, pages)?;
    let mut gone: Vec<PhysFrame> = Vec::new();
    if gone.try_reserve_exact(pages as usize).is_err() {
        return Err(MemError::OutOfMemory);
    }
    let active = kobj::with(|t| {
        let Ok(KObject::Process(p)) = t.get_mut(pid) else {
            return Err(MemError::NoSuchProcess);
        };
        for i in 0..pages {
            if is_device_page(p, va + i * FRAME_SIZE) || is_shared_page(p, va + i * FRAME_SIZE) {
                return Err(MemError::InvalidRange);
            }
            if p.space
                .translate(VirtPage::containing(va + i * FRAME_SIZE))
                .is_none()
            {
                return Err(MemError::NotMapped);
            }
        }
        if !p.space.begin_shootdown() {
            return Err(MemError::Busy);
        }
        for i in 0..pages {
            match p.space.unmap_raw(VirtPage::containing(va + i * FRAME_SIZE)) {
                Ok(f) => gone.push(f),
                Err(e) => {
                    p.space.end_shootdown();
                    return Err(match e {
                        MapError::Busy => MemError::Busy,
                        MapError::OutOfFrames => MemError::OutOfMemory,
                        _ => MemError::InvalidRange,
                    });
                }
            }
        }
        let _ = p.memory_caps.revoke_range(va, pages);
        Ok(p.space.active_cpus())
    })?;
    // 页表修改已经完成，但帧仍记在进程名下；必须先等所有活跃处理器应答，才能归还。
    if crate::smp::tlb_shootdown_on(active, va, pages).is_err() {
        // 击落未确认：旧 TLB 仍可能引用这些帧。把它们从可归还集合移入永久隔离集合，
        // 让进程销毁路径也不会把帧放回分配器。
        kobj::with(|t| {
            if let Ok(KObject::Process(p)) = t.get_mut(pid) {
                gone.sort_unstable_by_key(|f| f.start());
                for page in &p.frames {
                    if gone
                        .binary_search_by_key(&page.frame().start(), |g| g.start())
                        .is_ok()
                    {
                        page.quarantine();
                    }
                }
                p.frames.retain(|f| {
                    gone.binary_search_by_key(&f.frame().start(), |g| g.start())
                        .is_err()
                });
                p.quarantine(gone);
            }
            Ok::<(), MemError>(())
        })
        .ok();
        return Err(MemError::Busy);
    }
    kobj::with(|t| {
        let Ok(KObject::Process(p)) = t.get_mut(pid) else {
            return Err(MemError::NoSuchProcess);
        };
        gone.sort_unstable_by_key(|f| f.start());
        for f in &gone {
            crate::mm::pin::mapping_released(*f);
        }
        p.frames.retain(|f| {
            gone.binary_search_by_key(&f.frame().start(), |g| g.start())
                .is_err()
        });
        p.space.end_shootdown();
        Ok(())
    })?;
    Ok(())
}

/// Fast Linux `munmap` for a private range. Unlike [`unmap_range`], unmapped
/// holes are allowed. Returns `false` before changing anything when the range
/// includes a shared or device mapping, so the caller can use backing-aware
/// removal for that rare mixed case.
#[cfg(feature = "linux-abi")]
pub(crate) fn linux_unmap_private_range(
    pid: ObjId,
    start: u64,
    end: u64,
) -> Result<bool, ProcError> {
    if start % FRAME_SIZE != 0 || end <= start {
        return Err(ProcError::Map(MapError::InvalidAddress));
    }
    let pages = (end - start) / FRAME_SIZE;
    let special = kobj::with(|t| match t.get(pid) {
        Ok(KObject::Process(p)) => Ok((0..pages).any(|i| {
            let va = start + i * FRAME_SIZE;
            is_shared_page(p, va) || is_device_page(p, va)
        })),
        _ => Err(ProcError::NoSuchProcess),
    })?;
    if special {
        return Ok(false);
    }

    let mut gone = Vec::new();
    gone.try_reserve_exact(pages as usize)
        .map_err(|_| ProcError::OutOfFrames)?;
    let active = kobj::with(|t| {
        let Ok(KObject::Process(p)) = t.get_mut(pid) else {
            return Err(ProcError::NoSuchProcess);
        };
        if !p.space.begin_shootdown() {
            return Err(ProcError::Map(MapError::Busy));
        }
        for i in 0..pages {
            let va = start + i * FRAME_SIZE;
            if p.space.translate(VirtPage::containing(va)).is_none() {
                continue;
            }
            match p.space.unmap_raw(VirtPage::containing(va)) {
                Ok(frame) => gone.push(frame),
                Err(error) => {
                    p.space.end_shootdown();
                    return Err(ProcError::Map(error));
                }
            }
        }
        let _ = p.memory_caps.revoke_range(start, pages);
        if let Some(linux) = p.linux.as_mut() {
            linux
                .mappings
                .retain(|mapping| mapping.va < start || mapping.va >= end);
        }
        Ok(p.space.active_cpus())
    })?;

    if crate::smp::tlb_shootdown_on(active, start, pages).is_err() {
        kobj::with(|t| {
            if let Ok(KObject::Process(p)) = t.get_mut(pid) {
                gone.sort_unstable_by_key(|frame| frame.start());
                for page in &p.frames {
                    if gone
                        .binary_search_by_key(&page.frame().start(), |frame| frame.start())
                        .is_ok()
                    {
                        page.quarantine();
                    }
                }
                p.frames.retain(|page| {
                    gone.binary_search_by_key(&page.frame().start(), |frame| frame.start())
                        .is_err()
                });
                p.quarantine(gone);
            }
            Ok::<(), ProcError>(())
        })
        .ok();
        return Err(ProcError::Map(MapError::Busy));
    }

    kobj::with(|t| {
        let Ok(KObject::Process(p)) = t.get_mut(pid) else {
            return Err(ProcError::NoSuchProcess);
        };
        gone.sort_unstable_by_key(|frame| frame.start());
        for frame in &gone {
            crate::mm::pin::mapping_released(*frame);
        }
        p.frames.retain(|page| {
            gone.binary_search_by_key(&page.frame().start(), |frame| frame.start())
                .is_err()
        });
        p.space.end_shootdown();
        Ok(())
    })?;
    Ok(true)
}

/// 修改进程 `pid` 中 `[va, va + pages 页)` 的访问权限：`writable` 与 `executable` 不能同时为真（W^X）。
///
/// **全有或全无**：区间内任一页未映射 ⇒ 什么也不改，返回 [`MemError::NotMapped`]。
/// 帧与记账不变；只改权限位。可执行权限只能经本接口获得（`map_anon` 映射的页永不可执行）。
/// Changes access rights of a mapped range (W^X enforced), all-or-nothing.
pub fn protect_range(
    pid: ObjId,
    va: u64,
    pages: u64,
    writable: bool,
    executable: bool,
) -> Result<(), MemError> {
    if writable && executable {
        return Err(MemError::InvalidRange);
    }
    protect_range_access(pid, va, pages, true, writable, executable)
}

/// Changes access rights with an explicit user-accessible bit. `accessible == false`
/// implements Linux `PROT_NONE` while retaining the mapped backing pages.
pub fn protect_range_access(
    pid: ObjId,
    va: u64,
    pages: u64,
    accessible: bool,
    writable: bool,
    executable: bool,
) -> Result<(), MemError> {
    checked_range(va, pages)?;
    let mut flags = MapFlags::READ_ONLY;
    if accessible {
        flags = flags.union(MapFlags::USER);
    }
    if writable {
        flags = flags.union(MapFlags::WRITE);
    }
    if executable {
        flags = flags.union(MapFlags::EXECUTE);
    }
    let active = kobj::with(|t| {
        let Ok(KObject::Process(p)) = t.get_mut(pid) else {
            return Err(MemError::NoSuchProcess);
        };
        if p.state != ProcState::Running {
            return Err(MemError::NoSuchProcess);
        }
        for i in 0..pages {
            if is_device_page(p, va + i * FRAME_SIZE) || is_shared_page(p, va + i * FRAME_SIZE) {
                return Err(MemError::InvalidRange);
            }
            if p.space
                .translate(VirtPage::containing(va + i * FRAME_SIZE))
                .is_none()
            {
                return Err(MemError::NotMapped);
            }
        }
        if !p.space.begin_shootdown() {
            return Err(MemError::Busy);
        }
        for i in 0..pages {
            if let Err(e) = p
                .space
                .protect_raw(VirtPage::containing(va + i * FRAME_SIZE), flags)
            {
                p.space.end_shootdown();
                return Err(match e {
                    MapError::Busy => MemError::Busy,
                    MapError::OutOfFrames => MemError::OutOfMemory,
                    _ => MemError::InvalidRange,
                });
            }
        }
        Ok(p.space.active_cpus())
    })?;
    if crate::smp::tlb_shootdown_on(active, va, pages).is_err() {
        // 权限修改已写入页表，但旧 TLB 可能仍允许旧权限。帧不再由进程负责归还，
        // 而是永久隔离，进程销毁时也不会回到分配器。
        kobj::with(|t| {
            if let Ok(KObject::Process(p)) = t.get_mut(pid) {
                for i in 0..pages {
                    let frame = p
                        .space
                        .translate(VirtPage::containing(va + i * FRAME_SIZE))
                        .map(|(frame, _)| frame);
                    if let Some(frame) = frame {
                        if let Some(index) = p
                            .frames
                            .iter()
                            .position(|page| page.frame().start() == frame.start())
                        {
                            let page = p.frames.remove(index);
                            page.quarantine();
                            p.quarantine_one(frame);
                        }
                    }
                }
            }
            Ok::<(), MemError>(())
        })
        .ok();
        return Err(MemError::Busy);
    }
    kobj::with(|t| {
        let Ok(KObject::Process(p)) = t.get_mut(pid) else {
            return Err(MemError::NoSuchProcess);
        };
        p.space.end_shootdown();
        Ok(())
    })
}

/// Applies Linux `mprotect(2)` permissions to private and shared pages.
///
/// Native Jasper capabilities keep shared mappings immutable through the
/// stricter [`protect_range_access`] path. Linux processes, however, may change
/// the per-process page protection of a shared backing; the backing frame stays
/// shared while only this address-space mapping receives the new permissions.
#[cfg(feature = "linux-abi")]
pub(crate) fn protect_linux_range_access(
    pid: ObjId,
    va: u64,
    pages: u64,
    accessible: bool,
    writable: bool,
    executable: bool,
) -> Result<(), MemError> {
    checked_range(va, pages)?;
    let mut flags = MapFlags::READ_ONLY;
    if accessible {
        flags = flags.union(MapFlags::USER);
    }
    if writable {
        flags = flags.union(MapFlags::WRITE);
    }
    if executable {
        flags = flags.union(MapFlags::EXECUTE);
    }
    let active = kobj::with(|t| {
        let Ok(KObject::Process(p)) = t.get_mut(pid) else {
            return Err(MemError::NoSuchProcess);
        };
        if p.state != ProcState::Running {
            return Err(MemError::NoSuchProcess);
        }
        for i in 0..pages {
            if is_device_page(p, va + i * FRAME_SIZE) {
                return Err(MemError::InvalidRange);
            }
            if p.space
                .translate(VirtPage::containing(va + i * FRAME_SIZE))
                .is_none()
            {
                return Err(MemError::NotMapped);
            }
        }
        if !p.space.begin_shootdown() {
            return Err(MemError::Busy);
        }
        for i in 0..pages {
            if let Err(e) = p
                .space
                .protect_raw(VirtPage::containing(va + i * FRAME_SIZE), flags)
            {
                p.space.end_shootdown();
                return Err(match e {
                    MapError::Busy => MemError::Busy,
                    MapError::OutOfFrames => MemError::OutOfMemory,
                    _ => MemError::InvalidRange,
                });
            }
        }
        let end = va + pages * FRAME_SIZE;
        for mapping in &mut p.shared_maps {
            if mapping.va >= va && mapping.va < end {
                mapping.flags = flags;
            }
        }
        Ok(p.space.active_cpus())
    })?;
    if crate::smp::tlb_shootdown_on(active, va, pages).is_err() {
        kobj::with(|t| {
            if let Ok(KObject::Process(p)) = t.get_mut(pid) {
                for i in 0..pages {
                    let frame = p
                        .space
                        .translate(VirtPage::containing(va + i * FRAME_SIZE))
                        .map(|(frame, _)| frame);
                    if let Some(frame) = frame {
                        if let Some(index) = p
                            .frames
                            .iter()
                            .position(|page| page.frame().start() == frame.start())
                        {
                            let page = p.frames.remove(index);
                            page.quarantine();
                            p.quarantine_one(frame);
                        }
                    }
                }
            }
            Ok::<(), MemError>(())
        })
        .ok();
        return Err(MemError::Busy);
    }
    kobj::with(|t| {
        let Ok(KObject::Process(p)) = t.get_mut(pid) else {
            return Err(MemError::NoSuchProcess);
        };
        p.space.end_shootdown();
        Ok(())
    })
}

/// 进程中 `va` 所在页的映射标志（未映射为 `None`；诊断与验收用）。
pub fn page_flags(pid: ObjId, va: u64) -> Option<MapFlags> {
    with_proc(pid, |p| {
        Ok(p.space.translate(VirtPage::containing(va)).map(|(_, f)| f))
    })
    .ok()
    .flatten()
}

/// Returns one private Linux mapping's original protection flags.
#[cfg(feature = "linux-abi")]
pub(crate) fn linux_mapping_flags(pid: ObjId, va: u64) -> Option<MapFlags> {
    with_proc(pid, |process| {
        let linux = process.linux.as_ref().ok_or(ProcError::Exited)?;
        Ok(linux
            .mappings
            .iter()
            .find(|mapping| mapping.va == va)
            .map(|mapping| mapping.flags))
    })
    .ok()
    .flatten()
}

/// Returns the immutable-file backing metadata for one Linux mapping page.
#[cfg(feature = "linux-abi")]
pub(crate) fn linux_mapping_file(
    pid: ObjId,
    va: u64,
) -> Option<(crate::linux_vfs::FileId, u64, bool)> {
    let va = va - va % FRAME_SIZE;
    with_proc(pid, |process| {
        let linux = process.linux.as_ref().ok_or(ProcError::Exited)?;
        let mapping = linux
            .mappings
            .iter()
            .find(|mapping| mapping.va == va)
            .ok_or(ProcError::NoSuchProcess)?;
        Ok(mapping.file.map(|file| (file, mapping.file_offset, mapping.shared_file)))
    })
    .ok()
    .flatten()
}

/// Records immutable-file backing metadata after a successful mapping.
#[cfg(feature = "linux-abi")]
pub(crate) fn set_linux_mapping_file(
    pid: ObjId,
    va: u64,
    file: crate::linux_vfs::FileId,
    file_offset: u64,
    shared: bool,
) -> bool {
    with_proc(pid, |process| {
        let linux = process.linux.as_mut().ok_or(ProcError::Exited)?;
        let mapping = linux
            .mappings
            .iter_mut()
            .find(|mapping| mapping.va == va)
            .ok_or(ProcError::NoSuchProcess)?;
        mapping.file = Some(file);
        mapping.file_offset = file_offset;
        mapping.shared_file = shared;
        Ok(())
    })
    .is_ok()
}

/// Reports whether one Linux virtual page belongs to a shared memory mapping.
#[cfg(feature = "linux-abi")]
pub(crate) fn linux_page_is_shared(pid: ObjId, va: u64) -> bool {
    with_proc(pid, |process| Ok(is_shared_page(process, va)))
        .unwrap_or(false)
}

/// Returns a process-independent futex identity for a shared mapping word.
#[cfg(feature = "linux-abi")]
pub(crate) fn linux_shared_futex_key(pid: ObjId, va: u64) -> Option<u64> {
    with_proc(pid, |process| {
        if !is_shared_page(process, va) {
            return Ok(None);
        }
        let Some((frame, _)) = process.space.translate(VirtPage::containing(va)) else {
            return Ok(None);
        };
        Ok(Some(
            frame.start() + va % kernel_core::frame::FRAME_SIZE,
        ))
    })
    .ok()
    .flatten()
}

/// Returns the current hardware address-space root for one process.
/// 返回进程当前硬件地址空间根。
pub(crate) fn current_space_root(pid: ObjId) -> Option<crate::arch::SpaceRoot> {
    with_proc(pid, |p| Ok(p.space.root())).ok()
}

/// 进程当前拥有的数据帧数（诊断与验收用）。
pub fn frame_count(pid: ObjId) -> Option<usize> {
    with_proc(pid, |p| Ok(p.frames.len())).ok()
}

/// Returns `(page_count, total Arc references, maximum Arc references per page)`.
///
/// 返回进程页引用诊断；用于证明退出回收并非被额外 Arc 强引用阻止。
pub fn frame_reference_stats(pid: ObjId) -> Option<(usize, usize, usize)> {
    with_proc(pid, |p| {
        let total = p
            .frames
            .iter()
            .map(|page| alloc::sync::Arc::strong_count(page))
            .sum();
        let max = p
            .frames
            .iter()
            .map(|page| alloc::sync::Arc::strong_count(page))
            .max()
            .unwrap_or(0);
        Ok((p.frames.len(), total, max))
    })
    .ok()
}

/// (Allocated backing pages, fixed-page references); account may outlive its creator.
pub fn memory_quota(pid: ObjId) -> Option<kernel_core::memory_object::Usage> {
    with_proc(pid, |p| Ok(p.memory_account.snapshot())).ok()
}

/// Reserve fixed-page references inside an existing object-table transaction.
pub(crate) fn reserve_memory_pins_in(
    t: &mut kobj::Table,
    pid: ObjId,
    pages: u64,
) -> Option<crate::mm::memory_quota::Charge> {
    let p = receiver(t, pid).ok()?;
    p.memory_account
        .reserve(0, pages, p.memory_owned_limit, p.memory_pin_limit)
}

/// Set optional hard limits for the ordinary process account; the default is no fixed cap.
pub(crate) fn set_memory_limits(pid: ObjId, owned: u64, pinned: u64) -> bool {
    with_proc(pid, |p| {
        let usage = p.memory_account.snapshot();
        if usage.mapped > owned || usage.pinned > pinned {
            return Err(ProcError::MemoryQuota);
        }
        p.memory_owned_limit = owned;
        p.memory_pin_limit = pinned;
        Ok(())
    })
    .is_ok()
}

/// Effective ordinary object/fixed-page limits `(owned, pinned)`.
pub fn memory_limits(pid: ObjId) -> Option<(u64, u64)> {
    with_proc(pid, |p| Ok((p.memory_owned_limit, p.memory_pin_limit))).ok()
}

/// Current separate VM guest RAM usage for diagnostics.
pub fn vm_guest_memory_quota(pid: ObjId) -> Option<kernel_core::memory_object::Usage> {
    with_proc(pid, |p| Ok(p.vm_guest_account.snapshot())).ok()
}

/// 进程当前持有的设备 BAR 映射数（诊断与验收用；进程已退出时应为 0）。
/// Number of device BAR mappings currently held by a process (diagnostics / acceptance).
pub fn device_map_count(pid: ObjId) -> Option<usize> {
    with_proc(pid, |p| Ok(p.device_maps.len())).ok()
}

/// SEC-6 diagnostic: active software memory capabilities and revocation count.
pub fn memory_capability_stats(pid: ObjId) -> Option<(usize, u64)> {
    with_proc(pid, |p| {
        Ok((p.memory_caps.active(), p.memory_caps.revoked()))
    })
    .ok()
}

/// 在锁内固定进程 `pid` 的用户区间 `[va, va+len)`：区间须位于私有窗口、每页已映射且带用户权限（`write` 时还须可写）。
/// 返回的范围此后只经物理映射访问；任一页不满足 ⇒ 不固定任何帧。
/// Pins a user range of `pid` (all-or-nothing).
pub(crate) fn pin_user_in(
    t: &mut kobj::Table,
    pid: ObjId,
    va: u64,
    len: usize,
    write: bool,
) -> Result<crate::mm::pin::PinnedRange, ProcError> {
    let bad = ProcError::Map(MapError::InvalidAddress);
    let p = match t.get(pid) {
        Ok(KObject::Process(p)) => p,
        _ => return Err(ProcError::NoSuchProcess),
    };
    let mut segs = Vec::new();
    let mut page_refs = Vec::new();
    if len > 0 {
        let end = va.checked_add(len as u64).ok_or(bad)?;
        if !in_private_window(va) || !in_private_window(end - 1) {
            return Err(bad);
        }
        let mut cur = va;
        while cur < end {
            let off = cur % FRAME_SIZE;
            let n = (FRAME_SIZE - off).min(end - cur);
            let (f, flags) = p.space.translate(VirtPage::containing(cur)).ok_or(bad)?;
            if !flags.contains(MapFlags::USER) || (write && !flags.contains(MapFlags::WRITE)) {
                return Err(bad);
            }
            let required = MemoryRights::READ.union(if write {
                MemoryRights::WRITE
            } else {
                MemoryRights::NONE
            });
            let shared = p.shared_maps.iter().find(|m| m.va == cur - off);
            p.memory_caps
                .check(cur, n, required, shared.map(|mapping| mapping.source))
                .map_err(|_| bad)?;
            segs.try_reserve(1).map_err(|_| ProcError::OutOfFrames)?;
            let backing = if let Some(mapping) = shared {
                Some(Arc::clone(&mapping.page))
            } else if let Some(page) = p.frames.iter().find(|page| page.frame() == f) {
                Some(Arc::clone(page))
            } else if is_device_page(p, cur - off) {
                None
            } else {
                return Err(bad);
            };
            page_refs
                .try_reserve(1)
                .map_err(|_| ProcError::OutOfFrames)?;
            page_refs.push(backing);
            segs.push((f, off as u32, n as u32));
            cur += n;
        }
    }
    let charge = p
        .memory_account
        .reserve(
            0,
            segs.len() as u64,
            p.memory_owned_limit,
            p.memory_pin_limit,
        )
        .ok_or(ProcError::MemoryQuota)?;
    crate::mm::pin::PinnedRange::new(segs, page_refs, charge).ok_or(ProcError::OutOfFrames)
}

/// 向进程内存写入字节（经页表查询 + 物理映射；目标必须已映射）。用于装载代码与初始数据。
pub fn write(id: ObjId, va: u64, bytes: &[u8]) -> Result<(), ProcError> {
    with_proc(id, |p| {
        let mut done = 0usize;
        while done < bytes.len() {
            let cur = va + done as u64;
            let off = cur % FRAME_SIZE;
            let n = ((FRAME_SIZE - off) as usize).min(bytes.len() - done);
            let (f, _) = p
                .space
                .translate(VirtPage::containing(cur))
                .ok_or(ProcError::Map(MapError::NotMapped))?;
            let k =
                phys_to_virt(f.start() + off).ok_or(ProcError::Map(MapError::InvalidAddress))?;
            // SAFETY：目标帧属于该进程且已映射；n 不越过页尾。
            unsafe { core::ptr::copy_nonoverlapping(bytes[done..].as_ptr(), k, n) };
            done += n;
        }
        Ok(())
    })
}

/// Read bytes from a mapped process range through the page table and physical mapping.
///
/// 经页表查询和物理映射读取已映射的进程内存；复制前验证整个范围，失败不产生部分输出。
pub fn read(id: ObjId, va: u64, output: &mut [u8]) -> Result<(), ProcError> {
    with_proc(id, |p| {
        if output.is_empty() {
            return Ok(());
        }
        let end = va
            .checked_add(output.len() as u64)
            .ok_or(ProcError::Map(MapError::InvalidAddress))?;
        let mut check = va;
        while check < end {
            p.space
                .translate(VirtPage::containing(check))
                .ok_or(ProcError::Map(MapError::NotMapped))?;
            check = (check - check % FRAME_SIZE) + FRAME_SIZE;
        }
        let mut done = 0usize;
        while done < output.len() {
            let cur = va + done as u64;
            let off = cur % FRAME_SIZE;
            let n = ((FRAME_SIZE - off) as usize).min(output.len() - done);
            let (f, _) = p
                .space
                .translate(VirtPage::containing(cur))
                .ok_or(ProcError::Map(MapError::NotMapped))?;
            let k =
                phys_to_virt(f.start() + off).ok_or(ProcError::Map(MapError::InvalidAddress))?;
            // SAFETY: the mapped frame belongs to this process and n stays within the page.
            unsafe { core::ptr::copy_nonoverlapping(k, output[done..].as_mut_ptr(), n) };
            done += n;
        }
        Ok(())
    })
}

/// 装载 ELF 失败的原因。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LoadError {
    /// 文件本身不合法（见 `kernel_core::elf::ElfError`）。
    Elf(kernel_core::elf::ElfError),
    /// 程序 ABI 章缺失、损坏或与内核世代不兼容（在任何页映射之前拒绝）。
    Abi(kernel_core::abi_version::AbiReject),
    /// 程序声明的所需能力在当前生效 Profile 中未装配或不可用。
    Capability,
    /// 某个段不在用户私有窗口内。
    OutsideWindow,
    /// 映射或复制失败。
    Proc(ProcError),
    /// Linux compatibility input unexpectedly carried Jasper ABI metadata.
    /// Linux 兼容输入意外携带了 Jasper ABI 元数据。
    UnexpectedMetadata,
}

impl LoadError {
    /// 规范错误名。
    pub fn name(self) -> &'static str {
        match self {
            LoadError::Elf(e) => e.name(),
            LoadError::Abi(e) => e.name(),
            LoadError::Capability => "system.error.abi_capability",
            LoadError::OutsideWindow => "system.memory.error.invalid_address",
            LoadError::Proc(_) => "system.memory.error.out_of_frames",
            LoadError::UnexpectedMetadata => "system.error.abi_metadata",
        }
    }
}

/// 把 ELF64 静态可执行文件装进进程，返回入口地址（按段权限映射，先清零再复制，BSS 天然为零）。
///
/// ABI 世代检查在**任何页映射之前**完成：没有章、章损坏、跨主版本或要求的次版本高于本内核，
/// 都返回 [`LoadError::Abi`]，进程地址空间保持原样，用户代码没有机会执行。
pub fn load_elf(id: ObjId, image: &[u8]) -> Result<u64, LoadError> {
    load_static_elf(id, image, true)
}

/// Loads an unmodified static Linux ET_EXEC into a Linux-flavored process.
///
/// 把没有 Jasper ABI/capability 章的静态 Linux ET_EXEC 映射到 Linux flavor 进程。
/// 这是首片静态执行入口；动态解释器、libc 和信号栈仍由后续节点实现。
#[cfg(feature = "linux-abi")]
pub fn load_linux_elf(id: ObjId, image: &[u8]) -> Result<u64, LoadError> {
    if !is_linux_process(id) {
        return Err(LoadError::OutsideWindow);
    }
    load_static_elf(id, image, false)
}

fn load_static_elf(id: ObjId, image: &[u8], require_jasper_abi: bool) -> Result<u64, LoadError> {
    let elf = kernel_core::elf::parse(image, arch::ELF_MACHINE, arch::ELF_CLASS)
        .map_err(LoadError::Elf)?;
    if require_jasper_abi {
        kernel_core::abi_version::check_image(elf.abi(), kernel_core::abi_version::NATIVE)
            .map_err(LoadError::Abi)?;
        if elf
            .required_capabilities()
            .first_unavailable(crate::profile::has_capability)
            .is_some()
        {
            return Err(LoadError::Capability);
        }
    } else if elf.abi().is_some() || elf.required_capabilities().iter().next().is_some() {
        return Err(LoadError::UnexpectedMetadata);
    }
    for seg in elf.segments() {
        // 解析器保证 memsz > 0 且页区间可表示；这里仍用检查式算术，任何溢出都按「窗口外」拒绝
        let (lo, hi) = seg.page_range().ok_or(LoadError::OutsideWindow)?;
        if !in_private_window(lo) || !in_private_window(hi - 1) {
            return Err(LoadError::OutsideWindow);
        }
    }
    for seg in elf.segments() {
        let mut flags = MapFlags::USER;
        if seg.flags.write {
            flags = flags | MapFlags::WRITE;
        }
        if seg.flags.execute {
            flags = flags | MapFlags::EXECUTE;
        }
        let (lo, hi) = seg.page_range().ok_or(LoadError::OutsideWindow)?;
        let mut va = lo;
        while va < hi {
            map_new(id, va, flags).map_err(LoadError::Proc)?;
            va += FRAME_SIZE;
        }
        write(id, seg.vaddr, seg.file_bytes(image)).map_err(LoadError::Proc)?;
    }
    Ok(elf.entry)
}

/// 读进程内存中的一个 64 位字（诊断与验收用）。
pub fn read_u64(id: ObjId, va: u64) -> Option<u64> {
    with_proc(id, |p| {
        let (f, _) = p
            .space
            .translate(VirtPage::containing(va))
            .ok_or(ProcError::Map(MapError::NotMapped))?;
        let k = phys_to_virt(f.start() + va % FRAME_SIZE)
            .ok_or(ProcError::Map(MapError::InvalidAddress))?;
        // SAFETY：已映射的进程帧，调用者保证 8 字节对齐。
        Ok(unsafe { (k as *const u64).read_volatile() })
    })
    .ok()
}

/// 线程首次运行的入口：取出启动参数 → 切到进程空间与调用集合 → 进入用户态。
fn thread_entry() {
    let (me, _) = sched::current();
    let (start, member) = {
        let reg = REG.lock();
        (
            reg.starts.iter().find(|s| s.task == me).copied(),
            reg.members.iter().find(|m| m.task == me).copied(),
        )
    };
    let (Some(s), Some(m)) = (start, member) else {
        return;
    };
    let Ok((root, syscalls)) = with_proc(m.process, |p| Ok((p.space.root(), p.syscalls))) else {
        return;
    };
    sched::set_current_space(Some(root));
    sched::set_current_syscalls(syscalls);
    if let Some(base) = s.fs_base {
        let _ = arch::set_user_fs_base(base);
    }
    #[cfg(all(feature = "linux-abi", target_arch = "x86_64"))]
    if s.linux_clone {
        // SAFETY：clone 的 RIP/RSP 已由 spawn_linux_clone 校验在用户私有窗口内。
        unsafe {
            crate::arch::x86_64::enter_syscall_return( // JASPER-ISA-REFERENCE: x86_64 Linux clone entry only.
                s.entry,
                s.stack,
                s.linux_fork_regs.unwrap_or([0; 6]),
                s.linux_fork_args
                    .unwrap_or([0, 0, s.clone_rdx, 0, s.clone_r8, 0]),
                s.clone_rdx,
                s.clone_r8,
            )
        }
    }
    // SAFETY：entry/stack 已校验位于私有窗口，代码与栈页由创建方映射；内核栈顶由调度器设置。
    unsafe { arch::enter_user(s.entry, s.stack, s.arg0, s.arg1) }
}

/// 在进程中创建线程（入口与栈顶必须位于私有窗口内）。返回调度任务标识与 Task 对象标识。
///
/// Task 对象初始持有 2 个内部引用：线程执行上下文、进程线程表；执行上下文另持有 Process 的 1 个内部引用。
pub fn spawn_thread(
    id: ObjId,
    name: &'static str,
    entry: u64,
    stack: u64,
    arg0: u64,
    arg1: u64,
) -> Result<(TaskId, ObjId), ProcError> {
    spawn_thread_mode(
        id, name, entry, stack, arg0, arg1, None, false, None, None, None, 0, 0, 0,
    )
}

/// Author: chatgpt. Install affinity before publishing the runnable thread.
/// The existing rollback path owns all resources if spawn_on rejects the set.
pub(crate) fn spawn_thread_affinity(
    id: ObjId,
    name: &'static str,
    entry: u64,
    stack: u64,
    arg0: u64,
    arg1: u64,
    affinity: Option<kernel_core::smp::CpuSet>,
) -> Result<(TaskId, ObjId), ProcError> {
    spawn_thread_mode(
        id, name, entry, stack, arg0, arg1, affinity, false, None, None, None, 0, 0, 0,
    )
}

/// Creates a Linux clone child that resumes at the syscall return address with `rax=0`.
///
/// 创建 Linux clone 子线程；首次进入用户态时按 syscall 子线程约定返回 `rax=0`。
#[cfg(all(feature = "linux-abi", target_arch = "x86_64"))]
pub fn spawn_linux_clone(
    id: ObjId,
    name: &'static str,
    user_rip: u64,
    user_stack: u64,
    fs_base: Option<u64>,
    preserved_regs: Option<[u64; 6]>,
    fork_args: Option<[u64; 6]>,
    clear_child_tid: u64,
    clone_rdx: u64,
    clone_r8: u64,
) -> Result<(TaskId, ObjId), ProcError> {
    spawn_thread_mode(
        id,
        name,
        user_rip,
        user_stack,
        0,
        0,
        None,
        true,
        fs_base,
        preserved_regs,
        fork_args,
        clear_child_tid,
        clone_rdx,
        clone_r8,
    )
}

/// Creates one bounded Linux fork child with a private copy of the parent address space.
///
/// 创建有界 Linux fork 子进程并复制父进程的私有地址空间。共享映射、设备映射和
/// 击落隔离帧不属于当前 fork 子集，调用会失败关闭而不是错误共享父页。
#[cfg(all(feature = "linux-abi", target_arch = "x86_64"))]
pub fn fork_linux_process(
    parent: ObjId,
    user_rip: u64,
    user_stack: u64,
    fs_base: u64,
    preserved_regs: [u64; 6],
    fork_args: [u64; 6],
    clear_child_tid: u64,
) -> Result<ObjId, ProcError> {
    let (parent_linux_pid, calls, state, mappings, shared_mappings) =
        kobj::with(|t| match t.get(parent) {
        Ok(KObject::Process(p)) if p.state == ProcState::Running => {
            let linux = p.linux.as_ref().ok_or(ProcError::NoSuchProcess)?;
            if !p.device_maps.is_empty() || !p.quarantined.is_empty() {
                return Err(ProcError::NotTransferable);
            }
            let mappings = linux
                .mappings
                .iter()
                .copied()
                .filter(|mapping| mapping.flags.contains(MapFlags::USER))
                .collect::<Vec<_>>();
            let shared_mappings = p
                .shared_maps
                .iter()
                .map(|mapping| {
                    (
                        mapping.va,
                        Arc::clone(&mapping.page),
                        mapping.source,
                        mapping.flags,
                    )
                })
                .collect::<Vec<_>>();
            Ok((
                linux.pid,
                linux.calls,
                linux.clone(),
                mappings,
                shared_mappings,
            ))
        }
        _ => Err(ProcError::NoSuchProcess),
    })?;

    let child = create_linux("linux-fork", calls)?;
    let rollback = |child: ObjId, adopted: bool| {
        if adopted {
            let _ = release_child(parent, child);
        }
        let _ = exit_idle(child, -1);
        let _ = reap(child);
    };
    let child_pid = match linux_pid(child) {
        Some(pid) => pid,
        None => {
            rollback(child, false);
            return Err(ProcError::NoSuchProcess);
        }
    };
    let prepared = with_proc(child, |p| {
        let linux = p.linux.as_mut().ok_or(ProcError::NoSuchProcess)?;
        *linux = state;
        linux.pid = child_pid;
        linux.ppid = parent_linux_pid;
        linux.child_cpu_ticks = 0;
        linux.exited_cpu_ticks = 0;
        linux.pdeathsig = 0;
        linux.subreaper = false;
        linux.termination_signal = 0;
        linux.mappings.clear();
        linux.aio_contexts.clear();
        Ok(())
    });
    if prepared.is_err() || inherit_application(parent, child).is_err() {
        rollback(child, false);
        return Err(ProcError::NoSuchProcess);
    }
    for mapping in mappings {
        if let Err(error) = copy_linux_mapping(parent, child, mapping) {
            kprintln!(
                "[JSR-LINUX-FORK-PAGE-FAIL] va={:#x} flags={:?} error={:?}",
                mapping.va,
                mapping.flags,
                error
            );
            rollback(child, false);
            return Err(error);
        }
    }
    for (va, page, source, flags) in shared_mappings {
        if let Err(error) = copy_linux_shared_mapping(child, va, page, source, flags) {
            rollback(child, false);
            return Err(error);
        }
    }
    if !crate::linux_abi::inherit_sysv_shared_process(parent, child) {
        rollback(child, false);
        return Err(ProcError::OutOfFrames);
    }
    if adopt(parent, child).is_err() {
        rollback(child, false);
        return Err(ProcError::NoSuchProcess);
    }
    if spawn_linux_clone(
        child,
        "linux-fork",
        user_rip,
        user_stack,
        Some(fs_base),
        Some(preserved_regs),
        Some(fork_args),
        clear_child_tid,
        0,
        0,
    )
    .is_err()
    {
        rollback(child, true);
        return Err(ProcError::NoTaskSlot);
    }
    Ok(child)
}

/// Creates a Linux vfork child without copying its pages.
///
/// 创建 Linux vfork 子进程但不复制页面：子进程映射父进程相同的物理帧，父线程
/// 由调用者休眠等待。既有共享映射随借用地址空间保留；设备映射和隔离帧失败关闭。
#[cfg(all(feature = "linux-abi", target_arch = "x86_64"))]
pub fn vfork_linux_process(
    parent: ObjId,
    user_rip: u64,
    user_stack: u64,
    fs_base: u64,
    preserved_regs: [u64; 6],
    syscall_args: [u64; 6],
    parent_task: TaskId,
) -> Result<ObjId, ProcError> {
    let parent_stack_top = crate::arch::kernel_stack();
    let (
        parent_linux_pid,
        calls,
        state,
        parent_root,
        frames,
        memory_caps,
        shared_mappings,
    ) =
        kobj::with(|t| match t.get(parent) {
            Ok(KObject::Process(p)) if p.state == ProcState::Running && p.threads_live != 0 => {
                let linux = p.linux.as_ref().ok_or(ProcError::NoSuchProcess)?;
                if !p.device_maps.is_empty() || !p.quarantined.is_empty() {
                    return Err(ProcError::NotTransferable);
                }
                let mut frames = Vec::new();
                frames
                    .try_reserve(p.frames.len())
                    .map_err(|_| ProcError::OutOfFrames)?;
                frames.extend(p.frames.iter().cloned());
                let shared_mappings = p
                    .shared_maps
                    .iter()
                    .map(|mapping| {
                        (
                            mapping.va,
                            Arc::clone(&mapping.page),
                            mapping.source,
                            mapping.flags,
                        )
                    })
                    .collect::<Vec<_>>();
                Ok((
                    linux.pid,
                    linux.calls,
                    linux.clone(),
                    p.space.root(),
                    frames,
                    p.memory_caps.clone(),
                    shared_mappings,
                ))
            }
            Ok(KObject::Process(_)) => Err(ProcError::Exited),
            _ => Err(ProcError::NoSuchProcess),
        })?;
    let phys_offset = crate::boot::get()
        .and_then(|boot| boot.phys_offset)
        .ok_or(ProcError::Map(MapError::NotMapped))?;
    let parent_stack_base = parent_stack_top
        .checked_sub(crate::sched::stack::STACK_SIZE as u64)
        .ok_or(ProcError::Map(MapError::InvalidAddress))?;
    for va in (parent_stack_base..parent_stack_top).step_by(kernel_core::frame::FRAME_SIZE as usize)
    {
        let parent_stack_frame = unsafe { crate::arch::translate_in(parent_root, phys_offset, va) }
            .map(|(frame, _)| frame)
            .ok_or(ProcError::Map(MapError::NotMapped))?;
        if frames.iter().any(|page| page.frame() == parent_stack_frame) {
            return Err(ProcError::NotTransferable);
        }
    }

    let child = create_linux("linux-vfork", calls)?;
    let rollback = |child: ObjId, adopted: bool| {
        if adopted {
            let _ = release_child(parent, child);
        }
        let _ = exit_idle(child, -1);
        let _ = reap(child);
    };
    let child_pid = match linux_pid(child) {
        Some(pid) => pid,
        None => {
            rollback(child, false);
            return Err(ProcError::NoSuchProcess);
        }
    };
    let prepared = with_proc(child, |p| {
        let linux = p.linux.as_mut().ok_or(ProcError::NoSuchProcess)?;
        *linux = state;
        linux.pid = child_pid;
        linux.ppid = parent_linux_pid;
        linux.child_cpu_ticks = 0;
        linux.exited_cpu_ticks = 0;
        linux.pdeathsig = 0;
        linux.subreaper = false;
        linux.termination_signal = 0;
        linux.vfork_parent = Some(VforkParent {
            task: parent_task,
            exec_committed: false,
        });
        p.frames = frames;
        p.memory_caps = memory_caps;
        p.shared_maps.clear();
        p.shared_maps
            .try_reserve(shared_mappings.len())
            .map_err(|_| ProcError::OutOfFrames)?;
        for (va, page, source, flags) in shared_mappings {
            p.shared_maps.push(SharedMapping {
                va,
                page,
                source,
                flags,
            });
        }
        let borrowed = crate::mm::space::VmSpace::borrowed(parent_root).map_err(ProcError::Map)?;
        let old = core::mem::replace(&mut p.space, borrowed);
        drop(old);
        Ok(())
    });
    if prepared.is_err() || inherit_application(parent, child).is_err() {
        rollback(child, false);
        return Err(ProcError::NoSuchProcess);
    }
    if !crate::linux_abi::inherit_sysv_shared_process(parent, child) {
        rollback(child, false);
        return Err(ProcError::OutOfFrames);
    }
    if adopt(parent, child).is_err() {
        rollback(child, false);
        return Err(ProcError::NoSuchProcess);
    }
    if spawn_linux_clone(
        child,
        "linux-vfork",
        user_rip,
        user_stack,
        Some(fs_base),
        Some(preserved_regs),
        Some(syscall_args),
        0,
        0,
        0,
    )
    .is_err()
    {
        rollback(child, true);
        return Err(ProcError::NoTaskSlot);
    }
    Ok(child)
}

/// Commits successful exec as the child-side vfork terminal transition.
/// 把成功 exec 作为 vfork 子侧终态迁移；重复提交或非 vfork 子进程无副作用。
#[cfg(feature = "linux-abi")]
pub(crate) fn vfork_commit_exec(child: ObjId) -> bool {
    let parent = with_proc(child, |p| {
        let linux = p.linux.as_mut().ok_or(ProcError::NoSuchProcess)?;
        let Some(parent) = linux.vfork_parent.as_mut() else {
            return Ok(None);
        };
        if parent.exec_committed {
            return Ok(None);
        }
        parent.exec_committed = true;
        Ok(Some(parent.task))
    })
    .ok()
    .flatten();
    if let Some(task) = parent {
        sched::wake(task);
        true
    } else {
        false
    }
}

/// Returns whether a vfork parent may resume.
///
/// 子进程提交 exec 或已离开 Running 后父线程可恢复；不存在的子进程也视为终止，
/// 调用者随后会按正常 Linux 子进程错误路径失败关闭。
#[cfg(feature = "linux-abi")]
pub(crate) fn vfork_parent_may_resume(child: ObjId) -> bool {
    kobj::with(|t| match t.get(child) {
        Ok(KObject::Process(p)) => {
            p.state != ProcState::Running
                || p.linux
                    .as_ref()
                    .and_then(|linux| linux.vfork_parent)
                    .is_some_and(|parent| parent.exec_committed)
        }
        _ => true,
    })
}

#[cfg(all(feature = "linux-abi", target_arch = "x86_64"))]
fn copy_linux_shared_mapping(
    child: ObjId,
    va: u64,
    page: Arc<crate::mm::memory_object::Page>,
    source: BackingIdentity,
    flags: MapFlags,
) -> Result<(), ProcError> {
    with_proc(child, |process| {
        if process.state != ProcState::Running
            || process
                .shared_maps
                .len()
                .checked_add(1)
                .is_none_or(|count| count > MAX_PROCESS_FRAMES)
        {
            return Err(ProcError::MemoryQuota);
        }
        if process
            .space
            .translate(VirtPage::containing(va))
            .is_some()
        {
            return Err(ProcError::Map(MapError::InvalidAddress));
        }
        process
            .shared_maps
            .try_reserve(1)
            .map_err(|_| ProcError::NoTaskSlot)?;
        if !process.space.begin_shootdown() {
            return Err(ProcError::Map(MapError::Busy));
        }
        let writable = flags.contains(MapFlags::WRITE);
        if process
            .space
            .map_raw(VirtPage::containing(va), page.frame(), flags)
            .is_err()
        {
            process.space.end_shootdown();
            return Err(ProcError::Map(MapError::NotMapped));
        }
        let rights = MemoryRights::READ
            .union(MemoryRights::MAP)
            .union(if writable {
                MemoryRights::WRITE
            } else {
                MemoryRights::NONE
            });
        if process
            .memory_caps
            .grant(va, 1, rights, MemoryKind::Shared, source)
            .is_err()
        {
            let _ = process.space.unmap_raw(VirtPage::containing(va));
            process.space.end_shootdown();
            return Err(ProcError::MemoryQuota);
        }
        process.shared_maps.push(SharedMapping {
            va,
            page,
            source,
            flags,
        });
        process.space.end_shootdown();
        Ok(())
    })
}

#[cfg(all(feature = "linux-abi", target_arch = "x86_64"))]
fn copy_linux_mapping(parent: ObjId, child: ObjId, mapping: LinuxMapping) -> Result<(), ProcError> {
    let (source, current_flags) = with_proc(parent, |p| {
        let (frame, current_flags) = p
            .space
            .translate(VirtPage::containing(mapping.va))
            .ok_or(ProcError::Map(MapError::NotMapped))?;
        let page = p
            .frames
            .iter()
            .find(|page| page.frame() == frame)
            .cloned()
            .ok_or(ProcError::Map(MapError::NotMapped))?;
        Ok((page, current_flags))
    })?;
    let source_frame = source.frame();
    let charge = kobj::with(|t| {
        let p = receiver(t, child)?;
        p.memory_account
            .reserve(1, 0, p.memory_owned_limit, p.memory_pin_limit)
            .ok_or(ProcError::MemoryQuota)
    })?;
    let page = crate::mm::memory_object::Page::zeroed(charge).ok_or(ProcError::OutOfFrames)?;
    let destination_frame = page.frame();
    let source_ptr =
        phys_to_virt(source_frame.start()).ok_or(ProcError::Map(MapError::NotMapped))? as *const u8;
    let destination_ptr = phys_to_virt(destination_frame.start())
        .ok_or(ProcError::Map(MapError::NotMapped))? as *mut u8;
    // SAFETY: both aliases cover one live private data frame. `source` keeps the
    // parent frame retained while the child frame is exclusively new.
    unsafe {
        core::ptr::copy_nonoverlapping(
            source_ptr,
            destination_ptr,
            kernel_core::frame::FRAME_SIZE as usize,
        );
    }
    with_proc(child, |p| {
        if p.frames.len() + p.shared_maps.len() >= MAX_PROCESS_FRAMES {
            return Err(ProcError::MemoryQuota);
        }
        p.frames
            .try_reserve(1)
            .map_err(|_| ProcError::OutOfFrames)?;
        let linux = p.linux.as_mut().ok_or(ProcError::NoSuchProcess)?;
        linux
            .mappings
            .try_reserve(1)
            .map_err(|_| ProcError::OutOfFrames)?;
        p.space
            .map(
                VirtPage::containing(mapping.va),
                destination_frame,
                current_flags,
            )
            .map_err(ProcError::Map)?;
        let rights = MemoryRights::READ
            .union(if current_flags.contains(MapFlags::WRITE) {
                MemoryRights::WRITE
            } else {
                MemoryRights::NONE
            })
            .union(if current_flags.contains(MapFlags::EXECUTE) {
                MemoryRights::EXECUTE
            } else {
                MemoryRights::NONE
            });
        if p.memory_caps
            .grant(
                mapping.va,
                1,
                rights,
                MemoryKind::Image,
                BackingIdentity::new(0, 1).expect("fixed valid generation"),
            )
            .is_err()
        {
            let _ = p.space.unmap_raw(VirtPage::containing(mapping.va));
            return Err(ProcError::MemoryQuota);
        }
        linux.mappings.push(LinuxMapping {
            va: mapping.va,
            flags: current_flags,
            file: mapping.file,
            file_offset: mapping.file_offset,
            shared_file: mapping.shared_file,
        });
        p.frames.push(Arc::clone(&page));
        Ok(())
    })
}

#[cfg(feature = "linux-abi")]
#[derive(Clone, Copy)]
enum LinuxWaitSelector {
    Any,
    Pid(u32),
    ProcessGroup(u32),
}

#[cfg(feature = "linux-abi")]
fn linux_child_exit(
    parent: ObjId,
    selector: LinuxWaitSelector,
    consume: bool,
) -> Result<Option<(u32, i32)>, ProcError> {
    let children = kobj::with(|table| match table.get(parent) {
        Ok(KObject::Process(process)) => Ok(process.children.clone()),
        _ => Err(ProcError::NoSuchProcess),
    })?;
    let mut matching = matches!(selector, LinuxWaitSelector::Any) && !children.is_empty();
    for candidate in children {
        let found = kobj::with(|table| match table.get(candidate) {
            Ok(KObject::Process(process)) => {
                let linux = process.linux.as_ref().ok_or(ProcError::NoSuchProcess)?;
                let selected = match selector {
                    LinuxWaitSelector::Any => true,
                    LinuxWaitSelector::Pid(pid) => linux.pid == pid,
                    LinuxWaitSelector::ProcessGroup(pgid) => linux.pgid == pgid,
                };
                if selected {
                    matching = true;
                }
                Ok(selected.then_some((
                    linux.pid,
                    process.state,
                    linux.termination_signal,
                )))
            }
            _ => Err(ProcError::NoSuchProcess),
        })?;
        let Some((pid, state, termination_signal)) = found else {
            continue;
        };
        let ProcState::Exited { code } = state else {
            continue;
        };
        let status = if termination_signal == 0 {
            (((code as u32) & 0xff) << 8) as i32
        } else {
            (termination_signal & 0x7f) as i32
        };
        if consume {
            let child_ticks = linux_process_cpu_ticks(candidate).unwrap_or(0);
            if !linux_account_child_cpu(parent, child_ticks) {
                return Err(ProcError::NoSuchProcess);
            }
            let _ = reap(candidate);
            let _ = release_child(parent, candidate);
            // Reclaim the child's address-space frames immediately.  Otherwise
            // a fork/wait loop can exhaust the frame allocator before the next
            // scheduler cleanup point, which is not Linux wait semantics.
            crate::kobj::run_cleanup(usize::MAX);
        }
        return Ok(Some((pid, status)));
    }
    if matching {
        Ok(None)
    } else {
        Err(ProcError::NoSuchProcess)
    }
}

/// Takes one exited Linux child's status and releases its object ownership.
#[cfg(feature = "linux-abi")]
pub(crate) fn take_linux_child_exit(
    parent: ObjId,
    target_pid: Option<u32>,
) -> Result<Option<(u32, i32)>, ProcError> {
    linux_child_exit(
        parent,
        target_pid.map_or(LinuxWaitSelector::Any, LinuxWaitSelector::Pid),
        true,
    )
}

/// Takes one exited child from a Linux process group.
#[cfg(feature = "linux-abi")]
pub(crate) fn take_linux_child_exit_group(
    parent: ObjId,
    pgid: u32,
) -> Result<Option<(u32, i32)>, ProcError> {
    linux_child_exit(parent, LinuxWaitSelector::ProcessGroup(pgid), true)
}

/// Observes one exited Linux child without accounting or releasing it.
#[cfg(feature = "linux-abi")]
pub(crate) fn peek_linux_child_exit(
    parent: ObjId,
    target_pid: Option<u32>,
) -> Result<Option<(u32, i32)>, ProcError> {
    linux_child_exit(
        parent,
        target_pid.map_or(LinuxWaitSelector::Any, LinuxWaitSelector::Pid),
        false,
    )
}

/// Observes one exited child from a Linux process group without consuming it.
#[cfg(feature = "linux-abi")]
pub(crate) fn peek_linux_child_exit_group(
    parent: ObjId,
    pgid: u32,
) -> Result<Option<(u32, i32)>, ProcError> {
    linux_child_exit(parent, LinuxWaitSelector::ProcessGroup(pgid), false)
}

#[allow(clippy::too_many_arguments)]
fn spawn_thread_mode(
    id: ObjId,
    name: &'static str,
    entry: u64,
    stack: u64,
    arg0: u64,
    arg1: u64,
    affinity: Option<kernel_core::smp::CpuSet>,
    linux_clone: bool,
    fs_base: Option<u64>,
    linux_fork_regs: Option<[u64; 6]>,
    linux_fork_args: Option<[u64; 6]>,
    linux_clear_child_tid: u64,
    clone_rdx: u64,
    clone_r8: u64,
) -> Result<(TaskId, ObjId), ProcError> {
    // 栈顶为 0 时 `stack - 1` 会下溢：用检查式算术，失败按非法地址拒绝
    let stack_last = stack
        .checked_sub(1)
        .ok_or(ProcError::Map(MapError::InvalidAddress))?;
    if !in_private_window(entry) || !in_private_window(stack_last) {
        return Err(ProcError::Map(MapError::InvalidAddress));
    }
    with_proc(id, |p| {
        if p.state == ProcState::Running {
            Ok(())
        } else {
            Err(ProcError::Exited)
        }
    })?;
    // 任务号用尽 ⇒ 拒绝（不回绕复用旧任务号）；此时尚未创建任何资源，无需回滚
    let task = TASK_IDS
        .allocate()
        .and_then(|n| n.checked_add(1000))
        .map(TaskId)
        .ok_or(ProcError::NoTaskSlot)?;
    let task_obj = kobj::with(|t| {
        let es = crate::exit_state::create_in_with_security(
            t,
            kernel_core::security::SecuritySeed::active(
                crate::security::boot_id(),
                IdentityClass::KernelObject,
            ),
        )
        .ok_or(ProcError::NoTaskSlot)?;
        match kobj::insert_for_process_in(
            t,
            id,
            KObject::Task(TaskObj {
                task,
                process: id,
                exit_state: es,
            }),
            0,
            2,
        ) {
            Ok(obj) => Ok(obj),
            Err(_) => {
                let _ = t.release_internal(es); // 回滚：退出状态随之死亡
                Err(ProcError::NoTaskSlot)
            }
        }
    })?;
    {
        let mut reg = REG.lock();
        reg.starts.push(ThreadStart {
            task,
            entry,
            stack,
            arg0,
            arg1,
            linux_clone,
            fs_base,
            linux_fork_regs,
            linux_fork_args,
            clone_rdx,
            clone_r8,
        });
        reg.members.push(Member {
            task,
            process: id,
            task_obj,
        });
    }
    let workload = with_proc(id, |p| Ok(p.workload)).ok().flatten();
    // 先完成全部记账（执行上下文 → Process、线程表 → Task），再交给调度器：
    // 否则新线程可能在记账完成前就运行并退出。
    // 先确认进程仍在运行，再取内部引用：两步在同一次对象表访问内完成，失败时不留下半份记账
    let accounted = kobj::with(|t| {
        match t.get_mut(id) {
            Ok(KObject::Process(p)) if p.state == ProcState::Running => {}
            Ok(KObject::Process(_)) => return Err(ProcError::Exited),
            _ => return Err(ProcError::NoSuchProcess),
        }
        t.acquire_internal(id)
            .map_err(|_| ProcError::NoSuchProcess)?;
        if let Ok(KObject::Process(p)) = t.get_mut(id) {
            p.threads_live += 1;
            p.threads_total += 1;
            p.threads.push(task_obj);
        }
        Ok(())
    });
    let rollback =
        |reason: ProcError,
         accounted: bool,
         charged_workload: Option<kernel_core::workload::WorkloadKey>| {
            {
                let mut reg = REG.lock();
                reg.starts.retain(|s| s.task != task);
                reg.members.retain(|m| m.task != task);
            }
            kobj::with(|t| {
                if accounted {
                    if let Ok(KObject::Process(p)) = t.get_mut(id) {
                        p.threads_live -= 1;
                        p.threads_total -= 1;
                        p.threads.retain(|x| *x != task_obj);
                    }
                    let _ = t.release_internal(id);
                }
                let _ = t.release_internal(task_obj);
                let _ = t.release_internal(task_obj);
            });
            if let Some(workload) = charged_workload {
                crate::workload::release_thread(workload);
            }
            reason
        };
    if let Err(e) = accounted {
        return Err(rollback(e, false, None));
    }
    if workload.is_some_and(|key| crate::workload::reserve_thread(key).is_err()) {
        return Err(rollback(ProcError::MemoryQuota, true, None));
    }
    #[cfg(all(feature = "linux-abi", target_arch = "x86_64"))]
    if !crate::linux_abi::register_linux_thread(id, task, linux_clear_child_tid) {
        return Err(rollback(ProcError::NoTaskSlot, true, workload));
    }
    // 新线程与进程的其它线程同属一个 CPU 组。交给调度器之后再核对一次：设置上限与创建线程并发时，
    // 两边总有一边把新线程放进组里。
    let group = with_proc(id, |p| Ok(p.cpu_group)).ok().flatten();
    let spawned = match (group, affinity) {
        (group, Some(set)) => sched::spawn_on(task, name, thread_entry, group, set),
        (Some(g), None) => sched::spawn_in(task, name, thread_entry, g),
        (None, None) => sched::spawn(task, name, thread_entry),
    };
    if spawned.is_err() {
        #[cfg(all(feature = "linux-abi", target_arch = "x86_64"))]
        crate::linux_abi::unregister_linux_thread(task);
        return Err(rollback(ProcError::NoTaskSlot, true, workload));
    }
    if let Some(g) = with_proc(id, |p| Ok(p.cpu_group)).ok().flatten() {
        let _ = sched::assign_cpu_group(task, Some(g));
    }
    kprintln!(
        "[JSR-PROC] event=system.task.spawned process={:#x} task={} task_obj={:#x} name={}",
        id.raw(),
        task.0,
        task_obj.raw(),
        name
    );
    Ok((task, task_obj))
}

/// 设置 CPU 上限失败的原因。失败时进程与调度器状态不变。
/// Why setting a process CPU limit was refused; nothing is changed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CpuLimitError {
    /// 进程不存在或已不在运行。
    NoSuchProcess,
    /// CPU authority is owned by the bound native workload.
    /// CPU 权限由绑定的原生 Workload 持有。
    ManagedByWorkload,
    /// 上限不在 `1..=1000` 千分比之内，或 CPU 组表已满。
    Refused(sched::scheduler::GroupError),
}

/// 设置进程 `pid` 的 CPU 上限（千分比，1000 = 不限）：进程的全部线程（现有的与以后创建的）合计
/// 在任意时间窗内最多运行约这个比例的 tick，超出即被限速——失控的进程拖不垮整机。
/// 由进程的创建方（管理者）调用；可重复调用以修改上限。
/// Sets the CPU limit of process `pid` (permille of the processor, shared by all its threads).
pub fn set_cpu_limit(pid: ObjId, limit_permille: u32) -> Result<(), CpuLimitError> {
    let existing = with_proc(pid, |p| {
        if p.state == ProcState::Running {
            if p.workload.is_some() {
                return Err(ProcError::Exited);
            }
            Ok(p.cpu_group)
        } else {
            Err(ProcError::Exited)
        }
    })
    .map_err(|_| {
        if with_proc(pid, |p| Ok(p.workload.is_some())).unwrap_or(false) {
            CpuLimitError::ManagedByWorkload
        } else {
            CpuLimitError::NoSuchProcess
        }
    })?;
    if let Some(g) = existing {
        return sched::set_cpu_group_limit(g, limit_permille).map_err(CpuLimitError::Refused);
    }
    let g = sched::create_cpu_group(limit_permille).map_err(CpuLimitError::Refused)?;
    let stored = with_proc(pid, |p| {
        if p.state == ProcState::Running && p.cpu_group.is_none() {
            p.cpu_group = Some(g);
            p.cpu_group_owned = true;
            Ok(())
        } else {
            Err(ProcError::Exited)
        }
    });
    if stored.is_err() {
        let _ = sched::release_cpu_group(g); // 回滚：组从未有成员，随之释放
        return Err(CpuLimitError::NoSuchProcess);
    }
    let tasks: Vec<TaskId> = REG
        .lock()
        .members
        .iter()
        .filter(|m| m.process == pid)
        .map(|m| m.task)
        .collect();
    for t in tasks {
        let _ = sched::assign_cpu_group(t, Some(g)); // 已退出的线程无需加入
    }
    Ok(())
}

/// Binds a thread-less process to one running native workload.
///
/// 将尚未创建线程的进程绑定到一个 Running 原生 Workload；成员关系和进程字段
/// 只在两侧都成功后提交。
pub fn bind_workload(pid: ObjId, workload: kernel_core::workload::WorkloadKey) -> bool {
    let Ok(cpu_group) = crate::workload::cpu_group(workload) else {
        return false;
    };
    with_proc(pid, |process| {
        if process.workload.is_some()
            || process.cpu_group.is_some()
            || process.threads_live != 0
            || !process.frames.is_empty()
            || !process.shared_maps.is_empty()
            || !process.device_maps.is_empty()
            || !process.quarantined.is_empty()
            || process.ring_quota != ResourceQuota::default()
            || process.memory_account.snapshot().mapped != 0
            || process.memory_account.snapshot().pinned != 0
            || process.vm_guest_account.snapshot().mapped != 0
            || process.subscription_account.snapshot().mapped != 0
        {
            return Err(ProcError::Exited);
        }
        crate::workload::snapshot(workload).map_err(|_| ProcError::NoSuchProcess)?;
        crate::workload::bind_member(workload, pid.raw()).map_err(|_| ProcError::NoSuchProcess)?;
        process.workload = Some(workload);
        process.workload_member = Some(pid.raw());
        process.cpu_group = Some(cpu_group);
        process.cpu_group_owned = false;
        Ok(())
    })
    .is_ok()
}

pub fn workload_key(pid: ObjId) -> Option<kernel_core::workload::WorkloadKey> {
    with_proc(pid, |process| Ok(process.workload))
        .ok()
        .flatten()
}

pub(crate) fn workload_key_in(
    table: &kobj::Table,
    pid: ObjId,
) -> Option<kernel_core::workload::WorkloadKey> {
    match table.get(pid) {
        Ok(KObject::Process(process)) => process.workload,
        _ => None,
    }
}

/// Return the kernel-issued Workload authority domain for a process.
///
/// Domains are allocated monotonically and never reused, so a stale domain
/// cannot become valid after process-object slot reuse.
pub fn workload_domain(pid: ObjId) -> Option<DomainKey> {
    with_proc(pid, |process| {
        if let Some(domain) = process.workload_domain {
            return Ok(domain);
        }
        let Some(id) = NEXT_WORKLOAD_DOMAIN
            .try_update(Ordering::AcqRel, Ordering::Acquire, |id| {
                (id != u32::MAX).then_some(id + 1)
            })
            .ok()
        else {
            return Err(ProcError::NoTaskSlot);
        };
        let domain = DomainKey {
            id,
            generation: 1,
        };
        process.workload_domain = Some(domain);
        Ok(domain)
    })
    .ok()
}

/// Opaque snapshot of one live Device handle used by a launch-plan authority.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct DeviceAuthorityTicket {
    pid: ObjId,
    handle: HandleId,
    object: ObjId,
    rights: Rights,
}

impl DeviceAuthorityTicket {
    pub(crate) fn matches(self, object: ObjId, rights: Rights) -> bool {
        self.object == object && rights.difference(self.rights).is_empty()
    }
}

/// Capture the current process's live Device-handle authority for one object.
///
/// The handle table is the sole source of device grant liveness. A caller may
/// not synthesize a DeviceGrant from an arbitrary object id or stale rights.
pub(crate) fn device_authority_ticket(
    domain: DomainKey,
    object: Option<ObjId>,
    required: Rights,
) -> Option<DeviceAuthorityTicket> {
    let pid = current_process()?;
    kobj::with(|t| {
        let KObject::Process(process) = t.get(pid).ok()? else {
            return None;
        };
        if process.workload_domain != Some(domain)
            || t.security(pid).ok()?.require_active().is_err()
        {
            return None;
        }
        for (handle, _link, rights) in process.handles.capability_records() {
            if !rights.contains(required) {
                continue;
            }
            let Ok((object_ref, _)) = process.handles.get(handle) else {
                continue;
            };
            if object_ref.ty != ObjectType::Device {
                continue;
            }
            let Some(object_id) = ObjId::from_raw(object_ref.id.0) else {
                continue;
            };
            if object.is_some_and(|expected| expected != object_id)
                || !matches!(t.get(object_id), Ok(KObject::Device(_)))
            {
                continue;
            }
            return Some(DeviceAuthorityTicket {
                pid,
                handle,
                object: object_id,
                rights,
            });
        }
        None
    })
}

/// Resolve an exact caller handle into a canonical device object identity.
///
/// User ABI records carry handles, never kernel object ids. The returned object
/// id, generation and rights snapshot are all taken from this process's live
/// handle table and belong only to the kernel-issued workload domain.
pub(crate) fn device_authority_identity(
    domain: DomainKey,
    handle: HandleId,
    required: Rights,
) -> Option<(ObjId, Rights)> {
    let pid = current_process()?;
    kobj::with(|t| {
        let KObject::Process(process) = t.get(pid).ok()? else {
            return None;
        };
        if process.workload_domain != Some(domain)
            || t.security(pid).ok()?.require_active().is_err()
        {
            return None;
        }
        let (object, rights) = process.handles.get(handle).ok()?;
        if object.ty != ObjectType::Device || !rights.contains(required) || required.is_empty() {
            return None;
        }
        let object = ObjId::from_raw(object.id.0)?;
        matches!(t.get(object), Ok(KObject::Device(_))).then_some((object, rights))
    })
}

/// Revalidate the exact handle and object generation captured earlier.
pub(crate) fn device_authority_ticket_live(
    domain: DomainKey,
    ticket: DeviceAuthorityTicket,
) -> bool {
    kobj::with(|t| {
        let KObject::Process(process) = t.get(ticket.pid).ok()? else {
            return None;
        };
        if process.workload_domain != Some(domain)
            || !matches!(t.get(ticket.object), Ok(KObject::Device(_)))
        {
            return None;
        }
        let (object, rights) = process.handles.get(ticket.handle).ok()?;
        (object.ty == ObjectType::Device
            && ObjId::from_raw(object.id.0) == Some(ticket.object)
            && rights.contains(ticket.rights))
        .then_some(())
    })
    .is_some()
}

/// 进程 `pid` 的 CPU 记账（设置过上限时有值；进程销毁后 `None`）。
pub fn cpu_stats(pid: ObjId) -> Option<sched::policy::CpuLimitStats> {
    let g = with_proc(pid, |p| Ok(p.cpu_group)).ok().flatten()?;
    sched::cpu_group_stats(g)
}

/// 当前任务所属的进程（内核任务为 `None`）。
pub fn current_process() -> Option<ObjId> {
    let (me, _) = sched::current();
    REG.lock()
        .members
        .iter()
        .find(|m| m.task == me)
        .map(|m| m.process)
}

/// Reserve or classify a USI request ID under the process object-table lock.
pub(crate) fn begin_usi_request(
    pid: ObjId,
    request_id: u64,
    service: u16,
) -> Result<UsiRequestBegin, ProcError> {
    with_proc(pid, |p| Ok(p.usi_requests.begin(request_id, service)))
}

/// Mark a successfully executed (possibly replayable read-only) request complete.
pub(crate) fn complete_usi_request(pid: ObjId, slot: usize, request_id: u64, service: u16) {
    kobj::with(|t| {
        if let Ok(KObject::Process(p)) = t.get_mut(pid) {
            p.usi_requests.complete(slot, request_id, service);
        }
    });
}

/// Remove a request reservation after a pre-response failure.
pub(crate) fn abort_usi_request(pid: ObjId, slot: usize, request_id: u64, service: u16) {
    kobj::with(|t| {
        if let Ok(KObject::Process(p)) = t.get_mut(pid) {
            p.usi_requests.abort(slot, request_id, service);
        }
    });
}

/// 取得一个**允许接收新句柄**的进程（存在且处于 Running）。
///
/// 进程进入 exited 时已经关闭并释放了整张句柄表；之后若再放入句柄，这些句柄持有的外部所有权
/// 将不再有任何路径释放（泄漏）。因此所有「向进程放入句柄」的入口都必须先经此检查，
/// 并且检查与放入发生在同一把对象表锁内（之间不存在进程退出的时间窗）。
/// Returns the process only if it may still receive handles (exists and is Running).
fn receiver<'a>(t: &'a mut kobj::Table, pid: ObjId) -> Result<&'a mut Process, ProcError> {
    match t.get_mut(pid) {
        Ok(KObject::Process(p)) if p.state == ProcState::Running => Ok(p),
        Ok(KObject::Process(_)) => Err(ProcError::Exited),
        _ => Err(ProcError::NoSuchProcess),
    }
}

/// 按对象类型登记表检查一次句柄创建：句柄类型须与对象种类一致、`TRANSFER` 只给可转移种类、
/// 权限须在该种类的合法上限之内。所有创建新句柄的路径都必须先经过这里（复制 / 降权只会让权限更小）。
/// Checks a handle creation against the object type registry (type, transferability, rights ceiling).
pub(crate) fn admit_handle(kind: Kind, ty: ObjectType, rights: Rights) -> Result<(), ProcError> {
    match check_grant(kind, ty, rights) {
        GrantCheck::Allowed => Ok(()),
        GrantCheck::WrongType => Err(ProcError::Handle(HandleError::Invalid)),
        GrantCheck::NotTransferable => Err(ProcError::NotTransferable),
        GrantCheck::RightsDenied => Err(ProcError::Handle(HandleError::RightsDenied)),
    }
}

/// [`admit_handle`] 的已存在对象版本（锁内；对象不存在 ⇒ 句柄无效）。
fn admit_existing_in(
    t: &mut kobj::Table,
    obj: ObjId,
    ty: ObjectType,
    rights: Rights,
) -> Result<(), ProcError> {
    let kind = t
        .get(obj)
        .map(|o| o.kind())
        .map_err(|_| ProcError::Handle(HandleError::Invalid))?;
    admit_handle(kind, ty, rights)
}

/// 在当前进程的句柄表中放入一个指向 Task 对象的句柄（同时增加该对象的一个外部所有权）。
pub fn put_task_handle(task_obj: ObjId, rights: Rights) -> Result<HandleId, ProcError> {
    let pid = current_process().ok_or(ProcError::NoSuchProcess)?;
    kobj::with(|t| {
        receiver(t, pid)?; // 先确认可接收，再取所有权（失败路径无需回滚）
        admit_existing_in(t, task_obj, ObjectType::Task, rights)?;
        t.acquire_owner(task_obj)
            .map_err(|_| ProcError::Handle(HandleError::Invalid))?;
        let r = receiver(t, pid).and_then(|p| {
            p.handles
                .put(
                    ObjectRef {
                        id: ObjectId(task_obj.raw()),
                        ty: ObjectType::Task,
                    },
                    rights,
                )
                .map_err(ProcError::Handle)
        });
        if r.is_err() {
            let _ = kobj::release_owner_in(t, task_obj);
        }
        r
    })
}

/// 把一个已存在的对象发放给进程：增加一份外部所有权并放进其句柄表（全有或全无）。
/// 接收进程已退出 ⇒ [`ProcError::Exited`]，对象引用计数不变。
pub fn grant(
    pid: ObjId,
    obj: ObjId,
    ty: ObjectType,
    rights: Rights,
) -> Result<HandleId, ProcError> {
    kobj::with(|t| grant_in(t, pid, obj, ty, rights))
}
pub(crate) fn grant_in(
    t: &mut kobj::Table,
    pid: ObjId,
    obj: ObjId,
    ty: ObjectType,
    rights: Rights,
) -> Result<HandleId, ProcError> {
    let room = receiver(t, pid)?.handles.free_slots();
    if room == 0 {
        return Err(ProcError::Handle(HandleError::TableFull));
    }
    admit_existing_in(t, obj, ty, rights)?;
    t.acquire_owner(obj)
        .map_err(|_| ProcError::Handle(HandleError::Invalid))?;
    // 已确认可接收且有空位：以下 put 不会失败；仍保留回滚以防御未来的修改。
    let r = receiver(t, pid).and_then(|p| {
        p.handles
            .put(
                ObjectRef {
                    id: ObjectId(obj.raw()),
                    ty,
                },
                rights,
            )
            .map_err(ProcError::Handle)
    });
    if r.is_err() {
        let _ = kobj::release_owner_in(t, obj);
    }
    r
}

/// 新建一个对象并直接发放给进程（对象的唯一外部所有权就是这个句柄）。
///
/// 「检查接收方 → 建对象 → 放句柄」在同一把锁内完成：接收方已退出或句柄表已满时**根本不创建对象**，
/// 因此失败路径上不存在需要回收的新对象。
/// Creates an object and hands it to `pid` atomically; on failure no object is created.
pub fn grant_new(
    pid: ObjId,
    obj: KObject,
    ty: ObjectType,
    rights: Rights,
) -> Result<HandleId, ProcError> {
    kobj::with(|t| grant_new_in(t, pid, obj, ty, rights).map(|(h, _)| h))
}

/// [`grant_new`] 的锁内版本：调用者已持有对象表锁（可与自己的配额检查合成一个原子步骤）。
/// 返回（新句柄, 新对象标识）。
/// In-lock variant of [`grant_new`]; returns the handle and the new object's id.
pub(crate) fn grant_new_in(
    t: &mut kobj::Table,
    pid: ObjId,
    obj: KObject,
    ty: ObjectType,
    rights: Rights,
) -> Result<(HandleId, ObjId), ProcError> {
    if receiver(t, pid)?.handles.free_slots() == 0 {
        return Err(ProcError::Handle(HandleError::TableFull));
    }
    admit_handle(obj.kind(), ty, rights)?; // 不合法则根本不创建对象
    let id = kobj::insert_for_process_in(t, pid, obj, 1, 0).map_err(|_| ProcError::NoTaskSlot)?;
    let r = receiver(t, pid).and_then(|p| {
        p.handles
            .put(
                ObjectRef {
                    id: ObjectId(id.raw()),
                    ty,
                },
                rights,
            )
            .map_err(ProcError::Handle)
    });
    match r {
        Ok(h) => Ok((h, id)),
        Err(e) => {
            let _ = kobj::release_owner_in(t, id); // 防御：对象随即死亡入队，由清理过程销毁
            Err(e)
        }
    }
}

/// 在锁内把进程 `pid` 的句柄 `h` 解析为对象标识：类型须为 `ty`，且句柄权限须包含 `need`。
/// 进程须仍在运行（已退出的进程句柄表已关闭）。
/// Resolves a handle of `pid` to an object id, checking its type and rights.
pub(crate) fn resolve_in(
    t: &mut kobj::Table,
    pid: ObjId,
    h: HandleId,
    ty: ObjectType,
    need: Rights,
) -> Result<ObjId, ProcError> {
    let p = receiver(t, pid)?;
    let (r, have) = p.handles.get(h).map_err(ProcError::Handle)?;
    if r.ty != ty {
        return Err(ProcError::Handle(HandleError::Invalid));
    }
    if !have.contains(need) {
        return Err(ProcError::Handle(HandleError::RightsDenied));
    }
    ObjId::from_raw(r.id.0).ok_or(ProcError::Handle(HandleError::Invalid))
}

/// Captured authority for an asynchronous operation. This value never leaves
/// the kernel and contains no raw handle; effects revalidate the exact live
/// capability lineage immediately before committing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct HandleAuthority {
    capability: CapabilityId,
    rights: Rights,
}

pub(crate) fn authority_in(
    t: &mut kobj::Table,
    pid: ObjId,
    h: HandleId,
    required: Rights,
) -> Result<HandleAuthority, ProcError> {
    let p = receiver(t, pid)?;
    let (_, rights) = p.handles.get(h).map_err(ProcError::Handle)?;
    if !rights.contains(required) {
        return Err(ProcError::Handle(HandleError::RightsDenied));
    }
    let link = p.handles.capability(h).map_err(ProcError::Handle)?;
    Ok(HandleAuthority {
        capability: link.id,
        rights: required,
    })
}

pub(crate) fn authority_active_in(
    t: &mut kobj::Table,
    pid: ObjId,
    authority: HandleAuthority,
) -> bool {
    match t.get(pid) {
        Ok(KObject::Process(p)) => p
            .handles
            .authority_active(authority.capability, authority.rights),
        _ => false,
    }
}

/// 在锁内读取进程 `pid` 的句柄 `h`（对象引用与权限）。进程须仍在运行。
pub(crate) fn handle_in(
    t: &mut kobj::Table,
    pid: ObjId,
    h: HandleId,
) -> Result<(ObjectRef, Rights), ProcError> {
    let p = receiver(t, pid)?;
    p.handles
        .get(h)
        .map(|(r, x)| (*r, x))
        .map_err(ProcError::Handle)
}

/// 在锁内从进程 `pid` 的句柄表移出句柄 `h`，返回其对象标识；**不释放**它持有的外部所有权
/// （所有权随句柄转给调用者，例如放进消息）。
pub(crate) fn take_handle_in(
    t: &mut kobj::Table,
    pid: ObjId,
    h: HandleId,
) -> Result<ObjId, ProcError> {
    let p = receiver(t, pid)?;
    let r = p.handles.remove(h).map_err(ProcError::Handle)?;
    // 句柄离开本进程时，它创建的设备窗口随之撤销：映射权限不得比句柄活得更久。
    revoke_device_mappings_for_handle(p, h);
    ObjId::from_raw(r.id.0).ok_or(ProcError::Handle(HandleError::Invalid))
}

/// 在锁内把一份已持有的外部所有权作为新句柄放进进程 `pid` 的句柄表（不再增加计数）。
pub(crate) fn put_handle_in(
    t: &mut kobj::Table,
    pid: ObjId,
    r: ObjectRef,
    rights: Rights,
) -> Result<HandleId, ProcError> {
    receiver(t, pid)?
        .handles
        .put(r, rights)
        .map_err(ProcError::Handle)
}

/// 在锁内查询进程 `pid` 句柄表的空位数（进程不在运行时为 0）。
pub(crate) fn free_slots_in(t: &mut kobj::Table, pid: ObjId) -> usize {
    receiver(t, pid)
        .map(|p| p.handles.free_slots())
        .unwrap_or(0)
}

/// 在锁内取进程的异步环配额记账（进程已退出也可取，用于收尾时归还；进程已销毁返回 `None`）。
pub(crate) fn ring_quota_in(t: &mut kobj::Table, pid: ObjId) -> Option<&mut ResourceQuota> {
    match t.get_mut(pid) {
        Ok(KObject::Process(p)) => Some(&mut p.ring_quota),
        _ => None,
    }
}

/// 在锁内取进程可用的系统调用集合（进程须仍在运行）。
pub(crate) fn syscalls_in(t: &mut kobj::Table, pid: ObjId) -> Result<SyscallSet, ProcError> {
    receiver(t, pid).map(|p| p.syscalls)
}

/// 进程的异步环配额记账（诊断与验收用）。
pub fn ring_quota(pid: ObjId) -> Option<ResourceQuota> {
    kobj::with(|t| ring_quota_in(t, pid).copied())
}

/// 进程 `pid` 中句柄 `h` 的（对象, 权限）；无效返回 `None`（诊断与验收用）。
pub fn handle_info(pid: ObjId, h: HandleId) -> Option<(ObjectRef, Rights)> {
    with_proc(pid, |p| {
        p.handles
            .get(h)
            .map(|(r, rights)| (*r, rights))
            .map_err(ProcError::Handle)
    })
    .ok()
}

/// SEC-2 lineage diagnostics. This does not expose a user-callable token.
pub fn capability_info(pid: ObjId, h: HandleId) -> Option<CapabilityLink> {
    with_proc(pid, |p| p.handles.capability(h).map_err(ProcError::Handle)).ok()
}

/// 进程 `pid` 的句柄表还能容纳的句柄数。
pub fn free_handle_slots(pid: ObjId) -> usize {
    with_proc(pid, |p| Ok(p.handles.free_slots())).unwrap_or(0)
}

/// 复制当前进程中的句柄，新句柄权限为 `rights`：原句柄须带 `DUPLICATE`，且 `rights` ⊆ 原权限（只可降权）。
/// 新句柄是同一对象的又一份外部所有权。
pub fn duplicate_current(h: HandleId, rights: Rights) -> Result<HandleId, ProcError> {
    let pid = current_process().ok_or(ProcError::NoSuchProcess)?;
    duplicate_for(pid, h, rights)
}

/// Explicit-process form used by in-kernel composition and acceptance. The
/// object identity and security context stay attached to the object; the new
/// handle is only another ownership reference.
pub(crate) fn duplicate_for(
    pid: ObjId,
    h: HandleId,
    rights: Rights,
) -> Result<HandleId, ProcError> {
    kobj::with(|t| duplicate_in(t, pid, h, rights))
}

fn duplicate_in(
    t: &mut kobj::Table,
    pid: ObjId,
    h: HandleId,
    rights: Rights,
) -> Result<HandleId, ProcError> {
    let (r, have, parent) = match t.get(pid) {
        Ok(KObject::Process(p)) => {
            let (r, have) = p.handles.get(h).map_err(ProcError::Handle)?;
            let parent = p.handles.capability(h).map_err(ProcError::Handle)?;
            (*r, have, parent)
        }
        _ => return Err(ProcError::NoSuchProcess),
    };
    if !have.contains(Rights::DUPLICATE) || !have.contains(rights) {
        return Err(ProcError::Handle(HandleError::RightsDenied));
    }
    let obj = ObjId::from_raw(r.id.0).ok_or(ProcError::Handle(HandleError::Invalid))?;
    receiver(t, pid)?;
    t.acquire_owner(obj)
        .map_err(|_| ProcError::Handle(HandleError::Invalid))?;
    let put = receiver(t, pid).and_then(|p| {
        p.handles
            .put_delegated(r, rights, parent.id)
            .map_err(ProcError::Handle)
    });
    if put.is_err() {
        let _ = kobj::release_owner_in(t, obj);
    }
    put
}

/// Delegate an attenuated capability into another process while retaining the
/// source. Capability IDs are globally unique, so revoking either the source or
/// the child invalidates the complete cross-process descendant closure.
pub fn delegate_to(
    from: ObjId,
    h: HandleId,
    to: ObjId,
    rights: Rights,
) -> Result<HandleId, ProcError> {
    kobj::with(|t| {
        let (r, have, parent) = match t.get(from) {
            Ok(KObject::Process(p)) => {
                let (r, have) = p.handles.get(h).map_err(ProcError::Handle)?;
                let parent = p.handles.capability(h).map_err(ProcError::Handle)?;
                (*r, have, parent)
            }
            _ => return Err(ProcError::NoSuchProcess),
        };
        if !have.contains(Rights::DUPLICATE) || !have.contains(rights) {
            return Err(ProcError::Handle(HandleError::RightsDenied));
        }
        let obj = ObjId::from_raw(r.id.0).ok_or(ProcError::Handle(HandleError::Invalid))?;
        receiver(t, to)?;
        if receiver(t, to)?.handles.free_slots() == 0 {
            return Err(ProcError::Handle(HandleError::TableFull));
        }
        t.acquire_owner(obj)
            .map_err(|_| ProcError::Handle(HandleError::Invalid))?;
        let inserted = receiver(t, to).and_then(|p| {
            p.handles
                .put_delegated_shared(r, rights, parent.id)
                .map_err(ProcError::Handle)
        });
        if inserted.is_err() {
            let _ = kobj::release_owner_in(t, obj);
        }
        inserted
    })
}

/// 原地降低当前进程中句柄的权限（只减不增）。
pub fn restrict_current(h: HandleId, rights: Rights) -> Result<(), ProcError> {
    let pid = current_process().ok_or(ProcError::NoSuchProcess)?;
    restrict_for(pid, h, rights)
}

/// Explicit-process rights decay. It changes handle rights only and cannot
/// rewrite the object's security context.
pub(crate) fn restrict_for(pid: ObjId, h: HandleId, rights: Rights) -> Result<(), ProcError> {
    with_proc(pid, |p| {
        p.handles
            .reduce_rights(h, rights)
            .map_err(ProcError::Handle)
    })
}

/// Copy the full internal application identity from one process to a freshly
/// created child. The legacy 32-bit `Process::app` projection is deliberately
/// not the source of truth because a measured stable id can exceed `u32`.
pub(crate) fn inherit_application(parent: ObjId, child: ObjId) -> Result<(), ProcError> {
    let application = kobj::with(|t| match t.get(parent) {
        Ok(KObject::Process(_)) => Ok(crate::security::process_application_in(t, parent)),
        _ => Err(ProcError::NoSuchProcess),
    })?;
    match application {
        Some(application) => set_application(child, application),
        None => Ok(()),
    }
}

/// **原子**地把进程 `from` 的句柄 `h` 移到进程 `to`（M4.0 规范 v0.6 §3.2 的转移原语；M4.4 的 send/recv 建立在它之上）。
///
/// 在同一把对象表锁内：先检查（句柄有效、带 `TRANSFER`、对象是 v1 叶子、接收方句柄表有空位），
/// 全部通过后才「从 from 移出 → 放进 to」。检查之后不存在可失败的步骤，因此失败时发送方句柄表原样不变；
/// 成功时外部所有权总数不变（从 from 的句柄转为 to 的句柄），发送方旧句柄值永久失效。
pub fn transfer(from: ObjId, h: HandleId, to: ObjId) -> Result<HandleId, ProcError> {
    kobj::with(|t| {
        let (r, rights, has_dependents) = match t.get(from) {
            Ok(KObject::Process(p)) => {
                let (r, rights) = p.handles.get(h).map_err(ProcError::Handle)?;
                (*r, rights, p.handles.has_dependents(h))
            }
            _ => return Err(ProcError::NoSuchProcess),
        };
        if !rights.contains(Rights::TRANSFER) {
            return Err(ProcError::Handle(HandleError::RightsDenied));
        }
        if !r.ty.is_transferable_v1() {
            return Err(ProcError::NotTransferable);
        }
        if has_dependents {
            return Err(ProcError::Handle(HandleError::RightsDenied));
        }
        // 接收方必须仍可接收句柄（Running），且句柄表有空位
        if receiver(t, to)?.handles.free_slots() == 0 {
            return Err(ProcError::Handle(HandleError::TableFull));
        }
        // chatgpt: distinct-process commit uses the Kani-checked real mechanism.
        if from != to {
            let (source, destination) = t
                .get_pair_mut(from, to)
                .map_err(|_| ProcError::NoSuchProcess)?;
            let (KObject::Process(source), KObject::Process(destination)) = (source, destination)
            else {
                return Err(ProcError::NoSuchProcess);
            };
            let moved = source
                .handles
                .transfer_to(h, &mut destination.handles)
                .map_err(ProcError::Handle)?;
            revoke_device_mappings_for_handle(source, h);
            return Ok(moved);
        }
        // —— 提交：以下步骤在检查通过后不会失败 ——
        if let Ok(KObject::Process(p)) = t.get_mut(from) {
            let link = p.handles.capability(h).map_err(ProcError::Handle)?;
            p.handles.remove(h).map_err(ProcError::Handle)?;
            // 转移后发送方不再持有句柄，它经该句柄建立的设备窗口一并撤销（只改页表，不会失败）。
            revoke_device_mappings_for_handle(p, h);
            match t.get_mut(to) {
                Ok(KObject::Process(p)) => p
                    .handles
                    .put_capability_link(r, rights, link)
                    .map_err(ProcError::Handle),
                _ => Err(ProcError::NoSuchProcess),
            }
        } else {
            Err(ProcError::NoSuchProcess)
        }
    })
}

/// 进程的线程计数 `(存活, 累计创建)`（诊断与回滚验收用）。
/// Live and total thread counts of a process (diagnostics).
pub fn thread_counts(pid: ObjId) -> Option<(u32, u32)> {
    kobj::with(|t| match t.get(pid) {
        Ok(KObject::Process(p)) => Some((p.threads_live, p.threads_total)),
        _ => None,
    })
}

/// 线程登记表中的条目数 `(待启动, 运行身份)`（诊断与回滚验收用）。
/// Number of entries in the thread registry (diagnostics).
pub fn registry_len() -> (usize, usize) {
    let reg = REG.lock();
    (reg.starts.len(), reg.members.len())
}

/// 让一个没有线程的进程进入 exited（关闭其句柄表）；有线程存活时不做任何事并返回 `false`。
pub fn exit_idle(pid: ObjId, code: i64) -> bool {
    let mut parent_deaths = Vec::new();
    let ok = kobj::with(|t| {
        let ok = matches!(t.get(pid), Ok(KObject::Process(p)) if p.threads_live == 0 && p.state == ProcState::Running);
        if ok {
            release_resources_in(t, pid, &mut parent_deaths);
            finish_exit_in(t, pid, code);
        }
        ok
    });
    #[cfg(all(feature = "linux-abi", target_arch = "x86_64"))]
    for (child, signal) in parent_deaths {
        crate::linux_abi::notify_parent_death(child, signal);
    }
    ok
}

#[cfg(feature = "linux-abi")]
fn linux_process_for_pid_in(t: &kobj::Table, linux_pid: u32) -> Option<ObjId> {
    let mut found = None;
    t.for_each_live(|id, object| {
        if let KObject::Process(process) = object {
            if process
                .linux
                .as_ref()
                .is_some_and(|linux| linux.pid == linux_pid)
            {
                found = Some(id);
                return false;
            }
        }
        true
    });
    found
}

#[cfg(feature = "linux-abi")]
fn nearest_subreaper_in(t: &kobj::Table, mut linux_parent: u32) -> Option<ObjId> {
    for _ in 0..64 {
        let parent = linux_process_for_pid_in(t, linux_parent)?;
        let KObject::Process(process) = t.get(parent).ok()? else {
            return None;
        };
        let linux = process.linux.as_ref()?;
        if process.state == ProcState::Running && linux.subreaper {
            return Some(parent);
        }
        linux_parent = linux.ppid;
    }
    None
}

/// 关闭进程的句柄表并释放其子进程表（exiting 或 exited 时；只做一次，之后两表为空）。返回关闭的句柄数。
fn release_resources_in(
    t: &mut kobj::Table,
    pid: ObjId,
    parent_deaths: &mut Vec<(ObjId, u32)>,
) -> usize {
    let mut closed: Vec<ObjectRef> = Vec::new();
    let mut children = Vec::new();
    #[cfg(feature = "linux-abi")]
    let mut linux_parent = 0u32;
    let n = match t.get_mut(pid) {
        Ok(KObject::Process(p)) => {
            children = core::mem::take(&mut p.children);
            let n = p.handles.close_all(|r| closed.push(r));
            // 进程进入退出流程后它的设备窗口一律撤销；BAR 不是 RAM，这里只改页表。
            revoke_all_device_mappings(p);
            #[cfg(feature = "linux-abi")]
            if let Some(linux) = p.linux.as_mut() {
                linux_parent = linux.ppid;
                let _ = linux.fds.take_all();
                linux.pipes.clear();
                linux.sockets.clear();
            }
            n
        }
        _ => 0,
    };
    #[cfg(feature = "linux-abi")]
    for child in &children {
        if let Ok(KObject::Process(process)) = t.get(*child) {
            if let Some(signal) = process
                .linux
                .as_ref()
                .map(|linux| linux.pdeathsig)
                .filter(|signal| *signal != 0)
            {
                parent_deaths.push((*child, signal));
            }
        }
    }
    #[cfg(feature = "linux-abi")]
    let mut adopted = Vec::new();
    #[cfg(feature = "linux-abi")]
    if let Some(reaper) = nearest_subreaper_in(t, linux_parent) {
        let reaper_pid = match t.get(reaper) {
            Ok(KObject::Process(process)) => process
                .linux
                .as_ref()
                .map(|linux| linux.pid)
                .unwrap_or(compat_core::syscall::LINUX_COMPAT_ROOT_PPID as u32),
            _ => compat_core::syscall::LINUX_COMPAT_ROOT_PPID as u32,
        };
        for child in &children {
            if let Ok(KObject::Process(child_process)) = t.get_mut(*child) {
                if let Some(linux) = child_process.linux.as_mut() {
                    linux.ppid = reaper_pid;
                }
            }
            if let Ok(KObject::Process(reaper_process)) = t.get_mut(reaper) {
                reaper_process.children.push(*child);
                adopted.push(*child);
            }
        }
    }
    #[cfg(feature = "linux-abi")]
    for child in &children {
        if adopted.contains(child) {
            continue;
        }
        if let Ok(KObject::Process(child_process)) = t.get_mut(*child) {
            if let Some(linux) = child_process.linux.as_mut() {
                linux.ppid = compat_core::syscall::LINUX_COMPAT_ROOT_PPID as u32;
            }
        }
        // With no live subreaper there is no process able to consume this
        // child's wait status (Jasper's compatibility root is not Linux PID 1).
        // Release the creation ownership now so the task reference alone keeps
        // a running orphan alive, and a later exit is reclaimed automatically.
        let _ = kobj::release_owner_in(t, *child);
    }
    for r in closed {
        if let Some(id) = ObjId::from_raw(r.id.0) {
            let _ = kobj::release_owner_in(t, id);
        }
    }
    for c in children {
        #[cfg(feature = "linux-abi")]
        if adopted.contains(&c) {
            continue;
        }
        let _ = t.release_internal(c);
    }
    n
}

/// 进入 exited：确定退出码、写入退出状态并通知等待者（wait 在此刻完成，而不是 exiting 时）。
fn finish_exit_in(t: &mut kobj::Table, pid: ObjId, code: i64) {
    let es = match t.get_mut(pid) {
        Ok(KObject::Process(p)) => {
            p.state = ProcState::Exited { code };
            p.exit_state
        }
        _ => return,
    };
    crate::exit_state::notify_in(t, es, code);
}

/// 发起进程终止（exiting）：确定退出码，关闭句柄表与子进程表（其后的提交原子失败）；
/// 其余线程在各自的下一个调度点停止，最后一个线程停止时进入 exited。没有线程的进程直接进入 exited。
/// 进程不在运行（已在退出）时返回 `false`。
/// 开始终止后唤醒该进程所有在睡的线程：长时间的定时等待（`time.wait`）也要尽快观察到 exiting。
/// Begins process termination (exiting phase).
pub fn begin_exit(pid: ObjId, code: i64) -> bool {
    let (started, parent_deaths) = begin_exit_in_table(pid, code);
    #[cfg(all(feature = "linux-abi", target_arch = "x86_64"))]
    for (child, signal) in parent_deaths {
        crate::linux_abi::notify_parent_death(child, signal);
    }
    if started {
        wake_threads(pid);
        #[cfg(feature = "linux-abi")]
        if let Some(task) = vfork_parent_task(pid) {
            sched::wake(task);
        }
    }
    started
}

#[cfg(feature = "linux-abi")]
fn vfork_parent_task(pid: ObjId) -> Option<TaskId> {
    with_proc(pid, |process| {
        Ok(process
            .linux
            .as_ref()
            .and_then(|linux| linux.vfork_parent)
            .map(|parent| parent.task))
    })
    .ok()
    .flatten()
}

/// 唤醒进程 `pid` 的全部睡眠线程（不在睡眠的线程不受影响）。调度器不持锁，可在登记表锁内调用。
fn wake_threads(pid: ObjId) {
    let reg = REG.lock();
    for m in reg.members.iter().filter(|m| m.process == pid) {
        sched::wake(m.task);
    }
}

/// [`begin_exit`] 的对象表部分：状态迁移、关闭句柄表、无线程时直接进入 exited。
fn begin_exit_in_table(pid: ObjId, code: i64) -> (bool, Vec<(ObjId, u32)>) {
    let mut parent_deaths = Vec::new();
    let started = kobj::with(|t| {
        let idle = match t.get_mut(pid) {
            Ok(KObject::Process(p)) if p.state == ProcState::Running => {
                p.state = ProcState::Exiting { code };
                p.threads_live == 0
            }
            _ => return false,
        };
        let n = release_resources_in(t, pid, &mut parent_deaths);
        kprintln!(
            "[JSR-PROC] event=system.process.exiting id={:#x} code={} handles_closed={}",
            pid.raw(),
            code,
            n
        );
        if idle {
            finish_exit_in(t, pid, code);
        }
        true
    });
    (started, parent_deaths)
}

/// Author: chatgpt。对象锁内等待登记的进程门槛，与begin_exit状态迁移串行。
/// 无效或非Running进程均拒绝新阻塞，不向其他模块暴露Process内部字段。
pub(crate) fn running_in(t: &kobj::Table, pid: ObjId) -> bool {
    matches!(t.get(pid), Ok(KObject::Process(p)) if p.state == ProcState::Running)
}

/// 当前线程所属进程是否处于 exiting（调度点据此停止该线程）。
pub fn current_exiting() -> bool {
    let Some(pid) = current_process() else {
        return false;
    };
    kobj::with(
        |t| matches!(t.get(pid), Ok(KObject::Process(p)) if matches!(p.state, ProcState::Exiting { .. })),
    )
}

/// 阻塞等待被进程终止打断（[`block_step`] 的错误）。
/// The blocking wait was interrupted because the owning process is exiting.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Interrupted;

/// 系统调用内阻塞等待的一步：让出处理器并休眠到下一个中断，醒来后检查所属进程是否已在 exiting。
///
/// 为什么需要它：线程停在内核里等待时不会经过「系统调用入口 / 从用户态被中断」这两个调度点，
/// 若等待循环只检查自己的完成条件，`process.exit` 或故障终止就无法让它停止，进程停留在 exiting、资源不回收。
/// 返回 [`Interrupted`] 时，调用者须**先释放本次等待持有的全部资源**（内部引用、固定、等待登记），
/// 再以错误返回；系统调用出口会随后经线程退出路径停止该线程（返回值不会到达用户态）。
/// One step of an in-kernel blocking wait that also observes process termination.
pub fn block_step() -> Result<(), Interrupted> {
    sched::pause();
    if current_exiting() {
        Err(Interrupted)
    } else {
        Ok(())
    }
}

/// 系统调用内的定时等待：睡眠到时刻 `deadline`（tick，期间不占用处理器），醒来后检查所属进程是否已在 exiting。
/// 进程开始终止时睡眠线程会被提前唤醒，因此长时间的等待也能及时以 [`Interrupted`] 返回。
/// 返回 `Ok(())` 只表示醒来且进程仍在运行，调用者须自行确认时刻已到（可能被提前唤醒）。
/// A timed in-kernel wait that also observes process termination.
pub fn block_until(deadline: u64) -> Result<(), Interrupted> {
    sched::sleep_until(deadline);
    if current_exiting() {
        Err(Interrupted)
    } else {
        Ok(())
    }
}

/// 父进程收养子进程：子进程表取得子进程的一个内部引用（父 → 子单向）。父进程须仍在运行。
pub fn adopt(parent: ObjId, child: ObjId) -> Result<(), ProcError> {
    kobj::with(|t| {
        receiver(t, parent)?;
        t.acquire_internal(child)
            .map_err(|_| ProcError::NoSuchProcess)?;
        if let Ok(KObject::Process(p)) = t.get_mut(parent) {
            p.children.push(child);
        }
        Ok(())
    })
}

/// 父进程从子进程表释放一个子进程（例如回收它之后）。不在表中返回 `false`。
pub fn release_child(parent: ObjId, child: ObjId) -> bool {
    kobj::with(|t| {
        let found = match t.get_mut(parent) {
            Ok(KObject::Process(p)) => match p.children.iter().position(|c| *c == child) {
                Some(i) => {
                    p.children.swap_remove(i);
                    true
                }
                None => false,
            },
            _ => false,
        };
        if found {
            let _ = t.release_internal(child);
        }
        found
    })
}

/// 进程句柄 / 线程句柄所指对象的退出状态（锁内）：句柄须带 WAIT。取得退出状态的一个内部引用后返回。
pub(crate) fn acquire_exit_state_in(
    t: &mut kobj::Table,
    pid: ObjId,
    h: HandleId,
    ty: ObjectType,
) -> Result<ObjId, ProcError> {
    let obj = resolve_in(t, pid, h, ty, Rights::WAIT)?;
    let es = match t.get(obj) {
        Ok(KObject::Process(p)) => p.exit_state,
        Ok(KObject::Task(task)) => task.exit_state,
        _ => return Err(ProcError::Handle(HandleError::Invalid)),
    };
    t.acquire_internal(es)
        .map_err(|_| ProcError::Handle(HandleError::Invalid))?;
    Ok(es)
}

/// 关闭当前进程中的一个句柄：移出句柄表并释放它持有的那份外部所有权（INV-01：不等于销毁对象）。
pub fn close_handle(h: HandleId) -> Result<(), ProcError> {
    let pid = current_process().ok_or(ProcError::NoSuchProcess)?;
    close_handle_for(pid, h)
}

/// Internal caller supplies an already trusted Process identity; public syscall uses current_process.
pub(crate) fn close_handle_for(pid: ObjId, h: HandleId) -> Result<(), ProcError> {
    kobj::with(|t| {
        let obj = match t.get_mut(pid) {
            // 先移出句柄：同一句柄的映射只在这一次关闭时撤销；重复关闭在 remove 处被拒，
            // 因此不会误撤销后来用同一代次句柄以外的映射。
            Ok(KObject::Process(p)) => {
                let obj = p.handles.remove(h).map_err(ProcError::Handle)?;
                revoke_device_mappings_for_handle(p, h);
                obj
            }
            _ => return Err(ProcError::NoSuchProcess),
        };
        if let Some(id) = ObjId::from_raw(obj.id.0) {
            let _ = kobj::release_owner_in(t, id);
        }
        Ok(())
    })
}

/// Revoke a capability subtree rooted at `h` and close every revoked handle in
/// that process. This is the SEC-2 authority-lifetime primitive: aliases and
/// all delegated descendants become invalid before their object ownership is
/// returned, so an old handle cannot be reconstructed through a copied slot.
pub fn revoke_current(h: HandleId) -> Result<usize, ProcError> {
    let pid = current_process().ok_or(ProcError::NoSuchProcess)?;
    revoke_for(pid, h)
}

pub(crate) fn revoke_for(pid: ObjId, h: HandleId) -> Result<usize, ProcError> {
    revoke_global_for(pid, h)
}

/// Revoke one capability subtree across every process table.
///
/// The complete closure is computed before any capability is marked revoked,
/// then each affected handle is closed under the same object-table
/// transaction. A cross-process delegate and every descendant become unusable
/// before object ownership is released.
pub(crate) fn revoke_global_for(pid: ObjId, h: HandleId) -> Result<usize, ProcError> {
    kobj::with(|t| {
        let root = match t.get(pid) {
            Ok(KObject::Process(p)) => p.handles.capability(h).map_err(ProcError::Handle)?.id,
            _ => return Err(ProcError::NoSuchProcess),
        };
        let mut processes = Vec::new();
        t.for_each_live(|id, object| {
            if matches!(object, KObject::Process(_)) {
                processes.push(id);
            }
            true
        });
        let mut records = Vec::new();
        for process in &processes {
            if let Ok(KObject::Process(p)) = t.get(*process) {
                for (handle, link, _) in p.handles.capability_records() {
                    records.push((*process, handle, link));
                }
            }
        }
        let mut revoked = Vec::new();
        revoked.push(root);
        loop {
            let mut changed = false;
            for (_, _, link) in &records {
                if link.state == kernel_core::capability::CapabilityState::Active
                    && link.parent.is_some_and(|parent| revoked.contains(&parent))
                    && !revoked.contains(&link.id)
                {
                    revoked.push(link.id);
                    changed = true;
                }
            }
            if !changed {
                break;
            }
        }

        let mut affected = 0usize;
        let mut closed = Vec::new();
        for process in processes {
            let mut revoked_handles = Vec::new();
            let Ok(KObject::Process(p)) = t.get_mut(process) else {
                continue;
            };
            let local = p.handles.revoke_ids(&revoked);
            if local == 0 {
                continue;
            }
            affected += local;
            p.handles.close_revoked_with(|handle, object| {
                revoked_handles.push(handle);
                closed.push(object);
            });
            for handle in revoked_handles {
                revoke_device_mappings_for_handle(p, handle);
            }
            kprintln!(
                "[JSR-SEC2-REVOKE] process={:#x} capabilities={} root={:#x}",
                process.raw(),
                local,
                root.raw()
            );
        }
        for object in closed {
            if let Some(id) = ObjId::from_raw(object.id.0) {
                let _ = kobj::release_owner_in(t, id);
            }
        }
        #[cfg(feature = "sec2-verify")]
        crate::sec2_notices::publish_in(t, affected).map_err(|_| ProcError::CapabilityNotice)?;
        Ok(affected)
    })
}

/// 线程退出（正常退出或故障终止的唯一出口；永不返回）：进程记账、释放执行上下文的内部引用后结束任务。
///
/// 最后一个线程停止 ⇒ 进程进入 exited：确定退出码并**关闭整张句柄表**（释放各句柄的外部所有权）。
/// 这里只做计数与入队；任何销毁动作都留给清理过程（这条路径可能处在中断上下文）。
pub fn thread_exit(code: i64, cause: &'static str) -> ! {
    let (me, _) = sched::current();
    let member = {
        let mut reg = REG.lock();
        let m = reg.members.iter().find(|m| m.task == me).copied();
        reg.starts.retain(|s| s.task != me);
        reg.members.retain(|m| m.task != me);
        m
    };
    if let Some(m) = member {
        #[cfg(all(feature = "linux-abi", target_arch = "x86_64"))]
        crate::linux_abi::linux_thread_exit(m.process, m.task);
        let mut exiting_workload = None;
        let mut parent_deaths = Vec::new();
        let exited = kobj::with(|t| {
            // 线程自己的退出状态：写入本线程的退出码
            if let Ok(KObject::Task(task)) = t.get(m.task_obj) {
                let es = task.exit_state;
                crate::exit_state::notify_in(t, es, code);
            }
            let mut out = None;
            // 已退出的线程离开进程的线程表，并释放线程表持有的那份内部引用：否则长期运行、反复开线程的进程
            // 会让每个已退出线程的 Task 与退出状态一直占着对象表，直到整个进程退出（HARDEN-1C 的长期运行用例
            // 约 510 轮复现：每轮泄漏 2 个对象，1024 槽的对象表被占满）。线程对象此后的去留只取决于还有没有句柄。
            let mut left_table = false;
            let last = match t.get_mut(m.process) {
                Ok(KObject::Process(p)) => {
                    exiting_workload = p.workload;
                    if let Some(i) = p.threads.iter().position(|x| *x == m.task_obj) {
                        p.threads.swap_remove(i);
                        left_table = true;
                    }
                    p.threads_live = p.threads_live.saturating_sub(1);
                    // exiting 中的进程以发起终止时确定的退出码结束
                    let final_code = match p.state {
                        ProcState::Exiting { code: c } => c,
                        _ => code,
                    };
                    (p.threads_live == 0).then_some((final_code, p.name, p.threads_total))
                }
                _ => None,
            };
            if let Some((final_code, name, threads)) = last {
                let n = release_resources_in(t, m.process, &mut parent_deaths);
                finish_exit_in(t, m.process, final_code);
                out = Some((name, threads, n, final_code));
            }
            if left_table {
                let _ = t.release_internal(m.task_obj); // 线程表 → Task
            }
            let _ = t.release_internal(m.task_obj); // 执行上下文 → Task
            let _ = t.release_internal(m.process); // 执行上下文 → Process
            out
        });
        #[cfg(all(feature = "linux-abi", target_arch = "x86_64"))]
        for (child, signal) in parent_deaths {
            crate::linux_abi::notify_parent_death(child, signal);
        }
        if let Some(workload) = exiting_workload {
            crate::workload::release_thread(workload);
        }
        if let Some((name, threads, handles, code)) = exited {
            kprintln!(
                "[JSR-PROC] event=system.process.exited id={:#x} name={} code={} threads={} handles_closed={}",
                m.process.raw(),
                name,
                code,
                threads,
                handles
            );
        }
    }
    kprintln!("[JSR-PROC] event=system.task.exit_switch task={} cause={}", me.0, cause);
    sched::exit_current(cause)
}

/// 进程状态（已死亡或已销毁返回 `None`）。
pub fn state(id: ObjId) -> Option<ProcState> {
    with_proc(id, |p| Ok(p.state)).ok()
}

/// Snapshot every live process for the read-only USI process service.
pub fn process_snapshot() -> Vec<kernel_core::usi::Process> {
    let mut out = Vec::new();
    kobj::with(|t| {
        t.for_each_live(|id, object| {
            let KObject::Process(process) = object else {
                return true;
            };
            let (state, exit_code) = match process.state {
                ProcState::Running => (kernel_core::usi::PROCESS_RUNNING, 0),
                ProcState::Exiting { code } => (kernel_core::usi::PROCESS_EXITING, code),
                ProcState::Exited { code } => (kernel_core::usi::PROCESS_EXITED, code),
            };
            out.push(kernel_core::usi::Process {
                pid: id.raw(),
                app: process.app,
                state,
                flags: u8::from(process.kill_on_release),
                threads_live: process.threads_live.min(u16::MAX as u32) as u16,
                threads_total: process.threads_total,
                exit_code,
            });
            true
        });
    });
    out
}

/// 创建者回收已退出的进程：读取退出信息并**释放创建者持有的外部所有权**。未退出返回 `None`。
///
/// 进程对象在全部强引用释放后才被清理过程销毁（[`destroy_object`]）；调用者需要立即回收资源时调用 `kobj::run_cleanup`。
pub fn reap(id: ObjId) -> Option<ExitInfo> {
    let info = kobj::with(|t| {
        let info = match t.get(id) {
            Ok(KObject::Process(p)) => match p.state {
                ProcState::Exited { code } => ExitInfo {
                    code,
                    threads: p.threads_total,
                    frames: p.frames.len(),
                    quarantined: p.quarantined.len(),
                },
                ProcState::Running | ProcState::Exiting { .. } => return None,
            },
            _ => return None,
        };
        kobj::release_owner_in(t, id).ok()?;
        Some(info)
    })?;
    kprintln!(
        "[JSR-PROC] event=system.process.reaped id={:#x} frames={} quarantined={} threads={} code={}",
        id.raw(),
        info.frames,
        info.quarantined,
        info.threads,
        info.code
    );
    Some(info)
}

/// 进程对象所属模块的唯一锁外销毁入口。调用者已释放对象表锁；这里解释 `Process` 载荷。
/// The Process module's sole lock-outside destroy entry.
pub(crate) fn destroy_object(object: KObject) {
    let KObject::Process(p) = object else {
        panic!("process destroy hook received another object kind");
    };
    destroy_process(p);
}

/// Task 对象所属模块的唯一锁外销毁入口：释放线程对象对退出状态的内部引用（级联）。
/// The Task module's sole lock-outside destroy entry.
pub(crate) fn destroy_task_object(object: KObject) {
    let KObject::Task(task) = object else {
        panic!("task destroy hook received another object kind");
    };
    let _ = kobj::release_internal(task.exit_state);
}

/// 进程载荷的销毁动作（只由 [`destroy_object`] 调用，不持对象表锁）：销毁地址空间、归还帧、释放线程表引用（级联）。
///
/// 正常路径上句柄表在 exited 时已被关闭；这里**不依赖该假设**：仍有残余句柄则逐个释放其外部所有权，
/// 并输出诊断标记（出现即说明某条路径漏了检查）。
fn destroy_process(p: Box<Process>) {
    let Process {
        space,
        frames,
        shared_maps,
        quarantined,
        device_maps: _,
        threads,
        mut handles,
        name,
        exit_state,
        children,
        cpu_group,
        cpu_group_owned,
        workload,
        workload_member,
        ..
    } = *p;
    if let Some(g) = cpu_group.filter(|_| cpu_group_owned) {
        let _ = sched::release_cpu_group(g); // 持有者引用；线程早已全部退出，组随之释放
    }
    if let Some(workload) = workload {
        let bytes = (frames.len() + shared_maps.len() + quarantined.len()) as u64
            * kernel_core::frame::FRAME_SIZE as u64;
        crate::workload::release_memory(workload, bytes);
        if let Some(member) = workload_member {
            let _ = crate::workload::unbind_member(workload, member);
        }
    }
    // 防御：正常路径已在 exiting / exited 时撤销；这里再撤销一次，且不触碰页帧分配器。
    // Device mappings are revoked while the process is still addressable;
    // destroy_process only receives the detached address space.
    let mut residual: Vec<ObjectRef> = Vec::new();
    let n = handles.close_all(|r| residual.push(r));
    if n > 0 {
        kprintln!("[JSR-LIFE] warning residual_handles={} process={}", n, name);
    }
    for r in residual {
        if let Some(id) = ObjId::from_raw(r.id.0) {
            let _ = kobj::release_owner(id);
        }
    }
    drop(handles);
    drop(space); // 先销毁地址空间（回收私有页表帧），再归还数据帧
    drop(shared_maps); // Process has no active threads; shared page refs outlive its page tables.
    for page in &frames {
        crate::mm::pin::mapping_released(page.frame());
    }
    drop(frames); // RAM allocation ownership is in Page; outstanding pins retain Page refs.
    if !quarantined.is_empty() {
        // 这些帧的击落从未确认；即使页表已随地址空间销毁，也绝不放回分配器。
        kprintln!(
            "[JSR-LIFE] warning quarantined_frames={} process={}",
            quarantined.len(),
            name
        );
    }
    drop(quarantined);
    for t in threads {
        let _ = kobj::release_internal(t); // 线程表 → Task；可能使 Task 死亡并入队（下一轮清理）
    }
    for c in children {
        let _ = kobj::release_internal(c); // 防御：子进程表正常应已在退出时释放
    }
    let _ = kobj::release_internal(exit_state); // 进程 → 退出状态（在飞 wait 仍可持有它）
}

/// Dedicated subscription-count/queue-slot admission. Does not share memory quota.
pub(crate) fn subscription_charge_in(
    t: &mut kobj::Table,
    pid: ObjId,
    slots: u64,
) -> Option<crate::mm::memory_quota::Charge> {
    receiver(t, pid).ok()?.subscription_account.reserve(
        1,
        slots,
        crate::subscription::PROCESS_SUBSCRIPTIONS,
        crate::subscription::PROCESS_QUEUE_SLOTS,
    )
}

pub(crate) fn subscription_quota(pid: ObjId) -> Option<kernel_core::memory_object::Usage> {
    kobj::with(|t| match t.get(pid) {
        Ok(KObject::Process(p)) => Some(p.subscription_account.snapshot()),
        _ => None,
    })
}
