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
    BackingIdentity, MemoryCapabilityTable, MemoryKind, MemoryRights,
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
use compat_core::fd::FdTable;
#[cfg(feature = "linux-abi")]
use compat_core::syscall::{LinuxSyscall, LinuxSyscallSet};

pub mod spawn;

/// 每个进程句柄表的容量。
pub const HANDLES_PER_PROCESS: usize = crate::config::ACTIVE.objects.handles_per_process;
const USI_REQUEST_SLOTS: usize = 16;
#[cfg(feature = "linux-abi")]
static LINUX_PID_NEXT: AtomicU32 = AtomicU32::new(1);
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

/// Compatibility-only process state installed by the optional Linux service.
///
/// 可选 Linux 服务安装的进程兼容状态。原生 Jasper 进程不携带 fd 表、
/// Linux pid 或 Linux syscall 权限位。
#[derive(Clone)]
#[cfg(feature = "linux-abi")]
struct LinuxProcessState {
    calls: LinuxSyscallSet,
    fds: FdTable<64>,
    pid: u32,
    ppid: u32,
    /// Authorized directory view used for relative AT_FDCWD resolution.
    cwd: crate::linux_vfs::DirectoryId,
    brk: u64,
    mmap_next: u64,
    /// Linux process-wide signal dispositions.
    signal_actions: [[u64; 4]; 64],
    /// Exact executable path exposed through `/proc/self/exe`.
    exec_path: [u8; 128],
    exec_path_len: usize,
    mappings: Vec<LinuxMapping>,
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
}

#[cfg(feature = "linux-abi")]
#[derive(Clone)]
struct LinuxPipeHandle {
    handle: u64,
    endpoint: Arc<compat_core::PipeEndpoint>,
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
    name: SpinLock<([u8; 256], usize)>,
    pages: SpinLock<Vec<Arc<crate::mm::memory_object::Page>>>,
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
    NoMemory,
    NotAshmem,
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
    memory_caps: MemoryCapabilityTable<{ kernel_core::memory_capability::MAX_MEMORY_CAPABILITIES }>,
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
    memory_caps: MemoryCapabilityTable<{ kernel_core::memory_capability::MAX_MEMORY_CAPABILITIES }>,
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
        if linux.pipes.len() >= 32 {
            return Err(ProcError::NoTaskSlot);
        }
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
            let (
                handle,
                pending_pipe,
                pending_ashmem,
                pending_binder,
                pending_ion_device,
                pending_socket,
            ) = match resource {
                LinuxFdResource::Generic => {
                    (description.entry.handle, None, None, None, false, None)
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
fn release_unreferenced_pipe(linux: &mut LinuxProcessState, handle: u64) {
    if handle >= LINUX_PIPE_HANDLE_BASE && linux.fds.handle_fd_count(handle) == 0 {
        linux.pipes.retain(|pipe| pipe.handle != handle);
    }
    if handle >= LINUX_SOCKET_HANDLE_BASE && linux.fds.handle_fd_count(handle) == 0 {
        linux.sockets.retain(|socket| socket.handle != handle);
    }
    if handle >= LINUX_ASHMEM_HANDLE_BASE && linux.fds.handle_fd_count(handle) == 0 {
        linux.ashmem.retain(|ashmem| ashmem.handle != handle);
    }
    if handle >= LINUX_BINDER_HANDLE_BASE && linux.fds.handle_fd_count(handle) == 0 {
        linux.binder.retain(|binder| binder.handle != handle);
    }
    if handle >= LINUX_ION_DEVICE_HANDLE_BASE && linux.fds.handle_fd_count(handle) == 0 {
        linux.ion_devices.retain(|device| *device != handle);
    }
}

/// Opens one anonymous ashmem buffer descriptor.
#[cfg(feature = "linux-abi")]
pub(crate) fn linux_open_ashmem(pid: ObjId, close_on_exec: bool) -> Option<u32> {
    linux_open_ashmem_kind(pid, close_on_exec, false)
}

/// Creates one anonymous regular-file descriptor backed by the same bounded
/// shared-page mechanism used by ashmem.
#[cfg(feature = "linux-abi")]
pub(crate) fn linux_create_memfd(pid: ObjId, close_on_exec: bool) -> Option<u32> {
    linux_open_ashmem_kind(pid, close_on_exec, true)
}

#[cfg(feature = "linux-abi")]
fn linux_open_ashmem_kind(
    pid: ObjId,
    close_on_exec: bool,
    regular_file: bool,
) -> Option<u32> {
    with_proc(pid, |p| {
        let linux = p.linux.as_mut().ok_or(ProcError::Exited)?;
        if linux.ashmem.len() >= 32 {
            return Err(ProcError::NoTaskSlot);
        }
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

/// Opens one bounded Android binder device descriptor.
#[cfg(feature = "linux-abi")]
pub(crate) fn linux_open_binder(pid: ObjId, close_on_exec: bool) -> Option<u32> {
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
        linux.next_binder_handle = next;
        linux.binder.push(Arc::new(LinuxBinderHandle {
            handle,
            max_threads: AtomicU32::new(0),
        }));
        Ok(fd.fd())
    })
    .ok()
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
    const MAX_BYTES: u64 = 16 * 1024 * 1024;
    if size == 0
        || size > MAX_BYTES
        || alignment > PAGE
        || heap_mask & 1 == 0
        || flags & !3 != 0
    {
        return Err(LinuxAshmemError::Invalid);
    }
    with_proc(pid, |p| {
        let linux = p.linux.as_mut().ok_or(ProcError::Exited)?;
        let linux_pid = linux.pid;
        if linux.ion_allocations.len() >= 32 {
            return Err(ProcError::NoTaskSlot);
        }
        linux
            .ion_allocations
            .try_reserve(1)
            .map_err(|_| ProcError::NoTaskSlot)?;
        let user_handle = linux
            .next_ion_user_handle
            .checked_add(1)
            .ok_or(ProcError::NoTaskSlot)?;
        let current = linux.next_ion_user_handle;
        let pages_count = size.div_ceil(PAGE);
        let mut charge = p
            .memory_account
            .reserve(
                pages_count,
                0,
                p.memory_owned_limit,
                p.memory_pin_limit,
            )
            .ok_or(ProcError::MemoryQuota)?;
        let mut pages = Vec::new();
        pages
            .try_reserve_exact(pages_count as usize)
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

/// Resizes one empty ashmem buffer and commits its zeroed page backing
/// all-or-nothing.
#[cfg(feature = "linux-abi")]
pub(crate) fn linux_ashmem_set_size(
    pid: ObjId,
    handle: u64,
    size: u64,
) -> Result<(), LinuxAshmemError> {
    const PAGE: u64 = kernel_core::frame::FRAME_SIZE;
    const MAX_BYTES: u64 = 16 * 1024 * 1024;
    if size == 0 || size > MAX_BYTES {
        return Err(LinuxAshmemError::Invalid);
    }
    let pages_count = size.div_ceil(PAGE);
    with_proc(pid, |p| {
        let linux = p.linux.as_mut().ok_or(ProcError::Exited)?;
        let buffer = linux
            .ashmem
            .iter()
            .find(|ashmem| ashmem.handle == handle)
            .map(|ashmem| Arc::clone(&ashmem.buffer))
            .ok_or(ProcError::NoTaskSlot)?;
        if buffer.size.load(Ordering::Acquire) != 0 {
            return Err(ProcError::NoTaskSlot);
        }
        let mut charge = p
            .memory_account
            .reserve(
                pages_count,
                0,
                p.memory_owned_limit,
                p.memory_pin_limit,
            )
            .ok_or(ProcError::MemoryQuota)?;
        let mut pages = Vec::new();
        pages
            .try_reserve_exact(pages_count as usize)
            .map_err(|_| ProcError::OutOfFrames)?;
        for _ in 0..pages_count {
            let page_charge = charge.take_page().ok_or(ProcError::OutOfFrames)?;
            pages.push(
                crate::mm::memory_object::Page::zeroed(page_charge)
                    .ok_or(ProcError::OutOfFrames)?,
            );
        }
        *buffer.pages.lock() = pages;
        buffer.size.store(size, Ordering::Release);
        Ok(())
    })
    .map_err(|_| LinuxAshmemError::NoMemory)
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
            });
        }
        p.space.end_shootdown();
        Ok(())
    })
    .map_err(|_| LinuxAshmemError::NoMemory)
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
        linux.fds.close_fd(fd).map_err(|_| ProcError::NoTaskSlot)?;
        if let Some(handle) = handle {
            release_unreferenced_pipe(linux, handle);
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
    let mut fds = FdTable::new();
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
        cwd: crate::linux_vfs::DirectoryId::Root,
        brk: crate::arch::USER_WINDOW.0 + 0x1000_0000,
        mmap_next: crate::arch::USER_WINDOW.0 + 0x4000_0000,
        signal_actions: [[0; 4]; 64],
        exec_path: [0; 128],
        exec_path_len: 0,
        mappings: Vec::new(),
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
    let space = VmSpace::new().map_err(ProcError::Map)?;
    let memory_account = crate::mm::memory_quota::Account::new().ok_or(ProcError::OutOfFrames)?;
    crate::mm::space::activate_kernel();
    kobj::with(|t| match t.get_mut(pid) {
        Ok(KObject::Process(p))
            if p.state == ProcState::Running && p.threads_live == 1 && p.linux.is_some() =>
        {
            revoke_all_device_mappings(p);
            let linux = p.linux.as_mut().expect("checked Linux process");
            let _ = linux.fds.take_close_on_exec();
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
            linux.mappings.clear();
            linux.brk = crate::arch::USER_WINDOW.0 + 0x1000_0000;
            linux.mmap_next = crate::arch::USER_WINDOW.0 + 0x4000_0000;
            linux.signal_actions = [[0; 4]; 64];
            linux.exec_path.fill(0);
            linux.exec_path_len = 0;
            Ok(ExecAddressSpace {
                space: core::mem::replace(&mut p.space, space),
                frames: core::mem::take(&mut p.frames),
                shared_maps: core::mem::take(&mut p.shared_maps),
                memory_caps: core::mem::replace(&mut p.memory_caps, MemoryCapabilityTable::new()),
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
        memory_caps: MemoryCapabilityTable::new(),
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
        "[JSR-PROC] event=system.process.created id={:#x} name={}",
        id.raw(),
        name
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
            linux.mappings.push(LinuxMapping { va, flags });
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
/// 单个设备 BAR 映射最多涉及的页数（4 MiB；QEMU 的 virtio BAR 远小于此）。
/// Upper bound on pages in one device BAR mapping (4 MiB).
pub const MAX_DEVICE_MAP_PAGES: u64 = 1024;

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
                source: BackingIdentity::new(id.raw(), id.generation())
                    .expect("live object has a valid generation"),
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
                BackingIdentity::new(id.raw(), id.generation())
                    .expect("live object has a valid generation"),
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
/// 非零且不超过 [`MAX_DEVICE_MAP_PAGES`] 页。同一进程内同一物理 BAR 范围只允许一个映射（重复请求
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
    if pages == 0 || pages > MAX_DEVICE_MAP_PAGES || phys.checked_add(size).is_none() {
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
        if !p.memory_caps.can_grant(va, pages, MemoryKind::DeviceMmio) {
            return Err(MemError::Quota);
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
    checked_range(va, pages)?;
    let mut flags = MapFlags::USER;
    if writable {
        flags = flags.union(MapFlags::WRITE);
    }
    if executable {
        flags = flags.union(MapFlags::EXECUTE);
    }
    let mut touched: Vec<PhysFrame> = Vec::new();
    if touched.try_reserve_exact(pages as usize).is_err() {
        return Err(MemError::OutOfMemory);
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
            match p.space.translate(VirtPage::containing(va + i * FRAME_SIZE)) {
                Some((f, _)) => touched.push(f),
                None => return Err(MemError::NotMapped),
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
                touched.sort_unstable_by_key(|f| f.start());
                for page in &p.frames {
                    if touched
                        .binary_search_by_key(&page.frame().start(), |g| g.start())
                        .is_ok()
                    {
                        page.quarantine();
                    }
                }
                p.frames.retain(|f| {
                    touched
                        .binary_search_by_key(&f.frame().start(), |g| g.start())
                        .is_err()
                });
                p.quarantine(touched);
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
            crate::arch::x86_64::enter_syscall_return(
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
    let (parent_linux_pid, calls, state, mappings) = kobj::with(|t| match t.get(parent) {
        Ok(KObject::Process(p)) if p.state == ProcState::Running => {
            let linux = p.linux.as_ref().ok_or(ProcError::NoSuchProcess)?;
            if !p.shared_maps.is_empty() || !p.device_maps.is_empty() || !p.quarantined.is_empty() {
                return Err(ProcError::NotTransferable);
            }
            let mappings = linux
                .mappings
                .iter()
                .copied()
                .filter(|mapping| mapping.flags.contains(MapFlags::USER))
                .collect::<Vec<_>>();
            Ok((linux.pid, linux.calls, linux.clone(), mappings))
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
        linux.mappings.clear();
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
/// 由调用者休眠等待。共享映射、设备映射和隔离帧不在当前有界切片内，失败关闭。
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
    let (parent_linux_pid, calls, state, parent_root, frames, memory_caps) =
        kobj::with(|t| match t.get(parent) {
            Ok(KObject::Process(p)) if p.state == ProcState::Running && p.threads_live == 1 => {
                let linux = p.linux.as_ref().ok_or(ProcError::NoSuchProcess)?;
                if !p.shared_maps.is_empty()
                    || !p.device_maps.is_empty()
                    || !p.quarantined.is_empty()
                {
                    return Err(ProcError::NotTransferable);
                }
                let mut frames = Vec::new();
                frames
                    .try_reserve(p.frames.len())
                    .map_err(|_| ProcError::OutOfFrames)?;
                frames.extend(p.frames.iter().cloned());
                Ok((
                    linux.pid,
                    linux.calls,
                    linux.clone(),
                    p.space.root(),
                    frames,
                    p.memory_caps.clone(),
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
        linux.vfork_parent = Some(VforkParent {
            task: parent_task,
            exec_committed: false,
        });
        p.frames = frames;
        p.memory_caps = memory_caps;
        let borrowed = crate::mm::space::VmSpace::borrowed(parent_root).map_err(ProcError::Map)?;
        let old = core::mem::replace(&mut p.space, borrowed);
        drop(old);
        Ok(())
    });
    if prepared.is_err() || inherit_application(parent, child).is_err() {
        rollback(child, false);
        return Err(ProcError::NoSuchProcess);
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
        });
        p.frames.push(Arc::clone(&page));
        Ok(())
    })
}

/// Takes one exited Linux child's status and releases its object ownership.
/// 取得一个已退出 Linux 子进程的状态，并释放父进程和创建者持有的引用。
#[cfg(feature = "linux-abi")]
pub(crate) fn take_linux_child_exit(
    parent: ObjId,
    target_pid: Option<u32>,
) -> Result<Option<(u32, i32)>, ProcError> {
    let child = kobj::with(|t| match t.get(parent) {
        Ok(KObject::Process(p)) => Ok(p.children.clone()),
        _ => Err(ProcError::NoSuchProcess),
    })?;
    let mut matching = target_pid.is_none() && !child.is_empty();
    for candidate in child {
        let found = kobj::with(|t| match t.get(candidate) {
            Ok(KObject::Process(p)) => {
                let linux = p.linux.as_ref().ok_or(ProcError::NoSuchProcess)?;
                if target_pid.is_some_and(|target| linux.pid != target) {
                    return Ok(None);
                }
                matching = true;
                Ok(Some((linux.pid, p.state)))
            }
            _ => Err(ProcError::NoSuchProcess),
        })?;
        let Some((pid, state)) = found else {
            continue;
        };
        let ProcState::Exited { code } = state else {
            return Ok(None);
        };
        let status = (((code as u32) & 0xff) << 8) as i32;
        let _ = reap(candidate);
        let _ = release_child(parent, candidate);
        return Ok(Some((pid, status)));
    }
    if matching {
        Ok(None)
    } else {
        Err(ProcError::NoSuchProcess)
    }
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
    kobj::with(|t| {
        let ok = matches!(t.get(pid), Ok(KObject::Process(p)) if p.threads_live == 0 && p.state == ProcState::Running);
        if ok {
            release_resources_in(t, pid);
            finish_exit_in(t, pid, code);
        }
        ok
    })
}

/// 关闭进程的句柄表并释放其子进程表（exiting 或 exited 时；只做一次，之后两表为空）。返回关闭的句柄数。
fn release_resources_in(t: &mut kobj::Table, pid: ObjId) -> usize {
    let mut closed: Vec<ObjectRef> = Vec::new();
    let mut children = Vec::new();
    let n = match t.get_mut(pid) {
        Ok(KObject::Process(p)) => {
            children = core::mem::take(&mut p.children);
            let n = p.handles.close_all(|r| closed.push(r));
            // 进程进入退出流程后它的设备窗口一律撤销；BAR 不是 RAM，这里只改页表。
            revoke_all_device_mappings(p);
            #[cfg(feature = "linux-abi")]
            if let Some(linux) = p.linux.as_mut() {
                let _ = linux.fds.take_all();
                linux.pipes.clear();
                linux.sockets.clear();
            }
            n
        }
        _ => 0,
    };
    for r in closed {
        if let Some(id) = ObjId::from_raw(r.id.0) {
            let _ = kobj::release_owner_in(t, id);
        }
    }
    for c in children {
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
    let started = begin_exit_in_table(pid, code);
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
fn begin_exit_in_table(pid: ObjId, code: i64) -> bool {
    kobj::with(|t| {
        let idle = match t.get_mut(pid) {
            Ok(KObject::Process(p)) if p.state == ProcState::Running => {
                p.state = ProcState::Exiting { code };
                p.threads_live == 0
            }
            _ => return false,
        };
        let n = release_resources_in(t, pid);
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
    })
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
                let n = release_resources_in(t, m.process);
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
