//! 内核全局对象表（M4.1）：Process 与 Task 对象的生命周期记账与清理过程。
//! Kernel-wide object table: lifetime accounting, type-dispatched lock-outside destruction and cleanup.
//!
//! # 依据（M4.0 规范 v0.6）
//! * 句柄 = **外部所有权**；在飞请求、线程执行上下文、进程线程表 = **内部引用**（第 1、2 节）
//! * 两者都归零 ⇒ 对象只进入清理队列；销毁动作由 [`run_cleanup`] 在**不持对象表锁、非中断上下文**中执行（第 6.2 节）
//! * 销毁动作可以释放其他对象（例如 Process 销毁时释放线程表对 Task 的引用），被释放者入队，下一轮处理——迭代而非递归
//! * 最后一份外部所有权先线性化为 0，再运行类型特有 closing；closing 返回前对象仍可寻址但不可死亡或重获所有者
//! * closing 的嵌套锁路径与锁外销毁阶段由对象类型登记表声明，生产钩子表逐项核对
//!
//! # 已实现的对象种类
//! 包括 Process、Task、Ring、Channel、设备资源与页存储叶子Memory（SHM-1正在接入映射与ABI）；
//! 地址空间属于进程内部，不作为可经句柄传递的对象，也不代替共享内存对象。
//! Memory is a page-storage leaf; its user mapping and ABI integration is in progress.
//!
//! # 锁
//! 对象表锁在全局锁顺序中位于「进程句柄表锁」一层（M4.0 §3.4），持锁期间只做计数与查表，以及调用方明确的页表/帧操作
//! （页帧、映射锁在顺序中更靠后）。销毁动作在释放对象表锁之后执行。
//!
//! # 容量
//! 容量在启动期决定（[`install`]，由 `bootcap` 在堆就绪后调用），不是编译期常量；安装之前任何插入都安全失败。

use alloc::boxed::Box;

use kernel_core::kobj_type::{
    closing_locks_match, destroy_hook_matches, destroy_locks_match, ClosingLocks, Destroy, DestroyLocks,
    Kind, REGISTRY,
};
use kernel_core::objtable::{InstallError, ObjError, ObjId, ObjectTable, Released, Slot};
use kernel_core::pci::Bdf;

use crate::proc::Process;
use crate::sync::IrqSpinLock;
use crate::task::TaskId;

/// 线程对象（句柄可见）。对所属进程只有**弱回指**（带世代的对象标识，M4.0 §2.3）。
#[derive(Debug, Clone, Copy)]
pub struct TaskObj {
    /// 调度器中的任务标识。
    pub task: TaskId,
    /// 所属进程（弱回指，不计引用）。
    pub process: ObjId,
    /// 本线程的退出状态（持有一个内部引用）。
    pub exit_state: ObjId,
}

/// 设备对象（句柄可见）。只记录启动期设备表中的 BDF；设备表项本身常驻，不随句柄关闭而消失。
/// Device object: a handle to one entry of the boot-time PCI table.
#[derive(Debug, Clone, Copy)]
pub struct DeviceObj {
    /// 设备地址。
    pub bdf: Bdf,
}

/// 内核对象表的具体类型（供需要在同一把锁内操作多个对象的模块使用）。
pub type Table = ObjectTable<KObject>;

/// 内核对象。
pub enum KObject {
    EventSource(Box<crate::subscription::Source>),
    Subscription(Box<crate::subscription::Subscription>),
    /// 进程（地址空间、句柄表、帧所有权……）。
    Process(Box<Process>),
    /// Shared RAM backing leaf; mappings and pins retain page references independently.
    Memory(crate::mm::memory_object::MemoryObject),
    /// User-visible priority-inheriting mutex. Boxed so its scheduler wait key
    /// remains stable even if the object-table slot storage moves.
    Mutex(Box<crate::user_mutex::MutexObj>),
    /// User-visible absolute/relative timer with one waiter at a time.
    Timer(Box<crate::user_timer::TimerObj>),
    /// Vendor-neutral hardware-virtualization vCPU.
    Vcpu(Box<crate::vcpu::VcpuObj>),
    /// 线程。
    Task(TaskObj),
    /// 事件（叶子对象：不持有句柄、不强引用其他对象）。
    Event {
        /// 是否已触发。
        signaled: bool,
    },
    /// 异步环（进程私有；句柄不带 TRANSFER）。
    Ring(Box<crate::ring::RingObj>),
    /// Channel 端点（v1 不可传递；句柄不带 TRANSFER）。
    Endpoint(Box<crate::ipc::Endpoint>),
    /// 退出状态（强引用图最底层，无强引用出边）。
    ExitState(crate::exit_state::ExitState),
    /// 设备（叶子对象：只指向常驻的启动期设备表项，不持有句柄）。
    /// Device (leaf object referencing a permanent boot-time PCI table entry).
    Device(DeviceObj),
    /// 设备中断（MSI-X 表项到处理器向量的绑定；关闭即解绑）。
    /// Device interrupt (an MSI-X entry bound to a processor vector; unbound on close).
    Interrupt(Box<crate::interrupt::InterruptObj>),
}

impl KObject {
    /// 对象种类（与 [`kernel_core::kobj_type::REGISTRY`] 中的契约一一对应；穷举匹配，新增变体必须在此登记）。
    /// The object's kind in the type registry (exhaustive: a new variant must be registered here).
    pub const fn kind(&self) -> Kind {
        match self {
            KObject::Process(_) => Kind::Process,
            KObject::Memory(_) => Kind::Memory,
            KObject::Mutex(_) => Kind::Mutex,
            KObject::Timer(_) => Kind::Timer,
            KObject::Vcpu(_) => Kind::Vcpu,
            KObject::EventSource(_) => Kind::EventSource,
            KObject::Subscription(_) => Kind::Subscription,
            KObject::Task(_) => Kind::Task,
            KObject::Event { .. } => Kind::Event,
            KObject::Ring(_) => Kind::Ring,
            KObject::Endpoint(_) => Kind::Endpoint,
            KObject::ExitState(_) => Kind::ExitState,
            KObject::Device(_) => Kind::Device,
            KObject::Interrupt(_) => Kind::Interrupt,
        }
    }

    /// 类型名（日志用；取自登记表）。
    pub fn type_name(&self) -> &'static str {
        self.kind().contract().name
    }
}

/// closing 动作的签名：最后一份外部所有权已线性化为 0，但对象仍留在表中；只做有界操作。
type CloseHook = fn(&mut Table, ObjId);

/// closing 动作及其锁路径声明；锁路径必须与 [`REGISTRY`] 对应行逐项一致。
/// Closing action together with the exact lock path declared by the registry.
#[derive(Clone, Copy)]
struct CloseHookEntry {
    run: CloseHook,
    locks: ClosingLocks,
}

const fn close_entry(run: CloseHook, locks: ClosingLocks) -> CloseHookEntry {
    CloseHookEntry { run, locks }
}

/// 种类 → closing 动作（穷举、无兜底分支；是否有动作必须与登记表的 `closing` 一致，见下方编译期断言）。
/// Kind → closing hook; must agree with the registry's `closing` field (checked at compile time).
const fn close_hook(kind: Kind) -> Option<CloseHookEntry> {
    match kind {
        Kind::Process => Some(close_entry(
            crate::proc::spawn::close_in,
            ClosingLocks::ObjectTableThenSchedulerThenConsole,
        )),
        Kind::Ring => Some(close_entry(
            crate::ring::close_in,
            ClosingLocks::ObjectTableThenSchedulerThenConsole,
        )),
        Kind::Interrupt => Some(close_entry(
            crate::interrupt::close_in,
            ClosingLocks::ObjectTableThenDeviceIrqThenSchedulerThenConsole,
        )),
        Kind::Subscription => Some(close_entry(
            crate::subscription::close_in,
            ClosingLocks::ObjectTableThenSchedulerThenConsole,
        )),
        Kind::EventSource => Some(close_entry(
            crate::subscription::close_in,
            ClosingLocks::ObjectTableThenSchedulerThenConsole,
        )),
        Kind::Endpoint => Some(close_entry(
            crate::ipc::close_in,
            ClosingLocks::ObjectTableThenSchedulerThenConsole,
        )),
        Kind::Mutex => Some(close_entry(
            crate::user_mutex::close_in,
            ClosingLocks::ObjectTableThenScheduler,
        )),
        Kind::Timer => Some(close_entry(
            crate::user_timer::close_in,
            ClosingLocks::ObjectTableThenScheduler,
        )),
        Kind::Vcpu => Some(close_entry(crate::vcpu::close_in, ClosingLocks::ObjectTable)),
        Kind::Task | Kind::ExitState | Kind::Memory | Kind::Event | Kind::Device => None,
    }
}

/// 按种类下标排列的 closing 动作表（热路径只查表）。
const CLOSE_HOOKS: [Option<CloseHookEntry>; Kind::COUNT] = {
    let mut t: [Option<CloseHookEntry>; Kind::COUNT] = [None; Kind::COUNT];
    let mut i = 0;
    while i < Kind::COUNT {
        t[i] = close_hook(Kind::ALL[i]);
        i += 1;
    }
    t
};

/// 编译期断言：每个种类「有 closing 动作」与登记表声明一致。
const _: () = {
    let mut i = 0;
    while i < Kind::COUNT {
        let actual = match CLOSE_HOOKS[i] {
            Some(hook) => hook.locks as u8,
            None => ClosingLocks::None as u8,
        };
        assert!(
            closing_locks_match(REGISTRY[i].closing, REGISTRY[i].closing_locks)
                && actual == REGISTRY[i].closing_locks as u8,
            "close_hook 与对象类型登记表的 closing 动作或锁路径不一致"
        );
        i += 1;
    }
};

/// 销毁动作的签名：对象已离开对象表且对象表锁已释放，模块独占该对象值。
/// Destroy hook: invoked after the object leaves the table and its lock is released.
type DestroyHook = fn(KObject);

/// 种类 → 所属模块的锁外销毁入口。没有额外动作的种类为 `None`；存在性与登记表在编译期比对。
/// Kind → owning module's lock-outside destroy entry, checked against the registry at compile time.
const fn destroy_hook(kind: Kind) -> Option<DestroyHook> {
    match kind {
        Kind::Process => Some(crate::proc::destroy_object),
        Kind::Ring => Some(crate::ring::destroy_object),
        Kind::Task => Some(crate::proc::destroy_task_object),
        Kind::Endpoint => Some(crate::ipc::destroy_object),
        Kind::ExitState => Some(crate::exit_state::destroy_object),
        Kind::Interrupt
        | Kind::Subscription
        | Kind::EventSource
        | Kind::Mutex
        | Kind::Timer
        | Kind::Vcpu
        | Kind::Memory
        | Kind::Event
        | Kind::Device => None,
    }
}

/// 按种类下标排列的销毁动作表（清理过程只查表，不展开任何对象变体）。
/// Destroy hooks indexed by kind; cleanup never matches individual object variants.
const DESTROY_HOOKS: [Option<DestroyHook>; Kind::COUNT] = {
    let mut t: [Option<DestroyHook>; Kind::COUNT] = [None; Kind::COUNT];
    let mut i = 0;
    while i < Kind::COUNT {
        t[i] = destroy_hook(Kind::ALL[i]);
        i += 1;
    }
    t
};

/// 编译期断言：每个种类是否有销毁钩子与登记表声明一致，特别要求 `Destroy::None` 的槽为空。
/// Compile-time assertion that destroy hooks agree with the registry, including empty `Destroy::None` slots.
const _: () = {
    let mut i = 0;
    while i < Kind::COUNT {
        assert!(
            destroy_hook_matches(REGISTRY[i].destroy, DESTROY_HOOKS[i].is_some()),
            "destroy_hook 与对象类型登记表的 destroy 声明不一致"
        );
        i += 1;
    }
};

static TABLE: IrqSpinLock<Table> = IrqSpinLock::ranked(crate::lockorder::OBJECT_TABLE, ObjectTable::empty());

/// 对象表锁的争用测量值。
/// Contention counters of the object table lock.
pub fn lock_stats() -> crate::sync::LockStats {
    TABLE.stats()
}

/// 清零对象表锁的争用测量值。
pub fn reset_lock_stats() {
    TABLE.reset_stats();
}

/// 每个对象槽位占用的字节数（槽位 + 清理队列项），供启动期容量的内存预算使用。
pub const BYTES_PER_OBJECT: usize = core::mem::size_of::<Slot<KObject>>() + core::mem::size_of::<u32>();

/// 启动期安装对象表存储（容量 `capacity`，只能一次）。存储从内核堆分配后常驻。
///
/// 分配失败返回 `Err(None)`；表拒绝安装返回 `Err(Some(原因))`。两种情况下表都保持为空，调用者拒绝启动。
/// Install the object-table storage at boot (once).
pub fn install(capacity: usize) -> Result<usize, Option<InstallError>> {
    let slots = crate::bootcap::try_boxed(capacity, || Slot::VACANT).ok_or(None)?;
    let pending = crate::bootcap::try_boxed(capacity, || 0u32).ok_or(None)?;
    let slots = Box::into_raw(slots);
    let pending = Box::into_raw(pending);
    // SAFETY: The boxed storage is not aliased, and the table either adopts both
    // allocations on success or this function reconstructs both boxes below.
    let installed = with(|t| unsafe { t.install(&mut *slots, &mut *pending) });
    match installed {
        Ok(n) => Ok(n),
        Err(e) => {
            // SAFETY: both slices were released from their boxes immediately above
            // and have not been adopted by a successful installation.
            unsafe {
                drop(Box::from_raw(slots as *mut [Slot<KObject>]));
                drop(Box::from_raw(pending as *mut [u32]));
            }
            Err(Some(e))
        }
    }
}

/// 启动期回滚对象表：只接受仍完全为空的对象表，释放其存储并把容量恢复到 0。
///
/// 运行期对象释放继续只走既有所有权/closing 协议；本入口不处理活对象。
/// Roll back an unused boot-time object table and return its storage to the heap.
pub fn rollback_boot() -> Result<(), &'static str> {
    if capacity() == 0 {
        return Ok(());
    }
    let storage = with(|t| t.take_storage_if_vacant());
    let Some((slots, pending)) = storage else {
        return Err("object table not vacant");
    };
    // SAFETY: Vacant storage was allocated by `install` using Box and has never
    // contained a live object. The table no longer aliases either allocation.
    unsafe {
        drop(Box::from_raw(slots as *mut [Slot<KObject>]));
        drop(Box::from_raw(pending as *mut [u32]));
    }
    Ok(())
}

/// 可执行检查：遍历生产 closing / 销毁表，返回 `(锁外销毁种类数, 无销毁动作种类数)`。
///
/// 不一致时返回原因；动作存在性与登记表的锁路径都会逐项核对。
/// Executable check of production release dispatch, including exact lock-path declarations.
pub fn verify_release_dispatch() -> Result<(usize, usize), &'static str> {
    let mut outside = 0;
    let mut none = 0;
    let mut i = 0;
    while i < Kind::COUNT {
        let close_actual = match CLOSE_HOOKS[i] {
            Some(hook) => hook.locks,
            None => ClosingLocks::None,
        };
        if !closing_locks_match(REGISTRY[i].closing, REGISTRY[i].closing_locks)
            || close_actual as u8 != REGISTRY[i].closing_locks as u8
        {
            return Err("closing_lock_path_mismatch");
        }
        let declared = REGISTRY[i].destroy;
        let hook_present = DESTROY_HOOKS[i].is_some();
        if !destroy_hook_matches(declared, hook_present) {
            return Err(match declared {
                Destroy::None => "destroy_none_has_hook",
                Destroy::OutsideLock => "destroy_outside_lock_has_no_hook",
            });
        }
        if !destroy_locks_match(REGISTRY[i].destroy, REGISTRY[i].destroy_locks)
            || matches!(REGISTRY[i].destroy_locks, DestroyLocks::AfterObjectTable) != hook_present
        {
            return Err("destroy_lock_path_mismatch");
        }
        match declared {
            Destroy::None => none += 1,
            Destroy::OutsideLock => outside += 1,
        }
        i += 1;
    }
    Ok((outside, none))
}

/// 对象表容量（安装之前为 0）。
pub fn capacity() -> usize {
    with(|t| t.capacity())
}

/// 因世代用尽而永久退役的对象槽位数（长期运行审计用）。
pub fn retired_slots() -> usize {
    with(|t| t.retired_slots())
}

/// 在对象表锁内执行 `f`（只做计数、查表与有界的页表操作；不得在其中执行销毁动作）。
pub fn with<R>(f: impl FnOnce(&mut Table) -> R) -> R {
    f(&mut TABLE.lock())
}

/// 放入新对象。
pub fn insert(obj: KObject, owners: u32, internal: u32) -> Result<ObjId, ObjError> {
    with(|t| t.insert(obj, owners, internal))
}

/// 在对象表锁内释放一个外部所有权；最后一份所有权归零时执行该类型的 **closing 动作**：
/// 哪些种类有 closing 动作由对象类型登记表声明、[`close_hook`] 登记（编译期断言两者一致）：Ring（拒绝新提交、取消可取消的请求、丢弃未消费的完成记录）、
/// 设备中断（解绑硬件、以「已关闭」终态完成未完成的等待）、
/// Channel 端点（销毁队列中的消息、取消在其上等待的接收、通知对端）、
/// 由用户进程创建的子进程（仍在运行则终止）。
/// 所有释放外部所有权的路径（关闭句柄、进程退出关闭句柄表、回滚）都必须经由这里，closing 才不会被漏掉。
/// Releases one external ownership and runs the type's closing action when it becomes unowned.
///
/// 所有者计数先降到 0，随后 closing 在同一个对象表事务内运行；对象在钩子返回前保持可寻址且禁止死亡，
/// 因而钩子可以释放本对象的内部引用、顺序关闭其他对象或取消等待，而不会重入 closing 或提前离开对象表。
/// 钩子返回后才检查两种计数是否都归零；死亡仍只进入清理队列，锁外销毁仍由 [`run_cleanup`] 分派。
pub fn release_owner_in(t: &mut Table, id: ObjId) -> Result<Released, ObjError> {
    t.release_owner_with_closing(id, |t, id| {
        if let Some(hook) = t.get(id).ok().and_then(|o| CLOSE_HOOKS[o.kind().index()]) {
            (hook.run)(t, id);
        }
    })
}

/// 释放一个外部所有权（见 [`release_owner_in`]）。
pub fn release_owner(id: ObjId) -> Result<Released, ObjError> {
    with(|t| release_owner_in(t, id))
}

/// 增加一个外部所有权。
pub fn acquire_owner(id: ObjId) -> Result<(), ObjError> {
    with(|t| t.acquire_owner(id))
}

/// 释放一个内部引用。
pub fn release_internal(id: ObjId) -> Result<Released, ObjError> {
    with(|t| t.release_internal(id))
}

/// 清理队列长度（死亡、等待清理过程销毁的对象数）。
pub fn pending() -> usize {
    with(|t| t.pending())
}

/// 对象表统计：(仍在表中的对象数, 清理队列长度, 累计销毁数)。
pub fn stats() -> (usize, usize, u64) {
    with(|t| (t.live(), t.pending(), t.destroyed()))
}

/// 累计进入过清理队列的对象数（已销毁 + 仍在队列中），单调不减。
/// 前后两次读数不同 ⇒ 期间有对象死亡。
pub fn enqueued_total() -> u64 {
    with(|t| t.destroyed() + t.pending() as u64)
}

/// 清理过程：最多销毁 `limit` 个死亡对象，返回实际处理数。
///
/// 每次只在锁内取出一个死亡对象，**释放锁后**执行它的销毁动作（可能很重：销毁地址空间、归还帧、
/// 释放它持有的其他对象的引用）。被级联释放的对象入队，由本轮剩余预算或下一轮处理。
pub fn run_cleanup(limit: usize) -> usize {
    let mut n = 0;
    while n < limit {
        let Some((id, obj)) = with(|t| t.take_dead()) else {
            break;
        };
        crate::kprintln!("[JSR-LIFE] cleanup destroy type={} id={:#x}", obj.type_name(), id.raw());
        // 只按种类查表分派。Destroy::None 的槽为空，对象值在本轮直接丢弃；
        // 类型特有的销毁载荷由所属模块的单一入口解释，中心代码不展开任何对象变体。
        if let Some(hook) = DESTROY_HOOKS[obj.kind().index()] {
            hook(obj);
        }
        n += 1;
    }
    n
}
