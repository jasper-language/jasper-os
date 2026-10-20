//! 内核全局对象表（M4.1）：Process 与 Task 对象的生命周期记账与清理过程。
//! Kernel-wide object table: lifetime accounting and the cleanup pass for Process and Task objects.
//!
//! # 依据（M4.0 规范 v0.6）
//! * 句柄 = **外部所有权**；在飞请求、线程执行上下文、进程线程表 = **内部引用**（第 1、2 节）
//! * 两者都归零 ⇒ 对象只进入清理队列；销毁动作由 [`run_cleanup`] 在**不持对象表锁、非中断上下文**中执行（第 6.2 节）
//! * 销毁动作可以释放其他对象（例如 Process 销毁时释放线程表对 Task 的引用），被释放者入队，下一轮处理——迭代而非递归
//!
//! # 已实现的对象种类
//! 目前只有 Process、Task、Ring、Channel 端点与（演练用的）Event。规范中的叶子对象「共享内存（Memory）」**尚未实现**；
//! 地址空间属于进程内部，不作为可经句柄传递的对象，也不代替共享内存对象。
//! Implemented kinds: Process, Task, Ring, Channel endpoint, Event. The shared-memory leaf object is not implemented yet.
//!
//! # 锁
//! 对象表锁在全局锁顺序中位于「进程句柄表锁」一层（M4.0 §3.4），持锁期间只做计数与查表，以及调用方明确的页表/帧操作
//! （页帧、映射锁在顺序中更靠后）。销毁动作在释放对象表锁之后执行。
//!
//! # 容量
//! 容量在启动期决定（[`install`]，由 `bootcap` 在堆就绪后调用），不是编译期常量；安装之前任何插入都安全失败。

use alloc::boxed::Box;

use kernel_core::objtable::{InstallError, ObjError, ObjId, ObjectTable, Released, Slot};

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

/// 内核对象表的具体类型（供需要在同一把锁内操作多个对象的模块使用）。
pub type Table = ObjectTable<KObject>;

/// 内核对象。
pub enum KObject {
    /// 进程（地址空间、句柄表、帧所有权……）。
    Process(Box<Process>),
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
}

impl KObject {
    /// 类型名（日志用）。
    pub fn type_name(&self) -> &'static str {
        match self {
            KObject::Process(_) => "Process",
            KObject::Task(_) => "Task",
            KObject::Event { .. } => "Event",
            KObject::Ring(_) => "Ring",
            KObject::Endpoint(_) => "Endpoint",
            KObject::ExitState(_) => "ExitState",
        }
    }
}

static TABLE: IrqSpinLock<Table> = IrqSpinLock::ranked(crate::lockorder::OBJECT_TABLE, ObjectTable::empty());

/// 每个对象槽位占用的字节数（槽位 + 清理队列项），供启动期容量的内存预算使用。
pub const BYTES_PER_OBJECT: usize = core::mem::size_of::<Slot<KObject>>() + core::mem::size_of::<u32>();

/// 启动期安装对象表存储（容量 `capacity`，只能一次）。存储从内核堆分配后常驻。
///
/// 分配失败返回 `Err(None)`；表拒绝安装返回 `Err(Some(原因))`。两种情况下表都保持为空，调用者拒绝启动。
/// Install the object-table storage at boot (once).
pub fn install(capacity: usize) -> Result<usize, Option<InstallError>> {
    let slots = crate::bootcap::try_leak(capacity, || Slot::VACANT).ok_or(None)?;
    let pending = crate::bootcap::try_leak(capacity, || 0u32).ok_or(None)?;
    with(|t| t.install(slots, pending)).map_err(Some)
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

/// 在对象表锁内释放一个外部所有权，并执行该类型的 **closing 动作**（有效外部所有权归零、对象尚未死亡时）：
/// 有 closing 动作的类型：Ring（拒绝新提交、取消可取消的请求、丢弃未消费的完成记录）、
/// Channel 端点（销毁队列中的消息、取消在其上等待的接收、通知对端）、
/// 由用户进程创建的子进程（仍在运行则终止）。
/// 所有释放外部所有权的路径（关闭句柄、进程退出关闭句柄表、回滚）都必须经由这里，closing 才不会被漏掉。
/// Releases one external ownership and runs the type's closing action when it becomes unowned.
///
/// closing 动作在**释放最后一份外部所有权之前**执行：没有内部引用的对象在释放的同一刻就会死亡并离开对象表，
/// 之后再执行就找不到它了（队列里的消息因此泄漏、对端也收不到关闭通知）。
pub fn release_owner_in(t: &mut Table, id: ObjId) -> Result<Released, ObjError> {
    if matches!(t.counts(id), Ok((1, _, _))) {
        match t.get(id) {
            Ok(KObject::Ring(_)) => crate::ring::close_in(t, id),
            Ok(KObject::Endpoint(_)) => crate::ipc::close_in(t, id),
            Ok(KObject::Process(_)) => crate::proc::spawn::close_in(t, id),
            _ => {}
        }
    }
    t.release_owner(id)
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
        match obj {
            KObject::Process(p) => crate::proc::destroy(p),
            KObject::Ring(r) => crate::ring::destroy(r),
            KObject::Endpoint(e) => crate::ipc::destroy(e),
            KObject::Task(task) => {
                let _ = release_internal(task.exit_state); // 线程 → 退出状态
            }
            KObject::Event { .. } | KObject::ExitState(_) => {}
        }
        n += 1;
    }
    n
}
