//! 用户态异步环（`system.async.ring.*`、`system.async.cancel`）：把 `kernel_core::async_ring` 的
//! 请求状态机接到对象表、进程配额、系统调用与具体后端上。
//! User-mode asynchronous rings: binds the request state machine to kernel objects, quotas, syscalls and backends.
//!
//! # 模型
//! * Ring 是对象表中的一个对象（[`RingObj`]），**进程私有**：句柄不带 `TRANSFER`，对所属进程只有弱回指。
//! * 用户经 `enter` 一次「提交一批记录 → 推进后端 → 收取完成记录」；完成队列是唯一的等待对象（没有就绪通知）。
//! * 请求的裁决、完成信用、发布与销毁全部由状态机负责；本模块只负责：
//!   提交时的检查与预留（操作是否支持、调用者是否被授予该操作、每进程在飞配额）、后端执行、配额归还、Ring 的保活与收尾。
//!
//! # 后端（Strategy）
//! | 操作 | 后端 | 可中止 | 说明 |
//! |---|---|---|---|
//! | `system.time.now` | `Backend::Now` | 否（瞬时） | 提交即执行完毕，结果为当前时钟 tick |
//! | `system.time.wait` | `Backend::Wait` | 是 | 到达截止 tick 后自然结束（结果 0）；可被取消 |
//! | `system.channel.send` | 提交时执行 | 否（瞬时） | 两阶段发送，提交时即裁决终态（见 `crate::ipc`） |
//! | `system.channel.recv` | `Backend::Recv` | 是 | 缓冲区在提交时固定；消息到达时原子交付；可被取消 |
//! | `system.device.interrupt.wait` | `Backend::InterruptWait` | 是 | 只能经 ring 提交；已有到达即刻完成，否则等下一次到达；结果为交付的到达次数 |
//! | （内核自检） | `Backend::Manual` | 由调用者指定 | 进展完全由内核调用者报告，可固定一段用户内存，用于验证收尾与固定 |
//!
//! 访问用户缓冲区的请求（recv、带固定的人工后端）遵守「后端静止之后才发布完成」；它们持有的资源
//! （固定的页帧、对端点的内部引用）随后端一起在请求结束时释放（`retire_in`）。
//!
//! # 保活与收尾
//! * 只要还有尚未销毁的请求控制块，Ring 就持有**自身的一个内部引用**——请求的收尾不依赖用户句柄：
//!   句柄全部关闭（或进程退出）后 Ring 进入 closing，内部引用保证它活到最后一个控制块销毁，然后才交给清理过程。
//! * closing 动作由 [`crate::kobj::release_owner_in`] 在外部所有权归零时调用（[`close_in`]）：拒绝新提交、
//!   取消可取消的请求、丢弃未消费的完成记录；不可中止的请求继续到自然结束。
//!
//! # 锁
//! 全部记账在对象表锁内完成（单 CPU；对象表锁在全局锁顺序中处于句柄表一层，之后只会取页帧/映射等更低层的锁）。
//! `enter` 等待完成时**不持锁**地让出处理器并休眠到下一个中断（[`sched::pause`]），每轮重新解析句柄（期间句柄可能已被关闭）。

use alloc::boxed::Box;
use alloc::vec;
use alloc::vec::Vec;

use kernel_core::async_ring::{AsyncRing, CancelError, Cancelled, Exec, SubmitError, Submission, Terminal};
use kernel_core::object::{HandleId, ObjectType, Rights};
use kernel_core::objtable::ObjId;
use kernel_core::ring_abi::{Cqe, EnterArgs, MsgDesc, Sqe, CQE_SIZE, ENTER_ARGS_SIZE, SQE_SIZE};

use crate::ipc::{self, Delivery, RecvTarget};
use crate::kobj::{self, KObject, Table};
use crate::mm::pin::PinnedRange;
use crate::mm::user::{copy_from_user, copy_to_user, UserPtrError};
use crate::proc::{self, ProcError};
use crate::syscall::table::*;
use crate::syscall::{err, SyscallSet};
use crate::sched;
use crate::config;

/// 完成队列容量 C 的上限（取自配置档；创建时可指定 1..=C）。
pub const CQ_CAPACITY: usize = config::ACTIVE.ring.cq_capacity;
/// 每个 Ring 的请求控制块容量。
pub const BLOCKS_PER_RING: usize = config::ACTIVE.ring.blocks_per_ring;
/// 单次 `enter` 最多带入的提交数。
pub const SQ_BATCH: usize = config::ACTIVE.ring.sq_batch;
/// 每进程 Ring 数上限。
pub const MAX_RINGS_PER_PROCESS: u32 = config::ACTIVE.ring.max_rings_per_process;
/// 每进程跨所有 Ring 的在飞请求（尚未销毁的控制块）上限。
pub const MAX_IN_FLIGHT_PER_PROCESS: u32 = config::ACTIVE.ring.max_in_flight_per_process;
/// Ring 句柄的权限：提交（WRITE）、收取（WAIT）、取消（CONTROL）、进程内复制（DUPLICATE）；**永不带 TRANSFER**。
pub const RING_RIGHTS: Rights = Rights::WRITE.union(Rights::WAIT).union(Rights::CONTROL).union(Rights::DUPLICATE);

type StateMachine = AsyncRing<CQ_CAPACITY, BLOCKS_PER_RING>;

/// 正在执行的请求的后端状态（瞬时完成的操作不进入这里）。
enum Backend {
    /// 等到时钟到达 `deadline`（可中止）。
    Wait {
        /// 截止 tick。
        deadline: u64,
    },
    /// 接收消息（可中止）：持有端点的内部引用与固定的缓冲区。
    Recv(Box<RecvTarget>),
    /// 内核自检用：进展由调用者报告；可固定一段用户内存。
    Manual {
        /// 固定的用户内存（模拟访问缓冲区的请求）。
        pins: Option<PinnedRange>,
    },
    /// 等待进程 / 线程退出（可中止）：持有目标退出状态的一个内部引用。
    ExitWait {
        /// 目标的退出状态。
        es: ObjId,
    },
    /// 等待设备中断（可中止）：持有中断对象的一个内部引用。
    InterruptWait {
        /// 中断对象。
        irq: ObjId,
    },
}

/// 一次提交要做的工作（提交时的可信快照；用户内存已在此之前复制或固定）。
pub(crate) enum Work {
    /// `system.time.now`。
    Now,
    /// `system.time.wait`：等待 `ticks` 个 tick。
    Wait {
        /// 等待时长。
        ticks: u64,
    },
    /// `system.channel.send`：阶段 A 已完成（消息体与句柄值已复制）。
    Send {
        /// 发送所用的端点句柄。
        endpoint: HandleId,
        /// 消息体。
        body: Vec<u8>,
        /// 要随消息移动的句柄值。
        handles: Vec<u64>,
    },
    /// `system.channel.recv`：目标已建立（缓冲区已固定、端点内部引用已取得）。
    Recv(Box<RecvTarget>),
    /// `system.task.wait` / `system.process.wait`：已取得目标退出状态的内部引用。
    ExitWait {
        /// 目标的退出状态。
        es: ObjId,
    },
    /// `system.device.interrupt.wait`：已取得中断对象的内部引用。
    InterruptWait {
        /// 中断对象。
        irq: ObjId,
    },
    /// 内核自检：人工后端；`start = None` 停留在排队状态。
    Manual {
        /// 开始执行时的可中止性。
        start: Option<Exec>,
        /// 固定的用户内存。
        pins: Option<PinnedRange>,
    },
}

/// 异步环对象。
pub struct RingObj {
    /// 所属进程（弱回指：只用于配额记账，不计引用）。
    owner: ObjId,
    sm: StateMachine,
    /// 正在执行的请求及其后端（请求静止后移除）。
    running: Vec<(u64, Backend)>,
    /// 是否持有「自身的内部引用」（有未销毁的控制块时持有）。
    pinned: bool,
}

/// Ring 的可观测状态（诊断与验收用）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RingView {
    /// 可用完成信用。
    pub credits: usize,
    /// 已预留未发布的信用数。
    pub reserved: usize,
    /// 已发布未消费的完成记录数。
    pub ready: usize,
    /// 尚未销毁的控制块数。
    pub in_flight: usize,
    /// 已裁决但尚未发布的请求数。
    pub decided_unpublished: usize,
    /// 是否已 closing。
    pub closing: bool,
}

impl RingObj {
    fn view(&self) -> RingView {
        RingView {
            credits: self.sm.credits(),
            reserved: self.sm.reserved(),
            ready: self.sm.ready(),
            in_flight: self.sm.in_flight(),
            decided_unpublished: self.sm.decided_unpublished(),
            closing: self.sm.is_closing(),
        }
    }

    fn take_running(&mut self, id: u64) -> Option<Backend> {
        let i = self.running.iter().position(|(rid, _)| *rid == id)?;
        Some(self.running.swap_remove(i).1)
    }

    /// 推进到期的等待后端：截止 tick 已到 ⇒ 自然结束并静止。
    fn poll(&mut self, now: u64) {
        let mut i = 0;
        while i < self.running.len() {
            match self.running[i] {
                (id, Backend::Wait { deadline }) if now >= deadline => {
                    self.running.swap_remove(i);
                    let _ = self.sm.finish(id, 0);
                }
                _ => i += 1,
            }
        }
    }
}

fn ring_mut(t: &mut Table, id: ObjId) -> Option<&mut RingObj> {
    match t.get_mut(id) {
        Ok(KObject::Ring(r)) => Some(r),
        _ => None,
    }
}

/// 释放一个已结束请求的后端资源（锁内）：recv 撤销等待登记并释放端点引用；固定随之解除。
fn retire_in(t: &mut Table, ring: ObjId, req: u64, b: Backend) {
    match b {
        Backend::Recv(target) => ipc::release_target_in(t, *target, Some((ring, req))),
        Backend::Manual { pins } => drop(pins),
        Backend::ExitWait { es } => {
            crate::exit_state::remove_waiter_in(t, es, (ring, req));
            let _ = t.release_internal(es);
        }
        Backend::InterruptWait { irq } => {
            crate::interrupt::cancel_wait_in(t, irq, (ring, req));
            let _ = t.release_internal(irq);
        }
        Backend::Wait { .. } => {}
    }
}

/// 收尾记账（每次改动状态机之后调用）：推进到期后端 → 归还已销毁控制块占用的在飞配额 →
/// 维持「有控制块 ⇔ 持有自身内部引用」。最后一个控制块销毁且 Ring 已无外部所有者时，Ring 随之死亡并入清理队列。
fn settle_in(t: &mut Table, id: ObjId) {
    // 先把等待中的设备中断的新到达并入（可能完成其中的请求）；没有中断等待时不分配
    let Some(r) = ring_mut(t, id) else { return };
    if r.running.iter().any(|(_, b)| matches!(b, Backend::InterruptWait { .. })) {
        let irqs: Vec<ObjId> = r
            .running
            .iter()
            .filter_map(|(_, b)| match b {
                Backend::InterruptWait { irq } => Some(*irq),
                _ => None,
            })
            .collect();
        for irq in irqs {
            crate::interrupt::sync_in(t, irq);
        }
    }
    let Some(r) = ring_mut(t, id) else { return };
    r.poll(sched::timer_ticks());
    let mut reclaimed = 0u32;
    while r.sm.take_reclaimed().is_some() {
        reclaimed += 1;
    }
    let owner = r.owner;
    let busy = r.sm.in_flight() > 0;
    let change = match (busy, r.pinned) {
        (true, false) => Some(true),
        (false, true) => Some(false),
        _ => None,
    };
    if let Some(p) = change {
        r.pinned = p;
    }
    if reclaimed > 0 {
        if let Some(q) = proc::ring_quota_in(t, owner) {
            q.in_flight = q.in_flight.saturating_sub(reclaimed);
        }
    }
    match change {
        Some(true) => {
            let _ = t.acquire_internal(id);
        }
        Some(false) => {
            let _ = t.release_internal(id);
        }
        None => {}
    }
}

/// 中止一个已被裁决为取消的执行中请求（锁内）：可立即停止的后端（等待、接收）释放资源并静止；
/// 人工后端放回原处，由调用者报告静止。
fn abort_in(t: &mut Table, ring: ObjId, req: u64) {
    let Some(r) = ring_mut(t, ring) else { return };
    match r.take_running(req) {
        Some(Backend::Manual { pins }) => r.running.push((req, Backend::Manual { pins })),
        Some(b) => {
            retire_in(t, ring, req, b);
            if let Some(r) = ring_mut(t, ring) {
                let _ = r.sm.quiesce(req);
            }
        }
        None => {}
    }
}

/// closing 动作（外部所有权归零时由对象表调用）：拒绝新提交、丢弃未消费的完成记录、
/// 排队中与可中止的请求裁决为取消；可立即停止的后端直接静止；不可中止的请求继续执行到自然结束。
pub fn close_in(t: &mut Table, id: ObjId) {
    let Some(r) = ring_mut(t, id) else { return };
    let mut aborted: Vec<u64> = Vec::new();
    r.sm.close(|_, req| aborted.push(req));
    for req in aborted {
        abort_in(t, id, req);
    }
    let n = ring_mut(t, id).map(|r| r.sm.in_flight()).unwrap_or(0);
    crate::kprintln!("[JSR-RING] event=system.async.ring.closing ring={:#x} in_flight={}", id.raw(), n);
    settle_in(t, id);
}

/// 内核强制取消一个请求（锁内；例如它等待的端点被关闭）：未裁决 ⇒ 裁决为取消并中止后端。
pub(crate) fn kernel_cancel_in(t: &mut Table, ring: ObjId, req: u64) {
    let Some(r) = ring_mut(t, ring) else { return };
    if let Ok(Cancelled::AbortBackend { .. }) = r.sm.cancel(req) {
        abort_in(t, ring, req);
    }
    settle_in(t, ring);
}

/// 端点上有消息到达或对端关闭时，为一个等待者尝试交付（锁内）。返回 `false` = 仍需等待（未改变任何状态）。
pub(crate) fn deliver_waiter_in(t: &mut Table, ring: ObjId, req: u64) -> bool {
    let Some(r) = ring_mut(t, ring) else { return true };
    if r.sm.decision(req) != Some(None) {
        return true; // 已被取消或已结束：陈旧登记，丢弃
    }
    let Some(Backend::Recv(target)) = r.take_running(req) else { return true };
    match ipc::try_deliver_in(t, &target) {
        Delivery::Empty => {
            if let Some(r) = ring_mut(t, ring) {
                r.running.push((req, Backend::Recv(target)));
            }
            false
        }
        Delivery::Done(v) => {
            if let Some(r) = ring_mut(t, ring) {
                let _ = r.sm.finish(req, v);
            }
            retire_in(t, ring, req, Backend::Recv(target));
            settle_in(t, ring);
            true
        }
    }
}

/// 销毁动作（清理过程调用，不持对象表锁）：归还所属进程的 Ring 配额。
pub fn destroy(r: Box<RingObj>) {
    kobj::with(|t| {
        if let Some(q) = proc::ring_quota_in(t, r.owner) {
            q.rings = q.rings.saturating_sub(1);
        }
    });
}

/// 进程层错误 → 返回值。
fn perr(e: ProcError) -> i64 {
    crate::syscall::proc_err(e)
}

/// 用户指针错误 → 返回值。
pub(crate) fn user_err(e: UserPtrError) -> i64 {
    match e {
        UserPtrError::TooLong => err(SYSTEM_ERROR_INVALID_ARGUMENT),
        UserPtrError::InvalidAddress | UserPtrError::NotUserTask => err(SYSTEM_MEMORY_ERROR_INVALID_ADDRESS),
    }
}

fn submit_err(e: SubmitError) -> i64 {
    err(match e {
        SubmitError::CqFull => SYSTEM_ASYNC_ERROR_CQ_FULL,
        SubmitError::IdExhausted => SYSTEM_ASYNC_ERROR_ID_EXHAUSTED,
        SubmitError::QuotaExceeded => SYSTEM_ERROR_QUOTA_EXCEEDED,
        SubmitError::Closing => SYSTEM_HANDLE_ERROR_INVALID,
    })
}

fn cancel_err(e: CancelError) -> i64 {
    err(match e {
        CancelError::AlreadyCompleted => SYSTEM_ASYNC_ERROR_ALREADY_COMPLETED,
        CancelError::NotFound => SYSTEM_ASYNC_ERROR_NOT_FOUND,
        CancelError::InProgress => SYSTEM_ASYNC_ERROR_IN_PROGRESS,
    })
}

/// 终态 → 完成记录中的结果值。
fn result_of(t: Terminal) -> i64 {
    match t {
        Terminal::Done(v) => v,
        Terminal::Cancelled => err(SYSTEM_ASYNC_ERROR_CANCELLED),
    }
}

// ———————————————————————— 创建 ————————————————————————

/// 为进程 `pid` 创建容量为 `capacity` 的 Ring，返回句柄。全有或全无：容量非法、Ring 数超额、
/// 句柄表已满或进程已退出时不创建对象、不改配额。
pub fn create_for(pid: ObjId, capacity: u64) -> Result<HandleId, i64> {
    if capacity == 0 || capacity > CQ_CAPACITY as u64 {
        return Err(err(SYSTEM_ERROR_INVALID_ARGUMENT));
    }
    let sm = StateMachine::new(capacity as usize).ok_or(err(SYSTEM_ERROR_INVALID_ARGUMENT))?;
    let obj = KObject::Ring(Box::new(RingObj { owner: pid, sm, running: Vec::new(), pinned: false }));
    kobj::with(|t| {
        proc::syscalls_in(t, pid).map_err(perr)?;
        if proc::ring_quota_in(t, pid).and_then(|q|
            kernel_core::quota::reserve_u32(q.rings, 1, MAX_RINGS_PER_PROCESS)).is_none() {
            return Err(err(SYSTEM_ERROR_QUOTA_EXCEEDED));
        }
        let (h, id) = proc::grant_new_in(t, pid, obj, ObjectType::Ring, RING_RIGHTS).map_err(perr)?;
        if let Some(q) = proc::ring_quota_in(t, pid) {
            q.rings += 1;
        }
        crate::kprintln!("[JSR-RING] event=system.async.ring.created ring={:#x} capacity={}", id.raw(), capacity);
        Ok(h)
    })
}

/// `system.async.ring.create(capacity)`：返回 Ring 句柄（权限见 [`RING_RIGHTS`]）。
pub fn sys_create(capacity: u64) -> i64 {
    let Some(pid) = proc::current_process() else {
        return err(SYSTEM_ERROR_RIGHTS_DENIED);
    };
    match create_for(pid, capacity) {
        Ok(h) => h.raw() as i64,
        Err(e) => e,
    }
}

// ———————————————————————— 提交 ————————————————————————

/// 检查一条提交记录的标志、操作是否可经 ring 提交、调用者是否被授予该操作。
fn check_sqe(sqe: &Sqe, allowed: SyscallSet) -> Result<(), i64> {
    if sqe.flags != 0 {
        return Err(err(SYSTEM_ERROR_INVALID_ARGUMENT));
    }
    if !matches!(
        sqe.op,
        SYSTEM_TIME_NOW
            | SYSTEM_TIME_WAIT
            | SYSTEM_CHANNEL_SEND
            | SYSTEM_CHANNEL_RECV
            | SYSTEM_TASK_WAIT
            | SYSTEM_PROCESS_WAIT
            | SYSTEM_DEVICE_INTERRUPT_WAIT
    ) {
        return Err(err(SYSTEM_ERROR_UNSUPPORTED));
    }
    if !allowed.contains(sqe.op as u64) {
        return Err(err(SYSTEM_ERROR_RIGHTS_DENIED));
    }
    Ok(())
}

/// 在锁内提交一个请求（INV-11：检查、配额预留、信用预留原子成功或原子失败）并启动其后端。
/// 提交被拒时，工作已持有的资源（recv 的固定与端点引用）全部释放。
fn submit_in(t: &mut Table, pid: ObjId, ring: ObjId, op: u32, user_tag: u64, work: Work) -> Result<u64, i64> {
    let reject = |t: &mut Table, work: Work, e: i64| {
        release_work_in(t, work);
        Err(e)
    };
    let quota = match proc::ring_quota_in(t, pid) {
        Some(q) => q.in_flight,
        None => return reject(t, work, err(SYSTEM_ERROR_RIGHTS_DENIED)),
    };
    if kernel_core::quota::reserve_u32(quota, 1, MAX_IN_FLIGHT_PER_PROCESS).is_none() {
        return reject(t, work, err(SYSTEM_ERROR_QUOTA_EXCEEDED));
    }
    let deadline = match work {
        Work::Wait { ticks } => match sched::timer_ticks().checked_add(ticks) {
            Some(d) => d,
            None => return reject(t, work, err(SYSTEM_ERROR_INVALID_ARGUMENT)),
        },
        _ => 0,
    };
    // 中断等待：忙或已关闭在建立控制块之前拒绝（与上面的检查同在一把锁内，提交因此原子成功或原子失败）
    if let Work::InterruptWait { irq } = work {
        if let Err(e) = crate::interrupt::check_wait_in(t, irq) {
            return reject(t, work, e);
        }
    }
    let uses_buffer = matches!(work, Work::Recv(_) | Work::Manual { pins: Some(_), .. });
    let Some(r) = ring_mut(t, ring) else { return reject(t, work, err(SYSTEM_HANDLE_ERROR_INVALID)) };
    let id = match r.sm.submit(Submission { op, user_tag, context: 0, uses_buffer }) {
        Ok(id) => id,
        Err(e) => return reject(t, work, submit_err(e)),
    };
    // 以下步骤不会失败：控制块已建立，信用已预留
    match work {
        Work::Now => {
            let _ = r.sm.start(id, Exec::NonAbortable);
            let _ = r.sm.finish(id, sched::timer_ticks() as i64);
        }
        Work::Wait { .. } => {
            let _ = r.sm.start(id, Exec::Abortable);
            r.running.push((id, Backend::Wait { deadline }));
        }
        Work::Send { endpoint, body, handles } => {
            let _ = r.sm.start(id, Exec::NonAbortable);
            let v = ipc::send_in(t, pid, endpoint, body, &handles);
            if let Some(r) = ring_mut(t, ring) {
                let _ = r.sm.finish(id, v);
            }
        }
        Work::Recv(target) => {
            let _ = r.sm.start(id, Exec::Abortable);
            match ipc::try_deliver_in(t, &target) {
                Delivery::Empty => {
                    ipc::add_waiter_in(t, &target, ring, id);
                    if let Some(r) = ring_mut(t, ring) {
                        r.running.push((id, Backend::Recv(target)));
                    }
                }
                Delivery::Done(v) => {
                    if let Some(r) = ring_mut(t, ring) {
                        let _ = r.sm.finish(id, v);
                    }
                    retire_in(t, ring, id, Backend::Recv(target));
                }
            }
        }
        Work::ExitWait { es } => {
            let _ = r.sm.start(id, Exec::Abortable);
            match crate::exit_state::code_in(t, es) {
                Some(code) => {
                    // 目标已退出：立即完成（INV-13）
                    if let Some(r) = ring_mut(t, ring) {
                        let _ = r.sm.finish(id, crate::exit_state::report(code));
                    }
                    retire_in(t, ring, id, Backend::ExitWait { es });
                }
                None => {
                    crate::exit_state::add_waiter_in(t, es, (ring, id));
                    if let Some(r) = ring_mut(t, ring) {
                        r.running.push((id, Backend::ExitWait { es }));
                    }
                }
            }
        }
        Work::InterruptWait { irq } => {
            let _ = r.sm.start(id, Exec::Abortable);
            match crate::interrupt::submit_wait_in(t, irq, (ring, id)) {
                Ok(None) => {
                    if let Some(r) = ring_mut(t, ring) {
                        r.running.push((id, Backend::InterruptWait { irq }));
                    }
                }
                // 已有到达：立即完成；预检之后不会被拒，防御性地把错误作为结果
                Ok(Some(v)) | Err(v) => {
                    if let Some(r) = ring_mut(t, ring) {
                        let _ = r.sm.finish(id, v);
                    }
                    retire_in(t, ring, id, Backend::InterruptWait { irq });
                }
            }
        }
        Work::Manual { start, pins } => {
            if let Some(exec) = start {
                let _ = r.sm.start(id, exec);
            }
            r.running.push((id, Backend::Manual { pins }));
        }
    }
    if let Some(q) = proc::ring_quota_in(t, pid) {
        q.in_flight += 1;
    }
    settle_in(t, ring);
    Ok(id)
}

/// 释放一项未被接受的工作已持有的资源（锁内）。
fn release_work_in(t: &mut Table, work: Work) {
    match work {
        Work::Recv(target) => ipc::release_target_in(t, *target, None),
        Work::ExitWait { es } | Work::InterruptWait { irq: es } => {
            let _ = t.release_internal(es);
        }
        _ => {}
    }
}

/// 等待的目标到达时为一个请求完成（锁内；由退出状态的通知或中断对象的到达调用）。请求已被取消或已结束则什么也不做。
pub(crate) fn complete_waiter_in(t: &mut Table, ring: ObjId, req: u64, value: i64) {
    let Some(r) = ring_mut(t, ring) else { return };
    if r.sm.decision(req) != Some(None) {
        return;
    }
    let Some(b) = r.take_running(req) else { return };
    let _ = r.sm.finish(req, value);
    retire_in(t, ring, req, b);
    settle_in(t, ring);
}

/// 以进程 `pid` 的身份经 Ring 句柄 `h` 提交一项工作（内核侧入口；用户态入口见 [`sys_enter`]）。
pub(crate) fn submit_work_for(pid: ObjId, h: HandleId, op: u32, user_tag: u64, work: Work) -> Result<u64, i64> {
    kobj::with(|t| {
        let ring = match proc::resolve_in(t, pid, h, ObjectType::Ring, Rights::WRITE) {
            Ok(r) => r,
            Err(e) => {
                release_work_in(t, work);
                return Err(perr(e));
            }
        };
        submit_in(t, pid, ring, op, user_tag, work)
    })
}

/// 以进程 `pid` 的身份经句柄 `h` 提交一条 `system.time.*` 记录（内核自检用；与 `enter` 的单条提交路径相同）。
pub fn submit_for(pid: ObjId, h: HandleId, sqe: &Sqe) -> Result<u64, i64> {
    let allowed = kobj::with(|t| proc::syscalls_in(t, pid)).map_err(perr)?;
    check_sqe(sqe, allowed)?;
    let work = match sqe.op {
        SYSTEM_TIME_NOW => Work::Now,
        SYSTEM_TIME_WAIT => Work::Wait { ticks: sqe.arg0 },
        _ => return Err(err(SYSTEM_ERROR_UNSUPPORTED)),
    };
    submit_work_for(pid, h, sqe.op, sqe.user_tag, work)
}

/// 内核自检：以进程 `pid` 的身份经 Ring `h` 提交 recv（`desc` 是已写入进程内存 `desc_ptr` 处的描述）。
pub fn submit_recv_for(pid: ObjId, h: HandleId, endpoint: HandleId, desc_ptr: u64, desc: &MsgDesc) -> Result<u64, i64> {
    let target = kobj::with(|t| ipc::prepare_recv_in(t, pid, endpoint, desc_ptr, desc))?;
    submit_work_for(pid, h, SYSTEM_CHANNEL_RECV, 0, Work::Recv(Box::new(target)))
}

/// 以进程 `pid` 的身份经 Ring `h` 提交对 `target`（进程或线程句柄，须带 WAIT）的 wait。
pub fn submit_wait_for(pid: ObjId, h: HandleId, target: HandleId, ty: ObjectType) -> Result<u64, i64> {
    let es = kobj::with(|t| proc::acquire_exit_state_in(t, pid, target, ty)).map_err(perr)?;
    let op = if ty == ObjectType::Task { SYSTEM_TASK_WAIT } else { SYSTEM_PROCESS_WAIT };
    submit_work_for(pid, h, op, 0, Work::ExitWait { es })
}

/// `system.task.wait(h)` / `system.process.wait(h)` 的同步形式：阻塞到目标退出，返回退出码（32 位无符号）。
pub fn sys_wait(h: u64, ty: ObjectType) -> i64 {
    let Some(pid) = proc::current_process() else { return err(SYSTEM_ERROR_RIGHTS_DENIED) };
    let es = match kobj::with(|t| proc::acquire_exit_state_in(t, pid, crate::syscall::handle_arg(h), ty)) {
        Ok(es) => es,
        Err(e) => return perr(e),
    };
    loop {
        if let Some(code) = kobj::with(|t| crate::exit_state::code_in(t, es)) {
            kobj::with(|t| {
                let _ = t.release_internal(es);
            });
            return crate::exit_state::report(code);
        }
        // 进程终止打断等待：先释放对退出状态的引用再返回
        if proc::block_step().is_err() {
            kobj::with(|t| {
                let _ = t.release_internal(es);
            });
            return err(SYSTEM_ASYNC_ERROR_CANCELLED);
        }
    }
}

/// 内核自检：以进程 `pid` 的身份经 Ring `h` 提交 send（消息体与句柄值由内核给出，相当于阶段 A 已完成）。
pub fn submit_send_for(pid: ObjId, h: HandleId, endpoint: HandleId, body: Vec<u8>, handles: Vec<u64>) -> Result<u64, i64> {
    submit_work_for(pid, h, SYSTEM_CHANNEL_SEND, 0, Work::Send { endpoint, body, handles })
}

/// 内核自检：提交一个人工后端请求；`start = None` 时请求停留在排队状态，否则以给定可中止性开始执行。
/// `pin = Some((va, len))` 时固定进程的一段内存，模拟访问用户缓冲区的请求（完成须等后端静止才发布）。
pub fn submit_manual(pid: ObjId, h: HandleId, user_tag: u64, start: Option<Exec>, pin: Option<(u64, usize)>) -> Result<u64, i64> {
    let pins = match pin {
        Some((va, len)) => Some(kobj::with(|t| proc::pin_user_in(t, pid, va, len, true)).map_err(perr)?),
        None => None,
    };
    submit_work_for(pid, h, 0, user_tag, Work::Manual { start, pins })
}

/// 内核自检：人工后端自然结束（结果 `value`）。
pub fn manual_finish(ring: ObjId, req: u64, value: i64) -> bool {
    kobj::with(|t| {
        let Some(r) = ring_mut(t, ring) else { return false };
        let b = r.take_running(req);
        let ok = r.sm.finish(req, value).is_ok();
        if let Some(b) = b {
            retire_in(t, ring, req, b);
        }
        settle_in(t, ring);
        ok
    })
}

/// 内核自检：人工后端在被要求中止后报告静止。
pub fn manual_quiesce(ring: ObjId, req: u64) -> bool {
    kobj::with(|t| {
        let Some(r) = ring_mut(t, ring) else { return false };
        let b = r.take_running(req);
        let ok = r.sm.quiesce(req).is_ok();
        if let Some(b) = b {
            retire_in(t, ring, req, b);
        }
        settle_in(t, ring);
        ok
    })
}

// ———————————————————————— 取消 ————————————————————————

/// 以进程 `pid` 的身份同步取消请求（不占完成信用）。成功返回 0。
pub fn cancel_for(pid: ObjId, h: HandleId, req: u64) -> i64 {
    kobj::with(|t| {
        let ring = match proc::resolve_in(t, pid, h, ObjectType::Ring, Rights::CONTROL) {
            Ok(r) => r,
            Err(e) => return perr(e),
        };
        let Some(r) = ring_mut(t, ring) else { return err(SYSTEM_HANDLE_ERROR_INVALID) };
        r.poll(sched::timer_ticks()); // 先推进到期后端：已自然结束的请求应得到 already_completed
        let ret = match r.sm.cancel(req) {
            Ok(Cancelled::NotStarted) => 0,
            Ok(Cancelled::AbortBackend { .. }) => {
                abort_in(t, ring, req);
                0
            }
            Err(e) => cancel_err(e),
        };
        settle_in(t, ring);
        ret
    })
}

/// `system.async.cancel(ring, request_id)`。
pub fn sys_cancel(h: u64, req: u64) -> i64 {
    let Some(pid) = proc::current_process() else {
        return err(SYSTEM_ERROR_RIGHTS_DENIED);
    };
    cancel_for(pid, crate::syscall::handle_arg(h), req)
}

// ———————————————————————— enter ————————————————————————

/// 为一条用户提交记录准备工作：send 完成阶段 A（复制消息体与句柄值）；recv 复制描述并固定缓冲区。
fn prepare_user_work(pid: ObjId, sqe: &Sqe, allowed: SyscallSet) -> Result<Work, i64> {
    check_sqe(sqe, allowed)?;
    Ok(match sqe.op {
        SYSTEM_TIME_NOW => Work::Now,
        SYSTEM_TIME_WAIT => Work::Wait { ticks: sqe.arg0 },
        SYSTEM_CHANNEL_SEND => {
            let (body, handles) = ipc::copy_send_args(sqe.arg1)?;
            Work::Send { endpoint: crate::syscall::handle_arg(sqe.arg0), body, handles }
        }
        SYSTEM_DEVICE_INTERRUPT_WAIT => {
            let irq = kobj::with(|t| crate::interrupt::prepare_wait_in(t, pid, crate::syscall::handle_arg(sqe.arg0)))?;
            Work::InterruptWait { irq }
        }
        SYSTEM_TASK_WAIT | SYSTEM_PROCESS_WAIT => {
            let ty = if sqe.op == SYSTEM_TASK_WAIT { ObjectType::Task } else { ObjectType::Process };
            let es = kobj::with(|t| proc::acquire_exit_state_in(t, pid, crate::syscall::handle_arg(sqe.arg0), ty)).map_err(perr)?;
            Work::ExitWait { es }
        }
        _ => {
            let d = ipc::copy_desc(sqe.arg1)?;
            let target = kobj::with(|t| ipc::prepare_recv_in(t, pid, crate::syscall::handle_arg(sqe.arg0), sqe.arg1, &d))?;
            Work::Recv(Box::new(target))
        }
    })
}

/// `system.async.ring.enter(ring, args)`：按顺序提交 `sq_count` 条记录（遇到第一条被拒即停止并记下其错误；
/// 被接受者的请求 ID 写回 `id_ptr` 数组）→
/// 等到至少 `wait_min` 条完成可收取（无法再满足时提前返回）→ 收取至多 `cq_max` 条。成功返回 0。
///
/// 收取是「复制成功才消费」：完成记录先复制到用户缓冲区，复制成功后才归还信用，复制失败不丢记录。
pub fn sys_enter(h: u64, args_ptr: u64) -> i64 {
    let Some(pid) = proc::current_process() else {
        return err(SYSTEM_ERROR_RIGHTS_DENIED);
    };
    let h = crate::syscall::handle_arg(h);
    let mut raw = [0u8; ENTER_ARGS_SIZE];
    if let Err(e) = copy_from_user(&mut raw, args_ptr, ENTER_ARGS_SIZE) {
        return user_err(e);
    }
    let args = EnterArgs::decode(&raw);
    if args.reserved != 0 || args.sq_count as usize > SQ_BATCH || args.cq_max as usize > CQ_CAPACITY {
        return err(SYSTEM_ERROR_INVALID_ARGUMENT);
    }
    // 输出字段先清零：同时确认参数块可写（之后的提交不会因为无法回写结果而「做了却不报告」）
    let (out_off, out_len) = EnterArgs::OUTPUT_RANGE;
    if let Err(e) = copy_to_user(args_ptr + out_off as u64, &[0u8; 16][..out_len], out_len) {
        return user_err(e);
    }
    let mut sq = vec![0u8; args.sq_count as usize * SQE_SIZE];
    if let Err(e) = copy_from_user(&mut sq, args.sq_ptr, SQ_BATCH * SQE_SIZE) {
        return user_err(e);
    }
    // 请求 ID 输出数组同样先确认可写（被接受的提交一定能把 ID 交回用户，用户才能取消它）
    let mut ids = vec![0u8; args.sq_count as usize * 8];
    if args.id_ptr != 0 {
        if let Err(e) = copy_to_user(args.id_ptr, &ids, SQ_BATCH * 8) {
            return user_err(e);
        }
    }
    let allowed = match kobj::with(|t| proc::syscalls_in(t, pid)) {
        Ok(a) => a,
        Err(e) => return perr(e),
    };
    if let Err(e) = kobj::with(|t| proc::resolve_in(t, pid, h, ObjectType::Ring, Rights::WRITE.union(Rights::WAIT))) {
        return perr(e);
    }

    // 1. 提交：逐条准备（复制 / 固定，可失败）后在锁内提交；遇到第一条被拒即停止
    let mut submitted = 0u32;
    let mut first_error = 0i64;
    for chunk in sq.chunks_exact(SQE_SIZE) {
        let mut b = [0u8; SQE_SIZE];
        b.copy_from_slice(chunk);
        let sqe = Sqe::decode(&b);
        let r = prepare_user_work(pid, &sqe, allowed).and_then(|w| submit_work_for(pid, h, sqe.op, sqe.user_tag, w));
        match r {
            Ok(id) => {
                ids[submitted as usize * 8..submitted as usize * 8 + 8].copy_from_slice(&id.to_le_bytes());
                submitted += 1;
            }
            Err(e) => {
                first_error = e;
                break;
            }
        }
    }
    if args.id_ptr != 0 && submitted > 0 {
        if let Err(e) = copy_to_user(args.id_ptr, &ids[..submitted as usize * 8], SQ_BATCH * 8) {
            return user_err(e);
        }
    }

    // 2. 等待：不持锁地让出处理器，每轮重新解析句柄
    loop {
        let state = kobj::with(|t| {
            let ring = proc::resolve_in(t, pid, h, ObjectType::Ring, Rights::WAIT).ok()?;
            settle_in(t, ring);
            ring_mut(t, ring).map(|r| r.view())
        });
        match state {
            Some(v) if v.ready < args.wait_min as usize && v.reserved > 0 && !v.closing => {
                // 进程终止打断等待：本循环不持有资源，直接返回（Ring 随句柄表关闭进入 closing）
                if proc::block_step().is_err() {
                    return err(SYSTEM_ASYNC_ERROR_CANCELLED);
                }
            }
            _ => break,
        }
    }

    // 3. 收取：复制成功才消费
    let mut reaped = 0u32;
    let res = kobj::with(|t| {
        let ring = proc::resolve_in(t, pid, h, ObjectType::Ring, Rights::WAIT).map_err(perr)?;
        let r = ring_mut(t, ring).ok_or(err(SYSTEM_HANDLE_ERROR_INVALID))?;
        let n = (args.cq_max as usize).min(r.sm.ready());
        if n > 0 {
            let mut out = vec![0u8; n * CQE_SIZE];
            for i in 0..n {
                let c = r.sm.peek(i).ok_or(err(SYSTEM_ERROR_INVALID_ARGUMENT))?;
                let cqe = Cqe { request_id: c.request_id, user_tag: c.user_tag, op: c.op, reserved: 0, result: result_of(c.terminal) };
                out[i * CQE_SIZE..(i + 1) * CQE_SIZE].copy_from_slice(&cqe.encode());
            }
            // 已在对象表锁内：用持锁版本（复制成功才消费完成记录，二者必须在同一把锁里）。
            // 先结束对环的借用再复制，复制成功后重新取环消费——三步都在这一把锁内，期间完成记录不会变化。
            crate::mm::user::copy_to_user_in(t, pid, args.cq_ptr, &out, CQ_CAPACITY * CQE_SIZE).map_err(user_err)?;
            ring_mut(t, ring).ok_or(err(SYSTEM_HANDLE_ERROR_INVALID))?.sm.consume(n);
            reaped = n as u32;
        }
        settle_in(t, ring);
        Ok::<(), i64>(())
    });
    let done = EnterArgs { submitted, reaped, first_error, ..args }.encode();
    let wrote = copy_to_user(args_ptr + out_off as u64, &done[out_off..out_off + out_len], out_len);
    match (res, wrote) {
        (Err(e), _) => e,
        (Ok(()), Err(e)) => user_err(e),
        (Ok(()), Ok(())) => 0,
    }
}

// ———————————————————————— 诊断 ————————————————————————

/// 内核自检：取消 Ring 上全部执行中的 `system.time.wait` 请求（经与用户取消相同的裁决路径），返回取消数。
/// 用于让一个停在长时间等待上的用户线程在内核确认某个状态之后继续，而不必猜测时长。
/// Kernel self-test: cancels every running `system.time.wait` on the ring.
pub fn kernel_cancel_time_waits(ring: ObjId) -> usize {
    kobj::with(|t| {
        let Some(r) = ring_mut(t, ring) else { return 0 };
        let waits: Vec<u64> = r.running.iter().filter(|(_, b)| matches!(b, Backend::Wait { .. })).map(|(id, _)| *id).collect();
        for req in &waits {
            kernel_cancel_in(t, ring, *req);
        }
        waits.len()
    })
}

/// Ring 上执行中的 `system.time.wait` 请求数（Ring 已销毁返回 0）。
/// Number of running `system.time.wait` requests on the ring.
pub fn running_time_waits(ring: ObjId) -> usize {
    kobj::with(|t| {
        settle_in(t, ring);
        ring_mut(t, ring).map(|r| r.running.iter().filter(|(_, b)| matches!(b, Backend::Wait { .. })).count()).unwrap_or(0)
    })
}

/// 内核自检：从 Ring 收取至多 `max` 条完成记录 `(请求 ID, 结果)` 并归还信用（与用户收取相同的消费路径）。
pub fn reap_kernel(ring: ObjId, max: usize) -> Vec<(u64, i64)> {
    kobj::with(|t| {
        settle_in(t, ring);
        let Some(r) = ring_mut(t, ring) else { return Vec::new() };
        let n = max.min(r.sm.ready());
        let out: Vec<(u64, i64)> = (0..n).filter_map(|i| r.sm.peek(i)).map(|c| (c.request_id, result_of(c.terminal))).collect();
        r.sm.consume(n);
        settle_in(t, ring);
        out
    })
}

/// 进程 `pid` 的句柄 `h` 所指的 Ring（诊断与自检用）。
pub fn ring_of(pid: ObjId, h: HandleId) -> Option<ObjId> {
    kobj::with(|t| proc::resolve_in(t, pid, h, ObjectType::Ring, Rights::NONE).ok())
}

/// Ring 的可观测状态（Ring 已销毁返回 `None`）。
pub fn view(ring: ObjId) -> Option<RingView> {
    kobj::with(|t| {
        settle_in(t, ring);
        ring_mut(t, ring).map(|r| r.view())
    })
}
