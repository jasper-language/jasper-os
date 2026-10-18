//! IPC Channel：一对端点之间的消息传递；send / recv 经异步环提交，句柄随消息**移动**。
//! IPC channels: message passing between a pair of endpoints; handles move with messages.
//!
//! # 模型
//! * `system.channel.create` 建立一对端点（对象表中两个 [`Endpoint`]，互为对端，只有弱回指）。
//!   每个端点有一个**接收队列**：对端发来的消息排在这里。端点在 v1 不可传递（句柄不带 TRANSFER）。
//! * **send（两阶段）**：阶段 A 复制消息体与句柄值（可失败，不动句柄表）；阶段 B 在同一把锁内复核
//!   「对端仍开着、队列有空位、每个句柄仍有效且带 TRANSFER、对象是叶子、句柄互不相同」，然后一次性
//!   「从发送方句柄表移出 → 放进消息 → 入队」——这是句柄所有权的**唯一转移点**。阶段 B 内没有可失败的步骤。
//!   队列满 ⇒ `queue_full`、对端已关闭 ⇒ `peer_closed`，均不移出任何句柄。send 在提交时即裁决终态。
//! * **recv**：提交时校验并**固定**接收缓冲区、句柄数组与描述的输出字段所在的页（[`crate::mm::pin`]）；
//!   之后只经这些已固定的帧写入，不经用户虚拟地址。交付在一把锁内完成：先检查（请求仍未裁决、缓冲区够大、
//!   句柄数组够大、接收方句柄表放得下全部句柄），全部满足才「写消息体 → 安装句柄 → 写句柄值与输出 → 出队 →
//!   裁决成功」，否则消息留在队列里（全有或全无）。
//! * 消息持有其中叶子对象的**外部所有权**（从发送方句柄转来，总数不变）；端点关闭时队列中的消息被销毁，
//!   这些所有权随之释放（不归还发送方）。
//!
//! # 关闭
//! 端点的有效外部所有权归零 ⇒ closing：销毁队列中的消息、以 `cancelled` 结束在它上面等待的 recv；
//! 对端此后 send 得到 `peer_closed`，对端上等待的 recv（队列已空，不会再有消息）以 `peer_closed` 结束。
//!
//! # 锁
//! 请求状态、端点队列、接收方句柄表都在对象表锁内一次完成（单 CPU；锁顺序见对象表模块），
//! 因此「取消与交付」由先取得锁者裁决：交付先 ⇒ 取消得到 `already_completed`；取消先 ⇒ 交付看到已裁决而不触碰消息。

use alloc::boxed::Box;
use alloc::collections::VecDeque;
use alloc::vec::Vec;

use kernel_core::object::{HandleId, ObjectRef, ObjectType, Rights};
use kernel_core::objtable::ObjId;
use kernel_core::ring_abi::MsgDesc;

use crate::kobj::{self, KObject, Table};
use crate::mm::pin::PinnedRange;
use crate::proc::{self, ProcError};
use crate::syscall::err;
use crate::syscall::table::*;

/// 每进程端点数上限（开发默认值）。
pub const MAX_ENDPOINTS_PER_PROCESS: u32 = 64;
/// 单条消息的消息体上限。
pub const MAX_MSG_BYTES: usize = 64 * 1024;
/// 单条消息可携带的句柄数上限。
pub const MAX_MSG_HANDLES: usize = 8;
/// 每个端点接收队列的消息数上限。
pub const MAX_QUEUE_MSGS: usize = 64;
/// 每个端点接收队列的总字节上限。
pub const MAX_QUEUE_BYTES: usize = 1024 * 1024;
/// 端点句柄的权限：接收（READ）、发送（WRITE）、等待（WAIT）、控制（CONTROL）、进程内复制（DUPLICATE）；**v1 不带 TRANSFER**。
pub const ENDPOINT_RIGHTS: Rights =
    Rights::READ.union(Rights::WRITE).union(Rights::WAIT).union(Rights::CONTROL).union(Rights::DUPLICATE);

/// 一条消息：消息体 + 随消息移动的句柄（持有各对象的外部所有权）。
struct Message {
    body: Vec<u8>,
    handles: Vec<(ObjectRef, Rights)>,
}

/// Channel 的一个端点。
pub struct Endpoint {
    /// 创建者进程（弱回指：只用于配额记账）。
    owner: ObjId,
    /// 对端（弱回指）。
    peer: Option<ObjId>,
    /// 接收队列（对端发来的消息）。
    queue: VecDeque<Message>,
    queued_bytes: usize,
    /// 已 closing。
    closed: bool,
    /// 在本端点上等待的 recv 请求 (Ring, 请求 ID)——非拥有式登记。
    waiters: VecDeque<(ObjId, u64)>,
}

fn ep_mut(t: &mut Table, id: ObjId) -> Option<&mut Endpoint> {
    match t.get_mut(id) {
        Ok(KObject::Endpoint(e)) => Some(e),
        _ => None,
    }
}

/// 端点是否已关闭（已销毁也算关闭）。
fn is_closed(t: &mut Table, id: Option<ObjId>) -> bool {
    match id.and_then(|id| ep_mut(t, id)) {
        Some(e) => e.closed,
        None => true,
    }
}

/// 释放一条消息持有的全部外部所有权（消息被销毁时）。
fn drop_message(t: &mut Table, m: Message) {
    for (r, _) in m.handles {
        if let Some(id) = ObjId::from_raw(r.id.0) {
            let _ = kobj::release_owner_in(t, id);
        }
    }
}

// ———————————————————————— 创建 / 关闭 / 销毁 ————————————————————————

/// 为进程 `pa`、`pb` 各发放一个端点（可为同一进程），返回两个句柄。全有或全无。
/// 进程间通道在 v1 由创建方建立并分别放入双方的句柄表。
pub fn create_pair(pa: ObjId, pb: ObjId) -> Result<(HandleId, HandleId), i64> {
    kobj::with(|t| {
        for (pid, need) in [(pa, if pa == pb { 2 } else { 1 }), (pb, if pa == pb { 2 } else { 1 })] {
            proc::syscalls_in(t, pid).map_err(proc_err)?;
            let q = proc::ring_quota_in(t, pid).ok_or(err(SYSTEM_ERROR_RIGHTS_DENIED))?;
            if q.endpoints + need > MAX_ENDPOINTS_PER_PROCESS {
                return Err(err(SYSTEM_ERROR_QUOTA_EXCEEDED));
            }
        }
        let new = |owner| KObject::Endpoint(Box::new(Endpoint { owner, peer: None, queue: VecDeque::new(), queued_bytes: 0, closed: false, waiters: VecDeque::new() }));
        let (ha, a) = proc::grant_new_in(t, pa, new(pa), ObjectType::Channel, ENDPOINT_RIGHTS).map_err(proc_err)?;
        let (hb, b) = match proc::grant_new_in(t, pb, new(pb), ObjectType::Channel, ENDPOINT_RIGHTS) {
            Ok(x) => x,
            Err(e) => {
                // 回滚：关闭第一个端点的句柄（其唯一外部所有权）⇒ closing ⇒ 由清理过程销毁
                let _ = proc::take_handle_in(t, pa, ha).map(|id| kobj::release_owner_in(t, id));
                return Err(proc_err(e));
            }
        };
        if let Some(e) = ep_mut(t, a) {
            e.peer = Some(b);
        }
        if let Some(e) = ep_mut(t, b) {
            e.peer = Some(a);
        }
        for pid in [pa, pb] {
            if let Some(q) = proc::ring_quota_in(t, pid) {
                q.endpoints += 1;
            }
        }
        crate::kprintln!("[JSR-IPC] event=system.channel.created a={:#x} b={:#x}", a.raw(), b.raw());
        Ok((ha, hb))
    })
}

/// closing 动作（端点外部所有权归零时由对象表调用）：销毁队列中的消息、取消本端点上等待的 recv、
/// 让对端上等待的 recv 以 `peer_closed` 结束。
pub fn close_in(t: &mut Table, id: ObjId) {
    let Some(e) = ep_mut(t, id) else { return };
    e.closed = true;
    let msgs: Vec<Message> = e.queue.drain(..).collect();
    e.queued_bytes = 0;
    let waiters: Vec<(ObjId, u64)> = e.waiters.drain(..).collect();
    let peer = e.peer;
    let dropped = msgs.len();
    for m in msgs {
        drop_message(t, m);
    }
    for (ring, req) in waiters {
        crate::ring::kernel_cancel_in(t, ring, req);
    }
    if let Some(p) = peer {
        wake_in(t, p);
    }
    crate::kprintln!("[JSR-IPC] event=system.channel.closing endpoint={:#x} dropped_messages={}", id.raw(), dropped);
}

/// 销毁动作（清理过程调用，不持对象表锁）：归还创建者的端点配额。
pub fn destroy(e: Box<Endpoint>) {
    kobj::with(|t| {
        if let Some(q) = proc::ring_quota_in(t, e.owner) {
            q.endpoints = q.endpoints.saturating_sub(1);
        }
    });
}

fn proc_err(e: ProcError) -> i64 {
    crate::syscall::proc_err(e)
}

// ———————————————————————— send ————————————————————————

/// send 的阶段 B（锁内，唯一转移点）：复核后一次性移动句柄并入队。阶段 A（复制消息体与句柄值）由调用者完成。
/// 返回值即 send 的终态：成功为消息体字节数，失败为 `-(错误 ID)`，失败时句柄表与队列均无变化。
pub(crate) fn send_in(t: &mut Table, pid: ObjId, h: HandleId, body: Vec<u8>, handle_vals: &[u32]) -> i64 {
    if body.len() > MAX_MSG_BYTES || handle_vals.len() > MAX_MSG_HANDLES {
        return err(SYSTEM_ERROR_INVALID_ARGUMENT);
    }
    let me = match proc::resolve_in(t, pid, h, ObjectType::Channel, Rights::WRITE) {
        Ok(id) => id,
        Err(e) => return proc_err(e),
    };
    let peer = ep_mut(t, me).and_then(|e| e.peer);
    if is_closed(t, peer) {
        return err(SYSTEM_CHANNEL_ERROR_PEER_CLOSED);
    }
    let Some(peer) = peer else { return err(SYSTEM_CHANNEL_ERROR_PEER_CLOSED) };
    match ep_mut(t, peer) {
        Some(p) if p.queue.len() < MAX_QUEUE_MSGS && p.queued_bytes + body.len() <= MAX_QUEUE_BYTES => {}
        _ => return err(SYSTEM_CHANNEL_ERROR_QUEUE_FULL),
    }
    // 复核每个要移动的句柄：有效、带 TRANSFER、叶子对象、互不相同、不是本次发送所用的端点
    let mut ids: Vec<HandleId> = Vec::with_capacity(handle_vals.len());
    for &v in handle_vals {
        let hid = HandleId::from_raw(v);
        if ids.contains(&hid) || hid == h {
            return err(SYSTEM_ERROR_INVALID_ARGUMENT);
        }
        match proc::handle_in(t, pid, hid) {
            Ok((r, rights)) => {
                if !rights.contains(Rights::TRANSFER) {
                    return err(SYSTEM_HANDLE_ERROR_RIGHTS_DENIED);
                }
                if !r.ty.is_transferable_v1() {
                    return err(SYSTEM_HANDLE_ERROR_NOT_TRANSFERABLE);
                }
            }
            Err(e) => return proc_err(e),
        }
        ids.push(hid);
    }
    // 提交：以下步骤不会失败（全部条件已在同一把锁内确认）
    let mut handles = Vec::with_capacity(ids.len());
    for hid in ids {
        if let Ok((r, rights)) = proc::handle_in(t, pid, hid) {
            let _ = proc::take_handle_in(t, pid, hid); // 外部所有权随句柄移进消息，总数不变
            handles.push((r, rights));
        }
    }
    let n = body.len();
    if let Some(p) = ep_mut(t, peer) {
        p.queued_bytes += n;
        p.queue.push_back(Message { body, handles });
    }
    wake_in(t, peer);
    n as i64
}

/// 让端点上的等待者依次尝试取消息（消息到达或对端关闭时调用）。
fn wake_in(t: &mut Table, id: ObjId) {
    loop {
        let Some(e) = ep_mut(t, id) else { return };
        let Some((ring, req)) = e.waiters.pop_front() else { return };
        if !crate::ring::deliver_waiter_in(t, ring, req) {
            // 仍需等待（队列已空且对端仍开着）：放回队首，停止
            if let Some(e) = ep_mut(t, id) {
                e.waiters.push_front((ring, req));
            }
            return;
        }
    }
}

// ———————————————————————— recv ————————————————————————

/// 一个 recv 请求的执行目标：端点（持有一个内部引用）、接收方进程、已固定的三段用户内存。
pub struct RecvTarget {
    endpoint: ObjId,
    receiver: ObjId,
    data: PinnedRange,
    handles: PinnedRange,
    handles_cap: usize,
    out: PinnedRange,
}

/// 一次交付尝试的结果。
pub enum Delivery {
    /// 队列为空且对端仍开着：继续等待。
    Empty,
    /// 请求结束，结果为该值（成功 = 消息体字节数；失败 = `-(错误 ID)`，消息留在队列里）。
    Done(i64),
}

/// 建立 recv 目标（锁内）：解析端点（READ 权限）、取得它的一个内部引用、固定接收缓冲区 / 句柄数组 / 描述输出字段。
/// 任一步失败 ⇒ 不保留任何引用与固定。
pub(crate) fn prepare_recv_in(t: &mut Table, pid: ObjId, h: HandleId, desc_ptr: u64, d: &MsgDesc) -> Result<RecvTarget, i64> {
    if d.data_len as usize > MAX_MSG_BYTES || d.handles_cap as usize > MAX_MSG_HANDLES {
        return Err(err(SYSTEM_ERROR_INVALID_ARGUMENT));
    }
    let ep = proc::resolve_in(t, pid, h, ObjectType::Channel, Rights::READ).map_err(proc_err)?;
    let (off, len) = MsgDesc::OUTPUT_RANGE;
    let out = proc::pin_user_in(t, pid, desc_ptr.checked_add(off as u64).ok_or(err(SYSTEM_ERROR_INVALID_ARGUMENT))?, len, true).map_err(proc_err)?;
    let data = proc::pin_user_in(t, pid, d.data_ptr, d.data_len as usize, true).map_err(proc_err)?;
    let handles = proc::pin_user_in(t, pid, d.handles_ptr, d.handles_cap as usize * 4, true).map_err(proc_err)?;
    t.acquire_internal(ep).map_err(|_| err(SYSTEM_HANDLE_ERROR_INVALID))?;
    Ok(RecvTarget { endpoint: ep, receiver: pid, data, handles, handles_cap: d.handles_cap as usize, out })
}

/// 释放 recv 目标（锁内；请求结束或提交失败时）：撤销等待登记（`waiter` 为其登记的 (Ring, 请求 ID)，
/// 未登记过为 `None`）、释放端点的内部引用；固定随目标丢弃而解除。
pub(crate) fn release_target_in(t: &mut Table, target: RecvTarget, waiter: Option<(ObjId, u64)>) {
    if let (Some(w), Some(e)) = (waiter, ep_mut(t, target.endpoint)) {
        e.waiters.retain(|x| *x != w);
    }
    let _ = t.release_internal(target.endpoint);
    drop(target);
}

/// 登记一个等待者（队列为空时）。
pub(crate) fn add_waiter_in(t: &mut Table, target: &RecvTarget, ring: ObjId, req: u64) {
    if let Some(e) = ep_mut(t, target.endpoint) {
        e.waiters.push_back((ring, req));
    }
}

/// 写 recv 描述的输出字段（经固定的帧）。
fn write_out(target: &RecvTarget, data_len: usize, nhandles: usize) {
    let mut b = [0u8; 8];
    b[0..4].copy_from_slice(&(data_len as u32).to_le_bytes());
    b[4..8].copy_from_slice(&(nhandles as u32).to_le_bytes());
    target.out.write_at(0, &b);
}

/// 尝试交付端点队首的消息（锁内；调用者已确认请求仍未裁决）。见模块文档的「先检查、再执行」。
pub(crate) fn try_deliver_in(t: &mut Table, target: &RecvTarget) -> Delivery {
    let ep = target.endpoint;
    let Some(e) = ep_mut(t, ep) else { return Delivery::Done(err(SYSTEM_ASYNC_ERROR_CANCELLED)) };
    if e.closed {
        return Delivery::Done(err(SYSTEM_ASYNC_ERROR_CANCELLED));
    }
    let peer = e.peer;
    let Some(m) = e.queue.front() else {
        return if is_closed(t, peer) { Delivery::Done(err(SYSTEM_CHANNEL_ERROR_PEER_CLOSED)) } else { Delivery::Empty };
    };
    let (n, nh) = (m.body.len(), m.handles.len());
    // —— 检查（任一不满足：消息留在队列，接收方无变化）——
    if n > target.data.len() || nh > target.handles_cap {
        write_out(target, n, nh);
        return Delivery::Done(err(SYSTEM_CHANNEL_ERROR_BUFFER_TOO_SMALL));
    }
    if proc::free_slots_in(t, target.receiver) < nh {
        write_out(target, n, nh);
        return Delivery::Done(err(SYSTEM_HANDLE_ERROR_TABLE_FULL));
    }
    // —— 执行（不再有可失败的步骤）——
    let Some(e) = ep_mut(t, ep) else { return Delivery::Empty };
    let Some(m) = e.queue.pop_front() else { return Delivery::Empty };
    e.queued_bytes -= n;
    target.data.write_at(0, &m.body);
    let mut vals = Vec::with_capacity(nh);
    for (r, rights) in m.handles {
        match proc::put_handle_in(t, target.receiver, r, rights) {
            Ok(h) => vals.push(h.raw()),
            Err(_) => {
                // 已确认有空位，不会发生；防御：释放这份所有权，避免泄漏
                if let Some(id) = ObjId::from_raw(r.id.0) {
                    let _ = kobj::release_owner_in(t, id);
                }
            }
        }
    }
    for (i, v) in vals.iter().enumerate() {
        target.handles.write_at(i * 4, &v.to_le_bytes());
    }
    write_out(target, n, vals.len());
    Delivery::Done(n as i64)
}

/// 端点是否已关闭（诊断）；`None` = 端点已销毁。
pub fn endpoint_closed(pid: ObjId, h: HandleId) -> Option<bool> {
    kobj::with(|t| {
        let id = proc::resolve_in(t, pid, h, ObjectType::Channel, Rights::NONE).ok()?;
        ep_mut(t, id).map(|e| e.closed)
    })
}

/// 端点接收队列中的消息数（诊断）。
pub fn queued(pid: ObjId, h: HandleId) -> Option<usize> {
    kobj::with(|t| {
        let id = proc::resolve_in(t, pid, h, ObjectType::Channel, Rights::NONE).ok()?;
        ep_mut(t, id).map(|e| e.queue.len())
    })
}

// ———————————————————————— 系统调用 ————————————————————————

/// `system.channel.create(out_ptr)`：在当前进程建立一对端点，把两个句柄值（`u32`）写到 `out_ptr`。返回 0。
pub fn sys_create(out_ptr: u64) -> i64 {
    let Some(pid) = proc::current_process() else { return err(SYSTEM_ERROR_RIGHTS_DENIED) };
    // 先确认输出位置可写：创建之后不会出现「对象建了却交不回句柄」
    if let Err(e) = crate::mm::user::copy_to_user(out_ptr, &[0u8; 8], 8) {
        return crate::ring::user_err(e);
    }
    match create_pair(pid, pid) {
        Ok((a, b)) => {
            let mut v = [0u8; 8];
            v[0..4].copy_from_slice(&a.raw().to_le_bytes());
            v[4..8].copy_from_slice(&b.raw().to_le_bytes());
            match crate::mm::user::copy_to_user(out_ptr, &v, 8) {
                Ok(()) => 0,
                Err(e) => crate::ring::user_err(e),
            }
        }
        Err(e) => e,
    }
}

/// 阶段 A：从当前进程复制消息描述、消息体与句柄值（可失败，不动任何句柄）。
pub(crate) fn copy_send_args(desc_ptr: u64) -> Result<(Vec<u8>, Vec<u32>), i64> {
    let d = copy_desc(desc_ptr)?;
    if d.data_len as usize > MAX_MSG_BYTES || d.handles_cap as usize > MAX_MSG_HANDLES {
        return Err(err(SYSTEM_ERROR_INVALID_ARGUMENT));
    }
    let mut body = alloc::vec![0u8; d.data_len as usize];
    crate::mm::user::copy_from_user(&mut body, d.data_ptr, MAX_MSG_BYTES).map_err(crate::ring::user_err)?;
    let mut raw = alloc::vec![0u8; d.handles_cap as usize * 4];
    crate::mm::user::copy_from_user(&mut raw, d.handles_ptr, MAX_MSG_HANDLES * 4).map_err(crate::ring::user_err)?;
    let vals = raw.chunks_exact(4).map(|c| u32::from_le_bytes([c[0], c[1], c[2], c[3]])).collect();
    Ok((body, vals))
}

/// 从当前进程复制一份消息描述（可信快照）。
pub(crate) fn copy_desc(desc_ptr: u64) -> Result<MsgDesc, i64> {
    let mut b = [0u8; kernel_core::ring_abi::MSG_DESC_SIZE];
    crate::mm::user::copy_from_user(&mut b, desc_ptr, kernel_core::ring_abi::MSG_DESC_SIZE).map_err(crate::ring::user_err)?;
    Ok(MsgDesc::decode(&b))
}

/// `system.channel.send(endpoint, desc)` 的同步形式：返回 send 的终态（与经 ring 提交时的完成结果相同）。
pub fn sys_send(h: u64, desc_ptr: u64) -> i64 {
    let Some(pid) = proc::current_process() else { return err(SYSTEM_ERROR_RIGHTS_DENIED) };
    match copy_send_args(desc_ptr) {
        Ok((body, vals)) => kobj::with(|t| send_in(t, pid, HandleId::from_raw(h as u32), body, &vals)),
        Err(e) => e,
    }
}

/// `system.channel.recv(endpoint, desc)` 的同步形式：阻塞直到交付、对端关闭或本端点关闭。
/// 与经 ring 提交时一样先固定缓冲区，交付规则完全相同；等待期间让出处理器并休眠到下一个中断。
pub fn sys_recv(h: u64, desc_ptr: u64) -> i64 {
    let Some(pid) = proc::current_process() else { return err(SYSTEM_ERROR_RIGHTS_DENIED) };
    let d = match copy_desc(desc_ptr) {
        Ok(d) => d,
        Err(e) => return e,
    };
    let target = match kobj::with(|t| prepare_recv_in(t, pid, HandleId::from_raw(h as u32), desc_ptr, &d)) {
        Ok(x) => x,
        Err(e) => return e,
    };
    loop {
        match kobj::with(|t| try_deliver_in(t, &target)) {
            Delivery::Done(v) => {
                kobj::with(|t| release_target_in(t, target, None));
                return v;
            }
            Delivery::Empty => crate::sched::pause(),
        }
    }
}
