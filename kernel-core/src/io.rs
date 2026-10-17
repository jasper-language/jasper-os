//! 异步 I/O：提交 → 完成（`system.async` 契约 + `system.async.ring` 后端形状）。
//!
//! # 职责
//! * [`IoRequest`] / [`Completion`]：一次异步操作的请求与完成记录
//! * [`IoBackend`]：真正执行请求的后端（Strategy 模式）；[`MemIoCore`] 是内存假设备
//! * [`Ring`]：提交队列（SQ）+ 完成队列（CQ）。`submit` 只入队；`enter` 推进执行；
//!   `reap` 取完成；`cancel` 取消尚未执行的请求
//!
//! # 纪律（设计约束「async 只有 ring」）及其在代码里的落点
//! * **不提供就绪式接口**：没有「可读了吗？」这类查询，调用者只能拿到完成记录。
//! * **缓冲区固定到完成**：`Ring<'buf, …>` 借用请求里的缓冲区，生命周期 `'buf` 覆盖整个 ring，
//!   借用检查器保证缓冲区在请求完成（或被取消）之前不可能被释放或修改。
//! * **完成永不丢失**：每个被接受的请求在提交时就预留了 CQ 槽位（`SQ 中 + CQ 中 < CQ 容量`
//!   才接受提交），因此执行或取消时向 CQ 推入必然成功。
//! * **取消不得 double-completion**：请求只会从 SQ 里离开一次——要么被 `enter` 执行，要么被
//!   `cancel` 摘除；两条路径各自恰好产生一条完成记录。已执行的请求再取消返回 `not_found`。
//!
//! # 命名（命名约定）
//! 机制名挂 L2：`system.async.ring.{create,submit,enter}`；契约级的取消挂 L1：`system.async.cancel`；
//! 被提交的操作按**目标对象**命名（`system.device.read` 等），后端换代时它们不变。
//! 原型里的 `Ioctl` 是 POSIX 概念，Core 不用：这里叫 [`IoOp::Control`]，名为 `system.device.update`。

use crate::meta::{Effects, InterfaceMeta};
use crate::object::{IdAllocator, Rights};
use crate::trace::RingBuffer;

/// 异步操作种类。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IoOp {
    /// 从设备读取。
    Read,
    /// 向设备写入。
    Write,
    /// 设备控制命令（原型的 `Ioctl`）。
    Control,
}

impl IoOp {
    /// 输出用的大写标签。
    pub const fn label(self) -> &'static str {
        match self {
            IoOp::Read => "READ",
            IoOp::Write => "WRITE",
            IoOp::Control => "CONTROL",
        }
    }

    /// 该操作的接口元数据（被提交的操作按目标对象命名）。
    pub const fn meta(self) -> InterfaceMeta {
        match self {
            IoOp::Read => InterfaceMeta::op("system.device.read", Rights::READ, Effects::Read, "设备·读取"),
            IoOp::Write => InterfaceMeta::op("system.device.write", Rights::WRITE, Effects::Write, "设备·写入"),
            IoOp::Control => {
                InterfaceMeta::op("system.device.update", Rights::CONTROL, Effects::Write, "设备·控制命令")
            }
        }
    }
}

/// ring 自身的操作元数据（L2 后端级 + L1 契约级）。
pub const RING_OPS: [InterfaceMeta; 4] = [
    InterfaceMeta::op("system.async.ring.create", Rights::NONE, Effects::Write, "异步环·创建"),
    InterfaceMeta::op("system.async.ring.submit", Rights::WRITE, Effects::Write, "异步环·提交请求"),
    InterfaceMeta::op("system.async.ring.enter", Rights::WAIT, Effects::Write, "异步环·推进并收割完成"),
    InterfaceMeta::op("system.async.cancel", Rights::CONTROL, Effects::Write, "异步·取消请求"),
];

/// 一次异步请求。缓冲区以 `'buf` 借用，直到完成。
#[derive(Debug, Clone, Copy)]
pub struct IoRequest<'buf> {
    /// 操作种类。
    pub op: IoOp,
    /// 载荷（写入的数据或控制命令参数）。
    pub payload: &'buf [u8],
    /// 调用者自定义数据，原样带回完成记录。
    pub user_data: u64,
}

impl<'buf> IoRequest<'buf> {
    /// 构造请求。
    pub const fn new(op: IoOp, payload: &'buf [u8], user_data: u64) -> Self {
        IoRequest { op, payload, user_data }
    }
}

/// 异步操作错误（`system.async.error.*` / `system.error.*`）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IoError {
    /// 请求在执行前被取消。
    Cancelled,
    /// 后端不支持该操作。
    Unsupported,
}

impl IoError {
    /// 规范错误名。
    pub const fn name(self) -> &'static str {
        match self {
            IoError::Cancelled => "system.async.error.cancelled",
            IoError::Unsupported => "system.error.unsupported",
        }
    }
}

/// 完成记录（`system.async.Completion`）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Completion {
    /// 提交时分配的请求号。
    pub request_id: u64,
    /// 请求的 `user_data`。
    pub user_data: u64,
    /// 操作种类。
    pub op: IoOp,
    /// 成功时为传输的字节数。
    pub result: Result<usize, IoError>,
}

impl Completion {
    /// 是否成功。
    pub fn is_ok(&self) -> bool {
        self.result.is_ok()
    }
}

/// ring 提交侧错误。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RingError {
    /// 没有空余的提交槽位或预留的完成槽位，稍后 `reap` 再提交。
    Busy,
    /// 请求号不存在或已执行完毕（不能再取消）。
    NotFound,
}

impl RingError {
    /// 规范错误名。
    pub const fn name(self) -> &'static str {
        match self {
            RingError::Busy => "system.async.error.busy",
            RingError::NotFound => "system.async.error.not_found",
        }
    }
}

/// 后端（Strategy）：同步执行一个请求，返回传输字节数。
///
/// ring 机制与具体设备无关；换真实设备（或将来的加速器设备对象 + DMA 映射）只需换后端。
pub trait IoBackend {
    /// 后端名（诊断用）。
    fn name(&self) -> &'static str;
    /// 执行请求。
    fn execute(&mut self, req: &IoRequest<'_>) -> Result<usize, IoError>;
}

/// 内存假设备：沿用原型语义——`Write` 返回载荷长度，`Read` / `Control` 返回 0。
#[derive(Debug, Default)]
pub struct MemIoCore {
    /// 累计写入字节数（便于测试与诊断）。
    pub bytes_written: usize,
}

impl MemIoCore {
    /// 新建。
    pub const fn new() -> Self {
        MemIoCore { bytes_written: 0 }
    }
}

impl IoBackend for MemIoCore {
    fn name(&self) -> &'static str {
        "mem"
    }

    fn execute(&mut self, req: &IoRequest<'_>) -> Result<usize, IoError> {
        match req.op {
            IoOp::Write => {
                self.bytes_written += req.payload.len();
                Ok(req.payload.len())
            }
            IoOp::Read | IoOp::Control => Ok(0),
        }
    }
}

/// 提交队列里的一项。
struct Pending<'buf> {
    id: u64,
    req: IoRequest<'buf>,
}

/// 提交/完成队列对：`SQ` 个提交槽位、`CQ` 个完成槽位，不使用堆。
pub struct Ring<'buf, B: IoBackend, const SQ: usize, const CQ: usize> {
    sq: RingBuffer<Pending<'buf>, SQ>,
    cq: RingBuffer<Completion, CQ>,
    ids: IdAllocator,
    backend: B,
}

impl<'buf, B: IoBackend, const SQ: usize, const CQ: usize> Ring<'buf, B, SQ, CQ> {
    /// 以给定后端创建 ring（`system.async.ring.create`）。
    pub const fn new(backend: B) -> Self {
        Ring { sq: RingBuffer::new(), cq: RingBuffer::new(), ids: IdAllocator::new(), backend }
    }

    /// 提交一个请求，返回请求号（`system.async.ring.submit`）。只入队，不执行。
    pub fn submit(&mut self, req: IoRequest<'buf>) -> Result<u64, RingError> {
        // 预留完成槽位：保证每个被接受的请求将来一定能把完成记录放进 CQ。
        if self.sq.is_full() || self.sq.len() + self.cq.len() >= CQ {
            return Err(RingError::Busy);
        }
        let id = self.ids.allocate();
        self.sq.push(Pending { id, req }).map_err(|_| RingError::Busy)?;
        Ok(id)
    }

    /// 按提交顺序执行至多 `max` 个请求，把完成记录放入 CQ，返回执行个数
    /// （`system.async.ring.enter` 的推进部分）。
    pub fn enter(&mut self, max: usize) -> usize {
        let mut done = 0;
        while done < max {
            let Some(p) = self.sq.pop() else { break };
            let result = self.backend.execute(&p.req);
            self.complete(p, result);
            done += 1;
        }
        done
    }

    /// 取出最早的一条完成记录。
    pub fn reap(&mut self) -> Option<Completion> {
        self.cq.pop()
    }

    /// 取消一个尚未执行的请求（`system.async.cancel`）：它从 SQ 摘除，并产生**唯一**一条
    /// `cancelled` 完成记录。已执行或不存在的请求返回 [`RingError::NotFound`]。
    pub fn cancel(&mut self, request_id: u64) -> Result<(), RingError> {
        let p = self.sq.remove_first(|p| p.id == request_id).ok_or(RingError::NotFound)?;
        self.complete(p, Err(IoError::Cancelled));
        Ok(())
    }

    /// 生成完成记录。CQ 槽位已在提交时预留，推入必然成功。
    fn complete(&mut self, p: Pending<'buf>, result: Result<usize, IoError>) {
        let c = Completion { request_id: p.id, user_data: p.req.user_data, op: p.req.op, result };
        let pushed = self.cq.push(c);
        debug_assert!(pushed.is_ok(), "完成槽位预留失效");
    }

    /// 尚未执行的请求数。
    pub fn pending(&self) -> usize {
        self.sq.len()
    }

    /// 尚未收割的完成数。
    pub fn completed(&self) -> usize {
        self.cq.len()
    }

    /// 后端（只读）。
    pub fn backend(&self) -> &B {
        &self.backend
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    type MemRing<'b> = Ring<'b, MemIoCore, 4, 4>;

    #[test]
    fn submit_does_not_execute_until_enter() {
        let data = *b"ping";
        let mut r = MemRing::new(MemIoCore::new());
        let id = r.submit(IoRequest::new(IoOp::Write, &data, 42)).unwrap();
        assert_eq!((r.pending(), r.completed()), (1, 0), "提交只入队");
        assert_eq!(r.reap(), None, "没有就绪查询，也不会凭空完成");
        assert_eq!(r.enter(usize::MAX), 1);
        let c = r.reap().unwrap();
        assert_eq!((c.request_id, c.user_data, c.op), (id, 42, IoOp::Write));
        assert_eq!(c.result, Ok(4), "Write 返回载荷长度");
        assert_eq!(r.backend().bytes_written, 4);
    }

    #[test]
    fn read_and_control_return_zero_in_fifo_order() {
        let mut r = MemRing::new(MemIoCore::new());
        let a = r.submit(IoRequest::new(IoOp::Read, &[], 0)).unwrap();
        let b = r.submit(IoRequest::new(IoOp::Control, &[1, 2], 0)).unwrap();
        r.enter(8);
        assert_eq!(r.reap().map(|c| (c.request_id, c.result)), Some((a, Ok(0))));
        assert_eq!(r.reap().map(|c| (c.request_id, c.result)), Some((b, Ok(0))));
    }

    #[test]
    fn cancel_completes_exactly_once() {
        let mut r = MemRing::new(MemIoCore::new());
        let a = r.submit(IoRequest::new(IoOp::Write, b"a", 1)).unwrap();
        let b = r.submit(IoRequest::new(IoOp::Write, b"bb", 2)).unwrap();
        assert_eq!(r.cancel(a), Ok(()));
        assert_eq!(r.cancel(a), Err(RingError::NotFound), "不能重复取消");
        r.enter(8);
        assert_eq!(r.cancel(b), Err(RingError::NotFound), "已执行的不能再取消");
        let all: Vec<_> = core::iter::from_fn(|| r.reap()).collect();
        assert_eq!(all.len(), 2, "两个请求恰好两条完成");
        assert_eq!(all[0].result, Err(IoError::Cancelled));
        assert_eq!(all[1].result, Ok(2));
        assert_eq!(r.backend().bytes_written, 2, "被取消的请求没有执行");
        assert_eq!(IoError::Cancelled.name(), "system.async.error.cancelled");
    }

    #[test]
    fn completion_slots_are_reserved_at_submit() {
        let mut r: Ring<'_, MemIoCore, 4, 2> = Ring::new(MemIoCore::new());
        r.submit(IoRequest::new(IoOp::Read, &[], 0)).unwrap();
        r.submit(IoRequest::new(IoOp::Read, &[], 0)).unwrap();
        assert_eq!(r.submit(IoRequest::new(IoOp::Read, &[], 0)), Err(RingError::Busy));
        r.enter(8);
        assert_eq!(r.submit(IoRequest::new(IoOp::Read, &[], 0)), Err(RingError::Busy), "未收割前仍占预留");
        r.reap();
        assert!(r.submit(IoRequest::new(IoOp::Read, &[], 0)).is_ok());
    }

    #[test]
    fn op_metadata_names_follow_spec() {
        assert_eq!(IoOp::Write.meta().name, "system.device.write");
        assert_eq!(IoOp::Control.meta().rights, Rights::CONTROL);
        assert!(RING_OPS.iter().all(|m| m.name.starts_with("system.async.")));
        assert!(RING_OPS.iter().all(|m| !m.display_zh.is_empty()));
    }
}
