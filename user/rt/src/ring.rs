//! 异步环：提交 → 完成。所有异步操作只有这一种形态。
//! Async ring: submit, then reap completions.
//!
//! 内核语义：每条被接受的提交得到一个请求 ID（同一 Ring 内单调递增、永不复用），**恰好**产生一条完成记录
//! （成功、失败或 `ASYNC_CANCELLED`）；完成记录占用的信用在被收取后归还。
//!
//! 安全的 [`Op`] 只包含不引用用户内存的操作。引用用户缓冲区的操作（Channel 收发）用 [`Ring::submit_raw`]：
//! 调用者须保证缓冲区在请求完成（并被收取）之前一直有效。

use kernel_core::ring_abi::{Cqe, EnterArgs, Sqe, ENTER_ARGS_SIZE};

use crate::error::{check, Error, Result};
use crate::handle::Handle;
use crate::{ids, sys};

/// 不引用用户内存的异步操作。
#[derive(Debug, Clone, Copy)]
pub enum Op<'a> {
    /// 读取当前时刻（完成结果 = tick 数）。
    Now,
    /// 等待 `ticks` 个 tick。
    Sleep(u64),
    /// 等待句柄所指的线程退出（完成结果 = 退出码）。
    WaitTask(&'a Handle),
    /// 等待句柄所指的进程退出（完成结果 = 退出码）。
    WaitProcess(&'a Handle),
}

impl Op<'_> {
    fn sqe(self, tag: u64) -> Sqe {
        let (op, arg0) = match self {
            Op::Now => (ids::SYSTEM_TIME_NOW, 0),
            Op::Sleep(t) => (ids::SYSTEM_TIME_WAIT, t),
            Op::WaitTask(h) => (ids::SYSTEM_TASK_WAIT, h.raw() as u64),
            Op::WaitProcess(h) => (ids::SYSTEM_PROCESS_WAIT, h.raw() as u64),
        };
        Sqe { op: op as u32, flags: 0, user_tag: tag, arg0, arg1: 0 }
    }
}

/// 一条完成记录。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Completion {
    /// 内核分配的请求 ID。
    pub request_id: u64,
    /// 提交时的用户标签（原样带回）。
    pub user_tag: u64,
    /// 操作 ID。
    pub op: u32,
    /// 原始结果（非负 = 成功值，负数 = `-(错误 ID)`）。
    pub result: i64,
}

impl Completion {
    /// 结果转换为 [`Result`]。
    pub fn outcome(&self) -> Result<u64> {
        check(self.result)
    }
}

/// 一次 enter 的输出。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Entered {
    /// 被接受的提交数（从第一条起连续）。
    pub submitted: u32,
    /// 收取的完成记录数。
    pub reaped: u32,
    /// 第一条被拒的提交的错误（全部被接受时为 `None`）。
    pub first_error: Option<Error>,
}

/// 一个异步环（拥有其句柄）。
#[derive(Debug)]
pub struct Ring(Handle);

impl Ring {
    /// 新建容量为 `capacity` 的 Ring。
    pub fn create(capacity: u32) -> Result<Ring> {
        let raw = check(sys::call(ids::SYSTEM_ASYNC_RING_CREATE, capacity as u64, 0, 0))?;
        // SAFETY：内核刚放入本进程句柄表的新句柄。
        Ok(Ring(unsafe { Handle::from_raw(raw as u32) }))
    }

    /// Ring 句柄。
    pub fn handle(&self) -> &Handle {
        &self.0
    }

    /// 底层 enter：按顺序提交 `sq`（请求 ID 写入 `ids`，长度须不小于 `sq`），
    /// 等到至少 `wait_min` 条完成可收取（无法再满足时提前返回），收取至多 `cq.len()` 条到 `cq`。
    ///
    /// # Safety
    /// `sq` 中引用用户内存的操作，其内存必须在对应请求完成并被收取之前保持有效。
    pub unsafe fn enter_raw(&self, sq: &[Sqe], ids_out: &mut [u64], cq: &mut [Cqe], wait_min: u32) -> Result<Entered> {
        if ids_out.len() < sq.len() {
            return Err(Error::INVALID_ARGUMENT);
        }
        let args = EnterArgs {
            sq_ptr: sq.as_ptr() as u64,
            cq_ptr: cq.as_mut_ptr() as u64,
            id_ptr: ids_out.as_mut_ptr() as u64,
            sq_count: sq.len() as u32,
            cq_max: cq.len() as u32,
            wait_min,
            ..EnterArgs::default()
        };
        let mut b: [u8; ENTER_ARGS_SIZE] = args.encode();
        check(sys::call3(ids::SYSTEM_ASYNC_RING_ENTER, self.0.raw() as u64, b.as_mut_ptr() as u64, 0))?;
        let out = EnterArgs::decode(&b);
        Ok(Entered {
            submitted: out.submitted,
            reaped: out.reaped,
            first_error: if out.first_error < 0 { Some(Error(out.first_error.unsigned_abs())) } else { None },
        })
    }

    /// 提交一条安全操作，返回请求 ID。
    pub fn submit(&self, tag: u64, op: Op<'_>) -> Result<u64> {
        // SAFETY：Op 中的操作不引用用户内存。
        unsafe { self.submit_raw(op.sqe(tag)) }
    }

    /// 提交一条原始记录，返回请求 ID。
    ///
    /// # Safety
    /// 同 [`Ring::enter_raw`]。
    pub unsafe fn submit_raw(&self, sqe: Sqe) -> Result<u64> {
        let mut id = [0u64; 1];
        let e = self.enter_raw(core::slice::from_ref(&sqe), &mut id, &mut [], 0)?;
        match (e.submitted, e.first_error) {
            (1, _) => Ok(id[0]),
            (_, Some(err)) => Err(err),
            _ => Err(Error::INVALID_ARGUMENT),
        }
    }

    /// 等到至少 `wait_min` 条完成可收取，收取至多 `out.len()` 条；返回收取数。
    pub fn reap(&self, out: &mut [Completion], wait_min: u32) -> Result<usize> {
        let mut cq = [Cqe::default(); 16];
        let n = out.len().min(cq.len());
        // SAFETY：不提交任何记录。
        let e = unsafe { self.enter_raw(&[], &mut [], &mut cq[..n], wait_min) }?;
        for (o, c) in out.iter_mut().zip(cq.iter()).take(e.reaped as usize) {
            *o = Completion { request_id: c.request_id, user_tag: c.user_tag, op: c.op, result: c.result };
        }
        Ok(e.reaped as usize)
    }

    /// 同步取消请求 `request_id`：成功则该请求以 `ASYNC_CANCELLED` 完成（完成记录仍须收取）。
    pub fn cancel(&self, request_id: u64) -> Result<()> {
        check(sys::call(ids::SYSTEM_ASYNC_CANCEL, self.0.raw() as u64, request_id, 0)).map(|_| ())
    }
}
