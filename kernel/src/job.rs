//! 批处理作业服务：把 `kernel_core::job` 的队列接到内核。
//! Batch job service: wires the job queue into the kernel.
//!
//! 职责：提供唯一的全局队列与受锁保护的入口；队列本身的语义（依赖/优先级/取消/
//! 统计）全部在 `kernel_core::job`，这里不重复实现。
//! English: a single locked queue; all semantics live in `kernel_core::job`.

use kernel_core::job::{Job, JobError, JobPriority, JobQueue, JobStats};

use crate::sync::IrqSpinLock;

static QUEUE: IrqSpinLock<JobQueue> = IrqSpinLock::new(JobQueue::new());

/// 提交作业。
pub fn submit(id: u32, priority: JobPriority, deps: &[u32]) -> Result<(), JobError> {
    QUEUE.lock().submit(id, priority, deps)
}

/// 选出一个可运行作业。
pub fn pick() -> Option<u32> {
    QUEUE.lock().pick()
}

/// 标记运行中。
pub fn start(id: u32) -> Result<(), JobError> {
    QUEUE.lock().start(id)
}

/// 记录结束（退出码 0 = 成功）。
pub fn finish(id: u32, exit_code: i32) -> Result<(), JobError> {
    QUEUE.lock().finish(id, exit_code)
}

/// 取消作业，返回取消前的状态。
pub fn cancel(id: u32) -> Result<kernel_core::job::JobState, JobError> {
    QUEUE.lock().cancel(id)
}

/// 按 ID 取作业快照。
pub fn get(id: u32) -> Option<Job> {
    QUEUE.lock().get(id).copied()
}

/// 统计快照。
pub fn stats() -> JobStats {
    QUEUE.lock().stats()
}

/// 清空队列（仅演练使用）。
pub fn reset() {
    *QUEUE.lock() = JobQueue::new();
}
