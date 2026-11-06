//! 批处理作业服务：把 `kernel_core::job` 的队列接到内核。
//! Batch job service: wires the job queue into the kernel.
//!
//! 职责：提供唯一的全局队列与受锁保护的入口；队列本身的语义（依赖/优先级/取消/
//! 统计）全部在 `kernel_core::job`，这里不重复实现。
//! English: a single blocking queue lock; all semantics live in `kernel_core::job`.
//! The queue may scan dependencies and mutate several records, so task-context
//! callers use `KMutex` instead of holding interrupts off for the whole operation.
//! Interrupt context must enqueue work through its own bounded handoff path.

use core::sync::atomic::{AtomicBool, Ordering};

use kernel_core::job::{Job, JobError, JobPriority, JobQueue, JobStats};

use crate::sched::{KMutex, KMutexGuard};

static QUEUE: KMutex<JobQueue> = KMutex::new(JobQueue::new());
static ACTIVE: AtomicBool = AtomicBool::new(false);

fn queue() -> KMutexGuard<'static, JobQueue> {
    QUEUE.lock().unwrap_or_else(|_| panic!("job queue KMutex wait graph rejected"))
}

/// `job` 模块激活：把编译期空队列置为本次启动的可用初始状态；重复激活被拒。
/// Activate the job module by establishing the single empty boot queue.
pub fn activate() -> Result<(), &'static str> {
    ACTIVE
        .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
        .map_err(|_| "job queue already activated")?;
    reset();
    if stats().total != 0 {
        ACTIVE.store(false, Ordering::Release);
        return Err("job queue not empty after activation");
    }
    Ok(())
}

/// 作业服务是否完成了模块激活。
/// Whether the job module activation completed.
pub fn active() -> bool {
    ACTIVE.load(Ordering::Acquire)
}

/// 提交作业。
pub fn submit(id: u32, priority: JobPriority, deps: &[u32]) -> Result<(), JobError> {
    // Profile 没有声明 `sched.batch` 时，批处理接口整体不存在（与实时能力的口径一致）。
    if !crate::profile::has_capability("sched.batch") {
        return Err(JobError::NotPermitted);
    }
    queue().submit(id, priority, deps)
}

/// 选出一个可运行作业。
pub fn pick() -> Option<u32> {
    queue().pick()
}

/// 标记运行中。
pub fn start(id: u32) -> Result<(), JobError> {
    queue().start(id)
}

/// 记录结束（退出码 0 = 成功）。
pub fn finish(id: u32, exit_code: i32) -> Result<(), JobError> {
    queue().finish(id, exit_code)
}

/// 取消作业，返回取消前的状态。
pub fn cancel(id: u32) -> Result<kernel_core::job::JobState, JobError> {
    queue().cancel(id)
}

/// 按 ID 取作业快照。
pub fn get(id: u32) -> Option<Job> {
    queue().get(id).copied()
}

/// 统计快照。
pub fn stats() -> JobStats {
    queue().stats()
}

/// 清空队列（仅演练使用）。
pub fn reset() {
    *queue() = JobQueue::new();
}
