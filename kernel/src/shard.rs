//! 系统服务的分片组件（内核侧）：N 个分片，每个分片一把锁 + 一个固定容量队列 + 计数；
//! 每个分片由钉在对应处理器上的一个工作线程消费。
//! Kernel-side sharded service queues: one lock, one bounded queue and counters per shard.
//!
//! # 职责
//! * 请求按 `kernel_core::shard::ShardKey`（处理器 / 队列 / 流）路由到分片；同一个流永远进同一分片，流内有序。
//! * 分片之间没有共享的锁或计数器：提交方只碰目标分片，各工作线程只碰自己的分片，
//!   服务的吞吐随处理器数伸缩，不会退化成「一核跑满、多核围观」。
//! * 可复用：任何系统服务定义一个 `static` 的 [`ShardedQueues`]，用 [`spawn_workers`] 每核起一个工作线程，
//!   工作线程以本处理器下标为分片号取请求（按处理器分片时下标即分片）。
//!
//! # 边界
//! 只负责排队与路由，不规定请求的含义与处理方式；队列满时拒绝而不覆盖，由提交方决定退避或施加反压。
//! 提交可以在中断上下文中进行（锁会关中断）。

use core::sync::atomic::{AtomicUsize, Ordering};

use kernel_core::shard::{ShardError, ShardKey, ShardRing, ShardRouter};
use kernel_core::smp::CpuSet;

use crate::lockorder;
use crate::sched::{self, scheduler::SpawnError};
use crate::sync::{IrqSpinLock, IrqU64};
use crate::task::TaskId;

/// N 个分片的服务队列（`CAP` 为每个分片的容量）。
/// Sharded service queues with `N` shards of capacity `CAP`.
pub struct ShardedQueues<T: Copy, const N: usize, const CAP: usize> {
    /// 当前启用的分片数（0 = 未配置，提交一律被拒）。
    active: AtomicUsize,
    queues: [IrqSpinLock<ShardRing<T, CAP>>; N],
    submitted: [IrqU64; N],
    processed: [IrqU64; N],
}

impl<T: Copy, const N: usize, const CAP: usize> ShardedQueues<T, N, CAP> {
    /// 未配置的服务队列（`static` 初始化用）。
    /// Unconfigured queues.
    pub const fn new() -> Self {
        ShardedQueues {
            active: AtomicUsize::new(0),
            queues: [const { IrqSpinLock::ranked(lockorder::SERVICE_SHARD, ShardRing::new()) }; N],
            submitted: [const { IrqU64::new(0) }; N],
            processed: [const { IrqU64::new(0) }; N],
        }
    }

    /// 启用前 `shards` 个分片并清零计数（队列必须为空）；数量非法或仍有未处理请求时拒绝、状态不变。
    /// Enable the first `shards` shards.
    pub fn configure(&self, shards: usize) -> Result<ShardRouter, ShardError> {
        let router = if shards > N { Err(ShardError::BadCount) } else { ShardRouter::new(shards) }?;
        if self.pending() != 0 {
            return Err(ShardError::Full);
        }
        for i in 0..N {
            self.submitted[i].store(0, Ordering::Relaxed);
            self.processed[i].store(0, Ordering::Relaxed);
        }
        self.active.store(shards, Ordering::Release);
        Ok(router)
    }

    /// 停用（之后提交被拒）。
    /// Disable the queues.
    pub fn shutdown(&self) {
        self.active.store(0, Ordering::Release);
    }

    /// 当前启用的分片数。
    /// Number of enabled shards.
    pub fn shards(&self) -> usize {
        self.active.load(Ordering::Acquire)
    }

    /// 按键提交一个请求，返回进入的分片；未配置、键无对应分片或分片已满时拒绝，所有分片不变。
    /// Submit `item` under `key`.
    pub fn submit(&self, key: ShardKey, item: T) -> Result<usize, ShardError> {
        let router = ShardRouter::new(self.shards())?;
        let shard = router.route(key)?;
        self.queues[shard].lock().push(item)?;
        self.submitted[shard].fetch_add(1, Ordering::Relaxed);
        Ok(shard)
    }

    /// 从分片 `shard` 取出最早的请求。
    /// Take the oldest request of `shard`.
    pub fn take(&self, shard: usize) -> Option<T> {
        if shard >= self.shards() {
            return None;
        }
        self.queues[shard].lock().pop()
    }

    /// 记一次「分片 `shard` 完成了一个请求」。
    /// Count one completed request of `shard`.
    pub fn complete(&self, shard: usize) {
        if shard < N {
            self.processed[shard].fetch_add(1, Ordering::Relaxed);
        }
    }

    /// 全部分片中尚未取走的请求数。
    /// Requests not yet taken, over all shards.
    pub fn pending(&self) -> usize {
        self.queues.iter().map(|q| q.lock().len()).sum()
    }

    /// 分片 `shard` 的 (已提交, 已完成, 因满被拒)。
    /// Counters of `shard`.
    pub fn counters(&self, shard: usize) -> (u64, u64, u64) {
        if shard >= N {
            return (0, 0, 0);
        }
        (self.submitted[shard].load(Ordering::Relaxed), self.processed[shard].load(Ordering::Relaxed), self.queues[shard].lock().rejected())
    }
}

impl<T: Copy, const N: usize, const CAP: usize> Default for ShardedQueues<T, N, CAP> {
    fn default() -> Self {
        Self::new()
    }
}

/// 每个在线处理器起一个钉在该处理器上的工作线程（任务号 `base_id + 处理器下标`）。
/// 任一创建失败时返回错误；已创建的线程照常运行到结束（由服务自己的停止条件决定）。返回创建的线程数。
/// Spawn one pinned worker per online processor.
pub fn spawn_workers(base_id: u64, name: &'static str, entry: fn(), cpus: usize) -> Result<usize, SpawnError> {
    let online = sched::online_cpus();
    let mut spawned = 0;
    for c in online.iter().take(cpus) {
        let mut only = CpuSet::EMPTY;
        only.insert(c);
        sched::spawn_on(TaskId(base_id + c as u64), name, entry, None, only)?;
        spawned += 1;
    }
    Ok(spawned)
}
