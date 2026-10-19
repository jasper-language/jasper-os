//! 实时预算与准入的内核侧入口：唯一一份全局实时任务表。
//! Kernel-side entry for real-time quotas and admission: one global table.
//!
//! 语义（准入判定、预算记账、周期补充）全部在 `kernel_core::rt`，这里只提供
//! 受锁保护的访问，不重复实现。抢占式执行（tick 里强制节流）尚未接入，
//! 当前由任务自行记账并在耗尽时让出——这一步是真实行为，但不是抢占，不能当作
//! 「失控任务也会被停住」的保证。

use kernel_core::rt::{Charge, RtError, RtSet, RtTask, DEFAULT_UTILISATION_PERMILLE};

use crate::sync::IrqSpinLock;

static SET: IrqSpinLock<RtSet> = IrqSpinLock::new(RtSet::new(DEFAULT_UTILISATION_PERMILLE));

/// 准入一个实时任务。
pub fn admit(id: u32, quota: u32, period: u32, now: u64) -> Result<(), RtError> {
    // Profile 没有声明 `sched.realtime` 时，实时接口整体不存在（不是"降级为准入失败"）。
    if !crate::profile::has_capability("sched.realtime") {
        return Err(RtError::NotPermitted);
    }
    SET.lock().admit(id, quota, period, now)
}

/// 退出一个实时任务。
pub fn release(id: u32) -> Result<(), RtError> {
    SET.lock().release(id)
}

/// 记账。
pub fn charge(id: u32, ticks: u32) -> Result<Charge, RtError> {
    SET.lock().charge(id, ticks)
}

/// 周期补充。
pub fn replenish(now: u64) -> usize {
    SET.lock().replenish(now)
}

/// 任务快照。
pub fn get(id: u32) -> Option<RtTask> {
    SET.lock().get(id)
}

/// 当前总利用率（千分比）。
pub fn utilisation_permille() -> u32 {
    SET.lock().utilisation_permille()
}

/// 准入上限（千分比）。
pub fn limit_permille() -> u32 {
    SET.lock().limit_permille()
}
