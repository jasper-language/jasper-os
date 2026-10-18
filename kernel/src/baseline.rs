//! 资源基线：演练用例前后各取一次，比较后判定没有泄漏（页帧、内核对象、清理队列、固定帧）。
//! Resource baseline taken before and after a scenario to prove nothing leaked.
//!
//! 独立成模块的原因：只用内核任务的演练（优先级继承等）与运行用户程序的演练都用它，
//! 放在任何一个演练里都会让另一类演练被迫依赖它。

use crate::kobj;
use crate::mm::{frame, pin};

/// 资源基线。
/// Snapshot of leak-relevant resource counters.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Baseline {
    /// 空闲页帧数。
    pub(crate) free_frames: usize,
    /// 存活内核对象数。
    pub(crate) objects: usize,
    /// 清理队列中待处理的对象数。
    pub(crate) pending: usize,
    /// 固定帧统计。
    pub(crate) pins: (usize, usize),
}

/// 先跑完清理过程，再读取资源基线。
/// Drain the cleanup queue, then read the counters.
pub(crate) fn baseline() -> Baseline {
    kobj::run_cleanup(usize::MAX);
    let (objects, pending, _) = kobj::stats();
    Baseline { free_frames: frame::free_frames(), objects, pending, pins: pin::stats() }
}
