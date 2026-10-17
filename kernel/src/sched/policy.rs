//! 调度策略（Strategy 模式）。
//!
//! 职责：只回答「下一个该运行哪个槽位」，**不碰**寄存器、栈、任务状态写入。
//! 为什么拆出来：design.md 规定 Core 只提供调度*机制*，分时/实时/批处理等*策略*
//! 由模块提供，且长期要支持多策略共存（模式 B）。把选择逻辑抽象为 trait，
//! 机制层（`scheduler.rs`）对策略泛型化，换策略不需要改切换代码。
//!
//! 约定：槽位 0 是引导线程，**不交给策略选择**；策略只在工作槽位 `1..slots` 中挑选。

/// 调度策略接口。
///
/// 实现者必须是纯决策：给定当前槽位与「某槽位是否可运行」的查询，返回下一个槽位。
/// 返回 `None` 表示没有可运行的工作任务（机制层会切回引导线程）。
pub trait SchedPolicy {
    /// 策略名（用于诊断输出）。
    fn name(&self) -> &'static str;

    /// 选出下一个要运行的工作槽位。
    ///
    /// * `current`：当前运行的槽位（可能是 0，即引导线程）
    /// * `slots`：槽位总数（含槽位 0）
    /// * `is_runnable`：查询某槽位当前是否可运行
    fn pick_next(&mut self, current: usize, slots: usize, is_runnable: &dyn Fn(usize) -> bool) -> Option<usize>;

    /// 时间片长度（单位：定时器 tick）。抢占式调度时，当前任务连续运行满这么多 tick 才被切走。
    /// 时间片属于「策略」而非「机制」：实时策略可以给不同任务不同的片长。
    fn quantum_ticks(&self) -> u32 {
        2
    }
}

/// 轮转策略：从当前槽位的下一个开始环形查找第一个可运行的工作槽位。
///
/// 当前槽位若仍可运行，会排在环的最后一个被考虑，因此「只剩自己」时返回自己。
pub struct RoundRobin;

impl SchedPolicy for RoundRobin {
    fn name(&self) -> &'static str {
        "round-robin"
    }

    fn pick_next(&mut self, current: usize, slots: usize, is_runnable: &dyn Fn(usize) -> bool) -> Option<usize> {
        let workers = slots.checked_sub(1)?;
        if workers == 0 {
            return None;
        }
        // 工作槽位 1..slots 组成一个环；引导线程视作位于环尾之后，因此从槽位 1 开始找。
        let base = if current == 0 { workers } else { current };
        (1..=workers)
            .map(|k| 1 + (base - 1 + k) % workers)
            .find(|&slot| is_runnable(slot))
    }
}
