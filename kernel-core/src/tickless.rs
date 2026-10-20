//! 空闲 tick 规划：决定下一个定时器中断该在多久之后到来。
//! Idle tick planning: decide when the next timer interrupt should fire.
//!
//! # 为什么需要单独一层
//! "把 tick 拉长"与"唤醒延迟有上界"是一对矛盾：唤醒只在下一次中断时被处理，
//! 若盲目按固定倍数拉长，交互唤醒延迟就会变成 `divisor` 个 tick，直接破坏既有验收判据。
//! 因此正确做法是：**只在没有近期截止时刻时空闲拉长**，一旦有任务要在这个窗口内醒来，
//! 就按最近的截止时刻安排下一次中断。
//!
//! 本模块只做这段纯决策，不碰硬件；调用方负责把结果交给 `arch::timer_set_next`。
//!
//! English summary:
//!   Pure decision logic for how far to push the next tick during idle, so that
//!   idle coalescing never delays a wake-up beyond its deadline.

/// 下一次定时器中断的安排。
/// How to arm the next timer interrupt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TickPlan {
    /// 保持每 tick 一次（有近期截止时刻，或未启用空闲合并）。
    Periodic,
    /// 往后推 `ticks` 个 tick 再中断（1 = 与周期等价）。
    OneShot(u32),
}

/// 规划下一次中断。
///
/// 输入：
/// * `deadline`：本处理器上最近的唤醒时刻（`None` 表示没有任务在等）；
/// * `now`：当前 tick；
/// * `idle_divisor`：空闲时允许的最大间隔（<2 表示不做合并）。
///
/// 规则（按顺序）：
/// 1. 未启用合并（`idle_divisor < 2`）⇒ 周期；
/// 2. 没有等待者 ⇒ 一次性推迟 `idle_divisor`；
/// 3. 最近的截止时刻在 `idle_divisor` 之内 ⇒ 周期（不能为了省电而迟到）；
/// 4. 否则推迟到"不超过截止时刻"的最大值。
///
/// English: plan the next tick without ever overshooting a wake-up deadline.
/// 带「本核是否有人在按 tick 驱动工作」的规划。
///
/// 这条约束来自实测：把二级核的 tick 拉长后，分片服务与设备记账的进展被拖住
/// （SMP-3 出现「有核没有参与处理」「风暴下任务几乎没进展」）。
/// 因此只要本核上存在按 tick 推进的工作，就必须保持每秒一次的节奏。
/// English: keep the periodic tick while any tick-driven work lives on this CPU.
pub fn plan_with(now: u64, deadline: Option<u64>, idle_divisor: u32, needs_periodic: bool) -> TickPlan {
    if needs_periodic {
        return TickPlan::Periodic;
    }
    plan(now, deadline, idle_divisor)
}

pub fn plan(now: u64, deadline: Option<u64>, idle_divisor: u32) -> TickPlan {
    if idle_divisor < 2 {
        return TickPlan::Periodic;
    }
    let Some(deadline) = deadline else {
        return TickPlan::OneShot(idle_divisor);
    };
    let gap = deadline.saturating_sub(now);
    if gap <= 1 {
        return TickPlan::Periodic;
    }
    let ahead = gap.min(idle_divisor as u64);
    if ahead <= 1 {
        TickPlan::Periodic
    } else {
        TickPlan::OneShot(ahead as u32)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn disabled_divisor_keeps_periodic() {
        assert_eq!(plan(10, None, 1), TickPlan::Periodic);
        assert_eq!(plan(10, Some(100), 0), TickPlan::Periodic);
    }

    #[test]
    fn no_waiter_coalesces_to_divisor() {
        assert_eq!(plan(10, None, 4), TickPlan::OneShot(4));
    }

    #[test]
    fn imminent_deadline_forces_periodic() {
        assert_eq!(plan(10, Some(11), 4), TickPlan::Periodic, "下一 tick 就要醒来");
        assert_eq!(plan(10, Some(10), 4), TickPlan::Periodic, "已经到期");
    }

    #[test]
    fn deadline_inside_window_caps_the_gap() {
        assert_eq!(plan(10, Some(13), 4), TickPlan::OneShot(3));
    }

    #[test]
    fn far_deadline_uses_full_divisor() {
        assert_eq!(plan(10, Some(1000), 4), TickPlan::OneShot(4));
    }

    #[test]
    fn tick_consumers_force_periodic() {
        // 本核有按 tick 推进的工作时，即便没有任何等待者也必须保持周期 tick。
        assert_eq!(plan_with(0, None, 8, true), TickPlan::Periodic);
        assert_eq!(plan_with(0, Some(1000), 8, true), TickPlan::Periodic);
        // 没有这类工作时才允许合并。
        assert_eq!(plan_with(0, None, 8, false), TickPlan::OneShot(8));
    }

    #[test]
    fn never_overshoots_the_deadline() {
        for divisor in 2..=8u32 {
            for gap in 0..=20u64 {
                let p = plan(0, Some(gap), divisor);
                if let TickPlan::OneShot(n) = p {
                    assert!(n as u64 <= gap.max(1), "推迟 {n} 超过截止 {gap}");
                }
            }
        }
    }
}
