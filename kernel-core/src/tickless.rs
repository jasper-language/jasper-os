//! 空闲停表（tickless idle）的纯机制：下一次定时器中断的规划，与「哪些处理器停了表」的登记。
//! Pure mechanisms of tickless idle: planning the next timer interrupt and the stopped-CPU board.
//!
//! # 职责
//! * [`plan`] / [`plan_with`] —— 决定空闲处理器的下一次本地定时器中断推迟多少个 tick：
//!   有近期截止时刻或本核还有按 tick 推进的工作时保持周期，否则按配置的倍数推迟，且永不越过截止时刻。
//! * [`StopBoard`] —— 登记停表的处理器、停表起点（全局 tick 与本地已记账 tick），
//!   重新开表时算出「停表期间没有被本地 tick 记账的空闲时长」，让调度统计不因停表而失真。
//!
//! # 边界
//! 不碰硬件、不持锁：调用者（调度器）在自己的锁内调用，并负责把规划交给平台的定时器接口。
//! 计时处理器（推进全局时间、处理到期唤醒的那一个）永远不停表，登记会拒绝它。
//!
//! # 为什么这样分
//! 停表的正确性取决于两件事：不越过截止时刻（唤醒延迟有上界），以及停表期间出现的工作一定有人
//! 叫醒停表的处理器（空闲等待有上界）。前者是这里的纯函数，后者由调度器在计时处理器的每个 tick
//! 查询 [`StopBoard::stopped`] 并对有工作可接的处理器发重新调度请求来保证。两者都与指令集无关，放在这里宿主可测。
//!
//! English summary:
//!   Pure decision logic for how far to push an idle CPU's next tick, plus the board that
//!   records which CPUs stopped their tick so the scheduler can wake them and keep honest stats.

use crate::smp::{CpuSet, MAX_CPUS};

/// 下一次定时器中断的安排。
/// How to arm the next timer interrupt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TickPlan {
    /// 保持每 tick 一次（有近期截止时刻、本核有按 tick 推进的工作，或未启用空闲合并）。
    Periodic,
    /// 往后推 `ticks` 个 tick 再中断（总是 ≥ 2）。
    OneShot(u32),
}

/// 规划空闲处理器的下一次中断。
///
/// 输入：`now` 为当前 tick；`deadline` 为本处理器上最近的唤醒时刻（`None` 表示没有）；
/// `idle_divisor` 为空闲时允许的最大间隔（< 2 表示不做合并）。
///
/// 规则（按顺序）：
/// 1. 未启用合并（`idle_divisor < 2`）⇒ 周期；
/// 2. 没有截止时刻 ⇒ 一次性推迟 `idle_divisor`；
/// 3. 截止时刻在下一个 tick 之内 ⇒ 周期（不能为了省电而迟到）；
/// 4. 否则推迟到「不超过截止时刻」的最大值。
///
/// English: plan the next tick without ever overshooting a wake-up deadline.
pub fn plan(now: u64, deadline: Option<u64>, idle_divisor: u32) -> TickPlan {
    if idle_divisor < 2 {
        return TickPlan::Periodic;
    }
    let Some(deadline) = deadline else {
        return TickPlan::OneShot(idle_divisor);
    };
    let ahead = deadline.saturating_sub(now).min(idle_divisor as u64);
    if ahead <= 1 {
        TickPlan::Periodic
    } else {
        TickPlan::OneShot(ahead as u32)
    }
}

/// 带「本核是否还有按 tick 推进的工作」的规划：有就必须保持周期 tick。
///
/// 这类工作包括被预算节流、只在本核下一个 tick 才解除屏蔽的设备中断线等：
/// 停表会把它们的恢复推迟到停表结束，表现为「设备中断超预算、风暴下任务无进展」。
/// English: keep the periodic tick while any tick-driven work lives on this CPU.
pub fn plan_with(now: u64, deadline: Option<u64>, idle_divisor: u32, needs_periodic: bool) -> TickPlan {
    if needs_periodic {
        return TickPlan::Periodic;
    }
    plan(now, deadline, idle_divisor)
}

/// 停表登记被拒绝的原因（被拒绝时登记不变）。
/// Why a stop was refused; the board is left unchanged.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StopError {
    /// 处理器下标超出容量。
    NoSuchCpu,
    /// 计时处理器永不停表（全局时间与到期唤醒靠它推进）。
    Timekeeper,
    /// 该处理器已经停表。
    AlreadyStopped,
}

impl StopError {
    /// 规范名。
    /// Canonical name.
    pub const fn name(self) -> &'static str {
        match self {
            StopError::NoSuchCpu => "system.cpu.error.no_such_cpu",
            StopError::Timekeeper => "system.cpu.error.timekeeper",
            StopError::AlreadyStopped => "system.cpu.error.already_stopped",
        }
    }
}

/// 停表处理器的登记（由调度器在自己的锁内持有）。
/// Board of processors whose periodic tick is stopped.
#[derive(Debug, Clone, Copy)]
pub struct StopBoard {
    timekeeper: usize,
    stopped: CpuSet,
    /// 停表时的全局 tick。
    since: [u64; MAX_CPUS],
    /// 停表时该处理器已记账的本地 tick 数。
    local_at: [u64; MAX_CPUS],
    stops: u64,
    restarts: u64,
}

impl StopBoard {
    /// 新登记：`timekeeper` 为计时处理器的下标。
    /// New board; `timekeeper` never stops its tick.
    pub const fn new(timekeeper: usize) -> StopBoard {
        StopBoard { timekeeper, stopped: CpuSet::EMPTY, since: [0; MAX_CPUS], local_at: [0; MAX_CPUS], stops: 0, restarts: 0 }
    }

    /// 登记处理器 `cpu` 停表：`now` 为全局 tick，`local` 为它已记账的本地 tick 数。
    /// 计时处理器、越界下标、重复停表被拒绝，登记不变。
    /// Record that `cpu` stopped its tick.
    pub fn stop(&mut self, cpu: usize, now: u64, local: u64) -> Result<(), StopError> {
        if cpu >= MAX_CPUS {
            return Err(StopError::NoSuchCpu);
        }
        if cpu == self.timekeeper {
            return Err(StopError::Timekeeper);
        }
        if self.stopped.contains(cpu) {
            return Err(StopError::AlreadyStopped);
        }
        self.stopped.insert(cpu);
        self.since[cpu] = now;
        self.local_at[cpu] = local;
        self.stops += 1;
        Ok(())
    }

    /// 处理器 `cpu` 重新开表：返回停表期间没有被本地 tick 记账的空闲 tick 数
    /// （全局经过的 tick 减去本地已记账的 tick，不为负）；它本来就没停表时返回 `None`，登记不变。
    /// Restart `cpu`'s tick; returns the idle ticks the local tick did not account.
    pub fn restart(&mut self, cpu: usize, now: u64, local: u64) -> Option<u64> {
        if !self.stopped.contains(cpu) {
            return None;
        }
        self.stopped.remove(cpu);
        self.restarts += 1;
        let elapsed = now.saturating_sub(self.since[cpu]);
        let accounted = local.saturating_sub(self.local_at[cpu]);
        Some(elapsed.saturating_sub(accounted))
    }

    /// 当前停表的处理器集合。
    /// Processors whose tick is stopped.
    pub const fn stopped(&self) -> CpuSet {
        self.stopped
    }

    /// 计时处理器下标。
    /// Index of the timekeeping processor.
    pub const fn timekeeper(&self) -> usize {
        self.timekeeper
    }

    /// 累计 (停表次数, 重新开表次数)。
    /// Cumulative (stops, restarts).
    pub const fn counts(&self) -> (u64, u64) {
        (self.stops, self.restarts)
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
                    assert!(n >= 2 && n as u64 <= gap, "推迟 {n} 超过截止 {gap}");
                }
            }
        }
    }

    #[test]
    fn stop_and_restart_report_unaccounted_idle() {
        let mut b = StopBoard::new(0);
        assert_eq!(b.stop(2, 100, 40), Ok(()));
        assert!(b.stopped().contains(2));
        // 全局走了 12 tick，本地只记了 3 个（停表期间的保底 tick）⇒ 补记 9 个空闲 tick
        assert_eq!(b.restart(2, 112, 43), Some(9));
        assert!(b.stopped().is_empty());
        assert_eq!(b.counts(), (1, 1));
    }

    #[test]
    fn restart_never_goes_negative() {
        let mut b = StopBoard::new(0);
        b.stop(1, 50, 10).unwrap();
        // 本地时钟比全局时钟快（两个时钟源相互独立）：补记 0，而不是回绕成巨大值
        assert_eq!(b.restart(1, 52, 15), Some(0));
        b.stop(1, 60, 15).unwrap();
        // 全局 tick 比停表时还小（不会发生，但不能回绕）
        assert_eq!(b.restart(1, 10, 15), Some(0));
    }

    #[test]
    fn refusals_leave_the_board_unchanged() {
        let mut b = StopBoard::new(0);
        assert_eq!(b.stop(0, 1, 1), Err(StopError::Timekeeper));
        assert_eq!(b.stop(MAX_CPUS, 1, 1), Err(StopError::NoSuchCpu));
        assert!(b.stopped().is_empty());
        assert_eq!(b.counts(), (0, 0));
        b.stop(3, 5, 5).unwrap();
        let before = (b.stopped(), b.counts());
        assert_eq!(b.stop(3, 9, 9), Err(StopError::AlreadyStopped));
        assert_eq!((b.stopped(), b.counts()), before);
        // 没停表的处理器重新开表：None，登记不变
        assert_eq!(b.restart(4, 9, 9), None);
        assert_eq!((b.stopped(), b.counts()), before);
        // 被拒绝的重复停表没有改写起点
        assert_eq!(b.restart(3, 9, 5), Some(4));
    }

    #[test]
    fn many_cpus_tracked_independently() {
        let mut b = StopBoard::new(0);
        for c in 1..MAX_CPUS {
            b.stop(c, c as u64, 0).unwrap();
        }
        assert_eq!(b.stopped().len(), MAX_CPUS - 1);
        for c in 1..MAX_CPUS {
            assert_eq!(b.restart(c, 100, 0), Some(100 - c as u64));
        }
        assert!(b.stopped().is_empty());
    }
}
