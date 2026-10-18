//! CPU 上限（每组一份令牌桶）：失控的进程被限速，而不是拖垮整机。
//! Per-group CPU limit (token bucket): a runaway process is throttled instead of starving the machine.
//!
//! # 职责边界
//! 本模块只做**记账与判定**：一组（通常是一个进程的全部线程）在每个 tick 得到 `limit_permille`
//! 份令牌，运行一个 tick 花掉 [`TICK_COST`] 份；令牌不为正时该组「被限速」，调度机制不再选它的成员。
//! 组与任务的对应关系、组的生命周期由内核调度机制维护；这里不知道任务表长什么样，因此可在宿主上
//! 逐 tick 确定性模拟。
//!
//! # 为什么是令牌桶
//! * **长期上限精确**：任意长度 T 个 tick 内，组的运行 tick 数不超过 `T × limit / 1000 + burst + 1`
//!   （见 [`CpuLimit::bound`]），与组内有多少线程无关——多开线程不能绕过上限。
//! * **允许短突发**：桶容量 `burst` 个 tick，偶发的短任务不被限速打断。
//! * **O(1)、无分配**：每 tick 一次加减，适合在时钟中断里调用。
//!
//! 上限是**硬上限**：即使处理器空闲，被限速的组也要等令牌回到正数（这正是「可配置的上限」的语义；
//! 不想要硬上限的组用 [`UNLIMITED`]）。被借出档位的成员（优先级继承中的持有者）由调度机制豁免，
//! 以免限速把高档等待者也拖住。

/// 一个 tick 的令牌数（千分比的分母）。
pub const TICK_COST: i32 = 1000;
/// 不限速（千分之一千 = 整个处理器）。
pub const UNLIMITED: u32 = 1000;
/// 桶容量的上限（tick）：再大的突发会让「上限」在短窗口内失去意义。
pub const MAX_BURST_TICKS: u32 = 64;

/// 配置 CPU 上限失败的原因。失败时原有配置不变。
/// Why a CPU-limit configuration was refused; the previous configuration stays.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LimitError {
    /// 上限不在 `1..=1000` 千分比之内（0 会让组永远无法运行）。
    InvalidLimit,
    /// 桶容量不在 `1..=MAX_BURST_TICKS` 之内。
    InvalidBurst,
}

/// 一组的 CPU 上限与记账。
/// CPU limit and accounting of one group.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CpuLimit {
    limit_permille: u32,
    burst_ticks: u32,
    /// 令牌余额（可为负：运行一个 tick 后才扣费，最多欠一个 tick）。
    tokens: i32,
    used_ticks: u64,
    throttled_ticks: u64,
    throttle_events: u64,
    throttled: bool,
}

/// 一组 CPU 记账的快照（诊断与验收）。
/// Snapshot of a group's CPU accounting.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct CpuLimitStats {
    /// 上限（千分比）。
    pub limit_permille: u32,
    /// 桶容量（tick）。
    pub burst_ticks: u32,
    /// 组内成员累计运行的 tick 数。
    pub used_ticks: u64,
    /// 组内有成员想运行却因限速不能运行的 tick 数。
    pub throttled_ticks: u64,
    /// 从「可运行」变为「被限速」的次数。
    pub throttle_events: u64,
    /// 当前是否被限速。
    pub throttled: bool,
}

impl CpuLimit {
    /// 以上限（千分比）与桶容量（tick）构造；桶初始为满。
    /// Builds a limit; the bucket starts full.
    pub const fn new(limit_permille: u32, burst_ticks: u32) -> Result<Self, LimitError> {
        if limit_permille == 0 || limit_permille > UNLIMITED {
            return Err(LimitError::InvalidLimit);
        }
        if burst_ticks == 0 || burst_ticks > MAX_BURST_TICKS {
            return Err(LimitError::InvalidBurst);
        }
        Ok(CpuLimit {
            limit_permille,
            burst_ticks,
            tokens: burst_ticks as i32 * TICK_COST,
            used_ticks: 0,
            throttled_ticks: 0,
            throttle_events: 0,
            throttled: false,
        })
    }

    /// 修改上限（桶容量不变）；非法值被拒且原配置不变。令牌余额截到新容量内。
    /// Changes the limit; invalid values are refused without side effects.
    pub fn set_limit(&mut self, limit_permille: u32) -> Result<(), LimitError> {
        if limit_permille == 0 || limit_permille > UNLIMITED {
            return Err(LimitError::InvalidLimit);
        }
        self.limit_permille = limit_permille;
        if limit_permille >= UNLIMITED {
            self.throttled = false;
        }
        Ok(())
    }

    /// 当前上限（千分比）。
    pub const fn limit_permille(&self) -> u32 {
        self.limit_permille
    }

    /// 组内成员现在能否被选中运行。
    /// Whether members of this group may run now.
    pub const fn eligible(&self) -> bool {
        self.limit_permille >= UNLIMITED || self.tokens > 0
    }

    /// 每个时钟 tick 调用一次：`ran` = 刚过去的这个 tick 是否由本组成员运行；
    /// `wants` = 本组是否还有成员可运行（用于统计被限速的 tick）。先扣费、再补充令牌。
    /// Per-tick accounting: charge the tick just run, then refill.
    pub fn on_tick(&mut self, ran: bool, wants: bool) {
        if ran {
            self.used_ticks += 1;
            self.tokens -= TICK_COST;
        }
        let cap = self.burst_ticks as i32 * TICK_COST;
        self.tokens = (self.tokens + self.limit_permille as i32).min(cap);
        let now_throttled = !self.eligible();
        if now_throttled && !self.throttled {
            self.throttle_events += 1;
        }
        if now_throttled && wants {
            self.throttled_ticks += 1;
        }
        self.throttled = now_throttled;
    }

    /// 长度为 `window` 个 tick 的任意窗口内，本组最多能运行的 tick 数（验收判据）。
    /// Upper bound on ticks this group can run in any window of `window` ticks.
    pub const fn bound(&self, window: u64) -> u64 {
        if self.limit_permille >= UNLIMITED {
            return window;
        }
        (window * self.limit_permille as u64).div_ceil(1000) + self.burst_ticks as u64 + 1
    }

    /// 记账快照。
    pub const fn stats(&self) -> CpuLimitStats {
        CpuLimitStats {
            limit_permille: self.limit_permille,
            burst_ticks: self.burst_ticks,
            used_ticks: self.used_ticks,
            throttled_ticks: self.throttled_ticks,
            throttle_events: self.throttle_events,
            throttled: self.throttled,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_invalid_configuration_without_change() {
        assert_eq!(CpuLimit::new(0, 4), Err(LimitError::InvalidLimit));
        assert_eq!(CpuLimit::new(1001, 4), Err(LimitError::InvalidLimit));
        assert_eq!(CpuLimit::new(500, 0), Err(LimitError::InvalidBurst));
        assert_eq!(CpuLimit::new(500, MAX_BURST_TICKS + 1), Err(LimitError::InvalidBurst));
        let mut l = CpuLimit::new(300, 4).unwrap();
        let before = l;
        assert_eq!(l.set_limit(0), Err(LimitError::InvalidLimit));
        assert_eq!(l.set_limit(5000), Err(LimitError::InvalidLimit));
        assert_eq!(l, before, "被拒的修改不得留下改动");
    }

    /// 一直想运行的组：任意窗口内运行 tick 数不超过上界，长期比例趋近上限。
    #[test]
    fn greedy_group_stays_within_bound() {
        for limit in [50u32, 250, 500, 900] {
            let mut l = CpuLimit::new(limit, 4).unwrap();
            let mut ran_log = Vec::new();
            for _ in 0..4000 {
                let ran = l.eligible();
                l.on_tick(ran, true);
                ran_log.push(ran as u64);
            }
            for window in [10usize, 37, 100, 1000] {
                for start in (0..ran_log.len() - window).step_by(7) {
                    let used: u64 = ran_log[start..start + window].iter().sum();
                    assert!(used <= l.bound(window as u64), "limit={} window={} used={}", limit, window, used);
                }
            }
            let total = l.stats().used_ticks;
            let expect = 4000 * limit as u64 / 1000;
            assert!(total + 2 >= expect && total <= expect + 5, "limit={} total={} expect={}", limit, total, expect);
            assert!(l.stats().throttle_events > 0 && l.stats().throttled_ticks > 0);
        }
    }

    /// 不想运行时不被统计为限速；空闲期令牌只补到桶容量（不会攒出长时间独占）。
    #[test]
    fn idle_group_refills_only_up_to_burst() {
        let mut l = CpuLimit::new(100, 3).unwrap();
        for _ in 0..1000 {
            l.on_tick(false, false);
        }
        assert_eq!(l.stats().throttled_ticks, 0);
        let mut run = 0;
        while l.eligible() {
            l.on_tick(true, true);
            run += 1;
        }
        assert!(run <= 4, "空闲后最多突发桶容量 + 1 个 tick，实际 {}", run);
    }

    /// 不限速的组永远可运行、从不计限速。
    #[test]
    fn unlimited_never_throttles() {
        let mut l = CpuLimit::new(UNLIMITED, 1).unwrap();
        for _ in 0..500 {
            assert!(l.eligible());
            l.on_tick(true, true);
        }
        let s = l.stats();
        assert_eq!((s.used_ticks, s.throttled_ticks, s.throttle_events, s.throttled), (500, 0, 0, false));
        assert_eq!(l.bound(77), 77);
    }

    /// 放宽上限后立即解除限速；收紧后按新上限计。
    #[test]
    fn changing_limit_takes_effect() {
        let mut l = CpuLimit::new(100, 1).unwrap();
        while l.eligible() {
            l.on_tick(true, true);
        }
        assert!(l.set_limit(UNLIMITED).is_ok());
        assert!(l.eligible() && !l.stats().throttled);
        assert!(l.set_limit(200).is_ok());
        let mut used = 0;
        for _ in 0..1000 {
            let r = l.eligible();
            l.on_tick(r, true);
            used += r as u64;
        }
        assert!(used <= l.bound(1000));
    }
}
