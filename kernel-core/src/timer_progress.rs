//! 定时器中断的前进保证：调度事务的开销不能吃满处理器。
//! Forward-progress guarantee for timer interrupts.
//!
//! 一次定时器事务要做全局记账与重新编程。处理器相对时钟很慢时（虚拟处理器被宿主挤占、纯解释执行），
//! 事务开销可以超过事件间隔：中断返回时下一个已经挂起，被打断的代码一条指令也执行不了。
//! 窗口：上一次完整事务结束到这次事件的时间。窗口不足上一次事务开销（超过 `cap` 时按 `cap`）算一次「短窗口」。
//! 规则：连续 [`GRACE`] 次短窗口之后才算活锁，此后事件不做事务，只由调用方推进时钟并记下欠账，直到窗口够长。
//! 因此连续 `GRACE + 1` 次完整事务之中，至少有一次之前留出了足够的时间给其他代码。
//! 偶尔一次短窗口（两个定时源碰巧挨着、事务中途被宿主换下）不推迟，精确事件不受影响。
//!
//! 时钟单位由调用方决定，这里只比较差值。时钟倒退时放行，时钟异常不能让定时器停摆。

/// 一次结算最多补记的 tick 数；再多的欠账丢弃，不让补记本身变成新的长事务。
/// Most deferred ticks settled at once.
pub const MAX_SETTLE: u32 = 64;

/// 允许连续多少次短窗口的完整事务。
/// Consecutive short windows tolerated before events are deferred.
pub const GRACE: u32 = 2;

/// 一个处理器的前进状态。只由该处理器在关中断时访问。
/// One processor's progress state.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Progress {
    /// 上一次完整事务结束的时刻。
    pub last_exit: u64,
    /// 上一次完整事务的开销（不超过记录时的 `cap`）。
    pub cost: u64,
    /// 尚未补记的 tick 数。
    pub deferred: u32,
    /// 连续短窗口的完整事务数（不超过 [`GRACE`]）。
    pub short: u32,
}

impl Progress {
    /// 窗口还差多少才够长；0 表示已经够长。
    /// Time left until the window since the last transaction is long enough.
    pub fn remaining(&self, now: u64) -> u64 {
        if now < self.last_exit {
            return 0;
        }
        let window = now - self.last_exit;
        if window >= self.cost { 0 } else { self.cost - window }
    }

    /// 这次事件能否做完整事务。
    /// Whether this event may run a full transaction.
    pub fn admit(&self, now: u64) -> bool {
        self.short < GRACE || self.remaining(now) == 0
    }

    /// 记录一次完整事务（`entry` 须是放行时的时刻）；开销按 `cap` 封顶（事务中途被宿主换下时，读到的开销不代表真实工作量）。
    /// Record a full transaction; the cost is capped.
    pub fn record(&mut self, entry: u64, exit: u64, cap: u64) {
        self.short = if self.remaining(entry) != 0 && self.short < GRACE { self.short + 1 } else { 0 };
        let cost = if exit >= entry { exit - entry } else { 0 };
        self.cost = if cost > cap { cap } else { cost };
        self.last_exit = exit;
    }

    /// 记下一个推迟的 tick。
    /// Note one deferred tick.
    pub fn defer(&mut self) {
        if self.deferred < u32::MAX {
            self.deferred += 1;
        }
    }

    /// 取走欠账（不超过 [`MAX_SETTLE`]），欠账清零。
    /// Take the deferred ticks (at most [`MAX_SETTLE`]).
    pub fn take_deferred(&mut self) -> u32 {
        let n = if self.deferred > MAX_SETTLE { MAX_SETTLE } else { self.deferred };
        self.deferred = 0;
        n
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn short_windows_are_refused_after_grace() {
        let mut p = Progress::default();
        p.record(100, 150, u64::MAX);
        assert_eq!(p.remaining(150), 50);
        for i in 0..GRACE as u64 {
            assert!(p.admit(150 + i * 60));
            p.record(150 + i * 60, 200 + i * 60, u64::MAX);
        }
        let last = 150 + (GRACE as u64 - 1) * 60 + 50;
        assert_eq!(p.short, GRACE);
        assert!(!p.admit(last + 49));
        assert!(p.admit(last + 50));
        p.record(last + 50, last + 60, u64::MAX);
        assert_eq!(p.short, 0);
    }

    #[test]
    fn cap_bounds_the_wait() {
        let mut p = Progress::default();
        p.record(0, 1_000_000, 10);
        assert_eq!(p.cost, 10);
        assert!(p.admit(1_000_010));
    }

    #[test]
    fn clock_anomalies_fail_open() {
        let mut p = Progress::default();
        p.record(500, 100, 1000);
        assert_eq!(p.cost, 0);
        p.record(100, 200, 1000);
        p.short = GRACE;
        assert!(p.admit(50));
    }

    #[test]
    fn deferred_is_bounded_and_cleared() {
        let mut p = Progress { deferred: u32::MAX, ..Progress::default() };
        p.defer();
        assert_eq!(p.deferred, u32::MAX);
        assert_eq!(p.take_deferred(), MAX_SETTLE);
        assert_eq!(p.take_deferred(), 0);
    }
}
