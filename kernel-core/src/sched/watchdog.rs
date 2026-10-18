//! 调度看门狗：记录长时间不主动让出处理器的任务。
//! Scheduler watchdog: records tasks that run for a long time without voluntarily giving up the CPU.
//!
//! # 职责边界
//! 只做**判定与记录**，不杀任务、不改档位：过载时如何处置（限速、降档、终止）是策略层与管理者的事，
//! 看门狗提供的是「谁、连续占用了多久、在什么时刻」的结构化证据。
//!
//! # 「连续占用」怎么算
//! 每个任务一份 [`RunStreak`]：它每运行一个 tick 加一；任务**主动**放弃处理器（睡眠、阻塞等待、
//! 主动让出、退出）时清零。被时间片抢占、被更高档抢占、被限速都**不**清零——吃满 CPU 的任务即使
//! 被频繁换下，它的连续占用照样累积，这正是要抓的对象。每段连续占用只报告一次（越过阈值的那一刻）。
//!
//! 报告保存在定长环形日志 [`WatchdogLog`] 里（无分配，可在时钟中断中写入），满了覆盖最旧的一条，
//! 总数另计，读者据此知道有没有丢。

/// 一个任务的连续占用记录。
/// Per-task streak of CPU ticks since the last voluntary yield.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct RunStreak {
    ticks: u32,
    reported: bool,
}

impl RunStreak {
    /// 新记录（零占用）。
    pub const fn new() -> Self {
        RunStreak { ticks: 0, reported: false }
    }

    /// 当前连续占用的 tick 数。
    pub const fn ticks(&self) -> u32 {
        self.ticks
    }
}

/// 看门狗判定器（阈值可配置）。
/// Watchdog judge with a configurable threshold.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Watchdog {
    threshold: u32,
}

impl Watchdog {
    /// 阈值（tick）至少为 1。
    pub const fn new(threshold: u32) -> Self {
        Watchdog { threshold: if threshold == 0 { 1 } else { threshold } }
    }

    /// 生效阈值。
    pub const fn threshold(&self) -> u32 {
        self.threshold
    }

    /// 任务运行了一个 tick：记账，刚越过阈值时返回这段连续占用的长度（只返回一次）。
    /// Charges one tick; returns the streak length the moment it crosses the threshold.
    pub fn charge(&self, s: &mut RunStreak) -> Option<u32> {
        s.ticks = s.ticks.saturating_add(1);
        if !s.reported && s.ticks >= self.threshold {
            s.reported = true;
            Some(s.ticks)
        } else {
            None
        }
    }

    /// 任务主动放弃处理器：连续占用清零，下一段重新判定。
    /// The task voluntarily gave up the CPU: reset its streak.
    pub fn yielded(&self, s: &mut RunStreak) {
        *s = RunStreak::new();
    }
}

/// 一条看门狗报告。
/// One watchdog report.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WatchdogReport {
    /// 任务标识（调用者定义的编号）。
    pub task: u64,
    /// 任务名。
    pub name: &'static str,
    /// 报告时的连续占用（tick）。
    pub streak: u32,
    /// 报告时刻（tick）。
    pub at: u64,
}

/// 定长环形报告日志（`N` ≥ 1）。
/// Fixed-size ring of watchdog reports.
#[derive(Debug, Clone, Copy)]
pub struct WatchdogLog<const N: usize> {
    entries: [Option<WatchdogReport>; N],
    next: usize,
    total: u64,
}

impl<const N: usize> WatchdogLog<N> {
    /// 空日志。
    pub const fn new() -> Self {
        WatchdogLog { entries: [None; N], next: 0, total: 0 }
    }

    /// 追加一条（满了覆盖最旧的）。
    pub fn push(&mut self, r: WatchdogReport) {
        if N == 0 {
            self.total += 1;
            return;
        }
        self.entries[self.next] = Some(r);
        self.next = (self.next + 1) % N;
        self.total += 1;
    }

    /// 累计报告数（含已被覆盖的）。
    pub const fn total(&self) -> u64 {
        self.total
    }

    /// 是否有任务 `task` 的报告仍在日志中。
    pub fn mentions(&self, task: u64) -> bool {
        self.entries.iter().flatten().any(|r| r.task == task)
    }

    /// 日志中的报告（从旧到新）。
    pub fn iter(&self) -> impl Iterator<Item = &WatchdogReport> {
        let (newer, older) = self.entries.split_at(self.next);
        older.iter().chain(newer.iter()).flatten()
    }

    /// 清空（每个测量场景开始前调用）。
    pub fn clear(&mut self) {
        *self = Self::new();
    }
}

impl<const N: usize> Default for WatchdogLog<N> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reports_once_per_streak_and_resets_on_yield() {
        let w = Watchdog::new(5);
        let mut s = RunStreak::new();
        let hits: Vec<_> = (0..20).filter_map(|_| w.charge(&mut s)).collect();
        assert_eq!(hits, vec![5], "每段连续占用只报告一次");
        assert_eq!(s.ticks(), 20);
        w.yielded(&mut s);
        assert_eq!(s.ticks(), 0);
        let again: Vec<_> = (0..5).filter_map(|_| w.charge(&mut s)).collect();
        assert_eq!(again, vec![5], "主动让出后重新判定");
    }

    #[test]
    fn short_bursts_never_reported() {
        let w = Watchdog::new(8);
        let mut s = RunStreak::new();
        for _ in 0..1000 {
            for _ in 0..7 {
                assert_eq!(w.charge(&mut s), None);
            }
            w.yielded(&mut s);
        }
        assert_eq!(Watchdog::new(0).threshold(), 1, "阈值 0 视为 1");
    }

    #[test]
    fn log_wraps_and_counts_total() {
        let mut log: WatchdogLog<3> = WatchdogLog::new();
        for i in 0..5u64 {
            log.push(WatchdogReport { task: i, name: "t", streak: 10, at: i });
        }
        assert_eq!(log.total(), 5);
        let kept: Vec<u64> = log.iter().map(|r| r.task).collect();
        assert_eq!(kept, vec![2, 3, 4], "满了覆盖最旧的，按旧到新输出");
        assert!(log.mentions(4) && !log.mentions(0));
        log.clear();
        assert_eq!((log.total(), log.iter().count()), (0, 0));
    }
}
