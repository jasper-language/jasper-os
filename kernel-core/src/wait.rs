//! 等待与通知：可等待对象（事件、定时器）+ 等待集合（`system.wait` 领域）。
//!
//! # 职责
//! * [`Waitable`]：「在时刻 `now` 是否已触发」的统一接口
//! * [`Event`]：手动复位事件（`signal` / `reset`）
//! * [`Timer`]：到期即触发的一次性定时器
//! * [`WaitSet`]：同时等多个对象，`wait_any` 返回第一个触发者或超时
//!
//! # 为什么这样设计
//! * **时间源抽象为 [`TimeSource`] trait**：内核注入定时器 tick，宿主测试注入假时钟，
//!   机制代码一行不改即可测试超时语义。
//! * **「怎么等」由调用者注入（`idle` 回调）**：内核里是「让出 CPU / 等中断」，测试里是推进
//!   假时钟。本模块因此不依赖调度器，也不碰任何 ISA 指令。
//! * 边界（纪律「async 只有 ring」）：这里是**同步阻塞**原语——线程等待对象被触发；
//!   它不是 I/O 就绪通知接口。异步 I/O 的唯一形态是 [`crate::io`] 的提交 → 完成，
//!   ring 的「等完成」将建立在本模块之上。
//! * 唤醒判定先于超时判定：同一轮里既触发又到期时返回 `Signaled`，避免丢失已发生的信号。

use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

/// 单调时间源（单位：tick，由提供者定义）。
pub trait TimeSource {
    /// 当前时刻。
    fn now(&self) -> u64;
}

/// 可等待对象。
pub trait Waitable {
    /// 在时刻 `now` 是否处于已触发状态。
    fn is_signaled(&self, now: u64) -> bool;
}

/// 手动复位事件：`signal` 后保持触发，直到 `reset`。可在中断上下文中 `signal`。
pub struct Event {
    signaled: AtomicBool,
}

impl Event {
    /// 新建（未触发）。
    pub const fn new() -> Self {
        Event { signaled: AtomicBool::new(false) }
    }

    /// 触发（`system.wait.signal`）。
    pub fn signal(&self) {
        self.signaled.store(true, Ordering::Release);
    }

    /// 复位为未触发。
    pub fn reset(&self) {
        self.signaled.store(false, Ordering::Release);
    }
}

impl Default for Event {
    fn default() -> Self {
        Self::new()
    }
}

impl Waitable for Event {
    fn is_signaled(&self, _now: u64) -> bool {
        self.signaled.load(Ordering::Acquire)
    }
}

/// 一次性定时器：到达截止时刻即触发。截止时刻 0 表示未设定。
pub struct Timer {
    deadline: AtomicU64,
}

impl Timer {
    /// 新建（未设定）。
    pub const fn new() -> Self {
        Timer { deadline: AtomicU64::new(0) }
    }

    /// 设定绝对截止时刻（必须 > 0）。
    pub fn arm_at(&self, deadline: u64) {
        self.deadline.store(deadline.max(1), Ordering::Release);
    }

    /// 设定相对截止时刻：`now + after`。
    pub fn arm_after(&self, now: u64, after: u64) {
        self.arm_at(now.saturating_add(after));
    }

    /// 取消。
    pub fn disarm(&self) {
        self.deadline.store(0, Ordering::Release);
    }
}

impl Default for Timer {
    fn default() -> Self {
        Self::new()
    }
}

impl Waitable for Timer {
    fn is_signaled(&self, now: u64) -> bool {
        let d = self.deadline.load(Ordering::Acquire);
        d != 0 && now >= d
    }
}

/// 等待结果。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WaitResult {
    /// 集合中下标为该值的对象已触发。
    Signaled(usize),
    /// 超时。
    Timeout,
}

/// 等待错误（`system.wait.error.*`）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WaitError {
    /// 等待集合已满。
    SetFull,
    /// 集合为空且没有超时：会永远阻塞，直接拒绝。
    WouldBlockForever,
}

impl WaitError {
    /// 规范错误名。
    pub const fn name(self) -> &'static str {
        match self {
            WaitError::SetFull => "system.wait.error.set_full",
            WaitError::WouldBlockForever => "system.wait.error.would_block_forever",
        }
    }
}

/// 最多 `N` 个对象的等待集合（借用对象，不拥有）。
pub struct WaitSet<'a, const N: usize> {
    members: [Option<&'a dyn Waitable>; N],
    len: usize,
}

impl<'a, const N: usize> WaitSet<'a, N> {
    /// 新建空集合。
    pub const fn new() -> Self {
        WaitSet { members: [None; N], len: 0 }
    }

    /// 加入一个对象，返回它在集合中的下标。
    pub fn add(&mut self, w: &'a dyn Waitable) -> Result<usize, WaitError> {
        let slot = self.members.get_mut(self.len).ok_or(WaitError::SetFull)?;
        *slot = Some(w);
        self.len += 1;
        Ok(self.len - 1)
    }

    /// 成员个数。
    pub fn len(&self) -> usize {
        self.len
    }

    /// 是否为空。
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// 非阻塞检查：返回第一个已触发成员的下标。
    pub fn poll(&self, now: u64) -> Option<usize> {
        self.members[..self.len].iter().position(|m| m.is_some_and(|w| w.is_signaled(now)))
    }

    /// 等任意一个成员触发，或超时（`timeout = None` 表示不限时）。
    ///
    /// 每轮检查都失败后调用一次 `idle`（让出 CPU / 等中断 / 推进假时钟）。
    pub fn wait_any(
        &self,
        clock: &dyn TimeSource,
        timeout: Option<u64>,
        mut idle: impl FnMut(),
    ) -> Result<WaitResult, WaitError> {
        if self.is_empty() && timeout.is_none() {
            return Err(WaitError::WouldBlockForever);
        }
        let deadline = timeout.map(|t| clock.now().saturating_add(t));
        loop {
            let now = clock.now();
            if let Some(i) = self.poll(now) {
                return Ok(WaitResult::Signaled(i));
            }
            if deadline.is_some_and(|d| now >= d) {
                return Ok(WaitResult::Timeout);
            }
            idle();
        }
    }
}

impl<const N: usize> Default for WaitSet<'_, N> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::cell::Cell;

    /// 假时钟：测试里由 `idle` 推进。
    struct FakeClock(Cell<u64>);
    impl TimeSource for FakeClock {
        fn now(&self) -> u64 {
            self.0.get()
        }
    }

    #[test]
    fn event_signal_and_reset() {
        let e = Event::new();
        assert!(!e.is_signaled(0));
        e.signal();
        assert!(e.is_signaled(0));
        e.reset();
        assert!(!e.is_signaled(0));
    }

    #[test]
    fn timer_fires_at_deadline() {
        let t = Timer::new();
        assert!(!t.is_signaled(u64::MAX), "未设定的定时器不触发");
        t.arm_after(10, 5);
        assert!(!t.is_signaled(14));
        assert!(t.is_signaled(15));
        t.disarm();
        assert!(!t.is_signaled(100));
    }

    #[test]
    fn wait_any_returns_first_signaled() {
        let clock = FakeClock(Cell::new(0));
        let (a, b) = (Event::new(), Event::new());
        let mut ws: WaitSet<2> = WaitSet::new();
        ws.add(&a).unwrap();
        ws.add(&b).unwrap();
        let mut rounds = 0;
        let r = ws.wait_any(&clock, None, || {
            rounds += 1;
            if rounds == 3 {
                b.signal();
            }
        });
        assert_eq!(r, Ok(WaitResult::Signaled(1)));
        assert_eq!(rounds, 3);
    }

    #[test]
    fn wait_any_times_out() {
        let clock = FakeClock(Cell::new(100));
        let e = Event::new();
        let mut ws: WaitSet<1> = WaitSet::new();
        ws.add(&e).unwrap();
        let r = ws.wait_any(&clock, Some(4), || clock.0.set(clock.0.get() + 1));
        assert_eq!(r, Ok(WaitResult::Timeout));
        assert_eq!(clock.now(), 104);
    }

    #[test]
    fn timer_in_waitset_wins_over_timeout_when_simultaneous() {
        let clock = FakeClock(Cell::new(0));
        let t = Timer::new();
        t.arm_at(3);
        let mut ws: WaitSet<1> = WaitSet::new();
        ws.add(&t).unwrap();
        let r = ws.wait_any(&clock, Some(3), || clock.0.set(clock.0.get() + 1));
        assert_eq!(r, Ok(WaitResult::Signaled(0)), "同时满足时信号优先");
    }

    #[test]
    fn waitset_limits() {
        let clock = FakeClock(Cell::new(0));
        let e = Event::new();
        let mut ws: WaitSet<1> = WaitSet::new();
        assert_eq!(ws.wait_any(&clock, None, || {}), Err(WaitError::WouldBlockForever));
        ws.add(&e).unwrap();
        assert_eq!(ws.add(&e), Err(WaitError::SetFull));
        assert_eq!(WaitError::SetFull.name(), "system.wait.error.set_full");
    }
}
