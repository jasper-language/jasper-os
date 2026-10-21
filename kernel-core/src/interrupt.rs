//! 设备中断对象的纯状态机：到达计数、至多一个未完成的等待、绑定 / 关闭两态。
//! Pure state machine of a device-interrupt object: arrival count, at most one outstanding wait, bound/closed.
//!
//! # 职责
//! * 记录「已到达但尚未交付」的次数（饱和计数，不溢出）。
//! * 至多登记一个等待者：到达时有等待者 ⇒ 把累计次数一次交付给它并清零；没有 ⇒ 累加。
//! * 提交等待时已有累计次数 ⇒ 立即以该次数完成；已有等待者 ⇒ 拒绝（忙）；已关闭 ⇒ 拒绝。
//! * 取消等待只移除等待登记，已到达的次数保留到下一次等待；关闭交出未完成的等待者，由调用者以「已关闭」终态完成它。
//!
//! # 边界与原因
//! * 不认识向量、处理器、设备寄存器或 Ring：等待者只是调用者给出的不透明令牌 `T`，
//!   交付与终态的投递由内核侧负责。这样同一份规则既能在宿主上确定性测试，又不把任何硬件细节带进 Core。
//! * 每个方法要么完整成功，要么返回错误且状态不变（失败路径无残留改动）。

/// 等待提交被拒的原因。
/// Why a wait submission was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WaitError {
    /// 已有一个未完成的等待。
    /// Another wait is already outstanding.
    Busy,
    /// 中断对象已关闭。
    /// The interrupt object is closed.
    Closed,
}

impl WaitError {
    /// 规范名（日志用）。
    /// Canonical name.
    pub const fn name(self) -> &'static str {
        match self {
            WaitError::Busy => "interrupt_busy",
            WaitError::Closed => "interrupt_closed",
        }
    }
}

/// 一次等待提交的结果。
/// Outcome of a wait submission.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Submitted {
    /// 已有到达：立即以该次数完成（计数已清零，等待者未登记）。
    /// Arrivals were pending: the wait completes at once with this count.
    Ready(u32),
    /// 尚无到达：等待者已登记，下次到达时交付。
    /// Nothing pending: the waiter is parked until the next arrival.
    Parked,
}

/// 设备中断对象的状态。
/// State of one device-interrupt object.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InterruptLine<T: Copy + PartialEq> {
    pending: u32,
    waiter: Option<T>,
    closed: bool,
    delivered: u64,
}

impl<T: Copy + PartialEq> Default for InterruptLine<T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T: Copy + PartialEq> InterruptLine<T> {
    /// 新绑定的中断对象：无到达、无等待者。
    /// A freshly bound line with nothing pending and no waiter.
    pub const fn new() -> Self {
        InterruptLine { pending: 0, waiter: None, closed: false, delivered: 0 }
    }

    /// 已到达但尚未交付的次数。
    /// Arrivals not yet handed to a waiter.
    pub const fn pending(&self) -> u32 {
        self.pending
    }

    /// 当前登记的等待者。
    /// The parked waiter, if any.
    pub const fn waiter(&self) -> Option<T> {
        self.waiter
    }

    /// 是否已关闭。
    /// Whether the line is closed.
    pub const fn is_closed(&self) -> bool {
        self.closed
    }

    /// 累计交付次数（每次完成一个等待算一次，与该次交付的到达数无关）。
    /// Number of waits completed so far.
    pub const fn delivered(&self) -> u64 {
        self.delivered
    }

    /// 记录 `count` 次到达。有等待者 ⇒ 返回 `(等待者, 交付次数)` 并清零、移除登记；否则累加（饱和）。
    /// 已关闭或 `count == 0` 时什么也不做。
    /// Records `count` arrivals, handing the accumulated count to the parked waiter if there is one.
    pub fn arrive(&mut self, count: u32) -> Option<(T, u32)> {
        if self.closed || count == 0 {
            return None;
        }
        let total = self.pending.saturating_add(count);
        match self.waiter.take() {
            Some(w) => {
                self.pending = 0;
                self.delivered = self.delivered.saturating_add(1);
                Some((w, total))
            }
            None => {
                self.pending = total;
                None
            }
        }
    }

    /// 是否可以提交新的等待（不改变状态；提交前的预检）。
    /// Checks whether a new wait would be accepted, without changing state.
    pub fn can_wait(&self) -> Result<(), WaitError> {
        if self.closed {
            Err(WaitError::Closed)
        } else if self.waiter.is_some() {
            Err(WaitError::Busy)
        } else {
            Ok(())
        }
    }

    /// 提交一个等待：有累计次数 ⇒ 立即完成并清零；否则登记 `token`。被拒时状态不变。
    /// Submits a wait for `token`; completes at once when arrivals are pending.
    pub fn submit_wait(&mut self, token: T) -> Result<Submitted, WaitError> {
        self.can_wait()?;
        if self.pending > 0 {
            let n = self.pending;
            self.pending = 0;
            self.delivered = self.delivered.saturating_add(1);
            Ok(Submitted::Ready(n))
        } else {
            self.waiter = Some(token);
            Ok(Submitted::Parked)
        }
    }

    /// 取消 `token` 的等待登记；已到达的次数保留。返回是否确实移除了登记。
    /// Withdraws the waiter `token`; pending arrivals are kept for the next wait.
    pub fn cancel(&mut self, token: T) -> bool {
        if self.waiter == Some(token) {
            self.waiter = None;
            true
        } else {
            false
        }
    }

    /// 关闭：此后拒绝新的等待、忽略到达；返回未完成的等待者（调用者以「已关闭」终态完成它）。重复关闭返回 `None`。
    /// Closes the line and hands back the outstanding waiter, which the caller completes as closed.
    pub fn close(&mut self) -> Option<T> {
        if self.closed {
            return None;
        }
        self.closed = true;
        self.pending = 0;
        self.waiter.take()
    }
}

/// 两次读取同一个单调递增（模 2³² 回绕）的到达计数器之间新到达的次数。
///
/// 计数器是 `u32`，长期运行后会从 `u32::MAX` 回绕到 0；按模 2³² 求差即可跨越回绕得到正确增量。
/// 前提：两次读取之间的到达次数小于 2³²（读者在每次到达或等待时都会同步读数，远小于此界）。
/// 计数器因此只能单调回绕、不能被清零，否则差值没有意义。
/// Arrivals between two readings of a wrapping `u32` counter (modular difference; assumes fewer than 2^32 in between).
pub fn arrivals_since(seen: u32, now: u32) -> u32 {
    now.wrapping_sub(seen)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn arrivals_plain_increment() {
        assert_eq!(arrivals_since(10, 17), 7);
    }

    #[test]
    fn arrivals_equal_readings_are_zero() {
        assert_eq!(arrivals_since(5, 5), 0);
        assert_eq!(arrivals_since(u32::MAX, u32::MAX), 0);
    }

    #[test]
    fn arrivals_across_wrap() {
        let seen = u32::MAX - 3;
        let mut now = seen;
        for _ in 0..6 {
            now = now.wrapping_add(1);
        }
        assert_eq!(now, 2);
        assert_eq!(arrivals_since(seen, now), 6);
    }

    #[test]
    fn arrivals_exactly_at_boundary() {
        assert_eq!(arrivals_since(u32::MAX, 0), 1);
        assert_eq!(arrivals_since(0, u32::MAX), u32::MAX);
    }

    type Line = InterruptLine<u64>;

    #[test]
    fn arrival_before_wait_completes_at_submit() {
        let mut l = Line::new();
        assert_eq!(l.arrive(1), None);
        assert_eq!(l.pending(), 1);
        assert_eq!(l.submit_wait(7), Ok(Submitted::Ready(1)));
        assert_eq!((l.pending(), l.waiter(), l.delivered()), (0, None, 1));
    }

    #[test]
    fn wait_before_arrival_parks_then_delivers() {
        let mut l = Line::new();
        assert_eq!(l.submit_wait(7), Ok(Submitted::Parked));
        assert_eq!(l.waiter(), Some(7));
        assert_eq!(l.arrive(1), Some((7, 1)));
        assert_eq!((l.pending(), l.waiter(), l.delivered()), (0, None, 1));
    }

    #[test]
    fn several_arrivals_merge_into_one_delivery() {
        let mut l = Line::new();
        assert_eq!(l.arrive(2), None);
        assert_eq!(l.arrive(3), None);
        assert_eq!(l.submit_wait(1), Ok(Submitted::Ready(5)));
        assert_eq!(l.delivered(), 1);
    }

    #[test]
    fn second_wait_is_busy_and_state_unchanged() {
        let mut l = Line::new();
        assert_eq!(l.submit_wait(1), Ok(Submitted::Parked));
        let before = l.clone();
        assert_eq!(l.submit_wait(2), Err(WaitError::Busy));
        assert_eq!(l.can_wait(), Err(WaitError::Busy));
        assert_eq!(l, before);
    }

    #[test]
    fn close_hands_back_outstanding_waiter_once() {
        let mut l = Line::new();
        assert_eq!(l.submit_wait(9), Ok(Submitted::Parked));
        assert_eq!(l.close(), Some(9));
        assert!(l.is_closed());
        assert_eq!(l.waiter(), None);
        assert_eq!(l.close(), None, "重复关闭不得再交出等待者");
    }

    #[test]
    fn closed_line_rejects_waits_and_ignores_arrivals() {
        let mut l = Line::new();
        assert_eq!(l.arrive(1), None);
        assert_eq!(l.close(), None);
        let before = l.clone();
        assert_eq!(l.submit_wait(1), Err(WaitError::Closed));
        assert_eq!(l.arrive(4), None);
        assert_eq!(l, before);
        assert_eq!(l.pending(), 0);
    }

    #[test]
    fn pending_count_saturates() {
        let mut l = Line::new();
        assert_eq!(l.arrive(u32::MAX - 1), None);
        assert_eq!(l.arrive(5), None);
        assert_eq!(l.pending(), u32::MAX);
        assert_eq!(l.submit_wait(1), Ok(Submitted::Ready(u32::MAX)));
    }

    #[test]
    fn cancel_keeps_arrivals_for_next_wait() {
        let mut l = Line::new();
        assert_eq!(l.submit_wait(1), Ok(Submitted::Parked));
        assert!(l.cancel(1));
        assert_eq!(l.arrive(1), None, "取消后到达的中断不得交给已撤销的等待者");
        assert_eq!(l.pending(), 1);
        assert_eq!(l.submit_wait(2), Ok(Submitted::Ready(1)));
    }

    #[test]
    fn cancel_of_unknown_token_changes_nothing() {
        let mut l = Line::new();
        assert_eq!(l.submit_wait(1), Ok(Submitted::Parked));
        let before = l.clone();
        assert!(!l.cancel(2));
        assert_eq!(l, before);
    }

    #[test]
    fn zero_arrivals_do_not_complete_waiter() {
        let mut l = Line::new();
        assert_eq!(l.submit_wait(3), Ok(Submitted::Parked));
        assert_eq!(l.arrive(0), None);
        assert_eq!(l.waiter(), Some(3));
        assert_eq!(l.delivered(), 0);
    }
}
