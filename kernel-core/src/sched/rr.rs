//! 纯轮转策略（最小的替代策略）：不分级、固定时间片、先来先服务的环形顺序。
//! Plain round-robin policy: no classes, fixed quantum, FIFO ring order.
//!
//! # 职责边界
//! 实现 [`SchedPolicy`] 的全部钩子，忽略 QoS 档位（机制仍为继承、放置与统计维护档位，本策略不据此排序）。
//! 存在的意义：证明调度接口不偏向任何一种策略——同一内核换成本策略构建，机制代码不改一行。
//!
//! # 顺序规则
//! 每个实体带一个排队号：入队、被换下（让出 / 被抢占 / 预算耗尽）、迁入时都取本实例的下一个号，
//! 排到队尾；选择总取排队号最小的。于是 k 个可运行实体中任一个从入队到运行最多等 (k − 1) 个时间片——
//! 延迟有上界，但随同队实体数线性增长（这正是分时策略分级要解决的问题）。

use super::{class::SchedClass, Choice, ClassMask, Dequeue, Enqueue, Preempt, Qos, Requeue, SchedEntity, SchedPolicy};

/// 纯轮转策略的每实体私有状态。
/// Per-entity private state of the round-robin policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RrState {
    /// 排队号（越小越靠前）。
    ticket: u64,
}

impl RrState {
    /// 初始状态（排队号 0；入队时会被改写）。
    pub const INITIAL: RrState = RrState { ticket: 0 };

    /// 排队号（诊断与测试用）。
    pub const fn ticket(&self) -> u64 {
        self.ticket
    }
}

/// 纯轮转策略实例（每个运行队列一份）。
/// Round-robin policy instance (one per run queue).
#[derive(Debug, Clone, Copy)]
pub struct RoundRobin {
    /// 时间片（tick，≥ 1）。
    quantum: u32,
    /// 下一个排队号。
    next: u64,
    /// 累计派发次数（诊断：轮转是否在转）。
    dispatches: u64,
}

impl RoundRobin {
    /// 以给定时间片构造（0 按 1 处理）。
    pub const fn new(quantum: u32) -> Self {
        RoundRobin { quantum: if quantum == 0 { 1 } else { quantum }, next: 1, dispatches: 0 }
    }

    /// 生效时间片。
    pub const fn quantum(&self) -> u32 {
        self.quantum
    }

    /// 累计派发次数。
    pub const fn dispatches(&self) -> u64 {
        self.dispatches
    }

    /// 把实体排到本实例的队尾。
    fn to_tail(&mut self, e: &mut SchedEntity<RrState>) {
        e.state.ticket = self.next;
        self.next += 1;
    }
}

impl SchedPolicy for RoundRobin {
    type State = RrState;
    const INITIAL: RrState = RrState::INITIAL;
    const CLASS: SchedClass = SchedClass::TIME_SHARE;

    fn name(&self) -> &'static str {
        "round_robin"
    }

    fn enqueue(&mut self, e: &mut SchedEntity<RrState>, why: Enqueue) {
        // 新建与唤醒一视同仁：排到队尾（不给唤醒者插队）
        let _ = why;
        self.to_tail(e);
    }

    fn dequeue(&mut self, e: &mut SchedEntity<RrState>, why: Dequeue) {
        // 离队后排队号作废：下次入队一定重新取号，旧号不会让它插到别人前面
        let _ = why;
        e.state.ticket = u64::MAX;
    }

    fn requeue(&mut self, e: &mut SchedEntity<RrState>, why: Requeue) {
        let _ = why;
        self.to_tail(e);
    }

    fn throttled(&mut self, e: &mut SchedEntity<RrState>) {
        self.to_tail(e);
    }

    fn migrate_in(&mut self, from: &Self, e: &mut SchedEntity<RrState>) {
        // 两个实例的排队号互不可比：迁来的实体排到本队列的队尾
        let _ = from;
        self.to_tail(e);
    }

    fn choose(&self, candidates: &mut dyn Iterator<Item = (usize, &SchedEntity<RrState>)>) -> Option<Choice> {
        let (slot, _) = candidates.min_by_key(|(slot, e)| (e.state.ticket, *slot))?;
        Some(Choice { slot, quantum: self.quantum, rescued: false })
    }

    fn dispatched(&mut self, e: &mut SchedEntity<RrState>) {
        // 运行期间保持原排队号（仍在队首）；被换下时由让出钩子排到队尾
        debug_assert!(e.state.ticket < self.next);
        self.dispatches += 1;
    }

    fn should_preempt(&self, current: Option<&SchedEntity<RrState>>, used: u32, quantum: u32, waiting: ClassMask) -> Option<Preempt> {
        if waiting == ClassMask::EMPTY {
            return None;
        }
        match current {
            None => Some(Preempt::Higher),
            Some(_) if used >= quantum => Some(Preempt::Quantum),
            Some(_) => None,
        }
    }

    fn wake_preempts(&self, woken: Qos, current: Option<Qos>) -> bool {
        // 不分级：唤醒只抢占空闲
        let _ = woken;
        current.is_none()
    }

    fn outranks(&self, a: Qos, b: Qos) -> bool {
        let _ = (a, b);
        false
    }

    fn default_quantum(&self) -> u32 {
        self.quantum
    }
}
