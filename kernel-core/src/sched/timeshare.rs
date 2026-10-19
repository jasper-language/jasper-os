//! 分时策略（默认策略）：QoS 四档严格优先 + 档内按近期用量衰减 + 档内唤醒优先 + 各档最低份额 + 后台限速。
//! Time-sharing policy (default): strict QoS classes, decayed usage within a class, wake-first,
//! per-class minimum shares and background throttling.
//!
//! # 职责边界
//! 只做决策，实现 [`SchedPolicy`] 的全部钩子；不碰任务表、寄存器、栈与地址空间。私有的每实体状态
//! （近期用量、衰减纪元、派发序号、唤醒标记）放在 [`TimeShareState`] 里，由 Core 的 `SchedEntity`
//! 代为保存。设计理由（为什么这样能在过载下保持响应）见上级模块文档。
//!
//! # 多处理器
//! 每个处理器的运行队列各持一份实例（欠账与衰减纪元按核独立）。实体迁移时经迁入钩子把用量从源实例的
//! 纪元换算到目标实例的纪元，避免两个实例的时钟不同步让迁移来的实体用量被多算或少算。

use super::{
    class::SchedClass, Choice, ClassMask, Dequeue, Enqueue, Preempt, Qos, QosParams, Requeue, SchedEntity, SchedPolicy, QOS_CLASSES, TICK_UNITS,
};

/// 运行一个 tick 记入的用量。
const USAGE_PER_TICK: u32 = 1024;

/// 分时策略的每实体私有状态。
/// Per-entity private state of the time-sharing policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TimeShareState {
    /// 近期用量（截至 `epoch` 时的值）。
    usage: u32,
    /// `usage` 对应的衰减纪元（本实体所在实例的纪元）。
    epoch: u64,
    /// 最近一次被派发或主动让出时的序号（档内用量相同时选序号最小的，即最久没运行的）。
    last_seq: u64,
    /// 被唤醒后还没有运行过（档内排在最前）。
    woken: bool,
}

impl TimeShareState {
    /// 初始状态：用量为 0，从未运行。
    pub const INITIAL: TimeShareState = TimeShareState { usage: 0, epoch: 0, last_seq: 0, woken: false };
}

/// 分时策略。可复制：多处理器下每个处理器的运行队列各持一份。
/// Time-sharing policy instance (one per run queue).
#[derive(Debug, Clone, Copy)]
pub struct TimeSharePolicy {
    params: QosParams,
    /// 各档欠账（千分之一 tick）。
    owed: [u32; QOS_CLASSES],
    /// 已记账的 tick 数（衰减纪元 = ticks / decay_period）。
    ticks: u64,
    /// 决策序号。
    seq: u64,
}

impl TimeSharePolicy {
    /// 以给定参数构造（`const`，可放进 `static`）。
    pub const fn new(params: QosParams) -> Self {
        TimeSharePolicy { params, owed: [0; QOS_CLASSES], ticks: 0, seq: 0 }
    }

    /// 生效参数。
    pub const fn params(&self) -> &QosParams {
        &self.params
    }

    /// 当前衰减纪元。
    fn epoch(&self) -> u64 {
        self.ticks / self.params.decay_period.max(1) as u64
    }

    /// 实体在本实例当前纪元的有效用量：每经过一个纪元减半（惰性计算，不改实体）。
    pub fn effective_usage(&self, e: &SchedEntity<TimeShareState>) -> u32 {
        let elapsed = self.epoch().saturating_sub(e.state.epoch);
        if elapsed >= 32 {
            0
        } else {
            e.state.usage >> elapsed
        }
    }

    /// 某档当前欠账（千分之一 tick；诊断与测试用）。
    pub fn owed(&self, q: Qos) -> u32 {
        self.owed[q.index()]
    }

    /// 欠账满一个 tick、且不是最高可运行档的最高档位。
    fn owed_class(&self, runnable: ClassMask) -> Option<Qos> {
        let top = runnable.highest()?;
        Qos::ALL.into_iter().find(|&q| top.above(q) && runnable.contains(q) && self.owed[q.index()] >= TICK_UNITS)
    }

    /// 取下一个序号。
    fn next_seq(&mut self) -> u64 {
        self.seq += 1;
        self.seq
    }
}

impl SchedPolicy for TimeSharePolicy {
    type State = TimeShareState;
    const INITIAL: TimeShareState = TimeShareState::INITIAL;
    const CLASS: SchedClass = SchedClass::TIME_SHARE;

    fn name(&self) -> &'static str {
        "timeshare"
    }

    fn enqueue(&mut self, e: &mut SchedEntity<TimeShareState>, why: Enqueue) {
        match why {
            // 新实体从本实例的当前纪元、零用量开始（不继承创建者的用量，也不被旧纪元误衰减）
            Enqueue::Spawn => {
                e.state = TimeShareState { epoch: self.epoch(), ..TimeShareState::INITIAL };
            }
            // 档内唤醒优先：刚醒来、还没运行过的实体在本档内排在最前
            Enqueue::Wake => e.state.woken = true,
        }
    }

    fn dequeue(&mut self, e: &mut SchedEntity<TimeShareState>, why: Dequeue) {
        // 离队即失去唤醒优先（睡眠前若还没运行就又睡下，下次醒来重新获得）；用量保留到下次入队时继续衰减。
        let _ = why;
        e.state.woken = false;
    }

    fn requeue(&mut self, e: &mut SchedEntity<TimeShareState>, why: Requeue) {
        e.state.woken = false;
        // 主动让出：在同档、同用量的实体中排到最后（被抢占的实体保留派发时的序号）
        if why == Requeue::Yield {
            e.state.last_seq = self.next_seq();
        }
    }

    fn throttled(&mut self, e: &mut SchedEntity<TimeShareState>) {
        // 预算耗尽：预算回正后按用量与其他实体公平竞争，不保留唤醒优先，并排在同用量者之后
        e.state.woken = false;
        e.state.last_seq = self.next_seq();
    }

    fn migrate_in(&mut self, from: &Self, e: &mut SchedEntity<TimeShareState>) {
        // 先按源实例的纪元衰减到「现在」，再记到本实例的当前纪元；派发序号换成本实例的（排在本队列同用量者之后）
        e.state.usage = from.effective_usage(e);
        e.state.epoch = self.epoch();
        e.state.last_seq = self.next_seq();
    }

    fn choose(&self, candidates: &mut dyn Iterator<Item = (usize, &SchedEntity<TimeShareState>)>) -> Option<Choice> {
        // 一次遍历：记下每档的最佳候选（刚被唤醒的优先，其次有效用量最少，再次最久没运行）。
        // 比较键相同则保留先遇到的（槽位序）——结果只取决于输入，便于确定性测试。
        let mut best: [Option<(usize, (bool, u32, u64))>; QOS_CLASSES] = [None; QOS_CLASSES];
        let mut runnable = ClassMask::EMPTY;
        for (slot, e) in candidates {
            runnable.insert(e.qos);
            let key = (!e.state.woken, self.effective_usage(e), e.state.last_seq);
            let b = &mut best[e.qos.index()];
            let better = match b {
                None => true,
                Some((_, k)) => key < *k,
            };
            if better {
                *b = Some((slot, key));
            }
        }
        // 先补给欠账的低档（一个 tick），否则按严格优先选最高档。
        let (class, rescued) = match self.owed_class(runnable) {
            Some(q) => (q, true),
            None => (runnable.highest()?, false),
        };
        let (slot, _) = best[class.index()]?;
        let quantum = if rescued { 1 } else { self.params.quantum[class.index()].max(1) };
        Some(Choice { slot, quantum, rescued })
    }

    fn dispatched(&mut self, e: &mut SchedEntity<TimeShareState>) {
        e.state.last_seq = self.next_seq();
        e.state.woken = false;
    }

    fn on_tick(&mut self, running: Option<&mut SchedEntity<TimeShareState>>, waiting: ClassMask) {
        self.ticks += 1;
        let epoch = self.epoch();
        let ran = running.map(|e| {
            // 先把用量衰减到当前纪元，再记入这个 tick。
            e.state.usage = self.effective_usage(e).saturating_add(USAGE_PER_TICK);
            e.state.epoch = epoch;
            e.qos
        });
        for q in Qos::ALL {
            let o = &mut self.owed[q.index()];
            if Some(q) == ran {
                *o = o.saturating_sub(TICK_UNITS);
            } else if waiting.contains(q) {
                *o = (*o + self.params.min_share_permille[q.index()]).min(self.params.owed_cap);
            }
        }
    }

    fn should_preempt(&self, current: Option<&SchedEntity<TimeShareState>>, used: u32, quantum: u32, waiting: ClassMask) -> Option<Preempt> {
        let Some(cur) = current else {
            return waiting.highest().map(|_| Preempt::Higher);
        };
        let mut all = waiting;
        all.insert(cur.qos);
        if waiting.highest().is_some_and(|top| top.above(cur.qos)) {
            return Some(Preempt::Higher);
        }
        if self.owed_class(all).is_some_and(|q| q != cur.qos) {
            return Some(Preempt::Owed);
        }
        // 时间片用完：只有还有别的可运行实体时才值得切换（否则选回自己，徒增开销）。
        if used >= quantum && waiting != ClassMask::EMPTY {
            return Some(Preempt::Quantum);
        }
        None
    }

    fn wake_preempts(&self, woken: Qos, current: Option<Qos>) -> bool {
        match current {
            None => true,
            // 后台限速：后台实体被唤醒时只抢占空闲。
            Some(_) if woken == Qos::Background => false,
            Some(c) => woken.above(c),
        }
    }

    fn outranks(&self, a: Qos, b: Qos) -> bool {
        a.above(b)
    }

    fn default_quantum(&self) -> u32 {
        self.params.quantum[Qos::UserInitiated.index()]
    }
}
