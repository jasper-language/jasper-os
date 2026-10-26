//! 每核运行队列机制（Core 部分）：持有一个策略实例，校验实体的队列成员关系后再调用策略钩子，
//! 并做与策略无关的记账（入队实体数、累计运行 tick）。
//! Per-CPU run-queue mechanism: membership checks, policy hook dispatch, policy-neutral accounting.
//!
//! # 职责边界
//! * 成员关系只在这里维护：实体的 `queue` 字段只能经本模块改写；重复入队、对不在本队列的实体调用钩子、
//!   迁移到自身或越界的队列一律拒绝，且不改动任何状态（不调用策略钩子、计数不变）。
//! * 本模块不保存实体列表（实体在调用者的任务表里）；它只记「本队列上有多少实体」，
//!   调用者可以据此核对任务表与各队列的一致性（钩子是否漏调或多调）。
//! * 「运行中」的实体仍算在队列上（与「可运行」一样），直到它睡眠、退出或迁走。

use super::{Choice, ClassMask, Dequeue, Enqueue, Preempt, Qos, Requeue, SchedEntity, SchedPolicy};

/// 队列操作被拒绝的原因。被拒绝时队列与实体都不变。
/// Why a run-queue operation was refused (nothing changed).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QueueError {
    /// 实体已在某个队列上（`Some(处理器下标)`）。
    AlreadyQueued(usize),
    /// 实体不在本队列上（实际所在队列；`None` = 不在任何队列）。
    NotQueued(Option<usize>),
    /// 迁移的源与目标是同一个队列。
    SameQueue,
    /// 队列下标越界。
    NoSuchQueue,
}

/// 一个处理器的运行队列：策略实例 + 编号 + 入队实体数。
/// One processor's run queue.
#[derive(Debug, Clone, Copy)]
pub struct CoreQueue<P> {
    policy: P,
    id: u8,
    queued: u32,
}

impl<P: SchedPolicy> CoreQueue<P> {
    /// 以策略实例与处理器编号构造（`const`，可放进 `static`）。
    pub const fn new(policy: P, id: u8) -> Self {
        CoreQueue { policy, id, queued: 0 }
    }

    /// 构造 `M` 个队列，编号依次为 0..M（每个持一份 `policy` 的副本）。
    /// Build `M` queues numbered 0..M.
    pub const fn array<const M: usize>(policy: P) -> [CoreQueue<P>; M] {
        let mut q = [CoreQueue::new(policy, 0); M];
        let mut i = 0;
        while i < M {
            q[i].id = i as u8;
            i += 1;
        }
        q
    }

    /// 本队列的策略实例（只读：决策查询经它进行，状态改动只经本类型的钩子方法）。
    pub const fn policy(&self) -> &P {
        &self.policy
    }

    /// 处理器编号。
    pub const fn id(&self) -> usize {
        self.id as usize
    }

    /// 本队列上的实体数（可运行 + 运行中）。
    pub const fn queued(&self) -> u32 {
        self.queued
    }

    /// 实体在本队列上，否则返回拒绝原因。
    fn member(&self, e: &SchedEntity<P::State>) -> Result<(), QueueError> {
        if e.queue == Some(self.id) {
            Ok(())
        } else {
            Err(QueueError::NotQueued(e.queue()))
        }
    }

    /// 入队（新建或被唤醒）。实体已在任何队列上时拒绝。
    pub fn enqueue(&mut self, e: &mut SchedEntity<P::State>, why: Enqueue) -> Result<(), QueueError> {
        if let Some(q) = e.queue() {
            return Err(QueueError::AlreadyQueued(q));
        }
        e.queue = Some(self.id);
        self.queued += 1;
        self.policy.enqueue(e, why);
        Ok(())
    }

    /// 出队（睡眠或退出）。实体不在本队列上时拒绝。
    pub fn dequeue(&mut self, e: &mut SchedEntity<P::State>, why: Dequeue) -> Result<(), QueueError> {
        self.member(e)?;
        self.policy.dequeue(e, why);
        e.queue = None;
        self.queued -= 1;
        Ok(())
    }

    /// 运行中的实体被换下但仍可运行（让出或被抢占）。实体不在本队列上时拒绝。
    pub fn requeue(&mut self, e: &mut SchedEntity<P::State>, why: Requeue) -> Result<(), QueueError> {
        self.member(e)?;
        self.policy.requeue(e, why);
        Ok(())
    }

    /// 实体因预算耗尽被换下。实体不在本队列上时拒绝。
    pub fn throttled(&mut self, e: &mut SchedEntity<P::State>) -> Result<(), QueueError> {
        self.member(e)?;
        self.policy.throttled(e);
        Ok(())
    }

    /// 实体被选中、即将运行。实体不在本队列上时拒绝。
    pub fn dispatched(&mut self, e: &mut SchedEntity<P::State>) -> Result<(), QueueError> {
        self.member(e)?;
        self.policy.dispatched(e);
        Ok(())
    }

    /// 每 tick 记账：正在运行的实体累计运行 tick 加一（Core 记账），再交给策略。
    /// 正在运行的实体不在本队列上时拒绝（不记账，策略也不推进）。
    pub fn tick(&mut self, running: Option<&mut SchedEntity<P::State>>, waiting: ClassMask) -> Result<(), QueueError> {
        if let Some(e) = running {
            self.member(e)?;
            e.cpu_ticks += 1;
            self.policy.on_tick(Some(e), waiting);
        } else {
            self.policy.on_tick(None, waiting);
        }
        Ok(())
    }

    /// 从候选中选下一个（只读查询，转交策略）。
    pub fn choose(&self, candidates: &mut dyn Iterator<Item = (usize, &SchedEntity<P::State>)>) -> Option<Choice> {
        self.policy.choose(candidates)
    }

    /// 是否要抢占当前实体（只读查询，转交策略）。
    pub fn should_preempt(&self, current: Option<&SchedEntity<P::State>>, used: u32, quantum: u32, waiting: ClassMask) -> Option<Preempt> {
        self.policy.should_preempt(current, used, quantum, waiting)
    }

    /// 唤醒是否立即抢占（只读查询，转交策略）。
    pub fn wake_preempts(&self, woken: Qos, current: Option<Qos>) -> bool {
        self.policy.wake_preempts(woken, current)
    }

    /// Move one member to a separately locked destination queue. Callers must
    /// hold both queue locks in a globally consistent order.
    pub fn migrate_to(&mut self, destination: &mut Self, e: &mut SchedEntity<P::State>) -> Result<(), QueueError> {
        if self.id == destination.id { return Err(QueueError::SameQueue); }
        self.member(e)?;
        let source_policy = self.policy;
        self.queued -= 1;
        destination.policy.migrate_in(&source_policy, e);
        e.queue = Some(destination.id);
        destination.queued += 1;
        Ok(())
    }
}

/// 把实体从队列 `from` 迁到队列 `to`：源队列出队（不调用出队钩子：实体没有睡眠或退出），
/// 目标队列调用迁入钩子后入队。越界、源与目标相同、实体不在源队列上时拒绝，且什么都不改。
/// Move an entity between two run queues.
pub fn migrate<P: SchedPolicy>(queues: &mut [CoreQueue<P>], from: usize, to: usize, e: &mut SchedEntity<P::State>) -> Result<(), QueueError> {
    if from >= queues.len() || to >= queues.len() {
        return Err(QueueError::NoSuchQueue);
    }
    if from == to {
        return Err(QueueError::SameQueue);
    }
    if from < to {
        let (left, right) = queues.split_at_mut(to);
        left[from].migrate_to(&mut right[0], e)
    } else {
        let (left, right) = queues.split_at_mut(from);
        right[0].migrate_to(&mut left[to], e)
    }
}
