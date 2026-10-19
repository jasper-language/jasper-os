//! 调度类别与多类别仲裁的扩展点：每个策略声明自己所属的类别，仲裁器决定多个类别同时有可运行实体时
//! 先服务哪一类。
//! Scheduling classes and the arbitration extension point.
//!
//! # 职责边界
//! 只定义类别标识、类别集合与仲裁接口，以及最简单的仲裁器「严格顺序」。份额、预留与跨类别抢占边界
//! 属于更完整的仲裁器，由以后的实现按同一接口提供；本模块不含任何指令集或任务表概念。
//!
//! # 为什么现在就要有
//! 内核构建期只选一个策略时，仲裁器在启动时校验「所选策略的类别被仲裁器接纳」；以后同一实例同时运行
//! 多个类别时，机制只需把各类别的可运行集合交给仲裁器，不必改动策略接口。

/// 类别数上限。
pub const MAX_SCHED_CLASSES: usize = 8;

/// 调度类别标识（登记表式的小整数；不同类别的策略实例由仲裁器分派）。
/// Scheduling-class identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SchedClass(u8);

impl SchedClass {
    /// 分时类别（交互与一般工作负载）。
    pub const TIME_SHARE: SchedClass = SchedClass(0);

    /// 由编号构造；超出上限时 `None`。
    pub const fn new(id: u8) -> Option<SchedClass> {
        if (id as usize) < MAX_SCHED_CLASSES {
            Some(SchedClass(id))
        } else {
            None
        }
    }

    /// 编号。
    pub const fn id(self) -> u8 {
        self.0
    }

    /// 规范名（诊断与结构化事件用；未命名的类别统一为 `class`）。
    pub const fn name(self) -> &'static str {
        match self.0 {
            0 => "timeshare",
            _ => "class",
        }
    }
}

/// 一组类别的位集合。
/// Set of scheduling classes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ClassSet(u8);

impl ClassSet {
    /// 空集合。
    pub const EMPTY: ClassSet = ClassSet(0);

    /// 只含一个类别的集合。
    pub const fn of(c: SchedClass) -> ClassSet {
        ClassSet(1 << c.0)
    }

    /// 加入一个类别。
    pub fn insert(&mut self, c: SchedClass) {
        self.0 |= 1 << c.0;
    }

    /// 是否含某类别。
    pub const fn contains(self, c: SchedClass) -> bool {
        self.0 & (1 << c.0) != 0
    }
}

/// 仲裁接口：给定有可运行实体的类别集合，回答先服务哪一类（`None` = 没有可服务的类别）。
/// Arbiter interface: which class to serve next.
pub trait Arbiter {
    /// 选出要服务的类别。
    fn pick(&self, runnable: ClassSet) -> Option<SchedClass>;

    /// 仲裁器是否接纳某类别（不接纳的类别永远不会被选中；启动时据此拒绝无法服务的策略组合）。
    fn admits(&self, c: SchedClass) -> bool;
}

/// 仲裁器构造失败的原因。失败时不产生仲裁器。
/// Why an arbiter could not be built.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArbiterError {
    /// 顺序表为空。
    Empty,
    /// 同一类别出现两次。
    Duplicate(SchedClass),
    /// 超过类别数上限。
    TooMany,
}

/// 严格顺序仲裁：按给定顺序，第一个有可运行实体的类别胜出。
/// Strict-order arbiter.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StrictOrder {
    order: [SchedClass; MAX_SCHED_CLASSES],
    len: usize,
}

impl StrictOrder {
    /// 只含一个类别（`const`：构建期只选一个策略时用）。
    pub const fn single(c: SchedClass) -> StrictOrder {
        StrictOrder { order: [c; MAX_SCHED_CLASSES], len: 1 }
    }

    /// 由顺序表构造：空表、重复类别、超过上限一律拒绝。
    pub fn new(order: &[SchedClass]) -> Result<StrictOrder, ArbiterError> {
        if order.is_empty() {
            return Err(ArbiterError::Empty);
        }
        if order.len() > MAX_SCHED_CLASSES {
            return Err(ArbiterError::TooMany);
        }
        let mut seen = ClassSet::EMPTY;
        for &c in order {
            if seen.contains(c) {
                return Err(ArbiterError::Duplicate(c));
            }
            seen.insert(c);
        }
        let mut out = StrictOrder::single(order[0]);
        out.order[..order.len()].copy_from_slice(order);
        out.len = order.len();
        Ok(out)
    }

    /// 顺序表。
    pub fn order(&self) -> &[SchedClass] {
        &self.order[..self.len]
    }
}

impl Arbiter for StrictOrder {
    fn pick(&self, runnable: ClassSet) -> Option<SchedClass> {
        self.order().iter().copied().find(|&c| runnable.contains(c))
    }

    fn admits(&self, c: SchedClass) -> bool {
        self.order().contains(&c)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn c(id: u8) -> SchedClass {
        SchedClass::new(id).unwrap()
    }

    #[test]
    fn class_ids_are_bounded() {
        assert_eq!(SchedClass::new(0), Some(SchedClass::TIME_SHARE));
        assert_eq!(SchedClass::new(7).map(SchedClass::id), Some(7));
        assert_eq!(SchedClass::new(8), None);
        assert_eq!(SchedClass::TIME_SHARE.name(), "timeshare");
    }

    #[test]
    fn strict_order_serves_first_runnable_class() {
        let a = StrictOrder::new(&[c(2), c(0), c(1)]).unwrap();
        let mut s = ClassSet::EMPTY;
        assert_eq!(a.pick(s), None);
        s.insert(c(1));
        assert_eq!(a.pick(s), Some(c(1)));
        s.insert(c(0));
        assert_eq!(a.pick(s), Some(c(0)));
        s.insert(c(2));
        assert_eq!(a.pick(s), Some(c(2)));
        // 不在顺序表里的类别永远不被选中
        assert_eq!(a.pick(ClassSet::of(c(5))), None);
        assert!(a.admits(c(0)) && !a.admits(c(5)));
        let single = StrictOrder::single(SchedClass::TIME_SHARE);
        assert_eq!(single.order(), &[SchedClass::TIME_SHARE]);
        assert_eq!(single.pick(ClassSet::of(SchedClass::TIME_SHARE)), Some(SchedClass::TIME_SHARE));
    }

    #[test]
    fn strict_order_rejects_bad_tables() {
        assert_eq!(StrictOrder::new(&[]), Err(ArbiterError::Empty));
        assert_eq!(StrictOrder::new(&[c(1), c(3), c(1)]), Err(ArbiterError::Duplicate(c(1))));
        let nine = [c(0), c(1), c(2), c(3), c(4), c(5), c(6), c(7), c(0)];
        assert_eq!(StrictOrder::new(&nine), Err(ArbiterError::TooMany));
    }
}
