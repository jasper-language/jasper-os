//! 调度策略（`system.task` 领域的「选谁运行」部分）：QoS 分级 + 档内按 CPU 用量衰减的动态优先级 +
//! 各档最低份额（防饿死）+ 后台限速。
//! Scheduling policy: QoS classes, usage-decayed dynamic priority within a class,
//! per-class minimum shares (starvation guard) and background throttling.
//!
//! # 职责边界
//! 本模块只做**决策**：给定一组可运行实体的调度属性，回答「下一个是谁、给多长时间片、要不要抢占」。
//! 它不碰寄存器、栈、地址空间，也不知道任务表长什么样——这些是内核调度*机制*的事。
//! 因此整套策略可以在宿主上用确定性模拟测试锁死（见本文件末尾的测试）。
//!
//! # 为什么这样设计（过载下仍然响应）
//! 目标现象：多个吃满 CPU 的任务把负载压到 100% 时，交互任务从被唤醒到开始运行的延迟仍有上界；
//! 压力撤销后立即恢复。做法：
//! * **QoS 四档，严格优先**：交互 > 用户发起 > 工具 > 后台。高档任务一旦可运行（包括被唤醒），
//!   立即抢占低档任务——唤醒延迟因此与低档负载多少无关。
//! * **档内按 CPU 用量衰减**：每个实体记一份「近期 CPU 用量」，每运行一个 tick 加一份，
//!   每过一个衰减周期减半（惰性计算，O(1)）。档内总是选近期用量最少的——短暂运行就睡下的任务
//!   天然排在吃满 CPU 的任务前面；吃满 CPU 的任务之间轮流（用量相同则选最久没运行的）。
//! * **档内唤醒优先**：刚被唤醒、还没运行过的实体在本档内排在最前（同档不抢占当前任务，
//!   但当前时间片一结束就轮到它）。只看用量不够：醒来的任务若刚好在上一个衰减周期里跑得多，
//!   它可能排在已衰减的吃满任务后面，同档唤醒延迟就失去上界。
//! * **各档最低份额（防饿死）**：严格优先会饿死低档。每档有一个千分比份额：该档有任务在等而没运行时
//!   每个 tick 累积份额，累积满一个 tick（1000）就「欠它一个 tick」，下次决策时优先补给它一个 tick
//!   的时间片。于是低档在任何负载下都有保底进展，而高档的延迟最多多出一个 tick。
//! * **后台限速**：后台档被唤醒时不抢占任何正在运行的任务（只抢占空闲），在有更高档工作时只拿到
//!   它的最低份额；补给的时间片恒为一个 tick。
//!
//! # QoS 变更规则（能力约束）
//! 任务可以把自己的档位**降低**或保持不变；**提升**需要创建方授予的「QoS 上限」能力，且不能超过该上限。
//! 判定是纯函数 [`qos_change_allowed`]，由系统调用层调用。
//!
//! # 优先级继承
//! 等待关系（谁在等谁）与「有效档位 = 自身档位与全部直接/间接等待者档位中的最高者」的计算见 [`inherit`]；
//! 策略只看实体的有效档位，因此继承不需要改动选择与抢占逻辑。

pub mod inherit;

/// 服务质量档位（数值越小越优先）。登记表外的数值经 [`Qos::from_raw`] 拒绝。
/// Quality-of-service class (lower value = higher priority).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u8)]
pub enum Qos {
    /// 交互：直接响应用户操作（界面、输入）。
    Interactive = 0,
    /// 用户发起：用户在等结果的工作（默认档）。
    UserInitiated = 1,
    /// 工具：用户知道在进行、不急等结果的工作。
    Utility = 2,
    /// 后台：用户看不见的维护工作（索引、备份）。
    Background = 3,
}

/// 档位数。
pub const QOS_CLASSES: usize = 4;

impl Qos {
    /// 全部档位，从高到低。
    pub const ALL: [Qos; QOS_CLASSES] = [Qos::Interactive, Qos::UserInitiated, Qos::Utility, Qos::Background];

    /// 由系统调用参数解析档位；未定义的数值返回 `None`（调用方报参数非法，不静默截断）。
    pub const fn from_raw(v: u64) -> Option<Qos> {
        match v {
            0 => Some(Qos::Interactive),
            1 => Some(Qos::UserInitiated),
            2 => Some(Qos::Utility),
            3 => Some(Qos::Background),
            _ => None,
        }
    }

    /// 档位序号（0 = 最高），用作各档数组的下标。
    pub const fn index(self) -> usize {
        self as usize
    }

    /// 规范名（诊断与结构化事件用）。
    pub const fn name(self) -> &'static str {
        match self {
            Qos::Interactive => "interactive",
            Qos::UserInitiated => "user_initiated",
            Qos::Utility => "utility",
            Qos::Background => "background",
        }
    }

    /// `self` 是否严格比 `other` 优先。
    pub const fn above(self, other: Qos) -> bool {
        (self as u8) < (other as u8)
    }

    /// 两档中较优先的一档（优先级继承取「等待者与持有者中较高者」）。
    /// The higher-priority of two classes.
    pub const fn higher(self, other: Qos) -> Qos {
        if other.above(self) {
            other
        } else {
            self
        }
    }
}

/// QoS 变更是否允许：降低或不变总是允许；提升只在持有上限能力且目标不高于上限时允许。
///
/// * `current`：任务当前档位
/// * `requested`：想要的档位
/// * `ceiling`：创建方授予的上限（`None` = 没有提升能力）
pub const fn qos_change_allowed(current: Qos, requested: Qos, ceiling: Option<Qos>) -> bool {
    if !requested.above(current) {
        return true;
    }
    match ceiling {
        Some(c) => !requested.above(c),
        None => false,
    }
}

/// 一组档位的位集合（位 i = 档位序号 i）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ClassMask(u8);

impl ClassMask {
    /// 空集合。
    pub const EMPTY: ClassMask = ClassMask(0);

    /// 加入一个档位。
    pub fn insert(&mut self, q: Qos) {
        self.0 |= 1 << q.index();
    }

    /// 是否含某档位。
    pub const fn contains(self, q: Qos) -> bool {
        self.0 & (1 << q.index()) != 0
    }

    /// 集合中最高的档位。
    pub fn highest(self) -> Option<Qos> {
        Qos::ALL.into_iter().find(|&q| self.contains(q))
    }
}

/// 策略参数（构建期选定；以后由内核配置档统一提供）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct QosParams {
    /// 各档的时间片（tick）。必须 ≥ 1。
    pub quantum: [u32; QOS_CLASSES],
    /// 各档的最低份额（千分比）：该档有任务在等时，至少约这么多比例的 tick 归它。最高档不需要（填 0）。
    pub min_share_permille: [u32; QOS_CLASSES],
    /// 用量衰减周期（tick）：每过一个周期，近期用量减半。必须 ≥ 1。
    pub decay_period: u32,
    /// 欠账上限（千分之一 tick 为单位）：长时间饥饿后最多一次补给这么多，避免补给变成长时间独占。
    pub owed_cap: u32,
}

impl QosParams {
    /// 默认参数：时间片 2/2/4/4 tick；最低份额 —/10%/5%/2%；用量每 8 tick 减半；欠账最多 2 个 tick。
    pub const DEFAULT: QosParams = QosParams {
        quantum: [2, 2, 4, 4],
        min_share_permille: [0, 100, 50, 20],
        decay_period: 8,
        owed_cap: 2 * TICK_UNITS,
    };
}

/// 一个 tick 的份额单位（千分比的分母）。
pub const TICK_UNITS: u32 = 1000;
/// 运行一个 tick 记入的用量。
const USAGE_PER_TICK: u32 = 1024;

/// 每个可调度实体（线程）的调度属性。由内核任务表持有，策略读写。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SchedEntity {
    /// 当前档位。
    pub qos: Qos,
    /// 近期用量（截至 `epoch` 时的值）。
    usage: u32,
    /// `usage` 对应的衰减纪元。
    epoch: u64,
    /// 最近一次被选中运行时的决策序号（档内用量相同时选最久没运行的）。
    last_seq: u64,
    /// 被唤醒后还没有运行过（档内排在最前，见模块文档「档内唤醒优先」）。
    woken: bool,
    /// 累计运行的 tick 数（诊断与验收：后台任务是否有进展）。
    pub cpu_ticks: u64,
}

impl SchedEntity {
    /// 新实体：近期用量为 0，从未运行。
    pub const fn new(qos: Qos) -> Self {
        SchedEntity { qos, usage: 0, epoch: 0, last_seq: 0, woken: false, cpu_ticks: 0 }
    }
}

/// 一次选择的结果。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Choice {
    /// 选中的槽位（由调用者定义的编号）。
    pub slot: usize,
    /// 这次给的时间片（tick）。
    pub quantum: u32,
    /// 是否为最低份额补给（不是按严格优先选中的）。
    pub rescued: bool,
}

/// 抢占的原因。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Preempt {
    /// 时间片用完。
    Quantum,
    /// 有更高档的任务可运行（含刚被唤醒的）。
    Higher,
    /// 某个低档欠账满一个 tick，需要补给。
    Owed,
}

/// 调度策略接口（Strategy 模式）：内核调度机制对它泛型化，换策略不改切换代码。
/// Scheduling-policy interface: the mechanism is generic over it.
pub trait SchedPolicy {
    /// 策略名（诊断输出）。
    fn name(&self) -> &'static str;

    /// 从候选（可运行的工作实体）中选出下一个。没有候选时返回 `None`（机制切回空闲/引导线程）。
    fn choose(&self, candidates: &mut dyn Iterator<Item = (usize, &SchedEntity)>) -> Option<Choice>;

    /// 实体被选中、即将运行：记录决策序号（档内轮转依据）。
    fn dispatched(&mut self, e: &mut SchedEntity);

    /// 实体从阻塞（睡眠）变为可运行：策略可据此调整它在档内的位置。
    fn woken(&mut self, e: &mut SchedEntity);

    /// 每个时钟 tick 调用一次：给正在运行的实体记账（`None` = 空闲），给在等的档位累积份额。
    /// `waiting` 是除正在运行者之外、还有可运行任务的档位集合。
    fn on_tick(&mut self, running: Option<&mut SchedEntity>, waiting: ClassMask);

    /// 每个 tick 记账之后判断是否要抢占当前实体。
    /// `current = None` 表示空闲（引导线程在等）：此时只要有任何可运行任务就抢占。
    fn should_preempt(&self, current: Option<&SchedEntity>, used: u32, quantum: u32, waiting: ClassMask) -> Option<Preempt>;

    /// 实体被唤醒时是否立即抢占当前实体（`None` = 空闲）。
    fn wake_preempts(&self, woken: Qos, current: Option<Qos>) -> bool;

    /// 默认档位（用户发起）的时间片（tick；诊断输出用）。
    fn default_quantum(&self) -> u32;
}

/// QoS 分级策略（见模块文档）。
pub struct QosPolicy {
    params: QosParams,
    /// 各档欠账（千分之一 tick）。
    owed: [u32; QOS_CLASSES],
    /// 已记账的 tick 数（衰减纪元 = ticks / decay_period）。
    ticks: u64,
    /// 决策序号。
    seq: u64,
}

impl QosPolicy {
    /// 以给定参数构造（`const`，可放进 `static`）。
    pub const fn new(params: QosParams) -> Self {
        QosPolicy { params, owed: [0; QOS_CLASSES], ticks: 0, seq: 0 }
    }

    /// 生效参数。
    pub const fn params(&self) -> &QosParams {
        &self.params
    }

    /// 当前衰减纪元。
    fn epoch(&self) -> u64 {
        self.ticks / self.params.decay_period.max(1) as u64
    }

    /// 实体在当前纪元的有效用量：每经过一个纪元减半（惰性计算，不改实体）。
    pub fn effective_usage(&self, e: &SchedEntity) -> u32 {
        let elapsed = self.epoch().saturating_sub(e.epoch);
        if elapsed >= 32 {
            0
        } else {
            e.usage >> elapsed
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
}

impl SchedPolicy for QosPolicy {
    fn name(&self) -> &'static str {
        "qos"
    }

    fn choose(&self, candidates: &mut dyn Iterator<Item = (usize, &SchedEntity)>) -> Option<Choice> {
        // 一次遍历：记下每档的最佳候选（刚被唤醒的优先，其次有效用量最少，再次最久没运行）。
        // 比较键相同则保留先遇到的（槽位序）——结果只取决于输入，便于确定性测试。
        let mut best: [Option<(usize, (bool, u32, u64))>; QOS_CLASSES] = [None; QOS_CLASSES];
        let mut runnable = ClassMask::EMPTY;
        for (slot, e) in candidates {
            runnable.insert(e.qos);
            let key = (!e.woken, self.effective_usage(e), e.last_seq);
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

    fn dispatched(&mut self, e: &mut SchedEntity) {
        self.seq += 1;
        e.last_seq = self.seq;
        e.woken = false;
    }

    fn woken(&mut self, e: &mut SchedEntity) {
        e.woken = true;
    }

    fn on_tick(&mut self, running: Option<&mut SchedEntity>, waiting: ClassMask) {
        self.ticks += 1;
        let epoch = self.epoch();
        let ran = running.map(|e| {
            // 先把用量衰减到当前纪元，再记入这个 tick。
            e.usage = self.effective_usage(e).saturating_add(USAGE_PER_TICK);
            e.epoch = epoch;
            e.cpu_ticks += 1;
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

    fn should_preempt(&self, current: Option<&SchedEntity>, used: u32, quantum: u32, waiting: ClassMask) -> Option<Preempt> {
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
        // 时间片用完：只有还有别的可运行任务时才值得切换（否则选回自己，徒增开销）。
        if used >= quantum && waiting != ClassMask::EMPTY {
            return Some(Preempt::Quantum);
        }
        None
    }

    fn default_quantum(&self) -> u32 {
        self.params.quantum[Qos::UserInitiated.index()]
    }

    fn wake_preempts(&self, woken: Qos, current: Option<Qos>) -> bool {
        match current {
            None => true,
            // 后台限速：后台任务被唤醒时只抢占空闲。
            Some(_) if woken == Qos::Background => false,
            Some(c) => woken.above(c),
        }
    }
}

/// 唤醒延迟直方图（单位 tick；无堆、定长）：桶 i 统计延迟恰为 i 的次数，最后一桶收容更大的值。
/// Wake-to-run latency histogram in ticks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LatencyHistogram {
    buckets: [u32; LATENCY_BUCKETS],
    count: u32,
    max: u64,
}

/// 直方图桶数（延迟 0..=14 各一桶，≥15 合并为一桶）。
pub const LATENCY_BUCKETS: usize = 16;

impl LatencyHistogram {
    /// 空直方图。
    pub const fn new() -> Self {
        LatencyHistogram { buckets: [0; LATENCY_BUCKETS], count: 0, max: 0 }
    }

    /// 记录一次延迟。
    pub fn record(&mut self, ticks: u64) {
        let i = (ticks as usize).min(LATENCY_BUCKETS - 1);
        self.buckets[i] = self.buckets[i].saturating_add(1);
        self.count = self.count.saturating_add(1);
        self.max = self.max.max(ticks);
    }

    /// 样本数。
    pub const fn count(&self) -> u32 {
        self.count
    }

    /// 最大延迟。
    pub const fn max(&self) -> u64 {
        self.max
    }

    /// 第 `permille` 千分位（如 990 = p99）：最小的 v，使延迟 ≤ v 的样本占比 ≥ 该千分比。
    /// 没有样本时返回 0；落在最后一桶时返回实际最大值。
    pub fn percentile(&self, permille: u32) -> u64 {
        if self.count == 0 {
            return 0;
        }
        let need = (self.count as u64 * permille.min(1000) as u64).div_ceil(1000).max(1);
        let mut acc = 0u64;
        for (i, &n) in self.buckets.iter().enumerate() {
            acc += n as u64;
            if acc >= need {
                return if i == LATENCY_BUCKETS - 1 { self.max } else { i as u64 };
            }
        }
        self.max
    }
}

impl Default for LatencyHistogram {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests;
