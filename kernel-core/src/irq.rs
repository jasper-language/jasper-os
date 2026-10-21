//! 设备中断多核化的纯决策：每核中断处理预算（超额节流、每 tick 补充）与中断线亲和的分配策略。
//! Pure decisions for multi-core device interrupts: per-core handling quotas and line affinity policies.
//!
//! # 职责
//! * [`CoreQuota`]：一个处理器在一个 tick 内处理设备中断可用的时间与次数。超出 ⇒ 该中断线被节流
//!   （由调用者在中断控制器上屏蔽），下一个 tick 补充预算时交还给调用者解除屏蔽。
//!   这样中断风暴最多占用每核一个固定比例的处理器时间，交互任务不会被饿死。
//!   MSI / MSI-X 按「向量槽位」记账，与传统中断线**共用同一份**每 tick 预算，节流集合分开记录
//!   （[`SlotSet`]），由调用者屏蔽 / 解除屏蔽产生该向量的消息表项。
//! * [`AffinityPolicy`]：给每条设备中断线选一个处理器（Strategy 模式，可替换）。
//!   默认的 [`Spread`] 按负载从大到小把中断线分给预计负载最小的处理器，带迟滞避免来回搬动；
//!   [`Keep`] 只修正不合法的位置，作为「不做均衡」的对照策略。
//!
//! # 边界与原因
//! * 只做记账与决定，不碰中断控制器、锁或时钟源：调用者给出周期计数与负载快照，执行屏蔽与路由。
//!   因此能在宿主上做确定性测试；内核的中断机制层负责采样与执行。
//! * 亲和集合是硬约束：任何分配都不会把中断线放到它的允许集合或在线集合之外；
//!   任一中断线无处可放时整次分配失败，输出不被修改。

use crate::msi::MAX_SLOTS;
use crate::smp::{CpuSet, MAX_CPUS};

/// 可登记的设备中断线上限（节流集合用 32 位位图表示）。
/// Maximum number of device interrupt lines.
pub const MAX_LINES: usize = 32;

/// 中断子系统的错误。
/// Errors of the interrupt subsystem.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IrqError {
    /// 中断线不存在（超出上限或平台没有这条线）。
    NoLine,
    /// 允许集合为空。
    EmptySet,
    /// 允许集合里没有在线处理器。
    Offline,
    /// 预算参数超出范围。
    BadQuota,
    /// 中断控制器拒绝了路由（例如目标处理器不可寻址）。
    RouteFailed,
}

impl IrqError {
    /// 规范名。
    /// Canonical name.
    pub const fn name(self) -> &'static str {
        match self {
            IrqError::NoLine => "system.irq.error.no_line",
            IrqError::EmptySet => "system.irq.error.empty_set",
            IrqError::Offline => "system.irq.error.offline",
            IrqError::BadQuota => "system.irq.error.bad_quota",
            IrqError::RouteFailed => "system.irq.error.route_failed",
        }
    }
}

// ---------------------------------------------------------------------------
// 每核预算
// ---------------------------------------------------------------------------

/// 预算参数。
/// Quota parameters.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct QuotaParams {
    /// 每个 tick 中设备中断处理可占用的时间（千分比，1..=900）。
    pub permille: u32,
    /// 每个 tick 每个处理器最多处理的设备中断次数（≥ 1；同时约束测不到的入口 / 返回开销）。
    pub max_per_tick: u32,
}

impl QuotaParams {
    /// 默认：四分之一的处理器时间、每 tick 至多 64 次。
    /// Default: a quarter of each tick, at most 64 interrupts per tick.
    pub const DEFAULT: QuotaParams = QuotaParams { permille: 250, max_per_tick: 64 };
    /// 千分比上限：至少留十分之一给任务。
    /// Upper bound of `permille`: at least a tenth of each tick stays with tasks.
    pub const MAX_PERMILLE: u32 = 900;

    /// 校验参数；不合法返回 [`IrqError::BadQuota`]。
    /// Validate the parameters.
    pub const fn validate(self) -> Result<QuotaParams, IrqError> {
        if self.permille == 0 || self.permille > Self::MAX_PERMILLE || self.max_per_tick == 0 {
            Err(IrqError::BadQuota)
        } else {
            Ok(self)
        }
    }
}

/// 一次记账的结果。
/// Outcome of charging one interrupt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Charge {
    /// 仍在预算内。
    Within,
    /// 本 tick 预算已用完：调用者应屏蔽这条线，直到下一次补充。
    Exhausted,
}

/// MSI 向量槽位集合（位图，容量 [`MAX_SLOTS`]）。
/// Set of MSI vector slots.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct SlotSet([u64; MAX_SLOTS / 64]);

impl SlotSet {
    /// 空集合。
    /// The empty set.
    pub const EMPTY: SlotSet = SlotSet([0; MAX_SLOTS / 64]);

    /// 是否为空。
    /// Whether the set is empty.
    pub const fn is_empty(&self) -> bool {
        let mut i = 0;
        while i < self.0.len() {
            if self.0[i] != 0 {
                return false;
            }
            i += 1;
        }
        true
    }

    /// 是否含槽位 `slot`（越界视为不含）。
    /// Whether `slot` is in the set.
    pub const fn contains(&self, slot: usize) -> bool {
        slot < MAX_SLOTS && self.0[slot / 64] & (1 << (slot % 64)) != 0
    }

    /// 加入槽位（调用者已校验 `slot < MAX_SLOTS`）；返回此前是否不在集合里。
    fn insert(&mut self, slot: usize) -> bool {
        let fresh = !self.contains(slot);
        self.0[slot / 64] |= 1 << (slot % 64);
        fresh
    }

    /// 元素个数。
    /// Number of slots in the set.
    pub const fn len(&self) -> usize {
        let mut n = 0;
        let mut i = 0;
        while i < self.0.len() {
            n += self.0[i].count_ones() as usize;
            i += 1;
        }
        n
    }

    /// 按从小到大遍历槽位。
    /// Iterate the slots in ascending order.
    pub fn iter(&self) -> impl Iterator<Item = usize> + '_ {
        (0..MAX_SLOTS).filter(move |&s| self.contains(s))
    }
}

/// 一次 tick 补充后需要解除屏蔽的集合。
/// What a tick refill releases.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Released {
    /// 被节流的传统中断线（位图）。
    pub lines: u32,
    /// 被节流的 MSI 向量槽位。
    pub msi: SlotSet,
}

/// 判定「被拉长的 tick」的门槛：间隔超过平滑 tick 长度的 3/2 即视为停表或补发，不计入长度测量。
/// Threshold (3/2 of the smoothed length) above which an interval is treated as a stretched tick.
pub const STRETCH_NUM: u64 = 3;
/// 见 [`STRETCH_NUM`]。
/// Denominator of the stretched-tick threshold.
pub const STRETCH_DEN: u64 = 2;

/// 一个处理器的设备中断预算（只由所属处理器在关中断状态下修改）。
/// Device-interrupt quota of one processor.
#[derive(Debug, Clone, Copy)]
pub struct CoreQuota {
    params: QuotaParams,
    /// 上一个 tick 的周期计数（0 = 尚未见过 tick）。
    last_tick: u64,
    /// 平滑后的 tick 长度（周期计数；0 = 尚未测得，只按次数限制）。
    tick_cycles: u64,
    used_cycles: u64,
    used_count: u32,
    /// 因预算而被节流的中断线集合。
    throttled: u32,
    /// 因预算而被节流的 MSI 向量槽位集合。
    msi_throttled: SlotSet,
    /// 累计节流次数（中断线）。
    throttle_events: u32,
    /// 累计节流次数（MSI 槽位）。
    msi_throttle_events: u32,
    /// 被判为拉长、未计入长度测量的 tick 数。
    stretched: u32,
    /// 累计处理次数与周期计数。
    handled: u64,
    cycles_total: u64,
}

impl CoreQuota {
    /// 新建一份预算（参数应已校验）。
    /// Create a quota with validated parameters.
    pub const fn new(params: QuotaParams) -> CoreQuota {
        CoreQuota {
            params,
            last_tick: 0,
            tick_cycles: 0,
            used_cycles: 0,
            used_count: 0,
            throttled: 0,
            msi_throttled: SlotSet::EMPTY,
            throttle_events: 0,
            msi_throttle_events: 0,
            stretched: 0,
            handled: 0,
            cycles_total: 0,
        }
    }

    /// 更换参数（下一次记账即生效）；不合法时不修改并返回错误。
    /// Replace the parameters.
    pub fn set_params(&mut self, params: QuotaParams) -> Result<(), IrqError> {
        self.params = params.validate()?;
        Ok(())
    }

    /// 当前参数。
    /// Current parameters.
    pub const fn params(&self) -> QuotaParams {
        self.params
    }

    /// 本 tick 的中断次数上限。
    /// Interrupt count limit of the current tick.
    pub const fn count_limit(&self) -> u32 {
        self.params.max_per_tick
    }

    /// 本 tick 可用的周期计数上限（tick 长度尚未测得时为 `None`）。
    /// Cycle limit of the current tick, once the tick length is known.
    pub const fn limit_cycles(&self) -> Option<u64> {
        if self.tick_cycles == 0 {
            None
        } else {
            Some(self.tick_cycles * self.params.permille as u64 / 1000)
        }
    }

    /// 平滑后的 tick 长度（周期计数）。
    /// Smoothed tick length in cycles.
    pub const fn tick_cycles(&self) -> u64 {
        self.tick_cycles
    }

    /// 本处理器是否还需要周期 tick：本 tick 处理过设备中断（预算窗口正在消耗）或有被节流的线
    /// （只有下一个 tick 才会解除屏蔽）。是 ⇒ 不得空闲停表，否则风暴下的补充与解除屏蔽会被推迟。
    /// Whether this CPU still needs its periodic tick for quota refill.
    pub const fn needs_tick(&self) -> bool {
        self.used_count != 0 || self.throttled != 0 || !self.msi_throttled.is_empty()
    }

    /// 被判为拉长、未计入长度测量的 tick 数。
    /// Number of stretched ticks excluded from the length estimate.
    pub const fn stretched_ticks(&self) -> u32 {
        self.stretched
    }

    /// 记一次设备中断处理（`cycles` 为处理耗时）。超出时间或次数上限 ⇒ 节流这条线并返回 [`Charge::Exhausted`]。
    /// 中断线超出上限时只记账、不节流（调用者已校验过线号）。
    /// Charge one handled interrupt of `line`.
    pub fn charge(&mut self, line: usize, cycles: u64) -> Charge {
        if self.spend(cycles) && line < MAX_LINES {
            if self.throttled & (1 << line) == 0 {
                self.throttle_events += 1;
            }
            self.throttled |= 1 << line;
            Charge::Exhausted
        } else {
            Charge::Within
        }
    }

    /// 记一次 MSI 处理（`slot` 为向量槽位，`cycles` 为处理耗时），与中断线共用本 tick 的预算。
    /// 超出 ⇒ 节流该槽位并返回 [`Charge::Exhausted`]；槽位越界返回 [`IrqError::NoLine`]，不记账、状态不变。
    /// Charge one handled MSI of `slot` against the shared per-tick quota.
    pub fn charge_msi(&mut self, slot: usize, cycles: u64) -> Result<Charge, IrqError> {
        if slot >= MAX_SLOTS {
            return Err(IrqError::NoLine);
        }
        if self.spend(cycles) {
            if self.msi_throttled.insert(slot) {
                self.msi_throttle_events += 1;
            }
            Ok(Charge::Exhausted)
        } else {
            Ok(Charge::Within)
        }
    }

    /// 记入一次处理的耗时与次数；返回本 tick 的时间或次数预算是否已用完。
    fn spend(&mut self, cycles: u64) -> bool {
        self.used_cycles = self.used_cycles.saturating_add(cycles);
        self.used_count = self.used_count.saturating_add(1);
        self.handled += 1;
        self.cycles_total = self.cycles_total.saturating_add(cycles);
        let over_time = self.limit_cycles().is_some_and(|l| self.used_cycles >= l);
        over_time || self.used_count >= self.count_limit()
    }

    /// 本处理器的 tick：测 tick 长度（取四分之三旧值 + 四分之一新值）、补充预算，
    /// 返回需要解除屏蔽的中断线与 MSI 槽位（之后两个节流集合都为空）。
    ///
    /// 超过平滑值 3/2 的间隔（见 [`STRETCH_NUM`]）不计入长度：那是空闲停表或长时间关中断后的补发 tick，
    /// 不是 tick 本身变长了；计入会把之后每个 tick 的时间预算成倍放大，风暴时就会超出预算。
    /// Refill on a tick; returns the lines to unmask. Stretched intervals do not feed the estimate.
    pub fn on_tick(&mut self, now: u64) -> Released {
        if self.last_tick != 0 && now > self.last_tick {
            let delta = now - self.last_tick;
            let stretched = self.tick_cycles != 0 && delta.saturating_mul(STRETCH_DEN) > self.tick_cycles.saturating_mul(STRETCH_NUM);
            if stretched {
                self.stretched = self.stretched.saturating_add(1);
            } else {
                self.tick_cycles = if self.tick_cycles == 0 { delta } else { (self.tick_cycles * 3 + delta) / 4 };
            }
        }
        self.last_tick = now;
        self.used_cycles = 0;
        self.used_count = 0;
        Released { lines: core::mem::take(&mut self.throttled), msi: core::mem::take(&mut self.msi_throttled) }
    }

    /// 当前被节流的中断线集合。
    /// Lines currently throttled on this processor.
    pub const fn throttled(&self) -> u32 {
        self.throttled
    }

    /// 当前被节流的 MSI 槽位集合。
    /// MSI slots currently throttled on this processor.
    pub const fn msi_throttled(&self) -> SlotSet {
        self.msi_throttled
    }

    /// 累计 MSI 槽位节流次数。
    /// Number of MSI throttle events.
    pub const fn msi_throttles(&self) -> u32 {
        self.msi_throttle_events
    }

    /// 统计：(累计处理次数（中断线与 MSI 合计）, 累计处理周期计数, 累计中断线节流次数)。
    /// Statistics: handled count, handled cycles, throttle events.
    pub const fn stats(&self) -> (u64, u64, u32) {
        (self.handled, self.cycles_total, self.throttle_events)
    }

    /// 清零统计（参数、tick 长度与节流状态保留）。
    /// Reset statistics, keeping parameters, tick length and throttle state.
    pub fn reset_stats(&mut self) {
        self.handled = 0;
        self.cycles_total = 0;
        self.throttle_events = 0;
        self.msi_throttle_events = 0;
    }
}

// ---------------------------------------------------------------------------
// 亲和分配
// ---------------------------------------------------------------------------

/// 一条中断线的分配输入。
/// Assignment input of one line.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LineLoad {
    /// 允许的处理器集合（用户或驱动设定的亲和）。
    pub allowed: CpuSet,
    /// 当前路由到的处理器。
    pub current: Option<usize>,
    /// 最近一个窗口的负载（处理周期计数或次数，单位由调用者统一）。
    pub load: u64,
}

/// 分配策略（Strategy 模式）：为每条线写出目标处理器。
/// 实现必须先校验全部输入：任一线无合法处理器 ⇒ 返回错误且不修改 `out`。
/// Affinity assignment strategy.
pub trait AffinityPolicy {
    /// 策略名（诊断输出用）。
    /// Policy name.
    fn name(&self) -> &'static str;

    /// `lines[i]` 的目标写到 `out[i]`；`base[c]` 是处理器 c 上中断以外的已有负载（与 `load` 同一单位）。
    /// Write the target processor of `lines[i]` into `out[i]`.
    fn assign(&self, lines: &[LineLoad], online: CpuSet, base: &[u64; MAX_CPUS], out: &mut [usize]) -> Result<(), IrqError>;
}

/// 每条线的候选集合 = 允许 ∩ 在线；任一为空即拒绝（空允许集合单独报告）。
fn validate(lines: &[LineLoad], online: CpuSet, out: &[usize]) -> Result<(), IrqError> {
    if lines.len() > MAX_LINES || out.len() < lines.len() {
        return Err(IrqError::NoLine);
    }
    for l in lines {
        if l.allowed.is_empty() {
            return Err(IrqError::EmptySet);
        }
        if l.allowed.intersect(online).is_empty() {
            return Err(IrqError::Offline);
        }
    }
    Ok(())
}

fn candidates(l: &LineLoad, online: CpuSet) -> CpuSet {
    l.allowed.intersect(online)
}

/// 均衡策略：按负载从大到小，把每条线放到预计负载最小的合法处理器；
/// 只有搬动后「两核中较大的预计负载」比不搬时小出该线负载的 `hysteresis_permille`‰ 以上才搬。
/// Spreading policy with hysteresis.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Spread {
    /// 迟滞（千分比，相对于该线自身负载）。
    pub hysteresis_permille: u32,
}

impl Spread {
    /// 默认迟滞：该线负载的四分之一。
    /// Default hysteresis: a quarter of the line's own load.
    pub const DEFAULT: Spread = Spread { hysteresis_permille: 250 };
}

impl AffinityPolicy for Spread {
    fn name(&self) -> &'static str {
        "spread"
    }

    fn assign(&self, lines: &[LineLoad], online: CpuSet, base: &[u64; MAX_CPUS], out: &mut [usize]) -> Result<(), IrqError> {
        validate(lines, online, out)?;
        // 按负载从大到小（同负载按线号）排出处理顺序
        let mut order = [0usize; MAX_LINES];
        for (i, o) in order.iter_mut().enumerate().take(lines.len()) {
            *o = i;
        }
        let order = &mut order[..lines.len()];
        order.sort_unstable_by(|&a, &b| lines[b].load.cmp(&lines[a].load).then(a.cmp(&b)));
        let mut proj = *base;
        for &i in order.iter() {
            let l = &lines[i];
            let cands = candidates(l, online);
            let best = cands.iter().min_by_key(|&c| (proj[c], c)).unwrap_or(0);
            let target = match l.current.filter(|&c| cands.contains(c)) {
                Some(cur) if cur != best => {
                    let (a, b, load) = (proj[cur], proj[best], l.load);
                    let stay = (a + load).max(b);
                    let moved = a.max(b + load);
                    let margin = load * self.hysteresis_permille as u64 / 1000;
                    if moved + margin < stay {
                        best
                    } else {
                        cur
                    }
                }
                Some(cur) => cur,
                None => best,
            };
            proj[target] += l.load;
            out[i] = target;
        }
        Ok(())
    }
}

/// 对照策略：合法的当前位置保持不动，不合法（未路由、离线或不在允许集合内）时取候选集合中下标最小的处理器。
/// Keep policy: only repairs illegal placements.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Keep;

impl AffinityPolicy for Keep {
    fn name(&self) -> &'static str {
        "keep"
    }

    fn assign(&self, lines: &[LineLoad], online: CpuSet, _base: &[u64; MAX_CPUS], out: &mut [usize]) -> Result<(), IrqError> {
        validate(lines, online, out)?;
        for (i, l) in lines.iter().enumerate() {
            let cands = candidates(l, online);
            out[i] = l.current.filter(|&c| cands.contains(c)).or_else(|| cands.iter().next()).unwrap_or(0);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn set(cpus: &[usize]) -> CpuSet {
        let mut s = CpuSet::EMPTY;
        for &c in cpus {
            s.insert(c);
        }
        s
    }

    fn line(allowed: CpuSet, current: Option<usize>, load: u64) -> LineLoad {
        LineLoad { allowed, current, load }
    }

    #[test]
    fn quota_params_validate_bounds() {
        assert!(QuotaParams::DEFAULT.validate().is_ok());
        assert_eq!(QuotaParams { permille: 0, max_per_tick: 8 }.validate(), Err(IrqError::BadQuota));
        assert_eq!(QuotaParams { permille: 901, max_per_tick: 8 }.validate(), Err(IrqError::BadQuota));
        assert_eq!(QuotaParams { permille: 500, max_per_tick: 0 }.validate(), Err(IrqError::BadQuota));
        assert_eq!(IrqError::BadQuota.name(), "system.irq.error.bad_quota");
    }

    #[test]
    fn quota_counts_until_tick_length_known_then_time() {
        let mut b = CoreQuota::new(QuotaParams { permille: 250, max_per_tick: 4 });
        // 尚未见过 tick：只有次数限制
        assert_eq!(b.limit_cycles(), None);
        for _ in 0..3 {
            assert_eq!(b.charge(1, 1_000_000), Charge::Within);
        }
        assert_eq!(b.charge(1, 1), Charge::Exhausted);
        assert_eq!(b.throttled(), 1 << 1);
        // 两个 tick 之后测得长度 1000，预算 250
        assert_eq!(b.on_tick(10_000).lines, 1 << 1);
        assert_eq!(b.throttled(), 0);
        assert_eq!(b.on_tick(11_000).lines, 0);
        assert_eq!(b.limit_cycles(), Some(250));
        assert_eq!(b.charge(3, 100), Charge::Within);
        assert_eq!(b.charge(3, 100), Charge::Within);
        assert_eq!(b.charge(5, 60), Charge::Exhausted);
        // 被节流的线再到一次只算一次节流事件
        assert_eq!(b.charge(5, 1), Charge::Exhausted);
        assert_eq!(b.throttled(), 1 << 5);
        let (handled, cycles, events) = b.stats();
        assert_eq!((handled, events), (8, 2));
        assert_eq!(cycles, 3_000_000 + 1 + 100 + 100 + 60 + 1);
        // 补充：交还节流集合，预算清零
        assert_eq!(b.on_tick(12_000).lines, 1 << 5);
        assert_eq!(b.charge(5, 10), Charge::Within);
    }

    #[test]
    fn stretched_tick_does_not_inflate_the_quota() {
        let p = QuotaParams { permille: 250, max_per_tick: 10 };
        let mut q = CoreQuota::new(p);
        q.on_tick(1000);
        q.on_tick(2000);
        assert_eq!(q.limit_cycles(), Some(250));
        assert!(!q.needs_tick(), "没有处理过中断的空闲窗口可以停表");
        // 空闲停表：一个间隔是平常的 4 倍。预算不随之放大，被节流的线照常交还。
        q.charge(2, 300);
        assert_eq!(q.throttled(), 1 << 2);
        assert!(q.needs_tick(), "有被节流的线时必须保持周期 tick");
        assert_eq!(q.on_tick(6000).lines, 1 << 2);
        assert_eq!(q.tick_cycles(), 1000);
        assert_eq!(q.limit_cycles(), Some(250));
        assert_eq!(q.count_limit(), 10);
        assert_eq!(q.stretched_ticks(), 1);
        assert!(!q.needs_tick(), "补充之后窗口清零");
        q.charge(40, 1);
        assert!(q.needs_tick(), "窗口内处理过中断（即便线号越界未节流）也要保持周期 tick");
        // 恢复周期 tick 之后照常测量
        q.on_tick(7100);
        assert_eq!(q.tick_cycles(), (3000 + 1100) / 4);
        assert_eq!(q.stretched_ticks(), 1);
    }

    #[test]
    fn quota_smooths_tick_length_and_ignores_backwards_clock() {
        let mut b = CoreQuota::new(QuotaParams::DEFAULT);
        b.on_tick(1000);
        b.on_tick(2000);
        assert_eq!(b.tick_cycles(), 1000);
        // 1.4 倍：仍在门槛内，计入平滑
        b.on_tick(3400);
        assert_eq!(b.tick_cycles(), (3000 + 1400) / 4);
        let before = b.tick_cycles();
        b.on_tick(3000);
        assert_eq!(b.tick_cycles(), before);
    }

    #[test]
    fn quota_set_params_rejects_without_change_and_line_out_of_range_not_throttled() {
        let mut b = CoreQuota::new(QuotaParams { permille: 100, max_per_tick: 1 });
        assert_eq!(b.set_params(QuotaParams { permille: 0, max_per_tick: 1 }), Err(IrqError::BadQuota));
        assert_eq!(b.params(), QuotaParams { permille: 100, max_per_tick: 1 });
        assert_eq!(b.charge(MAX_LINES, 1), Charge::Within);
        assert_eq!(b.throttled(), 0);
        b.reset_stats();
        assert_eq!(b.stats(), (0, 0, 0));
        assert!(b.set_params(QuotaParams { permille: 500, max_per_tick: 2 }).is_ok());
        assert_eq!(b.params().max_per_tick, 2);
    }

    #[test]
    fn spread_puts_equal_lines_on_distinct_cores() {
        let all = CpuSet::first(4);
        let lines = [line(all, Some(0), 100), line(all, Some(0), 100), line(all, Some(0), 100), line(all, Some(0), 100)];
        let mut out = [9usize; 4];
        Spread::DEFAULT.assign(&lines, all, &[0; MAX_CPUS], &mut out).unwrap();
        let mut seen = CpuSet::EMPTY;
        for &c in &out {
            assert!(seen.insert(c), "两条线落在同一个核 {out:?}");
        }
        assert_eq!(seen, all);
    }

    #[test]
    fn spread_avoids_busy_cores_and_respects_allowed() {
        let all = CpuSet::first(4);
        let mut base = [0u64; MAX_CPUS];
        base[0] = 1000;
        base[1] = 500;
        let lines = [line(all, None, 300), line(set(&[0, 1]), None, 300)];
        let mut out = [0usize; 2];
        Spread::DEFAULT.assign(&lines, all, &base, &mut out).unwrap();
        assert!(out[0] == 2 || out[0] == 3);
        assert_eq!(out[1], 1);
    }

    #[test]
    fn spread_hysteresis_keeps_nearly_balanced_line() {
        let all = CpuSet::first(2);
        let mut base = [0u64; MAX_CPUS];
        // 当前核比最闲的核只多一点：不值得搬
        base[0] = 110;
        base[1] = 100;
        let lines = [line(all, Some(0), 100)];
        let mut out = [9usize; 1];
        Spread::DEFAULT.assign(&lines, all, &base, &mut out).unwrap();
        assert_eq!(out[0], 0);
        // 差距远大于迟滞：搬
        base[0] = 400;
        Spread::DEFAULT.assign(&lines, all, &base, &mut out).unwrap();
        assert_eq!(out[0], 1);
    }

    #[test]
    fn assign_refuses_empty_offline_and_leaves_output() {
        let online = CpuSet::first(2);
        let mut out = [7usize; 2];
        let bad_empty = [line(online, Some(0), 1), line(CpuSet::EMPTY, None, 1)];
        assert_eq!(Spread::DEFAULT.assign(&bad_empty, online, &[0; MAX_CPUS], &mut out), Err(IrqError::EmptySet));
        assert_eq!(out, [7, 7]);
        let bad_off = [line(set(&[3]), None, 1)];
        assert_eq!(Keep.assign(&bad_off, online, &[0; MAX_CPUS], &mut out), Err(IrqError::Offline));
        assert_eq!(out, [7, 7]);
        let too_many = [line(online, None, 1); MAX_LINES + 1];
        let mut big = [0usize; MAX_LINES + 1];
        assert_eq!(Spread::DEFAULT.assign(&too_many, online, &[0; MAX_CPUS], &mut big), Err(IrqError::NoLine));
        assert_eq!(Spread::DEFAULT.assign(&bad_off[..0], online, &[0; MAX_CPUS], &mut out[..0]), Ok(()));
    }

    #[test]
    fn keep_only_repairs_illegal_placement() {
        let online = CpuSet::first(4);
        let lines = [line(online, Some(3), 1000), line(set(&[1, 2]), Some(0), 1), line(online, None, 1)];
        let mut out = [0usize; 3];
        Keep.assign(&lines, online, &[0; MAX_CPUS], &mut out).unwrap();
        assert_eq!(out, [3, 1, 0]);
        assert_eq!(Keep.name(), "keep");
        assert_eq!(Spread::DEFAULT.name(), "spread");
    }

    /// 测得 tick 长度 1000（时间预算 = 1000 × permille / 1000）的预算。
    fn measured(permille: u32, max_per_tick: u32) -> CoreQuota {
        let mut q = CoreQuota::new(QuotaParams { permille, max_per_tick });
        q.on_tick(1000);
        q.on_tick(2000);
        assert_eq!(q.tick_cycles(), 1000);
        q
    }

    #[test]
    fn msi_shares_quota_with_lines_both_ways() {
        // 线先用完 ⇒ 随后的 MSI 立即被节流
        let mut q = CoreQuota::new(QuotaParams { permille: 250, max_per_tick: 3 });
        assert_eq!(q.charge(0, 1), Charge::Within);
        assert_eq!(q.charge(0, 1), Charge::Within);
        assert_eq!(q.charge_msi(40, 1), Ok(Charge::Exhausted));
        assert!(q.msi_throttled().contains(40));
        assert_eq!(q.throttled(), 0);
        // MSI 先用完 ⇒ 随后的线立即被节流
        let mut q = CoreQuota::new(QuotaParams { permille: 250, max_per_tick: 2 });
        assert_eq!(q.charge_msi(41, 1), Ok(Charge::Within));
        assert_eq!(q.charge_msi(41, 1), Ok(Charge::Exhausted));
        assert_eq!(q.charge(3, 1), Charge::Exhausted);
        assert_eq!(q.throttled(), 1 << 3);
        assert_eq!(q.msi_throttled().len(), 1);
        assert_eq!(q.stats().0, 3);
    }

    #[test]
    fn msi_throttled_by_count() {
        let mut q = CoreQuota::new(QuotaParams { permille: 900, max_per_tick: 4 });
        for _ in 0..3 {
            assert_eq!(q.charge_msi(200, 0), Ok(Charge::Within));
        }
        assert_eq!(q.charge_msi(200, 0), Ok(Charge::Exhausted));
        // 已节流的槽位再次超额：仍报告用完，但节流次数只算一次
        assert_eq!(q.charge_msi(200, 0), Ok(Charge::Exhausted));
        assert_eq!(q.msi_throttles(), 1);
        assert!(q.needs_tick());
    }

    #[test]
    fn msi_throttled_by_time() {
        let mut q = measured(250, 64);
        assert_eq!(q.limit_cycles(), Some(250));
        assert_eq!(q.charge_msi(7, 100), Ok(Charge::Within));
        assert_eq!(q.charge_msi(7, 149), Ok(Charge::Within));
        assert_eq!(q.charge_msi(7, 1), Ok(Charge::Exhausted));
        assert!(q.msi_throttled().contains(7));
        assert!(!q.msi_throttled().contains(8));
    }

    #[test]
    fn msi_tick_releases_and_clears() {
        let mut q = measured(250, 2);
        q.charge(1, 0);
        q.charge_msi(9, 0).unwrap();
        q.charge_msi(255, 0).unwrap();
        let r = q.on_tick(3000);
        assert_eq!(r.lines, 0);
        assert_eq!(r.msi.iter().collect::<std::vec::Vec<_>>(), [9, 255]);
        assert!(q.msi_throttled().is_empty());
        assert!(!q.needs_tick());
        // 补充后预算重新可用；空 tick 什么也不释放
        assert_eq!(q.charge_msi(9, 0), Ok(Charge::Within));
        assert_eq!(q.on_tick(4000), Released::default());
        assert_eq!(q.msi_throttles(), 2);
        q.reset_stats();
        assert_eq!(q.msi_throttles(), 0);
    }

    #[test]
    fn msi_out_of_range_slot_rejected_without_change() {
        let mut q = measured(250, 2);
        q.charge_msi(3, 0).unwrap();
        let before = (q.stats(), q.msi_throttled(), q.needs_tick());
        assert_eq!(q.charge_msi(MAX_SLOTS, 1_000_000), Err(IrqError::NoLine));
        assert_eq!(q.charge_msi(usize::MAX, 1), Err(IrqError::NoLine));
        assert_eq!((q.stats(), q.msi_throttled(), q.needs_tick()), before);
        // 未超额：下一次记账仍在预算内（越界调用没有消耗次数）
        let mut fresh = CoreQuota::new(QuotaParams { permille: 250, max_per_tick: 2 });
        assert!(fresh.charge_msi(MAX_SLOTS, 0).is_err());
        assert_eq!(fresh.charge_msi(0, 0), Ok(Charge::Within));
        assert!(!SlotSet::EMPTY.contains(MAX_SLOTS));
    }

    #[test]
    fn msi_set_params_takes_effect_immediately() {
        let mut q = CoreQuota::new(QuotaParams { permille: 250, max_per_tick: 64 });
        assert_eq!(q.charge_msi(5, 0), Ok(Charge::Within));
        q.set_params(QuotaParams { permille: 250, max_per_tick: 2 }).unwrap();
        assert_eq!(q.charge_msi(5, 0), Ok(Charge::Exhausted));
        // 非法参数被拒，原参数不变
        assert_eq!(q.set_params(QuotaParams { permille: 0, max_per_tick: 2 }), Err(IrqError::BadQuota));
        assert_eq!(q.params(), QuotaParams { permille: 250, max_per_tick: 2 });
        q.on_tick(10);
        q.set_params(QuotaParams { permille: 250, max_per_tick: 64 }).unwrap();
        assert_eq!(q.charge_msi(5, 0), Ok(Charge::Within));
    }
}
