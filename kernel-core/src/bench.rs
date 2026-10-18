//! 基准测量的统计与参数取值规则（与硬件无关，宿主可测）。
//! Benchmark statistics and measurement-driven parameter selection (hardware independent).
//!
//! # 职责
//! * [`Samples`] —— 定长样本缓冲（无堆）：记录每次操作的耗时（周期计数器单位），满了就拒收并计数；
//! * [`Summary`] —— 样本的最小值 / 中位数 / 第 99 百分位 / 最大值 / 均值（最近秩法，结果可复现）；
//! * [`Calibration`] —— 用定时器 tick 校准周期计数器：周期 → 纳秒、每秒周期数；
//! * [`overhead_ppm`] 与 [`select`] —— 把「固定开销 / 周期长度」换算成百万分比，按预算与偏好方向
//!   在候选取值中选出边界值，并给出当前取值是否在预算内（[`Decision`]）。
//!
//! # 边界（为什么放在这里）
//! 读周期计数器、开关中断、跑被测操作都在内核与用户程序里；这里只有纯算术，因此统计口径与取值规则
//! 可以在宿主上用确定的输入验证，内核与用户态共用同一份实现、口径一致。
//!
//! # 取值规则的含义
//! 周期性开销（时钟中断、时间片轮转时的上下文切换）按「每个周期的固定成本 / 周期长度」计入百万分比。
//! [`Prefer`] 是策略：时钟频率越高定时越细，故取**预算内最大**的候选；时间片越短交互越及时，故取**预算内最小**的候选。
//! 得到的是预算允许的边界，不是唯一答案：默认值只要在预算内即可保留，由调用者结合其它约束决定。

/// 单个缓冲最多保存的样本数。
pub const MAX_SAMPLES: usize = 256;

/// 定长样本缓冲。
/// Fixed-capacity sample buffer (no heap).
#[derive(Debug, Clone)]
pub struct Samples {
    buf: [u64; MAX_SAMPLES],
    len: usize,
    rejected: u32,
}

impl Default for Samples {
    fn default() -> Self {
        Self::new()
    }
}

impl Samples {
    /// 空缓冲。
    /// Empty buffer.
    pub const fn new() -> Self {
        Samples { buf: [0; MAX_SAMPLES], len: 0, rejected: 0 }
    }

    /// 记录一个样本；缓冲已满时拒收（已有样本不变）并计入 [`Samples::rejected`]，返回 `false`。
    /// Record one sample; returns `false` (and keeps existing samples) when full.
    pub fn push(&mut self, v: u64) -> bool {
        if self.len == MAX_SAMPLES {
            self.rejected = self.rejected.saturating_add(1);
            return false;
        }
        self.buf[self.len] = v;
        self.len += 1;
        true
    }

    /// 已保存的样本数。
    /// Number of stored samples.
    pub const fn len(&self) -> usize {
        self.len
    }

    /// 是否没有样本。
    /// Whether no sample is stored.
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// 因缓冲已满被拒收的样本数。
    /// Samples rejected because the buffer was full.
    pub const fn rejected(&self) -> u32 {
        self.rejected
    }

    /// 汇总；没有样本时为 `None`。不修改缓冲（在副本上排序）。
    /// Summarize the samples; `None` when empty. The buffer itself is not reordered.
    pub fn summary(&self) -> Option<Summary> {
        if self.len == 0 {
            return None;
        }
        let mut sorted = self.buf;
        let s = &mut sorted[..self.len];
        s.sort_unstable();
        let sum: u128 = s.iter().map(|&v| v as u128).sum();
        Some(Summary {
            count: self.len as u32,
            min: s[0],
            p50: rank(s, 500),
            p99: rank(s, 990),
            max: s[self.len - 1],
            mean: (sum / self.len as u128) as u64,
        })
    }
}

/// 最近秩法的千分位：第 `ceil(p × n / 1000)` 小的样本（`s` 已排序且非空）。
fn rank(s: &[u64], permille: usize) -> u64 {
    let n = s.len();
    let k = (permille * n).div_ceil(1000).clamp(1, n);
    s[k - 1]
}

/// 样本汇总（单位与样本相同）。
/// Summary of a sample set.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Summary {
    /// 样本数。
    pub count: u32,
    /// 最小值。
    pub min: u64,
    /// 中位数（最近秩）。
    pub p50: u64,
    /// 第 99 百分位（最近秩）。
    pub p99: u64,
    /// 最大值。
    pub max: u64,
    /// 算术平均（向下取整）。
    pub mean: u64,
}

/// 周期计数器的校准结果：在 `ticks` 个定时器 tick 内走过了 `cycles` 个周期。
/// Cycle-counter calibration against the periodic timer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Calibration {
    cycles_per_tick: u64,
    timer_hz: u32,
}

impl Calibration {
    /// 由一次测量建立校准；任何一个量为 0（计数器不走、没等到 tick、频率未知）时为 `None`。
    /// Build a calibration; `None` if any input is zero.
    pub fn new(cycles: u64, ticks: u64, timer_hz: u32) -> Option<Self> {
        if cycles == 0 || ticks == 0 || timer_hz == 0 {
            return None;
        }
        let cycles_per_tick = cycles / ticks;
        if cycles_per_tick == 0 {
            return None;
        }
        Some(Calibration { cycles_per_tick, timer_hz })
    }

    /// 只知道每秒周期数时（例如由内核把校准结果传给用户程序）建立校准：视为 1 Hz、每 tick `cycles_per_second` 个周期。
    /// Build a calibration from cycles per second alone (treated as a 1 Hz timer).
    pub fn per_second(cycles_per_second: u64) -> Option<Self> {
        Self::new(cycles_per_second, 1, 1)
    }

    /// 每个 tick 的周期数。
    /// Cycles per timer tick.
    pub const fn cycles_per_tick(&self) -> u64 {
        self.cycles_per_tick
    }

    /// 校准时的定时器频率（Hz）。
    /// Timer frequency used for calibration.
    pub const fn timer_hz(&self) -> u32 {
        self.timer_hz
    }

    /// 每秒周期数。
    /// Cycles per second.
    pub const fn cycles_per_second(&self) -> u64 {
        self.cycles_per_tick.saturating_mul(self.timer_hz as u64)
    }

    /// 周期数换算为纳秒（向下取整，饱和）。
    /// Convert cycles to nanoseconds (floor, saturating).
    pub fn to_ns(&self, cycles: u64) -> u64 {
        let ns = cycles as u128 * 1_000_000_000 / self.cycles_per_second() as u128;
        ns.min(u64::MAX as u128) as u64
    }
}

/// 每个周期固定花费 `cost` 个周期、周期长 `period` 个周期时的开销（百万分比，饱和）；`period` 为 0 时为 `None`。
/// Overhead of a fixed per-period cost, in parts per million.
pub fn overhead_ppm(cost: u64, period: u64) -> Option<u64> {
    if period == 0 {
        return None;
    }
    let ppm = cost as u128 * 1_000_000 / period as u128;
    Some(ppm.min(u64::MAX as u128) as u64)
}

/// 选取方向（策略）。
/// Selection direction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Prefer {
    /// 预算内取最大的候选（例如时钟频率）。
    Largest,
    /// 预算内取最小的候选（例如时间片）。
    Smallest,
}

/// 取值失败的原因。
/// Why a selection could not be made.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TuneError {
    /// 没有候选取值。
    NoCandidates,
    /// 某个候选取值（或当前取值）无法换算开销（例如为 0）。
    InvalidValue(u32),
}

/// 一次取值的结论。
/// Outcome of a measurement-driven selection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Decision {
    /// 参数名（与配置输出中的名字一致）。
    pub param: &'static str,
    /// 当前取值。
    pub current: u32,
    /// 当前取值的开销（百万分比）。
    pub current_ppm: u64,
    /// 预算内按偏好方向的边界候选；没有候选在预算内时为 `None`。
    pub bound: Option<u32>,
    /// 边界候选的开销（百万分比）。
    pub bound_ppm: Option<u64>,
    /// 预算（百万分比）。
    pub limit_ppm: u64,
}

impl Decision {
    /// 当前取值是否在预算内。
    /// Whether the current value fits the limit.
    pub const fn current_within_limit(&self) -> bool {
        self.current_ppm <= self.limit_ppm
    }
}

/// 在 `candidates` 中按 `prefer` 选出开销不超过 `limit_ppm` 的边界取值，并评估 `current`。
/// `cost` 把一个取值换算成开销（百万分比），无法换算时返回 `None`。
/// 任何一个取值无法换算即整体失败（不给出部分结论）。
/// Pick the limit-bounded extreme candidate and evaluate the current value.
pub fn select(
    param: &'static str,
    current: u32,
    candidates: &[u32],
    limit_ppm: u64,
    prefer: Prefer,
    cost: impl Fn(u32) -> Option<u64>,
) -> Result<Decision, TuneError> {
    if candidates.is_empty() {
        return Err(TuneError::NoCandidates);
    }
    let current_ppm = cost(current).ok_or(TuneError::InvalidValue(current))?;
    let mut bound: Option<(u32, u64)> = None;
    for &c in candidates {
        let ppm = cost(c).ok_or(TuneError::InvalidValue(c))?;
        if ppm > limit_ppm {
            continue;
        }
        let better = match (bound, prefer) {
            (None, _) => true,
            (Some((b, _)), Prefer::Largest) => c > b,
            (Some((b, _)), Prefer::Smallest) => c < b,
        };
        if better {
            bound = Some((c, ppm));
        }
    }
    Ok(Decision { param, current, current_ppm, bound: bound.map(|b| b.0), bound_ppm: bound.map(|b| b.1), limit_ppm })
}

/// 时钟频率的开销：每个 tick 的中断成本 `tick_cost` × 频率 / 每秒周期数。
/// Timer-interrupt overhead of running the timer at `hz`.
pub fn timer_overhead(tick_cost: u64, cal: &Calibration, hz: u32) -> Option<u64> {
    if hz == 0 {
        return None;
    }
    overhead_ppm(tick_cost.saturating_mul(hz as u64), cal.cycles_per_second())
}

/// 时间片的开销：一次切换成本 `switch_cost` / （时间片 tick 数 × 每 tick 周期数）。
/// Context-switch overhead of a time slice of `quantum` ticks.
pub fn quantum_overhead(switch_cost: u64, cal: &Calibration, quantum: u32) -> Option<u64> {
    if quantum == 0 {
        return None;
    }
    overhead_ppm(switch_cost, cal.cycles_per_tick().saturating_mul(quantum as u64))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn summary_uses_nearest_rank_and_keeps_buffer() {
        let mut s = Samples::new();
        assert!(s.summary().is_none(), "空缓冲没有汇总");
        for v in (1..=100u64).rev() {
            assert!(s.push(v));
        }
        let sum = s.summary().unwrap();
        assert_eq!(sum, Summary { count: 100, min: 1, p50: 50, p99: 99, max: 100, mean: 50 });
        // 汇总不改变缓冲本身：再次汇总结果相同
        assert_eq!(s.summary().unwrap(), sum);
        let mut one = Samples::new();
        one.push(7);
        assert_eq!(one.summary().unwrap(), Summary { count: 1, min: 7, p50: 7, p99: 7, max: 7, mean: 7 });
    }

    #[test]
    fn full_buffer_rejects_without_changing_samples() {
        let mut s = Samples::new();
        for i in 0..MAX_SAMPLES as u64 {
            assert!(s.push(i));
        }
        let before = s.summary().unwrap();
        assert!(!s.push(u64::MAX), "满了必须拒收");
        assert!(!s.push(0));
        assert_eq!(s.len(), MAX_SAMPLES);
        assert_eq!(s.rejected(), 2);
        assert_eq!(s.summary().unwrap(), before, "拒收不得改变已有样本");
    }

    #[test]
    fn calibration_converts_and_rejects_zero_inputs() {
        let cal = Calibration::new(10_000_000, 10, 100).unwrap();
        assert_eq!(cal.cycles_per_tick(), 1_000_000);
        assert_eq!(cal.cycles_per_second(), 100_000_000);
        assert_eq!(cal.to_ns(100), 1_000);
        assert_eq!(cal.to_ns(u64::MAX), u64::MAX, "换算饱和");
        let ps = Calibration::per_second(100_000_000).unwrap();
        assert_eq!(ps.cycles_per_second(), 100_000_000);
        assert_eq!(ps.to_ns(100), 1_000, "两种建立方式换算一致");
        assert!(Calibration::per_second(0).is_none());
        assert!(Calibration::new(0, 10, 100).is_none());
        assert!(Calibration::new(10, 0, 100).is_none());
        assert!(Calibration::new(10, 10, 0).is_none());
        assert!(Calibration::new(5, 10, 100).is_none(), "不足一周期每 tick 视为未校准");
    }

    #[test]
    fn overhead_is_ppm_and_saturates() {
        assert_eq!(overhead_ppm(1, 1_000), Some(1_000));
        assert_eq!(overhead_ppm(0, 5), Some(0));
        assert_eq!(overhead_ppm(u64::MAX, 1), Some(u64::MAX));
        assert_eq!(overhead_ppm(1, 0), None);
    }

    #[test]
    fn select_picks_bound_by_direction() {
        let cal = Calibration::new(1_000_000, 1, 100).unwrap(); // 每秒 1e8 周期
        // 每 tick 成本 10_000 周期：100 Hz = 1e4 ppm，250 Hz = 2.5e4，1000 Hz = 1e5
        let d = select("timer_hz", 100, &[100, 250, 1000], 30_000, Prefer::Largest, |hz| timer_overhead(10_000, &cal, hz)).unwrap();
        assert_eq!(d.bound, Some(250));
        assert_eq!(d.bound_ppm, Some(25_000));
        assert_eq!(d.current_ppm, 10_000);
        assert!(d.current_within_limit());
        // 每次切换 20_000 周期：1 tick = 2e4 ppm，2 tick = 1e4，4 tick = 5e3
        let q = select("quantum", 2, &[4, 1, 2], 10_000, Prefer::Smallest, |q| quantum_overhead(20_000, &cal, q)).unwrap();
        assert_eq!(q.bound, Some(2));
        assert_eq!(q.current_ppm, 10_000);
        assert!(q.current_within_limit(), "恰好等于预算视为在预算内");
    }

    #[test]
    fn select_reports_none_and_out_of_limit_current() {
        let cal = Calibration::new(1_000_000, 1, 100).unwrap();
        let d = select("timer_hz", 1000, &[250, 1000], 1_000, Prefer::Largest, |hz| timer_overhead(10_000, &cal, hz)).unwrap();
        assert_eq!(d.bound, None);
        assert_eq!(d.bound_ppm, None);
        assert!(!d.current_within_limit());
    }

    #[test]
    fn select_rejects_invalid_inputs_without_partial_result() {
        let cal = Calibration::new(1_000_000, 1, 100).unwrap();
        let cost = |q| quantum_overhead(1, &cal, q);
        assert_eq!(select("quantum", 2, &[], 10, Prefer::Smallest, cost), Err(TuneError::NoCandidates));
        assert_eq!(select("quantum", 2, &[1, 0, 4], 10, Prefer::Smallest, cost), Err(TuneError::InvalidValue(0)));
        assert_eq!(select("quantum", 0, &[1, 2], 10, Prefer::Smallest, cost), Err(TuneError::InvalidValue(0)));
        assert_eq!(timer_overhead(1, &cal, 0), None);
    }
}
