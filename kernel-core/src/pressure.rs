//! 内存压力分级与按 QoS 的准入（`system.memory` 领域）：内存紧张时**拒绝**低档请求，而不是换页风暴。
//! Memory-pressure levels and QoS-based admission: refuse low-class requests instead of thrashing.
//!
//! # 职责边界
//! 纯判定：给定「空闲帧数、可分配帧总数、请求帧数、请求者的档位」，回答准不准、处在哪一级。
//! 帧从哪里来、谁持有多少（每进程帧配额）由内存管理与进程模块负责；本模块不碰页帧，可在宿主上测试。
//!
//! # 规则（按分配**之后**的空闲量判定）
//! 按分配后的空闲量判级，一次大请求不能越级跨过阈值：
//!
//! | 分配后的级别 | 准入的档位 |
//! |---|---|
//! | 正常 [`PressureLevel::Normal`] | 全部 |
//! | 紧张 [`PressureLevel::Low`] | 交互、用户发起（工具、后台被拒） |
//! | 危急 [`PressureLevel::Critical`] | 只有交互 |
//!
//! 另有一份**保留帧**：任何任务的请求都不得让空闲帧低于它（留给内核自身的页表与堆，保证拒绝路径
//! 本身还能走通）。不属于任何任务的内核内部请求（`requester = None`）只受「不能超过空闲量」约束。
//! 被拒的请求必须不留任何改动——调用者在分配任何帧之前做准入判定。

use crate::sched::Qos;

/// 内存压力级别（越往后越紧张）。
/// Memory-pressure level.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum PressureLevel {
    /// 正常。
    Normal,
    /// 紧张：低档请求被拒。
    Low,
    /// 危急：只有交互档请求可准入。
    Critical,
}

impl PressureLevel {
    /// 规范名（诊断与结构化事件用）。
    pub const fn name(self) -> &'static str {
        match self {
            PressureLevel::Normal => "normal",
            PressureLevel::Low => "low",
            PressureLevel::Critical => "critical",
        }
    }

    /// 该级别下 `q` 档的请求是否可准入。
    /// Whether class `q` is admitted at this level.
    pub const fn admits(self, q: Qos) -> bool {
        match self {
            PressureLevel::Normal => true,
            PressureLevel::Low => matches!(q, Qos::Interactive | Qos::UserInitiated),
            PressureLevel::Critical => matches!(q, Qos::Interactive),
        }
    }
}

/// 拒绝的原因。
/// Why a request was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
    /// 请求的帧数超过当前空闲帧数。
    Exhausted,
    /// 会动用内核保留帧。
    Reserve,
    /// 分配后的压力级别不准入请求者的档位。
    Class {
        /// 分配后的级别。
        level: PressureLevel,
        /// 请求者档位。
        qos: Qos,
    },
}

/// 压力参数（千分比相对于可分配帧总数）。
/// Pressure thresholds, as permille of usable frames.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PressureParams {
    /// 空闲帧低于此比例 ⇒ 紧张。
    pub low_permille: u32,
    /// 空闲帧低于此比例 ⇒ 危急（应小于 `low_permille`）。
    pub critical_permille: u32,
    /// 任务请求不得动用的保留帧数。
    pub reserve_frames: usize,
}

/// 参数不合法（阈值次序错误或超出 1000）。
/// Invalid pressure parameters.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InvalidParams;

impl PressureParams {
    /// 默认参数：空闲 < 12.5% 紧张、< 5% 危急；保留 256 帧（1 MiB）。
    pub const DEFAULT: PressureParams = PressureParams { low_permille: 125, critical_permille: 50, reserve_frames: 256 };

    /// 校验后构造：`0 < critical < low ≤ 1000`。
    pub const fn new(low_permille: u32, critical_permille: u32, reserve_frames: usize) -> Result<Self, InvalidParams> {
        if critical_permille == 0 || critical_permille >= low_permille || low_permille > 1000 {
            return Err(InvalidParams);
        }
        Ok(PressureParams { low_permille, critical_permille, reserve_frames })
    }

    /// 按指定内存策略计算压力级别。
    ///
    /// 两种策略的差别是可观测的：`PressureAware` 用低/危急两条水位线分级，
    /// `FixedThreshold` 只看一条水位线（低于 `low_permille` 一律危急），
    /// 因此同样空闲帧数下两者可能给出不同结论——这正是"策略可替换"的验收点。
    /// English: compute the level under the given memory policy.
    pub const fn level_with(&self, policy: crate::config::MemoryPolicy, free: usize, total: usize) -> PressureLevel {
        use crate::config::MemoryPolicy;
        if total == 0 {
            return PressureLevel::Critical;
        }
        let f = free as u128 * 1000;
        match policy {
            MemoryPolicy::PressureAware => {
                if f < self.critical_permille as u128 * total as u128 {
                    PressureLevel::Critical
                } else if f < self.low_permille as u128 * total as u128 {
                    PressureLevel::Low
                } else {
                    PressureLevel::Normal
                }
            }
            MemoryPolicy::FixedThreshold => {
                if f < self.low_permille as u128 * total as u128 {
                    PressureLevel::Critical
                } else {
                    PressureLevel::Normal
                }
            }
        }
    }

    /// 空闲 `free` 帧（共 `total` 帧可分配）时的压力级别（压力感知策略）。`total = 0` 视为危急。
    /// Pressure level for `free` of `total` usable frames (pressure-aware).
    pub const fn level(&self, free: usize, total: usize) -> PressureLevel {
        if total == 0 {
            return PressureLevel::Critical;
        }
        // 比较 free/total < p/1000 ⇔ free × 1000 < p × total（u128 防溢出）
        let f = free as u128 * 1000;
        if f < self.critical_permille as u128 * total as u128 {
            PressureLevel::Critical
        } else if f < self.low_permille as u128 * total as u128 {
            PressureLevel::Low
        } else {
            PressureLevel::Normal
        }
    }

    /// 准入判定（压力感知策略）。
    /// Admission under the pressure-aware policy.
    pub const fn admit(&self, requester: Option<Qos>, frames: usize, free: usize, total: usize) -> Result<PressureLevel, Refusal> {
        self.admit_with(crate::config::MemoryPolicy::PressureAware, requester, frames, free, total)
    }

    /// 准入判定：`requester` 为请求者的有效档位（`None` = 不属于任何任务的内核内部请求）。
    /// 成功返回分配后的级别。
    /// Admission decision; returns the level after the allocation on success.
    pub const fn admit_with(&self, policy: crate::config::MemoryPolicy, requester: Option<Qos>, frames: usize, free: usize, total: usize) -> Result<PressureLevel, Refusal> {
        if frames > free {
            return Err(Refusal::Exhausted);
        }
        let after = free - frames;
        let level = self.level_with(policy, after, total);
        match requester {
            None => Ok(level),
            Some(q) => {
                if after < self.reserve_frames {
                    Err(Refusal::Reserve)
                } else if level.admits(q) {
                    Ok(level)
                } else {
                    Err(Refusal::Class { level, qos: q })
                }
            }
        }
    }
}

/// 每级拒绝次数的统计（诊断与验收）。
/// Refusal counters per requester class.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct PressureStats {
    /// 准入次数。
    pub admitted: u64,
    /// 各档被拒次数（下标 = 档位序号）。
    pub refused: [u64; crate::sched::QOS_CLASSES],
    /// 内核内部请求被拒次数。
    pub refused_kernel: u64,
    /// 见过的最紧张级别（自上次清零以来）。
    pub worst: Option<PressureLevel>,
}

impl PressureStats {
    /// 全零统计（`const`，可放进 `static`）。
    pub const fn new() -> Self {
        PressureStats { admitted: 0, refused: [0; crate::sched::QOS_CLASSES], refused_kernel: 0, worst: None }
    }

    /// 记录一次判定结果。
    pub fn record(&mut self, requester: Option<Qos>, r: Result<PressureLevel, Refusal>) {
        let level = match r {
            Ok(l) => {
                self.admitted += 1;
                Some(l)
            }
            Err(e) => {
                match requester {
                    Some(q) => self.refused[q.index()] += 1,
                    None => self.refused_kernel += 1,
                }
                match e {
                    Refusal::Class { level, .. } => Some(level),
                    Refusal::Reserve | Refusal::Exhausted => Some(PressureLevel::Critical),
                }
            }
        };
        self.worst = match (self.worst, level) {
            (Some(a), Some(b)) => Some(if b > a { b } else { a }),
            (a, b) => b.or(a),
        };
    }

    /// 被拒总次数。
    pub fn refused_total(&self) -> u64 {
        self.refused.iter().sum::<u64>() + self.refused_kernel
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const P: PressureParams = PressureParams::DEFAULT;

    #[test]
    fn levels_follow_thresholds() {
        assert_eq!(P.level(1000, 1000), PressureLevel::Normal);
        assert_eq!(P.level(125, 1000), PressureLevel::Normal);
        assert_eq!(P.level(124, 1000), PressureLevel::Low);
        assert_eq!(P.level(50, 1000), PressureLevel::Low);
        assert_eq!(P.level(49, 1000), PressureLevel::Critical);
        assert_eq!(P.level(0, 0), PressureLevel::Critical);
        assert_eq!(P.level(usize::MAX, usize::MAX), PressureLevel::Normal, "大数不溢出");
    }

    #[test]
    fn invalid_params_refused() {
        assert_eq!(PressureParams::new(100, 100, 0), Err(InvalidParams));
        assert_eq!(PressureParams::new(100, 0, 0), Err(InvalidParams));
        assert_eq!(PressureParams::new(1001, 10, 0), Err(InvalidParams));
        assert!(PressureParams::new(200, 100, 8).is_ok());
    }

    #[test]
    fn admission_by_class_uses_level_after_allocation() {
        let total = 10_000;
        // 正常 → 全部准入
        for q in Qos::ALL {
            assert_eq!(P.admit(Some(q), 10, 5000, total), Ok(PressureLevel::Normal));
        }
        // 一次大请求从「正常」跨入「紧张」：按分配后判级，后台被拒
        assert_eq!(P.admit(Some(Qos::Background), 4000, 5000, total), Err(Refusal::Class { level: PressureLevel::Low, qos: Qos::Background }));
        assert_eq!(P.admit(Some(Qos::Utility), 10, 1000, total), Err(Refusal::Class { level: PressureLevel::Low, qos: Qos::Utility }));
        assert_eq!(P.admit(Some(Qos::UserInitiated), 10, 1000, total), Ok(PressureLevel::Low));
        // 危急 → 只有交互
        assert_eq!(P.admit(Some(Qos::UserInitiated), 10, 400, total), Err(Refusal::Class { level: PressureLevel::Critical, qos: Qos::UserInitiated }));
        assert_eq!(P.admit(Some(Qos::Interactive), 10, 400, total), Ok(PressureLevel::Critical));
        // 保留帧：交互也不得动用
        assert_eq!(P.admit(Some(Qos::Interactive), 10, 260, total), Err(Refusal::Reserve));
        // 内核内部请求只受空闲量约束
        assert_eq!(P.admit(None, 10, 260, total), Ok(PressureLevel::Critical));
        assert_eq!(P.admit(None, 11, 10, total), Err(Refusal::Exhausted));
        assert_eq!(P.admit(Some(Qos::Interactive), 11, 10, total), Err(Refusal::Exhausted));
    }

    #[test]
    fn policies_differ_at_the_low_watermark() {
        use crate::config::MemoryPolicy;
        let p = PressureParams::DEFAULT;
        // 空闲 100‰：压力感知给出 Low，固定阈值直接判危急。
        let aware = p.level_with(MemoryPolicy::PressureAware, 100, 1000);
        let fixed = p.level_with(MemoryPolicy::FixedThreshold, 100, 1000);
        assert_eq!(aware, PressureLevel::Low);
        assert_eq!(fixed, PressureLevel::Critical);
        assert_ne!(aware, fixed, "两种策略必须在同一水位下给出不同结论");
        // 充足与耗尽时两者一致，避免策略差异扩散到不该变的地方。
        assert_eq!(
            p.level_with(MemoryPolicy::PressureAware, 900, 1000),
            p.level_with(MemoryPolicy::FixedThreshold, 900, 1000)
        );
        assert_eq!(
            p.level_with(MemoryPolicy::PressureAware, 0, 1000),
            p.level_with(MemoryPolicy::FixedThreshold, 0, 1000)
        );
    }

    #[test]
    fn stats_count_refusals_and_worst_level() {
        let mut s = PressureStats::default();
        let total = 10_000;
        for (q, free) in [(Qos::Background, 5000), (Qos::Background, 1000), (Qos::UserInitiated, 400), (Qos::Interactive, 400)] {
            s.record(Some(q), P.admit(Some(q), 1, free, total));
        }
        assert_eq!(s.admitted, 2);
        assert_eq!(s.refused, [0, 1, 0, 1]);
        assert_eq!(s.refused_total(), 2);
        assert_eq!(s.worst, Some(PressureLevel::Critical));
    }
}
