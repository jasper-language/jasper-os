//! Coherent clock identity, quality and dual-width snapshot contract.
//! 一致的时钟身份、质量与双位宽快照契约。
//!
//! This module is one publication mechanism for time facts. It is not a time
//! service, a second clock authority, or evidence of physical accuracy.
//! 本模块是时间事实的单一发布机制；它不是时间服务、第二时钟权威或物理精度证据。

use crate::sync::SpinLock;
use crate::time128::{AbsoluteTime64, Time128, TimeConversionError};

/// Semantic time scale. Values with different scales are not interchangeable.
/// 语义时间尺度；不同尺度的时间值不可互换。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TimeScale {
    /// Raw monotonic hardware count converted only for display.
    /// 仅用于展示换算的原始单调硬件计数。
    RawMonotonic,
    /// Monotonic elapsed time that may exclude suspend.
    /// 可能不包含休眠时长的单调流逝时间。
    Monotonic,
    /// Monotonic elapsed time that includes suspend.
    /// 包含休眠时长的单调流逝时间。
    Boottime,
    /// Continuous atomic time without leap-second steps.
    /// 不带闰秒跳变的连续原子时间。
    Tai,
    /// Civil UTC with an explicit leap-second state.
    /// 带显式闰秒状态的民用 UTC。
    Utc,
}

/// Epoch paired with a time scale.
/// 与时间尺度成对出现的纪元。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Epoch {
    /// Unknown epoch. Such a value cannot be treated as trusted civil time.
    /// 未知纪元；此类值不能作为可信民用时间。
    Unknown,
    /// A boot-local epoch identified by a non-zero boot generation.
    /// 由非零启动世代标识的本机启动纪元。
    Boot(u64),
    /// Signed Unix seconds.
    /// 有符号 Unix 秒。
    Unix,
}

/// Evidence state for an absolute clock.
/// 绝对时钟的证据状态。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TrustState {
    Unknown,
    Untrusted,
    Authenticated,
    Verified,
}

/// Source category used for diagnostics and selection, never as authority.
/// 用于诊断和选择的来源类别，本身不构成权限。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SourceClass {
    None,
    Rtc,
    ArchitectureTimer,
    Ntp,
    Nts,
    Ptp,
    Gnss,
    Cellular,
    Virtual,
}

/// A quantity that is either measured or explicitly unknown.
/// 已测量或显式未知的数值。
///
/// `Unknown` never aliases zero: zero is a real uncertainty claim.
/// `Unknown` 从不等于零；零本身是一个真实的误差声明。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Measurement {
    Unknown,
    Nanoseconds(u64),
}

impl Measurement {
    pub const fn known_nanoseconds(self) -> Option<u64> {
        match self {
            Self::Unknown => None,
            Self::Nanoseconds(value) => Some(value),
        }
    }
}

/// Clock quality and provenance carried with one snapshot.
/// 随单个快照携带的时钟质量与来源信息。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ClockQuality {
    pub source: SourceClass,
    pub source_id: u64,
    pub trust: TrustState,
    pub synchronized: bool,
    pub resolution: Measurement,
    pub uncertainty: Measurement,
    pub sample_age: Measurement,
    pub drift_ppb: Option<i32>,
}

impl ClockQuality {
    /// Unknown quality is explicit rather than a fabricated zero.
    /// 未知质量显式表示，不伪造为零。
    pub const fn unknown() -> Self {
        Self {
            source: SourceClass::None,
            source_id: 0,
            trust: TrustState::Unknown,
            synchronized: false,
            resolution: Measurement::Unknown,
            uncertainty: Measurement::Unknown,
            sample_age: Measurement::Unknown,
            drift_ppb: None,
        }
    }
}

/// Identity shared by every width view of one clock fact.
/// 同一时钟事实的所有位宽视图共享的身份。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ClockIdentity {
    pub scale: TimeScale,
    pub epoch: Epoch,
    pub boot_generation: u64,
    pub domain_id: u64,
    pub publication_sequence: u64,
    pub quality: ClockQuality,
}

impl ClockIdentity {
    /// Reject identities that cannot describe one meaningful clock fact.
    /// 拒绝无法描述一个有意义时钟事实的身份。
    pub fn validate(self) -> Result<(), SnapshotError> {
        if self.boot_generation == 0 || self.domain_id == 0 {
            return Err(SnapshotError::InvalidIdentity);
        }
        match (self.scale, self.epoch) {
            (
                TimeScale::RawMonotonic | TimeScale::Monotonic | TimeScale::Boottime,
                Epoch::Boot(boot),
            ) if boot == self.boot_generation => {}
            (TimeScale::Tai | TimeScale::Utc, Epoch::Unix) => {}
            _ => return Err(SnapshotError::InvalidIdentity),
        }
        if matches!(self.scale, TimeScale::Tai | TimeScale::Utc)
            && !matches!(
                self.quality.trust,
                TrustState::Authenticated | TrustState::Verified
            )
        {
            return Err(SnapshotError::UntrustedAbsoluteTime);
        }
        Ok(())
    }
}

/// One coherent monotonic fact available as unsigned Time64 and Time128.
/// 同一单调事实的无符号 Time64 与 Time128 视图。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MonotonicSnapshot {
    pub time64_ns: u64,
    pub time128: Time128,
    pub identity: ClockIdentity,
}

impl MonotonicSnapshot {
    /// Construct both widths from one nanosecond source value.
    /// 从同一个纳秒源值构造两个位宽。
    pub fn from_nanos(nanos: u64, identity: ClockIdentity) -> Result<Self, SnapshotError> {
        identity.validate()?;
        if !matches!(
            identity.scale,
            TimeScale::RawMonotonic | TimeScale::Monotonic | TimeScale::Boottime
        ) {
            return Err(SnapshotError::InvalidScale);
        }
        let time128 = Time128::from_nanos(i128::from(nanos)).map_err(SnapshotError::Conversion)?;
        if time128.to_nanos() != i128::from(nanos) {
            return Err(SnapshotError::InconsistentWidths);
        }
        Ok(Self {
            time64_ns: nanos,
            time128,
            identity,
        })
    }
}

/// One coherent absolute fact available as signed Time64 nanoseconds and Time128.
/// 同一绝对事实的有符号 Time64 纳秒与 Time128 视图。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AbsoluteSnapshot {
    pub time64_ns: AbsoluteTime64,
    pub time128: Time128,
    pub identity: ClockIdentity,
}

impl AbsoluteSnapshot {
    /// Construct both widths from one signed Unix nanosecond source value.
    /// 从同一个有符号 Unix 纳秒源值构造两个位宽。
    pub fn from_unix_nanos(nanos: i64, identity: ClockIdentity) -> Result<Self, SnapshotError> {
        identity.validate()?;
        if !matches!(identity.scale, TimeScale::Tai | TimeScale::Utc)
            || identity.epoch != Epoch::Unix
        {
            return Err(SnapshotError::InvalidScale);
        }
        let time128 = Time128::from_nanos(i128::from(nanos)).map_err(SnapshotError::Conversion)?;
        if time128.to_nanos() != i128::from(nanos) {
            return Err(SnapshotError::InconsistentWidths);
        }
        Ok(Self {
            time64_ns: AbsoluteTime64::from_nanos(nanos),
            time128,
            identity,
        })
    }
}

/// Raw hardware sample that is not yet a civil or trusted time.
/// 尚未成为民用或可信时间的原始硬件采样。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RawCounterSample {
    pub value: u64,
    pub frequency_hz: u64,
    pub domain_id: u64,
    pub boot_generation: u64,
}

impl RawCounterSample {
    pub fn validate(self) -> Result<(), SnapshotError> {
        if self.frequency_hz == 0 || self.domain_id == 0 || self.boot_generation == 0 {
            return Err(SnapshotError::InvalidIdentity);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SnapshotError {
    Unavailable,
    InvalidIdentity,
    InvalidScale,
    UntrustedAbsoluteTime,
    InconsistentWidths,
    StaleBootGeneration,
    NonMonotonic(u64),
    SequenceExhausted,
    Conversion(TimeConversionError),
}

enum PublishedSnapshot {
    Monotonic(MonotonicSnapshot),
    Absolute(AbsoluteSnapshot),
}

impl PublishedSnapshot {
    fn identity(&self) -> ClockIdentity {
        match self {
            Self::Monotonic(snapshot) => snapshot.identity,
            Self::Absolute(snapshot) => snapshot.identity,
        }
    }

    fn monotonic_nanos(&self) -> Option<u64> {
        match self {
            Self::Monotonic(snapshot) => Some(snapshot.time64_ns),
            Self::Absolute(_) => None,
        }
    }
}

/// Single-writer coherent snapshot cell.
/// 单写入者的相干快照单元。
///
/// Multiword values are published under one lock, so readers cannot observe a
/// mixed 64/128 pair even on processors without a 128-bit atomic instruction.
/// 多字值在同一把锁下发布，即使处理器没有 128 位原子指令，读者也不会看到混合的 64/128 对。
pub struct ClockSnapshotCell {
    published: SpinLock<Option<PublishedSnapshot>>,
}

impl ClockSnapshotCell {
    pub const fn new() -> Self {
        Self {
            published: SpinLock::new(None),
        }
    }

    /// Publish a monotonic snapshot, advancing sequence and boot generation.
    /// 发布单调快照，并推进序号与启动世代。
    pub fn publish_monotonic(
        &self,
        mut snapshot: MonotonicSnapshot,
    ) -> Result<ClockIdentity, SnapshotError> {
        snapshot.identity.validate()?;
        let mut published = self.published.lock();
        let sequence = match published.as_ref() {
            None => 1,
            Some(previous) => {
                let previous_identity = previous.identity();
                if snapshot.identity.boot_generation < previous_identity.boot_generation {
                    return Err(SnapshotError::StaleBootGeneration);
                }
                if snapshot.identity.boot_generation == previous_identity.boot_generation {
                    if let Some(previous_nanos) = previous.monotonic_nanos() {
                        if snapshot.time64_ns < previous_nanos {
                            return Err(SnapshotError::NonMonotonic(previous_nanos));
                        }
                    }
                    previous_identity
                        .publication_sequence
                        .checked_add(1)
                        .ok_or(SnapshotError::SequenceExhausted)?
                } else {
                    1
                }
            }
        };
        snapshot.identity.publication_sequence = sequence;
        *published = Some(PublishedSnapshot::Monotonic(snapshot));
        Ok(snapshot.identity)
    }

    /// Publish an absolute snapshot, advancing sequence and boot generation.
    /// 发布绝对快照，并推进序号与启动世代。
    pub fn publish_absolute(
        &self,
        mut snapshot: AbsoluteSnapshot,
    ) -> Result<ClockIdentity, SnapshotError> {
        snapshot.identity.validate()?;
        let mut published = self.published.lock();
        let sequence = match published.as_ref() {
            None => 1,
            Some(previous) => {
                let previous_identity = previous.identity();
                if snapshot.identity.boot_generation < previous_identity.boot_generation {
                    return Err(SnapshotError::StaleBootGeneration);
                }
                if snapshot.identity.boot_generation == previous_identity.boot_generation {
                    previous_identity
                        .publication_sequence
                        .checked_add(1)
                        .ok_or(SnapshotError::SequenceExhausted)?
                } else {
                    1
                }
            }
        };
        snapshot.identity.publication_sequence = sequence;
        *published = Some(PublishedSnapshot::Absolute(snapshot));
        Ok(snapshot.identity)
    }

    /// Read one complete monotonic pair and identity under the same lock.
    /// 在同一把锁下读取完整单调对与身份。
    pub fn read_monotonic(&self) -> Result<MonotonicSnapshot, SnapshotError> {
        match *self.published.lock() {
            Some(PublishedSnapshot::Monotonic(snapshot)) => Ok(snapshot),
            Some(PublishedSnapshot::Absolute(_)) | None => Err(SnapshotError::Unavailable),
        }
    }

    /// Read one complete absolute pair and identity under the same lock.
    /// 在同一把锁下读取完整绝对对与身份。
    pub fn read_absolute(&self) -> Result<AbsoluteSnapshot, SnapshotError> {
        match *self.published.lock() {
            Some(PublishedSnapshot::Absolute(snapshot)) => Ok(snapshot),
            Some(PublishedSnapshot::Monotonic(_)) | None => Err(SnapshotError::Unavailable),
        }
    }
}

impl Default for ClockSnapshotCell {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::time128::Time128;

    fn monotonic_identity(value: u64) -> ClockIdentity {
        ClockIdentity {
            scale: TimeScale::Monotonic,
            epoch: Epoch::Boot(7),
            boot_generation: 7,
            domain_id: 1,
            publication_sequence: value,
            quality: ClockQuality::unknown(),
        }
    }

    #[test]
    fn unknown_and_zero_measurements_remain_distinct() {
        assert_eq!(Measurement::Unknown.known_nanoseconds(), None);
        assert_eq!(Measurement::Nanoseconds(0).known_nanoseconds(), Some(0));
    }

    #[test]
    fn one_source_produces_one_coherent_width_pair() {
        let snapshot = MonotonicSnapshot::from_nanos(1_000_000_001, monotonic_identity(0)).unwrap();
        assert_eq!(snapshot.time64_ns, 1_000_000_001);
        assert_eq!(snapshot.time128.to_nanos(), 1_000_000_001);
    }

    #[test]
    fn publication_rejects_non_monotonic_time_and_stale_boot_generation() {
        let cell = ClockSnapshotCell::new();
        let first = MonotonicSnapshot::from_nanos(10, monotonic_identity(0)).unwrap();
        let identity = cell.publish_monotonic(first).unwrap();
        assert_eq!(identity.publication_sequence, 1);

        let reversed = MonotonicSnapshot::from_nanos(9, monotonic_identity(0)).unwrap();
        assert_eq!(
            cell.publish_monotonic(reversed),
            Err(SnapshotError::NonMonotonic(10))
        );
        assert_eq!(cell.read_monotonic().unwrap().time64_ns, 10);

        let mut stale_identity = monotonic_identity(0);
        stale_identity.epoch = Epoch::Boot(6);
        stale_identity.boot_generation = 6;
        let stale = MonotonicSnapshot::from_nanos(1, stale_identity).unwrap();
        assert_eq!(
            cell.publish_monotonic(stale),
            Err(SnapshotError::StaleBootGeneration)
        );
    }

    #[test]
    fn untrusted_tai_and_utc_fail_closed() {
        let identity = ClockIdentity {
            scale: TimeScale::Utc,
            epoch: Epoch::Unix,
            boot_generation: 1,
            domain_id: 1,
            publication_sequence: 0,
            quality: ClockQuality::unknown(),
        };
        assert_eq!(
            AbsoluteSnapshot::from_unix_nanos(0, identity),
            Err(SnapshotError::UntrustedAbsoluteTime)
        );
    }

    #[test]
    fn absolute_negative_epoch_round_trips() {
        let mut quality = ClockQuality::unknown();
        quality.trust = TrustState::Verified;
        let identity = ClockIdentity {
            scale: TimeScale::Tai,
            epoch: Epoch::Unix,
            boot_generation: 1,
            domain_id: 2,
            publication_sequence: 0,
            quality,
        };
        let snapshot = AbsoluteSnapshot::from_unix_nanos(-1, identity).unwrap();
        assert_eq!(snapshot.time64_ns.as_nanos(), -1);
        assert_eq!(snapshot.time128, Time128::from_nanos(-1).unwrap());
        assert_eq!(snapshot.time128.to_nanos(), -1);
    }
}
