//! Width-explicit time values shared by native time providers.
//!
//! These are representation primitives, not a trusted-clock service. A
//! `Time128` can represent an arbitrary fraction; that says nothing about the
//! accuracy or uncertainty of the source clock.

/// Nanoseconds in one SI second.
pub const NANOS_PER_SECOND: i128 = 1_000_000_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TimeConversionError {
    SecondsOverflow,
}

/// Compact monotonic or duration value in integer nanoseconds.
#[repr(transparent)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Time64(u64);

impl Time64 {
    pub const ZERO: Self = Self(0);

    pub const fn from_nanos(nanos: u64) -> Self {
        Self(nanos)
    }

    pub const fn as_nanos(self) -> u64 {
        self.0
    }

    pub const fn checked_add(self, rhs: Self) -> Option<Self> {
        match self.0.checked_add(rhs.0) {
            Some(value) => Some(Self(value)),
            None => None,
        }
    }

    pub const fn checked_sub(self, rhs: Self) -> Option<Self> {
        match self.0.checked_sub(rhs.0) {
            Some(value) => Some(Self(value)),
            None => None,
        }
    }
}

/// Absolute Time64 value in signed integer nanoseconds.
/// 有符号整数纳秒的绝对 Time64 值。
///
/// The epoch and scale remain separate metadata; this type prevents accidental
/// comparison with unsigned monotonic `Time64`.
/// 纪元与尺度仍由独立元数据表达；该类型防止与无符号单调 `Time64` 误比较。
#[repr(transparent)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct AbsoluteTime64(i64);

impl AbsoluteTime64 {
    pub const fn from_nanos(nanos: i64) -> Self {
        Self(nanos)
    }

    pub const fn as_nanos(self) -> i64 {
        self.0
    }

    pub fn to_time128(self) -> Result<Time128, TimeConversionError> {
        Time128::from_nanos(i128::from(self.0))
    }
}

/// A time value with signed whole seconds and an unsigned binary fraction.
///
/// This follows the NTP Date layout: `seconds + fraction / 2^64`. The epoch
/// and scale are deliberately not encoded here; callers must carry those as
/// separate typed metadata.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct Time128 {
    pub seconds: i64,
    pub fraction: u64,
}

impl Time128 {
    pub const ZERO: Self = Self {
        seconds: 0,
        fraction: 0,
    };

    pub const fn new(seconds: i64, fraction: u64) -> Self {
        Self { seconds, fraction }
    }

    /// Converts signed integer nanoseconds using round-to-nearest, ties-to-even.
    ///
    /// Negative values use floor seconds and a non-negative fraction, so
    /// `-1 ns` becomes `(-1 s, 0.999999999 s)`.
    pub fn from_nanos(nanos: i128) -> Result<Self, TimeConversionError> {
        let seconds = nanos.div_euclid(NANOS_PER_SECOND);
        let seconds = i64::try_from(seconds).map_err(|_| TimeConversionError::SecondsOverflow)?;
        let subsecond = nanos.rem_euclid(NANOS_PER_SECOND) as u128;
        let fraction = round_div_even(subsecond << 64, NANOS_PER_SECOND as u128);
        Ok(Self {
            seconds,
            fraction: fraction as u64,
        })
    }

    /// Converts to integer nanoseconds using round-to-nearest, ties-to-even.
    ///
    /// The i128 range is sufficient for every `i64` whole-second Time128.
    pub fn to_nanos(self) -> i128 {
        let whole = i128::from(self.seconds) * NANOS_PER_SECOND;
        let fraction = i128::from(self.fraction);
        whole + round_div_even(fraction as u128 * NANOS_PER_SECOND as u128, 1u128 << 64) as i128
    }

    /// Canonical little-endian wire form: signed seconds then binary fraction.
    /// 规范小端线格式：有符号秒后接二进制小数。
    pub fn to_le_bytes(self) -> [u8; 16] {
        let mut out = [0u8; 16];
        out[..8].copy_from_slice(&self.seconds.to_le_bytes());
        out[8..].copy_from_slice(&self.fraction.to_le_bytes());
        out
    }

    /// Decode the canonical wire form without changing the epoch or scale.
    /// 解码规范线格式，不改变纪元或尺度。
    pub const fn from_le_bytes(bytes: [u8; 16]) -> Self {
        let seconds = i64::from_le_bytes([
            bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
        ]);
        let fraction = u64::from_le_bytes([
            bytes[8], bytes[9], bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15],
        ]);
        Self { seconds, fraction }
    }

    /// Checked addition preserving normalized signed seconds and unsigned fraction.
    /// 保持规范化“有符号秒 + 无符号小数”的可检查加法。
    pub fn checked_add(self, rhs: Self) -> Option<Self> {
        let fraction = u128::from(self.fraction) + u128::from(rhs.fraction);
        let carry = i64::from(fraction > u64::MAX as u128);
        let seconds = self.seconds.checked_add(rhs.seconds)?.checked_add(carry)?;
        Some(Self {
            seconds,
            fraction: (fraction & u128::from(u64::MAX)) as u64,
        })
    }

    /// Checked subtraction with borrow represented by signed floor seconds.
    /// 通过“有符号秒取 floor”表示借位的可检查减法。
    pub fn checked_sub(self, rhs: Self) -> Option<Self> {
        let (seconds, fraction) = if self.fraction >= rhs.fraction {
            (
                self.seconds.checked_sub(rhs.seconds)?,
                self.fraction - rhs.fraction,
            )
        } else {
            (
                self.seconds.checked_sub(rhs.seconds)?.checked_sub(1)?,
                u64::try_from((1u128 << 64) + u128::from(self.fraction) - u128::from(rhs.fraction))
                    .ok()?,
            )
        };
        Some(Self { seconds, fraction })
    }
}

fn round_div_even(numerator: u128, denominator: u128) -> u128 {
    let quotient = numerator / denominator;
    let remainder = numerator % denominator;
    if remainder * 2 > denominator || remainder * 2 == denominator && quotient & 1 == 1 {
        quotient + 1
    } else {
        quotient
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn time64_arithmetic_is_checked() {
        let one = Time64::from_nanos(1);
        assert_eq!(
            one.checked_add(Time64::from_nanos(2)),
            Some(Time64::from_nanos(3))
        );
        assert_eq!(one.checked_sub(Time64::from_nanos(2)), None);
        assert_eq!(Time64::from_nanos(u64::MAX).checked_add(one), None);
    }

    #[test]
    fn time128_negative_values_are_normalized() {
        assert_eq!(
            Time128::from_nanos(-1),
            Ok(Time128::new(-1, 18_446_744_055_262_807_542))
        );
        assert_eq!(Time128::from_nanos(-1).unwrap().to_nanos(), -1);
        assert_eq!(Time128::from_nanos(-1_000_000_000), Ok(Time128::new(-1, 0)));
    }

    #[test]
    fn nanosecond_roundtrip_is_exact_for_representative_values() {
        for nanos in [
            i128::from(i64::MIN) + 1,
            -NANOS_PER_SECOND,
            -1,
            0,
            1,
            NANOS_PER_SECOND - 1,
            i128::from(i64::MAX),
        ] {
            assert_eq!(Time128::from_nanos(nanos).unwrap().to_nanos(), nanos);
        }
    }

    #[test]
    fn out_of_range_seconds_fail_closed() {
        assert_eq!(
            Time128::from_nanos(i128::MAX),
            Err(TimeConversionError::SecondsOverflow)
        );
    }

    #[test]
    fn layout_is_stable_and_packed() {
        assert_eq!(core::mem::size_of::<Time64>(), 8);
        assert_eq!(core::mem::size_of::<AbsoluteTime64>(), 8);
        assert_eq!(core::mem::size_of::<Time128>(), 16);
    }

    #[test]
    fn canonical_wire_form_round_trips_negative_values() {
        let value = Time128::from_nanos(-1).unwrap();
        assert_eq!(Time128::from_le_bytes(value.to_le_bytes()), value);
        assert_eq!(AbsoluteTime64::from_nanos(-1).to_time128(), Ok(value));
    }

    #[test]
    fn checked_arithmetic_normalizes_carry_and_borrow() {
        let half = Time128::new(0, 1u64 << 63);
        assert_eq!(half.checked_add(half), Some(Time128::new(1, 0)));
        assert_eq!(
            Time128::ZERO.checked_sub(half),
            Some(Time128::new(-1, 1u64 << 63))
        );
        assert_eq!(
            Time128::new(i64::MAX, u64::MAX).checked_add(Time128::new(0, 1)),
            None
        );
        assert_eq!(
            Time128::new(i64::MIN, 0).checked_sub(Time128::new(0, 1)),
            None
        );
    }
}
