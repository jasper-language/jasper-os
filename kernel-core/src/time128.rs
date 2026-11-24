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
        assert_eq!(core::mem::size_of::<Time128>(), 16);
    }
}
