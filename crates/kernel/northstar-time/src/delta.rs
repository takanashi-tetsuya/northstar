// Ported and adapted from chrono 0.4.45 (MIT OR Apache-2.0).
use core::fmt;
use core::ops::{Add, AddAssign, Div, Mul, Neg, Sub, SubAssign};
use core::time::Duration;
use std::error::Error;

use crate::expect;

const NANOS_PER_MICRO: i32 = 1000;
const NANOS_PER_MILLI: i32 = 1_000_000;
pub(crate) const NANOS_PER_SEC: i32 = 1_000_000_000;
const MICROS_PER_SEC: i64 = 1_000_000;
const MILLIS_PER_SEC: i64 = 1000;
const SECS_PER_MINUTE: i64 = 60;
const SECS_PER_HOUR: i64 = 3600;
const SECS_PER_DAY: i64 = 86_400;
const SECS_PER_WEEK: i64 = 604_800;

#[derive(Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Debug, Hash)]
pub struct TimeDelta {
    secs: i64,
    nanos: i32, // Always 0 <= nanos < NANOS_PER_SEC
}

pub(crate) const MIN: TimeDelta = TimeDelta {
    secs: -i64::MAX / MILLIS_PER_SEC - 1,
    nanos: NANOS_PER_SEC + (-i64::MAX % MILLIS_PER_SEC) as i32 * NANOS_PER_MILLI,
};

pub(crate) const MAX: TimeDelta = TimeDelta {
    secs: i64::MAX / MILLIS_PER_SEC,
    nanos: (i64::MAX % MILLIS_PER_SEC) as i32 * NANOS_PER_MILLI,
};

impl TimeDelta {
    pub const fn new(secs: i64, nanos: u32) -> Option<TimeDelta> {
        if secs < MIN.secs
            || secs > MAX.secs
            || nanos >= 1_000_000_000
            || (secs == MAX.secs && nanos > MAX.nanos as u32)
            || (secs == MIN.secs && nanos < MIN.nanos as u32)
        {
            return None;
        }
        Some(TimeDelta {
            secs,
            nanos: nanos as i32,
        })
    }

    #[inline]
    #[must_use]
    #[track_caller]
    pub const fn weeks(weeks: i64) -> TimeDelta {
        expect(
            TimeDelta::try_weeks(weeks),
            "TimeDelta::weeks out of bounds",
        )
    }

    #[inline]
    pub const fn try_weeks(weeks: i64) -> Option<TimeDelta> {
        TimeDelta::try_seconds(try_opt!(weeks.checked_mul(SECS_PER_WEEK)))
    }

    #[inline]
    #[must_use]
    #[track_caller]
    pub const fn days(days: i64) -> TimeDelta {
        expect(TimeDelta::try_days(days), "TimeDelta::days out of bounds")
    }

    #[inline]
    pub const fn try_days(days: i64) -> Option<TimeDelta> {
        TimeDelta::try_seconds(try_opt!(days.checked_mul(SECS_PER_DAY)))
    }

    #[inline]
    #[must_use]
    #[track_caller]
    pub const fn hours(hours: i64) -> TimeDelta {
        expect(
            TimeDelta::try_hours(hours),
            "TimeDelta::hours out of bounds",
        )
    }

    #[inline]
    pub const fn try_hours(hours: i64) -> Option<TimeDelta> {
        TimeDelta::try_seconds(try_opt!(hours.checked_mul(SECS_PER_HOUR)))
    }

    #[inline]
    #[must_use]
    #[track_caller]
    pub const fn minutes(minutes: i64) -> TimeDelta {
        expect(
            TimeDelta::try_minutes(minutes),
            "TimeDelta::minutes out of bounds",
        )
    }

    #[inline]
    pub const fn try_minutes(minutes: i64) -> Option<TimeDelta> {
        TimeDelta::try_seconds(try_opt!(minutes.checked_mul(SECS_PER_MINUTE)))
    }

    #[inline]
    #[must_use]
    #[track_caller]
    pub const fn seconds(seconds: i64) -> TimeDelta {
        expect(
            TimeDelta::try_seconds(seconds),
            "TimeDelta::seconds out of bounds",
        )
    }

    #[inline]
    pub const fn try_seconds(seconds: i64) -> Option<TimeDelta> {
        TimeDelta::new(seconds, 0)
    }

    #[inline]
    #[track_caller]
    pub const fn milliseconds(milliseconds: i64) -> TimeDelta {
        expect(
            TimeDelta::try_milliseconds(milliseconds),
            "TimeDelta::milliseconds out of bounds",
        )
    }

    #[inline]
    pub const fn try_milliseconds(milliseconds: i64) -> Option<TimeDelta> {
        // We don't need to compare against MAX, as this function accepts an
        // i64, and MAX is aligned to i64::MAX milliseconds.
        if milliseconds < -i64::MAX {
            return None;
        }
        let (secs, millis) = div_mod_floor_64(milliseconds, MILLIS_PER_SEC);
        let d = TimeDelta {
            secs,
            nanos: millis as i32 * NANOS_PER_MILLI,
        };
        Some(d)
    }

    #[inline]
    pub const fn microseconds(microseconds: i64) -> TimeDelta {
        let (secs, micros) = div_mod_floor_64(microseconds, MICROS_PER_SEC);
        let nanos = micros as i32 * NANOS_PER_MICRO;
        TimeDelta { secs, nanos }
    }

    #[inline]
    pub const fn nanoseconds(nanos: i64) -> TimeDelta {
        let (secs, nanos) = div_mod_floor_64(nanos, NANOS_PER_SEC as i64);
        TimeDelta {
            secs,
            nanos: nanos as i32,
        }
    }

    #[inline]
    pub const fn num_weeks(&self) -> i64 {
        self.num_days() / 7
    }

    #[inline]
    pub const fn num_days(&self) -> i64 {
        self.num_seconds() / SECS_PER_DAY
    }

    #[inline]
    pub const fn num_hours(&self) -> i64 {
        self.num_seconds() / SECS_PER_HOUR
    }

    #[inline]
    pub const fn num_minutes(&self) -> i64 {
        self.num_seconds() / SECS_PER_MINUTE
    }

    pub const fn num_seconds(&self) -> i64 {
        // If secs is negative, nanos should be subtracted from the duration.
        if self.secs < 0 && self.nanos > 0 {
            self.secs + 1
        } else {
            self.secs
        }
    }

    pub fn as_seconds_f64(self) -> f64 {
        self.secs as f64 + self.nanos as f64 / NANOS_PER_SEC as f64
    }

    pub fn as_seconds_f32(self) -> f32 {
        self.secs as f32 + self.nanos as f32 / NANOS_PER_SEC as f32
    }

    pub const fn num_milliseconds(&self) -> i64 {
        // A proper TimeDelta will not overflow, because MIN and MAX are defined such
        // that the range is within the bounds of an i64, from -i64::MAX through to
        // +i64::MAX inclusive. Notably, i64::MIN is excluded from this range.
        let secs_part = self.num_seconds() * MILLIS_PER_SEC;
        let nanos_part = self.subsec_nanos() / NANOS_PER_MILLI;
        secs_part + nanos_part as i64
    }

    pub const fn subsec_millis(&self) -> i32 {
        self.subsec_nanos() / NANOS_PER_MILLI
    }

    pub const fn num_microseconds(&self) -> Option<i64> {
        let secs_part = try_opt!(self.num_seconds().checked_mul(MICROS_PER_SEC));
        let nanos_part = self.subsec_nanos() / NANOS_PER_MICRO;
        secs_part.checked_add(nanos_part as i64)
    }

    pub const fn subsec_micros(&self) -> i32 {
        self.subsec_nanos() / NANOS_PER_MICRO
    }

    pub const fn num_nanoseconds(&self) -> Option<i64> {
        let secs_part = try_opt!(self.num_seconds().checked_mul(NANOS_PER_SEC as i64));
        let nanos_part = self.subsec_nanos();
        secs_part.checked_add(nanos_part as i64)
    }

    pub const fn subsec_nanos(&self) -> i32 {
        if self.secs < 0 && self.nanos > 0 {
            self.nanos - NANOS_PER_SEC
        } else {
            self.nanos
        }
    }

    #[must_use]
    pub const fn checked_add(&self, rhs: &TimeDelta) -> Option<TimeDelta> {
        // No overflow checks here because we stay comfortably within the range of an `i64`.
        // Range checks happen in `TimeDelta::new`.
        let mut secs = self.secs + rhs.secs;
        let mut nanos = self.nanos + rhs.nanos;
        if nanos >= NANOS_PER_SEC {
            nanos -= NANOS_PER_SEC;
            secs += 1;
        }
        TimeDelta::new(secs, nanos as u32)
    }

    #[must_use]
    pub const fn checked_sub(&self, rhs: &TimeDelta) -> Option<TimeDelta> {
        // No overflow checks here because we stay comfortably within the range of an `i64`.
        // Range checks happen in `TimeDelta::new`.
        let mut secs = self.secs - rhs.secs;
        let mut nanos = self.nanos - rhs.nanos;
        if nanos < 0 {
            nanos += NANOS_PER_SEC;
            secs -= 1;
        }
        TimeDelta::new(secs, nanos as u32)
    }

    #[must_use]
    pub const fn checked_mul(&self, rhs: i32) -> Option<TimeDelta> {
        // Multiply nanoseconds as i64, because it cannot overflow that way.
        let total_nanos = self.nanos as i64 * rhs as i64;
        let (extra_secs, nanos) = div_mod_floor_64(total_nanos, NANOS_PER_SEC as i64);
        // Multiply seconds as i128 to prevent overflow
        let secs: i128 = self.secs as i128 * rhs as i128 + extra_secs as i128;
        if secs <= i64::MIN as i128 || secs >= i64::MAX as i128 {
            return None;
        };
        Some(TimeDelta {
            secs: secs as i64,
            nanos: nanos as i32,
        })
    }

    #[must_use]
    pub const fn checked_div(&self, rhs: i32) -> Option<TimeDelta> {
        if rhs == 0 {
            return None;
        }
        let secs = self.secs / rhs as i64;
        let carry = self.secs % rhs as i64;
        let extra_nanos = carry * NANOS_PER_SEC as i64 / rhs as i64;
        let nanos = self.nanos / rhs + extra_nanos as i32;

        let (secs, nanos) = match nanos {
            i32::MIN..=-1 => (secs - 1, nanos + NANOS_PER_SEC),
            NANOS_PER_SEC..=i32::MAX => (secs + 1, nanos - NANOS_PER_SEC),
            _ => (secs, nanos),
        };

        Some(TimeDelta { secs, nanos })
    }

    #[inline]
    pub const fn abs(&self) -> TimeDelta {
        if self.secs < 0 && self.nanos != 0 {
            TimeDelta {
                secs: (self.secs + 1).abs(),
                nanos: NANOS_PER_SEC - self.nanos,
            }
        } else {
            TimeDelta {
                secs: self.secs.abs(),
                nanos: self.nanos,
            }
        }
    }

    #[deprecated(since = "0.4.39", note = "Use `TimeDelta::MIN` instead")]
    #[inline]
    pub const fn min_value() -> TimeDelta {
        MIN
    }

    #[deprecated(since = "0.4.39", note = "Use `TimeDelta::MAX` instead")]
    #[inline]
    pub const fn max_value() -> TimeDelta {
        MAX
    }

    #[inline]
    pub const fn zero() -> TimeDelta {
        TimeDelta { secs: 0, nanos: 0 }
    }

    #[inline]
    pub const fn is_zero(&self) -> bool {
        self.secs == 0 && self.nanos == 0
    }

    pub const fn from_std(duration: Duration) -> Result<TimeDelta, OutOfRangeError> {
        // We need to check secs as u64 before coercing to i64
        if duration.as_secs() > MAX.secs as u64 {
            return Err(OutOfRangeError(()));
        }
        match TimeDelta::new(duration.as_secs() as i64, duration.subsec_nanos()) {
            Some(d) => Ok(d),
            None => Err(OutOfRangeError(())),
        }
    }

    pub const fn to_std(&self) -> Result<Duration, OutOfRangeError> {
        if self.secs < 0 {
            return Err(OutOfRangeError(()));
        }
        Ok(Duration::new(self.secs as u64, self.nanos as u32))
    }

    pub(crate) const fn neg(self) -> TimeDelta {
        let (secs_diff, nanos) = match self.nanos {
            0 => (0, 0),
            nanos => (1, NANOS_PER_SEC - nanos),
        };
        TimeDelta {
            secs: -self.secs - secs_diff,
            nanos,
        }
    }

    pub const MIN: Self = MIN;

    pub const MAX: Self = MAX;
}

impl Neg for TimeDelta {
    type Output = TimeDelta;

    #[inline]
    #[track_caller]
    fn neg(self) -> TimeDelta {
        let (secs_diff, nanos) = match self.nanos {
            0 => (0, 0),
            nanos => (1, NANOS_PER_SEC - nanos),
        };
        TimeDelta {
            secs: -self.secs - secs_diff,
            nanos,
        }
    }
}

impl Add for TimeDelta {
    type Output = TimeDelta;

    #[track_caller]
    fn add(self, rhs: TimeDelta) -> TimeDelta {
        self.checked_add(&rhs)
            .expect("`TimeDelta + TimeDelta` overflowed")
    }
}

impl Sub for TimeDelta {
    type Output = TimeDelta;

    #[track_caller]
    fn sub(self, rhs: TimeDelta) -> TimeDelta {
        self.checked_sub(&rhs)
            .expect("`TimeDelta - TimeDelta` overflowed")
    }
}

impl AddAssign for TimeDelta {
    #[track_caller]
    fn add_assign(&mut self, rhs: TimeDelta) {
        let new = self
            .checked_add(&rhs)
            .expect("`TimeDelta + TimeDelta` overflowed");
        *self = new;
    }
}

impl SubAssign for TimeDelta {
    #[track_caller]
    fn sub_assign(&mut self, rhs: TimeDelta) {
        let new = self
            .checked_sub(&rhs)
            .expect("`TimeDelta - TimeDelta` overflowed");
        *self = new;
    }
}

impl Mul<i32> for TimeDelta {
    type Output = TimeDelta;

    #[track_caller]
    fn mul(self, rhs: i32) -> TimeDelta {
        self.checked_mul(rhs).expect("`TimeDelta * i32` overflowed")
    }
}

impl Div<i32> for TimeDelta {
    type Output = TimeDelta;

    #[track_caller]
    fn div(self, rhs: i32) -> TimeDelta {
        self.checked_div(rhs).expect("`i32` is zero")
    }
}

impl<'a> core::iter::Sum<&'a TimeDelta> for TimeDelta {
    fn sum<I: Iterator<Item = &'a TimeDelta>>(iter: I) -> TimeDelta {
        iter.fold(TimeDelta::zero(), |acc, x| acc + *x)
    }
}

impl core::iter::Sum<TimeDelta> for TimeDelta {
    fn sum<I: Iterator<Item = TimeDelta>>(iter: I) -> TimeDelta {
        iter.fold(TimeDelta::zero(), |acc, x| acc + x)
    }
}

impl fmt::Display for TimeDelta {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        // technically speaking, negative duration is not valid ISO 8601,
        // but we need to print it anyway.
        let (abs, sign) = if self.secs < 0 {
            (-*self, "-")
        } else {
            (*self, "")
        };

        write!(f, "{sign}P")?;
        // Plenty of ways to encode an empty string. `P0D` is short and not too strange.
        if abs.secs == 0 && abs.nanos == 0 {
            return f.write_str("0D");
        }

        f.write_fmt(format_args!("T{}", abs.secs))?;

        if abs.nanos > 0 {
            // Count the number of significant digits, while removing all trailing zero's.
            let mut figures = 9usize;
            let mut fraction_digits = abs.nanos;
            loop {
                let div = fraction_digits / 10;
                let last_digit = fraction_digits % 10;
                if last_digit != 0 {
                    break;
                }
                fraction_digits = div;
                figures -= 1;
            }
            f.write_fmt(format_args!(".{fraction_digits:0figures$}"))?;
        }
        f.write_str("S")?;
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OutOfRangeError(());

impl fmt::Display for OutOfRangeError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "Source duration value is out of range for the target type"
        )
    }
}

impl Error for OutOfRangeError {
    #[allow(deprecated)]
    fn description(&self) -> &str {
        "out of range error"
    }
}

#[inline]
const fn div_mod_floor_64(this: i64, other: i64) -> (i64, i64) {
    (this.div_euclid(other), this.rem_euclid(other))
}
