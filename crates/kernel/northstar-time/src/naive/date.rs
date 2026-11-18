// Ported and adapted from chrono 0.4.45 (MIT OR Apache-2.0).
use crate::format::{parse, Item, Numeric, Pad, ParseError, ParseResult, Parsed, StrftimeItems};
use crate::{expect, NaiveDateTime, NaiveTime, TimeDelta};
use core::ops::{Add, AddAssign, Sub, SubAssign};
use core::{fmt, str};

const MIN_YEAR: i32 = (i32::MIN >> 13) + 1;
const MAX_YEAR: i32 = (i32::MAX >> 13) - 1;
const CE_JULIAN_DAY: i32 = 1_721_425;

#[derive(PartialEq, Eq, Hash, PartialOrd, Ord, Copy, Clone)]
pub struct NaiveDate {
    inner: time::Date,
}

const fn calendar_date(year: i32, ordinal: u16) -> time::Date {
    match time::Date::from_ordinal_date(year, ordinal) {
        Ok(date) => date,
        Err(_) => panic!("invalid internal calendar date"),
    }
}

impl NaiveDate {
    pub const MIN: Self = Self {
        inner: calendar_date(MIN_YEAR, 1),
    };
    pub const MAX: Self = Self {
        inner: calendar_date(MAX_YEAR, 365),
    };
    pub(crate) const BEFORE_MIN: Self = Self {
        inner: calendar_date(MIN_YEAR - 1, 366),
    };
    pub(crate) const AFTER_MAX: Self = Self {
        inner: calendar_date(MAX_YEAR + 1, 1),
    };

    pub const fn from_ymd_opt(year: i32, month: u32, day: u32) -> Option<Self> {
        if year < MIN_YEAR || year > MAX_YEAR || month < 1 || month > 12 || day < 1 || day > 31 {
            return None;
        }
        let month = match month {
            1 => time::Month::January,
            2 => time::Month::February,
            3 => time::Month::March,
            4 => time::Month::April,
            5 => time::Month::May,
            6 => time::Month::June,
            7 => time::Month::July,
            8 => time::Month::August,
            9 => time::Month::September,
            10 => time::Month::October,
            11 => time::Month::November,
            12 => time::Month::December,
            _ => return None,
        };
        match time::Date::from_calendar_date(year, month, day as u8) {
            Ok(inner) => Some(Self { inner }),
            Err(_) => None,
        }
    }

    pub const fn from_num_days_from_ce_opt(days: i32) -> Option<Self> {
        let jd = try_opt!(days.checked_add(CE_JULIAN_DAY));
        let inner = match time::Date::from_julian_day(jd) {
            Ok(value) => value,
            Err(_) => return None,
        };
        if inner.year() < MIN_YEAR || inner.year() > MAX_YEAR {
            return None;
        }
        Some(Self { inner })
    }

    pub const fn year(&self) -> i32 {
        self.inner.year()
    }
    pub const fn month(&self) -> u32 {
        self.inner.month() as u32
    }
    pub const fn day(&self) -> u32 {
        self.inner.day() as u32
    }
    pub const fn ordinal(&self) -> u32 {
        self.inner.ordinal() as u32
    }
    pub(crate) const fn num_days_from_ce(&self) -> i32 {
        self.inner.to_julian_day() - CE_JULIAN_DAY
    }
    pub(crate) const fn add_days(self, days: i32) -> Option<Self> {
        Self::from_num_days_from_ce_opt(try_opt!(self.num_days_from_ce().checked_add(days)))
    }
    pub(crate) const fn pred_opt(&self) -> Option<Self> {
        self.add_days(-1)
    }
    pub(crate) const fn succ_opt(&self) -> Option<Self> {
        self.add_days(1)
    }

    pub const fn signed_duration_since(self, rhs: Self) -> TimeDelta {
        expect(
            TimeDelta::try_days((self.inner.to_julian_day() - rhs.inner.to_julian_day()) as i64),
            "always in range",
        )
    }
    pub const fn and_time(&self, time: NaiveTime) -> NaiveDateTime {
        NaiveDateTime::new(*self, time)
    }

    pub const fn and_hms_opt(&self, hour: u32, min: u32, sec: u32) -> Option<NaiveDateTime> {
        let time = try_opt!(NaiveTime::from_hms_opt(hour, min, sec));
        Some(self.and_time(time))
    }

    pub const fn and_hms_milli_opt(
        &self,
        hour: u32,
        min: u32,
        sec: u32,
        milli: u32,
    ) -> Option<NaiveDateTime> {
        let time = try_opt!(NaiveTime::from_hms_milli_opt(hour, min, sec, milli));
        Some(self.and_time(time))
    }

    pub const fn and_hms_micro_opt(
        &self,
        hour: u32,
        min: u32,
        sec: u32,
        micro: u32,
    ) -> Option<NaiveDateTime> {
        let time = try_opt!(NaiveTime::from_hms_micro_opt(hour, min, sec, micro));
        Some(self.and_time(time))
    }

    pub const fn and_hms_nano_opt(
        &self,
        hour: u32,
        min: u32,
        sec: u32,
        nano: u32,
    ) -> Option<NaiveDateTime> {
        let time = try_opt!(NaiveTime::from_hms_nano_opt(hour, min, sec, nano));
        Some(self.and_time(time))
    }

    pub const fn checked_add_signed(self, rhs: TimeDelta) -> Option<NaiveDate> {
        let days = rhs.num_days();
        if days < i32::MIN as i64 || days > i32::MAX as i64 {
            return None;
        }
        self.add_days(days as i32)
    }

    pub const fn checked_sub_signed(self, rhs: TimeDelta) -> Option<NaiveDate> {
        let days = -rhs.num_days();
        if days < i32::MIN as i64 || days > i32::MAX as i64 {
            return None;
        }
        self.add_days(days as i32)
    }
    /// Parses the restricted strftime set documented at the crate root.
    pub fn parse_from_str(s: &str, fmt: &str) -> ParseResult<Self> {
        let mut parsed = Parsed::new();
        parse(&mut parsed, s, StrftimeItems::new(fmt))?;
        parsed.to_naive_date()
    }
}
impl fmt::Debug for NaiveDate {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let year = self.year();
        if (0..=9999).contains(&year) {
            write!(f, "{year:04}")?;
        } else {
            write!(f, "{year:+05}")?;
        }
        write!(f, "-{:02}-{:02}", self.month(), self.day())
    }
}
impl fmt::Display for NaiveDate {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Debug::fmt(self, f)
    }
}

impl str::FromStr for NaiveDate {
    type Err = ParseError;

    fn from_str(s: &str) -> ParseResult<NaiveDate> {
        const ITEMS: &[Item<'static>] = &[
            Item::Numeric(Numeric::Year, Pad::Zero),
            Item::Space(""),
            Item::Literal("-"),
            Item::Numeric(Numeric::Month, Pad::Zero),
            Item::Space(""),
            Item::Literal("-"),
            Item::Numeric(Numeric::Day, Pad::Zero),
            Item::Space(""),
        ];

        let mut parsed = Parsed::new();
        parse(&mut parsed, s, ITEMS.iter())?;
        parsed.to_naive_date()
    }
}

impl Default for NaiveDate {
    fn default() -> Self {
        NaiveDate::from_ymd_opt(1970, 1, 1).unwrap()
    }
}

impl Add<TimeDelta> for NaiveDate {
    type Output = NaiveDate;

    #[inline]
    #[track_caller]
    fn add(self, rhs: TimeDelta) -> NaiveDate {
        self.checked_add_signed(rhs)
            .expect("`NaiveDate + TimeDelta` overflowed")
    }
}

impl AddAssign<TimeDelta> for NaiveDate {
    #[inline]
    #[track_caller]
    fn add_assign(&mut self, rhs: TimeDelta) {
        *self = self.add(rhs);
    }
}

impl Sub<TimeDelta> for NaiveDate {
    type Output = NaiveDate;

    #[inline]
    #[track_caller]
    fn sub(self, rhs: TimeDelta) -> NaiveDate {
        self.checked_sub_signed(rhs)
            .expect("`NaiveDate - TimeDelta` overflowed")
    }
}

impl SubAssign<TimeDelta> for NaiveDate {
    #[inline]
    #[track_caller]
    fn sub_assign(&mut self, rhs: TimeDelta) {
        *self = self.sub(rhs);
    }
}

impl Sub<NaiveDate> for NaiveDate {
    type Output = TimeDelta;

    #[inline]
    fn sub(self, rhs: NaiveDate) -> TimeDelta {
        self.signed_duration_since(rhs)
    }
}
