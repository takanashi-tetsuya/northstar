// Ported and adapted from chrono 0.4.45 (MIT OR Apache-2.0).
use crate::format::{
    parse, Fixed, Item, Numeric, Pad, ParseError, ParseResult, Parsed, StrftimeItems,
};
use crate::{
    expect, DateTime, FixedOffset, MappedLocalTime, NaiveDate, NaiveTime, TimeDelta, TimeZone, Utc,
};
use core::fmt::Write;
use core::ops::{Add, AddAssign, Sub, SubAssign};
use core::{fmt, str};

#[derive(PartialEq, Eq, Hash, PartialOrd, Ord, Copy, Clone)]
pub struct NaiveDateTime {
    date: NaiveDate,
    time: NaiveTime,
}
impl NaiveDateTime {
    pub const fn new(date: NaiveDate, time: NaiveTime) -> NaiveDateTime {
        NaiveDateTime { date, time }
    }

    pub const fn date(&self) -> NaiveDate {
        self.date
    }

    pub const fn time(&self) -> NaiveTime {
        self.time
    }

    pub const fn and_utc(&self) -> DateTime<Utc> {
        DateTime::from_naive_utc_and_offset(*self, Utc)
    }

    pub const fn checked_add_signed(self, rhs: TimeDelta) -> Option<NaiveDateTime> {
        let (time, remainder) = self.time.overflowing_add_signed(rhs);
        let remainder = try_opt!(TimeDelta::try_seconds(remainder));
        let date = try_opt!(self.date.checked_add_signed(remainder));
        Some(NaiveDateTime { date, time })
    }

    pub const fn checked_sub_signed(self, rhs: TimeDelta) -> Option<NaiveDateTime> {
        let (time, remainder) = self.time.overflowing_sub_signed(rhs);
        let remainder = try_opt!(TimeDelta::try_seconds(remainder));
        let date = try_opt!(self.date.checked_sub_signed(remainder));
        Some(NaiveDateTime { date, time })
    }

    pub const fn signed_duration_since(self, rhs: NaiveDateTime) -> TimeDelta {
        expect(
            self.date
                .signed_duration_since(rhs.date)
                .checked_add(&self.time.signed_duration_since(rhs.time)),
            "always in range",
        )
    }

    pub const fn checked_add_offset(self, rhs: FixedOffset) -> Option<NaiveDateTime> {
        let (time, days) = self.time.overflowing_add_offset(rhs);
        let date = match days {
            -1 => try_opt!(self.date.pred_opt()),
            1 => try_opt!(self.date.succ_opt()),
            _ => self.date,
        };
        Some(NaiveDateTime { date, time })
    }

    pub const fn checked_sub_offset(self, rhs: FixedOffset) -> Option<NaiveDateTime> {
        let (time, days) = self.time.overflowing_sub_offset(rhs);
        let date = match days {
            -1 => try_opt!(self.date.pred_opt()),
            1 => try_opt!(self.date.succ_opt()),
            _ => self.date,
        };
        Some(NaiveDateTime { date, time })
    }

    pub(crate) fn overflowing_add_offset(self, rhs: FixedOffset) -> NaiveDateTime {
        let (time, days) = self.time.overflowing_add_offset(rhs);
        let date = match days {
            -1 => self.date.pred_opt().unwrap_or(NaiveDate::BEFORE_MIN),
            1 => self.date.succ_opt().unwrap_or(NaiveDate::AFTER_MAX),
            _ => self.date,
        };
        NaiveDateTime { date, time }
    }

    pub fn and_local_timezone<Tz: TimeZone>(&self, tz: Tz) -> MappedLocalTime<DateTime<Tz>> {
        tz.from_local_datetime(self)
    }
    pub const MIN: Self = Self {
        date: NaiveDate::MIN,
        time: NaiveTime::MIN,
    };
    pub const MAX: Self = Self {
        date: NaiveDate::MAX,
        time: NaiveTime::MAX,
    };
    pub(crate) const fn nanosecond(&self) -> u32 {
        self.time.nanosecond()
    }
    /// Parses the restricted strftime set documented at the crate root.
    pub fn parse_from_str(s: &str, fmt: &str) -> ParseResult<Self> {
        let mut parsed = Parsed::new();
        parse(&mut parsed, s, StrftimeItems::new(fmt))?;
        parsed.to_naive_datetime_with_offset(0)
    }
}
impl fmt::Debug for NaiveDateTime {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.date.fmt(f)?;
        f.write_char('T')?;
        self.time.fmt(f)
    }
}

impl fmt::Display for NaiveDateTime {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.date.fmt(f)?;
        f.write_char(' ')?;
        self.time.fmt(f)
    }
}

impl str::FromStr for NaiveDateTime {
    type Err = ParseError;

    fn from_str(s: &str) -> ParseResult<NaiveDateTime> {
        const ITEMS: &[Item<'static>] = &[
            Item::Numeric(Numeric::Year, Pad::Zero),
            Item::Space(""),
            Item::Literal("-"),
            Item::Numeric(Numeric::Month, Pad::Zero),
            Item::Space(""),
            Item::Literal("-"),
            Item::Numeric(Numeric::Day, Pad::Zero),
            Item::Space(""),
            Item::Literal("T"), // XXX shouldn't this be case-insensitive?
            Item::Numeric(Numeric::Hour, Pad::Zero),
            Item::Space(""),
            Item::Literal(":"),
            Item::Numeric(Numeric::Minute, Pad::Zero),
            Item::Space(""),
            Item::Literal(":"),
            Item::Numeric(Numeric::Second, Pad::Zero),
            Item::Fixed(Fixed::Nanosecond),
            Item::Space(""),
        ];

        let mut parsed = Parsed::new();
        parse(&mut parsed, s, ITEMS.iter())?;
        parsed.to_naive_datetime_with_offset(0)
    }
}

impl Default for NaiveDateTime {
    fn default() -> Self {
        DateTime::UNIX_EPOCH.naive_local()
    }
}

impl Add<TimeDelta> for NaiveDateTime {
    type Output = NaiveDateTime;

    #[inline]
    #[track_caller]
    fn add(self, rhs: TimeDelta) -> NaiveDateTime {
        self.checked_add_signed(rhs)
            .expect("`NaiveDateTime + TimeDelta` overflowed")
    }
}

impl AddAssign<TimeDelta> for NaiveDateTime {
    #[inline]
    #[track_caller]
    fn add_assign(&mut self, rhs: TimeDelta) {
        *self = self.add(rhs);
    }
}

impl Sub<TimeDelta> for NaiveDateTime {
    type Output = NaiveDateTime;

    #[inline]
    #[track_caller]
    fn sub(self, rhs: TimeDelta) -> NaiveDateTime {
        self.checked_sub_signed(rhs)
            .expect("`NaiveDateTime - TimeDelta` overflowed")
    }
}

impl SubAssign<TimeDelta> for NaiveDateTime {
    #[inline]
    #[track_caller]
    fn sub_assign(&mut self, rhs: TimeDelta) {
        *self = self.sub(rhs);
    }
}

impl Sub<NaiveDateTime> for NaiveDateTime {
    type Output = TimeDelta;

    #[inline]
    fn sub(self, rhs: NaiveDateTime) -> TimeDelta {
        self.signed_duration_since(rhs)
    }
}
