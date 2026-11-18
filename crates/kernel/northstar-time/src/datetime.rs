// Ported and adapted from chrono 0.4.45 (MIT OR Apache-2.0).
use crate::format::{
    parse, parse_rfc3339, write_rfc3339, DelayedFormat, ParseError, ParseResult, Parsed,
    SecondsFormat, StrftimeItems,
};
use crate::{
    expect, FixedOffset, NaiveDate, NaiveDateTime, NaiveTime, Offset, TimeDelta, TimeZone, Utc,
};
use core::borrow::Borrow;
use core::cmp::Ordering;
use core::fmt::{self, Write};
use core::ops::{Add, AddAssign, Sub, SubAssign};
use core::{hash, str};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const UNIX_EPOCH_DAY: i64 = 719_163;
#[derive(Clone)]
pub struct DateTime<Tz: TimeZone> {
    datetime: NaiveDateTime,
    offset: Tz::Offset,
}
impl<Tz: TimeZone> DateTime<Tz> {
    pub const fn from_naive_utc_and_offset(
        datetime: NaiveDateTime,
        offset: Tz::Offset,
    ) -> DateTime<Tz> {
        DateTime { datetime, offset }
    }

    pub const fn timestamp(&self) -> i64 {
        let gregorian_day = self.datetime.date().num_days_from_ce() as i64;
        let seconds_from_midnight = self.datetime.time().num_seconds_from_midnight() as i64;
        (gregorian_day - UNIX_EPOCH_DAY) * 86_400 + seconds_from_midnight
    }

    pub const fn timestamp_millis(&self) -> i64 {
        let as_ms = self.timestamp() * 1000;
        as_ms + self.timestamp_subsec_millis() as i64
    }

    pub const fn timestamp_micros(&self) -> i64 {
        let as_us = self.timestamp() * 1_000_000;
        as_us + self.timestamp_subsec_micros() as i64
    }

    pub const fn timestamp_nanos_opt(&self) -> Option<i64> {
        let mut timestamp = self.timestamp();
        let mut subsec_nanos = self.timestamp_subsec_nanos() as i64;
        // `(timestamp * 1_000_000_000) + subsec_nanos` may create a temporary that underflows while
        // the final value can be represented as an `i64`.
        // As workaround we converting the negative case to:
        // `((timestamp + 1) * 1_000_000_000) + (ns - 1_000_000_000)``
        //
        // Also see <https://github.com/chronotope/chrono/issues/1289>.
        if timestamp < 0 {
            subsec_nanos -= 1_000_000_000;
            timestamp += 1;
        }
        try_opt!(timestamp.checked_mul(1_000_000_000)).checked_add(subsec_nanos)
    }

    pub const fn timestamp_subsec_millis(&self) -> u32 {
        self.timestamp_subsec_nanos() / 1_000_000
    }

    pub const fn timestamp_subsec_micros(&self) -> u32 {
        self.timestamp_subsec_nanos() / 1_000
    }

    pub const fn timestamp_subsec_nanos(&self) -> u32 {
        self.datetime.time().nanosecond()
    }

    pub const fn naive_utc(&self) -> NaiveDateTime {
        self.datetime
    }

    pub fn naive_local(&self) -> NaiveDateTime {
        self.datetime
            .checked_add_offset(self.offset.fix())
            .expect("Local time out of range for `NaiveDateTime`")
    }

    pub fn date_naive(&self) -> NaiveDate {
        self.naive_local().date()
    }

    pub fn time(&self) -> NaiveTime {
        self.datetime
            .time()
            .overflowing_add_offset(self.offset.fix())
            .0
    }

    pub const fn offset(&self) -> &Tz::Offset {
        &self.offset
    }

    pub fn timezone(&self) -> Tz {
        TimeZone::from_offset(&self.offset)
    }

    pub fn with_timezone<Tz2: TimeZone>(&self, tz: &Tz2) -> DateTime<Tz2> {
        tz.from_utc_datetime(&self.datetime)
    }

    pub fn fixed_offset(&self) -> DateTime<FixedOffset> {
        self.with_timezone(&self.offset().fix())
    }

    pub const fn to_utc(&self) -> DateTime<Utc> {
        DateTime {
            datetime: self.datetime,
            offset: Utc,
        }
    }

    pub fn signed_duration_since<Tz2: TimeZone>(
        self,
        rhs: impl Borrow<DateTime<Tz2>>,
    ) -> TimeDelta {
        self.datetime.signed_duration_since(rhs.borrow().datetime)
    }

    pub fn checked_add_signed(self, rhs: TimeDelta) -> Option<DateTime<Tz>> {
        let datetime = self.datetime.checked_add_signed(rhs)?;
        let tz = self.timezone();
        Some(tz.from_utc_datetime(&datetime))
    }

    pub fn checked_sub_signed(self, rhs: TimeDelta) -> Option<DateTime<Tz>> {
        let datetime = self.datetime.checked_sub_signed(rhs)?;
        let tz = self.timezone();
        Some(tz.from_utc_datetime(&datetime))
    }

    pub(crate) fn overflowing_naive_local(&self) -> NaiveDateTime {
        self.datetime.overflowing_add_offset(self.offset.fix())
    }

    pub fn to_rfc3339(&self) -> String {
        // For some reason a string with a capacity less than 32 is ca 20% slower when benchmarking.
        let mut result = String::with_capacity(32);
        let naive = self.overflowing_naive_local();
        let offset = self.offset.fix();
        write_rfc3339(&mut result, naive, offset, SecondsFormat::AutoSi, false)
            .expect("writing rfc3339 datetime to string should never fail");
        result
    }

    pub fn to_rfc3339_opts(&self, secform: SecondsFormat, use_z: bool) -> String {
        let mut result = String::with_capacity(38);
        write_rfc3339(
            &mut result,
            self.naive_local(),
            self.offset.fix(),
            secform,
            use_z,
        )
        .expect("writing rfc3339 datetime to string should never fail");
        result
    }
    pub const MIN_UTC: DateTime<Utc> = DateTime {
        datetime: NaiveDateTime::MIN,
        offset: Utc,
    };
    pub const MAX_UTC: DateTime<Utc> = DateTime {
        datetime: NaiveDateTime::MAX,
        offset: Utc,
    };
}
impl DateTime<Utc> {
    pub const fn from_timestamp(secs: i64, nsecs: u32) -> Option<Self> {
        let days = secs.div_euclid(86_400) + UNIX_EPOCH_DAY;
        let secs = secs.rem_euclid(86_400);
        if days < i32::MIN as i64 || days > i32::MAX as i64 {
            return None;
        }
        let date = try_opt!(NaiveDate::from_num_days_from_ce_opt(days as i32));
        let time = try_opt!(NaiveTime::from_num_seconds_from_midnight_opt(
            secs as u32,
            nsecs
        ));
        Some(date.and_time(time).and_utc())
    }

    pub const fn from_timestamp_millis(millis: i64) -> Option<Self> {
        let secs = millis.div_euclid(1000);
        let nsecs = millis.rem_euclid(1000) as u32 * 1_000_000;
        Self::from_timestamp(secs, nsecs)
    }

    pub const fn from_timestamp_micros(micros: i64) -> Option<Self> {
        let secs = micros.div_euclid(1_000_000);
        let nsecs = micros.rem_euclid(1_000_000) as u32 * 1000;
        Self::from_timestamp(secs, nsecs)
    }

    pub const fn from_timestamp_nanos(nanos: i64) -> Self {
        let secs = nanos.div_euclid(1_000_000_000);
        let nsecs = nanos.rem_euclid(1_000_000_000) as u32;
        expect(
            Self::from_timestamp(secs, nsecs),
            "timestamp in nanos is always in range",
        )
    }
    pub const UNIX_EPOCH: Self = expect(NaiveDate::from_ymd_opt(1970, 1, 1), "")
        .and_time(NaiveTime::MIN)
        .and_utc();
}
impl DateTime<FixedOffset> {
    pub fn parse_from_rfc3339(s: &str) -> ParseResult<DateTime<FixedOffset>> {
        parse_rfc3339(s)
    }
    /// Parses the restricted strftime set documented at the crate root.
    pub fn parse_from_str(s: &str, fmt: &str) -> ParseResult<DateTime<FixedOffset>> {
        let mut parsed = Parsed::new();
        parse(&mut parsed, s, StrftimeItems::new(fmt))?;
        parsed.to_datetime()
    }
}
impl<Tz: TimeZone> DateTime<Tz>
where
    Tz::Offset: fmt::Display,
{
    /// Formats the restricted strftime set documented at the crate root.
    pub fn format<'a>(&self, fmt: &'a str) -> DelayedFormat<StrftimeItems<'a>> {
        let local = self.overflowing_naive_local();
        DelayedFormat::new_with_offset(
            Some(local.date()),
            Some(local.time()),
            &self.offset,
            StrftimeItems::new(fmt),
        )
    }
}
impl Default for DateTime<Utc> {
    fn default() -> Self {
        Utc.from_utc_datetime(&NaiveDateTime::default())
    }
}

impl Default for DateTime<FixedOffset> {
    fn default() -> Self {
        FixedOffset::west_opt(0)
            .unwrap()
            .from_utc_datetime(&NaiveDateTime::default())
    }
}

impl From<DateTime<Utc>> for DateTime<FixedOffset> {
    fn from(src: DateTime<Utc>) -> Self {
        src.with_timezone(&FixedOffset::east_opt(0).unwrap())
    }
}

impl From<DateTime<FixedOffset>> for DateTime<Utc> {
    fn from(src: DateTime<FixedOffset>) -> Self {
        src.with_timezone(&Utc)
    }
}

impl<Tz: TimeZone> Copy for DateTime<Tz>
where
    <Tz as TimeZone>::Offset: Copy,
    NaiveDateTime: Copy,
{
}

impl<Tz: TimeZone, Tz2: TimeZone> PartialEq<DateTime<Tz2>> for DateTime<Tz> {
    fn eq(&self, other: &DateTime<Tz2>) -> bool {
        self.datetime == other.datetime
    }
}

impl<Tz: TimeZone> Eq for DateTime<Tz> {}

impl<Tz: TimeZone, Tz2: TimeZone> PartialOrd<DateTime<Tz2>> for DateTime<Tz> {
    fn partial_cmp(&self, other: &DateTime<Tz2>) -> Option<Ordering> {
        self.datetime.partial_cmp(&other.datetime)
    }
}

impl<Tz: TimeZone> Ord for DateTime<Tz> {
    fn cmp(&self, other: &DateTime<Tz>) -> Ordering {
        self.datetime.cmp(&other.datetime)
    }
}

impl<Tz: TimeZone> hash::Hash for DateTime<Tz> {
    fn hash<H: hash::Hasher>(&self, state: &mut H) {
        self.datetime.hash(state)
    }
}

impl<Tz: TimeZone> Add<TimeDelta> for DateTime<Tz> {
    type Output = DateTime<Tz>;

    #[inline]
    #[track_caller]
    fn add(self, rhs: TimeDelta) -> DateTime<Tz> {
        self.checked_add_signed(rhs)
            .expect("`DateTime + TimeDelta` overflowed")
    }
}

impl<Tz: TimeZone> Add<Duration> for DateTime<Tz> {
    type Output = DateTime<Tz>;

    #[inline]
    #[track_caller]
    fn add(self, rhs: Duration) -> DateTime<Tz> {
        let rhs = TimeDelta::from_std(rhs)
            .expect("overflow converting from core::time::Duration to TimeDelta");
        self.checked_add_signed(rhs)
            .expect("`DateTime + TimeDelta` overflowed")
    }
}

impl<Tz: TimeZone> AddAssign<TimeDelta> for DateTime<Tz> {
    #[inline]
    #[track_caller]
    fn add_assign(&mut self, rhs: TimeDelta) {
        let datetime = self
            .datetime
            .checked_add_signed(rhs)
            .expect("`DateTime + TimeDelta` overflowed");
        let tz = self.timezone();
        *self = tz.from_utc_datetime(&datetime);
    }
}

impl<Tz: TimeZone> AddAssign<Duration> for DateTime<Tz> {
    #[inline]
    #[track_caller]
    fn add_assign(&mut self, rhs: Duration) {
        let rhs = TimeDelta::from_std(rhs)
            .expect("overflow converting from core::time::Duration to TimeDelta");
        *self += rhs;
    }
}

impl<Tz: TimeZone> Sub<TimeDelta> for DateTime<Tz> {
    type Output = DateTime<Tz>;

    #[inline]
    #[track_caller]
    fn sub(self, rhs: TimeDelta) -> DateTime<Tz> {
        self.checked_sub_signed(rhs)
            .expect("`DateTime - TimeDelta` overflowed")
    }
}

impl<Tz: TimeZone> Sub<Duration> for DateTime<Tz> {
    type Output = DateTime<Tz>;

    #[inline]
    #[track_caller]
    fn sub(self, rhs: Duration) -> DateTime<Tz> {
        let rhs = TimeDelta::from_std(rhs)
            .expect("overflow converting from core::time::Duration to TimeDelta");
        self.checked_sub_signed(rhs)
            .expect("`DateTime - TimeDelta` overflowed")
    }
}

impl<Tz: TimeZone> SubAssign<TimeDelta> for DateTime<Tz> {
    #[inline]
    #[track_caller]
    fn sub_assign(&mut self, rhs: TimeDelta) {
        let datetime = self
            .datetime
            .checked_sub_signed(rhs)
            .expect("`DateTime - TimeDelta` overflowed");
        let tz = self.timezone();
        *self = tz.from_utc_datetime(&datetime)
    }
}

impl<Tz: TimeZone> SubAssign<Duration> for DateTime<Tz> {
    #[inline]
    #[track_caller]
    fn sub_assign(&mut self, rhs: Duration) {
        let rhs = TimeDelta::from_std(rhs)
            .expect("overflow converting from core::time::Duration to TimeDelta");
        *self -= rhs;
    }
}

impl<Tz: TimeZone> Sub<DateTime<Tz>> for DateTime<Tz> {
    type Output = TimeDelta;

    #[inline]
    fn sub(self, rhs: DateTime<Tz>) -> TimeDelta {
        self.signed_duration_since(rhs)
    }
}

impl<Tz: TimeZone> fmt::Debug for DateTime<Tz> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.overflowing_naive_local().fmt(f)?;
        self.offset.fmt(f)
    }
}

impl<Tz: TimeZone> fmt::Display for DateTime<Tz>
where
    Tz::Offset: fmt::Display,
{
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.overflowing_naive_local().fmt(f)?;
        f.write_char(' ')?;
        self.offset.fmt(f)
    }
}

impl str::FromStr for DateTime<Utc> {
    type Err = ParseError;

    fn from_str(s: &str) -> ParseResult<DateTime<Utc>> {
        s.parse::<DateTime<FixedOffset>>()
            .map(|dt| dt.with_timezone(&Utc))
    }
}

impl From<SystemTime> for DateTime<Utc> {
    fn from(t: SystemTime) -> DateTime<Utc> {
        let (sec, nsec) = match t.duration_since(UNIX_EPOCH) {
            Ok(dur) => (dur.as_secs() as i64, dur.subsec_nanos()),
            Err(e) => {
                // unlikely but should be handled
                let dur = e.duration();
                let (sec, nsec) = (dur.as_secs() as i64, dur.subsec_nanos());
                if nsec == 0 {
                    (-sec, 0)
                } else {
                    (-sec - 1, 1_000_000_000 - nsec)
                }
            }
        };
        Utc.timestamp_opt(sec, nsec).unwrap()
    }
}

impl<Tz: TimeZone> From<DateTime<Tz>> for SystemTime {
    fn from(dt: DateTime<Tz>) -> SystemTime {
        let sec = dt.timestamp();
        let nsec = dt.timestamp_subsec_nanos();
        if sec < 0 {
            // unlikely but should be handled
            UNIX_EPOCH - Duration::new(-sec as u64, 0) + Duration::new(0, nsec)
        } else {
            UNIX_EPOCH + Duration::new(sec as u64, nsec)
        }
    }
}
