// Ported and adapted from chrono 0.4.45 (MIT OR Apache-2.0).
use super::{ParseResult, IMPOSSIBLE, NOT_ENOUGH, OUT_OF_RANGE};
use crate::{
    DateTime, FixedOffset, MappedLocalTime, NaiveDate, NaiveDateTime, NaiveTime, TimeZone,
};

#[derive(Clone, Default)]
pub(crate) struct Parsed {
    year: Option<i32>,
    month: Option<u32>,
    day: Option<u32>,
    hour_div_12: Option<u32>,
    hour_mod_12: Option<u32>,
    minute: Option<u32>,
    second: Option<u32>,
    nanosecond: Option<u32>,
    offset: Option<i32>,
}
impl Parsed {
    pub(crate) fn new() -> Self {
        Self::default()
    }
    pub fn set_year(&mut self, value: i64) -> ParseResult<()> {
        set_if_consistent(
            &mut self.year,
            i32::try_from(value).map_err(|_| OUT_OF_RANGE)?,
        )
    }

    pub fn set_month(&mut self, value: i64) -> ParseResult<()> {
        if !(1..=12).contains(&value) {
            return Err(OUT_OF_RANGE);
        }
        set_if_consistent(&mut self.month, value as u32)
    }

    pub fn set_day(&mut self, value: i64) -> ParseResult<()> {
        if !(1..=31).contains(&value) {
            return Err(OUT_OF_RANGE);
        }
        set_if_consistent(&mut self.day, value as u32)
    }

    pub fn set_hour(&mut self, value: i64) -> ParseResult<()> {
        let (hour_div_12, hour_mod_12) = match value {
            hour @ 0..=11 => (0, hour as u32),
            hour @ 12..=23 => (1, hour as u32 - 12),
            _ => return Err(OUT_OF_RANGE),
        };
        set_if_consistent(&mut self.hour_div_12, hour_div_12)?;
        set_if_consistent(&mut self.hour_mod_12, hour_mod_12)
    }

    pub fn set_minute(&mut self, value: i64) -> ParseResult<()> {
        if !(0..=59).contains(&value) {
            return Err(OUT_OF_RANGE);
        }
        set_if_consistent(&mut self.minute, value as u32)
    }

    pub fn set_second(&mut self, value: i64) -> ParseResult<()> {
        if !(0..=60).contains(&value) {
            return Err(OUT_OF_RANGE);
        }
        set_if_consistent(&mut self.second, value as u32)
    }

    pub fn set_nanosecond(&mut self, value: i64) -> ParseResult<()> {
        if !(0..=999_999_999).contains(&value) {
            return Err(OUT_OF_RANGE);
        }
        set_if_consistent(&mut self.nanosecond, value as u32)
    }

    pub fn set_offset(&mut self, value: i64) -> ParseResult<()> {
        set_if_consistent(
            &mut self.offset,
            i32::try_from(value).map_err(|_| OUT_OF_RANGE)?,
        )
    }

    pub fn to_naive_time(&self) -> ParseResult<NaiveTime> {
        let hour_div_12 = match self.hour_div_12 {
            Some(v @ 0..=1) => v,
            Some(_) => return Err(OUT_OF_RANGE),
            None => return Err(NOT_ENOUGH),
        };
        let hour_mod_12 = match self.hour_mod_12 {
            Some(v @ 0..=11) => v,
            Some(_) => return Err(OUT_OF_RANGE),
            None => return Err(NOT_ENOUGH),
        };
        let hour = hour_div_12 * 12 + hour_mod_12;

        let minute = match self.minute {
            Some(v @ 0..=59) => v,
            Some(_) => return Err(OUT_OF_RANGE),
            None => return Err(NOT_ENOUGH),
        };

        // we allow omitting seconds or nanoseconds, but they should be in the range.
        let (second, mut nano) = match self.second.unwrap_or(0) {
            v @ 0..=59 => (v, 0),
            60 => (59, 1_000_000_000),
            _ => return Err(OUT_OF_RANGE),
        };
        nano += match self.nanosecond {
            Some(v @ 0..=999_999_999) if self.second.is_some() => v,
            Some(0..=999_999_999) => return Err(NOT_ENOUGH), // second is missing
            Some(_) => return Err(OUT_OF_RANGE),
            None => 0,
        };

        NaiveTime::from_hms_nano_opt(hour, minute, second, nano).ok_or(OUT_OF_RANGE)
    }
    pub(crate) fn to_naive_date(&self) -> ParseResult<NaiveDate> {
        match (self.year, self.month, self.day) {
            (Some(year), Some(month), Some(day)) => {
                NaiveDate::from_ymd_opt(year, month, day).ok_or(OUT_OF_RANGE)
            }
            _ => Err(NOT_ENOUGH),
        }
    }
    pub(crate) fn to_naive_datetime_with_offset(&self, _offset: i32) -> ParseResult<NaiveDateTime> {
        // Without a timestamp field chrono resolves the date error before the time error.
        let date = self.to_naive_date()?;
        let time = self.to_naive_time()?;
        Ok(date.and_time(time))
    }
    pub(crate) fn to_datetime(&self) -> ParseResult<DateTime<FixedOffset>> {
        let offset = self.offset.ok_or(NOT_ENOUGH)?;
        let datetime = self.to_naive_datetime_with_offset(offset)?;
        let offset = FixedOffset::east_opt(offset).ok_or(OUT_OF_RANGE)?;
        match offset.from_local_datetime(&datetime) {
            MappedLocalTime::None => Err(IMPOSSIBLE),
            MappedLocalTime::Single(t) => Ok(t),
            MappedLocalTime::Ambiguous(..) => Err(NOT_ENOUGH),
        }
    }
}
fn set_if_consistent<T: PartialEq>(old: &mut Option<T>, new: T) -> ParseResult<()> {
    match old {
        Some(old) if *old != new => Err(IMPOSSIBLE),
        _ => {
            *old = Some(new);
            Ok(())
        }
    }
}
