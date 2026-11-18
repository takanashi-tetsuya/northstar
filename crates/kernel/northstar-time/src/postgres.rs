// Chrono 0.4.45 arithmetic; PostgreSQL codecs adapted from SQLx 0.9.0
// (MIT OR Apache-2.0; see LICENSE-sqlx.txt).
use crate::{
    DateTime, Duration, FixedOffset, NaiveDate, NaiveDateTime, Offset, TimeDelta, TimeZone, Utc,
};
use sqlx::decode::Decode;
use sqlx::encode::{Encode, IsNull};
use sqlx::error::BoxDynError;
use sqlx::postgres::{PgArgumentBuffer, PgHasArrayType, PgTypeInfo, PgValueFormat, PgValueRef};
use sqlx::Postgres;
use sqlx::Type;
use std::mem;

impl Type<Postgres> for NaiveDateTime {
    fn type_info() -> PgTypeInfo {
        PgTypeInfo::with_name("timestamp")
    }
}

impl<Tz: TimeZone> Type<Postgres> for DateTime<Tz> {
    fn type_info() -> PgTypeInfo {
        PgTypeInfo::with_name("timestamptz")
    }
}

impl PgHasArrayType for NaiveDateTime {
    fn array_type_info() -> PgTypeInfo {
        PgTypeInfo::array_of("timestamp")
    }
}

impl<Tz: TimeZone> PgHasArrayType for DateTime<Tz> {
    fn array_type_info() -> PgTypeInfo {
        PgTypeInfo::array_of("timestamptz")
    }
}

impl Encode<'_, Postgres> for NaiveDateTime {
    fn encode_by_ref(&self, buf: &mut PgArgumentBuffer) -> Result<IsNull, BoxDynError> {
        // TIMESTAMP is encoded as the microseconds since the epoch
        let micros = (*self - postgres_epoch_datetime())
            .num_microseconds()
            .ok_or_else(|| format!("NaiveDateTime out of range for Postgres: {self:?}"))?;

        Encode::<Postgres>::encode(micros, buf)
    }

    fn size_hint(&self) -> usize {
        mem::size_of::<i64>()
    }
}

impl<'r> Decode<'r, Postgres> for NaiveDateTime {
    fn decode(value: PgValueRef<'r>) -> Result<Self, BoxDynError> {
        Ok(match value.format() {
            PgValueFormat::Binary => {
                // TIMESTAMP is encoded as the microseconds since the epoch
                let us = Decode::<Postgres>::decode(value)?;
                postgres_epoch_datetime() + Duration::microseconds(us)
            }

            PgValueFormat::Text => {
                let s = value.as_str()?;
                NaiveDateTime::parse_from_str(
                    s,
                    if s.contains('+') {
                        // Contains a time-zone specifier
                        // This is given for timestamptz for some reason
                        // Postgres already guarantees this to always be UTC
                        "%Y-%m-%d %H:%M:%S%.f%#z"
                    } else {
                        "%Y-%m-%d %H:%M:%S%.f"
                    },
                )?
            }
        })
    }
}

impl<Tz: TimeZone> Encode<'_, Postgres> for DateTime<Tz> {
    fn encode_by_ref(&self, buf: &mut PgArgumentBuffer) -> Result<IsNull, BoxDynError> {
        Encode::<Postgres>::encode(self.naive_utc(), buf)
    }

    fn size_hint(&self) -> usize {
        mem::size_of::<i64>()
    }
}

impl<'r> Decode<'r, Postgres> for DateTime<Utc> {
    fn decode(value: PgValueRef<'r>) -> Result<Self, BoxDynError> {
        let fixed = <DateTime<FixedOffset> as Decode<Postgres>>::decode(value)?;
        Ok(Utc.from_utc_datetime(&fixed.naive_utc()))
    }
}

impl<'r> Decode<'r, Postgres> for DateTime<FixedOffset> {
    fn decode(value: PgValueRef<'r>) -> Result<Self, BoxDynError> {
        Ok(match value.format() {
            PgValueFormat::Binary => {
                let naive = <NaiveDateTime as Decode<Postgres>>::decode(value)?;
                Utc.fix().from_utc_datetime(&naive)
            }

            PgValueFormat::Text => {
                let s = value.as_str()?;
                DateTime::parse_from_str(
                    s,
                    if s.contains('+') || s.contains('-') {
                        // Contains a time-zone specifier
                        // This is given for timestamptz for some reason
                        // Postgres already guarantees this to always be UTC
                        "%Y-%m-%d %H:%M:%S%.f%#z"
                    } else {
                        "%Y-%m-%d %H:%M:%S%.f"
                    },
                )?
            }
        })
    }
}

#[inline]
fn postgres_epoch_datetime() -> NaiveDateTime {
    NaiveDate::from_ymd_opt(2000, 1, 1)
        .expect("expected 2000-01-01 to be a valid NaiveDate")
        .and_hms_opt(0, 0, 0)
        .expect("expected 2000-01-01T00:00:00 to be a valid NaiveDateTime")
}

impl Type<Postgres> for NaiveDate {
    fn type_info() -> PgTypeInfo {
        PgTypeInfo::with_name("date")
    }
}

impl PgHasArrayType for NaiveDate {
    fn array_type_info() -> PgTypeInfo {
        PgTypeInfo::array_of("date")
    }
}

impl Encode<'_, Postgres> for NaiveDate {
    fn encode_by_ref(&self, buf: &mut PgArgumentBuffer) -> Result<IsNull, BoxDynError> {
        // DATE is encoded as the days since epoch
        let days: i32 = (*self - postgres_epoch_date())
            .num_days()
            .try_into()
            .map_err(|_| {
                format!("value {self:?} would overflow binary encoding for Postgres DATE")
            })?;

        Encode::<Postgres>::encode(days, buf)
    }

    fn size_hint(&self) -> usize {
        mem::size_of::<i32>()
    }
}

impl<'r> Decode<'r, Postgres> for NaiveDate {
    fn decode(value: PgValueRef<'r>) -> Result<Self, BoxDynError> {
        Ok(match value.format() {
            PgValueFormat::Binary => {
                // DATE is encoded as the days since epoch
                let days: i32 = Decode::<Postgres>::decode(value)?;

                let days = TimeDelta::try_days(days.into())
                    .unwrap_or_else(|| {
                        unreachable!("BUG: days ({days}) as `i32` multiplied into seconds should not overflow `i64`")
                    });

                postgres_epoch_date() + days
            }

            PgValueFormat::Text => NaiveDate::parse_from_str(value.as_str()?, "%Y-%m-%d")?,
        })
    }
}

#[inline]
fn postgres_epoch_date() -> NaiveDate {
    NaiveDate::from_ymd_opt(2000, 1, 1).expect("expected 2000-01-01 to be a valid NaiveDate")
}
