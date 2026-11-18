// Ported and adapted from chrono 0.4.45 (MIT OR Apache-2.0).
use super::{
    scan, Fixed, InternalFixed, InternalInternal, Item, Numeric, Pad, ParseError, ParseResult,
    Parsed, BAD_FORMAT, INVALID, OUT_OF_RANGE, TOO_LONG, TOO_SHORT,
};
use crate::{DateTime, FixedOffset, MappedLocalTime, NaiveDate, NaiveTime};
use core::{borrow::Borrow, str};

pub(crate) fn parse_rfc3339(mut s: &str) -> ParseResult<DateTime<FixedOffset>> {
    macro_rules! try_consume {
        ($e:expr) => {{
            let (s_, v) = $e?;
            s = s_;
            v
        }};
    }

    // an adapted RFC 3339 syntax from Section 5.6:
    //
    // date-fullyear  = 4DIGIT
    // date-month     = 2DIGIT ; 01-12
    // date-mday      = 2DIGIT ; 01-28, 01-29, 01-30, 01-31 based on month/year
    // time-hour      = 2DIGIT ; 00-23
    // time-minute    = 2DIGIT ; 00-59
    // time-second    = 2DIGIT ; 00-58, 00-59, 00-60 based on leap second rules
    // time-secfrac   = "." 1*DIGIT
    // time-numoffset = ("+" / "-") time-hour ":" time-minute
    // time-offset    = "Z" / time-numoffset
    // partial-time   = time-hour ":" time-minute ":" time-second [time-secfrac]
    // full-date      = date-fullyear "-" date-month "-" date-mday
    // full-time      = partial-time time-offset
    // date-time      = full-date "T" full-time
    //
    // some notes:
    //
    // - quoted characters can be in any mixture of lower and upper cases.
    //
    // - it may accept any number of fractional digits for seconds.
    //   for Chrono, this means that we should skip digits past first 9 digits.
    //
    // - unlike RFC 2822, the valid offset ranges from -23:59 to +23:59.
    //   note that this restriction is unique to RFC 3339 and not ISO 8601.
    //   since this is not a typical Chrono behavior, we check it earlier.
    //
    // - For readability a full-date and a full-time may be separated by a space character.

    let bytes = s.as_bytes();
    if bytes.len() < 19 {
        return Err(TOO_SHORT);
    }

    let fixed = <&[u8; 19]>::try_from(&bytes[..19]).unwrap(); // we just checked the length
    let year = digit(fixed, 0)? as u16 * 1000
        + digit(fixed, 1)? as u16 * 100
        + digit(fixed, 2)? as u16 * 10
        + digit(fixed, 3)? as u16;
    if bytes.get(4) != Some(&b'-') {
        return Err(INVALID);
    }

    let month = digit(fixed, 5)? * 10 + digit(fixed, 6)?;
    if bytes.get(7) != Some(&b'-') {
        return Err(INVALID);
    }

    let day = digit(fixed, 8)? * 10 + digit(fixed, 9)?;
    let date =
        NaiveDate::from_ymd_opt(year as i32, month as u32, day as u32).ok_or(OUT_OF_RANGE)?;

    if !matches!(bytes.get(10), Some(&b't' | &b'T' | &b' ')) {
        return Err(INVALID);
    }

    let hour = digit(fixed, 11)? * 10 + digit(fixed, 12)?;
    if bytes.get(13) != Some(&b':') {
        return Err(INVALID);
    }

    let min = digit(fixed, 14)? * 10 + digit(fixed, 15)?;
    if bytes.get(16) != Some(&b':') {
        return Err(INVALID);
    }

    let sec = digit(fixed, 17)? * 10 + digit(fixed, 18)?;
    let (sec, extra_nanos) = match sec {
        60 => (59, 1_000_000_000), // rfc3339 allows leap seconds
        _ => (sec, 0),
    };

    let nano = if bytes.get(19) == Some(&b'.') {
        let nanosecond = try_consume!(scan::nanosecond(&s[20..]));
        extra_nanos + nanosecond
    } else {
        s = &s[19..];
        extra_nanos
    };

    let time = NaiveTime::from_hms_nano_opt(hour as u32, min as u32, sec as u32, nano)
        .ok_or(OUT_OF_RANGE)?;

    // Max for the hours field is `23`, and for the minutes field `59`.
    let offset = try_consume!(scan::timezone_offset(
        s,
        |s| scan::char(s, b':'),
        true,
        false,
        true
    ));
    if !s.is_empty() {
        return Err(TOO_LONG);
    }

    let tz = FixedOffset::east_opt(offset).ok_or(OUT_OF_RANGE)?;
    Ok(match date.and_time(time).and_local_timezone(tz) {
        MappedLocalTime::Single(dt) => dt,
        // `FixedOffset::with_ymd_and_hms` doesn't return `MappedLocalTime::Ambiguous`
        // and returns `MappedLocalTime::None` on invalid data
        MappedLocalTime::Ambiguous(_, _) | MappedLocalTime::None => unreachable!(),
    })
}

fn digit(bytes: &[u8; 19], index: usize) -> ParseResult<u8> {
    match bytes[index].is_ascii_digit() {
        true => Ok(bytes[index] - b'0'),
        false => Err(INVALID),
    }
}

pub(crate) fn parse<'a, I, B>(parsed: &mut Parsed, s: &str, items: I) -> ParseResult<()>
where
    I: Iterator<Item = B>,
    B: Borrow<Item<'a>>,
{
    match parse_internal(parsed, s, items) {
        Ok("") => Ok(()),
        Ok(_) => Err(TOO_LONG), // if there are trailing chars it is an error
        Err(e) => Err(e),
    }
}

pub(crate) fn parse_and_remainder<'a, 'b, I, B>(
    parsed: &mut Parsed,
    s: &'b str,
    items: I,
) -> ParseResult<&'b str>
where
    I: Iterator<Item = B>,
    B: Borrow<Item<'a>>,
{
    parse_internal(parsed, s, items)
}
fn parse_internal<'a, 'b, I, B>(
    parsed: &mut Parsed,
    mut s: &'b str,
    items: I,
) -> Result<&'b str, ParseError>
where
    I: Iterator<Item = B>,
    B: Borrow<Item<'a>>,
{
    macro_rules! try_consume {
        ($e:expr) => {{
            let (s_, v) = $e?;
            s = s_;
            v
        }};
    }
    for item in items {
        match *item.borrow() {
            Item::Literal(prefix) => {
                if s.len() < prefix.len() {
                    return Err(TOO_SHORT);
                }
                if !s.starts_with(prefix) {
                    return Err(INVALID);
                }
                s = &s[prefix.len()..];
            }
            Item::Space(_) => {
                s = s.trim_start();
            }
            Item::Numeric(ref spec, _) => {
                type Setter = fn(&mut Parsed, i64) -> ParseResult<()>;
                let (width, signed, set): (usize, bool, Setter) = match *spec {
                    Numeric::Year => (4, true, Parsed::set_year),
                    Numeric::Month => (2, false, Parsed::set_month),
                    Numeric::Day => (2, false, Parsed::set_day),
                    Numeric::Hour => (2, false, Parsed::set_hour),
                    Numeric::Minute => (2, false, Parsed::set_minute),
                    Numeric::Second => (2, false, Parsed::set_second),
                };
                s = s.trim_start();
                let v = if signed {
                    if let Some(rest) = s.strip_prefix('-') {
                        let v = try_consume!(scan::number(rest, 1, usize::MAX));
                        0i64.checked_sub(v).ok_or(OUT_OF_RANGE)?
                    } else if let Some(rest) = s.strip_prefix('+') {
                        try_consume!(scan::number(rest, 1, usize::MAX))
                    } else {
                        try_consume!(scan::number(s, 1, width))
                    }
                } else {
                    try_consume!(scan::number(s, 1, width))
                };
                set(parsed, v)?;
            }
            Item::Fixed(ref spec) => match *spec {
                Fixed::ShortMonthName => {
                    let month0 = try_consume!(scan::short_month0(s));
                    parsed.set_month(i64::from(month0) + 1)?;
                }
                Fixed::Nanosecond => {
                    if let Some(rest) = s.strip_prefix('.') {
                        let nano = try_consume!(scan::nanosecond(rest));
                        parsed.set_nanosecond(i64::from(nano))?;
                    }
                }
                Fixed::TimezoneOffset => {
                    let offset = try_consume!(scan::timezone_offset(
                        s.trim_start(),
                        scan::colon_or_space,
                        false,
                        false,
                        true
                    ));
                    parsed.set_offset(i64::from(offset))?;
                }
                Fixed::Internal(InternalFixed {
                    val: InternalInternal::TimezoneOffsetPermissive,
                }) => {
                    let offset = try_consume!(scan::timezone_offset(
                        s.trim_start(),
                        scan::colon_or_space,
                        true,
                        true,
                        true
                    ));
                    parsed.set_offset(i64::from(offset))?;
                }
            },
            Item::Error => return Err(BAD_FORMAT),
        }
    }
    Ok(s)
}
impl str::FromStr for DateTime<FixedOffset> {
    type Err = ParseError;

    fn from_str(s: &str) -> ParseResult<DateTime<FixedOffset>> {
        let mut parsed = Parsed::new();
        let (s, _) = parse_rfc3339_relaxed(&mut parsed, s)?;
        if !s.trim_start().is_empty() {
            return Err(TOO_LONG);
        }
        parsed.to_datetime()
    }
}
fn parse_rfc3339_relaxed<'a>(parsed: &mut Parsed, mut s: &'a str) -> ParseResult<(&'a str, ())> {
    const DATE_ITEMS: &[Item<'static>] = &[
        Item::Numeric(Numeric::Year, Pad::Zero),
        Item::Space(""),
        Item::Literal("-"),
        Item::Numeric(Numeric::Month, Pad::Zero),
        Item::Space(""),
        Item::Literal("-"),
        Item::Numeric(Numeric::Day, Pad::Zero),
    ];
    const TIME_ITEMS: &[Item<'static>] = &[
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

    s = parse_internal(parsed, s, DATE_ITEMS.iter())?;

    s = match s.as_bytes().first() {
        Some(&b't' | &b'T' | &b' ') => &s[1..],
        Some(_) => return Err(INVALID),
        None => return Err(TOO_SHORT),
    };

    s = parse_internal(parsed, s, TIME_ITEMS.iter())?;
    s = s.trim_start();
    let (s, offset) = if s.len() >= 3 && "UTC".as_bytes().eq_ignore_ascii_case(&s.as_bytes()[..3]) {
        (&s[3..], 0)
    } else {
        scan::timezone_offset(s, scan::colon_or_space, true, false, true)?
    };
    parsed.set_offset(i64::from(offset))?;
    Ok((s, ()))
}
