// Ported and adapted from chrono 0.4.45 (MIT OR Apache-2.0).
use super::{Fixed, Item, Numeric, Pad};
use crate::{FixedOffset, NaiveDate, NaiveDateTime, NaiveTime, Offset};
use core::borrow::Borrow;
use core::fmt::{self, Write};

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
#[allow(clippy::manual_non_exhaustive)]
pub enum SecondsFormat {
    Secs,

    Millis,

    Micros,

    Nanos,

    AutoSi,

    // Do not match against this.
    #[doc(hidden)]
    __NonExhaustive,
}

pub struct DelayedFormat<I> {
    date: Option<NaiveDate>,
    time: Option<NaiveTime>,
    off: Option<(String, FixedOffset)>,
    items: I,
}
#[derive(Debug)]
struct Locale;

impl<I: fmt::Debug> fmt::Debug for DelayedFormat<I> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DelayedFormat")
            .field("date", &self.date)
            .field("time", &self.time)
            .field("off", &self.off)
            .field("items", &self.items)
            .field("locale", &Locale)
            .finish()
    }
}
impl<'a, I: Iterator<Item = B> + Clone, B: Borrow<Item<'a>>> DelayedFormat<I> {
    pub fn new(date: Option<NaiveDate>, time: Option<NaiveTime>, items: I) -> Self {
        Self {
            date,
            time,
            off: None,
            items,
        }
    }
    pub fn new_with_offset<Off>(
        date: Option<NaiveDate>,
        time: Option<NaiveTime>,
        offset: &Off,
        items: I,
    ) -> Self
    where
        Off: Offset + fmt::Display,
    {
        Self {
            date,
            time,
            off: Some((offset.to_string(), offset.fix())),
            items,
        }
    }
    pub fn write_to(&self, w: &mut (impl Write + ?Sized)) -> fmt::Result {
        for item in self.items.clone() {
            match *item.borrow() {
                Item::Literal(s) | Item::Space(s) => w.write_str(s),
                Item::Numeric(ref spec, pad) => {
                    let value = match (spec, self.date, self.time) {
                        (Numeric::Year, Some(d), _) => i64::from(d.year()),
                        (Numeric::Month, Some(d), _) => i64::from(d.month()),
                        (Numeric::Day, Some(d), _) => i64::from(d.day()),
                        (Numeric::Hour, _, Some(t)) => i64::from(t.hour()),
                        (Numeric::Minute, _, Some(t)) => i64::from(t.minute()),
                        (Numeric::Second, _, Some(t)) => {
                            i64::from(t.second() + t.nanosecond() / 1_000_000_000)
                        }
                        _ => return Err(fmt::Error),
                    };
                    let year = *spec == Numeric::Year;
                    let width = if year { 4 } else { 2 };
                    let sign = year && !(0..10_000).contains(&value);
                    write_number(w, value, width, pad, sign)
                }
                Item::Fixed(Fixed::ShortMonthName) => {
                    const MONTHS: [&str; 12] = [
                        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct",
                        "Nov", "Dec",
                    ];
                    let d = self.date.ok_or(fmt::Error)?;
                    w.write_str(MONTHS[(d.month() - 1) as usize])
                }
                Item::Fixed(Fixed::Nanosecond) => {
                    write_fraction(w, self.time.ok_or(fmt::Error)?.nanosecond() % 1_000_000_000)
                }
                Item::Fixed(Fixed::TimezoneOffset) => {
                    write_offset(w, self.off.as_ref().ok_or(fmt::Error)?.1, false, false)
                }
                // Chrono's %#z is parse-only.
                Item::Fixed(Fixed::Internal(_)) | Item::Error => Err(fmt::Error),
            }?;
        }
        Ok(())
    }
}
impl<'a, I: Iterator<Item = B> + Clone, B: Borrow<Item<'a>>> fmt::Display for DelayedFormat<I> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut result = String::new();
        self.write_to(&mut result)?;
        f.pad(&result)
    }
}
fn write_number(
    w: &mut (impl Write + ?Sized),
    value: i64,
    width: usize,
    pad: Pad,
    sign: bool,
) -> fmt::Result {
    if sign {
        match pad {
            Pad::None => write!(w, "{value:+}"),
            Pad::Zero => write!(w, "{:+01$}", value, width + 1),
            Pad::Space => write!(w, "{:+1$}", value, width + 1),
        }
    } else {
        match pad {
            Pad::None => write!(w, "{value}"),
            Pad::Zero => write!(w, "{value:0width$}"),
            Pad::Space => write!(w, "{value:width$}"),
        }
    }
}
fn write_fraction(w: &mut (impl Write + ?Sized), nano: u32) -> fmt::Result {
    if nano == 0 {
        Ok(())
    } else if nano.is_multiple_of(1_000_000) {
        write!(w, ".{:03}", nano / 1_000_000)
    } else if nano.is_multiple_of(1_000) {
        write!(w, ".{:06}", nano / 1_000)
    } else {
        write!(w, ".{nano:09}")
    }
}
fn write_offset(
    w: &mut (impl Write + ?Sized),
    off: FixedOffset,
    colon: bool,
    use_z: bool,
) -> fmt::Result {
    let off = off.local_minus_utc();
    if use_z && off == 0 {
        return w.write_char('Z');
    }
    let (sign, off) = if off < 0 { ('-', -off) } else { ('+', off) };
    // Preserve chrono's rounding, including +24:00 for +23:59:59.
    let minutes = (off + 30) / 60;
    write!(
        w,
        "{sign}{:02}{}{:02}",
        minutes / 60,
        if colon { ":" } else { "" },
        minutes % 60
    )
}
pub(crate) fn write_hundreds(w: &mut (impl Write + ?Sized), n: u8) -> fmt::Result {
    if n >= 100 {
        return Err(fmt::Error);
    }

    let tens = b'0' + n / 10;
    let ones = b'0' + n % 10;
    w.write_char(tens as char)?;
    w.write_char(ones as char)
}
pub(crate) fn write_rfc3339(
    w: &mut (impl Write + ?Sized),
    dt: NaiveDateTime,
    off: FixedOffset,
    secform: SecondsFormat,
    use_z: bool,
) -> fmt::Result {
    let year = dt.date().year();
    if (0..=9999).contains(&year) {
        write_hundreds(w, (year / 100) as u8)?;
        write_hundreds(w, (year % 100) as u8)?;
    } else {
        // ISO 8601 requires the explicit sign for out-of-range years
        write!(w, "{year:+05}")?;
    }
    w.write_char('-')?;
    write_hundreds(w, dt.date().month() as u8)?;
    w.write_char('-')?;
    write_hundreds(w, dt.date().day() as u8)?;

    w.write_char('T')?;

    let (hour, min, mut sec) = dt.time().hms();
    let mut nano = dt.nanosecond();
    if nano >= 1_000_000_000 {
        sec += 1;
        nano -= 1_000_000_000;
    }
    write_hundreds(w, hour as u8)?;
    w.write_char(':')?;
    write_hundreds(w, min as u8)?;
    w.write_char(':')?;
    write_hundreds(w, sec as u8)?;

    match secform {
        SecondsFormat::Secs => {}
        SecondsFormat::Millis => write!(w, ".{:03}", nano / 1_000_000)?,
        SecondsFormat::Micros => write!(w, ".{:06}", nano / 1000)?,
        SecondsFormat::Nanos => write!(w, ".{nano:09}")?,
        SecondsFormat::AutoSi => {
            if nano == 0 {
            } else if nano.is_multiple_of(1_000_000) {
                write!(w, ".{:03}", nano / 1_000_000)?
            } else if nano.is_multiple_of(1_000) {
                write!(w, ".{:06}", nano / 1_000)?
            } else {
                write!(w, ".{nano:09}")?
            }
        }
        SecondsFormat::__NonExhaustive => unreachable!(),
    };

    write_offset(w, off, true, use_z)
}
