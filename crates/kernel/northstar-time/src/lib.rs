// Ported and adapted from chrono 0.4.45 (MIT OR Apache-2.0).
//! Chrono-compatible timestamps using `time` for all calendar conversions.
//!
//! Duration arithmetic, leap seconds, timestamp conversion, formatting, parsing,
//! and serialization are derived from chrono 0.4.45, under its MIT OR Apache-2.0
//! licence (see LICENSE-chrono.txt). Calendar storage and conversion use `time`.
//! The optional PostgreSQL codecs are adapted from SQLx 0.9.0, under its MIT OR
//! Apache-2.0 licence (see LICENSE-sqlx.txt).
//!
//! Strftime is restricted to literals, whitespace, `%%`, `%Y`, `%m`, `%d`,
//! `%e`, `%b`, `%H`, `%M`, `%S`, `%.f`, `%z`, and `%#z`.
//! Other items fail formatting with `fmt::Error` and parsing with `BadFormat`.

macro_rules! try_opt {
    ($e:expr) => {
        match $e {
            Some(v) => v,
            None => return None,
        }
    };
}

pub(crate) const fn expect<T: Copy>(opt: Option<T>, msg: &str) -> T {
    match opt {
        Some(val) => val,
        None => panic!("{}", msg),
    }
}

mod datetime;
mod delta;
pub mod format;
mod naive;
mod offset;
#[cfg(feature = "postgres")]
mod postgres;
#[cfg(feature = "serde")]
mod serde;

pub use datetime::DateTime;
pub use delta::{OutOfRangeError, TimeDelta};
pub type Duration = TimeDelta;
pub use format::{ParseError, ParseErrorKind, ParseResult, SecondsFormat};
pub use naive::{NaiveDate, NaiveDateTime, NaiveTime};
pub use offset::{FixedOffset, MappedLocalTime, Offset, TimeZone, Utc};
pub type LocalResult<T> = MappedLocalTime<T>;
