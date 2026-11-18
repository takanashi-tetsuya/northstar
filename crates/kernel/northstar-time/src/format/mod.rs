// Ported and adapted from chrono 0.4.45 (MIT OR Apache-2.0).
//! Restricted chrono-compatible strftime formatting and parsing.
mod errors;
mod items;
mod parse;
mod parsed;
pub(crate) mod scan;
mod write;

pub use errors::{ParseError, ParseErrorKind, ParseResult};
pub(crate) use errors::{
    BAD_FORMAT, IMPOSSIBLE, INVALID, NOT_ENOUGH, OUT_OF_RANGE, TOO_LONG, TOO_SHORT,
};
pub use items::StrftimeItems;
pub(crate) use parse::{parse, parse_and_remainder, parse_rfc3339};
pub(crate) use parsed::Parsed;
pub(crate) use write::{write_hundreds, write_rfc3339};
pub use write::{DelayedFormat, SecondsFormat};

#[derive(Copy, Clone, PartialEq, Eq, Debug, Hash)]
pub enum Pad {
    None,
    Zero,
    Space,
}
#[derive(Clone, PartialEq, Eq, Debug, Hash)]
pub enum Numeric {
    Year,
    Month,
    Day,
    Hour,
    Minute,
    Second,
}
#[derive(Clone, PartialEq, Eq, Debug, Hash)]
pub enum Fixed {
    ShortMonthName,
    Nanosecond,
    TimezoneOffset,
    Internal(InternalFixed),
}
#[derive(Clone, PartialEq, Eq, Debug, Hash)]
pub struct InternalFixed {
    val: InternalInternal,
}
#[derive(Clone, PartialEq, Eq, Debug, Hash)]
enum InternalInternal {
    TimezoneOffsetPermissive,
}
#[derive(Clone, PartialEq, Eq, Debug, Hash)]
pub enum Item<'a> {
    Literal(&'a str),
    Space(&'a str),
    Numeric(Numeric, Pad),
    Fixed(Fixed),
    Error,
}
