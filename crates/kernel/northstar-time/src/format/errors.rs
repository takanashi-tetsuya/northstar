// Ported and adapted from chrono 0.4.45 (MIT OR Apache-2.0).
use core::fmt;
use std::error::Error;

#[derive(Debug, Clone, PartialEq, Eq, Copy, Hash)]
pub struct ParseError(ParseErrorKind);
impl ParseError {
    pub const fn kind(&self) -> ParseErrorKind {
        self.0
    }
}
#[allow(clippy::manual_non_exhaustive)]
#[derive(Debug, Clone, PartialEq, Eq, Copy, Hash)]
pub enum ParseErrorKind {
    OutOfRange,

    Impossible,

    NotEnough,

    Invalid,

    TooShort,

    TooLong,

    BadFormat,

    // TODO: Change this to `#[non_exhaustive]` (on the enum) with the next breaking release.
    #[doc(hidden)]
    __Nonexhaustive,
}
pub type ParseResult<T> = Result<T, ParseError>;
impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self.0 {
            ParseErrorKind::OutOfRange => write!(f, "input is out of range"),
            ParseErrorKind::Impossible => write!(f, "no possible date and time matching input"),
            ParseErrorKind::NotEnough => write!(f, "input is not enough for unique date and time"),
            ParseErrorKind::Invalid => write!(f, "input contains invalid characters"),
            ParseErrorKind::TooShort => write!(f, "premature end of input"),
            ParseErrorKind::TooLong => write!(f, "trailing input"),
            ParseErrorKind::BadFormat => write!(f, "bad or unsupported format string"),
            _ => unreachable!(),
        }
    }
}
impl Error for ParseError {
    #[allow(deprecated)]
    fn description(&self) -> &str {
        "parser error, see to_string() for details"
    }
}
pub(crate) const OUT_OF_RANGE: ParseError = ParseError(ParseErrorKind::OutOfRange);
pub(crate) const IMPOSSIBLE: ParseError = ParseError(ParseErrorKind::Impossible);
pub(crate) const NOT_ENOUGH: ParseError = ParseError(ParseErrorKind::NotEnough);
pub(crate) const INVALID: ParseError = ParseError(ParseErrorKind::Invalid);
pub(crate) const TOO_SHORT: ParseError = ParseError(ParseErrorKind::TooShort);
pub(crate) const TOO_LONG: ParseError = ParseError(ParseErrorKind::TooLong);
pub(crate) const BAD_FORMAT: ParseError = ParseError(ParseErrorKind::BadFormat);
