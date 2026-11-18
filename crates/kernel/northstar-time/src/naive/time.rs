// Ported and adapted from chrono 0.4.45 (MIT OR Apache-2.0).
use crate::format::{
    parse, parse_and_remainder, write_hundreds, Fixed, Item, Numeric, Pad, ParseError, ParseResult,
    Parsed,
};
use crate::{expect, FixedOffset, TimeDelta};
use core::{fmt, str};

#[derive(PartialEq, Eq, Hash, PartialOrd, Ord, Copy, Clone)]
pub struct NaiveTime {
    secs: u32,
    frac: u32,
}

impl NaiveTime {
    pub const fn from_hms_opt(hour: u32, min: u32, sec: u32) -> Option<NaiveTime> {
        NaiveTime::from_hms_nano_opt(hour, min, sec, 0)
    }

    pub const fn from_hms_milli_opt(
        hour: u32,
        min: u32,
        sec: u32,
        milli: u32,
    ) -> Option<NaiveTime> {
        let nano = try_opt!(milli.checked_mul(1_000_000));
        NaiveTime::from_hms_nano_opt(hour, min, sec, nano)
    }

    pub const fn from_hms_micro_opt(
        hour: u32,
        min: u32,
        sec: u32,
        micro: u32,
    ) -> Option<NaiveTime> {
        let nano = try_opt!(micro.checked_mul(1_000));
        NaiveTime::from_hms_nano_opt(hour, min, sec, nano)
    }

    pub const fn from_hms_nano_opt(hour: u32, min: u32, sec: u32, nano: u32) -> Option<NaiveTime> {
        if (hour >= 24 || min >= 60 || sec >= 60)
            || (nano >= 1_000_000_000 && sec != 59)
            || nano >= 2_000_000_000
        {
            return None;
        }
        let secs = hour * 3600 + min * 60 + sec;
        Some(NaiveTime { secs, frac: nano })
    }

    pub const fn from_num_seconds_from_midnight_opt(secs: u32, nano: u32) -> Option<NaiveTime> {
        if secs >= 86_400 || nano >= 2_000_000_000 || (nano >= 1_000_000_000 && secs % 60 != 59) {
            return None;
        }
        Some(NaiveTime { secs, frac: nano })
    }

    pub const fn overflowing_add_signed(&self, rhs: TimeDelta) -> (NaiveTime, i64) {
        let mut secs = self.secs as i64;
        let mut frac = self.frac as i32;
        let secs_to_add = rhs.num_seconds();
        let frac_to_add = rhs.subsec_nanos();

        // Check if `self` is a leap second and adding `rhs` would escape that leap second.
        // If that is the case, update `frac` and `secs` to involve no leap second.
        // If it stays within the leap second or the second before, and only adds a fractional
        // second, just do that and return (this way the rest of the code can ignore leap seconds).
        if frac >= 1_000_000_000 {
            // check below is adjusted to not overflow an i32: `frac + frac_to_add >= 2_000_000_000`
            if secs_to_add > 0 || (frac_to_add > 0 && frac >= 2_000_000_000 - frac_to_add) {
                frac -= 1_000_000_000;
            } else if secs_to_add < 0 {
                frac -= 1_000_000_000;
                secs += 1;
            } else {
                return (
                    NaiveTime {
                        secs: self.secs,
                        frac: (frac + frac_to_add) as u32,
                    },
                    0,
                );
            }
        }

        let mut secs = secs + secs_to_add;
        frac += frac_to_add;

        if frac < 0 {
            frac += 1_000_000_000;
            secs -= 1;
        } else if frac >= 1_000_000_000 {
            frac -= 1_000_000_000;
            secs += 1;
        }

        let secs_in_day = secs.rem_euclid(86_400);
        let remaining = secs - secs_in_day;
        (
            NaiveTime {
                secs: secs_in_day as u32,
                frac: frac as u32,
            },
            remaining,
        )
    }

    pub const fn overflowing_sub_signed(&self, rhs: TimeDelta) -> (NaiveTime, i64) {
        let (time, rhs) = self.overflowing_add_signed(rhs.neg());
        (time, -rhs) // safe to negate, rhs is within +/- (2^63 / 1000)
    }

    pub const fn signed_duration_since(self, rhs: NaiveTime) -> TimeDelta {
        //     |    |    :leap|    |    |    |    |    |    |    :leap|    |
        //     |    |    :    |    |    |    |    |    |    |    :    |    |
        // ----+----+-----*---+----+----+----+----+----+----+-------*-+----+----
        //          |   `rhs` |                             |    `self`
        //          |======================================>|       |
        //          |     |  `self.secs - rhs.secs`         |`self.frac`
        //          |====>|   |                             |======>|
        //      `rhs.frac`|========================================>|
        //          |     |   |        `self - rhs`         |       |

        let mut secs = self.secs as i64 - rhs.secs as i64;
        let frac = self.frac as i64 - rhs.frac as i64;

        // `secs` may contain a leap second yet to be counted
        if self.secs > rhs.secs && rhs.frac >= 1_000_000_000 {
            secs += 1;
        } else if self.secs < rhs.secs && self.frac >= 1_000_000_000 {
            secs -= 1;
        }

        let secs_from_frac = frac.div_euclid(1_000_000_000);
        let frac = frac.rem_euclid(1_000_000_000) as u32;

        expect(
            TimeDelta::new(secs + secs_from_frac, frac),
            "must be in range",
        )
    }

    pub(crate) const fn overflowing_add_offset(&self, offset: FixedOffset) -> (NaiveTime, i32) {
        let secs = self.secs as i32 + offset.local_minus_utc();
        let days = secs.div_euclid(86_400);
        let secs = secs.rem_euclid(86_400);
        (
            NaiveTime {
                secs: secs as u32,
                frac: self.frac,
            },
            days,
        )
    }

    pub(crate) const fn overflowing_sub_offset(&self, offset: FixedOffset) -> (NaiveTime, i32) {
        let secs = self.secs as i32 - offset.local_minus_utc();
        let days = secs.div_euclid(86_400);
        let secs = secs.rem_euclid(86_400);
        (
            NaiveTime {
                secs: secs as u32,
                frac: self.frac,
            },
            days,
        )
    }

    pub(crate) fn hms(&self) -> (u32, u32, u32) {
        let sec = self.secs % 60;
        let mins = self.secs / 60;
        let min = mins % 60;
        let hour = mins / 60;
        (hour, min, sec)
    }

    pub(crate) const fn num_seconds_from_midnight(&self) -> u32 {
        self.secs
    }

    pub const fn nanosecond(&self) -> u32 {
        self.frac
    }
    pub const fn hour(&self) -> u32 {
        self.secs / 3600
    }
    pub const fn minute(&self) -> u32 {
        self.secs / 60 % 60
    }
    pub const fn second(&self) -> u32 {
        self.secs % 60
    }
    pub const MIN: Self = Self { secs: 0, frac: 0 };
    pub(crate) const MAX: Self = Self {
        secs: 86399,
        frac: 999_999_999,
    };
}
impl fmt::Debug for NaiveTime {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let (hour, min, sec) = self.hms();
        let (sec, nano) = if self.frac >= 1_000_000_000 {
            (sec + 1, self.frac - 1_000_000_000)
        } else {
            (sec, self.frac)
        };

        use core::fmt::Write;
        write_hundreds(f, hour as u8)?;
        f.write_char(':')?;
        write_hundreds(f, min as u8)?;
        f.write_char(':')?;
        write_hundreds(f, sec as u8)?;

        if nano == 0 {
            Ok(())
        } else if nano % 1_000_000 == 0 {
            write!(f, ".{:03}", nano / 1_000_000)
        } else if nano % 1_000 == 0 {
            write!(f, ".{:06}", nano / 1_000)
        } else {
            write!(f, ".{nano:09}")
        }
    }
}

impl fmt::Display for NaiveTime {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Debug::fmt(self, f)
    }
}

impl str::FromStr for NaiveTime {
    type Err = ParseError;

    fn from_str(s: &str) -> ParseResult<NaiveTime> {
        const HOUR_AND_MINUTE: &[Item<'static>] = &[
            Item::Numeric(Numeric::Hour, Pad::Zero),
            Item::Space(""),
            Item::Literal(":"),
            Item::Numeric(Numeric::Minute, Pad::Zero),
        ];
        const SECOND_AND_NANOS: &[Item<'static>] = &[
            Item::Space(""),
            Item::Literal(":"),
            Item::Numeric(Numeric::Second, Pad::Zero),
            Item::Fixed(Fixed::Nanosecond),
            Item::Space(""),
        ];
        const TRAILING_WHITESPACE: [Item<'static>; 1] = [Item::Space("")];

        let mut parsed = Parsed::new();
        let s = parse_and_remainder(&mut parsed, s, HOUR_AND_MINUTE.iter())?;
        // Seconds are optional, don't fail if parsing them doesn't succeed.
        let s = parse_and_remainder(&mut parsed, s, SECOND_AND_NANOS.iter()).unwrap_or(s);
        parse(&mut parsed, s, TRAILING_WHITESPACE.iter())?;
        parsed.to_naive_time()
    }
}

impl Default for NaiveTime {
    fn default() -> Self {
        NaiveTime::from_hms_opt(0, 0, 0).unwrap()
    }
}
