use super::{Case, Span, Stamp};

const DELTA_CONSTRUCTORS: &[&str] = &[
    "new",
    "weeks",
    "try_weeks",
    "days",
    "try_days",
    "hours",
    "try_hours",
    "minutes",
    "try_minutes",
    "seconds",
    "try_seconds",
    "milliseconds",
    "try_milliseconds",
    "microseconds",
    "nanoseconds",
    "from_std",
];
const DELTA_OPS: &[&str] = &[
    "accessors",
    "abs",
    "neg",
    "checked_add",
    "checked_sub",
    "checked_mul",
    "checked_div",
    "add",
    "sub",
    "add_assign",
    "sub_assign",
    "mul",
    "div",
    "sum",
    "sum_ref",
    "compare",
    "debug",
    "display",
    "to_std",
];
const DATE_OPS: &[&str] = &[
    "accessors",
    "and_hms",
    "and_milli",
    "and_micro",
    "and_nano",
    "and_time",
    "checked_add",
    "checked_sub",
    "add",
    "sub",
    "add_assign",
    "sub_assign",
    "since",
    "difference",
    "compare",
    "display",
    "debug",
];
const TIME_OPS: &[&str] = &[
    "accessors",
    "overflowing_add",
    "since",
    "compare",
    "display",
    "debug",
];
const NAIVE_OPS: &[&str] = &[
    "new",
    "accessors",
    "checked_add",
    "checked_sub",
    "since",
    "difference",
    "add",
    "sub",
    "add_assign",
    "sub_assign",
    "compare",
    "display",
    "debug",
];
const TIMESTAMP_OPS: &[&str] = &[
    "seconds",
    "millis",
    "micros",
    "nanos",
    "tz_seconds",
    "tz_millis",
    "tz_micros",
    "tz_nanos",
    "utc_seconds",
    "utc_millis",
    "utc_micros",
    "utc_nanos",
];
const ZONED_OPS: &[&str] = &[
    "from_naive",
    "timestamps",
    "naive_utc",
    "naive_local",
    "date_naive",
    "time",
    "offset",
    "timezone",
    "with_timezone",
    "tz_from_local",
    "tz_from_utc",
    "fixed_offset",
    "to_utc",
    "from_utc",
    "into_utc",
    "since",
    "difference",
    "checked_add",
    "checked_sub",
    "add",
    "sub",
    "add_assign",
    "sub_assign",
    "add_std",
    "sub_std",
    "add_assign_std",
    "sub_assign_std",
    "compare",
    "rfc3339",
    "rfc3339_opts",
    "format",
    "format_debug",
    "seconds_format_debug",
    "display",
    "debug",
    "utc_display",
    "utc_debug",
    "utc_format",
];
const OFFSET_OPS: &[&str] = &[
    "east",
    "west",
    "utc",
    "from_offset",
    "from_utc_date",
    "from_utc_datetime",
    "from_local_date",
    "from_local_datetime",
    "from_utc",
    "from_local",
    "with_ymd",
    "utc_methods",
];
const FRACTIONS: &[u32] = &[
    0,
    1,
    999,
    1_000,
    999_999,
    1_000_000,
    123_456_789,
    999_999_999,
    1_000_000_000,
    1_000_000_001,
    1_123_456_789,
    1_999_999_999,
    2_000_000_000,
    u32::MAX,
];
const OFFSETS: &[i32] = &[
    0,
    1,
    -1,
    60,
    -60,
    14 * 3600,
    -14 * 3600,
    86_399,
    -86_399,
    86_400,
    -86_400,
    i32::MIN,
    i32::MAX,
];
const FORMATS: &[&str] = &[
    "%Y-%m-%dT%H:%M:%SZ",
    "%b %e %H:%M:%S %Y GMT",
    "%Y-%m-%d %H:%M:%S%.f%#z",
    "%Y-%m-%d %H:%M:%S%.f",
    "%Y-%m-%d",
    "%Y %m %d %e %b %H %M %S %.f %z",
    "%%",
    "%Q",
    "%",
    "",
];
const INPUTS: &[&str] = &[
    "1970-01-01T00:00:00Z",
    "1969-12-31T23:59:59.999999999Z",
    "1999-12-31T23:59:59Z",
    "2000-01-01T00:00:00Z",
    "2016-12-31T23:59:60Z",
    "2016-12-31T23:59:60.123456789Z",
    "2016-12-31T23:59:59Z",
    "2017-01-01T00:00:00Z",
    "2026-09-02T12:00:00+14:00",
    "2026-09-02t12:00:00z",
    "2026-09-02 12:00:00-00:00",
    "2026-09-02_12:00:00Z",
    "2026-09-02T12:00:00+0000",
    "2026-09-02T12:00:00+00:00:01",
    "2026-09-02T12:00Z",
    "2026-09-02T12:00:00",
    "2026-09-02T12:00:00Zjunk",
    "2025-02-29T00:00:00Z",
    "2026-01-01T24:00:00Z",
    "2026-01-01T12:34:60Z",
    "2026-01-01T23:58:60Z",
    "Sep  2 12:00:00 2026 GMT",
    "sEP 2 12:00:60.123 2026 GMT",
    "2026-09-02 12:00:00.123+00",
    "2026-09-02 12:00:00.123",
    "2026-09-02",
    "2025-02-29",
    "0000-01-01",
    "9999-12-31",
    "+10000-01-01",
    "-0001-01-01",
    "-262143-01-01",
    "+262142-12-31",
    "-262144-12-31",
    "+262143-01-01",
    "00:00",
    "23:59:60.999999999",
    "0:0:0",
    " 2026 - 9 - 2 T 12 : 00 : 00 UTC ",
    "2026-09-02T12:00:00−00:00",
    "",
    "z",
    "2026",
    "\t\n",
    "+0000",
    "-00:00",
    "+00:01",
    "-23:59",
    "+24:00",
    "+01:00:01",
    "+01 23trailing",
    "−05:30",
    "+00",
];
const PARSERS: &[&str] = &["rfc3339", "utc", "fixed", "date", "time", "naive", "offset"];

struct SplitMix64(u64);
impl SplitMix64 {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }
    fn index(&mut self, len: usize) -> usize {
        (self.next() % len as u64) as usize
    }
    fn pick<T: Copy>(&mut self, values: &[T]) -> T {
        values[self.index(values.len())]
    }
}
fn span(seconds: i64, nanos: u32) -> Span {
    Span { seconds, nanos }
}
fn stamp(seconds: i64, nanos: u32, offset: i32) -> Stamp {
    Stamp {
        seconds,
        nanos,
        offset,
    }
}
fn zoned(
    op: &str,
    a: Stamp,
    b: Stamp,
    delta: Span,
    format: &str,
    precision: u8,
    use_z: bool,
) -> Case {
    Case::Zoned {
        op: op.to_string(),
        a,
        b,
        delta,
        format: format.to_string(),
        precision,
        use_z,
    }
}
fn parser_cases(cases: &mut Vec<Case>, input: &str) {
    for target in PARSERS {
        cases.push(Case::Parse {
            target: (*target).to_string(),
            input: input.to_string(),
            format: None,
        });
    }
    for target in ["date", "naive", "fixed"] {
        for fmt in &FORMATS[1..5] {
            cases.push(Case::Parse {
                target: target.to_string(),
                input: input.to_string(),
                format: Some((*fmt).to_string()),
            });
        }
    }
}
fn mutate(input: &str, rng: &mut SplitMix64) -> String {
    const ALPHABET: &[u8] =
        b"0123456789-+:.,TtZz _\t\nABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
    let mut chars: Vec<char> = input.chars().collect();
    let at = rng.index(chars.len() + 1);
    let replacement = char::from(rng.pick(ALPHABET));
    match rng.index(7) {
        0 => chars.insert(at, replacement),
        1 if at < chars.len() => {
            chars.remove(at);
        }
        2 if at < chars.len() => {
            chars[at] = replacement;
        }
        3 => chars.truncate(at),
        4 => return input.to_ascii_lowercase(),
        5 => return input.to_ascii_uppercase(),
        _ => chars.push(replacement),
    }
    chars.into_iter().collect()
}
fn digits(rng: &mut SplitMix64, count: impl FnOnce(&mut SplitMix64) -> usize) -> String {
    let count = count(rng);
    (0..count)
        .map(|_| char::from(b'0' + rng.index(10) as u8))
        .collect()
}
/// A string in one of the textual shapes the parsers accept, with fields that
/// are mostly in range, then zero to two random mutations.
fn shaped_input(rng: &mut SplitMix64) -> String {
    let shape = rng.index(9);
    shaped_input_of(rng, shape)
}
/// Shapes: 0 RFC 3339, 2 PostgreSQL TIMESTAMPTZ text, 3 OpenSSL, 4 date, 5 time,
/// 6 date and time without offset, 7 offset, 8 `NaiveDateTime`'s own form; 1 is
/// RFC 3339 too.
fn shaped_input_of(rng: &mut SplitMix64, shape: usize) -> String {
    const MONTHS: &[&str] = &[
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];
    let year: i64 = match rng.index(8) {
        0 => rng.pick(&[0, 1, 9999, 10_000, -1, -262_144, 262_143, 262_144, -262_145]),
        1 => (rng.next() % 10_000) as i64,
        _ => 1900 + (rng.next() % 200) as i64,
    };
    let month = if rng.index(12) == 0 {
        rng.index(14)
    } else {
        1 + rng.index(12)
    };
    let day = if rng.index(12) == 0 {
        rng.index(33)
    } else {
        1 + rng.index(28) + rng.index(4)
    };
    let hour = if rng.index(16) == 0 {
        24
    } else {
        rng.index(24)
    };
    let minute = if rng.index(16) == 0 {
        60
    } else {
        rng.index(60)
    };
    let second = match rng.index(16) {
        0 => 60,
        1 => 61,
        _ => rng.index(60),
    };
    let fraction = match rng.index(4) {
        0 => String::new(),
        1 => format!(".{}", digits(rng, |rng| 1 + rng.index(12))),
        _ => format!(".{}", digits(rng, |rng| rng.pick(&[3, 6, 9]))),
    };
    let sign = if rng.next() & 1 == 0 { '+' } else { '-' };
    let (oh, om) = (rng.index(26), rng.pick(&[0, 0, 30, 45, 59, 60]));
    let year_text = if (0..=9999).contains(&year) {
        format!("{year:04}")
    } else {
        format!("{year:+05}")
    };
    let date = format!("{year_text}-{month:02}-{day:02}");
    let clock = format!("{hour:02}:{minute:02}:{second:02}");
    let text = match shape {
        0 | 1 => {
            let separator = rng.pick(&['T', 't', ' ', '_']);
            let offset = match rng.index(8) {
                0 | 1 => "Z".to_string(),
                2 => "z".to_string(),
                3 => format!("{sign}{oh:02}{om:02}"),
                4 => format!("{sign}{oh:02}"),
                5 => "-00:00".to_string(),
                _ => format!("{sign}{oh:02}:{om:02}"),
            };
            format!("{date}{separator}{clock}{fraction}{offset}")
        }
        2 => {
            let micros = if rng.next() & 1 == 0 {
                String::new()
            } else {
                format!(".{}", digits(rng, |rng| 1 + rng.index(6)))
            };
            let offset = if rng.next() & 1 == 0 {
                format!("{sign}{oh:02}")
            } else {
                format!("{sign}{oh:02}:{om:02}")
            };
            let era = if rng.index(8) == 0 { " BC" } else { "" };
            format!("{date} {clock}{micros}{offset}{era}")
        }
        3 => {
            let name = MONTHS[(month + 11) % 12];
            let name = match rng.index(4) {
                0 => name.to_ascii_uppercase(),
                1 => name.to_ascii_lowercase(),
                _ => name.to_string(),
            };
            let day = match rng.index(3) {
                0 => format!("{day:>2}"),
                1 => format!("{day:02}"),
                _ => day.to_string(),
            };
            format!("{name} {day} {clock} {year} GMT")
        }
        4 => date,
        5 => format!("{clock}{fraction}"),
        6 => format!("{date} {clock}{fraction}"),
        8 => format!("{date}T{clock}{fraction}"),
        _ => match rng.index(3) {
            0 => format!("{sign}{oh:02}{om:02}"),
            1 => format!("{sign}{oh:02}"),
            _ => format!("{sign}{oh:02}:{om:02}"),
        },
    };
    let mut text = text;
    let mutations = match rng.index(10) {
        0..=4 => 0,
        5..=7 => 1,
        _ => 2,
    };
    for _ in 0..mutations {
        text = mutate(&text, rng);
    }
    text
}
fn edges() -> Vec<Case> {
    let mut cases = vec![Case::Constants];
    let minimum = northstar_time::DateTime::<northstar_time::Utc>::MIN_UTC.timestamp();
    let maximum = northstar_time::DateTime::<northstar_time::Utc>::MAX_UTC.timestamp();
    let mut integers = vec![
        i64::MIN,
        -i64::MAX,
        i64::MAX,
        -1_000_000_000,
        -1_000_000,
        -1000,
        -1,
        0,
        1,
        1000,
        1_000_000,
        1_000_000_000,
        946_684_799,
        946_684_800,
        1_483_228_799,
        1_483_228_800,
        minimum - 1,
        minimum,
        maximum,
        maximum + 1,
    ];
    // Include both sides of the duration limit for every scaled constructor.
    for scale in [1, 60, 3600, 86_400, 604_800] {
        let bound = (i64::MAX / 1000) / scale;
        for value in [bound - 1, bound, bound + 1, -bound - 1, -bound, -bound + 1] {
            integers.push(value);
        }
    }
    for &value in &integers {
        for &op in DELTA_CONSTRUCTORS {
            cases.push(Case::Delta {
                op: op.to_string(),
                a: span(value, 0),
                b: span(1, 0),
                factor: 2,
            });
        }
        for &op in TIMESTAMP_OPS {
            cases.push(Case::Timestamp {
                op: op.to_string(),
                value,
                nanos: 0,
                offset: 0,
            });
        }
    }
    let spans = [
        span(-i64::MAX / 1000 - 1, 193_000_000),
        span(i64::MAX / 1000, 807_000_000),
        span(-1, 999_999_999),
        span(-1, 999_999_000),
        span(-1, 999_000_000),
        span(-1, 0),
        span(0, 0),
        span(0, 1),
        span(0, 1000),
        span(0, 1_000_000),
        span(1, 0),
    ];
    for &a in &spans {
        for &op in DELTA_OPS {
            let factors: &[i32] = if matches!(op, "checked_mul" | "checked_div" | "mul" | "div") {
                &[i32::MIN, -2, -1, 0, 1, 2, i32::MAX]
            } else {
                &[1]
            };
            for &factor in factors {
                cases.push(Case::Delta {
                    op: op.to_string(),
                    a,
                    b: span(1, 1),
                    factor,
                });
            }
        }
    }
    for (seconds, nanos) in [
        (-i64::MAX / 1000 - 1, 192_999_999),
        (-i64::MAX / 1000 - 1, 193_000_000),
        (-i64::MAX / 1000 - 1, 193_000_001),
        (i64::MAX / 1000, 806_999_999),
        (i64::MAX / 1000, 807_000_000),
        (i64::MAX / 1000, 807_000_001),
    ] {
        cases.push(Case::Delta {
            op: "new".to_string(),
            a: span(seconds, nanos),
            b: span(0, 0),
            factor: 1,
        });
    }
    for &nanos in FRACTIONS {
        for seconds in [-1, 0, 59, minimum, maximum, 1_483_228_799] {
            cases.push(Case::Delta {
                op: "new".to_string(),
                a: span(seconds, nanos),
                b: span(0, 0),
                factor: 1,
            });
            cases.push(Case::Timestamp {
                op: "seconds".to_string(),
                value: seconds,
                nanos,
                offset: 0,
            });
        }
        for &hms in &[
            [0, 0, 0],
            [23, 59, 59],
            [0, 0, 59],
            [12, 34, 59],
            [24, 0, 0],
            [23, 59, 60],
            [23, 60, 0],
        ] {
            for op in ["hms", "milli", "micro", "nano", "midnight"] {
                cases.push(Case::Time {
                    op: op.to_string(),
                    hmsn: [hms[0], hms[1], hms[2], i64::from(nanos)],
                    other: [hms[0] * 3600 + hms[1] * 60 + hms[2], i64::from(nanos)],
                    delta: span(0, 0),
                });
            }
        }
    }
    for year in [
        -262_144, -262_143, -1, 0, 1969, 1970, 1999, 2000, 2025, 9999, 10_000, 262_142, 262_143,
    ] {
        for (month, day) in [(1, 1), (2, 28), (2, 29), (12, 31), (0, 1), (13, 1), (1, 32)] {
            cases.push(Case::Date {
                op: "from_ymd".to_string(),
                ymd: [year, month, day],
                hmsn: [0, 0, 0, 0],
                other_days: 719_163,
                delta: span(0, 0),
            });
        }
    }
    for ymd in [
        [-262_143, 1, 1],
        [262_142, 12, 31],
        [0, 1, 1],
        [-1, 12, 31],
        [9999, 12, 31],
        [10_000, 1, 1],
        [1969, 12, 31],
        [1970, 1, 1],
        [1999, 12, 31],
        [2000, 1, 1],
    ] {
        for &op in DATE_OPS {
            for &d in &spans[2..] {
                cases.push(Case::Date {
                    op: op.to_string(),
                    ymd,
                    hmsn: [23, 59, 59, 123_456_789],
                    other_days: 719_163,
                    delta: d,
                });
            }
        }
    }
    for ymd in [
        [-262_144, 12, 31],
        [-262_143, 1, 1],
        [262_142, 12, 31],
        [262_143, 1, 1],
        [0, 1, 1],
        [2025, 2, 29],
        [2000, 2, 29],
    ] {
        for hms in [[0, 0, 0], [23, 59, 59], [23, 59, 60], [24, 0, 0]] {
            for offset in [0, -1, 1, -86_399, 86_399] {
                for utc in [false, true] {
                    cases.push(Case::Local {
                        offset,
                        ymd,
                        hms,
                        utc,
                    });
                }
            }
        }
    }
    for ymd in [[-262_143, 1, 1], [262_142, 12, 31], [2000, 1, 1]] {
        for op in [
            "checked_add",
            "checked_sub",
            "add",
            "sub",
            "add_assign",
            "sub_assign",
        ] {
            for delta in [span(-86_400, 0), span(86_400, 0), spans[0], spans[1]] {
                cases.push(Case::Date {
                    op: op.to_string(),
                    ymd,
                    hmsn: [0, 0, 0, 0],
                    other_days: 719_163,
                    delta,
                });
            }
        }
    }
    let min_days = northstar_time::NaiveDate::MIN
        .signed_duration_since(northstar_time::NaiveDate::default())
        .num_days()
        + 719_163;
    let max_days = northstar_time::NaiveDate::MAX
        .signed_duration_since(northstar_time::NaiveDate::default())
        .num_days()
        + 719_163;
    for days in [
        i32::MIN,
        i32::MAX,
        (min_days - 1) as i32,
        min_days as i32,
        max_days as i32,
        (max_days + 1) as i32,
        -1,
        0,
        1,
        719_163,
    ] {
        cases.push(Case::Date {
            op: "from_ce".to_string(),
            ymd: [1970, 1, 1],
            hmsn: [0, 0, 0, 0],
            other_days: days,
            delta: span(0, 0),
        });
    }
    for &fraction in &FRACTIONS[..12] {
        let hmsn = [23, 59, 59, i64::from(fraction)];
        for &op in TIME_OPS {
            let durations: &[Span] = if op == "overflowing_add" {
                &spans
            } else {
                &spans[6..7]
            };
            for &d in durations {
                for other_seconds in [0, 86_398, 86_399] {
                    cases.push(Case::Time {
                        op: op.to_string(),
                        hmsn,
                        other: [other_seconds, 0],
                        delta: d,
                    });
                }
            }
        }
    }
    for &fraction in &FRACTIONS[8..12] {
        for (hmsn, other) in [
            ([1, 0, 0, 0], [3599, i64::from(fraction)]),
            ([0, 59, 59, i64::from(fraction)], [3600, 0]),
            ([23, 59, 59, 0], [86_399, i64::from(fraction)]),
        ] {
            cases.push(Case::Time {
                op: "since".to_string(),
                hmsn,
                other,
                delta: span(0, 0),
            });
        }
    }
    let mut stamps = vec![
        stamp(minimum, 0, 0),
        stamp(maximum, 999_999_999, 0),
        stamp(-1, 0, 0),
        stamp(0, 0, 0),
        stamp(1, 0, 0),
        stamp(946_684_799, 999_999_999, 0),
        stamp(946_684_800, 0, 0),
    ];
    for &nanos in &FRACTIONS[..12] {
        stamps.push(stamp(1_483_228_799, nanos, 0));
    }
    let neighbour = stamp(1_483_228_800, 0, 0);
    for &a in &stamps {
        for &op in NAIVE_OPS {
            for &d in &spans[2..] {
                cases.push(Case::Naive {
                    op: op.to_string(),
                    a,
                    b: neighbour,
                    delta: d,
                });
            }
        }
        for &off in &OFFSETS[..9] {
            let a = Stamp { offset: off, ..a };
            for &op in ZONED_OPS {
                // Keep every operation at each offset and range edge, while
                // reserving some corpus space for seeded parser mutations.
                if !matches!(a.nanos, 0 | 1 | 999_999_999 | 1_000_000_000 | 1_999_999_999)
                    && !matches!(op, "time" | "timestamps" | "compare" | "rfc3339")
                {
                    continue;
                }
                cases.push(zoned(op, a, neighbour, span(0, 1), FORMATS[0], 4, false));
            }
            for precision in 0..=5 {
                for use_z in [false, true] {
                    cases.push(zoned(
                        "rfc3339_opts",
                        a,
                        neighbour,
                        span(0, 0),
                        FORMATS[0],
                        precision,
                        use_z,
                    ));
                }
            }
            for &format in FORMATS {
                cases.push(zoned("format", a, neighbour, span(0, 0), format, 4, false));
            }
            for target in ["utc", "fixed", "date", "time", "naive"] {
                cases.push(Case::Serde {
                    target: target.to_string(),
                    input: None,
                    stamp: a,
                });
            }
            for target in ["utc", "fixed", "date", "naive"] {
                cases.push(Case::Postgres {
                    target: target.to_string(),
                    stamp: a,
                });
            }
        }
    }
    // Compare the leap second with each neighbour in both directions.
    for &nanos in &FRACTIONS[8..12] {
        let leap = stamp(1_483_228_799, nanos, 0);
        for other in [stamp(1_483_228_799, 0, 0), neighbour] {
            for (a, b) in [(leap, other), (other, leap)] {
                for op in ["since", "difference", "compare"] {
                    cases.push(zoned(op, a, b, span(0, 0), FORMATS[0], 4, false));
                    cases.push(Case::Naive {
                        op: op.to_string(),
                        a,
                        b,
                        delta: span(0, 0),
                    });
                }
            }
        }
    }
    for &value in OFFSETS {
        for &op in OFFSET_OPS {
            cases.push(Case::Offset {
                op: op.to_string(),
                value,
            });
        }
    }
    for op in ["single", "earliest", "latest", "map", "unwrap", "debug"] {
        for variant in 0..3 {
            cases.push(Case::Mapping {
                op: op.to_string(),
                variant,
                a: -1,
                b: 1,
            });
        }
    }
    for precision in 0..=5 {
        cases.push(zoned(
            "seconds_format_debug",
            stamp(0, 0, 0),
            neighbour,
            span(0, 0),
            FORMATS[0],
            precision,
            false,
        ));
    }
    for &input in INPUTS {
        parser_cases(&mut cases, input);
    }
    for digits in 1..=12 {
        let fraction = &"123456789012"[..digits];
        for second in ["59", "60"] {
            parser_cases(
                &mut cases,
                &format!("2016-12-31T23:59:{second}.{fraction}Z"),
            );
        }
    }
    for target in ["utc", "fixed", "date", "time", "naive"] {
        for input in [
            "null",
            "0",
            "true",
            "[]",
            "{}",
            "\"\"",
            "\"2025-02-29\"",
            "\"2016-12-31T23:59:60Z\"",
            "\"23:59:60.1\"",
            "\"2026-09-02\"",
            "\"2026-09-02T12:00:00\"",
        ] {
            cases.push(Case::Serde {
                target: target.to_string(),
                input: Some(input.to_string()),
                stamp: stamp(0, 0, 0),
            });
        }
    }
    for seconds in [-1, 0, 1, 946_684_800, 1_483_228_799] {
        for &nanos in &FRACTIONS[..8] {
            for op in ["from", "into"] {
                cases.push(Case::System {
                    op: op.to_string(),
                    seconds,
                    nanos,
                });
            }
        }
    }
    cases
}
fn random_case(rng: &mut SplitMix64) -> Case {
    let seconds = if rng.next() & 1 == 0 {
        rng.next() as i64
    } else {
        (rng.next() % 20_000_000_000) as i64 - 10_000_000_000
    };
    let nanos = rng.pick(&FRACTIONS[..8]);
    let a = stamp(
        (rng.next() % 20_000_000_000) as i64 - 10_000_000_000,
        nanos,
        rng.pick(&OFFSETS[..9]),
    );
    let b = stamp(
        a.seconds.wrapping_add((rng.next() % 1000) as i64 - 500),
        rng.pick(&FRACTIONS[..8]),
        rng.pick(&OFFSETS[..9]),
    );
    let d = span(
        (rng.next() % 200_000) as i64 - 100_000,
        rng.pick(&FRACTIONS[..8]),
    );
    match rng.index(16) {
        0 => Case::Delta {
            op: rng.pick(DELTA_CONSTRUCTORS).to_string(),
            a: span(seconds, rng.pick(FRACTIONS)),
            b: d,
            factor: rng.next() as i32,
        },
        1 => Case::Delta {
            op: rng.pick(DELTA_OPS).to_string(),
            a: d,
            b: span(
                (rng.next() % 200_000) as i64 - 100_000,
                rng.pick(&FRACTIONS[..8]),
            ),
            factor: rng.pick(&[i32::MIN, -2, -1, 0, 1, 2, i32::MAX]),
        },
        2 => Case::Timestamp {
            op: rng.pick(TIMESTAMP_OPS).to_string(),
            value: seconds,
            nanos: rng.pick(FRACTIONS),
            offset: a.offset,
        },
        3 => Case::Date {
            op: "from_ymd".to_string(),
            ymd: [
                (rng.next() % 600_000) as i64 - 300_000,
                (rng.next() % 15) as i64,
                (rng.next() % 35) as i64,
            ],
            hmsn: [0, 0, 0, 0],
            other_days: rng.next() as i32,
            delta: d,
        },
        4 => Case::Time {
            op: rng
                .pick(&["hms", "milli", "micro", "nano", "midnight"])
                .to_string(),
            hmsn: [
                (rng.next() % 26) as i64,
                (rng.next() % 62) as i64,
                (rng.next() % 62) as i64,
                i64::from(rng.pick(FRACTIONS)),
            ],
            other: [(rng.next() % 90_000) as i64, i64::from(nanos)],
            delta: d,
        },
        5 => Case::Naive {
            op: rng.pick(NAIVE_OPS).to_string(),
            a,
            b,
            delta: d,
        },
        6 => zoned(
            rng.pick(ZONED_OPS),
            a,
            b,
            d,
            rng.pick(FORMATS),
            rng.index(6) as u8,
            rng.next() & 1 != 0,
        ),
        7 | 8 | 13 | 14 | 15 => {
            let input = if rng.next() & 1 == 0 {
                mutate(rng.pick(INPUTS), rng)
            } else {
                shaped_input(rng)
            };
            let target = rng.pick(PARSERS).to_string();
            let format =
                if matches!(target.as_str(), "date" | "naive" | "fixed") && rng.next() & 1 != 0 {
                    Some(rng.pick(&FORMATS[1..]).to_string())
                } else {
                    None
                };
            Case::Parse {
                target,
                input,
                format,
            }
        }
        9 => {
            let target = rng
                .pick(&["utc", "fixed", "date", "time", "naive"])
                .to_string();
            let input = if rng.next() & 1 == 0 {
                None
            } else {
                Some(serde_json::Value::String(shaped_input(rng)).to_string())
            };
            Case::Serde {
                target,
                input,
                stamp: a,
            }
        }
        10 => Case::Postgres {
            target: rng.pick(&["utc", "fixed", "date", "naive"]).to_string(),
            stamp: a,
        },
        11 => Case::Offset {
            op: rng.pick(OFFSET_OPS).to_string(),
            value: rng.pick(OFFSETS),
        },
        _ => Case::Mapping {
            op: rng
                .pick(&["single", "earliest", "latest", "map", "unwrap", "debug"])
                .to_string(),
            variant: rng.index(3) as u8,
            a: seconds,
            b: b.seconds,
        },
    }
}
pub fn corpus(seed: u64, count: usize) -> Vec<Case> {
    let mut cases = edges();
    // Keep the complete fixed edge corpus even when a smaller count is requested.
    let mut rng = SplitMix64(seed);
    while cases.len() < count {
        cases.push(random_case(&mut rng));
    }
    cases
}
/// A parser or serde-input case over a shaped input, with every parser target and format reachable.
fn shaped_parse_case(rng: &mut SplitMix64) -> Case {
    let input = shaped_input(rng);
    if rng.index(5) == 0 {
        return Case::Serde {
            target: rng
                .pick(&["utc", "fixed", "date", "time", "naive"])
                .to_string(),
            input: Some(serde_json::Value::String(input).to_string()),
            stamp: stamp(0, 0, 0),
        };
    }
    let target = rng.pick(PARSERS).to_string();
    let format = if matches!(target.as_str(), "date" | "naive" | "fixed") && rng.next() & 1 != 0 {
        Some(rng.pick(&FORMATS[1..5]).to_string())
    } else {
        None
    };
    // Half of the inputs take the shape the chosen parser expects.
    let input = if rng.next() & 1 == 0 {
        input
    } else {
        let shape = match (target.as_str(), format.as_deref()) {
            (_, Some("%b %e %H:%M:%S %Y GMT")) => 3,
            (_, Some("%Y-%m-%d %H:%M:%S%.f%#z")) => 2,
            (_, Some("%Y-%m-%d %H:%M:%S%.f")) => 6,
            (_, Some(_)) | ("date", None) => 4,
            ("time", None) => 5,
            ("offset", None) => 7,
            ("naive", None) => rng.pick(&[0, 8, 8]),
            _ => 0,
        };
        shaped_input_of(rng, shape)
    };
    Case::Parse {
        target,
        input,
        format,
    }
}
pub fn golden_corpus() -> Vec<Case> {
    let mut cases = corpus(0x5970_0044_5000_0037, 20_000);
    // The edge corpus fills most of the general corpus, so freeze a separate
    // set of parser inputs that survives the removal of the chrono oracle.
    let mut rng = SplitMix64(0x5970_0044_5000_3339);
    cases.extend((0..6_000).map(|_| shaped_parse_case(&mut rng)));
    cases
}
