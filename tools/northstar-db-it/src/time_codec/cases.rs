//! Inputs shared as integers or SQL literals, never converted between libraries.

pub(super) const TIMESTAMPS: &[(&str, &str)] = &[
    ("unix_epoch", "'1970-01-01 00:00:00+00'"),
    ("before_unix_epoch", "'1969-12-31 23:59:59.999999+00'"),
    ("postgres_epoch", "'2000-01-01 00:00:00+00'"),
    ("before_postgres_epoch", "'1999-12-31 23:59:59.999999+00'"),
    ("fraction", "'2026-09-02 12:00:00.123456+00'"),
    ("east_offset", "'2026-09-02 21:00:00+09'"),
    ("west_offset", "'2026-09-02 08:30:00-03:30'"),
    ("first_ce_year", "'0001-01-01 00:00:00+00'"),
    ("postgres_min", "'4714-11-24 00:00:00+00 BC'"),
    ("year_262143", "'262143-12-31 23:59:59.999999+00'"),
    ("year_262144", "'262144-01-01 00:00:00+00'"),
    ("postgres_max", "'294276-12-31 23:59:59.999999+00'"),
    ("infinity", "'infinity'"),
    ("negative_infinity", "'-infinity'"),
];

pub(super) const NAIVE_TIMESTAMPS: &[(&str, &str)] = &[
    ("unix_epoch", "'1970-01-01 00:00:00'"),
    ("before_unix_epoch", "'1969-12-31 23:59:59.999999'"),
    ("postgres_epoch", "'2000-01-01 00:00:00'"),
    ("fraction", "'2026-09-02 12:00:00.123456'"),
    ("postgres_min", "'4714-11-24 00:00:00 BC'"),
    ("year_262144", "'262144-01-01 00:00:00'"),
    ("infinity", "'infinity'"),
    ("negative_infinity", "'-infinity'"),
];

// Astronomical year -4713 is PostgreSQL's 4714 BC (there is no SQL year zero).
pub(super) const DATES: &[(&str, i32, u32, u32)] = &[
    ("1970-01-01", 1970, 1, 1),
    ("2000-01-01", 2000, 1, 1),
    ("1999-12-31", 1999, 12, 31),
    ("2000-01-02", 2000, 1, 2),
    ("0001-01-01", 1, 1, 1),
    ("4714-11-24 BC", -4713, 11, 24),
    ("5874897-12-31", 5_874_897, 12, 31),
    ("262143-12-31", 262_143, 12, 31),
    ("262144-01-01", 262_144, 1, 1),
];

pub(super) struct Instant {
    pub label: String,
    pub seconds: i64,
    pub nanos: u32,
}

pub(super) fn instants() -> Vec<Instant> {
    let mut cases = Vec::new();
    // Euclidean splitting preserves the negative subsecond inputs exactly.
    for (label, seconds, offsets) in [
        (
            "unix_epoch",
            0,
            &[
                0_i64, -1, 1, -1000, 1000, -1500, 1500, -499, 499, -500, 500, -999, 999,
            ][..],
        ),
        (
            "postgres_epoch",
            946_684_800,
            &[
                0, -1, 1, -499, 499, -500, 500, -501, 501, -999, 999, -1000, 1000,
            ][..],
        ),
    ] {
        for &delta in offsets {
            cases.push(Instant {
                label: format!("{label}/{delta}ns"),
                seconds: seconds + delta.div_euclid(1_000_000_000),
                nanos: delta.rem_euclid(1_000_000_000) as u32,
            });
        }
    }
    for (label, seconds, nanos) in [
        ("1999_last_nanosecond", 946_684_799, 999_999_999),
        ("2026_fraction", 1_788_350_400, 123_456_789),
        ("leap_second", 1_483_228_799, 1_000_000_000),
        ("leap_half", 1_483_228_799, 1_500_000_000),
        ("leap_last_nanosecond", 1_483_228_799, 1_999_999_999),
        (
            "min_utc",
            chrono::DateTime::<chrono::Utc>::MIN_UTC.timestamp(),
            chrono::DateTime::<chrono::Utc>::MIN_UTC.timestamp_subsec_nanos(),
        ),
        (
            "max_utc",
            chrono::DateTime::<chrono::Utc>::MAX_UTC.timestamp(),
            chrono::DateTime::<chrono::Utc>::MAX_UTC.timestamp_subsec_nanos(),
        ),
        // Julian day zero at midnight: 2,440,588 days before the Unix epoch.
        ("postgres_min", -2_440_588 * 86_400, 0),
        // The last microsecond before PostgreSQL's exclusive upper bound.
        ("postgres_max", 9_224_318_015_999, 999_999_000),
    ] {
        cases.push(Instant {
            label: label.into(),
            seconds,
            nanos,
        });
    }
    cases
}
