// Each backend executes this same operation description against its own types.
// Canonical values contain scalar fields as well as Debug, so Display cannot
// conceal an arithmetic or offset mismatch.
use crate::support::{capture, Case, Span, Stamp};
use clock::{
    DateTime, FixedOffset, MappedLocalTime, NaiveDate, NaiveDateTime, NaiveTime, Offset,
    ParseError, SecondsFormat, TimeDelta, TimeZone, Utc,
};
use std::fmt::{self, Write};
use std::time::{Duration as StdDuration, SystemTime, UNIX_EPOCH};

fn ok(value: impl fmt::Display) -> String {
    format!("Ok({value})")
}
fn optional<T>(value: Option<T>, render: impl FnOnce(T) -> String) -> String {
    value.map_or_else(|| "Err(None)".to_string(), |value| ok(render(value)))
}
fn parsed<T>(value: Result<T, ParseError>, render: impl FnOnce(T) -> String) -> String {
    match value {
        Ok(value) => ok(render(value)),
        Err(error) => format!(
            "Err(kind={:?} Debug={error:?} Display={error})",
            error.kind()
        ),
    }
}
fn fallible<T, E: fmt::Debug + fmt::Display>(
    value: Result<T, E>,
    render: impl FnOnce(T) -> String,
) -> String {
    match value {
        Ok(value) => ok(render(value)),
        Err(error) => format!("Err({error:?}: {error})"),
    }
}
fn delta(value: TimeDelta) -> String {
    format!(
        "seconds={} subsec={} Debug={value:?}",
        value.num_seconds(),
        value.subsec_nanos()
    )
}
fn date(value: NaiveDate) -> String {
    format!(
        "year={} month={} day={} ordinal={} Debug={value:?}",
        value.year(),
        value.month(),
        value.day(),
        value.ordinal()
    )
}
fn time(value: NaiveTime) -> String {
    format!(
        "h={} m={} s={} nanos={} Debug={value:?}",
        value.hour(),
        value.minute(),
        value.second(),
        value.nanosecond()
    )
}
fn naive(value: NaiveDateTime) -> String {
    format!(
        "date=[{}] time=[{}] Debug={value:?}",
        date(value.date()),
        time(value.time())
    )
}
fn zoned<Tz: TimeZone>(value: DateTime<Tz>) -> String {
    format!(
        "seconds={} nanos={} offset={} Debug={value:?}",
        value.timestamp(),
        value.timestamp_subsec_nanos(),
        value.offset().fix().local_minus_utc()
    )
}
fn span(value: Span) -> TimeDelta {
    TimeDelta::new(value.seconds, value.nanos).expect("valid duration case argument")
}
fn stamp(value: Stamp) -> DateTime<Utc> {
    DateTime::from_timestamp(value.seconds, value.nanos).expect("valid timestamp case argument")
}
fn fixed(value: Stamp) -> DateTime<FixedOffset> {
    stamp(value)
        .with_timezone(&FixedOffset::east_opt(value.offset).expect("valid offset case argument"))
}
fn offset(value: FixedOffset) -> String {
    format!(
        "east={} west={} Debug={value:?} Display={value}",
        value.local_minus_utc(),
        value.utc_minus_local()
    )
}
fn cloned<T: Clone>(value: &T) -> T {
    value.clone()
}
fn value_traits<T: Clone + Copy + Eq + std::hash::Hash + Send + Sync>(value: T) -> String {
    use std::hash::Hasher;
    let copy = value;
    let clone = cloned(&value);
    let mut original = std::collections::hash_map::DefaultHasher::new();
    let mut copied = std::collections::hash_map::DefaultHasher::new();
    value.hash(&mut original);
    clone.hash(&mut copied);
    format!(
        "copy={} clone={} hash={}",
        copy == value,
        clone == value,
        original.finish() == copied.finish()
    )
}
fn mapping<T>(value: MappedLocalTime<T>, render: impl Fn(T) -> String) -> String {
    match value {
        MappedLocalTime::None => "None".to_string(),
        MappedLocalTime::Single(v) => format!("Single({})", render(v)),
        MappedLocalTime::Ambiguous(a, b) => format!("Ambiguous({}, {})", render(a), render(b)),
    }
}
fn delta_case(op: &str, a: Span, b: Span, factor: i32) -> String {
    let v = a.seconds;
    match op {
        "new" => return optional(TimeDelta::new(v, a.nanos), delta),
        "weeks" => return ok(delta(TimeDelta::weeks(v))),
        "try_weeks" => return optional(TimeDelta::try_weeks(v), delta),
        "days" => return ok(delta(TimeDelta::days(v))),
        "try_days" => return optional(TimeDelta::try_days(v), delta),
        "hours" => return ok(delta(TimeDelta::hours(v))),
        "try_hours" => return optional(TimeDelta::try_hours(v), delta),
        "minutes" => return ok(delta(TimeDelta::minutes(v))),
        "try_minutes" => return optional(TimeDelta::try_minutes(v), delta),
        "seconds" => return ok(delta(TimeDelta::seconds(v))),
        "try_seconds" => return optional(TimeDelta::try_seconds(v), delta),
        "milliseconds" => return ok(delta(TimeDelta::milliseconds(v))),
        "try_milliseconds" => return optional(TimeDelta::try_milliseconds(v), delta),
        "microseconds" => return ok(delta(TimeDelta::microseconds(v))),
        "nanoseconds" => return ok(delta(TimeDelta::nanoseconds(v))),
        "from_std" => {
            return fallible(
                TimeDelta::from_std(StdDuration::new(v as u64, a.nanos)),
                delta,
            )
        }
        _ => {}
    }
    let mut a = span(a);
    let b = span(b);
    match op {
        "accessors" => ok(format!(
            "{} {} {} {} {} {} {:?} {:?} {} {} {} {} {} {}",
            a.num_weeks(),
            a.num_days(),
            a.num_hours(),
            a.num_minutes(),
            a.num_seconds(),
            a.num_milliseconds(),
            a.num_microseconds(),
            a.num_nanoseconds(),
            a.subsec_millis(),
            a.subsec_micros(),
            a.subsec_nanos(),
            a.is_zero(),
            a.as_seconds_f32().to_bits(),
            a.as_seconds_f64().to_bits()
        )),
        "abs" => ok(delta(a.abs())),
        "neg" => ok(delta(-a)),
        "checked_add" => optional(a.checked_add(&b), delta),
        "checked_sub" => optional(a.checked_sub(&b), delta),
        "checked_mul" => optional(a.checked_mul(factor), delta),
        "checked_div" => optional(a.checked_div(factor), delta),
        "add" => ok(delta(a + b)),
        "sub" => ok(delta(a - b)),
        "add_assign" => {
            a += b;
            ok(delta(a))
        }
        "sub_assign" => {
            a -= b;
            ok(delta(a))
        }
        "mul" => ok(delta(a * factor)),
        "div" => ok(delta(a / factor)),
        "sum" => ok(delta([a, b].into_iter().sum())),
        "sum_ref" => ok(delta([a, b].iter().sum())),
        "compare" => ok(format!(
            "eq={} cmp={:?} partial={:?}",
            a == b,
            a.cmp(&b),
            a.partial_cmp(&b)
        )),
        "debug" => ok(format!("{a:?}")),
        "display" => ok(a.to_string()),
        "to_std" => fallible(a.to_std(), |v| {
            format!(
                "seconds={} nanos={} Debug={v:?}",
                v.as_secs(),
                v.subsec_nanos()
            )
        }),
        _ => panic!("unknown delta operation {op}"),
    }
}
fn date_case(op: &str, ymd: [i64; 3], hmsn: [i64; 4], other_days: i32, d: Span) -> String {
    if op == "from_ce" {
        return optional(NaiveDate::from_num_days_from_ce_opt(other_days), date);
    }
    let [y, m, d0] = ymd;
    let value = NaiveDate::from_ymd_opt(y as i32, m as u32, d0 as u32);
    if op == "from_ymd" {
        return optional(value, date);
    }
    let mut a = value.expect("valid date case argument");
    let [h, m, s, n] = hmsn.map(|v| v as u32);
    match op {
        "and_hms" => optional(a.and_hms_opt(h, m, s), naive),
        "and_milli" => optional(a.and_hms_milli_opt(h, m, s, n), naive),
        "and_micro" => optional(a.and_hms_micro_opt(h, m, s, n), naive),
        "and_nano" => optional(a.and_hms_nano_opt(h, m, s, n), naive),
        "and_time" => ok(naive(a.and_time(
            NaiveTime::from_hms_nano_opt(h, m, s, n).expect("valid time case argument"),
        ))),
        "accessors" => ok(date(a)),
        "checked_add" => optional(a.checked_add_signed(span(d)), date),
        "checked_sub" => optional(a.checked_sub_signed(span(d)), date),
        "add" => ok(date(a + span(d))),
        "sub" => ok(date(a - span(d))),
        "add_assign" => {
            a += span(d);
            ok(date(a))
        }
        "sub_assign" => {
            a -= span(d);
            ok(date(a))
        }
        "since" => ok(delta(a.signed_duration_since(
            NaiveDate::from_num_days_from_ce_opt(other_days).expect("valid other date"),
        ))),
        "difference" => ok(delta(
            a - NaiveDate::from_num_days_from_ce_opt(other_days).expect("valid other date"),
        )),
        "compare" => {
            let b = NaiveDate::from_num_days_from_ce_opt(other_days).expect("valid other date");
            ok(format!("eq={} cmp={:?}", a == b, a.cmp(&b)))
        }
        "display" => ok(a.to_string()),
        "debug" => ok(format!("{a:?}")),
        _ => panic!("unknown date operation {op}"),
    }
}
fn time_case(op: &str, hmsn: [i64; 4], other: [i64; 2], d: Span) -> String {
    let [h, m, s, n] = hmsn.map(|v| v as u32);
    match op {
        "hms" => return optional(NaiveTime::from_hms_opt(h, m, s), time),
        "milli" => return optional(NaiveTime::from_hms_milli_opt(h, m, s, n), time),
        "micro" => return optional(NaiveTime::from_hms_micro_opt(h, m, s, n), time),
        "nano" => return optional(NaiveTime::from_hms_nano_opt(h, m, s, n), time),
        "midnight" => {
            return optional(
                NaiveTime::from_num_seconds_from_midnight_opt(other[0] as u32, other[1] as u32),
                time,
            )
        }
        _ => {}
    }
    let a = NaiveTime::from_hms_nano_opt(h, m, s, n).expect("valid time case argument");
    match op {
        "accessors" => ok(time(a)),
        "overflowing_add" => {
            let (v, overflow) = a.overflowing_add_signed(span(d));
            ok(format!("{} overflow={overflow}", time(v)))
        }
        "since" => ok(delta(
            a.signed_duration_since(
                NaiveTime::from_num_seconds_from_midnight_opt(other[0] as u32, other[1] as u32)
                    .expect("valid other time"),
            ),
        )),
        "compare" => {
            let b = NaiveTime::from_num_seconds_from_midnight_opt(other[0] as u32, other[1] as u32)
                .expect("valid other time");
            ok(format!("eq={} cmp={:?}", a == b, a.cmp(&b)))
        }
        "display" => ok(a.to_string()),
        "debug" => ok(format!("{a:?}")),
        _ => panic!("unknown time operation {op}"),
    }
}
fn naive_case(op: &str, a: Stamp, b: Stamp, d: Span) -> String {
    let mut a = stamp(a).naive_utc();
    let b = stamp(b).naive_utc();
    match op {
        "new" => ok(naive(NaiveDateTime::new(a.date(), a.time()))),
        "accessors" => ok(format!(
            "{} {} {}",
            date(a.date()),
            time(a.time()),
            zoned(a.and_utc())
        )),
        "checked_add" => optional(a.checked_add_signed(span(d)), naive),
        "checked_sub" => optional(a.checked_sub_signed(span(d)), naive),
        "since" => ok(delta(a.signed_duration_since(b))),
        "difference" => ok(delta(a - b)),
        "add" => ok(naive(a + span(d))),
        "sub" => ok(naive(a - span(d))),
        "add_assign" => {
            a += span(d);
            ok(naive(a))
        }
        "sub_assign" => {
            a -= span(d);
            ok(naive(a))
        }
        "compare" => ok(format!("eq={} cmp={:?}", a == b, a.cmp(&b))),
        "display" => ok(a.to_string()),
        "debug" => ok(format!("{a:?}")),
        _ => panic!("unknown naive operation {op}"),
    }
}
fn timestamp_case(op: &str, value: i64, nanos: u32, off: i32) -> String {
    let tz = FixedOffset::east_opt(off).expect("valid offset case argument");
    match op {
        "seconds" => optional(DateTime::from_timestamp(value, nanos), zoned),
        "millis" => optional(DateTime::from_timestamp_millis(value), zoned),
        "micros" => optional(DateTime::from_timestamp_micros(value), zoned),
        "nanos" => ok(zoned(DateTime::from_timestamp_nanos(value))),
        "tz_seconds" => ok(mapping(tz.timestamp_opt(value, nanos), zoned)),
        "tz_millis" => ok(mapping(tz.timestamp_millis_opt(value), zoned)),
        "tz_micros" => ok(mapping(tz.timestamp_micros(value), zoned)),
        "tz_nanos" => ok(zoned(tz.timestamp_nanos(value))),
        "utc_seconds" => ok(mapping(Utc.timestamp_opt(value, nanos), zoned)),
        "utc_millis" => ok(mapping(Utc.timestamp_millis_opt(value), zoned)),
        "utc_micros" => ok(mapping(Utc.timestamp_micros(value), zoned)),
        "utc_nanos" => ok(zoned(Utc.timestamp_nanos(value))),
        _ => panic!("unknown timestamp operation {op}"),
    }
}
fn seconds_format(precision: u8) -> SecondsFormat {
    match precision {
        0 => SecondsFormat::Secs,
        1 => SecondsFormat::Millis,
        2 => SecondsFormat::Micros,
        3 => SecondsFormat::Nanos,
        4 => SecondsFormat::AutoSi,
        5 => SecondsFormat::__NonExhaustive,
        _ => panic!("unknown seconds precision {precision}"),
    }
}
fn zoned_case(
    op: &str,
    a0: Stamp,
    b0: Stamp,
    d: Span,
    fmt: &str,
    precision: u8,
    use_z: bool,
) -> String {
    let mut a = fixed(a0);
    let b = fixed(b0);
    match op {
        "from_naive" => ok(zoned(DateTime::<FixedOffset>::from_naive_utc_and_offset(
            a.naive_utc(),
            *a.offset(),
        ))),
        "timestamps" => ok(format!(
            "{} {} {} {:?} {} {} {}",
            a.timestamp(),
            a.timestamp_millis(),
            a.timestamp_micros(),
            a.timestamp_nanos_opt(),
            a.timestamp_subsec_millis(),
            a.timestamp_subsec_micros(),
            a.timestamp_subsec_nanos()
        )),
        "naive_utc" => ok(naive(a.naive_utc())),
        "naive_local" => ok(naive(a.naive_local())),
        "date_naive" => ok(date(a.date_naive())),
        "time" => ok(time(a.time())),
        "offset" => ok(offset(*a.offset())),
        "timezone" => ok(offset(a.timezone())),
        "with_timezone" => ok(zoned(a.with_timezone(b.offset()))),
        "tz_from_local" => ok(mapping(
            a.timezone().from_local_datetime(&a.naive_utc()),
            zoned,
        )),
        "tz_from_utc" => ok(zoned(a.timezone().from_utc_datetime(&a.naive_utc()))),
        "fixed_offset" => ok(zoned(a.to_utc().fixed_offset())),
        "to_utc" => ok(zoned(a.to_utc())),
        "from_utc" => ok(zoned(DateTime::<FixedOffset>::from(a.to_utc()))),
        "into_utc" => ok(zoned(DateTime::<Utc>::from(a))),
        "since" => ok(delta(a.signed_duration_since(b.to_utc()))),
        "difference" => ok(delta(a - b)),
        "checked_add" => optional(a.checked_add_signed(span(d)), zoned),
        "checked_sub" => optional(a.checked_sub_signed(span(d)), zoned),
        "add" => ok(zoned(a + span(d))),
        "sub" => ok(zoned(a - span(d))),
        "add_assign" => {
            a += span(d);
            ok(zoned(a))
        }
        "sub_assign" => {
            a -= span(d);
            ok(zoned(a))
        }
        "add_std" => ok(zoned(a + StdDuration::new(d.seconds as u64, d.nanos))),
        "sub_std" => ok(zoned(a - StdDuration::new(d.seconds as u64, d.nanos))),
        "add_assign_std" => {
            a += StdDuration::new(d.seconds as u64, d.nanos);
            ok(zoned(a))
        }
        "sub_assign_std" => {
            a -= StdDuration::new(d.seconds as u64, d.nanos);
            ok(zoned(a))
        }
        "compare" => ok(format!(
            "eq={} cmp={:?} partial={:?} cross_eq={} cross_partial={:?}",
            a == b,
            a.cmp(&b),
            a.partial_cmp(&b),
            a == b.to_utc(),
            a.partial_cmp(&b.to_utc())
        )),
        "rfc3339" => ok(a.to_rfc3339()),
        "rfc3339_opts" => ok(a.to_rfc3339_opts(seconds_format(precision), use_z)),
        "seconds_format_debug" => ok(format!("{:?}", seconds_format(precision))),
        "format_debug" => ok(format!("{:?}", a.format(fmt))),
        "format" => {
            let mut value = String::new();
            match write!(value, "{}", a.format(fmt)) {
                Ok(()) => ok(value),
                Err(error) => format!("Err({error:?}: {error})"),
            }
        }
        "display" => ok(a.to_string()),
        "debug" => ok(format!("{a:?}")),
        "utc_display" => ok(a.to_utc().to_string()),
        "utc_debug" => ok(format!("{:?}", a.to_utc())),
        "utc_format" => {
            let mut value = String::new();
            match write!(value, "{}", a.to_utc().format(fmt)) {
                Ok(()) => ok(value),
                Err(error) => format!("Err({error:?}: {error})"),
            }
        }
        _ => panic!("unknown zoned operation {op}"),
    }
}
fn parse_case(target: &str, input: &str, fmt: Option<&str>) -> String {
    match (target, fmt) {
        ("rfc3339", _) => parsed(DateTime::parse_from_rfc3339(input), zoned),
        ("utc", None) => parsed(input.parse::<DateTime<Utc>>(), zoned),
        ("fixed", None) => parsed(input.parse::<DateTime<FixedOffset>>(), zoned),
        ("fixed", Some(fmt)) => parsed(DateTime::parse_from_str(input, fmt), zoned),
        ("date", None) => parsed(input.parse::<NaiveDate>(), date),
        ("date", Some(fmt)) => parsed(NaiveDate::parse_from_str(input, fmt), date),
        ("time", None) => parsed(input.parse::<NaiveTime>(), time),
        ("offset", None) => parsed(input.parse::<FixedOffset>(), offset),
        ("naive", None) => parsed(input.parse::<NaiveDateTime>(), naive),
        ("naive", Some(fmt)) => parsed(NaiveDateTime::parse_from_str(input, fmt), naive),
        _ => panic!("unknown parser {target} {fmt:?}"),
    }
}
fn offset_case(op: &str, value: i32) -> String {
    match op {
        "east" => return optional(FixedOffset::east_opt(value), offset),
        "west" => return optional(FixedOffset::west_opt(value), offset),
        "utc" => {
            return ok(format!(
                "Debug={Utc:?} Display={Utc} fix={}",
                offset(Utc.fix())
            ))
        }
        _ => {}
    }
    let tz = FixedOffset::east_opt(value).expect("valid offset case argument");
    let dt = DateTime::UNIX_EPOCH.naive_utc();
    match op {
        "from_offset" => ok(offset(FixedOffset::from_offset(&tz))),
        "from_utc_date" => ok(offset(tz.offset_from_utc_date(&dt.date()))),
        "from_utc_datetime" => ok(offset(tz.offset_from_utc_datetime(&dt))),
        "from_local_date" => ok(mapping(tz.offset_from_local_date(&dt.date()), offset)),
        "from_local_datetime" => ok(mapping(tz.offset_from_local_datetime(&dt), offset)),
        "from_utc" => ok(zoned(tz.from_utc_datetime(&dt))),
        "from_local" => ok(mapping(tz.from_local_datetime(&dt), zoned)),
        "with_ymd" => ok(mapping(tz.with_ymd_and_hms(2000, 1, 1, 0, 0, 0), zoned)),
        "utc_methods" => ok(format!(
            "{:?} {:?} {:?} {:?} {:?} {:?} {:?}",
            Utc::from_offset(&Utc),
            Utc.offset_from_utc_date(&dt.date()),
            Utc.offset_from_utc_datetime(&dt),
            Utc.offset_from_local_date(&dt.date()),
            Utc.offset_from_local_datetime(&dt),
            Utc.from_local_datetime(&dt),
            Utc.with_ymd_and_hms(0, 1, 1, 0, 0, 0)
        )),
        _ => panic!("unknown offset operation {op}"),
    }
}
fn mapping_case(op: &str, variant: u8, a: i64, b: i64) -> String {
    let value = match variant {
        0 => MappedLocalTime::None,
        1 => MappedLocalTime::Single(a),
        _ => MappedLocalTime::Ambiguous(a, b),
    };
    match op {
        "single" => ok(format!("{:?}", value.single())),
        "earliest" => ok(format!("{:?}", value.earliest())),
        "latest" => ok(format!("{:?}", value.latest())),
        "map" => ok(format!("{:?}", value.map(|v| v.wrapping_add(1)))),
        "unwrap" => ok(value.unwrap()),
        "debug" => ok(format!("{value:?}")),
        _ => panic!("unknown mapping operation {op}"),
    }
}
#[allow(deprecated)]
fn constants() -> String {
    let error = "".parse::<NaiveDate>().unwrap_err();
    let values = [
        delta(TimeDelta::MIN),
        delta(TimeDelta::MAX),
        delta(TimeDelta::min_value()),
        delta(TimeDelta::max_value()),
        delta(TimeDelta::zero()),
        delta(TimeDelta::default()),
        delta(clock::Duration::zero()),
        date(NaiveDate::MIN),
        date(NaiveDate::MAX),
        date(NaiveDate::default()),
        naive(NaiveDateTime::MIN),
        naive(NaiveDateTime::MAX),
        naive(NaiveDateTime::default()),
        time(NaiveTime::default()),
        zoned(DateTime::<Utc>::MIN_UTC),
        zoned(DateTime::<Utc>::MAX_UTC),
        zoned(DateTime::UNIX_EPOCH),
        zoned(DateTime::<Utc>::default()),
        zoned(DateTime::<FixedOffset>::default()),
        value_traits(TimeDelta::zero()),
        value_traits(NaiveDate::MIN),
        value_traits(NaiveTime::default()),
        value_traits(NaiveDateTime::MIN),
        value_traits(DateTime::UNIX_EPOCH),
        value_traits(Utc),
        value_traits(Utc.fix()),
        value_traits(MappedLocalTime::Single(0)),
        value_traits(SecondsFormat::AutoSi),
        value_traits(error),
        value_traits(error.kind()),
    ];
    ok(values.join("; "))
}
fn system_case(op: &str, seconds: i64, nanos: u32) -> String {
    let dt = DateTime::from_timestamp(seconds, nanos).expect("valid system timestamp argument");
    match op {
        "from" => {
            let value = if seconds < 0 {
                UNIX_EPOCH - StdDuration::new(seconds.unsigned_abs(), 0)
                    + StdDuration::new(0, nanos)
            } else {
                UNIX_EPOCH + StdDuration::new(seconds as u64, nanos)
            };
            ok(zoned(DateTime::<Utc>::from(value)))
        }
        "into" => {
            let value = SystemTime::from(dt);
            match value.duration_since(UNIX_EPOCH) {
                Ok(v) => ok(format!(
                    "after seconds={} nanos={}",
                    v.as_secs(),
                    v.subsec_nanos()
                )),
                Err(e) => ok(format!(
                    "before seconds={} nanos={}",
                    e.duration().as_secs(),
                    e.duration().subsec_nanos()
                )),
            }
        }
        _ => panic!("unknown system operation {op}"),
    }
}
#[cfg(feature = "serde")]
fn serde_case(target: &str, input: Option<&str>, value: Stamp) -> String {
    match (target, input) {
        ("utc", Some(input)) => fallible(serde_json::from_str::<DateTime<Utc>>(input), zoned),
        ("fixed", Some(input)) => {
            fallible(serde_json::from_str::<DateTime<FixedOffset>>(input), zoned)
        }
        ("date", Some(input)) => fallible(serde_json::from_str::<NaiveDate>(input), date),
        ("time", Some(input)) => fallible(serde_json::from_str::<NaiveTime>(input), time),
        ("naive", Some(input)) => fallible(serde_json::from_str::<NaiveDateTime>(input), naive),
        ("utc", None) => fallible(serde_json::to_string(&stamp(value)), |v| v),
        ("fixed", None) => fallible(serde_json::to_string(&fixed(value)), |v| v),
        ("date", None) => fallible(serde_json::to_string(&stamp(value).date_naive()), |v| v),
        ("time", None) => fallible(serde_json::to_string(&stamp(value).time()), |v| v),
        ("naive", None) => fallible(serde_json::to_string(&stamp(value).naive_utc()), |v| v),
        _ => panic!("unknown serde type {target}"),
    }
}
#[cfg(feature = "postgres")]
fn postgres_case(target: &str, value: Stamp) -> String {
    use sqlx::postgres::PgArgumentBuffer;
    use sqlx::{Encode, Postgres};
    fn bytes<'q>(value: &impl Encode<'q, Postgres>) -> String {
        let mut buf = PgArgumentBuffer::default();
        match value.encode_by_ref(&mut buf) {
            Ok(_) => ok(format!(
                "bytes={:02x?} size_hint={}",
                *buf,
                value.size_hint()
            )),
            Err(error) => format!("Err({error})"),
        }
    }
    match target {
        "utc" => bytes(&stamp(value)),
        "fixed" => bytes(&fixed(value)),
        "naive" => bytes(&stamp(value).naive_utc()),
        "date" => bytes(&stamp(value).date_naive()),
        _ => panic!("unknown postgres type {target}"),
    }
}
pub fn eval(case: &Case) -> String {
    if !case.enabled() {
        return "skip(feature disabled)".to_string();
    }
    capture(|| match case {
        Case::Delta { op, a, b, factor } => delta_case(op, *a, *b, *factor),
        Case::Date {
            op,
            ymd,
            hmsn,
            other_days,
            delta,
        } => date_case(op, *ymd, *hmsn, *other_days, *delta),
        Case::Time {
            op,
            hmsn,
            other,
            delta,
        } => time_case(op, *hmsn, *other, *delta),
        Case::Naive { op, a, b, delta } => naive_case(op, *a, *b, *delta),
        Case::Timestamp {
            op,
            value,
            nanos,
            offset,
        } => timestamp_case(op, *value, *nanos, *offset),
        Case::Local {
            offset,
            ymd,
            hms,
            utc,
        } => {
            let [y, m, day] = *ymd;
            let [h, min, s] = (*hms).map(|v| v as u32);
            if *utc {
                ok(mapping(
                    Utc.with_ymd_and_hms(y as i32, m as u32, day as u32, h, min, s),
                    zoned,
                ))
            } else {
                let tz = FixedOffset::east_opt(*offset).expect("valid offset case argument");
                ok(mapping(
                    tz.with_ymd_and_hms(y as i32, m as u32, day as u32, h, min, s),
                    zoned,
                ))
            }
        }
        Case::Zoned {
            op,
            a,
            b,
            delta,
            format,
            precision,
            use_z,
        } => zoned_case(op, *a, *b, *delta, format, *precision, *use_z),
        Case::Offset { op, value } => offset_case(op, *value),
        Case::Mapping { op, variant, a, b } => mapping_case(op, *variant, *a, *b),
        Case::Parse {
            target,
            input,
            format,
        } => parse_case(target, input, format.as_deref()),
        #[cfg(feature = "serde")]
        Case::Serde {
            target,
            input,
            stamp,
        } => serde_case(target, input.as_deref(), *stamp),
        #[cfg(not(feature = "serde"))]
        Case::Serde { .. } => unreachable!(),
        #[cfg(feature = "postgres")]
        Case::Postgres { target, stamp } => postgres_case(target, *stamp),
        #[cfg(not(feature = "postgres"))]
        Case::Postgres { .. } => unreachable!(),
        Case::System { op, seconds, nanos } => system_case(op, *seconds, *nanos),
        Case::Constants => constants(),
    })
}
