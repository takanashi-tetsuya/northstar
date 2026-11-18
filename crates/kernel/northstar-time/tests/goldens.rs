pub mod support;

#[test]
fn frozen_chrono_goldens_replay_unchanged() {
    let mut failures = Vec::new();
    for (case, expected) in support::read_goldens() {
        if !case.enabled() {
            continue;
        }
        let actual = support::eval(&case);
        if actual != expected && failures.len() < 20 {
            failures.push(format!("{case:?}\nchrono: {expected}\nnorthstar: {actual}"));
        }
    }
    assert!(
        failures.is_empty(),
        "first golden mismatches:\n{}",
        failures.join("\n\n")
    );
}

#[test]
fn utc_now_uses_the_system_unix_timestamp() {
    let before = std::time::SystemTime::now();
    let value = northstar_time::Utc::now();
    let after = std::time::SystemTime::now();
    let value = std::time::SystemTime::from(value);
    assert!(value >= before && value <= after);
}

#[test]
fn unsupported_strftime_items_fail_formatting_and_parsing() {
    use northstar_time::{DateTime, FixedOffset, NaiveDate, NaiveDateTime, ParseErrorKind};
    use std::fmt::Write;
    for format in ["%F", "%T", "%+", "%:z", "%3f", "%.3f", "%a", "%-d", "%_Y"] {
        let mut text = String::new();
        assert!(
            write!(text, "{}", DateTime::UNIX_EPOCH.format(format)).is_err(),
            "{format}"
        );
        for error in [
            NaiveDate::parse_from_str("", format).unwrap_err(),
            NaiveDateTime::parse_from_str("", format).unwrap_err(),
            DateTime::<FixedOffset>::parse_from_str("", format).unwrap_err(),
        ] {
            assert_eq!(error.kind(), ParseErrorKind::BadFormat, "{format}");
        }
    }
}
