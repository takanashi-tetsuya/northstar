pub mod support;

use support::Case;

mod chrono_backend {
    use chrono as clock;
    use chrono::{Datelike, Timelike};
    include!("support/evaluate.rs");
}

fn eval_chrono(case: &Case) -> String {
    chrono_backend::eval(case)
}

#[test]
fn northstar_time_matches_chrono_on_a_generated_corpus() {
    let mut failures = Vec::new();
    let mut count = 0;
    for seed in [
        0x597,
        0x37,
        0xdead_beef_cafe_f00d,
        0x1234_5678_90ab_cdef,
        0x5eed,
        0x2026_0902,
    ] {
        let cases = support::corpus(seed, 100_000);
        count += cases.len();
        for failure in support::mismatches(cases, eval_chrono) {
            if failures.len() < 20 {
                failures.push(failure);
            }
        }
    }
    assert!(
        count >= 600_000,
        "differential corpus must cover at least 600,000 cases"
    );
    assert!(
        failures.is_empty(),
        "first mismatches:\n{}",
        failures.join("\n\n")
    );
}

#[test]
fn frozen_goldens_match_chrono() {
    let generated = support::golden_corpus();
    if std::env::var("NORTHSTAR_TIME_BLESS").as_deref() == Ok("1") {
        // A fixture must preserve every feature's results for later replay.
        assert!(
            generated.iter().all(Case::enabled),
            "bless chrono goldens with both serde and postgres enabled"
        );
        use std::io::Write;
        let path = support::fixture_path();
        std::fs::create_dir_all(path.parent().expect("fixture directory")).unwrap();
        let mut output = std::io::BufWriter::new(std::fs::File::create(path).unwrap());
        for case in &generated {
            writeln!(output, "{}", support::golden_line(case, &eval_chrono(case))).unwrap();
        }
        output.flush().unwrap();
        return;
    }
    let frozen = support::read_goldens();
    assert_eq!(
        frozen.len(),
        generated.len(),
        "golden corpus size changed; review before blessing"
    );
    let mut failures = Vec::new();
    for ((case, result), generated) in frozen.into_iter().zip(generated) {
        assert_eq!(
            case.to_json(),
            generated.to_json(),
            "golden case description changed"
        );
        if !case.enabled() {
            continue;
        }
        let actual = eval_chrono(&case);
        if result != actual && failures.len() < 20 {
            failures.push(format!("{case:?}\nfrozen: {result}\nchrono: {actual}"));
        }
    }
    assert!(
        failures.is_empty(),
        "first frozen mismatches:\n{}",
        failures.join("\n\n")
    );
}
