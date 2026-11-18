//! Shared, manually serialized cases. No serde derive or random dependency is used.
use serde_json::{json, Value};
use std::cell::Cell;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::Once;

mod corpus;
mod json;
mod native {
    use northstar_time as clock;
    include!("evaluate.rs");
}
pub use corpus::{corpus, golden_corpus};
pub use native::eval;

#[derive(Clone, Copy, Debug)]
pub struct Span {
    pub seconds: i64,
    pub nanos: u32,
}
#[derive(Clone, Copy, Debug)]
pub struct Stamp {
    pub seconds: i64,
    pub nanos: u32,
    pub offset: i32,
}
#[derive(Clone, Debug)]
pub enum Case {
    Delta {
        op: String,
        a: Span,
        b: Span,
        factor: i32,
    },
    Date {
        op: String,
        ymd: [i64; 3],
        hmsn: [i64; 4],
        other_days: i32,
        delta: Span,
    },
    Time {
        op: String,
        hmsn: [i64; 4],
        other: [i64; 2],
        delta: Span,
    },
    Naive {
        op: String,
        a: Stamp,
        b: Stamp,
        delta: Span,
    },
    Timestamp {
        op: String,
        value: i64,
        nanos: u32,
        offset: i32,
    },
    Local {
        offset: i32,
        ymd: [i64; 3],
        hms: [i64; 3],
        utc: bool,
    },
    Zoned {
        op: String,
        a: Stamp,
        b: Stamp,
        delta: Span,
        format: String,
        precision: u8,
        use_z: bool,
    },
    Offset {
        op: String,
        value: i32,
    },
    Mapping {
        op: String,
        variant: u8,
        a: i64,
        b: i64,
    },
    Parse {
        target: String,
        input: String,
        format: Option<String>,
    },
    Serde {
        target: String,
        input: Option<String>,
        stamp: Stamp,
    },
    Postgres {
        target: String,
        stamp: Stamp,
    },
    System {
        op: String,
        seconds: i64,
        nanos: u32,
    },
    Constants,
}
impl Case {
    pub fn enabled(&self) -> bool {
        match self {
            Self::Serde { .. } => cfg!(feature = "serde"),
            Self::Postgres { .. } => cfg!(feature = "postgres"),
            _ => true,
        }
    }
}

thread_local! {
    static CAPTURING_PANIC: Cell<bool> = const { Cell::new(false) };
}
struct RestoreCapture(bool);
impl Drop for RestoreCapture {
    fn drop(&mut self) {
        CAPTURING_PANIC.with(|capturing| capturing.set(self.0));
    }
}

pub fn capture(f: impl FnOnce() -> String) -> String {
    static SILENT_PANICS: Once = Once::new();
    SILENT_PANICS.call_once(|| {
        let previous = std::panic::take_hook();
        std::panic::set_hook(Box::new(move |info| {
            if !CAPTURING_PANIC.with(Cell::get) {
                previous(info);
            }
        }));
    });
    // Silence only the panics being compared; test failures still print their
    // diagnostics, including a missing or empty golden fixture.
    let _restore = RestoreCapture(CAPTURING_PANIC.with(|capturing| capturing.replace(true)));
    match catch_unwind(AssertUnwindSafe(f)) {
        Ok(value) => value,
        Err(payload) => {
            let message = payload
                .downcast_ref::<String>()
                .map(String::as_str)
                .or_else(|| payload.downcast_ref::<&str>().copied())
                .unwrap_or("non-string panic payload");
            format!("panic({message})")
        }
    }
}

/// Reports at most the first twenty failures while evaluating the whole corpus.
pub fn mismatches(
    cases: impl IntoIterator<Item = Case>,
    oracle: impl Fn(&Case) -> String,
) -> Vec<String> {
    let mut failures = Vec::new();
    for case in cases {
        if !case.enabled() {
            continue;
        }
        let expected = oracle(&case);
        let actual = eval(&case);
        if expected != actual && failures.len() < 20 {
            failures.push(format!("{case:?}\nchrono: {expected}\nnorthstar: {actual}"));
        }
    }
    failures
}

pub fn fixture_path() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/chrono-0.4.45.jsonl")
}

pub fn read_goldens() -> Vec<(Case, String)> {
    let path = fixture_path();
    let text = std::fs::read_to_string(&path).unwrap_or_else(|error| {
        panic!("missing chrono golden fixture at {}: {error}; generate it with NORTHSTAR_TIME_BLESS=1 and all features", path.display())
    });
    let values: Vec<_> = text
        .lines()
        .enumerate()
        .filter(|(_, line)| !line.trim().is_empty())
        .map(|(index, line)| {
            let value: Value = serde_json::from_str(line).unwrap_or_else(|error| {
                panic!("invalid golden JSON on line {}: {error}", index + 1)
            });
            let case = Case::from_json(&value["case"]).unwrap_or_else(|error| {
                panic!("invalid golden case on line {}: {error}", index + 1)
            });
            let result = value["result"]
                .as_str()
                .unwrap_or_else(|| panic!("missing golden result on line {}", index + 1));
            (case, result.to_string())
        })
        .collect();
    assert!(!values.is_empty(), "chrono golden fixture is empty: {}; generate it with NORTHSTAR_TIME_BLESS=1 and all features", path.display());
    values
}

pub fn golden_line(case: &Case, result: &str) -> String {
    json!({"case": case.to_json(), "result": result}).to_string()
}
