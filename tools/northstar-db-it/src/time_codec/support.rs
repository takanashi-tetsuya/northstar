use anyhow::{ensure, Context};
use serde_json::{json, Value};
use sqlx::{postgres::PgRow, Decode, Postgres, Row, Type};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::Arc;

pub(super) trait Canonical {
    fn canonical(&self) -> String;
}

impl<Tz: chrono::TimeZone> Canonical for chrono::DateTime<Tz> {
    fn canonical(&self) -> String {
        format!(
            "secs={} nanos={} off={}",
            self.timestamp(),
            self.timestamp_subsec_nanos(),
            chrono::Offset::fix(self.offset()).local_minus_utc(),
        )
    }
}

impl<Tz: northstar_time::TimeZone> Canonical for northstar_time::DateTime<Tz> {
    fn canonical(&self) -> String {
        format!(
            "secs={} nanos={} off={}",
            self.timestamp(),
            self.timestamp_subsec_nanos(),
            northstar_time::Offset::fix(self.offset()).local_minus_utc(),
        )
    }
}

impl Canonical for chrono::NaiveDateTime {
    fn canonical(&self) -> String {
        self.and_utc().canonical()
    }
}

impl Canonical for northstar_time::NaiveDateTime {
    fn canonical(&self) -> String {
        self.and_utc().canonical()
    }
}

impl Canonical for chrono::NaiveDate {
    fn canonical(&self) -> String {
        format!("days={}", chrono::Datelike::num_days_from_ce(self))
    }
}

impl Canonical for northstar_time::NaiveDate {
    fn canonical(&self) -> String {
        // northstar-time intentionally has no public Datelike trait. Its public
        // duration API gives the same CE day number, with 0001-01-01 as day 1.
        let origin = northstar_time::NaiveDate::from_ymd_opt(1, 1, 1).expect("valid CE origin");
        format!("days={}", self.signed_duration_since(origin).num_days() + 1)
    }
}

impl<T: Canonical> Canonical for Option<T> {
    fn canonical(&self) -> String {
        self.as_ref()
            .map_or_else(|| "null".into(), Canonical::canonical)
    }
}

impl<T: Canonical> Canonical for Vec<T> {
    fn canonical(&self) -> String {
        let values: Vec<_> = self.iter().map(Canonical::canonical).collect();
        format!("[{}]", values.join(", "))
    }
}

impl Canonical for String {
    fn canonical(&self) -> String {
        self.clone()
    }
}

impl Canonical for bool {
    fn canonical(&self) -> String {
        self.to_string()
    }
}

fn error_text(error: &sqlx::Error) -> String {
    match error {
        // SQLx's Display appends PostgreSQL's source line, which varies between
        // server builds; the SQLSTATE and message do not.
        sqlx::Error::Database(database) => format!(
            "database {}: {}",
            database.code().unwrap_or_default(),
            database.message(),
        ),
        error => error.to_string(),
    }
}

pub(super) fn outcome<T: Canonical>(result: Result<T, sqlx::Error>) -> String {
    match result {
        Ok(value) => format!("Ok({})", value.canonical()),
        Err(error) => format!("Err({})", error_text(&error)),
    }
}

fn capture(f: impl FnOnce() -> String) -> String {
    // The hook is global, so continue reporting unrelated threads' panics.
    // Only the synchronous decode is silenced, never a database fetch or await.
    let thread = std::thread::current().id();
    let previous = Arc::new(std::panic::take_hook());
    let forward = Arc::clone(&previous);
    std::panic::set_hook(Box::new(move |info| {
        if std::thread::current().id() != thread {
            forward(info);
        }
    }));
    let result = catch_unwind(AssertUnwindSafe(f));
    drop(std::panic::take_hook());
    match Arc::try_unwrap(previous) {
        Ok(previous) => std::panic::set_hook(previous),
        Err(_) => panic!("temporary decode hook retained the previous panic hook"),
    }
    match result {
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

pub(super) fn column<T>(row: &Result<PgRow, sqlx::Error>, index: usize) -> String
where
    T: for<'r> Decode<'r, Postgres> + Type<Postgres> + Canonical,
{
    match row {
        Ok(row) => capture(|| outcome(row.try_get::<T, _>(index))),
        Err(error) => format!("Err({})", error_text(error)),
    }
}

struct Record {
    label: String,
    chrono: String,
    northstar: String,
}

#[derive(Default)]
pub(super) struct Records(Vec<Record>);

impl Records {
    pub fn push(&mut self, label: impl Into<String>, chrono: String, northstar: String) {
        self.0.push(Record {
            label: label.into(),
            chrono,
            northstar,
        });
    }

    pub fn compare_libraries(&self) -> anyhow::Result<()> {
        let failures: Vec<_> = self
            .0
            .iter()
            .filter(|record| {
                record.chrono != record.northstar
                    || (record.label.ends_with("/equal") && record.chrono == "Ok(false)")
            })
            .take(20)
            .map(|record| {
                format!(
                    "{}\nchrono: {}\nnorthstar: {}",
                    record.label, record.chrono, record.northstar,
                )
            })
            .collect();
        ensure!(
            failures.is_empty(),
            "first codec mismatches (successful cross-driver equality must be true):\n{}",
            failures.join("\n\n"),
        );
        Ok(())
    }

    pub fn compare_or_bless_fixture(&self) -> anyhow::Result<()> {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("fixtures/time-codec-chrono-0.4.45.jsonl");
        let stable: Vec<_> = self
            .0
            .iter()
            .filter(|record| !record.label.starts_with("live:"))
            .collect();
        if std::env::var("NORTHSTAR_TIME_BLESS").as_deref() == Ok("1") {
            use std::io::Write;
            std::fs::create_dir_all(path.parent().context("fixture directory")?)?;
            let mut output = std::io::BufWriter::new(std::fs::File::create(&path)?);
            for record in stable {
                writeln!(
                    output,
                    "{}",
                    json!({"label": record.label, "result": record.chrono}),
                )?;
            }
            output.flush()?;
            return Ok(());
        }
        let text = std::fs::read_to_string(&path).with_context(|| {
            format!(
                "read {}; generate against PostgreSQL with NORTHSTAR_TIME_BLESS=1",
                path.display(),
            )
        })?;
        let frozen: Vec<Value> = text
            .lines()
            .enumerate()
            .map(|(index, line)| {
                serde_json::from_str(line)
                    .with_context(|| format!("invalid fixture JSON on line {}", index + 1))
            })
            .collect::<anyhow::Result<_>>()?;
        ensure!(!frozen.is_empty(), "empty chrono PostgreSQL fixture");
        ensure!(
            frozen.len() == stable.len(),
            "fixture record count changed: frozen={}, actual={}; review before blessing",
            frozen.len(),
            stable.len(),
        );
        let mut failures = Vec::new();
        for (expected, actual) in frozen.iter().zip(stable) {
            let label = expected["label"]
                .as_str()
                .context("missing fixture label")?;
            let result = expected["result"]
                .as_str()
                .context("missing fixture result")?;
            if (label != actual.label || result != actual.northstar) && failures.len() < 20 {
                failures.push(format!(
                    "frozen {label}: {result}\nactual {}: {}",
                    actual.label, actual.northstar,
                ));
            }
        }
        ensure!(
            failures.is_empty(),
            "first frozen codec mismatches:\n{}",
            failures.join("\n\n"),
        );
        Ok(())
    }
}
