use super::{Case, Span, Stamp};
use serde_json::Value;

impl Span {
    fn read(value: &Value) -> Result<Self, String> {
        let [seconds, nanos] = numbers(value)?;
        Ok(Self {
            seconds,
            nanos: u32::try_from(nanos).map_err(|e| e.to_string())?,
        })
    }
}
impl Stamp {
    fn read(value: &Value) -> Result<Self, String> {
        let [seconds, nanos, offset] = numbers(value)?;
        Ok(Self {
            seconds,
            nanos: u32::try_from(nanos).map_err(|e| e.to_string())?,
            offset: i32::try_from(offset).map_err(|e| e.to_string())?,
        })
    }
}
fn string(value: &Value, key: &str) -> Result<String, String> {
    value[key]
        .as_str()
        .map(str::to_string)
        .ok_or_else(|| format!("missing string {key}"))
}
fn integer(value: &Value, key: &str) -> Result<i64, String> {
    value[key]
        .as_i64()
        .ok_or_else(|| format!("missing integer {key}"))
}
fn optional_string(value: &Value, key: &str) -> Result<Option<String>, String> {
    if value[key].is_null() {
        Ok(None)
    } else {
        string(value, key).map(Some)
    }
}
fn numbers<const N: usize>(value: &Value) -> Result<[i64; N], String> {
    let array = value.as_array().ok_or("expected array")?;
    let values: Vec<_> = array
        .iter()
        .map(|v| v.as_i64().ok_or_else(|| "expected integer".to_string()))
        .collect::<Result<_, _>>()?;
    values
        .try_into()
        .map_err(|_| format!("expected {N} integers"))
}
impl Case {
    pub fn from_json(v: &Value) -> Result<Self, String> {
        Ok(match string(v, "type")?.as_str() {
            "delta" => Self::Delta {
                op: string(v, "op")?,
                a: Span::read(&v["a"])?,
                b: Span::read(&v["b"])?,
                factor: integer(v, "factor")?
                    .try_into()
                    .map_err(|e: std::num::TryFromIntError| e.to_string())?,
            },
            "date" => Self::Date {
                op: string(v, "op")?,
                ymd: numbers(&v["ymd"])?,
                hmsn: numbers(&v["hmsn"])?,
                other_days: integer(v, "other_days")?
                    .try_into()
                    .map_err(|e: std::num::TryFromIntError| e.to_string())?,
                delta: Span::read(&v["delta"])?,
            },
            "time" => Self::Time {
                op: string(v, "op")?,
                hmsn: numbers(&v["hmsn"])?,
                other: numbers(&v["other"])?,
                delta: Span::read(&v["delta"])?,
            },
            "naive" => Self::Naive {
                op: string(v, "op")?,
                a: Stamp::read(&v["a"])?,
                b: Stamp::read(&v["b"])?,
                delta: Span::read(&v["delta"])?,
            },
            "timestamp" => Self::Timestamp {
                op: string(v, "op")?,
                value: integer(v, "value")?,
                nanos: integer(v, "nanos")?
                    .try_into()
                    .map_err(|e: std::num::TryFromIntError| e.to_string())?,
                offset: integer(v, "offset")?
                    .try_into()
                    .map_err(|e: std::num::TryFromIntError| e.to_string())?,
            },
            "zoned" => Self::Zoned {
                op: string(v, "op")?,
                a: Stamp::read(&v["a"])?,
                b: Stamp::read(&v["b"])?,
                delta: Span::read(&v["delta"])?,
                format: string(v, "format")?,
                precision: integer(v, "precision")?
                    .try_into()
                    .map_err(|e: std::num::TryFromIntError| e.to_string())?,
                use_z: v["use_z"].as_bool().ok_or("missing use_z")?,
            },
            "local" => Self::Local {
                offset: integer(v, "offset")?
                    .try_into()
                    .map_err(|e: std::num::TryFromIntError| e.to_string())?,
                ymd: numbers(&v["ymd"])?,
                hms: numbers(&v["hms"])?,
                utc: v["utc"].as_bool().ok_or("missing utc")?,
            },
            "offset" => Self::Offset {
                op: string(v, "op")?,
                value: integer(v, "value")?
                    .try_into()
                    .map_err(|e: std::num::TryFromIntError| e.to_string())?,
            },
            "mapping" => Self::Mapping {
                op: string(v, "op")?,
                variant: integer(v, "variant")?
                    .try_into()
                    .map_err(|e: std::num::TryFromIntError| e.to_string())?,
                a: integer(v, "a")?,
                b: integer(v, "b")?,
            },
            "parse" => Self::Parse {
                target: string(v, "target")?,
                input: string(v, "input")?,
                format: optional_string(v, "format")?,
            },
            "serde" => Self::Serde {
                target: string(v, "target")?,
                input: optional_string(v, "input")?,
                stamp: Stamp::read(&v["stamp"])?,
            },
            "postgres" => Self::Postgres {
                target: string(v, "target")?,
                stamp: Stamp::read(&v["stamp"])?,
            },
            "system" => Self::System {
                op: string(v, "op")?,
                seconds: integer(v, "seconds")?,
                nanos: integer(v, "nanos")?
                    .try_into()
                    .map_err(|e: std::num::TryFromIntError| e.to_string())?,
            },
            "constants" => Self::Constants,
            kind => return Err(format!("unknown case type {kind}")),
        })
    }
}
