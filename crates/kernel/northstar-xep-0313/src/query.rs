//! Query and filter data models, validated identifiers, timestamps, and paging modes.

use crate::constants::{MAX_ARCHIVE_ID_BYTES, MAX_MAM_IDS, MAX_MAM_RESULTS, MAX_QUERY_ID_BYTES};
use crate::error::MamError;
use northstar_xmpp_types::CanonicalJid;
use std::fmt;

/// A validated, bounded archive message identifier (normalized canonical representation).
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ArchiveId(String);

impl ArchiveId {
    /// Parse and validate a message archive identifier.
    ///
    /// Archive IDs in Northstar are strictly formatted UUIDs (36-character hyphenated hexadecimal).
    /// If the identifier is syntactically invalid, `MamError::ItemNotFound` is returned per XEP-0313.
    pub fn parse(value: &str) -> Result<Self, MamError> {
        let trimmed = value.trim();
        if trimmed.is_empty() || trimmed.len() > MAX_ARCHIVE_ID_BYTES || trimmed != value {
            return Err(MamError::ItemNotFound(
                "archive ID is empty or contains whitespace",
            ));
        }
        if trimmed.chars().any(char::is_control) {
            return Err(MamError::ItemNotFound(
                "archive ID contains control characters",
            ));
        }
        if !is_valid_uuid(trimmed) {
            return Err(MamError::ItemNotFound("archive ID is not a valid UUID"));
        }
        Ok(Self(trimmed.to_ascii_lowercase()))
    }

    /// Return the string slice of the archive ID.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for ArchiveId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl AsRef<str> for ArchiveId {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

fn is_valid_uuid(s: &str) -> bool {
    if s.len() != 36 {
        return false;
    }
    let bytes = s.as_bytes();
    for (i, &b) in bytes.iter().enumerate() {
        if i == 8 || i == 13 || i == 18 || i == 23 {
            if b != b'-' {
                return false;
            }
        } else if !b.is_ascii_hexdigit() {
            return false;
        }
    }
    true
}

/// A validated RFC 3339 / ISO 8601 UTC timestamp.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct UtcTimestamp {
    /// Total nanoseconds since the Unix epoch (1970-01-01T00:00:00Z).
    epoch_nanos: i128,
}

impl UtcTimestamp {
    /// Construct a [`UtcTimestamp`] from epoch nanoseconds.
    pub const fn from_epoch_nanos(nanos: i128) -> Self {
        Self { epoch_nanos: nanos }
    }

    /// Construct a [`UtcTimestamp`] from epoch milliseconds.
    pub const fn from_epoch_millis(millis: i64) -> Self {
        Self {
            epoch_nanos: (millis as i128) * 1_000_000,
        }
    }

    /// Construct a [`UtcTimestamp`] from epoch seconds.
    pub const fn from_epoch_secs(secs: i64) -> Self {
        Self {
            epoch_nanos: (secs as i128) * 1_000_000_000,
        }
    }

    /// Return the total nanoseconds since Unix epoch.
    pub const fn epoch_nanos(&self) -> i128 {
        self.epoch_nanos
    }

    /// Return the total milliseconds since Unix epoch.
    pub const fn epoch_millis(&self) -> i64 {
        (self.epoch_nanos / 1_000_000) as i64
    }

    /// Return the total seconds since Unix epoch.
    pub const fn epoch_secs(&self) -> i64 {
        (self.epoch_nanos / 1_000_000_000) as i64
    }

    /// Parse an RFC 3339 timestamp string into a normalized [`UtcTimestamp`].
    pub fn parse(value: &str) -> Result<Self, MamError> {
        let bytes = value.as_bytes();
        if bytes.len() < 20 || bytes.len() > 64 {
            return Err(MamError::BadRequest("invalid timestamp length"));
        }

        // Parse Year YYYY
        let year = parse_four_digits(&bytes[0..4])
            .ok_or(MamError::BadRequest("invalid year in timestamp"))?;
        if year == 0 || bytes[4] != b'-' {
            return Err(MamError::BadRequest("invalid timestamp year separator"));
        }

        // Parse Month MM
        let month = parse_two_digits(bytes[5], bytes[6])
            .ok_or(MamError::BadRequest("invalid month in timestamp"))?;
        if !(1..=12).contains(&month) || bytes[7] != b'-' {
            return Err(MamError::BadRequest("invalid timestamp month"));
        }

        // Parse Day DD
        let day = parse_two_digits(bytes[8], bytes[9])
            .ok_or(MamError::BadRequest("invalid day in timestamp"))?;
        let max_day = match month {
            2 if is_leap_year(year) => 29,
            2 => 28,
            4 | 6 | 9 | 11 => 30,
            _ => 31,
        };
        if !(1..=max_day).contains(&day) {
            return Err(MamError::BadRequest("invalid day for month in timestamp"));
        }

        if bytes[10] != b'T' && bytes[10] != b't' {
            return Err(MamError::BadRequest("missing T separator in timestamp"));
        }

        // Parse Hour HH
        let hour = parse_two_digits(bytes[11], bytes[12])
            .ok_or(MamError::BadRequest("invalid hour in timestamp"))?;
        if hour > 23 || bytes[13] != b':' {
            return Err(MamError::BadRequest("invalid hour in timestamp"));
        }

        // Parse Minute MM
        let minute = parse_two_digits(bytes[14], bytes[15])
            .ok_or(MamError::BadRequest("invalid minute in timestamp"))?;
        if minute > 59 || bytes[16] != b':' {
            return Err(MamError::BadRequest("invalid minute in timestamp"));
        }

        // Parse Second SS
        let second = parse_two_digits(bytes[17], bytes[18])
            .ok_or(MamError::BadRequest("invalid second in timestamp"))?;
        if second > 59 {
            return Err(MamError::BadRequest("invalid second in timestamp"));
        }

        let mut cursor = 19;
        let mut nanos: u32 = 0;

        // Optional fractional seconds: .fff...
        if cursor < bytes.len() && bytes[cursor] == b'.' {
            cursor += 1;
            let fraction_start = cursor;
            while cursor < bytes.len() && bytes[cursor].is_ascii_digit() {
                cursor += 1;
            }
            if cursor == fraction_start {
                return Err(MamError::BadRequest(
                    "empty fractional seconds in timestamp",
                ));
            }
            let fraction_str = &value[fraction_start..cursor];
            let mut scale: u32 = 100_000_000;
            for &b in fraction_str.as_bytes().iter().take(9) {
                nanos += ((b - b'0') as u32) * scale;
                scale /= 10;
            }
        }

        if cursor >= bytes.len() {
            return Err(MamError::BadRequest("missing timezone offset in timestamp"));
        }

        // Parse timezone offset: Z, z, +HH:MM, or -HH:MM
        let offset_secs: i64 = match bytes[cursor] {
            b'Z' | b'z' => {
                if cursor + 1 != bytes.len() {
                    return Err(MamError::BadRequest("extra content after Z in timestamp"));
                }
                0
            }
            b'+' | b'-' => {
                let sign = if bytes[cursor] == b'+' { 1 } else { -1 };
                cursor += 1;
                if bytes.len() != cursor + 5 || bytes[cursor + 2] != b':' {
                    return Err(MamError::BadRequest("invalid timezone offset format"));
                }
                let off_h = parse_two_digits(bytes[cursor], bytes[cursor + 1])
                    .ok_or(MamError::BadRequest("invalid timezone offset hour"))?;
                let off_m = parse_two_digits(bytes[cursor + 3], bytes[cursor + 4])
                    .ok_or(MamError::BadRequest("invalid timezone offset minute"))?;
                if off_h > 14 || off_m > 59 || (off_h == 14 && off_m != 0) {
                    return Err(MamError::BadRequest("timezone offset out of range"));
                }
                sign * ((off_h as i64) * 3600 + (off_m as i64) * 60)
            }
            _ => return Err(MamError::BadRequest("invalid timezone designator")),
        };

        let days = days_from_civil(year as i64, month as u64, day as u64);
        let time_secs = (hour as i64) * 3600 + (minute as i64) * 60 + (second as i64);
        let epoch_secs = days * 86400 + time_secs - offset_secs;
        let epoch_nanos = (epoch_secs as i128) * 1_000_000_000 + (nanos as i128);

        Ok(Self { epoch_nanos })
    }

    /// Format the timestamp as a canonical RFC 3339 UTC string with millisecond precision.
    pub fn to_rfc3339_millis(&self) -> String {
        let (year, month, day, hour, minute, second, millis) = self.decompose();
        format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}.{millis:03}Z")
    }

    /// Format the timestamp as a canonical RFC 3339 UTC string with second precision.
    pub fn to_rfc3339_secs(&self) -> String {
        let (year, month, day, hour, minute, second, _) = self.decompose();
        format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}Z")
    }

    fn decompose(&self) -> (i64, u32, u32, u32, u32, u32, u32) {
        let total_nanos = self.epoch_nanos;
        let total_secs = total_nanos.div_euclid(1_000_000_000) as i64;
        let rem_nanos = total_nanos.rem_euclid(1_000_000_000) as u32;
        let millis = rem_nanos / 1_000_000;

        let days = total_secs.div_euclid(86400);
        let rem_secs = total_secs.rem_euclid(86400) as u32;

        let hour = rem_secs / 3600;
        let minute = (rem_secs % 3600) / 60;
        let second = rem_secs % 60;

        let (year, month, day) = civil_from_days(days);
        (year, month, day, hour, minute, second, millis)
    }
}

impl fmt::Display for UtcTimestamp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_rfc3339_millis())
    }
}

const fn parse_four_digits(bytes: &[u8]) -> Option<u16> {
    if !bytes[0].is_ascii_digit()
        || !bytes[1].is_ascii_digit()
        || !bytes[2].is_ascii_digit()
        || !bytes[3].is_ascii_digit()
    {
        return None;
    }
    Some(
        (bytes[0] - b'0') as u16 * 1000
            + (bytes[1] - b'0') as u16 * 100
            + (bytes[2] - b'0') as u16 * 10
            + (bytes[3] - b'0') as u16,
    )
}

const fn parse_two_digits(b1: u8, b2: u8) -> Option<u8> {
    if !b1.is_ascii_digit() || !b2.is_ascii_digit() {
        return None;
    }
    Some((b1 - b'0') * 10 + (b2 - b'0'))
}

const fn is_leap_year(year: u16) -> bool {
    year.is_multiple_of(4) && (!year.is_multiple_of(100) || year.is_multiple_of(400))
}

const fn days_from_civil(mut y: i64, m: u64, d: u64) -> i64 {
    y -= (m <= 2) as i64;
    let era = (if y >= 0 { y } else { y - 399 }) / 400;
    let yoe = (y - era * 400) as u64;
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146097 + doe as i64 - 719468
}

fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719468;
    let era = (if z >= 0 { z } else { z - 146096 }) / 146097;
    let doe = (z - era * 146097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = (if mp < 10 { mp + 3 } else { mp - 9 }) as u32;
    let y = y + (m <= 2) as i64;
    (y, m, d)
}

/// Keyset and index-based Result Set Management paging modes for MAM queries.
#[derive(Clone, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum MamRsmPage {
    /// Retrieve the first page of results starting from the oldest matching item.
    First,
    /// Retrieve the last page of results ending at the newest matching item (`<before/>`).
    Last,
    /// Keyset paging: retrieve items strictly before the specified archive ID.
    Before(ArchiveId),
    /// Keyset paging: retrieve items strictly after the specified archive ID.
    After(ArchiveId),
    /// Offset paging: retrieve items starting at the zero-based result index.
    Index(u64),
}

/// Filter criteria specified in an extended MAM query form.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct MamFilter {
    /// Filter results to conversations with this specific peer entity.
    pub with_jid: Option<CanonicalJid>,
    /// Filter results to items on or after this timestamp.
    pub start: Option<UtcTimestamp>,
    /// Filter results to items on or before this timestamp.
    pub end: Option<UtcTimestamp>,
    /// Filter results to items strictly preceding this message archive ID.
    pub before_id: Option<ArchiveId>,
    /// Filter results to items strictly following this message archive ID.
    pub after_id: Option<ArchiveId>,
    /// Specific list of archive IDs to retrieve (up to [`MAX_MAM_IDS`]).
    pub ids: Vec<ArchiveId>,
}

impl MamFilter {
    /// Validate filter constraints (e.g. `start <= end`, `ids.len() <= MAX_MAM_IDS`).
    pub fn validate(&self) -> Result<(), MamError> {
        if let (Some(start), Some(end)) = (self.start, self.end) {
            if start > end {
                return Err(MamError::BadRequest(
                    "start timestamp is after end timestamp",
                ));
            }
        }
        if self.ids.len() > MAX_MAM_IDS {
            return Err(MamError::ResourceConstraint(
                "too many IDs requested in filter",
            ));
        }
        Ok(())
    }
}

/// A complete, validated XEP-0313 MAM query request.
#[derive(Clone, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct MamQuery {
    /// Extended search and archive filter parameters.
    pub filter: MamFilter,
    /// Page selection mode (RSM or default).
    pub page: MamRsmPage,
    /// Maximum number of results requested (bounded to [`MAX_MAM_RESULTS`]).
    pub max: u32,
    /// Client-specified correlation query ID.
    pub query_id: Option<String>,
    /// Whether the page ordering should be reversed for client presentation.
    pub flip_page: bool,
}

impl Default for MamQuery {
    fn default() -> Self {
        Self {
            filter: MamFilter::default(),
            page: MamRsmPage::First,
            max: MAX_MAM_RESULTS,
            query_id: None,
            flip_page: false,
        }
    }
}

impl MamQuery {
    /// Validate query parameters and limits.
    pub fn validate(&self) -> Result<(), MamError> {
        self.filter.validate()?;
        if let Some(query_id) = &self.query_id {
            if query_id.len() > MAX_QUERY_ID_BYTES || query_id.chars().any(char::is_control) {
                return Err(MamError::BadRequest("invalid queryid attribute"));
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_and_formats_timestamps() {
        let ts = UtcTimestamp::parse("2026-09-02T15:25:08.123Z").unwrap();
        assert_eq!(ts.to_rfc3339_millis(), "2026-09-02T15:25:08.123Z");
        assert_eq!(ts.to_rfc3339_secs(), "2026-09-02T15:25:08Z");

        let offset_ts = UtcTimestamp::parse("2026-09-02T18:25:08.123+03:00").unwrap();
        assert_eq!(ts, offset_ts);

        assert!(UtcTimestamp::parse("invalid").is_err());
        assert!(UtcTimestamp::parse("2026-13-01T00:00:00Z").is_err());
        assert!(UtcTimestamp::parse("2026-02-29T00:00:00Z").is_err());
        assert!(UtcTimestamp::parse("2024-02-29T00:00:00Z").is_ok());
    }

    #[test]
    fn timestamp_ordering() {
        let early = UtcTimestamp::parse("2026-09-02T10:00:00Z").unwrap();
        let late = UtcTimestamp::parse("2026-09-02T12:00:00Z").unwrap();
        assert!(early < late);
    }

    #[test]
    fn archive_id_validation() {
        assert!(ArchiveId::parse("de305d54-75b4-431b-adb2-eb6b9e546013").is_ok());
        assert_eq!(
            ArchiveId::parse("DE305D54-75B4-431B-ADB2-EB6B9E546013")
                .unwrap()
                .as_str(),
            "de305d54-75b4-431b-adb2-eb6b9e546013"
        );
        assert_eq!(
            ArchiveId::parse("not-a-server-id"),
            Err(MamError::ItemNotFound("archive ID is not a valid UUID"))
        );
        assert_eq!(
            ArchiveId::parse(""),
            Err(MamError::ItemNotFound(
                "archive ID is empty or contains whitespace"
            ))
        );
    }
}
