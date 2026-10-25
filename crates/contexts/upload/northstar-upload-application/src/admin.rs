//! Administrator views of upload-recovery dead letters: kinds, identities, keyset boundaries and pages.

use chrono::{DateTime, Utc};
use uuid::{Uuid, Variant};
use zeroize::Zeroizing;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UploadDeadLetterKind {
    StorageJob,
    Cleanup,
}

impl UploadDeadLetterKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::StorageJob => "storage_job",
            Self::Cleanup => "cleanup",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "storage_job" => Some(Self::StorageJob),
            "cleanup" => Some(Self::Cleanup),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum UploadDeadLetterId {
    StorageJob(i64),
    /// Random administrator-facing recovery handle. This is deliberately not
    /// `upload_cleanup_queue.object_id`, which is also the local object key.
    Cleanup(Uuid),
}

impl UploadDeadLetterId {
    pub fn parse(kind: UploadDeadLetterKind, value: &str) -> Option<Self> {
        match kind {
            UploadDeadLetterKind::StorageJob => value
                .parse::<i64>()
                .ok()
                .filter(|id| *id > 0 && id.to_string() == value)
                .map(Self::StorageJob),
            UploadDeadLetterKind::Cleanup => Uuid::parse_str(value)
                .ok()
                .filter(|id| {
                    !id.is_nil()
                        && id.get_version_num() == 4
                        && id.get_variant() == Variant::RFC4122
                        && id.hyphenated().to_string() == value
                })
                .map(Self::Cleanup),
        }
    }

    pub fn as_api_string(self) -> String {
        match self {
            Self::StorageJob(id) => id.to_string(),
            Self::Cleanup(id) => id.to_string(),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UploadDeadLetterBoundary {
    StorageJob(i64),
    Cleanup(Uuid),
}

pub struct UploadDeadLetterRecord {
    pub id: UploadDeadLetterId,
    pub operation: String,
    pub attempts: i64,
    pub dead_lettered_at: DateTime<Utc>,
    pub available_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
    /// Never serialize this field directly. The HTTP boundary emits only a
    /// scrubbed, bounded categorical summary.
    pub last_error: Option<Zeroizing<String>>,
}

pub struct UploadDeadLetterPage {
    pub rows: Vec<UploadDeadLetterRecord>,
    pub next: Option<UploadDeadLetterBoundary>,
    pub database_now: DateTime<Utc>,
}
