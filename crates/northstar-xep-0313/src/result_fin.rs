//! Models for MAM archived results, forwarded stanzas, fin completion envelopes, and metadata boundaries.

use crate::query::{ArchiveId, UtcTimestamp};

/// An archived message result item wrapped in XEP-0313 `<result>` and XEP-0297 `<forwarded>` envelopes.
#[derive(Clone, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct MamResult {
    /// Immutable archive UID for this archived message.
    pub id: ArchiveId,
    /// Client-specified query identifier (if provided in the query).
    pub query_id: Option<String>,
    /// Delayed delivery timestamp when the stanza originally occurred.
    pub delay_stamp: UtcTimestamp,
    /// The serialized archived XML stanza (e.g. `<message ...>...</message>`).
    pub forwarded_stanza: String,
}

/// A MAM completion response envelope (`<fin>`).
#[derive(Clone, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct MamFin {
    /// Whether this page returned all remaining results (`complete='true'`).
    pub complete: bool,
    /// Whether the archive order and IDs are stable across queries (`stable='true'`).
    pub stable: bool,
    /// First item in the page and its zero-based index in the full result set.
    pub first: Option<(ArchiveId, Option<u64>)>,
    /// Last item in the page.
    pub last: Option<ArchiveId>,
    /// Total count of matching items in the archive.
    pub count: Option<u64>,
}

impl Default for MamFin {
    fn default() -> Self {
        Self {
            complete: true,
            stable: true,
            first: None,
            last: None,
            count: None,
        }
    }
}

/// Timestamp and identifier boundary for an archive endpoint.
#[derive(Clone, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct MamMetadataBoundary {
    /// The archive message ID of the boundary.
    pub id: ArchiveId,
    /// The timestamp of the boundary message.
    pub timestamp: UtcTimestamp,
}

/// Archive metadata descriptor providing earliest and latest boundaries.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct MamMetadata {
    /// Earliest available message in the archive.
    pub start: Option<MamMetadataBoundary>,
    /// Latest available message in the archive.
    pub end: Option<MamMetadataBoundary>,
}
