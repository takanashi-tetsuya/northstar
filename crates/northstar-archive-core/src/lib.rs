//! Capability-free XEP-0313 MAM archive domain models, visibility projections,
//! and RSM paging boundaries.

#![forbid(unsafe_code)]

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ArchiveBoundary {
    pub id: Uuid,
    pub created_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ArchiveRow {
    pub id: Uuid,
    pub peer_jid: String,
    pub stanza: String,
    pub encrypted: bool,
    /// The client-provided stanza id, when one was present at admission.
    /// This is distinct from `id`, which is the immutable MAM archive UID.
    pub stanza_id: Option<String>,
    pub created_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ArchivePage {
    pub rows: Vec<ArchiveRow>,
    pub total: i64,
    pub first_index: i64,
    pub complete: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct MamPreferences {
    pub default_policy: String,
    pub always: Vec<String>,
    pub never: Vec<String>,
}

impl Default for MamPreferences {
    fn default() -> Self {
        Self {
            default_policy: "always".to_owned(),
            always: Vec::new(),
            never: Vec::new(),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MamRsmPage {
    First,
    Last,
    Before(Uuid),
    After(Uuid),
    Index(i64),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MamArchiveQuery {
    pub with_jid: Option<String>,
    pub start: Option<DateTime<Utc>>,
    pub end: Option<DateTime<Utc>>,
    pub before_id: Option<Uuid>,
    pub after_id: Option<Uuid>,
    pub ids: Vec<Uuid>,
    pub page: MamRsmPage,
    pub max: i64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MamRoomArchiveAccess {
    pub room_id: Uuid,
    pub localpart: String,
    pub occupant_id_secret: Vec<u8>,
    pub reveal_real_jid: bool,
}

impl MamRoomArchiveAccess {
    pub fn new(
        room_id: Uuid,
        localpart: String,
        occupant_id_secret: Vec<u8>,
        reveal_real_jid: bool,
    ) -> Self {
        Self {
            room_id,
            localpart,
            occupant_id_secret,
            reveal_real_jid,
        }
    }

    pub fn room_id(&self) -> Uuid {
        self.room_id
    }

    pub fn localpart(&self) -> &str {
        &self.localpart
    }

    pub fn occupant_id_secret(&self) -> &[u8] {
        &self.occupant_id_secret
    }

    pub fn reveal_real_jid(&self) -> bool {
        self.reveal_real_jid
    }
}

/// Repository-level read outcome containing full archive access including room ID.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum MamDbRoomReadOutcome<T> {
    Allowed {
        access: MamRoomArchiveAccess,
        value: T,
    },
    Missing,
    Forbidden,
}

/// Service-level read outcome exposing authorized room access (without room UUID).
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum MamRoomReadOutcome<T> {
    Allowed { access: MamRoomAccess, value: T },
    Missing,
    Forbidden,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MamRoomAccess {
    pub localpart: String,
    pub occupant_id_secret: Vec<u8>,
    pub reveal_real_jid: bool,
}

impl MamRoomAccess {
    pub fn new(localpart: String, occupant_id_secret: Vec<u8>, reveal_real_jid: bool) -> Self {
        Self {
            localpart,
            occupant_id_secret,
            reveal_real_jid,
        }
    }

    pub fn localpart(&self) -> &str {
        &self.localpart
    }

    pub fn occupant_id_secret(&self) -> &[u8] {
        &self.occupant_id_secret
    }

    pub fn reveal_real_jid(&self) -> bool {
        self.reveal_real_jid
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum MamRoomAccessOutcome {
    Allowed(MamRoomAccess),
    Missing,
    Forbidden,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct FederatedMamStreamRow {
    pub id: Uuid,
    pub peer_jid: String,
    pub stanza: String,
    pub created_at: DateTime<Utc>,
}

impl FederatedMamStreamRow {
    pub fn new(id: Uuid, peer_jid: String, stanza: String, created_at: DateTime<Utc>) -> Self {
        Self {
            id,
            peer_jid,
            stanza,
            created_at,
        }
    }

    pub fn id(&self) -> Uuid {
        self.id
    }

    pub fn peer_jid(&self) -> &str {
        &self.peer_jid
    }

    pub fn stanza(&self) -> &str {
        &self.stanza
    }

    pub fn created_at(&self) -> &DateTime<Utc> {
        &self.created_at
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FederatedMamStreamPage {
    pub access: MamRoomAccess,
    pub rows: Vec<FederatedMamStreamRow>,
    pub total: i64,
    pub first_index: i64,
    pub complete: bool,
}

impl FederatedMamStreamPage {
    pub fn new(
        access: MamRoomAccess,
        rows: Vec<FederatedMamStreamRow>,
        total: i64,
        first_index: i64,
        complete: bool,
    ) -> Self {
        Self {
            access,
            rows,
            total,
            first_index,
            complete,
        }
    }

    pub fn access(&self) -> &MamRoomAccess {
        &self.access
    }

    pub fn rows(&self) -> &[FederatedMamStreamRow] {
        &self.rows
    }

    pub fn total(&self) -> i64 {
        self.total
    }

    pub fn first_index(&self) -> i64 {
        self.first_index
    }

    pub fn complete(&self) -> bool {
        self.complete
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FederatedMamAdmissionOutcome {
    Queued,
    Missing,
    Forbidden,
    PageMissing,
    OutboxRejected,
}

/// Pure helper to check if a query's time range is logically valid (`start <= end`).
pub fn validate_query_time_range(start: Option<DateTime<Utc>>, end: Option<DateTime<Utc>>) -> bool {
    match (start, end) {
        (Some(start), Some(end)) => start <= end,
        _ => true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn time_range_validation() {
        let t1 = Utc::now();
        let t2 = t1 + chrono::Duration::seconds(60);
        assert!(validate_query_time_range(Some(t1), Some(t2)));
        assert!(validate_query_time_range(Some(t1), Some(t1)));
        assert!(!validate_query_time_range(Some(t2), Some(t1)));
        assert!(validate_query_time_range(Some(t1), None));
        assert!(validate_query_time_range(None, Some(t2)));
        assert!(validate_query_time_range(None, None));
    }

    #[test]
    fn preferences_default() {
        let prefs = MamPreferences::default();
        assert_eq!(prefs.default_policy, "always");
        assert!(prefs.always.is_empty());
        assert!(prefs.never.is_empty());
    }

    #[test]
    fn room_access_and_stream_rows() {
        let access = MamRoomAccess::new("general".to_string(), vec![1, 2, 3], false);
        assert_eq!(access.localpart(), "general");
        assert_eq!(access.occupant_id_secret(), &[1, 2, 3]);
        assert!(!access.reveal_real_jid());

        let id = Uuid::new_v4();
        let now = Utc::now();
        let row = FederatedMamStreamRow::new(
            id,
            "peer@example.test".to_string(),
            "<message/>".to_string(),
            now,
        );
        assert_eq!(row.id(), id);
        assert_eq!(row.peer_jid(), "peer@example.test");
        assert_eq!(row.stanza(), "<message/>");
        assert_eq!(row.created_at(), &now);
    }
}
