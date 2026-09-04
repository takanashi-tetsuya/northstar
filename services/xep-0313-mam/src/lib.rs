//! XEP-0313 Message Archive Management (MAM) microservice.
//!
//! Defined per `northstar_microservices_deep_audit_2026-09-03.md` (Sections 6, 7, 8, 19.2, 20.2).

use foundation_contracts::events::MessageAcceptedEventPayload;
use foundation_eventing::memory::InMemoryInbox;
use std::collections::HashMap;
use std::sync::RwLock;
use uuid::Uuid;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArchivedMessage {
    pub archive_id: String,
    pub scope_jid: String,
    pub server_message_id: String,
    pub from_jid: String,
    pub to_jid: String,
    pub raw_stanza: Vec<u8>,
    pub timestamp_ms: u64,
}

#[derive(Debug, Clone)]
pub struct MamQueryRequest {
    pub scope_jid: String,
    pub start_time_ms: Option<u64>,
    pub end_time_ms: Option<u64>,
    pub with_jid: Option<String>,
    pub max: usize,
    pub after: Option<String>,
}

#[derive(Debug, Clone)]
pub struct MamQueryResponse {
    pub messages: Vec<ArchivedMessage>,
    pub first_id: Option<String>,
    pub last_id: Option<String>,
    pub complete: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArchivePrincipal {
    pub account_id: Uuid,
    pub bare_jid: String,
    pub is_admin: bool,
}

impl ArchivePrincipal {
    pub fn user(account_id: Uuid, bare_jid: impl Into<String>) -> Self {
        Self {
            account_id,
            bare_jid: bare_jid.into(),
            is_admin: false,
        }
    }

    pub fn admin(account_id: Uuid, bare_jid: impl Into<String>) -> Self {
        Self {
            account_id,
            bare_jid: bare_jid.into(),
            is_admin: true,
        }
    }
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum MamQueryError {
    #[error("Invalid with_jid filter: '{0}' cannot be parsed as a canonical JID")]
    InvalidWithJid(String),
    #[error("Invalid time range: start_time_ms ({0}) > end_time_ms ({1})")]
    InvalidTimeRange(u64, u64),
    #[error("Invalid page size: max limit must be between 1 and 100, got {0}")]
    InvalidPageSize(usize),
    #[error("Unauthorized to access archive scope: principal '{0}' cannot access scope '{1}'")]
    UnauthorizedScope(String, String),
    #[error("Unknown or invalid cursor: '{0}'")]
    InvalidCursor(String),
}

pub struct MamService {
    inbox: InMemoryInbox,
    archives: RwLock<HashMap<String, Vec<ArchivedMessage>>>, // scope_jid -> archived items
}

impl Default for MamService {
    fn default() -> Self {
        Self::new()
    }
}

impl MamService {
    pub fn new() -> Self {
        Self {
            inbox: InMemoryInbox::new(),
            archives: RwLock::new(HashMap::new()),
        }
    }

    /// Ingests an accepted message from Kafka event stream with Consumer Inbox deduplication.
    pub fn ingest_message(&self, event_id: Uuid, msg: MessageAcceptedEventPayload) -> bool {
        if self.inbox.is_processed("mam_worker", event_id) {
            return false;
        }

        let from_bare = msg
            .from_full_jid
            .split('/')
            .next()
            .unwrap_or(&msg.from_full_jid)
            .to_string();
        let to_bare = msg
            .to_jid
            .split('/')
            .next()
            .unwrap_or(&msg.to_jid)
            .to_string();

        let item = ArchivedMessage {
            archive_id: Uuid::new_v4().to_string(),
            scope_jid: from_bare.clone(),
            server_message_id: msg.server_message_id,
            from_jid: msg.from_full_jid,
            to_jid: msg.to_jid,
            raw_stanza: msg.raw_stanza,
            timestamp_ms: msg.timestamp_ms,
        };

        let mut archives = self.archives.write().unwrap();
        // Index under sender's archive
        archives
            .entry(from_bare.clone())
            .or_default()
            .push(item.clone());

        // Index under recipient's archive if distinct
        if from_bare != to_bare {
            let mut recipient_item = item;
            recipient_item.scope_jid = to_bare.clone();
            archives.entry(to_bare).or_default().push(recipient_item);
        }

        self.inbox.record_processed("mam_worker", event_id);
        true
    }

    /// Queries message archive with caller authorization, fail-closed validation, and RSM cursor support.
    pub fn query_archive(
        &self,
        principal: &ArchivePrincipal,
        req: MamQueryRequest,
    ) -> Result<MamQueryResponse, MamQueryError> {
        // 1. Authorization check: scope JID must be normalized and principal must be owner or admin
        let parsed_scope =
            northstar_xmpp_types::CanonicalJid::parse(&req.scope_jid).map_err(|_| {
                MamQueryError::UnauthorizedScope(principal.bare_jid.clone(), req.scope_jid.clone())
            })?;

        if !principal.is_admin && principal.bare_jid != parsed_scope.bare() {
            return Err(MamQueryError::UnauthorizedScope(
                principal.bare_jid.clone(),
                req.scope_jid,
            ));
        }

        // 2. Strict with_jid validation (fail-closed)
        let parsed_with = match req.with_jid.as_deref() {
            Some(w) => Some(
                northstar_xmpp_types::CanonicalJid::parse(w)
                    .map_err(|_| MamQueryError::InvalidWithJid(w.to_string()))?,
            ),
            None => None,
        };

        // 3. Time range validation
        if let (Some(start), Some(end)) = (req.start_time_ms, req.end_time_ms) {
            if start > end {
                return Err(MamQueryError::InvalidTimeRange(start, end));
            }
        }

        // 4. Page size validation
        let max_limit = match req.max {
            0 => 50,
            m if m > 100 => return Err(MamQueryError::InvalidPageSize(m)),
            m => m,
        };

        let archives = self.archives.read().unwrap();
        let Some(items) = archives.get(&parsed_scope.bare()) else {
            return Ok(MamQueryResponse {
                messages: Vec::new(),
                first_id: None,
                last_id: None,
                complete: true,
            });
        };

        let mut filtered: Vec<ArchivedMessage> = items
            .iter()
            .filter(|m| {
                if let Some(start) = req.start_time_ms {
                    if m.timestamp_ms < start {
                        return false;
                    }
                }
                if let Some(end) = req.end_time_ms {
                    if m.timestamp_ms > end {
                        return false;
                    }
                }
                if let Some(ref target_with) = parsed_with {
                    let from_j = northstar_xmpp_types::CanonicalJid::parse(&m.from_jid).ok();
                    let to_j = northstar_xmpp_types::CanonicalJid::parse(&m.to_jid).ok();

                    let matches = if target_with.resourcepart().is_some() {
                        from_j.as_ref() == Some(target_with) || to_j.as_ref() == Some(target_with)
                    } else {
                        from_j.as_ref().map(|j| j.bare()) == Some(target_with.bare())
                            || to_j.as_ref().map(|j| j.bare()) == Some(target_with.bare())
                    };
                    if !matches {
                        return false;
                    }
                }
                true
            })
            .cloned()
            .collect();

        // Stable ordering by (timestamp_ms ASC, archive_id ASC)
        filtered.sort_by(|a, b| {
            a.timestamp_ms
                .cmp(&b.timestamp_ms)
                .then_with(|| a.archive_id.cmp(&b.archive_id))
        });

        // Cursor pagination
        let mut start_idx = 0;
        if let Some(ref after_id) = req.after {
            if let Some(pos) = filtered.iter().position(|m| &m.archive_id == after_id) {
                start_idx = pos + 1;
            } else {
                return Err(MamQueryError::InvalidCursor(after_id.clone()));
            }
        }

        let slice = &filtered[start_idx..];
        let take_count = slice.len().min(max_limit);
        let result_messages = slice[..take_count].to_vec();
        let complete = start_idx + take_count >= filtered.len();

        let first_id = result_messages.first().map(|m| m.archive_id.clone());
        let last_id = result_messages.last().map(|m| m.archive_id.clone());

        Ok(MamQueryResponse {
            messages: result_messages,
            first_id,
            last_id,
            complete,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mam_ingestion_and_rsm_query() {
        let mam = MamService::new();
        let event_id = Uuid::new_v4();

        let msg = MessageAcceptedEventPayload {
            server_message_id: "msg-101".to_string(),
            from_full_jid: "alice@example.com/laptop".to_string(),
            to_jid: "bob@example.com/mobile".to_string(),
            stanza_id: "client-a1".to_string(),
            message_type: "chat".to_string(),
            raw_stanza: b"<message>Hello Bob from archive</message>".to_vec(),
            timestamp_ms: 1000,
        };

        // 1. Ingest message
        assert!(mam.ingest_message(event_id, msg.clone()));

        // 2. Duplicate ingestion ignored by inbox
        assert!(!mam.ingest_message(event_id, msg));

        // 3. Query from Alice's scope as Alice
        let alice_principal = ArchivePrincipal::user(Uuid::new_v4(), "alice@example.com");
        let query_alice = mam
            .query_archive(
                &alice_principal,
                MamQueryRequest {
                    scope_jid: "alice@example.com".to_string(),
                    start_time_ms: None,
                    end_time_ms: None,
                    with_jid: None,
                    max: 10,
                    after: None,
                },
            )
            .expect("Alice query should succeed");

        assert_eq!(query_alice.messages.len(), 1);
        assert_eq!(query_alice.messages[0].server_message_id, "msg-101");
        assert!(query_alice.complete);

        // 4. Query from Bob's scope as Bob (bilateral indexing)
        let bob_principal = ArchivePrincipal::user(Uuid::new_v4(), "bob@example.com");
        let query_bob = mam
            .query_archive(
                &bob_principal,
                MamQueryRequest {
                    scope_jid: "bob@example.com".to_string(),
                    start_time_ms: None,
                    end_time_ms: None,
                    with_jid: None,
                    max: 10,
                    after: None,
                },
            )
            .expect("Bob query should succeed");

        assert_eq!(query_bob.messages.len(), 1);
        assert_eq!(query_bob.messages[0].server_message_id, "msg-101");
    }

    #[test]
    fn prefix_collision_with_jid_rejected() {
        let mam = MamService::new();
        let event_id = Uuid::new_v4();

        let msg = MessageAcceptedEventPayload {
            server_message_id: "msg-prefix-1".to_string(),
            from_full_jid: "alice@example.com/laptop".to_string(),
            to_jid: "bob@example.com/mobile".to_string(),
            stanza_id: "client-p1".to_string(),
            message_type: "chat".to_string(),
            raw_stanza: b"<message>For Bob only</message>".to_vec(),
            timestamp_ms: 2000,
        };
        assert!(mam.ingest_message(event_id, msg));

        let alice_principal = ArchivePrincipal::user(Uuid::new_v4(), "alice@example.com");

        // Attempt querying with a JID that starts with "bob" prefix but is a different user
        let query_bobby = mam
            .query_archive(
                &alice_principal,
                MamQueryRequest {
                    scope_jid: "alice@example.com".to_string(),
                    start_time_ms: None,
                    end_time_ms: None,
                    with_jid: Some("bobby@example.com".to_string()),
                    max: 10,
                    after: None,
                },
            )
            .unwrap();
        assert_eq!(query_bobby.messages.len(), 0);

        // Attempt querying with an attacker domain prefix collision
        let query_evil = mam
            .query_archive(
                &alice_principal,
                MamQueryRequest {
                    scope_jid: "alice@example.com".to_string(),
                    start_time_ms: None,
                    end_time_ms: None,
                    with_jid: Some("bob@example.com.evil.com".to_string()),
                    max: 10,
                    after: None,
                },
            )
            .unwrap();
        assert_eq!(query_evil.messages.len(), 0);

        // Querying with legitimate Bob succeeds
        let query_bob = mam
            .query_archive(
                &alice_principal,
                MamQueryRequest {
                    scope_jid: "alice@example.com".to_string(),
                    start_time_ms: None,
                    end_time_ms: None,
                    with_jid: Some("bob@example.com".to_string()),
                    max: 10,
                    after: None,
                },
            )
            .unwrap();
        assert_eq!(query_bob.messages.len(), 1);
        assert_eq!(query_bob.messages[0].server_message_id, "msg-prefix-1");
    }

    #[test]
    fn invalid_with_jid_fails_closed() {
        let mam = MamService::new();
        let alice_principal = ArchivePrincipal::user(Uuid::new_v4(), "alice@example.com");

        // Crucial security invariant: invalid with_jid must FAIL CLOSED, never ignored/fail-open
        let result = mam.query_archive(
            &alice_principal,
            MamQueryRequest {
                scope_jid: "alice@example.com".to_string(),
                start_time_ms: None,
                end_time_ms: None,
                with_jid: Some("not a valid jid@@@evil.com".to_string()),
                max: 10,
                after: None,
            },
        );

        match result {
            Err(MamQueryError::InvalidWithJid(j)) => {
                assert_eq!(j, "not a valid jid@@@evil.com");
            }
            _ => panic!("Expected InvalidWithJid error, got: {:?}", result),
        }
    }

    #[test]
    fn unauthorized_scope_query_rejected() {
        let mam = MamService::new();
        let eve_principal = ArchivePrincipal::user(Uuid::new_v4(), "eve@example.com");

        // Eve tries to query Alice's archive
        let result = mam.query_archive(
            &eve_principal,
            MamQueryRequest {
                scope_jid: "alice@example.com".to_string(),
                start_time_ms: None,
                end_time_ms: None,
                with_jid: None,
                max: 10,
                after: None,
            },
        );

        match result {
            Err(MamQueryError::UnauthorizedScope(principal_jid, scope)) => {
                assert_eq!(principal_jid, "eve@example.com");
                assert_eq!(scope, "alice@example.com");
            }
            _ => panic!("Expected UnauthorizedScope error, got: {:?}", result),
        }

        // Admin is authorized to query Alice's archive
        let admin_principal = ArchivePrincipal::admin(Uuid::new_v4(), "admin@example.com");
        let admin_result = mam.query_archive(
            &admin_principal,
            MamQueryRequest {
                scope_jid: "alice@example.com".to_string(),
                start_time_ms: None,
                end_time_ms: None,
                with_jid: None,
                max: 10,
                after: None,
            },
        );
        assert!(admin_result.is_ok());
    }

    #[test]
    fn missing_after_cursor_returns_error() {
        let mam = MamService::new();
        let event_id = Uuid::new_v4();

        let msg = MessageAcceptedEventPayload {
            server_message_id: "msg-cursor-1".to_string(),
            from_full_jid: "alice@example.com/laptop".to_string(),
            to_jid: "bob@example.com/mobile".to_string(),
            stanza_id: "client-c1".to_string(),
            message_type: "chat".to_string(),
            raw_stanza: b"<message>Testing cursor</message>".to_vec(),
            timestamp_ms: 3000,
        };
        assert!(mam.ingest_message(event_id, msg));

        let alice_principal = ArchivePrincipal::user(Uuid::new_v4(), "alice@example.com");

        // Query with an unknown cursor ID must return typed InvalidCursor error
        let result = mam.query_archive(
            &alice_principal,
            MamQueryRequest {
                scope_jid: "alice@example.com".to_string(),
                start_time_ms: None,
                end_time_ms: None,
                with_jid: None,
                max: 10,
                after: Some("nonexistent-stale-archive-id".to_string()),
            },
        );

        match result {
            Err(MamQueryError::InvalidCursor(c)) => {
                assert_eq!(c, "nonexistent-stale-archive-id");
            }
            _ => panic!("Expected InvalidCursor error, got: {:?}", result),
        }
    }

    #[test]
    fn start_after_end_returns_error() {
        let mam = MamService::new();
        let alice_principal = ArchivePrincipal::user(Uuid::new_v4(), "alice@example.com");

        // Query with start > end must return typed InvalidTimeRange error
        let result = mam.query_archive(
            &alice_principal,
            MamQueryRequest {
                scope_jid: "alice@example.com".to_string(),
                start_time_ms: Some(5000),
                end_time_ms: Some(2000),
                with_jid: None,
                max: 10,
                after: None,
            },
        );

        match result {
            Err(MamQueryError::InvalidTimeRange(5000, 2000)) => {}
            _ => panic!("Expected InvalidTimeRange error, got: {:?}", result),
        }
    }

    #[test]
    fn invalid_page_size_returns_error() {
        let mam = MamService::new();
        let alice_principal = ArchivePrincipal::user(Uuid::new_v4(), "alice@example.com");

        // Query with max > 100 must return typed InvalidPageSize error
        let result = mam.query_archive(
            &alice_principal,
            MamQueryRequest {
                scope_jid: "alice@example.com".to_string(),
                start_time_ms: None,
                end_time_ms: None,
                with_jid: None,
                max: 150,
                after: None,
            },
        );

        match result {
            Err(MamQueryError::InvalidPageSize(150)) => {}
            _ => panic!("Expected InvalidPageSize error, got: {:?}", result),
        }
    }
}
