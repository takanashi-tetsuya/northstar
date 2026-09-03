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
            .unwrap_or(&msg.from_full_jid);
        let to_bare = msg.to_jid.split('/').next().unwrap_or(&msg.to_jid);

        let archive_id = Uuid::new_v4().to_string();
        let item = ArchivedMessage {
            archive_id: archive_id.clone(),
            scope_jid: from_bare.to_string(),
            server_message_id: msg.server_message_id.clone(),
            from_jid: msg.from_full_jid.clone(),
            to_jid: msg.to_jid.clone(),
            raw_stanza: msg.raw_stanza.clone(),
            timestamp_ms: msg.timestamp_ms,
        };

        let mut archives = self.archives.write().unwrap();
        // Index under sender's archive
        archives
            .entry(from_bare.to_string())
            .or_default()
            .push(item.clone());

        // Index under recipient's archive if distinct
        if from_bare != to_bare {
            let mut recipient_item = item;
            recipient_item.scope_jid = to_bare.to_string();
            archives
                .entry(to_bare.to_string())
                .or_default()
                .push(recipient_item);
        }

        self.inbox.record_processed("mam_worker", event_id);
        true
    }

    /// Queries message archive with RSM cursor support.
    pub fn query_archive(&self, req: MamQueryRequest) -> MamQueryResponse {
        let archives = self.archives.read().unwrap();
        let Some(items) = archives.get(&req.scope_jid) else {
            return MamQueryResponse {
                messages: Vec::new(),
                first_id: None,
                last_id: None,
                complete: true,
            };
        };

        let max_limit = if req.max == 0 || req.max > 100 {
            50
        } else {
            req.max
        };

        let filtered: Vec<ArchivedMessage> = items
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
                if let Some(ref with) = req.with_jid {
                    if !m.from_jid.starts_with(with) && !m.to_jid.starts_with(with) {
                        return false;
                    }
                }
                true
            })
            .cloned()
            .collect();

        // Cursor pagination
        let mut start_idx = 0;
        if let Some(ref after_id) = req.after {
            if let Some(pos) = filtered.iter().position(|m| &m.archive_id == after_id) {
                start_idx = pos + 1;
            }
        }

        let slice = &filtered[start_idx..];
        let take_count = slice.len().min(max_limit);
        let result_messages = slice[..take_count].to_vec();
        let complete = start_idx + take_count >= filtered.len();

        let first_id = result_messages.first().map(|m| m.archive_id.clone());
        let last_id = result_messages.last().map(|m| m.archive_id.clone());

        MamQueryResponse {
            messages: result_messages,
            first_id,
            last_id,
            complete,
        }
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

        // 3. Query from Alice's scope
        let query_alice = mam.query_archive(MamQueryRequest {
            scope_jid: "alice@example.com".to_string(),
            start_time_ms: None,
            end_time_ms: None,
            with_jid: None,
            max: 10,
            after: None,
        });

        assert_eq!(query_alice.messages.len(), 1);
        assert_eq!(query_alice.messages[0].server_message_id, "msg-101");
        assert!(query_alice.complete);

        // 4. Query from Bob's scope (bilateral indexing)
        let query_bob = mam.query_archive(MamQueryRequest {
            scope_jid: "bob@example.com".to_string(),
            start_time_ms: None,
            end_time_ms: None,
            with_jid: None,
            max: 10,
            after: None,
        });

        assert_eq!(query_bob.messages.len(), 1);
        assert_eq!(query_bob.messages[0].server_message_id, "msg-101");
    }
}
