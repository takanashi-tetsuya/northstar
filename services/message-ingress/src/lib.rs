//! Message Ingress Authority microservice.
//!
//! Defined per `northstar_microservices_deep_audit_2026-09-03.md` (Sections 5.1, 6, 12).

use chrono::Utc;
use foundation_contracts::common::ErrorDetail;
use foundation_contracts::events::MessageAcceptedEventPayload;
use foundation_contracts::ingress::{SubmitMessageRequest, SubmitMessageResponse};
use foundation_eventing::memory::InMemoryOutbox;
use foundation_eventing::OutboxEvent;
use std::collections::HashMap;
use std::sync::RwLock;
use uuid::Uuid;

pub const MAX_STANZA_BYTES: usize = 65_536;

#[derive(Debug, Clone)]
pub struct StoredAcceptedMessage {
    pub server_message_id: String,
    pub from_full_jid: String,
    pub to_jid: String,
    pub stanza_id: String,
    pub message_type: String,
    pub raw_stanza: Vec<u8>,
    pub admission_timestamp_ms: u64,
}

pub struct MessageIngressService {
    messages: RwLock<HashMap<String, StoredAcceptedMessage>>,
    outbox: InMemoryOutbox,
}

impl Default for MessageIngressService {
    fn default() -> Self {
        Self::new()
    }
}

impl MessageIngressService {
    pub fn new() -> Self {
        Self {
            messages: RwLock::new(HashMap::new()),
            outbox: InMemoryOutbox::new(),
        }
    }

    pub fn submit_message(&self, req: SubmitMessageRequest) -> SubmitMessageResponse {
        // Enforce maximum stanza size
        if req.raw_stanza.len() > MAX_STANZA_BYTES {
            return SubmitMessageResponse {
                accepted: false,
                server_message_id: String::new(),
                admission_timestamp_ms: 0,
                error: Some(ErrorDetail::new(
                    "RESOURCE_CONSTRAINT",
                    "Message stanza exceeds maximum size",
                )),
            };
        }

        // Validate sender authority: from_full_jid must match authenticated canonical JID
        let authenticated_bare = &req.auth.canonical_jid;
        if !req.from_full_jid.starts_with(authenticated_bare) {
            return SubmitMessageResponse {
                accepted: false,
                server_message_id: String::new(),
                admission_timestamp_ms: 0,
                error: Some(ErrorDetail::new(
                    "NOT_AUTHORIZED",
                    "Sender JID does not match authenticated identity",
                )),
            };
        }

        let server_message_id = Uuid::new_v4().to_string();
        let timestamp_ms = Utc::now().timestamp_millis() as u64;

        let accepted = StoredAcceptedMessage {
            server_message_id: server_message_id.clone(),
            from_full_jid: req.from_full_jid.clone(),
            to_jid: req.to_jid.clone(),
            stanza_id: req.stanza_id.clone(),
            message_type: req.message_type.clone(),
            raw_stanza: req.raw_stanza.clone(),
            admission_timestamp_ms: timestamp_ms,
        };

        // Transactional Outbox: atomically stage message.accepted event
        let payload = serde_json::to_vec(&MessageAcceptedEventPayload {
            server_message_id: server_message_id.clone(),
            from_full_jid: req.from_full_jid,
            to_jid: req.to_jid,
            stanza_id: req.stanza_id,
            message_type: req.message_type,
            raw_stanza: req.raw_stanza,
            timestamp_ms,
        })
        .unwrap_or_default();

        let event = OutboxEvent::new(
            "message",
            &server_message_id,
            1,
            "message.accepted.v1",
            payload,
        );
        self.outbox.stage(event);

        self.messages
            .write()
            .unwrap()
            .insert(server_message_id.clone(), accepted);

        SubmitMessageResponse {
            accepted: true,
            server_message_id,
            admission_timestamp_ms: timestamp_ms,
            error: None,
        }
    }

    pub fn pending_outbox(&self) -> Vec<OutboxEvent> {
        self.outbox.pending()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use foundation_contracts::common::AuthContext;

    #[test]
    fn message_admission_and_outbox_staging() {
        let ingress = MessageIngressService::new();
        let auth = AuthContext::new("acc-1", "alice@example.com", 1, "local");

        let req = SubmitMessageRequest {
            from_full_jid: "alice@example.com/mobile".to_string(),
            to_jid: "bob@example.com".to_string(),
            stanza_id: "client-id-1".to_string(),
            message_type: "chat".to_string(),
            raw_stanza: b"<message to='bob@example.com'><body>Hi Bob!</body></message>".to_vec(),
            auth: auth.clone(),
            trace: None,
        };

        let res = ingress.submit_message(req);
        assert!(res.accepted);
        assert!(!res.server_message_id.is_empty());

        let outbox = ingress.pending_outbox();
        assert_eq!(outbox.len(), 1);
        assert_eq!(outbox[0].event_type, "message.accepted.v1");
        assert_eq!(outbox[0].aggregate_id, res.server_message_id);
    }

    #[test]
    fn unauthorized_sender_rejected() {
        let ingress = MessageIngressService::new();
        let auth = AuthContext::new("acc-1", "alice@example.com", 1, "local");

        let spoofed = SubmitMessageRequest {
            from_full_jid: "eve@example.com/spoof".to_string(), // Spoofed!
            to_jid: "bob@example.com".to_string(),
            stanza_id: "client-id-2".to_string(),
            message_type: "chat".to_string(),
            raw_stanza: b"<message>hi</message>".to_vec(),
            auth,
            trace: None,
        };

        let res = ingress.submit_message(spoofed);
        assert!(!res.accepted);
        assert_eq!(res.error.unwrap().code, "NOT_AUTHORIZED");
    }
}
