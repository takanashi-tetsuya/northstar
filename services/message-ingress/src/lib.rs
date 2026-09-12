//! Message Ingress Authority microservice.
//!
//! Defined per `northstar_microservices_deep_audit_2026-09-03.md` (Sections 5.1, 6, 12).

use chrono::Utc;
use foundation_contracts::adapters::common::ErrorDetail;
use foundation_contracts::adapters::events::MessageAcceptedEventPayload;
use foundation_contracts::adapters::ingress::{SubmitMessageRequest, SubmitMessageResponse};
use foundation_eventing::memory::InMemoryOutbox;
use foundation_eventing::OutboxEvent;
use std::collections::HashMap;
use std::sync::{Mutex, RwLock};
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
    idempotency: Mutex<HashMap<String, (Vec<u8>, SubmitMessageResponse)>>,
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
            idempotency: Mutex::new(HashMap::new()),
            outbox: InMemoryOutbox::new(),
        }
    }

    pub fn submit_message(&self, req: SubmitMessageRequest) -> SubmitMessageResponse {
        let fingerprint = req.idempotency_key.as_ref().map(|_| {
            use sha2::{Digest, Sha256};
            let mut hasher = Sha256::new();
            hasher.update(req.from_full_jid.as_bytes());
            hasher.update([0]);
            hasher.update(req.to_jid.as_bytes());
            hasher.update([0]);
            hasher.update(req.stanza_id.as_bytes());
            hasher.update([0]);
            hasher.update(req.message_type.as_bytes());
            hasher.update([0]);
            hasher.update(&req.raw_stanza);
            if let Some(canonical) = &req.canonical_input {
                hasher.update(&canonical.payload);
                hasher.update(canonical.origin_id.as_bytes());
            }
            hasher.finalize().to_vec()
        });
        let idempotency_key = req
            .idempotency_key
            .as_ref()
            .map(|key| key.as_str().to_owned());
        let mut idempotency_guard = self.idempotency.lock().unwrap();
        if let (Some(key), Some(fingerprint)) = (&idempotency_key, &fingerprint) {
            if let Some((previous, response)) = idempotency_guard.get(key) {
                if previous == fingerprint {
                    return response.clone();
                }
                return SubmitMessageResponse {
                    accepted: false,
                    server_message_id: String::new(),
                    admission_timestamp_ms: 0,
                    error: Some(ErrorDetail::new(
                        "CONFLICT",
                        "Idempotency key was used with a different message",
                    )),
                };
            }
        }
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
        let sender_jid = match northstar_xmpp_types::CanonicalJid::parse(&req.from_full_jid) {
            Ok(j) => j,
            Err(_) => {
                return SubmitMessageResponse {
                    accepted: false,
                    server_message_id: String::new(),
                    admission_timestamp_ms: 0,
                    error: Some(ErrorDetail::new(
                        "JABBER_ID_MALFORMED",
                        "Sender JID cannot be parsed",
                    )),
                };
            }
        };

        let auth_jid = match northstar_xmpp_types::CanonicalJid::parse(&req.auth.canonical_jid) {
            Ok(j) => j,
            Err(_) => {
                return SubmitMessageResponse {
                    accepted: false,
                    server_message_id: String::new(),
                    admission_timestamp_ms: 0,
                    error: Some(ErrorDetail::new(
                        "NOT_AUTHORIZED",
                        "Authenticated identity JID is invalid",
                    )),
                };
            }
        };

        if sender_jid.bare() != auth_jid.bare() {
            return SubmitMessageResponse {
                accepted: false,
                server_message_id: String::new(),
                admission_timestamp_ms: 0,
                error: Some(ErrorDetail::new(
                    "NOT_AUTHORIZED",
                    "Sender bare JID does not match authenticated identity",
                )),
            };
        }

        if let Some(canonical) = &req.canonical_input {
            if canonical.from_full_jid != req.from_full_jid
                || canonical.to_jid != req.to_jid
                || canonical.stanza_id != req.stanza_id
                || canonical.message_type != req.message_type
            {
                return SubmitMessageResponse {
                    accepted: false,
                    server_message_id: String::new(),
                    admission_timestamp_ms: 0,
                    error: Some(ErrorDetail::new(
                        "INVALID_ARGUMENT",
                        "Canonical message input does not match the request",
                    )),
                };
            }
        }
        if let Some(assertion) = &req.session_assertion {
            if assertion
                .validate_at(Utc::now(), "message-ingress")
                .is_err()
                || assertion.account_id != req.auth.account_id
                || assertion.bare_jid != auth_jid.bare()
            {
                return SubmitMessageResponse {
                    accepted: false,
                    server_message_id: String::new(),
                    admission_timestamp_ms: 0,
                    error: Some(ErrorDetail::new(
                        "UNAUTHENTICATED",
                        "Session assertion is invalid",
                    )),
                };
            }
        }

        // Generate time-sortable, monotonic-per-node UUIDv7 message ID
        let server_message_id = Uuid::now_v7().to_string();
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

        let response = SubmitMessageResponse {
            accepted: true,
            server_message_id,
            admission_timestamp_ms: timestamp_ms,
            error: None,
        };
        if let (Some(key), Some(fingerprint)) = (idempotency_key, fingerprint) {
            idempotency_guard.insert(key, (fingerprint, response.clone()));
        }
        response
    }

    pub fn pending_outbox(&self) -> Vec<OutboxEvent> {
        self.outbox.pending()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use foundation_contracts::adapters::common::AuthContext;

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
            idempotency_key: None,
            session_assertion: None,
            canonical_input: None,
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
            idempotency_key: None,
            session_assertion: None,
            canonical_input: None,
            trace: None,
        };

        let res = ingress.submit_message(spoofed);
        assert!(!res.accepted);
        assert_eq!(res.error.unwrap().code, "NOT_AUTHORIZED");
    }

    #[test]
    fn prefix_collision_spoofing_rejected() {
        let ingress = MessageIngressService::new();
        let auth = AuthContext::new("acc-1", "alice@example.com", 1, "local");

        // Alice.evil domain suffix should NOT match alice@example.com even though it starts with the string
        let collision_attack = SubmitMessageRequest {
            from_full_jid: "alice@example.com.evil/desktop".to_string(),
            to_jid: "bob@example.com".to_string(),
            stanza_id: "client-id-evil".to_string(),
            message_type: "chat".to_string(),
            raw_stanza: b"<message>phishing</message>".to_vec(),
            auth,
            idempotency_key: None,
            session_assertion: None,
            canonical_input: None,
            trace: None,
        };

        let res = ingress.submit_message(collision_attack);
        assert!(!res.accepted);
        assert_eq!(res.error.unwrap().code, "NOT_AUTHORIZED");
    }

    #[test]
    fn idempotency_replays_same_message_and_conflicts_on_changed_payload() {
        use foundation_contracts::adapters::common::IdempotencyKey;

        let ingress = MessageIngressService::new();
        let auth = AuthContext::new("acc-idem", "alice@example.com", 1, "local");
        let request = |body: &[u8]| SubmitMessageRequest {
            from_full_jid: "alice@example.com/mobile".to_owned(),
            to_jid: "bob@example.com".to_owned(),
            stanza_id: "idempotent-1".to_owned(),
            message_type: "chat".to_owned(),
            raw_stanza: body.to_vec(),
            auth: auth.clone(),
            idempotency_key: Some(IdempotencyKey::new("idem-1").unwrap()),
            session_assertion: None,
            canonical_input: None,
            trace: None,
        };

        let first = ingress.submit_message(request(b"<message>A</message>"));
        let replay = ingress.submit_message(request(b"<message>A</message>"));
        assert!(first.accepted);
        assert_eq!(replay.server_message_id, first.server_message_id);
        assert_eq!(ingress.pending_outbox().len(), 1);

        let conflict = ingress.submit_message(request(b"<message>B</message>"));
        assert!(!conflict.accepted);
        assert_eq!(conflict.error.unwrap().code, "CONFLICT");
    }

    #[test]
    fn canonical_input_mismatch_is_rejected_before_admission() {
        use foundation_contracts::adapters::ingress::CanonicalMessageInput;

        let ingress = MessageIngressService::new();
        let response = ingress.submit_message(SubmitMessageRequest {
            from_full_jid: "alice@example.com/mobile".to_owned(),
            to_jid: "bob@example.com".to_owned(),
            stanza_id: "canonical-1".to_owned(),
            message_type: "chat".to_owned(),
            raw_stanza: b"<message/>".to_vec(),
            auth: AuthContext::new("acc-canonical", "alice@example.com", 1, "local"),
            idempotency_key: None,
            session_assertion: None,
            canonical_input: Some(CanonicalMessageInput {
                from_full_jid: "eve@example.com/mobile".to_owned(),
                to_jid: "bob@example.com".to_owned(),
                stanza_id: "canonical-1".to_owned(),
                message_type: "chat".to_owned(),
                payload: Vec::new(),
                origin_id: "origin-1".to_owned(),
                schema_version: 1,
            }),
            trace: None,
        });
        assert!(!response.accepted);
        assert_eq!(response.error.unwrap().code, "INVALID_ARGUMENT");
    }
}
