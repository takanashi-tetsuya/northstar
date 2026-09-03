//! Delivery Router microservice implementation.
//!
//! Defined per `northstar_microservices_deep_audit_2026-09-03.md` (Sections 6, 8, 12, 19.2).

use foundation_contracts::delivery::DeliveryServerMessage;
use foundation_contracts::events::MessageAcceptedEventPayload;
use foundation_contracts::session::SessionTarget;
use foundation_eventing::memory::InMemoryInbox;
use std::collections::HashMap;
use std::sync::RwLock;
use tokio::sync::mpsc;
use uuid::Uuid;

#[derive(Debug, Clone)]
pub struct OfflineMessage {
    pub server_message_id: String,
    pub recipient_bare_jid: String,
    pub stanza: Vec<u8>,
    pub timestamp_ms: u64,
}

pub struct DeliveryRouterService {
    inbox: InMemoryInbox,
    offline_spool: RwLock<HashMap<String, Vec<OfflineMessage>>>, // bare_jid -> queued messages
    edge_streams: RwLock<HashMap<String, mpsc::Sender<DeliveryServerMessage>>>, // edge_id -> channel
}

impl Default for DeliveryRouterService {
    fn default() -> Self {
        Self::new()
    }
}

impl DeliveryRouterService {
    pub fn new() -> Self {
        Self {
            inbox: InMemoryInbox::new(),
            offline_spool: RwLock::new(HashMap::new()),
            edge_streams: RwLock::new(HashMap::new()),
        }
    }

    /// Registers a live delivery channel from an active Edge gateway instance.
    pub fn register_edge_stream(
        &self,
        edge_instance_id: impl Into<String>,
        tx: mpsc::Sender<DeliveryServerMessage>,
    ) {
        self.edge_streams
            .write()
            .unwrap()
            .insert(edge_instance_id.into(), tx);
    }

    /// Processes an accepted message event from Kafka with Consumer Inbox idempotency.
    pub async fn process_accepted_message(
        &self,
        event_id: Uuid,
        msg: MessageAcceptedEventPayload,
        targets: &[SessionTarget],
    ) -> bool {
        // Consumer Inbox: Deduplicate to guarantee exactly-once delivery effect
        if self.inbox.is_processed("delivery_router", event_id) {
            return false;
        }

        let recipient = msg
            .to_jid
            .split('/')
            .next()
            .unwrap_or(&msg.to_jid)
            .to_string();

        if targets.is_empty() {
            // Recipient is offline: store in offline spool
            let offline = OfflineMessage {
                server_message_id: msg.server_message_id,
                recipient_bare_jid: recipient.clone(),
                stanza: msg.raw_stanza,
                timestamp_ms: msg.timestamp_ms,
            };
            self.offline_spool
                .write()
                .unwrap()
                .entry(recipient)
                .or_default()
                .push(offline);
        } else {
            // Recipient has active sessions: fan out to all resolved targets
            let to_send: Vec<(mpsc::Sender<DeliveryServerMessage>, DeliveryServerMessage)> = {
                let streams = self.edge_streams.read().unwrap();
                targets
                    .iter()
                    .filter_map(|target| {
                        streams.get(&target.edge_instance_id).map(|tx| {
                            (
                                tx.clone(),
                                DeliveryServerMessage {
                                    delivery_id: Uuid::new_v4().to_string(),
                                    target_connection_id: target.connection_id.clone(),
                                    target_full_jid: target.full_jid.clone(),
                                    stanza: msg.raw_stanza.clone(),
                                    trace: None,
                                },
                            )
                        })
                    })
                    .collect()
            };

            for (tx, delivery) in to_send {
                let _ = tx.send(delivery).await;
            }
        }

        // Record processed state in Consumer Inbox
        self.inbox.record_processed("delivery_router", event_id);
        true
    }

    /// Drains offline spooled messages for a user upon connection or binding.
    pub fn drain_offline_spool(&self, recipient_bare_jid: &str) -> Vec<OfflineMessage> {
        self.offline_spool
            .write()
            .unwrap()
            .remove(recipient_bare_jid)
            .unwrap_or_default()
    }

    /// Returns the current count of offline messages for a given user.
    pub fn offline_count(&self, recipient_bare_jid: &str) -> usize {
        self.offline_spool
            .read()
            .unwrap()
            .get(recipient_bare_jid)
            .map(|v| v.len())
            .unwrap_or(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn delivery_router_online_offline_and_deduplication() {
        let router = DeliveryRouterService::new();
        let (tx, mut rx) = mpsc::channel(16);
        router.register_edge_stream("edge-1", tx);

        let event_id = Uuid::new_v4();
        let msg = MessageAcceptedEventPayload {
            server_message_id: "srv-msg-1".to_string(),
            from_full_jid: "alice@example.com/mobile".to_string(),
            to_jid: "bob@example.com".to_string(),
            stanza_id: "client-1".to_string(),
            message_type: "chat".to_string(),
            raw_stanza: b"<message>Hi Bob</message>".to_vec(),
            timestamp_ms: 1000,
        };

        // 1. Online delivery to active target
        let target = SessionTarget {
            full_jid: "bob@example.com/desktop".to_string(),
            edge_instance_id: "edge-1".to_string(),
            connection_id: "conn-123".to_string(),
            session_epoch: 1,
        };

        let processed = router
            .process_accepted_message(event_id, msg.clone(), &[target])
            .await;
        assert!(processed);

        let received = rx.recv().await.unwrap();
        assert_eq!(received.target_full_jid, "bob@example.com/desktop");
        assert_eq!(received.stanza, b"<message>Hi Bob</message>");

        // 2. Duplicate event ignored by Consumer Inbox
        let dup_processed = router
            .process_accepted_message(event_id, msg.clone(), &[])
            .await;
        assert!(!dup_processed);

        // 3. Offline delivery when no targets exist
        let offline_event_id = Uuid::new_v4();
        let offline_msg = MessageAcceptedEventPayload {
            server_message_id: "srv-msg-2".to_string(),
            from_full_jid: "alice@example.com/mobile".to_string(),
            to_jid: "charlie@example.com".to_string(),
            stanza_id: "client-2".to_string(),
            message_type: "chat".to_string(),
            raw_stanza: b"<message>Hi Charlie</message>".to_vec(),
            timestamp_ms: 2000,
        };

        let offline_processed = router
            .process_accepted_message(offline_event_id, offline_msg, &[])
            .await;
        assert!(offline_processed);
        assert_eq!(router.offline_count("charlie@example.com"), 1);

        // Drain offline spool
        let drained = router.drain_offline_spool("charlie@example.com");
        assert_eq!(drained.len(), 1);
        assert_eq!(drained[0].server_message_id, "srv-msg-2");
        assert_eq!(router.offline_count("charlie@example.com"), 0);
    }
}
