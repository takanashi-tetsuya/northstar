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

use std::sync::atomic::{AtomicU64, Ordering};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeliveryTaskStatus {
    Pending,
    InFlight,
    Delivered,
    Spooled,
    Failed,
    DeadLettered,
}

#[derive(Debug, Clone)]
pub struct TargetDeliveryAttempt {
    pub attempt_id: u64,
    pub delivery_id: String,
    pub server_message_id: String,
    pub target_full_jid: String,
    pub connection_id: String,
    pub session_epoch: u64,
    pub status: DeliveryTaskStatus,
    pub failure_reason: Option<String>,
    pub timestamp_ms: u64,
}

#[derive(Debug, Clone)]
pub struct OfflineMessage {
    pub server_message_id: String,
    pub recipient_bare_jid: String,
    pub target_full_jid: Option<String>,
    pub stanza: Vec<u8>,
    pub timestamp_ms: u64,
}

pub struct DeliveryRouterService {
    inbox: InMemoryInbox,
    offline_spool: RwLock<HashMap<String, Vec<OfflineMessage>>>, // bare_jid -> queued messages
    edge_streams: RwLock<HashMap<String, mpsc::Sender<DeliveryServerMessage>>>, // edge_id -> channel
    delivery_attempts: RwLock<Vec<TargetDeliveryAttempt>>,
    attempt_counter: AtomicU64,
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
            delivery_attempts: RwLock::new(Vec::new()),
            attempt_counter: AtomicU64::new(1),
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
    ///
    /// Per-target delivery tasks guarantee that partial fan-out failure does NOT drop messages:
    /// each target session is routed independently, and any failing or disconnected edge stream
    /// falls back to offline spooling for that specific target.
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
            // Recipient is completely offline: store in offline spool
            let offline = OfflineMessage {
                server_message_id: msg.server_message_id.clone(),
                recipient_bare_jid: recipient.clone(),
                target_full_jid: None,
                stanza: msg.raw_stanza.clone(),
                timestamp_ms: msg.timestamp_ms,
            };
            self.offline_spool
                .write()
                .unwrap()
                .entry(recipient.clone())
                .or_default()
                .push(offline);

            let attempt_id = self.attempt_counter.fetch_add(1, Ordering::Relaxed);
            self.delivery_attempts
                .write()
                .unwrap()
                .push(TargetDeliveryAttempt {
                    attempt_id,
                    delivery_id: Uuid::new_v4().to_string(),
                    server_message_id: msg.server_message_id,
                    target_full_jid: recipient,
                    connection_id: "offline".to_string(),
                    session_epoch: 0,
                    status: DeliveryTaskStatus::Spooled,
                    failure_reason: Some("Recipient offline".to_string()),
                    timestamp_ms: msg.timestamp_ms,
                });
        } else {
            // Recipient has active sessions: fan out to all resolved targets individually
            for target in targets {
                let maybe_tx = {
                    let streams = self.edge_streams.read().unwrap();
                    streams.get(&target.edge_instance_id).cloned()
                };

                let delivery_id = Uuid::new_v4().to_string();
                let attempt_id = self.attempt_counter.fetch_add(1, Ordering::Relaxed);

                if let Some(tx) = maybe_tx {
                    let delivery = DeliveryServerMessage {
                        delivery_id: delivery_id.clone(),
                        target_connection_id: target.connection_id.clone(),
                        target_full_jid: target.full_jid.clone(),
                        stanza: msg.raw_stanza.clone(),
                        trace: None,
                    };

                    match tx.send(delivery).await {
                        Ok(()) => {
                            self.delivery_attempts
                                .write()
                                .unwrap()
                                .push(TargetDeliveryAttempt {
                                    attempt_id,
                                    delivery_id,
                                    server_message_id: msg.server_message_id.clone(),
                                    target_full_jid: target.full_jid.clone(),
                                    connection_id: target.connection_id.clone(),
                                    session_epoch: target.session_epoch,
                                    status: DeliveryTaskStatus::Delivered,
                                    failure_reason: None,
                                    timestamp_ms: msg.timestamp_ms,
                                });
                        }
                        Err(err) => {
                            // Edge stream push failed: record failure and spool for this target
                            let reason = format!("Edge stream send error: {err}");
                            self.delivery_attempts
                                .write()
                                .unwrap()
                                .push(TargetDeliveryAttempt {
                                    attempt_id,
                                    delivery_id,
                                    server_message_id: msg.server_message_id.clone(),
                                    target_full_jid: target.full_jid.clone(),
                                    connection_id: target.connection_id.clone(),
                                    session_epoch: target.session_epoch,
                                    status: DeliveryTaskStatus::Spooled,
                                    failure_reason: Some(reason),
                                    timestamp_ms: msg.timestamp_ms,
                                });

                            let offline = OfflineMessage {
                                server_message_id: msg.server_message_id.clone(),
                                recipient_bare_jid: recipient.clone(),
                                target_full_jid: Some(target.full_jid.clone()),
                                stanza: msg.raw_stanza.clone(),
                                timestamp_ms: msg.timestamp_ms,
                            };
                            self.offline_spool
                                .write()
                                .unwrap()
                                .entry(recipient.clone())
                                .or_default()
                                .push(offline);
                        }
                    }
                } else {
                    // Edge stream not registered for this target: spool to prevent message loss
                    let reason = format!(
                        "No edge stream registered for edge_instance_id {}",
                        target.edge_instance_id
                    );
                    self.delivery_attempts
                        .write()
                        .unwrap()
                        .push(TargetDeliveryAttempt {
                            attempt_id,
                            delivery_id,
                            server_message_id: msg.server_message_id.clone(),
                            target_full_jid: target.full_jid.clone(),
                            connection_id: target.connection_id.clone(),
                            session_epoch: target.session_epoch,
                            status: DeliveryTaskStatus::Spooled,
                            failure_reason: Some(reason),
                            timestamp_ms: msg.timestamp_ms,
                        });

                    let offline = OfflineMessage {
                        server_message_id: msg.server_message_id.clone(),
                        recipient_bare_jid: recipient.clone(),
                        target_full_jid: Some(target.full_jid.clone()),
                        stanza: msg.raw_stanza.clone(),
                        timestamp_ms: msg.timestamp_ms,
                    };
                    self.offline_spool
                        .write()
                        .unwrap()
                        .entry(recipient.clone())
                        .or_default()
                        .push(offline);
                }
            }
        }

        // Record processed state in Consumer Inbox
        self.inbox.record_processed("delivery_router", event_id);
        true
    }

    /// Returns recorded delivery attempts for a given server message ID.
    pub fn attempts_for_message(&self, server_message_id: &str) -> Vec<TargetDeliveryAttempt> {
        self.delivery_attempts
            .read()
            .unwrap()
            .iter()
            .filter(|a| a.server_message_id == server_message_id)
            .cloned()
            .collect()
    }

    /// Returns the total count of delivery attempts recorded.
    pub fn total_attempts_count(&self) -> usize {
        self.delivery_attempts.read().unwrap().len()
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

    #[tokio::test]
    async fn delivery_router_edge_stream_failure_falls_back_to_offline_spool() {
        let router = DeliveryRouterService::new();
        // Register channel and immediately drop receiver to simulate abrupt edge disconnection
        let (tx, rx) = mpsc::channel(1);
        drop(rx);
        router.register_edge_stream("edge-broken", tx);

        let event_id = Uuid::new_v4();
        let msg = MessageAcceptedEventPayload {
            server_message_id: "srv-msg-disconnected".to_string(),
            from_full_jid: "alice@example.com/mobile".to_string(),
            to_jid: "bob@example.com".to_string(),
            stanza_id: "client-broken".to_string(),
            message_type: "chat".to_string(),
            raw_stanza: b"<message>Will not drop</message>".to_vec(),
            timestamp_ms: 3000,
        };

        let target = SessionTarget {
            full_jid: "bob@example.com/phone".to_string(),
            edge_instance_id: "edge-broken".to_string(),
            connection_id: "conn-dead".to_string(),
            session_epoch: 1,
        };

        let processed = router
            .process_accepted_message(event_id, msg, &[target])
            .await;
        assert!(processed);

        // Crucial invariant: when edge stream sends fail, message is NOT dropped; it is safely spooled!
        assert_eq!(router.offline_count("bob@example.com"), 1);
        let drained = router.drain_offline_spool("bob@example.com");
        assert_eq!(drained.len(), 1);
        assert_eq!(drained[0].server_message_id, "srv-msg-disconnected");
    }

    #[tokio::test]
    async fn delivery_router_partial_fanout_failure_spools_failed_target() {
        let router = DeliveryRouterService::new();

        // 1. Setup edge-alive with an active receiver
        let (tx_alive, mut rx_alive) = mpsc::channel(16);
        router.register_edge_stream("edge-alive", tx_alive);

        // 2. Setup edge-dead with dropped receiver (simulates broken TCP/gRPC stream)
        let (tx_dead, rx_dead) = mpsc::channel(1);
        drop(rx_dead);
        router.register_edge_stream("edge-dead", tx_dead);

        let event_id = Uuid::new_v4();
        let msg = MessageAcceptedEventPayload {
            server_message_id: "srv-msg-fanout-1".to_string(),
            from_full_jid: "alice@example.com/laptop".to_string(),
            to_jid: "bob@example.com".to_string(),
            stanza_id: "client-f1".to_string(),
            message_type: "chat".to_string(),
            raw_stanza: b"<message>Fanout reliability test</message>".to_vec(),
            timestamp_ms: 4000,
        };

        // Bob has three active resources across different edge instances:
        // - target1 on edge-alive (succeeds)
        // - target2 on edge-dead (send fails)
        // - target3 on edge-unregistered (no stream)
        let targets = vec![
            SessionTarget {
                full_jid: "bob@example.com/desktop".to_string(),
                edge_instance_id: "edge-alive".to_string(),
                connection_id: "conn-1".to_string(),
                session_epoch: 1,
            },
            SessionTarget {
                full_jid: "bob@example.com/mobile".to_string(),
                edge_instance_id: "edge-dead".to_string(),
                connection_id: "conn-2".to_string(),
                session_epoch: 2,
            },
            SessionTarget {
                full_jid: "bob@example.com/tablet".to_string(),
                edge_instance_id: "edge-unregistered".to_string(),
                connection_id: "conn-3".to_string(),
                session_epoch: 3,
            },
        ];

        let processed = router
            .process_accepted_message(event_id, msg, &targets)
            .await;
        assert!(processed);

        // 1. The alive target must receive its push message
        let received = rx_alive.recv().await.unwrap();
        assert_eq!(received.target_full_jid, "bob@example.com/desktop");
        assert_eq!(
            received.stanza,
            b"<message>Fanout reliability test</message>"
        );

        // 2. The two failed targets must NOT be dropped! They must be safely spooled.
        assert_eq!(router.offline_count("bob@example.com"), 2);
        let drained = router.drain_offline_spool("bob@example.com");
        assert_eq!(drained.len(), 2);
        assert_eq!(
            drained[0].target_full_jid,
            Some("bob@example.com/mobile".to_string())
        );
        assert_eq!(
            drained[1].target_full_jid,
            Some("bob@example.com/tablet".to_string())
        );

        // 3. Inspect per-target delivery attempts
        let attempts = router.attempts_for_message("srv-msg-fanout-1");
        assert_eq!(attempts.len(), 3);
        assert_eq!(attempts[0].target_full_jid, "bob@example.com/desktop");
        assert_eq!(attempts[0].status, DeliveryTaskStatus::Delivered);

        assert_eq!(attempts[1].target_full_jid, "bob@example.com/mobile");
        assert_eq!(attempts[1].status, DeliveryTaskStatus::Spooled);

        assert_eq!(attempts[2].target_full_jid, "bob@example.com/tablet");
        assert_eq!(attempts[2].status, DeliveryTaskStatus::Spooled);
    }
}
