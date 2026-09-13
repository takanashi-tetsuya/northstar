//! Transactional Outbox and Consumer Inbox abstractions.
//!
//! Defined per `northstar_microservices_deep_audit_2026-09-03.md` (Sections 9, 11, Appendix B.2, B.3).

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Transactional outbox event entity stored atomically in the service's exclusive database.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OutboxEvent {
    pub event_id: Uuid,
    pub aggregate_type: String,
    pub aggregate_id: String,
    pub aggregate_version: u64,
    pub event_type: String,
    pub schema_version: u32,
    pub payload: Vec<u8>,
    pub traceparent: Option<String>,
    pub correlation_id: Option<Uuid>,
    pub causation_id: Option<Uuid>,
    pub created_at: DateTime<Utc>,
    pub published_at: Option<DateTime<Utc>>,
}

impl OutboxEvent {
    pub fn new(
        aggregate_type: impl Into<String>,
        aggregate_id: impl Into<String>,
        aggregate_version: u64,
        event_type: impl Into<String>,
        payload: Vec<u8>,
    ) -> Self {
        Self {
            event_id: Uuid::new_v4(),
            aggregate_type: aggregate_type.into(),
            aggregate_id: aggregate_id.into(),
            aggregate_version,
            event_type: event_type.into(),
            schema_version: 1,
            payload,
            traceparent: None,
            correlation_id: None,
            causation_id: None,
            created_at: Utc::now(),
            published_at: None,
        }
    }

    pub fn with_trace(mut self, traceparent: impl Into<String>) -> Self {
        self.traceparent = Some(traceparent.into());
        self
    }

    pub fn with_correlation(mut self, correlation_id: Uuid, causation_id: Option<Uuid>) -> Self {
        self.correlation_id = Some(correlation_id);
        self.causation_id = causation_id;
        self
    }
}

/// Consumer Inbox record ensuring idempotent exactly-once processing under at-least-once message delivery.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConsumerInboxEntry {
    pub consumer_name: String,
    pub event_id: Uuid,
    pub processed_at: DateTime<Utc>,
    pub result_digest: Option<Vec<u8>>,
}

impl ConsumerInboxEntry {
    pub fn new(consumer_name: impl Into<String>, event_id: Uuid) -> Self {
        Self {
            consumer_name: consumer_name.into(),
            event_id,
            processed_at: Utc::now(),
            result_digest: None,
        }
    }

    pub fn with_digest(mut self, digest: Vec<u8>) -> Self {
        self.result_digest = Some(digest);
        self
    }
}

/// Port trait for persisting and polling transactional outbox events.
pub trait OutboxRepository: Send + Sync {
    type Error: std::error::Error + Send + Sync + 'static;

    fn stage_event(&mut self, event: &OutboxEvent) -> Result<(), Self::Error>;
    fn fetch_pending(&self, limit: usize) -> Result<Vec<OutboxEvent>, Self::Error>;
    fn mark_published(&self, event_id: Uuid) -> Result<(), Self::Error>;
}

/// Port trait for checking and recording processed events to prevent duplicate executions.
pub trait ConsumerInboxRepository: Send + Sync {
    type Error: std::error::Error + Send + Sync + 'static;

    fn is_processed(&self, consumer_name: &str, event_id: Uuid) -> Result<bool, Self::Error>;
    fn record_processed(&mut self, entry: &ConsumerInboxEntry) -> Result<(), Self::Error>;
}

/// In-memory implementation of Outbox and Inbox for contract and unit testing.
#[cfg(any(test, feature = "test-support"))]
pub mod memory {
    use super::*;
    use std::collections::{HashMap, HashSet};
    use std::sync::Mutex;

    #[derive(Default)]
    pub struct InMemoryInbox {
        processed: Mutex<HashSet<(String, Uuid)>>,
    }

    impl InMemoryInbox {
        pub fn new() -> Self {
            Self::default()
        }

        pub fn is_processed(&self, consumer_name: &str, event_id: Uuid) -> bool {
            let guard = self.processed.lock().unwrap();
            guard.contains(&(consumer_name.to_string(), event_id))
        }

        pub fn record_processed(&self, consumer_name: &str, event_id: Uuid) -> bool {
            let mut guard = self.processed.lock().unwrap();
            guard.insert((consumer_name.to_string(), event_id))
        }
    }

    #[derive(Default)]
    pub struct InMemoryOutbox {
        events: Mutex<HashMap<Uuid, OutboxEvent>>,
    }

    impl InMemoryOutbox {
        pub fn new() -> Self {
            Self::default()
        }

        pub fn stage(&self, event: OutboxEvent) {
            let mut guard = self.events.lock().unwrap();
            guard.insert(event.event_id, event);
        }

        pub fn pending(&self) -> Vec<OutboxEvent> {
            let guard = self.events.lock().unwrap();
            guard
                .values()
                .filter(|e| e.published_at.is_none())
                .cloned()
                .collect()
        }

        pub fn mark_published(&self, event_id: Uuid) {
            let mut guard = self.events.lock().unwrap();
            if let Some(event) = guard.get_mut(&event_id) {
                event.published_at = Some(Utc::now());
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use memory::*;

    #[test]
    fn outbox_event_creation_and_lifecycle() {
        let outbox = InMemoryOutbox::new();
        let event = OutboxEvent::new(
            "account",
            "acc_123",
            1,
            "identity.account.created.v1",
            b"test_payload".to_vec(),
        );
        let id = event.event_id;

        outbox.stage(event);
        let pending = outbox.pending();
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].event_id, id);

        outbox.mark_published(id);
        let pending_after = outbox.pending();
        assert_eq!(pending_after.len(), 0);
    }

    #[test]
    fn consumer_inbox_deduplication() {
        let inbox = InMemoryInbox::new();
        let event_id = Uuid::new_v4();

        assert!(!inbox.is_processed("delivery_worker", event_id));
        assert!(inbox.record_processed("delivery_worker", event_id));
        assert!(inbox.is_processed("delivery_worker", event_id));

        // Different consumer receives the same event
        assert!(!inbox.is_processed("mam_worker", event_id));
    }
}
