//! Domain event payloads and the checked EventEnvelope adapter.

use super::common::TraceContext;
pub use foundation_eventing::{ConsumerInboxEntry, OutboxEvent};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccountCreatedEventPayload {
    pub account_id: String,
    pub username: String,
    pub canonical_jid: String,
    pub credential_generation: u64,
    pub home_region: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionBoundEventPayload {
    pub account_id: String,
    pub full_jid: String,
    pub edge_instance_id: String,
    pub connection_id: String,
    pub session_epoch: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionClosedEventPayload {
    pub full_jid: String,
    pub session_epoch: u64,
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MessageAcceptedEventPayload {
    pub server_message_id: String,
    pub from_full_jid: String,
    pub to_jid: String,
    pub stanza_id: String,
    pub message_type: String,
    pub raw_stanza: Vec<u8>,
    pub timestamp_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeliveryStatusEventPayload {
    pub delivery_id: String,
    pub server_message_id: String,
    pub recipient_full_jid: String,
    pub delivered: bool,
    pub error_reason: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EventEnvelope {
    pub event_id: String,
    pub producer_service: String,
    pub producer_instance: String,
    pub schema: String,
    pub schema_version: u32,
    pub aggregate_type: String,
    pub aggregate_id: String,
    pub aggregate_version: u64,
    pub partition_key: String,
    pub event_type: String,
    pub payload: Vec<u8>,
    pub payload_type: String,
    pub correlation_id: Option<String>,
    pub causation_id: Option<String>,
    pub trace: Option<TraceContext>,
    pub classification: String,
    pub created_at_unix_ms: i64,
}
