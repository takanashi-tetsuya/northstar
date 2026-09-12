//! Delivery domain values.  RPC callers use generated messages.

use super::common::TraceContext;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum DeliveryClientMessage {
    Register(EdgeRegister),
    Ack(DeliveryAck),
    Heartbeat(EdgeHeartbeat),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EdgeRegister {
    pub edge_instance_id: String,
    pub protocol_version: String,
    pub attestation: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EdgeHeartbeat {
    pub edge_instance_id: String,
    pub observed_at_unix_ms: i64,
    pub active_connections: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeliveryAck {
    pub delivery_id: String,
    pub delivered: bool,
    pub error_reason: Option<String>,
    pub target_connection_id: String,
    pub target_full_jid: String,
    pub session_epoch: u64,
    pub stage: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeliveryServerMessage {
    pub delivery_id: String,
    pub target_connection_id: String,
    pub target_full_jid: String,
    pub stanza: Vec<u8>,
    pub trace: Option<TraceContext>,
    pub server_message_id: String,
    pub delivery_attempt: u32,
    pub session_epoch: u64,
}
