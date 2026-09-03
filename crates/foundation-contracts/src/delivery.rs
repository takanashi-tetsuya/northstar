//! Delivery router streaming contract.

use crate::common::TraceContext;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum DeliveryClientMessage {
    Register(EdgeRegister),
    Ack(DeliveryAck),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EdgeRegister {
    pub edge_instance_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeliveryAck {
    pub delivery_id: String,
    pub delivered: bool,
    pub error_reason: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeliveryServerMessage {
    pub delivery_id: String,
    pub target_connection_id: String,
    pub target_full_jid: String,
    pub stanza: Vec<u8>,
    pub trace: Option<TraceContext>,
}
