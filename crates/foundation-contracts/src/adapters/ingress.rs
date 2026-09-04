//! Message ingress domain values.  RPC callers use generated messages.

use super::{
    assertions::SessionAssertion,
    common::{AuthContext, ErrorDetail, IdempotencyKey, TraceContext},
};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SubmitMessageRequest {
    pub from_full_jid: String,
    pub to_jid: String,
    pub stanza_id: String,
    pub message_type: String,
    pub raw_stanza: Vec<u8>,
    pub auth: AuthContext,
    pub idempotency_key: Option<IdempotencyKey>,
    pub session_assertion: Option<SessionAssertion>,
    pub canonical_input: Option<CanonicalMessageInput>,
    pub trace: Option<TraceContext>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CanonicalMessageInput {
    pub from_full_jid: String,
    pub to_jid: String,
    pub stanza_id: String,
    pub message_type: String,
    pub payload: Vec<u8>,
    pub origin_id: String,
    pub schema_version: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SubmitMessageResponse {
    pub accepted: bool,
    pub server_message_id: String,
    pub admission_timestamp_ms: u64,
    pub error: Option<ErrorDetail>,
}
