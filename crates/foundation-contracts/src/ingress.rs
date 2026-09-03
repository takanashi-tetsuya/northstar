//! Message ingress contract.

use crate::common::{AuthContext, ErrorDetail, TraceContext};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SubmitMessageRequest {
    pub from_full_jid: String,
    pub to_jid: String,
    pub stanza_id: String,
    pub message_type: String,
    pub raw_stanza: Vec<u8>,
    pub auth: AuthContext,
    pub trace: Option<TraceContext>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SubmitMessageResponse {
    pub accepted: bool,
    pub server_message_id: String,
    pub admission_timestamp_ms: u64,
    pub error: Option<ErrorDetail>,
}
