//! Session directory contract.

use crate::common::{AuthContext, ErrorDetail, TraceContext};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BindSessionRequest {
    pub auth: AuthContext,
    pub desired_resource: String,
    pub edge_instance_id: String,
    pub connection_id: String,
    pub trace: Option<TraceContext>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BindSessionResponse {
    pub success: bool,
    pub full_jid: String,
    pub session_epoch: u64,
    pub error: Option<ErrorDetail>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResumeFenceRequest {
    pub full_jid: String,
    pub expected_epoch: u64,
    pub new_edge_instance_id: String,
    pub new_connection_id: String,
    pub trace: Option<TraceContext>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResumeFenceResponse {
    pub success: bool,
    pub new_epoch: u64,
    pub error: Option<ErrorDetail>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResolveTargetsRequest {
    pub bare_or_full_jid: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionTarget {
    pub full_jid: String,
    pub edge_instance_id: String,
    pub connection_id: String,
    pub session_epoch: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResolveTargetsResponse {
    pub targets: Vec<SessionTarget>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CloseSessionRequest {
    pub full_jid: String,
    pub session_epoch: u64,
    pub reason: String,
    pub trace: Option<TraceContext>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CloseSessionResponse {
    pub success: bool,
}
