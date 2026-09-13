//! Session domain inputs and outputs.  RPC callers use generated messages.

use super::{
    assertions::{AuthGrant, SessionAssertion},
    common::{AuthContext, ErrorDetail, IdempotencyKey, TraceContext},
};
use foundation_security::{OpaqueToken, SecretBytes};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BindSessionRequest {
    pub auth: AuthContext,
    pub auth_grant: Option<AuthGrant>,
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
    pub assertion: Option<SessionAssertion>,
    pub error: Option<ErrorDetail>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResumeFenceRequest {
    pub full_jid: String,
    pub expected_epoch: u64,
    pub new_edge_instance_id: String,
    pub new_connection_id: String,
    pub expected_region_epoch: u64,
    pub idempotency_key: Option<IdempotencyKey>,
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
    pub trace: Option<TraceContext>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionTarget {
    pub full_jid: String,
    pub edge_instance_id: String,
    pub connection_id: String,
    pub session_epoch: u64,
    pub route_incarnation: u64,
    pub expires_at_unix_ms: i64,
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
    pub expected_region_epoch: u64,
    pub idempotency_key: Option<IdempotencyKey>,
    pub trace: Option<TraceContext>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CloseSessionResponse {
    pub success: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RenewLeaseRequest {
    pub full_jid: String,
    pub expected_session_epoch: u64,
    pub expected_region_epoch: u64,
    pub lease_ttl_seconds: u32,
    pub idempotency_key: Option<IdempotencyKey>,
    pub trace: Option<TraceContext>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RenewLeaseResponse {
    pub success: bool,
    pub session_epoch: u64,
    pub lease_expires_at_unix_ms: i64,
    pub error: Option<ErrorDetail>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrepareResumeRequest {
    pub full_jid: String,
    pub resume_token_hash: SecretBytes,
    pub expected_session_epoch: u64,
    pub new_edge_instance_id: String,
    pub new_connection_id: String,
    pub idempotency_key: Option<IdempotencyKey>,
    pub trace: Option<TraceContext>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrepareResumeResponse {
    pub success: bool,
    pub resume_id: Option<OpaqueToken>,
    pub session_epoch: u64,
    pub error: Option<ErrorDetail>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommitResumeRequest {
    pub resume_id: OpaqueToken,
    pub expected_session_epoch: u64,
    pub idempotency_key: Option<IdempotencyKey>,
    pub trace: Option<TraceContext>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CommitResumeResponse {
    pub success: bool,
    pub new_session_epoch: u64,
    pub error: Option<ErrorDetail>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValidateAssertionRequest {
    pub assertion: SessionAssertion,
    pub expected_audience: String,
    pub trace: Option<TraceContext>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValidateAssertionResponse {
    pub valid: bool,
    pub error: Option<ErrorDetail>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RevokeAccountSessionsRequest {
    pub account_id: String,
    pub expected_credential_generation: u64,
    pub idempotency_key: Option<IdempotencyKey>,
    pub reason: String,
    pub trace: Option<TraceContext>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RevokeAccountSessionsResponse {
    pub success: bool,
    pub revoked_count: u64,
    pub error: Option<ErrorDetail>,
}
