//! Identity service contract.

use crate::common::{AuthContext, ErrorDetail, TraceContext};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthenticateRequest {
    pub username: String,
    pub mechanism: String,
    pub auth_payload: Vec<u8>,
    pub trace: Option<TraceContext>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthenticateResponse {
    pub success: bool,
    pub auth_context: Option<AuthContext>,
    pub challenge_or_response: Vec<u8>,
    pub error: Option<ErrorDetail>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegisterRequest {
    pub username: String,
    pub password: String,
    pub invitation_code: Option<String>,
    pub trace: Option<TraceContext>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegisterResponse {
    pub success: bool,
    pub account_id: String,
    pub canonical_jid: String,
    pub error: Option<ErrorDetail>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChangePasswordRequest {
    pub account_id: String,
    pub old_password: String,
    pub new_password: String,
    pub trace: Option<TraceContext>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChangePasswordResponse {
    pub success: bool,
    pub new_credential_generation: u64,
    pub error: Option<ErrorDetail>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum GetIdentityRequest {
    ById(String),
    ByUsername(String),
    ByJid(String),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GetIdentityResponse {
    pub found: bool,
    pub identity: Option<AuthContext>,
    pub account_status: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RevokeCredentialsRequest {
    pub account_id: String,
    pub reason: String,
    pub trace: Option<TraceContext>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RevokeCredentialsResponse {
    pub success: bool,
    pub new_credential_generation: u64,
}
