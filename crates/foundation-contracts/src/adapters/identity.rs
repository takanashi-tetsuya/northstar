//! Identity domain inputs and outputs.  RPC callers use generated messages.

use super::{
    assertions::AuthGrant,
    common::{AuthContext, ErrorDetail, TraceContext},
};
use foundation_security::{OpaqueToken, SecretBytes, SecretString};
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
    pub auth_grant: Option<AuthGrant>,
    pub challenge_or_response: Vec<u8>,
    pub error: Option<ErrorDetail>,
}

/// First leg of the internal SCRAM exchange.  The client-first message is
/// opaque protocol data and must not be logged as a normal string.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StartAuthenticationRequest {
    pub username: String,
    pub mechanism: String,
    pub client_first: SecretBytes,
    pub channel_binding: Option<String>,
    pub channel_binding_data: Option<SecretBytes>,
    pub trace: Option<TraceContext>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StartAuthenticationResponse {
    pub success: bool,
    pub exchange_id: Option<OpaqueToken>,
    pub server_first: Vec<u8>,
    pub exchange_ttl_seconds: u32,
    pub error: Option<ErrorDetail>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContinueAuthenticationRequest {
    pub exchange_id: OpaqueToken,
    pub client_final: SecretBytes,
    pub trace: Option<TraceContext>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContinueAuthenticationResponse {
    pub success: bool,
    pub server_final: Vec<u8>,
    pub auth_grant: Option<AuthGrant>,
    pub error: Option<ErrorDetail>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AbortAuthenticationRequest {
    pub exchange_id: OpaqueToken,
    pub reason: String,
    pub trace: Option<TraceContext>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AbortAuthenticationResponse {
    pub success: bool,
    pub error: Option<ErrorDetail>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegisterRequest {
    pub username: String,
    pub password: SecretString,
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChangePasswordRequest {
    pub account_id: String,
    pub old_password: SecretString,
    pub new_password: SecretString,
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
