//! Common contract types and error models.

pub use foundation_security::AuthContext;
pub use foundation_telemetry::DistributedTraceContext as TraceContext;
use serde::{Deserialize, Serialize};

/// Unified machine-readable error response.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ErrorDetail {
    pub code: String,
    pub retryable: bool,
    pub safe_message: String,
    pub current_version: Option<u64>,
    pub violations: Vec<FieldViolation>,
    pub retry_after_ms: Option<u64>,
}

impl ErrorDetail {
    pub fn new(code: impl Into<String>, safe_message: impl Into<String>) -> Self {
        Self {
            code: code.into(),
            retryable: false,
            safe_message: safe_message.into(),
            current_version: None,
            violations: Vec::new(),
            retry_after_ms: None,
        }
    }

    pub fn retryable(mut self, retryable: bool) -> Self {
        self.retryable = retryable;
        self
    }

    pub fn with_version(mut self, version: u64) -> Self {
        self.current_version = Some(version);
        self
    }

    pub fn with_violation(
        mut self,
        field: impl Into<String>,
        description: impl Into<String>,
    ) -> Self {
        self.violations.push(FieldViolation {
            field: field.into(),
            description: description.into(),
        });
        self
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FieldViolation {
    pub field: String,
    pub description: String,
}

/// Cryptographically verified session assertion issued by Session Directory / Identity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionAssertion {
    pub account_id: String,
    pub canonical_bare_jid: String,
    pub full_jid: String,
    pub connection_id: String,
    pub edge_instance_id: String,
    pub session_epoch: u64,
    pub credential_generation: u64,
    pub home_region: String,
    pub region_epoch: u64,
    pub issued_at_ms: u64,
    pub expires_at_ms: u64,
    pub audience: String,
    pub nonce: String,
    pub key_id: String,
    pub signature: Vec<u8>,
}

