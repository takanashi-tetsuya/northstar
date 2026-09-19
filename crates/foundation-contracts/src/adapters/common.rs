//! Domain-side common values.  These are not wire messages.

pub use foundation_security::AuthContext;
pub use foundation_telemetry::DistributedTraceContext as TraceContext;
use serde::{Deserialize, Serialize};

/// Opaque idempotency key scoped by the receiving service.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IdempotencyKey(String);

impl IdempotencyKey {
    pub fn new(value: impl Into<String>) -> Option<Self> {
        let value = value.into();
        (!value.trim().is_empty() && value.len() <= 256).then_some(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Opaque pagination cursor. Consumers must validate it with their own key
/// and expiry policy; it is never interpreted as a database offset.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PageToken(Vec<u8>);

impl PageToken {
    pub fn new(value: Vec<u8>) -> Option<Self> {
        (!value.is_empty() && value.len() <= 4096).then_some(Self(value))
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

/// Non-authoritative metadata attached to an internal request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RequestMetadata {
    pub request_id: String,
    pub trace: Option<TraceContext>,
    pub idempotency_key: Option<IdempotencyKey>,
    pub page_token: Option<PageToken>,
}

impl RequestMetadata {
    pub fn new(request_id: impl Into<String>) -> Self {
        Self {
            request_id: request_id.into(),
            trace: None,
            idempotency_key: None,
            page_token: None,
        }
    }

    pub fn with_idempotency_key(mut self, key: IdempotencyKey) -> Self {
        self.idempotency_key = Some(key);
        self
    }

    pub fn with_page_token(mut self, token: PageToken) -> Self {
        self.page_token = Some(token);
        self
    }

    pub fn with_trace(mut self, trace: TraceContext) -> Self {
        self.trace = Some(trace);
        self
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ErrorDetail {
    pub code: String,
    pub retryable: bool,
    pub safe_message: String,
    pub current_version: Option<u64>,
    pub violations: Vec<FieldViolation>,
    pub retry_after_ms: Option<u64>,
    /// Canonical error metadata is boxed so adding contract context does not
    /// inflate every `Result<T, ErrorDetail>` on service hot paths.
    pub context: Box<ErrorContext>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ErrorContext {
    pub reason: String,
    pub domain: String,
    pub correlation_id: Option<String>,
}

impl ErrorDetail {
    pub fn new(code: impl Into<String>, safe_message: impl Into<String>) -> Self {
        let code = code.into();
        Self {
            code: code.clone(),
            retryable: false,
            safe_message: safe_message.into(),
            current_version: None,
            violations: Vec::new(),
            retry_after_ms: None,
            context: Box::new(ErrorContext {
                reason: code,
                domain: String::new(),
                correlation_id: None,
            }),
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

    pub fn with_domain(mut self, domain: impl Into<String>) -> Self {
        self.context.domain = domain.into();
        self
    }

    pub fn with_correlation_id(mut self, correlation_id: impl Into<String>) -> Self {
        self.context.correlation_id = Some(correlation_id.into());
        self
    }

    pub fn reason(&self) -> &str {
        &self.context.reason
    }

    pub fn domain(&self) -> &str {
        &self.context.domain
    }

    pub fn correlation_id(&self) -> Option<&str> {
        self.context.correlation_id.as_deref()
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

/// Domain representation of a verified session assertion.
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
