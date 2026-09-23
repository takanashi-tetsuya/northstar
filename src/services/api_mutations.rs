//! Request identities and canonical results for idempotent API commands.
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use uuid::Uuid;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ApiPrincipalKind {
    Anonymous,
    User,
    #[allow(dead_code)]
    Admin,
    #[allow(dead_code)]
    Upload,
}

impl ApiPrincipalKind {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Anonymous => "anonymous",
            Self::User => "user",
            Self::Admin => "admin",
            Self::Upload => "upload",
        }
    }
}

pub struct IdempotencyRequest<'a> {
    pub request_id: Uuid,
    pub actor_id: Option<Uuid>,
    /// Canonical request-scoped identity. It is HMACed and never persisted.
    pub principal_scope: &'a [u8],
    /// Coarser abuse boundary used only to cap unfinished reservations.
    pub capacity_scope: &'a [u8],
    /// Canonical path/object identity. Raw identifiers are never persisted;
    /// a keyed digest is compared under the idempotency scope instead.
    pub target_scope: &'a [u8],
    pub principal_kind: ApiPrincipalKind,
    pub method: &'a str,
    /// Canonical route template, never a raw URI or query string.
    pub route: &'a str,
    pub idempotency_key: &'a str,
    pub request_fingerprint: [u8; 32],
    pub ttl_seconds: i64,
    pub lease_seconds: i64,
}

#[derive(Debug, Eq, PartialEq)]
pub struct IdempotentResponse {
    pub request_id: Uuid,
    pub status: u16,
    pub headers: BTreeMap<String, String>,
    pub body: Vec<u8>,
}

pub fn json_replay_headers() -> BTreeMap<String, String> {
    BTreeMap::from([
        ("cache-control".to_owned(), "no-store, max-age=0".to_owned()),
        ("content-type".to_owned(), "application/json".to_owned()),
    ])
}

/// The same status, headers and bytes are committed for replay and returned
/// for the first execution. The transport adapter constructs the HTTP object.
pub(crate) struct StoredApiResponse {
    pub(crate) status: u16,
    pub(crate) headers: BTreeMap<String, String>,
    pub(crate) body: Vec<u8>,
    pub(crate) replay_resource_id: Option<Uuid>,
}
impl StoredApiResponse {
    pub(crate) fn json(status: u16, body: Value) -> anyhow::Result<Self> {
        Ok(Self {
            status,
            headers: json_replay_headers(),
            body: serde_json::to_vec(&body)?,
            replay_resource_id: None,
        })
    }
    pub(crate) fn with_header(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.headers.insert(name.into(), value.into());
        self
    }
    pub(crate) fn with_optional_replay_resource_id(mut self, id: Option<Uuid>) -> Self {
        self.replay_resource_id = id;
        self
    }
}

pub(crate) enum ApiMutationRejection {
    Unauthorized,
    Forbidden,
    BadRequest(&'static str),
    Conflict(String),
    Unavailable(String),
    IdempotencyConflict,
    ReplayInvalidated,
    Busy { retry_after: u64 },
    CapacityLimited { retry_after: u64 },
    InProgress { retry_after: u64 },
}
pub(crate) enum ApiMutationOutcome<T> {
    Committed(T),
    Replay(IdempotentResponse),
    Rejected(ApiMutationRejection),
}
pub(crate) struct UserMutationAdmission<'a> {
    pub(crate) authority: crate::services::api_queries::ApiReadAuthority<'a>,
    pub(crate) idempotency: IdempotencyRequest<'a>,
    pub(crate) subject: &'a str,
    pub(crate) actors: &'a [String],
    pub(crate) proof: Option<&'a crate::abuse::PowProof>,
    pub(crate) intent: &'a crate::abuse::PowIntent,
}

pub(crate) fn error_response(
    status: u16,
    code: &str,
    message: &str,
) -> anyhow::Result<StoredApiResponse> {
    StoredApiResponse::json(
        status,
        serde_json::json!({"error":{"code":code,"message":message}}),
    )
}
pub(crate) fn guard_denial_response(
    error: crate::abuse::GuardError,
) -> anyhow::Result<StoredApiResponse> {
    let requirement = error.requirement();
    let retry_after = requirement
        .retry_after_seconds
        .max(requirement.hard_wait_seconds);
    let details = serde_json::json!({"message":error.message(),"requirement":requirement});
    let mut response = StoredApiResponse::json(
        429,
        serde_json::json!({"error":{
            "code":"rate_limited", "message":"operation requires proof of work or cooldown", "details":details
        }}),
    )?;
    if retry_after > 0 {
        response = response.with_header("retry-after", retry_after.to_string());
    }
    Ok(response)
}

pub(crate) struct AdminMutationAdmission<'a> {
    pub(crate) authority: crate::services::api_queries::ApiReadAuthority<'a>,
    pub(crate) idempotency: IdempotencyRequest<'a>,
}

/// Hash the exact media type and bytes consumed by a mutation handler. HTTP
/// code must call this before deserializing so semantically different JSON
/// encodings cannot be silently substituted under one idempotency key.
pub fn api_request_fingerprint(content_type: &str, body: &[u8]) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update((content_type.len() as u64).to_be_bytes());
    hash.update(content_type.as_bytes());
    hash.update((body.len() as u64).to_be_bytes());
    hash.update(body);
    hash.finalize().into()
}
