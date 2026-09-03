use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use thiserror::Error;
use uuid::Uuid;

pub const POW_INTENT_VERSION: u16 = 2;
pub const POW_BODY_DIGEST_BYTES: usize = 32;
pub const POW_INTENT_PATH_MAX_BYTES: usize = 512;

pub const MAX_PENALTY_LEVEL: u32 = 10;
pub const MAX_ACTIVE_POW_CHALLENGES_GLOBAL: usize = 50_000;
pub const MAX_ACTIVE_POW_CHALLENGES_PER_ACTOR: usize = 8;
pub const MAX_ACTIVE_POW_CHALLENGES_PER_IP: usize = 256;
pub const MAX_CHALLENGE_ISSUES_PER_IP_WINDOW: usize = 300;
pub const CHALLENGE_CAPACITY_ADVISORY_LOCK: i64 = 5_640_963_765_310_692_929;
pub const MESSAGE_ADMISSION_CAPACITY_SHARDS: u8 = 64;
pub const MAX_ACTIVE_MESSAGE_ADMISSIONS_PER_SHARD: i32 = 32_768;
pub const MAX_ACTIVE_MESSAGE_ADMISSIONS_PER_USER: i64 = 4_096;
pub const MESSAGE_ADMISSION_LEASE: std::time::Duration = std::time::Duration::from_secs(60);
pub const MESSAGE_ADMISSION_PENDING_TTL: std::time::Duration =
    std::time::Duration::from_secs(30 * 60);
pub const MESSAGE_ADMISSION_ACCEPTED_TTL: std::time::Duration =
    std::time::Duration::from_secs(6 * 60 * 60);
pub const OFFLINE_MESSAGE_ADMISSION_REPLAY_GRACE: std::time::Duration =
    std::time::Duration::from_secs(30 * 24 * 60 * 60);
pub const MESSAGE_ADMISSION_CLEANUP_BATCH: i64 = 1_000;
pub const ABUSE_STATE_GATE_SHARDS: usize = 1_024;
pub const ABUSE_STATE_ADVISORY_HASH_SEED: i64 = 5_841_153_820_082_015_233;

/// Action category targeted by rate-limiting, proof-of-work, or cooldown.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AbuseAction {
    Registration,
    Message,
    Report,
    Appeal,
    Login,
    PasswordChange,
}

impl AbuseAction {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Registration => "registration",
            Self::Message => "message",
            Self::Report => "report",
            Self::Appeal => "appeal",
            Self::Login => "login",
            Self::PasswordChange => "password_change",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "registration" => Some(Self::Registration),
            "message" => Some(Self::Message),
            "report" => Some(Self::Report),
            "appeal" => Some(Self::Appeal),
            "login" => Some(Self::Login),
            "password_change" => Some(Self::PasswordChange),
            _ => None,
        }
    }
}

impl std::fmt::Display for AbuseAction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Strongly-typed actor dimension representing pseudonymized identity components.
///
/// Raw IP addresses, account passwords, and unpseudonymized personal identifiers
/// must never be stored in this type.
#[derive(Clone, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub enum ActorDimension {
    /// Network source dimension (e.g. pseudonymized IP or NAT bucket)
    Ip(String),
    /// Account identity dimension (e.g. pseudonymized user UUID)
    Account(String),
    /// Behavioral clustering dimension (persists across distinct action families)
    Behavior(String),
    /// Login-specific target account tag
    LoginAccount(String),
    /// Custom dimension with an explicit prefix
    Custom { prefix: String, tag: String },
}

impl ActorDimension {
    /// Parse from an existing prefixed actor string representation.
    pub fn parse(actor_str: &str) -> Self {
        if let Some(ip) = actor_str.strip_prefix("ip:") {
            Self::Ip(ip.to_owned())
        } else if let Some(user) = actor_str.strip_prefix("user:") {
            Self::Account(user.to_owned())
        } else if let Some(behavior) = actor_str.strip_prefix("behavior:") {
            Self::Behavior(behavior.to_owned())
        } else if let Some(login) = actor_str.strip_prefix("login-account:") {
            Self::LoginAccount(login.to_owned())
        } else if let Some((prefix, tag)) = actor_str.split_once(':') {
            Self::Custom {
                prefix: prefix.to_owned(),
                tag: tag.to_owned(),
            }
        } else {
            Self::Account(actor_str.to_owned())
        }
    }

    /// Formats this actor dimension with its standard prefix.
    pub fn to_prefixed_string(&self) -> String {
        match self {
            Self::Ip(tag) => format!("ip:{tag}"),
            Self::Account(tag) => format!("user:{tag}"),
            Self::Behavior(tag) => format!("behavior:{tag}"),
            Self::LoginAccount(tag) => format!("login-account:{tag}"),
            Self::Custom { prefix, tag } => format!("{prefix}:{tag}"),
        }
    }

    pub fn is_ip(&self) -> bool {
        matches!(self, Self::Ip(_))
    }

    pub fn is_behavior(&self) -> bool {
        matches!(self, Self::Behavior(_))
    }

    /// Whether this actor represents a shared IP address for multi-actor actions.
    ///
    /// Registration actions treat the source IP as primary. Authenticated multi-actor
    /// actions (e.g. messaging with account + IP + behavior) treat the IP as a shared
    /// carrier-grade NAT signal that receives high-threshold burst protection without
    /// exhausting NAT peers.
    pub fn is_shared_ip(&self, action: AbuseAction, total_actors_count: usize) -> bool {
        action != AbuseAction::Registration && total_actors_count > 1 && self.is_ip()
    }

    /// Canonical state key for this actor dimension and action.
    ///
    /// Behavior keys are cross-action by design; other dimensions are action-scoped.
    pub fn canonical_state_key(&self, action: AbuseAction) -> String {
        match self {
            Self::Behavior(tag) => format!("behavior:{tag}"),
            other => format!(
                "{}:{actor}",
                action.as_str(),
                actor = other.to_prefixed_string()
            ),
        }
    }
}

impl std::fmt::Display for ActorDimension {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.to_prefixed_string())
    }
}

/// Dynamic computational work and cooldown requirement returned to clients or callers.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct WorkRequirement {
    pub action: String,
    pub step: u32,
    pub work_factor: u64,
    pub max_work_factor: u64,
    pub hard_wait_seconds: u64,
    pub retry_after_seconds: u64,
    pub cooldown_seconds: u64,
    pub approximate_max_device_seconds: u64,
    pub notice: String,
}

/// Errors occurring during PoW intent creation or validation.
#[derive(Clone, Debug, Eq, PartialEq, Error)]
pub enum IntentError {
    #[error("invalid PoW intent method: {0}")]
    InvalidMethod(String),
    #[error("invalid PoW intent path: {0}")]
    InvalidPath(String),
    #[error("PoW intent is not valid for action {action}: {method} {path}")]
    ActionMismatch {
        action: AbuseAction,
        method: String,
        path: String,
    },
    #[error("unsupported PoW intent version: {0}")]
    UnsupportedVersion(u16),
    #[error("PoW body digest is not canonical base64url")]
    InvalidDigestEncoding,
    #[error("PoW body digest must contain {expected} bytes, found {found}")]
    InvalidDigestLength { expected: usize, found: usize },
}

/// Public, non-secret commitment supplied when a client requests a v2 PoW challenge.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PowIntentRequest {
    pub version: u16,
    pub method: String,
    pub path: String,
    pub body_sha256: String,
}

/// Read-only wire view of a validated PoW intent.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct PowIntentView {
    pub version: u16,
    pub method: String,
    pub path: String,
    pub body_sha256: String,
}

/// Validated semantic action intent bound to a proof-of-work challenge.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct PowIntent {
    method: String,
    path: String,
    body_sha256: [u8; POW_BODY_DIGEST_BYTES],
}

impl PowIntent {
    pub fn new(
        action: AbuseAction,
        method: &str,
        path: &str,
        body_sha256: [u8; POW_BODY_DIGEST_BYTES],
    ) -> Result<Self, IntentError> {
        let trimmed_method = method.trim();
        if trimmed_method != method
            || method != method.to_ascii_uppercase()
            || !matches!(method, "POST" | "PATCH" | "XMPP")
        {
            return Err(IntentError::InvalidMethod(method.to_owned()));
        }
        if !canonical_pow_path(path) {
            return Err(IntentError::InvalidPath(path.to_owned()));
        }
        if !action_accepts_intent(action, method, path) {
            return Err(IntentError::ActionMismatch {
                action,
                method: method.to_owned(),
                path: path.to_owned(),
            });
        }
        Ok(Self {
            method: method.to_owned(),
            path: path.to_owned(),
            body_sha256,
        })
    }

    pub fn from_request(
        action: AbuseAction,
        request: &PowIntentRequest,
    ) -> Result<Self, IntentError> {
        if request.version != POW_INTENT_VERSION {
            return Err(IntentError::UnsupportedVersion(request.version));
        }
        let decoded = URL_SAFE_NO_PAD
            .decode(request.body_sha256.as_bytes())
            .map_err(|_| IntentError::InvalidDigestEncoding)?;
        if decoded.len() != POW_BODY_DIGEST_BYTES {
            return Err(IntentError::InvalidDigestLength {
                expected: POW_BODY_DIGEST_BYTES,
                found: decoded.len(),
            });
        }
        let mut body_sha256 = [0_u8; POW_BODY_DIGEST_BYTES];
        body_sha256.copy_from_slice(&decoded);
        if URL_SAFE_NO_PAD.encode(body_sha256) != request.body_sha256 {
            return Err(IntentError::InvalidDigestEncoding);
        }
        Self::new(action, &request.method, &request.path, body_sha256)
    }

    pub fn http_json(
        action: AbuseAction,
        path: &str,
        value: &serde_json::Value,
    ) -> Result<Self, IntentError> {
        Self::http_json_method(action, "POST", path, value)
    }

    pub fn http_json_method(
        action: AbuseAction,
        method: &str,
        path: &str,
        value: &serde_json::Value,
    ) -> Result<Self, IntentError> {
        Self::new(action, method, path, canonical_json_body_digest(value))
    }

    pub fn xmpp(
        action: AbuseAction,
        path: &str,
        canonical_body: &[u8],
    ) -> Result<Self, IntentError> {
        Self::new(action, "XMPP", path, Sha256::digest(canonical_body).into())
    }

    /// Build semantic commitment for XEP-0077 and XEP-0389 registration.
    ///
    /// The password and invitation token are fed directly into SHA-256 and
    /// are never stored in memory or JSON/XML structures.
    pub fn xmpp_registration(
        username: &str,
        password: &str,
        invitation_token: Option<&str>,
    ) -> Result<Self, IntentError> {
        fn field(digest: &mut Sha256, value: Option<&str>) {
            match value {
                Some(value) => {
                    digest.update([1]);
                    digest.update((value.len() as u64).to_be_bytes());
                    digest.update(value.as_bytes());
                }
                None => digest.update([0]),
            }
        }

        let mut digest = Sha256::new();
        digest.update(b"northstar/xmpp-registration-intent/v1\0");
        field(&mut digest, Some(username));
        field(&mut digest, Some(password));
        field(&mut digest, invitation_token);
        Self::new(
            AbuseAction::Registration,
            "XMPP",
            "/xmpp/register",
            digest.finalize().into(),
        )
    }

    pub fn view(&self) -> PowIntentView {
        PowIntentView {
            version: POW_INTENT_VERSION,
            method: self.method.clone(),
            path: self.path.clone(),
            body_sha256: URL_SAFE_NO_PAD.encode(self.body_sha256),
        }
    }

    pub fn method(&self) -> &str {
        &self.method
    }

    pub fn path(&self) -> &str {
        &self.path
    }

    pub fn body_sha256(&self) -> &[u8; POW_BODY_DIGEST_BYTES] {
        &self.body_sha256
    }

    pub fn body_sha256_base64url(&self) -> String {
        URL_SAFE_NO_PAD.encode(self.body_sha256)
    }
}

/// Verifies whether an HTTP/XMPP path adheres to canonical PoW intent constraints.
pub fn canonical_pow_path(path: &str) -> bool {
    !path.is_empty()
        && path.len() <= POW_INTENT_PATH_MAX_BYTES
        && path.starts_with('/')
        && path.is_ascii()
        && !path.contains(['?', '#', '\\', '\0'])
        && !path.contains("//")
        && !path.split('/').any(|segment| matches!(segment, "." | ".."))
        && !path.chars().any(char::is_control)
}

/// Validates whether a specific action accepts a method and path combination.
pub fn action_accepts_intent(action: AbuseAction, method: &str, path: &str) -> bool {
    match (action, method, path) {
        (AbuseAction::Registration, "POST", "/api/v1/register")
        | (AbuseAction::Registration, "XMPP", "/xmpp/register")
        | (AbuseAction::Login, "POST", "/api/v1/login")
        | (AbuseAction::Message, "XMPP", "/xmpp/message")
        | (AbuseAction::Report, "POST", "/api/v1/reports")
        | (AbuseAction::PasswordChange, "PATCH", "/api/v1/me/password")
        | (AbuseAction::PasswordChange, "XMPP", "/xmpp/password-change")
        | (AbuseAction::PasswordChange, "XMPP", "/xmpp/account-remove") => true,
        (AbuseAction::Appeal, "POST", path) => path
            .strip_prefix("/api/v1/reports/")
            .and_then(|tail| tail.strip_suffix("/appeals"))
            .and_then(|id| Uuid::parse_str(id).ok().map(|parsed| (id, parsed)))
            .is_some_and(|(id, parsed)| id == parsed.to_string()),
        _ => false,
    }
}

/// Computes a canonical SHA-256 digest over a JSON value where object keys are sorted.
pub fn canonical_json_body_digest(value: &serde_json::Value) -> [u8; 32] {
    fn append(value: &serde_json::Value, output: &mut String) {
        match value {
            serde_json::Value::Null => output.push_str("null"),
            serde_json::Value::Bool(val) => {
                output.push_str(if *val { "true" } else { "false" });
            }
            serde_json::Value::Number(val) => output.push_str(&val.to_string()),
            serde_json::Value::String(val) => {
                let serialized = serde_json::to_string(val).unwrap_or_else(|_| "\"\"".to_owned());
                output.push_str(&serialized);
            }
            serde_json::Value::Array(values) => {
                output.push('[');
                for (index, val) in values.iter().enumerate() {
                    if index > 0 {
                        output.push(',');
                    }
                    append(val, output);
                }
                output.push(']');
            }
            serde_json::Value::Object(values) => {
                output.push('{');
                let mut keys = values.keys().collect::<Vec<_>>();
                keys.sort_unstable();
                for (index, key) in keys.into_iter().enumerate() {
                    if index > 0 {
                        output.push(',');
                    }
                    let serialized_key =
                        serde_json::to_string(key).unwrap_or_else(|_| "\"\"".to_owned());
                    output.push_str(&serialized_key);
                    output.push(':');
                    append(&values[key], output);
                }
                output.push('}');
            }
        }
    }

    let mut canonical = String::new();
    append(value, &mut canonical);
    Sha256::digest(canonical.as_bytes()).into()
}

/// Proof-of-work solution submitted by a client.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PowProof {
    pub challenge_id: Uuid,
    pub nonce: String,
}

/// Complete proof-of-work challenge issued by the anti-abuse policy.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PowChallenge {
    pub version: u16,
    pub challenge_id: Uuid,
    pub prefix: String,
    pub key_id: String,
    pub issued_at: chrono::DateTime<chrono::Utc>,
    pub expires_at: chrono::DateTime<chrono::Utc>,
    pub expires_in_seconds: u64,
    pub server_nonce: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub intent: Option<PowIntentView>,
    pub requirement: WorkRequirement,
}

/// Least-authority purpose for content-identity commitments.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum ContentIdentityPurpose {
    PersonalMessage,
    PersonalRetraction,
    MixMessage,
    MixRetraction,
}

impl ContentIdentityPurpose {
    pub const fn label(self) -> &'static [u8] {
        match self {
            Self::PersonalMessage => b"personal-message",
            Self::PersonalRetraction => b"personal-retraction",
            Self::MixMessage => b"mix-message",
            Self::MixRetraction => b"mix-retraction",
        }
    }
}

/// Public commitment produced by the private content-identity keyring.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ContentIdentityAuthenticator {
    pub key_id: String,
    pub mac: [u8; 32],
}

impl ContentIdentityAuthenticator {
    pub fn new(key_id: String, mac: [u8; 32]) -> Self {
        Self { key_id, mac }
    }

    pub fn key_id(&self) -> &str {
        &self.key_id
    }

    pub fn mac(&self) -> &[u8; 32] {
        &self.mac
    }

    pub fn verifies(&self, key_id: &str, expected_mac: &[u8]) -> bool {
        self.key_id == key_id && bool::from(self.mac.as_slice().ct_eq(expected_mac))
    }
}

/// Current and previous commitments for one exact canonical payload.
#[derive(Clone, Debug)]
pub struct ContentIdentityAuthenticators {
    pub candidates: Vec<ContentIdentityAuthenticator>,
}

impl ContentIdentityAuthenticators {
    pub fn new(candidates: Vec<ContentIdentityAuthenticator>) -> Self {
        Self { candidates }
    }

    pub fn primary(&self) -> Option<&ContentIdentityAuthenticator> {
        self.candidates.first()
    }

    pub fn verifies(&self, key_id: &str, expected_mac: &[u8]) -> bool {
        self.candidates
            .iter()
            .any(|candidate| candidate.verifies(key_id, expected_mac))
    }

    pub fn candidates(&self) -> &[ContentIdentityAuthenticator] {
        &self.candidates
    }
}

/// Immutable, validated input to durable message rate admission.
#[derive(Clone, Copy, Debug)]
pub struct MessageAdmissionRequest<'a> {
    pub actor_id: Uuid,
    pub account_bare: &'a str,
    pub normalized_target: &'a str,
    pub origin_id: Option<&'a str>,
    pub normalized_payload: &'a str,
    pub pow_intent_payload: &'a str,
    pub subject: &'a str,
    pub actors: &'a [String],
    pub proof: Option<&'a PowProof>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MessageDedupeCandidate {
    pub key_id: String,
    pub payload_mac: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MessageDedupeIdentity {
    pub identity_digest: Vec<u8>,
    pub candidates: Vec<MessageDedupeCandidate>,
}

/// Guard error returned when PoW or cooldown admission fails.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum GuardError {
    Required(WorkRequirement),
    Invalid(&'static str, WorkRequirement),
}

impl GuardError {
    pub fn requirement(&self) -> &WorkRequirement {
        match self {
            Self::Required(req) | Self::Invalid(_, req) => req,
        }
    }

    pub fn message(&self) -> &'static str {
        match self {
            Self::Required(_) => "proof of work or cooldown is required",
            Self::Invalid(msg, _) => msg,
        }
    }
}

impl std::fmt::Display for GuardError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: step {}", self.message(), self.requirement().step)
    }
}

impl std::error::Error for GuardError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_json_digest_sorting_and_determinism() {
        let first = serde_json::json!({"z":[3, {"b":true,"a":"value"}],"a":null});
        let reordered = serde_json::json!({"a":null,"z":[3, {"a":"value","b":true}]});
        let changed = serde_json::json!({"a":null,"z":[3, {"a":"changed","b":true}]});
        assert_eq!(
            canonical_json_body_digest(&first),
            canonical_json_body_digest(&reordered)
        );
        assert_ne!(
            canonical_json_body_digest(&first),
            canonical_json_body_digest(&changed)
        );

        let browser_vector = serde_json::json!({
            "username":"alice",
            "password":"秘密pass123",
            "invitation_token":null
        });
        assert_eq!(
            URL_SAFE_NO_PAD.encode(canonical_json_body_digest(&browser_vector)),
            "YQTJXLqYiX5ozfSad42LkiW0yxb40r7JzrfODA-h1YY"
        );
    }

    #[test]
    fn actor_dimension_parsing_and_shared_ip_classification() {
        let ip = ActorDimension::parse("ip:198.51.100.1");
        assert!(ip.is_ip());
        assert!(!ip.is_behavior());
        assert_eq!(ip.to_prefixed_string(), "ip:198.51.100.1");
        assert!(ip.is_shared_ip(AbuseAction::Message, 3));
        assert!(!ip.is_shared_ip(AbuseAction::Registration, 3));
        assert!(!ip.is_shared_ip(AbuseAction::Message, 1));

        let user = ActorDimension::parse("user:00000000-0000-0000-0000-000000000001");
        assert!(!user.is_ip());
        assert_eq!(
            user.canonical_state_key(AbuseAction::Message),
            "message:user:00000000-0000-0000-0000-000000000001"
        );

        let behavior = ActorDimension::parse("behavior:session-cluster-1");
        assert!(behavior.is_behavior());
        assert_eq!(
            behavior.canonical_state_key(AbuseAction::Message),
            "behavior:session-cluster-1"
        );
        assert_eq!(
            behavior.canonical_state_key(AbuseAction::Login),
            "behavior:session-cluster-1"
        );
    }

    #[test]
    fn intent_path_and_action_verification() {
        assert!(canonical_pow_path("/api/v1/reports"));
        assert!(canonical_pow_path("/xmpp/message"));
        assert!(!canonical_pow_path(""));
        assert!(!canonical_pow_path("relative/path"));
        assert!(!canonical_pow_path("/path/../traversal"));
        assert!(!canonical_pow_path("/path//double-slash"));
        assert!(!canonical_pow_path("/path?query=1"));

        assert!(action_accepts_intent(
            AbuseAction::Report,
            "POST",
            "/api/v1/reports"
        ));
        assert!(action_accepts_intent(
            AbuseAction::Message,
            "XMPP",
            "/xmpp/message"
        ));
        assert!(action_accepts_intent(
            AbuseAction::Appeal,
            "POST",
            "/api/v1/reports/a0000000-0000-0000-0000-000000000001/appeals"
        ));
        assert!(!action_accepts_intent(
            AbuseAction::Appeal,
            "POST",
            "/api/v1/reports/invalid-uuid/appeals"
        ));
    }
}
