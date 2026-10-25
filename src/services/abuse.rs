use self::records::DbActorState;
use crate::services::message_admission::witness::AdmissionWitness;
#[cfg(test)]
use crate::services::message_admission::{begin_command, operation};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use dashmap::DashMap;
use hmac::{Hmac, Mac};
pub use northstar_abuse_policy::{
    AbuseAction, AbuseConfig, GuardError, PowChallenge, PowIntentRequest, PowIntentView, PowProof,
    WorkRequirement,
};
use rand::RngCore;
use sha2::{Digest, Sha256};
#[cfg(test)]
use sqlx::PgPool;
use std::{
    collections::{HashSet, VecDeque},
    future::Future,
    pin::Pin,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
use subtle::ConstantTimeEq;
use uuid::Uuid;
use zeroize::Zeroizing;

mod challenges;
mod key_management;
mod persistence;
pub(crate) mod records;

use self::challenges::{build_requirement, decayed_penalty, max_penalty_decay_horizon};
#[cfg(test)]
use self::key_management::{actor_key_id, derive_actor_key_secret, ContentIdentityAuthenticator};
use self::key_management::{
    derive_content_identity_key, opaque_actor_key, opaque_challenge_capacity_key, pow_prefix,
    subject_hash, ContentIdentityGeneration,
};
pub(crate) use self::key_management::{
    ContentIdentityAuthenticators, MixMessageContentKeyring, MixRetractionContentKeyring,
};
use self::persistence::actor_state_keys;

pub const POW_INTENT_VERSION: u16 = northstar_abuse_policy::POW_INTENT_VERSION;
const POW_BODY_DIGEST_BYTES: usize = northstar_abuse_policy::POW_BODY_DIGEST_BYTES;

/// Public, non-secret commitment supplied when a capable client requests a
/// v2 challenge. `body_sha256` is the base64url (unpadded) SHA-256 of the
/// canonical operation body; callers never send the body itself to the
/// challenge endpoint.
/// Server-validated action intent.  It is deliberately independent from the
/// proof envelope: mutation handlers reconstruct this value from their own
/// route and pow-less body rather than trusting fields repeated by a client.
#[derive(Clone, Debug, Eq, PartialEq)]
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
    ) -> anyhow::Result<Self> {
        anyhow::ensure!(
            method == method.trim()
                && method == method.to_ascii_uppercase()
                && matches!(method, "POST" | "PATCH" | "XMPP"),
            "invalid PoW intent method"
        );
        anyhow::ensure!(canonical_pow_path(path), "invalid PoW intent path");
        anyhow::ensure!(
            action_accepts_intent(action, method, path),
            "PoW intent is not valid for this action"
        );
        Ok(Self {
            method: method.to_owned(),
            path: path.to_owned(),
            body_sha256,
        })
    }

    pub fn from_request(action: AbuseAction, request: &PowIntentRequest) -> anyhow::Result<Self> {
        anyhow::ensure!(
            request.version == POW_INTENT_VERSION,
            "unsupported PoW intent version"
        );
        let decoded = URL_SAFE_NO_PAD
            .decode(request.body_sha256.as_bytes())
            .map_err(|_| anyhow::anyhow!("PoW body digest is not canonical base64url"))?;
        let body_sha256: [u8; POW_BODY_DIGEST_BYTES] = decoded
            .try_into()
            .map_err(|_| anyhow::anyhow!("PoW body digest must contain 32 bytes"))?;
        anyhow::ensure!(
            URL_SAFE_NO_PAD.encode(body_sha256) == request.body_sha256,
            "PoW body digest is not canonical base64url"
        );
        Self::new(action, &request.method, &request.path, body_sha256)
    }

    pub fn http_json(action: AbuseAction, path: &str, value: &serde_json::Value) -> Self {
        Self::http_json_method(action, "POST", path, value)
    }

    pub fn http_json_method(
        action: AbuseAction,
        method: &str,
        path: &str,
        value: &serde_json::Value,
    ) -> Self {
        Self::new(action, method, path, canonical_json_body_digest(value))
            .expect("server-owned HTTP PoW intent is valid")
    }

    pub fn xmpp(action: AbuseAction, path: &str, canonical_body: &[u8]) -> Self {
        Self::new(action, "XMPP", path, Sha256::digest(canonical_body).into())
            .expect("server-owned XMPP PoW intent is valid")
    }

    /// Build the semantic commitment used by both XEP-0077 and XEP-0389
    /// registration.  Those protocols render the same values through
    /// different XML shapes, so hashing the wire representation would make a
    /// challenge transport-specific and vulnerable to harmless serializer
    /// drift.  Length-prefixed fields are unambiguous; the domain separator
    /// lets this profile evolve without colliding with other XMPP intents.
    ///
    /// The password and invitation token are fed directly into SHA-256 and are
    /// never copied into a JSON/XML value or retained by `PowIntent`.
    pub fn xmpp_registration(
        username: &str,
        password: &str,
        invitation_token: Option<&str>,
    ) -> Self {
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
        .expect("server-owned XMPP registration intent is valid")
    }

    fn view(&self) -> PowIntentView {
        PowIntentView {
            version: POW_INTENT_VERSION,
            method: self.method.clone(),
            path: self.path.clone(),
            body_sha256: URL_SAFE_NO_PAD.encode(self.body_sha256),
        }
    }

    fn commitment(&self) -> northstar_abuse_policy::PowIntentCommitment<'_> {
        northstar_abuse_policy::PowIntentCommitment {
            method: &self.method,
            path: &self.path,
            body_sha256: &self.body_sha256,
        }
    }
}

fn canonical_pow_path(path: &str) -> bool {
    northstar_abuse_policy::canonical_pow_path(path)
}

fn action_accepts_intent(action: AbuseAction, method: &str, path: &str) -> bool {
    northstar_abuse_policy::action_accepts_intent(action, method, path)
}

/// Deterministic JSON used only as a digest preimage. Object keys are sorted;
/// arrays retain order; scalar serialization follows JSON. The returned bytes
/// are never persisted. Browser code implements the same small profile.
pub fn canonical_json_body_digest(value: &serde_json::Value) -> [u8; 32] {
    northstar_abuse_policy::canonical_json_body_digest(value)
}

const MAX_ACTIVE_POW_CHALLENGES_GLOBAL: usize =
    northstar_abuse_policy::MAX_ACTIVE_POW_CHALLENGES_GLOBAL;
const MAX_ACTIVE_POW_CHALLENGES_PER_ACTOR: usize =
    northstar_abuse_policy::MAX_ACTIVE_POW_CHALLENGES_PER_ACTOR;
const MAX_ACTIVE_POW_CHALLENGES_PER_IP: usize =
    northstar_abuse_policy::MAX_ACTIVE_POW_CHALLENGES_PER_IP;
const MAX_CHALLENGE_ISSUES_PER_IP_WINDOW: usize =
    northstar_abuse_policy::MAX_CHALLENGE_ISSUES_PER_IP_WINDOW;
#[cfg(test)]
const MESSAGE_ADMISSION_CAPACITY_SHARDS: u8 =
    northstar_abuse_policy::MESSAGE_ADMISSION_CAPACITY_SHARDS;
#[cfg(test)]
const MAX_ACTIVE_MESSAGE_ADMISSIONS_PER_SHARD: i32 =
    northstar_abuse_policy::MAX_ACTIVE_MESSAGE_ADMISSIONS_PER_SHARD;
#[cfg(test)]
const MAX_ACTIVE_MESSAGE_ADMISSIONS_PER_USER: i64 =
    northstar_abuse_policy::MAX_ACTIVE_MESSAGE_ADMISSIONS_PER_USER;
#[cfg(test)]
const MESSAGE_ADMISSION_LEASE: Duration = northstar_abuse_policy::MESSAGE_ADMISSION_LEASE;
const MESSAGE_ADMISSION_ACCEPTED_TTL: Duration =
    northstar_abuse_policy::MESSAGE_ADMISSION_ACCEPTED_TTL;
#[cfg(test)]
const MESSAGE_ADMISSION_CLEANUP_BATCH: i64 =
    northstar_abuse_policy::MESSAGE_ADMISSION_CLEANUP_BATCH;
/// A delivered offline message retains its replay tombstone for exactly this
/// long.  The PostgreSQL trigger in migration 0079 uses the same 30-day value.
/// Live queued messages can outlast this bound and are therefore protected by
/// the deployment reference fence in `db::abuse_keys` as well.
pub(crate) const OFFLINE_MESSAGE_ADMISSION_REPLAY_GRACE: Duration =
    northstar_abuse_policy::OFFLINE_MESSAGE_ADMISSION_REPLAY_GRACE;
/// Local waiters queue on these stripes before acquiring a PgPool connection.
/// PostgreSQL try-locks below remain the cross-process authority.
const ABUSE_STATE_GATE_SHARDS: usize = northstar_abuse_policy::ABUSE_STATE_GATE_SHARDS;

#[derive(Debug)]
pub struct ChallengeCapacityExceeded {
    pub(crate) retry_after_seconds: u64,
}

impl ChallengeCapacityExceeded {
    pub fn retry_after_seconds(&self) -> u64 {
        self.retry_after_seconds.max(1)
    }
}

impl std::fmt::Display for ChallengeCapacityExceeded {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("proof-of-work challenge issuance capacity is exhausted")
    }
}

impl std::error::Error for ChallengeCapacityExceeded {}

#[derive(Debug)]
pub struct AbuseStateBusy;

impl std::fmt::Display for AbuseStateBusy {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("anti-abuse actor state is busy; retry later")
    }
}

impl std::error::Error for AbuseStateBusy {}

pub fn is_abuse_state_busy(error: &anyhow::Error) -> bool {
    error.downcast_ref::<AbuseStateBusy>().is_some()
}

#[derive(Clone, Copy)]
enum ContentIdentityPurpose {
    PersonalMessage,
    PersonalRetraction,
    MixMessage,
    MixRetraction,
}

impl ContentIdentityPurpose {
    fn label(self) -> &'static [u8] {
        match self {
            Self::PersonalMessage => b"personal-message",
            Self::PersonalRetraction => b"personal-retraction",
            Self::MixMessage => b"mix-message",
            Self::MixRetraction => b"mix-retraction",
        }
    }
}

impl ContentIdentityAuthenticators {
    #[cfg(test)]
    pub(crate) fn candidates(&self) -> &[ContentIdentityAuthenticator] {
        &self.candidates
    }
}

#[derive(Clone)]
pub(crate) struct PersonalMessageContentKeyring {
    generations: Arc<Vec<ContentIdentityGeneration>>,
}

#[derive(Clone)]
pub(crate) struct PersonalRetractionContentKeyring {
    generations: Arc<Vec<ContentIdentityGeneration>>,
}

#[cfg(test)]
fn test_content_identity_generations(
    purpose: ContentIdentityPurpose,
) -> Arc<Vec<ContentIdentityGeneration>> {
    let actor_secret = Zeroizing::new(derive_actor_key_secret(
        b"northstar-content-identity-test-secret-v1",
    ));
    Arc::new(vec![ContentIdentityGeneration {
        key_id: actor_key_id(actor_secret.as_slice()),
        key: Zeroizing::new(derive_content_identity_key(
            actor_secret.as_slice(),
            purpose,
        )),
    }])
}

#[cfg(test)]
pub(crate) fn test_personal_message_content_keyring() -> PersonalMessageContentKeyring {
    PersonalMessageContentKeyring {
        generations: test_content_identity_generations(ContentIdentityPurpose::PersonalMessage),
    }
}

#[cfg(test)]
pub(crate) fn test_personal_retraction_content_keyring() -> PersonalRetractionContentKeyring {
    PersonalRetractionContentKeyring {
        generations: test_content_identity_generations(ContentIdentityPurpose::PersonalRetraction),
    }
}

#[cfg(test)]
pub(crate) fn test_mix_message_content_keyring() -> MixMessageContentKeyring {
    MixMessageContentKeyring {
        generations: test_content_identity_generations(ContentIdentityPurpose::MixMessage),
    }
}

#[cfg(test)]
pub(crate) fn test_mix_retraction_content_keyring() -> MixRetractionContentKeyring {
    MixRetractionContentKeyring {
        generations: test_content_identity_generations(ContentIdentityPurpose::MixRetraction),
    }
}

fn message_admission_identity<'a>(
    request: &'a MessageAdmissionRequest<'a>,
) -> Option<(&'static [u8], Vec<u8>)> {
    request
        .origin_id
        .map(|origin| (b"origin-id".as_slice(), origin.as_bytes().to_vec()))
        .or_else(|| {
            request.proof.map(|proof| {
                (
                    b"challenge".as_slice(),
                    proof.challenge_id.as_bytes().to_vec(),
                )
            })
        })
}

fn message_admission_mac_field(mac: &mut Hmac<Sha256>, value: &[u8]) {
    mac.update(&u64::try_from(value.len()).unwrap_or(u64::MAX).to_be_bytes());
    mac.update(value);
}

/// Stable lookup key for the offline-delivery tombstone. The identity value is
/// a client-generated XEP-0359 origin-id or a random one-use challenge UUID,
/// so this digest is not an enumerable account/JID hash. Payload authenticity
/// remains protected separately by the rotating HMAC keyring.
fn message_admission_identity_digest(
    request: &MessageAdmissionRequest<'_>,
    identity_kind: &[u8],
    identity_value: &[u8],
) -> Vec<u8> {
    northstar_abuse_policy::message_admission_identity_digest(
        request.account_bare,
        request.normalized_target,
        identity_kind,
        identity_value,
    )
    .to_vec()
}

fn message_admission_material(
    request: &MessageAdmissionRequest<'_>,
    secret: &[u8],
    identity_kind: &[u8],
    identity_value: &[u8],
) -> (Vec<u8>, Vec<u8>) {
    let (admission_key, payload_mac) = northstar_abuse_policy::message_admission_material(
        request.account_bare,
        request.normalized_target,
        identity_kind,
        identity_value,
        request.normalized_payload,
        secret,
    );
    (admission_key.to_vec(), payload_mac.to_vec())
}

#[cfg(test)]
fn message_admission_capacity_shard(admission_key: &[u8]) -> i16 {
    northstar_abuse_policy::message_admission_capacity_shard(admission_key)
}

fn chrono_duration(duration: Duration) -> chrono::Duration {
    chrono::Duration::seconds(i64::try_from(duration.as_secs()).unwrap_or(i64::MAX))
}

fn ceil_seconds(duration: Duration) -> u64 {
    duration
        .as_secs()
        .saturating_add(u64::from(duration.subsec_nanos() != 0))
        .max(1)
}

/// Immutable, authenticated input to one durable message-rate admission.
/// `normalized_payload` is the already validated stanza with the private PoW
/// envelope and untrusted delay assertions removed.  It is never stored; the
/// database retains only a keyed digest.
#[derive(Clone, Copy)]
pub struct MessageAdmissionRequest<'a> {
    pub actor_id: Uuid,
    pub account_bare: &'a str,
    pub normalized_target: &'a str,
    pub origin_id: Option<&'a str>,
    pub normalized_payload: &'a str,
    /// Exact client stanza after direct PoW and unauthenticated delay
    /// elements are removed. This is the v2 body commitment; it is separate
    /// from the server-rewritten payload used for durable deduplication.
    pub pow_intent_payload: &'a str,
    pub subject: &'a str,
    pub actors: &'a [String],
    pub proof: Option<&'a PowProof>,
}

pub(crate) fn validate_message_admission_request(
    request: &MessageAdmissionRequest<'_>,
) -> anyhow::Result<()> {
    anyhow::ensure!(
        request.actor_id != Uuid::nil(),
        "message admission actor must not be nil"
    );
    anyhow::ensure!(
        northstar_xmpp_types::jid::canonical_bare_key(request.account_bare)
            .is_ok_and(|value| value == request.account_bare),
        "message admission account must be a canonical bare JID"
    );
    anyhow::ensure!(
        northstar_xmpp_types::jid::canonicalize(request.normalized_target)
            .is_ok_and(|value| value == request.normalized_target),
        "message admission target must already be canonical"
    );
    anyhow::ensure!(
        !request.normalized_payload.is_empty() && request.normalized_payload.len() <= 1_048_576,
        "message admission payload must contain 1 byte to 1 MiB"
    );
    anyhow::ensure!(
        !request.pow_intent_payload.is_empty() && request.pow_intent_payload.len() <= 1_048_576,
        "message PoW intent payload must contain 1 byte to 1 MiB"
    );
    if let Some(origin_id) = request.origin_id {
        anyhow::ensure!(
            !origin_id.is_empty()
                && origin_id.len() <= 1_024
                && !origin_id.chars().any(char::is_control),
            "message origin-id must contain 1 to 1024 non-control bytes"
        );
    }

    Ok(())
}

#[derive(Clone, Debug)]
pub(crate) struct MessageDedupeCandidate {
    pub(crate) key_id: String,
    pub(crate) payload_mac: Vec<u8>,
}

pub(crate) struct MessageAdmissionCandidate {
    pub(crate) key_id: String,
    pub(crate) admission_key: Vec<u8>,
    pub(crate) payload_mac: Vec<u8>,
}

#[derive(Clone, Debug)]
pub(crate) struct MessageDedupeIdentity {
    pub(crate) identity_digest: Vec<u8>,
    pub(crate) candidates: Vec<MessageDedupeCandidate>,
}

#[derive(Clone)]
pub struct MessageAdmissionLease {
    admission_key: Vec<u8>,
    payload_mac: Vec<u8>,
    lease_token: Uuid,
    pub(crate) offline_dedupe: MessageDedupeIdentity,
}

/// The exact admission fence handed to the database after message delivery.
/// Only a lease issued by the guard can construct this view.
pub(crate) struct MessageAdmissionAcceptance<'a> {
    admission_key: &'a [u8],
    payload_mac: &'a [u8],
    lease_token: Uuid,
}

#[derive(Debug)]
pub enum MessageAdmissionStart {
    Proceed {
        lease: Option<MessageAdmissionLease>,
        requirement: WorkRequirement,
    },
    ReplayAccepted,
    InProgress {
        requirement: WorkRequirement,
    },
    Denied(GuardError),
    Conflict,
    CapacityLimited,
}

/// A denial has already mutated persistent challenge/rate state in the
/// caller's transaction and therefore must be committed before the HTTP error
/// is returned. Database/internal errors remain ordinary `Err` values and the
/// caller must roll the transaction back.
pub enum TransactionalGuardOutcome {
    Allowed,
    DeniedNeedsCommit(GuardError),
}

pub(crate) struct PersistentVerificationInput<'a> {
    pub(crate) action: AbuseAction,
    pub(crate) subject: &'a str,
    pub(crate) actors: &'a [String],
    pub(crate) proof: Option<&'a PowProof>,
    pub(crate) intent: Option<&'a PowIntent>,
}

pub(crate) type AbusePersistenceFuture<'a, T> =
    Pin<Box<dyn Future<Output = anyhow::Result<T>> + Send + 'a>>;
pub(crate) type IssueDecision<'a> = Box<
    dyn FnOnce(
            &mut [DbActorState],
            chrono::DateTime<chrono::Utc>,
        ) -> anyhow::Result<crate::services::abuse::records::IssueRecord>
        + Send
        + 'a,
>;
pub(crate) type VerificationPolicy<'a> = Box<
    dyn FnOnce(
            &mut [DbActorState],
            chrono::DateTime<chrono::Utc>,
            Option<crate::services::abuse::records::ConsumedChallenge>,
        ) -> anyhow::Result<crate::services::abuse::records::VerificationDecision>
        + Send
        + 'a,
>;
pub(crate) type RequirementPolicy<'a> = Box<
    dyn FnOnce(&mut [DbActorState], chrono::DateTime<chrono::Utc>) -> WorkRequirement + Send + 'a,
>;
pub(crate) type FailurePolicy<'a> =
    Box<dyn FnOnce(&mut [DbActorState], chrono::DateTime<chrono::Utc>) + Send + 'a>;

/// Persistence operations own their transactions and connection pool. Policy,
/// signing, and key-rotation decisions remain with the guard and run only
/// while the repository holds the required actor-state locks.
pub(crate) trait AbusePersistence: Send + Sync {
    fn issue<'a>(
        &'a self,
        request: crate::services::abuse::records::IssueRequest,
        decide: IssueDecision<'a>,
    ) -> AbusePersistenceFuture<'a, PowChallenge>;

    fn verify<'a>(
        &'a self,
        actor_state_keys: &'a [String],
        challenge_id: Option<Uuid>,
        decide: VerificationPolicy<'a>,
        witness: Option<&'a AdmissionWitness>,
    ) -> AbusePersistenceFuture<'a, std::result::Result<WorkRequirement, GuardError>>;

    fn current_requirement<'a>(
        &'a self,
        actor_state_keys: &'a [String],
        decide: RequirementPolicy<'a>,
    ) -> AbusePersistenceFuture<'a, WorkRequirement>;

    fn record_failure<'a>(
        &'a self,
        actor_state_keys: &'a [String],
        decide: FailurePolicy<'a>,
    ) -> AbusePersistenceFuture<'a, ()>;

    fn begin_message_admission<'a, 'r: 'a>(
        &'a self,
        guard: &'a AbuseGuard,
        request: &'a MessageAdmissionRequest<'r>,
        candidates: &'a [MessageAdmissionCandidate],
        offline_dedupe: MessageDedupeIdentity,
        witness: &'a AdmissionWitness,
    ) -> AbusePersistenceFuture<'a, MessageAdmissionStart>;

    fn cleanup<'a>(
        &'a self,
        window_seconds: u64,
        stale_seconds: u64,
    ) -> AbusePersistenceFuture<'a, ()>;
}

struct ActorState {
    events: VecDeque<Instant>,
    penalty_level: u32,
    last_activity: Instant,
    blocked_until: Instant,
    sequence: u64,
}

impl ActorState {
    fn new(now: Instant) -> Self {
        Self {
            events: VecDeque::new(),
            penalty_level: 0,
            last_activity: now,
            blocked_until: now,
            sequence: 0,
        }
    }
}

struct StoredChallenge {
    protocol_version: u16,
    action: AbuseAction,
    subject: String,
    intent: Option<PowIntent>,
    key_id: String,
    prefix: String,
    work_factor: u64,
    issued_at: chrono::DateTime<chrono::Utc>,
    expires_at_wall: chrono::DateTime<chrono::Utc>,
    server_nonce: String,
    not_before: Instant,
    expires_at: Instant,
    actor_sequences: Vec<(String, u64)>,
    capacity_actors: Vec<String>,
    requirement: WorkRequirement,
}

#[derive(Debug)]
pub struct LegacyPowV1Disabled;

impl std::fmt::Display for LegacyPowV1Disabled {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("proof-of-work v1 compatibility window is closed")
    }
}

impl std::error::Error for LegacyPowV1Disabled {}

pub struct AbuseGuard {
    config: AbuseConfig,
    /// Production instances use PostgreSQL as the decision point so restart
    /// and multi-process deployments do not reset penalties or permit two
    /// concurrent uses of a challenge. Unit tests may omit it to exercise the
    /// deterministic in-memory model without an external service.
    persistence: Option<Arc<dyn AbusePersistence>>,
    actor_key_secret: Zeroizing<Vec<u8>>,
    actor_key_id: String,
    previous_actor_key_secret: Option<Zeroizing<Vec<u8>>>,
    previous_actor_key_id: Option<String>,
    /// During the rolling overlap, old-only and new dual-key nodes coexist.
    /// Durable artifacts must therefore remain old-key-primary until the
    /// PostgreSQL authority enters `retiring` and fences every old-only node.
    write_with_previous_actor_key: bool,
    legacy_v1_compatibility_until: Option<chrono::DateTime<chrono::Utc>>,
    states: DashMap<String, ActorState>,
    challenges: DashMap<Uuid, StoredChallenge>,
    challenge_issues: DashMap<String, VecDeque<Instant>>,
    challenge_issue_gate: Mutex<()>,
    last_cleanup: Mutex<Instant>,
    /// Fixed stripes avoid an attacker growing a per-identity lock map. Tasks
    /// waiting on a shared NAT/account key hold no database connection.
    db_state_gates: Vec<Arc<tokio::sync::Mutex<()>>>,
}

impl AbuseGuard {
    #[cfg(test)]
    pub fn new_persistent(
        config: AbuseConfig,
        pool: PgPool,
        shared_secret: Option<&[u8]>,
        previous_shared_secret: Option<&[u8]>,
    ) -> Self {
        Self::new_persistent_for_deployment(
            config,
            Arc::new(crate::db::abuse_persistence_repository::PostgresAbusePersistence::new(pool)),
            shared_secret,
            previous_shared_secret,
            false,
            Some(chrono::DateTime::<chrono::Utc>::MAX_UTC),
        )
    }

    fn content_identity_generations(
        &self,
        purpose: ContentIdentityPurpose,
    ) -> Arc<Vec<ContentIdentityGeneration>> {
        Arc::new(
            self.persistent_actor_key_candidates()
                .into_iter()
                .map(|(key_id, actor_secret)| ContentIdentityGeneration {
                    key_id: key_id.to_owned(),
                    key: Zeroizing::new(derive_content_identity_key(actor_secret, purpose)),
                })
                .collect(),
        )
    }

    /// A MessageService receives only the message-purpose subkeys. It cannot
    /// produce or verify a retraction commitment even though both generations
    /// originate from the same mounted deployment secret.
    pub(crate) fn personal_message_content_keyring(&self) -> PersonalMessageContentKeyring {
        PersonalMessageContentKeyring {
            generations: self.content_identity_generations(ContentIdentityPurpose::PersonalMessage),
        }
    }

    /// RetractionService receives a separate least-authority capability.
    pub(crate) fn personal_retraction_content_keyring(&self) -> PersonalRetractionContentKeyring {
        PersonalRetractionContentKeyring {
            generations: self
                .content_identity_generations(ContentIdentityPurpose::PersonalRetraction),
        }
    }

    #[cfg(test)]
    fn issue_memory(
        &self,
        action: AbuseAction,
        subject: &str,
        actors: &[String],
    ) -> anyhow::Result<PowChallenge> {
        self.issue_memory_bound(action, subject, actors, None)
    }

    #[cfg(test)]
    pub async fn verify_or_allow(
        &self,
        action: AbuseAction,
        subject: &str,
        actors: &[String],
        proof: Option<&PowProof>,
    ) -> anyhow::Result<std::result::Result<WorkRequirement, GuardError>> {
        self.verify_or_allow_bound(action, subject, actors, proof, None)
            .await
    }

    /// Consume a message proof and create a recoverable pending admission in
    /// one PostgreSQL transaction. An exact retry resumes after the short
    /// fencing lease expires without consuming the proof or advancing the
    /// actor step twice. An accepted retry is suppressed. The same identity
    /// with different content is always a conflict.
    #[cfg(test)]
    pub async fn begin_message_admission(
        &self,
        request: &MessageAdmissionRequest<'_>,
    ) -> anyhow::Result<MessageAdmissionStart> {
        let (_, witness) = operation(begin_command(request)?);
        self.begin_message_admission_observed(request, &witness)
            .await
    }

    pub(crate) async fn begin_message_admission_observed(
        &self,
        request: &MessageAdmissionRequest<'_>,
        witness: &AdmissionWitness,
    ) -> anyhow::Result<MessageAdmissionStart> {
        validate_message_admission_request(request)?;

        let Some((identity_kind, identity_value)) = message_admission_identity(request) else {
            let intent = PowIntent::xmpp(
                AbuseAction::Message,
                "/xmpp/message",
                request.pow_intent_payload.as_bytes(),
            );
            // This may commit proof/actor state, but never a reservation row.
            let result = if self.persistence.is_some() {
                self.verify_persistent_bound_observed(
                    AbuseAction::Message,
                    request.subject,
                    request.actors,
                    request.proof,
                    Some(&intent),
                    Some(witness),
                )
                .await?
            } else {
                self.verify_memory_bound(
                    AbuseAction::Message,
                    request.subject,
                    request.actors,
                    request.proof,
                    Some(&intent),
                )
            };
            return Ok(match result {
                Ok(requirement) => MessageAdmissionStart::Proceed {
                    lease: None,
                    requirement,
                },
                Err(error) => MessageAdmissionStart::Denied(error),
            });
        };
        let Some(persistence) = self.persistence.as_ref() else {
            let intent = PowIntent::xmpp(
                AbuseAction::Message,
                "/xmpp/message",
                request.pow_intent_payload.as_bytes(),
            );
            let result = self.verify_memory_bound(
                AbuseAction::Message,
                request.subject,
                request.actors,
                request.proof,
                Some(&intent),
            );
            return Ok(match result {
                Ok(requirement) => MessageAdmissionStart::Proceed {
                    lease: None,
                    requirement,
                },
                Err(error) => MessageAdmissionStart::Denied(error),
            });
        };
        let _db_state_gates = self
            .acquire_db_state_gates(AbuseAction::Message, request.actors)
            .await;

        let candidates = self.persistent_actor_key_candidates();
        let candidate_material = candidates
            .iter()
            .map(|(key_id, secret)| {
                let (admission_key, payload_mac) =
                    message_admission_material(request, secret, identity_kind, &identity_value);
                MessageAdmissionCandidate {
                    key_id: (*key_id).to_owned(),
                    admission_key,
                    payload_mac,
                }
            })
            .collect::<Vec<_>>();
        let offline_dedupe = MessageDedupeIdentity {
            identity_digest: message_admission_identity_digest(
                request,
                identity_kind,
                &identity_value,
            ),
            candidates: candidate_material
                .iter()
                .map(|candidate| MessageDedupeCandidate {
                    key_id: candidate.key_id.clone(),
                    payload_mac: candidate.payload_mac.clone(),
                })
                .collect(),
        };
        persistence
            .begin_message_admission(self, request, &candidate_material, offline_dedupe, witness)
            .await
    }

    #[cfg(test)]
    fn verify_memory(
        &self,
        action: AbuseAction,
        subject: &str,
        actors: &[String],
        proof: Option<&PowProof>,
    ) -> Result<WorkRequirement, GuardError> {
        self.verify_memory_bound(action, subject, actors, proof, None)
    }
}

type Policy = northstar_abuse_policy::Policy;

fn policy(action: AbuseAction, base: u64, message_free_burst: usize) -> Policy {
    northstar_abuse_policy::policy(action, base, message_free_burst)
}

/// A message client can legitimately prepare several stanza-bound challenges
/// before the server consumes the first one. A previous acceptance advances
/// the actor sequence, but that must not invalidate a second proof whose
/// advertised work and wait are still at least as strict as the requirement
/// calculated at consumption time.
///
/// Other actions retain exact sequence fencing. A prefetched message is also
/// rejected as soon as a new cooldown is active or either the computational
/// work or hard-wait step has risen. This prevents a batch of cheap challenges
/// from crossing a rate-limit boundary.
fn prefetched_message_challenge_remains_sufficient(
    action: AbuseAction,
    challenge: &WorkRequirement,
    current: &WorkRequirement,
) -> bool {
    northstar_abuse_policy::prefetched_message_challenge_remains_sufficient(
        action, challenge, current,
    )
}

fn state_key(action: AbuseAction, actor: &str) -> String {
    if actor.starts_with("behavior:") {
        actor.to_owned()
    } else {
        format!("{}:{actor}", action.as_str())
    }
}

#[cfg(test)]
mod tests;
