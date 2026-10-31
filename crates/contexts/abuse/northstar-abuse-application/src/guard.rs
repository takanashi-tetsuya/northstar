use self::records::DbActorState;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use dashmap::DashMap;
use northstar_abuse_policy::admission_execution::AdmissionCommitObserver;
use northstar_abuse_policy::admission_transaction::AdmissionFence;
#[cfg(test)]
use northstar_abuse_policy::canonical_json_body_digest;
#[cfg(test)]
use northstar_abuse_policy::PowIntentRequest;
use northstar_abuse_policy::{action_accepts_intent, ContentIdentityPurpose};
use northstar_abuse_policy::{
    AbuseAction, AbuseConfig, GuardError, MessageAdmissionRequest, MessageDedupeCandidate,
    MessageDedupeIdentity, PowChallenge, PowIntent, PowProof, WorkRequirement,
};
use rand::RngCore;
use sha2::{Digest, Sha256};
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
pub mod records;

use self::challenges::{build_requirement, decayed_penalty, max_penalty_decay_horizon};
#[cfg(any(test, feature = "test-support"))]
use self::key_management::{actor_key_id, derive_actor_key_secret};
use self::key_management::{
    derive_content_identity_key, opaque_actor_key, opaque_challenge_capacity_key, pow_prefix,
    subject_hash, ContentIdentityGeneration,
};
pub use self::key_management::{MixMessageContentKeyring, MixRetractionContentKeyring};
use self::persistence::actor_state_keys;
use northstar_abuse_policy::ContentIdentityAuthenticators;

const POW_INTENT_VERSION: u16 = northstar_abuse_policy::POW_INTENT_VERSION;
const MAX_ACTIVE_POW_CHALLENGES_GLOBAL: usize =
    northstar_abuse_policy::MAX_ACTIVE_POW_CHALLENGES_GLOBAL;
const MAX_ACTIVE_POW_CHALLENGES_PER_ACTOR: usize =
    northstar_abuse_policy::MAX_ACTIVE_POW_CHALLENGES_PER_ACTOR;
const MAX_ACTIVE_POW_CHALLENGES_PER_IP: usize =
    northstar_abuse_policy::MAX_ACTIVE_POW_CHALLENGES_PER_IP;
const MAX_CHALLENGE_ISSUES_PER_IP_WINDOW: usize =
    northstar_abuse_policy::MAX_CHALLENGE_ISSUES_PER_IP_WINDOW;
const MESSAGE_ADMISSION_ACCEPTED_TTL: Duration =
    northstar_abuse_policy::MESSAGE_ADMISSION_ACCEPTED_TTL;
/// A delivered offline message retains its replay tombstone for exactly this
/// long.  The PostgreSQL trigger in migration 0079 uses the same 30-day value.
/// Live queued messages can outlast this bound and are therefore protected by
/// the deployment reference fence in `db::abuse_keys` as well.
pub const OFFLINE_MESSAGE_ADMISSION_REPLAY_GRACE: Duration =
    northstar_abuse_policy::OFFLINE_MESSAGE_ADMISSION_REPLAY_GRACE;
/// Local waiters queue on these stripes before acquiring a PgPool connection.
/// PostgreSQL try-locks below remain the cross-process authority.
const ABUSE_STATE_GATE_SHARDS: usize = northstar_abuse_policy::ABUSE_STATE_GATE_SHARDS;

#[derive(Debug)]
pub struct ChallengeCapacityExceeded {
    pub retry_after_seconds: u64,
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

#[derive(Clone)]
pub struct PersonalMessageContentKeyring {
    generations: Arc<Vec<ContentIdentityGeneration>>,
}

#[derive(Clone)]
pub struct PersonalRetractionContentKeyring {
    generations: Arc<Vec<ContentIdentityGeneration>>,
}

#[cfg(any(test, feature = "test-support"))]
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

#[cfg(any(test, feature = "test-support"))]
pub fn test_personal_message_content_keyring() -> PersonalMessageContentKeyring {
    PersonalMessageContentKeyring {
        generations: test_content_identity_generations(ContentIdentityPurpose::PersonalMessage),
    }
}

#[cfg(any(test, feature = "test-support"))]
pub fn test_personal_retraction_content_keyring() -> PersonalRetractionContentKeyring {
    PersonalRetractionContentKeyring {
        generations: test_content_identity_generations(ContentIdentityPurpose::PersonalRetraction),
    }
}

#[cfg(any(test, feature = "test-support"))]
pub fn test_mix_message_content_keyring() -> MixMessageContentKeyring {
    MixMessageContentKeyring {
        generations: test_content_identity_generations(ContentIdentityPurpose::MixMessage),
    }
}

#[cfg(any(test, feature = "test-support"))]
pub fn test_mix_retraction_content_keyring() -> MixRetractionContentKeyring {
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

pub fn validate_message_admission_request(
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

pub struct MessageAdmissionCandidate {
    pub key_id: String,
    pub admission_key: Vec<u8>,
    pub payload_mac: Vec<u8>,
}

#[derive(Clone)]
pub struct MessageAdmissionLease {
    admission_key: Vec<u8>,
    payload_mac: Vec<u8>,
    lease_token: Uuid,
    pub offline_dedupe: MessageDedupeIdentity,
}

/// The exact admission fence handed to the database after message delivery.
/// Only a lease issued by the guard can construct this view.
pub struct MessageAdmissionAcceptance<'a> {
    admission_key: &'a [u8],
    payload_mac: &'a [u8],
    lease_token: Uuid,
}

pub fn acceptance_fence(acceptance: &MessageAdmissionAcceptance<'_>) -> AdmissionFence {
    AdmissionFence {
        admission_key: acceptance.admission_key().to_vec(),
        payload_mac: acceptance.payload_mac().to_vec(),
        lease_token: acceptance.lease_token(),
    }
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

pub struct PersistentVerificationInput<'a> {
    pub action: AbuseAction,
    pub subject: &'a str,
    pub actors: &'a [String],
    pub proof: Option<&'a PowProof>,
    pub intent: Option<&'a PowIntent>,
}

pub type AbusePersistenceFuture<'a, T> =
    Pin<Box<dyn Future<Output = anyhow::Result<T>> + Send + 'a>>;
pub type IssueDecision<'a> = Box<
    dyn FnOnce(
            &mut [DbActorState],
            chrono::DateTime<chrono::Utc>,
        ) -> anyhow::Result<records::IssueRecord>
        + Send
        + 'a,
>;
pub type VerificationPolicy<'a> = Box<
    dyn FnOnce(
            &mut [DbActorState],
            chrono::DateTime<chrono::Utc>,
            Option<records::ConsumedChallenge>,
        ) -> anyhow::Result<records::VerificationDecision>
        + Send
        + 'a,
>;
pub type RequirementPolicy<'a> = Box<
    dyn FnOnce(&mut [DbActorState], chrono::DateTime<chrono::Utc>) -> WorkRequirement + Send + 'a,
>;
pub type FailurePolicy<'a> =
    Box<dyn FnOnce(&mut [DbActorState], chrono::DateTime<chrono::Utc>) + Send + 'a>;

/// Persistence operations own their transactions and connection pool. Policy,
/// signing, and key-rotation decisions remain with the guard and run only
/// while the repository holds the required actor-state locks.
pub trait AbusePersistence: Send + Sync {
    fn issue<'a>(
        &'a self,
        request: records::IssueRequest,
        decide: IssueDecision<'a>,
    ) -> AbusePersistenceFuture<'a, PowChallenge>;

    fn verify<'a>(
        &'a self,
        actor_state_keys: &'a [String],
        challenge_id: Option<Uuid>,
        decide: VerificationPolicy<'a>,
        witness: Option<&'a dyn AdmissionCommitObserver>,
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
        witness: &'a dyn AdmissionCommitObserver,
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
    pub fn personal_message_content_keyring(&self) -> PersonalMessageContentKeyring {
        PersonalMessageContentKeyring {
            generations: self.content_identity_generations(ContentIdentityPurpose::PersonalMessage),
        }
    }

    /// RetractionService receives a separate least-authority capability.
    pub fn personal_retraction_content_keyring(&self) -> PersonalRetractionContentKeyring {
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

    #[cfg(any(test, feature = "test-support"))]
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
    pub async fn begin_message_admission_observed(
        &self,
        request: &MessageAdmissionRequest<'_>,
        witness: &dyn AdmissionCommitObserver,
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

/// What the root crate's cross-context tests need of the guard's internals.
#[cfg(any(test, feature = "test-support"))]
pub mod test_support {
    use super::*;

    pub fn actor_state_keys(action: AbuseAction, actors: &[String], secret: &[u8]) -> Vec<String> {
        super::actor_state_keys(action, actors, secret)
    }

    pub fn opaque_actor_key(action: AbuseAction, actor: &str, secret: &[u8]) -> String {
        super::opaque_actor_key(action, actor, secret)
    }

    pub fn message_admission_identity<'a>(
        request: &'a MessageAdmissionRequest<'a>,
    ) -> Option<(&'static [u8], Vec<u8>)> {
        super::message_admission_identity(request)
    }

    pub fn message_admission_identity_digest(
        request: &MessageAdmissionRequest<'_>,
        identity_kind: &[u8],
        identity_value: &[u8],
    ) -> Vec<u8> {
        super::message_admission_identity_digest(request, identity_kind, identity_value)
    }

    pub fn message_admission_material(
        request: &MessageAdmissionRequest<'_>,
        secret: &[u8],
        identity_kind: &[u8],
        identity_value: &[u8],
    ) -> (Vec<u8>, Vec<u8>) {
        super::message_admission_material(request, secret, identity_kind, identity_value)
    }

    impl AbuseGuard {
        pub fn actor_key_id(&self) -> &str {
            &self.actor_key_id
        }

        pub fn actor_key_secret(&self) -> &[u8] {
            &self.actor_key_secret
        }
    }

    impl MessageAdmissionLease {
        pub fn admission_key(&self) -> &[u8] {
            &self.admission_key
        }
    }
}

#[cfg(test)]
mod tests;
