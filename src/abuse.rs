use crate::db::abuse_actor_state_repository::DbActorState;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use dashmap::DashMap;
use hmac::{Hmac, Mac};
pub use northstar_abuse_policy::{
    AbuseAction, AbuseConfig, GuardError, PowChallenge, PowIntentRequest, PowIntentView, PowProof,
    WorkRequirement,
};
use rand::RngCore;
use sha2::{Digest, Sha256};
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

fn actor_state_keys(action: AbuseAction, actors: &[String], secret: &[u8]) -> Vec<String> {
    let mut keys: Vec<String> = actors
        .iter()
        .map(|actor| opaque_actor_key(action, actor, secret))
        .collect();
    keys.sort();
    keys.dedup();
    keys
}

fn trim_db_events(
    events: &mut Vec<chrono::DateTime<chrono::Utc>>,
    now: chrono::DateTime<chrono::Utc>,
    window: Duration,
) {
    let cutoff = now - chrono_duration(window);
    events.retain(|event| *event >= cutoff && *event <= now);
    // Independent of configuration mistakes or clock jumps, keep the row
    // bounded.  Counts above this cap already map to the maximum step.
    if events.len() > 4_096 {
        events.drain(..events.len() - 4_096);
    }
}

fn decay_db_states(
    states: &mut [DbActorState],
    now: chrono::DateTime<chrono::Utc>,
    config: &AbuseConfig,
) {
    for state in states {
        trim_db_events(&mut state.events, now, config.window);
        if state.penalty_level == 0 || config.cooldown_step.is_zero() {
            continue;
        }
        let elapsed = now
            .signed_duration_since(state.last_activity)
            .num_seconds()
            .max(0) as u64;
        let (level, consumed) = decayed_penalty(
            state.penalty_level,
            Duration::from_secs(elapsed),
            config.cooldown_step,
        );
        if level != state.penalty_level {
            state.penalty_level = level;
            state.last_activity += chrono_duration(consumed);
        }
    }
}

fn requirement_from_db(
    action: AbuseAction,
    states: &[DbActorState],
    shared_ip_keys: &HashSet<String>,
    now: chrono::DateTime<chrono::Utc>,
    config: &AbuseConfig,
) -> WorkRequirement {
    let policy = policy(action, config.base_work_factor, config.message_free_burst);
    let event_count = states
        .iter()
        .map(|state| {
            if shared_ip_keys.contains(&state.key) {
                // Authenticated users behind a carrier-grade NAT must not
                // consume each other's normal burst. The shared source is a
                // high-volume safety signal; account/behaviour remain primary.
                state.events.len() / 20
            } else {
                state.events.len()
            }
        })
        .max()
        .unwrap_or(0);
    let penalty = states
        .iter()
        .filter(|state| !shared_ip_keys.contains(&state.key))
        .map(|state| state.penalty_level)
        .max()
        .unwrap_or(0);
    let retry_after = states
        .iter()
        .filter(|state| !shared_ip_keys.contains(&state.key))
        .map(|state| {
            let millis = state
                .blocked_until
                .signed_duration_since(now)
                .num_milliseconds();
            if millis <= 0 {
                0
            } else {
                u64::try_from((millis + 999) / 1_000).unwrap_or(u64::MAX)
            }
        })
        .max()
        .unwrap_or(0);
    build_requirement(action, policy, event_count, penalty, retry_after, config)
}

fn record_db_states(
    states: &mut [DbActorState],
    shared_ip_keys: &HashSet<String>,
    now: chrono::DateTime<chrono::Utc>,
    requirement: &WorkRequirement,
) {
    for state in states {
        state.events.push(now);
        state.sequence = state.sequence.saturating_add(1);
        state.last_activity = now;
        if requirement.hard_wait_seconds > 0 && !shared_ip_keys.contains(&state.key) {
            state.blocked_until =
                now + chrono_duration(Duration::from_secs(requirement.hard_wait_seconds));
        }
    }
}

fn punish_db_states(
    states: &mut [DbActorState],
    shared_ip_keys: &HashSet<String>,
    now: chrono::DateTime<chrono::Utc>,
    config: &AbuseConfig,
) {
    for state in states {
        state.events.push(now);
        state.sequence = state.sequence.saturating_add(1);
        state.last_activity = now;
        if shared_ip_keys.contains(&state.key) {
            continue;
        }
        state.penalty_level = state.penalty_level.saturating_add(1).min(10);
        let wait = 2_u64
            .saturating_pow(state.penalty_level.min(9))
            .min(config.max_wait.as_secs());
        state.blocked_until = now + chrono_duration(Duration::from_secs(wait));
    }
}

fn opaque_actor_key(action: AbuseAction, actor: &str, secret: &[u8]) -> String {
    northstar_abuse_policy::opaque_actor_key(action, actor, secret)
}

fn opaque_challenge_capacity_key(action: AbuseAction, actor: &str, secret: &[u8]) -> String {
    northstar_abuse_policy::opaque_challenge_capacity_key(action, actor, secret)
}

fn derive_actor_key_secret(secret: &[u8]) -> Vec<u8> {
    northstar_abuse_policy::derive_actor_key_secret(secret).to_vec()
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

/// A public commitment produced by the private content-identity keyring. It
/// contains no reusable key material and is safe to pass to a repository.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ContentIdentityAuthenticator {
    key_id: String,
    mac: [u8; 32],
}

impl ContentIdentityAuthenticator {
    pub(crate) fn key_id(&self) -> &str {
        &self.key_id
    }

    pub(crate) fn mac(&self) -> &[u8; 32] {
        &self.mac
    }
}

/// Current/previous commitments for one exact canonical payload. The first
/// entry follows the existing rolling-overlap writer rule; verification is
/// constant-time once the non-secret key generation ID has been selected.
#[derive(Clone, Debug)]
pub(crate) struct ContentIdentityAuthenticators {
    candidates: Vec<ContentIdentityAuthenticator>,
}

impl ContentIdentityAuthenticators {
    pub(crate) fn primary(&self) -> &ContentIdentityAuthenticator {
        self.candidates
            .first()
            .expect("a content identity keyring always has a primary generation")
    }

    pub(crate) fn verifies(&self, key_id: &str, expected: &[u8]) -> bool {
        self.candidates.iter().any(|candidate| {
            candidate.key_id == key_id && bool::from(candidate.mac.as_slice().ct_eq(expected))
        })
    }

    #[cfg(test)]
    pub(crate) fn candidates(&self) -> &[ContentIdentityAuthenticator] {
        &self.candidates
    }
}

struct ContentIdentityGeneration {
    key_id: String,
    key: Zeroizing<Vec<u8>>,
}

#[derive(Clone)]
pub(crate) struct PersonalMessageContentKeyring {
    generations: Arc<Vec<ContentIdentityGeneration>>,
}

impl PersonalMessageContentKeyring {
    pub(crate) fn authenticators(&self, canonical_payload: &[u8]) -> ContentIdentityAuthenticators {
        content_identity_authenticators(
            &self.generations,
            ContentIdentityPurpose::PersonalMessage,
            canonical_payload,
        )
    }
}

#[derive(Clone)]
pub(crate) struct PersonalRetractionContentKeyring {
    generations: Arc<Vec<ContentIdentityGeneration>>,
}

/// Least-authority capability for XEP-0369 channel message replay identities.
/// It cannot produce personal-message or MIX-retraction commitments even
/// though all generations originate from the same mounted deployment secret.
#[derive(Clone)]
pub(crate) struct MixMessageContentKeyring {
    generations: Arc<Vec<ContentIdentityGeneration>>,
}

impl MixMessageContentKeyring {
    pub(crate) fn authenticators(&self, canonical_payload: &[u8]) -> ContentIdentityAuthenticators {
        content_identity_authenticators(
            &self.generations,
            ContentIdentityPurpose::MixMessage,
            canonical_payload,
        )
    }
}

/// Least-authority capability for XEP-0425 MIX retraction replay identities.
/// Keeping it distinct from channel-message identity prevents a compromised
/// service path from forging an authenticator for the other operation family.
#[derive(Clone)]
pub(crate) struct MixRetractionContentKeyring {
    generations: Arc<Vec<ContentIdentityGeneration>>,
}

impl MixRetractionContentKeyring {
    pub(crate) fn authenticators(&self, canonical_payload: &[u8]) -> ContentIdentityAuthenticators {
        content_identity_authenticators(
            &self.generations,
            ContentIdentityPurpose::MixRetraction,
            canonical_payload,
        )
    }
}

impl PersonalRetractionContentKeyring {
    pub(crate) fn authenticators(&self, canonical_payload: &[u8]) -> ContentIdentityAuthenticators {
        content_identity_authenticators(
            &self.generations,
            ContentIdentityPurpose::PersonalRetraction,
            canonical_payload,
        )
    }
}

fn content_identity_authenticators(
    generations: &[ContentIdentityGeneration],
    purpose: ContentIdentityPurpose,
    canonical_payload: &[u8],
) -> ContentIdentityAuthenticators {
    let candidates = generations
        .iter()
        .map(|generation| {
            let mut mac = Hmac::<Sha256>::new_from_slice(generation.key.as_slice())
                .expect("derived HMAC key is valid");
            mac.update(b"northstar/content-identity/mac/v1\0");
            message_admission_mac_field(&mut mac, purpose.label());
            message_admission_mac_field(&mut mac, canonical_payload);
            ContentIdentityAuthenticator {
                key_id: generation.key_id.clone(),
                mac: mac.finalize().into_bytes().into(),
            }
        })
        .collect();
    ContentIdentityAuthenticators { candidates }
}

fn derive_content_identity_key(actor_secret: &[u8], purpose: ContentIdentityPurpose) -> Vec<u8> {
    let purpose = match purpose {
        ContentIdentityPurpose::PersonalMessage => {
            northstar_abuse_policy::ContentIdentityPurpose::PersonalMessage
        }
        ContentIdentityPurpose::PersonalRetraction => {
            northstar_abuse_policy::ContentIdentityPurpose::PersonalRetraction
        }
        ContentIdentityPurpose::MixMessage => {
            northstar_abuse_policy::ContentIdentityPurpose::MixMessage
        }
        ContentIdentityPurpose::MixRetraction => {
            northstar_abuse_policy::ContentIdentityPurpose::MixRetraction
        }
    };
    northstar_abuse_policy::derive_content_identity_key(actor_secret, purpose).to_vec()
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

fn actor_key_id(secret: &[u8]) -> String {
    northstar_abuse_policy::actor_key_id(secret)
}

fn subject_hash(action: AbuseAction, subject: &str, secret: &[u8]) -> Vec<u8> {
    northstar_abuse_policy::subject_hash(action, subject, secret).to_vec()
}

#[allow(clippy::too_many_arguments)]
fn pow_prefix(
    secret: &[u8],
    version: u16,
    id: Uuid,
    action: AbuseAction,
    key_id: &str,
    subject: &str,
    actors: &[String],
    work_factor: u64,
    issued_at: chrono::DateTime<chrono::Utc>,
    expires_at: chrono::DateTime<chrono::Utc>,
    server_nonce: &str,
    intent: Option<&PowIntent>,
) -> String {
    northstar_abuse_policy::compute_pow_prefix_with_commitment(
        secret,
        version,
        id,
        action,
        key_id,
        subject,
        actors,
        work_factor,
        issued_at,
        expires_at,
        server_nonce,
        intent.map(PowIntent::commitment),
    )
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

#[derive(Clone, Debug)]
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

impl MessageAdmissionLease {
    pub(crate) fn new(
        admission_key: Vec<u8>,
        payload_mac: Vec<u8>,
        lease_token: Uuid,
        offline_dedupe: MessageDedupeIdentity,
    ) -> Self {
        Self {
            admission_key,
            payload_mac,
            lease_token,
            offline_dedupe,
        }
    }

    pub(crate) fn acceptance(&self) -> MessageAdmissionAcceptance<'_> {
        MessageAdmissionAcceptance {
            admission_key: &self.admission_key,
            payload_mac: &self.payload_mac,
            lease_token: self.lease_token,
        }
    }
}

impl MessageAdmissionAcceptance<'_> {
    pub(crate) fn admission_key(&self) -> &[u8] {
        self.admission_key
    }

    pub(crate) fn payload_mac(&self) -> &[u8] {
        self.payload_mac
    }

    pub(crate) fn lease_token(&self) -> Uuid {
        self.lease_token
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
        )
            -> anyhow::Result<crate::db::abuse_challenge_issuance_repository::IssueRecord>
        + Send
        + 'a,
>;
pub(crate) type VerificationPolicy<'a> = Box<
    dyn FnOnce(
            &mut [DbActorState],
            chrono::DateTime<chrono::Utc>,
            Option<crate::db::abuse_verification_repository::ConsumedChallenge>,
        )
            -> anyhow::Result<crate::db::abuse_verification_repository::VerificationDecision>
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
        request: crate::db::abuse_challenge_issuance_repository::IssueRequest,
        decide: IssueDecision<'a>,
    ) -> AbusePersistenceFuture<'a, PowChallenge>;

    fn verify<'a>(
        &'a self,
        actor_state_keys: &'a [String],
        challenge_id: Option<Uuid>,
        decide: VerificationPolicy<'a>,
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
    pub(crate) fn persistent_storage_enabled(&self) -> bool {
        self.persistence.is_some()
    }

    pub fn new(config: AbuseConfig) -> Self {
        Self {
            config,
            persistence: None,
            actor_key_secret: Zeroizing::new(Vec::new()),
            actor_key_id: "memory-only".to_owned(),
            previous_actor_key_secret: None,
            previous_actor_key_id: None,
            write_with_previous_actor_key: false,
            // In-memory guards exist only in unit tests. Production state
            // always overwrites this through the deployment constructor.
            legacy_v1_compatibility_until: Some(chrono::DateTime::<chrono::Utc>::MAX_UTC),
            states: DashMap::new(),
            challenges: DashMap::new(),
            challenge_issues: DashMap::new(),
            challenge_issue_gate: Mutex::new(()),
            last_cleanup: Mutex::new(Instant::now()),
            db_state_gates: (0..ABUSE_STATE_GATE_SHARDS)
                .map(|_| Arc::new(tokio::sync::Mutex::new(())))
                .collect(),
        }
    }

    #[cfg(test)]
    pub fn new_persistent(
        config: AbuseConfig,
        pool: PgPool,
        shared_secret: Option<&[u8]>,
        previous_shared_secret: Option<&[u8]>,
    ) -> Self {
        Self::new_persistent_for_deployment(
            config,
            pool,
            shared_secret,
            previous_shared_secret,
            false,
            Some(chrono::DateTime::<chrono::Utc>::MAX_UTC),
        )
    }

    pub(crate) fn new_persistent_for_deployment(
        config: AbuseConfig,
        pool: PgPool,
        shared_secret: Option<&[u8]>,
        previous_shared_secret: Option<&[u8]>,
        write_with_previous_actor_key: bool,
        legacy_v1_compatibility_until: Option<chrono::DateTime<chrono::Utc>>,
    ) -> Self {
        let mut guard = Self::new(config);
        guard.persistence = Some(Arc::new(
            crate::db::abuse_persistence_repository::PostgresAbusePersistence::new(pool),
        ));
        if let Some(secret) = shared_secret {
            guard.actor_key_secret = Zeroizing::new(derive_actor_key_secret(secret));
        } else {
            let mut key = vec![0_u8; 32];
            rand::thread_rng().fill_bytes(&mut key);
            guard.actor_key_secret = Zeroizing::new(key);
            tracing::warn!(
                "ABUSE_STATE_HMAC_KEY is unset; durable anti-abuse actor keys cannot be shared across restarts or nodes"
            );
        }
        guard.actor_key_id = actor_key_id(&guard.actor_key_secret);
        guard.previous_actor_key_secret = previous_shared_secret
            .map(derive_actor_key_secret)
            .map(Zeroizing::new);
        guard.previous_actor_key_id = guard
            .previous_actor_key_secret
            .as_ref()
            .map(|secret| actor_key_id(secret.as_slice()));
        guard.write_with_previous_actor_key =
            write_with_previous_actor_key && guard.previous_actor_key_secret.is_some();
        guard.legacy_v1_compatibility_until = legacy_v1_compatibility_until;
        guard
    }

    fn legacy_v1_allowed(&self) -> bool {
        self.legacy_v1_compatibility_until
            .is_some_and(|deadline| chrono::Utc::now() <= deadline)
    }

    /// Irreversible, purpose-separated identifiers used only to prove that
    /// every process is operating in the PostgreSQL-authorized key generation.
    /// They are safe to persist and log; the mounted HMAC material is never
    /// returned by this interface.
    pub(crate) fn deployment_key_ids(&self) -> (&str, Option<&str>) {
        (&self.actor_key_id, self.previous_actor_key_id.as_deref())
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

    /// MIX channel-message admission receives a purpose-separated capability;
    /// it cannot authenticate personal messages or any retraction family.
    pub(crate) fn mix_message_content_keyring(&self) -> MixMessageContentKeyring {
        MixMessageContentKeyring {
            generations: self.content_identity_generations(ContentIdentityPurpose::MixMessage),
        }
    }

    /// MIX retraction admission receives a separate capability from MIX
    /// messages so the two durable replay journals cannot forge each other.
    pub(crate) fn mix_retraction_content_keyring(&self) -> MixRetractionContentKeyring {
        MixRetractionContentKeyring {
            generations: self.content_identity_generations(ContentIdentityPurpose::MixRetraction),
        }
    }

    /// The previous deployment key must remain available until every durable
    /// object which can reference it and the complete exponential penalty
    /// history have expired.  Keeping this calculation beside the constants
    /// prevents the deployment protocol from drifting away from abuse policy.
    pub(crate) fn minimum_key_rotation_overlap(&self) -> Duration {
        self.config
            .window
            .max(self.config.max_wait)
            .max(self.config.max_wait.saturating_add(Duration::from_secs(30)))
            .max(max_penalty_decay_horizon(self.config.cooldown_step))
            .max(MESSAGE_ADMISSION_ACCEPTED_TTL)
            .max(OFFLINE_MESSAGE_ADMISSION_REPLAY_GRACE)
    }

    fn primary_actor_key(&self) -> (&str, &[u8]) {
        if self.write_with_previous_actor_key {
            if let (Some(key_id), Some(secret)) = (
                self.previous_actor_key_id.as_deref(),
                self.previous_actor_key_secret.as_deref(),
            ) {
                return (key_id, secret);
            }
        }
        (&self.actor_key_id, &self.actor_key_secret)
    }

    fn persistent_actor_key_candidates(&self) -> Vec<(&str, &[u8])> {
        let primary = self.primary_actor_key();
        let mut candidates = vec![primary];
        let current = (self.actor_key_id.as_str(), self.actor_key_secret.as_slice());
        if current.0 != primary.0 {
            candidates.push(current);
        }
        if let (Some(key_id), Some(secret)) = (
            self.previous_actor_key_id.as_deref(),
            self.previous_actor_key_secret.as_deref(),
        ) {
            if key_id != primary.0 {
                candidates.push((key_id, secret));
            }
        }
        candidates
    }

    fn actor_secret_for_id(&self, key_id: &str) -> Option<&[u8]> {
        if key_id == "legacy-current" {
            Some(self.primary_actor_key().1)
        } else if self.actor_key_id == key_id {
            Some(&self.actor_key_secret)
        } else if self.previous_actor_key_id.as_deref() == Some(key_id) {
            self.previous_actor_key_secret
                .as_ref()
                .map(|secret| secret.as_slice())
        } else {
            None
        }
    }

    pub(crate) fn persistent_actor_state_keys(
        &self,
        action: AbuseAction,
        actors: &[String],
    ) -> Vec<String> {
        let mut keys = actor_state_keys(action, actors, &self.actor_key_secret);
        if let Some(previous) = self.previous_actor_key_secret.as_deref() {
            keys.extend(actor_state_keys(action, actors, previous));
            keys.sort();
            keys.dedup();
        }
        keys
    }

    async fn acquire_db_state_gates(
        &self,
        action: AbuseAction,
        actors: &[String],
    ) -> Vec<tokio::sync::OwnedMutexGuard<()>> {
        let mut shards = self
            .persistent_actor_state_keys(action, actors)
            .into_iter()
            .map(|key| {
                let digest = Sha256::digest(key.as_bytes());
                let prefix = u64::from_be_bytes(
                    digest[..8]
                        .try_into()
                        .expect("SHA-256 has an eight-byte prefix"),
                );
                usize::try_from(prefix % ABUSE_STATE_GATE_SHARDS as u64)
                    .expect("gate shard index fits usize")
            })
            .collect::<Vec<_>>();
        shards.sort_unstable();
        shards.dedup();
        let mut guards = Vec::with_capacity(shards.len());
        for shard in shards {
            guards.push(Arc::clone(&self.db_state_gates[shard]).lock_owned().await);
        }
        guards
    }

    fn persistent_shared_ip_keys(&self, action: AbuseAction, actors: &[String]) -> HashSet<String> {
        if action == AbuseAction::Registration || actors.len() <= 1 {
            return HashSet::new();
        }
        let mut keys = HashSet::new();
        for actor in actors.iter().filter(|actor| actor.starts_with("ip:")) {
            keys.insert(opaque_actor_key(action, actor, &self.actor_key_secret));
            if let Some(previous) = self.previous_actor_key_secret.as_deref() {
                keys.insert(opaque_actor_key(action, actor, previous));
            }
        }
        keys
    }

    fn challenge_capacity_groups(
        &self,
        action: AbuseAction,
        actors: &[String],
    ) -> Vec<(Vec<String>, usize)> {
        let mut groups = actors
            .iter()
            .map(|actor| {
                let mut keys = vec![opaque_challenge_capacity_key(
                    action,
                    actor,
                    &self.actor_key_secret,
                )];
                if let Some(previous) = self.previous_actor_key_secret.as_deref() {
                    keys.push(opaque_challenge_capacity_key(action, actor, previous));
                }
                keys.sort();
                keys.dedup();
                let limit = if actor.starts_with("ip:") {
                    MAX_ACTIVE_POW_CHALLENGES_PER_IP
                } else {
                    MAX_ACTIVE_POW_CHALLENGES_PER_ACTOR
                };
                (keys, limit)
            })
            .collect::<Vec<_>>();
        groups.sort_by(|left, right| left.0.cmp(&right.0));
        groups.dedup_by(|left, right| left.0 == right.0);
        groups
    }

    fn challenge_issue_groups(
        &self,
        action: AbuseAction,
        actors: &[String],
    ) -> Vec<(Vec<String>, usize)> {
        let mut groups = actors
            .iter()
            .map(|actor| {
                let mut keys = vec![format!(
                    "challenge:{}",
                    opaque_challenge_capacity_key(action, actor, &self.actor_key_secret)
                )];
                if !actor.starts_with("ip:") {
                    keys.push(format!(
                        "challenge:{}",
                        opaque_actor_key(action, actor, &self.actor_key_secret)
                    ));
                }
                if let Some(previous) = self.previous_actor_key_secret.as_deref() {
                    keys.push(format!(
                        "challenge:{}",
                        opaque_challenge_capacity_key(action, actor, previous)
                    ));
                    if !actor.starts_with("ip:") {
                        keys.push(format!(
                            "challenge:{}",
                            opaque_actor_key(action, actor, previous)
                        ));
                    }
                }
                keys.sort();
                keys.dedup();
                let limit = if actor.starts_with("ip:") {
                    MAX_CHALLENGE_ISSUES_PER_IP_WINDOW
                } else {
                    self.challenge_issue_limit(action)
                };
                (keys, limit)
            })
            .collect::<Vec<_>>();
        groups.sort_by(|left, right| left.0.cmp(&right.0));
        groups.dedup_by(|left, right| left.0 == right.0);
        groups
    }

    /// Seed a newly rotated HMAC row from its previous opaque row. Mutations
    /// during the overlap then advance both rows, so removing PREVIOUS after
    /// the decay horizon does not reset the surviving penalty history.
    fn merge_previous_actor_states(
        &self,
        action: AbuseAction,
        actors: &[String],
        states: &mut [DbActorState],
    ) {
        let Some(previous) = self.previous_actor_key_secret.as_deref() else {
            return;
        };
        for actor in actors {
            let old_key = opaque_actor_key(action, actor, previous);
            let new_key = opaque_actor_key(action, actor, &self.actor_key_secret);
            if old_key == new_key {
                continue;
            }
            let Some(old) = states.iter().find(|state| state.key == old_key) else {
                continue;
            };
            let old_snapshot = (
                old.events.clone(),
                old.penalty_level,
                old.last_activity,
                old.blocked_until,
                old.sequence,
            );
            let Some(new) = states.iter_mut().find(|state| state.key == new_key) else {
                continue;
            };
            if new.sequence >= old_snapshot.4 {
                continue;
            }
            new.events = old_snapshot.0;
            new.penalty_level = old_snapshot.1;
            new.last_activity = old_snapshot.2;
            new.blocked_until = old_snapshot.3;
            new.sequence = old_snapshot.4;
        }
    }

    fn is_shared_ip_actor(action: AbuseAction, actors_len: usize, actor: &str) -> bool {
        action != AbuseAction::Registration && actors_len > 1 && actor.starts_with("ip:")
    }

    pub async fn issue(
        &self,
        action: AbuseAction,
        subject: &str,
        actors: &[String],
    ) -> anyhow::Result<PowChallenge> {
        if !self.legacy_v1_allowed() {
            return Err(LegacyPowV1Disabled.into());
        }
        self.issue_bound(action, subject, actors, None).await
    }

    pub async fn issue_v2(
        &self,
        action: AbuseAction,
        subject: &str,
        actors: &[String],
        intent: &PowIntent,
    ) -> anyhow::Result<PowChallenge> {
        anyhow::ensure!(
            action_accepts_intent(action, &intent.method, &intent.path),
            "PoW intent action mismatch"
        );
        self.issue_bound(action, subject, actors, Some(intent))
            .await
    }

    async fn issue_bound(
        &self,
        action: AbuseAction,
        subject: &str,
        actors: &[String],
        intent: Option<&PowIntent>,
    ) -> anyhow::Result<PowChallenge> {
        if self.persistence.is_some() {
            self.issue_persistent_bound(action, subject, actors, intent)
                .await
        } else {
            self.issue_memory_bound(action, subject, actors, intent)
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

    fn issue_memory_bound(
        &self,
        action: AbuseAction,
        subject: &str,
        actors: &[String],
        intent: Option<&PowIntent>,
    ) -> anyhow::Result<PowChallenge> {
        let _issue_gate = self
            .challenge_issue_gate
            .lock()
            .expect("challenge issue mutex poisoned");
        self.maybe_cleanup();
        let now = Instant::now();
        let issue_groups = self.challenge_issue_groups(action, actors);
        let mut normalized_issues = Vec::with_capacity(issue_groups.len());
        for (keys, limit) in issue_groups {
            let mut events = keys
                .iter()
                .filter_map(|key| self.challenge_issues.get(key))
                .flat_map(|events| events.iter().copied().collect::<Vec<_>>())
                .collect::<Vec<_>>();
            events.sort();
            events.dedup();
            events.retain(|time| now.saturating_duration_since(*time) <= self.config.window);
            if events.len() >= limit {
                let retry_after_seconds = events
                    .first()
                    .map(|oldest| {
                        ceil_seconds(
                            self.config
                                .window
                                .saturating_sub(now.saturating_duration_since(*oldest)),
                        )
                    })
                    .unwrap_or(1);
                return Err(ChallengeCapacityExceeded {
                    retry_after_seconds,
                }
                .into());
            }
            normalized_issues.push((keys, events));
        }

        let active = self
            .challenges
            .iter()
            .filter(|challenge| challenge.expires_at > now)
            .collect::<Vec<_>>();
        if active.len() >= MAX_ACTIVE_POW_CHALLENGES_GLOBAL {
            let retry_after_seconds = active
                .iter()
                .map(|challenge| ceil_seconds(challenge.expires_at.saturating_duration_since(now)))
                .min()
                .unwrap_or(1);
            return Err(ChallengeCapacityExceeded {
                retry_after_seconds,
            }
            .into());
        }
        let capacity_groups = self.challenge_capacity_groups(action, actors);
        for (keys, limit) in &capacity_groups {
            let matching = active
                .iter()
                .filter(|challenge| {
                    challenge
                        .capacity_actors
                        .iter()
                        .any(|stored| keys.binary_search(stored).is_ok())
                })
                .collect::<Vec<_>>();
            if matching.len() >= *limit {
                let retry_after_seconds = matching
                    .iter()
                    .map(|challenge| {
                        ceil_seconds(challenge.expires_at.saturating_duration_since(now))
                    })
                    .min()
                    .unwrap_or(1);
                return Err(ChallengeCapacityExceeded {
                    retry_after_seconds,
                }
                .into());
            }
        }
        drop(active);

        for (keys, mut events) in normalized_issues {
            events.push(now);
            for key in keys {
                self.challenge_issues
                    .insert(key, events.iter().copied().collect());
            }
        }

        let requirement = self.requirement(action, actors, now);
        let issued_at = chrono::Utc::now();
        let mut random = [0_u8; 18];
        rand::thread_rng().fill_bytes(&mut random);
        let id = Uuid::new_v4();
        let server_nonce = URL_SAFE_NO_PAD.encode(random);
        let version = if intent.is_some() {
            POW_INTENT_VERSION
        } else {
            1
        };
        let ttl =
            Duration::from_secs(120).max(Duration::from_secs(requirement.hard_wait_seconds + 30));
        let expires_at =
            issued_at + chrono::Duration::seconds(i64::try_from(ttl.as_secs()).unwrap_or(i64::MAX));
        let prefix = pow_prefix(
            &self.actor_key_secret,
            version,
            id,
            action,
            &self.actor_key_id,
            subject,
            actors,
            requirement.work_factor,
            issued_at,
            expires_at,
            &server_nonce,
            intent,
        );
        let actor_sequences = actors
            .iter()
            .filter(|actor| !Self::is_shared_ip_actor(action, actors.len(), actor))
            .map(|actor| {
                let key = state_key(action, actor);
                let sequence = self
                    .states
                    .get(&key)
                    .map(|state| state.sequence)
                    .unwrap_or(0);
                (key, sequence)
            })
            .collect();
        let mut capacity_actors = capacity_groups
            .into_iter()
            .flat_map(|(keys, _)| keys)
            .collect::<Vec<_>>();
        capacity_actors.sort();
        capacity_actors.dedup();
        self.challenges.insert(
            id,
            StoredChallenge {
                protocol_version: version,
                action,
                subject: subject.to_owned(),
                intent: intent.cloned(),
                key_id: self.actor_key_id.clone(),
                prefix: prefix.clone(),
                work_factor: requirement.work_factor,
                issued_at,
                expires_at_wall: expires_at,
                server_nonce: server_nonce.clone(),
                not_before: now + Duration::from_secs(requirement.hard_wait_seconds),
                expires_at: now + ttl,
                actor_sequences,
                capacity_actors,
                requirement: requirement.clone(),
            },
        );
        Ok(PowChallenge {
            version,
            challenge_id: id,
            prefix,
            key_id: self.actor_key_id.clone(),
            issued_at,
            expires_at,
            expires_in_seconds: ttl.as_secs(),
            server_nonce,
            intent: intent.map(PowIntent::view),
            requirement,
        })
    }

    fn challenge_issue_limit(&self, action: AbuseAction) -> usize {
        match action {
            // The bundled capable client intentionally prefetches a one-use
            // challenge for each outgoing stanza. Do not punish that normal
            // pattern before the ordinary message window itself can decide.
            AbuseAction::Message => self.config.message_free_burst.saturating_mul(5).max(300),
            _ => 30,
        }
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

    pub async fn verify_or_allow_v2(
        &self,
        action: AbuseAction,
        subject: &str,
        actors: &[String],
        proof: Option<&PowProof>,
        intent: &PowIntent,
    ) -> anyhow::Result<std::result::Result<WorkRequirement, GuardError>> {
        self.verify_or_allow_bound(action, subject, actors, proof, Some(intent))
            .await
    }

    async fn verify_or_allow_bound(
        &self,
        action: AbuseAction,
        subject: &str,
        actors: &[String],
        proof: Option<&PowProof>,
        intent: Option<&PowIntent>,
    ) -> anyhow::Result<std::result::Result<WorkRequirement, GuardError>> {
        if self.persistence.is_some() {
            self.verify_persistent_bound(action, subject, actors, proof, intent)
                .await
        } else {
            Ok(self.verify_memory_bound(action, subject, actors, proof, intent))
        }
    }

    /// Consume a message proof and create a recoverable pending admission in
    /// one PostgreSQL transaction. An exact retry resumes after the short
    /// fencing lease expires without consuming the proof or advancing the
    /// actor step twice. An accepted retry is suppressed. The same identity
    /// with different content is always a conflict.
    pub async fn begin_message_admission(
        &self,
        request: &MessageAdmissionRequest<'_>,
    ) -> anyhow::Result<MessageAdmissionStart> {
        anyhow::ensure!(
            request.actor_id != Uuid::nil(),
            "message admission actor must not be nil"
        );
        anyhow::ensure!(
            crate::jid::canonical_bare_key(request.account_bare)
                .is_ok_and(|value| value == request.account_bare),
            "message admission account must be a canonical bare JID"
        );
        anyhow::ensure!(
            crate::jid::canonicalize(request.normalized_target)
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

        let Some((identity_kind, identity_value)) = message_admission_identity(request) else {
            let intent = PowIntent::xmpp(
                AbuseAction::Message,
                "/xmpp/message",
                request.pow_intent_payload.as_bytes(),
            );
            let result = self
                .verify_or_allow_v2(
                    AbuseAction::Message,
                    request.subject,
                    request.actors,
                    request.proof,
                    &intent,
                )
                .await?;
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
            .begin_message_admission(self, request, &candidate_material, offline_dedupe)
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

    fn verify_memory_bound(
        &self,
        action: AbuseAction,
        subject: &str,
        actors: &[String],
        proof: Option<&PowProof>,
        intent: Option<&PowIntent>,
    ) -> Result<WorkRequirement, GuardError> {
        self.maybe_cleanup();
        let now = Instant::now();
        let current = self.requirement(action, actors, now);
        if current.work_factor <= 1 && current.retry_after_seconds == 0 && proof.is_none() {
            self.record(action, actors, now, &current);
            return Ok(current);
        }
        let Some(proof) = proof else {
            self.punish(action, actors, now);
            return Err(GuardError::Required(current));
        };
        let Some((_, challenge)) = self.challenges.remove(&proof.challenge_id) else {
            self.punish(action, actors, now);
            return Err(GuardError::Invalid(
                "proof-of-work challenge is missing or already used",
                current,
            ));
        };
        let intent_matches = match challenge.intent.as_ref() {
            Some(challenge_intent) => intent == Some(challenge_intent),
            None => self.legacy_v1_allowed(),
        };
        let binding_matches = if challenge.protocol_version == POW_INTENT_VERSION {
            self.actor_secret_for_id(&challenge.key_id)
                .zip(intent)
                .is_some_and(|(secret, expected)| {
                    let expected_prefix = pow_prefix(
                        secret,
                        challenge.protocol_version,
                        proof.challenge_id,
                        action,
                        &challenge.key_id,
                        subject,
                        actors,
                        challenge.work_factor,
                        challenge.issued_at,
                        challenge.expires_at_wall,
                        &challenge.server_nonce,
                        Some(expected),
                    );
                    bool::from(
                        challenge
                            .prefix
                            .as_bytes()
                            .ct_eq(expected_prefix.as_bytes()),
                    )
                })
        } else {
            challenge.protocol_version == 1
        };
        if challenge.action != action
            || challenge.subject != subject
            || !intent_matches
            || !binding_matches
        {
            self.punish(action, actors, now);
            return Err(GuardError::Invalid(
                "proof-of-work challenge does not match this operation",
                current,
            ));
        }
        if now > challenge.expires_at {
            return Err(GuardError::Invalid(
                "proof-of-work challenge expired",
                current,
            ));
        }
        if now < challenge.not_before {
            return Err(GuardError::Invalid(
                "hard cooldown has not finished",
                challenge.requirement,
            ));
        }
        for (key, expected) in &challenge.actor_sequences {
            let actual = self
                .states
                .get(key)
                .map(|state| state.sequence)
                .unwrap_or(0);
            if actual != *expected
                && !prefetched_message_challenge_remains_sufficient(
                    action,
                    &challenge.requirement,
                    &current,
                )
            {
                return Err(GuardError::Invalid(
                    "another operation already advanced this rate-limit step",
                    current,
                ));
            }
        }
        if proof.nonce.is_empty()
            || proof.nonce.len() > 64
            || !proof.nonce.bytes().all(|byte| byte.is_ascii_digit())
        {
            self.punish(action, actors, now);
            return Err(GuardError::Invalid(
                "proof-of-work nonce is invalid",
                current,
            ));
        }
        let mut hasher = Sha256::new();
        hasher.update(challenge.prefix.as_bytes());
        hasher.update(proof.nonce.as_bytes());
        let digest = hasher.finalize();
        let value = u64::from_be_bytes(digest[..8].try_into().expect("SHA-256 prefix"));
        let target = u64::MAX / challenge.work_factor.max(1);
        if value > target {
            self.punish(action, actors, now);
            return Err(GuardError::Invalid(
                "proof of work is insufficient",
                current,
            ));
        }
        self.record(action, actors, now, &challenge.requirement);
        Ok(challenge.requirement)
    }

    pub async fn current_requirement(
        &self,
        action: AbuseAction,
        actors: &[String],
    ) -> anyhow::Result<WorkRequirement> {
        if self.persistence.is_some() {
            self.current_requirement_persistent(action, actors).await
        } else {
            Ok(self.requirement(action, actors, Instant::now()))
        }
    }

    pub(crate) fn current_requirement_decision(
        &self,
        action: AbuseAction,
        actors: &[String],
        states: &mut [DbActorState],
        now: chrono::DateTime<chrono::Utc>,
    ) -> WorkRequirement {
        let shared_ip_keys = self.persistent_shared_ip_keys(action, actors);
        decay_db_states(states, now, &self.config);
        self.merge_previous_actor_states(action, actors, states);
        requirement_from_db(action, states, &shared_ip_keys, now, &self.config)
    }

    pub(crate) fn record_failure_decision(
        &self,
        action: AbuseAction,
        actors: &[String],
        states: &mut [DbActorState],
        now: chrono::DateTime<chrono::Utc>,
    ) {
        let shared_ip_keys = self.persistent_shared_ip_keys(action, actors);
        let requirement = self.current_requirement_decision(action, actors, states, now);
        record_db_states(states, &shared_ip_keys, now, &requirement);
    }

    pub async fn record_failure(
        &self,
        action: AbuseAction,
        actors: &[String],
    ) -> anyhow::Result<()> {
        if self.persistence.is_some() {
            self.record_failure_persistent(action, actors).await
        } else {
            self.record_failure_memory(action, actors);
            Ok(())
        }
    }

    fn record_failure_memory(&self, action: AbuseAction, actors: &[String]) {
        self.maybe_cleanup();
        let now = Instant::now();
        let requirement = self.requirement(action, actors, now);
        self.record(action, actors, now, &requirement);
    }

    fn requirement(&self, action: AbuseAction, actors: &[String], now: Instant) -> WorkRequirement {
        let policy = policy(
            action,
            self.config.base_work_factor,
            self.config.message_free_burst,
        );
        let mut event_count = 0_usize;
        let mut penalty = 0_u32;
        let mut retry_after = 0_u64;
        for actor in actors {
            let is_shared_ip = Self::is_shared_ip_actor(action, actors.len(), actor);
            let key = state_key(action, actor);
            if let Some(mut state) = self.states.get_mut(&key) {
                decay(
                    &mut state,
                    now,
                    self.config.window,
                    self.config.cooldown_step,
                );
                event_count = event_count.max(if is_shared_ip {
                    state.events.len() / 20
                } else {
                    state.events.len()
                });
                if !is_shared_ip {
                    penalty = penalty.max(state.penalty_level);
                    retry_after = retry_after
                        .max(state.blocked_until.saturating_duration_since(now).as_secs());
                }
            }
        }
        build_requirement(
            action,
            policy,
            event_count,
            penalty,
            retry_after,
            &self.config,
        )
    }

    fn record(
        &self,
        action: AbuseAction,
        actors: &[String],
        now: Instant,
        requirement: &WorkRequirement,
    ) {
        for actor in actors {
            let is_shared_ip = Self::is_shared_ip_actor(action, actors.len(), actor);
            let key = state_key(action, actor);
            let mut state = self
                .states
                .entry(key)
                .or_insert_with(|| ActorState::new(now));
            decay(
                &mut state,
                now,
                self.config.window,
                self.config.cooldown_step,
            );
            state.events.push_back(now);
            state.sequence = state.sequence.wrapping_add(1);
            state.last_activity = now;
            if requirement.hard_wait_seconds > 0 && !is_shared_ip {
                state.blocked_until = now + Duration::from_secs(requirement.hard_wait_seconds);
            }
        }
    }

    fn punish(&self, action: AbuseAction, actors: &[String], now: Instant) {
        for actor in actors {
            let is_shared_ip = Self::is_shared_ip_actor(action, actors.len(), actor);
            let key = state_key(action, actor);
            let mut state = self
                .states
                .entry(key)
                .or_insert_with(|| ActorState::new(now));
            decay(
                &mut state,
                now,
                self.config.window,
                self.config.cooldown_step,
            );
            state.events.push_back(now);
            state.sequence = state.sequence.wrapping_add(1);
            state.last_activity = now;
            if is_shared_ip {
                continue;
            }
            state.penalty_level = state.penalty_level.saturating_add(1).min(10);
            let wait = 2_u64
                .saturating_pow(state.penalty_level.min(9))
                .min(self.config.max_wait.as_secs());
            state.blocked_until = now + Duration::from_secs(wait);
        }
    }

    async fn issue_persistent_bound(
        &self,
        action: AbuseAction,
        subject: &str,
        actors: &[String],
        intent: Option<&PowIntent>,
    ) -> anyhow::Result<PowChallenge> {
        use crate::db::abuse_challenge_issuance_repository::{IssueRecord, IssueRequest};

        let persistence = self.persistence.as_ref().expect("persistent abuse storage");
        let _db_state_gates = self.acquire_db_state_gates(action, actors).await;
        let request = IssueRequest {
            issue_groups: self.challenge_issue_groups(action, actors),
            capacity_groups: self.challenge_capacity_groups(action, actors),
            actor_state_keys: self.persistent_actor_state_keys(action, actors),
            window: self.config.window,
        };
        let shared_ip_keys = self.persistent_shared_ip_keys(action, actors);
        let (primary_key_id, primary_secret) = self.primary_actor_key();
        let subject_hash = subject_hash(action, subject, primary_secret);
        let primary_actor_state_keys = actor_state_keys(action, actors, primary_secret);
        persistence
            .issue(
                request,
                Box::new(|states, now| {
                    decay_db_states(states, now, &self.config);
                    self.merge_previous_actor_states(action, actors, states);
                    let requirement =
                        requirement_from_db(action, states, &shared_ip_keys, now, &self.config);
                    let mut random = [0_u8; 18];
                    rand::thread_rng().fill_bytes(&mut random);
                    let id = Uuid::new_v4();
                    let server_nonce = URL_SAFE_NO_PAD.encode(random);
                    let ttl = Duration::from_secs(120)
                        .max(Duration::from_secs(requirement.hard_wait_seconds + 30));
                    let expires_at = now + chrono_duration(ttl);
                    let version = if intent.is_some() {
                        POW_INTENT_VERSION
                    } else {
                        1
                    };
                    let prefix = pow_prefix(
                        primary_secret,
                        version,
                        id,
                        action,
                        primary_key_id,
                        subject,
                        actors,
                        requirement.work_factor,
                        now,
                        expires_at,
                        &server_nonce,
                        intent,
                    );
                    // During key rotation, sign only the primary generation's sequence
                    // snapshot; a dual-key verifier may load additional mirrored rows.
                    let actor_sequences = serde_json::Value::Object(
                        states
                            .iter()
                            .filter(|state| {
                                primary_actor_state_keys.contains(&state.key)
                                    && !shared_ip_keys.contains(&state.key)
                            })
                            .map(|state| {
                                (state.key.clone(), serde_json::Value::from(state.sequence))
                            })
                            .collect(),
                    );
                    Ok(IssueRecord {
                        action,
                        challenge: PowChallenge {
                            version,
                            challenge_id: id,
                            prefix,
                            key_id: primary_key_id.to_owned(),
                            issued_at: now,
                            expires_at,
                            expires_in_seconds: ttl.as_secs(),
                            server_nonce,
                            intent: intent.map(PowIntent::view),
                            requirement,
                        },
                        subject_hash: subject_hash.clone(),
                        actor_sequences,
                        intent_method: intent.map(|intent| intent.method.clone()),
                        intent_path: intent.map(|intent| intent.path.clone()),
                        body_sha256: intent.map(|intent| intent.body_sha256.to_vec()),
                    })
                }),
            )
            .await
    }

    async fn current_requirement_persistent(
        &self,
        action: AbuseAction,
        actors: &[String],
    ) -> anyhow::Result<WorkRequirement> {
        let persistence = self.persistence.as_ref().expect("persistent abuse storage");
        let _db_state_gates = self.acquire_db_state_gates(action, actors).await;
        let keys = self.persistent_actor_state_keys(action, actors);
        let shared_ip_keys = self.persistent_shared_ip_keys(action, actors);
        persistence
            .current_requirement(
                &keys,
                Box::new(|states, now| {
                    decay_db_states(states, now, &self.config);
                    self.merge_previous_actor_states(action, actors, states);
                    requirement_from_db(action, states, &shared_ip_keys, now, &self.config)
                }),
            )
            .await
    }

    async fn record_failure_persistent(
        &self,
        action: AbuseAction,
        actors: &[String],
    ) -> anyhow::Result<()> {
        let persistence = self.persistence.as_ref().expect("persistent abuse storage");
        let _db_state_gates = self.acquire_db_state_gates(action, actors).await;
        let keys = self.persistent_actor_state_keys(action, actors);
        persistence
            .record_failure(
                &keys,
                Box::new(|states, now| {
                    self.record_failure_decision(action, actors, states, now);
                }),
            )
            .await
    }

    async fn verify_persistent_bound(
        &self,
        action: AbuseAction,
        subject: &str,
        actors: &[String],
        proof: Option<&PowProof>,
        intent: Option<&PowIntent>,
    ) -> anyhow::Result<std::result::Result<WorkRequirement, GuardError>> {
        let persistence = self.persistence.as_ref().expect("persistent abuse storage");
        let _db_state_gates = self.acquire_db_state_gates(action, actors).await;
        let keys = self.persistent_actor_state_keys(action, actors);
        persistence
            .verify(
                &keys,
                proof.map(|proof| proof.challenge_id),
                Box::new(|states, now, challenge| {
                    self.decide_persistent_verification(
                        PersistentVerificationInput {
                            action,
                            subject,
                            actors,
                            proof,
                            intent,
                        },
                        states,
                        now,
                        challenge,
                    )
                }),
            )
            .await
    }

    pub(crate) fn decide_persistent_verification(
        &self,
        input: PersistentVerificationInput<'_>,
        states: &mut [DbActorState],
        now: chrono::DateTime<chrono::Utc>,
        challenge: Option<crate::db::abuse_verification_repository::ConsumedChallenge>,
    ) -> anyhow::Result<crate::db::abuse_verification_repository::VerificationDecision> {
        use crate::db::abuse_verification_repository::VerificationDecision;
        let PersistentVerificationInput {
            action,
            subject,
            actors,
            proof,
            intent,
        } = input;

        let shared_ip_keys = self.persistent_shared_ip_keys(action, actors);
        decay_db_states(states, now, &self.config);
        self.merge_previous_actor_states(action, actors, states);
        let current = requirement_from_db(action, states, &shared_ip_keys, now, &self.config);

        let Some(proof) = proof else {
            if current.work_factor <= 1 && current.retry_after_seconds == 0 {
                record_db_states(states, &shared_ip_keys, now, &current);
                return Ok(VerificationDecision {
                    outcome: Ok(current),
                    persist_states: true,
                });
            }
            punish_db_states(states, &shared_ip_keys, now, &self.config);
            return Ok(VerificationDecision {
                outcome: Err(GuardError::Required(current)),
                persist_states: true,
            });
        };
        let Some(challenge) = challenge else {
            punish_db_states(states, &shared_ip_keys, now, &self.config);
            return Ok(VerificationDecision {
                outcome: Err(GuardError::Invalid(
                    "proof-of-work challenge is missing or already used",
                    current,
                )),
                persist_states: true,
            });
        };
        let challenge_requirement: WorkRequirement =
            serde_json::from_value(challenge.requirement.clone())?;
        let protocol_version = u16::try_from(challenge.protocol_version).unwrap_or(u16::MAX);
        let intent_matches = if protocol_version == 1 {
            self.legacy_v1_allowed()
        } else if protocol_version == POW_INTENT_VERSION {
            intent.is_some_and(|expected| {
                challenge.intent_method.as_deref() == Some(expected.method.as_str())
                    && challenge.intent_path.as_deref() == Some(expected.path.as_str())
                    && challenge.body_sha256.as_deref() == Some(expected.body_sha256.as_slice())
            })
        } else {
            false
        };
        let valid_identity = self
            .actor_secret_for_id(&challenge.key_id)
            .is_some_and(|secret| {
                if challenge.action != action.as_str()
                    || challenge.subject_hash != subject_hash(action, subject, secret)
                {
                    return false;
                }
                if protocol_version != POW_INTENT_VERSION {
                    return protocol_version == 1;
                }
                let Some(expected) = intent else {
                    return false;
                };
                let Some(issued_at) = challenge.issued_at else {
                    return false;
                };
                let Some(server_nonce) = challenge.server_nonce.as_deref() else {
                    return false;
                };
                let work_factor = u64::try_from(challenge.work_factor).unwrap_or(u64::MAX);
                let expected_prefix = pow_prefix(
                    secret,
                    protocol_version,
                    proof.challenge_id,
                    action,
                    &challenge.key_id,
                    subject,
                    actors,
                    work_factor,
                    issued_at,
                    challenge.expires_at,
                    server_nonce,
                    Some(expected),
                );
                bool::from(
                    challenge
                        .prefix
                        .as_bytes()
                        .ct_eq(expected_prefix.as_bytes()),
                )
            });
        if !valid_identity || !intent_matches {
            tracing::debug!(
                action = action.as_str(),
                valid_identity,
                intent_matches,
                "rejected a PoW v2 challenge whose operation binding changed"
            );
            punish_db_states(states, &shared_ip_keys, now, &self.config);
            return Ok(VerificationDecision {
                outcome: Err(GuardError::Invalid(
                    "proof-of-work challenge does not match this operation",
                    current,
                )),
                persist_states: true,
            });
        }
        if now > challenge.expires_at {
            return Ok(VerificationDecision {
                outcome: Err(GuardError::Invalid(
                    "proof-of-work challenge expired",
                    current,
                )),
                persist_states: false,
            });
        }
        if now < challenge.not_before {
            return Ok(VerificationDecision {
                outcome: Err(GuardError::Invalid(
                    "hard cooldown has not finished",
                    challenge_requirement,
                )),
                persist_states: false,
            });
        }
        let expected: serde_json::Map<String, serde_json::Value> = challenge
            .actor_sequences
            .as_object()
            .cloned()
            .unwrap_or_default();
        // An old-key challenge signs only its own key set. Newly mirrored
        // state rows do not by themselves indicate replay.
        let sequences_match = expected.iter().all(|(key, sequence)| {
            states
                .iter()
                .find(|state| state.key == *key)
                .is_some_and(|state| {
                    sequence.as_i64() == Some(state.sequence)
                        && !shared_ip_keys.contains(&state.key)
                })
        });
        if !sequences_match
            && !prefetched_message_challenge_remains_sufficient(
                action,
                &challenge_requirement,
                &current,
            )
        {
            return Ok(VerificationDecision {
                outcome: Err(GuardError::Invalid(
                    "another operation already advanced this rate-limit step",
                    current,
                )),
                persist_states: false,
            });
        }
        if proof.nonce.is_empty()
            || proof.nonce.len() > 64
            || !proof.nonce.bytes().all(|byte| byte.is_ascii_digit())
        {
            punish_db_states(states, &shared_ip_keys, now, &self.config);
            return Ok(VerificationDecision {
                outcome: Err(GuardError::Invalid(
                    "proof-of-work nonce is invalid",
                    current,
                )),
                persist_states: true,
            });
        }
        let mut hasher = Sha256::new();
        hasher.update(challenge.prefix.as_bytes());
        hasher.update(proof.nonce.as_bytes());
        let digest = hasher.finalize();
        let value = u64::from_be_bytes(digest[..8].try_into().expect("SHA-256 prefix"));
        let work_factor = u64::try_from(challenge.work_factor).unwrap_or(u64::MAX);
        if value > u64::MAX / work_factor.max(1) {
            punish_db_states(states, &shared_ip_keys, now, &self.config);
            return Ok(VerificationDecision {
                outcome: Err(GuardError::Invalid(
                    "proof of work is insufficient",
                    current,
                )),
                persist_states: true,
            });
        }
        record_db_states(states, &shared_ip_keys, now, &challenge_requirement);
        Ok(VerificationDecision {
            outcome: Ok(challenge_requirement),
            persist_states: true,
        })
    }

    pub(crate) async fn cleanup_challenges(&self) -> anyhow::Result<()> {
        if let Some(persistence) = self.persistence.as_ref() {
            let stale_seconds = self
                .config
                .window
                .max(self.config.max_wait)
                .max(max_penalty_decay_horizon(self.config.cooldown_step))
                .as_secs();
            return persistence
                .cleanup(self.config.window.as_secs(), stale_seconds)
                .await;
        }
        self.cleanup_challenges_memory();
        Ok(())
    }

    fn cleanup_challenges_memory(&self) {
        let now = Instant::now();
        self.challenges
            .retain(|_, challenge| challenge.expires_at > now);
        self.challenge_issues.retain(|_, issues| {
            while issues
                .front()
                .is_some_and(|time| now.saturating_duration_since(*time) > self.config.window)
            {
                issues.pop_front();
            }
            !issues.is_empty()
        });

        // A penalty is capped at ten levels. Each higher level takes twice as
        // long as the preceding level to cool, so cleanup must retain state
        // through the complete geometric decay horizon. Once the window,
        // maximum wait and that horizon have elapsed, retaining the actor key
        // cannot affect a future decision and only lets an attacker grow the
        // map forever.
        let stale_after = self
            .config
            .window
            .max(self.config.max_wait)
            .max(max_penalty_decay_horizon(self.config.cooldown_step));
        self.states.retain(|_, state| {
            state.blocked_until > now
                || now.saturating_duration_since(state.last_activity) <= stale_after
        });
    }

    fn maybe_cleanup(&self) {
        let now = Instant::now();
        let Ok(mut last_cleanup) = self.last_cleanup.try_lock() else {
            return;
        };
        if now.saturating_duration_since(*last_cleanup) < Duration::from_secs(10) {
            return;
        }
        *last_cleanup = now;
        drop(last_cleanup);
        self.cleanup_challenges_memory();
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

fn build_requirement(
    action: AbuseAction,
    policy: Policy,
    event_count: usize,
    penalty: u32,
    retry_after: u64,
    config: &AbuseConfig,
) -> WorkRequirement {
    northstar_abuse_policy::build_requirement(
        action,
        policy,
        event_count,
        penalty,
        retry_after,
        config,
    )
}

fn state_key(action: AbuseAction, actor: &str) -> String {
    if actor.starts_with("behavior:") {
        actor.to_owned()
    } else {
        format!("{}:{actor}", action.as_str())
    }
}

fn decay(state: &mut ActorState, now: Instant, window: Duration, cooldown_step: Duration) {
    while state
        .events
        .front()
        .is_some_and(|time| now.saturating_duration_since(*time) > window)
    {
        state.events.pop_front();
    }
    if cooldown_step.is_zero() || state.penalty_level == 0 {
        return;
    }
    let elapsed = now.saturating_duration_since(state.last_activity);
    let (level, consumed) = decayed_penalty(state.penalty_level, elapsed, cooldown_step);
    if level != state.penalty_level {
        state.penalty_level = level;
        state.last_activity += consumed;
    }
}

fn decayed_penalty(level: u32, elapsed: Duration, cooldown_step: Duration) -> (u32, Duration) {
    northstar_abuse_policy::decayed_penalty(level, elapsed, cooldown_step)
}

fn max_penalty_decay_horizon(cooldown_step: Duration) -> Duration {
    northstar_abuse_policy::max_penalty_decay_horizon(cooldown_step)
}

#[cfg(test)]
#[path = "abuse_tests.rs"]
mod tests;
