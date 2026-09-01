use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use dashmap::DashMap;
use hmac::{Hmac, Mac};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sqlx::{PgPool, Postgres, QueryBuilder, Row};
use std::{
    collections::{HashSet, VecDeque},
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
use subtle::ConstantTimeEq;
use uuid::Uuid;
use zeroize::Zeroizing;

pub const POW_INTENT_VERSION: u16 = 2;
const POW_BODY_DIGEST_BYTES: usize = 32;
const POW_INTENT_PATH_MAX_BYTES: usize = 512;

/// Public, non-secret commitment supplied when a capable client requests a
/// v2 challenge. `body_sha256` is the base64url (unpadded) SHA-256 of the
/// canonical operation body; callers never send the body itself to the
/// challenge endpoint.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PowIntentRequest {
    pub version: u16,
    pub method: String,
    pub path: String,
    pub body_sha256: String,
}

/// Server-validated action intent.  It is deliberately independent from the
/// proof envelope: mutation handlers reconstruct this value from their own
/// route and pow-less body rather than trusting fields repeated by a client.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PowIntent {
    method: String,
    path: String,
    body_sha256: [u8; POW_BODY_DIGEST_BYTES],
}

#[derive(Clone, Debug, Serialize)]
pub struct PowIntentView {
    pub version: u16,
    pub method: String,
    pub path: String,
    pub body_sha256: String,
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
}

fn canonical_pow_path(path: &str) -> bool {
    !path.is_empty()
        && path.len() <= POW_INTENT_PATH_MAX_BYTES
        && path.starts_with('/')
        && path.is_ascii()
        && !path.contains(['?', '#', '\\', '\0'])
        && !path.contains("//")
        && !path.split('/').any(|segment| matches!(segment, "." | ".."))
        && !path.chars().any(char::is_control)
}

fn action_accepts_intent(action: AbuseAction, method: &str, path: &str) -> bool {
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

/// Deterministic JSON used only as a digest preimage. Object keys are sorted;
/// arrays retain order; scalar serialization follows JSON. The returned bytes
/// are never persisted. Browser code implements the same small profile.
pub fn canonical_json_body_digest(value: &serde_json::Value) -> [u8; 32] {
    fn append(value: &serde_json::Value, output: &mut String) {
        match value {
            serde_json::Value::Null => output.push_str("null"),
            serde_json::Value::Bool(value) => {
                output.push_str(if *value { "true" } else { "false" })
            }
            serde_json::Value::Number(value) => output.push_str(&value.to_string()),
            serde_json::Value::String(value) => output.push_str(
                &serde_json::to_string(value).expect("serializing a JSON string cannot fail"),
            ),
            serde_json::Value::Array(values) => {
                output.push('[');
                for (index, value) in values.iter().enumerate() {
                    if index > 0 {
                        output.push(',');
                    }
                    append(value, output);
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
                    output.push_str(
                        &serde_json::to_string(key)
                            .expect("serializing a JSON object key cannot fail"),
                    );
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

const MAX_ACTIVE_POW_CHALLENGES_GLOBAL: usize = 50_000;
const MAX_ACTIVE_POW_CHALLENGES_PER_ACTOR: usize = 8;
const MAX_ACTIVE_POW_CHALLENGES_PER_IP: usize = 256;
const MAX_CHALLENGE_ISSUES_PER_IP_WINDOW: usize = 300;
const CHALLENGE_CAPACITY_ADVISORY_LOCK: i64 = 5_640_963_765_310_692_929;
const MESSAGE_ADMISSION_CAPACITY_SHARDS: u8 = 64;
const MAX_ACTIVE_MESSAGE_ADMISSIONS_PER_SHARD: i32 = 32_768;
const MAX_ACTIVE_MESSAGE_ADMISSIONS_PER_USER: i64 = 4_096;
const MESSAGE_ADMISSION_LEASE: Duration = Duration::from_secs(60);
const MESSAGE_ADMISSION_PENDING_TTL: Duration = Duration::from_secs(30 * 60);
const MESSAGE_ADMISSION_ACCEPTED_TTL: Duration = Duration::from_secs(6 * 60 * 60);
const MESSAGE_ADMISSION_CLEANUP_BATCH: i64 = 1_000;
/// A delivered offline message retains its replay tombstone for exactly this
/// long.  The PostgreSQL trigger in migration 0079 uses the same 30-day value.
/// Live queued messages can outlast this bound and are therefore protected by
/// the deployment reference fence in `db::abuse_keys` as well.
pub(crate) const OFFLINE_MESSAGE_ADMISSION_REPLAY_GRACE: Duration =
    Duration::from_secs(30 * 24 * 60 * 60);
/// Local waiters queue on these stripes before acquiring a PgPool connection.
/// PostgreSQL try-locks below remain the cross-process authority.
const ABUSE_STATE_GATE_SHARDS: usize = 1_024;
const ABUSE_STATE_ADVISORY_HASH_SEED: i64 = 5_841_153_820_082_015_233;

#[derive(Debug)]
pub struct ChallengeCapacityExceeded {
    retry_after_seconds: u64,
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AbuseAction {
    Registration,
    Message,
    Report,
    Appeal,
    Login,
    PasswordChange,
}

#[derive(Debug)]
struct DbActorState {
    key: String,
    events: Vec<chrono::DateTime<chrono::Utc>>,
    penalty_level: u32,
    last_activity: chrono::DateTime<chrono::Utc>,
    blocked_until: chrono::DateTime<chrono::Utc>,
    sequence: i64,
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

async fn lock_db_states(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    keys: &[String],
    now: chrono::DateTime<chrono::Utc>,
) -> anyhow::Result<Vec<DbActorState>> {
    if keys.is_empty() {
        return Ok(Vec::new());
    }
    let mut keys = keys.to_vec();
    keys.sort();
    keys.dedup();

    // A blocking row lock is enough to let one hot NAT/account consume every
    // PgPool connection. Transaction advisory try-locks cover even the
    // first-ever INSERT (where ON CONFLICT can otherwise wait), and NOWAIT
    // below protects rolling upgrades from an older node holding a row lock.
    for key in &keys {
        let acquired: bool = sqlx::query_scalar(
            "SELECT pg_try_advisory_xact_lock(hashtextextended($1::text, $2::bigint))",
        )
        .bind(key)
        .bind(ABUSE_STATE_ADVISORY_HASH_SEED)
        .fetch_one(&mut **tx)
        .await?;
        if !acquired {
            return Err(AbuseStateBusy.into());
        }
    }
    sqlx::query(
        "INSERT INTO abuse_actor_states (state_key, last_activity, blocked_until)
         SELECT key, $2, $2 FROM UNNEST($1::text[]) AS key
         ON CONFLICT (state_key) DO NOTHING",
    )
    .bind(&keys)
    .bind(now)
    .execute(&mut **tx)
    .await?;
    let rows = sqlx::query("SELECT state_key, event_times, penalty_level, last_activity, blocked_until, sequence FROM abuse_actor_states WHERE state_key = ANY($1) ORDER BY state_key FOR UPDATE NOWAIT")
        .bind(&keys)
        .fetch_all(&mut **tx)
        .await
        .map_err(|error| {
            if error
                .as_database_error()
                .and_then(|database| database.code())
                .as_deref()
                == Some("55P03")
            {
                anyhow::Error::new(AbuseStateBusy)
            } else {
                anyhow::Error::new(error)
            }
        })?;
    Ok(rows
        .into_iter()
        .map(|row| DbActorState {
            key: row.get("state_key"),
            events: row.get("event_times"),
            penalty_level: u32::try_from(row.get::<i32, _>("penalty_level")).unwrap_or(10),
            last_activity: row.get("last_activity"),
            blocked_until: row.get("blocked_until"),
            sequence: row.get("sequence"),
        })
        .collect())
}

async fn persist_db_states(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    states: &[DbActorState],
) -> anyhow::Result<()> {
    if states.is_empty() {
        return Ok(());
    }
    let mut query = QueryBuilder::<Postgres>::new(
        "UPDATE abuse_actor_states AS target SET event_times=incoming.event_times, penalty_level=incoming.penalty_level, last_activity=incoming.last_activity, blocked_until=incoming.blocked_until, sequence=incoming.sequence FROM (",
    );
    query.push_values(states, |mut row, state| {
        row.push_bind(&state.key)
            .push_bind(&state.events)
            .push_bind(i32::try_from(state.penalty_level).unwrap_or(10))
            .push_bind(state.last_activity)
            .push_bind(state.blocked_until)
            .push_bind(state.sequence);
    });
    query.push(") AS incoming(state_key,event_times,penalty_level,last_activity,blocked_until,sequence) WHERE target.state_key=incoming.state_key");
    query.build().execute(&mut **tx).await?;
    Ok(())
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
    let state = state_key(action, actor);
    let mut mac = Hmac::<Sha256>::new_from_slice(secret).expect("HMAC accepts every key length");
    mac.update(b"actor\0");
    mac.update(state.as_bytes());
    URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes())
}

fn opaque_challenge_capacity_key(action: AbuseAction, actor: &str, secret: &[u8]) -> String {
    let mut mac = Hmac::<Sha256>::new_from_slice(secret).expect("HMAC accepts every key length");
    mac.update(b"challenge-capacity\0");
    if actor.starts_with("ip:") {
        // The source-IP ceiling is deliberately shared by all challenge
        // actions. Otherwise an unauthenticated caller could multiply the
        // storage allowance by cycling action names.
        mac.update(b"ip\0");
    } else {
        mac.update(action.as_str().as_bytes());
        mac.update(b"\0actor\0");
    }
    mac.update(actor.as_bytes());
    URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes())
}

fn derive_actor_key_secret(secret: &[u8]) -> Vec<u8> {
    let mut mac = Hmac::<Sha256>::new_from_slice(secret).expect("HMAC accepts every secret length");
    mac.update(b"northstar/abuse-actor-key/v1");
    mac.finalize().into_bytes().to_vec()
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
    let mut mac =
        Hmac::<Sha256>::new_from_slice(actor_secret).expect("HMAC accepts every secret length");
    mac.update(b"northstar/content-identity/subkey/v1\0");
    message_admission_mac_field(&mut mac, purpose.label());
    mac.finalize().into_bytes().to_vec()
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
    let mut digest = Sha256::new();
    digest.update(b"northstar/abuse-key-id/v1\0");
    digest.update(secret);
    URL_SAFE_NO_PAD.encode(&digest.finalize()[..12])
}

fn subject_hash(action: AbuseAction, subject: &str, secret: &[u8]) -> Vec<u8> {
    let mut mac = Hmac::<Sha256>::new_from_slice(secret).expect("HMAC accepts every key length");
    mac.update(b"subject\0");
    mac.update(action.as_str().as_bytes());
    mac.update(b"\0");
    mac.update(subject.as_bytes());
    mac.finalize().into_bytes().to_vec()
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
    fn field(mac: &mut Hmac<Sha256>, value: &[u8]) {
        mac.update(&u64::try_from(value.len()).unwrap_or(u64::MAX).to_be_bytes());
        mac.update(value);
    }

    let mut mac = Hmac::<Sha256>::new_from_slice(secret).expect("HMAC accepts every key length");
    mac.update(b"northstar/pow-challenge/v2\0");
    field(&mut mac, &version.to_be_bytes());
    field(&mut mac, id.as_bytes());
    field(&mut mac, action.as_str().as_bytes());
    field(&mut mac, key_id.as_bytes());
    field(&mut mac, subject.as_bytes());
    let mut actors = actors.to_vec();
    actors.sort();
    actors.dedup();
    field(
        &mut mac,
        &u64::try_from(actors.len())
            .unwrap_or(u64::MAX)
            .to_be_bytes(),
    );
    for actor in actors {
        field(&mut mac, actor.as_bytes());
    }
    field(&mut mac, &work_factor.to_be_bytes());
    field(&mut mac, &issued_at.timestamp_millis().to_be_bytes());
    field(&mut mac, &expires_at.timestamp_millis().to_be_bytes());
    field(&mut mac, server_nonce.as_bytes());
    field(&mut mac, &[u8::from(intent.is_some())]);
    if let Some(intent) = intent {
        field(&mut mac, intent.method.as_bytes());
        field(&mut mac, intent.path.as_bytes());
        field(&mut mac, &intent.body_sha256);
    }
    let binding = URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes());
    format!(
        "northstar:v{version}:{id}:{}:{key_id}:{server_nonce}:{binding}:",
        action.as_str()
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

fn message_admission_digest_field(digest: &mut Sha256, value: &[u8]) {
    digest.update(u64::try_from(value.len()).unwrap_or(u64::MAX).to_be_bytes());
    digest.update(value);
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
    let mut digest = Sha256::new();
    digest.update(b"northstar/offline-message-identity/v1\0");
    message_admission_digest_field(&mut digest, AbuseAction::Message.as_str().as_bytes());
    message_admission_digest_field(&mut digest, request.account_bare.as_bytes());
    message_admission_digest_field(&mut digest, request.normalized_target.as_bytes());
    message_admission_digest_field(&mut digest, identity_kind);
    message_admission_digest_field(&mut digest, identity_value);
    digest.finalize().to_vec()
}

fn message_admission_material(
    request: &MessageAdmissionRequest<'_>,
    secret: &[u8],
    identity_kind: &[u8],
    identity_value: &[u8],
) -> (Vec<u8>, Vec<u8>) {
    let mut key_mac =
        Hmac::<Sha256>::new_from_slice(secret).expect("HMAC accepts every key length");
    key_mac.update(b"northstar/message-admission/key/v1\0");
    message_admission_mac_field(&mut key_mac, AbuseAction::Message.as_str().as_bytes());
    message_admission_mac_field(&mut key_mac, request.account_bare.as_bytes());
    message_admission_mac_field(&mut key_mac, request.normalized_target.as_bytes());
    message_admission_mac_field(&mut key_mac, identity_kind);
    message_admission_mac_field(&mut key_mac, identity_value);
    let admission_key = key_mac.finalize().into_bytes().to_vec();

    let payload_hash = Sha256::digest(request.normalized_payload.as_bytes());
    let mut payload_mac =
        Hmac::<Sha256>::new_from_slice(secret).expect("HMAC accepts every key length");
    payload_mac.update(b"northstar/message-admission/payload/v1\0");
    message_admission_mac_field(&mut payload_mac, AbuseAction::Message.as_str().as_bytes());
    message_admission_mac_field(&mut payload_mac, request.account_bare.as_bytes());
    message_admission_mac_field(&mut payload_mac, request.normalized_target.as_bytes());
    message_admission_mac_field(&mut payload_mac, identity_kind);
    message_admission_mac_field(&mut payload_mac, identity_value);
    message_admission_mac_field(&mut payload_mac, payload_hash.as_slice());
    let payload_mac = payload_mac.finalize().into_bytes().to_vec();
    (admission_key, payload_mac)
}

fn message_admission_lock_id(admission_key: &[u8]) -> i64 {
    i64::from_be_bytes(
        admission_key[..8]
            .try_into()
            .expect("message admission HMAC has a 64-bit prefix"),
    )
}

fn message_admission_capacity_shard(admission_key: &[u8]) -> i16 {
    i16::from(admission_key[8] % MESSAGE_ADMISSION_CAPACITY_SHARDS)
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

fn retry_after_db(
    available_at: Option<chrono::DateTime<chrono::Utc>>,
    now: chrono::DateTime<chrono::Utc>,
) -> u64 {
    available_at
        .map(|available_at| {
            u64::try_from(
                available_at
                    .signed_duration_since(now)
                    .num_milliseconds()
                    .max(1)
                    .saturating_add(999)
                    / 1_000,
            )
            .unwrap_or(u64::MAX)
        })
        .unwrap_or(1)
        .max(1)
}

impl AbuseAction {
    pub fn as_str(self) -> &'static str {
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

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PowProof {
    pub challenge_id: Uuid,
    pub nonce: String,
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

#[derive(Clone, Debug, Serialize, Deserialize)]
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

#[derive(Clone, Debug, Serialize)]
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

#[derive(Debug)]
pub enum GuardError {
    Required(WorkRequirement),
    Invalid(&'static str, WorkRequirement),
}

/// A denial has already mutated persistent challenge/rate state in the
/// caller's transaction and therefore must be committed before the HTTP error
/// is returned. Database/internal errors remain ordinary `Err` values and the
/// caller must roll the transaction back.
pub enum TransactionalGuardOutcome {
    Allowed(WorkRequirement),
    DeniedNeedsCommit(GuardError),
}

impl GuardError {
    pub fn requirement(&self) -> &WorkRequirement {
        match self {
            Self::Required(requirement) | Self::Invalid(_, requirement) => requirement,
        }
    }

    pub fn message(&self) -> &'static str {
        match self {
            Self::Required(_) => "proof of work or cooldown is required",
            Self::Invalid(message, _) => message,
        }
    }
}

#[derive(Clone, Copy)]
pub struct AbuseConfig {
    pub base_work_factor: u64,
    pub max_work_factor: u64,
    pub window: Duration,
    pub cooldown_step: Duration,
    pub max_wait: Duration,
    pub message_free_burst: usize,
    pub approximate_max_device_seconds: u64,
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
    pool: Option<PgPool>,
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
    pub fn new(config: AbuseConfig) -> Self {
        Self {
            config,
            pool: None,
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
        guard.pool = Some(pool);
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

    fn persistent_actor_state_keys(&self, action: AbuseAction, actors: &[String]) -> Vec<String> {
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
        if self.pool.is_some() {
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
        if self.pool.is_some() {
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
        let Some(pool) = self.pool.as_ref() else {
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
                ((*key_id).to_owned(), admission_key, payload_mac)
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
                .map(|(key_id, _, payload_mac)| MessageDedupeCandidate {
                    key_id: key_id.clone(),
                    payload_mac: payload_mac.clone(),
                })
                .collect(),
        };
        let candidate_keys = candidate_material
            .iter()
            .map(|(_, key, _)| key.clone())
            .collect::<Vec<_>>();
        let mut lock_ids = candidate_keys
            .iter()
            .map(|key| message_admission_lock_id(key))
            .collect::<Vec<_>>();
        lock_ids.sort_unstable();
        lock_ids.dedup();

        let mut tx = pool.begin().await?;
        for lock_id in lock_ids {
            sqlx::query("SELECT pg_advisory_xact_lock($1)")
                .bind(lock_id)
                .execute(&mut *tx)
                .await?;
        }
        let now: chrono::DateTime<chrono::Utc> = sqlx::query_scalar("SELECT clock_timestamp()")
            .fetch_one(&mut *tx)
            .await?;
        sqlx::query(
            "DELETE FROM abuse_message_admissions
             WHERE admission_key=ANY($1::bytea[]) AND expires_at <= $2",
        )
        .bind(&candidate_keys)
        .bind(now)
        .execute(&mut *tx)
        .await?;
        let rows = sqlx::query(
            "SELECT admission_key,key_id,actor_id,payload_mac,state,
                    lease_token,lease_expires_at
             FROM abuse_message_admissions
             WHERE admission_key=ANY($1::bytea[])
             ORDER BY admission_key FOR UPDATE",
        )
        .bind(&candidate_keys)
        .fetch_all(&mut *tx)
        .await?;
        anyhow::ensure!(
            rows.len() <= 1,
            "message admission exists under multiple rotation keys"
        );
        if let Some(row) = rows.first() {
            let stored_key: Vec<u8> = row.get("admission_key");
            let stored_key_id: String = row.get("key_id");
            let stored_payload_mac: Vec<u8> = row.get("payload_mac");
            let exact = candidate_material.iter().any(|(key_id, key, payload_mac)| {
                *key_id == stored_key_id
                    && bool::from(stored_key.as_slice().ct_eq(key.as_slice()))
                    && bool::from(stored_payload_mac.as_slice().ct_eq(payload_mac.as_slice()))
            }) && row.get::<Uuid, _>("actor_id") == request.actor_id;
            if !exact {
                tx.rollback().await?;
                return Ok(MessageAdmissionStart::Conflict);
            }
            if row.get::<String, _>("state") == "accepted" {
                tx.commit().await?;
                return Ok(MessageAdmissionStart::ReplayAccepted);
            }
            let lease_expires_at: chrono::DateTime<chrono::Utc> = row.get("lease_expires_at");
            if lease_expires_at > now {
                let retry_after_seconds = u64::try_from(
                    lease_expires_at
                        .signed_duration_since(now)
                        .num_milliseconds()
                        .saturating_add(999)
                        / 1_000,
                )
                .unwrap_or(u64::MAX)
                .max(1);
                let mut requirement = self
                    .current_requirement_in_tx(&mut tx, AbuseAction::Message, request.actors)
                    .await?;
                requirement.retry_after_seconds =
                    requirement.retry_after_seconds.max(retry_after_seconds);
                tx.commit().await?;
                return Ok(MessageAdmissionStart::InProgress { requirement });
            }
            let lease_token = Uuid::new_v4();
            sqlx::query(
                "UPDATE abuse_message_admissions
                 SET lease_token=$2,lease_expires_at=$3,updated_at=$4
                 WHERE admission_key=$1",
            )
            .bind(&stored_key)
            .bind(lease_token)
            .bind(now + chrono_duration(MESSAGE_ADMISSION_LEASE))
            .bind(now)
            .execute(&mut *tx)
            .await?;
            let requirement = self
                .current_requirement_in_tx(&mut tx, AbuseAction::Message, request.actors)
                .await?;
            tx.commit().await?;
            return Ok(MessageAdmissionStart::Proceed {
                lease: Some(MessageAdmissionLease {
                    admission_key: stored_key,
                    payload_mac: stored_payload_mac,
                    lease_token,
                    offline_dedupe,
                }),
                requirement,
            });
        }

        let intent = PowIntent::xmpp(
            AbuseAction::Message,
            "/xmpp/message",
            request.pow_intent_payload.as_bytes(),
        );
        let guard_outcome = self
            .verify_or_allow_in_tx_v2(
                &mut tx,
                AbuseAction::Message,
                request.subject,
                request.actors,
                request.proof,
                &intent,
            )
            .await?;
        let requirement = match guard_outcome {
            TransactionalGuardOutcome::Allowed(requirement) => requirement,
            TransactionalGuardOutcome::DeniedNeedsCommit(error) => {
                tx.commit().await?;
                return Ok(MessageAdmissionStart::Denied(error));
            }
        };

        let (primary_key_id, admission_key, payload_mac) = candidate_material
            .first()
            .expect("primary message-admission key is always present");
        let capacity_shard = message_admission_capacity_shard(admission_key);
        // Expired rows cannot be allowed to pin a shard indefinitely if the
        // periodic maintenance task is delayed. Keep the foreground work
        // strictly bounded and let the ordinary cleanup finish the remainder.
        sqlx::query(
            "WITH doomed AS (
                 SELECT admission_key FROM abuse_message_admissions
                  WHERE capacity_shard=$1 AND expires_at <= $2
                  ORDER BY expires_at,admission_key
                  LIMIT 128 FOR UPDATE SKIP LOCKED
             )
             DELETE FROM abuse_message_admissions AS target
              USING doomed WHERE target.admission_key=doomed.admission_key",
        )
        .bind(capacity_shard)
        .bind(now)
        .execute(&mut *tx)
        .await?;
        let active_for_user: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM abuse_message_admissions
             WHERE actor_id=$1 AND expires_at > $2",
        )
        .bind(request.actor_id)
        .bind(now)
        .fetch_one(&mut *tx)
        .await?;
        if active_for_user >= MAX_ACTIVE_MESSAGE_ADMISSIONS_PER_USER {
            tx.rollback().await?;
            return Ok(MessageAdmissionStart::CapacityLimited);
        }
        let capacity_reserved = sqlx::query_scalar::<_, i32>(
            "UPDATE abuse_message_admission_capacity
             SET active_records=active_records+1
             WHERE shard=$1 AND active_records < $2
             RETURNING active_records",
        )
        .bind(capacity_shard)
        .bind(MAX_ACTIVE_MESSAGE_ADMISSIONS_PER_SHARD)
        .fetch_optional(&mut *tx)
        .await?
        .is_some();
        if !capacity_reserved {
            tx.rollback().await?;
            return Ok(MessageAdmissionStart::CapacityLimited);
        }
        let lease_token = Uuid::new_v4();
        sqlx::query(
            "INSERT INTO abuse_message_admissions
             (admission_key,key_id,actor_id,capacity_shard,payload_mac,
              proof_challenge_id,state,lease_token,lease_expires_at,expires_at)
             VALUES($1,$2,$3,$4,$5,$6,'pending',$7,$8,$9)",
        )
        .bind(admission_key)
        .bind(primary_key_id)
        .bind(request.actor_id)
        .bind(capacity_shard)
        .bind(payload_mac)
        .bind(request.proof.map(|proof| proof.challenge_id))
        .bind(lease_token)
        .bind(now + chrono_duration(MESSAGE_ADMISSION_LEASE))
        .bind(now + chrono_duration(MESSAGE_ADMISSION_PENDING_TTL))
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(MessageAdmissionStart::Proceed {
            lease: Some(MessageAdmissionLease {
                admission_key: admission_key.clone(),
                payload_mac: payload_mac.clone(),
                lease_token,
                offline_dedupe,
            }),
            requirement,
        })
    }

    /// Fence and finalize a message admission after a durable outbox/offline
    /// write or an online queue accepted the stanza. A failure here happens
    /// after message acceptance and must be logged, never reflected as a
    /// retryable stanza error to the sender.
    pub async fn accept_message_admission(
        &self,
        lease: &MessageAdmissionLease,
    ) -> anyhow::Result<()> {
        let Some(pool) = self.pool.as_ref() else {
            return Ok(());
        };
        let mut tx = pool.begin().await?;
        sqlx::query("SELECT pg_advisory_xact_lock($1)")
            .bind(message_admission_lock_id(&lease.admission_key))
            .execute(&mut *tx)
            .await?;
        let row = sqlx::query(
            "SELECT payload_mac,state,lease_token FROM abuse_message_admissions
             WHERE admission_key=$1 FOR UPDATE",
        )
        .bind(&lease.admission_key)
        .fetch_optional(&mut *tx)
        .await?;
        let Some(row) = row else {
            anyhow::bail!("message admission disappeared before acceptance");
        };
        let stored_mac: Vec<u8> = row.get("payload_mac");
        anyhow::ensure!(
            bool::from(stored_mac.as_slice().ct_eq(lease.payload_mac.as_slice())),
            "message admission payload changed before acceptance"
        );
        if row.get::<String, _>("state") == "accepted" {
            tx.commit().await?;
            return Ok(());
        }
        anyhow::ensure!(
            row.get::<Uuid, _>("lease_token") == lease.lease_token,
            "message admission fencing lease was lost before acceptance"
        );
        let now: chrono::DateTime<chrono::Utc> = sqlx::query_scalar("SELECT clock_timestamp()")
            .fetch_one(&mut *tx)
            .await?;
        sqlx::query(
            "UPDATE abuse_message_admissions
             SET state='accepted',accepted_at=$2,updated_at=$2,expires_at=$3
             WHERE admission_key=$1",
        )
        .bind(&lease.admission_key)
        .bind(now)
        .bind(now + chrono_duration(MESSAGE_ADMISSION_ACCEPTED_TTL))
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(())
    }

    /// Verify and advance a persistent anti-abuse step inside the caller's
    /// transaction. This is required when consuming a one-use PoW challenge
    /// protects an idempotent mutation: challenge deletion, the durable guard
    /// marker, business rows, audit, and response replay must commit or roll
    /// back together.
    #[cfg(test)]
    pub async fn verify_or_allow_in_tx(
        &self,
        tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
        action: AbuseAction,
        subject: &str,
        actors: &[String],
        proof: Option<&PowProof>,
    ) -> anyhow::Result<TransactionalGuardOutcome> {
        self.verify_or_allow_in_tx_bound(tx, action, subject, actors, proof, None)
            .await
    }

    pub async fn verify_or_allow_in_tx_v2(
        &self,
        tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
        action: AbuseAction,
        subject: &str,
        actors: &[String],
        proof: Option<&PowProof>,
        intent: &PowIntent,
    ) -> anyhow::Result<TransactionalGuardOutcome> {
        self.verify_or_allow_in_tx_bound(tx, action, subject, actors, proof, Some(intent))
            .await
    }

    async fn verify_or_allow_in_tx_bound(
        &self,
        tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
        action: AbuseAction,
        subject: &str,
        actors: &[String],
        proof: Option<&PowProof>,
        intent: Option<&PowIntent>,
    ) -> anyhow::Result<TransactionalGuardOutcome> {
        let result = if self.pool.is_some() {
            self.verify_persistent_in_tx_bound(tx, action, subject, actors, proof, intent)
                .await
        } else {
            Ok(self.verify_memory_bound(action, subject, actors, proof, intent))
        }?;
        Ok(match result {
            Ok(requirement) => TransactionalGuardOutcome::Allowed(requirement),
            Err(error) => TransactionalGuardOutcome::DeniedNeedsCommit(error),
        })
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
        if self.pool.is_some() {
            self.current_requirement_persistent(action, actors).await
        } else {
            Ok(self.requirement(action, actors, Instant::now()))
        }
    }

    /// Read the persistent requirement while holding the caller's transaction.
    /// Login uses this to decide whether a proof is necessary and to persist
    /// cooldown decay under the same lease lock as proof consumption. A
    /// backend error aborts the transaction and therefore never becomes an
    /// accidental allow.
    pub async fn current_requirement_in_tx(
        &self,
        tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
        action: AbuseAction,
        actors: &[String],
    ) -> anyhow::Result<WorkRequirement> {
        anyhow::ensure!(
            self.pool.is_some(),
            "transactional abuse decisions require persistent storage"
        );
        let now: chrono::DateTime<chrono::Utc> = sqlx::query_scalar("SELECT clock_timestamp()")
            .fetch_one(&mut **tx)
            .await?;
        let keys = self.persistent_actor_state_keys(action, actors);
        let shared_ip_keys = self.persistent_shared_ip_keys(action, actors);
        let mut states = lock_db_states(tx, &keys, now).await?;
        decay_db_states(&mut states, now, &self.config);
        self.merge_previous_actor_states(action, actors, &mut states);
        let requirement = requirement_from_db(action, &states, &shared_ip_keys, now, &self.config);
        persist_db_states(tx, &states).await?;
        Ok(requirement)
    }

    pub async fn record_failure(
        &self,
        action: AbuseAction,
        actors: &[String],
    ) -> anyhow::Result<()> {
        if self.pool.is_some() {
            self.record_failure_persistent(action, actors).await
        } else {
            self.record_failure_memory(action, actors);
            Ok(())
        }
    }

    /// Advance a failed-operation abuse step in the caller's transaction.
    /// REST mutations use this so an invalid credential, its idempotent error
    /// response, and the increasing penalty either all commit or all retry.
    pub async fn record_failure_in_tx(
        &self,
        tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
        action: AbuseAction,
        actors: &[String],
    ) -> anyhow::Result<()> {
        anyhow::ensure!(
            self.pool.is_some(),
            "transactional abuse decisions require persistent storage"
        );
        let now: chrono::DateTime<chrono::Utc> = sqlx::query_scalar("SELECT clock_timestamp()")
            .fetch_one(&mut **tx)
            .await?;
        let keys = self.persistent_actor_state_keys(action, actors);
        let shared_ip_keys = self.persistent_shared_ip_keys(action, actors);
        let mut states = lock_db_states(tx, &keys, now).await?;
        decay_db_states(&mut states, now, &self.config);
        self.merge_previous_actor_states(action, actors, &mut states);
        let requirement = requirement_from_db(action, &states, &shared_ip_keys, now, &self.config);
        record_db_states(&mut states, &shared_ip_keys, now, &requirement);
        persist_db_states(tx, &states).await
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
        let pool = self.pool.as_ref().expect("persistent abuse pool");
        let _db_state_gates = self.acquire_db_state_gates(action, actors).await;
        let mut tx = pool.begin().await?;
        let now: chrono::DateTime<chrono::Utc> = sqlx::query_scalar("SELECT clock_timestamp()")
            .fetch_one(&mut *tx)
            .await?;
        // One transaction-wide gate makes the global and per-actor active-row
        // checks exact across processes. Per-IP issue rows still provide the
        // narrower lock and restart-safe retry time.
        sqlx::query("SELECT pg_advisory_xact_lock($1)")
            .bind(CHALLENGE_CAPACITY_ADVISORY_LOCK)
            .execute(&mut *tx)
            .await?;

        let issue_groups = self.challenge_issue_groups(action, actors);
        let mut issue_keys = issue_groups
            .iter()
            .flat_map(|(keys, _)| keys.iter().cloned())
            .collect::<Vec<_>>();
        issue_keys.sort();
        issue_keys.dedup();
        for key in &issue_keys {
            sqlx::query(
                "INSERT INTO abuse_challenge_issue_windows (actor_key) VALUES ($1) ON CONFLICT (actor_key) DO NOTHING",
            )
            .bind(key)
            .execute(&mut *tx)
            .await?;
        }
        let rows = sqlx::query(
            "SELECT actor_key,event_times FROM abuse_challenge_issue_windows
             WHERE actor_key=ANY($1) ORDER BY actor_key FOR UPDATE",
        )
        .bind(&issue_keys)
        .fetch_all(&mut *tx)
        .await?;
        let issue_state = rows
            .into_iter()
            .map(|row| {
                (
                    row.get::<String, _>("actor_key"),
                    row.get::<Vec<chrono::DateTime<chrono::Utc>>, _>("event_times"),
                )
            })
            .collect::<std::collections::HashMap<_, _>>();
        let mut merged_issue_state = std::collections::BTreeMap::new();
        for (group, limit) in issue_groups {
            let mut events = group
                .iter()
                .filter_map(|key| issue_state.get(key))
                .flatten()
                .copied()
                .collect::<Vec<_>>();
            events.sort();
            events.dedup();
            trim_db_events(&mut events, now, self.config.window);
            if events.len() >= limit {
                let retry_after_seconds = events
                    .first()
                    .map(|oldest| {
                        let available_at = *oldest + chrono_duration(self.config.window);
                        u64::try_from(
                            available_at
                                .signed_duration_since(now)
                                .num_milliseconds()
                                .max(1)
                                .saturating_add(999)
                                / 1_000,
                        )
                        .unwrap_or(u64::MAX)
                    })
                    .unwrap_or(1);
                return Err(ChallengeCapacityExceeded {
                    retry_after_seconds,
                }
                .into());
            }
            events.push(now);
            for key in group {
                merged_issue_state.insert(key, events.clone());
            }
        }
        for (key, events) in merged_issue_state {
            sqlx::query(
                "UPDATE abuse_challenge_issue_windows SET event_times=$2, updated_at=$3 WHERE actor_key=$1",
            )
            .bind(key)
            .bind(events)
            .bind(now)
            .execute(&mut *tx)
            .await?;
        }

        let capacity_groups = self.challenge_capacity_groups(action, actors);
        let mut capacity_actor_keys = capacity_groups
            .iter()
            .flat_map(|(keys, _)| keys.iter().cloned())
            .collect::<Vec<_>>();
        capacity_actor_keys.sort();
        capacity_actor_keys.dedup();
        let (primary_key_id, primary_secret) = self.primary_actor_key();
        let subject_hash = subject_hash(action, subject, primary_secret);
        let (global_count, global_available_at): (i64, Option<chrono::DateTime<chrono::Utc>>) =
            sqlx::query_as(
                "SELECT COUNT(*)::bigint,MIN(expires_at)
                 FROM abuse_pow_challenges
                 WHERE expires_at > $1",
            )
            .bind(now)
            .fetch_one(&mut *tx)
            .await?;
        if global_count >= i64::try_from(MAX_ACTIVE_POW_CHALLENGES_GLOBAL).unwrap_or(i64::MAX) {
            return Err(ChallengeCapacityExceeded {
                retry_after_seconds: retry_after_db(global_available_at, now),
            }
            .into());
        }
        for (group, limit) in &capacity_groups {
            let (count, available_at): (i64, Option<chrono::DateTime<chrono::Utc>>) =
                sqlx::query_as(
                    "SELECT COUNT(*)::bigint,MIN(expires_at)
                     FROM abuse_pow_challenges
                     WHERE expires_at > $1
                       AND capacity_actor_keys && $2::text[]",
                )
                .bind(now)
                .bind(group)
                .fetch_one(&mut *tx)
                .await?;
            if count >= i64::try_from(*limit).unwrap_or(i64::MAX) {
                return Err(ChallengeCapacityExceeded {
                    retry_after_seconds: retry_after_db(available_at, now),
                }
                .into());
            }
        }

        let keys = self.persistent_actor_state_keys(action, actors);
        let shared_ip_keys = self.persistent_shared_ip_keys(action, actors);
        let mut states = lock_db_states(&mut tx, &keys, now).await?;
        decay_db_states(&mut states, now, &self.config);
        self.merge_previous_actor_states(action, actors, &mut states);
        let requirement = requirement_from_db(action, &states, &shared_ip_keys, now, &self.config);
        persist_db_states(&mut tx, &states).await?;

        let mut random = [0_u8; 18];
        rand::thread_rng().fill_bytes(&mut random);
        let id = Uuid::new_v4();
        let server_nonce = URL_SAFE_NO_PAD.encode(random);
        let ttl =
            Duration::from_secs(120).max(Duration::from_secs(requirement.hard_wait_seconds + 30));
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
        // New dual-key nodes mirror state under both generations, but an
        // old-only node can verify only the previous generation.  Sign only
        // the primary generation's sequence snapshot; a dual-key verifier
        // still loads it while safely ignoring its extra mirrored rows.
        let primary_actor_state_keys = actor_state_keys(action, actors, primary_secret);
        let actor_sequences = serde_json::Value::Object(
            states
                .iter()
                .filter(|state| {
                    primary_actor_state_keys.contains(&state.key)
                        && !shared_ip_keys.contains(&state.key)
                })
                .map(|state| (state.key.clone(), serde_json::Value::from(state.sequence)))
                .collect(),
        );
        sqlx::query(
            "INSERT INTO abuse_pow_challenges (id,action,subject_hash,key_id,prefix,work_factor,not_before,expires_at,actor_sequences,requirement,capacity_actor_keys,protocol_version,intent_method,intent_path,body_sha256,server_nonce,issued_at)
             VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17)",
        )
        .bind(id)
        .bind(action.as_str())
        .bind(subject_hash)
        .bind(primary_key_id)
        .bind(&prefix)
        .bind(i64::try_from(requirement.work_factor).unwrap_or(i64::MAX))
        .bind(now + chrono_duration(Duration::from_secs(requirement.hard_wait_seconds)))
        .bind(now + chrono_duration(ttl))
        .bind(actor_sequences)
        .bind(serde_json::to_value(&requirement)?)
        .bind(capacity_actor_keys)
        .bind(i16::try_from(version).unwrap_or(i16::MAX))
        .bind(intent.map(|intent| intent.method.as_str()))
        .bind(intent.map(|intent| intent.path.as_str()))
        .bind(intent.map(|intent| intent.body_sha256.as_slice()))
        .bind(&server_nonce)
        .bind(now)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(PowChallenge {
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
        })
    }

    async fn current_requirement_persistent(
        &self,
        action: AbuseAction,
        actors: &[String],
    ) -> anyhow::Result<WorkRequirement> {
        let pool = self.pool.as_ref().expect("persistent abuse pool");
        let _db_state_gates = self.acquire_db_state_gates(action, actors).await;
        let mut tx = pool.begin().await?;
        let now: chrono::DateTime<chrono::Utc> = sqlx::query_scalar("SELECT clock_timestamp()")
            .fetch_one(&mut *tx)
            .await?;
        let keys = self.persistent_actor_state_keys(action, actors);
        let shared_ip_keys = self.persistent_shared_ip_keys(action, actors);
        let mut states = lock_db_states(&mut tx, &keys, now).await?;
        decay_db_states(&mut states, now, &self.config);
        self.merge_previous_actor_states(action, actors, &mut states);
        let requirement = requirement_from_db(action, &states, &shared_ip_keys, now, &self.config);
        persist_db_states(&mut tx, &states).await?;
        tx.commit().await?;
        Ok(requirement)
    }

    async fn record_failure_persistent(
        &self,
        action: AbuseAction,
        actors: &[String],
    ) -> anyhow::Result<()> {
        let pool = self.pool.as_ref().expect("persistent abuse pool");
        let _db_state_gates = self.acquire_db_state_gates(action, actors).await;
        let mut tx = pool.begin().await?;
        let now: chrono::DateTime<chrono::Utc> = sqlx::query_scalar("SELECT clock_timestamp()")
            .fetch_one(&mut *tx)
            .await?;
        let keys = self.persistent_actor_state_keys(action, actors);
        let shared_ip_keys = self.persistent_shared_ip_keys(action, actors);
        let mut states = lock_db_states(&mut tx, &keys, now).await?;
        decay_db_states(&mut states, now, &self.config);
        self.merge_previous_actor_states(action, actors, &mut states);
        let requirement = requirement_from_db(action, &states, &shared_ip_keys, now, &self.config);
        record_db_states(&mut states, &shared_ip_keys, now, &requirement);
        persist_db_states(&mut tx, &states).await?;
        tx.commit().await?;
        Ok(())
    }

    async fn verify_persistent_bound(
        &self,
        action: AbuseAction,
        subject: &str,
        actors: &[String],
        proof: Option<&PowProof>,
        intent: Option<&PowIntent>,
    ) -> anyhow::Result<std::result::Result<WorkRequirement, GuardError>> {
        let pool = self.pool.as_ref().expect("persistent abuse pool");
        let _db_state_gates = self.acquire_db_state_gates(action, actors).await;
        let mut tx = pool.begin().await?;
        let outcome = self
            .verify_or_allow_in_tx_bound(&mut tx, action, subject, actors, proof, intent)
            .await?;
        tx.commit().await?;
        Ok(match outcome {
            TransactionalGuardOutcome::Allowed(requirement) => Ok(requirement),
            TransactionalGuardOutcome::DeniedNeedsCommit(error) => Err(error),
        })
    }

    async fn verify_persistent_in_tx_bound(
        &self,
        tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
        action: AbuseAction,
        subject: &str,
        actors: &[String],
        proof: Option<&PowProof>,
        intent: Option<&PowIntent>,
    ) -> anyhow::Result<std::result::Result<WorkRequirement, GuardError>> {
        let now: chrono::DateTime<chrono::Utc> = sqlx::query_scalar("SELECT clock_timestamp()")
            .fetch_one(&mut **tx)
            .await?;
        let keys = self.persistent_actor_state_keys(action, actors);
        let shared_ip_keys = self.persistent_shared_ip_keys(action, actors);
        let mut states = lock_db_states(tx, &keys, now).await?;
        decay_db_states(&mut states, now, &self.config);
        self.merge_previous_actor_states(action, actors, &mut states);
        let current = requirement_from_db(action, &states, &shared_ip_keys, now, &self.config);

        let Some(proof) = proof else {
            if current.work_factor <= 1 && current.retry_after_seconds == 0 {
                record_db_states(&mut states, &shared_ip_keys, now, &current);
                persist_db_states(tx, &states).await?;
                return Ok(Ok(current));
            }
            punish_db_states(&mut states, &shared_ip_keys, now, &self.config);
            persist_db_states(tx, &states).await?;
            return Ok(Err(GuardError::Required(current)));
        };

        let challenge = sqlx::query(
            "DELETE FROM abuse_pow_challenges WHERE id=$1
             RETURNING action,subject_hash,key_id,prefix,work_factor,not_before,
                       expires_at,actor_sequences,requirement,protocol_version,
                       intent_method,intent_path,body_sha256,server_nonce,issued_at",
        )
        .bind(proof.challenge_id)
        .fetch_optional(&mut **tx)
        .await?;
        let Some(challenge) = challenge else {
            punish_db_states(&mut states, &shared_ip_keys, now, &self.config);
            persist_db_states(tx, &states).await?;
            return Ok(Err(GuardError::Invalid(
                "proof-of-work challenge is missing or already used",
                current,
            )));
        };
        let challenge_requirement: WorkRequirement =
            serde_json::from_value(challenge.get("requirement"))?;
        let challenge_key_id: String = challenge.get("key_id");
        let protocol_version =
            u16::try_from(challenge.get::<i16, _>("protocol_version")).unwrap_or(u16::MAX);
        let intent_matches = if protocol_version == 1 {
            self.legacy_v1_allowed()
        } else if protocol_version == POW_INTENT_VERSION {
            intent.is_some_and(|expected| {
                challenge
                    .get::<Option<String>, _>("intent_method")
                    .as_deref()
                    == Some(expected.method.as_str())
                    && challenge.get::<Option<String>, _>("intent_path").as_deref()
                        == Some(expected.path.as_str())
                    && challenge
                        .get::<Option<Vec<u8>>, _>("body_sha256")
                        .as_deref()
                        == Some(expected.body_sha256.as_slice())
            })
        } else {
            false
        };
        let valid_identity = self
            .actor_secret_for_id(&challenge_key_id)
            .is_some_and(|secret| {
                if challenge.get::<String, _>("action") != action.as_str()
                    || challenge.get::<Vec<u8>, _>("subject_hash")
                        != subject_hash(action, subject, secret)
                {
                    return false;
                }
                if protocol_version != POW_INTENT_VERSION {
                    return protocol_version == 1;
                }
                let Some(expected) = intent else {
                    return false;
                };
                let Some(issued_at) =
                    challenge.get::<Option<chrono::DateTime<chrono::Utc>>, _>("issued_at")
                else {
                    return false;
                };
                let Some(server_nonce) = challenge.get::<Option<String>, _>("server_nonce") else {
                    return false;
                };
                let work_factor =
                    u64::try_from(challenge.get::<i64, _>("work_factor")).unwrap_or(u64::MAX);
                let expected_prefix = pow_prefix(
                    secret,
                    protocol_version,
                    proof.challenge_id,
                    action,
                    &challenge_key_id,
                    subject,
                    actors,
                    work_factor,
                    issued_at,
                    challenge.get("expires_at"),
                    &server_nonce,
                    Some(expected),
                );
                bool::from(
                    challenge
                        .get::<String, _>("prefix")
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
            punish_db_states(&mut states, &shared_ip_keys, now, &self.config);
            persist_db_states(tx, &states).await?;
            return Ok(Err(GuardError::Invalid(
                "proof-of-work challenge does not match this operation",
                current,
            )));
        }
        if now > challenge.get::<chrono::DateTime<chrono::Utc>, _>("expires_at") {
            return Ok(Err(GuardError::Invalid(
                "proof-of-work challenge expired",
                current,
            )));
        }
        if now < challenge.get::<chrono::DateTime<chrono::Utc>, _>("not_before") {
            return Ok(Err(GuardError::Invalid(
                "hard cooldown has not finished",
                challenge_requirement,
            )));
        }
        let expected: serde_json::Map<String, serde_json::Value> = challenge
            .get::<serde_json::Value, _>("actor_sequences")
            .as_object()
            .cloned()
            .unwrap_or_default();
        // Rotation may add current-key state rows after an old-key challenge
        // was issued. Validate exactly the signed key set; extra rows are not
        // evidence that the old challenge was replayed.
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
            return Ok(Err(GuardError::Invalid(
                "another operation already advanced this rate-limit step",
                current,
            )));
        }
        if proof.nonce.is_empty()
            || proof.nonce.len() > 64
            || !proof.nonce.bytes().all(|byte| byte.is_ascii_digit())
        {
            punish_db_states(&mut states, &shared_ip_keys, now, &self.config);
            persist_db_states(tx, &states).await?;
            return Ok(Err(GuardError::Invalid(
                "proof-of-work nonce is invalid",
                current,
            )));
        }
        let prefix: String = challenge.get("prefix");
        let mut hasher = Sha256::new();
        hasher.update(prefix.as_bytes());
        hasher.update(proof.nonce.as_bytes());
        let digest = hasher.finalize();
        let value = u64::from_be_bytes(digest[..8].try_into().expect("SHA-256 prefix"));
        let work_factor = u64::try_from(challenge.get::<i64, _>("work_factor")).unwrap_or(u64::MAX);
        if value > u64::MAX / work_factor.max(1) {
            punish_db_states(&mut states, &shared_ip_keys, now, &self.config);
            persist_db_states(tx, &states).await?;
            return Ok(Err(GuardError::Invalid(
                "proof of work is insufficient",
                current,
            )));
        }
        record_db_states(&mut states, &shared_ip_keys, now, &challenge_requirement);
        persist_db_states(tx, &states).await?;
        Ok(Ok(challenge_requirement))
    }

    pub(crate) async fn cleanup_challenges(&self) -> anyhow::Result<()> {
        if let Some(pool) = self.pool.as_ref() {
            let stale_seconds = self
                .config
                .window
                .max(self.config.max_wait)
                .max(max_penalty_decay_horizon(self.config.cooldown_step))
                .as_secs();
            // Each maintenance tick is deliberately bounded.  A flood cannot
            // turn cleanup into an unbounded delete/lock spike on the same
            // PostgreSQL instance that serves live sessions.
            sqlx::query(
                "WITH doomed AS (
                    SELECT ctid FROM abuse_pow_challenges
                    WHERE expires_at <= clock_timestamp()
                    ORDER BY expires_at LIMIT 1000
                 )
                 DELETE FROM abuse_pow_challenges AS target
                 USING doomed WHERE target.ctid=doomed.ctid",
            )
            .execute(pool)
            .await?;
            sqlx::query(
                "WITH doomed AS (
                    SELECT ctid FROM abuse_challenge_issue_windows
                    WHERE updated_at < clock_timestamp() - ($1::bigint * INTERVAL '1 second')
                    ORDER BY updated_at LIMIT 1000
                 )
                 DELETE FROM abuse_challenge_issue_windows AS target
                 USING doomed WHERE target.ctid=doomed.ctid",
            )
            .bind(i64::try_from(self.config.window.as_secs()).unwrap_or(i64::MAX))
            .execute(pool)
            .await?;
            sqlx::query(
                "WITH doomed AS (
                    SELECT ctid FROM abuse_actor_states
                    WHERE GREATEST(last_activity, blocked_until) < clock_timestamp() - ($1::bigint * INTERVAL '1 second')
                    ORDER BY GREATEST(last_activity, blocked_until) LIMIT 1000
                 )
                 DELETE FROM abuse_actor_states AS target
                 USING doomed WHERE target.ctid=doomed.ctid",
            )
                .bind(i64::try_from(stale_seconds).unwrap_or(i64::MAX))
                .execute(pool)
                .await?;
            sqlx::query(
                "WITH doomed AS (
                    SELECT admission_key FROM abuse_message_admissions
                    WHERE expires_at <= clock_timestamp()
                    ORDER BY expires_at,admission_key
                    LIMIT $1 FOR UPDATE SKIP LOCKED
                 )
                 DELETE FROM abuse_message_admissions AS target
                 USING doomed WHERE target.admission_key=doomed.admission_key",
            )
            .bind(MESSAGE_ADMISSION_CLEANUP_BATCH)
            .execute(pool)
            .await?;
            sqlx::query(
                "WITH doomed AS (
                    SELECT identity_digest FROM offline_message_admissions
                    WHERE offline_message_id IS NULL
                      AND expires_at IS NOT NULL AND expires_at <= clock_timestamp()
                    ORDER BY expires_at,identity_digest
                    LIMIT $1 FOR UPDATE SKIP LOCKED
                 )
                 DELETE FROM offline_message_admissions AS target
                 USING doomed WHERE target.identity_digest=doomed.identity_digest",
            )
            .bind(MESSAGE_ADMISSION_CLEANUP_BATCH)
            .execute(pool)
            .await?;
            return Ok(());
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

#[derive(Clone, Copy)]
struct Policy {
    free_burst: usize,
    base_work: u64,
}

fn policy(action: AbuseAction, base: u64, message_free_burst: usize) -> Policy {
    match action {
        AbuseAction::Registration => Policy {
            free_burst: 1,
            base_work: base,
        },
        AbuseAction::Message => Policy {
            free_burst: message_free_burst,
            base_work: base,
        },
        AbuseAction::Report => Policy {
            free_burst: 0,
            base_work: base.saturating_mul(2),
        },
        AbuseAction::Appeal => Policy {
            free_burst: 0,
            base_work: base.saturating_mul(8),
        },
        AbuseAction::Login => Policy {
            free_burst: 5,
            base_work: base,
        },
        AbuseAction::PasswordChange => Policy {
            free_burst: 3,
            base_work: base.saturating_mul(4),
        },
    }
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
    action == AbuseAction::Message
        && current.retry_after_seconds == 0
        && challenge.work_factor >= current.work_factor
        && challenge.hard_wait_seconds >= current.hard_wait_seconds
}

fn build_requirement(
    action: AbuseAction,
    policy: Policy,
    event_count: usize,
    penalty: u32,
    retry_after: u64,
    config: &AbuseConfig,
) -> WorkRequirement {
    let step = event_count
        .saturating_add(1)
        .saturating_sub(policy.free_burst) as u32;
    let squared = u64::from(step).saturating_mul(u64::from(step));
    let penalty_multiplier = 1_u64.checked_shl(penalty.min(20)).unwrap_or(u64::MAX);
    let work_factor = if step == 0 || policy.base_work == 0 {
        1
    } else {
        policy
            .base_work
            .saturating_mul(squared)
            .saturating_mul(penalty_multiplier)
            .clamp(1, config.max_work_factor)
    };
    let hard_wait = hard_wait_seconds(action, step, penalty)
        .min(config.max_wait.as_secs())
        .max(retry_after);
    WorkRequirement {
        action: action.as_str().to_owned(),
        step,
        work_factor,
        max_work_factor: config.max_work_factor,
        hard_wait_seconds: hard_wait,
        retry_after_seconds: retry_after,
        // With no accumulated penalty, the next ordinary n² step can fall
        // only when events age out of the rolling window. Once a failure has
        // raised the penalty, report its exponentially longer one-level decay
        // interval instead. This keeps the client notice truthful when an
        // operator configures the two base intervals differently.
        cooldown_seconds: if penalty == 0 {
            config.window.as_secs()
        } else {
            penalty_cooldown_interval(config.cooldown_step, penalty).as_secs()
        },
        approximate_max_device_seconds: config.approximate_max_device_seconds,
        notice: "Work rises in quadratic steps, has an operator-calibrated fixed maximum, and falls one penalty level at a time after activity stops. The advertised cooldown is the interval for the current penalty level; each higher level takes twice as long. Standards-only XMPP clients use the free burst and retry cooldown instead of PoW.".to_owned(),
    }
}

fn hard_wait_seconds(action: AbuseAction, step: u32, penalty: u32) -> u64 {
    let base: u64 = match step {
        0..=3 => 0,
        4..=7 => 2,
        8..=11 => 10,
        12..=15 => 30,
        _ => 120,
    };
    let strict: u64 = match action {
        AbuseAction::Appeal => 15,
        _ => 0,
    };
    base.max(strict).saturating_mul(1_u64 << penalty.min(8))
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

const MAX_PENALTY_LEVEL: u32 = 10;

fn penalty_cooldown_interval(base: Duration, level: u32) -> Duration {
    base.saturating_mul(1_u32 << level.min(MAX_PENALTY_LEVEL))
}

fn decayed_penalty(mut level: u32, elapsed: Duration, cooldown_step: Duration) -> (u32, Duration) {
    if cooldown_step.is_zero() || level == 0 {
        return (level, Duration::ZERO);
    }
    let mut consumed = Duration::ZERO;
    while level > 0 {
        let interval = penalty_cooldown_interval(cooldown_step, level);
        if elapsed.saturating_sub(consumed) < interval {
            break;
        }
        consumed = consumed.saturating_add(interval);
        level -= 1;
    }
    (level, consumed)
}

fn max_penalty_decay_horizon(cooldown_step: Duration) -> Duration {
    (1..=MAX_PENALTY_LEVEL).fold(Duration::ZERO, |total, level| {
        total.saturating_add(penalty_cooldown_interval(cooldown_step, level))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn guard() -> AbuseGuard {
        AbuseGuard::new(AbuseConfig {
            base_work_factor: 100,
            max_work_factor: 10_000,
            window: Duration::from_secs(60),
            cooldown_step: Duration::from_secs(60),
            max_wait: Duration::from_secs(900),
            message_free_burst: 6,
            approximate_max_device_seconds: 8,
        })
    }

    #[tokio::test]
    async fn shared_nat_state_waits_before_a_database_connection_is_acquired() {
        let guard = guard();
        let first = vec![
            "ip:203.0.113.9".to_owned(),
            "user:first".to_owned(),
            "behavior:first".to_owned(),
        ];
        let second = vec![
            "ip:203.0.113.9".to_owned(),
            "user:second".to_owned(),
            "behavior:second".to_owned(),
        ];
        let held = guard
            .acquire_db_state_gates(AbuseAction::Message, &first)
            .await;
        assert!(
            tokio::time::timeout(
                Duration::from_millis(20),
                guard.acquire_db_state_gates(AbuseAction::Message, &second),
            )
            .await
            .is_err(),
            "a second user behind the same NAT must queue outside PgPool"
        );
        drop(held);
        let released = tokio::time::timeout(
            Duration::from_secs(1),
            guard.acquire_db_state_gates(AbuseAction::Message, &second),
        )
        .await;
        assert!(released.is_ok());
    }

    #[test]
    fn actor_state_contention_is_a_distinct_retryable_condition() {
        let error = anyhow::Error::new(AbuseStateBusy);
        assert!(is_abuse_state_busy(&error));
        assert!(!is_abuse_state_busy(&anyhow::anyhow!("database offline")));
    }

    fn solve(challenge: &PowChallenge) -> PowProof {
        let target = u64::MAX / challenge.requirement.work_factor.max(1);
        for nonce in 0_u64.. {
            let nonce = nonce.to_string();
            let mut hasher = Sha256::new();
            hasher.update(challenge.prefix.as_bytes());
            hasher.update(nonce.as_bytes());
            let digest = hasher.finalize();
            let value = u64::from_be_bytes(digest[..8].try_into().unwrap());
            if value <= target {
                return PowProof {
                    challenge_id: challenge.challenge_id,
                    nonce,
                };
            }
        }
        unreachable!()
    }

    #[test]
    fn canonical_json_digest_is_order_independent_and_value_sensitive() {
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
        let non_bmp_key_vector = serde_json::json!({"😀":2,"":1});
        assert_eq!(
            URL_SAFE_NO_PAD.encode(canonical_json_body_digest(&non_bmp_key_vector)),
            "hxlUUxhZx1csYnn5Drg6WU3cOiiei9wo0qhP-4waFwM",
            "browser and Rust sort object keys by Unicode scalar value, not UTF-16 code unit"
        );
    }

    #[test]
    fn xmpp_registration_intent_is_transport_independent_and_field_bound() {
        let first =
            PowIntent::xmpp_registration("alice", "correct horse battery staple", Some("invite-1"));
        let same =
            PowIntent::xmpp_registration("alice", "correct horse battery staple", Some("invite-1"));
        assert_eq!(first, same);
        assert_ne!(
            first,
            PowIntent::xmpp_registration(
                "alice",
                "correct horse battery staple!",
                Some("invite-1"),
            )
        );
        assert_ne!(
            first,
            PowIntent::xmpp_registration("alice", "correct horse battery staple", Some("invite-2"),)
        );
        assert_ne!(
            PowIntent::xmpp_registration("ab", "cdefghijkl", None),
            PowIntent::xmpp_registration("a", "bcdefghijkl", None),
            "length prefixes must make adjacent-field splits unambiguous"
        );
        assert_ne!(
            PowIntent::xmpp_registration("alice", "correct horse battery staple", None),
            PowIntent::xmpp_registration("alice", "correct horse battery staple", Some("")),
            "missing and present-empty optional fields are distinct"
        );
    }

    #[tokio::test]
    async fn v2_challenge_is_bound_to_method_path_body_and_subject() {
        let actors = vec!["user:pow-v2".to_owned()];
        let expected = PowIntent::http_json(
            AbuseAction::Report,
            "/api/v1/reports",
            &serde_json::json!({"body":"one"}),
        );

        for changed in [
            PowIntent {
                method: "XMPP".to_owned(),
                ..expected.clone()
            },
            PowIntent {
                path: "/api/v1/reports/other".to_owned(),
                ..expected.clone()
            },
            PowIntent::http_json(
                AbuseAction::Report,
                "/api/v1/reports",
                &serde_json::json!({"body":"two"}),
            ),
        ] {
            let guard = guard();
            let challenge = guard
                .issue_v2(AbuseAction::Report, "report:pow-v2", &actors, &expected)
                .await
                .unwrap();
            let proof = solve(&challenge);
            assert!(guard
                .verify_or_allow_v2(
                    AbuseAction::Report,
                    "report:pow-v2",
                    &actors,
                    Some(&proof),
                    &changed,
                )
                .await
                .unwrap()
                .is_err());
        }

        let subject_mismatch_guard = guard();
        let challenge = subject_mismatch_guard
            .issue_v2(AbuseAction::Report, "report:pow-v2", &actors, &expected)
            .await
            .unwrap();
        let proof = solve(&challenge);
        assert!(subject_mismatch_guard
            .verify_or_allow_v2(
                AbuseAction::Report,
                "report:another-subject",
                &actors,
                Some(&proof),
                &expected,
            )
            .await
            .unwrap()
            .is_err());

        let actor_mismatch_guard = guard();
        let challenge = actor_mismatch_guard
            .issue_v2(AbuseAction::Report, "report:pow-v2", &actors, &expected)
            .await
            .unwrap();
        let proof = solve(&challenge);
        assert!(actor_mismatch_guard
            .verify_or_allow_v2(
                AbuseAction::Report,
                "report:pow-v2",
                &["user:another-actor".to_owned()],
                Some(&proof),
                &expected,
            )
            .await
            .unwrap()
            .is_err());

        let valid_guard = guard();
        let challenge = valid_guard
            .issue_v2(AbuseAction::Report, "report:pow-v2", &actors, &expected)
            .await
            .unwrap();
        assert_eq!(challenge.version, POW_INTENT_VERSION);
        assert!(challenge.intent.is_some());
        let proof = solve(&challenge);
        assert!(valid_guard
            .verify_or_allow_v2(
                AbuseAction::Report,
                "report:pow-v2",
                &actors,
                Some(&proof),
                &expected,
            )
            .await
            .unwrap()
            .is_ok());
    }

    #[tokio::test]
    async fn parallel_message_challenges_remain_one_use_and_cannot_cross_a_work_step() {
        let guard = guard();
        let actors = vec!["user:parallel-message-pow".to_owned()];
        let subject = "message:parallel-message-pow";
        let intents = (0..7)
            .map(|index| {
                PowIntent::xmpp(
                    AbuseAction::Message,
                    "/xmpp/message",
                    format!("<message id='{index}'><body>{index}</body></message>").as_bytes(),
                )
            })
            .collect::<Vec<_>>();
        let mut challenges = Vec::new();
        for intent in &intents {
            challenges.push(
                guard
                    .issue_v2(AbuseAction::Message, subject, &actors, intent)
                    .await
                    .unwrap(),
            );
        }
        assert_eq!(guard.challenges.len(), 7);

        for (challenge, intent) in challenges.iter().zip(&intents).take(6) {
            assert!(guard
                .verify_or_allow_v2(
                    AbuseAction::Message,
                    subject,
                    &actors,
                    Some(&solve(challenge)),
                    intent,
                )
                .await
                .unwrap()
                .is_ok());
        }

        // The seventh proof was issued at the free step. Six accepted sends
        // have now raised the live requirement, so it must fail closed rather
        // than spend a stale cheap proof across that boundary.
        assert!(guard
            .verify_or_allow_v2(
                AbuseAction::Message,
                subject,
                &actors,
                Some(&solve(&challenges[6])),
                &intents[6],
            )
            .await
            .unwrap()
            .is_err());

        let replay = guard
            .verify_or_allow_v2(
                AbuseAction::Message,
                subject,
                &actors,
                Some(&solve(&challenges[0])),
                &intents[0],
            )
            .await
            .unwrap()
            .unwrap_err();
        assert!(replay.message().contains("already used"));
    }

    #[test]
    fn v2_intent_request_rejects_noncanonical_routes_and_digests() {
        let digest = URL_SAFE_NO_PAD.encode([7_u8; 32]);
        assert!(PowIntent::from_request(
            AbuseAction::Report,
            &PowIntentRequest {
                version: 2,
                method: "POST".to_owned(),
                path: "/api/v1/reports".to_owned(),
                body_sha256: digest.clone(),
            },
        )
        .is_ok());
        for (version, method, path, body_sha256) in [
            (1, "POST", "/api/v1/reports", digest.as_str()),
            (2, "post", "/api/v1/reports", digest.as_str()),
            (2, "GET", "/api/v1/reports", digest.as_str()),
            (2, "POST", "/api/v1/reports?scope=other", digest.as_str()),
            (2, "POST", "/api/v1/../reports", digest.as_str()),
            (2, "POST", "/api/v1/reports", "not-base64"),
        ] {
            assert!(PowIntent::from_request(
                AbuseAction::Report,
                &PowIntentRequest {
                    version,
                    method: method.to_owned(),
                    path: path.to_owned(),
                    body_sha256: body_sha256.to_owned(),
                },
            )
            .is_err());
        }
    }

    #[tokio::test]
    async fn closed_v1_window_rejects_issue_and_consumption_but_v2_remains_available() {
        let mut guard = guard();
        let actors = vec!["user:pow-v2-only".to_owned()];
        let legacy = guard
            .issue(AbuseAction::Report, "report:legacy", &actors)
            .await
            .unwrap();
        let legacy_proof = solve(&legacy);
        guard.legacy_v1_compatibility_until = None;
        assert!(guard
            .verify_or_allow(
                AbuseAction::Report,
                "report:legacy",
                &actors,
                Some(&legacy_proof),
            )
            .await
            .unwrap()
            .is_err());
        assert!(guard
            .issue(AbuseAction::Report, "report:v1", &actors)
            .await
            .unwrap_err()
            .downcast_ref::<LegacyPowV1Disabled>()
            .is_some());
        let intent = PowIntent::http_json(
            AbuseAction::Report,
            "/api/v1/reports",
            &serde_json::json!({"body":"v2"}),
        );
        assert!(guard
            .issue_v2(AbuseAction::Report, "report:v2", &actors, &intent)
            .await
            .is_ok());
    }

    #[test]
    fn message_admission_hmac_is_domain_separated_and_sharded() {
        let secret = b"message-admission-property-secret-0001";
        let actor_id = Uuid::new_v4();
        let actors = vec![format!("user:{actor_id}")];
        let baseline = MessageAdmissionRequest {
            actor_id,
            account_bare: "alice@example.test",
            normalized_target: "bob@example.test",
            origin_id: Some("origin-1"),
            normalized_payload: "<message to='bob@example.test'><body>one</body></message>",
            pow_intent_payload: "<message to='bob@example.test'><body>one</body></message>",
            subject: "message:alice",
            actors: &actors,
            proof: None,
        };
        let (base_key, base_payload) =
            message_admission_material(&baseline, secret, b"origin-id", b"origin-1");
        let (same_key, same_payload) =
            message_admission_material(&baseline, secret, b"origin-id", b"origin-1");
        assert_eq!(base_key, same_key);
        assert_eq!(base_payload, same_payload);
        let stable_identity =
            message_admission_identity_digest(&baseline, b"origin-id", b"origin-1");
        assert_eq!(stable_identity.len(), 32);

        let changed_payload = MessageAdmissionRequest {
            normalized_payload: "<message to='bob@example.test'><body>two</body></message>",
            pow_intent_payload: "<message to='bob@example.test'><body>two</body></message>",
            ..baseline
        };
        let (payload_key, payload_mac) =
            message_admission_material(&changed_payload, secret, b"origin-id", b"origin-1");
        assert_eq!(
            base_key, payload_key,
            "content must not change the retry key"
        );
        assert_ne!(
            base_payload, payload_mac,
            "content must change the keyed payload digest"
        );
        assert_eq!(
            stable_identity,
            message_admission_identity_digest(&changed_payload, b"origin-id", b"origin-1"),
            "the offline lookup identity must be a stable SHA-256 value, independent of payload and HMAC rotation"
        );

        for (account, target, kind, identity) in [
            (
                "mallory@example.test",
                "bob@example.test",
                b"origin-id".as_slice(),
                b"origin-1".as_slice(),
            ),
            (
                "alice@example.test",
                "carol@example.test",
                b"origin-id".as_slice(),
                b"origin-1".as_slice(),
            ),
            (
                "alice@example.test",
                "bob@example.test",
                b"origin-id".as_slice(),
                b"origin-2".as_slice(),
            ),
            (
                "alice@example.test",
                "bob@example.test",
                b"challenge".as_slice(),
                b"origin-1".as_slice(),
            ),
        ] {
            let variant = MessageAdmissionRequest {
                account_bare: account,
                normalized_target: target,
                ..baseline
            };
            let (key, mac) = message_admission_material(&variant, secret, kind, identity);
            assert_ne!(base_key, key);
            assert_ne!(base_payload, mac);
            assert_ne!(
                stable_identity,
                message_admission_identity_digest(&variant, kind, identity)
            );
        }

        let mut shards = HashSet::new();
        for index in 0..10_000_u32 {
            let origin = format!("origin-{index}");
            let (key, _) =
                message_admission_material(&baseline, secret, b"origin-id", origin.as_bytes());
            let shard = message_admission_capacity_shard(&key);
            assert!((0..64).contains(&shard));
            shards.insert(shard);
        }
        assert_eq!(shards.len(), 64, "all capacity shards must be reachable");
    }

    #[test]
    fn message_work_grows_quadratically_after_free_burst() {
        let guard = guard();
        let actors = vec!["user:1".to_owned()];
        for _ in 0..6 {
            let requirement = guard
                .verify_memory(AbuseAction::Message, "user:1", &actors, None)
                .unwrap();
            assert_eq!(requirement.work_factor, 1);
        }
        let requirement = guard.requirement(AbuseAction::Message, &actors, Instant::now());
        assert_eq!(requirement.step, 1);
        assert_eq!(requirement.work_factor, 100);
        let challenge = guard
            .issue_memory(AbuseAction::Message, "user:1", &actors)
            .unwrap();
        guard
            .verify_memory(
                AbuseAction::Message,
                "user:1",
                &actors,
                Some(&solve(&challenge)),
            )
            .unwrap();
        let requirement = guard.requirement(AbuseAction::Message, &actors, Instant::now());
        assert_eq!(requirement.step, 2);
        assert_eq!(requirement.work_factor, 400);

        let challenge = guard
            .issue_memory(AbuseAction::Message, "user:1", &actors)
            .unwrap();
        guard
            .verify_memory(
                AbuseAction::Message,
                "user:1",
                &actors,
                Some(&solve(&challenge)),
            )
            .unwrap();
        let requirement = guard.requirement(AbuseAction::Message, &actors, Instant::now());
        assert_eq!(requirement.step, 3);
        assert_eq!(requirement.work_factor, 900);
    }

    #[test]
    fn message_escalation_has_bounded_quadratic_work_and_hard_wait_gates() {
        let config = &guard().config;
        let policy = Policy {
            free_burst: 0,
            base_work: config.base_work_factor,
        };
        for (events, expected_work, expected_wait) in [
            (0, 100, 0),
            (1, 400, 0),
            (3, 1_600, 2),
            (7, 6_400, 10),
            (11, 10_000, 30),
            (15, 10_000, 120),
            (10_000, 10_000, 120),
        ] {
            let requirement = build_requirement(AbuseAction::Message, policy, events, 0, 0, config);
            assert_eq!(requirement.work_factor, expected_work);
            assert_eq!(requirement.hard_wait_seconds, expected_wait);
            assert!(requirement.work_factor <= requirement.max_work_factor);
            assert_eq!(requirement.approximate_max_device_seconds, 8);
        }
    }

    #[test]
    fn cooldown_notice_and_penalty_decay_follow_exponential_steps() {
        let config = AbuseConfig {
            window: Duration::from_secs(45),
            cooldown_step: Duration::from_secs(30),
            ..guard().config
        };
        let policy = Policy {
            free_burst: 0,
            base_work: config.base_work_factor,
        };
        let ordinary = build_requirement(AbuseAction::Message, policy, 0, 0, 0, &config);
        assert_eq!(ordinary.cooldown_seconds, 45);
        let penalized = build_requirement(AbuseAction::Message, policy, 0, 3, 0, &config);
        assert_eq!(penalized.cooldown_seconds, 240);
        assert_eq!(penalized.work_factor, 800);

        assert_eq!(
            decayed_penalty(3, Duration::from_secs(239), config.cooldown_step),
            (3, Duration::ZERO)
        );
        assert_eq!(
            decayed_penalty(3, Duration::from_secs(240), config.cooldown_step),
            (2, Duration::from_secs(240))
        );
        assert_eq!(
            decayed_penalty(3, Duration::from_secs(360), config.cooldown_step),
            (1, Duration::from_secs(360))
        );
    }

    #[test]
    fn standards_only_client_is_throttled_then_recovers_after_window() {
        let guard = guard();
        let actors = vec!["user:standards-client".to_owned()];
        for _ in 0..6 {
            assert!(guard
                .verify_memory(AbuseAction::Message, "user:standards-client", &actors, None,)
                .is_ok());
        }
        let limited = guard
            .verify_memory(AbuseAction::Message, "user:standards-client", &actors, None)
            .unwrap_err();
        assert_eq!(limited.requirement().step, 1);
        assert_eq!(limited.requirement().work_factor, 100);

        let old = Instant::now() - Duration::from_secs(61);
        let key = state_key(AbuseAction::Message, &actors[0]);
        let mut state = guard.states.get_mut(&key).unwrap();
        state.events = VecDeque::from([old; 7]);
        state.penalty_level = 0;
        state.last_activity = old;
        state.blocked_until = old;
        drop(state);
        let recovered = guard.requirement(AbuseAction::Message, &actors, Instant::now());
        assert_eq!(recovered.step, 0);
        assert_eq!(recovered.work_factor, 1);
        assert_eq!(recovered.retry_after_seconds, 0);
    }

    #[test]
    fn prefetched_pow_is_accepted_once_and_replay_is_rejected() {
        let guard = guard();
        let actors = vec!["user:pow-client".to_owned()];
        let challenge = guard
            .issue_memory(AbuseAction::Report, "report:pow-client", &actors)
            .unwrap();
        let proof = solve(&challenge);
        assert!(guard
            .verify_memory(
                AbuseAction::Report,
                "report:pow-client",
                &actors,
                Some(&proof),
            )
            .is_ok());
        let replay = guard
            .verify_memory(
                AbuseAction::Report,
                "report:pow-client",
                &actors,
                Some(&proof),
            )
            .unwrap_err();
        assert!(replay.message().contains("already used"));
    }

    #[test]
    fn challenge_issuance_is_hard_bounded_in_memory() {
        let account_guard = guard();
        let account_actors = vec!["user:capacity-account".to_owned()];
        for index in 0..MAX_ACTIVE_POW_CHALLENGES_PER_ACTOR {
            account_guard
                .issue_memory(
                    AbuseAction::Message,
                    &format!("message:capacity-account:{index}"),
                    &account_actors,
                )
                .unwrap();
        }
        let limited = account_guard
            .issue_memory(
                AbuseAction::Message,
                "message:capacity-account:overflow",
                &account_actors,
            )
            .unwrap_err();
        assert!(limited
            .downcast_ref::<ChallengeCapacityExceeded>()
            .is_some());

        // A second challenge for the same subject is a distinct active slot;
        // it must not bypass the per-actor cap. An expired row immediately
        // makes capacity available.
        let limited = account_guard
            .issue_memory(
                AbuseAction::Message,
                "message:capacity-account:0",
                &account_actors,
            )
            .unwrap_err();
        assert!(limited
            .downcast_ref::<ChallengeCapacityExceeded>()
            .is_some());
        let expired_id = *account_guard.challenges.iter().next().unwrap().key();
        account_guard
            .challenges
            .get_mut(&expired_id)
            .unwrap()
            .expires_at = Instant::now();
        account_guard
            .issue_memory(
                AbuseAction::Message,
                "message:capacity-account:after-expiry",
                &account_actors,
            )
            .unwrap();

        let ip_guard = guard();
        let ip_actors = vec!["ip:192.0.2.44".to_owned()];
        for index in 0..MAX_ACTIVE_POW_CHALLENGES_PER_IP {
            ip_guard
                .issue_memory(
                    AbuseAction::Registration,
                    &format!("registration:capacity-ip:{index}"),
                    &ip_actors,
                )
                .unwrap();
        }
        let limited = ip_guard
            .issue_memory(
                AbuseAction::Registration,
                "registration:capacity-ip:overflow",
                &ip_actors,
            )
            .unwrap_err();
        assert!(limited
            .downcast_ref::<ChallengeCapacityExceeded>()
            .is_some());

        let issue_guard = guard();
        for _ in 0..MAX_CHALLENGE_ISSUES_PER_IP_WINDOW {
            let challenge = issue_guard
                .issue_memory(
                    AbuseAction::Registration,
                    "registration:replace",
                    &ip_actors,
                )
                .unwrap();
            issue_guard.challenges.remove(&challenge.challenge_id);
        }
        let limited = issue_guard
            .issue_memory(
                AbuseAction::Registration,
                "registration:replace",
                &ip_actors,
            )
            .unwrap_err();
        assert!(limited
            .downcast_ref::<ChallengeCapacityExceeded>()
            .is_some());

        let global_guard = guard();
        let now = Instant::now();
        let requirement = global_guard.requirement(
            AbuseAction::Registration,
            &["ip:198.51.100.9".to_owned()],
            now,
        );
        for _ in 0..MAX_ACTIVE_POW_CHALLENGES_GLOBAL {
            global_guard.challenges.insert(
                Uuid::new_v4(),
                StoredChallenge {
                    protocol_version: 1,
                    action: AbuseAction::Registration,
                    subject: "preloaded".to_owned(),
                    intent: None,
                    key_id: global_guard.actor_key_id.clone(),
                    prefix: String::new(),
                    work_factor: 1,
                    issued_at: chrono::Utc::now(),
                    expires_at_wall: chrono::Utc::now() + chrono::Duration::seconds(60),
                    server_nonce: "test-only-server-nonce".to_owned(),
                    not_before: now,
                    expires_at: now + Duration::from_secs(60),
                    actor_sequences: Vec::new(),
                    capacity_actors: Vec::new(),
                    requirement: requirement.clone(),
                },
            );
        }
        let limited = global_guard
            .issue_memory(
                AbuseAction::Registration,
                "registration:global-overflow",
                &["ip:198.51.100.9".to_owned()],
            )
            .unwrap_err();
        assert!(limited
            .downcast_ref::<ChallengeCapacityExceeded>()
            .is_some());
    }

    #[test]
    fn capable_message_client_can_prefetch_through_the_normal_burst() {
        let guard = guard();
        let actors = vec!["user:prefetch".to_owned()];
        for _ in 0..guard.config.message_free_burst {
            let challenge = guard
                .issue_memory(AbuseAction::Message, "message:prefetch", &actors)
                .unwrap();
            guard
                .verify_memory(
                    AbuseAction::Message,
                    "message:prefetch",
                    &actors,
                    Some(&solve(&challenge)),
                )
                .unwrap();
        }
        let requirement = guard.requirement(AbuseAction::Message, &actors, Instant::now());
        assert_eq!(requirement.step, 1);
        assert_eq!(requirement.work_factor, 100);
        assert_eq!(requirement.retry_after_seconds, 0);
    }

    #[test]
    fn shared_ip_is_a_high_threshold_signal_not_a_nat_wide_penalty() {
        let guard = guard();
        let ip = "ip:198.51.100.10".to_owned();
        let user_a = vec![ip.clone(), "user:a".to_owned(), "behavior:a".to_owned()];
        let user_b = vec![ip.clone(), "user:b".to_owned(), "behavior:b".to_owned()];
        let now = Instant::now();
        let free = WorkRequirement {
            action: "message".to_owned(),
            step: 0,
            work_factor: 1,
            max_work_factor: 10_000,
            hard_wait_seconds: 0,
            retry_after_seconds: 0,
            cooldown_seconds: 60,
            approximate_max_device_seconds: 8,
            notice: String::new(),
        };
        for _ in 0..60 {
            guard.record(AbuseAction::Message, &user_a, now, &free);
        }
        let b = guard.requirement(AbuseAction::Message, &user_b, now);
        assert_eq!(
            b.step, 0,
            "one active account must not exhaust its NAT peers"
        );

        // The shared IP still acts as a high-volume circuit breaker.  At 20x
        // the account burst it begins contributing a rate-limit step.
        for _ in 0..80 {
            guard.record(AbuseAction::Message, &user_a, now, &free);
        }
        let b = guard.requirement(AbuseAction::Message, &user_b, now);
        assert_eq!(b.step, 2);
        assert_eq!(b.work_factor, 400);
    }

    #[test]
    fn reports_require_pow_immediately_and_appeals_are_stricter() {
        let guard = guard();
        let actors = vec!["user:1".to_owned()];
        assert_eq!(
            guard
                .requirement(AbuseAction::Report, &actors, Instant::now())
                .work_factor,
            200
        );
        let appeal = guard.requirement(AbuseAction::Appeal, &actors, Instant::now());
        assert_eq!(appeal.work_factor, 800);
        assert_eq!(appeal.hard_wait_seconds, 15);
    }

    #[test]
    fn password_change_failures_get_a_separate_strict_policy() {
        let guard = guard();
        let actors = vec!["user:1".to_owned()];
        for _ in 0..3 {
            guard.record_failure_memory(AbuseAction::PasswordChange, &actors);
        }
        let requirement = guard.requirement(AbuseAction::PasswordChange, &actors, Instant::now());
        assert_eq!(requirement.step, 1);
        assert_eq!(requirement.work_factor, 400);
        assert_eq!(requirement.hard_wait_seconds, 0);
    }

    #[test]
    fn sasl_failures_are_account_primary_and_do_not_lock_a_nat_peer() {
        let guard = guard();
        let ip = "ip:203.0.113.20".to_owned();
        let account_a = vec![ip.clone(), "login-account:a".to_owned()];
        let account_b = vec![ip, "login-account:b".to_owned()];
        for _ in 0..5 {
            guard.record_failure_memory(AbuseAction::Login, &account_a);
        }
        let limited = guard.requirement(AbuseAction::Login, &account_a, Instant::now());
        assert_eq!(limited.step, 1);
        assert!(limited.work_factor > 1);
        let peer = guard.requirement(AbuseAction::Login, &account_b, Instant::now());
        assert_eq!(peer.step, 0);
        assert_eq!(peer.work_factor, 1);
        assert_eq!(peer.retry_after_seconds, 0);
    }

    #[test]
    fn registration_escalates_to_real_work_after_the_free_burst() {
        let guard = guard();
        let actors = vec!["ip:127.0.0.1".to_owned()];
        guard
            .verify_memory(
                AbuseAction::Registration,
                "registration:local",
                &actors,
                None,
            )
            .unwrap();
        let requirement = guard.requirement(AbuseAction::Registration, &actors, Instant::now());
        assert_eq!(requirement.step, 1);
        assert_eq!(requirement.work_factor, 100);
    }

    #[test]
    fn cleanup_removes_fully_cooled_actor_and_challenge_issue_keys() {
        let guard = guard();
        let retention = guard
            .config
            .window
            .max(guard.config.max_wait)
            .max(max_penalty_decay_horizon(guard.config.cooldown_step));
        let old = Instant::now() - retention - Duration::from_secs(1);
        guard.states.insert(
            "message:ip:stale".to_owned(),
            ActorState {
                events: VecDeque::new(),
                penalty_level: 0,
                last_activity: old,
                blocked_until: old,
                sequence: 1,
            },
        );
        guard
            .challenge_issues
            .insert("challenge:ip:stale".to_owned(), VecDeque::from([old]));
        guard.cleanup_challenges_memory();
        assert!(guard.states.is_empty());
        assert!(guard.challenge_issues.is_empty());
    }

    #[tokio::test]
    async fn closed_persistent_backend_is_never_treated_as_an_allow() {
        let pool = sqlx::postgres::PgPoolOptions::new()
            .connect_lazy("postgres://closed:closed@127.0.0.1:9/closed")
            .unwrap();
        pool.close().await;
        let guard = AbuseGuard::new_persistent(
            guard().config,
            pool,
            Some(b"test-only-abuse-state-key-at-least-32-bytes"),
            None,
        );
        let outcome = tokio::time::timeout(
            Duration::from_secs(1),
            guard.verify_or_allow(
                AbuseAction::Message,
                "message:closed",
                &["user:closed".to_owned()],
                None,
            ),
        )
        .await
        .expect("closed backend must fail immediately");
        assert!(outcome.is_err(), "backend failure must not fail open");
    }

    #[tokio::test]
    async fn overlap_keeps_previous_primary_until_retirement_is_fenced() {
        let pool = sqlx::postgres::PgPoolOptions::new()
            .connect_lazy("postgres://unused:unused@127.0.0.1:9/unused")
            .unwrap();
        let config = guard().config;
        let old_secret = b"rotation-unit-old-secret-at-least-32-bytes";
        let new_secret = b"rotation-unit-new-secret-at-least-32-bytes";
        let old = AbuseGuard::new_persistent(config, pool.clone(), Some(old_secret), None);
        let overlap = AbuseGuard::new_persistent_for_deployment(
            config,
            pool.clone(),
            Some(new_secret),
            Some(old_secret),
            true,
            Some(chrono::DateTime::<chrono::Utc>::MAX_UTC),
        );
        let retiring = AbuseGuard::new_persistent_for_deployment(
            config,
            pool,
            Some(new_secret),
            Some(old_secret),
            false,
            Some(chrono::DateTime::<chrono::Utc>::MAX_UTC),
        );

        assert_eq!(overlap.primary_actor_key().0, old.actor_key_id);
        assert_eq!(
            overlap.persistent_actor_key_candidates()[0].0,
            old.actor_key_id
        );
        assert_eq!(
            overlap.actor_secret_for_id("legacy-current").unwrap(),
            old.actor_key_secret.as_slice()
        );
        assert_eq!(retiring.primary_actor_key().0, retiring.actor_key_id);
        assert_eq!(
            retiring.persistent_actor_key_candidates()[1].0,
            old.actor_key_id
        );
        let payload = b"canonical content identity";
        let overlap_message = overlap
            .personal_message_content_keyring()
            .authenticators(payload);
        let overlap_retraction = overlap
            .personal_retraction_content_keyring()
            .authenticators(payload);
        let overlap_mix_message = overlap
            .mix_message_content_keyring()
            .authenticators(payload);
        let overlap_mix_retraction = overlap
            .mix_retraction_content_keyring()
            .authenticators(payload);
        let retiring_message = retiring
            .personal_message_content_keyring()
            .authenticators(payload);
        assert_eq!(overlap_message.primary().key_id(), old.actor_key_id);
        assert_eq!(retiring_message.primary().key_id(), retiring.actor_key_id);
        assert_eq!(overlap_message.candidates().len(), 2);
        assert!(retiring_message.verifies(
            overlap_message.primary().key_id(),
            overlap_message.primary().mac(),
        ));
        let changed_message = retiring
            .personal_message_content_keyring()
            .authenticators(b"changed canonical content identity");
        assert!(!changed_message.verifies(
            overlap_message.primary().key_id(),
            overlap_message.primary().mac(),
        ));
        assert_ne!(
            overlap_message.primary().mac(),
            overlap_retraction.primary().mac(),
            "a service-purpose key must not authenticate another service's content"
        );
        let purpose_macs = [
            overlap_message.primary().mac(),
            overlap_retraction.primary().mac(),
            overlap_mix_message.primary().mac(),
            overlap_mix_retraction.primary().mac(),
        ];
        for left in 0..purpose_macs.len() {
            for right in (left + 1)..purpose_macs.len() {
                assert_ne!(
                    purpose_macs[left], purpose_macs[right],
                    "every durable replay journal must use a distinct purpose subkey"
                );
            }
        }
        assert!(!retiring_message.verifies("unknown-generation", &[0_u8; 32]));
        assert!(!retiring_message.verifies(retiring_message.primary().key_id(), &[0_u8; 31]));
        assert!(overlap.minimum_key_rotation_overlap() >= OFFLINE_MESSAGE_ADMISSION_REPLAY_GRACE);
    }

    #[test]
    fn offline_replay_grace_matches_the_database_trigger() {
        assert_eq!(
            OFFLINE_MESSAGE_ADMISSION_REPLAY_GRACE,
            Duration::from_secs(30 * 24 * 60 * 60)
        );
        assert!(
            include_str!("../migrations/0079_offline_message_dedupe.sql")
                .contains("INTERVAL '30 days'")
        );
    }

    #[tokio::test]
    #[ignore = "requires an isolated TEST_DATABASE_URL PostgreSQL database"]
    async fn postgres_v2_intent_mismatch_consumes_but_rollback_restores_proof() {
        let url = std::env::var("TEST_DATABASE_URL")
            .expect("set TEST_DATABASE_URL to an isolated PostgreSQL database");
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(4)
            .connect(&url)
            .await
            .unwrap();
        crate::db::migrate(&pool).await.unwrap();
        let guard = AbuseGuard::new_persistent(
            guard().config,
            pool.clone(),
            Some(b"postgres-v2-intent-test-key-at-least-32-bytes"),
            None,
        );
        let marker = Uuid::new_v4();
        let actors = vec![format!("user:v2-intent:{marker}")];
        let subject = format!("report:v2-intent:{marker}");
        let expected = PowIntent::http_json(
            AbuseAction::Report,
            "/api/v1/reports",
            &serde_json::json!({"body":"bound"}),
        );
        let changed = PowIntent::http_json(
            AbuseAction::Report,
            "/api/v1/reports",
            &serde_json::json!({"body":"changed"}),
        );

        let mismatch = guard
            .issue_v2(AbuseAction::Report, &subject, &actors, &expected)
            .await
            .unwrap();
        let stored: (i16, String, String, Vec<u8>, String) = sqlx::query_as(
            "SELECT protocol_version,intent_method,intent_path,body_sha256,server_nonce
             FROM abuse_pow_challenges WHERE id=$1",
        )
        .bind(mismatch.challenge_id)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(stored.0, POW_INTENT_VERSION as i16);
        assert_eq!(stored.1, "POST");
        assert_eq!(stored.2, "/api/v1/reports");
        assert_eq!(stored.3, expected.body_sha256);
        assert!(stored.4.len() >= 16);

        tokio::time::sleep(
            Duration::from_secs(mismatch.requirement.hard_wait_seconds) + Duration::from_millis(50),
        )
        .await;
        let mut mismatch_tx = pool.begin().await.unwrap();
        let mismatch_result = guard
            .verify_or_allow_in_tx_v2(
                &mut mismatch_tx,
                AbuseAction::Report,
                &subject,
                &actors,
                Some(&solve(&mismatch)),
                &changed,
            )
            .await
            .unwrap();
        assert!(matches!(
            mismatch_result,
            TransactionalGuardOutcome::DeniedNeedsCommit(_)
        ));
        mismatch_tx.commit().await.unwrap();
        let mismatch_remaining: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM abuse_pow_challenges WHERE id=$1")
                .bind(mismatch.challenge_id)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(mismatch_remaining, 0, "a mismatched proof is one-use");

        let rollback = guard
            .issue_v2(AbuseAction::Report, &subject, &actors, &expected)
            .await
            .unwrap();
        let proof = solve(&rollback);
        tokio::time::sleep(
            Duration::from_secs(rollback.requirement.hard_wait_seconds) + Duration::from_millis(50),
        )
        .await;
        let mut rollback_tx = pool.begin().await.unwrap();
        assert!(matches!(
            guard
                .verify_or_allow_in_tx_v2(
                    &mut rollback_tx,
                    AbuseAction::Report,
                    &subject,
                    &actors,
                    Some(&proof),
                    &expected,
                )
                .await
                .unwrap(),
            TransactionalGuardOutcome::Allowed(_)
        ));
        rollback_tx.rollback().await.unwrap();
        let restored: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM abuse_pow_challenges WHERE id=$1")
                .bind(rollback.challenge_id)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(restored, 1, "rolling back the mutation restores its proof");

        let mut commit_tx = pool.begin().await.unwrap();
        assert!(matches!(
            guard
                .verify_or_allow_in_tx_v2(
                    &mut commit_tx,
                    AbuseAction::Report,
                    &subject,
                    &actors,
                    Some(&proof),
                    &expected,
                )
                .await
                .unwrap(),
            TransactionalGuardOutcome::Allowed(_)
        ));
        commit_tx.commit().await.unwrap();
        let consumed: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM abuse_pow_challenges WHERE id=$1")
                .bind(rollback.challenge_id)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(consumed, 0);

        let before_rotation = guard
            .issue_v2(AbuseAction::Report, &subject, &actors, &expected)
            .await
            .unwrap();
        tokio::time::sleep(
            Duration::from_secs(before_rotation.requirement.hard_wait_seconds)
                + Duration::from_millis(50),
        )
        .await;
        let rotated = AbuseGuard::new_persistent_for_deployment(
            guard.config,
            pool.clone(),
            Some(b"postgres-v2-rotated-test-key-at-least-32-bytes"),
            Some(b"postgres-v2-intent-test-key-at-least-32-bytes"),
            false,
            None,
        );
        assert!(rotated
            .verify_or_allow_v2(
                AbuseAction::Report,
                &subject,
                &actors,
                Some(&solve(&before_rotation)),
                &expected,
            )
            .await
            .unwrap()
            .is_ok());
        pool.close().await;
    }

    #[tokio::test]
    #[ignore = "requires an isolated TEST_DATABASE_URL PostgreSQL database"]
    async fn postgres_parallel_message_challenges_are_independent_bounded_and_one_use() {
        let url = std::env::var("TEST_DATABASE_URL")
            .expect("set TEST_DATABASE_URL to an isolated PostgreSQL database");
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(8)
            .connect(&url)
            .await
            .unwrap();
        crate::db::migrate(&pool).await.unwrap();
        let guard = AbuseGuard::new_persistent(
            guard().config,
            pool.clone(),
            Some(b"parallel-message-pow-test-key-32bytes"),
            None,
        );
        let marker = Uuid::new_v4();
        let actors = vec![format!("user:parallel-message:{marker}")];
        let subject = format!("message:parallel-message:{marker}");
        let first_intent = PowIntent::xmpp(
            AbuseAction::Message,
            "/xmpp/message",
            b"<message id='parallel-one'><body>one</body></message>",
        );
        let second_intent = PowIntent::xmpp(
            AbuseAction::Message,
            "/xmpp/message",
            b"<message id='parallel-two'><body>two</body></message>",
        );

        let (first, second) = tokio::join!(
            guard.issue_v2(AbuseAction::Message, &subject, &actors, &first_intent),
            guard.issue_v2(AbuseAction::Message, &subject, &actors, &second_intent),
        );
        let first = first.unwrap();
        let second = second.unwrap();
        assert_ne!(first.challenge_id, second.challenge_id);
        let stored: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM abuse_pow_challenges WHERE id=ANY($1::uuid[])",
        )
        .bind(vec![first.challenge_id, second.challenge_id])
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(
            stored, 2,
            "same-subject challenges must not replace each other"
        );

        let first_proof = solve(&first);
        let second_proof = solve(&second);
        let (first_result, second_result) = tokio::join!(
            guard.verify_or_allow_v2(
                AbuseAction::Message,
                &subject,
                &actors,
                Some(&first_proof),
                &first_intent,
            ),
            guard.verify_or_allow_v2(
                AbuseAction::Message,
                &subject,
                &actors,
                Some(&second_proof),
                &second_intent,
            ),
        );
        assert!(first_result.unwrap().is_ok());
        assert!(second_result.unwrap().is_ok());

        let mut capacity_ids = Vec::new();
        for index in 0..MAX_ACTIVE_POW_CHALLENGES_PER_ACTOR {
            let intent = PowIntent::xmpp(
                AbuseAction::Message,
                "/xmpp/message",
                format!("<message id='capacity-{index}'/>").as_bytes(),
            );
            capacity_ids.push(
                guard
                    .issue_v2(AbuseAction::Message, &subject, &actors, &intent)
                    .await
                    .unwrap()
                    .challenge_id,
            );
        }
        let overflow_intent = PowIntent::xmpp(
            AbuseAction::Message,
            "/xmpp/message",
            b"<message id='capacity-overflow'/>",
        );
        let overflow = guard
            .issue_v2(AbuseAction::Message, &subject, &actors, &overflow_intent)
            .await
            .unwrap_err();
        assert!(overflow
            .downcast_ref::<ChallengeCapacityExceeded>()
            .is_some());
        let capacity_rows: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM abuse_pow_challenges WHERE id=ANY($1::uuid[])",
        )
        .bind(&capacity_ids)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(
            capacity_rows,
            i64::try_from(MAX_ACTIVE_POW_CHALLENGES_PER_ACTOR).unwrap(),
            "capacity rejection must not replace or add a challenge row"
        );

        let replay = guard
            .verify_or_allow_v2(
                AbuseAction::Message,
                &subject,
                &actors,
                Some(&first_proof),
                &first_intent,
            )
            .await
            .unwrap()
            .unwrap_err();
        assert!(replay.message().contains("already used"));
        pool.close().await;
    }

    #[tokio::test]
    #[ignore = "requires an isolated TEST_DATABASE_URL PostgreSQL database"]
    async fn postgres_challenges_are_one_use_restart_safe_and_deidentified() {
        let url = std::env::var("TEST_DATABASE_URL")
            .expect("set TEST_DATABASE_URL to an isolated PostgreSQL database");
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(12)
            .connect(&url)
            .await
            .unwrap();
        crate::db::migrate(&pool).await.unwrap();
        let config = AbuseConfig {
            base_work_factor: 32,
            max_work_factor: 4_096,
            window: Duration::from_secs(60),
            cooldown_step: Duration::from_secs(60),
            max_wait: Duration::from_secs(900),
            message_free_burst: 60,
            approximate_max_device_seconds: 8,
        };
        let secret = b"test-only-shared-abuse-key-at-least-32-bytes";
        let guard = std::sync::Arc::new(AbuseGuard::new_persistent(
            config,
            pool.clone(),
            Some(secret),
            None,
        ));
        let marker = Uuid::new_v4();
        let actors = vec![
            format!("ip:198.51.100.{}", marker.as_bytes()[0]),
            format!("user:{marker}"),
            format!("behavior:{marker}"),
        ];
        let subject = format!("report:{marker}");
        let challenge = guard
            .issue(AbuseAction::Report, &subject, &actors)
            .await
            .unwrap();
        // 0057 labels challenges that predate the key-id column as
        // legacy-current. An upgrade that keeps the current abuse key must
        // preserve those proofs instead of burning them unconditionally.
        sqlx::query("UPDATE abuse_pow_challenges SET key_id='legacy-current' WHERE id=$1")
            .bind(challenge.challenge_id)
            .execute(&pool)
            .await
            .unwrap();
        let proof = solve(&challenge);
        let first = {
            let guard = std::sync::Arc::clone(&guard);
            let actors = actors.clone();
            let subject = subject.clone();
            let proof = proof.clone();
            tokio::spawn(async move {
                guard
                    .verify_or_allow(AbuseAction::Report, &subject, &actors, Some(&proof))
                    .await
                    .unwrap()
            })
        };
        let second = {
            let guard = std::sync::Arc::clone(&guard);
            let actors = actors.clone();
            let subject = subject.clone();
            tokio::spawn(async move {
                guard
                    .verify_or_allow(AbuseAction::Report, &subject, &actors, Some(&proof))
                    .await
                    .unwrap()
            })
        };
        let outcomes = [first.await.unwrap(), second.await.unwrap()];
        assert_eq!(outcomes.iter().filter(|outcome| outcome.is_ok()).count(), 1);
        assert_eq!(
            outcomes.iter().filter(|outcome| outcome.is_err()).count(),
            1
        );

        let restarted = AbuseGuard::new_persistent(config, pool.clone(), Some(secret), None);
        let requirement = restarted
            .current_requirement(AbuseAction::Report, &actors)
            .await
            .unwrap();
        assert!(requirement.step >= 2, "accepted proof must survive restart");

        let keys: Vec<String> =
            sqlx::query_scalar("SELECT state_key FROM abuse_actor_states ORDER BY state_key")
                .fetch_all(&pool)
                .await
                .unwrap();
        assert!(keys.iter().all(|key| {
            !actors.iter().any(|actor| key.contains(actor))
                && !key.contains("198.51.100")
                && !key.contains(&marker.to_string())
        }));

        // Rotation overlaps old and new actor keys. Mutations during the
        // overlap are copied to the new key so removing PREVIOUS later does
        // not reset the surviving penalty history.
        let new_secret = b"test-only-new-abuse-key-at-least-32-bytes";
        let issued_before_rotation = restarted
            .issue(AbuseAction::Report, &subject, &actors)
            .await
            .unwrap();
        let rotated = AbuseGuard::new_persistent_for_deployment(
            config,
            pool.clone(),
            Some(new_secret),
            Some(secret),
            true,
            Some(chrono::DateTime::<chrono::Utc>::MAX_UTC),
        );
        tokio::time::sleep(
            Duration::from_secs(issued_before_rotation.requirement.hard_wait_seconds)
                + Duration::from_millis(100),
        )
        .await;
        rotated
            .verify_or_allow(
                AbuseAction::Report,
                &subject,
                &actors,
                Some(&solve(&issued_before_rotation)),
            )
            .await
            .unwrap()
            .unwrap();
        let before = rotated
            .current_requirement(AbuseAction::Report, &actors)
            .await
            .unwrap();
        assert!(before.step >= 2);
        let rotated_challenge = rotated
            .issue(AbuseAction::Report, &subject, &actors)
            .await
            .unwrap();
        let rotated_challenge_key_id: String =
            sqlx::query_scalar("SELECT key_id FROM abuse_pow_challenges WHERE id=$1")
                .bind(rotated_challenge.challenge_id)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(rotated_challenge_key_id, restarted.actor_key_id);
        tokio::time::sleep(
            Duration::from_secs(rotated_challenge.requirement.hard_wait_seconds)
                + Duration::from_millis(100),
        )
        .await;
        restarted
            .verify_or_allow(
                AbuseAction::Report,
                &subject,
                &actors,
                Some(&solve(&rotated_challenge)),
            )
            .await
            .unwrap()
            .unwrap();
        // A dual-key read mirrors the old-only node's accepted transition into
        // the new generation before the previous generation is removed.
        rotated
            .current_requirement(AbuseAction::Report, &actors)
            .await
            .unwrap();
        let after_overlap =
            AbuseGuard::new_persistent(config, pool.clone(), Some(new_secret), None)
                .current_requirement(AbuseAction::Report, &actors)
                .await
                .unwrap();
        assert!(after_overlap.step > before.step);

        // Challenge issuance windows rotate as one lock-ordered state. An
        // actor at limit-1 under the old key has exactly one issuance left,
        // not a fresh window under the new key.
        let issue_actor = format!("user:issue-window-{}", Uuid::new_v4());
        let issue_actors = vec![issue_actor.clone()];
        let issue_subject = format!("report:issue-window:{issue_actor}");
        let old_issue_guard = AbuseGuard::new_persistent(config, pool.clone(), Some(secret), None);
        for _ in 0..(old_issue_guard.challenge_issue_limit(AbuseAction::Report) - 1) {
            let issued = old_issue_guard
                .issue(AbuseAction::Report, &issue_subject, &issue_actors)
                .await
                .unwrap();
            // This section isolates issuance-window continuity across key
            // rotation. Expire each proof after issuance so the independent
            // active-challenge ceiling cannot become the first limiter.
            sqlx::query(
                "UPDATE abuse_pow_challenges
                    SET expires_at=clock_timestamp()
                  WHERE id=$1",
            )
            .bind(issued.challenge_id)
            .execute(&pool)
            .await
            .unwrap();
        }
        let rotated_issue_guard = AbuseGuard::new_persistent_for_deployment(
            config,
            pool.clone(),
            Some(new_secret),
            Some(secret),
            true,
            Some(chrono::DateTime::<chrono::Utc>::MAX_UTC),
        );
        rotated_issue_guard
            .issue(AbuseAction::Report, &issue_subject, &issue_actors)
            .await
            .unwrap();
        let old_issue_key = format!(
            "challenge:{}",
            opaque_actor_key(
                AbuseAction::Report,
                &issue_actor,
                old_issue_guard.actor_key_secret.as_slice(),
            )
        );
        let new_issue_key = format!(
            "challenge:{}",
            opaque_actor_key(
                AbuseAction::Report,
                &issue_actor,
                rotated_issue_guard.actor_key_secret.as_slice(),
            )
        );
        let event_counts: Vec<i64> = sqlx::query_scalar(
            "SELECT cardinality(event_times)::bigint
             FROM abuse_challenge_issue_windows
             WHERE actor_key=ANY($1) ORDER BY actor_key",
        )
        .bind(vec![old_issue_key.clone(), new_issue_key.clone()])
        .fetch_all(&pool)
        .await
        .unwrap();
        assert_eq!(event_counts, vec![30, 30]);
        let limited = rotated_issue_guard
            .issue(AbuseAction::Report, &issue_subject, &issue_actors)
            .await
            .unwrap_err();
        assert!(limited
            .downcast_ref::<ChallengeCapacityExceeded>()
            .is_some());
        let after_limit: Vec<i64> = sqlx::query_scalar(
            "SELECT cardinality(event_times)::bigint
             FROM abuse_challenge_issue_windows
             WHERE actor_key=ANY($1) ORDER BY actor_key",
        )
        .bind(vec![old_issue_key, new_issue_key])
        .fetch_all(&pool)
        .await
        .unwrap();
        assert_eq!(after_limit, vec![30, 30]);

        // A cleanup pass is bounded to 1000 rows; a second pass drains the
        // remainder. This keeps maintenance latency bounded under attack.
        let cleanup_prefix = format!("cleanup-{marker}-");
        sqlx::query(
            "INSERT INTO abuse_actor_states (state_key,last_activity,blocked_until)
             SELECT $1 || value::text,
                    clock_timestamp() - INTERVAL '10 days',
                    clock_timestamp() - INTERVAL '10 days'
             FROM generate_series(1,1001) AS value",
        )
        .bind(&cleanup_prefix)
        .execute(&pool)
        .await
        .unwrap();
        rotated.cleanup_challenges().await.unwrap();
        let remaining: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM abuse_actor_states WHERE state_key LIKE $1")
                .bind(format!("{cleanup_prefix}%"))
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(remaining, 1);
        rotated.cleanup_challenges().await.unwrap();

        for key in actor_state_keys(AbuseAction::Report, &actors, &restarted.actor_key_secret) {
            sqlx::query("DELETE FROM abuse_actor_states WHERE state_key=$1")
                .bind(key)
                .execute(&pool)
                .await
                .unwrap();
        }
        pool.close().await;
    }

    #[tokio::test]
    #[ignore = "requires an isolated TEST_DATABASE_URL PostgreSQL database"]
    async fn postgres_challenge_capacity_is_concurrent_restart_safe_and_hard_limited() {
        let url = std::env::var("TEST_DATABASE_URL")
            .expect("set TEST_DATABASE_URL to an isolated PostgreSQL database");
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(24)
            .connect(&url)
            .await
            .unwrap();
        crate::db::migrate(&pool).await.unwrap();
        let config = AbuseConfig {
            base_work_factor: 2,
            max_work_factor: 4_096,
            window: Duration::from_secs(60),
            cooldown_step: Duration::from_secs(60),
            max_wait: Duration::from_secs(8),
            message_free_burst: 60,
            approximate_max_device_seconds: 8,
        };
        let secret = b"challenge-capacity-test-secret-00000001";
        let guard = std::sync::Arc::new(AbuseGuard::new_persistent(
            config,
            pool.clone(),
            Some(secret),
            None,
        ));
        let account_actor = format!("user:capacity-{}", Uuid::new_v4());
        let account_actors = vec![account_actor.clone()];
        let mut tasks = Vec::new();
        for index in 0..24 {
            let guard = std::sync::Arc::clone(&guard);
            let actors = account_actors.clone();
            tasks.push(tokio::spawn(async move {
                let subject = format!("message:concurrent-capacity:{index}");
                (
                    index,
                    guard.issue(AbuseAction::Message, &subject, &actors).await,
                )
            }));
        }
        let mut successful_subject = None;
        let mut successful_challenge_id = None;
        let mut issued_challenge_ids = Vec::new();
        let mut accepted = 0;
        let mut limited = 0;
        for task in tasks {
            let (index, outcome) = task.await.unwrap();
            match outcome {
                Ok(challenge) => {
                    accepted += 1;
                    successful_subject
                        .get_or_insert_with(|| format!("message:concurrent-capacity:{index}"));
                    successful_challenge_id.get_or_insert(challenge.challenge_id);
                    issued_challenge_ids.push(challenge.challenge_id);
                }
                Err(error) => {
                    assert!(error.downcast_ref::<ChallengeCapacityExceeded>().is_some());
                    limited += 1;
                }
            }
        }
        assert_eq!(accepted, MAX_ACTIVE_POW_CHALLENGES_PER_ACTOR);
        assert_eq!(limited, 24 - MAX_ACTIVE_POW_CHALLENGES_PER_ACTOR);

        let restarted = AbuseGuard::new_persistent(config, pool.clone(), Some(secret), None);
        let error = restarted
            .issue(
                AbuseAction::Message,
                "message:concurrent-capacity:restart-overflow",
                &account_actors,
            )
            .await
            .unwrap_err();
        assert!(error.downcast_ref::<ChallengeCapacityExceeded>().is_some());
        let error = restarted
            .issue(
                AbuseAction::Message,
                successful_subject.as_deref().unwrap(),
                &account_actors,
            )
            .await
            .unwrap_err();
        assert!(error.downcast_ref::<ChallengeCapacityExceeded>().is_some());

        let expired = sqlx::query(
            "UPDATE abuse_pow_challenges SET expires_at=clock_timestamp()
             WHERE id=$1 AND expires_at > clock_timestamp()",
        )
        .bind(successful_challenge_id.expect("at least one account challenge was accepted"))
        .execute(&pool)
        .await
        .unwrap();
        assert_eq!(expired.rows_affected(), 1);
        let after_expiry = restarted
            .issue(
                AbuseAction::Message,
                "message:concurrent-capacity:after-expiry",
                &account_actors,
            )
            .await
            .unwrap();
        issued_challenge_ids.push(after_expiry.challenge_id);

        let ip_actor = format!("ip:198.51.100.{}", Uuid::new_v4().as_bytes()[0]);
        let ip_actors = vec![ip_actor.clone()];
        for index in 0..MAX_ACTIVE_POW_CHALLENGES_PER_IP {
            let challenge = restarted
                .issue(
                    AbuseAction::Registration,
                    &format!("registration:ip-capacity:{index}"),
                    &ip_actors,
                )
                .await
                .unwrap();
            issued_challenge_ids.push(challenge.challenge_id);
        }
        let error = restarted
            .issue(
                AbuseAction::Registration,
                "registration:ip-capacity:overflow",
                &ip_actors,
            )
            .await
            .unwrap_err();
        assert!(error.downcast_ref::<ChallengeCapacityExceeded>().is_some());

        let window_ip = format!("ip:203.0.113.{}", Uuid::new_v4().as_bytes()[0]);
        let window_actors = vec![window_ip];
        let issue_keys = restarted
            .challenge_issue_groups(AbuseAction::Registration, &window_actors)
            .into_iter()
            .flat_map(|(keys, _)| keys)
            .collect::<Vec<_>>();
        sqlx::query(
            "INSERT INTO abuse_challenge_issue_windows(actor_key,event_times,updated_at)
             SELECT actor_key,events,clock_timestamp()
             FROM UNNEST($1::text[]) AS actor_key
             CROSS JOIN LATERAL (
                 SELECT array_agg(clock_timestamp()-(value*INTERVAL '1 millisecond')
                                  ORDER BY value) AS events
                 FROM generate_series(0,$2::integer-1) AS value
             ) AS seeded
             ON CONFLICT(actor_key) DO UPDATE
             SET event_times=EXCLUDED.event_times,updated_at=EXCLUDED.updated_at",
        )
        .bind(&issue_keys)
        .bind(i32::try_from(MAX_CHALLENGE_ISSUES_PER_IP_WINDOW).unwrap())
        .execute(&pool)
        .await
        .unwrap();
        let seeded_issue_count: i64 = sqlx::query_scalar(
            "SELECT COALESCE(MAX(cardinality(event_times)),0)::bigint
             FROM abuse_challenge_issue_windows WHERE actor_key=ANY($1)",
        )
        .bind(&issue_keys)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(
            seeded_issue_count,
            i64::try_from(MAX_CHALLENGE_ISSUES_PER_IP_WINDOW).unwrap()
        );
        let challenge_count_before: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM abuse_pow_challenges")
                .fetch_one(&pool)
                .await
                .unwrap();
        let error = restarted
            .issue(
                AbuseAction::Registration,
                "registration:issue-window-overflow",
                &window_actors,
            )
            .await
            .unwrap_err();
        let capacity = error
            .downcast_ref::<ChallengeCapacityExceeded>()
            .expect("issue-window overflow must be typed");
        assert!((1..=60).contains(&capacity.retry_after_seconds()));
        let challenge_count_after: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM abuse_pow_challenges")
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(challenge_count_after, challenge_count_before);

        let active_count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM abuse_pow_challenges WHERE expires_at > clock_timestamp()",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        let fill_count = i64::try_from(MAX_ACTIVE_POW_CHALLENGES_GLOBAL).unwrap() - active_count;
        let marker = Uuid::new_v4().simple().to_string();
        sqlx::query(
            "INSERT INTO abuse_pow_challenges(
                 id,action,subject_hash,key_id,prefix,work_factor,not_before,
                 expires_at,actor_sequences,requirement,capacity_actor_keys
             )
             SELECT md5($1 || value::text)::uuid,'login',int8send(value),$1,
                    $1 || value::text,1,clock_timestamp(),
                    clock_timestamp()+INTERVAL '2 minutes','{}'::jsonb,'{}'::jsonb,'{}'::text[]
             FROM generate_series(1,$2) AS value",
        )
        .bind(&marker)
        .bind(fill_count)
        .execute(&pool)
        .await
        .unwrap();
        let error = restarted
            .issue(
                AbuseAction::Registration,
                "registration:global-overflow",
                &["ip:192.0.2.250".to_owned()],
            )
            .await
            .unwrap_err();
        assert!(error.downcast_ref::<ChallengeCapacityExceeded>().is_some());
        assert_eq!(
            sqlx::query_scalar::<_, i64>(
                "SELECT COUNT(*) FROM abuse_pow_challenges WHERE expires_at > clock_timestamp()",
            )
            .fetch_one(&pool)
            .await
            .unwrap(),
            i64::try_from(MAX_ACTIVE_POW_CHALLENGES_GLOBAL).unwrap()
        );

        let persisted_capacity_keys: Vec<String> = sqlx::query_scalar(
            "SELECT UNNEST(capacity_actor_keys) FROM abuse_pow_challenges
             WHERE cardinality(capacity_actor_keys) > 0 LIMIT 32",
        )
        .fetch_all(&pool)
        .await
        .unwrap();
        assert!(persisted_capacity_keys
            .iter()
            .all(|key| { !key.contains(&account_actor) && !key.contains("198.51.100") }));

        // This test deliberately fills the process-wide challenge ceiling.
        // The WSL invariant suite runs several PostgreSQL tests in one
        // isolated schema, so retain only pre-existing fixture rows and remove
        // every challenge created here before the next test process starts.
        let cleaned = sqlx::query(
            "DELETE FROM abuse_pow_challenges
             WHERE id=ANY($1) OR key_id=$2",
        )
        .bind(&issued_challenge_ids)
        .bind(&marker)
        .execute(&pool)
        .await
        .unwrap();
        let expected_cleaned =
            u64::try_from(issued_challenge_ids.len()).unwrap() + u64::try_from(fill_count).unwrap();
        assert_eq!(cleaned.rows_affected(), expected_cleaned);

        pool.close().await;
    }

    #[tokio::test]
    #[ignore = "requires an isolated TEST_DATABASE_URL PostgreSQL database"]
    async fn postgres_message_admission_is_crash_atomic_fenced_and_rotation_safe() {
        let url = std::env::var("TEST_DATABASE_URL")
            .expect("set TEST_DATABASE_URL to an isolated PostgreSQL database");
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(32)
            .connect(&url)
            .await
            .unwrap();
        crate::db::migrate(&pool).await.unwrap();
        let marker = Uuid::new_v4();
        let username = format!("msgpow{}", &marker.simple().to_string()[..16]);
        let user = crate::db::create_user(
            &pool,
            &username,
            "message-admission-test-password-42",
            false,
            true,
            crate::auth::MIN_SCRAM_ITERATIONS,
            false,
        )
        .await
        .unwrap();
        let config = AbuseConfig {
            base_work_factor: 2,
            max_work_factor: 4_096,
            window: Duration::from_secs(60),
            cooldown_step: Duration::from_secs(60),
            max_wait: Duration::from_secs(8),
            message_free_burst: 60,
            approximate_max_device_seconds: 8,
        };
        let old_secret = b"message-admission-old-secret-00000001";
        let guard = std::sync::Arc::new(AbuseGuard::new_persistent(
            config,
            pool.clone(),
            Some(old_secret),
            None,
        ));
        let account = format!("{username}@example.test");
        let target = "bob@example.test".to_owned();
        let origin = format!("origin-{marker}");
        let payload = format!(
            "<message to='{target}' type='chat'><body>atomic</body><origin-id xmlns='urn:xmpp:sid:0' id='{origin}'/></message>"
        );
        let actors = vec![
            "ip:198.51.100.81".to_owned(),
            format!("user:{}", user.id),
            format!("behavior:{}", user.id),
        ];
        let subject = format!("message:{}", user.id);
        let challenge = guard
            .issue(AbuseAction::Message, &subject, &actors)
            .await
            .unwrap();
        let proof = solve(&challenge);

        let mut tasks = Vec::new();
        for _ in 0..24 {
            let guard = std::sync::Arc::clone(&guard);
            let account = account.clone();
            let target = target.clone();
            let origin = origin.clone();
            let payload = payload.clone();
            let actors = actors.clone();
            let subject = subject.clone();
            let proof = proof.clone();
            tasks.push(tokio::spawn(async move {
                guard
                    .begin_message_admission(&MessageAdmissionRequest {
                        actor_id: user.id,
                        account_bare: &account,
                        normalized_target: &target,
                        origin_id: Some(&origin),
                        normalized_payload: &payload,
                        pow_intent_payload: &payload,
                        subject: &subject,
                        actors: &actors,
                        proof: Some(&proof),
                    })
                    .await
                    .unwrap()
            }));
        }
        let mut first_lease = None;
        let mut proceeded = 0;
        let mut in_progress = 0;
        for task in tasks {
            match task.await.unwrap() {
                MessageAdmissionStart::Proceed {
                    lease: Some(lease), ..
                } => {
                    proceeded += 1;
                    first_lease = Some(lease);
                }
                MessageAdmissionStart::InProgress { requirement } => {
                    assert!((1..=MESSAGE_ADMISSION_LEASE.as_secs())
                        .contains(&requirement.retry_after_seconds));
                    in_progress += 1;
                }
                other => panic!("unexpected concurrent message admission outcome: {other:?}"),
            }
        }
        assert_eq!(proceeded, 1);
        assert_eq!(in_progress, 23);
        let first_lease = first_lease.unwrap();
        assert_eq!(
            sqlx::query_scalar::<_, i64>(
                "SELECT COUNT(*) FROM abuse_message_admissions WHERE actor_id=$1",
            )
            .bind(user.id)
            .fetch_one(&pool)
            .await
            .unwrap(),
            1
        );
        assert_eq!(
            sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM abuse_pow_challenges WHERE id=$1",)
                .bind(proof.challenge_id)
                .fetch_one(&pool)
                .await
                .unwrap(),
            0
        );
        let actor_keys = actor_state_keys(AbuseAction::Message, &actors, &guard.actor_key_secret);
        let sequences: Vec<i64> = sqlx::query_scalar(
            "SELECT sequence FROM abuse_actor_states WHERE state_key=ANY($1) ORDER BY state_key",
        )
        .bind(&actor_keys)
        .fetch_all(&pool)
        .await
        .unwrap();
        assert_eq!(sequences, vec![1; actor_keys.len()]);

        // Simulate a process crash after the proof/actor/pending commit. The
        // restarted worker may take over only after the fencing lease expires,
        // and it must not advance any actor a second time.
        sqlx::query(
            "UPDATE abuse_message_admissions
             SET lease_expires_at=created_at
             WHERE actor_id=$1",
        )
        .bind(user.id)
        .execute(&pool)
        .await
        .unwrap();
        let restarted = AbuseGuard::new_persistent(config, pool.clone(), Some(old_secret), None);
        let takeover = restarted
            .begin_message_admission(&MessageAdmissionRequest {
                actor_id: user.id,
                account_bare: &account,
                normalized_target: &target,
                origin_id: Some(&origin),
                normalized_payload: &payload,
                pow_intent_payload: &payload,
                subject: &subject,
                actors: &actors,
                proof: Some(&proof),
            })
            .await
            .unwrap();
        let takeover_lease = match takeover {
            MessageAdmissionStart::Proceed {
                lease: Some(lease), ..
            } => lease,
            other => panic!("expired pending admission was not resumed: {other:?}"),
        };
        let resumed_sequences: Vec<i64> = sqlx::query_scalar(
            "SELECT sequence FROM abuse_actor_states WHERE state_key=ANY($1) ORDER BY state_key",
        )
        .bind(&actor_keys)
        .fetch_all(&pool)
        .await
        .unwrap();
        assert_eq!(resumed_sequences, sequences);
        assert!(restarted
            .accept_message_admission(&first_lease)
            .await
            .is_err());
        restarted
            .accept_message_admission(&takeover_lease)
            .await
            .unwrap();
        assert!(matches!(
            restarted
                .begin_message_admission(&MessageAdmissionRequest {
                    actor_id: user.id,
                    account_bare: &account,
                    normalized_target: &target,
                    origin_id: Some(&origin),
                    normalized_payload: &payload,
                    pow_intent_payload: &payload,
                    subject: &subject,
                    actors: &actors,
                    proof: Some(&proof),
                })
                .await
                .unwrap(),
            MessageAdmissionStart::ReplayAccepted
        ));
        let conflicting_payload = payload.replace("atomic", "different");
        assert!(matches!(
            restarted
                .begin_message_admission(&MessageAdmissionRequest {
                    actor_id: user.id,
                    account_bare: &account,
                    normalized_target: &target,
                    origin_id: Some(&origin),
                    normalized_payload: &conflicting_payload,
                    pow_intent_payload: &conflicting_payload,
                    subject: &subject,
                    actors: &actors,
                    proof: Some(&proof),
                })
                .await
                .unwrap(),
            MessageAdmissionStart::Conflict
        ));

        // A capacity rejection happens after transactional proof verification,
        // but rolls the proof deletion and actor update back together.
        let rollback_origin = format!("rollback-{marker}");
        let rollback_payload = format!(
            "<message to='{target}'><body>rollback</body><origin-id xmlns='urn:xmpp:sid:0' id='{rollback_origin}'/></message>"
        );
        let rollback_challenge = restarted
            .issue(AbuseAction::Message, &subject, &actors)
            .await
            .unwrap();
        let rollback_proof = solve(&rollback_challenge);
        let rollback_request = MessageAdmissionRequest {
            actor_id: user.id,
            account_bare: &account,
            normalized_target: &target,
            origin_id: Some(&rollback_origin),
            normalized_payload: &rollback_payload,
            pow_intent_payload: &rollback_payload,
            subject: &subject,
            actors: &actors,
            proof: Some(&rollback_proof),
        };
        let (rollback_key, _) = message_admission_material(
            &rollback_request,
            &restarted.actor_key_secret,
            b"origin-id",
            rollback_origin.as_bytes(),
        );
        let rollback_shard = message_admission_capacity_shard(&rollback_key);
        sqlx::query("UPDATE abuse_message_admission_capacity SET active_records=$2 WHERE shard=$1")
            .bind(rollback_shard)
            .bind(MAX_ACTIVE_MESSAGE_ADMISSIONS_PER_SHARD)
            .execute(&pool)
            .await
            .unwrap();
        let sequence_before_rollback: i64 = sqlx::query_scalar(
            "SELECT MAX(sequence) FROM abuse_actor_states WHERE state_key=ANY($1)",
        )
        .bind(&actor_keys)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert!(matches!(
            restarted
                .begin_message_admission(&rollback_request)
                .await
                .unwrap(),
            MessageAdmissionStart::CapacityLimited
        ));
        assert_eq!(
            sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM abuse_pow_challenges WHERE id=$1")
                .bind(rollback_proof.challenge_id)
                .fetch_one(&pool)
                .await
                .unwrap(),
            1
        );
        assert_eq!(
            sqlx::query_scalar::<_, i64>(
                "SELECT MAX(sequence) FROM abuse_actor_states WHERE state_key=ANY($1)",
            )
            .bind(&actor_keys)
            .fetch_one(&pool)
            .await
            .unwrap(),
            sequence_before_rollback
        );
        let actual_shard_count: i32 = sqlx::query_scalar(
            "SELECT COUNT(*)::integer FROM abuse_message_admissions WHERE capacity_shard=$1",
        )
        .bind(rollback_shard)
        .fetch_one(&pool)
        .await
        .unwrap();
        sqlx::query("UPDATE abuse_message_admission_capacity SET active_records=$2 WHERE shard=$1")
            .bind(rollback_shard)
            .bind(actual_shard_count)
            .execute(&pool)
            .await
            .unwrap();

        // A deferred failure fires after INSERT at COMMIT, covering the last
        // crash cut. The challenge, actor sequence, capacity and pending row
        // must all roll back and the exact proof must remain usable.
        let suffix = marker.simple().to_string();
        let function_name = format!("test_message_admission_fail_{suffix}");
        let trigger_name = format!("test_message_admission_trigger_{suffix}");
        sqlx::query(&format!(
            "CREATE FUNCTION {function_name}() RETURNS TRIGGER AS $$
             BEGIN RAISE EXCEPTION 'injected message admission commit failure'; END;
             $$ LANGUAGE plpgsql"
        ))
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query(&format!(
            "CREATE CONSTRAINT TRIGGER {trigger_name}
             AFTER INSERT ON abuse_message_admissions
             DEFERRABLE INITIALLY DEFERRED FOR EACH ROW
             EXECUTE FUNCTION {function_name}()"
        ))
        .execute(&pool)
        .await
        .unwrap();
        assert!(restarted
            .begin_message_admission(&rollback_request)
            .await
            .is_err());
        assert_eq!(
            sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM abuse_pow_challenges WHERE id=$1")
                .bind(rollback_proof.challenge_id)
                .fetch_one(&pool)
                .await
                .unwrap(),
            1
        );
        assert_eq!(
            sqlx::query_scalar::<_, i64>(
                "SELECT COUNT(*) FROM abuse_message_admissions WHERE admission_key=$1",
            )
            .bind(&rollback_key)
            .fetch_one(&pool)
            .await
            .unwrap(),
            0
        );
        assert_eq!(
            sqlx::query_scalar::<_, i64>(
                "SELECT MAX(sequence) FROM abuse_actor_states WHERE state_key=ANY($1)",
            )
            .bind(&actor_keys)
            .fetch_one(&pool)
            .await
            .unwrap(),
            sequence_before_rollback
        );
        sqlx::query(&format!(
            "DROP TRIGGER {trigger_name} ON abuse_message_admissions"
        ))
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query(&format!("DROP FUNCTION {function_name}()"))
            .execute(&pool)
            .await
            .unwrap();
        assert!(matches!(
            restarted
                .begin_message_admission(&rollback_request)
                .await
                .unwrap(),
            MessageAdmissionStart::Proceed { lease: Some(_), .. }
        ));

        let new_secret = b"message-admission-new-secret-00000002";
        let rotated = AbuseGuard::new_persistent_for_deployment(
            config,
            pool.clone(),
            Some(new_secret),
            Some(old_secret),
            true,
            Some(chrono::DateTime::<chrono::Utc>::MAX_UTC),
        );
        assert!(matches!(
            rotated
                .begin_message_admission(&MessageAdmissionRequest {
                    actor_id: user.id,
                    account_bare: &account,
                    normalized_target: &target,
                    origin_id: Some(&origin),
                    normalized_payload: &payload,
                    pow_intent_payload: &payload,
                    subject: &subject,
                    actors: &actors,
                    proof: Some(&proof),
                })
                .await
                .unwrap(),
            MessageAdmissionStart::ReplayAccepted
        ));

        // A fresh admission created by a dual-key overlap node remains fully
        // interoperable with an old-only node. The admission and its offline
        // dedupe projection are both written under the old primary key; the
        // new key is retained only as a verification candidate.
        let rotation_origin = format!("rotation-{marker}");
        let rotation_payload = format!(
            "<message to='{target}' type='chat'><body>rotation</body><origin-id xmlns='urn:xmpp:sid:0' id='{rotation_origin}'/></message>"
        );
        let rotation_challenge = rotated
            .issue(AbuseAction::Message, &subject, &actors)
            .await
            .unwrap();
        let rotation_proof = solve(&rotation_challenge);
        let rotation_request = MessageAdmissionRequest {
            actor_id: user.id,
            account_bare: &account,
            normalized_target: &target,
            origin_id: Some(&rotation_origin),
            normalized_payload: &rotation_payload,
            pow_intent_payload: &rotation_payload,
            subject: &subject,
            actors: &actors,
            proof: Some(&rotation_proof),
        };
        let rotation_lease = match rotated
            .begin_message_admission(&rotation_request)
            .await
            .unwrap()
        {
            MessageAdmissionStart::Proceed {
                lease: Some(lease), ..
            } => lease,
            other => panic!("overlap admission was not accepted: {other:?}"),
        };
        assert_eq!(
            rotation_lease.offline_dedupe.candidates[0].key_id,
            restarted.actor_key_id
        );
        assert_eq!(
            rotation_lease.offline_dedupe.candidates[1].key_id,
            rotated.actor_key_id
        );
        let stored_admission_key_id: String = sqlx::query_scalar(
            "SELECT key_id FROM abuse_message_admissions WHERE admission_key=$1",
        )
        .bind(&rotation_lease.admission_key)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(stored_admission_key_id, restarted.actor_key_id);

        let offline_policy = crate::db::OfflineStorePolicy {
            max_messages: 100,
            max_bytes: 1_048_576,
            ttl_days: 30,
            mam_backed: false,
        };
        assert_eq!(
            crate::db::store_offline_idempotent(
                &pool,
                user.id,
                &account,
                &rotation_payload,
                true,
                offline_policy,
                Some(&rotation_lease.offline_dedupe),
            )
            .await
            .unwrap(),
            crate::db::OfflineStoreOutcome::Stored
        );
        let stored_offline_key_id: String = sqlx::query_scalar(
            "SELECT payload_key_id FROM offline_message_admissions WHERE identity_digest=$1",
        )
        .bind(&rotation_lease.offline_dedupe.identity_digest)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(stored_offline_key_id, restarted.actor_key_id);

        let (identity_kind, identity_value) =
            message_admission_identity(&rotation_request).unwrap();
        let (_, old_payload_mac) = message_admission_material(
            &rotation_request,
            &restarted.actor_key_secret,
            identity_kind,
            &identity_value,
        );
        let old_only_dedupe = MessageDedupeIdentity {
            identity_digest: message_admission_identity_digest(
                &rotation_request,
                identity_kind,
                &identity_value,
            ),
            candidates: vec![MessageDedupeCandidate {
                key_id: restarted.actor_key_id.clone(),
                payload_mac: old_payload_mac,
            }],
        };
        assert_eq!(
            crate::db::store_offline_idempotent(
                &pool,
                user.id,
                &account,
                &rotation_payload,
                true,
                offline_policy,
                Some(&old_only_dedupe),
            )
            .await
            .unwrap(),
            crate::db::OfflineStoreOutcome::Replay
        );
        rotated
            .accept_message_admission(&rotation_lease)
            .await
            .unwrap();
        assert!(matches!(
            restarted
                .begin_message_admission(&rotation_request)
                .await
                .unwrap(),
            MessageAdmissionStart::ReplayAccepted
        ));

        let over_rotated = AbuseGuard::new_persistent(
            config,
            pool.clone(),
            Some(b"message-admission-third-secret-000003"),
            None,
        );
        assert!(matches!(
            over_rotated
                .begin_message_admission(&MessageAdmissionRequest {
                    actor_id: user.id,
                    account_bare: &account,
                    normalized_target: &target,
                    origin_id: Some(&origin),
                    normalized_payload: &payload,
                    pow_intent_payload: &payload,
                    subject: &subject,
                    actors: &actors,
                    proof: Some(&proof),
                })
                .await
                .unwrap(),
            MessageAdmissionStart::Denied(_)
        ));

        sqlx::query("DELETE FROM users WHERE id=$1")
            .bind(user.id)
            .execute(&pool)
            .await
            .unwrap();
        pool.close().await;
    }

    #[tokio::test]
    #[ignore = "requires an isolated TEST_DATABASE_URL PostgreSQL database"]
    async fn postgres_message_admission_capacity_and_cleanup_are_bounded() {
        let url = std::env::var("TEST_DATABASE_URL")
            .expect("set TEST_DATABASE_URL to an isolated PostgreSQL database");
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(16)
            .connect(&url)
            .await
            .unwrap();
        crate::db::migrate(&pool).await.unwrap();
        let marker = Uuid::new_v4();
        let marker_text = marker.simple().to_string();
        let username = format!("msgcap{}", &marker_text[..16]);
        let user = crate::db::create_user(
            &pool,
            &username,
            "message-capacity-test-password-42",
            false,
            true,
            crate::auth::MIN_SCRAM_ITERATIONS,
            false,
        )
        .await
        .unwrap();
        let config = AbuseConfig {
            base_work_factor: 2,
            max_work_factor: 4_096,
            window: Duration::from_secs(60),
            cooldown_step: Duration::from_secs(60),
            max_wait: Duration::from_secs(8),
            message_free_burst: 60,
            approximate_max_device_seconds: 8,
        };
        let secret = b"message-admission-capacity-secret-0001";
        let guard = AbuseGuard::new_persistent(config, pool.clone(), Some(secret), None);
        let account = format!("{username}@example.test");
        let target = "bob@example.test";
        let actors = vec![format!("user:{}", user.id)];
        let subject = format!("message:{}", user.id);
        let challenge = guard
            .issue(AbuseAction::Message, &subject, &actors)
            .await
            .unwrap();
        let proof = solve(&challenge);
        let payload = "<message to='bob@example.test'><body>capacity</body></message>";

        let mut origins_by_shard = vec![None; usize::from(MESSAGE_ADMISSION_CAPACITY_SHARDS)];
        for index in 0..100_000_u32 {
            let origin = format!("capacity-{marker}-{index}");
            let request = MessageAdmissionRequest {
                actor_id: user.id,
                account_bare: &account,
                normalized_target: target,
                origin_id: Some(&origin),
                normalized_payload: payload,
                pow_intent_payload: payload,
                subject: &subject,
                actors: &actors,
                proof: Some(&proof),
            };
            let (key, _) = message_admission_material(
                &request,
                &guard.actor_key_secret,
                b"origin-id",
                origin.as_bytes(),
            );
            let shard = usize::try_from(message_admission_capacity_shard(&key)).unwrap();
            origins_by_shard[shard].get_or_insert(origin);
            if origins_by_shard.iter().all(Option::is_some) {
                break;
            }
        }
        assert!(origins_by_shard.iter().all(Option::is_some));
        for (shard, origin) in origins_by_shard.iter().enumerate() {
            let shard = i16::try_from(shard).unwrap();
            let actual: i32 = sqlx::query_scalar(
                "SELECT COUNT(*)::integer FROM abuse_message_admissions WHERE capacity_shard=$1",
            )
            .bind(shard)
            .fetch_one(&pool)
            .await
            .unwrap();
            sqlx::query(
                "UPDATE abuse_message_admission_capacity SET active_records=$2 WHERE shard=$1",
            )
            .bind(shard)
            .bind(MAX_ACTIVE_MESSAGE_ADMISSIONS_PER_SHARD)
            .execute(&pool)
            .await
            .unwrap();
            let outcome = guard
                .begin_message_admission(&MessageAdmissionRequest {
                    actor_id: user.id,
                    account_bare: &account,
                    normalized_target: target,
                    origin_id: origin.as_deref(),
                    normalized_payload: payload,
                    pow_intent_payload: payload,
                    subject: &subject,
                    actors: &actors,
                    proof: Some(&proof),
                })
                .await
                .unwrap();
            assert!(matches!(outcome, MessageAdmissionStart::CapacityLimited));
            sqlx::query(
                "UPDATE abuse_message_admission_capacity SET active_records=$2 WHERE shard=$1",
            )
            .bind(shard)
            .bind(actual)
            .execute(&pool)
            .await
            .unwrap();
        }
        assert_eq!(
            sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM abuse_pow_challenges WHERE id=$1")
                .bind(proof.challenge_id)
                .fetch_one(&pool)
                .await
                .unwrap(),
            1,
            "every full-shard rejection must roll the proof back"
        );
        let first_origin = origins_by_shard[0].as_deref().unwrap();
        assert!(matches!(
            guard
                .begin_message_admission(&MessageAdmissionRequest {
                    actor_id: user.id,
                    account_bare: &account,
                    normalized_target: target,
                    origin_id: Some(first_origin),
                    normalized_payload: payload,
                    pow_intent_payload: payload,
                    subject: &subject,
                    actors: &actors,
                    proof: Some(&proof),
                })
                .await
                .unwrap(),
            MessageAdmissionStart::Proceed { lease: Some(_), .. }
        ));

        // Fill the per-account boundary in one set-based transaction. The
        // counter update and fixture rows mirror the production reservation;
        // trigger-backed deletion later proves exact capacity release.
        let existing_for_user: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM abuse_message_admissions WHERE actor_id=$1")
                .bind(user.id)
                .fetch_one(&pool)
                .await
                .unwrap();
        let fixture_count = MAX_ACTIVE_MESSAGE_ADMISSIONS_PER_USER - existing_for_user;
        let fixture_shard = 63_i16;
        let mut fixture_tx = pool.begin().await.unwrap();
        sqlx::query(
            "UPDATE abuse_message_admission_capacity
             SET active_records=active_records+$2 WHERE shard=$1",
        )
        .bind(fixture_shard)
        .bind(i32::try_from(fixture_count).unwrap())
        .execute(&mut *fixture_tx)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO abuse_message_admissions
             (admission_key,key_id,actor_id,capacity_shard,payload_mac,state,
              lease_token,lease_expires_at,expires_at)
             SELECT decode(md5($1 || value::text) || md5('key:' || $1 || value::text),'hex'),
                    'capacity-fixture',$2,$3,
                    decode(md5('payload:' || $1 || value::text) || md5('mac:' || $1 || value::text),'hex'),
                    'pending',
                    ('10000000-0000-4000-8000-' || lpad(value::text,12,'0'))::uuid,
                    clock_timestamp()+INTERVAL '10 minutes',
                    clock_timestamp()+INTERVAL '20 minutes'
             FROM generate_series(1,$4::integer) AS value",
        )
        .bind(&marker_text)
        .bind(user.id)
        .bind(fixture_shard)
        .bind(i32::try_from(fixture_count).unwrap())
        .execute(&mut *fixture_tx)
        .await
        .unwrap();
        fixture_tx.commit().await.unwrap();
        let overflow_origin = format!("user-overflow-{marker}");
        let overflow_challenge = guard
            .issue(AbuseAction::Message, &subject, &actors)
            .await
            .unwrap();
        let overflow_proof = solve(&overflow_challenge);
        let overflow_request = MessageAdmissionRequest {
            actor_id: user.id,
            account_bare: &account,
            normalized_target: target,
            origin_id: Some(&overflow_origin),
            normalized_payload: payload,
            pow_intent_payload: payload,
            subject: &subject,
            actors: &actors,
            proof: Some(&overflow_proof),
        };
        assert!(matches!(
            guard
                .begin_message_admission(&overflow_request)
                .await
                .unwrap(),
            MessageAdmissionStart::CapacityLimited
        ));
        assert_eq!(
            sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM abuse_pow_challenges WHERE id=$1")
                .bind(overflow_proof.challenge_id)
                .fetch_one(&pool)
                .await
                .unwrap(),
            1
        );
        sqlx::query("DELETE FROM abuse_message_admissions WHERE key_id='capacity-fixture'")
            .execute(&pool)
            .await
            .unwrap();
        assert!(matches!(
            guard
                .begin_message_admission(&overflow_request)
                .await
                .unwrap(),
            MessageAdmissionStart::Proceed { lease: Some(_), .. }
        ));

        // More expired rows than one maintenance batch leave exactly the
        // bounded remainder. A live row with an active fencing lease is never
        // selected, and capacity counters equal physical rows after both runs.
        let cleanup_shard = 62_i16;
        let expired_count = MESSAGE_ADMISSION_CLEANUP_BATCH + 1;
        let mut cleanup_tx = pool.begin().await.unwrap();
        sqlx::query(
            "UPDATE abuse_message_admission_capacity
             SET active_records=active_records+$2 WHERE shard=$1",
        )
        .bind(cleanup_shard)
        .bind(i32::try_from(expired_count + 1).unwrap())
        .execute(&mut *cleanup_tx)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO abuse_message_admissions
             (admission_key,key_id,actor_id,capacity_shard,payload_mac,state,
              lease_token,lease_expires_at,expires_at)
             SELECT decode(md5('expired:' || $1 || value::text) || md5('expired-key:' || $1 || value::text),'hex'),
                    'cleanup-expired',$2,$3,
                    decode(md5('expired-payload:' || $1 || value::text) || md5('expired-mac:' || $1 || value::text),'hex'),
                    'pending',
                    ('20000000-0000-4000-8000-' || lpad(value::text,12,'0'))::uuid,
                    clock_timestamp()+INTERVAL '10 minutes',
                    clock_timestamp()-INTERVAL '1 second'
             FROM generate_series(1,$4::integer) AS value",
        )
        .bind(&marker_text)
        .bind(user.id)
        .bind(cleanup_shard)
        .bind(i32::try_from(expired_count).unwrap())
        .execute(&mut *cleanup_tx)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO abuse_message_admissions
             (admission_key,key_id,actor_id,capacity_shard,payload_mac,state,
              lease_token,lease_expires_at,expires_at)
             VALUES(decode(md5('active:' || $1) || md5('active-key:' || $1),'hex'),
                    'cleanup-active',$2,$3,
                    decode(md5('active-payload:' || $1) || md5('active-mac:' || $1),'hex'),
                    'pending','30000000-0000-4000-8000-000000000001',
                    clock_timestamp()+INTERVAL '10 minutes',
                    clock_timestamp()+INTERVAL '20 minutes')",
        )
        .bind(&marker_text)
        .bind(user.id)
        .bind(cleanup_shard)
        .execute(&mut *cleanup_tx)
        .await
        .unwrap();
        cleanup_tx.commit().await.unwrap();
        guard.cleanup_challenges().await.unwrap();
        assert_eq!(
            sqlx::query_scalar::<_, i64>(
                "SELECT COUNT(*) FROM abuse_message_admissions WHERE key_id='cleanup-expired'",
            )
            .fetch_one(&pool)
            .await
            .unwrap(),
            1
        );
        assert_eq!(
            sqlx::query_scalar::<_, i64>(
                "SELECT COUNT(*) FROM abuse_message_admissions WHERE key_id='cleanup-active'",
            )
            .fetch_one(&pool)
            .await
            .unwrap(),
            1
        );
        guard.cleanup_challenges().await.unwrap();
        assert_eq!(
            sqlx::query_scalar::<_, i64>(
                "SELECT COUNT(*) FROM abuse_message_admissions WHERE key_id='cleanup-expired'",
            )
            .fetch_one(&pool)
            .await
            .unwrap(),
            0
        );
        let shard_rows: i32 = sqlx::query_scalar(
            "SELECT COUNT(*)::integer FROM abuse_message_admissions WHERE capacity_shard=$1",
        )
        .bind(cleanup_shard)
        .fetch_one(&pool)
        .await
        .unwrap();
        let shard_capacity: i32 = sqlx::query_scalar(
            "SELECT active_records FROM abuse_message_admission_capacity WHERE shard=$1",
        )
        .bind(cleanup_shard)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(shard_capacity, shard_rows);

        sqlx::query("DELETE FROM users WHERE id=$1")
            .bind(user.id)
            .execute(&pool)
            .await
            .unwrap();
        let counters_match: bool = sqlx::query_scalar(
            "SELECT NOT EXISTS(
                 SELECT 1 FROM abuse_message_admission_capacity capacity
                 WHERE capacity.active_records <> (
                     SELECT COUNT(*)::integer FROM abuse_message_admissions admission
                     WHERE admission.capacity_shard=capacity.shard
                 )
             )",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        assert!(counters_match);
        pool.close().await;
    }

    #[tokio::test]
    #[ignore = "requires an isolated TEST_DATABASE_URL PostgreSQL database"]
    async fn postgres_accepts_one_thousand_independent_actor_decisions() {
        let url = std::env::var("TEST_DATABASE_URL")
            .expect("set TEST_DATABASE_URL to an isolated PostgreSQL database");
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(32)
            .connect(&url)
            .await
            .unwrap();
        crate::db::migrate(&pool).await.unwrap();
        let guard = std::sync::Arc::new(AbuseGuard::new_persistent(
            AbuseConfig {
                base_work_factor: 32,
                max_work_factor: 4_096,
                window: Duration::from_secs(60),
                cooldown_step: Duration::from_secs(60),
                max_wait: Duration::from_secs(900),
                message_free_burst: 60,
                approximate_max_device_seconds: 8,
            },
            pool.clone(),
            Some(b"test-only-throughput-key-at-least-32-bytes"),
            None,
        ));
        let marker = Uuid::new_v4();
        let started = Instant::now();
        let mut tasks = Vec::with_capacity(1_000);
        for index in 0..1_000 {
            let guard = std::sync::Arc::clone(&guard);
            let actor = format!("user:{marker}:{index}");
            tasks.push(tokio::spawn(async move {
                guard
                    .verify_or_allow(
                        AbuseAction::Message,
                        &format!("message:{actor}"),
                        std::slice::from_ref(&actor),
                        None,
                    )
                    .await
                    .unwrap()
                    .unwrap();
            }));
        }
        tokio::time::timeout(Duration::from_secs(60), async {
            for task in tasks {
                task.await.unwrap();
            }
        })
        .await
        .expect("1000 independent actor decisions exceeded 60 seconds");
        let elapsed = started.elapsed();
        eprintln!(
            "1000 durable abuse decisions: {:.2}s ({:.0} decisions/s)",
            elapsed.as_secs_f64(),
            1_000_f64 / elapsed.as_secs_f64()
        );
        let state_rows: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM abuse_actor_states WHERE jsonb_array_length(to_jsonb(event_times))=1",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        assert!(state_rows >= 1_000);
        pool.close().await;
    }
}
