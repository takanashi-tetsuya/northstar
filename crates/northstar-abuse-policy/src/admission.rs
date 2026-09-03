use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::time::Duration;
use subtle::ConstantTimeEq;

use crate::config::AbuseConfig;
use crate::cooldown::{
    decay_penalty_level_utc, punish_penalty_and_wait, trim_event_timestamps_utc,
};
use crate::escalation::{
    build_requirement, policy, prefetched_message_challenge_remains_sufficient,
};
use crate::model::{
    AbuseAction, GuardError, MessageAdmissionRequest, MessageDedupeCandidate,
    MessageDedupeIdentity, PowIntent, PowProof, WorkRequirement, MESSAGE_ADMISSION_CAPACITY_SHARDS,
    POW_INTENT_VERSION,
};
use crate::pow::{compute_pow_prefix, subject_hash, verify_pow_nonce};

type HmacSha256 = Hmac<Sha256>;

fn hmac_field(mac: &mut HmacSha256, value: &[u8]) {
    let len_bytes = u64::try_from(value.len()).unwrap_or(u64::MAX).to_be_bytes();
    mac.update(&len_bytes);
    mac.update(value);
}

fn digest_field(digest: &mut Sha256, value: &[u8]) {
    let len_bytes = u64::try_from(value.len()).unwrap_or(u64::MAX).to_be_bytes();
    digest.update(len_bytes);
    digest.update(value);
}

/// Computes the 64-bit advisory lock ID from the message admission key prefix.
pub fn message_admission_lock_id(admission_key: &[u8]) -> i64 {
    i64::from_be_bytes(
        admission_key[..8]
            .try_into()
            .expect("message admission key has at least 8 bytes"),
    )
}

/// Computes the capacity shard (0..64) from byte 8 of the admission key.
pub fn message_admission_capacity_shard(admission_key: &[u8]) -> i16 {
    i16::from(admission_key[8] % MESSAGE_ADMISSION_CAPACITY_SHARDS)
}

/// Stable SHA-256 digest lookup key for the offline delivery deduplication tombstone.
pub fn message_admission_identity_digest(
    account_bare: &str,
    normalized_target: &str,
    identity_kind: &[u8],
    identity_value: &[u8],
) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(b"northstar/offline-message-identity/v1\0");
    digest_field(&mut digest, AbuseAction::Message.as_str().as_bytes());
    digest_field(&mut digest, account_bare.as_bytes());
    digest_field(&mut digest, normalized_target.as_bytes());
    digest_field(&mut digest, identity_kind);
    digest_field(&mut digest, identity_value);
    digest.finalize().into()
}

/// Computes the keyed admission lookup key and payload MAC for durable deduplication.
pub fn message_admission_material(
    account_bare: &str,
    normalized_target: &str,
    identity_kind: &[u8],
    identity_value: &[u8],
    normalized_payload: &str,
    secret: &[u8],
) -> ([u8; 32], [u8; 32]) {
    let mut key_mac =
        HmacSha256::new_from_slice(secret).expect("HMAC accepts arbitrary key length");
    key_mac.update(b"northstar/message-admission/key/v1\0");
    hmac_field(&mut key_mac, AbuseAction::Message.as_str().as_bytes());
    hmac_field(&mut key_mac, account_bare.as_bytes());
    hmac_field(&mut key_mac, normalized_target.as_bytes());
    hmac_field(&mut key_mac, identity_kind);
    hmac_field(&mut key_mac, identity_value);
    let admission_key: [u8; 32] = key_mac.finalize().into_bytes().into();

    let payload_hash = Sha256::digest(normalized_payload.as_bytes());
    let mut payload_mac =
        HmacSha256::new_from_slice(secret).expect("HMAC accepts arbitrary key length");
    payload_mac.update(b"northstar/message-admission/payload/v1\0");
    hmac_field(&mut payload_mac, AbuseAction::Message.as_str().as_bytes());
    hmac_field(&mut payload_mac, account_bare.as_bytes());
    hmac_field(&mut payload_mac, normalized_target.as_bytes());
    hmac_field(&mut payload_mac, identity_kind);
    hmac_field(&mut payload_mac, identity_value);
    hmac_field(&mut payload_mac, payload_hash.as_slice());
    let payload_mac: [u8; 32] = payload_mac.finalize().into_bytes().into();

    (admission_key, payload_mac)
}

/// Resolves message admission identity tuple `(kind, value)` from request.
pub fn resolve_message_admission_identity<'a>(
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

/// Builds offline dedupe identity across key rotation candidates.
pub fn build_message_dedupe_identity(
    account_bare: &str,
    normalized_target: &str,
    identity_kind: &[u8],
    identity_value: &[u8],
    normalized_payload: &str,
    key_candidates: &[(&str, &[u8])],
) -> MessageDedupeIdentity {
    let identity_digest = message_admission_identity_digest(
        account_bare,
        normalized_target,
        identity_kind,
        identity_value,
    )
    .to_vec();

    let candidates = key_candidates
        .iter()
        .map(|(key_id, secret)| {
            let (_, payload_mac) = message_admission_material(
                account_bare,
                normalized_target,
                identity_kind,
                identity_value,
                normalized_payload,
                secret,
            );
            MessageDedupeCandidate {
                key_id: (*key_id).to_owned(),
                payload_mac: payload_mac.to_vec(),
            }
        })
        .collect();

    MessageDedupeIdentity {
        identity_digest,
        candidates,
    }
}

/// Pure snapshot representation of persistent or in-memory actor state.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ActorStateSnapshot {
    pub state_key: String,
    pub events: Vec<chrono::DateTime<chrono::Utc>>,
    pub penalty_level: u32,
    pub last_activity: chrono::DateTime<chrono::Utc>,
    pub blocked_until: chrono::DateTime<chrono::Utc>,
    pub sequence: i64,
}

impl ActorStateSnapshot {
    pub fn new(state_key: String, now: chrono::DateTime<chrono::Utc>) -> Self {
        Self {
            state_key,
            events: Vec::new(),
            penalty_level: 0,
            last_activity: now,
            blocked_until: now,
            sequence: 0,
        }
    }
}

/// Pure state decay applied to an actor snapshot with an injected timestamp.
pub fn decay_actor_state_snapshot(
    state: &mut ActorStateSnapshot,
    now: chrono::DateTime<chrono::Utc>,
    config: &AbuseConfig,
) {
    trim_event_timestamps_utc(&mut state.events, now, config.window);
    let (new_level, new_activity) = decay_penalty_level_utc(
        state.penalty_level,
        state.last_activity,
        now,
        config.cooldown_step,
    );
    state.penalty_level = new_level;
    state.last_activity = new_activity;
}

/// Pure state update on successful operation admission.
pub fn record_success_in_snapshot(
    state: &mut ActorStateSnapshot,
    now: chrono::DateTime<chrono::Utc>,
    hard_wait_seconds: u64,
    is_shared_ip: bool,
) {
    state.events.push(now);
    state.sequence = state.sequence.saturating_add(1);
    state.last_activity = now;
    if hard_wait_seconds > 0 && !is_shared_ip {
        let wait_secs = i64::try_from(hard_wait_seconds).unwrap_or(i64::MAX);
        state.blocked_until = now + chrono::Duration::seconds(wait_secs);
    }
}

/// Pure state update on operation failure or malicious submission (punish).
pub fn record_failure_in_snapshot(
    state: &mut ActorStateSnapshot,
    now: chrono::DateTime<chrono::Utc>,
    max_wait: Duration,
    is_shared_ip: bool,
) {
    state.events.push(now);
    state.sequence = state.sequence.saturating_add(1);
    state.last_activity = now;
    if is_shared_ip {
        return;
    }
    let (new_penalty, wait) = punish_penalty_and_wait(state.penalty_level, max_wait);
    state.penalty_level = new_penalty;
    let wait_secs = i64::try_from(wait.as_secs()).unwrap_or(i64::MAX);
    state.blocked_until = now + chrono::Duration::seconds(wait_secs);
}

/// Merges state from a previous key generation into a newly rotated state row.
pub fn merge_previous_actor_snapshot(
    old_state: &ActorStateSnapshot,
    new_state: &mut ActorStateSnapshot,
) {
    if new_state.sequence >= old_state.sequence {
        return;
    }
    new_state.events = old_state.events.clone();
    new_state.penalty_level = old_state.penalty_level;
    new_state.last_activity = old_state.last_activity;
    new_state.blocked_until = old_state.blocked_until;
    new_state.sequence = old_state.sequence;
}

/// Calculates the dynamic work requirement from a set of loaded actor snapshots.
pub fn requirement_from_snapshots(
    action: AbuseAction,
    states: &[ActorStateSnapshot],
    shared_ip_keys: &HashSet<String>,
    now: chrono::DateTime<chrono::Utc>,
    config: &AbuseConfig,
) -> WorkRequirement {
    let p = policy(action, config.base_work_factor, config.message_free_burst);

    let event_count = states
        .iter()
        .map(|state| {
            if shared_ip_keys.contains(&state.state_key) {
                // High-volume NAT signal: 20x higher threshold
                state.events.len() / 20
            } else {
                state.events.len()
            }
        })
        .max()
        .unwrap_or(0);

    let penalty = states
        .iter()
        .filter(|state| !shared_ip_keys.contains(&state.state_key))
        .map(|state| state.penalty_level)
        .max()
        .unwrap_or(0);

    let retry_after = states
        .iter()
        .filter(|state| !shared_ip_keys.contains(&state.state_key))
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

    build_requirement(action, p, event_count, penalty, retry_after, config)
}

/// Pure challenge verification and admission decision.
#[allow(clippy::too_many_arguments)]
pub fn evaluate_challenge_proof(
    action: AbuseAction,
    subject: &str,
    actors: &[String],
    proof: Option<&PowProof>,
    intent: Option<&PowIntent>,
    current_requirement: &WorkRequirement,
    challenge_meta: Option<&ChallengeVerificationContext>,
    legacy_v1_allowed: bool,
) -> Result<WorkRequirement, GuardError> {
    // If no work is required, retry delay is 0, and no proof was provided: allow immediately.
    if current_requirement.work_factor <= 1
        && current_requirement.retry_after_seconds == 0
        && proof.is_none()
    {
        return Ok(current_requirement.clone());
    }

    let Some(proof) = proof else {
        return Err(GuardError::Required(current_requirement.clone()));
    };

    let Some(ctx) = challenge_meta else {
        return Err(GuardError::Invalid(
            "proof-of-work challenge is missing or already used",
            current_requirement.clone(),
        ));
    };

    // Protocol version and intent matching
    let intent_matches = if ctx.protocol_version == 1 {
        legacy_v1_allowed
    } else if ctx.protocol_version == POW_INTENT_VERSION {
        match (ctx.intent.as_ref(), intent) {
            (Some(expected), Some(actual)) => expected == actual,
            _ => false,
        }
    } else {
        false
    };

    // Cryptographic prefix and subject verification
    let subject_matches =
        ctx.action == action && ctx.subject_hash == subject_hash(action, subject, ctx.actor_secret);

    let binding_matches = if ctx.protocol_version == POW_INTENT_VERSION {
        let expected_prefix = compute_pow_prefix(
            ctx.actor_secret,
            ctx.protocol_version,
            proof.challenge_id,
            action,
            &ctx.key_id,
            subject,
            actors,
            ctx.work_factor,
            ctx.issued_at,
            ctx.expires_at,
            &ctx.server_nonce,
            intent,
        );
        bool::from(ctx.prefix.as_bytes().ct_eq(expected_prefix.as_bytes()))
    } else {
        ctx.protocol_version == 1
    };

    if !subject_matches || !intent_matches || !binding_matches {
        return Err(GuardError::Invalid(
            "proof-of-work challenge does not match this operation",
            current_requirement.clone(),
        ));
    }

    // Expiry check
    if ctx.now > ctx.expires_at {
        return Err(GuardError::Invalid(
            "proof-of-work challenge expired",
            current_requirement.clone(),
        ));
    }

    // Hard delay check
    if ctx.now < ctx.not_before {
        return Err(GuardError::Invalid(
            "hard cooldown has not finished",
            ctx.requirement.clone(),
        ));
    }

    // Rate limit sequence advance check
    if !ctx.sequences_match
        && !prefetched_message_challenge_remains_sufficient(
            action,
            &ctx.requirement,
            current_requirement,
        )
    {
        return Err(GuardError::Invalid(
            "another operation already advanced this rate-limit step",
            current_requirement.clone(),
        ));
    }

    // PoW nonce difficulty verification
    if verify_pow_nonce(&ctx.prefix, &proof.nonce, ctx.work_factor).is_err() {
        return Err(GuardError::Invalid(
            "proof of work is insufficient",
            current_requirement.clone(),
        ));
    }

    Ok(ctx.requirement.clone())
}

/// Context structure supplied to pure challenge verification.
#[derive(Clone, Debug)]
pub struct ChallengeVerificationContext<'a> {
    pub protocol_version: u16,
    pub action: AbuseAction,
    pub key_id: String,
    pub prefix: String,
    pub work_factor: u64,
    pub issued_at: chrono::DateTime<chrono::Utc>,
    pub expires_at: chrono::DateTime<chrono::Utc>,
    pub not_before: chrono::DateTime<chrono::Utc>,
    pub server_nonce: String,
    pub subject_hash: [u8; 32],
    pub actor_secret: &'a [u8],
    pub intent: Option<PowIntent>,
    pub requirement: WorkRequirement,
    pub sequences_match: bool,
    pub now: chrono::DateTime<chrono::Utc>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn message_admission_material_and_shard_distribution() {
        let secret = b"message-admission-test-secret-0001";
        let (key, payload_mac) = message_admission_material(
            "alice@example.test",
            "bob@example.test",
            b"origin-id",
            b"origin-12345",
            "<message><body>test</body></message>",
            secret,
        );
        assert_eq!(key.len(), 32);
        assert_eq!(payload_mac.len(), 32);

        let shard = message_admission_capacity_shard(&key);
        assert!((0..64).contains(&shard));

        let lock_id = message_admission_lock_id(&key);
        assert_ne!(lock_id, 0);

        let stable_digest = message_admission_identity_digest(
            "alice@example.test",
            "bob@example.test",
            b"origin-id",
            b"origin-12345",
        );
        assert_eq!(stable_digest.len(), 32);
    }

    #[test]
    fn snapshot_state_transitions_and_merging() {
        let now = chrono::DateTime::parse_from_rfc3339("2026-09-02T12:00:00Z")
            .unwrap()
            .with_timezone(&chrono::Utc);
        let config = AbuseConfig::builder().build().unwrap();

        let mut state = ActorStateSnapshot::new("message:user:alice".to_owned(), now);
        assert_eq!(state.sequence, 0);
        assert_eq!(state.penalty_level, 0);

        record_success_in_snapshot(&mut state, now, 0, false);
        assert_eq!(state.sequence, 1);
        assert_eq!(state.events.len(), 1);

        record_failure_in_snapshot(&mut state, now, config.max_wait, false);
        assert_eq!(state.sequence, 2);
        assert_eq!(state.penalty_level, 1);

        // Merge old into new rotated state
        let mut rotated_state = ActorStateSnapshot::new("message:user:alice-new".to_owned(), now);
        merge_previous_actor_snapshot(&state, &mut rotated_state);
        assert_eq!(rotated_state.sequence, 2);
        assert_eq!(rotated_state.penalty_level, 1);
        assert_eq!(rotated_state.events.len(), 2);
    }
}
