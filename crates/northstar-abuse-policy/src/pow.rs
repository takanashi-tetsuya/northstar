use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use thiserror::Error;
use uuid::Uuid;

use crate::model::{
    AbuseAction, ActorDimension, ContentIdentityAuthenticator, ContentIdentityAuthenticators,
    ContentIdentityPurpose, PowIntent,
};

type HmacSha256 = Hmac<Sha256>;

/// Borrowed, already-validated semantic intent commitment used by the
/// cryptographic binding layer. Validation remains the caller's concern;
/// this type deliberately carries no action or transport capabilities.
#[derive(Clone, Copy, Debug)]
pub struct PowIntentCommitment<'a> {
    pub method: &'a str,
    pub path: &'a str,
    pub body_sha256: &'a [u8; 32],
}

impl<'a> From<&'a PowIntent> for PowIntentCommitment<'a> {
    fn from(intent: &'a PowIntent) -> Self {
        Self {
            method: intent.method(),
            path: intent.path(),
            body_sha256: intent.body_sha256(),
        }
    }
}

/// Errors occurring during proof-of-work nonce verification.
#[derive(Clone, Debug, Eq, PartialEq, Error)]
pub enum PowVerifyError {
    #[error("proof-of-work nonce is empty")]
    EmptyNonce,
    #[error("proof-of-work nonce length ({0}) exceeds maximum allowed 64 bytes")]
    NonceTooLong(usize),
    #[error("proof-of-work nonce contains non-ASCII-digit bytes")]
    NonDigitNonce,
    #[error("proof of work is insufficient: digest value {digest_value} > target {target}")]
    InsufficientWork { digest_value: u64, target: u64 },
}

/// Helper to serialize length-prefixed bytes into an HMAC stream.
fn hmac_field(mac: &mut HmacSha256, value: &[u8]) {
    let len_bytes = u64::try_from(value.len()).unwrap_or(u64::MAX).to_be_bytes();
    mac.update(&len_bytes);
    mac.update(value);
}

/// Derives the dedicated actor key secret from the deployment master secret.
pub fn derive_actor_key_secret(master_secret: &[u8]) -> [u8; 32] {
    let mut mac =
        HmacSha256::new_from_slice(master_secret).expect("HMAC accepts arbitrary key lengths");
    mac.update(b"northstar/abuse-actor-key/v1");
    mac.finalize().into_bytes().into()
}

/// Computes the 12-byte unpadded base64url key identifier from an actor secret.
pub fn actor_key_id(secret: &[u8]) -> String {
    let mut digest = Sha256::new();
    digest.update(b"northstar/abuse-key-id/v1\0");
    digest.update(secret);
    URL_SAFE_NO_PAD.encode(&digest.finalize()[..12])
}

/// Computes a deterministic keyed hash over an action and subject string.
pub fn subject_hash(action: AbuseAction, subject: &str, secret: &[u8]) -> [u8; 32] {
    let mut mac = HmacSha256::new_from_slice(secret).expect("HMAC accepts arbitrary key lengths");
    mac.update(b"subject\0");
    mac.update(action.as_str().as_bytes());
    mac.update(b"\0");
    mac.update(subject.as_bytes());
    mac.finalize().into_bytes().into()
}

/// Derives a pseudonymized, opaque state key for a specific actor dimension.
pub fn opaque_actor_key(action: AbuseAction, actor: &str, secret: &[u8]) -> String {
    let dim = ActorDimension::parse(actor);
    let state = dim.canonical_state_key(action);
    let mut mac = HmacSha256::new_from_slice(secret).expect("HMAC accepts arbitrary key lengths");
    mac.update(b"actor\0");
    mac.update(state.as_bytes());
    URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes())
}

/// Derives an opaque challenge capacity tracking key for an actor.
///
/// IP actors share a single namespace across actions to prevent attackers
/// from multiplying storage allowances by cycling action names.
pub fn opaque_challenge_capacity_key(action: AbuseAction, actor: &str, secret: &[u8]) -> String {
    let mut mac = HmacSha256::new_from_slice(secret).expect("HMAC accepts arbitrary key lengths");
    mac.update(b"challenge-capacity\0");
    if actor.starts_with("ip:") {
        mac.update(b"ip\0");
    } else {
        mac.update(action.as_str().as_bytes());
        mac.update(b"\0actor\0");
    }
    mac.update(actor.as_bytes());
    URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes())
}

/// Computes the cryptographic challenge prefix containing the HMAC commitment.
#[allow(clippy::too_many_arguments)]
pub fn compute_pow_prefix(
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
    compute_pow_prefix_with_commitment(
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
        intent.map(PowIntentCommitment::from),
    )
}

/// Computes the challenge prefix from an already-validated borrowed intent.
/// Server adapters with a compatibility wrapper can use this without
/// reconstructing or weakening the policy crate's `PowIntent` validation.
#[allow(clippy::too_many_arguments)]
pub fn compute_pow_prefix_with_commitment(
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
    intent: Option<PowIntentCommitment<'_>>,
) -> String {
    let mut mac = HmacSha256::new_from_slice(secret).expect("HMAC accepts arbitrary key lengths");
    mac.update(b"northstar/pow-challenge/v2\0");
    hmac_field(&mut mac, &version.to_be_bytes());
    hmac_field(&mut mac, id.as_bytes());
    hmac_field(&mut mac, action.as_str().as_bytes());
    hmac_field(&mut mac, key_id.as_bytes());
    hmac_field(&mut mac, subject.as_bytes());

    let mut actors = actors.to_vec();
    actors.sort();
    actors.dedup();
    let actors_len_bytes = u64::try_from(actors.len())
        .unwrap_or(u64::MAX)
        .to_be_bytes();
    mac.update(&actors_len_bytes);
    for actor in actors {
        hmac_field(&mut mac, actor.as_bytes());
    }

    hmac_field(&mut mac, &work_factor.to_be_bytes());
    hmac_field(&mut mac, &issued_at.timestamp_millis().to_be_bytes());
    hmac_field(&mut mac, &expires_at.timestamp_millis().to_be_bytes());
    hmac_field(&mut mac, server_nonce.as_bytes());
    hmac_field(&mut mac, &[u8::from(intent.is_some())]);

    if let Some(intent) = intent {
        hmac_field(&mut mac, intent.method.as_bytes());
        hmac_field(&mut mac, intent.path.as_bytes());
        hmac_field(&mut mac, intent.body_sha256);
    }

    let binding = URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes());
    format!(
        "northstar:v{version}:{id}:{}:{key_id}:{server_nonce}:{binding}:",
        action.as_str()
    )
}

/// Constant-time verification of a candidate PoW challenge prefix.
#[allow(clippy::too_many_arguments)]
pub fn verify_pow_prefix_binding(
    candidate_prefix: &str,
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
) -> bool {
    let expected_prefix = compute_pow_prefix(
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
        intent,
    );
    bool::from(
        candidate_prefix
            .as_bytes()
            .ct_eq(expected_prefix.as_bytes()),
    )
}

/// Verifies that a client-submitted nonce satisfies the SHA-256 target difficulty.
pub fn verify_pow_nonce(prefix: &str, nonce: &str, work_factor: u64) -> Result<(), PowVerifyError> {
    if nonce.is_empty() {
        return Err(PowVerifyError::EmptyNonce);
    }
    if nonce.len() > 64 {
        return Err(PowVerifyError::NonceTooLong(nonce.len()));
    }
    if !nonce.bytes().all(|b| b.is_ascii_digit()) {
        return Err(PowVerifyError::NonDigitNonce);
    }

    let mut hasher = Sha256::new();
    hasher.update(prefix.as_bytes());
    hasher.update(nonce.as_bytes());
    let digest = hasher.finalize();

    let digest_value = u64::from_be_bytes(
        digest[..8]
            .try_into()
            .expect("SHA-256 has at least 8 bytes"),
    );
    let target = u64::MAX / work_factor.max(1);

    if digest_value > target {
        return Err(PowVerifyError::InsufficientWork {
            digest_value,
            target,
        });
    }
    Ok(())
}

/// Derives a purpose-separated subkey from an actor secret for content authentication.
pub fn derive_content_identity_key(
    actor_secret: &[u8],
    purpose: ContentIdentityPurpose,
) -> [u8; 32] {
    let mut mac =
        HmacSha256::new_from_slice(actor_secret).expect("HMAC accepts arbitrary key lengths");
    mac.update(b"northstar/content-identity/subkey/v1\0");
    hmac_field(&mut mac, purpose.label());
    mac.finalize().into_bytes().into()
}

/// Generates a single content identity commitment.
pub fn compute_content_identity_authenticator(
    key_id: &str,
    generation_key: &[u8],
    purpose: ContentIdentityPurpose,
    canonical_payload: &[u8],
) -> ContentIdentityAuthenticator {
    let mut mac =
        HmacSha256::new_from_slice(generation_key).expect("HMAC accepts arbitrary key lengths");
    mac.update(b"northstar/content-identity/mac/v1\0");
    hmac_field(&mut mac, purpose.label());
    hmac_field(&mut mac, canonical_payload);
    ContentIdentityAuthenticator::new(key_id.to_owned(), mac.finalize().into_bytes().into())
}

/// Helper for building authenticators across multiple key generations.
pub fn compute_content_identity_authenticators<'a, I>(
    generations: I,
    purpose: ContentIdentityPurpose,
    canonical_payload: &[u8],
) -> ContentIdentityAuthenticators
where
    I: IntoIterator<Item = (&'a str, &'a [u8])>,
{
    let candidates = generations
        .into_iter()
        .map(|(key_id, key)| {
            compute_content_identity_authenticator(key_id, key, purpose, canonical_payload)
        })
        .collect();
    ContentIdentityAuthenticators::new(candidates)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::POW_INTENT_VERSION;

    fn solve(prefix: &str, work_factor: u64) -> String {
        let target = u64::MAX / work_factor.max(1);
        for nonce in 0_u64.. {
            let nonce_str = nonce.to_string();
            let mut hasher = Sha256::new();
            hasher.update(prefix.as_bytes());
            hasher.update(nonce_str.as_bytes());
            let digest = hasher.finalize();
            let value = u64::from_be_bytes(digest[..8].try_into().unwrap());
            if value <= target {
                return nonce_str;
            }
        }
        unreachable!()
    }

    #[test]
    fn prefix_computation_and_nonce_solving() {
        let secret = b"unit-test-secret-at-least-32-bytes-long";
        let id = Uuid::from_u128(0xa000_0000_0000_4000_8000_0000_0000_0001);
        let key_id = "test-key-id";
        let subject = "report:test-subject";
        let actors = vec!["user:alice".to_owned(), "ip:198.51.100.1".to_owned()];
        let issued_at = chrono::DateTime::parse_from_rfc3339("2026-09-02T12:00:00Z")
            .unwrap()
            .with_timezone(&chrono::Utc);
        let expires_at = issued_at + chrono::Duration::seconds(120);
        let server_nonce = "sample-server-nonce";

        let intent = PowIntent::http_json(
            AbuseAction::Report,
            "/api/v1/reports",
            &serde_json::json!({"reason":"spam"}),
        )
        .unwrap();

        let prefix = compute_pow_prefix(
            secret,
            POW_INTENT_VERSION,
            id,
            AbuseAction::Report,
            key_id,
            subject,
            &actors,
            50,
            issued_at,
            expires_at,
            server_nonce,
            Some(&intent),
        );

        assert!(verify_pow_prefix_binding(
            &prefix,
            secret,
            POW_INTENT_VERSION,
            id,
            AbuseAction::Report,
            key_id,
            subject,
            &actors,
            50,
            issued_at,
            expires_at,
            server_nonce,
            Some(&intent),
        ));

        // Binding verification fails if any parameter is altered
        assert!(!verify_pow_prefix_binding(
            &prefix,
            b"different-secret-000000000000000000",
            POW_INTENT_VERSION,
            id,
            AbuseAction::Report,
            key_id,
            subject,
            &actors,
            50,
            issued_at,
            expires_at,
            server_nonce,
            Some(&intent),
        ));

        // Solve and verify nonce
        let nonce = solve(&prefix, 50);
        assert!(verify_pow_nonce(&prefix, &nonce, 50).is_ok());

        // Incorrect / invalid nonces
        assert!(matches!(
            verify_pow_nonce(&prefix, "", 50),
            Err(PowVerifyError::EmptyNonce)
        ));
        assert!(matches!(
            verify_pow_nonce(&prefix, "not_digits", 50),
            Err(PowVerifyError::NonDigitNonce)
        ));
        assert!(matches!(
            verify_pow_nonce(&prefix, &"1".repeat(65), 50),
            Err(PowVerifyError::NonceTooLong(65))
        ));
    }

    #[test]
    fn content_identity_purpose_separation() {
        let secret = b"content-key-test-secret-at-least-32";
        let payload = b"<message><body>secure content</body></message>";

        let msg_key = derive_content_identity_key(secret, ContentIdentityPurpose::PersonalMessage);
        let ret_key =
            derive_content_identity_key(secret, ContentIdentityPurpose::PersonalRetraction);
        let mix_msg_key = derive_content_identity_key(secret, ContentIdentityPurpose::MixMessage);
        let mix_ret_key =
            derive_content_identity_key(secret, ContentIdentityPurpose::MixRetraction);

        assert_ne!(msg_key, ret_key);
        assert_ne!(msg_key, mix_msg_key);
        assert_ne!(mix_msg_key, mix_ret_key);

        let auth_msg = compute_content_identity_authenticator(
            "gen-1",
            &msg_key,
            ContentIdentityPurpose::PersonalMessage,
            payload,
        );
        let auth_ret = compute_content_identity_authenticator(
            "gen-1",
            &ret_key,
            ContentIdentityPurpose::PersonalRetraction,
            payload,
        );

        assert_ne!(auth_msg.mac(), auth_ret.mac());
        assert!(auth_msg.verifies("gen-1", auth_msg.mac()));
        assert!(!auth_msg.verifies("gen-2", auth_msg.mac()));
        assert!(!auth_msg.verifies("gen-1", auth_ret.mac()));
    }
}
