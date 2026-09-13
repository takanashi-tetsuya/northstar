use anyhow::Result;
use argon2::{
    password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Algorithm, Argon2, Params, Version,
};
use rand::{distributions::Alphanumeric, rngs::OsRng, Rng};
use sha2::{Digest, Sha256};
use std::sync::OnceLock;
use zeroize::Zeroize;

use crate::scram::{
    compute_scram_sha1, compute_scram_sha256, generate_scram_salt, MAX_SCRAM_ITERATIONS,
    MIN_SCRAM_ITERATIONS,
};

// A stored PHC string is database-controlled input. The argon2 crate honors
// the encoded work factors, so accepting its type-level maxima would let a
// corrupt/imported row allocate nearly arbitrary memory or monopolize a
// bounded password worker. These ceilings intentionally exceed Northstar's
// generated Argon2id profile while keeping one verification bounded.
const MAX_STORED_ARGON2_MEMORY_KIB: u32 = 64 * 1_024;
const MAX_STORED_ARGON2_TIME_COST: u32 = 8;
const MAX_STORED_ARGON2_PARALLELISM: u32 = 4;
const STORED_ARGON2_OUTPUT_BYTES: usize = 32;

pub fn normalize_username(value: &str) -> Result<String> {
    // Bound work before Unicode normalization. Protocol stanzas and the REST
    // body have larger outer limits, so checking only the prepared output
    // would let an attacker repeatedly feed very large strings into PRECIS.
    if value.is_empty() || value.len() > 1_024 {
        anyhow::bail!("username input is too large");
    }
    let username = northstar_xmpp_types::prepare_localpart(value)?;
    if username.len() < 3 || username.len() > 64 {
        anyhow::bail!("username must contain 3 to 64 UTF-8 octets");
    }
    Ok(username)
}

pub fn validate_password(value: &str) -> Result<()> {
    if value.len() < 10 || value.len() > 1024 {
        anyhow::bail!("password must contain 10 to 1024 UTF-8 octets");
    }
    Ok(())
}

pub struct PasswordCredentials {
    pub hash: String,
    pub scram_salt: Vec<u8>,
    pub scram_iterations: u32,
    pub scram_stored_key: Vec<u8>,
    pub scram_server_key: Vec<u8>,
    pub scram_sha1_salt: Option<Vec<u8>>,
    pub scram_sha1_stored_key: Option<Vec<u8>>,
    pub scram_sha1_server_key: Option<Vec<u8>>,
}

impl std::fmt::Debug for PasswordCredentials {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PasswordCredentials")
            .field("hash", &"[REDACTED]")
            .field("scram_iterations", &self.scram_iterations)
            .field("scram_sha1_enabled", &self.scram_sha1_salt.is_some())
            .finish_non_exhaustive()
    }
}

impl PasswordCredentials {
    /// Transfer the SHA-256 verifier set without cloning sensitive buffers.
    /// `self` still runs its `Drop` implementation afterwards, zeroizing any
    /// unconsumed compatibility verifier material.
    pub fn into_sha256_parts(mut self) -> (String, u32, Vec<u8>, Vec<u8>, Vec<u8>) {
        (
            std::mem::take(&mut self.hash),
            self.scram_iterations,
            std::mem::take(&mut self.scram_salt),
            std::mem::take(&mut self.scram_stored_key),
            std::mem::take(&mut self.scram_server_key),
        )
    }
}

impl Drop for PasswordCredentials {
    fn drop(&mut self) {
        self.hash.zeroize();
        self.scram_salt.zeroize();
        self.scram_stored_key.zeroize();
        self.scram_server_key.zeroize();
        self.scram_sha1_salt.zeroize();
        self.scram_sha1_stored_key.zeroize();
        self.scram_sha1_server_key.zeroize();
    }
}

pub fn hash_password(
    value: &str,
    validate: bool,
    scram_iterations: u32,
    scram_sha1_enabled: bool,
) -> Result<PasswordCredentials> {
    if !(MIN_SCRAM_ITERATIONS..=MAX_SCRAM_ITERATIONS).contains(&scram_iterations) {
        anyhow::bail!(
            "SCRAM iteration count must be between {MIN_SCRAM_ITERATIONS} and {MAX_SCRAM_ITERATIONS}"
        );
    }
    if validate {
        validate_password(value)?;
    }
    let salt = SaltString::generate(&mut OsRng);
    let hash = Argon2::default()
        .hash_password(value.as_bytes(), &salt)
        .map(|hash| hash.to_string())
        .map_err(|error| anyhow::anyhow!("password hashing failed: {error}"))?;

    let scram_salt = generate_scram_salt();
    let (scram_stored_key, scram_server_key) =
        compute_scram_sha256(value, &scram_salt, scram_iterations);
    let (scram_sha1_salt, scram_sha1_stored_key, scram_sha1_server_key) = if scram_sha1_enabled {
        let salt = generate_scram_salt();
        let (stored_key, server_key) = compute_scram_sha1(value, &salt, scram_iterations);
        (Some(salt), Some(stored_key), Some(server_key))
    } else {
        (None, None, None)
    };

    Ok(PasswordCredentials {
        hash,
        scram_salt,
        scram_iterations,
        scram_stored_key,
        scram_server_key,
        scram_sha1_salt,
        scram_sha1_stored_key,
        scram_sha1_server_key,
    })
}

#[derive(Debug)]
pub struct PasswordVerifierError {
    details: String,
}

impl PasswordVerifierError {
    pub fn new(error: argon2::password_hash::Error) -> Self {
        Self {
            details: error.to_string(),
        }
    }

    pub fn policy(details: &'static str) -> Self {
        Self {
            details: details.to_owned(),
        }
    }
}

impl std::fmt::Display for PasswordVerifierError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "stored Argon2 password verifier is invalid: {}",
            self.details
        )
    }
}

impl std::error::Error for PasswordVerifierError {}

pub fn is_password_verifier_integrity_error(error: &anyhow::Error) -> bool {
    error
        .chain()
        .any(|cause| cause.downcast_ref::<PasswordVerifierError>().is_some())
}

/// Verify an Argon2 PHC value without collapsing malformed/corrupt stored
/// material into an ordinary password mismatch. Callers must expose both
/// cases uniformly to untrusted users while treating `Err` as an observable
/// backend-integrity failure.
pub fn verify_password(
    hash: &str,
    candidate: &str,
) -> std::result::Result<bool, PasswordVerifierError> {
    let parsed = PasswordHash::new(hash).map_err(PasswordVerifierError::new)?;
    if parsed.algorithm != Algorithm::Argon2id.ident() {
        return Err(PasswordVerifierError::policy(
            "algorithm is not the approved Argon2id profile",
        ));
    }
    if parsed.version != Some(u32::from(Version::V0x13)) {
        return Err(PasswordVerifierError::policy(
            "version is not the approved Argon2 v=19 profile",
        ));
    }
    let params = Params::try_from(&parsed).map_err(PasswordVerifierError::new)?;
    if params.m_cost() > MAX_STORED_ARGON2_MEMORY_KIB
        || params.t_cost() > MAX_STORED_ARGON2_TIME_COST
        || params.p_cost() > MAX_STORED_ARGON2_PARALLELISM
    {
        return Err(PasswordVerifierError::policy(
            "work factors exceed the bounded verification policy",
        ));
    }
    if params.output_len() != Some(STORED_ARGON2_OUTPUT_BYTES)
        || !params.keyid().is_empty()
        || !params.data().is_empty()
        || parsed.salt.is_none()
        || parsed.hash.is_none()
    {
        return Err(PasswordVerifierError::policy(
            "parameters do not match the approved stored-verifier shape",
        ));
    }
    match Argon2::default().verify_password(candidate.as_bytes(), &parsed) {
        Ok(()) => Ok(true),
        Err(argon2::password_hash::Error::Password) => Ok(false),
        Err(error) => Err(PasswordVerifierError::new(error)),
    }
}

pub fn verify_against_dummy_hash(
    candidate: &str,
) -> std::result::Result<(), PasswordVerifierError> {
    static DUMMY_HASH: OnceLock<String> = OnceLock::new();
    let hash = DUMMY_HASH.get_or_init(|| {
        let salt = SaltString::generate(&mut OsRng);
        Argon2::default()
            .hash_password(b"northstar-dummy-authentication-secret", &salt)
            .expect("dummy password hashing should succeed")
            .to_string()
    });
    verify_password(hash, candidate).map(|_| ())
}

pub fn new_session_token() -> String {
    rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(64)
        .map(char::from)
        .collect()
}

pub fn token_hash(token: &str) -> Vec<u8> {
    Sha256::digest(token.as_bytes()).to_vec()
}

pub fn constant_time_bytes_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    left.iter()
        .zip(right)
        .fold(0_u8, |difference, (left, right)| {
            difference | (left ^ right)
        })
        == 0
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scram::DEFAULT_SCRAM_ITERATIONS;

    #[test]
    fn password_round_trip() {
        let creds = hash_password(
            "correct horse battery staple",
            true,
            DEFAULT_SCRAM_ITERATIONS,
            true,
        )
        .unwrap();
        assert_eq!(creds.scram_iterations, DEFAULT_SCRAM_ITERATIONS);
        assert!(verify_password(&creds.hash, "correct horse battery staple").unwrap());
        assert!(!verify_password(&creds.hash, "wrong password").unwrap());
        let malformed = verify_password("not-a-phc-verifier", "wrong password").unwrap_err();
        let classified = anyhow::Error::new(malformed);
        assert!(is_password_verifier_integrity_error(&classified));
    }

    #[test]
    fn stored_argon2_work_factors_are_rejected_before_expensive_verification() {
        let credentials = hash_password(
            "correct horse battery staple",
            true,
            DEFAULT_SCRAM_ITERATIONS,
            false,
        )
        .unwrap();
        for oversized in [
            credentials.hash.replacen("m=19456", "m=65537", 1),
            credentials.hash.replacen("t=2", "t=9", 1),
            credentials.hash.replacen("p=1", "p=5", 1),
        ] {
            let error = verify_password(&oversized, "correct horse battery staple").unwrap_err();
            assert!(error.to_string().contains("bounded verification policy"));
        }
    }

    #[test]
    fn password_hashing_rejects_weak_scram_cost() {
        assert!(hash_password("correct horse battery staple", true, 4_095, true).is_err());
    }

    #[test]
    fn password_hashing_omits_sha1_verifier_when_compatibility_is_disabled() {
        let credentials = hash_password(
            "correct horse battery staple",
            true,
            DEFAULT_SCRAM_ITERATIONS,
            false,
        )
        .unwrap();
        assert!(credentials.scram_sha1_salt.is_none());
        assert!(credentials.scram_sha1_stored_key.is_none());
        assert!(credentials.scram_sha1_server_key.is_none());
        let debug = format!("{credentials:?}");
        assert!(debug.contains("[REDACTED]"));
        assert!(!debug.contains("$argon2"));
        assert!(!debug.contains("correct horse battery staple"));
    }

    #[test]
    fn password_validation_enforces_bounds() {
        assert!(validate_password("short").is_err());
        assert!(validate_password("1234567890").is_ok());
        assert!(validate_password(&"a".repeat(1024)).is_ok());
        assert!(validate_password(&"a".repeat(1025)).is_err());
    }

    #[test]
    fn usernames_are_normalized() {
        assert_eq!(normalize_username("Alice_1").unwrap(), "alice_1");
        assert_eq!(normalize_username("A\u{30a}LICE").unwrap(), "\u{e5}lice");
        assert!(normalize_username("bad name").is_err());
        assert!(normalize_username("ali\u{200b}ce").is_err());
        assert!(normalize_username(" Alice_1 ").is_err());
        assert!(normalize_username(&"a".repeat(1_025)).is_err());
    }

    #[test]
    fn dummy_hash_verification_succeeds_without_integrity_error() {
        assert!(verify_against_dummy_hash("any-candidate-password").is_ok());
    }

    #[test]
    fn session_token_and_hash_properties() {
        let token = new_session_token();
        assert_eq!(token.len(), 64);
        let hash1 = token_hash(&token);
        let hash2 = token_hash(&token);
        assert_eq!(hash1, hash2);
        assert_eq!(hash1.len(), 32);
        assert!(constant_time_bytes_eq(&hash1, &hash2));
        assert!(!constant_time_bytes_eq(&hash1, &[0u8; 32]));
        assert!(!constant_time_bytes_eq(&hash1, &[0u8; 16]));
    }

    #[test]
    fn into_sha256_parts_transfers_buffers() {
        let credentials = hash_password(
            "correct horse battery staple",
            true,
            DEFAULT_SCRAM_ITERATIONS,
            true,
        )
        .unwrap();
        let (hash, iters, salt, stored_key, server_key) = credentials.into_sha256_parts();
        assert!(hash.starts_with("$argon2id$"));
        assert_eq!(iters, DEFAULT_SCRAM_ITERATIONS);
        assert_eq!(salt.len(), 32);
        assert_eq!(stored_key.len(), 32);
        assert_eq!(server_key.len(), 32);
    }
}
