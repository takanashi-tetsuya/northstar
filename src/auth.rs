use anyhow::Result;
use argon2::{
    password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Algorithm, Argon2, Params, Version,
};
use base64::{engine::general_purpose::STANDARD, Engine};
use hmac::{Hmac, Mac};
use pbkdf2::pbkdf2;
use rand::{distributions::Alphanumeric, rngs::OsRng, Rng};
use sha1::Sha1;
use sha2::{Digest, Sha256};
use std::sync::OnceLock;
use uuid::Uuid;
use zeroize::{Zeroize, Zeroizing};

pub const MIN_SCRAM_ITERATIONS: u32 = 4_096;
pub const DEFAULT_SCRAM_ITERATIONS: u32 = 600_000;
pub const MAX_SCRAM_ITERATIONS: u32 = 10_000_000;

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
    let username = crate::jid::prepare_localpart(value)?;
    if username.len() < 3 || username.len() > 64 {
        anyhow::bail!("username must contain 3 to 64 UTF-8 octets");
    }
    Ok(username)
}

/// Per-connection channel-binding data.  Neither binding type is inferred from
/// the other: RFC 5929 `tls-server-end-point` is unavailable for certificate
/// signature algorithms such as Ed25519, while RFC 9266 `tls-exporter` is
/// derived from the negotiated TLS connection rather than the certificate.
/// At least one binding must be present before this value is constructed.
#[derive(Clone, Debug)]
pub struct ChannelBindings {
    tls_server_end_point: Option<Vec<u8>>,
    tls_exporter: Option<Vec<u8>>,
}

impl Drop for ChannelBindings {
    fn drop(&mut self) {
        self.tls_server_end_point.zeroize();
        self.tls_exporter.zeroize();
    }
}

impl ChannelBindings {
    #[cfg(test)]
    pub fn new(tls_server_end_point: Vec<u8>, tls_exporter: Option<Vec<u8>>) -> Result<Self> {
        Self::from_available(Some(tls_server_end_point), tls_exporter)?.ok_or_else(|| {
            anyhow::anyhow!("at least one TLS channel-binding type must be available")
        })
    }

    pub fn from_available(
        tls_server_end_point: Option<Vec<u8>>,
        tls_exporter: Option<Vec<u8>>,
    ) -> Result<Option<Self>> {
        if tls_server_end_point
            .as_ref()
            .is_some_and(|value| value.is_empty())
            || tls_exporter.as_ref().is_some_and(|value| value.len() != 32)
        {
            anyhow::bail!("invalid TLS channel-binding data");
        }
        if tls_server_end_point.is_none() && tls_exporter.is_none() {
            return Ok(None);
        }
        Ok(Some(Self {
            tls_server_end_point,
            tls_exporter,
        }))
    }

    pub fn get(&self, kind: &str) -> Option<&[u8]> {
        match kind {
            "tls-server-end-point" => self.tls_server_end_point.as_deref(),
            "tls-exporter" => self.tls_exporter.as_deref(),
            _ => None,
        }
    }

    pub fn feature_xml(&self) -> String {
        let endpoint = if self.tls_server_end_point.is_some() {
            "<channel-binding type='tls-server-end-point'/>"
        } else {
            ""
        };
        let exporter = if self.tls_exporter.is_some() {
            "<channel-binding type='tls-exporter'/>"
        } else {
            ""
        };
        format!(
            "<sasl-channel-binding xmlns='urn:xmpp:sasl-cb:0'>{endpoint}{exporter}</sasl-channel-binding>"
        )
    }

    /// Channel-binding bytes used by the hash-token SASL mechanisms from
    /// XEP-0484.  Keeping this mapping next to the SCRAM binding container
    /// prevents the two authentication profiles from silently disagreeing.
    pub fn for_fast_mechanism(&self, mechanism: &str) -> Option<&[u8]> {
        match mechanism {
            "HT-SHA-256-ENDP" => self.get("tls-server-end-point"),
            "HT-SHA-256-EXPR" => self.get("tls-exporter"),
            _ => None,
        }
    }
}

pub const FAST_MECHANISMS: [&str; 3] = ["HT-SHA-256-ENDP", "HT-SHA-256-EXPR", "HT-SHA-256-NONE"];

pub fn is_fast_mechanism(mechanism: &str) -> bool {
    FAST_MECHANISMS.contains(&mechanism)
}

pub fn fast_channel_binding_name(mechanism: &str) -> Option<&'static str> {
    match mechanism {
        "HT-SHA-256-ENDP" => Some("tls-server-end-point"),
        "HT-SHA-256-EXPR" => Some("tls-exporter"),
        "HT-SHA-256-NONE" => Some("none"),
        _ => None,
    }
}

/// Derive a FAST bearer token without storing it in PostgreSQL.  `nonce` is
/// public per-row diversification; secrecy comes exclusively from the
/// deployment master key.  Every identity/binding field is length-delimited
/// to avoid ambiguous concatenations.
pub fn derive_fast_token(
    master_key: &[u8],
    token_id: Uuid,
    user_id: Uuid,
    device_id: Uuid,
    mechanism: &str,
    nonce: &[u8],
) -> Result<String> {
    if master_key.len() < 32 || nonce.len() != 32 || !is_fast_mechanism(mechanism) {
        anyhow::bail!("invalid FAST token derivation input");
    }
    let mut mac = Hmac::<Sha256>::new_from_slice(master_key)
        .map_err(|_| anyhow::anyhow!("invalid FAST master key"))?;
    mac.update(b"northstar/xmpp-fast-token/v1\0");
    mac.update(token_id.as_bytes());
    mac.update(user_id.as_bytes());
    mac.update(device_id.as_bytes());
    mac.update(&(mechanism.len() as u32).to_be_bytes());
    mac.update(mechanism.as_bytes());
    mac.update(nonce);
    let secret = mac.finalize().into_bytes();
    Ok(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(secret))
}

pub fn fast_proof(token: &str, responder: bool, channel_binding: &[u8]) -> Vec<u8> {
    let mut mac = Hmac::<Sha256>::new_from_slice(token.as_bytes())
        .expect("HMAC accepts arbitrary token sizes");
    mac.update(if responder {
        b"Responder"
    } else {
        b"Initiator"
    });
    mac.update(channel_binding);
    mac.finalize().into_bytes().to_vec()
}

/// HMAC verification is constant-time for equal-length candidate tags.
pub fn verify_fast_proof(
    token: &str,
    responder: bool,
    channel_binding: &[u8],
    candidate: &[u8],
) -> bool {
    let mut mac = Hmac::<Sha256>::new_from_slice(token.as_bytes())
        .expect("HMAC accepts arbitrary token sizes");
    mac.update(if responder {
        b"Responder"
    } else {
        b"Initiator"
    });
    mac.update(channel_binding);
    mac.verify_slice(candidate).is_ok()
}

pub fn validate_password(value: &str) -> Result<()> {
    if value.len() < 10 || value.len() > 1024 {
        anyhow::bail!("password must contain 10 to 1024 UTF-8 octets");
    }
    Ok(())
}

pub fn generate_scram_salt() -> Vec<u8> {
    let mut salt = vec![0u8; 32];
    rand::thread_rng().fill(&mut salt[..]);
    salt
}

pub fn compute_scram_sha256(password: &str, salt: &[u8], iterations: u32) -> (Vec<u8>, Vec<u8>) {
    let mut salted_password = Zeroizing::new(vec![0u8; 32]);
    pbkdf2::<Hmac<Sha256>>(password.as_bytes(), salt, iterations, &mut salted_password)
        .expect("pbkdf2 should not fail");

    // Keep HMAC state in the smallest possible scope. The reusable derived
    // bytes which remain outside that scope are explicitly zeroized.
    let client_key = Zeroizing::new({
        let mut mac_client = Hmac::<Sha256>::new_from_slice(&salted_password).unwrap();
        mac_client.update(b"Client Key");
        mac_client.finalize().into_bytes().to_vec()
    });

    let stored_key = Sha256::digest(&*client_key).to_vec();

    let server_key = {
        let mut mac_server = Hmac::<Sha256>::new_from_slice(&salted_password).unwrap();
        mac_server.update(b"Server Key");
        mac_server.finalize().into_bytes().to_vec()
    };

    (stored_key, server_key)
}

pub fn compute_scram_sha1(password: &str, salt: &[u8], iterations: u32) -> (Vec<u8>, Vec<u8>) {
    let mut salted_password = Zeroizing::new(vec![0u8; 20]);
    pbkdf2::<Hmac<Sha1>>(password.as_bytes(), salt, iterations, &mut salted_password)
        .expect("pbkdf2 should not fail");

    let client_key = Zeroizing::new({
        let mut mac_client = Hmac::<Sha1>::new_from_slice(&salted_password).unwrap();
        mac_client.update(b"Client Key");
        mac_client.finalize().into_bytes().to_vec()
    });
    let stored_key = Sha1::digest(&*client_key).to_vec();

    let server_key = {
        let mut mac_server = Hmac::<Sha1>::new_from_slice(&salted_password).unwrap();
        mac_server.update(b"Server Key");
        mac_server.finalize().into_bytes().to_vec()
    };
    (stored_key, server_key)
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ScramAlgorithm {
    Sha256,
    Sha1,
}

impl ScramAlgorithm {
    pub const fn key_len(self) -> usize {
        match self {
            Self::Sha256 => 32,
            Self::Sha1 => 20,
        }
    }

    const fn label(self) -> &'static [u8] {
        match self {
            Self::Sha256 => b"SCRAM-SHA-256",
            Self::Sha1 => b"SCRAM-SHA-1",
        }
    }
}

/// Select a deployment-stable dummy iteration profile for an unknown or
/// disabled account. The caller supplies the bounded, sorted set of every
/// live verifier cost plus the RFC floor and configured profile, so historical
/// accounts remain plausible dummy responses rather than an enumeration bit.
pub fn dummy_scram_iterations(
    secret: &[u8],
    username: &str,
    algorithm: ScramAlgorithm,
    iteration_profiles: &[u32],
) -> u32 {
    assert!(
        !iteration_profiles.is_empty()
            && iteration_profiles.iter().all(|iterations| {
                (MIN_SCRAM_ITERATIONS..=MAX_SCRAM_ITERATIONS).contains(iterations)
            }),
        "dummy SCRAM iteration profiles must be validated at startup"
    );
    let mut mac = Hmac::<Sha256>::new_from_slice(secret)
        .expect("HMAC accepts the deployment dummy-auth secret");
    mac.update(b"northstar/dummy-scram-iterations/v1\0");
    mac.update(algorithm.label());
    mac.update(b"\0");
    mac.update(username.as_bytes());
    let selector = mac.finalize().into_bytes()[0] as usize;
    iteration_profiles[selector % iteration_profiles.len()]
}

/// Build account-specific credentials for an unknown or disabled account.
/// The material is keyed by the independent mounted dummy-SCRAM secret, so it
/// is stable across restarts and nodes without coupling account-obfuscation
/// identity to FAST token rotation. Database corruption never uses this path.
pub fn dummy_scram_credentials(
    secret: &[u8],
    username: &str,
    algorithm: ScramAlgorithm,
    iterations: u32,
) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
    let derive = |purpose: &[u8], length: usize| {
        let mut mac = Hmac::<Sha256>::new_from_slice(secret)
            .expect("HMAC accepts the deployment dummy-auth secret");
        mac.update(b"northstar/dummy-scram-material/v1\0");
        mac.update(algorithm.label());
        mac.update(b"\0");
        mac.update(purpose);
        mac.update(b"\0");
        mac.update(&iterations.to_be_bytes());
        mac.update(b"\0");
        mac.update(username.as_bytes());
        mac.finalize().into_bytes()[..length].to_vec()
    };
    (
        derive(b"salt", 32),
        derive(b"stored-key", algorithm.key_len()),
        derive(b"server-key", algorithm.key_len()),
    )
}

#[derive(Debug, thiserror::Error)]
#[error("stored Argon2 password verifier is invalid: {details}")]
pub struct PasswordVerifierError {
    details: String,
}

impl PasswordVerifierError {
    fn new(error: argon2::password_hash::Error) -> Self {
        Self {
            details: error.to_string(),
        }
    }

    fn policy(details: &'static str) -> Self {
        Self {
            details: details.to_owned(),
        }
    }
}

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

use std::collections::HashMap;

/// A terminal SASL mechanism failure.  The public condition is deliberately
/// kept separate from the diagnostic: peers receive only the standardized
/// condition, while logs retain enough local detail to diagnose malformed
/// exchanges without leaking backend or parser information.
#[derive(Debug)]
pub struct SaslFailure {
    condition: &'static str,
    diagnostic: String,
}

impl SaslFailure {
    pub fn invalid_authzid(diagnostic: impl Into<String>) -> Self {
        Self {
            condition: "invalid-authzid",
            diagnostic: diagnostic.into(),
        }
    }

    pub fn condition(&self) -> &'static str {
        self.condition
    }
}

impl From<&str> for SaslFailure {
    fn from(diagnostic: &str) -> Self {
        Self {
            condition: "not-authorized",
            diagnostic: diagnostic.to_owned(),
        }
    }
}

impl From<String> for SaslFailure {
    fn from(diagnostic: String) -> Self {
        Self {
            condition: "not-authorized",
            diagnostic,
        }
    }
}

impl std::fmt::Display for SaslFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.diagnostic)
    }
}

impl std::ops::Deref for SaslFailure {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        &self.diagnostic
    }
}

/// Result of a SASL exchange step
pub enum SaslStep {
    /// Authentication succeeded. Contains the authenticated username.
    Success(String, Option<Zeroizing<String>>), // (username, password or SCRAM success-data)
    /// Need to send a challenge to the client and wait for response.
    Challenge(String), // base64-encoded challenge
    /// Need credentials for the given username to proceed (SCRAM)
    NeedsCredentials(String),
    /// Authentication failed.
    Failure(SaslFailure),
}

/// Trait for SASL mechanism implementations
pub trait SaslMechanism: Send + Sync {
    /// Process the initial client response (from <auth> element)
    fn initial_response(&mut self, data: &str) -> SaslStep;
    /// Process a subsequent client response (from <response> element)
    fn response(&mut self, data: &str) -> SaslStep;
    /// Provide credentials retrieved from the database (for SCRAM)
    fn provide_credentials(
        &mut self,
        _salt: Vec<u8>,
        _iters: u32,
        _stored_key: Vec<u8>,
        _server_key: Vec<u8>,
    ) -> SaslStep {
        SaslStep::Failure("Credentials not expected".into())
    }
    /// Get the mechanism name
    fn name(&self) -> &'static str;
    /// Canonical authentication identity observed so far. This is never sent
    /// to a peer; the server uses it to key failed-login throttling.
    fn attempted_username(&self) -> Option<&str> {
        None
    }
    fn scram_algorithm(&self) -> Option<ScramAlgorithm> {
        None
    }
}

/// PLAIN mechanism - only allowed inside TLS
pub struct PlainMechanism {
    domain: String,
    attempted_username: Option<String>,
}

impl PlainMechanism {
    pub fn new(domain: String) -> Self {
        Self {
            domain,
            attempted_username: None,
        }
    }
}

impl SaslMechanism for PlainMechanism {
    fn initial_response(&mut self, data: &str) -> SaslStep {
        let bytes = match STANDARD.decode(data.trim()) {
            Ok(b) => b,
            Err(_) => return SaslStep::Failure("Invalid base64".into()),
        };
        let value = match String::from_utf8(bytes) {
            Ok(v) => v,
            Err(_) => return SaslStep::Failure("Invalid UTF-8".into()),
        };
        let value = Zeroizing::new(value);
        let mut fields = value.split('\0');
        let authz = fields.next().unwrap_or_default();
        let authc = match fields.next() {
            Some(a) => a,
            None => return SaslStep::Failure("Missing username".into()),
        };
        let pass = match fields.next() {
            Some(p) => p,
            None => return SaslStep::Failure("Missing password".into()),
        };
        if fields.next().is_some() {
            return SaslStep::Failure("Invalid PLAIN payload".into());
        }
        let username = match normalize_username(authc) {
            Ok(username) => username,
            Err(_) => return SaslStep::Failure("Invalid authentication identity".into()),
        };
        self.attempted_username = Some(username.clone());
        if !authz.is_empty() {
            // RFC 6120 authorization identities are bare JIDs. A localpart-
            // only value is not silently reinterpreted in a server-specific
            // way because that can produce different identities at federated
            // or virtual-host boundaries.
            let matches = crate::jid::CanonicalJid::parse_bare(authz)
                .ok()
                .is_some_and(|jid| {
                    jid.localpart() == Some(username.as_str()) && jid.domainpart() == self.domain
                });
            if !matches {
                return SaslStep::Failure(SaslFailure::invalid_authzid(
                    "Authorization identity does not match authentication identity",
                ));
            }
        }

        SaslStep::Success(username, Some(Zeroizing::new(pass.to_string())))
    }

    fn response(&mut self, _data: &str) -> SaslStep {
        SaslStep::Failure("PLAIN does not support multi-step".into())
    }

    fn name(&self) -> &'static str {
        "PLAIN"
    }

    fn attempted_username(&self) -> Option<&str> {
        self.attempted_username.as_deref()
    }
}

/// RFC 4422 EXTERNAL for a client identity already authenticated by mTLS.
/// Only PKIX-validated id-on-xmppAddr bare JIDs are supplied by the transport.
pub struct ExternalMechanism {
    identities: Vec<String>,
    attempted_username: Option<String>,
}

impl ExternalMechanism {
    pub fn new(identities: Vec<String>) -> Self {
        Self {
            identities,
            attempted_username: None,
        }
    }
}

impl SaslMechanism for ExternalMechanism {
    fn initial_response(&mut self, data: &str) -> SaslStep {
        // RFC 4422 uses a single "=" at the protocol layer to distinguish an
        // explicitly empty initial response from an omitted response.
        let encoded = data.trim();
        let decoded = match if encoded == "=" {
            Ok(Vec::new())
        } else {
            STANDARD.decode(encoded)
        } {
            Ok(value) => value,
            Err(_) => return SaslStep::Failure("Invalid EXTERNAL base64".into()),
        };
        let authorization = match String::from_utf8(decoded) {
            Ok(value) if value.len() <= 1_024 && !value.chars().any(char::is_control) => value,
            _ => return SaslStep::Failure("Invalid EXTERNAL authorization identity".into()),
        };
        let selected = if authorization.is_empty() {
            match self.identities.as_slice() {
                [identity] => identity.clone(),
                _ => {
                    return SaslStep::Failure(SaslFailure::invalid_authzid(
                        "EXTERNAL certificate identity is ambiguous",
                    ))
                }
            }
        } else {
            let identity = match crate::jid::CanonicalJid::parse_bare(&authorization) {
                Ok(jid) if jid.localpart().is_some() => jid.to_string(),
                _ => {
                    return SaslStep::Failure(SaslFailure::invalid_authzid(
                        "Invalid EXTERNAL authorization identity",
                    ))
                }
            };
            if !self.identities.iter().any(|allowed| allowed == &identity) {
                return SaslStep::Failure(SaslFailure::invalid_authzid(
                    "EXTERNAL authorization identity is not in the certificate",
                ));
            }
            identity
        };
        let jid = crate::jid::CanonicalJid::parse_bare(&selected)
            .expect("transport supplied a canonical bare JID");
        let username = jid
            .localpart()
            .expect("C2S certificate identity has a localpart")
            .to_owned();
        self.attempted_username = Some(username.clone());
        SaslStep::Success(username, None)
    }

    fn response(&mut self, data: &str) -> SaslStep {
        if self.attempted_username.is_some() {
            SaslStep::Failure("EXTERNAL authentication is already complete".into())
        } else {
            self.initial_response(data)
        }
    }

    fn name(&self) -> &'static str {
        "EXTERNAL"
    }

    fn attempted_username(&self) -> Option<&str> {
        self.attempted_username.as_deref()
    }
}

enum ScramState {
    WaitingForClientFirst,
    WaitingForCredentials,
    WaitingForClientFinal,
    Completed,
}

/// SCRAM-SHA-256 mechanism
pub struct ScramSha256Mechanism {
    state: ScramState,
    domain: String,
    plus: bool,
    channel_binding_advertised: bool,
    channel_bindings: Option<ChannelBindings>,
    selected_binding: Vec<u8>,
    gs2_header: String,
    server_nonce: String,
    client_first_bare: String,
    auth_message: String,
    stored_key: Vec<u8>,
    server_key: Vec<u8>,
    username: String,
    iteration_count: u32,
    salt: Vec<u8>,
    algorithm: ScramAlgorithm,
}

impl Drop for ScramSha256Mechanism {
    fn drop(&mut self) {
        self.selected_binding.zeroize();
        self.gs2_header.zeroize();
        self.server_nonce.zeroize();
        self.client_first_bare.zeroize();
        self.auth_message.zeroize();
        self.stored_key.zeroize();
        self.server_key.zeroize();
        self.salt.zeroize();
    }
}

impl ScramSha256Mechanism {
    pub fn new(domain: String) -> Self {
        Self::new_inner(domain, ScramAlgorithm::Sha256, false, false, None)
    }

    pub fn new_with_channel_binding_support(domain: String) -> Self {
        Self::new_inner(domain, ScramAlgorithm::Sha256, false, true, None)
    }

    pub fn new_plus(domain: String, channel_bindings: ChannelBindings) -> Self {
        Self::new_inner(
            domain,
            ScramAlgorithm::Sha256,
            true,
            true,
            Some(channel_bindings),
        )
    }

    pub fn new_sha1(domain: String) -> Self {
        Self::new_inner(domain, ScramAlgorithm::Sha1, false, false, None)
    }

    pub fn new_sha1_with_channel_binding_support(domain: String) -> Self {
        Self::new_inner(domain, ScramAlgorithm::Sha1, false, true, None)
    }

    pub fn new_sha1_plus(domain: String, channel_bindings: ChannelBindings) -> Self {
        Self::new_inner(
            domain,
            ScramAlgorithm::Sha1,
            true,
            true,
            Some(channel_bindings),
        )
    }

    fn new_inner(
        domain: String,
        algorithm: ScramAlgorithm,
        plus: bool,
        channel_binding_advertised: bool,
        channel_bindings: Option<ChannelBindings>,
    ) -> Self {
        let server_nonce: String = rand::thread_rng()
            .sample_iter(&Alphanumeric)
            .take(24)
            .map(char::from)
            .collect();

        Self {
            state: ScramState::WaitingForClientFirst,
            domain,
            plus,
            channel_binding_advertised,
            channel_bindings,
            selected_binding: Vec::new(),
            gs2_header: String::new(),
            server_nonce,
            client_first_bare: String::new(),
            auth_message: String::new(),
            stored_key: Vec::new(),
            server_key: Vec::new(),
            username: String::new(),
            iteration_count: 0,
            salt: Vec::new(),
            algorithm,
        }
    }

    fn parse_client_first(
        &self,
        data: &str,
    ) -> Result<(String, String, String, Vec<u8>), SaslFailure> {
        let parts: Vec<&str> = data.splitn(3, ',').collect();
        if parts.len() < 3 {
            return Err("Invalid SCRAM GS2 header".into());
        }
        let selected_binding = if self.plus {
            let kind = parts[0]
                .strip_prefix("p=")
                .filter(|kind| !kind.is_empty())
                .ok_or("SCRAM-PLUS requires a channel-binding flag")?;
            self.channel_bindings
                .as_ref()
                .and_then(|bindings| bindings.get(kind))
                .map(<[u8]>::to_vec)
                .ok_or("Unsupported SCRAM channel-binding type")?
        } else {
            match parts[0] {
                "n" => Vec::new(),
                "y" if self.channel_binding_advertised => {
                    return Err("SCRAM channel-binding downgrade detected".into());
                }
                "y" => Vec::new(),
                _ => return Err("Invalid SCRAM GS2 channel-binding flag".into()),
            }
        };
        let bare = parts[2];
        let attrs = Self::parse_attributes(bare)?;
        if attrs.contains_key("m") {
            return Err("Unsupported mandatory SCRAM extension".into());
        }
        let user = Self::unescape_username(attrs.get("n").ok_or("Missing username")?)?;
        let user = normalize_username(&user).map_err(|_| "Invalid SCRAM username")?;
        if !parts[1].is_empty() {
            let authzid = parts[1].strip_prefix("a=").ok_or_else(|| {
                SaslFailure::invalid_authzid("Invalid SCRAM authorization identity")
            })?;
            self.validate_authzid(authzid, &user)
                .map_err(SaslFailure::invalid_authzid)?;
        }
        let nonce = attrs.get("r").ok_or("Missing nonce")?.to_string();
        if nonce.is_empty()
            || nonce.len() > 1_024
            || nonce.contains(',')
            || nonce.chars().any(char::is_control)
        {
            return Err("Invalid SCRAM nonce".into());
        }

        Ok((
            user,
            nonce,
            format!("{},{},", parts[0], parts[1]),
            selected_binding,
        ))
    }

    fn validate_authzid(&self, encoded: &str, username: &str) -> Result<(), &'static str> {
        let authzid =
            Self::unescape_username(encoded).map_err(|_| "Invalid SCRAM authorization identity")?;
        let jid = crate::jid::CanonicalJid::parse_bare(&authzid)
            .map_err(|_| "Invalid SCRAM authorization identity")?;
        if jid.localpart() != Some(username)
            || jid.domainpart() != self.domain
            || jid.resourcepart().is_some()
        {
            return Err("SCRAM authorization identity does not match authentication identity");
        }
        Ok(())
    }

    fn parse_attributes(data: &str) -> Result<HashMap<String, String>, &'static str> {
        let mut map = HashMap::new();
        for kv in data.split(',') {
            let bytes = kv.as_bytes();
            if bytes.len() < 3 || bytes[1] != b'=' || !bytes[0].is_ascii_alphabetic() {
                return Err("Invalid attribute format");
            }
            let k = char::from(bytes[0]).to_string();
            let v = kv[2..].to_string();
            if map.insert(k, v).is_some() {
                return Err("Duplicate SCRAM attribute");
            }
        }
        Ok(map)
    }

    fn unescape_username(value: &str) -> Result<String, &'static str> {
        let mut output = String::with_capacity(value.len());
        let mut chars = value.chars();
        while let Some(character) = chars.next() {
            if character != '=' {
                output.push(character);
                continue;
            }
            match (chars.next(), chars.next()) {
                (Some('2'), Some('C')) => output.push(','),
                (Some('3'), Some('D')) => output.push('='),
                _ => return Err("Invalid SCRAM username escape"),
            }
        }
        Ok(output)
    }
}

impl SaslMechanism for ScramSha256Mechanism {
    fn initial_response(&mut self, data: &str) -> SaslStep {
        if !matches!(self.state, ScramState::WaitingForClientFirst) {
            return SaslStep::Failure("Unexpected initial response".into());
        }

        let decoded = match STANDARD.decode(data) {
            Ok(d) => d,
            Err(_) => return SaslStep::Failure("Invalid base64".into()),
        };
        let decoded_str = match String::from_utf8(decoded) {
            Ok(s) => s,
            Err(_) => return SaslStep::Failure("Invalid UTF-8".into()),
        };

        match self.parse_client_first(&decoded_str) {
            Ok((user, nonce, gs2_header, selected_binding)) => {
                // Keep client_first_bare for the auth message
                // The bare part is everything after the GS2 header "n,,"
                let parts: Vec<&str> = decoded_str.splitn(3, ',').collect();
                self.client_first_bare = parts[2].to_string();

                self.username = user.clone();
                self.gs2_header = gs2_header;
                self.selected_binding = selected_binding;
                // Append server nonce to client nonce
                self.server_nonce = format!("{}{}", nonce, self.server_nonce);

                self.state = ScramState::WaitingForCredentials;
                SaslStep::NeedsCredentials(user)
            }
            Err(e) => SaslStep::Failure(e),
        }
    }

    fn provide_credentials(
        &mut self,
        salt: Vec<u8>,
        iters: u32,
        stored_key: Vec<u8>,
        server_key: Vec<u8>,
    ) -> SaslStep {
        if !matches!(self.state, ScramState::WaitingForCredentials) {
            return SaslStep::Failure("Not expecting credentials".into());
        }

        if iters == 0
            || stored_key.len() != self.algorithm.key_len()
            || server_key.len() != self.algorithm.key_len()
        {
            return SaslStep::Failure("Invalid stored SCRAM credentials".into());
        }
        self.salt = salt;
        self.iteration_count = iters;
        self.stored_key = stored_key;
        self.server_key = server_key;

        let salt_b64 = STANDARD.encode(&self.salt);
        let server_first = format!(
            "r={},s={},i={}",
            self.server_nonce, salt_b64, self.iteration_count
        );

        self.auth_message = format!("{},{}", self.client_first_bare, server_first);

        self.state = ScramState::WaitingForClientFinal;
        SaslStep::Challenge(server_first)
    }

    fn response(&mut self, data: &str) -> SaslStep {
        if !matches!(self.state, ScramState::WaitingForClientFinal) {
            return SaslStep::Failure("Unexpected response".into());
        }

        let decoded = match STANDARD.decode(data) {
            Ok(d) => d,
            Err(_) => return SaslStep::Failure("Invalid base64".into()),
        };
        let decoded_str = match String::from_utf8(decoded) {
            Ok(s) => s,
            Err(_) => return SaslStep::Failure("Invalid UTF-8".into()),
        };

        let attrs = match Self::parse_attributes(&decoded_str) {
            Ok(a) => a,
            Err(e) => return SaslStep::Failure(e.into()),
        };
        if attrs.contains_key("m") {
            return SaslStep::Failure("Unsupported mandatory SCRAM extension".into());
        }

        let Some((client_final_bare, proof_suffix)) = decoded_str.rsplit_once(",p=") else {
            return SaslStep::Failure("Missing proof".into());
        };
        if client_final_bare.is_empty() || proof_suffix.is_empty() || proof_suffix.contains(',') {
            return SaslStep::Failure("Invalid client-final message".into());
        }
        let Some(channel_binding) = attrs.get("c") else {
            return SaslStep::Failure("Missing channel binding".into());
        };
        let decoded_binding = match STANDARD.decode(channel_binding) {
            Ok(binding) => binding,
            Err(_) => return SaslStep::Failure("Invalid channel binding".into()),
        };
        let mut expected_binding = self.gs2_header.as_bytes().to_vec();
        expected_binding.extend_from_slice(&self.selected_binding);
        if decoded_binding != expected_binding {
            return SaslStep::Failure("Channel binding does not match GS2 header".into());
        }
        if attrs.get("r").map(String::as_str) != Some(self.server_nonce.as_str()) {
            return SaslStep::Failure("SCRAM nonce does not match".into());
        }
        self.auth_message.push(',');
        self.auth_message.push_str(client_final_bare);

        let proof_b64 = match attrs.get("p") {
            Some(p) => p,
            None => return SaslStep::Failure("Missing proof".into()),
        };
        let client_proof = match STANDARD.decode(proof_b64) {
            Ok(p) => p,
            Err(_) => return SaslStep::Failure("Invalid proof base64".into()),
        };
        if client_proof.len() != self.algorithm.key_len() {
            return SaslStep::Failure("Invalid proof length".into());
        }

        // Compute ClientSignature = HMAC(StoredKey, AuthMessage)
        let client_signature = scram_hmac(
            self.algorithm,
            &self.stored_key,
            self.auth_message.as_bytes(),
        );

        // ClientKey = ClientProof XOR ClientSignature
        let mut client_key = Zeroizing::new(vec![0u8; self.algorithm.key_len()]);
        for i in 0..self.algorithm.key_len() {
            client_key[i] = client_proof[i] ^ client_signature[i];
        }

        // StoredKey = SHA-256(ClientKey)
        let expected_stored_key = match self.algorithm {
            ScramAlgorithm::Sha256 => Sha256::digest(client_key).to_vec(),
            ScramAlgorithm::Sha1 => Sha1::digest(client_key).to_vec(),
        };

        let difference = expected_stored_key
            .iter()
            .zip(&self.stored_key)
            .fold(0_u8, |difference, (left, right)| {
                difference | (left ^ right)
            });
        if difference != 0 {
            return SaslStep::Failure("Authentication failed".into());
        }

        // Generate ServerSignature = HMAC(ServerKey, AuthMessage)
        let server_signature = scram_hmac(
            self.algorithm,
            &self.server_key,
            self.auth_message.as_bytes(),
        );
        let server_signature_b64 = STANDARD.encode(server_signature);

        let server_final = format!("v={}", server_signature_b64);

        self.state = ScramState::Completed;
        // Return success with server-final-message as success-data
        SaslStep::Success(self.username.clone(), Some(Zeroizing::new(server_final)))
    }

    fn name(&self) -> &'static str {
        match (self.algorithm, self.plus) {
            (ScramAlgorithm::Sha256, true) => "SCRAM-SHA-256-PLUS",
            (ScramAlgorithm::Sha256, false) => "SCRAM-SHA-256",
            (ScramAlgorithm::Sha1, true) => "SCRAM-SHA-1-PLUS",
            (ScramAlgorithm::Sha1, false) => "SCRAM-SHA-1",
        }
    }

    fn attempted_username(&self) -> Option<&str> {
        (!self.username.is_empty()).then_some(self.username.as_str())
    }

    fn scram_algorithm(&self) -> Option<ScramAlgorithm> {
        Some(self.algorithm)
    }
}

fn scram_hmac(algorithm: ScramAlgorithm, key: &[u8], message: &[u8]) -> Vec<u8> {
    match algorithm {
        ScramAlgorithm::Sha256 => {
            let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("valid HMAC key");
            mac.update(message);
            mac.finalize().into_bytes().to_vec()
        }
        ScramAlgorithm::Sha1 => {
            let mut mac = Hmac::<Sha1>::new_from_slice(key).expect("valid HMAC key");
            mac.update(message);
            mac.finalize().into_bytes().to_vec()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn channel_binding_advertisement_matches_available_tls_capabilities() {
        let exporter_only = ChannelBindings::from_available(None, Some(vec![0x11; 32]))
            .unwrap()
            .unwrap();
        assert!(exporter_only.get("tls-server-end-point").is_none());
        assert_eq!(exporter_only.get("tls-exporter"), Some(&[0x11; 32][..]));
        assert_eq!(
            exporter_only.feature_xml(),
            "<sasl-channel-binding xmlns='urn:xmpp:sasl-cb:0'><channel-binding type='tls-exporter'/></sasl-channel-binding>"
        );

        let endpoint_only = ChannelBindings::from_available(Some(vec![0x22; 32]), None)
            .unwrap()
            .unwrap();
        assert_eq!(
            endpoint_only.get("tls-server-end-point"),
            Some(&[0x22; 32][..])
        );
        assert!(endpoint_only.get("tls-exporter").is_none());
        assert_eq!(
            endpoint_only.feature_xml(),
            "<sasl-channel-binding xmlns='urn:xmpp:sasl-cb:0'><channel-binding type='tls-server-end-point'/></sasl-channel-binding>"
        );

        assert!(ChannelBindings::from_available(None, None)
            .unwrap()
            .is_none());
        assert!(ChannelBindings::from_available(None, Some(vec![0; 31])).is_err());
        assert!(ChannelBindings::from_available(Some(Vec::new()), None).is_err());
    }

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
    fn fast_ht_proofs_are_directional_and_binding_specific() {
        let token = "opaque-fast-token";
        let endpoint = [0x11_u8; 32];
        let exporter = [0x22_u8; 32];
        let initiator = fast_proof(token, false, &endpoint);
        let responder = fast_proof(token, true, &endpoint);
        assert_ne!(initiator, responder);
        assert!(verify_fast_proof(token, false, &endpoint, &initiator));
        assert!(!verify_fast_proof(token, true, &endpoint, &initiator));
        assert!(!verify_fast_proof(token, false, &exporter, &initiator));
        assert!(!verify_fast_proof(
            "other-token",
            false,
            &endpoint,
            &initiator
        ));
    }

    #[test]
    fn fast_tokens_are_bound_to_every_identity_dimension() {
        let key = [0x33_u8; 32];
        let id = Uuid::from_u128(1);
        let user = Uuid::from_u128(2);
        let device = Uuid::from_u128(3);
        let nonce = [0x44_u8; 32];
        let original =
            derive_fast_token(&key, id, user, device, "HT-SHA-256-ENDP", &nonce).unwrap();
        assert_ne!(
            original,
            derive_fast_token(
                &key,
                id,
                user,
                Uuid::from_u128(4),
                "HT-SHA-256-ENDP",
                &nonce,
            )
            .unwrap()
        );
        assert_ne!(
            original,
            derive_fast_token(&key, id, user, device, "HT-SHA-256-NONE", &nonce,).unwrap()
        );
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
    fn plain_rejects_authorization_as_another_account() {
        let mut mechanism = PlainMechanism::new("example.test".into());
        let payload = STANDARD.encode("mallory@example.test\0alice\0secret");
        assert!(matches!(
            mechanism.initial_response(&payload),
            SaslStep::Failure(ref failure) if failure.condition() == "invalid-authzid"
        ));
        let localpart_only = STANDARD.encode("alice\0alice\0secret");
        assert!(matches!(
            mechanism.initial_response(&localpart_only),
            SaslStep::Failure(ref failure) if failure.condition() == "invalid-authzid"
        ));
    }

    #[test]
    fn external_accepts_only_certificate_bound_bare_jids() {
        let identities = vec!["alice@example.test".to_owned()];
        let mut implicit = ExternalMechanism::new(identities.clone());
        assert!(matches!(
            implicit.initial_response(""),
            SaslStep::Success(ref username, None) if username == "alice"
        ));
        let mut explicit_empty = ExternalMechanism::new(identities.clone());
        assert!(matches!(
            explicit_empty.initial_response("="),
            SaslStep::Success(ref username, None) if username == "alice"
        ));

        let mut explicit = ExternalMechanism::new(identities.clone());
        assert!(matches!(
            explicit.initial_response(&STANDARD.encode("alice@example.test")),
            SaslStep::Success(ref username, None) if username == "alice"
        ));

        let mut unauthorized = ExternalMechanism::new(identities);
        assert!(matches!(
            unauthorized.initial_response(&STANDARD.encode("mallory@example.test")),
            SaslStep::Failure(ref failure) if failure.condition() == "invalid-authzid"
        ));

        let mut ambiguous = ExternalMechanism::new(vec![
            "alice@example.test".to_owned(),
            "alice@other.test".to_owned(),
        ]);
        assert!(matches!(
            ambiguous.initial_response(""),
            SaslStep::Failure(ref failure) if failure.condition() == "invalid-authzid"
        ));
    }

    #[test]
    fn scram_reports_supplied_invalid_authorization_identity() {
        for client_first in [
            "n,a=mallory@example.test,n=alice,r=nonce",
            "n,not-an-authzid,n=alice,r=nonce",
        ] {
            let mut mechanism = ScramSha256Mechanism::new("example.test".into());
            let initial = STANDARD.encode(client_first);
            assert!(matches!(
                mechanism.initial_response(&initial),
                SaslStep::Failure(ref failure)
                    if failure.condition() == "invalid-authzid"
            ));
        }
    }

    #[test]
    fn scram_sha256_accepts_a_valid_exchange() {
        let password = "correct horse battery staple";
        let salt = vec![7_u8; 32];
        let iterations = 4096;
        let (stored_key, server_key) = compute_scram_sha256(password, &salt, iterations);
        let mut mechanism = ScramSha256Mechanism::new("example.test".into());

        let client_first_bare = "n=alice,r=clientnonce";
        let initial = STANDARD.encode(format!("n,,{client_first_bare}"));
        assert!(matches!(
            mechanism.initial_response(&initial),
            SaslStep::NeedsCredentials(ref username) if username == "alice"
        ));

        let server_first = match mechanism.provide_credentials(
            salt.clone(),
            iterations,
            stored_key.clone(),
            server_key,
        ) {
            SaslStep::Challenge(challenge) => challenge,
            _ => panic!("SCRAM did not produce a server-first challenge"),
        };
        let nonce = server_first
            .split(',')
            .find_map(|attribute| attribute.strip_prefix("r="))
            .unwrap();
        let client_final_bare = format!("c=biws,r={nonce}");
        let auth_message = format!("{client_first_bare},{server_first},{client_final_bare}");

        let mut salted_password = vec![0_u8; 32];
        pbkdf2::<Hmac<Sha256>>(password.as_bytes(), &salt, iterations, &mut salted_password)
            .unwrap();
        let mut client_key_mac = Hmac::<Sha256>::new_from_slice(&salted_password).unwrap();
        client_key_mac.update(b"Client Key");
        let client_key = client_key_mac.finalize().into_bytes();
        let mut signature_mac = Hmac::<Sha256>::new_from_slice(&stored_key).unwrap();
        signature_mac.update(auth_message.as_bytes());
        let client_signature = signature_mac.finalize().into_bytes();
        let proof: Vec<u8> = client_key
            .iter()
            .zip(client_signature)
            .map(|(key, signature)| key ^ signature)
            .collect();
        let client_final =
            STANDARD.encode(format!("{client_final_bare},p={}", STANDARD.encode(proof)));

        assert!(matches!(
            mechanism.response(&client_final),
            SaslStep::Success(ref username, Some(ref final_data))
                if username == "alice" && final_data.starts_with("v=")
        ));
    }

    #[test]
    fn scram_sha1_accepts_a_valid_exchange_with_independent_verifier() {
        let password = "correct horse battery staple";
        let salt = vec![3_u8; 32];
        let iterations = 4096;
        let (stored_key, server_key) = compute_scram_sha1(password, &salt, iterations);
        assert_eq!(stored_key.len(), 20);
        let mut mechanism = ScramSha256Mechanism::new_sha1("example.test".into());
        let client_first_bare = "n=alice,r=clientnonce";
        let initial = STANDARD.encode(format!("n,,{client_first_bare}"));
        assert!(matches!(
            mechanism.initial_response(&initial),
            SaslStep::NeedsCredentials(ref username) if username == "alice"
        ));
        let server_first = match mechanism.provide_credentials(
            salt.clone(),
            iterations,
            stored_key.clone(),
            server_key,
        ) {
            SaslStep::Challenge(challenge) => challenge,
            _ => panic!("SCRAM-SHA-1 did not produce a challenge"),
        };
        let nonce = server_first
            .split(',')
            .find_map(|attribute| attribute.strip_prefix("r="))
            .unwrap();
        let client_final_bare = format!("c=biws,r={nonce}");
        let auth_message = format!("{client_first_bare},{server_first},{client_final_bare}");
        let mut salted_password = vec![0_u8; 20];
        pbkdf2::<Hmac<Sha1>>(password.as_bytes(), &salt, iterations, &mut salted_password).unwrap();
        let client_key = scram_hmac(ScramAlgorithm::Sha1, &salted_password, b"Client Key");
        let client_signature =
            scram_hmac(ScramAlgorithm::Sha1, &stored_key, auth_message.as_bytes());
        let proof = client_key
            .iter()
            .zip(client_signature)
            .map(|(key, signature)| key ^ signature)
            .collect::<Vec<_>>();
        let client_final =
            STANDARD.encode(format!("{client_final_bare},p={}", STANDARD.encode(proof)));
        assert!(matches!(
            mechanism.response(&client_final),
            SaslStep::Success(ref username, Some(ref final_data))
                if username == "alice" && final_data.starts_with("v=")
        ));
        assert_eq!(mechanism.name(), "SCRAM-SHA-1");
    }

    #[test]
    fn scram_sha1_plus_authenticates_the_tls_exporter_binding() {
        let password = "correct horse battery staple";
        let salt = vec![4_u8; 32];
        let iterations = 4096;
        let (stored_key, server_key) = compute_scram_sha1(password, &salt, iterations);
        let exporter = vec![0xa5_u8; 32];
        let bindings = ChannelBindings::new(vec![0x5a_u8; 32], Some(exporter.clone())).unwrap();
        let mut mechanism = ScramSha256Mechanism::new_sha1_plus("example.test".into(), bindings);
        let client_first_bare = "n=alice,r=clientnonce";
        let gs2_header = "p=tls-exporter,,";
        let initial = STANDARD.encode(format!("{gs2_header}{client_first_bare}"));
        assert!(matches!(
            mechanism.initial_response(&initial),
            SaslStep::NeedsCredentials(ref username) if username == "alice"
        ));
        let server_first = match mechanism.provide_credentials(
            salt.clone(),
            iterations,
            stored_key.clone(),
            server_key,
        ) {
            SaslStep::Challenge(challenge) => challenge,
            _ => panic!("SCRAM-SHA-1-PLUS did not produce a challenge"),
        };
        let nonce = server_first
            .split(',')
            .find_map(|attribute| attribute.strip_prefix("r="))
            .unwrap();
        let mut channel_binding = gs2_header.as_bytes().to_vec();
        channel_binding.extend_from_slice(&exporter);
        let client_final_bare = format!("c={},r={nonce}", STANDARD.encode(channel_binding));
        let auth_message = format!("{client_first_bare},{server_first},{client_final_bare}");
        let mut salted_password = vec![0_u8; 20];
        pbkdf2::<Hmac<Sha1>>(password.as_bytes(), &salt, iterations, &mut salted_password).unwrap();
        let client_key = scram_hmac(ScramAlgorithm::Sha1, &salted_password, b"Client Key");
        let signature = scram_hmac(ScramAlgorithm::Sha1, &stored_key, auth_message.as_bytes());
        let proof = client_key
            .iter()
            .zip(signature)
            .map(|(key, signature)| key ^ signature)
            .collect::<Vec<_>>();
        let final_message =
            STANDARD.encode(format!("{client_final_bare},p={}", STANDARD.encode(proof)));
        assert!(matches!(
            mechanism.response(&final_message),
            SaslStep::Success(ref username, Some(ref final_data))
                if username == "alice" && final_data.starts_with("v=")
        ));
        assert_eq!(mechanism.name(), "SCRAM-SHA-1-PLUS");
    }

    #[test]
    fn dummy_scram_material_is_account_and_family_specific() {
        let key = [0x5a; 32];
        let alice256 = dummy_scram_credentials(&key, "alice", ScramAlgorithm::Sha256, 4096);
        let alice256_again = dummy_scram_credentials(&key, "alice", ScramAlgorithm::Sha256, 4096);
        let bob256 = dummy_scram_credentials(&key, "bob", ScramAlgorithm::Sha256, 4096);
        let alice1 = dummy_scram_credentials(&key, "alice", ScramAlgorithm::Sha1, 4096);
        let alice256_stronger =
            dummy_scram_credentials(&key, "alice", ScramAlgorithm::Sha256, 600_000);
        assert_eq!(alice256, alice256_again);
        assert_ne!(alice256.0, bob256.0);
        assert_ne!(alice256.0, alice1.0);
        assert_ne!(alice256.0, alice256_stronger.0);
        assert_eq!(alice256.1.len(), 32);
        assert_eq!(alice1.1.len(), 20);
        let selected = dummy_scram_iterations(
            &key,
            "alice",
            ScramAlgorithm::Sha256,
            &[MIN_SCRAM_ITERATIONS, DEFAULT_SCRAM_ITERATIONS],
        );
        assert!(matches!(
            selected,
            MIN_SCRAM_ITERATIONS | DEFAULT_SCRAM_ITERATIONS
        ));
    }

    #[test]
    fn dummy_scram_uses_the_real_wire_shape_and_completes_before_uniform_failure() {
        fn exchange_shape(
            mut mechanism: ScramSha256Mechanism,
            salt: Vec<u8>,
            stored_key: Vec<u8>,
            server_key: Vec<u8>,
            proof_len: usize,
        ) -> (usize, u32, &'static str) {
            let initial = STANDARD.encode("n,,n=missing-account,r=clientnonce");
            assert!(matches!(
                mechanism.initial_response(&initial),
                SaslStep::NeedsCredentials(ref username) if username == "missing-account"
            ));
            let challenge = match mechanism.provide_credentials(
                salt,
                MIN_SCRAM_ITERATIONS,
                stored_key,
                server_key,
            ) {
                SaslStep::Challenge(challenge) => challenge,
                _ => panic!("SCRAM dummy exchange did not emit server-first"),
            };
            let nonce = challenge
                .split(',')
                .find_map(|attribute| attribute.strip_prefix("r="))
                .unwrap();
            assert!(nonce.starts_with("clientnonce"));
            let salt_len = challenge
                .split(',')
                .find_map(|attribute| attribute.strip_prefix("s="))
                .and_then(|salt| STANDARD.decode(salt).ok())
                .map(|salt| salt.len())
                .unwrap();
            let iterations = challenge
                .split(',')
                .find_map(|attribute| attribute.strip_prefix("i="))
                .and_then(|value| value.parse::<u32>().ok())
                .unwrap();
            let final_message = STANDARD.encode(format!(
                "c=biws,r={nonce},p={}",
                STANDARD.encode(vec![0_u8; proof_len])
            ));
            let condition = match mechanism.response(&final_message) {
                SaslStep::Failure(failure) => failure.condition(),
                _ => panic!("arbitrary proof authenticated against dummy SCRAM credentials"),
            };
            (salt_len, iterations, condition)
        }

        for algorithm in [ScramAlgorithm::Sha256, ScramAlgorithm::Sha1] {
            let key = [0xa5; 32];
            let (salt, stored_key, server_key) =
                dummy_scram_credentials(&key, "missing-account", algorithm, MIN_SCRAM_ITERATIONS);
            let mechanism = match algorithm {
                ScramAlgorithm::Sha256 => ScramSha256Mechanism::new("example.test".into()),
                ScramAlgorithm::Sha1 => ScramSha256Mechanism::new_sha1("example.test".into()),
            };
            assert_eq!(
                exchange_shape(mechanism, salt, stored_key, server_key, algorithm.key_len(),),
                (32, MIN_SCRAM_ITERATIONS, "not-authorized")
            );
        }
    }

    #[test]
    fn scram_sha256_rejects_wrong_channel_binding() {
        let salt = vec![9_u8; 32];
        let (stored_key, server_key) = compute_scram_sha256("password1234", &salt, 4096);
        let mut mechanism = ScramSha256Mechanism::new("example.test".into());
        let initial = STANDARD.encode("n,,n=alice,r=clientnonce");
        assert!(matches!(
            mechanism.initial_response(&initial),
            SaslStep::NeedsCredentials(_)
        ));
        let challenge = match mechanism.provide_credentials(salt, 4096, stored_key, server_key) {
            SaslStep::Challenge(challenge) => challenge,
            _ => panic!("SCRAM did not produce a server-first challenge"),
        };
        let nonce = challenge
            .split(',')
            .find_map(|attribute| attribute.strip_prefix("r="))
            .unwrap();
        let final_message = STANDARD.encode(format!(
            "c=eSws,r={nonce},p={}",
            STANDARD.encode([0_u8; 32])
        ));

        assert!(matches!(
            mechanism.response(&final_message),
            SaslStep::Failure(ref error) if error.contains("Channel binding")
        ));
    }

    #[test]
    fn scram_sha256_plus_accepts_tls_exporter_binding() {
        let password = "correct horse battery staple";
        let salt = vec![5_u8; 32];
        let iterations = 4096;
        let (stored_key, server_key) = compute_scram_sha256(password, &salt, iterations);
        let exporter = vec![0x42_u8; 32];
        let bindings = ChannelBindings::new(vec![0x24_u8; 32], Some(exporter.clone())).unwrap();
        let mut mechanism = ScramSha256Mechanism::new_plus("example.test".into(), bindings);

        let client_first_bare = "n=alice,r=clientnonce";
        let gs2_header = "p=tls-exporter,,";
        let initial = STANDARD.encode(format!("{gs2_header}{client_first_bare}"));
        assert!(matches!(
            mechanism.initial_response(&initial),
            SaslStep::NeedsCredentials(ref username) if username == "alice"
        ));
        let server_first = match mechanism.provide_credentials(
            salt.clone(),
            iterations,
            stored_key.clone(),
            server_key,
        ) {
            SaslStep::Challenge(challenge) => challenge,
            _ => panic!("SCRAM-PLUS did not produce a server-first challenge"),
        };
        let nonce = server_first
            .split(',')
            .find_map(|attribute| attribute.strip_prefix("r="))
            .unwrap();
        let mut cb_input = gs2_header.as_bytes().to_vec();
        cb_input.extend_from_slice(&exporter);
        let client_final_bare = format!("c={},r={nonce}", STANDARD.encode(cb_input));
        let auth_message = format!("{client_first_bare},{server_first},{client_final_bare}");
        let proof = scram_client_proof(password, &salt, iterations, &stored_key, &auth_message);
        let client_final =
            STANDARD.encode(format!("{client_final_bare},p={}", STANDARD.encode(proof)));

        assert!(matches!(
            mechanism.response(&client_final),
            SaslStep::Success(ref username, Some(ref final_data))
                if username == "alice" && final_data.starts_with("v=")
        ));
    }

    #[test]
    fn scram_sha256_plus_rejects_wrong_tls_binding_before_proof() {
        let salt = vec![3_u8; 32];
        let (stored_key, server_key) = compute_scram_sha256("password1234", &salt, 4096);
        let bindings = ChannelBindings::new(vec![7_u8; 32], Some(vec![8_u8; 32])).unwrap();
        let mut mechanism = ScramSha256Mechanism::new_plus("example.test".into(), bindings);
        let initial = STANDARD.encode("p=tls-exporter,,n=alice,r=clientnonce");
        assert!(matches!(
            mechanism.initial_response(&initial),
            SaslStep::NeedsCredentials(_)
        ));
        let challenge = match mechanism.provide_credentials(salt, 4096, stored_key, server_key) {
            SaslStep::Challenge(challenge) => challenge,
            _ => panic!("SCRAM-PLUS did not produce a server-first challenge"),
        };
        let nonce = challenge
            .split(',')
            .find_map(|attribute| attribute.strip_prefix("r="))
            .unwrap();
        let mut wrong = b"p=tls-exporter,,".to_vec();
        wrong.extend_from_slice(&[9_u8; 32]);
        let final_message = STANDARD.encode(format!(
            "c={},r={nonce},p={}",
            STANDARD.encode(wrong),
            STANDARD.encode([0_u8; 32])
        ));
        assert!(matches!(
            mechanism.response(&final_message),
            SaslStep::Failure(ref error) if error.contains("Channel binding")
        ));
    }

    #[test]
    fn scram_rejects_channel_binding_downgrade_signal() {
        let mut mechanism =
            ScramSha256Mechanism::new_with_channel_binding_support("example.test".into());
        let initial = STANDARD.encode("y,,n=alice,r=clientnonce");
        assert!(matches!(
            mechanism.initial_response(&initial),
            SaslStep::Failure(ref error) if error.contains("downgrade")
        ));
    }

    #[test]
    fn scram_bounds_nonce_and_rejects_mandatory_final_extensions() {
        let mut oversized = ScramSha256Mechanism::new("example.test".into());
        let initial = STANDARD.encode(format!("n,,n=alice,r={}", "x".repeat(1_025)));
        assert!(matches!(
            oversized.initial_response(&initial),
            SaslStep::Failure(ref error) if error.contains("nonce")
        ));

        let salt = vec![1_u8; 32];
        let (stored_key, server_key) = compute_scram_sha256("password1234", &salt, 4_096);
        let mut mechanism = ScramSha256Mechanism::new("example.test".into());
        let initial = STANDARD.encode("n,,n=alice,r=nonce");
        assert!(matches!(
            mechanism.initial_response(&initial),
            SaslStep::NeedsCredentials(_)
        ));
        let challenge = match mechanism.provide_credentials(salt, 4_096, stored_key, server_key) {
            SaslStep::Challenge(challenge) => challenge,
            _ => panic!("SCRAM did not produce a challenge"),
        };
        let nonce = challenge
            .split(',')
            .find_map(|attribute| attribute.strip_prefix("r="))
            .unwrap();
        let final_message = STANDARD.encode(format!(
            "c=biws,r={nonce},m=required,p={}",
            STANDARD.encode([0_u8; 32])
        ));
        assert!(matches!(
            mechanism.response(&final_message),
            SaslStep::Failure(ref error) if error.contains("mandatory")
        ));
    }

    #[test]
    fn scram_authorization_identity_uses_canonical_jid_comparison() {
        let mut mechanism = ScramSha256Mechanism::new("bücher.example".into());
        let initial = STANDARD.encode("n,a=A\u{30a}LICE@B\u{fc}CHER.Example,n=\u{e5}lice,r=nonce");
        assert!(matches!(
            mechanism.initial_response(&initial),
            SaslStep::NeedsCredentials(ref username) if username == "\u{e5}lice"
        ));
    }

    fn scram_client_proof(
        password: &str,
        salt: &[u8],
        iterations: u32,
        stored_key: &[u8],
        auth_message: &str,
    ) -> Vec<u8> {
        let mut salted_password = vec![0_u8; 32];
        pbkdf2::<Hmac<Sha256>>(password.as_bytes(), salt, iterations, &mut salted_password)
            .unwrap();
        let mut client_key_mac = Hmac::<Sha256>::new_from_slice(&salted_password).unwrap();
        client_key_mac.update(b"Client Key");
        let client_key = client_key_mac.finalize().into_bytes();
        let mut signature_mac = Hmac::<Sha256>::new_from_slice(stored_key).unwrap();
        signature_mac.update(auth_message.as_bytes());
        let client_signature = signature_mac.finalize().into_bytes();
        client_key
            .iter()
            .zip(client_signature)
            .map(|(key, signature)| key ^ signature)
            .collect()
    }
}
