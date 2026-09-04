//! Canonical, transport-neutral assertion claims.
//!
//! This module deliberately does not depend on Protobuf or a private key
//! store.  Wire adapters translate into these claims and the keyring verifies
//! them.  Keeping the canonical bytes here prevents algorithm/serialization
//! confusion between services.

use chrono::{DateTime, Utc};

pub const MAX_ASSERTION_TTL_SECONDS: i64 = 300;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AssertionClaims {
    pub issuer: String,
    pub audience: String,
    pub issued_at: DateTime<Utc>,
    pub not_before: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub jwt_id: String,
    pub schema_version: u32,
    pub account_id: String,
    pub bare_jid: String,
    pub credential_generation: u64,
    pub session_epoch: u64,
    pub region_epoch: u64,
    pub key_id: String,
    pub algorithm: String,
    pub signature: Vec<u8>,
    pub scopes: Vec<String>,
    pub roles: Vec<String>,
}

impl AssertionClaims {
    /// Stable length-prefixed canonical representation with the signature
    /// omitted.  Length prefixes prevent concatenation ambiguity.
    pub fn canonical_bytes_without_signature(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(512);
        for value in [
            self.issuer.as_bytes(),
            self.audience.as_bytes(),
            self.jwt_id.as_bytes(),
            self.account_id.as_bytes(),
            self.bare_jid.as_bytes(),
            self.key_id.as_bytes(),
            self.algorithm.as_bytes(),
        ] {
            out.extend_from_slice(&(value.len() as u32).to_be_bytes());
            out.extend_from_slice(value);
        }
        for timestamp in [self.issued_at, self.not_before, self.expires_at] {
            out.extend_from_slice(&timestamp.timestamp_millis().to_be_bytes());
        }
        for value in [
            self.schema_version as u64,
            self.credential_generation,
            self.session_epoch,
            self.region_epoch,
        ] {
            out.extend_from_slice(&value.to_be_bytes());
        }
        for values in [&self.scopes, &self.roles] {
            out.extend_from_slice(&(values.len() as u32).to_be_bytes());
            for value in values {
                out.extend_from_slice(&(value.len() as u32).to_be_bytes());
                out.extend_from_slice(value.as_bytes());
            }
        }
        out
    }

    pub fn validate_claims(
        &self,
        now: DateTime<Utc>,
        expected_audience: &str,
        clock_skew_seconds: i64,
    ) -> Result<(), AssertionError> {
        if self.issuer.trim().is_empty()
            || self.audience.trim().is_empty()
            || self.jwt_id.trim().is_empty()
            || self.account_id.trim().is_empty()
            || self.bare_jid.trim().is_empty()
            || self.key_id.trim().is_empty()
            || self.algorithm.trim().is_empty()
        {
            return Err(AssertionError::MissingField);
        }
        if self.audience != expected_audience {
            return Err(AssertionError::AudienceMismatch);
        }
        if self.schema_version != 1 {
            return Err(AssertionError::UnsupportedSchema);
        }
        if self.issued_at > self.not_before || self.not_before > self.expires_at {
            return Err(AssertionError::InvalidWindow);
        }
        if self
            .expires_at
            .signed_duration_since(self.issued_at)
            .num_seconds()
            > MAX_ASSERTION_TTL_SECONDS
        {
            return Err(AssertionError::LifetimeTooLong);
        }
        let skew = chrono::Duration::seconds(clock_skew_seconds.max(0));
        if now + skew < self.not_before || now - skew >= self.expires_at {
            return Err(AssertionError::ExpiredOrNotYetValid);
        }
        if self.signature.is_empty() || self.signature.len() > 4096 {
            return Err(AssertionError::InvalidSignature);
        }
        if self.scopes.len() > 64 || self.roles.len() > 64 {
            return Err(AssertionError::TooManyClaims);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AssertionError {
    MissingField,
    AudienceMismatch,
    UnsupportedSchema,
    InvalidWindow,
    LifetimeTooLong,
    ExpiredOrNotYetValid,
    InvalidSignature,
    UnknownKey,
    UnsupportedAlgorithm,
    SignatureMismatch,
    TooManyClaims,
    Replay,
    ReplayCapacity,
}
