//! Domain-side signed authorization assertions.
//!
//! These values are intentionally separate from the generated wire messages.
//! Signature verification and key lookup belong to the security runtime; this
//! module enforces structural, audience, and lifetime invariants before a
//! verifier or service can consume an assertion.

use chrono::{DateTime, Utc};
use prost::Message;
use serde::{Deserialize, Serialize};
use thiserror::Error;

pub const MAX_ASSERTION_TTL_SECONDS: i64 = 300;

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum AssertionValidationError {
    #[error("assertion field is missing: {0}")]
    MissingField(&'static str),
    #[error("assertion field is invalid: {0}")]
    InvalidField(&'static str),
    #[error("assertion audience does not match the requested service")]
    AudienceMismatch,
    #[error("assertion is outside its validity window")]
    NotCurrentlyValid,
    #[error("assertion lifetime exceeds the maximum")]
    LifetimeTooLong,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthGrant {
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
    pub auth_method: String,
    pub auth_strength: String,
    pub channel_binding: String,
    pub key_id: String,
    pub algorithm: String,
    pub signature: Vec<u8>,
    pub scopes: Vec<String>,
}

impl AuthGrant {
    pub fn validate_at(
        &self,
        now: DateTime<Utc>,
        expected_audience: &str,
    ) -> Result<(), AssertionValidationError> {
        validate_common(
            &self.issuer,
            &self.audience,
            &self.issued_at,
            &self.not_before,
            &self.expires_at,
            &self.jwt_id,
            self.schema_version,
            &self.key_id,
            &self.algorithm,
            &self.signature,
            now,
            expected_audience,
        )?;
        required(&self.account_id, "account_id")?;
        required(&self.bare_jid, "bare_jid")?;
        required(&self.auth_method, "auth_method")?;
        required(&self.auth_strength, "auth_strength")?;
        validate_scopes(&self.scopes)?;
        Ok(())
    }

    /// Canonical bytes to sign/verify: signature is omitted from the payload.
    pub fn canonical_bytes_without_signature(&self) -> Vec<u8> {
        let wire: crate::northstar::security::v1::AuthGrant = self.clone().into();
        let mut unsigned = wire;
        unsigned.signature.clear();
        unsigned.encode_to_vec()
    }

    /// Applies the runtime key-rotation allow-list after structural checks.
    /// Unknown key IDs fail closed instead of falling back to an older key.
    pub fn require_known_key(
        &self,
        known_key_ids: &[&str],
    ) -> Result<(), AssertionValidationError> {
        if known_key_ids
            .iter()
            .any(|candidate| *candidate == self.key_id)
        {
            Ok(())
        } else {
            Err(AssertionValidationError::InvalidField("key_id"))
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionAssertion {
    pub issuer: String,
    pub audience: String,
    pub issued_at: DateTime<Utc>,
    pub not_before: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub jwt_id: String,
    pub schema_version: u32,
    pub account_id: String,
    pub bare_jid: String,
    pub full_jid: String,
    pub connection_id: String,
    pub edge_instance_id: String,
    pub session_epoch: u64,
    pub credential_generation: u64,
    pub home_region: String,
    pub region_epoch: u64,
    pub key_id: String,
    pub algorithm: String,
    pub signature: Vec<u8>,
    pub scopes: Vec<String>,
    pub roles: Vec<String>,
}

impl SessionAssertion {
    pub fn validate_at(
        &self,
        now: DateTime<Utc>,
        expected_audience: &str,
    ) -> Result<(), AssertionValidationError> {
        validate_common(
            &self.issuer,
            &self.audience,
            &self.issued_at,
            &self.not_before,
            &self.expires_at,
            &self.jwt_id,
            self.schema_version,
            &self.key_id,
            &self.algorithm,
            &self.signature,
            now,
            expected_audience,
        )?;
        for (value, field) in [
            (&self.account_id, "account_id"),
            (&self.bare_jid, "bare_jid"),
            (&self.full_jid, "full_jid"),
            (&self.connection_id, "connection_id"),
            (&self.edge_instance_id, "edge_instance_id"),
            (&self.home_region, "home_region"),
        ] {
            required(value, field)?;
        }
        validate_scopes(&self.scopes)?;
        validate_scopes(&self.roles)?;
        Ok(())
    }

    pub fn canonical_bytes_without_signature(&self) -> Vec<u8> {
        let wire: crate::northstar::security::v1::SessionAssertion = self.clone().into();
        let mut unsigned = wire;
        unsigned.signature.clear();
        unsigned.encode_to_vec()
    }

    /// Applies the runtime key-rotation allow-list after structural checks.
    pub fn require_known_key(
        &self,
        known_key_ids: &[&str],
    ) -> Result<(), AssertionValidationError> {
        if known_key_ids
            .iter()
            .any(|candidate| *candidate == self.key_id)
        {
            Ok(())
        } else {
            Err(AssertionValidationError::InvalidField("key_id"))
        }
    }
}

fn required(value: &str, field: &'static str) -> Result<(), AssertionValidationError> {
    if value.trim().is_empty() {
        return Err(AssertionValidationError::MissingField(field));
    }
    if value.len() > 512 {
        return Err(AssertionValidationError::InvalidField(field));
    }
    Ok(())
}

fn validate_scopes(values: &[String]) -> Result<(), AssertionValidationError> {
    if values.len() > 64 {
        return Err(AssertionValidationError::InvalidField("scopes"));
    }
    for value in values {
        required(value, "scope")?;
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn validate_common(
    issuer: &str,
    audience: &str,
    issued_at: &DateTime<Utc>,
    not_before: &DateTime<Utc>,
    expires_at: &DateTime<Utc>,
    jwt_id: &str,
    schema_version: u32,
    key_id: &str,
    algorithm: &str,
    signature: &[u8],
    now: DateTime<Utc>,
    expected_audience: &str,
) -> Result<(), AssertionValidationError> {
    required(issuer, "issuer")?;
    required(audience, "audience")?;
    required(jwt_id, "jti")?;
    required(key_id, "key_id")?;
    required(algorithm, "alg")?;
    required(expected_audience, "expected_audience")?;
    if audience != expected_audience {
        return Err(AssertionValidationError::AudienceMismatch);
    }
    if schema_version != 1 {
        return Err(AssertionValidationError::InvalidField("schema_version"));
    }
    if issued_at > not_before || not_before > expires_at {
        return Err(AssertionValidationError::InvalidField("validity window"));
    }
    if expires_at.signed_duration_since(*issued_at).num_seconds() > MAX_ASSERTION_TTL_SECONDS {
        return Err(AssertionValidationError::LifetimeTooLong);
    }
    if now < *not_before || now >= *expires_at {
        return Err(AssertionValidationError::NotCurrentlyValid);
    }
    if signature.is_empty() || signature.len() > 4096 {
        return Err(AssertionValidationError::InvalidField("signature"));
    }
    Ok(())
}
