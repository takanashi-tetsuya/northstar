//! Provider-neutral KMS/HSM boundaries.
//!
//! Services receive opaque provider handles and short-lived signatures.  They
//! never receive a master key or read a key file from configuration.  The
//! optional `memory` provider exists only for local tests and is intentionally
//! not enabled by default.

use chrono::{DateTime, Utc};
use thiserror::Error;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum KeyClass {
    Assertion,
    RegistrySnapshot,
    AuditCheckpoint,
    UploadToken,
    DataEnvelope,
    Dialback,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyState {
    Creating,
    Active,
    Retired,
    Revoked,
    Destroyed,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyMetadata {
    pub key_id: String,
    pub class: KeyClass,
    pub algorithm: String,
    pub owner_service: String,
    pub region: String,
    pub environment: String,
    pub created_at: DateTime<Utc>,
    pub rotation_due_at: DateTime<Utc>,
    pub state: KeyState,
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum KmsError {
    #[error("key is not available for this operation")]
    KeyUnavailable,
    #[error("key metadata is invalid")]
    InvalidMetadata,
    #[error("provider rejected the operation")]
    ProviderRejected,
    #[error("development memory provider is disabled")]
    MemoryProviderDisabled,
}

/// Signing boundary.  Implementations may be backed by KMS, HSM or a
/// workload-identity signer; the caller never receives private key material.
pub trait Signer: Send + Sync {
    fn sign(&self, key_id: &str, payload: &[u8]) -> Result<Vec<u8>, KmsError>;
}

pub trait AeadKeyProvider: Send + Sync {
    fn seal(
        &self,
        key_id: &str,
        associated_data: &[u8],
        plaintext: &[u8],
    ) -> Result<Vec<u8>, KmsError>;
    fn open(
        &self,
        key_id: &str,
        associated_data: &[u8],
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, KmsError>;
}

pub trait HmacKeyProvider: Send + Sync {
    fn mac(&self, key_id: &str, payload: &[u8]) -> Result<Vec<u8>, KmsError>;
    fn verify(&self, key_id: &str, payload: &[u8], mac: &[u8]) -> Result<(), KmsError>;
}

/// Lifecycle metadata is kept separate from key bytes and can be persisted by
/// a control plane.  The state machine is monotonic and fail-closed.
pub fn validate_transition(from: KeyState, to: KeyState) -> Result<(), KmsError> {
    let allowed = matches!(
        (from, to),
        (KeyState::Creating, KeyState::Active)
            | (KeyState::Active, KeyState::Retired)
            | (KeyState::Active, KeyState::Revoked)
            | (KeyState::Retired, KeyState::Revoked)
            | (KeyState::Revoked, KeyState::Destroyed)
            | (KeyState::Retired, KeyState::Destroyed)
    );
    allowed.then_some(()).ok_or(KmsError::InvalidMetadata)
}

#[cfg(feature = "memory")]
pub mod memory {
    use super::*;
    use ring::hmac;
    use std::collections::HashMap;
    use std::sync::RwLock;
    use zeroize::Zeroizing;

    /// Development-only HMAC provider.  It is not available in default or
    /// production feature sets and must never be used for release signing.
    pub struct InMemoryHmacProvider {
        keys: RwLock<HashMap<String, Zeroizing<Vec<u8>>>>,
    }

    impl InMemoryHmacProvider {
        pub fn new() -> Self {
            Self {
                keys: RwLock::new(HashMap::new()),
            }
        }

        pub fn insert_for_test(&self, key_id: impl Into<String>, key: Vec<u8>) {
            self.keys
                .write()
                .unwrap()
                .insert(key_id.into(), Zeroizing::new(key));
        }
    }

    impl Default for InMemoryHmacProvider {
        fn default() -> Self {
            Self::new()
        }
    }

    impl HmacKeyProvider for InMemoryHmacProvider {
        fn mac(&self, key_id: &str, payload: &[u8]) -> Result<Vec<u8>, KmsError> {
            let keys = self.keys.read().unwrap();
            let key = keys.get(key_id).ok_or(KmsError::KeyUnavailable)?;
            Ok(hmac::sign(&hmac::Key::new(hmac::HMAC_SHA256, key), payload)
                .as_ref()
                .to_vec())
        }

        fn verify(&self, key_id: &str, payload: &[u8], mac: &[u8]) -> Result<(), KmsError> {
            let keys = self.keys.read().unwrap();
            let key = keys.get(key_id).ok_or(KmsError::KeyUnavailable)?;
            hmac::verify(&hmac::Key::new(hmac::HMAC_SHA256, key), payload, mac)
                .map_err(|_| KmsError::ProviderRejected)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lifecycle_is_monotonic_and_rejects_reactivation() {
        assert!(validate_transition(KeyState::Creating, KeyState::Active).is_ok());
        assert!(validate_transition(KeyState::Active, KeyState::Retired).is_ok());
        assert!(validate_transition(KeyState::Retired, KeyState::Destroyed).is_ok());
        assert_eq!(
            validate_transition(KeyState::Retired, KeyState::Active),
            Err(KmsError::InvalidMetadata)
        );
    }

    #[cfg(feature = "memory")]
    #[test]
    fn development_provider_round_trips_and_rejects_tampering() {
        let provider = memory::InMemoryHmacProvider::new();
        provider.insert_for_test("test", vec![7u8; 32]);
        let mac = provider.mac("test", b"payload").unwrap();
        assert!(provider.verify("test", b"payload", &mac).is_ok());
        assert_eq!(
            provider.verify("test", b"tampered", &mac),
            Err(KmsError::ProviderRejected)
        );
    }
}
