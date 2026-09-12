//! Public-key verification and rotation/grace-period policy.

use crate::{
    assertion::{AssertionClaims, AssertionError, MAX_ASSERTION_TTL_SECONDS},
    principal::VerifiedPrincipal,
};
use chrono::{DateTime, Duration, Utc};
use ring::signature;
use std::collections::BTreeMap;

#[derive(Clone)]
struct VerificationKey {
    algorithm: String,
    public_key: Vec<u8>,
    active_from: DateTime<Utc>,
    retire_at: Option<DateTime<Utc>>,
}

pub struct VerifyKeyRing {
    keys: BTreeMap<String, VerificationKey>,
    clock_skew: Duration,
}

impl Default for VerifyKeyRing {
    fn default() -> Self {
        Self::new(Duration::seconds(30))
    }
}

impl VerifyKeyRing {
    pub fn new(clock_skew: Duration) -> Self {
        Self {
            keys: BTreeMap::new(),
            clock_skew,
        }
    }

    pub fn insert_ed25519(
        &mut self,
        key_id: impl Into<String>,
        public_key: Vec<u8>,
        active_from: DateTime<Utc>,
        retire_at: Option<DateTime<Utc>>,
    ) -> Result<(), AssertionError> {
        if public_key.len() != 32 || retire_at.is_some_and(|until| until <= active_from) {
            return Err(AssertionError::UnsupportedAlgorithm);
        }
        let key_id = key_id.into();
        if key_id.trim().is_empty() || key_id.len() > 256 {
            return Err(AssertionError::UnknownKey);
        }
        self.keys.insert(
            key_id,
            VerificationKey {
                algorithm: "Ed25519".to_owned(),
                public_key,
                active_from,
                retire_at,
            },
        );
        Ok(())
    }

    pub fn verify(
        &self,
        claims: &AssertionClaims,
        expected_audience: &str,
        now: DateTime<Utc>,
    ) -> Result<VerifiedPrincipal, AssertionError> {
        claims.validate_claims(now, expected_audience, self.clock_skew.num_seconds())?;
        if claims.algorithm != "Ed25519" {
            return Err(AssertionError::UnsupportedAlgorithm);
        }
        let key = self
            .keys
            .get(&claims.key_id)
            .ok_or(AssertionError::UnknownKey)?;
        if key.algorithm != claims.algorithm
            || now + self.clock_skew < key.active_from
            || key
                .retire_at
                .is_some_and(|until| now - self.clock_skew >= until)
        {
            return Err(AssertionError::UnknownKey);
        }
        let verifier = signature::UnparsedPublicKey::new(&signature::ED25519, &key.public_key);
        verifier
            .verify(
                &claims.canonical_bytes_without_signature(),
                &claims.signature,
            )
            .map_err(|_| AssertionError::SignatureMismatch)?;
        Ok(VerifiedPrincipal::from_claims(claims))
    }

    pub fn max_lifetime_seconds(&self) -> i64 {
        MAX_ASSERTION_TTL_SECONDS
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ring::signature::{Ed25519KeyPair, KeyPair};

    fn unsigned_claims(now: DateTime<Utc>) -> AssertionClaims {
        AssertionClaims {
            issuer: "identity".to_owned(),
            audience: "message-ingress".to_owned(),
            issued_at: now - Duration::seconds(1),
            not_before: now - Duration::seconds(1),
            expires_at: now + Duration::seconds(60),
            jwt_id: "jti-1".to_owned(),
            schema_version: 1,
            account_id: "acc-1".to_owned(),
            bare_jid: "alice@example.com".to_owned(),
            credential_generation: 2,
            session_epoch: 3,
            region_epoch: 4,
            key_id: "key-1".to_owned(),
            algorithm: "Ed25519".to_owned(),
            signature: Vec::new(),
            scopes: vec!["xmpp:message".to_owned()],
            roles: Vec::new(),
        }
    }

    #[test]
    fn verifies_ed25519_and_constructs_principal() {
        let now = Utc::now();
        let seed = [7u8; 32];
        let pair = Ed25519KeyPair::from_seed_unchecked(&seed).unwrap();
        let mut claims = unsigned_claims(now);
        claims.signature = pair
            .sign(&claims.canonical_bytes_without_signature())
            .as_ref()
            .to_vec();
        let mut ring = VerifyKeyRing::default();
        ring.insert_ed25519(
            "key-1",
            pair.public_key().as_ref().to_vec(),
            now - Duration::hours(1),
            None,
        )
        .unwrap();
        let principal = ring.verify(&claims, "message-ingress", now).unwrap();
        assert_eq!(principal.account_id(), "acc-1");
        assert!(principal.has_scope("xmpp:message"));
    }

    #[test]
    fn bit_flip_unknown_algorithm_and_retired_key_fail_closed() {
        let now = Utc::now();
        let pair = Ed25519KeyPair::from_seed_unchecked(&[8u8; 32]).unwrap();
        let mut claims = unsigned_claims(now);
        claims.signature = pair
            .sign(&claims.canonical_bytes_without_signature())
            .as_ref()
            .to_vec();
        let mut ring = VerifyKeyRing::default();
        ring.insert_ed25519(
            "key-1",
            pair.public_key().as_ref().to_vec(),
            now - Duration::hours(1),
            Some(now + Duration::seconds(1)),
        )
        .unwrap();
        let mut tampered = claims.clone();
        tampered.account_id = "attacker".to_owned();
        assert_eq!(
            ring.verify(&tampered, "message-ingress", now),
            Err(AssertionError::SignatureMismatch)
        );
        let mut unknown_alg = claims.clone();
        unknown_alg.algorithm = "HS256".to_owned();
        assert_eq!(
            ring.verify(&unknown_alg, "message-ingress", now),
            Err(AssertionError::UnsupportedAlgorithm)
        );
        assert_eq!(
            ring.verify(&claims, "message-ingress", now + Duration::seconds(40)),
            Err(AssertionError::UnknownKey)
        );
    }
}
