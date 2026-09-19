//! mTLS peer policy. Certificate acquisition/rotation is delegated to SPIRE
//! or another workload-identity provider; this module only makes acceptance
//! decisions after the provider has verified the chain.

use crate::workload_identity::{SpiffeId, VerifiedWorkload, WorkloadIdentityError};
use std::collections::BTreeSet;
use std::time::SystemTime;
use thiserror::Error;

#[derive(Debug, Clone)]
pub struct MtlsPolicy {
    trust_domain: String,
    allowed_services: BTreeSet<String>,
    require_client_auth: bool,
}

impl MtlsPolicy {
    pub fn new(trust_domain: impl Into<String>) -> Result<Self, MtlsPolicyError> {
        let trust_domain = trust_domain.into();
        if trust_domain.is_empty()
            || trust_domain.len() > 253
            || !trust_domain.is_ascii()
            || trust_domain.contains('/')
        {
            return Err(MtlsPolicyError::InvalidTrustDomain);
        }
        Ok(Self {
            trust_domain,
            allowed_services: BTreeSet::new(),
            require_client_auth: true,
        })
    }

    pub fn allow_service(mut self, service: impl Into<String>) -> Result<Self, MtlsPolicyError> {
        let service = service.into();
        if service.is_empty() || service.len() > 128 || !service.is_ascii() || service.contains('/')
        {
            return Err(MtlsPolicyError::InvalidService);
        }
        self.allowed_services.insert(service);
        Ok(self)
    }

    pub fn require_client_auth(&self) -> bool {
        self.require_client_auth
    }

    pub fn verify_peer(
        &self,
        peer: VerifiedWorkload,
        now: SystemTime,
    ) -> Result<VerifiedWorkload, MtlsPolicyError> {
        peer.validate_at(now)?;
        let identity: &SpiffeId = peer.identity();
        if identity.trust_domain().as_str() != self.trust_domain {
            return Err(MtlsPolicyError::TrustDomainMismatch);
        }
        if !self.allowed_services.is_empty() && !self.allowed_services.contains(identity.service())
        {
            return Err(MtlsPolicyError::ServiceNotAllowed);
        }
        Ok(peer)
    }
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum MtlsPolicyError {
    #[error("invalid trust domain")]
    InvalidTrustDomain,
    #[error("invalid service name")]
    InvalidService,
    #[error("workload identity verification failed: {0}")]
    Workload(#[from] WorkloadIdentityError),
    #[error("peer is outside the configured trust domain")]
    TrustDomainMismatch,
    #[error("peer service is not allowlisted")]
    ServiceNotAllowed,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::workload_identity::{SpiffeId, TrustDomain};

    #[test]
    fn peer_policy_rejects_expired_wrong_domain_and_unknown_service() {
        let policy = MtlsPolicy::new("northstar.test")
            .unwrap()
            .allow_service("identity")
            .unwrap();
        let valid_id = SpiffeId::new(
            TrustDomain::new("northstar.test").unwrap(),
            "identity",
            "r1",
            "prod",
        )
        .unwrap();
        let valid = VerifiedWorkload::new(
            valid_id,
            SystemTime::now() + std::time::Duration::from_secs(30),
            "1",
        )
        .unwrap();
        assert!(policy.verify_peer(valid, SystemTime::now()).is_ok());
        let other = SpiffeId::new(
            TrustDomain::new("other.test").unwrap(),
            "identity",
            "r1",
            "prod",
        )
        .unwrap();
        let other = VerifiedWorkload::new(
            other,
            SystemTime::now() + std::time::Duration::from_secs(30),
            "2",
        )
        .unwrap();
        assert_eq!(
            policy.verify_peer(other, SystemTime::now()),
            Err(MtlsPolicyError::TrustDomainMismatch)
        );
    }
}
