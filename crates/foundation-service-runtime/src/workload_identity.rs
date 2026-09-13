//! Provider-neutral SPIFFE/SVID workload identity validation.

use std::time::SystemTime;
use thiserror::Error;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustDomain(String);

impl TrustDomain {
    pub fn new(value: impl Into<String>) -> Result<Self, WorkloadIdentityError> {
        let value = value.into();
        if value.is_empty() || value.len() > 253 || !value.is_ascii() || value.contains('/') {
            return Err(WorkloadIdentityError::InvalidSpiffeId);
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpiffeId {
    trust_domain: TrustDomain,
    service: String,
    region: String,
    environment: String,
}

impl SpiffeId {
    pub fn new(
        trust_domain: TrustDomain,
        service: impl Into<String>,
        region: impl Into<String>,
        environment: impl Into<String>,
    ) -> Result<Self, WorkloadIdentityError> {
        let id = Self {
            trust_domain,
            service: service.into(),
            region: region.into(),
            environment: environment.into(),
        };
        id.validate()?
            .then_some(id)
            .ok_or(WorkloadIdentityError::InvalidSpiffeId)
    }

    fn validate(&self) -> Result<bool, WorkloadIdentityError> {
        let valid_segment = |value: &str| {
            !value.is_empty()
                && value.len() <= 128
                && value.is_ascii()
                && !value.contains('/')
                && !value.contains(|c: char| c.is_ascii_control() || c.is_whitespace())
        };
        if valid_segment(&self.service)
            && valid_segment(&self.region)
            && valid_segment(&self.environment)
        {
            Ok(true)
        } else {
            Ok(false)
        }
    }

    pub fn as_uri(&self) -> String {
        format!(
            "spiffe://{}/service/{}/{}/{}",
            self.trust_domain.as_str(),
            self.environment,
            self.region,
            self.service
        )
    }

    pub fn service(&self) -> &str {
        &self.service
    }
    pub fn region(&self) -> &str {
        &self.region
    }
    pub fn environment(&self) -> &str {
        &self.environment
    }
    pub fn trust_domain(&self) -> &TrustDomain {
        &self.trust_domain
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedWorkload {
    identity: SpiffeId,
    expires_at: SystemTime,
    certificate_serial: String,
}

impl VerifiedWorkload {
    pub fn new(
        identity: SpiffeId,
        expires_at: SystemTime,
        certificate_serial: impl Into<String>,
    ) -> Result<Self, WorkloadIdentityError> {
        let certificate_serial = certificate_serial.into();
        if certificate_serial.is_empty()
            || certificate_serial.len() > 128
            || !certificate_serial.is_ascii()
        {
            return Err(WorkloadIdentityError::InvalidCertificate);
        }
        Ok(Self {
            identity,
            expires_at,
            certificate_serial,
        })
    }

    pub fn validate_at(&self, now: SystemTime) -> Result<(), WorkloadIdentityError> {
        if now >= self.expires_at {
            Err(WorkloadIdentityError::ExpiredCertificate)
        } else {
            Ok(())
        }
    }

    pub fn identity(&self) -> &SpiffeId {
        &self.identity
    }
    pub fn certificate_serial(&self) -> &str {
        &self.certificate_serial
    }
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum WorkloadIdentityError {
    #[error("invalid SPIFFE trust domain or path")]
    InvalidSpiffeId,
    #[error("invalid certificate metadata")]
    InvalidCertificate,
    #[error("workload certificate is expired")]
    ExpiredCertificate,
    #[error("workload identity is outside the configured trust domain")]
    TrustDomainMismatch,
    #[error("workload identity is not allowed for this service")]
    ServiceNotAllowed,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn spiffe_identity_is_structured_and_expiry_is_fail_closed() {
        let domain = TrustDomain::new("northstar.test").unwrap();
        let id = SpiffeId::new(domain, "message-ingress", "us-east", "production").unwrap();
        assert_eq!(
            id.as_uri(),
            "spiffe://northstar.test/service/production/us-east/message-ingress"
        );
        let workload = VerifiedWorkload::new(id, SystemTime::UNIX_EPOCH, "01").unwrap();
        assert_eq!(
            workload.validate_at(SystemTime::UNIX_EPOCH),
            Err(WorkloadIdentityError::ExpiredCertificate)
        );
    }

    #[test]
    fn path_and_domain_inputs_are_bounded() {
        assert!(TrustDomain::new("northstar.test/path").is_err());
        assert!(SpiffeId::new(
            TrustDomain::new("northstar.test").unwrap(),
            "",
            "r1",
            "prod"
        )
        .is_err());
    }
}
