//! Login-specific anti-abuse capabilities for SASL and Passkeys.

use anyhow::Result;
use northstar_abuse_policy::{GuardError, PowIntent, PowProof, WorkRequirement};
use std::future::Future;

pub trait SaslLoginAbuseRepository: Send + Sync {
    fn current_requirement(
        &self,
        actors: &[String],
    ) -> impl Future<Output = Result<WorkRequirement>> + Send;
    fn record_failure(&self, actors: &[String]) -> impl Future<Output = Result<()>> + Send;
}

pub struct SaslLoginAbuseService<R> {
    repository: R,
}

impl<R: SaslLoginAbuseRepository> SaslLoginAbuseService<R> {
    pub fn new(repository: R) -> Self {
        Self { repository }
    }

    pub async fn is_limited(&self, actors: &[String]) -> Result<bool> {
        let requirement = self.repository.current_requirement(actors).await?;
        Ok(requirement.work_factor > 1 || requirement.retry_after_seconds > 0)
    }

    pub async fn record_failure(&self, actors: &[String]) -> Result<()> {
        self.repository.record_failure(actors).await
    }
}

pub trait PasskeyLoginAbuseRepository: Send + Sync {
    fn verify(
        &self,
        subject: &str,
        actors: &[String],
        proof: Option<&PowProof>,
        intent: &PowIntent,
    ) -> impl Future<Output = Result<std::result::Result<WorkRequirement, GuardError>>> + Send;
}

pub struct PasskeyLoginAbuseService<R> {
    repository: R,
}

impl<R: PasskeyLoginAbuseRepository> PasskeyLoginAbuseService<R> {
    pub fn new(repository: R) -> Self {
        Self { repository }
    }

    pub async fn verify(
        &self,
        subject: &str,
        actors: &[String],
        proof: Option<&PowProof>,
        intent: &PowIntent,
    ) -> Result<std::result::Result<WorkRequirement, GuardError>> {
        self.repository.verify(subject, actors, proof, intent).await
    }
}
