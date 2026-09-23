//! Login-specific anti-abuse capabilities for SASL and Passkeys.

use crate::abuse::{GuardError, PowIntent, PowProof, WorkRequirement};
use anyhow::Result;
use std::future::Future;

pub(crate) trait SaslLoginAbuseRepository: Send + Sync {
    fn current_requirement(
        &self,
        actors: &[String],
    ) -> impl Future<Output = Result<WorkRequirement>> + Send;
    fn record_failure(&self, actors: &[String]) -> impl Future<Output = Result<()>> + Send;
}

pub(crate) struct SaslLoginAbuseService<R> {
    repository: R,
}

impl<R: SaslLoginAbuseRepository> SaslLoginAbuseService<R> {
    pub(crate) fn new(repository: R) -> Self {
        Self { repository }
    }

    pub(crate) async fn is_limited(&self, actors: &[String]) -> Result<bool> {
        let requirement = self.repository.current_requirement(actors).await?;
        Ok(requirement.work_factor > 1 || requirement.retry_after_seconds > 0)
    }

    pub(crate) async fn record_failure(&self, actors: &[String]) -> Result<()> {
        self.repository.record_failure(actors).await
    }
}

pub(crate) trait PasskeyLoginAbuseRepository: Send + Sync {
    fn verify(
        &self,
        subject: &str,
        actors: &[String],
        proof: Option<&PowProof>,
        intent: &PowIntent,
    ) -> impl Future<Output = Result<std::result::Result<WorkRequirement, GuardError>>> + Send;
}

pub(crate) struct PasskeyLoginAbuseService<R> {
    repository: R,
}

impl<R: PasskeyLoginAbuseRepository> PasskeyLoginAbuseService<R> {
    pub(crate) fn new(repository: R) -> Self {
        Self { repository }
    }

    pub(crate) async fn verify(
        &self,
        subject: &str,
        actors: &[String],
        proof: Option<&PowProof>,
        intent: &PowIntent,
    ) -> Result<std::result::Result<WorkRequirement, GuardError>> {
        self.repository.verify(subject, actors, proof, intent).await
    }
}
