//! PostgreSQL-backed login abuse adapters with distinct SASL and Passkey grants.

use anyhow::Result;
use northstar_abuse_application::guard::AbuseGuard;
use northstar_abuse_application::login::{PasskeyLoginAbuseRepository, SaslLoginAbuseRepository};
use northstar_abuse_policy::{AbuseAction, GuardError, PowIntent, PowProof, WorkRequirement};
use std::sync::Arc;

pub(crate) struct PostgresSaslLoginAbuseRepository {
    guard: Arc<AbuseGuard>,
}

impl PostgresSaslLoginAbuseRepository {
    pub(crate) fn new(guard: Arc<AbuseGuard>) -> Self {
        Self { guard }
    }
}

impl SaslLoginAbuseRepository for PostgresSaslLoginAbuseRepository {
    async fn current_requirement(&self, actors: &[String]) -> Result<WorkRequirement> {
        self.guard
            .current_requirement(AbuseAction::Login, actors)
            .await
    }

    async fn record_failure(&self, actors: &[String]) -> Result<()> {
        self.guard.record_failure(AbuseAction::Login, actors).await
    }
}

pub(crate) struct PostgresPasskeyLoginAbuseRepository {
    guard: Arc<AbuseGuard>,
}

impl PostgresPasskeyLoginAbuseRepository {
    pub(crate) fn new(guard: Arc<AbuseGuard>) -> Self {
        Self { guard }
    }
}

impl PasskeyLoginAbuseRepository for PostgresPasskeyLoginAbuseRepository {
    async fn verify(
        &self,
        subject: &str,
        actors: &[String],
        proof: Option<&PowProof>,
        intent: &PowIntent,
    ) -> Result<std::result::Result<WorkRequirement, GuardError>> {
        self.guard
            .verify_or_allow_v2(AbuseAction::Login, subject, actors, proof, intent)
            .await
    }
}
