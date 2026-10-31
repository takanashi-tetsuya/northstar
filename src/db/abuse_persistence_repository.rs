//! PostgreSQL implementation of the anti-abuse persistence port.

use crate::db::{
    abuse_actor_state_repository, abuse_challenge_issuance_repository,
    abuse_verification_repository, challenge_cleanup_repository, message_admission_repository,
};
use northstar_abuse_application::guard::{
    AbuseGuard, AbusePersistence, AbusePersistenceFuture, FailurePolicy, IssueDecision,
    MessageAdmissionCandidate, MessageAdmissionStart, RequirementPolicy, VerificationPolicy,
};
use northstar_abuse_policy::admission_execution::AdmissionCommitObserver;
use northstar_abuse_policy::{MessageAdmissionRequest, MessageDedupeIdentity};
use sqlx::PgPool;
use uuid::Uuid;

pub(crate) struct PostgresAbusePersistence {
    pool: PgPool,
}

impl PostgresAbusePersistence {
    pub(crate) fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

impl AbusePersistence for PostgresAbusePersistence {
    fn issue<'a>(
        &'a self,
        request: northstar_abuse_application::guard::records::IssueRequest,
        decide: IssueDecision<'a>,
    ) -> AbusePersistenceFuture<'a, northstar_abuse_policy::PowChallenge> {
        Box::pin(async move {
            abuse_challenge_issuance_repository::issue(&self.pool, request, decide).await
        })
    }

    fn verify<'a>(
        &'a self,
        actor_state_keys: &'a [String],
        challenge_id: Option<Uuid>,
        decide: VerificationPolicy<'a>,
        witness: Option<&'a dyn AdmissionCommitObserver>,
    ) -> AbusePersistenceFuture<
        'a,
        std::result::Result<
            northstar_abuse_policy::WorkRequirement,
            northstar_abuse_policy::GuardError,
        >,
    > {
        Box::pin(async move {
            abuse_verification_repository::verify(
                &self.pool,
                actor_state_keys,
                challenge_id,
                decide,
                witness,
            )
            .await
        })
    }

    fn current_requirement<'a>(
        &'a self,
        actor_state_keys: &'a [String],
        decide: RequirementPolicy<'a>,
    ) -> AbusePersistenceFuture<'a, northstar_abuse_policy::WorkRequirement> {
        Box::pin(async move {
            abuse_actor_state_repository::current_requirement(&self.pool, actor_state_keys, decide)
                .await
        })
    }

    fn record_failure<'a>(
        &'a self,
        actor_state_keys: &'a [String],
        decide: FailurePolicy<'a>,
    ) -> AbusePersistenceFuture<'a, ()> {
        Box::pin(async move {
            abuse_actor_state_repository::record_failure(&self.pool, actor_state_keys, decide).await
        })
    }

    fn begin_message_admission<'a, 'r: 'a>(
        &'a self,
        guard: &'a AbuseGuard,
        request: &'a MessageAdmissionRequest<'r>,
        candidates: &'a [MessageAdmissionCandidate],
        offline_dedupe: MessageDedupeIdentity,
        witness: &'a dyn AdmissionCommitObserver,
    ) -> AbusePersistenceFuture<'a, MessageAdmissionStart> {
        Box::pin(async move {
            message_admission_repository::begin_message_admission(
                &self.pool,
                guard,
                request,
                candidates,
                offline_dedupe,
                witness,
            )
            .await
        })
    }

    fn cleanup<'a>(
        &'a self,
        window_seconds: u64,
        stale_seconds: u64,
    ) -> AbusePersistenceFuture<'a, ()> {
        Box::pin(async move {
            challenge_cleanup_repository::cleanup(&self.pool, window_seconds, stale_seconds).await
        })
    }
}

/// A guard over this adapter for tests, keeping every durable artifact on the current key.
#[cfg(test)]
pub(crate) fn persistent_guard(
    config: northstar_abuse_policy::AbuseConfig,
    pool: PgPool,
    shared_secret: Option<&[u8]>,
    previous_shared_secret: Option<&[u8]>,
) -> AbuseGuard {
    AbuseGuard::new_persistent_for_deployment(
        config,
        std::sync::Arc::new(PostgresAbusePersistence::new(pool)),
        shared_secret,
        previous_shared_secret,
        false,
        Some(chrono::DateTime::<chrono::Utc>::MAX_UTC),
    )
}
