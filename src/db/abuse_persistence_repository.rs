//! PostgreSQL implementation of the anti-abuse persistence port.

use crate::{
    abuse::{
        AbuseGuard, AbusePersistence, AbusePersistenceFuture, FailurePolicy, IssueDecision,
        MessageAdmissionCandidate, MessageAdmissionRequest, MessageAdmissionStart,
        MessageDedupeIdentity, RequirementPolicy, VerificationPolicy,
    },
    db::{
        abuse_actor_state_repository, abuse_challenge_issuance_repository,
        abuse_verification_repository, challenge_cleanup_repository, message_admission_repository,
    },
};
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
        request: abuse_challenge_issuance_repository::IssueRequest,
        decide: IssueDecision<'a>,
    ) -> AbusePersistenceFuture<'a, crate::abuse::PowChallenge> {
        Box::pin(async move {
            abuse_challenge_issuance_repository::issue(&self.pool, request, decide).await
        })
    }

    fn verify<'a>(
        &'a self,
        actor_state_keys: &'a [String],
        challenge_id: Option<Uuid>,
        decide: VerificationPolicy<'a>,
    ) -> AbusePersistenceFuture<
        'a,
        std::result::Result<crate::abuse::WorkRequirement, crate::abuse::GuardError>,
    > {
        Box::pin(async move {
            abuse_verification_repository::verify(
                &self.pool,
                actor_state_keys,
                challenge_id,
                decide,
            )
            .await
        })
    }

    fn current_requirement<'a>(
        &'a self,
        actor_state_keys: &'a [String],
        decide: RequirementPolicy<'a>,
    ) -> AbusePersistenceFuture<'a, crate::abuse::WorkRequirement> {
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
    ) -> AbusePersistenceFuture<'a, MessageAdmissionStart> {
        Box::pin(async move {
            message_admission_repository::begin_message_admission(
                &self.pool,
                guard,
                request,
                candidates,
                offline_dedupe,
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
