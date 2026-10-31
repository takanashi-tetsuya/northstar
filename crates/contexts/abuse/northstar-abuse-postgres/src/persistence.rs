//! PostgreSQL implementation of the anti-abuse persistence port.

use crate::effects::AbuseEffects;
use crate::{actor_state, challenge_cleanup, challenge_issuance, message_admission, verification};
use northstar_abuse_application::guard::{
    AbuseGuard, AbusePersistence, AbusePersistenceFuture, FailurePolicy, IssueDecision,
    MessageAdmissionCandidate, MessageAdmissionStart, RequirementPolicy, VerificationPolicy,
};
use northstar_abuse_policy::admission_execution::AdmissionCommitObserver;
use northstar_abuse_policy::{MessageAdmissionRequest, MessageDedupeIdentity};
use sqlx::PgPool;
use uuid::Uuid;

pub struct PostgresAbusePersistence<E> {
    pool: PgPool,
    effects: E,
}

impl<E> PostgresAbusePersistence<E> {
    pub fn new(pool: PgPool, effects: E) -> Self {
        Self { pool, effects }
    }
}

impl<E: AbuseEffects> AbusePersistence for PostgresAbusePersistence<E> {
    fn issue<'a>(
        &'a self,
        request: northstar_abuse_application::guard::records::IssueRequest,
        decide: IssueDecision<'a>,
    ) -> AbusePersistenceFuture<'a, northstar_abuse_policy::PowChallenge> {
        Box::pin(async move { challenge_issuance::issue(&self.pool, request, decide).await })
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
            verification::verify(&self.pool, actor_state_keys, challenge_id, decide, witness).await
        })
    }

    fn current_requirement<'a>(
        &'a self,
        actor_state_keys: &'a [String],
        decide: RequirementPolicy<'a>,
    ) -> AbusePersistenceFuture<'a, northstar_abuse_policy::WorkRequirement> {
        Box::pin(async move {
            actor_state::current_requirement(&self.pool, actor_state_keys, decide).await
        })
    }

    fn record_failure<'a>(
        &'a self,
        actor_state_keys: &'a [String],
        decide: FailurePolicy<'a>,
    ) -> AbusePersistenceFuture<'a, ()> {
        Box::pin(
            async move { actor_state::record_failure(&self.pool, actor_state_keys, decide).await },
        )
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
            message_admission::begin_message_admission(
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
            challenge_cleanup::cleanup(&self.pool, &self.effects, window_seconds, stale_seconds)
                .await
        })
    }
}
