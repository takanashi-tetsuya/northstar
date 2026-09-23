//! Atomic journal authorization and target point-of-no-return transition.
//! The transaction is committed before the caller may start an effect.

use crate::db::{self, OperationLease, OperationTargetLease};
use crate::services::operation_effect_fence::{
    EffectFenceDecision, OperationEffectFenceRepository,
};
use anyhow::Result;
use sqlx::PgPool;

pub(crate) struct PostgresOperationEffectFenceRepository {
    pool: PgPool,
}

impl PostgresOperationEffectFenceRepository {
    pub(crate) fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

impl OperationEffectFenceRepository for PostgresOperationEffectFenceRepository {
    type Parent = OperationLease;
    type Target = OperationTargetLease;

    async fn commit_fence(
        &self,
        parent: &OperationLease,
        target: &OperationTargetLease,
    ) -> Result<EffectFenceDecision> {
        let mut fence = self.pool.begin().await?;
        if db::authorize_operation_effect_in_tx(&mut fence, parent).await?
            != db::EffectAuthorizationOutcome::Authorized
            || !db::mark_operation_target_point_of_no_return_in_tx(&mut fence, target).await?
        {
            let _ = db::acknowledge_operation_target_cancel_in_tx(&mut fence, target).await?;
            let _ = db::acknowledge_operation_cancel_in_tx(&mut fence, parent).await?;
            fence.commit().await?;
            return Ok(EffectFenceDecision::Denied);
        }
        fence.commit().await?;
        Ok(EffectFenceDecision::Authorized)
    }
}
