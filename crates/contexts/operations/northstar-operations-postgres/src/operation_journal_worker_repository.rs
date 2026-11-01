//! Atomic lease renewal and target claim for the administrator operation worker.

use crate::api_operations::{OperationLease, OperationTargetLease};
use anyhow::Result;
use northstar_operations_application::operation_journal_worker::{
    ClaimedOperation, OperationJournalWorkerRepository, ParentTerminalization, TargetClaim,
    TargetSeed,
};
use serde_json::{json, Value};
use sqlx::PgPool;
use uuid::Uuid;

#[derive(Clone)]
pub struct PostgresOperationJournalWorkerRepository {
    pool: PgPool,
}

impl PostgresOperationJournalWorkerRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

impl OperationJournalWorkerRepository for PostgresOperationJournalWorkerRepository {
    type Parent = OperationLease;
    type Target = OperationTargetLease;

    async fn claim_parent_with_targets<F>(
        &self,
        worker_id: Uuid,
        lease_seconds: i64,
        planner: F,
    ) -> Result<Option<OperationLease>>
    where
        F: for<'a> FnOnce(ClaimedOperation<'a>) -> Result<Vec<TargetSeed>> + Send,
    {
        if !crate::api_operations::operation_work_pending(&self.pool, worker_id, lease_seconds)
            .await?
        {
            return Ok(None);
        }
        let mut tx = self.pool.begin().await?;
        let Some(lease) =
            crate::api_operations::claim_operation_in_tx(&mut tx, worker_id, lease_seconds).await?
        else {
            // Claim maintenance can expire or revoke rows even when no candidate
            // remains; the original worker commits those transitions.
            tx.commit().await?;
            return Ok(None);
        };
        let seeds = planner(ClaimedOperation {
            kind: &lease.operation.kind,
            payload: &lease.operation.payload,
        })?;
        for seed in seeds {
            crate::api_operations::enqueue_operation_target_in_tx(
                &mut tx,
                &crate::api_operations::EnqueueOperationTarget {
                    operation_id: lease.operation.id,
                    target_key: &seed.target_key,
                    ordinal: seed.ordinal,
                    payload: &seed.payload,
                    max_attempts: lease.operation.max_attempts,
                    deadline_seconds: 24 * 60 * 60,
                },
            )
            .await?;
        }
        tx.commit().await?;
        Ok(Some(lease))
    }

    async fn claim_target(
        &self,
        parent: &OperationLease,
        worker_id: Uuid,
        lease_seconds: i64,
    ) -> Result<TargetClaim<OperationTargetLease>> {
        let mut claim = self.pool.begin().await?;
        if !crate::api_operations::renew_operation_lease_in_tx(&mut claim, parent, lease_seconds)
            .await?
        {
            claim.rollback().await?;
            return Ok(TargetClaim::LeaseLost);
        }
        let target = crate::api_operations::claim_operation_target_in_tx(
            &mut claim,
            parent.operation.id,
            worker_id,
            lease_seconds,
        )
        .await?;
        claim.commit().await?;
        Ok(match target {
            Some(target) => TargetClaim::Claimed(target),
            None => TargetClaim::NoTarget,
        })
    }

    async fn acknowledge_cancel(&self, parent: &OperationLease) -> Result<bool> {
        let mut cancel_tx = self.pool.begin().await?;
        if crate::api_operations::acknowledge_operation_cancel_in_tx(&mut cancel_tx, parent).await?
        {
            cancel_tx.commit().await?;
            return Ok(true);
        }
        cancel_tx.rollback().await?;
        Ok(false)
    }

    async fn renew_effect_leases(
        &self,
        parent: &OperationLease,
        target: &OperationTargetLease,
        lease_seconds: i64,
    ) -> Result<bool> {
        let mut tx = self.pool.begin().await?;
        let parent_ok =
            crate::api_operations::renew_operation_lease_in_tx(&mut tx, parent, lease_seconds)
                .await?;
        let target_ok = crate::api_operations::renew_operation_target_lease_in_tx(
            &mut tx,
            target,
            lease_seconds,
        )
        .await?;
        if !parent_ok || !target_ok {
            tx.rollback().await?;
            return Ok(false);
        }
        tx.commit().await?;
        Ok(true)
    }

    async fn succeed_target(&self, target: &OperationTargetLease, result: &Value) -> Result<bool> {
        let mut finish = self.pool.begin().await?;
        if !crate::api_operations::succeed_operation_target_in_tx(&mut finish, target, result)
            .await?
        {
            finish.rollback().await?;
            return Ok(false);
        }
        finish.commit().await?;
        Ok(true)
    }

    async fn mark_target_indeterminate(
        &self,
        parent: &OperationLease,
        target: &OperationTargetLease,
        operation_id: Uuid,
        target_id: Uuid,
        error: &anyhow::Error,
    ) -> Result<bool> {
        let mut finish = self.pool.begin().await?;
        tracing::warn!(operation_id=%operation_id, target_id=%target_id, ?error, "durable operation effect failed after PONR");
        let details = json!({"message": error.to_string()});
        if !crate::api_operations::mark_operation_target_indeterminate_in_tx(
            &mut finish,
            parent,
            target,
            "effect_outcome_unprovable",
            Some(&details),
        )
        .await?
        {
            finish.rollback().await?;
            return Ok(false);
        }
        finish.commit().await?;
        Ok(true)
    }

    async fn terminalize_parent(&self, parent: &OperationLease) -> Result<ParentTerminalization> {
        let mut finish = self.pool.begin().await?;
        if !crate::api_operations::succeed_operation_in_tx(
            &mut finish,
            parent,
            &json!({"completed":true}),
        )
        .await?
        {
            if crate::api_operations::fail_operation_in_tx(
                &mut finish,
                parent,
                "target_incomplete",
                None,
            )
            .await?
            {
                finish.commit().await?;
                return Ok(ParentTerminalization::FailedIncomplete);
            }
            finish.rollback().await?;
            return Ok(ParentTerminalization::LeaseLost);
        }
        finish.commit().await?;
        Ok(ParentTerminalization::Succeeded)
    }
}
