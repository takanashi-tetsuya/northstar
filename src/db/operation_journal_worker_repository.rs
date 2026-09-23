//! Atomic lease renewal and target claim for the administrator operation worker.

use crate::db::{self, OperationLease, OperationTargetLease};
use crate::services::operation_journal_worker::{
    ClaimedOperation, OperationJournalWorkerRepository, ParentTerminalization, TargetClaim,
    TargetSeed,
};
use anyhow::Result;
use serde_json::{json, Value};
use sqlx::PgPool;
use uuid::Uuid;

pub(crate) struct PostgresOperationJournalWorkerRepository {
    pool: PgPool,
}

impl PostgresOperationJournalWorkerRepository {
    pub(crate) fn new(pool: PgPool) -> Self {
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
        if !db::operation_work_pending(&self.pool, worker_id, lease_seconds).await? {
            return Ok(None);
        }
        let mut tx = self.pool.begin().await?;
        let Some(lease) = db::claim_operation_in_tx(&mut tx, worker_id, lease_seconds).await?
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
            db::enqueue_operation_target_in_tx(
                &mut tx,
                &db::EnqueueOperationTarget {
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
        if !db::renew_operation_lease_in_tx(&mut claim, parent, lease_seconds).await? {
            claim.rollback().await?;
            return Ok(TargetClaim::LeaseLost);
        }
        let target = db::claim_operation_target_in_tx(
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
        if db::acknowledge_operation_cancel_in_tx(&mut cancel_tx, parent).await? {
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
        let parent_ok = db::renew_operation_lease_in_tx(&mut tx, parent, lease_seconds).await?;
        let target_ok =
            db::renew_operation_target_lease_in_tx(&mut tx, target, lease_seconds).await?;
        if !parent_ok || !target_ok {
            tx.rollback().await?;
            return Ok(false);
        }
        tx.commit().await?;
        Ok(true)
    }

    async fn succeed_target(&self, target: &OperationTargetLease, result: &Value) -> Result<bool> {
        let mut finish = self.pool.begin().await?;
        if !db::succeed_operation_target_in_tx(&mut finish, target, result).await? {
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
        if !db::mark_operation_target_indeterminate_in_tx(
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
        if !db::succeed_operation_in_tx(&mut finish, parent, &json!({"completed":true})).await? {
            if db::fail_operation_in_tx(&mut finish, parent, "target_incomplete", None).await? {
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::services::operation_journal_worker::OperationJournalWorkerService;

    async fn enqueue_broadcast(pool: &PgPool) -> Uuid {
        let actor = Uuid::new_v4();
        sqlx::query(
            "INSERT INTO users(id,username,password_hash,is_admin)
             VALUES($1,$2,'test-only',TRUE)",
        )
        .bind(actor)
        .bind(format!("operation-{}", &actor.simple().to_string()[..12]))
        .execute(pool)
        .await
        .unwrap();
        let idempotency = Uuid::new_v4();
        let request = Uuid::new_v4();
        let token = Uuid::new_v4();
        let digest: Vec<u8> = idempotency
            .as_bytes()
            .iter()
            .copied()
            .cycle()
            .take(32)
            .collect();
        sqlx::query(
            "INSERT INTO api_idempotency_records
             (id,scope_hash,principal_hash,scope_key_id,request_actor_id,ownership_actor_id,
              principal_kind,method,route,request_fingerprint,request_id,state,
              lease_token,lease_expires_at,expires_at)
             VALUES($1,$2,$3,'0011223344556677',$4,$4,'admin','POST',
                    '/api/v1/admin/broadcast',$5,$6,'started',$7,
                    clock_timestamp()+INTERVAL '5 minutes',
                    clock_timestamp()+INTERVAL '1 hour')",
        )
        .bind(idempotency)
        .bind(&digest)
        .bind(vec![8_u8; 32])
        .bind(actor)
        .bind(vec![9_u8; 32])
        .bind(request)
        .bind(token)
        .execute(pool)
        .await
        .unwrap();
        let mut tx = pool.begin().await.unwrap();
        let operation = db::enqueue_operation_in_tx(
            &mut tx,
            &db::EnqueueOperation {
                request_id: request,
                idempotency_id: idempotency,
                idempotency_lease_token: token,
                actor_id: actor,
                actor_auth_generation: 0,
                authorization_policy: db::AuthorizationPolicy::ReauthorizeUntilEffect,
                kind: "admin.broadcast",
                target: None,
                payload_version: 1,
                payload: &json!({"message":"maintenance"}),
                max_attempts: 3,
                deadline_seconds: 3600,
            },
        )
        .await
        .unwrap();
        tx.commit().await.unwrap();
        operation.id
    }

    async fn assert_unclaimed_without_targets(pool: &PgPool, operation_id: Uuid) {
        let (status, attempts): (String, i32) =
            sqlx::query_as("SELECT status,attempts FROM api_operation_journal WHERE id=$1")
                .bind(operation_id)
                .fetch_one(pool)
                .await
                .unwrap();
        let targets: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM api_operation_targets WHERE operation_id=$1")
                .bind(operation_id)
                .fetch_one(pool)
                .await
                .unwrap();
        assert_eq!((status.as_str(), attempts, targets), ("pending", 0, 0));
    }

    #[tokio::test]
    #[ignore = "requires a random isolated TEST_DATABASE_URL PostgreSQL schema"]
    async fn claim_and_target_plan_commit_or_roll_back_together() {
        let pool = crate::db::test_support::operation_mutation_pool().await;
        let operation_id = enqueue_broadcast(&pool).await;
        let service = OperationJournalWorkerService::new(
            PostgresOperationJournalWorkerRepository::new(pool.clone()),
        );
        let worker_id = Uuid::new_v4();

        let error = service
            .claim_parent_with_targets(worker_id, 60, |operation| {
                assert_eq!(operation.kind, "admin.broadcast");
                assert_eq!(operation.payload, &json!({"message":"maintenance"}));
                anyhow::bail!("injected target snapshot failure")
            })
            .await
            .expect_err("planner failure must abort the claim");
        assert!(error
            .to_string()
            .contains("injected target snapshot failure"));
        assert_unclaimed_without_targets(&pool, operation_id).await;

        assert!(service
            .claim_parent_with_targets(worker_id, 60, |_| {
                Ok(vec![
                    TargetSeed {
                        target_key: "connection:first".to_owned(),
                        ordinal: 0,
                        payload: json!({"message":"maintenance"}),
                    },
                    TargetSeed {
                        target_key: String::new(),
                        ordinal: 1,
                        payload: json!({"message":"maintenance"}),
                    },
                ])
            })
            .await
            .is_err());
        assert_unclaimed_without_targets(&pool, operation_id).await;

        let lease = service
            .claim_parent_with_targets(worker_id, 60, |_| {
                Ok(vec![TargetSeed {
                    target_key: "connection:first".to_owned(),
                    ordinal: 0,
                    payload: json!({"message":"maintenance"}),
                }])
            })
            .await
            .unwrap()
            .expect("the valid plan must commit its claim");
        assert_eq!(lease.operation.id, operation_id);
        let (status, attempts): (String, i32) =
            sqlx::query_as("SELECT status,attempts FROM api_operation_journal WHERE id=$1")
                .bind(operation_id)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!((status.as_str(), attempts), ("running", 1));
        let (target_key, ordinal, max_attempts): (String, i64, i32) = sqlx::query_as(
            "SELECT target_key,ordinal,max_attempts FROM api_operation_targets WHERE operation_id=$1",
        )
        .bind(operation_id)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(
            (target_key.as_str(), ordinal, max_attempts),
            ("connection:first", 0, 3)
        );

        let none = service
            .claim_parent_with_targets(worker_id, 60, |_| {
                panic!("a claim without a candidate must not take a new snapshot")
            })
            .await
            .unwrap();
        assert!(none.is_none());
        pool.close().await;
    }
}
