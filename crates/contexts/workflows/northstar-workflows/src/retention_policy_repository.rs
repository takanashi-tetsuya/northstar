//! Complete authorization, retention policy and response replay transactions.
use northstar_operations_application::retention_policy::*;
use northstar_operations_core::api_mutations::*;
use sqlx::{PgPool, Postgres, Transaction};
use std::sync::Arc;
use uuid::Uuid;

#[derive(Clone)]
pub struct PostgresRetentionPolicyRepository {
    pool: PgPool,
    keyring: Arc<northstar_operations_postgres::api_control::ApiControlKeyring>,
}

enum RetentionMutationStart<'a> {
    Ready(
        Transaction<'a, Postgres>,
        Uuid,
        northstar_operations_postgres::api_control::IdempotencyLease,
    ),
    Finished(ApiMutationOutcome<StoredApiResponse>),
}

fn backend(error: impl Into<anyhow::Error>) -> RetentionPolicyError {
    RetentionPolicyError::Internal(error.into())
}

impl PostgresRetentionPolicyRepository {
    pub fn new(
        pool: PgPool,
        keyring: Arc<northstar_operations_postgres::api_control::ApiControlKeyring>,
    ) -> Self {
        Self { pool, keyring }
    }

    async fn authorized(
        &self,
        token: &str,
    ) -> Result<(Transaction<'_, Postgres>, Uuid), RetentionPolicyError> {
        let mut tx = self.pool.begin().await.map_err(backend)?;
        // Resolve and hold users -> exact bearer locks through the policy operation.
        let user = northstar_auth_postgres::users::user_for_token_in_tx(&mut tx, token)
            .await
            .map_err(backend)?
            .ok_or(RetentionPolicyError::Unauthorized)?;
        Ok((tx, user.id))
    }

    async fn start(
        &self,
        admission: &RetentionMutationAdmission<'_>,
    ) -> Result<RetentionMutationStart<'_>, RetentionPolicyError> {
        let (mut tx, user_id) = self.authorized(admission.session_token).await?;
        let rejection = match northstar_operations_postgres::api_control::acquire_idempotency_in_tx(
            &self.keyring,
            &mut tx,
            &admission.idempotency,
        )
        .await
        .map_err(backend)?
        {
            northstar_operations_postgres::api_control::IdempotencyAcquire::Acquired(lease) => {
                return Ok(RetentionMutationStart::Ready(tx, user_id, lease))
            }
            northstar_operations_postgres::api_control::IdempotencyAcquire::Replay(response) => {
                tx.commit().await.map_err(backend)?;
                return Ok(RetentionMutationStart::Finished(
                    ApiMutationOutcome::Replay(response),
                ));
            }
            northstar_operations_postgres::api_control::IdempotencyAcquire::FingerprintConflict
            | northstar_operations_postgres::api_control::IdempotencyAcquire::RotationConflict => {
                ApiMutationRejection::IdempotencyConflict
            }
            northstar_operations_postgres::api_control::IdempotencyAcquire::ReplayInvalidated => {
                ApiMutationRejection::ReplayInvalidated
            }
            northstar_operations_postgres::api_control::IdempotencyAcquire::Busy {
                retry_after_seconds,
            } => ApiMutationRejection::Busy {
                retry_after: retry_after_seconds,
            },
            northstar_operations_postgres::api_control::IdempotencyAcquire::CapacityLimited {
                retry_after_seconds,
            } => ApiMutationRejection::CapacityLimited {
                retry_after: retry_after_seconds,
            },
            northstar_operations_postgres::api_control::IdempotencyAcquire::InProgress {
                retry_after_seconds,
            } => ApiMutationRejection::InProgress {
                retry_after: retry_after_seconds,
            },
        };
        tx.rollback().await.map_err(backend)?;
        Ok(RetentionMutationStart::Finished(
            ApiMutationOutcome::Rejected(rejection),
        ))
    }

    async fn finish(
        &self,
        mut tx: Transaction<'_, Postgres>,
        lease: &northstar_operations_postgres::api_control::IdempotencyLease,
        response: StoredApiResponse,
    ) -> Result<ApiMutationOutcome<StoredApiResponse>, RetentionPolicyError> {
        if !northstar_operations_postgres::api_mutations::persist_response_in_tx(
            &self.keyring,
            &mut tx,
            lease,
            &response,
        )
        .await
        .map_err(backend)?
        {
            return Err(backend(anyhow::anyhow!(
                "data-policy idempotency lease changed"
            )));
        }
        tx.commit().await.map_err(backend)?;
        Ok(ApiMutationOutcome::Committed(response))
    }
}

impl RetentionPolicyRepository for PostgresRetentionPolicyRepository {
    async fn user_policy(
        &self,
        session_token: &str,
    ) -> Result<UserRetentionPolicy, RetentionPolicyError> {
        let (mut tx, user_id) = self.authorized(session_token).await?;
        let policy = northstar_operations_postgres::data_lifecycle::user_retention_policy_in_tx(
            &mut tx, user_id,
        )
        .await
        .map_err(backend)?;
        tx.commit().await.map_err(backend)?;
        Ok(policy)
    }

    async fn muc_policy(
        &self,
        session_token: &str,
        room_id: Uuid,
    ) -> Result<Option<i32>, RetentionPolicyError> {
        let (mut tx, user_id) = self.authorized(session_token).await?;
        let policy =
            northstar_operations_postgres::data_lifecycle::muc_retention_policy_authorized_in_tx(
                &mut tx, user_id, room_id,
            )
            .await?;
        tx.commit().await.map_err(backend)?;
        Ok(policy)
    }

    async fn set_user_policy(
        &self,
        admission: RetentionMutationAdmission<'_>,
        requested: UserRetentionPolicy,
        limits: RetentionPolicyLimits,
    ) -> Result<ApiMutationOutcome<StoredApiResponse>, RetentionPolicyError> {
        let (mut tx, user_id, lease) = match self.start(&admission).await? {
            RetentionMutationStart::Ready(tx, user_id, lease) => (tx, user_id, lease),
            RetentionMutationStart::Finished(outcome) => return Ok(outcome),
        };
        northstar_operations_postgres::data_lifecycle::set_user_retention_policy_in_tx(
            &mut tx,
            user_id,
            user_id,
            requested,
            limits,
            lease.request_id,
        )
        .await?;
        let response = StoredApiResponse::json(200, serde_json::json!({"policy":requested}))
            .map_err(backend)?;
        self.finish(tx, &lease, response).await
    }

    async fn set_muc_policy(
        &self,
        admission: RetentionMutationAdmission<'_>,
        room_id: Uuid,
        requested_days: Option<i32>,
        global_days: i64,
    ) -> Result<ApiMutationOutcome<StoredApiResponse>, RetentionPolicyError> {
        let (mut tx, user_id, lease) = match self.start(&admission).await? {
            RetentionMutationStart::Ready(tx, user_id, lease) => (tx, user_id, lease),
            RetentionMutationStart::Finished(outcome) => return Ok(outcome),
        };
        northstar_operations_postgres::data_lifecycle::set_muc_retention_policy_in_tx(
            &mut tx,
            user_id,
            room_id,
            requested_days,
            global_days,
            lease.request_id,
        )
        .await?;
        let response = StoredApiResponse::json(
            200,
            serde_json::json!({"room_id":room_id,"retention_days":requested_days}),
        )
        .map_err(backend)?;
        self.finish(tx, &lease, response).await
    }
}
