//! Shared transaction admission for administrative repository commands.
use crate::services::operations::AuthorizationPolicy;
use crate::{
    cluster::{ClusterAdmission, ClusterOperation},
    db,
    services::api_mutations::*,
};
use anyhow::Result;
use serde_json::{json, Value};
use sqlx::{PgPool, Postgres, Transaction};
use std::sync::Arc;
use uuid::Uuid;

#[derive(Clone)]
pub(crate) struct AdminMutationStore {
    pool: PgPool,
    keyring: Arc<db::ApiControlKeyring>,
    cluster: ClusterAdmission,
}

pub(crate) enum AdminMutationStart<'a> {
    Ready(Transaction<'a, Postgres>, db::IdempotencyLease),
    Finished(ApiMutationOutcome<StoredApiResponse>),
}
impl AdminMutationStore {
    pub(crate) fn new(
        pool: PgPool,
        keyring: Arc<db::ApiControlKeyring>,
        cluster: ClusterAdmission,
    ) -> Self {
        Self {
            pool,
            keyring,
            cluster,
        }
    }
    pub(crate) async fn start(
        &self,
        admission: &AdminMutationAdmission<'_>,
    ) -> Result<AdminMutationStart<'_>> {
        let mut tx = self.pool.begin().await?;
        // Recheck after pool admission: health can change while waiting for a connection.
        if let Err(error) = self.cluster.admit(ClusterOperation::AdminMutation) {
            tx.rollback().await?;
            return Ok(AdminMutationStart::Finished(ApiMutationOutcome::Rejected(
                ApiMutationRejection::Unavailable(error.to_string()),
            )));
        }
        let actor = &admission.authority;
        if !db::authorize_admin_in_tx(
            &mut tx,
            actor.user_id,
            actor.auth_generation,
            actor.session_token,
        )
        .await?
        {
            tx.rollback().await?;
            return Ok(AdminMutationStart::Finished(ApiMutationOutcome::Rejected(
                ApiMutationRejection::Forbidden,
            )));
        }
        let rejection =
            match db::acquire_idempotency_in_tx(&self.keyring, &mut tx, &admission.idempotency)
                .await?
            {
                db::IdempotencyAcquire::Acquired(lease) => {
                    return Ok(AdminMutationStart::Ready(tx, lease))
                }
                db::IdempotencyAcquire::Replay(response) => {
                    tx.commit().await?;
                    return Ok(AdminMutationStart::Finished(ApiMutationOutcome::Replay(
                        response,
                    )));
                }
                db::IdempotencyAcquire::FingerprintConflict
                | db::IdempotencyAcquire::RotationConflict => {
                    ApiMutationRejection::IdempotencyConflict
                }
                db::IdempotencyAcquire::ReplayInvalidated => {
                    ApiMutationRejection::ReplayInvalidated
                }
                db::IdempotencyAcquire::Busy {
                    retry_after_seconds,
                } => ApiMutationRejection::Busy {
                    retry_after: retry_after_seconds,
                },
                db::IdempotencyAcquire::CapacityLimited {
                    retry_after_seconds,
                } => ApiMutationRejection::CapacityLimited {
                    retry_after: retry_after_seconds,
                },
                db::IdempotencyAcquire::InProgress {
                    retry_after_seconds,
                } => ApiMutationRejection::InProgress {
                    retry_after: retry_after_seconds,
                },
            };
        tx.rollback().await?;
        Ok(AdminMutationStart::Finished(ApiMutationOutcome::Rejected(
            rejection,
        )))
    }
    pub(crate) async fn finish(
        &self,
        mut tx: Transaction<'_, Postgres>,
        lease: &db::IdempotencyLease,
        response: StoredApiResponse,
    ) -> Result<ApiMutationOutcome<StoredApiResponse>> {
        anyhow::ensure!(
            db::api_mutations::persist_response_in_tx(&self.keyring, &mut tx, lease, &response)
                .await?,
            "administrator idempotency lease changed"
        );
        tx.commit().await?;
        Ok(ApiMutationOutcome::Committed(response))
    }
}

// The caller persists replay bytes and commits together with domain side records.
pub(crate) struct AdminOperationIntent<'a> {
    pub(crate) kind: &'a str,
    pub(crate) target: Option<&'a str>,
    pub(crate) policy: AuthorizationPolicy,
    pub(crate) payload: &'a Value,
}

pub(crate) async fn enqueue_operation_response_in_tx(
    tx: &mut Transaction<'_, Postgres>,
    admission: &AdminMutationAdmission<'_>,
    lease: &db::IdempotencyLease,
    intent: AdminOperationIntent<'_>,
) -> Result<(StoredApiResponse, Uuid)> {
    let operation = db::enqueue_operation_in_tx(
        tx,
        &db::EnqueueOperation {
            request_id: lease.request_id,
            idempotency_id: lease.record_id,
            idempotency_lease_token: lease.lease_token(),
            actor_id: admission.authority.user_id,
            actor_auth_generation: admission.authority.auth_generation,
            authorization_policy: intent.policy,
            kind: intent.kind,
            target: intent.target,
            payload_version: 1,
            payload: intent.payload,
            max_attempts: 8,
            deadline_seconds: 24 * 60 * 60,
        },
    )
    .await?;
    let response =
        StoredApiResponse::json(202, json!({"operation_id":operation.id,"status":"pending"}))?
            .with_header(
                "location",
                format!("/api/v1/admin/operations/{}", operation.id),
            );
    Ok((response, operation.id))
}
