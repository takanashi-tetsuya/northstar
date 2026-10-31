//! Shared transaction admission for administrative repository commands.
use crate::cluster::{ClusterAdmission, ClusterOperation};
use anyhow::Result;
use northstar_operations_application::operations::AuthorizationPolicy;
use northstar_operations_core::api_mutations::*;
use serde_json::{json, Value};
use sqlx::{PgPool, Postgres, Transaction};
use std::sync::Arc;
use uuid::Uuid;

#[derive(Clone)]
pub(crate) struct AdminMutationStore {
    pool: PgPool,
    keyring: Arc<northstar_operations_postgres::api_control::ApiControlKeyring>,
    cluster: ClusterAdmission,
}

pub(crate) enum AdminMutationStart<'a> {
    Ready(
        Transaction<'a, Postgres>,
        northstar_operations_postgres::api_control::IdempotencyLease,
    ),
    Finished(ApiMutationOutcome<StoredApiResponse>),
}
impl AdminMutationStore {
    pub(crate) fn new(
        pool: PgPool,
        keyring: Arc<northstar_operations_postgres::api_control::ApiControlKeyring>,
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
        if !northstar_auth_postgres::users::authorize_admin_in_tx(
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
        let rejection = match northstar_operations_postgres::api_control::acquire_idempotency_in_tx(
            &self.keyring,
            &mut tx,
            &admission.idempotency,
        )
        .await?
        {
            northstar_operations_postgres::api_control::IdempotencyAcquire::Acquired(lease) => {
                return Ok(AdminMutationStart::Ready(tx, lease))
            }
            northstar_operations_postgres::api_control::IdempotencyAcquire::Replay(response) => {
                tx.commit().await?;
                return Ok(AdminMutationStart::Finished(ApiMutationOutcome::Replay(
                    response,
                )));
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
        tx.rollback().await?;
        Ok(AdminMutationStart::Finished(ApiMutationOutcome::Rejected(
            rejection,
        )))
    }
    pub(crate) async fn finish(
        &self,
        mut tx: Transaction<'_, Postgres>,
        lease: &northstar_operations_postgres::api_control::IdempotencyLease,
        response: StoredApiResponse,
    ) -> Result<ApiMutationOutcome<StoredApiResponse>> {
        anyhow::ensure!(
            northstar_operations_postgres::api_mutations::persist_response_in_tx(
                &self.keyring,
                &mut tx,
                lease,
                &response
            )
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
    lease: &northstar_operations_postgres::api_control::IdempotencyLease,
    intent: AdminOperationIntent<'_>,
) -> Result<(StoredApiResponse, Uuid)> {
    let operation = northstar_operations_postgres::api_operations::enqueue_operation_in_tx(
        tx,
        &northstar_operations_postgres::api_operations::EnqueueOperation {
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
