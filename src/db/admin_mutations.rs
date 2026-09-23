//! Shared transaction admission for administrative repository commands.
use crate::{
    cluster::{ClusterAdmission, ClusterOperation},
    db,
    services::api_mutations::*,
};
use anyhow::Result;
use sqlx::{PgPool, Postgres, Transaction};
use std::sync::Arc;

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
