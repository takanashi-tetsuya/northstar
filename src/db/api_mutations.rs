//! Persists canonical command responses inside the owning use-case transaction.
use crate::{db, services::api_mutations::StoredApiResponse};
use sqlx::{Postgres, Transaction};

pub(crate) async fn persist_response_in_tx(
    keyring: &db::ApiControlKeyring,
    tx: &mut Transaction<'_, Postgres>,
    lease: &db::IdempotencyLease,
    response: &StoredApiResponse,
) -> anyhow::Result<bool> {
    match response.replay_resource_id {
        Some(resource_id) => {
            db::complete_idempotency_with_resource_in_tx(
                keyring,
                tx,
                lease,
                response.status,
                &response.headers,
                &response.body,
                Some(resource_id),
            )
            .await
        }
        None => {
            db::complete_idempotency_in_tx(
                keyring,
                tx,
                lease,
                response.status,
                &response.headers,
                &response.body,
            )
            .await
        }
    }
}
