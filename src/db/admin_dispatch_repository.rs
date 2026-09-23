//! Durable administrative dispatch, side records and replay share a transaction.
use crate::{
    db::{
        self,
        admin_mutations::{AdminMutationStart, AdminMutationStore},
    },
    services::{admin_dispatch::*, api_mutations::*, operations::AuthorizationPolicy},
};
use anyhow::Result;
use serde_json::{json, Value};
use sqlx::{Postgres, Transaction};
use uuid::Uuid;

#[derive(Clone)]
pub(crate) struct PostgresAdminDispatchRepository {
    mutations: AdminMutationStore,
}
struct OperationIntent<'a> {
    kind: &'a str,
    target: Option<&'a str>,
    policy: AuthorizationPolicy,
    payload: &'a Value,
}

impl PostgresAdminDispatchRepository {
    pub(crate) fn new(mutations: AdminMutationStore) -> Self {
        Self { mutations }
    }

    async fn dispatch(
        &self,
        admission: AdminMutationAdmission<'_>,
        intent: OperationIntent<'_>,
    ) -> Result<ApiMutationOutcome<StoredApiResponse>> {
        let (mut tx, lease) = match self.mutations.start(&admission).await? {
            AdminMutationStart::Ready(tx, lease) => (tx, lease),
            AdminMutationStart::Finished(outcome) => return Ok(outcome),
        };
        let (response, _) = enqueue(&mut tx, &admission, &lease, intent).await?;
        self.mutations.finish(tx, &lease, response).await
    }
}

async fn enqueue(
    tx: &mut Transaction<'_, Postgres>,
    admission: &AdminMutationAdmission<'_>,
    lease: &db::IdempotencyLease,
    intent: OperationIntent<'_>,
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

impl AdminDispatchRepository for PostgresAdminDispatchRepository {
    async fn reload_tls(
        &self,
        admission: AdminMutationAdmission<'_>,
    ) -> Result<ApiMutationOutcome<StoredApiResponse>> {
        self.dispatch(
            admission,
            OperationIntent {
                kind: "admin.tls_reload",
                target: None,
                policy: AuthorizationPolicy::ReauthorizeUntilEffect,
                payload: &json!({}),
            },
        )
        .await
    }
    async fn panic_disconnect(
        &self,
        admission: AdminMutationAdmission<'_>,
    ) -> Result<ApiMutationOutcome<StoredApiResponse>> {
        self.dispatch(
            admission,
            OperationIntent {
                kind: "admin.panic_disconnect",
                target: None,
                policy: AuthorizationPolicy::ReauthorizeUntilEffect,
                payload: &json!({"reason":"administrator request"}),
            },
        )
        .await
    }
    async fn set_island_mode(
        &self,
        admission: AdminMutationAdmission<'_>,
        enabled: bool,
    ) -> Result<ApiMutationOutcome<StoredApiResponse>> {
        let (mut tx, lease) = match self.mutations.start(&admission).await? {
            AdminMutationStart::Ready(tx, lease) => (tx, lease),
            AdminMutationStart::Finished(outcome) => return Ok(outcome),
        };
        db::set_admin_runtime_setting_in_tx(
            &mut tx,
            admission.authority.user_id,
            "island_mode",
            enabled,
            Some(lease.request_id),
        )
        .await?;
        let payload = json!({"mode":if enabled {"enabled"} else {"disabled"},"epoch":lease.request_id.as_u128().min(i64::MAX as u128) as i64});
        let (response, _) = enqueue(
            &mut tx,
            &admission,
            &lease,
            OperationIntent {
                kind: "admin.island_converge",
                target: Some("island_mode"),
                policy: AuthorizationPolicy::CommittedConsequence,
                payload: &payload,
            },
        )
        .await?;
        self.mutations.finish(tx, &lease, response).await
    }
    async fn destroy_room(
        &self,
        admission: AdminMutationAdmission<'_>,
        room: &RoomDestructionTarget,
    ) -> Result<ApiMutationOutcome<StoredApiResponse>> {
        let (mut tx, lease) = match self.mutations.start(&admission).await? {
            AdminMutationStart::Ready(tx, lease) => (tx, lease),
            AdminMutationStart::Finished(outcome) => return Ok(outcome),
        };
        let localpart = room.localpart();
        sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1,0))")
            .bind(format!("northstar:muc-room:{localpart}"))
            .execute(&mut *tx)
            .await?;
        let room_exists = sqlx::query_scalar::<_, String>(
            "SELECT localpart FROM muc_rooms
          WHERE localpart=$1 AND destroyed_at IS NULL FOR UPDATE",
        )
        .bind(localpart)
        .fetch_optional(&mut *tx)
        .await?
        .is_some();
        if !room_exists {
            tx.rollback().await?;
            return Ok(ApiMutationOutcome::Rejected(
                ApiMutationRejection::BadRequest("room does not exist"),
            ));
        }
        let (response, operation_id) = enqueue(
            &mut tx,
            &admission,
            &lease,
            OperationIntent {
                kind: "admin.muc_destroy",
                target: Some(room.room_jid()),
                policy: AuthorizationPolicy::CommittedConsequence,
                payload: &json!({"room_jid":room.room_jid()}),
            },
        )
        .await?;
        sqlx::query(
            "INSERT INTO api_muc_destroy_intents(room_jid,localpart,operation_id) VALUES($1,$2,$3)",
        )
        .bind(room.room_jid())
        .bind(localpart)
        .bind(operation_id)
        .execute(&mut *tx)
        .await?;
        self.mutations.finish(tx, &lease, response).await
    }
    async fn broadcast(
        &self,
        admission: AdminMutationAdmission<'_>,
        message: &str,
    ) -> Result<ApiMutationOutcome<StoredApiResponse>> {
        self.dispatch(
            admission,
            OperationIntent {
                kind: "admin.broadcast",
                target: None,
                policy: AuthorizationPolicy::ReauthorizeUntilEffect,
                payload: &json!({"message":message}),
            },
        )
        .await
    }
}

#[cfg(test)]
#[path = "admin_dispatch_repository_tests.rs"]
mod tests;
