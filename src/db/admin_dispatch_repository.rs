//! Durable administrative dispatch, side records and replay share a transaction.
use crate::{
    db::{
        self,
        admin_mutations::{
            enqueue_operation_response_in_tx, AdminMutationStart, AdminMutationStore,
            AdminOperationIntent,
        },
    },
    services::{admin_dispatch::*, api_mutations::*, operations::AuthorizationPolicy},
};
use anyhow::Result;
use serde_json::json;

#[derive(Clone)]
pub(crate) struct PostgresAdminDispatchRepository {
    mutations: AdminMutationStore,
}

impl PostgresAdminDispatchRepository {
    pub(crate) fn new(mutations: AdminMutationStore) -> Self {
        Self { mutations }
    }

    async fn dispatch(
        &self,
        admission: AdminMutationAdmission<'_>,
        intent: AdminOperationIntent<'_>,
    ) -> Result<ApiMutationOutcome<StoredApiResponse>> {
        let (mut tx, lease) = match self.mutations.start(&admission).await? {
            AdminMutationStart::Ready(tx, lease) => (tx, lease),
            AdminMutationStart::Finished(outcome) => return Ok(outcome),
        };
        let (response, _) =
            enqueue_operation_response_in_tx(&mut tx, &admission, &lease, intent).await?;
        self.mutations.finish(tx, &lease, response).await
    }
}

impl AdminDispatchRepository for PostgresAdminDispatchRepository {
    async fn reload_tls(
        &self,
        admission: AdminMutationAdmission<'_>,
    ) -> Result<ApiMutationOutcome<StoredApiResponse>> {
        self.dispatch(
            admission,
            AdminOperationIntent {
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
            AdminOperationIntent {
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
        let (response, _) = enqueue_operation_response_in_tx(
            &mut tx,
            &admission,
            &lease,
            AdminOperationIntent {
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
        let (response, operation_id) = enqueue_operation_response_in_tx(
            &mut tx,
            &admission,
            &lease,
            AdminOperationIntent {
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
            AdminOperationIntent {
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
