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
use sqlx::{PgPool, Row};
use std::sync::Arc;
use uuid::Uuid;

#[derive(Clone)]
pub(crate) struct PostgresAdminDispatchRepository {
    mutations: AdminMutationStore,
    command: AdminCommandStore,
}

#[derive(Clone)]
pub(crate) struct AdminCommandStore {
    command_pool: PgPool,
    keyring: Arc<db::ApiControlKeyring>,
    cluster: crate::cluster::ClusterAdmission,
}

impl PostgresAdminDispatchRepository {
    pub(crate) fn new(
        mutations: AdminMutationStore,
        command_pool: PgPool,
        keyring: Arc<db::ApiControlKeyring>,
        cluster: crate::cluster::ClusterAdmission,
    ) -> Self {
        Self {
            mutations,
            command: AdminCommandStore {
                command_pool,
                keyring,
                cluster,
            },
        }
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

impl AdminCommandStore {
    pub(crate) fn new(
        command_pool: PgPool,
        keyring: Arc<db::ApiControlKeyring>,
        cluster: crate::cluster::ClusterAdmission,
    ) -> Self {
        Self {
            command_pool,
            keyring,
            cluster,
        }
    }

    pub(crate) async fn dispatch(
        &self,
        admission: AdminMutationAdmission<'_>,
        route: db::api_control::AdminCommandRoute,
        registration_enabled: Option<bool>,
    ) -> Result<ApiMutationOutcome<StoredApiResponse>> {
        anyhow::ensure!(
            matches!(route, db::api_control::AdminCommandRoute::Registration)
                == registration_enabled.is_some(),
            "administrator command payload does not match route"
        );
        let hashes = self
            .keyring
            .admin_command_hashes(&admission.idempotency, route)?;
        anyhow::ensure!(
            admission.idempotency.actor_id == Some(admission.authority.user_id),
            "administrator command actor and idempotency identity differ"
        );
        let mut tx = self.command_pool.begin().await?;
        if let Err(error) = self
            .cluster
            .admit(crate::cluster::ClusterOperation::AdminMutation)
        {
            tx.rollback().await?;
            return Ok(ApiMutationOutcome::Rejected(
                ApiMutationRejection::Unavailable(error.to_string()),
            ));
        }
        let actor_id = admission.authority.user_id;
        let auth_generation = admission.authority.auth_generation;
        let session_hash = crate::auth::token_hash(admission.authority.session_token);
        let admit_sql = match route {
            db::api_control::AdminCommandRoute::TlsReload =>
                "SELECT * FROM northstar_admin_tls_reload_admit($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)",
            db::api_control::AdminCommandRoute::PanicDisconnect =>
                "SELECT * FROM northstar_admin_panic_disconnect_admit($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)",
            db::api_control::AdminCommandRoute::Registration =>
                "SELECT * FROM northstar_admin_registration_admit($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)",
        };
        let row = sqlx::query(admit_sql)
            .bind(actor_id)
            .bind(auth_generation)
            .bind(session_hash.as_slice())
            .bind(hashes.current_scope.as_slice())
            .bind(hashes.previous_scope.as_ref().map(<[u8; 32]>::as_slice))
            .bind(hashes.current_principal.as_slice())
            .bind(hashes.previous_principal.as_ref().map(<[u8; 32]>::as_slice))
            .bind(hashes.current_fingerprint.as_slice())
            .bind(
                hashes
                    .previous_fingerprint
                    .as_ref()
                    .map(<[u8; 32]>::as_slice),
            )
            .bind(&hashes.current_key_id)
            .bind(admission.idempotency.request_id)
            .bind(admission.idempotency.lease_seconds)
            .bind(admission.idempotency.ttl_seconds)
            .fetch_one(&mut *tx)
            .await?;
        let outcome: &str = row.try_get("outcome")?;
        match outcome {
            "acquired" => {
                let record_id: Uuid = row.try_get("record_id")?;
                let lease_token: Uuid = row.try_get("lease_token")?;
                let operation_id = if registration_enabled.is_some() {
                    None
                } else {
                    Some(Uuid::new_v4())
                };
                let response = match operation_id {
                    Some(operation_id) => StoredApiResponse::json(
                        202,
                        json!({"operation_id":operation_id,"status":"pending"}),
                    )?
                    .with_header(
                        "location",
                        format!("/api/v1/admin/operations/{operation_id}"),
                    ),
                    None => StoredApiResponse::json(
                        200,
                        json!({"open_registration":registration_enabled.expect("checked route")}),
                    )?,
                };
                let sealed = self.keyring.seal_admin_command_response(
                    route,
                    record_id,
                    &hashes.current_scope,
                    &hashes.current_fingerprint,
                    &response.headers,
                    &response.body,
                )?;
                let commit_sql = match route {
                    db::api_control::AdminCommandRoute::TlsReload =>
                        "SELECT northstar_admin_tls_reload_commit($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)",
                    db::api_control::AdminCommandRoute::PanicDisconnect =>
                        "SELECT northstar_admin_panic_disconnect_commit($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)",
                    db::api_control::AdminCommandRoute::Registration =>
                        "SELECT northstar_admin_registration_commit($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)",
                };
                let commit = sqlx::query_scalar(commit_sql)
                    .bind(record_id)
                    .bind(lease_token)
                    .bind(actor_id)
                    .bind(auth_generation)
                    .bind(session_hash.as_slice());
                let commit = match operation_id {
                    Some(operation_id) => commit.bind(operation_id),
                    None => commit.bind(registration_enabled.expect("checked route")),
                };
                let committed: bool = commit
                    .bind(&sealed.key_id)
                    .bind(sealed.nonce.as_slice())
                    .bind(&sealed.ciphertext)
                    .bind(admission.idempotency.ttl_seconds)
                    .fetch_one(&mut *tx)
                    .await?;
                anyhow::ensure!(
                    committed,
                    "administrator command lease changed before commit"
                );
                tx.commit().await?;
                Ok(ApiMutationOutcome::Committed(response))
            }
            "replay" => {
                let record_id: Uuid = row.try_get("record_id")?;
                let request_id: Uuid = row.try_get("request_id")?;
                let stored_scope_hash: Vec<u8> = row.try_get("stored_scope_hash")?;
                let stored_fingerprint: Vec<u8> = row.try_get("stored_fingerprint")?;
                let status: i16 = row.try_get("response_status")?;
                let response_key_id: String = row.try_get("response_key_id")?;
                let response_nonce: Vec<u8> = row.try_get("response_nonce")?;
                let response_ciphertext: Vec<u8> = row.try_get("response_ciphertext")?;
                let replay = self.keyring.open_admin_command_replay(
                    route,
                    db::api_control::AdminCommandReplayRecord {
                        record_id,
                        request_id,
                        scope_hash: &stored_scope_hash,
                        fingerprint: &stored_fingerprint,
                        status,
                        key_id: &response_key_id,
                        nonce: &response_nonce,
                        ciphertext: response_ciphertext,
                    },
                )?;
                if row.try_get::<bool, _>("needs_rotation")? {
                    let sealed = self.keyring.seal_admin_command_response(
                        route,
                        record_id,
                        &hashes.current_scope,
                        &hashes.current_fingerprint,
                        &replay.headers,
                        &replay.body,
                    )?;
                    let rekey_sql = match route {
                        db::api_control::AdminCommandRoute::TlsReload =>
                            "SELECT northstar_admin_tls_reload_rekey($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)",
                        db::api_control::AdminCommandRoute::PanicDisconnect =>
                            "SELECT northstar_admin_panic_disconnect_rekey($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)",
                        db::api_control::AdminCommandRoute::Registration =>
                            "SELECT northstar_admin_registration_rekey($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)",
                    };
                    let changed: bool = sqlx::query_scalar(rekey_sql)
                        .bind(record_id)
                        .bind(actor_id)
                        .bind(auth_generation)
                        .bind(session_hash.as_slice())
                        .bind(&stored_scope_hash)
                        .bind(&stored_fingerprint)
                        .bind(hashes.current_scope.as_slice())
                        .bind(hashes.current_principal.as_slice())
                        .bind(hashes.current_fingerprint.as_slice())
                        .bind(&sealed.key_id)
                        .bind(sealed.nonce.as_slice())
                        .bind(&sealed.ciphertext)
                        .fetch_one(&mut *tx)
                        .await?;
                    if !changed {
                        tx.rollback().await?;
                        return Ok(ApiMutationOutcome::Rejected(
                            ApiMutationRejection::IdempotencyConflict,
                        ));
                    }
                }
                tx.commit().await?;
                Ok(ApiMutationOutcome::Replay(replay))
            }
            "forbidden" => {
                tx.rollback().await?;
                Ok(ApiMutationOutcome::Rejected(
                    ApiMutationRejection::Forbidden,
                ))
            }
            "busy" | "capacity_limited" | "in_progress" | "idempotency_conflict" => {
                let retry_after: Option<i64> = row.try_get("retry_after")?;
                let retry_after = retry_after.unwrap_or_default().max(1) as u64;
                let rejection = match outcome {
                    "busy" => ApiMutationRejection::Busy { retry_after },
                    "capacity_limited" => ApiMutationRejection::CapacityLimited { retry_after },
                    "in_progress" => ApiMutationRejection::InProgress { retry_after },
                    _ => ApiMutationRejection::IdempotencyConflict,
                };
                tx.rollback().await?;
                Ok(ApiMutationOutcome::Rejected(rejection))
            }
            _ => anyhow::bail!("administrator command returned an unknown outcome"),
        }
    }
}

impl AdminDispatchRepository for PostgresAdminDispatchRepository {
    async fn reload_tls(
        &self,
        admission: AdminMutationAdmission<'_>,
    ) -> Result<ApiMutationOutcome<StoredApiResponse>> {
        self.command
            .dispatch(
                admission,
                db::api_control::AdminCommandRoute::TlsReload,
                None,
            )
            .await
    }
    async fn panic_disconnect(
        &self,
        admission: AdminMutationAdmission<'_>,
    ) -> Result<ApiMutationOutcome<StoredApiResponse>> {
        self.command
            .dispatch(
                admission,
                db::api_control::AdminCommandRoute::PanicDisconnect,
                None,
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
