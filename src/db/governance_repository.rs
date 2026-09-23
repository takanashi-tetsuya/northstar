//! Governance resources, immutable export pages and encrypted response replay.
use crate::{
    db::{
        self,
        admin_mutations::{AdminMutationStart, AdminMutationStore},
    },
    services::{api_mutations::*, api_queries::ApiReadAuthority, governance::*},
};
use serde::Serialize;
use sqlx::{PgPool, Postgres, Transaction};
use std::sync::Arc;
use uuid::Uuid;

#[derive(Clone)]
pub(crate) struct PostgresGovernanceRepository<C> {
    pool: PgPool,
    mutations: AdminMutationStore,
    keyring: Arc<db::ApiControlKeyring>,
    cursors: C,
}
impl<C: GovernanceCursorCodec> PostgresGovernanceRepository<C> {
    pub(crate) fn new(
        pool: PgPool,
        mutations: AdminMutationStore,
        keyring: Arc<db::ApiControlKeyring>,
        cursors: C,
    ) -> Self {
        Self {
            pool,
            mutations,
            keyring,
            cursors,
        }
    }

    async fn finish_export<T: Serialize>(
        &self,
        mut tx: Transaction<'_, Postgres>,
        lease: &db::IdempotencyLease,
        export: &T,
        next_cursor: Option<String>,
    ) -> Result<ApiMutationOutcome<StoredApiResponse>, GovernanceFailure> {
        let mut value = serde_json::to_value(export).map_err(GovernanceFailure::internal)?;
        value
            .as_object_mut()
            .ok_or_else(|| {
                GovernanceFailure::internal(anyhow::anyhow!("export response is not an object"))
            })?
            .insert("next_cursor".into(), serde_json::json!(next_cursor));
        // Materialize and validate all bytes before publishing either the
        // export lease/audit or its idempotent response. The HTTP body is owned.
        let response = StoredApiResponse::json(200, value)
            .map_err(|error| GovernanceFailure::internal(error).operation())?;
        ensure_governance_export_size(&response.body).map_err(GovernanceFailure::operation)?;
        let persisted =
            db::api_mutations::persist_response_in_tx(&self.keyring, &mut tx, lease, &response)
                .await
                .map_err(|error| GovernanceFailure::internal(error).operation())?;
        if !persisted {
            return Err(GovernanceFailure::internal(anyhow::anyhow!(
                "governance-export idempotency lease changed"
            ))
            .operation());
        }
        // Preserve the distinction between response-persistence failure and
        // commit failure in the existing governance counters.
        tx.commit().await.map_err(GovernanceFailure::internal)?;
        Ok(ApiMutationOutcome::Committed(response))
    }
}

impl<C: GovernanceCursorCodec> GovernanceRepository for PostgresGovernanceRepository<C> {
    async fn list_holds(
        &self,
        actor: ApiReadAuthority<'_>,
        active_only: bool,
        limit: i64,
        access_key_sha256: &str,
    ) -> Result<Vec<LegalHoldSummary>, GovernanceFailure> {
        db::list_legal_holds_audited(
            &self.pool,
            actor.user_id,
            actor.auth_generation,
            actor.session_token,
            active_only,
            limit,
            access_key_sha256,
        )
        .await
        .map_err(GovernanceFailure::hold)
    }

    async fn create_hold(
        &self,
        command: CreateHoldCommand<'_>,
    ) -> Result<ApiMutationOutcome<StoredApiResponse>, GovernanceFailure> {
        let (mut tx, lease) = match self
            .mutations
            .start(&command.admission)
            .await
            .map_err(GovernanceFailure::internal)?
        {
            AdminMutationStart::Ready(tx, lease) => (tx, lease),
            AdminMutationStart::Finished(outcome) => return Ok(outcome),
        };
        let id = Uuid::new_v4();
        let input = db::CreateLegalHold {
            id,
            title: command.title,
            authority_reference: command.authority_reference,
            reason: command.reason,
            targets: command.targets,
            request_id: lease.request_id,
        };
        db::create_legal_hold_in_tx(&mut tx, command.admission.authority.user_id, &input)
            .await
            .map_err(|error| GovernanceFailure::hold(error).operation())?;
        let response = StoredApiResponse::json(
            201,
            serde_json::json!({"id":id,"active":true,"target_count":command.targets.len()}),
        )
        .map_err(GovernanceFailure::internal)?;
        self.mutations
            .finish(tx, &lease, response)
            .await
            .map_err(GovernanceFailure::internal)
    }

    async fn release_hold(
        &self,
        admission: AdminMutationAdmission<'_>,
        id: Uuid,
        reason: &str,
    ) -> Result<ApiMutationOutcome<StoredApiResponse>, GovernanceFailure> {
        let (mut tx, lease) = match self
            .mutations
            .start(&admission)
            .await
            .map_err(GovernanceFailure::internal)?
        {
            AdminMutationStart::Ready(tx, lease) => (tx, lease),
            AdminMutationStart::Finished(outcome) => return Ok(outcome),
        };
        db::release_legal_hold_in_tx(
            &mut tx,
            admission.authority.user_id,
            id,
            reason,
            lease.request_id,
        )
        .await
        .map_err(|error| GovernanceFailure::hold(error).operation())?;
        let response = StoredApiResponse::json(200, serde_json::json!({"id":id,"active":false}))
            .map_err(GovernanceFailure::internal)?;
        self.mutations
            .finish(tx, &lease, response)
            .await
            .map_err(GovernanceFailure::internal)
    }

    async fn export_hold(
        &self,
        command: HoldExportCommand<'_>,
    ) -> Result<ApiMutationOutcome<StoredApiResponse>, GovernanceFailure> {
        let actor = command.admission.authority.user_id;
        let (mut tx, lease) = match self
            .mutations
            .start(&command.admission)
            .await
            .map_err(GovernanceFailure::internal)?
        {
            AdminMutationStart::Ready(tx, lease) => (tx, lease),
            AdminMutationStart::Finished(outcome) => return Ok(outcome),
        };
        // Replay wins before cursor expiry checks; a fresh key must verify
        // against the clock on the connection that already owns this request.
        let continuation = if let Some(token) = command.cursor {
            let now = db::database_cursor_clock_in_tx(&mut tx)
                .await
                .map_err(GovernanceFailure::internal)?;
            Some(
                self.cursors
                    .decode_hold(actor, command.hold_id, token, now)?,
            )
        } else {
            None
        };
        let export = db::export_legal_hold_page_in_tx(
            &mut tx,
            actor,
            command.hold_id,
            command.max_rows,
            Uuid::new_v4(),
            continuation,
            lease.request_id,
        )
        .await
        .map_err(GovernanceFailure::export)?;
        let next_cursor = self.cursors.encode_hold(actor, &export)?;
        self.finish_export(tx, &lease, &export, next_cursor).await
    }

    async fn export_audit(
        &self,
        command: AuditExportCommand<'_>,
    ) -> Result<ApiMutationOutcome<StoredApiResponse>, GovernanceFailure> {
        let actor = command.admission.authority.user_id;
        let (mut tx, lease) = match self
            .mutations
            .start(&command.admission)
            .await
            .map_err(GovernanceFailure::internal)?
        {
            AdminMutationStart::Ready(tx, lease) => (tx, lease),
            AdminMutationStart::Finished(outcome) => return Ok(outcome),
        };
        let continuation = if let Some(token) = command.cursor {
            let now = db::database_cursor_clock_in_tx(&mut tx)
                .await
                .map_err(GovernanceFailure::internal)?;
            Some(
                self.cursors
                    .decode_audit(actor, command.start, command.end, token, now)?,
            )
        } else {
            None
        };
        let export = db::export_audit_log_page_in_tx(
            &mut tx,
            db::AuditExportPageRequest {
                actor_id: actor,
                start: command.start,
                end: command.end,
                max_rows: command.max_rows,
                initial_export_id: Uuid::new_v4(),
                continuation,
                access_request_id: lease.request_id,
            },
        )
        .await
        .map_err(GovernanceFailure::export)?;
        let next_cursor = self
            .cursors
            .encode_audit(actor, command.start, command.end, &export)?;
        self.finish_export(tx, &lease, &export, next_cursor).await
    }
}

#[cfg(test)]
#[path = "governance_repository_tests.rs"]
mod tests;
