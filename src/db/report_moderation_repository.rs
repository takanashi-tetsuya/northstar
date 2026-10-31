//! Atomic moderation decisions, audit records and idempotent responses.
use crate::db::admin_mutations::{AdminMutationStart, AdminMutationStore};
use anyhow::Result;
use northstar_operations_application::report_moderation::*;
use northstar_operations_core::api_mutations::*;

#[derive(Clone)]
pub(crate) struct PostgresReportModerationRepository {
    mutations: AdminMutationStore,
}

enum RecordKind {
    Report,
    Appeal,
}

impl PostgresReportModerationRepository {
    pub(crate) fn new(mutations: AdminMutationStore) -> Self {
        Self { mutations }
    }

    async fn update(
        &self,
        kind: RecordKind,
        command: ModerationCommand<'_>,
    ) -> Result<ApiMutationOutcome<StoredApiResponse>> {
        let (mut tx, lease) = match self.mutations.start(&command.admission).await? {
            AdminMutationStart::Ready(tx, lease) => (tx, lease),
            AdminMutationStart::Finished(outcome) => return Ok(outcome),
        };
        let actor = command.admission.authority.user_id;
        let result = match kind {
            RecordKind::Report => {
                northstar_operations_postgres::reports::admin_update_report_in_tx(
                    &mut tx,
                    command.id,
                    actor,
                    command.status,
                    command.resolution,
                    lease.request_id,
                )
                .await
            }
            RecordKind::Appeal => {
                northstar_operations_postgres::reports::admin_update_appeal_in_tx(
                    &mut tx,
                    command.id,
                    actor,
                    command.status,
                    command.resolution,
                    lease.request_id,
                )
                .await
            }
        };
        let response = match result {
            Ok(()) => StoredApiResponse::json(200, serde_json::json!({"updated":true}))?,
            Err(northstar_operations_postgres::reports::ModerationUpdateError::NotFound) => {
                error_response(404, "not_found", "moderation record does not exist")?
            }
            Err(
                northstar_operations_postgres::reports::ModerationUpdateError::InvalidTransition,
            ) => error_response(409, "conflict", "invalid moderation state transition")?,
            Err(northstar_operations_postgres::reports::ModerationUpdateError::Unauthorized) => {
                tx.rollback().await?;
                return Ok(ApiMutationOutcome::Rejected(
                    ApiMutationRejection::Forbidden,
                ));
            }
            Err(northstar_operations_postgres::reports::ModerationUpdateError::Internal(error)) => {
                return Err(error)
            }
        };
        self.mutations.finish(tx, &lease, response).await
    }
}

impl ReportModerationRepository for PostgresReportModerationRepository {
    async fn update_report(
        &self,
        command: ModerationCommand<'_>,
    ) -> Result<ApiMutationOutcome<StoredApiResponse>> {
        self.update(RecordKind::Report, command).await
    }

    async fn update_appeal(
        &self,
        command: ModerationCommand<'_>,
    ) -> Result<ApiMutationOutcome<StoredApiResponse>> {
        self.update(RecordKind::Appeal, command).await
    }
}

#[cfg(test)]
#[path = "report_moderation_repository_tests.rs"]
mod tests;
