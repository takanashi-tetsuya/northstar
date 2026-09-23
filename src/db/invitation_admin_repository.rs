//! Invitation resources, audit and encrypted replay commit in one transaction.
use crate::{
    db::{
        self,
        admin_mutations::{AdminMutationStart, AdminMutationStore},
    },
    services::{api_mutations::*, invitation_admin::*},
};
use anyhow::Result;
use uuid::Uuid;

#[derive(Clone)]
pub(crate) struct PostgresInvitationAdminRepository {
    mutations: AdminMutationStore,
}
impl PostgresInvitationAdminRepository {
    pub(crate) fn new(mutations: AdminMutationStore) -> Self {
        Self { mutations }
    }
}
impl InvitationAdminRepository for PostgresInvitationAdminRepository {
    async fn create(
        &self,
        command: CreateInvitationCommand<'_>,
    ) -> Result<ApiMutationOutcome<StoredApiResponse>> {
        let (mut tx, lease) = match self.mutations.start(&command.admission).await? {
            AdminMutationStart::Ready(tx, lease) => (tx, lease),
            AdminMutationStart::Finished(outcome) => return Ok(outcome),
        };
        let id = Uuid::new_v4();
        let token = crate::auth::new_session_token();
        db::create_invitation_in_tx(
            &mut tx,
            command.admission.authority.user_id,
            id,
            &token,
            command.label,
            command.max_uses,
            command.expires_in_hours,
            Some(lease.request_id),
        )
        .await?;
        let response = StoredApiResponse::json(
            201,
            serde_json::json!({"id":id,"token":token,"shown_once":true}),
        )?
        .with_optional_replay_resource_id(Some(id));
        self.mutations.finish(tx, &lease, response).await
    }

    async fn revoke(
        &self,
        admission: AdminMutationAdmission<'_>,
        id: Uuid,
    ) -> Result<ApiMutationOutcome<StoredApiResponse>> {
        let (mut tx, lease) = match self.mutations.start(&admission).await? {
            AdminMutationStart::Ready(tx, lease) => (tx, lease),
            AdminMutationStart::Finished(outcome) => return Ok(outcome),
        };
        let outcome = db::revoke_invitation_in_tx(
            &mut tx,
            admission.authority.user_id,
            id,
            Some(lease.request_id),
        )
        .await?;
        let response = match outcome {
            db::InvitationRevokeOutcome::NotFound => {
                error_response(404, "not_found", "invitation does not exist")?
            }
            db::InvitationRevokeOutcome::Revoked | db::InvitationRevokeOutcome::AlreadyRevoked => {
                StoredApiResponse::json(
                    200,
                    serde_json::json!({"revoked":true,"already_revoked":outcome == db::InvitationRevokeOutcome::AlreadyRevoked}),
                )?
            }
        };
        self.mutations.finish(tx, &lease, response).await
    }
}

#[cfg(test)]
#[path = "invitation_admin_repository_tests.rs"]
mod tests;
