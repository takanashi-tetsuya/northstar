//! Account status, cleanup intents, registration settings and replay commit together.
use crate::{
    db::{
        self,
        admin_mutations::{
            enqueue_operation_response_in_tx, AdminMutationStart, AdminMutationStore,
            AdminOperationIntent,
        },
    },
    services::{account_admin::*, api_mutations::*, operations::AuthorizationPolicy},
};
use anyhow::Result;
use serde_json::json;
use sqlx::PgPool;
use uuid::Uuid;

#[derive(Clone)]
pub(crate) struct PostgresAccountAdminRepository {
    mutations: AdminMutationStore,
}
impl PostgresAccountAdminRepository {
    pub(crate) fn new(mutations: AdminMutationStore) -> Self {
        Self { mutations }
    }
}

impl AccountAdminRepository for PostgresAccountAdminRepository {
    async fn update_user(
        &self,
        admission: AdminMutationAdmission<'_>,
        user_id: Uuid,
        patch: UserStatusPatch,
    ) -> Result<ApiMutationOutcome<StoredApiResponse>> {
        let (mut tx, lease) = match self.mutations.start(&admission).await? {
            AdminMutationStart::Ready(tx, lease) => (tx, lease),
            AdminMutationStart::Finished(outcome) => return Ok(outcome),
        };
        let actor = &admission.authority;
        let previous_auth_generation = match db::set_user_status_admin_in_tx(
            &mut tx,
            actor.user_id,
            actor.auth_generation,
            actor.session_token,
            user_id,
            patch.disabled,
            patch.admin,
        )
        .await
        {
            Ok(generation) => generation,
            Err(error) => {
                // These failures did not retain an idempotency reservation in
                // the HTTP implementation, so they remain retryable here.
                let rejection = match error {
                    db::UserStatusError::NotFound =>
                        ApiMutationRejection::BadRequest("user does not exist"),
                    db::UserStatusError::LastAdministrator =>
                        ApiMutationRejection::Conflict(error.to_string()),
                    db::UserStatusError::SelfMutation => ApiMutationRejection::BadRequest(
                        "an administrator cannot disable or demote the account authorizing this request",
                    ),
                    db::UserStatusError::Unauthorized => ApiMutationRejection::Forbidden,
                    db::UserStatusError::Internal(error) => return Err(error),
                };
                tx.rollback().await?;
                return Ok(ApiMutationOutcome::Rejected(rejection));
            }
        };
        let response = if patch.disabled == Some(true) {
            let target = format!("user:{user_id}:generation:{previous_auth_generation}");
            let (response, _) = enqueue_operation_response_in_tx(
                &mut tx,
                &admission,
                &lease,
                AdminOperationIntent {
                    kind: "admin.user_session_cleanup",
                    target: Some(&target),
                    policy: AuthorizationPolicy::CommittedConsequence,
                    payload: &json!({"user_id":user_id,"auth_generation":previous_auth_generation}),
                },
            )
            .await?;
            response
        } else {
            StoredApiResponse::json(200, json!({"updated":true}))?
        };
        self.mutations.finish(tx, &lease, response).await
    }

    async fn clear_offline_messages(
        &self,
        admission: AdminMutationAdmission<'_>,
    ) -> Result<ApiMutationOutcome<StoredApiResponse>> {
        let (mut tx, lease) = match self.mutations.start(&admission).await? {
            AdminMutationStart::Ready(tx, lease) => (tx, lease),
            AdminMutationStart::Finished(outcome) => return Ok(outcome),
        };
        let removed = match db::clear_offline_messages_in_tx(
            &mut tx,
            admission.authority.user_id,
            Some(lease.request_id),
        )
        .await
        {
            Ok(removed) => removed,
            Err(error)
                if error
                    .downcast_ref::<db::OfflineMessagesTransportOwned>()
                    .is_some() =>
            {
                tx.rollback().await?;
                return Ok(ApiMutationOutcome::Rejected(
                    ApiMutationRejection::Conflict(error.to_string()),
                ));
            }
            Err(error) => return Err(error),
        };
        let response = StoredApiResponse::json(200, json!({"cleared":true,"removed":removed}))?;
        self.mutations.finish(tx, &lease, response).await
    }
}

#[derive(Clone)]
pub(crate) struct PostgresRegistrationAdminRepository {
    mutations: AdminMutationStore,
    settings_pool: PgPool,
}
impl PostgresRegistrationAdminRepository {
    pub(crate) fn new(mutations: AdminMutationStore, settings_pool: PgPool) -> Self {
        Self {
            mutations,
            settings_pool,
        }
    }
}
impl RegistrationAdminRepository for PostgresRegistrationAdminRepository {
    async fn set_registration(
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
            "registration_closed",
            !enabled,
            Some(lease.request_id),
        )
        .await?;
        let response = StoredApiResponse::json(200, json!({"open_registration":enabled}))?;
        self.mutations.finish(tx, &lease, response).await
    }
    async fn current_registration_closed(&self) -> Result<bool> {
        let (_, closed) = db::admin_runtime_settings(&self.settings_pool).await?;
        Ok(closed)
    }
}

#[derive(Clone)]
pub(crate) struct PostgresSessionAdminRepository {
    mutations: AdminMutationStore,
}
impl PostgresSessionAdminRepository {
    pub(crate) fn new(mutations: AdminMutationStore) -> Self {
        Self { mutations }
    }
}
impl SessionAdminRepository for PostgresSessionAdminRepository {
    async fn kick_session<L: AdminSessionLookup>(
        &self,
        admission: AdminMutationAdmission<'_>,
        connection_id: Uuid,
        sessions: &L,
    ) -> Result<ApiMutationOutcome<StoredApiResponse>> {
        let (mut tx, lease) = match self.mutations.start(&admission).await? {
            AdminMutationStart::Ready(tx, lease) => (tx, lease),
            AdminMutationStart::Finished(outcome) => return Ok(outcome),
        };
        let Some(session) = sessions.exact_connection(connection_id) else {
            let response = error_response(400, "bad_request", "session does not exist")?;
            return self.mutations.finish(tx, &lease, response).await;
        };
        anyhow::ensure!(
            session.connection_id == connection_id,
            "session lookup changed connection identity"
        );
        let target = format!("connection:{connection_id}");
        let payload = json!({
            "user_id":session.user_id,
            "auth_generation":session.auth_generation,
            "connection_id":session.connection_id.to_string(),
        });
        let (response, _) = enqueue_operation_response_in_tx(
            &mut tx,
            &admission,
            &lease,
            AdminOperationIntent {
                kind: "admin.session_kick",
                target: Some(&target),
                policy: AuthorizationPolicy::ReauthorizeUntilEffect,
                payload: &payload,
            },
        )
        .await?;
        self.mutations.finish(tx, &lease, response).await
    }
}

#[cfg(test)]
#[path = "account_admin_repository_tests.rs"]
mod tests;
