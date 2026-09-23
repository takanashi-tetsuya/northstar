//! Account mutations, registration policy and exact-session administrative commands.
use crate::services::api_mutations::{
    AdminMutationAdmission, ApiMutationOutcome, ApiMutationRejection, StoredApiResponse,
};
use anyhow::Result;
use uuid::Uuid;

#[derive(Clone, Copy)]
pub(crate) struct UserStatusPatch {
    pub(crate) disabled: Option<bool>,
    pub(crate) admin: Option<bool>,
}

pub(crate) trait AccountAdminRepository: Send + Sync {
    fn update_user(
        &self,
        admission: AdminMutationAdmission<'_>,
        user_id: Uuid,
        patch: UserStatusPatch,
    ) -> impl std::future::Future<Output = Result<ApiMutationOutcome<StoredApiResponse>>> + Send;
    fn clear_offline_messages(
        &self,
        admission: AdminMutationAdmission<'_>,
    ) -> impl std::future::Future<Output = Result<ApiMutationOutcome<StoredApiResponse>>> + Send;
}

#[derive(Clone)]
pub(crate) struct AccountAdminService<R> {
    repository: R,
}
impl<R: AccountAdminRepository> AccountAdminService<R> {
    pub(crate) fn new(repository: R) -> Self {
        Self { repository }
    }
    pub(crate) async fn update_user(
        &self,
        admission: AdminMutationAdmission<'_>,
        user_id: Uuid,
        patch: UserStatusPatch,
    ) -> Result<ApiMutationOutcome<StoredApiResponse>> {
        if patch.disabled.is_none() && patch.admin.is_none() {
            return Ok(ApiMutationOutcome::Rejected(
                ApiMutationRejection::BadRequest("user patch is empty"),
            ));
        }
        self.repository.update_user(admission, user_id, patch).await
    }
    pub(crate) async fn clear_offline_messages(
        &self,
        admission: AdminMutationAdmission<'_>,
    ) -> Result<ApiMutationOutcome<StoredApiResponse>> {
        self.repository.clear_offline_messages(admission).await
    }
}

pub(crate) trait RegistrationAdminRepository: Send + Sync {
    fn set_registration(
        &self,
        admission: AdminMutationAdmission<'_>,
        enabled: bool,
    ) -> impl std::future::Future<Output = Result<ApiMutationOutcome<StoredApiResponse>>> + Send;
    fn current_registration_closed(&self)
        -> impl std::future::Future<Output = Result<bool>> + Send;
}

pub(crate) trait RegistrationCache: Send + Sync {
    fn dependency_locked(&self) -> bool;
    fn apply_current_closed(&self, closed: bool);
}

#[derive(Clone)]
pub(crate) struct RegistrationAdminService<R, C> {
    repository: R,
    cache: C,
}
impl<R: RegistrationAdminRepository, C: RegistrationCache> RegistrationAdminService<R, C> {
    pub(crate) fn new(repository: R, cache: C) -> Self {
        Self { repository, cache }
    }
    pub(crate) async fn set_registration(
        &self,
        admission: AdminMutationAdmission<'_>,
        enabled: bool,
    ) -> Result<ApiMutationOutcome<StoredApiResponse>> {
        if enabled && self.cache.dependency_locked() {
            return Ok(ApiMutationOutcome::Rejected(ApiMutationRejection::Conflict(
                "registration cannot be opened while invitation-only mode is dependency-locked by WEB_CLIENT_ENABLED=false".into(),
            )));
        }
        let outcome = self.repository.set_registration(admission, enabled).await?;
        let committed_action = match &outcome {
            ApiMutationOutcome::Committed(_) => "registration_toggle",
            ApiMutationOutcome::Replay(_) => "idempotency_replay",
            ApiMutationOutcome::Rejected(_) => return Ok(outcome),
        };
        // Another request may have changed the durable flag since this response.
        // In particular, replay bytes cannot be used to refresh discovery state.
        match self.repository.current_registration_closed().await {
            Ok(closed) => self.cache.apply_current_closed(closed),
            Err(error) => tracing::error!(
                ?error,
                committed_action,
                "failed to refresh registration cache after committed administrator mutation"
            ),
        }
        Ok(outcome)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct SessionKickSnapshot {
    pub(crate) user_id: Uuid,
    pub(crate) auth_generation: i64,
    pub(crate) connection_id: Uuid,
}

pub(crate) trait AdminSessionLookup: Send + Sync {
    /// Called only after admission and replay lookup. The returned value owns
    /// its identity; no live-session map guard can cross a database await.
    fn exact_connection(&self, connection_id: Uuid) -> Option<SessionKickSnapshot>;
}

pub(crate) trait SessionAdminRepository: Send + Sync {
    fn kick_session<L: AdminSessionLookup>(
        &self,
        admission: AdminMutationAdmission<'_>,
        connection_id: Uuid,
        sessions: &L,
    ) -> impl std::future::Future<Output = Result<ApiMutationOutcome<StoredApiResponse>>> + Send;
}

#[derive(Clone)]
pub(crate) struct SessionAdminService<R, L> {
    repository: R,
    sessions: L,
}
impl<R: SessionAdminRepository, L: AdminSessionLookup> SessionAdminService<R, L> {
    pub(crate) fn new(repository: R, sessions: L) -> Self {
        Self {
            repository,
            sessions,
        }
    }
    pub(crate) async fn kick_session(
        &self,
        admission: AdminMutationAdmission<'_>,
        connection_id: Uuid,
    ) -> Result<ApiMutationOutcome<StoredApiResponse>> {
        if connection_id.is_nil() {
            return Ok(ApiMutationOutcome::Rejected(
                ApiMutationRejection::BadRequest("connection id must not be nil"),
            ));
        }
        self.repository
            .kick_session(admission, connection_id, &self.sessions)
            .await
    }
}

#[cfg(test)]
#[path = "account_admin_tests.rs"]
mod tests;
