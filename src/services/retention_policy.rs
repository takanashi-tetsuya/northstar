//! Account and room retention policies, including the operator's upper bounds.
use crate::services::api_mutations::{ApiMutationOutcome, IdempotencyRequest, StoredApiResponse};
use serde::Serialize;
use uuid::Uuid;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize)]
pub struct UserRetentionPolicy {
    pub personal_mam_days: Option<i32>,
    pub offline_message_days: Option<i32>,
    pub moderation_evidence_days: Option<i32>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub struct RetentionPolicyLimits {
    pub personal_mam_days: i64,
    pub offline_message_days: i64,
    pub moderation_evidence_days: i64,
}

#[derive(Debug, thiserror::Error)]
pub enum RetentionPolicyError {
    #[error("authentication is required")]
    Unauthorized,
    #[error(
        "retention policy is outside the operator limit or would extend user-controlled retention"
    )]
    Forbidden,
    #[error("retention policy subject does not exist")]
    NotFound,
    #[error("retention policy backend failed")]
    Internal(#[source] anyhow::Error),
}

pub(crate) fn effective_days(value: Option<i32>, global: i64) -> i64 {
    value
        .map(i64::from)
        .unwrap_or_else(|| if global == 0 { i64::MAX } else { global })
}

pub(crate) fn valid_requested_days(value: Option<i32>, global: i64, minimum: i32) -> bool {
    value.is_none_or(|days| {
        days >= minimum && days <= 36_500 && (global == 0 || i64::from(days) <= global)
    })
}

pub(crate) fn policy_does_not_extend(
    old: UserRetentionPolicy,
    new: UserRetentionPolicy,
    limits: RetentionPolicyLimits,
) -> bool {
    effective_days(new.personal_mam_days, limits.personal_mam_days)
        <= effective_days(old.personal_mam_days, limits.personal_mam_days)
        && effective_days(new.offline_message_days, limits.offline_message_days)
            <= effective_days(old.offline_message_days, limits.offline_message_days)
        && effective_days(
            new.moderation_evidence_days,
            limits.moderation_evidence_days,
        ) <= effective_days(
            old.moderation_evidence_days,
            limits.moderation_evidence_days,
        )
}

pub(crate) struct RetentionMutationAdmission<'a> {
    pub(crate) session_token: &'a str,
    pub(crate) idempotency: IdempotencyRequest<'a>,
}

pub(crate) trait RetentionPolicyRepository: Send + Sync {
    fn user_policy(
        &self,
        session_token: &str,
    ) -> impl std::future::Future<Output = Result<UserRetentionPolicy, RetentionPolicyError>> + Send;
    fn muc_policy(
        &self,
        session_token: &str,
        room_id: Uuid,
    ) -> impl std::future::Future<Output = Result<Option<i32>, RetentionPolicyError>> + Send;
    fn set_user_policy(
        &self,
        admission: RetentionMutationAdmission<'_>,
        requested: UserRetentionPolicy,
        limits: RetentionPolicyLimits,
    ) -> impl std::future::Future<
        Output = Result<ApiMutationOutcome<StoredApiResponse>, RetentionPolicyError>,
    > + Send;
    fn set_muc_policy(
        &self,
        admission: RetentionMutationAdmission<'_>,
        room_id: Uuid,
        requested_days: Option<i32>,
        global_days: i64,
    ) -> impl std::future::Future<
        Output = Result<ApiMutationOutcome<StoredApiResponse>, RetentionPolicyError>,
    > + Send;
}

#[derive(Clone)]
pub(crate) struct RetentionPolicyService<R> {
    repository: R,
    limits: RetentionPolicyLimits,
    muc_limit_days: i64,
}

impl<R: RetentionPolicyRepository> RetentionPolicyService<R> {
    pub(crate) fn new(repository: R, limits: RetentionPolicyLimits, muc_limit_days: i64) -> Self {
        Self {
            repository,
            limits,
            muc_limit_days,
        }
    }

    pub(crate) fn limits(&self) -> RetentionPolicyLimits {
        self.limits
    }

    pub(crate) fn muc_limit_days(&self) -> i64 {
        self.muc_limit_days
    }

    pub(crate) async fn user_policy(
        &self,
        session_token: &str,
    ) -> Result<UserRetentionPolicy, RetentionPolicyError> {
        self.repository.user_policy(session_token).await
    }

    pub(crate) async fn muc_policy(
        &self,
        session_token: &str,
        room_id: Uuid,
    ) -> Result<Option<i32>, RetentionPolicyError> {
        self.repository.muc_policy(session_token, room_id).await
    }

    pub(crate) async fn set_user_policy(
        &self,
        admission: RetentionMutationAdmission<'_>,
        requested: UserRetentionPolicy,
    ) -> Result<ApiMutationOutcome<StoredApiResponse>, RetentionPolicyError> {
        self.repository
            .set_user_policy(admission, requested, self.limits)
            .await
    }

    pub(crate) async fn set_muc_policy(
        &self,
        admission: RetentionMutationAdmission<'_>,
        room_id: Uuid,
        requested_days: Option<i32>,
    ) -> Result<ApiMutationOutcome<StoredApiResponse>, RetentionPolicyError> {
        self.repository
            .set_muc_policy(admission, room_id, requested_days, self.muc_limit_days)
            .await
    }
}
