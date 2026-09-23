//! Administrative invitation commands and input policy.
use crate::services::{
    api_mutations::{
        AdminMutationAdmission, ApiMutationOutcome, ApiMutationRejection, StoredApiResponse,
    },
    report_moderation::valid_administrative_text,
};
use uuid::Uuid;

pub(crate) struct InvitationInput<'a> {
    pub(crate) label: &'a str,
    pub(crate) max_uses: Option<i32>,
    pub(crate) expires_in_hours: Option<i32>,
}

pub(crate) struct CreateInvitationCommand<'a> {
    pub(crate) admission: AdminMutationAdmission<'a>,
    pub(crate) label: &'a str,
    pub(crate) max_uses: i32,
    pub(crate) expires_in_hours: Option<i32>,
}

pub(crate) trait InvitationAdminRepository: Send + Sync {
    fn create(
        &self,
        command: CreateInvitationCommand<'_>,
    ) -> impl std::future::Future<Output = anyhow::Result<ApiMutationOutcome<StoredApiResponse>>> + Send;
    fn revoke(
        &self,
        admission: AdminMutationAdmission<'_>,
        id: Uuid,
    ) -> impl std::future::Future<Output = anyhow::Result<ApiMutationOutcome<StoredApiResponse>>> + Send;
}

#[derive(Clone)]
pub(crate) struct InvitationAdminService<R> {
    repository: R,
}

impl<R: InvitationAdminRepository> InvitationAdminService<R> {
    pub(crate) fn new(repository: R) -> Self {
        Self { repository }
    }

    pub(crate) async fn create<'a>(
        &self,
        admission: AdminMutationAdmission<'a>,
        input: InvitationInput<'a>,
    ) -> anyhow::Result<ApiMutationOutcome<StoredApiResponse>> {
        let label = input.label.trim();
        let max_uses = input.max_uses.unwrap_or(1);
        let validation_error = if !valid_administrative_text(label, 128, 512, false) {
            Some("invitation label is invalid")
        } else if !(1..=100_000).contains(&max_uses) {
            Some("invitation max uses is invalid")
        } else if input
            .expires_in_hours
            .is_some_and(|hours| !(1..=8760).contains(&hours))
        {
            Some("invitation expiry is invalid")
        } else {
            None
        };
        if let Some(message) = validation_error {
            return Ok(ApiMutationOutcome::Rejected(
                ApiMutationRejection::BadRequest(message),
            ));
        }
        self.repository
            .create(CreateInvitationCommand {
                admission,
                label,
                max_uses,
                expires_in_hours: input.expires_in_hours,
            })
            .await
    }

    pub(crate) async fn revoke(
        &self,
        admission: AdminMutationAdmission<'_>,
        id: Uuid,
    ) -> anyhow::Result<ApiMutationOutcome<StoredApiResponse>> {
        self.repository.revoke(admission, id).await
    }
}
