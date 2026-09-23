//! Authorized, fenced upload retries with their audit and replay committed together.
use crate::{
    db::{
        self,
        admin_mutations::{AdminMutationStart, AdminMutationStore},
    },
    services::{
        api_mutations::{
            error_response, AdminMutationAdmission, ApiMutationOutcome, ApiMutationRejection,
            StoredApiResponse,
        },
        api_queries::{UploadDeadLetterId, UploadDeadLetterKind},
        upload_admin::UploadAdminRepository,
    },
};
use anyhow::Result;
use serde_json::json;

#[derive(Clone)]
pub(crate) struct PostgresUploadAdminRepository {
    mutations: AdminMutationStore,
}

impl PostgresUploadAdminRepository {
    pub(crate) fn new(mutations: AdminMutationStore) -> Self {
        Self { mutations }
    }
}

impl UploadAdminRepository for PostgresUploadAdminRepository {
    async fn retry_dead_letter(
        &self,
        admission: AdminMutationAdmission<'_>,
        id: UploadDeadLetterId,
    ) -> Result<ApiMutationOutcome<StoredApiResponse>> {
        let (mut tx, lease) = match self.mutations.start(&admission).await? {
            AdminMutationStart::Ready(tx, lease) => (tx, lease),
            AdminMutationStart::Finished(outcome) => return Ok(outcome),
        };
        let actor = &admission.authority;
        let outcome = db::retry_upload_dead_letter_in_tx(
            &mut tx,
            actor.user_id,
            actor.auth_generation,
            actor.session_token,
            id,
            lease.request_id,
        )
        .await?;
        let response = match outcome {
            db::RetryUploadDeadLetter::Retried => {
                let kind = match id {
                    UploadDeadLetterId::StorageJob(_) => UploadDeadLetterKind::StorageJob,
                    UploadDeadLetterId::Cleanup(_) => UploadDeadLetterKind::Cleanup,
                };
                StoredApiResponse::json(
                    202,
                    json!({"kind":kind.as_str(),"id":id.as_api_string(),"state":"queued"}),
                )?
            }
            db::RetryUploadDeadLetter::Unavailable => {
                error_response(404, "not_found", "upload dead-letter entry is unavailable")?
            }
            db::RetryUploadDeadLetter::Unauthorized => {
                tx.rollback().await?;
                return Ok(ApiMutationOutcome::Rejected(
                    ApiMutationRejection::Forbidden,
                ));
            }
        };
        self.mutations.finish(tx, &lease, response).await
    }
}
