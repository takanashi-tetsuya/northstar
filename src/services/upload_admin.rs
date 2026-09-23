//! Administrative upload recovery commands and their atomic repository boundary.
use crate::services::{
    api_mutations::{
        api_request_fingerprint, AdminMutationAdmission, ApiMutationOutcome, StoredApiResponse,
    },
    api_queries::UploadDeadLetterId,
};

pub(crate) trait UploadAdminRepository: Send + Sync {
    fn retry_dead_letter(
        &self,
        admission: AdminMutationAdmission<'_>,
        id: UploadDeadLetterId,
    ) -> impl std::future::Future<Output = anyhow::Result<ApiMutationOutcome<StoredApiResponse>>> + Send;
}

#[derive(Clone)]
pub(crate) struct UploadAdminService<R> {
    repository: R,
}

impl<R: UploadAdminRepository> UploadAdminService<R> {
    pub(crate) fn new(repository: R) -> Self {
        Self { repository }
    }

    pub(crate) async fn retry_dead_letter(
        &self,
        admission: AdminMutationAdmission<'_>,
        id: UploadDeadLetterId,
    ) -> anyhow::Result<ApiMutationOutcome<StoredApiResponse>> {
        self.repository.retry_dead_letter(admission, id).await
    }
}

/// Bind an otherwise bodyless administrator retry to the credential
/// generation which authorized it. The outer API-control HMAC keeps this
/// digest opaque in storage. Keeping the actor UUID as principal/capacity
/// scope means reuse of one key after a credential rotation finds the same
/// record and fails with a fingerprint conflict instead of opening a second
/// idempotency namespace.
pub(crate) fn admin_generation_bound_request_fingerprint(
    base: [u8; 32],
    auth_generation: i64,
) -> [u8; 32] {
    let mut material = [0_u8; 40];
    material[..32].copy_from_slice(&base);
    material[32..].copy_from_slice(&auth_generation.to_be_bytes());
    api_request_fingerprint(
        "application/vnd.northstar.admin-auth-generation-v1",
        &material,
    )
}
