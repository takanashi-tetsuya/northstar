//! Repository port traits for HTTP file upload slot reservation and file records.

use uuid::Uuid;

use crate::UploadSlotRequest;

pub type UploadRepoResult<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;

/// Repository port for HTTP upload slot reservation and file lifecycle persistence.
pub trait UploadRepository: Send + Sync {
    /// Reserve an upload slot with quota validation.
    fn reserve_slot(
        &self,
        request: &UploadSlotRequest<'_>,
    ) -> impl std::future::Future<Output = UploadRepoResult<Uuid>> + Send;

    /// Complete or confirm an upload file after payload transfer.
    fn confirm_upload(
        &self,
        file_id: Uuid,
        user_id: Uuid,
    ) -> impl std::future::Future<Output = UploadRepoResult<()>> + Send;

    /// Prune expired or uncompleted upload slots.
    fn prune_expired_slots(
        &self,
    ) -> impl std::future::Future<Output = UploadRepoResult<u64>> + Send;
}
