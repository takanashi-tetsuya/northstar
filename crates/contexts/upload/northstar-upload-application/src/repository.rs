//! Upload reservation authority. Object transfer and reconciliation use separate ports.

use uuid::Uuid;

use crate::UploadSlotRequest;

pub trait UploadRepository: Send + Sync {
    type Error;

    /// Atomically reserve account and deployment capacity for this token hash.
    /// `None` means that admission was denied without creating a reservation.
    fn reserve_slot(
        &self,
        request: &UploadSlotRequest<'_>,
        token_hash: &[u8],
    ) -> impl std::future::Future<Output = Result<Option<Uuid>, Self::Error>> + Send;
}
