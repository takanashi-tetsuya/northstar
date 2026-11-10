//! What the node provides to the session side of the upload context.

use northstar_upload_application::{
    UploadSlotAdmission, UploadSlotLimits, UploadSlotRequestCommand,
};

/// What the node provides to the XEP-0363 handler of a client session. The composition root implements it.
pub trait UploadSessionHost: Send + Sync {
    /// Whether XEP-0363 is enabled on this node.
    fn upload_enabled(&self) -> bool;
    /// The server's local domain.
    fn upload_local_domain(&self) -> &str;
    /// The public base URL slots are built on.
    fn upload_public_url(&self) -> &str;
    /// The configured limits a slot request is admitted against.
    fn upload_slot_limits(&self) -> UploadSlotLimits;
    /// The storage backend new slots are recorded with.
    fn upload_storage_backend(&self) -> &'static str;
    /// Reserves a slot through the upload application service.
    fn reserve_upload_slot(
        &self,
        command: UploadSlotRequestCommand<'_>,
    ) -> impl std::future::Future<Output = anyhow::Result<UploadSlotAdmission>> + Send;
}
