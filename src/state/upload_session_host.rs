//! The node's side of the upload context's session handler.

use super::AppState;
use northstar_upload_application::{
    UploadSlotAdmission, UploadSlotLimits, UploadSlotRequestCommand,
};
use northstar_upload_xmpp::UploadSessionHost;

impl UploadSessionHost for AppState {
    fn upload_enabled(&self) -> bool {
        self.config.xmpp_http_upload_enabled()
    }

    fn upload_local_domain(&self) -> &str {
        self.config.domain.as_str()
    }

    fn upload_public_url(&self) -> &str {
        &self.config.public_url
    }

    fn upload_slot_limits(&self) -> UploadSlotLimits {
        northstar_upload_application::UploadSlotLimits {
            max_file_bytes: self.config.upload_max_bytes,
            max_files_per_user: self.config.upload_max_files_per_user,
            max_bytes_per_user: self.config.upload_max_bytes_per_user,
            max_retained_files: self.config.upload_storage_max_retained_files,
            max_retained_bytes: self.config.upload_storage_max_retained_bytes,
            max_pending_jobs: self.config.upload_storage_max_pending_jobs,
        }
    }

    fn upload_storage_backend(&self) -> &'static str {
        self.upload_store().backend()
    }

    async fn reserve_upload_slot(
        &self,
        command: UploadSlotRequestCommand<'_>,
    ) -> anyhow::Result<UploadSlotAdmission> {
        self.upload
            .upload_service()
            .execute_upload_slot_reservation(command)
            .await
    }
}
