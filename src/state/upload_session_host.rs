//! The node's side of the upload context's session handler.

use super::AppState;
use northstar_upload_application::{
    UploadSlotAdmission, UploadSlotLimits, UploadSlotRequestCommand,
};
use northstar_upload_xmpp::UploadSessionHost;

impl UploadSessionHost for AppState {
    fn upload_enabled(&self) -> bool {
        self.xmpp_http_upload_enabled()
    }

    fn upload_local_domain(&self) -> &str {
        self.local_domain()
    }

    fn upload_public_url(&self) -> &str {
        AppState::upload_public_url(self)
    }

    fn upload_slot_limits(&self) -> UploadSlotLimits {
        AppState::upload_slot_limits(self)
    }

    fn upload_storage_backend(&self) -> &'static str {
        self.upload_store().backend()
    }

    async fn reserve_upload_slot(
        &self,
        command: UploadSlotRequestCommand<'_>,
    ) -> anyhow::Result<UploadSlotAdmission> {
        self.upload_service()
            .execute_upload_slot_reservation(command)
            .await
    }
}
