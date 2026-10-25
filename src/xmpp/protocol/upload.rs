use super::{Action, ProtocolSession};
use anyhow::Result;
use northstar_upload_application::{
    UploadSlotAdmission, UploadSlotLimits, UploadSlotRequestCommand,
};
use roxmltree::Node;

impl ProtocolSession {
    pub(crate) fn http_upload_enabled(&self) -> bool {
        self.state.xmpp_http_upload_enabled()
    }

    pub(crate) fn upload_domain(&self) -> String {
        northstar_xmpp_types::jid::prepare_domainpart(&format!(
            "upload.{}",
            self.state.local_domain()
        ))
        .expect("configured XMPP domain must form a valid upload service domain")
    }

    pub(crate) async fn http_upload_slot(
        &self,
        id: &str,
        to: Option<&str>,
        request: Node<'_, '_>,
    ) -> Result<Action> {
        northstar_upload_xmpp::http_upload_slot(self, id, to, request)
            .await
            .map(Action::Send)
    }
}

impl northstar_upload_xmpp::UploadSlotSession for ProtocolSession {
    fn upload_user_id(&self) -> Option<uuid::Uuid> {
        self.authenticated.as_ref().map(|user| user.id)
    }

    fn upload_service_domain(&self) -> String {
        self.upload_domain()
    }

    fn upload_public_url(&self) -> &str {
        self.state.upload_public_url()
    }

    fn upload_slot_limits(&self) -> UploadSlotLimits {
        self.state.upload_slot_limits()
    }

    fn upload_storage_backend(&self) -> &'static str {
        self.state.upload_store().backend()
    }

    async fn reserve_upload_slot(
        &self,
        command: UploadSlotRequestCommand<'_>,
    ) -> Result<UploadSlotAdmission> {
        self.state
            .upload_service()
            .execute_upload_slot_reservation(command)
            .await
    }
}
