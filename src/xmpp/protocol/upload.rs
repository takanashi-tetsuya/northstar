use super::{Action, ProtocolSession, SessionHost};
use anyhow::Result;
use northstar_upload_application::{
    UploadSlotAdmission, UploadSlotLimits, UploadSlotRequestCommand,
};
use northstar_upload_xmpp::UploadSessionHost;
use roxmltree::Node;

/// The session handlers of upload.rs.
pub(crate) trait UploadHandlers {
    async fn http_upload_slot(
        &self,
        id: &str,
        to: Option<&str>,
        request: Node<'_, '_>,
    ) -> Result<Action>;
}

impl<H: SessionHost + UploadSessionHost> UploadHandlers for ProtocolSession<H> {
    async fn http_upload_slot(
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

impl<H: SessionHost + UploadSessionHost> northstar_upload_xmpp::UploadSlotSession
    for ProtocolSession<H>
{
    fn upload_user_id(&self) -> Option<uuid::Uuid> {
        self.authenticated.as_ref().map(|user| user.id)
    }

    fn upload_service_domain(&self) -> String {
        self.host.upload_domain()
    }

    fn upload_public_url(&self) -> &str {
        self.host.upload_public_url()
    }

    fn upload_slot_limits(&self) -> UploadSlotLimits {
        self.host.upload_slot_limits()
    }

    fn upload_storage_backend(&self) -> &'static str {
        self.host.upload_storage_backend()
    }

    async fn reserve_upload_slot(
        &self,
        command: UploadSlotRequestCommand<'_>,
    ) -> Result<UploadSlotAdmission> {
        self.host.reserve_upload_slot(command).await
    }
}
