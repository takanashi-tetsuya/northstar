//! The protocol session as this context sees it: the impls of this crate's session ports for
//! `northstar_stream::protocol::ProtocolSession`.

use crate::UploadSessionHost;
use anyhow::Result;
use northstar_stream::protocol::{ProtocolSession, SessionHost};
use northstar_upload_application::{
    UploadSlotAdmission, UploadSlotLimits, UploadSlotRequestCommand,
};

// From src/xmpp/protocol/upload.rs.
impl<H: SessionHost + UploadSessionHost> crate::UploadSlotSession for ProtocolSession<H> {
    fn upload_user_id(&self) -> Option<uuid::Uuid> {
        self.authenticated.as_ref().map(|user| user.id)
    }

    fn upload_service_domain(&self) -> String {
        self.host().upload_domain()
    }

    fn upload_public_url(&self) -> &str {
        self.host().upload_public_url()
    }

    fn upload_slot_limits(&self) -> UploadSlotLimits {
        self.host().upload_slot_limits()
    }

    fn upload_storage_backend(&self) -> &'static str {
        self.host().upload_storage_backend()
    }

    async fn reserve_upload_slot(
        &self,
        command: UploadSlotRequestCommand<'_>,
    ) -> Result<UploadSlotAdmission> {
        self.host().reserve_upload_slot(command).await
    }
}
