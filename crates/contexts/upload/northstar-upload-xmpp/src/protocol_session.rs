//! The protocol session as this context sees it: the impls of this crate's session ports for
//! `northstar_stream::protocol::ProtocolSession`, and the handlers the root's client IQ route table calls on
//! it.

use crate::UploadSessionHost;
use anyhow::Result;
use northstar_stream::protocol::{ProtocolSession, SessionHost};
use northstar_stream::transport::Action;
use northstar_upload_application::{
    UploadSlotAdmission, UploadSlotLimits, UploadSlotRequestCommand,
};
use roxmltree::Node;

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

/// The HTTP upload handlers the root calls on the session.
#[allow(async_fn_in_trait)] // Called on the root's concrete session type only.
pub trait UploadHandlers {
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
        crate::http_upload_slot(self, id, to, request)
            .await
            .map(Action::Send)
    }
}
