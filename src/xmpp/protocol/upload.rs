use super::{Action, ProtocolSession, SessionHost};
use anyhow::Result;
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
