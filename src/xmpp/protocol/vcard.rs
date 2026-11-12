use super::{Action, ProtocolSession, SessionHost};
use anyhow::Result;
use northstar_pubsub_xmpp::PubSubSessionHost;
use roxmltree::Node;

/// The session handlers of vcard.rs.
pub(crate) trait VCardHandlers {
    async fn vcard_get(&self, id: &str, iq: Node<'_, '_>) -> Result<Action>;

    async fn vcard_set(
        &self,
        id: &str,
        iq: Node<'_, '_>,
        vcard: Node<'_, '_>,
        raw: &str,
    ) -> Result<Action>;
}

impl<H: SessionHost + PubSubSessionHost> VCardHandlers for ProtocolSession<H> {
    async fn vcard_get(&self, id: &str, iq: Node<'_, '_>) -> Result<Action> {
        northstar_pubsub_xmpp::vcard::vcard_get(self, id, iq)
            .await
            .map(Action::Send)
    }

    async fn vcard_set(
        &self,
        id: &str,
        iq: Node<'_, '_>,
        vcard: Node<'_, '_>,
        raw: &str,
    ) -> Result<Action> {
        northstar_pubsub_xmpp::vcard::vcard_set(self, id, iq, vcard, raw)
            .await
            .map(Action::Send)
    }
}
