use super::{Action, ProtocolSession, SessionHost};
use anyhow::Result;
use northstar_pubsub_xmpp::PubSubSessionHost;
use roxmltree::Node;

/// The session handlers of private.rs.
pub(crate) trait PrivateXmlHandlers {
    async fn private_get(
        &mut self,
        id: &str,
        to: Option<&str>,
        query: Node<'_, '_>,
    ) -> Result<Action>;

    async fn private_set(
        &mut self,
        id: &str,
        to: Option<&str>,
        query: Node<'_, '_>,
        raw: &str,
    ) -> Result<Action>;
}

impl<H: SessionHost + PubSubSessionHost> PrivateXmlHandlers for ProtocolSession<H> {
    async fn private_get(
        &mut self,
        id: &str,
        to: Option<&str>,
        query: Node<'_, '_>,
    ) -> Result<Action> {
        northstar_pubsub_xmpp::private_xml::private_get(&*self, id, to, query)
            .await
            .map(Action::Send)
    }

    async fn private_set(
        &mut self,
        id: &str,
        to: Option<&str>,
        query: Node<'_, '_>,
        raw: &str,
    ) -> Result<Action> {
        northstar_pubsub_xmpp::private_xml::private_set(&*self, id, to, query, raw)
            .await
            .map(Action::Send)
    }
}
