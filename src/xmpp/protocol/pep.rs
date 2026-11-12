//! Personal Eventing Protocol (PEP) delegation to `northstar-pubsub-xmpp`.

use super::{Action, ProtocolSession, SessionHost};
use anyhow::Result;
use northstar_pubsub_xmpp::PubSubSessionHost;
use roxmltree::Node;

#[cfg(test)]
pub(crate) use northstar_pubsub_xmpp::pep::bookmarks2_items_event;
pub(crate) use northstar_pubsub_xmpp::pep::{pep_access_allowed, prepare_pep_last_item_outbox};

/// The session handlers of pep.rs.
pub(crate) trait PepHandlers {
    async fn pep_get(&self, id: &str, iq: Node<'_, '_>, pubsub: Node<'_, '_>) -> Result<Action>;

    async fn pep_publish(
        &self,
        id: &str,
        iq: Node<'_, '_>,
        pubsub: Node<'_, '_>,
        raw: &str,
    ) -> Result<Action>;

    async fn pep_owner_get(
        &self,
        id: &str,
        iq: Node<'_, '_>,
        pubsub: Node<'_, '_>,
    ) -> Result<Action>;

    async fn pep_owner_set(
        &self,
        id: &str,
        iq: Node<'_, '_>,
        pubsub: Node<'_, '_>,
    ) -> Result<Action>;
}

impl<H: SessionHost + PubSubSessionHost> PepHandlers for ProtocolSession<H> {
    async fn pep_get(&self, id: &str, iq: Node<'_, '_>, pubsub: Node<'_, '_>) -> Result<Action> {
        northstar_pubsub_xmpp::pep::pep_get(self, id, iq, pubsub)
            .await
            .map(Action::Send)
    }

    async fn pep_publish(
        &self,
        id: &str,
        iq: Node<'_, '_>,
        pubsub: Node<'_, '_>,
        raw: &str,
    ) -> Result<Action> {
        northstar_pubsub_xmpp::pep::pep_publish(self, id, iq, pubsub, raw)
            .await
            .map(Action::Send)
    }

    async fn pep_owner_get(
        &self,
        id: &str,
        iq: Node<'_, '_>,
        pubsub: Node<'_, '_>,
    ) -> Result<Action> {
        northstar_pubsub_xmpp::pep::pep_owner_get(self, id, iq, pubsub)
            .await
            .map(Action::Send)
    }

    async fn pep_owner_set(
        &self,
        id: &str,
        iq: Node<'_, '_>,
        pubsub: Node<'_, '_>,
    ) -> Result<Action> {
        northstar_pubsub_xmpp::pep::pep_owner_set(self, id, iq, pubsub)
            .await
            .map(Action::Send)
    }
}
