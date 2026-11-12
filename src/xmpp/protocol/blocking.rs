use super::{Action, ProtocolSession, SessionHost};
use anyhow::Result;
use northstar_roster_xmpp::RosterSessionHost;
use roxmltree::Node;

/// The session handlers of blocking.rs.
pub(crate) trait BlockingHandlers {
    async fn blocklist(
        &self,
        id: &str,
        root: Node<'_, '_>,
        _blocklist: Node<'_, '_>,
    ) -> Result<Action>;

    async fn block(&self, id: &str, root: Node<'_, '_>, _block: Node<'_, '_>) -> Result<Action>;

    async fn unblock(&self, id: &str, root: Node<'_, '_>, _unblock: Node<'_, '_>)
        -> Result<Action>;
}

impl<H: SessionHost + RosterSessionHost> BlockingHandlers for ProtocolSession<H> {
    async fn blocklist(
        &self,
        id: &str,
        root: Node<'_, '_>,
        _blocklist: Node<'_, '_>,
    ) -> Result<Action> {
        northstar_roster_xmpp::blocking::blocklist(self, id, root)
            .await
            .map(Action::Send)
    }

    async fn block(&self, id: &str, root: Node<'_, '_>, _block: Node<'_, '_>) -> Result<Action> {
        northstar_roster_xmpp::blocking::block(self, id, root)
            .await
            .map(Action::Send)
    }

    async fn unblock(
        &self,
        id: &str,
        root: Node<'_, '_>,
        _unblock: Node<'_, '_>,
    ) -> Result<Action> {
        northstar_roster_xmpp::blocking::unblock(self, id, root)
            .await
            .map(Action::Send)
    }
}
