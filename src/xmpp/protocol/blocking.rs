use super::{Action, ProtocolSession, SessionHost};
use anyhow::Result;
use northstar_roster_application::blocking::{BlockingRepository, BlockingService};
use northstar_roster_xmpp::RosterSessionHost;
use roxmltree::Node;
use std::sync::atomic::Ordering;

impl<H: SessionHost + RosterSessionHost> ProtocolSession<H> {
    pub(crate) async fn blocklist(
        &self,
        id: &str,
        root: Node<'_, '_>,
        _blocklist: Node<'_, '_>,
    ) -> Result<Action> {
        northstar_roster_xmpp::blocking::blocklist(self, id, root)
            .await
            .map(Action::Send)
    }

    pub(crate) async fn block(
        &self,
        id: &str,
        root: Node<'_, '_>,
        _block: Node<'_, '_>,
    ) -> Result<Action> {
        northstar_roster_xmpp::blocking::block(self, id, root)
            .await
            .map(Action::Send)
    }

    pub(crate) async fn unblock(
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

impl<H: SessionHost + RosterSessionHost> northstar_roster_xmpp::blocking::BlockingSession
    for ProtocolSession<H>
{
    fn blocking_service(&self) -> &BlockingService<impl BlockingRepository> {
        self.host.blocking_service()
    }

    fn blocking_mark_requested(&self) {
        self.blocklist_requested.store(true, Ordering::Release);
    }

    async fn blocking_push_change(&self, owner: &str, payload: &str) {
        self.host.push_blocklist_change(owner, payload).await;
    }

    async fn blocking_presence_change(
        &self,
        owner: &str,
        targets: &[String],
        changed_patterns: &[String],
        available: bool,
    ) {
        self.host
            .deliver_blocking_presence_change(owner, targets, changed_patterns, available)
            .await;
    }
}
