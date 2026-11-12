use super::{Action, ProtocolSession, SessionHost};
use anyhow::Result;
use northstar_roster_xmpp::RosterSessionHost;
use roxmltree::Node;

/// The session handlers of privacy.rs.
pub(crate) trait PrivacyHandlers {
    async fn privacy_get(
        &self,
        id: &str,
        root: Node<'_, '_>,
        query: Node<'_, '_>,
    ) -> Result<Action>;

    async fn privacy_set(
        &self,
        id: &str,
        root: Node<'_, '_>,
        query: Node<'_, '_>,
    ) -> Result<Action>;
}

impl<H: SessionHost + RosterSessionHost> PrivacyHandlers for ProtocolSession<H> {
    async fn privacy_get(
        &self,
        id: &str,
        root: Node<'_, '_>,
        query: Node<'_, '_>,
    ) -> Result<Action> {
        northstar_roster_xmpp::privacy::privacy_get(self, id, root, query)
            .await
            .map(Action::Send)
    }

    async fn privacy_set(
        &self,
        id: &str,
        root: Node<'_, '_>,
        query: Node<'_, '_>,
    ) -> Result<Action> {
        let (response, current_push) =
            northstar_roster_xmpp::privacy::privacy_set(self, id, root, query).await?;
        Ok(match current_push {
            Some(push) => Action::SendMany(vec![response, push]),
            None => Action::Send(response),
        })
    }
}
