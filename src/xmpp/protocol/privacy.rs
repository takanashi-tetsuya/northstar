use super::{Action, ProtocolSession, SessionHost};
use anyhow::Result;
use northstar_roster_application::privacy::{PrivacyRepository, PrivacyService};
use northstar_roster_xmpp::RosterSessionHost;
use roxmltree::Node;
use std::sync::atomic::Ordering;

impl<H: SessionHost + RosterSessionHost> ProtocolSession<H> {
    pub(crate) async fn privacy_get(
        &self,
        id: &str,
        root: Node<'_, '_>,
        query: Node<'_, '_>,
    ) -> Result<Action> {
        northstar_roster_xmpp::privacy::privacy_get(self, id, root, query)
            .await
            .map(Action::Send)
    }

    pub(crate) async fn privacy_set(
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

impl<H: SessionHost + RosterSessionHost> northstar_roster_xmpp::privacy::PrivacySession
    for ProtocolSession<H>
{
    fn privacy_full_jid(&self) -> Option<&str> {
        self.full_jid.as_deref()
    }

    fn privacy_connection_id(&self) -> uuid::Uuid {
        self.connection_id
    }

    fn privacy_service(&self) -> &PrivacyService<impl PrivacyRepository> {
        self.host.privacy_service()
    }

    fn privacy_mark_requested(&self) {
        self.privacy_requested.store(true, Ordering::Release);
    }

    fn privacy_active_list(&self) -> Option<String> {
        self.privacy_active
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
    }

    fn privacy_set_active_list(&self, name: Option<String>) {
        *self
            .privacy_active
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = name;
    }

    fn privacy_local_resources(&self, account: &str) -> usize {
        self.host.local_resource_count(account)
    }

    async fn privacy_has_remote_resources(&self, account: &str) -> Result<bool> {
        self.host.account_has_remote_resources(account).await
    }

    fn privacy_list_active_locally(&self, account: &str, name: &str) -> bool {
        self.host.privacy_list_active_locally(account, name)
    }

    async fn privacy_push_change(&self, account: &str, name: &str, base: &str) -> Option<String> {
        self.host
            .push_privacy_change(account, name, base, self.connection_id)
            .await
    }
}
