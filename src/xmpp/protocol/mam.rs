use super::{Action, ProtocolSession, SessionHost};
use anyhow::Result;
use northstar_archive_xmpp::ArchiveSessionHost;
use roxmltree::Node;

fn action(reply: northstar_archive_xmpp::MamReply) -> Action {
    match reply {
        northstar_archive_xmpp::MamReply::Send(x) => Action::Send(x),
        northstar_archive_xmpp::MamReply::SendMany(x) => Action::SendMany(x),
    }
}

/// The session handlers of mam.rs.
pub(crate) trait MamHandlers {
    async fn mam_preferences_get(
        &self,
        id: &str,
        to: Option<&str>,
        prefs: Node<'_, '_>,
    ) -> Result<Action>;

    async fn mam_preferences_set(
        &self,
        id: &str,
        to: Option<&str>,
        prefs: Node<'_, '_>,
    ) -> Result<Action>;

    async fn mam_query_form(
        &self,
        id: &str,
        to: Option<&str>,
        query: Node<'_, '_>,
    ) -> Result<Action>;

    async fn mam_metadata(
        &self,
        id: &str,
        to: Option<&str>,
        metadata: Node<'_, '_>,
    ) -> Result<Action>;

    async fn mam(&self, id: &str, query: Node<'_, '_>, to: Option<&str>) -> Result<Action>;
}

impl<H: SessionHost + ArchiveSessionHost> MamHandlers for ProtocolSession<H> {
    async fn mam_preferences_get(
        &self,
        id: &str,
        to: Option<&str>,
        prefs: Node<'_, '_>,
    ) -> Result<Action> {
        northstar_archive_xmpp::mam_preferences_get(self, id, to, prefs)
            .await
            .map(action)
    }

    async fn mam_preferences_set(
        &self,
        id: &str,
        to: Option<&str>,
        prefs: Node<'_, '_>,
    ) -> Result<Action> {
        northstar_archive_xmpp::mam_preferences_set(self, id, to, prefs)
            .await
            .map(action)
    }

    async fn mam_query_form(
        &self,
        id: &str,
        to: Option<&str>,
        query: Node<'_, '_>,
    ) -> Result<Action> {
        northstar_archive_xmpp::mam_query_form(self, id, to, query)
            .await
            .map(action)
    }

    async fn mam_metadata(
        &self,
        id: &str,
        to: Option<&str>,
        metadata: Node<'_, '_>,
    ) -> Result<Action> {
        northstar_archive_xmpp::mam_metadata(self, id, to, metadata)
            .await
            .map(action)
    }

    async fn mam(&self, id: &str, query: Node<'_, '_>, to: Option<&str>) -> Result<Action> {
        northstar_archive_xmpp::mam_query(self, id, query, to)
            .await
            .map(action)
    }
}
