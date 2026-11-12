use super::{Action, ProtocolSession, SessionHost};
use anyhow::Result;
use northstar_pubsub_application::profile::{
    ProfileAudienceSnapshot, ProfileRepository, ProfileService,
};
use northstar_pubsub_core::{PepQuotas, PubSubAccount};
use northstar_pubsub_xmpp::vcard::VCardSession;
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

impl<H: SessionHost + PubSubSessionHost> VCardSession for ProtocolSession<H> {
    fn vcard_account(&self) -> Option<PubSubAccount> {
        self.authenticated.as_ref().map(|user| PubSubAccount {
            id: user.id,
            username: user.username.clone(),
            auth_generation: user.auth_generation,
        })
    }

    fn vcard_full_jid(&self) -> Option<&str> {
        self.full_jid.as_deref()
    }

    fn vcard_connection_id(&self) -> uuid::Uuid {
        self.connection_id
    }

    fn vcard_local_domain(&self) -> &str {
        self.host.pubsub_local_domain()
    }

    fn vcard_pep_quotas(&self) -> PepQuotas {
        self.host.pep_account_quotas()
    }

    fn vcard_profile_service(&self) -> &ProfileService<impl ProfileRepository> {
        self.host.profile_service()
    }

    fn vcard_profile_audience_messages(
        &self,
        publisher_full_jid: Option<&str>,
        node: &str,
        event: &str,
        audience: &ProfileAudienceSnapshot,
    ) -> Result<Vec<(String, String)>> {
        northstar_pubsub_xmpp::pep::profile_audience_messages(
            &*self.host,
            publisher_full_jid,
            node,
            event,
            audience,
        )
    }

    fn vcard_refresh_avatar_presence(&self, owner_bare: &str, hash: Option<&str>) {
        self.host.refresh_avatar_presence(owner_bare, hash);
    }
}
