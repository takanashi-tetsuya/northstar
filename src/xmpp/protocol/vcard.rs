use super::{Action, ProtocolSession};
use crate::services::xml_util::inject_vcard_avatar_hash;
use anyhow::Result;
use northstar_pubsub_application::profile::{
    ProfileAudienceSnapshot, ProfileRepository, ProfileService,
};
use northstar_pubsub_core::{PepQuotas, PubSubAccount};
use northstar_pubsub_xmpp::vcard::VCardSession;
use roxmltree::Node;

impl ProtocolSession {
    pub(crate) async fn vcard_get(&self, id: &str, iq: Node<'_, '_>) -> Result<Action> {
        northstar_pubsub_xmpp::vcard::vcard_get(self, id, iq)
            .await
            .map(Action::Send)
    }

    pub(crate) async fn vcard_set(
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

    pub(crate) fn refresh_local_avatar_presence(&self, owner_bare: &str, hash: Option<&str>) {
        for session in self.state.sessions_for(owner_bare) {
            let mut last_presence = session
                .last_presence
                .write()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            let refreshed = last_presence.as_deref().and_then(|raw| {
                let document = roxmltree::Document::parse(raw).ok()?;
                Some(inject_vcard_avatar_hash(raw, document.root_element(), hash))
            });
            if let Some(refreshed) = refreshed {
                *last_presence = Some(refreshed);
            }
        }
    }
}

impl VCardSession for ProtocolSession {
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
        self.state.local_domain()
    }

    fn vcard_pep_quotas(&self) -> PepQuotas {
        self.state.pep_account_quotas()
    }

    fn vcard_profile_service(&self) -> &ProfileService<impl ProfileRepository> {
        self.state.profile_service()
    }

    fn vcard_profile_audience_messages(
        &self,
        publisher_full_jid: Option<&str>,
        node: &str,
        event: &str,
        audience: &ProfileAudienceSnapshot,
    ) -> Result<Vec<(String, String)>> {
        ProtocolSession::prepare_profile_audience_messages(
            self.state.as_ref(),
            publisher_full_jid,
            node,
            event,
            audience,
        )
    }

    fn vcard_refresh_avatar_presence(&self, owner_bare: &str, hash: Option<&str>) {
        self.refresh_local_avatar_presence(owner_bare, hash);
    }
}
