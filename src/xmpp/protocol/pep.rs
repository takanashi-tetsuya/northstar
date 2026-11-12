//! Personal Eventing Protocol (PEP) delegation to `northstar-pubsub-xmpp`.

use super::{Action, ProtocolSession, SessionHost};
use anyhow::Result;
use northstar_pubsub_application::profile::{ProfileRepository, ProfileService};
use northstar_pubsub_application::PubSubService;
use northstar_pubsub_core::{PepQuotas, PubSubAccount};
use northstar_pubsub_xmpp::PubSubSessionHost;
use roxmltree::Node;

#[cfg(test)]
pub(crate) use northstar_pubsub_xmpp::pep::bookmarks2_items_event;
pub(crate) use northstar_pubsub_xmpp::pep::{pep_access_allowed, prepare_pep_last_item_outbox};

impl<H: SessionHost + PubSubSessionHost> ProtocolSession<H> {
    pub(crate) async fn pep_get(
        &self,
        id: &str,
        iq: Node<'_, '_>,
        pubsub: Node<'_, '_>,
    ) -> Result<Action> {
        northstar_pubsub_xmpp::pep::pep_get(self, id, iq, pubsub)
            .await
            .map(Action::Send)
    }

    pub(crate) async fn pep_publish(
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

    pub(crate) async fn pep_owner_get(
        &self,
        id: &str,
        iq: Node<'_, '_>,
        pubsub: Node<'_, '_>,
    ) -> Result<Action> {
        northstar_pubsub_xmpp::pep::pep_owner_get(self, id, iq, pubsub)
            .await
            .map(Action::Send)
    }

    pub(crate) async fn pep_owner_set(
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

impl<H: SessionHost + PubSubSessionHost> northstar_pubsub_xmpp::pep::PepSession
    for ProtocolSession<H>
{
    fn pep_account(&self) -> Option<PubSubAccount> {
        self.authenticated.as_ref().map(|user| PubSubAccount {
            id: user.id,
            username: user.username.clone(),
            auth_generation: user.auth_generation,
        })
    }

    fn pep_full_jid(&self) -> Option<&str> {
        self.full_jid.as_deref()
    }

    fn pep_connection_id(&self) -> uuid::Uuid {
        self.connection_id
    }

    fn pep_local_domain(&self) -> &str {
        self.host.pubsub_local_domain()
    }

    fn pep_quotas(&self) -> PepQuotas {
        self.host.pep_account_quotas()
    }

    fn pep_pubsub_service(&self) -> &PubSubService<impl northstar_pubsub_xmpp::PubSubRepositories> {
        self.host.pubsub_application_service()
    }

    fn pep_profile_service(&self) -> &ProfileService<impl ProfileRepository> {
        self.host.profile_service()
    }

    fn pep_audience_routing(&self) -> &impl northstar_pubsub_xmpp::pep::PepAudienceRouting {
        &*self.host
    }

    fn pep_record_published(&self, count: u64) {
        self.host.pep_record_published(count);
    }

    fn pep_record_retracted(&self, count: u64) {
        self.host.pep_record_retracted(count);
    }

    fn pep_record_retrieved(&self) {
        self.host.pep_record_retrieved();
    }

    fn pep_refresh_avatar_presence(&self, owner_bare: &str, hash: Option<&str>) {
        self.host.refresh_avatar_presence(owner_bare, hash);
    }
}
