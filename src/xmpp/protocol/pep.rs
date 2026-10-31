//! Personal Eventing Protocol (PEP) delegation to `northstar-pubsub-xmpp`.

use super::{Action, ProtocolSession};
use anyhow::Result;
use northstar_pubsub_application::profile::{ProfileRepository, ProfileService};
use northstar_pubsub_application::PubSubService;
use northstar_pubsub_core::{PepQuotas, PubSubAccount};
use roxmltree::Node;

pub(crate) use northstar_pubsub_xmpp::payload::{valid_avatar_data, valid_avatar_metadata};
#[cfg(test)]
pub(crate) use northstar_pubsub_xmpp::pep::bookmarks2_items_event;
pub(crate) use northstar_pubsub_xmpp::pep::{
    deliver_explicit_pep_last_items_for_resource, deliver_pep_last_items_for_federated_resource,
    deliver_pep_last_items_for_resource, pep_access_allowed, prepare_pep_last_item_outbox,
};

pub(crate) async fn federated_pep_disco_info(
    state: &crate::state::AppState,
    owner: &PubSubAccount,
    requester: &str,
    requested_node: Option<&str>,
) -> Result<Option<String>> {
    northstar_pubsub_xmpp::pep::federated_pep_disco_info(state, owner, requester, requested_node)
        .await
}

pub(crate) async fn federated_pep_disco_items(
    state: &crate::state::AppState,
    owner: &PubSubAccount,
    requester: &str,
    requested_node: Option<&str>,
) -> Result<Option<String>> {
    northstar_pubsub_xmpp::pep::federated_pep_disco_items(state, owner, requester, requested_node)
        .await
}

impl ProtocolSession {
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

impl northstar_pubsub_xmpp::pep::PepSession for ProtocolSession {
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
        self.state.local_domain()
    }

    fn pep_quotas(&self) -> PepQuotas {
        self.state.pep_account_quotas()
    }

    fn pep_pubsub_service(&self) -> &PubSubService<impl northstar_pubsub_xmpp::PubSubRepositories> {
        self.state.pubsub_service()
    }

    fn pep_profile_service(&self) -> &ProfileService<impl ProfileRepository> {
        self.state.profile_service()
    }

    fn pep_audience_routing(&self) -> &impl northstar_pubsub_xmpp::pep::PepAudienceRouting {
        self.state.as_ref()
    }

    fn pep_record_published(&self, count: u64) {
        self.state.pep_telemetry().published(count);
    }

    fn pep_record_retracted(&self, count: u64) {
        self.state.pep_telemetry().retracted(count);
    }

    fn pep_record_retrieved(&self) {
        self.state.pep_telemetry().retrieved();
    }

    fn pep_refresh_avatar_presence(&self, owner_bare: &str, hash: Option<&str>) {
        self.refresh_local_avatar_presence(owner_bare, hash);
    }
}

impl northstar_pubsub_xmpp::pep::PepAudienceRouting for crate::state::AppState {
    fn pep_routing_local_domain(&self) -> &str {
        self.local_domain()
    }

    fn pep_available_resources_wanting(&self, bare_jid: &str, node: &str) -> Vec<String> {
        self.session_entries_for(bare_jid)
            .into_iter()
            .filter(|(full_jid, target)| {
                target.available.load(std::sync::atomic::Ordering::Relaxed)
                    && super::caps::wants_pep_node(self, full_jid, node)
            })
            .map(|(full_jid, _)| full_jid)
            .collect()
    }

    fn pep_interested_resources(&self, bare_jid: &str, node: &str) -> Vec<String> {
        super::caps::interested_resources_for_bare(self, bare_jid, node)
    }
}
