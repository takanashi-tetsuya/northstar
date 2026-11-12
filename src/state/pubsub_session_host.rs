//! The node's side of the PubSub context's session handlers.

use super::AppState;
use northstar_pubsub_application::private_storage::{
    PrivateStorageRepository, PrivateStorageService,
};
use northstar_pubsub_application::profile::{ProfileRepository, ProfileService};
use northstar_pubsub_application::PubSubService;
use northstar_pubsub_core::PepQuotas;
use northstar_pubsub_xmpp::PubSubSessionHost;
use northstar_roster_xmpp::presence::inject_vcard_avatar_hash;

impl PubSubSessionHost for AppState {
    fn pep_account_quotas(&self) -> PepQuotas {
        AppState::pep_account_quotas(self)
    }

    fn profile_service(&self) -> &ProfileService<impl ProfileRepository> {
        AppState::profile_service(self)
    }

    fn private_storage_service(&self) -> &PrivateStorageService<impl PrivateStorageRepository> {
        AppState::private_storage_service(self)
    }

    fn pep_record_published(&self, count: u64) {
        self.pep_telemetry().published(count);
    }

    fn pep_record_retracted(&self, count: u64) {
        self.pep_telemetry().retracted(count);
    }

    fn pep_record_retrieved(&self) {
        self.pep_telemetry().retrieved();
    }

    fn refresh_avatar_presence(&self, owner_bare: &str, hash: Option<&str>) {
        for session in self.sessions_for(owner_bare) {
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

impl northstar_pubsub_xmpp::pubsub::PubSubHost for AppState {
    fn pubsub_local_domain(&self) -> &str {
        AppState::local_domain(self)
    }

    fn pubsub_server_name(&self) -> &str {
        AppState::server_name(self)
    }

    fn pubsub_node_owner_limits(&self) -> northstar_pubsub_xmpp::pubsub::PubSubOwnerLimits {
        let limits = AppState::pubsub_owner_limits(self);
        northstar_pubsub_xmpp::pubsub::PubSubOwnerLimits {
            max_nodes: limits.max_nodes,
            max_storage_bytes: limits.max_storage_bytes,
        }
    }

    fn pubsub_application_service(
        &self,
    ) -> &PubSubService<impl northstar_pubsub_xmpp::PubSubRepositories> {
        AppState::pubsub_service(self)
    }
}

impl northstar_pubsub_xmpp::pep::PepAudienceRouting for AppState {
    fn pep_routing_local_domain(&self) -> &str {
        self.local_domain()
    }

    fn pep_available_resources_wanting(&self, bare_jid: &str, node: &str) -> Vec<String> {
        self.session_entries_for(bare_jid)
            .into_iter()
            .filter(|(full_jid, target)| {
                target.available.load(std::sync::atomic::Ordering::Relaxed)
                    && crate::xmpp::protocol::caps::wants_pep_node(self, full_jid, node)
            })
            .map(|(full_jid, _)| full_jid)
            .collect()
    }

    fn pep_interested_resources(&self, bare_jid: &str, node: &str) -> Vec<String> {
        crate::xmpp::protocol::caps::interested_resources_for_bare(self, bare_jid, node)
    }
}
