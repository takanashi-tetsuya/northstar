//! The node's side of the PubSub context's session handlers.

use crate::node::ServerNode;
use northstar_pubsub_application::private_storage::{
    PrivateStorageRepository, PrivateStorageService,
};
use northstar_pubsub_application::profile::{ProfileRepository, ProfileService};
use northstar_pubsub_application::PubSubService;
use northstar_pubsub_core::telemetry::PepTelemetry;
use northstar_pubsub_core::PepQuotas;
use northstar_pubsub_xmpp::PubSubSessionHost;

impl PubSubSessionHost for ServerNode {
    fn pep_account_quotas(&self) -> PepQuotas {
        northstar_pubsub_core::PepQuotas {
            max_nodes: self.config.pep_max_nodes_per_account,
            max_storage_bytes: self.config.pep_max_storage_bytes_per_account,
        }
    }

    fn profile_service(&self) -> &ProfileService<impl ProfileRepository> {
        self.pubsub.profile_service()
    }

    fn private_storage_service(&self) -> &PrivateStorageService<impl PrivateStorageRepository> {
        self.pubsub.private_storage_service()
    }

    fn pep_record_published(&self, count: u64) {
        PepTelemetry::new(
            &self.metrics.pep_items_published_total,
            &self.metrics.pep_items_retracted_total,
            &self.metrics.pep_retrievals_total,
        )
        .published(count);
    }

    fn pep_record_retracted(&self, count: u64) {
        PepTelemetry::new(
            &self.metrics.pep_items_published_total,
            &self.metrics.pep_items_retracted_total,
            &self.metrics.pep_retrievals_total,
        )
        .retracted(count);
    }

    fn pep_record_retrieved(&self) {
        PepTelemetry::new(
            &self.metrics.pep_items_published_total,
            &self.metrics.pep_items_retracted_total,
            &self.metrics.pep_retrievals_total,
        )
        .retrieved();
    }

    fn refresh_avatar_presence(&self, owner_bare: &str, hash: Option<&str>) {
        northstar_roster_xmpp::presence::refresh_avatar_presence(
            self.sessions.sessions_for(owner_bare),
            hash,
        );
    }
}

impl northstar_pubsub_xmpp::pubsub::PubSubHost for ServerNode {
    fn pubsub_local_domain(&self) -> &str {
        &self.config.domain
    }

    fn pubsub_server_name(&self) -> &str {
        &self.config.server_name
    }

    fn pubsub_node_owner_limits(&self) -> northstar_pubsub_xmpp::pubsub::PubSubOwnerLimits {
        northstar_pubsub_xmpp::pubsub::PubSubOwnerLimits {
            max_nodes: self.config.pubsub_max_nodes_per_owner,
            max_storage_bytes: self.config.pubsub_max_storage_bytes_per_owner,
        }
    }

    fn pubsub_application_service(
        &self,
    ) -> &PubSubService<impl northstar_pubsub_xmpp::PubSubRepositories> {
        self.pubsub.pubsub_service()
    }
}

impl northstar_pubsub_xmpp::pep::PepAudienceRouting for ServerNode {
    fn pep_routing_local_domain(&self) -> &str {
        self.config.domain.as_str()
    }

    fn pep_available_resources_wanting(&self, bare_jid: &str, node: &str) -> Vec<String> {
        northstar_stream::protocol::caps::available_resources_wanting_pep_node(
            self,
            self.sessions.session_entries_for(bare_jid),
            node,
        )
    }

    fn pep_interested_resources(&self, bare_jid: &str, node: &str) -> Vec<String> {
        northstar_stream::protocol::caps::interested_resources_for_bare(self, bare_jid, node)
    }
}
