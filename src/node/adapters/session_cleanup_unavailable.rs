//! Root bindings for stream-owned unavailable presence delivery.

use crate::node::FederationRouter;
use crate::node::ServerNode;
use anyhow::Result;
use northstar_cluster::ClusterUnavailableDelivery;
use northstar_config::ExternalRouteDomainPolicy;
use northstar_stream::session_cleanup::unavailable::{
    SessionCleanupUnavailable, SessionCleanupUnavailablePorts,
};
use northstar_workflows::message_repository::PostgresMessageRepository;
use northstar_workflows::sm_teardown_presence_repository::PostgresSmTeardownPresenceRepository;
use std::sync::Arc;

pub(crate) type AppSessionCleanupUnavailable = SessionCleanupUnavailable<
    PostgresSmTeardownPresenceRepository,
    PostgresMessageRepository,
    SessionCleanupUnavailableAdapters,
>;

pub(crate) struct SessionCleanupUnavailableAdapters {
    remote: ClusterUnavailableDelivery,
    federation: FederationRouter,
    domains: ExternalRouteDomainPolicy,
}

impl ServerNode {
    pub(crate) fn session_cleanup_unavailable(&self) -> AppSessionCleanupUnavailable {
        SessionCleanupUnavailable::new(
            self.session.sm_teardown_presence_service().clone(),
            Arc::clone(self.session.live().sessions()),
            self.message.message_service.clone(),
            SessionCleanupUnavailableAdapters {
                remote: self.cluster.unavailable_delivery(),
                federation: self.federation.federation_outbox.clone(),
                domains: self.config.external_route_domain_policy(),
            },
            self.config.domain.clone(),
        )
    }
}

impl SessionCleanupUnavailablePorts for SessionCleanupUnavailableAdapters {
    async fn send_unavailable_to_remote_nodes(
        &self,
        target_jid: &str,
        stanza: &str,
        exclude_jid: &str,
        bare_target: bool,
    ) -> Result<()> {
        self.remote
            .send_unavailable_to_remote_nodes(target_jid, stanza, exclude_jid, bare_target)
            .await
    }

    fn external_route_domain_allowed(&self, domain: &str) -> bool {
        self.domains.external_route_domain_allowed(domain)
    }

    async fn send_federation(&self, domain: &str, stanza: String, origin: Option<String>) -> bool {
        self.federation.send(domain, stanza, origin).await
    }
}
