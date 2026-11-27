//! Root bindings for stream-owned unavailable presence delivery.

use crate::node::FederationRouter;
use crate::node::ServerNode;
use anyhow::Result;
use northstar_cluster::{ClusterManager, ClusterUnavailableDelivery};
use northstar_config::ExternalRouteDomainPolicy;
use northstar_roster_application::presence::PresenceService;
use northstar_session_application::sm_teardown_presence::{
    ExactPresenceAcceptance, TerminalRoute, TerminalRouteCandidate,
};
use northstar_stream::session_cleanup::unavailable::{
    SessionCleanupUnavailable, SessionCleanupUnavailablePorts,
};
use northstar_workflows::presence_repository::PostgresPresenceRepository;
use northstar_workflows::sm_teardown_presence_repository::PostgresSmTeardownPresenceRepository;
use std::sync::Arc;

pub(crate) type AppSessionCleanupUnavailable = SessionCleanupUnavailable<
    PostgresSmTeardownPresenceRepository,
    SessionCleanupUnavailableAdapters,
>;

pub(crate) struct SessionCleanupUnavailableAdapters {
    remote: ClusterUnavailableDelivery,
    cluster: ClusterManager,
    presence: PresenceService<PostgresPresenceRepository>,
    federation: FederationRouter,
    domains: ExternalRouteDomainPolicy,
}

impl ServerNode {
    pub(crate) fn session_cleanup_unavailable(&self) -> AppSessionCleanupUnavailable {
        SessionCleanupUnavailable::new(
            self.session.sm_teardown_presence_service().clone(),
            Arc::clone(self.session.live().sessions()),
            SessionCleanupUnavailableAdapters {
                remote: self.cluster.unavailable_delivery(),
                cluster: self.cluster.clone(),
                presence: self.roster.presence_service.clone(),
                federation: self.federation.federation_outbox.clone(),
                domains: self.config.external_route_domain_policy(),
            },
            self.config.domain.clone(),
        )
    }
}

impl SessionCleanupUnavailablePorts for SessionCleanupUnavailableAdapters {
    async fn capture_remote_routes(&self, bare: &str) -> Result<Vec<TerminalRouteCandidate>> {
        let jid = northstar_xmpp_types::jid::CanonicalJid::parse(bare)?;
        let Some(username) = jid.localpart() else {
            return Ok(Vec::new());
        };
        let Some(account) = self.presence.find_enabled_user(username).await? else {
            return Ok(Vec::new());
        };
        Ok(self
            .cluster
            .capture_remote_message_routes(bare, account.id, account.auth_generation)
            .await?
            .into_iter()
            .map(|route| TerminalRouteCandidate {
                route: TerminalRoute {
                    full_jid: route.full_jid,
                    account_id: route.account_id,
                    auth_generation: route.auth_generation,
                    connection_id: route.connection_id,
                    node_id: route.node_id,
                },
                available: route.available == Some(true),
                expects_active: false,
            })
            .collect())
    }

    async fn send_terminal_unavailable(
        &self,
        source: &TerminalRoute,
        target: &TerminalRoute,
        stanza: &str,
    ) -> Result<ExactPresenceAcceptance> {
        self.remote
            .send_terminal_unavailable(source, target, stanza)
            .await
    }

    fn external_route_domain_allowed(&self, domain: &str) -> bool {
        self.domains.external_route_domain_allowed(domain)
    }

    async fn send_federation(&self, domain: &str, stanza: String, origin: Option<String>) -> bool {
        self.federation.send(domain, stanza, origin).await
    }
}
