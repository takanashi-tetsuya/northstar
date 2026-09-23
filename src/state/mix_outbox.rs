//! Durable MIX delivery lanes and their live routing observations.

use super::{
    local_caps_route_epoch_matches, session_entries_for_in, AppState, OnlineSession,
    RuntimeFederationPolicy,
};
use crate::{
    cluster::{ClusterMixRouteLookup, ClusterNodeDelivery, NodeDeliveryReceipt},
    config::ExternalRouteDomainPolicy,
    db::mix_repository::PostgresMixRepository,
    outbound::MixDelivery,
    s2s::FederationRouter,
    services::mix::MixService,
    xmpp::{
        capabilities::MixPostCommitTelemetry,
        protocol::mix::{MixSessionCapability, CORE_NS, PAM_NS},
    },
};
use anyhow::Result;
use dashmap::DashMap;
use northstar_protocol_runtime::caps::{CapsObservationOwner, CapsResourceIndex, PendingCapsIndex};
use std::sync::{
    atomic::{AtomicU64, Ordering},
    Arc,
};
use uuid::Uuid;

pub(crate) struct MixOutboxContext {
    service: MixService<PostgresMixRepository>,
    sessions: Arc<DashMap<String, OnlineSession>>,
    caps_by_jid: Arc<CapsResourceIndex>,
    pending_caps: Arc<PendingCapsIndex>,
    cluster_routes: ClusterMixRouteLookup,
    cluster_delivery: ClusterNodeDelivery,
    federation: FederationRouter,
    local_domain: String,
    static_policy: ExternalRouteDomainPolicy,
    runtime_policy: Arc<arc_swap::ArcSwap<RuntimeFederationPolicy>>,
    delivery_failures: Arc<AtomicU64>,
    post_accept_failures: Arc<AtomicU64>,
}

fn remote_nodes_in_order(nodes: Vec<String>, local_node: &str) -> Vec<String> {
    nodes
        .into_iter()
        .filter(|node| node != local_node)
        .collect()
}

impl AppState {
    pub(crate) fn mix_outbox_context(&self) -> MixOutboxContext {
        MixOutboxContext {
            service: self.mix_service.clone(),
            sessions: Arc::clone(&self.sessions),
            caps_by_jid: Arc::clone(&self.caps_by_jid),
            pending_caps: Arc::clone(&self.pending_caps),
            cluster_routes: self.cluster.mix_route_lookup(),
            cluster_delivery: self.cluster.node_delivery(),
            federation: self.federation_outbox.clone(),
            local_domain: self.config.domain.clone(),
            static_policy: self.config.external_route_domain_policy(),
            runtime_policy: Arc::clone(&self.federation_runtime_policy),
            delivery_failures: Arc::clone(&self.metrics.mix_post_commit_delivery_failures_total),
            post_accept_failures: Arc::clone(&self.metrics.post_accept_side_effect_failures_total),
        }
    }
}

impl MixOutboxContext {
    pub(crate) fn service(&self) -> &MixService<PostgresMixRepository> {
        &self.service
    }

    pub(crate) fn local_domain(&self) -> &str {
        &self.local_domain
    }

    pub(crate) fn federation_domain_allowed(&self, domain: &str) -> bool {
        let Ok(domain) = crate::jid::prepare_domainpart(domain) else {
            return false;
        };
        self.static_policy.federation_domain_allowed(&domain)
            && self.runtime_policy.load().allows_domain(&domain)
    }

    pub(crate) fn federation_outbox(&self) -> &FederationRouter {
        &self.federation
    }

    pub(crate) fn session_entries_for(&self, jid: &str) -> Vec<(String, OnlineSession)> {
        session_entries_for_in(&self.sessions, jid)
    }

    /// The same verified observation and stale-local-epoch eviction used by
    /// ordinary CAPS routing. An unknown observation keeps durable delivery
    /// parked until verification or the recipient's next route wake.
    pub(crate) fn session_mix_capability(&self, full_jid: &str) -> MixSessionCapability {
        let Ok(full_jid) = crate::jid::canonical_session_key(full_jid) else {
            return MixSessionCapability::Unknown;
        };
        let Some(observation) = self.caps_by_jid.snapshot(&full_jid) else {
            return MixSessionCapability::Unknown;
        };
        if let CapsObservationOwner::Local(epoch) = observation.owner {
            let current = self.sessions.get(&full_jid).is_some_and(|session| {
                local_caps_route_epoch_matches(
                    session.connection_id,
                    session.caps_observation_generation.load(Ordering::Acquire),
                    session.routable.load(Ordering::Acquire),
                    session.disconnect.is_cancelled(),
                    session.lifecycle.load(Ordering::Acquire),
                    true,
                    epoch,
                )
            });
            if !current {
                self.pending_caps.remove_local_epoch(&full_jid, epoch);
                self.caps_by_jid.remove_local_epoch(&full_jid, epoch);
                return MixSessionCapability::Unknown;
            }
        }
        match observation.summary {
            Some(summary) if summary.has_feature(CORE_NS) || summary.has_feature(PAM_NS) => {
                MixSessionCapability::Supported
            }
            Some(_) => MixSessionCapability::Unsupported,
            None => MixSessionCapability::Unknown,
        }
    }

    pub(crate) async fn lookup_nodes(&self, jid: &str) -> Result<Vec<String>> {
        let nodes = self.cluster_routes.lookup_nodes(jid).await?;
        Ok(remote_nodes_in_order(nodes, self.cluster_routes.node_id()))
    }

    pub(crate) async fn outbox_lookup_cluster_nodes(&self, jid: &str) -> Result<Vec<String>> {
        let nodes = self
            .service
            .outbox_lookup_cluster_nodes(&self.cluster_routes, jid)
            .await?;
        Ok(remote_nodes_in_order(nodes, self.cluster_routes.node_id()))
    }

    pub(crate) async fn send_cluster_mix(
        &self,
        node_id: &str,
        recipient: &str,
        stanza: &str,
        source: Option<MixDelivery>,
    ) -> Result<NodeDeliveryReceipt> {
        self.cluster_delivery
            .send_mix(node_id, recipient, stanza, source)
            .await
    }

    pub(crate) async fn send_cluster_pam_result(
        &self,
        node_id: &str,
        target_full_jid: &str,
        stanza: &str,
        expected_user_id: Uuid,
    ) -> Result<bool> {
        self.cluster_delivery
            .send_mix_exact_account(node_id, target_full_jid, stanza, expected_user_id)
            .await
    }

    pub(crate) fn record_post_commit_failure(&self) {
        MixPostCommitTelemetry::new(&self.delivery_failures, &self.post_accept_failures)
            .delivery_failed();
    }
}

#[cfg(test)]
mod tests {
    use super::remote_nodes_in_order;

    #[test]
    fn remote_mix_nodes_keep_authority_order_and_duplicate_routes() {
        assert_eq!(
            remote_nodes_in_order(
                vec!["second", "local", "first", "second"]
                    .into_iter()
                    .map(str::to_owned)
                    .collect(),
                "local",
            ),
            vec!["second", "first", "second"]
        );
    }
}
