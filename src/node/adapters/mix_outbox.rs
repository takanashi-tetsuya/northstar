//! Durable MIX delivery lanes and their live routing observations.

use crate::node::{session_entries_for_in, FederationRouter, OnlineSession, ServerNode};
use anyhow::Result;
use dashmap::DashMap;
use northstar_cluster::{ClusterMixRouteLookup, ClusterNodeDelivery};
use northstar_delivery_core::node_delivery::NodeDeliveryReceipt;
use northstar_federation_application::effective_policy::EffectiveFederationPolicy;
use northstar_mix_xmpp::ports::{remote_nodes_in_order, MixOutboxPort};
use northstar_protocol_runtime::caps::{CapsResourceIndex, PendingCapsIndex};
use northstar_room_application::mix_service::MixService;
use northstar_room_core::mix::MixSessionCapability;
use northstar_room_core::telemetry::MixPostCommitTelemetry;
use northstar_stream::local_routes::session_table::session_mix_capability_in;
use northstar_stream::outbound::MixDelivery;
use northstar_workflows::room_effects::PostgresMixRepository;
use std::sync::{atomic::AtomicU64, Arc};
use uuid::Uuid;

mod room_policy;

pub struct MixOutboxContext {
    service: MixService<PostgresMixRepository>,
    sessions: Arc<DashMap<String, OnlineSession>>,
    caps_by_jid: Arc<CapsResourceIndex>,
    pending_caps: Arc<PendingCapsIndex>,
    cluster_routes: ClusterMixRouteLookup,
    cluster_delivery: ClusterNodeDelivery,
    federation: FederationRouter,
    local_domain: String,
    policy: EffectiveFederationPolicy,
    delivery_failures: Arc<AtomicU64>,
    post_accept_failures: Arc<AtomicU64>,
    room_policy: northstar_workflows::muc_delivery_repository::PostgresRoomDeliveryPolicy,
}

impl ServerNode {
    pub(crate) fn mix_outbox_context(&self) -> MixOutboxContext {
        MixOutboxContext {
            service: self.room.mix_service.clone(),
            sessions: Arc::clone(self.session.live().sessions()),
            caps_by_jid: Arc::clone(self.session.live().caps_by_jid()),
            pending_caps: Arc::clone(self.session.live().pending_caps()),
            cluster_routes: self.cluster.mix_route_lookup(),
            cluster_delivery: self.cluster.node_delivery(),
            federation: self.federation.federation_outbox.clone(),
            local_domain: self.config.domain.clone(),
            policy: self.federation.effective_policy.clone(),
            delivery_failures: Arc::clone(&self.metrics.mix_post_commit_delivery_failures_total),
            post_accept_failures: Arc::clone(&self.metrics.post_accept_side_effect_failures_total),
            room_policy:
                northstar_workflows::muc_delivery_repository::PostgresRoomDeliveryPolicy::new(
                    self.pool.clone(),
                ),
        }
    }
}

impl MixOutboxPort for MixOutboxContext {
    type Repository = PostgresMixRepository;
    type Session = OnlineSession;
    type Federation = FederationRouter;

    fn service(&self) -> &MixService<PostgresMixRepository> {
        &self.service
    }

    fn local_domain(&self) -> &str {
        &self.local_domain
    }

    fn federation_domain_allowed(&self, domain: &str) -> bool {
        self.policy.domain_allowed(domain)
    }

    fn federation_outbox(&self) -> &FederationRouter {
        &self.federation
    }

    fn session_entries_for(&self, jid: &str) -> Vec<(String, OnlineSession)> {
        session_entries_for_in(&self.sessions, jid)
    }

    /// The same verified observation and stale-local-epoch eviction used by
    /// ordinary CAPS routing. An unknown observation keeps durable delivery
    /// parked until verification or the recipient's next route wake.
    fn session_mix_capability(&self, full_jid: &str) -> MixSessionCapability {
        session_mix_capability_in(
            &self.sessions,
            &self.caps_by_jid,
            &self.pending_caps,
            full_jid,
        )
    }

    async fn lookup_nodes(&self, jid: &str) -> Result<Vec<String>> {
        let nodes = self.cluster_routes.lookup_nodes(jid).await?;
        Ok(remote_nodes_in_order(nodes, self.cluster_routes.node_id()))
    }

    async fn outbox_lookup_cluster_nodes(&self, jid: &str) -> Result<Vec<String>> {
        let nodes = self
            .service
            .outbox_lookup_cluster_nodes(&self.cluster_routes, jid)
            .await?;
        Ok(remote_nodes_in_order(nodes, self.cluster_routes.node_id()))
    }

    async fn send_cluster_mix(
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

    async fn send_cluster_pam_result(
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

    fn record_post_commit_failure(&self) {
        MixPostCommitTelemetry::new(&self.delivery_failures, &self.post_accept_failures)
            .delivery_failed();
    }
}
