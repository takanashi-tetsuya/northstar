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

pub(crate) fn session_mix_capability_in(
    sessions: &DashMap<String, OnlineSession>,
    caps_by_jid: &CapsResourceIndex,
    pending_caps: &PendingCapsIndex,
    full_jid: &str,
) -> MixSessionCapability {
    let Ok(full_jid) = crate::jid::canonical_session_key(full_jid) else {
        return MixSessionCapability::Unknown;
    };
    let Some(observation) = caps_by_jid.snapshot(&full_jid) else {
        return MixSessionCapability::Unknown;
    };
    if let CapsObservationOwner::Local(epoch) = observation.owner {
        let current = sessions.get(&full_jid).is_some_and(|session| {
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
            pending_caps.remove_local_epoch(&full_jid, epoch);
            caps_by_jid.remove_local_epoch(&full_jid, epoch);
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
        session_mix_capability_in(
            &self.sessions,
            &self.caps_by_jid,
            &self.pending_caps,
            full_jid,
        )
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
    use super::*;
    use crate::state::{route_helper_tests::session, LocalCapsEpoch};
    use northstar_protocol_runtime::caps::{CapsKey, VerifiedCapsSummary};
    use std::time::{Duration, Instant};

    const KEY: &str = "alice@example.test/fixture";

    fn caps_key(version: &str) -> CapsKey {
        CapsKey {
            algorithm: "sha-1".to_owned(),
            node: "https://example.test/caps".to_owned(),
            version: version.to_owned(),
        }
    }

    fn supplied_summary(core: bool, pam: bool) -> Arc<VerifiedCapsSummary> {
        // Supplied verified environment; these tests do not run disco/hash verification.
        Arc::new(VerifiedCapsSummary::new(
            core,
            pam,
            String::new(),
            Vec::new(),
        ))
    }

    #[test]
    fn local_caps_classification_uses_the_current_canonical_route_and_summary() {
        for (features, expected) in [
            (Some((true, false)), MixSessionCapability::Supported),
            (Some((false, true)), MixSessionCapability::Supported),
            (Some((false, false)), MixSessionCapability::Unsupported),
            (None, MixSessionCapability::Unknown),
        ] {
            let sessions = DashMap::new();
            let (route, _receiver) = session(Uuid::from_u128(1), Uuid::from_u128(2), true);
            let epoch = LocalCapsEpoch {
                connection_id: route.connection_id,
                generation: route.caps_observation_generation.load(Ordering::Acquire),
            };
            sessions.insert(KEY.to_owned(), route);
            let caps = CapsResourceIndex::new();
            let pending = PendingCapsIndex::new();
            let now = Instant::now();
            caps.observe_local(
                KEY.to_owned(),
                epoch,
                Some(caps_key("current")),
                features.map(|(core, pam)| supplied_summary(core, pam)),
                now,
            );
            assert!(pending.insert(
                "current".to_owned(),
                KEY.to_owned(),
                caps_key("current"),
                CapsObservationOwner::Local(epoch),
                now + Duration::from_secs(30),
            ));
            assert_eq!(
                session_mix_capability_in(&sessions, &caps, &pending, "ALICE@EXAMPLE.TEST/fixture"),
                expected
            );
            assert_eq!(caps.owner(KEY), Some(CapsObservationOwner::Local(epoch)));
            assert_eq!(caps.len(), 1);
            assert_eq!(pending.len(), 1);
            assert_eq!(
                pending.entries.get("current").unwrap().owner,
                CapsObservationOwner::Local(epoch)
            );
        }
    }

    #[test]
    fn invalid_or_unobserved_caps_target_keeps_existing_indexes() {
        let sessions = DashMap::new();
        let (route, _receiver) = session(Uuid::from_u128(1), Uuid::from_u128(2), true);
        let epoch = LocalCapsEpoch {
            connection_id: route.connection_id,
            generation: route.caps_observation_generation.load(Ordering::Acquire),
        };
        sessions.insert(KEY.to_owned(), route);
        let caps = CapsResourceIndex::new();
        let pending = PendingCapsIndex::new();
        let now = Instant::now();
        caps.observe_local(
            KEY.to_owned(),
            epoch,
            Some(caps_key("current")),
            Some(supplied_summary(true, false)),
            now,
        );
        assert!(pending.insert(
            "current".to_owned(),
            KEY.to_owned(),
            caps_key("current"),
            CapsObservationOwner::Local(epoch),
            now + Duration::from_secs(30),
        ));
        for target in ["", "alice@example.test", "alice@example.test/missing"] {
            assert_eq!(
                session_mix_capability_in(&sessions, &caps, &pending, target),
                MixSessionCapability::Unknown,
                "{target}"
            );
            assert_eq!(caps.owner(KEY), Some(CapsObservationOwner::Local(epoch)));
            assert_eq!(caps.len(), 1);
            assert_eq!(pending.len(), 1);
        }
    }

    #[test]
    fn stale_local_caps_evict_only_the_queried_epoch_and_preserve_other_observations() {
        for case in [
            "missing session",
            "connection",
            "generation",
            "unroutable",
            "session cancelled",
            "lifecycle one",
            "lifecycle two",
        ] {
            let sessions = DashMap::new();
            let (mut route, _receiver) = session(Uuid::from_u128(1), Uuid::from_u128(2), true);
            let epoch = LocalCapsEpoch {
                connection_id: route.connection_id,
                generation: route.caps_observation_generation.load(Ordering::Acquire),
            };
            match case {
                "missing session" => {}
                "connection" => {
                    route.connection_id = Uuid::from_u128(3);
                    route.route_incarnation =
                        crate::state::RouteIncarnationSignal::new(route.connection_id);
                }
                "generation" => route
                    .caps_observation_generation
                    .store(12, Ordering::Release),
                "unroutable" => route.routable.store(false, Ordering::Release),
                "session cancelled" => route.disconnect.cancel(),
                "lifecycle one" => route.lifecycle.store(1, Ordering::Release),
                "lifecycle two" => route.lifecycle.store(2, Ordering::Release),
                _ => unreachable!(),
            }
            if case != "missing session" {
                sessions.insert(KEY.to_owned(), route);
            }
            let caps = CapsResourceIndex::new();
            let pending = PendingCapsIndex::new();
            let now = Instant::now();
            let summary = supplied_summary(true, false);
            for key in [KEY, "alice@example.test/other"] {
                caps.observe_local(
                    key.to_owned(),
                    epoch,
                    Some(caps_key("old")),
                    Some(Arc::clone(&summary)),
                    now,
                );
            }
            let newer_epoch = LocalCapsEpoch {
                connection_id: epoch.connection_id,
                generation: epoch.generation + 1,
            };
            for (id, owner) in [("old", epoch), ("newer", newer_epoch)] {
                assert!(pending.insert(
                    id.to_owned(),
                    KEY.to_owned(),
                    caps_key(id),
                    CapsObservationOwner::Local(owner),
                    now + Duration::from_secs(30),
                ));
            }
            assert_eq!(caps.len(), 2);
            assert_eq!(pending.len(), 2);
            assert_eq!(
                session_mix_capability_in(&sessions, &caps, &pending, "ALICE@EXAMPLE.TEST/fixture"),
                MixSessionCapability::Unknown,
                "{case}"
            );
            assert!(caps.owner(KEY).is_none(), "{case}");
            assert!(pending.entries.get("old").is_none(), "{case}");
            assert_eq!(
                pending.entries.get("newer").unwrap().owner,
                CapsObservationOwner::Local(newer_epoch),
                "{case}"
            );
            // The other target is also stale, but was never queried.
            assert_eq!(
                caps.owner("alice@example.test/other"),
                Some(CapsObservationOwner::Local(epoch)),
                "{case}"
            );
            assert_eq!(caps.len(), 1);
            assert_eq!(pending.len(), 1);
            assert_eq!(
                caps.admission.lock().unwrap().summary_bytes,
                summary.resident_charge()
            );
        }
    }

    #[test]
    fn federated_caps_classification_does_not_apply_local_route_fences() {
        for (features, expected) in [
            (Some((false, true)), MixSessionCapability::Supported),
            (Some((false, false)), MixSessionCapability::Unsupported),
            (None, MixSessionCapability::Unknown),
        ] {
            let sessions = DashMap::new();
            let (route, _receiver) = session(Uuid::from_u128(1), Uuid::from_u128(2), false);
            route.disconnect.cancel();
            route.lifecycle.store(2, Ordering::Release);
            sessions.insert(KEY.to_owned(), route);
            let caps = CapsResourceIndex::new();
            let pending = PendingCapsIndex::new();
            let now = Instant::now();
            let owner = caps
                .observe_federated(
                    KEY.to_owned(),
                    Uuid::from_u128(3),
                    "example.test".to_owned(),
                    Some(caps_key("federated")),
                    features.map(|(core, pam)| supplied_summary(core, pam)),
                    now,
                )
                .unwrap();
            assert!(pending.insert(
                "federated".to_owned(),
                KEY.to_owned(),
                caps_key("federated"),
                owner,
                now + Duration::from_secs(30),
            ));
            assert_eq!(
                session_mix_capability_in(&sessions, &caps, &pending, KEY),
                expected
            );
            assert_eq!(caps.owner(KEY), Some(owner));
            assert_eq!(pending.entries.get("federated").unwrap().owner, owner);
            assert_eq!(caps.len(), 1);
            assert_eq!(pending.len(), 1);
        }
    }

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
