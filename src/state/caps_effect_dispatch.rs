//! CAPS effect scheduling, exact local routes, and disco transport authority.

use super::{
    local_caps_route_epoch_matches, mix_presence_recovery::MixPresenceRecoveryContext,
    pep_last_items::PepLastItemsContext, AppState, OnlineSession,
};
use crate::{
    metrics::DurationHistogram, outbound::OutboundSender, s2s::FederationRouter,
    xmpp::capabilities::CapsEffectTelemetry,
};
use dashmap::DashMap;
use northstar_protocol_runtime::caps::{
    CapsCacheIndex, CapsEffectDispatcher, CapsResourceIndex, FederatedCapsGateIndex,
    FederatedCapsGuard, PendingCapsIndex,
};
use northstar_session_core::LocalCapsEpoch;
use std::sync::{
    atomic::{AtomicU64, Ordering},
    Arc,
};

/// The supervised task owns only CAPS state, exact route fences, and PEP/MIX
/// effect capabilities. It never retains the application state or a raw pool.
pub(crate) struct CapsEffectDispatchContext {
    pub(crate) observations: Arc<CapsResourceIndex>,
    pub(crate) pending: Arc<PendingCapsIndex>,
    pub(crate) cache: Arc<CapsCacheIndex>,
    pub(crate) dispatcher: Arc<CapsEffectDispatcher>,
    counters: CapsEffectCounters,
    federated_gates: Arc<FederatedCapsGateIndex>,
    sessions: Arc<DashMap<String, OnlineSession>>,
    federation_outbox: FederationRouter,
    local_domain: String,
    pep: PepLastItemsContext,
    mix: MixPresenceRecoveryContext,
}

struct CapsEffectCounters {
    coalesced: Arc<AtomicU64>,
    queue_saturated: Arc<AtomicU64>,
    failures: Arc<AtomicU64>,
    latency: Arc<DurationHistogram>,
}

impl AppState {
    pub(crate) fn caps_effect_dispatch_context(&self) -> CapsEffectDispatchContext {
        CapsEffectDispatchContext {
            observations: Arc::clone(&self.caps_by_jid),
            pending: Arc::clone(&self.pending_caps),
            cache: Arc::clone(&self.caps_cache),
            dispatcher: Arc::clone(&self.caps_effect_dispatcher),
            counters: CapsEffectCounters {
                coalesced: Arc::clone(&self.metrics.caps_effect_coalesced_total),
                queue_saturated: Arc::clone(&self.metrics.caps_effect_queue_saturated_total),
                failures: Arc::clone(&self.metrics.caps_effect_failures_total),
                latency: Arc::clone(&self.metrics.caps_effect_latency_seconds),
            },
            federated_gates: Arc::clone(&self.federated_caps_gates),
            sessions: Arc::clone(&self.sessions),
            federation_outbox: self.federation_outbox.clone(),
            local_domain: self.config.domain.clone(),
            pep: self.pep_last_items_context(),
            mix: self.mix_presence_recovery_context(),
        }
    }
}

impl CapsEffectDispatchContext {
    pub(crate) fn telemetry(&self) -> CapsEffectTelemetry<'_> {
        CapsEffectTelemetry::new(
            &self.counters.coalesced,
            &self.counters.queue_saturated,
            &self.counters.failures,
            &self.counters.latency,
        )
    }

    pub(crate) fn pep(&self) -> &PepLastItemsContext {
        &self.pep
    }

    pub(crate) fn mix(&self) -> &MixPresenceRecoveryContext {
        &self.mix
    }

    pub(crate) fn local_domain(&self) -> &str {
        &self.local_domain
    }

    pub(crate) fn local_epoch_is_current(&self, full_jid: &str, epoch: LocalCapsEpoch) -> bool {
        self.sessions.get(full_jid).is_some_and(|session| {
            local_caps_route_epoch_matches(
                session.connection_id,
                session.caps_observation_generation.load(Ordering::Acquire),
                session.routable.load(Ordering::Acquire),
                session.disconnect.is_cancelled(),
                session.lifecycle.load(Ordering::Acquire),
                true,
                epoch,
            )
        })
    }

    pub(crate) fn local_sender_if_current(
        &self,
        full_jid: &str,
        epoch: LocalCapsEpoch,
    ) -> Option<OutboundSender> {
        self.sessions.get(full_jid).and_then(|session| {
            local_caps_route_epoch_matches(
                session.connection_id,
                session.caps_observation_generation.load(Ordering::Acquire),
                session.routable.load(Ordering::Acquire),
                session.disconnect.is_cancelled(),
                session.lifecycle.load(Ordering::Acquire),
                true,
                epoch,
            )
            .then(|| session.sender.clone())
        })
    }

    pub(crate) async fn lock_federated_resource(&self, full_jid: &str) -> FederatedCapsGuard<'_> {
        self.federated_gates.lock(full_jid).await
    }

    pub(crate) async fn send_federated_disco(&self, domain: &str, query: String) -> bool {
        self.federation_outbox
            .send(domain, query, Some(self.local_domain.to_owned()))
            .await
    }
}
