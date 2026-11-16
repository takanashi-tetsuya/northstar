//! Root bindings for the stream-owned CAPS effect dispatcher.

use super::{
    mix_presence_recovery::MixPresenceRecoveryContext, pep_last_items::PepLastItemsAdapters,
    AppState,
};
use crate::state::FederationRouter;
use northstar_pubsub_xmpp::pep_last_items::PepLastItemsContext;
use northstar_session_core::LocalCapsEpoch;
use northstar_stream::caps_effects::{
    CapsEffectCounters, CapsEffectDispatchContext, CapsEffectPorts,
};
use northstar_workflows::pubsub_repository::PostgresPubSubRepository;
use std::sync::Arc;

pub(crate) struct CapsEffectAdapters {
    federation_outbox: FederationRouter,
    pep: PepLastItemsContext<PostgresPubSubRepository, PepLastItemsAdapters>,
    mix: MixPresenceRecoveryContext,
}

impl AppState {
    pub(crate) fn caps_effect_dispatch_context(
        &self,
    ) -> CapsEffectDispatchContext<CapsEffectAdapters> {
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
            local_domain: self.config.domain.clone(),
            ports: CapsEffectAdapters {
                federation_outbox: self.federation.federation_outbox.clone(),
                pep: self.pep_last_items_context(),
                mix: self.mix_presence_recovery_context(),
            },
        }
    }
}

impl CapsEffectPorts for CapsEffectAdapters {
    async fn send_federated_disco(&self, domain: &str, query: String, local_domain: &str) -> bool {
        self.federation_outbox
            .send(domain, query, Some(local_domain.to_owned()))
            .await
    }

    async fn deliver_explicit_pep_last_items_for_resource(
        &self,
        full_jid: &str,
        local_epoch: Option<LocalCapsEpoch>,
    ) -> anyhow::Result<()> {
        northstar_pubsub_xmpp::pep::deliver_explicit_pep_last_items_for_resource(
            &self.pep,
            full_jid,
            local_epoch,
        )
        .await
    }

    async fn deliver_pep_last_items_for_resource(
        &self,
        full_jid: &str,
        epoch: LocalCapsEpoch,
    ) -> anyhow::Result<()> {
        northstar_pubsub_xmpp::pep::deliver_pep_last_items_for_resource(&self.pep, full_jid, epoch)
            .await
    }

    async fn deliver_pep_last_items_for_federated_resource(
        &self,
        full_jid: &str,
    ) -> anyhow::Result<()> {
        northstar_pubsub_xmpp::pep::deliver_pep_last_items_for_federated_resource(
            &self.pep, full_jid,
        )
        .await
    }

    async fn publish_verified_mix_presence(
        &self,
        full_jid: &str,
        epoch: LocalCapsEpoch,
    ) -> anyhow::Result<()> {
        northstar_mix_xmpp::publish_verified_mix_presence_with(
            &self.mix,
            full_jid,
            epoch.connection_id,
            epoch.generation,
        )
        .await
    }
}

impl AppState {
    pub(crate) fn caps_effect_dispatcher(
        &self,
    ) -> &Arc<northstar_protocol_runtime::caps::CapsEffectDispatcher> {
        &self.caps_effect_dispatcher
    }

    pub(crate) fn caps_cache(&self) -> &northstar_protocol_runtime::caps::CapsCacheIndex {
        &self.caps_cache
    }

    pub(crate) fn caps_by_jid(&self) -> &northstar_protocol_runtime::caps::CapsResourceIndex {
        &self.caps_by_jid
    }

    pub(crate) fn pending_caps(&self) -> &northstar_protocol_runtime::caps::PendingCapsIndex {
        &self.pending_caps
    }

    pub(crate) fn federated_caps_gates(
        &self,
    ) -> &northstar_protocol_runtime::caps::FederatedCapsGateIndex {
        &self.federated_caps_gates
    }
}
