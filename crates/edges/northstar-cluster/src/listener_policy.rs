//! Typed message policy and command outcomes the cluster listener receives from the composition root.

use crate::ClusterAdapters;
use northstar_telemetry::metrics::Metrics;
use std::sync::{atomic::Ordering, Arc};
use uuid::Uuid;

pub struct ClusterListenerMessagePolicy<A: ClusterAdapters> {
    pub local_domain: String,
    pub presence: northstar_roster_application::presence::PresenceService<A::Presence>,
    pub message: northstar_message_application::messaging::MessageService<A::Message>,
    pub mix: northstar_room_application::mix_service::MixService<A::Mix>,
    pub verifier:
        northstar_session_application::node_message_contract_verifier::NodeMessageContractVerifier<
            A::NodeMessageProjection,
        >,
    pub metrics: Arc<Metrics>,
}

impl<A: ClusterAdapters> ClusterListenerMessagePolicy<A> {
    pub fn start_redis_setup_timer(&self) -> northstar_telemetry::metrics::DurationTimer<'_> {
        self.metrics.redis_operation_duration_seconds.start_timer()
    }

    pub fn presence_probe_failed(&self) {
        self.metrics
            .cluster_presence_probe_failures_total
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_online_queue_acceptance(&self, durable: bool) {
        let counter = if durable {
            &self.metrics.online_queue_durable_acceptances_total
        } else {
            &self.metrics.online_queue_volatile_acceptances_total
        };
        counter.fetch_add(1, Ordering::Relaxed);
    }

    pub async fn presence_authority_is_current(
        &self,
        owner: &str,
        owner_id: Uuid,
        owner_auth_generation: i64,
        recipient: &str,
        recipient_id: Uuid,
        recipient_auth_generation: i64,
    ) -> bool {
        self.presence
            .cluster_authority_is_current(
                &self.local_domain,
                owner,
                owner_id,
                owner_auth_generation,
                recipient,
                recipient_id,
                recipient_auth_generation,
            )
            .await
            .unwrap_or(false)
    }

    pub async fn owner_avatar_hash(&self, user_id: Uuid) -> anyhow::Result<Option<String>> {
        self.presence.avatar_hash(user_id).await
    }

    pub fn verifier(
        &self,
    ) -> &northstar_session_application::node_message_contract_verifier::NodeMessageContractVerifier<
        A::NodeMessageProjection,
    >{
        &self.verifier
    }

    pub async fn privacy_allows_session(
        &self,
        user_id: Uuid,
        connection_id: Uuid,
        active_privacy_list: Option<&str>,
        peer: &str,
        kind: northstar_xep_0016::PrivacyStanzaKind,
    ) -> anyhow::Result<bool> {
        self.message
            .privacy_allows_session(user_id, connection_id, active_privacy_list, peer, kind)
            .await
    }

    pub async fn transfer_mix_delivery(
        &self,
        source: northstar_stream::outbound::MixDelivery,
        node_id: &str,
        request_id: Uuid,
        ttl_seconds: u64,
    ) -> anyhow::Result<northstar_stream::outbound::MixDelivery> {
        self.mix
            .transfer_mix_delivery_to_cluster(source, node_id, request_id, ttl_seconds)
            .await
    }

    pub async fn release_mix_delivery(
        &self,
        source: northstar_stream::outbound::MixDelivery,
        node_id: &str,
        request_id: Uuid,
    ) -> anyhow::Result<bool> {
        self.mix
            .release_mix_cluster_delivery(source, node_id, request_id)
            .await
    }
}

pub enum SessionTerminationEffect {
    Absent,
    WrongOwner,
    Matched,
}

pub enum ClusterMixCapability {
    Supported,
    Unsupported,
    Unknown,
}
