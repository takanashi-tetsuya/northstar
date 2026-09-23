//! Typed policy and durable hand-off effects for authenticated node delivery.

use super::{AppState, OnlineSession};
use crate::{db, metrics::Metrics};
use std::sync::{atomic::Ordering, Arc};
use uuid::Uuid;

pub(crate) struct ClusterListenerMessagePolicy {
    local_domain: String,
    presence: crate::services::presence::PresenceService<
        db::presence_repository::PostgresPresenceRepository,
    >,
    message: crate::services::messaging::MessageService<db::messaging::PostgresMessageRepository>,
    mix: crate::services::mix::MixService<db::mix_repository::PostgresMixRepository>,
    verifier: crate::services::node_message_contract_verifier::NodeMessageContractVerifier<
        db::node_message_projection_repository::PostgresNodeMessageProjectionRepository,
    >,
    metrics: Arc<Metrics>,
}

impl AppState {
    pub(crate) fn cluster_listener_message_policy(&self) -> ClusterListenerMessagePolicy {
        ClusterListenerMessagePolicy {
            local_domain: self.config.domain.clone(),
            presence: self.presence_service.clone(),
            message: self.message_service.clone(),
            mix: self.mix_service.clone(),
            verifier: self.node_message_contract_verifier(),
            metrics: Arc::clone(&self.metrics),
        }
    }
}

impl ClusterListenerMessagePolicy {
    pub(crate) fn start_redis_setup_timer(&self) -> crate::metrics::DurationTimer<'_> {
        self.metrics.redis_operation_duration_seconds.start_timer()
    }

    pub(crate) fn presence_probe_failed(&self) {
        self.metrics
            .cluster_presence_probe_failures_total
            .fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn record_online_queue_acceptance(&self, durable: bool) {
        let counter = if durable {
            &self.metrics.online_queue_durable_acceptances_total
        } else {
            &self.metrics.online_queue_volatile_acceptances_total
        };
        counter.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) async fn presence_authority_is_current(
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

    pub(crate) async fn owner_avatar_hash(&self, user_id: Uuid) -> anyhow::Result<Option<String>> {
        self.presence.avatar_hash(user_id).await
    }

    pub(crate) fn verifier(
        &self,
    ) -> &crate::services::node_message_contract_verifier::NodeMessageContractVerifier<
        db::node_message_projection_repository::PostgresNodeMessageProjectionRepository,
    > {
        &self.verifier
    }

    pub(crate) async fn privacy_allows_session(
        &self,
        session: &OnlineSession,
        peer: &str,
        kind: db::PrivacyStanzaKind,
    ) -> anyhow::Result<bool> {
        let active = session
            .privacy_active
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone();
        self.message
            .privacy_allows_session(
                session.user_id,
                session.connection_id,
                active.as_deref(),
                peer,
                kind,
            )
            .await
    }

    pub(crate) async fn transfer_mix_delivery(
        &self,
        source: crate::outbound::MixDelivery,
        node_id: &str,
        request_id: Uuid,
        ttl_seconds: u64,
    ) -> anyhow::Result<crate::outbound::MixDelivery> {
        self.mix
            .transfer_mix_delivery_to_cluster(source, node_id, request_id, ttl_seconds)
            .await
    }

    pub(crate) async fn release_mix_delivery(
        &self,
        source: crate::outbound::MixDelivery,
        node_id: &str,
        request_id: Uuid,
    ) -> anyhow::Result<bool> {
        self.mix
            .release_mix_cluster_delivery(source, node_id, request_id)
            .await
    }
}
