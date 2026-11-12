//! AppState metrics recorders, telemetry handles, broadcast routes and cluster runtime handles.

use super::*;
use crate::state::http_contexts::MetricsContext;

impl AppState {
    pub(crate) fn record_bosh_session_opened(&self) {
        self.metrics
            .bosh_sessions_total
            .fetch_add(1, Ordering::Relaxed);
        self.metrics
            .bosh_sessions_active
            .fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn record_bosh_session_closed(&self) {
        self.metrics
            .bosh_sessions_active
            .fetch_sub(1, Ordering::Relaxed);
    }

    pub(crate) fn record_c2s_tcp_connection(&self) {
        self.metrics
            .tcp_connections_total
            .fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn record_c2s_websocket_connection(&self) {
        self.metrics
            .websocket_connections_total
            .fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn record_c2s_backpressure_disconnect(&self) {
        self.metrics
            .c2s_backpressure_disconnects_total
            .fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn c2s_backpressure_telemetry(
        &self,
    ) -> northstar_telemetry::metrics::C2sBackpressureTelemetry {
        self.metrics.c2s_backpressure_telemetry()
    }

    pub(crate) fn federation_outbox(&self) -> &FederationRouter {
        &self.federation.federation_outbox
    }

    pub(crate) fn cluster_authority_service(
        &self,
    ) -> northstar_session_application::cluster_authority::ClusterAuthorityService<
        northstar_session_postgres::cluster_authority_repository::PostgresClusterAuthorityRepository,
    >{
        northstar_session_application::cluster_authority::ClusterAuthorityService::new(
            northstar_session_postgres::cluster_authority_repository::PostgresClusterAuthorityRepository::new(
                self.pool.clone(),
            ),
        )
    }

    pub(crate) fn cluster_muc_occupancy_maintenance_service(
        &self,
    ) -> northstar_room_application::muc_service::ClusterMucOccupancyMaintenanceService<
        northstar_room_postgres::room::PostgresClusterMucOccupancyMaintenanceRepository,
    > {
        northstar_room_application::muc_service::ClusterMucOccupancyMaintenanceService::new(
            northstar_room_postgres::room::PostgresClusterMucOccupancyMaintenanceRepository::new(
                self.pool.clone(),
            ),
        )
    }

    pub(crate) fn node_message_contract_verifier(
        &self,
    ) -> northstar_session_application::node_message_contract_verifier::NodeMessageContractVerifier<
        northstar_session_postgres::node_message_projection_repository::PostgresNodeMessageProjectionRepository,
    >{
        northstar_session_application::node_message_contract_verifier::NodeMessageContractVerifier::new(
            northstar_session_postgres::node_message_projection_repository::PostgresNodeMessageProjectionRepository::new(
                self.pool.clone(),
            ),
        )
    }

    pub(crate) fn cluster_instance_release_service(
        &self,
    ) -> northstar_session_application::cluster_instance_release::ClusterInstanceReleaseService<
        northstar_session_postgres::cluster_instance_release_repository::PostgresClusterInstanceReleaseRepository,
    >{
        northstar_session_application::cluster_instance_release::ClusterInstanceReleaseService::new(
            northstar_session_postgres::cluster_instance_release_repository::PostgresClusterInstanceReleaseRepository::new(
                self.pool.clone(),
            ),
        )
    }

    pub(crate) fn metrics_context(&self) -> MetricsContext {
        metrics_context::metrics_context(self)
    }

    pub(crate) fn broadcast_routes(
        &self,
    ) -> crate::runtime::operation_runtime::LocalBroadcastRoutes {
        crate::runtime::operation_runtime::LocalBroadcastRoutes::new(
            Arc::clone(&self.sessions),
            self.config.domain.clone(),
            self.cluster.node_id.clone(),
        )
    }

    pub(crate) fn session_kick_routes(
        &self,
    ) -> crate::runtime::operation_runtime::LocalSessionKickRoutes {
        crate::runtime::operation_runtime::LocalSessionKickRoutes::new(Arc::clone(&self.sessions))
    }

    pub(crate) fn generation_cleanup_routes(
        &self,
    ) -> crate::runtime::operation_runtime::LocalGenerationCleanupRoutes {
        crate::runtime::operation_runtime::LocalGenerationCleanupRoutes::new(Arc::clone(
            &self.sessions,
        ))
    }

    pub(crate) fn panic_disconnect_routes(
        &self,
    ) -> crate::runtime::operation_runtime::LocalPanicDisconnectRoutes {
        crate::runtime::operation_runtime::LocalPanicDisconnectRoutes::new(Arc::clone(
            &self.sessions,
        ))
    }

    pub(crate) fn muc_telemetry(&self) -> northstar_room_core::telemetry::MucTelemetry<'_> {
        northstar_room_core::telemetry::MucTelemetry::new(
            &self.metrics.muc_post_commit_delivery_failures_total,
            &self.metrics.post_accept_side_effect_failures_total,
            &self.metrics.cluster_muc_authority_rejections_total,
            &self.metrics.online_queue_durable_acceptances_total,
            &self.metrics.online_queue_volatile_acceptances_total,
            &self.metrics.messages_routed_total,
            &self.metrics.capacity_reservations_rejected_total,
        )
    }

    pub(crate) fn caps_effect_telemetry(
        &self,
    ) -> northstar_session_application::telemetry::CapsEffectTelemetry<'_> {
        northstar_session_application::telemetry::CapsEffectTelemetry::new(
            &self.metrics.caps_effect_coalesced_total,
            &self.metrics.caps_effect_queue_saturated_total,
            &self.metrics.caps_effect_failures_total,
            &self.metrics.caps_effect_latency_seconds,
        )
    }

    pub(crate) fn presence_probe_telemetry(
        &self,
    ) -> crate::xmpp::capabilities::PresenceProbeTelemetry<'_> {
        crate::xmpp::capabilities::PresenceProbeTelemetry::new(
            &self.metrics.cluster_presence_probe_failures_total,
        )
    }

    pub(crate) fn inbound_stanza_telemetry(
        &self,
    ) -> northstar_session_application::telemetry::InboundStanzaTelemetry<'_> {
        northstar_session_application::telemetry::InboundStanzaTelemetry::new(
            &self.metrics.stanzas_in_total,
        )
    }

    pub(crate) fn post_accept_failure_telemetry(
        &self,
    ) -> northstar_roster_xmpp::PostAcceptFailureTelemetry {
        northstar_roster_xmpp::PostAcceptFailureTelemetry::new(Arc::clone(
            &self.metrics.post_accept_side_effect_failures_total,
        ))
    }

    pub(crate) fn push_subscription_telemetry(
        &self,
    ) -> northstar_session_application::telemetry::PushSubscriptionTelemetry<'_> {
        northstar_session_application::telemetry::PushSubscriptionTelemetry::new(
            &self.metrics.rate_limited_total,
            &self.metrics.push_subscriptions_rate_limited_total,
        )
    }

    pub(crate) fn push_delivery_telemetry(
        &self,
    ) -> northstar_session_application::telemetry::PushDeliveryTelemetry<'_> {
        northstar_session_application::telemetry::PushDeliveryTelemetry::new(
            &self.metrics.push_notifications_failed_total,
            &self.metrics.push_notifications_routed_total,
            &self.metrics.push_notifications_attempted_total,
        )
    }

    pub(crate) fn registration_telemetry(
        &self,
    ) -> northstar_session_application::telemetry::RegistrationTelemetry<'_> {
        northstar_session_application::telemetry::RegistrationTelemetry::new(
            &self.metrics.anti_abuse_backend_failures_total,
            &self.metrics.registrations_total,
            &self.metrics.rate_limited_total,
            &self.metrics.capacity_reservations_rejected_total,
        )
    }

    pub(crate) fn account_abuse_telemetry(
        &self,
    ) -> northstar_session_application::telemetry::AccountAbuseTelemetry<'_> {
        northstar_session_application::telemetry::AccountAbuseTelemetry::new(
            &self.metrics.anti_abuse_backend_failures_total,
            &self.metrics.rate_limited_total,
        )
    }

    pub(crate) fn session_bind_telemetry(
        &self,
    ) -> northstar_session_application::telemetry::SessionBindTelemetry<'_> {
        northstar_session_application::telemetry::SessionBindTelemetry::new(
            &self.metrics.capacity_reservations_rejected_total,
            &self.metrics.active_sessions,
        )
    }

    pub(crate) fn sm_session_telemetry(
        &self,
    ) -> northstar_session_application::telemetry::SmSessionTelemetry<'_> {
        northstar_session_application::telemetry::SmSessionTelemetry::new(
            &self.metrics.capacity_reservations_rejected_total,
            &self.metrics.active_sessions,
        )
    }

    pub(crate) fn sasl2_authentication_telemetry(
        &self,
    ) -> northstar_session_application::telemetry::Sasl2AuthenticationTelemetry<'_> {
        northstar_session_application::telemetry::Sasl2AuthenticationTelemetry::new(
            &self.metrics.fast_credential_integrity_failures_total,
            &self.metrics.authentication_backend_failures_total,
        )
    }

    pub(crate) fn sasl2_authentication_timer(
        &self,
    ) -> northstar_telemetry::metrics::OwnedDurationTimer {
        self.metrics
            .authentication_duration_seconds
            .start_owned_timer()
    }

    pub(crate) fn c2s_authentication_telemetry(
        &self,
    ) -> northstar_session_application::telemetry::C2sAuthenticationTelemetry<'_> {
        northstar_session_application::telemetry::C2sAuthenticationTelemetry::new(
            &self.metrics.authentication_backend_failures_total,
            &self.metrics.fast_credential_integrity_failures_total,
            &self.metrics.authentication_failures_total,
            &self.metrics.rate_limited_total,
        )
    }

    pub(crate) fn outbound_stanza_telemetry(
        &self,
    ) -> northstar_session_application::telemetry::OutboundStanzaTelemetry<'_> {
        northstar_session_application::telemetry::OutboundStanzaTelemetry::new(
            &self.metrics.stanzas_out_total,
        )
    }

    pub(crate) fn session_drop_fallback_telemetry(
        &self,
    ) -> northstar_session_application::telemetry::SessionDropFallbackTelemetry<'_> {
        northstar_session_application::telemetry::SessionDropFallbackTelemetry::new(
            &self.metrics.session_drop_fallbacks_total,
        )
    }

    pub(crate) fn c2s_post_action_telemetry(
        &self,
    ) -> northstar_session_application::post_actions::PostActionTelemetry<'_> {
        northstar_session_application::post_actions::PostActionTelemetry::new(
            &self.metrics.post_action_tasks_started_total,
            &self.metrics.post_action_tasks_completed_total,
            &self.metrics.post_action_tasks_panicked_total,
            &self.metrics.post_action_tasks_aborted_total,
            &self.metrics.post_action_capacity_rejections_total,
        )
    }

    pub(crate) fn personal_message_telemetry(
        &self,
    ) -> northstar_message_application::telemetry::PersonalMessageTelemetry<'_> {
        northstar_message_application::telemetry::PersonalMessageTelemetry::new(
            northstar_message_application::telemetry::PersonalMessageTelemetryCells {
                routing_duration: &self.metrics.routing_duration_seconds,
                rate_limited: &self.metrics.rate_limited_total,
                abuse_backend_failures: &self.metrics.anti_abuse_backend_failures_total,
                messages_routed: &self.metrics.messages_routed_total,
                post_accept_failures: &self.metrics.post_accept_side_effect_failures_total,
                durable_queue_acceptances: &self.metrics.online_queue_durable_acceptances_total,
                volatile_queue_acceptances: &self.metrics.online_queue_volatile_acceptances_total,
                carbon_delivery_failures: &self.metrics.carbon_post_accept_delivery_failures_total,
                carbon_target_timeouts: &self.metrics.carbon_fanout_target_timeouts_total,
                cluster_legacy_acceptances: &self.metrics.cluster_legacy_delivery_acceptances_total,
            },
        )
    }

    pub(crate) fn federated_muc_telemetry(
        &self,
    ) -> northstar_room_core::telemetry::FederatedMucTelemetry<'_> {
        northstar_room_core::telemetry::FederatedMucTelemetry::new(
            &self.metrics.muc_post_commit_delivery_failures_total,
            &self.metrics.post_accept_side_effect_failures_total,
            &self.metrics.capacity_reservations_rejected_total,
            &self.metrics.online_queue_durable_acceptances_total,
            &self.metrics.online_queue_volatile_acceptances_total,
            &self.metrics.messages_routed_total,
        )
    }

    pub(crate) fn pep_telemetry(&self) -> crate::xmpp::capabilities::PepTelemetry<'_> {
        crate::xmpp::capabilities::PepTelemetry::new(
            &self.metrics.pep_items_published_total,
            &self.metrics.pep_items_retracted_total,
            &self.metrics.pep_retrievals_total,
        )
    }

    pub(crate) fn component_telemetry(
        &self,
    ) -> northstar_federation_application::components::ComponentTelemetry<'_> {
        northstar_federation_application::components::ComponentTelemetry::new(
            &self.metrics.component_connections_active,
            &self.metrics.outbox_delivery_duration_seconds,
            &self.metrics.component_failures_total,
            &self.metrics.component_deliveries_total,
            &self.metrics.s2s_outbox_lease_lost_total,
        )
    }

    pub(crate) fn s2s_online_queue_telemetry(
        &self,
    ) -> northstar_federation_application::telemetry::OnlineQueueAcceptanceTelemetry<'_> {
        northstar_federation_application::telemetry::OnlineQueueAcceptanceTelemetry::new(
            &self.metrics.online_queue_durable_acceptances_total,
            &self.metrics.online_queue_volatile_acceptances_total,
        )
    }

    pub(crate) fn s2s_outbox_delivery_telemetry(
        &self,
    ) -> northstar_federation_application::telemetry::OutboxDeliveryTelemetry<'_> {
        northstar_federation_application::telemetry::OutboxDeliveryTelemetry::new(
            &self.metrics.outbox_delivery_duration_seconds,
        )
    }

    pub(crate) fn s2s_inbound_connection_telemetry(
        &self,
    ) -> northstar_federation_application::telemetry::InboundConnectionTelemetry<'_> {
        northstar_federation_application::telemetry::InboundConnectionTelemetry::new(
            &self.metrics.federation_inbound_connections_total,
            &self.metrics.federation_inbound_active,
        )
    }

    pub(crate) fn s2s_inbound_delivery_telemetry(
        &self,
    ) -> northstar_federation_application::telemetry::InboundDeliveryTelemetry<'_> {
        northstar_federation_application::telemetry::InboundDeliveryTelemetry::new(
            &self.metrics.post_accept_side_effect_failures_total,
            &self.metrics.messages_routed_total,
        )
    }

    pub(crate) fn s2s_outbound_disposition_telemetry(
        &self,
    ) -> northstar_federation_application::telemetry::OutboundDispositionTelemetry<'_> {
        northstar_federation_application::telemetry::OutboundDispositionTelemetry::new(
            &self.metrics.federation_failures_total,
            &self.metrics.s2s_outbox_lease_lost_total,
            &self.metrics.federation_outbound_deliveries_total,
            &self.metrics.s2s_outbox_permanent_failures_total,
            &self.metrics.s2s_outbox_expired_total,
            &self.metrics.s2s_outbox_retries_total,
        )
    }
}
