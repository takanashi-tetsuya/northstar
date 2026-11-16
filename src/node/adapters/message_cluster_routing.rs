//! Personal-message route ports over the local session table and the cluster routes.

use crate::node::{OnlineSession, ServerNode};
use anyhow::Result;
use northstar_message_application::messaging::{
    DirectMessageRoutePort, FullJidFallbackPort, OnlineRoutePort, OnlineRouteResult,
};
use northstar_roster_application::privacy::PrivacyStanzaKind;
use northstar_stream::outbound::DurableDelivery;
use std::sync::atomic::Ordering;
use uuid::Uuid;

impl OnlineRoutePort for ServerNode {
    type Item = northstar_stream::outbound::OutboundItem;
    type Session = OnlineSession;

    fn try_local(
        &self,
        session: &Self::Session,
        enqueue: northstar_stream::outbound::RouteEnqueue,
    ) -> Result<(), northstar_stream::outbound::RouteSendError> {
        session.sender.try_send_route_item(enqueue)
    }

    fn record_local_accept(&self, durable: bool) {
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
        .online_queue_result(true, durable);
    }

    async fn route_available_remote(
        &self,
        jid: &str,
        stanza: &str,
        delivery: Option<DurableDelivery>,
    ) -> bool {
        self.cluster
            .route_personal_message_to_available_remote_resources(jid, stanza, delivery)
            .await
    }

    async fn route_remote_primary(
        &self,
        jid: &str,
        stanza: &str,
        delivery: Option<DurableDelivery>,
    ) -> OnlineRouteResult {
        self.cluster
            .route_personal_message_to_remote_primary(
                jid,
                stanza,
                delivery,
                &northstar_message_application::telemetry::PersonalMessageTelemetry::new(
                    northstar_message_application::telemetry::PersonalMessageTelemetryCells {
                        routing_duration: &self.metrics.routing_duration_seconds,
                        rate_limited: &self.metrics.rate_limited_total,
                        abuse_backend_failures: &self.metrics.anti_abuse_backend_failures_total,
                        messages_routed: &self.metrics.messages_routed_total,
                        post_accept_failures: &self.metrics.post_accept_side_effect_failures_total,
                        durable_queue_acceptances: &self
                            .metrics
                            .online_queue_durable_acceptances_total,
                        volatile_queue_acceptances: &self
                            .metrics
                            .online_queue_volatile_acceptances_total,
                        carbon_delivery_failures: &self
                            .metrics
                            .carbon_post_accept_delivery_failures_total,
                        carbon_target_timeouts: &self.metrics.carbon_fanout_target_timeouts_total,
                        cluster_legacy_acceptances: &self
                            .metrics
                            .cluster_legacy_delivery_acceptances_total,
                    },
                ),
            )
            .await
    }
}

impl FullJidFallbackPort for ServerNode {
    fn fallback_sessions(&self, bare: &str) -> Vec<(String, Self::Session)> {
        self.sessions.session_entries_for(bare)
    }

    fn available_priority(&self, session: &Self::Session) -> Option<i16> {
        if !session.available.load(Ordering::Relaxed) {
            return None;
        }
        let priority = session.priority.load(Ordering::Relaxed);
        (priority >= 0).then_some(priority)
    }

    fn priority(&self, session: &Self::Session) -> i16 {
        session.priority.load(Ordering::Relaxed)
    }

    async fn privacy_allows_fallback(&self, session: &Self::Session, sender: &str) -> Result<bool> {
        self.privacy_allows_session(session, sender, PrivacyStanzaKind::Message)
            .await
    }

    fn post_accept_failed(&self) {
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
        .post_accept_failed();
    }
}

impl DirectMessageRoutePort for ServerNode {
    fn direct_route_mode(&self) -> crate::cluster::DirectPostCommitMode {
        self.message.message_service().direct_mode()
    }

    fn clustered_direct_routes(&self) -> bool {
        self.message
            .message_service()
            .clustered_direct_admission_enabled()
    }

    async fn rearm_direct_route(&self, delivery: DurableDelivery) {
        let mut claim_id = delivery.claim_id;
        self.message
            .message_service()
            .rearm_unrouted_live_direct(delivery.recipient_id, delivery.message_id, &mut claim_id)
            .await;
    }
}

/// An old cluster peer may acknowledge only with a delivered count. Accept a
/// positive receipt rather than risk duplicating a stanza in offline storage.
impl ServerNode {
    pub(crate) async fn wake_committed_direct_muc_invite(&self, operation_id: Uuid) -> Result<()> {
        self.room
            .muc_service()
            .wake_committed_operation(&self.cluster, operation_id)
            .await
    }
}
