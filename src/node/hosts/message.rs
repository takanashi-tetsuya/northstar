//! The node's capabilities as the message handlers see them.

use crate::node::*;
use anyhow::Result;
use northstar_federation_core::S2sOutboxPolicy;
use northstar_message_application::message_admission::MessageAdmissionService;
use northstar_message_application::messaging::{MessageService, OnlineRouteResult};
use northstar_message_application::retractions::RetractionService;
use northstar_message_application::telemetry::PersonalMessageTelemetry;
use northstar_message_core::OfflineDeliveryLimits;
use northstar_message_xmpp::extdisco::ExtDiscoHost;
use northstar_message_xmpp::ports::{DirectInviteRoom, FederatedMessageHost, MessageHost};
use northstar_room_core::{ClusterMucAffiliationSubject, ClusterMucInviteAuthority};
use northstar_session_application::RemoteRoutePort;
use northstar_stream::local_routes::session::OnlineSession;
use northstar_stream::outbound::DurableDelivery;
use northstar_workflows::message_admission_port::AbuseMessageAdmissionPort;
use northstar_workflows::message_repository::PostgresMessageRepository;
use northstar_workflows::retraction_repository::PostgresRetractionRepository;
use roxmltree::Node;

impl MessageHost for ServerNode {
    type Messages = PostgresMessageRepository;
    type Admissions = AbuseMessageAdmissionPort;
    type Retractions = PostgresRetractionRepository;

    fn message_service(&self) -> &MessageService<PostgresMessageRepository> {
        self.message.message_service()
    }

    fn message_admission_service(&self) -> &MessageAdmissionService<AbuseMessageAdmissionPort> {
        self.message.message_admission_service()
    }

    fn retraction_service(&self) -> &RetractionService<PostgresRetractionRepository> {
        self.message.retraction_service()
    }

    fn personal_message_telemetry(&self) -> PersonalMessageTelemetry<'_> {
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

    fn validate_routed_message(&self, root: roxmltree::Node<'_, '_>) -> Result<(), &'static str> {
        northstar_message_core::validation::validate_routed_message(
            root,
            &self.config.xmpp_extensions,
        )
    }

    fn local_domain(&self) -> &str {
        &self.config.domain
    }

    fn archive_requires_encryption(&self) -> bool {
        self.config.require_encrypted_archive
    }

    fn offline_delivery_limits(&self) -> OfflineDeliveryLimits {
        northstar_message_core::OfflineDeliveryLimits {
            max_messages: self.config.offline_max_messages_per_account,
            max_bytes: self.config.offline_max_bytes_per_account,
            ttl_days: self.config.offline_message_ttl_days,
        }
    }

    fn xmpp_external_route_domain_allowed(&self, domain: &str) -> bool {
        self.config.external_route_domain_allowed(domain)
    }

    fn federation_outbox_policy(&self) -> S2sOutboxPolicy {
        self.federation.federation_outbox.outbox_policy()
    }

    fn wake_federation_outbox(&self) {
        self.federation.federation_outbox.wake_outbox();
    }

    async fn send_volatile(
        &self,
        source_domain: &str,
        target_domain: &str,
        stanza: String,
    ) -> bool {
        RemoteRoutePort::send_volatile(self, source_domain, target_domain, stanza).await
    }

    async fn personal_message_remote_resource_exists(&self, jid: &str) -> bool {
        self.cluster
            .personal_message_remote_resource_exists(jid)
            .await
    }

    async fn dispatch_push_notification(&self, recipient_id: uuid::Uuid) -> Result<()> {
        ServerNode::dispatch_push_notification(self, recipient_id).await
    }

    async fn direct_invite_room(&self, localpart: &str) -> Result<Option<DirectInviteRoom>> {
        Ok(self
            .room
            .muc_service()
            .room(localpart)
            .await?
            .map(|room| DirectInviteRoom {
                id: room.id,
                members_only: room.members_only,
                room_epoch: room.room_epoch,
                config_version: room.config_version,
            }))
    }

    async fn direct_invite_affiliation(
        &self,
        room_id: uuid::Uuid,
        account_id: uuid::Uuid,
    ) -> Result<Option<String>> {
        self.room
            .muc_service()
            .local_affiliation(room_id, account_id)
            .await
    }

    fn direct_muc_invite_cluster_authority(
        &self,
        operation_id: uuid::Uuid,
        room_epoch: uuid::Uuid,
        config_version: i64,
        actor_user_id: uuid::Uuid,
        actor_full_jid: &str,
        subject: ClusterMucAffiliationSubject,
    ) -> Result<Option<ClusterMucInviteAuthority>> {
        self.cluster.direct_muc_invite_cluster_authority(
            operation_id,
            room_epoch,
            config_version,
            actor_user_id,
            actor_full_jid,
            subject,
        )
    }

    async fn wake_committed_direct_muc_invite(&self, operation_id: uuid::Uuid) -> Result<()> {
        ServerNode::wake_committed_direct_muc_invite(self, operation_id).await
    }
}

impl ExtDiscoHost for ServerNode {
    fn extdisco_service(&self) -> &northstar_message_application::extdisco::ExtDiscoService {
        self.message.extdisco_service()
    }
}

impl FederatedMessageHost for ServerNode {
    fn session_entries_for(&self, jid: &str) -> Vec<(String, OnlineSession)> {
        self.sessions.session_entries_for(jid)
    }

    async fn s2s_remote_recipient_route_exists(&self, jid: &str) -> bool {
        self.cluster.s2s_remote_recipient_route_exists(jid).await
    }

    async fn handle_push_disable(&self, root: Node<'_, '_>, from: &str, to: &str) -> Result<bool> {
        northstar_stream::protocol::misc::handle_push_disable(self, root, from, to).await
    }

    fn record_s2s_post_accept_failure(&self) {
        northstar_federation_application::telemetry::InboundDeliveryTelemetry::new(
            &self.metrics.post_accept_side_effect_failures_total,
            &self.metrics.messages_routed_total,
        )
        .post_accept_failed();
    }

    fn record_s2s_message_routed(&self) {
        northstar_federation_application::telemetry::InboundDeliveryTelemetry::new(
            &self.metrics.post_accept_side_effect_failures_total,
            &self.metrics.messages_routed_total,
        )
        .routed();
    }

    fn record_s2s_online_accept(&self, durable: bool) {
        northstar_federation_application::telemetry::OnlineQueueAcceptanceTelemetry::new(
            &self.metrics.online_queue_durable_acceptances_total,
            &self.metrics.online_queue_volatile_acceptances_total,
        )
        .accepted(durable);
    }

    async fn route_s2s_message_to_available_remote_resources(
        &self,
        jid: &str,
        stanza: &str,
        delivery: Option<DurableDelivery>,
    ) -> bool {
        self.cluster
            .route_s2s_message_to_available_remote_resources(jid, stanza, delivery)
            .await
    }

    async fn route_s2s_message_to_remote_primary(
        &self,
        jid: &str,
        stanza: &str,
        delivery: Option<DurableDelivery>,
    ) -> OnlineRouteResult {
        let routed = self
            .cluster
            .route_s2s_message_to_remote_primary(
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
            .await;
        OnlineRouteResult {
            delivered: routed.delivered,
            accepted_full_jid: routed.accepted_full_jid,
        }
    }
}
