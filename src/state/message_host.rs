//! The node's capabilities as the message handlers see them.

use super::*;
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

impl MessageHost for AppState {
    type Messages = PostgresMessageRepository;
    type Admissions = AbuseMessageAdmissionPort;
    type Retractions = PostgresRetractionRepository;

    fn message_service(&self) -> &MessageService<PostgresMessageRepository> {
        AppState::message_service(self)
    }

    fn message_admission_service(&self) -> &MessageAdmissionService<AbuseMessageAdmissionPort> {
        AppState::message_admission_service(self)
    }

    fn retraction_service(&self) -> &RetractionService<PostgresRetractionRepository> {
        AppState::retraction_service(self)
    }

    fn personal_message_telemetry(&self) -> PersonalMessageTelemetry<'_> {
        AppState::personal_message_telemetry(self)
    }

    fn validate_routed_message(&self, root: roxmltree::Node<'_, '_>) -> Result<(), &'static str> {
        AppState::validate_routed_message(self, root)
    }

    fn local_domain(&self) -> &str {
        AppState::local_domain(self)
    }

    fn archive_requires_encryption(&self) -> bool {
        AppState::archive_requires_encryption(self)
    }

    fn offline_delivery_limits(&self) -> OfflineDeliveryLimits {
        AppState::offline_delivery_limits(self)
    }

    fn xmpp_external_route_domain_allowed(&self, domain: &str) -> bool {
        AppState::xmpp_external_route_domain_allowed(self, domain)
    }

    fn federation_outbox_policy(&self) -> S2sOutboxPolicy {
        self.federation_outbox().outbox_policy()
    }

    fn wake_federation_outbox(&self) {
        self.federation_outbox().wake_outbox();
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
        self.cluster()
            .personal_message_remote_resource_exists(jid)
            .await
    }

    async fn dispatch_push_notification(&self, recipient_id: uuid::Uuid) -> Result<()> {
        AppState::dispatch_push_notification(self, recipient_id).await
    }

    async fn direct_invite_room(&self, localpart: &str) -> Result<Option<DirectInviteRoom>> {
        Ok(self
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
        self.muc_service()
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
        self.cluster().direct_muc_invite_cluster_authority(
            operation_id,
            room_epoch,
            config_version,
            actor_user_id,
            actor_full_jid,
            subject,
        )
    }

    async fn wake_committed_direct_muc_invite(&self, operation_id: uuid::Uuid) -> Result<()> {
        AppState::wake_committed_direct_muc_invite(self, operation_id).await
    }
}

impl ExtDiscoHost for AppState {
    fn extdisco_service(&self) -> &northstar_message_application::extdisco::ExtDiscoService {
        AppState::extdisco_service(self)
    }
}

impl FederatedMessageHost for AppState {
    fn session_entries_for(&self, jid: &str) -> Vec<(String, OnlineSession)> {
        AppState::session_entries_for(self, jid)
    }

    async fn s2s_remote_recipient_route_exists(&self, jid: &str) -> bool {
        self.cluster().s2s_remote_recipient_route_exists(jid).await
    }

    async fn handle_push_disable(&self, root: Node<'_, '_>, from: &str, to: &str) -> Result<bool> {
        northstar_stream::protocol::misc::handle_push_disable(self, root, from, to).await
    }

    fn record_s2s_post_accept_failure(&self) {
        self.s2s_inbound_delivery_telemetry().post_accept_failed();
    }

    fn record_s2s_message_routed(&self) {
        self.s2s_inbound_delivery_telemetry().routed();
    }

    fn record_s2s_online_accept(&self, durable: bool) {
        self.s2s_online_queue_telemetry().accepted(durable);
    }

    async fn route_s2s_message_to_available_remote_resources(
        &self,
        jid: &str,
        stanza: &str,
        delivery: Option<DurableDelivery>,
    ) -> bool {
        self.cluster()
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
            .cluster()
            .route_s2s_message_to_remote_primary(
                jid,
                stanza,
                delivery,
                &self.personal_message_telemetry(),
            )
            .await;
        OnlineRouteResult {
            delivered: routed.delivered,
            accepted_full_jid: routed.accepted_full_jid,
        }
    }
}
