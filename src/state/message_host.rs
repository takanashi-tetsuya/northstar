//! The node's capabilities as the message handlers see them.

use super::*;
use anyhow::Result;
use northstar_federation_core::S2sOutboxPolicy;
use northstar_message_application::message_admission::MessageAdmissionService;
use northstar_message_application::messaging::MessageService;
use northstar_message_application::retractions::RetractionService;
use northstar_message_application::telemetry::PersonalMessageTelemetry;
use northstar_message_core::OfflineDeliveryLimits;
use northstar_message_xmpp::ports::{DirectInviteRoom, MessageHost};
use northstar_room_core::{ClusterMucAffiliationSubject, ClusterMucInviteAuthority};
use northstar_session_application::RemoteRoutePort;
use northstar_workflows::message_admission_port::AbuseMessageAdmissionPort;
use northstar_workflows::message_repository::PostgresMessageRepository;
use northstar_workflows::retraction_repository::PostgresRetractionRepository;

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
        AppState::personal_message_remote_resource_exists(self, jid).await
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
        AppState::direct_muc_invite_cluster_authority(
            self,
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
