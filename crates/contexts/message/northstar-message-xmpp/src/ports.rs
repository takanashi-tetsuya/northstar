//! What the message handlers ask of the client session and of the node around it.

use anyhow::Result;
use northstar_federation_core::S2sOutboxPolicy;
use northstar_message_application::message_admission::witness::DirectOperationHandle;
use northstar_message_application::message_admission::{
    MessageAdmissionRepository, MessageAdmissionService,
};
use northstar_message_application::message_carbons::CarbonDeliveryPort;
use northstar_message_application::messaging::{
    DirectMessageRoutePort, MessageRepository, MessageService,
};
use northstar_message_application::retractions::{RetractionRepository, RetractionService};
use northstar_message_application::telemetry::PersonalMessageTelemetry;
use northstar_message_core::OfflineDeliveryLimits;
use northstar_room_core::{ClusterMucAffiliationSubject, ClusterMucInviteAuthority};
use northstar_stream::transport::Action;
use roxmltree::Node;
use std::future::Future;
use std::net::IpAddr;
use uuid::Uuid;

/// The frame stages the message pipeline reports to the session's frame execution.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MessageFrameStage {
    Handler,
    Policy,
    Admission,
    Routing,
    Followup,
}

/// The session's answer to a stanza. MIX and MUC stanzas leave the pipeline with their own answer,
/// so the handler only ever builds these two forms and asks whether an answer is silent.
pub trait MessageOutcome: Send {
    fn none() -> Self;
    fn send(stanza: String) -> Self;
    fn is_none(&self) -> bool;
}

impl MessageOutcome for Action {
    fn none() -> Self {
        Action::None
    }

    fn send(stanza: String) -> Self {
        Action::Send(stanza)
    }

    fn is_none(&self) -> bool {
        matches!(self, Action::None)
    }
}

/// The facts of a local room that a direct invitation needs.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DirectInviteRoom {
    pub id: Uuid,
    pub members_only: bool,
    pub room_epoch: Uuid,
    pub config_version: i64,
}

/// The node as the message pipeline sees it.
pub trait MessageHost: DirectMessageRoutePort + CarbonDeliveryPort + Send + Sync + 'static {
    type Messages: MessageRepository;
    type Admissions: MessageAdmissionRepository;
    type Retractions: RetractionRepository;

    fn message_service(&self) -> &MessageService<Self::Messages>;
    fn message_admission_service(&self) -> &MessageAdmissionService<Self::Admissions>;
    fn retraction_service(&self) -> &RetractionService<Self::Retractions>;
    fn personal_message_telemetry(&self) -> PersonalMessageTelemetry<'_>;
    fn validate_routed_message(&self, root: Node<'_, '_>) -> Result<(), &'static str>;
    fn local_domain(&self) -> &str;
    fn archive_requires_encryption(&self) -> bool;
    fn offline_delivery_limits(&self) -> OfflineDeliveryLimits;
    fn xmpp_external_route_domain_allowed(&self, domain: &str) -> bool;
    fn federation_outbox_policy(&self) -> S2sOutboxPolicy;
    fn wake_federation_outbox(&self);
    /// Writes `stanza` on an authenticated writable route; never opens, stores or retries.
    fn send_volatile(
        &self,
        source_domain: &str,
        target_domain: &str,
        stanza: String,
    ) -> impl Future<Output = bool> + Send;
    fn personal_message_remote_resource_exists(
        &self,
        jid: &str,
    ) -> impl Future<Output = bool> + Send;
    fn dispatch_push_notification(
        &self,
        recipient_id: Uuid,
    ) -> impl Future<Output = Result<()>> + Send;
    fn direct_invite_room(
        &self,
        localpart: &str,
    ) -> impl Future<Output = Result<Option<DirectInviteRoom>>> + Send;
    fn direct_invite_affiliation(
        &self,
        room_id: Uuid,
        account_id: Uuid,
    ) -> impl Future<Output = Result<Option<String>>> + Send;
    fn direct_muc_invite_cluster_authority(
        &self,
        operation_id: Uuid,
        room_epoch: Uuid,
        config_version: i64,
        actor_user_id: Uuid,
        actor_full_jid: &str,
        subject: ClusterMucAffiliationSubject,
    ) -> Result<Option<ClusterMucInviteAuthority>>;
    fn wake_committed_direct_muc_invite(
        &self,
        operation_id: Uuid,
    ) -> impl Future<Output = Result<()>> + Send;
}

/// One client session as the message pipeline sees it.
pub trait MessageSession: Send + Sync {
    type Host: MessageHost;
    type Action: MessageOutcome;

    fn host(&self) -> &Self::Host;
    fn enter_frame_stage(&self, stage: MessageFrameStage);
    fn account_id(&self) -> Option<Uuid>;
    fn full_jid(&self) -> Option<&str>;
    fn peer_ip(&self) -> IpAddr;
    fn muc_domain(&self) -> String;
    fn upload_domain(&self) -> String;
    fn pubsub_domain(&self) -> String;
    fn message_operation(&self) -> Option<DirectOperationHandle>;
    fn active_privacy(&self) -> Option<String>;
    fn joined_room_nick(&self, room_jid: &str) -> Option<String>;
    /// True when the stanza was a PubSub authorization form and needs no further handling. A form
    /// dropped because mutation capacity is exhausted counts as handled.
    fn pubsub_authorization_response(
        &self,
        root: Node<'_, '_>,
    ) -> impl Future<Output = Result<bool>> + Send;
    fn push_disable_message(
        &self,
        root: Node<'_, '_>,
        from: &str,
        to: &str,
    ) -> impl Future<Output = Result<bool>> + Send;
    fn try_mix_message(
        &self,
        root: Node<'_, '_>,
        raw: &str,
    ) -> impl Future<Output = Result<Option<Self::Action>>> + Send;
    fn muc_message(
        &self,
        root: Node<'_, '_>,
        raw: &str,
    ) -> impl Future<Output = Result<Self::Action>> + Send;
}
