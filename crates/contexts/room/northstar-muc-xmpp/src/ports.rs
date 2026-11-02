//! What the MUC adapter needs from live sessions, routing and federation.
//!
//! The composition root implements these until the session, cluster, message
//! and federation contexts own those capabilities. Every handler stays generic
//! over them, so this crate names no transport, session or cluster type.

use anyhow::Result;
use dashmap::DashMap;
use northstar_archive_core::{
    FederatedMamAdmissionOutcome, FederatedMamMetadataCommand, FederatedMamStreamPage,
    FederatedMamStreamRequest, MamMetadataResult, MamRoomAccessOutcome,
};
use northstar_delivery_core::{node_delivery::NodeDeliveryReceipt, DurableDelivery};
use northstar_federation_core::S2sOutboxPolicy;
use northstar_message_core::{DirectPostCommitMode, OfflineDeliveryLimits};
use northstar_room_application::discussion;
use northstar_room_application::mix_service::{MixRepository, MixService};
use northstar_room_application::muc_service::{MucRepository, MucService};
use northstar_room_core::occupancy::{
    FederatedMucAccountRoute, LocalMucJoinPublication, LocalMucNicknameMove,
    LocalMucOccupantIdentity, MucJoinCacheAttempt, MucOccupant, MucPresencePublication, MucRename,
    MucRoleChange, SerializableMucOccupant,
};
use northstar_session_core::JoinedMucMembership;
use northstar_stream::local_routes::session::OnlineSession;
use northstar_stream::outbound::OutboundSender;
use northstar_stream::transport::Action;
use std::{collections::HashMap, future::Future};
use tokio::sync::mpsc::error::TrySendError;
use uuid::Uuid;

/// What one MUC stanza asks the session to write.
#[derive(Debug)]
pub enum MucAction {
    Send(String),
    SendMany(Vec<String>),
    None,
}

impl From<MucAction> for Action {
    fn from(action: MucAction) -> Self {
        match action {
            MucAction::Send(stanza) => Action::Send(stanza),
            MucAction::SendMany(stanzas) => Action::SendMany(stanzas),
            MucAction::None => Action::None,
        }
    }
}

/// The stages of a frame execution that MUC reports.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MucFrameStage {
    Policy,
    GateWait,
    Authority,
    Admission,
    ClusterFanout,
    LocalFanout,
}

/// The ordered output queue of one local stream.
pub trait MucOutbound: Clone + Send + Sync + 'static {
    fn try_send(&self, stanza: String) -> Result<(), TrySendError<String>>;

    fn try_send_durable(
        &self,
        stanza: String,
        delivery: DurableDelivery,
    ) -> Result<(), TrySendError<String>>;
}

/// One live local route.
pub trait MucLocalSession: Send + Sync + 'static {
    type Outbound: MucOutbound;

    fn sender(&self) -> &Self::Outbound;
    fn priority(&self) -> i16;
    fn is_available(&self) -> bool;
}

/// The occupant record of one host.
pub type Occupant<H> = MucOccupant<<H as MucHost>::Outbound, <H as MucHost>::SuspendedEndpoint>;

/// The node's view for the MUC handlers.
pub trait MucHost: Send + Sync + 'static {
    type Repository: MucRepository + 'static;
    type MixRepository: MixRepository + 'static;
    type Outbound: MucOutbound;
    type SuspendedEndpoint: Send + Sync + 'static;
    type Session: MucLocalSession<Outbound = Self::Outbound>;

    fn muc_service(&self) -> &MucService<Self::Repository>;
    fn mix_service(&self) -> &MixService<Self::MixRepository>;
    fn session_entries_for(&self, jid: &str) -> Vec<(String, Self::Session)>;

    fn message_direct_mode(&self) -> DirectPostCommitMode;
    fn rearm_unrouted_live_direct(
        &self,
        recipient_id: Uuid,
        message_id: Uuid,
        claim_id: &mut Option<Uuid>,
    ) -> impl Future<Output = ()> + Send;
    fn send_received_carbons(
        &self,
        recipient: &str,
        delivered: Option<&str>,
        forwarded: &str,
    ) -> impl Future<Output = ()> + Send;

    fn federation_outbox_policy(&self) -> S2sOutboxPolicy;

    /// Call only after a caller-owned outbox transaction commits.
    fn wake_federation_outbox(&self);

    fn send_federated(
        &self,
        target_domain: &str,
        stanza: String,
        bounce_to: Option<String>,
    ) -> impl Future<Output = bool> + Send;

    fn authorize_federated_room(
        &self,
        localpart: &str,
        viewer_bare_jid: &str,
        currently_joined: bool,
    ) -> impl Future<Output = Result<MamRoomAccessOutcome>> + Send;
    fn execute_federated_mam_metadata(
        &self,
        command: FederatedMamMetadataCommand,
    ) -> impl Future<Output = Result<MamMetadataResult>> + Send;
    fn admit_federated_room_stream<F>(
        &self,
        request: FederatedMamStreamRequest<'_>,
        render: F,
    ) -> impl Future<Output = Result<FederatedMamAdmissionOutcome>> + Send
    where
        F: FnOnce(&FederatedMamStreamPage) -> Result<Vec<String>> + Send;

    fn admit_muc_pg_mutation(&self) -> Result<()>;
    fn archive_requires_encryption(&self) -> bool;
    fn blocked_muc_recipient_accounts(
        &self,
        occupants: &[Occupant<Self>],
        stanza_senders: &[String],
    ) -> impl Future<Output = std::collections::HashSet<String>> + Send;
    fn cache_committed_muc_join(
        &self,
        occupant: &SerializableMucOccupant,
        capacity: usize,
    ) -> impl Future<Output = Result<MucJoinCacheAttempt>> + Send;
    fn cached_muc_cluster_occupants(
        &self,
        room: &str,
    ) -> impl Future<Output = Result<HashMap<String, String>>> + Send;
    fn change_cluster_muc_affiliation_exact(
        &self,
        room: &str,
        occupant: &SerializableMucOccupant,
        affiliation: &str,
        role: &str,
    ) -> impl Future<Output = Result<MucRoleChange>> + Send;
    fn change_cluster_muc_role_exact(
        &self,
        room: &str,
        occupant: &SerializableMucOccupant,
        role: &str,
    ) -> impl Future<Output = Result<MucRoleChange>> + Send;
    fn deliver_muc_primary_to_remote_node(
        &self,
        target: &str,
        stanza: &str,
        durable: Option<DurableDelivery>,
    ) -> impl Future<Output = Option<NodeDeliveryReceipt>> + Send;
    fn deliver_to_muc_occupant(
        &self,
        occupant: &Occupant<Self>,
        stanza: String,
    ) -> impl Future<Output = bool> + Send;
    fn deliver_to_muc_occupant_unchecked(
        &self,
        occupant: &Occupant<Self>,
        stanza: String,
    ) -> impl Future<Output = bool> + Send;
    fn dispatch_push_notification(
        &self,
        recipient_id: uuid::Uuid,
    ) -> impl Future<Output = Result<()>> + Send;
    fn evict_cluster_muc_occupant(
        &self,
        occupant: &SerializableMucOccupant,
        status: u16,
        actor_nick: Option<&str>,
        reason: Option<&str>,
    ) -> impl Future<Output = Result<()>> + Send;
    fn federated_muc_admit_mutation(&self) -> Result<()>;
    fn federated_muc_change_occupant_affiliation(
        &self,
        room_jid: &str,
        occupant: &SerializableMucOccupant,
        affiliation: &str,
        role: &str,
    ) -> impl Future<Output = Result<MucRoleChange>> + Send;
    fn federated_muc_change_occupant_policy(
        &self,
        room_jid: &str,
        occupant: &SerializableMucOccupant,
        role: &str,
        room_non_anonymous: bool,
    ) -> impl Future<Output = Result<MucRoleChange>> + Send;
    fn federated_muc_change_occupant_role(
        &self,
        room_jid: &str,
        occupant: &SerializableMucOccupant,
        role: &str,
    ) -> impl Future<Output = Result<MucRoleChange>> + Send;
    fn federated_muc_evict_occupant(
        &self,
        occupant: &SerializableMucOccupant,
        status: u16,
        actor_nick: Option<&str>,
        reason: Option<&str>,
    ) -> impl Future<Output = Result<bool>> + Send;
    fn federated_muc_global_occupants(
        &self,
        room_jid: &str,
    ) -> impl Future<Output = Result<HashMap<String, String>>> + Send;
    fn federated_muc_join_room(&self, room_jid: &str) -> impl Future<Output = Result<()>> + Send;
    fn federated_muc_leave_room(&self, room_jid: &str) -> impl Future<Output = Result<()>> + Send;
    fn federated_muc_occupants_for_closed_connection(
        &self,
        authenticated_domain: &str,
        connection_id: uuid::Uuid,
    ) -> Vec<Occupant<Self>>;
    fn federated_muc_owner_node_id(&self) -> &str;
    fn federated_muc_pg_authority_enabled(&self) -> bool;
    fn federated_muc_publish_nickname_change(
        &self,
        room_jid: &str,
        old_occupant: &SerializableMucOccupant,
        new_occupant: &SerializableMucOccupant,
        id: Option<&str>,
    ) -> impl Future<Output = Result<()>> + Send;
    fn federated_muc_publish_presence(
        &self,
        room_jid: &str,
        occupant: &SerializableMucOccupant,
        unavailable: bool,
        created: bool,
        id: Option<&str>,
    ) -> impl Future<Output = Result<()>> + Send;
    fn federated_muc_publish_private_message(
        &self,
        room_jid: &str,
        target_nick: &str,
        stanza: &str,
        real_sender: &str,
    ) -> impl Future<Output = Result<()>> + Send;
    fn federated_muc_publish_removal_presence(
        &self,
        room_jid: &str,
        occupant: &SerializableMucOccupant,
        status: Option<u16>,
        actor_nick: Option<&str>,
        reason: Option<&str>,
    ) -> impl Future<Output = Result<()>> + Send;
    fn federated_muc_publish_room_message(
        &self,
        room_jid: &str,
        stanza: &str,
        real_sender: Option<&str>,
    ) -> impl Future<Output = Result<()>> + Send;
    fn federated_muc_redis_transport_enabled(&self) -> bool;
    fn federated_muc_register_occupant(
        &self,
        room_jid: &str,
        nick: &str,
        json: &str,
    ) -> impl Future<Output = Result<bool>> + Send;
    fn federated_muc_rename_occupant(
        &self,
        room_jid: &str,
        old_nick: &str,
        new_nick: &str,
        expected_epoch: uuid::Uuid,
        old_json: &str,
        new_json: &str,
    ) -> impl Future<Output = Result<MucRename>> + Send;
    fn federated_muc_telemetry(&self) -> northstar_room_core::telemetry::FederatedMucTelemetry<'_>;
    fn join_cluster_muc_room(&self, room: &str) -> impl Future<Output = Result<()>> + Send;
    fn leave_cluster_muc_room(&self, room: &str) -> impl Future<Output = Result<()>> + Send;
    fn local_domain(&self) -> &str;
    fn local_muc_occupant_by_nick(&self, room_jid: &str, nick: &str) -> Option<Occupant<Self>>;
    fn local_muc_occupant_exact(
        &self,
        identity: LocalMucOccupantIdentity<'_>,
    ) -> Option<Occupant<Self>>;
    fn mix_muc_mirror_enabled(&self) -> bool;
    fn move_local_muc_nickname_exact(
        &self,
        old: LocalMucOccupantIdentity<'_>,
        renamed: &Occupant<Self>,
        cluster_committed: bool,
    ) -> LocalMucNicknameMove;
    fn muc_cluster_node_id(&self) -> &str;
    fn muc_mam_retention_days(&self) -> i64;
    fn muc_occupants_for(&self, room_jid: &str) -> Vec<(String, Occupant<Self>)>;
    fn muc_pg_authority_enabled(&self) -> bool;
    fn muc_redis_transport_enabled(&self) -> bool;
    fn muc_telemetry(&self) -> northstar_room_core::telemetry::MucTelemetry<'_>;
    fn offline_delivery_limits(&self) -> OfflineDeliveryLimits;
    fn publish_local_muc_join_if_vacant(&self, joining: &Occupant<Self>)
        -> LocalMucJoinPublication;
    fn publish_muc_cluster_nickname_change(
        &self,
        room: &str,
        before: &SerializableMucOccupant,
        after: &SerializableMucOccupant,
        id: Option<&str>,
    ) -> impl Future<Output = Result<()>> + Send;
    fn publish_muc_cluster_presence(
        &self,
        publication: MucPresencePublication<'_>,
    ) -> impl Future<Output = Result<()>> + Send;
    fn publish_muc_cluster_presence_with_id(
        &self,
        room: &str,
        occupant: &SerializableMucOccupant,
        unavailable: bool,
        created: bool,
        id: Option<&str>,
    ) -> impl Future<Output = Result<()>> + Send;
    fn publish_muc_cluster_private_message(
        &self,
        room: &str,
        nick: &str,
        stanza: &str,
        real_sender: &str,
    ) -> impl Future<Output = Result<()>> + Send;
    fn publish_muc_cluster_stanza(
        &self,
        room: &str,
        stanza: &str,
        real_sender: Option<&str>,
    ) -> impl Future<Output = Result<()>> + Send;
    fn rebind_local_federated_muc_occupant_exact(
        &self,
        old: &Occupant<Self>,
        new_connection_id: uuid::Uuid,
    ) -> Option<Occupant<Self>>;
    fn record_muc_cluster_control_plane_failure(&self, error: &anyhow::Error);
    fn refresh_local_muc_policy_exact(
        &self,
        identity: LocalMucOccupantIdentity<'_>,
        moderated: Option<bool>,
        non_anonymous: Option<bool>,
    ) -> Option<(Occupant<Self>, bool)>;
    fn refresh_local_muc_presence_exact(
        &self,
        prepared: &Occupant<Self>,
        apply_policy: bool,
    ) -> Option<Occupant<Self>>;
    fn register_cluster_muc_occupant(
        &self,
        room: &str,
        nick: &str,
        json: &str,
    ) -> impl Future<Output = Result<bool>> + Send;
    fn remove_exact_muc_soft_state(
        &self,
        occupant: &Occupant<Self>,
    ) -> impl Future<Output = Result<bool>> + Send;
    fn remove_live_muc_membership(&self, occupant: &SerializableMucOccupant) -> bool;
    fn remove_local_muc_occupant_exact(
        &self,
        identity: LocalMucOccupantIdentity<'_>,
    ) -> Option<Occupant<Self>>;
    fn rename_cluster_muc_occupant_exact(
        &self,
        room: &str,
        old_nick: &str,
        new_nick: &str,
        expected_epoch: uuid::Uuid,
        old_json: &str,
        new_json: &str,
    ) -> impl Future<Output = Result<MucRename>> + Send;
    fn revoke_cluster_muc_occupant_exact(
        &self,
        occupant: &SerializableMucOccupant,
        status: u16,
        actor_nick: Option<&str>,
        reason: Option<&str>,
    ) -> impl Future<Output = Result<bool>> + Send;
    fn route_federated_muc_account_message_remote(
        &self,
        target_jid: &str,
        stanza: &str,
        delivery: Option<DurableDelivery>,
    ) -> impl Future<Output = Option<FederatedMucAccountRoute>> + Send;
    fn server_name(&self) -> &str;
    fn set_local_muc_affiliation_exact(
        &self,
        identity: LocalMucOccupantIdentity<'_>,
        affiliation: &str,
        moderated: bool,
        only_if_none: bool,
        expected_affiliation: Option<&str>,
    ) -> Option<Occupant<Self>>;
    fn set_local_muc_role_exact(
        &self,
        identity: LocalMucOccupantIdentity<'_>,
        expected_role: &str,
        role: &str,
        non_anonymous: Option<bool>,
    ) -> Option<Occupant<Self>>;
    fn validate_routed_message(&self, root: roxmltree::Node<'_, '_>) -> Result<(), &'static str>;
    fn validated_local_muc_occupant(
        &self,
        full_jid: &str,
        connection_id: uuid::Uuid,
        room_jid: &str,
        membership: &JoinedMucMembership,
    ) -> Option<Occupant<Self>>;
    fn wake_committed_muc_operation(
        &self,
        operation_id: uuid::Uuid,
    ) -> impl Future<Output = anyhow::Result<()>> + Send;
    fn xmpp_extension_enabled(&self, id: northstar_xep_core::XepId) -> bool;
    fn xmpp_external_route_domain_allowed(&self, domain: &str) -> bool;
}

/// The account of an authenticated client stream.
#[derive(Clone, Copy, Debug)]
pub struct MucSessionUser<'a> {
    pub id: Uuid,
    pub username: &'a str,
}

/// One client session's view for the MUC stanza entry points.
pub trait MucSession: Send + Sync {
    type Host: MucHost;

    fn host(&self) -> &Self::Host;
    fn user(&self) -> Option<MucSessionUser<'_>>;
    fn full_jid(&self) -> Option<&str>;
    fn connection_id(&self) -> Uuid;
    fn sm_db_id(&self) -> Option<Uuid>;
    fn joined_rooms(&self) -> &DashMap<String, JoinedMucMembership>;
    fn outbound(&self) -> &<Self::Host as MucHost>::Outbound;
    fn enter_frame_stage(&self, stage: MucFrameStage);
    fn muc_discussion_operation(
        &self,
        prepared: &discussion::PreparedDiscussion,
    ) -> Result<Option<discussion::Observation>, discussion::Rejected>;
}

impl MucOutbound for OutboundSender {
    fn try_send(&self, stanza: String) -> Result<(), TrySendError<String>> {
        OutboundSender::try_send(self, stanza)
    }

    fn try_send_durable(
        &self,
        stanza: String,
        delivery: DurableDelivery,
    ) -> Result<(), TrySendError<String>> {
        OutboundSender::try_send_durable(self, stanza, delivery)
    }
}

impl MucLocalSession for OnlineSession {
    type Outbound = OutboundSender;

    fn sender(&self) -> &OutboundSender {
        &self.sender
    }

    fn priority(&self) -> i16 {
        self.priority.load(std::sync::atomic::Ordering::Relaxed)
    }

    fn is_available(&self) -> bool {
        self.available.load(std::sync::atomic::Ordering::Relaxed)
    }
}
