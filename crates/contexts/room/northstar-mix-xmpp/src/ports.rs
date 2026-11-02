//! What the MIX adapter needs from live sessions, routing and federation.
//!
//! The composition root implements these until the session and federation
//! contexts own those capabilities. Every handler stays generic over them, so
//! this crate names no transport, session or cluster type.

use anyhow::Result;
use chrono::{DateTime, Utc};
use dashmap::DashSet;
use northstar_delivery_core::{
    node_delivery::NodeDeliveryReceipt, MixDelivery, MixTransportCompletion,
};
use northstar_federation_core::FederationRoute;
use northstar_room_application::mix_service::{
    foreground, MixAccount, MixChannel, MixRepository, MixService, PamMembership, PresenceOutcome,
};
use northstar_room_core::mix::MixSessionCapability;
use northstar_room_core::mix_iq_relay::{MixIqRelayIndex, PendingMixIqRelay};
use northstar_roster_core::RosterChange;
use northstar_stream::local_routes::session::OnlineSession;
use northstar_stream::outbound::OutboundSender;
use northstar_xep_core::XepId;
use roxmltree::Node;
use std::{future::Future, sync::Arc, time::Instant};
use tokio::sync::{
    mpsc::{self, error::TrySendError},
    oneshot, Mutex,
};
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

/// What one MIX stanza asks the session to write.
#[derive(Debug)]
pub enum MixAction {
    Send(String),
    SendMany(Vec<String>),
    None,
}

/// The stages of a frame execution that MIX reports.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MixFrameStage {
    Policy,
    Admission,
}

pub trait MixFrameObserver: Sync {
    fn enter(&self, stage: MixFrameStage);

    /// Registers the foreground owner of the current frame; `Ok(None)` when
    /// no frame is current.
    #[allow(clippy::type_complexity)]
    fn mix_foreground(
        &self,
        prepare: Box<
            dyn FnOnce() -> Result<foreground::PreparedIngress, foreground::Rejected> + '_,
        >,
    ) -> Result<Option<foreground::Observation>, foreground::Rejected>;
}

/// The ordered output queue of one local stream.
pub trait MixOutbound: Clone + Send + Sync + 'static {
    fn try_send(&self, stanza: String) -> Result<(), TrySendError<String>>;

    fn try_send_with_transport_receipt(
        &self,
        stanza: String,
        receipt: mpsc::UnboundedSender<()>,
    ) -> Result<(), TrySendError<String>>;

    /// Queues one leased MIX source. The receiver resolves at the actual
    /// transport boundary, never at queue admission.
    fn try_send_durable_mix(
        &self,
        stanza: String,
        delivery: MixDelivery,
    ) -> Result<oneshot::Receiver<MixTransportCompletion>, TrySendError<String>>;

    fn disconnect_backpressured_transport(&self);
}

/// One live local route.
pub trait MixLocalSession: Clone + Send + Sync + 'static {
    type Outbound: MixOutbound;

    fn sender(&self) -> &Self::Outbound;
    fn disconnect(&self) -> &CancellationToken;
    fn user_id(&self) -> Uuid;
    fn is_available(&self) -> bool;
}

/// Delivery of one relayed MIX IQ response to a local or federated JID.
pub trait MixIqRelayRoutePort: Send + Sync + 'static {
    fn deliver(&self, recipient: &str, stanza: String) -> impl Future<Output = ()> + Send;
}

/// The MIX IQ timeout worker's view of the correlation index.
pub trait MixIqRelayExpiryPort: Send + Sync + 'static {
    type Route: MixIqRelayRoutePort;

    fn take_expired(&self, now: Instant) -> Vec<PendingMixIqRelay>;
    fn route(&self) -> &Self::Route;
}

/// The durable MIX delivery lanes' view of routing.
pub trait MixOutboxPort: Send + Sync + 'static {
    type Repository: MixRepository + 'static;
    type Session: MixLocalSession;
    type Federation: FederationRoute;

    fn service(&self) -> &MixService<Self::Repository>;
    fn local_domain(&self) -> &str;
    fn federation_domain_allowed(&self, domain: &str) -> bool;
    fn federation_outbox(&self) -> &Self::Federation;
    fn session_entries_for(&self, jid: &str) -> Vec<(String, Self::Session)>;
    fn session_mix_capability(&self, full_jid: &str) -> MixSessionCapability;
    fn lookup_nodes(&self, jid: &str) -> impl Future<Output = Result<Vec<String>>> + Send;
    fn outbox_lookup_cluster_nodes(
        &self,
        jid: &str,
    ) -> impl Future<Output = Result<Vec<String>>> + Send;
    fn send_cluster_mix(
        &self,
        node_id: &str,
        recipient: &str,
        stanza: &str,
        source: Option<MixDelivery>,
    ) -> impl Future<Output = Result<NodeDeliveryReceipt>> + Send;
    fn send_cluster_pam_result(
        &self,
        node_id: &str,
        target_full_jid: &str,
        stanza: &str,
        expected_user_id: Uuid,
    ) -> impl Future<Output = Result<bool>> + Send;
    fn record_post_commit_failure(&self);
}

/// Live-route fences read by MIX presence recovery.
pub trait MixPresenceRoutes: Send + Sync + 'static {
    fn local_epochs(&self, participant: &str) -> Vec<(String, Uuid, u64)>;
    fn gate(&self, full_jid: &str, connection_id: Uuid) -> Option<Arc<Mutex<()>>>;
    fn epoch_state(
        &self,
        full_jid: &str,
        expected_connection_id: Uuid,
        expected_caps_generation: u64,
        expected_gate: &Arc<Mutex<()>>,
        channel_jid: &str,
    ) -> Option<(bool, bool)>;
}

/// The effects MIX presence recovery may apply.
pub trait MixPresenceRecoveryPort: Send + Sync + 'static {
    type Routes: MixPresenceRoutes;

    fn routes(&self) -> &Self::Routes;
    fn local_domain(&self) -> &str;
    fn local_mix_domain(&self) -> String;
    fn federation_domain_allowed(&self, domain: &str) -> bool;
    fn send_federated(
        &self,
        domain: &str,
        stanza: String,
        source: Option<String>,
    ) -> impl Future<Output = ()> + Send;
    fn find_enabled_user(
        &self,
        username: &str,
    ) -> impl Future<Output = Result<Option<MixAccount>>> + Send;
    fn wake_delivery_recipient(&self, bare_jid: &str) -> impl Future<Output = Result<()>> + Send;
    fn pam_memberships(
        &self,
        user_id: Uuid,
    ) -> impl Future<Output = Result<Vec<PamMembership>>> + Send;
    fn mix_channel(
        &self,
        domain: &str,
        localpart: &str,
    ) -> impl Future<Output = Result<Option<MixChannel>>> + Send;
    fn ensure_presence(
        &self,
        channel_id: Uuid,
        actor_bare: &str,
        actor_full: &str,
    ) -> impl Future<Output = Result<PresenceOutcome>> + Send;
    fn expire_unrefreshed(
        &self,
        cutoff: DateTime<Utc>,
    ) -> impl Future<Output = Result<usize>> + Send;
}

/// Server-wide capabilities the MIX handlers use.
pub trait MixHost: Send + Sync + 'static {
    type Repository: MixRepository + 'static;
    type Session: MixLocalSession;
    type Federation: FederationRoute;
    type IqRelayRoute: MixIqRelayRoutePort;
    type OutboxContext: MixOutboxPort;

    fn mix_service(&self) -> &MixService<Self::Repository>;
    fn federation_outbox(&self) -> &Self::Federation;
    fn local_domain(&self) -> &str;
    fn server_name(&self) -> &str;
    fn pending_mix_iq(&self) -> &MixIqRelayIndex;
    fn federation_domain_allowed(&self, domain: &str) -> bool;
    fn mix_muc_mirror_enabled(&self) -> bool;
    fn xmpp_extension_enabled(&self, id: XepId) -> bool;
    fn session_entries_for(&self, jid: &str) -> Vec<(String, Self::Session)>;
    fn sessions_for(&self, jid: &str) -> Vec<Self::Session>;
    fn mix_iq_relay_route(&self) -> Self::IqRelayRoute;
    fn mix_outbox_context(&self) -> Self::OutboxContext;
    fn session_mix_capability(&self, full_jid: &str) -> MixSessionCapability;
    fn validate_routed_message(&self, root: Node<'_, '_>) -> Result<(), &'static str>;
    fn local_mix_presence_route_is_current(
        &self,
        full_jid: &str,
        expected_connection_id: Uuid,
        expected_gate: &Arc<Mutex<()>>,
        require_available: bool,
    ) -> bool;
    fn deliver_roster_change(
        &self,
        owner_id: Uuid,
        owner: &str,
        change: &RosterChange,
        participant_id: Option<&str>,
    ) -> impl Future<Output = Result<()>> + Send;
}

/// The authenticated account of a client session.
#[derive(Clone, Copy, Debug)]
pub struct MixSessionUser<'a> {
    pub id: Uuid,
    pub username: &'a str,
}

/// One client session's view for the MIX stanza entry points.
pub trait MixSession: Send + Sync {
    type Host: MixHost;

    fn host(&self) -> &Arc<Self::Host>;
    fn user(&self) -> Option<MixSessionUser<'_>>;
    fn full_jid(&self) -> Option<&str>;
    fn connection_id(&self) -> Uuid;
    fn mix_presence_gate(&self) -> &Arc<Mutex<()>>;
    fn mix_presence_fallback_suppressed(&self) -> &DashSet<String>;
    fn frame_observer(&self) -> &dyn MixFrameObserver;
}

impl MixOutbound for OutboundSender {
    fn try_send(&self, stanza: String) -> Result<(), TrySendError<String>> {
        OutboundSender::try_send(self, stanza)
    }

    fn try_send_with_transport_receipt(
        &self,
        stanza: String,
        receipt: mpsc::UnboundedSender<()>,
    ) -> Result<(), TrySendError<String>> {
        OutboundSender::try_send_with_transport_receipt(self, stanza, receipt)
    }

    fn try_send_durable_mix(
        &self,
        stanza: String,
        delivery: MixDelivery,
    ) -> Result<oneshot::Receiver<MixTransportCompletion>, TrySendError<String>> {
        OutboundSender::try_send_durable_mix(self, stanza, delivery)
    }

    fn disconnect_backpressured_transport(&self) {
        OutboundSender::disconnect_backpressured_transport(self);
    }
}

impl MixLocalSession for OnlineSession {
    type Outbound = OutboundSender;

    fn sender(&self) -> &OutboundSender {
        &self.sender
    }

    fn disconnect(&self) -> &CancellationToken {
        &self.disconnect
    }

    fn user_id(&self) -> Uuid {
        self.user_id
    }

    fn is_available(&self) -> bool {
        self.available.load(std::sync::atomic::Ordering::Relaxed)
    }
}
