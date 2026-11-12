//! What the node provides to the session side of the roster context.

use anyhow::Result;
use northstar_roster_application::blocking::{BlockingRepository, BlockingService};
use northstar_roster_application::{RosterRepository, RosterService, S2sOutboxPolicy};
use northstar_roster_core::{
    ClusterPresenceAuthority, LocalRosterContact, PresenceAccount, RosterChange,
};
use northstar_stream::local_routes::session::OnlineSession;
use northstar_stream::outbound::OutboundSender;
use northstar_stream::protocol::{ProtocolSession, SessionHost};
use northstar_stream::transport::Action;
use roxmltree::Node;
use std::future::Future;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use uuid::Uuid;

/// One post-commit delivery failure counter shared by roster, blocking and
/// privacy pushes. Each caller retains its own recovery/disconnect decision.
pub struct PostAcceptFailureTelemetry {
    failures: Arc<AtomicU64>,
}

impl PostAcceptFailureTelemetry {
    /// A handle on the node's post-accept side-effect failure counter.
    pub fn new(failures: Arc<AtomicU64>) -> Self {
        Self { failures }
    }

    /// Counts one post-commit delivery failure.
    pub fn record_failure(&self) {
        self.failures.fetch_add(1, Ordering::Relaxed);
    }
}

/// What the node provides to the roster, blocking and privacy handlers of a client session, beyond the session
/// core's host. The composition root implements it.
pub trait RosterSessionHost: Send + Sync {
    /// The roster service, over the repository the composition root binds.
    fn roster_service(&self) -> &RosterService<impl RosterRepository<Error = anyhow::Error>>;
    /// The blocking service, over the repository the composition root binds.
    fn blocking_service(&self) -> &BlockingService<impl BlockingRepository>;
    /// The post-accept side-effect failure counter.
    fn post_accept_failure_telemetry(&self) -> PostAcceptFailureTelemetry;
    /// The federation outbox admission policy of roster subscription traffic.
    fn roster_outbox_policy(&self) -> S2sOutboxPolicy;
    /// Wakes the federation outbox after a roster transition queued remote traffic.
    fn roster_wake_outbox(&self);
    /// Delivers a committed roster change to the owner's interested resources on every node.
    fn deliver_committed_roster_change(
        &self,
        owner_id: Uuid,
        owner: &str,
        change: &RosterChange,
        participant_id: Option<&str>,
    ) -> impl Future<Output = Result<()>> + Send;
    /// Delivers the presence of a subscription removal to the recipient's available resources on every node.
    fn deliver_roster_removal_presence(
        &self,
        owner: &PresenceAccount,
        recipient: &LocalRosterContact,
        target_bare: &str,
        stanza: &str,
    ) -> impl Future<Output = ()> + Send;
    /// Pushes a committed blocklist change to the owner's resources that requested the blocklist, on every node.
    fn push_blocklist_change(&self, owner: &str, payload: &str) -> impl Future<Output = ()> + Send;
    /// Delivers the polite-blocking presence transitions of a blocklist change, on every node.
    fn deliver_blocking_presence_change(
        &self,
        owner: &str,
        targets: &[String],
        changed_patterns: &[String],
        available: bool,
    ) -> impl Future<Output = ()> + Send;
    /// The number of local resources of `account`.
    fn local_resource_count(&self, account: &str) -> usize;
    /// Whether another cluster node holds a resource of `account`.
    fn account_has_remote_resources(
        &self,
        account: &str,
    ) -> impl Future<Output = Result<bool>> + Send;
    /// Whether a local resource of `account` has the privacy list `name` active.
    fn privacy_list_active_locally(&self, account: &str, name: &str) -> bool;
    /// Pushes a committed privacy list change to the account's resources that requested privacy lists, on every
    /// node. The push for the resource of connection `current_connection` is returned instead of queued.
    fn push_privacy_change(
        &self,
        account: &str,
        name: &str,
        base: &str,
        current_connection: Uuid,
    ) -> impl Future<Output = Option<String>> + Send;
    /// Whether `domain` is a configured external component's domain.
    fn presence_component_domain(&self, domain: &str) -> bool;
    /// Delivers directed presence from `from` to `to` on every node: the matching local sessions that the
    /// recipient's privacy lists allow, then the other cluster nodes. A bare target reaches only available
    /// resources. Returns whether any route took the stanza.
    fn deliver_directed_presence(
        &self,
        to: &str,
        canonical_to: &str,
        from: &str,
        stanza: &str,
        bare_target: bool,
    ) -> impl Future<Output = Result<bool>> + Send;
    /// Delivers subscription-related presence of `owner` to the available resources of `recipient` on every node.
    fn deliver_subscription_presence(
        &self,
        owner: &PresenceAccount,
        recipient: &PresenceAccount,
        owner_bare: &str,
        recipient_bare: &str,
        stanza: &str,
    ) -> impl Future<Output = Result<()>> + Send;
    /// Delivers a subscription approval to the available resources of `recipient` on every node, except the local
    /// resource `skip_full`.
    fn deliver_subscription_approval(
        &self,
        owner: &PresenceAccount,
        recipient: &PresenceAccount,
        owner_bare: &str,
        recipient_bare: &str,
        approved: &str,
        skip_full: Option<&str>,
    ) -> impl Future<Output = Result<()>> + Send;
    /// Delivers broadcast presence from `from` to the available resources of `contact` on every node.
    fn deliver_contact_presence(
        &self,
        contact: &str,
        from: &str,
        stanza: &str,
    ) -> impl Future<Output = Result<()>> + Send;
    /// Echoes broadcast presence to the resources of the sender's own account on every node.
    fn echo_account_presence(
        &self,
        account: &str,
        from: &str,
        stanza: &str,
    ) -> impl Future<Output = ()> + Send;
    /// Delivers directed unavailable presence to the local sessions of `target`.
    fn deliver_directed_unavailable(
        &self,
        target: &str,
        bare_target: bool,
        from: &str,
        stanza: &str,
    ) -> impl Future<Output = ()> + Send;
    /// Whether a local resource of `bare` is available.
    fn account_has_available_resource(&self, bare: &str) -> bool;
    /// Whether another cluster node owns an available resource of `bare` that a probe must ask.
    fn probe_has_remote_owner(&self, bare: &str) -> impl Future<Output = Result<bool>> + Send;
    /// Whether the local resource `owner_full` sent directed presence to `requester`.
    fn directed_presence_recipient(&self, owner_full: &str, requester: &str) -> bool;
    /// Answers an authorized full-JID presence probe from `requester`. Returns the stanza to send back to the
    /// requester's session, or `None` when nothing is to be sent there (privacy, or another node answers).
    fn answer_full_presence_probe(
        &self,
        owner_full: &str,
        owner_bare: &str,
        requester: &str,
        probe_id: Option<&str>,
    ) -> impl Future<Output = Result<Option<String>>> + Send;
    /// Sends the current presence of `owner` to the available resources of `recipient`, on every node.
    fn send_current_presence(
        &self,
        owner: &str,
        recipient: &str,
    ) -> impl Future<Output = ()> + Send;
    /// Sends the current presence of the exact account `owner` to the exact account `recipient`, on every node.
    fn send_current_presence_exact(
        &self,
        owner: &PresenceAccount,
        recipient: &PresenceAccount,
        owner_bare: &str,
        recipient_bare: &str,
    ) -> impl Future<Output = ()> + Send;
    /// Whether some node holds a route for the full JID `full_jid`.
    fn full_presence_target_routed(&self, full_jid: &str) -> impl Future<Output = bool> + Send;
    /// Dispatches the push notification of an offline account.
    fn notify_offline_account(&self, user_id: Uuid) -> impl Future<Output = Result<()>> + Send;
}

/// Where a client's presence leaves the roster context: presence addressed to the MIX, MUC and PubSub services,
/// and the broadcast copy the MIX channels of the account receive. The composition root hands each to its
/// context.
pub trait PresenceRouting: SessionHost {
    /// Hands a directed `<presence/>` to the MIX context, or `None` when it addresses no MIX channel.
    fn route_mix_presence(
        session: &ProtocolSession<Self>,
        root: Node<'_, '_>,
        raw: &str,
    ) -> impl Future<Output = Result<Option<Action>>> + Send;
    /// Hands a `<presence/>` of kind `kind` addressed to the PubSub service to the PubSub context, which replays
    /// the last published items to an available resource.
    fn route_pubsub_presence(
        session: &mut ProtocolSession<Self>,
        kind: &str,
        from: &str,
    ) -> impl Future<Output = Result<Action>> + Send;
    /// Hands a `<presence/>` addressed to the MUC service to the MUC context.
    fn route_muc_presence(
        session: &mut ProtocolSession<Self>,
        root: Node<'_, '_>,
        raw: &str,
    ) -> impl Future<Output = Result<Action>> + Send;
    /// Forwards a broadcast `<presence/>` of kind `kind` from `from` to the account's MIX channels, while the
    /// caller holds the resource's MIX presence gate. False, forwarding nothing, when this connection no longer
    /// owns the resource's MIX presence route.
    fn forward_presence_to_mix(
        session: &ProtocolSession<Self>,
        root: Node<'_, '_>,
        kind: &str,
        from: &str,
        raw: &str,
    ) -> impl Future<Output = Result<bool>> + Send;
}

/// The node as federated presence (an S2S inbound `<presence/>`) sees it.
pub trait FederatedPresenceHost: RosterSessionHost + SessionHost {
    /// The local sessions of `jid`: every resource of a bare JID, the one resource of a full JID.
    fn sessions_for(&self, jid: &str) -> Vec<OnlineSession>;
    /// Wakes the XEP-0357 push services of the account `user_id`.
    fn dispatch_push_notification(&self, user_id: Uuid) -> impl Future<Output = Result<()>> + Send;
}

/// The node as presence fan-out ([`crate::presence_delivery`]) sees it: the local session table's owner routes,
/// rechecked after every await, and the cluster's presence routes to the other nodes.
pub trait PresenceDeliveryHost: FederatedPresenceHost {
    /// A snapshot of the local session keys. The caller rechecks each route after its awaits.
    fn local_presence_owner_keys(&self) -> Vec<String>;
    /// The routable, available local session `key` when it belongs to the account incarnation `user_id` at
    /// `auth_generation`.
    fn local_presence_owner_candidate(
        &self,
        key: &str,
        user_id: Uuid,
        auth_generation: i64,
    ) -> Option<OnlineSession>;
    /// The local session `key` when it is still the connection and route incarnation of `expected`, of that
    /// account incarnation, routable and available.
    fn local_presence_owner_if_current(
        &self,
        key: &str,
        expected: &OnlineSession,
        user_id: Uuid,
        auth_generation: i64,
    ) -> Option<OnlineSession>;
    /// Sends `presence` to `recipient` only while the local session `key` is still `expected` (as
    /// [`Self::local_presence_owner_if_current`] checks). True when it was queued.
    fn send_presence_if_owner_current(
        &self,
        key: &str,
        expected: &OnlineSession,
        user_id: Uuid,
        auth_generation: i64,
        recipient: &OutboundSender,
        presence: &str,
    ) -> bool;
    /// Routes directed presence to the other nodes holding `target`. True when one accepted it.
    fn route_directed_presence_remote(
        &self,
        target: &str,
        stanza: &str,
        bare_target: bool,
    ) -> impl Future<Output = bool> + Send;
    /// Routes subscription presence to the other nodes holding `target`, for the account incarnations
    /// `authority` names.
    fn route_presence_subscription_remote(
        &self,
        target: &str,
        stanza: &str,
        authority: ClusterPresenceAuthority,
    ) -> impl Future<Output = ()> + Send;
    /// Broadcasts available presence to the other nodes holding `target`.
    fn broadcast_available_presence_remote(
        &self,
        target: &str,
        stanza: &str,
    ) -> impl Future<Output = ()> + Send;
    /// Hands a full-JID presence probe to the other nodes holding `owner_full`. True when one took it.
    fn delegate_authorized_full_presence_probe_remote(
        &self,
        owner_full: &str,
        requester: &str,
        authority: Option<ClusterPresenceAuthority>,
    ) -> impl Future<Output = Result<bool>> + Send;
    /// Asks the other nodes holding `owner_lookup` to replay its current presence to `recipient`, only the
    /// availability fact when `availability_only`.
    fn replay_current_presence_from_remote_owners(
        &self,
        owner_lookup: &str,
        recipient: &str,
        availability_only: bool,
        authority: ClusterPresenceAuthority,
    ) -> impl Future<Output = ()> + Send;
}
