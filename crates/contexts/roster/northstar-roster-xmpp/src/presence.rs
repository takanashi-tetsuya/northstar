//! RFC 6121 presence: directed presence, the broadcast of a resource's availability, probes and
//! subscriptions.

use anyhow::Result;
use northstar_roster_application::presence::{
    LocalPresenceEffect, LocalSubscriptionRequest, PresenceMutation, PresencePolicyDenial,
    PresenceRepository, PresenceService, RemoteSubscriptionTransition,
};
use northstar_roster_application::subscription_retry::SubscriptionRetryRepository;
use northstar_roster_core::PresenceAccount;
use northstar_stream::local_routes::pending_subscription::PendingSubscriptionKey;
use northstar_xml_builder::rewrite::{set_from, set_to};
use northstar_xml_builder::stanza::{blocked_stanza_error, child_text, stanza_error};
use northstar_xml_builder::XmlElement;
use roxmltree::Node;
use std::future::Future;

use crate::blocking::BlockingSession;
use crate::presence_delivery::DirectedPresenceSession;
use crate::privacy::PrivacySession;
use crate::roster::RosterSession;
use crate::AvatarPresenceGate;

mod availability;
mod avatar;
mod broadcast;
mod directed;
mod notice;
mod probe_route;
mod subscription_route;
mod subscriptions;

pub use self::availability::{full_jid_probe_available_response, presence_probe_status_response};
pub use self::avatar::refresh_avatar_presence;
pub(crate) use self::broadcast::{
    broadcast_presence, prepare_broadcast_presence, PreparedBroadcastPresence,
};
pub use self::directed::{directed_presence_gate, route_directed_presence, PresenceGate};
pub use self::notice::deliver_service_messages;
pub(crate) use northstar_xmpp_avatar::vcard_update::inject_vcard_avatar_hash;

use self::directed::DirectedPresencePlan;
use self::subscription_route::{RemoteSubscriptionRequest, SubscriptionMutationDisposition};

/// What a client session provides to the presence handlers, beyond its blocking, privacy and
/// roster capabilities. The fan-out over online sessions lives behind this trait until the
/// session context moves.
pub trait PresenceSession:
    BlockingSession
    + PrivacySession
    + RosterSession
    + crate::SubscriptionRetryWake
    + DirectedPresenceSession
    + crate::exact_presence::ExactPresenceSession
{
    /// The presence service, over the repository the composition root binds.
    fn presence_service(
        &self,
    ) -> &PresenceService<impl PresenceRepository + SubscriptionRetryRepository>;
    /// The node's gate for projecting the current avatar into cached presence.
    fn avatar_presence_gate(&self) -> &AvatarPresenceGate;
    /// Queues `stanza` to this session, dropping it when the queue is full.
    fn presence_try_send(&self, stanza: String);
    /// Queues `stanza` to this session, waiting for room.
    fn presence_send(&self, stanza: String) -> impl Future<Output = Result<()>> + Send;

    /// Whether the session sent directed presence to `target`.
    fn presence_directed_contains(&self, target: &str) -> bool;
    /// How many targets the session sent directed presence to.
    fn presence_directed_count(&self) -> usize;
    /// Records directed presence to `target`.
    fn presence_directed_insert(&self, target: String);
    /// Forgets directed presence to `target`.
    fn presence_directed_remove(&self, target: &str);
    /// Forgets directed presence to every target `keep` rejects.
    fn presence_directed_retain(&self, keep: impl Fn(&str) -> bool);

    /// Whether stanzas may be routed to the external `domain`.
    fn presence_route_allowed(&self, domain: &str) -> bool;
    /// Whether `domain` is an external component of this server.
    fn presence_is_component_domain(&self, domain: &str) -> bool;
    /// Sends `stanza` towards the external `domain`. Returns whether it was accepted.
    fn presence_send_federated(
        &self,
        domain: &str,
        stanza: String,
        bounce_to: Option<String>,
    ) -> impl Future<Output = bool> + Send;

    /// Delivers the directed presence `stanza` of `from` to `to` on this node, and to
    /// `canonical_to` on the others. A `bare_target` reaches only available resources. Returns
    /// whether a session accepted it.
    fn presence_deliver_directed(
        &self,
        to: &str,
        canonical_to: &str,
        from: &str,
        stanza: &str,
        bare_target: bool,
    ) -> impl Future<Output = Result<bool>> + Send;
    /// Delivers the subscription `stanza` of `owner` to the available resources of `recipient`,
    /// each addressed exactly, on this node and on the others.
    fn presence_deliver_subscription(
        &self,
        owner: &PresenceAccount,
        recipient: &PresenceAccount,
        owner_bare: &str,
        recipient_bare: &str,
        stanza: &str,
        pending: Option<PendingSubscriptionKey>,
    ) -> impl Future<Output = Result<()>> + Send;
    /// Delivers the `approved` subscription of `owner` to the other available resources of
    /// `recipient`, the account of this session, on this node and on the others.
    fn presence_deliver_approval(
        &self,
        owner: &PresenceAccount,
        recipient: &PresenceAccount,
        owner_bare: &str,
        recipient_bare: &str,
        approved: &str,
    ) -> impl Future<Output = Result<()>> + Send;
    /// Delivers the broadcast `stanza` of `from` to the available resources of `contact`, a
    /// local account, on this node and on the others.
    fn presence_deliver_to_contact(
        &self,
        contact: &str,
        from: &str,
        stanza: &str,
    ) -> impl Future<Output = Result<()>> + Send;
    /// Echoes the broadcast `stanza` of the resource `from` to its own `account`, on this node
    /// and on the others.
    fn presence_echo_to_account(
        &self,
        account: &str,
        from: &str,
        stanza: &str,
    ) -> impl Future<Output = ()> + Send;
    /// The process-local epoch of the last committed broadcast presence.
    fn presence_broadcast_epoch(&self) -> Option<u64>;
    /// Whether a resource of the local account `bare` is available on this node.
    fn presence_has_available_resource(&self, bare: &str) -> bool;
    /// Whether another node holds a resource of the local account `bare`.
    fn presence_probe_has_remote_owner(
        &self,
        bare: &str,
    ) -> impl Future<Output = Result<bool>> + Send;
    /// Whether a local session of `owner_full` sent directed presence to `requester`.
    fn presence_directed_recipient(&self, owner_full: &str, requester: &str) -> bool;
    /// Answers a probe of `requester` for the resource `owner_full`, once it is authorized.
    fn presence_answer_full_probe(
        &self,
        owner_full: &str,
        owner_bare: &str,
        requester: &str,
        probe_id: Option<&str>,
    ) -> impl Future<Output = Result<()>> + Send;
    /// Sends the current availability of `owner` to `recipient`.
    fn presence_send_current(
        &self,
        owner: &str,
        recipient: &str,
    ) -> impl Future<Output = ()> + Send;
    /// Sends the current availability of `owner` to `recipient`, for exactly these accounts.
    fn presence_send_current_exact(
        &self,
        owner: &PresenceAccount,
        recipient: &PresenceAccount,
        owner_bare: &str,
        recipient_bare: &str,
    ) -> impl Future<Output = ()> + Send;
    /// Whether the full JID has a published route for this target precondition.
    fn presence_full_target_routed(
        &self,
        full_jid: &str,
        account: &PresenceAccount,
    ) -> impl Future<Output = bool> + Send;
    /// Tells the devices of an account without a session that something arrived.
    fn presence_notify_offline(
        &self,
        user_id: uuid::Uuid,
    ) -> impl Future<Output = Result<()>> + Send;
}

/// The numeric show value for an announced presence.
pub fn announced_show(root: Node<'_, '_>, kind: &str) -> u8 {
    if kind == "available" {
        match child_text(root, "show") {
            Some("away") => 2,
            Some("chat") => 3,
            Some("dnd") => 4,
            Some("xa") => 5,
            _ => 1,
        }
    } else {
        0
    }
}

/// The announced priority value for a presence stanza.
pub fn announced_priority(root: Node<'_, '_>, kind: &str) -> i16 {
    if kind == "available" {
        child_text(root, "priority")
            .and_then(|value| value.parse::<i16>().ok())
            .filter(|value| (-128..=127).contains(value))
            .unwrap_or(0)
    } else {
        0
    }
}

#[cfg(test)]
mod tests;
