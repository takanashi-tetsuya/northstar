//! Read-only admission for a room stanza addressed to an exact resource.

use anyhow::Result;
pub use northstar_xep_0016::PrivacyStanzaKind;
use std::future::Future;
use uuid::Uuid;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RoomPolicyRoute {
    /// A detached SM route can defer resolution to the existing SM capability.
    /// In that case the account UUID is nil and the generation is unavailable.
    pub account_id: Uuid,
    pub auth_generation: Option<i64>,
    pub subject: RoomPolicySubject,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RoomPolicySubject {
    Connection {
        id: Uuid,
        expects_active: bool,
    },
    AccountDefault,
    /// The existing SM capability resolves the account of a detached stream.
    Suspended {
        id: Uuid,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RoomDeliveryPolicyQuery<'a> {
    pub route: RoomPolicyRoute,
    /// Used for both blocking and privacy. The real peer is used only for blocking.
    pub visible_peer: &'a str,
    pub real_peer: Option<&'a str>,
    /// Account-level block checks for archive and routing use no stanza mask.
    pub kind: Option<PrivacyStanzaKind>,
    /// Required for the same-account exception to blocking.
    pub recipient_jid: &'a str,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RoomDeliveryDecision {
    Allow,
    PrivacyDenies,
    Blocked,
    StaleRoute,
}

impl RoomDeliveryDecision {
    pub fn allows(self) -> bool {
        self == Self::Allow
    }
}

pub trait RoomDeliveryPolicyReader: Send + Sync {
    /// Return one result per query, in input order.
    fn read_room_delivery_policies(
        &self,
        queries: &[RoomDeliveryPolicyQuery<'_>],
    ) -> impl Future<Output = Result<Vec<RoomDeliveryDecision>>> + Send;
}

pub trait RoomPolicyLiveSession {
    fn room_policy_route(&self) -> RoomPolicyRoute;
}

pub trait MixRelayPolicyReader: RoomDeliveryPolicyReader {
    fn read_remote_mix_relay(
        &self,
        policy: &RoomDeliveryPolicyQuery<'_>,
        channel: &northstar_room_core::mix::MixChannelAddress,
    ) -> impl Future<Output = Result<Option<northstar_room_core::mix_iq_relay::RelayPamIncarnation>>>
           + Send;
}
