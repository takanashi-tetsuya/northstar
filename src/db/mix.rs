use crate::platform::delivery_counters::{
    MIX_DELIVERY_CAPACITY_REJECTIONS_TOTAL, MIX_DELIVERY_DEAD_LETTERS_TOTAL,
    MIX_DELIVERY_LEASE_LOST_TOTAL, MIX_DELIVERY_RETRIES_TOTAL,
};
use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use northstar_archive_application::MAX_MAM_PAGE_SIZE;
use northstar_archive_core::{
    classify_mam_blocked_jids, finish_mam_page, mam_referenced_ids, mix_mam_peer_filter_allowed,
    resolve_mam_query, MamBlockedIdentitySource, MamBlockedPattern,
};
use sha2::{Digest, Sha256};
use sqlx::{PgPool, Postgres, QueryBuilder, Row, Transaction};
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::atomic::Ordering,
};
use uuid::Uuid;

mod admin;
mod channel;
mod delivery_capacity;
mod delivery_queue;
mod delivery_settlement;
mod delivery_transfer;
mod intent;
mod jid_map_retract;
mod mam;
mod membership;
mod nick_preference;
mod pam_completion;
mod pam_join;
mod participant;
mod projection;
mod publish;

pub use self::admin::*;
pub use self::channel::*;
pub use self::delivery_capacity::*;
pub use self::delivery_queue::*;
pub use self::delivery_settlement::*;
pub use self::delivery_transfer::*;
pub use self::intent::*;
pub use self::jid_map_retract::*;
pub use self::mam::*;
pub use self::membership::*;
pub use self::nick_preference::*;
pub use self::pam_completion::*;
pub use self::pam_join::*;
pub use self::participant::*;
use self::projection::*;
pub use self::publish::*;

pub const NODE_MESSAGES: &str = "urn:xmpp:mix:nodes:messages";
pub const NODE_PRESENCE: &str = "urn:xmpp:mix:nodes:presence";
pub const NODE_PARTICIPANTS: &str = "urn:xmpp:mix:nodes:participants";
pub const NODE_INFO: &str = "urn:xmpp:mix:nodes:info";
pub const NODE_CONFIG: &str = "urn:xmpp:mix:nodes:config";
pub const NODE_ALLOWED: &str = "urn:xmpp:mix:nodes:allowed";
pub const NODE_BANNED: &str = "urn:xmpp:mix:nodes:banned";
pub const NODE_JIDMAP: &str = "urn:xmpp:mix:nodes:jidmap";
pub const NODE_AVATAR_DATA: &str = "urn:xmpp:avatar:data";
pub const NODE_AVATAR_METADATA: &str = "urn:xmpp:avatar:metadata";

pub const ALL_NODES: [&str; 10] = [
    NODE_MESSAGES,
    NODE_PRESENCE,
    NODE_PARTICIPANTS,
    NODE_INFO,
    NODE_CONFIG,
    NODE_ALLOWED,
    NODE_BANNED,
    NODE_JIDMAP,
    NODE_AVATAR_DATA,
    NODE_AVATAR_METADATA,
];

pub(crate) use crate::services::mix::valid_stable_participant_id;

pub(crate) use crate::services::mix::mix_timestamp_item_id;

pub(crate) use crate::services::mix::MixChannel;

pub(crate) use crate::services::mix::MixParticipant;

#[derive(Clone, Debug)]
pub struct MixEvent {
    pub id: Uuid,
    pub item_id: String,
    pub payload: String,
    pub created_at: DateTime<Utc>,
}

#[derive(Clone, Debug)]
pub struct MixEventPage {
    pub events: Vec<MixEvent>,
}

#[derive(Clone, Debug)]
pub enum MixReadOutcome<T> {
    Found(T),
    Unauthorized,
    NotFound,
}

#[derive(Clone, Debug)]
pub struct MixMamPage {
    pub events: Vec<MixEvent>,
    pub total: i64,
    pub first_index: i64,
    pub complete: bool,
}

#[derive(Clone, Debug)]
pub struct MixPresenceProbeTarget {
    pub channel_jid: String,
    pub participant_jid: String,
}

#[derive(Clone, Debug)]
pub struct ExpiredMixPresence {
    pub channel_id: Uuid,
    pub participant: MixParticipant,
    pub item_id: String,
    pub payload: String,
    pub source_full_jid: Option<String>,
}

#[derive(Clone, Debug)]
pub struct PamMembership {
    pub id: Uuid,
    pub user_id: Uuid,
    pub channel_jid: String,
    pub participant_id: Option<String>,
    pub state: String,
    pub request_id: Option<String>,
    pub client_request_id: Option<String>,
    pub requester_full_jid: Option<String>,
    pub subscriptions: Vec<String>,
}

pub(crate) use crate::services::mix::MixParticipantPreference;

/// Authenticated federation identity and durable reply policy attached to one
/// mutating MIX IQ.  A successful repository mutation must journal its exact
/// result and enqueue that result before the business transaction commits.
/// Keeping this context explicit avoids task-local state leaking across
/// unrelated async work and makes every mutation boundary reviewable.
pub(crate) use crate::services::mix::FederatedMixMutation;

/// Typed successful effects from which the application serializer produces
/// the exact IQ result persisted by the mutation transaction.
pub(crate) use crate::services::mix::FederatedMixSuccess;

pub(crate) use crate::services::mix::MixPresenceDelivery;

pub(crate) use crate::services::mix::PamJoinResult;

/// Application-layer serializer used while a durable MIX mutation is still
/// inside its database transaction. Persistence owns atomic storage, but it
/// never constructs protocol XML or interpolates untrusted stanza values.
pub(crate) use crate::services::mix::MixEventPayloadRenderer;

#[derive(Clone, Debug)]
pub struct ClaimedMixDelivery {
    pub delivery_id: Uuid,
    pub event_id: Uuid,
    pub channel_id: Uuid,
    pub channel_jid: String,
    pub recipient: MixParticipant,
    pub stanza: String,
    pub authoritative_stanza_id: Option<Uuid>,
    pub archive: bool,
    pub encrypted: bool,
    pub attempt_count: i32,
    pub lease_token: Uuid,
    /// Durable route-wake epoch observed while this exact recipient head was
    /// leased. A later epoch prevents this worker from parking an available
    /// route behind its recovery backoff.
    pub route_wake_generation: i64,
}

/// Durable completion of one leased MIX delivery retry.
///
/// The repository owns the terminal decision because the claimed attempt
/// snapshot can be stale by the time the worker releases its lease.  In
/// particular, a committed route wake at the attempt limit is a durable
/// routing fact which gets one fresh claim before the normal terminal path.
pub(crate) use crate::services::mix::MixDeliveryRetryOutcome;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PamOperationReplay {
    Miss,
    Pending,
    Replay(String),
    Conflict,
}

#[derive(Clone, Debug)]
pub struct ClaimedPamResult {
    pub operation_id: Uuid,
    pub user_id: Uuid,
    pub requester_full_jid: String,
    pub response_xml: String,
    pub attempt_count: i32,
    pub lease_token: Uuid,
}

#[derive(Clone, Debug)]
pub struct RemotePamCompletion {
    pub response_xml: String,
    pub membership: Option<PamMembership>,
    pub applied: bool,
    pub roster_removed: Option<bool>,
}

#[derive(Clone, Debug)]
pub struct MixDeliveryDeadLetter {
    pub dead_letter_id: Uuid,
    pub delivery_id: Uuid,
    pub event_id: Uuid,
    pub channel_id: Uuid,
    pub channel_jid: String,
    pub recipient_jid: String,
    pub attempt_count: i32,
    pub terminal_reason: String,
    pub last_error: Option<String>,
    pub failed_at: DateTime<Utc>,
}

const MIX_DELIVERY_MAX_ROWS: i64 = 100_000;
const MIX_DELIVERY_MAX_BYTES: i64 = 268_435_456;
const MIX_DELIVERY_RECIPIENT_OVERHEAD: i64 = 128;
const MIX_DELIVERY_DEAD_LETTER_LIMIT: i64 = 10_000;
const MIX_DELIVERY_LEASE_SECONDS: i64 = 90;
// Direct sockets have no peer acknowledgement below XEP-0198. Keep a
// separate bounded lease for the interval after the writer has fenced the
// source but before the OS accepts the bytes. It is deliberately longer than
// the transport write deadline and shorter than a normal worker lease; a
// failed process therefore recovers through the same ordered claim path.
const MIX_SOCKET_WRITE_FENCE_SECONDS: i64 = 30;

/// MIX recommends the RFC 7700 nickname profile of PRECIS OpaqueString. The
/// resourcepart preparation used by RFC 7622 has the same case-preserving
/// OpaqueString behavior and enforces the protocol's 1023-octet bound.
pub(crate) use crate::services::mix::prepare_mix_nick;

pub(crate) use crate::services::mix::valid_join_nodes;

pub(crate) use crate::services::mix::canonical_mix_access_pattern;

pub(crate) use crate::services::mix::participant_jid_visible;

#[cfg(test)]
#[path = "mix_pam_durability_tests.rs"]
mod pam_durability_integration_tests;

#[cfg(test)]
#[path = "mix_delivery_capacity_tests.rs"]
mod delivery_capacity_integration_tests;

#[cfg(test)]
#[path = "mix_sequence_retention_tests.rs"]
mod delivery_sequence_retention_integration_tests;

#[cfg(test)]
#[path = "mix_delivery_route_wake_tests.rs"]
mod delivery_route_wake_integration_tests;

#[cfg(test)]
#[path = "mix_nickname_tests.rs"]
mod nickname_tests;

#[cfg(test)]
#[path = "mix_delivery_order_contract_tests.rs"]
mod delivery_order_contract_tests;

#[cfg(test)]
#[path = "mix_mam_tests.rs"]
mod mam_integration_tests;
