//! Cluster MUC values the room adapter persists and the cluster edge carries
//! between nodes: delivery rows, event context, and the audience and policy
//! snapshots captured at commit.

use serde::{Deserialize, Serialize};
use serde_json::Value;
use uuid::Uuid;

/// Compact, immutable result of a policy mutation. This deliberately omits
/// `presence_payload`: policy audit data is not a second durable copy of
/// arbitrary user-supplied presence XML.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ClusterMucPolicySnapshot {
    pub room_id: Uuid,
    pub room_epoch: Uuid,
    pub occupant_incarnation: Uuid,
    pub occupancy_epoch: i64,
    pub full_jid: String,
    pub bare_jid: String,
    pub nick: String,
    pub connection_uuid: Uuid,
    pub connection_epoch: i64,
    pub sm_session_id: Option<Uuid>,
    pub role: String,
    pub affiliation: String,
    pub state: String,
}

#[derive(Clone, Debug)]
pub struct ClusterMucOutboxDelivery {
    pub delivery_id: Uuid,
    pub operation_id: Uuid,
    pub room_id: Uuid,
    pub room_epoch: Uuid,
    pub event_sequence: i64,
    pub event_id: Uuid,
    pub audience_kind: String,
    pub target_node_id: String,
    pub recipient_full_jid: Option<String>,
    pub recipient_nick: Option<String>,
    pub recipient_occupant_incarnation: Option<Uuid>,
    pub recipient_occupancy_epoch: Option<i64>,
    pub recipient_connection_uuid: Option<Uuid>,
    pub recipient_connection_epoch: Option<i64>,
    pub payload: String,
    pub payload_digest: Vec<u8>,
    pub attempt_count: i32,
    pub claim_token: Uuid,
    pub handoff_version: i64,
}

#[derive(Clone, Debug)]
pub struct ClusterMucEventContext {
    pub operation_kind: String,
    pub room_localpart: String,
    pub room_epoch: Uuid,
    pub room_non_anonymous: bool,
    pub occupant_id_secret: Vec<u8>,
    pub actor_full_jid: Option<String>,
    pub actor_affiliation: Option<String>,
    pub details: Value,
    pub target: Option<ClusterMucEventOccupant>,
}

#[derive(Clone, Debug)]
pub struct ClusterMucEventOccupant {
    pub full_jid: String,
    pub bare_jid: String,
    pub nick: String,
    pub affiliation: String,
    pub role: String,
    pub presence_payload: String,
    pub occupant_incarnation: Uuid,
    pub occupancy_epoch: i64,
    pub connection_uuid: Uuid,
    pub connection_epoch: i64,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ClusterMucOutboxSnapshot {
    pub queued_rows: i64,
    pub expired_rows: i64,
    pub claimed_rows: i64,
    pub dead_letter_rows: i64,
    pub oldest_age_seconds: i64,
}

/// Immutable, bounded delivery projection captured at operation commit. It
/// deliberately excludes the potentially 1 MiB presence payload: recipient
/// endpoint reconstruction needs identity/route/role facts, not the
/// recipient's last advertised presence. Keeping this projection in the
/// append-only operation prevents a later resume/rename from rewriting who
/// was in the audience of an already committed event.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ClusterMucAudienceSnapshot {
    pub room_id: Uuid,
    pub room_epoch: Uuid,
    pub identity_kind: String,
    pub local_user_id: Option<Uuid>,
    pub bare_jid: String,
    pub full_jid: String,
    pub nick: String,
    pub authenticated_domain: Option<String>,
    pub owner_node_id: String,
    pub occupant_incarnation: Uuid,
    pub occupancy_epoch: i64,
    pub connection_uuid: Uuid,
    pub connection_epoch: i64,
    pub sm_session_id: Option<Uuid>,
    pub role: String,
    pub affiliation: String,
}
