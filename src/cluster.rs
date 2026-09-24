use crate::services::cluster_authority::{ClusterAuthorityRepository, ClusterAuthorityService};
use crate::services::cluster_instance_release::{
    ClusterInstanceReleaseIdentity, ClusterInstanceReleaseRepository, ClusterInstanceReleaseService,
};
use crate::services::cluster_muc_outbox_settlement::AckOutcome;
use crate::services::node_message_contract_verifier::{
    NodeMessageContractVerifier, NodeMessageProjectionRepository, RequestedNodeMessageProjection,
    VerifiedNodeMessageProjection,
};
use crate::state::AppState;
use anyhow::{Context, Result};
use bb8::Pool;
use futures::{future::BoxFuture, FutureExt, StreamExt};
use redis::AsyncCommands;
use serde::{Deserialize, Serialize};
use sha2::Digest;
use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::atomic::{AtomicBool, AtomicI64, AtomicU64, AtomicU8, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio_util::sync::CancellationToken;

mod listener;
mod pool;

use listener::*;

use pool::{
    cluster_pool_builder, open_pubsub, publish_listener_probe, subscribe_pubsub,
    RedisConnectionManager,
};

const SESSION_TTL_SECONDS: u64 = 900;
// Match the configured XEP-0198 resume-timeout upper bound. This prevents a
// very late disconnect task from recreating a Redis MUC occupant after its
// durable stream has already completed teardown.
const SM_TEARDOWN_TOMBSTONE_TTL_SECONDS: u64 = 86_400;
const USER_SET_TTL_SECONDS: u64 = 1_800;
const NODE_TTL_SECONDS: u64 = 90;
const CLUSTER_MAINTENANCE_INTERVAL_SECONDS: u64 = 30;
// Redis is only a disposable routing projection for MUC occupancy.  Keep the
// projection long enough to survive several missed maintenance ticks, but
// never leave an abandoned temporary room unbounded.  Every exact
// PostgreSQL-authoritative occupant refresh renews all three room keys
// atomically; a room with no live refresher therefore disappears by itself.
const MUC_SOFT_STATE_TTL_SECONDS: u64 = 300;
// Bound every Redis control-plane request, not only the delivery ACK wait.
// Without this, a command written while Redis is paused can remain queued and
// execute after recovery, turning a failed/expired stanza route into a late
// delivery. The command immediately preceding PUBLISH now fails closed before
// the side-effecting command is issued.
const REDIS_CONNECT_TIMEOUT: Duration = Duration::from_secs(2);
const REDIS_IO_TIMEOUT: Duration = Duration::from_millis(500);
const CLUSTER_REDIS_POOL_MAX_SIZE: u32 = 16;
const DELIVERY_ACK_TIMEOUT: Duration = Duration::from_secs(2);
// This is the per-resource C2S ownership wait for the older exact-resource
// delivery path. MIX uses a typed durable hand-off below instead: it waits for
// an actual socket/SM/BOSH boundary and closes the one route if its caller is
// cancelled, rather than declaring ownership after this timer elapses.
const DELIVERY_TRANSPORT_RECEIPT_TIMEOUT: Duration = Duration::from_millis(500);
const MIX_CLUSTER_HANDOFF_TTL_SECONDS: u64 = 30;
const MAX_DELIVERY_ACK_BYTES: usize = 4096;
const MAX_CLUSTER_PAYLOAD_BYTES: usize = 2 * 1024 * 1024;
const MAX_DELIVERY_EXCLUSIONS: usize = 16;
const MAX_PENDING_CLUSTER_ACKS: usize = 4096;
const MAX_LISTENER_CONTINUATIONS: usize = 16;
const MUC_OUTBOX_MAX_BATCHES_PER_PASS: usize = 4;
const MUC_OUTBOX_BATCH_SIZE: i64 = 16;
const MUC_OUTBOX_PASS_BUDGET: Duration = Duration::from_secs(20);
const MUC_OUTBOX_DELIVERY_BUDGET: Duration = Duration::from_secs(5);
const CLUSTER_MAINTENANCE_BUDGET: Duration = Duration::from_secs(25);
const NODE_PROTOCOL_VERSION: &str = "13";
const DELIVERY_CONTRACT_PROTOCOL_VERSION: u16 = 13;
// Version 8 introduced the explicit volatile/durable delivery contract.
// Versions 9 through 13 retain that wire meaning while adding independent
// signed envelope, presence-authority, MIX-capability, and MIX transport
// receipt requirements. Version 13 adds an exact leased MIX source; it must
// never fall back to the version-7 stanza-id inference rules during a rolling
// upgrade.
const DELIVERY_CONTRACT_PROTOCOL_MIN: u16 = 8;
const PRESENCE_AUTHORITY_VERSION: u16 = 1;
const LEGACY_DELIVERY_PROTOCOL_MAX: u16 = 7;
#[cfg(test)]
const MAX_REPLAY_ENTRIES: usize = 65_536;

fn requires_correlated_ack(peer_version: Option<&str>) -> bool {
    peer_version
        .and_then(|version| version.parse::<u16>().ok())
        .is_some_and(|version| version >= 2)
}

fn supports_control_ack(peer_version: Option<&str>) -> bool {
    peer_version
        .and_then(|version| version.parse::<u16>().ok())
        .is_some_and(|version| {
            (LEGACY_DELIVERY_PROTOCOL_MAX..=DELIVERY_CONTRACT_PROTOCOL_VERSION).contains(&version)
        })
}

fn supports_delivery_contract(peer_version: Option<&str>) -> bool {
    peer_version
        .and_then(|version| version.parse::<u16>().ok())
        .is_some_and(|version| {
            (DELIVERY_CONTRACT_PROTOCOL_MIN..=DELIVERY_CONTRACT_PROTOCOL_VERSION).contains(&version)
        })
}

fn supports_current_cluster_protocol(peer_version: Option<&str>) -> bool {
    peer_version == Some(NODE_PROTOCOL_VERSION)
}

fn supports_legacy_delivery_inference(peer_version: Option<&str>) -> bool {
    peer_version
        .and_then(|version| version.parse::<u16>().ok())
        .is_some_and(|version| (1..=LEGACY_DELIVERY_PROTOCOL_MAX).contains(&version))
}

fn delivery_contract_compatible_with_peer(
    peer_version: Option<&str>,
    contract: NodeDeliveryContract,
    identity: crate::outbound::RecipientDeliveryIdentity,
) -> bool {
    if supports_delivery_contract(peer_version) {
        return true;
    }
    if !supports_legacy_delivery_inference(peer_version) {
        return false;
    }
    match (contract, identity) {
        (
            NodeDeliveryContract::DurableC2s { message_id, .. },
            crate::outbound::RecipientDeliveryIdentity::Exact(stanza_id),
        ) => message_id == stanza_id,
        (
            NodeDeliveryContract::Volatile {},
            crate::outbound::RecipientDeliveryIdentity::Missing,
        ) => true,
        _ => false,
    }
}

#[cfg(test)]
fn generation_control_revokes(
    session_user: uuid::Uuid,
    session_generation: i64,
    target_user: uuid::Uuid,
    minimum_generation: i64,
) -> bool {
    session_user == target_user && session_generation < minimum_generation
}

fn user_agent_control_revokes(
    session_user: uuid::Uuid,
    session_device: Option<uuid::Uuid>,
    session_epoch: Option<i64>,
    target_user: uuid::Uuid,
    target_device: uuid::Uuid,
    minimum_epoch: i64,
) -> bool {
    session_user == target_user
        && session_device == Some(target_device)
        && session_epoch.is_some_and(|epoch| epoch < minimum_epoch)
}

fn delivery_user_identity_matches(
    expected_user_id: Option<uuid::Uuid>,
    expected_auth_generation: Option<i64>,
    session_user_id: uuid::Uuid,
    session_auth_generation: i64,
) -> bool {
    expected_user_id.is_none_or(|expected| expected == session_user_id)
        && expected_auth_generation.is_none_or(|expected| expected == session_auth_generation)
}

fn cluster_roster_push_version(stanza: &str) -> Option<i64> {
    let Ok(document) = roxmltree::Document::parse(stanza) else {
        return None;
    };
    let root = document.root_element();
    if root.tag_name().name() != "iq" || root.attribute("type") != Some("set") {
        return None;
    }
    let mut children = root.children().filter(roxmltree::Node::is_element);
    let query = children.next()?;
    if children.next().is_some()
        || query.tag_name().name() != "query"
        || query.tag_name().namespace() != Some("jabber:iq:roster")
    {
        return None;
    }
    query.attribute("ver")?.parse().ok()
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct NodeDeliveryReceipt {
    pub delivered: bool,
    pub accepted_full_jid: Option<String>,
    pub acknowledged: bool,
    pub mix_supported: usize,
    pub mix_unsupported: usize,
    pub mix_unknown: usize,
    pub mix_handoff: Option<ClusterMixHandoff>,
}

#[derive(Clone, Copy, Debug, Default)]
struct NodeDeliveryOptions<'a> {
    carbons_only: bool,
    blocklist_requested_only: bool,
    roster_requested_only: bool,
    /// Exact account incarnation authorized by the originating transaction.
    /// Roster/removal delivery must not cross a delete/recreate boundary.
    expected_user_id: Option<uuid::Uuid>,
    expected_auth_generation: Option<i64>,
    /// Immutable roster journal version used by the recipient's initial-sync
    /// gate. Present whenever `roster_requested_only` is true.
    roster_version: Option<i64>,
    /// Optional XEP-0405 rendering of the same immutable roster version.
    /// The receiving resource selects it under its synchronization gate.
    roster_annotated_stanza: Option<&'a str>,
    privacy_requested_only: bool,
    mix_capable_only: bool,
    /// Do not acknowledge the request when the stanza merely entered the
    /// peer's in-memory queue. The receiver waits for the exact transport to
    /// take ownership (or rejects and keeps the durable source journal).
    transport_receipt_required: bool,
    /// Dedicated transport-ownership acknowledgement for a bare-JID MIX
    /// message. This deliberately differs from `transport_receipt_required`:
    /// MIX must retain its verified-capability fan-out and may acknowledge any
    /// one qualified resource, rather than a single preselected full JID.
    mix_transport_receipt_required: bool,
    exclude_jids: &'a [&'a str],
    primary: bool,
    available_only: bool,
    available_nonnegative_only: bool,
    /// Restrict a sent Carbon for a MUC private message to resources sharing
    /// the sender's exact room/nick membership (XEP-0280 section 6.1).
    carbon_muc_scope: Option<(&'a str, &'a str)>,
    /// Exact PostgreSQL row whose lifetime fences this C2S delivery. `None`
    /// means the message is deliberately volatile; it must never be inferred
    /// as durable merely because it contains an XEP-0359 stanza-id.
    durable_delivery: Option<crate::outbound::DurableDelivery>,
    /// Exact leased MIX recipient source. Unlike C2S, this source is first
    /// transferred to a remote-node fence and then to socket/SM/BOSH
    /// ownership; it is never inferred from a stanza-id.
    mix_delivery: Option<crate::outbound::MixDelivery>,
    presence_authority: Option<ClusterPresenceAuthority>,
    presence_delivery: Option<ClusterPresenceDelivery>,
}

/// Database identities carried by current-presence and local subscription
/// replay. Signed Redis traffic authenticates a node, not the account
/// incarnation named by a JID; the receiver therefore revalidates all four
/// fields against PostgreSQL before touching a live route.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ClusterPresenceAuthority {
    pub(crate) owner_id: uuid::Uuid,
    pub(crate) owner_auth_generation: i64,
    pub(crate) recipient_id: uuid::Uuid,
    pub(crate) recipient_auth_generation: i64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ClusterPresenceDelivery {
    CurrentReplay,
    Subscription,
}

fn presence_delivery_stanza_matches(
    document: &roxmltree::Document<'_>,
    delivery: ClusterPresenceDelivery,
) -> bool {
    let root = document.root_element();
    if root.tag_name().name() != "presence" {
        return false;
    }
    let kind = root.attribute("type").unwrap_or("available");
    match delivery {
        ClusterPresenceDelivery::CurrentReplay => kind == "available",
        ClusterPresenceDelivery::Subscription => matches!(
            kind,
            "subscribe" | "subscribed" | "unsubscribe" | "unsubscribed"
        ),
    }
}

fn is_presence_subscription_stanza(document: &roxmltree::Document<'_>) -> bool {
    presence_delivery_stanza_matches(document, ClusterPresenceDelivery::Subscription)
}

fn presence_authority(json: &serde_json::Value) -> Result<Option<ClusterPresenceAuthority>> {
    let authority_fields_present = [
        "presence_owner_id",
        "presence_owner_auth_generation",
        "presence_recipient_id",
        "presence_recipient_auth_generation",
    ]
    .iter()
    .any(|field| json.get(field).is_some_and(|value| !value.is_null()));
    let version = match json.get("presence_authority_version") {
        None | Some(serde_json::Value::Null) => {
            if authority_fields_present {
                anyhow::bail!("cluster presence authority is unversioned");
            }
            return Ok(None);
        }
        Some(value) => value
            .as_u64()
            .and_then(|value| u16::try_from(value).ok())
            .context("cluster presence authority version is invalid")?,
    };
    anyhow::ensure!(
        version == PRESENCE_AUTHORITY_VERSION,
        "unsupported cluster presence authority version"
    );
    let parse_id = |field: &str| -> Result<uuid::Uuid> {
        json.get(field)
            .and_then(serde_json::Value::as_str)
            .context("cluster presence authority omitted an account UUID")
            .and_then(|value| {
                uuid::Uuid::parse_str(value)
                    .context("cluster presence authority account UUID is invalid")
            })
            .and_then(|value| {
                anyhow::ensure!(
                    !value.is_nil(),
                    "cluster presence authority account UUID is nil"
                );
                Ok(value)
            })
    };
    let parse_generation = |field: &str| -> Result<i64> {
        json.get(field)
            .and_then(serde_json::Value::as_i64)
            .filter(|value| *value >= 0)
            .context("cluster presence authority generation is invalid")
    };
    Ok(Some(ClusterPresenceAuthority {
        owner_id: parse_id("presence_owner_id")?,
        owner_auth_generation: parse_generation("presence_owner_auth_generation")?,
        recipient_id: parse_id("presence_recipient_id")?,
        recipient_auth_generation: parse_generation("presence_recipient_auth_generation")?,
    }))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "reliability", rename_all = "snake_case", deny_unknown_fields)]
enum NodeDeliveryContract {
    Volatile {},
    DurableC2s {
        recipient_id: uuid::Uuid,
        message_id: uuid::Uuid,
    },
    DurableMix {
        delivery_id: uuid::Uuid,
        lease_token: uuid::Uuid,
    },
}

/// The durable local boundary reached by a remote node after it accepted one
/// exact MIX source. The source node uses this only to decide that its old
/// lease was transferred; database rows retain the actual new lease token.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ClusterMixHandoff {
    SocketFenced,
    SmPersisted,
    BoshPersisted,
}

impl NodeDeliveryContract {
    fn from_durable(delivery: crate::outbound::DurableDelivery) -> Result<Self> {
        anyhow::ensure!(
            delivery.claim_id.is_none(),
            "cluster live delivery cannot carry an offline replay claim"
        );
        Ok(Self::DurableC2s {
            recipient_id: delivery.recipient_id,
            message_id: delivery.message_id,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum ClusterControlOutcome {
    Matched,
    AuthoritativelyAbsent,
    WrongOwner,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct NodeDeliveryAck {
    request_id: String,
    nonce: String,
    node_id: String,
    delivered: usize,
    accepted_full_jid: Option<String>,
    #[serde(default)]
    mix_supported: usize,
    #[serde(default)]
    mix_unsupported: usize,
    #[serde(default)]
    mix_unknown: usize,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    control_processed: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    control_outcome: Option<ClusterControlOutcome>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    delivery: Option<NodeDeliveryContract>,
    /// Present only for a durable MIX contract after the destination has
    /// transferred the exact PostgreSQL source to a socket, SM, or BOSH
    /// owner. Redis acknowledgement alone is deliberately not sufficient.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    mix_handoff: Option<ClusterMixHandoff>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RequestedNodeMessageDelivery {
    LegacyInference,
    Explicit(NodeDeliveryContract),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ResolvedNodeMessageDelivery {
    Volatile,
    Durable(crate::outbound::DurableDelivery),
    Mix(crate::outbound::MixDelivery),
}

impl ResolvedNodeMessageDelivery {
    fn contract(self) -> NodeDeliveryContract {
        match self {
            Self::Volatile => NodeDeliveryContract::Volatile {},
            Self::Durable(delivery) => NodeDeliveryContract::DurableC2s {
                recipient_id: delivery.recipient_id,
                message_id: delivery.message_id,
            },
            Self::Mix(delivery) => NodeDeliveryContract::DurableMix {
                delivery_id: delivery.delivery_id,
                lease_token: delivery.lease_token,
            },
        }
    }
}

fn requested_node_message_delivery(
    json: &serde_json::Value,
    is_message_stanza: bool,
) -> Result<Option<RequestedNodeMessageDelivery>> {
    let advertised_version = match json.get("protocol_version") {
        None | Some(serde_json::Value::Null) => None,
        Some(serde_json::Value::String(version)) => Some(
            version
                .parse::<u16>()
                .context("cluster protocol version is invalid")?,
        ),
        Some(_) => anyhow::bail!("cluster protocol version must be a string"),
    };
    if advertised_version.is_some_and(|version| version > DELIVERY_CONTRACT_PROTOCOL_VERSION) {
        anyhow::bail!("cluster delivery protocol version is newer than this node");
    }
    let delivery_value = json.get("delivery").filter(|value| !value.is_null());
    if !is_message_stanza {
        anyhow::ensure!(
            delivery_value.is_none(),
            "non-message cluster stanza carried a delivery contract"
        );
        return Ok(None);
    }
    if let Some(delivery) = delivery_value {
        anyhow::ensure!(
            advertised_version.is_some_and(|version| {
                (DELIVERY_CONTRACT_PROTOCOL_MIN..=DELIVERY_CONTRACT_PROTOCOL_VERSION)
                    .contains(&version)
            }),
            "cluster delivery contract requires a delivery-contract capable protocol version"
        );
        let contract: NodeDeliveryContract = serde_json::from_value(delivery.clone())
            .context("cluster delivery contract is invalid")?;
        if matches!(contract, NodeDeliveryContract::DurableMix { .. }) {
            anyhow::ensure!(
                advertised_version == Some(DELIVERY_CONTRACT_PROTOCOL_VERSION),
                "typed MIX cluster hand-off requires the current protocol version"
            );
        }
        return Ok(Some(RequestedNodeMessageDelivery::Explicit(contract)));
    }
    anyhow::ensure!(
        advertised_version.is_none_or(|version| version <= LEGACY_DELIVERY_PROTOCOL_MAX),
        "current cluster protocol message omitted its delivery contract"
    );
    Ok(Some(RequestedNodeMessageDelivery::LegacyInference))
}

async fn resolve_node_message_delivery<R: NodeMessageProjectionRepository>(
    verifier: &NodeMessageContractVerifier<R>,
    request: RequestedNodeMessageDelivery,
    stanza: &str,
    target_jid: &str,
) -> Result<ResolvedNodeMessageDelivery> {
    let request = match request {
        RequestedNodeMessageDelivery::LegacyInference => {
            RequestedNodeMessageProjection::LegacyInference
        }
        RequestedNodeMessageDelivery::Explicit(NodeDeliveryContract::Volatile {}) => {
            RequestedNodeMessageProjection::Volatile
        }
        RequestedNodeMessageDelivery::Explicit(NodeDeliveryContract::DurableC2s {
            recipient_id,
            message_id,
        }) => RequestedNodeMessageProjection::DurableC2s {
            recipient_id,
            message_id,
        },
        RequestedNodeMessageDelivery::Explicit(NodeDeliveryContract::DurableMix {
            delivery_id,
            lease_token,
        }) => RequestedNodeMessageProjection::DurableMix {
            delivery_id,
            lease_token,
        },
    };
    Ok(match verifier.resolve(request, stanza, target_jid).await? {
        VerifiedNodeMessageProjection::Volatile => ResolvedNodeMessageDelivery::Volatile,
        VerifiedNodeMessageProjection::Durable(delivery) => {
            ResolvedNodeMessageDelivery::Durable(delivery)
        }
        VerifiedNodeMessageProjection::Mix(delivery) => ResolvedNodeMessageDelivery::Mix(delivery),
    })
}

fn outbound_delivery_contract(
    stanza: &str,
    target_jid: &str,
    durable_delivery: Option<crate::outbound::DurableDelivery>,
    mix_delivery: Option<crate::outbound::MixDelivery>,
) -> Result<Option<NodeDeliveryContract>> {
    let document = roxmltree::Document::parse(stanza).context("cluster stanza is invalid XML")?;
    let is_message = document.root_element().tag_name().name() == "message";
    if !is_message {
        anyhow::ensure!(
            durable_delivery.is_none() && mix_delivery.is_none(),
            "non-message cluster stanza cannot be durable"
        );
        return Ok(None);
    }
    anyhow::ensure!(
        !(durable_delivery.is_some() && mix_delivery.is_some()),
        "cluster message cannot carry both C2S and MIX durable sources"
    );
    if let Some(delivery) = durable_delivery {
        anyhow::ensure!(
            matches!(
                crate::outbound::recipient_delivery_identity(stanza, target_jid),
                crate::outbound::RecipientDeliveryIdentity::Exact(_)
            ),
            "durable cluster message lacks an unambiguous recipient stanza-id"
        );
        return NodeDeliveryContract::from_durable(delivery).map(Some);
    }
    if let Some(delivery) = mix_delivery {
        anyhow::ensure!(
            crate::jid::CanonicalJid::parse(target_jid)?
                .resourcepart()
                .is_none(),
            "durable cluster MIX delivery requires a bare target"
        );
        return Ok(Some(NodeDeliveryContract::DurableMix {
            delivery_id: delivery.delivery_id,
            lease_token: delivery.lease_token,
        }));
    }
    Ok(Some(NodeDeliveryContract::Volatile {}))
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct MucOccupancyIdentity {
    nick: String,
    full_jid: String,
    cluster_epoch: uuid::Uuid,
    connection_id: uuid::Uuid,
}

impl MucOccupancyIdentity {
    #[allow(dead_code)] // Legacy Redis destroy compatibility; decoded identities remain wire-compatible.
    fn from_occupant(occupant: &crate::state::SerializableMucOccupant) -> Option<Self> {
        (!occupant.cluster_epoch.is_nil() && !occupant.connection_id.is_nil()).then(|| Self {
            nick: occupant.nick.clone(),
            full_jid: occupant.full_jid.clone(),
            cluster_epoch: occupant.cluster_epoch,
            connection_id: occupant.connection_id,
        })
    }
}

struct DeliveryAckExpectation<'a> {
    request_id: &'a str,
    nonce: &'a str,
    node_id: &'a str,
    target_jid: &'a str,
    primary: bool,
    delivery: Option<NodeDeliveryContract>,
    require_delivery_contract: bool,
    mix_capable_only: bool,
    transport_receipt_required: bool,
    mix_transport_receipt_required: bool,
}

fn validated_delivery_ack(
    payload: &str,
    expected: DeliveryAckExpectation<'_>,
) -> Option<NodeDeliveryReceipt> {
    if payload.len() > MAX_DELIVERY_ACK_BYTES {
        return None;
    }
    let ack: NodeDeliveryAck = serde_json::from_str(payload).ok()?;
    if ack.request_id != expected.request_id
        || ack.nonce != expected.nonce
        || ack.node_id != expected.node_id
    {
        return None;
    }
    if expected.require_delivery_contract && ack.delivery != expected.delivery {
        return None;
    }
    if expected.primary && ack.delivered > 1 {
        return None;
    }
    if expected.transport_receipt_required
        && (ack.delivered > 1 || (ack.delivered == 0) != ack.accepted_full_jid.is_none())
    {
        return None;
    }
    if expected.mix_transport_receipt_required {
        // A MIX recipient row is transferred to exactly one destination
        // resource.  The capability counters may describe every resource,
        // but the authoritative source can cross only one local boundary.
        if !matches!(
            expected.delivery,
            Some(NodeDeliveryContract::DurableMix { .. })
        ) || ack.delivered > 1
            || (ack.delivered == 0) != ack.accepted_full_jid.is_none()
            || (ack.delivered == 0) != ack.mix_handoff.is_none()
        {
            return None;
        }
    } else if ack.mix_handoff.is_some() {
        return None;
    }
    if expected.mix_capable_only {
        if ack.delivered > ack.mix_supported {
            return None;
        }
    } else if ack.mix_supported != 0 || ack.mix_unsupported != 0 || ack.mix_unknown != 0 {
        return None;
    }
    let accepted_full_jid = ack
        .accepted_full_jid
        .as_deref()
        .map(crate::jid::canonical_session_key)
        .transpose()
        .ok()?;
    if let Some(accepted) = accepted_full_jid.as_deref() {
        let target = crate::jid::CanonicalJid::parse(expected.target_jid).ok()?;
        let accepted_jid = crate::jid::CanonicalJid::parse(accepted).ok()?;
        if accepted_jid.resourcepart().is_none()
            || (target.resourcepart().is_some() && accepted != target.to_string())
            || (target.resourcepart().is_none() && accepted_jid.bare() != target.bare())
        {
            return None;
        }
    }
    if (ack.delivered == 0) != accepted_full_jid.is_none() && expected.primary {
        return None;
    }
    Some(NodeDeliveryReceipt {
        delivered: ack.delivered > 0,
        accepted_full_jid,
        acknowledged: true,
        mix_supported: ack.mix_supported,
        mix_unsupported: ack.mix_unsupported,
        mix_unknown: ack.mix_unknown,
        mix_handoff: ack.mix_handoff,
    })
}

fn session_route_keys(full_jid: &str) -> Result<(String, String)> {
    let full = crate::jid::canonical_session_key(full_jid)?;
    let bare = crate::jid::canonical_bare_key(&full)?;
    Ok((full, bare))
}

fn node_delivery_stanza(stanza: &str, carbons_only: bool, session_key: &str) -> String {
    if !carbons_only {
        return stanza.to_owned();
    }
    let Ok(exact_full_jid) = crate::jid::canonical_session_key(session_key) else {
        return stanza.to_owned();
    };
    crate::xmpp::xml_util::set_to(stanza, &exact_full_jid)
}

/// The remote cluster worker owns a concrete C2S route while awaiting a
/// typed MIX hand-off.  If the request task is cancelled or the driver drops
/// its completion channel, the route is torn down before an old queued item
/// can become visible after its database lease is released for retry.
struct PendingClusterMixHandoff {
    sender: crate::outbound::OutboundSender,
    disconnect: CancellationToken,
    completed: bool,
}

impl PendingClusterMixHandoff {
    fn new(sender: crate::outbound::OutboundSender, disconnect: CancellationToken) -> Self {
        Self {
            sender,
            disconnect,
            completed: false,
        }
    }

    fn mark_completed(&mut self) {
        self.completed = true;
    }
}

impl Drop for PendingClusterMixHandoff {
    fn drop(&mut self) {
        if !self.completed {
            self.sender.disconnect_backpressured_transport();
            self.disconnect.cancel();
        }
    }
}

/// Enqueue an exact remote MIX source and wait for a typed durable boundary.
/// There is intentionally no synthetic ownership timeout: a socket writer
/// fences the source before bytes, while SM and BOSH persist it.  Cancellation
/// closes only this route and leaves the database fence reclaimable.
async fn try_send_cluster_mix_transport(
    sender: &crate::outbound::OutboundSender,
    disconnect: &CancellationToken,
    stanza: String,
    source: crate::outbound::MixDelivery,
) -> Result<crate::outbound::MixTransportCompletion> {
    let receiver = match sender.try_send_durable_mix(stanza, source) {
        Ok(receiver) => receiver,
        Err(tokio::sync::mpsc::error::TrySendError::Full(_)) => {
            sender.disconnect_backpressured_transport();
            disconnect.cancel();
            anyhow::bail!("remote MIX resource output queue is full");
        }
        Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => {
            sender.disconnect_backpressured_transport();
            disconnect.cancel();
            anyhow::bail!("remote MIX resource output queue is closed");
        }
    };
    let mut pending = PendingClusterMixHandoff::new(sender.clone(), disconnect.clone());
    let completion = receiver
        .await
        .context("remote MIX resource closed before durable hand-off")?;
    pending.mark_completed();
    Ok(completion)
}

/// Privacy lists are resource scoped, while both Carbon wrappers are addressed
/// between resources of the same account. The policy peer must therefore come
/// from the forwarded stanza: `from` for a received Carbon and `to` for a sent
/// Carbon. Looking only at the outer wrapper would turn every sent Carbon into
/// apparent self-traffic and bypass a deny rule on another cluster node.
fn delivery_privacy_peer(
    document: &roxmltree::Document<'_>,
    carbons_only: bool,
) -> Option<(String, crate::db::PrivacyStanzaKind)> {
    let root = document.root_element();
    let kind = match root.tag_name().name() {
        "message" => crate::db::PrivacyStanzaKind::Message,
        "iq" => crate::db::PrivacyStanzaKind::Iq,
        "presence" => crate::db::PrivacyStanzaKind::PresenceIn,
        _ => return None,
    };
    let peer = if carbons_only {
        let mut wrappers = root.children().filter(|child| {
            child.is_element()
                && child.tag_name().namespace() == Some("urn:xmpp:carbons:2")
                && matches!(child.tag_name().name(), "sent" | "received")
        });
        let wrapper = wrappers.next()?;
        if wrappers.next().is_some() {
            return None;
        }
        let mut forwarded_nodes = wrapper.children().filter(|child| {
            child.is_element()
                && child.tag_name().namespace() == Some("urn:xmpp:forward:0")
                && child.tag_name().name() == "forwarded"
        });
        let forwarded = forwarded_nodes.next()?;
        if forwarded_nodes.next().is_some() {
            return None;
        }
        let mut messages = forwarded.children().filter(|child| {
            child.is_element()
                && child.tag_name().namespace() == Some("jabber:client")
                && child.tag_name().name() == "message"
        });
        let message = messages.next()?;
        if messages.next().is_some() {
            return None;
        }
        match wrapper.tag_name().name() {
            "received" => message.attribute("from"),
            "sent" => message.attribute("to"),
            _ => None,
        }
    } else {
        root.attribute("from")
    };
    crate::jid::canonicalize(peer?)
        .ok()
        .map(|peer| (peer, kind))
}

fn delivery_exclusions(json: &serde_json::Value) -> HashSet<String> {
    if let Some(values) = json["exclude_jids"]
        .as_array()
        .filter(|values| values.len() <= MAX_DELIVERY_EXCLUSIONS)
    {
        let parsed = values
            .iter()
            .map(|value| {
                value
                    .as_str()
                    .and_then(|jid| crate::jid::canonical_session_key(jid).ok())
            })
            .collect::<Option<HashSet<_>>>();
        if let Some(parsed) = parsed {
            return parsed;
        }
    }
    json["exclude_jid"]
        .as_str()
        .and_then(|jid| crate::jid::canonical_session_key(jid).ok())
        .into_iter()
        .collect()
}

fn delivery_carbon_muc_scope(json: &serde_json::Value) -> Result<Option<(String, String)>, ()> {
    match (
        json["carbon_muc_room"].as_str(),
        json["carbon_muc_nick"].as_str(),
    ) {
        (None, None) => Ok(None),
        (Some(room), Some(nick)) => Ok(Some((
            crate::jid::canonicalize_bare(room).map_err(|_| ())?,
            crate::xmpp::xml_util::prepare_muc_nick(nick).map_err(|_| ())?,
        ))),
        _ => Err(()),
    }
}

/// Admission decisions share the live health state without Redis or publication authority.
#[derive(Clone)]
pub(crate) struct ClusterAdmission {
    health: Arc<ClusterHealth>,
}
impl ClusterAdmission {
    pub(crate) fn admit(&self, operation: ClusterOperation) -> Result<()> {
        admit_health(&self.health, operation)
    }
}
fn admit_health(health: &ClusterHealth, operation: ClusterOperation) -> Result<()> {
    let state = health.state.load(Ordering::Acquire);
    if operation_allowed(state, operation) {
        return Ok(());
    }
    match state {
        CLUSTER_RECONCILING => anyhow::bail!("cluster control plane is reconciling"),
        CLUSTER_DURABLE_DIRECT_ONLY => anyhow::bail!(
            "cluster control plane is degraded; only PostgreSQL-spooled direct messages are accepted"
        ),
        CLUSTER_FAIL_CLOSED => anyhow::bail!("cluster control plane is unavailable"),
        CLUSTER_SHUTDOWN_REQUIRED => anyhow::bail!("cluster safety lease expired"),
        _ => anyhow::bail!("cluster control plane is in an invalid state"),
    }
}

#[derive(Clone)]
pub struct ClusterManager {
    pub node_id: String,
    namespace: String,
    key_prefix: String,
    pool: Option<Pool<RedisConnectionManager>>,
    client: Option<redis::Client>,
    security: Option<Arc<crate::cluster_security::ClusterSecurityConfig>>,
    connection_uuid: uuid::Uuid,
    instance_epoch: Arc<AtomicI64>,
    authorized_instances: Arc<dashmap::DashMap<String, AuthorizedClusterInstance>>,
    authorized_peer_keys: Arc<dashmap::DashMap<String, AuthorizedPeerKeys>>,
    #[cfg(test)]
    replay_cache: Arc<dashmap::DashMap<String, i64>>,
    #[cfg(test)]
    replay_cache_gate: Arc<Mutex<()>>,
    #[cfg(test)]
    replay_cache_next_expiry: Arc<AtomicI64>,
    #[cfg(test)]
    replay_cache_sweeps: Arc<AtomicU64>,
    authority_pool: Arc<std::sync::OnceLock<sqlx::PgPool>>,
    health: Arc<ClusterHealth>,
    publication_gate: Arc<tokio::sync::RwLock<()>>,
    muc_outbox_notify: Arc<tokio::sync::Notify>,
    account_revocation_notify: Arc<tokio::sync::Notify>,
    listener_rotation: Arc<tokio::sync::Notify>,
    pending_ack_slots: Arc<tokio::sync::Semaphore>,
    pending_acks: Arc<dashmap::DashMap<String, PendingClusterAck>>,
}

/// MIX route discovery reads current PostgreSQL session ownership without
/// receiving publication, Redis, or session-mutation authority.
#[derive(Clone)]
pub(crate) struct ClusterMixRouteLookup {
    routes: ClusterListenerPresenceRoutes,
}

impl ClusterMixRouteLookup {
    pub(crate) async fn lookup_nodes(&self, jid: &str) -> Result<Vec<String>> {
        self.routes.lookup_nodes(jid).await
    }

    pub(crate) fn node_id(&self) -> &str {
        self.routes.node_id()
    }
}

/// The PubSub reader's connection, self-loop and generation fence. This handle
/// cannot sign a command, consume replay authority or dispatch an ACK.
#[derive(Clone)]
pub(crate) struct ClusterPubsubListenerTransport {
    client: Option<redis::Client>,
    pool: Option<Pool<RedisConnectionManager>>,
    key_prefix: String,
    node_id: String,
    connection_uuid: uuid::Uuid,
    instance_epoch: Arc<AtomicI64>,
    health: Arc<ClusterHealth>,
    listener_rotation: Arc<tokio::sync::Notify>,
    failure_policy: Option<crate::cluster_security::ClusterFailurePolicy>,
}

impl ClusterPubsubListenerTransport {
    fn is_enabled(&self) -> bool {
        self.pool.is_some()
    }

    fn key(&self, suffix: String) -> String {
        format!("{}:{suffix}", self.key_prefix)
    }

    fn rotation_already_required(&self) -> bool {
        self.health.listener_generation.load(Ordering::Acquire)
            < self
                .health
                .required_listener_generation
                .load(Ordering::Acquire)
    }

    fn record_listener_failure(&self, error: &anyhow::Error) {
        record_cluster_failure(
            &self.health,
            &self.listener_rotation,
            self.is_enabled(),
            self.failure_policy,
            ClusterFailureClass::PubSub,
            error,
        );
    }

    fn confirm_generation(&self, generation: u64, rotation_epoch: u64) -> Result<()> {
        confirm_listener_generation(&self.health, generation, rotation_epoch)
    }
}

/// Listener-only admission after a signed envelope has passed durable replay
/// verification. This can check the current generation and match a pending
/// ACK, but cannot sign, publish or admit an envelope into PostgreSQL.
#[derive(Clone)]
pub(crate) struct ClusterListenerAdmission {
    health: Arc<ClusterHealth>,
    pending_acks: Arc<dashmap::DashMap<String, PendingClusterAck>>,
}

impl ClusterListenerAdmission {
    fn validate_generation(&self, generation: u64, rotation_epoch: u64) -> Result<()> {
        validate_listener_generation_health(&self.health, generation, rotation_epoch)
    }

    fn dispatch_pending_ack(&self, source_node: &str, payload: serde_json::Value) -> bool {
        dispatch_pending_ack(&self.pending_acks, source_node, payload)
    }

    fn note_authentication_failure(&self, error: &anyhow::Error) {
        note_cluster_authentication_failure(&self.health, error);
    }

    fn note_incompatible_peer_version(&self, node_id: &str, observed: Option<&str>) {
        note_incompatible_peer_version(&self.health, node_id, observed);
    }
}

impl ClusterListenerSecurity {
    fn verify_current_envelope(
        &self,
        raw: &str,
        channel: &str,
        expected_source: Option<&str>,
    ) -> Result<crate::cluster_security::SignedClusterEnvelope> {
        anyhow::ensure!(
            raw.len() <= MAX_CLUSTER_PAYLOAD_BYTES,
            "cluster envelope is oversized"
        );
        let security = self
            .publisher
            .security
            .as_ref()
            .context("cluster verifier is not configured")?;
        let envelope: crate::cluster_security::SignedClusterEnvelope =
            serde_json::from_str(raw).context("cluster envelope is invalid JSON")?;
        envelope.verify(
            &self.publisher.namespace,
            &self.publisher.node_id,
            channel,
            expected_source,
            security.peers().as_ref(),
            chrono::Utc::now().timestamp(),
        )?;
        self.validate_verified_envelope(&envelope)?;
        Ok(envelope)
    }

    fn validate_verified_envelope(
        &self,
        envelope: &crate::cluster_security::SignedClusterEnvelope,
    ) -> Result<()> {
        let security = self
            .publisher
            .security
            .as_ref()
            .context("cluster verifier is not configured")?;
        envelope
            .current_verification_key(security.peers().as_ref(), chrono::Utc::now().timestamp())?;
        anyhow::ensure!(
            envelope.destination_connection_uuid == self.publisher.connection_uuid
                && envelope.destination_connection_epoch
                    == self.publisher.instance_epoch.load(Ordering::Acquire)
                && envelope.destination_key_id == security.current_key_id
                && envelope.destination_key_epoch == security.key_epoch,
            "cluster destination process instance or key is mismatched"
        );
        let key_authority = self
            .authorized_peer_keys
            .get(&envelope.source_node)
            .context("cluster source key has no current PostgreSQL authority cache")?;
        anyhow::ensure!(
            key_authority.accepts(&envelope.key_id, envelope.key_epoch, Instant::now()),
            "cluster source key generation is staged incorrectly, stale, or retired"
        );
        let authority = self
            .publisher
            .authorized_instances
            .get(&envelope.source_node)
            .context("cluster source process has no active PostgreSQL instance lease")?;
        anyhow::ensure!(
            authoritative_instance_matches(
                &authority,
                envelope.connection_uuid,
                envelope.connection_epoch,
                &envelope.key_id,
                envelope.key_epoch,
                Instant::now(),
            ),
            "cluster source process instance lease is stale or mismatched"
        );
        Ok(())
    }

    async fn verify_signed_payload_persisted(
        &self,
        raw: &str,
        channel: &str,
        expected_source: Option<&str>,
    ) -> Result<crate::cluster_security::SignedClusterEnvelope> {
        let envelope = self.verify_current_envelope(raw, channel, expected_source)?;
        if envelope.kind == crate::cluster_security::ClusterCommandKind::Ack {
            anyhow::ensure!(
                serde_json::to_vec(&envelope.payload)?.len() <= MAX_DELIVERY_ACK_BYTES,
                "cluster acknowledgement payload is oversized"
            );
        }
        let pool = self
            .authority_pool
            .get()
            .context("cluster replay authority pool is unavailable")?;
        let admitted = match crate::db::admit_cluster_envelope_replay(
            pool,
            &self.publisher.namespace,
            &envelope,
        )
        .await
        {
            Ok(admitted) => admitted,
            Err(error) => {
                // PostgreSQL replay failures are control-plane failures, not
                // unauthenticated traffic. Rotate and fail closed for repair.
                record_cluster_failure(
                    &self.publisher.health,
                    &self.publisher.listener_rotation,
                    self.publisher.is_enabled(),
                    self.publisher.failure_policy,
                    ClusterFailureClass::PostgreSqlAuthority,
                    &error,
                );
                return Err(error);
            }
        };
        if !admitted {
            self.publisher
                .health
                .replay_rejections
                .fetch_add(1, Ordering::Relaxed);
            anyhow::bail!("cluster envelope replay rejected by PostgreSQL authority");
        }
        // The durable unique fence has committed. A process-local replay
        // cache must not reject this already-consumed command afterward.
        Ok(envelope)
    }

    async fn publish_ack(
        &self,
        admission: &ClusterListenerAdmission,
        source_node: &str,
        ack: NodeDeliveryAck,
        authority: &ListenerCommandAuthority,
    ) -> Result<()> {
        let Some(pool) = &self.publisher.pool else {
            return Ok(());
        };
        let mut conn = pool.get().await?;
        authority.validate(admission, self)?;
        let channel = self.publisher.key(format!("node:{source_node}"));
        self.publisher
            .publish_signed(&mut conn, source_node, &channel, serde_json::to_value(ack)?)
            .await?;
        Ok(())
    }
}

/// Authenticate and durably admit listener envelopes, then publish only their
/// correlated acknowledgements. This has no command routing or Redis mutation
/// authority beyond the signed ACK channel.
#[derive(Clone)]
pub(crate) struct ClusterListenerSecurity {
    publisher: ClusterSignedPublisher,
    authorized_peer_keys: Arc<dashmap::DashMap<String, AuthorizedPeerKeys>>,
    authority_pool: Arc<std::sync::OnceLock<sqlx::PgPool>>,
}

/// Immutable identity used by the readiness persistence probe. Capturing the
/// local lease epoch alongside the configured key avoids passing live cluster
/// control-plane authority into the service or repository.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ClusterReadinessAuthority {
    pub(crate) key_identity: crate::db::ClusterKeyDeploymentIdentity,
    pub(crate) instance_node_id: String,
    pub(crate) instance_uuid: uuid::Uuid,
    pub(crate) instance_epoch: i64,
    pub(crate) signing_key_id: String,
    pub(crate) signing_key_epoch: i64,
}

/// Read-only health and exact identity view. This has no Redis, signing,
/// publication, or instance-claim authority.
#[derive(Clone)]
pub(crate) struct ClusterReadinessProbe {
    health: Arc<ClusterHealth>,
    authority: Option<ClusterReadinessAuthority>,
    instance_epoch: Arc<AtomicI64>,
}

/// Exactly the cluster identity, wakeup, and fail-closed reporting authority
/// needed by the committed account-revocation consumer. No Redis client,
/// publication key, or broader cluster control plane crosses this boundary.
#[derive(Clone)]
pub(crate) struct ClusterRevocationAuthority {
    domain: String,
    node_id: String,
    instance_uuid: uuid::Uuid,
    instance_epoch: Arc<AtomicI64>,
    notify: Arc<tokio::sync::Notify>,
    enabled: bool,
    failure_policy: Option<crate::cluster_security::ClusterFailurePolicy>,
    health: Arc<ClusterHealth>,
    listener_rotation: Arc<tokio::sync::Notify>,
}

/// The failure supervisor can validate PostgreSQL identity, refresh peer
/// caches and fence cluster admission. It cannot publish, sign or issue Redis
/// commands.
#[derive(Clone)]
pub(crate) struct ClusterFailureSupervisorAuthority {
    enabled: bool,
    readiness: Option<ClusterReadinessAuthority>,
    instance_epoch: Arc<AtomicI64>,
    domain: String,
    peer_nodes: Vec<String>,
    expected_peer_keys: Vec<crate::db::ExpectedClusterPeerKey>,
    authorized_peer_keys: Arc<dashmap::DashMap<String, AuthorizedPeerKeys>>,
    authorized_instances: Arc<dashmap::DashMap<String, AuthorizedClusterInstance>>,
    health: Arc<ClusterHealth>,
    listener_rotation: Arc<tokio::sync::Notify>,
    failure_policy: Option<crate::cluster_security::ClusterFailurePolicy>,
    safety_lease_seconds: Option<u64>,
}

/// The maintenance worker may observe readiness and record a failed Redis
/// projection without receiving signing or publication authority.
#[derive(Clone)]
pub(crate) struct ClusterMaintenanceControl {
    node_id: String,
    enabled: bool,
    peer_authority: ClusterFailureSupervisorAuthority,
    health: Arc<ClusterHealth>,
    listener_rotation: Arc<tokio::sync::Notify>,
    failure_policy: Option<crate::cluster_security::ClusterFailurePolicy>,
}

/// Shared signed command publication without listener replay, database, or
/// session-routing authority. Only cluster-owned projections use this signer.
#[derive(Clone)]
struct ClusterSignedPublisher {
    pool: Option<Pool<RedisConnectionManager>>,
    namespace: String,
    key_prefix: String,
    node_id: String,
    security: Option<Arc<crate::cluster_security::ClusterSecurityConfig>>,
    connection_uuid: uuid::Uuid,
    instance_epoch: Arc<AtomicI64>,
    authorized_instances: Arc<dashmap::DashMap<String, AuthorizedClusterInstance>>,
    health: Arc<ClusterHealth>,
    listener_rotation: Arc<tokio::sync::Notify>,
    failure_policy: Option<crate::cluster_security::ClusterFailurePolicy>,
    publication_gate: Arc<tokio::sync::RwLock<()>>,
}

/// Bounded correlated control ACKs shared by the manager and teardown notifier.
/// It can publish authenticated controls but cannot discover or mutate routes.
#[derive(Clone)]
struct ClusterCorrelatedControlSender {
    publisher: ClusterSignedPublisher,
    transport_ready: bool,
    pending_ack_slots: Arc<tokio::sync::Semaphore>,
    pending_acks: Arc<dashmap::DashMap<String, PendingClusterAck>>,
}

/// Signed, acknowledged stanza delivery. This projection can neither mutate
/// session routes nor consume listener replay authority.
#[derive(Clone)]
pub(crate) struct ClusterNodeDelivery {
    publisher: ClusterSignedPublisher,
    pool: Option<Pool<RedisConnectionManager>>,
    client: Option<redis::Client>,
    health: Arc<ClusterHealth>,
    pending_ack_slots: Arc<tokio::sync::Semaphore>,
    pending_acks: Arc<dashmap::DashMap<String, PendingClusterAck>>,
}

#[derive(Clone)]
pub(crate) struct ClusterUnavailableDelivery {
    routes: ClusterListenerPresenceRoutes,
    sender: ClusterNodeDelivery,
}

/// Post-commit revocation controls can discover only PostgreSQL-owned routes
/// and send exact, signed, acknowledged account/session teardowns.
#[derive(Clone)]
pub(crate) struct ClusterAccountTeardownNotifier {
    routes: ClusterListenerPresenceRoutes,
    sender: ClusterCorrelatedControlSender,
}

/// Exact durable SM session teardown control, without route mutation or
/// general cluster publication authority.
#[derive(Clone)]
pub(crate) struct ClusterSmSessionTeardownNotifier {
    routes: ClusterListenerPresenceRoutes,
    sender: ClusterCorrelatedControlSender,
}

/// Exact clustered SM MUC teardown with correlated ACKs and a fenced Redis
/// tombstone. It cannot publish arbitrary stanzas or change other occupancies.
#[derive(Clone)]
pub(crate) struct ClusterSmMucTeardown {
    sender: ClusterCorrelatedControlSender,
}

/// Exact local occupant withdrawal followed by its signed room presence.
/// This handle cannot join a room or mutate another occupant's role.
#[derive(Clone)]
pub(crate) struct ClusterMucDeparture {
    projection: ClusterSmMucTeardownProjection,
    publisher: ClusterSignedPublisher,
}

impl ClusterMucDeparture {
    pub(crate) async fn publish_local_departure(
        &self,
        departed: &crate::state::MucOccupant,
        was_last: bool,
    ) -> Result<()> {
        self.projection
            .unregister_muc_occupant_epoch(
                &departed.room_jid,
                &departed.nick,
                departed.cluster_epoch,
                departed.connection_id,
            )
            .await?;
        if was_last {
            self.projection.leave_muc(&departed.room_jid).await?;
        }
        self.publisher
            .send_muc_presence_with_status(
                &departed.room_jid,
                &crate::state::SerializableMucOccupant::from(departed),
                true,
                false,
                None,
                None,
                None,
                None,
            )
            .await
    }
}

/// Exact SM/MUC suspension projection and committed-operation wake. It can
/// neither consume listener replay authority nor access PostgreSQL directly.
#[derive(Clone)]
pub(crate) struct ClusterSmSuspension {
    publisher: ClusterSignedPublisher,
    muc_outbox_notify: Arc<tokio::sync::Notify>,
}

/// Publish only a committed MUC operation wake using the shared signed
/// cluster transport; no SM suspension or route mutation authority is exposed.
#[derive(Clone)]
pub(crate) struct ClusterMucOperationWake {
    publisher: ClusterSignedPublisher,
    muc_outbox_notify: Arc<tokio::sync::Notify>,
}

impl ClusterSignedPublisher {
    fn is_enabled(&self) -> bool {
        self.pool.is_some()
    }

    fn key(&self, suffix: String) -> String {
        format!("{}:{suffix}", self.key_prefix)
    }

    async fn active_muc_nodes(&self, room_jid: &str) -> Result<Vec<String>> {
        let Some(pool) = &self.pool else {
            return Ok(Vec::new());
        };
        let room = crate::jid::canonicalize_bare(room_jid)?;
        let mut conn = pool.get().await?;
        let key = self.key(format!("muc_nodes:{room}"));
        // Fan-out uses bounded live-node hints; full reconciliation belongs
        // to maintenance and explicit room reads. The peer limit includes one
        // extra slot for this process.
        let script = redis::Script::new(
            r#"
            if redis.call('scard', KEYS[1]) > tonumber(ARGV[2]) then
                return redis.error_reply('MUC routing node hint limit exceeded')
            end
            local nodes = redis.call('smembers', KEYS[1])
            for _, node in ipairs(nodes) do
                if #node == 0 or #node > tonumber(ARGV[3]) then
                    return redis.error_reply('MUC routing node hint has an invalid length')
                end
            end
            local active = {}
            local stale = {}
            for _, node in ipairs(nodes) do
                if redis.call('get', ARGV[1] .. node .. ':alive') then
                    table.insert(active, node)
                else
                    table.insert(stale, node)
                end
            end
            for _, node in ipairs(stale) do
                redis.call('srem', KEYS[1], node)
            end
            return active
            "#,
        );
        let mut nodes: Vec<String> = script
            .key(key)
            .arg(self.key("node:".to_owned()))
            .arg(crate::cluster_security::MAX_PEERS + 1)
            .arg(crate::cluster_security::MAX_NODE_ID_BYTES)
            .invoke_async(&mut *conn)
            .await?;
        nodes.sort_unstable();
        Ok(nodes)
    }

    #[allow(clippy::too_many_arguments)]
    async fn send_muc_presence_with_status(
        &self,
        room_jid: &str,
        occupant: &crate::state::SerializableMucOccupant,
        unavailable: bool,
        created: bool,
        id: Option<&str>,
        removal_status: Option<u16>,
        actor_nick: Option<&str>,
        reason: Option<&str>,
    ) -> Result<()> {
        let Some(pool) = &self.pool else {
            return Ok(());
        };
        let nodes = self.active_muc_nodes(room_jid).await?;
        let payload = serde_json::json!({
            "target": room_jid,
            "muc_presence": true,
            "occupant": occupant,
            "unavailable": unavailable,
            "created": created,
            "id": id,
            "removal_status": removal_status,
            "actor_nick": actor_nick,
            "reason": reason,
        });
        let mut conn = pool.get().await?;
        for node_id in nodes {
            if node_id != self.node_id {
                let channel = self.key(format!("node:{node_id}"));
                let _ = self
                    .publish_signed(&mut conn, &node_id, &channel, payload.clone())
                    .await?;
            }
        }
        Ok(())
    }

    fn process_instance_token(&self) -> Result<String> {
        let epoch = self.instance_epoch.load(Ordering::Acquire);
        anyhow::ensure!(epoch >= 1, "cluster process instance is not authoritative");
        Ok(format!("{}.{}", self.connection_uuid.simple(), epoch))
    }

    fn process_alive_key(&self) -> Result<String> {
        Ok(self.key(format!(
            "node_instance:{}:{}:alive",
            self.node_id,
            self.process_instance_token()?
        )))
    }

    fn sign_payload(
        &self,
        destination_node: &str,
        channel: &str,
        payload: serde_json::Value,
    ) -> Result<String> {
        let security = self
            .security
            .as_ref()
            .context("cluster signer is not configured")?;
        let destination = self
            .authorized_instances
            .get(destination_node)
            .context("cluster destination process authority is unavailable")?;
        anyhow::ensure!(
            destination.valid_until > Instant::now() && destination.refresh_until > Instant::now(),
            "cluster destination process authority is stale"
        );
        let kind = crate::cluster_security::infer_kind(&payload)?;
        let envelope = crate::cluster_security::SignedClusterEnvelope::sign(
            &security.signer(),
            &self.namespace,
            &self.node_id,
            destination_node,
            destination.instance_uuid,
            destination.instance_epoch,
            &destination.signing_key_id,
            destination.signing_key_epoch,
            channel,
            kind,
            self.connection_uuid,
            self.instance_epoch.load(Ordering::Acquire),
            payload,
            chrono::Utc::now().timestamp(),
        )?;
        let encoded =
            serde_json::to_string(&envelope).context("could not encode signed cluster envelope")?;
        anyhow::ensure!(
            encoded.len() <= MAX_CLUSTER_PAYLOAD_BYTES,
            "cluster envelope exceeds the transport limit"
        );
        Ok(encoded)
    }

    async fn publish_signed(
        &self,
        conn: &mut redis::aio::MultiplexedConnection,
        destination_node: &str,
        channel: &str,
        payload: serde_json::Value,
    ) -> Result<i32> {
        let _publication = self.publication_gate.read().await;
        admit_health(&self.health, ClusterOperation::VolatileDelivery)?;
        let encoded = self.sign_payload(destination_node, channel, payload)?;
        match conn.publish(channel, encoded).await {
            Ok(receivers) if receivers > 0 => Ok(receivers),
            Ok(_) => {
                let failure =
                    anyhow::anyhow!("signed cluster publish had no authoritative subscriber");
                self.record_control_plane_failure(&failure);
                Err(failure)
            }
            Err(error) => {
                let failure = anyhow::Error::new(error).context("signed cluster publish failed");
                self.record_control_plane_failure(&failure);
                Err(failure)
            }
        }
    }

    fn record_control_plane_failure(&self, error: &anyhow::Error) {
        record_cluster_failure(
            &self.health,
            &self.listener_rotation,
            self.is_enabled(),
            self.failure_policy,
            ClusterFailureClass::RedisCommand,
            error,
        );
    }
}

impl ClusterCorrelatedControlSender {
    async fn send_control_to_node(
        &self,
        node_id: &str,
        target: &str,
        payload: serde_json::Value,
    ) -> Result<()> {
        let acknowledgement = self
            .send_control_to_node_ack(node_id, target, payload)
            .await?;
        anyhow::ensure!(
            acknowledgement.control_processed == Some(true),
            "cluster control was rejected by its authoritative receiver"
        );
        Ok(())
    }

    async fn send_control_to_node_ack(
        &self,
        node_id: &str,
        target: &str,
        mut payload: serde_json::Value,
    ) -> Result<NodeDeliveryAck> {
        let Some(pool) = self
            .publisher
            .pool
            .as_ref()
            .filter(|_| self.transport_ready)
        else {
            anyhow::bail!("cluster control requested without an active cluster transport");
        };
        let request_id = uuid::Uuid::new_v4().to_string();
        let nonce = format!("{}{}", uuid::Uuid::new_v4(), uuid::Uuid::new_v4());
        let mut conn = pool.get().await?;
        let peer_version: Option<String> = conn
            .get(self.publisher.key(format!("node:{node_id}:alive")))
            .await?;
        if !supports_current_cluster_protocol(peer_version.as_deref()) {
            if peer_version.is_some() {
                note_incompatible_peer_version(
                    &self.publisher.health,
                    node_id,
                    peer_version.as_deref(),
                );
            }
            anyhow::bail!("cluster peer does not support authenticated current-version controls");
        }
        let Some(fields) = payload.as_object_mut() else {
            anyhow::bail!("cluster control payload is not an object");
        };
        anyhow::ensure!(
            fields.get("target").and_then(serde_json::Value::as_str) == Some(target),
            "cluster control target mismatch"
        );
        fields.insert("request_id".to_owned(), request_id.clone().into());
        fields.insert("ack_nonce".to_owned(), nonce.clone().into());
        fields.insert("protocol_version".to_owned(), NODE_PROTOCOL_VERSION.into());
        let channel = self.publisher.key(format!("node:{node_id}"));
        let mut acknowledgement = register_pending_ack_in(
            &self.pending_ack_slots,
            &self.pending_acks,
            &request_id,
            node_id,
            &nonce,
        )?;
        let result = async {
            let receivers = self
                .publisher
                .publish_signed(&mut conn, node_id, &channel, payload)
                .await?;
            // Keep only the bounded registration while the peer publishes its
            // ACK; the listener needs this pool to send that ACK.
            drop(conn);
            if receivers == 0 {
                let error = anyhow::anyhow!("cluster control had no subscriber");
                self.publisher.record_control_plane_failure(&error);
                return Err(error);
            }
            let deadline = tokio::time::Instant::now() + DELIVERY_ACK_TIMEOUT;
            loop {
                let Some(ack) = tokio::time::timeout_at(deadline, acknowledgement.recv())
                    .await
                    .ok()
                    .flatten()
                else {
                    let error = anyhow::anyhow!("cluster control acknowledgement timed out");
                    self.publisher.record_control_plane_failure(&error);
                    return Err(error);
                };
                if ack.control_processed.is_some() {
                    return Ok(ack);
                }
            }
        }
        .await;
        result
    }
}

impl ClusterAccountTeardownNotifier {
    pub(crate) async fn send_account_generation_teardown(
        &self,
        bare_jid: &str,
        user_id: uuid::Uuid,
        minimum_generation: i64,
    ) -> Result<()> {
        anyhow::ensure!(minimum_generation >= 0, "invalid auth generation");
        let bare_jid = crate::jid::canonicalize_bare(bare_jid)?;
        if !self.sender.publisher.is_enabled() {
            return Ok(());
        }
        let nodes = self.routes.lookup_nodes(&bare_jid).await?;
        let payload = serde_json::json!({
            "target": bare_jid,
            "account_generation_teardown": true,
            "user_id": user_id,
            "minimum_generation": minimum_generation,
        });
        for node_id in nodes {
            if node_id != self.routes.node_id() {
                self.sender
                    .send_control_to_node(&node_id, &bare_jid, payload.clone())
                    .await?;
            }
        }
        Ok(())
    }

    pub(crate) async fn send_session_instance_termination(
        &self,
        full_jid: &str,
        expected_connection_id: uuid::Uuid,
    ) -> Result<bool> {
        anyhow::ensure!(
            !expected_connection_id.is_nil(),
            "session termination requires a non-nil connection identity"
        );
        let full_jid = crate::jid::canonical_session_key(full_jid)?;
        if !self.sender.publisher.is_enabled() {
            return Ok(false);
        }
        let authority_pool = self
            .routes
            .authority_pool
            .get()
            .context("cluster session authority pool is unavailable")?;
        let Some(route) = crate::db::cluster_session_route_authority(
            authority_pool,
            &self.routes.namespace,
            &full_jid,
        )
        .await?
        else {
            return Ok(false);
        };
        if route.connection_uuid != expected_connection_id
            || route.owner_node_id == self.routes.node_id()
        {
            return Ok(false);
        }
        let payload = serde_json::json!({
            "target":full_jid,
            "session_termination":true,
            "connection_id":expected_connection_id,
        });
        let acknowledgement = self
            .sender
            .send_control_to_node_ack(&route.owner_node_id, &full_jid, payload)
            .await?;
        match acknowledgement.control_outcome {
            Some(ClusterControlOutcome::Matched) => Ok(true),
            Some(ClusterControlOutcome::AuthoritativelyAbsent) => Ok(false),
            Some(ClusterControlOutcome::WrongOwner) => {
                anyhow::bail!("cluster session termination reached the wrong process owner")
            }
            None => {
                anyhow::bail!("cluster session termination acknowledgement omitted its outcome")
            }
        }
    }
}

impl ClusterSmSessionTeardownNotifier {
    pub(crate) async fn send_sm_session_teardown(
        &self,
        full_jid: &str,
        sm_session_id: uuid::Uuid,
    ) -> Result<()> {
        let full_jid = crate::jid::canonical_session_key(full_jid)?;
        if !self.sender.publisher.is_enabled() {
            return Ok(());
        }
        let started = tokio::time::Instant::now();
        let nodes = self.routes.lookup_nodes(&full_jid).await;
        tracing::debug!(
            elapsed_ms = started.elapsed().as_millis(),
            success = nodes.is_ok(),
            "Redis session-route lookup completed"
        );
        let nodes = nodes?;
        let payload = serde_json::json!({
            "target": full_jid,
            "sm_session_teardown": true,
            "sm_session_id": sm_session_id,
        });
        for node_id in nodes {
            if node_id != self.routes.node_id() {
                self.sender
                    .send_control_to_node(&node_id, &full_jid, payload.clone())
                    .await?;
            }
        }
        Ok(())
    }
}

impl ClusterSmMucTeardown {
    /// Acknowledge every current room node before writing the exact SM
    /// tombstone and removing matching Redis occupancy indexes.
    pub(crate) async fn send_sm_muc_teardown(
        &self,
        room_jid: &str,
        sm_session_id: uuid::Uuid,
        occupant: &crate::state::SerializableMucOccupant,
    ) -> Result<()> {
        let Some(pool) = &self.sender.publisher.pool else {
            return Ok(());
        };
        let room_jid = crate::jid::canonicalize_bare(room_jid)?;
        let nick = crate::xmpp::xml_util::prepare_muc_nick(&occupant.nick)?;
        let nodes = self.sender.publisher.active_muc_nodes(&room_jid).await?;
        let occupants_key = self
            .sender
            .publisher
            .key(format!("muc_occupants:{room_jid}"));
        let owners_key = self
            .sender
            .publisher
            .key(format!("muc_occupant_nodes:{room_jid}"));
        let nodes_key = self.sender.publisher.key(format!("muc_nodes:{room_jid}"));
        let instances_key = self
            .sender
            .publisher
            .key(format!("muc_occupant_instances:{room_jid}"));
        let node_counts_key = self
            .sender
            .publisher
            .key(format!("muc_node_counts:{room_jid}"));
        let tombstone_key = self
            .sender
            .publisher
            .key(format!("sm_muc_teardown:{sm_session_id}"));
        let payload = serde_json::json!({
            "target": &room_jid,
            "sm_muc_teardown": true,
            "sm_session_id": sm_session_id,
            "occupant": occupant,
        });
        // Capture and acknowledge every current room node before mutating the
        // Redis ownership indexes. If the owner node removes itself first,
        // a crash could otherwise make a retry forget which live process
        // still needs the unavailable broadcast.
        for node_id in &nodes {
            if node_id != &self.sender.publisher.node_id {
                self.sender
                    .send_control_to_node(node_id, &room_jid, payload.clone())
                    .await?;
            }
        }
        let mut conn = pool.get().await?;
        let script = redis::Script::new(
            r#"
            redis.call('set', KEYS[4], '1', 'EX', ARGV[6])
            local raw = redis.call('hget', KEYS[1], ARGV[1])
            if not raw then return 0 end
            local ok, decoded = pcall(cjson.decode, raw)
            if not ok
                or decoded['sm_session_id'] ~= ARGV[2]
                or decoded['full_jid'] ~= ARGV[3]
                or decoded['cluster_epoch'] ~= ARGV[4]
                or decoded['connection_id'] ~= ARGV[5]
            then return 0 end
            local owner = redis.call('hget', KEYS[2], ARGV[1])
            redis.call('hdel', KEYS[1], ARGV[1])
            redis.call('hdel', KEYS[2], ARGV[1])
            redis.call('hdel', KEYS[5], ARGV[1])
            if owner then
                local remaining = redis.call('hincrby', KEYS[6], owner, -1)
                if remaining <= 0 then
                    redis.call('hdel', KEYS[6], owner)
                    redis.call('srem', KEYS[3], owner)
                end
            end
            if redis.call('hlen', KEYS[1]) == 0 and redis.call('hlen', KEYS[2]) == 0 then
                redis.call('del', KEYS[1], KEYS[2], KEYS[3], KEYS[5], KEYS[6])
            else
                redis.call('expire', KEYS[1], ARGV[7])
                redis.call('expire', KEYS[2], ARGV[7])
                redis.call('expire', KEYS[3], ARGV[7])
                redis.call('expire', KEYS[5], ARGV[7])
                redis.call('expire', KEYS[6], ARGV[7])
            end
            return 1
            "#,
        );
        let _: i32 = script
            .key(occupants_key)
            .key(owners_key)
            .key(nodes_key)
            .key(tombstone_key)
            .key(instances_key)
            .key(node_counts_key)
            .arg(&nick)
            .arg(sm_session_id.to_string())
            .arg(&occupant.full_jid)
            .arg(occupant.cluster_epoch.to_string())
            .arg(occupant.connection_id.to_string())
            .arg(SM_TEARDOWN_TOMBSTONE_TTL_SECONDS)
            .arg(MUC_SOFT_STATE_TTL_SECONDS)
            .invoke_async(&mut *conn)
            .await?;
        Ok(())
    }
}

impl ClusterSmSuspension {
    pub(crate) fn is_enabled(&self) -> bool {
        self.publisher.is_enabled()
    }

    pub(crate) fn node_id(&self) -> &str {
        &self.publisher.node_id
    }

    /// Refresh only the exact occupancy/SM epoch. A teardown tombstone wins
    /// over a delayed disconnect task and prevents a ghost from reappearing.
    pub(crate) async fn register_suspended_muc_occupant(
        &self,
        room_jid: &str,
        nick: &str,
        sm_session_id: uuid::Uuid,
        json: &str,
    ) -> Result<bool> {
        admit_health(&self.publisher.health, ClusterOperation::Resume)?;
        let incoming: crate::state::SerializableMucOccupant = serde_json::from_str(json)?;
        anyhow::ensure!(
            incoming.sm_session_id == Some(sm_session_id)
                && !incoming.cluster_epoch.is_nil()
                && !incoming.connection_id.is_nil(),
            "suspended MUC refresh requires the exact occupancy and SM identities"
        );
        let Some(pool) = &self.publisher.pool else {
            return Ok(true);
        };
        let mut conn = pool.get().await?;
        let room = crate::jid::canonicalize_bare(room_jid)?;
        let nick = crate::xmpp::xml_util::prepare_muc_nick(nick)?;
        let process_instance = self.publisher.process_instance_token()?;
        let occupants_key = self.publisher.key(format!("muc_occupants:{room}"));
        let owners_key = self.publisher.key(format!("muc_occupant_nodes:{room}"));
        let tombstone_key = self
            .publisher
            .key(format!("sm_muc_teardown:{sm_session_id}"));
        let nodes_key = self.publisher.key(format!("muc_nodes:{room}"));
        let instances_key = self.publisher.key(format!("muc_occupant_instances:{room}"));
        let node_counts_key = self.publisher.key(format!("muc_node_counts:{room}"));
        let alive_key = self
            .publisher
            .key(format!("node:{}:alive", self.publisher.node_id));
        let process_alive_key = self.publisher.process_alive_key()?;
        let script = redis::Script::new(
            r#"
            if redis.call('exists', KEYS[3]) == 1 then return 0 end
            if redis.call('hget', KEYS[2], ARGV[1]) ~= ARGV[2] then return 0 end
            if redis.call('hget', KEYS[5], ARGV[1]) ~= ARGV[3] then return 0 end
            local raw = redis.call('hget', KEYS[1], ARGV[1])
            if not raw then return 0 end
            local ok, current = pcall(cjson.decode, raw)
            if not ok or current['cluster_epoch'] ~= ARGV[5]
                or current['connection_id'] ~= ARGV[6] then return 0 end
            redis.call('hset', KEYS[1], ARGV[1], ARGV[4])
            redis.call('sadd', KEYS[4], ARGV[2])
            redis.call('set', KEYS[7], ARGV[8], 'EX', ARGV[7])
            redis.call('set', KEYS[8], ARGV[8], 'EX', ARGV[7])
            redis.call('expire', KEYS[1], ARGV[9])
            redis.call('expire', KEYS[2], ARGV[9])
            redis.call('expire', KEYS[4], ARGV[9])
            redis.call('expire', KEYS[5], ARGV[9])
            redis.call('expire', KEYS[6], ARGV[9])
            return 1
            "#,
        );
        let stored: i32 = script
            .key(occupants_key)
            .key(owners_key)
            .key(tombstone_key)
            .key(nodes_key)
            .key(instances_key)
            .key(node_counts_key)
            .key(alive_key)
            .key(process_alive_key)
            .arg(&nick)
            .arg(&self.publisher.node_id)
            .arg(process_instance)
            .arg(json)
            .arg(incoming.cluster_epoch.to_string())
            .arg(incoming.connection_id.to_string())
            .arg(NODE_TTL_SECONDS)
            .arg(NODE_PROTOCOL_VERSION)
            .arg(MUC_SOFT_STATE_TTL_SECONDS)
            .invoke_async(&mut *conn)
            .await?;
        Ok(stored == 1)
    }

    async fn send_muc_operation_wake(
        &self,
        descriptor: &northstar_room_core::ClusterMucWakeDescriptor,
    ) -> Result<()> {
        send_muc_operation_wake(&self.publisher, &self.muc_outbox_notify, descriptor).await
    }
}

async fn send_muc_operation_wake(
    publisher: &ClusterSignedPublisher,
    muc_outbox_notify: &tokio::sync::Notify,
    descriptor: &northstar_room_core::ClusterMucWakeDescriptor,
) -> Result<()> {
    if descriptor
        .target_nodes
        .iter()
        .any(|node| node == &publisher.node_id)
    {
        muc_outbox_notify.notify_one();
    }
    let Some(pool) = &publisher.pool else {
        return Ok(());
    };
    let payload = serde_json::json!({
        "target": descriptor.room_id.to_string(),
        "muc_operation_wake": true,
        "operation_id": descriptor.operation_id.to_string(),
        "database_event_id": descriptor.event_id.to_string(),
        "event_sequence": descriptor.event_sequence,
        "request_id": descriptor.operation_id.to_string(),
    });
    let mut conn = pool.get().await?;
    for node_id in &descriptor.target_nodes {
        if node_id == &publisher.node_id {
            continue;
        }
        let channel = publisher.key(format!("node:{node_id}"));
        let _ = publisher
            .publish_signed(&mut conn, node_id, &channel, payload.clone())
            .await?;
    }
    Ok(())
}

impl crate::services::muc::MucWakePort for ClusterSmSuspension {
    async fn wake(&self, descriptor: &northstar_room_core::ClusterMucWakeDescriptor) -> Result<()> {
        self.send_muc_operation_wake(descriptor).await
    }

    fn record_failure(&self, error: &anyhow::Error) {
        self.publisher.record_control_plane_failure(error);
    }
}

impl crate::services::muc::MucWakePort for ClusterMucOperationWake {
    async fn wake(&self, descriptor: &northstar_room_core::ClusterMucWakeDescriptor) -> Result<()> {
        send_muc_operation_wake(&self.publisher, &self.muc_outbox_notify, descriptor).await
    }

    fn record_failure(&self, error: &anyhow::Error) {
        self.publisher.record_control_plane_failure(error);
    }
}

/// PostgreSQL-fenced maintenance of disposable Redis projections. This handle
/// has no signer, publication gate, PubSub client, or delivery route.
#[derive(Clone)]
pub(crate) struct ClusterMaintenanceRedis {
    pool: Option<Pool<RedisConnectionManager>>,
    authority_pool: Arc<std::sync::OnceLock<sqlx::PgPool>>,
    namespace: String,
    key_prefix: String,
    node_id: String,
    connection_uuid: uuid::Uuid,
    instance_epoch: Arc<AtomicI64>,
    peer_nodes: Vec<String>,
    health: Arc<ClusterHealth>,
}

impl ClusterMaintenanceRedis {
    fn key(&self, suffix: String) -> String {
        format!("{}:{suffix}", self.key_prefix)
    }

    fn process_instance_token(&self) -> Result<String> {
        let epoch = self.instance_epoch.load(Ordering::Acquire);
        anyhow::ensure!(epoch >= 1, "cluster process instance is not authoritative");
        Ok(format!("{}.{}", self.connection_uuid.simple(), epoch))
    }

    fn process_alive_key(&self) -> Result<String> {
        Ok(self.key(format!(
            "node_instance:{}:{}:alive",
            self.node_id,
            self.process_instance_token()?
        )))
    }

    fn note_incompatible_peer_version(&self, node_id: &str, observed: Option<&str>) {
        note_incompatible_peer_version(&self.health, node_id, observed);
    }
}

impl ClusterMaintenanceRedis {
    async fn touch_node(&self) -> Result<()> {
        let Some(pool) = &self.pool else {
            return Ok(());
        };
        let mut conn = pool.get().await?;
        let key = self.key(format!("node:{}:alive", self.node_id));
        let process_key = self.process_alive_key()?;
        // Version 2 peers require nonce-correlated delivery acknowledgements.
        // Keeping this in the existing liveness key makes the change safe for
        // rolling upgrades: version 1 peers still publish the legacy value.
        let script = redis::Script::new(
            r#"
            redis.call('set', KEYS[1], ARGV[1], 'EX', ARGV[2])
            redis.call('set', KEYS[2], ARGV[1], 'EX', ARGV[2])
            return 1
            "#,
        );
        let _: i32 = script
            .key(key)
            .key(process_key)
            .arg(NODE_PROTOCOL_VERSION)
            .arg(NODE_TTL_SECONDS)
            .invoke_async(&mut *conn)
            .await?;
        let mut compatible = true;
        for node_id in &self.peer_nodes {
            let observed: Option<String> =
                conn.get(self.key(format!("node:{node_id}:alive"))).await?;
            if observed
                .as_deref()
                .is_some_and(|version| version != NODE_PROTOCOL_VERSION)
            {
                compatible = false;
                self.note_incompatible_peer_version(node_id, observed.as_deref());
            }
        }
        if compatible {
            self.health
                .peer_versions_compatible
                .store(true, Ordering::Release);
        }
        Ok(())
    }

    async fn refresh_session(
        &self,
        full_jid: &str,
        activity_age_seconds: u64,
        connection_id: uuid::Uuid,
    ) -> Result<bool> {
        let (full_jid, bare) = session_route_keys(full_jid)?;
        let Some(pool) = &self.pool else {
            return Ok(true);
        };
        let authority_pool = self
            .authority_pool
            .get()
            .context("cluster session authority pool is unavailable")?;
        let owner_instance_epoch = self.instance_epoch.load(Ordering::Acquire);
        if !crate::db::refresh_cluster_session_route(
            authority_pool,
            &self.namespace,
            &full_jid,
            &self.node_id,
            self.connection_uuid,
            owner_instance_epoch,
            connection_id,
            Duration::from_secs(SESSION_TTL_SECONDS),
        )
        .await?
        {
            return Ok(false);
        }
        let mut conn = pool.get().await?;
        let full_key = self.key(format!("session:{full_jid}"));
        let bare_key = self.key(format!("user_sessions:{bare}"));
        let activity_key = self.key("session_activity".to_owned());
        let instance_key = self.key(format!("session_instance:{full_jid}"));
        let script = redis::Script::new(
            r#"
            if redis.call('get', KEYS[1]) ~= ARGV[1] or redis.call('get', KEYS[4]) ~= ARGV[6] then return 0 end
            redis.call('expire', KEYS[1], ARGV[3])
            redis.call('expire', KEYS[4], ARGV[3])
            redis.call('sadd', KEYS[2], ARGV[2])
            redis.call('expire', KEYS[2], ARGV[4])
            local now = redis.call('time')
            redis.call('zadd', KEYS[3], tonumber(now[1])-tonumber(ARGV[5]), ARGV[2])
            redis.call('zremrangebyscore', KEYS[3], '-inf', tonumber(now[1])-tonumber(ARGV[3])-1)
            return 1
            "#,
        );
        let refreshed = script
            .key(full_key)
            .key(bare_key)
            .key(activity_key)
            .key(instance_key)
            .arg(&self.node_id)
            .arg(&full_jid)
            .arg(SESSION_TTL_SECONDS)
            .arg(USER_SET_TTL_SECONDS)
            .arg(activity_age_seconds.min(SESSION_TTL_SECONDS))
            .arg(connection_id.to_string())
            .invoke_async::<i32>(&mut *conn)
            .await;
        match refreshed {
            Ok(1) => Ok(true),
            Ok(_) => {
                let _ = crate::db::release_cluster_session_route(
                    authority_pool,
                    &self.namespace,
                    &full_jid,
                    &self.node_id,
                    self.connection_uuid,
                    owner_instance_epoch,
                    connection_id,
                )
                .await;
                Ok(false)
            }
            Err(error) => {
                let _ = crate::db::release_cluster_session_route(
                    authority_pool,
                    &self.namespace,
                    &full_jid,
                    &self.node_id,
                    self.connection_uuid,
                    owner_instance_epoch,
                    connection_id,
                )
                .await;
                Err(error.into())
            }
        }
    }

    async fn reconcile_muc_soft_state(&self, room_jid: &str) -> Result<()> {
        reconcile_muc_soft_state_in(self.pool.as_ref(), &self.key_prefix, room_jid).await
    }

    pub async fn register_muc_occupant(
        &self,
        room_jid: &str,
        nick: &str,
        json: &str,
    ) -> Result<bool> {
        let incoming: crate::state::SerializableMucOccupant = serde_json::from_str(json)?;
        anyhow::ensure!(
            !incoming.cluster_epoch.is_nil()
                && !incoming.connection_id.is_nil()
                && incoming.room_jid == crate::jid::canonicalize_bare(room_jid)?
                && incoming.nick == crate::xmpp::xml_util::prepare_muc_nick(nick)?,
            "MUC refresh requires the exact non-nil occupancy identity"
        );
        let Some(pool) = &self.pool else {
            return Ok(true);
        };
        let mut conn = pool.get().await?;
        let room = crate::jid::canonicalize_bare(room_jid)?;
        let nick = crate::xmpp::xml_util::prepare_muc_nick(nick)?;
        let process_instance = self.process_instance_token()?;
        let occupants_key = self.key(format!("muc_occupants:{room}"));
        let owners_key = self.key(format!("muc_occupant_nodes:{room}"));
        let nodes_key = self.key(format!("muc_nodes:{room}"));
        let instances_key = self.key(format!("muc_occupant_instances:{room}"));
        let node_counts_key = self.key(format!("muc_node_counts:{room}"));
        let alive_key = self.key(format!("node:{}:alive", self.node_id));
        let process_alive_key = self.process_alive_key()?;
        let script = redis::Script::new(
            r#"
            local raw = redis.call('hget', KEYS[1], ARGV[1])
            local owner = redis.call('hget', KEYS[2], ARGV[1])
            local instance = redis.call('hget', KEYS[4], ARGV[1])
            local created = not raw and not owner and not instance
            if raw and owner and instance then
                if owner ~= ARGV[2] or instance ~= ARGV[3] then return 0 end
                local ok, current = pcall(cjson.decode, raw)
                if not ok then return 0 end
                if current['cluster_epoch'] ~= ARGV[5]
                    or current['connection_id'] ~= ARGV[6] then return 0 end
            elseif raw or owner or instance then
                -- Incomplete soft-state cannot authorize anything. The
                -- caller has just revalidated this exact identity against
                -- PostgreSQL, so repair only this internally inconsistent nick
                -- while keeping the O(1) owner-count index balanced.
                redis.call('hdel', KEYS[1], ARGV[1])
                redis.call('hdel', KEYS[2], ARGV[1])
                redis.call('hdel', KEYS[4], ARGV[1])
                if owner then
                    local remaining = redis.call('hincrby', KEYS[5], owner, -1)
                    if remaining <= 0 then
                        redis.call('hdel', KEYS[5], owner)
                        redis.call('srem', KEYS[3], owner)
                    end
                end
                created = true
            end
            redis.call('hset', KEYS[1], ARGV[1], ARGV[4])
            redis.call('hset', KEYS[2], ARGV[1], ARGV[2])
            redis.call('hset', KEYS[4], ARGV[1], ARGV[3])
            if created then redis.call('hincrby', KEYS[5], ARGV[2], 1) end
            redis.call('sadd', KEYS[3], ARGV[2])
            redis.call('set', KEYS[6], ARGV[8], 'EX', ARGV[7])
            redis.call('set', KEYS[7], ARGV[8], 'EX', ARGV[7])
            redis.call('expire', KEYS[1], ARGV[9])
            redis.call('expire', KEYS[2], ARGV[9])
            redis.call('expire', KEYS[3], ARGV[9])
            redis.call('expire', KEYS[4], ARGV[9])
            redis.call('expire', KEYS[5], ARGV[9])
            return 1
            "#,
        );
        let refreshed: i32 = script
            .key(occupants_key)
            .key(owners_key)
            .key(nodes_key)
            .key(instances_key)
            .key(node_counts_key)
            .key(alive_key)
            .key(process_alive_key)
            .arg(&nick)
            .arg(&self.node_id)
            .arg(process_instance)
            .arg(json)
            .arg(incoming.cluster_epoch.to_string())
            .arg(incoming.connection_id.to_string())
            .arg(NODE_TTL_SECONDS)
            .arg(NODE_PROTOCOL_VERSION)
            .arg(MUC_SOFT_STATE_TTL_SECONDS)
            .invoke_async(&mut *conn)
            .await?;
        Ok(refreshed == 1)
    }

    pub async fn join_muc(&self, room_jid: &str) -> Result<()> {
        let Some(pool) = &self.pool else {
            return Ok(());
        };
        self.touch_node().await?;
        let mut conn = pool.get().await?;
        let room = crate::jid::canonicalize_bare(room_jid)?;
        let key = self.key(format!("muc_nodes:{room}"));
        let script = redis::Script::new(
            r#"
            redis.call('sadd', KEYS[1], ARGV[1])
            redis.call('expire', KEYS[1], ARGV[2])
            return 1
            "#,
        );
        let _: i32 = script
            .key(key)
            .arg(&self.node_id)
            .arg(MUC_SOFT_STATE_TTL_SECONDS)
            .invoke_async(&mut *conn)
            .await?;
        Ok(())
    }
}

impl ClusterMaintenanceControl {
    async fn refresh_peers_with<R: ClusterAuthorityRepository>(
        &self,
        service: &ClusterAuthorityService<R>,
    ) -> Result<()> {
        self.peer_authority.refresh_peers_with(service).await
    }

    fn readiness_error(&self) -> Option<String> {
        cluster_readiness_error(&self.health)
    }

    fn begin_reconciliation(&self) -> Result<u64> {
        begin_cluster_reconciliation(&self.health, self.enabled)
    }

    fn complete_reconciliation(&self, rotation_epoch: u64) -> Result<ReconciliationOutcome> {
        complete_cluster_reconciliation(&self.health, rotation_epoch)
    }

    fn record_control_plane_failure(&self, error: &anyhow::Error) {
        record_cluster_failure(
            &self.health,
            &self.listener_rotation,
            self.enabled,
            self.failure_policy,
            ClusterFailureClass::RedisCommand,
            error,
        );
    }
}

/// A MUC outbox worker needs only its node identity and committed wake signal
/// from the cluster control plane. Neither capability can publish a packet.
#[derive(Clone)]
pub(crate) struct ClusterMucOutboxSignal {
    node_id: String,
    wake: Arc<tokio::sync::Notify>,
}

/// PostgreSQL session-route discovery for listener presence probes. Redis is
/// only the command transport; it is not the authority for session ownership.
#[derive(Clone)]
pub(crate) struct ClusterListenerPresenceRoutes {
    authority_pool: Arc<std::sync::OnceLock<sqlx::PgPool>>,
    namespace: String,
    node_id: String,
    enabled: bool,
}

impl ClusterListenerPresenceRoutes {
    async fn lookup_nodes(&self, jid: &str) -> Result<Vec<String>> {
        let jid = crate::jid::CanonicalJid::parse(jid)?;
        if !self.enabled {
            return Ok(Vec::new());
        }
        let authority_pool = self
            .authority_pool
            .get()
            .context("cluster session authority pool is unavailable")?;
        let nodes = if jid.resourcepart().is_some() {
            crate::db::cluster_session_route_authority(
                authority_pool,
                &self.namespace,
                &jid.to_string(),
            )
            .await?
            .map(|authority| authority.owner_node_id)
            .into_iter()
            .collect()
        } else {
            crate::db::cluster_session_nodes_for_bare(authority_pool, &self.namespace, &jid.bare())
                .await?
        };
        Ok(nodes)
    }

    pub(crate) async fn remote_nodes(&self, jid: &str) -> Result<Vec<String>> {
        Ok(self
            .lookup_nodes(jid)
            .await?
            .into_iter()
            .filter(|node_id| node_id != &self.node_id)
            .collect())
    }

    pub(crate) fn node_id(&self) -> &str {
        &self.node_id
    }
}

/// Disposable Redis room-membership projection used after an exact local
/// removal. The script keeps a node subscribed while any occupancy remains.
#[derive(Clone)]
pub(crate) struct ClusterListenerMucProjection {
    pool: Option<Pool<RedisConnectionManager>>,
    key_prefix: String,
    node_id: String,
}

impl ClusterListenerMucProjection {
    pub(crate) async fn leave_empty_room(&self, room_jid: &str) -> Result<()> {
        leave_muc_node_projection(
            self.pool.as_ref(),
            &self.key_prefix,
            &self.node_id,
            room_jid,
        )
        .await
    }
}

/// Exact local SM-owned occupancy removal and reconciled room emptiness.
/// It cannot publish node commands or mutate PostgreSQL authority.
#[derive(Clone)]
pub(crate) struct ClusterSmMucTeardownProjection {
    pool: Option<Pool<RedisConnectionManager>>,
    key_prefix: String,
    node_id: String,
    connection_uuid: uuid::Uuid,
    instance_epoch: Arc<AtomicI64>,
}

impl ClusterSmMucTeardownProjection {
    fn key(&self, suffix: String) -> String {
        format!("{}:{suffix}", self.key_prefix)
    }

    fn process_instance_token(&self) -> Result<String> {
        let epoch = self.instance_epoch.load(Ordering::Acquire);
        anyhow::ensure!(epoch >= 1, "cluster process instance is not authoritative");
        Ok(format!("{}.{}", self.connection_uuid.simple(), epoch))
    }

    pub(crate) async fn unregister_muc_occupant_epoch(
        &self,
        room_jid: &str,
        nick: &str,
        cluster_epoch: uuid::Uuid,
        connection_id: uuid::Uuid,
    ) -> Result<bool> {
        anyhow::ensure!(
            !cluster_epoch.is_nil() && !connection_id.is_nil(),
            "MUC unregister requires non-nil occupancy and connection identities"
        );
        let Some(pool) = &self.pool else {
            return Ok(true);
        };
        let mut conn = pool.get().await?;
        let room = crate::jid::canonicalize_bare(room_jid)?;
        let nick = crate::xmpp::xml_util::prepare_muc_nick(nick)?;
        let process_instance = self.process_instance_token()?;
        let occupants_key = self.key(format!("muc_occupants:{room}"));
        let owners_key = self.key(format!("muc_occupant_nodes:{room}"));
        let nodes_key = self.key(format!("muc_nodes:{room}"));
        let instances_key = self.key(format!("muc_occupant_instances:{room}"));
        let node_counts_key = self.key(format!("muc_node_counts:{room}"));
        let script = redis::Script::new(
            r#"
            if redis.call('hget', KEYS[2], ARGV[1]) ~= ARGV[2] then return 0 end
            if redis.call('hget', KEYS[4], ARGV[1]) ~= ARGV[3] then return 0 end
            local raw = redis.call('hget', KEYS[1], ARGV[1])
            if not raw then return 0 end
            local ok, decoded = pcall(cjson.decode, raw)
            if not ok or decoded['cluster_epoch'] ~= ARGV[4]
                or decoded['connection_id'] ~= ARGV[5] then return 0 end
            redis.call('hdel', KEYS[1], ARGV[1])
            redis.call('hdel', KEYS[2], ARGV[1])
            redis.call('hdel', KEYS[4], ARGV[1])
            local remaining = redis.call('hincrby', KEYS[5], ARGV[2], -1)
            if remaining <= 0 then
                redis.call('hdel', KEYS[5], ARGV[2])
                redis.call('srem', KEYS[3], ARGV[2])
            end
            if redis.call('hlen', KEYS[1]) == 0 and redis.call('hlen', KEYS[2]) == 0 then
                redis.call('del', KEYS[1], KEYS[2], KEYS[3], KEYS[4], KEYS[5])
            else
                redis.call('expire', KEYS[1], ARGV[6])
                redis.call('expire', KEYS[2], ARGV[6])
                redis.call('expire', KEYS[3], ARGV[6])
                redis.call('expire', KEYS[4], ARGV[6])
                redis.call('expire', KEYS[5], ARGV[6])
            end
            return 1
            "#,
        );
        let removed: i32 = script
            .key(occupants_key)
            .key(owners_key)
            .key(nodes_key)
            .key(instances_key)
            .key(node_counts_key)
            .arg(&nick)
            .arg(&self.node_id)
            .arg(process_instance)
            .arg(cluster_epoch.to_string())
            .arg(connection_id.to_string())
            .arg(MUC_SOFT_STATE_TTL_SECONDS)
            .invoke_async(&mut *conn)
            .await?;
        Ok(removed == 1)
    }

    pub(crate) async fn get_muc_occupants(
        &self,
        room_jid: &str,
    ) -> Result<HashMap<String, String>> {
        let Some(pool) = &self.pool else {
            return Ok(HashMap::new());
        };
        let room = crate::jid::canonicalize_bare(room_jid)?;
        reconcile_muc_soft_state_in(self.pool.as_ref(), &self.key_prefix, &room).await?;
        let mut conn = pool.get().await?;
        let occupants_key = self.key(format!("muc_occupants:{room}"));
        Ok(conn.hgetall(&occupants_key).await?)
    }

    pub(crate) async fn leave_muc(&self, room_jid: &str) -> Result<()> {
        leave_muc_node_projection(
            self.pool.as_ref(),
            &self.key_prefix,
            &self.node_id,
            room_jid,
        )
        .await
    }

    pub(crate) async fn room_is_empty(&self, room_jid: &str) -> Result<bool> {
        Ok(self.get_muc_occupants(room_jid).await?.is_empty())
    }
}

async fn reconcile_muc_soft_state_in(
    pool: Option<&Pool<RedisConnectionManager>>,
    key_prefix: &str,
    room_jid: &str,
) -> Result<()> {
    let Some(pool) = pool else {
        return Ok(());
    };
    let key = |suffix: String| format!("{key_prefix}:{suffix}");
    let room = crate::jid::canonicalize_bare(room_jid)?;
    let occupants_key = key(format!("muc_occupants:{room}"));
    let owners_key = key(format!("muc_occupant_nodes:{room}"));
    let nodes_key = key(format!("muc_nodes:{room}"));
    let instances_key = key(format!("muc_occupant_instances:{room}"));
    let node_counts_key = key(format!("muc_node_counts:{room}"));
    let alive_prefix = key("node:".to_owned());
    let instance_alive_prefix = key("node_instance:".to_owned());
    let mut conn = pool.get().await?;
    let script = redis::Script::new(
        r#"
        local alive_cache = {}
        local function node_is_alive(node)
            local cached = alive_cache[node]
            if cached == nil then
                cached = redis.call('exists', ARGV[1] .. node .. ':alive')
                alive_cache[node] = cached
            end
            return cached == 1
        end

        local function instance_is_alive(node, instance)
            if not instance then return false end
            local cache_key = node .. '|' .. instance
            local cached = alive_cache[cache_key]
            if cached == nil then
                cached = redis.call(
                    'exists', ARGV[2] .. node .. ':' .. instance .. ':alive'
                )
                alive_cache[cache_key] = cached
            end
            return cached == 1
        end

        local owners = redis.call('hgetall', KEYS[2])
        for index = 1, #owners, 2 do
            local nick = owners[index]
            local owner = owners[index + 1]
            local instance = redis.call('hget', KEYS[4], nick)
            if redis.call('hexists', KEYS[1], nick) == 0
                or not node_is_alive(owner)
                or not instance_is_alive(owner, instance)
            then
                redis.call('hdel', KEYS[1], nick)
                redis.call('hdel', KEYS[2], nick)
                redis.call('hdel', KEYS[4], nick)
            end
        end

        local occupants = redis.call('hgetall', KEYS[1])
        for index = 1, #occupants, 2 do
            local nick = occupants[index]
            if redis.call('hexists', KEYS[2], nick) == 0
                or redis.call('hexists', KEYS[4], nick) == 0
            then
                redis.call('hdel', KEYS[1], nick)
                redis.call('hdel', KEYS[2], nick)
                redis.call('hdel', KEYS[4], nick)
            end
        end

        for _, nick in ipairs(redis.call('hkeys', KEYS[4])) do
            if redis.call('hexists', KEYS[1], nick) == 0
                or redis.call('hexists', KEYS[2], nick) == 0
            then
                redis.call('hdel', KEYS[4], nick)
            end
        end

        local live_owner_nodes = {}
        redis.call('del', KEYS[5])
        owners = redis.call('hgetall', KEYS[2])
        for index = 1, #owners, 2 do
            local owner = owners[index + 1]
            live_owner_nodes[owner] = true
            redis.call('hincrby', KEYS[5], owner, 1)
            redis.call('sadd', KEYS[3], owner)
        end
        for _, node in ipairs(redis.call('smembers', KEYS[3])) do
            if not live_owner_nodes[node] or not node_is_alive(node) then
                redis.call('srem', KEYS[3], node)
            end
        end

        if redis.call('hlen', KEYS[1]) == 0
            and redis.call('hlen', KEYS[2]) == 0
            and redis.call('hlen', KEYS[4]) == 0
        then
            redis.call('del', KEYS[1], KEYS[2], KEYS[3], KEYS[4], KEYS[5])
            return 0
        end
        redis.call('expire', KEYS[1], ARGV[3])
        redis.call('expire', KEYS[2], ARGV[3])
        redis.call('expire', KEYS[3], ARGV[3])
        redis.call('expire', KEYS[4], ARGV[3])
        redis.call('expire', KEYS[5], ARGV[3])
        return redis.call('hlen', KEYS[1])
        "#,
    );
    let _: usize = script
        .key(occupants_key)
        .key(owners_key)
        .key(nodes_key)
        .key(instances_key)
        .key(node_counts_key)
        .arg(alive_prefix)
        .arg(instance_alive_prefix)
        .arg(MUC_SOFT_STATE_TTL_SECONDS)
        .invoke_async(&mut *conn)
        .await?;
    Ok(())
}

async fn leave_muc_node_projection(
    pool: Option<&Pool<RedisConnectionManager>>,
    key_prefix: &str,
    node_id: &str,
    room_jid: &str,
) -> Result<()> {
    let Some(pool) = pool else {
        return Ok(());
    };
    let mut conn = pool.get().await?;
    let room = crate::jid::canonicalize_bare(room_jid)?;
    let key = |suffix: &str| format!("{key_prefix}:{suffix}");
    let owners_key = key(&format!("muc_occupant_nodes:{room}"));
    let nodes_key = key(&format!("muc_nodes:{room}"));
    let occupants_key = key(&format!("muc_occupants:{room}"));
    let instances_key = key(&format!("muc_occupant_instances:{room}"));
    let node_counts_key = key(&format!("muc_node_counts:{room}"));
    let script = redis::Script::new(
        r#"
        if tonumber(redis.call('hget', KEYS[5], ARGV[1]) or '0') > 0 then return 0 end
        redis.call('srem', KEYS[2], ARGV[1])
        if redis.call('hlen', KEYS[3]) == 0 then
            redis.call('del', KEYS[1], KEYS[2], KEYS[3], KEYS[4], KEYS[5])
        else
            redis.call('expire', KEYS[1], ARGV[2])
            redis.call('expire', KEYS[2], ARGV[2])
            redis.call('expire', KEYS[3], ARGV[2])
            redis.call('expire', KEYS[4], ARGV[2])
            redis.call('expire', KEYS[5], ARGV[2])
        end
        return 1
        "#,
    );
    let _: i32 = script
        .key(owners_key)
        .key(nodes_key)
        .key(occupants_key)
        .key(instances_key)
        .key(node_counts_key)
        .arg(node_id)
        .arg(MUC_SOFT_STATE_TTL_SECONDS)
        .invoke_async(&mut *conn)
        .await?;
    Ok(())
}

/// Identity needed to authorize a signed session-termination command against
/// the PostgreSQL route. The epoch is read after the authority query, so a
/// listener never uses a stale process-instance snapshot.
#[derive(Clone)]
pub(crate) struct ClusterSessionTerminationIdentity {
    namespace: String,
    node_id: String,
    instance_uuid: uuid::Uuid,
    instance_epoch: Arc<AtomicI64>,
}

/// Exact local route release after a connection has been removed from the
/// process-local map. This handle cannot register routes or publish commands.
#[derive(Clone)]
pub(crate) struct ClusterSessionRouteRelease {
    pool: Option<Pool<RedisConnectionManager>>,
    authority_pool: Arc<std::sync::OnceLock<sqlx::PgPool>>,
    namespace: String,
    key_prefix: String,
    node_id: String,
    connection_uuid: uuid::Uuid,
    instance_epoch: Arc<AtomicI64>,
}

impl ClusterSessionRouteRelease {
    pub(crate) async fn release_exact_local_session_route(
        &self,
        full_jid: &str,
        connection_id: uuid::Uuid,
    ) -> Result<()> {
        let (full_jid, bare) = session_route_keys(full_jid)?;
        let Some(pool) = &self.pool else {
            return Ok(());
        };
        let authority_pool = self
            .authority_pool
            .get()
            .context("cluster session authority pool is unavailable")?;
        let _ = crate::db::release_cluster_session_route(
            authority_pool,
            &self.namespace,
            &full_jid,
            &self.node_id,
            self.connection_uuid,
            self.instance_epoch.load(Ordering::Acquire),
            connection_id,
        )
        .await?;
        let mut conn = pool.get().await?;
        let full_key = format!("{}:session:{full_jid}", self.key_prefix);
        let bare_key = format!("{}:user_sessions:{bare}", self.key_prefix);
        let activity_key = format!("{}:session_activity", self.key_prefix);
        let instance_key = format!("{}:session_instance:{full_jid}", self.key_prefix);
        let script = redis::Script::new(
            r#"
            if redis.call('get', KEYS[1]) == ARGV[1] and redis.call('get', KEYS[4]) == ARGV[3] then
                redis.call('del', KEYS[1])
                redis.call('del', KEYS[4])
                redis.call('srem', KEYS[2], ARGV[2])
                redis.call('zrem', KEYS[3], ARGV[2])
                return 1
            end
            return 0
            "#,
        );
        let _: i32 = script
            .key(&full_key)
            .key(&bare_key)
            .key(&activity_key)
            .key(&instance_key)
            .arg(&self.node_id)
            .arg(&full_jid)
            .arg(connection_id.to_string())
            .invoke_async(&mut *conn)
            .await?;
        Ok(())
    }
}

impl ClusterSessionTerminationIdentity {
    pub(crate) fn namespace(&self) -> &str {
        &self.namespace
    }

    pub(crate) fn local_instance(
        &self,
    ) -> crate::services::session_termination_authority::LocalClusterInstance {
        crate::services::session_termination_authority::LocalClusterInstance {
            node_id: self.node_id.clone(),
            instance_uuid: self.instance_uuid,
            instance_epoch: self.instance_epoch.load(Ordering::Acquire),
        }
    }
}

impl ClusterMucOutboxSignal {
    async fn wait(&self) {
        self.wake.notified().await;
    }

    pub(crate) fn notify(&self) {
        self.wake.notify_one();
    }
}

impl ClusterFailureSupervisorAuthority {
    pub(crate) fn is_enabled(&self) -> bool {
        self.enabled
    }

    pub(crate) fn key_identity(&self) -> Option<&crate::db::ClusterKeyDeploymentIdentity> {
        self.readiness
            .as_ref()
            .map(|readiness| &readiness.key_identity)
    }

    pub(crate) fn readiness_snapshot(&self) -> Option<ClusterReadinessAuthority> {
        let mut readiness = self.readiness.clone()?;
        readiness.instance_epoch = self.instance_epoch.load(Ordering::Acquire);
        Some(readiness)
    }

    pub(crate) async fn refresh_peers_with<R: ClusterAuthorityRepository>(
        &self,
        service: &ClusterAuthorityService<R>,
    ) -> Result<()> {
        if !self.enabled {
            return Ok(());
        }
        refresh_peer_authority_with(
            service,
            &self.domain,
            &self.expected_peer_keys,
            &self.peer_nodes,
            &self.authorized_peer_keys,
            &self.authorized_instances,
        )
        .await
    }

    pub(crate) fn record_authority_failure(&self, error: &anyhow::Error) {
        record_cluster_failure(
            &self.health,
            &self.listener_rotation,
            self.enabled,
            self.failure_policy,
            ClusterFailureClass::PostgreSqlAuthority,
            error,
        );
    }

    pub(crate) fn failure_policy(&self) -> crate::cluster_security::ClusterFailurePolicy {
        self.failure_policy
            .unwrap_or(crate::cluster_security::ClusterFailurePolicy::FailClosed)
    }

    pub(crate) fn safety_lease_expired(&self) -> bool {
        let Some(seconds) = self.safety_lease_seconds else {
            return false;
        };
        self.health
            .failure_since
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .is_some_and(|since| since.elapsed() >= Duration::from_secs(seconds))
    }

    pub(crate) fn require_shutdown(&self) {
        require_cluster_shutdown(&self.health, self.enabled);
    }
}

impl ClusterRevocationAuthority {
    fn identity(
        &self,
    ) -> crate::services::account_revocation_consumer::AccountRevocationConsumerIdentity {
        crate::services::account_revocation_consumer::AccountRevocationConsumerIdentity {
            domain: self.domain.clone(),
            node_id: self.node_id.clone(),
            instance_uuid: self.instance_uuid,
            instance_epoch: self.instance_epoch.load(Ordering::Acquire),
        }
    }

    fn record_failure(&self, error: &anyhow::Error) {
        record_cluster_failure(
            &self.health,
            &self.listener_rotation,
            self.enabled,
            self.failure_policy,
            ClusterFailureClass::PostgreSqlAuthority,
            error,
        );
    }
}

fn record_cluster_failure(
    health: &ClusterHealth,
    listener_rotation: &tokio::sync::Notify,
    enabled: bool,
    policy: Option<crate::cluster_security::ClusterFailurePolicy>,
    class: ClusterFailureClass,
    error: &anyhow::Error,
) {
    if !enabled {
        return;
    }
    // Serialize the failure fence with complete_reconciliation's generation
    // check and healthy commit, so an older completion cannot hide failure.
    let mut since = health
        .failure_since
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    if health.state.load(Ordering::Acquire) == CLUSTER_SHUTDOWN_REQUIRED {
        return;
    }
    let degraded = match policy {
        Some(crate::cluster_security::ClusterFailurePolicy::DurableDirectOnly) => {
            CLUSTER_DURABLE_DIRECT_ONLY
        }
        _ => CLUSTER_FAIL_CLOSED,
    };
    let previous = health.state.swap(degraded, Ordering::AcqRel);
    if previous != degraded {
        health.degraded_transitions.fetch_add(1, Ordering::Relaxed);
    }
    let next_listener = health
        .listener_generation
        .load(Ordering::Acquire)
        .saturating_add(1);
    health
        .required_listener_generation
        .fetch_max(next_listener, Ordering::AcqRel);
    health
        .listener_rotation_epoch
        .fetch_add(1, Ordering::AcqRel);
    listener_rotation.notify_waiters();
    if since.is_none() {
        *since = Some(Instant::now());
    }
    drop(since);
    tracing::error!(
        ?error,
        ?class,
        ?policy,
        "cluster control plane entered a degraded state"
    );
}

fn require_cluster_shutdown(health: &ClusterHealth, enabled: bool) {
    if enabled {
        let _transition = health
            .failure_since
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        health
            .state
            .store(CLUSTER_SHUTDOWN_REQUIRED, Ordering::Release);
    }
}

fn note_incompatible_peer_version(health: &ClusterHealth, node_id: &str, observed: Option<&str>) {
    if health
        .peer_versions_compatible
        .swap(false, Ordering::AcqRel)
    {
        health
            .incompatible_peer_versions
            .fetch_add(1, Ordering::Relaxed);
    }
    tracing::error!(
        %node_id,
        observed_version = observed.unwrap_or("missing"),
        required_version = NODE_PROTOCOL_VERSION,
        "live cluster peer uses an incompatible application protocol; readiness is fail-closed"
    );
}

fn note_cluster_authentication_failure(health: &ClusterHealth, error: &anyhow::Error) {
    health
        .authentication_failures
        .fetch_add(1, Ordering::Relaxed);
    tracing::warn!(?error, "rejected unauthenticated cluster protocol envelope");
}

fn dispatch_pending_ack(
    pending_acks: &dashmap::DashMap<String, PendingClusterAck>,
    source_node: &str,
    payload: serde_json::Value,
) -> bool {
    let Ok(ack) = serde_json::from_value::<NodeDeliveryAck>(payload) else {
        return false;
    };
    let Some(pending) = pending_acks.get(&ack.request_id) else {
        return false;
    };
    if pending.source_node != source_node
        || pending.nonce != ack.nonce
        || pending.source_node != ack.node_id
    {
        return false;
    }
    pending.sender.try_send(ack).is_ok()
}

fn begin_cluster_reconciliation(health: &ClusterHealth, enabled: bool) -> Result<u64> {
    let _transition = health
        .failure_since
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    anyhow::ensure!(
        health.state.load(Ordering::Acquire) != CLUSTER_SHUTDOWN_REQUIRED,
        "cluster shutdown is required; reconciliation cannot begin"
    );
    if enabled {
        health.state.store(CLUSTER_RECONCILING, Ordering::Release);
    }
    Ok(health.listener_rotation_epoch.load(Ordering::Acquire))
}

fn complete_cluster_reconciliation(
    health: &ClusterHealth,
    rotation_epoch: u64,
) -> Result<ReconciliationOutcome> {
    let mut since = health
        .failure_since
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    complete_cluster_reconciliation_locked(health, &mut since, rotation_epoch)
}

fn confirm_listener_generation(
    health: &ClusterHealth,
    generation: u64,
    rotation_epoch: u64,
) -> Result<()> {
    let mut since = health
        .failure_since
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    anyhow::ensure!(
        health.state.load(Ordering::Acquire) != CLUSTER_SHUTDOWN_REQUIRED
            && health.listener_rotation_epoch.load(Ordering::Acquire) == rotation_epoch
            && generation == health.next_listener_generation()
            && !health.listener_requires_rotation(generation),
        "Redis PubSub listener rotation was requested before self-loop confirmation"
    );
    health
        .listener_generation
        .store(generation, Ordering::Release);
    // Only the initial self-loop may complete startup reconciliation. Later
    // recoveries still require the full maintenance pass.
    if health.state.load(Ordering::Acquire) == CLUSTER_RECONCILING
        && health.degraded_transitions.load(Ordering::Acquire) == 0
    {
        let outcome = complete_cluster_reconciliation_locked(health, &mut since, rotation_epoch)?;
        anyhow::ensure!(
            outcome == ReconciliationOutcome::Complete,
            "confirmed initial listener did not complete startup reconciliation"
        );
    }
    Ok(())
}

fn complete_cluster_reconciliation_locked(
    health: &ClusterHealth,
    since: &mut std::sync::MutexGuard<'_, Option<Instant>>,
    rotation_epoch: u64,
) -> Result<ReconciliationOutcome> {
    anyhow::ensure!(
        health.state.load(Ordering::Acquire) != CLUSTER_SHUTDOWN_REQUIRED,
        "cluster shutdown is required; reconciliation cannot restore readiness"
    );
    anyhow::ensure!(
        health.listener_rotation_epoch.load(Ordering::Acquire) == rotation_epoch,
        "cluster control-plane failure invalidated this reconciliation attempt"
    );
    // The first maintenance pass can finish authority I/O before the initial
    // listener self-loop. Keep the original failure timer until that proof.
    if health.state.load(Ordering::Acquire) == CLUSTER_RECONCILING
        && health.listener_generation.load(Ordering::Acquire) == 0
        && health.required_listener_generation.load(Ordering::Acquire) == 1
        && rotation_epoch == 0
        && health.degraded_transitions.load(Ordering::Acquire) == 0
    {
        return Ok(ReconciliationOutcome::WaitingForInitialListener);
    }
    anyhow::ensure!(
        health.listener_generation.load(Ordering::Acquire)
            >= health.required_listener_generation.load(Ordering::Acquire),
        "cluster PubSub listener generation has not been re-established"
    );
    health.state.store(CLUSTER_HEALTHY, Ordering::Release);
    **since = None;
    Ok(ReconciliationOutcome::Complete)
}

pub(crate) struct AccountRevocationWorkerContext<R> {
    service: crate::services::account_revocation_consumer::AccountRevocationConsumerService<R>,
    routes: crate::state::AccountRevocationRoutes,
    authority: ClusterRevocationAuthority,
}

impl<R: crate::services::account_revocation_consumer::AccountRevocationRepository>
    AccountRevocationWorkerContext<R>
{
    pub(crate) fn new(
        service: crate::services::account_revocation_consumer::AccountRevocationConsumerService<R>,
        routes: crate::state::AccountRevocationRoutes,
        authority: ClusterRevocationAuthority,
    ) -> Self {
        Self {
            service,
            routes,
            authority,
        }
    }
}

impl ClusterReadinessProbe {
    pub(crate) fn readiness_error(&self) -> Option<String> {
        cluster_readiness_error(&self.health)
    }

    pub(crate) fn authority_snapshot(&self) -> Option<ClusterReadinessAuthority> {
        self.authority.clone().map(|mut authority| {
            authority.instance_epoch = self.instance_epoch.load(Ordering::Acquire);
            authority
        })
    }
}

fn cluster_readiness_error(health: &ClusterHealth) -> Option<String> {
    if !health.peer_versions_compatible.load(Ordering::Acquire) {
        return Some("a live cluster peer uses an incompatible application protocol".into());
    }
    match health.state.load(Ordering::Acquire) {
        CLUSTER_DISABLED | CLUSTER_HEALTHY => None,
        CLUSTER_RECONCILING => Some("cluster ownership reconciliation is incomplete".into()),
        CLUSTER_DURABLE_DIRECT_ONLY => {
            Some("cluster is degraded to PostgreSQL-spooled direct messages".into())
        }
        CLUSTER_FAIL_CLOSED => Some("cluster control plane is fail-closed".into()),
        CLUSTER_SHUTDOWN_REQUIRED => Some("cluster safety lease expired".into()),
        _ => Some("cluster control plane has an invalid state".into()),
    }
}

#[derive(Clone)]
struct PendingClusterAck {
    source_node: String,
    nonce: String,
    registration_id: uuid::Uuid,
    sender: tokio::sync::mpsc::Sender<NodeDeliveryAck>,
}

struct PendingAckRegistration {
    request_id: String,
    registration_id: uuid::Uuid,
    entries: Arc<dashmap::DashMap<String, PendingClusterAck>>,
    receiver: tokio::sync::mpsc::Receiver<NodeDeliveryAck>,
    _permit: tokio::sync::OwnedSemaphorePermit,
}

impl PendingAckRegistration {
    async fn recv(&mut self) -> Option<NodeDeliveryAck> {
        self.receiver.recv().await
    }
}

impl Drop for PendingAckRegistration {
    fn drop(&mut self) {
        let registration_id = self.registration_id;
        self.entries.remove_if(&self.request_id, |_, pending| {
            pending.registration_id == registration_id
        });
    }
}

fn register_pending_ack_in(
    slots: &Arc<tokio::sync::Semaphore>,
    entries: &Arc<dashmap::DashMap<String, PendingClusterAck>>,
    request_id: &str,
    source_node: &str,
    nonce: &str,
) -> Result<PendingAckRegistration> {
    let permit = Arc::clone(slots)
        .try_acquire_owned()
        .map_err(|_| anyhow::anyhow!("cluster acknowledgement capacity is exhausted"))?;
    let (sender, receiver) = tokio::sync::mpsc::channel(1);
    let registration_id = uuid::Uuid::new_v4();
    match entries.entry(request_id.to_owned()) {
        dashmap::mapref::entry::Entry::Vacant(entry) => {
            entry.insert(PendingClusterAck {
                source_node: source_node.to_owned(),
                nonce: nonce.to_owned(),
                registration_id,
                sender,
            });
        }
        dashmap::mapref::entry::Entry::Occupied(_) => {
            anyhow::bail!("cluster acknowledgement request ID collided");
        }
    }
    Ok(PendingAckRegistration {
        request_id: request_id.to_owned(),
        registration_id,
        entries: Arc::clone(entries),
        receiver,
        _permit: permit,
    })
}

#[derive(Clone, Copy, Debug)]
enum ClusterFailureClass {
    RedisCommand,
    PubSub,
    PostgreSqlAuthority,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct AuthorizedClusterInstance {
    instance_uuid: uuid::Uuid,
    instance_epoch: i64,
    signing_key_id: String,
    signing_key_epoch: i64,
    valid_until: Instant,
    refresh_until: Instant,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct AuthorizedPeerKeys {
    epoch: i64,
    current_key_id: String,
    previous_key_id: Option<String>,
    refresh_until: Instant,
}

impl AuthorizedPeerKeys {
    fn accepts(&self, key_id: &str, key_epoch: i64, now: Instant) -> bool {
        self.refresh_until > now
            && ((key_epoch == self.epoch && self.current_key_id == key_id)
                || (self.epoch > 1
                    && key_epoch == self.epoch - 1
                    && self.previous_key_id.as_deref() == Some(key_id)))
    }
}

fn authoritative_instance_matches(
    authority: &AuthorizedClusterInstance,
    connection_uuid: uuid::Uuid,
    connection_epoch: i64,
    signing_key_id: &str,
    signing_key_epoch: i64,
    now: Instant,
) -> bool {
    authority.instance_uuid == connection_uuid
        && authority.instance_epoch == connection_epoch
        && authority.signing_key_id == signing_key_id
        && authority.signing_key_epoch == signing_key_epoch
        && authority.valid_until > now
        && authority.refresh_until > now
}

const CLUSTER_DISABLED: u8 = 0;
const CLUSTER_RECONCILING: u8 = 1;
const CLUSTER_HEALTHY: u8 = 2;
const CLUSTER_FAIL_CLOSED: u8 = 3;
const CLUSTER_DURABLE_DIRECT_ONLY: u8 = 4;
const CLUSTER_SHUTDOWN_REQUIRED: u8 = 5;

#[derive(Debug, Eq, PartialEq)]
enum ReconciliationOutcome {
    Complete,
    WaitingForInitialListener,
}

struct ClusterHealth {
    state: AtomicU8,
    listener_generation: AtomicU64,
    required_listener_generation: AtomicU64,
    listener_rotation_epoch: AtomicU64,
    failure_since: Mutex<Option<Instant>>,
    authentication_failures: AtomicU64,
    replay_rejections: AtomicU64,
    degraded_transitions: AtomicU64,
    peer_versions_compatible: AtomicBool,
    incompatible_peer_versions: AtomicU64,
}

impl ClusterHealth {
    fn disabled() -> Self {
        Self {
            state: AtomicU8::new(CLUSTER_DISABLED),
            listener_generation: AtomicU64::new(0),
            required_listener_generation: AtomicU64::new(0),
            listener_rotation_epoch: AtomicU64::new(0),
            failure_since: Mutex::new(None),
            authentication_failures: AtomicU64::new(0),
            replay_rejections: AtomicU64::new(0),
            degraded_transitions: AtomicU64::new(0),
            peer_versions_compatible: AtomicBool::new(true),
            incompatible_peer_versions: AtomicU64::new(0),
        }
    }

    fn next_listener_generation(&self) -> u64 {
        self.listener_generation
            .load(Ordering::Acquire)
            .saturating_add(1)
    }

    fn begin_listener_attempt(&self) -> (u64, u64) {
        let _transition = self
            .failure_since
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        (
            self.next_listener_generation(),
            self.listener_rotation_epoch.load(Ordering::Acquire),
        )
    }

    fn listener_requires_rotation(&self, candidate_generation: u64) -> bool {
        candidate_generation < self.required_listener_generation.load(Ordering::Acquire)
    }

    fn enabled() -> Self {
        Self {
            state: AtomicU8::new(CLUSTER_RECONCILING),
            listener_generation: AtomicU64::new(0),
            required_listener_generation: AtomicU64::new(1),
            listener_rotation_epoch: AtomicU64::new(0),
            failure_since: Mutex::new(Some(Instant::now())),
            authentication_failures: AtomicU64::new(0),
            replay_rejections: AtomicU64::new(0),
            degraded_transitions: AtomicU64::new(0),
            peer_versions_compatible: AtomicBool::new(true),
            incompatible_peer_versions: AtomicU64::new(0),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ClusterOperation {
    NewBinding,
    Resume,
    MucMutation,
    AdminMutation,
    VolatileDelivery,
    DurableDirect,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ClusterMetricsSnapshot {
    pub state: u8,
    pub listener_generation: u64,
    pub authentication_failures: u64,
    pub replay_rejections: u64,
    pub degraded_transitions: u64,
    pub incompatible_peer_versions: u64,
}

/// Read-only process gauges without Redis, signing, or authority mutation.
#[derive(Clone)]
pub(crate) struct ClusterMetricsProbe {
    health: Arc<ClusterHealth>,
}

impl ClusterMetricsProbe {
    pub(crate) fn snapshot(&self) -> ClusterMetricsSnapshot {
        cluster_metrics_snapshot(&self.health)
    }
}

fn cluster_metrics_snapshot(health: &ClusterHealth) -> ClusterMetricsSnapshot {
    ClusterMetricsSnapshot {
        state: health.state.load(Ordering::Relaxed),
        listener_generation: health.listener_generation.load(Ordering::Relaxed),
        authentication_failures: health.authentication_failures.load(Ordering::Relaxed),
        replay_rejections: health.replay_rejections.load(Ordering::Relaxed),
        degraded_transitions: health.degraded_transitions.load(Ordering::Relaxed),
        incompatible_peer_versions: health.incompatible_peer_versions.load(Ordering::Relaxed),
    }
}

fn operation_allowed(state: u8, operation: ClusterOperation) -> bool {
    matches!(state, CLUSTER_DISABLED | CLUSTER_HEALTHY)
        || (state == CLUSTER_DURABLE_DIRECT_ONLY && operation == ClusterOperation::DurableDirect)
}

fn degraded_shutdown_required(
    policy: crate::cluster_security::ClusterFailurePolicy,
    postgres_authority_healthy: bool,
    safety_lease_expired: bool,
) -> bool {
    !postgres_authority_healthy
        || (policy == crate::cluster_security::ClusterFailurePolicy::FailClosed
            && safety_lease_expired)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MucRegistration {
    Joined,
    Conflict,
    Full,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MucRename {
    Renamed,
    Conflict,
    Stale,
}

#[derive(Clone)]
pub enum MucRoleChange {
    Changed(Box<crate::state::SerializableMucOccupant>),
    Stale,
}

impl crate::services::muc::MucWakePort for ClusterManager {
    async fn wake(&self, descriptor: &northstar_room_core::ClusterMucWakeDescriptor) -> Result<()> {
        self.send_muc_operation_wake(descriptor).await
    }

    fn record_failure(&self, error: &anyhow::Error) {
        self.record_control_plane_failure(error);
    }
}

async fn refresh_peer_authority_with<R: ClusterAuthorityRepository>(
    service: &ClusterAuthorityService<R>,
    domain: &str,
    expected: &[crate::db::ExpectedClusterPeerKey],
    nodes: &[String],
    authorized_peer_keys: &dashmap::DashMap<String, AuthorizedPeerKeys>,
    authorized_instances: &dashmap::DashMap<String, AuthorizedClusterInstance>,
) -> Result<()> {
    service
        .refresh_peers(
            domain,
            expected,
            nodes,
            |key_authorities| {
                let replacements = key_authorities
                    .into_iter()
                    .map(|authority| {
                        (
                            authority.node_id,
                            AuthorizedPeerKeys {
                                epoch: authority.epoch,
                                current_key_id: authority.current_key_id,
                                previous_key_id: authority.previous_key_id,
                                refresh_until: Instant::now() + Duration::from_secs(10),
                            },
                        )
                    })
                    .collect::<HashMap<_, _>>();
                authorized_peer_keys.retain(|node, _| replacements.contains_key(node));
                for (node, authority) in replacements {
                    authorized_peer_keys.insert(node, authority);
                }
            },
            |active| {
                let replacements = active
                    .into_iter()
                    .map(|instance| {
                        (
                            instance.node_id,
                            AuthorizedClusterInstance {
                                instance_uuid: instance.instance_uuid,
                                instance_epoch: instance.instance_epoch,
                                signing_key_id: instance.signing_key_id,
                                signing_key_epoch: instance.signing_key_epoch,
                                valid_until: Instant::now()
                                    + instance
                                        .lease_remaining
                                        .saturating_sub(Duration::from_secs(1)),
                                refresh_until: Instant::now() + Duration::from_secs(10),
                            },
                        )
                    })
                    .collect::<HashMap<_, _>>();
                authorized_instances.retain(|node, _| replacements.contains_key(node));
                for (node, instance) in replacements {
                    authorized_instances.insert(node, instance);
                }
            },
        )
        .await
}

impl ClusterManager {
    pub async fn new(
        redis_url: Option<&str>,
        namespace: &str,
        tls_ca_cert_path: Option<&std::path::Path>,
        tls_client_cert_path: Option<&std::path::Path>,
        tls_client_key_path: Option<&std::path::Path>,
        security: Option<Arc<crate::cluster_security::ClusterSecurityConfig>>,
    ) -> Result<Self> {
        let namespace = crate::jid::prepare_domainpart(namespace)
            .context("cluster namespace must be a valid XMPP domain")?;
        let key_prefix = format!("northstar:{namespace}");
        let Some(redis_url) = redis_url else {
            anyhow::ensure!(
                security.is_none(),
                "cluster security configuration cannot be enabled without Redis"
            );
            let node_id = uuid::Uuid::new_v4().to_string();
            tracing::info!("Redis is not configured; running in supported single-node mode");
            return Ok(Self {
                node_id,
                namespace,
                key_prefix,
                pool: None,
                client: None,
                security: None,
                connection_uuid: uuid::Uuid::new_v4(),
                instance_epoch: Arc::new(AtomicI64::new(0)),
                authorized_instances: Arc::new(dashmap::DashMap::new()),
                authorized_peer_keys: Arc::new(dashmap::DashMap::new()),
                #[cfg(test)]
                replay_cache: Arc::new(dashmap::DashMap::new()),
                #[cfg(test)]
                replay_cache_gate: Arc::new(Mutex::new(())),
                #[cfg(test)]
                replay_cache_next_expiry: Arc::new(AtomicI64::new(i64::MAX)),
                #[cfg(test)]
                replay_cache_sweeps: Arc::new(AtomicU64::new(0)),
                authority_pool: Arc::new(std::sync::OnceLock::new()),
                health: Arc::new(ClusterHealth::disabled()),
                publication_gate: Arc::new(tokio::sync::RwLock::new(())),
                muc_outbox_notify: Arc::new(tokio::sync::Notify::new()),
                account_revocation_notify: Arc::new(tokio::sync::Notify::new()),
                listener_rotation: Arc::new(tokio::sync::Notify::new()),
                pending_ack_slots: Arc::new(tokio::sync::Semaphore::new(MAX_PENDING_CLUSTER_ACKS)),
                pending_acks: Arc::new(dashmap::DashMap::new()),
            });
        };
        let security = security
            .context("Redis cluster mode requires Ed25519 signing identity and peer allowlist")?;
        let node_id = security.node_id.clone();

        let tls_files_configured = tls_ca_cert_path.is_some() || tls_client_cert_path.is_some();
        let client = if tls_files_configured {
            let root_cert = tls_ca_cert_path
                .map(|path| crate::config::read_secret_file(path, "REDIS_TLS_CA_CERT_PATH"))
                .transpose()?
                .map(String::into_bytes);
            let client_tls = match (tls_client_cert_path, tls_client_key_path) {
                (Some(cert), Some(key)) => Some(redis::ClientTlsConfig {
                    client_cert: crate::config::read_secret_file(
                        cert,
                        "REDIS_TLS_CLIENT_CERT_PATH",
                    )?
                    .into_bytes(),
                    client_key: crate::config::read_secret_file(key, "REDIS_TLS_CLIENT_KEY_PATH")?
                        .into_bytes(),
                }),
                (None, None) => None,
                _ => anyhow::bail!(
                    "Redis TLS client certificate and key must be configured together"
                ),
            };
            redis::Client::build_with_tls(
                redis_url,
                redis::TlsCertificates {
                    client_tls,
                    root_cert,
                },
            )?
        } else {
            redis::Client::open(redis_url)?
        };
        let manager = RedisConnectionManager {
            client: client.clone(),
        };
        // `bb8` otherwise retries a failed connection acquisition for thirty
        // seconds. That outer retry defeats the per-connection Redis timeout:
        // a stanza can wait through an outage, acquire a connection after
        // recovery, and then be delivered long after the sender's request
        // should have failed closed.
        let pool = cluster_pool_builder().build(manager).await?;
        let cluster = Self {
            node_id,
            namespace,
            key_prefix,
            pool: Some(pool),
            client: Some(client),
            security: Some(security),
            connection_uuid: uuid::Uuid::new_v4(),
            instance_epoch: Arc::new(AtomicI64::new(0)),
            authorized_instances: Arc::new(dashmap::DashMap::new()),
            authorized_peer_keys: Arc::new(dashmap::DashMap::new()),
            #[cfg(test)]
            replay_cache: Arc::new(dashmap::DashMap::new()),
            #[cfg(test)]
            replay_cache_gate: Arc::new(Mutex::new(())),
            #[cfg(test)]
            replay_cache_next_expiry: Arc::new(AtomicI64::new(i64::MAX)),
            #[cfg(test)]
            replay_cache_sweeps: Arc::new(AtomicU64::new(0)),
            authority_pool: Arc::new(std::sync::OnceLock::new()),
            health: Arc::new(ClusterHealth::enabled()),
            publication_gate: Arc::new(tokio::sync::RwLock::new(())),
            muc_outbox_notify: Arc::new(tokio::sync::Notify::new()),
            account_revocation_notify: Arc::new(tokio::sync::Notify::new()),
            listener_rotation: Arc::new(tokio::sync::Notify::new()),
            pending_ack_slots: Arc::new(tokio::sync::Semaphore::new(MAX_PENDING_CLUSTER_ACKS)),
            pending_acks: Arc::new(dashmap::DashMap::new()),
        };
        tracing::warn!(node_id = %cluster.node_id, "experimental Redis multi-node routing is enabled");
        Ok(cluster)
    }

    pub(crate) fn account_revocation_notify(&self) -> Arc<tokio::sync::Notify> {
        Arc::clone(&self.account_revocation_notify)
    }

    pub(crate) fn account_revocation_authority(&self) -> ClusterRevocationAuthority {
        ClusterRevocationAuthority {
            domain: self.namespace.clone(),
            node_id: self.node_id.clone(),
            instance_uuid: self.connection_uuid,
            instance_epoch: Arc::clone(&self.instance_epoch),
            notify: Arc::clone(&self.account_revocation_notify),
            enabled: self.is_enabled(),
            failure_policy: self.failure_policy(),
            health: Arc::clone(&self.health),
            listener_rotation: Arc::clone(&self.listener_rotation),
        }
    }

    pub(crate) fn failure_supervisor_authority(&self) -> ClusterFailureSupervisorAuthority {
        ClusterFailureSupervisorAuthority {
            enabled: self.is_enabled(),
            readiness: self.readiness_authority_snapshot(),
            instance_epoch: Arc::clone(&self.instance_epoch),
            domain: self.namespace.clone(),
            peer_nodes: self
                .security
                .as_ref()
                .map_or_else(Vec::new, |security| security.peer_node_ids()),
            expected_peer_keys: self
                .security
                .as_ref()
                .map_or_else(Vec::new, |security| security.peer_key_authorities()),
            authorized_peer_keys: Arc::clone(&self.authorized_peer_keys),
            authorized_instances: Arc::clone(&self.authorized_instances),
            health: Arc::clone(&self.health),
            listener_rotation: Arc::clone(&self.listener_rotation),
            failure_policy: self.failure_policy(),
            safety_lease_seconds: self
                .security
                .as_ref()
                .map(|security| security.safety_lease_seconds),
        }
    }

    pub(crate) fn maintenance_control(&self) -> ClusterMaintenanceControl {
        ClusterMaintenanceControl {
            node_id: self.node_id.clone(),
            enabled: self.is_enabled(),
            peer_authority: self.failure_supervisor_authority(),
            health: Arc::clone(&self.health),
            listener_rotation: Arc::clone(&self.listener_rotation),
            failure_policy: self.failure_policy(),
        }
    }

    pub(crate) fn maintenance_redis(&self) -> ClusterMaintenanceRedis {
        ClusterMaintenanceRedis {
            pool: self.pool.clone(),
            authority_pool: Arc::clone(&self.authority_pool),
            namespace: self.namespace.clone(),
            key_prefix: self.key_prefix.clone(),
            node_id: self.node_id.clone(),
            connection_uuid: self.connection_uuid,
            instance_epoch: Arc::clone(&self.instance_epoch),
            peer_nodes: self
                .security
                .as_ref()
                .map_or_else(Vec::new, |security| security.peer_node_ids()),
            health: Arc::clone(&self.health),
        }
    }

    pub(crate) fn muc_outbox_signal(&self) -> ClusterMucOutboxSignal {
        ClusterMucOutboxSignal {
            node_id: self.node_id.clone(),
            wake: Arc::clone(&self.muc_outbox_notify),
        }
    }

    fn signed_publisher(&self) -> ClusterSignedPublisher {
        ClusterSignedPublisher {
            pool: self.pool.clone(),
            namespace: self.namespace.clone(),
            key_prefix: self.key_prefix.clone(),
            node_id: self.node_id.clone(),
            security: self.security.clone(),
            connection_uuid: self.connection_uuid,
            instance_epoch: Arc::clone(&self.instance_epoch),
            authorized_instances: Arc::clone(&self.authorized_instances),
            health: Arc::clone(&self.health),
            listener_rotation: Arc::clone(&self.listener_rotation),
            failure_policy: self.failure_policy(),
            publication_gate: Arc::clone(&self.publication_gate),
        }
    }

    fn correlated_control_sender(&self) -> ClusterCorrelatedControlSender {
        ClusterCorrelatedControlSender {
            publisher: self.signed_publisher(),
            transport_ready: self.client.is_some(),
            pending_ack_slots: Arc::clone(&self.pending_ack_slots),
            pending_acks: Arc::clone(&self.pending_acks),
        }
    }

    pub(crate) fn node_delivery(&self) -> ClusterNodeDelivery {
        ClusterNodeDelivery {
            publisher: self.signed_publisher(),
            pool: self.pool.clone(),
            client: self.client.clone(),
            health: Arc::clone(&self.health),
            pending_ack_slots: Arc::clone(&self.pending_ack_slots),
            pending_acks: Arc::clone(&self.pending_acks),
        }
    }

    pub(crate) fn unavailable_delivery(&self) -> ClusterUnavailableDelivery {
        ClusterUnavailableDelivery {
            routes: self.listener_presence_routes(),
            sender: self.node_delivery(),
        }
    }

    pub(crate) fn account_teardown_notifier(&self) -> ClusterAccountTeardownNotifier {
        ClusterAccountTeardownNotifier {
            routes: self.listener_presence_routes(),
            sender: self.correlated_control_sender(),
        }
    }

    pub(crate) fn sm_session_teardown_notifier(&self) -> ClusterSmSessionTeardownNotifier {
        ClusterSmSessionTeardownNotifier {
            routes: self.listener_presence_routes(),
            sender: self.correlated_control_sender(),
        }
    }

    pub(crate) fn sm_muc_teardown(&self) -> ClusterSmMucTeardown {
        ClusterSmMucTeardown {
            sender: self.correlated_control_sender(),
        }
    }

    pub(crate) fn sm_suspension(&self) -> ClusterSmSuspension {
        ClusterSmSuspension {
            publisher: self.signed_publisher(),
            muc_outbox_notify: Arc::clone(&self.muc_outbox_notify),
        }
    }

    pub(crate) fn muc_operation_wake(&self) -> ClusterMucOperationWake {
        ClusterMucOperationWake {
            publisher: self.signed_publisher(),
            muc_outbox_notify: Arc::clone(&self.muc_outbox_notify),
        }
    }

    pub(crate) fn listener_presence_routes(&self) -> ClusterListenerPresenceRoutes {
        ClusterListenerPresenceRoutes {
            authority_pool: Arc::clone(&self.authority_pool),
            namespace: self.namespace.clone(),
            node_id: self.node_id.clone(),
            enabled: self.pool.is_some(),
        }
    }

    pub(crate) fn mix_route_lookup(&self) -> ClusterMixRouteLookup {
        ClusterMixRouteLookup {
            routes: self.listener_presence_routes(),
        }
    }

    pub(crate) fn listener_muc_projection(&self) -> ClusterListenerMucProjection {
        ClusterListenerMucProjection {
            pool: self.pool.clone(),
            key_prefix: self.key_prefix.clone(),
            node_id: self.node_id.clone(),
        }
    }

    pub(crate) fn sm_muc_teardown_projection(&self) -> ClusterSmMucTeardownProjection {
        ClusterSmMucTeardownProjection {
            pool: self.pool.clone(),
            key_prefix: self.key_prefix.clone(),
            node_id: self.node_id.clone(),
            connection_uuid: self.connection_uuid,
            instance_epoch: Arc::clone(&self.instance_epoch),
        }
    }

    pub(crate) fn muc_departure(&self) -> ClusterMucDeparture {
        ClusterMucDeparture {
            projection: self.sm_muc_teardown_projection(),
            publisher: self.signed_publisher(),
        }
    }

    pub(crate) fn session_termination_identity(&self) -> ClusterSessionTerminationIdentity {
        ClusterSessionTerminationIdentity {
            namespace: self.namespace.clone(),
            node_id: self.node_id.clone(),
            instance_uuid: self.connection_uuid,
            instance_epoch: Arc::clone(&self.instance_epoch),
        }
    }

    pub(crate) fn session_route_release(&self) -> ClusterSessionRouteRelease {
        ClusterSessionRouteRelease {
            pool: self.pool.clone(),
            authority_pool: Arc::clone(&self.authority_pool),
            namespace: self.namespace.clone(),
            key_prefix: self.key_prefix.clone(),
            node_id: self.node_id.clone(),
            connection_uuid: self.connection_uuid,
            instance_epoch: Arc::clone(&self.instance_epoch),
        }
    }

    pub(crate) fn pubsub_listener_transport(&self) -> ClusterPubsubListenerTransport {
        ClusterPubsubListenerTransport {
            client: self.client.clone(),
            pool: self.pool.clone(),
            key_prefix: self.key_prefix.clone(),
            node_id: self.node_id.clone(),
            connection_uuid: self.connection_uuid,
            instance_epoch: Arc::clone(&self.instance_epoch),
            health: Arc::clone(&self.health),
            listener_rotation: Arc::clone(&self.listener_rotation),
            failure_policy: self.failure_policy(),
        }
    }

    pub(crate) fn listener_admission(&self) -> ClusterListenerAdmission {
        ClusterListenerAdmission {
            health: Arc::clone(&self.health),
            pending_acks: Arc::clone(&self.pending_acks),
        }
    }

    pub(crate) fn listener_security(&self) -> ClusterListenerSecurity {
        ClusterListenerSecurity {
            publisher: self.signed_publisher(),
            authorized_peer_keys: Arc::clone(&self.authorized_peer_keys),
            authority_pool: Arc::clone(&self.authority_pool),
        }
    }

    pub fn is_enabled(&self) -> bool {
        self.pool.is_some()
    }

    pub fn configure_authority_pool(&self, pool: &sqlx::PgPool) -> Result<()> {
        self.authority_pool
            .set(pool.clone())
            .map_err(|_| anyhow::anyhow!("cluster PostgreSQL authority pool was configured twice"))
    }

    #[cfg(test)]
    fn register_pending_ack(
        &self,
        request_id: &str,
        source_node: &str,
        nonce: &str,
    ) -> Result<PendingAckRegistration> {
        register_pending_ack_in(
            &self.pending_ack_slots,
            &self.pending_acks,
            request_id,
            source_node,
            nonce,
        )
    }

    #[cfg(test)]
    fn dispatch_pending_ack(&self, source_node: &str, payload: serde_json::Value) -> bool {
        dispatch_pending_ack(&self.pending_acks, source_node, payload)
    }

    pub fn key_authority_identity(&self) -> Option<crate::db::ClusterKeyDeploymentIdentity> {
        let security = self.security.as_ref()?;
        Some(crate::db::ClusterKeyDeploymentIdentity {
            xmpp_domain: self.namespace.clone(),
            node_id: security.node_id.clone(),
            epoch: security.key_epoch,
            current_key_id: security.current_key_id.clone(),
            current_public_key_sha256: security.current_public_key_sha256.clone(),
            previous_key_id: security.previous_key_id.clone(),
            previous_public_key_sha256: security.previous_public_key_sha256.clone(),
            staged_next_key_id: security.staged_next_key_id.clone(),
            staged_next_public_key_sha256: security.staged_next_public_key_sha256.clone(),
        })
    }

    pub(crate) fn readiness_authority_snapshot(&self) -> Option<ClusterReadinessAuthority> {
        let security = self.security.as_ref()?;
        Some(ClusterReadinessAuthority {
            key_identity: self.key_authority_identity()?,
            instance_node_id: self.node_id.clone(),
            instance_uuid: self.connection_uuid,
            instance_epoch: self.instance_epoch.load(Ordering::Acquire),
            signing_key_id: security.current_key_id.clone(),
            signing_key_epoch: security.key_epoch,
        })
    }

    pub(crate) fn readiness_probe(&self) -> ClusterReadinessProbe {
        ClusterReadinessProbe {
            health: Arc::clone(&self.health),
            authority: self.readiness_authority_snapshot(),
            instance_epoch: Arc::clone(&self.instance_epoch),
        }
    }

    pub fn peer_key_authority_identities(&self) -> Vec<crate::db::ClusterKeyDeploymentIdentity> {
        self.security
            .as_ref()
            .map(|security| {
                security
                    .peer_key_authorities()
                    .into_iter()
                    .map(|peer| crate::db::ClusterKeyDeploymentIdentity {
                        xmpp_domain: self.namespace.clone(),
                        node_id: peer.node_id,
                        epoch: peer.epoch,
                        current_key_id: peer.current_key_id,
                        current_public_key_sha256: peer.current_public_key_sha256,
                        previous_key_id: peer.previous_key_id,
                        previous_public_key_sha256: peer.previous_public_key_sha256,
                        staged_next_key_id: peer.staged_next_key_id,
                        staged_next_public_key_sha256: peer.staged_next_public_key_sha256,
                    })
                    .collect()
            })
            .unwrap_or_default()
    }

    pub async fn activate(&self) -> Result<()> {
        if self.is_enabled() {
            anyhow::ensure!(
                self.instance_epoch.load(Ordering::Acquire) >= 1,
                "cluster node instance authority was not claimed"
            );
            self.touch_node().await?;
        }
        Ok(())
    }

    pub async fn claim_instance_authority(&self, pool: &sqlx::PgPool) -> Result<()> {
        if !self.is_enabled() {
            return Ok(());
        }
        let security = self
            .security
            .as_ref()
            .context("cluster signing identity is missing")?;
        let instance = crate::db::claim_cluster_node_instance(
            pool,
            &self.namespace,
            &self.node_id,
            self.connection_uuid,
            &security.current_key_id,
            security.key_epoch,
            Duration::from_secs(NODE_TTL_SECONDS),
        )
        .await?;
        self.install_instance_epoch(instance.instance_epoch)
    }

    pub fn install_instance_epoch(&self, instance_epoch: i64) -> Result<()> {
        anyhow::ensure!(
            instance_epoch >= 1,
            "cluster instance epoch must be positive"
        );
        let previous = self.instance_epoch.swap(instance_epoch, Ordering::AcqRel);
        anyhow::ensure!(
            previous == 0 || previous == instance_epoch,
            "cluster instance epoch changed inside one process"
        );
        Ok(())
    }

    pub async fn refresh_instance_authority(&self, pool: &sqlx::PgPool) -> Result<()> {
        // Bootstrap still owns its local pool before AppState is constructed.
        // Runtime workers use the AppState-owned typed authority service.
        let service = ClusterAuthorityService::new(
            crate::db::cluster_authority_repository::PostgresClusterAuthorityRepository::new(
                pool.clone(),
            ),
        );
        self.refresh_instance_authority_with(&service).await
    }

    pub(crate) async fn refresh_instance_authority_with<R: ClusterAuthorityRepository>(
        &self,
        service: &ClusterAuthorityService<R>,
    ) -> Result<()> {
        let Some(security) = self.security.as_ref() else {
            return Ok(());
        };
        let nodes = security.peer_node_ids();
        let expected = security.peer_key_authorities();
        refresh_peer_authority_with(
            service,
            &self.namespace,
            &expected,
            &nodes,
            &self.authorized_peer_keys,
            &self.authorized_instances,
        )
        .await
    }

    pub(crate) async fn release_instance_authority_with<R: ClusterInstanceReleaseRepository>(
        &self,
        service: &ClusterInstanceReleaseService<R>,
    ) -> Result<bool> {
        if !self.is_enabled() {
            return Ok(false);
        }
        let security = self
            .security
            .as_ref()
            .context("cluster signing identity is missing")?;
        service
            .release(&ClusterInstanceReleaseIdentity {
                xmpp_domain: self.namespace.clone(),
                node_id: self.node_id.clone(),
                instance_uuid: self.connection_uuid,
                instance_epoch: self.instance_epoch.load(Ordering::Acquire),
                signing_key_id: security.current_key_id.clone(),
                signing_key_epoch: security.key_epoch,
            })
            .await
    }

    pub fn begin_shutdown(&self) {
        self.require_shutdown();
    }

    /// Wait for every already-admitted signed publication to complete and
    /// prevent any later publication while the caller releases the database
    /// instance fence. `begin_shutdown` must be called first.
    pub async fn quiesce_publication(&self) -> tokio::sync::RwLockWriteGuard<'_, ()> {
        self.publication_gate.write().await
    }

    pub fn failure_policy(&self) -> Option<crate::cluster_security::ClusterFailurePolicy> {
        self.security
            .as_ref()
            .map(|security| security.failure_policy)
    }

    pub(crate) fn admission(&self) -> ClusterAdmission {
        ClusterAdmission {
            health: Arc::clone(&self.health),
        }
    }

    pub fn admit(&self, operation: ClusterOperation) -> Result<()> {
        admit_health(&self.health, operation)
    }

    #[cfg(test)]
    pub fn readiness_error(&self) -> Option<String> {
        cluster_readiness_error(&self.health)
    }

    pub(crate) fn metrics_probe(&self) -> ClusterMetricsProbe {
        ClusterMetricsProbe {
            health: Arc::clone(&self.health),
        }
    }

    pub fn record_control_plane_failure(&self, error: &anyhow::Error) {
        self.record_failure(ClusterFailureClass::RedisCommand, error);
    }

    #[cfg(test)]
    fn record_listener_failure(&self, error: &anyhow::Error) {
        self.record_failure(ClusterFailureClass::PubSub, error);
    }

    fn record_failure(&self, class: ClusterFailureClass, error: &anyhow::Error) {
        record_cluster_failure(
            &self.health,
            &self.listener_rotation,
            self.is_enabled(),
            self.failure_policy(),
            class,
            error,
        );
    }

    #[cfg(test)]
    fn confirm_listener_generation(&self, generation: u64, rotation_epoch: u64) -> Result<()> {
        confirm_listener_generation(&self.health, generation, rotation_epoch)
    }

    #[cfg(test)]
    fn note_listener_generation(&self) {
        let (generation, rotation_epoch) = self.health.begin_listener_attempt();
        self.confirm_listener_generation(generation, rotation_epoch)
            .unwrap();
    }

    #[cfg(test)]
    fn begin_reconciliation(&self) -> Result<u64> {
        begin_cluster_reconciliation(&self.health, self.is_enabled())
    }

    #[cfg(test)]
    fn complete_reconciliation(&self, rotation_epoch: u64) -> Result<ReconciliationOutcome> {
        complete_cluster_reconciliation(&self.health, rotation_epoch)
    }

    #[cfg(test)]
    fn complete_reconciliation_locked(
        &self,
        since: &mut std::sync::MutexGuard<'_, Option<Instant>>,
        rotation_epoch: u64,
    ) -> Result<ReconciliationOutcome> {
        complete_cluster_reconciliation_locked(&self.health, since, rotation_epoch)
    }

    fn require_shutdown(&self) {
        require_cluster_shutdown(&self.health, self.is_enabled());
    }

    fn key(&self, suffix: String) -> String {
        format!("{}:{suffix}", self.key_prefix)
    }

    fn process_instance_token(&self) -> Result<String> {
        let epoch = self.instance_epoch.load(Ordering::Acquire);
        anyhow::ensure!(epoch >= 1, "cluster process instance is not authoritative");
        Ok(format!("{}.{}", self.connection_uuid.simple(), epoch))
    }

    fn process_alive_key(&self) -> Result<String> {
        Ok(self.key(format!(
            "node_instance:{}:{}:alive",
            self.node_id,
            self.process_instance_token()?
        )))
    }

    async fn publish_signed(
        &self,
        conn: &mut redis::aio::MultiplexedConnection,
        destination_node: &str,
        channel: &str,
        payload: serde_json::Value,
    ) -> Result<i32> {
        self.signed_publisher()
            .publish_signed(conn, destination_node, channel, payload)
            .await
    }

    #[cfg(test)]
    fn verify_signed_payload(
        &self,
        raw: &str,
        channel: &str,
        expected_source: Option<&str>,
    ) -> Result<crate::cluster_security::SignedClusterEnvelope> {
        self.verify_signed_payload_inner(raw, channel, expected_source, true)
    }

    #[cfg(test)]
    fn verify_signed_payload_inner(
        &self,
        raw: &str,
        channel: &str,
        expected_source: Option<&str>,
        remember_replay: bool,
    ) -> Result<crate::cluster_security::SignedClusterEnvelope> {
        let envelope =
            self.listener_security()
                .verify_current_envelope(raw, channel, expected_source)?;
        if remember_replay {
            self.remember_envelope_replay(&envelope)?;
        }
        Ok(envelope)
    }

    #[cfg(test)]
    fn remember_envelope_replay(
        &self,
        envelope: &crate::cluster_security::SignedClusterEnvelope,
    ) -> Result<()> {
        let replay_key = format!(
            "{}:{}:{}:{}",
            envelope.source_node,
            envelope.connection_epoch,
            envelope.connection_uuid,
            envelope.event_id
        );
        let now = chrono::Utc::now().timestamp();
        let accept_until = envelope
            .expires_at
            .saturating_add(crate::cluster_security::CLOCK_SKEW_SECONDS);
        self.remember_replay_key(replay_key, accept_until, now, MAX_REPLAY_ENTRIES)
    }

    #[cfg(test)]
    fn remember_replay_key(
        &self,
        replay_key: String,
        accept_until: i64,
        now: i64,
        limit: usize,
    ) -> Result<()> {
        anyhow::ensure!(limit > 0, "cluster replay cache limit must be positive");
        // DashMap makes an individual entry operation atomic, but a separate
        // len-check followed by an insert is not an atomic capacity admission.
        // A signed peer can submit many envelopes concurrently, so serialize
        // expiry, capacity reservation and insertion under one short-lived
        // process-local gate. No await or external I/O occurs while held.
        let _admission = self
            .replay_cache_gate
            .lock()
            .map_err(|_| anyhow::anyhow!("cluster replay cache admission gate was poisoned"))?;
        if let Some(existing) = self.replay_cache.get(&replay_key) {
            let still_accepted = *existing >= now;
            drop(existing);
            if still_accepted {
                self.health
                    .replay_rejections
                    .fetch_add(1, Ordering::Relaxed);
                anyhow::bail!("cluster envelope replay rejected");
            }
            self.replay_cache.remove(&replay_key);
        }
        if self.replay_cache.len() >= limit
            && now > self.replay_cache_next_expiry.load(Ordering::Relaxed)
        {
            #[cfg(test)]
            self.replay_cache_sweeps.fetch_add(1, Ordering::Relaxed);
            let mut next_expiry = i64::MAX;
            self.replay_cache.retain(|_, accept_until| {
                let retained = *accept_until >= now;
                if retained {
                    next_expiry = next_expiry.min(*accept_until);
                }
                retained
            });
            self.replay_cache_next_expiry
                .store(next_expiry, Ordering::Relaxed);
        }
        anyhow::ensure!(
            self.replay_cache.len() < limit,
            "cluster replay cache is at capacity"
        );
        match self.replay_cache.entry(replay_key) {
            dashmap::mapref::entry::Entry::Vacant(entry) => {
                entry.insert(accept_until);
                self.replay_cache_next_expiry
                    .fetch_min(accept_until, Ordering::Relaxed);
            }
            dashmap::mapref::entry::Entry::Occupied(_) => {
                self.health
                    .replay_rejections
                    .fetch_add(1, Ordering::Relaxed);
                anyhow::bail!("cluster envelope replay rejected");
            }
        }
        Ok(())
    }

    async fn touch_node(&self) -> Result<()> {
        self.maintenance_redis().touch_node().await
    }

    pub async fn try_register_session(
        &self,
        full_jid: &str,
        connection_id: uuid::Uuid,
        proof: crate::services::sm::SessionRouteClaimProof,
    ) -> Result<bool> {
        self.admit(ClusterOperation::NewBinding)?;
        let (full_jid, bare) = session_route_keys(full_jid)?;
        let Some(pool) = &self.pool else {
            return Ok(true);
        };
        let authority_pool = self
            .authority_pool
            .get()
            .context("cluster session authority pool is unavailable")?;
        let owner_instance_epoch = self.instance_epoch.load(Ordering::Acquire);
        if !crate::db::claim_cluster_session_route(
            authority_pool,
            &self.namespace,
            &full_jid,
            &bare,
            &self.node_id,
            self.connection_uuid,
            owner_instance_epoch,
            connection_id,
            proof.into(),
            Duration::from_secs(SESSION_TTL_SECONDS),
        )
        .await?
        {
            return Ok(false);
        }
        let mut conn = pool.get().await?;
        let full_key = self.key(format!("session:{full_jid}"));
        let bare_key = self.key(format!("user_sessions:{bare}"));
        let activity_key = self.key("session_activity".to_owned());
        let instance_key = self.key(format!("session_instance:{full_jid}"));

        let script = redis::Script::new(
            r#"
            local owner = redis.call('get', KEYS[1])
            if owner and owner ~= ARGV[1] then
                local owner_alive = ARGV[3] .. ':node:' .. owner .. ':alive'
                if redis.call('exists', owner_alive) == 1 then return 0 end
            end
            redis.call('set', KEYS[1], ARGV[1], 'EX', ARGV[4])
            redis.call('set', KEYS[4], ARGV[6], 'EX', ARGV[4])
            redis.call('sadd', KEYS[2], ARGV[2])
            redis.call('expire', KEYS[2], ARGV[5])
            local now = redis.call('time')
            redis.call('zadd', KEYS[3], now[1], ARGV[2])
            return 1
            "#,
        );
        let reserved = script
            .key(&full_key)
            .key(&bare_key)
            .key(&activity_key)
            .key(&instance_key)
            .arg(&self.node_id)
            .arg(&full_jid)
            .arg(&self.key_prefix)
            .arg(SESSION_TTL_SECONDS)
            .arg(USER_SET_TTL_SECONDS)
            .arg(connection_id.to_string())
            .invoke_async::<i32>(&mut *conn)
            .await;
        match reserved {
            Ok(1) => Ok(true),
            Ok(_) => {
                let _ = crate::db::release_cluster_session_route(
                    authority_pool,
                    &self.namespace,
                    &full_jid,
                    &self.node_id,
                    self.connection_uuid,
                    owner_instance_epoch,
                    connection_id,
                )
                .await;
                Ok(false)
            }
            Err(error) => {
                let _ = crate::db::release_cluster_session_route(
                    authority_pool,
                    &self.namespace,
                    &full_jid,
                    &self.node_id,
                    self.connection_uuid,
                    owner_instance_epoch,
                    connection_id,
                )
                .await;
                Err(error.into())
            }
        }
    }

    pub async fn unregister_session(
        &self,
        full_jid: &str,
        connection_id: uuid::Uuid,
    ) -> Result<()> {
        self.session_route_release()
            .release_exact_local_session_route(full_jid, connection_id)
            .await
    }

    pub async fn lookup_nodes(&self, jid: &str) -> Result<Vec<String>> {
        let started = tokio::time::Instant::now();
        let result = self.listener_presence_routes().lookup_nodes(jid).await;
        tracing::debug!(
            elapsed_ms = started.elapsed().as_millis(),
            success = result.is_ok(),
            "Redis session-route lookup completed"
        );
        result
    }

    /// Enumerate canonical bare JIDs with at least one live Redis route.
    /// This is intentionally reserved for authenticated administrative
    /// statistics; normal stanza routing remains O(1) and never scans Redis.
    pub async fn online_bare_jids(&self) -> Result<std::collections::BTreeSet<String>> {
        let Some(pool) = &self.pool else {
            return Ok(std::collections::BTreeSet::new());
        };
        let mut conn = pool.get().await?;
        let prefix = self.key("user_sessions:".to_owned());
        let pattern = format!("{prefix}*");
        let mut cursor = 0u64;
        let mut online = std::collections::BTreeSet::new();
        loop {
            let (next, keys): (u64, Vec<String>) = redis::cmd("SCAN")
                .arg(cursor)
                .arg("MATCH")
                .arg(&pattern)
                .arg("COUNT")
                .arg(1000usize)
                .query_async(&mut *conn)
                .await?;
            for key in keys {
                let Some(candidate) = key.strip_prefix(&prefix) else {
                    continue;
                };
                let Ok(bare) = crate::jid::canonicalize_bare(candidate) else {
                    continue;
                };
                let full_jids: Vec<String> = conn.smembers(&key).await?;
                let mut live = false;
                for full_jid in full_jids {
                    let owner: Option<String> =
                        conn.get(self.key(format!("session:{full_jid}"))).await?;
                    if owner.is_some() {
                        live = true;
                    } else {
                        let _: usize = conn.srem(&key, &full_jid).await?;
                    }
                }
                if live {
                    online.insert(bare);
                }
            }
            cursor = next;
            if cursor == 0 {
                break;
            }
        }
        Ok(online)
    }

    pub async fn activity_bare_jids(
        &self,
        idle_seconds: u64,
        active: bool,
    ) -> Result<std::collections::BTreeSet<String>> {
        let Some(pool) = &self.pool else {
            return Ok(std::collections::BTreeSet::new());
        };
        let mut conn = pool.get().await?;
        let time: Vec<String> = redis::cmd("TIME").query_async(&mut *conn).await?;
        let now = time
            .first()
            .and_then(|value| value.parse::<i64>().ok())
            .context("Redis TIME response is invalid")?;
        let oldest = now.saturating_sub(SESSION_TTL_SECONDS as i64);
        let threshold = now.saturating_sub(idle_seconds as i64);
        let (minimum, maximum) = if active {
            (threshold.to_string(), "+inf".to_owned())
        } else {
            (oldest.to_string(), format!("({threshold}"))
        };
        let members: Vec<String> = redis::cmd("ZRANGEBYSCORE")
            .arg(self.key("session_activity".to_owned()))
            .arg(minimum)
            .arg(maximum)
            .query_async(&mut *conn)
            .await?;
        let mut users = std::collections::BTreeSet::new();
        for full_jid in members {
            let owner: Option<String> = conn.get(self.key(format!("session:{full_jid}"))).await?;
            if owner.is_none() {
                continue;
            }
            if let Ok(bare) = crate::jid::canonical_bare_key(&full_jid) {
                users.insert(bare);
            }
        }
        Ok(users)
    }

    pub async fn send_to_node(
        &self,
        node_id: &str,
        target_jid: &str,
        stanza: &str,
        carbons_only: bool,
        exclude_jid: Option<&str>,
    ) -> Result<bool> {
        let exclude_jids = exclude_jid.into_iter().collect::<Vec<_>>();
        Ok(self
            .send_to_node_receipt(
                node_id,
                target_jid,
                stanza,
                NodeDeliveryOptions {
                    carbons_only,
                    exclude_jids: &exclude_jids,
                    ..NodeDeliveryOptions::default()
                },
            )
            .await?
            .delivered)
    }

    /// Route a bare-JID broadcast only to resources that have announced
    /// available presence with a non-negative priority.  RFC 6121 uses this
    /// delivery mode for headline messages; ordinary cluster broadcasts
    /// (roster pushes, Carbons, and directed traffic) must not inherit this
    /// filter.
    pub async fn send_to_node_available(
        &self,
        node_id: &str,
        target_jid: &str,
        stanza: &str,
    ) -> Result<bool> {
        Ok(self
            .send_to_node_receipt(
                node_id,
                target_jid,
                stanza,
                NodeDeliveryOptions {
                    available_nonnegative_only: true,
                    ..NodeDeliveryOptions::default()
                },
            )
            .await?
            .delivered)
    }

    /// Route a database-backed bare-JID message to every eligible resource
    /// while carrying the exact PostgreSQL acknowledgement fence across the
    /// cluster bus.
    pub async fn send_to_node_available_durable(
        &self,
        node_id: &str,
        target_jid: &str,
        stanza: &str,
        delivery: crate::outbound::DurableDelivery,
    ) -> Result<bool> {
        Ok(self
            .send_to_node_receipt(
                node_id,
                target_jid,
                stanza,
                NodeDeliveryOptions {
                    available_nonnegative_only: true,
                    durable_delivery: Some(delivery),
                    ..NodeDeliveryOptions::default()
                },
            )
            .await?
            .delivered)
    }

    /// Route presence to every available resource of a bare JID. Presence
    /// routing does not use message priority, so negative-priority resources
    /// remain eligible here (unlike headline-message routing above).
    pub async fn send_to_node_available_presence(
        &self,
        node_id: &str,
        target_jid: &str,
        stanza: &str,
    ) -> Result<bool> {
        self.send_to_node_available_presence_excluding(node_id, target_jid, stanza, None)
            .await
    }

    pub async fn send_to_node_available_presence_excluding(
        &self,
        node_id: &str,
        target_jid: &str,
        stanza: &str,
        exclude_jid: Option<&str>,
    ) -> Result<bool> {
        let exclude_jids = exclude_jid.into_iter().collect::<Vec<_>>();
        Ok(self
            .send_to_node_receipt(
                node_id,
                target_jid,
                stanza,
                NodeDeliveryOptions {
                    available_only: true,
                    exclude_jids: &exclude_jids,
                    ..NodeDeliveryOptions::default()
                },
            )
            .await?
            .delivered)
    }

    /// Ask the node that owns one or more resources of `owner` to replay
    /// those resources' current available presence to every available
    /// resource of `recipient`. This closes the RFC 6121 initial-presence
    /// probe gap when the contact and requester are attached to different
    /// application nodes.
    pub async fn request_presence_probe_from_node(
        &self,
        node_id: &str,
        owner: &str,
        recipient: &str,
        availability_only: bool,
        authority: ClusterPresenceAuthority,
    ) -> Result<()> {
        let owner = crate::jid::canonicalize(owner)?;
        let recipient = crate::jid::canonicalize(recipient)?;
        self.send_control_to_node(
            node_id,
            &owner,
            serde_json::json!({
                "target": owner,
                "presence_probe": true,
                "recipient": recipient,
                "availability_only": availability_only,
                "presence_authority_version": PRESENCE_AUTHORITY_VERSION,
                "presence_owner_id": authority.owner_id,
                "presence_owner_auth_generation": authority.owner_auth_generation,
                "presence_recipient_id": authority.recipient_id,
                "presence_recipient_auth_generation": authority.recipient_auth_generation,
            }),
        )
        .await
    }

    /// Deliver an XEP-0191 push only to resources that successfully requested
    /// their blocklist on this (possibly resumed) session.
    pub async fn send_to_node_blocklist(
        &self,
        node_id: &str,
        target_jid: &str,
        stanza: &str,
    ) -> Result<bool> {
        Ok(self
            .send_to_node_receipt(
                node_id,
                target_jid,
                stanza,
                NodeDeliveryOptions {
                    blocklist_requested_only: true,
                    ..NodeDeliveryOptions::default()
                },
            )
            .await?
            .delivered)
    }

    /// Deliver an XEP-0016 list-definition push only to resources that have
    /// requested privacy-list state during this logical (possibly resumed)
    /// session.
    pub async fn send_to_node_privacy(
        &self,
        node_id: &str,
        target_jid: &str,
        stanza: &str,
    ) -> Result<bool> {
        Ok(self
            .send_to_node_receipt(
                node_id,
                target_jid,
                stanza,
                NodeDeliveryOptions {
                    privacy_requested_only: true,
                    ..NodeDeliveryOptions::default()
                },
            )
            .await?
            .delivered)
    }

    /// Deliver a presence-subscription notification to available resources.
    /// RFC 6121 roster interest gates roster pushes, not subscription-related
    /// presence. Callers therefore normally pass `false`; the parameter is
    /// retained for rolling compatibility with older cluster senders.
    pub async fn send_to_node_presence_subscription(
        &self,
        node_id: &str,
        target_jid: &str,
        stanza: &str,
        roster_requested_only: bool,
        authority: ClusterPresenceAuthority,
    ) -> Result<bool> {
        Ok(self
            .send_to_node_receipt(
                node_id,
                target_jid,
                stanza,
                NodeDeliveryOptions {
                    available_only: true,
                    roster_requested_only,
                    expected_user_id: Some(authority.recipient_id),
                    expected_auth_generation: Some(authority.recipient_auth_generation),
                    presence_authority: Some(authority),
                    presence_delivery: Some(ClusterPresenceDelivery::Subscription),
                    ..NodeDeliveryOptions::default()
                },
            )
            .await?
            .delivered)
    }

    /// Ask another node that owns resources of `owner` to emit those exact
    /// resources' polite-blocking presence transition.
    pub async fn send_blocking_presence_change(
        &self,
        node_id: &str,
        owner: &str,
        targets: &[String],
        patterns: &[String],
        available: bool,
    ) -> Result<()> {
        let (Some(pool), _) = (&self.pool, &self.client) else {
            return Ok(());
        };
        let owner = crate::jid::canonicalize_bare(owner)?;
        if targets.len() > northstar_xep_0191::MAX_ITEMS
            || patterns.len() > northstar_xep_0191::MAX_ITEMS
        {
            anyhow::bail!("too many blocking presence targets");
        }
        let targets = targets
            .iter()
            .map(|target| crate::jid::canonicalize(target))
            .collect::<Result<Vec<_>>>()?;
        let patterns = patterns
            .iter()
            .map(|pattern| crate::jid::canonicalize(pattern))
            .collect::<Result<Vec<_>>>()?;
        let payload = serde_json::json!({
            "target": owner,
            "blocking_presence_change": true,
            "blocking_targets": targets,
            "blocking_patterns": patterns,
            "available": available,
        });
        let mut conn = pool.get().await?;
        let channel = self.key(format!("node:{node_id}"));
        let _ = self
            .publish_signed(&mut conn, node_id, &channel, payload)
            .await?;
        Ok(())
    }

    /// Route a Carbon to a peer node while excluding every exact canonical
    /// resource in `exclude_jids`. The first exclusion is also written to the
    /// legacy scalar field, so rolling-upgrade peers still exclude the primary
    /// receiving resource rather than echoing a Carbon to it.
    pub async fn send_to_node_excluding(
        &self,
        node_id: &str,
        target_jid: &str,
        stanza: &str,
        carbons_only: bool,
        exclude_jids: &[&str],
    ) -> Result<bool> {
        Ok(self
            .send_to_node_receipt(
                node_id,
                target_jid,
                stanza,
                NodeDeliveryOptions {
                    carbons_only,
                    exclude_jids,
                    ..NodeDeliveryOptions::default()
                },
            )
            .await?
            .delivered)
    }

    pub async fn send_to_node_muc_carbons_excluding(
        &self,
        node_id: &str,
        target_jid: &str,
        stanza: &str,
        exclude_jids: &[&str],
        room_jid: &str,
        nick: &str,
    ) -> Result<bool> {
        Ok(self
            .send_to_node_receipt(
                node_id,
                target_jid,
                stanza,
                NodeDeliveryOptions {
                    carbons_only: true,
                    exclude_jids,
                    carbon_muc_scope: Some((room_jid, nick)),
                    ..NodeDeliveryOptions::default()
                },
            )
            .await?
            .delivered)
    }

    /// Route one primary one-to-one stanza and return the exact full-resource
    /// key that accepted it. A legacy peer can still report successful
    /// delivery without a key; callers must then suppress Carbons rather than
    /// guessing an exclusion.
    pub async fn send_to_node_primary(
        &self,
        node_id: &str,
        target_jid: &str,
        stanza: &str,
    ) -> Result<NodeDeliveryReceipt> {
        self.send_to_node_receipt(
            node_id,
            target_jid,
            stanza,
            NodeDeliveryOptions {
                primary: true,
                ..NodeDeliveryOptions::default()
            },
        )
        .await
    }

    /// Durable counterpart of [`Self::send_to_node_primary`]. The receiver
    /// verifies the exact spool row before attaching this fence to a socket.
    pub async fn send_to_node_primary_durable(
        &self,
        node_id: &str,
        target_jid: &str,
        stanza: &str,
        delivery: crate::outbound::DurableDelivery,
    ) -> Result<NodeDeliveryReceipt> {
        self.send_to_node_receipt(
            node_id,
            target_jid,
            stanza,
            NodeDeliveryOptions {
                primary: true,
                durable_delivery: Some(delivery),
                ..NodeDeliveryOptions::default()
            },
        )
        .await
    }

    /// Revoke older live logins belonging to one XEP-0388 client
    /// installation. The PostgreSQL epoch makes delayed/replayed controls
    /// harmless to a later replacement login.
    pub async fn send_user_agent_replacement(
        &self,
        bare_jid: &str,
        user_id: uuid::Uuid,
        device_id: uuid::Uuid,
        minimum_epoch: i64,
    ) -> Result<()> {
        anyhow::ensure!(minimum_epoch > 0, "invalid user-agent epoch");
        let bare_jid = crate::jid::canonicalize_bare(bare_jid)?;
        if self.pool.is_none() {
            return Ok(());
        }
        let nodes = self.lookup_nodes(&bare_jid).await?;
        let payload = serde_json::json!({
            "target": bare_jid,
            "user_agent_replacement": true,
            "user_id": user_id,
            "device_id": device_id,
            "minimum_epoch": minimum_epoch,
        });
        for node_id in nodes {
            if node_id != self.node_id {
                self.send_control_to_node(&node_id, &bare_jid, payload.clone())
                    .await?;
            }
        }
        Ok(())
    }

    /// Deliver an idempotent cluster control operation and wait until the
    /// addressed node confirms that it processed it. Redis Pub/Sub's publish
    /// return value only proves that a subscriber existed; without this
    /// correlated acknowledgement the durable teardown lease could be
    /// finalized while the remote node still retained live state.
    async fn send_control_to_node(
        &self,
        node_id: &str,
        target: &str,
        payload: serde_json::Value,
    ) -> Result<()> {
        self.correlated_control_sender()
            .send_control_to_node(node_id, target, payload)
            .await
    }

    async fn send_to_node_receipt(
        &self,
        node_id: &str,
        target_jid: &str,
        stanza: &str,
        options: NodeDeliveryOptions<'_>,
    ) -> Result<NodeDeliveryReceipt> {
        self.node_delivery()
            .send_to_node_receipt(node_id, target_jid, stanza, options)
            .await
    }
}

impl ClusterUnavailableDelivery {
    /// Preserve PostgreSQL route order and require the signed delivery ACK
    /// before considering a cleanup unavailable notification complete.
    pub(crate) async fn send_unavailable_to_remote_nodes(
        &self,
        target_jid: &str,
        stanza: &str,
        exclude_jid: &str,
        bare_target: bool,
    ) -> Result<()> {
        for node_id in self.routes.lookup_nodes(target_jid).await? {
            if node_id == self.routes.node_id {
                continue;
            }
            let exclusions = [exclude_jid];
            let receipt = self
                .sender
                .send_to_node_receipt(
                    &node_id,
                    target_jid,
                    stanza,
                    NodeDeliveryOptions {
                        available_only: bare_target,
                        exclude_jids: &exclusions,
                        ..NodeDeliveryOptions::default()
                    },
                )
                .await?;
            anyhow::ensure!(
                receipt.acknowledged,
                "cluster presence delivery was not acknowledged"
            );
        }
        Ok(())
    }
}

impl ClusterNodeDelivery {
    pub(crate) async fn send_mix(
        &self,
        node_id: &str,
        target_jid: &str,
        stanza: &str,
        source: Option<crate::outbound::MixDelivery>,
    ) -> Result<NodeDeliveryReceipt> {
        self.send_to_node_receipt(
            node_id,
            target_jid,
            stanza,
            NodeDeliveryOptions {
                mix_capable_only: true,
                mix_transport_receipt_required: source.is_some(),
                mix_delivery: source,
                ..NodeDeliveryOptions::default()
            },
        )
        .await
    }

    pub(crate) async fn send_mix_exact_account(
        &self,
        node_id: &str,
        target_full_jid: &str,
        stanza: &str,
        expected_user_id: uuid::Uuid,
    ) -> Result<bool> {
        let target = crate::jid::CanonicalJid::parse(target_full_jid)?;
        anyhow::ensure!(
            target.resourcepart().is_some(),
            "exact cluster delivery requires a full JID"
        );
        let canonical_target = target.to_string();
        let document = roxmltree::Document::parse(stanza)
            .context("exact cluster delivery requires one valid XML stanza")?;
        let root = document.root_element();
        anyhow::ensure!(
            root.tag_name().name() == "iq"
                && root.tag_name().namespace() == Some("jabber:client")
                && matches!(root.attribute("type"), Some("result" | "error"))
                && root.attribute("id").is_some_and(|id| !id.is_empty())
                && root.attribute("to").is_some_and(|to| {
                    crate::jid::canonical_session_key(to).ok().as_deref()
                        == Some(canonical_target.as_str())
                }),
            "exact cluster delivery must be an IQ addressed to the target resource"
        );
        let receipt = self
            .send_to_node_receipt(
                node_id,
                target_full_jid,
                stanza,
                NodeDeliveryOptions {
                    expected_user_id: Some(expected_user_id),
                    transport_receipt_required: true,
                    ..NodeDeliveryOptions::default()
                },
            )
            .await?;
        anyhow::ensure!(
            receipt.acknowledged,
            "exact cluster delivery was not acknowledged"
        );
        Ok(receipt.delivered)
    }

    pub(crate) async fn send_pubsub_notification(
        &self,
        node_id: &str,
        target_jid: &str,
        stanza: &str,
    ) -> Result<bool> {
        Ok(self
            .send_to_node_receipt(node_id, target_jid, stanza, NodeDeliveryOptions::default())
            .await?
            .delivered)
    }

    pub(crate) async fn send_roster_push(
        &self,
        node_id: &str,
        target_jid: &str,
        expected_user_id: uuid::Uuid,
        roster_version: i64,
        stanza: &str,
        annotated_stanza: Option<&str>,
    ) -> Result<bool> {
        Ok(self
            .send_to_node_receipt(
                node_id,
                target_jid,
                stanza,
                NodeDeliveryOptions {
                    roster_requested_only: true,
                    expected_user_id: Some(expected_user_id),
                    roster_version: Some(roster_version),
                    roster_annotated_stanza: annotated_stanza,
                    ..NodeDeliveryOptions::default()
                },
            )
            .await?
            .delivered)
    }

    pub(crate) async fn send_account_removal_presence(
        &self,
        node_id: &str,
        target_jid: &str,
        stanza: &str,
    ) -> Result<bool> {
        Ok(self
            .send_to_node_receipt(node_id, target_jid, stanza, NodeDeliveryOptions::default())
            .await?
            .delivered)
    }

    pub(crate) async fn send_available_presence(
        &self,
        node_id: &str,
        target_jid: &str,
        stanza: &str,
    ) -> Result<bool> {
        Ok(self
            .send_to_node_receipt(
                node_id,
                target_jid,
                stanza,
                NodeDeliveryOptions {
                    available_only: true,
                    ..NodeDeliveryOptions::default()
                },
            )
            .await?
            .delivered)
    }

    pub(crate) async fn send_current_presence_replay(
        &self,
        node_id: &str,
        target_jid: &str,
        stanza: &str,
        authority: ClusterPresenceAuthority,
    ) -> Result<bool> {
        Ok(self
            .send_to_node_receipt(
                node_id,
                target_jid,
                stanza,
                NodeDeliveryOptions {
                    available_only: true,
                    expected_user_id: Some(authority.recipient_id),
                    expected_auth_generation: Some(authority.recipient_auth_generation),
                    presence_authority: Some(authority),
                    presence_delivery: Some(ClusterPresenceDelivery::CurrentReplay),
                    ..NodeDeliveryOptions::default()
                },
            )
            .await?
            .delivered)
    }

    fn key(&self, suffix: String) -> String {
        self.publisher.key(suffix)
    }

    fn admit(&self, operation: ClusterOperation) -> Result<()> {
        admit_health(&self.health, operation)
    }

    fn note_incompatible_peer_version(&self, node_id: &str, observed: Option<&str>) {
        note_incompatible_peer_version(&self.health, node_id, observed);
    }

    fn record_control_plane_failure(&self, error: &anyhow::Error) {
        self.publisher.record_control_plane_failure(error);
    }

    fn register_pending_ack(
        &self,
        request_id: &str,
        source_node: &str,
        nonce: &str,
    ) -> Result<PendingAckRegistration> {
        register_pending_ack_in(
            &self.pending_ack_slots,
            &self.pending_acks,
            request_id,
            source_node,
            nonce,
        )
    }

    async fn publish_signed(
        &self,
        conn: &mut redis::aio::MultiplexedConnection,
        destination_node: &str,
        channel: &str,
        payload: serde_json::Value,
    ) -> Result<i32> {
        self.publisher
            .publish_signed(conn, destination_node, channel, payload)
            .await
    }

    async fn send_to_node_receipt(
        &self,
        node_id: &str,
        target_jid: &str,
        stanza: &str,
        options: NodeDeliveryOptions<'_>,
    ) -> Result<NodeDeliveryReceipt> {
        anyhow::ensure!(
            !options.roster_requested_only
                || (options.expected_user_id.is_some() && options.roster_version.is_some()),
            "cluster roster delivery requires an exact account and version fence"
        );
        anyhow::ensure!(
            options.roster_annotated_stanza.is_none() || options.roster_requested_only,
            "annotated roster payload cannot be used for ordinary delivery"
        );
        anyhow::ensure!(
            options.presence_delivery.is_some() == options.presence_authority.is_some(),
            "cluster presence delivery requires one complete versioned authority"
        );
        if let Some(authority) = options.presence_authority {
            anyhow::ensure!(
                options.expected_user_id == Some(authority.recipient_id)
                    && options.expected_auth_generation
                        == Some(authority.recipient_auth_generation),
                "cluster presence recipient fence does not match its authority"
            );
        }
        if let Some(version) = options.roster_version {
            anyhow::ensure!(
                cluster_roster_push_version(stanza) == Some(version),
                "cluster roster payload version does not match its delivery fence"
            );
        }
        if let Some(annotated) = options.roster_annotated_stanza {
            anyhow::ensure!(
                annotated.len() <= crate::xmpp::MAX_XMPP_FRAME_BYTES,
                "annotated roster payload exceeds the stanza limit"
            );
            anyhow::ensure!(
                cluster_roster_push_version(annotated) == options.roster_version,
                "annotated cluster roster payload version does not match its delivery fence"
            );
        }
        if self.health.state.load(Ordering::Acquire) == CLUSTER_DURABLE_DIRECT_ONLY
            && (options.durable_delivery.is_some() || options.mix_delivery.is_some())
        {
            // The PostgreSQL row remains the only accepted projection. The
            // caller observes no live acceptance and leaves it for replay.
            return Ok(NodeDeliveryReceipt::default());
        }
        self.admit(
            if options.durable_delivery.is_some() || options.mix_delivery.is_some() {
                ClusterOperation::DurableDirect
            } else {
                ClusterOperation::VolatileDelivery
            },
        )?;
        let target_jid = crate::jid::canonicalize(target_jid)?;
        let delivery_contract = outbound_delivery_contract(
            stanza,
            &target_jid,
            options.durable_delivery,
            options.mix_delivery,
        )?;
        if options.exclude_jids.len() > MAX_DELIVERY_EXCLUSIONS {
            anyhow::bail!("too many cluster delivery exclusions");
        }
        let exclude_jids = options
            .exclude_jids
            .iter()
            .map(|jid| crate::jid::canonical_session_key(jid))
            .collect::<Result<Vec<_>>>()?;
        let carbon_muc_scope = options
            .carbon_muc_scope
            .map(|(room, nick)| {
                Ok::<_, anyhow::Error>((
                    crate::jid::canonicalize_bare(room)?,
                    crate::xmpp::xml_util::prepare_muc_nick(nick)?,
                ))
            })
            .transpose()?;
        anyhow::ensure!(
            !(options.transport_receipt_required && options.mix_transport_receipt_required),
            "cluster delivery cannot combine exact-resource and MIX transport receipts"
        );
        if options.transport_receipt_required {
            anyhow::ensure!(
                delivery_contract.is_none()
                    && options.expected_user_id.is_some()
                    && crate::jid::CanonicalJid::parse(&target_jid)?
                        .resourcepart()
                        .is_some()
                    && !options.carbons_only
                    && !options.blocklist_requested_only
                    && !options.roster_requested_only
                    && !options.privacy_requested_only
                    && !options.mix_capable_only
                    && !options.primary
                    && !options.available_only
                    && !options.available_nonnegative_only
                    && exclude_jids.is_empty()
                    && carbon_muc_scope.is_none(),
                "transport-receipted cluster delivery requires one exact account resource"
            );
        }
        if options.mix_transport_receipt_required {
            anyhow::ensure!(
                matches!(
                    delivery_contract,
                    Some(NodeDeliveryContract::DurableMix { .. })
                ) && options.mix_capable_only
                    && crate::jid::CanonicalJid::parse(&target_jid)?
                        .resourcepart()
                        .is_none()
                    && !options.carbons_only
                    && !options.blocklist_requested_only
                    && !options.roster_requested_only
                    && !options.privacy_requested_only
                    && !options.primary
                    && !options.available_only
                    && !options.available_nonnegative_only
                    && options.expected_user_id.is_none()
                    && options.expected_auth_generation.is_none()
                    && options.roster_version.is_none()
                    && options.roster_annotated_stanza.is_none()
                    && exclude_jids.is_empty()
                    && carbon_muc_scope.is_none(),
                "MIX transport-receipted cluster delivery requires one exact bare-JID MIX source"
            );
        }
        let legacy_exclude_jid = exclude_jids.first();
        let (Some(pool), Some(_)) = (&self.pool, &self.client) else {
            return Ok(NodeDeliveryReceipt::default());
        };
        let request_id = uuid::Uuid::new_v4().to_string();
        let nonce = format!("{}{}", uuid::Uuid::new_v4(), uuid::Uuid::new_v4());
        let channel = self.key(format!("node:{node_id}"));
        let payload = serde_json::json!({
            "protocol_version": NODE_PROTOCOL_VERSION,
            "target": target_jid,
            "stanza": stanza,
            "delivery": delivery_contract,
            "carbons_only": options.carbons_only,
            "blocklist_requested_only": options.blocklist_requested_only,
            "roster_requested_only": options.roster_requested_only,
            "expected_user_id": options.expected_user_id,
            "expected_auth_generation": options.expected_auth_generation,
            "roster_version": options.roster_version,
            "roster_annotated_stanza": options.roster_annotated_stanza,
            "privacy_requested_only": options.privacy_requested_only,
            "mix_capable_only": options.mix_capable_only,
            "transport_receipt_required": options.transport_receipt_required,
            "mix_transport_receipt_required": options.mix_transport_receipt_required,
            "exclude_jid": legacy_exclude_jid,
            "exclude_jids": exclude_jids,
            "request_id": request_id,
            "ack_nonce": nonce,
            "primary_one_to_one": options.primary,
            "available_only": options.available_only,
            "available_nonnegative_only": options.available_nonnegative_only,
            "presence_authority_version": options
                .presence_authority
                .map(|_| PRESENCE_AUTHORITY_VERSION),
            "presence_owner_id": options.presence_authority.map(|value| value.owner_id),
            "presence_owner_auth_generation": options
                .presence_authority
                .map(|value| value.owner_auth_generation),
            "presence_recipient_id": options.presence_authority.map(|value| value.recipient_id),
            "presence_recipient_auth_generation": options
                .presence_authority
                .map(|value| value.recipient_auth_generation),
            "current_presence_replay": options.presence_delivery
                == Some(ClusterPresenceDelivery::CurrentReplay),
            "presence_subscription": options.presence_delivery
                == Some(ClusterPresenceDelivery::Subscription),
            "carbon_muc_room": carbon_muc_scope.as_ref().map(|scope| scope.0.as_str()),
            "carbon_muc_nick": carbon_muc_scope.as_ref().map(|scope| scope.1.as_str()),
        });
        let mut conn = pool.get().await?;
        let peer_version: Option<String> =
            conn.get(self.key(format!("node:{node_id}:alive"))).await?;
        if !supports_current_cluster_protocol(peer_version.as_deref()) {
            if peer_version.is_some() {
                self.note_incompatible_peer_version(node_id, peer_version.as_deref());
            }
            tracing::warn!(
                %node_id,
                peer_version = peer_version.as_deref().unwrap_or("missing"),
                "declined traffic for a peer without the authenticated current cluster protocol"
            );
            return Ok(NodeDeliveryReceipt::default());
        }
        // Older peers do not understand the MUC membership scope and would
        // fan the private-message Carbon to unrelated resources. Fail closed
        // during a rolling upgrade rather than weakening conversation
        // privacy; an ordinary Carbon remains backward compatible.
        if carbon_muc_scope.is_some() && !supports_control_ack(peer_version.as_deref()) {
            return Ok(NodeDeliveryReceipt::default());
        }
        if let Some(contract) = delivery_contract {
            if supports_delivery_contract(peer_version.as_deref()) {
                // The current peer will validate and echo the exact contract.
            } else if supports_legacy_delivery_inference(peer_version.as_deref()) {
                // Version 7 and older recover a durable fence from the
                // recipient-authoritative stanza-id. Only send traffic whose
                // explicit current-version contract is exactly representable by that old
                // algorithm. In particular, a volatile no-store stanza with
                // such an ID must wait for the rolling upgrade to finish.
                let identity = crate::outbound::recipient_delivery_identity(stanza, &target_jid);
                if !delivery_contract_compatible_with_peer(
                    peer_version.as_deref(),
                    contract,
                    identity,
                ) {
                    tracing::warn!(
                        %node_id,
                        "declined a message whose delivery contract is unsafe for a legacy cluster peer"
                    );
                    return Ok(NodeDeliveryReceipt::default());
                }
            } else {
                tracing::warn!(
                    %node_id,
                    peer_version = peer_version.as_deref().unwrap_or("missing"),
                    "declined a message for a cluster peer with an unsupported delivery protocol"
                );
                return Ok(NodeDeliveryReceipt::default());
            }
        }
        let require_correlated_ack = requires_correlated_ack(peer_version.as_deref());
        let require_delivery_contract =
            delivery_contract.is_some() && supports_delivery_contract(peer_version.as_deref());
        let mut acknowledgement = self.register_pending_ack(&request_id, node_id, &nonce)?;
        let result = async {
            let receivers = self
                .publish_signed(&mut conn, node_id, &channel, payload)
                .await?;
            drop(conn);
            if receivers == 0 {
                self.record_control_plane_failure(&anyhow::anyhow!(
                    "cluster delivery had no authoritative subscriber"
                ));
                return Ok(NodeDeliveryReceipt::default());
            }
            let deadline = tokio::time::Instant::now() + DELIVERY_ACK_TIMEOUT;
            loop {
                let Some(ack) = tokio::time::timeout_at(deadline, acknowledgement.recv())
                    .await
                    .ok()
                    .flatten()
                else {
                    self.record_control_plane_failure(&anyhow::anyhow!(
                        "cluster delivery acknowledgement timed out"
                    ));
                    return Ok(NodeDeliveryReceipt::default());
                };
                let Ok(ack_payload) = serde_json::to_string(&ack) else {
                    continue;
                };
                if let Some(receipt) = validated_delivery_ack(
                    &ack_payload,
                    DeliveryAckExpectation {
                        request_id: &request_id,
                        nonce: &nonce,
                        node_id,
                        target_jid: &target_jid,
                        primary: options.primary,
                        delivery: delivery_contract,
                        require_delivery_contract,
                        mix_capable_only: options.mix_capable_only,
                        transport_receipt_required: options.transport_receipt_required,
                        mix_transport_receipt_required: options.mix_transport_receipt_required,
                    },
                ) {
                    return Ok(receipt);
                }
                debug_assert!(require_correlated_ack);
            }
        }
        .await;
        result
    }
}

impl ClusterManager {
    /// Reconcile disposable Redis room indexes without consulting them for
    /// authority. Both the stable node lease and the exact process-instance
    /// lease must be live. This lets a restarted process remove its own old
    /// projection immediately instead of preserving ghosts behind a reused
    /// node ID. The O(room-size) sweep is maintenance/read-only work; stanza
    /// fan-out never invokes it.
    async fn reconcile_muc_soft_state(&self, room_jid: &str) -> Result<()> {
        self.maintenance_redis()
            .reconcile_muc_soft_state(room_jid)
            .await
    }

    pub async fn try_register_muc_occupant(
        &self,
        room_jid: &str,
        nick: &str,
        json: &str,
        max_occupants: usize,
    ) -> Result<MucRegistration> {
        self.admit(ClusterOperation::MucMutation)?;
        let incoming: crate::state::SerializableMucOccupant = serde_json::from_str(json)?;
        let canonical_room = crate::jid::canonicalize_bare(room_jid)?;
        let prepared_nick = crate::xmpp::xml_util::prepare_muc_nick(nick)?;
        anyhow::ensure!(
            incoming.room_jid == canonical_room
                && incoming.nick == prepared_nick
                && !incoming.cluster_epoch.is_nil()
                && !incoming.connection_id.is_nil(),
            "MUC registration requires an exact non-nil occupancy identity"
        );
        let Some(pool) = &self.pool else {
            return Ok(MucRegistration::Joined);
        };
        let mut conn = pool.get().await?;
        let room = canonical_room;
        let nick = prepared_nick;
        let process_instance = self.process_instance_token()?;
        let occupants_key = self.key(format!("muc_occupants:{room}"));
        let owners_key = self.key(format!("muc_occupant_nodes:{room}"));
        let nodes_key = self.key(format!("muc_nodes:{room}"));
        let instances_key = self.key(format!("muc_occupant_instances:{room}"));
        let node_counts_key = self.key(format!("muc_node_counts:{room}"));
        let alive_key = self.key(format!("node:{}:alive", self.node_id));
        let process_alive_key = self.process_alive_key()?;
        let script = redis::Script::new(
            r#"
            redis.call('set', KEYS[6], ARGV[7], 'EX', ARGV[6])
            redis.call('set', KEYS[7], ARGV[7], 'EX', ARGV[6])
            local current = redis.call('hget', KEYS[1], ARGV[1])
            local owner = redis.call('hget', KEYS[2], ARGV[1])
            local instance = redis.call('hget', KEYS[4], ARGV[1])
            if owner and instance
                and redis.call(
                    'exists', ARGV[9] .. owner .. ':' .. instance .. ':alive'
                ) == 0
            then
                redis.call('hdel', KEYS[1], ARGV[1])
                redis.call('hdel', KEYS[2], ARGV[1])
                redis.call('hdel', KEYS[4], ARGV[1])
                local count = redis.call('hincrby', KEYS[5], owner, -1)
                if count <= 0 then
                    redis.call('hdel', KEYS[5], owner)
                    redis.call('srem', KEYS[3], owner)
                end
                current = false
                owner = false
                instance = false
            end
            if current or owner or instance then
                if current == ARGV[2] and owner == ARGV[3] and instance == ARGV[4] then
                    redis.call('sadd', KEYS[3], ARGV[3])
                    redis.call('expire', KEYS[1], ARGV[8])
                    redis.call('expire', KEYS[2], ARGV[8])
                    redis.call('expire', KEYS[3], ARGV[8])
                    redis.call('expire', KEYS[4], ARGV[8])
                    redis.call('expire', KEYS[5], ARGV[8])
                    return 1
                end
                return 0
            end
            if redis.call('hlen', KEYS[1]) >= tonumber(ARGV[5]) then return -1 end
            redis.call('hset', KEYS[1], ARGV[1], ARGV[2])
            redis.call('hset', KEYS[2], ARGV[1], ARGV[3])
            redis.call('hset', KEYS[4], ARGV[1], ARGV[4])
            redis.call('hincrby', KEYS[5], ARGV[3], 1)
            redis.call('sadd', KEYS[3], ARGV[3])
            redis.call('expire', KEYS[1], ARGV[8])
            redis.call('expire', KEYS[2], ARGV[8])
            redis.call('expire', KEYS[3], ARGV[8])
            redis.call('expire', KEYS[4], ARGV[8])
            redis.call('expire', KEYS[5], ARGV[8])
            return 1
            "#,
        );
        let result: i32 = script
            .key(occupants_key)
            .key(owners_key)
            .key(nodes_key)
            .key(instances_key)
            .key(node_counts_key)
            .key(alive_key)
            .key(process_alive_key)
            .arg(&nick)
            .arg(json)
            .arg(&self.node_id)
            .arg(process_instance)
            .arg(max_occupants.max(1))
            .arg(NODE_TTL_SECONDS)
            .arg(NODE_PROTOCOL_VERSION)
            .arg(MUC_SOFT_STATE_TTL_SECONDS)
            .arg(self.key("node_instance:".to_owned()))
            .invoke_async(&mut *conn)
            .await?;
        Ok(match result {
            1 => MucRegistration::Joined,
            -1 => MucRegistration::Full,
            _ => MucRegistration::Conflict,
        })
    }

    /// Atomically move one exact MUC occupancy to a new nickname.  The
    /// serialized occupant contains a per-join UUID (`cluster_epoch`); Redis
    /// compares the entire old value and the owning node before changing any
    /// key, so a delayed rename can neither steal a nickname nor delete a
    /// newer ABA replacement on the same node.
    pub async fn rename_muc_occupant(
        &self,
        room_jid: &str,
        old_nick: &str,
        new_nick: &str,
        expected_epoch: uuid::Uuid,
        old_json: &str,
        new_json: &str,
    ) -> Result<MucRename> {
        self.admit(ClusterOperation::MucMutation)?;
        let room = crate::jid::canonicalize_bare(room_jid)?;
        let old_nick = crate::xmpp::xml_util::prepare_muc_nick(old_nick)?;
        let new_nick = crate::xmpp::xml_util::prepare_muc_nick(new_nick)?;
        anyhow::ensure!(
            old_nick != new_nick,
            "MUC nickname rename must change the nickname"
        );
        anyhow::ensure!(
            !expected_epoch.is_nil(),
            "MUC rename requires a non-nil occupancy epoch"
        );
        for (json, expected_nick) in [(old_json, old_nick.as_str()), (new_json, new_nick.as_str())]
        {
            let occupant: crate::state::SerializableMucOccupant = serde_json::from_str(json)?;
            anyhow::ensure!(
                occupant.cluster_epoch == expected_epoch
                    && occupant.room_jid == room
                    && occupant.nick == expected_nick,
                "MUC rename payload does not describe the guarded occupancy"
            );
        }
        let old_occupant: crate::state::SerializableMucOccupant = serde_json::from_str(old_json)?;
        let new_occupant: crate::state::SerializableMucOccupant = serde_json::from_str(new_json)?;
        anyhow::ensure!(
            old_occupant.full_jid == new_occupant.full_jid
                && old_occupant.connection_id == new_occupant.connection_id
                && !old_occupant.connection_id.is_nil(),
            "MUC nickname rename cannot change actor or transport ownership"
        );
        let Some(pool) = &self.pool else {
            return Ok(MucRename::Renamed);
        };
        let mut conn = pool.get().await?;
        let process_instance = self.process_instance_token()?;
        let occupants_key = self.key(format!("muc_occupants:{room}"));
        let owners_key = self.key(format!("muc_occupant_nodes:{room}"));
        let nodes_key = self.key(format!("muc_nodes:{room}"));
        let instances_key = self.key(format!("muc_occupant_instances:{room}"));
        let node_counts_key = self.key(format!("muc_node_counts:{room}"));
        let alive_key = self.key(format!("node:{}:alive", self.node_id));
        let process_alive_key = self.process_alive_key()?;
        let script = redis::Script::new(
            r#"
            if redis.call('hget', KEYS[2], ARGV[1]) ~= ARGV[4] then return -1 end
            if redis.call('hget', KEYS[1], ARGV[1]) ~= ARGV[3] then return -1 end
            if redis.call('hget', KEYS[4], ARGV[1]) ~= ARGV[5] then return -1 end
            if redis.call('hexists', KEYS[1], ARGV[2]) == 1 then return 0 end
            redis.call('hset', KEYS[1], ARGV[2], ARGV[6])
            redis.call('hset', KEYS[2], ARGV[2], ARGV[4])
            redis.call('hset', KEYS[4], ARGV[2], ARGV[5])
            redis.call('hdel', KEYS[1], ARGV[1])
            redis.call('hdel', KEYS[2], ARGV[1])
            redis.call('hdel', KEYS[4], ARGV[1])
            redis.call('sadd', KEYS[3], ARGV[4])
            redis.call('set', KEYS[6], ARGV[8], 'EX', ARGV[7])
            redis.call('set', KEYS[7], ARGV[8], 'EX', ARGV[7])
            redis.call('expire', KEYS[1], ARGV[9])
            redis.call('expire', KEYS[2], ARGV[9])
            redis.call('expire', KEYS[3], ARGV[9])
            redis.call('expire', KEYS[4], ARGV[9])
            redis.call('expire', KEYS[5], ARGV[9])
            return 1
            "#,
        );
        let result: i32 = script
            .key(occupants_key)
            .key(owners_key)
            .key(nodes_key)
            .key(instances_key)
            .key(node_counts_key)
            .key(alive_key)
            .key(process_alive_key)
            .arg(&old_nick)
            .arg(&new_nick)
            .arg(old_json)
            .arg(&self.node_id)
            .arg(process_instance)
            .arg(new_json)
            .arg(NODE_TTL_SECONDS)
            .arg(NODE_PROTOCOL_VERSION)
            .arg(MUC_SOFT_STATE_TTL_SECONDS)
            .invoke_async(&mut *conn)
            .await?;
        Ok(match result {
            1 => MucRename::Renamed,
            0 => MucRename::Conflict,
            _ => MucRename::Stale,
        })
    }

    /// Atomically update the role of one exact occupancy and notify all room
    /// nodes.  Exact serialized-value comparison is an ABA guard: a delayed
    /// moderator action cannot mutate a newer occupant that reused the nick.
    pub async fn change_muc_occupant_role(
        &self,
        room_jid: &str,
        occupant: &crate::state::SerializableMucOccupant,
        new_role: &str,
    ) -> Result<MucRoleChange> {
        self.admit(ClusterOperation::MucMutation)?;
        anyhow::ensure!(
            matches!(new_role, "moderator" | "participant" | "visitor"),
            "clustered role changes require moderator, participant, or visitor role"
        );
        let room = crate::jid::canonicalize_bare(room_jid)?;
        let nick = crate::xmpp::xml_util::prepare_muc_nick(&occupant.nick)?;
        anyhow::ensure!(
            occupant.room_jid == room && !occupant.cluster_epoch.is_nil(),
            "clustered voice change requires the exact non-nil occupancy epoch"
        );
        let mut updated = occupant.clone();
        updated.role = new_role.to_owned();
        let old_json = serde_json::to_string(occupant)?;
        let new_json = serde_json::to_string(&updated)?;
        let Some(pool) = &self.pool else {
            return Ok(MucRoleChange::Changed(Box::new(updated)));
        };
        let mut conn = pool.get().await?;
        let occupants_key = self.key(format!("muc_occupants:{room}"));
        let owners_key = self.key(format!("muc_occupant_nodes:{room}"));
        let script = redis::Script::new(
            r#"
            if redis.call('hexists', KEYS[2], ARGV[1]) == 0 then return 0 end
            if redis.call('hget', KEYS[1], ARGV[1]) ~= ARGV[2] then return 0 end
            redis.call('hset', KEYS[1], ARGV[1], ARGV[3])
            return 1
            "#,
        );
        let changed: i32 = script
            .key(occupants_key)
            .key(owners_key)
            .arg(&nick)
            .arg(old_json)
            .arg(new_json)
            .invoke_async(&mut *conn)
            .await?;
        if changed != 1 {
            return Ok(MucRoleChange::Stale);
        }
        let nodes = self.active_muc_nodes(&room).await?;
        let payload = serde_json::json!({
            "target": room,
            "muc_role_change": true,
            "occupant": updated,
        });
        for node_id in nodes {
            if node_id != self.node_id {
                let channel = self.key(format!("node:{node_id}"));
                let _ = self
                    .publish_signed(&mut conn, &node_id, &channel, payload.clone())
                    .await?;
            }
        }
        Ok(MucRoleChange::Changed(Box::new(updated)))
    }

    /// Atomically apply an affiliation-derived role to an exact occupancy.
    /// This is used by a room administrator on a different node; the old
    /// serialized value is the CAS token and the immutable identity fields
    /// may not change.
    pub async fn change_muc_occupant_affiliation(
        &self,
        room_jid: &str,
        occupant: &crate::state::SerializableMucOccupant,
        affiliation: &str,
        role: &str,
    ) -> Result<MucRoleChange> {
        self.admit(ClusterOperation::MucMutation)?;
        anyhow::ensure!(
            matches!(affiliation, "owner" | "admin" | "member" | "none")
                && matches!(role, "moderator" | "participant" | "visitor"),
            "invalid live MUC affiliation transition"
        );
        let room = crate::jid::canonicalize_bare(room_jid)?;
        let nick = crate::xmpp::xml_util::prepare_muc_nick(&occupant.nick)?;
        anyhow::ensure!(
            occupant.room_jid == room
                && !occupant.cluster_epoch.is_nil()
                && !occupant.connection_id.is_nil(),
            "clustered affiliation change requires the exact occupancy identity"
        );
        let mut updated = occupant.clone();
        updated.affiliation = affiliation.to_owned();
        updated.role = role.to_owned();
        let old_json = serde_json::to_string(occupant)?;
        let new_json = serde_json::to_string(&updated)?;
        let Some(pool) = &self.pool else {
            return Ok(MucRoleChange::Changed(Box::new(updated)));
        };
        let mut conn = pool.get().await?;
        let occupants_key = self.key(format!("muc_occupants:{room}"));
        let owners_key = self.key(format!("muc_occupant_nodes:{room}"));
        let script = redis::Script::new(
            r#"
            if redis.call('hexists', KEYS[2], ARGV[1]) == 0 then return 0 end
            if redis.call('hget', KEYS[1], ARGV[1]) ~= ARGV[2] then return 0 end
            redis.call('hset', KEYS[1], ARGV[1], ARGV[3])
            return 1
            "#,
        );
        let changed: i32 = script
            .key(occupants_key)
            .key(owners_key)
            .arg(&nick)
            .arg(old_json)
            .arg(new_json)
            .invoke_async(&mut *conn)
            .await?;
        if changed != 1 {
            return Ok(MucRoleChange::Stale);
        }
        let nodes = self.active_muc_nodes(&room).await?;
        let payload = serde_json::json!({
            "target": room,
            "muc_role_change": true,
            "occupant": updated,
        });
        for node_id in nodes {
            if node_id != self.node_id {
                let channel = self.key(format!("node:{node_id}"));
                let _ = self
                    .publish_signed(&mut conn, &node_id, &channel, payload.clone())
                    .await?;
            }
        }
        Ok(MucRoleChange::Changed(Box::new(updated)))
    }

    /// Atomically synchronize the room-derived live policy for one exact
    /// occupancy.  Room configuration is PostgreSQL-authoritative, but the
    /// role and real-JID visibility cached in Redis and on every serving node
    /// must change together so a remote participant cannot retain voice or a
    /// stale anonymity view after an owner configuration update.
    pub async fn change_muc_occupant_policy(
        &self,
        room_jid: &str,
        occupant: &crate::state::SerializableMucOccupant,
        role: &str,
        room_non_anonymous: bool,
    ) -> Result<MucRoleChange> {
        self.admit(ClusterOperation::MucMutation)?;
        anyhow::ensure!(
            matches!(role, "moderator" | "participant" | "visitor"),
            "invalid room-derived MUC role"
        );
        let room = crate::jid::canonicalize_bare(room_jid)?;
        let nick = crate::xmpp::xml_util::prepare_muc_nick(&occupant.nick)?;
        anyhow::ensure!(
            occupant.room_jid == room
                && !occupant.cluster_epoch.is_nil()
                && !occupant.connection_id.is_nil(),
            "clustered room policy change requires the exact occupancy identity"
        );
        let mut updated = occupant.clone();
        updated.role = role.to_owned();
        updated.room_non_anonymous = room_non_anonymous;
        let old_json = serde_json::to_string(occupant)?;
        let new_json = serde_json::to_string(&updated)?;
        let Some(pool) = &self.pool else {
            return Ok(MucRoleChange::Changed(Box::new(updated)));
        };
        let mut conn = pool.get().await?;
        let occupants_key = self.key(format!("muc_occupants:{room}"));
        let owners_key = self.key(format!("muc_occupant_nodes:{room}"));
        let script = redis::Script::new(
            r#"
            if redis.call('hexists', KEYS[2], ARGV[1]) == 0 then return 0 end
            if redis.call('hget', KEYS[1], ARGV[1]) ~= ARGV[2] then return 0 end
            redis.call('hset', KEYS[1], ARGV[1], ARGV[3])
            return 1
            "#,
        );
        let changed: i32 = script
            .key(occupants_key)
            .key(owners_key)
            .arg(&nick)
            .arg(old_json)
            .arg(new_json)
            .invoke_async(&mut *conn)
            .await?;
        if changed != 1 {
            return Ok(MucRoleChange::Stale);
        }
        let nodes = self.active_muc_nodes(&room).await?;
        let payload = serde_json::json!({
            "target": room,
            "muc_role_change": true,
            "occupant": updated,
        });
        for node_id in nodes {
            if node_id != self.node_id {
                let channel = self.key(format!("node:{node_id}"));
                let _ = self
                    .publish_signed(&mut conn, &node_id, &channel, payload.clone())
                    .await?;
            }
        }
        Ok(MucRoleChange::Changed(Box::new(updated)))
    }

    pub async fn register_muc_occupant(
        &self,
        room_jid: &str,
        nick: &str,
        json: &str,
    ) -> Result<bool> {
        self.maintenance_redis()
            .register_muc_occupant(room_jid, nick, json)
            .await
    }

    /// Replace the transport owner of an XEP-0198-resumed occupancy.  The
    /// complete previous value is a CAS token, while the immutable occupancy
    /// epoch and durable SM session id must remain unchanged.
    pub async fn resume_muc_occupant(
        &self,
        previous: &crate::state::SerializableMucOccupant,
        resumed: &crate::state::SerializableMucOccupant,
    ) -> Result<bool> {
        self.admit(ClusterOperation::Resume)?;
        anyhow::ensure!(
            previous.room_jid == resumed.room_jid
                && previous.nick == resumed.nick
                && previous.full_jid == resumed.full_jid
                && previous.cluster_epoch == resumed.cluster_epoch
                && previous.sm_session_id.is_some()
                && previous.sm_session_id == resumed.sm_session_id
                && !previous.cluster_epoch.is_nil()
                && !resumed.connection_id.is_nil(),
            "invalid MUC resume ownership transition"
        );
        let Some(pool) = &self.pool else {
            return Ok(true);
        };
        let room = crate::jid::canonicalize_bare(&resumed.room_jid)?;
        let nick = crate::xmpp::xml_util::prepare_muc_nick(&resumed.nick)?;
        let process_instance = self.process_instance_token()?;
        let mut conn = pool.get().await?;
        let occupants_key = self.key(format!("muc_occupants:{room}"));
        let owners_key = self.key(format!("muc_occupant_nodes:{room}"));
        let nodes_key = self.key(format!("muc_nodes:{room}"));
        let instances_key = self.key(format!("muc_occupant_instances:{room}"));
        let node_counts_key = self.key(format!("muc_node_counts:{room}"));
        let alive_key = self.key(format!("node:{}:alive", self.node_id));
        let process_alive_key = self.process_alive_key()?;
        let previous_json = serde_json::to_string(previous)?;
        let resumed_json = serde_json::to_string(resumed)?;
        let script = redis::Script::new(
            r#"
            local previous_owner = redis.call('hget', KEYS[2], ARGV[1])
            local previous_instance = redis.call('hget', KEYS[4], ARGV[1])
            if not previous_owner or not previous_instance then return 0 end
            if redis.call('hget', KEYS[1], ARGV[1]) ~= ARGV[4] then return 0 end
            redis.call('hset', KEYS[1], ARGV[1], ARGV[5])
            redis.call('hset', KEYS[2], ARGV[1], ARGV[2])
            redis.call('hset', KEYS[4], ARGV[1], ARGV[3])
            if previous_owner ~= ARGV[2] then
                local old_remaining = redis.call('hincrby', KEYS[5], previous_owner, -1)
                if old_remaining <= 0 then
                    redis.call('hdel', KEYS[5], previous_owner)
                    redis.call('srem', KEYS[3], previous_owner)
                end
                redis.call('hincrby', KEYS[5], ARGV[2], 1)
            end
            redis.call('sadd', KEYS[3], ARGV[2])
            redis.call('set', KEYS[6], ARGV[7], 'EX', ARGV[6])
            redis.call('set', KEYS[7], ARGV[7], 'EX', ARGV[6])
            redis.call('expire', KEYS[1], ARGV[8])
            redis.call('expire', KEYS[2], ARGV[8])
            redis.call('expire', KEYS[3], ARGV[8])
            redis.call('expire', KEYS[4], ARGV[8])
            redis.call('expire', KEYS[5], ARGV[8])
            return 1
            "#,
        );
        let resumed: i32 = script
            .key(occupants_key)
            .key(owners_key)
            .key(nodes_key)
            .key(instances_key)
            .key(node_counts_key)
            .key(alive_key)
            .key(process_alive_key)
            .arg(&nick)
            .arg(&self.node_id)
            .arg(process_instance)
            .arg(previous_json)
            .arg(resumed_json)
            .arg(NODE_TTL_SECONDS)
            .arg(NODE_PROTOCOL_VERSION)
            .arg(MUC_SOFT_STATE_TTL_SECONDS)
            .invoke_async(&mut *conn)
            .await?;
        Ok(resumed == 1)
    }

    /// Verify that Redis still grants this node the exact live occupancy.
    /// This is checked before every actor-authorized MUC operation so a lost
    /// lease or a nickname ABA cannot continue with a stale local cache.
    #[allow(dead_code)] // Protocol-v7 rolling compatibility; PG is authoritative in v9.
    pub async fn owns_muc_occupant(
        &self,
        room_jid: &str,
        nick: &str,
        cluster_epoch: uuid::Uuid,
        connection_id: uuid::Uuid,
    ) -> Result<bool> {
        anyhow::ensure!(
            !cluster_epoch.is_nil() && !connection_id.is_nil(),
            "MUC ownership validation requires non-nil identities"
        );
        let Some(pool) = &self.pool else {
            return Ok(true);
        };
        let room = crate::jid::canonicalize_bare(room_jid)?;
        let nick = crate::xmpp::xml_util::prepare_muc_nick(nick)?;
        let process_instance = self.process_instance_token()?;
        let mut conn = pool.get().await?;
        let occupants_key = self.key(format!("muc_occupants:{room}"));
        let owners_key = self.key(format!("muc_occupant_nodes:{room}"));
        let instances_key = self.key(format!("muc_occupant_instances:{room}"));
        let script = redis::Script::new(
            r#"
            if redis.call('hget', KEYS[2], ARGV[1]) ~= ARGV[2] then return 0 end
            if redis.call('hget', KEYS[3], ARGV[1]) ~= ARGV[3] then return 0 end
            local raw = redis.call('hget', KEYS[1], ARGV[1])
            if not raw then return 0 end
            local ok, current = pcall(cjson.decode, raw)
            if not ok then return 0 end
            if current['cluster_epoch'] ~= ARGV[4]
                or current['connection_id'] ~= ARGV[5] then return 0 end
            return 1
            "#,
        );
        let owned: i32 = script
            .key(occupants_key)
            .key(owners_key)
            .key(instances_key)
            .arg(&nick)
            .arg(&self.node_id)
            .arg(process_instance)
            .arg(cluster_epoch.to_string())
            .arg(connection_id.to_string())
            .invoke_async(&mut *conn)
            .await?;
        Ok(owned == 1)
    }

    /// Persist the exact suspended-SM epoch in the Redis occupant value. A
    /// teardown tombstone wins over a late disconnect task, preventing that
    /// task from recreating a ghost after PostgreSQL expiry/revocation.
    pub async fn register_suspended_muc_occupant(
        &self,
        room_jid: &str,
        nick: &str,
        sm_session_id: uuid::Uuid,
        json: &str,
    ) -> Result<bool> {
        self.sm_suspension()
            .register_suspended_muc_occupant(room_jid, nick, sm_session_id, json)
            .await
    }

    /// Remove only the exact occupancy epoch owned by this node.  This is the
    /// cleanup primitive for delayed connection Drop tasks; a nickname reused
    /// by a later join must survive the older task.
    pub async fn unregister_muc_occupant_epoch(
        &self,
        room_jid: &str,
        nick: &str,
        cluster_epoch: uuid::Uuid,
        connection_id: uuid::Uuid,
    ) -> Result<bool> {
        self.sm_muc_teardown_projection()
            .unregister_muc_occupant_epoch(room_jid, nick, cluster_epoch, connection_id)
            .await
    }

    /// Revoke one exact occupancy, acknowledging the owning node before the
    /// Redis lease is removed.  The full actor identity prevents a delayed
    /// kick/ban from touching a later user who reused the nickname.
    pub async fn evict_muc_occupant(
        &self,
        occupant: &crate::state::SerializableMucOccupant,
        status: u16,
        actor_nick: Option<&str>,
        reason: Option<&str>,
    ) -> Result<bool> {
        self.admit(ClusterOperation::MucMutation)?;
        anyhow::ensure!(
            !occupant.cluster_epoch.is_nil()
                && !occupant.connection_id.is_nil()
                && reason.is_none_or(|value| value.len() <= 4096),
            "MUC eviction requires exact non-nil identity and bounded reason"
        );
        let Some(pool) = &self.pool else {
            return Ok(true);
        };
        let room = crate::jid::canonicalize_bare(&occupant.room_jid)?;
        let nick = crate::xmpp::xml_util::prepare_muc_nick(&occupant.nick)?;
        let occupants_key = self.key(format!("muc_occupants:{room}"));
        let owners_key = self.key(format!("muc_occupant_nodes:{room}"));
        let nodes_key = self.key(format!("muc_nodes:{room}"));
        let instances_key = self.key(format!("muc_occupant_instances:{room}"));
        let node_counts_key = self.key(format!("muc_node_counts:{room}"));
        let mut conn = pool.get().await?;
        let owner_script = redis::Script::new(
            r#"
            local owner = redis.call('hget', KEYS[2], ARGV[1])
            if not owner then return false end
            local raw = redis.call('hget', KEYS[1], ARGV[1])
            if not raw then return false end
            local ok, current = pcall(cjson.decode, raw)
            if not ok or current['full_jid'] ~= ARGV[2]
                or current['cluster_epoch'] ~= ARGV[3]
                or current['connection_id'] ~= ARGV[4] then return false end
            return owner
            "#,
        );
        let owner: Option<String> = owner_script
            .key(&occupants_key)
            .key(&owners_key)
            .arg(&nick)
            .arg(&occupant.full_jid)
            .arg(occupant.cluster_epoch.to_string())
            .arg(occupant.connection_id.to_string())
            .invoke_async(&mut *conn)
            .await?;
        let Some(owner) = owner else {
            return Ok(false);
        };
        if owner != self.node_id {
            let payload = serde_json::json!({
                "target": &room,
                "muc_evict": true,
                "occupant": occupant,
                "status": status,
                "actor_nick": actor_nick,
                "reason": reason,
            });
            self.send_control_to_node(&owner, &room, payload).await?;
        }
        let remove_script = redis::Script::new(
            r#"
            if redis.call('hget', KEYS[2], ARGV[1]) ~= ARGV[2] then return 0 end
            local raw = redis.call('hget', KEYS[1], ARGV[1])
            if not raw then return 0 end
            local ok, current = pcall(cjson.decode, raw)
            if not ok or current['full_jid'] ~= ARGV[3]
                or current['cluster_epoch'] ~= ARGV[4]
                or current['connection_id'] ~= ARGV[5] then return 0 end
            redis.call('hdel', KEYS[1], ARGV[1])
            redis.call('hdel', KEYS[2], ARGV[1])
            redis.call('hdel', KEYS[4], ARGV[1])
            local remaining = redis.call('hincrby', KEYS[5], ARGV[2], -1)
            if remaining <= 0 then
                redis.call('hdel', KEYS[5], ARGV[2])
                redis.call('srem', KEYS[3], ARGV[2])
            end
            if redis.call('hlen', KEYS[1]) == 0 and redis.call('hlen', KEYS[2]) == 0 then
                redis.call('del', KEYS[1], KEYS[2], KEYS[3], KEYS[4], KEYS[5])
            else
                redis.call('expire', KEYS[1], ARGV[6])
                redis.call('expire', KEYS[2], ARGV[6])
                redis.call('expire', KEYS[3], ARGV[6])
                redis.call('expire', KEYS[4], ARGV[6])
                redis.call('expire', KEYS[5], ARGV[6])
            end
            return 1
            "#,
        );
        let removed: i32 = remove_script
            .key(occupants_key)
            .key(owners_key)
            .key(nodes_key)
            .key(instances_key)
            .key(node_counts_key)
            .arg(&nick)
            .arg(owner)
            .arg(&occupant.full_jid)
            .arg(occupant.cluster_epoch.to_string())
            .arg(occupant.connection_id.to_string())
            .arg(MUC_SOFT_STATE_TTL_SECONDS)
            .invoke_async(&mut *conn)
            .await?;
        Ok(removed == 1)
    }

    pub async fn get_muc_occupants(&self, room_jid: &str) -> Result<HashMap<String, String>> {
        self.sm_muc_teardown_projection()
            .get_muc_occupants(room_jid)
            .await
    }

    pub async fn join_muc(&self, room_jid: &str) -> Result<()> {
        self.maintenance_redis().join_muc(room_jid).await
    }

    pub async fn leave_muc(&self, room_jid: &str) -> Result<()> {
        self.sm_muc_teardown_projection().leave_muc(room_jid).await
    }

    async fn active_muc_nodes(&self, room_jid: &str) -> Result<Vec<String>> {
        self.signed_publisher().active_muc_nodes(room_jid).await
    }

    pub async fn send_to_muc(&self, room_jid: &str, stanza: &str) -> Result<()> {
        self.send_to_muc_internal(room_jid, stanza, None).await
    }

    /// Best-effort signed wake after PostgreSQL committed a MUC operation.
    /// The envelope contains only immutable IDs; receivers must pull and
    /// authorize the operation/outbox row from PostgreSQL.
    pub async fn send_muc_operation_wake(
        &self,
        descriptor: &northstar_room_core::ClusterMucWakeDescriptor,
    ) -> Result<()> {
        self.sm_suspension()
            .send_muc_operation_wake(descriptor)
            .await
    }

    pub async fn send_to_muc_from(
        &self,
        room_jid: &str,
        stanza: &str,
        real_sender: &str,
    ) -> Result<()> {
        let real_sender = crate::jid::canonicalize(real_sender)?;
        self.send_to_muc_internal(room_jid, stanza, Some(&real_sender))
            .await
    }

    async fn send_to_muc_internal(
        &self,
        room_jid: &str,
        stanza: &str,
        real_sender: Option<&str>,
    ) -> Result<()> {
        let Some(pool) = &self.pool else {
            return Ok(());
        };
        let nodes = self.active_muc_nodes(room_jid).await?;
        let payload = serde_json::json!({
            "target": room_jid,
            "stanza": stanza,
            "muc_broadcast": true,
            "real_sender": real_sender,
        });
        let mut conn = pool.get().await?;
        self.publish_muc_fan_out(&mut conn, nodes, payload).await
    }

    async fn publish_muc_fan_out(
        &self,
        conn: &mut redis::aio::MultiplexedConnection,
        nodes: Vec<String>,
        payload: serde_json::Value,
    ) -> Result<()> {
        let mut first_error = None;
        for node_id in nodes {
            if node_id != self.node_id {
                let channel = self.key(format!("node:{node_id}"));
                // A destination-specific authority error must not suppress
                // other recipients. Each attempt still uses publish_signed's
                // admission gate: global degradation remains fail-closed.
                if let Err(error) = self
                    .publish_signed(conn, &node_id, &channel, payload.clone())
                    .await
                {
                    first_error.get_or_insert_with(|| {
                        error.context(format!("MUC volatile fan-out to node {node_id} failed"))
                    });
                }
            }
        }
        match first_error {
            Some(error) => Err(error),
            None => Ok(()),
        }
    }

    pub async fn send_muc_private_from(
        &self,
        room_jid: &str,
        target_nick: &str,
        stanza: &str,
        real_sender: &str,
    ) -> Result<()> {
        let real_sender = crate::jid::canonicalize(real_sender)?;
        self.send_muc_private_internal(room_jid, target_nick, stanza, Some(&real_sender))
            .await
    }

    async fn send_muc_private_internal(
        &self,
        room_jid: &str,
        target_nick: &str,
        stanza: &str,
        real_sender: Option<&str>,
    ) -> Result<()> {
        let Some(pool) = &self.pool else {
            return Ok(());
        };
        let nodes = self.active_muc_nodes(room_jid).await?;
        let payload = serde_json::json!({
            "target": room_jid,
            "muc_private": true,
            "target_nick": target_nick,
            "stanza": stanza,
            "real_sender": real_sender,
        });
        let mut conn = pool.get().await?;
        for node_id in nodes {
            if node_id != self.node_id {
                let channel = self.key(format!("node:{node_id}"));
                let _ = self
                    .publish_signed(&mut conn, &node_id, &channel, payload.clone())
                    .await?;
            }
        }
        Ok(())
    }

    pub async fn send_muc_presence(
        &self,
        room_jid: &str,
        occupant: &crate::state::SerializableMucOccupant,
        unavailable: bool,
        created: bool,
        id: Option<&str>,
    ) -> Result<()> {
        self.send_muc_presence_with_status(
            room_jid,
            occupant,
            unavailable,
            created,
            id,
            None,
            None,
            None,
        )
        .await
    }

    pub async fn send_muc_nickname_change(
        &self,
        room_jid: &str,
        old_occupant: &crate::state::SerializableMucOccupant,
        new_occupant: &crate::state::SerializableMucOccupant,
        id: Option<&str>,
    ) -> Result<()> {
        let Some(pool) = &self.pool else {
            return Ok(());
        };
        anyhow::ensure!(
            old_occupant.cluster_epoch == new_occupant.cluster_epoch
                && old_occupant.full_jid == new_occupant.full_jid
                && old_occupant.room_jid == new_occupant.room_jid
                && old_occupant.nick != new_occupant.nick,
            "invalid clustered MUC nickname change"
        );
        let nodes = self.active_muc_nodes(room_jid).await?;
        let payload = serde_json::json!({
            "target": room_jid,
            "muc_nickname_change": true,
            "old_occupant": old_occupant,
            "new_occupant": new_occupant,
            "id": id,
        });
        let mut conn = pool.get().await?;
        for node_id in nodes {
            if node_id != self.node_id {
                let channel = self.key(format!("node:{node_id}"));
                let _ = self
                    .publish_signed(&mut conn, &node_id, &channel, payload.clone())
                    .await?;
            }
        }
        Ok(())
    }

    /// Remove all distributed occupancy state for a destroyed room and tell
    /// every node that previously hosted one of its occupants to emit the
    /// XEP-0045 destroy presence locally.
    #[allow(dead_code)] // Legacy Redis cleanup fallback; authoritative destroy uses PG/outbox.
    pub async fn destroy_muc_room(
        &self,
        room_jid: &str,
        alternate: Option<&str>,
        reason: Option<&str>,
    ) -> Result<()> {
        let room = crate::jid::canonicalize_bare(room_jid)?;
        let alternate = alternate.map(crate::jid::canonicalize_bare).transpose()?;
        anyhow::ensure!(
            reason.is_none_or(|value| value.len() <= 4096),
            "MUC destroy reason exceeds 4096 bytes"
        );
        let Some(pool) = &self.pool else {
            return Ok(());
        };
        let mut conn = pool.get().await?;
        let occupants_key = self.key(format!("muc_occupants:{room}"));
        let owners_key = self.key(format!("muc_occupant_nodes:{room}"));
        let raw_occupants: HashMap<String, String> = conn.hgetall(&occupants_key).await?;
        let owners: HashMap<String, String> = conn.hgetall(&owners_key).await?;
        let mut identities = Vec::new();
        let mut nodes = HashSet::new();
        for (nick, raw) in &raw_occupants {
            let Ok(occupant) = serde_json::from_str::<crate::state::SerializableMucOccupant>(raw)
            else {
                continue;
            };
            if occupant.room_jid != room || occupant.nick != *nick {
                continue;
            }
            if let Some(identity) = MucOccupancyIdentity::from_occupant(&occupant) {
                identities.push(identity);
                if let Some(owner) = owners.get(nick) {
                    nodes.insert(owner.clone());
                }
            }
        }
        let payload = serde_json::json!({
            "target": &room,
            "muc_destroy": true,
            "alternate": &alternate,
            "reason": reason,
            "occupancies": &identities,
        });
        for node_id in nodes {
            if node_id != self.node_id {
                self.send_control_to_node(&node_id, &room, payload.clone())
                    .await?;
            }
        }
        let remove_script = redis::Script::new(
            r#"
            local raw = redis.call('hget', KEYS[1], ARGV[1])
            if not raw then return 0 end
            local ok, current = pcall(cjson.decode, raw)
            if not ok or current['full_jid'] ~= ARGV[2]
                or current['cluster_epoch'] ~= ARGV[3]
                or current['connection_id'] ~= ARGV[4] then return 0 end
            redis.call('hdel', KEYS[1], ARGV[1])
            redis.call('hdel', KEYS[2], ARGV[1])
            return 1
            "#,
        );
        for identity in identities {
            let _: i32 = remove_script
                .key(&occupants_key)
                .key(&owners_key)
                .arg(identity.nick)
                .arg(identity.full_jid)
                .arg(identity.cluster_epoch.to_string())
                .arg(identity.connection_id.to_string())
                .invoke_async(&mut *conn)
                .await?;
        }
        drop(conn);
        // Empty Redis hashes disappear automatically; reconcile the companion
        // node set as well.  A concurrent new authoritative join remains
        // intact because reconciliation retains entries owned by live nodes.
        self.reconcile_muc_soft_state(&room).await?;
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn send_muc_presence_with_status(
        &self,
        room_jid: &str,
        occupant: &crate::state::SerializableMucOccupant,
        unavailable: bool,
        created: bool,
        id: Option<&str>,
        removal_status: Option<u16>,
        actor_nick: Option<&str>,
        reason: Option<&str>,
    ) -> Result<()> {
        self.signed_publisher()
            .send_muc_presence_with_status(
                room_jid,
                occupant,
                unavailable,
                created,
                id,
                removal_status,
                actor_nick,
                reason,
            )
            .await
    }
}

/// Read committed account fences independently of Redis and cluster maintenance.
/// Notifications reduce latency; polling recovers missed notifications.
pub(crate) async fn run_account_revocations<
    R: crate::services::account_revocation_consumer::AccountRevocationRepository,
>(
    context: Arc<AccountRevocationWorkerContext<R>>,
    cancel: CancellationToken,
    heartbeat: crate::workers::WorkerHeartbeat,
) -> Result<()> {
    let mut interval = tokio::time::interval(Duration::from_secs(1));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut cleanup_interval = tokio::time::interval(Duration::from_secs(30));
    let notify = Arc::clone(&context.authority.notify);
    loop {
        tokio::select! {
            biased;
            _ = cancel.cancelled() => return Ok(()),
            _ = notify.notified() => {},
            _ = interval.tick() => {},
            _ = cleanup_interval.tick() => {
                // A replaced process cannot host live sessions. Its queue can
                // be removed, but an expired lease alone is not replacement.
                match tokio::time::timeout(Duration::from_secs(2),
                    context.service.cleanup()).await {
                    Ok(Ok(())) => {},
                    error => tracing::warn!(?error, "account revocation queue cleanup deferred"),
                }
                continue;
            }
        }
        let consume = async {
            let identity = context.authority.identity();
            let more = context
                .service
                .consume_batch(&identity, |user_id, bare_jid, before_generation| {
                    context.routes.revoke(user_id, bare_jid, before_generation);
                })
                .await?;
            if more {
                notify.notify_one();
            }
            Ok::<(), anyhow::Error>(())
        };
        let result = tokio::select! {
            _ = cancel.cancelled() => return Ok(()),
            result = tokio::time::timeout(Duration::from_secs(2), consume) =>
                result.context("account revocation read exceeded its time budget")
                    .and_then(std::convert::identity),
        };
        match result {
            Ok(()) => heartbeat.ok(),
            Err(error) => {
                context.authority.record_failure(&error);
                heartbeat.error(&error);
                // An unreachable authority cannot confirm that existing
                // credentials are still valid. Fence routes before retrying.
                context.routes.fence_all();
                tracing::warn!(
                    ?error,
                    "account revocation authority unavailable; local routes fenced"
                );
            }
        }
        tokio::task::yield_now().await;
    }
}

pub(crate) async fn run_maintenance(
    context: Arc<crate::state::cluster_maintenance_context::ClusterMaintenanceContext>,
    cancel: CancellationToken,
    heartbeat: crate::workers::WorkerHeartbeat,
) -> Result<()> {
    let control = &context.control;
    let locals = &context.locals;
    let mut interval =
        tokio::time::interval(Duration::from_secs(CLUSTER_MAINTENANCE_INTERVAL_SECONDS));
    loop {
        tokio::select! {
            _ = cancel.cancelled() => return Ok(()),
            _ = interval.tick() => {
                let maintenance = tokio::select! {
                    _ = cancel.cancelled() => return Ok(()),
                    result = tokio::time::timeout(
                        CLUSTER_MAINTENANCE_BUDGET,
                        maintenance_once(&context),
                    ) => result
                        .context("cluster maintenance pass exceeded its time budget")
                        .and_then(std::convert::identity),
                };
                if let Err(error) = maintenance {
                    control.record_control_plane_failure(&error);
                    heartbeat.error(&error);
                    locals.record_background_failure();
                    tracing::warn!(?error, "session authorization/cluster lease maintenance failed; it will be retried");
                } else {
                    heartbeat.ok();
                }
            }
        }
    }
}

async fn maintenance_once(
    context: &crate::state::cluster_maintenance_context::ClusterMaintenanceContext,
) -> Result<()> {
    let control = &context.control;
    let redis = &context.redis;
    let locals = &context.locals;
    // PostgreSQL is authoritative for credential generations.  One bounded
    // batch query provides a Redis-independent safety net for lost controls,
    // node restarts and rolling upgrades.
    let snapshots = locals.session_authority_snapshots();
    let authority_snapshots = snapshots
        .iter()
        .map(|snapshot| snapshot.authority)
        .collect::<Vec<_>>();
    let stale_generations = context
        .session_authority
        .stale_generations(&authority_snapshots)
        .await?;
    for (snapshot, stale) in snapshots.iter().zip(stale_generations) {
        if stale {
            let full_jid = &snapshot.full_jid;
            let user_id = snapshot.authority.user_id;
            let generation = snapshot.authority.auth_generation;
            tracing::warn!(%full_jid, %user_id, auth_generation = generation, "disconnecting credential-stale live session");
            snapshot.disconnect.cancel();
        }
    }
    let stale_device_epochs = context
        .session_authority
        .stale_device_epochs(&authority_snapshots)
        .await?;
    for (snapshot, stale) in snapshots.iter().zip(stale_device_epochs) {
        if let Some((device_id, epoch)) = snapshot
            .authority
            .device_id
            .zip(snapshot.authority.device_epoch)
        {
            if stale {
                let full_jid = &snapshot.full_jid;
                let user_id = snapshot.authority.user_id;
                tracing::warn!(%full_jid, %user_id, %device_id, epoch, "disconnecting replaced user-agent session");
                snapshot.disconnect.cancel();
            }
        }
    }
    if !control.enabled {
        return Ok(());
    }
    let reconciliation_epoch = if control.readiness_error().is_some() {
        Some(control.begin_reconciliation()?)
    } else {
        None
    };
    // PostgreSQL instance authority is refreshed before Redis ownership. A
    // recovered listener cannot make this node ready while its view of peer
    // process epochs is stale.
    control
        .refresh_peers_with(&context.cluster_authority)
        .await?;
    let _redis_timer = locals.redis_operation_timer();
    redis.touch_node().await?;
    let sessions = locals.session_lease_snapshots();
    for snapshot in sessions {
        let full_jid = &snapshot.full_jid;
        let connection_id = snapshot.connection_id;
        if !redis
            .refresh_session(full_jid, snapshot.activity_age_seconds, connection_id)
            .await?
        {
            // Redis compares both node and immutable connection UUID. If a
            // failover or newer bind owns this route, leaving the old local
            // stream routable creates split brain. Disconnect it; its exact
            // UUID-guarded unregister/Drop cannot erase the replacement.
            tracing::warn!(%full_jid, %connection_id, "disconnecting local session that lost its Redis routing lease");
            snapshot.disconnect.cancel();
        }
    }
    // PostgreSQL, not Redis, owns clustered MUC occupancy. Refresh the
    // complete node snapshot once, then require each local actor to match its
    // exact incarnation and connection fence. Redis is repopulated only as a
    // disposable fan-out cache after the authoritative check succeeds.
    let occupancy_maintenance = &context.muc_occupancy;
    let authoritative_muc = occupancy_maintenance
        .authoritative_for_node(&control.node_id)
        .await?;
    locals.record_muc_reconciliation();
    let authoritative_muc = authoritative_muc
        .into_iter()
        .map(|occupancy| {
            (
                (occupancy.occupant_incarnation, occupancy.connection_uuid),
                occupancy,
            )
        })
        .collect::<std::collections::HashMap<_, _>>();
    let occupants = locals.muc_occupant_snapshots();
    let mut unrenewed_muc = Vec::new();
    let mut renewed_muc = Vec::new();
    for occupant in occupants {
        let authoritative =
            authoritative_muc.get(&(occupant.cluster_epoch, occupant.connection_id));
        let exact = authoritative.is_some_and(|authority| {
            authority.full_jid == occupant.full_jid && authority.nick == occupant.nick
        });
        let renewed = if let Some(authority) = authoritative.filter(|_| exact) {
            occupancy_maintenance
                .renew_exact(authority, &control.node_id)
                .await?
        } else {
            false
        };
        if !renewed {
            unrenewed_muc.push(occupant);
            continue;
        }
        renewed_muc.push(occupant);
    }
    for chunk in unrenewed_muc.chunks(crate::services::muc::MAX_MUC_OCCUPANCY_RENEW_BATCH) {
        let mut candidates = Vec::with_capacity(chunk.len());
        for occupant in chunk {
            match crate::services::muc::MucOccupancyLookup::new(
                &occupant.room_jid,
                &occupant.full_jid,
                &occupant.nick,
                occupant.cluster_epoch,
                occupant.connection_id,
            ) {
                Ok(lookup) => candidates.push((occupant, lookup)),
                Err(_) => locals.remove_stale_muc_actor(occupant),
            }
        }
        let lookups = candidates
            .iter()
            .map(|(_, lookup)| lookup.clone())
            .collect::<Vec<_>>();
        let terminal = match occupancy_maintenance
            .committed_terminal_exact_batch(&lookups, &control.node_id)
            .await
        {
            Ok(terminal) => terminal.into_iter().collect::<HashSet<_>>(),
            Err(error) => {
                for (occupant, _) in candidates {
                    locals.remove_stale_muc_actor(occupant);
                }
                return Err(error);
            }
        };
        for (occupant, lookup) in candidates {
            if terminal.contains(&lookup) {
                locals.remove_committed_terminal_muc_actor(occupant);
            } else {
                locals.remove_stale_muc_actor(occupant);
                tracing::warn!(
                    room = %occupant.room_jid,
                    nick = %occupant.nick,
                    epoch = %occupant.cluster_epoch,
                    "removed local MUC actor that lost its PostgreSQL occupancy authority"
                );
            }
        }
    }
    // Clear lost authority before any Redis network wait can postpone its
    // route fence. Redis remains a disposable projection of renewed actors.
    let mut muc_soft_state_errors = 0_u64;
    let mut active_muc_rooms = HashSet::new();
    for occupant in renewed_muc {
        let serializable = crate::state::SerializableMucOccupant::from(&occupant);
        let json = serde_json::to_string(&serializable)?;
        if let Err(error) = async {
            redis.join_muc(&occupant.room_jid).await?;
            anyhow::ensure!(
                redis
                    .register_muc_occupant(&occupant.room_jid, &occupant.nick, &json)
                    .await?,
                "Redis MUC soft-state rejected the exact PostgreSQL occupant"
            );
            Ok::<_, anyhow::Error>(())
        }
        .await
        {
            muc_soft_state_errors = muc_soft_state_errors.saturating_add(1);
            control.record_control_plane_failure(&error);
            tracing::warn!(?error, room=%occupant.room_jid, nick=%occupant.nick,
                "could not refresh disposable Redis MUC soft-state");
        } else {
            active_muc_rooms.insert(occupant.room_jid.clone());
        }
    }
    // Sweep each active room once, irrespective of its occupant count. This
    // removes crashed-node members while another live node keeps renewing the
    // room lease, without imposing O(occupants²) maintenance work.
    for room in active_muc_rooms {
        if let Err(error) = redis.reconcile_muc_soft_state(&room).await {
            muc_soft_state_errors = muc_soft_state_errors.saturating_add(1);
            control.record_control_plane_failure(&error);
            tracing::warn!(?error, %room, "could not reconcile Redis MUC room soft-state");
        }
    }
    if let Some(rotation_epoch) = reconciliation_epoch {
        anyhow::ensure!(
            muc_soft_state_errors == 0,
            "Redis MUC soft-state reconciliation failed for {muc_soft_state_errors} authoritative occupancies"
        );
        if control.complete_reconciliation(rotation_epoch)?
            == ReconciliationOutcome::WaitingForInitialListener
        {
            // Every database/Redis operation above succeeded. The independent
            // cluster readiness gate stays closed until the first self-loop.
            tracing::debug!("cluster authority reconciled; awaiting initial listener self-loop");
        }
    }
    Ok(())
}

/// Listener capabilities are assembled once; the receive loop never retains
/// the application state or a general cluster manager.
struct ClusterListenerRuntime {
    message_policy: Arc<crate::state::cluster_listener_message::ClusterListenerMessagePolicy>,
    dispatch: crate::state::cluster_listener_dispatch::ClusterListenerDispatch,
    muc_endpoints: crate::state::cluster_muc_delivery_endpoints::ClusterMucDeliveryEndpoints,
    muc_delivery: crate::state::muc_delivery::MucDeliveryContext,
    mix_caps: crate::state::cluster_listener_mix_caps::ClusterListenerMixCaps,
    blocking: crate::state::cluster_listener_blocking::ClusterListenerBlocking,
    sm_muc_teardown: crate::state::cluster_listener_sm_muc_teardown::ClusterListenerSmMucTeardown,
    presence_sender: Arc<ClusterNodeDelivery>,
    security: Arc<ClusterListenerSecurity>,
}

impl ClusterListenerRuntime {
    fn from_state(state: &AppState) -> Self {
        Self {
            message_policy: Arc::new(state.cluster_listener_message_policy()),
            dispatch: state.cluster_listener_dispatch(),
            muc_endpoints: state.cluster_muc_delivery_endpoints(),
            muc_delivery: state.muc_delivery_context(),
            mix_caps: state.cluster_listener_mix_caps(),
            blocking: state.cluster_listener_blocking(),
            sm_muc_teardown: state.cluster_listener_sm_muc_teardown(),
            presence_sender: Arc::new(state.cluster_listener_presence_sender()),
            security: Arc::new(state.cluster_listener_security()),
        }
    }
}

pub(crate) async fn run_pubsub_listener(
    transport: Arc<ClusterPubsubListenerTransport>,
    admission: Arc<ClusterListenerAdmission>,
    state: Arc<AppState>,
    cancel: CancellationToken,
    heartbeat: crate::workers::WorkerHeartbeat,
) -> Result<()> {
    if !transport.is_enabled() {
        return Ok(());
    }
    let runtime = ClusterListenerRuntime::from_state(&state);
    drop(state);
    let result = listen_once(
        Arc::clone(&transport),
        Arc::clone(&admission),
        runtime,
        cancel.clone(),
        heartbeat,
    )
    .await;
    if cancel.is_cancelled() {
        return result;
    }
    let error = match result {
        Ok(()) => anyhow::anyhow!("Redis PubSub stream ended unexpectedly"),
        Err(error) => error,
    };
    if !transport.rotation_already_required() {
        transport.record_listener_failure(&error);
    }
    Err(error)
}

/// Supervise the PostgreSQL half of cluster identity fencing and the bounded
/// degraded-mode shutdown deadline. This worker never makes Redis healthy;
/// only full lease/occupant/listener reconciliation in maintenance can do so.
pub async fn run_failure_supervisor(
    context: Arc<crate::state::cluster_failure_supervisor::ClusterFailureSupervisorContext>,
    cancel: CancellationToken,
    heartbeat: crate::workers::WorkerHeartbeat,
) -> Result<()> {
    let authority = &context.authority;
    if !authority.is_enabled() {
        return Ok(());
    }
    let identity = authority
        .key_identity()
        .context("cluster signing-key authority is missing")?;
    let authority_service = &context.authority_service;
    let mut interval = tokio::time::interval(Duration::from_secs(5));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut heartbeat_tick = 0_u8;
    loop {
        tokio::select! {
            _ = cancel.cancelled() => return Ok(()),
            _ = interval.tick() => {
                heartbeat_tick = heartbeat_tick.wrapping_add(1);
                let validation = async {
                    authority_service.validate_cluster_key(identity).await?;
                    let instance = authority.readiness_snapshot()
                        .context("cluster signing identity is missing")?;
                    authority_service.validate_local_instance(&instance).await?;
                    if heartbeat_tick % 6 == 1 {
                        let instance = authority.readiness_snapshot()
                            .context("cluster signing identity is missing")?;
                        authority_service.heartbeat_local_instance(
                            &instance,
                            Duration::from_secs(NODE_TTL_SECONDS),
                        ).await?;
                        context.replay_maintenance
                            .cleanup_and_validate(4096)
                            .await?;
                        context.route_maintenance
                            .cleanup_and_validate(4096)
                            .await?;
                    }
                    authority.refresh_peers_with(authority_service).await?;
                    Ok::<_, anyhow::Error>(())
                }.await;
                match validation {
                    Ok(()) => heartbeat.ok(),
                    Err(error) => {
                        heartbeat.error(&error);
                        authority.record_authority_failure(&error);
                        if degraded_shutdown_required(
                            authority.failure_policy(),
                            false,
                            false,
                        ) {
                            authority.require_shutdown();
                            // The critical-worker supervisor owns process-wide
                            // cancellation. Return the authority error first so
                            // it can persist the terminal cause before waking
                            // the main shutdown path; cancelling this shared
                            // token here would make the same exit look like an
                            // operator-requested shutdown.
                            anyhow::bail!(
                                "PostgreSQL cluster key/instance authority was lost; refusing unfenced degraded operation: {error:#}"
                            );
                        }
                    }
                }
                let policy = authority.failure_policy();
                if degraded_shutdown_required(policy, true, authority.safety_lease_expired()) {
                    authority.require_shutdown();
                    tracing::error!(
                        ?policy,
                        "cluster safety lease expired; requesting supervised shutdown"
                    );
                    // As above, the retained critical-worker supervisor must
                    // record this exact terminal cause before it cancels the
                    // service token.
                    anyhow::bail!("cluster safety lease expired before full reconciliation");
                }
            }
        }
    }
}

pub fn start_muc_outbox_delivery(state: Arc<AppState>, cancel: CancellationToken) {
    // The PostgreSQL maintenance half also runs in supported single-node
    // mode: lifecycle tombstones/operation IDs are still recorded there and
    // must obey the same bounded retention. With clustering disabled there
    // are no cross-node audience rows and no signing key is required.
    let worker_registry = Arc::clone(state.worker_registry());
    let context = Arc::new(state.cluster_muc_outbox_worker_context());
    worker_registry.supervise(
        "cluster-muc-outbox",
        crate::workers::WorkerCriticality::Restartable,
        crate::workers::WorkerMode::Continuous,
        Some(Duration::from_secs(30)),
        cancel.clone(),
        move |heartbeat| {
            let context = Arc::clone(&context);
            let cancel = cancel.clone();
            async move { run_muc_outbox_delivery(context, cancel, heartbeat).await }
        },
    );
}

async fn run_muc_outbox_delivery(
    context: Arc<crate::state::cluster_muc_outbox_worker::ClusterMucOutboxWorkerContext>,
    cancel: CancellationToken,
    heartbeat: crate::workers::WorkerHeartbeat,
) -> Result<()> {
    let mut poll = tokio::time::interval(Duration::from_secs(1));
    poll.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut next_history_cleanup = Instant::now();
    loop {
        tokio::select! {
            _ = cancel.cancelled() => return Ok(()),
            _ = poll.tick() => {},
            _ = context.signal.wait() => {},
        }
        {
            let _database_turn = context.database_turn().await;
            context.preclaim.prepare_pass(32, 256).await?;
        }
        let pass_started = Instant::now();
        'batches: for _ in 0..MUC_OUTBOX_MAX_BATCHES_PER_PASS {
            if cancel.is_cancelled() || pass_started.elapsed() >= MUC_OUTBOX_PASS_BUDGET {
                break;
            }
            let deliveries = {
                let _database_turn = context.database_turn().await;
                context
                    .claim
                    .claim_batch(
                        &context.signal.node_id,
                        MUC_OUTBOX_BATCH_SIZE,
                        Duration::from_secs(30),
                    )
                    .await?
            };
            if deliveries.is_empty() {
                break;
            }
            for delivery in deliveries {
                if cancel.is_cancelled() {
                    return Ok(());
                }
                if pass_started.elapsed() >= MUC_OUTBOX_PASS_BUDGET {
                    break 'batches;
                }
                let outcome = tokio::time::timeout(
                    MUC_OUTBOX_DELIVERY_BUDGET,
                    deliver_cluster_muc_event(&context, &delivery),
                )
                .await
                .map_err(|_| anyhow::anyhow!("cluster MUC delivery exceeded its time budget"))
                .and_then(std::convert::identity);
                match outcome {
                    Ok(()) => {
                        let acknowledged = {
                            let _database_turn = context.database_turn().await;
                            context.settlement.acknowledge(&delivery).await?
                        };
                        anyhow::ensure!(
                            acknowledged == AckOutcome::Acknowledged,
                            "cluster MUC outbox ACK lost its exact claim lease"
                        );
                        context.record_delivery();
                    }
                    Err(error) => {
                        tracing::warn!(
                            ?error,
                            delivery_id=%delivery.delivery_id,
                            operation_id=%delivery.operation_id,
                            event_id=%delivery.event_id,
                            "cluster MUC audience delivery will retry with the same stable event ID"
                        );
                        {
                            let _database_turn = context.database_turn().await;
                            context
                                .settlement
                                .retry(&delivery, &error.to_string())
                                .await?;
                        }
                        context.record_retry();
                    }
                }
                heartbeat.ok();
            }
        }
        let housekeeping = &context.housekeeping;
        {
            let _database_turn = context.database_turn().await;
            housekeeping.purge_expired_dead_letters().await?;
        }
        if Instant::now() >= next_history_cleanup {
            // Ninety days is the bounded online idempotency/recovery horizon
            // for experimental clustered room-control events. Active legal
            // holds and outstanding delivery projections make the database
            // cleanup fail closed or skip the protected incarnation.
            {
                let _database_turn = context.database_turn().await;
                housekeeping.purge_history().await?;
            }
            next_history_cleanup = Instant::now() + Duration::from_secs(60);
        }
        let snapshot = {
            let _database_turn = context.database_turn().await;
            housekeeping.snapshot().await?
        };
        context.record_gauges(snapshot);
        heartbeat.ok();
    }
}

struct ClusterMucPolicyRender<'a> {
    endpoints: &'a crate::state::cluster_muc_delivery_endpoints::ClusterMucDeliveryEndpoints,
    context: &'a crate::db::ClusterMucEventContext,
    room_jid: &'a str,
    recipient: &'a crate::state::MucOccupant,
    event_id: &'a str,
    change: &'a serde_json::Value,
    configuration_change: bool,
    stanzas: &'a mut Vec<String>,
}

fn cluster_muc_policy_result(
    change: &serde_json::Value,
) -> Result<(
    crate::db::ClusterMucOccupancyTarget,
    crate::db::ClusterMucPolicySnapshot,
)> {
    let target: crate::db::ClusterMucOccupancyTarget =
        serde_json::from_value(change["target"].clone())
            .context("cluster MUC policy target tuple is invalid")?;
    let snapshot: crate::db::ClusterMucPolicySnapshot =
        serde_json::from_value(change["snapshot"].clone())
            .context("cluster MUC policy result snapshot is invalid")?;
    anyhow::ensure!(
        snapshot.room_id == target.room_id
            && snapshot.room_epoch == target.room_epoch
            && snapshot.occupant_incarnation == target.occupant_incarnation
            && snapshot.occupancy_epoch == target.occupancy_epoch
            && snapshot.full_jid == target.full_jid
            && snapshot.nick == target.nick
            && snapshot.connection_uuid == target.connection_uuid
            && snapshot.connection_epoch == target.connection_epoch,
        "cluster MUC policy snapshot is not exactly bound"
    );
    Ok((target, snapshot))
}

fn validate_cluster_muc_admin_batch_details(
    details: &serde_json::Value,
    room_id: uuid::Uuid,
    room_epoch: uuid::Uuid,
) -> Result<&[serde_json::Value]> {
    let room_non_anonymous = details["non_anonymous"]
        .as_bool()
        .context("cluster MUC batch has no committed anonymity policy")?;
    let changes = details["changes"]
        .as_array()
        .context("cluster MUC batch has no ordered result snapshots")?;
    let request_change_count = details["request_change_count"]
        .as_u64()
        .context("cluster MUC batch has no committed request item count")?;
    anyhow::ensure!(
        (1..=63).contains(&request_change_count) && changes.len() <= 63,
        "cluster MUC batch exceeds the receipt ordinal limit"
    );
    for change in changes {
        match change["kind"].as_str() {
            Some("presence") => {
                let (target, snapshot) = cluster_muc_policy_result(change)?;
                anyhow::ensure!(
                    target.room_id == room_id && target.room_epoch == room_epoch,
                    "cluster MUC batch target belongs to another room incarnation"
                );
                anyhow::ensure!(
                    matches!(snapshot.state.as_str(), "active" | "suspended" | "revoked"),
                    "cluster MUC batch presence has an invalid result state"
                );
                let status = change["status"].as_u64();
                if matches!(snapshot.state.as_str(), "active" | "suspended") {
                    anyhow::ensure!(
                        change["status"].is_null(),
                        "cluster MUC batch active presence has a removal status"
                    );
                } else {
                    anyhow::ensure!(
                        matches!(status, Some(301 | 307 | 321)),
                        "cluster MUC batch removal has no valid status"
                    );
                }
            }
            Some("offline_affiliation") => {
                anyhow::ensure!(
                    room_non_anonymous,
                    "cluster MUC batch anonymous room has an offline JID notice"
                );
                let bare_jid = change["bare_jid"]
                    .as_str()
                    .context("cluster MUC batch offline target has no bare JID")?;
                anyhow::ensure!(
                    crate::jid::canonicalize_bare(bare_jid)? == bare_jid,
                    "cluster MUC batch offline target is not canonical"
                );
                let affiliation = change["affiliation"]
                    .as_str()
                    .context("cluster MUC batch offline target has no affiliation")?;
                anyhow::ensure!(
                    matches!(
                        affiliation,
                        "owner" | "admin" | "member" | "outcast" | "none"
                    ),
                    "cluster MUC batch offline affiliation is invalid"
                );
                anyhow::ensure!(
                    change["nick"].is_null() || change["nick"].is_string(),
                    "cluster MUC batch offline nickname is invalid"
                );
                anyhow::ensure!(
                    change["nick"].as_str().is_none_or(|nick| nick.len() <= 128),
                    "cluster MUC batch offline nickname is oversized"
                );
            }
            _ => anyhow::bail!("cluster MUC batch result kind is invalid"),
        }
        anyhow::ensure!(
            change["reason"].is_null() || change["reason"].is_string(),
            "cluster MUC batch reason is invalid"
        );
        anyhow::ensure!(
            change["reason"]
                .as_str()
                .is_none_or(|reason| reason.len() <= 4096),
            "cluster MUC batch reason is oversized"
        );
    }
    Ok(changes.as_slice())
}

fn append_cluster_muc_policy_snapshot(render: ClusterMucPolicyRender<'_>) -> Result<()> {
    let ClusterMucPolicyRender {
        endpoints,
        context,
        room_jid,
        recipient,
        event_id,
        change,
        configuration_change,
        stanzas,
    } = render;
    let (_target, snapshot) = cluster_muc_policy_result(change)?;
    let room_non_anonymous = context.details["non_anonymous"]
        .as_bool()
        .unwrap_or(context.room_non_anonymous);
    let subject = crate::state::SerializableMucOccupant {
        full_jid: snapshot.full_jid.clone(),
        room_jid: room_jid.to_owned(),
        nick: snapshot.nick.clone(),
        affiliation: snapshot.affiliation.clone(),
        role: snapshot.role.clone(),
        room_non_anonymous,
        occupant_id: crate::xmpp::xml_util::muc_occupant_id(
            &context.occupant_id_secret,
            &snapshot.bare_jid,
        ),
        cluster_epoch: snapshot.occupant_incarnation,
        connection_id: snapshot.connection_uuid,
        federated_domain: None,
        sm_session_id: snapshot.sm_session_id,
        payload: String::new(),
    };
    let subject_is_recipient = snapshot.full_jid == recipient.full_jid
        && snapshot.occupant_incarnation == recipient.cluster_epoch
        && snapshot.connection_uuid == recipient.connection_id;
    let terminal = !matches!(snapshot.state.as_str(), "active" | "suspended");
    if terminal {
        let fallback = if snapshot.affiliation == "outcast" {
            301
        } else if configuration_change {
            322
        } else {
            321
        };
        let status = change["status"]
            .as_u64()
            .and_then(|value| u16::try_from(value).ok())
            .or(Some(fallback));
        stanzas.push(crate::xmpp::xml_util::muc_presence_stanza_with_status(
            &subject,
            &recipient.full_jid,
            true,
            snapshot.full_jid == recipient.full_jid,
            false,
            Some(event_id),
            room_non_anonymous || subject_is_recipient || recipient.role == "moderator",
            status,
            None,
            change["reason"].as_str(),
        ));
        // The target's own durable delivery performs cache revocation. If a
        // different audience row removed it first, the target row would no
        // longer be able to deliver its required self-unavailable stanza.
        if subject_is_recipient {
            endpoints.revoke_exact_recipient(&subject);
        }
    } else {
        if subject_is_recipient {
            endpoints.apply_policy_projection_exact(&subject);
        }
        stanzas.push(crate::xmpp::xml_util::muc_presence_stanza(
            &subject,
            &recipient.full_jid,
            false,
            snapshot.full_jid == recipient.full_jid,
            false,
            Some(event_id),
            room_non_anonymous
                || snapshot.full_jid == recipient.full_jid
                || recipient.role == "moderator",
        ));
    }
    Ok(())
}

fn render_cluster_muc_departure_presence(
    target: &crate::state::SerializableMucOccupant,
    recipient: &crate::state::SerializableMucOccupant,
    event_id: &str,
    room_non_anonymous: bool,
    operation_kind: &str,
    details: &serde_json::Value,
) -> Result<String> {
    let status = if operation_kind == "leave" {
        match details.get("status") {
            None => None,
            Some(value) => {
                anyhow::ensure!(value.as_u64() == Some(333), "invalid MUC leave status");
                Some(333)
            }
        }
    } else {
        None
    };
    let self_presence = target.full_jid == recipient.full_jid;
    Ok(crate::xmpp::xml_util::muc_presence_stanza_with_status(
        target,
        &recipient.full_jid,
        true,
        self_presence,
        false,
        Some(event_id),
        room_non_anonymous || recipient.role == "moderator",
        status,
        None,
        None,
    ))
}

async fn deliver_cluster_muc_event(
    worker: &crate::state::cluster_muc_outbox_worker::ClusterMucOutboxWorkerContext,
    delivery: &crate::db::ClusterMucOutboxDelivery,
) -> Result<()> {
    let endpoints = &worker.endpoints;
    anyhow::ensure!(
        matches!(delivery.audience_kind.as_str(), "occupant" | "node_pull"),
        "cluster MUC outbox audience kind is unsupported"
    );
    let payload: serde_json::Value = serde_json::from_str(&delivery.payload)
        .context("cluster MUC outbox payload is invalid JSON")?;
    let canonical_digest = sha2::Sha256::digest(delivery.payload.as_bytes()).to_vec();
    anyhow::ensure!(
        canonical_digest == delivery.payload_digest,
        "cluster MUC outbox payload digest mismatch"
    );
    let operation_id = delivery.operation_id.to_string();
    let database_event_id = delivery.event_id.to_string();
    anyhow::ensure!(
        payload["operation_id"].as_str() == Some(operation_id.as_str())
            && payload["event_id"].as_str() == Some(database_event_id.as_str())
            && payload["event_sequence"].as_i64() == Some(delivery.event_sequence),
        "cluster MUC outbox payload identity is not exactly bound"
    );
    let context = {
        let _database_turn = worker.database_turn().await;
        worker
            .delivery_read
            .event_context(delivery.operation_id)
            .await?
            .context("cluster MUC outbox operation is missing")?
    };
    anyhow::ensure!(
        context.room_epoch == delivery.room_epoch,
        "cluster MUC outbox room epoch is stale"
    );
    anyhow::ensure!(
        context
            .actor_affiliation
            .as_deref()
            .is_none_or(|value| matches!(value, "owner" | "admin" | "member" | "outcast" | "none")),
        "cluster MUC operation contains an invalid actor affiliation"
    );
    let room_jid = format!("{}@conference.{}", context.room_localpart, worker.domain);
    let Some(recipient_nick) = delivery.recipient_nick.as_deref() else {
        // node_pull rows are wake hints only; the worker has completed the
        // authoritative PostgreSQL pull by reaching this point.
        return Ok(());
    };
    let cached_recipient = endpoints.cached_recipient(&room_jid, recipient_nick);
    let exact_cached = cached_recipient.as_ref().is_some_and(|recipient| {
        delivery.recipient_full_jid.as_deref() == Some(&recipient.full_jid)
            && delivery.recipient_occupant_incarnation == Some(recipient.cluster_epoch)
            && delivery.recipient_connection_uuid == Some(recipient.connection_id)
            && recipient.nick == recipient_nick
    });
    let mut recipient = if exact_cached {
        cached_recipient.expect("exact cached MUC recipient was checked")
    } else {
        // A terminal transition revokes the PG lease before its notification
        // is written to the socket. Reconstruct only an endpoint from the
        // immutable outbox audience tuple; never revive membership or trust a
        // Redis nickname cache. The stable event ID remains the retry key.
        let snapshot = {
            let _database_turn = worker.database_turn().await;
            worker.delivery_read.recipient_snapshot(delivery).await?
        };
        let Some(snapshot) = snapshot else {
            let audience_is_current = {
                let _database_turn = worker.database_turn().await;
                worker.delivery_read.audience_is_current(delivery).await?
            };
            if audience_is_current {
                anyhow::bail!("authoritative MUC audience snapshot disappeared");
            }
            return Ok(());
        };
        let room_non_anonymous = context.details["non_anonymous"]
            .as_bool()
            .unwrap_or(context.room_non_anonymous);
        endpoints
            .recipient_from_snapshot(
                &snapshot,
                &room_jid,
                room_non_anonymous,
                crate::xmpp::xml_util::muc_occupant_id(
                    &context.occupant_id_secret,
                    &snapshot.bare_jid,
                ),
            )
            .context("immutable MUC audience has no exact live, SM or federated endpoint")?
    };
    if context.operation_kind == "admin_batch" {
        // A later role change or SM handoff may alter the live endpoint, but
        // neither may change the visibility rules of this committed event.
        let original = if let Some(snapshot) = payload.get("original_audience") {
            serde_json::from_value::<crate::db::ClusterMucAudienceSnapshot>(snapshot.clone())
                .context("cluster MUC batch payload original audience is malformed")?
        } else {
            let _database_turn = worker.database_turn().await;
            worker
                .delivery_read
                .original_audience_snapshot(delivery)
                .await?
                .context("cluster MUC batch original audience is missing")?
        };
        anyhow::ensure!(
            original.room_id == delivery.room_id
                && original.room_epoch == delivery.room_epoch
                && original.full_jid == recipient.full_jid
                && original.nick == recipient.nick
                && original.occupant_incarnation == recipient.cluster_epoch
                && Some(original.occupancy_epoch) == delivery.recipient_occupancy_epoch
                && matches!(
                    original.role.as_str(),
                    "moderator" | "participant" | "visitor" | "none"
                )
                && matches!(
                    original.affiliation.as_str(),
                    "owner" | "admin" | "member" | "outcast" | "none"
                ),
            "cluster MUC batch original audience is not exactly bound"
        );
        recipient.role = original.role;
        recipient.affiliation = original.affiliation;
    }
    let recipient_serializable = crate::state::SerializableMucOccupant::from(&recipient);
    let event_id = delivery.event_id.to_string();
    let target = context
        .target
        .as_ref()
        .map(|target| {
            anyhow::ensure!(
                target.occupancy_epoch >= 1 && target.connection_epoch >= 1,
                "cluster MUC target has invalid authority epochs"
            );
            Ok(crate::state::SerializableMucOccupant {
                full_jid: target.full_jid.clone(),
                room_jid: room_jid.clone(),
                nick: target.nick.clone(),
                affiliation: target.affiliation.clone(),
                role: target.role.clone(),
                room_non_anonymous: context.room_non_anonymous,
                occupant_id: crate::xmpp::xml_util::muc_occupant_id(
                    &context.occupant_id_secret,
                    &target.bare_jid,
                ),
                cluster_epoch: target.occupant_incarnation,
                connection_id: target.connection_uuid,
                federated_domain: None,
                sm_session_id: None,
                payload: target.presence_payload.clone(),
            })
        })
        .transpose()?;
    let mut stanzas = Vec::with_capacity(2);
    match context.operation_kind.as_str() {
        "join" | "resume" | "role" => {
            let target = target.context("MUC join/resume/role event has no exact target")?;
            if context.operation_kind == "role" {
                endpoints.apply_role_projection_exact(&target);
            }
            let self_presence = target.full_jid == recipient.full_jid;
            stanzas.push(crate::xmpp::xml_util::muc_presence_stanza(
                &target,
                &recipient.full_jid,
                false,
                self_presence,
                false,
                Some(&event_id),
                context.room_non_anonymous || self_presence || recipient.role == "moderator",
            ));
        }
        "rename" => {
            let target = target.context("MUC rename event has no exact target")?;
            let old_nick = context.details["old_nick"]
                .as_str()
                .context("MUC rename event has no old nickname")?;
            let new_nick = context.details["new_nick"]
                .as_str()
                .context("MUC rename event has no new nickname")?;
            let mut old = target.clone();
            old.nick = old_nick.to_owned();
            stanzas.push(crate::xmpp::xml_util::muc_nickname_change_presence(
                &old,
                &recipient_serializable,
                new_nick,
                Some(&event_id),
            ));
            let self_presence = target.full_jid == recipient.full_jid;
            stanzas.push(crate::xmpp::xml_util::muc_presence_stanza(
                &target,
                &recipient.full_jid,
                false,
                self_presence,
                false,
                Some(&event_id),
                context.room_non_anonymous || self_presence || recipient.role == "moderator",
            ));
        }
        "leave" | "expire" | "account_delete" => {
            let target = target.context("MUC departure event has no exact target")?;
            let self_presence = target.full_jid == recipient.full_jid;
            stanzas.push(render_cluster_muc_departure_presence(
                &target,
                &recipient_serializable,
                &event_id,
                context.room_non_anonymous,
                &context.operation_kind,
                &context.details,
            )?);
            if self_presence {
                endpoints.revoke_exact_recipient(&target);
            }
        }
        "suspend" => {
            // XEP-0198 suspension retains membership until its PG lease
            // expires; it intentionally emits no transient unavailable.
        }
        "kick" | "ban" => {
            let target = target.context("MUC removal event has no exact target")?;
            let status = context.details["status"]
                .as_u64()
                .and_then(|value| u16::try_from(value).ok())
                .or(Some(if context.operation_kind == "ban" {
                    301
                } else {
                    307
                }));
            let reason = context.details["reason"].as_str();
            let actor_nick = context
                .actor_full_jid
                .as_deref()
                .and_then(|full| endpoints.actor_nick(&room_jid, full));
            let self_presence = target.full_jid == recipient.full_jid;
            stanzas.push(crate::xmpp::xml_util::muc_presence_stanza_with_status(
                &target,
                &recipient.full_jid,
                true,
                self_presence,
                false,
                Some(&event_id),
                true,
                status,
                actor_nick.as_deref(),
                reason,
            ));
            if self_presence {
                endpoints.revoke_exact_recipient(&target);
            }
        }
        "destroy" | "locked_expiry" => {
            let alternate = context.details["alternate_jid"].as_str();
            let reason = context.details["reason"].as_str();
            let stanza = crate::xmpp::xml_util::muc_destroy_presence(
                &recipient_serializable,
                alternate,
                reason,
            );
            stanzas.push(crate::xmpp::xml_util::set_root_attribute(
                &stanza, "id", &event_id,
            ));
        }
        "subject" => {
            let stanza = context.details["stanza"]
                .as_str()
                .context("cluster MUC subject event has no committed stanza")?;
            let stanza = crate::xmpp::xml_util::set_to(stanza, &recipient.full_jid);
            let stanza = crate::xmpp::xml_util::set_from(&stanza, &room_jid);
            stanzas.push(crate::xmpp::xml_util::add_stanza_id(
                &stanza,
                &room_jid,
                delivery.event_id,
            ));
        }
        "config" | "affiliation" => {
            let configuration_change = context.operation_kind == "config";
            let changes = context.details[if configuration_change {
                "affected"
            } else {
                "changes"
            }]
            .as_array()
            .context("cluster MUC policy event has no exact result snapshot array")?;
            for change in changes {
                append_cluster_muc_policy_snapshot(ClusterMucPolicyRender {
                    endpoints,
                    context: &context,
                    room_jid: &room_jid,
                    recipient: &recipient,
                    event_id: &event_id,
                    change,
                    configuration_change,
                    stanzas: &mut stanzas,
                })?;
            }
            if !configuration_change {
                if let Some(offline) = context.details["offline_affiliation"].as_object() {
                    let bare_jid = offline
                        .get("bare_jid")
                        .and_then(serde_json::Value::as_str)
                        .context("cluster MUC offline affiliation has no bare JID")?;
                    let affiliation = offline
                        .get("affiliation")
                        .and_then(serde_json::Value::as_str)
                        .context("cluster MUC offline affiliation has no affiliation")?;
                    let nick = offline.get("nick").and_then(serde_json::Value::as_str);
                    let reason = offline.get("reason").and_then(serde_json::Value::as_str);
                    let notice = crate::xmpp::protocol::muc::muc_offline_affiliation_change_notice(
                        &room_jid,
                        bare_jid,
                        affiliation,
                        nick,
                        reason,
                    );
                    let notice = crate::xmpp::xml_util::set_to(&notice, &recipient.full_jid);
                    stanzas.push(crate::xmpp::xml_util::set_root_attribute(
                        &notice, "id", &event_id,
                    ));
                }
            }
            if configuration_change {
                let extension = crate::xmpp::xml_builder::XmlElement::namespaced(
                    "x",
                    "http://jabber.org/protocol/muc#user",
                )
                .child(crate::xmpp::xml_builder::XmlElement::new("status").attr("code", "104"));
                stanzas.push(
                    crate::xmpp::xml_builder::XmlElement::namespaced("message", "jabber:client")
                        .attr("from", &room_jid)
                        .attr("to", &recipient.full_jid)
                        .attr("type", "groupchat")
                        .attr("id", &event_id)
                        .child(extension)
                        .finish(),
                );
            }
        }
        "admin_batch" => {
            anyhow::ensure!(target.is_none(), "cluster MUC batch has a singular target");
            // Validate every projection before the first cache mutation or
            // transport write. A corrupt later item cannot partially apply
            // an earlier item and then fail the whole delivery.
            let changes = validate_cluster_muc_admin_batch_details(
                &context.details,
                delivery.room_id,
                delivery.room_epoch,
            )?;
            for change in changes {
                match change["kind"].as_str() {
                    Some("presence") => {
                        append_cluster_muc_policy_snapshot(ClusterMucPolicyRender {
                            endpoints,
                            context: &context,
                            room_jid: &room_jid,
                            recipient: &recipient,
                            event_id: &event_id,
                            change,
                            configuration_change: false,
                            stanzas: &mut stanzas,
                        })?;
                    }
                    Some("offline_affiliation") => {
                        let bare_jid = change["bare_jid"].as_str().expect("batch was validated");
                        let affiliation =
                            change["affiliation"].as_str().expect("batch was validated");
                        let nick = change["nick"].as_str();
                        let reason = change["reason"].as_str();
                        let notice =
                            crate::xmpp::protocol::muc::muc_offline_affiliation_change_notice(
                                &room_jid,
                                bare_jid,
                                affiliation,
                                nick,
                                reason,
                            );
                        let notice = crate::xmpp::xml_util::set_to(&notice, &recipient.full_jid);
                        stanzas.push(crate::xmpp::xml_util::set_root_attribute(
                            &notice, "id", &event_id,
                        ));
                    }
                    _ => unreachable!("batch was validated"),
                }
            }
        }
        other => anyhow::bail!("unsupported cluster MUC event kind {other}"),
    }
    for (ordinal, stanza) in stanzas.into_iter().enumerate() {
        let ordinal =
            i32::try_from(ordinal).context("MUC event has too many stanza projections")?;
        let stable_item_id = format!("{}:{ordinal}", delivery.event_id);
        let stanza = if context.operation_kind == "admin_batch" {
            crate::xmpp::xml_util::set_root_attribute(&stanza, "id", &stable_item_id)
        } else {
            stanza
        };
        let completed = {
            let _database_turn = worker.database_turn().await;
            worker
                .delivery_item
                .completed(delivery.delivery_id, ordinal, &stable_item_id)
                .await?
        };
        if completed {
            continue;
        }
        anyhow::ensure!(
            worker
                .delivery
                .deliver_to_muc_occupant_with_receipt(&recipient, stanza, delivery,)
                .await?,
            "exact MUC audience transport did not reach a durable ownership/write boundary"
        );
        let completed = {
            let _database_turn = worker.database_turn().await;
            worker
                .delivery_item
                .complete_exact(delivery, ordinal, &stable_item_id)
                .await?
        };
        anyhow::ensure!(
            completed,
            "cluster MUC delivery item lost its stable ordinal identity"
        );
    }
    Ok(())
}

#[cfg(test)]
#[path = "cluster_listener_continuation_tests.rs"]
mod listener_continuation_tests;

#[cfg(test)]
#[path = "cluster_muc_routing_tests.rs"]
mod muc_routing_tests;

#[cfg(test)]
#[path = "cluster_tests.rs"]
mod tests;
