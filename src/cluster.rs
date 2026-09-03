use crate::state::AppState;
use anyhow::{Context, Result};
use bb8::Pool;
use futures::StreamExt;
use redis::AsyncCommands;
use serde::{Deserialize, Serialize};
use sha2::Digest;
use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicBool, AtomicI64, AtomicU64, AtomicU8, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio_util::sync::CancellationToken;

#[derive(Clone, Debug)]
struct RedisConnectionManager {
    client: redis::Client,
}

impl bb8::ManageConnection for RedisConnectionManager {
    type Connection = redis::aio::MultiplexedConnection;
    type Error = redis::RedisError;

    async fn connect(&self) -> std::result::Result<Self::Connection, Self::Error> {
        let config = redis::AsyncConnectionConfig::new()
            .set_connection_timeout(Some(REDIS_CONNECT_TIMEOUT))
            .set_response_timeout(Some(REDIS_IO_TIMEOUT));
        self.client
            .get_multiplexed_async_connection_with_config(&config)
            .await
    }

    async fn is_valid(
        &self,
        connection: &mut Self::Connection,
    ) -> std::result::Result<(), Self::Error> {
        let pong: String = redis::cmd("PING").query_async(connection).await?;
        if pong == "PONG" {
            Ok(())
        } else {
            Err((
                redis::ErrorKind::Extension,
                "Redis PING returned an invalid response",
            )
                .into())
        }
    }

    fn has_broken(&self, _: &mut Self::Connection) -> bool {
        false
    }
}

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
const MAX_DELIVERY_ACK_BYTES: usize = 4096;
const MAX_CLUSTER_PAYLOAD_BYTES: usize = 2 * 1024 * 1024;
const MAX_DELIVERY_EXCLUSIONS: usize = 16;
const MAX_PENDING_CLUSTER_ACKS: usize = 4096;
const MUC_OUTBOX_MAX_BATCHES_PER_PASS: usize = 4;
const MUC_OUTBOX_BATCH_SIZE: i64 = 16;
const MUC_OUTBOX_PASS_BUDGET: Duration = Duration::from_secs(20);
const MUC_OUTBOX_DELIVERY_BUDGET: Duration = Duration::from_secs(5);
const CLUSTER_MAINTENANCE_BUDGET: Duration = Duration::from_secs(25);
const NODE_PROTOCOL_VERSION: &str = "11";
const DELIVERY_CONTRACT_PROTOCOL_VERSION: u16 = 11;
// Version 8 introduced the explicit volatile/durable delivery contract.
// Versions 9 through 11 retain that wire meaning while adding independent
// signed envelope, presence-authority and MIX-capability requirements. They must never fall back to
// the version-7 stanza-id inference rules during a rolling upgrade.
const DELIVERY_CONTRACT_PROTOCOL_MIN: u16 = 8;
const PRESENCE_AUTHORITY_VERSION: u16 = 1;
const LEGACY_DELIVERY_PROTOCOL_MAX: u16 = 7;
const MAX_REPLAY_ENTRIES: usize = 65_536;

async fn open_pubsub(client: &redis::Client) -> Result<redis::aio::PubSub> {
    tokio::time::timeout(REDIS_CONNECT_TIMEOUT, client.get_async_pubsub())
        .await
        .context("Redis PubSub connection timed out")?
        .context("failed to connect Redis PubSub")
}

async fn subscribe_pubsub(pubsub: &mut redis::aio::PubSub, channel: &str) -> Result<()> {
    tokio::time::timeout(REDIS_IO_TIMEOUT, pubsub.subscribe(channel))
        .await
        .context("Redis PubSub subscription timed out")?
        .context("failed to subscribe Redis PubSub")
}

async fn publish_listener_probe(
    cluster: &ClusterManager,
    channel: &str,
    token: &str,
) -> Result<()> {
    let pool = cluster
        .pool
        .as_ref()
        .context("Redis listener probe started without a configured pool")?;
    let mut connection = pool.get().await?;
    let receivers: usize =
        tokio::time::timeout(REDIS_IO_TIMEOUT, connection.publish(channel, token))
            .await
            .context("Redis listener self-loop publish timed out")??;
    anyhow::ensure!(receivers > 0, "Redis listener self-loop had no subscriber");
    Ok(())
}

fn cluster_pool_builder<M: bb8::ManageConnection>() -> bb8::Builder<M> {
    Pool::<M>::builder()
        .max_size(CLUSTER_REDIS_POOL_MAX_SIZE)
        .connection_timeout(REDIS_IO_TIMEOUT)
        .retry_connection(false)
}

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

fn session_instance_control_revokes(
    current_connection_id: uuid::Uuid,
    expected_connection_id: uuid::Uuid,
) -> bool {
    !expected_connection_id.is_nil() && current_connection_id == expected_connection_id
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
}

impl ResolvedNodeMessageDelivery {
    fn contract(self) -> NodeDeliveryContract {
        match self {
            Self::Volatile => NodeDeliveryContract::Volatile {},
            Self::Durable(delivery) => NodeDeliveryContract::DurableC2s {
                recipient_id: delivery.recipient_id,
                message_id: delivery.message_id,
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
        return Ok(Some(RequestedNodeMessageDelivery::Explicit(
            serde_json::from_value(delivery.clone())
                .context("cluster delivery contract is invalid")?,
        )));
    }
    anyhow::ensure!(
        advertised_version.is_none_or(|version| version <= LEGACY_DELIVERY_PROTOCOL_MAX),
        "current cluster protocol message omitted its delivery contract"
    );
    Ok(Some(RequestedNodeMessageDelivery::LegacyInference))
}

async fn resolve_node_message_delivery(
    pool: &sqlx::PgPool,
    request: RequestedNodeMessageDelivery,
    stanza: &str,
    target_jid: &str,
) -> Result<ResolvedNodeMessageDelivery> {
    match request {
        RequestedNodeMessageDelivery::Explicit(NodeDeliveryContract::Volatile {}) => {
            Ok(ResolvedNodeMessageDelivery::Volatile)
        }
        RequestedNodeMessageDelivery::Explicit(NodeDeliveryContract::DurableC2s {
            recipient_id,
            message_id,
        }) => {
            anyhow::ensure!(
                !matches!(
                    crate::outbound::recipient_delivery_identity(stanza, target_jid),
                    crate::outbound::RecipientDeliveryIdentity::Missing
                        | crate::outbound::RecipientDeliveryIdentity::Invalid
                ),
                "durable cluster message lacks an unambiguous recipient stanza-id"
            );
            let stored_stanza: Option<String> = sqlx::query_scalar(
                "SELECT stanza FROM offline_messages WHERE recipient_id=$1 AND id=$2",
            )
            .bind(recipient_id)
            .bind(message_id)
            .fetch_optional(pool)
            .await
            .context("failed to verify clustered durable C2S projection")?;
            let stored_stanza =
                stored_stanza.context("cluster durable delivery projection is missing")?;
            anyhow::ensure!(
                durable_projection_matches(&stored_stanza, stanza),
                "cluster durable delivery payload does not match its PostgreSQL projection"
            );
            Ok(ResolvedNodeMessageDelivery::Durable(
                crate::outbound::DurableDelivery {
                    recipient_id,
                    message_id,
                    claim_id: None,
                },
            ))
        }
        RequestedNodeMessageDelivery::LegacyInference => {
            let message_id = match crate::outbound::recipient_delivery_identity(stanza, target_jid)
            {
                crate::outbound::RecipientDeliveryIdentity::Missing => {
                    return Ok(ResolvedNodeMessageDelivery::Volatile);
                }
                crate::outbound::RecipientDeliveryIdentity::Exact(message_id) => message_id,
                crate::outbound::RecipientDeliveryIdentity::Invalid => {
                    anyhow::bail!("legacy cluster delivery identity is ambiguous")
                }
            };
            let projection: Option<(uuid::Uuid, String)> =
                sqlx::query_as("SELECT recipient_id, stanza FROM offline_messages WHERE id=$1")
                    .bind(message_id)
                    .fetch_optional(pool)
                    .await
                    .context("failed to verify legacy clustered C2S projection")?;
            let (recipient_id, stored_stanza) =
                projection.context("legacy cluster durable delivery projection is missing")?;
            anyhow::ensure!(
                durable_projection_matches(&stored_stanza, stanza),
                "legacy cluster durable delivery payload does not match its PostgreSQL projection"
            );
            Ok(ResolvedNodeMessageDelivery::Durable(
                crate::outbound::DurableDelivery {
                    recipient_id,
                    message_id,
                    claim_id: None,
                },
            ))
        }
    }
}

fn durable_projection_matches(stored_stanza: &str, routed_stanza: &str) -> bool {
    // Durable rows add one direct server delay marker before routing. Remove
    // only direct delays and require the remaining XML bytes to match the
    // proposed cluster payload exactly. Merely proving that a row ID exists
    // would let a compromised Redis writer consume an unrelated spool fence
    // while injecting different content.
    crate::xmpp::xml_util::strip_untrusted_direct_delays(stored_stanza, None) == routed_stanza
}

fn outbound_delivery_contract(
    stanza: &str,
    target_jid: &str,
    durable_delivery: Option<crate::outbound::DurableDelivery>,
) -> Result<Option<NodeDeliveryContract>> {
    let document = roxmltree::Document::parse(stanza).context("cluster stanza is invalid XML")?;
    let is_message = document.root_element().tag_name().name() == "message";
    if !is_message {
        anyhow::ensure!(
            durable_delivery.is_none(),
            "non-message cluster stanza cannot be durable"
        );
        return Ok(None);
    }
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
    replay_cache: Arc<dashmap::DashMap<String, i64>>,
    replay_cache_gate: Arc<Mutex<()>>,
    replay_cache_next_expiry: Arc<AtomicI64>,
    #[cfg(test)]
    replay_cache_sweeps: Arc<AtomicU64>,
    authority_pool: Arc<std::sync::OnceLock<sqlx::PgPool>>,
    health: Arc<ClusterHealth>,
    publication_gate: Arc<tokio::sync::RwLock<()>>,
    muc_outbox_notify: Arc<tokio::sync::Notify>,
    listener_rotation: Arc<tokio::sync::Notify>,
    pending_ack_slots: Arc<tokio::sync::Semaphore>,
    pending_acks: Arc<dashmap::DashMap<String, PendingClusterAck>>,
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

struct ClusterHealth {
    state: AtomicU8,
    listener_generation: AtomicU64,
    required_listener_generation: AtomicU64,
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
            failure_since: Mutex::new(None),
            authentication_failures: AtomicU64::new(0),
            replay_rejections: AtomicU64::new(0),
            degraded_transitions: AtomicU64::new(0),
            peer_versions_compatible: AtomicBool::new(true),
            incompatible_peer_versions: AtomicU64::new(0),
        }
    }

    fn enabled() -> Self {
        Self {
            state: AtomicU8::new(CLUSTER_RECONCILING),
            listener_generation: AtomicU64::new(0),
            required_listener_generation: AtomicU64::new(1),
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
                replay_cache: Arc::new(dashmap::DashMap::new()),
                replay_cache_gate: Arc::new(Mutex::new(())),
                replay_cache_next_expiry: Arc::new(AtomicI64::new(i64::MAX)),
                #[cfg(test)]
                replay_cache_sweeps: Arc::new(AtomicU64::new(0)),
                authority_pool: Arc::new(std::sync::OnceLock::new()),
                health: Arc::new(ClusterHealth::disabled()),
                publication_gate: Arc::new(tokio::sync::RwLock::new(())),
                muc_outbox_notify: Arc::new(tokio::sync::Notify::new()),
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
            replay_cache: Arc::new(dashmap::DashMap::new()),
            replay_cache_gate: Arc::new(Mutex::new(())),
            replay_cache_next_expiry: Arc::new(AtomicI64::new(i64::MAX)),
            #[cfg(test)]
            replay_cache_sweeps: Arc::new(AtomicU64::new(0)),
            authority_pool: Arc::new(std::sync::OnceLock::new()),
            health: Arc::new(ClusterHealth::enabled()),
            publication_gate: Arc::new(tokio::sync::RwLock::new(())),
            muc_outbox_notify: Arc::new(tokio::sync::Notify::new()),
            listener_rotation: Arc::new(tokio::sync::Notify::new()),
            pending_ack_slots: Arc::new(tokio::sync::Semaphore::new(MAX_PENDING_CLUSTER_ACKS)),
            pending_acks: Arc::new(dashmap::DashMap::new()),
        };
        tracing::warn!(node_id = %cluster.node_id, "experimental Redis multi-node routing is enabled");
        Ok(cluster)
    }

    pub fn is_enabled(&self) -> bool {
        self.pool.is_some()
    }

    pub fn configure_authority_pool(&self, pool: &sqlx::PgPool) -> Result<()> {
        self.authority_pool
            .set(pool.clone())
            .map_err(|_| anyhow::anyhow!("cluster PostgreSQL authority pool was configured twice"))
    }

    async fn verify_signed_payload_persisted(
        &self,
        raw: &str,
        channel: &str,
        expected_source: Option<&str>,
    ) -> Result<crate::cluster_security::SignedClusterEnvelope> {
        let envelope = self.verify_signed_payload_inner(raw, channel, expected_source, false)?;
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
            &self.namespace,
            &envelope,
        )
        .await
        {
            Ok(admitted) => admitted,
            Err(error) => {
                // A full/drifted replay ledger and a PostgreSQL timeout are
                // control-plane authority failures, not unauthenticated input.
                // Rotate the listener and fail cluster mutations closed until
                // the bounded cleanup/attestation pass proves recovery.
                self.record_authority_failure(&error);
                return Err(error);
            }
        };
        if !admitted {
            self.health
                .replay_rejections
                .fetch_add(1, Ordering::Relaxed);
            anyhow::bail!("cluster envelope replay rejected by PostgreSQL authority");
        }
        // PostgreSQL is the durable replay authority for this path. Once its
        // unique fence commits, a bounded process-local cache must not turn a
        // successfully consumed event into an application failure: the retry
        // would then be rejected by PostgreSQL and the event would be lost.
        // Volatile channels still use the fail-closed in-memory cache below.
        Ok(envelope)
    }

    fn register_pending_ack(
        &self,
        request_id: &str,
        source_node: &str,
        nonce: &str,
    ) -> Result<PendingAckRegistration> {
        let permit = Arc::clone(&self.pending_ack_slots)
            .try_acquire_owned()
            .map_err(|_| anyhow::anyhow!("cluster acknowledgement capacity is exhausted"))?;
        let (sender, receiver) = tokio::sync::mpsc::channel(1);
        let registration_id = uuid::Uuid::new_v4();
        match self.pending_acks.entry(request_id.to_owned()) {
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
            entries: Arc::clone(&self.pending_acks),
            receiver,
            _permit: permit,
        })
    }

    fn dispatch_pending_ack(&self, source_node: &str, payload: serde_json::Value) -> bool {
        let Ok(ack) = serde_json::from_value::<NodeDeliveryAck>(payload) else {
            return false;
        };
        let Some(pending) = self.pending_acks.get(&ack.request_id) else {
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
        let Some(security) = self.security.as_ref() else {
            return Ok(());
        };
        let nodes = security.peer_node_ids();
        crate::db::validate_cluster_peer_key_deployments(
            pool,
            &self.namespace,
            &security.peer_key_authorities(),
        )
        .await?;
        let key_authorities =
            crate::db::cluster_peer_key_authorities(pool, &self.namespace, &nodes).await?;
        let key_replacements = key_authorities
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
        self.authorized_peer_keys
            .retain(|node, _| key_replacements.contains_key(node));
        for (node, authority) in key_replacements {
            self.authorized_peer_keys.insert(node, authority);
        }
        let active =
            crate::db::active_cluster_node_instances(pool, &self.namespace, &nodes).await?;
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
        self.authorized_instances
            .retain(|node, _| replacements.contains_key(node));
        for (node, instance) in replacements {
            self.authorized_instances.insert(node, instance);
        }
        Ok(())
    }

    pub async fn heartbeat_instance_authority(&self, pool: &sqlx::PgPool) -> Result<()> {
        if !self.is_enabled() {
            return Ok(());
        }
        let epoch = self.instance_epoch.load(Ordering::Acquire);
        let security = self
            .security
            .as_ref()
            .context("cluster signing identity is missing")?;
        crate::db::heartbeat_cluster_node_instance(
            pool,
            crate::db::ClusterNodeHeartbeat {
                xmpp_domain: &self.namespace,
                node_id: &self.node_id,
                instance_uuid: self.connection_uuid,
                instance_epoch: epoch,
                signing_key_id: &security.current_key_id,
                signing_key_epoch: security.key_epoch,
                lease: Duration::from_secs(NODE_TTL_SECONDS),
            },
        )
        .await?;
        Ok(())
    }

    pub async fn validate_instance_authority(&self, pool: &sqlx::PgPool) -> Result<()> {
        let Some(security) = self.security.as_ref() else {
            return Ok(());
        };
        let rows = crate::db::active_cluster_node_instances(
            pool,
            &self.namespace,
            std::slice::from_ref(&self.node_id),
        )
        .await?;
        let epoch = self.instance_epoch.load(Ordering::Acquire);
        anyhow::ensure!(
            rows.iter().any(|instance| {
                instance.instance_uuid == self.connection_uuid
                    && instance.instance_epoch == epoch
                    && instance.signing_key_id == security.current_key_id
                    && instance.signing_key_epoch == security.key_epoch
                    && !instance.lease_remaining.is_zero()
            }),
            "this process no longer owns the authoritative cluster node-instance lease"
        );
        Ok(())
    }

    pub async fn release_instance_authority(&self, pool: &sqlx::PgPool) -> Result<bool> {
        if !self.is_enabled() {
            return Ok(false);
        }
        let security = self
            .security
            .as_ref()
            .context("cluster signing identity is missing")?;
        crate::db::release_cluster_node_instance(
            pool,
            &self.namespace,
            &self.node_id,
            self.connection_uuid,
            self.instance_epoch.load(Ordering::Acquire),
            &security.current_key_id,
            security.key_epoch,
        )
        .await
    }

    pub fn begin_shutdown(&self) {
        if self.is_enabled() {
            self.health
                .state
                .store(CLUSTER_SHUTDOWN_REQUIRED, Ordering::Release);
        }
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

    pub fn admit(&self, operation: ClusterOperation) -> Result<()> {
        let state = self.health.state.load(Ordering::Acquire);
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

    pub fn readiness_error(&self) -> Option<String> {
        if !self.health.peer_versions_compatible.load(Ordering::Acquire) {
            return Some("a live cluster peer uses an incompatible application protocol".into());
        }
        match self.health.state.load(Ordering::Acquire) {
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

    pub fn metrics_snapshot(&self) -> ClusterMetricsSnapshot {
        ClusterMetricsSnapshot {
            state: self.health.state.load(Ordering::Relaxed),
            listener_generation: self.health.listener_generation.load(Ordering::Relaxed),
            authentication_failures: self.health.authentication_failures.load(Ordering::Relaxed),
            replay_rejections: self.health.replay_rejections.load(Ordering::Relaxed),
            degraded_transitions: self.health.degraded_transitions.load(Ordering::Relaxed),
            incompatible_peer_versions: self
                .health
                .incompatible_peer_versions
                .load(Ordering::Relaxed),
        }
    }

    pub fn record_control_plane_failure(&self, error: &anyhow::Error) {
        self.record_failure(ClusterFailureClass::RedisCommand, error);
    }

    fn record_listener_failure(&self, error: &anyhow::Error) {
        self.record_failure(ClusterFailureClass::PubSub, error);
    }

    fn record_authority_failure(&self, error: &anyhow::Error) {
        self.record_failure(ClusterFailureClass::PostgreSqlAuthority, error);
    }

    fn record_failure(&self, class: ClusterFailureClass, error: &anyhow::Error) {
        if !self.is_enabled() {
            return;
        }
        let degraded = match self.failure_policy() {
            Some(crate::cluster_security::ClusterFailurePolicy::DurableDirectOnly) => {
                CLUSTER_DURABLE_DIRECT_ONLY
            }
            _ => CLUSTER_FAIL_CLOSED,
        };
        let previous = self.health.state.swap(degraded, Ordering::AcqRel);
        if previous != degraded {
            self.health
                .degraded_transitions
                .fetch_add(1, Ordering::Relaxed);
        }
        let next_listener = self
            .health
            .listener_generation
            .load(Ordering::Acquire)
            .saturating_add(1);
        self.health
            .required_listener_generation
            .fetch_max(next_listener, Ordering::AcqRel);
        self.listener_rotation.notify_waiters();
        let mut since = self
            .health
            .failure_since
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if since.is_none() {
            *since = Some(Instant::now());
        }
        tracing::error!(?error, ?class, policy = ?self.failure_policy(), "cluster control plane entered a degraded state");
    }

    fn note_listener_generation(&self) {
        self.health
            .listener_generation
            .fetch_add(1, Ordering::AcqRel);
        // Startup has no pre-existing local sessions or MUC occupants: State
        // already reconciled PostgreSQL key/instance authority and activate()
        // acquired the Redis node lease. The first subscribed listener is the
        // final empty-state fence. Later recoveries have degraded_transitions
        // and must pass full maintenance reconciliation instead.
        if self.health.state.load(Ordering::Acquire) == CLUSTER_RECONCILING
            && self.health.degraded_transitions.load(Ordering::Acquire) == 0
        {
            let _ = self.complete_reconciliation();
        }
    }

    fn begin_reconciliation(&self) {
        if self.is_enabled() {
            self.health
                .state
                .store(CLUSTER_RECONCILING, Ordering::Release);
        }
    }

    fn complete_reconciliation(&self) -> Result<()> {
        anyhow::ensure!(
            self.health.listener_generation.load(Ordering::Acquire)
                >= self
                    .health
                    .required_listener_generation
                    .load(Ordering::Acquire),
            "cluster PubSub listener generation has not been re-established"
        );
        self.health.state.store(CLUSTER_HEALTHY, Ordering::Release);
        *self
            .health
            .failure_since
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = None;
        Ok(())
    }

    fn safety_lease_expired(&self) -> bool {
        let Some(security) = self.security.as_ref() else {
            return false;
        };
        self.health
            .failure_since
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .is_some_and(|since| {
                since.elapsed() >= Duration::from_secs(security.safety_lease_seconds)
            })
    }

    fn require_shutdown(&self) {
        if self.is_enabled() {
            self.health
                .state
                .store(CLUSTER_SHUTDOWN_REQUIRED, Ordering::Release);
        }
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
        self.admit(ClusterOperation::VolatileDelivery)?;
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

    #[cfg(test)]
    fn verify_signed_payload(
        &self,
        raw: &str,
        channel: &str,
        expected_source: Option<&str>,
    ) -> Result<crate::cluster_security::SignedClusterEnvelope> {
        self.verify_signed_payload_inner(raw, channel, expected_source, true)
    }

    fn verify_signed_payload_inner(
        &self,
        raw: &str,
        channel: &str,
        expected_source: Option<&str>,
        remember_replay: bool,
    ) -> Result<crate::cluster_security::SignedClusterEnvelope> {
        anyhow::ensure!(
            raw.len() <= MAX_CLUSTER_PAYLOAD_BYTES,
            "cluster envelope is oversized"
        );
        let security = self
            .security
            .as_ref()
            .context("cluster verifier is not configured")?;
        let envelope: crate::cluster_security::SignedClusterEnvelope =
            serde_json::from_str(raw).context("cluster envelope is invalid JSON")?;
        envelope.verify(
            &self.namespace,
            &self.node_id,
            channel,
            expected_source,
            security.peers().as_ref(),
            chrono::Utc::now().timestamp(),
        )?;
        anyhow::ensure!(
            envelope.destination_connection_uuid == self.connection_uuid
                && envelope.destination_connection_epoch
                    == self.instance_epoch.load(Ordering::Acquire)
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
        if remember_replay {
            self.remember_envelope_replay(&envelope)?;
        }
        Ok(envelope)
    }

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

    fn note_authentication_failure(&self, error: &anyhow::Error) {
        self.health
            .authentication_failures
            .fetch_add(1, Ordering::Relaxed);
        tracing::warn!(?error, "rejected unauthenticated cluster protocol envelope");
    }

    fn note_incompatible_peer_version(&self, node_id: &str, observed: Option<&str>) {
        if self
            .health
            .peer_versions_compatible
            .swap(false, Ordering::AcqRel)
        {
            self.health
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
        if let Some(security) = self.security.as_ref() {
            for node_id in security.peer_node_ids() {
                let observed: Option<String> =
                    conn.get(self.key(format!("node:{node_id}:alive"))).await?;
                if observed
                    .as_deref()
                    .is_some_and(|version| version != NODE_PROTOCOL_VERSION)
                {
                    compatible = false;
                    self.note_incompatible_peer_version(&node_id, observed.as_deref());
                }
            }
        }
        if compatible {
            self.health
                .peer_versions_compatible
                .store(true, Ordering::Release);
        }
        Ok(())
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

    pub async fn unregister_session(
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
        let full_key = self.key(format!("session:{full_jid}"));
        let bare_key = self.key(format!("user_sessions:{bare}"));
        let activity_key = self.key("session_activity".to_owned());
        let instance_key = self.key(format!("session_instance:{full_jid}"));
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

    pub async fn lookup_nodes(&self, jid: &str) -> Result<Vec<String>> {
        let started = tokio::time::Instant::now();
        let result = async {
            let jid = crate::jid::CanonicalJid::parse(jid)?;
            let Some(_) = &self.pool else {
                return Ok(Vec::new());
            };
            if jid.resourcepart().is_some() {
                let jid = jid.to_string();
                let authority_pool = self
                    .authority_pool
                    .get()
                    .context("cluster session authority pool is unavailable")?;
                let route = crate::db::cluster_session_route_authority(
                    authority_pool,
                    &self.namespace,
                    &jid,
                )
                .await?;
                return Ok(route
                    .map(|authority| authority.owner_node_id)
                    .into_iter()
                    .collect());
            }

            let jid = jid.bare();
            let authority_pool = self
                .authority_pool
                .get()
                .context("cluster session authority pool is unavailable")?;
            crate::db::cluster_session_nodes_for_bare(authority_pool, &self.namespace, &jid).await
        }
        .await;
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

    /// Signed MIX-only fanout with tri-state capability evidence. Unknown
    /// resources are reported to the source so it can perform a bounded
    /// capability wait without charging a business retry attempt.
    pub async fn send_to_node_mix(
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
                mix_capable_only: true,
                ..NodeDeliveryOptions::default()
            },
        )
        .await
    }

    pub async fn send_to_node_confirmed(
        &self,
        node_id: &str,
        target_jid: &str,
        stanza: &str,
        exclude_jid: Option<&str>,
    ) -> Result<bool> {
        let exclude_jids = exclude_jid.into_iter().collect::<Vec<_>>();
        let receipt = self
            .send_to_node_receipt(
                node_id,
                target_jid,
                stanza,
                NodeDeliveryOptions {
                    exclude_jids: &exclude_jids,
                    ..NodeDeliveryOptions::default()
                },
            )
            .await?;
        anyhow::ensure!(
            receipt.acknowledged,
            "cluster presence delivery was not acknowledged"
        );
        Ok(receipt.delivered)
    }

    /// Deliver an exact-resource non-message stanza without crossing an
    /// account delete/recreate boundary. MIX-PAM result journals use this
    /// after committing their terminal state; the UUID is the original
    /// account authority captured by that transaction.
    pub async fn send_to_node_exact_account(
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

    pub async fn send_to_node_available_presence_confirmed_excluding(
        &self,
        node_id: &str,
        target_jid: &str,
        stanza: &str,
        exclude_jid: Option<&str>,
    ) -> Result<bool> {
        let exclude_jids = exclude_jid.into_iter().collect::<Vec<_>>();
        let receipt = self
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
            .await?;
        anyhow::ensure!(
            receipt.acknowledged,
            "cluster presence delivery was not acknowledged"
        );
        Ok(receipt.delivered)
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

    /// Deliver an RFC 6121 roster push only to resources that have requested
    /// their roster on this (possibly resumed) session.
    pub async fn send_to_node_roster(
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

    async fn send_to_node_current_presence_replay(
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

    /// Cancel the exact live transport whose durable XEP-0198 epoch was
    /// revoked. Receivers compare the UUID, so delayed control traffic cannot
    /// disconnect a later bind that reused the full JID.
    pub async fn send_sm_session_teardown(
        &self,
        full_jid: &str,
        sm_session_id: uuid::Uuid,
    ) -> Result<()> {
        let full_jid = crate::jid::canonical_session_key(full_jid)?;
        if self.pool.is_none() {
            return Ok(());
        }
        let nodes = self.lookup_nodes(&full_jid).await?;
        let payload = serde_json::json!({
            "target": full_jid,
            "sm_session_teardown": true,
            "sm_session_id": sm_session_id,
        });
        for node_id in nodes {
            if node_id != self.node_id {
                self.send_control_to_node(&node_id, &full_jid, payload.clone())
                    .await?;
            }
        }
        Ok(())
    }

    /// Cancel credential-stale transports on every node currently routing an
    /// account.  Receivers compare both the immutable user UUID and monotonic
    /// generation, so delayed or replayed controls cannot kill a replacement
    /// account or a session authenticated after the mutation.
    pub async fn send_account_generation_teardown(
        &self,
        bare_jid: &str,
        user_id: uuid::Uuid,
        minimum_generation: i64,
    ) -> Result<()> {
        anyhow::ensure!(minimum_generation >= 0, "invalid auth generation");
        let bare_jid = crate::jid::canonicalize_bare(bare_jid)?;
        if self.pool.is_none() {
            return Ok(());
        }
        let nodes = self.lookup_nodes(&bare_jid).await?;
        let payload = serde_json::json!({
            "target": bare_jid,
            "account_generation_teardown": true,
            "user_id": user_id,
            "minimum_generation": minimum_generation,
        });
        for node_id in nodes {
            if node_id != self.node_id {
                self.send_control_to_node(&node_id, &bare_jid, payload.clone())
                    .await?;
            }
        }
        Ok(())
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

    /// Terminate only the caller-authorized immutable connection instance.
    /// This primitive verifies the immutable connection UUID against current
    /// authority, so an admin effect committed for an old connection cannot
    /// be retargeted to a later bind of the same full JID while the effect is
    /// being dispatched or retried.
    pub async fn send_session_instance_termination(
        &self,
        full_jid: &str,
        expected_connection_id: uuid::Uuid,
    ) -> Result<bool> {
        anyhow::ensure!(
            !expected_connection_id.is_nil(),
            "session termination requires a non-nil connection identity"
        );
        let full_jid = crate::jid::canonical_session_key(full_jid)?;
        if self.pool.is_none() {
            return Ok(false);
        }
        let authority_pool = self
            .authority_pool
            .get()
            .context("cluster session authority pool is unavailable")?;
        let Some(route) =
            crate::db::cluster_session_route_authority(authority_pool, &self.namespace, &full_jid)
                .await?
        else {
            return Ok(false);
        };
        if route.connection_uuid != expected_connection_id || route.owner_node_id == self.node_id {
            return Ok(false);
        }
        let payload = serde_json::json!({
            "target":full_jid,
            "session_termination":true,
            "connection_id":expected_connection_id,
        });
        let acknowledgement = self
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
        let (Some(pool), Some(_)) = (&self.pool, &self.client) else {
            anyhow::bail!("cluster control requested without an active cluster transport");
        };
        let request_id = uuid::Uuid::new_v4().to_string();
        let nonce = format!("{}{}", uuid::Uuid::new_v4(), uuid::Uuid::new_v4());
        let mut conn = pool.get().await?;
        let peer_version: Option<String> =
            conn.get(self.key(format!("node:{node_id}:alive"))).await?;
        if !supports_current_cluster_protocol(peer_version.as_deref()) {
            if peer_version.is_some() {
                self.note_incompatible_peer_version(node_id, peer_version.as_deref());
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
        let channel = self.key(format!("node:{node_id}"));
        let mut acknowledgement = self.register_pending_ack(&request_id, node_id, &nonce)?;
        let result = async {
            let receivers = self
                .publish_signed(&mut conn, node_id, &channel, payload)
                .await?;
            if receivers == 0 {
                let error = anyhow::anyhow!("cluster control had no subscriber");
                self.record_control_plane_failure(&error);
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
                    self.record_control_plane_failure(&error);
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
            && options.durable_delivery.is_some()
        {
            // The PostgreSQL row remains the only accepted projection. The
            // caller observes no live acceptance and leaves it for replay.
            return Ok(NodeDeliveryReceipt::default());
        }
        self.admit(if options.durable_delivery.is_some() {
            ClusterOperation::DurableDirect
        } else {
            ClusterOperation::VolatileDelivery
        })?;
        let target_jid = crate::jid::canonicalize(target_jid)?;
        let delivery_contract =
            outbound_delivery_contract(stanza, &target_jid, options.durable_delivery)?;
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

    /// Reconcile disposable Redis room indexes without consulting them for
    /// authority. Both the stable node lease and the exact process-instance
    /// lease must be live. This lets a restarted process remove its own old
    /// projection immediately instead of preserving ghosts behind a reused
    /// node ID. The O(room-size) sweep is maintenance/read-only work; stanza
    /// fan-out never invokes it.
    async fn reconcile_muc_soft_state(&self, room_jid: &str) -> Result<()> {
        let Some(pool) = &self.pool else {
            return Ok(());
        };
        let room = crate::jid::canonicalize_bare(room_jid)?;
        let occupants_key = self.key(format!("muc_occupants:{room}"));
        let owners_key = self.key(format!("muc_occupant_nodes:{room}"));
        let nodes_key = self.key(format!("muc_nodes:{room}"));
        let instances_key = self.key(format!("muc_occupant_instances:{room}"));
        let node_counts_key = self.key(format!("muc_node_counts:{room}"));
        let alive_prefix = self.key("node:".to_owned());
        let instance_alive_prefix = self.key("node_instance:".to_owned());
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
        self.admit(ClusterOperation::Resume)?;
        let incoming: crate::state::SerializableMucOccupant = serde_json::from_str(json)?;
        anyhow::ensure!(
            incoming.sm_session_id == Some(sm_session_id)
                && !incoming.cluster_epoch.is_nil()
                && !incoming.connection_id.is_nil(),
            "suspended MUC refresh requires the exact occupancy and SM identities"
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
        let tombstone_key = self.key(format!("sm_muc_teardown:{sm_session_id}"));
        let nodes_key = self.key(format!("muc_nodes:{room}"));
        let instances_key = self.key(format!("muc_occupant_instances:{room}"));
        let node_counts_key = self.key(format!("muc_node_counts:{room}"));
        let alive_key = self.key(format!("node:{}:alive", self.node_id));
        let process_alive_key = self.process_alive_key()?;
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
        Ok(stored == 1)
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
        let Some(pool) = &self.pool else {
            return Ok(HashMap::new());
        };
        let room = crate::jid::canonicalize_bare(room_jid)?;
        self.reconcile_muc_soft_state(&room).await?;
        let mut conn = pool.get().await?;
        let occupants_key = self.key(format!("muc_occupants:{room}"));
        Ok(conn.hgetall(&occupants_key).await?)
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

    pub async fn leave_muc(&self, room_jid: &str) -> Result<()> {
        let Some(pool) = &self.pool else {
            return Ok(());
        };
        let mut conn = pool.get().await?;
        let room = crate::jid::canonicalize_bare(room_jid)?;
        let owners_key = self.key(format!("muc_occupant_nodes:{room}"));
        let nodes_key = self.key(format!("muc_nodes:{room}"));
        let occupants_key = self.key(format!("muc_occupants:{room}"));
        let instances_key = self.key(format!("muc_occupant_instances:{room}"));
        let node_counts_key = self.key(format!("muc_node_counts:{room}"));
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
            .arg(&self.node_id)
            .arg(MUC_SOFT_STATE_TTL_SECONDS)
            .invoke_async(&mut *conn)
            .await?;
        Ok(())
    }

    async fn active_muc_nodes(&self, room_jid: &str) -> Result<Vec<String>> {
        let Some(pool) = &self.pool else {
            return Ok(Vec::new());
        };
        let room = crate::jid::canonicalize_bare(room_jid)?;
        let mut conn = pool.get().await?;
        let key = self.key(format!("muc_nodes:{room}"));
        Ok(conn.smembers(&key).await?)
    }

    pub async fn send_to_muc(&self, room_jid: &str, stanza: &str) -> Result<()> {
        self.send_to_muc_internal(room_jid, stanza, None).await
    }

    /// Best-effort signed wake after PostgreSQL committed a MUC operation.
    /// The envelope contains only immutable IDs; receivers must pull and
    /// authorize the operation/outbox row from PostgreSQL.
    pub async fn send_muc_operation_wake(
        &self,
        descriptor: &crate::db::ClusterMucWakeDescriptor,
    ) -> Result<()> {
        if descriptor
            .target_nodes
            .iter()
            .any(|node| node == &self.node_id)
        {
            self.muc_outbox_notify.notify_one();
        }
        let Some(pool) = &self.pool else {
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
            if node_id == &self.node_id {
                continue;
            }
            let channel = self.key(format!("node:{node_id}"));
            let _ = self
                .publish_signed(&mut conn, node_id, &channel, payload.clone())
                .await?;
        }
        Ok(())
    }

    pub async fn wake_committed_muc_operation(
        &self,
        pool: &sqlx::PgPool,
        operation_id: uuid::Uuid,
    ) -> Result<()> {
        let result = async {
            if let Some(descriptor) =
                crate::db::cluster_muc_wake_descriptor(pool, operation_id).await?
            {
                self.send_muc_operation_wake(&descriptor).await?;
            }
            Ok::<_, anyhow::Error>(())
        }
        .await;
        if let Err(error) = result {
            // The PostgreSQL operation/outbox is already committed. Redis is
            // only a wake accelerator; surfacing this as protocol failure
            // would invite an unsafe duplicate mutation retry.
            tracing::warn!(?error, %operation_id, "committed MUC operation wake failed; PostgreSQL poller will catch up");
            self.record_control_plane_failure(&error);
        }
        Ok(())
    }

    async fn wait_for_muc_outbox_wake(&self) {
        self.muc_outbox_notify.notified().await;
    }

    fn notify_muc_outbox_worker(&self) {
        self.muc_outbox_notify.notify_one();
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

    /// Ask every other node serving a room to discard an exact suspended SM
    /// occupant and publish its final unavailable presence locally.  The
    /// session UUID prevents a late expiry from evicting a newly resumed or
    /// rejoined occupant that happens to reuse the same nick/full JID.
    pub async fn send_sm_muc_teardown(
        &self,
        room_jid: &str,
        sm_session_id: uuid::Uuid,
        occupant: &crate::state::SerializableMucOccupant,
    ) -> Result<()> {
        let Some(pool) = &self.pool else {
            return Ok(());
        };
        let room_jid = crate::jid::canonicalize_bare(room_jid)?;
        let nick = crate::xmpp::xml_util::prepare_muc_nick(&occupant.nick)?;
        let nodes = self.active_muc_nodes(&room_jid).await?;
        let occupants_key = self.key(format!("muc_occupants:{room_jid}"));
        let owners_key = self.key(format!("muc_occupant_nodes:{room_jid}"));
        let nodes_key = self.key(format!("muc_nodes:{room_jid}"));
        let instances_key = self.key(format!("muc_occupant_instances:{room_jid}"));
        let node_counts_key = self.key(format!("muc_node_counts:{room_jid}"));
        let tombstone_key = self.key(format!("sm_muc_teardown:{sm_session_id}"));
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
            if node_id != &self.node_id {
                self.send_control_to_node(node_id, &room_jid, payload.clone())
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
}

pub async fn run_maintenance(
    state: Arc<AppState>,
    cancel: CancellationToken,
    heartbeat: crate::workers::WorkerHeartbeat,
) -> Result<()> {
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
                        maintenance_once(&state),
                    ) => result
                        .context("cluster maintenance pass exceeded its time budget")
                        .and_then(std::convert::identity),
                };
                if let Err(error) = maintenance {
                    state.cluster.record_control_plane_failure(&error);
                    heartbeat.error(&error);
                    state
                        .metrics
                        .background_maintenance_failures_total
                        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    tracing::warn!(?error, "session authorization/cluster lease maintenance failed; it will be retried");
                } else {
                    heartbeat.ok();
                }
            }
        }
    }
}

async fn maintenance_once(state: &AppState) -> Result<()> {
    // PostgreSQL is authoritative for credential generations.  One bounded
    // batch query provides a Redis-independent safety net for lost controls,
    // node restarts and rolling upgrades.
    let snapshots: Vec<_> = state
        .sessions
        .iter()
        .map(|entry| {
            (
                entry.key().clone(),
                entry.user_id,
                entry.auth_generation,
                entry.user_agent_id,
                entry.user_agent_epoch,
                Arc::clone(&entry.last_activity),
                entry.disconnect.clone(),
            )
        })
        .collect();
    let mut user_ids = snapshots
        .iter()
        .map(|(_, user_id, _, _, _, _, _)| *user_id)
        .collect::<Vec<_>>();
    user_ids.sort_unstable();
    user_ids.dedup();
    let auth_states = crate::db::auth_states_for_users(&state.pool, &user_ids).await?;
    for (full_jid, user_id, generation, _, _, _, disconnect) in &snapshots {
        if auth_states
            .get(user_id)
            .is_none_or(|current| current.is_disabled || current.auth_generation != *generation)
        {
            tracing::warn!(%full_jid, %user_id, auth_generation = generation, "disconnecting credential-stale live session");
            disconnect.cancel();
        }
    }
    let mut agents = snapshots
        .iter()
        .filter_map(|(_, user_id, _, device_id, epoch, _, _)| {
            device_id
                .zip(*epoch)
                .map(|(device_id, _)| (*user_id, device_id))
        })
        .collect::<Vec<_>>();
    agents.sort_unstable();
    agents.dedup();
    let current_epochs = crate::db::user_agent_login_epochs(&state.pool, &agents).await?;
    for (full_jid, user_id, _, device_id, epoch, _, disconnect) in &snapshots {
        if let Some((device_id, epoch)) = device_id.zip(*epoch) {
            if current_epochs
                .get(&(*user_id, device_id))
                .is_none_or(|current| epoch < *current)
            {
                tracing::warn!(%full_jid, %user_id, %device_id, epoch, "disconnecting replaced user-agent session");
                disconnect.cancel();
            }
        }
    }
    if !state.cluster.is_enabled() {
        return Ok(());
    }
    let reconcile = state.cluster.readiness_error().is_some();
    if reconcile {
        state.cluster.begin_reconciliation();
    }
    // PostgreSQL instance authority is refreshed before Redis ownership. A
    // recovered listener cannot make this node ready while its view of peer
    // process epochs is stale.
    state
        .cluster
        .refresh_instance_authority(&state.pool)
        .await?;
    let _redis_timer = state.metrics.redis_operation_duration_seconds.start_timer();
    state.cluster.touch_node().await?;
    let sessions = state
        .sessions
        .iter()
        .map(|entry| {
            let age = entry
                .last_activity
                .read()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .elapsed()
                .as_secs();
            (
                entry.key().clone(),
                age,
                entry.connection_id,
                entry.disconnect.clone(),
            )
        })
        .collect::<Vec<_>>();
    for (full_jid, activity_age, connection_id, disconnect) in sessions {
        if !state
            .cluster
            .refresh_session(&full_jid, activity_age, connection_id)
            .await?
        {
            // Redis compares both node and immutable connection UUID. If a
            // failover or newer bind owns this route, leaving the old local
            // stream routable creates split brain. Disconnect it; its exact
            // UUID-guarded unregister/Drop cannot erase the replacement.
            tracing::warn!(%full_jid, %connection_id, "disconnecting local session that lost its Redis routing lease");
            disconnect.cancel();
        }
    }
    // PostgreSQL, not Redis, owns clustered MUC occupancy. Refresh the
    // complete node snapshot once, then require each local actor to match its
    // exact incarnation and connection fence. Redis is repopulated only as a
    // disposable fan-out cache after the authoritative check succeeds.
    let authoritative_muc = crate::db::authoritative_cluster_muc_occupancies_for_node(
        &state.pool,
        &state.cluster.node_id,
    )
    .await?;
    state
        .metrics
        .cluster_muc_pg_reconciliations_total
        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let authoritative_muc = authoritative_muc
        .into_iter()
        .map(|occupancy| {
            (
                (occupancy.occupant_incarnation, occupancy.connection_uuid),
                occupancy,
            )
        })
        .collect::<std::collections::HashMap<_, _>>();
    let occupants: Vec<_> = state
        .muc_occupants
        .iter()
        .map(|entry| entry.value().clone())
        .collect();
    let mut muc_soft_state_errors = 0_u64;
    let mut active_muc_rooms = HashSet::new();
    for occupant in occupants {
        let serializable = crate::state::SerializableMucOccupant::from(&occupant);
        let authoritative =
            authoritative_muc.get(&(occupant.cluster_epoch, occupant.connection_id));
        let exact = authoritative.is_some_and(|authority| {
            authority.full_jid == occupant.full_jid && authority.nick == occupant.nick
        });
        let renewed = if let Some(authority) = authoritative.filter(|_| exact) {
            let target = crate::db::ClusterMucOccupancyTarget::from(authority);
            crate::db::renew_cluster_muc_occupancy(
                &state.pool,
                &target,
                &state.cluster.node_id,
                Duration::from_secs(90),
            )
            .await?
        } else {
            false
        };
        if !renewed {
            state.remove_live_muc_membership(&serializable);
            let key = crate::xmpp::xml_util::muc_occupant_key(&occupant.room_jid, &occupant.nick);
            state.muc_occupants.remove_if(&key, |_, current| {
                current.full_jid == occupant.full_jid
                    && current.connection_id == occupant.connection_id
                    && current.cluster_epoch == occupant.cluster_epoch
            });
            if let Some(session) = state.sessions.get(&occupant.full_jid) {
                if session.connection_id == occupant.connection_id {
                    session.disconnect.cancel();
                }
            }
            tracing::warn!(
                room = %occupant.room_jid,
                nick = %occupant.nick,
                epoch = %occupant.cluster_epoch,
                "removed local MUC actor that lost its PostgreSQL occupancy authority"
            );
            continue;
        }
        let json = serde_json::to_string(&serializable)?;
        if let Err(error) = async {
            state.cluster.join_muc(&occupant.room_jid).await?;
            anyhow::ensure!(
                state
                    .cluster
                    .register_muc_occupant(&occupant.room_jid, &occupant.nick, &json)
                    .await?,
                "Redis MUC soft-state rejected the exact PostgreSQL occupant"
            );
            Ok::<_, anyhow::Error>(())
        }
        .await
        {
            muc_soft_state_errors = muc_soft_state_errors.saturating_add(1);
            state.cluster.record_control_plane_failure(&error);
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
        if let Err(error) = state.cluster.reconcile_muc_soft_state(&room).await {
            muc_soft_state_errors = muc_soft_state_errors.saturating_add(1);
            state.cluster.record_control_plane_failure(&error);
            tracing::warn!(?error, %room, "could not reconcile Redis MUC room soft-state");
        }
    }
    if reconcile {
        anyhow::ensure!(
            muc_soft_state_errors == 0,
            "Redis MUC soft-state reconciliation failed for {muc_soft_state_errors} authoritative occupancies"
        );
        state.cluster.complete_reconciliation()?;
    }
    Ok(())
}

pub async fn run_pubsub_listener(
    state: Arc<AppState>,
    cancel: CancellationToken,
    heartbeat: crate::workers::WorkerHeartbeat,
) -> Result<()> {
    if !state.cluster.is_enabled() {
        return Ok(());
    }
    let result = listen_once(Arc::clone(&state), cancel.clone(), heartbeat).await;
    if cancel.is_cancelled() {
        return result;
    }
    let error = match result {
        Ok(()) => anyhow::anyhow!("Redis PubSub stream ended unexpectedly"),
        Err(error) => error,
    };
    let rotation_already_required = state
        .cluster
        .health
        .listener_generation
        .load(Ordering::Acquire)
        < state
            .cluster
            .health
            .required_listener_generation
            .load(Ordering::Acquire);
    if !rotation_already_required {
        state.cluster.record_listener_failure(&error);
    }
    Err(error)
}

/// Supervise the PostgreSQL half of cluster identity fencing and the bounded
/// degraded-mode shutdown deadline. This worker never makes Redis healthy;
/// only full lease/occupant/listener reconciliation in maintenance can do so.
pub async fn run_failure_supervisor(
    state: Arc<AppState>,
    cancel: CancellationToken,
    heartbeat: crate::workers::WorkerHeartbeat,
) -> Result<()> {
    if !state.cluster.is_enabled() {
        return Ok(());
    }
    let identity = state
        .cluster
        .key_authority_identity()
        .context("cluster signing-key authority is missing")?;
    let mut interval = tokio::time::interval(Duration::from_secs(5));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut heartbeat_tick = 0_u8;
    loop {
        tokio::select! {
            _ = cancel.cancelled() => return Ok(()),
            _ = interval.tick() => {
                heartbeat_tick = heartbeat_tick.wrapping_add(1);
                let validation = async {
                    crate::db::validate_cluster_key_deployment(&state.pool, &identity).await?;
                    state.cluster.validate_instance_authority(&state.pool).await?;
                    if heartbeat_tick % 6 == 1 {
                        state.cluster.heartbeat_instance_authority(&state.pool).await?;
                        crate::db::cleanup_cluster_envelope_replays(&state.pool, 4096).await?;
                        crate::db::validate_cluster_replay_capacity_authority(&state.pool).await?;
                        crate::db::cleanup_cluster_session_routes(&state.pool, 4096).await?;
                        crate::db::validate_cluster_session_route_authority(&state.pool).await?;
                    }
                    state.cluster.refresh_instance_authority(&state.pool).await?;
                    Ok::<_, anyhow::Error>(())
                }.await;
                match validation {
                    Ok(()) => heartbeat.ok(),
                    Err(error) => {
                        heartbeat.error(&error);
                        state.cluster.record_authority_failure(&error);
                        if degraded_shutdown_required(
                            state.cluster.failure_policy().unwrap_or(
                                crate::cluster_security::ClusterFailurePolicy::FailClosed,
                            ),
                            false,
                            false,
                        ) {
                            state.cluster.require_shutdown();
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
                let policy = state.cluster.failure_policy().unwrap_or(
                    crate::cluster_security::ClusterFailurePolicy::FailClosed,
                );
                if degraded_shutdown_required(policy, true, state.cluster.safety_lease_expired()) {
                    state.cluster.require_shutdown();
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
    worker_registry.supervise(
        "cluster-muc-outbox",
        crate::workers::WorkerCriticality::Restartable,
        crate::workers::WorkerMode::Continuous,
        Some(Duration::from_secs(30)),
        cancel.clone(),
        move |heartbeat| {
            let state = Arc::clone(&state);
            let cancel = cancel.clone();
            async move { run_muc_outbox_delivery(state, cancel, heartbeat).await }
        },
    );
}

async fn run_muc_outbox_delivery(
    state: Arc<AppState>,
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
            _ = state.cluster.wait_for_muc_outbox_wake() => {},
        }
        crate::db::expire_cluster_muc_occupancies(&state.pool, 32).await?;
        crate::db::dead_letter_expired_cluster_muc_outbox(&state.pool, 256).await?;
        let pass_started = Instant::now();
        'batches: for _ in 0..MUC_OUTBOX_MAX_BATCHES_PER_PASS {
            if cancel.is_cancelled() || pass_started.elapsed() >= MUC_OUTBOX_PASS_BUDGET {
                break;
            }
            let deliveries = crate::db::claim_cluster_muc_outbox(
                &state.pool,
                &state.cluster.node_id,
                MUC_OUTBOX_BATCH_SIZE,
                Duration::from_secs(30),
            )
            .await?;
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
                    deliver_cluster_muc_event(&state, &delivery),
                )
                .await
                .map_err(|_| anyhow::anyhow!("cluster MUC delivery exceeded its time budget"))
                .and_then(std::convert::identity);
                match outcome {
                    Ok(()) => {
                        anyhow::ensure!(
                            crate::db::ack_cluster_muc_outbox(
                                &state.pool,
                                delivery.delivery_id,
                                delivery.claim_token,
                            )
                            .await?,
                            "cluster MUC outbox ACK lost its exact claim lease"
                        );
                        state
                            .metrics
                            .cluster_muc_outbox_deliveries_total
                            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    }
                    Err(error) => {
                        tracing::warn!(
                            ?error,
                            delivery_id=%delivery.delivery_id,
                            operation_id=%delivery.operation_id,
                            event_id=%delivery.event_id,
                            "cluster MUC audience delivery will retry with the same stable event ID"
                        );
                        crate::db::retry_cluster_muc_outbox(
                            &state.pool,
                            &delivery,
                            &error.to_string(),
                        )
                        .await?;
                        state
                            .metrics
                            .cluster_muc_outbox_retries_total
                            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    }
                }
                heartbeat.ok();
            }
        }
        crate::db::cleanup_cluster_muc_dead_letters(&state.pool, 256).await?;
        if Instant::now() >= next_history_cleanup {
            // Ninety days is the bounded online idempotency/recovery horizon
            // for experimental clustered room-control events. Active legal
            // holds and outstanding delivery projections make the database
            // cleanup fail closed or skip the protected incarnation.
            crate::db::cleanup_cluster_muc_history(&state.pool, 90, 256).await?;
            next_history_cleanup = Instant::now() + Duration::from_secs(60);
        }
        let snapshot = crate::db::cluster_muc_outbox_snapshot(&state.pool).await?;
        state.metrics.cluster_muc_outbox_queued.store(
            snapshot.queued_rows.max(0) as u64,
            std::sync::atomic::Ordering::Relaxed,
        );
        state.metrics.cluster_muc_outbox_dead_letters.store(
            snapshot.dead_letter_rows.max(0) as u64,
            std::sync::atomic::Ordering::Relaxed,
        );
        state.metrics.cluster_muc_outbox_oldest_age_seconds.store(
            snapshot.oldest_age_seconds.max(0) as u64,
            std::sync::atomic::Ordering::Relaxed,
        );
        heartbeat.ok();
    }
}

struct ClusterMucPolicyRender<'a> {
    state: &'a AppState,
    context: &'a crate::db::ClusterMucEventContext,
    room_jid: &'a str,
    recipient: &'a crate::state::MucOccupant,
    event_id: &'a str,
    change: &'a serde_json::Value,
    configuration_change: bool,
    stanzas: &'a mut Vec<String>,
}

fn append_cluster_muc_policy_snapshot(render: ClusterMucPolicyRender<'_>) -> Result<()> {
    let ClusterMucPolicyRender {
        state,
        context,
        room_jid,
        recipient,
        event_id,
        change,
        configuration_change,
        stanzas,
    } = render;
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
    let subject_key = crate::xmpp::xml_util::muc_occupant_key(room_jid, &snapshot.nick);
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
            room_non_anonymous || recipient.role == "moderator",
            status,
            None,
            change["reason"].as_str(),
        ));
        // The target's own durable delivery performs cache revocation. If a
        // different audience row removed it first, the target row would no
        // longer be able to deliver its required self-unavailable stanza.
        if subject_is_recipient {
            state.remove_live_muc_membership(&subject);
            state.muc_occupants.remove_if(&subject_key, |_, current| {
                current.full_jid == snapshot.full_jid
                    && current.cluster_epoch == snapshot.occupant_incarnation
                    && current.connection_id == snapshot.connection_uuid
            });
        }
    } else {
        if subject_is_recipient {
            if let Some(mut local) = state
                .muc_occupants
                .get(&subject_key)
                .map(|entry| entry.value().clone())
                .filter(|local| {
                    local.cluster_epoch == snapshot.occupant_incarnation
                        && local.connection_id == snapshot.connection_uuid
                })
            {
                local.affiliation = snapshot.affiliation.clone();
                local.role = snapshot.role.clone();
                local.room_non_anonymous = room_non_anonymous;
                state.muc_occupants.insert(subject_key, local);
            }
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

async fn deliver_cluster_muc_event(
    state: &Arc<AppState>,
    delivery: &crate::db::ClusterMucOutboxDelivery,
) -> Result<()> {
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
    let context = crate::db::cluster_muc_event_context(&state.pool, delivery.operation_id)
        .await?
        .context("cluster MUC outbox operation is missing")?;
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
    let room_jid = format!(
        "{}@conference.{}",
        context.room_localpart, state.config.domain
    );
    let Some(recipient_nick) = delivery.recipient_nick.as_deref() else {
        // node_pull rows are wake hints only; the worker has completed the
        // authoritative PostgreSQL pull by reaching this point.
        return Ok(());
    };
    let recipient_key = crate::xmpp::xml_util::muc_occupant_key(&room_jid, recipient_nick);
    let cached_recipient = state
        .muc_occupants
        .get(&recipient_key)
        .map(|entry| entry.value().clone());
    let exact_cached = cached_recipient.as_ref().is_some_and(|recipient| {
        delivery.recipient_full_jid.as_deref() == Some(&recipient.full_jid)
            && delivery.recipient_occupant_incarnation == Some(recipient.cluster_epoch)
            && delivery.recipient_connection_uuid == Some(recipient.connection_id)
            && recipient.nick == recipient_nick
    });
    let recipient = if exact_cached {
        cached_recipient.expect("exact cached MUC recipient was checked")
    } else {
        // A terminal transition revokes the PG lease before its notification
        // is written to the socket. Reconstruct only an endpoint from the
        // immutable outbox audience tuple; never revive membership or trust a
        // Redis nickname cache. The stable event ID remains the retry key.
        let snapshot =
            crate::db::cluster_muc_delivery_recipient_snapshot(&state.pool, delivery).await?;
        let Some(snapshot) = snapshot else {
            if crate::db::cluster_muc_delivery_audience_is_current(&state.pool, delivery).await? {
                anyhow::bail!("authoritative MUC audience snapshot disappeared");
            }
            return Ok(());
        };
        let room_non_anonymous = context.details["non_anonymous"]
            .as_bool()
            .unwrap_or(context.room_non_anonymous);
        state
            .cluster_muc_recipient_from_snapshot(
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
                let target_key = crate::xmpp::xml_util::muc_occupant_key(&room_jid, &target.nick);
                if let Some(mut local) = state
                    .muc_occupants
                    .get(&target_key)
                    .map(|entry| entry.value().clone())
                    .filter(|local| {
                        local.cluster_epoch == target.cluster_epoch
                            && local.connection_id == target.connection_id
                    })
                {
                    local.role = target.role.clone();
                    local.affiliation = target.affiliation.clone();
                    state.muc_occupants.insert(target_key, local);
                }
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
            stanzas.push(crate::xmpp::xml_util::muc_presence_stanza(
                &target,
                &recipient.full_jid,
                true,
                target.full_jid == recipient.full_jid,
                false,
                Some(&event_id),
                context.room_non_anonymous || recipient.role == "moderator",
            ));
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
            let actor_nick = context.actor_full_jid.as_deref().and_then(|full| {
                state
                    .muc_occupants_for(&room_jid)
                    .into_iter()
                    .find_map(|(_, actor)| (actor.full_jid == full).then_some(actor.nick))
            });
            stanzas.push(crate::xmpp::xml_util::muc_presence_stanza_with_status(
                &target,
                &recipient.full_jid,
                true,
                target.full_jid == recipient.full_jid,
                false,
                Some(&event_id),
                true,
                status,
                actor_nick.as_deref(),
                reason,
            ));
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
                    state,
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
        other => anyhow::bail!("unsupported cluster MUC event kind {other}"),
    }
    for (ordinal, stanza) in stanzas.into_iter().enumerate() {
        let ordinal =
            i32::try_from(ordinal).context("MUC event has too many stanza projections")?;
        let stable_item_id = format!("{}:{ordinal}", delivery.event_id);
        if crate::db::cluster_muc_delivery_item_completed(
            &state.pool,
            delivery.delivery_id,
            ordinal,
            &stable_item_id,
        )
        .await?
        {
            continue;
        }
        anyhow::ensure!(
            state
                .deliver_to_muc_occupant_with_receipt(&recipient, stanza, delivery,)
                .await?,
            "exact MUC audience transport did not reach a durable ownership/write boundary"
        );
        anyhow::ensure!(
            crate::db::complete_cluster_muc_delivery_item(
                &state.pool,
                delivery,
                ordinal,
                &stable_item_id,
            )
            .await?,
            "cluster MUC delivery item lost its stable ordinal identity"
        );
    }
    Ok(())
}

async fn listen_once(
    state: Arc<AppState>,
    cancel: CancellationToken,
    heartbeat: crate::workers::WorkerHeartbeat,
) -> Result<()> {
    let client = state
        .cluster
        .client
        .as_ref()
        .context("Redis listener started without a configured Redis client")?;
    let mut redis_setup_timer = Some(state.metrics.redis_operation_duration_seconds.start_timer());
    let mut pubsub_conn = open_pubsub(client).await?;
    let channel = state.cluster.key(format!("node:{}", state.cluster.node_id));
    let probe_channel = state.cluster.key(format!(
        "listener_probe:{}:{}:{}",
        state.cluster.node_id,
        state.cluster.connection_uuid,
        state.cluster.instance_epoch.load(Ordering::Acquire)
    ));
    subscribe_pubsub(&mut pubsub_conn, &channel).await?;
    subscribe_pubsub(&mut pubsub_conn, &probe_channel).await?;
    let (_pubsub_sink, mut stream) = pubsub_conn.split();
    let initial_probe = uuid::Uuid::new_v4().to_string();
    publish_listener_probe(&state.cluster, &probe_channel, &initial_probe).await?;
    let mut pending_probe = Some((
        initial_probe,
        tokio::time::Instant::now() + REDIS_CONNECT_TIMEOUT,
        true,
    ));
    let mut liveness = tokio::time::interval_at(
        tokio::time::Instant::now() + Duration::from_secs(15),
        Duration::from_secs(15),
    );
    liveness.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    enum ListenerInput {
        ProbeDue,
        ProbeTimedOut,
        Message(Option<redis::Msg>),
    }

    loop {
        if state
            .cluster
            .health
            .listener_generation
            .load(Ordering::Acquire)
            < state
                .cluster
                .health
                .required_listener_generation
                .load(Ordering::Acquire)
        {
            anyhow::bail!("Redis PubSub listener rotation was requested");
        }
        let probe_deadline = pending_probe
            .as_ref()
            .map(|(_, deadline, _)| *deadline)
            .unwrap_or_else(|| tokio::time::Instant::now() + Duration::from_secs(86_400));
        let input = tokio::select! {
            _ = cancel.cancelled() => return Ok(()),
            _ = state.cluster.listener_rotation.notified() => {
                anyhow::bail!("Redis PubSub listener rotation was requested");
            }
            _ = liveness.tick() => ListenerInput::ProbeDue,
            _ = tokio::time::sleep_until(probe_deadline), if pending_probe.is_some() => {
                ListenerInput::ProbeTimedOut
            }
            message = stream.next() => ListenerInput::Message(message),
        };
        let message = match input {
            ListenerInput::ProbeDue => {
                anyhow::ensure!(
                    pending_probe.is_none(),
                    "Redis PubSub self-loop probe remained outstanding"
                );
                let token = uuid::Uuid::new_v4().to_string();
                publish_listener_probe(&state.cluster, &probe_channel, &token).await?;
                pending_probe = Some((
                    token,
                    tokio::time::Instant::now() + REDIS_CONNECT_TIMEOUT,
                    false,
                ));
                continue;
            }
            ListenerInput::ProbeTimedOut => {
                anyhow::bail!("Redis PubSub publish/subscription self-loop timed out")
            }
            ListenerInput::Message(message) => message,
        };
        let Some(message) = message else {
            return Ok(());
        };
        let received_channel = message.get_channel_name().to_owned();
        let Ok(payload) = message.get_payload::<String>() else {
            continue;
        };
        if received_channel == probe_channel {
            if pending_probe
                .as_ref()
                .is_some_and(|(token, _, _)| token == &payload)
            {
                let (_, _, establishing) = pending_probe.take().expect("probe was present");
                if establishing {
                    state.cluster.note_listener_generation();
                    drop(redis_setup_timer.take());
                }
                heartbeat.ok();
            }
            continue;
        }
        anyhow::ensure!(
            received_channel == channel,
            "Redis PubSub listener received an unexpected channel"
        );
        let envelope = match state
            .cluster
            .verify_signed_payload_persisted(&payload, &channel, None)
            .await
        {
            Ok(envelope) => envelope,
            Err(error) => {
                state.cluster.note_authentication_failure(&error);
                continue;
            }
        };
        let protocol_version = envelope.version;
        let envelope_kind = envelope.kind;
        let source_node = envelope.source_node;
        let json = envelope.payload;
        if envelope_kind == crate::cluster_security::ClusterCommandKind::Ack {
            if !state.cluster.dispatch_pending_ack(&source_node, json) {
                state.cluster.note_authentication_failure(&anyhow::anyhow!(
                    "cluster acknowledgement had no exact pending request"
                ));
            }
            continue;
        }
        let Some(target) = json["target"].as_str() else {
            continue;
        };
        let mut delivered = 0usize;
        let mut accepted_full_jid = None;
        let mut mix_supported = 0usize;
        let mut mix_unsupported = 0usize;
        let mut mix_unknown = 0usize;
        let mut control_processed = None;
        let mut control_outcome = None;
        let mut acknowledged_delivery = None;
        let is_muc = json["muc_broadcast"].as_bool().unwrap_or(false);
        let is_muc_presence = json["muc_presence"].as_bool().unwrap_or(false);
        let is_muc_nickname_change = json["muc_nickname_change"].as_bool().unwrap_or(false);
        let is_muc_role_change = json["muc_role_change"].as_bool().unwrap_or(false);
        let is_muc_evict = json["muc_evict"].as_bool().unwrap_or(false);
        let is_muc_destroy = json["muc_destroy"].as_bool().unwrap_or(false);
        let is_muc_operation_wake = json["muc_operation_wake"].as_bool().unwrap_or(false);
        let is_muc_private = json["muc_private"].as_bool().unwrap_or(false);
        let is_sm_muc_teardown = json["sm_muc_teardown"].as_bool().unwrap_or(false);
        let is_sm_session_teardown = json["sm_session_teardown"].as_bool().unwrap_or(false);
        let is_account_generation_teardown = json["account_generation_teardown"]
            .as_bool()
            .unwrap_or(false);
        let is_user_agent_replacement = json["user_agent_replacement"].as_bool().unwrap_or(false);
        let is_session_termination = json["session_termination"].as_bool().unwrap_or(false);
        let is_blocking_presence_change =
            json["blocking_presence_change"].as_bool().unwrap_or(false);
        let is_presence_probe = json["presence_probe"].as_bool().unwrap_or(false);

        if protocol_version >= crate::cluster_security::SIGNED_PROTOCOL_VERSION
            && (is_muc_nickname_change || is_muc_role_change || is_muc_evict || is_muc_destroy)
        {
            // Protocol-v9 MUC controls are wake-only. A signed Redis payload
            // is authenticated transport data, not authorization to execute
            // a mutation; peers must commit/pull the PG operation instead.
            state.cluster.note_authentication_failure(&anyhow::anyhow!(
                "protocol-v9 executable MUC control rejected"
            ));
            continue;
        }

        if is_muc_operation_wake {
            let valid = uuid::Uuid::parse_str(target).is_ok()
                && json["operation_id"]
                    .as_str()
                    .and_then(|value| uuid::Uuid::parse_str(value).ok())
                    .is_some()
                && json["database_event_id"]
                    .as_str()
                    .and_then(|value| uuid::Uuid::parse_str(value).ok())
                    .is_some()
                && json["event_sequence"]
                    .as_i64()
                    .is_some_and(|value| value >= 1);
            if valid {
                // This is deliberately the only side effect of the Redis
                // command. The worker re-reads the operation, exact audience
                // and payload digest from PostgreSQL before delivery.
                state.cluster.notify_muc_outbox_worker();
                control_processed = Some(true);
            }
        } else if is_session_termination {
            let instance = json["connection_id"]
                .as_str()
                .and_then(|value| uuid::Uuid::parse_str(value).ok());
            if let (Ok(target), Some(instance)) =
                (crate::jid::canonical_session_key(target), instance)
            {
                let authority = crate::db::cluster_session_route_authority(
                    &state.pool,
                    &state.cluster.namespace,
                    &target,
                )
                .await?;
                match authority {
                    None => {
                        control_processed = Some(true);
                        control_outcome = Some(ClusterControlOutcome::AuthoritativelyAbsent);
                    }
                    Some(authority) if authority.connection_uuid != instance => {
                        control_processed = Some(true);
                        control_outcome = Some(ClusterControlOutcome::AuthoritativelyAbsent);
                    }
                    Some(authority)
                        if authority.owner_node_id != state.cluster.node_id
                            || authority.owner_instance_uuid != state.cluster.connection_uuid
                            || authority.owner_instance_epoch
                                != state.cluster.instance_epoch.load(Ordering::Acquire) =>
                    {
                        control_processed = Some(false);
                        control_outcome = Some(ClusterControlOutcome::WrongOwner);
                    }
                    Some(_) => {
                        let matched = state.sessions.get_mut(&target).is_some_and(|session| {
                            if session_instance_control_revokes(session.connection_id, instance) {
                                session.routable.store(false, Ordering::Release);
                                session.disconnect.cancel();
                                true
                            } else {
                                false
                            }
                        });
                        control_processed = Some(matched);
                        control_outcome = Some(if matched {
                            delivered = 1;
                            ClusterControlOutcome::Matched
                        } else {
                            ClusterControlOutcome::WrongOwner
                        });
                    }
                }
            }
        } else if is_user_agent_replacement {
            let parsed = crate::jid::canonicalize_bare(target)
                .ok()
                .zip(
                    json["user_id"]
                        .as_str()
                        .and_then(|value| uuid::Uuid::parse_str(value).ok()),
                )
                .zip(
                    json["device_id"]
                        .as_str()
                        .and_then(|value| uuid::Uuid::parse_str(value).ok()),
                );
            let epoch = json["minimum_epoch"].as_i64().filter(|value| *value > 0);
            if let (Some(((account, user_id), device_id)), Some(epoch)) = (parsed, epoch) {
                for (_, session) in state.session_entries_for(&account) {
                    if user_agent_control_revokes(
                        session.user_id,
                        session.user_agent_id,
                        session.user_agent_epoch,
                        user_id,
                        device_id,
                        epoch,
                    ) {
                        session.disconnect.cancel();
                        delivered += 1;
                    }
                }
                control_processed = Some(true);
            }
        } else if is_account_generation_teardown {
            let parsed = crate::jid::canonicalize_bare(target).ok().zip(
                json["user_id"]
                    .as_str()
                    .and_then(|value| uuid::Uuid::parse_str(value).ok()),
            );
            let generation = json["minimum_generation"]
                .as_i64()
                .filter(|value| *value >= 0);
            if let (Some((account, user_id)), Some(generation)) = (parsed, generation) {
                delivered += state.revoke_local_account_routes(user_id, &account, Some(generation));
                control_processed = Some(true);
            }
        } else if is_sm_session_teardown {
            if let Some(sm_session_id) = json["sm_session_id"]
                .as_str()
                .and_then(|value| uuid::Uuid::parse_str(value).ok())
            {
                if let Ok(target) = crate::jid::canonical_session_key(target) {
                    if let Some(session) = state.sessions.get_mut(&target) {
                        let matches = *session
                            .sm_session_id
                            .read()
                            .unwrap_or_else(|poisoned| poisoned.into_inner())
                            == Some(sm_session_id);
                        if matches {
                            session.routable.store(false, Ordering::Release);
                            session.disconnect.cancel();
                            delivered = 1;
                        }
                    }
                    control_processed = Some(true);
                }
            }
        } else if is_presence_probe {
            if json["protocol_version"].as_str() != Some(NODE_PROTOCOL_VERSION) {
                state.cluster.note_incompatible_peer_version(
                    &source_node,
                    json["protocol_version"].as_str(),
                );
                continue;
            }
            let owner = crate::jid::canonicalize(target).ok();
            let recipient = json["recipient"]
                .as_str()
                .and_then(|recipient| crate::jid::canonicalize(recipient).ok());
            let availability_only = json["availability_only"].as_bool().unwrap_or(false);
            let authority = match presence_authority(&json) {
                Ok(Some(authority)) => Some(authority),
                Ok(None) => {
                    state.cluster.note_authentication_failure(&anyhow::anyhow!(
                        "cluster presence probe omitted versioned account authority"
                    ));
                    continue;
                }
                Err(error) => {
                    state.cluster.note_authentication_failure(&error);
                    continue;
                }
            };
            if let (Some(owner), Some(recipient), Some(authority)) = (owner, recipient, authority) {
                if !state
                    .presence_service()
                    .cluster_authority_is_current(
                        &state.config.domain,
                        &owner,
                        authority.owner_id,
                        authority.owner_auth_generation,
                        &recipient,
                        authority.recipient_id,
                        authority.recipient_auth_generation,
                    )
                    .await
                    .unwrap_or(false)
                {
                    state.cluster.note_authentication_failure(&anyhow::anyhow!(
                        "cluster presence probe account authority is stale or mismatched"
                    ));
                    continue;
                }
                let authoritative_avatar_hash = state
                    .presence_service()
                    .avatar_hash(authority.owner_id)
                    .await
                    .ok();
                let mut responses = Vec::new();
                for (owner_full, session) in state.session_entries_for(&owner) {
                    if session.user_id != authority.owner_id
                        || session.auth_generation != authority.owner_auth_generation
                        || !session.available.load(Ordering::Acquire)
                        || !state
                            .privacy_allows_session(
                                &session,
                                &recipient,
                                crate::db::PrivacyStanzaKind::PresenceOut,
                            )
                            .await
                            .unwrap_or(false)
                    {
                        continue;
                    }
                    let presence = if availability_only {
                        let original_id = session
                            .last_presence
                            .read()
                            .unwrap_or_else(|poisoned| poisoned.into_inner())
                            .clone()
                            .and_then(|presence| {
                                let document = roxmltree::Document::parse(&presence).ok()?;
                                document
                                    .root_element()
                                    .attribute("id")
                                    .filter(|id| {
                                        !id.is_empty()
                                            && id.len() <= 1_024
                                            && !id.chars().any(char::is_control)
                                    })
                                    .map(str::to_owned)
                            });
                        crate::xmpp::xml_builder::XmlElement::namespaced(
                            "presence",
                            "jabber:client",
                        )
                        .attr("from", &owner_full)
                        .attr("to", &recipient)
                        .optional_attr("id", original_id.as_deref())
                        .finish()
                    } else {
                        session
                            .last_presence
                            .read()
                            .unwrap_or_else(|poisoned| poisoned.into_inner())
                            .clone()
                            .map(|presence| {
                                let presence = authoritative_avatar_hash
                                    .as_ref()
                                    .and_then(|hash| {
                                        let document =
                                            roxmltree::Document::parse(&presence).ok()?;
                                        Some(crate::xmpp::xml_util::inject_vcard_avatar_hash(
                                            &presence,
                                            document.root_element(),
                                            hash.as_deref(),
                                        ))
                                    })
                                    .unwrap_or(presence);
                                crate::xmpp::xml_util::set_to(&presence, &recipient)
                            })
                            .unwrap_or_else(|| {
                                crate::xmpp::xml_builder::XmlElement::namespaced(
                                    "presence",
                                    "jabber:client",
                                )
                                .attr("from", &owner_full)
                                .attr("to", &recipient)
                                .finish()
                            })
                    };
                    responses.push(presence);
                }

                let mut processed = true;
                for presence in responses {
                    for (_, recipient_session) in state
                        .session_entries_for(&recipient)
                        .into_iter()
                        .filter(|(_, session)| {
                            session.user_id == authority.recipient_id
                                && session.auth_generation == authority.recipient_auth_generation
                                && session.available.load(Ordering::Acquire)
                        })
                    {
                        if state
                            .privacy_allows_session(
                                &recipient_session,
                                &owner,
                                crate::db::PrivacyStanzaKind::PresenceIn,
                            )
                            .await
                            .unwrap_or(false)
                        {
                            delivered += usize::from(
                                recipient_session.sender.try_send(presence.clone()).is_ok(),
                            );
                        }
                    }
                    match state.cluster.lookup_nodes(&recipient).await {
                        Ok(nodes) => {
                            for node_id in nodes {
                                if node_id == state.cluster.node_id {
                                    continue;
                                }
                                match state
                                    .cluster
                                    .send_to_node_current_presence_replay(
                                        &node_id, &recipient, &presence, authority,
                                    )
                                    .await
                                {
                                    Ok(accepted) => delivered += usize::from(accepted),
                                    Err(error) => {
                                        processed = false;
                                        state
                                            .metrics
                                            .cluster_presence_probe_failures_total
                                            .fetch_add(1, Ordering::Relaxed);
                                        tracing::warn!(?error, %owner, %recipient, %node_id, "cross-node initial-presence response failed");
                                    }
                                }
                            }
                        }
                        Err(error) => {
                            processed = false;
                            state
                                .metrics
                                .cluster_presence_probe_failures_total
                                .fetch_add(1, Ordering::Relaxed);
                            tracing::warn!(?error, %owner, %recipient, "could not resolve cross-node initial-presence recipients");
                        }
                    }
                }
                control_processed = Some(processed);
            }
        } else if is_blocking_presence_change {
            let owner = crate::jid::canonicalize_bare(target).ok();
            let targets = json["blocking_targets"]
                .as_array()
                .filter(|items| items.len() <= northstar_xep_0191::MAX_ITEMS)
                .and_then(|items| {
                    items
                        .iter()
                        .map(|item| {
                            item.as_str()
                                .and_then(|jid| crate::jid::canonicalize(jid).ok())
                        })
                        .collect::<Option<Vec<_>>>()
                });
            let patterns = json["blocking_patterns"]
                .as_array()
                .filter(|items| items.len() <= northstar_xep_0191::MAX_ITEMS)
                .and_then(|items| {
                    items
                        .iter()
                        .map(|item| {
                            item.as_str()
                                .and_then(|jid| crate::jid::canonicalize(jid).ok())
                        })
                        .collect::<Option<Vec<_>>>()
                });
            if let (Some(owner), Some(targets), Some(patterns)) = (owner, targets, patterns) {
                crate::xmpp::protocol::blocking::deliver_blocking_presence_change(
                    &state,
                    &owner,
                    &targets,
                    &patterns,
                    json["available"].as_bool().unwrap_or(false),
                )
                .await;
            }
        } else if is_sm_muc_teardown {
            let parsed = json["sm_session_id"]
                .as_str()
                .and_then(|value| uuid::Uuid::parse_str(value).ok())
                .zip(
                    serde_json::from_value::<crate::state::SerializableMucOccupant>(
                        json["occupant"].clone(),
                    )
                    .ok(),
                );
            if let Some((sm_session_id, occupant)) = parsed {
                let target_matches = crate::jid::canonicalize_bare(target)
                    .ok()
                    .is_some_and(|room| room == occupant.room_jid);
                if target_matches {
                    match state
                        .teardown_suspended_muc_membership(sm_session_id, &occupant)
                        .await
                    {
                        Ok(_) => {
                            delivered = 1;
                            control_processed = Some(true);
                        }
                        Err(error) => {
                            tracing::warn!(?error, %target, "clustered SM MUC teardown failed and will be retried by its DB lease owner")
                        }
                    }
                }
            }
        } else if is_muc_evict {
            if let Ok(occupant) = serde_json::from_value::<crate::state::SerializableMucOccupant>(
                json["occupant"].clone(),
            ) {
                let status = json["status"]
                    .as_u64()
                    .and_then(|value| u16::try_from(value).ok());
                let reason = json["reason"].as_str().filter(|value| value.len() <= 4096);
                let actor_nick = json["actor_nick"].as_str();
                if status.is_some()
                    && occupant.room_jid == target
                    && !occupant.cluster_epoch.is_nil()
                    && !occupant.connection_id.is_nil()
                {
                    let key = crate::xmpp::xml_util::muc_occupant_key(target, &occupant.nick);
                    state.remove_live_muc_membership(&occupant);
                    if let Some((_, removed)) = state.muc_occupants.remove_if(&key, |_, current| {
                        current.full_jid == occupant.full_jid
                            && current.connection_id == occupant.connection_id
                            && current.cluster_epoch == occupant.cluster_epoch
                    }) {
                        let self_presence = crate::xmpp::xml_util::muc_presence_stanza_with_status(
                            &occupant,
                            &removed.full_jid,
                            true,
                            true,
                            false,
                            None,
                            true,
                            status,
                            actor_nick,
                            reason,
                        );
                        delivered += usize::from(
                            state.deliver_to_muc_occupant(&removed, self_presence).await,
                        );
                    }
                    if state.muc_occupants_for(target).is_empty() {
                        let _ = state.cluster.leave_muc(target).await;
                    }
                    control_processed = Some(true);
                }
            }
        } else if is_muc_destroy {
            if let Ok(room) = crate::jid::canonicalize_bare(target) {
                let alternate = json["alternate"]
                    .as_str()
                    .and_then(|jid| crate::jid::canonicalize_bare(jid).ok());
                let reason = json["reason"]
                    .as_str()
                    .filter(|reason| reason.len() <= 4096);
                let identities = serde_json::from_value::<Vec<MucOccupancyIdentity>>(
                    json["occupancies"].clone(),
                )
                .ok()
                .filter(|items| items.len() <= 10_000);
                if let Some(identities) = identities {
                    for identity in identities {
                        if identity.cluster_epoch.is_nil() || identity.connection_id.is_nil() {
                            continue;
                        }
                        let key = crate::xmpp::xml_util::muc_occupant_key(&room, &identity.nick);
                        let removed = state.muc_occupants.remove_if(&key, |_, current| {
                            current.full_jid == identity.full_jid
                                && current.connection_id == identity.connection_id
                                && current.cluster_epoch == identity.cluster_epoch
                        });
                        if let Some((_, occupant)) = removed {
                            let serializable =
                                crate::state::SerializableMucOccupant::from(&occupant);
                            state.remove_live_muc_membership(&serializable);
                            let presence = crate::xmpp::xml_util::muc_destroy_presence(
                                &serializable,
                                alternate.as_deref(),
                                reason,
                            );
                            delivered += usize::from(
                                state.deliver_to_muc_occupant(&occupant, presence).await,
                            );
                        }
                    }
                    control_processed = Some(true);
                }
            }
        } else if is_muc_role_change {
            if let Ok(occupant) = serde_json::from_value::<crate::state::SerializableMucOccupant>(
                json["occupant"].clone(),
            ) {
                if occupant.room_jid == target
                    && !occupant.cluster_epoch.is_nil()
                    && matches!(
                        occupant.role.as_str(),
                        "moderator" | "participant" | "visitor"
                    )
                {
                    let key = crate::xmpp::xml_util::muc_occupant_key(target, &occupant.nick);
                    if let Some(mut local) = state.muc_occupants.get_mut(&key) {
                        if local.cluster_epoch == occupant.cluster_epoch
                            && local.full_jid == occupant.full_jid
                            && local.connection_id == occupant.connection_id
                        {
                            local.role = occupant.role.clone();
                            local.affiliation = occupant.affiliation.clone();
                            local.room_non_anonymous = occupant.room_non_anonymous;
                        }
                    }
                    for (_, session) in state.muc_occupants_for(target) {
                        let self_presence = session.full_jid == occupant.full_jid;
                        let presence = crate::xmpp::xml_util::muc_presence_stanza(
                            &occupant,
                            &session.full_jid,
                            false,
                            self_presence,
                            false,
                            None,
                            occupant.room_non_anonymous
                                || self_presence
                                || session.role == "moderator",
                        );
                        delivered +=
                            usize::from(state.deliver_to_muc_occupant(&session, presence).await);
                    }
                    control_processed = Some(true);
                }
            }
        } else if is_muc_nickname_change {
            if let (Ok(old_occupant), Ok(new_occupant)) = (
                serde_json::from_value::<crate::state::SerializableMucOccupant>(
                    json["old_occupant"].clone(),
                ),
                serde_json::from_value::<crate::state::SerializableMucOccupant>(
                    json["new_occupant"].clone(),
                ),
            ) {
                if old_occupant.cluster_epoch == new_occupant.cluster_epoch
                    && old_occupant.full_jid == new_occupant.full_jid
                    && old_occupant.room_jid == target
                    && new_occupant.room_jid == target
                    && old_occupant.nick != new_occupant.nick
                {
                    let id = json["id"].as_str();
                    for (_, session) in state.muc_occupants_for(target) {
                        let unavailable = crate::xmpp::xml_util::muc_nickname_change_presence(
                            &old_occupant,
                            &crate::state::SerializableMucOccupant::from(&session),
                            &new_occupant.nick,
                            id,
                        );
                        delivered +=
                            usize::from(state.deliver_to_muc_occupant(&session, unavailable).await);
                        let available = crate::xmpp::xml_util::muc_presence_stanza(
                            &new_occupant,
                            &session.full_jid,
                            false,
                            session.full_jid == new_occupant.full_jid,
                            false,
                            id,
                            new_occupant.room_non_anonymous
                                || session.full_jid == new_occupant.full_jid
                                || session.role == "moderator",
                        );
                        delivered +=
                            usize::from(state.deliver_to_muc_occupant(&session, available).await);
                    }
                }
            }
        } else if is_muc_presence {
            if let Ok(occupant) = serde_json::from_value::<crate::state::SerializableMucOccupant>(
                json["occupant"].clone(),
            ) {
                let unavailable = json["unavailable"].as_bool().unwrap_or(false);
                let created = json["created"].as_bool().unwrap_or(false);
                let id = json["id"].as_str();
                let removal_status = json["removal_status"]
                    .as_u64()
                    .and_then(|value| u16::try_from(value).ok());
                let actor_nick = json["actor_nick"].as_str();
                let reason = json["reason"].as_str();
                for (_, session) in state.muc_occupants_for(target) {
                    let disclose = occupant.room_non_anonymous || session.role == "moderator";
                    let self_presence = session.full_jid == occupant.full_jid;
                    let presence = crate::xmpp::xml_util::muc_presence_stanza_with_status(
                        &occupant,
                        &session.full_jid,
                        unavailable,
                        self_presence,
                        created,
                        id,
                        disclose,
                        removal_status,
                        actor_nick,
                        reason,
                    );
                    delivered +=
                        usize::from(state.deliver_to_muc_occupant(&session, presence).await);
                }
            }
        } else if let Some(stanza) = json["stanza"].as_str() {
            let parsed_stanza = roxmltree::Document::parse(stanza).ok();
            let current_presence_replay = json["current_presence_replay"].as_bool() == Some(true);
            let presence_subscription = json["presence_subscription"].as_bool() == Some(true);
            if current_presence_replay && presence_subscription {
                continue;
            }
            // A v9 sender did not carry account-incarnation authority. Detect
            // its subscription stanza from the XML itself instead of trusting
            // the absent boolean marker, otherwise a mixed-version sender
            // could reach the old generic presence fan-out path.
            if parsed_stanza
                .as_ref()
                .is_some_and(is_presence_subscription_stanza)
                && !presence_subscription
            {
                state.cluster.note_incompatible_peer_version(
                    &source_node,
                    json["protocol_version"].as_str(),
                );
                continue;
            }
            if (current_presence_replay || presence_subscription)
                && json["protocol_version"].as_str() != Some(NODE_PROTOCOL_VERSION)
            {
                state.cluster.note_incompatible_peer_version(
                    &source_node,
                    json["protocol_version"].as_str(),
                );
                continue;
            }
            let parsed_presence_authority = match presence_authority(&json) {
                Ok(authority) => authority,
                Err(error) => {
                    state.cluster.note_authentication_failure(&error);
                    continue;
                }
            };
            if current_presence_replay || presence_subscription {
                let Some(authority) = parsed_presence_authority else {
                    state.cluster.note_authentication_failure(&anyhow::anyhow!(
                        "cluster presence delivery omitted versioned account authority"
                    ));
                    continue;
                };
                let Some(document) = parsed_stanza.as_ref() else {
                    continue;
                };
                let root = document.root_element();
                let expected_delivery = if current_presence_replay {
                    ClusterPresenceDelivery::CurrentReplay
                } else {
                    ClusterPresenceDelivery::Subscription
                };
                let endpoints = root
                    .attribute("from")
                    .and_then(|from| crate::jid::canonicalize(from).ok())
                    .zip(
                        root.attribute("to")
                            .and_then(|to| crate::jid::canonicalize(to).ok()),
                    );
                let Some((owner, recipient)) = endpoints else {
                    continue;
                };
                if !presence_delivery_stanza_matches(document, expected_delivery)
                    || crate::jid::canonical_bare_key(&recipient).ok()
                        != crate::jid::canonical_bare_key(target).ok()
                    || !state
                        .presence_service()
                        .cluster_authority_is_current(
                            &state.config.domain,
                            &owner,
                            authority.owner_id,
                            authority.owner_auth_generation,
                            &recipient,
                            authority.recipient_id,
                            authority.recipient_auth_generation,
                        )
                        .await
                        .unwrap_or(false)
                {
                    state.cluster.note_authentication_failure(&anyhow::anyhow!(
                        "cluster presence delivery account authority is stale or mismatched"
                    ));
                    continue;
                }
            } else if parsed_presence_authority.is_some() {
                state.cluster.note_authentication_failure(&anyhow::anyhow!(
                    "ordinary cluster delivery carried executable presence authority"
                ));
                continue;
            }
            let is_message_stanza = parsed_stanza
                .as_ref()
                .is_some_and(|document| document.root_element().tag_name().name() == "message");
            let (resolved_message_delivery, direct_delivery_contract_valid) = if !is_muc
                && !is_muc_private
            {
                match requested_node_message_delivery(&json, is_message_stanza) {
                    Ok(Some(request)) => {
                        match resolve_node_message_delivery(&state.pool, request, stanza, target)
                            .await
                        {
                            Ok(resolved) => {
                                acknowledged_delivery = Some(resolved.contract());
                                (Some(resolved), true)
                            }
                            Err(error) => {
                                tracing::warn!(
                                    ?error,
                                    target,
                                    "rejected an unverified clustered message delivery contract"
                                );
                                (None, false)
                            }
                        }
                    }
                    Ok(None) => (None, true),
                    Err(error) => {
                        tracing::warn!(
                            ?error,
                            target,
                            "rejected an invalid clustered message delivery contract"
                        );
                        (None, false)
                    }
                }
            } else {
                (None, true)
            };
            let carbons_only = json["carbons_only"].as_bool().unwrap_or(false);
            let privacy_peer_kind = parsed_stanza
                .as_ref()
                .and_then(|document| delivery_privacy_peer(document, carbons_only));
            // Both Carbon directions deliberately use a self-addressed outer
            // wrapper. If the exact forwarded conversation peer cannot be
            // recovered, an unfiltered fallback would bypass the resource's
            // active XEP-0016 list.
            if carbons_only && privacy_peer_kind.is_none() {
                continue;
            }
            let mut muc_senders = roxmltree::Document::parse(stanza)
                .ok()
                .and_then(|document| document.root_element().attribute("from").map(str::to_owned))
                .into_iter()
                .collect::<Vec<_>>();
            if let Some(real_sender) = json["real_sender"]
                .as_str()
                .and_then(|sender| crate::jid::canonicalize(sender).ok())
            {
                muc_senders.push(real_sender);
            }
            if is_muc_private {
                if let Some(nick) = json["target_nick"].as_str() {
                    let key = crate::xmpp::xml_util::muc_occupant_key(target, nick);
                    if let Some(session) = state
                        .muc_occupants
                        .get(&key)
                        .map(|entry| entry.value().clone())
                    {
                        let delivery = crate::xmpp::xml_util::set_to(stanza, &session.full_jid);
                        let blocked = state
                            .blocked_muc_recipient_accounts(
                                std::slice::from_ref(&session),
                                &muc_senders,
                            )
                            .await;
                        if !crate::jid::canonical_bare_key(&session.full_jid)
                            .is_ok_and(|owner| blocked.contains(&owner))
                        {
                            delivered += usize::from(
                                state
                                    .deliver_to_muc_occupant_unchecked(&session, delivery)
                                    .await,
                            );
                        }
                    }
                }
            } else if is_muc {
                let sessions = state
                    .muc_occupants_for(target)
                    .into_iter()
                    .map(|(_, occupant)| occupant)
                    .collect::<Vec<_>>();
                let blocked = state
                    .blocked_muc_recipient_accounts(&sessions, &muc_senders)
                    .await;
                for session in sessions {
                    if crate::jid::canonical_bare_key(&session.full_jid)
                        .is_ok_and(|owner| blocked.contains(&owner))
                    {
                        continue;
                    }
                    let delivery = crate::xmpp::xml_util::set_to(stanza, &session.full_jid);
                    delivered += usize::from(
                        state
                            .deliver_to_muc_occupant_unchecked(&session, delivery)
                            .await,
                    );
                }
            } else {
                let blocklist_requested_only =
                    json["blocklist_requested_only"].as_bool().unwrap_or(false);
                let roster_requested_only =
                    json["roster_requested_only"].as_bool().unwrap_or(false);
                let expected_user_id = match json.get("expected_user_id") {
                    None | Some(serde_json::Value::Null) => None,
                    Some(serde_json::Value::String(value)) => {
                        let Ok(value) = uuid::Uuid::parse_str(value) else {
                            continue;
                        };
                        Some(value)
                    }
                    Some(_) => continue,
                };
                let expected_auth_generation = match json.get("expected_auth_generation") {
                    None | Some(serde_json::Value::Null) => None,
                    Some(value) => value.as_i64().filter(|value| *value >= 0),
                };
                if json
                    .get("expected_auth_generation")
                    .is_some_and(|value| !value.is_null() && expected_auth_generation.is_none())
                {
                    continue;
                }
                if let Some(authority) = parsed_presence_authority {
                    if expected_user_id != Some(authority.recipient_id)
                        || expected_auth_generation != Some(authority.recipient_auth_generation)
                    {
                        continue;
                    }
                }
                let roster_version = match json.get("roster_version") {
                    None | Some(serde_json::Value::Null) => None,
                    Some(value) => value.as_i64(),
                };
                let roster_annotated_stanza = match json.get("roster_annotated_stanza") {
                    None | Some(serde_json::Value::Null) => None,
                    Some(serde_json::Value::String(value))
                        if value.len() <= crate::xmpp::MAX_XMPP_FRAME_BYTES
                            && roxmltree::Document::parse(value).is_ok() =>
                    {
                        Some(value.as_str())
                    }
                    Some(_) => continue,
                };
                if roster_requested_only && (expected_user_id.is_none() || roster_version.is_none())
                {
                    continue;
                }
                if roster_requested_only {
                    let Some(roster_version) = roster_version else {
                        continue;
                    };
                    if cluster_roster_push_version(stanza) != Some(roster_version)
                        || roster_annotated_stanza.is_some_and(|value| {
                            cluster_roster_push_version(value) != Some(roster_version)
                        })
                    {
                        continue;
                    }
                }
                if !roster_requested_only
                    && (roster_version.is_some() || roster_annotated_stanza.is_some())
                {
                    continue;
                }
                let privacy_requested_only =
                    json["privacy_requested_only"].as_bool().unwrap_or(false);
                let mix_capable_only = match json.get("mix_capable_only") {
                    None => false,
                    Some(serde_json::Value::Bool(value)) => *value,
                    Some(_) => continue,
                };
                let transport_receipt_required = match json.get("transport_receipt_required") {
                    None => false,
                    Some(serde_json::Value::Bool(value)) => *value,
                    Some(_) => continue,
                };
                let exclude_jids = delivery_exclusions(&json);
                let Ok(carbon_muc_scope) = delivery_carbon_muc_scope(&json) else {
                    continue;
                };
                let primary_one_to_one = json["primary_one_to_one"].as_bool().unwrap_or(false);
                let available_only = json["available_only"].as_bool().unwrap_or(false);
                let available_nonnegative_only = json["available_nonnegative_only"]
                    .as_bool()
                    .unwrap_or(false);
                let transport_receipt_stanza_valid =
                    parsed_stanza.as_ref().is_some_and(|document| {
                        let root = document.root_element();
                        root.tag_name().name() == "iq"
                            && root.tag_name().namespace() == Some("jabber:client")
                            && matches!(root.attribute("type"), Some("result" | "error"))
                            && root.attribute("id").is_some_and(|id| !id.is_empty())
                            && root.attribute("to").is_some_and(|to| {
                                matches!(
                                    (
                                        crate::jid::canonical_session_key(to),
                                        crate::jid::canonical_session_key(target),
                                    ),
                                    (Ok(addressed), Ok(expected)) if addressed == expected
                                )
                            })
                    });
                if transport_receipt_required
                    && (is_message_stanza
                        || expected_user_id.is_none()
                        || !target.contains('/')
                        || carbons_only
                        || blocklist_requested_only
                        || roster_requested_only
                        || privacy_requested_only
                        || mix_capable_only
                        || primary_one_to_one
                        || available_only
                        || available_nonnegative_only
                        || !exclude_jids.is_empty()
                        || carbon_muc_scope.is_some()
                        || !transport_receipt_stanza_valid)
                {
                    continue;
                }
                let mut targets = state.session_entries_for(target);
                if (primary_one_to_one || available_only || available_nonnegative_only)
                    && !target.contains('/')
                {
                    targets.retain(|(_, session)| {
                        session.available.load(Ordering::Relaxed)
                            && (!available_nonnegative_only
                                || session.priority.load(Ordering::Relaxed) >= 0)
                    });
                }
                if primary_one_to_one && !target.contains('/') {
                    targets.sort_by(|(left_jid, left), (right_jid, right)| {
                        right
                            .priority
                            .load(Ordering::Relaxed)
                            .cmp(&left.priority.load(Ordering::Relaxed))
                            .then_with(|| left_jid.cmp(right_jid))
                    });
                }
                for (jid, session) in targets {
                    if !direct_delivery_contract_valid
                        || (is_message_stanza && resolved_message_delivery.is_none())
                    {
                        break;
                    }
                    if exclude_jids.contains(&jid)
                        || !delivery_user_identity_matches(
                            expected_user_id,
                            expected_auth_generation,
                            session.user_id,
                            session.auth_generation,
                        )
                        || (carbons_only
                            && !session.carbons.load(std::sync::atomic::Ordering::Acquire))
                        || (blocklist_requested_only
                            && !session.blocklist_requested.load(Ordering::Acquire))
                        || (roster_requested_only
                            && !session.roster_requested.load(Ordering::Acquire))
                        || (privacy_requested_only
                            && !session.privacy_requested.load(Ordering::Acquire))
                        || carbon_muc_scope.as_ref().is_some_and(|(room, nick)| {
                            session
                                .muc_memberships
                                .get(room)
                                .is_none_or(|membership| membership.nick != *nick)
                        })
                    {
                        continue;
                    }
                    if !blocklist_requested_only
                        && !roster_requested_only
                        && !privacy_requested_only
                    {
                        if let Some((peer, kind)) = privacy_peer_kind.as_ref() {
                            match state.privacy_allows_session(&session, peer, *kind).await {
                                Ok(true) => {}
                                Ok(false) => continue,
                                Err(error) => {
                                    // Delivery policy reads are fail closed.
                                    // A database outage must never turn a deny
                                    // list into an allow list on another node.
                                    tracing::warn!(?error, %jid, "privacy policy lookup failed during clustered delivery");
                                    continue;
                                }
                            }
                        }
                    }
                    if mix_capable_only {
                        match crate::xmpp::protocol::mix::session_mix_capability(&state, &jid) {
                            crate::xmpp::protocol::mix::MixSessionCapability::Supported => {
                                mix_supported = mix_supported.saturating_add(1);
                            }
                            crate::xmpp::protocol::mix::MixSessionCapability::Unsupported => {
                                mix_unsupported = mix_unsupported.saturating_add(1);
                                continue;
                            }
                            crate::xmpp::protocol::mix::MixSessionCapability::Unknown => {
                                mix_unknown = mix_unknown.saturating_add(1);
                                continue;
                            }
                        }
                    }
                    let delivery = if blocklist_requested_only
                        || roster_requested_only
                        || privacy_requested_only
                    {
                        crate::xmpp::xml_util::set_to(stanza, &jid)
                    } else {
                        node_delivery_stanza(stanza, carbons_only, &jid)
                    };
                    let durable_delivery = if is_message_stanza {
                        match resolved_message_delivery {
                            Some(ResolvedNodeMessageDelivery::Volatile) => None,
                            Some(ResolvedNodeMessageDelivery::Durable(durable))
                                if durable.recipient_id == session.user_id =>
                            {
                                Some(durable)
                            }
                            Some(ResolvedNodeMessageDelivery::Durable(_)) | None => continue,
                        }
                    } else {
                        None
                    };
                    let accepted = if roster_requested_only {
                        let version = roster_version
                            .expect("cluster roster shape validated before session fanout");
                        let annotated = roster_annotated_stanza
                            .map(|stanza| crate::xmpp::xml_util::set_to(stanza, &jid));
                        match session.roster_sync.route(
                            &session.roster_requested,
                            &session.mix_roster_annotations,
                            version,
                            delivery.clone(),
                            annotated,
                        ) {
                            northstar_roster_application::RosterPushDisposition::NotInterested => {
                                false
                            }
                            northstar_roster_application::RosterPushDisposition::Buffered => true,
                            northstar_roster_application::RosterPushDisposition::Deliver(
                                stanza,
                            ) => {
                                if session.sender.try_send(stanza).is_ok() {
                                    true
                                } else {
                                    session.sender.disconnect_backpressured_transport();
                                    session.disconnect.cancel();
                                    false
                                }
                            }
                            northstar_roster_application::RosterPushDisposition::Overflow => {
                                session.sender.disconnect_backpressured_transport();
                                session.disconnect.cancel();
                                false
                            }
                        }
                    } else if transport_receipt_required {
                        let (receipt_tx, mut receipt_rx) = tokio::sync::mpsc::unbounded_channel();
                        match session
                            .sender
                            .try_send_with_transport_receipt(delivery.clone(), receipt_tx)
                        {
                            Ok(()) => match tokio::time::timeout(
                                Duration::from_millis(500),
                                receipt_rx.recv(),
                            )
                            .await
                            {
                                Ok(Some(())) => true,
                                Ok(None) => false,
                                Err(_) => {
                                    session.sender.disconnect_backpressured_transport();
                                    session.disconnect.cancel();
                                    false
                                }
                            },
                            Err(_) => {
                                session.sender.disconnect_backpressured_transport();
                                session.disconnect.cancel();
                                false
                            }
                        }
                    } else if let Some(durable) = durable_delivery {
                        session
                            .sender
                            .try_send_durable(delivery.clone(), durable)
                            .is_ok()
                    } else {
                        session.sender.try_send(delivery.clone()).is_ok()
                    };
                    if accepted {
                        if is_message_stanza {
                            let counter = if durable_delivery.is_some() {
                                &state.metrics.online_queue_durable_acceptances_total
                            } else {
                                &state.metrics.online_queue_volatile_acceptances_total
                            };
                            counter.fetch_add(1, Ordering::Relaxed);
                        }
                        delivered += 1;
                        accepted_full_jid.get_or_insert(jid);
                        if primary_one_to_one {
                            break;
                        }
                    }
                }
            }
        }

        if let Some(request_id) = json["request_id"].as_str() {
            if uuid::Uuid::parse_str(request_id).is_err() {
                continue;
            }
            if let Some(pool) = &state.cluster.pool {
                let mut conn = pool.get().await?;
                let ack_channel = state.cluster.key(format!("node:{source_node}"));
                if let Some(nonce) = json["ack_nonce"]
                    .as_str()
                    .filter(|nonce| (32..=128).contains(&nonce.len()))
                {
                    let ack = NodeDeliveryAck {
                        request_id: request_id.to_owned(),
                        nonce: nonce.to_owned(),
                        node_id: state.cluster.node_id.clone(),
                        delivered,
                        accepted_full_jid,
                        mix_supported,
                        mix_unsupported,
                        mix_unknown,
                        control_processed,
                        control_outcome,
                        delivery: acknowledged_delivery,
                    };
                    let ack_payload = serde_json::to_value(&ack)?;
                    let _ = state
                        .cluster
                        .publish_signed(&mut conn, &source_node, &ack_channel, ack_payload)
                        .await?;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn pending_ack_registration_is_bounded_and_cancel_safe() {
        let cluster = ClusterManager::new(None, "example.test", None, None, None, None)
            .await
            .unwrap();
        let mut registrations = Vec::with_capacity(MAX_PENDING_CLUSTER_ACKS);
        for index in 0..MAX_PENDING_CLUSTER_ACKS {
            registrations.push(
                cluster
                    .register_pending_ack(
                        &uuid::Uuid::from_u128(index as u128 + 1).to_string(),
                        "node-b",
                        "bounded-nonce",
                    )
                    .unwrap(),
            );
        }
        assert_eq!(cluster.pending_acks.len(), MAX_PENDING_CLUSTER_ACKS);
        assert!(cluster
            .register_pending_ack(
                &uuid::Uuid::from_u128(MAX_PENDING_CLUSTER_ACKS as u128 + 1).to_string(),
                "node-b",
                "overflow-nonce",
            )
            .is_err());
        drop(registrations);
        assert!(cluster.pending_acks.is_empty());
    }

    #[test]
    fn muc_soft_state_lease_survives_multiple_refresh_and_node_lease_windows() {
        const {
            assert!(
                MUC_SOFT_STATE_TTL_SECONDS >= CLUSTER_MAINTENANCE_INTERVAL_SECONDS * 8,
                "a live room needs several maintenance retries before its soft-state expires"
            );
            assert!(
                MUC_SOFT_STATE_TTL_SECONDS >= NODE_TTL_SECONDS * 3,
                "room cleanup must not race a single missed node-heartbeat window"
            );
        }
    }

    #[test]
    fn delayed_session_instance_termination_does_not_revoke_a_new_bind() {
        let old_connection = uuid::Uuid::new_v4();
        let rebound_connection = uuid::Uuid::new_v4();
        assert!(session_instance_control_revokes(
            old_connection,
            old_connection
        ));
        assert!(!session_instance_control_revokes(
            rebound_connection,
            old_connection
        ));
        assert!(!session_instance_control_revokes(
            rebound_connection,
            uuid::Uuid::nil()
        ));
    }

    fn verification_manager(
        namespace: &str,
        security: Arc<crate::cluster_security::ClusterSecurityConfig>,
    ) -> ClusterManager {
        ClusterManager {
            node_id: security.node_id.clone(),
            namespace: namespace.into(),
            key_prefix: format!("northstar:{namespace}"),
            pool: None,
            client: None,
            security: Some(security),
            connection_uuid: uuid::Uuid::new_v4(),
            instance_epoch: Arc::new(AtomicI64::new(1)),
            authorized_instances: Arc::new(dashmap::DashMap::new()),
            authorized_peer_keys: Arc::new(dashmap::DashMap::new()),
            replay_cache: Arc::new(dashmap::DashMap::new()),
            replay_cache_gate: Arc::new(Mutex::new(())),
            replay_cache_next_expiry: Arc::new(AtomicI64::new(i64::MAX)),
            replay_cache_sweeps: Arc::new(AtomicU64::new(0)),
            authority_pool: Arc::new(std::sync::OnceLock::new()),
            health: Arc::new(ClusterHealth::disabled()),
            publication_gate: Arc::new(tokio::sync::RwLock::new(())),
            muc_outbox_notify: Arc::new(tokio::sync::Notify::new()),
            listener_rotation: Arc::new(tokio::sync::Notify::new()),
            pending_ack_slots: Arc::new(tokio::sync::Semaphore::new(MAX_PENDING_CLUSTER_ACKS)),
            pending_acks: Arc::new(dashmap::DashMap::new()),
        }
    }

    #[test]
    fn replay_cache_capacity_admission_is_linearizable() {
        let namespace = "example.test";
        let (_, receiver_security) = crate::cluster_security::test_configuration_pair(namespace);
        let manager = verification_manager(namespace, receiver_security);
        let workers = 64;
        let limit = 16;
        let barrier = Arc::new(std::sync::Barrier::new(workers));
        let accepted = std::thread::scope(|scope| {
            let mut handles = Vec::with_capacity(workers);
            for index in 0..workers {
                let barrier = Arc::clone(&barrier);
                let manager = &manager;
                handles.push(scope.spawn(move || {
                    barrier.wait();
                    manager
                        .remember_replay_key(
                            format!("peer:epoch:connection:{index}"),
                            200,
                            100,
                            limit,
                        )
                        .is_ok()
                }));
            }
            handles
                .into_iter()
                .map(|handle| handle.join().expect("replay admission worker"))
                .filter(|accepted| *accepted)
                .count()
        });

        assert_eq!(accepted, limit);
        assert_eq!(manager.replay_cache.len(), limit);
    }

    #[test]
    fn full_replay_cache_without_expiry_rejects_in_constant_time_path() {
        let namespace = "example.test";
        let (_, receiver_security) = crate::cluster_security::test_configuration_pair(namespace);
        let manager = verification_manager(namespace, receiver_security);
        manager
            .remember_replay_key("resident".to_owned(), 200, 100, 1)
            .expect("resident replay identity admitted");

        for index in 0..128 {
            assert!(manager
                .remember_replay_key(format!("rejected-{index}"), 300, 100, 1)
                .is_err());
        }
        assert_eq!(manager.replay_cache_sweeps.load(Ordering::Relaxed), 0);

        manager
            .remember_replay_key("replacement".to_owned(), 300, 201, 1)
            .expect("the first request after expiry performs one reclamation");
        assert_eq!(manager.replay_cache_sweeps.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn replay_cache_preserves_the_clock_skew_boundary_and_reclaims_after_it() {
        let namespace = "example.test";
        let (_, receiver_security) = crate::cluster_security::test_configuration_pair(namespace);
        let manager = verification_manager(namespace, receiver_security);

        manager
            .remember_replay_key("first".to_owned(), 105, 100, 1)
            .expect("first replay identity admitted");
        assert!(manager
            .remember_replay_key("first".to_owned(), 105, 100, 1)
            .is_err());
        assert!(manager
            .remember_replay_key("second".to_owned(), 200, 105, 1)
            .is_err());
        manager
            .remember_replay_key("second".to_owned(), 200, 106, 1)
            .expect("entry is reclaimable only after its final skew-valid second");
        assert!(!manager.replay_cache.contains_key("first"));
        assert!(manager.replay_cache.contains_key("second"));
    }

    #[test]
    fn exact_signed_envelope_is_accepted_once_for_the_authoritative_instance() {
        let namespace = "example.test";
        let (sender_security, receiver_security) =
            crate::cluster_security::test_configuration_pair(namespace);
        let receiver = verification_manager(namespace, receiver_security);
        let instance_uuid = uuid::Uuid::new_v4();
        let now = Instant::now();
        receiver.authorized_instances.insert(
            sender_security.node_id.clone(),
            AuthorizedClusterInstance {
                instance_uuid,
                instance_epoch: 7,
                signing_key_id: sender_security.current_key_id.clone(),
                signing_key_epoch: sender_security.key_epoch,
                valid_until: now + Duration::from_secs(30),
                refresh_until: now + Duration::from_secs(10),
            },
        );
        receiver.authorized_peer_keys.insert(
            sender_security.node_id.clone(),
            AuthorizedPeerKeys {
                epoch: sender_security.key_epoch,
                current_key_id: sender_security.current_key_id.clone(),
                previous_key_id: None,
                refresh_until: now + Duration::from_secs(10),
            },
        );
        let channel = format!("northstar:{namespace}:node:{}", receiver.node_id);
        let envelope = crate::cluster_security::SignedClusterEnvelope::sign(
            &sender_security.signer(),
            namespace,
            &sender_security.node_id,
            &receiver.node_id,
            receiver.connection_uuid,
            receiver.instance_epoch.load(Ordering::Acquire),
            &receiver.security.as_ref().unwrap().current_key_id,
            receiver.security.as_ref().unwrap().key_epoch,
            &channel,
            crate::cluster_security::ClusterCommandKind::DirectDelivery,
            instance_uuid,
            7,
            serde_json::json!({"target":"alice@example.test","stanza":"<message/>"}),
            chrono::Utc::now().timestamp(),
        )
        .unwrap();
        let encoded = serde_json::to_string(&envelope).unwrap();
        receiver
            .verify_signed_payload(&encoded, &channel, Some(&sender_security.node_id))
            .unwrap();
        assert!(receiver
            .verify_signed_payload(&encoded, &channel, Some(&sender_security.node_id))
            .is_err());
    }

    #[test]
    fn staged_key_cannot_copy_the_current_instance_tuple_before_activation() {
        let namespace = "example.test";
        let (staged_sender, receiver_security, active_key_id) =
            crate::cluster_security::test_prepared_staged_pair(namespace);
        let receiver_peers = receiver_security.peers();
        let receiver = verification_manager(namespace, receiver_security);
        let copied_uuid = uuid::Uuid::new_v4();
        let now = Instant::now();
        receiver.authorized_instances.insert(
            staged_sender.node_id.clone(),
            AuthorizedClusterInstance {
                instance_uuid: copied_uuid,
                instance_epoch: 7,
                signing_key_id: active_key_id.clone(),
                signing_key_epoch: 1,
                valid_until: now + Duration::from_secs(30),
                refresh_until: now + Duration::from_secs(10),
            },
        );
        receiver.authorized_peer_keys.insert(
            staged_sender.node_id.clone(),
            AuthorizedPeerKeys {
                epoch: 1,
                current_key_id: active_key_id,
                previous_key_id: None,
                refresh_until: now + Duration::from_secs(10),
            },
        );
        let channel = format!("northstar:{namespace}:node:{}", receiver.node_id);
        let envelope = crate::cluster_security::SignedClusterEnvelope::sign(
            &staged_sender.signer(),
            namespace,
            &staged_sender.node_id,
            &receiver.node_id,
            receiver.connection_uuid,
            receiver.instance_epoch.load(Ordering::Acquire),
            &receiver.security.as_ref().unwrap().current_key_id,
            receiver.security.as_ref().unwrap().key_epoch,
            &channel,
            crate::cluster_security::ClusterCommandKind::DirectDelivery,
            copied_uuid,
            7,
            serde_json::json!({"target":"alice@example.test","stanza":"<message/>"}),
            chrono::Utc::now().timestamp(),
        )
        .unwrap();
        envelope
            .verify(
                namespace,
                &receiver.node_id,
                &channel,
                Some(&staged_sender.node_id),
                receiver_peers.as_ref(),
                chrono::Utc::now().timestamp(),
            )
            .unwrap();
        // The static peer file can verify the prepared public key for rolling
        // upgrade compatibility, but PostgreSQL has not activated it and the
        // live instance lease is explicitly bound to the old key generation.
        assert!(receiver
            .verify_signed_payload(
                &serde_json::to_string(&envelope).unwrap(),
                &channel,
                Some(&staged_sender.node_id),
            )
            .is_err());
    }

    #[test]
    fn stale_or_wrong_cluster_process_instance_is_rejected() {
        let now = Instant::now();
        let instance_uuid = uuid::Uuid::new_v4();
        let authority = AuthorizedClusterInstance {
            instance_uuid,
            instance_epoch: 9,
            signing_key_id: "current-key".into(),
            signing_key_epoch: 4,
            valid_until: now + Duration::from_secs(30),
            refresh_until: now + Duration::from_secs(10),
        };
        assert!(authoritative_instance_matches(
            &authority,
            instance_uuid,
            9,
            "current-key",
            4,
            now
        ));
        assert!(!authoritative_instance_matches(
            &authority,
            uuid::Uuid::new_v4(),
            9,
            "current-key",
            4,
            now
        ));
        assert!(!authoritative_instance_matches(
            &authority,
            instance_uuid,
            8,
            "current-key",
            4,
            now
        ));
        assert!(!authoritative_instance_matches(
            &authority,
            instance_uuid,
            9,
            "current-key",
            4,
            authority.refresh_until
        ));
        assert!(!authoritative_instance_matches(
            &authority,
            instance_uuid,
            9,
            "previous-key",
            3,
            now
        ));
        assert!(!authoritative_instance_matches(
            &authority,
            instance_uuid,
            9,
            "staged-key",
            5,
            now
        ));
    }

    #[test]
    fn postgres_key_cache_controls_prepare_activate_and_retire_acceptance() {
        let now = Instant::now();
        let prepared = AuthorizedPeerKeys {
            epoch: 4,
            current_key_id: "old".into(),
            previous_key_id: None,
            refresh_until: now + Duration::from_secs(10),
        };
        assert!(prepared.accepts("old", 4, now));
        // A staged key authorizes the future DB activation only. Even if an
        // attacker copies the observable current process UUID/epoch, staged
        // material is not a wire-command authority before activation.
        assert!(!prepared.accepts("next", 5, now));
        assert!(!prepared.accepts("older", 3, now));

        let activated = AuthorizedPeerKeys {
            epoch: 5,
            current_key_id: "next".into(),
            previous_key_id: Some("old".into()),
            refresh_until: now + Duration::from_secs(10),
        };
        assert!(activated.accepts("next", 5, now));
        assert!(activated.accepts("old", 4, now));

        let retired = AuthorizedPeerKeys {
            previous_key_id: None,
            ..activated
        };
        assert!(!retired.accepts("old", 4, now));
        assert!(!retired.accepts("next", 5, retired.refresh_until));
    }

    #[test]
    fn cluster_failure_policy_static_matrix_is_fail_closed_by_class() {
        let operations = [
            ClusterOperation::NewBinding,
            ClusterOperation::Resume,
            ClusterOperation::MucMutation,
            ClusterOperation::AdminMutation,
            ClusterOperation::VolatileDelivery,
            ClusterOperation::DurableDirect,
        ];
        for operation in operations {
            assert!(operation_allowed(CLUSTER_HEALTHY, operation));
            assert!(!operation_allowed(CLUSTER_FAIL_CLOSED, operation));
            assert!(!operation_allowed(CLUSTER_RECONCILING, operation));
            assert!(!operation_allowed(CLUSTER_SHUTDOWN_REQUIRED, operation));
            assert_eq!(
                operation_allowed(CLUSTER_DURABLE_DIRECT_ONLY, operation),
                operation == ClusterOperation::DurableDirect
            );
        }
        use crate::cluster_security::ClusterFailurePolicy::{DurableDirectOnly, FailClosed};
        assert!(!degraded_shutdown_required(FailClosed, true, false));
        assert!(degraded_shutdown_required(FailClosed, true, true));
        assert!(!degraded_shutdown_required(DurableDirectOnly, true, true));
        assert!(degraded_shutdown_required(DurableDirectOnly, false, false));
        assert!(degraded_shutdown_required(FailClosed, false, false));
    }

    #[derive(Clone, Debug, Default)]
    struct NeverConnectManager {
        attempts: Arc<std::sync::atomic::AtomicUsize>,
    }

    impl bb8::ManageConnection for NeverConnectManager {
        type Connection = ();
        type Error = std::io::Error;

        async fn connect(&self) -> std::result::Result<Self::Connection, Self::Error> {
            self.attempts
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            std::future::pending().await
        }

        async fn is_valid(&self, _: &mut Self::Connection) -> std::result::Result<(), Self::Error> {
            Ok(())
        }

        fn has_broken(&self, _: &mut Self::Connection) -> bool {
            false
        }
    }

    #[tokio::test]
    async fn three_failed_cluster_pool_acquisitions_finish_inside_two_seconds() {
        let manager = NeverConnectManager::default();
        let attempts = manager.attempts.clone();
        let pool = cluster_pool_builder().build_unchecked(manager);

        tokio::time::timeout(Duration::from_secs(2), async {
            for _ in 0..3 {
                assert!(matches!(pool.get().await, Err(bb8::RunError::TimedOut)));
            }
        })
        .await
        .expect("three serial Redis pool acquisition failures exceeded two seconds");

        // bb8 coalesces concurrent/serial waiters behind the same in-flight
        // connection attempt. The callers must still receive their own hard
        // deadline instead of waiting for that attempt to finish or retry.
        assert_eq!(attempts.load(std::sync::atomic::Ordering::SeqCst), 1);
    }

    #[test]
    fn carbon_privacy_uses_the_forwarded_conversation_peer() {
        let received = roxmltree::Document::parse(
            "<message from='alice@example.test' to='alice@example.test/Tablet'>\
               <received xmlns='urn:xmpp:carbons:2'>\
                 <forwarded xmlns='urn:xmpp:forward:0'>\
                   <message xmlns='jabber:client' from='blocked@example.net/Phone' to='alice@example.test/Phone'/>\
                 </forwarded>\
               </received>\
             </message>",
        )
        .unwrap();
        assert_eq!(
            delivery_privacy_peer(&received, true),
            Some((
                "blocked@example.net/Phone".to_owned(),
                crate::db::PrivacyStanzaKind::Message,
            ))
        );

        let sent = roxmltree::Document::parse(
            "<message from='alice@example.test'><sent xmlns='urn:xmpp:carbons:2'><forwarded xmlns='urn:xmpp:forward:0'><message xmlns='jabber:client' from='alice@example.test/Phone' to='bob@example.net'/></forwarded></sent></message>",
        )
        .unwrap();
        assert_eq!(
            delivery_privacy_peer(&sent, true),
            Some((
                "bob@example.net".to_owned(),
                crate::db::PrivacyStanzaKind::Message,
            ))
        );

        let malformed_received = roxmltree::Document::parse(
            "<message from='alice@example.test'><received xmlns='urn:xmpp:carbons:2'><forwarded xmlns='urn:xmpp:forward:0'><message xmlns='jabber:client'/></forwarded></received></message>",
        )
        .unwrap();
        assert_eq!(delivery_privacy_peer(&malformed_received, true), None);

        let missing_sent_recipient = roxmltree::Document::parse(
            "<message from='alice@example.test'><sent xmlns='urn:xmpp:carbons:2'><forwarded xmlns='urn:xmpp:forward:0'><message xmlns='jabber:client' from='alice@example.test/Phone'/></forwarded></sent></message>",
        )
        .unwrap();
        assert_eq!(
            delivery_privacy_peer(&missing_sent_recipient, true),
            None,
            "a malformed sent Carbon must not fall back to its self-addressed wrapper"
        );

        let ambiguous = roxmltree::Document::parse(
            "<message from='alice@example.test'><sent xmlns='urn:xmpp:carbons:2'><forwarded xmlns='urn:xmpp:forward:0'><message xmlns='jabber:client' from='alice@example.test/Phone' to='bob@example.net'/></forwarded></sent><received xmlns='urn:xmpp:carbons:2'><forwarded xmlns='urn:xmpp:forward:0'><message xmlns='jabber:client' from='mallory@example.net' to='alice@example.test/Phone'/></forwarded></received></message>",
        )
        .unwrap();
        assert_eq!(delivery_privacy_peer(&ambiguous, true), None);
    }

    fn rename_occupant(epoch: uuid::Uuid, nick: &str) -> crate::state::SerializableMucOccupant {
        crate::state::SerializableMucOccupant {
            full_jid: "alice@example.test/Phone".to_owned(),
            room_jid: "room@conference.example.test".to_owned(),
            nick: nick.to_owned(),
            affiliation: "member".to_owned(),
            role: "participant".to_owned(),
            room_non_anonymous: true,
            occupant_id: "opaque".to_owned(),
            cluster_epoch: epoch,
            connection_id: uuid::Uuid::new_v4(),
            federated_domain: None,
            sm_session_id: None,
            payload: String::new(),
        }
    }

    #[tokio::test]
    async fn single_node_muc_rename_requires_the_exact_non_nil_occupancy_epoch() {
        let cluster = ClusterManager::new(None, "example.test", None, None, None, None)
            .await
            .unwrap();
        let epoch = uuid::Uuid::new_v4();
        let old = rename_occupant(epoch, "Old");
        let mut new = old.clone();
        new.nick = "New".to_owned();
        assert_eq!(
            cluster
                .rename_muc_occupant(
                    &old.room_jid,
                    &old.nick,
                    &new.nick,
                    epoch,
                    &serde_json::to_string(&old).unwrap(),
                    &serde_json::to_string(&new).unwrap(),
                )
                .await
                .unwrap(),
            MucRename::Renamed
        );

        let stale = rename_occupant(uuid::Uuid::new_v4(), "Old");
        assert!(cluster
            .rename_muc_occupant(
                &old.room_jid,
                &old.nick,
                &new.nick,
                epoch,
                &serde_json::to_string(&stale).unwrap(),
                &serde_json::to_string(&new).unwrap(),
            )
            .await
            .is_err());
        let nil_old = rename_occupant(uuid::Uuid::nil(), "Old");
        let nil_new = rename_occupant(uuid::Uuid::nil(), "New");
        assert!(cluster
            .rename_muc_occupant(
                &nil_old.room_jid,
                &nil_old.nick,
                &nil_new.nick,
                uuid::Uuid::nil(),
                &serde_json::to_string(&nil_old).unwrap(),
                &serde_json::to_string(&nil_new).unwrap(),
            )
            .await
            .is_err());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[ignore = "requires TEST_REDIS_URL; uses and removes a unique key namespace"]
    async fn redis_muc_nickname_and_voice_mutations_reject_conflicts_and_aba() {
        let redis_url = std::env::var("TEST_REDIS_URL")
            .expect("set TEST_REDIS_URL to a disposable Redis instance");
        let namespace = format!("muc-{}.test", uuid::Uuid::new_v4().simple());
        let (first_security, second_security) =
            crate::cluster_security::test_configuration_pair(&namespace);
        let first = ClusterManager::new(
            Some(&redis_url),
            &namespace,
            None,
            None,
            None,
            Some(first_security),
        )
        .await
        .unwrap();
        let second = ClusterManager::new(
            Some(&redis_url),
            &namespace,
            None,
            None,
            None,
            Some(second_security),
        )
        .await
        .unwrap();
        for cluster in [&first, &second] {
            cluster.install_instance_epoch(1).unwrap();
            cluster.touch_node().await.unwrap();
            cluster.note_listener_generation();
        }
        let room = "room@conference.example.test";
        let original_epoch = uuid::Uuid::new_v4();
        let original = rename_occupant(original_epoch, "Old");
        let original_json = serde_json::to_string(&original).unwrap();
        assert_eq!(
            first
                .try_register_muc_occupant(room, "Old", &original_json, 100)
                .await
                .unwrap(),
            MucRegistration::Joined
        );
        assert_eq!(
            first
                .try_register_muc_occupant(room, "Old", &original_json, 100)
                .await
                .unwrap(),
            MucRegistration::Joined,
            "an exact registration retry must be idempotent and renew its lease"
        );
        {
            let mut connection = first.pool.as_ref().unwrap().get().await.unwrap();
            for key in [
                first.key(format!("muc_occupants:{room}")),
                first.key(format!("muc_occupant_nodes:{room}")),
                first.key(format!("muc_nodes:{room}")),
                first.key(format!("muc_occupant_instances:{room}")),
                first.key(format!("muc_node_counts:{room}")),
            ] {
                let ttl: i64 = connection.ttl(key).await.unwrap();
                assert!((1..=MUC_SOFT_STATE_TTL_SECONDS as i64).contains(&ttl));
            }
        }

        let occupied = rename_occupant(uuid::Uuid::new_v4(), "Taken");
        assert_eq!(
            second
                .try_register_muc_occupant(
                    room,
                    "Taken",
                    &serde_json::to_string(&occupied).unwrap(),
                    100,
                )
                .await
                .unwrap(),
            MucRegistration::Joined
        );
        {
            let Some(pool) = &first.pool else {
                panic!("Redis-backed cluster expected");
            };
            let mut connection = pool.get().await.unwrap();
            let occupants_key = first.key(format!("muc_occupants:{room}"));
            let owners_key = first.key(format!("muc_occupant_nodes:{room}"));
            let nodes_key = first.key(format!("muc_nodes:{room}"));
            let _: usize = connection
                .hset(&occupants_key, "Ghost", "{}")
                .await
                .unwrap();
            let _: usize = connection
                .hset(&owners_key, "Ghost", "crashed-node")
                .await
                .unwrap();
            let _: usize = connection.sadd(&nodes_key, "crashed-node").await.unwrap();
            drop(connection);
            let visible = first.get_muc_occupants(room).await.unwrap();
            assert!(!visible.contains_key("Ghost"));
            let mut connection = pool.get().await.unwrap();
            let nodes: Vec<String> = connection.smembers(nodes_key).await.unwrap();
            assert!(!nodes.iter().any(|node| node == "crashed-node"));
        }
        let mut conflicting = original.clone();
        conflicting.nick = "Taken".to_owned();
        assert_eq!(
            first
                .rename_muc_occupant(
                    room,
                    "Old",
                    "Taken",
                    original_epoch,
                    &original_json,
                    &serde_json::to_string(&conflicting).unwrap(),
                )
                .await
                .unwrap(),
            MucRename::Conflict
        );
        assert!(first
            .get_muc_occupants(room)
            .await
            .unwrap()
            .contains_key("Old"));

        assert!(first
            .unregister_muc_occupant_epoch(room, "Old", original_epoch, original.connection_id,)
            .await
            .unwrap());
        let replacement_epoch = uuid::Uuid::new_v4();
        let replacement = rename_occupant(replacement_epoch, "Old");
        let replacement_json = serde_json::to_string(&replacement).unwrap();
        assert_eq!(
            first
                .try_register_muc_occupant(room, "Old", &replacement_json, 100)
                .await
                .unwrap(),
            MucRegistration::Joined
        );
        let mut delayed_target = original.clone();
        delayed_target.nick = "Late".to_owned();
        assert_eq!(
            first
                .rename_muc_occupant(
                    room,
                    "Old",
                    "Late",
                    original_epoch,
                    &original_json,
                    &serde_json::to_string(&delayed_target).unwrap(),
                )
                .await
                .unwrap(),
            MucRename::Stale
        );
        assert_eq!(
            first.get_muc_occupants(room).await.unwrap().get("Old"),
            Some(&replacement_json)
        );
        assert!(!first
            .unregister_muc_occupant_epoch(room, "Old", original_epoch, original.connection_id,)
            .await
            .unwrap());
        assert!(!first
            .evict_muc_occupant(&original, 307, Some("Moderator"), Some("delayed"))
            .await
            .unwrap());
        assert_eq!(
            first.get_muc_occupants(room).await.unwrap().get("Old"),
            Some(&replacement_json)
        );
        assert!(matches!(
            first
                .change_muc_occupant_role(room, &original, "participant")
                .await
                .unwrap(),
            MucRoleChange::Stale
        ));
        let changed = first
            .change_muc_occupant_role(room, &replacement, "visitor")
            .await
            .unwrap();
        assert!(matches!(
            changed,
            MucRoleChange::Changed(ref occupant) if occupant.role == "visitor"
        ));
        let changed = match changed {
            MucRoleChange::Changed(occupant) => occupant,
            MucRoleChange::Stale => unreachable!(),
        };
        let policy_changed = first
            .change_muc_occupant_policy(room, &changed, "participant", true)
            .await
            .unwrap();
        assert!(matches!(
            policy_changed,
            MucRoleChange::Changed(ref occupant)
                if occupant.role == "participant" && occupant.room_non_anonymous
        ));
        let persisted: crate::state::SerializableMucOccupant = serde_json::from_str(
            first
                .get_muc_occupants(room)
                .await
                .unwrap()
                .get("Old")
                .unwrap(),
        )
        .unwrap();
        assert_eq!(persisted.role, "participant");
        assert!(persisted.room_non_anonymous);
        assert!(matches!(
            first
                .change_muc_occupant_policy(room, &replacement, "visitor", false)
                .await
                .unwrap(),
            MucRoleChange::Stale
        ));

        assert!(first
            .unregister_muc_occupant_epoch(
                room,
                "Old",
                replacement_epoch,
                replacement.connection_id,
            )
            .await
            .unwrap());
        assert!(second
            .unregister_muc_occupant_epoch(
                room,
                "Taken",
                occupied.cluster_epoch,
                occupied.connection_id,
            )
            .await
            .unwrap());
        assert!(first.get_muc_occupants(room).await.unwrap().is_empty());

        let Some(pool) = &first.pool else {
            panic!("Redis-backed cluster expected");
        };
        let mut connection = pool.get().await.unwrap();
        for key in [
            first.key(format!("muc_occupants:{room}")),
            first.key(format!("muc_occupant_nodes:{room}")),
            first.key(format!("muc_nodes:{room}")),
            first.key(format!("muc_occupant_instances:{room}")),
            first.key(format!("muc_node_counts:{room}")),
        ] {
            let exists: bool = connection.exists(key).await.unwrap();
            assert!(!exists, "last occupant cleanup left a room soft-state key");
        }
        let prefix = format!("{}*", first.key_prefix);
        let keys: Vec<String> = redis::cmd("KEYS")
            .arg(prefix)
            .query_async(&mut *connection)
            .await
            .unwrap();
        if !keys.is_empty() {
            let _: usize = redis::cmd("DEL")
                .arg(&keys)
                .query_async(&mut *connection)
                .await
                .unwrap();
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    #[ignore = "requires TEST_REDIS_URL; exercises 10,000 disposable MUC room lifecycles"]
    async fn redis_ten_thousand_temporary_muc_rooms_leave_no_soft_state_keys() {
        use futures::StreamExt as _;

        let redis_url = std::env::var("TEST_REDIS_URL")
            .expect("set TEST_REDIS_URL to a disposable Redis instance");
        let namespace = format!("muc-churn-{}.test", uuid::Uuid::new_v4().simple());
        let (security, _) = crate::cluster_security::test_configuration_pair(&namespace);
        let cluster = ClusterManager::new(
            Some(&redis_url),
            &namespace,
            None,
            None,
            None,
            Some(security),
        )
        .await
        .unwrap();
        cluster.install_instance_epoch(1).unwrap();
        cluster.touch_node().await.unwrap();
        cluster.note_listener_generation();

        futures::stream::iter(0..10_000_u32)
            .map(|index| {
                let cluster = cluster.clone();
                async move {
                    let room = format!("churn-{index}@conference.example.test");
                    let mut occupant = rename_occupant(uuid::Uuid::new_v4(), "Only");
                    occupant.room_jid.clone_from(&room);
                    let json = serde_json::to_string(&occupant).unwrap();
                    assert_eq!(
                        cluster
                            .try_register_muc_occupant(&room, "Only", &json, 1)
                            .await
                            .unwrap(),
                        MucRegistration::Joined
                    );
                    assert!(cluster
                        .unregister_muc_occupant_epoch(
                            &room,
                            "Only",
                            occupant.cluster_epoch,
                            occupant.connection_id,
                        )
                        .await
                        .unwrap());
                }
            })
            .buffer_unordered(16)
            .collect::<Vec<_>>()
            .await;

        let mut connection = cluster.pool.as_ref().unwrap().get().await.unwrap();
        for kind in [
            "muc_occupants",
            "muc_occupant_nodes",
            "muc_nodes",
            "muc_occupant_instances",
            "muc_node_counts",
        ] {
            let pattern = cluster.key(format!("{kind}:*"));
            let mut cursor = 0_u64;
            let mut found = Vec::new();
            loop {
                let (next, keys): (u64, Vec<String>) = redis::cmd("SCAN")
                    .arg(cursor)
                    .arg("MATCH")
                    .arg(&pattern)
                    .arg("COUNT")
                    .arg(1_000)
                    .query_async(&mut *connection)
                    .await
                    .unwrap();
                found.extend(keys);
                cursor = next;
                if cursor == 0 {
                    break;
                }
            }
            assert!(found.is_empty(), "temporary room churn leaked {kind} keys");
        }
    }

    #[test]
    fn redis_session_routes_keep_opaque_resource_case() {
        let upper = session_route_keys("ALICE@Example.test/Phone").unwrap();
        let lower = session_route_keys("alice@example.test/phone").unwrap();
        assert_eq!(upper.0, "alice@example.test/Phone");
        assert_eq!(lower.0, "alice@example.test/phone");
        assert_ne!(upper.0, lower.0);
        assert_eq!(upper.1, lower.1);
        assert_eq!(
            session_route_keys("ÅLICE@BÜCHER.example/DeviceÅ").unwrap(),
            (
                "ålice@bücher.example/DeviceÅ".to_owned(),
                "ålice@bücher.example".to_owned()
            )
        );
        assert!(session_route_keys("alice@example..test/Phone").is_err());
        assert!(session_route_keys("alice@example.test/bad\u{0007}resource").is_err());
    }

    #[test]
    fn clustered_carbon_targets_each_exact_resource() {
        let wrapper = "<message xmlns='jabber:client' from='alice@example.test' to='alice@example.test'><sent xmlns='urn:xmpp:carbons:2'/></message>";
        let upper = node_delivery_stanza(wrapper, true, "alice@example.test/Phone");
        let lower = node_delivery_stanza(wrapper, true, "alice@example.test/phone");
        assert!(upper.contains("to='alice@example.test/Phone'"));
        assert!(lower.contains("to='alice@example.test/phone'"));
        assert_ne!(upper, lower);
    }

    #[test]
    fn rolling_upgrade_accepts_legacy_ack_only_from_legacy_nodes() {
        let future_protocol_version = (DELIVERY_CONTRACT_PROTOCOL_VERSION + 1).to_string();

        assert!(!requires_correlated_ack(None));
        assert!(!requires_correlated_ack(Some("1")));
        assert!(requires_correlated_ack(Some("2")));
        assert!(requires_correlated_ack(Some(NODE_PROTOCOL_VERSION)));
        assert!(requires_correlated_ack(Some("7")));
        assert!(!requires_correlated_ack(Some("invalid")));
        assert!(!supports_control_ack(Some("6")));
        assert!(supports_control_ack(Some("7")));
        assert!(supports_control_ack(Some(NODE_PROTOCOL_VERSION)));
        assert!(!supports_control_ack(Some("12")));
        assert!(!supports_delivery_contract(Some("7")));
        assert!(supports_delivery_contract(Some("8")));
        assert!(supports_delivery_contract(Some("9")));
        assert!(supports_delivery_contract(Some(NODE_PROTOCOL_VERSION)));
        assert!(!supports_delivery_contract(Some(&future_protocol_version)));
        // Presence authority became mandatory in application protocol 10.
        // A new sender must not publish an executable payload to a live v9
        // peer which would ignore the new UUID/generation fields.
        assert!(supports_current_cluster_protocol(Some("11")));
        assert!(!supports_current_cluster_protocol(Some("10")));
        assert!(!supports_current_cluster_protocol(None));
    }

    #[test]
    fn roster_delivery_rejects_a_recreated_account_with_the_same_jid() {
        let committed_owner = uuid::Uuid::from_u128(100);
        let recreated_owner = uuid::Uuid::from_u128(101);
        assert!(delivery_user_identity_matches(
            Some(committed_owner),
            Some(7),
            committed_owner,
            7,
        ));
        assert!(!delivery_user_identity_matches(
            Some(committed_owner),
            Some(7),
            recreated_owner,
            7,
        ));
        assert!(!delivery_user_identity_matches(
            Some(committed_owner),
            Some(7),
            committed_owner,
            8,
        ));
    }

    #[test]
    fn presence_authority_is_versioned_complete_and_generation_fenced() {
        let owner = uuid::Uuid::from_u128(201);
        let recipient = uuid::Uuid::from_u128(202);
        let current = serde_json::json!({
            "presence_authority_version": 1,
            "presence_owner_id": owner,
            "presence_owner_auth_generation": 4,
            "presence_recipient_id": recipient,
            "presence_recipient_auth_generation": 9,
        });
        assert_eq!(
            presence_authority(&current).unwrap(),
            Some(ClusterPresenceAuthority {
                owner_id: owner,
                owner_auth_generation: 4,
                recipient_id: recipient,
                recipient_auth_generation: 9,
            })
        );
        assert!(presence_authority(&serde_json::json!({
            "presence_owner_id": owner,
            "presence_owner_auth_generation": 4,
            "presence_recipient_id": recipient,
            "presence_recipient_auth_generation": 9,
        }))
        .is_err());
        assert!(presence_authority(&serde_json::json!({
            "presence_authority_version": 1,
            "presence_owner_id": owner,
            "presence_owner_auth_generation": 4,
            "presence_recipient_id": recipient,
        }))
        .is_err());
        assert!(presence_authority(&serde_json::json!({
            "presence_authority_version": 2,
            "presence_owner_id": owner,
            "presence_owner_auth_generation": 4,
            "presence_recipient_id": recipient,
            "presence_recipient_auth_generation": 9,
        }))
        .is_err());
        assert_eq!(presence_authority(&serde_json::json!({})).unwrap(), None);
    }

    #[test]
    fn presence_wire_shape_cannot_downgrade_subscription_into_generic_delivery() {
        let subscription = roxmltree::Document::parse(
            "<presence xmlns='jabber:client' from='a@example.test' to='b@example.test' type='subscribe'/>",
        )
        .unwrap();
        let current = roxmltree::Document::parse(
            "<presence xmlns='jabber:client' from='a@example.test/Phone' to='b@example.test'/>",
        )
        .unwrap();
        let message = roxmltree::Document::parse(
            "<message xmlns='jabber:client' from='a@example.test' to='b@example.test'/>",
        )
        .unwrap();
        assert!(is_presence_subscription_stanza(&subscription));
        assert!(presence_delivery_stanza_matches(
            &subscription,
            ClusterPresenceDelivery::Subscription,
        ));
        assert!(!presence_delivery_stanza_matches(
            &subscription,
            ClusterPresenceDelivery::CurrentReplay,
        ));
        assert!(presence_delivery_stanza_matches(
            &current,
            ClusterPresenceDelivery::CurrentReplay,
        ));
        assert!(!presence_delivery_stanza_matches(
            &message,
            ClusterPresenceDelivery::CurrentReplay,
        ));
    }

    #[test]
    fn roster_delivery_shape_binds_the_signed_fence_to_the_stanza_version() {
        let plain = "<iq xmlns='jabber:client' type='set'><query xmlns='jabber:iq:roster' ver='42'><item jid='peer@example.test'/></query></iq>";
        let annotated = "<iq xmlns='jabber:client' type='set'><query xmlns='jabber:iq:roster' ver='42'><item jid='room@mix.example.test'><channel xmlns='urn:xmpp:mix:roster:0' participant-id='p1'/></item></query></iq>";
        assert_eq!(cluster_roster_push_version(plain), Some(42));
        assert_eq!(cluster_roster_push_version(annotated), Some(42));
        assert_ne!(cluster_roster_push_version(plain), Some(41));
        assert_eq!(
            cluster_roster_push_version(
                "<iq xmlns='jabber:client' type='get'><query xmlns='jabber:iq:roster' ver='42'/></iq>"
            ),
            None
        );
        assert_eq!(
            cluster_roster_push_version(
                "<iq xmlns='jabber:client' type='set'><query xmlns='jabber:iq:roster' ver='42'/><query xmlns='jabber:iq:roster' ver='42'/></iq>"
            ),
            None
        );
        assert_eq!(
            cluster_roster_push_version(
                "<iq xmlns='jabber:client' type='set'><query xmlns='jabber:iq:roster' ver='not-a-version'/></iq>"
            ),
            None
        );
    }

    #[test]
    fn message_delivery_contract_is_explicit_strict_and_versioned() {
        let future_protocol_version = (DELIVERY_CONTRACT_PROTOCOL_VERSION + 1).to_string();
        let volatile = serde_json::json!({
            "protocol_version": NODE_PROTOCOL_VERSION,
            "delivery": { "reliability": "volatile" }
        });
        assert_eq!(
            requested_node_message_delivery(&volatile, true).unwrap(),
            Some(RequestedNodeMessageDelivery::Explicit(
                NodeDeliveryContract::Volatile {}
            ))
        );
        for version in ["8", "9"] {
            let adjacent = serde_json::json!({
                "protocol_version": version,
                "delivery": { "reliability": "volatile" }
            });
            assert_eq!(
                requested_node_message_delivery(&adjacent, true).unwrap(),
                Some(RequestedNodeMessageDelivery::Explicit(
                    NodeDeliveryContract::Volatile {}
                )),
                "protocol {version} must retain explicit delivery semantics"
            );
            assert!(requested_node_message_delivery(
                &serde_json::json!({"protocol_version": version}),
                true,
            )
            .is_err());
        }

        let recipient_id = uuid::Uuid::from_u128(10);
        let message_id = uuid::Uuid::from_u128(11);
        let durable = serde_json::json!({
            "protocol_version": NODE_PROTOCOL_VERSION,
            "delivery": {
                "reliability": "durable_c2s",
                "recipient_id": recipient_id,
                "message_id": message_id
            }
        });
        assert_eq!(
            requested_node_message_delivery(&durable, true).unwrap(),
            Some(RequestedNodeMessageDelivery::Explicit(
                NodeDeliveryContract::DurableC2s {
                    recipient_id,
                    message_id,
                }
            ))
        );
        assert!(requested_node_message_delivery(
            &serde_json::json!({"protocol_version": NODE_PROTOCOL_VERSION}),
            true
        )
        .is_err());
        assert!(requested_node_message_delivery(
            &serde_json::json!({
                "protocol_version": NODE_PROTOCOL_VERSION,
                "delivery": {"reliability": "volatile", "unexpected": true}
            }),
            true
        )
        .is_err());
        assert!(requested_node_message_delivery(
            &serde_json::json!({
                "protocol_version": future_protocol_version,
                "delivery": {"reliability": "volatile"}
            }),
            true
        )
        .is_err());
        assert_eq!(
            requested_node_message_delivery(&serde_json::json!({"protocol_version": "6"}), true)
                .unwrap(),
            Some(RequestedNodeMessageDelivery::LegacyInference)
        );
        assert!(requested_node_message_delivery(&volatile, false).is_err());
    }

    #[test]
    fn rolling_delivery_contract_never_turns_volatile_into_legacy_durable() {
        let future_protocol_version = (DELIVERY_CONTRACT_PROTOCOL_VERSION + 1).to_string();
        let recipient_id = uuid::Uuid::from_u128(12);
        let stanza_id = uuid::Uuid::from_u128(13);
        let other_row = uuid::Uuid::from_u128(14);
        let exact = crate::outbound::RecipientDeliveryIdentity::Exact(stanza_id);
        let missing = crate::outbound::RecipientDeliveryIdentity::Missing;

        assert!(delivery_contract_compatible_with_peer(
            Some("8"),
            NodeDeliveryContract::Volatile {},
            exact,
        ));
        assert!(!delivery_contract_compatible_with_peer(
            Some("7"),
            NodeDeliveryContract::Volatile {},
            exact,
        ));
        assert!(delivery_contract_compatible_with_peer(
            Some("7"),
            NodeDeliveryContract::Volatile {},
            missing,
        ));
        assert!(delivery_contract_compatible_with_peer(
            Some("7"),
            NodeDeliveryContract::DurableC2s {
                recipient_id,
                message_id: stanza_id,
            },
            exact,
        ));
        assert!(!delivery_contract_compatible_with_peer(
            Some("7"),
            NodeDeliveryContract::DurableC2s {
                recipient_id,
                message_id: other_row,
            },
            exact,
        ));
        assert!(delivery_contract_compatible_with_peer(
            Some("8"),
            NodeDeliveryContract::Volatile {},
            missing,
        ));
        assert!(delivery_contract_compatible_with_peer(
            Some("9"),
            NodeDeliveryContract::Volatile {},
            missing,
        ));
        assert!(delivery_contract_compatible_with_peer(
            Some(NODE_PROTOCOL_VERSION),
            NodeDeliveryContract::Volatile {},
            exact,
        ));
        // Once version 8 advertises an explicit contract, an exact stanza-id
        // must not make a volatile message look like a legacy durable fence,
        // and a durable row ID need not equal that stanza-id.
        assert!(delivery_contract_compatible_with_peer(
            Some("8"),
            NodeDeliveryContract::DurableC2s {
                recipient_id,
                message_id: other_row,
            },
            exact,
        ));
        for unsupported in [
            None,
            Some("0"),
            Some(future_protocol_version.as_str()),
            Some("invalid"),
        ] {
            assert!(!delivery_contract_compatible_with_peer(
                unsupported,
                NodeDeliveryContract::Volatile {},
                missing,
            ));
        }
    }

    #[test]
    fn durable_contract_carries_the_real_row_fence_not_the_stanza_id() {
        let stanza_id = uuid::Uuid::from_u128(15);
        let offline_row_id = uuid::Uuid::from_u128(16);
        let recipient_id = uuid::Uuid::from_u128(17);
        let stanza = format!(
            "<message to='bob@example.test'><stanza-id xmlns='urn:xmpp:sid:0' by='bob@example.test' id='{stanza_id}'/></message>"
        );
        assert_eq!(
            outbound_delivery_contract(
                &stanza,
                "bob@example.test",
                Some(crate::outbound::DurableDelivery {
                    recipient_id,
                    message_id: offline_row_id,
                    claim_id: None,
                }),
            )
            .unwrap(),
            Some(NodeDeliveryContract::DurableC2s {
                recipient_id,
                message_id: offline_row_id,
            })
        );
    }

    #[test]
    fn durable_contract_is_bound_to_the_exact_spooled_payload() {
        let routed = "<message from='alice@example.test/Phone' to='bob@example.test' type='chat' id='m1'><body>hello</body></message>";
        let stored =
            crate::xmpp::xml_util::add_delay_from(routed, chrono::Utc::now(), Some("example.test"));
        assert!(durable_projection_matches(&stored, routed));
        assert!(!durable_projection_matches(
            &stored,
            "<message from='alice@example.test/Phone' to='bob@example.test' type='chat' id='m1'><body>changed</body></message>"
        ));
        assert!(!durable_projection_matches(
            &stored,
            "<message from='alice@example.test/Phone' to='mallory@example.test' type='chat' id='m1'><body>hello</body></message>"
        ));
    }

    #[test]
    fn delayed_auth_controls_never_revoke_newer_or_recreated_sessions() {
        let original_user = uuid::Uuid::new_v4();
        let recreated_user = uuid::Uuid::new_v4();
        assert!(generation_control_revokes(
            original_user,
            3,
            original_user,
            4
        ));
        assert!(!generation_control_revokes(
            original_user,
            4,
            original_user,
            4
        ));
        assert!(!generation_control_revokes(
            recreated_user,
            0,
            original_user,
            i64::MAX
        ));

        let device = uuid::Uuid::new_v4();
        assert!(user_agent_control_revokes(
            original_user,
            Some(device),
            Some(8),
            original_user,
            device,
            9,
        ));
        assert!(!user_agent_control_revokes(
            original_user,
            Some(device),
            Some(10),
            original_user,
            device,
            9,
        ));
        assert!(!user_agent_control_revokes(
            recreated_user,
            Some(device),
            Some(1),
            original_user,
            device,
            99,
        ));
    }

    #[test]
    fn carbon_exclusions_preserve_exact_resources_and_legacy_primary() {
        let modern = serde_json::json!({
            "exclude_jid": "alice@example.test/Laptop",
            "exclude_jids": [
                "Alice@Example.test/Laptop",
                "alice@example.test/Phone"
            ]
        });
        let exclusions = delivery_exclusions(&modern);
        assert_eq!(exclusions.len(), 2);
        assert!(exclusions.contains("alice@example.test/Laptop"));
        assert!(exclusions.contains("alice@example.test/Phone"));

        let legacy = serde_json::json!({
            "exclude_jid": "Alice@Example.test/Laptop"
        });
        assert_eq!(
            delivery_exclusions(&legacy),
            HashSet::from(["alice@example.test/Laptop".to_owned()])
        );
    }

    #[test]
    fn clustered_muc_carbon_scope_is_bounded_and_unambiguous() {
        let scoped = serde_json::json!({
            "carbon_muc_room": "Room@Conference.Example.test",
            "carbon_muc_nick": "Alice"
        });
        assert_eq!(
            delivery_carbon_muc_scope(&scoped),
            Ok(Some((
                "room@conference.example.test".to_owned(),
                "Alice".to_owned()
            )))
        );
        assert!(delivery_carbon_muc_scope(&serde_json::json!({
            "carbon_muc_room": "room@conference.example.test"
        }))
        .is_err());
    }

    fn ack_expectation<'a>(
        request_id: &'a str,
        nonce: &'a str,
        node_id: &'a str,
        target_jid: &'a str,
    ) -> DeliveryAckExpectation<'a> {
        DeliveryAckExpectation {
            request_id,
            nonce,
            node_id,
            target_jid,
            primary: true,
            delivery: None,
            require_delivery_contract: false,
            mix_capable_only: false,
            transport_receipt_required: false,
        }
    }

    #[test]
    fn delivery_ack_requires_correlation_nonce_node_and_exact_resource() {
        let ack = NodeDeliveryAck {
            request_id: "request-1".to_owned(),
            nonce: "nonce-1".to_owned(),
            node_id: "node-b".to_owned(),
            delivered: 1,
            accepted_full_jid: Some("Alice@Example.test/Phone".to_owned()),
            mix_supported: 0,
            mix_unsupported: 0,
            mix_unknown: 0,
            control_processed: None,
            control_outcome: None,
            delivery: None,
        };
        let payload = serde_json::to_string(&ack).unwrap();
        let receipt = validated_delivery_ack(
            &payload,
            ack_expectation("request-1", "nonce-1", "node-b", "alice@example.test"),
        )
        .unwrap();
        assert!(receipt.delivered);
        assert_eq!(
            receipt.accepted_full_jid.as_deref(),
            Some("alice@example.test/Phone")
        );
        assert!(validated_delivery_ack(
            &payload,
            ack_expectation("request-1", "forged", "node-b", "alice@example.test"),
        )
        .is_none());
        assert!(validated_delivery_ack(
            &payload,
            ack_expectation("request-1", "nonce-1", "node-c", "alice@example.test"),
        )
        .is_none());
        assert!(validated_delivery_ack(
            &payload,
            ack_expectation("request-1", "nonce-1", "node-b", "mallory@example.test"),
        )
        .is_none());
        assert!(validated_delivery_ack(
            &payload,
            ack_expectation("request-1", "nonce-1", "node-b", "alice@example.test/phone",),
        )
        .is_none());
    }

    #[test]
    fn primary_delivery_ack_cannot_claim_multiple_or_missing_resources() {
        for ack in [
            NodeDeliveryAck {
                request_id: "r".to_owned(),
                nonce: "n".to_owned(),
                node_id: "node".to_owned(),
                delivered: 2,
                accepted_full_jid: Some("a@example.test/one".to_owned()),
                mix_supported: 0,
                mix_unsupported: 0,
                mix_unknown: 0,
                control_processed: None,
                control_outcome: None,
                delivery: None,
            },
            NodeDeliveryAck {
                request_id: "r".to_owned(),
                nonce: "n".to_owned(),
                node_id: "node".to_owned(),
                delivered: 1,
                accepted_full_jid: None,
                mix_supported: 0,
                mix_unsupported: 0,
                mix_unknown: 0,
                control_processed: None,
                control_outcome: None,
                delivery: None,
            },
        ] {
            let payload = serde_json::to_string(&ack).unwrap();
            assert!(validated_delivery_ack(
                &payload,
                ack_expectation("r", "n", "node", "a@example.test"),
            )
            .is_none());
        }
    }

    #[test]
    fn mix_delivery_ack_carries_authenticated_tri_state_counts() {
        let ack = NodeDeliveryAck {
            request_id: "mix-r".to_owned(),
            nonce: "mix-n".to_owned(),
            node_id: "node".to_owned(),
            delivered: 1,
            accepted_full_jid: Some("a@example.test/one".to_owned()),
            mix_supported: 1,
            mix_unsupported: 2,
            mix_unknown: 3,
            control_processed: None,
            control_outcome: None,
            delivery: None,
        };
        let mut expected = ack_expectation("mix-r", "mix-n", "node", "a@example.test");
        expected.primary = false;
        expected.mix_capable_only = true;
        let receipt = validated_delivery_ack(&serde_json::to_string(&ack).unwrap(), expected)
            .expect("valid MIX capability receipt");
        assert!(receipt.delivered);
        assert_eq!(receipt.mix_supported, 1);
        assert_eq!(receipt.mix_unsupported, 2);
        assert_eq!(receipt.mix_unknown, 3);

        let forged = NodeDeliveryAck {
            delivered: 2,
            ..ack
        };
        let mut expected = ack_expectation("mix-r", "mix-n", "node", "a@example.test");
        expected.primary = false;
        expected.mix_capable_only = true;
        assert!(
            validated_delivery_ack(&serde_json::to_string(&forged).unwrap(), expected).is_none()
        );
    }

    #[test]
    fn transport_receipt_ack_requires_one_exact_resource_or_none() {
        let ack = NodeDeliveryAck {
            request_id: "pam-r".to_owned(),
            nonce: "pam-n".to_owned(),
            node_id: "node".to_owned(),
            delivered: 1,
            accepted_full_jid: Some("a@example.test/one".to_owned()),
            mix_supported: 0,
            mix_unsupported: 0,
            mix_unknown: 0,
            control_processed: None,
            control_outcome: None,
            delivery: None,
        };
        let expectation = || {
            let mut expected = ack_expectation("pam-r", "pam-n", "node", "a@example.test/one");
            expected.primary = false;
            expected.transport_receipt_required = true;
            expected
        };
        assert!(
            validated_delivery_ack(&serde_json::to_string(&ack).unwrap(), expectation(),).is_some()
        );

        for forged in [
            NodeDeliveryAck {
                delivered: 0,
                ..ack.clone()
            },
            NodeDeliveryAck {
                delivered: 2,
                ..ack.clone()
            },
            NodeDeliveryAck {
                accepted_full_jid: None,
                ..ack.clone()
            },
        ] {
            assert!(validated_delivery_ack(
                &serde_json::to_string(&forged).unwrap(),
                expectation(),
            )
            .is_none());
        }
    }

    #[test]
    fn version_seven_ack_must_echo_the_exact_delivery_contract() {
        let ack = NodeDeliveryAck {
            request_id: "r".to_owned(),
            nonce: "n".to_owned(),
            node_id: "node".to_owned(),
            delivered: 1,
            accepted_full_jid: Some("a@example.test/one".to_owned()),
            mix_supported: 0,
            mix_unsupported: 0,
            mix_unknown: 0,
            control_processed: None,
            control_outcome: None,
            delivery: Some(NodeDeliveryContract::Volatile {}),
        };
        let payload = serde_json::to_string(&ack).unwrap();
        let mut expected = ack_expectation("r", "n", "node", "a@example.test");
        expected.delivery = Some(NodeDeliveryContract::Volatile {});
        expected.require_delivery_contract = true;
        assert!(validated_delivery_ack(&payload, expected).is_some());
        let mut wrong = ack_expectation("r", "n", "node", "a@example.test");
        wrong.delivery = Some(NodeDeliveryContract::DurableC2s {
            recipient_id: uuid::Uuid::from_u128(1),
            message_id: uuid::Uuid::from_u128(2),
        });
        wrong.require_delivery_contract = true;
        assert!(validated_delivery_ack(&payload, wrong,).is_none());
    }
}
