//! Peer protocol versions, node delivery contracts, presence authority and delivery acknowledgements.

use super::*;

pub(super) fn requires_correlated_ack(peer_version: Option<&str>) -> bool {
    peer_version
        .and_then(|version| version.parse::<u16>().ok())
        .is_some_and(|version| version >= 2)
}

pub(super) fn supports_control_ack(peer_version: Option<&str>) -> bool {
    peer_version
        .and_then(|version| version.parse::<u16>().ok())
        .is_some_and(|version| {
            (LEGACY_DELIVERY_PROTOCOL_MAX..=DELIVERY_CONTRACT_PROTOCOL_VERSION).contains(&version)
        })
}

pub(super) fn supports_delivery_contract(peer_version: Option<&str>) -> bool {
    peer_version
        .and_then(|version| version.parse::<u16>().ok())
        .is_some_and(|version| {
            (DELIVERY_CONTRACT_PROTOCOL_MIN..=DELIVERY_CONTRACT_PROTOCOL_VERSION).contains(&version)
        })
}

pub(super) fn supports_current_cluster_protocol(peer_version: Option<&str>) -> bool {
    peer_version == Some(NODE_PROTOCOL_VERSION)
}

pub(super) fn supports_legacy_delivery_inference(peer_version: Option<&str>) -> bool {
    peer_version
        .and_then(|version| version.parse::<u16>().ok())
        .is_some_and(|version| (1..=LEGACY_DELIVERY_PROTOCOL_MAX).contains(&version))
}

pub(super) fn delivery_contract_compatible_with_peer(
    peer_version: Option<&str>,
    contract: NodeDeliveryContract,
    identity: crate::xmpp::outbound::RecipientDeliveryIdentity,
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
            crate::xmpp::outbound::RecipientDeliveryIdentity::Exact(stanza_id),
        ) => message_id == stanza_id,
        (
            NodeDeliveryContract::Volatile {},
            crate::xmpp::outbound::RecipientDeliveryIdentity::Missing,
        ) => true,
        _ => false,
    }
}

#[cfg(test)]
pub(super) fn generation_control_revokes(
    session_user: uuid::Uuid,
    session_generation: i64,
    target_user: uuid::Uuid,
    minimum_generation: i64,
) -> bool {
    session_user == target_user && session_generation < minimum_generation
}

pub(super) fn user_agent_control_revokes(
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

pub(super) fn delivery_user_identity_matches(
    expected_user_id: Option<uuid::Uuid>,
    expected_auth_generation: Option<i64>,
    session_user_id: uuid::Uuid,
    session_auth_generation: i64,
) -> bool {
    expected_user_id.is_none_or(|expected| expected == session_user_id)
        && expected_auth_generation.is_none_or(|expected| expected == session_auth_generation)
}

pub(super) fn cluster_roster_push_version(stanza: &str) -> Option<i64> {
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
pub(super) struct NodeDeliveryOptions<'a> {
    pub(super) carbons_only: bool,
    pub(super) blocklist_requested_only: bool,
    pub(super) roster_requested_only: bool,
    /// Exact account incarnation authorized by the originating transaction.
    /// Roster/removal delivery must not cross a delete/recreate boundary.
    pub(super) expected_user_id: Option<uuid::Uuid>,
    pub(super) expected_auth_generation: Option<i64>,
    /// Immutable roster journal version used by the recipient's initial-sync
    /// gate. Present whenever `roster_requested_only` is true.
    pub(super) roster_version: Option<i64>,
    /// Optional XEP-0405 rendering of the same immutable roster version.
    /// The receiving resource selects it under its synchronization gate.
    pub(super) roster_annotated_stanza: Option<&'a str>,
    pub(super) privacy_requested_only: bool,
    pub(super) mix_capable_only: bool,
    /// Do not acknowledge the request when the stanza merely entered the
    /// peer's in-memory queue. The receiver waits for the exact transport to
    /// take ownership (or rejects and keeps the durable source journal).
    pub(super) transport_receipt_required: bool,
    /// Dedicated transport-ownership acknowledgement for a bare-JID MIX
    /// message. This deliberately differs from `transport_receipt_required`:
    /// MIX must retain its verified-capability fan-out and may acknowledge any
    /// one qualified resource, rather than a single preselected full JID.
    pub(super) mix_transport_receipt_required: bool,
    pub(super) exclude_jids: &'a [&'a str],
    pub(super) primary: bool,
    pub(super) available_only: bool,
    pub(super) available_nonnegative_only: bool,
    /// Restrict a sent Carbon for a MUC private message to resources sharing
    /// the sender's exact room/nick membership (XEP-0280 section 6.1).
    pub(super) carbon_muc_scope: Option<(&'a str, &'a str)>,
    /// Exact PostgreSQL row whose lifetime fences this C2S delivery. `None`
    /// means the message is deliberately volatile; it must never be inferred
    /// as durable merely because it contains an XEP-0359 stanza-id.
    pub(super) durable_delivery: Option<crate::xmpp::outbound::DurableDelivery>,
    /// Exact leased MIX recipient source. Unlike C2S, this source is first
    /// transferred to a remote-node fence and then to socket/SM/BOSH
    /// ownership; it is never inferred from a stanza-id.
    pub(super) mix_delivery: Option<crate::xmpp::outbound::MixDelivery>,
    pub(super) presence_authority: Option<ClusterPresenceAuthority>,
    pub(super) presence_delivery: Option<ClusterPresenceDelivery>,
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
pub(super) enum ClusterPresenceDelivery {
    CurrentReplay,
    Subscription,
}

pub(super) fn presence_delivery_stanza_matches(
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

pub(super) fn is_presence_subscription_stanza(document: &roxmltree::Document<'_>) -> bool {
    presence_delivery_stanza_matches(document, ClusterPresenceDelivery::Subscription)
}

pub(super) fn presence_authority(
    json: &serde_json::Value,
) -> Result<Option<ClusterPresenceAuthority>> {
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
pub(super) enum NodeDeliveryContract {
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
    pub(super) fn from_durable(delivery: crate::xmpp::outbound::DurableDelivery) -> Result<Self> {
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
pub(super) enum ClusterControlOutcome {
    Matched,
    AuthoritativelyAbsent,
    WrongOwner,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(super) struct NodeDeliveryAck {
    pub(super) request_id: String,
    pub(super) nonce: String,
    pub(super) node_id: String,
    pub(super) delivered: usize,
    pub(super) accepted_full_jid: Option<String>,
    #[serde(default)]
    pub(super) mix_supported: usize,
    #[serde(default)]
    pub(super) mix_unsupported: usize,
    #[serde(default)]
    pub(super) mix_unknown: usize,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) control_processed: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) control_outcome: Option<ClusterControlOutcome>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) delivery: Option<NodeDeliveryContract>,
    /// Present only for a durable MIX contract after the destination has
    /// transferred the exact PostgreSQL source to a socket, SM, or BOSH
    /// owner. Redis acknowledgement alone is deliberately not sufficient.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) mix_handoff: Option<ClusterMixHandoff>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum RequestedNodeMessageDelivery {
    LegacyInference,
    Explicit(NodeDeliveryContract),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum ResolvedNodeMessageDelivery {
    Volatile,
    Durable(crate::xmpp::outbound::DurableDelivery),
    Mix(crate::xmpp::outbound::MixDelivery),
}

impl ResolvedNodeMessageDelivery {
    pub(super) fn contract(self) -> NodeDeliveryContract {
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

pub(super) fn requested_node_message_delivery(
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

pub(super) async fn resolve_node_message_delivery<R: NodeMessageProjectionRepository>(
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

pub(super) fn outbound_delivery_contract(
    stanza: &str,
    target_jid: &str,
    durable_delivery: Option<crate::xmpp::outbound::DurableDelivery>,
    mix_delivery: Option<crate::xmpp::outbound::MixDelivery>,
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
                crate::xmpp::outbound::recipient_delivery_identity(stanza, target_jid),
                crate::xmpp::outbound::RecipientDeliveryIdentity::Exact(_)
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
pub(super) struct MucOccupancyIdentity {
    pub(super) nick: String,
    pub(super) full_jid: String,
    pub(super) cluster_epoch: uuid::Uuid,
    pub(super) connection_id: uuid::Uuid,
}

impl MucOccupancyIdentity {
    #[allow(dead_code)] // Legacy Redis destroy compatibility; decoded identities remain wire-compatible.
    pub(super) fn from_occupant(
        occupant: &crate::services::muc::SerializableMucOccupant,
    ) -> Option<Self> {
        (!occupant.cluster_epoch.is_nil() && !occupant.connection_id.is_nil()).then(|| Self {
            nick: occupant.nick.clone(),
            full_jid: occupant.full_jid.clone(),
            cluster_epoch: occupant.cluster_epoch,
            connection_id: occupant.connection_id,
        })
    }
}

pub(super) struct DeliveryAckExpectation<'a> {
    pub(super) request_id: &'a str,
    pub(super) nonce: &'a str,
    pub(super) node_id: &'a str,
    pub(super) target_jid: &'a str,
    pub(super) primary: bool,
    pub(super) delivery: Option<NodeDeliveryContract>,
    pub(super) require_delivery_contract: bool,
    pub(super) mix_capable_only: bool,
    pub(super) transport_receipt_required: bool,
    pub(super) mix_transport_receipt_required: bool,
}

pub(super) fn validated_delivery_ack(
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

pub(super) fn session_route_keys(full_jid: &str) -> Result<(String, String)> {
    let full = crate::jid::canonical_session_key(full_jid)?;
    let bare = crate::jid::canonical_bare_key(&full)?;
    Ok((full, bare))
}

pub(super) fn node_delivery_stanza(stanza: &str, carbons_only: bool, session_key: &str) -> String {
    if !carbons_only {
        return stanza.to_owned();
    }
    let Ok(exact_full_jid) = crate::jid::canonical_session_key(session_key) else {
        return stanza.to_owned();
    };
    crate::services::xml_util::set_to(stanza, &exact_full_jid)
}
