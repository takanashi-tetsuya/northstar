//! XEP-0369 MIX Core, XEP-0405 MIX-PAM, and XEP-0406 MIX Administration.
//!
//! MIX channel nodes intentionally use their own persistence and permission
//! checks.  They are not exposed through the general-purpose PubSub service:
//! in particular, clients cannot publish participant, configuration, allowed,
//! or banned items without going through the MIX authorization model.

use super::{Action, ProtocolSession};
use crate::jid::{prepare_domainpart, CanonicalJid};
use crate::services::mix::{
    ArchiveBoundary, BeginRemotePamJoin, BeginRemotePamLeave, ClaimedPamResult,
    CreateChannelOutcome, FederatedMixIqReplay, FederatedMixMutation, JoinChannelOutcome,
    JoinMixRequest, MamArchiveQuery, MixAccessEntryOperation, MixAccessEntryUpdate, MixAccessList,
    MixBusinessReplay, MixChannel, MixConfigUpdate, MixEvent, MixInfoUpdate, MixInvitationProof,
    MixMutationOutcome, MixParticipant, MixParticipantPreference, MixPresenceProbeTarget,
    MixReadOutcome, MixReplayIdentity, MixRoleUpdate, MixService, PamMembership,
    PamOperationReplay, PresenceOutcome, RegisterMixNickOutcome, RemotePamCompletionOutcome,
    RemotePamJoin, RetractMixMessageOutcome, RetractMixMessageRequest, SetNickError,
    SourceArchiveAdmission, StoreEventOutcome, StoreMixMessageRequest, ALL_NODES, NODE_ALLOWED,
    NODE_AVATAR_DATA, NODE_AVATAR_METADATA, NODE_BANNED, NODE_CONFIG, NODE_INFO, NODE_JIDMAP,
    NODE_MESSAGES, NODE_PRESENCE,
};
use crate::state::{AppState, MixIqRelayStage, PendingMixIqRelay};
use crate::xmpp::xml_builder::XmlElement;
use crate::xmpp::xml_util::{
    add_stanza_id, is_encrypted, mam_extended_form, stanza_error, stanza_error_type,
};
use anyhow::{Context, Result};
use dashmap::DashMap;
use futures::{stream, StreamExt};
use roxmltree::{Document, Node};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use uuid::Uuid;

pub(crate) const CORE_NS: &str = "urn:xmpp:mix:core:1";
pub(crate) const PAM_NS: &str = "urn:xmpp:mix:pam:2";
pub(crate) const ADMIN_NS: &str = "urn:xmpp:mix:admin:0";
pub(crate) const PRESENCE_NS: &str = "urn:xmpp:mix:presence:0";
pub(crate) const ANON_NS: &str = "urn:xmpp:mix:anon:0";
pub(crate) const MISC_NS: &str = "urn:xmpp:mix:misc:0";
const PUBSUB_NS: &str = "http://jabber.org/protocol/pubsub";
const MAM_NS: &str = "urn:xmpp:mam:2";
const MAX_CHANNELS_PER_OWNER: i64 = 100;
const MAX_ITEMS_PAGE: i64 = 200;
const MIX_IQ_RELAY_LIMIT: usize = 1_024;
const MIX_IQ_RELAY_TTL: Duration = Duration::from_secs(30);
// Main grants background workers 15 seconds to join. MIX delivery cancellation
// releases claimed leases immediately, leaving one second for the supervisor
// and registry to record the terminal health transition.
const MIX_OUTBOX_DRAIN_GRACE: Duration = Duration::from_secs(14);
#[derive(Debug)]
struct PermanentMixDeliveryError {
    reason: &'static str,
    detail: String,
}

impl std::fmt::Display for PermanentMixDeliveryError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{}: {}", self.reason, self.detail)
    }
}

impl std::error::Error for PermanentMixDeliveryError {}

#[derive(Debug)]
struct MixCapabilityPending;

impl std::fmt::Display for MixCapabilityPending {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("waiting for verified MIX entity capabilities")
    }
}

impl std::error::Error for MixCapabilityPending {}

#[derive(Debug)]
struct MixOutboxShutdown;

impl std::fmt::Display for MixOutboxShutdown {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("MIX outbox worker is shutting down")
    }
}

impl std::error::Error for MixOutboxShutdown {}

fn permanent_mix_delivery_error(reason: &'static str, detail: impl Into<String>) -> anyhow::Error {
    PermanentMixDeliveryError {
        reason,
        detail: detail.into(),
    }
    .into()
}

/// One linearizable correlation budget for every MIX IQ relay. Expiry is
/// drained by a single supervised worker; admission never creates one timer
/// task per untrusted request.
pub(crate) struct MixIqRelayIndex {
    entries: DashMap<String, PendingMixIqRelay>,
    admission: Mutex<()>,
    max_entries: usize,
    ttl: Duration,
}

impl MixIqRelayIndex {
    pub(crate) fn new() -> Self {
        Self::with_limits(MIX_IQ_RELAY_LIMIT, MIX_IQ_RELAY_TTL)
    }

    fn with_limits(max_entries: usize, ttl: Duration) -> Self {
        assert!(max_entries > 0, "MIX relay capacity must be positive");
        Self {
            entries: DashMap::new(),
            admission: Mutex::new(()),
            max_entries,
            ttl,
        }
    }

    fn admit(&self, id: String, stage: MixIqRelayStage, now: Instant) -> bool {
        let _admission = self
            .admission
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if self.entries.contains_key(&id) || self.entries.len() >= self.max_entries {
            return false;
        }
        self.entries.insert(
            id,
            PendingMixIqRelay {
                stage,
                expires_at: now + self.ttl,
            },
        );
        debug_assert!(self.entries.len() <= self.max_entries);
        true
    }

    fn get(&self, id: &str) -> Option<PendingMixIqRelay> {
        self.entries.get(id).map(|pending| pending.value().clone())
    }

    fn remove(&self, id: &str) -> Option<PendingMixIqRelay> {
        let _admission = self
            .admission
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        self.entries.remove(id).map(|(_, pending)| pending)
    }

    fn take_expired(&self, now: Instant) -> Vec<PendingMixIqRelay> {
        let _admission = self
            .admission
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let expired = self
            .entries
            .iter()
            .filter(|pending| pending.expires_at <= now)
            .map(|pending| pending.key().clone())
            .collect::<Vec<_>>();
        expired
            .into_iter()
            .filter_map(|id| self.entries.remove(&id).map(|(_, pending)| pending))
            .collect()
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.entries.len()
    }
}

fn same_jid_domain(left: &str, right: &str) -> bool {
    matches!(
        (prepare_domainpart(left), prepare_domainpart(right)),
        (Ok(left), Ok(right)) if left == right
    )
}

fn local_mix_domain(state: &AppState) -> String {
    prepare_domainpart(&format!("mix.{}", state.config.domain))
        .expect("configured XMPP domain must form a valid MIX service domain")
}

fn local_muc_domain(state: &AppState) -> String {
    prepare_domainpart(&format!("conference.{}", state.config.domain))
        .expect("configured XMPP domain must form a valid MUC service domain")
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum RelayPayload {
    VCardTemp,
    VCard4 { item_id: Option<String> },
}

#[derive(Clone, Debug)]
struct RelayIq {
    id: String,
    kind: String,
    from: String,
    to: String,
    payload_xml: String,
    request: Option<RelayPayload>,
}

fn parse_relay_iq(raw: &str) -> Result<Option<RelayIq>> {
    if raw.len() > 1_048_576 {
        anyhow::bail!("MIX IQ relay stanza is too large");
    }
    let document = Document::parse(raw).context("malformed MIX IQ relay stanza")?;
    let root = document.root_element();
    if root.tag_name().name() != "iq" {
        return Ok(None);
    }
    let id = root.attribute("id").unwrap_or_default();
    let kind = root.attribute("type").unwrap_or_default();
    let from = root.attribute("from").unwrap_or_default();
    let to = root.attribute("to").unwrap_or_default();
    if id.is_empty()
        || id.len() > 1_024
        || to.is_empty()
        || !matches!(kind, "get" | "result" | "error")
    {
        return Ok(None);
    }
    let elements = root.children().filter(Node::is_element).collect::<Vec<_>>();
    let request = if kind == "get" {
        if elements.len() != 1 {
            return Ok(None);
        }
        let child = elements[0];
        match (child.tag_name().name(), child.tag_name().namespace()) {
            ("vCard", Some("vcard-temp")) => {
                if child.attributes().len() != 0
                    || child.children().any(|node| node.is_element())
                    || child.text().is_some_and(|text| !text.trim().is_empty())
                {
                    return Ok(None);
                }
                Some(RelayPayload::VCardTemp)
            }
            ("pubsub", Some(PUBSUB_NS)) => {
                if child.attributes().len() != 0 {
                    return Ok(None);
                }
                let actions = child
                    .children()
                    .filter(Node::is_element)
                    .collect::<Vec<_>>();
                if actions.len() != 1
                    || actions[0].tag_name().name() != "items"
                    || actions[0].tag_name().namespace() != Some(PUBSUB_NS)
                    || actions[0].attribute("node") != Some("urn:xmpp:vcard4")
                    || actions[0].attributes().len() != 1
                {
                    return Ok(None);
                }
                let items = actions[0]
                    .children()
                    .filter(Node::is_element)
                    .collect::<Vec<_>>();
                let item_id = match items.as_slice() {
                    [] => None,
                    [item]
                        if item.tag_name().name() == "item"
                            && item.tag_name().namespace() == Some(PUBSUB_NS)
                            && item.attributes().len() == 1
                            && !item.children().any(|node| node.is_element()) =>
                    {
                        let id = item.attribute("id").unwrap_or_default();
                        if id.is_empty() || id.len() > 1_024 {
                            return Ok(None);
                        }
                        Some(id.to_owned())
                    }
                    _ => return Ok(None),
                };
                Some(RelayPayload::VCard4 { item_id })
            }
            _ => return Ok(None),
        }
    } else {
        if elements.len() > 2
            || (kind == "error"
                && elements
                    .iter()
                    .filter(|node| node.tag_name().name() == "error")
                    .count()
                    != 1)
        {
            return Ok(None);
        }
        None
    };
    let payload_xml = elements
        .iter()
        .map(|element| &raw[element.range()])
        .collect::<String>();
    Ok(Some(RelayIq {
        id: id.to_owned(),
        kind: kind.to_owned(),
        from: if from.is_empty() {
            String::new()
        } else {
            crate::jid::canonicalize(from)?
        },
        to: crate::jid::canonicalize(to)?,
        payload_xml,
        request,
    }))
}

fn relay_iq_xml(iq: &RelayIq, id: &str, from: &str, to: &str) -> String {
    let mut reply = XmlElement::namespaced("iq", "jabber:client")
        .attr("type", &iq.kind)
        .attr("from", from)
        .attr("to", to)
        .attr("id", id);
    if reply.push_validated_fragment(&iq.payload_xml).is_err() {
        return iq_error_to(id, from, to, "modify", "bad-request");
    }
    reply.finish()
}

fn relay_error(id: &str, from: &str, to: &str, kind: &str, condition: &str) -> String {
    iq_error_to(id, from, to, kind, condition)
}

#[derive(Clone, Debug)]
struct OwnedIq {
    id: String,
    kind: String,
    from: Option<String>,
    to: Option<String>,
    operation: IqOperation,
}

#[derive(Clone, Debug)]
struct MixDiscoInfoRequest {
    id: String,
    from: String,
    to: String,
    node: Option<String>,
    error: Option<&'static str>,
}

fn parse_mix_disco_info(raw: &str) -> Result<Option<MixDiscoInfoRequest>> {
    let document = Document::parse(raw).context("malformed MIX disco IQ")?;
    let root = document.root_element();
    if root.tag_name().name() != "iq" {
        return Ok(None);
    }
    let elements = root.children().filter(Node::is_element).collect::<Vec<_>>();
    let Some(query) = elements.first().copied().filter(|query| {
        query.tag_name().name() == "query"
            && query.tag_name().namespace() == Some("http://jabber.org/protocol/disco#info")
    }) else {
        return Ok(None);
    };
    let id = root.attribute("id").unwrap_or_default().to_owned();
    let from = root.attribute("from").unwrap_or_default().to_owned();
    let to = root.attribute("to").unwrap_or_default().to_owned();
    let node = query.attribute("node").map(str::to_owned);
    let error = if root.attribute("type") != Some("get")
        || elements.len() != 1
        || id.is_empty()
        || from.is_empty()
        || to.is_empty()
        || query
            .attributes()
            .any(|attribute| attribute.namespace().is_some() || attribute.name() != "node")
        || query.children().any(|child| child.is_element())
        || query
            .children()
            .filter(|child| child.is_text())
            .any(|child| child.text().is_some_and(|text| !text.trim().is_empty()))
        || node.as_deref().is_some_and(|node| {
            node.is_empty() || node.len() > 1_024 || node.chars().any(char::is_control)
        }) {
        Some("bad-request")
    } else {
        None
    };
    Ok(Some(MixDiscoInfoRequest {
        id,
        from,
        to,
        node,
        error,
    }))
}

pub(crate) fn mix_service_disco_info_payload(server_name: &str, mirror: &str) -> Result<String> {
    let mut query = XmlElement::namespaced("query", "http://jabber.org/protocol/disco#info").child(
        XmlElement::new("identity")
            .attr("category", "conference")
            .attr("type", "mix")
            .attr("name", format!("{server_name} MIX Service")),
    );
    for feature in [
        "http://jabber.org/protocol/disco#info",
        "http://jabber.org/protocol/disco#items",
        "urn:xmpp:mix:core:1",
        "urn:xmpp:mix:core:1#searchable",
        "urn:xmpp:mix:core:1#create-channel",
        "urn:xmpp:mix:misc:0#nick-register",
    ] {
        query.push_child(XmlElement::new("feature").attr("var", feature));
    }
    query.push_validated_fragment(mirror)?;
    Ok(query.finish())
}

pub(crate) fn mix_channel_disco_info_payload(
    name: &str,
    supports_retraction: bool,
    supports_private_messages: bool,
    supports_mam: bool,
    mirror: &str,
) -> Result<String> {
    let mut query = XmlElement::namespaced("query", "http://jabber.org/protocol/disco#info").child(
        XmlElement::new("identity")
            .attr("category", "conference")
            .attr("type", "mix")
            .attr("name", name),
    );
    for feature in [
        "http://jabber.org/protocol/disco#info",
        "http://jabber.org/protocol/disco#items",
        "http://jabber.org/protocol/pubsub",
        "http://jabber.org/protocol/rsm",
        "urn:xmpp:mix:core:1",
        "urn:xmpp:mix:admin:0",
        "urn:xmpp:mix:presence:0",
        "urn:xmpp:mix:anon:0",
        "urn:xmpp:mix:misc:0",
        "urn:xmpp:avatar:data",
        "urn:xmpp:avatar:metadata",
        "urn:xmpp:sid:0",
    ] {
        query.push_child(XmlElement::new("feature").attr("var", feature));
    }
    if supports_mam {
        query.push_child(
            XmlElement::new("feature").attr("var", northstar_xep_0313::DISCO_FEATURE_MAM),
        );
        query.push_child(
            XmlElement::new("feature").attr("var", northstar_xep_0313::DISCO_FEATURE_MAM_EXTENDED),
        );
    }
    if supports_retraction {
        query.push_child(
            XmlElement::new("feature").attr("var", "urn:xmpp:mix:misc:0#message-retract"),
        );
    }
    if supports_private_messages {
        query.push_child(
            XmlElement::new("feature").attr("var", "urn:xmpp:mix:anon:0#private-messages"),
        );
    }
    query.push_validated_fragment(mirror)?;
    Ok(query.finish())
}

#[derive(Clone, Debug)]
enum IqOperation {
    Create {
        channel: Option<String>,
    },
    Destroy {
        channel: String,
    },
    Join(JoinData),
    Leave,
    SetNick(String),
    UpdateSubscription {
        subscribe: Vec<String>,
        unsubscribe: Vec<String>,
    },
    PamJoin {
        channel: String,
        join: JoinData,
    },
    PamLeave {
        channel: String,
    },
    PubSubGet {
        node: String,
        max: i64,
    },
    PubSubPublish {
        node: String,
        item_count: usize,
        item_ids: Vec<String>,
        fields: BTreeMap<String, Vec<String>>,
        payloads: Vec<String>,
    },
    PubSubRetract {
        node: String,
        item_ids: Vec<String>,
    },
    Mam(super::mam::ParsedMamQuery),
    MamForm,
    MamMetadata,
    MamError(&'static str),
    Ping,
    RegisterNick(Option<String>),
    UserPreferenceGet,
    UserPreferenceSet(BTreeMap<String, Vec<String>>),
    Invite {
        invitee: String,
    },
    /// An IQ result/error whose payload is empty or not otherwise a MIX
    /// request. Used only to correlate federated PAM replies.
    Response,
}

#[derive(Clone, Debug)]
struct JoinData {
    nodes: Vec<String>,
    nick: Option<String>,
    invitation: Option<MixInvitationProof>,
    preference: Option<MixParticipantPreference>,
    anonymous_profile: bool,
}

fn parse_iq(raw: &str) -> Result<Option<OwnedIq>> {
    let document = Document::parse(raw).context("malformed MIX IQ")?;
    let root = document.root_element();
    if root.tag_name().name() != "iq" {
        return Ok(None);
    }
    let kind = root.attribute("type").unwrap_or_default().to_owned();
    anyhow::ensure!(
        matches!(kind.as_str(), "get" | "set" | "result" | "error"),
        "invalid MIX IQ type"
    );
    let id = root.attribute("id").unwrap_or_default();
    anyhow::ensure!(
        !id.is_empty() && id.len() <= 1_024 && !id.chars().any(char::is_control),
        "invalid MIX IQ id"
    );
    let elements = root.children().filter(Node::is_element).collect::<Vec<_>>();
    match kind.as_str() {
        "get" | "set" => anyhow::ensure!(elements.len() == 1, "invalid MIX IQ payload count"),
        "result" => anyhow::ensure!(elements.len() <= 1, "invalid MIX IQ result payload count"),
        "error" => {
            anyhow::ensure!(
                (1..=2).contains(&elements.len())
                    && elements
                        .iter()
                        .filter(|node| node.tag_name().name() == "error")
                        .count()
                        == 1,
                "invalid MIX IQ error payload"
            );
        }
        _ => unreachable!(),
    }
    let child = elements.first().copied();
    let operation = if matches!(kind.as_str(), "result" | "error") {
        IqOperation::Response
    } else {
        match child.map(|child| (child, child.tag_name().name(), child.tag_name().namespace())) {
            Some((child, "create", Some(CORE_NS))) => {
                anyhow::ensure!(
                    !child.children().any(|node| node.is_element()),
                    "invalid MIX create"
                );
                IqOperation::Create {
                    channel: child.attribute("channel").map(str::to_owned),
                }
            }
            Some((child, "destroy", Some(CORE_NS))) => {
                anyhow::ensure!(
                    !child.children().any(|node| node.is_element()),
                    "invalid MIX destroy"
                );
                let channel = child.attribute("channel").unwrap_or_default();
                anyhow::ensure!(!channel.is_empty(), "MIX destroy is missing channel");
                IqOperation::Destroy {
                    channel: channel.to_owned(),
                }
            }
            Some((child, "join", Some(CORE_NS | ANON_NS | MISC_NS))) => {
                IqOperation::Join(parse_join(child)?)
            }
            Some((child, "leave", Some(CORE_NS))) => {
                anyhow::ensure!(
                    !child.children().any(|node| node.is_element()),
                    "invalid MIX leave"
                );
                IqOperation::Leave
            }
            Some((child, "setnick", Some(CORE_NS))) => {
                let nick = child
                    .children()
                    .filter(Node::is_element)
                    .collect::<Vec<_>>();
                anyhow::ensure!(
                    nick.len() == 1
                        && nick[0].tag_name().name() == "nick"
                        && nick[0].tag_name().namespace() == Some(CORE_NS)
                        && !nick[0].children().any(|node| node.is_element()),
                    "invalid MIX setnick"
                );
                IqOperation::SetNick(MixService::prepare_mix_nick(
                    nick[0].text().unwrap_or_default(),
                )?)
            }
            Some((child, "update-subscription", Some(CORE_NS))) => {
                let (subscribe, unsubscribe) = parse_subscription_changes(child)?;
                IqOperation::UpdateSubscription {
                    subscribe,
                    unsubscribe,
                }
            }
            Some((child, "client-join", Some(PAM_NS))) => {
                let channel = child.attribute("channel").unwrap_or_default().to_owned();
                let children = child
                    .children()
                    .filter(Node::is_element)
                    .collect::<Vec<_>>();
                anyhow::ensure!(
                    children.len() == 1
                        && children[0].tag_name().name() == "join"
                        && matches!(children[0].tag_name().namespace(), Some(CORE_NS | ANON_NS)),
                    "invalid MIX-PAM client-join"
                );
                IqOperation::PamJoin {
                    channel,
                    join: parse_join(children[0])?,
                }
            }
            Some((child, "client-leave", Some(PAM_NS))) => {
                let children = child
                    .children()
                    .filter(Node::is_element)
                    .collect::<Vec<_>>();
                anyhow::ensure!(
                    children.len() == 1
                        && children[0].tag_name().name() == "leave"
                        && children[0].tag_name().namespace() == Some(CORE_NS)
                        && !children[0].children().any(|node| node.is_element()),
                    "invalid MIX-PAM client-leave"
                );
                IqOperation::PamLeave {
                    channel: child.attribute("channel").unwrap_or_default().to_owned(),
                }
            }
            Some((child, "pubsub", Some(PUBSUB_NS))) => parse_pubsub(child, raw)?,
            Some((child, "register", Some(MISC_NS))) => {
                let children = child
                    .children()
                    .filter(Node::is_element)
                    .collect::<Vec<_>>();
                anyhow::ensure!(children.len() <= 1, "invalid MIX nick registration");
                let nick = match children.as_slice() {
                    [] => None,
                    [nick]
                        if nick.tag_name().name() == "nick"
                            && nick.tag_name().namespace() == Some(MISC_NS)
                            && !nick.children().any(|node| node.is_element()) =>
                    {
                        Some(MixService::prepare_mix_nick(
                            nick.text().unwrap_or_default(),
                        )?)
                    }
                    _ => anyhow::bail!("invalid MIX nick registration"),
                };
                IqOperation::RegisterNick(nick)
            }
            Some((child, "user-preference", Some(ANON_NS))) => {
                let forms = child
                    .children()
                    .filter(|node| is_xdata(*node))
                    .collect::<Vec<_>>();
                anyhow::ensure!(forms.len() <= 1, "invalid MIX preference form count");
                if kind == "get" {
                    anyhow::ensure!(forms.is_empty(), "MIX preference get must be empty");
                    IqOperation::UserPreferenceGet
                } else {
                    anyhow::ensure!(forms.len() == 1, "MIX preference set needs a form");
                    IqOperation::UserPreferenceSet(parse_fields(forms[0])?)
                }
            }
            Some((child, "invite", Some(MISC_NS))) if kind == "get" => {
                let invitees = child
                    .children()
                    .filter(Node::is_element)
                    .collect::<Vec<_>>();
                anyhow::ensure!(
                    invitees.len() == 1
                        && invitees[0].tag_name().name() == "invitee"
                        && invitees[0].tag_name().namespace() == Some(MISC_NS)
                        && !invitees[0].children().any(|node| node.is_element()),
                    "invalid MIX invitation request"
                );
                IqOperation::Invite {
                    invitee: crate::jid::canonicalize_bare(invitees[0].text().unwrap_or_default())?,
                }
            }
            Some((child, "query", Some(MAM_NS))) if kind == "get" => {
                if child.attributes().len() == 0
                    && !child.children().any(|node| node.is_element())
                    && child.text().is_none_or(|text| text.trim().is_empty())
                {
                    IqOperation::MamForm
                } else {
                    IqOperation::MamError("bad-request")
                }
            }
            Some((child, "query", Some(MAM_NS))) if kind == "set" => {
                match super::mam::parse_mam_query(child) {
                    Ok(query) => IqOperation::Mam(query),
                    Err(condition) => IqOperation::MamError(condition),
                }
            }
            Some((child, "metadata", Some(MAM_NS))) if kind == "get" => {
                if child.attributes().len() == 0
                    && !child.children().any(|node| node.is_element())
                    && child.text().is_none_or(|text| text.trim().is_empty())
                {
                    IqOperation::MamMetadata
                } else {
                    IqOperation::MamError("bad-request")
                }
            }
            Some((child, "ping", Some(northstar_xep_0199::NAMESPACE))) => {
                northstar_xep_0199::parse_ping_element(child)
                    .map_err(|error| anyhow::anyhow!("invalid MIX ping: {error}"))?;
                IqOperation::Ping
            }
            _ => return Ok(None),
        }
    };
    Ok(Some(OwnedIq {
        id: id.to_owned(),
        kind,
        from: root.attribute("from").map(str::to_owned),
        to: root.attribute("to").map(str::to_owned),
        operation,
    }))
}

fn mix_iq_route_candidate(raw: &str, mix_domain: &str) -> bool {
    let Ok(document) = Document::parse(raw) else {
        return false;
    };
    let root = document.root_element();
    if root.tag_name().name() != "iq" {
        return false;
    }
    // PAM requests are addressed to the user's own bare JID rather than the
    // MIX service. Their exact target is checked after the full parse.
    if root
        .children()
        .find(Node::is_element)
        .is_some_and(|child| child.tag_name().namespace() == Some(PAM_NS))
    {
        return true;
    }
    // Everything else owned by the MIX parser is addressed to the MIX
    // service. In particular, a general-purpose PubSub <create/><configure/>
    // request to pubsub.example must never be parsed as a malformed MIX
    // PubSub operation merely because both protocols use the PubSub namespace.
    root.attribute("to")
        .and_then(|to| CanonicalJid::parse(to).ok())
        .is_some_and(|target| target.domainpart() == mix_domain)
}

fn parse_join(node: Node<'_, '_>) -> Result<JoinData> {
    let mut nodes = Vec::new();
    let mut nick = None;
    let mut invitation = None;
    let mut preference = None;
    let anonymous_profile = node.tag_name().namespace() == Some(ANON_NS);
    for child in node.children().filter(Node::is_element) {
        match (child.tag_name().name(), child.tag_name().namespace()) {
            ("subscribe", Some(CORE_NS | ANON_NS | MISC_NS)) => {
                anyhow::ensure!(
                    !child.children().any(|node| node.is_element()),
                    "invalid MIX subscribe payload"
                );
                nodes.push(
                    child
                        .attribute("node")
                        .context("MIX subscribe missing node")?
                        .to_owned(),
                );
            }
            ("nick", Some(CORE_NS | ANON_NS | MISC_NS)) => {
                anyhow::ensure!(nick.is_none(), "duplicate MIX nick");
                anyhow::ensure!(
                    !child.children().any(|node| node.is_element()),
                    "invalid MIX nick payload"
                );
                nick = Some(MixService::prepare_mix_nick(
                    child.text().unwrap_or_default(),
                )?);
            }
            ("invitation", Some(MISC_NS)) => {
                anyhow::ensure!(invitation.is_none(), "duplicate MIX invitation");
                let mut values = BTreeMap::new();
                for field in child.children().filter(Node::is_element) {
                    anyhow::ensure!(
                        field.tag_name().namespace() == Some(MISC_NS)
                            && matches!(
                                field.tag_name().name(),
                                "inviter" | "invitee" | "channel" | "token"
                            )
                            && !field.children().any(|node| node.is_element()),
                        "invalid MIX invitation"
                    );
                    anyhow::ensure!(
                        values
                            .insert(
                                field.tag_name().name().to_owned(),
                                field.text().unwrap_or_default().to_owned(),
                            )
                            .is_none(),
                        "duplicate MIX invitation field"
                    );
                }
                invitation = Some(MixInvitationProof {
                    inviter_jid: values.remove("inviter").context("missing MIX inviter")?,
                    invitee_jid: values.remove("invitee").context("missing MIX invitee")?,
                    channel_jid: values.remove("channel").context("missing MIX channel")?,
                    token: values
                        .remove("token")
                        .context("missing MIX invitation token")?,
                });
            }
            ("x", Some("jabber:x:data")) if anonymous_profile => {
                anyhow::ensure!(preference.is_none(), "duplicate MIX preference form");
                let fields = parse_fields(child)?;
                preference = Some(parse_preference_submission(&fields, None)?);
            }
            _ => anyhow::bail!("unknown MIX join child"),
        }
    }
    let nodes = MixService::valid_join_nodes(&nodes)?;
    Ok(JoinData {
        nodes,
        nick,
        invitation,
        preference,
        anonymous_profile,
    })
}

fn parse_subscription_changes(node: Node<'_, '_>) -> Result<(Vec<String>, Vec<String>)> {
    let mut subscribe = Vec::new();
    let mut unsubscribe = Vec::new();
    for child in node.children().filter(Node::is_element) {
        let target = match (child.tag_name().name(), child.tag_name().namespace()) {
            ("subscribe", Some(CORE_NS)) => &mut subscribe,
            ("unsubscribe", Some(CORE_NS)) => &mut unsubscribe,
            _ => anyhow::bail!("unknown MIX subscription child"),
        };
        anyhow::ensure!(
            !child.children().any(|node| node.is_element()),
            "invalid MIX subscription payload"
        );
        target.push(
            child
                .attribute("node")
                .context("MIX subscription missing node")?
                .to_owned(),
        );
    }
    Ok((
        MixService::valid_join_nodes(&subscribe)?,
        MixService::valid_join_nodes(&unsubscribe)?,
    ))
}

fn parse_pubsub(pubsub: Node<'_, '_>, raw: &str) -> Result<IqOperation> {
    let actions = pubsub
        .children()
        .filter(Node::is_element)
        .collect::<Vec<_>>();
    anyhow::ensure!(actions.len() == 1, "invalid MIX PubSub action count");
    let action = actions[0];
    anyhow::ensure!(
        action.tag_name().namespace() == Some(PUBSUB_NS),
        "invalid MIX PubSub action namespace"
    );
    let node = action.attribute("node").unwrap_or_default().to_owned();
    match action.tag_name().name() {
        "items" => {
            anyhow::ensure!(
                !action.children().any(|node| node.is_element()),
                "MIX item selection is not supported"
            );
            let max = action
                .attribute("max_items")
                .map(str::parse::<i64>)
                .transpose()
                .context("invalid MIX max_items")?
                .unwrap_or(MAX_ITEMS_PAGE)
                .clamp(1, MAX_ITEMS_PAGE);
            Ok(IqOperation::PubSubGet { node, max })
        }
        "publish" => {
            let children = action
                .children()
                .filter(Node::is_element)
                .collect::<Vec<_>>();
            anyhow::ensure!(children.len() == 1, "invalid MIX publish payload");
            let items = if children[0].tag_name().name() == "item"
                && children[0].tag_name().namespace() == Some(PUBSUB_NS)
            {
                vec![children[0]]
            } else if children[0].tag_name().name() == "items"
                && children[0].tag_name().namespace() == Some(PUBSUB_NS)
            {
                let items = children[0]
                    .children()
                    .filter(Node::is_element)
                    .collect::<Vec<_>>();
                anyhow::ensure!(
                    items.iter().all(|item| {
                        item.tag_name().name() == "item"
                            && item.tag_name().namespace() == Some(PUBSUB_NS)
                    }),
                    "invalid MIX publish item"
                );
                items
            } else {
                anyhow::bail!("invalid MIX publish payload")
            };
            anyhow::ensure!(
                !items.is_empty() && items.len() <= 64,
                "invalid MIX publish item count"
            );
            let item_ids = items
                .iter()
                .filter_map(|item| item.attribute("id").map(str::to_owned))
                .collect::<Vec<_>>();
            let forms = items
                .iter()
                .flat_map(|item| item.descendants().filter(|node| is_xdata(*node)))
                .collect::<Vec<_>>();
            anyhow::ensure!(forms.len() <= 1, "multiple MIX publish forms");
            Ok(IqOperation::PubSubPublish {
                node,
                item_count: items.len(),
                item_ids,
                fields: forms
                    .first()
                    .copied()
                    .map(parse_fields)
                    .transpose()?
                    .unwrap_or_default(),
                payloads: items
                    .iter()
                    .map(|item| {
                        item.children()
                            .filter(Node::is_element)
                            .map(|child| raw[child.range()].to_owned())
                            .collect::<String>()
                    })
                    .collect(),
            })
        }
        "retract" => {
            let items = action
                .children()
                .filter(Node::is_element)
                .collect::<Vec<_>>();
            anyhow::ensure!(
                !items.is_empty()
                    && items.len() <= 64
                    && items.iter().all(|item| {
                        item.tag_name().name() == "item"
                            && item.tag_name().namespace() == Some(PUBSUB_NS)
                            && item.attribute("id").is_some_and(|id| !id.is_empty())
                            && !item.children().any(|node| node.is_element())
                    }),
                "invalid MIX retract item count"
            );
            let item_ids = items
                .iter()
                .map(|item| item.attribute("id").unwrap_or_default().to_owned())
                .collect::<Vec<_>>();
            Ok(IqOperation::PubSubRetract { node, item_ids })
        }
        _ => anyhow::bail!("unsupported MIX PubSub operation"),
    }
}

fn is_xdata(node: Node<'_, '_>) -> bool {
    node.is_element()
        && node.tag_name().name() == "x"
        && node.tag_name().namespace() == Some("jabber:x:data")
}

fn parse_fields(form: Node<'_, '_>) -> Result<BTreeMap<String, Vec<String>>> {
    anyhow::ensure!(
        matches!(form.attribute("type"), Some("submit" | "result")),
        "invalid MIX data form"
    );
    let mut fields = BTreeMap::new();
    for field in form.children().filter(|node| {
        node.is_element()
            && node.tag_name().name() == "field"
            && node.tag_name().namespace() == Some("jabber:x:data")
    }) {
        let var = field
            .attribute("var")
            .context("MIX form field missing var")?;
        let values = field
            .children()
            .filter(|node| node.is_element() && node.tag_name().name() == "value")
            .map(|node| node.text().unwrap_or_default().to_owned())
            .collect::<Vec<_>>();
        anyhow::ensure!(
            fields.insert(var.to_owned(), values).is_none(),
            "duplicate MIX form field"
        );
    }
    Ok(fields)
}

fn iq_result_to(id: &str, from: &str, to: &str, payload: &str) -> String {
    let mut iq = XmlElement::namespaced("iq", "jabber:client")
        .attr("type", "result")
        .attr("from", from)
        .attr("to", to)
        .attr("id", id);
    if iq.push_validated_fragment(payload).is_err() {
        return iq_error_to(id, from, to, "wait", "internal-server-error");
    }
    iq.finish()
}

fn iq_error_to(id: &str, from: &str, to: &str, error_type: &str, condition: &str) -> String {
    let condition = XmlElement::dynamic(condition)
        .unwrap_or_else(|_| XmlElement::new("undefined-condition"))
        .attr("xmlns", "urn:ietf:params:xml:ns:xmpp-stanzas");
    XmlElement::namespaced("iq", "jabber:client")
        .attr("type", "error")
        .attr("from", from)
        .attr("to", to)
        .attr("id", id)
        .child(
            XmlElement::new("error")
                .attr("type", error_type)
                .child(condition),
        )
        .finish()
}

fn mix_xdata_value_field(
    variable: &'static str,
    kind: Option<&'static str>,
    value: impl ToString,
) -> XmlElement {
    XmlElement::new("field")
        .attr("var", variable)
        .optional_attr("type", kind)
        .child(XmlElement::new("value").text(value.to_string()))
}

fn mix_xdata_option(value: &'static str) -> XmlElement {
    XmlElement::new("option").child(XmlElement::new("value").text(value))
}

fn preference_result_form(preference: &MixParticipantPreference) -> String {
    XmlElement::namespaced("x", "jabber:x:data")
        .attr("type", "result")
        .child(mix_xdata_value_field("FORM_TYPE", Some("hidden"), ANON_NS))
        .child(mix_xdata_value_field(
            "JID Visibility",
            None,
            &preference.jid_visibility,
        ))
        .child(mix_xdata_value_field(
            "Private Messages",
            None,
            &preference.private_messages,
        ))
        .child(mix_xdata_value_field("vCard", None, &preference.vcard))
        .child(mix_xdata_value_field(
            "Presence",
            None,
            if preference.share_presence {
                "share"
            } else {
                "not share"
            },
        ))
        .finish()
}

fn preference_template_form() -> String {
    let mut visibility = XmlElement::new("field")
        .attr("type", "list-single")
        .attr("var", "JID Visibility");
    for value in ["default", "never", "always", "prefer not"] {
        visibility.push_child(mix_xdata_option(value));
    }
    let mut private_messages = XmlElement::new("field")
        .attr("type", "list-single")
        .attr("var", "Private Messages");
    for value in ["allow", "block"] {
        private_messages.push_child(mix_xdata_option(value));
    }
    let mut vcard = XmlElement::new("field")
        .attr("type", "list-single")
        .attr("var", "vCard");
    for value in ["allow", "block"] {
        vcard.push_child(mix_xdata_option(value));
    }
    let mut presence = XmlElement::new("field")
        .attr("type", "list-single")
        .attr("var", "Presence");
    for value in ["share", "not share"] {
        presence.push_child(mix_xdata_option(value));
    }
    XmlElement::namespaced("x", "jabber:x:data")
        .attr("type", "form")
        .child(mix_xdata_value_field("FORM_TYPE", Some("hidden"), ANON_NS))
        .child(visibility)
        .child(private_messages)
        .child(vcard)
        .child(presence)
        .finish()
}

fn parse_preference_submission(
    fields: &BTreeMap<String, Vec<String>>,
    current: Option<&MixParticipantPreference>,
) -> Result<MixParticipantPreference> {
    validate_form_fields(
        fields,
        &[
            "FORM_TYPE",
            "JID Visibility",
            "Private Messages",
            "vCard",
            "Presence",
        ],
        &[],
    )?;
    anyhow::ensure!(
        field_first(fields, "FORM_TYPE") == Some(ANON_NS),
        "invalid MIX-ANON preference form"
    );
    let default = MixParticipantPreference::default();
    let current = current.unwrap_or(&default);
    let preference = MixParticipantPreference {
        jid_visibility: field_first(fields, "JID Visibility")
            .unwrap_or(&current.jid_visibility)
            .to_owned(),
        private_messages: field_first(fields, "Private Messages")
            .unwrap_or(&current.private_messages)
            .to_owned(),
        vcard: field_first(fields, "vCard")
            .unwrap_or(&current.vcard)
            .to_owned(),
        share_presence: match field_first(fields, "Presence") {
            None => current.share_presence,
            Some("share") => true,
            Some("not share") => false,
            Some(_) => anyhow::bail!("invalid MIX presence preference"),
        },
    };
    anyhow::ensure!(
        matches!(
            preference.jid_visibility.as_str(),
            "default" | "never" | "always" | "prefer not"
        ) && matches!(preference.private_messages.as_str(), "allow" | "block")
            && matches!(preference.vcard.as_str(), "allow" | "block"),
        "invalid MIX participant preference"
    );
    Ok(preference)
}

fn join_body(
    participant: &MixParticipant,
    subscriptions: &[String],
    preference: Option<&MixParticipantPreference>,
) -> Result<String> {
    let mut body = XmlElement::new("mix-join-body");
    for node in subscriptions {
        body.push_child(XmlElement::new("subscribe").attr("node", node));
    }
    if let Some(nick) = participant.nick.as_deref() {
        body.push_child(XmlElement::new("nick").text(nick.to_owned()));
    }
    if let Some(preference) = preference {
        body.push_validated_fragment(&preference_result_form(preference))?;
    }
    Ok(body.finish_children())
}

/// XEP-0369 identifies the participant with the Stable Participant ID in an
/// `id` attribute on the channel's direct join result.
fn core_join_payload(
    participant: &MixParticipant,
    subscriptions: &[String],
    preference: Option<&MixParticipantPreference>,
    anonymous_profile: bool,
) -> Result<String> {
    let namespace = if anonymous_profile { ANON_NS } else { CORE_NS };
    XmlElement::namespaced("join", namespace)
        .attr("id", participant.participant_id)
        .validated_fragment(&join_body(participant, subscriptions, preference)?)
        .map(|element| element.finish())
}

/// XEP-0405 exposes the stable participant reference to a client as an
/// encoded bare JID: `stable-id#channel@mix-service`.  Ensure that embedding
/// the opaque ID in an RFC 7622 localpart does not change it under PRECIS.
fn encoded_participant_jid(channel_jid: &str, participant_id: &str) -> Result<String> {
    anyhow::ensure!(
        MixService::valid_stable_participant_id(participant_id),
        "invalid MIX stable participant id"
    );
    let channel = crate::jid::CanonicalJid::parse_bare(channel_jid)?;
    let channel_localpart = channel
        .localpart()
        .context("MIX channel JID requires a localpart")?;
    let encoded_localpart = format!("{participant_id}#{channel_localpart}");
    let encoded = crate::jid::CanonicalJid::parse_bare(&format!(
        "{encoded_localpart}@{}",
        channel.domainpart()
    ))?;
    anyhow::ensure!(
        encoded.localpart() == Some(encoded_localpart.as_str()),
        "MIX stable participant id is not a canonical JID localpart prefix"
    );
    Ok(encoded.to_string())
}

fn decode_participant_jid(value: &str) -> Result<(String, String)> {
    let raw_localpart = value
        .split_once('@')
        .map(|(localpart, _)| localpart)
        .context("encoded MIX participant JID requires a localpart")?;
    let encoded = crate::jid::CanonicalJid::parse_bare(value)?;
    anyhow::ensure!(
        encoded.localpart() == Some(raw_localpart),
        "encoded MIX participant JID is not in canonical localpart form"
    );
    let (participant_id, channel_localpart) = encoded
        .localpart()
        .and_then(|localpart| localpart.split_once('#'))
        .context("encoded MIX participant JID is missing its channel")?;
    anyhow::ensure!(
        MixService::valid_stable_participant_id(participant_id),
        "invalid MIX stable participant id"
    );
    let channel = crate::jid::CanonicalJid::parse_bare(&format!(
        "{channel_localpart}@{}",
        encoded.domainpart()
    ))?;
    Ok((participant_id.to_owned(), channel.to_string()))
}

fn participant_id_from_encoded_jid(value: &str, channel_jid: &str) -> Result<String> {
    let (participant_id, encoded_channel) = decode_participant_jid(value)?;
    let channel = crate::jid::CanonicalJid::parse_bare(channel_jid)?;
    anyhow::ensure!(
        encoded_channel == channel.to_string(),
        "encoded MIX participant JID has the wrong channel"
    );
    Ok(participant_id)
}

fn pam_join_payload(
    channel_jid: &str,
    participant: &MixParticipant,
    subscriptions: &[String],
    preference: Option<&MixParticipantPreference>,
    anonymous_profile: bool,
) -> Result<String> {
    let participant_jid =
        encoded_participant_jid(channel_jid, &participant.participant_id.to_string())?;
    let namespace = if anonymous_profile { ANON_NS } else { CORE_NS };
    Ok(XmlElement::namespaced("join", namespace)
        .attr("jid", &participant_jid)
        .validated_fragment(&join_body(participant, subscriptions, preference)?)?
        .finish())
}

#[derive(Debug, Eq, PartialEq)]
struct RemoteJoinResult {
    participant_id: String,
    participant_jid: String,
    subscriptions: Vec<String>,
    nick: Option<String>,
}

#[derive(Debug, Eq, PartialEq)]
struct RemoteIqError {
    error_type: String,
    condition: String,
}

fn parse_remote_iq_error(raw: &str) -> Result<RemoteIqError> {
    const STANZA_ERRORS_NS: &str = "urn:ietf:params:xml:ns:xmpp-stanzas";
    const CONDITIONS: [&str; 22] = [
        "bad-request",
        "conflict",
        "feature-not-implemented",
        "forbidden",
        "gone",
        "internal-server-error",
        "item-not-found",
        "jid-malformed",
        "not-acceptable",
        "not-allowed",
        "not-authorized",
        "policy-violation",
        "recipient-unavailable",
        "redirect",
        "registration-required",
        "remote-server-not-found",
        "remote-server-timeout",
        "resource-constraint",
        "service-unavailable",
        "subscription-required",
        "undefined-condition",
        "unexpected-request",
    ];
    let document = Document::parse(raw).context("malformed federated MIX error")?;
    let root = document.root_element();
    anyhow::ensure!(
        root.tag_name().name() == "iq" && root.attribute("type") == Some("error"),
        "not an IQ error"
    );
    let error = root
        .children()
        .filter(Node::is_element)
        .find(|node| node.tag_name().name() == "error")
        .context("missing IQ error payload")?;
    let error_type = error.attribute("type").unwrap_or_default();
    anyhow::ensure!(
        matches!(
            error_type,
            "auth" | "cancel" | "continue" | "modify" | "wait"
        ),
        "invalid IQ error type"
    );
    let conditions = error
        .children()
        .filter(|node| {
            node.is_element()
                && node.tag_name().namespace() == Some(STANZA_ERRORS_NS)
                && node.tag_name().name() != "text"
        })
        .collect::<Vec<_>>();
    anyhow::ensure!(conditions.len() == 1, "invalid IQ error condition count");
    let condition = conditions[0].tag_name().name();
    anyhow::ensure!(
        CONDITIONS.contains(&condition),
        "unknown IQ error condition"
    );
    Ok(RemoteIqError {
        error_type: error_type.to_owned(),
        condition: condition.to_owned(),
    })
}

fn parse_remote_join_result(raw: &str, channel_jid: &str) -> Result<RemoteJoinResult> {
    let document = Document::parse(raw).context("malformed federated MIX join result")?;
    let root = document.root_element();
    anyhow::ensure!(
        root.tag_name().name() == "iq" && root.attribute("type") == Some("result"),
        "not a MIX join result"
    );
    let elements = root.children().filter(Node::is_element).collect::<Vec<_>>();
    anyhow::ensure!(elements.len() == 1, "invalid MIX join result payload count");
    let join = elements[0];
    anyhow::ensure!(
        join.tag_name().name() == "join"
            && matches!(join.tag_name().namespace(), Some(CORE_NS | ANON_NS)),
        "invalid MIX join result payload element name={:?} namespace={:?}",
        join.tag_name().name(),
        join.tag_name().namespace()
    );
    let participant_id = match (join.attribute("id"), join.attribute("jid")) {
        (Some(participant_id), None) => {
            anyhow::ensure!(
                MixService::valid_stable_participant_id(participant_id),
                "invalid MIX stable participant id"
            );
            participant_id.to_owned()
        }
        // XEP-0405 examples use the encoded JID form in the channel response,
        // while the current XEP-0369 text uses `id`. Accept both documented
        // forms but never accept an ambiguous response containing both.
        (None, Some(participant_jid)) => {
            participant_id_from_encoded_jid(participant_jid, channel_jid)?
        }
        _ => anyhow::bail!("MIX join result requires exactly one participant identifier"),
    };
    let participant_jid = encoded_participant_jid(channel_jid, &participant_id)?;
    let join = parse_join(join)?;
    Ok(RemoteJoinResult {
        participant_id,
        participant_jid,
        subscriptions: join.nodes,
        nick: join.nick,
    })
}

fn parse_remote_pam_success(raw: &str, channel_jid: &str) -> Result<Option<RemoteJoinResult>> {
    let document = Document::parse(raw).context("malformed federated MIX result")?;
    let root = document.root_element();
    anyhow::ensure!(
        root.tag_name().name() == "iq" && root.attribute("type") == Some("result"),
        "not a MIX result"
    );
    let payloads = root.children().filter(Node::is_element).collect::<Vec<_>>();
    match payloads.as_slice() {
        [leave]
            if leave.tag_name().name() == "leave"
                && leave.tag_name().namespace() == Some(CORE_NS) =>
        {
            anyhow::ensure!(
                leave.attributes().len() == 0
                    && !leave.children().any(|node| node.is_element())
                    && leave
                        .children()
                        .filter(Node::is_text)
                        .all(|node| node.text().is_none_or(|text| text.trim().is_empty())),
                "invalid MIX leave result payload"
            );
            Ok(None)
        }
        [] => Ok(None),
        [_] => parse_remote_join_result(raw, channel_jid).map(Some),
        _ => anyhow::bail!("invalid MIX result payload count"),
    }
}

fn mix_pubsub_publish_ack(node: &str, item_id: &str) -> String {
    XmlElement::namespaced("pubsub", PUBSUB_NS)
        .child(
            XmlElement::new("publish")
                .attr("node", node)
                .child(XmlElement::new("item").attr("id", item_id)),
        )
        .finish()
}

fn mix_empty_pubsub() -> String {
    XmlElement::namespaced("pubsub", PUBSUB_NS).finish()
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum MixSessionCapability {
    Supported,
    Unsupported,
    Unknown,
}

pub(crate) fn session_mix_capability(state: &AppState, full_jid: &str) -> MixSessionCapability {
    match super::caps::verified_caps_has_any_feature(state, full_jid, &[CORE_NS, PAM_NS]) {
        Some(true) => MixSessionCapability::Supported,
        Some(false) => MixSessionCapability::Unsupported,
        None => MixSessionCapability::Unknown,
    }
}

fn register_mix_iq_relay(state: &Arc<AppState>, id: String, stage: MixIqRelayStage) -> bool {
    state.pending_mix_iq().admit(id, stage, Instant::now())
}

async fn expire_mix_iq_relay(state: &Arc<AppState>, pending: PendingMixIqRelay) {
    let (requester, stanza) = match pending.stage {
        MixIqRelayStage::Participant {
            requester_full_jid,
            original_id,
            expected_from,
            ..
        } => {
            let stanza = relay_error(
                &original_id,
                &expected_from,
                &requester_full_jid,
                "wait",
                "remote-server-timeout",
            );
            (requester_full_jid, stanza)
        }
        MixIqRelayStage::Channel {
            requester_full_jid,
            original_id,
            target_encoded_jid,
            ..
        } => {
            let stanza = relay_error(
                &original_id,
                &target_encoded_jid,
                &requester_full_jid,
                "wait",
                "remote-server-timeout",
            );
            (requester_full_jid, stanza)
        }
    };
    deliver_mix_relay_stanza(state, &requester, stanza).await;
}

pub(crate) fn start_mix_iq_relay_expiry(
    state: Arc<AppState>,
    cancel: tokio_util::sync::CancellationToken,
) {
    let registry = Arc::clone(state.worker_registry());
    registry.supervise(
        "mix-iq-relay-expiry",
        crate::workers::WorkerCriticality::Restartable,
        crate::workers::WorkerMode::Continuous,
        Some(Duration::from_secs(10)),
        cancel.clone(),
        move |heartbeat| {
            let state = Arc::clone(&state);
            let cancel = cancel.clone();
            async move {
                let mut interval = tokio::time::interval(Duration::from_millis(250));
                interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
                loop {
                    tokio::select! {
                        _ = cancel.cancelled() => return Ok(()),
                        _ = interval.tick() => {
                            for pending in state.pending_mix_iq().take_expired(Instant::now()) {
                                expire_mix_iq_relay(&state, pending).await;
                            }
                            heartbeat.ok();
                        }
                    }
                }
            }
        },
    );
}

async fn deliver_mix_relay_stanza(state: &Arc<AppState>, recipient: &str, stanza: String) {
    let Ok(recipient_jid) = CanonicalJid::parse(recipient) else {
        return;
    };
    let domain = recipient_jid.domainpart();
    if same_jid_domain(domain, &state.config.domain) {
        for target in state.sessions_for(recipient) {
            let _ = target.sender.try_send(stanza.clone());
        }
    } else if state.federation_domain_allowed(domain) {
        let _ = state.federation.send(domain, stanza, None).await;
    }
}

async fn relay_vcard_payload(
    state: &Arc<AppState>,
    user: &crate::services::mix::MixAccount,
    request: &RelayPayload,
) -> Result<std::result::Result<String, &'static str>> {
    match request {
        RelayPayload::VCardTemp => Ok(Ok(state
            .mix_service()
            .get_vcard(user.id)
            .await?
            .payload_vcard_temp
            .unwrap_or_else(|| XmlElement::namespaced("vCard", "vcard-temp").finish()))),
        RelayPayload::VCard4 { item_id } => {
            if state
                .mix_service()
                .pep_node(user.id, "urn:xmpp:vcard4")
                .await?
                .is_none()
            {
                return Ok(Err("item-not-found"));
            }
            let items = state
                .mix_service()
                .pep_items(user.id, "urn:xmpp:vcard4", item_id.as_deref(), 1)
                .await?;
            if items.is_empty() {
                return Ok(Err("item-not-found"));
            }
            let mut item_elements = XmlElement::new("items").attr("node", "urn:xmpp:vcard4");
            for (_, payload) in items {
                item_elements.push_validated_fragment(&payload)?;
            }
            Ok(Ok(XmlElement::namespaced("pubsub", PUBSUB_NS)
                .child(item_elements)
                .finish()))
        }
    }
}

fn encoded_participant_full_jid(
    channel_jid: &str,
    participant_id: &str,
    resource: &str,
) -> Result<String> {
    let bare = encoded_participant_jid(channel_jid, participant_id)?;
    crate::jid::canonicalize(&format!("{bare}/{resource}"))
}

async fn handle_channel_relay_request(
    state: &Arc<AppState>,
    request: &RelayIq,
    actor_full: &str,
) -> Result<String> {
    let actor = crate::jid::CanonicalJid::parse(actor_full)?;
    let actor_resource = actor
        .resourcepart()
        .context("MIX IQ relay requires a full participant JID")?;
    let target = crate::jid::CanonicalJid::parse(&request.to)?;
    let (target_id, channel_jid) = decode_participant_jid(&target.bare())?;
    let channel = CanonicalJid::parse_bare(&channel_jid)?;
    let channel_domain = channel.domainpart();
    let local_mix = local_mix_domain(state);
    anyhow::ensure!(
        channel_domain == local_mix,
        "MIX relay channel is not hosted locally"
    );
    let channel_localpart = channel
        .localpart()
        .context("MIX channel lacks a localpart")?;
    let Some(channel) = state
        .mix_service()
        .mix_channel(channel_domain, channel_localpart)
        .await?
    else {
        return Ok(relay_error(
            &request.id,
            &request.to,
            actor_full,
            "cancel",
            "item-not-found",
        ));
    };
    let Some(requester) = state
        .mix_service()
        .mix_participant(channel.id, &actor.bare())
        .await?
    else {
        return Ok(relay_error(
            &request.id,
            &request.to,
            actor_full,
            "auth",
            "forbidden",
        ));
    };
    let target_id = match Uuid::parse_str(&target_id) {
        Ok(target_id) => target_id,
        Err(_) => {
            return Ok(relay_error(
                &request.id,
                &request.to,
                actor_full,
                "modify",
                "jid-malformed",
            ));
        }
    };
    let Some(target_participant) = state
        .mix_service()
        .mix_participant_by_id(channel.id, target_id)
        .await?
    else {
        return Ok(relay_error(
            &request.id,
            &request.to,
            actor_full,
            "cancel",
            "item-not-found",
        ));
    };
    let target_preference = state
        .mix_service()
        .mix_participant_preference(channel.id, &target_participant.jid)
        .await?
        .unwrap_or_default();
    if target_preference.vcard != "allow" {
        return Ok(relay_error(
            &request.id,
            &request.to,
            actor_full,
            "auth",
            "forbidden",
        ));
    }
    let expected_target_bare = encoded_participant_jid(
        &channel.jid(),
        &target_participant.participant_id.to_string(),
    )?;
    anyhow::ensure!(
        target.bare() == expected_target_bare,
        "MIX encoded target does not belong to this channel"
    );
    let mapped_target = if target.resourcepart().is_some() {
        match state
            .mix_service()
            .mix_presence_source_jid(channel.id, &request.to)
            .await?
        {
            Some(source) => Some(source),
            None => {
                return Ok(relay_error(
                    &request.id,
                    &request.to,
                    actor_full,
                    "cancel",
                    "item-not-found",
                ));
            }
        }
    } else {
        None
    };
    let requester_encoded = encoded_participant_full_jid(
        &channel.jid(),
        &requester.participant_id.to_string(),
        actor_resource,
    )?;
    let target_real_jid = mapped_target.unwrap_or_else(|| target_participant.jid.clone());

    let requester_jid = CanonicalJid::parse_bare(&requester.jid)?;
    if same_jid_domain(requester_jid.domainpart(), &state.config.domain) {
        if let Some(username) = requester_jid.localpart() {
            if let Some(user) = state.mix_service().find_enabled_user(username).await? {
                if state
                    .mix_service()
                    .is_blocked(user.id, &channel.jid())
                    .await?
                    || state
                        .mix_service()
                        .is_blocked(user.id, &target_participant.jid)
                        .await?
                {
                    return Ok(relay_error(
                        &request.id,
                        &request.to,
                        actor_full,
                        "auth",
                        "forbidden",
                    ));
                }
            }
        }
    }
    let target_participant_jid = CanonicalJid::parse_bare(&target_participant.jid)?;
    let target_domain = target_participant_jid.domainpart();
    if same_jid_domain(target_domain, &state.config.domain) {
        let Some(target_username) = target_participant_jid.localpart() else {
            return Ok(relay_error(
                &request.id,
                &request.to,
                actor_full,
                "modify",
                "jid-malformed",
            ));
        };
        let Some(target_user) = state
            .mix_service()
            .find_enabled_user(target_username)
            .await?
        else {
            return Ok(relay_error(
                &request.id,
                &request.to,
                actor_full,
                "cancel",
                "item-not-found",
            ));
        };
        if state
            .mix_service()
            .is_blocked(target_user.id, &channel.jid())
            .await?
            || state
                .mix_service()
                .is_blocked(target_user.id, &requester.jid)
                .await?
        {
            return Ok(relay_error(
                &request.id,
                &request.to,
                actor_full,
                "auth",
                "forbidden",
            ));
        }
        let payload = relay_vcard_payload(
            state,
            &target_user,
            request.request.as_ref().context("missing relay request")?,
        )
        .await?;
        return Ok(match payload {
            Ok(payload) => iq_result_to(&request.id, &request.to, actor_full, &payload),
            Err(condition) => {
                relay_error(&request.id, &request.to, actor_full, "cancel", condition)
            }
        });
    }
    if !state.federation_domain_allowed(target_domain) {
        return Ok(relay_error(
            &request.id,
            &request.to,
            actor_full,
            "cancel",
            "remote-server-not-found",
        ));
    }
    let relay_id = Uuid::new_v4().to_string();
    if !register_mix_iq_relay(
        state,
        relay_id.clone(),
        MixIqRelayStage::Channel {
            requester_full_jid: actor_full.to_owned(),
            requester_encoded_jid: requester_encoded.clone(),
            original_id: request.id.clone(),
            target_real_jid: target_real_jid.clone(),
            target_encoded_jid: request.to.clone(),
            channel_jid: channel.jid(),
        },
    ) {
        return Ok(relay_error(
            &request.id,
            &request.to,
            actor_full,
            "wait",
            "resource-constraint",
        ));
    }
    let outbound = relay_iq_xml(request, &relay_id, &requester_encoded, &target_real_jid);
    if !state
        .federation
        .send(target_domain, outbound, Some(channel.jid()))
        .await
    {
        state.pending_mix_iq().remove(&relay_id);
        return Ok(relay_error(
            &request.id,
            &request.to,
            actor_full,
            "wait",
            "remote-server-timeout",
        ));
    }
    Ok(String::new())
}

struct ChannelStanzaDelivery<'a> {
    channel_jid: &'a str,
    recipient: &'a MixParticipant,
    stanza: String,
    authoritative_stanza_id: Option<Uuid>,
    archive: bool,
    encrypted: bool,
    durable: bool,
    wait_for_unknown_caps: bool,
}

async fn deliver_channel_stanza(
    state: &Arc<AppState>,
    delivery: ChannelStanzaDelivery<'_>,
) -> Result<()> {
    let ChannelStanzaDelivery {
        channel_jid,
        recipient,
        stanza,
        authoritative_stanza_id,
        archive,
        encrypted,
        durable,
        wait_for_unknown_caps,
    } = delivery;
    let recipient_jid = match CanonicalJid::parse_bare(&recipient.jid) {
        Ok(jid) => jid,
        Err(error) => {
            record_mix_post_commit_failure(
                state,
                channel_jid,
                &recipient.jid,
                "invalid persisted recipient JID",
                &error,
            );
            if durable {
                return Err(permanent_mix_delivery_error(
                    "invalid-recipient",
                    error.to_string(),
                ));
            }
            return Ok(());
        }
    };
    let domain = recipient_jid.domainpart();
    if same_jid_domain(domain, &state.config.domain) {
        let Some(username) = recipient_jid.localpart() else {
            return Ok(());
        };
        let user = match state.mix_service().find_enabled_user(username).await {
            Ok(user) => user,
            Err(error) => {
                record_mix_post_commit_failure(
                    state,
                    channel_jid,
                    &recipient.jid,
                    "local account lookup",
                    &error,
                );
                if durable {
                    return Err(error);
                }
                return Ok(());
            }
        };
        let Some(user) = user else {
            if durable {
                return Err(permanent_mix_delivery_error(
                    "account-unavailable",
                    "local MIX recipient no longer exists or is disabled",
                ));
            }
            return Ok(());
        };
        // `recipient` is an immutable MIX Core participant/subscription
        // snapshot captured by the channel mutation transaction.  XEP-0405
        // PAM is only an optional account-side roster projection; requiring a
        // PAM row here silently dropped every event for a valid direct Core
        // join.  Account blocking remains a live, fail-closed privacy check.
        let blocked = match state.mix_service().is_blocked(user.id, channel_jid).await {
            Ok(blocked) => blocked,
            Err(error) => {
                record_mix_post_commit_failure(
                    state,
                    channel_jid,
                    &recipient.jid,
                    "blocking lookup",
                    &error,
                );
                if durable {
                    return Err(error);
                }
                return Ok(());
            }
        };
        if blocked {
            if durable {
                return Err(permanent_mix_delivery_error(
                    "policy-cancelled",
                    "recipient currently blocks this MIX channel",
                ));
            }
            return Ok(());
        }
        if archive {
            let authoritative_stanza_id = authoritative_stanza_id
                .context("archived MIX delivery requires an authoritative stanza id")?;
            let archive_id = Uuid::new_v4();
            let client_stanza_id = authoritative_stanza_id.to_string();
            let admission = state
                .mix_service()
                .archive_mix_message_once(
                    archive_id,
                    user.id,
                    channel_jid,
                    authoritative_stanza_id,
                    &stanza,
                    encrypted,
                    Some(&client_stanza_id),
                )
                .await;
            match admission {
                Ok(SourceArchiveAdmission::Stored(_)) => {}
                // The archive projection may have committed immediately
                // before a crash.  A durable outbox retry must continue to
                // live routing; the authoritative stanza-id makes the
                // resulting at-least-once transport delivery deduplicable.
                Ok(SourceArchiveAdmission::Replay(_)) => {}
                Err(error) => {
                    record_mix_post_commit_failure(
                        state,
                        channel_jid,
                        &recipient.jid,
                        "personal MAM archive",
                        &error,
                    );
                    if durable {
                        return Err(error);
                    }
                    return Ok(());
                }
            }
        }
        let local_targets = state.session_entries_for(&recipient.jid);
        let mut had_deliverable_target = false;
        let mut had_unknown_target = false;
        let mut cluster_delivery_failed = false;
        let mut accepted = false;
        for (jid, session) in &local_targets {
            match session_mix_capability(state, jid) {
                MixSessionCapability::Supported => {
                    had_deliverable_target = true;
                    match session.sender.try_send(stanza.clone()) {
                        Ok(()) => accepted = true,
                        Err(error) => {
                            record_mix_post_commit_failure(
                                state,
                                channel_jid,
                                jid,
                                "local session queue",
                                &error,
                            );
                        }
                    }
                }
                MixSessionCapability::Unsupported => {}
                MixSessionCapability::Unknown => had_unknown_target = true,
            }
        }
        let nodes = match state.cluster.lookup_nodes(&recipient.jid).await {
            Ok(nodes) => nodes,
            Err(error) => {
                record_mix_post_commit_failure(
                    state,
                    channel_jid,
                    &recipient.jid,
                    "cluster recipient lookup",
                    &error,
                );
                if durable {
                    return Err(error);
                }
                return Ok(());
            }
        };
        for node_id in nodes {
            if node_id != state.cluster.node_id {
                match state
                    .cluster
                    .send_to_node_mix(&node_id, &recipient.jid, &stanza)
                    .await
                {
                    Ok(receipt) => {
                        if receipt.acknowledged {
                            accepted |= receipt.delivered;
                            had_deliverable_target |= receipt.mix_supported > 0;
                            had_unknown_target |= receipt.mix_unknown > 0;
                        } else {
                            cluster_delivery_failed = true;
                        }
                    }
                    Err(error) => {
                        cluster_delivery_failed = true;
                        record_mix_post_commit_failure(
                            state,
                            channel_jid,
                            &recipient.jid,
                            "cluster queue",
                            &error,
                        );
                    }
                }
            }
        }
        if durable && cluster_delivery_failed && !accepted {
            anyhow::bail!("cluster MIX capability delivery failed");
        }
        if durable
            && !accepted
            && !had_deliverable_target
            && had_unknown_target
            && wait_for_unknown_caps
        {
            return Err(MixCapabilityPending.into());
        }
        if durable && !accepted && !had_deliverable_target && !archive {
            return Err(permanent_mix_delivery_error(
                "capability-unresolved",
                if had_unknown_target {
                    "no resource produced verified MIX capabilities within the bounded wait"
                } else {
                    "no MIX-capable resource was eligible for this non-archived delivery"
                },
            ));
        }
        if durable && had_deliverable_target && !accepted {
            anyhow::bail!("no online MIX resource accepted durable delivery");
        }
    } else if !state.federation_domain_allowed(domain) {
        if durable {
            return Err(permanent_mix_delivery_error(
                "policy-cancelled",
                "recipient federation domain is no longer allowed",
            ));
        }
    } else if !state.federation.send(domain, stanza, None).await {
        record_mix_post_commit_failure(
            state,
            channel_jid,
            &recipient.jid,
            "federation queue rejected stanza",
            &"not accepted",
        );
        if durable {
            anyhow::bail!("federated MIX delivery was not admitted");
        }
    }
    Ok(())
}

fn addressed_mix_delivery(template: &str, recipient: &str) -> Result<String> {
    let stanza = crate::xmpp::xml_util::set_to(template, recipient);
    let document = Document::parse(&stanza).context("invalid durable MIX stanza template")?;
    anyhow::ensure!(
        document.root_element().attribute("to") == Some(recipient),
        "durable MIX stanza could not be addressed"
    );
    Ok(stanza)
}

async fn process_claimed_mix_delivery(
    state: Arc<AppState>,
    delivery: crate::services::mix::ClaimedMixDelivery,
    cancel: tokio_util::sync::CancellationToken,
) -> Result<()> {
    let stanza = match addressed_mix_delivery(&delivery.stanza, &delivery.recipient.jid) {
        Ok(stanza) => stanza,
        Err(error) => {
            let moved = state
                .mix_service()
                .dead_letter_mix_delivery(
                    delivery.delivery_id,
                    delivery.lease_token,
                    "invalid-template",
                    &error.to_string(),
                )
                .await?;
            if !moved {
                tracing::warn!(delivery_id=%delivery.delivery_id, event_id=%delivery.event_id, channel_id=%delivery.channel_id, "lost MIX delivery lease while dead-lettering an invalid template");
            }
            return Ok(());
        }
    };

    let mut operation = Box::pin(tokio::time::timeout(
        Duration::from_secs(20),
        deliver_channel_stanza(
            &state,
            ChannelStanzaDelivery {
                channel_jid: &delivery.channel_jid,
                recipient: &delivery.recipient,
                stanza,
                authoritative_stanza_id: delivery.authoritative_stanza_id,
                archive: delivery.archive,
                encrypted: delivery.encrypted,
                durable: true,
                wait_for_unknown_caps: chrono::Utc::now()
                    .signed_duration_since(delivery.created_at)
                    < chrono::Duration::seconds(30),
            },
        ),
    ));
    let mut renew = tokio::time::interval(Duration::from_secs(10));
    renew.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let result = loop {
        tokio::select! {
            biased;
            _ = cancel.cancelled() => {
                break Err(MixOutboxShutdown.into());
            }
            result = &mut operation => {
                break result
                    .map_err(|_| anyhow::anyhow!("MIX outbox delivery timed out"))
                    .and_then(std::convert::identity);
            }
            _ = renew.tick() => {
                if !state
                    .mix_service()
                    .renew_mix_delivery_lease(delivery.delivery_id, delivery.lease_token)
                    .await?
                {
                    tracing::warn!(delivery_id=%delivery.delivery_id, event_id=%delivery.event_id, channel_id=%delivery.channel_id, "lost MIX delivery lease while an external side effect was in flight");
                    return Ok(());
                }
            }
        }
    };

    let completed = match result {
        Ok(()) => {
            state
                .mix_service()
                .acknowledge_mix_delivery(delivery.delivery_id, delivery.lease_token)
                .await?
        }
        Err(error) => {
            if error.downcast_ref::<MixOutboxShutdown>().is_some() {
                // Do not count an orderly shutdown as a failed attempt. The
                // one-second defer releases the ordered head lease before the
                // process exits, while a possibly accepted network side effect
                // remains safe under stanza-id replay semantics.
                state
                    .mix_service()
                    .defer_mix_delivery(delivery.delivery_id, delivery.lease_token, 1)
                    .await?
            } else if error.downcast_ref::<MixCapabilityPending>().is_some() {
                state
                    .mix_service()
                    .defer_mix_delivery(delivery.delivery_id, delivery.lease_token, 2)
                    .await?
            } else if let Some(permanent) = error.downcast_ref::<PermanentMixDeliveryError>() {
                state
                    .mix_service()
                    .dead_letter_mix_delivery(
                        delivery.delivery_id,
                        delivery.lease_token,
                        permanent.reason,
                        &permanent.detail,
                    )
                    .await?
            } else {
                state
                    .mix_service()
                    .retry_mix_delivery(
                        delivery.delivery_id,
                        delivery.lease_token,
                        delivery.attempt_count,
                        &error.to_string(),
                    )
                    .await?
            }
        }
    };
    if !completed {
        tracing::warn!(delivery_id=%delivery.delivery_id, event_id=%delivery.event_id, channel_id=%delivery.channel_id, "MIX delivery completion lost its lease fence");
    }
    Ok(())
}

enum PamResultRoute {
    Accepted,
    Offline,
}

async fn deliver_claimed_pam_result(
    state: &Arc<AppState>,
    result: &ClaimedPamResult,
) -> Result<PamResultRoute> {
    let target = CanonicalJid::parse(&result.requester_full_jid)?;
    anyhow::ensure!(
        target.resourcepart().is_some(),
        "PAM result target is not a full JID"
    );
    for (jid, session) in state.session_entries_for(&result.requester_full_jid) {
        if jid != result.requester_full_jid || session.user_id != result.user_id {
            continue;
        }
        let (receipt_tx, mut receipt_rx) = tokio::sync::mpsc::unbounded_channel();
        if let Err(error) = session
            .sender
            .try_send_with_transport_receipt(result.response_xml.clone(), receipt_tx)
        {
            if matches!(&error, tokio::sync::mpsc::error::TrySendError::Full(_)) {
                session.sender.disconnect_backpressured_transport();
                session.disconnect.cancel();
            }
            anyhow::bail!("PAM result resource rejected durable delivery: {error}");
        }
        match tokio::time::timeout(Duration::from_secs(5), receipt_rx.recv()).await {
            Ok(Some(())) => return Ok(PamResultRoute::Accepted),
            Ok(None) => anyhow::bail!("PAM result transport closed before taking ownership"),
            Err(_) => {
                // The stanza may still be sitting in the ordered socket
                // queue. Close that transport before a retry can overtake it;
                // the journal remains authoritative for reconnect/retry.
                session.sender.disconnect_backpressured_transport();
                session.disconnect.cancel();
                anyhow::bail!("PAM result transport ownership timed out");
            }
        }
    }
    let nodes = state
        .cluster
        .lookup_nodes(&result.requester_full_jid)
        .await?;
    for node in nodes {
        if node == state.cluster.node_id {
            continue;
        }
        if state
            .cluster
            .send_to_node_exact_account(
                &node,
                &result.requester_full_jid,
                &result.response_xml,
                result.user_id,
            )
            .await?
        {
            return Ok(PamResultRoute::Accepted);
        }
    }
    Ok(PamResultRoute::Offline)
}

async fn process_claimed_pam_result(
    state: Arc<AppState>,
    result: ClaimedPamResult,
    cancel: tokio_util::sync::CancellationToken,
) -> Result<()> {
    let mut delivery = Box::pin(tokio::time::timeout(
        Duration::from_secs(20),
        deliver_claimed_pam_result(&state, &result),
    ));
    let mut renew = tokio::time::interval(Duration::from_secs(10));
    renew.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let routed = loop {
        tokio::select! {
            biased;
            _ = cancel.cancelled() => {
                break Err(MixOutboxShutdown.into());
            }
            routed = &mut delivery => {
                break routed
                    .map_err(|_| anyhow::anyhow!("PAM result delivery timed out"))
                    .and_then(std::convert::identity);
            }
            _ = renew.tick() => {
                if !state
                    .mix_service()
                    .renew_pam_result_lease(result.operation_id, result.lease_token)
                    .await?
                {
                    tracing::warn!(operation_id=%result.operation_id, "lost PAM result lease during delivery");
                    return Ok(());
                }
            }
        }
    };
    let completed = match routed {
        Ok(PamResultRoute::Accepted) => {
            state
                .mix_service()
                .acknowledge_pam_result(result.operation_id, result.lease_token)
                .await?
        }
        Ok(PamResultRoute::Offline) => {
            // Being offline is not a failed business attempt. Preserve the
            // exact response and retry without escalating the attempt count.
            state
                .mix_service()
                .defer_pam_result(result.operation_id, result.lease_token, 5)
                .await?
        }
        Err(error) if error.downcast_ref::<MixOutboxShutdown>().is_some() => {
            state
                .mix_service()
                .defer_pam_result(result.operation_id, result.lease_token, 1)
                .await?
        }
        Err(error) => {
            state
                .mix_service()
                .retry_pam_result(
                    result.operation_id,
                    result.lease_token,
                    result.attempt_count,
                    &error.to_string(),
                )
                .await?
        }
    };
    if !completed {
        tracing::warn!(operation_id=%result.operation_id, "PAM result completion lost its lease fence");
    }
    Ok(())
}

fn record_mix_post_commit_failure(
    state: &AppState,
    channel_jid: &str,
    recipient: &str,
    stage: &str,
    error: &dyn std::fmt::Display,
) {
    state
        .metrics
        .mix_post_commit_delivery_failures_total
        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    state
        .metrics
        .post_accept_side_effect_failures_total
        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    tracing::warn!(
        channel = channel_jid,
        recipient,
        stage,
        error = %error,
        "post-commit MIX delivery was not admitted"
    );
}

/// Supervised durable MIX delivery worker.  Database rows are the authority;
/// the timer is only a wake mechanism.  A crash after personal MAM commit is
/// safe because archive replay continues to the same stanza-id delivery.
pub(crate) fn start_mix_delivery_outbox(
    state: Arc<AppState>,
    cancel: tokio_util::sync::CancellationToken,
) {
    let registry = Arc::clone(state.worker_registry());
    registry.supervise_draining(
        "mix-delivery-outbox",
        crate::workers::WorkerCriticality::Restartable,
        crate::workers::WorkerMode::Continuous,
        Some(Duration::from_secs(30)),
        MIX_OUTBOX_DRAIN_GRACE,
        cancel.clone(),
        move |heartbeat| {
            let state = Arc::clone(&state);
            let cancel = cancel.clone();
            async move {
                let mut next_intent_cleanup = tokio::time::Instant::now();
                loop {
                    tokio::select! {
                        _ = cancel.cancelled() => return Ok(()),
                        _ = tokio::time::sleep(Duration::from_millis(250)) => {}
                    }
                    if tokio::time::Instant::now() >= next_intent_cleanup {
                        // One bounded page per minute is enough to keep replay
                        // retention finite without competing with live MIX
                        // mutations or authority/outbox rows.
                        state
                            .mix_service()
                            .prune_expired_business_intents(512)
                            .await?;
                        state
                            .mix_service()
                            .prune_expired_federated_iq_results(512)
                            .await?;
                        state
                            .mix_service()
                            .reconcile_expired_remote_pam(128)
                            .await?;
                        state.mix_service().prune_expired_pam_results(512).await?;
                        next_intent_cleanup = tokio::time::Instant::now() + Duration::from_secs(60);
                    }
                    let deliveries = state
                        .mix_service()
                        .claim_mix_deliveries(64, 8 * 1024 * 1024)
                        .await?;
                    let pam_results = state.mix_service().claim_pam_results(32).await?;
                    let batch_state = Arc::clone(&state);
                    let batch_cancel = cancel.clone();
                    let mut batch = Box::pin(async move {
                        let mix_state = Arc::clone(&batch_state);
                        let mix_cancel = batch_cancel.clone();
                        let mix_outcomes =
                            stream::iter(deliveries.into_iter().map(move |delivery| {
                                process_claimed_mix_delivery(
                                    Arc::clone(&mix_state),
                                    delivery,
                                    mix_cancel.clone(),
                                )
                            }))
                            .buffer_unordered(16)
                            .collect::<Vec<_>>();
                        let pam_outcomes =
                            stream::iter(pam_results.into_iter().map(move |result| {
                                process_claimed_pam_result(
                                    Arc::clone(&batch_state),
                                    result,
                                    batch_cancel.clone(),
                                )
                            }))
                            // A peer's signed cluster listener processes delivery
                            // receipts in order. Bound concurrent exact-resource
                            // IQs so their transport receipts cannot consume the
                            // two-second correlated ACK window as one burst.
                            .buffer_unordered(2)
                            .collect::<Vec<_>>();
                        let (mix_outcomes, pam_outcomes) =
                            futures::future::join(mix_outcomes, pam_outcomes).await;
                        for outcome in mix_outcomes {
                            if let Err(error) = outcome {
                                // A row retains its fenced lease and becomes
                                // claimable again after expiry. One recipient
                                // cannot restart the supervised worker.
                                tracing::warn!(
                                    ?error,
                                    "MIX delivery attempt failed before completion"
                                );
                            }
                        }
                        for outcome in pam_outcomes {
                            if let Err(error) = outcome {
                                tracing::warn!(
                                    ?error,
                                    "PAM result attempt failed before completion"
                                );
                            }
                        }
                    });
                    // Delivery calls carry their own row-lease renewal, while
                    // this independent pulse proves the worker itself is live
                    // even for an 80-second worst-case batch.
                    let shutdown_requested =
                        complete_mix_outbox_batch(&mut batch, &cancel, || heartbeat.ok()).await;
                    heartbeat.ok();
                    if shutdown_requested {
                        return Ok(());
                    }
                }
            }
        },
    );
}

async fn complete_mix_outbox_batch<F, H>(
    batch: F,
    cancel: &tokio_util::sync::CancellationToken,
    mut heartbeat: H,
) -> bool
where
    F: std::future::Future<Output = ()>,
    H: FnMut(),
{
    tokio::pin!(batch);
    let mut pulse = tokio::time::interval(Duration::from_secs(5));
    pulse.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut batch_mode = MixOutboxBatchMode::Active;
    loop {
        tokio::select! {
            _ = &mut batch => break,
            _ = pulse.tick() => heartbeat(),
            _ = cancel.cancelled(), if batch_mode == MixOutboxBatchMode::Active => {
                // Claims already carry durable side effects and a strict
                // per-recipient sequence. Dropping these futures during an
                // orderly shutdown strands their leases until expiry, so an
                // immediate restart can block every later stanza for that
                // recipient. Stop claiming new work, but let this bounded
                // batch acknowledge, retry, or defer each exact lease.
                batch_mode = MixOutboxBatchMode::Draining;
            },
        }
    }
    batch_mode == MixOutboxBatchMode::Draining
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum MixOutboxBatchMode {
    Active,
    Draining,
}

async fn push_mix_roster_update(
    state: &Arc<AppState>,
    user: &crate::services::mix::MixAccount,
    channel_jid: &str,
    _removed: bool,
) -> Result<()> {
    let Some(change) = state
        .mix_service()
        .latest_roster_change_for_contact(user.id, channel_jid)
        .await?
    else {
        return Ok(());
    };
    let participant_id = if change.removed {
        None
    } else {
        let participant_id = state
            .mix_service()
            .pam_membership(user.id, channel_jid)
            .await?
            .filter(|membership| membership.state == "joined")
            .and_then(|membership| membership.participant_id);
        participant_id
    };
    super::roster::deliver_roster_change(
        state,
        user.id,
        &user.username,
        &change,
        participant_id.as_deref(),
    )
    .await
}

impl ProtocolSession {
    pub(crate) fn mix_domain(&self) -> String {
        local_mix_domain(&self.state)
    }

    /// Intercept MIX/PAM IQs before ordinary entity and PubSub routing.
    pub(crate) async fn try_mix_iq(&self, raw: &str) -> Result<Option<Action>> {
        if let Some(action) = self.try_mix_iq_relay(raw).await? {
            return Ok(Some(action));
        }
        if !mix_iq_route_candidate(raw, &self.mix_domain()) {
            return Ok(None);
        }
        let Some(request) = parse_iq(raw)? else {
            return Ok(None);
        };
        let Some(user) = self.authenticated.as_ref() else {
            return Ok(Some(Action::Send(iq_error_to(
                &request.id,
                request.to.as_deref().unwrap_or(&self.state.config.domain),
                request.from.as_deref().unwrap_or_default(),
                "auth",
                "not-authorized",
            ))));
        };
        let Some(full_jid) = self.full_jid.as_deref() else {
            return Ok(Some(Action::Send(iq_error_to(
                &request.id,
                &self.state.config.domain,
                "",
                "auth",
                "not-authorized",
            ))));
        };
        let actor_bare = format!("{}@{}", user.username, self.state.config.domain);
        if let Some(asserted) = request.from.as_deref() {
            let asserted = crate::jid::canonicalize(asserted).ok();
            if asserted.as_deref() != Some(full_jid)
                && asserted.as_deref() != Some(actor_bare.as_str())
            {
                return Ok(Some(Action::Send(iq_error_to(
                    &request.id,
                    request.to.as_deref().unwrap_or(&self.state.config.domain),
                    full_jid,
                    "auth",
                    "not-authorized",
                ))));
            }
        }
        let own_target = request.to.as_deref().is_some_and(|to| {
            CanonicalJid::parse_bare(to).is_ok_and(|target| target.to_string() == actor_bare)
        });
        if matches!(
            request.operation,
            IqOperation::PamJoin { .. } | IqOperation::PamLeave { .. }
        ) {
            if !own_target || request.kind != "set" {
                return Ok(Some(Action::Send(iq_error_to(
                    &request.id,
                    &actor_bare,
                    full_jid,
                    "modify",
                    "bad-request",
                ))));
            }
            return self
                .handle_pam_request(
                    request,
                    user.id,
                    &user.username,
                    &actor_bare,
                    full_jid,
                    Sha256::digest(raw.as_bytes()).into(),
                )
                .await
                .map(Some);
        }
        let to = request.to.as_deref().unwrap_or_default();
        if !CanonicalJid::parse(to).is_ok_and(|target| target.domainpart() == self.mix_domain()) {
            return Ok(None);
        }
        self.handle_local_mix_iq(request, &actor_bare, full_jid)
            .await
            .map(Some)
    }

    async fn try_mix_iq_relay(&self, raw: &str) -> Result<Option<Action>> {
        let Some(request) = parse_relay_iq(raw)? else {
            return Ok(None);
        };
        if request.kind != "get" || request.request.is_none() {
            return Ok(None);
        }
        let target = match crate::jid::CanonicalJid::parse(&request.to) {
            Ok(target) if target.localpart().is_some() => target,
            _ => return Ok(None),
        };
        let (_target_id, channel_jid) = match decode_participant_jid(&target.bare()) {
            Ok(decoded) => decoded,
            Err(_) => return Ok(None),
        };
        let Some(user) = self.authenticated.as_ref() else {
            return Ok(Some(Action::Send(relay_error(
                &request.id,
                &request.to,
                &request.from,
                "auth",
                "not-authorized",
            ))));
        };
        let Some(full_jid) = self.full_jid.as_deref() else {
            return Ok(Some(Action::Send(relay_error(
                &request.id,
                &request.to,
                &request.from,
                "auth",
                "not-authorized",
            ))));
        };
        if !request.from.is_empty() && request.from != full_jid {
            return Ok(Some(Action::Send(relay_error(
                &request.id,
                &request.to,
                full_jid,
                "auth",
                "not-authorized",
            ))));
        }
        let channel_address = CanonicalJid::parse_bare(&channel_jid)?;
        let channel_domain = channel_address.domainpart();
        if channel_domain == self.mix_domain() {
            let response = handle_channel_relay_request(&self.state, &request, full_jid).await?;
            return Ok(Some(if response.is_empty() {
                Action::None
            } else {
                Action::Send(response)
            }));
        }
        let membership = self
            .state
            .mix_service()
            .pam_membership(user.id, &channel_jid)
            .await?;
        if !membership.is_some_and(|membership| membership.state == "joined")
            || self
                .state
                .mix_service()
                .is_blocked(user.id, &channel_jid)
                .await?
            || !self.state.federation_domain_allowed(channel_domain)
        {
            return Ok(Some(Action::Send(relay_error(
                &request.id,
                &request.to,
                full_jid,
                "auth",
                "forbidden",
            ))));
        }
        let relay_id = Uuid::new_v4().to_string();
        if !register_mix_iq_relay(
            &self.state,
            relay_id.clone(),
            MixIqRelayStage::Participant {
                requester_full_jid: full_jid.to_owned(),
                original_id: request.id.clone(),
                expected_from: request.to.clone(),
                channel_jid: channel_jid.clone(),
            },
        ) {
            return Ok(Some(Action::Send(relay_error(
                &request.id,
                &request.to,
                full_jid,
                "wait",
                "resource-constraint",
            ))));
        }
        let outbound = relay_iq_xml(&request, &relay_id, full_jid, &request.to);
        if !self
            .state
            .federation
            .send(
                channel_domain,
                outbound,
                Some(CanonicalJid::parse(full_jid)?.bare()),
            )
            .await
        {
            self.state.pending_mix_iq().remove(&relay_id);
            return Ok(Some(Action::Send(relay_error(
                &request.id,
                &request.to,
                full_jid,
                "wait",
                "remote-server-timeout",
            ))));
        }
        Ok(Some(Action::None))
    }

    async fn handle_pam_request(
        &self,
        request: OwnedIq,
        user_id: Uuid,
        username: &str,
        actor_bare: &str,
        full_jid: &str,
        request_digest: [u8; 32],
    ) -> Result<Action> {
        match request.operation {
            IqOperation::PamJoin { channel, join } => {
                let channel_address = match CanonicalJid::parse_bare(&channel) {
                    Ok(channel) if channel.localpart().is_some() => channel,
                    _ => {
                        return Ok(Action::Send(iq_error_to(
                            &request.id,
                            actor_bare,
                            full_jid,
                            "modify",
                            "jid-malformed",
                        )));
                    }
                };
                let channel = channel_address.to_string();
                let domain = channel_address.domainpart();
                if domain == self.mix_domain() {
                    let channel_localpart = channel_address
                        .localpart()
                        .expect("MIX channel localpart was checked above");
                    let Some(mix_channel) = self
                        .state
                        .mix_service()
                        .mix_channel(domain, channel_localpart)
                        .await?
                    else {
                        return Ok(Action::Send(iq_error_to(
                            &request.id,
                            actor_bare,
                            full_jid,
                            "cancel",
                            "item-not-found",
                        )));
                    };
                    match self
                        .state
                        .mix_service()
                        .join_mix_channel(
                            mix_channel.id,
                            JoinMixRequest {
                                actor_jid: actor_bare.to_owned(),
                                nick: join.nick.clone(),
                                nodes: join.nodes.clone(),
                                pam_user_id: Some(user_id),
                                invitation: join.invitation.clone(),
                                preference: join.preference.clone(),
                                anonymous_profile: join.anonymous_profile,
                            },
                            None,
                        )
                        .await?
                    {
                        JoinChannelOutcome::Joined {
                            participant,
                            preference,
                            subscriptions,
                            newly_joined: _,
                            roster_change,
                        } => {
                            if let Some(change) = roster_change.as_ref() {
                                let participant_id = participant.participant_id.to_string();
                                self.push_roster_change(
                                    user_id,
                                    username,
                                    change,
                                    Some(&participant_id),
                                )
                                .await?;
                            }
                            let payload = XmlElement::namespaced("client-join", PAM_NS)
                                .validated_fragment(&pam_join_payload(
                                    &channel,
                                    &participant,
                                    &subscriptions,
                                    join.preference.as_ref().map(|_| &preference),
                                    join.anonymous_profile,
                                )?)?
                                .finish();
                            Ok(Action::Send(iq_result_to(
                                &request.id,
                                actor_bare,
                                full_jid,
                                &payload,
                            )))
                        }
                        outcome => Ok(Action::Send(join_error(
                            &request.id,
                            actor_bare,
                            full_jid,
                            outcome,
                        ))),
                    }
                } else {
                    match self
                        .state
                        .mix_service()
                        .lookup_remote_pam_operation(
                            user_id,
                            full_jid,
                            &request.id,
                            &request_digest,
                        )
                        .await?
                    {
                        PamOperationReplay::Replay(response) => return Ok(Action::Send(response)),
                        PamOperationReplay::Pending => {
                            self.state.federation.wake_outbox();
                            return Ok(Action::None);
                        }
                        PamOperationReplay::Conflict => {
                            return Ok(Action::Send(iq_error_to(
                                &request.id,
                                actor_bare,
                                full_jid,
                                "cancel",
                                "conflict",
                            )));
                        }
                        PamOperationReplay::Miss => {}
                    }
                    // Exact retries are journal reads, not new federation
                    // attempts. A later policy change must not replace the
                    // original byte-stable result or strand a pending request.
                    if !self.state.federation_domain_allowed(domain) {
                        return Ok(Action::Send(iq_error_to(
                            &request.id,
                            actor_bare,
                            full_jid,
                            "cancel",
                            "remote-server-not-found",
                        )));
                    }
                    let federation_id = Uuid::new_v4().to_string();
                    let mut join_element = XmlElement::namespaced("join", CORE_NS);
                    for node in &join.nodes {
                        join_element.push_child(XmlElement::new("subscribe").attr("node", node));
                    }
                    if let Some(nick) = join.nick.as_deref() {
                        join_element.push_child(XmlElement::new("nick").text(nick.to_owned()));
                    }
                    let outbound = XmlElement::namespaced("iq", "jabber:server")
                        .attr("type", "set")
                        .attr("from", actor_bare)
                        .attr("to", &channel)
                        .attr("id", &federation_id)
                        .child(join_element)
                        .finish();
                    let admitted = self
                        .state
                        .mix_service()
                        .begin_remote_pam_join(BeginRemotePamJoin {
                            user_id,
                            actor_jid: actor_bare.to_owned(),
                            channel_jid: channel.clone(),
                            nick: join.nick.clone(),
                            nodes: join.nodes.clone(),
                            request_id: federation_id,
                            client_request_id: request.id.clone(),
                            requester_full_jid: full_jid.to_owned(),
                            request_digest,
                            remote_domain: domain.to_owned(),
                            outbound_stanza: outbound,
                            policy: self.state.federation.outbox_policy().into(),
                        })
                        .await?;
                    match admitted {
                        PamOperationReplay::Replay(response) => return Ok(Action::Send(response)),
                        PamOperationReplay::Conflict => {
                            return Ok(Action::Send(iq_error_to(
                                &request.id,
                                actor_bare,
                                full_jid,
                                "cancel",
                                "conflict",
                            )));
                        }
                        PamOperationReplay::Pending => {
                            self.state.federation.wake_outbox();
                        }
                        PamOperationReplay::Miss => {
                            return Ok(Action::Send(iq_error_to(
                                &request.id,
                                actor_bare,
                                full_jid,
                                "wait",
                                "resource-constraint",
                            )));
                        }
                    }
                    Ok(Action::None)
                }
            }
            IqOperation::PamLeave { channel } => {
                let channel_address = match CanonicalJid::parse_bare(&channel) {
                    Ok(channel) if channel.localpart().is_some() => channel,
                    _ => {
                        return Ok(Action::Send(iq_error_to(
                            &request.id,
                            actor_bare,
                            full_jid,
                            "modify",
                            "jid-malformed",
                        )));
                    }
                };
                let channel = channel_address.to_string();
                let domain = channel_address.domainpart();
                if domain == self.mix_domain() {
                    let channel_localpart = channel_address
                        .localpart()
                        .expect("MIX channel localpart was checked above");
                    let Some(mix_channel) = self
                        .state
                        .mix_service()
                        .mix_channel(domain, channel_localpart)
                        .await?
                    else {
                        return Ok(Action::Send(iq_error_to(
                            &request.id,
                            actor_bare,
                            full_jid,
                            "cancel",
                            "item-not-found",
                        )));
                    };
                    let Some(left) = self
                        .state
                        .mix_service()
                        .leave_mix_channel(mix_channel.id, actor_bare, Some(user_id), None)
                        .await?
                    else {
                        return Ok(Action::Send(iq_error_to(
                            &request.id,
                            actor_bare,
                            full_jid,
                            "cancel",
                            "item-not-found",
                        )));
                    };
                    let roster_change = left.roster_change.clone();
                    if let Some(change) = roster_change.as_ref() {
                        self.push_roster_change(user_id, username, change, None)
                            .await?;
                    }
                    let payload = XmlElement::namespaced("client-leave", PAM_NS)
                        .attr("channel", &channel)
                        .child(XmlElement::namespaced("leave", CORE_NS))
                        .finish();
                    Ok(Action::Send(iq_result_to(
                        &request.id,
                        actor_bare,
                        full_jid,
                        &payload,
                    )))
                } else {
                    match self
                        .state
                        .mix_service()
                        .lookup_remote_pam_operation(
                            user_id,
                            full_jid,
                            &request.id,
                            &request_digest,
                        )
                        .await?
                    {
                        PamOperationReplay::Replay(response) => return Ok(Action::Send(response)),
                        PamOperationReplay::Pending => {
                            self.state.federation.wake_outbox();
                            return Ok(Action::None);
                        }
                        PamOperationReplay::Conflict => {
                            return Ok(Action::Send(iq_error_to(
                                &request.id,
                                actor_bare,
                                full_jid,
                                "cancel",
                                "conflict",
                            )));
                        }
                        PamOperationReplay::Miss => {}
                    }
                    if !self.state.federation_domain_allowed(domain) {
                        return Ok(Action::Send(iq_error_to(
                            &request.id,
                            actor_bare,
                            full_jid,
                            "cancel",
                            "remote-server-not-found",
                        )));
                    }
                    let federation_id = Uuid::new_v4().to_string();
                    let outbound = XmlElement::namespaced("iq", "jabber:server")
                        .attr("type", "set")
                        .attr("from", actor_bare)
                        .attr("to", &channel)
                        .attr("id", &federation_id)
                        .child(XmlElement::namespaced("leave", CORE_NS))
                        .finish();
                    let admitted = self
                        .state
                        .mix_service()
                        .begin_remote_pam_leave(BeginRemotePamLeave {
                            user_id,
                            actor_jid: actor_bare.to_owned(),
                            channel_jid: channel.clone(),
                            request_id: federation_id,
                            client_request_id: request.id.clone(),
                            requester_full_jid: full_jid.to_owned(),
                            request_digest,
                            remote_domain: domain.to_owned(),
                            outbound_stanza: outbound,
                            policy: self.state.federation.outbox_policy().into(),
                        })
                        .await?;
                    match admitted {
                        PamOperationReplay::Replay(response) => return Ok(Action::Send(response)),
                        PamOperationReplay::Conflict => {
                            return Ok(Action::Send(iq_error_to(
                                &request.id,
                                actor_bare,
                                full_jid,
                                "cancel",
                                "conflict",
                            )));
                        }
                        PamOperationReplay::Pending => self.state.federation.wake_outbox(),
                        PamOperationReplay::Miss => {
                            return Ok(Action::Send(iq_error_to(
                                &request.id,
                                actor_bare,
                                full_jid,
                                "cancel",
                                "item-not-found",
                            )));
                        }
                    }
                    Ok(Action::None)
                }
            }
            _ => unreachable!("PAM dispatcher only passes PAM requests"),
        }
    }

    async fn handle_local_mix_iq(
        &self,
        request: OwnedIq,
        actor_bare: &str,
        reply_to: &str,
    ) -> Result<Action> {
        let from = request
            .to
            .as_deref()
            .unwrap_or(&self.mix_domain())
            .to_owned();
        if matches!(
            request.operation,
            IqOperation::Mam(_)
                | IqOperation::MamForm
                | IqOperation::MamMetadata
                | IqOperation::MamError(_)
        ) {
            return Ok(Action::SendMany(
                handle_mix_mam_iq(&self.state, &request, actor_bare, &from, reply_to).await?,
            ));
        }
        let response =
            handle_channel_iq(&self.state, &request, actor_bare, &from, reply_to, None).await?;
        Ok(Action::Send(response))
    }

    pub(crate) async fn try_mix_message(
        &self,
        root: Node<'_, '_>,
        raw: &str,
    ) -> Result<Option<Action>> {
        let Some(to) = root.attribute("to") else {
            return Ok(None);
        };
        if !CanonicalJid::parse(to).is_ok_and(|target| target.domainpart() == self.mix_domain()) {
            return Ok(None);
        }
        let Some(user) = self.authenticated.as_ref() else {
            return Ok(Some(Action::Send(stanza_error(
                root,
                "auth",
                "not-authorized",
            ))));
        };
        let Some(full_jid) = self.full_jid.as_deref() else {
            return Ok(Some(Action::Send(stanza_error(
                root,
                "auth",
                "not-authorized",
            ))));
        };
        let actor_bare = format!("{}@{}", user.username, self.state.config.domain);
        let result = process_channel_message(&self.state, &actor_bare, full_jid, raw).await?;
        Ok(Some(result.map_or(Action::None, Action::Send)))
    }

    pub(crate) async fn try_mix_presence(
        &self,
        root: Node<'_, '_>,
        raw: &str,
    ) -> Result<Option<Action>> {
        let Some(to) = root.attribute("to") else {
            return Ok(None);
        };
        if !CanonicalJid::parse(to).is_ok_and(|target| target.domainpart() == self.mix_domain()) {
            return Ok(None);
        }
        let Some(user) = self.authenticated.as_ref() else {
            return Ok(Some(Action::Send(stanza_error(
                root,
                "auth",
                "not-authorized",
            ))));
        };
        let Some(full_jid) = self.full_jid.as_deref() else {
            return Ok(Some(Action::Send(stanza_error(
                root,
                "auth",
                "not-authorized",
            ))));
        };
        let actor_bare = format!("{}@{}", user.username, self.state.config.domain);
        // Directed MIX presence and verified-caps fallback share the exact
        // resource epoch. Record only a successfully applied transition: an
        // error response must not suppress later initialisation. The set is
        // resource-owned and therefore disappears with the session rather
        // than accumulating in a process-global keyed lock/tombstone map.
        let mix_presence_epoch = Arc::clone(&self.mix_presence_gate).lock_owned().await;
        if !mix_presence_route_is_current(
            &self.state,
            full_jid,
            self.connection_id,
            &self.mix_presence_gate,
            false,
        ) {
            return Ok(Some(Action::None));
        }
        let result = process_channel_presence(&self.state, &actor_bare, full_jid, raw).await?;
        if result.is_none() {
            let target = CanonicalJid::parse_bare(to)?.to_string();
            match root.attribute("type").unwrap_or("available") {
                "unavailable" => {
                    self.mix_presence_fallback_suppressed.insert(target);
                }
                "available" => {
                    self.mix_presence_fallback_suppressed.remove(&target);
                }
                _ => {}
            }
        }
        drop(mix_presence_epoch);
        Ok(Some(result.map_or(Action::None, Action::Send)))
    }

    /// XEP-0405 participant-server fan-out for a broadcast presence.  Only a
    /// resource whose verified capabilities advertise MIX is represented in
    /// a channel's presence node.
    pub(crate) async fn forward_presence_to_mix_channels(
        &self,
        kind: &str,
        advertised_capability: MixSessionCapability,
        raw: &str,
    ) -> Result<()> {
        let (Some(user), Some(full_jid)) = (self.authenticated.as_ref(), self.full_jid.as_deref())
        else {
            return Ok(());
        };
        let action = mix_broadcast_presence_action(kind, advertised_capability);
        if action == MixBroadcastPresenceAction::Ignore {
            return Ok(());
        }
        let synthesized_unavailable;
        let projected = if action == MixBroadcastPresenceAction::Retract && kind != "unavailable" {
            synthesized_unavailable = XmlElement::namespaced("presence", "jabber:client")
                .attr("from", full_jid)
                .attr("type", "unavailable")
                .finish();
            synthesized_unavailable.as_str()
        } else {
            raw
        };
        let actor_bare = format!("{}@{}", user.username, self.state.config.domain);
        for membership in self.state.mix_service().pam_memberships(user.id).await? {
            if membership.state != "joined"
                || !membership
                    .subscriptions
                    .iter()
                    .any(|node| node == NODE_PRESENCE)
            {
                continue;
            }
            let Ok(channel) = CanonicalJid::parse_bare(&membership.channel_jid) else {
                tracing::warn!(channel = %membership.channel_jid, "ignored malformed persisted MIX membership JID");
                continue;
            };
            let domain = channel.domainpart();
            let directed = crate::xmpp::xml_util::set_to(
                &crate::xmpp::xml_util::set_from(projected, full_jid),
                &membership.channel_jid,
            );
            if domain == self.mix_domain() {
                let _ =
                    process_channel_presence(&self.state, &actor_bare, full_jid, &directed).await?;
            } else if self.state.federation_domain_allowed(domain) {
                let _ = self
                    .state
                    .federation
                    .send(domain, directed, Some(actor_bare.clone()))
                    .await;
            }
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum MixBroadcastPresenceAction {
    Publish,
    Retract,
    Ignore,
}

fn mix_broadcast_presence_action(
    kind: &str,
    capability: MixSessionCapability,
) -> MixBroadcastPresenceAction {
    match (kind, capability) {
        ("available", MixSessionCapability::Supported) => MixBroadcastPresenceAction::Publish,
        ("available" | "unavailable", _) => MixBroadcastPresenceAction::Retract,
        _ => MixBroadcastPresenceAction::Ignore,
    }
}

fn join_error(id: &str, from: &str, to: &str, outcome: JoinChannelOutcome) -> String {
    let (kind, condition) = match outcome {
        JoinChannelOutcome::Banned => ("auth", "forbidden"),
        JoinChannelOutcome::NotAllowed => ("auth", "registration-required"),
        JoinChannelOutcome::Full => ("wait", "resource-constraint"),
        JoinChannelOutcome::MissingNick => ("modify", "not-acceptable"),
        JoinChannelOutcome::NickConflict => ("cancel", "conflict"),
        JoinChannelOutcome::Joined { .. } => unreachable!(),
    };
    iq_error_to(id, from, to, kind, condition)
}

async fn handle_channel_iq(
    state: &Arc<AppState>,
    request: &OwnedIq,
    actor_bare: &str,
    addressed: &str,
    reply_to: &str,
    federated: Option<&FederatedMixMutation>,
) -> Result<String> {
    let mix_domain = local_mix_domain(state);
    let target = match CanonicalJid::parse_bare(addressed) {
        Ok(target) => target,
        Err(_) => {
            return Ok(iq_error_to(
                &request.id,
                addressed,
                reply_to,
                "modify",
                "jid-malformed",
            ));
        }
    };
    let target_bare = target.to_string();
    let service_request = target.localpart().is_none() && target.domainpart() == mix_domain;
    if service_request {
        return match &request.operation {
            IqOperation::Create { channel } if request.kind == "set" => {
                match state
                    .mix_service()
                    .create_mix_channel(
                        &mix_domain,
                        channel.as_deref(),
                        actor_bare,
                        MAX_CHANNELS_PER_OWNER,
                        federated,
                    )
                    .await?
                {
                    (CreateChannelOutcome::Created(_), localpart) => {
                        let _ =
                            super::mix_muc::maybe_link_local_mirror(state, &localpart, actor_bare)
                                .await?;
                        let payload = XmlElement::namespaced("create", CORE_NS)
                            .attr("channel", &localpart)
                            .finish();
                        Ok(iq_result_to(&request.id, &mix_domain, reply_to, &payload))
                    }
                    (CreateChannelOutcome::Conflict, _) => Ok(iq_error_to(
                        &request.id,
                        &mix_domain,
                        reply_to,
                        "cancel",
                        "conflict",
                    )),
                    (CreateChannelOutcome::QuotaExceeded, _) => Ok(iq_error_to(
                        &request.id,
                        &mix_domain,
                        reply_to,
                        "wait",
                        "resource-constraint",
                    )),
                }
            }
            IqOperation::Destroy { channel } if request.kind == "set" => {
                let Some(channel) = state
                    .mix_service()
                    .mix_channel(&mix_domain, channel)
                    .await?
                else {
                    return Ok(iq_error_to(
                        &request.id,
                        &mix_domain,
                        reply_to,
                        "cancel",
                        "item-not-found",
                    ));
                };
                let local_users = state
                    .mix_service()
                    .local_pam_users_for_channel(&channel.jid())
                    .await?;
                if state
                    .mix_service()
                    .destroy_mix_channel(channel.id, actor_bare, federated)
                    .await?
                {
                    for user_id in local_users {
                        if let Some(user) =
                            state.mix_service().find_enabled_user_by_id(user_id).await?
                        {
                            push_mix_roster_update(state, &user, &channel.jid(), true).await?;
                        }
                    }
                    let payload = XmlElement::namespaced("destroy", CORE_NS)
                        .attr("channel", &channel.localpart)
                        .finish();
                    Ok(iq_result_to(&request.id, &mix_domain, reply_to, &payload))
                } else {
                    Ok(iq_error_to(
                        &request.id,
                        &mix_domain,
                        reply_to,
                        "auth",
                        "forbidden",
                    ))
                }
            }
            IqOperation::Ping
                if request.kind == "get"
                    && !state
                        .config
                        .xmpp_extensions
                        .enabled(northstar_xep_0199::XEP_ID) =>
            {
                Ok(iq_error_to(
                    &request.id,
                    &mix_domain,
                    reply_to,
                    "cancel",
                    "service-unavailable",
                ))
            }
            IqOperation::Ping if request.kind == "get" => {
                Ok(iq_result_to(&request.id, &mix_domain, reply_to, ""))
            }
            IqOperation::RegisterNick(requested) if request.kind == "set" => {
                let nick = requested
                    .clone()
                    .unwrap_or_else(|| Uuid::new_v4().to_string());
                match state
                    .mix_service()
                    .register_mix_nick(&mix_domain, actor_bare, &nick, federated)
                    .await?
                {
                    RegisterMixNickOutcome::Registered { nick: assigned } => {
                        let payload = XmlElement::namespaced("register", MISC_NS)
                            .child(XmlElement::new("nick").text(assigned))
                            .finish();
                        Ok(iq_result_to(&request.id, &mix_domain, reply_to, &payload))
                    }
                    RegisterMixNickOutcome::Conflict => Ok(iq_error_to(
                        &request.id,
                        &mix_domain,
                        reply_to,
                        "cancel",
                        "conflict",
                    )),
                }
            }
            _ => Ok(iq_error_to(
                &request.id,
                &mix_domain,
                reply_to,
                "cancel",
                "service-unavailable",
            )),
        };
    }
    let Some(channel_localpart) = target.localpart() else {
        return Ok(iq_error_to(
            &request.id,
            &target_bare,
            reply_to,
            "modify",
            "jid-malformed",
        ));
    };
    if target.domainpart() != mix_domain {
        return Ok(iq_error_to(
            &request.id,
            &target_bare,
            reply_to,
            "cancel",
            "item-not-found",
        ));
    }
    let Some(channel) = state
        .mix_service()
        .mix_channel(target.domainpart(), channel_localpart)
        .await?
    else {
        return Ok(iq_error_to(
            &request.id,
            &target_bare,
            reply_to,
            "cancel",
            "item-not-found",
        ));
    };
    match &request.operation {
        IqOperation::Join(join) if request.kind == "set" => {
            if federated.is_none()
                && request
                    .from
                    .as_deref()
                    .is_some_and(|from| from.contains('/'))
            {
                return Ok(iq_error_to(
                    &request.id,
                    &channel.jid(),
                    reply_to,
                    "auth",
                    "not-authorized",
                ));
            }
            match state
                .mix_service()
                .join_mix_channel(
                    channel.id,
                    JoinMixRequest {
                        actor_jid: actor_bare.to_owned(),
                        nick: join.nick.clone(),
                        nodes: join.nodes.clone(),
                        pam_user_id: None,
                        invitation: join.invitation.clone(),
                        preference: join.preference.clone(),
                        anonymous_profile: join.anonymous_profile,
                    },
                    federated,
                )
                .await?
            {
                JoinChannelOutcome::Joined {
                    participant,
                    preference,
                    subscriptions,
                    ..
                } => Ok(iq_result_to(
                    &request.id,
                    &channel.jid(),
                    reply_to,
                    &core_join_payload(
                        &participant,
                        &subscriptions,
                        join.preference.as_ref().map(|_| &preference),
                        join.anonymous_profile,
                    )?,
                )),
                outcome => Ok(join_error(&request.id, &channel.jid(), reply_to, outcome)),
            }
        }
        IqOperation::Leave if request.kind == "set" => {
            let Some(left) = state
                .mix_service()
                .leave_mix_channel(channel.id, actor_bare, None, federated)
                .await?
            else {
                return Ok(iq_error_to(
                    &request.id,
                    &channel.jid(),
                    reply_to,
                    "cancel",
                    "item-not-found",
                ));
            };
            let _ = left;
            let payload = XmlElement::namespaced("leave", CORE_NS).finish();
            Ok(iq_result_to(
                &request.id,
                &channel.jid(),
                reply_to,
                &payload,
            ))
        }
        IqOperation::SetNick(nick) if request.kind == "set" => {
            match state
                .mix_service()
                .set_mix_nick(channel.id, actor_bare, nick, federated)
                .await?
            {
                Ok(participant) => {
                    let payload = XmlElement::namespaced("setnick", CORE_NS)
                        .child(
                            XmlElement::new("nick")
                                .text(participant.nick.clone().unwrap_or_default()),
                        )
                        .finish();
                    Ok(iq_result_to(
                        &request.id,
                        &channel.jid(),
                        reply_to,
                        &payload,
                    ))
                }
                Err(SetNickError::NotParticipant) => Ok(iq_error_to(
                    &request.id,
                    &channel.jid(),
                    reply_to,
                    "auth",
                    "forbidden",
                )),
                Err(SetNickError::Conflict) => Ok(iq_error_to(
                    &request.id,
                    &channel.jid(),
                    reply_to,
                    "cancel",
                    "conflict",
                )),
            }
        }
        IqOperation::UpdateSubscription {
            subscribe,
            unsubscribe,
        } if request.kind == "set" => {
            let Some(outcome) = state
                .mix_service()
                .update_mix_subscriptions(channel.id, actor_bare, subscribe, unsubscribe, federated)
                .await?
            else {
                return Ok(iq_error_to(
                    &request.id,
                    &channel.jid(),
                    reply_to,
                    "auth",
                    "forbidden",
                ));
            };
            let mut update = XmlElement::namespaced("update-subscription", CORE_NS);
            for node in &outcome.subscriptions {
                update.push_child(XmlElement::new("subscribe").attr("node", node));
            }
            Ok(iq_result_to(
                &request.id,
                &channel.jid(),
                reply_to,
                &update.finish(),
            ))
        }
        IqOperation::PubSubGet { node, max } if request.kind == "get" => {
            pubsub_get(state, request, &channel, actor_bare, reply_to, node, *max).await
        }
        IqOperation::PubSubPublish {
            node,
            item_count,
            item_ids,
            fields,
            payloads,
        } if request.kind == "set" => {
            pubsub_publish(
                state,
                request,
                &channel,
                actor_bare,
                reply_to,
                node,
                *item_count,
                item_ids,
                fields,
                payloads,
                federated,
            )
            .await
        }
        IqOperation::PubSubRetract { node, item_ids } if request.kind == "set" => {
            pubsub_retract(
                state,
                PubSubRetractRequest {
                    request,
                    channel: &channel,
                    actor: actor_bare,
                    reply_to,
                    node,
                    item_ids,
                    federated,
                },
            )
            .await
        }
        IqOperation::Ping
            if request.kind == "get"
                && !state
                    .config
                    .xmpp_extensions
                    .enabled(northstar_xep_0199::XEP_ID) =>
        {
            Ok(iq_error_to(
                &request.id,
                &channel.jid(),
                reply_to,
                "cancel",
                "service-unavailable",
            ))
        }
        IqOperation::Ping if request.kind == "get" => {
            Ok(iq_result_to(&request.id, &channel.jid(), reply_to, ""))
        }
        IqOperation::UserPreferenceGet if request.kind == "get" => {
            if state
                .mix_service()
                .mix_participant_preference(channel.id, actor_bare)
                .await?
                .is_none()
            {
                return Ok(iq_error_to(
                    &request.id,
                    &channel.jid(),
                    reply_to,
                    "auth",
                    "forbidden",
                ));
            }
            let payload = XmlElement::namespaced("user-preference", ANON_NS)
                .validated_fragment(&preference_template_form())?
                .finish();
            Ok(iq_result_to(
                &request.id,
                &channel.jid(),
                reply_to,
                &payload,
            ))
        }
        IqOperation::UserPreferenceSet(fields) if request.kind == "set" => {
            let current = state
                .mix_service()
                .mix_participant_preference(channel.id, actor_bare)
                .await?
                .unwrap_or_default();
            let preference = parse_preference_submission(fields, Some(&current))?;
            let Some(outcome) = state
                .mix_service()
                .update_mix_participant_preference(channel.id, actor_bare, &preference, federated)
                .await?
            else {
                return Ok(iq_error_to(
                    &request.id,
                    &channel.jid(),
                    reply_to,
                    "modify",
                    "not-acceptable",
                ));
            };
            for (user_id, change) in &outcome.roster_changes {
                if let Some(user) = state
                    .mix_service()
                    .find_enabled_user_by_id(*user_id)
                    .await?
                {
                    super::roster::deliver_roster_change(
                        state,
                        *user_id,
                        &user.username,
                        change,
                        Some(&outcome.participant.participant_id.to_string()),
                    )
                    .await?;
                }
            }
            let preference_payload = XmlElement::namespaced("user-preference", ANON_NS)
                .validated_fragment(&preference_result_form(&preference))?
                .finish();
            Ok(iq_result_to(
                &request.id,
                &channel.jid(),
                reply_to,
                &preference_payload,
            ))
        }
        IqOperation::Invite { invitee } if request.kind == "get" => {
            let token = format!("{}{}", Uuid::new_v4().simple(), Uuid::new_v4().simple());
            if !state
                .mix_service()
                .issue_mix_invitation(
                    channel.id,
                    actor_bare,
                    invitee,
                    &token,
                    chrono::Duration::hours(1),
                    federated,
                )
                .await?
            {
                return Ok(iq_error_to(
                    &request.id,
                    &channel.jid(),
                    reply_to,
                    "auth",
                    "forbidden",
                ));
            }
            let payload = XmlElement::namespaced("invite", MISC_NS)
                .child(
                    XmlElement::new("invitation")
                        .child(XmlElement::new("inviter").text(actor_bare.to_owned()))
                        .child(XmlElement::new("invitee").text(invitee.to_owned()))
                        .child(XmlElement::new("channel").text(channel.jid()))
                        .child(XmlElement::new("token").text(token)),
                )
                .finish();
            Ok(iq_result_to(
                &request.id,
                &channel.jid(),
                reply_to,
                &payload,
            ))
        }
        _ => Ok(iq_error_to(
            &request.id,
            &channel.jid(),
            reply_to,
            "cancel",
            "feature-not-implemented",
        )),
    }
}

async fn pubsub_get(
    state: &Arc<AppState>,
    request: &OwnedIq,
    channel: &MixChannel,
    actor: &str,
    reply_to: &str,
    node: &str,
    max: i64,
) -> Result<String> {
    if !ALL_NODES.contains(&node) {
        return Ok(iq_error_to(
            &request.id,
            &channel.jid(),
            reply_to,
            "auth",
            "forbidden",
        ));
    }
    // XEP-0403 makes presence a channel-managed node. Clients receive its
    // standard presence fan-out and MUST NOT fetch current state directly via
    // PubSub (MAM remains the explicit historical query path).
    if matches!(node, NODE_MESSAGES | NODE_PRESENCE) {
        return Ok(iq_error_to(
            &request.id,
            &channel.jid(),
            reply_to,
            "cancel",
            "feature-not-implemented",
        ));
    }
    if matches!(node, NODE_ALLOWED | NODE_BANNED) {
        let entries = match state
            .mix_service()
            .authorized_mix_access_entries(channel.id, actor, node == NODE_BANNED, max)
            .await?
        {
            MixReadOutcome::Found(entries) => entries,
            MixReadOutcome::Unauthorized | MixReadOutcome::NotFound => {
                return Ok(iq_error_to(
                    &request.id,
                    &channel.jid(),
                    reply_to,
                    "auth",
                    "forbidden",
                ));
            }
        };
        let mut items = XmlElement::new("items").attr("node", node);
        for entry in &entries {
            items.push_child(XmlElement::new("item").attr("id", entry));
        }
        let payload = XmlElement::namespaced("pubsub", PUBSUB_NS)
            .child(items)
            .finish();
        return Ok(iq_result_to(
            &request.id,
            &channel.jid(),
            reply_to,
            &payload,
        ));
    }
    if node == NODE_JIDMAP {
        let entries = match state
            .mix_service()
            .authorized_mix_jid_map_entries(channel.id, actor, max)
            .await?
        {
            MixReadOutcome::Found(entries) => entries,
            MixReadOutcome::Unauthorized | MixReadOutcome::NotFound => {
                return Ok(iq_error_to(
                    &request.id,
                    &channel.jid(),
                    reply_to,
                    "auth",
                    "forbidden",
                ));
            }
        };
        let mut items = XmlElement::new("items").attr("node", NODE_JIDMAP);
        for (participant_id, jid) in &entries {
            items.push_child(
                XmlElement::new("item").attr("id", participant_id).child(
                    XmlElement::namespaced("participant", ANON_NS)
                        .child(XmlElement::new("jid").text(jid.clone())),
                ),
            );
        }
        let payload = XmlElement::namespaced("pubsub", PUBSUB_NS)
            .child(items)
            .finish();
        return Ok(iq_result_to(
            &request.id,
            &channel.jid(),
            reply_to,
            &payload,
        ));
    }
    let effective_max = if matches!(node, NODE_INFO | NODE_CONFIG) {
        1
    } else {
        max
    };
    let page = match state
        .mix_service()
        .authorized_mix_event_page(channel.id, actor, node, None, effective_max)
        .await?
    {
        MixReadOutcome::Found(page) => page,
        MixReadOutcome::Unauthorized | MixReadOutcome::NotFound => {
            return Ok(iq_error_to(
                &request.id,
                &channel.jid(),
                reply_to,
                "auth",
                "forbidden",
            ));
        }
    };
    let mut items = XmlElement::new("items").attr("node", node);
    for event in page.events.iter().rev() {
        items.push_child(
            XmlElement::new("item")
                .attr("id", &event.item_id)
                .validated_fragment(&event.payload)?,
        );
    }
    let payload = XmlElement::namespaced("pubsub", PUBSUB_NS)
        .child(items)
        .finish();
    Ok(iq_result_to(
        &request.id,
        &channel.jid(),
        reply_to,
        &payload,
    ))
}

fn field_first<'a>(fields: &'a BTreeMap<String, Vec<String>>, name: &str) -> Option<&'a str> {
    fields
        .get(name)
        .and_then(|values| values.first())
        .map(String::as_str)
}

fn field_bool(fields: &BTreeMap<String, Vec<String>>, name: &str, default: bool) -> Result<bool> {
    match field_first(fields, name) {
        None => Ok(default),
        Some("1" | "true") => Ok(true),
        Some("0" | "false") => Ok(false),
        Some(_) => anyhow::bail!("invalid MIX boolean field"),
    }
}

fn validate_form_fields(
    fields: &BTreeMap<String, Vec<String>>,
    allowed: &[&str],
    multi_value: &[&str],
) -> Result<()> {
    for (name, values) in fields {
        anyhow::ensure!(allowed.contains(&name.as_str()), "unknown MIX form field");
        if !multi_value.contains(&name.as_str()) {
            anyhow::ensure!(values.len() == 1, "invalid MIX form value count");
        }
    }
    Ok(())
}

fn validate_fixed_field(
    fields: &BTreeMap<String, Vec<String>>,
    name: &str,
    expected: &str,
) -> Result<()> {
    if let Some(value) = field_first(fields, name) {
        anyhow::ensure!(value == expected, "unsupported MIX configuration value");
    }
    Ok(())
}

fn validate_fixed_config(
    fields: &BTreeMap<String, Vec<String>>,
    channel: &MixChannel,
) -> Result<()> {
    for (name, expected) in [
        ("Messages Node Subscription", "participants"),
        ("Presence Node Subscription", "participants"),
        ("Participants Node Subscription", "participants"),
        (
            "Information Node Subscription",
            if channel.access_model == "open" {
                "anyone"
            } else {
                "participants"
            },
        ),
        ("Allowed Node Subscription", "admins"),
        ("Banned Node Subscription", "admins"),
        ("Configuration Node Access", "admins"),
        ("Information Node Update Rights", "admins"),
        ("Avatar Nodes Update Rights", "admins"),
        ("Participants Must Provide Presence", "0"),
        ("Open Presence", "0"),
    ] {
        validate_fixed_field(fields, name, expected)?;
    }
    if let Some(nodes) = fields.get("Nodes Present") {
        let actual = nodes
            .iter()
            .map(String::as_str)
            .collect::<std::collections::BTreeSet<_>>();
        let expected = [
            "allowed",
            "banned",
            "information",
            "avatar",
            "jidmap-visible",
            "participants",
            "presence",
        ]
        .into_iter()
        .collect::<std::collections::BTreeSet<_>>();
        anyhow::ensure!(
            actual.len() == nodes.len() && actual == expected,
            "unsupported MIX node set"
        );
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn pubsub_publish(
    state: &Arc<AppState>,
    request: &OwnedIq,
    channel: &MixChannel,
    actor: &str,
    reply_to: &str,
    node: &str,
    item_count: usize,
    item_ids: &[String],
    fields: &BTreeMap<String, Vec<String>>,
    payloads: &[String],
    federated: Option<&FederatedMixMutation>,
) -> Result<String> {
    anyhow::ensure!(
        payloads.len() == item_count,
        "MIX publish payload count mismatch"
    );
    match node {
        NODE_AVATAR_DATA | NODE_AVATAR_METADATA => {
            anyhow::ensure!(
                item_count == 1 && item_ids.len() == 1 && payloads.len() == 1,
                "MIX avatar publish requires one identified item"
            );
            anyhow::ensure!(fields.is_empty(), "MIX avatar item cannot contain a form");
            let payload_document =
                Document::parse(&payloads[0]).context("malformed MIX avatar payload")?;
            let payload = payload_document.root_element();
            let valid = if node == NODE_AVATAR_DATA {
                super::pep::valid_avatar_data(&item_ids[0], payload)
            } else {
                super::pep::valid_avatar_metadata(&item_ids[0], payload)
            };
            anyhow::ensure!(valid, "invalid MIX avatar payload");
            if !state
                .mix_service()
                .publish_mix_avatar(
                    channel.id,
                    actor,
                    node,
                    &item_ids[0],
                    &payloads[0],
                    federated,
                )
                .await?
            {
                return Ok(iq_error_to(
                    &request.id,
                    &channel.jid(),
                    reply_to,
                    "auth",
                    "forbidden",
                ));
            }
            let acknowledgement = mix_pubsub_publish_ack(node, &item_ids[0]);
            return Ok(iq_result_to(
                &request.id,
                &channel.jid(),
                reply_to,
                &acknowledgement,
            ));
        }
        NODE_INFO => {
            anyhow::ensure!(item_count == 1, "MIX information publish requires one item");
            validate_form_fields(
                fields,
                &[
                    "FORM_TYPE",
                    "Name",
                    "Description",
                    "Contact",
                    "JID Visibility",
                ],
                &["Contact"],
            )?;
            anyhow::ensure!(
                field_first(fields, "FORM_TYPE") == Some(CORE_NS),
                "invalid MIX information form type"
            );
            let expected_visibility = if channel.jid_visibility == "visible" {
                "jid-mandatory-visible"
            } else if channel.jid_visibility == "maybe" {
                "jid-maybe-visible"
            } else {
                "jid-hidden"
            };
            validate_fixed_field(fields, "JID Visibility", expected_visibility)?;
            let current = state
                .mix_service()
                .mix_channel(&channel.service_domain, &channel.localpart)
                .await?
                .context("MIX channel disappeared")?;
            let name = field_first(fields, "Name").or(current.name.as_deref());
            let description = field_first(fields, "Description").or(current.description.as_deref());
            let contacts = fields.get("Contact").cloned().unwrap_or(current.contacts);
            let item_id = MixService::mix_timestamp_item_id();
            let mutation = state
                .mix_service()
                .update_mix_info(
                    channel.id,
                    actor,
                    MixInfoUpdate {
                        item_id: item_id.clone(),
                        expected_revision: current.revision,
                        name: name.map(str::to_owned),
                        description: description.map(str::to_owned),
                        contacts: contacts.clone(),
                    },
                    federated,
                )
                .await?;
            let admission = match mutation {
                MixMutationOutcome::Applied(admission) => admission,
                MixMutationOutcome::Conflict => {
                    return Ok(iq_error_to(
                        &request.id,
                        &channel.jid(),
                        reply_to,
                        "cancel",
                        "conflict",
                    ));
                }
                MixMutationOutcome::NotFound => {
                    return Ok(iq_error_to(
                        &request.id,
                        &channel.jid(),
                        reply_to,
                        "cancel",
                        "item-not-found",
                    ));
                }
                MixMutationOutcome::Forbidden => {
                    return Ok(iq_error_to(
                        &request.id,
                        &channel.jid(),
                        reply_to,
                        "auth",
                        "forbidden",
                    ));
                }
            };
            // The exact committed payload and recipient snapshot were placed
            // in the durable MIX outbox by the mutation transaction.
            debug_assert_eq!(admission.channel.id, channel.id);
            debug_assert_eq!(admission.node, NODE_INFO);
            debug_assert!(!admission.payload.is_empty());
            let _committed_recipient_count = admission.recipients.len();
            let acknowledgement = mix_pubsub_publish_ack(&admission.node, &admission.item_id);
            return Ok(iq_result_to(
                &request.id,
                &channel.jid(),
                reply_to,
                &acknowledgement,
            ));
        }
        NODE_CONFIG => {
            anyhow::ensure!(
                item_count == 1,
                "MIX configuration publish requires one item"
            );
            validate_form_fields(
                fields,
                &[
                    "FORM_TYPE",
                    "Last Change Made By",
                    "Owner",
                    "Administrator",
                    "Nodes Present",
                    "Messages Node Subscription",
                    "Presence Node Subscription",
                    "Participants Node Subscription",
                    "Information Node Subscription",
                    "Allowed Node Subscription",
                    "Banned Node Subscription",
                    "Configuration Node Access",
                    "Information Node Update Rights",
                    "Avatar Nodes Update Rights",
                    "JID Visibility",
                    "Mandatory Nicks",
                    "Participants Must Provide Presence",
                    "Open Presence",
                    "User Message Retraction",
                    "Administrator Message Retraction Rights",
                    "Participation Addition by Invitation from Participant",
                    "Private Messages",
                    "Enforce Registered Nick",
                    "access_model",
                    "max_participants",
                    "max_events",
                ],
                &["Owner", "Administrator", "Nodes Present"],
            )?;
            anyhow::ensure!(
                field_first(fields, "FORM_TYPE") == Some(ADMIN_NS),
                "invalid MIX administration form type"
            );
            let role = state.mix_service().mix_role(channel.id, actor).await?;
            if role.as_deref() != Some("owner") {
                return Ok(iq_error_to(
                    &request.id,
                    &channel.jid(),
                    reply_to,
                    "auth",
                    "forbidden",
                ));
            }
            validate_fixed_config(fields, channel)?;
            let access_model = field_first(fields, "access_model").unwrap_or(&channel.access_model);
            let visibility = match field_first(fields, "JID Visibility") {
                Some("jid-hidden") => "hidden",
                Some("jid-maybe-visible") => "maybe",
                Some("jid-mandatory-visible") => "visible",
                Some(_) => anyhow::bail!("unsupported MIX JID visibility mode"),
                None => &channel.jid_visibility,
            };
            let nick_required = field_bool(fields, "Mandatory Nicks", channel.nick_required)?;
            let allow_private_messages =
                field_bool(fields, "Private Messages", channel.allow_private_messages)?;
            let allow_participant_invites = field_bool(
                fields,
                "Participation Addition by Invitation from Participant",
                channel.allow_participant_invites,
            )?;
            let allow_user_message_retraction = field_bool(
                fields,
                "User Message Retraction",
                channel.allow_user_message_retraction,
            )?;
            let administrator_retraction_rights =
                match field_first(fields, "Administrator Message Retraction Rights") {
                    None => channel.administrator_retraction_rights.as_str(),
                    Some("admins") => "administrators",
                    Some(value @ ("nobody" | "owners")) => value,
                    Some(_) => anyhow::bail!("invalid MIX administrator retraction rights"),
                };
            let enforce_registered_nick = field_bool(
                fields,
                "Enforce Registered Nick",
                channel.enforce_registered_nick,
            )?;
            let max_participants = field_first(fields, "max_participants")
                .and_then(|value| value.parse().ok())
                .unwrap_or(channel.max_participants);
            let max_events = field_first(fields, "max_events")
                .and_then(|value| value.parse().ok())
                .unwrap_or(channel.max_events);
            let item_id = MixService::mix_timestamp_item_id();
            let mutation = state
                .mix_service()
                .update_mix_config(
                    channel.id,
                    actor,
                    MixConfigUpdate {
                        item_id: item_id.clone(),
                        expected_revision: channel.revision,
                        access_model: access_model.to_owned(),
                        jid_visibility: visibility.to_owned(),
                        nick_required,
                        max_participants,
                        max_events,
                        allow_private_messages,
                        allow_participant_invites,
                        allow_user_message_retraction,
                        administrator_retraction_rights: administrator_retraction_rights.to_owned(),
                        enforce_registered_nick,
                    },
                    MixRoleUpdate {
                        owners: fields.get("Owner").cloned(),
                        administrators: fields.get("Administrator").cloned(),
                    },
                    federated,
                )
                .await?;
            let admission = match mutation {
                MixMutationOutcome::Applied(admission) => admission,
                MixMutationOutcome::Conflict => {
                    return Ok(iq_error_to(
                        &request.id,
                        &channel.jid(),
                        reply_to,
                        "cancel",
                        "conflict",
                    ));
                }
                MixMutationOutcome::NotFound => {
                    return Ok(iq_error_to(
                        &request.id,
                        &channel.jid(),
                        reply_to,
                        "cancel",
                        "item-not-found",
                    ));
                }
                MixMutationOutcome::Forbidden => {
                    return Ok(iq_error_to(
                        &request.id,
                        &channel.jid(),
                        reply_to,
                        "auth",
                        "forbidden",
                    ));
                }
            };
            // The exact committed payload and recipient snapshot were placed
            // in the durable MIX outbox by the mutation transaction.
            debug_assert_eq!(admission.channel.id, channel.id);
            debug_assert_eq!(admission.node, NODE_CONFIG);
            debug_assert!(!admission.payload.is_empty());
            let _committed_recipient_count = admission.recipients.len();
            let acknowledgement = mix_pubsub_publish_ack(&admission.node, &admission.item_id);
            return Ok(iq_result_to(
                &request.id,
                &channel.jid(),
                reply_to,
                &acknowledgement,
            ));
        }
        NODE_ALLOWED | NODE_BANNED => {
            anyhow::ensure!(
                item_count == 1 && item_ids.len() == 1,
                "MIX access publish requires one identified item"
            );
            anyhow::ensure!(
                fields.is_empty(),
                "MIX access items do not contain payloads"
            );
            let pattern = MixService::canonical_mix_access_pattern(&item_ids[0])?;
            let Some(outcome) = state
                .mix_service()
                .set_mix_access_entry(
                    MixAccessEntryUpdate {
                        channel_id: channel.id,
                        actor,
                        pattern: &pattern,
                        list: if node == NODE_BANNED {
                            MixAccessList::Banned
                        } else {
                            MixAccessList::Allowed
                        },
                        operation: MixAccessEntryOperation::Publish { reason: None },
                    },
                    federated,
                )
                .await?
            else {
                return Ok(iq_error_to(
                    &request.id,
                    &channel.jid(),
                    reply_to,
                    "auth",
                    "forbidden",
                ));
            };
            let _ = (&outcome.removed_presence, &outcome.removed_participants);
            for user_id in outcome.removed_local_users {
                if let Some(user) = state.mix_service().find_enabled_user_by_id(user_id).await? {
                    push_mix_roster_update(state, &user, &channel.jid(), true).await?;
                }
            }
        }
        _ => {
            return Ok(iq_error_to(
                &request.id,
                &channel.jid(),
                reply_to,
                "auth",
                "forbidden",
            ));
        }
    }
    Ok(iq_result_to(
        &request.id,
        &channel.jid(),
        reply_to,
        &mix_empty_pubsub(),
    ))
}

struct PubSubRetractRequest<'a> {
    request: &'a OwnedIq,
    channel: &'a MixChannel,
    actor: &'a str,
    reply_to: &'a str,
    node: &'a str,
    item_ids: &'a [String],
    federated: Option<&'a FederatedMixMutation>,
}

async fn pubsub_retract(
    state: &Arc<AppState>,
    operation: PubSubRetractRequest<'_>,
) -> Result<String> {
    let PubSubRetractRequest {
        request,
        channel,
        actor,
        reply_to,
        node,
        item_ids,
        federated,
    } = operation;
    if matches!(node, NODE_AVATAR_DATA | NODE_AVATAR_METADATA) && item_ids.len() == 1 {
        if !state
            .mix_service()
            .retract_mix_avatar(channel.id, actor, node, &item_ids[0], federated)
            .await?
        {
            return Ok(iq_error_to(
                &request.id,
                &channel.jid(),
                reply_to,
                "auth",
                "forbidden",
            ));
        }
        return Ok(iq_result_to(
            &request.id,
            &channel.jid(),
            reply_to,
            &mix_empty_pubsub(),
        ));
    }
    if !matches!(node, NODE_ALLOWED | NODE_BANNED) || item_ids.len() != 1 {
        return Ok(iq_error_to(
            &request.id,
            &channel.jid(),
            reply_to,
            "auth",
            "forbidden",
        ));
    }
    let pattern = MixService::canonical_mix_access_pattern(&item_ids[0])?;
    let Some(_) = state
        .mix_service()
        .set_mix_access_entry(
            MixAccessEntryUpdate {
                channel_id: channel.id,
                actor,
                pattern: &pattern,
                list: if node == NODE_BANNED {
                    MixAccessList::Banned
                } else {
                    MixAccessList::Allowed
                },
                operation: MixAccessEntryOperation::Retract,
            },
            federated,
        )
        .await?
    else {
        return Ok(iq_error_to(
            &request.id,
            &channel.jid(),
            reply_to,
            "auth",
            "forbidden",
        ));
    };
    Ok(iq_result_to(
        &request.id,
        &channel.jid(),
        reply_to,
        &mix_empty_pubsub(),
    ))
}

async fn handle_mix_mam_iq(
    state: &Arc<AppState>,
    request: &OwnedIq,
    actor: &str,
    addressed: &str,
    reply_to: &str,
) -> Result<Vec<String>> {
    if !state
        .config
        .xmpp_extensions
        .enabled(northstar_xep_0313::XEP_ID)
    {
        return Ok(vec![iq_error_to(
            &request.id,
            addressed,
            reply_to,
            "cancel",
            "feature-not-implemented",
        )]);
    }
    let target = match CanonicalJid::parse_bare(addressed) {
        Ok(target) => target,
        Err(_) => {
            return Ok(vec![iq_error_to(
                &request.id,
                addressed,
                reply_to,
                "modify",
                "jid-malformed",
            )]);
        }
    };
    let mix_domain = local_mix_domain(state);
    let Some(localpart) = target.localpart() else {
        return Ok(vec![iq_error_to(
            &request.id,
            addressed,
            reply_to,
            "cancel",
            "service-unavailable",
        )]);
    };
    let viewer_id = match CanonicalJid::parse_bare(actor) {
        Ok(viewer) if same_jid_domain(viewer.domainpart(), &state.config.domain) => {
            match viewer.localpart() {
                Some(username) => state
                    .mix_service()
                    .find_enabled_user(username)
                    .await?
                    .map(|user| user.id),
                None => None,
            }
        }
        _ => None,
    };
    if target.domainpart() != mix_domain {
        return Ok(vec![iq_error_to(
            &request.id,
            addressed,
            reply_to,
            "cancel",
            "item-not-found",
        )]);
    }
    let Some(channel) = state
        .mix_service()
        .mix_channel(target.domainpart(), localpart)
        .await?
    else {
        return Ok(vec![iq_error_to(
            &request.id,
            addressed,
            reply_to,
            "cancel",
            "item-not-found",
        )]);
    };
    if let IqOperation::MamError(condition) = &request.operation {
        return Ok(vec![iq_error_to(
            &request.id,
            &channel.jid(),
            reply_to,
            stanza_error_type(condition),
            condition,
        )]);
    }
    match &request.operation {
        IqOperation::MamForm => {
            if !matches!(
                state
                    .mix_service()
                    .authorized_mix_mam_boundaries(channel.id, actor, viewer_id)
                    .await?,
                MixReadOutcome::Found(_)
            ) {
                return Ok(vec![iq_error_to(
                    &request.id,
                    &channel.jid(),
                    reply_to,
                    "auth",
                    "forbidden",
                )]);
            }
            return Ok(vec![iq_result_to(
                &request.id,
                &channel.jid(),
                reply_to,
                mam_extended_form(),
            )]);
        }
        IqOperation::MamMetadata => {
            let (first, last) = match state
                .mix_service()
                .authorized_mix_mam_boundaries(channel.id, actor, viewer_id)
                .await?
            {
                MixReadOutcome::Found(boundaries) => boundaries,
                MixReadOutcome::Unauthorized | MixReadOutcome::NotFound => {
                    return Ok(vec![iq_error_to(
                        &request.id,
                        &channel.jid(),
                        reply_to,
                        "auth",
                        "forbidden",
                    )]);
                }
            };
            let boundary = |name: &str, value: Option<ArchiveBoundary>| -> Result<_> {
                value
                    .map(|value| {
                        Ok(XmlElement::dynamic(name)?.attr("id", value.id).attr(
                            "timestamp",
                            value
                                .created_at
                                .to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
                        ))
                    })
                    .transpose()
            };
            let mut metadata = XmlElement::namespaced("metadata", MAM_NS);
            if let Some(start) = boundary("start", first)? {
                metadata.push_child(start);
            }
            if let Some(end) = boundary("end", last)? {
                metadata.push_child(end);
            }
            return Ok(vec![iq_result_to(
                &request.id,
                &channel.jid(),
                reply_to,
                &metadata.finish(),
            )]);
        }
        IqOperation::Mam(_) => {}
        _ => unreachable!("MIX MAM dispatcher received a non-MAM operation"),
    }

    let IqOperation::Mam(parsed) = &request.operation else {
        unreachable!();
    };
    // The MAM protocol parser produces the service-owned query; translate it
    // once so both paging variants share the identical authorized snapshot.
    let query = MamArchiveQuery::from(parsed.query.clone());
    if channel.jid_visibility != "visible" && parsed.query.with_jid.is_some() {
        return Ok(vec![iq_error_to(
            &request.id,
            &channel.jid(),
            reply_to,
            "auth",
            "forbidden",
        )]);
    }
    let page = match state
        .mix_service()
        .authorized_mix_mam_page(channel.id, actor, viewer_id, &query)
        .await?
    {
        MixReadOutcome::Found(page) => page,
        MixReadOutcome::Unauthorized => {
            return Ok(vec![iq_error_to(
                &request.id,
                &channel.jid(),
                reply_to,
                "auth",
                "forbidden",
            )]);
        }
        MixReadOutcome::NotFound => {
            return Ok(vec![iq_error_to(
                &request.id,
                &channel.jid(),
                reply_to,
                "cancel",
                "item-not-found",
            )]);
        }
    };
    let mut replies = Vec::with_capacity(page.events.len() + 1);
    let events: Box<dyn Iterator<Item = &MixEvent>> = if parsed.flip_page {
        Box::new(page.events.iter().rev())
    } else {
        Box::new(page.events.iter())
    };
    for event in events {
        let mut forwarded = XmlElement::namespaced("forwarded", "urn:xmpp:forward:0").child(
            XmlElement::namespaced("delay", "urn:xmpp:delay").attr(
                "stamp",
                event
                    .created_at
                    .to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
            ),
        );
        forwarded.push_validated_fragment(&event.payload)?;
        let result = XmlElement::namespaced("result", MAM_NS)
            .attr("id", event.id)
            .optional_attr("queryid", parsed.query_id.as_deref())
            .child(forwarded);
        replies.push(
            XmlElement::namespaced("message", "jabber:client")
                .attr("from", channel.jid())
                .attr("to", reply_to)
                .attr("id", Uuid::new_v4())
                .child(result)
                .finish(),
        );
    }
    let mut rsm_page = XmlElement::namespaced("set", "http://jabber.org/protocol/rsm");
    if let (Some(first), Some(last)) = (page.events.first(), page.events.last()) {
        rsm_page.push_child(
            XmlElement::new("first")
                .attr("index", page.first_index)
                .text(first.id.to_string()),
        );
        rsm_page.push_child(XmlElement::new("last").text(last.id.to_string()));
    }
    rsm_page.push_child(XmlElement::new("count").text(page.total.to_string()));
    let fin = XmlElement::namespaced("fin", MAM_NS)
        .attr("complete", page.complete)
        .attr("stable", "true")
        .child(rsm_page);
    replies.push(iq_result_to(
        &request.id,
        &channel.jid(),
        reply_to,
        &fin.finish(),
    ));
    Ok(replies)
}

fn presence_children(raw: &str) -> Result<(String, bool)> {
    let document = Document::parse(raw).context("malformed MIX presence")?;
    let root = document.root_element();
    anyhow::ensure!(root.tag_name().name() == "presence", "not a MIX presence");
    let unavailable = root.attribute("type") == Some("unavailable");
    anyhow::ensure!(
        matches!(
            root.attribute("type"),
            None | Some("available" | "unavailable")
        ),
        "unsupported MIX presence type"
    );
    let mut children = String::new();
    for child in root.children().filter(Node::is_element) {
        if child.tag_name().name() == "mix" && child.tag_name().namespace() == Some(PRESENCE_NS) {
            continue;
        }
        children.push_str(&raw[child.range()]);
    }
    Ok((children, unavailable))
}

async fn process_channel_presence(
    state: &Arc<AppState>,
    actor_bare: &str,
    actor_full: &str,
    raw: &str,
) -> Result<Option<String>> {
    let document = Document::parse(raw).context("malformed MIX presence")?;
    let root = document.root_element();
    let to = root.attribute("to").unwrap_or_default();
    let id = root.attribute("id").unwrap_or_default();
    let target = CanonicalJid::parse_bare(to)?;
    let mix_domain = local_mix_domain(state);
    let Some(channel_localpart) = target.localpart() else {
        return Ok(Some(presence_error(
            id,
            to,
            actor_full,
            "modify",
            "jid-malformed",
        )));
    };
    if target.domainpart() != mix_domain {
        return Ok(None);
    }
    let Some(channel) = state
        .mix_service()
        .mix_channel(&mix_domain, channel_localpart)
        .await?
    else {
        return Ok(Some(presence_error(
            id,
            to,
            actor_full,
            "cancel",
            "item-not-found",
        )));
    };
    let (children, unavailable) = presence_children(raw)?;
    match state
        .mix_service()
        .store_mix_presence(channel.id, actor_bare, actor_full, &children, unavailable)
        .await?
    {
        PresenceOutcome::NotParticipant => Ok(Some(presence_error(
            id,
            &channel.jid(),
            actor_full,
            "auth",
            "forbidden",
        ))),
        PresenceOutcome::NotSharing => Ok(None),
        PresenceOutcome::Unchanged => Ok(None),
        PresenceOutcome::Published | PresenceOutcome::Retracted => Ok(None),
    }
}

/// Remove the disconnected resource from every joined presence node.  This
/// is also called when the client transport disappears without first sending
/// unavailable presence; the database operation is idempotent so a graceful
/// unavailable followed by socket teardown cannot create a duplicate event.
pub(crate) async fn disconnect_mix_presence(
    state: &Arc<AppState>,
    user_id: Uuid,
    actor_bare: &str,
    actor_full: &str,
) -> Result<()> {
    let unavailable = XmlElement::namespaced("presence", "jabber:client")
        .attr("from", actor_full)
        .attr("type", "unavailable")
        .finish();
    for membership in state.mix_service().pam_memberships(user_id).await? {
        if !pam_membership_receives(&membership, NODE_PRESENCE) {
            continue;
        }
        let Ok(channel) = CanonicalJid::parse_bare(&membership.channel_jid) else {
            tracing::warn!(channel = %membership.channel_jid, "ignored malformed persisted MIX membership JID");
            continue;
        };
        let domain = channel.domainpart();
        let directed = crate::xmpp::xml_util::set_to(&unavailable, &membership.channel_jid);
        if domain == local_mix_domain(state) {
            let _ = process_channel_presence(state, actor_bare, actor_full, &directed).await?;
        } else if state.federation_domain_allowed(domain) {
            let _ = state
                .federation
                .send(domain, directed, Some(actor_bare.to_owned()))
                .await;
        }
    }
    Ok(())
}

/// A first presence may arrive before the advertised XEP-0115 hash has been
/// verified. Once capability verification succeeds, publish a conservative
/// available state so a fresh cache or server restart does not permanently
/// omit that resource from MIX. Later presence updates replace this item.
pub(crate) async fn publish_verified_mix_presence(
    state: &Arc<AppState>,
    actor_full: &str,
    expected_connection_id: Uuid,
    expected_caps_generation: u64,
) -> Result<()> {
    let actor = crate::jid::CanonicalJid::parse(actor_full)?;
    let actor_full = actor.to_string();
    // Snapshot only the epoch identity and its shared gate. The authoritative
    // route is deliberately re-read after the async lock acquisition; using a
    // cloned pre-lock session here would let a delayed caps job act on a
    // removed or SM-replaced resource.
    let Some(mix_presence_gate) = state
        .sessions
        .get(&actor_full)
        .filter(|entry| entry.connection_id == expected_connection_id)
        .map(|entry| Arc::clone(&entry.mix_presence_gate))
    else {
        return Ok(());
    };
    let expected_mix_presence_gate = Arc::clone(&mix_presence_gate);
    let Some(username) = actor.localpart() else {
        return Ok(());
    };
    let Some(user) = state.mix_service().find_enabled_user(username).await? else {
        return Ok(());
    };
    let actor_bare = actor.bare();
    let available = XmlElement::namespaced("presence", "jabber:client")
        .attr("from", &actor_full)
        .finish();
    for membership in state.mix_service().pam_memberships(user.id).await? {
        if !pam_membership_receives(&membership, NODE_PRESENCE) {
            continue;
        }
        let Ok(channel) = CanonicalJid::parse_bare(&membership.channel_jid) else {
            tracing::warn!(channel = %membership.channel_jid, "ignored malformed persisted MIX membership JID");
            continue;
        };
        let domain = channel.domainpart();
        let directed = crate::xmpp::xml_util::set_to(&available, &membership.channel_jid);
        // Hold the epoch for only one durable projection. User/membership
        // discovery above is intentionally outside it. Explicit presence or
        // teardown can therefore make progress between channels, and every
        // iteration revalidates the exact route before applying an effect.
        let mix_presence_epoch = Arc::clone(&mix_presence_gate).lock_owned().await;
        let Some((epoch_is_current, fallback_suppressed)) =
            state.sessions.get(&actor_full).map(|entry| {
                (
                    mix_presence_epoch_is_current(
                        entry.connection_id,
                        expected_connection_id,
                        entry
                            .caps_observation_generation
                            .load(std::sync::atomic::Ordering::Acquire),
                        expected_caps_generation,
                        entry.routable.load(std::sync::atomic::Ordering::Acquire),
                        entry.available.load(std::sync::atomic::Ordering::Acquire),
                        Arc::ptr_eq(&entry.mix_presence_gate, &expected_mix_presence_gate),
                    ),
                    mix_presence_fallback_is_suppressed(
                        &entry.mix_presence_fallback_suppressed,
                        &membership.channel_jid,
                    ),
                )
            })
        else {
            break;
        };
        if !epoch_is_current {
            break;
        }
        if fallback_suppressed {
            continue;
        }
        if domain == local_mix_domain(state) {
            let Some(channel) = state
                .mix_service()
                .mix_channel(
                    domain,
                    channel
                        .localpart()
                        .expect("joined MIX channel has a localpart"),
                )
                .await?
            else {
                continue;
            };
            let _ = state
                .mix_service()
                .ensure_mix_presence(channel.id, &actor_bare, &actor_full, "")
                .await?;
        } else if state.federation_domain_allowed(domain) {
            let _ = state
                .federation
                .send(domain, directed, Some(actor_bare.clone()))
                .await;
        }
        drop(mix_presence_epoch);
    }
    Ok(())
}

fn mix_presence_epoch_is_current(
    current_connection_id: uuid::Uuid,
    expected_connection_id: uuid::Uuid,
    current_caps_generation: u64,
    expected_caps_generation: u64,
    routable: bool,
    available: bool,
    same_gate: bool,
) -> bool {
    current_connection_id == expected_connection_id
        && current_caps_generation == expected_caps_generation
        && routable
        && available
        && same_gate
}

pub(crate) fn mix_presence_route_is_current(
    state: &AppState,
    full_jid: &str,
    expected_connection_id: Uuid,
    expected_gate: &Arc<tokio::sync::Mutex<()>>,
    require_available: bool,
) -> bool {
    state.sessions.get(full_jid).is_some_and(|entry| {
        entry.connection_id == expected_connection_id
            && Arc::ptr_eq(&entry.mix_presence_gate, expected_gate)
            && entry.routable.load(std::sync::atomic::Ordering::Acquire)
            && (!require_available || entry.available.load(std::sync::atomic::Ordering::Acquire))
            && !entry.disconnect.is_cancelled()
            && entry.lifecycle.load(std::sync::atomic::Ordering::Acquire) == 0
    })
}

fn mix_presence_fallback_is_suppressed(
    suppressed: &dashmap::DashSet<String>,
    channel_jid: &str,
) -> bool {
    suppressed.contains("*") || suppressed.contains(channel_jid)
}

pub(crate) fn start_mix_presence_recovery(
    state: Arc<AppState>,
    cutoff: chrono::DateTime<chrono::Utc>,
    // The state layer snapshots these targets straight from its own
    // repository query; the persistence-type conversion happens on this
    // boundary so the protocol never names the storage DTO.
    probes: impl IntoIterator<Item = impl Into<MixPresenceProbeTarget>>,
    cancel: tokio_util::sync::CancellationToken,
) {
    let probes: Vec<MixPresenceProbeTarget> = probes.into_iter().map(Into::into).collect();
    let registry = Arc::clone(state.worker_registry());
    registry.supervise(
        "mix-presence-recovery",
        crate::workers::WorkerCriticality::Restartable,
        crate::workers::WorkerMode::OneShot,
        Some(Duration::from_secs(90)),
        cancel,
        move |heartbeat| {
            let state = Arc::clone(&state);
            let probes = probes.clone();
            async move {
        for probe in probes {
            let Ok(participant) = CanonicalJid::parse_bare(&probe.participant_jid) else {
                tracing::warn!(participant = %probe.participant_jid, "ignored malformed persisted MIX participant JID");
                continue;
            };
            let domain = participant.domainpart();
            if same_jid_domain(domain, &state.config.domain) {
                for (full_jid, session) in state.session_entries_for(&probe.participant_jid) {
                    publish_verified_mix_presence(
                        &state,
                        &full_jid,
                        session.connection_id,
                        session
                            .caps_observation_generation
                            .load(std::sync::atomic::Ordering::Acquire),
                    )
                    .await?;
                }
                continue;
            }
            if !state.federation_domain_allowed(domain) { continue; }
            let stanza = XmlElement::namespaced("presence", "jabber:client")
                .attr("type", "probe")
                .attr("from", &probe.channel_jid)
                .attr("to", &probe.participant_jid)
                .finish();
            let _ = state.federation.send(domain, stanza, None).await;
        }
        // The deadline is intentionally short and bounded: a remote resource
        // that cannot answer a startup probe is no longer authoritative
        // current state. A later available presence recreates the item.
        tokio::time::sleep(MIX_IQ_RELAY_TTL).await;
        let expired = match state.mix_service().expire_unrefreshed_mix_presence( cutoff).await {
            Ok(expired) => expired,
            Err(error) => {
                return Err(error).context("failed to expire unrefreshed MIX presence");
            }
        };
        // Expiry and every unavailable projection were committed atomically;
        // the delivery worker owns transport retries.
        let _expired_count = expired.len();
        heartbeat.ok();
        Ok(())
            }
        },
    );
}

fn presence_error(id: &str, from: &str, to: &str, error_type: &str, condition: &str) -> String {
    let condition = XmlElement::dynamic(condition)
        .unwrap_or_else(|_| XmlElement::new("undefined-condition"))
        .attr("xmlns", "urn:ietf:params:xml:ns:xmpp-stanzas");
    XmlElement::namespaced("presence", "jabber:client")
        .attr("type", "error")
        .attr("from", from)
        .attr("to", to)
        .attr("id", id)
        .child(
            XmlElement::new("error")
                .attr("type", error_type)
                .child(condition),
        )
        .finish()
}

fn message_children(raw: &str) -> Result<(String, bool)> {
    let document = Document::parse(raw).context("malformed MIX message")?;
    let root = document.root_element();
    anyhow::ensure!(root.tag_name().name() == "message", "not a MIX message");
    anyhow::ensure!(
        root.attribute("type") == Some("groupchat"),
        "MIX messages must be groupchat"
    );
    let encrypted = is_encrypted(root);
    let mut children = String::new();
    for child in root.children().filter(Node::is_element) {
        let namespace = child.tag_name().namespace();
        if (child.tag_name().name() == "mix" && namespace == Some(CORE_NS))
            || child.tag_name().name() == "delay" && namespace == Some("urn:xmpp:delay")
            || child.tag_name().name() == "occupant-id"
                && namespace == Some("urn:xmpp:occupant-id:0")
            || child.tag_name().name() == "stanza-id" && namespace == Some("urn:xmpp:sid:0")
        {
            continue;
        }
        children.push_str(&raw[child.range()]);
    }
    anyhow::ensure!(!children.is_empty(), "empty MIX message");
    Ok((children, encrypted))
}

fn private_message_children(raw: &str) -> Result<(String, bool, &'static str)> {
    let document = Document::parse(raw).context("malformed MIX private message")?;
    let root = document.root_element();
    anyhow::ensure!(root.tag_name().name() == "message", "not a MIX message");
    let kind = match root.attribute("type") {
        None | Some("normal") => "normal",
        Some("chat") => "chat",
        _ => anyhow::bail!("unsupported MIX private message type"),
    };
    let encrypted = is_encrypted(root);
    let mut children = String::new();
    for child in root.children().filter(Node::is_element) {
        let namespace = child.tag_name().namespace();
        if (child.tag_name().name() == "mix" && matches!(namespace, Some(CORE_NS | PRESENCE_NS)))
            || child.tag_name().name() == "delay" && namespace == Some("urn:xmpp:delay")
            || child.tag_name().name() == "stanza-id" && namespace == Some("urn:xmpp:sid:0")
        {
            continue;
        }
        children.push_str(&raw[child.range()]);
    }
    anyhow::ensure!(!children.is_empty(), "empty MIX private message");
    Ok((children, encrypted, kind))
}

async fn process_private_message(
    state: &Arc<AppState>,
    actor_bare: &str,
    actor_full: &str,
    raw: &str,
    target: &CanonicalJid,
) -> Result<Option<String>> {
    let document = Document::parse(raw).context("malformed MIX private message")?;
    let root = document.root_element();
    let id = root.attribute("id").unwrap_or_default();
    let to = root.attribute("to").unwrap_or_default();
    let (target_id, channel_jid) = match decode_participant_jid(&target.bare()) {
        Ok(value) => value,
        Err(_) => {
            return Ok(Some(message_error(
                id,
                to,
                actor_full,
                "modify",
                "jid-malformed",
            )));
        }
    };
    // A resource-specific private message needs the server-private anonymous
    // resource map. Until an exact mapping exists, fail closed rather than
    // accidentally exposing or addressing the user's real resource.
    if target.resourcepart().is_some() {
        return Ok(Some(message_error(
            id,
            to,
            actor_full,
            "cancel",
            "item-not-found",
        )));
    }
    let channel_address = CanonicalJid::parse_bare(&channel_jid)?;
    let channel_localpart = channel_address
        .localpart()
        .context("encoded MIX target lacks a channel localpart")?;
    let Some(channel) = state
        .mix_service()
        .mix_channel(channel_address.domainpart(), channel_localpart)
        .await?
    else {
        return Ok(Some(message_error(
            id,
            to,
            actor_full,
            "cancel",
            "item-not-found",
        )));
    };
    let recipient_id = match Uuid::parse_str(&target_id) {
        Ok(value) if value.to_string() == target_id => value,
        _ => {
            return Ok(Some(message_error(
                id,
                to,
                actor_full,
                "modify",
                "jid-malformed",
            )));
        }
    };
    let Some((sender, recipient)) = state
        .mix_service()
        .mix_private_message_recipient(channel.id, actor_bare, recipient_id)
        .await?
    else {
        return Ok(Some(message_error(id, to, actor_full, "auth", "forbidden")));
    };
    let (children, encrypted, kind) = private_message_children(raw)?;
    let sender_encoded =
        encoded_participant_jid(&channel.jid(), &sender.participant_id.to_string())?;
    let mut delivery = XmlElement::namespaced("message", "jabber:client")
        .attr("from", sender_encoded)
        .attr("to", &recipient.jid)
        .attr("id", id)
        .attr("type", kind);
    delivery.push_validated_fragment(&children)?;
    // XEP-0404 explicitly forbids the MIX channel from archiving private
    // messages. Participant servers remain free to archive them locally.
    deliver_channel_stanza(
        state,
        ChannelStanzaDelivery {
            channel_jid: &channel.jid(),
            recipient: &recipient,
            stanza: delivery.finish(),
            authoritative_stanza_id: None,
            archive: false,
            encrypted,
            durable: false,
            wait_for_unknown_caps: false,
        },
    )
    .await?;
    Ok(None)
}

fn validate_reflected_mix_identity(root: Node<'_, '_>) -> Result<()> {
    let identities = root
        .children()
        .filter(|node| {
            node.is_element()
                && node.tag_name().name() == "mix"
                && node.tag_name().namespace() == Some(CORE_NS)
        })
        .collect::<Vec<_>>();
    anyhow::ensure!(
        identities.len() == 1,
        "reflected MIX message requires one authoritative identity"
    );
    let mut nick = None;
    let mut jid = None;
    for child in identities[0].children().filter(Node::is_element) {
        anyhow::ensure!(
            !child.children().any(|node| node.is_element()),
            "invalid reflected MIX identity payload"
        );
        match (child.tag_name().name(), child.tag_name().namespace()) {
            ("nick", Some(CORE_NS)) => {
                anyhow::ensure!(nick.is_none(), "duplicate reflected MIX nick");
                nick = Some(MixService::prepare_mix_nick(
                    child.text().unwrap_or_default(),
                )?);
            }
            ("jid", Some(CORE_NS)) => {
                anyhow::ensure!(jid.is_none(), "duplicate reflected MIX JID");
                jid = Some(crate::jid::canonicalize_bare(
                    child.text().unwrap_or_default(),
                )?);
            }
            _ => anyhow::bail!("unknown reflected MIX identity child"),
        }
    }
    Ok(())
}

fn reflected_mix_stanza_id(root: Node<'_, '_>) -> Result<Uuid> {
    let from = crate::jid::CanonicalJid::parse(root.attribute("from").unwrap_or_default())?;
    anyhow::ensure!(
        from.localpart().is_some() && from.resourcepart().is_some(),
        "reflected MIX message requires a channel participant source"
    );
    let channel = from.bare();
    let stanza_ids = root
        .children()
        .filter(|node| {
            node.is_element()
                && node.tag_name().name() == "stanza-id"
                && node.tag_name().namespace() == Some("urn:xmpp:sid:0")
        })
        .collect::<Vec<_>>();
    anyhow::ensure!(
        stanza_ids.len() == 1,
        "reflected MIX message requires one authoritative stanza-id"
    );
    let stanza_id = stanza_ids[0];
    anyhow::ensure!(
        stanza_id
            .attributes()
            .all(|attribute| matches!(attribute.name(), "id" | "by"))
            && !stanza_id.children().any(|node| node.is_element())
            && stanza_id.text().is_none_or(|text| text.trim().is_empty()),
        "invalid reflected MIX stanza-id shape"
    );
    let by = crate::jid::CanonicalJid::parse_bare(stanza_id.attribute("by").unwrap_or_default())?;
    anyhow::ensure!(
        by.to_string() == channel,
        "reflected MIX stanza-id authority does not match the channel"
    );
    let id = stanza_id
        .attribute("id")
        .context("missing MIX stanza-id id")?;
    let id = Uuid::parse_str(id)?;
    anyhow::ensure!(
        id.to_string() == stanza_id.attribute("id").unwrap_or_default(),
        "MIX stanza-id must be a canonical UUID"
    );
    Ok(id)
}

fn validate_reflected_mix_presence_identity(root: Node<'_, '_>) -> Result<()> {
    let identities = root
        .children()
        .filter(|node| {
            node.is_element()
                && node.tag_name().name() == "mix"
                && node.tag_name().namespace() == Some(PRESENCE_NS)
        })
        .collect::<Vec<_>>();
    anyhow::ensure!(
        identities.len() == 1,
        "reflected MIX presence requires one authoritative identity"
    );
    let mut nick = None;
    let mut jid = None;
    for child in identities[0].children().filter(Node::is_element) {
        anyhow::ensure!(
            !child.children().any(|node| node.is_element()),
            "invalid reflected MIX presence identity payload"
        );
        match (child.tag_name().name(), child.tag_name().namespace()) {
            ("nick", Some(PRESENCE_NS)) => {
                anyhow::ensure!(nick.is_none(), "duplicate reflected MIX presence nick");
                nick = Some(MixService::prepare_mix_nick(
                    child.text().unwrap_or_default(),
                )?);
            }
            ("jid", Some(PRESENCE_NS)) => {
                anyhow::ensure!(jid.is_none(), "duplicate reflected MIX presence JID");
                jid = Some(crate::jid::canonicalize(child.text().unwrap_or_default())?);
            }
            _ => anyhow::bail!("unknown reflected MIX presence identity child"),
        }
    }
    Ok(())
}

fn mix_retraction_target(root: Node<'_, '_>) -> Result<Option<Uuid>> {
    let retracts = root
        .children()
        .filter(|node| {
            node.is_element()
                && node.tag_name().name() == "retract"
                && node.tag_name().namespace() == Some(MISC_NS)
        })
        .collect::<Vec<_>>();
    if retracts.is_empty() {
        return Ok(None);
    }
    anyhow::ensure!(retracts.len() == 1, "duplicate MIX retraction");
    let retract = retracts[0];
    anyhow::ensure!(
        retract.attributes().len() == 1
            && retract.attribute("id").is_some()
            && !retract.children().any(|node| node.is_element())
            && retract.text().is_none_or(|text| text.trim().is_empty()),
        "invalid MIX retraction"
    );
    anyhow::ensure!(
        root.children()
            .filter(Node::is_element)
            .all(|child| child == retract),
        "MIX retraction cannot carry a body or another payload"
    );
    let target = retract.attribute("id").unwrap_or_default();
    let target = Uuid::parse_str(target).context("invalid MIX retraction MAM id")?;
    anyhow::ensure!(
        target.to_string() == retract.attribute("id").unwrap_or_default(),
        "MIX retraction id must be a canonical UUID"
    );
    Ok(Some(target))
}

fn trusted_mix_origin_id(root: Node<'_, '_>) -> Result<Option<String>> {
    let origins = root
        .children()
        .filter(|node| {
            node.is_element()
                && node.tag_name().name() == "origin-id"
                && node.tag_name().namespace() == Some("urn:xmpp:sid:0")
        })
        .collect::<Vec<_>>();
    anyhow::ensure!(origins.len() <= 1, "duplicate MIX origin-id");
    let Some(origin) = origins.first() else {
        return Ok(None);
    };
    anyhow::ensure!(
        origin.attributes().len() == 1
            && origin.attribute("id").is_some()
            && !origin.children().any(|node| node.is_element())
            && origin.text().is_none_or(|text| text.trim().is_empty()),
        "invalid MIX origin-id"
    );
    let id = origin.attribute("id").unwrap_or_default();
    anyhow::ensure!(
        !id.is_empty() && id.len() <= 1_024 && !id.chars().any(char::is_control),
        "invalid MIX origin-id value"
    );
    Ok(Some(id.to_owned()))
}

fn mix_replay_semantics(
    operation: &str,
    actor: &str,
    channel: &str,
    target: Option<Uuid>,
    payload: &str,
) -> Vec<u8> {
    let mut commitment =
        Vec::with_capacity(operation.len() + actor.len() + channel.len() + payload.len() + 128);
    let mut append_field = |field: &[u8]| {
        commitment.extend_from_slice(&(field.len() as u64).to_be_bytes());
        commitment.extend_from_slice(field);
    };
    append_field(operation.as_bytes());
    append_field(actor.as_bytes());
    append_field(channel.as_bytes());
    if let Some(target) = target {
        append_field(target.as_bytes());
    } else {
        append_field(&[]);
    }
    append_field(payload.as_bytes());
    commitment
}

fn mix_message_identity(nick: Option<&str>, jid: Option<&str>) -> XmlElement {
    let mut identity = XmlElement::namespaced("mix", CORE_NS);
    if let Some(nick) = nick {
        identity.push_child(XmlElement::new("nick").text(nick));
    }
    if let Some(jid) = jid {
        identity.push_child(XmlElement::new("jid").text(jid));
    }
    identity
}

struct MixChannelMessage<'a> {
    from: &'a str,
    to: Option<&'a str>,
    id: Uuid,
    payload: Option<&'a str>,
    nick: Option<&'a str>,
    jid: Option<&'a str>,
}

fn mix_channel_message(message: MixChannelMessage<'_>) -> Result<String> {
    let mut stanza = XmlElement::namespaced("message", "jabber:client")
        .attr("from", message.from)
        .optional_attr("to", message.to)
        .attr("id", message.id)
        .attr("type", "groupchat");
    if let Some(payload) = message.payload {
        stanza.push_validated_fragment(payload)?;
    }
    stanza.push_child(mix_message_identity(message.nick, message.jid));
    Ok(add_stanza_id(
        &stanza.finish(),
        message.from.split('/').next().unwrap_or(message.from),
        message.id,
    ))
}

fn mix_retraction_action(
    from: &str,
    to: Option<&str>,
    id: Uuid,
    target: Uuid,
    nick: Option<&str>,
    jid: Option<&str>,
) -> String {
    let stanza = XmlElement::namespaced("message", "jabber:client")
        .attr("from", from)
        .optional_attr("to", to)
        .attr("id", id)
        .attr("type", "groupchat")
        .child(XmlElement::namespaced("retract", MISC_NS).attr("id", target))
        .child(mix_message_identity(nick, jid));
    add_stanza_id(&stanza.finish(), from.split('/').next().unwrap_or(from), id)
}

async fn process_channel_message(
    state: &Arc<AppState>,
    actor_bare: &str,
    actor_full: &str,
    raw: &str,
) -> Result<Option<String>> {
    let document = Document::parse(raw).context("malformed MIX message")?;
    let root = document.root_element();
    let to = root.attribute("to").unwrap_or_default().to_owned();
    let id = root.attribute("id").unwrap_or_default().to_owned();
    let target = CanonicalJid::parse(&to)?;
    let mix_domain = local_mix_domain(state);
    if target.domainpart() != mix_domain {
        return Ok(None);
    }
    if target
        .localpart()
        .is_some_and(|localpart| localpart.contains('#'))
    {
        return process_private_message(state, actor_bare, actor_full, raw, &target).await;
    }
    if target.resourcepart().is_some() {
        return Ok(Some(message_error(
            &id,
            &to,
            actor_full,
            "modify",
            "jid-malformed",
        )));
    }
    let Some(channel_localpart) = target.localpart() else {
        return Ok(Some(message_error(
            &id,
            &to,
            actor_full,
            "modify",
            "jid-malformed",
        )));
    };
    let Some(channel) = state
        .mix_service()
        .mix_channel(&mix_domain, channel_localpart)
        .await?
    else {
        return Ok(Some(message_error(
            &id,
            &to,
            actor_full,
            "cancel",
            "item-not-found",
        )));
    };
    let retraction_target = mix_retraction_target(root)?;
    let retraction_identity = retraction_target.map(|target_id| MixReplayIdentity {
        client_id: id.clone(),
        canonical_semantics: mix_replay_semantics(
            "retraction",
            actor_bare,
            &channel.jid(),
            Some(target_id),
            "",
        ),
    });
    let (message_children, message_encrypted, message_replay_identity) =
        if retraction_target.is_none() {
            let (children, encrypted) = message_children(raw)?;
            let replay = trusted_mix_origin_id(root)?.map(|client_id| MixReplayIdentity {
                client_id,
                canonical_semantics: mix_replay_semantics(
                    "message",
                    actor_bare,
                    &channel.jid(),
                    None,
                    &children,
                ),
            });
            (Some(children), encrypted, replay)
        } else {
            (None, false, None)
        };
    if let (Some(target_id), Some(identity)) = (retraction_target, retraction_identity.as_ref()) {
        match state
            .mix_service()
            .lookup_mix_retraction_replay(channel.id, actor_bare, target_id, identity)
            .await?
        {
            MixBusinessReplay::Replay(_) => return Ok(None),
            MixBusinessReplay::Conflict => {
                return Ok(Some(message_error(
                    &id,
                    &channel.jid(),
                    actor_full,
                    "cancel",
                    "conflict",
                )));
            }
            MixBusinessReplay::Miss => {}
        }
    }
    if let Some(identity) = message_replay_identity.as_ref() {
        match state
            .mix_service()
            .lookup_mix_message_replay(channel.id, actor_bare, identity)
            .await?
        {
            MixBusinessReplay::Replay(_) => return Ok(None),
            MixBusinessReplay::Conflict => {
                return Ok(Some(message_error(
                    &id,
                    &channel.jid(),
                    actor_full,
                    "cancel",
                    "conflict",
                )));
            }
            MixBusinessReplay::Miss => {}
        }
    }
    let Some(participant) = state
        .mix_service()
        .mix_participant(channel.id, actor_bare)
        .await?
    else {
        return Ok(Some(message_error(
            &id,
            &channel.jid(),
            actor_full,
            "auth",
            "forbidden",
        )));
    };
    let preference = state
        .mix_service()
        .mix_participant_preference(channel.id, actor_bare)
        .await?
        .unwrap_or_default();
    if let Some(target_id) = retraction_target {
        anyhow::ensure!(
            !id.is_empty() && id.len() <= 1_024 && !id.chars().any(char::is_control),
            "MIX retraction requires a bounded client action id"
        );
        let retraction_id = Uuid::new_v4();
        let now = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
        let archived_actor = if channel.jid_visibility == "visible" {
            actor_bare.to_owned()
        } else {
            encoded_participant_jid(&channel.jid(), &participant.participant_id.to_string())?
        };
        let tombstone = XmlElement::namespaced("message", "jabber:client")
            .attr("from", channel.jid())
            .attr("id", target_id)
            .attr("type", "groupchat")
            .child(
                XmlElement::namespaced("retracted", MISC_NS)
                    .attr("by", archived_actor)
                    .attr("time", now),
            )
            .finish();
        let tombstone = add_stanza_id(&tombstone, &channel.jid(), target_id);
        let archived_jid = (channel.jid_visibility == "visible").then_some(actor_bare);
        let live_jid =
            MixService::participant_jid_visible(&channel, &preference).then_some(actor_bare);
        let archived_action = mix_retraction_action(
            &channel.jid(),
            None,
            retraction_id,
            target_id,
            participant.nick.as_deref(),
            archived_jid,
        );
        let admission = state
            .mix_service()
            .retract_mix_message(RetractMixMessageRequest {
                channel_id: channel.id,
                actor: actor_bare,
                target_id,
                retraction_id,
                tombstone_payload: &tombstone,
                retraction_payload: &archived_action,
                identity: retraction_identity,
                visible_jid: live_jid,
            })
            .await?;
        match admission.outcome {
            RetractMixMessageOutcome::NotFound => {
                return Ok(Some(message_error(
                    &id,
                    &channel.jid(),
                    actor_full,
                    "cancel",
                    "item-not-found",
                )));
            }
            RetractMixMessageOutcome::Forbidden => {
                return Ok(Some(message_error(
                    &id,
                    &channel.jid(),
                    actor_full,
                    "auth",
                    "forbidden",
                )));
            }
            RetractMixMessageOutcome::Retracted => {}
            RetractMixMessageOutcome::Replay(_) => return Ok(None),
            RetractMixMessageOutcome::Conflict => {
                return Ok(Some(message_error(
                    &id,
                    &channel.jid(),
                    actor_full,
                    "cancel",
                    "conflict",
                )));
            }
        }
        return Ok(None);
    }
    let children = message_children.expect("non-retraction MIX message has parsed children");
    let archive_id = Uuid::new_v4();
    let archived_jid = (channel.jid_visibility == "visible").then_some(actor_bare);
    let live_jid = MixService::participant_jid_visible(&channel, &preference).then_some(actor_bare);
    let archive = mix_channel_message(MixChannelMessage {
        from: &channel.jid(),
        to: None,
        id: archive_id,
        payload: Some(&children),
        nick: participant.nick.as_deref(),
        jid: archived_jid,
    })?;
    // The durable archive and subscriber snapshot share the channel-locked
    // transaction. This prevents delivery to a participant who concurrently
    // left and prevents a post-join subscriber from missing an archive that
    // linearized after their subscription.
    let admission = state
        .mix_service()
        .store_mix_message(StoreMixMessageRequest {
            channel_id: channel.id,
            actor: actor_bare,
            item_id: &archive_id.to_string(),
            payload: &archive,
            identity: message_replay_identity,
            delivery_payload: &children,
            visible_jid: live_jid,
            encrypted: message_encrypted,
        })
        .await?;
    match admission.outcome {
        StoreEventOutcome::Stored(_) => {}
        StoreEventOutcome::Replay(_) => return Ok(None),
        StoreEventOutcome::NotParticipant => {
            return Ok(Some(message_error(
                &id,
                &channel.jid(),
                actor_full,
                "auth",
                "forbidden",
            )));
        }
        StoreEventOutcome::Conflict => {
            return Ok(Some(message_error(
                &id,
                &channel.jid(),
                actor_full,
                "cancel",
                "conflict",
            )));
        }
        StoreEventOutcome::TooLarge => {
            return Ok(Some(message_error(
                &id,
                &channel.jid(),
                actor_full,
                "modify",
                "policy-violation",
            )));
        }
    }
    Ok(None)
}

fn message_error(id: &str, from: &str, to: &str, error_type: &str, condition: &str) -> String {
    let condition = XmlElement::dynamic(condition)
        .unwrap_or_else(|_| XmlElement::new("undefined-condition"))
        .attr("xmlns", "urn:ietf:params:xml:ns:xmpp-stanzas");
    XmlElement::namespaced("message", "jabber:client")
        .attr("type", "error")
        .attr("from", from)
        .attr("to", to)
        .attr("id", id)
        .child(
            XmlElement::new("error")
                .attr("type", error_type)
                .child(condition),
        )
        .finish()
}

#[derive(Debug, Eq, PartialEq)]
struct AuthenticatedMixIqActor {
    bare: String,
    reply_to: String,
}

fn authenticated_actor(from: &str, authenticated_domain: &str) -> Result<AuthenticatedMixIqActor> {
    let actor = crate::jid::CanonicalJid::parse(from)?;
    anyhow::ensure!(
        actor.localpart().is_some(),
        "federated MIX actor requires a user JID"
    );
    anyhow::ensure!(
        same_jid_domain(actor.domainpart(), authenticated_domain),
        "federated MIX actor domain is not authenticated"
    );
    Ok(AuthenticatedMixIqActor {
        bare: actor.bare(),
        reply_to: actor.to_string(),
    })
}

fn authenticated_mix_disco_requester(
    from: &str,
    authenticated_domain: &str,
) -> Result<AuthenticatedMixIqActor> {
    let actor = crate::jid::CanonicalJid::parse(from)?;
    anyhow::ensure!(
        same_jid_domain(actor.domainpart(), authenticated_domain),
        "federated MIX disco requester domain is not authenticated"
    );
    Ok(AuthenticatedMixIqActor {
        bare: actor.bare(),
        reply_to: actor.to_string(),
    })
}

fn authenticated_full_actor(from: &str, authenticated_domain: &str) -> Result<String> {
    let actor = crate::jid::CanonicalJid::parse(from)?;
    anyhow::ensure!(
        actor.localpart().is_some(),
        "federated MIX actor requires a user JID"
    );
    anyhow::ensure!(
        actor.resourcepart().is_some(),
        "federated MIX message actor requires a full JID"
    );
    anyhow::ensure!(
        same_jid_domain(actor.domainpart(), authenticated_domain),
        "federated MIX actor domain is not authenticated"
    );
    Ok(actor.to_string())
}

fn authenticated_mix_service(asserted_domain: &str, authenticated_domain: &str) -> bool {
    let Ok(authenticated_domain) = prepare_domainpart(authenticated_domain) else {
        return false;
    };
    prepare_domainpart(asserted_domain)
        .is_ok_and(|asserted| same_jid_domain(&asserted, &authenticated_domain))
}

async fn federated_mix_disco_info(
    state: &Arc<AppState>,
    request: &MixDiscoInfoRequest,
    requester: &AuthenticatedMixIqActor,
) -> Result<String> {
    if let Some(condition) = request.error {
        return Ok(iq_error_to(
            &request.id,
            &request.to,
            &requester.reply_to,
            stanza_error_type(condition),
            condition,
        ));
    }
    if request.node.is_some() {
        return Ok(iq_error_to(
            &request.id,
            &request.to,
            &requester.reply_to,
            "cancel",
            "item-not-found",
        ));
    }
    let target = match CanonicalJid::parse(&request.to) {
        Ok(target)
            if target.resourcepart().is_none()
                && same_jid_domain(target.domainpart(), &local_mix_domain(state)) =>
        {
            target
        }
        _ => {
            return Ok(iq_error_to(
                &request.id,
                &request.to,
                &requester.reply_to,
                "cancel",
                "item-not-found",
            ));
        }
    };
    let muc_domain = local_muc_domain(state);
    let mirror = if let Some(localpart) = target.localpart() {
        let Some(channel) = state
            .mix_service()
            .mix_channel(target.domainpart(), localpart)
            .await?
        else {
            return Ok(iq_error_to(
                &request.id,
                &request.to,
                &requester.reply_to,
                "cancel",
                "item-not-found",
            ));
        };
        if !state
            .mix_service()
            .mix_channel_discoverable_to(&channel, &requester.bare)
            .await?
        {
            // Hidden channels deliberately use item-not-found so disco does
            // not become an existence oracle for remote domains.
            return Ok(iq_error_to(
                &request.id,
                &request.to,
                &requester.reply_to,
                "cancel",
                "item-not-found",
            ));
        }
        let linked = state.config.mix_muc_mirror_enabled
            && state
                .mix_service()
                .mix_muc_mirror_for_mix(channel.id)
                .await?
                .is_some();
        let mirror = super::mix_muc::conditional_mirror_discovery_form(
            state.config.mix_muc_mirror_enabled,
            linked,
            super::mix_muc::MirrorDirection::Muc,
            &muc_domain,
        );
        mix_channel_disco_info_payload(
            channel.name.as_deref().unwrap_or(&channel.localpart),
            channel.allow_user_message_retraction
                || channel.administrator_retraction_rights != "nobody",
            channel.allow_private_messages,
            state
                .config
                .xmpp_extensions
                .enabled(northstar_xep_0313::XEP_ID),
            &mirror,
        )?
    } else {
        let linked = state.config.mix_muc_mirror_enabled
            && state
                .mix_service()
                .mix_muc_mirror_service_complete(target.domainpart())
                .await?;
        let mirror = super::mix_muc::conditional_mirror_discovery_form(
            state.config.mix_muc_mirror_enabled,
            linked,
            super::mix_muc::MirrorDirection::Muc,
            &muc_domain,
        );
        mix_service_disco_info_payload(&state.config.server_name, &mirror)?
    };
    Ok(iq_result_to(
        &request.id,
        &target.to_string(),
        &requester.reply_to,
        &mirror,
    ))
}

fn pam_membership_receives(membership: &PamMembership, node: &str) -> bool {
    membership.state == "joined"
        && membership
            .subscriptions
            .iter()
            .any(|subscription| subscription == node)
}

fn federated_mix_iq_is_mutation(request: &OwnedIq) -> bool {
    request.kind == "set" || matches!(&request.operation, IqOperation::Invite { .. })
}

/// S2S entry point.  The S2S layer must call this only after authenticating
/// `authenticated_domain`; the function independently verifies the stanza's
/// asserted `from` before creating or mutating a remote participant actor.
pub(crate) async fn federated_mix_iq(
    state: Arc<AppState>,
    authenticated_domain: &str,
    raw: String,
) -> Result<bool> {
    if let Some(request) = parse_relay_iq(&raw)? {
        if federated_mix_iq_relay(&state, authenticated_domain, request).await? {
            return Ok(true);
        }
    }
    if let Some(request) = parse_mix_disco_info(&raw)? {
        let requester = authenticated_mix_disco_requester(&request.from, authenticated_domain)?;
        let response = federated_mix_disco_info(&state, &request, &requester).await?;
        let _ = state
            .federation
            .send(authenticated_domain, response, None)
            .await;
        return Ok(true);
    }
    let Some(request) = parse_iq(&raw)? else {
        return Ok(false);
    };
    let from = request.from.as_deref().unwrap_or_default();
    let to = request.to.as_deref().unwrap_or_default();
    let local_mix = local_mix_domain(&state);
    let to_jid = CanonicalJid::parse(to)?;
    if to_jid.domainpart() == local_mix {
        let actor = authenticated_actor(from, authenticated_domain)?;
        let mutation = federated_mix_iq_is_mutation(&request);
        let request_digest: [u8; 32] = Sha256::digest(raw.as_bytes()).into();
        let federated_mutation = mutation.then(|| FederatedMixMutation {
            authenticated_domain: authenticated_domain.to_owned(),
            actor_jid: actor.reply_to.clone(),
            request_id: request.id.clone(),
            request_digest,
            addressed: to_jid.to_string(),
            reply_to: actor.reply_to.clone(),
            policy: state.federation.outbox_policy().into(),
        });
        if mutation {
            match state
                .mix_service()
                .federated_mix_iq_replay(
                    authenticated_domain,
                    &actor.reply_to,
                    &request.id,
                    &request_digest,
                )
                .await?
            {
                FederatedMixIqReplay::Replay(response) => {
                    state
                        .mix_service()
                        .enqueue_s2s_response_batch(
                            authenticated_domain,
                            &[response],
                            state.federation.outbox_policy().into(),
                        )
                        .await?;
                    state.federation.wake_outbox();
                    return Ok(true);
                }
                FederatedMixIqReplay::Conflict => {
                    let response = iq_error_to(
                        &request.id,
                        &to_jid.to_string(),
                        &actor.reply_to,
                        "cancel",
                        "conflict",
                    );
                    state
                        .mix_service()
                        .enqueue_s2s_response_batch(
                            authenticated_domain,
                            &[response],
                            state.federation.outbox_policy().into(),
                        )
                        .await?;
                    state.federation.wake_outbox();
                    return Ok(true);
                }
                FederatedMixIqReplay::Miss => {}
            }
        }
        if matches!(
            request.operation,
            IqOperation::Mam(_)
                | IqOperation::MamForm
                | IqOperation::MamMetadata
                | IqOperation::MamError(_)
        ) {
            let responses = handle_mix_mam_iq(
                &state,
                &request,
                &actor.bare,
                &to_jid.to_string(),
                &actor.reply_to,
            )
            .await?;
            // A MAM response is one ordered result stream followed by one
            // terminal IQ. Admit every stanza into the durable S2S outbox in
            // one transaction so a quota/backend failure can never expose a
            // prefix without its `fin`, nor a `fin` without every result.
            let policy = state.federation.outbox_policy();
            if let Err(error) = state
                .mix_service()
                .enqueue_s2s_response_batch(authenticated_domain, &responses, policy.into())
                .await
            {
                tracing::warn!(
                    domain = authenticated_domain,
                    request_id = %request.id,
                    ?error,
                    "federated MIX MAM stream was rejected atomically"
                );
                let _ = state
                    .federation
                    .send(
                        authenticated_domain,
                        iq_error_to(
                            &request.id,
                            &to_jid.to_string(),
                            &actor.reply_to,
                            "wait",
                            "remote-server-timeout",
                        ),
                        None,
                    )
                    .await;
                return Ok(true);
            }
            state.federation.wake_outbox();
            return Ok(true);
        }
        let response = match handle_channel_iq(
            &state,
            &request,
            &actor.bare,
            &to_jid.to_string(),
            &actor.reply_to,
            federated_mutation.as_ref(),
        )
        .await
        {
            Ok(response) => response,
            Err(error) if mutation => {
                // A process/task can fail after the mutation transaction has
                // atomically committed its exact result (for example while
                // performing a non-authoritative local projection). Recover
                // that result rather than reporting failure or re-executing.
                match state
                    .mix_service()
                    .federated_mix_iq_replay(
                        authenticated_domain,
                        &actor.reply_to,
                        &request.id,
                        &request_digest,
                    )
                    .await?
                {
                    FederatedMixIqReplay::Replay(_) => {
                        tracing::warn!(
                            domain = authenticated_domain,
                            request_id = %request.id,
                            ?error,
                            "recovered committed federated MIX mutation result"
                        );
                        state.federation.wake_outbox();
                        return Ok(true);
                    }
                    FederatedMixIqReplay::Conflict => {
                        let conflict = iq_error_to(
                            &request.id,
                            &to_jid.to_string(),
                            &actor.reply_to,
                            "cancel",
                            "conflict",
                        );
                        state
                            .mix_service()
                            .enqueue_s2s_response_batch(
                                authenticated_domain,
                                &[conflict],
                                state.federation.outbox_policy().into(),
                            )
                            .await?;
                        state.federation.wake_outbox();
                        return Ok(true);
                    }
                    FederatedMixIqReplay::Miss => return Err(error),
                }
            }
            Err(error) => return Err(error),
        };
        if mutation {
            match state
                .mix_service()
                .federated_mix_iq_replay(
                    authenticated_domain,
                    &actor.reply_to,
                    &request.id,
                    &request_digest,
                )
                .await?
            {
                FederatedMixIqReplay::Replay(journaled) => {
                    anyhow::ensure!(
                        journaled == response,
                        "atomic federated MIX result differs from protocol result"
                    );
                    state.federation.wake_outbox();
                }
                FederatedMixIqReplay::Conflict => {
                    let conflict = iq_error_to(
                        &request.id,
                        &to_jid.to_string(),
                        &actor.reply_to,
                        "cancel",
                        "conflict",
                    );
                    state
                        .mix_service()
                        .enqueue_s2s_response_batch(
                            authenticated_domain,
                            &[conflict],
                            state.federation.outbox_policy().into(),
                        )
                        .await?;
                    state.federation.wake_outbox();
                }
                FederatedMixIqReplay::Miss => {
                    let response_kind = Document::parse(&response).ok().and_then(|document| {
                        document.root_element().attribute("type").map(str::to_owned)
                    });
                    anyhow::ensure!(
                        response_kind.as_deref() == Some("error"),
                        "successful federated MIX mutation lacked atomic result admission"
                    );
                    match state
                        .mix_service()
                        .admit_federated_mix_iq_result(
                            authenticated_domain,
                            &actor.reply_to,
                            &request.id,
                            &request_digest,
                            &response,
                            state.federation.outbox_policy().into(),
                        )
                        .await?
                    {
                        FederatedMixIqReplay::Replay(_) => state.federation.wake_outbox(),
                        FederatedMixIqReplay::Conflict => {
                            anyhow::bail!("federated MIX error result raced a changed request")
                        }
                        FederatedMixIqReplay::Miss => {
                            anyhow::bail!("federated MIX error result admission lost its row")
                        }
                    }
                }
            }
        } else {
            let _ = state
                .federation
                .send(authenticated_domain, response, None)
                .await;
        }
        return Ok(true);
    }
    if same_jid_domain(to_jid.domainpart(), &state.config.domain)
        && matches!(request.kind.as_str(), "result" | "error")
    {
        let from_jid = CanonicalJid::parse_bare(from)?;
        anyhow::ensure!(
            authenticated_mix_service(from_jid.domainpart(), authenticated_domain),
            "forged federated MIX response"
        );
        if to_jid.resourcepart().is_some() || to_jid.localpart().is_none() {
            return Ok(false);
        }
        let response_digest: [u8; 32] = Sha256::digest(raw.as_bytes()).into();
        let outcome = if request.kind == "result" {
            let join = parse_remote_pam_success(&raw, from)?;
            state
                .mix_service()
                .complete_remote_pam_success(
                    authenticated_domain,
                    from,
                    to,
                    &request.id,
                    &response_digest,
                    join.as_ref().map(|join| RemotePamJoin {
                        participant_id: &join.participant_id,
                        subscriptions: &join.subscriptions,
                        nick: join.nick.as_deref(),
                    }),
                )
                .await?
        } else {
            let remote_error = parse_remote_iq_error(&raw)?;
            state
                .mix_service()
                .complete_remote_pam_error(
                    authenticated_domain,
                    from,
                    to,
                    &request.id,
                    &response_digest,
                    &remote_error.error_type,
                    &remote_error.condition,
                )
                .await?
        };
        match outcome {
            RemotePamCompletionOutcome::Applied(completion) => {
                debug_assert!(completion.applied);
                debug_assert!(!completion.response_xml.is_empty());
                if let (Some(membership), Some(removed)) =
                    (completion.membership.as_ref(), completion.roster_removed)
                {
                    if let Some(user) = state
                        .mix_service()
                        .find_enabled_user_by_id(membership.user_id)
                        .await?
                    {
                        if let Err(error) =
                            push_mix_roster_update(&state, &user, &membership.channel_jid, removed)
                                .await
                        {
                            tracing::warn!(?error, channel=%membership.channel_jid, "post-commit PAM roster push failed");
                        }
                    }
                }
            }
            RemotePamCompletionOutcome::Replay(completion) => {
                debug_assert!(!completion.applied);
                debug_assert!(!completion.response_xml.is_empty());
            }
            RemotePamCompletionOutcome::Missing => {}
            RemotePamCompletionOutcome::Conflict => {
                tracing::warn!(request_id=%request.id, from, to, "ignored conflicting remote PAM result replay");
            }
        }
        return Ok(true);
    }
    Ok(false)
}

async fn federated_mix_iq_relay(
    state: &Arc<AppState>,
    authenticated_domain: &str,
    request: RelayIq,
) -> Result<bool> {
    if request.from.is_empty() {
        return Ok(false);
    }
    if matches!(request.kind.as_str(), "result" | "error") {
        let Some(pending) = state.pending_mix_iq().get(&request.id) else {
            return Ok(false);
        };
        if pending.expires_at <= Instant::now() {
            if let Some(expired) = state.pending_mix_iq().remove(&request.id) {
                expire_mix_iq_relay(state, expired).await;
            }
            return Ok(true);
        }
        match pending.stage {
            MixIqRelayStage::Participant {
                requester_full_jid,
                original_id,
                expected_from,
                channel_jid,
            } => {
                if request.from != expected_from || request.to != requester_full_jid {
                    return Ok(true);
                }
                let source_domain = CanonicalJid::parse(&request.from)?.domainpart().to_owned();
                anyhow::ensure!(
                    authenticated_mix_service(&source_domain, authenticated_domain),
                    "forged MIX IQ participant response"
                );
                let requester = crate::jid::CanonicalJid::parse(&requester_full_jid)?;
                let Some(username) = requester.localpart() else {
                    state.pending_mix_iq().remove(&request.id);
                    return Ok(true);
                };
                let Some(user) = state.mix_service().find_enabled_user(username).await? else {
                    state.pending_mix_iq().remove(&request.id);
                    return Ok(true);
                };
                if !state
                    .mix_service()
                    .pam_membership(user.id, &channel_jid)
                    .await?
                    .is_some_and(|membership| membership.state == "joined")
                    || state
                        .mix_service()
                        .is_blocked(user.id, &channel_jid)
                        .await?
                {
                    state.pending_mix_iq().remove(&request.id);
                    return Ok(true);
                }
                if state.pending_mix_iq().remove(&request.id).is_none() {
                    return Ok(true);
                }
                let stanza =
                    relay_iq_xml(&request, &original_id, &expected_from, &requester_full_jid);
                deliver_mix_relay_stanza(state, &requester_full_jid, stanza).await;
                return Ok(true);
            }
            MixIqRelayStage::Channel {
                requester_full_jid,
                requester_encoded_jid,
                original_id,
                target_real_jid,
                target_encoded_jid,
                channel_jid,
            } => {
                if request.from != target_real_jid || request.to != requester_encoded_jid {
                    return Ok(true);
                }
                let source_domain = CanonicalJid::parse(&request.from)?.domainpart().to_owned();
                anyhow::ensure!(
                    same_jid_domain(&source_domain, authenticated_domain),
                    "forged MIX IQ target response"
                );
                let local_mix = local_mix_domain(state);
                let channel_address = CanonicalJid::parse_bare(&channel_jid)?;
                let Some(channel_localpart) = channel_address.localpart() else {
                    state.pending_mix_iq().remove(&request.id);
                    return Ok(true);
                };
                let Some(channel) = state
                    .mix_service()
                    .mix_channel(&local_mix, channel_localpart)
                    .await?
                else {
                    state.pending_mix_iq().remove(&request.id);
                    return Ok(true);
                };
                if state
                    .mix_service()
                    .mix_participant(
                        channel.id,
                        &CanonicalJid::parse(&requester_full_jid)?.bare(),
                    )
                    .await?
                    .is_none()
                {
                    state.pending_mix_iq().remove(&request.id);
                    return Ok(true);
                }
                if state.pending_mix_iq().remove(&request.id).is_none() {
                    return Ok(true);
                }
                let stanza = relay_iq_xml(
                    &request,
                    &original_id,
                    &target_encoded_jid,
                    &requester_full_jid,
                );
                deliver_mix_relay_stanza(state, &requester_full_jid, stanza).await;
                return Ok(true);
            }
        }
    }
    if request.kind != "get" {
        return Ok(false);
    }

    let local_mix = local_mix_domain(state);
    let to = crate::jid::CanonicalJid::parse(&request.to)?;
    if to.domainpart() == local_mix && decode_participant_jid(&to.bare()).is_ok() {
        let actor = crate::jid::CanonicalJid::parse(&request.from)?;
        anyhow::ensure!(
            actor.resourcepart().is_some()
                && same_jid_domain(actor.domainpart(), authenticated_domain),
            "federated MIX IQ requester is not an authenticated full JID"
        );
        let response = handle_channel_relay_request(state, &request, &request.from).await?;
        if !response.is_empty() {
            let _ = state
                .federation
                .send(authenticated_domain, response, None)
                .await;
        }
        return Ok(true);
    }

    if same_jid_domain(to.domainpart(), &state.config.domain) {
        let source = crate::jid::CanonicalJid::parse(&request.from)?;
        let (_source_id, channel_jid) = decode_participant_jid(&source.bare())?;
        anyhow::ensure!(
            authenticated_mix_service(source.domainpart(), authenticated_domain),
            "federated MIX IQ source service is not authenticated"
        );
        let Some(username) = to.localpart() else {
            return Ok(false);
        };
        let Some(user) = state.mix_service().find_enabled_user(username).await? else {
            let response = relay_error(
                &request.id,
                &request.to,
                &request.from,
                "cancel",
                "item-not-found",
            );
            let _ = state
                .federation
                .send(authenticated_domain, response, None)
                .await;
            return Ok(true);
        };
        if !state
            .mix_service()
            .pam_membership(user.id, &channel_jid)
            .await?
            .is_some_and(|membership| membership.state == "joined")
            || state
                .mix_service()
                .is_blocked(user.id, &channel_jid)
                .await?
            || (to.resourcepart().is_some() && state.sessions_for(&request.to).is_empty())
        {
            let response =
                relay_error(&request.id, &request.to, &request.from, "auth", "forbidden");
            let _ = state
                .federation
                .send(authenticated_domain, response, None)
                .await;
            return Ok(true);
        }
        let payload = relay_vcard_payload(
            state,
            &user,
            request.request.as_ref().context("missing relay request")?,
        )
        .await?;
        let response = match payload {
            Ok(payload) => iq_result_to(&request.id, &request.to, &request.from, &payload),
            Err(condition) => {
                relay_error(&request.id, &request.to, &request.from, "cancel", condition)
            }
        };
        let _ = state
            .federation
            .send(authenticated_domain, response, None)
            .await;
        return Ok(true);
    }
    Ok(false)
}

pub(crate) async fn federated_mix_message(
    state: Arc<AppState>,
    authenticated_domain: &str,
    raw: String,
) -> Result<bool> {
    let (from, to, id, kind, encrypted, reflected_identity, reflected_stanza_id, validation_error) = {
        let document = Document::parse(&raw).context("malformed federated MIX message")?;
        let root = document.root_element();
        if root.tag_name().name() != "message" {
            return Ok(false);
        }
        let validation_error =
            crate::xmpp::xml_util::validate_routed_message(root, &state.config.xmpp_extensions)
                .err()
                .map(|condition| {
                    (
                        crate::xmpp::xml_util::stanza_error_type(condition),
                        condition,
                    )
                });
        (
            root.attribute("from").unwrap_or_default().to_owned(),
            root.attribute("to").unwrap_or_default().to_owned(),
            root.attribute("id").unwrap_or_default().to_owned(),
            root.attribute("type").unwrap_or("normal").to_owned(),
            is_encrypted(root),
            validate_reflected_mix_identity(root),
            reflected_mix_stanza_id(root),
            validation_error,
        )
    };
    let local_mix = local_mix_domain(&state);
    let to_jid = CanonicalJid::parse(&to)?;
    if let Some((error_type, condition)) = validation_error {
        if kind != "error" {
            let response = message_error(&id, &to, &from, error_type, condition);
            let _ = state
                .federation
                .send(authenticated_domain, response, None)
                .await;
        }
        return Ok(true);
    }
    if to_jid.domainpart() == local_mix {
        let actor_full = authenticated_full_actor(&from, authenticated_domain)?;
        let actor_bare = crate::jid::CanonicalJid::parse(&actor_full)?.bare();
        if let Some(error) = process_channel_message(&state, &actor_bare, &actor_full, &raw).await?
        {
            let _ = state
                .federation
                .send(authenticated_domain, error, None)
                .await;
        }
        return Ok(true);
    }
    if same_jid_domain(to_jid.domainpart(), &state.config.domain) {
        if kind != "groupchat" {
            return Ok(false);
        }
        reflected_identity?;
        let authoritative_stanza_id = reflected_stanza_id?;
        let from_jid = crate::jid::CanonicalJid::parse(&from)?;
        let participant_id = from_jid
            .resourcepart()
            .context("reflected MIX message requires a stable participant resource")?;
        anyhow::ensure!(
            MixService::valid_stable_participant_id(participant_id),
            "invalid reflected MIX stable participant id"
        );
        anyhow::ensure!(
            from_jid.localpart().is_some(),
            "reflected MIX message requires a channel localpart"
        );
        anyhow::ensure!(
            authenticated_mix_service(from_jid.domainpart(), authenticated_domain),
            "forged federated MIX channel message"
        );
        let channel = from_jid.bare();
        let to_jid = crate::jid::CanonicalJid::parse_bare(&to)?;
        let Some(username) = to_jid.localpart() else {
            return Ok(false);
        };
        let Some(user) = state.mix_service().find_enabled_user(username).await? else {
            return Ok(true);
        };
        if !state
            .mix_service()
            .pam_membership(user.id, &channel)
            .await?
            .is_some_and(|membership| pam_membership_receives(&membership, NODE_MESSAGES))
        {
            return Ok(true);
        }
        if state.mix_service().is_blocked(user.id, &channel).await? {
            return Ok(true);
        }
        let personal_archive_id = Uuid::new_v4();
        let source_stanza_id = authoritative_stanza_id.to_string();
        let admission = state
            .mix_service()
            .archive_mix_message_once(
                personal_archive_id,
                user.id,
                &channel,
                authoritative_stanza_id,
                &raw,
                encrypted,
                Some(&source_stanza_id),
            )
            .await?;
        if matches!(admission, SourceArchiveAdmission::Replay(_)) {
            return Ok(true);
        }
        for (jid, session) in state.session_entries_for(&to_jid.to_string()) {
            if session_mix_capability(&state, &jid) == MixSessionCapability::Supported {
                let _ = session.sender.try_send(raw.clone());
            }
        }
        return Ok(true);
    }
    Ok(false)
}

pub(crate) async fn federated_mix_presence(
    state: Arc<AppState>,
    authenticated_domain: &str,
    raw: String,
) -> Result<bool> {
    let (from, to, kind, reflected_identity) = {
        let document = Document::parse(&raw).context("malformed federated MIX presence")?;
        let root = document.root_element();
        if root.tag_name().name() != "presence" {
            return Ok(false);
        }
        (
            root.attribute("from").unwrap_or_default().to_owned(),
            root.attribute("to").unwrap_or_default().to_owned(),
            root.attribute("type").unwrap_or("available").to_owned(),
            validate_reflected_mix_presence_identity(root),
        )
    };
    let to_jid = CanonicalJid::parse(&to)?;
    if kind == "probe" && same_jid_domain(to_jid.domainpart(), &state.config.domain) {
        let channel = crate::jid::CanonicalJid::parse_bare(&from)?;
        anyhow::ensure!(
            channel.localpart().is_some()
                && authenticated_mix_service(channel.domainpart(), authenticated_domain),
            "forged federated MIX presence probe"
        );
        let target = crate::jid::CanonicalJid::parse_bare(&to)?;
        let Some(username) = target.localpart() else {
            return Ok(false);
        };
        let Some(user) = state.mix_service().find_enabled_user(username).await? else {
            return Ok(true);
        };
        if !state
            .mix_service()
            .pam_membership(user.id, &channel.to_string())
            .await?
            .is_some_and(|membership| pam_membership_receives(&membership, NODE_PRESENCE))
            || state
                .mix_service()
                .is_blocked(user.id, &channel.to_string())
                .await?
        {
            return Ok(true);
        }
        for (full_jid, session) in state.session_entries_for(&to) {
            if session.available.load(std::sync::atomic::Ordering::Relaxed)
                && session_mix_capability(&state, &full_jid) == MixSessionCapability::Supported
            {
                let response = XmlElement::namespaced("presence", "jabber:client")
                    .attr("from", &full_jid)
                    .attr("to", channel.to_string())
                    .finish();
                let _ = state
                    .federation
                    .send(authenticated_domain, response, Some(to.clone()))
                    .await;
            }
        }
        return Ok(true);
    }
    let from_jid = crate::jid::CanonicalJid::parse(&from)?;
    let local_mix = local_mix_domain(&state);
    if to_jid.domainpart() == local_mix {
        if from_jid.resourcepart().is_none() {
            // A bare-JID presence to a channel is a state refresh request.
            // The participant server can obtain authoritative presence with
            // MAM/PubSub; silently accepting it as a publication would create
            // an unbounded ghost item.
            return Ok(true);
        }
        let actor = authenticated_full_actor(&from, authenticated_domain)?;
        let _ = presence_children(&raw)?;
        let actor_bare = crate::jid::CanonicalJid::parse(&actor)?.bare();
        if let Some(error) = process_channel_presence(&state, &actor_bare, &actor, &raw).await? {
            let _ = state
                .federation
                .send(authenticated_domain, error, None)
                .await;
        }
        return Ok(true);
    }
    if same_jid_domain(to_jid.domainpart(), &state.config.domain) {
        anyhow::ensure!(
            authenticated_mix_service(from_jid.domainpart(), authenticated_domain),
            "federated MIX presence domain is not authenticated"
        );
        if kind == "error" {
            for (_, session) in state.session_entries_for(&to) {
                let _ = session.sender.try_send(raw.clone());
            }
            return Ok(true);
        }
        let _ = presence_children(&raw)?;
        if from_jid.resourcepart().is_none() {
            return Ok(false);
        }
        reflected_identity?;
        let (_participant_id, channel_jid) = decode_participant_jid(&from_jid.bare())?;
        let to_jid = crate::jid::CanonicalJid::parse_bare(&to)?;
        let Some(username) = to_jid.localpart() else {
            return Ok(false);
        };
        let Some(user) = state.mix_service().find_enabled_user(username).await? else {
            return Ok(true);
        };
        if !state
            .mix_service()
            .pam_membership(user.id, &channel_jid)
            .await?
            .is_some_and(|membership| pam_membership_receives(&membership, NODE_PRESENCE))
            || state
                .mix_service()
                .is_blocked(user.id, &channel_jid)
                .await?
        {
            return Ok(true);
        }
        for (jid, session) in state.session_entries_for(&to_jid.to_string()) {
            if session_mix_capability(&state, &jid) == MixSessionCapability::Supported {
                let _ = session.sender.try_send(raw.clone());
            }
        }
        return Ok(true);
    }
    Ok(false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::services::mix::MamRsmPage;

    #[test]
    fn verified_mix_presence_requires_the_exact_live_resource_epoch() {
        let expected = Uuid::new_v4();
        assert!(mix_presence_epoch_is_current(
            expected, expected, 7, 7, true, true, true
        ));
        assert!(!mix_presence_epoch_is_current(
            Uuid::new_v4(),
            expected,
            7,
            7,
            true,
            true,
            true
        ));
        assert!(!mix_presence_epoch_is_current(
            expected, expected, 8, 7, true, true, true
        ));
        assert!(!mix_presence_epoch_is_current(
            expected, expected, 7, 7, false, true, true
        ));
        assert!(!mix_presence_epoch_is_current(
            expected, expected, 7, 7, true, false, true
        ));
        assert!(!mix_presence_epoch_is_current(
            expected, expected, 7, 7, true, true, false
        ));
    }

    #[test]
    fn directed_mix_unavailable_suppresses_only_its_channel() {
        let suppressed = dashmap::DashSet::new();
        suppressed.insert("one@mix.example.test".to_owned());
        assert!(mix_presence_fallback_is_suppressed(
            &suppressed,
            "one@mix.example.test"
        ));
        assert!(!mix_presence_fallback_is_suppressed(
            &suppressed,
            "two@mix.example.test"
        ));
        suppressed.insert("*".to_owned());
        assert!(mix_presence_fallback_is_suppressed(
            &suppressed,
            "two@mix.example.test"
        ));
    }

    #[test]
    fn broadcast_unavailable_never_depends_on_a_remaining_caps_mapping() {
        assert_eq!(
            mix_broadcast_presence_action("unavailable", MixSessionCapability::Unknown),
            MixBroadcastPresenceAction::Retract
        );
        assert_eq!(
            mix_broadcast_presence_action("unavailable", MixSessionCapability::Unsupported),
            MixBroadcastPresenceAction::Retract
        );
        assert_eq!(
            mix_broadcast_presence_action("available", MixSessionCapability::Unknown),
            MixBroadcastPresenceAction::Retract
        );
        assert_eq!(
            mix_broadcast_presence_action("available", MixSessionCapability::Supported),
            MixBroadcastPresenceAction::Publish
        );
    }

    #[tokio::test]
    async fn graceful_shutdown_drains_the_claimed_mix_batch_before_stopping() {
        let cancel = tokio_util::sync::CancellationToken::new();
        let (started_tx, started_rx) = tokio::sync::oneshot::channel();
        let (release_tx, release_rx) = tokio::sync::oneshot::channel();
        let task_cancel = cancel.clone();
        let task = tokio::spawn(async move {
            complete_mix_outbox_batch(
                async move {
                    let _ = started_tx.send(());
                    let _ = release_rx.await;
                },
                &task_cancel,
                || {},
            )
            .await
        });

        started_rx.await.unwrap();
        cancel.cancel();
        tokio::task::yield_now().await;
        assert!(
            !task.is_finished(),
            "shutdown must not drop a batch that owns durable delivery leases"
        );
        release_tx.send(()).unwrap();
        assert!(task.await.unwrap(), "the worker must stop after draining");
    }

    #[test]
    fn replay_commitments_are_stable_and_purpose_separated() {
        let target = Uuid::parse_str("00112233-4455-6677-8899-aabbccddeeff").unwrap();
        let first = mix_replay_semantics(
            "retraction",
            "alice@example.test",
            "room@mix.example.test",
            Some(target),
            "",
        );
        let retry = mix_replay_semantics(
            "retraction",
            "alice@example.test",
            "room@mix.example.test",
            Some(target),
            "",
        );
        let message = mix_replay_semantics(
            "message",
            "alice@example.test",
            "room@mix.example.test",
            Some(target),
            "",
        );
        assert_eq!(first, retry);
        assert_ne!(first, message);
    }

    #[test]
    fn only_state_changing_federated_iqs_enter_result_replay() {
        let ping = parse_iq("<iq type='get' id='p'><ping xmlns='urn:xmpp:ping'/></iq>")
            .unwrap()
            .unwrap();
        let leave = parse_iq("<iq type='set' id='l'><leave xmlns='urn:xmpp:mix:core:1'/></iq>")
            .unwrap()
            .unwrap();
        assert!(!federated_mix_iq_is_mutation(&ping));
        assert!(federated_mix_iq_is_mutation(&leave));
    }

    fn relay_stage(seed: usize) -> MixIqRelayStage {
        MixIqRelayStage::Participant {
            requester_full_jid: format!("alice@example.test/{seed}"),
            original_id: format!("original-{seed}"),
            expected_from: "channel@mix.example.test".to_owned(),
            channel_jid: "channel@mix.example.test".to_owned(),
        }
    }

    #[test]
    fn mix_iq_relay_admission_is_concurrently_hard_bounded() {
        let limit = 8;
        let workers = 64;
        let index = Arc::new(MixIqRelayIndex::with_limits(limit, Duration::from_secs(30)));
        let barrier = Arc::new(std::sync::Barrier::new(workers));
        let mut threads = Vec::new();
        for seed in 0..workers {
            let index = Arc::clone(&index);
            let barrier = Arc::clone(&barrier);
            threads.push(std::thread::spawn(move || {
                barrier.wait();
                index.admit(format!("relay-{seed}"), relay_stage(seed), Instant::now())
            }));
        }
        let admitted = threads
            .into_iter()
            .map(|thread| thread.join().expect("MIX relay worker panicked"))
            .filter(|admitted| *admitted)
            .count();
        assert_eq!(admitted, limit);
        assert_eq!(index.len(), limit);
    }

    #[test]
    fn mix_iq_relay_expiry_has_one_exact_consumer() {
        let index = MixIqRelayIndex::with_limits(2, Duration::ZERO);
        assert!(index.admit("relay".to_owned(), relay_stage(1), Instant::now()));
        assert_eq!(index.take_expired(Instant::now()).len(), 1);
        assert!(index.take_expired(Instant::now()).is_empty());
        assert_eq!(index.len(), 0);
    }

    #[test]
    fn parses_pam_join_without_default_subscriptions() {
        let request = parse_iq("<iq type='set' id='j1' from='a@example.test/r' to='a@example.test'><client-join xmlns='urn:xmpp:mix:pam:2' channel='c@mix.example.test'><join xmlns='urn:xmpp:mix:core:1'><nick>A</nick></join></client-join></iq>").unwrap().unwrap();
        let IqOperation::PamJoin { channel, join } = request.operation else {
            panic!("wrong operation")
        };
        assert_eq!(channel, "c@mix.example.test");
        assert!(join.nodes.is_empty());
        assert_eq!(join.nick.as_deref(), Some("A"));
    }

    #[test]
    fn mix_anon_join_uses_exact_preferences_and_returns_every_supported_value() {
        let request = parse_iq("<iq type='set' id='anon'><join xmlns='urn:xmpp:mix:anon:0'><subscribe node='urn:xmpp:mix:nodes:messages'/><x xmlns='jabber:x:data' type='submit'><field var='FORM_TYPE'><value>urn:xmpp:mix:anon:0</value></field><field var='JID Visibility'><value>prefer not</value></field><field var='Presence'><value>not share</value></field></x></join></iq>").unwrap().unwrap();
        let IqOperation::Join(join) = request.operation else {
            panic!("MIX-ANON join was not parsed")
        };
        assert!(join.anonymous_profile);
        let preference = join.preference.unwrap();
        assert_eq!(preference.jid_visibility, "prefer not");
        assert_eq!(preference.private_messages, "allow");
        assert_eq!(preference.vcard, "block");
        assert!(!preference.share_presence);
        let participant = MixParticipant {
            participant_id: Uuid::nil(),
            jid: "alice@example.test".to_owned(),
            nick: Some("Alice".to_owned()),
        };
        let response =
            core_join_payload(&participant, &join.nodes, Some(&preference), true).unwrap();
        assert!(response.contains("xmlns='urn:xmpp:mix:anon:0'"));
        for value in ["prefer not", "allow", "block", "not share"] {
            assert!(response.contains(&format!("<value>{value}</value>")));
        }
    }

    #[test]
    fn mix_private_messages_strip_forged_identity_and_never_accept_groupchat() {
        let (children, encrypted, kind) = private_message_children("<message type='chat'><body>secret</body><mix xmlns='urn:xmpp:mix:core:1'><jid>mallory@example.test</jid></mix><stanza-id xmlns='urn:xmpp:sid:0' id='forged'/></message>").unwrap();
        assert_eq!(kind, "chat");
        assert!(children.contains("secret"));
        assert!(!children.contains("mallory"));
        assert!(!children.contains("forged"));
        assert!(!encrypted);
        assert!(private_message_children(
            "<message type='groupchat'><body>not private</body></message>"
        )
        .is_err());
    }

    #[test]
    fn mix_misc_retraction_is_canonical_bodyless_and_unambiguous() {
        let target = Uuid::new_v4();
        let valid_xml = format!(
            "<message type='groupchat'><retract xmlns='urn:xmpp:mix:misc:0' id='{target}'/></message>"
        );
        let valid = Document::parse(&valid_xml).unwrap();
        assert_eq!(
            mix_retraction_target(valid.root_element()).unwrap(),
            Some(target)
        );
        for invalid in [
            format!(
                "<message><body>x</body><retract xmlns='urn:xmpp:mix:misc:0' id='{target}'/></message>"
            ),
            format!(
                "<message><retract xmlns='urn:xmpp:mix:misc:0' id='{target}'/><retract xmlns='urn:xmpp:mix:misc:0' id='{target}'/></message>"
            ),
            "<message><retract xmlns='urn:xmpp:mix:misc:0' id='not-a-uuid'/></message>".to_owned(),
        ] {
            let invalid = Document::parse(&invalid).unwrap();
            assert!(mix_retraction_target(invalid.root_element()).is_err());
        }
    }

    #[test]
    fn rejects_unknown_or_duplicate_form_fields() {
        assert!(parse_iq("<iq type='set' id='form1'><pubsub xmlns='http://jabber.org/protocol/pubsub'><publish node='urn:xmpp:mix:nodes:info'><item><x xmlns='jabber:x:data' type='submit'><field var='Name'><value>A</value></field><field var='Name'><value>B</value></field></x></item></publish></pubsub></iq>").is_err());
    }

    #[test]
    fn strict_iq_shape_rejects_ambiguous_or_nested_payloads() {
        assert!(parse_iq("<iq type='set' id='two'><join xmlns='urn:xmpp:mix:core:1'/><leave xmlns='urn:xmpp:mix:core:1'/></iq>").is_err());
        assert!(parse_iq("<iq type='set' id='leave'><client-leave xmlns='urn:xmpp:mix:pam:2' channel='c@mix.example.test'/></iq>").is_err());
        assert!(parse_iq("<iq type='set' id='nick'><join xmlns='urn:xmpp:mix:core:1'><nick>A</nick><nick>B</nick></join></iq>").is_err());
        assert!(parse_iq("<iq type='get' id='max'><pubsub xmlns='http://jabber.org/protocol/pubsub'><items node='urn:xmpp:mix:nodes:participants' max_items='NaN'/></pubsub></iq>").is_err());
        assert!(parse_iq("<iq type='set' id='retract'><pubsub xmlns='http://jabber.org/protocol/pubsub'><retract node='urn:xmpp:mix:nodes:banned'><unexpected/><item id='a@example.test'/></retract></pubsub></iq>").is_err());
    }

    #[test]
    fn mix_routing_does_not_intercept_general_pubsub_requests() {
        let general_pubsub = "<iq type='set' id='p1' to='pubsub.example.test'><pubsub xmlns='http://jabber.org/protocol/pubsub'><create node='managed'/><configure/></pubsub></iq>";
        assert!(!mix_iq_route_candidate(general_pubsub, "mix.example.test"));

        let mix_pubsub = "<iq type='get' id='m1' to='channel@mix.example.test'><pubsub xmlns='http://jabber.org/protocol/pubsub'><items node='urn:xmpp:mix:nodes:messages'/></pubsub></iq>";
        assert!(mix_iq_route_candidate(mix_pubsub, "mix.example.test"));

        let pam = "<iq type='set' id='j1' to='alice@example.test'><client-join xmlns='urn:xmpp:mix:pam:2' channel='channel@mix.remote.test'><join xmlns='urn:xmpp:mix:core:1'/></client-join></iq>";
        assert!(mix_iq_route_candidate(pam, "mix.example.test"));
    }

    #[test]
    fn mix_mam_uses_the_standard_extended_query_model() {
        let request = parse_iq("<iq type='set' id='m1' to='room@mix.example.test'><query xmlns='urn:xmpp:mam:2' queryid='sync'><x xmlns='jabber:x:data' type='submit'><field var='FORM_TYPE' type='hidden'><value>urn:xmpp:mam:2</value></field><field var='with' type='jid-single'><value>alice@example.test</value></field><field var='start'><value>2026-01-01T00:00:00Z</value></field></x><set xmlns='http://jabber.org/protocol/rsm'><max>25</max><before/></set><flip-page xmlns='urn:xmpp:mam:2'/></query></iq>").unwrap().unwrap();
        let IqOperation::Mam(parsed) = request.operation else {
            panic!("MIX MAM query was not parsed");
        };
        assert_eq!(parsed.query.with_jid.as_deref(), Some("alice@example.test"));
        assert_eq!(parsed.query.max, 25);
        assert_eq!(
            MamArchiveQuery::from(parsed.query.clone()).page,
            MamRsmPage::Last
        );
        assert_eq!(parsed.query.start.unwrap().timestamp(), 1_767_225_600);
        assert_eq!(parsed.query_id.as_deref(), Some("sync"));
        assert!(parsed.flip_page);

        let malformed = parse_iq("<iq type='set' id='m2' to='room@mix.example.test'><query xmlns='urn:xmpp:mam:2'><set xmlns='http://jabber.org/protocol/rsm'><max>NaN</max></set></query></iq>").unwrap().unwrap();
        assert!(matches!(
            malformed.operation,
            IqOperation::MamError("bad-request")
        ));
    }

    #[test]
    fn mix_mam_form_and_metadata_require_empty_get_payloads() {
        let form = parse_iq("<iq type='get' id='f1' to='room@mix.example.test'><query xmlns='urn:xmpp:mam:2'/></iq>").unwrap().unwrap();
        assert!(matches!(form.operation, IqOperation::MamForm));
        let metadata = parse_iq("<iq type='get' id='f2' to='room@mix.example.test'><metadata xmlns='urn:xmpp:mam:2'/></iq>").unwrap().unwrap();
        assert!(matches!(metadata.operation, IqOperation::MamMetadata));
        let invalid = parse_iq("<iq type='get' id='f3' to='room@mix.example.test'><query xmlns='urn:xmpp:mam:2'><unexpected/></query></iq>").unwrap().unwrap();
        assert!(matches!(
            invalid.operation,
            IqOperation::MamError("bad-request")
        ));
    }

    #[test]
    fn pam_and_core_join_identifiers_follow_their_respective_xeps() {
        let participant = MixParticipant {
            participant_id: Uuid::parse_str("00112233-4455-6677-8899-aabbccddeeff").unwrap(),
            jid: "alice@example.test".to_owned(),
            nick: Some("Nick".to_owned()),
        };
        let nodes = vec![NODE_MESSAGES.to_owned()];
        let core = core_join_payload(&participant, &nodes, None, false).unwrap();
        assert!(core.contains("id='00112233-4455-6677-8899-aabbccddeeff'"));
        assert!(!core.contains(" jid="));
        let pam =
            pam_join_payload("room@mix.example.test", &participant, &nodes, None, false).unwrap();
        assert!(pam.contains("jid='00112233-4455-6677-8899-aabbccddeeff#room@mix.example.test'"));
        assert!(!pam.contains(" id="));
    }

    #[test]
    fn remote_join_result_is_direct_channel_bound_and_unambiguous() {
        let result = parse_remote_join_result(
            "<iq type='result' id='j1'><join xmlns='urn:xmpp:mix:core:1' id='opaque'><subscribe node='urn:xmpp:mix:nodes:messages'/><nick>Nick</nick></join></iq>",
            "room@mix.remote.test",
        )
        .unwrap();
        assert_eq!(result.participant_id, "opaque");
        assert_eq!(result.participant_jid, "opaque#room@mix.remote.test");
        assert_eq!(result.nick.as_deref(), Some("Nick"));

        let documented_pam_form = parse_remote_join_result(
            "<iq type='result' id='j2'><join xmlns='urn:xmpp:mix:core:1' jid='opaque#room@mix.remote.test'/></iq>",
            "room@mix.remote.test",
        )
        .unwrap();
        assert_eq!(documented_pam_form.participant_id, "opaque");

        assert!(parse_remote_join_result(
            "<iq type='result' id='bad'><wrapper><join xmlns='urn:xmpp:mix:core:1' id='nested'/></wrapper></iq>",
            "room@mix.remote.test",
        )
        .is_err());
        assert!(parse_remote_join_result(
            "<iq type='result' id='bad'><join xmlns='urn:xmpp:mix:core:1' id='one' jid='one#room@mix.remote.test'/></iq>",
            "room@mix.remote.test",
        )
        .is_err());
        assert!(parse_remote_join_result(
            "<iq type='result' id='bad'><join xmlns='urn:xmpp:mix:core:1' jid='opaque#other@mix.remote.test'/></iq>",
            "room@mix.remote.test",
        )
        .is_err());
        assert_eq!(
            parse_remote_pam_success("<iq type='result' id='leave'/>", "room@mix.remote.test",)
                .unwrap(),
            None
        );
        assert_eq!(
            parse_remote_pam_success(
                "<iq type='result' id='leave'><leave xmlns='urn:xmpp:mix:core:1'/></iq>",
                "room@mix.remote.test",
            )
            .unwrap(),
            None
        );
        assert!(parse_remote_pam_success(
            "<iq type='result' id='bad-leave'><leave xmlns='urn:xmpp:mix:core:1' unexpected='true'/></iq>",
            "room@mix.remote.test",
        )
        .is_err());
        assert!(parse_remote_pam_success(
            "<iq type='result' id='bad-leave-text'><leave xmlns='urn:xmpp:mix:core:1'> <!-- split -->unexpected</leave></iq>",
            "room@mix.remote.test",
        )
        .is_err());
        assert!(parse_remote_pam_success(
            "<iq type='result' id='bad'><unexpected/></iq>",
            "room@mix.remote.test",
        )
        .is_err());
    }

    #[test]
    fn remote_iq_error_relay_accepts_only_standard_safe_conditions() {
        let error = parse_remote_iq_error("<iq type='error' id='e1'><error type='auth'><forbidden xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/><text xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'>no</text></error></iq>").unwrap();
        assert_eq!(error.error_type, "auth");
        assert_eq!(error.condition, "forbidden");
        assert!(parse_remote_iq_error("<iq type='error' id='e2'><error type='cancel'><attacker-controlled xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/></error></iq>").is_err());
        assert!(parse_remote_iq_error("<iq type='error' id='e3'><error type='evil'><forbidden xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/></error></iq>").is_err());
    }

    #[test]
    fn strips_client_asserted_mix_identity_but_preserves_modern_payloads() {
        let (children, encrypted) = message_children("<message type='groupchat' to='c@mix.example.test'><body>x</body><file-sharing xmlns='urn:xmpp:sfs:0'/><origin-id xmlns='urn:xmpp:sid:0' id='client'/><stanza-id xmlns='urn:xmpp:sid:0' id='forged' by='c@mix.example.test'/><mix xmlns='urn:xmpp:mix:core:1'><jid>mallory@example.test</jid></mix></message>").unwrap();
        assert!(children.contains("file-sharing"));
        assert!(children.contains("origin-id"));
        assert!(!children.contains("forged"));
        assert!(!children.contains("mallory"));
        assert!(!encrypted);
    }

    #[test]
    fn reflected_mix_history_identity_is_channel_bound_and_canonical() {
        let id = Uuid::new_v4();
        let valid_xml = format!(
            "<message type='groupchat' from='room@mix.remote.test/participant' to='alice@example.test'><mix xmlns='urn:xmpp:mix:core:1'><nick>Alice</nick></mix><stanza-id xmlns='urn:xmpp:sid:0' by='room@mix.remote.test' id='{id}'/></message>"
        );
        let valid = Document::parse(&valid_xml).unwrap();
        assert_eq!(reflected_mix_stanza_id(valid.root_element()).unwrap(), id);

        for invalid in [
            format!("<message from='room@mix.remote.test/participant'><stanza-id xmlns='urn:xmpp:sid:0' by='other@mix.remote.test' id='{id}'/></message>"),
            format!("<message from='room@mix.remote.test/participant'><stanza-id xmlns='urn:xmpp:sid:0' by='room@mix.remote.test' id='{id}'/><stanza-id xmlns='urn:xmpp:sid:0' by='room@mix.remote.test' id='{id}'/></message>"),
            "<message from='room@mix.remote.test/participant'><stanza-id xmlns='urn:xmpp:sid:0' by='room@mix.remote.test' id='NOT-A-UUID'/></message>".to_owned(),
        ] {
            let invalid = Document::parse(&invalid).unwrap();
            assert!(reflected_mix_stanza_id(invalid.root_element()).is_err());
        }
    }

    #[test]
    fn federated_actor_identity_helpers_preserve_their_bare_or_full_contract() {
        assert_eq!(
            authenticated_actor("alice@remote.test", "remote.test").unwrap(),
            AuthenticatedMixIqActor {
                bare: "alice@remote.test".to_owned(),
                reply_to: "alice@remote.test".to_owned(),
            }
        );
        assert_eq!(
            authenticated_actor("alice@remote.test/Phone", "remote.test").unwrap(),
            AuthenticatedMixIqActor {
                bare: "alice@remote.test".to_owned(),
                reply_to: "alice@remote.test/Phone".to_owned(),
            }
        );
        assert!(authenticated_actor("alice@evil.test", "remote.test").is_err());
        assert_eq!(
            authenticated_full_actor("alice@remote.test/Phone", "remote.test").unwrap(),
            "alice@remote.test/Phone"
        );
        assert!(authenticated_full_actor("alice@remote.test", "remote.test").is_err());
        assert!(authenticated_full_actor("alice@evil.test/Phone", "remote.test").is_err());
    }

    #[test]
    fn federated_mix_disco_is_strict_and_advertises_mam_only_on_channels() {
        let request = parse_mix_disco_info(
            "<iq type='get' id='d1' from='alice@remote.test/Phone' to='room@mix.example.test'><query xmlns='http://jabber.org/protocol/disco#info'/></iq>",
        )
        .unwrap()
        .unwrap();
        assert_eq!(request.id, "d1");
        assert_eq!(request.node, None);
        assert_eq!(request.error, None);

        let malformed = parse_mix_disco_info(
            "<iq type='get' id='d2' from='remote.test' to='mix.example.test'><query xmlns='http://jabber.org/protocol/disco#info'><unexpected/></query></iq>",
        )
        .unwrap()
        .unwrap();
        assert_eq!(malformed.error, Some("bad-request"));

        let service = mix_service_disco_info_payload("Northstar", "").unwrap();
        assert!(!service.contains("urn:xmpp:mam:2"));
        let channel_without_mam =
            mix_channel_disco_info_payload("Room", false, false, false, "").unwrap();
        assert!(!channel_without_mam.contains("urn:xmpp:mam:2"));
        let channel = mix_channel_disco_info_payload("Room", false, false, true, "").unwrap();
        for feature in [
            "http://jabber.org/protocol/rsm",
            "urn:xmpp:mam:2",
            "urn:xmpp:mam:2#extended",
            "urn:xmpp:sid:0",
        ] {
            assert!(channel.contains(feature), "missing {feature}");
        }
    }

    #[test]
    fn parses_empty_federated_iq_response_for_pam_correlation() {
        let request = parse_iq(
            "<iq type='result' id='server-correlation' from='c@mix.remote.test' to='a@example.test'/>",
        )
        .unwrap()
        .unwrap();
        assert_eq!(request.id, "server-correlation");
        assert!(matches!(request.operation, IqOperation::Response));
    }

    #[test]
    fn mix_service_identity_is_bound_to_authenticated_s2s_domain() {
        assert!(authenticated_mix_service("remote.test", "remote.test"));
        assert!(!authenticated_mix_service("mix.remote.test", "remote.test"));
        assert!(authenticated_mix_service(
            "mix.remote.test",
            "mix.remote.test"
        ));
        assert!(!authenticated_mix_service("mix.evil.test", "remote.test"));
        assert!(!authenticated_mix_service("evil.test", "remote.test"));
    }

    #[test]
    fn remote_stable_participant_ids_are_opaque_but_delimiter_safe() {
        assert!(MixService::valid_stable_participant_id("not-a-uuid"));
        assert!(MixService::valid_stable_participant_id("αβγ"));
        assert!(!MixService::valid_stable_participant_id(""));
        assert!(!MixService::valid_stable_participant_id("id#channel"));
        assert!(!MixService::valid_stable_participant_id("id@example.test"));
        assert!(!MixService::valid_stable_participant_id("id/resource"));
        assert_eq!(
            decode_participant_jid("opaque#room@mix.remote.test").unwrap(),
            ("opaque".to_owned(), "room@mix.remote.test".to_owned())
        );
        assert!(decode_participant_jid("UPPER#room@mix.remote.test").is_err());
    }

    #[test]
    fn reflected_federated_payloads_require_one_strict_server_identity() {
        let message = Document::parse("<message type='groupchat'><body>x</body><mix xmlns='urn:xmpp:mix:core:1'><nick>Nick</nick></mix></message>").unwrap();
        assert!(validate_reflected_mix_identity(message.root_element()).is_ok());
        let missing =
            Document::parse("<message type='groupchat'><body>x</body></message>").unwrap();
        assert!(validate_reflected_mix_identity(missing.root_element()).is_err());

        let presence = Document::parse("<presence><mix xmlns='urn:xmpp:mix:presence:0'><jid>a@example.test/r</jid><nick>Nick</nick></mix></presence>").unwrap();
        assert!(validate_reflected_mix_presence_identity(presence.root_element()).is_ok());
        let duplicate = Document::parse("<presence><mix xmlns='urn:xmpp:mix:presence:0'/><mix xmlns='urn:xmpp:mix:presence:0'/></presence>").unwrap();
        assert!(validate_reflected_mix_presence_identity(duplicate.root_element()).is_err());
    }

    #[test]
    fn federated_delivery_is_node_scoped_not_bound_to_the_receivers_own_id() {
        let membership = PamMembership {
            id: Uuid::new_v4(),
            user_id: Uuid::new_v4(),
            channel_jid: "room@mix.remote.test".to_owned(),
            participant_id: Some("receivers-stable-id".to_owned()),
            state: "joined".to_owned(),
            request_id: None,
            client_request_id: None,
            requester_full_jid: None,
            subscriptions: vec![NODE_PRESENCE.to_owned()],
        };
        assert!(pam_membership_receives(&membership, NODE_PRESENCE));
        assert!(!pam_membership_receives(&membership, NODE_MESSAGES));
    }

    #[test]
    fn mix_presence_relay_accepts_only_read_only_vcards() {
        let temp = parse_relay_iq("<iq type='get' id='v1' from='alice@example.test/Phone' to='opaque#room@mix.remote.test/Target'><vCard xmlns='vcard-temp'/></iq>").unwrap().unwrap();
        assert_eq!(temp.request, Some(RelayPayload::VCardTemp));
        let v4 = parse_relay_iq("<iq type='get' id='v2' from='alice@example.test/Phone' to='opaque#room@mix.remote.test'><pubsub xmlns='http://jabber.org/protocol/pubsub'><items node='urn:xmpp:vcard4'><item id='current'/></items></pubsub></iq>").unwrap().unwrap();
        assert_eq!(
            v4.request,
            Some(RelayPayload::VCard4 {
                item_id: Some("current".to_owned())
            })
        );
        assert!(parse_relay_iq("<iq type='set' id='v3' from='alice@example.test/Phone' to='opaque#room@mix.remote.test'><vCard xmlns='vcard-temp'/></iq>").unwrap().is_none());
        assert!(parse_relay_iq("<iq type='get' id='v4' from='alice@example.test/Phone' to='opaque#room@mix.remote.test'><query xmlns='jabber:iq:version'/></iq>").unwrap().is_none());
        assert!(parse_relay_iq("<iq type='get' id='v5' from='alice@example.test/Phone' to='opaque#room@mix.remote.test'><pubsub xmlns='http://jabber.org/protocol/pubsub'><items node='urn:xmpp:vcard4'/><publish node='urn:xmpp:vcard4'/></pubsub></iq>").unwrap().is_none());
    }

    #[test]
    fn encoded_presence_resource_is_precis_case_sensitive() {
        let upper = encoded_participant_full_jid(
            "room@mix.example.test",
            "00112233-4455-6677-8899-aabbccddeeff",
            "Phone",
        )
        .unwrap();
        let lower = encoded_participant_full_jid(
            "room@mix.example.test",
            "00112233-4455-6677-8899-aabbccddeeff",
            "phone",
        )
        .unwrap();
        assert_eq!(
            upper,
            "00112233-4455-6677-8899-aabbccddeeff#room@mix.example.test/Phone"
        );
        assert_ne!(upper, lower);
    }
}
