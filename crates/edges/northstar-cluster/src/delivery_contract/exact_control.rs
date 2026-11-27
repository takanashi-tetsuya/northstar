//! Exact controls use a per-payload version, like exact message delivery.
//! Both use the current node heartbeat (13) and have no separate peer
//! capability advertisement. A peer that only implements v13/v14 delivery
//! rejects the v15 payload.

use super::{
    cluster_roster_push_version, is_presence_subscription_stanza, presence_delivery_stanza_matches,
    supports_current_cluster_protocol, ClusterPresenceDelivery,
};
use anyhow::{Context, Result};
use northstar_xmpp_types::jid::CanonicalJid;
use roxmltree::{Document, Node};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use uuid::Uuid;

pub const EXACT_CONTROL_DELIVERY_VERSION: &str = "15";

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExactControlKind {
    RosterPush,
    BlocklistPush,
    PrivacyPush,
    SubscriptionPresence,
    CurrentPresenceReplay,
    AvailablePresence,
    DirectedPresence,
    UnavailablePresence,
    ProbeResponse,
    BlockingPresence,
    TeardownUnavailable,
    FederatedInboundPresence,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExactControl {
    pub kind: ExactControlKind,
    pub account_id: Uuid,
    pub auth_generation: i64,
    pub expected_connections: BTreeMap<String, Uuid>,
    pub roster_version: Option<i64>,
    pub blocklist_revision: Option<i64>,
    pub remote_peer: Option<String>,
    pub source: Option<ExactControlSource>,
    pub sequence: Option<u64>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExactControlSource {
    pub account_id: Uuid,
    pub auth_generation: i64,
    pub connection_id: Uuid,
    pub full_jid: String,
}

pub fn supports_exact_control(peer_version: Option<&str>) -> bool {
    supports_current_cluster_protocol(peer_version)
}

pub fn validate_exact_control(
    control: &ExactControl,
    target: &str,
    stanza: &Document<'_>,
) -> Result<()> {
    use ExactControlKind::*;

    anyhow::ensure!(
        !control.account_id.is_nil() && control.auth_generation >= 0,
        "exact control has an invalid recipient account fence"
    );
    let target_jid = CanonicalJid::parse(target)?;
    let target_bare = target_jid.to_bare();
    anyhow::ensure!(
        !control.expected_connections.is_empty(),
        "exact control has no recipient connections"
    );
    for (key, connection_id) in &control.expected_connections {
        let jid = CanonicalJid::parse(key)?;
        anyhow::ensure!(
            !connection_id.is_nil()
                && jid.resourcepart().is_some()
                && jid.to_string() == *key
                && jid.to_bare() == target_bare
                && (target_jid.resourcepart().is_none() || key == target),
            "exact control has an invalid recipient connection"
        );
    }
    anyhow::ensure!(
        control.roster_version.is_some() == (control.kind == RosterPush)
            && control.roster_version.is_none_or(|version| version > 0),
        "exact control has an invalid roster version"
    );
    anyhow::ensure!(
        control.blocklist_revision.is_some() == (control.kind == BlocklistPush)
            && control
                .blocklist_revision
                .is_none_or(|revision| revision > 0),
        "exact control has an invalid blocklist revision"
    );
    let federation_owner_request = control.remote_peer.is_some()
        && matches!(control.kind, CurrentPresenceReplay | ProbeResponse);
    anyhow::ensure!(
        (control.kind != FederatedInboundPresence || control.remote_peer.is_some())
            && (control.remote_peer.is_none()
                || control.kind == FederatedInboundPresence
                || federation_owner_request)
            && (control.remote_peer.is_none() || control.source.is_none()),
        "exact control remote peer does not match its kind"
    );
    if let Some(peer) = &control.remote_peer {
        let jid = CanonicalJid::parse_bare(peer)?;
        anyhow::ensure!(
            jid.localpart().is_none() && jid.domainpart() == peer,
            "exact control remote peer is not a domain"
        );
    }
    let root = stanza.root_element();
    if !federation_owner_request
        && matches!(
            control.kind,
            AvailablePresence
                | DirectedPresence
                | UnavailablePresence
                | CurrentPresenceReplay
                | ProbeResponse
                | TeardownUnavailable
                | BlockingPresence
        )
    {
        control
            .source
            .as_ref()
            .context("exact presence control has no source")?;
    }
    if let Some(source) = &control.source {
        let jid = CanonicalJid::parse(&source.full_jid)?;
        anyhow::ensure!(
            !source.account_id.is_nil()
                && source.auth_generation >= 0
                && !source.connection_id.is_nil()
                && jid.resourcepart().is_some()
                && jid.to_string() == source.full_jid
                && root.attribute("from") == Some(source.full_jid.as_str()),
            "exact control source does not match the stanza's full JID"
        );
    }
    let is_presence = root.tag_name().name() == "presence";
    let stanza_matches = match control.kind {
        RosterPush => cluster_roster_push_version(stanza.input_text()) == control.roster_version,
        BlocklistPush => {
            iq_set_payload(root).is_some_and(|payload| match payload.tag_name().name() {
                "block" => northstar_xep_0191::parse_block(payload).is_ok(),
                "unblock" => northstar_xep_0191::parse_unblock(payload).is_ok(),
                _ => false,
            })
        }
        PrivacyPush => iq_set_payload(root).is_some_and(is_privacy_push),
        SubscriptionPresence => is_presence_subscription_stanza(stanza),
        CurrentPresenceReplay if federation_owner_request => {
            is_presence && matches!(root.attribute("type"), None | Some("unavailable"))
        }
        ProbeResponse if federation_owner_request => {
            is_presence && root.attribute("type") == Some("probe")
        }
        AvailablePresence | CurrentPresenceReplay => {
            presence_delivery_stanza_matches(stanza, ClusterPresenceDelivery::CurrentReplay)
        }
        UnavailablePresence | TeardownUnavailable => {
            is_presence && root.attribute("type") == Some("unavailable")
        }
        DirectedPresence | BlockingPresence | ProbeResponse | FederatedInboundPresence => {
            is_presence
        }
    };
    anyhow::ensure!(
        stanza_matches,
        "exact control kind does not match its stanza"
    );
    Ok(())
}

fn iq_set_payload<'a, 'input>(root: Node<'a, 'input>) -> Option<Node<'a, 'input>> {
    if root.tag_name().name() != "iq" || root.attribute("type") != Some("set") {
        return None;
    }
    let mut children = root.children().filter(Node::is_element);
    let payload = children.next()?;
    children.next().is_none().then_some(payload)
}

fn is_privacy_push(query: Node<'_, '_>) -> bool {
    let namespace = Some(northstar_xep_0016::NAMESPACE);
    let mut children = query.children().filter(Node::is_element);
    query.tag_name().name() == "query"
        && query.tag_name().namespace() == namespace
        && query.attributes().len() == 0
        && children.next().is_some_and(|list| {
            list.tag_name().name() == "list"
                && list.tag_name().namespace() == namespace
                && list.attributes().len() == 1
                && list.attribute("name").is_some_and(|name| !name.is_empty())
                && list.children().all(|child| {
                    !child.is_element() && child.text().is_none_or(|text| text.trim().is_empty())
                })
        })
        && children.next().is_none()
        && query
            .children()
            .filter(Node::is_text)
            .all(|child| child.text().is_none_or(|text| text.trim().is_empty()))
}
