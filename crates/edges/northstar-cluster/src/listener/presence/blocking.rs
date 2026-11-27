use super::super::ListenerTurn;
use crate::{
    listener_blocking::{
        wire::{checked_control, control, SnapshotRequest, WireTarget, SNAPSHOT_PAGE},
        ClusterListenerBlocking,
    },
    ClusterAdapters, ClusterControlOutcome,
};
use anyhow::Result;
use northstar_roster_application::{blocking_mutation::BlockingPresenceTarget, ExactPresenceRoute};
use northstar_xmpp_types::jid::CanonicalJid;
use serde::Deserialize;
use serde_json::Value;

pub(in super::super) async fn deliver_blocking_presence<A: ClusterAdapters>(
    blocking: &ClusterListenerBlocking<A>,
    source_node: &str,
    json: &Value,
    target: &str,
    turn: &mut ListenerTurn,
) {
    match process(blocking, source_node, json, target).await {
        Ok(outcome) => {
            turn.control_processed = Some(true);
            turn.control_outcome = outcome;
        }
        Err(error) => {
            turn.control_processed = Some(false);
            tracing::warn!(?error, %source_node, %target, "rejected blocking presence control");
        }
    }
}

async fn process<A: ClusterAdapters>(
    blocking: &ClusterListenerBlocking<A>,
    source_node: &str,
    json: &Value,
    target: &str,
) -> Result<Option<ClusterControlOutcome>> {
    let stanza = json["stanza"].as_str();
    let exact = checked_control(json, target, stanza)?;
    let source = exact
        .source
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("missing blocking source"))?;
    let route = ExactPresenceRoute {
        account_id: source.account_id,
        auth_generation: source.auth_generation,
        connection_id: source.connection_id,
        full_jid: source.full_jid.clone(),
        node_id: Some(source_node.to_owned()),
    };
    if !json["blocking_snapshot"].is_null() {
        anyhow::ensure!(
            exact == control(&route, &route)
                && json["stanza"].is_null()
                && json["blocking_targets"].is_null()
                && json["blocking_recipient"].is_null(),
            "invalid blocking snapshot selectors"
        );
        anyhow::ensure!(
            blocking.snapshot_actor_is_current(&route).await?,
            "stale blocking snapshot actor"
        );
        let request = SnapshotRequest::deserialize(&json["blocking_snapshot"])?;
        anyhow::ensure!(
            request.patterns.as_ref().is_none_or(|patterns| {
                patterns.len() <= northstar_xep_0191::MAX_ITEMS
                    && patterns.iter().all(|key| {
                        CanonicalJid::parse(key).is_ok_and(|jid| jid.to_string() == *key)
                    })
            }),
            "invalid blocking snapshot patterns"
        );
        let entries = blocking.snapshot_entries(
            northstar_xmpp_types::jid_text::bare_jid(target),
            request.patterns.as_deref(),
            request
                .after
                .as_ref()
                .map(|(full, directed)| (full.as_str(), directed.as_deref())),
            Some(SNAPSHOT_PAGE),
        );
        return Ok(Some(ClusterControlOutcome::BlockingSnapshot(entries)));
    }

    let available = json["available"]
        .as_bool()
        .ok_or_else(|| anyhow::anyhow!("missing blocking presence effect kind"))?;
    if let Some(stanza) = stanza {
        anyhow::ensure!(
            json["blocking_targets"].is_null()
                && stanza.len() <= northstar_stream::MAX_XMPP_FRAME_BYTES,
            "invalid blocking recipient selectors or stanza size"
        );
        let WireTarget(effect) = WireTarget::deserialize(&json["blocking_recipient"])?;
        let recipient = effect
            .recipient
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("missing blocking recipient"))?;
        anyhow::ensure!(
            valid_target(&effect) && effect.source == route && exact == control(&route, recipient),
            "blocking recipient does not match exact control"
        );
        let document = roxmltree::Document::parse(stanza)?;
        let root = document.root_element();
        anyhow::ensure!(
            root.attribute("to") == Some(effect.address.as_str())
                && (if available {
                    root.attribute("type")
                        .is_none_or(|kind| kind == "available")
                } else {
                    root.attribute("type") == Some("unavailable")
                }),
            "invalid blocking presence stanza"
        );
        blocking.receive(effect, stanza, available).await?;
        return Ok(None);
    }

    anyhow::ensure!(
        exact == control(&route, &route)
            && json["blocking_recipient"].is_null()
            && json["stanza"].is_null(),
        "invalid blocking source selectors"
    );
    let targets = json["blocking_targets"]
        .as_array()
        .filter(|targets| !targets.is_empty() && targets.len() <= northstar_xep_0191::MAX_ITEMS)
        .ok_or_else(|| anyhow::anyhow!("invalid blocking presence slice size"))?;
    let targets = targets
        .iter()
        .map(WireTarget::deserialize)
        .collect::<Result<Vec<_>, _>>()?;
    anyhow::ensure!(
        targets.iter().all(|WireTarget(effect)| {
            valid_target(effect) && control(&effect.source, &effect.source) == exact
        }),
        "blocking source does not match exact control"
    );
    let failed = blocking
        .emit_slice(targets.into_iter().map(|target| target.0), available)
        .await;
    Ok(Some(ClusterControlOutcome::BlockingPresence { failed }))
}

fn valid_target(effect: &BlockingPresenceTarget) -> bool {
    let Ok(address) = CanonicalJid::parse(&effect.address) else {
        return false;
    };
    address.to_string() == effect.address
        && effect.recipient.as_ref().is_none_or(|route| {
            !route.account_id.is_nil()
                && route.auth_generation >= 0
                && !route.connection_id.is_nil()
                && route.account_id != effect.source.account_id
                && CanonicalJid::parse(&route.full_jid).is_ok_and(|jid| {
                    jid.resourcepart().is_some()
                        && jid.to_string() == route.full_jid
                        && (address == jid || address == jid.to_bare())
                })
        })
}
