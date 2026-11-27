//! Handle federated presence, subscription transitions, probes and presence responses.

use anyhow::Result;
use northstar_federation_core::wire::s2s_stanza_error;
use northstar_stream::protocol::caps::{observe_federated_caps, FederatedCapsObservationResult};
use northstar_xmpp_types::jid::{canonical_session_key, prepare_domainpart, CanonicalJid};
use roxmltree::Node;
use std::ops::ControlFlow;
use uuid::Uuid;

use crate::{
    FederatedPresenceEffect, FederatedPresenceHandoff, FederatedPresenceHost,
    FederatedPresenceOwnerHost,
};

mod ordinary;
mod probe;
mod render;
mod replay;
mod transition;

use self::ordinary::dispatch_ordinary_presence;
use self::probe::route_inbound_presence_probe;
use self::render::canonical_subscription_stanza;
use self::transition::transition_inbound_subscription;

pub async fn route_inbound_presence<H: FederatedPresenceHost + FederatedPresenceOwnerHost>(
    state: &H,
    root: Node<'_, '_>,
    raw: &str,
    from: &str,
    to: &str,
    connection_id: Uuid,
    verified_peer: &str,
) -> Result<Option<String>> {
    let Ok(to_jid) = CanonicalJid::parse(to) else {
        return Ok(Some(s2s_stanza_error(root, "modify", "jid-malformed")));
    };
    let Some(recipient_name) = to_jid.localpart() else {
        return Ok(Some(s2s_stanza_error(root, "modify", "jid-malformed")));
    };
    let sender = CanonicalJid::parse(from)?;
    let remote_peer = prepare_domainpart(verified_peer)?;
    if sender.domainpart() != remote_peer {
        return Ok(None);
    }
    let Some(recipient) = state
        .presence_service()
        .find_enabled_user(recipient_name)
        .await?
    else {
        return Ok(None);
    };
    let recipient_bare = format!("{}@{}", recipient.username, state.local_domain());
    let target = to_jid.to_string();
    let canonical_sender = sender.to_string();
    let mut handoff = FederatedPresenceHandoff {
        target: &target,
        sender: &canonical_sender,
        remote_peer: &remote_peer,
        stanza: raw,
        effect: FederatedPresenceEffect::Forward {
            pending_created_at_micros: None,
        },
    };
    let kind = root.attribute("type").unwrap_or("available");
    // Multiple authenticated streams for one remote domain can concurrently
    // carry presence for the same full JID. Choose one server-side order and
    // retain it through capability side effects and final local/cluster
    // routing; otherwise an older available could be delivered after a newer
    // unavailable even if the caps cache itself had already been cleaned.
    let federated_presence_epoch = if matches!(kind, "available" | "unavailable") {
        match canonical_session_key(from) {
            Ok(full_jid) => Some(state.federated_caps_gates().lock(&full_jid).await),
            Err(_) => None,
        }
    } else {
        None
    };
    let subscription_kind = matches!(
        kind,
        "subscribe" | "subscribed" | "unsubscribe" | "unsubscribed"
    );
    if !subscription_kind
        && state
            .presence_service()
            .is_blocked_for_account(recipient.id, &recipient_bare, from)
            .await?
    {
        return Ok(None);
    }
    if kind == "probe" {
        handoff.effect = FederatedPresenceEffect::Probe;
        return route_inbound_presence_probe(state, root, &recipient, &recipient_bare, handoff)
            .await;
    }
    if subscription_kind
        && to_jid.resourcepart().is_some()
        && kind != "subscribe"
        && state
            .capture_federated_presence(&target, &recipient)
            .await?
            .is_empty()
    {
        return Ok(None);
    }
    if let Some(resource_epoch) = federated_presence_epoch.as_ref() {
        match observe_federated_caps(state, root, from, connection_id, resource_epoch).await {
            FederatedCapsObservationResult::Accepted => {}
            FederatedCapsObservationResult::StaleOwner => {
                return Ok(None);
            }
            FederatedCapsObservationResult::Saturated => {
                return Ok(Some(s2s_stanza_error(root, "wait", "resource-constraint")));
            }
        }
    }
    if subscription_kind {
        let contact = sender.bare();
        let persisted = canonical_subscription_stanza(raw, &contact, to);
        handoff.target = &recipient_bare;
        handoff.stanza = &persisted;
        if let ControlFlow::Break(reply) =
            transition_inbound_subscription(state, root, kind, &recipient, &contact, handoff)
                .await?
        {
            return Ok(reply);
        }
        return Ok(None);
    }
    dispatch_ordinary_presence(state, &recipient, handoff).await?;
    Ok(None)
}

#[cfg(test)]
mod tests;
