use super::*;
use crate::{ExactControl, ExactControlKind, EXACT_CONTROL_DELIVERY_VERSION};

pub(in super::super) async fn validate_stanza_presence<'a, A: ClusterAdapters>(
    admission: &ClusterListenerAdmission,
    message_policy: &ClusterListenerMessagePolicy<A>,
    source_node: &str,
    json: &serde_json::Value,
    target: &str,
    stanza: &'a str,
) -> ListenerStep<(
    Option<roxmltree::Document<'a>>,
    Option<ClusterPresenceAuthority>,
)> {
    let parsed_stanza = roxmltree::Document::parse(stanza).ok();
    let exact = json["protocol_version"].as_str() == Some(EXACT_CONTROL_DELIVERY_VERSION);
    let control = exact
        .then(|| serde_json::from_value::<ExactControl>(json["exact_control"].clone()).ok())
        .flatten();
    let kind = control.as_ref().map(|control| control.kind);
    let subscription = parsed_stanza
        .as_ref()
        .is_some_and(is_presence_subscription_stanza);
    let legacy_available = !exact
        && json["available_only"].as_bool() == Some(true)
        && json["legacy_directed_or_blocking_presence"].as_bool() != Some(true)
        && parsed_stanza
            .as_ref()
            .is_some_and(|document| document.root_element().tag_name().name() == "presence");
    if json["current_presence_replay"].as_bool() == Some(true)
        || json["presence_subscription"].as_bool() == Some(true)
        || json["presence_probe"].as_bool() == Some(true)
        || json["probe_response"].as_bool() == Some(true)
        || legacy_available
        || (subscription && kind != Some(ExactControlKind::SubscriptionPresence))
    {
        admission.note_incompatible_peer_version(source_node, json["protocol_version"].as_str());
        return ListenerStep::Continue;
    }
    let authority = match presence_authority(json) {
        Ok(authority) => authority,
        Err(error) => {
            admission.note_authentication_failure(&error);
            return ListenerStep::Continue;
        }
    };
    if matches!(
        kind,
        Some(
            ExactControlKind::CurrentPresenceReplay
                | ExactControlKind::AvailablePresence
                | ExactControlKind::UnavailablePresence
                | ExactControlKind::ProbeResponse
                | ExactControlKind::SubscriptionPresence
        )
    ) && !addressed_presence_matches(parsed_stanza.as_ref(), target)
    {
        return ListenerStep::Continue;
    }
    if kind == Some(ExactControlKind::ProbeResponse)
        && !parsed_stanza.as_ref().is_some_and(|document| {
            presence_delivery_stanza_matches(document, ClusterPresenceDelivery::CurrentReplay)
        })
    {
        return ListenerStep::Continue;
    }

    if kind == Some(ExactControlKind::SubscriptionPresence) {
        let (Some(authority), Some(control), Some(document)) =
            (authority, control.as_ref(), parsed_stanza.as_ref())
        else {
            return ListenerStep::Continue;
        };
        let root = document.root_element();
        let endpoints = root
            .attribute("from")
            .and_then(|jid| northstar_xmpp_types::jid::CanonicalJid::parse_bare(jid).ok())
            .zip(
                root.attribute("to")
                    .and_then(|jid| northstar_xmpp_types::jid::canonical_bare_key(jid).ok()),
            );
        let Some((owner, recipient)) = endpoints else {
            return ListenerStep::Continue;
        };
        if !subscription
            || control.source.is_some()
            || control.account_id != authority.recipient_id
            || control.auth_generation != authority.recipient_auth_generation
            || northstar_xmpp_types::jid::canonical_bare_key(target)
                .ok()
                .as_deref()
                != Some(recipient.as_str())
            || !message_policy
                .presence_authority_is_current(
                    &owner.bare(),
                    authority.owner_id,
                    authority.owner_auth_generation,
                    &recipient,
                    authority.recipient_id,
                    authority.recipient_auth_generation,
                )
                .await
        {
            return ListenerStep::Continue;
        }
    } else if authority.is_some() {
        return ListenerStep::Continue;
    }
    ListenerStep::Next((parsed_stanza, authority))
}

fn addressed_presence_matches(document: Option<&roxmltree::Document<'_>>, target: &str) -> bool {
    use northstar_xmpp_types::jid::CanonicalJid;

    let addresses = document
        .and_then(|document| document.root_element().attribute("to"))
        .and_then(|to| CanonicalJid::parse(to).ok())
        .zip(CanonicalJid::parse(target).ok());
    addresses.is_some_and(|(to, target)| {
        to.to_bare() == target.to_bare() && (to.resourcepart().is_none() || to == target)
    })
}
