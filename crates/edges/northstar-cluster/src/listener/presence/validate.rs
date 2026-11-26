use super::*;

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
    let current_presence_replay = json["current_presence_replay"].as_bool() == Some(true);
    let presence_subscription = json["presence_subscription"].as_bool() == Some(true);
    if current_presence_replay && presence_subscription {
        return ListenerStep::Continue;
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
        admission.note_incompatible_peer_version(source_node, json["protocol_version"].as_str());
        return ListenerStep::Continue;
    }
    if (current_presence_replay || presence_subscription)
        && json["protocol_version"].as_str() != Some(NODE_PROTOCOL_VERSION)
    {
        admission.note_incompatible_peer_version(source_node, json["protocol_version"].as_str());
        return ListenerStep::Continue;
    }
    let parsed_presence_authority = match presence_authority(json) {
        Ok(authority) => authority,
        Err(error) => {
            admission.note_authentication_failure(&error);
            return ListenerStep::Continue;
        }
    };
    if current_presence_replay || presence_subscription {
        let Some(authority) = parsed_presence_authority else {
            admission.note_authentication_failure(&anyhow::anyhow!(
                "cluster presence delivery omitted versioned account authority"
            ));
            return ListenerStep::Continue;
        };
        let Some(document) = parsed_stanza.as_ref() else {
            return ListenerStep::Continue;
        };
        let root = document.root_element();
        let expected_delivery = if current_presence_replay {
            ClusterPresenceDelivery::CurrentReplay
        } else {
            ClusterPresenceDelivery::Subscription
        };
        let endpoints = root
            .attribute("from")
            .and_then(|from| northstar_xmpp_types::jid::canonicalize(from).ok())
            .zip(
                root.attribute("to")
                    .and_then(|to| northstar_xmpp_types::jid::canonicalize(to).ok()),
            );
        let Some((owner, recipient)) = endpoints else {
            return ListenerStep::Continue;
        };
        if !presence_delivery_stanza_matches(document, expected_delivery)
            || northstar_xmpp_types::jid::canonical_bare_key(&recipient).ok()
                != northstar_xmpp_types::jid::canonical_bare_key(target).ok()
            || !message_policy
                .presence_authority_is_current(
                    &owner,
                    authority.owner_id,
                    authority.owner_auth_generation,
                    &recipient,
                    authority.recipient_id,
                    authority.recipient_auth_generation,
                )
                .await
        {
            admission.note_authentication_failure(&anyhow::anyhow!(
                "cluster presence delivery account authority is stale or mismatched"
            ));
            return ListenerStep::Continue;
        }
    } else if parsed_presence_authority.is_some() {
        admission.note_authentication_failure(&anyhow::anyhow!(
            "ordinary cluster delivery carried executable presence authority"
        ));
        return ListenerStep::Continue;
    }
    ListenerStep::Next((parsed_stanza, parsed_presence_authority))
}
