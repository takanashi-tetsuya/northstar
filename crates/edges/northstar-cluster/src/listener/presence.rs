//! Handle presence probes, blocking changes, and delivery authority checks.

use super::*;
use crate::{
    listener_blocking::ClusterListenerBlocking, listener_dispatch::ClusterListenerDispatch,
};

pub(super) async fn handle_presence_probe<A: ClusterAdapters>(
    admission: &ClusterListenerAdmission,
    dispatch: &ClusterListenerDispatch<A>,
    message_policy: &ClusterListenerMessagePolicy<A>,
    source_node: &str,
    json: &serde_json::Value,
    target: &str,
    turn: &mut ListenerTurn,
) -> Result<ListenerStep<()>> {
    let ListenerTurn {
        delivered,
        control_processed,
        responses,
        ..
    } = turn;
    if json["protocol_version"].as_str() != Some(NODE_PROTOCOL_VERSION) {
        admission.note_incompatible_peer_version(source_node, json["protocol_version"].as_str());
        return Ok(ListenerStep::Continue);
    }
    let owner = northstar_xmpp_types::jid::canonicalize(target).ok();
    let recipient = json["recipient"]
        .as_str()
        .and_then(|recipient| northstar_xmpp_types::jid::canonicalize(recipient).ok());
    let availability_only = json["availability_only"].as_bool().unwrap_or(false);
    let authority = match presence_authority(json) {
        Ok(Some(authority)) => Some(authority),
        Ok(None) => {
            admission.note_authentication_failure(&anyhow::anyhow!(
                "cluster presence probe omitted versioned account authority"
            ));
            return Ok(ListenerStep::Continue);
        }
        Err(error) => {
            admission.note_authentication_failure(&error);
            return Ok(ListenerStep::Continue);
        }
    };
    if let (Some(owner), Some(recipient), Some(authority)) = (owner, recipient, authority) {
        if !message_policy
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
                "cluster presence probe account authority is stale or mismatched"
            ));
            return Ok(ListenerStep::Continue);
        }
        let authoritative_avatar_hash = message_policy
            .owner_avatar_hash(authority.owner_id)
            .await
            .ok();
        let mut presences = Vec::new();
        for (owner_full, session) in dispatch.session_entries_for(&owner) {
            if session.user_id != authority.owner_id
                || session.auth_generation != authority.owner_auth_generation
                || !session.available.load(Ordering::Acquire)
                || !message_policy
                    .privacy_allows_session(
                        session.user_id,
                        session.connection_id,
                        active_privacy_list(&session.privacy_active).as_deref(),
                        &recipient,
                        northstar_xep_0016::PrivacyStanzaKind::PresenceOut,
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
                northstar_xml_builder::XmlElement::namespaced("presence", "jabber:client")
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
                                let document = roxmltree::Document::parse(&presence).ok()?;
                                Some(
                                    northstar_xmpp_avatar::vcard_update::inject_vcard_avatar_hash(
                                        &presence,
                                        document.root_element(),
                                        hash.as_deref(),
                                    ),
                                )
                            })
                            .unwrap_or(presence);
                        set_to(&presence, &recipient)
                    })
                    .unwrap_or_else(|| {
                        northstar_xml_builder::XmlElement::namespaced("presence", "jabber:client")
                            .attr("from", &owner_full)
                            .attr("to", &recipient)
                            .finish()
                    })
            };
            presences.push(presence);
        }

        let mut processed = true;
        for presence in presences {
            for (_, recipient_session) in dispatch
                .session_entries_for(&recipient)
                .into_iter()
                .filter(|(_, session)| {
                    session.user_id == authority.recipient_id
                        && session.auth_generation == authority.recipient_auth_generation
                        && session.available.load(Ordering::Acquire)
                })
            {
                if message_policy
                    .privacy_allows_session(
                        recipient_session.user_id,
                        recipient_session.connection_id,
                        active_privacy_list(&recipient_session.privacy_active).as_deref(),
                        &owner,
                        northstar_xep_0016::PrivacyStanzaKind::PresenceIn,
                    )
                    .await
                    .unwrap_or(false)
                {
                    *delivered +=
                        usize::from(recipient_session.sender.try_send(presence.clone()).is_ok());
                }
            }
            match dispatch.remote_presence_nodes(&recipient).await {
                Ok(nodes) => {
                    for node_id in nodes {
                        responses.push(ListenerResponse {
                            node_id,
                            recipient: recipient.clone(),
                            stanza: presence.clone(),
                            presence_authority: Some(authority),
                        })?;
                    }
                }
                Err(error) => {
                    processed = false;
                    message_policy.presence_probe_failed();
                    tracing::warn!(?error, %owner, %recipient, "could not resolve cross-node initial-presence recipients");
                }
            }
        }
        *control_processed = Some(processed);
    }
    Ok(ListenerStep::Next(()))
}

pub(super) async fn deliver_blocking_presence<A: ClusterAdapters>(
    blocking: &ClusterListenerBlocking<A>,
    json: &serde_json::Value,
    target: &str,
    turn: &mut ListenerTurn,
) -> Result<()> {
    let responses = &mut turn.responses;
    let owner = northstar_xmpp_types::jid::canonicalize_bare(target).ok();
    let targets = json["blocking_targets"]
        .as_array()
        .filter(|items| items.len() <= northstar_xep_0191::MAX_ITEMS)
        .and_then(|items| {
            items
                .iter()
                .map(|item| {
                    item.as_str()
                        .and_then(|jid| northstar_xmpp_types::jid::canonicalize(jid).ok())
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
                        .and_then(|jid| northstar_xmpp_types::jid::canonicalize(jid).ok())
                })
                .collect::<Option<Vec<_>>>()
        });
    if let (Some(owner), Some(targets), Some(patterns)) = (owner, targets, patterns) {
        blocking
            .deliver_presence_change(
                &owner,
                &targets,
                &patterns,
                json["available"].as_bool().unwrap_or(false),
                |node_id, recipient, stanza| {
                    responses.push(ListenerResponse {
                        node_id,
                        recipient,
                        stanza,
                        presence_authority: None,
                    })
                },
            )
            .await?;
    }
    Ok(())
}

pub(super) async fn validate_stanza_presence<'a, A: ClusterAdapters>(
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
