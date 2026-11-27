//! Handle presence probes, blocking changes, and delivery authority checks.

use super::*;
use crate::listener_dispatch::ClusterListenerDispatch;
use northstar_stream::outbound::PresenceDelivery;
use northstar_xml_builder::rewrite::project_presence_avatar;

mod blocking;
mod validate;

pub(super) use self::blocking::deliver_blocking_presence;
pub(super) use self::validate::validate_stanza_presence;

pub(super) fn delivery_scope(
    control: Option<&crate::delivery_contract::ExactControl>,
    legacy_replay: bool,
) -> Option<PresenceDelivery> {
    use crate::delivery_contract::ExactControlKind;

    match control.map(|control| control.kind) {
        Some(ExactControlKind::CurrentPresenceReplay | ExactControlKind::ProbeResponse) => {
            Some(PresenceDelivery::ProbeReply)
        }
        Some(ExactControlKind::DirectedPresence | ExactControlKind::FederatedInboundPresence) => {
            Some(PresenceDelivery::Directed)
        }
        Some(
            ExactControlKind::AvailablePresence
            | ExactControlKind::UnavailablePresence
            | ExactControlKind::TeardownUnavailable,
        ) => Some(
            control
                .and_then(|control| {
                    Some(PresenceDelivery::RemoteStatus {
                        connection: control.source.as_ref()?.connection_id,
                        sequence: control.sequence?,
                    })
                })
                .unwrap_or(PresenceDelivery::Status { source_epoch: None }),
        ),
        None if legacy_replay => Some(PresenceDelivery::ProbeReply),
        _ => None,
    }
}

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
        let authoritative_avatar_hash = if availability_only {
            None
        } else {
            message_policy
                .owner_avatar_hash(authority.owner_id)
                .await
                .ok()
        };
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
            let Some(cached) = session.current_presence() else {
                continue;
            };
            let presence = if availability_only {
                let original_id = cached.and_then(|presence| {
                    let document = roxmltree::Document::parse(&presence).ok()?;
                    document
                        .root_element()
                        .attribute("id")
                        .filter(|id| {
                            !id.is_empty() && id.len() <= 1_024 && !id.chars().any(char::is_control)
                        })
                        .map(str::to_owned)
                });
                northstar_xml_builder::XmlElement::namespaced("presence", "jabber:client")
                    .attr("from", &owner_full)
                    .attr("to", &recipient)
                    .optional_attr("id", original_id.as_deref())
                    .finish()
            } else {
                cached
                    .and_then(|presence| {
                        project_presence_avatar(
                            &presence,
                            authoritative_avatar_hash
                                .as_ref()
                                .map(|hash| hash.as_deref()),
                        )
                    })
                    .map(|presence| set_to(&presence, &recipient))
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
                    *delivered += usize::from(
                        recipient_session
                            .sender
                            .try_send_presence(presence.clone(), PresenceDelivery::ProbeReply)
                            .is_ok(),
                    );
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
