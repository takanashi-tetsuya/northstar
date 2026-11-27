use super::*;
use crate::listener_dispatch::ClusterListenerDispatch;
use crate::{
    presence_routing::CapturedPresenceProbe, ExactControlKind, EXACT_CONTROL_DELIVERY_VERSION,
};
use northstar_message_application::messaging::ExactMessageRoute;
use northstar_roster_application::probe_decision::{
    PresenceRoute, ProbeCandidate, ProbeDecision, ProbeQuery, ProbeStatus,
};
use northstar_roster_core::{ExactPresenceRoute, PresenceAccount, RosterActor};
use northstar_stream::local_routes::session::OnlineSession;
use northstar_stream::local_routes::session_table::LocalSessionTable;
use northstar_stream::outbound::PresenceDelivery;
use northstar_xml_builder::rewrite::project_presence_avatar;
use northstar_xmpp_types::jid::CanonicalJid;

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
    if json["protocol_version"].as_str() != Some(EXACT_CONTROL_DELIVERY_VERSION)
        || !json["exact_control"].is_null()
        || !json["stanza"].is_null()
    {
        admission.note_incompatible_peer_version(source_node, json["protocol_version"].as_str());
        return Ok(ListenerStep::Continue);
    }
    let Ok(probe) =
        serde_json::from_value::<CapturedPresenceProbe>(json["captured_presence_probe"].clone())
    else {
        return Ok(ListenerStep::Continue);
    };
    let (Ok(owner), Ok(requester)) = (
        CanonicalJid::parse(target),
        CanonicalJid::parse(&probe.requester),
    ) else {
        return Ok(ListenerStep::Continue);
    };
    let Some(username) = owner.localpart() else {
        return Ok(ListenerStep::Continue);
    };
    if owner.domainpart() != message_policy.local_domain
        || requester.domainpart() != message_policy.local_domain
        || probe.owner_id.is_nil()
        || probe.owner_auth_generation < 0
        || probe.owners.is_empty()
        || probe.recipients.is_empty()
        || probe
            .owners
            .iter()
            .any(|(jid, connection)| connection.is_nil() || !captured_address(&owner, jid))
        || probe.recipients.iter().any(|route| {
            route.account_id.is_nil()
                || route.auth_generation < 0
                || route.connection_id.is_nil()
                || route.node_id.as_ref().is_none_or(String::is_empty)
                || !captured_address(&requester, &route.full_jid)
                || (probe.explicit && route.node_id.as_deref() != Some(source_node))
        })
    {
        return Ok(ListenerStep::Continue);
    }
    let owner_account = PresenceAccount {
        id: probe.owner_id,
        auth_generation: probe.owner_auth_generation,
        username: username.to_owned(),
    };
    let full = owner.resourcepart().is_some();
    let candidates: Vec<_> = dispatch
        .session_entries_for(target)
        .into_iter()
        .filter(|(jid, session)| {
            session.user_id == probe.owner_id
                && session.auth_generation == probe.owner_auth_generation
                && probe.owners.get(jid) == Some(&session.connection_id)
        })
        .map(|(full_jid, session)| ProbeCandidate {
            available: session.available.load(Ordering::Acquire),
            directed: full && directed_grant(&session, &probe.requester),
            route: PresenceRoute {
                exact: ExactPresenceRoute {
                    account_id: session.user_id,
                    auth_generation: session.auth_generation,
                    connection_id: session.connection_id,
                    full_jid,
                    node_id: None,
                },
                active_list: session.privacy_active_snapshot(),
            },
        })
        .collect();
    let table = LocalSessionTable::new(Arc::clone(&dispatch.account_routes.sessions));
    let recipients: Vec<_> = probe
        .recipients
        .into_iter()
        .filter_map(|exact| {
            let active_list = if exact.node_id.as_deref() == Some(dispatch.node_id()) {
                table.with_exact_message_route(
                    &message_route(&exact),
                    OnlineSession::privacy_active_snapshot,
                )?
            } else {
                None
            };
            Some(PresenceRoute { exact, active_list })
        })
        .collect();
    let decision = message_policy
        .presence
        .decide_probe(ProbeQuery {
            owner: &owner_account,
            target,
            requester: &probe.requester,
            candidates: &candidates,
            recipients: &recipients,
            explicit: probe.explicit,
        })
        .await?;
    let status = if let ProbeDecision::Unavailable {
        directed: Some(index),
    } = &decision
    {
        let route = &candidates[*index].route;
        let still_directed =
            table.with_exact_message_route(&message_route(&route.exact), |session| {
                session.privacy_active_snapshot() == route.active_list
                    && directed_grant(session, &probe.requester)
            });
        if still_directed == Some(true) {
            ProbeStatus::Unavailable
        } else {
            ProbeStatus::Silent
        }
    } else {
        decision.status()
    };
    turn.control_outcome = Some(match status {
        ProbeStatus::Silent => ClusterControlOutcome::PresenceSilent,
        ProbeStatus::Unsubscribed => ClusterControlOutcome::PresenceUnsubscribed,
        ProbeStatus::Unavailable => ClusterControlOutcome::PresenceUnavailable,
        ProbeStatus::Available => ClusterControlOutcome::PresenceAvailable,
    });
    if let ProbeDecision::Available(deliveries) = decision {
        let hash = if full {
            Ok(None)
        } else {
            message_policy.owner_avatar_hash(probe.owner_id).await
        };
        for delivery in deliveries {
            let owner = &candidates[delivery.owner].route;
            let Some(recipient) = delivery.recipient.map(|index| &recipients[index]) else {
                continue;
            };
            let stanza = table
                .with_exact_message_route(&message_route(&owner.exact), |session| {
                    if session.privacy_active_snapshot() != owner.active_list
                        || (delivery.directed && !directed_grant(session, &probe.requester))
                    {
                        return None;
                    }
                    Some(render(
                        session.current_presence()?,
                        &owner.exact.full_jid,
                        &probe.requester,
                        full,
                        hash.as_ref().map(|hash| hash.as_deref()).ok(),
                    ))
                })
                .flatten();
            let Some(stanza) = stanza else { continue };
            if recipient.exact.node_id.as_deref() == Some(dispatch.node_id()) {
                let sent =
                    table.with_exact_message_route(&message_route(&recipient.exact), |session| {
                        (probe.explicit && full || session.available.load(Ordering::Acquire))
                            && session.privacy_active_snapshot() == recipient.active_list
                            && session
                                .sender
                                .try_send_presence(stanza.clone(), PresenceDelivery::ProbeReply)
                                .is_ok()
                    });
                turn.delivered += usize::from(sent == Some(true));
            } else if let Some(node_id) = &recipient.exact.node_id {
                let source = RosterActor {
                    account_id: owner.exact.account_id,
                    auth_generation: owner.exact.auth_generation,
                    connection_id: owner.exact.connection_id,
                    full_jid: owner.exact.full_jid.clone(),
                };
                let kind = if probe.explicit {
                    ExactControlKind::ProbeResponse
                } else {
                    ExactControlKind::CurrentPresenceReplay
                };
                let control =
                    crate::node_delivery::presence_control(&source, &recipient.exact, kind);
                turn.responses.push(ListenerResponse {
                    node_id: node_id.clone(),
                    recipient: recipient.exact.full_jid.clone(),
                    stanza,
                    exact_control: Some(control),
                })?;
            }
        }
    }
    turn.control_processed = Some(true);
    Ok(ListenerStep::Next(()))
}

fn captured_address(address: &CanonicalJid, full: &str) -> bool {
    CanonicalJid::parse(full).is_ok_and(|jid| {
        jid.resourcepart().is_some()
            && jid.to_string() == full
            && jid.to_bare() == address.to_bare()
            && (address.resourcepart().is_none() || address == &jid)
    })
}

fn directed_grant(session: &OnlineSession, requester: &str) -> bool {
    session.directed_presence.iter().any(|grant| {
        let target = grant.key();
        target == requester || target == northstar_xmpp_types::jid_text::bare_jid(requester)
    })
}

fn message_route(route: &ExactPresenceRoute) -> ExactMessageRoute {
    ExactMessageRoute {
        full_jid: route.full_jid.clone(),
        account_id: route.account_id,
        auth_generation: route.auth_generation,
        connection_id: route.connection_id,
        node_id: None,
        priority: None,
        available: None,
    }
}

/// Renders an atomically sampled cached presence. A failed avatar read (`hash` of `None`)
/// omits the photo; a cache the projection rejects falls back to bare availability.
fn render(
    cached: Option<String>,
    from: &str,
    to: &str,
    availability_only: bool,
    hash: Option<Option<&str>>,
) -> String {
    let initial = northstar_xml_builder::XmlElement::namespaced("presence", "jabber:client")
        .attr("from", from)
        .attr("to", to);
    if availability_only {
        let document = cached
            .as_deref()
            .and_then(|raw| roxmltree::Document::parse(raw).ok());
        let id = document
            .as_ref()
            .and_then(|document| document.root_element().attribute("id"))
            .filter(|id| !id.is_empty() && id.len() <= 1_024 && !id.chars().any(char::is_control));
        return initial.optional_attr("id", id).finish();
    }
    cached
        .and_then(|presence| project_presence_avatar(&presence, hash))
        .map(|presence| set_to(&presence, to))
        .unwrap_or_else(|| initial.finish())
}
