use crate::exact_presence::PresenceEffect;
use crate::presence::{full_jid_probe_available_response, presence_probe_status_response};
use crate::PresenceDeliveryHost;
use anyhow::Result;
use northstar_roster_application::probe_decision::{
    PresenceRoute, ProbeCandidate, ProbeDecision, ProbeQuery, ProbeStatus,
};
use northstar_roster_core::{
    ClusterPresenceAuthority, ExactPresenceRoute, PresenceAccount, RosterActor,
};
use northstar_stream::local_routes::session::OnlineSession;
use northstar_xml_builder::rewrite::{project_presence_avatar, set_to};
use northstar_xml_builder::XmlElement;
use northstar_xmpp_types::jid::CanonicalJid;
use std::sync::atomic::Ordering;
use uuid::Uuid;

pub fn account_has_available_resource<H: PresenceDeliveryHost>(host: &H, bare: &str) -> bool {
    host.session_entries_for(bare)
        .into_iter()
        .any(|(_, session)| session.available.load(Ordering::Acquire))
}

pub async fn answer_full_presence_probe<H: PresenceDeliveryHost>(
    host: &H,
    owner_full: &str,
    _owner_bare: &str,
    requester: &str,
    probe_id: Option<&str>,
) -> Result<Option<String>> {
    let Some((full_jid, session)) = host.session_entries_for(requester).into_iter().next() else {
        return Ok(None);
    };
    if let Some(owner) = resolve_account(host, owner_full).await? {
        let actor = RosterActor {
            full_jid,
            account_id: session.user_id,
            auth_generation: session.auth_generation,
            connection_id: session.connection_id,
        };
        answer_local_probe(
            host,
            &owner,
            owner_full,
            &actor,
            session.privacy_active_snapshot(),
            probe_id,
        )
        .await?;
    }
    Ok(None)
}

pub async fn answer_local_probe<H: PresenceDeliveryHost>(
    host: &H,
    owner: &PresenceAccount,
    target: &str,
    requester: &RosterActor,
    active_list: Option<String>,
    id: Option<&str>,
) -> Result<()> {
    let recipient = PresenceRoute {
        exact: ExactPresenceRoute {
            account_id: requester.account_id,
            auth_generation: requester.auth_generation,
            connection_id: requester.connection_id,
            full_jid: requester.full_jid.clone(),
            node_id: None,
        },
        active_list,
    };
    let recipients = [recipient];
    let query = ProbeQuery {
        owner,
        target,
        requester: &requester.full_jid,
        candidates: &[],
        recipients: &recipients,
        explicit: true,
    };
    let status = resolve_current(host, query).await?;
    let Some(stanza) = probe_status_stanza(status, target, &requester.full_jid, id) else {
        return Ok(());
    };
    host.send_presence_route(
        requester,
        &recipients[0],
        &stanza,
        PresenceEffect::ProbeResponse,
        false,
    )
    .await?;
    Ok(())
}

fn probe_status_stanza(
    status: ProbeStatus,
    target: &str,
    requester: &str,
    id: Option<&str>,
) -> Option<String> {
    let kind = match status {
        ProbeStatus::Unsubscribed => "unsubscribed",
        ProbeStatus::Unavailable => "unavailable",
        ProbeStatus::Silent | ProbeStatus::Available => return None,
    };
    Some(presence_probe_status_response(
        northstar_xmpp_types::jid_text::bare_jid(target),
        requester,
        kind,
        id,
    ))
}

pub async fn send_current_availability<H: PresenceDeliveryHost>(
    host: &H,
    owner: &str,
    recipient: &str,
) {
    let Ok(Some(owner_account)) = resolve_account(host, owner).await else {
        return;
    };
    let Ok(Some(recipient_account)) = resolve_account(host, recipient).await else {
        return;
    };
    if let Err(error) =
        capture_and_replay(host, &owner_account, owner, &recipient_account, recipient).await
    {
        tracing::warn!(?error, %owner, %recipient, "current presence replay failed");
    }
}

pub async fn send_current_availability_exact<H: PresenceDeliveryHost>(
    host: &H,
    owner: &str,
    expected_owner_id: Uuid,
    expected_owner_auth_generation: i64,
    recipient: &str,
    expected_recipient_id: Uuid,
    expected_recipient_auth_generation: i64,
) {
    let Ok(owner_address) = CanonicalJid::parse(owner) else {
        return;
    };
    let Ok(recipient_address) = CanonicalJid::parse(recipient) else {
        return;
    };
    let (Some(owner_name), Some(recipient_name)) =
        (owner_address.localpart(), recipient_address.localpart())
    else {
        return;
    };
    let owner_account = PresenceAccount {
        id: expected_owner_id,
        auth_generation: expected_owner_auth_generation,
        username: owner_name.to_owned(),
    };
    let recipient_account = PresenceAccount {
        id: expected_recipient_id,
        auth_generation: expected_recipient_auth_generation,
        username: recipient_name.to_owned(),
    };
    if let Err(error) =
        capture_and_replay(host, &owner_account, owner, &recipient_account, recipient).await
    {
        tracing::warn!(?error, %owner, %recipient, "current presence replay failed");
    }
}

async fn resolve_account<H: PresenceDeliveryHost>(
    host: &H,
    address: &str,
) -> Result<Option<PresenceAccount>> {
    let jid = CanonicalJid::parse(address)?;
    match jid.localpart() {
        Some(name) if jid.domainpart() == host.local_domain() => {
            host.presence_service().find_enabled_user(name).await
        }
        _ => Ok(None),
    }
}

async fn capture_and_replay<H: PresenceDeliveryHost>(
    host: &H,
    owner: &PresenceAccount,
    target: &str,
    recipient: &PresenceAccount,
    recipient_jid: &str,
) -> Result<()> {
    let routes = host
        .capture_presence_routes(recipient_jid, recipient, true)
        .await?;
    replay_to_captured_routes(host, owner, target, recipient_jid, &routes).await
}

pub async fn replay_to_captured_routes<H: PresenceDeliveryHost>(
    host: &H,
    owner: &PresenceAccount,
    target: &str,
    requester: &str,
    recipients: &[PresenceRoute],
) -> Result<()> {
    if !recipients.is_empty() {
        resolve_current(
            host,
            ProbeQuery {
                owner,
                target,
                requester,
                candidates: &[],
                recipients,
                explicit: false,
            },
        )
        .await?;
    }
    Ok(())
}

async fn resolve_current<H: PresenceDeliveryHost>(
    host: &H,
    query: ProbeQuery<'_>,
) -> Result<ProbeStatus> {
    let full = CanonicalJid::parse(query.target)?.resourcepart().is_some();
    let local = host
        .session_entries_for(query.target)
        .into_iter()
        .filter(|(_, session)| {
            session.user_id == query.owner.id
                && session.auth_generation == query.owner.auth_generation
        })
        .map(|(full_jid, session)| {
            let route = PresenceRoute {
                exact: ExactPresenceRoute {
                    account_id: session.user_id,
                    auth_generation: session.auth_generation,
                    connection_id: session.connection_id,
                    full_jid,
                    node_id: None,
                },
                active_list: session.privacy_active_snapshot(),
            };
            let candidate = ProbeCandidate {
                route,
                available: session.available.load(Ordering::Acquire),
                directed: full && has_directed_grant(&session, query.requester),
            };
            (candidate, session)
        })
        .collect::<Vec<_>>();
    let remote = host
        .capture_presence_routes(query.target, query.owner, false)
        .await?
        .into_iter()
        .filter(|route| {
            route.exact.node_id.is_some()
                && local
                    .iter()
                    .all(|(candidate, _)| candidate.route.exact.full_jid != route.exact.full_jid)
        })
        .collect::<Vec<_>>();
    let candidates = local
        .iter()
        .map(|(candidate, _)| candidate.clone())
        .collect::<Vec<_>>();
    let decision = host
        .presence_service()
        .decide_probe(ProbeQuery {
            candidates: &candidates,
            ..query.clone()
        })
        .await?;
    if let ProbeDecision::Unavailable {
        directed: Some(index),
    } = &decision
    {
        let route = &candidates[*index].route;
        if !host
            .session_entries_for(&route.exact.full_jid)
            .iter()
            .any(|(_, current)| probe_owner_is_current(route, current, query.requester, true))
        {
            return Ok(ProbeStatus::Silent);
        }
    }
    if let ProbeDecision::Available(deliveries) = &decision {
        let hash = if full {
            Ok(None)
        } else {
            host.presence_service().avatar_hash(query.owner.id).await
        };
        for delivery in deliveries {
            let (candidate, sampled) = &local[delivery.owner];
            let Some(recipient) = delivery.recipient.map(|index| &query.recipients[index]) else {
                continue;
            };
            let route = &candidate.route.exact;
            let Some(current) = host.local_presence_owner_if_current(
                &route.full_jid,
                sampled,
                route.account_id,
                route.auth_generation,
            ) else {
                continue;
            };
            if !probe_owner_is_current(
                &candidate.route,
                &current,
                query.requester,
                delivery.directed,
            ) {
                continue;
            }
            let Some(cached) = current.current_presence() else {
                continue;
            };
            let source = RosterActor {
                account_id: route.account_id,
                auth_generation: route.auth_generation,
                connection_id: route.connection_id,
                full_jid: route.full_jid.clone(),
            };
            let presence = render_current(
                cached,
                &source.full_jid,
                query.requester,
                full,
                hash.as_ref().map(|hash| hash.as_deref()).ok(),
            );
            host.send_presence_route(
                &source,
                recipient,
                &presence,
                if query.explicit {
                    PresenceEffect::ProbeResponse
                } else {
                    PresenceEffect::CurrentReplay
                },
                !query.explicit || !full,
            )
            .await?;
        }
    }
    let status = decision.status();
    if let Some(remote) = host.request_captured_presence(query, &remote).await? {
        // The one full-JID owner was captured on the peer. The local empty
        // route set supplied policy screening, but cannot overrule its grant.
        if full && local.is_empty() && status != ProbeStatus::Silent {
            return Ok(remote);
        }
        return Ok(status.combine(remote));
    }
    Ok(status)
}

fn has_directed_grant(session: &OnlineSession, requester: &str) -> bool {
    session
        .directed_presence
        .iter()
        .any(|grant| northstar_presence_core::directed_recipient_matches(grant.key(), requester))
}

fn probe_owner_is_current(
    captured: &PresenceRoute,
    current: &OnlineSession,
    requester: &str,
    directed: bool,
) -> bool {
    current.user_id == captured.exact.account_id
        && current.auth_generation == captured.exact.auth_generation
        && current.connection_id == captured.exact.connection_id
        && current.privacy_active_snapshot() == captured.active_list
        && (!directed || has_directed_grant(current, requester))
}

/// Renders the atomically sampled presence of an available owner. A failed avatar read
/// (`hash` of `None`) omits the photo; a cache the projection rejects falls back to bare
/// availability.
fn render_current(
    cached: Option<String>,
    from: &str,
    recipient: &str,
    availability_only: bool,
    hash: Option<Option<&str>>,
) -> String {
    if availability_only {
        let id = cached.as_deref().and_then(presence_id);
        return full_jid_probe_available_response(from, recipient, id.as_deref());
    }
    cached
        .and_then(|presence| project_presence_avatar(&presence, hash))
        .map(|presence| set_to(&presence, recipient))
        .unwrap_or_else(|| {
            XmlElement::namespaced("presence", "jabber:client")
                .attr("from", from)
                .attr("to", recipient)
                .finish()
        })
}

pub(super) fn cluster_authority(
    owner: &PresenceAccount,
    recipient: &PresenceAccount,
) -> ClusterPresenceAuthority {
    ClusterPresenceAuthority {
        owner_id: owner.id,
        owner_auth_generation: owner.auth_generation,
        recipient_id: recipient.id,
        recipient_auth_generation: recipient.auth_generation,
    }
}

fn presence_id(raw: &str) -> Option<String> {
    let document = roxmltree::Document::parse(raw).ok()?;
    document
        .root_element()
        .attribute("id")
        .filter(|id| !id.is_empty() && id.len() <= 1_024 && !id.chars().any(char::is_control))
        .map(str::to_owned)
}

#[cfg(test)]
mod tests;
