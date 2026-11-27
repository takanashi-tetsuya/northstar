//! Handles directed presence tracking, authorized probes, current availability delivery and their supporting helpers.

use super::*;
use crate::presence_delivery::DirectedDelivery;
use northstar_roster_core::ExactPresenceRoute;
use northstar_stream::session_cleanup::unavailable::{DirectedGrant, TerminalRoute};

pub(super) fn plan_directed_presence<S: PresenceSession>(
    session: &S,
    target: &str,
    kind: &str,
) -> DirectedPresencePlan {
    if kind == "unavailable" {
        return DirectedPresencePlan::Remove(target.to_owned());
    }
    if kind != "available" {
        return DirectedPresencePlan::None;
    }
    if directed_presence_capacity_reached(
        session.presence_directed_count(),
        session.presence_directed_contains(target),
    ) {
        return DirectedPresencePlan::AtCapacity;
    }
    DirectedPresencePlan::Insert(target.to_owned())
}

pub(super) fn commit_directed_presence<S: PresenceSession>(
    session: &S,
    plan: DirectedPresencePlan,
) {
    match plan {
        DirectedPresencePlan::Insert(target) => {
            session.presence_directed_insert(target);
        }
        DirectedPresencePlan::Remove(target) => {
            session.presence_directed_remove(&target);
        }
        DirectedPresencePlan::None | DirectedPresencePlan::AtCapacity => {}
    }
}

pub(super) fn remove_directed_presence_for_bare<S: PresenceSession>(
    session: &S,
    target_bare: &str,
) {
    session.presence_directed_retain(|target| {
        // The broadcast's address handoff covers an external grant. A local
        // grant identifies a transport, which a bare broadcast may not reach.
        DirectedGrant::decode(target).is_ok_and(|grant| grant.is_some())
            || directed_presence_target_is_outside_bare_scope(target, target_bare)
    });
}

fn grant(scope: &str, route: ExactPresenceRoute) -> DirectedGrant {
    DirectedGrant {
        scope: scope.to_owned(),
        route: TerminalRoute {
            account_id: route.account_id,
            auth_generation: route.auth_generation,
            connection_id: route.connection_id,
            full_jid: route.full_jid,
            node_id: route.node_id,
        },
    }
}

pub(super) async fn route_local_directed<S: PresenceSession>(
    session: &S,
    recipient: &PresenceAccount,
    scope: &str,
    stanza: &str,
    kind: &str,
) -> Result<bool> {
    let source = session
        .roster_actor()
        .ok_or_else(|| anyhow::anyhow!("directed presence has no bound actor"))?;
    let existing = grants_for_scope(session.presence_directed_entries(), scope);
    let withdraw = kind == "unavailable";
    let track = kind == "available";
    let free_slots = northstar_presence_core::MAX_DIRECTED_PRESENCE_RECIPIENTS
        .saturating_sub(session.presence_directed_count());
    if track && free_slots == 0 && existing.is_empty() {
        return Ok(true);
    }
    let receipt = session
        .presence_deliver_exact_directed(DirectedDelivery {
            source: &source,
            recipient,
            scope,
            stanza,
            existing: &existing,
            free_slots,
            track,
            withdraw,
        })
        .await;
    if track {
        for accepted in newly_accepted_grants(receipt.accepted, &existing, scope) {
            session.presence_directed_insert(accepted.encode());
        }
    } else if withdraw {
        session.presence_directed_remove(scope);
        for accepted in existing {
            if !receipt.remaining.iter().any(|route| {
                route.connection_id == accepted.route.connection_id
                    && route.full_jid == accepted.route.full_jid
            }) {
                session.presence_directed_remove(&accepted.encode());
            }
        }
    }
    if let Some(error) = receipt.error {
        return Err(error);
    }
    anyhow::ensure!(
        !withdraw || receipt.remaining.is_empty(),
        "directed withdrawal queue remained full"
    );
    Ok(receipt.at_capacity)
}

fn grants_for_scope(entries: Vec<String>, scope: &str) -> Vec<DirectedGrant> {
    entries
        .into_iter()
        .filter_map(|entry| DirectedGrant::decode(&entry).ok().flatten())
        .filter(|grant| grant.scope == scope)
        .collect()
}

fn newly_accepted_grants(
    accepted: Vec<ExactPresenceRoute>,
    existing: &[DirectedGrant],
    scope: &str,
) -> Vec<DirectedGrant> {
    accepted
        .into_iter()
        .map(|route| grant(scope, route))
        .filter(|accepted| {
            !existing
                .iter()
                .any(|grant| grant.route.same_transport(&accepted.route))
        })
        .collect()
}

pub(super) async fn broadcast_directed_unavailable<S: PresenceSession>(
    session: &S,
    unavailable: &str,
    from: &str,
) {
    let mut targets = session.presence_directed_entries();
    targets.sort_unstable();
    let mut scopes = std::collections::HashSet::new();
    for target in targets {
        if let Ok(Some(grant)) = DirectedGrant::decode(&target) {
            if !scopes.insert(grant.scope.clone()) {
                continue;
            }
            let Ok(jid) = northstar_xmpp_types::jid::CanonicalJid::parse(&grant.scope) else {
                continue;
            };
            let Some(username) = jid.localpart() else {
                continue;
            };
            match session.presence_service().find_enabled_user(username).await {
                Ok(Some(recipient)) => {
                    let delivery = set_to(unavailable, &grant.scope);
                    if let Err(error) = route_local_directed(
                        session,
                        &recipient,
                        &grant.scope,
                        &delivery,
                        "unavailable",
                    )
                    .await
                    {
                        tracing::warn!(?error, scope = %grant.scope, "directed presence withdrawal requires refresh");
                    }
                }
                Ok(None) => session.presence_directed_retain(|entry| {
                    DirectedGrant::decode(entry)
                        .ok()
                        .flatten()
                        .is_none_or(|entry| entry.scope != grant.scope)
                }),
                Err(error) => {
                    tracing::warn!(?error, scope = %grant.scope, "could not read directed presence recipient")
                }
            }
            continue;
        }
        let Ok(jid) = northstar_xmpp_types::jid::CanonicalJid::parse(&target) else {
            continue;
        };
        if jid.domainpart() == session.session_local_domain()
            || send_address_withdrawal(
                session,
                jid.domainpart(),
                set_to(unavailable, &target),
                from,
            )
            .await
        {
            session.presence_directed_remove(&target);
        }
    }
}

pub(super) async fn send_address_withdrawal<S: PresenceSession>(
    session: &S,
    domain: &str,
    stanza: String,
    from: &str,
) -> bool {
    session
        .presence_send_federated(domain, stanza.clone(), Some(from.to_owned()))
        .await
        || session
            .presence_send_federated(domain, stanza, Some(from.to_owned()))
            .await
}

pub(super) async fn probe_contact_presence<S: PresenceSession>(
    session: &S,
    contact: &str,
    requester_bare: &str,
) {
    let Ok(contact_jid) = northstar_xmpp_types::jid::CanonicalJid::parse_bare(contact) else {
        return;
    };
    if contact_jid.domainpart() == session.session_local_domain() {
        session.presence_send_current(contact, requester_bare).await;
        return;
    }
    if !session.presence_route_allowed(contact_jid.domainpart()) {
        return;
    }
    let probe = XmlElement::namespaced("presence", "jabber:client")
        .attr("from", requester_bare)
        .attr("to", contact)
        .attr("type", "probe")
        .finish();
    let _ = session
        .presence_send_federated(
            contact_jid.domainpart(),
            probe,
            Some(requester_bare.to_owned()),
        )
        .await;
}

pub fn full_jid_probe_available_response(
    owner_full: &str,
    requester: &str,
    original_presence_id: Option<&str>,
) -> String {
    XmlElement::namespaced("presence", "jabber:client")
        .attr("from", owner_full)
        .attr("to", requester)
        .optional_attr("id", original_presence_id)
        .finish()
}

pub fn presence_probe_status_response(
    target_bare: &str,
    requester: &str,
    kind: &str,
    id: Option<&str>,
) -> String {
    XmlElement::namespaced("presence", "jabber:client")
        .attr("from", target_bare)
        .attr("to", requester)
        .attr("type", kind)
        .optional_attr("id", id)
        .finish()
}

pub(super) fn unsubscribed_probe_response(
    target_bare: &str,
    requester: &str,
    id: Option<&str>,
) -> String {
    presence_probe_status_response(target_bare, requester, "unsubscribed", id)
}

pub(super) fn directed_presence_capacity_reached(current: usize, already_present: bool) -> bool {
    northstar_presence_core::directed_presence_capacity_reached(current, already_present)
}

pub(super) fn directed_presence_target_is_outside_bare_scope(
    target: &str,
    target_bare: &str,
) -> bool {
    northstar_presence_core::directed_presence_target_is_outside_bare_scope(target, target_bare)
}

#[cfg(test)]
mod tests;
