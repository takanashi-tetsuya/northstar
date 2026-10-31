//! Handles directed presence tracking, authorized probes, current availability delivery and their supporting helpers.

use super::*;

pub(super) async fn plan_directed_presence<S: PresenceSession>(
    session: &S,
    user: &PresenceAccount,
    target: &str,
    kind: &str,
) -> Result<DirectedPresencePlan> {
    if kind == "unavailable" {
        return Ok(DirectedPresencePlan::Remove(target.to_owned()));
    }
    if kind != "available" {
        return Ok(DirectedPresencePlan::None);
    }
    let target_bare = northstar_xmpp_types::jid::canonical_bare_key(target)?;
    let receives_broadcast = session.presence_is_available()
        && session
            .presence_service()
            .roster_subscription(user.id, &target_bare)
            .await?
            .is_some_and(|subscription| matches!(subscription.as_str(), "from" | "both"));
    if receives_broadcast {
        return Ok(DirectedPresencePlan::RemoveBroadcastScope(target_bare));
    }
    if session.presence_directed_contains(target) {
        return Ok(DirectedPresencePlan::None);
    }
    if directed_presence_capacity_reached(session.presence_directed_count(), false) {
        return Ok(DirectedPresencePlan::AtCapacity);
    }
    Ok(DirectedPresencePlan::Insert(target.to_owned()))
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
        DirectedPresencePlan::RemoveBroadcastScope(target_bare) => {
            remove_directed_presence_for_bare(session, &target_bare);
        }
        DirectedPresencePlan::None | DirectedPresencePlan::AtCapacity => {}
    }
}

pub(super) fn remove_directed_presence_for_bare<S: PresenceSession>(
    session: &S,
    target_bare: &str,
) {
    session.presence_directed_retain(|target| {
        directed_presence_target_is_outside_bare_scope(target, target_bare)
    });
}

pub(super) async fn answer_directed_presence_probe<S: PresenceSession>(
    session: &S,
    owner_full: &str,
    owner_bare: &str,
    requester: &str,
    probe_id: Option<&str>,
) -> Result<bool> {
    if !session.presence_directed_recipient(owner_full, requester) {
        return Ok(false);
    }
    session
        .presence_answer_full_probe(owner_full, owner_bare, requester, probe_id)
        .await?;
    Ok(true)
}

pub(super) async fn broadcast_directed_unavailable<S: PresenceSession>(
    session: &S,
    unavailable: &str,
    from: &str,
) {
    let targets = session.presence_directed_take();
    for target in targets {
        let delivery = set_to(unavailable, &target);
        let Ok(jid) = northstar_xmpp_types::jid::CanonicalJid::parse(&target) else {
            continue;
        };
        if jid.domainpart() == session.session_local_domain() {
            session
                .presence_deliver_directed_unavailable(
                    &target,
                    jid.resourcepart().is_none(),
                    from,
                    &delivery,
                )
                .await;
        } else {
            let _ = session
                .presence_send_federated(jid.domainpart(), delivery, Some(from.to_owned()))
                .await;
        }
    }
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
