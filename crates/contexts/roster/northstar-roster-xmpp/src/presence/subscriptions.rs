//! Handles local, federated and component presence subscription transitions and subscription stanza helpers.

use super::subscription_route::subscription_reply_allowed;
use super::*;

pub(super) async fn update_remote_presence_subscription<S: PresenceSession>(
    session: &S,
    request: RemoteSubscriptionRequest<'_>,
) -> Result<SubscriptionMutationDisposition> {
    let RemoteSubscriptionRequest {
        actor_id,
        expected_auth_generation,
        contact,
        kind,
        target_domain,
        stanza,
        bounce_to,
    } = request;
    let contact = northstar_xmpp_types::jid::canonicalize_bare(contact)?;
    let outcome = session
        .presence_service()
        .transition_remote_with_outbox(
            actor_id,
            expected_auth_generation,
            session.privacy_connection_id(),
            session.session_local_domain(),
            &contact,
            kind,
            target_domain,
            stanza,
            Some(bounce_to),
            session.roster_outbox_policy(),
        )
        .await?;
    let transition = match outcome {
        PresenceMutation::Unauthorized => {
            return Ok(SubscriptionMutationDisposition::Unauthorized);
        }
        PresenceMutation::PolicyDenied(reason) => {
            return Ok(SubscriptionMutationDisposition::PolicyDenied(reason));
        }
        PresenceMutation::Missing => return Ok(SubscriptionMutationDisposition::Missing),
        PresenceMutation::Transition(transition) => transition,
    };
    if transition.routed {
        session.roster_wake_outbox(Some(target_domain));
    }
    finish_remote_presence_transition(session, &contact, transition).await;
    Ok(SubscriptionMutationDisposition::Accepted(false))
}

pub(super) async fn finish_remote_presence_transition<S: PresenceSession>(
    session: &S,
    contact: &str,
    transition: RemoteSubscriptionTransition,
) {
    if let Some(change) = transition.change.as_ref() {
        if let Err(error) = session
            .roster_push_change(transition.actor.id, &transition.actor.username, change)
            .await
        {
            tracing::warn!(
                owner = %transition.actor.username,
                %contact,
                version = change.version,
                ?error,
                "failed to deliver committed federated roster transition"
            );
        }
    }
}

pub(super) async fn update_presence_subscription<S: PresenceSession>(
    session: &S,
    actor: &PresenceAccount,
    target_jid: &str,
    kind: &str,
    raw: &str,
    expected_target: &PresenceAccount,
) -> Result<SubscriptionMutationDisposition> {
    let target_jid = northstar_xmpp_types::jid::CanonicalJid::parse_bare(target_jid)?;
    if target_jid.domainpart() != session.session_local_domain() {
        return Ok(SubscriptionMutationDisposition::Missing);
    }
    let Some(target_name) = target_jid.localpart() else {
        return Ok(SubscriptionMutationDisposition::Missing);
    };
    let actor_jid = format!("{}@{}", actor.username, session.session_local_domain());
    let target_jid = format!("{}@{}", target_name, session.session_local_domain());
    let stamped_stanza = set_to(&set_from(raw, &actor_jid), &target_jid);
    let outcome = session
        .presence_service()
        .transition_local(LocalSubscriptionRequest {
            actor_id: actor.id,
            expected_auth_generation: actor.auth_generation,
            connection_id: session.privacy_connection_id(),
            local_domain: session.session_local_domain(),
            target_username: target_name,
            kind,
            stanza: &stamped_stanza,
            expected_target,
        })
        .await?;
    let transition = match outcome {
        PresenceMutation::Unauthorized => {
            return Ok(SubscriptionMutationDisposition::Unauthorized);
        }
        PresenceMutation::PolicyDenied(reason) => {
            return Ok(SubscriptionMutationDisposition::PolicyDenied(reason));
        }
        PresenceMutation::Missing => return Ok(SubscriptionMutationDisposition::Missing),
        PresenceMutation::Transition(transition) => transition,
    };
    let actor = transition.actor.clone();
    let target = transition.target.clone();
    let actor_jid = format!("{}@{}", actor.username, session.session_local_domain());
    let target_jid = format!("{}@{}", target.username, session.session_local_domain());
    let stamped_stanza = set_to(&set_from(raw, &actor_jid), &target_jid);

    // RFC 6121 requires the subscription notification to be delivered
    // before the resulting roster push.  Keep that ordering explicit here
    // instead of returning to the generic presence router (which cannot
    // distinguish available from roster-interested resources).
    match transition.effect {
        LocalPresenceEffect::AutoApproved => {
            let approved = XmlElement::namespaced("presence", "jabber:client")
                .attr("from", &target_jid)
                .attr("to", &actor_jid)
                .attr("type", "subscribed")
                .finish();
            if subscription_reply_allowed(session, &actor, &target_jid).await? {
                session.presence_try_send(approved.clone());
            }
            session
                .presence_deliver_approval(&target, &actor, &target_jid, &actor_jid, &approved)
                .await?;
        }
        LocalPresenceEffect::Forward => {
            session
                .presence_deliver_subscription(
                    &actor,
                    &target,
                    &actor_jid,
                    &target_jid,
                    &stamped_stanza,
                    transition
                        .pending_created_at_micros
                        .map(|created_at_micros| {
                            PendingSubscriptionKey::local(actor.id, created_at_micros)
                        }),
                )
                .await?;
        }
        LocalPresenceEffect::Suppressed => {}
    }

    if let Some(change) = transition.actor_change.as_ref() {
        if let Err(error) = session
            .roster_push_change(actor.id, &actor.username, change)
            .await
        {
            tracing::warn!(owner = %actor.username, version = change.version, ?error, "failed to deliver committed actor roster transition");
        }
    }
    if let Some(change) = transition.target_change.as_ref() {
        if let Err(error) = session
            .roster_push_change(target.id, &target.username, change)
            .await
        {
            tracing::warn!(owner = %target.username, version = change.version, ?error, "failed to deliver committed target roster transition");
        }
    }
    match transition.effect {
        LocalPresenceEffect::AutoApproved => {
            session
                .presence_send_current_exact(&target, &actor, &target_jid, &actor_jid)
                .await;
            return Ok(SubscriptionMutationDisposition::Accepted(false));
        }
        LocalPresenceEffect::Suppressed => {
            return Ok(SubscriptionMutationDisposition::Accepted(false));
        }
        LocalPresenceEffect::Forward => {}
    }
    if kind == "subscribe" && session.privacy_local_resources(&target_jid) == 0 {
        if let Err(error) = session.presence_notify_offline(target.id).await {
            tracing::warn!(target = %target.username, ?error, "failed to send post-commit subscription notification");
        }
    }
    if kind == "subscribed" {
        session
            .presence_send_current_exact(&actor, &target, &actor_jid, &target_jid)
            .await;
    }
    // Subscription stanzas were routed above to preserve notification ->
    // roster-push ordering and exact available-resource semantics.
    Ok(SubscriptionMutationDisposition::Accepted(false))
}

pub(super) fn should_resend_pending_outbound_subscription(
    first_available: bool,
    ask: Option<&str>,
) -> bool {
    northstar_presence_core::should_resend_pending_subscription(first_available, ask)
}

pub(super) fn subscription_policy_error(
    root: Node<'_, '_>,
    reason: PresencePolicyDenial,
) -> String {
    match reason {
        PresencePolicyDenial::Blocking => blocked_stanza_error(root),
        PresencePolicyDenial::Privacy => stanza_error(root, "cancel", "service-unavailable"),
    }
}

pub(super) fn stamped_subscription_presence(raw: &str, from_bare: &str, to_bare: &str) -> String {
    set_to(&set_from(raw, from_bare), to_bare)
}

#[cfg(test)]
mod tests;
