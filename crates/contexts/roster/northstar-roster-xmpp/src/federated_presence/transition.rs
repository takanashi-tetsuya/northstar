use super::render::subscription_reply;
use super::replay::{send_current_presence_to_remote, send_unavailable_presence_to_remote};
use crate::{
    FederatedPresenceEffect, FederatedPresenceHandoff, FederatedPresenceHost,
    FederatedPresenceOwnerHost,
};
use anyhow::Result;
use northstar_federation_core::wire::s2s_stanza_error;
use northstar_federation_core::FederationRoute;
use northstar_roster_application::presence::{
    InboundRemotePresenceEffect, InboundSubscriptionRequest, InboundSubscriptionTransition,
    PresenceAccount, PresenceMutation, SubscriptionOutboxAdmissionError,
};
use northstar_roster_application::probe_decision::PresenceRoute;
use northstar_roster_core::{SubscriptionAction, SubscriptionReply};
use roxmltree::Node;
use std::ops::ControlFlow;

pub(super) async fn transition_inbound_subscription(
    state: &(impl FederatedPresenceHost + FederatedPresenceOwnerHost),
    root: Node<'_, '_>,
    kind: &str,
    recipient: &PresenceAccount,
    contact: &str,
    handoff: FederatedPresenceHandoff<'_>,
) -> Result<ControlFlow<Option<String>>> {
    let recipient_bare = format!("{}@{}", recipient.username, state.local_domain());
    let action = SubscriptionAction::parse(kind).expect("guarded above");
    let reply = |kind| subscription_reply(&recipient_bare, contact, kind, root.attribute("id"));
    let subscribed_reply = reply(SubscriptionReply::Subscribed);
    let unsubscribed_reply = reply(SubscriptionReply::Unsubscribed);
    let transition = match state
        .presence_service()
        .transition_inbound(InboundSubscriptionRequest {
            recipient,
            local_domain: state.local_domain(),
            contact,
            action,
            stanza: handoff.stanza,
            verified_peer: handoff.remote_peer,
            subscribed_reply: &subscribed_reply,
            unsubscribed_reply: &unsubscribed_reply,
            outbox_policy: state.federation_outbox().outbox_policy(),
        })
        .await
    {
        Ok(PresenceMutation::Transition(transition)) => transition,
        Ok(
            PresenceMutation::PolicyDenied(_)
            | PresenceMutation::Missing
            | PresenceMutation::Unauthorized,
        ) => {
            // The exact local UUID disappeared/was disabled, or its
            // account-wide inbound policy denied the authenticated remote
            // stanza. Inbound federation intentionally has no C2S
            // generation authority of its own.
            return Ok(ControlFlow::Break(None));
        }
        Err(error) if error.is::<SubscriptionOutboxAdmissionError>() => {
            tracing::warn!(?error, %contact, %kind, "federated subscription admission rolled back");
            return Ok(ControlFlow::Break(Some(s2s_stanza_error(
                root,
                "wait",
                "resource-constraint",
            ))));
        }
        Err(error) => return Err(error),
    };
    let recipient = &transition.recipient;
    if transition.auto_reply.is_some() {
        state.roster_wake_outbox(Some(handoff.remote_peer));
    }
    let forward = transition.effect == InboundRemotePresenceEffect::Forward;
    let followup = followup_presence(&transition);
    let routes = if forward || followup.is_some() {
        match state
            .capture_federated_presence(&recipient_bare, recipient)
            .await
        {
            Ok(routes) => Some(routes),
            Err(error) => {
                state.post_accept_failure_telemetry().record_failure();
                tracing::warn!(?error, %recipient_bare, %contact, "could not capture routes after federated subscription commit");
                None
            }
        }
    } else {
        None
    };

    // Subscription notifications precede the corresponding roster push
    // (RFC 6121 sections 3.2/3.3). Incoming subscribe requests are sent to
    // available resources; the other state notifications go only to
    // resources that requested the roster.
    if let Some(routes) = routes.as_deref().filter(|_| forward) {
        if let Err(error) = forward_committed_subscription(
            state,
            recipient,
            handoff,
            routes,
            transition.pending_created_at_micros,
        )
        .await
        {
            state.post_accept_failure_telemetry().record_failure();
            tracing::warn!(?error, %recipient_bare, %contact, %kind, "federated subscription forward failed after commit");
        }
    }

    // Follow-ups run on the owner nodes, which recheck the exact route and
    // outbound policy before admitting them to the federation outbox.
    match (followup, routes.as_deref()) {
        (Some(FollowupPresence::Current), Some(routes)) => {
            send_current_presence_to_remote(state, recipient, handoff, contact, routes).await;
        }
        (Some(FollowupPresence::Unavailable), Some(routes)) => {
            send_unavailable_presence_to_remote(state, recipient, handoff, contact, routes).await;
        }
        _ => {}
    }

    if let Some(change) = transition.change.as_ref() {
        if let Err(error) = state
            .deliver_committed_roster_change(
                recipient.id,
                &recipient.username,
                change,
                None,
                &northstar_roster_application::SystemRosterEvents,
            )
            .await
        {
            state.post_accept_failure_telemetry().record_failure();
            tracing::warn!(?error, recipient_id = %recipient.id, contact = %contact, %kind, "federated roster transition was committed but roster push failed");
        }
    }
    if kind == "subscribe" && forward && routes.as_ref().is_some_and(Vec::is_empty) {
        if let Err(error) = state.dispatch_push_notification(recipient.id).await {
            state.post_accept_failure_telemetry().record_failure();
            tracing::warn!(?error, recipient_id = %recipient.id, contact = %contact, "federated subscription was committed but push notification failed");
        }
    }
    Ok(ControlFlow::Continue(()))
}

pub(super) async fn forward_committed_subscription(
    state: &impl FederatedPresenceOwnerHost,
    recipient: &PresenceAccount,
    handoff: FederatedPresenceHandoff<'_>,
    routes: &[PresenceRoute],
    pending_created_at_micros: Option<i64>,
) -> Result<()> {
    let handoff = FederatedPresenceHandoff {
        effect: FederatedPresenceEffect::Forward {
            pending_created_at_micros,
        },
        ..handoff
    };
    state
        .handoff_federated_presence(recipient, handoff, routes)
        .await?;
    Ok(())
}

#[derive(Debug, Eq, PartialEq)]
enum FollowupPresence {
    Current,
    Unavailable,
}

fn followup_presence(transition: &InboundSubscriptionTransition) -> Option<FollowupPresence> {
    if transition.send_unavailable {
        Some(FollowupPresence::Unavailable)
    } else if transition.auto_reply == Some(SubscriptionReply::Subscribed) {
        Some(FollowupPresence::Current)
    } else {
        None
    }
}

#[cfg(test)]
mod tests;
