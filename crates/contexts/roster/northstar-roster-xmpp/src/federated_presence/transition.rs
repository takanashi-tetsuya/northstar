use super::render::subscription_reply;
use super::replay::{send_current_presence_to_remote, send_unavailable_presence_to_remote};
use super::SubscriptionRevocationRoute;
use crate::FederatedPresenceHost;
use anyhow::Result;
use northstar_federation_core::wire::s2s_stanza_error;
use northstar_federation_core::FederationRoute;
use northstar_roster_application::presence::{
    InboundRemotePresenceEffect, InboundSubscriptionRequest, InboundSubscriptionTransition,
    PresenceAccount, PresenceMutation, SubscriptionOutboxAdmissionError,
};
use northstar_roster_application::privacy::PrivacyStanzaKind;
use northstar_roster_application::{
    CommunicationPolicyQuery, CommunicationPolicyReader, PolicyDirection, PolicySubject,
};
use northstar_roster_core::{SubscriptionAction, SubscriptionReply};
use northstar_xml_builder::rewrite::set_to;
use roxmltree::Node;
use std::ops::ControlFlow;
use std::sync::atomic::Ordering;

#[allow(clippy::too_many_arguments)]
pub(super) async fn transition_inbound_subscription<
    H: FederatedPresenceHost + SubscriptionRevocationRoute,
>(
    state: &H,
    root: Node<'_, '_>,
    from: &str,
    kind: &str,
    recipient: &PresenceAccount,
    subscription_from: Option<&str>,
    canonical_subscription: Option<&str>,
    verified_peer: &str,
) -> Result<ControlFlow<Option<String>>> {
    let contact = subscription_from.expect("guarded above");
    let persisted = canonical_subscription.expect("guarded above");
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
            stanza: persisted,
            verified_peer,
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
        state.roster_wake_outbox(Some(verified_peer));
    }

    // Subscription notifications precede the corresponding roster push
    // (RFC 6121 sections 3.2/3.3).
    if transition.effect == InboundRemotePresenceEffect::Forward {
        let mut targets = state.session_entries_for(&recipient_bare);
        targets.retain(|(_, target)| {
            target.user_id == recipient.id
                && target.auth_generation == recipient.auth_generation
                && target.available.load(Ordering::Acquire)
        });
        for (target_jid, target) in targets {
            let query = CommunicationPolicyQuery {
                account_id: target.user_id,
                expected_auth_generation: Some(target.auth_generation),
                subject: PolicySubject::Connection {
                    connection_id: target.connection_id,
                    expects_active: target.privacy_active_snapshot().is_some(),
                },
                peer: from.to_owned(),
                kind: PrivacyStanzaKind::PresenceIn,
                direction: PolicyDirection::Inbound,
                check_owner_block: true,
                check_peer_block: false,
            };
            match state
                .presence_service()
                .communication_policy()
                .read_communication_policy(&query)
                .await
            {
                Ok(decision) if decision.allows() => {
                    if let Some(current) =
                        state.sessions_for(&target_jid).into_iter().find(|current| {
                            current.connection_id == target.connection_id
                                && current.user_id == target.user_id
                                && current.auth_generation == target.auth_generation
                                && current.available.load(Ordering::Acquire)
                        })
                    {
                        let _ = current.sender.try_send(set_to(persisted, &target_jid));
                    }
                }
                Ok(_) => {}
                Err(error) => {
                    state.post_accept_failure_telemetry().record_failure();
                    tracing::warn!(?error, %target_jid, %contact, "federated subscription delivery policy unavailable");
                }
            }
        }
    }

    match followup_presence(&transition) {
        Some(FollowupPresence::Current) => {
            send_current_presence_to_remote(state, &recipient_bare, contact).await;
        }
        Some(FollowupPresence::Unavailable) => {
            send_unavailable_presence_to_remote(
                state,
                recipient,
                &recipient_bare,
                contact,
                verified_peer,
            )
            .await;
        }
        None => {}
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
    if kind == "subscribe"
        && transition.effect == InboundRemotePresenceEffect::Forward
        && state.sessions_for(&recipient_bare).is_empty()
    {
        if let Err(error) = state.dispatch_push_notification(recipient.id).await {
            state.post_accept_failure_telemetry().record_failure();
            tracing::warn!(?error, recipient_id = %recipient.id, contact = %contact, "federated subscription was committed but push notification failed");
        }
    }
    Ok(ControlFlow::Continue(()))
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
