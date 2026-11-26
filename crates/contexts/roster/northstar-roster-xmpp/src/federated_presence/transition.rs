use super::render::presence_probe_status_response;
use super::replay::{send_current_presence_to_remote, send_unavailable_presence_to_remote};
use crate::FederatedPresenceHost;
use anyhow::Result;
use northstar_federation_core::wire::s2s_stanza_error;
use northstar_federation_core::FederationRoute;
use northstar_roster_application::presence::{
    InboundRemotePresenceEffect, PresenceAccount, PresenceMutation,
};
use northstar_roster_application::privacy::PrivacyStanzaKind;
use northstar_xml_builder::rewrite::set_to;
use northstar_xmpp_types::jid::CanonicalJid;
use roxmltree::Node;
use std::ops::ControlFlow;
use std::sync::atomic::Ordering;

pub(super) async fn transition_inbound_subscription<H: FederatedPresenceHost>(
    state: &H,
    root: Node<'_, '_>,
    from: &str,
    kind: &str,
    recipient: &PresenceAccount,
    subscription_from: Option<&str>,
    canonical_subscription: Option<&str>,
) -> Result<ControlFlow<Option<String>>> {
    let contact = subscription_from.expect("guarded above");
    let persisted = canonical_subscription.expect("guarded above");
    let transition = match state
        .presence_service()
        .transition_inbound(recipient.id, state.local_domain(), contact, kind, persisted)
        .await?
    {
        PresenceMutation::Transition(transition) => transition,
        PresenceMutation::PolicyDenied(_)
        | PresenceMutation::Missing
        | PresenceMutation::Unauthorized => {
            // The exact local UUID disappeared/was disabled, or its
            // account-wide inbound policy denied the authenticated remote
            // stanza. Inbound federation intentionally has no C2S
            // generation authority of its own.
            return Ok(ControlFlow::Break(None));
        }
    };
    let recipient = transition.recipient.clone();
    let recipient_bare = format!("{}@{}", recipient.username, state.local_domain());

    // Subscription notifications precede the corresponding roster push
    // (RFC 6121 sections 3.2/3.3). Incoming subscribe requests are sent to
    // available resources; the other state notifications go only to
    // resources that requested the roster.
    if transition.effect == InboundRemotePresenceEffect::Forward {
        let mut targets = state.session_entries_for(&recipient_bare);
        if kind == "subscribe" {
            targets.retain(|(_, target)| {
                target.user_id == recipient.id
                    && target.auth_generation == recipient.auth_generation
                    && target.available.load(Ordering::Acquire)
            });
        } else {
            targets.retain(|(_, target)| {
                target.user_id == recipient.id
                    && target.auth_generation == recipient.auth_generation
                    && target.available.load(Ordering::Acquire)
                    && target.roster_requested.load(Ordering::Acquire)
            });
        }
        for (target_jid, target) in targets {
            if state
                .privacy_allows_session(&target, from, PrivacyStanzaKind::PresenceIn)
                .await?
            {
                let _ = target.sender.try_send(set_to(persisted, &target_jid));
            }
        }
    }

    if let Some(reply_kind) = transition.auto_reply {
        let response = presence_probe_status_response(
            &recipient_bare,
            contact,
            reply_kind,
            root.attribute("id"),
        );
        let remote_domain = CanonicalJid::parse(contact)
            .expect("canonical federated contact")
            .domainpart()
            .to_owned();
        if !state
            .federation_outbox()
            .send(&remote_domain, response, None)
            .await
        {
            return Ok(ControlFlow::Break(Some(s2s_stanza_error(
                root,
                "wait",
                "resource-constraint",
            ))));
        }
        if reply_kind == "subscribed" {
            send_current_presence_to_remote(state, &recipient_bare, contact).await;
        }
    }

    if transition.send_unavailable {
        send_unavailable_presence_to_remote(state, &recipient_bare, contact).await;
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
