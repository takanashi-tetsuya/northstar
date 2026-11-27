use super::super::availability::probe_contact_presence;
use super::super::subscriptions::should_resend_pending_outbound_subscription;
use super::super::PresenceSession;
use super::should_probe_contact_on_presence;
use anyhow::Result;
use northstar_roster_application::subscription_retry::{
    SubscriptionRetryAdmission, SubscriptionRetryRepository, SubscriptionRetryRequest,
    SubscriptionRetryTarget,
};
use northstar_roster_core::PresenceAccount;
use northstar_stream::local_routes::pending_subscription::PendingSubscriptionKey;
use northstar_xml_builder::XmlElement;
use northstar_xmpp_types::jid::CanonicalJid;
use std::ops::ControlFlow;

#[allow(clippy::too_many_arguments)]
pub(super) async fn resend_pending_subscription<S: PresenceSession>(
    session: &S,
    user: &PresenceAccount,
    account: &str,
    jid: &str,
    contact_jid: Option<&CanonicalJid>,
    local_contact: Option<&PresenceAccount>,
    first_available: bool,
    ask: Option<&str>,
) -> Result<ControlFlow<()>> {
    if !should_resend_pending_outbound_subscription(first_available, ask) {
        return Ok(ControlFlow::Continue(()));
    }
    let Some(contact) = contact_jid else {
        return Ok(ControlFlow::Continue(()));
    };
    let target = if contact.domainpart() == session.session_local_domain() {
        let Some(local_contact) = local_contact else {
            return Ok(ControlFlow::Break(()));
        };
        SubscriptionRetryTarget::Local(local_contact)
    } else if session.presence_route_allowed(contact.domainpart()) {
        SubscriptionRetryTarget::Federated {
            policy: session.roster_outbox_policy(),
        }
    } else {
        return Ok(ControlFlow::Continue(()));
    };
    let Some(actor) = session.roster_actor() else {
        return Ok(ControlFlow::Continue(()));
    };
    let request = SubscriptionRetryRequest {
        actor: &actor,
        contact: jid,
        expects_active: session.privacy_active_list().is_some(),
        target,
    };
    match admit_subscription_retry(session.presence_service(), request, account).await {
        Ok((SubscriptionRetryAdmission::Stale, _)) => {}
        Ok((SubscriptionRetryAdmission::Local { created_at_micros }, stanza)) => {
            if let SubscriptionRetryTarget::Local(recipient) = target {
                session
                    .presence_deliver_subscription(
                        user,
                        recipient,
                        account,
                        jid,
                        &stanza,
                        Some(PendingSubscriptionKey::local(user.id, created_at_micros)),
                    )
                    .await?;
            }
        }
        Ok((SubscriptionRetryAdmission::FederatedQueued, _)) => {
            session.wake_subscription_retry(contact.domainpart());
        }
        Err(error) if matches!(target, SubscriptionRetryTarget::Federated { .. }) => {
            tracing::warn!(
                domain = contact.domainpart(),
                ?error,
                "federation subscription retry was not persisted"
            );
        }
        Err(error) => return Err(error),
    }
    Ok(ControlFlow::Continue(()))
}

async fn admit_subscription_retry(
    repository: &impl SubscriptionRetryRepository,
    request: SubscriptionRetryRequest<'_>,
    account: &str,
) -> Result<(SubscriptionRetryAdmission, String)> {
    let Some(identity) = repository.pending_retry_identity(request).await? else {
        return Ok((SubscriptionRetryAdmission::Stale, String::new()));
    };
    let stanza = minimal_subscription_retry(account, request.contact);
    let admission = repository
        .retry_outbound_subscription(request, identity, &stanza)
        .await?;
    Ok((admission, stanza))
}

fn minimal_subscription_retry(account: &str, jid: &str) -> String {
    XmlElement::namespaced("presence", "jabber:client")
        .attr("from", account)
        .attr("to", jid)
        .attr("type", "subscribe")
        .finish()
}

pub(super) async fn probe_initial_contact<S: PresenceSession>(
    session: &S,
    first_available: bool,
    subscription: &str,
    jid: &str,
    account: &str,
) {
    if should_probe_contact_on_presence(first_available, subscription) {
        probe_contact_presence(session, jid, account).await;
    }
}

#[cfg(test)]
mod tests;
