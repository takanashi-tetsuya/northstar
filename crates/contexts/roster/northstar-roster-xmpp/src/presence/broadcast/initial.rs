use super::super::availability::probe_contact_presence;
use super::super::subscriptions::should_resend_pending_outbound_subscription;
use super::super::PresenceSession;
use super::should_probe_contact_on_presence;
use anyhow::Result;
use northstar_roster_core::PresenceAccount;
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
    if should_resend_pending_outbound_subscription(first_available, ask) {
        // RFC 6121 section 3.1.2 recommends re-sending every
        // outstanding outbound subscription request when a
        // resource sends initial presence. Roster state remains
        // unchanged: this is delivery recovery, not a second
        // subscription transition. Blocking/privacy checks above
        // remain authoritative for both local and federated
        // destinations.
        let request = XmlElement::namespaced("presence", "jabber:client")
            .attr("from", account)
            .attr("to", jid)
            .attr("type", "subscribe")
            .finish();
        if let Some(contact) = contact_jid {
            if contact.domainpart() == session.session_local_domain() {
                let Some(local_contact) = local_contact else {
                    return Ok(ControlFlow::Break(()));
                };
                session
                    .presence_deliver_subscription(user, local_contact, account, jid, &request)
                    .await?;
            } else if session.presence_route_allowed(contact.domainpart()) {
                let _ = session
                    .presence_send_federated(
                        contact.domainpart(),
                        request,
                        Some(account.to_owned()),
                    )
                    .await;
            }
        }
    }
    Ok(ControlFlow::Continue(()))
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
