use crate::FederatedPresenceHost;
use northstar_federation_core::FederationRoute;
use northstar_roster_application::privacy::PrivacyStanzaKind;
use northstar_xml_builder::rewrite::set_to;
use northstar_xml_builder::XmlElement;
use northstar_xmpp_types::jid::CanonicalJid;
use std::sync::atomic::Ordering;

pub(super) async fn send_unavailable_presence_to_remote<H: FederatedPresenceHost>(
    state: &H,
    owner: &str,
    contact: &str,
) {
    let remote_domain = CanonicalJid::parse(contact)
        .expect("canonical federated contact")
        .domainpart()
        .to_owned();
    let mut resources = state.session_entries_for(owner);
    resources.retain(|(_, session)| session.available.load(Ordering::Acquire));
    for (full_jid, session) in resources {
        match state
            .privacy_allows_session(&session, contact, PrivacyStanzaKind::PresenceOut)
            .await
        {
            Ok(true) => {}
            Ok(false) => continue,
            Err(error) => {
                tracing::warn!(?error, %full_jid, %contact, "privacy policy lookup failed for outbound unavailable presence");
                continue;
            }
        }
        let stanza = XmlElement::new("presence")
            .attr("xmlns", "jabber:client")
            .attr("from", &full_jid)
            .attr("to", contact)
            .attr("type", "unavailable")
            .finish();
        if !state
            .federation_outbox()
            .send(&remote_domain, stanza, None)
            .await
        {
            state.post_accept_failure_telemetry().record_failure();
            tracing::warn!(owner = %owner, contact = %contact, "failed to admit required federated unavailable presence after subscription removal");
        }
    }
}

pub(super) async fn send_current_presence_to_remote<H: FederatedPresenceHost>(
    state: &H,
    owner: &str,
    contact: &str,
) {
    let remote_domain = CanonicalJid::parse(contact)
        .expect("canonical federated contact")
        .domainpart()
        .to_owned();
    let mut resources = state.session_entries_for(owner);
    resources.retain(|(_, session)| session.available.load(Ordering::Acquire));
    for (full_jid, session) in resources {
        match state
            .privacy_allows_session(&session, contact, PrivacyStanzaKind::PresenceOut)
            .await
        {
            Ok(true) => {}
            Ok(false) => continue,
            Err(error) => {
                tracing::warn!(?error, %full_jid, %contact, "privacy policy lookup failed for outbound current presence");
                continue;
            }
        }
        let stanza = session
            .last_presence
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
            .map(|presence| set_to(&presence, contact))
            .unwrap_or_else(|| {
                XmlElement::new("presence")
                    .attr("xmlns", "jabber:client")
                    .attr("from", &full_jid)
                    .attr("to", contact)
                    .finish()
            });
        if !state
            .federation_outbox()
            .send(&remote_domain, stanza, None)
            .await
        {
            state.post_accept_failure_telemetry().record_failure();
            tracing::warn!(owner = %owner, contact = %contact, "failed to admit current presence after federated subscription approval");
        }
    }
}
