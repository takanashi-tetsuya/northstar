use super::super::availability::remove_directed_presence_for_bare;
use super::super::PresenceSession;
use super::initial::{probe_initial_contact, resend_pending_subscription};
use anyhow::Result;
use northstar_roster_application::blocking::RosterEntry;
use northstar_roster_core::PresenceAccount;
use northstar_xml_builder::rewrite::set_to;
use northstar_xmpp_types::jid_text::bare_jid;
use std::ops::ControlFlow;
use uuid::Uuid;

pub(super) async fn read_broadcast_roster<S: PresenceSession>(
    session: &S,
    owner: Uuid,
) -> Result<Vec<RosterEntry>> {
    session.blocking_service().roster(owner).await
}

pub(super) async fn broadcast_audience<S: PresenceSession>(
    session: &S,
    user: &PresenceAccount,
    roster: Vec<RosterEntry>,
    account: &str,
    from: &str,
    rewritten: &str,
    first_available: bool,
) -> Result<()> {
    let active_privacy = session.privacy_active_list();
    for (jid, _, subscription, ask) in roster {
        if session
            .presence_service()
            .outbound_denied(user.id, bare_jid(from), active_privacy.as_deref(), &jid)
            .await?
        {
            continue;
        }
        let contact_jid = northstar_xmpp_types::jid::CanonicalJid::parse_bare(&jid).ok();
        let local_contact = match contact_jid.as_ref().and_then(|jid| jid.localpart()) {
            Some(username)
                if contact_jid
                    .as_ref()
                    .is_some_and(|jid| jid.domainpart() == session.session_local_domain()) =>
            {
                session
                    .presence_service()
                    .find_enabled_user(username)
                    .await?
            }
            _ => None,
        };
        if let Some(contact) = local_contact.as_ref() {
            let contact_bare = format!("{}@{}", contact.username, session.session_local_domain());
            if session
                .presence_service()
                .is_blocked_for_account(contact.id, &contact_bare, from)
                .await?
            {
                continue;
            }
        }
        if let ControlFlow::Break(()) = resend_pending_subscription(
            session,
            user,
            account,
            &jid,
            contact_jid.as_ref(),
            local_contact.as_ref(),
            first_available,
            ask.as_deref(),
        )
        .await?
        {
            continue;
        }
        if matches!(subscription.as_str(), "from" | "both") {
            let delivery = set_to(rewritten, &jid);
            if let Ok(contact) = northstar_xmpp_types::jid::CanonicalJid::parse_bare(&jid) {
                if contact.domainpart() == session.session_local_domain() {
                    session
                        .presence_deliver_to_contact(&jid, from, &delivery)
                        .await?;
                } else if session.presence_route_allowed(contact.domainpart())
                    && session
                        .presence_send_federated(
                            contact.domainpart(),
                            delivery,
                            Some(from.to_owned()),
                        )
                        .await
                {
                    remove_directed_presence_for_bare(session, &jid);
                }
            }
        }
        probe_initial_contact(session, first_available, &subscription, &jid, account).await;
    }
    Ok(())
}
