use super::super::availability::remove_directed_presence_for_bare;
use super::super::PresenceSession;
use super::initial::{probe_initial_contact, resend_pending_subscription};
use crate::exact_presence::{ExactPresenceHost, PresenceEffect};
use anyhow::Result;
use northstar_roster_application::probe_decision::{
    BroadcastCandidate, BroadcastFacts, BroadcastQuery, PresenceRoute,
};
use northstar_roster_core::RosterActor;
use northstar_xml_builder::rewrite::set_to;
use northstar_xmpp_types::jid::CanonicalJid;
use std::ops::ControlFlow;

pub(super) async fn read_broadcast_roster<S: PresenceSession>(
    session: &S,
    actor: &RosterActor,
) -> Result<Vec<BroadcastFacts>> {
    let host = session.exact_presence_host();
    let mut candidates = Vec::new();
    for (jid, _, _, _) in session.blocking_service().roster(actor.account_id).await? {
        let peer = CanonicalJid::parse_bare(&jid)?;
        let account = match peer.localpart() {
            Some(name) if peer.domainpart() == session.session_local_domain() => {
                session.presence_service().find_enabled_user(name).await?
            }
            _ => None,
        };
        let routes = match &account {
            Some(account) => host.capture_presence_routes(&jid, account, true).await?,
            None => Vec::new(),
        };
        candidates.push(BroadcastCandidate {
            jid,
            account,
            routes,
        });
    }
    session
        .presence_service()
        .read_broadcast_facts(BroadcastQuery {
            actor,
            expects_active: session.privacy_active_list().is_some(),
            local_domain: session.session_local_domain(),
            candidates: &candidates,
        })
        .await
}

pub(super) async fn broadcast_audience<S: PresenceSession>(
    session: &S,
    actor: &RosterActor,
    roster: Vec<BroadcastFacts>,
    rewritten: &str,
    first_available: bool,
    replay_recipients: &[PresenceRoute],
    effect: PresenceEffect,
) -> Result<()> {
    let user = &session.session_account().expect("authenticated session");
    let account = actor.bare_jid();
    let host = session.exact_presence_host();
    for BroadcastFacts {
        jid,
        subscription,
        ask,
        account: local_contact,
        recipients,
    } in roster
    {
        let contact = CanonicalJid::parse_bare(&jid)?;
        if let ControlFlow::Break(()) = resend_pending_subscription(
            session,
            user,
            account,
            &jid,
            Some(&contact),
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
            if local_contact.is_some() {
                for route in recipients {
                    if let Err(error) = host
                        .send_presence_route(actor, &route, &delivery, effect, true)
                        .await
                    {
                        tracing::warn!(?error, target = %route.exact.full_jid, "broadcast presence delivery failed");
                    }
                }
            } else if session.presence_route_allowed(contact.domainpart())
                && session
                    .presence_send_federated(
                        contact.domainpart(),
                        delivery,
                        Some(actor.full_jid.clone()),
                    )
                    .await
            {
                remove_directed_presence_for_bare(session, &jid);
            }
        }
        if let Some(owner) = local_contact {
            if super::should_probe_contact_on_presence(first_available, &subscription) {
                if let Err(error) = host
                    .replay_presence_to_routes(&owner, &jid, account, replay_recipients)
                    .await
                {
                    tracing::warn!(?error, owner = %jid, "initial presence replay failed");
                }
            }
        } else {
            probe_initial_contact(session, first_available, &subscription, &jid, account).await;
        }
    }
    Ok(())
}
