use super::current::cluster_authority;
use crate::PresenceDeliveryHost;
use anyhow::Result;
use northstar_roster_application::privacy::PrivacyStanzaKind;
use northstar_roster_core::PresenceAccount;
use northstar_stream::local_routes::pending_subscription::{
    deliver_pending_subscription, PendingSubscriptionKey,
};
use northstar_xml_builder::rewrite::set_to;
use std::sync::atomic::Ordering;

/// The node side of `RosterSessionHost::deliver_subscription_presence`.
pub async fn deliver_subscription_presence<H: PresenceDeliveryHost>(
    host: &H,
    owner: &PresenceAccount,
    recipient: &PresenceAccount,
    owner_bare: &str,
    recipient_bare: &str,
    stanza: &str,
    pending: Option<PendingSubscriptionKey>,
) -> Result<()> {
    let mut targets = host.session_entries_for(recipient_bare);
    // RFC 6121 subscription-related presence is delivered to
    // available resources independently of roster interest.
    // `roster_requested` gates roster pushes only; using it here
    // can drop the approval on the exact resource that just sent
    // the subscription request after reconnecting.
    targets.retain(|(_, session)| {
        session.user_id == recipient.id
            && session.auth_generation == recipient.auth_generation
            && session.available.load(Ordering::Acquire)
    });
    for (target_full, session) in targets {
        let epoch = session.availability_generation.load(Ordering::Acquire);
        if host
            .privacy_allows_session(&session, owner_bare, PrivacyStanzaKind::PresenceIn)
            .await?
        {
            let delivery = set_to(stanza, &target_full);
            if let Some(key) = &pending {
                deliver_pending_subscription(&session, epoch, key.clone(), || {
                    host.send_presence_if_owner_current(
                        &target_full,
                        &session,
                        recipient.id,
                        recipient.auth_generation,
                        &session.sender,
                        &delivery,
                    )
                });
            } else {
                let _ = session.sender.try_send(delivery);
            }
        }
    }
    host.route_presence_subscription_remote(
        recipient_bare,
        stanza,
        cluster_authority(owner, recipient),
    )
    .await;
    Ok(())
}

/// The node side of `RosterSessionHost::deliver_subscription_approval`.
pub async fn deliver_subscription_approval<H: PresenceDeliveryHost>(
    host: &H,
    owner: &PresenceAccount,
    recipient: &PresenceAccount,
    owner_bare: &str,
    recipient_bare: &str,
    approved: &str,
    skip_full: Option<&str>,
) -> Result<()> {
    let current = skip_full;
    for (jid, session) in
        host.session_entries_for(recipient_bare)
            .into_iter()
            .filter(|(_, session)| {
                session.user_id == recipient.id
                    && session.auth_generation == recipient.auth_generation
                    && session.available.load(Ordering::Acquire)
            })
    {
        if current != Some(jid.as_str())
            && host
                .privacy_allows_session(&session, owner_bare, PrivacyStanzaKind::PresenceIn)
                .await?
        {
            let _ = session.sender.try_send(approved.to_owned());
        }
    }
    host.route_presence_subscription_remote(
        recipient_bare,
        approved,
        cluster_authority(owner, recipient),
    )
    .await;
    Ok(())
}

/// The node side of `RosterSessionHost::deliver_contact_presence`.
pub async fn deliver_contact_presence<H: PresenceDeliveryHost>(
    host: &H,
    contact: &str,
    from: &str,
    stanza: &str,
) -> Result<()> {
    for (_, target) in host
        .session_entries_for(contact)
        .into_iter()
        .filter(|(_, target)| target.available.load(Ordering::Relaxed))
    {
        if host
            .privacy_allows_session(&target, from, PrivacyStanzaKind::PresenceIn)
            .await?
        {
            let _ = target.sender.try_send(stanza.to_owned());
        }
    }
    host.broadcast_available_presence_remote(contact, stanza)
        .await;
    Ok(())
}

/// The node side of `RosterSessionHost::echo_account_presence`.
pub async fn echo_account_presence<H: PresenceDeliveryHost>(
    host: &H,
    account: &str,
    from: &str,
    stanza: &str,
) {
    for (jid, target) in host.session_entries_for(account) {
        if target.available.load(Ordering::Relaxed) || jid == from {
            let _ = target.sender.try_send(set_to(stanza, &jid));
        }
    }
    let account_delivery = set_to(stanza, account);
    host.broadcast_available_presence_remote(account, &account_delivery)
        .await;
}
