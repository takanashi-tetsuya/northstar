use crate::PresenceDeliveryHost;
use anyhow::Result;
use northstar_roster_application::privacy::PrivacyStanzaKind;
use std::sync::atomic::Ordering;

/// The node side of `RosterSessionHost::deliver_directed_presence`.
pub async fn deliver_directed_presence<H: PresenceDeliveryHost>(
    host: &H,
    to: &str,
    canonical_to: &str,
    from: &str,
    stanza: &str,
    bare_target: bool,
) -> Result<bool> {
    let mut targets = host.session_entries_for(to);
    if bare_target {
        targets.retain(|(_, target)| target.available.load(Ordering::Relaxed));
    }
    let mut delivered = false;
    for (_, target) in targets {
        if host
            .privacy_allows_session(&target, from, PrivacyStanzaKind::PresenceIn)
            .await?
            && target.sender.try_send(stanza.to_owned()).is_ok()
        {
            delivered = true;
        }
    }
    delivered |= host
        .route_directed_presence_remote(canonical_to, stanza, bare_target)
        .await;
    Ok(delivered)
}

/// The node side of `RosterSessionHost::deliver_directed_unavailable`.
pub async fn deliver_directed_unavailable<H: PresenceDeliveryHost>(
    host: &H,
    target: &str,
    bare_target: bool,
    from: &str,
    stanza: &str,
) {
    let mut recipients = host.session_entries_for(target);
    if bare_target {
        recipients.retain(|(_, session)| session.available.load(Ordering::Relaxed));
    }
    for (_, recipient) in recipients {
        if host
            .privacy_allows_session(&recipient, from, PrivacyStanzaKind::PresenceIn)
            .await
            .unwrap_or(false)
        {
            let _ = recipient.sender.try_send(stanza.to_owned());
        }
    }
}

/// The node side of `RosterSessionHost::directed_presence_recipient`.
pub fn directed_presence_recipient<H: PresenceDeliveryHost>(
    host: &H,
    owner_full: &str,
    requester: &str,
) -> bool {
    host.session_entries_for(owner_full)
        .into_iter()
        .any(|(_, owner)| {
            owner.directed_presence.iter().any(|target| {
                northstar_presence_core::directed_recipient_matches(target.key(), requester)
            })
        })
}
