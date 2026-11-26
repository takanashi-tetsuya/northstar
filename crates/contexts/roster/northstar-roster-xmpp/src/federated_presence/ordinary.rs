use crate::FederatedPresenceHost;
use anyhow::Result;
use northstar_roster_application::privacy::PrivacyStanzaKind;
use northstar_xmpp_types::jid::CanonicalJid;
use std::sync::atomic::Ordering;

pub(super) async fn dispatch_ordinary_presence<H: FederatedPresenceHost>(
    state: &H,
    raw: &str,
    from: &str,
    to: &str,
    canonical_subscription: Option<String>,
    recipient_bare: &str,
) -> Result<Option<String>> {
    let (delivery_target, delivery) = canonical_subscription
        .map_or_else(|| (to, raw.to_owned()), |stanza| (recipient_bare, stanza));
    let mut targets = state.session_entries_for(delivery_target);
    if CanonicalJid::parse(delivery_target).is_ok_and(|jid| jid.resourcepart().is_none()) {
        targets.retain(|(_, target)| target.available.load(Ordering::Relaxed));
    }
    for (_, target) in targets {
        if state
            .privacy_allows_session(&target, from, PrivacyStanzaKind::PresenceIn)
            .await?
        {
            let _ = target.sender.try_send(delivery.clone());
        }
    }
    Ok(None)
}
