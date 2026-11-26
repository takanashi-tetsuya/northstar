use super::BlockingSession;
use northstar_roster_core::PresenceAccount;
use northstar_xep_0191::{BlockPattern, PresencePeer, Subscription};

pub(super) async fn notify_blocking_presence<S: BlockingSession>(
    session: &S,
    user: &PresenceAccount,
    roster: &[(String, Option<String>, String, Option<String>)],
    changed_patterns: &[String],
    available: bool,
) {
    let targets = blocking_presence_targets(roster, changed_patterns);
    let owner = format!("{}@{}", user.username, session.session_local_domain());
    session
        .blocking_presence_change(&owner, &targets, changed_patterns, available)
        .await;
}

fn blocking_presence_targets(
    roster: &[(String, Option<String>, String, Option<String>)],
    patterns: &[String],
) -> Vec<String> {
    let patterns = patterns
        .iter()
        .filter_map(|pattern| northstar_xmpp_types::jid::CanonicalJid::parse(pattern).ok())
        .map(BlockPattern::new)
        .collect::<Vec<_>>();
    let roster = roster
        .iter()
        .filter_map(|(jid, _, subscription, _)| {
            let jid = northstar_xmpp_types::jid::CanonicalJid::parse(jid).ok()?;
            let subscription = match subscription.as_str() {
                "to" => Subscription::To,
                "from" => Subscription::From,
                "both" => Subscription::Both,
                _ => Subscription::None,
            };
            Some(PresencePeer { jid, subscription })
        })
        .collect::<Vec<_>>();
    northstar_xep_0191::presence_targets(&patterns, &roster, &[])
        .into_iter()
        .map(|jid| jid.to_string())
        .collect()
}
