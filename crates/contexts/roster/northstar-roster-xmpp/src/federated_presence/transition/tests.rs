use super::*;
use northstar_roster_core::{inbound_subscription_transition, SubscriptionFacts};

#[test]
fn revoke_followup_uses_old_grant_and_is_not_replayed_on_duplicate() {
    let initial = SubscriptionFacts::from_row("from", None, false);
    let revoked = inbound_subscription_transition(initial, false, SubscriptionAction::Unsubscribe);
    let duplicate =
        inbound_subscription_transition(revoked.facts, false, SubscriptionAction::Unsubscribe);

    for (decision, expected) in [
        (revoked, Some(FollowupPresence::Unavailable)),
        (duplicate, None),
    ] {
        assert_eq!(decision.auto_reply, Some(SubscriptionReply::Unsubscribed));
        let transition = InboundSubscriptionTransition {
            recipient: PresenceAccount {
                id: uuid::Uuid::nil(),
                username: "owner".to_owned(),
                auth_generation: 1,
            },
            effect: InboundRemotePresenceEffect::Suppressed,
            subscription: decision.facts.subscription().to_owned(),
            change: None,
            auto_reply: decision.auto_reply,
            send_unavailable: decision.send_unavailable,
            pending_created_at_micros: None,
        };
        assert_eq!(followup_presence(&transition), expected);
    }
}
