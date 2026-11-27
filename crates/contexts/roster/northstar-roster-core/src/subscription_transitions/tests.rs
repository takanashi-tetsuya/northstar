use super::*;
use LocalPresenceEffect::{AutoApproved, Forward, Suppressed};
use PendingSubscriptionChange::{Delete, Insert, Keep};
use SubscriptionAction::{Subscribe, Subscribed, Unsubscribe, Unsubscribed};

const STATES: [&str; 6] = ["none", "to", "from", "both", "remove", "To"];
const GRANT_TO: [&str; 6] = ["to", "to", "both", "both", "none", "none"];
const GRANT_FROM: [&str; 6] = ["from", "both", "from", "both", "none", "none"];
const REVOKE_TO: [&str; 6] = ["none", "none", "from", "from", "none", "none"];
const REVOKE_FROM: [&str; 6] = ["none", "to", "none", "to", "none", "none"];
const ASKS: [Option<&str>; 3] = [None, Some("subscribe"), Some("other")];
const ACTIONS: [SubscriptionAction; 4] = [Subscribe, Subscribed, Unsubscribe, Unsubscribed];

#[test]
fn outbound_commands_match_every_storage_state() {
    for (index, subscription) in STATES.into_iter().enumerate() {
        let from = matches!(index, 2 | 3);
        for ask in ASKS {
            for approved in [false, true] {
                for pending in [false, true] {
                    let facts = SubscriptionFacts::from_row(subscription, ask, approved);
                    let expected = [
                        (
                            subscription,
                            if matches!(index, 0 | 2) {
                                Some("subscribe")
                            } else {
                                ask
                            },
                            approved,
                            Keep,
                            true,
                        ),
                        if pending {
                            (GRANT_FROM[index], ask, false, Delete, true)
                        } else {
                            (subscription, ask, approved || !from, Keep, false)
                        },
                        (REVOKE_TO[index], None, approved, Keep, true),
                        (REVOKE_FROM[index], ask, false, Delete, from || pending),
                    ];
                    for (action, (sub, ask, approved, pending_effect, forward)) in
                        ACTIONS.into_iter().zip(expected)
                    {
                        let actual = outbound_subscription_transition(facts, pending, action);
                        let next = SubscriptionFacts::from_row(sub, ask, approved);
                        assert_eq!(
                            actual,
                            RemoteSubscriptionDecision {
                                facts: next,
                                journal: next != facts,
                                pending: pending_effect,
                                forward,
                                auto_reply: None,
                                send_unavailable: false,
                            }
                        );
                    }
                }
            }
        }
    }
}

#[test]
fn inbound_commands_match_every_storage_state() {
    for (index, subscription) in STATES.into_iter().enumerate() {
        let from = matches!(index, 2 | 3);
        let to = matches!(index, 1 | 3);
        for ask in ASKS {
            for approved in [false, true] {
                for pending in [false, true] {
                    let facts = SubscriptionFacts::from_row(subscription, ask, approved);
                    let mut expected = [RemoteSubscriptionDecision::unchanged(facts); 4];
                    if approved || from {
                        expected[0].auto_reply = Some(SubscriptionReply::Subscribed);
                    } else if !pending {
                        expected[0].pending = Insert;
                        expected[0].forward = true;
                    }
                    if approved {
                        expected[0].facts =
                            SubscriptionFacts::from_row(GRANT_FROM[index], ask, false);
                        expected[0].pending = Delete;
                    }
                    if ask == Some("subscribe") && matches!(index, 0 | 2) {
                        expected[1].facts =
                            SubscriptionFacts::from_row(GRANT_TO[index], None, approved);
                        expected[1].forward = true;
                    }
                    expected[2].auto_reply = Some(SubscriptionReply::Unsubscribed);
                    if from || pending {
                        expected[2].facts =
                            SubscriptionFacts::from_row(REVOKE_FROM[index], ask, false);
                        expected[2].pending = Delete;
                        expected[2].forward = true;
                        expected[2].send_unavailable = from;
                    }
                    if to || ask == Some("subscribe") {
                        expected[3].facts =
                            SubscriptionFacts::from_row(REVOKE_TO[index], None, approved);
                        expected[3].forward = true;
                    }
                    for (action, mut decision) in ACTIONS.into_iter().zip(expected) {
                        decision.journal = decision.facts != facts;
                        assert_eq!(
                            inbound_subscription_transition(facts, pending, action),
                            decision
                        );
                    }
                }
            }
        }
    }
}

#[test]
fn local_commands_match_every_pair_of_storage_states() {
    for (actor_index, actor_sub) in STATES.into_iter().enumerate() {
        for (target_index, target_sub) in STATES.into_iter().enumerate() {
            for actor_ask in ASKS {
                for target_ask in ASKS {
                    for mask in 0..16 {
                        let actor_approved = mask & 1 != 0;
                        let target_approved = mask & 2 != 0;
                        let outbound = mask & 4 != 0;
                        let inbound = mask & 8 != 0;
                        let actor =
                            SubscriptionFacts::from_row(actor_sub, actor_ask, actor_approved);
                        let target =
                            SubscriptionFacts::from_row(target_sub, target_ask, target_approved);
                        let with_actor = SubscriptionFacts::from_row;
                        let with_target = SubscriptionFacts::from_row;
                        let from = matches!(actor_index, 2 | 3);
                        let to = matches!(actor_index, 1 | 3);
                        let expected = [
                            if target_approved {
                                (
                                    with_actor(GRANT_TO[actor_index], None, actor_approved),
                                    with_target(GRANT_FROM[target_index], target_ask, false),
                                    Delete,
                                    Keep,
                                    AutoApproved,
                                )
                            } else if to || outbound {
                                (actor, target, Keep, Keep, Suppressed)
                            } else {
                                (
                                    with_actor(actor_sub, Some("subscribe"), actor_approved),
                                    target,
                                    Insert,
                                    Keep,
                                    Forward,
                                )
                            },
                            if inbound {
                                (
                                    with_actor(GRANT_FROM[actor_index], actor_ask, false),
                                    with_target(GRANT_TO[target_index], None, target_approved),
                                    Keep,
                                    Delete,
                                    Forward,
                                )
                            } else {
                                (
                                    with_actor(actor_sub, actor_ask, actor_approved || !from),
                                    target,
                                    Keep,
                                    Keep,
                                    Suppressed,
                                )
                            },
                            (
                                with_actor(REVOKE_TO[actor_index], None, actor_approved),
                                with_target(REVOKE_FROM[target_index], target_ask, target_approved),
                                Delete,
                                Keep,
                                Forward,
                            ),
                            if inbound || from {
                                (
                                    with_actor(REVOKE_FROM[actor_index], actor_ask, false),
                                    with_target(REVOKE_TO[target_index], None, target_approved),
                                    Keep,
                                    Delete,
                                    Forward,
                                )
                            } else {
                                (
                                    with_actor(REVOKE_FROM[actor_index], actor_ask, false),
                                    target,
                                    Keep,
                                    Delete,
                                    Suppressed,
                                )
                            },
                        ];
                        for (
                            action,
                            (next_actor, next_target, pending_outbound, pending_inbound, effect),
                        ) in ACTIONS.into_iter().zip(expected)
                        {
                            assert_eq!(
                                local_subscription_transition(
                                    actor, target, outbound, inbound, action
                                ),
                                LocalSubscriptionDecision {
                                    actor: next_actor,
                                    target: next_target,
                                    journal_actor: next_actor != actor,
                                    journal_target: next_target != target,
                                    pending_outbound,
                                    pending_inbound,
                                    effect,
                                }
                            );
                        }
                    }
                }
            }
        }
    }
}

#[test]
fn legacy_storage_spelling_is_preserved_until_the_table_changes_it() {
    let legacy = SubscriptionFacts::from_row("To", Some("other"), false);
    let subscribed = outbound_subscription_transition(legacy, false, Subscribe);
    assert_eq!(subscribed.facts.subscription(), "To");
    assert_eq!(subscribed.facts.ask(), Some("other"));
    assert!(!subscribed.journal);
    let unsubscribed = outbound_subscription_transition(legacy, false, Unsubscribe);
    assert_eq!(unsubscribed.facts.subscription(), "none");
    assert_eq!(unsubscribed.facts.ask(), None);
    assert!(unsubscribed.journal);
}
