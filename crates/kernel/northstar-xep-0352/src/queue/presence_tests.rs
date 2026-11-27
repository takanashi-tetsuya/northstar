use super::{DeferredQueue, EnqueueResult, OverflowDecision};
use crate::policy::{CoalescingKey, CsiPolicyConfig, PresenceEpoch, PresenceScope};

fn key(scope: PresenceScope, epoch: Option<u64>) -> Option<CoalescingKey> {
    Some(CoalescingKey::ScopedPresence {
        from: "alice@example.test/phone".to_owned(),
        scope,
        source_epoch: epoch.map(PresenceEpoch::Local),
    })
}

#[test]
fn probe_reply_does_not_replace_status_presence() {
    let mut queue = DeferredQueue::new(CsiPolicyConfig::default());
    assert!(queue
        .enqueue("status", 6, key(PresenceScope::Status, Some(10)))
        .is_enqueued());
    assert!(queue
        .enqueue("probe", 5, key(PresenceScope::ProbeReply, None))
        .is_enqueued());
    assert!(queue
        .enqueue("directed", 8, key(PresenceScope::Directed, None))
        .is_enqueued());
    assert_eq!(queue.drain_all(), ["status", "probe", "directed"]);
}

#[test]
fn a_late_older_presence_cannot_replace_the_committed_broadcast() {
    let mut queue = DeferredQueue::new(CsiPolicyConfig::default());
    assert!(queue
        .enqueue("online", 6, key(PresenceScope::Status, Some(12)))
        .is_enqueued());
    assert_eq!(
        queue.enqueue("old unavailable", 15, key(PresenceScope::Status, Some(11))),
        EnqueueResult::Discarded {
            discarded_item: "old unavailable"
        },
    );
    assert!(queue
        .enqueue("unknown", 7, key(PresenceScope::Status, None))
        .is_discarded());
    assert_eq!(queue.total_bytes(), 6);
    assert_eq!(
        queue.enqueue("away", 4, key(PresenceScope::Status, Some(13))),
        EnqueueResult::Enqueued {
            replaced_previous: Some("online")
        },
    );
    assert_eq!(queue.drain_all(), ["away"]);
}

#[test]
fn remote_sequences_are_comparable_only_within_one_connection() {
    let mut queue = DeferredQueue::new(CsiPolicyConfig::default());
    let remote = |connection, sequence| {
        Some(CoalescingKey::ScopedPresence {
            from: "alice@example.test/phone".to_owned(),
            scope: PresenceScope::Status,
            source_epoch: Some(PresenceEpoch::Remote {
                connection,
                sequence,
            }),
        })
    };
    assert!(queue.enqueue("online", 6, remote(2, 2)).is_enqueued());
    assert!(queue.enqueue("stale", 5, remote(2, 1)).is_discarded());
    assert!(queue.enqueue("old route", 9, remote(1, 99)).is_discarded());
    assert!(queue.enqueue("away", 4, remote(2, 3)).is_enqueued());
    assert_eq!(queue.drain_all(), ["away"]);
}

#[test]
fn scoped_presence_overflow_returns_evicted_item() {
    let mut queue = DeferredQueue::new(CsiPolicyConfig {
        max_deferred_stanzas: 1,
        ..CsiPolicyConfig::default()
    });
    assert!(queue
        .enqueue("status", 6, key(PresenceScope::Status, None))
        .is_enqueued());
    assert_eq!(
        queue.enqueue("probe", 5, key(PresenceScope::ProbeReply, None)),
        EnqueueResult::Overflow {
            decision: OverflowDecision::EvictedOldest {
                evicted: vec!["status"],
                replaced_previous: None,
            }
        },
    );
    assert_eq!(queue.drain_all(), ["probe"]);
}
