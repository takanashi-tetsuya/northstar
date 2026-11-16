//! Local resource selection for push-service notifications.

use super::session::OnlineSession;
use std::sync::atomic::Ordering;

pub async fn deliver_to_best_local_resource(
    mut local_targets: Vec<(String, OnlineSession)>,
    notification: &str,
) -> bool {
    let mut delivered = false;
    // Select the highest-priority available local resource, with its
    // full JID as a stable tie-breaker.
    local_targets.retain(|(_, session)| {
        session.available.load(Ordering::Relaxed) && session.priority.load(Ordering::Relaxed) >= 0
    });
    local_targets.sort_by(|(left_jid, left), (right_jid, right)| {
        right
            .priority
            .load(Ordering::Relaxed)
            .cmp(&left.priority.load(Ordering::Relaxed))
            .then_with(|| left_jid.cmp(right_jid))
    });
    let local_deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(5);
    for (_, target) in local_targets {
        if tokio::time::timeout_at(local_deadline, target.sender.send(notification.to_owned()))
            .await
            .is_ok_and(|result| result.is_ok())
        {
            delivered = true;
            break;
        }
    }
    delivered
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capacity_maintenance::tests::session;
    use crate::outbound::{OutboundItem, OutboundSender};
    use std::time::Duration;
    use tokio::sync::mpsc;
    use uuid::Uuid;

    fn target(
        jid: &str,
        available: bool,
        priority: i16,
    ) -> ((String, OnlineSession), mpsc::Receiver<OutboundItem>) {
        let mut session = session(Uuid::new_v4(), true);
        let (sender, receiver) = mpsc::channel(1);
        session.sender = OutboundSender::new(sender);
        session.available.store(available, Ordering::Relaxed);
        session.priority.store(priority, Ordering::Relaxed);
        ((jid.to_owned(), session), receiver)
    }

    #[tokio::test]
    async fn highest_priority_first() {
        let (low, mut low_rx) = target("push@example.test/a", true, 1);
        let (high, mut high_rx) = target("push@example.test/z", true, 10);

        assert!(deliver_to_best_local_resource(vec![low, high], "notification").await);
        assert_eq!(high_rx.try_recv().unwrap().stanza, "notification");
        assert!(low_rx.try_recv().is_err());
    }

    #[tokio::test]
    async fn equal_priority_ordered_by_full_jid() {
        let (last, mut last_rx) = target("push@example.test/z", true, 5);
        let (first, mut first_rx) = target("push@example.test/a", true, 5);

        assert!(deliver_to_best_local_resource(vec![last, first], "notification").await);
        assert_eq!(first_rx.try_recv().unwrap().stanza, "notification");
        assert!(last_rx.try_recv().is_err());
    }

    #[tokio::test]
    async fn unavailable_and_negative_priority_sessions_skipped() {
        let (unavailable, mut unavailable_rx) = target("push@example.test/a", false, 100);
        let (negative, mut negative_rx) = target("push@example.test/b", true, -1);
        let (available, mut available_rx) = target("push@example.test/c", true, 0);

        assert!(
            deliver_to_best_local_resource(vec![unavailable, negative, available], "notification",)
                .await
        );
        assert_eq!(available_rx.try_recv().unwrap().stanza, "notification");
        assert!(unavailable_rx.try_recv().is_err());
        assert!(negative_rx.try_recv().is_err());
    }

    #[tokio::test]
    async fn no_eligible_target_returns_false() {
        let (unavailable, mut unavailable_rx) = target("push@example.test/a", false, 100);
        let (negative, mut negative_rx) = target("push@example.test/b", true, -1);

        assert!(!deliver_to_best_local_resource(vec![unavailable, negative], "notification").await);
        assert!(!deliver_to_best_local_resource(Vec::new(), "notification").await);
        assert!(unavailable_rx.try_recv().is_err());
        assert!(negative_rx.try_recv().is_err());
    }

    #[tokio::test]
    async fn first_successful_send_stops() {
        let (first, mut first_rx) = target("push@example.test/a", true, 0);
        let (second, mut second_rx) = target("push@example.test/b", true, 0);
        let (third, mut third_rx) = target("push@example.test/c", true, 0);

        assert!(deliver_to_best_local_resource(vec![first, second, third], "notification").await);
        assert_eq!(first_rx.try_recv().unwrap().stanza, "notification");
        assert!(second_rx.try_recv().is_err());
        assert!(third_rx.try_recv().is_err());
    }

    #[tokio::test]
    async fn closed_receiver_falls_through_to_next_target() {
        let (closed, closed_rx) = target("push@example.test/a", true, 10);
        let (next, mut next_rx) = target("push@example.test/b", true, 0);
        drop(closed_rx);

        assert!(deliver_to_best_local_resource(vec![closed, next], "notification").await);
        assert_eq!(next_rx.try_recv().unwrap().stanza, "notification");
    }

    #[tokio::test(start_paused = true)]
    async fn blocked_targets_share_one_five_second_deadline() {
        let (first, mut first_rx) = target("push@example.test/a", true, 10);
        let (second, mut second_rx) = target("push@example.test/b", true, 0);
        first.1.sender.try_send("older-first".to_owned()).unwrap();
        second.1.sender.try_send("older-second".to_owned()).unwrap();
        let started = tokio::time::Instant::now();

        assert!(!deliver_to_best_local_resource(vec![first, second], "notification").await);
        assert!(started.elapsed() >= Duration::from_secs(5));
        assert!(started.elapsed() < Duration::from_secs(6));
        assert_eq!(first_rx.try_recv().unwrap().stanza, "older-first");
        assert_eq!(second_rx.try_recv().unwrap().stanza, "older-second");
        assert!(first_rx.try_recv().is_err());
        assert!(second_rx.try_recv().is_err());
    }
}
