use super::*;
use std::sync::atomic::{AtomicUsize, Ordering};

impl PushHandoffAuthority for FakePushRepository {
    async fn validate_handoff(&self, _: Uuid, _: &PushDelivery) -> anyhow::Result<bool> {
        unreachable!()
    }
}

struct AllowedChecks(AtomicUsize);

impl PushHandoffAuthority for AllowedChecks {
    async fn validate_handoff(
        &self,
        user_id: Uuid,
        delivery: &PushDelivery,
    ) -> anyhow::Result<bool> {
        assert_eq!(user_id, Uuid::from_u128(545));
        assert_eq!(delivery.request_id, Uuid::from_u128(523));
        Ok(self
            .0
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |left| {
                left.checked_sub(1)
            })
            .is_ok())
    }
}

pub(super) async fn route_push_notification(
    routes: &FakeRoutes,
    delivery: &PushDelivery,
    counts: PushNotificationCounts,
) -> anyhow::Result<bool> {
    let outcome = super::super::route_push_notification(
        routes,
        &AllowedChecks(AtomicUsize::new(2)),
        Uuid::from_u128(545),
        delivery,
        counts,
    )
    .await?;
    assert_ne!(outcome, PushHandoffOutcome::StaleClaim);
    Ok(outcome == PushHandoffOutcome::QueueAccepted)
}

#[tokio::test]
async fn stale_claim_stops_before_any_queue_or_cluster_fallback() {
    for checks in [0, 1] {
        let routes = FakeRoutes {
            cluster_delivered: true,
            ..FakeRoutes::default()
        };
        let outcome = super::super::route_push_notification(
            &routes,
            &AllowedChecks(AtomicUsize::new(checks)),
            Uuid::from_u128(545),
            &delivery("push@example.test"),
            counts(),
        )
        .await
        .unwrap();
        assert_eq!(outcome, PushHandoffOutcome::StaleClaim);
        let calls = routes.calls.lock().unwrap();
        assert_eq!(calls.len(), checks);
        assert!(calls.iter().all(|call| matches!(call, Call::Local(..))));
    }
}

#[tokio::test]
async fn accepted_iq_uses_both_counts_from_the_claim_including_zero() {
    let routes = FakeRoutes {
        local_delivered: true,
        ..FakeRoutes::default()
    };
    let claimed_counts = PushNotificationCounts {
        message_count: 0,
        pending_subscription_count: 47,
    };
    let authority = AllowedChecks(AtomicUsize::new(1));
    assert_eq!(
        super::super::route_push_notification(
            &routes,
            &authority,
            Uuid::from_u128(545),
            &delivery("push@example.test"),
            claimed_counts,
        )
        .await
        .unwrap(),
        PushHandoffOutcome::QueueAccepted
    );
    assert_eq!(authority.0.load(Ordering::Relaxed), 0);
    let calls = routes.calls.lock().unwrap();
    let [Call::Local(_, iq)] = calls.as_slice() else {
        panic!("expected one local queue handoff, got {calls:?}");
    };
    let document = roxmltree::Document::parse(iq).unwrap();
    let counts: Vec<_> = document
        .descendants()
        .filter_map(|element| {
            let name = element.attribute("var")?;
            matches!(name, "message-count" | "pending-subscription-count").then(|| {
                let value = element.children().find(|child| child.is_element());
                (name, value.and_then(|child| child.text()))
            })
        })
        .collect();
    assert_eq!(
        counts,
        [
            ("message-count", Some("0")),
            ("pending-subscription-count", Some("47"))
        ],
    );
}
