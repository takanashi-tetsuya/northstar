use super::*;
use std::sync::{Arc, Mutex};

#[derive(Clone, Copy)]
enum Failure {
    None,
    Claim,
    Route,
    Mark,
}

#[derive(Clone)]
struct StubRepository {
    events: Arc<Mutex<Vec<&'static str>>>,
    failure: Failure,
}

impl PushRepository for StubRepository {
    async fn enable(
        &self,
        _: Uuid,
        _: &str,
        _: &str,
        _: Option<&str>,
    ) -> Result<PushEnableOutcome> {
        unreachable!()
    }

    async fn disable(&self, _: Uuid, _: &str, _: Option<&str>) -> Result<u64> {
        unreachable!()
    }

    async fn claim_batch(&self, _: Uuid) -> Result<PushBatch> {
        self.events.lock().unwrap().push("claim");
        if matches!(self.failure, Failure::Claim) {
            anyhow::bail!("claim failed");
        }
        Ok(PushBatch {
            message_count: 2,
            pending_subscription_count: 1,
            deliveries: [1_u128, 2]
                .into_iter()
                .map(|id| PushDelivery {
                    request_id: Uuid::from_u128(id),
                    service_jid: "push@example.test".to_owned(),
                    node: "device".to_owned(),
                    options: None,
                })
                .collect(),
        })
    }

    async fn mark_unroutable(&self, _: Uuid) -> Result<()> {
        self.events.lock().unwrap().push("mark");
        if matches!(self.failure, Failure::Mark) {
            anyhow::bail!("mark failed");
        }
        Ok(())
    }

    async fn complete_response(
        &self,
        _: Uuid,
        _: &str,
        _: PushResponseKind,
    ) -> Result<PushResponseOutcome> {
        unreachable!()
    }

    async fn disable_from_service(&self, _: &str, _: &str, _: &str) -> Result<bool> {
        unreachable!()
    }
}

struct StubRouter {
    events: Arc<Mutex<Vec<&'static str>>>,
    failure: Failure,
}

impl PushNotificationRouter for StubRouter {
    async fn route(&self, delivery: &PushDelivery, counts: PushNotificationCounts) -> Result<bool> {
        assert_eq!(counts.message_count, 2);
        assert_eq!(counts.pending_subscription_count, 1);
        self.events.lock().unwrap().push("route");
        if matches!(self.failure, Failure::Route) {
            anyhow::bail!("route failed");
        }
        Ok(delivery.request_id == Uuid::from_u128(2))
    }

    fn routed(&self) {
        self.events.lock().unwrap().push("routed");
    }

    fn failed(&self) {
        self.events.lock().unwrap().push("failed");
    }

    fn attempted(&self) {
        self.events.lock().unwrap().push("attempted");
    }
}

async fn dispatch(failure: Failure) -> (Result<()>, Vec<&'static str>) {
    let events = Arc::new(Mutex::new(Vec::new()));
    let repository = StubRepository {
        events: Arc::clone(&events),
        failure,
    };
    let router = StubRouter {
        events: Arc::clone(&events),
        failure,
    };
    let result = PushService::new(repository)
        .dispatch_after_commit(Uuid::nil(), &router)
        .await;
    let trace = events.lock().unwrap().clone();
    (result, trace)
}

#[tokio::test]
async fn claim_route_mark_and_metrics_keep_per_subscription_order() {
    let (result, trace) = dispatch(Failure::None).await;
    result.unwrap();
    assert_eq!(
        trace,
        [
            "claim",
            "route",
            "mark",
            "failed",
            "attempted",
            "route",
            "routed",
            "attempted"
        ]
    );
}

#[tokio::test]
async fn provider_or_settlement_error_stops_before_later_subscriptions() {
    for (failure, expected) in [
        (Failure::Claim, vec!["claim"]),
        (Failure::Route, vec!["claim", "route"]),
        (Failure::Mark, vec!["claim", "route", "mark"]),
    ] {
        let (result, trace) = dispatch(failure).await;
        assert!(result.is_err());
        assert_eq!(trace, expected);
    }
}
