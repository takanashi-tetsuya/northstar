use super::{
    admit_offline_then_push, OfflineAdmissionOutcome, OnlineMessageRouter, OnlineRoutePort,
    OnlineRouteResult,
};
use crate::outbound::DurableDelivery;
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Mutex,
};

struct Target {
    name: &'static str,
    accepts: bool,
}

struct RoutePort {
    events: Mutex<Vec<String>>,
    remote_primary_accepts: bool,
    remote_primary_key: Option<&'static str>,
    remote_available_accepts: bool,
}

impl RoutePort {
    fn new(remote_primary_accepts: bool, remote_available_accepts: bool) -> Self {
        Self {
            events: Mutex::new(Vec::new()),
            remote_primary_accepts,
            remote_primary_key: None,
            remote_available_accepts,
        }
    }

    fn events(&self) -> Vec<String> {
        self.events.lock().unwrap().clone()
    }
}

impl OnlineRoutePort for RoutePort {
    type Session = Target;

    fn try_local(&self, session: &Self::Session, _: String, _: Option<DurableDelivery>) -> bool {
        self.events
            .lock()
            .unwrap()
            .push(format!("local:{}", session.name));
        session.accepts
    }

    fn record_local_accept(&self, durable: bool) {
        self.events
            .lock()
            .unwrap()
            .push(format!("accepted:{durable}"));
    }

    async fn route_available_remote(&self, _: &str, _: &str, _: Option<DurableDelivery>) -> bool {
        self.events.lock().unwrap().push("remote:all".into());
        self.remote_available_accepts
    }

    async fn route_remote_primary(
        &self,
        _: &str,
        _: &str,
        _: Option<DurableDelivery>,
    ) -> OnlineRouteResult {
        self.events.lock().unwrap().push("remote:primary".into());
        OnlineRouteResult {
            delivered: self.remote_primary_accepts,
            accepted_full_jid: self.remote_primary_key.map(str::to_owned),
        }
    }
}

fn target(name: &'static str, accepts: bool) -> (String, Target) {
    (name.to_owned(), Target { name, accepts })
}

fn durable_delivery() -> DurableDelivery {
    DurableDelivery {
        recipient_id: uuid::Uuid::new_v4(),
        message_id: uuid::Uuid::new_v4(),
        claim_id: None,
    }
}

#[tokio::test]
async fn highest_priority_local_acceptance_stops_primary_routing() {
    let port = RoutePort::new(true, false);
    let targets = [
        target("alice@example.test/high", true),
        target("alice@example.test/low", true),
    ];
    let route = OnlineMessageRouter::dispatch(
        &port,
        "alice@example.test",
        "<message/>",
        Some(durable_delivery()),
        false,
        &targets,
    )
    .await;
    assert_eq!(
        route.accepted_full_jid.as_deref(),
        Some("alice@example.test/high")
    );
    assert!(route.delivered);
    assert_eq!(
        port.events(),
        ["local:alice@example.test/high", "accepted:true"]
    );
}

#[tokio::test]
async fn full_local_queues_fall_through_to_first_remote_primary() {
    let port = RoutePort {
        remote_primary_key: Some("alice@example.test/remote"),
        ..RoutePort::new(true, false)
    };
    let targets = [
        target("alice@example.test/high", false),
        target("alice@example.test/low", false),
    ];
    let route = OnlineMessageRouter::dispatch(
        &port,
        "alice@example.test",
        "<message/>",
        Some(durable_delivery()),
        false,
        &targets,
    )
    .await;
    assert_eq!(
        route.accepted_full_jid.as_deref(),
        Some("alice@example.test/remote")
    );
    assert!(route.delivered);
    assert_eq!(
        port.events(),
        [
            "local:alice@example.test/high",
            "local:alice@example.test/low",
            "remote:primary",
        ]
    );
}

#[tokio::test]
async fn headline_fans_out_locally_then_to_remote_nodes() {
    let port = RoutePort::new(false, true);
    let targets = [
        target("alice@example.test/high", true),
        target("alice@example.test/full", false),
        target("alice@example.test/low", true),
    ];
    let route = OnlineMessageRouter::dispatch(
        &port,
        "alice@example.test",
        "<message type='headline'/>",
        None,
        true,
        &targets,
    )
    .await;
    assert_eq!(
        route.accepted_full_jid.as_deref(),
        Some("alice@example.test/high")
    );
    assert!(route.delivered);
    assert_eq!(
        port.events(),
        [
            "local:alice@example.test/high",
            "accepted:false",
            "local:alice@example.test/full",
            "local:alice@example.test/low",
            "accepted:false",
            "remote:all",
        ]
    );
}

#[tokio::test]
async fn legacy_remote_acceptance_without_resource_key_prevents_duplicate_fallback() {
    let port = RoutePort::new(true, false);
    let route = OnlineMessageRouter::dispatch(
        &port,
        "alice@example.test",
        "<message/>",
        Some(durable_delivery()),
        false,
        &[],
    )
    .await;
    assert_eq!(
        route,
        OnlineRouteResult {
            delivered: true,
            accepted_full_jid: None
        }
    );
    assert_eq!(port.events(), ["remote:primary"]);
}

#[tokio::test]
async fn failed_offline_commit_never_polls_push_provider() {
    let calls = AtomicUsize::new(0);
    let result = admit_offline_then_push(
        async { anyhow::bail!("offline transaction failed") },
        true,
        async {
            calls.fetch_add(1, Ordering::SeqCst);
            Ok(())
        },
    )
    .await;
    assert!(result.is_err());
    assert_eq!(calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn replay_and_unaccepted_offline_outcomes_never_notify_again() {
    let calls = AtomicUsize::new(0);
    for (admission, history_committed) in [
        (OfflineAdmissionOutcome::Replay, true),
        (OfflineAdmissionOutcome::QuotaExceeded, false),
        (OfflineAdmissionOutcome::RecipientUnavailable, true),
    ] {
        let result = admit_offline_then_push(async { Ok(admission) }, history_committed, async {
            calls.fetch_add(1, Ordering::SeqCst);
            Ok(())
        })
        .await
        .unwrap();
        assert_eq!(result.admission, admission);
        assert!(result.push_error.is_none());
    }
    assert_eq!(calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn committed_offline_or_mam_recovery_attempts_push_once() {
    let calls = AtomicUsize::new(0);
    for admission in [
        OfflineAdmissionOutcome::Stored,
        OfflineAdmissionOutcome::QuotaExceeded,
    ] {
        let result = admit_offline_then_push(async { Ok(admission) }, true, async {
            calls.fetch_add(1, Ordering::SeqCst);
            anyhow::bail!("provider failed")
        })
        .await
        .unwrap();
        assert_eq!(result.admission, admission);
        assert!(result.push_error.is_some());
    }
    assert_eq!(calls.load(Ordering::SeqCst), 2);
}
