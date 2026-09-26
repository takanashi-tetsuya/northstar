use super::{
    admit_offline_then_push, FullJidFallback, FullJidFallbackPort, FullJidFallbackResult,
    OfflineAdmissionOutcome, OnlineMessageRouter, OnlineRoutePort, OnlineRouteResult,
};
use crate::outbound::DurableDelivery;
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Mutex,
};

#[derive(Clone, Copy)]
enum Privacy {
    Allow,
    Deny,
    Error,
}

#[derive(Clone)]
struct Target {
    name: &'static str,
    accepts: bool,
    available: bool,
    priority: i16,
    privacy: Privacy,
}

struct RoutePort {
    events: Mutex<Vec<String>>,
    remote_primary_accepts: bool,
    remote_primary_key: Option<&'static str>,
    remote_available_accepts: bool,
    fallback: Vec<(String, Target)>,
}

impl RoutePort {
    fn new(remote_primary_accepts: bool, remote_available_accepts: bool) -> Self {
        Self {
            events: Mutex::new(Vec::new()),
            remote_primary_accepts,
            remote_primary_key: None,
            remote_available_accepts,
            fallback: Vec::new(),
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

impl FullJidFallbackPort for RoutePort {
    fn fallback_sessions(&self, bare: &str) -> Vec<(String, Self::Session)> {
        self.events.lock().unwrap().push(format!("lookup:{bare}"));
        self.fallback.clone()
    }

    fn available_priority(&self, session: &Self::Session) -> Option<i16> {
        (session.available && session.priority >= 0).then_some(session.priority)
    }

    fn priority(&self, session: &Self::Session) -> i16 {
        session.priority
    }

    async fn privacy_allows_fallback(
        &self,
        session: &Self::Session,
        _: &str,
    ) -> anyhow::Result<bool> {
        self.events
            .lock()
            .unwrap()
            .push(format!("privacy:{}", session.name));
        match session.privacy {
            Privacy::Allow => Ok(true),
            Privacy::Deny => Ok(false),
            Privacy::Error => anyhow::bail!("injected privacy failure"),
        }
    }

    fn post_accept_failed(&self) {
        self.events.lock().unwrap().push("postacceptfailed".into());
    }
}

fn target(name: &'static str, accepts: bool) -> (String, Target) {
    (
        name.to_owned(),
        Target {
            name,
            accepts,
            available: true,
            priority: 0,
            privacy: Privacy::Allow,
        },
    )
}

fn durable_delivery() -> DurableDelivery {
    DurableDelivery {
        recipient_id: uuid::Uuid::new_v4(),
        message_id: uuid::Uuid::new_v4(),
        claim_id: None,
    }
}

fn fallback_target(
    name: &'static str,
    priority: i16,
    available: bool,
    privacy: Privacy,
    accepts: bool,
) -> (String, Target) {
    (
        name.to_owned(),
        Target {
            name,
            accepts,
            available,
            priority,
            privacy,
        },
    )
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
async fn full_jid_chat_fallback_checks_privacy_before_priority_ordered_enqueue() {
    let port = RoutePort {
        fallback: vec![
            fallback_target("alice@example.test/low", 1, true, Privacy::Allow, true),
            fallback_target("alice@example.test/z", 5, true, Privacy::Allow, true),
            fallback_target("alice@example.test/blocked", 7, true, Privacy::Deny, true),
            fallback_target("alice@example.test/a", 5, true, Privacy::Allow, true),
            fallback_target(
                "alice@example.test/unavailable",
                9,
                false,
                Privacy::Allow,
                true,
            ),
            fallback_target(
                "alice@example.test/negative",
                -1,
                true,
                Privacy::Allow,
                true,
            ),
        ],
        ..RoutePort::new(true, false)
    };
    let outcome = OnlineMessageRouter::full_jid_fallback(
        &port,
        FullJidFallback {
            message_type: "chat",
            full_target: "alice@example.test/gone",
            bare_target: "alice@example.test",
            sender: "bob@example.test/phone",
            recipient_id: uuid::Uuid::nil(),
            stanza: "<message/>",
            delivery: None,
        },
    )
    .await
    .unwrap();
    assert_eq!(
        outcome,
        FullJidFallbackResult::Delivered(Some("alice@example.test/a".into()))
    );
    assert_eq!(
        port.events(),
        [
            "lookup:alice@example.test",
            "privacy:alice@example.test/blocked",
            "privacy:alice@example.test/a",
            "privacy:alice@example.test/z",
            "privacy:alice@example.test/low",
            "local:alice@example.test/a",
            "accepted:false",
        ]
    );
}

#[tokio::test]
async fn committed_full_jid_chat_privacy_error_fails_closed_without_rejecting() {
    let port = RoutePort {
        fallback: vec![
            fallback_target("alice@example.test/high", 5, true, Privacy::Error, true),
            fallback_target("alice@example.test/low", 1, true, Privacy::Allow, true),
        ],
        ..RoutePort::new(false, false)
    };
    let outcome = OnlineMessageRouter::full_jid_fallback(
        &port,
        FullJidFallback {
            message_type: "chat",
            full_target: "alice@example.test/gone",
            bare_target: "alice@example.test",
            sender: "bob@example.test/phone",
            recipient_id: uuid::Uuid::nil(),
            stanza: "<message/>",
            delivery: Some(durable_delivery()),
        },
    )
    .await
    .unwrap();
    assert_eq!(
        outcome,
        FullJidFallbackResult::Delivered(Some("alice@example.test/low".into()))
    );
    assert_eq!(
        port.events(),
        [
            "lookup:alice@example.test",
            "privacy:alice@example.test/high",
            "postacceptfailed",
            "privacy:alice@example.test/low",
            "local:alice@example.test/low",
            "accepted:true",
        ]
    );
}

#[tokio::test]
async fn volatile_full_jid_chat_privacy_error_prevents_any_fallback_enqueue() {
    let port = RoutePort {
        fallback: vec![
            fallback_target("alice@example.test/high", 5, true, Privacy::Allow, true),
            fallback_target("alice@example.test/low", 1, true, Privacy::Error, true),
        ],
        ..RoutePort::new(true, false)
    };
    assert!(OnlineMessageRouter::full_jid_fallback(
        &port,
        FullJidFallback {
            message_type: "chat",
            full_target: "alice@example.test/gone",
            bare_target: "alice@example.test",
            sender: "bob@example.test/phone",
            recipient_id: uuid::Uuid::nil(),
            stanza: "<message/>",
            delivery: None,
        },
    )
    .await
    .is_err());
    assert_eq!(
        port.events(),
        [
            "lookup:alice@example.test",
            "privacy:alice@example.test/high",
            "privacy:alice@example.test/low",
        ]
    );
}

#[tokio::test]
async fn full_jid_mismatch_preserves_durable_recovery_and_volatile_rejection() {
    let durable = RoutePort::new(true, false);
    let outcome = OnlineMessageRouter::full_jid_fallback(
        &durable,
        FullJidFallback {
            message_type: "normal",
            full_target: "alice@example.test/gone",
            bare_target: "alice@example.test",
            sender: "bob@example.test/phone",
            recipient_id: uuid::Uuid::nil(),
            stanza: "<message/>",
            delivery: Some(durable_delivery()),
        },
    )
    .await
    .unwrap();
    assert_eq!(outcome, FullJidFallbackResult::Undelivered);
    assert_eq!(durable.events(), ["postacceptfailed"]);

    let volatile = RoutePort::new(true, false);
    let outcome = OnlineMessageRouter::full_jid_fallback(
        &volatile,
        FullJidFallback {
            message_type: "normal",
            full_target: "alice@example.test/gone",
            bare_target: "alice@example.test",
            sender: "bob@example.test/phone",
            recipient_id: uuid::Uuid::nil(),
            stanza: "<message/>",
            delivery: None,
        },
    )
    .await
    .unwrap();
    assert_eq!(outcome, FullJidFallbackResult::Rejected);
    assert!(volatile.events().is_empty());
}

#[tokio::test]
async fn full_jid_error_stanza_is_dropped_without_fallback_effects() {
    let port = RoutePort::new(true, true);
    let outcome = OnlineMessageRouter::full_jid_fallback(
        &port,
        FullJidFallback {
            message_type: "error",
            full_target: "alice@example.test/gone",
            bare_target: "alice@example.test",
            sender: "bob@example.test/phone",
            recipient_id: uuid::Uuid::nil(),
            stanza: "<message type='error'/>",
            delivery: None,
        },
    )
    .await
    .unwrap();
    assert_eq!(outcome, FullJidFallbackResult::Dropped);
    assert!(port.events().is_empty());
}

#[tokio::test]
async fn full_jid_chat_queue_failure_tries_bare_remote_primary() {
    let port = RoutePort {
        fallback: vec![fallback_target(
            "alice@example.test/full",
            1,
            true,
            Privacy::Allow,
            false,
        )],
        ..RoutePort::new(true, false)
    };
    let outcome = OnlineMessageRouter::full_jid_fallback(
        &port,
        FullJidFallback {
            message_type: "chat",
            full_target: "alice@example.test/gone",
            bare_target: "alice@example.test",
            sender: "bob@example.test/phone",
            recipient_id: uuid::Uuid::nil(),
            stanza: "<message/>",
            delivery: None,
        },
    )
    .await
    .unwrap();
    assert_eq!(outcome, FullJidFallbackResult::Delivered(None));
    assert_eq!(
        port.events(),
        [
            "lookup:alice@example.test",
            "privacy:alice@example.test/full",
            "local:alice@example.test/full",
            "remote:primary",
        ]
    );
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
