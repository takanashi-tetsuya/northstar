use super::*;
use crate::services::messaging::{OnlineRoutePort, OnlineRouteResult};
use std::{
    collections::{BTreeMap, VecDeque},
    sync::Mutex,
};

#[derive(Clone)]
struct Target {
    jid: &'static str,
    accepts: bool,
    privacy_error: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum RouteDestination {
    Local(&'static str),
    PrimaryRemote(String),
    AvailableRemote(String),
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct RouteCall {
    destination: RouteDestination,
    stanza: String,
    delivery: Option<DurableDelivery>,
}

struct Port {
    events: Mutex<Vec<String>>,
    route_calls: Mutex<Vec<RouteCall>>,
    modes: Mutex<VecDeque<DirectPostCommitMode>>,
    rearmed: Mutex<Vec<DurableDelivery>>,
    clustered: bool,
    remote_accepts: bool,
    remote_accepts_for: Option<&'static str>,
    remote_accepted_full_jid: Option<&'static str>,
    fallback: Vec<(String, Target)>,
    accepted_kinds: Mutex<Vec<bool>>,
    privacy_calls: Mutex<Vec<(String, String)>>,
    fallback_denied: Vec<&'static str>,
    priorities: BTreeMap<&'static str, i16>,
}

impl Port {
    fn new(modes: &[DirectPostCommitMode]) -> Self {
        Self {
            events: Mutex::new(Vec::new()),
            route_calls: Mutex::new(Vec::new()),
            modes: Mutex::new(modes.iter().copied().collect()),
            rearmed: Mutex::new(Vec::new()),
            clustered: true,
            remote_accepts: false,
            remote_accepts_for: None,
            remote_accepted_full_jid: None,
            fallback: Vec::new(),
            accepted_kinds: Mutex::new(Vec::new()),
            privacy_calls: Mutex::new(Vec::new()),
            fallback_denied: Vec::new(),
            priorities: BTreeMap::new(),
        }
    }

    fn record(&self, event: impl Into<String>) {
        self.events.lock().unwrap().push(event.into());
    }

    fn record_route(
        &self,
        destination: RouteDestination,
        stanza: &str,
        delivery: Option<DurableDelivery>,
    ) {
        self.route_calls.lock().unwrap().push(RouteCall {
            destination,
            stanza: stanza.to_owned(),
            delivery,
        });
    }

    fn route_calls(&self) -> Vec<RouteCall> {
        self.route_calls.lock().unwrap().clone()
    }

    fn events(&self) -> Vec<String> {
        self.events.lock().unwrap().clone()
    }
}

impl OnlineRoutePort for Port {
    type Session = Target;

    fn try_local(
        &self,
        target: &Target,
        stanza: String,
        delivery: Option<DurableDelivery>,
    ) -> bool {
        self.record("enqueue");
        self.record_route(RouteDestination::Local(target.jid), &stanza, delivery);
        target.accepts
    }

    fn record_local_accept(&self, durable: bool) {
        self.accepted_kinds.lock().unwrap().push(durable);
        self.record("accepted");
    }

    async fn route_available_remote(
        &self,
        jid: &str,
        stanza: &str,
        delivery: Option<DurableDelivery>,
    ) -> bool {
        self.record("remote:all");
        self.record_route(
            RouteDestination::AvailableRemote(jid.to_owned()),
            stanza,
            delivery,
        );
        self.remote_accepts
    }

    async fn route_remote_primary(
        &self,
        jid: &str,
        stanza: &str,
        delivery: Option<DurableDelivery>,
    ) -> OnlineRouteResult {
        self.record(format!("remote:{jid}"));
        self.record_route(
            RouteDestination::PrimaryRemote(jid.to_owned()),
            stanza,
            delivery,
        );
        let delivered = self.remote_accepts || self.remote_accepts_for == Some(jid);
        OnlineRouteResult {
            delivered,
            accepted_full_jid: if delivered {
                self.remote_accepted_full_jid.map(str::to_owned)
            } else {
                None
            },
        }
    }
}

impl FullJidFallbackPort for Port {
    fn fallback_sessions(&self, _: &str) -> Vec<(String, Target)> {
        self.record("fallback:snapshot");
        self.fallback.clone()
    }

    fn available_priority(&self, target: &Target) -> Option<i16> {
        let priority = self.priority(target);
        (priority >= 0).then_some(priority)
    }

    fn priority(&self, target: &Target) -> i16 {
        self.priorities.get(target.jid).copied().unwrap_or(1)
    }

    async fn privacy_allows_fallback(&self, target: &Target, sender: &str) -> anyhow::Result<bool> {
        self.record("fallback:privacy");
        self.privacy_calls
            .lock()
            .unwrap()
            .push((target.jid.to_owned(), sender.to_owned()));
        anyhow::ensure!(!target.privacy_error, "injected privacy failure");
        Ok(!self.fallback_denied.contains(&target.jid))
    }

    fn post_accept_failed(&self) {
        self.record("post_accept_failure");
    }
}

impl DirectMessageRoutePort for Port {
    fn direct_route_mode(&self) -> DirectPostCommitMode {
        let mut modes = self.modes.lock().unwrap();
        let mode = if modes.len() > 1 {
            modes.pop_front().unwrap()
        } else {
            *modes.front().unwrap_or(&DirectPostCommitMode::Live)
        };
        self.record(format!("health:{mode:?}"));
        mode
    }

    fn clustered_direct_routes(&self) -> bool {
        self.clustered
    }

    async fn rearm_direct_route(&self, delivery: DurableDelivery) {
        self.record("rearm");
        self.rearmed.lock().unwrap().push(delivery);
    }
}

fn committed() -> DurableDelivery {
    DurableDelivery {
        recipient_id: Uuid::from_u128(1),
        message_id: Uuid::from_u128(2),
        claim_id: Some(Uuid::from_u128(2)),
    }
}

fn request<'a>(delivery: DirectRouteDelivery) -> DirectRouteRequest<'a, Target> {
    DirectRouteRequest {
        message_type: "chat",
        target: DirectRouteTarget::Full {
            jid: "alice@example.test/gone",
            bare: "alice@example.test",
        },
        sender: "bob@example.test/phone",
        recipient_id: Uuid::from_u128(1),
        stanza: "<message/>",
        delivery,
        approved_targets: &[],
        enforce_direct_health: true,
    }
}

fn recovery(stage: DirectRouteStage) -> DirectRouteOutcome {
    DirectRouteOutcome::AcceptedForRecovery {
        stage,
        reason: DirectRouteRecoveryReason::HealthChanged,
    }
}

#[tokio::test]
async fn degraded_before_routing_rearms_exact_committed_claim_without_enqueuing() {
    for mode in [
        DirectPostCommitMode::SpoolOnly,
        DirectPostCommitMode::Rejected,
    ] {
        let port = Port::new(&[mode]);
        let outcome =
            DirectMessageRouter::route(&port, request(DirectRouteDelivery::Committed(committed())))
                .await
                .unwrap();
        assert_eq!(outcome, recovery(DirectRouteStage::PrimaryRoute));
        assert_eq!(*port.rearmed.lock().unwrap(), [committed()]);
        assert_eq!(port.events(), [format!("health:{mode:?}"), "rearm".into()]);
    }
}

#[tokio::test]
async fn degraded_volatile_route_rejects_without_routing_or_persistence() {
    let port = Port::new(&[DirectPostCommitMode::SpoolOnly]);
    let outcome = DirectMessageRouter::route(&port, request(DirectRouteDelivery::Volatile))
        .await
        .unwrap();
    assert_eq!(
        outcome,
        DirectRouteOutcome::Rejected(DirectRouteRejection::Unavailable)
    );
    assert_eq!(port.events(), ["health:SpoolOnly"]);
    assert!(port.rearmed.lock().unwrap().is_empty());
}

#[tokio::test]
async fn loss_of_health_before_full_jid_fallback_stops_the_next_route() {
    let port = Port::new(&[DirectPostCommitMode::Live, DirectPostCommitMode::SpoolOnly]);
    let outcome =
        DirectMessageRouter::route(&port, request(DirectRouteDelivery::Committed(committed())))
            .await
            .unwrap();
    assert_eq!(outcome, recovery(DirectRouteStage::FullJidFallback));
    assert_eq!(
        port.events(),
        [
            "health:Live",
            "remote:alice@example.test/gone",
            "health:SpoolOnly",
            "rearm",
        ]
    );
    assert_eq!(*port.rearmed.lock().unwrap(), [committed()]);
}

#[tokio::test]
async fn accepted_queue_is_never_rearmed_when_health_changes() {
    for delivery in [
        DirectRouteDelivery::Volatile,
        DirectRouteDelivery::Committed(committed()),
    ] {
        let port = Port {
            remote_accepts: true,
            ..Port::new(&[DirectPostCommitMode::Live, DirectPostCommitMode::Rejected])
        };
        let outcome = DirectMessageRouter::route(&port, request(delivery))
            .await
            .unwrap();
        assert_eq!(
            outcome,
            match delivery {
                DirectRouteDelivery::Volatile => DirectRouteOutcome::AcceptedBeforeDegradation,
                DirectRouteDelivery::Committed(_) => recovery(DirectRouteStage::AfterRouting),
            }
        );
        assert!(port.rearmed.lock().unwrap().is_empty());
        assert_eq!(
            port.events(),
            [
                "health:Live",
                "remote:alice@example.test/gone",
                "health:Rejected"
            ]
        );
    }
}

#[tokio::test]
async fn unaccepted_claim_is_rearmed_once_even_if_final_health_check_degrades() {
    let port = Port::new(&[
        DirectPostCommitMode::Live,
        DirectPostCommitMode::Live,
        DirectPostCommitMode::SpoolOnly,
    ]);
    let outcome =
        DirectMessageRouter::route(&port, request(DirectRouteDelivery::Committed(committed())))
            .await
            .unwrap();
    assert_eq!(outcome, recovery(DirectRouteStage::AfterRouting));
    assert_eq!(*port.rearmed.lock().unwrap(), [committed()]);
    assert_eq!(
        port.events()
            .iter()
            .filter(|event| *event == "rearm")
            .count(),
        1
    );
}

#[tokio::test]
async fn missing_or_wrong_live_reservation_never_enters_a_queue_or_rearms_foreign_token() {
    for claim_id in [None, Some(Uuid::from_u128(99))] {
        let port = Port::new(&[]);
        let delivery = DurableDelivery {
            claim_id,
            ..committed()
        };
        let outcome =
            DirectMessageRouter::route(&port, request(DirectRouteDelivery::Committed(delivery)))
                .await
                .unwrap();
        assert_eq!(
            outcome,
            DirectRouteOutcome::AcceptedForRecovery {
                stage: DirectRouteStage::LiveReservation,
                reason: DirectRouteRecoveryReason::MissingLiveReservation,
            }
        );
        assert_eq!(port.events(), ["post_accept_failure"]);
        assert!(port.rearmed.lock().unwrap().is_empty());
    }
}

#[tokio::test]
async fn full_jid_fallback_errors_are_stage_typed_only_before_acceptance() {
    for durable in [false, true] {
        let port = Port {
            fallback: vec![(
                "alice@example.test/phone".into(),
                Target {
                    jid: "alice@example.test/phone",
                    accepts: true,
                    privacy_error: true,
                },
            )],
            ..Port::new(&[])
        };
        let delivery = if durable {
            DirectRouteDelivery::Committed(committed())
        } else {
            DirectRouteDelivery::Volatile
        };
        let result = DirectMessageRouter::route(&port, request(delivery)).await;
        if durable {
            assert_eq!(result.unwrap(), DirectRouteOutcome::Unrouted);
            assert_eq!(*port.rearmed.lock().unwrap(), [committed()]);
            assert!(port.events().contains(&"post_accept_failure".into()));
        } else {
            assert_eq!(result.unwrap_err().stage, DirectRouteStage::FullJidFallback);
            assert!(port.rearmed.lock().unwrap().is_empty());
        }
        assert!(!port.events().contains(&"enqueue".into()));
    }
}

const EXACT_STANZA: &str = "<message from='bob@example.test/phone' to='alice@example.test/gone' type='chat' id='exact-envelope'><body>preserve &amp; bytes</body></message>";

fn expected_route(destination: RouteDestination, delivery: DirectRouteDelivery) -> RouteCall {
    RouteCall {
        destination,
        stanza: EXACT_STANZA.to_owned(),
        delivery: delivery.durable(),
    }
}

#[tokio::test]
async fn successful_local_route_preserves_exact_payload_recipient_message_and_claim() {
    for delivery in [
        DirectRouteDelivery::Volatile,
        DirectRouteDelivery::Committed(committed()),
    ] {
        let port = Port::new(&[]);
        let targets = vec![(
            "alice@example.test/gone".into(),
            Target {
                jid: "alice@example.test/gone",
                accepts: true,
                privacy_error: false,
            },
        )];
        let mut request = request(delivery);
        request.stanza = EXACT_STANZA;
        request.approved_targets = &targets;
        let outcome = DirectMessageRouter::route(&port, request).await.unwrap();
        assert_eq!(
            outcome,
            DirectRouteOutcome::Routed {
                accepted_full_jid: Some("alice@example.test/gone".into()),
            }
        );
        assert_eq!(
            port.route_calls(),
            [expected_route(
                RouteDestination::Local("alice@example.test/gone"),
                delivery,
            )]
        );
        assert!(port.rearmed.lock().unwrap().is_empty());
    }
}

#[tokio::test]
async fn successful_primary_remote_preserves_exact_payload_recipient_message_and_claim() {
    for delivery in [
        DirectRouteDelivery::Volatile,
        DirectRouteDelivery::Committed(committed()),
    ] {
        let port = Port {
            remote_accepts: true,
            ..Port::new(&[])
        };
        let mut request = request(delivery);
        request.stanza = EXACT_STANZA;
        let outcome = DirectMessageRouter::route(&port, request).await.unwrap();
        assert_eq!(
            outcome,
            DirectRouteOutcome::Routed {
                accepted_full_jid: None
            }
        );
        assert_eq!(
            port.route_calls(),
            [expected_route(
                RouteDestination::PrimaryRemote("alice@example.test/gone".into()),
                delivery,
            )]
        );
        assert!(port.rearmed.lock().unwrap().is_empty());
    }
}

#[tokio::test]
async fn successful_fallback_preserves_exact_resource_and_claim_ownership() {
    for delivery in [
        DirectRouteDelivery::Volatile,
        DirectRouteDelivery::Committed(committed()),
    ] {
        let port = Port {
            fallback: vec![(
                "alice@example.test/phone".into(),
                Target {
                    jid: "alice@example.test/phone",
                    accepts: true,
                    privacy_error: false,
                },
            )],
            ..Port::new(&[])
        };
        let mut request = request(delivery);
        request.stanza = EXACT_STANZA;
        let outcome = DirectMessageRouter::route(&port, request).await.unwrap();
        assert_eq!(
            outcome,
            DirectRouteOutcome::Routed {
                accepted_full_jid: Some("alice@example.test/phone".into()),
            }
        );
        assert_eq!(
            port.route_calls(),
            [
                expected_route(
                    RouteDestination::PrimaryRemote("alice@example.test/gone".into()),
                    delivery
                ),
                expected_route(
                    RouteDestination::Local("alice@example.test/phone"),
                    delivery
                ),
            ]
        );
        assert!(port.rearmed.lock().unwrap().is_empty());
        assert_eq!(
            port.events(),
            [
                "health:Live",
                "remote:alice@example.test/gone",
                "health:Live",
                "fallback:snapshot",
                "fallback:privacy",
                "enqueue",
                "accepted",
                "health:Live",
            ]
        );
    }
}

#[tokio::test]
async fn successful_remote_fallback_changes_route_but_preserves_the_exact_envelope_and_claim() {
    for delivery in [
        DirectRouteDelivery::Volatile,
        DirectRouteDelivery::Committed(committed()),
    ] {
        let port = Port {
            remote_accepts_for: Some("alice@example.test"),
            ..Port::new(&[])
        };
        let mut request = request(delivery);
        request.stanza = EXACT_STANZA;
        let outcome = DirectMessageRouter::route(&port, request).await.unwrap();
        assert_eq!(
            outcome,
            DirectRouteOutcome::Routed {
                accepted_full_jid: None
            }
        );
        assert_eq!(
            port.route_calls(),
            [
                expected_route(
                    RouteDestination::PrimaryRemote("alice@example.test/gone".into()),
                    delivery
                ),
                expected_route(
                    RouteDestination::PrimaryRemote("alice@example.test".into()),
                    delivery
                ),
            ]
        );
        assert!(port.rearmed.lock().unwrap().is_empty());
    }
}

#[tokio::test]
async fn exact_normal_route_failure_rejects_volatile_but_preserves_committed_admission() {
    for durable in [false, true] {
        let port = Port::new(&[]);
        let mut request = request(if durable {
            DirectRouteDelivery::Committed(committed())
        } else {
            DirectRouteDelivery::Volatile
        });
        request.message_type = "normal";
        let outcome = DirectMessageRouter::route(&port, request).await.unwrap();
        assert_eq!(
            outcome,
            if durable {
                DirectRouteOutcome::Unrouted
            } else {
                DirectRouteOutcome::Rejected(DirectRouteRejection::NoMatchingResource)
            }
        );
        assert_eq!(port.rearmed.lock().unwrap().len(), usize::from(durable));
    }
}

#[tokio::test]
async fn bare_target_never_enters_full_jid_fallback() {
    let port = Port::new(&[]);
    let mut request = request(DirectRouteDelivery::Volatile);
    request.target = DirectRouteTarget::Bare("alice@example.test");
    let outcome = DirectMessageRouter::route(&port, request).await.unwrap();
    assert_eq!(outcome, DirectRouteOutcome::Unrouted);
    assert_eq!(
        port.events(),
        ["health:Live", "remote:alice@example.test", "health:Live"]
    );
}

#[tokio::test]
async fn error_stanzas_drop_without_offline_fallback_or_error_loop() {
    let port = Port::new(&[]);
    let mut request = request(DirectRouteDelivery::Volatile);
    request.message_type = "error";
    let outcome = DirectMessageRouter::route(&port, request).await.unwrap();
    assert_eq!(outcome, DirectRouteOutcome::Dropped);
    assert!(!port.events().contains(&"fallback:snapshot".into()));
}

#[tokio::test]
async fn non_direct_service_routes_do_not_consume_direct_health_checks() {
    let port = Port {
        remote_accepts: true,
        ..Port::new(&[DirectPostCommitMode::Rejected])
    };
    let mut request = request(DirectRouteDelivery::Volatile);
    request.enforce_direct_health = false;
    let outcome = DirectMessageRouter::route(&port, request).await.unwrap();
    assert_eq!(
        outcome,
        DirectRouteOutcome::Routed {
            accepted_full_jid: None
        }
    );
    assert_eq!(port.events(), ["remote:alice@example.test/gone"]);
}

fn target(jid: &'static str, accepts: bool) -> (String, Target) {
    (
        jid.into(),
        Target {
            jid,
            accepts,
            privacy_error: false,
        },
    )
}

fn delivery_cases() -> [DirectRouteDelivery; 2] {
    [
        DirectRouteDelivery::Volatile,
        DirectRouteDelivery::Committed(committed()),
    ]
}

#[tokio::test]
async fn federation_successful_routes_preserve_checkpoint_order_and_exact_envelope() {
    for delivery in delivery_cases() {
        for route in ["local", "remote", "fallback_local", "fallback_remote"] {
            let targets = if route == "local" {
                vec![target("alice@example.test/gone", true)]
            } else {
                Vec::new()
            };
            let port = Port {
                remote_accepts_for: match route {
                    "remote" => Some("alice@example.test/gone"),
                    "fallback_remote" => Some("alice@example.test"),
                    _ => None,
                },
                fallback: if route == "fallback_local" {
                    vec![target("alice@example.test/phone", true)]
                } else {
                    Vec::new()
                },
                ..Port::new(&[])
            };
            let mut request = request(delivery);
            request.stanza = EXACT_STANZA;
            request.approved_targets = &targets;
            let outcome = DirectMessageRouter::route_federated(&port, request, false)
                .await
                .unwrap();
            let (key, events, destinations) = match route {
                "local" => (
                    Some("alice@example.test/gone".into()),
                    vec![
                        "health:Live",
                        "enqueue",
                        "accepted",
                        "health:Live",
                        "health:Live",
                    ],
                    vec![RouteDestination::Local("alice@example.test/gone")],
                ),
                "remote" => (
                    None,
                    vec![
                        "health:Live",
                        "health:Live",
                        "remote:alice@example.test/gone",
                        "health:Live",
                    ],
                    vec![RouteDestination::PrimaryRemote(
                        "alice@example.test/gone".into(),
                    )],
                ),
                "fallback_local" => (
                    Some("alice@example.test/phone".into()),
                    vec![
                        "health:Live",
                        "health:Live",
                        "remote:alice@example.test/gone",
                        "health:Live",
                        "fallback:snapshot",
                        "fallback:privacy",
                        "health:Live",
                        "enqueue",
                        "accepted",
                        "health:Live",
                    ],
                    vec![
                        RouteDestination::PrimaryRemote("alice@example.test/gone".into()),
                        RouteDestination::Local("alice@example.test/phone"),
                    ],
                ),
                "fallback_remote" => (
                    None,
                    vec![
                        "health:Live",
                        "health:Live",
                        "remote:alice@example.test/gone",
                        "health:Live",
                        "fallback:snapshot",
                        "health:Live",
                        "health:Live",
                        "remote:alice@example.test",
                        "health:Live",
                    ],
                    vec![
                        RouteDestination::PrimaryRemote("alice@example.test/gone".into()),
                        RouteDestination::PrimaryRemote("alice@example.test".into()),
                    ],
                ),
                _ => unreachable!(),
            };
            assert_eq!(
                outcome,
                DirectRouteOutcome::Routed {
                    accepted_full_jid: key
                },
                "{route}"
            );
            assert_eq!(port.events(), events, "{route}");
            assert_eq!(
                port.route_calls(),
                destinations
                    .into_iter()
                    .map(|destination| expected_route(destination, delivery))
                    .collect::<Vec<_>>(),
                "{route}"
            );
            assert_eq!(
                port.accepted_kinds.lock().unwrap().as_slice(),
                if matches!(route, "local" | "fallback_local") {
                    vec![delivery.durable().is_some()]
                } else {
                    vec![]
                }
            );
            assert!(port.rearmed.lock().unwrap().is_empty());
        }
    }
}

#[tokio::test]
async fn federation_every_preaccept_health_checkpoint_stops_later_effects() {
    use DirectRouteStage::*;
    let cases = [
        (PrimaryRoute, vec![]),
        (PrimaryRemote, vec!["health:Live", "enqueue"]),
        (
            FullJidFallback,
            vec![
                "health:Live",
                "enqueue",
                "health:Live",
                "remote:alice@example.test/gone",
            ],
        ),
        (
            FallbackLocal,
            vec![
                "health:Live",
                "enqueue",
                "health:Live",
                "remote:alice@example.test/gone",
                "health:Live",
                "fallback:snapshot",
                "fallback:privacy",
            ],
        ),
        (
            FallbackRemote,
            vec![
                "health:Live",
                "enqueue",
                "health:Live",
                "remote:alice@example.test/gone",
                "health:Live",
                "fallback:snapshot",
                "fallback:privacy",
                "health:Live",
                "enqueue",
            ],
        ),
    ];
    for delivery in delivery_cases() {
        for mode in [
            DirectPostCommitMode::SpoolOnly,
            DirectPostCommitMode::Rejected,
        ] {
            for (index, (stage, prefix)) in cases.iter().enumerate() {
                let mut modes = vec![DirectPostCommitMode::Live; index];
                modes.push(mode);
                let port = Port {
                    fallback: vec![target("alice@example.test/phone", false)],
                    ..Port::new(&modes)
                };
                let targets = [target("alice@example.test/gone", false)];
                let mut request = request(delivery);
                request.stanza = EXACT_STANZA;
                request.approved_targets = &targets;
                let outcome = DirectMessageRouter::route_federated(&port, request, false)
                    .await
                    .unwrap();
                let mut events = prefix
                    .iter()
                    .map(|event| (*event).to_owned())
                    .collect::<Vec<_>>();
                events.push(format!("health:{mode:?}"));
                if delivery.durable().is_some() {
                    events.push("rearm".into());
                    assert_eq!(outcome, recovery(*stage));
                    assert_eq!(*port.rearmed.lock().unwrap(), [committed()]);
                } else {
                    assert_eq!(
                        outcome,
                        DirectRouteOutcome::Rejected(DirectRouteRejection::Unavailable)
                    );
                    assert!(port.rearmed.lock().unwrap().is_empty());
                }
                assert_eq!(port.events(), events, "{stage:?} {mode:?} {delivery:?}");
                assert!(port.accepted_kinds.lock().unwrap().is_empty());
                for call in port.route_calls() {
                    assert_eq!(call.stanza, EXACT_STANZA);
                    assert_eq!(call.delivery, delivery.durable());
                }
            }
        }
    }
}

#[tokio::test]
async fn federation_history_acceptance_is_separate_from_a_live_delivery_claim() {
    for mode in [
        DirectPostCommitMode::SpoolOnly,
        DirectPostCommitMode::Rejected,
    ] {
        let degraded_health = format!("health:{mode:?}");

        for history_committed in [false, true] {
            let port = Port::new(&[mode]);
            let outcome = DirectMessageRouter::route_federated(
                &port,
                request(DirectRouteDelivery::Volatile),
                history_committed,
            )
            .await
            .unwrap();
            assert_eq!(
                outcome,
                if history_committed {
                    recovery(DirectRouteStage::PrimaryRoute)
                } else {
                    DirectRouteOutcome::Rejected(DirectRouteRejection::Unavailable)
                }
            );
            assert_eq!(port.events(), [format!("health:{mode:?}")]);
            assert!(port.rearmed.lock().unwrap().is_empty());
            assert!(port.route_calls().is_empty());
        }
        // The old federation path consults history only before primary routing.
        let port = Port::new(&[DirectPostCommitMode::Live, mode]);
        let outcome = DirectMessageRouter::route_federated(
            &port,
            request(DirectRouteDelivery::Volatile),
            true,
        )
        .await
        .unwrap();
        assert_eq!(
            outcome,
            DirectRouteOutcome::Rejected(DirectRouteRejection::Unavailable)
        );
        assert_eq!(port.events(), ["health:Live", degraded_health.as_str()]);
        assert!(port.rearmed.lock().unwrap().is_empty());
    }
}

#[tokio::test]
async fn federation_local_acceptance_before_degradation_never_rearms_or_routes_remote() {
    for delivery in delivery_cases() {
        for mode in [
            DirectPostCommitMode::SpoolOnly,
            DirectPostCommitMode::Rejected,
        ] {
            let port = Port::new(&[DirectPostCommitMode::Live, mode]);
            let targets = [target("alice@example.test/gone", true)];
            let mut request = request(delivery);
            request.approved_targets = &targets;
            let outcome = DirectMessageRouter::route_federated(&port, request, false)
                .await
                .unwrap();
            assert_eq!(
                outcome,
                if delivery.durable().is_some() {
                    recovery(DirectRouteStage::PrimaryRemote)
                } else {
                    DirectRouteOutcome::AcceptedBeforeDegradation
                }
            );
            assert_eq!(
                port.events(),
                [
                    "health:Live".to_owned(),
                    "enqueue".into(),
                    "accepted".into(),
                    format!("health:{mode:?}")
                ]
            );
            assert!(port.rearmed.lock().unwrap().is_empty());
            assert_eq!(
                *port.accepted_kinds.lock().unwrap(),
                [delivery.durable().is_some()]
            );
        }
    }
}

#[tokio::test]
async fn federation_headline_health_checkpoint_suppresses_remote_fanout_after_local_acceptance() {
    for mode in [
        DirectPostCommitMode::SpoolOnly,
        DirectPostCommitMode::Rejected,
    ] {
        let degraded_health = format!("health:{mode:?}");

        let port = Port::new(&[DirectPostCommitMode::Live, mode]);
        let targets = [
            target("alice@example.test/phone", true),
            target("alice@example.test/tablet", true),
        ];
        let mut request = request(DirectRouteDelivery::Volatile);
        request.message_type = "headline";
        request.target = DirectRouteTarget::Bare("alice@example.test");
        request.approved_targets = &targets;
        let outcome = DirectMessageRouter::route_federated(&port, request, false)
            .await
            .unwrap();
        assert_eq!(outcome, DirectRouteOutcome::AcceptedBeforeDegradation);
        assert_eq!(
            port.events(),
            [
                "health:Live",
                "enqueue",
                "accepted",
                "enqueue",
                "accepted",
                degraded_health.as_str()
            ]
        );
        assert_eq!(*port.accepted_kinds.lock().unwrap(), [false, false]);
    }
}

#[tokio::test]
async fn federation_remote_acceptance_before_final_degradation_never_rearms() {
    for mode in [
        DirectPostCommitMode::SpoolOnly,
        DirectPostCommitMode::Rejected,
    ] {
        let degraded_health = format!("health:{mode:?}");

        for delivery in delivery_cases() {
            for fallback in [false, true] {
                let mut modes = vec![DirectPostCommitMode::Live; if fallback { 5 } else { 2 }];
                modes.push(mode);
                let port = Port {
                    remote_accepts_for: Some(if fallback {
                        "alice@example.test"
                    } else {
                        "alice@example.test/gone"
                    }),
                    ..Port::new(&modes)
                };
                let outcome = DirectMessageRouter::route_federated(&port, request(delivery), false)
                    .await
                    .unwrap();
                assert_eq!(
                    outcome,
                    if delivery.durable().is_some() {
                        recovery(DirectRouteStage::AfterRouting)
                    } else {
                        DirectRouteOutcome::AcceptedBeforeDegradation
                    }
                );
                assert_eq!(
                    port.events(),
                    if fallback {
                        vec![
                            "health:Live",
                            "health:Live",
                            "remote:alice@example.test/gone",
                            "health:Live",
                            "fallback:snapshot",
                            "health:Live",
                            "health:Live",
                            "remote:alice@example.test",
                            degraded_health.as_str(),
                        ]
                    } else {
                        vec![
                            "health:Live",
                            "health:Live",
                            "remote:alice@example.test/gone",
                            degraded_health.as_str(),
                        ]
                    }
                );
                assert!(port.rearmed.lock().unwrap().is_empty());
                assert!(port.accepted_kinds.lock().unwrap().is_empty());
            }
        }
    }
}

#[tokio::test]
async fn federation_unrouted_returns_to_offline_policy_without_an_extra_health_read() {
    for message_type in ["chat", "headline"] {
        for delivery in delivery_cases() {
            if message_type == "headline" && delivery.durable().is_some() {
                continue;
            }
            let port = Port::new(&[
                DirectPostCommitMode::Live,
                DirectPostCommitMode::Live,
                DirectPostCommitMode::Rejected,
            ]);
            let mut request = request(delivery);
            request.message_type = message_type;
            request.target = DirectRouteTarget::Bare("alice@example.test");
            let outcome = DirectMessageRouter::route_federated(&port, request, false)
                .await
                .unwrap();
            assert_eq!(outcome, DirectRouteOutcome::Unrouted);
            let mut expected = vec![
                "health:Live",
                "health:Live",
                if message_type == "headline" {
                    "remote:all"
                } else {
                    "remote:alice@example.test"
                },
            ];
            if delivery.durable().is_some() {
                expected.push("rearm");
            }
            assert_eq!(port.events(), expected);
            assert_eq!(
                port.modes.lock().unwrap().front(),
                Some(&DirectPostCommitMode::Rejected)
            );
            assert_eq!(
                port.rearmed.lock().unwrap().len(),
                usize::from(delivery.durable().is_some())
            );
        }
    }
}

#[tokio::test]
async fn federation_full_jid_mismatch_preserves_drop_rejection_and_durable_recovery() {
    for delivery in delivery_cases() {
        for message_type in ["normal", "error"] {
            let port = Port::new(&[]);
            let mut request = request(delivery);
            request.message_type = message_type;
            let outcome = DirectMessageRouter::route_federated(&port, request, false)
                .await
                .unwrap();
            let expected = match (message_type, delivery.durable().is_some()) {
                ("error", _) => DirectRouteOutcome::Dropped,
                (_, true) => DirectRouteOutcome::Unrouted,
                (_, false) => {
                    DirectRouteOutcome::Rejected(DirectRouteRejection::NoMatchingResource)
                }
            };
            assert_eq!(outcome, expected);
            let mut events = vec![
                "health:Live",
                "health:Live",
                "remote:alice@example.test/gone",
                "health:Live",
            ];
            if message_type == "normal" && delivery.durable().is_some() {
                events.push("post_accept_failure");
            }
            if delivery.durable().is_some() {
                events.push("rearm");
            }
            assert_eq!(port.events(), events);
            assert_eq!(
                port.rearmed.lock().unwrap().len(),
                usize::from(delivery.durable().is_some())
            );
        }
    }
}

#[tokio::test]
async fn federation_invalid_fence_never_reads_health_or_rearms_a_foreign_claim() {
    for claim_id in [None, Some(Uuid::from_u128(99))] {
        let port = Port::new(&[]);
        let delivery = DirectRouteDelivery::Committed(DurableDelivery {
            claim_id,
            ..committed()
        });
        let outcome = DirectMessageRouter::route_federated(&port, request(delivery), true)
            .await
            .unwrap();
        assert_eq!(
            outcome,
            DirectRouteOutcome::AcceptedForRecovery {
                stage: DirectRouteStage::LiveReservation,
                reason: DirectRouteRecoveryReason::MissingLiveReservation
            }
        );
        assert_eq!(port.events(), ["post_accept_failure"]);
        assert!(port.route_calls().is_empty());
        assert!(port.rearmed.lock().unwrap().is_empty());
    }
}

#[tokio::test]
async fn federation_fallback_privacy_error_is_fail_closed_only_after_durable_admission() {
    for delivery in delivery_cases() {
        let port = Port {
            fallback: vec![(
                "alice@example.test/phone".into(),
                Target {
                    jid: "alice@example.test/phone",
                    accepts: true,
                    privacy_error: true,
                },
            )],
            ..Port::new(&[])
        };
        let result = DirectMessageRouter::route_federated(&port, request(delivery), false).await;
        let mut events = vec![
            "health:Live",
            "health:Live",
            "remote:alice@example.test/gone",
            "health:Live",
            "fallback:snapshot",
            "fallback:privacy",
        ];
        if delivery.durable().is_some() {
            assert_eq!(result.unwrap(), DirectRouteOutcome::Unrouted);
            events.extend([
                "post_accept_failure",
                "health:Live",
                "health:Live",
                "remote:alice@example.test",
                "rearm",
            ]);
            assert_eq!(*port.rearmed.lock().unwrap(), [committed()]);
        } else {
            assert_eq!(result.unwrap_err().stage, DirectRouteStage::FullJidFallback);
            assert!(port.rearmed.lock().unwrap().is_empty());
        }
        assert_eq!(port.events(), events);
        assert!(port.accepted_kinds.lock().unwrap().is_empty());
        assert_eq!(
            *port.privacy_calls.lock().unwrap(),
            [(
                "alice@example.test/phone".into(),
                "bob@example.test/phone".into()
            )]
        );
    }
}

#[tokio::test]
async fn federation_fallback_privacy_finishes_before_enqueue_and_preserves_order() {
    let port = Port {
        fallback: vec![
            target("alice@example.test/low", true),
            target("alice@example.test/z", true),
            target("alice@example.test/denied", true),
            target("alice@example.test/a", false),
            target("alice@example.test/unavailable", true),
        ],
        fallback_denied: vec!["alice@example.test/denied"],
        priorities: BTreeMap::from([
            ("alice@example.test/unavailable", -1),
            ("alice@example.test/low", 0),
            ("alice@example.test/denied", 2),
        ]),
        ..Port::new(&[])
    };
    let delivery = DirectRouteDelivery::Committed(committed());
    let mut request = request(delivery);
    request.stanza = EXACT_STANZA;
    let outcome = DirectMessageRouter::route_federated(&port, request, true)
        .await
        .unwrap();
    assert_eq!(
        outcome,
        DirectRouteOutcome::Routed {
            accepted_full_jid: Some("alice@example.test/z".into())
        }
    );
    assert_eq!(
        port.events(),
        [
            "health:Live",
            "health:Live",
            "remote:alice@example.test/gone",
            "health:Live",
            "fallback:snapshot",
            "fallback:privacy",
            "fallback:privacy",
            "fallback:privacy",
            "fallback:privacy",
            "health:Live",
            "enqueue",
            "enqueue",
            "accepted",
            "health:Live"
        ]
    );
    assert_eq!(
        port.privacy_calls
            .lock()
            .unwrap()
            .iter()
            .map(|(jid, _)| jid.as_str())
            .collect::<Vec<_>>(),
        [
            "alice@example.test/denied",
            "alice@example.test/a",
            "alice@example.test/z",
            "alice@example.test/low"
        ]
    );
    assert_eq!(
        port.route_calls(),
        [
            expected_route(
                RouteDestination::PrimaryRemote("alice@example.test/gone".into()),
                delivery
            ),
            expected_route(RouteDestination::Local("alice@example.test/a"), delivery),
            expected_route(RouteDestination::Local("alice@example.test/z"), delivery)
        ]
    );
    assert_eq!(*port.accepted_kinds.lock().unwrap(), [true]);
    assert!(port.rearmed.lock().unwrap().is_empty());
}

#[tokio::test]
async fn federation_standalone_unrouted_delivery_has_no_claim_to_rearm() {
    let port = Port {
        clustered: false,
        ..Port::new(&[])
    };
    let delivery = DirectRouteDelivery::Committed(DurableDelivery {
        claim_id: None,
        ..committed()
    });
    let mut request = request(delivery);
    request.target = DirectRouteTarget::Bare("alice@example.test");
    request.stanza = EXACT_STANZA;
    assert_eq!(
        DirectMessageRouter::route_federated(&port, request, false)
            .await
            .unwrap(),
        DirectRouteOutcome::Unrouted
    );
    assert_eq!(
        port.events(),
        ["health:Live", "health:Live", "remote:alice@example.test"]
    );
    assert_eq!(
        port.route_calls(),
        [expected_route(
            RouteDestination::PrimaryRemote("alice@example.test".into()),
            delivery
        )]
    );
    assert!(port.rearmed.lock().unwrap().is_empty());
}

#[tokio::test]
async fn federation_fallback_local_acceptance_before_degradation_never_rearms() {
    for mode in [
        DirectPostCommitMode::SpoolOnly,
        DirectPostCommitMode::Rejected,
    ] {
        let degraded_health = format!("health:{mode:?}");

        for delivery in delivery_cases() {
            let port = Port {
                fallback: vec![target("alice@example.test/phone", true)],
                ..Port::new(&[
                    DirectPostCommitMode::Live,
                    DirectPostCommitMode::Live,
                    DirectPostCommitMode::Live,
                    DirectPostCommitMode::Live,
                    mode,
                ])
            };
            let outcome = DirectMessageRouter::route_federated(&port, request(delivery), true)
                .await
                .unwrap();
            assert_eq!(
                outcome,
                if delivery.durable().is_some() {
                    recovery(DirectRouteStage::AfterRouting)
                } else {
                    DirectRouteOutcome::AcceptedBeforeDegradation
                }
            );
            assert_eq!(
                port.events(),
                [
                    "health:Live",
                    "health:Live",
                    "remote:alice@example.test/gone",
                    "health:Live",
                    "fallback:snapshot",
                    "fallback:privacy",
                    "health:Live",
                    "enqueue",
                    "accepted",
                    degraded_health.as_str(),
                ]
            );
            assert_eq!(
                *port.accepted_kinds.lock().unwrap(),
                [delivery.durable().is_some()]
            );
            assert!(port.rearmed.lock().unwrap().is_empty());
        }
    }
}

#[tokio::test]
async fn federation_headline_fanout_preserves_first_local_key_and_volatile_envelopes() {
    let port = Port {
        remote_accepts: true,
        ..Port::new(&[])
    };
    let targets = [
        target("alice@example.test/phone", true),
        target("alice@example.test/tablet", true),
    ];
    let delivery = DirectRouteDelivery::Volatile;
    let mut request = request(delivery);
    request.message_type = "headline";
    request.target = DirectRouteTarget::Bare("alice@example.test");
    request.approved_targets = &targets;
    request.stanza = EXACT_STANZA;
    let outcome = DirectMessageRouter::route_federated(&port, request, false)
        .await
        .unwrap();
    assert_eq!(
        outcome,
        DirectRouteOutcome::Routed {
            accepted_full_jid: Some("alice@example.test/phone".into())
        }
    );
    assert_eq!(
        port.events(),
        [
            "health:Live",
            "enqueue",
            "accepted",
            "enqueue",
            "accepted",
            "health:Live",
            "remote:all",
            "health:Live"
        ]
    );
    assert_eq!(
        port.route_calls(),
        [
            expected_route(
                RouteDestination::Local("alice@example.test/phone"),
                delivery
            ),
            expected_route(
                RouteDestination::Local("alice@example.test/tablet"),
                delivery
            ),
            expected_route(
                RouteDestination::AvailableRemote("alice@example.test".into()),
                delivery
            )
        ]
    );
    assert_eq!(*port.accepted_kinds.lock().unwrap(), [false, false]);
    assert!(port.rearmed.lock().unwrap().is_empty());
}

#[tokio::test]
async fn federation_correlated_remote_receipt_preserves_exact_carbon_exclusion_key() {
    for delivery in delivery_cases() {
        for fallback in [false, true] {
            let accepted_full_jid = if fallback {
                "alice@example.test/fallback-resource"
            } else {
                "alice@example.test/gone"
            };
            let port = Port {
                remote_accepts_for: Some(if fallback {
                    "alice@example.test"
                } else {
                    "alice@example.test/gone"
                }),
                remote_accepted_full_jid: Some(accepted_full_jid),
                ..Port::new(&[])
            };
            let mut request = request(delivery);
            request.stanza = EXACT_STANZA;
            let outcome = DirectMessageRouter::route_federated(&port, request, false)
                .await
                .unwrap();
            assert_eq!(
                outcome,
                DirectRouteOutcome::Routed {
                    accepted_full_jid: Some(accepted_full_jid.to_owned())
                }
            );
            let mut destinations = vec![RouteDestination::PrimaryRemote(
                "alice@example.test/gone".into(),
            )];
            if fallback {
                destinations.push(RouteDestination::PrimaryRemote("alice@example.test".into()));
            }
            assert_eq!(
                port.route_calls(),
                destinations
                    .into_iter()
                    .map(|destination| expected_route(destination, delivery))
                    .collect::<Vec<_>>()
            );
            assert_eq!(
                port.events(),
                if fallback {
                    vec![
                        "health:Live",
                        "health:Live",
                        "remote:alice@example.test/gone",
                        "health:Live",
                        "fallback:snapshot",
                        "health:Live",
                        "health:Live",
                        "remote:alice@example.test",
                        "health:Live",
                    ]
                } else {
                    vec![
                        "health:Live",
                        "health:Live",
                        "remote:alice@example.test/gone",
                        "health:Live",
                    ]
                }
            );
            assert!(port.rearmed.lock().unwrap().is_empty());
            assert!(port.accepted_kinds.lock().unwrap().is_empty());
        }
    }
}
