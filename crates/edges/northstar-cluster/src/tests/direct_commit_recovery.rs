use super::*;

#[tokio::test]
async fn direct_commit_turn_defers_failure_publication_and_freezes_new_work() {
    let manager = listener_health_manager();
    manager.note_listener_generation();
    let admission = manager.admission();
    let (turn, authority) = admission
        .begin_direct_commit_turn(DirectSpoolEligibility::Eligible)
        .unwrap();
    assert!(authority.is_some());

    std::thread::scope(|scope| {
        let (sent, received) = std::sync::mpsc::channel();
        let manager = &manager;
        scope.spawn(move || {
            manager.record_listener_failure(&anyhow::anyhow!("Redis failed during COMMIT"));
            sent.send(()).unwrap();
        });
        received
            .recv_timeout(Duration::from_secs(1))
            .expect("synchronous failure reporter waited for direct COMMIT");
    });
    assert_eq!(
        manager.health.state.load(Ordering::Acquire),
        CLUSTER_HEALTHY
    );
    assert!(manager.health.transition_pending());
    assert!(manager.readiness_error().is_some());
    assert!(manager.admit(ClusterOperation::DurableDirect).is_err());
    assert!(admission
        .begin_direct_commit_turn(DirectSpoolEligibility::Eligible)
        .is_err());
    assert_eq!(turn.finish(), DirectPostCommitMode::SpoolOnly);
    assert_eq!(
        manager.health.state.load(Ordering::Acquire),
        CLUSTER_FAIL_CLOSED
    );
    assert!(!manager.health.transition_pending());
}

#[tokio::test]
async fn direct_commit_gate_waits_for_all_turns_and_shutdown_is_absorbing() {
    let manager = listener_health_manager();
    manager.note_listener_generation();
    let admission = manager.admission();
    let (first, _) = admission
        .begin_direct_commit_turn(DirectSpoolEligibility::Eligible)
        .unwrap();
    let (second, _) = admission
        .begin_direct_commit_turn(DirectSpoolEligibility::Eligible)
        .unwrap();
    manager.record_listener_failure(&anyhow::anyhow!("Redis unavailable"));
    manager.require_shutdown();
    manager.record_listener_failure(&anyhow::anyhow!("late Redis failure"));
    assert_eq!(first.finish(), DirectPostCommitMode::SpoolOnly);
    assert_eq!(
        manager.health.state.load(Ordering::Acquire),
        CLUSTER_HEALTHY
    );
    assert!(manager.begin_reconciliation().is_err());
    assert_eq!(second.finish(), DirectPostCommitMode::SpoolOnly);
    assert_eq!(
        manager.health.state.load(Ordering::Acquire),
        CLUSTER_SHUTDOWN_REQUIRED
    );
    assert!(manager.admit(ClusterOperation::DurableDirect).is_err());
}

#[tokio::test]
async fn cancelled_direct_commit_turn_releases_pending_shutdown() {
    let manager = listener_health_manager();
    manager.note_listener_generation();
    let (turn, _) = manager
        .admission()
        .begin_direct_commit_turn(DirectSpoolEligibility::Eligible)
        .unwrap();
    manager.require_shutdown();
    assert!(manager.health.transition_pending());
    drop(turn);
    assert_eq!(
        manager.health.state.load(Ordering::Acquire),
        CLUSTER_SHUTDOWN_REQUIRED
    );
}

#[test]
fn disabled_cluster_direct_commit_stays_live_without_authority() {
    let cluster = ClusterHealth::disabled();
    let admission = ClusterAdmission {
        health: Arc::new(cluster),
        direct_authority: None,
    };
    let (turn, authority) = admission
        .begin_direct_commit_turn(DirectSpoolEligibility::LiveOnly)
        .unwrap();
    assert!(authority.is_none());
    assert_eq!(turn.finish(), DirectPostCommitMode::Live);
    assert_eq!(admission.direct_mode(), DirectPostCommitMode::Live);
}

#[tokio::test]
async fn recovery_defers_while_spooled_direct_commit_is_active() {
    use northstar_security::cluster_bus::ClusterFailurePolicy::DurableDirectOnly;
    let manager = listener_health_manager();
    manager.note_listener_generation();
    record_cluster_failure(
        &manager.health,
        &manager.listener_rotation,
        true,
        Some(DurableDirectOnly),
        ClusterFailureClass::RedisCommand,
        &anyhow::anyhow!("Redis unavailable"),
    );
    let admission = manager.admission();
    let (turn, _) = admission
        .begin_direct_commit_turn(DirectSpoolEligibility::Eligible)
        .unwrap();
    assert!(begin_cluster_reconciliation(&manager.health, true)
        .unwrap()
        .is_none());
    assert!(manager.health.transition_pending());
    assert!(manager.readiness_error().is_some());
    assert_eq!(turn.finish(), DirectPostCommitMode::SpoolOnly);
    assert_eq!(
        manager.health.state.load(Ordering::Acquire),
        CLUSTER_RECONCILING
    );
    assert!(begin_cluster_reconciliation(&manager.health, true)
        .unwrap()
        .is_some());
}

#[tokio::test]
async fn failure_overrides_queued_reconciliation_before_direct_commit_finishes() {
    use northstar_security::cluster_bus::ClusterFailurePolicy::DurableDirectOnly;
    let manager = listener_health_manager();
    manager.note_listener_generation();
    record_cluster_failure(
        &manager.health,
        &manager.listener_rotation,
        true,
        Some(DurableDirectOnly),
        ClusterFailureClass::RedisCommand,
        &anyhow::anyhow!("first Redis failure"),
    );
    let (turn, _) = manager
        .admission()
        .begin_direct_commit_turn(DirectSpoolEligibility::Eligible)
        .unwrap();
    assert!(begin_cluster_reconciliation(&manager.health, true)
        .unwrap()
        .is_none());
    record_cluster_failure(
        &manager.health,
        &manager.listener_rotation,
        true,
        Some(DurableDirectOnly),
        ClusterFailureClass::RedisCommand,
        &anyhow::anyhow!("Redis failed during reconciliation"),
    );
    assert_eq!(turn.finish(), DirectPostCommitMode::SpoolOnly);
    assert_eq!(
        manager.health.state.load(Ordering::Acquire),
        CLUSTER_DURABLE_DIRECT_ONLY
    );
}

#[test]
fn recovery_plan_advances_past_busy_first_page_and_rescans_only_when_incomplete() {
    use crate::recovery_replay_wake::RecoveryReplayStatus;

    let routes = (0..300_u128)
        .map(|index| {
            (
                format!("user-{index:03}@example.test/Phone"),
                uuid::Uuid::from_u128(index + 1),
            )
        })
        .collect::<Vec<_>>();
    let mut plan = RecoveryReplayPlan::new(7, 1);
    plan.queue_page(routes[..256].to_vec());
    assert_eq!(plan.pending.len(), 256);
    assert_eq!(plan.cursor.as_deref(), Some(routes[255].0.as_str()));

    let mut first = plan.pending.pop_front().unwrap();
    let mut scheduled = 0;
    assert_eq!(
        recovery_route_progress(
            &mut first,
            RecoveryReplayStatus::Retryable,
            Instant::now(),
            || scheduled += 1,
        ),
        RecoveryRouteProgress::Pending
    );
    assert_eq!(scheduled, 1);
    first.observations = RECOVERY_REPLAY_OBSERVATIONS_PER_SWEEP - 1;
    assert_eq!(
        recovery_route_progress(
            &mut first,
            RecoveryReplayStatus::Retryable,
            Instant::now(),
            || scheduled += 1,
        ),
        RecoveryRouteProgress::DeferredToNextSweep
    );
    assert_eq!(
        scheduled, 1,
        "busy route was not scheduled again at its cap"
    );
    let mut awaiting_eligibility = RecoveryReplayRoute {
        full_jid: "bind2@example.test/Phone".into(),
        connection_id: uuid::Uuid::new_v4(),
        attempts: 0,
        observations: 0,
        retry_after: Instant::now(),
    };
    assert_eq!(
        recovery_route_progress(
            &mut awaiting_eligibility,
            RecoveryReplayStatus::AwaitEligibility,
            Instant::now(),
            || panic!("ineligible Bind2 route must not schedule"),
        ),
        RecoveryRouteProgress::DeferredToNextSweep
    );
    assert_eq!(awaiting_eligibility.observations, 0);
    plan.incomplete = true;
    while let Some(mut route) = plan.pending.pop_front() {
        assert_eq!(
            recovery_route_progress(
                &mut route,
                RecoveryReplayStatus::Complete,
                Instant::now(),
                || panic!("completed route must not schedule"),
            ),
            RecoveryRouteProgress::Done
        );
    }
    plan.queue_page(routes[256..].to_vec());
    assert_eq!(plan.pending.len(), 44);
    assert_eq!(plan.cursor.as_deref(), Some(routes[299].0.as_str()));
    plan.pending.clear();
    plan.queue_page(Vec::new());
    assert!(plan.exhausted && plan.incomplete);
    plan.begin_next_sweep(2);
    assert_eq!(plan.wake_epoch, 2);
    assert!(plan.cursor.is_none() && plan.pending.is_empty());
    assert!(!plan.exhausted && !plan.incomplete);
}

#[test]
fn admission_capability_observes_shared_health_transitions() {
    let namespace = "admission-capability.test";
    let (_, security) = northstar_security::cluster_bus::test_configuration_pair(namespace);
    let manager = verification_manager(namespace, security);
    let admission = manager.admission();
    for state in [
        CLUSTER_DISABLED,
        CLUSTER_HEALTHY,
        CLUSTER_RECONCILING,
        CLUSTER_DURABLE_DIRECT_ONLY,
        CLUSTER_FAIL_CLOSED,
        CLUSTER_SHUTDOWN_REQUIRED,
    ] {
        manager.health.state.store(state, Ordering::Release);
        for operation in [
            ClusterOperation::AdminMutation,
            ClusterOperation::DurableDirect,
        ] {
            assert_eq!(
                admission
                    .admit(operation)
                    .map_err(|error| error.to_string()),
                manager.admit(operation).map_err(|error| error.to_string()),
            );
        }
    }
}

#[test]
fn cluster_failure_policy_static_matrix_is_fail_closed_by_class() {
    let operations = [
        ClusterOperation::NewBinding,
        ClusterOperation::Resume,
        ClusterOperation::MucMutation,
        ClusterOperation::AdminMutation,
        ClusterOperation::VolatileDelivery,
        ClusterOperation::DurableDirect,
    ];
    for operation in operations {
        assert!(operation_allowed(CLUSTER_HEALTHY, operation));
        assert!(!operation_allowed(CLUSTER_FAIL_CLOSED, operation));
        assert!(!operation_allowed(CLUSTER_RECONCILING, operation));
        assert!(!operation_allowed(CLUSTER_SHUTDOWN_REQUIRED, operation));
        assert_eq!(
            operation_allowed(CLUSTER_DURABLE_DIRECT_ONLY, operation),
            operation == ClusterOperation::DurableDirect
        );
    }
    use northstar_security::cluster_bus::ClusterFailurePolicy::DurableDirectOnly;
    use northstar_security::cluster_bus::ClusterFailurePolicy::FailClosed;
    assert!(!degraded_shutdown_required(FailClosed, true, false));
    assert!(degraded_shutdown_required(FailClosed, true, true));
    assert!(!degraded_shutdown_required(DurableDirectOnly, true, true));
    assert!(degraded_shutdown_required(DurableDirectOnly, false, false));
    assert!(degraded_shutdown_required(FailClosed, false, false));
}
