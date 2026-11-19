use super::*;

#[test]
fn metrics_probe_reads_live_health_without_cluster_control_authority() {
    let health = Arc::new(ClusterHealth::disabled());
    let probe = ClusterMetricsProbe {
        health: Arc::clone(&health),
    };
    assert_eq!(probe.snapshot().listener_generation, 0);
    health.listener_generation.store(7, Ordering::Relaxed);
    health.authentication_failures.store(3, Ordering::Relaxed);
    let snapshot = probe.snapshot();
    assert_eq!(snapshot.listener_generation, 7);
    assert_eq!(snapshot.authentication_failures, 3);
}

#[tokio::test]
async fn readiness_authority_is_absent_without_cluster_security() {
    let cluster = ClusterManager::new(None, "example.test", None, None, None, None)
        .await
        .unwrap();
    assert!(cluster.readiness_authority_snapshot().is_none());
    let probe = cluster.readiness_probe();
    assert!(probe.authority_snapshot().is_none());
    assert_eq!(probe.readiness_error(), cluster.readiness_error());
    cluster
        .health
        .peer_versions_compatible
        .store(false, Ordering::Release);
    assert_eq!(probe.readiness_error(), cluster.readiness_error());
    assert!(probe.readiness_error().is_some());
}

#[test]
fn readiness_probe_keeps_configured_identity_and_reads_current_epoch() {
    let epoch = Arc::new(AtomicI64::new(7));
    let probe = ClusterReadinessProbe {
        health: Arc::new(ClusterHealth::disabled()),
        authority: Some(ClusterReadinessAuthority {
            key_identity: northstar_security::cluster_keys::ClusterKeyDeploymentIdentity {
                xmpp_domain: "example.test".into(),
                node_id: "node-a".into(),
                epoch: 3,
                current_key_id: "key-a".into(),
                current_public_key_sha256: "digest-a".into(),
                previous_key_id: None,
                previous_public_key_sha256: None,
                staged_next_key_id: None,
                staged_next_public_key_sha256: None,
            },
            instance_node_id: "node-a".into(),
            instance_uuid: uuid::Uuid::from_u128(9),
            instance_epoch: 0,
            signing_key_id: "key-a".into(),
            signing_key_epoch: 3,
        }),
        instance_epoch: Arc::clone(&epoch),
    };
    let first = probe.authority_snapshot().unwrap();
    assert_eq!(first.instance_epoch, 7);
    epoch.store(8, Ordering::Release);
    let second = probe.authority_snapshot().unwrap();
    assert_eq!(second.instance_epoch, 8);
    assert_eq!(first.key_identity, second.key_identity);
    assert_eq!(first.instance_uuid, second.instance_uuid);
    assert_eq!(first.signing_key_id, second.signing_key_id);
}

#[tokio::test]
async fn session_termination_identity_reads_epoch_after_projection() {
    let cluster = ClusterManager::new(None, "example.test", None, None, None, None)
        .await
        .unwrap();
    let identity = cluster.session_termination_identity();
    cluster.instance_epoch.store(17, Ordering::Release);
    assert_eq!(identity.local_instance().instance_epoch, 17);
    cluster.instance_epoch.store(18, Ordering::Release);
    assert_eq!(identity.local_instance().instance_epoch, 18);
    assert_eq!(identity.namespace(), cluster.namespace);
}

#[tokio::test]
async fn account_revocation_identity_snapshots_instance_epoch() {
    let cluster = ClusterManager::new(None, "example.test", None, None, None, None)
        .await
        .unwrap();
    let authority = cluster.account_revocation_authority();
    cluster.instance_epoch.store(17, Ordering::Release);
    let identity = authority.identity();
    cluster.instance_epoch.store(18, Ordering::Release);

    assert_eq!(identity.domain, "example.test");
    assert_eq!(identity.node_id, cluster.node_id);
    assert_eq!(identity.instance_uuid, cluster.connection_uuid);
    assert_eq!(identity.instance_epoch, 17);
    assert_eq!(authority.identity().instance_epoch, 18);
}

#[tokio::test]
async fn revocation_authority_failure_requires_immediate_shutdown() {
    let cluster = ClusterManager::new(None, "example.test", None, None, None, None)
        .await
        .unwrap();
    cluster
        .health
        .state
        .store(CLUSTER_HEALTHY, Ordering::Release);
    let mut authority = cluster.account_revocation_authority();
    // A loopback-free fixture has no Redis pool; exercise the enabled
    // branch against the same health and listener-rotation cells.
    authority.enabled = true;
    authority.record_failure(&anyhow::anyhow!("authority unavailable"));
    assert_eq!(
        cluster.health.state.load(Ordering::Acquire),
        CLUSTER_SHUTDOWN_REQUIRED
    );
    assert_eq!(
        cluster.health.degraded_transitions.load(Ordering::Relaxed),
        1
    );
    assert_eq!(
        cluster
            .health
            .required_listener_generation
            .load(Ordering::Acquire),
        1
    );
    assert_eq!(
        cluster
            .health
            .listener_rotation_epoch
            .load(Ordering::Acquire),
        1
    );
    assert!(cluster.health.failure_since.lock().unwrap().is_some());
    assert!(cluster.admit(ClusterOperation::DurableDirect).is_err());
}

#[tokio::test]
async fn postgres_authority_failure_is_terminal_from_healthy_and_degraded_under_both_policies() {
    use northstar_security::cluster_bus::ClusterFailurePolicy::DurableDirectOnly;
    use northstar_security::cluster_bus::ClusterFailurePolicy::FailClosed;

    for policy in [FailClosed, DurableDirectOnly] {
        for already_degraded in [false, true] {
            let manager = listener_health_manager();
            manager.note_listener_generation();
            if already_degraded {
                record_cluster_failure(
                    &manager.health,
                    &manager.listener_rotation,
                    true,
                    Some(policy),
                    ClusterFailureClass::RedisCommand,
                    &anyhow::anyhow!("Redis unavailable"),
                );
                assert_eq!(
                    manager.health.state.load(Ordering::Acquire),
                    match policy {
                        FailClosed => CLUSTER_FAIL_CLOSED,
                        DurableDirectOnly => CLUSTER_DURABLE_DIRECT_ONLY,
                    }
                );
            }

            let previous_epoch = manager
                .health
                .listener_rotation_epoch
                .load(Ordering::Acquire);
            let previous_transitions = manager.health.degraded_transitions.load(Ordering::Acquire);
            let previous_failure_since = *manager.health.failure_since.lock().unwrap();
            let rotation = manager.listener_rotation.notified();
            tokio::pin!(rotation);
            rotation.as_mut().enable();

            record_cluster_failure(
                &manager.health,
                &manager.listener_rotation,
                true,
                Some(policy),
                ClusterFailureClass::PostgreSqlAuthority,
                &anyhow::anyhow!("PostgreSQL authority unavailable"),
            );
            tokio::time::timeout(Duration::from_millis(100), &mut rotation)
                .await
                .expect("authority failure did not rotate the listener");
            assert_eq!(
                manager.health.state.load(Ordering::Acquire),
                CLUSTER_SHUTDOWN_REQUIRED
            );
            assert_eq!(
                manager.health.degraded_transitions.load(Ordering::Acquire),
                previous_transitions + 1
            );
            assert_eq!(
                manager
                    .health
                    .listener_rotation_epoch
                    .load(Ordering::Acquire),
                previous_epoch + 1
            );
            assert_eq!(
                manager
                    .health
                    .required_listener_generation
                    .load(Ordering::Acquire),
                manager.health.listener_generation.load(Ordering::Acquire) + 1
            );
            let failure_since = *manager.health.failure_since.lock().unwrap();
            assert!(failure_since.is_some());
            if already_degraded {
                assert_eq!(failure_since, previous_failure_since);
            }
            assert!(manager.admit(ClusterOperation::DurableDirect).is_err());
            assert!(manager.begin_reconciliation().is_err());
            assert!(manager.complete_reconciliation(previous_epoch).is_err());
            let (candidate, epoch) = manager.health.begin_listener_attempt();
            assert!(manager
                .confirm_listener_generation(candidate, epoch)
                .is_err());

            record_cluster_failure(
                &manager.health,
                &manager.listener_rotation,
                true,
                Some(policy),
                ClusterFailureClass::RedisCommand,
                &anyhow::anyhow!("late Redis error"),
            );
            assert_eq!(
                manager.health.state.load(Ordering::Acquire),
                CLUSTER_SHUTDOWN_REQUIRED
            );
            assert_eq!(
                manager.health.degraded_transitions.load(Ordering::Acquire),
                previous_transitions + 1
            );
            assert_eq!(
                manager
                    .health
                    .listener_rotation_epoch
                    .load(Ordering::Acquire),
                previous_epoch + 1
            );
        }
    }
}

#[tokio::test]
async fn muc_projection_identity_conflict_preserves_healthy_listener() {
    let manager = listener_health_manager();
    manager.complete_reconciliation(0).unwrap();
    manager.note_listener_generation();
    assert!(manager.readiness_error().is_none());
    let generation = manager.health.listener_generation.load(Ordering::Acquire);
    let control = manager.maintenance_control();

    // A snapshot renewed in PostgreSQL can race a kick and same-nick rejoin.
    // Redis refusing that different exact identity must still be reported as
    // an unsuccessful projection, without rotating the healthy subscription.
    let error = control.record_muc_projection_failure(
        northstar_room_application::muc_service::MucSoftStateDegradation::IdentityRejected,
    );
    assert!(error
        .downcast_ref::<northstar_room_application::muc_service::MucSoftStateDegradation>()
        .is_some());
    assert!(manager.readiness_error().is_none());
    assert!(!manager.health.listener_requires_rotation(generation));
    manager.admit(ClusterOperation::MucMutation).unwrap();
}

#[tokio::test]
async fn muc_projection_command_errors_still_fence_the_control_plane() {
    use northstar_room_application::muc_service::MucSoftStateDegradation;
    for error in [
        MucSoftStateDegradation::Join(anyhow::anyhow!("join outage")),
        MucSoftStateDegradation::Refresh(anyhow::anyhow!("refresh outage")),
        MucSoftStateDegradation::Reconcile(anyhow::anyhow!("reconcile outage")),
    ] {
        let manager = listener_health_manager();
        manager.complete_reconciliation(0).unwrap();
        manager.note_listener_generation();
        assert!(manager.readiness_error().is_none());
        let generation = manager.health.listener_generation.load(Ordering::Acquire);
        let control = manager.maintenance_control();
        control.record_muc_projection_failure(error);
        assert!(manager.readiness_error().is_some());
        assert!(manager.health.listener_requires_rotation(generation));
        assert!(manager.admit(ClusterOperation::MucMutation).is_err());
    }
}

#[tokio::test]
async fn listener_generation_requires_proof_at_startup_and_after_failure() {
    let manager = listener_health_manager();
    let initial = manager.health.next_listener_generation();
    assert_eq!(initial, 1);
    assert!(!manager.health.listener_requires_rotation(initial));
    assert_eq!(
        manager.complete_reconciliation(0).unwrap(),
        ReconciliationOutcome::WaitingForInitialListener
    );
    assert!(manager.readiness_error().is_some());

    // Only the successfully matched initial self-loop publishes this.
    manager.note_listener_generation();
    assert!(manager.readiness_error().is_none());
    manager.record_listener_failure(&anyhow::anyhow!("lost initial subscription"));
    assert!(manager.health.listener_requires_rotation(initial));
    assert!(manager.readiness_error().is_some());

    let replacement = manager.health.next_listener_generation();
    assert_eq!(replacement, initial + 1);
    assert!(!manager.health.listener_requires_rotation(replacement));
    let recovery_epoch = manager.begin_reconciliation().unwrap();
    assert!(manager.complete_reconciliation(recovery_epoch).is_err());
    manager.note_listener_generation();
    // A recovery also needs maintenance reconciliation, unlike startup.
    assert!(manager.readiness_error().is_some());
    assert_eq!(
        manager.complete_reconciliation(recovery_epoch).unwrap(),
        ReconciliationOutcome::Complete
    );
    assert!(manager.readiness_error().is_none());

    // A concurrent later failure must fence even the proven replacement.
    manager.record_listener_failure(&anyhow::anyhow!("lost replacement subscription"));
    assert!(manager.health.listener_requires_rotation(replacement));
    assert!(manager.complete_reconciliation(recovery_epoch).is_err());
    assert!(manager.readiness_error().is_some());
}

#[tokio::test]
async fn maintenance_before_initial_probe_waits_without_invalidating_the_subscription() {
    let manager = listener_health_manager();
    let (candidate, listener_epoch) = manager.health.begin_listener_attempt();
    let initial_timer = *manager.health.failure_since.lock().unwrap();
    assert!(initial_timer.is_some());
    for _ in 0..2 {
        // All maintenance I/O has succeeded, but its listener has not yet
        // received the initial self-loop. Repeating this order is benign.
        let maintenance_epoch = manager.begin_reconciliation().unwrap();
        assert_eq!(
            manager.complete_reconciliation(maintenance_epoch).unwrap(),
            ReconciliationOutcome::WaitingForInitialListener
        );
        assert!(manager.readiness_error().is_some());
        assert_eq!(
            manager.health.listener_generation.load(Ordering::Acquire),
            0
        );
        assert_eq!(
            manager
                .health
                .listener_rotation_epoch
                .load(Ordering::Acquire),
            listener_epoch
        );
        assert_eq!(
            manager.health.degraded_transitions.load(Ordering::Acquire),
            0
        );
        assert_eq!(*manager.health.failure_since.lock().unwrap(), initial_timer);
    }
    manager
        .confirm_listener_generation(candidate, listener_epoch)
        .unwrap();
    assert!(manager.readiness_error().is_none());
    assert!(manager.health.failure_since.lock().unwrap().is_none());

    // Once a real failure has happened, an unproved subscription is no
    // longer the benign initial wait even if completed/required stay 0/1.
    let failed_manager = listener_health_manager();
    failed_manager.record_listener_failure(&anyhow::anyhow!("real startup Redis failure"));
    let failure_epoch = failed_manager.begin_reconciliation().unwrap();
    assert!(failed_manager
        .complete_reconciliation(failure_epoch)
        .is_err());
    assert!(failed_manager.readiness_error().is_some());
}

#[tokio::test]
async fn listener_rotation_during_setup_is_retained_without_generation_increment() {
    let manager = listener_health_manager();
    let rotation = manager.listener_rotation.notified();
    tokio::pin!(rotation);
    rotation.as_mut().enable();
    let candidate = manager.health.next_listener_generation();
    // Both failures happen during setup, before the listener first polls.
    manager.record_listener_failure(&anyhow::anyhow!("setup authority failure"));
    manager.record_listener_failure(&anyhow::anyhow!("repeated setup failure"));
    assert_eq!(candidate, 1);
    assert!(!manager.health.listener_requires_rotation(candidate));
    assert_eq!(
        manager.health.listener_generation.load(Ordering::Acquire),
        0
    );
    tokio::time::timeout(Duration::from_millis(100), &mut rotation)
        .await
        .expect("setup lost the requested rotation because its generation was unchanged");
    assert!(manager.readiness_error().is_some());
}

#[tokio::test]
async fn listener_selected_probe_cannot_confirm_after_same_generation_failure() {
    let manager = listener_health_manager();
    let (candidate, epoch) = manager.health.begin_listener_attempt();
    // Insert the failure after stream.next selected the initial probe but
    // before confirmation. The required generation stays at one.
    manager.record_listener_failure(&anyhow::anyhow!("failure after probe selection"));
    assert!(!manager.health.listener_requires_rotation(candidate));
    assert!(manager
        .confirm_listener_generation(candidate, epoch)
        .is_err());
    assert_eq!(
        manager.health.listener_generation.load(Ordering::Acquire),
        0
    );
    assert!(manager.complete_reconciliation(epoch).is_err());

    let (replacement, replacement_epoch) = manager.health.begin_listener_attempt();
    assert_eq!(replacement, candidate);
    assert_ne!(replacement_epoch, epoch);
    manager
        .confirm_listener_generation(replacement, replacement_epoch)
        .unwrap();
    assert!(manager.readiness_error().is_some());
    let reconciliation_epoch = manager.begin_reconciliation().unwrap();
    assert_eq!(
        manager
            .complete_reconciliation(reconciliation_epoch)
            .unwrap(),
        ReconciliationOutcome::Complete
    );
    assert!(manager.readiness_error().is_none());
    assert!(manager
        .confirm_listener_generation(replacement, replacement_epoch)
        .is_err());
}

#[tokio::test]
async fn reconciliation_cannot_borrow_a_new_probe_after_an_intervening_failure() {
    let manager = listener_health_manager();
    manager.note_listener_generation();
    manager.record_listener_failure(&anyhow::anyhow!("first failure"));
    let stale_epoch = manager.begin_reconciliation().unwrap();
    manager.record_listener_failure(&anyhow::anyhow!("failure during authority refresh"));
    manager.note_listener_generation();
    assert!(manager.complete_reconciliation(stale_epoch).is_err());
    assert!(manager.readiness_error().is_some());

    let fresh_epoch = manager.begin_reconciliation().unwrap();
    assert_eq!(
        manager.complete_reconciliation(fresh_epoch).unwrap(),
        ReconciliationOutcome::Complete
    );
    assert!(manager.readiness_error().is_none());
}

#[tokio::test]
async fn shutdown_is_terminal_for_every_cluster_health_transition() {
    for shutdown in [
        ClusterManager::begin_shutdown,
        ClusterManager::require_shutdown,
    ] {
        let manager = listener_health_manager();
        manager.note_listener_generation();
        let reconciliation_epoch = manager.begin_reconciliation().unwrap();
        shutdown(&manager);
        manager.record_listener_failure(&anyhow::anyhow!("failure after shutdown"));
        assert!(manager.begin_reconciliation().is_err());
        let (candidate, epoch) = manager.health.begin_listener_attempt();
        assert!(manager
            .confirm_listener_generation(candidate, epoch)
            .is_err());
        assert!(manager
            .complete_reconciliation(reconciliation_epoch)
            .is_err());
        assert_eq!(
            manager.health.state.load(Ordering::Acquire),
            CLUSTER_SHUTDOWN_REQUIRED
        );
        assert!(manager.readiness_error().is_some());
        assert!(manager.admit(ClusterOperation::DurableDirect).is_err());
    }
}

#[tokio::test]
async fn health_transition_lock_orders_failure_after_healthy_commit() {
    let manager = listener_health_manager();
    manager.note_listener_generation();
    let epoch = manager.begin_reconciliation().unwrap();
    let mut transition = manager.health.failure_since.lock().unwrap();
    let ready = std::sync::Barrier::new(2);
    std::thread::scope(|scope| {
        let worker = scope.spawn(|| {
            ready.wait();
            manager.record_listener_failure(&anyhow::anyhow!("failure racing with commit"));
        });
        // Use the same guard and actual commit implementation as production.
        assert_eq!(
            manager
                .complete_reconciliation_locked(&mut transition, epoch)
                .unwrap(),
            ReconciliationOutcome::Complete
        );
        ready.wait();
        drop(transition);
        worker.join().unwrap();
    });
    assert_eq!(
        manager.health.state.load(Ordering::Acquire),
        CLUSTER_FAIL_CLOSED
    );
    assert!(manager.complete_reconciliation(epoch).is_err());
    assert!(manager.readiness_error().is_some());
}
