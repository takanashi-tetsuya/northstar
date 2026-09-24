use super::*;

#[test]
fn muc_disconnect_outbox_renders_status_333_on_every_attempt() {
    let target = rename_occupant(uuid::Uuid::from_u128(1), "GatewayBot");
    let mut recipient = rename_occupant(uuid::Uuid::from_u128(2), "Alice");
    recipient.full_jid = "alice@example.test/Phone".to_owned();
    let details = serde_json::json!({"status": 333});
    let first = render_cluster_muc_departure_presence(
        &target,
        &recipient,
        "operation-id",
        true,
        "leave",
        &details,
    )
    .unwrap();
    let replay = render_cluster_muc_departure_presence(
        &target,
        &recipient,
        "operation-id",
        true,
        "leave",
        &details,
    )
    .unwrap();
    assert_eq!(first, replay);
    assert!(first.contains("type='unavailable'"));
    assert!(first.contains("code='333'"));
    assert!(first.contains("id='operation-id'"));

    let voluntary = render_cluster_muc_departure_presence(
        &target,
        &recipient,
        "ordinary-leave",
        true,
        "leave",
        &serde_json::json!({}),
    )
    .unwrap();
    assert!(!voluntary.contains("code='333'"));
}

#[test]
fn muc_admin_batch_preflights_every_projection_before_delivery() {
    let room_id = uuid::Uuid::from_u128(1);
    let room_epoch = uuid::Uuid::from_u128(2);
    let target = crate::db::ClusterMucOccupancyTarget {
        room_id,
        room_epoch,
        occupant_incarnation: uuid::Uuid::from_u128(3),
        occupancy_epoch: 1,
        full_jid: "user@example.test/client".into(),
        nick: "visitor".into(),
        connection_uuid: uuid::Uuid::from_u128(4),
        connection_epoch: 1,
    };
    let snapshot = crate::db::ClusterMucPolicySnapshot {
        room_id,
        room_epoch,
        occupant_incarnation: target.occupant_incarnation,
        occupancy_epoch: target.occupancy_epoch,
        full_jid: target.full_jid.clone(),
        bare_jid: "user@example.test".into(),
        nick: target.nick.clone(),
        connection_uuid: target.connection_uuid,
        connection_epoch: target.connection_epoch,
        sm_session_id: None,
        role: "none".into(),
        affiliation: "none".into(),
        state: "revoked".into(),
    };
    let mut details = serde_json::json!({
        "non_anonymous": true,
        "request_change_count":2,
        "changes": [
            {"kind":"presence","target":target,"snapshot":snapshot,
             "status":307,"reason":"removed"},
            {"kind":"offline_affiliation","bare_jid":"other@example.test",
             "affiliation":"member","nick":null,"reason":null}
        ]
    });
    assert!(validate_cluster_muc_admin_batch_details(&details, room_id, room_epoch).is_ok());
    details["changes"][1]["bare_jid"] = serde_json::json!("other@example.test/resource");
    assert!(validate_cluster_muc_admin_batch_details(&details, room_id, room_epoch).is_err());
    details["changes"][1]["bare_jid"] = serde_json::json!("other@example.test");
    details["non_anonymous"] = serde_json::json!(false);
    assert!(validate_cluster_muc_admin_batch_details(&details, room_id, room_epoch).is_err());
}

#[test]
fn muc_admin_batch_projection_count_fits_durable_receipts() {
    let room_id = uuid::Uuid::from_u128(1);
    let room_epoch = uuid::Uuid::from_u128(2);
    let notice = serde_json::json!({
        "kind":"offline_affiliation","bare_jid":"user@example.test",
        "affiliation":"member","nick":null,"reason":null
    });
    let details = serde_json::json!({
        "non_anonymous":true,"request_change_count":1,"changes":vec![notice; 64]
    });
    assert!(validate_cluster_muc_admin_batch_details(&details, room_id, room_epoch).is_err());
    let empty = serde_json::json!({
        "non_anonymous":false,"request_change_count":1,"changes":[]
    });
    assert!(validate_cluster_muc_admin_batch_details(&empty, room_id, room_epoch).is_ok());
}

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
            key_identity: crate::db::ClusterKeyDeploymentIdentity {
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
async fn revocation_authority_failure_fences_the_shared_cluster_health() {
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
        CLUSTER_FAIL_CLOSED
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
}

#[tokio::test]
async fn pending_ack_registration_is_bounded_and_cancel_safe() {
    let cluster = ClusterManager::new(None, "example.test", None, None, None, None)
        .await
        .unwrap();
    let mut registrations = Vec::with_capacity(MAX_PENDING_CLUSTER_ACKS);
    for index in 0..MAX_PENDING_CLUSTER_ACKS {
        registrations.push(
            cluster
                .register_pending_ack(
                    &uuid::Uuid::from_u128(index as u128 + 1).to_string(),
                    "node-b",
                    "bounded-nonce",
                )
                .unwrap(),
        );
    }
    assert_eq!(cluster.pending_acks.len(), MAX_PENDING_CLUSTER_ACKS);
    assert!(cluster
        .register_pending_ack(
            &uuid::Uuid::from_u128(MAX_PENDING_CLUSTER_ACKS as u128 + 1).to_string(),
            "node-b",
            "overflow-nonce",
        )
        .is_err());
    drop(registrations);
    assert!(cluster.pending_acks.is_empty());
}

#[tokio::test]
async fn listener_admission_dispatches_only_the_exact_pending_ack() {
    let cluster = ClusterManager::new(None, "example.test", None, None, None, None)
        .await
        .unwrap();
    let admission = cluster.listener_admission();
    let request_id = uuid::Uuid::new_v4().to_string();
    let mut pending = cluster
        .register_pending_ack(&request_id, "node-b", "exact-nonce")
        .unwrap();
    let ack = serde_json::json!({
        "request_id": request_id,
        "nonce": "exact-nonce",
        "node_id": "node-b",
        "delivered": 1,
        "accepted_full_jid": null,
    });
    assert!(!admission.dispatch_pending_ack("node-c", ack.clone()));
    let mut wrong_nonce = ack.clone();
    wrong_nonce["nonce"] = serde_json::json!("wrong-nonce");
    assert!(!admission.dispatch_pending_ack("node-b", wrong_nonce));
    assert!(admission.dispatch_pending_ack("node-b", ack));
    assert_eq!(pending.recv().await.unwrap().delivered, 1);
}

#[test]
fn muc_soft_state_lease_survives_multiple_refresh_and_node_lease_windows() {
    const {
        assert!(
            MUC_SOFT_STATE_TTL_SECONDS >= CLUSTER_MAINTENANCE_INTERVAL_SECONDS * 8,
            "a live room needs several maintenance retries before its soft-state expires"
        );
        assert!(
            MUC_SOFT_STATE_TTL_SECONDS >= NODE_TTL_SECONDS * 3,
            "room cleanup must not race a single missed node-heartbeat window"
        );
    }
}

pub(super) fn verification_manager(
    namespace: &str,
    security: Arc<crate::cluster_security::ClusterSecurityConfig>,
) -> ClusterManager {
    ClusterManager {
        node_id: security.node_id.clone(),
        namespace: namespace.into(),
        key_prefix: format!("northstar:{namespace}"),
        pool: None,
        client: None,
        security: Some(security),
        connection_uuid: uuid::Uuid::new_v4(),
        instance_epoch: Arc::new(AtomicI64::new(1)),
        authorized_instances: Arc::new(dashmap::DashMap::new()),
        authorized_peer_keys: Arc::new(dashmap::DashMap::new()),
        replay_cache: Arc::new(dashmap::DashMap::new()),
        replay_cache_gate: Arc::new(Mutex::new(())),
        replay_cache_next_expiry: Arc::new(AtomicI64::new(i64::MAX)),
        replay_cache_sweeps: Arc::new(AtomicU64::new(0)),
        authority_pool: Arc::new(std::sync::OnceLock::new()),
        health: Arc::new(ClusterHealth::disabled()),
        publication_gate: Arc::new(tokio::sync::RwLock::new(())),
        muc_outbox_notify: Arc::new(tokio::sync::Notify::new()),
        account_revocation_notify: Arc::new(tokio::sync::Notify::new()),
        listener_rotation: Arc::new(tokio::sync::Notify::new()),
        pending_ack_slots: Arc::new(tokio::sync::Semaphore::new(MAX_PENDING_CLUSTER_ACKS)),
        pending_acks: Arc::new(dashmap::DashMap::new()),
    }
}

pub(super) fn listener_health_manager() -> ClusterManager {
    let namespace = "listener-health.test";
    let (_, security) = crate::cluster_security::test_configuration_pair(namespace);
    let mut manager = verification_manager(namespace, security);
    // A lazy, unused pool enables the health policy without opening Redis.
    let client = redis::Client::open("redis://127.0.0.1:1").unwrap();
    manager.pool = Some(cluster_pool_builder().build_unchecked(RedisConnectionManager { client }));
    manager.health = Arc::new(ClusterHealth::enabled());
    manager
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

#[test]
fn replay_cache_capacity_admission_is_linearizable() {
    let namespace = "example.test";
    let (_, receiver_security) = crate::cluster_security::test_configuration_pair(namespace);
    let manager = verification_manager(namespace, receiver_security);
    let workers = 64;
    let limit = 16;
    let barrier = Arc::new(std::sync::Barrier::new(workers));
    let accepted = std::thread::scope(|scope| {
        let mut handles = Vec::with_capacity(workers);
        for index in 0..workers {
            let barrier = Arc::clone(&barrier);
            let manager = &manager;
            handles.push(scope.spawn(move || {
                barrier.wait();
                manager
                    .remember_replay_key(format!("peer:epoch:connection:{index}"), 200, 100, limit)
                    .is_ok()
            }));
        }
        handles
            .into_iter()
            .map(|handle| handle.join().expect("replay admission worker"))
            .filter(|accepted| *accepted)
            .count()
    });

    assert_eq!(accepted, limit);
    assert_eq!(manager.replay_cache.len(), limit);
}

#[test]
fn full_replay_cache_without_expiry_rejects_in_constant_time_path() {
    let namespace = "example.test";
    let (_, receiver_security) = crate::cluster_security::test_configuration_pair(namespace);
    let manager = verification_manager(namespace, receiver_security);
    manager
        .remember_replay_key("resident".to_owned(), 200, 100, 1)
        .expect("resident replay identity admitted");

    for index in 0..128 {
        assert!(manager
            .remember_replay_key(format!("rejected-{index}"), 300, 100, 1)
            .is_err());
    }
    assert_eq!(manager.replay_cache_sweeps.load(Ordering::Relaxed), 0);

    manager
        .remember_replay_key("replacement".to_owned(), 300, 201, 1)
        .expect("the first request after expiry performs one reclamation");
    assert_eq!(manager.replay_cache_sweeps.load(Ordering::Relaxed), 1);
}

#[test]
fn replay_cache_preserves_the_clock_skew_boundary_and_reclaims_after_it() {
    let namespace = "example.test";
    let (_, receiver_security) = crate::cluster_security::test_configuration_pair(namespace);
    let manager = verification_manager(namespace, receiver_security);

    manager
        .remember_replay_key("first".to_owned(), 105, 100, 1)
        .expect("first replay identity admitted");
    assert!(manager
        .remember_replay_key("first".to_owned(), 105, 100, 1)
        .is_err());
    assert!(manager
        .remember_replay_key("second".to_owned(), 200, 105, 1)
        .is_err());
    manager
        .remember_replay_key("second".to_owned(), 200, 106, 1)
        .expect("entry is reclaimable only after its final skew-valid second");
    assert!(!manager.replay_cache.contains_key("first"));
    assert!(manager.replay_cache.contains_key("second"));
}

#[test]
fn exact_signed_envelope_is_accepted_once_for_the_authoritative_instance() {
    let namespace = "example.test";
    let (sender_security, receiver_security) =
        crate::cluster_security::test_configuration_pair(namespace);
    let receiver = verification_manager(namespace, receiver_security);
    let instance_uuid = uuid::Uuid::new_v4();
    let now = Instant::now();
    receiver.authorized_instances.insert(
        sender_security.node_id.clone(),
        AuthorizedClusterInstance {
            instance_uuid,
            instance_epoch: 7,
            signing_key_id: sender_security.current_key_id.clone(),
            signing_key_epoch: sender_security.key_epoch,
            valid_until: now + Duration::from_secs(30),
            refresh_until: now + Duration::from_secs(10),
        },
    );
    receiver.authorized_peer_keys.insert(
        sender_security.node_id.clone(),
        AuthorizedPeerKeys {
            epoch: sender_security.key_epoch,
            current_key_id: sender_security.current_key_id.clone(),
            previous_key_id: None,
            refresh_until: now + Duration::from_secs(10),
        },
    );
    let channel = format!("northstar:{namespace}:node:{}", receiver.node_id);
    let envelope = crate::cluster_security::SignedClusterEnvelope::sign(
        &sender_security.signer(),
        namespace,
        &sender_security.node_id,
        &receiver.node_id,
        receiver.connection_uuid,
        receiver.instance_epoch.load(Ordering::Acquire),
        &receiver.security.as_ref().unwrap().current_key_id,
        receiver.security.as_ref().unwrap().key_epoch,
        &channel,
        crate::cluster_security::ClusterCommandKind::DirectDelivery,
        instance_uuid,
        7,
        serde_json::json!({"target":"alice@example.test","stanza":"<message/>"}),
        chrono::Utc::now().timestamp(),
    )
    .unwrap();
    let encoded = serde_json::to_string(&envelope).unwrap();
    receiver
        .verify_signed_payload(&encoded, &channel, Some(&sender_security.node_id))
        .unwrap();
    assert!(receiver
        .verify_signed_payload(&encoded, &channel, Some(&sender_security.node_id))
        .is_err());
}

#[test]
fn staged_key_cannot_copy_the_current_instance_tuple_before_activation() {
    let namespace = "example.test";
    let (staged_sender, receiver_security, active_key_id) =
        crate::cluster_security::test_prepared_staged_pair(namespace);
    let receiver_peers = receiver_security.peers();
    let receiver = verification_manager(namespace, receiver_security);
    let copied_uuid = uuid::Uuid::new_v4();
    let now = Instant::now();
    receiver.authorized_instances.insert(
        staged_sender.node_id.clone(),
        AuthorizedClusterInstance {
            instance_uuid: copied_uuid,
            instance_epoch: 7,
            signing_key_id: active_key_id.clone(),
            signing_key_epoch: 1,
            valid_until: now + Duration::from_secs(30),
            refresh_until: now + Duration::from_secs(10),
        },
    );
    receiver.authorized_peer_keys.insert(
        staged_sender.node_id.clone(),
        AuthorizedPeerKeys {
            epoch: 1,
            current_key_id: active_key_id,
            previous_key_id: None,
            refresh_until: now + Duration::from_secs(10),
        },
    );
    let channel = format!("northstar:{namespace}:node:{}", receiver.node_id);
    let envelope = crate::cluster_security::SignedClusterEnvelope::sign(
        &staged_sender.signer(),
        namespace,
        &staged_sender.node_id,
        &receiver.node_id,
        receiver.connection_uuid,
        receiver.instance_epoch.load(Ordering::Acquire),
        &receiver.security.as_ref().unwrap().current_key_id,
        receiver.security.as_ref().unwrap().key_epoch,
        &channel,
        crate::cluster_security::ClusterCommandKind::DirectDelivery,
        copied_uuid,
        7,
        serde_json::json!({"target":"alice@example.test","stanza":"<message/>"}),
        chrono::Utc::now().timestamp(),
    )
    .unwrap();
    envelope
        .verify(
            namespace,
            &receiver.node_id,
            &channel,
            Some(&staged_sender.node_id),
            receiver_peers.as_ref(),
            chrono::Utc::now().timestamp(),
        )
        .unwrap();
    // The static peer file can verify the prepared public key for rolling
    // upgrade compatibility, but PostgreSQL has not activated it and the
    // live instance lease is explicitly bound to the old key generation.
    assert!(receiver
        .verify_signed_payload(
            &serde_json::to_string(&envelope).unwrap(),
            &channel,
            Some(&staged_sender.node_id),
        )
        .is_err());
}

#[test]
fn stale_or_wrong_cluster_process_instance_is_rejected() {
    let now = Instant::now();
    let instance_uuid = uuid::Uuid::new_v4();
    let authority = AuthorizedClusterInstance {
        instance_uuid,
        instance_epoch: 9,
        signing_key_id: "current-key".into(),
        signing_key_epoch: 4,
        valid_until: now + Duration::from_secs(30),
        refresh_until: now + Duration::from_secs(10),
    };
    assert!(authoritative_instance_matches(
        &authority,
        instance_uuid,
        9,
        "current-key",
        4,
        now
    ));
    assert!(!authoritative_instance_matches(
        &authority,
        uuid::Uuid::new_v4(),
        9,
        "current-key",
        4,
        now
    ));
    assert!(!authoritative_instance_matches(
        &authority,
        instance_uuid,
        8,
        "current-key",
        4,
        now
    ));
    assert!(!authoritative_instance_matches(
        &authority,
        instance_uuid,
        9,
        "current-key",
        4,
        authority.refresh_until
    ));
    assert!(!authoritative_instance_matches(
        &authority,
        instance_uuid,
        9,
        "previous-key",
        3,
        now
    ));
    assert!(!authoritative_instance_matches(
        &authority,
        instance_uuid,
        9,
        "staged-key",
        5,
        now
    ));
}

#[test]
fn postgres_key_cache_controls_prepare_activate_and_retire_acceptance() {
    let now = Instant::now();
    let prepared = AuthorizedPeerKeys {
        epoch: 4,
        current_key_id: "old".into(),
        previous_key_id: None,
        refresh_until: now + Duration::from_secs(10),
    };
    assert!(prepared.accepts("old", 4, now));
    // A staged key authorizes the future DB activation only. Even if an
    // attacker copies the observable current process UUID/epoch, staged
    // material is not a wire-command authority before activation.
    assert!(!prepared.accepts("next", 5, now));
    assert!(!prepared.accepts("older", 3, now));

    let activated = AuthorizedPeerKeys {
        epoch: 5,
        current_key_id: "next".into(),
        previous_key_id: Some("old".into()),
        refresh_until: now + Duration::from_secs(10),
    };
    assert!(activated.accepts("next", 5, now));
    assert!(activated.accepts("old", 4, now));

    let retired = AuthorizedPeerKeys {
        previous_key_id: None,
        ..activated
    };
    assert!(!retired.accepts("old", 4, now));
    assert!(!retired.accepts("next", 5, retired.refresh_until));
}

#[test]
fn admission_capability_observes_shared_health_transitions() {
    let namespace = "admission-capability.test";
    let (_, security) = crate::cluster_security::test_configuration_pair(namespace);
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
    use crate::cluster_security::ClusterFailurePolicy::{DurableDirectOnly, FailClosed};
    assert!(!degraded_shutdown_required(FailClosed, true, false));
    assert!(degraded_shutdown_required(FailClosed, true, true));
    assert!(!degraded_shutdown_required(DurableDirectOnly, true, true));
    assert!(degraded_shutdown_required(DurableDirectOnly, false, false));
    assert!(degraded_shutdown_required(FailClosed, false, false));
}

#[derive(Clone, Debug, Default)]
struct NeverConnectManager {
    attempts: Arc<std::sync::atomic::AtomicUsize>,
}

impl bb8::ManageConnection for NeverConnectManager {
    type Connection = ();
    type Error = std::io::Error;

    async fn connect(&self) -> std::result::Result<Self::Connection, Self::Error> {
        self.attempts
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        std::future::pending().await
    }

    async fn is_valid(&self, _: &mut Self::Connection) -> std::result::Result<(), Self::Error> {
        Ok(())
    }

    fn has_broken(&self, _: &mut Self::Connection) -> bool {
        false
    }
}

#[tokio::test]
async fn three_failed_cluster_pool_acquisitions_finish_inside_two_seconds() {
    let manager = NeverConnectManager::default();
    let attempts = manager.attempts.clone();
    let pool = cluster_pool_builder().build_unchecked(manager);

    tokio::time::timeout(Duration::from_secs(2), async {
        for _ in 0..3 {
            assert!(matches!(pool.get().await, Err(bb8::RunError::TimedOut)));
        }
    })
    .await
    .expect("three serial Redis pool acquisition failures exceeded two seconds");

    // bb8 coalesces concurrent/serial waiters behind the same in-flight
    // connection attempt. The callers must still receive their own hard
    // deadline instead of waiting for that attempt to finish or retry.
    assert_eq!(attempts.load(std::sync::atomic::Ordering::SeqCst), 1);
}

#[test]
fn carbon_privacy_uses_the_forwarded_conversation_peer() {
    let received = roxmltree::Document::parse(
            "<message from='alice@example.test' to='alice@example.test/Tablet'>\
               <received xmlns='urn:xmpp:carbons:2'>\
                 <forwarded xmlns='urn:xmpp:forward:0'>\
                   <message xmlns='jabber:client' from='blocked@example.net/Phone' to='alice@example.test/Phone'/>\
                 </forwarded>\
               </received>\
             </message>",
        )
        .unwrap();
    assert_eq!(
        delivery_privacy_peer(&received, true),
        Some((
            "blocked@example.net/Phone".to_owned(),
            crate::db::PrivacyStanzaKind::Message,
        ))
    );

    let sent = roxmltree::Document::parse(
            "<message from='alice@example.test'><sent xmlns='urn:xmpp:carbons:2'><forwarded xmlns='urn:xmpp:forward:0'><message xmlns='jabber:client' from='alice@example.test/Phone' to='bob@example.net'/></forwarded></sent></message>",
        )
        .unwrap();
    assert_eq!(
        delivery_privacy_peer(&sent, true),
        Some((
            "bob@example.net".to_owned(),
            crate::db::PrivacyStanzaKind::Message,
        ))
    );

    let malformed_received = roxmltree::Document::parse(
            "<message from='alice@example.test'><received xmlns='urn:xmpp:carbons:2'><forwarded xmlns='urn:xmpp:forward:0'><message xmlns='jabber:client'/></forwarded></received></message>",
        )
        .unwrap();
    assert_eq!(delivery_privacy_peer(&malformed_received, true), None);

    let missing_sent_recipient = roxmltree::Document::parse(
            "<message from='alice@example.test'><sent xmlns='urn:xmpp:carbons:2'><forwarded xmlns='urn:xmpp:forward:0'><message xmlns='jabber:client' from='alice@example.test/Phone'/></forwarded></sent></message>",
        )
        .unwrap();
    assert_eq!(
        delivery_privacy_peer(&missing_sent_recipient, true),
        None,
        "a malformed sent Carbon must not fall back to its self-addressed wrapper"
    );

    let ambiguous = roxmltree::Document::parse(
            "<message from='alice@example.test'><sent xmlns='urn:xmpp:carbons:2'><forwarded xmlns='urn:xmpp:forward:0'><message xmlns='jabber:client' from='alice@example.test/Phone' to='bob@example.net'/></forwarded></sent><received xmlns='urn:xmpp:carbons:2'><forwarded xmlns='urn:xmpp:forward:0'><message xmlns='jabber:client' from='mallory@example.net' to='alice@example.test/Phone'/></forwarded></received></message>",
        )
        .unwrap();
    assert_eq!(delivery_privacy_peer(&ambiguous, true), None);
}

pub(super) fn rename_occupant(
    epoch: uuid::Uuid,
    nick: &str,
) -> crate::state::SerializableMucOccupant {
    crate::state::SerializableMucOccupant {
        full_jid: "alice@example.test/Phone".to_owned(),
        room_jid: "room@conference.example.test".to_owned(),
        nick: nick.to_owned(),
        affiliation: "member".to_owned(),
        role: "participant".to_owned(),
        room_non_anonymous: true,
        occupant_id: "opaque".to_owned(),
        cluster_epoch: epoch,
        connection_id: uuid::Uuid::new_v4(),
        federated_domain: None,
        sm_session_id: None,
        payload: String::new(),
    }
}

/// The Redis-only MUC fixture has no PostgreSQL authority worker.  Seed
/// both sides from the same immutable key/instance values that the
/// production authority refresh would read, so it verifies the signed
/// cross-node publication instead of bypassing it.
pub(super) fn seed_test_peer_authority(receiver: &ClusterManager, sender: &ClusterManager) {
    let sender_security = sender
        .security
        .as_ref()
        .expect("Redis cluster fixture requires signing identity");
    let now = Instant::now();
    receiver.authorized_instances.insert(
        sender.node_id.clone(),
        AuthorizedClusterInstance {
            instance_uuid: sender.connection_uuid,
            instance_epoch: sender.instance_epoch.load(Ordering::Acquire),
            signing_key_id: sender_security.current_key_id.clone(),
            signing_key_epoch: sender_security.key_epoch,
            valid_until: now + Duration::from_secs(NODE_TTL_SECONDS),
            refresh_until: now + Duration::from_secs(10),
        },
    );
    receiver.authorized_peer_keys.insert(
        sender.node_id.clone(),
        AuthorizedPeerKeys {
            epoch: sender_security.key_epoch,
            current_key_id: sender_security.current_key_id.clone(),
            previous_key_id: None,
            refresh_until: now + Duration::from_secs(10),
        },
    );
}

#[tokio::test]
async fn single_node_muc_rename_requires_the_exact_non_nil_occupancy_epoch() {
    let cluster = ClusterManager::new(None, "example.test", None, None, None, None)
        .await
        .unwrap();
    let epoch = uuid::Uuid::new_v4();
    let old = rename_occupant(epoch, "Old");
    let mut new = old.clone();
    new.nick = "New".to_owned();
    assert_eq!(
        cluster
            .rename_muc_occupant(
                &old.room_jid,
                &old.nick,
                &new.nick,
                epoch,
                &serde_json::to_string(&old).unwrap(),
                &serde_json::to_string(&new).unwrap(),
            )
            .await
            .unwrap(),
        MucRename::Renamed
    );

    let stale = rename_occupant(uuid::Uuid::new_v4(), "Old");
    assert!(cluster
        .rename_muc_occupant(
            &old.room_jid,
            &old.nick,
            &new.nick,
            epoch,
            &serde_json::to_string(&stale).unwrap(),
            &serde_json::to_string(&new).unwrap(),
        )
        .await
        .is_err());
    let nil_old = rename_occupant(uuid::Uuid::nil(), "Old");
    let nil_new = rename_occupant(uuid::Uuid::nil(), "New");
    assert!(cluster
        .rename_muc_occupant(
            &nil_old.room_jid,
            &nil_old.nick,
            &nil_new.nick,
            uuid::Uuid::nil(),
            &serde_json::to_string(&nil_old).unwrap(),
            &serde_json::to_string(&nil_new).unwrap(),
        )
        .await
        .is_err());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires TEST_REDIS_URL; uses and removes a unique key namespace"]
async fn redis_muc_nickname_and_voice_mutations_reject_conflicts_and_aba() {
    let redis_url =
        std::env::var("TEST_REDIS_URL").expect("set TEST_REDIS_URL to a disposable Redis instance");
    let namespace = format!("muc-{}.test", uuid::Uuid::new_v4().simple());
    let (first_security, second_security) =
        crate::cluster_security::test_configuration_pair(&namespace);
    let first = ClusterManager::new(
        Some(&redis_url),
        &namespace,
        None,
        None,
        None,
        Some(first_security),
    )
    .await
    .unwrap();
    let second = ClusterManager::new(
        Some(&redis_url),
        &namespace,
        None,
        None,
        None,
        Some(second_security),
    )
    .await
    .unwrap();
    for cluster in [&first, &second] {
        cluster.install_instance_epoch(1).unwrap();
        cluster.touch_node().await.unwrap();
        cluster.note_listener_generation();
    }
    seed_test_peer_authority(&first, &second);
    seed_test_peer_authority(&second, &first);
    let second_channel = second.key(format!("node:{}", second.node_id));
    let mut second_pubsub = open_pubsub(second.client.as_ref().unwrap()).await.unwrap();
    subscribe_pubsub(&mut second_pubsub, &second_channel)
        .await
        .unwrap();
    let mut second_messages = second_pubsub.on_message();
    let room = "room@conference.example.test";
    let original_epoch = uuid::Uuid::new_v4();
    let original = rename_occupant(original_epoch, "Old");
    let original_json = serde_json::to_string(&original).unwrap();
    assert_eq!(
        first
            .try_register_muc_occupant(room, "Old", &original_json, 100)
            .await
            .unwrap(),
        MucRegistration::Joined
    );
    assert_eq!(
        first
            .try_register_muc_occupant(room, "Old", &original_json, 100)
            .await
            .unwrap(),
        MucRegistration::Joined,
        "an exact registration retry must be idempotent and renew its lease"
    );
    {
        let mut connection = first.pool.as_ref().unwrap().get().await.unwrap();
        for key in [
            first.key(format!("muc_occupants:{room}")),
            first.key(format!("muc_occupant_nodes:{room}")),
            first.key(format!("muc_nodes:{room}")),
            first.key(format!("muc_occupant_instances:{room}")),
            first.key(format!("muc_node_counts:{room}")),
        ] {
            let ttl: i64 = connection.ttl(key).await.unwrap();
            assert!((1..=MUC_SOFT_STATE_TTL_SECONDS as i64).contains(&ttl));
        }
    }

    let occupied = rename_occupant(uuid::Uuid::new_v4(), "Taken");
    assert_eq!(
        second
            .try_register_muc_occupant(
                room,
                "Taken",
                &serde_json::to_string(&occupied).unwrap(),
                100,
            )
            .await
            .unwrap(),
        MucRegistration::Joined
    );
    {
        let Some(pool) = &first.pool else {
            panic!("Redis-backed cluster expected");
        };
        let mut connection = pool.get().await.unwrap();
        let occupants_key = first.key(format!("muc_occupants:{room}"));
        let owners_key = first.key(format!("muc_occupant_nodes:{room}"));
        let nodes_key = first.key(format!("muc_nodes:{room}"));
        let _: usize = connection
            .hset(&occupants_key, "Ghost", "{}")
            .await
            .unwrap();
        let _: usize = connection
            .hset(&owners_key, "Ghost", "crashed-node")
            .await
            .unwrap();
        let _: usize = connection.sadd(&nodes_key, "crashed-node").await.unwrap();
        drop(connection);
        let visible = first.get_muc_occupants(room).await.unwrap();
        assert!(!visible.contains_key("Ghost"));
        let mut connection = pool.get().await.unwrap();
        let nodes: Vec<String> = connection.smembers(nodes_key).await.unwrap();
        assert!(!nodes.iter().any(|node| node == "crashed-node"));
    }
    let mut conflicting = original.clone();
    conflicting.nick = "Taken".to_owned();
    assert_eq!(
        first
            .rename_muc_occupant(
                room,
                "Old",
                "Taken",
                original_epoch,
                &original_json,
                &serde_json::to_string(&conflicting).unwrap(),
            )
            .await
            .unwrap(),
        MucRename::Conflict
    );
    assert!(first
        .get_muc_occupants(room)
        .await
        .unwrap()
        .contains_key("Old"));

    assert!(first
        .unregister_muc_occupant_epoch(room, "Old", original_epoch, original.connection_id,)
        .await
        .unwrap());
    let replacement_epoch = uuid::Uuid::new_v4();
    let replacement = rename_occupant(replacement_epoch, "Old");
    let replacement_json = serde_json::to_string(&replacement).unwrap();
    assert_eq!(
        first
            .try_register_muc_occupant(room, "Old", &replacement_json, 100)
            .await
            .unwrap(),
        MucRegistration::Joined
    );
    let mut delayed_target = original.clone();
    delayed_target.nick = "Late".to_owned();
    assert_eq!(
        first
            .rename_muc_occupant(
                room,
                "Old",
                "Late",
                original_epoch,
                &original_json,
                &serde_json::to_string(&delayed_target).unwrap(),
            )
            .await
            .unwrap(),
        MucRename::Stale
    );
    assert_eq!(
        first.get_muc_occupants(room).await.unwrap().get("Old"),
        Some(&replacement_json)
    );
    assert!(!first
        .unregister_muc_occupant_epoch(room, "Old", original_epoch, original.connection_id,)
        .await
        .unwrap());
    assert!(!first
        .evict_muc_occupant(&original, 307, Some("Moderator"), Some("delayed"))
        .await
        .unwrap());
    assert_eq!(
        first.get_muc_occupants(room).await.unwrap().get("Old"),
        Some(&replacement_json)
    );
    assert!(matches!(
        first
            .change_muc_occupant_role(room, &original, "participant")
            .await
            .unwrap(),
        MucRoleChange::Stale
    ));
    let changed = first
        .change_muc_occupant_role(room, &replacement, "visitor")
        .await
        .unwrap();
    let signed_role_change: String = tokio::time::timeout(REDIS_IO_TIMEOUT, second_messages.next())
        .await
        .expect("remote role change publication timed out")
        .expect("remote role change subscription ended")
        .get_payload()
        .unwrap();
    second
        .verify_signed_payload(&signed_role_change, &second_channel, Some(&first.node_id))
        .unwrap();
    assert!(matches!(
        changed,
        MucRoleChange::Changed(ref occupant) if occupant.role == "visitor"
    ));
    let changed = match changed {
        MucRoleChange::Changed(occupant) => occupant,
        MucRoleChange::Stale => unreachable!(),
    };
    let policy_changed = first
        .change_muc_occupant_policy(room, &changed, "participant", true)
        .await
        .unwrap();
    let signed_policy_change: String =
        tokio::time::timeout(REDIS_IO_TIMEOUT, second_messages.next())
            .await
            .expect("remote policy change publication timed out")
            .expect("remote policy change subscription ended")
            .get_payload()
            .unwrap();
    second
        .verify_signed_payload(&signed_policy_change, &second_channel, Some(&first.node_id))
        .unwrap();
    assert!(matches!(
        policy_changed,
        MucRoleChange::Changed(ref occupant)
            if occupant.role == "participant" && occupant.room_non_anonymous
    ));
    let persisted: crate::state::SerializableMucOccupant = serde_json::from_str(
        first
            .get_muc_occupants(room)
            .await
            .unwrap()
            .get("Old")
            .unwrap(),
    )
    .unwrap();
    assert_eq!(persisted.role, "participant");
    assert!(persisted.room_non_anonymous);
    // A policy write is a full serialized-value compare-and-set, not only
    // an epoch check. `changed` still describes the preceding visitor
    // state for this exact connection and must not overwrite the newer
    // participant/non-anonymous policy.
    assert!(matches!(
        first
            .change_muc_occupant_policy(room, &changed, "visitor", false)
            .await
            .unwrap(),
        MucRoleChange::Stale
    ));

    assert!(first
        .unregister_muc_occupant_epoch(room, "Old", replacement_epoch, replacement.connection_id,)
        .await
        .unwrap());
    assert!(second
        .unregister_muc_occupant_epoch(
            room,
            "Taken",
            occupied.cluster_epoch,
            occupied.connection_id,
        )
        .await
        .unwrap());
    assert!(first.get_muc_occupants(room).await.unwrap().is_empty());

    let Some(pool) = &first.pool else {
        panic!("Redis-backed cluster expected");
    };
    let mut connection = pool.get().await.unwrap();
    for key in [
        first.key(format!("muc_occupants:{room}")),
        first.key(format!("muc_occupant_nodes:{room}")),
        first.key(format!("muc_nodes:{room}")),
        first.key(format!("muc_occupant_instances:{room}")),
        first.key(format!("muc_node_counts:{room}")),
    ] {
        let exists: bool = connection.exists(key).await.unwrap();
        assert!(!exists, "last occupant cleanup left a room soft-state key");
    }
    let prefix = format!("{}*", first.key_prefix);
    let keys: Vec<String> = redis::cmd("KEYS")
        .arg(prefix)
        .query_async(&mut *connection)
        .await
        .unwrap();
    if !keys.is_empty() {
        let _: usize = redis::cmd("DEL")
            .arg(&keys)
            .query_async(&mut *connection)
            .await
            .unwrap();
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires TEST_REDIS_URL; exercises 10,000 disposable MUC room lifecycles"]
async fn redis_ten_thousand_temporary_muc_rooms_leave_no_soft_state_keys() {
    use futures::StreamExt as _;

    let redis_url =
        std::env::var("TEST_REDIS_URL").expect("set TEST_REDIS_URL to a disposable Redis instance");
    let namespace = format!("muc-churn-{}.test", uuid::Uuid::new_v4().simple());
    let (security, _) = crate::cluster_security::test_configuration_pair(&namespace);
    let cluster = ClusterManager::new(
        Some(&redis_url),
        &namespace,
        None,
        None,
        None,
        Some(security),
    )
    .await
    .unwrap();
    cluster.install_instance_epoch(1).unwrap();
    cluster.touch_node().await.unwrap();
    cluster.note_listener_generation();

    futures::stream::iter(0..10_000_u32)
        .map(|index| {
            let cluster = cluster.clone();
            async move {
                let room = format!("churn-{index}@conference.example.test");
                let mut occupant = rename_occupant(uuid::Uuid::new_v4(), "Only");
                occupant.room_jid.clone_from(&room);
                let json = serde_json::to_string(&occupant).unwrap();
                assert_eq!(
                    cluster
                        .try_register_muc_occupant(&room, "Only", &json, 1)
                        .await
                        .unwrap(),
                    MucRegistration::Joined
                );
                assert!(cluster
                    .unregister_muc_occupant_epoch(
                        &room,
                        "Only",
                        occupant.cluster_epoch,
                        occupant.connection_id,
                    )
                    .await
                    .unwrap());
            }
        })
        .buffer_unordered(16)
        .collect::<Vec<_>>()
        .await;

    let mut connection = cluster.pool.as_ref().unwrap().get().await.unwrap();
    for kind in [
        "muc_occupants",
        "muc_occupant_nodes",
        "muc_nodes",
        "muc_occupant_instances",
        "muc_node_counts",
    ] {
        let pattern = cluster.key(format!("{kind}:*"));
        let mut cursor = 0_u64;
        let mut found = Vec::new();
        loop {
            let (next, keys): (u64, Vec<String>) = redis::cmd("SCAN")
                .arg(cursor)
                .arg("MATCH")
                .arg(&pattern)
                .arg("COUNT")
                .arg(1_000)
                .query_async(&mut *connection)
                .await
                .unwrap();
            found.extend(keys);
            cursor = next;
            if cursor == 0 {
                break;
            }
        }
        assert!(found.is_empty(), "temporary room churn leaked {kind} keys");
    }
}

#[test]
fn redis_session_routes_keep_opaque_resource_case() {
    let upper = session_route_keys("ALICE@Example.test/Phone").unwrap();
    let lower = session_route_keys("alice@example.test/phone").unwrap();
    assert_eq!(upper.0, "alice@example.test/Phone");
    assert_eq!(lower.0, "alice@example.test/phone");
    assert_ne!(upper.0, lower.0);
    assert_eq!(upper.1, lower.1);
    assert_eq!(
        session_route_keys("ÅLICE@BÜCHER.example/DeviceÅ").unwrap(),
        (
            "ålice@bücher.example/DeviceÅ".to_owned(),
            "ålice@bücher.example".to_owned()
        )
    );
    assert!(session_route_keys("alice@example..test/Phone").is_err());
    assert!(session_route_keys("alice@example.test/bad\u{0007}resource").is_err());
}

#[test]
fn clustered_carbon_targets_each_exact_resource() {
    let wrapper = "<message xmlns='jabber:client' from='alice@example.test' to='alice@example.test'><sent xmlns='urn:xmpp:carbons:2'/></message>";
    let upper = node_delivery_stanza(wrapper, true, "alice@example.test/Phone");
    let lower = node_delivery_stanza(wrapper, true, "alice@example.test/phone");
    assert!(upper.contains("to='alice@example.test/Phone'"));
    assert!(lower.contains("to='alice@example.test/phone'"));
    assert_ne!(upper, lower);
}

#[test]
fn rolling_upgrade_accepts_legacy_ack_only_from_legacy_nodes() {
    let future_protocol_version = (DELIVERY_CONTRACT_PROTOCOL_VERSION + 1).to_string();

    assert!(!requires_correlated_ack(None));
    assert!(!requires_correlated_ack(Some("1")));
    assert!(requires_correlated_ack(Some("2")));
    assert!(requires_correlated_ack(Some(NODE_PROTOCOL_VERSION)));
    assert!(requires_correlated_ack(Some("7")));
    assert!(!requires_correlated_ack(Some("invalid")));
    assert!(!supports_control_ack(Some("6")));
    assert!(supports_control_ack(Some("7")));
    assert!(supports_control_ack(Some(NODE_PROTOCOL_VERSION)));
    assert!(!supports_control_ack(Some(&future_protocol_version)));
    assert!(!supports_delivery_contract(Some("7")));
    assert!(supports_delivery_contract(Some("8")));
    assert!(supports_delivery_contract(Some("9")));
    assert!(supports_delivery_contract(Some(NODE_PROTOCOL_VERSION)));
    assert!(!supports_delivery_contract(Some(&future_protocol_version)));
    // Presence authority became mandatory in application protocol 10 and
    // Exact MIX transport hand-offs became mandatory in application
    // protocol 13.
    // A new sender must not publish a receipt-required MIX event to a
    // live v11 peer which would ignore the ownership requirement.
    assert!(supports_current_cluster_protocol(Some(
        NODE_PROTOCOL_VERSION
    )));
    assert!(!supports_current_cluster_protocol(Some("11")));
    assert!(!supports_current_cluster_protocol(None));
}

#[test]
fn roster_delivery_rejects_a_recreated_account_with_the_same_jid() {
    let committed_owner = uuid::Uuid::from_u128(100);
    let recreated_owner = uuid::Uuid::from_u128(101);
    assert!(delivery_user_identity_matches(
        Some(committed_owner),
        Some(7),
        committed_owner,
        7,
    ));
    assert!(!delivery_user_identity_matches(
        Some(committed_owner),
        Some(7),
        recreated_owner,
        7,
    ));
    assert!(!delivery_user_identity_matches(
        Some(committed_owner),
        Some(7),
        committed_owner,
        8,
    ));
}

#[test]
fn presence_authority_is_versioned_complete_and_generation_fenced() {
    let owner = uuid::Uuid::from_u128(201);
    let recipient = uuid::Uuid::from_u128(202);
    let current = serde_json::json!({
        "presence_authority_version": 1,
        "presence_owner_id": owner,
        "presence_owner_auth_generation": 4,
        "presence_recipient_id": recipient,
        "presence_recipient_auth_generation": 9,
    });
    assert_eq!(
        presence_authority(&current).unwrap(),
        Some(ClusterPresenceAuthority {
            owner_id: owner,
            owner_auth_generation: 4,
            recipient_id: recipient,
            recipient_auth_generation: 9,
        })
    );
    assert!(presence_authority(&serde_json::json!({
        "presence_owner_id": owner,
        "presence_owner_auth_generation": 4,
        "presence_recipient_id": recipient,
        "presence_recipient_auth_generation": 9,
    }))
    .is_err());
    assert!(presence_authority(&serde_json::json!({
        "presence_authority_version": 1,
        "presence_owner_id": owner,
        "presence_owner_auth_generation": 4,
        "presence_recipient_id": recipient,
    }))
    .is_err());
    assert!(presence_authority(&serde_json::json!({
        "presence_authority_version": 2,
        "presence_owner_id": owner,
        "presence_owner_auth_generation": 4,
        "presence_recipient_id": recipient,
        "presence_recipient_auth_generation": 9,
    }))
    .is_err());
    assert_eq!(presence_authority(&serde_json::json!({})).unwrap(), None);
}

#[test]
fn presence_wire_shape_cannot_downgrade_subscription_into_generic_delivery() {
    let subscription = roxmltree::Document::parse(
            "<presence xmlns='jabber:client' from='a@example.test' to='b@example.test' type='subscribe'/>",
        )
        .unwrap();
    let current = roxmltree::Document::parse(
        "<presence xmlns='jabber:client' from='a@example.test/Phone' to='b@example.test'/>",
    )
    .unwrap();
    let message = roxmltree::Document::parse(
        "<message xmlns='jabber:client' from='a@example.test' to='b@example.test'/>",
    )
    .unwrap();
    assert!(is_presence_subscription_stanza(&subscription));
    assert!(presence_delivery_stanza_matches(
        &subscription,
        ClusterPresenceDelivery::Subscription,
    ));
    assert!(!presence_delivery_stanza_matches(
        &subscription,
        ClusterPresenceDelivery::CurrentReplay,
    ));
    assert!(presence_delivery_stanza_matches(
        &current,
        ClusterPresenceDelivery::CurrentReplay,
    ));
    assert!(!presence_delivery_stanza_matches(
        &message,
        ClusterPresenceDelivery::CurrentReplay,
    ));
}

#[test]
fn roster_delivery_shape_binds_the_signed_fence_to_the_stanza_version() {
    let plain = "<iq xmlns='jabber:client' type='set'><query xmlns='jabber:iq:roster' ver='42'><item jid='peer@example.test'/></query></iq>";
    let annotated = "<iq xmlns='jabber:client' type='set'><query xmlns='jabber:iq:roster' ver='42'><item jid='room@mix.example.test'><channel xmlns='urn:xmpp:mix:roster:0' participant-id='p1'/></item></query></iq>";
    assert_eq!(cluster_roster_push_version(plain), Some(42));
    assert_eq!(cluster_roster_push_version(annotated), Some(42));
    assert_ne!(cluster_roster_push_version(plain), Some(41));
    assert_eq!(
        cluster_roster_push_version(
            "<iq xmlns='jabber:client' type='get'><query xmlns='jabber:iq:roster' ver='42'/></iq>"
        ),
        None
    );
    assert_eq!(
            cluster_roster_push_version(
                "<iq xmlns='jabber:client' type='set'><query xmlns='jabber:iq:roster' ver='42'/><query xmlns='jabber:iq:roster' ver='42'/></iq>"
            ),
            None
        );
    assert_eq!(
            cluster_roster_push_version(
                "<iq xmlns='jabber:client' type='set'><query xmlns='jabber:iq:roster' ver='not-a-version'/></iq>"
            ),
            None
        );
}

#[test]
fn message_delivery_contract_is_explicit_strict_and_versioned() {
    let future_protocol_version = (DELIVERY_CONTRACT_PROTOCOL_VERSION + 1).to_string();
    let volatile = serde_json::json!({
        "protocol_version": NODE_PROTOCOL_VERSION,
        "delivery": { "reliability": "volatile" }
    });
    assert_eq!(
        requested_node_message_delivery(&volatile, true).unwrap(),
        Some(RequestedNodeMessageDelivery::Explicit(
            NodeDeliveryContract::Volatile {}
        ))
    );
    for version in ["8", "9"] {
        let adjacent = serde_json::json!({
            "protocol_version": version,
            "delivery": { "reliability": "volatile" }
        });
        assert_eq!(
            requested_node_message_delivery(&adjacent, true).unwrap(),
            Some(RequestedNodeMessageDelivery::Explicit(
                NodeDeliveryContract::Volatile {}
            )),
            "protocol {version} must retain explicit delivery semantics"
        );
        assert!(requested_node_message_delivery(
            &serde_json::json!({"protocol_version": version}),
            true,
        )
        .is_err());
    }

    let recipient_id = uuid::Uuid::from_u128(10);
    let message_id = uuid::Uuid::from_u128(11);
    let durable = serde_json::json!({
        "protocol_version": NODE_PROTOCOL_VERSION,
        "delivery": {
            "reliability": "durable_c2s",
            "recipient_id": recipient_id,
            "message_id": message_id
        }
    });
    assert_eq!(
        requested_node_message_delivery(&durable, true).unwrap(),
        Some(RequestedNodeMessageDelivery::Explicit(
            NodeDeliveryContract::DurableC2s {
                recipient_id,
                message_id,
            }
        ))
    );
    let mix_delivery_id = uuid::Uuid::from_u128(31);
    let mix_lease_token = uuid::Uuid::from_u128(32);
    let mix = serde_json::json!({
        "protocol_version": NODE_PROTOCOL_VERSION,
        "delivery": {
            "reliability": "durable_mix",
            "delivery_id": mix_delivery_id,
            "lease_token": mix_lease_token
        }
    });
    assert_eq!(
        requested_node_message_delivery(&mix, true).unwrap(),
        Some(RequestedNodeMessageDelivery::Explicit(
            NodeDeliveryContract::DurableMix {
                delivery_id: mix_delivery_id,
                lease_token: mix_lease_token,
            }
        ))
    );
    let stale_mix = serde_json::json!({
        "protocol_version": "12",
        "delivery": {
            "reliability": "durable_mix",
            "delivery_id": mix_delivery_id,
            "lease_token": mix_lease_token
        }
    });
    assert!(requested_node_message_delivery(&stale_mix, true).is_err());
    assert!(requested_node_message_delivery(
        &serde_json::json!({"protocol_version": NODE_PROTOCOL_VERSION}),
        true
    )
    .is_err());
    assert!(requested_node_message_delivery(
        &serde_json::json!({
            "protocol_version": NODE_PROTOCOL_VERSION,
            "delivery": {"reliability": "volatile", "unexpected": true}
        }),
        true
    )
    .is_err());
    assert!(requested_node_message_delivery(
        &serde_json::json!({
            "protocol_version": future_protocol_version,
            "delivery": {"reliability": "volatile"}
        }),
        true
    )
    .is_err());
    assert_eq!(
        requested_node_message_delivery(&serde_json::json!({"protocol_version": "6"}), true)
            .unwrap(),
        Some(RequestedNodeMessageDelivery::LegacyInference)
    );
    assert!(requested_node_message_delivery(&volatile, false).is_err());
}

#[test]
fn rolling_delivery_contract_never_turns_volatile_into_legacy_durable() {
    let future_protocol_version = (DELIVERY_CONTRACT_PROTOCOL_VERSION + 1).to_string();
    let recipient_id = uuid::Uuid::from_u128(12);
    let stanza_id = uuid::Uuid::from_u128(13);
    let other_row = uuid::Uuid::from_u128(14);
    let exact = crate::outbound::RecipientDeliveryIdentity::Exact(stanza_id);
    let missing = crate::outbound::RecipientDeliveryIdentity::Missing;

    assert!(delivery_contract_compatible_with_peer(
        Some("8"),
        NodeDeliveryContract::Volatile {},
        exact,
    ));
    assert!(!delivery_contract_compatible_with_peer(
        Some("7"),
        NodeDeliveryContract::Volatile {},
        exact,
    ));
    assert!(delivery_contract_compatible_with_peer(
        Some("7"),
        NodeDeliveryContract::Volatile {},
        missing,
    ));
    assert!(delivery_contract_compatible_with_peer(
        Some("7"),
        NodeDeliveryContract::DurableC2s {
            recipient_id,
            message_id: stanza_id,
        },
        exact,
    ));
    assert!(!delivery_contract_compatible_with_peer(
        Some("7"),
        NodeDeliveryContract::DurableC2s {
            recipient_id,
            message_id: other_row,
        },
        exact,
    ));
    assert!(delivery_contract_compatible_with_peer(
        Some("8"),
        NodeDeliveryContract::Volatile {},
        missing,
    ));
    assert!(delivery_contract_compatible_with_peer(
        Some("9"),
        NodeDeliveryContract::Volatile {},
        missing,
    ));
    assert!(delivery_contract_compatible_with_peer(
        Some(NODE_PROTOCOL_VERSION),
        NodeDeliveryContract::Volatile {},
        exact,
    ));
    // Once version 8 advertises an explicit contract, an exact stanza-id
    // must not make a volatile message look like a legacy durable fence,
    // and a durable row ID need not equal that stanza-id.
    assert!(delivery_contract_compatible_with_peer(
        Some("8"),
        NodeDeliveryContract::DurableC2s {
            recipient_id,
            message_id: other_row,
        },
        exact,
    ));
    for unsupported in [
        None,
        Some("0"),
        Some(future_protocol_version.as_str()),
        Some("invalid"),
    ] {
        assert!(!delivery_contract_compatible_with_peer(
            unsupported,
            NodeDeliveryContract::Volatile {},
            missing,
        ));
    }
}

#[test]
fn durable_contract_carries_the_real_row_fence_not_the_stanza_id() {
    let stanza_id = uuid::Uuid::from_u128(15);
    let offline_row_id = uuid::Uuid::from_u128(16);
    let recipient_id = uuid::Uuid::from_u128(17);
    let stanza = format!(
            "<message to='bob@example.test'><stanza-id xmlns='urn:xmpp:sid:0' by='bob@example.test' id='{stanza_id}'/></message>"
        );
    assert_eq!(
        outbound_delivery_contract(
            &stanza,
            "bob@example.test",
            Some(crate::outbound::DurableDelivery {
                recipient_id,
                message_id: offline_row_id,
                claim_id: None,
            }),
            None,
        )
        .unwrap(),
        Some(NodeDeliveryContract::DurableC2s {
            recipient_id,
            message_id: offline_row_id,
        })
    );
}

#[test]
fn mix_contract_carries_only_the_exact_recipient_lease() {
    let source = crate::outbound::MixDelivery {
        delivery_id: uuid::Uuid::from_u128(41),
        lease_token: uuid::Uuid::from_u128(42),
    };
    let stanza = "<message xmlns='jabber:client' to='bob@example.test' type='groupchat'><body>hello</body></message>";
    assert_eq!(
        outbound_delivery_contract(stanza, "bob@example.test", None, Some(source)).unwrap(),
        Some(NodeDeliveryContract::DurableMix {
            delivery_id: source.delivery_id,
            lease_token: source.lease_token,
        })
    );
    assert!(
        outbound_delivery_contract(stanza, "bob@example.test/resource", None, Some(source))
            .is_err()
    );
}

#[test]
fn durable_contract_is_bound_to_the_exact_spooled_payload() {
    let routed = "<message from='alice@example.test/Phone' to='bob@example.test' type='chat' id='m1'><body>hello</body></message>";
    let stored =
        crate::xmpp::xml_util::add_delay_from(routed, chrono::Utc::now(), Some("example.test"));
    assert!(
        crate::services::node_message_contract_verifier::durable_projection_matches(
            &stored, routed
        )
    );
    assert!(
            !crate::services::node_message_contract_verifier::durable_projection_matches(
                &stored,
                "<message from='alice@example.test/Phone' to='bob@example.test' type='chat' id='m1'><body>changed</body></message>"
            )
        );
    assert!(
            !crate::services::node_message_contract_verifier::durable_projection_matches(
                &stored,
                "<message from='alice@example.test/Phone' to='mallory@example.test' type='chat' id='m1'><body>hello</body></message>"
            )
        );
}

#[test]
fn delayed_auth_controls_never_revoke_newer_or_recreated_sessions() {
    let original_user = uuid::Uuid::new_v4();
    let recreated_user = uuid::Uuid::new_v4();
    assert!(generation_control_revokes(
        original_user,
        3,
        original_user,
        4
    ));
    assert!(!generation_control_revokes(
        original_user,
        4,
        original_user,
        4
    ));
    assert!(!generation_control_revokes(
        recreated_user,
        0,
        original_user,
        i64::MAX
    ));

    let device = uuid::Uuid::new_v4();
    assert!(user_agent_control_revokes(
        original_user,
        Some(device),
        Some(8),
        original_user,
        device,
        9,
    ));
    assert!(!user_agent_control_revokes(
        original_user,
        Some(device),
        Some(10),
        original_user,
        device,
        9,
    ));
    assert!(!user_agent_control_revokes(
        recreated_user,
        Some(device),
        Some(1),
        original_user,
        device,
        99,
    ));
}

#[test]
fn carbon_exclusions_preserve_exact_resources_and_legacy_primary() {
    let modern = serde_json::json!({
        "exclude_jid": "alice@example.test/Laptop",
        "exclude_jids": [
            "Alice@Example.test/Laptop",
            "alice@example.test/Phone"
        ]
    });
    let exclusions = delivery_exclusions(&modern);
    assert_eq!(exclusions.len(), 2);
    assert!(exclusions.contains("alice@example.test/Laptop"));
    assert!(exclusions.contains("alice@example.test/Phone"));

    let legacy = serde_json::json!({
        "exclude_jid": "Alice@Example.test/Laptop"
    });
    assert_eq!(
        delivery_exclusions(&legacy),
        HashSet::from(["alice@example.test/Laptop".to_owned()])
    );
}

#[test]
fn clustered_muc_carbon_scope_is_bounded_and_unambiguous() {
    let scoped = serde_json::json!({
        "carbon_muc_room": "Room@Conference.Example.test",
        "carbon_muc_nick": "Alice"
    });
    assert_eq!(
        delivery_carbon_muc_scope(&scoped),
        Ok(Some((
            "room@conference.example.test".to_owned(),
            "Alice".to_owned()
        )))
    );
    assert!(delivery_carbon_muc_scope(&serde_json::json!({
        "carbon_muc_room": "room@conference.example.test"
    }))
    .is_err());
}

fn ack_expectation<'a>(
    request_id: &'a str,
    nonce: &'a str,
    node_id: &'a str,
    target_jid: &'a str,
) -> DeliveryAckExpectation<'a> {
    DeliveryAckExpectation {
        request_id,
        nonce,
        node_id,
        target_jid,
        primary: true,
        delivery: None,
        require_delivery_contract: false,
        mix_capable_only: false,
        transport_receipt_required: false,
        mix_transport_receipt_required: false,
    }
}

#[test]
fn delivery_ack_requires_correlation_nonce_node_and_exact_resource() {
    let ack = NodeDeliveryAck {
        request_id: "request-1".to_owned(),
        nonce: "nonce-1".to_owned(),
        node_id: "node-b".to_owned(),
        delivered: 1,
        accepted_full_jid: Some("Alice@Example.test/Phone".to_owned()),
        mix_supported: 0,
        mix_unsupported: 0,
        mix_unknown: 0,
        control_processed: None,
        control_outcome: None,
        delivery: None,
        mix_handoff: None,
    };
    let payload = serde_json::to_string(&ack).unwrap();
    let receipt = validated_delivery_ack(
        &payload,
        ack_expectation("request-1", "nonce-1", "node-b", "alice@example.test"),
    )
    .unwrap();
    assert!(receipt.delivered);
    assert_eq!(
        receipt.accepted_full_jid.as_deref(),
        Some("alice@example.test/Phone")
    );
    assert!(validated_delivery_ack(
        &payload,
        ack_expectation("request-1", "forged", "node-b", "alice@example.test"),
    )
    .is_none());
    assert!(validated_delivery_ack(
        &payload,
        ack_expectation("request-1", "nonce-1", "node-c", "alice@example.test"),
    )
    .is_none());
    assert!(validated_delivery_ack(
        &payload,
        ack_expectation("request-1", "nonce-1", "node-b", "mallory@example.test"),
    )
    .is_none());
    assert!(validated_delivery_ack(
        &payload,
        ack_expectation("request-1", "nonce-1", "node-b", "alice@example.test/phone",),
    )
    .is_none());
}

#[test]
fn primary_delivery_ack_cannot_claim_multiple_or_missing_resources() {
    for ack in [
        NodeDeliveryAck {
            request_id: "r".to_owned(),
            nonce: "n".to_owned(),
            node_id: "node".to_owned(),
            delivered: 2,
            accepted_full_jid: Some("a@example.test/one".to_owned()),
            mix_supported: 0,
            mix_unsupported: 0,
            mix_unknown: 0,
            control_processed: None,
            control_outcome: None,
            delivery: None,
            mix_handoff: None,
        },
        NodeDeliveryAck {
            request_id: "r".to_owned(),
            nonce: "n".to_owned(),
            node_id: "node".to_owned(),
            delivered: 1,
            accepted_full_jid: None,
            mix_supported: 0,
            mix_unsupported: 0,
            mix_unknown: 0,
            control_processed: None,
            control_outcome: None,
            delivery: None,
            mix_handoff: None,
        },
    ] {
        let payload = serde_json::to_string(&ack).unwrap();
        assert!(validated_delivery_ack(
            &payload,
            ack_expectation("r", "n", "node", "a@example.test"),
        )
        .is_none());
    }
}

#[test]
fn mix_delivery_ack_carries_authenticated_tri_state_counts() {
    let ack = NodeDeliveryAck {
        request_id: "mix-r".to_owned(),
        nonce: "mix-n".to_owned(),
        node_id: "node".to_owned(),
        delivered: 1,
        accepted_full_jid: Some("a@example.test/one".to_owned()),
        mix_supported: 1,
        mix_unsupported: 2,
        mix_unknown: 3,
        control_processed: None,
        control_outcome: None,
        delivery: None,
        mix_handoff: None,
    };
    let mut expected = ack_expectation("mix-r", "mix-n", "node", "a@example.test");
    expected.primary = false;
    expected.mix_capable_only = true;
    let receipt = validated_delivery_ack(&serde_json::to_string(&ack).unwrap(), expected)
        .expect("valid MIX capability receipt");
    assert!(receipt.delivered);
    assert_eq!(receipt.mix_supported, 1);
    assert_eq!(receipt.mix_unsupported, 2);
    assert_eq!(receipt.mix_unknown, 3);

    let forged = NodeDeliveryAck {
        delivered: 2,
        ..ack
    };
    let mut expected = ack_expectation("mix-r", "mix-n", "node", "a@example.test");
    expected.primary = false;
    expected.mix_capable_only = true;
    assert!(validated_delivery_ack(&serde_json::to_string(&forged).unwrap(), expected).is_none());
}

#[test]
fn transport_receipt_ack_requires_one_exact_resource_or_none() {
    let ack = NodeDeliveryAck {
        request_id: "pam-r".to_owned(),
        nonce: "pam-n".to_owned(),
        node_id: "node".to_owned(),
        delivered: 1,
        accepted_full_jid: Some("a@example.test/one".to_owned()),
        mix_supported: 0,
        mix_unsupported: 0,
        mix_unknown: 0,
        control_processed: None,
        control_outcome: None,
        delivery: None,
        mix_handoff: None,
    };
    let expectation = || {
        let mut expected = ack_expectation("pam-r", "pam-n", "node", "a@example.test/one");
        expected.primary = false;
        expected.transport_receipt_required = true;
        expected
    };
    assert!(
        validated_delivery_ack(&serde_json::to_string(&ack).unwrap(), expectation(),).is_some()
    );

    for forged in [
        NodeDeliveryAck {
            delivered: 0,
            ..ack.clone()
        },
        NodeDeliveryAck {
            delivered: 2,
            ..ack.clone()
        },
        NodeDeliveryAck {
            accepted_full_jid: None,
            ..ack.clone()
        },
    ] {
        assert!(
            validated_delivery_ack(&serde_json::to_string(&forged).unwrap(), expectation(),)
                .is_none()
        );
    }
}

#[test]
fn mix_transport_receipt_ack_requires_confirmed_capable_resource() {
    let source = crate::outbound::MixDelivery {
        delivery_id: uuid::Uuid::from_u128(11),
        lease_token: uuid::Uuid::from_u128(12),
    };
    let ack = NodeDeliveryAck {
        request_id: "mix-r".to_owned(),
        nonce: "mix-n".to_owned(),
        node_id: "node".to_owned(),
        // Capability accounting may describe more than one resource, but
        // one ordered recipient row can be transferred only once.
        delivered: 1,
        accepted_full_jid: Some("a@example.test/one".to_owned()),
        mix_supported: 2,
        mix_unsupported: 1,
        mix_unknown: 0,
        control_processed: None,
        control_outcome: None,
        delivery: Some(NodeDeliveryContract::DurableMix {
            delivery_id: source.delivery_id,
            lease_token: source.lease_token,
        }),
        mix_handoff: Some(ClusterMixHandoff::SocketFenced),
    };
    let expectation = || {
        let mut expected = ack_expectation("mix-r", "mix-n", "node", "a@example.test");
        expected.primary = false;
        expected.delivery = Some(NodeDeliveryContract::DurableMix {
            delivery_id: source.delivery_id,
            lease_token: source.lease_token,
        });
        expected.require_delivery_contract = true;
        expected.mix_capable_only = true;
        expected.mix_transport_receipt_required = true;
        expected
    };
    assert!(validated_delivery_ack(&serde_json::to_string(&ack).unwrap(), expectation()).is_some());

    for forged in [
        NodeDeliveryAck {
            delivered: 0,
            ..ack.clone()
        },
        NodeDeliveryAck {
            accepted_full_jid: None,
            ..ack.clone()
        },
        NodeDeliveryAck {
            delivered: 3,
            mix_supported: 2,
            ..ack.clone()
        },
        NodeDeliveryAck {
            mix_handoff: None,
            ..ack.clone()
        },
    ] {
        assert!(
            validated_delivery_ack(&serde_json::to_string(&forged).unwrap(), expectation(),)
                .is_none()
        );
    }
}

#[tokio::test]
async fn mix_transport_receipt_waits_for_typed_ownership_and_fails_closed() {
    // A queued stanza is not yet delivered. The peer must explicitly
    // signal the output boundary before the remote node reports success.
    let source = crate::outbound::MixDelivery {
        delivery_id: uuid::Uuid::from_u128(21),
        lease_token: uuid::Uuid::from_u128(22),
    };
    let (output, mut consumer) = tokio::sync::mpsc::channel(1);
    let sender = crate::outbound::OutboundSender::new(output);
    let disconnect = CancellationToken::new();
    let waiter = {
        let sender = sender.clone();
        let disconnect = disconnect.clone();
        tokio::spawn(async move {
            try_send_cluster_mix_transport(&sender, &disconnect, "owned".to_owned(), source).await
        })
    };
    let item = consumer.recv().await.expect("MIX item was queued");
    item.complete_mix_handoff(crate::outbound::MixTransportCompletion::SocketFenced {
        connection_id: uuid::Uuid::from_u128(23),
    });
    assert!(matches!(
        waiter.await.unwrap(),
        Ok(crate::outbound::MixTransportCompletion::SocketFenced { .. })
    ));
    assert!(!disconnect.is_cancelled());

    // A full bounded queue must not become a successful remote receipt.
    let (output, _consumer) = tokio::sync::mpsc::channel(1);
    let sender = crate::outbound::OutboundSender::new(output);
    let disconnect = CancellationToken::new();
    sender.try_send("older".to_owned()).unwrap();
    assert!(
        try_send_cluster_mix_transport(&sender, &disconnect, "full".to_owned(), source)
            .await
            .is_err()
    );
    assert!(disconnect.is_cancelled());

    // A disconnected output transport cannot acknowledge a durable MIX
    // row, even though the caller has a live session object.
    let (output, consumer) = tokio::sync::mpsc::channel(1);
    drop(consumer);
    let sender = crate::outbound::OutboundSender::new(output);
    let disconnect = CancellationToken::new();
    assert!(
        try_send_cluster_mix_transport(&sender, &disconnect, "closed".to_owned(), source)
            .await
            .is_err()
    );
    assert!(disconnect.is_cancelled());

    // A receiver that takes the item and drops it before a recoverable
    // boundary closes the one-shot and is rejected without inventing a
    // timer-based delivery decision.
    let (output, mut consumer) = tokio::sync::mpsc::channel(1);
    let sender = crate::outbound::OutboundSender::new(output);
    let disconnect = CancellationToken::new();
    let waiter = {
        let sender = sender.clone();
        let disconnect = disconnect.clone();
        tokio::spawn(async move {
            try_send_cluster_mix_transport(&sender, &disconnect, "late".to_owned(), source).await
        })
    };
    let late = consumer.recv().await.expect("late MIX item was queued");
    drop(late);
    assert!(waiter.await.unwrap().is_err());
    assert!(disconnect.is_cancelled());
}

#[test]
fn version_seven_ack_must_echo_the_exact_delivery_contract() {
    let ack = NodeDeliveryAck {
        request_id: "r".to_owned(),
        nonce: "n".to_owned(),
        node_id: "node".to_owned(),
        delivered: 1,
        accepted_full_jid: Some("a@example.test/one".to_owned()),
        mix_supported: 0,
        mix_unsupported: 0,
        mix_unknown: 0,
        control_processed: None,
        control_outcome: None,
        delivery: Some(NodeDeliveryContract::Volatile {}),
        mix_handoff: None,
    };
    let payload = serde_json::to_string(&ack).unwrap();
    let mut expected = ack_expectation("r", "n", "node", "a@example.test");
    expected.delivery = Some(NodeDeliveryContract::Volatile {});
    expected.require_delivery_contract = true;
    assert!(validated_delivery_ack(&payload, expected).is_some());
    let mut wrong = ack_expectation("r", "n", "node", "a@example.test");
    wrong.delivery = Some(NodeDeliveryContract::DurableC2s {
        recipient_id: uuid::Uuid::from_u128(1),
        message_id: uuid::Uuid::from_u128(2),
    });
    wrong.require_delivery_contract = true;
    assert!(validated_delivery_ack(&payload, wrong,).is_none());
}
