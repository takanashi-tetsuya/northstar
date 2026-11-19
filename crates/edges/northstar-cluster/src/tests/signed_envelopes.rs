use super::*;

#[test]
fn replay_cache_capacity_admission_is_linearizable() {
    let namespace = "example.test";
    let (_, receiver_security) =
        northstar_security::cluster_bus::test_configuration_pair(namespace);
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
    let (_, receiver_security) =
        northstar_security::cluster_bus::test_configuration_pair(namespace);
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
    let (_, receiver_security) =
        northstar_security::cluster_bus::test_configuration_pair(namespace);
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
        northstar_security::cluster_bus::test_configuration_pair(namespace);
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
    let envelope = northstar_security::cluster_bus::SignedClusterEnvelope::sign(
        &sender_security.signer(),
        namespace,
        &sender_security.node_id,
        &receiver.node_id,
        receiver.connection_uuid,
        receiver.instance_epoch.load(Ordering::Acquire),
        &receiver.security.as_ref().unwrap().current_key_id,
        receiver.security.as_ref().unwrap().key_epoch,
        &channel,
        northstar_security::cluster_bus::ClusterCommandKind::DirectDelivery,
        instance_uuid,
        7,
        serde_json::json!({"target":"alice@example.test","stanza":"<message/>"}),
        northstar_time::Utc::now().timestamp(),
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
        northstar_security::cluster_bus::test_prepared_staged_pair(namespace);
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
    let envelope = northstar_security::cluster_bus::SignedClusterEnvelope::sign(
        &staged_sender.signer(),
        namespace,
        &staged_sender.node_id,
        &receiver.node_id,
        receiver.connection_uuid,
        receiver.instance_epoch.load(Ordering::Acquire),
        &receiver.security.as_ref().unwrap().current_key_id,
        receiver.security.as_ref().unwrap().key_epoch,
        &channel,
        northstar_security::cluster_bus::ClusterCommandKind::DirectDelivery,
        copied_uuid,
        7,
        serde_json::json!({"target":"alice@example.test","stanza":"<message/>"}),
        northstar_time::Utc::now().timestamp(),
    )
    .unwrap();
    envelope
        .verify(
            namespace,
            &receiver.node_id,
            &channel,
            Some(&staged_sender.node_id),
            receiver_peers.as_ref(),
            northstar_time::Utc::now().timestamp(),
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
