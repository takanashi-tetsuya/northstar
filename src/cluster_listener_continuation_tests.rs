use super::*;
use std::sync::atomic::{AtomicBool, AtomicUsize};

async fn acknowledgement_manager() -> Arc<ClusterManager> {
    Arc::new(
        ClusterManager::new(None, "listener-responses.test", None, None, None, None)
            .await
            .unwrap(),
    )
}

#[derive(Debug)]
enum TestWireMessage {
    Leaf {
        source: &'static str,
        destination: &'static str,
        request_id: String,
        nonce: String,
    },
    Ack {
        source: &'static str,
        destination: &'static str,
        payload: serde_json::Value,
    },
}

async fn simulated_probe_continuation(
    manager: Arc<ClusterManager>,
    source: &'static str,
    destination: &'static str,
    wire: tokio::sync::mpsc::Sender<TestWireMessage>,
    original_control_completed: Arc<AtomicBool>,
) -> Result<()> {
    let request_id = uuid::Uuid::new_v4().to_string();
    let nonce = format!("response-nonce-{source}-must-match-exactly");
    let mut pending = manager.register_pending_ack(&request_id, destination, &nonce)?;
    wire.try_send(TestWireMessage::Leaf {
        source,
        destination,
        request_id,
        nonce,
    })?;
    let acknowledgement = pending
        .recv()
        .await
        .context("leaf delivery did not produce its correlated acknowledgement")?;
    anyhow::ensure!(acknowledgement.delivered == 1, "leaf was not delivered");
    // This models the final original-control ACK. It must happen after the
    // nested delivery ACK, not merely after publishing the nested request.
    original_control_completed.store(true, Ordering::Release);
    Ok(())
}

#[tokio::test]
async fn simultaneous_probe_responses_allow_leaf_delivery_and_both_correlated_acks() {
    let first = acknowledgement_manager().await;
    let second = acknowledgement_manager().await;
    let first_completed = Arc::new(AtomicBool::new(false));
    let second_completed = Arc::new(AtomicBool::new(false));
    let (wire, mut incoming) = tokio::sync::mpsc::channel(4);
    let mut first_continuations = ListenerContinuations::default();
    let mut second_continuations = ListenerContinuations::default();
    first_continuations
        .push(simulated_probe_continuation(
            Arc::clone(&first),
            "node-a",
            "node-b",
            wire.clone(),
            Arc::clone(&first_completed),
        ))
        .unwrap();
    second_continuations
        .push(simulated_probe_continuation(
            Arc::clone(&second),
            "node-b",
            "node-a",
            wire.clone(),
            Arc::clone(&second_completed),
        ))
        .unwrap();

    // Deterministically put both controls into their nested ACK wait before
    // allowing either reader to handle a leaf. A single serial dispatcher
    // on each node would now prevent either leaf from ever being handled.
    assert!(first_continuations.next().now_or_never().is_none());
    assert!(second_continuations.next().now_or_never().is_none());
    assert_eq!(first.pending_acks.len(), 1);
    assert_eq!(second.pending_acks.len(), 1);
    assert!(!first_completed.load(Ordering::Acquire));
    assert!(!second_completed.load(Ordering::Acquire));

    let delivered_leaves = AtomicUsize::new(0);
    tokio::time::timeout(Duration::from_secs(5), async {
        let mut completed = 0;
        while completed < 2 {
            tokio::select! {
                result = first_continuations.next(), if !first_continuations.pending.is_empty() => {
                    result.unwrap().unwrap();
                    completed += 1;
                }
                result = second_continuations.next(), if !second_continuations.pending.is_empty() => {
                    result.unwrap().unwrap();
                    completed += 1;
                }
                message = incoming.recv() => {
                    match message.unwrap() {
                        TestWireMessage::Leaf { source, destination, request_id, nonce } => {
                            delivered_leaves.fetch_add(1, Ordering::Relaxed);
                            wire.try_send(TestWireMessage::Ack {
                                source: destination,
                                destination: source,
                                payload: serde_json::json!({
                                    "request_id": request_id,
                                    "nonce": nonce,
                                    "node_id": destination,
                                    "delivered": 1,
                                    "accepted_full_jid": "alice@listener-responses.test/online",
                                }),
                            }).unwrap();
                        }
                        TestWireMessage::Ack { source, destination, payload } => {
                            let receiver = if destination == "node-a" { &first } else { &second };
                            let mut wrong_nonce = payload.clone();
                            wrong_nonce["nonce"] = "unrelated-response".into();
                            assert!(!receiver.dispatch_pending_ack(source, wrong_nonce));
                            assert!(receiver.dispatch_pending_ack(source, payload));
                        }
                    }
                }
            }
        }
    })
    .await
    .expect("nested responses blocked the readers from completing their ACKs");
    assert_eq!(delivered_leaves.load(Ordering::Relaxed), 2);
    assert!(first_completed.load(Ordering::Acquire));
    assert!(second_completed.load(Ordering::Acquire));
    assert!(first.pending_acks.is_empty());
    assert!(second.pending_acks.is_empty());
}

#[tokio::test]
async fn full_continuation_set_rejects_work_without_leaking_its_pending_ack() {
    let manager = acknowledgement_manager().await;
    let mut continuations = ListenerContinuations::default();
    for _ in 0..MAX_LISTENER_CONTINUATIONS {
        continuations.push(std::future::pending()).unwrap();
    }
    let pending = manager
        .register_pending_ack(&uuid::Uuid::new_v4().to_string(), "peer", "nonce")
        .unwrap();
    assert_eq!(manager.pending_acks.len(), 1);
    let rejected = continuations.push(async move {
        let mut pending = pending;
        pending.recv().await.context("cancelled response")?;
        Ok(())
    });
    assert!(rejected.unwrap_err().to_string().contains("capacity"));
    assert_eq!(continuations.pending.len(), MAX_LISTENER_CONTINUATIONS);
    assert!(manager.pending_acks.is_empty());
    assert_eq!(
        manager.pending_ack_slots.available_permits(),
        MAX_PENDING_CLUSTER_ACKS
    );
}

#[tokio::test]
async fn dropping_listener_continuations_cancels_pending_ack_and_original_success() {
    let manager = acknowledgement_manager().await;
    let completed = Arc::new(AtomicBool::new(false));
    let (wire, mut incoming) = tokio::sync::mpsc::channel(1);
    let mut continuations = ListenerContinuations::default();
    continuations
        .push(simulated_probe_continuation(
            Arc::clone(&manager),
            "node-a",
            "node-b",
            wire,
            Arc::clone(&completed),
        ))
        .unwrap();
    assert!(continuations.next().now_or_never().is_none());
    assert!(matches!(
        incoming.try_recv(),
        Ok(TestWireMessage::Leaf { .. })
    ));
    assert_eq!(manager.pending_acks.len(), 1);
    drop(continuations);
    assert!(manager.pending_acks.is_empty());
    assert_eq!(
        manager.pending_ack_slots.available_permits(),
        MAX_PENDING_CLUSTER_ACKS
    );
    assert!(!completed.load(Ordering::Acquire));
}

#[tokio::test]
async fn continuation_errors_are_observed_by_the_listener() {
    let mut continuations = ListenerContinuations::default();
    continuations
        .push(async { anyhow::bail!("remote delivery failed before receipt") })
        .unwrap();
    let error = continuations.next().await.unwrap().unwrap_err();
    assert!(error.to_string().contains("before receipt"));
    assert!(continuations.pending.is_empty());
}

#[tokio::test]
async fn later_control_responses_do_not_overtake_an_earlier_receipt_wait() {
    let manager = acknowledgement_manager().await;
    let completed = [
        Arc::new(AtomicBool::new(false)),
        Arc::new(AtomicBool::new(false)),
    ];
    let (wire, mut incoming) = tokio::sync::mpsc::channel(2);
    let mut continuations = ListenerContinuations::default();
    for completion in &completed {
        continuations
            .push(simulated_probe_continuation(
                Arc::clone(&manager),
                "node-a",
                "node-b",
                wire.clone(),
                Arc::clone(completion),
            ))
            .unwrap();
    }
    let acknowledge = |message| {
        let TestWireMessage::Leaf {
            destination,
            request_id,
            nonce,
            ..
        } = message
        else {
            panic!("continuation must publish a leaf before completing its control");
        };
        assert!(manager.dispatch_pending_ack(
            destination,
            serde_json::json!({
                "request_id": request_id,
                "nonce": nonce,
                "node_id": destination,
                "delivered": 1,
                "accepted_full_jid": "alice@listener-responses.test/online",
            })
        ));
    };
    assert!(continuations.next().now_or_never().is_none());
    let first_leaf = incoming.try_recv().unwrap();
    // Repeatedly polling the pending first turn must not start the next turn.
    assert!(continuations.next().now_or_never().is_none());
    assert!(matches!(
        incoming.try_recv(),
        Err(tokio::sync::mpsc::error::TryRecvError::Empty)
    ));
    assert_eq!(manager.pending_acks.len(), 1);
    assert!(!completed[0].load(Ordering::Acquire));
    assert!(!completed[1].load(Ordering::Acquire));
    acknowledge(first_leaf);
    continuations
        .next()
        .now_or_never()
        .expect("first ACK was ready")
        .unwrap()
        .unwrap();
    assert!(completed[0].load(Ordering::Acquire));
    assert!(!completed[1].load(Ordering::Acquire));
    assert!(manager.pending_acks.is_empty());
    assert!(matches!(
        incoming.try_recv(),
        Err(tokio::sync::mpsc::error::TryRecvError::Empty)
    ));
    assert!(continuations.next().now_or_never().is_none());
    acknowledge(incoming.try_recv().unwrap());
    continuations
        .next()
        .now_or_never()
        .expect("second ACK was ready")
        .unwrap()
        .unwrap();
    assert!(completed[1].load(Ordering::Acquire));
    assert!(manager.pending_acks.is_empty());
    assert!(continuations.pending.is_empty());
}

fn response(stanza: String) -> ListenerResponse {
    ListenerResponse {
        node_id: "n".into(),
        recipient: "r".into(),
        stanza,
        presence_authority: None,
    }
}

#[test]
fn response_batch_enforces_bytes_before_retaining_the_next_response() {
    let mut responses = ListenerResponses::default();
    responses
        .push(response("x".repeat(MAX_CLUSTER_PAYLOAD_BYTES - 2)))
        .unwrap();
    assert_eq!(responses.bytes, MAX_CLUSTER_PAYLOAD_BYTES);
    assert!(responses.push(response(String::new())).is_err());
    assert_eq!(responses.items.len(), 1);
    assert_eq!(responses.bytes, MAX_CLUSTER_PAYLOAD_BYTES);
}

#[test]
fn response_batch_enforces_count_even_for_small_responses() {
    let mut responses = ListenerResponses::default();
    for _ in 0..MAX_PENDING_CLUSTER_ACKS {
        responses.push(response("p".into())).unwrap();
    }
    let before = responses.bytes;
    assert!(responses.push(response("p".into())).is_err());
    assert_eq!(responses.items.len(), MAX_PENDING_CLUSTER_ACKS);
    assert_eq!(responses.bytes, before);
}

#[tokio::test]
async fn response_generation_is_rejected_after_rotation_replacement_and_shutdown() {
    let manager = super::tests::listener_health_manager();
    let (generation, epoch) = manager.health.begin_listener_attempt();
    manager
        .confirm_listener_generation(generation, epoch)
        .unwrap();
    validate_listener_generation(&manager, generation, epoch).unwrap();
    manager.record_listener_failure(&anyhow::anyhow!("rotate deferred response owner"));
    assert!(validate_listener_generation(&manager, generation, epoch).is_err());
    let (replacement, replacement_epoch) = manager.health.begin_listener_attempt();
    manager
        .confirm_listener_generation(replacement, replacement_epoch)
        .unwrap();
    validate_listener_generation(&manager, replacement, replacement_epoch).unwrap();
    assert!(validate_listener_generation(&manager, generation, epoch).is_err());
    manager.require_shutdown();
    assert!(validate_listener_generation(&manager, replacement, replacement_epoch).is_err());
}

#[test]
fn deferred_response_revalidates_expiry_source_authority_without_readmitting_replay() {
    let namespace = "listener-authority.test";
    let (sender_security, receiver_security) =
        crate::cluster_security::test_configuration_pair(namespace);
    let sender = super::tests::verification_manager(namespace, sender_security);
    let receiver = super::tests::verification_manager(namespace, receiver_security);
    let signing = sender.security.as_ref().unwrap();
    let now = Instant::now();
    receiver.authorized_instances.insert(
        sender.node_id.clone(),
        AuthorizedClusterInstance {
            instance_uuid: sender.connection_uuid,
            instance_epoch: sender.instance_epoch.load(Ordering::Acquire),
            signing_key_id: signing.current_key_id.clone(),
            signing_key_epoch: signing.key_epoch,
            valid_until: now + Duration::from_secs(60),
            refresh_until: now + Duration::from_secs(60),
        },
    );
    receiver.authorized_peer_keys.insert(
        sender.node_id.clone(),
        AuthorizedPeerKeys {
            epoch: signing.key_epoch,
            current_key_id: signing.current_key_id.clone(),
            previous_key_id: None,
            refresh_until: now + Duration::from_secs(60),
        },
    );
    let channel = receiver.key(format!("node:{}", receiver.node_id));
    let authority_at =
        |issued_at, historical| {
            let envelope = crate::cluster_security::SignedClusterEnvelope::sign(
            &signing.signer(), namespace, &sender.node_id, &receiver.node_id,
            receiver.connection_uuid, receiver.instance_epoch.load(Ordering::Acquire),
            &receiver.security.as_ref().unwrap().current_key_id,
            receiver.security.as_ref().unwrap().key_epoch, &channel,
            crate::cluster_security::ClusterCommandKind::DirectDelivery,
            sender.connection_uuid, sender.instance_epoch.load(Ordering::Acquire),
            serde_json::json!({"target": "alice@listener-authority.test", "stanza": "<presence/>"}),
            issued_at,
        ).unwrap();
            let envelope = if historical {
                // Simulate admission while this historical wire signature was
                // still valid. Never alter a field after signature checking.
                envelope
                    .verify(
                        namespace,
                        &receiver.node_id,
                        &channel,
                        Some(&sender.node_id),
                        receiver.security.as_ref().unwrap().peers().as_ref(),
                        issued_at,
                    )
                    .unwrap();
                envelope
            } else {
                receiver
                    .verify_signed_payload_inner(
                        &serde_json::to_string(&envelope).unwrap(),
                        &channel,
                        Some(&sender.node_id),
                        false,
                    )
                    .unwrap()
            };
            ListenerCommandAuthority {
                generation: 0,
                rotation_epoch: 0,
                envelope,
            }
        };
    let fresh = authority_at(chrono::Utc::now().timestamp(), false);
    fresh.validate(&receiver).unwrap();
    fresh.validate(&receiver).unwrap();
    assert!(
        receiver.replay_cache.is_empty(),
        "deferred revalidation must not consume replay twice"
    );
    assert!(authority_at(chrono::Utc::now().timestamp() - 60, true)
        .validate(&receiver)
        .is_err());
    receiver
        .authorized_peer_keys
        .get_mut(&sender.node_id)
        .unwrap()
        .refresh_until = Instant::now();
    assert!(
        fresh.validate(&receiver).is_err(),
        "expired source-key authority cannot authorize deferred work"
    );
    receiver
        .authorized_peer_keys
        .get_mut(&sender.node_id)
        .unwrap()
        .refresh_until = now + Duration::from_secs(60);
    receiver
        .authorized_instances
        .get_mut(&sender.node_id)
        .unwrap()
        .refresh_until = Instant::now();
    assert!(
        fresh.validate(&receiver).is_err(),
        "expired source-instance authority cannot authorize deferred work"
    );
}
