use super::*;

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
    let exact = northstar_stream::outbound::RecipientDeliveryIdentity::Exact(stanza_id);
    let missing = northstar_stream::outbound::RecipientDeliveryIdentity::Missing;

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
            Some(northstar_stream::outbound::DurableDelivery {
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
    let source = northstar_stream::outbound::MixDelivery {
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
    let stored = northstar_xml_builder::message_policy::add_delay_from(
        routed,
        northstar_time::Utc::now(),
        Some("example.test"),
    );
    assert!(
        northstar_session_application::node_message_contract_verifier::durable_projection_matches(
            &stored, routed
        )
    );
    assert!(
            !northstar_session_application::node_message_contract_verifier::durable_projection_matches(
                &stored,
                "<message from='alice@example.test/Phone' to='bob@example.test' type='chat' id='m1'><body>changed</body></message>"
            )
        );
    assert!(
            !northstar_session_application::node_message_contract_verifier::durable_projection_matches(
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
    let source = northstar_stream::outbound::MixDelivery {
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
    let source = northstar_stream::outbound::MixDelivery {
        delivery_id: uuid::Uuid::from_u128(21),
        lease_token: uuid::Uuid::from_u128(22),
    };
    let (output, mut consumer) = tokio::sync::mpsc::channel(1);
    let sender = northstar_stream::outbound::OutboundSender::new(output);
    let disconnect = CancellationToken::new();
    let waiter = {
        let sender = sender.clone();
        let disconnect = disconnect.clone();
        tokio::spawn(async move {
            try_send_cluster_mix_transport(&sender, &disconnect, "owned".to_owned(), source).await
        })
    };
    let item = consumer.recv().await.expect("MIX item was queued");
    item.complete_mix_handoff(
        northstar_stream::outbound::MixTransportCompletion::SocketFenced {
            connection_id: uuid::Uuid::from_u128(23),
        },
    );
    assert!(matches!(
        waiter.await.unwrap(),
        Ok(northstar_stream::outbound::MixTransportCompletion::SocketFenced { .. })
    ));
    assert!(!disconnect.is_cancelled());

    // A full bounded queue must not become a successful remote receipt.
    let (output, _consumer) = tokio::sync::mpsc::channel(1);
    let sender = northstar_stream::outbound::OutboundSender::new(output);
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
    let sender = northstar_stream::outbound::OutboundSender::new(output);
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
    let sender = northstar_stream::outbound::OutboundSender::new(output);
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
