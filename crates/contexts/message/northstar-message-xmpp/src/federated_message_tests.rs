use super::degraded::inbound_direct_spool_eligibility;
use super::*;
use northstar_message_application::messaging::{
    DirectMessageRoutePort, OnlineRoutePort, OnlineRouteResult,
};
use northstar_message_core::{DirectPostCommitMode, DirectSpoolEligibility};
use northstar_stream::outbound::{DurableDelivery, OutboundItem};
use roxmltree::Document;

#[test]
fn degraded_inbound_spool_accepts_only_recoverable_bare_messages() {
    for xml in [
        "<message type='chat'><body>hello</body></message>",
        "<message type='chat'><body>hello</body><composing xmlns='http://jabber.org/protocol/chatstates'/></message>",
        "<message type='normal'><body>hello</body></message>",
        "<message><body>hello</body></message>",
    ] {
        let document = Document::parse(xml).unwrap();
        assert!(degraded_inbound_direct_eligible(
            document.root_element(),
            true,
            false,
            false,
        ));
    }

    for xml in [
        "<message type='chat'><body>private</body><no-store xmlns='urn:xmpp:hints'/></message>",
        "<message type='chat'><composing xmlns='http://jabber.org/protocol/chatstates'/></message>",
        "<message type='chat'><composing xmlns='http://jabber.org/protocol/chatstates'/><store xmlns='urn:xmpp:hints'/></message>",
        "<message type='chat'><received xmlns='urn:xmpp:receipts' id='m1'/><store xmlns='urn:xmpp:hints'/></message>",
        "<message type='chat'><displayed xmlns='urn:xmpp:chat-markers:0' id='m1'/><store xmlns='urn:xmpp:hints'/></message>",
        "<message type='headline'><body>news</body></message>",
        "<message type='groupchat'><body>hello</body></message>",
        "<message type='chat'><body>join</body><x xmlns='jabber:x:conference' jid='room@conference.example.test'/></message>",
        "<message type='normal'><pubsub xmlns='http://jabber.org/protocol/pubsub' node='push'><affiliation affiliation='none' jid='push.example.test'/></pubsub><store xmlns='urn:xmpp:hints'/></message>",
    ] {
        let document = Document::parse(xml).unwrap();
        assert!(
            !degraded_inbound_direct_eligible(document.root_element(), true, false, false),
            "unexpected degraded spool eligibility: {xml}"
        );
    }

    let plain = Document::parse("<message type='chat'><body>hello</body></message>").unwrap();
    assert!(!degraded_inbound_direct_eligible(
        plain.root_element(),
        false,
        false,
        false,
    ));
    assert!(!degraded_inbound_direct_eligible(
        plain.root_element(),
        true,
        true,
        false,
    ));
    assert!(!degraded_inbound_direct_eligible(
        plain.root_element(),
        true,
        false,
        true,
    ));
    let encrypted = Document::parse(
        "<message type='chat'><encrypted xmlns='urn:xmpp:omemo:2'>ciphertext</encrypted></message>",
    )
    .unwrap();
    assert!(degraded_inbound_direct_eligible(
        encrypted.root_element(),
        true,
        false,
        true,
    ));
}

#[test]
fn degraded_inbound_postcommit_is_accepted_without_live_effects() {
    assert_eq!(
        inbound_live_effect(DirectPostCommitMode::Live, false),
        InboundLiveEffect::Proceed
    );
    assert_eq!(
        inbound_live_effect(DirectPostCommitMode::Live, true),
        InboundLiveEffect::Proceed
    );
    for mode in [
        DirectPostCommitMode::SpoolOnly,
        DirectPostCommitMode::Rejected,
    ] {
        assert_eq!(inbound_live_effect(mode, false), InboundLiveEffect::Reject);
        assert_eq!(
            inbound_live_effect(mode, true),
            InboundLiveEffect::AcceptedSpool
        );
    }
}

#[test]
fn degraded_inbound_privacy_uses_account_default_and_fences_live_only_admission() {
    assert_eq!(
        degraded_inbound_privacy_uses_default(DirectPostCommitMode::Live, true),
        Some(false)
    );
    assert_eq!(
        degraded_inbound_privacy_uses_default(DirectPostCommitMode::SpoolOnly, true),
        Some(true)
    );
    assert_eq!(
        degraded_inbound_privacy_uses_default(DirectPostCommitMode::SpoolOnly, false),
        None
    );
    assert_eq!(
        degraded_inbound_privacy_uses_default(DirectPostCommitMode::Rejected, true),
        None
    );
    assert_eq!(
        inbound_direct_spool_eligibility(true, false),
        DirectSpoolEligibility::Eligible
    );
    assert_eq!(
        inbound_direct_spool_eligibility(true, true),
        DirectSpoolEligibility::LiveOnly
    );
    assert_eq!(
        inbound_direct_spool_eligibility(false, false),
        DirectSpoolEligibility::LiveOnly
    );
}

#[test]
fn remote_history_identity_is_bound_to_the_authenticated_domain() {
    let document = Document::parse(
        "<message><stanza-id xmlns='urn:xmpp:sid:0' by='Alice@REMOTE.test' id='trusted'/><stanza-id xmlns='urn:xmpp:sid:0' by='mallory.test' id='ignored'/></message>",
    )
    .unwrap();
    assert_eq!(
        authoritative_remote_stanza_identity(document.root_element(), "remote.TEST"),
        Some((
            "Alice@REMOTE.test".to_owned(),
            "alice@remote.test".to_owned(),
            "trusted".to_owned()
        ))
    );
    assert!(
        authoritative_remote_stanza_identity(document.root_element(), "unrelated.test").is_none()
    );

    let ambiguous = Document::parse(
        "<message><stanza-id xmlns='urn:xmpp:sid:0' by='alice@remote.test' id='a'/><stanza-id xmlns='urn:xmpp:sid:0' by='remote.test' id='b'/></message>",
    )
    .unwrap();
    assert!(
        authoritative_remote_stanza_identity(ambiguous.root_element(), "remote.test").is_none()
    );
}

#[test]
fn message_delivery_errors_use_rfc6120_type_condition_pairs() {
    let request = Document::parse(
        "<message xmlns='jabber:server' from='alice@remote.test/a' to='bob@local.test'><body>hello</body></message>",
    )
    .unwrap();
    for (serialized, condition) in [
        (
            offline_quota_error(request.root_element()),
            "resource-constraint",
        ),
        (
            recipient_unavailable_error(request.root_element()),
            "recipient-unavailable",
        ),
    ] {
        let response = Document::parse(&serialized).unwrap();
        let error = response
            .root_element()
            .children()
            .find(|child| {
                child.is_element()
                    && child.tag_name().name() == "error"
                    && child.tag_name().namespace() == Some("jabber:server")
            })
            .unwrap();
        assert_eq!(error.attribute("type"), Some("wait"));
        assert!(error.children().any(|child| {
            child.is_element()
                && child.tag_name().name() == condition
                && child.tag_name().namespace() == Some("urn:ietf:params:xml:ns:xmpp-stanzas")
        }));
    }
}

#[test]
fn message_errors_never_generate_error_loops() {
    let ordinary = Document::parse(
        "<message xmlns='jabber:server' from='alice@remote.test/a' to='bob@local.test'><body>hello</body></message>",
    )
    .unwrap();
    assert!(
        inbound_message_error(ordinary.root_element(), "cancel", "service-unavailable").is_some()
    );

    let error = Document::parse(
        "<message xmlns='jabber:server' type='error' from='alice@remote.test/a' to='missing@local.test'><error type='cancel'><service-unavailable xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/></error></message>",
    )
    .unwrap();
    assert!(inbound_message_error(error.root_element(), "cancel", "service-unavailable").is_none());
}

#[test]
fn remote_muc_private_messages_are_not_carbon_copied() {
    let private = Document::parse(
        "<message xmlns='jabber:client' type='chat' from='room@conference.remote.example/nick' to='alice@example.test/phone'><body>private</body></message>",
    )
    .unwrap();
    assert!(is_remote_muc_private_message(
        private.root_element(),
        "room@conference.remote.example/nick",
        "conference.remote.example"
    ));
    let direct = Document::parse(
        "<message xmlns='jabber:client' type='chat' from='bob@remote.example/phone' to='alice@example.test/phone'><body>direct</body></message>",
    )
    .unwrap();
    assert!(!is_remote_muc_private_message(
        direct.root_element(),
        "bob@remote.example/phone",
        "remote.example"
    ));
}

#[tokio::test]
async fn federated_delivery_uses_the_hosts_event_source() {
    use crate::test_support::{Host, State, TARGET};
    use uuid::Uuid;

    let host = Host::new(State::default());
    let sender = "alice@remote.test/phone";
    let raw = format!(
        "<message from='{sender}' to='{TARGET}' type='chat'><body>event source</body></message>"
    );
    let document = Document::parse(&raw).unwrap();
    let result = route_inbound_message(
        &host,
        document.root_element(),
        &raw,
        sender,
        TARGET,
        "remote.test",
    )
    .await
    .unwrap();
    assert_eq!(result, None);

    let committed = host.state.committed.lock().unwrap();
    let delivery = committed.as_ref().expect("committed federated delivery");
    assert_eq!(delivery.actor_fence, None);
    let expected_id = Uuid::from_u128(0x100);
    assert_eq!(delivery.source.message_id, expected_id);
    let stanza = Document::parse(&delivery.stanza).unwrap();
    let stanza_id = stanza
        .root_element()
        .children()
        .find(|child| child.has_tag_name(("urn:xmpp:sid:0", "stanza-id")))
        .unwrap();
    assert_eq!(stanza_id.attribute("by"), Some(TARGET));
    assert_eq!(
        stanza_id.attribute("id"),
        Some(expected_id.to_string().as_str())
    );
    let delay = stanza
        .root_element()
        .children()
        .find(|child| child.has_tag_name(("urn:xmpp:delay", "delay")))
        .unwrap();
    assert_eq!(delay.attribute("stamp"), Some("2001-01-01T00:00:00Z"));
}

#[tokio::test]
async fn federated_routes_preserve_envelopes_refusals_and_acceptance() {
    use crate::test_support::{
        poll_once, Event, Host, QueueAnswer, State, CLAIM, RECIPIENT, TARGET,
    };
    use northstar_stream::outbound::{RouteEnqueue, RouteSendError};
    use std::sync::{atomic::Ordering, Mutex};
    use uuid::Uuid;

    let source = DurableDelivery {
        recipient_id: RECIPIENT,
        message_id: Uuid::from_u128(50),
        claim_id: Some(CLAIM),
    };
    let original = "<message from='alice@remote.test/phone' to='bob@example.test' type='chat'><body>exact adapter bytes</body></message>";
    for (label, queue) in [
        ("owned_enqueue", QueueAnswer::Accepted),
        ("full_refusal", QueueAnswer::Full),
        ("closed_refusal", QueueAnswer::Closed),
    ] {
        let host = Host::new(State {
            queue,
            ..State::default()
        });
        let adapter = FederatedDirectRoute(&host);
        let (receipt, mut receipt_rx) = tokio::sync::mpsc::unbounded_channel();
        let mut item = OutboundItem::durable(original.to_owned(), source);
        item.transport_receipt = Some(receipt);
        let session = &host.state.sessions[0].1;
        let result = adapter.try_local(session, RouteEnqueue::unobserved(item));
        if queue == QueueAnswer::Accepted {
            assert!(result.is_ok(), "{label}: exact_enqueue");
        } else {
            let returned = match result {
                Err(RouteSendError::Full(item)) if queue == QueueAnswer::Full => item,
                Err(RouteSendError::Closed(item)) if queue == QueueAnswer::Closed => item,
                other => panic!("{label}: refusal changed: {other:?}"),
            };
            assert_eq!(returned.stanza, original, "{label}: refusal_bytes");
            assert_eq!(
                returned.c2s_delivery(),
                Some(source),
                "{label}: refusal_source"
            );
            returned
                .transport_receipt
                .as_ref()
                .unwrap()
                .send(())
                .unwrap();
            assert_eq!(
                receipt_rx.try_recv(),
                Ok(()),
                "{label}: refusal_retains_original_item"
            );
        }
        assert_eq!(
            host.state.events(),
            vec![Event::Local(
                session.connection_id,
                original.to_owned(),
                Some(source)
            )],
            "{label}: exact_enqueue_arguments"
        );
        adapter.record_local_accept(true);
        adapter.record_local_accept(false);
        adapter.post_accept_failed();
        assert_eq!(
            host.state.events(),
            vec![
                Event::FederationAccepted(true),
                Event::FederationAccepted(false),
                Event::PostAcceptFailed
            ],
            "{label}: federation_telemetry"
        );
        assert!(
            host.counters
                .iter()
                .all(|counter| counter.load(Ordering::Relaxed) == 0),
            "{label}: origin_telemetry"
        );
    }

    let (release, gate) = tokio::sync::oneshot::channel();
    let host = Host::new(State {
        remote_gate: Mutex::new(Some(gate)),
        remote_result: Mutex::new(OnlineRouteResult {
            delivered: true,
            accepted_full_jid: Some(format!("{TARGET}/remote")),
        }),
        ..State::default()
    });
    let adapter = FederatedDirectRoute(&host);
    let mut primary = Box::pin(adapter.route_remote_primary(TARGET, original, Some(source)));
    assert!(
        poll_once(primary.as_mut()).is_pending(),
        "pending_primary: forward_await"
    );
    assert_eq!(
        host.state.events(),
        vec![Event::Primary(
            TARGET.to_owned(),
            original.to_owned(),
            Some(source)
        )],
        "pending_primary: remote_primary_arguments"
    );
    release.send(()).unwrap();
    assert_eq!(
        primary.await,
        OnlineRouteResult {
            delivered: true,
            accepted_full_jid: Some(format!("{TARGET}/remote"))
        },
        "remote_receipt: accepted_resource"
    );
    *host.state.remote_result.lock().unwrap() = OnlineRouteResult {
        delivered: true,
        accepted_full_jid: None,
    };
    assert!(
        adapter
            .route_available_remote(TARGET, original, Some(source))
            .await,
        "remote_fanout: acceptance"
    );
    *host.state.remote_result.lock().unwrap() = OnlineRouteResult::default();
    assert!(
        !adapter.route_available_remote(TARGET, original, None).await,
        "remote_fanout_refusal: refusal"
    );
    adapter.rearm_direct_route(source).await;
    assert_eq!(
        host.state.events(),
        vec![
            Event::Available(TARGET.to_owned(), original.to_owned(), Some(source)),
            Event::Available(TARGET.to_owned(), original.to_owned(), None),
            Event::Rearm(source)
        ],
        "remote_fanout: exact_source_and_rearm"
    );

    for (label, history, expected) in [
        ("history_without_delivery", true, true),
        ("no_history_or_delivery", false, false),
    ] {
        let host = Host::new(State {
            mode: Mutex::new(DirectPostCommitMode::SpoolOnly),
            ..State::default()
        });
        let outcome = DirectMessageRouter::route_federated(
            &FederatedDirectRoute(&host),
            DirectRouteRequest {
                message_type: "chat",
                target: DirectRouteTarget::Bare(TARGET),
                sender: "alice@remote.test/phone",
                recipient_id: RECIPIENT,
                stanza: original,
                delivery: DirectRouteDelivery::Volatile,
                approved_targets: &[],
                enforce_direct_health: true,
            },
            history,
        )
        .await
        .unwrap();
        assert_eq!(
            matches!(outcome, DirectRouteOutcome::AcceptedForRecovery { .. }),
            expected,
            "{label}: independent_history_input"
        );
        if !history {
            assert_eq!(
                outcome,
                DirectRouteOutcome::Rejected(DirectRouteRejection::Unavailable),
                "{label}: health_enforced"
            );
        }
        assert_eq!(
            host.state.events(),
            vec![Event::Health],
            "{label}: no_route_or_manufactured_claim"
        );
    }

    for (label, kind, target, queue, remote, key, pending, degrade) in [
        (
            "approved_local",
            "chat",
            TARGET,
            QueueAnswer::Accepted,
            false,
            None,
            false,
            false,
        ),
        (
            "pending_remote",
            "chat",
            TARGET,
            QueueAnswer::Full,
            true,
            Some("bob@example.test/remote"),
            true,
            false,
        ),
        (
            "legacy_remote_receipt",
            "chat",
            TARGET,
            QueueAnswer::Closed,
            true,
            None,
            false,
            false,
        ),
        (
            "refused_routes",
            "chat",
            TARGET,
            QueueAnswer::Full,
            false,
            None,
            false,
            false,
        ),
        (
            "headline_fanout",
            "headline",
            TARGET,
            QueueAnswer::Accepted,
            true,
            None,
            false,
            false,
        ),
        (
            "full_resource_fallback",
            "chat",
            "bob@example.test/missing",
            QueueAnswer::Accepted,
            false,
            None,
            false,
            false,
        ),
        (
            "health_after_remote",
            "chat",
            TARGET,
            QueueAnswer::Closed,
            true,
            Some("bob@example.test/remote"),
            true,
            true,
        ),
    ] {
        let (release, gate) = tokio::sync::oneshot::channel();
        let host = Host::new(State {
            queue,
            archive: kind != "headline",
            remote_gate: Mutex::new(pending.then_some(gate)),
            remote_result: Mutex::new(OnlineRouteResult {
                delivered: remote,
                accepted_full_jid: key.map(str::to_owned),
            }),
            ..State::default()
        });
        let sender = "alice@remote.test/phone";
        let raw = format!("<message xmlns='jabber:client' from='{sender}' to='{target}' type='{kind}' id='remote-original'><body>federated bytes</body><stanza-id xmlns='urn:xmpp:sid:0' by='remote.test' id='remote-identity'/><stanza-id xmlns='urn:xmpp:sid:0' by='example.test' id='forged'/></message>");
        let document = Document::parse(&raw).unwrap();
        let mut route = Box::pin(route_inbound_message(
            &host,
            document.root_element(),
            &raw,
            sender,
            target,
            "remote.test",
        ));
        let mut events = Vec::new();
        if pending {
            assert!(
                poll_once(route.as_mut()).is_pending(),
                "{label}: caller_waits_for_owner"
            );
            events = host.state.events();
            assert!(
                !events.iter().any(|event| matches!(
                    event,
                    Event::Carbon(..) | Event::Push(_) | Event::Routed
                )),
                "{label}: no_followup_before_remote_receipt"
            );
            if degrade {
                *host.state.mode.lock().unwrap() = DirectPostCommitMode::SpoolOnly;
            }
            release.send(()).unwrap();
        }
        assert_eq!(route.await.unwrap(), None, "{label}: accepted_result");
        events.extend(host.state.events());
        let committed = host.state.committed.lock().unwrap().clone();
        let expected_source = committed.as_ref().map(|envelope| envelope.source);
        if let Some(envelope) = &committed {
            assert_eq!(envelope.actor, None, "{label}: remote_actor");
            assert_eq!(
                (&*envelope.sender, &*envelope.recipient),
                (sender, TARGET),
                "{label}: committed_address"
            );
            assert_eq!(
                (envelope.source.recipient_id, envelope.source.claim_id),
                (RECIPIENT, Some(envelope.source.message_id)),
                "{label}: original_source"
            );
            assert_eq!(envelope.archives.len(), 1, "{label}: original_archive");
            assert_eq!(
                (envelope.archives[0].0, envelope.archives[0].1),
                (envelope.source.message_id, RECIPIENT),
                "{label}: original_archive_identity"
            );
            let identity = envelope.identity.as_ref().unwrap();
            assert_eq!(
                (&*identity.0, &*identity.1, &*identity.2),
                ("remote.test", TARGET, "remote-identity"),
                "{label}: authenticated_identity"
            );
        } else {
            assert_eq!(kind, "headline", "{label}: durable_admission");
        }
        let mut routed_stanza = None;
        let mut local_connections = Vec::new();
        let mut accepted = 0;
        for event in &events {
            let (stanza, delivery) = match event {
                Event::Local(connection, stanza, delivery) => {
                    local_connections.push(*connection);
                    (stanza, delivery)
                }
                Event::Primary(jid, stanza, delivery) | Event::Available(jid, stanza, delivery) => {
                    let expected_target = if label == "full_resource_fallback" {
                        "bob@example.test/missing"
                    } else {
                        target
                    };
                    assert_eq!(jid, expected_target, "{label}: remote_target");
                    (stanza, delivery)
                }
                Event::FederationAccepted(durable) => {
                    assert_eq!(*durable, kind != "headline", "{label}: acceptance_kind");
                    accepted += 1;
                    continue;
                }
                Event::LocalAccepted(_) => panic!("{label}: client_origin_telemetry"),
                _ => continue,
            };
            assert_eq!(*delivery, expected_source, "{label}: exact_delivery_tuple");
            if let Some(original) = routed_stanza {
                assert_eq!(stanza, original, "{label}: one_annotated_envelope");
            } else {
                routed_stanza = Some(stanza);
            }
            let parsed = Document::parse(stanza).unwrap();
            assert_eq!(
                parsed.root_element().attribute("from"),
                Some(sender),
                "{label}: original_sender"
            );
            assert_eq!(
                parsed.root_element().attribute("to"),
                Some(target),
                "{label}: original_target"
            );
            assert_eq!(
                parsed.root_element().attribute("type"),
                Some(kind),
                "{label}: original_type"
            );
            assert!(!stanza.contains("forged"), "{label}: authoritative_stanza");
            if let Some(envelope) = &committed {
                assert_eq!(
                    stanza, &envelope.archives[0].3,
                    "{label}: committed_annotated_bytes"
                );
            }
        }
        let expected_connections = if label == "headline_fanout" || queue != QueueAnswer::Accepted {
            vec![Uuid::from_u128(21), Uuid::from_u128(22)]
        } else {
            vec![Uuid::from_u128(21)]
        };
        assert_eq!(
            local_connections, expected_connections,
            "{label}: approved_order_and_privacy"
        );
        let expected_accepts = if label == "headline_fanout" {
            2
        } else {
            usize::from(queue == QueueAnswer::Accepted)
        };
        assert_eq!(accepted, expected_accepts, "{label}: acceptance_count");
        let carbons: Vec<_> = events
            .iter()
            .filter_map(|event| match event {
                Event::Carbon(recipient, excluded, stanza) => Some((recipient, excluded, stanza)),
                _ => None,
            })
            .collect();
        let expected_key = if queue == QueueAnswer::Accepted && kind == "chat" {
            Some("bob@example.test/phone")
        } else {
            key
        };
        assert_eq!(
            carbons.len(),
            usize::from(expected_key.is_some() && !degrade),
            "{label}: optional_carbon_exclusion"
        );
        if let Some((recipient, excluded, stanza)) = carbons.first() {
            assert_eq!(recipient.as_str(), TARGET, "{label}: carbon_recipient");
            assert_eq!(
                excluded.as_deref(),
                expected_key,
                "{label}: accepted_resource_exclusion"
            );
            assert_eq!(
                *stanza,
                routed_stanza.unwrap(),
                "{label}: carbon_original_envelope"
            );
        }
        if label == "refused_routes" {
            assert!(
                events.contains(&Event::Rearm(expected_source.unwrap())),
                "{label}: exact_rearm"
            );
            assert!(
                events.contains(&Event::Push(RECIPIENT)),
                "{label}: accepted_recovery"
            );
        }
        if degrade {
            assert!(
                !events.iter().any(|event| matches!(
                    event,
                    Event::Carbon(..) | Event::Routed | Event::Push(_)
                )),
                "{label}: health_suppresses_followup"
            );
        }
        assert!(
            host.counters
                .iter()
                .all(|counter| counter.load(Ordering::Relaxed) == 0),
            "{label}: no_client_telemetry"
        );
    }

    // The request's recipient metadata is observable when an exact normal
    // resource disappears after commit: the fallback reports that account.
    #[derive(Clone, Default)]
    struct RecipientTrace(std::sync::Arc<Mutex<Vec<String>>>);
    struct RecipientField<'a>(&'a mut Vec<String>);
    impl tracing::field::Visit for RecipientField<'_> {
        fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
            if field.name() == "recipient_id" {
                self.0.push(format!("{value:?}"));
            }
        }
    }
    impl tracing::Subscriber for RecipientTrace {
        fn enabled(&self, _: &tracing::Metadata<'_>) -> bool {
            true
        }
        fn new_span(&self, _: &tracing::span::Attributes<'_>) -> tracing::span::Id {
            tracing::span::Id::from_u64(1)
        }
        fn record(&self, _: &tracing::span::Id, _: &tracing::span::Record<'_>) {}
        fn record_follows_from(&self, _: &tracing::span::Id, _: &tracing::span::Id) {}
        fn event(&self, event: &tracing::Event<'_>) {
            let mut recipients = self.0.lock().unwrap();
            event.record(&mut RecipientField(&mut recipients));
        }
        fn enter(&self, _: &tracing::span::Id) {}
        fn exit(&self, _: &tracing::span::Id) {}
    }
    let trace = RecipientTrace::default();
    let dispatcher = tracing::Dispatch::new(trace.clone());
    let host = Host::new(State::default());
    let raw = "<message xmlns='jabber:client' from='alice@remote.test/phone' to='bob@example.test/missing' type='normal'><body>original recipient</body></message>";
    let document = Document::parse(raw).unwrap();
    let mut route = Box::pin(route_inbound_message(
        &host,
        document.root_element(),
        raw,
        "alice@remote.test/phone",
        "bob@example.test/missing",
        "remote.test",
    ));
    let result = tracing::dispatcher::with_default(&dispatcher, || poll_once(route.as_mut()));
    let std::task::Poll::Ready(result) = result else {
        panic!("recipient_metadata: unexpected pending route")
    };
    assert_eq!(
        result.unwrap(),
        None,
        "recipient_metadata: accepted_for_recovery"
    );
    assert!(
        host.state.events().contains(&Event::PostAcceptFailed),
        "post_accept_failure: federation_callback"
    );
    let recipients = trace.0.lock().unwrap();
    assert!(
        !recipients.is_empty(),
        "recipient_metadata: fallback_reports_account"
    );
    assert!(
        recipients
            .iter()
            .all(|recipient| recipient == &RECIPIENT.to_string()),
        "recipient_metadata: original_recipient"
    );
}
