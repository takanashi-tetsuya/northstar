use super::actor_fixture::{durable, poll_once, request, submit, Harness};
use super::actor_host::{Event, ItemFacts, RecordCut, CONTENT_TYPE, DELIVERY_SESSION};
use super::replay_store::{Call, Outcome};
use super::response_body_text;
use crate::BOSH_BACKEND_OPERATION_TIMEOUT;
use northstar_delivery_core::bosh_ownership::{OperationKind, Terminal, TransferKnowledge};
use northstar_stream::outbound::{MixDelivery, MixTransportCompletion, OutboundItem};
use std::task::Poll;
use std::time::Duration;
use uuid::Uuid;

#[tokio::test(start_paused = true)]
async fn actor_times_out_each_selected_backend_child_at_five_seconds() {
    for label in [
        "request renewal",
        "outbound record",
        "delivery finishes held response",
        "held deadline",
    ] {
        let mut harness = Harness::new(1);
        let manager = harness.host.manager.clone();
        let mut response = None;
        let mut hold_deadline = None;
        let (kind, drop_marker) = match label {
            "request renewal" => {
                harness.host.replay.set_outcome("renew", Outcome::Pending);
                response = Some(submit(&manager, request(2, "", "")));
                (
                    OperationKind::Request,
                    Event::Replay(Call::Dropped("renew")),
                )
            }
            "outbound record" => {
                *harness.host.record_cut.lock().unwrap() = RecordCut::Pending;
                harness
                    .outbound
                    .try_send(OutboundItem::plain("<presence/>".to_owned()))
                    .unwrap();
                (OperationKind::Outbound, Event::Session("record dropped"))
            }
            "delivery finishes held response" => {
                response = Some(submit(&manager, request(2, "", "")));
                assert!(harness.pump());
                assert!(harness.actor.held.is_some());
                harness.host.replay.set_outcome("bind", Outcome::Pending);
                harness.outbound.try_send(durable(11001)).unwrap();
                (
                    OperationKind::HeldResponse,
                    Event::Replay(Call::Dropped("bind")),
                )
            }
            "held deadline" => {
                for (rid, id) in [(2, 11002), (3, 11003)] {
                    harness.queue(durable(id));
                    let reply = harness.respond(request(rid, "", ""));
                    assert!(response_body_text(&reply).contains(&format!("id='{id}'")));
                }
                assert_eq!(harness.actor.replay.len(), 2);
                assert!(harness
                    .actor
                    .replay
                    .iter()
                    .all(|cached| !cached.durable_ownership.is_empty()));
                response = Some(submit(&manager, request(4, "", "")));
                assert!(harness.pump());
                hold_deadline = Some(tokio::time::Instant::from_std(
                    harness.actor.held.as_ref().unwrap().deadline,
                ));
                // A full durable cache makes the timer's response preparation
                // await the real release port before reporting its limit.
                harness.host.replay.set_outcome("release", Outcome::Pending);
                (
                    OperationKind::HeldResponse,
                    Event::Replay(Call::Dropped("release")),
                )
            }
            _ => unreachable!(),
        };
        harness.host.trace.clear();
        let mut running = Box::pin(tokio::task::unconstrained(harness.actor.run_loop()));
        assert!(poll_once(running.as_mut()).is_pending(), "{label}");
        if let Some(deadline) = hold_deadline {
            // The actor's std::Instant deadline can have a sub-millisecond
            // offset. Await Tokio's timer at that same deadline so its rounded
            // expiration has fired before polling the actor and measuring the
            // separate backend budget. Paused time advances without a wall wait.
            tokio::time::sleep_until(deadline).await;
            assert!(poll_once(running.as_mut()).is_pending(), "{label}");
        }
        let entered = harness.host.trace.effects();
        assert!(!entered.contains(&drop_marker), "{label}");
        assert!(
            entered.iter().any(|event| match label {
                "request renewal" => matches!(event, Event::Replay(Call::Renew { .. })),
                "outbound record" => matches!(event, Event::Record(_)),
                "delivery finishes held response" =>
                    matches!(event, Event::Replay(Call::Bind { .. })),
                "held deadline" =>
                    matches!(event, Event::Replay(Call::Release(id)) if *id == DELIVERY_SESSION),
                _ => unreachable!(),
            }),
            "{label}"
        );

        tokio::time::advance(Duration::from_millis(4_999)).await;
        assert!(poll_once(running.as_mut()).is_pending(), "{label}");
        assert!(
            !harness.host.trace.effects().contains(&drop_marker),
            "{label}"
        );
        tokio::time::advance(Duration::from_millis(1)).await;
        assert!(poll_once(running.as_mut()).is_ready(), "{label}");
        drop(running);
        let operation = harness.operation();
        let facts = operation.snapshot();
        assert_eq!(facts.scope.kind, kind, "{label}");
        assert_eq!(facts.scope.session_id, DELIVERY_SESSION, "{label}");
        assert_eq!(facts.scope.ttl_seconds, 150, "{label}");
        assert_eq!(facts.terminal, Some(Terminal::TimedOut), "{label}");
        assert_eq!(facts.keep_running, None, "{label}");
        assert_eq!(BOSH_BACKEND_OPERATION_TIMEOUT, Duration::from_secs(5));
        let events = harness.host.trace.effects();
        let dropped = events
            .iter()
            .position(|event| event == &drop_marker)
            .expect(label);
        let forbidden = events
            .iter()
            .position(|event| event == &Event::Session("forbid resume"))
            .expect(label);
        assert!(
            dropped < forbidden,
            "{label}: child must be destroyed before the actor continues"
        );
        assert_eq!(
            events.iter().filter(|event| *event == &drop_marker).count(),
            1,
            "{label}"
        );
        if let Some(mut response) = response {
            let Poll::Ready(reply) = poll_once(response.as_mut()) else {
                panic!("{label}: responder retained by destroyed child")
            };
            assert!(
                response_body_text(&reply).contains("item-not-found"),
                "{label}"
            );
        }
        harness
            .host
            .replay
            .set_outcome("release", Outcome::Committed);
        harness.finish().await;
        assert_eq!(
            operation.snapshot(),
            facts,
            "{label}: cleanup rewrote operation facts"
        );
        drop(harness);
        assert_eq!(
            manager.inner.session_slots.available_permits(),
            1,
            "{label}"
        );
    }
}

#[tokio::test(start_paused = true)]
async fn request_and_outbound_children_use_the_actor_operation_created_before_io() {
    for label in ["request item", "outbound item"] {
        let mut harness = Harness::new(0);
        let source = MixDelivery {
            delivery_id: Uuid::from_u128(12001),
            lease_token: Uuid::from_u128(12002),
        };
        let (item, mut handoff) =
            OutboundItem::durable_mix("<message id='original'/>".to_owned(), source);
        let original = ItemFacts::new(&item);
        let kind = if label == "request item" {
            harness.host.frame_items.lock().unwrap().push(item);
            let reply = harness.respond(request(2, "", "<items/>"));
            assert!(
                response_body_text(&reply).contains(&original.stanza),
                "{label}"
            );
            OperationKind::Request
        } else {
            harness.queue(item);
            assert_eq!(harness.actor.output.len(), 1, "{label}");
            assert_eq!(
                harness.actor.output[0].stanza.as_ptr() as usize,
                original.pointer,
                "{label}"
            );
            OperationKind::Outbound
        };
        let operation = harness.operation();
        let snapshot = operation.snapshot();
        assert_eq!(snapshot.scope.kind, kind, "{label}");
        assert_eq!(snapshot.scope.session_id, DELIVERY_SESSION, "{label}");
        assert_eq!(snapshot.terminal, Some(Terminal::Returned), "{label}");
        assert_eq!(snapshot.keep_running, Some(true), "{label}");
        assert_eq!(snapshot.transfers.len(), 1, "{label}");
        let transfer = snapshot.transfers[0];
        assert_eq!(transfer.source, source, "{label}");
        assert_eq!(
            transfer.knowledge,
            TransferKnowledge::ReceiptKnown(MixDelivery {
                lease_token: Uuid::from_u128(9003),
                ..source
            }),
            "{label}"
        );
        assert!(
            transfer.source_applied && transfer.notification_attempted,
            "{label}"
        );
        assert_eq!(transfer.queue_accepted, Some(true), "{label}");
        assert_eq!(
            handoff.try_recv().unwrap(),
            MixTransportCompletion::BoshPersisted {
                session_id: DELIVERY_SESSION
            },
            "{label}"
        );
        let events = harness.host.trace.effects();
        let record = events
            .iter()
            .position(|event| event == &Event::Record(original.clone()))
            .expect(label);
        let transfer = events
            .iter()
            .position(|event| {
                event
                    == &Event::Transfer {
                        source,
                        session_id: DELIVERY_SESSION,
                        ttl_seconds: 150,
                    }
            })
            .expect(label);
        assert!(record < transfer, "{label}");
        if kind == OperationKind::Request {
            assert_eq!(snapshot.renewals.len(), 1, "{label}");
            assert_eq!(snapshot.responses[0].rid, 2, "{label}");
            assert!(snapshot.responses[0].cached, "{label}");
        } else {
            assert!(
                snapshot.renewals.is_empty() && snapshot.responses.is_empty(),
                "{label}"
            );
        }
        harness.finish().await;
    }
}

#[tokio::test(start_paused = true)]
async fn actor_outer_operation_observes_a_panic_on_the_childs_first_record_poll() {
    for (label, kind) in [
        ("request child panic", OperationKind::Request),
        ("outbound child panic", OperationKind::Outbound),
    ] {
        let mut harness = Harness::new(0);
        let manager = harness.host.manager.clone();
        *harness.host.record_cut.lock().unwrap() = RecordCut::Panic;
        let item = durable(12501);
        let original = ItemFacts::new(&item);
        let mut response = if kind == OperationKind::Request {
            harness.host.frame_items.lock().unwrap().push(item);
            Some(submit(&manager, request(2, "", "<items/>")))
        } else {
            harness.outbound.try_send(item).unwrap();
            None
        };
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| harness.pump()));
        let Err(panic) = result else {
            panic!("{label}: child did not panic")
        };
        assert_eq!(
            panic.downcast_ref::<&str>().copied(),
            Some("first record poll panicked"),
            "{label}"
        );
        let snapshot = harness.operation().snapshot();
        assert_eq!(snapshot.scope.kind, kind, "{label}");
        assert_eq!(snapshot.scope.session_id, DELIVERY_SESSION, "{label}");
        assert_eq!(snapshot.terminal, Some(Terminal::Panicked), "{label}");
        assert_eq!(snapshot.keep_running, None, "{label}");
        assert!(
            snapshot.transfers.is_empty() && snapshot.responses.is_empty(),
            "{label}"
        );
        assert!(
            harness
                .host
                .trace
                .effects()
                .contains(&Event::Record(original)),
            "{label}"
        );
        if let Some(response) = response.as_mut() {
            let Poll::Ready(reply) = poll_once(response.as_mut()) else {
                panic!("{label}: panicking child retained responder")
            };
            assert!(
                response_body_text(&reply).contains("item-not-found"),
                "{label}"
            );
        }
        harness.finish().await;
    }
}

#[tokio::test(start_paused = true)]
async fn actor_preserves_original_item_and_only_skips_record_supersession() {
    for label in [
        "successful transfer",
        "record superseded",
        "transfer superseded",
    ] {
        let mut harness = Harness::new(1);
        let manager = harness.host.manager.clone();
        let mut response = submit(&manager, request(2, "", ""));
        assert!(harness.pump());
        let source = MixDelivery {
            delivery_id: Uuid::from_u128(13001),
            lease_token: Uuid::from_u128(13002),
        };
        let (mut item, mut handoff) =
            OutboundItem::durable_mix("<message id='exact-item'/>".to_owned(), source);
        let (receipt, mut delivered) = tokio::sync::mpsc::unbounded_channel();
        item.transport_receipt = Some(receipt);
        let alias = item.clone();
        let original = ItemFacts::new(&item);
        if label == "record superseded" {
            *harness.host.record_cut.lock().unwrap() = RecordCut::Superseded;
        }
        *harness.host.mix.superseded.lock().unwrap() = label == "transfer superseded";
        harness.host.trace.clear();
        harness.outbound.try_send(item).unwrap();
        assert_eq!(harness.pump(), label != "transfer superseded", "{label}");
        let Poll::Ready(reply) = poll_once(response.as_mut()) else {
            panic!("{label}: missing held response")
        };
        assert_eq!(reply.content_type, CONTENT_TYPE, "{label}");
        let events = harness.host.trace.effects();
        assert_eq!(events[0], Event::Csi(original.clone()), "{label}");
        assert_eq!(events[1], Event::Record(original.clone()), "{label}");
        let transfers = events
            .iter()
            .filter(|event| matches!(event, Event::Transfer { .. }))
            .count();
        assert_eq!(
            transfers,
            usize::from(label != "record superseded"),
            "{label}"
        );
        if label == "successful transfer" {
            assert_eq!(
                events[2],
                Event::Transfer {
                    source,
                    session_id: DELIVERY_SESSION,
                    ttl_seconds: 150
                },
                "{label}"
            );
            assert!(
                response_body_text(&reply).contains(&original.stanza),
                "{label}"
            );
            assert_eq!(
                handoff.try_recv().unwrap(),
                MixTransportCompletion::BoshPersisted {
                    session_id: DELIVERY_SESSION
                }
            );
            assert_eq!(
                harness.actor.replay[0].durable_ownership.mix_delivery_ids,
                [source.delivery_id]
            );
            let acknowledged = harness.respond(request(3, "ack='2' pause='1'", ""));
            assert!(!response_body_text(&acknowledged).contains("type='terminate'"));
            delivered.try_recv().unwrap();
        } else {
            assert!(
                !response_body_text(&reply).contains(&original.stanza),
                "{label}"
            );
            assert!(handoff.try_recv().is_err(), "{label}");
            assert!(delivered.try_recv().is_err(), "{label}");
            assert_eq!(
                response_body_text(&reply).contains("policy-violation"),
                label == "transfer superseded",
                "{label}"
            );
            assert_eq!(
                harness.actor.replay.len(),
                usize::from(label == "record superseded"),
                "{label}"
            );
            assert_eq!(
                events.contains(&Event::Session("forbid resume")),
                label == "transfer superseded",
                "{label}"
            );
        }
        harness.finish().await;
        assert!(!harness.registered(), "{label}");
        drop(alias);
    }
}
