use super::actor_fixture::{durable, http, poll_once, request, Harness, SID};
use super::actor_host::{Event, PublicationCut, CONNECTION, CONTENT_TYPE, DELIVERY_SESSION};
use super::replay_store::{Call, Outcome};
use super::response_body_text;
use crate::BoshCommand;
use northstar_auth_application::authentication::publication::{Knowledge, Terminal, Transport};
use northstar_delivery_core::bosh_ownership::OperationKind;
use northstar_stream::auth_publication::fixture::fixture_control;
use northstar_stream::auth_publication::AuthReplies;
use northstar_stream::outbound::OutboundItem;
use northstar_stream::transport::Action;
use std::cmp::Reverse;
use std::task::Poll;
use std::time::{Duration, Instant};
use tokio::sync::mpsc;
use uuid::Uuid;

#[tokio::test(start_paused = true)]
async fn selected_authentication_publishes_in_fifo_after_exposure_and_before_cache_bookkeeping() {
    for label in [
        "accepted publication",
        "first publication rejected",
        "second publication rejected",
        "closed responder",
    ] {
        let mut harness = Harness::new(0);
        let mut controls = [
            (
                "<success xmlns='urn:xmpp:sasl:2' id='alpha'/>",
                fixture_control("<success xmlns='urn:xmpp:sasl:2' id='alpha'/>", CONNECTION),
            ),
            (
                "<success xmlns='urn:xmpp:sasl:2' id='bravo'/>",
                fixture_control("<success xmlns='urn:xmpp:sasl:2' id='bravo'/>", CONNECTION),
            ),
        ];
        // Make FIFO oppose the holder lock order regardless of opaque fixture IDs.
        controls.sort_by_key(|(_, (_, observation))| Reverse(observation.snapshot().control));
        let mut observations = Vec::new();
        let mut joins = Vec::new();
        let mut payload = "<presence id='prefix'/>".to_owned();
        harness.queue(OutboundItem::plain(payload.clone()));
        let operation = harness
            .actor
            .begin_ownership_operation(OperationKind::Request);
        for (control, (holder, observation)) in controls {
            payload.push_str(control);
            payload.push_str("<features/>");
            joins.push(holder.join_observation());
            observations.push(observation);
            assert!(
                harness
                    .actor
                    .apply_action(
                        Action::SendManyThenActivate(AuthReplies {
                            replies: vec![control.to_owned(), "<features/>".to_owned()],
                            holder,
                        }),
                        &operation,
                    )
                    .await,
                "{label}"
            );
        }
        let (receipt, mut received) = mpsc::unbounded_channel();
        let mut item = durable(9301);
        let source = item.durable_source.unwrap();
        payload.push_str(&item.stanza);
        item.transport_receipt = Some(receipt);
        harness.queue(item);
        assert!(
            observations.iter().all(|observation| {
                let snapshot = observation.snapshot();
                snapshot.transport == Transport::Recording
                    && snapshot.publication == Knowledge::NotStarted
                    && snapshot.terminal.is_none()
            }),
            "{label}: FIFO admission cannot publish authentication"
        );
        assert!(
            !harness
                .host
                .trace
                .effects()
                .iter()
                .any(|event| matches!(event, Event::Publish { .. })),
            "{label}"
        );
        let cuts = match label {
            "accepted publication" => vec![PublicationCut::Gated, PublicationCut::Pass],
            "first publication rejected" => vec![PublicationCut::Reject],
            "second publication rejected" => vec![PublicationCut::Pass, PublicationCut::Reject],
            _ => vec![],
        };
        harness.host.publication_cuts.lock().unwrap().extend(cuts);
        harness.host.trace.clear();
        harness.actor.last_response = Instant::now() - Duration::from_secs(1);
        let before = harness.actor.last_response;
        let expected_body =
            format!("<body xmlns='http://jabber.org/protocol/httpbind'>{payload}</body>");
        let mut response = Some(Box::pin(http(
            harness.host.clone(),
            format!("<body xmlns='http://jabber.org/protocol/httpbind' rid='2' sid='{SID}'/>"),
        )));
        assert!(
            poll_once(response.as_mut().unwrap().as_mut()).is_pending(),
            "{label}"
        );
        let BoshCommand::Request {
            request: incoming,
            response: responder,
        } = harness.actor.commands.try_recv().unwrap()
        else {
            panic!("{label}: HTTP ingress did not enqueue its request")
        };
        let fingerprint = incoming.fingerprint;
        let replay_request = (*incoming).clone();
        if label == "closed responder" {
            drop(response.take());
        }
        let operation = harness
            .actor
            .begin_ownership_operation(OperationKind::Request);
        let mut continuation = Box::pin(
            harness
                .actor
                .accept_request(*incoming, responder, &operation),
        );
        let first_poll = poll_once(continuation.as_mut());
        if label == "accepted publication" {
            assert!(first_poll.is_pending(), "{label}");
            let snapshot = operation.snapshot();
            let selected = &snapshot.responses[0];
            assert!(selected.exposure_entered, "{label}");
            assert_eq!(selected.accepted_responders, 1, "{label}");
            assert!(!selected.bookkeeping && !selected.cached, "{label}");
            assert_eq!(
                harness
                    .host
                    .trace
                    .effects()
                    .iter()
                    .filter(|event| matches!(event, Event::Publish { .. }))
                    .count(),
                1,
                "{label}: publication must remain sequential"
            );
            assert!(
                observations.iter().all(|observation| {
                    matches!(
                        observation.snapshot().transport,
                        Transport::BoshAccepted { rid: 2 }
                    )
                }),
                "{label}"
            );
        } else {
            assert_eq!(first_poll, Poll::Ready(false), "{label}");
        }
        // The actual HTTP handler can complete while publication is still gated.
        if let Some(response) = response.as_mut() {
            let Poll::Ready((status, body)) = poll_once(response.as_mut()) else {
                panic!("{label}: publication ran before exposing the HTTP response")
            };
            assert_eq!(status, axum::http::StatusCode::OK, "{label}");
            assert_eq!(body, expected_body, "{label}");
        }
        assert!(
            received.try_recv().is_err(),
            "{label}: exposure cannot acknowledge a durable item"
        );
        if label == "accepted publication" {
            harness.host.publication_gate.add_permits(1);
            assert_eq!(
                poll_once(continuation.as_mut()),
                Poll::Ready(true),
                "{label}"
            );
        }
        drop(continuation);
        let effects = harness.host.trace.effects();
        assert!(
            matches!(&effects[0], Event::Replay(Call::Renew { session_id, ttl_seconds: 150, expected: None, .. }) if *session_id == DELIVERY_SESSION),
            "{label}"
        );
        assert_eq!(effects[1], Event::Replay(Call::Dropped("renew")), "{label}");
        assert!(
            matches!(&effects[2], Event::Replay(Call::Bind { session_id, rid: 2, ttl_seconds: 150, sources, .. }) if *session_id == DELIVERY_SESSION && sources == &[source]),
            "{label}"
        );
        assert_eq!(effects[3], Event::Replay(Call::Dropped("bind")), "{label}");
        let attempted = match label {
            "closed responder" => 0,
            "first publication rejected" => 1,
            _ => 2,
        };
        let mut expected_publications = vec![];
        for (index, observation) in observations.iter().enumerate().take(attempted) {
            let control = observation.snapshot().control;
            expected_publications.push(Event::Publish {
                connection: CONNECTION,
                control,
                transport: Transport::BoshAccepted { rid: 2 },
            });
            expected_publications.push(Event::Published {
                control,
                succeeded: label == "accepted publication" || index + 1 < attempted,
            });
        }
        assert_eq!(&effects[4..], expected_publications.as_slice(), "{label}");
        let snapshot = operation.snapshot();
        let selected = &snapshot.responses[0];
        assert_eq!(
            selected.bookkeeping,
            label == "accepted publication",
            "{label}"
        );
        assert_eq!(selected.cached, label == "accepted publication", "{label}");
        assert_eq!(selected.responder_calls, 1, "{label}");
        assert_eq!(
            selected.refused_responders,
            usize::from(label == "closed responder"),
            "{label}"
        );
        for (index, observation) in observations.iter().enumerate() {
            let facts = observation.snapshot();
            if label == "accepted publication"
                || (label == "second publication rejected" && index == 0)
            {
                assert!(observation.completed(), "{label}");
            } else if index < attempted {
                assert_eq!(facts.terminal, Some(Terminal::Failed), "{label}");
            } else if label == "closed responder" {
                assert_eq!(
                    facts.transport,
                    Transport::BoshRefused { rid: 2 },
                    "{label}"
                );
            } else {
                assert_eq!(
                    facts.terminal,
                    Some(Terminal::ExposedNotAttempted),
                    "{label}"
                );
                assert_eq!(facts.publication, Knowledge::NotStarted, "{label}");
            }
            assert_eq!(
                joins[index].snapshot().transferred.is_some(),
                label != "closed responder",
                "{label}"
            );
        }
        if label == "accepted publication" {
            assert_eq!(harness.actor.highest_responded, 2, "{label}");
            assert!(harness.actor.last_response > before, "{label}");
            assert_eq!(harness.actor.replay.len(), 1, "{label}");
            let cached = &harness.actor.replay[0];
            assert_eq!(cached.rid, 2, "{label}");
            assert_eq!(cached.fingerprint, fingerprint, "{label}");
            assert_eq!(cached.response.content_type, CONTENT_TYPE, "{label}");
            assert_eq!(
                response_body_text(&cached.response),
                expected_body,
                "{label}"
            );
            assert_eq!(
                cached.durable_ownership.c2s_message_ids,
                [Uuid::from_u128(9301)],
                "{label}"
            );
            assert!(
                cached.durable_ownership.mix_delivery_ids.is_empty(),
                "{label}"
            );
            assert_eq!(cached.transport_receipts.len(), 1, "{label}");
            assert_eq!(
                response_body_text(&harness.respond(replay_request)),
                expected_body,
                "{label}"
            );
            assert_eq!(
                harness
                    .host
                    .trace
                    .effects()
                    .iter()
                    .filter(|event| matches!(event, Event::Publish { .. }))
                    .count(),
                2,
                "{label}: cached replay cannot republish"
            );
            let ack = harness.respond(request(3, "ack='2' pause='1'", ""));
            assert!(!response_body_text(&ack).contains("terminate"), "{label}");
            received.try_recv().unwrap();
        } else {
            assert_eq!(harness.actor.highest_responded, 1, "{label}");
            assert_eq!(harness.actor.last_response, before, "{label}");
            assert!(harness.actor.replay.is_empty(), "{label}");
        }
        assert!(harness.actor.output.is_empty(), "{label}");
        assert_eq!(harness.actor.output_bytes, 0, "{label}");
        harness.finish().await;
        let (status, body) = http(
            harness.host.clone(),
            format!("<body xmlns='http://jabber.org/protocol/httpbind' rid='4' sid='{SID}'/>"),
        )
        .await;
        assert_eq!(status, axum::http::StatusCode::OK, "{label}");
        assert!(body.contains("condition='item-not-found'"), "{label}");
    }
}

#[tokio::test(start_paused = true)]
async fn response_connection_and_bind_failures_prevent_exposure_publication_and_caching() {
    for label in ["foreign connection", "bind rejected"] {
        let mut harness = Harness::new(0);
        let control = "<success xmlns='urn:xmpp:sasl:2'/>";
        let (holder, observation) = fixture_control(
            control,
            if label == "foreign connection" {
                Uuid::from_u128(9302)
            } else {
                CONNECTION
            },
        );
        harness.queue(
            OutboundItem::plain(control.to_owned())
                .with_auth_publication(holder)
                .unwrap(),
        );
        harness.queue(durable(9303));
        if label == "bind rejected" {
            harness.host.replay.set_outcome("bind", Outcome::Rejected);
        }
        let before = harness.actor.last_response;
        let mut response = Box::pin(http(
            harness.host.clone(),
            format!("<body xmlns='http://jabber.org/protocol/httpbind' rid='2' sid='{SID}'/>"),
        ));
        assert!(poll_once(response.as_mut()).is_pending(), "{label}");
        assert!(!harness.pump(), "{label}");
        let Poll::Ready((status, body)) = poll_once(response.as_mut()) else {
            panic!("{label}: failed actor retained the HTTP response")
        };
        assert_eq!(status, axum::http::StatusCode::OK, "{label}");
        assert!(
            body.contains(if label == "foreign connection" {
                "condition='item-not-found'"
            } else {
                "condition='internal-server-error'"
            }),
            "{label}"
        );
        assert!(!body.contains(control), "{label}");
        assert_eq!(
            observation.snapshot().publication,
            Knowledge::NotStarted,
            "{label}"
        );
        assert_eq!(
            observation.snapshot().transport,
            Transport::NotStarted,
            "{label}"
        );
        assert!(
            !harness
                .host
                .trace
                .effects()
                .iter()
                .any(|event| matches!(event, Event::Publish { .. })),
            "{label}"
        );
        assert!(harness.actor.replay.is_empty(), "{label}");
        assert_eq!(harness.actor.highest_responded, 1, "{label}");
        assert_eq!(harness.actor.last_response, before, "{label}");
        let snapshot = harness.operation().snapshot();
        assert!(
            snapshot.responses.iter().all(|response| {
                !response.exposure_entered && !response.cached && !response.bookkeeping
            }),
            "{label}"
        );
        harness.finish().await;
    }
}

#[tokio::test(start_paused = true)]
async fn response_size_selection_leaves_later_authentication_unpublished_until_its_own_rid() {
    let mut harness = Harness::new(0);
    harness.actor.max_response_bytes = 320;
    let controls = [
        "<success xmlns='urn:xmpp:sasl:2' id='first-selected-control'/>",
        "<success xmlns='urn:xmpp:sasl:2' id='later-unselected-control'/>",
    ];
    let mut observations = Vec::new();
    for control in controls {
        let (holder, observation) = fixture_control(control, CONNECTION);
        observations.push(observation);
        let operation = harness
            .actor
            .begin_ownership_operation(OperationKind::Request);
        assert!(
            harness
                .actor
                .apply_action(
                    Action::SendManyThenActivate(AuthReplies {
                        replies: vec![control.to_owned()],
                        holder,
                    }),
                    &operation,
                )
                .await
        );
    }
    let first = harness.respond(request(2, "", ""));
    assert!(response_body_text(&first).contains(controls[0]));
    assert!(!response_body_text(&first).contains(controls[1]));
    assert!(observations[0].completed());
    assert_eq!(
        observations[1].snapshot().publication,
        Knowledge::NotStarted
    );
    assert_eq!(observations[1].snapshot().transport, Transport::Recording);
    assert_eq!(harness.actor.output.len(), 1);
    assert_eq!(harness.actor.output[0].stanza, controls[1]);
    let second = harness.respond(request(3, "ack='2'", ""));
    assert!(response_body_text(&second).contains(controls[1]));
    assert!(!response_body_text(&second).contains(controls[0]));
    assert!(observations[1].completed());
    assert_eq!(
        observations[1].snapshot().transport,
        Transport::BoshAccepted { rid: 3 }
    );
    let publications = harness
        .host
        .trace
        .effects()
        .into_iter()
        .filter(|event| matches!(event, Event::Publish { .. }))
        .collect::<Vec<_>>();
    assert_eq!(
        publications,
        vec![
            Event::Publish {
                connection: CONNECTION,
                control: observations[0].snapshot().control,
                transport: Transport::BoshAccepted { rid: 2 },
            },
            Event::Publish {
                connection: CONNECTION,
                control: observations[1].snapshot().control,
                transport: Transport::BoshAccepted { rid: 3 },
            },
        ]
    );
    assert_eq!(harness.actor.replay.len(), 1);
    assert_eq!(harness.actor.replay[0].rid, 3);
    harness.finish().await;
}
