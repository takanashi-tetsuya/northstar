use super::actor_fixture::{durable, http, poll_once, request, submit, Harness};
use super::actor_host::{Event, TestHost, CONTENT_TYPE, DELIVERY_SESSION};
use super::replay_store::{Call, Outcome};
use super::response_body_text;
use crate::{PendingRequest, BOSH_BACKEND_OPERATION_TIMEOUT};
use northstar_delivery_core::bosh_ownership::{
    response::{Knowledge, ResponseKind},
    OperationKind, Terminal,
};
use northstar_stream::outbound::OutboundItem;
use sha1::{Digest, Sha1};
use std::fmt::Write as _;
use std::task::Poll;
use std::time::{Duration, Instant};
use tokio::sync::{mpsc, oneshot};

const KEY: &str = "0000000000000000000000000000000000000001";
const NEXT_KEY: &str = "0000000000000000000000000000000000000002";

fn key_hash() -> String {
    let mut hash = String::with_capacity(40);
    for byte in Sha1::digest(KEY.as_bytes()) {
        write!(&mut hash, "{byte:02x}").unwrap();
    }
    hash
}

fn receipt_pending(receiver: &mut mpsc::UnboundedReceiver<()>, label: &str) {
    assert!(
        matches!(receiver.try_recv(), Err(mpsc::error::TryRecvError::Empty)),
        "{label}"
    );
}

fn methods(calls: &[Call]) -> Vec<&'static str> {
    calls
        .iter()
        .filter_map(|call| match call {
            Call::Bind { .. } => Some("bind"),
            Call::Renew { .. } => Some("renew"),
            Call::Acknowledge { .. } => Some("acknowledge"),
            Call::Release(_) => Some("release"),
            Call::Dropped(_) => None,
        })
        .collect()
}

#[tokio::test(start_paused = true)]
async fn response_preparation_uses_actor_fields_and_only_caches_ordinary_requested_responses() {
    for (label, cache, condition, pause) in [
        ("cache ordinary response", true, None, None),
        ("uncached ordinary response", false, None, None),
        (
            "terminal suppresses cache",
            true,
            Some("remote-stream-error"),
            None,
        ),
        (
            "uncached terminal",
            false,
            Some("remote-stream-error"),
            None,
        ),
        ("pause suppresses cache", true, None, Some(10)),
        ("uncached pause", false, None, Some(10)),
        (
            "terminal pause suppresses cache",
            true,
            Some("remote-stream-error"),
            Some(10),
        ),
        (
            "uncached terminal pause",
            false,
            Some("remote-stream-error"),
            Some(10),
        ),
    ] {
        let mut harness = Harness::new(0);
        let prefix = harness.respond(request(2, "", ""));
        let prefix_pointer = harness.actor.replay[0].response.body.as_ptr();
        let item = durable(14001);
        let source = item.durable_source.unwrap();
        let stanza = item.stanza.clone();
        harness.queue(item);
        harness.queue(OutboundItem::plain("<presence id='tail'/>".to_owned()));
        let mut pending = request(3, "", "");
        pending.pause = pause;
        let fingerprint = pending.fingerprint;
        let (sender, mut receiver) = oneshot::channel();
        let (buffered_sender, _buffered_receiver) = oneshot::channel();
        harness.actor.next_rid = 4;
        harness.actor.highest_received = 4;
        harness.actor.buffered.insert(
            4,
            PendingRequest {
                request: request(4, "", ""),
                responders: vec![buffered_sender],
            },
        );
        harness.host.trace.clear();
        let operation = harness
            .actor
            .begin_ownership_operation(OperationKind::Request);
        assert!(
            harness
                .actor
                .finish_pending(
                    PendingRequest {
                        request: pending,
                        responders: vec![sender]
                    },
                    condition,
                    cache,
                    &operation,
                )
                .await,
            "{label}"
        );
        let response = receiver.try_recv().unwrap();
        let body = response_body_text(&response);
        let document = roxmltree::Document::parse(body).unwrap();
        let root = document.root_element();
        assert_eq!(
            root.attribute("ack"),
            condition.is_none().then_some("4"),
            "{label}"
        );
        assert_eq!(root.attribute("condition"), condition, "{label}");
        assert_eq!(
            root.attribute("type"),
            condition.map(|_| "terminate"),
            "{label}"
        );
        assert!(
            body.contains(&stanza) && body.contains("id='tail'"),
            "{label}"
        );
        assert_eq!(response.content_type, CONTENT_TYPE, "{label}");
        assert!(harness.actor.output.is_empty(), "{label}");
        assert_eq!(harness.actor.output_bytes, 0, "{label}");
        assert_eq!(harness.actor.highest_responded, 3, "{label}");
        let should_cache = cache && condition.is_none() && pause.is_none();
        assert_eq!(
            harness.actor.replay.len(),
            1 + usize::from(should_cache),
            "{label}"
        );
        assert_eq!(
            harness.actor.replay[0].response.body.as_ptr(),
            prefix_pointer,
            "{label}"
        );
        assert_eq!(
            harness.actor.replay[0].response.body, prefix.body,
            "{label}"
        );
        if should_cache {
            let cached = &harness.actor.replay[1];
            assert_eq!(cached.rid, 3, "{label}");
            assert_eq!(cached.fingerprint, fingerprint, "{label}");
            assert_eq!(
                cached.response.body.as_ptr(),
                response.body.as_ptr(),
                "{label}"
            );
            assert_eq!(cached.response_bytes, response.body.len(), "{label}");
            assert_eq!(
                cached.durable_ownership.c2s_message_ids,
                [source.c2s().unwrap().message_id],
                "{label}"
            );
        }
        let calls = harness.host.trace.effects();
        assert!(
            matches!(&calls[..], [Event::Replay(Call::Bind {
            session_id, rid: 3, ttl_seconds: 150, sources, ..
        }), Event::Replay(Call::Dropped("bind"))] if *session_id == DELIVERY_SESSION && sources == &[source]),
            "{label}: {calls:?}"
        );
        let facts = operation.snapshot();
        assert_eq!(facts.responses.len(), 1, "{label}");
        assert_eq!(facts.responses[0].rid, 3, "{label}");
        assert!(facts.responses[0].bookkeeping, "{label}");
        assert_eq!(facts.responses[0].cached, should_cache, "{label}");
        harness.finish().await;
    }
}

#[tokio::test(start_paused = true)]
async fn invalid_client_ack_is_rejected_before_cached_replay_or_rid_classification() {
    for (label, rid) in [
        ("cached RID", 2),
        ("fresh RID", 3),
        ("outside RID window", 20),
    ] {
        let mut harness = Harness::new(0);
        harness.queue(durable(15001));
        harness.respond(request(2, "", ""));
        let cached_pointer = harness.actor.replay[0].response.body.as_ptr();
        let call_count = harness.host.replay.calls().len();
        harness.host.trace.clear();
        let response = harness.respond(request(rid, "ack='3'", ""));
        assert!(
            response_body_text(&response).contains("condition='bad-request'"),
            "{label}"
        );
        assert_eq!(harness.host.replay.calls().len(), call_count, "{label}");
        assert_eq!(harness.actor.next_rid, 3, "{label}");
        assert_eq!(harness.actor.highest_received, 2, "{label}");
        assert_eq!(harness.actor.highest_responded, 2, "{label}");
        assert_eq!(harness.actor.replay.len(), 1, "{label}");
        assert_eq!(
            harness.actor.replay[0].response.body.as_ptr(),
            cached_pointer,
            "{label}"
        );
        assert_eq!(harness.actor.replay[0].replays, 0, "{label}");
        let facts = harness.operation().snapshot();
        assert!(
            facts.responses.is_empty(),
            "{label}: cached replay ran before ACK validation"
        );
        assert!(
            facts.renewals.is_empty() && facts.acknowledgements.is_empty(),
            "{label}"
        );
        assert_eq!(facts.terminal, Some(Terminal::Returned), "{label}");
        assert_eq!(facts.keep_running, Some(false), "{label}");
        assert_eq!(
            harness.host.trace.effects(),
            [Event::Session("forbid resume")],
            "{label}"
        );
        harness.finish().await;
    }
}

#[tokio::test(start_paused = true)]
async fn fresh_request_checks_key_and_shape_then_renews_before_applying_ack() {
    for label in [
        "bad key",
        "bad shape",
        "renewal failure",
        "ACK failure",
        "valid key and shape",
    ] {
        let mut harness = Harness::new(0);
        let (receipt, mut received) = mpsc::unbounded_channel();
        let mut item = durable(16001);
        item.transport_receipt = Some(receipt);
        harness.queue(item);
        harness.respond(request(2, "", ""));
        let prefix_pointer = harness.actor.replay[0].response.body.as_ptr();
        let expected_key = key_hash();
        harness.actor.expected_key = Some(expected_key.clone());
        if label == "renewal failure" {
            harness.host.replay.set_outcome("renew", Outcome::Rejected);
        }
        if label == "ACK failure" {
            harness
                .host
                .replay
                .set_outcome("acknowledge", Outcome::Rejected);
        }
        let key = if label == "bad key" { NEXT_KEY } else { KEY };
        let shape = if label == "bad shape" {
            "to='example.test'"
        } else {
            ""
        };
        let call_count = harness.host.replay.calls().len();
        harness.host.trace.clear();
        let response = harness.respond(request(
            3,
            &format!("key='{key}' newkey='{NEXT_KEY}' ack='2' pause='10' {shape}"),
            "",
        ));
        let calls = harness.host.replay.calls();
        let actual_methods = methods(&calls[call_count..]);
        let expected_methods: &[&str] = match label {
            "bad key" | "bad shape" => &[],
            "renewal failure" => &["renew"],
            _ => &["renew", "acknowledge"],
        };
        assert_eq!(actual_methods, expected_methods, "{label}");
        let condition = match label {
            "bad key" => Some("item-not-found"),
            "bad shape" => Some("bad-request"),
            "renewal failure" | "ACK failure" => Some("internal-server-error"),
            _ => None,
        };
        let document = roxmltree::Document::parse(response_body_text(&response)).unwrap();
        assert_eq!(
            document.root_element().attribute("condition"),
            condition,
            "{label}"
        );
        assert_eq!(
            harness.actor.expected_key.as_deref(),
            Some(if label == "bad key" {
                expected_key.as_str()
            } else {
                NEXT_KEY
            }),
            "{label}"
        );
        if label == "valid key and shape" {
            received.try_recv().unwrap();
            assert!(received.try_recv().is_err());
            assert!(harness.actor.replay.is_empty());
            assert_eq!(harness.actor.active_inactivity, Duration::from_secs(10));
        } else {
            receipt_pending(&mut received, label);
            assert_eq!(harness.actor.replay.len(), 1, "{label}");
            assert_eq!(
                harness.actor.replay[0].response.body.as_ptr(),
                prefix_pointer,
                "{label}"
            );
        }
        let facts = harness.operation().snapshot();
        assert_eq!(facts.scope.kind, OperationKind::Request, "{label}");
        assert_eq!(
            facts.keep_running,
            Some(label == "valid key and shape"),
            "{label}"
        );
        assert!(
            !harness.host.trace.effects().iter().any(|event| matches!(
                event,
                Event::Frame(_)
                    | Event::Record(_)
                    | Event::RecordStanza(_)
                    | Event::Transfer { .. }
            )),
            "{label}"
        );
        harness.finish().await;
    }
}

#[tokio::test(start_paused = true)]
async fn actor_ack_uses_its_cache_and_operation_after_the_exact_renewal_and_ack_return() {
    let mut harness = Harness::new(0);
    let (first_receipt, mut first) = mpsc::unbounded_channel();
    let (second_receipt, mut second) = mpsc::unbounded_channel();
    for (rid, id, receipt) in [(2, 17001, first_receipt), (3, 17002, second_receipt)] {
        let mut item = durable(id);
        item.transport_receipt = Some(receipt);
        harness.queue(item);
        harness.respond(request(rid, "", ""));
    }
    let remaining_pointer = harness.actor.replay[1].response.body.as_ptr();
    let renewal_gate = harness.host.replay.gate("renew");
    let ack_gate = harness.host.replay.gate("acknowledge");
    let manager = harness.host.manager.clone();
    let mut response = submit(&manager, request(4, "ack='2' pause='10'", ""));
    harness.host.trace.clear();
    let mut running = Box::pin(tokio::task::unconstrained(harness.actor.run_loop()));
    assert!(poll_once(running.as_mut()).is_pending());
    receipt_pending(&mut first, "renewal pending");
    receipt_pending(&mut second, "renewal pending");
    assert!(poll_once(response.as_mut()).is_pending());
    assert!(
        matches!(&harness.host.trace.effects()[..], [Event::Replay(Call::Renew {
        session_id, ttl_seconds: 150, expected: None, ..
    })] if *session_id == DELIVERY_SESSION)
    );
    renewal_gate.add_permits(1);
    assert!(poll_once(running.as_mut()).is_pending());
    receipt_pending(&mut first, "ACK pending");
    receipt_pending(&mut second, "ACK pending");
    assert!(poll_once(response.as_mut()).is_pending());
    assert!(matches!(&harness.host.trace.effects()[..], [
        Event::Replay(Call::Renew { .. }), Event::Replay(Call::Dropped("renew")),
        Event::Replay(Call::Acknowledge { session_id, rid: 2, .. })
    ] if *session_id == DELIVERY_SESSION));
    ack_gate.add_permits(1);
    assert!(poll_once(running.as_mut()).is_pending());
    drop(running);
    let Poll::Ready(reply) = poll_once(response.as_mut()) else {
        panic!("pause was not answered after ACK return")
    };
    assert_eq!(
        response_body_text(&reply),
        "<body xmlns='http://jabber.org/protocol/httpbind'/>"
    );
    first.try_recv().unwrap();
    assert!(first.try_recv().is_err());
    receipt_pending(&mut second, "newer response retained");
    assert_eq!(harness.actor.replay.len(), 1);
    assert_eq!(harness.actor.replay[0].rid, 3);
    assert_eq!(
        harness.actor.replay[0].response.body.as_ptr(),
        remaining_pointer
    );
    let facts = harness.operation().snapshot();
    assert_eq!(facts.scope.session_id, DELIVERY_SESSION);
    assert_eq!(facts.scope.kind, OperationKind::Request);
    assert_eq!(facts.terminal, Some(Terminal::Returned));
    assert_eq!(facts.keep_running, Some(true));
    assert_eq!(facts.renewals.len(), 1);
    assert_eq!(facts.renewals[0].knowledge, Knowledge::ReceiptKnown);
    assert!(facts.renewals[0].returned && facts.renewals[0].ack_issued);
    assert_eq!(facts.acknowledgements.len(), 1);
    let ack = &facts.acknowledgements[0];
    assert_eq!(ack.rid, 2);
    assert_eq!(ack.knowledge, Knowledge::ReceiptKnown);
    assert!(ack.returned && ack.return_matches);
    assert_eq!(ack.cache_evictions, 1);
    assert_eq!(ack.receipt_calls, 1);
    assert_eq!(ack.receipts_sent, 1);
    assert_eq!(facts.responses[0].kind, ResponseKind::EmptyControl);
    harness.finish().await;
}

#[tokio::test(start_paused = true)]
async fn actor_pause_wrapper_only_sends_empty_controls_and_updates_response_position() {
    let mut harness = Harness::new(0);
    let (receipt, mut received) = mpsc::unbounded_channel();
    let mut item = durable(18001);
    item.transport_receipt = Some(receipt);
    harness.queue(item);
    harness.respond(request(2, "", ""));
    let cached_pointer = harness.actor.replay[0].response.body.as_ptr();
    let output = durable(18002);
    let pointer = output.stanza.as_ptr();
    let bytes = output.stanza.len();
    harness.queue(output);
    let (sender, mut response) = oneshot::channel();
    let (closed_sender, closed_response) = oneshot::channel();
    drop(closed_response);
    harness.actor.last_response = Instant::now() - Duration::from_secs(1);
    let before = harness.actor.last_response;
    let calls = harness.host.replay.calls().len();
    let operation = harness
        .actor
        .begin_ownership_operation(OperationKind::Request);
    harness.host.trace.clear();
    harness.actor.finish_pending_empty(
        PendingRequest {
            request: request(3, "pause='10'", ""),
            responders: vec![sender, closed_sender],
        },
        &operation,
    );
    let response = response.try_recv().unwrap();
    assert_eq!(response.content_type, CONTENT_TYPE);
    assert_eq!(
        response_body_text(&response),
        "<body xmlns='http://jabber.org/protocol/httpbind'/>"
    );
    assert!(harness.actor.last_response > before);
    assert_eq!(harness.actor.highest_responded, 3);
    assert_eq!(harness.actor.output.len(), 1);
    assert_eq!(harness.actor.output[0].stanza.as_ptr(), pointer);
    assert_eq!(harness.actor.output_bytes, bytes);
    assert_eq!(harness.actor.replay.len(), 1);
    assert_eq!(
        harness.actor.replay[0].response.body.as_ptr(),
        cached_pointer
    );
    receipt_pending(&mut received, "pause leaves cached receipts alone");
    assert_eq!(harness.host.replay.calls().len(), calls);
    assert!(harness.host.trace.effects().is_empty());
    let facts = operation.snapshot();
    assert!(
        facts.renewals.is_empty()
            && facts.acknowledgements.is_empty()
            && facts.transfers.is_empty()
    );
    assert_eq!(facts.responses.len(), 1);
    let control = &facts.responses[0];
    assert_eq!(control.rid, 3);
    assert_eq!(control.kind, ResponseKind::EmptyControl);
    assert_eq!(control.control_calls, 2);
    assert_eq!(control.control_accepted, 1);
    assert_eq!(control.control_refused, 1);
    assert!(control.bookkeeping && !control.cached && control.attempts.is_empty());
    harness.finish().await;
}

#[tokio::test(start_paused = true)]
async fn http_actor_creation_preserves_response_bytes_replay_ack_and_pause_contracts() {
    let host = TestHost::new();
    let (status, creation) = http(host.clone(), format!(
        "<body xmlns='http://jabber.org/protocol/httpbind' rid='1' to='example.test' wait='60' hold='0' ack='1' content='{CONTENT_TYPE}'/>"
    )).await;
    assert_eq!(status, axum::http::StatusCode::OK);
    let document = roxmltree::Document::parse(&creation).unwrap();
    let sid = document.root_element().attribute("sid").unwrap().to_owned();
    assert_eq!(document.root_element().attribute("ack"), Some("1"));
    assert_eq!(host.manager.inner.sessions.len(), 1);
    let (receipt, mut received) = mpsc::unbounded_channel();
    host.outbound
        .lock()
        .unwrap()
        .as_ref()
        .unwrap()
        .try_send_with_transport_receipt("<message id='wire-original'/>".to_owned(), receipt)
        .unwrap();
    let raw = format!("<body xmlns='http://jabber.org/protocol/httpbind' rid='2' sid='{sid}'/>");
    let (status, first) = http(host.clone(), raw.clone()).await;
    assert_eq!(status, axum::http::StatusCode::OK);
    assert!(first.contains("id='wire-original'"));
    let (status, replayed) = http(host.clone(), raw).await;
    assert_eq!(status, axum::http::StatusCode::OK);
    assert_eq!(replayed, first);
    receipt_pending(
        &mut received,
        "cached replay cannot acknowledge a fresh response",
    );
    let (status, paused) = http(
        host.clone(),
        format!(
        "<body xmlns='http://jabber.org/protocol/httpbind' rid='3' sid='{sid}' ack='2' pause='10'/>"
    ),
    )
    .await;
    assert_eq!(status, axum::http::StatusCode::OK);
    assert_eq!(
        paused,
        "<body xmlns='http://jabber.org/protocol/httpbind'/>"
    );
    received.try_recv().unwrap();
    let before = host.replay.calls().len();
    let (status, invalid) = http(
        host.clone(),
        format!(
            "<body xmlns='http://jabber.org/protocol/httpbind' rid='20' sid='{sid}' ack='20'/>"
        ),
    )
    .await;
    assert_eq!(status, axum::http::StatusCode::OK);
    assert!(invalid.contains("condition='bad-request'"));
    // Actor cleanup may already have released its fences before HTTP resumes.
    assert!(host.replay.calls()[before..]
        .iter()
        .all(|call| matches!(call, Call::Release(_) | Call::Dropped("release"))));
    let report = host
        .actors
        .join_or_abort(BOSH_BACKEND_OPERATION_TIMEOUT, Duration::from_secs(1))
        .await;
    assert!(report.graceful);
    assert_eq!(report.remaining, 0);
    assert!(host.manager.inner.sessions.is_empty());
    assert_eq!(host.manager.inner.session_slots.available_permits(), 1);
    let effects = host.trace.effects();
    assert_eq!(
        effects
            .iter()
            .filter(|event| *event == &Event::Session("opened"))
            .count(),
        1
    );
    assert_eq!(
        effects
            .iter()
            .filter(|event| *event == &Event::Session("closed"))
            .count(),
        1
    );
    assert_eq!(
        effects
            .iter()
            .filter(|event| *event == &Event::Session("finalize"))
            .count(),
        1
    );
}
