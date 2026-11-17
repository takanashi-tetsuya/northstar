use super::actor_fixture::{http, poll_once, request, submit, Harness, SID};
use super::actor_host::{Event, CONNECTION, DELIVERY_SESSION};
use super::replay_store::{Call, Outcome};
use super::response_body_text;
use crate::{BoshCommand, BOSH_BACKEND_OPERATION_TIMEOUT};
use futures::FutureExt;
use northstar_delivery_core::bosh_ownership::OperationKind;
use northstar_stream::frame_execution::Stage;
use northstar_stream::session::StreamSession;
use northstar_stream::transport::Action;
use std::panic::AssertUnwindSafe;
use std::task::Poll;
use std::time::Duration;

#[tokio::test(start_paused = true)]
async fn request_payloads_enter_the_frame_runner_once_in_order_and_stop_on_failure() {
    for label in ["completed frames", "backend failure", "frame deadline"] {
        let mut harness = Harness::new(0);
        harness
            .host
            .frame_actions
            .lock()
            .unwrap()
            .push_back(Action::Send("<presence id='frame-result'/>".to_owned()));
        let second = match label {
            "backend failure" => "<backend/>",
            "frame deadline" => "<pending/>",
            _ => "<next/>",
        };
        let mut response = Box::pin(http(harness.host.clone(), format!(
            "<body xmlns='http://jabber.org/protocol/httpbind' rid='2' sid='{SID}'><actions/>{second}<last/></body>"
        )));
        assert!(poll_once(response.as_mut()).is_pending(), "{label}");
        let BoshCommand::Request {
            request: incoming,
            response: responder,
        } = harness.actor.commands.try_recv().unwrap()
        else {
            panic!("{label}: missing HTTP command")
        };
        let operation = harness
            .actor
            .begin_ownership_operation(OperationKind::Request);
        // Drive the real request handler without the enclosing request timer,
        // so the session's own frame runner supplies the timeout result.
        let mut handling = Box::pin(
            harness
                .actor
                .accept_request(*incoming, responder, &operation),
        );
        let first_poll = poll_once(handling.as_mut());
        if label == "frame deadline" {
            assert!(first_poll.is_pending(), "{label}");
            let execution = harness.host.frame_executions.lock().unwrap()[1].clone();
            let facts = execution.observation_for_saved_case();
            assert_eq!(facts.stage_raw, Stage::Handler as u8, "{label}");
            assert_eq!(facts.outcome_raw, 0, "{label}");
            assert!(poll_once(response.as_mut()).is_pending(), "{label}");
            tokio::time::advance(Duration::from_millis(4_999)).await;
            assert!(poll_once(handling.as_mut()).is_pending(), "{label}");
            tokio::time::advance(Duration::from_millis(1)).await;
            assert_eq!(poll_once(handling.as_mut()), Poll::Ready(false), "{label}");
            assert_eq!(
                execution.observation_for_saved_case().outcome_raw,
                3,
                "{label}"
            );
            assert_eq!(
                harness
                    .host
                    .trace
                    .effects()
                    .iter()
                    .filter(|event| *event == &Event::Session("frame dropped"))
                    .count(),
                1,
                "{label}"
            );
        } else {
            assert_eq!(
                first_poll,
                Poll::Ready(label == "completed frames"),
                "{label}"
            );
        }
        drop(handling);
        let Poll::Ready((status, body)) = poll_once(response.as_mut()) else {
            panic!("{label}: frame result did not reach HTTP")
        };
        assert_eq!(status, axum::http::StatusCode::OK, "{label}");
        if label == "completed frames" {
            assert_eq!(
                body,
                "<body xmlns='http://jabber.org/protocol/httpbind'><presence id='frame-result'/></body>",
                "{label}"
            );
            assert_eq!(harness.actor.replay.len(), 1, "{label}");
        } else {
            assert_eq!(
                body,
                "<body xmlns='http://jabber.org/protocol/httpbind' type='terminate' condition='internal-server-error'/>",
                "{label}"
            );
            assert!(harness.actor.replay.is_empty(), "{label}");
        }
        let calls = harness
            .host
            .trace
            .effects()
            .into_iter()
            .filter(|event| {
                matches!(
                    event,
                    Event::Frame(_) | Event::RecordStanza(_) | Event::Session("post action")
                )
            })
            .collect::<Vec<_>>();
        let mut expected = vec![
            Event::Frame("<actions/>".to_owned()),
            Event::RecordStanza("<presence id='frame-result'/>".to_owned()),
            Event::Session("post action"),
            Event::Frame(second.to_owned()),
        ];
        if label == "completed frames" {
            expected.extend([
                Event::Session("post action"),
                Event::Frame("<last/>".to_owned()),
                Event::Session("post action"),
            ]);
        }
        assert_eq!(calls, expected, "{label}");
        let executions = harness.host.frame_executions.lock().unwrap().clone();
        assert_eq!(
            executions.len(),
            if label == "completed frames" { 3 } else { 2 },
            "{label}"
        );
        for (index, execution) in executions.iter().enumerate() {
            let facts = execution.observation_for_saved_case();
            assert_eq!(
                facts.operation_id,
                uuid::Uuid::from_u128(9100 + index as u128),
                "{label}"
            );
            assert_eq!(facts.stage_raw, Stage::Handler as u8, "{label}");
            let outcome = if index == 1 && label != "completed frames" {
                if label == "frame deadline" {
                    3
                } else {
                    2
                }
            } else {
                1
            };
            assert_eq!(facts.outcome_raw, outcome, "{label}");
        }
        assert_eq!(
            harness.actor.protocol.connection_id(),
            CONNECTION,
            "{label}"
        );
        harness.finish().await;
    }
}

#[tokio::test(start_paused = true)]
async fn actor_exit_stops_admission_before_fence_release_and_finalizes_once_even_after_failure() {
    for label in [
        "terminate",
        "shutdown",
        "backpressure",
        "revocation",
        "overactivity",
        "mailbox closed",
        "release rejected",
        "release timed out",
        "frame panicked",
    ] {
        let mut harness = Harness::new(1);
        let host = harness.host.clone();
        let manager = host.manager.clone();
        let handle = manager
            .inner
            .sessions
            .get(&harness.actor.session_key)
            .unwrap()
            .clone();
        assert_eq!(
            manager.inner.session_slots.available_permits(),
            0,
            "{label}"
        );
        let mut held = submit(&manager, request(2, "", ""));
        assert!(harness.pump(), "{label}");
        assert!(harness.actor.held.is_some(), "{label}");
        let mut buffered = submit(&manager, request(4, "", ""));
        assert!(harness.pump(), "{label}");
        assert_eq!(harness.actor.buffered.len(), 1, "{label}");
        assert_eq!(handle.requests.available_permits(), 0, "{label}");
        let release = host.replay.gate("release");
        if label == "release rejected" {
            host.replay.set_outcome("release", Outcome::Rejected);
        }
        let mut terminating = if matches!(label, "terminate" | "frame panicked") {
            let response = submit(
                &manager,
                request(
                    3,
                    "type='terminate'",
                    if label == "frame panicked" {
                        "<panic/>"
                    } else {
                        ""
                    },
                ),
            );
            assert_eq!(handle.control_request.available_permits(), 0, "{label}");
            Some(response)
        } else {
            match label {
                "overactivity" => handle.overactivity.cancel(),
                "backpressure" => host.backpressure.cancel(),
                "revocation" => host.policy_revoke.cancel(),
                "mailbox closed" => harness.actor.commands.close(),
                _ => harness.actor.actor_shutdown.cancel(),
            }
            None
        };
        host.trace.clear();
        let mut running = Box::pin(
            AssertUnwindSafe(tokio::task::unconstrained(harness.actor.run())).catch_unwind(),
        );
        assert!(poll_once(running.as_mut()).is_pending(), "{label}");
        assert!(
            manager.inner.sessions.is_empty(),
            "{label}: admission must stop before the release await"
        );
        assert_eq!(
            manager.inner.session_slots.available_permits(),
            0,
            "{label}: actor still owns its slot during cleanup"
        );
        let before = host.trace.effects();
        assert_eq!(
            before
                .iter()
                .filter(|event| *event == &Event::Replay(Call::Release(DELIVERY_SESSION)))
                .count(),
            1,
            "{label}"
        );
        assert!(!before.contains(&Event::Session("finalize")), "{label}");
        assert!(
            !before.contains(&Event::Session("session dropped")),
            "{label}"
        );
        assert!(
            !before.contains(&Event::Session("connection dropped")),
            "{label}"
        );
        let (status, late) = http(
            host.clone(),
            format!("<body xmlns='http://jabber.org/protocol/httpbind' rid='5' sid='{SID}'/>"),
        )
        .await;
        assert_eq!(status, axum::http::StatusCode::OK, "{label}");
        assert!(late.contains("condition='item-not-found'"), "{label}");
        assert_eq!(
            host.trace.effects(),
            before,
            "{label}: rejected ingress cannot reach the session or repositories"
        );
        if label == "release timed out" {
            tokio::time::advance(BOSH_BACKEND_OPERATION_TIMEOUT - Duration::from_millis(1)).await;
            assert!(poll_once(running.as_mut()).is_pending(), "{label}");
            assert!(
                !host.trace.effects().contains(&Event::Session("finalize")),
                "{label}"
            );
            tokio::time::advance(Duration::from_millis(1)).await;
        } else {
            release.add_permits(1);
        }
        let Poll::Ready(result) = poll_once(running.as_mut()) else {
            panic!("{label}: cleanup did not finish")
        };
        assert_eq!(result.is_err(), label == "frame panicked", "{label}");
        if let Err(panic) = result {
            assert_eq!(
                panic.downcast_ref::<&str>().copied(),
                Some("recorded frame panic"),
                "{label}"
            );
        }
        drop(running);
        let Poll::Ready(held) = poll_once(held.as_mut()) else {
            panic!("{label}: held responder leaked")
        };
        let Poll::Ready(buffered) = poll_once(buffered.as_mut()) else {
            panic!("{label}: buffered responder leaked")
        };
        let condition = match label {
            "terminate" => "type='terminate'",
            "overactivity" | "backpressure" => "condition='policy-violation'",
            "frame panicked" | "mailbox closed" => "condition='item-not-found'",
            _ => "condition='system-shutdown'",
        };
        assert!(response_body_text(&held).contains(condition), "{label}");
        assert!(
            response_body_text(&buffered).contains(if label == "terminate" {
                "condition='other-request'"
            } else {
                condition
            }),
            "{label}"
        );
        if let Some(response) = terminating.as_mut() {
            let Poll::Ready(response) = poll_once(response.as_mut()) else {
                panic!("{label}: extra control responder leaked")
            };
            assert_eq!(
                response_body_text(&response),
                if label == "frame panicked" {
                    "<body xmlns='http://jabber.org/protocol/httpbind' type='terminate' condition='item-not-found'/>"
                } else {
                    "<body xmlns='http://jabber.org/protocol/httpbind'></body>"
                },
                "{label}"
            );
        }
        assert_eq!(handle.requests.available_permits(), 2, "{label}");
        assert_eq!(handle.control_request.available_permits(), 1, "{label}");
        assert_eq!(
            manager.inner.session_slots.available_permits(),
            1,
            "{label}"
        );
        let events = host.trace.effects();
        assert_eq!(
            events
                .iter()
                .filter(|event| *event == &Event::Session("backpressure"))
                .count(),
            usize::from(label == "backpressure"),
            "{label}"
        );
        for marker in [
            Event::Replay(Call::Release(DELIVERY_SESSION)),
            Event::Replay(Call::Dropped("release")),
            Event::Session("finalize"),
            Event::Session("closed"),
            Event::Session("session dropped"),
            Event::Session("connection dropped"),
        ] {
            assert_eq!(
                events.iter().filter(|event| *event == &marker).count(),
                1,
                "{label}: {marker:?}"
            );
        }
        let position = |marker: Event| events.iter().position(|event| event == &marker).unwrap();
        assert!(
            position(Event::Replay(Call::Release(DELIVERY_SESSION)))
                < position(Event::Replay(Call::Dropped("release"))),
            "{label}"
        );
        assert!(
            position(Event::Replay(Call::Dropped("release")))
                < position(Event::Session("finalize")),
            "{label}"
        );
        assert!(
            position(Event::Session("finalize")) < position(Event::Session("closed")),
            "{label}"
        );
        assert!(
            position(Event::Session("closed")) < position(Event::Session("session dropped")),
            "{label}"
        );
        assert!(manager.inner.sessions.is_empty(), "{label}");
    }
}
