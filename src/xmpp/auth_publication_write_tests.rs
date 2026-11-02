//! Authentication publication over the root's TCP and WebSocket writers: partial writes, flush failures and
//! cancellation never publish, and a written control survives publication failure.

use anyhow::ensure;
use northstar_auth_application::authentication::publication::{Knowledge, Terminal, Transport};
use northstar_stream::auth_publication::fixture::{
    fixture_bound_control, fixture_control, poll_once, publish_unbound_fixture, Cut, FakePort,
};
use northstar_stream::frame_execution::PublicationResult;
use std::{
    pin::Pin,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
    task::{Context, Poll},
};
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

#[derive(Default)]
struct MemoryWrite {
    bytes: Vec<u8>,
    fail_at: Option<usize>,
    fail_flush: bool,
    flushes: usize,
}
impl tokio::io::AsyncWrite for MemoryWrite {
    fn poll_write(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let this = self.get_mut();
        if this.fail_at.is_some_and(|limit| this.bytes.len() >= limit) {
            return Poll::Ready(Err(std::io::Error::other("controlled partial write")));
        }
        let count = bytes.len().min(3).min(
            this.fail_at
                .map_or(usize::MAX, |limit| limit - this.bytes.len()),
        );
        this.bytes.extend_from_slice(&bytes[..count]);
        Poll::Ready(Ok(count))
    }
    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        this.flushes += 1;
        if this.fail_flush {
            Poll::Ready(Err(std::io::Error::other("controlled flush failure")))
        } else {
            Poll::Ready(Ok(()))
        }
    }
    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

#[tokio::test]
async fn actual_tcp_send_partial_and_flush_failure_never_publish_authentication() {
    for flush_failure in [false, true] {
        let connection = Uuid::from_u128(302);
        let (holder, observation) = fixture_bound_control("<success/>", connection, false);
        holder.recording().unwrap();
        let mut io = MemoryWrite {
            fail_at: (!flush_failure).then_some(1),
            fail_flush: flush_failure,
            ..MemoryWrite::default()
        };
        let writer = &mut io;
        let result = holder
            .write("<success/>".to_owned(), |control| async move {
                super::send(writer, &control).await
            })
            .await;
        assert!(result.is_err());
        assert_eq!(
            io.bytes.len(),
            if flush_failure { "<success/>".len() } else { 1 }
        );
        assert_eq!(io.flushes, usize::from(flush_failure));
        assert_eq!(observation.snapshot().transport, Transport::WriteEntered);
        assert_eq!(observation.snapshot().publication, Knowledge::NotStarted);
    }
}

#[tokio::test]
async fn actual_tcp_write_survives_publication_failure_and_caps_cancellation() {
    for cut in [Cut::BeforeCommit, Cut::CommitPending, Cut::CapsPending] {
        let connection = Uuid::from_u128(302);
        let (holder, observation) = fixture_bound_control("<success/>", connection, false);
        holder.recording().unwrap();
        let mut io = MemoryWrite::default();
        let writer = &mut io;
        let owner = holder
            .write("<success/>".to_owned(), |control| async move {
                super::send(writer, &control).await
            })
            .await
            .unwrap();
        assert_eq!(io.bytes, b"<success/>");
        assert_eq!(io.flushes, 1);
        let mut port = FakePort::new(connection, cut);
        let mut future = Box::pin(owner.publish(&mut port));
        let polled = poll_once(future.as_mut());
        if matches!(cut, Cut::BeforeCommit) {
            assert!(matches!(
                polled,
                Poll::Ready(PublicationResult::BackendFailure)
            ));
        } else {
            assert!(polled.is_pending());
        }
        drop(future);
        let snapshot = observation.snapshot();
        assert_eq!(snapshot.transport, Transport::Written);
        assert_eq!(
            snapshot.publication,
            match cut {
                Cut::BeforeCommit => Knowledge::BeforeCommit,
                Cut::CommitPending => Knowledge::CommitCallEntered,
                _ => Knowledge::ReceiptKnown(Some(7)),
            }
        );
        assert_eq!(
            snapshot.terminal,
            Some(if matches!(cut, Cut::BeforeCommit) {
                Terminal::Failed
            } else {
                Terminal::Cancelled
            })
        );
    }
}

#[tokio::test]
async fn actual_websocket_live_write_gate_preserves_success_and_cancellation() {
    for cancel in [0, 1, 2, 3] {
        let connection = Uuid::from_u128(302);
        let (holder, observation) = fixture_control("<success/>", connection);
        holder.recording().unwrap();
        let shutdown = CancellationToken::new();
        let revoke = CancellationToken::new();
        let backpressure = CancellationToken::new();
        match cancel {
            1 => shutdown.cancel(),
            2 => revoke.cancel(),
            3 => backpressure.cancel(),
            _ => {}
        }
        let signals =
            northstar_stream::transport::SessionTerminationSignals::new(revoke, backpressure);
        let cancellation = super::WebSocketSendCancellation {
            actor_shutdown: &shutdown,
            signals: &signals,
        };
        let polls = Arc::new(AtomicUsize::new(0));
        let write_polls = polls.clone();
        let result = holder
            .write("<success/>".to_owned(), |control| async move {
                assert_eq!(control, "<success/>");
                let sent = super::bounded_websocket_live_write(
                    async move {
                        write_polls.fetch_add(1, Ordering::Relaxed);
                        Ok::<(), std::io::Error>(())
                    },
                    &cancellation,
                )
                .await;
                ensure!(sent, "controlled WS cancellation");
                Ok(())
            })
            .await;
        assert_eq!(polls.load(Ordering::Relaxed), usize::from(cancel == 0));
        if cancel == 0 {
            assert!(publish_unbound_fixture(vec![result.unwrap()]).await);
            assert_eq!(observation.snapshot().transport, Transport::Written);
        } else {
            assert!(result.is_err());
            assert_eq!(observation.snapshot().publication, Knowledge::NotStarted);
        }
    }
}
