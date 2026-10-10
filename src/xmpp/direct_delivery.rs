//! Durable ownership around one ordered TCP or WebSocket write.
//! Native ownership is per invocation and independent of the retired sender
//! frame. BOSH and persisted SM retain their own acknowledgement boundaries.

use super::{protocol::ProtocolSession, C2S_BACKEND_OPERATION_TIMEOUT};
use crate::outbound::{
    DurableDelivery, MixDelivery, MixTransportCompletion, OutboundItem, TransportOwnershipSource,
};
use anyhow::{Context, Result};
use northstar_delivery_core::native_write::{
    self, AckRequest, Observation, Terminal, WriterResult,
};
use std::{
    future::Future,
    pin::Pin,
    task::{Context as TaskContext, Poll},
};
use uuid::Uuid;

/// Existing persistence authority; the closed ACK request carries the exact
/// fenced source and the observation for this invocation together.
pub(super) trait DirectWritePort {
    fn record(&mut self, item: &OutboundItem) -> impl Future<Output = Result<bool>> + Send;
    fn fence_c2s(
        &self,
        delivery: DurableDelivery,
    ) -> impl Future<Output = Result<DurableDelivery>> + Send;
    fn fence_mix(&self, delivery: MixDelivery) -> impl Future<Output = Result<MixDelivery>> + Send;
    fn acknowledge_c2s(&self, request: &AckRequest) -> impl Future<Output = Result<()>> + Send;
    fn acknowledge_mix(&self, request: &AckRequest) -> impl Future<Output = Result<bool>> + Send;
    fn connection_id(&self) -> Uuid;
}
impl DirectWritePort for ProtocolSession {
    async fn record(&mut self, item: &OutboundItem) -> Result<bool> {
        self.record_outbound_item(item).await
    }
    async fn fence_c2s(&self, delivery: DurableDelivery) -> Result<DurableDelivery> {
        tokio::time::timeout(
            C2S_BACKEND_OPERATION_TIMEOUT,
            self.fence_c2s_socket_write(delivery),
        )
        .await
        .context("C2S socket-write fence timed out")?
    }
    async fn fence_mix(&self, delivery: MixDelivery) -> Result<MixDelivery> {
        tokio::time::timeout(
            C2S_BACKEND_OPERATION_TIMEOUT,
            self.fence_mix_socket_write(delivery),
        )
        .await
        .context("MIX socket-write fence timed out")?
    }
    async fn acknowledge_c2s(&self, request: &AckRequest) -> Result<()> {
        tokio::time::timeout(
            C2S_BACKEND_OPERATION_TIMEOUT,
            self.acknowledge_c2s_socket_write(request),
        )
        .await
        .context("C2S socket-write acknowledgement timed out")?
    }
    async fn acknowledge_mix(&self, request: &AckRequest) -> Result<bool> {
        tokio::time::timeout(
            C2S_BACKEND_OPERATION_TIMEOUT,
            self.acknowledge_mix_socket_write(request),
        )
        .await
        .context("MIX socket-write acknowledgement timed out")?
    }
    fn connection_id(&self) -> Uuid {
        self.route_connection_id()
    }
}

struct ObservationGuard {
    observation: Observation,
    finished: bool,
}
impl ObservationGuard {
    fn finish(&mut self, terminal: Terminal) {
        if self.finished {
            return;
        }
        self.finished = true;
        let summary = self.observation.retire(terminal).summary();
        tracing::debug!(target: "rust_xmpp_server::xmpp::native_write", ?summary, "native write owner retired");
    }
}
impl Drop for ObservationGuard {
    fn drop(&mut self) {
        self.finish(if std::thread::panicking() {
            Terminal::Panicked
        } else {
            Terminal::Cancelled
        });
    }
}
/// Constructed after the enclosing transport callback is polled, before its
/// child first poll. An entirely unpolled callback has no such observation.
/// Explicit child destruction keeps its final facts ahead of the summary.
pub(super) struct NativeWriteRunner<F> {
    child: Option<Pin<Box<F>>>,
    observation: ObservationGuard,
    poll_in_progress: bool,
}
impl<F: Future> NativeWriteRunner<F> {
    pub(super) fn new(observation: Observation, child: F) -> Self {
        Self {
            child: Some(Box::pin(child)),
            observation: ObservationGuard {
                observation,
                finished: false,
            },
            poll_in_progress: false,
        }
    }
}
impl<F: Future> Future for NativeWriteRunner<F> {
    type Output = F::Output;
    fn poll(self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        this.poll_in_progress = true;
        let result = match this
            .child
            .as_mut()
            .expect("native runner polled after completion")
            .as_mut()
            .poll(cx)
        {
            Poll::Pending => {
                this.poll_in_progress = false;
                return Poll::Pending;
            }
            Poll::Ready(result) => result,
        };
        drop(this.child.take());
        this.poll_in_progress = false;
        this.observation.finish(Terminal::Returned);
        Poll::Ready(result)
    }
}
impl<F> Drop for NativeWriteRunner<F> {
    fn drop(&mut self) {
        drop(self.child.take());
        if self.poll_in_progress {
            self.observation.finish(Terminal::Panicked);
        }
    }
}

/// The prepared/written values borrow the same item, including its receipt
/// channels. Callers cannot replace it when confirming or settling a write.
pub(super) struct DirectWriteLease<'a> {
    item: &'a OutboundItem,
    observation: Observation,
    managed_by_sm: bool,
}
pub(super) struct WrittenDirectLease<'a> {
    item: &'a OutboundItem,
    written: native_write::Written,
    managed_by_sm: bool,
}
impl<'a> DirectWriteLease<'a> {
    pub(super) async fn prepare(
        session: &mut ProtocolSession,
        item: &'a OutboundItem,
        observation: &Observation,
    ) -> Result<Self> {
        Self::prepare_with(session, item, observation).await
    }
    pub(super) async fn prepare_with<P: DirectWritePort>(
        port: &mut P,
        item: &'a OutboundItem,
        observation: &Observation,
    ) -> Result<Self> {
        observation.begin_record(item.durable_source)?;
        let result = Self::prepare_inner(port, item, observation).await;
        if let Err(error) = &result {
            observation.preparation_failed(
                error
                    .downcast_ref::<crate::outbound::DurableDeliverySuperseded>()
                    .is_some(),
            );
        }
        result
    }
    async fn prepare_inner<P: DirectWritePort>(
        port: &mut P,
        item: &'a OutboundItem,
        observation: &Observation,
    ) -> Result<Self> {
        let managed_by_sm = port.record(item).await.context("record outbound stanza")?;
        match observation.recorded(managed_by_sm)? {
            Some(TransportOwnershipSource::C2s(source)) => {
                let returned = port.fence_c2s(source).await.context("fence C2S write")?;
                observation.fenced(TransportOwnershipSource::C2s(returned))?;
            }
            Some(TransportOwnershipSource::Mix(source)) => {
                let returned = port.fence_mix(source).await.context("fence MIX write")?;
                observation.fenced(TransportOwnershipSource::Mix(returned))?;
                item.complete_mix_handoff(MixTransportCompletion::SocketFenced {
                    connection_id: port.connection_id(),
                });
            }
            None => {}
        }
        Ok(Self {
            item,
            observation: observation.clone(),
            managed_by_sm,
        })
    }
    pub(super) async fn write<F, W>(self, writer: F) -> Result<WrittenDirectLease<'a>>
    where
        F: FnOnce(&'a str) -> W,
        W: Future<Output = Result<()>>,
    {
        self.observation.begin_write()?;
        let actual = writer(&self.item.stanza).await;
        let truth = if actual.is_ok() {
            WriterResult::FullWrite
        } else {
            WriterResult::Failed
        };
        let written = self.observation.writer_completed(truth)?;
        actual?;
        let written = written
            .ok_or_else(|| anyhow::anyhow!("successful native write lacked its continuation"))?;
        Ok(WrittenDirectLease {
            item: self.item,
            written,
            managed_by_sm: self.managed_by_sm,
        })
    }
}
impl WrittenDirectLease<'_> {
    pub(super) async fn settle(self, session: &ProtocolSession) {
        self.settle_with(session).await;
    }
    pub(super) async fn settle_with<P: DirectWritePort>(self, port: &P) {
        // Full local write was retained by the writer helper before either
        // notification and before this first settlement await.
        self.item.confirm_transport_write();
        if !self.managed_by_sm {
            self.item.confirm_transport_ownership();
        }
        let request = match self.written.begin_ack() {
            Ok(Some(request)) => request,
            Ok(None) => return,
            Err(error) => {
                tracing::warn!(?error, "native settlement continuation rejected");
                return;
            }
        };
        match request.source() {
            TransportOwnershipSource::C2s(delivery) => {
                let result = port.acknowledge_c2s(&request).await;
                request.returned(result.is_ok());
                if let Err(error) = result {
                    tracing::warn!(?error, message_id = %delivery.message_id, "direct write succeeded but durable C2S acknowledgement failed");
                }
            }
            TransportOwnershipSource::Mix(delivery) => {
                let result = port.acknowledge_mix(&request).await;
                request.returned(result.is_ok());
                match result {
                    Ok(true) => {}
                    Ok(false) => {
                        tracing::warn!(delivery_id = %delivery.delivery_id, "no exact MIX source matched direct-write acknowledgement")
                    }
                    Err(error) => {
                        tracing::warn!(?error, delivery_id = %delivery.delivery_id, "direct write succeeded but durable MIX acknowledgement failed")
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;
    use tokio::sync::mpsc;

    #[derive(Clone, Copy, Default, Eq, PartialEq)]
    enum AckCut {
        #[default]
        Success,
        BeforeCommit,
        DuringCommit,
        CommitError,
        AfterReceiptPending,
        AfterReceiptError,
        NoMatch,
    }

    #[derive(Default)]
    struct FakePort {
        events: Mutex<Vec<&'static str>>,
        managed_by_sm: bool,
        fail_at: Option<&'static str>,
        acknowledged: Mutex<bool>,
        ack_cut: AckCut,
        pending_fence: bool,
        wrong_fence: bool,
        expected_c2s_claim: Option<Uuid>,
    }

    impl FakePort {
        fn event(&self, name: &'static str) -> Result<()> {
            self.events.lock().unwrap().push(name);
            anyhow::ensure!(self.fail_at != Some(name), "injected {name} failure");
            Ok(())
        }

        async fn acknowledge(&self, request: &AckRequest, mix: bool) -> Result<bool> {
            if self.ack_cut == AckCut::BeforeCommit {
                anyhow::bail!("injected pre-COMMIT error");
            }
            let disposition = if mix && self.ack_cut == AckCut::NoMatch {
                native_write::AckDisposition::NoMatchingMix
            } else {
                native_write::AckDisposition::Deleted
            };
            native_write::commit_observed(
                async {
                    if self.ack_cut == AckCut::DuringCommit {
                        std::future::pending::<()>().await;
                    }
                    if self.ack_cut == AckCut::CommitError {
                        return Err(std::io::Error::other("injected COMMIT response loss"));
                    }
                    Ok(())
                },
                request,
                disposition,
            )
            .await?;
            *self.acknowledged.lock().unwrap() =
                disposition == native_write::AckDisposition::Deleted;
            // These are deliberately injected continuation cuts; production
            // currently returns synchronously after its post-COMMIT bookkeeping.
            if self.ack_cut == AckCut::AfterReceiptPending {
                std::future::pending::<()>().await;
            }
            if self.ack_cut == AckCut::AfterReceiptError {
                anyhow::bail!("injected post-receipt error");
            }
            Ok(disposition == native_write::AckDisposition::Deleted)
        }

        fn events(&self) -> Vec<&'static str> {
            self.events.lock().unwrap().clone()
        }
    }

    impl DirectWritePort for FakePort {
        async fn record(&mut self, item: &OutboundItem) -> Result<bool> {
            if self.fail_at == Some("superseded_record") {
                return Err(crate::outbound::DurableDeliverySuperseded {
                    message_id: item.c2s_delivery().unwrap().message_id,
                }
                .into());
            }
            self.event("record")?;
            Ok(self.managed_by_sm)
        }

        async fn fence_c2s(&self, delivery: DurableDelivery) -> Result<DurableDelivery> {
            if self.fail_at == Some("superseded") {
                return Err(crate::outbound::DurableDeliverySuperseded {
                    message_id: delivery.message_id,
                }
                .into());
            }
            self.event("fence_c2s")?;
            if self.pending_fence {
                std::future::pending::<()>().await;
            }
            Ok(DurableDelivery {
                recipient_id: if self.wrong_fence {
                    Uuid::from_u128(99)
                } else {
                    delivery.recipient_id
                },
                claim_id: if delivery.claim_id.is_none()
                    || delivery.claim_id == Some(delivery.message_id)
                {
                    Some(Uuid::from_u128(11))
                } else {
                    delivery.claim_id
                },
                ..delivery
            })
        }

        async fn fence_mix(&self, delivery: MixDelivery) -> Result<MixDelivery> {
            self.event("fence_mix")?;
            if self.pending_fence {
                std::future::pending::<()>().await;
            }
            Ok(MixDelivery {
                delivery_id: if self.wrong_fence {
                    Uuid::from_u128(99)
                } else {
                    delivery.delivery_id
                },
                lease_token: Uuid::from_u128(12),
            })
        }

        async fn acknowledge_c2s(&self, request: &AckRequest) -> Result<()> {
            let TransportOwnershipSource::C2s(delivery) = request.source() else {
                panic!("wrong source")
            };
            assert_eq!(
                delivery.claim_id,
                self.expected_c2s_claim.or(Some(Uuid::from_u128(11)))
            );
            self.event("ack_c2s")?;
            self.acknowledge(request, false).await?;
            Ok(())
        }

        async fn acknowledge_mix(&self, request: &AckRequest) -> Result<bool> {
            let TransportOwnershipSource::Mix(delivery) = request.source() else {
                panic!("wrong source")
            };
            assert_eq!(delivery.lease_token, Uuid::from_u128(12));
            self.event("ack_mix")?;
            self.acknowledge(request, true).await
        }

        fn connection_id(&self) -> Uuid {
            Uuid::from_u128(13)
        }
    }

    fn c2s_item() -> OutboundItem {
        OutboundItem::durable(
            "<message/>".to_owned(),
            DurableDelivery {
                recipient_id: Uuid::from_u128(1),
                message_id: Uuid::from_u128(2),
                claim_id: Some(Uuid::from_u128(2)),
            },
        )
    }

    async fn prepare<'a>(
        port: &mut FakePort,
        item: &'a OutboundItem,
    ) -> Result<DirectWriteLease<'a>> {
        DirectWriteLease::prepare_with(port, item, &Observation::new(item.durable_source)).await
    }
    async fn write_and_settle(lease: DirectWriteLease<'_>, port: &FakePort) {
        lease
            .write(|_| async { port.event("write") })
            .await
            .unwrap()
            .settle_with(port)
            .await;
    }

    #[tokio::test]
    async fn c2s_fence_precedes_write_and_only_rotated_lease_is_acknowledged() {
        let mut port = FakePort::default();
        let (receipt, mut received) = mpsc::unbounded_channel();
        let mut item = c2s_item();
        item.transport_receipt = Some(receipt);
        let lease = prepare(&mut port, &item).await.unwrap();
        assert_eq!(port.events(), ["record", "fence_c2s"]);
        assert!(received.try_recv().is_err());
        write_and_settle(lease, &port).await;
        assert_eq!(port.events(), ["record", "fence_c2s", "write", "ack_c2s"]);
        assert!(received.try_recv().is_ok());
        assert!(*port.acknowledged.lock().unwrap());
    }

    #[tokio::test]
    async fn mix_handoff_follows_fence_and_ack_follows_write() {
        let mut port = FakePort::default();
        let (item, handoff) = OutboundItem::durable_mix(
            "<message/>".to_owned(),
            MixDelivery {
                delivery_id: Uuid::from_u128(4),
                lease_token: Uuid::from_u128(5),
            },
        );
        let lease = prepare(&mut port, &item).await.unwrap();
        assert_eq!(port.events(), ["record", "fence_mix"]);
        assert_eq!(
            handoff.await.unwrap(),
            MixTransportCompletion::SocketFenced {
                connection_id: Uuid::from_u128(13)
            }
        );
        write_and_settle(lease, &port).await;
        assert_eq!(port.events(), ["record", "fence_mix", "write", "ack_mix"]);
    }

    #[tokio::test]
    async fn fence_failure_and_write_cancellation_never_acknowledge() {
        let mut port = FakePort {
            fail_at: Some("fence_c2s"),
            ..FakePort::default()
        };
        assert!(prepare(&mut port, &c2s_item()).await.is_err());
        assert_eq!(port.events(), ["record", "fence_c2s"]);

        let mut port = FakePort::default();
        let item = c2s_item();
        {
            let _lease = prepare(&mut port, &item).await.unwrap();
            // Cancellation before the actual writer future starts issues no written continuation.
        }
        assert_eq!(port.events(), ["record", "fence_c2s"]);
        assert!(!*port.acknowledged.lock().unwrap());
    }

    #[tokio::test]
    async fn superseded_claim_survives_context_and_never_confirms_transport() {
        for fail_at in ["superseded", "superseded_record"] {
            let mut port = FakePort {
                fail_at: Some(fail_at),
                ..FakePort::default()
            };
            let item = c2s_item();
            let error = match prepare(&mut port, &item).await {
                Ok(_) => panic!("superseded claim must not prepare a socket write"),
                Err(error) => error,
            };
            assert_eq!(
                error
                    .downcast_ref::<crate::outbound::DurableDeliverySuperseded>()
                    .map(|superseded| superseded.message_id),
                item.c2s_delivery().map(|delivery| delivery.message_id)
            );
            assert!(!*port.acknowledged.lock().unwrap());
        }
    }

    #[tokio::test]
    async fn acknowledgement_failure_leaves_durable_lease_for_recovery() {
        let mut port = FakePort {
            fail_at: Some("ack_c2s"),
            ..FakePort::default()
        };
        let item = c2s_item();
        let lease = prepare(&mut port, &item).await.unwrap();
        write_and_settle(lease, &port).await;
        assert_eq!(port.events(), ["record", "fence_c2s", "write", "ack_c2s"]);
        assert!(!*port.acknowledged.lock().unwrap());
    }

    #[tokio::test]
    async fn sm_owner_never_uses_direct_fence_or_ack() {
        let mut port = FakePort {
            managed_by_sm: true,
            ..FakePort::default()
        };
        let item = c2s_item();
        let lease = prepare(&mut port, &item).await.unwrap();
        write_and_settle(lease, &port).await;
        assert_eq!(port.events(), ["record", "write"]);
        assert!(!*port.acknowledged.lock().unwrap());
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum IoCut {
        Complete,
        PartialError,
        PendingAfterPrefix,
        FlushError,
        FlushPending,
    }
    struct ScriptedWrite {
        cut: IoCut,
        bytes: Vec<u8>,
        flushes: usize,
    }
    impl ScriptedWrite {
        fn new(cut: IoCut) -> Self {
            Self {
                cut,
                bytes: vec![],
                flushes: 0,
            }
        }
    }
    impl tokio::io::AsyncWrite for ScriptedWrite {
        fn poll_write(
            mut self: Pin<&mut Self>,
            _: &mut TaskContext<'_>,
            bytes: &[u8],
        ) -> Poll<std::io::Result<usize>> {
            if !self.bytes.is_empty() {
                match self.cut {
                    IoCut::PartialError => {
                        return Poll::Ready(Err(std::io::Error::other(
                            "injected partial write failure",
                        )))
                    }
                    IoCut::PendingAfterPrefix => return Poll::Pending,
                    _ => {}
                }
            }
            let count = bytes.len().min(2);
            self.bytes.extend_from_slice(&bytes[..count]);
            Poll::Ready(Ok(count))
        }
        fn poll_flush(
            mut self: Pin<&mut Self>,
            _: &mut TaskContext<'_>,
        ) -> Poll<std::io::Result<()>> {
            self.flushes += 1;
            match self.cut {
                IoCut::FlushError => {
                    Poll::Ready(Err(std::io::Error::other("injected flush failure")))
                }
                IoCut::FlushPending => Poll::Pending,
                _ => Poll::Ready(Ok(())),
            }
        }
        fn poll_shutdown(
            self: Pin<&mut Self>,
            _: &mut TaskContext<'_>,
        ) -> Poll<std::io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    #[tokio::test(start_paused = true)]
    async fn actual_tcp_writer_requires_complete_write_and_flush_before_ack() {
        for cut in [
            IoCut::Complete,
            IoCut::PartialError,
            IoCut::PendingAfterPrefix,
            IoCut::FlushError,
            IoCut::FlushPending,
        ] {
            let mut port = FakePort::default();
            let item = c2s_item();
            let observation = Observation::new(item.durable_source);
            let mut io = ScriptedWrite::new(cut);
            let mut future = Box::pin(NativeWriteRunner::new(observation.clone(), async {
                let lease = DirectWriteLease::prepare_with(&mut port, &item, &observation).await?;
                let written = lease
                    .write(|stanza| super::super::send(&mut io, stanza))
                    .await?;
                written.settle_with(&port).await;
                Ok::<(), anyhow::Error>(())
            }));
            let polled = futures::poll!(&mut future);
            assert_eq!(
                polled.is_pending(),
                matches!(cut, IoCut::PendingAfterPrefix | IoCut::FlushPending)
            );
            if cut == IoCut::Complete {
                assert!(matches!(polled, Poll::Ready(Ok(()))));
            } else if polled.is_ready() {
                assert!(matches!(polled, Poll::Ready(Err(_))));
            }
            drop(future);
            let snapshot = observation.snapshot();
            assert_eq!(*port.acknowledged.lock().unwrap(), cut == IoCut::Complete);
            assert_eq!(
                snapshot.writer_result,
                match cut {
                    IoCut::Complete => Some(WriterResult::FullWrite),
                    IoCut::PartialError | IoCut::FlushError => Some(WriterResult::Failed),
                    _ => None,
                }
            );
            if cut == IoCut::Complete {
                assert_eq!(io.bytes, item.stanza.as_bytes());
                assert_eq!(io.flushes, 1);
                assert!(matches!(
                    snapshot.ack,
                    native_write::AckKnowledge::ReceiptKnown(_)
                ));
            } else {
                assert_eq!(snapshot.ack, native_write::AckKnowledge::NotRequested);
                assert!(!port.events().contains(&"ack_c2s"));
            }
            if matches!(cut, IoCut::PartialError | IoCut::PendingAfterPrefix) {
                assert_eq!(io.bytes.len(), 2);
            }
        }
    }

    #[tokio::test(start_paused = true)]
    async fn actual_tcp_timeout_keeps_its_existing_deadline_and_never_settles() {
        let mut port = FakePort::default();
        let item = c2s_item();
        let observation = Observation::new(item.durable_source);
        let mut io = ScriptedWrite::new(IoCut::FlushPending);
        let mut future = Box::pin(NativeWriteRunner::new(observation.clone(), async {
            let lease = DirectWriteLease::prepare_with(&mut port, &item, &observation).await?;
            lease
                .write(|stanza| super::super::send(&mut io, stanza))
                .await?
                .settle_with(&port)
                .await;
            Ok::<(), anyhow::Error>(())
        }));
        assert!(futures::poll!(&mut future).is_pending());
        tokio::time::advance(super::super::XMPP_WRITE_TIMEOUT).await;
        assert!(matches!(futures::poll!(&mut future), Poll::Ready(Err(_))));
        drop(future);
        assert_eq!(io.bytes, item.stanza.as_bytes());
        assert_eq!(
            observation.snapshot().writer_result,
            Some(WriterResult::Failed)
        );
        assert_eq!(
            observation.snapshot().ack,
            native_write::AckKnowledge::NotRequested
        );
    }

    #[tokio::test]
    async fn full_write_is_retained_before_real_ack_suspension_and_synthetic_receipt_cuts() {
        for cut in [
            AckCut::Success,
            AckCut::BeforeCommit,
            AckCut::DuringCommit,
            AckCut::CommitError,
            AckCut::AfterReceiptPending,
            AckCut::AfterReceiptError,
        ] {
            let mut port = FakePort {
                ack_cut: cut,
                ..Default::default()
            };
            let (receipt, mut receipt_rx) = mpsc::unbounded_channel();
            let (write_receipt, mut write_rx) = mpsc::unbounded_channel();
            let mut item = c2s_item();
            item.transport_receipt = Some(receipt);
            item.transport_write_receipt = Some(write_receipt);
            let observation = Observation::new(item.durable_source);
            let mut future = Box::pin(NativeWriteRunner::new(observation.clone(), async {
                let lease = DirectWriteLease::prepare_with(&mut port, &item, &observation)
                    .await
                    .unwrap();
                lease
                    .write(|stanza| async move {
                        assert_eq!(stanza, "<message/>");
                        Ok(())
                    })
                    .await
                    .unwrap()
                    .settle_with(&port)
                    .await;
                true // Existing outward write success survives ACK errors.
            }));
            let outcome = futures::poll!(&mut future);
            assert_eq!(
                outcome.is_pending(),
                matches!(cut, AckCut::DuringCommit | AckCut::AfterReceiptPending)
            );
            if outcome.is_ready() {
                assert_eq!(outcome, Poll::Ready(true));
            }
            assert_eq!(
                observation.snapshot().writer_result,
                Some(WriterResult::FullWrite)
            );
            assert_eq!(receipt_rx.try_recv(), Ok(()));
            assert_eq!(write_rx.try_recv(), Ok(()));
            drop(future);
            let snapshot = observation.snapshot();
            match cut {
                AckCut::BeforeCommit => {
                    assert_eq!(snapshot.ack, native_write::AckKnowledge::NoCommitRequested)
                }
                AckCut::DuringCommit | AckCut::CommitError => assert!(matches!(
                    snapshot.ack,
                    native_write::AckKnowledge::CommitCallEntered(_)
                )),
                _ => assert!(matches!(
                    snapshot.ack,
                    native_write::AckKnowledge::ReceiptKnown(_)
                )),
            }
        }
    }

    #[tokio::test]
    async fn wrong_or_unreturned_fence_never_polls_writer_and_retained_claim_is_accepted() {
        for pending in [false, true] {
            let mut port = FakePort {
                wrong_fence: !pending,
                pending_fence: pending,
                ..Default::default()
            };
            let item = c2s_item();
            let observation = Observation::new(item.durable_source);
            let polled = std::cell::Cell::new(false);
            let mut future = Box::pin(NativeWriteRunner::new(observation.clone(), async {
                let lease = DirectWriteLease::prepare_with(&mut port, &item, &observation).await?;
                lease
                    .write(|_| async {
                        polled.set(true);
                        Ok(())
                    })
                    .await?
                    .settle_with(&port)
                    .await;
                Ok::<(), anyhow::Error>(())
            }));
            let result = futures::poll!(&mut future);
            assert_eq!(result.is_pending(), pending);
            if !pending {
                assert!(matches!(result, Poll::Ready(Err(_))));
            }
            drop(future);
            assert!(!polled.get());
            assert!(observation.snapshot().fence_entered);
            assert_eq!(observation.snapshot().returned_fence, None);
            assert_eq!(
                observation.snapshot().ack,
                native_write::AckKnowledge::NotRequested
            );
        }
        for claim_id in [None, Some(Uuid::from_u128(7))] {
            let source = DurableDelivery {
                claim_id,
                ..c2s_item().c2s_delivery().unwrap()
            };
            let expected = DurableDelivery {
                claim_id: claim_id.or(Some(Uuid::from_u128(11))),
                ..source
            };
            let item = OutboundItem::durable("<message/>".into(), source);
            let mut port = FakePort {
                expected_c2s_claim: expected.claim_id,
                ..Default::default()
            };
            let observation = Observation::new(item.durable_source);
            DirectWriteLease::prepare_with(&mut port, &item, &observation)
                .await
                .unwrap()
                .write(|_| async { Ok(()) })
                .await
                .unwrap()
                .settle_with(&port)
                .await;
            assert_eq!(
                observation.snapshot().returned_fence,
                Some(TransportOwnershipSource::C2s(expected))
            );
            assert!(matches!(
                observation.snapshot().ack,
                native_write::AckKnowledge::ReceiptKnown(_)
            ));
        }
    }

    #[tokio::test]
    async fn committed_mix_no_match_is_not_a_deleted_row_or_failed_local_write() {
        let mut port = FakePort {
            ack_cut: AckCut::NoMatch,
            ..Default::default()
        };
        let (item, handoff) = OutboundItem::durable_mix(
            "<message/>".into(),
            MixDelivery {
                delivery_id: Uuid::from_u128(4),
                lease_token: Uuid::from_u128(5),
            },
        );
        let observation = Observation::new(item.durable_source);
        DirectWriteLease::prepare_with(&mut port, &item, &observation)
            .await
            .unwrap()
            .write(|_| async { Ok(()) })
            .await
            .unwrap()
            .settle_with(&port)
            .await;
        assert!(matches!(
            handoff.await.unwrap(),
            MixTransportCompletion::SocketFenced { .. }
        ));
        assert_eq!(
            observation.snapshot().writer_result,
            Some(WriterResult::FullWrite)
        );
        assert_eq!(
            observation.snapshot().summary().committed_disposition,
            Some(native_write::AckDisposition::NoMatchingMix)
        );
        assert!(!*port.acknowledged.lock().unwrap());
    }

    #[tokio::test(start_paused = true)]
    async fn actual_websocket_live_future_preserves_cancellation_bias_failure_and_timeout() {
        use tokio_util::sync::CancellationToken;
        for case in 0..7 {
            let shutdown = CancellationToken::new();
            let revoke = CancellationToken::new();
            let backpressure = CancellationToken::new();
            let signals = super::super::protocol::SessionTerminationSignals::from_test_tokens(
                revoke.clone(),
                backpressure.clone(),
            );
            let cancellation = super::super::WebSocketSendCancellation {
                actor_shutdown: &shutdown,
                signals: &signals,
            };
            if case == 0 {
                shutdown.cancel();
            }
            if case == 1 {
                revoke.cancel();
            }
            if case == 2 {
                backpressure.cancel();
            }
            let mut port = FakePort::default();
            let item = c2s_item();
            let observation = Observation::new(item.durable_source);
            let polled = std::cell::Cell::new(false);
            let mut future = Box::pin(NativeWriteRunner::new(observation.clone(), async {
                let lease = DirectWriteLease::prepare_with(&mut port, &item, &observation).await?;
                let written = lease
                    .write(|stanza| {
                        let polled = &polled;
                        let cancellation = &cancellation;
                        async move {
                            assert_eq!(stanza, "<message/>");
                            let success = super::super::bounded_websocket_live_write(
                                async {
                                    polled.set(true);
                                    if case >= 5 {
                                        std::future::pending::<()>().await;
                                    }
                                    if case == 4 {
                                        return Err(std::io::Error::other("injected WS failure"));
                                    }
                                    Ok(())
                                },
                                cancellation,
                            )
                            .await;
                            anyhow::ensure!(success, "controlled WS write did not complete");
                            Ok(())
                        }
                    })
                    .await?;
                written.settle_with(&port).await;
                Ok::<(), anyhow::Error>(())
            }));
            let first = futures::poll!(&mut future);
            if case >= 5 {
                assert!(first.is_pending());
                if case == 5 {
                    shutdown.cancel();
                } else {
                    tokio::time::advance(super::super::XMPP_WRITE_TIMEOUT).await;
                }
                assert!(matches!(futures::poll!(&mut future), Poll::Ready(Err(_))));
            } else if case == 3 {
                assert!(matches!(first, Poll::Ready(Ok(()))));
            } else {
                assert!(matches!(first, Poll::Ready(Err(_))));
            }
            drop(future);
            assert_eq!(polled.get(), case >= 3);
            assert_eq!(*port.acknowledged.lock().unwrap(), case == 3);
            assert_eq!(
                observation.snapshot().writer_result,
                Some(if case == 3 {
                    WriterResult::FullWrite
                } else {
                    WriterResult::Failed
                })
            );
        }
    }

    struct DropProbe {
        observation: Observation,
        dropped: std::sync::Arc<std::sync::atomic::AtomicBool>,
        panic_poll: bool,
        panic_drop: bool,
        ready: bool,
    }
    impl Future for DropProbe {
        type Output = ();
        fn poll(self: Pin<&mut Self>, _: &mut TaskContext<'_>) -> Poll<()> {
            if self.panic_poll {
                panic!("native child poll panic");
            }
            if self.ready {
                Poll::Ready(())
            } else {
                Poll::Pending
            }
        }
    }
    impl Drop for DropProbe {
        fn drop(&mut self) {
            assert!(
                self.observation.snapshot().terminal.is_none(),
                "owner retired before child destruction"
            );
            self.dropped
                .store(true, std::sync::atomic::Ordering::SeqCst);
            if self.panic_drop {
                panic!("native child drop panic");
            }
        }
    }
    #[tokio::test]
    async fn native_owner_destroys_unpolled_cancelled_and_panicking_children_before_summary() {
        for case in 0..5 {
            let observation = Observation::new(c2s_item().durable_source);
            let dropped = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
            let child = DropProbe {
                observation: observation.clone(),
                dropped: dropped.clone(),
                panic_poll: case == 3,
                panic_drop: case == 4,
                ready: case == 2 || case == 4,
            };
            let mut future = Box::pin(NativeWriteRunner::new(observation.clone(), child));
            if case != 0 {
                let mut context = TaskContext::from_waker(futures::task::noop_waker_ref());
                let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    future.as_mut().poll(&mut context)
                }));
                if case >= 3 {
                    let payload = result.unwrap_err();
                    assert_eq!(
                        payload.downcast_ref::<&str>().copied(),
                        Some(if case == 3 {
                            "native child poll panic"
                        } else {
                            "native child drop panic"
                        })
                    );
                } else {
                    assert_eq!(result.unwrap().is_ready(), case == 2);
                }
            }
            drop(future);
            assert!(dropped.load(std::sync::atomic::Ordering::SeqCst));
            assert_eq!(
                observation.snapshot().terminal,
                Some(if case >= 3 {
                    Terminal::Panicked
                } else if case == 2 {
                    Terminal::Returned
                } else {
                    Terminal::Cancelled
                })
            );
        }
    }
}
