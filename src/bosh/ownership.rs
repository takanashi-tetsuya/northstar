//! Pending MIX transfer at the actual BOSH item/FIFO boundary. The existing
//! actor owns request policy and timers; this helper owns no actor or service.
use crate::{
    outbound::{MixDelivery, MixTransportCompletion, OutboundItem, TransportOwnershipSource},
    services::mix::{MixRepository, MixService},
};
use anyhow::{Context, Result};
use northstar_delivery_core::bosh_ownership::{Operation, Terminal, TransferRequest, Transferred};
use std::{
    collections::VecDeque,
    future::Future,
    pin::Pin,
    task::{Context as TaskContext, Poll},
};

pub(super) struct Output<'a> {
    pub(super) items: &'a mut VecDeque<OutboundItem>,
    pub(super) bytes: &'a mut usize,
    pub(super) max_stanzas: usize,
    pub(super) max_bytes: usize,
}
impl Output<'_> {
    pub(super) fn can_push(&self, item: &OutboundItem) -> bool {
        let next_bytes = self.bytes.saturating_add(item.stanza.len());
        self.items.len() < self.max_stanzas && next_bytes <= self.max_bytes
    }
    pub(super) fn push(&mut self, item: OutboundItem) -> bool {
        if !self.can_push(&item) {
            return false;
        }
        *self.bytes = self.bytes.saturating_add(item.stanza.len());
        self.items.push_back(item);
        true
    }
}
/// The preparation owns the existing item. Only its immutable request is
/// lent across the service/repository await; no replacement item is accepted.
struct PreparedTransferItem {
    item: OutboundItem,
    request: TransferRequest,
}
impl std::fmt::Debug for PreparedTransferItem {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("PreparedBoshTransferItem { item and binding: [redacted] }")
    }
}
impl PreparedTransferItem {
    fn new(item: OutboundItem, operation: &Operation) -> Result<Self> {
        anyhow::ensure!(
            item.validate_durable_source_shape(),
            "invalid pending MIX handoff shape"
        );
        let source = item
            .mix_delivery()
            .context("pending BOSH transfer requires a MIX source")?;
        let request = operation.begin_transfer(source)?;
        Ok(Self { item, request })
    }
    fn returned(self, source: MixDelivery) -> Result<TransferredItem> {
        Ok(TransferredItem {
            item: self.item,
            transferred: self.request.returned(source)?,
        })
    }
}
struct TransferredItem {
    item: OutboundItem,
    transferred: Transferred,
}
impl std::fmt::Debug for TransferredItem {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("TransferredBoshItem { exact item: [redacted] }")
    }
}
impl TransferredItem {
    fn push(self, output: &mut Output<'_>) -> Result<bool> {
        let local = self.transferred.begin_local()?;
        let mut item = self.item;
        item.durable_source = Some(TransportOwnershipSource::Mix(local.current()));
        local.source_applied();
        // Keep the pre-existing one-shot-before-FIFO timing. A later refusal
        // cannot undo this notification or the committed pending fence.
        item.complete_mix_handoff(MixTransportCompletion::BoshPersisted {
            session_id: local.session_id(),
        });
        local.notification_attempted();
        let accepted = output.push(item);
        local.queue_returned(accepted);
        Ok(accepted)
    }
}
pub(super) trait TransferPort {
    fn transfer(
        &self,
        request: &TransferRequest,
    ) -> impl Future<Output = Result<MixDelivery>> + Send;
}
pub(super) struct ServiceTransfer<'a, R> {
    pub(super) service: &'a MixService<R>,
}
impl<R: MixRepository> TransferPort for ServiceTransfer<'_, R> {
    async fn transfer(&self, request: &TransferRequest) -> Result<MixDelivery> {
        self.service.transfer_mix_delivery_to_bosh(request).await
    }
}
pub(super) async fn transfer_and_push<P: TransferPort>(
    output: &mut Output<'_>,
    item: OutboundItem,
    operation: &Operation,
    port: &P,
) -> Result<bool> {
    if !output.can_push(&item) {
        return Ok(false);
    }
    let prepared = PreparedTransferItem::new(item, operation)?;
    let returned = port.transfer(&prepared.request).await?;
    prepared.returned(returned)?.push(output)
}

pub(crate) trait RecordPort {
    fn record(&mut self, item: &OutboundItem) -> impl Future<Output = Result<bool>> + Send;
}
impl RecordPort for crate::xmpp::protocol::ProtocolSession {
    async fn record(&mut self, item: &OutboundItem) -> Result<bool> {
        self.record_outbound_item(item).await
    }
}
pub(super) enum RecordPushError {
    Record(anyhow::Error),
    Transfer {
        source: MixDelivery,
        error: anyhow::Error,
    },
}
impl std::fmt::Debug for RecordPushError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Record(_) => "BoshRecordPushError::Record([redacted])",
            Self::Transfer { .. } => "BoshRecordPushError::Transfer([redacted])",
        })
    }
}
pub(super) async fn record_and_push<R: RecordPort, P: TransferPort>(
    output: &mut Output<'_>,
    mut item: OutboundItem,
    operation: &Operation,
    record: &mut R,
    transfer: &P,
) -> Result<bool, RecordPushError> {
    // Record before any FIFO capacity precheck: SM may already own and notify
    // the item before a later BOSH FIFO refusal, exactly as in the actor.
    let managed_by_sm = record
        .record(&item)
        .await
        .map_err(RecordPushError::Record)?;
    if managed_by_sm {
        item.durable_source = None;
        item.mix_handoff = None;
    } else if let Some(source) = item.mix_delivery() {
        return transfer_and_push(output, item, operation, transfer)
            .await
            .map_err(|error| RecordPushError::Transfer { source, error });
    }
    Ok(output.push(item))
}

struct ObservationGuard {
    operation: Operation,
    finished: bool,
}
impl ObservationGuard {
    fn finish(&mut self, terminal: Terminal, keep_running: Option<bool>) {
        if self.finished {
            return;
        }
        self.finished = true;
        let summary = match keep_running {
            Some(keep_running) => self.operation.returned(keep_running),
            None => self.operation.retire(terminal),
        };
        tracing::debug!(target: "rust_xmpp_server::bosh::ownership", ?summary, "BOSH operation retired");
    }
}
impl Drop for ObservationGuard {
    fn drop(&mut self) {
        self.finish(
            if std::thread::panicking() {
                Terminal::Panicked
            } else {
                Terminal::Cancelled
            },
            None,
        );
    }
}
/// The actor creates this owner outside its existing timeout. Destruction of
/// the timed child precedes retirement, including caught poll/drop panics.
pub(super) struct OperationRunner<F> {
    child: Option<Pin<Box<F>>>,
    observation: ObservationGuard,
    poll_in_progress: bool,
}
impl<F: Future> OperationRunner<F> {
    pub(super) fn new(operation: Operation, child: F) -> Self {
        Self {
            child: Some(Box::pin(child)),
            observation: ObservationGuard {
                operation,
                finished: false,
            },
            poll_in_progress: false,
        }
    }
}
impl<F: Future<Output = Result<bool, tokio::time::error::Elapsed>>> Future for OperationRunner<F> {
    type Output = F::Output;
    fn poll(self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        this.poll_in_progress = true;
        let result = match this
            .child
            .as_mut()
            .expect("BOSH operation polled after completion")
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
        this.observation.finish(
            if result.is_err() {
                Terminal::TimedOut
            } else {
                Terminal::Returned
            },
            result.as_ref().ok().copied(),
        );
        Poll::Ready(result)
    }
}
impl<F> Drop for OperationRunner<F> {
    fn drop(&mut self) {
        drop(self.child.take());
        if self.poll_in_progress {
            self.observation.finish(Terminal::Panicked, None);
        }
    }
}

/// Test-only composition entry. It uses the production record/clear/transfer/
/// FIFO algorithm and actual owners without constructing a synthetic actor.
#[cfg(test)]
pub(crate) async fn sm_record_composition<R: RecordPort>(
    record: &mut R,
    item: OutboundItem,
    full: bool,
) -> (bool, VecDeque<OutboundItem>, usize, Operation) {
    struct NoTransfer;
    impl TransferPort for NoTransfer {
        async fn transfer(&self, _: &TransferRequest) -> Result<MixDelivery> {
            panic!("SM-owned item reached BOSH transfer")
        }
    }
    let operation = Operation::new(northstar_delivery_core::bosh_ownership::Scope {
        session_id: uuid::Uuid::from_u128(900),
        ttl_seconds: 60,
        kind: northstar_delivery_core::bosh_ownership::OperationKind::Outbound,
    });
    let mut items = if full {
        VecDeque::from([
            OutboundItem::plain("<presence/>".to_owned()),
            OutboundItem::plain("<presence/>".to_owned()),
        ])
    } else {
        VecDeque::new()
    };
    let mut bytes = items.iter().map(|item| item.stanza.len()).sum();
    let accepted = {
        let mut output = Output {
            items: &mut items,
            bytes: &mut bytes,
            max_stanzas: 2,
            max_bytes: 1024,
        };
        OperationRunner::new(
            operation.clone(),
            tokio::time::timeout(super::BOSH_BACKEND_OPERATION_TIMEOUT, async {
                record_and_push(&mut output, item, &operation, record, &NoTransfer)
                    .await
                    .expect("valid SM composition")
            }),
        )
        .await
        .expect("ready in-process SM composition")
    };
    (accepted, items, bytes, operation)
}

#[cfg(test)]
mod tests {
    use super::*;
    use northstar_delivery_core::bosh_ownership::{self, OperationKind, Scope, TransferKnowledge};
    use std::{
        sync::{
            atomic::{AtomicBool, Ordering},
            Arc, Mutex,
        },
        task::Waker,
    };
    use uuid::Uuid;
    fn old() -> MixDelivery {
        MixDelivery {
            delivery_id: Uuid::from_u128(31),
            lease_token: Uuid::from_u128(32),
        }
    }
    fn current() -> MixDelivery {
        MixDelivery {
            lease_token: Uuid::from_u128(33),
            ..old()
        }
    }
    fn operation() -> Operation {
        Operation::new(Scope {
            session_id: Uuid::from_u128(34),
            ttl_seconds: 86_400,
            kind: OperationKind::Outbound,
        })
    }
    fn item() -> (
        OutboundItem,
        tokio::sync::oneshot::Receiver<MixTransportCompletion>,
    ) {
        OutboundItem::durable_mix(
            "<message id='private-body'><body>secret</body></message>".to_owned(),
            old(),
        )
    }
    fn poll_once<F: Future>(future: Pin<&mut F>) -> Poll<F::Output> {
        future.poll(&mut TaskContext::from_waker(Waker::noop()))
    }
    #[derive(Clone, Copy, Default, Eq, PartialEq)]
    enum Cut {
        #[default]
        Success,
        BeforeRepositoryPending,
        BeforeCommit,
        DuringCommit,
        CommitError,
        AfterReceiptPending,
        AfterReceiptError,
        BareSuccess,
        WrongToken,
        WrongIdentity,
        WrongReceipt,
        TypedAfterReceipt,
    }
    struct FakeTransfer {
        cut: Cut,
        events: Arc<Mutex<Vec<&'static str>>>,
        other: Operation,
    }
    impl FakeTransfer {
        fn new(cut: Cut, events: Arc<Mutex<Vec<&'static str>>>) -> Self {
            Self {
                cut,
                events,
                other: operation(),
            }
        }
    }
    impl TransferPort for FakeTransfer {
        async fn transfer(&self, request: &TransferRequest) -> Result<MixDelivery> {
            self.events.lock().unwrap().push("transfer");
            assert_eq!(request.source(), old());
            assert_eq!(request.session_id(), Uuid::from_u128(34));
            assert_eq!(request.ttl_seconds(), 86_400);
            // A controlled pre-repository pause. The actual service admission
            // guard remains source-verified; this fake does not run it.
            if self.cut == Cut::BeforeRepositoryPending {
                std::future::pending::<()>().await;
            }
            request.validate_for_io()?;
            if self.cut == Cut::BeforeCommit {
                anyhow::bail!("injected pre-COMMIT rejection");
            }
            if self.cut == Cut::BareSuccess {
                return Ok(current());
            }
            let wrong =
                (self.cut == Cut::WrongReceipt).then(|| self.other.begin_transfer(old()).unwrap());
            let actual = wrong.as_ref().unwrap_or(request);
            self.events.lock().unwrap().push("commit");
            bosh_ownership::transfer_commit_observed(
                async {
                    if self.cut == Cut::DuringCommit {
                        std::future::pending::<()>().await;
                    }
                    if self.cut == Cut::CommitError {
                        return Err(std::io::Error::other("injected COMMIT response loss"));
                    }
                    Ok(())
                },
                actual,
                current(),
            )
            .await?;
            self.events.lock().unwrap().push("receipt");
            // Synthetic continuation cuts; the real SQL callback currently
            // returns synchronously after retaining its positive receipt.
            if self.cut == Cut::AfterReceiptPending {
                std::future::pending::<()>().await;
            }
            if self.cut == Cut::AfterReceiptError {
                anyhow::bail!("injected post-receipt error");
            }
            if self.cut == Cut::TypedAfterReceipt {
                return Err(crate::outbound::DurableDeliverySuperseded {
                    message_id: old().delivery_id,
                }
                .into());
            }
            Ok(match self.cut {
                Cut::WrongToken => MixDelivery {
                    lease_token: Uuid::from_u128(35),
                    ..current()
                },
                Cut::WrongIdentity => MixDelivery {
                    delivery_id: Uuid::from_u128(36),
                    ..current()
                },
                _ => current(),
            })
        }
    }
    #[derive(Clone, Copy)]
    enum RecordMode {
        Unmanaged,
        Error,
        Superseded,
    }
    struct FakeRecord {
        mode: RecordMode,
        events: Arc<Mutex<Vec<&'static str>>>,
    }
    impl RecordPort for FakeRecord {
        async fn record(&mut self, _: &OutboundItem) -> Result<bool> {
            self.events.lock().unwrap().push("record");
            match self.mode {
                RecordMode::Unmanaged => Ok(false),
                RecordMode::Error => anyhow::bail!("injected record error"),
                RecordMode::Superseded => Err(crate::outbound::DurableDeliverySuperseded {
                    message_id: Uuid::from_u128(99),
                }
                .into()),
            }
        }
    }
    #[tokio::test]
    async fn actual_item_token_allocation_and_one_shot_survive_successful_transfer() {
        let operation = operation();
        let events = Arc::new(Mutex::new(vec![]));
        let port = FakeTransfer::new(Cut::Success, events.clone());
        let mut record = FakeRecord {
            mode: RecordMode::Unmanaged,
            events: events.clone(),
        };
        let (item, mut receiver) = item();
        let pointer = item.stanza.as_ptr();
        let clone = item.clone();
        let expected_bytes = item.stanza.len();
        let mut items = VecDeque::new();
        let mut bytes = 0;
        assert!(record_and_push(
            &mut Output {
                items: &mut items,
                bytes: &mut bytes,
                max_stanzas: 2,
                max_bytes: 1024
            },
            item,
            &operation,
            &mut record,
            &port
        )
        .await
        .unwrap());
        assert_eq!(
            *events.lock().unwrap(),
            vec!["record", "transfer", "commit", "receipt"]
        );
        assert_eq!(items[0].stanza.as_ptr(), pointer);
        assert_eq!(items[0].mix_delivery(), Some(current()));
        assert_eq!(bytes, expected_bytes);
        assert_eq!(
            receiver.try_recv().unwrap(),
            MixTransportCompletion::BoshPersisted {
                session_id: Uuid::from_u128(34)
            }
        );
        clone.complete_mix_handoff(MixTransportCompletion::SocketFenced {
            connection_id: Uuid::nil(),
        });
        assert!(receiver.try_recv().is_err());
        let facts = operation.snapshot().transfers[0];
        assert_eq!(facts.knowledge, TransferKnowledge::ReceiptKnown(current()));
        assert_eq!(facts.returned_source, Some(current()));
        assert!(
            facts.return_matches_receipt && facts.source_applied && facts.notification_attempted
        );
        assert_eq!(facts.queue_accepted, Some(true));
    }
    #[tokio::test]
    async fn record_precedes_capacity_rejection_and_transfer_is_never_started() {
        let operation = operation();
        let events = Arc::new(Mutex::new(vec![]));
        let port = FakeTransfer::new(Cut::Success, events.clone());
        let mut record = FakeRecord {
            mode: RecordMode::Unmanaged,
            events: events.clone(),
        };
        let (item, mut receiver) = item();
        let clone = item.clone();
        let mut items = VecDeque::from([
            OutboundItem::plain("<presence/>".to_owned()),
            OutboundItem::plain("<presence/>".to_owned()),
        ]);
        let mut bytes = items.iter().map(|item| item.stanza.len()).sum();
        let before = bytes;
        assert!(!record_and_push(
            &mut Output {
                items: &mut items,
                bytes: &mut bytes,
                max_stanzas: 2,
                max_bytes: 1024
            },
            item,
            &operation,
            &mut record,
            &port
        )
        .await
        .unwrap());
        assert_eq!(*events.lock().unwrap(), vec!["record"]);
        assert_eq!(items.len(), 2);
        assert_eq!(bytes, before);
        assert!(operation.snapshot().transfers.is_empty());
        assert!(receiver.try_recv().is_err());
        drop(clone);
    }
    #[tokio::test]
    async fn record_and_transfer_errors_preserve_their_distinct_actor_classification() {
        for mode in [RecordMode::Error, RecordMode::Superseded] {
            let operation = operation();
            let events = Arc::new(Mutex::new(vec![]));
            let port = FakeTransfer::new(Cut::Success, events.clone());
            let mut record = FakeRecord {
                mode,
                events: events.clone(),
            };
            let (item, _) = item();
            let mut items = VecDeque::new();
            let mut bytes = 0;
            let result = record_and_push(
                &mut Output {
                    items: &mut items,
                    bytes: &mut bytes,
                    max_stanzas: 2,
                    max_bytes: 1024,
                },
                item,
                &operation,
                &mut record,
                &port,
            )
            .await;
            assert!(matches!(result, Err(RecordPushError::Record(_))));
            assert_eq!(*events.lock().unwrap(), vec!["record"]);
            assert!(operation.snapshot().transfers.is_empty());
        }
        let operation = operation();
        let events = Arc::new(Mutex::new(vec![]));
        let port = FakeTransfer::new(Cut::TypedAfterReceipt, events.clone());
        let mut record = FakeRecord {
            mode: RecordMode::Unmanaged,
            events,
        };
        let (item, mut receiver) = item();
        let clone = item.clone();
        let mut items = VecDeque::new();
        let mut bytes = 0;
        let result = record_and_push(
            &mut Output {
                items: &mut items,
                bytes: &mut bytes,
                max_stanzas: 2,
                max_bytes: 1024,
            },
            item,
            &operation,
            &mut record,
            &port,
        )
        .await;
        assert!(matches!(result, Err(RecordPushError::Transfer { .. })));
        assert_eq!(
            operation.snapshot().transfers[0].knowledge,
            TransferKnowledge::ReceiptKnown(current())
        );
        assert!(items.is_empty());
        assert!(receiver.try_recv().is_err());
        drop(clone);
    }
    #[tokio::test]
    async fn missing_wrong_or_unrelated_receipt_returns_never_mutate_notify_or_enqueue() {
        for cut in [
            Cut::BareSuccess,
            Cut::WrongToken,
            Cut::WrongIdentity,
            Cut::WrongReceipt,
        ] {
            let operation = operation();
            let events = Arc::new(Mutex::new(vec![]));
            let port = FakeTransfer::new(cut, events);
            let (item, mut receiver) = item();
            let clone = item.clone();
            let mut items = VecDeque::new();
            let mut bytes = 0;
            assert!(transfer_and_push(
                &mut Output {
                    items: &mut items,
                    bytes: &mut bytes,
                    max_stanzas: 2,
                    max_bytes: 1024
                },
                item,
                &operation,
                &port
            )
            .await
            .is_err());
            assert!(items.is_empty());
            assert_eq!(bytes, 0);
            assert!(receiver.try_recv().is_err());
            assert_eq!(clone.mix_delivery(), Some(old()));
            let facts = operation.snapshot().transfers[0];
            assert!(facts.returned_source.is_some());
            assert!(!facts.return_matches_receipt);
            assert!(!facts.local_entered && !facts.source_applied && !facts.notification_attempted);
            assert_eq!(facts.queue_accepted, None);
            assert_eq!(
                matches!(facts.knowledge, TransferKnowledge::ReceiptKnown(_)),
                matches!(cut, Cut::WrongToken | Cut::WrongIdentity)
            );
            if cut == Cut::WrongReceipt {
                assert_eq!(
                    port.other.snapshot().transfers[0].knowledge,
                    TransferKnowledge::ReceiptKnown(current())
                );
            }
        }
    }
    #[tokio::test]
    async fn cancelled_transfer_keeps_pending_or_committed_facts_without_handoff() {
        for cut in [
            Cut::BeforeRepositoryPending,
            Cut::DuringCommit,
            Cut::AfterReceiptPending,
        ] {
            let operation = operation();
            let port = FakeTransfer::new(cut, Arc::new(Mutex::new(vec![])));
            let (item, mut receiver) = item();
            let clone = item.clone();
            let mut items = VecDeque::new();
            let mut bytes = 0;
            {
                let mut output = Output {
                    items: &mut items,
                    bytes: &mut bytes,
                    max_stanzas: 2,
                    max_bytes: 1024,
                };
                let mut future = Box::pin(OperationRunner::new(
                    operation.clone(),
                    tokio::time::timeout(super::super::BOSH_BACKEND_OPERATION_TIMEOUT, async {
                        transfer_and_push(&mut output, item, &operation, &port)
                            .await
                            .unwrap()
                    }),
                ));
                assert!(poll_once(future.as_mut()).is_pending());
                drop(future);
            }
            assert!(items.is_empty());
            assert_eq!(bytes, 0);
            assert!(receiver.try_recv().is_err());
            drop(clone);
            let snapshot = operation.snapshot();
            assert_eq!(snapshot.terminal, Some(Terminal::Cancelled));
            assert_eq!(snapshot.keep_running, None);
            assert_eq!(
                snapshot.transfers[0].knowledge,
                match cut {
                    Cut::BeforeRepositoryPending => TransferKnowledge::NoCommitRequested,
                    Cut::DuringCommit => TransferKnowledge::CommitCallEntered(current()),
                    _ => TransferKnowledge::ReceiptKnown(current()),
                }
            );
            assert!(!snapshot.transfers[0].notification_attempted);
        }
    }
    #[tokio::test]
    async fn returned_failure_keeps_commit_knowledge_and_records_keep_running_false() {
        for cut in [Cut::BeforeCommit, Cut::CommitError, Cut::AfterReceiptError] {
            let operation = operation();
            let port = FakeTransfer::new(cut, Arc::new(Mutex::new(vec![])));
            let (item, mut receiver) = item();
            let clone = item.clone();
            let mut items = VecDeque::new();
            let mut bytes = 0;
            let accepted = {
                let mut output = Output {
                    items: &mut items,
                    bytes: &mut bytes,
                    max_stanzas: 2,
                    max_bytes: 1024,
                };
                OperationRunner::new(
                    operation.clone(),
                    tokio::time::timeout(super::super::BOSH_BACKEND_OPERATION_TIMEOUT, async {
                        transfer_and_push(&mut output, item, &operation, &port)
                            .await
                            .is_ok_and(|accepted| accepted)
                    }),
                )
                .await
                .unwrap()
            };
            assert!(!accepted);
            assert!(items.is_empty());
            assert!(receiver.try_recv().is_err());
            drop(clone);
            let snapshot = operation.snapshot();
            assert_eq!(snapshot.terminal, Some(Terminal::Returned));
            assert_eq!(snapshot.keep_running, Some(false));
            assert_eq!(
                snapshot.transfers[0].knowledge,
                match cut {
                    Cut::BeforeCommit => TransferKnowledge::NoCommitRequested,
                    Cut::CommitError => TransferKnowledge::CommitCallEntered(current()),
                    _ => TransferKnowledge::ReceiptKnown(current()),
                }
            );
        }
    }
    #[tokio::test]
    async fn controlled_post_transfer_fifo_refusal_preserves_commit_and_one_shot() {
        // Controlled continuation cut: production's serial borrowed FIFO
        // normally stays stable after its precheck; this is not a new await.
        let operation = operation();
        let port = FakeTransfer::new(Cut::Success, Arc::new(Mutex::new(vec![])));
        let (item, mut receiver) = item();
        let prepared = PreparedTransferItem::new(item, &operation).unwrap();
        let returned = port.transfer(&prepared.request).await.unwrap();
        let transferred = prepared.returned(returned).unwrap();
        let mut items = VecDeque::from([
            OutboundItem::plain("<presence/>".to_owned()),
            OutboundItem::plain("<presence/>".to_owned()),
        ]);
        let mut bytes = items.iter().map(|item| item.stanza.len()).sum();
        let before = bytes;
        assert!(!transferred
            .push(&mut Output {
                items: &mut items,
                bytes: &mut bytes,
                max_stanzas: 2,
                max_bytes: 1024
            })
            .unwrap());
        assert_eq!(
            receiver.try_recv().unwrap(),
            MixTransportCompletion::BoshPersisted {
                session_id: Uuid::from_u128(34)
            }
        );
        assert_eq!(items.len(), 2);
        assert_eq!(bytes, before);
        let facts = operation.snapshot().transfers[0];
        assert_eq!(facts.knowledge, TransferKnowledge::ReceiptKnown(current()));
        assert!(facts.source_applied && facts.notification_attempted);
        assert_eq!(facts.queue_accepted, Some(false));
    }
    #[tokio::test]
    async fn dropped_receiver_is_only_a_notification_attempt_and_does_not_undo_fifo_acceptance() {
        let operation = operation();
        let port = FakeTransfer::new(Cut::Success, Arc::new(Mutex::new(vec![])));
        let (item, receiver) = item();
        drop(receiver);
        let mut items = VecDeque::new();
        let mut bytes = 0;
        assert!(transfer_and_push(
            &mut Output {
                items: &mut items,
                bytes: &mut bytes,
                max_stanzas: 2,
                max_bytes: 1024
            },
            item,
            &operation,
            &port
        )
        .await
        .unwrap());
        assert_eq!(items.len(), 1);
        let facts = operation.snapshot().transfers[0];
        assert!(facts.notification_attempted);
        assert_eq!(facts.queue_accepted, Some(true));
    }
    #[test]
    fn private_preparation_rejects_invalid_shape_and_redacts_owned_payloads() {
        let operation = operation();
        let invalid = OutboundItem {
            durable_source: Some(TransportOwnershipSource::Mix(old())),
            ..OutboundItem::plain("<message/>".to_owned())
        };
        assert!(PreparedTransferItem::new(invalid, &operation).is_err());
        assert!(operation.snapshot().transfers.is_empty());
        let (item, _) = item();
        let prepared = PreparedTransferItem::new(item, &operation).unwrap();
        let text = format!("{prepared:?}");
        assert!(!text.contains("private-body"));
        assert!(!text.contains("secret"));
        assert!(!text.contains(&old().lease_token.to_string()));
        prepared.request.enter_commit(current()).unwrap().received();
        let transferred = prepared.returned(current()).unwrap();
        assert!(!format!("{transferred:?}").contains("private-body"));
        operation.retire(Terminal::Cancelled);
        let mut items = VecDeque::new();
        let mut bytes = 0;
        assert!(transferred
            .push(&mut Output {
                items: &mut items,
                bytes: &mut bytes,
                max_stanzas: 2,
                max_bytes: 1024
            })
            .is_err());
        assert!(items.is_empty());
    }
    struct DropProbe {
        operation: Operation,
        dropped: Arc<AtomicBool>,
        ready: bool,
        panic_poll: bool,
        panic_drop: bool,
    }
    impl Future for DropProbe {
        type Output = Result<bool, tokio::time::error::Elapsed>;
        fn poll(self: Pin<&mut Self>, _: &mut TaskContext<'_>) -> Poll<Self::Output> {
            if self.panic_poll {
                panic!("BOSH child poll panic");
            }
            if self.ready {
                Poll::Ready(Ok(false))
            } else {
                Poll::Pending
            }
        }
    }
    impl Drop for DropProbe {
        fn drop(&mut self) {
            assert!(self.operation.snapshot().terminal.is_none());
            self.dropped.store(true, Ordering::SeqCst);
            if self.panic_drop {
                panic!("BOSH child drop panic");
            }
        }
    }
    #[test]
    fn owner_drops_unpolled_cancelled_ready_and_panicking_children_before_summary() {
        for case in 0..5 {
            let operation = operation();
            let dropped = Arc::new(AtomicBool::new(false));
            let child = DropProbe {
                operation: operation.clone(),
                dropped: dropped.clone(),
                ready: case == 2 || case == 4,
                panic_poll: case == 3,
                panic_drop: case == 4,
            };
            let mut future = Box::pin(OperationRunner::new(operation.clone(), child));
            if case != 0 {
                let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    poll_once(future.as_mut())
                }));
                if case >= 3 {
                    let payload = result.unwrap_err();
                    assert_eq!(
                        payload.downcast_ref::<&str>().copied(),
                        Some(if case == 3 {
                            "BOSH child poll panic"
                        } else {
                            "BOSH child drop panic"
                        })
                    );
                } else {
                    assert_eq!(result.unwrap().is_ready(), case == 2);
                }
            }
            drop(future);
            assert!(dropped.load(Ordering::SeqCst));
            let snapshot = operation.snapshot();
            assert_eq!(
                snapshot.terminal,
                Some(if case >= 3 {
                    Terminal::Panicked
                } else if case == 2 {
                    Terminal::Returned
                } else {
                    Terminal::Cancelled
                })
            );
            assert_eq!(snapshot.keep_running, (case == 2).then_some(false));
        }
    }
    #[tokio::test]
    async fn expired_test_timer_destroys_pending_child_before_timeout_summary() {
        let operation = operation();
        let dropped = Arc::new(AtomicBool::new(false));
        let child = DropProbe {
            operation: operation.clone(),
            dropped: dropped.clone(),
            ready: false,
            panic_poll: false,
            panic_drop: false,
        };
        // Only this in-process fixture uses an already-expired timer. The
        // actor's production budget remains the existing five seconds.
        let result = OperationRunner::new(
            operation.clone(),
            tokio::time::timeout(std::time::Duration::ZERO, async { child.await.unwrap() }),
        )
        .await;
        assert!(result.is_err());
        assert!(dropped.load(Ordering::SeqCst));
        let snapshot = operation.snapshot();
        assert_eq!(snapshot.terminal, Some(Terminal::TimedOut));
        assert_eq!(snapshot.keep_running, None);
    }
}
