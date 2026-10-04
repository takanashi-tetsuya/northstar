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

struct ObservationGuard {
    operation: Operation,
    finished: bool,
}
impl ObservationGuard {
    fn finish(&mut self, terminal: Terminal) {
        if self.finished {
            return;
        }
        self.finished = true;
        let summary = self.operation.retire(terminal);
        tracing::debug!(target: "rust_xmpp_server::bosh::ownership", ?summary, "BOSH operation retired");
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
        this.observation.finish(if result.is_err() {
            Terminal::TimedOut
        } else {
            Terminal::Returned
        });
        Poll::Ready(result)
    }
}
impl<F> Drop for OperationRunner<F> {
    fn drop(&mut self) {
        drop(self.child.take());
        if self.poll_in_progress {
            self.observation.finish(Terminal::Panicked);
        }
    }
}
