//! Invocation-local BOSH ownership facts. Pending MIX transfers, response
//! binding, renewal and ACK retain separate transaction knowledge.
//! The outer owner has constant-size setup. Transfer metadata is allocated
//! lazily inside the existing timed actor child, bounded by its FIFO/action
//! flow. The actor's T <= 2S+1 bound is a logical record count; Vec capacity
//! and allocator/RSS bytes require separate measurement. No metadata cap or
//! new traffic rejection is introduced here. It owns no body, item, channel,
//! capacity lease or background task.
pub mod response;
pub use response::BoshResponseOwnership;

use crate::MixDelivery;
use std::{
    future::Future,
    sync::{Arc, Mutex},
};
use uuid::Uuid;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OperationKind {
    Request,
    Outbound,
    HeldResponse,
}
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct Scope {
    pub session_id: Uuid,
    pub ttl_seconds: u64,
    pub kind: OperationKind,
}
impl std::fmt::Debug for Scope {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BoshScope")
            .field("kind", &self.kind)
            .field("ttl_seconds", &self.ttl_seconds)
            .finish_non_exhaustive()
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Terminal {
    Returned,
    TimedOut,
    Cancelled,
    Panicked,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Rejected {
    Retired,
    State,
    Source,
    Receipt,
}
impl std::fmt::Display for Rejected {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "BOSH operation rejected: {self:?}")
    }
}
impl std::error::Error for Rejected {}
#[derive(Clone, Copy, Eq, PartialEq)]
pub enum TransferKnowledge {
    NoCommitRequested,
    CommitCallEntered(MixDelivery),
    ReceiptKnown(MixDelivery),
}
impl std::fmt::Debug for TransferKnowledge {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::NoCommitRequested => "NoCommitRequested",
            Self::CommitCallEntered(_) => "CommitCallEntered([redacted])",
            Self::ReceiptKnown(_) => "ReceiptKnown([redacted])",
        })
    }
}
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct TransferSnapshot {
    pub source: MixDelivery,
    pub knowledge: TransferKnowledge,
    pub returned_source: Option<MixDelivery>,
    pub return_matches_receipt: bool,
    pub local_entered: bool,
    pub source_applied: bool,
    pub notification_attempted: bool,
    pub queue_accepted: Option<bool>,
}
impl std::fmt::Debug for TransferSnapshot {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BoshTransferSnapshot")
            .field("knowledge", &self.knowledge)
            .field("return_observed", &self.returned_source.is_some())
            .field("return_matches_receipt", &self.return_matches_receipt)
            .field("local_entered", &self.local_entered)
            .field("source_applied", &self.source_applied)
            .field("notification_attempted", &self.notification_attempted)
            .field("queue_accepted", &self.queue_accepted)
            .finish_non_exhaustive()
    }
}
#[derive(Clone, Eq, PartialEq)]
pub struct Snapshot {
    pub scope: Scope,
    pub transfers: Vec<TransferSnapshot>,
    pub responses: Vec<response::ResponseSnapshot>,
    pub renewals: Vec<response::RenewSnapshot>,
    pub acknowledgements: Vec<response::AckSnapshot>,
    pub terminal: Option<Terminal>,
    pub keep_running: Option<bool>,
}
impl std::fmt::Debug for Snapshot {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BoshOperationSnapshot")
            .field("summary", &self.summary())
            .finish_non_exhaustive()
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Summary {
    pub kind: OperationKind,
    pub responses: response::ResponseSummary,
    pub transfers: usize,
    pub commit_unknown: usize,
    pub receipt_known: usize,
    pub mismatched_returns: usize,
    pub notification_attempted: usize,
    pub queue_accepted: usize,
    pub queue_refused: usize,
    pub terminal: Option<Terminal>,
    pub keep_running: Option<bool>,
}
impl Snapshot {
    pub fn summary(&self) -> Summary {
        Summary {
            kind: self.scope.kind,
            responses: response::ResponseSummary {
                responses: self.responses.len(),
                bind_unknown: self
                    .responses
                    .iter()
                    .flat_map(|response| &response.attempts)
                    .filter(|attempt| {
                        matches!(
                            attempt.knowledge,
                            response::BindKnowledge::CommitCallEntered(_)
                        )
                    })
                    .count(),
                bind_receipts: self
                    .responses
                    .iter()
                    .flat_map(|response| &response.attempts)
                    .filter(|attempt| {
                        matches!(attempt.knowledge, response::BindKnowledge::ReceiptKnown(_))
                    })
                    .count(),
                restored_indices: self
                    .responses
                    .iter()
                    .flat_map(|response| &response.attempts)
                    .map(|attempt| attempt.removed_indices.len())
                    .sum(),
                retained_removal_capacity: self
                    .responses
                    .iter()
                    .flat_map(|response| &response.attempts)
                    .map(|attempt| attempt.removed_indices.capacity())
                    .sum(),
                accepted_responders: self
                    .responses
                    .iter()
                    .map(|response| response.accepted_responders)
                    .sum(),
                control_accepted: self
                    .responses
                    .iter()
                    .map(|response| response.control_accepted)
                    .sum(),
                cached: self
                    .responses
                    .iter()
                    .filter(|response| response.cached)
                    .count(),
                renew_unknown: self
                    .renewals
                    .iter()
                    .filter(|renewal| renewal.knowledge == response::Knowledge::CommitCallEntered)
                    .count(),
                renew_receipts: self
                    .renewals
                    .iter()
                    .filter(|renewal| renewal.knowledge == response::Knowledge::ReceiptKnown)
                    .count(),
                ack_unknown: self
                    .acknowledgements
                    .iter()
                    .filter(|ack| ack.knowledge == response::Knowledge::CommitCallEntered)
                    .count(),
                ack_receipts: self
                    .acknowledgements
                    .iter()
                    .filter(|ack| ack.knowledge == response::Knowledge::ReceiptKnown)
                    .count(),
                deleted: self
                    .acknowledgements
                    .iter()
                    .filter(|ack| ack.knowledge == response::Knowledge::ReceiptKnown)
                    .filter_map(|ack| ack.deleted.as_ref())
                    .map(|deleted| deleted.len())
                    .sum(),
                evictions: self
                    .acknowledgements
                    .iter()
                    .map(|ack| ack.cache_evictions)
                    .sum(),
                receipt_sends: self
                    .acknowledgements
                    .iter()
                    .map(|ack| ack.receipts_sent)
                    .sum(),
            },
            transfers: self.transfers.len(),
            commit_unknown: self
                .transfers
                .iter()
                .filter(|transfer| {
                    matches!(transfer.knowledge, TransferKnowledge::CommitCallEntered(_))
                })
                .count(),
            receipt_known: self
                .transfers
                .iter()
                .filter(|transfer| matches!(transfer.knowledge, TransferKnowledge::ReceiptKnown(_)))
                .count(),
            mismatched_returns: self
                .transfers
                .iter()
                .filter(|transfer| {
                    transfer.returned_source.is_some() && !transfer.return_matches_receipt
                })
                .count(),
            notification_attempted: self
                .transfers
                .iter()
                .filter(|transfer| transfer.notification_attempted)
                .count(),
            queue_accepted: self
                .transfers
                .iter()
                .filter(|transfer| transfer.queue_accepted == Some(true))
                .count(),
            queue_refused: self
                .transfers
                .iter()
                .filter(|transfer| transfer.queue_accepted == Some(false))
                .count(),
            terminal: self.terminal,
            keep_running: self.keep_running,
        }
    }
}
#[derive(Clone)]
pub struct Operation(Arc<Mutex<Snapshot>>);
impl std::fmt::Debug for Operation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("BoshOperation { invocation-local facts }")
    }
}
impl Operation {
    pub fn new(scope: Scope) -> Self {
        Self(Arc::new(Mutex::new(Snapshot {
            scope,
            transfers: Vec::new(),
            responses: Vec::new(),
            renewals: Vec::new(),
            acknowledgements: Vec::new(),
            terminal: None,
            keep_running: None,
        })))
    }
    pub fn session_id(&self) -> Uuid {
        self.0
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .scope
            .session_id
    }
    pub fn snapshot(&self) -> Snapshot {
        self.0.lock().unwrap_or_else(|e| e.into_inner()).clone()
    }
    /// Inspect retained storage without cloning vectors and losing their spare
    /// capacity. Counts describe these allocations, not allocator or RSS bytes.
    pub fn summary(&self) -> Summary {
        self.0.lock().unwrap_or_else(|e| e.into_inner()).summary()
    }
    fn open(state: &Snapshot) -> Result<(), Rejected> {
        if state.terminal.is_some() {
            Err(Rejected::Retired)
        } else {
            Ok(())
        }
    }
    pub fn begin_transfer(&self, source: MixDelivery) -> Result<TransferRequest, Rejected> {
        let mut state = self.0.lock().unwrap_or_else(|e| e.into_inner());
        Self::open(&state)?;
        let index = state.transfers.len();
        let scope = state.scope;
        state.transfers.push(TransferSnapshot {
            source,
            knowledge: TransferKnowledge::NoCommitRequested,
            returned_source: None,
            return_matches_receipt: false,
            local_entered: false,
            source_applied: false,
            notification_attempted: false,
            queue_accepted: None,
        });
        Ok(TransferRequest {
            operation: self.clone(),
            index,
            source,
            scope,
        })
    }
    pub fn retire(&self, terminal: Terminal) -> Summary {
        self.finish(terminal, None)
    }
    pub fn returned(&self, keep_running: bool) -> Summary {
        self.finish(Terminal::Returned, Some(keep_running))
    }
    fn finish(&self, terminal: Terminal, keep_running: Option<bool>) -> Summary {
        let mut state = self.0.lock().unwrap_or_else(|e| e.into_inner());
        if state.terminal.is_none() {
            state.terminal = Some(terminal);
            state.keep_running = keep_running;
        }
        state.summary()
    }
}
/// Constructed from the actor's actual item by its private service preparation.
/// This carries immutable inputs, never database authority by itself.
pub struct TransferRequest {
    operation: Operation,
    index: usize,
    source: MixDelivery,
    scope: Scope,
}
impl std::fmt::Debug for TransferRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("BoshTransferRequest { immutable binding: [redacted] }")
    }
}
impl TransferRequest {
    pub fn source(&self) -> MixDelivery {
        self.source
    }
    pub fn session_id(&self) -> Uuid {
        self.scope.session_id
    }
    pub fn ttl_seconds(&self) -> u64 {
        self.scope.ttl_seconds
    }
    fn validate<'a>(&self, state: &'a mut Snapshot) -> Result<&'a mut TransferSnapshot, Rejected> {
        Operation::open(state)?;
        if state.scope != self.scope {
            return Err(Rejected::Source);
        }
        let transfer = state.transfers.get_mut(self.index).ok_or(Rejected::State)?;
        if transfer.source != self.source {
            return Err(Rejected::Source);
        }
        Ok(transfer)
    }
    /// A pre-I/O state check, not a consuming start permit. The private item
    /// helper makes one port call, and enter_commit separately admits one
    /// COMMIT. This method alone does not exclude concurrent SQL invocations.
    pub fn validate_for_io(&self) -> Result<(), Rejected> {
        let mut state = self.operation.0.lock().unwrap_or_else(|e| e.into_inner());
        let transfer = self.validate(&mut state)?;
        if transfer.knowledge != TransferKnowledge::NoCommitRequested
            || transfer.returned_source.is_some()
        {
            return Err(Rejected::State);
        }
        Ok(())
    }
    pub fn enter_commit(&self, current: MixDelivery) -> Result<TransferCommitPermit, Rejected> {
        let mut state = self.operation.0.lock().unwrap_or_else(|e| e.into_inner());
        let transfer = self.validate(&mut state)?;
        if transfer.knowledge != TransferKnowledge::NoCommitRequested
            || transfer.returned_source.is_some()
        {
            return Err(Rejected::State);
        }
        // SQL generates a new UUID but does not assert token inequality.
        if current.delivery_id != self.source.delivery_id {
            return Err(Rejected::Source);
        }
        transfer.knowledge = TransferKnowledge::CommitCallEntered(current);
        Ok(TransferCommitPermit {
            operation: self.operation.clone(),
            index: self.index,
            current,
        })
    }
    pub fn returned(self, current: MixDelivery) -> Result<Transferred, Rejected> {
        {
            let mut state = self.operation.0.lock().unwrap_or_else(|e| e.into_inner());
            let transfer = self.validate(&mut state)?;
            if transfer.returned_source.is_some() {
                return Err(Rejected::State);
            }
            // Retain the actual return independently. A later positive COMMIT
            // callback must not retroactively accept this rejected return.
            transfer.returned_source = Some(current);
            transfer.return_matches_receipt =
                transfer.knowledge == TransferKnowledge::ReceiptKnown(current);
            if !transfer.return_matches_receipt {
                return Err(Rejected::Receipt);
            }
        }
        Ok(Transferred {
            request: self,
            current,
        })
    }
}
pub struct TransferCommitPermit {
    operation: Operation,
    index: usize,
    current: MixDelivery,
}
impl TransferCommitPermit {
    /// Prepared before COMMIT. Retaining the matching positive receipt cannot
    /// fail or depend on a later caller result, even after outer retirement.
    pub fn received(self) {
        self.operation
            .0
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .transfers[self.index]
            .knowledge = TransferKnowledge::ReceiptKnown(self.current);
    }
}
pub struct Transferred {
    request: TransferRequest,
    current: MixDelivery,
}
impl std::fmt::Debug for Transferred {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("BoshTransferred { matched receipt: [redacted] }")
    }
}
impl Transferred {
    pub fn begin_local(self) -> Result<LocalTransfer, Rejected> {
        {
            let mut state = self
                .request
                .operation
                .0
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            let transfer = self.request.validate(&mut state)?;
            if !transfer.return_matches_receipt
                || transfer.returned_source != Some(self.current)
                || transfer.knowledge != TransferKnowledge::ReceiptKnown(self.current)
                || transfer.local_entered
            {
                return Err(Rejected::State);
            }
            transfer.local_entered = true;
        }
        Ok(LocalTransfer {
            operation: self.request.operation,
            index: self.request.index,
            current: self.current,
            session_id: self.request.scope.session_id,
        })
    }
}
/// One already-entered synchronous item mutation/notification/FIFO call chain.
pub struct LocalTransfer {
    operation: Operation,
    index: usize,
    current: MixDelivery,
    session_id: Uuid,
}
impl LocalTransfer {
    pub fn current(&self) -> MixDelivery {
        self.current
    }
    pub fn session_id(&self) -> Uuid {
        self.session_id
    }
    pub fn source_applied(&self) {
        self.operation
            .0
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .transfers[self.index]
            .source_applied = true;
    }
    pub fn notification_attempted(&self) {
        self.operation
            .0
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .transfers[self.index]
            .notification_attempted = true;
    }
    pub fn queue_returned(self, accepted: bool) {
        self.operation
            .0
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .transfers[self.index]
            .queue_accepted = Some(accepted);
    }
}
#[derive(Debug)]
pub enum CompletionError<E> {
    Binding(Rejected),
    Repository(E),
}
impl<E: std::fmt::Display> std::fmt::Display for CompletionError<E> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Binding(error) => std::fmt::Display::fmt(error, f),
            Self::Repository(error) => std::fmt::Display::fmt(error, f),
        }
    }
}
impl<E: std::error::Error + 'static> std::error::Error for CompletionError<E> {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(match self {
            Self::Binding(error) => error,
            Self::Repository(error) => error,
        })
    }
}
pub async fn transfer_commit_observed<E>(
    future: impl Future<Output = Result<(), E>>,
    request: &TransferRequest,
    current: MixDelivery,
) -> Result<(), CompletionError<E>> {
    let permit = request
        .enter_commit(current)
        .map_err(CompletionError::Binding)?;
    future.await.map_err(CompletionError::Repository)?;
    permit.received();
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        pin::Pin,
        sync::atomic::{AtomicBool, Ordering},
        task::{Context, Poll, Waker},
    };
    fn old() -> MixDelivery {
        MixDelivery {
            delivery_id: Uuid::from_u128(11),
            lease_token: Uuid::from_u128(12),
        }
    }
    fn current() -> MixDelivery {
        MixDelivery {
            lease_token: Uuid::from_u128(13),
            ..old()
        }
    }
    fn operation() -> Operation {
        Operation::new(Scope {
            session_id: Uuid::from_u128(14),
            ttl_seconds: 86_400,
            kind: OperationKind::Outbound,
        })
    }
    fn poll_once<F: Future>(future: Pin<&mut F>) -> Poll<F::Output> {
        future.poll(&mut Context::from_waker(Waker::noop()))
    }
    #[test]
    fn closed_request_preserves_original_scope_and_rejects_retargeting_before_commit_poll() {
        let operation = operation();
        let request = operation.begin_transfer(old()).unwrap();
        assert_eq!(request.source(), old());
        assert_eq!(request.session_id(), Uuid::from_u128(14));
        assert_eq!(request.ttl_seconds(), 86_400);
        // Checking I/O state does not consume a SQL-start permit.
        request.validate_for_io().unwrap();
        request.validate_for_io().unwrap();
        let before = operation.snapshot();
        let polled = AtomicBool::new(false);
        let mut future = Box::pin(transfer_commit_observed(
            async {
                polled.store(true, Ordering::SeqCst);
                Ok::<_, std::io::Error>(())
            },
            &request,
            MixDelivery {
                delivery_id: Uuid::nil(),
                ..current()
            },
        ));
        assert!(matches!(
            poll_once(future.as_mut()),
            Poll::Ready(Err(CompletionError::Binding(Rejected::Source)))
        ));
        drop(future);
        assert!(!polled.load(Ordering::SeqCst));
        assert_eq!(operation.snapshot(), before);
        for change in 0..3 {
            let mut changed = TransferRequest {
                operation: operation.clone(),
                index: 0,
                source: old(),
                scope: before.scope,
            };
            match change {
                0 => changed.scope.session_id = Uuid::nil(),
                1 => changed.scope.ttl_seconds = 300,
                _ => changed.source.lease_token = Uuid::nil(),
            }
            assert_eq!(changed.validate_for_io(), Err(Rejected::Source));
            assert_eq!(operation.snapshot(), before);
        }
    }
    #[test]
    fn commit_drop_error_and_receipt_remain_distinct_without_rollback_inference() {
        for cut in 0..3 {
            let operation = operation();
            let request = operation.begin_transfer(old()).unwrap();
            let mut future = Box::pin(transfer_commit_observed(
                async {
                    if cut == 0 {
                        std::future::pending::<()>().await;
                    }
                    if cut == 1 {
                        Err(std::io::Error::other("COMMIT response loss"))
                    } else {
                        Ok(())
                    }
                },
                &request,
                current(),
            ));
            let result = poll_once(future.as_mut());
            assert_eq!(result.is_pending(), cut == 0);
            drop(future);
            let summary = operation.retire(Terminal::Cancelled);
            assert_eq!(summary.receipt_known, usize::from(cut == 2));
            assert_eq!(summary.commit_unknown, usize::from(cut != 2));
            assert_eq!(
                operation.snapshot().transfers[0].knowledge,
                if cut == 2 {
                    TransferKnowledge::ReceiptKnown(current())
                } else {
                    TransferKnowledge::CommitCallEntered(current())
                }
            );
            assert!(matches!(
                request.enter_commit(current()),
                Err(Rejected::Retired)
            ));
        }
    }
    #[test]
    fn actual_mismatched_and_bare_returns_never_authorize_local_continuation() {
        for committed in [false, true] {
            let operation = operation();
            let request = operation.begin_transfer(old()).unwrap();
            if committed {
                request.enter_commit(current()).unwrap().received();
            }
            let returned = MixDelivery {
                lease_token: Uuid::from_u128(15),
                ..current()
            };
            assert!(matches!(request.returned(returned), Err(Rejected::Receipt)));
            let snapshot = operation.snapshot();
            let transfer = snapshot.transfers[0];
            assert_eq!(transfer.returned_source, Some(returned));
            assert!(!transfer.return_matches_receipt);
            assert!(!transfer.local_entered);
            assert_eq!(snapshot.summary().mismatched_returns, 1);
            assert_eq!(snapshot.summary().receipt_known, usize::from(committed));
        }
    }
    #[test]
    fn late_receipt_does_not_retroactively_accept_an_earlier_rejected_return() {
        let operation = operation();
        let request = operation.begin_transfer(old()).unwrap();
        let permit = request.enter_commit(current()).unwrap();
        assert!(matches!(
            request.returned(current()),
            Err(Rejected::Receipt)
        ));
        operation.retire(Terminal::Cancelled);
        permit.received();
        let transfer = operation.snapshot().transfers[0];
        assert_eq!(
            transfer.knowledge,
            TransferKnowledge::ReceiptKnown(current())
        );
        assert_eq!(transfer.returned_source, Some(current()));
        assert!(!transfer.return_matches_receipt);
        assert!(!transfer.local_entered);
    }
    #[test]
    fn same_source_invocations_and_old_owners_cannot_share_receipt_authority() {
        let first = operation();
        let second = operation();
        let a = first.begin_transfer(old()).unwrap();
        let b = second.begin_transfer(old()).unwrap();
        b.enter_commit(current()).unwrap().received();
        assert!(matches!(a.returned(current()), Err(Rejected::Receipt)));
        let before = first.snapshot();
        let continuation = b.returned(current()).unwrap();
        second.retire(Terminal::Cancelled);
        assert!(matches!(continuation.begin_local(), Err(Rejected::Retired)));
        assert_eq!(first.snapshot(), before);
        assert!(matches!(
            second.begin_transfer(old()),
            Err(Rejected::Retired)
        ));
    }
    #[test]
    fn exact_local_continuation_retains_commit_and_notification_on_fifo_refusal() {
        for accepted in [false, true] {
            let operation = operation();
            let request = operation.begin_transfer(old()).unwrap();
            // Equal tokens are valid if that is the actual SQL-returned value.
            request.enter_commit(old()).unwrap().received();
            let local = request.returned(old()).unwrap().begin_local().unwrap();
            assert_eq!(local.current(), old());
            assert_eq!(local.session_id(), Uuid::from_u128(14));
            local.source_applied();
            local.notification_attempted();
            local.queue_returned(accepted);
            let snapshot = operation.snapshot();
            assert_eq!(
                snapshot.transfers[0].knowledge,
                TransferKnowledge::ReceiptKnown(old())
            );
            assert!(snapshot.transfers[0].notification_attempted);
            assert_eq!(snapshot.transfers[0].queue_accepted, Some(accepted));
        }
    }
    #[test]
    fn terminal_kind_keep_running_and_lazy_metadata_are_separate_facts() {
        let operation = operation();
        assert_eq!(operation.0.lock().unwrap().transfers.capacity(), 0);
        // A finite maximum logical actor-flow shape, not an allocator/RSS cap.
        let s = 2_048;
        for _ in 0..(2 * s + 1) {
            drop(operation.begin_transfer(old()).unwrap());
        }
        assert_eq!(operation.snapshot().transfers.len(), 2 * s + 1);
        let summary = operation.returned(false);
        assert_eq!(summary.terminal, Some(Terminal::Returned));
        assert_eq!(summary.keep_running, Some(false));
        assert_eq!(operation.returned(true), summary);
        assert_eq!(operation.retire(Terminal::Cancelled), summary);
    }
    #[test]
    fn debug_redacts_retained_original_committed_and_mismatched_return_tokens() {
        let operation = operation();
        let request = operation.begin_transfer(old()).unwrap();
        request.enter_commit(current()).unwrap().received();
        let request_debug = format!("{request:?}");
        let wrong = MixDelivery {
            lease_token: Uuid::from_u128(15),
            ..current()
        };
        assert!(request.returned(wrong).is_err());
        let snapshot = operation.snapshot();
        assert_eq!(snapshot.transfers[0].source, old());
        assert_eq!(
            snapshot.transfers[0].knowledge,
            TransferKnowledge::ReceiptKnown(current())
        );
        assert_eq!(snapshot.transfers[0].returned_source, Some(wrong));
        let debug = format!(
            "{request_debug} {operation:?} {snapshot:?} {:?} {:?} {:?}",
            snapshot.scope, snapshot.transfers[0], snapshot.transfers[0].knowledge
        );
        for id in 11..=15 {
            assert!(!debug.contains(&Uuid::from_u128(id).to_string()));
        }
    }
}
