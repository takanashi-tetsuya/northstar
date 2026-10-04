//! Invocation-local BOSH ownership facts. This slice observes pending MIX
//! transfers; response binding, replay and ACK remain separate boundaries.
//! The outer owner has constant-size setup. Transfer metadata is allocated
//! lazily inside the existing timed actor child, bounded by its FIFO/action
//! flow. It owns no body, item, channel, capacity lease or background task.
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
        write!(f, "BOSH transfer rejected: {self:?}")
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
    pub local_entered: bool,
    pub source_applied: bool,
    pub notification_attempted: bool,
    pub queue_accepted: Option<bool>,
}
impl std::fmt::Debug for TransferSnapshot {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BoshTransferSnapshot")
            .field("knowledge", &self.knowledge)
            .field("return_matched", &self.returned_source.is_some())
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
    pub terminal: Option<Terminal>,
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
    pub transfers: usize,
    pub commit_unknown: usize,
    pub receipt_known: usize,
    pub notification_attempted: usize,
    pub queue_accepted: usize,
    pub queue_refused: usize,
    pub terminal: Option<Terminal>,
}
impl Snapshot {
    pub fn summary(&self) -> Summary {
        Summary {
            kind: self.scope.kind,
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
            terminal: None,
        })))
    }
    pub fn snapshot(&self) -> Snapshot {
        self.0.lock().unwrap_or_else(|e| e.into_inner()).clone()
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
        let mut state = self.0.lock().unwrap_or_else(|e| e.into_inner());
        state.terminal.get_or_insert(terminal);
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
    pub fn validate_for_io(&self) -> Result<(), Rejected> {
        let mut state = self.operation.0.lock().unwrap_or_else(|e| e.into_inner());
        if self.validate(&mut state)?.knowledge != TransferKnowledge::NoCommitRequested {
            return Err(Rejected::State);
        }
        Ok(())
    }
    pub fn enter_commit(&self, current: MixDelivery) -> Result<TransferCommitPermit, Rejected> {
        let mut state = self.operation.0.lock().unwrap_or_else(|e| e.into_inner());
        let transfer = self.validate(&mut state)?;
        if transfer.knowledge != TransferKnowledge::NoCommitRequested {
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
            if transfer.knowledge != TransferKnowledge::ReceiptKnown(current)
                || transfer.returned_source.is_some()
            {
                return Err(Rejected::Receipt);
            }
            transfer.returned_source = Some(current);
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
            if transfer.returned_source != Some(self.current) || transfer.local_entered {
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
