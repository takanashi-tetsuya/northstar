//! Per-turn SM persistence facts. Ordered source-less slots are part of a cut;
//! payloads remain in the runtime's existing immutable prepared views.
//! A current turn retains three ordered source-metadata vectors and a commit
//! fact; validation allocates temporary source vectors. Their lengths follow
//! the existing FIFO bounds. They are additional logical allocations, not
//! governor-precharged payloads or a hard process-RSS bound.
use crate::{DurableDelivery, MixDelivery, TransportOwnershipSource as Source};
use std::{future::Future, sync::{Arc, Mutex}};
use uuid::Uuid;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Purpose { Record, Checkpoint, Acknowledge { h: u32 } }
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HDecision { NotRequested, Invalid, Prefix(usize) }
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Scope { pub purpose: Purpose, pub session_id: Option<Uuid>, pub connection_id: Uuid, pub inbound_h: u32, pub outbound_h: u32, pub acked_h: u32, pub queued: usize }
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Binding {
    pub session_id: Option<Uuid>, pub connection_id: Uuid,
    pub inbound_h: u32, pub outbound_h: u32, pub acked_h: u32,
    pub whole: Vec<Option<Source>>, pub acknowledged: Vec<Option<Source>>, pub remaining: Vec<Option<Source>>,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MixRotation { pub previous: MixDelivery, pub current: MixDelivery }
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CommitFact {
    Checkpoint { rotations: Vec<MixRotation>, settled: Vec<Source> },
    UnpersistedAck { deleted: Vec<Source>, absent_unclaimed: Vec<DurableDelivery> },
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Knowledge {
    NotRequested, NoCommitRequested, NoPersistence,
    RollbackCallEntered, RollbackKnown,
    CommitCallEntered(Arc<CommitFact>), ReceiptKnown(Arc<CommitFact>),
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KnowledgeClass { NotRequested, NoCommitRequested, NoPersistence, RollbackCallEntered, RollbackKnown, CommitCallEntered, ReceiptKnown }
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Terminal { Returned, Cancelled, Panicked }
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Rejected { Retired, State, Scope, Cut, Result }
impl std::fmt::Display for Rejected {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result { write!(f, "SM ownership rejected: {self:?}") }
}
impl std::error::Error for Rejected {}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Snapshot {
    pub scope: Scope, pub h_decision: HDecision, pub binding: Option<Arc<Binding>>, pub knowledge: Knowledge,
    pub appended: bool, pub restored: bool, pub ownership_applied: bool,
    pub acknowledged_h_applied: Option<u32>, pub notified: bool,
    pub capacity_completed: Option<bool>, pub returned_updated: Option<bool>, pub returned_error: bool,
    pub terminal: Option<Terminal>,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Summary {
    pub purpose: Purpose, pub h_decision: HDecision, pub knowledge: KnowledgeClass,
    pub appended: bool, pub restored: bool, pub ownership_applied: bool,
    pub acknowledged_h_applied: Option<u32>, pub notified: bool,
    pub capacity_completed: Option<bool>, pub returned_updated: Option<bool>, pub returned_error: bool,
    pub committed_settled: Option<usize>, pub committed_absent_unclaimed: Option<usize>, pub terminal: Option<Terminal>,
}
impl Snapshot {
    pub fn summary(&self) -> Summary {
        let (settled, absent) = match &self.knowledge {
            Knowledge::ReceiptKnown(fact) => match fact.as_ref() {
                CommitFact::Checkpoint { settled, .. } => (Some(settled.len()), Some(0)),
                CommitFact::UnpersistedAck { deleted, absent_unclaimed } => (Some(deleted.len()), Some(absent_unclaimed.len())),
            },
            _ => (None, None),
        };
        Summary { purpose: self.scope.purpose, h_decision: self.h_decision,
            knowledge: match self.knowledge { Knowledge::NotRequested => KnowledgeClass::NotRequested, Knowledge::NoCommitRequested => KnowledgeClass::NoCommitRequested, Knowledge::NoPersistence => KnowledgeClass::NoPersistence, Knowledge::RollbackCallEntered => KnowledgeClass::RollbackCallEntered, Knowledge::RollbackKnown => KnowledgeClass::RollbackKnown, Knowledge::CommitCallEntered(_) => KnowledgeClass::CommitCallEntered, Knowledge::ReceiptKnown(_) => KnowledgeClass::ReceiptKnown },
            appended: self.appended, restored: self.restored, ownership_applied: self.ownership_applied, acknowledged_h_applied: self.acknowledged_h_applied,
            notified: self.notified, capacity_completed: self.capacity_completed, returned_updated: self.returned_updated, returned_error: self.returned_error,
            committed_settled: settled, committed_absent_unclaimed: absent, terminal: self.terminal }
    }
}
#[derive(Clone)]
pub struct Observation(Arc<Mutex<Snapshot>>);
impl std::fmt::Debug for Observation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result { f.write_str("SmObservation { turn-local facts }") }
}
impl Observation {
    pub fn new(scope: Scope) -> Self {
        Self(Arc::new(Mutex::new(Snapshot { scope, h_decision: HDecision::NotRequested, binding: None, knowledge: Knowledge::NotRequested,
            appended: false, restored: false, ownership_applied: false, acknowledged_h_applied: None, notified: false,
            capacity_completed: None, returned_updated: None, returned_error: false, terminal: None })))
    }
    pub fn snapshot(&self) -> Snapshot { self.0.lock().unwrap_or_else(|e| e.into_inner()).clone() }
    fn open(state: &Snapshot) -> Result<(), Rejected> { if state.terminal.is_some() { Err(Rejected::Retired) } else { Ok(()) } }
    pub fn bind(&self, binding: Binding) -> Result<Request, Rejected> {
        let mut state = self.0.lock().unwrap_or_else(|e| e.into_inner()); Self::open(&state)?;
        if state.binding.is_some() { return Err(Rejected::State); }
        let scope = state.scope;
        if binding.session_id != scope.session_id || binding.connection_id != scope.connection_id || binding.inbound_h != scope.inbound_h { return Err(Rejected::Scope); }
        let expected_outbound = scope.outbound_h.wrapping_add(u32::from(state.appended));
        let expected_acked = match scope.purpose { Purpose::Acknowledge { h } => h, _ => scope.acked_h };
        if binding.outbound_h != expected_outbound || binding.acked_h != expected_acked { return Err(Rejected::Scope); }
        if Some(binding.whole.len()) != scope.queued.checked_add(usize::from(state.appended))
            || Some(binding.whole.len()) != binding.acknowledged.len().checked_add(binding.remaining.len())
            || !binding.whole.iter().eq(binding.acknowledged.iter().chain(&binding.remaining))
            || (!matches!(scope.purpose, Purpose::Acknowledge { .. }) && !binding.acknowledged.is_empty()) { return Err(Rejected::Cut); }
        if matches!(scope.purpose, Purpose::Acknowledge { .. }) && state.h_decision != HDecision::Prefix(binding.acknowledged.len()) { return Err(Rejected::Cut); }
        let binding = Arc::new(binding);
        state.binding = Some(binding.clone()); state.knowledge = Knowledge::NoCommitRequested;
        Ok(Request { observation: self.clone(), binding })
    }
    pub fn h_decision(&self, delta: Option<usize>) { self.0.lock().unwrap_or_else(|e| e.into_inner()).h_decision = match delta { Some(delta) => HDecision::Prefix(delta), None => HDecision::Invalid }; }
    pub fn appended(&self) { self.0.lock().unwrap_or_else(|e| e.into_inner()).appended = true; }
    pub fn restored(&self) { self.0.lock().unwrap_or_else(|e| e.into_inner()).restored = true; }
    pub fn ownership_applied(&self) { self.0.lock().unwrap_or_else(|e| e.into_inner()).ownership_applied = true; }
    pub fn ack_applied(&self, h: u32) { self.0.lock().unwrap_or_else(|e| e.into_inner()).acknowledged_h_applied = Some(h); }
    pub fn notified(&self) { self.0.lock().unwrap_or_else(|e| e.into_inner()).notified = true; }
    pub fn capacity_completed(&self, result: bool) { self.0.lock().unwrap_or_else(|e| e.into_inner()).capacity_completed = Some(result); }
    pub fn returned_error(&self) { self.0.lock().unwrap_or_else(|e| e.into_inner()).returned_error = true; }
    pub fn retire(&self, terminal: Terminal) -> Summary {
        let mut state = self.0.lock().unwrap_or_else(|e| e.into_inner()); state.terminal.get_or_insert(terminal); state.summary()
    }
}
pub struct Request { observation: Observation, binding: Arc<Binding> }
impl std::fmt::Debug for Request {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result { f.write_str("SmRequest { immutable binding: [redacted] }") }
}
impl Request {
    pub fn purpose(&self) -> Purpose { self.observation.0.lock().unwrap_or_else(|e| e.into_inner()).scope.purpose }
    pub fn binding(&self) -> &Binding { &self.binding }
    fn validate(&self, state: &Snapshot) -> Result<(), Rejected> {
        Observation::open(state)?;
        if !state.binding.as_ref().is_some_and(|binding| Arc::ptr_eq(binding, &self.binding)) { return Err(Rejected::Scope); }
        Ok(())
    }
    pub fn validate_binding(&self, binding: &Binding) -> Result<(), Rejected> {
        let state = self.observation.0.lock().unwrap_or_else(|e| e.into_inner()); self.validate(&state)?;
        if self.binding.as_ref() != binding { return Err(Rejected::Cut); }
        if state.knowledge != Knowledge::NoCommitRequested { return Err(Rejected::State); }
        Ok(())
    }
    pub fn no_persistence(&self) -> Result<(), Rejected> {
        let mut state = self.observation.0.lock().unwrap_or_else(|e| e.into_inner()); self.validate(&state)?;
        if state.knowledge != Knowledge::NoCommitRequested || self.binding.session_id.is_some() || self.binding.acknowledged.iter().any(Option::is_some) { return Err(Rejected::State); }
        state.knowledge = Knowledge::NoPersistence; Ok(())
    }
    pub fn rollback_entered(&self) -> Result<RollbackPermit, Rejected> {
        let mut state = self.observation.0.lock().unwrap_or_else(|e| e.into_inner()); self.validate(&state)?;
        if state.knowledge != Knowledge::NoCommitRequested || self.binding.session_id.is_none() { return Err(Rejected::State); }
        state.knowledge = Knowledge::RollbackCallEntered; Ok(RollbackPermit { observation: self.observation.clone() })
    }
    pub fn enter_commit(&self, fact: CommitFact) -> Result<CommitPermit, Rejected> {
        let mut state = self.observation.0.lock().unwrap_or_else(|e| e.into_inner()); self.validate(&state)?;
        if state.knowledge != Knowledge::NoCommitRequested { return Err(Rejected::State); }
        let mut expected = self.binding.acknowledged.iter().flatten().copied().collect::<Vec<_>>();
        expected.sort_unstable_by_key(source_key);
        let mut actual = match &fact {
            CommitFact::Checkpoint { rotations, settled } => {
                if self.binding.session_id.is_none() || rotations.iter().any(|rotation| rotation.previous.delivery_id != rotation.current.delivery_id || !self.binding.remaining.contains(&Some(Source::Mix(rotation.previous)))) { return Err(Rejected::Result); }
                settled.clone()
            }
            CommitFact::UnpersistedAck { deleted, absent_unclaimed } => {
                if self.binding.session_id.is_some() || absent_unclaimed.iter().any(|delivery| delivery.claim_id.is_some()) { return Err(Rejected::Result); }
                deleted.iter().copied().chain(absent_unclaimed.iter().copied().map(Source::C2s)).collect()
            }
        };
        actual.sort_unstable_by_key(source_key);
        if actual != expected { return Err(Rejected::Result); }
        let fact = Arc::new(fact);
        state.knowledge = Knowledge::CommitCallEntered(fact.clone());
        Ok(CommitPermit { observation: self.observation.clone(), fact })
    }
    pub fn validate_checkpoint_return(&self, updated: bool, rotations: &[MixRotation]) -> Result<(), Rejected> {
        let mut state = self.observation.0.lock().unwrap_or_else(|e| e.into_inner()); self.validate(&state)?;
        let valid = match (&state.knowledge, updated) {
            (Knowledge::RollbackKnown, false) => rotations.is_empty(),
            (Knowledge::ReceiptKnown(fact), true) => matches!(fact.as_ref(), CommitFact::Checkpoint { rotations: committed, .. } if committed == rotations),
            _ => false,
        };
        if !valid { return Err(Rejected::Result); }
        state.returned_updated = Some(updated); Ok(())
    }
    pub fn validate_batch_return(&self) -> Result<(), Rejected> {
        let state = self.observation.0.lock().unwrap_or_else(|e| e.into_inner()); self.validate(&state)?;
        if self.binding.session_id.is_some() { return Err(Rejected::Scope); }
        if matches!(&state.knowledge, Knowledge::NoPersistence) || matches!(&state.knowledge, Knowledge::ReceiptKnown(fact) if matches!(fact.as_ref(), CommitFact::UnpersistedAck { .. })) { Ok(()) } else { Err(Rejected::Result) }
    }
}
fn source_key(source: &Source) -> (u8, Uuid, Uuid, Option<Uuid>) {
    match source { Source::C2s(delivery) => (0, delivery.recipient_id, delivery.message_id, delivery.claim_id), Source::Mix(delivery) => (1, delivery.delivery_id, Uuid::nil(), Some(delivery.lease_token)) }
}
pub struct RollbackPermit { observation: Observation }
impl RollbackPermit { pub fn completed(self) { self.observation.0.lock().unwrap_or_else(|e| e.into_inner()).knowledge = Knowledge::RollbackKnown; } }
pub struct CommitPermit { observation: Observation, fact: Arc<CommitFact> }
impl CommitPermit { pub fn received(self) { self.observation.0.lock().unwrap_or_else(|e| e.into_inner()).knowledge = Knowledge::ReceiptKnown(self.fact); } }
#[derive(Debug)]
pub enum CompletionError<E> { Binding(Rejected), Repository(E) }
impl<E: std::fmt::Display> std::fmt::Display for CompletionError<E> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result { match self { Self::Binding(error) => std::fmt::Display::fmt(error, f), Self::Repository(error) => std::fmt::Display::fmt(error, f) } }
}
impl<E: std::error::Error + 'static> std::error::Error for CompletionError<E> {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> { Some(match self { Self::Binding(error) => error, Self::Repository(error) => error }) }
}
pub async fn commit_observed<E>(future: impl Future<Output = Result<(), E>>, request: &Request, fact: CommitFact) -> Result<(), CompletionError<E>> {
    let permit = request.enter_commit(fact).map_err(CompletionError::Binding)?;
    future.await.map_err(CompletionError::Repository)?;
    permit.received(); Ok(())
}
pub async fn rollback_observed<E>(future: impl Future<Output = Result<(), E>>, request: &Request) -> Result<(), CompletionError<E>> {
    let permit = request.rollback_entered().map_err(CompletionError::Binding)?;
    future.await.map_err(CompletionError::Repository)?;
    permit.completed(); Ok(())
}
