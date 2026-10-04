//! Per-turn SM persistence facts. Ordered source-less slots are part of a cut;
//! payloads remain in the runtime's existing immutable prepared views.
//! A current turn retains three ordered source-metadata vectors and a commit
//! fact; validation allocates temporary source vectors. Their lengths follow
//! the existing FIFO bounds. They are additional logical allocations, not
//! governor-precharged payloads or a hard process-RSS bound.
use crate::{DurableDelivery, MixDelivery, TransportOwnershipSource as Source};
use std::{
    collections::BTreeSet,
    future::Future,
    sync::{Arc, Mutex},
};
use uuid::Uuid;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Purpose {
    Record,
    Checkpoint,
    Acknowledge { h: u32 },
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HDecision {
    NotRequested,
    Invalid,
    Prefix(usize),
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Scope {
    pub purpose: Purpose,
    pub session_id: Option<Uuid>,
    pub connection_id: Uuid,
    pub inbound_h: u32,
    pub outbound_h: u32,
    pub acked_h: u32,
    pub queued: usize,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Binding {
    pub session_id: Option<Uuid>,
    pub connection_id: Uuid,
    pub inbound_h: u32,
    pub outbound_h: u32,
    pub acked_h: u32,
    pub whole: Vec<Option<Source>>,
    pub acknowledged: Vec<Option<Source>>,
    pub remaining: Vec<Option<Source>>,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MixRotation {
    pub previous: MixDelivery,
    pub current: MixDelivery,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CommitFact {
    Checkpoint {
        rotations: Vec<MixRotation>,
        settled: Vec<Source>,
    },
    UnpersistedAck {
        deleted: Vec<Source>,
        absent_unclaimed: Vec<DurableDelivery>,
    },
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Knowledge {
    NotRequested,
    NoCommitRequested,
    NoPersistence,
    RollbackCallEntered,
    RollbackKnown,
    CommitCallEntered(Arc<CommitFact>),
    ReceiptKnown(Arc<CommitFact>),
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KnowledgeClass {
    NotRequested,
    NoCommitRequested,
    NoPersistence,
    RollbackCallEntered,
    RollbackKnown,
    CommitCallEntered,
    ReceiptKnown,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Terminal {
    Returned,
    Cancelled,
    Panicked,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Rejected {
    Retired,
    State,
    Scope,
    Cut,
    Result,
}
impl std::fmt::Display for Rejected {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SM ownership rejected: {self:?}")
    }
}
impl std::error::Error for Rejected {}
#[derive(Clone, Eq, PartialEq)]
pub struct Snapshot {
    pub scope: Scope,
    pub h_decision: HDecision,
    pub binding: Option<Arc<Binding>>,
    pub knowledge: Knowledge,
    pub appended: bool,
    pub restored: bool,
    pub ownership_applied: bool,
    pub acknowledged_h_applied: Option<u32>,
    pub notification_attempted: bool,
    pub capacity_completed: Option<bool>,
    pub returned_updated: Option<bool>,
    pub returned_error: bool,
    pub terminal: Option<Terminal>,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Summary {
    pub purpose: Purpose,
    pub h_decision: HDecision,
    pub knowledge: KnowledgeClass,
    pub appended: bool,
    pub restored: bool,
    pub ownership_applied: bool,
    pub acknowledged_h_applied: Option<u32>,
    pub notification_attempted: bool,
    pub capacity_completed: Option<bool>,
    pub returned_updated: Option<bool>,
    pub returned_error: bool,
    pub committed_settled: Option<usize>,
    pub committed_absent_unclaimed: Option<usize>,
    pub terminal: Option<Terminal>,
}
impl std::fmt::Debug for Snapshot {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SmSnapshot")
            .field("summary", &self.summary())
            .finish_non_exhaustive()
    }
}
impl Snapshot {
    pub fn summary(&self) -> Summary {
        let (settled, absent) = match &self.knowledge {
            Knowledge::ReceiptKnown(fact) => match fact.as_ref() {
                CommitFact::Checkpoint { settled, .. } => (Some(settled.len()), Some(0)),
                CommitFact::UnpersistedAck {
                    deleted,
                    absent_unclaimed,
                } => (Some(deleted.len()), Some(absent_unclaimed.len())),
            },
            _ => (None, None),
        };
        Summary {
            purpose: self.scope.purpose,
            h_decision: self.h_decision,
            knowledge: match self.knowledge {
                Knowledge::NotRequested => KnowledgeClass::NotRequested,
                Knowledge::NoCommitRequested => KnowledgeClass::NoCommitRequested,
                Knowledge::NoPersistence => KnowledgeClass::NoPersistence,
                Knowledge::RollbackCallEntered => KnowledgeClass::RollbackCallEntered,
                Knowledge::RollbackKnown => KnowledgeClass::RollbackKnown,
                Knowledge::CommitCallEntered(_) => KnowledgeClass::CommitCallEntered,
                Knowledge::ReceiptKnown(_) => KnowledgeClass::ReceiptKnown,
            },
            appended: self.appended,
            restored: self.restored,
            ownership_applied: self.ownership_applied,
            acknowledged_h_applied: self.acknowledged_h_applied,
            notification_attempted: self.notification_attempted,
            capacity_completed: self.capacity_completed,
            returned_updated: self.returned_updated,
            returned_error: self.returned_error,
            committed_settled: settled,
            committed_absent_unclaimed: absent,
            terminal: self.terminal,
        }
    }
}
#[derive(Clone)]
pub struct Observation(Arc<Mutex<Snapshot>>);
impl std::fmt::Debug for Observation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SmObservation { turn-local facts }")
    }
}
impl Observation {
    pub fn new(scope: Scope) -> Self {
        Self(Arc::new(Mutex::new(Snapshot {
            scope,
            h_decision: HDecision::NotRequested,
            binding: None,
            knowledge: Knowledge::NotRequested,
            appended: false,
            restored: false,
            ownership_applied: false,
            acknowledged_h_applied: None,
            notification_attempted: false,
            capacity_completed: None,
            returned_updated: None,
            returned_error: false,
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
    pub fn bind(&self, binding: Binding) -> Result<Request, Rejected> {
        let mut state = self.0.lock().unwrap_or_else(|e| e.into_inner());
        Self::open(&state)?;
        if state.binding.is_some() {
            return Err(Rejected::State);
        }
        let scope = state.scope;
        if binding.session_id != scope.session_id
            || binding.connection_id != scope.connection_id
            || binding.inbound_h != scope.inbound_h
        {
            return Err(Rejected::Scope);
        }
        let expected_outbound = scope.outbound_h.wrapping_add(u32::from(state.appended));
        let expected_acked = match scope.purpose {
            Purpose::Acknowledge { h } => h,
            _ => scope.acked_h,
        };
        if binding.outbound_h != expected_outbound || binding.acked_h != expected_acked {
            return Err(Rejected::Scope);
        }
        if Some(binding.whole.len()) != scope.queued.checked_add(usize::from(state.appended))
            || Some(binding.whole.len())
                != binding
                    .acknowledged
                    .len()
                    .checked_add(binding.remaining.len())
            || !binding
                .whole
                .iter()
                .eq(binding.acknowledged.iter().chain(&binding.remaining))
            || (!matches!(scope.purpose, Purpose::Acknowledge { .. })
                && !binding.acknowledged.is_empty())
        {
            return Err(Rejected::Cut);
        }
        if matches!(scope.purpose, Purpose::Acknowledge { .. })
            && state.h_decision != HDecision::Prefix(binding.acknowledged.len())
        {
            return Err(Rejected::Cut);
        }
        let binding = Arc::new(binding);
        state.binding = Some(binding.clone());
        state.knowledge = Knowledge::NoCommitRequested;
        Ok(Request {
            observation: self.clone(),
            binding,
        })
    }
    pub fn h_decision(&self, delta: Option<usize>) {
        self.0.lock().unwrap_or_else(|e| e.into_inner()).h_decision = match delta {
            Some(delta) => HDecision::Prefix(delta),
            None => HDecision::Invalid,
        };
    }
    pub fn appended(&self) {
        self.0.lock().unwrap_or_else(|e| e.into_inner()).appended = true;
    }
    /// A typed adapter error cannot erase an entered or confirmed COMMIT.
    /// Current SQL emits supersession only before this boundary.
    pub fn may_restore_superseded(&self) -> bool {
        let state = self.0.lock().unwrap_or_else(|e| e.into_inner());
        state.terminal.is_none() && state.knowledge == Knowledge::NoCommitRequested
    }
    pub fn restored(&self) {
        self.0.lock().unwrap_or_else(|e| e.into_inner()).restored = true;
    }
    pub fn ownership_applied(&self) {
        self.0
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .ownership_applied = true;
    }
    pub fn ack_applied(&self, h: u32) {
        self.0
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .acknowledged_h_applied = Some(h);
    }
    /// The existing void item notification was invoked; channel delivery is not proven.
    pub fn notification_attempted(&self) {
        self.0
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .notification_attempted = true;
    }
    pub fn capacity_completed(&self, result: bool) {
        self.0
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .capacity_completed = Some(result);
    }
    pub fn returned_error(&self) {
        self.0
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .returned_error = true;
    }
    pub fn retire(&self, terminal: Terminal) -> Summary {
        let mut state = self.0.lock().unwrap_or_else(|e| e.into_inner());
        state.terminal.get_or_insert(terminal);
        state.summary()
    }
}
pub struct Request {
    observation: Observation,
    binding: Arc<Binding>,
}
impl std::fmt::Debug for Request {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SmRequest { immutable binding: [redacted] }")
    }
}
impl Request {
    pub fn purpose(&self) -> Purpose {
        self.observation
            .0
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .scope
            .purpose
    }
    pub fn binding(&self) -> &Binding {
        &self.binding
    }
    fn validate(&self, state: &Snapshot) -> Result<(), Rejected> {
        Observation::open(state)?;
        if !state
            .binding
            .as_ref()
            .is_some_and(|binding| Arc::ptr_eq(binding, &self.binding))
        {
            return Err(Rejected::Scope);
        }
        Ok(())
    }
    pub fn validate_binding(&self, binding: &Binding) -> Result<(), Rejected> {
        let state = self.observation.0.lock().unwrap_or_else(|e| e.into_inner());
        self.validate(&state)?;
        if self.binding.as_ref() != binding {
            return Err(Rejected::Cut);
        }
        if state.knowledge != Knowledge::NoCommitRequested {
            return Err(Rejected::State);
        }
        Ok(())
    }
    pub fn no_persistence(&self) -> Result<(), Rejected> {
        let mut state = self.observation.0.lock().unwrap_or_else(|e| e.into_inner());
        self.validate(&state)?;
        if state.knowledge != Knowledge::NoCommitRequested
            || self.binding.session_id.is_some()
            || self.binding.acknowledged.iter().any(Option::is_some)
        {
            return Err(Rejected::State);
        }
        state.knowledge = Knowledge::NoPersistence;
        Ok(())
    }
    pub fn rollback_entered(&self) -> Result<RollbackPermit, Rejected> {
        let mut state = self.observation.0.lock().unwrap_or_else(|e| e.into_inner());
        self.validate(&state)?;
        if state.knowledge != Knowledge::NoCommitRequested || self.binding.session_id.is_none() {
            return Err(Rejected::State);
        }
        state.knowledge = Knowledge::RollbackCallEntered;
        Ok(RollbackPermit {
            observation: self.observation.clone(),
        })
    }
    pub fn enter_commit(&self, fact: CommitFact) -> Result<CommitPermit, Rejected> {
        let mut state = self.observation.0.lock().unwrap_or_else(|e| e.into_inner());
        self.validate(&state)?;
        if state.knowledge != Knowledge::NoCommitRequested {
            return Err(Rejected::State);
        }
        let mut expected = self
            .binding
            .acknowledged
            .iter()
            .flatten()
            .copied()
            .collect::<Vec<_>>();
        expected.sort_unstable_by_key(source_key);
        let mut actual = match &fact {
            CommitFact::Checkpoint { rotations, settled } => {
                if self.binding.session_id.is_none() {
                    return Err(Rejected::Result);
                }
                let remaining = self
                    .binding
                    .remaining
                    .iter()
                    .flatten()
                    .map(source_key)
                    .collect::<BTreeSet<_>>();
                let mut rotated = BTreeSet::new();
                for rotation in rotations {
                    let key = source_key(&Source::Mix(rotation.previous));
                    if rotation.previous.delivery_id != rotation.current.delivery_id
                        || !remaining.contains(&key)
                        || !rotated.insert(rotation.previous.delivery_id)
                    {
                        return Err(Rejected::Result);
                    }
                }
                settled.clone()
            }
            CommitFact::UnpersistedAck {
                deleted,
                absent_unclaimed,
            } => {
                if self.binding.session_id.is_some()
                    || absent_unclaimed
                        .iter()
                        .any(|delivery| delivery.claim_id.is_some())
                {
                    return Err(Rejected::Result);
                }
                deleted
                    .iter()
                    .copied()
                    .chain(absent_unclaimed.iter().copied().map(Source::C2s))
                    .collect()
            }
        };
        actual.sort_unstable_by_key(source_key);
        if actual != expected {
            return Err(Rejected::Result);
        }
        let fact = Arc::new(fact);
        state.knowledge = Knowledge::CommitCallEntered(fact.clone());
        Ok(CommitPermit {
            observation: self.observation.clone(),
            fact,
        })
    }
    pub fn validate_checkpoint_return(
        &self,
        updated: bool,
        rotations: &[MixRotation],
    ) -> Result<(), Rejected> {
        let mut state = self.observation.0.lock().unwrap_or_else(|e| e.into_inner());
        self.validate(&state)?;
        let valid = match (&state.knowledge, updated) {
            (Knowledge::RollbackKnown, false) => rotations.is_empty(),
            (Knowledge::ReceiptKnown(fact), true) => {
                matches!(fact.as_ref(), CommitFact::Checkpoint { rotations: committed, .. } if committed == rotations)
            }
            _ => false,
        };
        if !valid {
            return Err(Rejected::Result);
        }
        state.returned_updated = Some(updated);
        Ok(())
    }
    pub fn validate_batch_return(&self) -> Result<(), Rejected> {
        let state = self.observation.0.lock().unwrap_or_else(|e| e.into_inner());
        self.validate(&state)?;
        if self.binding.session_id.is_some() {
            return Err(Rejected::Scope);
        }
        if matches!(&state.knowledge, Knowledge::NoPersistence)
            || matches!(&state.knowledge, Knowledge::ReceiptKnown(fact) if matches!(fact.as_ref(), CommitFact::UnpersistedAck { .. }))
        {
            Ok(())
        } else {
            Err(Rejected::Result)
        }
    }
}
fn source_key(source: &Source) -> (u8, Uuid, Uuid, Option<Uuid>) {
    match source {
        Source::C2s(delivery) => (
            0,
            delivery.recipient_id,
            delivery.message_id,
            delivery.claim_id,
        ),
        Source::Mix(delivery) => (
            1,
            delivery.delivery_id,
            Uuid::nil(),
            Some(delivery.lease_token),
        ),
    }
}
pub struct RollbackPermit {
    observation: Observation,
}
impl RollbackPermit {
    pub fn completed(self) {
        self.observation
            .0
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .knowledge = Knowledge::RollbackKnown;
    }
}
pub struct CommitPermit {
    observation: Observation,
    fact: Arc<CommitFact>,
}
impl CommitPermit {
    pub fn received(self) {
        self.observation
            .0
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .knowledge = Knowledge::ReceiptKnown(self.fact);
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
pub async fn commit_observed<E>(
    future: impl Future<Output = Result<(), E>>,
    request: &Request,
    fact: CommitFact,
) -> Result<(), CompletionError<E>> {
    let permit = request
        .enter_commit(fact)
        .map_err(CompletionError::Binding)?;
    future.await.map_err(CompletionError::Repository)?;
    permit.received();
    Ok(())
}
pub async fn rollback_observed<E>(
    future: impl Future<Output = Result<(), E>>,
    request: &Request,
) -> Result<(), CompletionError<E>> {
    let permit = request
        .rollback_entered()
        .map_err(CompletionError::Binding)?;
    future.await.map_err(CompletionError::Repository)?;
    permit.completed();
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        pin::Pin,
        task::{Context, Poll, Waker},
    };
    fn c2s(claimed: bool) -> Source {
        Source::C2s(DurableDelivery {
            recipient_id: Uuid::from_u128(101),
            message_id: Uuid::from_u128(102),
            claim_id: claimed.then(|| Uuid::from_u128(103)),
        })
    }
    fn mix() -> MixDelivery {
        MixDelivery {
            delivery_id: Uuid::from_u128(201),
            lease_token: Uuid::from_u128(202),
        }
    }
    fn scope(persisted: bool) -> Scope {
        Scope {
            purpose: Purpose::Acknowledge { h: 8 },
            session_id: persisted.then(|| Uuid::from_u128(301)),
            connection_id: Uuid::from_u128(302),
            inbound_h: 5,
            outbound_h: 10,
            acked_h: 7,
            queued: 3,
        }
    }
    fn binding(persisted: bool) -> Binding {
        Binding {
            session_id: scope(persisted).session_id,
            connection_id: scope(persisted).connection_id,
            inbound_h: 5,
            outbound_h: 10,
            acked_h: 8,
            whole: vec![Some(c2s(false)), None, Some(Source::Mix(mix()))],
            acknowledged: vec![Some(c2s(false))],
            remaining: vec![None, Some(Source::Mix(mix()))],
        }
    }
    fn request(persisted: bool) -> (Observation, Request) {
        let observation = Observation::new(scope(persisted));
        observation.h_decision(Some(1));
        let request = observation.bind(binding(persisted)).unwrap();
        (observation, request)
    }
    fn rotation() -> MixRotation {
        MixRotation {
            previous: mix(),
            current: MixDelivery {
                lease_token: Uuid::from_u128(203),
                ..mix()
            },
        }
    }
    fn checkpoint() -> CommitFact {
        CommitFact::Checkpoint {
            rotations: vec![rotation()],
            settled: vec![c2s(false)],
        }
    }
    fn poll_once<F: Future>(future: Pin<&mut F>) -> Poll<F::Output> {
        future.poll(&mut Context::from_waker(Waker::noop()))
    }

    #[test]
    fn ordered_cut_rejects_changed_scope_plain_slot_and_h_decision_inertly() {
        let observation = Observation::new(scope(true));
        observation.h_decision(Some(1));
        let before = observation.snapshot();
        for change in 0..7 {
            let mut binding = binding(true);
            match change {
                0 => binding.session_id = None,
                1 => binding.connection_id = Uuid::nil(),
                2 => binding.acked_h += 1,
                3 => binding.inbound_h += 1,
                4 => {
                    binding.whole.remove(1);
                    binding.remaining.remove(0);
                }
                5 => binding.whole.swap(0, 1),
                _ => {
                    binding.acknowledged.push(binding.remaining.remove(0));
                }
            }
            assert!(observation.bind(binding).is_err());
            assert_eq!(observation.snapshot(), before);
        }
        observation.bind(binding(true)).unwrap();
    }
    #[test]
    fn commit_fact_rejects_duplicate_rotations_and_inexact_settlement_inertly() {
        let (observation, request) = request(true);
        let before = observation.snapshot();
        for change in 0..5 {
            let mut rotations = vec![rotation()];
            let mut settled = vec![c2s(false)];
            match change {
                0 => rotations.push(rotation()),
                1 => rotations.push(MixRotation {
                    current: mix(),
                    ..rotation()
                }),
                2 => rotations[0].current.delivery_id = Uuid::nil(),
                3 => settled.clear(),
                _ => settled.push(c2s(false)),
            }
            assert!(matches!(
                request.enter_commit(CommitFact::Checkpoint { rotations, settled }),
                Err(Rejected::Result)
            ));
            assert_eq!(observation.snapshot(), before);
        }
        request.enter_commit(checkpoint()).unwrap().received();
        assert_eq!(
            request.validate_checkpoint_return(true, &[]),
            Err(Rejected::Result)
        );
        assert_eq!(observation.snapshot().returned_updated, None);
        request
            .validate_checkpoint_return(true, &[rotation()])
            .unwrap();
    }
    #[test]
    fn rollback_entry_error_drop_and_receipt_are_distinct_from_commit() {
        for cut in 0..3 {
            let (observation, request) = request(true);
            let mut future = Box::pin(rollback_observed(
                async {
                    if cut == 0 {
                        std::future::pending::<()>().await;
                    }
                    if cut == 1 {
                        Err(std::io::Error::other("rollback response lost"))
                    } else {
                        Ok(())
                    }
                },
                &request,
            ));
            let result = poll_once(future.as_mut());
            assert_eq!(result.is_pending(), cut == 0);
            drop(future);
            assert_eq!(
                observation.snapshot().knowledge,
                if cut == 2 {
                    Knowledge::RollbackKnown
                } else {
                    Knowledge::RollbackCallEntered
                }
            );
            assert_eq!(
                request.validate_checkpoint_return(false, &[]).is_ok(),
                cut == 2
            );
            assert_eq!(observation.snapshot().summary().committed_settled, None);
        }
    }
    #[test]
    fn commit_response_loss_stays_unknown_and_positive_receipt_survives_retirement() {
        for cut in 0..3 {
            let (observation, request) = request(true);
            let mut future = Box::pin(commit_observed(
                async {
                    if cut == 0 {
                        std::future::pending::<()>().await;
                    }
                    if cut == 1 {
                        Err(std::io::Error::other("COMMIT response lost"))
                    } else {
                        Ok(())
                    }
                },
                &request,
                checkpoint(),
            ));
            let result = poll_once(future.as_mut());
            assert_eq!(result.is_pending(), cut == 0);
            drop(future);
            let summary = observation.retire(Terminal::Cancelled);
            assert_eq!(
                summary.knowledge,
                if cut == 2 {
                    KnowledgeClass::ReceiptKnown
                } else {
                    KnowledgeClass::CommitCallEntered
                }
            );
            assert_eq!(summary.committed_settled, (cut == 2).then_some(1));
            assert!(matches!(
                request.enter_commit(checkpoint()),
                Err(Rejected::Retired)
            ));
        }
    }
    #[test]
    fn invocation_binding_and_old_retained_observations_are_independent() {
        let (old, old_request) = request(true);
        let (new, new_request) = request(true);
        let crossed = Request {
            observation: old.clone(),
            binding: new_request.binding.clone(),
        };
        assert!(matches!(
            crossed.enter_commit(checkpoint()),
            Err(Rejected::Scope)
        ));
        old_request.enter_commit(checkpoint()).unwrap().received();
        old.retire(Terminal::Returned);
        assert_eq!(new.snapshot().knowledge, Knowledge::NoCommitRequested);
        new_request.rollback_entered().unwrap().completed();
        assert!(matches!(
            old.snapshot().knowledge,
            Knowledge::ReceiptKnown(_)
        ));
        assert_eq!(old.snapshot().terminal, Some(Terminal::Returned));
    }
    #[test]
    fn nonpersisted_empty_and_absent_unclaimed_keep_exact_source_semantics() {
        let (observation, request) = request(false);
        assert_eq!(request.no_persistence(), Err(Rejected::State));
        assert!(matches!(
            request.enter_commit(CommitFact::UnpersistedAck {
                deleted: vec![],
                absent_unclaimed: vec![c2s(true).c2s().unwrap()]
            }),
            Err(Rejected::Result)
        ));
        request
            .enter_commit(CommitFact::UnpersistedAck {
                deleted: vec![],
                absent_unclaimed: vec![c2s(false).c2s().unwrap()],
            })
            .unwrap()
            .received();
        request.validate_batch_return().unwrap();
        assert_eq!(
            observation.snapshot().summary().committed_absent_unclaimed,
            Some(1)
        );
        let mut scope = scope(false);
        scope.queued = 1;
        let empty = Observation::new(scope);
        empty.h_decision(Some(1));
        let mut binding = binding(false);
        binding.whole = vec![None];
        binding.acknowledged = vec![None];
        binding.remaining.clear();
        let request = empty.bind(binding).unwrap();
        request.no_persistence().unwrap();
        request.validate_batch_return().unwrap();
        assert_eq!(empty.snapshot().knowledge, Knowledge::NoPersistence);
        // A missing MIX source cannot be turned into the native no-match case.
        let strict = Observation::new(scope);
        strict.h_decision(Some(1));
        let mut binding = request.binding().clone();
        binding.whole = vec![Some(Source::Mix(mix()))];
        binding.acknowledged = binding.whole.clone();
        let request = strict.bind(binding).unwrap();
        assert!(matches!(
            request.enter_commit(CommitFact::UnpersistedAck {
                deleted: vec![],
                absent_unclaimed: vec![]
            }),
            Err(Rejected::Result)
        ));
    }
    #[test]
    fn snapshot_and_owner_debug_redact_exact_claim_and_lease_tokens() {
        let observation = Observation::new(scope(true));
        observation.h_decision(Some(1));
        let mut binding = binding(true);
        binding.whole[0] = Some(c2s(true));
        binding.acknowledged[0] = Some(c2s(true));
        let request = observation.bind(binding).unwrap();
        request
            .enter_commit(CommitFact::Checkpoint {
                rotations: vec![rotation()],
                settled: vec![c2s(true)],
            })
            .unwrap()
            .received();
        assert_eq!(
            observation
                .snapshot()
                .binding
                .as_ref()
                .unwrap()
                .acknowledged[0]
                .unwrap()
                .c2s()
                .unwrap()
                .claim_id,
            Some(Uuid::from_u128(103))
        );
        let text = format!("{observation:?} {request:?} {:?}", observation.snapshot());
        for value in [101, 102, 103, 201, 202, 203, 301, 302] {
            assert!(!text.contains(&Uuid::from_u128(value).to_string()));
        }
        assert!(text.contains("ReceiptKnown"));
    }
}
