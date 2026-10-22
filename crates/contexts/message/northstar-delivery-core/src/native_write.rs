//! Per-invocation native write knowledge and consuming settlement authority.
//! No stanza, clock, database, transport, registry or work on Drop lives here.
use crate::TransportOwnershipSource;
use std::{
    future::Future,
    sync::{Arc, Mutex},
};

/// The claimed-row branch only. The repository still resolves the exact row,
/// holds its lock, checks missing/unclaimed ownership and performs the DELETE
/// compare-and-set atomically. No expiry or rotation requirement is added.
pub fn claimed_c2s_ack_matches(
    expected_claim: uuid::Uuid,
    current_claim: Option<uuid::Uuid>,
) -> bool {
    current_claim == Some(expected_claim)
}

#[cfg(test)]
mod claimed_token_tests {
    use super::claimed_c2s_ack_matches;
    use uuid::Uuid;

    #[test]
    fn old_claim_is_rejected_after_replacement_while_current_claim_still_matches() {
        let old = Uuid::from_u128(6);
        let replacement = Uuid::from_u128(10);
        assert!(claimed_c2s_ack_matches(old, Some(old)));
        assert!(!claimed_c2s_ack_matches(old, Some(replacement)));
        assert!(claimed_c2s_ack_matches(replacement, Some(replacement)));
        assert!(!claimed_c2s_ack_matches(old, None));
        // Only this claimed-token comparison is exercised; no elapsed lease,
        // SQL row selection, lock, or replacement authority is inferred.
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Rejected {
    State,
    Source,
    Retired,
    Outcome,
}
impl std::fmt::Display for Rejected {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "native write rejected: {self:?}")
    }
}
impl std::error::Error for Rejected {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Preparation {
    NotStarted,
    Recording,
    FenceCallEntered,
    Prepared,
    Superseded,
    Failed,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WriterResult {
    FullWrite,
    Failed,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WriteDecision {
    Withhold,
    Written,
}
/// The actual writer result is retained separately from this production-used
/// gate. A local complete write is still not a peer acknowledgement.
pub fn write_decision(result: WriterResult) -> WriteDecision {
    match result {
        WriterResult::FullWrite => WriteDecision::Written,
        WriterResult::Failed => WriteDecision::Withhold,
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AckDisposition {
    Deleted,
    AbsentUnclaimed,
    NoMatchingMix,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AckFact {
    pub source: TransportOwnershipSource,
    pub disposition: AckDisposition,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AckKnowledge {
    NotRequested,
    NoCommitRequested,
    CommitCallEntered(AckFact),
    ReceiptKnown(AckFact),
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Terminal {
    Returned,
    Cancelled,
    Panicked,
}
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct Snapshot {
    pub original: Option<TransportOwnershipSource>,
    pub preparation: Preparation,
    pub managed_by_sm: Option<bool>,
    pub fence_entered: bool,
    pub returned_fence: Option<TransportOwnershipSource>,
    pub writer_entered: bool,
    pub writer_result: Option<WriterResult>,
    pub write_decision: Option<WriteDecision>,
    pub ack: AckKnowledge,
    pub ack_returned: Option<bool>,
    pub terminal: Option<Terminal>,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AckClass {
    NotRequested,
    NoCommitRequested,
    CommitCallEntered,
    ReceiptKnown,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Summary {
    pub preparation: Preparation,
    pub managed_by_sm: Option<bool>,
    pub fence_entered: bool,
    pub fence_returned: bool,
    pub writer_entered: bool,
    pub writer_result: Option<WriterResult>,
    pub write_decision: Option<WriteDecision>,
    pub ack: AckClass,
    pub committed_disposition: Option<AckDisposition>,
    pub ack_returned: Option<bool>,
    pub terminal: Option<Terminal>,
}
impl Snapshot {
    pub fn summary(self) -> Summary {
        Summary {
            preparation: self.preparation,
            managed_by_sm: self.managed_by_sm,
            fence_entered: self.fence_entered,
            fence_returned: self.returned_fence.is_some(),
            writer_entered: self.writer_entered,
            writer_result: self.writer_result,
            write_decision: self.write_decision,
            ack: match self.ack {
                AckKnowledge::NotRequested => AckClass::NotRequested,
                AckKnowledge::NoCommitRequested => AckClass::NoCommitRequested,
                AckKnowledge::CommitCallEntered(_) => AckClass::CommitCallEntered,
                AckKnowledge::ReceiptKnown(_) => AckClass::ReceiptKnown,
            },
            committed_disposition: match self.ack {
                AckKnowledge::ReceiptKnown(fact) => Some(fact.disposition),
                _ => None,
            },
            ack_returned: self.ack_returned,
            terminal: self.terminal,
        }
    }
}
impl std::fmt::Debug for Snapshot {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NativeWriteSnapshot")
            .field("summary", &self.summary())
            .finish_non_exhaustive()
    }
}
struct State {
    snapshot: Snapshot,
    written_issued: bool,
    ack_issued: bool,
}
#[derive(Clone)]
pub struct Observation(Arc<Mutex<State>>);
impl std::fmt::Debug for Observation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("NativeWriteObservation { invocation-local facts }")
    }
}
impl Observation {
    pub fn new(source: Option<TransportOwnershipSource>) -> Self {
        Self(Arc::new(Mutex::new(State {
            snapshot: Snapshot {
                original: source,
                preparation: Preparation::NotStarted,
                managed_by_sm: None,
                fence_entered: false,
                returned_fence: None,
                writer_entered: false,
                writer_result: None,
                write_decision: None,
                ack: AckKnowledge::NotRequested,
                ack_returned: None,
                terminal: None,
            },
            written_issued: false,
            ack_issued: false,
        })))
    }
    pub fn snapshot(&self) -> Snapshot {
        self.0.lock().unwrap_or_else(|e| e.into_inner()).snapshot
    }
    fn open(state: &State) -> Result<(), Rejected> {
        if state.snapshot.terminal.is_some() {
            Err(Rejected::Retired)
        } else {
            Ok(())
        }
    }
    pub fn begin_record(&self, source: Option<TransportOwnershipSource>) -> Result<(), Rejected> {
        let mut state = self.0.lock().unwrap_or_else(|e| e.into_inner());
        Self::open(&state)?;
        if source != state.snapshot.original {
            return Err(Rejected::Source);
        }
        if state.snapshot.preparation != Preparation::NotStarted {
            return Err(Rejected::State);
        }
        state.snapshot.preparation = Preparation::Recording;
        Ok(())
    }
    pub fn recorded(
        &self,
        managed_by_sm: bool,
    ) -> Result<Option<TransportOwnershipSource>, Rejected> {
        let mut state = self.0.lock().unwrap_or_else(|e| e.into_inner());
        Self::open(&state)?;
        if state.snapshot.preparation != Preparation::Recording {
            return Err(Rejected::State);
        }
        state.snapshot.managed_by_sm = Some(managed_by_sm);
        let fence = state.snapshot.original.filter(|_| !managed_by_sm);
        state.snapshot.fence_entered = fence.is_some();
        state.snapshot.preparation = if fence.is_some() {
            Preparation::FenceCallEntered
        } else {
            Preparation::Prepared
        };
        Ok(fence)
    }
    /// A returned fence is authority; a failed/pending fence call says nothing
    /// about whether its own transaction persisted a rotation.
    pub fn fenced(&self, returned: TransportOwnershipSource) -> Result<(), Rejected> {
        let mut state = self.0.lock().unwrap_or_else(|e| e.into_inner());
        Self::open(&state)?;
        if state.snapshot.preparation != Preparation::FenceCallEntered {
            return Err(Rejected::State);
        }
        let valid = match (state.snapshot.original, returned) {
            (
                Some(TransportOwnershipSource::C2s(original)),
                TransportOwnershipSource::C2s(actual),
            ) => {
                original.recipient_id == actual.recipient_id
                    && original.message_id == actual.message_id
                    && actual.claim_id.is_some()
                    && match original.claim_id {
                        Some(claim) if claim == original.message_id => {
                            actual.claim_id != Some(original.message_id)
                        }
                        Some(claim) => actual.claim_id == Some(claim),
                        None => true,
                    }
            }
            (
                Some(TransportOwnershipSource::Mix(original)),
                TransportOwnershipSource::Mix(actual),
            ) => original.delivery_id == actual.delivery_id,
            _ => false,
        };
        if !valid {
            return Err(Rejected::Source);
        }
        state.snapshot.returned_fence = Some(returned);
        state.snapshot.preparation = Preparation::Prepared;
        Ok(())
    }
    pub fn preparation_failed(&self, superseded: bool) {
        let mut state = self.0.lock().unwrap_or_else(|e| e.into_inner());
        if state.snapshot.terminal.is_none() && !state.snapshot.writer_entered {
            state.snapshot.preparation = if superseded {
                Preparation::Superseded
            } else {
                Preparation::Failed
            };
        }
    }
    pub fn begin_write(&self) -> Result<(), Rejected> {
        let mut state = self.0.lock().unwrap_or_else(|e| e.into_inner());
        Self::open(&state)?;
        if state.snapshot.preparation != Preparation::Prepared || state.snapshot.writer_entered {
            return Err(Rejected::State);
        }
        state.snapshot.writer_entered = true;
        Ok(())
    }
    pub fn writer_completed(&self, actual: WriterResult) -> Result<Option<Written>, Rejected> {
        let mut state = self.0.lock().unwrap_or_else(|e| e.into_inner());
        Self::open(&state)?;
        if !state.snapshot.writer_entered || state.snapshot.writer_result.is_some() {
            return Err(Rejected::State);
        }
        state.snapshot.writer_result = Some(actual);
        let decision = write_decision(actual);
        state.snapshot.write_decision = Some(decision);
        if decision == WriteDecision::Written {
            state.written_issued = true;
            Ok(Some(Written {
                observation: self.clone(),
            }))
        } else {
            Ok(None)
        }
    }
    pub fn retire(&self, reason: Terminal) -> Snapshot {
        let mut state = self.0.lock().unwrap_or_else(|e| e.into_inner());
        state.snapshot.terminal.get_or_insert(reason);
        state.snapshot
    }
}

/// This private-field continuation is issued only after the writer result was
/// retained. Dropping it does not acknowledge, retry, or erase a full write.
pub struct Written {
    observation: Observation,
}
impl Written {
    pub fn begin_ack(self) -> Result<Option<AckRequest>, Rejected> {
        let mut state = self.observation.0.lock().unwrap_or_else(|e| e.into_inner());
        Observation::open(&state)?;
        if !state.written_issued
            || state.ack_issued
            || state.snapshot.writer_result != Some(WriterResult::FullWrite)
        {
            return Err(Rejected::State);
        }
        state.ack_issued = true;
        if state.snapshot.managed_by_sm == Some(true) || state.snapshot.original.is_none() {
            return Ok(None);
        }
        let source = state.snapshot.returned_fence.ok_or(Rejected::Source)?;
        state.snapshot.ack = AckKnowledge::NoCommitRequested;
        Ok(Some(AckRequest {
            source,
            observation: self.observation.clone(),
        }))
    }
}
/// One exact ACK invocation. Source and operation cannot be replaced between
/// preparing COMMIT and recording its receipt.
pub struct AckRequest {
    source: TransportOwnershipSource,
    observation: Observation,
}
impl AckRequest {
    pub fn source(&self) -> TransportOwnershipSource {
        self.source
    }
    pub fn validate_source(&self, source: TransportOwnershipSource) -> Result<(), Rejected> {
        let state = self.observation.0.lock().unwrap_or_else(|e| e.into_inner());
        Observation::open(&state)?;
        if source != self.source {
            return Err(Rejected::Source);
        }
        if state.snapshot.ack != AckKnowledge::NoCommitRequested {
            return Err(Rejected::State);
        }
        Ok(())
    }
    pub fn enter_commit(&self, disposition: AckDisposition) -> Result<AckCommitPermit, Rejected> {
        self.validate_source(self.source)?;
        let valid = match (self.source, disposition) {
            (_, AckDisposition::Deleted) => true,
            (TransportOwnershipSource::C2s(source), AckDisposition::AbsentUnclaimed) => {
                source.claim_id.is_none()
            }
            (TransportOwnershipSource::Mix(_), AckDisposition::NoMatchingMix) => true,
            _ => false,
        };
        if !valid {
            return Err(Rejected::Outcome);
        }
        let fact = AckFact {
            source: self.source,
            disposition,
        };
        let mut state = self.observation.0.lock().unwrap_or_else(|e| e.into_inner());
        Observation::open(&state)?;
        if state.snapshot.ack != AckKnowledge::NoCommitRequested {
            return Err(Rejected::State);
        }
        state.snapshot.ack = AckKnowledge::CommitCallEntered(fact);
        Ok(AckCommitPermit {
            fact,
            observation: self.observation.clone(),
        })
    }
    pub fn returned(&self, succeeded: bool) {
        let mut state = self.observation.0.lock().unwrap_or_else(|e| e.into_inner());
        if state.snapshot.ack_returned.is_none() {
            state.snapshot.ack_returned = Some(succeeded);
        }
    }
}
pub struct AckCommitPermit {
    fact: AckFact,
    observation: Observation,
}
impl AckCommitPermit {
    /// Infallible receipt retention has no caller-selected data after COMMIT.
    pub fn received(self) {
        self.observation
            .0
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .snapshot
            .ack = AckKnowledge::ReceiptKnown(self.fact);
    }
}
#[derive(Debug)]
pub enum CommitError<E> {
    Binding(Rejected),
    Repository(E),
}
impl<E: std::fmt::Display> std::fmt::Display for CommitError<E> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Binding(e) => std::fmt::Display::fmt(e, f),
            Self::Repository(e) => std::fmt::Display::fmt(e, f),
        }
    }
}
impl<E: std::error::Error + 'static> std::error::Error for CommitError<E> {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(match self {
            Self::Binding(error) => error,
            Self::Repository(error) => error,
        })
    }
}
/// The repository supplies its actual commit future and transaction-derived
/// disposition. Controlled futures exercise these same suspension boundaries.
pub async fn commit_observed<E>(
    commit: impl Future<Output = Result<(), E>>,
    request: &AckRequest,
    disposition: AckDisposition,
) -> Result<(), CommitError<E>> {
    let permit = request
        .enter_commit(disposition)
        .map_err(CommitError::Binding)?;
    commit.await.map_err(CommitError::Repository)?;
    permit.received();
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{DurableDelivery, MixDelivery};
    use std::{
        pin::Pin,
        task::{Context, Poll, Waker},
    };
    use uuid::Uuid;

    fn initial() -> TransportOwnershipSource {
        TransportOwnershipSource::C2s(DurableDelivery {
            recipient_id: Uuid::from_u128(1),
            message_id: Uuid::from_u128(2),
            claim_id: Some(Uuid::from_u128(2)),
        })
    }
    fn fenced() -> TransportOwnershipSource {
        TransportOwnershipSource::C2s(DurableDelivery {
            claim_id: Some(Uuid::from_u128(3)),
            ..initial().c2s().unwrap()
        })
    }
    fn prepared(
        source: TransportOwnershipSource,
        returned: TransportOwnershipSource,
    ) -> Observation {
        let observation = Observation::new(Some(source));
        observation.begin_record(Some(source)).unwrap();
        assert_eq!(observation.recorded(false).unwrap(), Some(source));
        observation.fenced(returned).unwrap();
        observation
    }
    fn written() -> (Observation, Written) {
        let observation = prepared(initial(), fenced());
        observation.begin_write().unwrap();
        let written = observation
            .writer_completed(WriterResult::FullWrite)
            .unwrap()
            .unwrap();
        (observation, written)
    }
    fn request() -> (Observation, AckRequest) {
        let (observation, written) = written();
        (observation, written.begin_ack().unwrap().unwrap())
    }
    fn poll_once<F: Future>(future: Pin<&mut F>) -> Poll<F::Output> {
        future.poll(&mut Context::from_waker(Waker::noop()))
    }

    #[test]
    fn exact_fence_rules_reject_changed_identity_and_preserve_sql_token_semantics() {
        for original in [initial(), fenced()] {
            let observation = Observation::new(Some(original));
            observation.begin_record(Some(original)).unwrap();
            observation.recorded(false).unwrap();
            let before = observation.snapshot();
            for wrong in [
                TransportOwnershipSource::C2s(DurableDelivery {
                    recipient_id: Uuid::from_u128(9),
                    ..fenced().c2s().unwrap()
                }),
                TransportOwnershipSource::C2s(DurableDelivery {
                    message_id: Uuid::from_u128(9),
                    ..fenced().c2s().unwrap()
                }),
                TransportOwnershipSource::C2s(DurableDelivery {
                    claim_id: None,
                    ..fenced().c2s().unwrap()
                }),
                initial(),
            ] {
                assert_eq!(observation.fenced(wrong), Err(Rejected::Source));
                assert_eq!(observation.snapshot(), before);
            }
            observation.fenced(fenced()).unwrap();
        }
        let unclaimed = TransportOwnershipSource::C2s(DurableDelivery {
            claim_id: None,
            ..initial().c2s().unwrap()
        });
        assert_eq!(
            prepared(unclaimed, fenced()).snapshot().returned_fence,
            Some(fenced())
        );
        let source = TransportOwnershipSource::Mix(MixDelivery {
            delivery_id: Uuid::from_u128(4),
            lease_token: Uuid::from_u128(5),
        });
        let observation = Observation::new(Some(source));
        observation.begin_record(Some(source)).unwrap();
        observation.recorded(false).unwrap();
        let before = observation.snapshot();
        assert_eq!(
            observation.fenced(TransportOwnershipSource::Mix(MixDelivery {
                delivery_id: Uuid::from_u128(9),
                lease_token: Uuid::from_u128(5)
            })),
            Err(Rejected::Source)
        );
        assert_eq!(observation.snapshot(), before);
        // SQL generates a new token but does not enforce inequality. Do not
        // add an application rejection for the same-token value.
        observation.fenced(source).unwrap();
        assert_eq!(observation.snapshot().returned_fence, Some(source));
    }

    #[test]
    fn writer_truth_and_gate_stay_separate_and_failed_write_never_issues_continuation() {
        for actual in [WriterResult::Failed, WriterResult::FullWrite] {
            let observation = prepared(initial(), fenced());
            observation.begin_write().unwrap();
            let continuation = observation.writer_completed(actual).unwrap();
            assert_eq!(observation.snapshot().writer_result, Some(actual));
            assert_eq!(
                observation.snapshot().write_decision,
                Some(if actual == WriterResult::FullWrite {
                    WriteDecision::Written
                } else {
                    WriteDecision::Withhold
                })
            );
            assert_eq!(continuation.is_some(), actual == WriterResult::FullWrite);
            drop(continuation);
            assert_eq!(observation.snapshot().ack, AckKnowledge::NotRequested);
        }
    }

    #[test]
    fn dropped_written_and_sm_owned_continuations_never_request_native_ack() {
        let (observation, continuation) = written();
        drop(continuation);
        observation.retire(Terminal::Cancelled);
        assert_eq!(
            observation.snapshot().writer_result,
            Some(WriterResult::FullWrite)
        );
        assert_eq!(observation.snapshot().ack, AckKnowledge::NotRequested);
        let sm = Observation::new(Some(initial()));
        sm.begin_record(Some(initial())).unwrap();
        assert_eq!(sm.recorded(true).unwrap(), None);
        sm.begin_write().unwrap();
        assert!(sm
            .writer_completed(WriterResult::FullWrite)
            .unwrap()
            .unwrap()
            .begin_ack()
            .unwrap()
            .is_none());
        assert!(!sm.snapshot().fence_entered);
        assert_eq!(sm.snapshot().ack, AckKnowledge::NotRequested);
    }

    #[test]
    fn real_commit_wrapper_records_entry_drop_receipt_and_later_error_independently() {
        let (pending, request) = request();
        let mut future = Box::pin(commit_observed(
            std::future::pending::<Result<(), std::io::Error>>(),
            &request,
            AckDisposition::Deleted,
        ));
        assert!(poll_once(future.as_mut()).is_pending());
        drop(future);
        assert!(matches!(
            pending.snapshot().ack,
            AckKnowledge::CommitCallEntered(_)
        ));
        pending.retire(Terminal::Cancelled);
        assert_eq!(
            pending.snapshot().writer_result,
            Some(WriterResult::FullWrite)
        );

        let (committed, request) = self::request();
        let mut future = Box::pin(commit_observed(
            std::future::ready(Ok::<(), std::io::Error>(())),
            &request,
            AckDisposition::Deleted,
        ));
        assert!(matches!(poll_once(future.as_mut()), Poll::Ready(Ok(()))));
        drop(future);
        request.returned(false); // Controlled later mapping error, no rollback claim.
        committed.retire(Terminal::Cancelled);
        assert!(matches!(
            committed.snapshot().ack,
            AckKnowledge::ReceiptKnown(AckFact {
                disposition: AckDisposition::Deleted,
                ..
            })
        ));
        assert_eq!(committed.snapshot().ack_returned, Some(false));
    }

    #[test]
    fn invalid_source_or_disposition_never_polls_commit_and_is_inert() {
        let (observation, request) = request();
        let before = observation.snapshot();
        assert_eq!(request.validate_source(initial()), Err(Rejected::Source));
        assert_eq!(observation.snapshot(), before);
        let polled = std::cell::Cell::new(false);
        let mut future = Box::pin(commit_observed(
            async {
                polled.set(true);
                Ok::<(), std::io::Error>(())
            },
            &request,
            AckDisposition::AbsentUnclaimed,
        ));
        assert!(matches!(
            poll_once(future.as_mut()),
            Poll::Ready(Err(CommitError::Binding(Rejected::Outcome)))
        ));
        assert!(!polled.get());
        assert_eq!(observation.snapshot(), before);
    }

    #[test]
    fn same_source_operations_and_retired_owner_cannot_replace_each_others_receipts() {
        let (first, request) = request();
        let (second, second_request) = self::request();
        let permit = request.enter_commit(AckDisposition::Deleted).unwrap();
        first.retire(Terminal::Cancelled);
        permit.received(); // Receipt for an already-entered effect stays factual.
        assert!(matches!(
            first.snapshot().ack,
            AckKnowledge::ReceiptKnown(_)
        ));
        assert_eq!(second.snapshot().ack, AckKnowledge::NoCommitRequested);
        let before = first.snapshot();
        assert!(request.enter_commit(AckDisposition::Deleted).is_err());
        assert_eq!(first.snapshot(), before);
        second_request
            .enter_commit(AckDisposition::Deleted)
            .unwrap()
            .received();
        assert_eq!(first.snapshot(), before);
    }

    #[test]
    fn compatibility_absent_unclaimed_and_mix_no_match_are_not_deleted_receipts() {
        for (source, disposition) in [
            (
                TransportOwnershipSource::C2s(DurableDelivery {
                    claim_id: None,
                    ..initial().c2s().unwrap()
                }),
                AckDisposition::AbsentUnclaimed,
            ),
            (
                TransportOwnershipSource::Mix(MixDelivery {
                    delivery_id: Uuid::from_u128(4),
                    lease_token: Uuid::from_u128(5),
                }),
                AckDisposition::NoMatchingMix,
            ),
        ] {
            // Repository compatibility fixture only. A successfully fenced
            // native C2S writer normally reaches ACK with Some(claim), so it
            // cannot manufacture this absent-unclaimed native continuation.
            let observation = Observation::new(Some(source));
            observation.0.lock().unwrap().snapshot.ack = AckKnowledge::NoCommitRequested;
            let request = AckRequest {
                source,
                observation: observation.clone(),
            };
            let mut future = Box::pin(commit_observed(
                std::future::ready(Ok::<(), std::io::Error>(())),
                &request,
                disposition,
            ));
            assert!(matches!(poll_once(future.as_mut()), Poll::Ready(Ok(()))));
            assert_eq!(
                observation.snapshot().summary().committed_disposition,
                Some(disposition)
            );
            assert_ne!(disposition, AckDisposition::Deleted);
        }
    }
}
