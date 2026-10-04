//! Operation-local admission ownership for the direct-message lifecycle.
//!
//! This first boundary retains reservation and finalization independently. It
//! does not infer a durable message commit, route, or scheduled recovery from
//! either admission transaction. No I/O, clock, entropy, or async Drop lives here.

use northstar_abuse_policy::{
    admission_execution::{
        BeginRequest, BeginResult, Command, CommitFact, CommitWitness, Completion,
        CompletionRejected, Coordinator, Correlation, Effect, EffectResult, ExecutionOutcome,
        ExecutionState, GuardDecision, Knowledge, PreparedCommit, Receipt,
    },
    admission_transaction::AdmissionFence,
};
use uuid::Uuid;

/// An effect handle can only be issued by its operation. It is not admission authority. The complete command remains
/// bound to it; an operation ID or a caller-selected effect number is not enough.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AdmissionEffectHandle {
    effect: Effect,
}

impl AdmissionEffectHandle {
    pub fn effect(&self) -> &Effect {
        &self.effect
    }
}

/// Actual authority is available only after the existing admission coordinator
/// accepts its real completion. An issued effect or prospective fence cannot
/// construct these values.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AdmissionGrant {
    Reserved(ReservationGrant),
    GuardOnly(GuardGrant),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReservationGrant {
    correlation: Correlation,
    fence: AdmissionFence,
}

impl ReservationGrant {
    pub fn fence(&self) -> &AdmissionFence {
        &self.fence
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GuardGrant {
    correlation: Correlation,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Rejected {
    Retired,
    AlreadyStarted,
    NotStarted,
    ReservationRequired,
    Fence,
    Grant,
    Request,
    Completion(CompletionRejected),
}

impl std::fmt::Display for Rejected {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "direct admission ownership rejected: {self:?}")
    }
}

impl std::error::Error for Rejected {}

impl From<CompletionRejected> for Rejected {
    fn from(value: CompletionRejected) -> Self {
        Self::Completion(value)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TerminalReason {
    Completed,
    BackendFailure,
    TimedOut,
    Cancelled,
    Panicked,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TerminalClassification {
    NoAdmission,
    AdmissionObserved,
    TerminalUnresolved,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EffectPhase {
    Issued,
    Waiting,
    Finished,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CommitKnowledgeClass {
    NoCommitRequested,
    CommitCallEntered,
    ReceiptKnown,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AdmissionSummary {
    pub phase: EffectPhase,
    pub knowledge: CommitKnowledgeClass,
    pub durable_reservation_receipt: bool,
}

impl AdmissionSummary {
    fn from_execution(started: bool, state: &ExecutionState, witness: &CommitWitness) -> Self {
        Self {
            phase: match state {
                ExecutionState::Finished(_) => EffectPhase::Finished,
                ExecutionState::Waiting(_) if started => EffectPhase::Waiting,
                ExecutionState::Waiting(_) => EffectPhase::Issued,
            },
            knowledge: match witness.knowledge() {
                Knowledge::NoCommitRequested => CommitKnowledgeClass::NoCommitRequested,
                Knowledge::CommitCallEntered(_) => CommitKnowledgeClass::CommitCallEntered,
                Knowledge::ReceiptKnown(_) => CommitKnowledgeClass::ReceiptKnown,
            },
            durable_reservation_receipt: matches!(witness.knowledge(), Knowledge::ReceiptKnown(receipt)
                if matches!(receipt.fact, CommitFact::Reserved(_))),
        }
    }
}

/// Payload-free retirement projection. AdmissionObserved describes transaction
/// knowledge only; phase and terminal reason still distinguish unfinished work.
/// It is never evidence of a direct-message commit, transfer, or settlement.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OperationSummary {
    pub operation: Uuid,
    pub reservation: Option<AdmissionSummary>,
    pub finalization: Option<AdmissionSummary>,
    pub terminal: Option<TerminalReason>,
}

impl OperationSummary {
    pub fn classification(&self) -> TerminalClassification {
        if [self.reservation, self.finalization]
            .into_iter()
            .flatten()
            .any(|execution| execution.knowledge == CommitKnowledgeClass::CommitCallEntered)
        {
            TerminalClassification::TerminalUnresolved
        } else if self.reservation.is_some() || self.finalization.is_some() {
            TerminalClassification::AdmissionObserved
        } else {
            TerminalClassification::NoAdmission
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AdmissionSnapshot {
    pub effect_started: bool,
    pub state: ExecutionState,
    pub witness: CommitWitness,
}

impl AdmissionSnapshot {
    /// Guard/proof transactions and replay reads do not reserve a message.
    pub fn has_durable_reservation_receipt(&self) -> bool {
        matches!(self.witness.knowledge(), Knowledge::ReceiptKnown(receipt)
            if matches!(receipt.fact, CommitFact::Reserved(_)))
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OperationSnapshot {
    pub operation: Uuid,
    pub reservation: Option<AdmissionSnapshot>,
    pub finalization: Option<AdmissionSnapshot>,
    pub terminal: Option<TerminalReason>,
}

impl OperationSnapshot {
    pub fn classification(&self) -> TerminalClassification {
        let summarize = |value: &AdmissionSnapshot| {
            AdmissionSummary::from_execution(value.effect_started, &value.state, &value.witness)
        };
        OperationSummary {
            operation: self.operation,
            reservation: self.reservation.as_ref().map(summarize),
            finalization: self.finalization.as_ref().map(summarize),
            terminal: self.terminal,
        }
        .classification()
    }
}

struct AdmissionExecution {
    started: bool,
    handle: AdmissionEffectHandle,
    coordinator: Coordinator,
    witness: CommitWitness,
}

impl AdmissionExecution {
    fn new(correlation: Correlation, command: Command) -> Self {
        let coordinator = Coordinator::new(correlation, command);
        let effect = coordinator
            .pending()
            .expect("new admission execution")
            .clone();
        Self {
            started: false,
            handle: AdmissionEffectHandle {
                effect: effect.clone(),
            },
            coordinator,
            witness: CommitWitness::new(effect),
        }
    }

    fn snapshot(&self) -> AdmissionSnapshot {
        AdmissionSnapshot {
            effect_started: self.started,
            state: self.coordinator.state().clone(),
            witness: self.witness.clone(),
        }
    }
}

/// One frame owns one instance. Replacing a session's current-frame pointer
/// must not reuse or mutate this operation. Retirement is synchronous and
/// preserves Waiting plus the independently observed transaction knowledge.
pub struct DirectLifecycle {
    operation: Uuid,
    generation: u64,
    attempt: u32,
    reservation: Option<AdmissionExecution>,
    finalization: Option<AdmissionExecution>,
    terminal: Option<TerminalReason>,
}

impl DirectLifecycle {
    pub fn new(operation: Uuid, generation: u64, attempt: u32) -> Self {
        Self {
            operation,
            generation,
            attempt,
            reservation: None,
            finalization: None,
            terminal: None,
        }
    }

    fn correlation(&self, effect: u64) -> Correlation {
        Correlation {
            operation: self.operation,
            effect,
            generation: self.generation,
            attempt: self.attempt,
        }
    }

    fn ensure_open(&self) -> Result<(), Rejected> {
        if self.terminal.is_some() {
            Err(Rejected::Retired)
        } else {
            Ok(())
        }
    }

    /// The runtime validates its existing admission bounds before constructing
    /// this owned request. No new message-size policy is imposed by this core.
    pub fn begin(&mut self, request: BeginRequest) -> Result<AdmissionEffectHandle, Rejected> {
        self.ensure_open()?;
        if self.reservation.is_some() {
            return Err(Rejected::AlreadyStarted);
        }
        let execution = AdmissionExecution::new(self.correlation(1), Command::Begin(request));
        let handle = execution.handle.clone();
        self.reservation = Some(execution);
        Ok(handle)
    }

    pub fn admission_grant(&self) -> Option<AdmissionGrant> {
        let execution = self.reservation.as_ref()?;
        let ExecutionState::Finished(ExecutionOutcome::Completed {
            result: EffectResult::Begin(result),
            ..
        }) = execution.coordinator.state()
        else {
            return None;
        };
        match result {
            BeginResult::Reserved(fence) => Some(AdmissionGrant::Reserved(ReservationGrant {
                correlation: execution.handle.effect.correlation,
                fence: fence.clone(),
            })),
            BeginResult::GuardOnly(GuardDecision::Allowed) => {
                Some(AdmissionGrant::GuardOnly(GuardGrant {
                    correlation: execution.handle.effect.correlation,
                }))
            }
            _ => None,
        }
    }

    pub fn finalize(
        &mut self,
        reservation: &ReservationGrant,
    ) -> Result<AdmissionEffectHandle, Rejected> {
        self.ensure_open()?;
        if self.finalization.is_some() {
            return Err(Rejected::AlreadyStarted);
        }
        let Some(AdmissionGrant::Reserved(expected)) = self.admission_grant() else {
            return Err(Rejected::ReservationRequired);
        };
        if expected != *reservation {
            return Err(Rejected::Fence);
        }
        let execution = AdmissionExecution::new(
            self.correlation(2),
            Command::Finalize(reservation.fence.clone()),
        );
        let handle = execution.handle.clone();
        self.finalization = Some(execution);
        Ok(handle)
    }

    fn execution(&self, handle: &AdmissionEffectHandle) -> Result<&AdmissionExecution, Rejected> {
        [&self.reservation, &self.finalization]
            .into_iter()
            .flatten()
            .find(|execution| execution.handle == *handle)
            .ok_or(Rejected::Grant)
    }

    fn execution_mut(
        &mut self,
        handle: &AdmissionEffectHandle,
    ) -> Result<&mut AdmissionExecution, Rejected> {
        self.ensure_open()?;
        [&mut self.reservation, &mut self.finalization]
            .into_iter()
            .flatten()
            .find(|execution| execution.handle == *handle)
            .ok_or(Rejected::Grant)
    }

    pub fn validate_request(
        &self,
        handle: &AdmissionEffectHandle,
        command: &Command,
    ) -> Result<(), Rejected> {
        self.ensure_open()?;
        let execution = self.execution(handle)?;
        if execution.handle.effect.command != *command {
            return Err(Rejected::Request);
        }
        if execution.coordinator.pending().is_none() {
            return Err(CompletionRejected::AlreadyCompleted.into());
        }
        Ok(())
    }

    /// Claim the single invocation before repository I/O. Cloning a retained
    /// handle cannot authorize a concurrent second invocation of the effect.
    pub fn start_effect(
        &mut self,
        handle: &AdmissionEffectHandle,
        command: &Command,
    ) -> Result<(), Rejected> {
        self.validate_request(handle, command)?;
        let execution = self.execution_mut(handle)?;
        if execution.started {
            return Err(Rejected::AlreadyStarted);
        }
        execution.started = true;
        Ok(())
    }

    pub fn witness(&self, handle: &AdmissionEffectHandle) -> Result<&CommitWitness, Rejected> {
        Ok(&self.execution(handle)?.witness)
    }

    pub fn enter_commit(
        &mut self,
        handle: &AdmissionEffectHandle,
        prepared: PreparedCommit,
    ) -> Result<(), Rejected> {
        let execution = self.execution_mut(handle)?;
        if !execution.started {
            return Err(Rejected::NotStarted);
        }
        if execution.coordinator.pending().is_none() {
            return Err(CompletionRejected::AlreadyCompleted.into());
        }
        execution.witness.enter_commit(prepared)?;
        Ok(())
    }

    pub fn record_receipt(
        &mut self,
        handle: &AdmissionEffectHandle,
        receipt: Receipt,
    ) -> Result<(), Rejected> {
        let execution = self.execution_mut(handle)?;
        if execution.coordinator.pending().is_none() {
            return Err(CompletionRejected::AlreadyCompleted.into());
        }
        execution.witness.record_receipt(receipt)?;
        Ok(())
    }

    pub fn complete(
        &mut self,
        handle: &AdmissionEffectHandle,
        result: EffectResult,
    ) -> Result<ExecutionOutcome, Rejected> {
        let execution = self.execution_mut(handle)?;
        if !execution.started {
            return Err(Rejected::NotStarted);
        }
        execution.coordinator.observe_witness(&execution.witness)?;
        Ok(execution
            .coordinator
            .complete(Completion {
                effect: handle.effect.clone(),
                result,
                knowledge: execution.witness.knowledge().clone(),
            })?
            .clone())
    }

    pub fn snapshot(&self) -> OperationSnapshot {
        OperationSnapshot {
            operation: self.operation,
            reservation: self.reservation.as_ref().map(AdmissionExecution::snapshot),
            finalization: self.finalization.as_ref().map(AdmissionExecution::snapshot),
            terminal: self.terminal,
        }
    }

    pub fn retire(&mut self, reason: TerminalReason) -> OperationSummary {
        if self.terminal.is_none() {
            self.terminal = Some(reason);
        }
        let summarize = |value: &AdmissionExecution| {
            AdmissionSummary::from_execution(
                value.started,
                value.coordinator.state(),
                &value.witness,
            )
        };
        OperationSummary {
            operation: self.operation,
            reservation: self.reservation.as_ref().map(summarize),
            finalization: self.finalization.as_ref().map(summarize),
            terminal: self.terminal,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use northstar_abuse_policy::admission_execution::{
        BeginCommitPurpose, FailureKind, FinalizeSuccess, TransactionScope,
    };
    use northstar_abuse_policy::PowProof;

    fn request() -> BeginRequest {
        BeginRequest {
            actor_id: Uuid::from_u128(1),
            account_bare: "private-sender@example.test".into(),
            normalized_target: "private-target@example.test/resource".into(),
            origin_id: Some("private-origin".into()),
            normalized_payload: "private-normalized-payload".into(),
            pow_intent_payload: "private-pow-intent".into(),
            subject: "private-subject".into(),
            actors: vec!["private-actor".into()],
            proof: Some(PowProof {
                challenge_id: Uuid::from_u128(2),
                nonce: "private-nonce".into(),
            }),
        }
    }

    fn fence() -> AdmissionFence {
        AdmissionFence {
            admission_key: vec![3; 32],
            payload_mac: vec![4; 32],
            lease_token: Uuid::from_u128(5),
        }
    }

    fn begin(id: u128) -> (DirectLifecycle, AdmissionEffectHandle) {
        let mut lifecycle = DirectLifecycle::new(Uuid::from_u128(id), 7, 1);
        let handle = lifecycle.begin(request()).unwrap();
        lifecycle
            .start_effect(&handle, &Command::Begin(request()))
            .unwrap();
        (lifecycle, handle)
    }

    fn prospective(handle: &AdmissionEffectHandle) -> PreparedCommit {
        PreparedCommit {
            correlation: handle.effect().correlation,
            scope: TransactionScope::RatedBegin(BeginCommitPurpose::NewReservation),
            fact: CommitFact::Reserved(fence()),
        }
    }

    fn received(
        lifecycle: &mut DirectLifecycle,
        handle: &AdmissionEffectHandle,
        prepared: PreparedCommit,
    ) {
        lifecycle.enter_commit(handle, prepared.clone()).unwrap();
        lifecycle
            .record_receipt(
                handle,
                Receipt {
                    correlation: prepared.correlation,
                    scope: prepared.scope,
                    fact: prepared.fact,
                },
            )
            .unwrap();
    }

    fn reserved(id: u128) -> (DirectLifecycle, ReservationGrant) {
        let (mut lifecycle, handle) = begin(id);
        received(&mut lifecycle, &handle, prospective(&handle));
        lifecycle
            .complete(&handle, EffectResult::Begin(BeginResult::Reserved(fence())))
            .unwrap();
        let Some(AdmissionGrant::Reserved(grant)) = lifecycle.admission_grant() else {
            panic!("reservation grant")
        };
        (lifecycle, grant)
    }

    #[test]
    fn effect_and_positive_witness_are_not_completed_admission_authority() {
        let (mut lifecycle, handle) = begin(10);
        assert_eq!(lifecycle.admission_grant(), None);
        lifecycle
            .enter_commit(&handle, prospective(&handle))
            .unwrap();
        assert_eq!(lifecycle.admission_grant(), None);
        let prepared = prospective(&handle);
        lifecycle
            .record_receipt(
                &handle,
                Receipt {
                    correlation: prepared.correlation,
                    scope: prepared.scope,
                    fact: prepared.fact,
                },
            )
            .unwrap();
        assert_eq!(lifecycle.admission_grant(), None);
        let before = lifecycle.snapshot();
        assert!(lifecycle
            .complete(&handle, EffectResult::Begin(BeginResult::ReplayAccepted))
            .is_err());
        assert_eq!(lifecycle.snapshot(), before);
        lifecycle
            .complete(&handle, EffectResult::Begin(BeginResult::Reserved(fence())))
            .unwrap();
        assert!(matches!(
            lifecycle.admission_grant(),
            Some(AdmissionGrant::Reserved(_))
        ));
        assert!(lifecycle
            .snapshot()
            .reservation
            .unwrap()
            .has_durable_reservation_receipt());
    }

    #[test]
    fn memory_and_guard_receipts_never_become_reservation_grants() {
        let (_, other_grant) = reserved(11);
        for durable_guard in [false, true] {
            let (mut lifecycle, handle) = begin(12);
            if durable_guard {
                received(
                    &mut lifecycle,
                    &handle,
                    PreparedCommit {
                        correlation: handle.effect().correlation,
                        scope: TransactionScope::GuardOnlyVerification,
                        fact: CommitFact::GuardOnly(GuardDecision::Allowed),
                    },
                );
            }
            lifecycle
                .complete(
                    &handle,
                    EffectResult::Begin(BeginResult::GuardOnly(GuardDecision::Allowed)),
                )
                .unwrap();
            assert!(matches!(
                lifecycle.admission_grant(),
                Some(AdmissionGrant::GuardOnly(_))
            ));
            assert!(!lifecycle
                .snapshot()
                .reservation
                .unwrap()
                .has_durable_reservation_receipt());
            assert_eq!(
                lifecycle.finalize(&other_grant),
                Err(Rejected::ReservationRequired)
            );
        }
    }

    #[test]
    fn completed_memory_guard_rejects_later_commit_entry_without_changing_facts() {
        let (mut lifecycle, handle) = begin(22);
        lifecycle
            .complete(
                &handle,
                EffectResult::Begin(BeginResult::GuardOnly(GuardDecision::Allowed)),
            )
            .unwrap();
        let before = lifecycle.snapshot();
        assert_eq!(
            lifecycle.enter_commit(
                &handle,
                PreparedCommit {
                    correlation: handle.effect().correlation,
                    scope: TransactionScope::GuardOnlyVerification,
                    fact: CommitFact::GuardOnly(GuardDecision::Allowed),
                }
            ),
            Err(Rejected::Completion(CompletionRejected::AlreadyCompleted))
        );
        assert_eq!(lifecycle.snapshot(), before);
        assert!(matches!(
            lifecycle.admission_grant(),
            Some(AdmissionGrant::GuardOnly(_))
        ));
        assert!(!before
            .reservation
            .unwrap()
            .has_durable_reservation_receipt());
    }

    #[test]
    fn completed_unknown_rejects_late_receipt_but_waiting_receipt_survives_failure() {
        for finish_before_receipt in [true, false] {
            let (mut lifecycle, handle) = begin(23);
            let prepared = prospective(&handle);
            lifecycle.enter_commit(&handle, prepared.clone()).unwrap();
            let receipt = Receipt {
                correlation: prepared.correlation,
                scope: prepared.scope,
                fact: prepared.fact,
            };
            if finish_before_receipt {
                let outcome = lifecycle
                    .complete(&handle, EffectResult::Failed(FailureKind::Backend))
                    .unwrap();
                assert!(matches!(outcome, ExecutionOutcome::Unknown { .. }));
                let before = lifecycle.snapshot();
                assert_eq!(
                    lifecycle.record_receipt(&handle, receipt),
                    Err(Rejected::Completion(CompletionRejected::AlreadyCompleted))
                );
                assert_eq!(lifecycle.snapshot(), before);
            } else {
                lifecycle.record_receipt(&handle, receipt.clone()).unwrap();
                assert_eq!(
                    lifecycle
                        .complete(&handle, EffectResult::Failed(FailureKind::Cancelled))
                        .unwrap(),
                    ExecutionOutcome::ReceiptPreserved {
                        receipt,
                        cause: FailureKind::Cancelled
                    }
                );
                assert!(lifecycle
                    .snapshot()
                    .reservation
                    .unwrap()
                    .has_durable_reservation_receipt());
            }
            assert!(lifecycle.admission_grant().is_none());
        }
    }

    #[test]
    fn all_original_authority_fields_are_bound_before_effect_start() {
        for field in 0..10 {
            let mut lifecycle = DirectLifecycle::new(Uuid::from_u128(13), 2, 3);
            let handle = lifecycle.begin(request()).unwrap();
            let before = lifecycle.snapshot();
            let mut changed = request();
            match field {
                0 => changed.actor_id = Uuid::from_u128(999),
                1 => changed.account_bare.push('x'),
                2 => changed.normalized_target.push('x'),
                3 => changed.origin_id = None,
                4 => changed.normalized_payload.push('x'),
                5 => changed.pow_intent_payload.push('x'),
                6 => changed.subject.push('x'),
                7 => changed.actors.push("other".into()),
                8 => changed.proof.as_mut().unwrap().challenge_id = Uuid::from_u128(999),
                9 => changed.proof.as_mut().unwrap().nonce.push('x'),
                _ => unreachable!(),
            }
            assert_eq!(
                lifecycle.start_effect(&handle, &Command::Begin(changed)),
                Err(Rejected::Request)
            );
            assert_eq!(lifecycle.snapshot(), before);
            lifecycle
                .start_effect(&handle, &Command::Begin(request()))
                .unwrap();
            assert_eq!(
                lifecycle.start_effect(&handle, &Command::Begin(request())),
                Err(Rejected::AlreadyStarted)
            );
        }
    }

    #[test]
    fn foreign_effect_generation_attempt_and_changed_source_cannot_mutate_owner() {
        let (mut lifecycle, handle) = begin(14);
        let before = lifecycle.snapshot();
        for field in 0..5 {
            let mut changed = handle.clone();
            match field {
                0 => changed.effect.correlation.operation = Uuid::from_u128(999),
                1 => changed.effect.correlation.effect += 1,
                2 => changed.effect.correlation.generation += 1,
                3 => changed.effect.correlation.attempt += 1,
                4 => changed.effect.command = Command::Finalize(fence()),
                _ => unreachable!(),
            }
            assert_eq!(
                lifecycle.enter_commit(&changed, prospective(&changed)),
                Err(Rejected::Grant)
            );
            assert_eq!(lifecycle.snapshot(), before);
        }
        assert_eq!(lifecycle.begin(request()), Err(Rejected::AlreadyStarted));
    }

    #[test]
    fn exact_completed_reservation_can_finalize_only_once() {
        let (mut lifecycle, grant) = reserved(15);
        let (_, foreign) = reserved(16);
        assert_eq!(lifecycle.finalize(&foreign), Err(Rejected::Fence));
        let handle = lifecycle.finalize(&grant).unwrap();
        assert_ne!(handle.effect().correlation, grant.correlation);
        assert_eq!(lifecycle.finalize(&grant), Err(Rejected::AlreadyStarted));
        let mut changed = fence();
        changed.lease_token = Uuid::from_u128(999);
        assert_eq!(
            lifecycle.start_effect(&handle, &Command::Finalize(changed)),
            Err(Rejected::Request)
        );
        lifecycle
            .start_effect(&handle, &Command::Finalize(fence()))
            .unwrap();
    }

    #[test]
    fn finalization_unknown_retains_separate_positive_reservation_receipt() {
        let (mut lifecycle, grant) = reserved(17);
        let reservation = lifecycle.snapshot().reservation;
        let handle = lifecycle.finalize(&grant).unwrap();
        lifecycle
            .start_effect(&handle, &Command::Finalize(fence()))
            .unwrap();
        lifecycle
            .enter_commit(
                &handle,
                PreparedCommit {
                    correlation: handle.effect().correlation,
                    scope: TransactionScope::AdmissionFinalize,
                    fact: CommitFact::Finalized {
                        fence: fence(),
                        result: FinalizeSuccess::PendingAccepted,
                    },
                },
            )
            .unwrap();
        assert!(matches!(
            lifecycle
                .complete(&handle, EffectResult::Failed(FailureKind::Cancelled))
                .unwrap(),
            ExecutionOutcome::Unknown { .. }
        ));
        let terminal = lifecycle.retire(TerminalReason::Cancelled);
        assert_eq!(
            terminal.classification(),
            TerminalClassification::TerminalUnresolved
        );
        assert_eq!(lifecycle.snapshot().reservation, reservation);
        assert_eq!(
            lifecycle.start_effect(&handle, &Command::Finalize(fence())),
            Err(Rejected::Retired)
        );
        assert_eq!(lifecycle.retire(TerminalReason::Completed), terminal);
    }

    #[test]
    fn two_unknown_operations_cannot_be_cleared_by_a_later_success() {
        let (mut first, first_handle) = begin(18);
        first
            .enter_commit(&first_handle, prospective(&first_handle))
            .unwrap();
        first.retire(TerminalReason::Cancelled);
        let old = first.snapshot();
        let (mut second, second_handle) = begin(19);
        second
            .enter_commit(&second_handle, prospective(&second_handle))
            .unwrap();
        second.retire(TerminalReason::TimedOut);
        let second_old = second.snapshot();
        let (mut later, _) = reserved(20);
        later.retire(TerminalReason::Completed);
        assert_eq!(first.snapshot(), old);
        assert_eq!(second.snapshot(), second_old);
        assert_eq!(
            old.classification(),
            TerminalClassification::TerminalUnresolved
        );
        assert_eq!(
            second_old.classification(),
            TerminalClassification::TerminalUnresolved
        );
        assert_eq!(
            first.complete(
                &first_handle,
                EffectResult::Begin(BeginResult::Reserved(fence()))
            ),
            Err(Rejected::Retired)
        );
    }

    #[test]
    fn debug_projection_redacts_all_retained_request_material() {
        let (mut lifecycle, handle) = begin(21);
        lifecycle
            .enter_commit(&handle, prospective(&handle))
            .unwrap();
        let summary = lifecycle.retire(TerminalReason::Cancelled);
        assert_eq!(summary.reservation.unwrap().phase, EffectPhase::Waiting);
        assert_eq!(
            summary.classification(),
            lifecycle.snapshot().classification()
        );
        let rendered = format!("{summary:?} {:?}", lifecycle.snapshot());
        for private in [
            "private-sender",
            "private-target",
            "private-origin",
            "private-normalized",
            "private-pow",
            "private-subject",
            "private-actor",
            "private-nonce",
        ] {
            assert!(
                !rendered.contains(private),
                "retained request leaked through Debug"
            );
        }
    }
}
