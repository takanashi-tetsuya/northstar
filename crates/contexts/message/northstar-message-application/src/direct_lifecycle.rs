//! Operation-local admission ownership for the direct-message lifecycle.
//!
//! This first boundary retains reservation and finalization independently. It
//! does not infer a durable message commit, route, or scheduled recovery from
//! either admission transaction. No I/O, clock, entropy, or async Drop lives here.

use crate::direct_commit;
use northstar_abuse_policy::{
    admission_execution::{
        BeginRequest, BeginResult, Command, CommitFact, CommitWitness, Completion,
        CompletionRejected, Coordinator, Correlation, Effect, EffectResult, ExecutionOutcome,
        ExecutionState, GuardDecision, Knowledge, PreparedCommit, Receipt,
    },
    admission_transaction::AdmissionFence,
};
use northstar_message_core::direct_handoff;
use northstar_message_core::DirectPersonalMessageAdmission;
use uuid::Uuid;

/// Purpose-specific admission projection derived by the private protocol
/// source adapter. No XML parsing or new normalization policy lives here.
pub struct OriginalAdmission<'a> {
    pub actor_id: Uuid,
    pub account_bare: &'a str,
    pub normalized_target: &'a str,
    pub origin_id: Option<&'a str>,
    pub normalized_payload: &'a str,
}

pub enum PreparationAdmission<'a> {
    Rated(OriginalAdmission<'a>),
    NoAdmissionRequired,
}

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
    Direct(direct_commit::Rejected),
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
/// Reservation/finalization alone never prove a direct commit. Only the direct
/// receipt outcome identifies a confirmed transaction; none of these facts
/// establishes transport transfer or settlement.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OperationSummary {
    pub operation: Uuid,
    pub reservation: Option<AdmissionSummary>,
    pub finalization: Option<AdmissionSummary>,
    pub direct: Option<DirectSummary>,
    pub handoff: Option<HandoffSummary>,
    pub terminal: Option<TerminalReason>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DirectSummary {
    pub phase: EffectPhase,
    pub knowledge: CommitKnowledgeClass,
    pub confirmed_outcome: Option<DirectOutcomeClass>,
    pub receipt_admitted_mode: Option<northstar_message_core::DirectPostCommitMode>,
    pub returned_mode: Option<northstar_message_core::DirectPostCommitMode>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DirectOutcomeClass {
    Stored,
    Replay,
    AccountUnavailable,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HandoffSummary {
    pub local: direct_handoff::LocalKnowledge,
    pub local_accepted: bool,
    pub remote: direct_handoff::RemoteKnowledge,
    pub prior_remote_uncertain: bool,
    pub rearm: direct_handoff::RearmKnowledge,
    pub route_end: direct_handoff::RouteEnd,
}
fn handoff_summary(snapshot: direct_handoff::Snapshot) -> HandoffSummary {
    HandoffSummary {
        local: snapshot.local_call,
        local_accepted: snapshot.local_accepted,
        remote: snapshot.remote,
        prior_remote_uncertain: snapshot.prior_remote_uncertain,
        rearm: snapshot.rearm,
        route_end: snapshot.route_end,
    }
}

fn direct_summary(state: &direct_commit::Snapshot) -> DirectSummary {
    let receipt = match &state.knowledge {
        direct_commit::Knowledge::ReceiptKnown(receipt) => Some(receipt),
        _ => None,
    };
    DirectSummary {
        phase: if state.outcome.is_some() {
            EffectPhase::Finished
        } else if state.started {
            EffectPhase::Waiting
        } else {
            EffectPhase::Issued
        },
        knowledge: match state.knowledge {
            direct_commit::Knowledge::NoCommitRequested => CommitKnowledgeClass::NoCommitRequested,
            direct_commit::Knowledge::CommitCallEntered(_) => {
                CommitKnowledgeClass::CommitCallEntered
            }
            direct_commit::Knowledge::ReceiptKnown(_) => CommitKnowledgeClass::ReceiptKnown,
        },
        confirmed_outcome: receipt.map(|receipt| match receipt.prepared.outcome {
            direct_commit::TransactionOutcome::Stored { .. } => DirectOutcomeClass::Stored,
            direct_commit::TransactionOutcome::Replay { .. } => DirectOutcomeClass::Replay,
            direct_commit::TransactionOutcome::AccountUnavailable => {
                DirectOutcomeClass::AccountUnavailable
            }
        }),
        receipt_admitted_mode: receipt.map(|receipt| receipt.prepared.admitted_mode),
        returned_mode: match &state.outcome {
            Some(direct_commit::ExecutionOutcome::Completed(result)) => Some(result.mode),
            _ => None,
        },
    }
}

impl OperationSummary {
    pub fn classification(&self) -> TerminalClassification {
        if self
            .direct
            .is_some_and(|direct| direct.knowledge == CommitKnowledgeClass::CommitCallEntered)
            || [self.reservation, self.finalization]
                .into_iter()
                .flatten()
                .any(|execution| execution.knowledge == CommitKnowledgeClass::CommitCallEntered)
        {
            TerminalClassification::TerminalUnresolved
        } else if self.reservation.is_some() || self.finalization.is_some() || self.direct.is_some()
        {
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
    pub direct: Option<direct_commit::Snapshot>,
    pub handoff: Option<direct_handoff::Snapshot>,
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
            direct: self.direct.as_ref().map(direct_summary),
            handoff: self.handoff.map(handoff_summary),
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
    direct: Option<direct_commit::Execution>,
    handoff: Option<direct_handoff::Control>,
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
            direct: None,
            handoff: None,
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
        if self.reservation.is_some() || self.direct.is_some() {
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
        if let Some(direct) = &self.direct {
            let state = direct.state();
            if state.outcome.is_none()
                || !matches!(&state.knowledge,
                direct_commit::Knowledge::ReceiptKnown(receipt)
                if matches!(receipt.prepared.outcome, direct_commit::TransactionOutcome::Stored { .. } | direct_commit::TransactionOutcome::Replay { .. }))
            {
                return Err(Rejected::Direct(direct_commit::Rejected::Knowledge));
            }
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
            direct: self.direct.as_ref().map(direct_commit::Execution::snapshot),
            handoff: self.handoff.as_ref().map(direct_handoff::Control::snapshot),
            terminal: self.terminal,
        }
    }

    pub fn retire(&mut self, reason: TerminalReason) -> OperationSummary {
        if self.terminal.is_none() {
            self.terminal = Some(reason);
        }
        if let Some(handoff) = &self.handoff {
            handoff.retire();
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
            direct: self
                .direct
                .as_ref()
                .map(|execution| direct_summary(execution.state())),
            handoff: self
                .handoff
                .as_ref()
                .map(|handoff| handoff_summary(handoff.snapshot())),
            terminal: self.terminal,
        }
    }

    pub fn prepare_direct(
        &mut self,
        admission: PreparationAdmission<'_>,
        command: direct_commit::DirectCommandFacts,
    ) -> Result<direct_commit::DirectEffect, Rejected> {
        self.ensure_open()?;
        if self.direct.is_some() || self.finalization.is_some() {
            return Err(Rejected::AlreadyStarted);
        }
        match admission {
            PreparationAdmission::NoAdmissionRequired => {
                if self.reservation.is_some() {
                    return Err(Rejected::Request);
                }
            }
            PreparationAdmission::Rated(original) => {
                let Some(begin) = &self.reservation else {
                    return Err(Rejected::ReservationRequired);
                };
                let Command::Begin(expected) = &begin.handle.effect.command else {
                    return Err(Rejected::Request);
                };
                if expected.actor_id != original.actor_id
                    || command.actor_id != original.actor_id
                    || expected.account_bare != original.account_bare
                    || expected.normalized_target != original.normalized_target
                    || expected.origin_id.as_deref() != original.origin_id
                    || expected.normalized_payload != original.normalized_payload
                {
                    return Err(Rejected::Request);
                }
                if self.admission_grant().is_none() {
                    return Err(Rejected::ReservationRequired);
                }
            }
        }
        let execution = direct_commit::Execution::new(self.correlation(3), command);
        let effect = execution.effect().clone();
        self.direct = Some(execution);
        Ok(effect)
    }

    fn direct_execution(
        &mut self,
    ) -> Result<&mut direct_commit::Execution, direct_commit::Rejected> {
        if self.terminal.is_some() {
            return Err(direct_commit::Rejected::AlreadyCompleted);
        }
        self.direct.as_mut().ok_or(direct_commit::Rejected::Command)
    }

    pub fn start_direct(
        &mut self,
        effect: &direct_commit::DirectEffect,
    ) -> Result<(), direct_commit::Rejected> {
        self.direct_execution()?.start(effect)
    }
    pub fn enter_direct_commit(
        &mut self,
        effect: &direct_commit::DirectEffect,
        prepared: direct_commit::PreparedCommit,
    ) -> Result<(), direct_commit::Rejected> {
        self.direct_execution()?.enter_commit(effect, prepared)
    }
    pub fn receive_direct_commit(
        &mut self,
        effect: &direct_commit::DirectEffect,
        prepared: direct_commit::PreparedCommit,
    ) -> Result<(), direct_commit::Rejected> {
        self.direct_execution()?.received(effect, prepared)
    }
    pub fn complete_direct(
        &mut self,
        effect: &direct_commit::DirectEffect,
        result: Option<DirectPersonalMessageAdmission>,
    ) -> Result<direct_commit::ExecutionOutcome, direct_commit::Rejected> {
        self.direct_execution()?.complete(effect, result)
    }

    pub fn begin_handoff(&mut self) -> Result<direct_handoff::Next, direct_handoff::Rejected> {
        use direct_handoff::Rejected as Error;
        use northstar_message_core::DirectPostCommitMode;
        if self.terminal.is_some() {
            return Err(Error::Retired);
        }
        if self.handoff.is_some() {
            return Err(Error::State);
        }
        let finalized = match self.admission_grant() {
            Some(AdmissionGrant::Reserved(_)) => {
                self.finalization.as_ref().is_some_and(|finalization| {
                    matches!(
                        finalization.coordinator.state(),
                        ExecutionState::Finished(_)
                    )
                })
            }
            Some(AdmissionGrant::GuardOnly(_)) => true,
            None => self.reservation.is_none(),
        };
        if !finalized {
            return Err(Error::State);
        }
        let state = self.direct.as_ref().ok_or(Error::Knowledge)?.state();
        let direct_commit::Knowledge::ReceiptKnown(receipt) = &state.knowledge else {
            return Err(Error::Knowledge);
        };
        let direct_commit::TransactionOutcome::Stored {
            recipient_id,
            delivery_id,
            live_claim_id,
            ..
        } = receipt.prepared.outcome
        else {
            return Err(Error::Knowledge);
        };
        let needs_health = match &state.outcome {
            Some(direct_commit::ExecutionOutcome::Completed(result)) => match result.mode {
                DirectPostCommitMode::Live => true,
                DirectPostCommitMode::SpoolOnly => false,
                DirectPostCommitMode::Rejected => return Err(Error::Knowledge),
            },
            Some(direct_commit::ExecutionOutcome::ReceiptPreserved(_)) => false,
            _ => return Err(Error::Knowledge),
        };
        let source = northstar_delivery_core::DurableDelivery {
            recipient_id,
            message_id: delivery_id,
            claim_id: live_claim_id,
        };
        let (control, next) =
            direct_handoff::Control::new(self.correlation(4), source, needs_health);
        self.handoff = Some(control);
        Ok(next)
    }
    fn handoff_control(
        &mut self,
    ) -> Result<&mut direct_handoff::Control, direct_handoff::Rejected> {
        if self.terminal.is_some() {
            return Err(direct_handoff::Rejected::Retired);
        }
        self.handoff.as_mut().ok_or(direct_handoff::Rejected::State)
    }
    pub fn observe_handoff_health(
        &mut self,
        permit: direct_handoff::HealthPermit,
        mode: northstar_message_core::DirectPostCommitMode,
    ) -> Result<direct_handoff::Next, direct_handoff::Rejected> {
        self.handoff_control()?.observed_health(permit, mode)
    }
    pub fn consume_route(
        &mut self,
        grant: direct_handoff::RouteGrant,
        source: northstar_delivery_core::DurableDelivery,
    ) -> Result<direct_handoff::HandoffHandle, direct_handoff::Rejected> {
        self.handoff_control()?.consume_route(grant, source)
    }
    pub fn consume_recovery(
        &mut self,
        grant: direct_handoff::RecoveryGrant,
    ) -> Result<direct_handoff::HandoffHandle, direct_handoff::Rejected> {
        self.handoff_control()?.consume_recovery(grant)
    }
}

#[cfg(test)]
mod tests;
