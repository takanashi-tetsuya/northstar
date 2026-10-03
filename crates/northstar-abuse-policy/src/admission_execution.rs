//! Production-shared admission effect correlation and caller knowledge.
//! No clock, entropy, I/O, executor or global state is owned here.
use crate::admission_transaction::{AdmissionFence, FinalizeDecision, ReconcileObservation};
use crate::{MessageAdmissionRequest, PowProof};
use std::fmt;
use uuid::Uuid;

/// Owned complete guard input. Never serialize or print authority-bearing data.
#[derive(Clone, PartialEq, Eq)]
pub struct BeginRequest {
    pub actor_id: Uuid,
    pub account_bare: String,
    pub normalized_target: String,
    pub origin_id: Option<String>,
    pub normalized_payload: String,
    pub pow_intent_payload: String,
    pub subject: String,
    pub actors: Vec<String>,
    pub proof: Option<PowProof>,
}

impl From<MessageAdmissionRequest<'_>> for BeginRequest {
    fn from(r: MessageAdmissionRequest<'_>) -> Self {
        Self {
            actor_id: r.actor_id,
            account_bare: r.account_bare.to_owned(),
            normalized_target: r.normalized_target.to_owned(),
            origin_id: r.origin_id.map(str::to_owned),
            normalized_payload: r.normalized_payload.to_owned(),
            pow_intent_payload: r.pow_intent_payload.to_owned(),
            subject: r.subject.to_owned(),
            actors: r.actors.to_vec(),
            proof: r.proof.cloned(),
        }
    }
}
impl fmt::Debug for BeginRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("BeginRequest { authority: [redacted] }")
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Correlation {
    pub operation: Uuid,
    pub effect: u64,
    pub generation: u64,
    pub attempt: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EffectKind {
    Begin,
    Finalize,
    Reconcile,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Command {
    Begin(BeginRequest),
    Finalize(AdmissionFence),
    Reconcile {
        unresolved: Correlation,
        fence: AdmissionFence,
    },
}
impl Command {
    pub fn kind(&self) -> EffectKind {
        match self {
            Self::Begin(_) => EffectKind::Begin,
            Self::Finalize(_) => EffectKind::Finalize,
            Self::Reconcile { .. } => EffectKind::Reconcile,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Effect {
    pub correlation: Correlation,
    pub command: Command,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BeginCommitPurpose {
    NewReservation,
    Reclaim,
    ReplayRead,
    PendingRequirement,
    GuardDenial,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TransactionScope {
    RatedBegin(BeginCommitPurpose),
    AdmissionFinalize,
    GuardOnlyVerification,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GuardDecision {
    Allowed,
    Denied,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FinalizeSuccess {
    PendingAccepted,
    AlreadyAccepted,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CommitFact {
    Reserved(AdmissionFence),
    ReplayAccepted,
    InProgress,
    Denied,
    Finalized {
        fence: AdmissionFence,
        result: FinalizeSuccess,
    },
    GuardOnly(GuardDecision),
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Receipt {
    pub correlation: Correlation,
    pub scope: TransactionScope,
    pub fact: CommitFact,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Knowledge {
    NoCommitRequested,
    CommitCallEntered(TransactionScope),
    ReceiptKnown(Receipt),
}

/// Independently retained repository knowledge. Invalid updates leave it intact.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CommitWitness {
    effect: Effect,
    knowledge: Knowledge,
}
impl CommitWitness {
    pub fn new(effect: Effect) -> Self {
        Self {
            effect,
            knowledge: Knowledge::NoCommitRequested,
        }
    }
    pub fn knowledge(&self) -> &Knowledge {
        &self.knowledge
    }
    pub fn effect(&self) -> &Effect {
        &self.effect
    }
    pub fn enter_commit(&mut self, scope: TransactionScope) -> Result<(), CompletionRejected> {
        if self.knowledge != Knowledge::NoCommitRequested
            || !scope_matches(self.effect.command.kind(), scope)
        {
            return Err(CompletionRejected::Knowledge);
        }
        self.knowledge = Knowledge::CommitCallEntered(scope);
        Ok(())
    }
    pub fn record_receipt(&mut self, receipt: Receipt) -> Result<(), CompletionRejected> {
        if receipt.correlation != self.effect.correlation {
            return Err(CompletionRejected::Correlation);
        }
        if self.knowledge != Knowledge::CommitCallEntered(receipt.scope)
            || !fact_matches_scope(&receipt.fact, receipt.scope)
            || !fact_matches_command(&receipt.fact, &self.effect.command)
        {
            return Err(CompletionRejected::Knowledge);
        }
        self.knowledge = Knowledge::ReceiptKnown(receipt);
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BeginResult {
    GuardOnly(GuardDecision),
    Reserved(AdmissionFence),
    ReplayAccepted,
    InProgress,
    Denied,
    Conflict,
    CapacityLimited,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FailureKind {
    Backend,
    ActorBusy,
    Cancelled,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EffectResult {
    Begin(BeginResult),
    Finalize(FinalizeDecision),
    Reconcile(ReconcileObservation),
    Failed(FailureKind),
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Completion {
    pub effect: Effect,
    pub result: EffectResult,
    pub knowledge: Knowledge,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ExecutionOutcome {
    Completed {
        result: EffectResult,
        knowledge: Knowledge,
    },
    PreCommitFailure(FailureKind),
    Unknown {
        scope: TransactionScope,
        cause: FailureKind,
    },
    /// The repository received a receipt even if its continuation was cancelled.
    ReceiptPreserved {
        receipt: Receipt,
        cause: FailureKind,
    },
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ExecutionState {
    Waiting(Effect),
    Finished(ExecutionOutcome),
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Coordinator {
    state: ExecutionState,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum CompletionRejected {
    #[error("admission completion correlation mismatch")]
    Correlation,
    #[error("admission completion request mismatch")]
    Request,
    #[error("admission completion kind mismatch")]
    Kind,
    #[error("admission completion knowledge mismatch")]
    Knowledge,
    #[error("admission operation already completed")]
    AlreadyCompleted,
}

impl Coordinator {
    pub fn new(correlation: Correlation, command: Command) -> Self {
        Self {
            state: ExecutionState::Waiting(Effect {
                correlation,
                command,
            }),
        }
    }
    pub fn state(&self) -> &ExecutionState {
        &self.state
    }
    pub fn pending(&self) -> Option<&Effect> {
        match &self.state {
            ExecutionState::Waiting(e) => Some(e),
            _ => None,
        }
    }
    pub fn complete(
        &mut self,
        completion: Completion,
    ) -> Result<&ExecutionOutcome, CompletionRejected> {
        let ExecutionState::Waiting(expected) = &self.state else {
            return Err(CompletionRejected::AlreadyCompleted);
        };
        if expected.correlation != completion.effect.correlation {
            return Err(CompletionRejected::Correlation);
        }
        if expected.command.kind() != completion.effect.command.kind() {
            return Err(CompletionRejected::Kind);
        }
        if expected.command != completion.effect.command {
            return Err(CompletionRejected::Request);
        }
        let result_kind = match &completion.result {
            EffectResult::Begin(_) => Some(EffectKind::Begin),
            EffectResult::Finalize(_) => Some(EffectKind::Finalize),
            EffectResult::Reconcile(_) => Some(EffectKind::Reconcile),
            EffectResult::Failed(_) => None,
        };
        if result_kind.is_some_and(|kind| kind != expected.command.kind()) {
            return Err(CompletionRejected::Kind);
        }
        validate_knowledge(expected, &completion.knowledge)?;
        let outcome = if let EffectResult::Failed(cause) = completion.result {
            match completion.knowledge {
                Knowledge::NoCommitRequested => ExecutionOutcome::PreCommitFailure(cause),
                Knowledge::CommitCallEntered(scope) => ExecutionOutcome::Unknown { scope, cause },
                Knowledge::ReceiptKnown(receipt) => {
                    ExecutionOutcome::ReceiptPreserved { receipt, cause }
                }
            }
        } else {
            validate_result(expected, &completion.result, &completion.knowledge)?;
            ExecutionOutcome::Completed {
                result: completion.result,
                knowledge: completion.knowledge,
            }
        };
        self.state = ExecutionState::Finished(outcome);
        match &self.state {
            ExecutionState::Finished(outcome) => Ok(outcome),
            _ => unreachable!(),
        }
    }
}

fn scope_matches(kind: EffectKind, scope: TransactionScope) -> bool {
    matches!(
        (kind, scope),
        (
            EffectKind::Begin,
            TransactionScope::RatedBegin(_) | TransactionScope::GuardOnlyVerification
        ) | (EffectKind::Finalize, TransactionScope::AdmissionFinalize)
    )
}
fn fact_matches_scope(fact: &CommitFact, scope: TransactionScope) -> bool {
    matches!(
        (fact, scope),
        (
            CommitFact::Reserved(_),
            TransactionScope::RatedBegin(
                BeginCommitPurpose::NewReservation | BeginCommitPurpose::Reclaim
            )
        ) | (
            CommitFact::ReplayAccepted,
            TransactionScope::RatedBegin(BeginCommitPurpose::ReplayRead)
        ) | (
            CommitFact::InProgress,
            TransactionScope::RatedBegin(BeginCommitPurpose::PendingRequirement)
        ) | (
            CommitFact::Denied,
            TransactionScope::RatedBegin(BeginCommitPurpose::GuardDenial)
        ) | (
            CommitFact::Finalized { .. },
            TransactionScope::AdmissionFinalize
        ) | (
            CommitFact::GuardOnly(_),
            TransactionScope::GuardOnlyVerification
        )
    )
}
fn fact_matches_command(fact: &CommitFact, command: &Command) -> bool {
    match (fact, command) {
        (CommitFact::Finalized { fence, .. }, Command::Finalize(expected)) => fence == expected,
        (
            CommitFact::Reserved(_)
            | CommitFact::ReplayAccepted
            | CommitFact::InProgress
            | CommitFact::Denied
            | CommitFact::GuardOnly(_),
            Command::Begin(_),
        ) => true,
        _ => false,
    }
}
fn validate_knowledge(effect: &Effect, knowledge: &Knowledge) -> Result<(), CompletionRejected> {
    let valid = match knowledge {
        Knowledge::NoCommitRequested => true,
        Knowledge::CommitCallEntered(scope) => scope_matches(effect.command.kind(), *scope),
        Knowledge::ReceiptKnown(receipt) => {
            receipt.correlation == effect.correlation
                && scope_matches(effect.command.kind(), receipt.scope)
                && fact_matches_scope(&receipt.fact, receipt.scope)
                && fact_matches_command(&receipt.fact, &effect.command)
        }
    };
    if valid {
        Ok(())
    } else {
        Err(CompletionRejected::Knowledge)
    }
}
fn validate_result(
    effect: &Effect,
    result: &EffectResult,
    knowledge: &Knowledge,
) -> Result<(), CompletionRejected> {
    let valid = match (effect.command.kind(), result, knowledge) {
        (
            EffectKind::Begin,
            EffectResult::Begin(BeginResult::GuardOnly(_)),
            Knowledge::NoCommitRequested,
        ) => true,
        (
            EffectKind::Begin,
            EffectResult::Begin(BeginResult::Conflict | BeginResult::CapacityLimited),
            Knowledge::NoCommitRequested,
        ) => true,
        (EffectKind::Begin, EffectResult::Begin(result), Knowledge::ReceiptKnown(receipt)) => {
            match (result, &receipt.fact) {
                (BeginResult::Reserved(a), CommitFact::Reserved(b)) => a == b,
                (BeginResult::GuardOnly(a), CommitFact::GuardOnly(b)) => a == b,
                (BeginResult::ReplayAccepted, CommitFact::ReplayAccepted)
                | (BeginResult::InProgress, CommitFact::InProgress)
                | (BeginResult::Denied, CommitFact::Denied) => true,
                _ => false,
            }
        }
        (
            EffectKind::Finalize,
            EffectResult::Finalize(
                FinalizeDecision::Missing
                | FinalizeDecision::PayloadConflict
                | FinalizeDecision::LostFence,
            ),
            Knowledge::NoCommitRequested,
        ) => true,
        (
            EffectKind::Finalize,
            EffectResult::Finalize(result),
            Knowledge::ReceiptKnown(receipt),
        ) => matches!(
            (result, &receipt.fact),
            (
                FinalizeDecision::AcceptPending,
                CommitFact::Finalized {
                    result: FinalizeSuccess::PendingAccepted,
                    ..
                }
            ) | (
                FinalizeDecision::AlreadyAccepted,
                CommitFact::Finalized {
                    result: FinalizeSuccess::AlreadyAccepted,
                    ..
                }
            )
        ),
        (EffectKind::Reconcile, EffectResult::Reconcile(_), Knowledge::NoCommitRequested) => true,
        _ => false,
    };
    if valid {
        Ok(())
    } else {
        Err(CompletionRejected::Knowledge)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn begin() -> Coordinator {
        Coordinator::new(
            Correlation {
                operation: Uuid::from_u128(1),
                effect: 2,
                generation: 3,
                attempt: 1,
            },
            Command::Begin(BeginRequest {
                actor_id: Uuid::from_u128(100),
                account_bare: "account-private".into(),
                normalized_target: "target-private".into(),
                origin_id: Some("origin-private".into()),
                normalized_payload: "payload-private".into(),
                pow_intent_payload: "intent-private".into(),
                subject: "subject-private".into(),
                actors: vec!["actor-private".into()],
                proof: Some(PowProof {
                    challenge_id: Uuid::from_u128(200),
                    nonce: "nonce-private".into(),
                }),
            }),
        )
    }
    fn allowed(c: &Coordinator) -> Completion {
        Completion {
            effect: c.pending().unwrap().clone(),
            result: EffectResult::Begin(BeginResult::GuardOnly(GuardDecision::Allowed)),
            knowledge: Knowledge::NoCommitRequested,
        }
    }
    #[test]
    fn every_guard_input_field_is_bound_before_pending_is_consumed() {
        for field in 0..10 {
            let mut c = begin();
            let before = c.state().clone();
            let mut completion = allowed(&c);
            let Command::Begin(r) = &mut completion.effect.command else {
                unreachable!()
            };
            match field {
                0 => r.actor_id = Uuid::nil(),
                1 => r.account_bare.push('x'),
                2 => r.normalized_target.push('x'),
                3 => r.origin_id = None,
                4 => r.normalized_payload.push('x'),
                5 => r.pow_intent_payload.push('x'),
                6 => r.subject.push('x'),
                7 => r.actors.push("different".into()),
                8 => r.proof.as_mut().unwrap().challenge_id = Uuid::nil(),
                9 => r.proof.as_mut().unwrap().nonce.push('x'),
                _ => unreachable!(),
            }
            assert_eq!(c.complete(completion), Err(CompletionRejected::Request));
            assert_eq!(c.state(), &before);
            let valid = allowed(&c);
            c.complete(valid.clone()).unwrap();
            assert_eq!(c.complete(valid), Err(CompletionRejected::AlreadyCompleted));
        }
    }
    #[test]
    fn operation_effect_attempt_generation_and_kind_reject_without_consumption() {
        for field in 0..5 {
            let mut c = begin();
            let before = c.state().clone();
            let mut completion = allowed(&c);
            match field {
                0 => completion.effect.correlation.operation = Uuid::nil(),
                1 => completion.effect.correlation.effect += 1,
                2 => completion.effect.correlation.attempt += 1,
                3 => completion.effect.correlation.generation += 1,
                4 => {
                    completion.effect.command = Command::Finalize(AdmissionFence {
                        admission_key: vec![1; 32],
                        payload_mac: vec![2; 32],
                        lease_token: Uuid::nil(),
                    })
                }
                _ => unreachable!(),
            }
            assert!(c.complete(completion).is_err());
            assert_eq!(c.state(), &before);
            let valid = allowed(&c);
            c.complete(valid).unwrap();
        }
    }
    #[test]
    fn guard_only_and_reservation_unknown_scopes_never_conflate() {
        for scope in [
            TransactionScope::GuardOnlyVerification,
            TransactionScope::RatedBegin(BeginCommitPurpose::NewReservation),
        ] {
            let mut c = begin();
            let effect = c.pending().unwrap().clone();
            let outcome = c
                .complete(Completion {
                    effect,
                    result: EffectResult::Failed(FailureKind::Cancelled),
                    knowledge: Knowledge::CommitCallEntered(scope),
                })
                .unwrap();
            assert_eq!(
                outcome,
                &ExecutionOutcome::Unknown {
                    scope,
                    cause: FailureKind::Cancelled
                }
            );
        }
        let mut c = begin();
        let effect = c.pending().unwrap().clone();
        assert_eq!(
            c.complete(Completion {
                effect,
                result: EffectResult::Failed(FailureKind::Cancelled),
                knowledge: Knowledge::NoCommitRequested
            })
            .unwrap(),
            &ExecutionOutcome::PreCommitFailure(FailureKind::Cancelled)
        );
    }
    #[test]
    fn positive_witness_survives_stale_completion_and_cancelled_continuation() {
        let mut c = begin();
        let effect = c.pending().unwrap().clone();
        let mut witness = CommitWitness::new(effect.clone());
        let scope = TransactionScope::GuardOnlyVerification;
        witness.enter_commit(scope).unwrap();
        let receipt = Receipt {
            correlation: effect.correlation,
            scope,
            fact: CommitFact::GuardOnly(GuardDecision::Allowed),
        };
        witness.record_receipt(receipt.clone()).unwrap();
        let mut stale = Completion {
            effect: effect.clone(),
            result: EffectResult::Failed(FailureKind::Cancelled),
            knowledge: witness.knowledge().clone(),
        };
        stale.effect.correlation.generation += 1;
        assert!(c.complete(stale).is_err());
        assert_eq!(
            witness.knowledge(),
            &Knowledge::ReceiptKnown(receipt.clone())
        );
        assert_eq!(
            c.complete(Completion {
                effect,
                result: EffectResult::Failed(FailureKind::Cancelled),
                knowledge: witness.knowledge().clone()
            })
            .unwrap(),
            &ExecutionOutcome::ReceiptPreserved {
                receipt,
                cause: FailureKind::Cancelled
            }
        );
        let before = witness.clone();
        assert!(witness.enter_commit(scope).is_err());
        assert_eq!(witness, before);
    }
    #[test]
    fn fake_success_without_receipt_is_rejected_and_memory_denial_needs_none() {
        let mut c = begin();
        let before = c.state().clone();
        let mut completion = allowed(&c);
        completion.result = EffectResult::Begin(BeginResult::ReplayAccepted);
        assert_eq!(c.complete(completion), Err(CompletionRejected::Knowledge));
        assert_eq!(c.state(), &before);
        let mut valid = allowed(&c);
        valid.result = EffectResult::Begin(BeginResult::GuardOnly(GuardDecision::Denied));
        c.complete(valid).unwrap();
    }
    #[test]
    fn debug_and_rejection_errors_are_payload_free() {
        let c = begin();
        let text = format!("{c:?}");
        for secret in [
            "account-private",
            "target-private",
            "origin-private",
            "payload-private",
            "intent-private",
            "subject-private",
            "actor-private",
            "nonce-private",
        ] {
            assert!(!text.contains(secret));
        }
        assert!(text.contains("redacted"));
        let fence = AdmissionFence {
            admission_key: b"secret-key".to_vec(),
            payload_mac: b"secret-mac".to_vec(),
            lease_token: Uuid::from_u128(9),
        };
        assert!(!format!("{fence:?}").contains("secret"));
        assert!(!CompletionRejected::Request.to_string().contains("private"));
    }
}
