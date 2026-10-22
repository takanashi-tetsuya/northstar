//! Production-shared admission effect correlation and caller knowledge.
//! No clock, entropy, I/O, executor or global state is owned here.
use crate::admission_transaction::{AdmissionFence, FinalizeDecision, TimedReconcileObservation};
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
/// Exact prospective transaction fact retained before the COMMIT await.
/// This is unconfirmed knowledge, never a receipt or an admission capability.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PreparedCommit {
    pub correlation: Correlation,
    pub scope: TransactionScope,
    pub fact: CommitFact,
}
impl PreparedCommit {
    fn matches_receipt(&self, receipt: &Receipt) -> bool {
        self.correlation == receipt.correlation
            && self.scope == receipt.scope
            && self.fact == receipt.fact
    }
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
    CommitCallEntered(PreparedCommit),
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
    pub fn enter_commit(&mut self, prepared: PreparedCommit) -> Result<(), CompletionRejected> {
        if prepared.correlation != self.effect.correlation {
            return Err(CompletionRejected::Correlation);
        }
        if self.knowledge != Knowledge::NoCommitRequested {
            return Err(CompletionRejected::Knowledge);
        }
        let knowledge = Knowledge::CommitCallEntered(prepared);
        validate_knowledge(&self.effect, &knowledge)?;
        self.knowledge = knowledge;
        Ok(())
    }
    pub fn record_receipt(&mut self, receipt: Receipt) -> Result<(), CompletionRejected> {
        if receipt.correlation != self.effect.correlation {
            return Err(CompletionRejected::Correlation);
        }
        if !matches!(&self.knowledge, Knowledge::CommitCallEntered(prepared) if prepared.matches_receipt(&receipt))
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
/// Current-row evidence bound to the exact read effect and unresolved request.
/// Keeping this effect does not establish any historical commit or retry right.
/// Its fence is the requested authority; ExactAccepted still precedes token equality.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReconcileResult {
    pub effect: Box<Effect>,
    pub observation: TimedReconcileObservation,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EffectResult {
    Begin(BeginResult),
    Finalize(FinalizeDecision),
    Reconcile(ReconcileResult),
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
        prepared: PreparedCommit,
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
    observed: Option<Knowledge>,
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
            observed: None,
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
    /// Supply a snapshot obtained directly from the repository's retained witness,
    /// independently of a completion. A completion cannot supply this observation.
    /// Same-attempt observations only advance knowledge; rejected updates are inert.
    pub fn observe_witness(&mut self, witness: &CommitWitness) -> Result<(), CompletionRejected> {
        let ExecutionState::Waiting(expected) = &self.state else {
            return Err(CompletionRejected::AlreadyCompleted);
        };
        validate_effect(expected, witness.effect())?;
        validate_knowledge(expected, witness.knowledge())?;
        if self
            .observed
            .as_ref()
            .is_some_and(|prior| !knowledge_advances(prior, witness.knowledge()))
        {
            return Err(CompletionRejected::Knowledge);
        }
        self.observed = Some(witness.knowledge().clone());
        Ok(())
    }
    pub fn complete(
        &mut self,
        completion: Completion,
    ) -> Result<&ExecutionOutcome, CompletionRejected> {
        let ExecutionState::Waiting(expected) = &self.state else {
            return Err(CompletionRejected::AlreadyCompleted);
        };
        validate_effect(expected, &completion.effect)?;
        let result_kind = match &completion.result {
            EffectResult::Begin(_) => Some(EffectKind::Begin),
            EffectResult::Finalize(_) => Some(EffectKind::Finalize),
            EffectResult::Reconcile(_) => Some(EffectKind::Reconcile),
            EffectResult::Failed(_) => None,
        };
        if result_kind.is_some_and(|kind| kind != expected.command.kind()) {
            return Err(CompletionRejected::Kind);
        }
        if self.observed.as_ref() != Some(&completion.knowledge) {
            return Err(CompletionRejected::Knowledge);
        }
        validate_knowledge(expected, &completion.knowledge)?;
        let outcome = if let EffectResult::Failed(cause) = completion.result {
            match completion.knowledge {
                Knowledge::NoCommitRequested => ExecutionOutcome::PreCommitFailure(cause),
                Knowledge::CommitCallEntered(prepared) => {
                    ExecutionOutcome::Unknown { prepared, cause }
                }
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

fn validate_effect(expected: &Effect, actual: &Effect) -> Result<(), CompletionRejected> {
    if expected.correlation != actual.correlation {
        return Err(CompletionRejected::Correlation);
    }
    if expected.command.kind() != actual.command.kind() {
        return Err(CompletionRejected::Kind);
    }
    if expected.command != actual.command {
        return Err(CompletionRejected::Request);
    }
    Ok(())
}
fn knowledge_advances(prior: &Knowledge, next: &Knowledge) -> bool {
    prior == next
        || match (prior, next) {
            (Knowledge::NoCommitRequested, _) => true,
            (Knowledge::CommitCallEntered(prepared), Knowledge::ReceiptKnown(receipt)) => {
                prepared.matches_receipt(receipt)
            }
            _ => false,
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
        Knowledge::CommitCallEntered(prepared) => {
            prepared.correlation == effect.correlation
                && scope_matches(effect.command.kind(), prepared.scope)
                && fact_matches_scope(&prepared.fact, prepared.scope)
                && fact_matches_command(&prepared.fact, &effect.command)
        }
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
    if let EffectResult::Reconcile(observed) = result {
        validate_effect(effect, &observed.effect)?;
    }
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
        let mut coordinator = Coordinator::new(
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
        );
        let witness = CommitWitness::new(coordinator.pending().unwrap().clone());
        coordinator.observe_witness(&witness).unwrap();
        coordinator
    }
    fn fence() -> AdmissionFence {
        AdmissionFence {
            admission_key: vec![1; 32],
            payload_mac: vec![2; 32],
            lease_token: Uuid::from_u128(3),
        }
    }
    fn prepared(effect: &Effect, scope: TransactionScope, fact: CommitFact) -> PreparedCommit {
        PreparedCommit {
            correlation: effect.correlation,
            scope,
            fact,
        }
    }
    fn receipt(prepared: &PreparedCommit) -> Receipt {
        Receipt {
            correlation: prepared.correlation,
            scope: prepared.scope,
            fact: prepared.fact.clone(),
        }
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
            let fact = if scope == TransactionScope::GuardOnlyVerification {
                CommitFact::GuardOnly(GuardDecision::Allowed)
            } else {
                CommitFact::Reserved(fence())
            };
            let prepared = prepared(&effect, scope, fact);
            let mut witness = CommitWitness::new(effect.clone());
            witness.enter_commit(prepared.clone()).unwrap();
            c.observe_witness(&witness).unwrap();
            let outcome = c
                .complete(Completion {
                    effect,
                    result: EffectResult::Failed(FailureKind::Cancelled),
                    knowledge: witness.knowledge().clone(),
                })
                .unwrap();
            assert_eq!(
                outcome,
                &ExecutionOutcome::Unknown {
                    prepared,
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
        let prepared = prepared(
            &effect,
            scope,
            CommitFact::GuardOnly(GuardDecision::Allowed),
        );
        witness.enter_commit(prepared.clone()).unwrap();
        let receipt = receipt(&prepared);
        witness.record_receipt(receipt.clone()).unwrap();
        c.observe_witness(&witness).unwrap();
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
        assert!(witness.enter_commit(prepared).is_err());
        assert_eq!(witness, before);
    }
    #[test]
    fn swapped_reservation_result_and_receipt_cannot_replace_observed_fence() {
        for field in 0..3 {
            let mut c = begin();
            let effect = c.pending().unwrap().clone();
            let prepared = prepared(
                &effect,
                TransactionScope::RatedBegin(BeginCommitPurpose::NewReservation),
                CommitFact::Reserved(fence()),
            );
            let mut witness = CommitWitness::new(effect.clone());
            witness.enter_commit(prepared.clone()).unwrap();
            witness.record_receipt(receipt(&prepared)).unwrap();
            c.observe_witness(&witness).unwrap();
            let before = c.clone();
            let mut swapped_fence = fence();
            match field {
                0 => swapped_fence.admission_key[0] ^= 1,
                1 => swapped_fence.payload_mac[0] ^= 1,
                2 => swapped_fence.lease_token = Uuid::from_u128(9),
                _ => unreachable!(),
            }
            let mut swapped_receipt = receipt(&prepared);
            swapped_receipt.fact = CommitFact::Reserved(swapped_fence.clone());
            assert_eq!(
                c.complete(Completion {
                    effect: effect.clone(),
                    result: EffectResult::Begin(BeginResult::Reserved(swapped_fence)),
                    knowledge: Knowledge::ReceiptKnown(swapped_receipt),
                }),
                Err(CompletionRejected::Knowledge)
            );
            assert_eq!(c, before);
            c.complete(Completion {
                effect,
                result: EffectResult::Begin(BeginResult::Reserved(fence())),
                knowledge: witness.knowledge().clone(),
            })
            .unwrap();
        }
    }
    #[test]
    fn completion_neither_supplies_a_witness_nor_upgrades_observed_preparation() {
        let observed = begin();
        let effect = observed.pending().unwrap().clone();
        let mut c = Coordinator::new(effect.correlation, effect.command.clone());
        let before = c.clone();
        let completion = allowed(&c);
        assert_eq!(c.complete(completion), Err(CompletionRejected::Knowledge));
        assert_eq!(c, before);

        let prepared = prepared(
            &effect,
            TransactionScope::RatedBegin(BeginCommitPurpose::NewReservation),
            CommitFact::Reserved(fence()),
        );
        let mut witness = CommitWitness::new(effect.clone());
        witness.enter_commit(prepared.clone()).unwrap();
        c.observe_witness(&witness).unwrap();
        let entered = witness.knowledge().clone();
        let before = c.clone();
        let completion = Completion {
            effect: effect.clone(),
            result: EffectResult::Begin(BeginResult::Reserved(fence())),
            knowledge: Knowledge::ReceiptKnown(receipt(&prepared)),
        };
        assert_eq!(
            c.complete(completion.clone()),
            Err(CompletionRejected::Knowledge)
        );
        assert_eq!(c, before);
        witness.record_receipt(receipt(&prepared)).unwrap();
        c.observe_witness(&witness).unwrap();
        let before = c.clone();
        assert_eq!(
            c.complete(Completion {
                effect,
                result: EffectResult::Failed(FailureKind::Cancelled),
                knowledge: entered,
            }),
            Err(CompletionRejected::Knowledge)
        );
        assert_eq!(c, before);
        c.complete(completion).unwrap();
    }
    #[test]
    fn observation_checks_full_effect_before_changing_retained_knowledge() {
        for field in 0..15 {
            let mut c = begin();
            let before = c.clone();
            let mut effect = c.pending().unwrap().clone();
            match field {
                0 => effect.correlation.operation = Uuid::nil(),
                1 => effect.correlation.effect += 1,
                2 => effect.correlation.generation += 1,
                3 => effect.correlation.attempt += 1,
                4 => effect.command = Command::Finalize(fence()),
                _ => {
                    let Command::Begin(request) = &mut effect.command else {
                        unreachable!()
                    };
                    match field {
                        5 => request.actor_id = Uuid::nil(),
                        6 => request.account_bare.push('x'),
                        7 => request.normalized_target.push('x'),
                        8 => request.origin_id = None,
                        9 => request.normalized_payload.push('x'),
                        10 => request.pow_intent_payload.push('x'),
                        11 => request.subject.push('x'),
                        12 => request.actors.push("different".into()),
                        13 => request.proof.as_mut().unwrap().challenge_id = Uuid::nil(),
                        14 => request.proof.as_mut().unwrap().nonce.push('x'),
                        _ => unreachable!(),
                    }
                }
            }
            let expected_error = match field {
                0..=3 => CompletionRejected::Correlation,
                4 => CompletionRejected::Kind,
                _ => CompletionRejected::Request,
            };
            assert_eq!(
                c.observe_witness(&CommitWitness::new(effect)),
                Err(expected_error)
            );
            assert_eq!(c, before);
            let valid = allowed(&c);
            c.complete(valid).unwrap();
        }
    }
    #[test]
    fn observation_is_monotone_and_identical_repeats_are_idempotent() {
        let mut c = begin();
        let effect = c.pending().unwrap().clone();
        let empty = CommitWitness::new(effect.clone());
        let before = c.clone();
        c.observe_witness(&empty).unwrap();
        assert_eq!(c, before);
        let prepared = prepared(
            &effect,
            TransactionScope::RatedBegin(BeginCommitPurpose::NewReservation),
            CommitFact::Reserved(fence()),
        );
        let mut witness = empty.clone();
        witness.enter_commit(prepared.clone()).unwrap();
        c.observe_witness(&witness).unwrap();
        let before = c.clone();
        c.observe_witness(&witness).unwrap();
        assert_eq!(c, before);
        assert_eq!(
            c.observe_witness(&empty),
            Err(CompletionRejected::Knowledge)
        );
        assert_eq!(c, before);

        for field in 0..5 {
            let mut changed = prepared.clone();
            match field {
                0 => changed.scope = TransactionScope::RatedBegin(BeginCommitPurpose::Reclaim),
                1 => {
                    changed.scope = TransactionScope::GuardOnlyVerification;
                    changed.fact = CommitFact::GuardOnly(GuardDecision::Allowed);
                }
                _ => {
                    let CommitFact::Reserved(fence) = &mut changed.fact else {
                        unreachable!()
                    };
                    match field {
                        2 => fence.admission_key[0] ^= 1,
                        3 => fence.payload_mac[0] ^= 1,
                        4 => fence.lease_token = Uuid::from_u128(9),
                        _ => unreachable!(),
                    }
                }
            }
            let mut replacement = empty.clone();
            replacement.enter_commit(changed.clone()).unwrap();
            assert_eq!(
                c.observe_witness(&replacement),
                Err(CompletionRejected::Knowledge)
            );
            assert_eq!(c, before);
            replacement.record_receipt(receipt(&changed)).unwrap();
            assert_eq!(
                c.observe_witness(&replacement),
                Err(CompletionRejected::Knowledge)
            );
            assert_eq!(c, before);
        }
        let entered = witness.clone();
        witness.record_receipt(receipt(&prepared)).unwrap();
        c.observe_witness(&witness).unwrap();
        let before = c.clone();
        c.observe_witness(&witness).unwrap();
        assert_eq!(c, before);
        for downgrade in [&empty, &entered] {
            assert_eq!(
                c.observe_witness(downgrade),
                Err(CompletionRejected::Knowledge)
            );
            assert_eq!(c, before);
        }
        c.complete(Completion {
            effect,
            result: EffectResult::Failed(FailureKind::Cancelled),
            knowledge: witness.knowledge().clone(),
        })
        .unwrap();
    }
    #[test]
    fn witness_rejects_a_receipt_that_changes_the_prepared_fact() {
        let c = begin();
        let effect = c.pending().unwrap().clone();
        let prepared = prepared(
            &effect,
            TransactionScope::RatedBegin(BeginCommitPurpose::NewReservation),
            CommitFact::Reserved(fence()),
        );
        let mut witness = CommitWitness::new(effect);
        witness.enter_commit(prepared.clone()).unwrap();
        let before = witness.clone();
        for field in 0..6 {
            let mut changed = receipt(&prepared);
            match field {
                0 => changed.correlation.attempt += 1,
                1 => changed.scope = TransactionScope::RatedBegin(BeginCommitPurpose::Reclaim),
                2 => changed.fact = CommitFact::Denied,
                _ => {
                    let CommitFact::Reserved(fence) = &mut changed.fact else {
                        unreachable!()
                    };
                    match field {
                        3 => fence.admission_key[0] ^= 1,
                        4 => fence.payload_mac[0] ^= 1,
                        5 => fence.lease_token = Uuid::from_u128(9),
                        _ => unreachable!(),
                    }
                }
            }
            assert!(witness.record_receipt(changed).is_err());
            assert_eq!(witness, before);
        }
        witness.record_receipt(receipt(&prepared)).unwrap();
    }
    #[test]
    fn already_accepted_observation_binds_request_fence_without_stored_token_equality() {
        use crate::admission_transaction::{decide_finalize, AdmissionRow, RowState};
        let request_fence = fence();
        let now = chrono::DateTime::from_timestamp(1, 0).unwrap();
        let accepted = AdmissionRow {
            admission_key: request_fence.admission_key.clone(),
            key_id: "key".into(),
            actor_id: Uuid::from_u128(100),
            payload_mac: request_fence.payload_mac.clone(),
            state: RowState::Accepted,
            lease_token: Uuid::from_u128(999),
            lease_expires_at: now,
            expires_at: now,
        };
        let result = decide_finalize(Some(&accepted), &request_fence);
        assert_eq!(result, FinalizeDecision::AlreadyAccepted);
        let mut c = Coordinator::new(
            begin().pending().unwrap().correlation,
            Command::Finalize(request_fence.clone()),
        );
        let effect = c.pending().unwrap().clone();
        let prepared = prepared(
            &effect,
            TransactionScope::AdmissionFinalize,
            CommitFact::Finalized {
                fence: request_fence,
                result: FinalizeSuccess::AlreadyAccepted,
            },
        );
        let mut witness = CommitWitness::new(effect.clone());
        witness.enter_commit(prepared.clone()).unwrap();
        witness.record_receipt(receipt(&prepared)).unwrap();
        c.observe_witness(&witness).unwrap();
        c.complete(Completion {
            effect,
            result: EffectResult::Finalize(result),
            knowledge: witness.knowledge().clone(),
        })
        .unwrap();
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
    fn reconciliation_retains_sample_and_rejects_relabelled_inner_effect_before_consumption() {
        use crate::admission_transaction::ReconcileObservation;
        let correlation = begin().pending().unwrap().correlation;
        let unresolved = Correlation {
            operation: Uuid::from_u128(7),
            ..correlation
        };
        let observed_at = chrono::DateTime::from_timestamp_micros(-123_456).unwrap();
        for field in 0..12 {
            let mut coordinator = Coordinator::new(
                correlation,
                Command::Reconcile {
                    unresolved,
                    fence: fence(),
                },
            );
            let effect = coordinator.pending().unwrap().clone();
            let witness = CommitWitness::new(effect.clone());
            coordinator.observe_witness(&witness).unwrap();
            let result = ReconcileResult {
                effect: Box::new(effect.clone()),
                observation: TimedReconcileObservation {
                    observed_at,
                    observation: ReconcileObservation::Missing,
                },
            };
            let mut wrong = result.clone();
            match field {
                0 => wrong.effect.correlation.operation = Uuid::nil(),
                1 => wrong.effect.correlation.effect += 1,
                2 => wrong.effect.correlation.generation += 1,
                3 => wrong.effect.correlation.attempt += 1,
                4..=10 => {
                    let Command::Reconcile { unresolved, fence } = &mut wrong.effect.command else {
                        unreachable!()
                    };
                    match field {
                        4 => unresolved.operation = Uuid::nil(),
                        5 => unresolved.effect += 1,
                        6 => unresolved.generation += 1,
                        7 => unresolved.attempt += 1,
                        8 => fence.admission_key[0] ^= 1,
                        9 => fence.payload_mac[0] ^= 1,
                        10 => fence.lease_token = Uuid::nil(),
                        _ => unreachable!(),
                    }
                }
                11 => wrong.effect.command = Command::Finalize(fence()),
                _ => unreachable!(),
            }
            let before = coordinator.clone();
            assert_eq!(
                coordinator.complete(Completion {
                    effect: effect.clone(),
                    result: EffectResult::Reconcile(wrong),
                    knowledge: Knowledge::NoCommitRequested,
                }),
                Err(if field < 4 {
                    CompletionRejected::Correlation
                } else if field == 11 {
                    CompletionRejected::Kind
                } else {
                    CompletionRejected::Request
                })
            );
            assert_eq!(coordinator, before);
            let completion = Completion {
                effect,
                result: EffectResult::Reconcile(result.clone()),
                knowledge: Knowledge::NoCommitRequested,
            };
            assert_eq!(
                coordinator.complete(completion.clone()).unwrap(),
                &ExecutionOutcome::Completed {
                    result: EffectResult::Reconcile(result),
                    knowledge: Knowledge::NoCommitRequested,
                }
            );
            assert_eq!(
                coordinator.complete(completion),
                Err(CompletionRejected::AlreadyCompleted)
            );
            assert_eq!(witness.knowledge(), &Knowledge::NoCommitRequested);
        }
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
        let result = ReconcileResult {
            effect: Box::new(Effect {
                correlation: c.pending().unwrap().correlation,
                command: Command::Reconcile {
                    unresolved: c.pending().unwrap().correlation,
                    fence,
                },
            }),
            observation: TimedReconcileObservation {
                observed_at: chrono::DateTime::from_timestamp_micros(1).unwrap(),
                observation: crate::admission_transaction::ReconcileObservation::Missing,
            },
        };
        assert!(!format!("{result:?}").contains("secret"));
        assert!(format!("{result:?}").contains("redacted"));
        assert!(!CompletionRejected::Request.to_string().contains("private"));
    }
}
