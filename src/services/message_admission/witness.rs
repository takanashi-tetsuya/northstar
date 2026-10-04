//! Operation-local knowledge at the real SQL COMMIT await. No async Drop work.
use northstar_abuse_policy::admission_execution::{
    Command, CommitFact, CommitWitness, Effect, EffectResult, ExecutionOutcome, PreparedCommit,
    Receipt, TransactionScope,
};
#[cfg(test)]
use northstar_message_application::direct_lifecycle::OperationSnapshot;
use northstar_message_application::direct_lifecycle::{
    AdmissionEffectHandle, AdmissionGrant, DirectLifecycle, OperationSummary, TerminalReason,
};
use northstar_message_application::{direct_commit, direct_lifecycle::PreparationAdmission};
use northstar_message_core::DirectPersonalMessageAdmission;
use sqlx::{Postgres, Transaction};
use std::sync::{Arc, Mutex};
use uuid::Uuid;

/// The outer frame creates this owner before polling the handler. Clones name
/// the same operation; a later frame gets a different owner, never a reset slot.
#[derive(Clone)]
pub(crate) struct DirectOperationHandle(Arc<Mutex<DirectLifecycle>>);

impl std::fmt::Debug for DirectOperationHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("DirectOperationHandle { authority: [redacted] }")
    }
}

impl DirectOperationHandle {
    pub(crate) fn new(operation: Uuid) -> Self {
        Self(Arc::new(Mutex::new(DirectLifecycle::new(operation, 0, 1))))
    }

    pub(crate) fn begin(
        &self,
        request: &crate::abuse::MessageAdmissionRequest<'_>,
    ) -> anyhow::Result<RetainedAdmission> {
        // The existing validator runs before cloning any authority input.
        let Command::Begin(request) = super::begin_command(request)? else {
            unreachable!("begin_command always constructs Begin")
        };
        let handle = self
            .0
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .begin(request)?;
        Ok(RetainedAdmission {
            owner: self.clone(),
            handle,
        })
    }

    pub(crate) fn finalize(
        &self,
        lease: &crate::abuse::MessageAdmissionLease,
    ) -> anyhow::Result<RetainedAdmission> {
        let fence = super::acceptance_fence(&lease.acceptance());
        let mut operation = self.0.lock().unwrap_or_else(|e| e.into_inner());
        let Some(AdmissionGrant::Reserved(grant)) = operation.admission_grant() else {
            anyhow::bail!("finalization requires a completed reservation grant");
        };
        anyhow::ensure!(
            grant.fence() == &fence,
            "finalization reservation fence mismatch"
        );
        let handle = operation.finalize(&grant)?;
        Ok(RetainedAdmission {
            owner: self.clone(),
            handle,
        })
    }

    #[cfg(test)]
    pub(crate) fn snapshot(&self) -> OperationSnapshot {
        self.0.lock().unwrap_or_else(|e| e.into_inner()).snapshot()
    }

    pub(crate) fn retire(&self, reason: TerminalReason) -> OperationSummary {
        self.0
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .retire(reason)
    }

    pub(crate) fn prepare_direct(
        &self,
        admission: PreparationAdmission<'_>,
        command: direct_commit::DirectCommandFacts,
    ) -> anyhow::Result<direct_commit::DirectEffect> {
        Ok(self
            .0
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .prepare_direct(admission, command)?)
    }
    pub(crate) fn start_direct(
        &self,
        effect: &direct_commit::DirectEffect,
    ) -> Result<(), direct_commit::Rejected> {
        self.0
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .start_direct(effect)
    }
    pub(crate) fn prepare_direct_commit(
        &self,
        effect: &direct_commit::DirectEffect,
        prepared: direct_commit::PreparedCommit,
    ) -> Result<(), direct_commit::Rejected> {
        self.0
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .enter_direct_commit(effect, prepared)
    }
    pub(crate) fn receive_direct_commit(
        &self,
        effect: &direct_commit::DirectEffect,
        prepared: direct_commit::PreparedCommit,
    ) -> Result<(), direct_commit::Rejected> {
        self.0
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .receive_direct_commit(effect, prepared)
    }
    pub(crate) fn complete_direct(
        &self,
        effect: &direct_commit::DirectEffect,
        result: Option<DirectPersonalMessageAdmission>,
    ) -> Result<direct_commit::ExecutionOutcome, direct_commit::Rejected> {
        self.0
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .complete_direct(effect, result)
    }
}

/// An exact pre-I/O handle, not a reservation or durable-message capability.
#[derive(Clone, Debug)]
pub(crate) struct RetainedAdmission {
    owner: DirectOperationHandle,
    handle: AdmissionEffectHandle,
}

impl RetainedAdmission {
    pub(crate) fn start(&self, command: &Command) -> anyhow::Result<()> {
        self.owner
            .0
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .start_effect(&self.handle, command)?;
        Ok(())
    }

    pub(crate) fn witness(&self) -> AdmissionWitness {
        AdmissionWitness::Retained(Box::new(self.clone()))
    }

    pub(crate) fn complete(&self, result: EffectResult) -> anyhow::Result<ExecutionOutcome> {
        self.owner
            .0
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .complete(&self.handle, result)
            .map_err(|error| match error {
                northstar_message_application::direct_lifecycle::Rejected::Completion(error) => {
                    error.into()
                }
                other => other.into(),
            })
    }

    pub(crate) fn admission_grant(&self) -> Option<AdmissionGrant> {
        self.owner
            .0
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .admission_grant()
    }
}

#[derive(Clone, Debug)]
pub(crate) enum AdmissionWitness {
    Standalone(Arc<Mutex<CommitWitness>>),
    Retained(Box<RetainedAdmission>),
}

impl AdmissionWitness {
    pub(crate) fn new(effect: Effect) -> Self {
        Self::Standalone(Arc::new(Mutex::new(CommitWitness::new(effect))))
    }
    pub(crate) fn snapshot(&self) -> CommitWitness {
        match self {
            Self::Standalone(state) => state.lock().unwrap_or_else(|e| e.into_inner()).clone(),
            Self::Retained(retained) => retained
                .owner
                .0
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .witness(&retained.handle)
                .expect("issued admission effect handle")
                .clone(),
        }
    }
    pub(super) fn prepare(
        &self,
        scope: TransactionScope,
        fact: CommitFact,
    ) -> anyhow::Result<PreparedCommit> {
        let prepared = PreparedCommit {
            correlation: self.snapshot().effect().correlation,
            scope,
            fact,
        };
        // Retain the exact prospective fact without claiming a positive receipt.
        match self {
            Self::Standalone(state) => state
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .enter_commit(prepared.clone())?,
            Self::Retained(retained) => retained
                .owner
                .0
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .enter_commit(&retained.handle, prepared.clone())?,
        }
        Ok(prepared)
    }
    pub(super) fn received(&self, prepared: PreparedCommit) {
        let receipt = Receipt {
            correlation: prepared.correlation,
            scope: prepared.scope,
            fact: prepared.fact,
        };
        match self {
            Self::Standalone(state) => state
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .record_receipt(receipt)
                .expect("prevalidated operation-local admission receipt"),
            Self::Retained(retained) => retained
                .owner
                .0
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .record_receipt(&retained.handle, receipt)
                .expect("prevalidated retained admission receipt"),
        }
    }
}

pub(crate) async fn commit_observed(
    tx: Transaction<'_, Postgres>,
    witness: &AdmissionWitness,
    scope: TransactionScope,
    fact: CommitFact,
) -> anyhow::Result<()> {
    // Call boundary entered: this does NOT prove PostgreSQL received COMMIT.
    let prepared = witness.prepare(scope, fact)?;
    tx.commit().await?;
    // No await, logging or caller continuation before this positive fact.
    witness.received(prepared);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use northstar_abuse_policy::admission_execution::{
        BeginCommitPurpose, BeginRequest, Command, Completion, Coordinator, Correlation,
        EffectResult, ExecutionOutcome, FailureKind, FinalizeSuccess, Knowledge,
    };
    use northstar_abuse_policy::admission_transaction::AdmissionFence;
    use uuid::Uuid;

    #[tokio::test]
    async fn positive_receipt_survives_dropped_continuation() {
        let fence = AdmissionFence {
            admission_key: vec![1; 32],
            payload_mac: vec![2; 32],
            lease_token: Uuid::from_u128(3),
        };
        let witness = AdmissionWitness::new(Effect {
            correlation: Correlation {
                operation: Uuid::from_u128(4),
                effect: 1,
                generation: 0,
                attempt: 1,
            },
            command: Command::Finalize(fence.clone()),
        });
        let prepared = witness
            .prepare(
                TransactionScope::AdmissionFinalize,
                CommitFact::Finalized {
                    fence,
                    result: FinalizeSuccess::PendingAccepted,
                },
            )
            .unwrap();
        {
            let continuation = async {
                witness.received(prepared);
                std::future::pending::<()>().await;
            };
            tokio::pin!(continuation);
            tokio::select! { biased; _ = &mut continuation => unreachable!(), _ = tokio::task::yield_now() => {} }
        }
        assert!(matches!(
            witness.snapshot().knowledge(),
            Knowledge::ReceiptKnown(_)
        ));
    }
    #[tokio::test]
    async fn prospective_reservation_survives_dropped_continuation_without_a_receipt() {
        let fence = AdmissionFence {
            admission_key: vec![1; 32],
            payload_mac: vec![2; 32],
            lease_token: Uuid::from_u128(3),
        };
        let mut coordinator = Coordinator::new(
            Correlation {
                operation: Uuid::from_u128(4),
                effect: 1,
                generation: 0,
                attempt: 1,
            },
            Command::Begin(BeginRequest {
                actor_id: Uuid::from_u128(5),
                account_bare: "alice@example.test".into(),
                normalized_target: "bob@example.test".into(),
                origin_id: Some("origin".into()),
                normalized_payload: "<message/>".into(),
                pow_intent_payload: "<message/>".into(),
                subject: "message".into(),
                actors: vec![],
                proof: None,
            }),
        );
        let effect = coordinator.pending().unwrap().clone();
        let witness = AdmissionWitness::new(effect.clone());
        let prepared = PreparedCommit {
            correlation: effect.correlation,
            scope: TransactionScope::RatedBegin(BeginCommitPurpose::NewReservation),
            fact: CommitFact::Reserved(fence),
        };
        {
            let continuation = async {
                let prospective = witness
                    .prepare(prepared.scope, prepared.fact.clone())
                    .unwrap();
                assert_eq!(prospective, prepared);
                std::future::pending::<()>().await;
            };
            tokio::pin!(continuation);
            tokio::select! { biased; _ = &mut continuation => unreachable!(), _ = tokio::task::yield_now() => {} }
        }
        let observed = witness.snapshot();
        assert_eq!(
            observed.knowledge(),
            &Knowledge::CommitCallEntered(prepared.clone())
        );
        coordinator.observe_witness(&observed).unwrap();
        assert_eq!(
            coordinator
                .complete(Completion {
                    effect,
                    result: EffectResult::Failed(FailureKind::Cancelled),
                    knowledge: observed.knowledge().clone(),
                })
                .unwrap(),
            &ExecutionOutcome::Unknown {
                prepared,
                cause: FailureKind::Cancelled,
            }
        );
    }
}
