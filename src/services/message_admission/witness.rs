//! Operation-local knowledge at the real SQL COMMIT await. No async Drop work.
use northstar_abuse_policy::admission_execution::{
    CommitFact, CommitWitness, Effect, PreparedCommit, Receipt, TransactionScope,
};
use sqlx::{Postgres, Transaction};
use std::sync::{Arc, Mutex};

#[derive(Clone, Debug)]
pub(crate) struct AdmissionWitness(Arc<Mutex<CommitWitness>>);

impl AdmissionWitness {
    pub(crate) fn new(effect: Effect) -> Self {
        Self(Arc::new(Mutex::new(CommitWitness::new(effect))))
    }
    pub(crate) fn snapshot(&self) -> CommitWitness {
        self.0.lock().unwrap_or_else(|e| e.into_inner()).clone()
    }
    pub(super) fn prepare(
        &self,
        scope: TransactionScope,
        fact: CommitFact,
    ) -> anyhow::Result<PreparedCommit> {
        let mut state = self.0.lock().unwrap_or_else(|e| e.into_inner());
        let prepared = PreparedCommit {
            correlation: state.effect().correlation,
            scope,
            fact,
        };
        // Retain the exact prospective fact without claiming a positive receipt.
        state.enter_commit(prepared.clone())?;
        Ok(prepared)
    }
    pub(super) fn received(&self, prepared: PreparedCommit) {
        self.0
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .record_receipt(Receipt {
                correlation: prepared.correlation,
                scope: prepared.scope,
                fact: prepared.fact,
            })
            .expect("prevalidated operation-local admission receipt");
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
