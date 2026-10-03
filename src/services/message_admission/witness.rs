//! Operation-local knowledge at the real SQL COMMIT await. No async Drop work.
use northstar_abuse_policy::admission_execution::{
    CommitFact, CommitWitness, Effect, Knowledge, Receipt, TransactionScope,
};
use sqlx::{Postgres, Transaction};
use std::sync::{Arc, Mutex};

#[derive(Clone, Debug)]
pub(crate) struct AdmissionWitness(Arc<Mutex<CommitWitness>>);

impl AdmissionWitness {
    pub(crate) fn new(effect: Effect) -> Self {
        Self(Arc::new(Mutex::new(CommitWitness::new(effect))))
    }
    pub(crate) fn knowledge(&self) -> Knowledge {
        self.0
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .knowledge()
            .clone()
    }
    pub(super) fn prepare(
        &self,
        scope: TransactionScope,
        fact: CommitFact,
    ) -> anyhow::Result<Receipt> {
        let mut state = self.0.lock().unwrap_or_else(|e| e.into_inner());
        let receipt = Receipt {
            correlation: state.effect().correlation,
            scope,
            fact,
        };
        // Validate the future receipt before allowing any COMMIT call.
        let mut proposed = state.clone();
        proposed.enter_commit(scope)?;
        proposed.record_receipt(receipt.clone())?;
        state.enter_commit(scope)?;
        Ok(receipt)
    }
    pub(super) fn received(&self, receipt: Receipt) {
        self.0
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .record_receipt(receipt)
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
    let receipt = witness.prepare(scope, fact)?;
    tx.commit().await?;
    // No await, logging or caller continuation before this positive fact.
    witness.received(receipt);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use northstar_abuse_policy::admission_execution::{Command, Correlation, FinalizeSuccess};
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
        let receipt = witness
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
                witness.received(receipt);
                std::future::pending::<()>().await;
            };
            tokio::pin!(continuation);
            tokio::select! { biased; _ = &mut continuation => unreachable!(), _ = tokio::task::yield_now() => {} }
        }
        assert!(matches!(witness.knowledge(), Knowledge::ReceiptKnown(_)));
    }
}
