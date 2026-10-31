//! The one COMMIT of every rated admission transaction.

use northstar_abuse_policy::admission_execution::{
    AdmissionCommitObserver, CommitFact, TransactionScope,
};
use sqlx::{Postgres, Transaction};

pub(crate) async fn commit_observed(
    tx: Transaction<'_, Postgres>,
    witness: &dyn AdmissionCommitObserver,
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
