//! What a direct commit needs from the cluster.

use anyhow::Result;
use futures::future::BoxFuture;
use northstar_message_core::{DirectPostCommitMode, DirectSpoolEligibility};
use northstar_security::cluster_keys::ClusterReadinessAuthority;
use sqlx::{Postgres, Transaction};

/// Keeps a health decision ordered with the acknowledged database commit. Dropping it without
/// [`DirectCommitPermit::finish`] releases the turn.
pub trait DirectCommitPermit: Send {
    fn admitted_mode(&self) -> DirectPostCommitMode;

    /// A successful commit can only lose live effects; it cannot become a postcommit rejection.
    fn finish(self: Box<Self>) -> DirectPostCommitMode;
}

/// Cluster health decisions and the PostgreSQL fence of this process's claimed instance. The
/// composition root implements this port over the cluster, which owns the fenced tables.
pub trait DirectCommitCluster: Send + Sync {
    fn is_enabled(&self) -> bool;

    fn direct_mode(&self) -> DirectPostCommitMode;

    /// The process authority to fence, when the cluster admits this operation now.
    fn check_direct_eligibility(
        &self,
        eligibility: DirectSpoolEligibility,
    ) -> Result<Option<&ClusterReadinessAuthority>>;

    /// Admits the final turn before the exact PostgreSQL authority recheck.
    fn begin_direct_commit_turn(
        &self,
        eligibility: DirectSpoolEligibility,
    ) -> Result<(
        Box<dyn DirectCommitPermit>,
        Option<&ClusterReadinessAuthority>,
    )>;

    /// Locks the signing key and instance rows of `authority` until the transaction ends.
    fn fence_authority<'a>(
        &'a self,
        transaction: &'a mut Transaction<'_, Postgres>,
        authority: &'a ClusterReadinessAuthority,
    ) -> BoxFuture<'a, Result<()>>;
}
