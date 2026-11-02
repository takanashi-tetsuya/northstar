//! The cluster half of a direct commit, until the session context owns the cluster tables.

use crate::cluster::{
    ClusterAdmission, DirectCommitTurn, DirectPostCommitMode, DirectSpoolEligibility,
};
use anyhow::Result;
use futures::{future::BoxFuture, FutureExt};
use northstar_message_postgres::direct_cluster::{DirectCommitCluster, DirectCommitPermit};
use northstar_security::cluster_keys::ClusterReadinessAuthority;
use sqlx::{Postgres, Transaction};

impl DirectCommitPermit for DirectCommitTurn {
    fn admitted_mode(&self) -> DirectPostCommitMode {
        DirectCommitTurn::admitted_mode(self)
    }

    fn finish(self: Box<Self>) -> DirectPostCommitMode {
        DirectCommitTurn::finish(*self)
    }
}

impl DirectCommitCluster for ClusterAdmission {
    fn is_enabled(&self) -> bool {
        ClusterAdmission::is_enabled(self)
    }

    fn direct_mode(&self) -> DirectPostCommitMode {
        ClusterAdmission::direct_mode(self)
    }

    fn check_direct_eligibility(
        &self,
        eligibility: DirectSpoolEligibility,
    ) -> Result<Option<&ClusterReadinessAuthority>> {
        ClusterAdmission::check_direct_eligibility(self, eligibility)
    }

    fn begin_direct_commit_turn(
        &self,
        eligibility: DirectSpoolEligibility,
    ) -> Result<(
        Box<dyn DirectCommitPermit>,
        Option<&ClusterReadinessAuthority>,
    )> {
        let (turn, authority) = ClusterAdmission::begin_direct_commit_turn(self, eligibility)?;
        Ok((Box::new(turn), authority))
    }

    fn fence_authority<'a>(
        &'a self,
        transaction: &'a mut Transaction<'_, Postgres>,
        authority: &'a ClusterReadinessAuthority,
    ) -> BoxFuture<'a, Result<()>> {
        northstar_session_postgres::cluster_keys::fence_direct_message_authority_in_transaction(
            transaction,
            authority,
        )
        .boxed()
    }
}
