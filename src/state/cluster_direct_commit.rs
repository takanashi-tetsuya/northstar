//! Binds the cluster's direct-commit admission to the message adapters' port. The composition root holds the
//! binding because the admission belongs to the cluster edge and the PostgreSQL fence to the session adapter.

use crate::cluster::{
    ClusterAdmission, DirectCommitTurn, DirectPostCommitMode, DirectSpoolEligibility,
};
use anyhow::Result;
use futures::{future::BoxFuture, FutureExt};
use northstar_message_postgres::direct_cluster::{DirectCommitCluster, DirectCommitPermit};
use northstar_security::cluster_keys::ClusterReadinessAuthority;
use sqlx::{Postgres, Transaction};

/// The cluster's admission as the message adapters' direct-commit port.
pub(crate) struct ClusterDirectCommit(pub(crate) ClusterAdmission);

struct ClusterDirectCommitTurn(DirectCommitTurn);

impl DirectCommitPermit for ClusterDirectCommitTurn {
    fn admitted_mode(&self) -> DirectPostCommitMode {
        self.0.admitted_mode()
    }

    fn finish(self: Box<Self>) -> DirectPostCommitMode {
        let Self(turn) = *self;
        turn.finish()
    }
}

impl DirectCommitCluster for ClusterDirectCommit {
    fn is_enabled(&self) -> bool {
        self.0.is_enabled()
    }

    fn direct_mode(&self) -> DirectPostCommitMode {
        self.0.direct_mode()
    }

    fn check_direct_eligibility(
        &self,
        eligibility: DirectSpoolEligibility,
    ) -> Result<Option<&ClusterReadinessAuthority>> {
        self.0.check_direct_eligibility(eligibility)
    }

    fn begin_direct_commit_turn(
        &self,
        eligibility: DirectSpoolEligibility,
    ) -> Result<(
        Box<dyn DirectCommitPermit>,
        Option<&ClusterReadinessAuthority>,
    )> {
        let (turn, authority) = self.0.begin_direct_commit_turn(eligibility)?;
        Ok((Box::new(ClusterDirectCommitTurn(turn)), authority))
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
