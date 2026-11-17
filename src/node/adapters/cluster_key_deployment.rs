//! PostgreSQL binding for cluster startup signing-key deployment reconciliation.

use northstar_cluster::startup_authority::ClusterKeyDeploymentPort;
use northstar_security::cluster_keys::ClusterKeyDeploymentIdentity;
use northstar_session_postgres::cluster_keys::{
    reconcile_cluster_key_deployment, reconcile_cluster_key_deployment_before_instance_claim,
    reconcile_cluster_peer_key_deployment,
};
use sqlx::PgPool;

pub(in crate::node) struct ClusterKeyDeployment<'a> {
    pool: &'a PgPool,
}

impl<'a> ClusterKeyDeployment<'a> {
    pub(in crate::node) fn new(pool: &'a PgPool) -> Self {
        Self { pool }
    }
}

impl ClusterKeyDeploymentPort for ClusterKeyDeployment<'_> {
    async fn reconcile_before_instance_claim(
        &self,
        identity: &ClusterKeyDeploymentIdentity,
    ) -> anyhow::Result<()> {
        reconcile_cluster_key_deployment_before_instance_claim(self.pool, identity).await
    }

    async fn reconcile_peer(&self, peer: &ClusterKeyDeploymentIdentity) -> anyhow::Result<()> {
        reconcile_cluster_peer_key_deployment(self.pool, peer).await
    }

    async fn finalize(&self, identity: &ClusterKeyDeploymentIdentity) -> anyhow::Result<()> {
        reconcile_cluster_key_deployment(self.pool, identity).await
    }
}
