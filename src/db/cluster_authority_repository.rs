//! PostgreSQL adapter for cluster signing-key and node-instance authority.

use crate::cluster::ClusterReadinessAuthority;
use crate::db::{
    self, ClusterKeyDeploymentIdentity, ClusterNodeHeartbeat, ClusterNodeInstance,
    ClusterPeerKeyAuthority, ExpectedClusterPeerKey,
};
use crate::services::cluster_authority::ClusterAuthorityRepository;
use anyhow::Result;
use sqlx::PgPool;
use std::time::Duration;

pub(crate) struct PostgresClusterAuthorityRepository {
    pool: PgPool,
}

impl PostgresClusterAuthorityRepository {
    pub(crate) fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

impl ClusterAuthorityRepository for PostgresClusterAuthorityRepository {
    async fn validate_cluster_key(&self, identity: &ClusterKeyDeploymentIdentity) -> Result<()> {
        db::validate_cluster_key_deployment(&self.pool, identity).await
    }

    async fn validate_peer_keys(
        &self,
        domain: &str,
        expected: &[ExpectedClusterPeerKey],
    ) -> Result<()> {
        db::validate_cluster_peer_key_deployments(&self.pool, domain, expected).await
    }

    async fn peer_keys(
        &self,
        domain: &str,
        nodes: &[String],
    ) -> Result<Vec<ClusterPeerKeyAuthority>> {
        db::cluster_peer_key_authorities(&self.pool, domain, nodes).await
    }

    async fn active_instances(
        &self,
        domain: &str,
        nodes: &[String],
    ) -> Result<Vec<ClusterNodeInstance>> {
        db::active_cluster_node_instances(&self.pool, domain, nodes).await
    }

    async fn heartbeat_instance(
        &self,
        authority: &ClusterReadinessAuthority,
        lease: Duration,
    ) -> Result<()> {
        db::heartbeat_cluster_node_instance(
            &self.pool,
            ClusterNodeHeartbeat {
                xmpp_domain: &authority.key_identity.xmpp_domain,
                node_id: &authority.instance_node_id,
                instance_uuid: authority.instance_uuid,
                instance_epoch: authority.instance_epoch,
                signing_key_id: &authority.signing_key_id,
                signing_key_epoch: authority.signing_key_epoch,
                lease,
            },
        )
        .await?;
        Ok(())
    }
}
