//! PostgreSQL adapter for the final exact cluster node-instance lease release.

use anyhow::Result;
use northstar_session_application::cluster_instance_release::{
    ClusterInstanceReleaseIdentity, ClusterInstanceReleaseRepository,
};
use sqlx::PgPool;

pub struct PostgresClusterInstanceReleaseRepository {
    pool: PgPool,
}

impl PostgresClusterInstanceReleaseRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

impl ClusterInstanceReleaseRepository for PostgresClusterInstanceReleaseRepository {
    async fn release(&self, identity: &ClusterInstanceReleaseIdentity) -> Result<bool> {
        crate::cluster_keys::release_cluster_node_instance(
            &self.pool,
            &identity.xmpp_domain,
            &identity.node_id,
            identity.instance_uuid,
            identity.instance_epoch,
            &identity.signing_key_id,
            identity.signing_key_epoch,
        )
        .await
    }
}
