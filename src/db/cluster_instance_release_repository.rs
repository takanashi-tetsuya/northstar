//! PostgreSQL adapter for the final exact cluster node-instance lease release.

use crate::services::cluster_instance_release::{
    ClusterInstanceReleaseIdentity, ClusterInstanceReleaseRepository,
};
use anyhow::Result;
use sqlx::PgPool;

pub(crate) struct PostgresClusterInstanceReleaseRepository {
    pool: PgPool,
}

impl PostgresClusterInstanceReleaseRepository {
    pub(crate) fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

impl ClusterInstanceReleaseRepository for PostgresClusterInstanceReleaseRepository {
    async fn release(&self, identity: &ClusterInstanceReleaseIdentity) -> Result<bool> {
        crate::db::release_cluster_node_instance(
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
