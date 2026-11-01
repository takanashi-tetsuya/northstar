//! PostgreSQL adapter for the atomic, node-scoped clustered-MUC outbox claim.

use crate::cluster_muc::ClusterMucOutboxDelivery;
use anyhow::Result;
use northstar_room_application::cluster_muc_outbox_claim::ClusterMucOutboxClaimRepository;
use sqlx::PgPool;
use std::time::Duration;

pub struct PostgresClusterMucOutboxClaimRepository {
    pool: PgPool,
}

impl PostgresClusterMucOutboxClaimRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

impl ClusterMucOutboxClaimRepository for PostgresClusterMucOutboxClaimRepository {
    type Delivery = ClusterMucOutboxDelivery;

    async fn claim_batch(
        &self,
        node_id: &str,
        limit: i64,
        lease: Duration,
    ) -> Result<Vec<ClusterMucOutboxDelivery>> {
        crate::cluster_muc::claim_cluster_muc_outbox(&self.pool, node_id, limit, lease).await
    }
}
