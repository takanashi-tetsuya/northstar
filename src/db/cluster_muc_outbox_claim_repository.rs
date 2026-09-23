//! PostgreSQL adapter for the atomic, node-scoped clustered-MUC outbox claim.

use crate::db::{self, ClusterMucOutboxDelivery};
use crate::services::cluster_muc_outbox_claim::ClusterMucOutboxClaimRepository;
use anyhow::Result;
use sqlx::PgPool;
use std::time::Duration;

pub(crate) struct PostgresClusterMucOutboxClaimRepository {
    pool: PgPool,
}

impl PostgresClusterMucOutboxClaimRepository {
    pub(crate) fn new(pool: PgPool) -> Self {
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
        db::claim_cluster_muc_outbox(&self.pool, node_id, limit, lease).await
    }
}
