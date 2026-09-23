//! PostgreSQL adapter for exact clustered-MUC delivery settlement.

use crate::db::{self, ClusterMucOutboxDelivery};
use crate::services::cluster_muc_outbox_settlement::ClusterMucOutboxSettlementRepository;
use anyhow::Result;
use sqlx::PgPool;

pub(crate) struct PostgresClusterMucOutboxSettlementRepository {
    pool: PgPool,
}

impl PostgresClusterMucOutboxSettlementRepository {
    pub(crate) fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

impl ClusterMucOutboxSettlementRepository for PostgresClusterMucOutboxSettlementRepository {
    type Delivery = ClusterMucOutboxDelivery;

    async fn ack_exact(&self, delivery: &ClusterMucOutboxDelivery) -> Result<bool> {
        db::ack_cluster_muc_outbox(&self.pool, delivery.delivery_id, delivery.claim_token).await
    }

    async fn record_retry(&self, delivery: &ClusterMucOutboxDelivery, error: &str) -> Result<bool> {
        db::retry_cluster_muc_outbox(&self.pool, delivery, error).await
    }
}
