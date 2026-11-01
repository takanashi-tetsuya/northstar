//! PostgreSQL adapter for exact clustered-MUC outbox lease renewal.

use anyhow::Result;
use northstar_room_application::cluster_muc_receipt_claim::ClusterMucReceiptClaimRepository;
use sqlx::PgPool;
use std::time::Duration;

pub struct PostgresClusterMucReceiptClaimRepository {
    pool: PgPool,
}

impl PostgresClusterMucReceiptClaimRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

impl ClusterMucReceiptClaimRepository for PostgresClusterMucReceiptClaimRepository {
    type Delivery = crate::cluster_muc::ClusterMucOutboxDelivery;

    async fn renew_exact(&self, delivery: &Self::Delivery, lease: Duration) -> Result<bool> {
        crate::cluster_muc::renew_cluster_muc_outbox_claim(&self.pool, delivery, lease).await
    }
}
