//! PostgreSQL adapter for exact clustered-MUC outbox lease renewal.

use crate::db;
use anyhow::Result;
use northstar_room_application::cluster_muc_receipt_claim::ClusterMucReceiptClaimRepository;
use sqlx::PgPool;
use std::time::Duration;

pub(crate) struct PostgresClusterMucReceiptClaimRepository {
    pool: PgPool,
}

impl PostgresClusterMucReceiptClaimRepository {
    pub(crate) fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

impl ClusterMucReceiptClaimRepository for PostgresClusterMucReceiptClaimRepository {
    type Delivery = db::ClusterMucOutboxDelivery;

    async fn renew_exact(&self, delivery: &Self::Delivery, lease: Duration) -> Result<bool> {
        db::renew_cluster_muc_outbox_claim(&self.pool, delivery, lease).await
    }
}
