//! PostgreSQL adapter for clustered-MUC stable item progress.

use crate::db::{self, ClusterMucOutboxDelivery};
use crate::services::cluster_muc_delivery_item::ClusterMucDeliveryItemRepository;
use anyhow::Result;
use sqlx::PgPool;
use uuid::Uuid;

pub(crate) struct PostgresClusterMucDeliveryItemRepository {
    pool: PgPool,
}

impl PostgresClusterMucDeliveryItemRepository {
    pub(crate) fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

impl ClusterMucDeliveryItemRepository for PostgresClusterMucDeliveryItemRepository {
    type Delivery = ClusterMucOutboxDelivery;

    async fn completed(&self, delivery_id: Uuid, ordinal: i32, stable_id: &str) -> Result<bool> {
        db::cluster_muc_delivery_item_completed(&self.pool, delivery_id, ordinal, stable_id).await
    }

    async fn complete_exact(
        &self,
        delivery: &ClusterMucOutboxDelivery,
        ordinal: i32,
        stable_id: &str,
    ) -> Result<bool> {
        db::complete_cluster_muc_delivery_item(&self.pool, delivery, ordinal, stable_id).await
    }
}
