//! PostgreSQL adapter for committed clustered-MUC delivery projections.

use crate::db::{
    self, ClusterMucAudienceSnapshot, ClusterMucEventContext, ClusterMucOutboxDelivery,
};
use crate::services::cluster_muc_delivery_read::ClusterMucDeliveryReadRepository;
use anyhow::Result;
use sqlx::PgPool;
use uuid::Uuid;

pub(crate) struct PostgresClusterMucDeliveryReadRepository {
    pool: PgPool,
}

impl PostgresClusterMucDeliveryReadRepository {
    pub(crate) fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

impl ClusterMucDeliveryReadRepository for PostgresClusterMucDeliveryReadRepository {
    type Delivery = ClusterMucOutboxDelivery;
    type EventContext = ClusterMucEventContext;
    type AudienceSnapshot = ClusterMucAudienceSnapshot;

    async fn event_context(&self, operation_id: Uuid) -> Result<Option<ClusterMucEventContext>> {
        db::cluster_muc_event_context(&self.pool, operation_id).await
    }

    async fn recipient_snapshot(
        &self,
        delivery: &ClusterMucOutboxDelivery,
    ) -> Result<Option<ClusterMucAudienceSnapshot>> {
        db::cluster_muc_delivery_recipient_snapshot(&self.pool, delivery).await
    }

    async fn audience_is_current(&self, delivery: &ClusterMucOutboxDelivery) -> Result<bool> {
        db::cluster_muc_delivery_audience_is_current(&self.pool, delivery).await
    }
}
