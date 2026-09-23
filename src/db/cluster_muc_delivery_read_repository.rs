//! PostgreSQL adapter for committed clustered-MUC delivery projections.

use crate::db::{
    self, ClusterMucAudienceSnapshot, ClusterMucEventContext, ClusterMucOutboxDelivery,
};
use crate::services::cluster_muc_delivery_read::ClusterMucDeliveryReadRepository;
use anyhow::{Context, Result};
use serde_json::Value;
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

    async fn original_audience_snapshot(
        &self,
        delivery: &ClusterMucOutboxDelivery,
    ) -> Result<Option<ClusterMucAudienceSnapshot>> {
        let (Some(incarnation), Some(occupancy_epoch), Some(full_jid), Some(nick)) = (
            delivery.recipient_occupant_incarnation,
            delivery.recipient_occupancy_epoch,
            delivery.recipient_full_jid.as_deref(),
            delivery.recipient_nick.as_deref(),
        ) else {
            return Ok(None);
        };
        // Read only the recipient's role at commit. A later transport handoff
        // can change the routing snapshot but cannot change JID visibility.
        let matches = sqlx::query_scalar::<_, Value>(
            "SELECT item.snapshot
               FROM cluster_muc_operations op
               CROSS JOIN LATERAL jsonb_array_elements(op.audience_snapshot) AS item(snapshot)
              WHERE op.operation_id=$1 AND op.room_id=$2 AND op.room_epoch=$3
                AND op.event_id=$4 AND op.event_sequence=$5
                AND item.snapshot->>'room_id'=$2::text
                AND item.snapshot->>'room_epoch'=$3::text
                AND item.snapshot->>'occupant_incarnation'=$6::text
                AND item.snapshot->>'occupancy_epoch'=$7::text
                AND item.snapshot->>'full_jid'=$8
                AND item.snapshot->>'nick'=$9
              LIMIT 2",
        )
        .bind(delivery.operation_id)
        .bind(delivery.room_id)
        .bind(delivery.room_epoch)
        .bind(delivery.event_id)
        .bind(delivery.event_sequence)
        .bind(incarnation)
        .bind(occupancy_epoch)
        .bind(full_jid)
        .bind(nick)
        .fetch_all(&self.pool)
        .await?;
        anyhow::ensure!(
            matches.len() <= 1,
            "cluster MUC original audience has duplicate recipient identities"
        );
        let Some(snapshot) = matches.into_iter().next() else {
            return Ok(None);
        };
        serde_json::from_value(snapshot)
            .context("cluster MUC immutable original audience snapshot is malformed")
            .map(Some)
    }

    async fn audience_is_current(&self, delivery: &ClusterMucOutboxDelivery) -> Result<bool> {
        db::cluster_muc_delivery_audience_is_current(&self.pool, delivery).await
    }
}
