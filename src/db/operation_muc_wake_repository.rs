//! Read only the committed outbox descriptor for an administrator MUC wake.

use crate::{db, services::operation_muc_wake::CommittedMucWakeRepository};
use anyhow::Result;
use northstar_room_core::ClusterMucWakeDescriptor;
use sqlx::PgPool;
use uuid::Uuid;

pub(crate) struct PostgresCommittedMucWakeRepository {
    pool: PgPool,
}

impl PostgresCommittedMucWakeRepository {
    pub(crate) fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

impl CommittedMucWakeRepository for PostgresCommittedMucWakeRepository {
    async fn descriptor(&self, operation_id: Uuid) -> Result<Option<ClusterMucWakeDescriptor>> {
        db::cluster_muc_wake_descriptor(&self.pool, operation_id).await
    }
}
