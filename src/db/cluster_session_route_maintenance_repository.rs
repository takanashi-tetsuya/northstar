//! PostgreSQL adapter for the cluster session-route maintenance sequence.

use crate::services::cluster_session_route_maintenance::ClusterSessionRouteMaintenanceRepository;
use anyhow::Result;
use sqlx::PgPool;

pub(crate) struct PostgresClusterSessionRouteMaintenanceRepository {
    pool: PgPool,
}

impl PostgresClusterSessionRouteMaintenanceRepository {
    pub(crate) fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

impl ClusterSessionRouteMaintenanceRepository for PostgresClusterSessionRouteMaintenanceRepository {
    async fn cleanup_routes(&self, limit: i32) -> Result<u64> {
        super::cleanup_cluster_session_routes(&self.pool, limit).await
    }

    async fn validate_authority(&self) -> Result<()> {
        super::validate_cluster_session_route_authority(&self.pool).await
    }
}
