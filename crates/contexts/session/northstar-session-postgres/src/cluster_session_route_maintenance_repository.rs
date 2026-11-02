//! PostgreSQL adapter for the cluster session-route maintenance sequence.

use anyhow::Result;
use northstar_session_application::cluster_session_route_maintenance::ClusterSessionRouteMaintenanceRepository;
use sqlx::PgPool;

pub struct PostgresClusterSessionRouteMaintenanceRepository {
    pool: PgPool,
}

impl PostgresClusterSessionRouteMaintenanceRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

impl ClusterSessionRouteMaintenanceRepository for PostgresClusterSessionRouteMaintenanceRepository {
    async fn cleanup_routes(&self, limit: i32) -> Result<u64> {
        crate::cluster_session_route::cleanup_cluster_session_routes(&self.pool, limit).await
    }

    async fn validate_authority(&self) -> Result<()> {
        crate::cluster_session_route::validate_cluster_session_route_authority(&self.pool).await
    }
}
