//! Builds the cluster failure supervisor's context (`cluster::failure_supervisor_context`).

use super::cluster_adapters::PostgresClusterAdapters;
use super::AppState;
use crate::cluster::failure_supervisor_context::ClusterFailureSupervisorContext;

impl AppState {
    pub(crate) fn cluster_failure_supervisor_context(
        &self,
    ) -> ClusterFailureSupervisorContext<PostgresClusterAdapters> {
        ClusterFailureSupervisorContext {
            authority: self.cluster.failure_supervisor_authority(),
            authority_service: northstar_session_application::cluster_authority::ClusterAuthorityService::new(
                northstar_session_postgres::cluster_authority_repository::PostgresClusterAuthorityRepository::new(
                    self.pool.clone(),
                ),
            ),
            replay_maintenance:
                northstar_session_application::cluster_replay_maintenance::ClusterReplayMaintenanceService::new(
                    northstar_session_postgres::cluster_replay_maintenance_repository::PostgresClusterReplayMaintenanceRepository::new(
                        self.pool.clone(),
                    ),
                ),
            route_maintenance: northstar_session_application::cluster_session_route_maintenance::ClusterSessionRouteMaintenanceService::new(
                northstar_session_postgres::cluster_session_route_maintenance_repository::PostgresClusterSessionRouteMaintenanceRepository::new(
                    self.pool.clone(),
                ),
            ),
        }
    }
}
