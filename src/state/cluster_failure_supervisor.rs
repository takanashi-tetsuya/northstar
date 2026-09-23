//! Only the PostgreSQL authority and local health controls used by the
//! cluster failure-policy worker. The shared pool stays inside repository
//! adapters; this context cannot publish or sign cluster messages.

use super::AppState;
use crate::{cluster::ClusterFailureSupervisorAuthority, db, services};

pub(crate) struct ClusterFailureSupervisorContext {
    pub(crate) authority: ClusterFailureSupervisorAuthority,
    pub(crate) authority_service: services::cluster_authority::ClusterAuthorityService<
        db::cluster_authority_repository::PostgresClusterAuthorityRepository,
    >,
    pub(crate) replay_maintenance: services::cluster_replay_maintenance::ClusterReplayMaintenanceService<
        db::cluster_replay_maintenance_repository::PostgresClusterReplayMaintenanceRepository,
    >,
    pub(crate) route_maintenance: services::cluster_session_route_maintenance::ClusterSessionRouteMaintenanceService<
        db::cluster_session_route_maintenance_repository::PostgresClusterSessionRouteMaintenanceRepository,
    >,
}

impl AppState {
    pub(crate) fn cluster_failure_supervisor_context(&self) -> ClusterFailureSupervisorContext {
        ClusterFailureSupervisorContext {
            authority: self.cluster.failure_supervisor_authority(),
            authority_service: services::cluster_authority::ClusterAuthorityService::new(
                db::cluster_authority_repository::PostgresClusterAuthorityRepository::new(
                    self.pool.clone(),
                ),
            ),
            replay_maintenance:
                services::cluster_replay_maintenance::ClusterReplayMaintenanceService::new(
                    db::cluster_replay_maintenance_repository::PostgresClusterReplayMaintenanceRepository::new(
                        self.pool.clone(),
                    ),
                ),
            route_maintenance: services::cluster_session_route_maintenance::ClusterSessionRouteMaintenanceService::new(
                db::cluster_session_route_maintenance_repository::PostgresClusterSessionRouteMaintenanceRepository::new(
                    self.pool.clone(),
                ),
            ),
        }
    }
}
