//! Authority, Redis projection and local snapshots for cluster maintenance.

use super::{cluster_maintenance::ClusterMaintenanceLocals, AppState};
use crate::{cluster, db, services};

pub(crate) struct ClusterMaintenanceContext {
    pub(crate) control: cluster::ClusterMaintenanceControl,
    pub(crate) redis: cluster::ClusterMaintenanceRedis,
    pub(crate) locals: ClusterMaintenanceLocals,
    pub(crate) session_authority: services::session_authority_sweep::SessionAuthoritySweepService<
        db::session_authority_sweep_repository::PostgresSessionAuthoritySweepRepository,
    >,
    pub(crate) cluster_authority: services::cluster_authority::ClusterAuthorityService<
        db::cluster_authority_repository::PostgresClusterAuthorityRepository,
    >,
    pub(crate) muc_occupancy: services::muc::ClusterMucOccupancyMaintenanceService<
        db::room::PostgresClusterMucOccupancyMaintenanceRepository,
    >,
}

impl AppState {
    pub(crate) fn cluster_maintenance_context(&self) -> ClusterMaintenanceContext {
        let (control, redis) = self.cluster_maintenance_handles();
        ClusterMaintenanceContext {
            control,
            redis,
            locals: self.cluster_maintenance_locals(),
            session_authority: services::session_authority_sweep::SessionAuthoritySweepService::new(
                db::session_authority_sweep_repository::PostgresSessionAuthoritySweepRepository::new(
                    self.pool.clone(),
                ),
            ),
            cluster_authority: self.cluster_authority_service(),
            muc_occupancy: self.cluster_muc_occupancy_maintenance_service(),
        }
    }
}
