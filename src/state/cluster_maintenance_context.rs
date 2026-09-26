//! Authority, Redis projection and local snapshots for cluster maintenance.

use super::{cluster_maintenance::ClusterMaintenanceLocals, AppState};
use crate::{cluster, db, services};
use std::{sync::Mutex, time::Instant};

pub(crate) struct ClusterMaintenanceContext {
    pub(crate) control: cluster::ClusterMaintenanceControl,
    pub(crate) redis: cluster::ClusterMaintenanceRedis,
    pub(crate) session_routes: services::session_route_maintenance::SessionRouteRenewalService<
        cluster::ClusterMaintenanceRedis,
    >,
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

/// PostgreSQL occupancy renewal in the single-node runtime has no Redis
/// dependency. The last complete pass survives worker restarts so repeated
/// failures cannot extend a local actor beyond its database lease.
pub(crate) struct StandaloneMucMaintenanceContext {
    pub(crate) node_id: String,
    pub(crate) muc_domain: String,
    pub(crate) locals: ClusterMaintenanceLocals,
    pub(crate) occupancy: services::muc::ClusterMucOccupancyMaintenanceService<
        db::room::PostgresClusterMucOccupancyMaintenanceRepository,
    >,
    pub(crate) last_complete_pass: Mutex<Instant>,
}

impl AppState {
    pub(crate) fn standalone_muc_maintenance_context(&self) -> StandaloneMucMaintenanceContext {
        StandaloneMucMaintenanceContext {
            node_id: self.muc_cluster_node_id().to_owned(),
            muc_domain: crate::jid::prepare_domainpart(&format!(
                "conference.{}",
                self.config.domain
            ))
            .expect("configured XMPP domain must form a valid MUC domain"),
            locals: self.cluster_maintenance_locals(),
            occupancy: self.cluster_muc_occupancy_maintenance_service(),
            last_complete_pass: Mutex::new(Instant::now()),
        }
    }

    pub(crate) fn cluster_maintenance_context(&self) -> ClusterMaintenanceContext {
        let (control, redis) = self.cluster_maintenance_handles();
        ClusterMaintenanceContext {
            control,
            session_routes:
                services::session_route_maintenance::SessionRouteRenewalService::new(redis.clone()),
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
