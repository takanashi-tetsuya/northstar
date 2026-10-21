//! The single-node MUC maintenance context, and the constructors of both maintenance contexts.

use super::AppState;
use crate::cluster::{
    maintenance_context::ClusterMaintenanceContext, maintenance_locals::ClusterMaintenanceLocals,
};
use crate::{db, services};
use std::{sync::Mutex, time::Instant};

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
        let replay_wake = self.cluster_recovery_replay_wake();
        ClusterMaintenanceContext {
            control,
            session_routes:
                services::session_route_maintenance::SessionRouteRenewalService::new(redis.clone()),
            redis,
            locals: self.cluster_maintenance_locals(),
            direct_spool_wake: self.direct_spool_wake_consumer(replay_wake.clone()),
            replay_wake,
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
