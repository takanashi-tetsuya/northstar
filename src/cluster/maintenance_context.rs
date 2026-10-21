//! Authority, Redis projection and local snapshots for one cluster maintenance pass. The composition root builds it.

use crate::{cluster, db, services};

pub(crate) struct ClusterMaintenanceContext {
    pub(crate) control: cluster::ClusterMaintenanceControl,
    pub(crate) redis: cluster::ClusterMaintenanceRedis,
    pub(crate) session_routes: services::session_route_maintenance::SessionRouteRenewalService<
        cluster::ClusterMaintenanceRedis,
    >,
    pub(crate) locals: super::maintenance_locals::ClusterMaintenanceLocals,
    pub(crate) replay_wake: super::recovery_replay_wake::ClusterRecoveryReplayWake,
    pub(crate) direct_spool_wake: super::direct_spool_wake::DirectSpoolWakeConsumer,
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
