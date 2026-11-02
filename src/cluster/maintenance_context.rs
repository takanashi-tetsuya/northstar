//! Authority, Redis projection and local snapshots for one cluster maintenance pass. The composition root builds it.

use crate::cluster;

pub(crate) struct ClusterMaintenanceContext {
    pub(crate) control: cluster::ClusterMaintenanceControl,
    pub(crate) redis: cluster::ClusterMaintenanceRedis,
    pub(crate) session_routes:
        northstar_session_application::session_route_maintenance::SessionRouteRenewalService<
            cluster::ClusterMaintenanceRedis,
        >,
    pub(crate) locals: super::maintenance_locals::ClusterMaintenanceLocals,
    pub(crate) replay_wake: super::recovery_replay_wake::ClusterRecoveryReplayWake,
    pub(crate) direct_spool_wake: super::direct_spool_wake::DirectSpoolWakeConsumer,
    pub(crate) session_authority:
        northstar_session_application::session_authority_sweep::SessionAuthoritySweepService<
            northstar_workflows::session_authority_sweep_repository::PostgresSessionAuthoritySweepRepository,
        >,
    pub(crate) cluster_authority:
        northstar_session_application::cluster_authority::ClusterAuthorityService<
            northstar_session_postgres::cluster_authority_repository::PostgresClusterAuthorityRepository,
        >,
    pub(crate) muc_occupancy:
        northstar_room_application::muc_service::ClusterMucOccupancyMaintenanceService<
            northstar_room_postgres::room::PostgresClusterMucOccupancyMaintenanceRepository,
        >,
}
