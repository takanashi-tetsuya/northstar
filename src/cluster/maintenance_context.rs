//! Authority, Redis projection and local snapshots for one cluster maintenance pass. The composition root builds it.

use crate::cluster::{self, ClusterAdapters};

pub(crate) struct ClusterMaintenanceContext<A: ClusterAdapters> {
    pub(crate) control: cluster::ClusterMaintenanceControl,
    pub(crate) redis: cluster::ClusterMaintenanceRedis,
    pub(crate) session_routes:
        northstar_session_application::session_route_maintenance::SessionRouteRenewalService<
            cluster::ClusterMaintenanceRedis,
        >,
    pub(crate) locals: super::maintenance_locals::ClusterMaintenanceLocals,
    pub(crate) replay_wake: super::recovery_replay_wake::ClusterRecoveryReplayWake<A>,
    pub(crate) direct_spool_wake: super::direct_spool_wake::DirectSpoolWakeConsumer<A>,
    pub(crate) session_authority:
        northstar_session_application::session_authority_sweep::SessionAuthoritySweepService<
            A::SessionAuthoritySweep,
        >,
    pub(crate) cluster_authority:
        northstar_session_application::cluster_authority::ClusterAuthorityService<
            A::ClusterAuthority,
        >,
    pub(crate) muc_occupancy:
        northstar_room_application::muc_service::ClusterMucOccupancyMaintenanceService<
            A::MucOccupancyMaintenance,
        >,
}
