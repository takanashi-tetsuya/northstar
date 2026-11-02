//! Authority, Redis projection and local snapshots for one cluster maintenance pass. The composition root builds it.

use crate::ClusterAdapters;

pub struct ClusterMaintenanceContext<A: ClusterAdapters> {
    pub control: crate::ClusterMaintenanceControl,
    pub redis: crate::ClusterMaintenanceRedis,
    pub session_routes:
        northstar_session_application::session_route_maintenance::SessionRouteRenewalService<
            crate::ClusterMaintenanceRedis,
        >,
    pub locals: super::maintenance_locals::ClusterMaintenanceLocals,
    pub replay_wake:
        super::recovery_replay_wake::ClusterRecoveryReplayWake<A::Replay, A::RecoveryReplay>,
    pub direct_spool_wake: super::direct_spool_wake::DirectSpoolWakeConsumer<A>,
    pub session_authority:
        northstar_session_application::session_authority_sweep::SessionAuthoritySweepService<
            A::SessionAuthoritySweep,
        >,
    pub cluster_authority:
        northstar_session_application::cluster_authority::ClusterAuthorityService<
            A::ClusterAuthority,
        >,
    pub muc_occupancy:
        northstar_room_application::muc_service::ClusterMucOccupancyMaintenanceService<
            A::MucOccupancyMaintenance,
        >,
}
