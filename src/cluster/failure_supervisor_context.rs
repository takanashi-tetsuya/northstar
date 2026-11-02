//! Only the PostgreSQL authority and local health controls used by the
//! cluster failure-policy worker. The shared pool stays inside repository
//! adapters; this context cannot publish or sign cluster messages.

use crate::cluster::{ClusterAdapters, ClusterFailureSupervisorAuthority};

pub(crate) struct ClusterFailureSupervisorContext<A: ClusterAdapters> {
    pub(crate) authority: ClusterFailureSupervisorAuthority,
    pub(crate) authority_service: northstar_session_application::cluster_authority::ClusterAuthorityService<
        A::ClusterAuthority,
    >,
    pub(crate) replay_maintenance: northstar_session_application::cluster_replay_maintenance::ClusterReplayMaintenanceService<
        A::ReplayMaintenance,
    >,
    pub(crate) route_maintenance: northstar_session_application::cluster_session_route_maintenance::ClusterSessionRouteMaintenanceService<
        A::RouteMaintenance,
    >,
}
