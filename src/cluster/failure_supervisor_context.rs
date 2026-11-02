//! Only the PostgreSQL authority and local health controls used by the
//! cluster failure-policy worker. The shared pool stays inside repository
//! adapters; this context cannot publish or sign cluster messages.

use crate::cluster::ClusterFailureSupervisorAuthority;

pub(crate) struct ClusterFailureSupervisorContext {
    pub(crate) authority: ClusterFailureSupervisorAuthority,
    pub(crate) authority_service: northstar_session_application::cluster_authority::ClusterAuthorityService<
        northstar_session_postgres::cluster_authority_repository::PostgresClusterAuthorityRepository,
    >,
    pub(crate) replay_maintenance: northstar_session_application::cluster_replay_maintenance::ClusterReplayMaintenanceService<
        northstar_session_postgres::cluster_replay_maintenance_repository::PostgresClusterReplayMaintenanceRepository,
    >,
    pub(crate) route_maintenance: northstar_session_application::cluster_session_route_maintenance::ClusterSessionRouteMaintenanceService<
        northstar_session_postgres::cluster_session_route_maintenance_repository::PostgresClusterSessionRouteMaintenanceRepository,
    >,
}
