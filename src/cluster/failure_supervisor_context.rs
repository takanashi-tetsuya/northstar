//! Only the PostgreSQL authority and local health controls used by the
//! cluster failure-policy worker. The shared pool stays inside repository
//! adapters; this context cannot publish or sign cluster messages.

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
