//! Constructors of the single-node MUC and cluster maintenance contexts.

use super::cluster_adapters::PostgresClusterAdapters;
use super::AppState;
use crate::cluster::{
    maintenance_context::ClusterMaintenanceContext,
    standalone_muc_maintenance::StandaloneMucMaintenanceContext,
};

impl AppState {
    pub(crate) fn standalone_muc_maintenance_context(
        &self,
    ) -> StandaloneMucMaintenanceContext<
        northstar_room_postgres::room::PostgresClusterMucOccupancyMaintenanceRepository,
    > {
        StandaloneMucMaintenanceContext::new(
            self.cluster().muc_cluster_node_id().to_owned(),
            northstar_xmpp_types::jid::prepare_domainpart(&format!(
                "conference.{}",
                self.config.domain
            ))
            .expect("configured XMPP domain must form a valid MUC domain"),
            self.cluster_maintenance_locals(),
            self.cluster_muc_occupancy_maintenance_service(),
        )
    }

    pub(crate) fn cluster_maintenance_context(
        &self,
    ) -> ClusterMaintenanceContext<PostgresClusterAdapters> {
        let (control, redis) = self.cluster_maintenance_handles();
        let replay_wake = self.cluster_recovery_replay_wake();
        ClusterMaintenanceContext {
            control,
            session_routes:
                northstar_session_application::session_route_maintenance::SessionRouteRenewalService::new(redis.clone()),
            redis,
            locals: self.cluster_maintenance_locals(),
            direct_spool_wake: self.direct_spool_wake_consumer(replay_wake.clone()),
            replay_wake,
            session_authority: northstar_session_application::session_authority_sweep::SessionAuthoritySweepService::new(
                northstar_workflows::session_authority_sweep_repository::PostgresSessionAuthoritySweepRepository::new(
                    self.pool.clone(),
                ),
            ),
            cluster_authority: self.cluster_authority_service(),
            muc_occupancy: self.cluster_muc_occupancy_maintenance_service(),
        }
    }
}
