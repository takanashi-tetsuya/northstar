//! Builds the direct-spool wake consumer (`cluster::direct_spool_wake`) from the composition root.

use super::cluster_adapters::PostgresClusterAdapters;
use super::AppState;
use crate::cluster::direct_spool_wake::DirectSpoolWakeConsumer;
use northstar_message_application::direct_spool_wake::DirectSpoolWakeService;
use northstar_message_postgres::direct_spool_wake::PostgresDirectSpoolWakeRepository;

impl AppState {
    pub(crate) fn direct_spool_wake_consumer(
        &self,
        replay: crate::cluster::recovery_replay_wake::ClusterRecoveryReplayWake<
            PostgresClusterAdapters,
        >,
    ) -> DirectSpoolWakeConsumer<PostgresClusterAdapters> {
        DirectSpoolWakeConsumer::new(
            DirectSpoolWakeService::new(PostgresDirectSpoolWakeRepository::new(self.pool.clone())),
            replay,
        )
    }
}
