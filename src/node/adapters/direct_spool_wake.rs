//! Builds the direct-spool wake consumer (`cluster::direct_spool_wake`) from the composition root.

use crate::cluster::direct_spool_wake::DirectSpoolWakeConsumer;
use crate::node::adapters::cluster_adapters::PostgresClusterAdapters;
use crate::node::ServerNode;
use northstar_message_application::direct_spool_wake::DirectSpoolWakeService;
use northstar_message_postgres::direct_spool_wake::PostgresDirectSpoolWakeRepository;

impl ServerNode {
    pub(crate) fn direct_spool_wake_consumer(
        &self,
        replay: crate::cluster::recovery_replay_wake::ClusterRecoveryReplayWake<
            northstar_session_postgres::replay_repository::PostgresReplayRepository,
            northstar_session_postgres::replay_repository::PostgresRecoveryReplayStore,
        >,
    ) -> DirectSpoolWakeConsumer<PostgresClusterAdapters> {
        DirectSpoolWakeConsumer::new(
            DirectSpoolWakeService::new(PostgresDirectSpoolWakeRepository::new(self.pool.clone())),
            replay,
        )
    }
}
