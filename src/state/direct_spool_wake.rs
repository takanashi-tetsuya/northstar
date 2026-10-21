//! Builds the direct-spool wake consumer (`cluster::direct_spool_wake`) from the composition root.

use super::AppState;
use crate::{
    cluster::direct_spool_wake::DirectSpoolWakeConsumer,
    db::direct_spool_wake_repository::PostgresDirectSpoolWakeRepository,
    services::direct_spool_wake::DirectSpoolWakeService,
};

impl AppState {
    pub(crate) fn direct_spool_wake_consumer(
        &self,
        replay: crate::cluster::recovery_replay_wake::ClusterRecoveryReplayWake,
    ) -> DirectSpoolWakeConsumer {
        DirectSpoolWakeConsumer::new(
            DirectSpoolWakeService::new(PostgresDirectSpoolWakeRepository::new(self.pool.clone())),
            replay,
        )
    }
}
