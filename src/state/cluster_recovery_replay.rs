//! Builds the local C2S recovery replay wake (`cluster::recovery_replay_wake`) from the composition root.

use super::AppState;
use crate::cluster::recovery_replay_wake::{
    ClusterRecoveryReplayWake, MAX_CONCURRENT_RECOVERY_REPLAYS,
};
use std::sync::Arc;
use tokio::sync::Semaphore;

impl AppState {
    pub(crate) fn cluster_recovery_replay_wake(&self) -> ClusterRecoveryReplayWake {
        ClusterRecoveryReplayWake {
            sessions: Arc::clone(&self.sessions),
            replay: self.replay_service.clone(),
            admission: self.cluster.admission(),
            pool: self.pool.clone(),
            metrics: Arc::clone(&self.metrics),
            permits: Arc::new(Semaphore::new(MAX_CONCURRENT_RECOVERY_REPLAYS)),
        }
    }
}
