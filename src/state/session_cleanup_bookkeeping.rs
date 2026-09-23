//! Connection-scoped privacy cleanup and finalization observation.

use super::AppState;
use crate::{
    db::privacy::PostgresPrivacyRepository, metrics::Metrics, services::privacy::PrivacyService,
    workers::WorkerRegistry,
};
use anyhow::Result;
use std::sync::{atomic::Ordering, Arc};
use uuid::Uuid;

pub(crate) struct SessionCleanupBookkeeping {
    privacy: PrivacyService<PostgresPrivacyRepository>,
    metrics: Arc<Metrics>,
    workers: Arc<WorkerRegistry>,
}

impl AppState {
    pub(crate) fn session_cleanup_bookkeeping(&self) -> SessionCleanupBookkeeping {
        SessionCleanupBookkeeping {
            privacy: self.privacy_service.clone(),
            metrics: Arc::clone(&self.metrics),
            workers: Arc::clone(&self.workers),
        }
    }
}

impl SessionCleanupBookkeeping {
    pub(crate) async fn clear_active_privacy_session(
        &self,
        user_id: Uuid,
        connection_id: Uuid,
    ) -> Result<()> {
        self.privacy
            .clear_active_session(user_id, connection_id)
            .await
    }

    pub(crate) fn finalization_started(&self) {
        self.metrics
            .session_finalizations_total
            .fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn finalization_failed(&self, failures: usize) {
        self.metrics
            .session_finalization_failures_total
            .fetch_add(failures as u64, Ordering::Relaxed);
    }

    pub(crate) fn worker_registry(&self) -> &WorkerRegistry {
        &self.workers
    }
}
