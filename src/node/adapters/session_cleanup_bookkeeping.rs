//! Connection-scoped privacy cleanup and finalization observation.

use crate::node::ServerNode;
use anyhow::Result;
use northstar_roster_application::privacy::PrivacyService;
use northstar_roster_postgres::privacy::PostgresPrivacyRepository;
use northstar_runtime::workers::WorkerRegistry;
use northstar_session_application::telemetry::SessionFinalizationTelemetry;
use northstar_telemetry::metrics::Metrics;
use std::sync::Arc;
use uuid::Uuid;

pub(crate) struct SessionCleanupBookkeeping {
    privacy: PrivacyService<PostgresPrivacyRepository>,
    metrics: Arc<Metrics>,
    workers: Arc<WorkerRegistry>,
}

impl ServerNode {
    pub(crate) fn session_cleanup_bookkeeping(&self) -> SessionCleanupBookkeeping {
        SessionCleanupBookkeeping {
            privacy: self.roster.privacy_service.clone(),
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
        SessionFinalizationTelemetry::new(
            &self.metrics.session_finalizations_total,
            &self.metrics.session_finalization_failures_total,
        )
        .started();
    }

    pub(crate) fn finalization_failed(&self, failures: usize) {
        SessionFinalizationTelemetry::new(
            &self.metrics.session_finalizations_total,
            &self.metrics.session_finalization_failures_total,
        )
        .failed(failures);
    }

    pub(crate) fn worker_registry(&self) -> &WorkerRegistry {
        &self.workers
    }
}
