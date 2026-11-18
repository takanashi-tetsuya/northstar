//! Process lifetime state built once by the composition root.

use northstar_runtime::workers::WorkerRegistry;
use std::sync::{Arc, OnceLock};
use std::time::Instant;
use tokio_util::sync::CancellationToken;

pub(in crate::node) struct RuntimeModule {
    started_at: Instant,
    process_started_at: northstar_time::DateTime<northstar_time::Utc>,
    service_shutdown: Arc<OnceLock<CancellationToken>>,
    runtime_control_liveness: Arc<()>,
    workers: Arc<WorkerRegistry>,
}

impl RuntimeModule {
    pub(in crate::node) fn new(
        started_at: Instant,
        process_started_at: northstar_time::DateTime<northstar_time::Utc>,
        service_shutdown: Arc<OnceLock<CancellationToken>>,
        runtime_control_liveness: Arc<()>,
        workers: Arc<WorkerRegistry>,
    ) -> Self {
        Self {
            started_at,
            process_started_at,
            service_shutdown,
            runtime_control_liveness,
            workers,
        }
    }

    pub(in crate::node) fn started_at(&self) -> Instant {
        self.started_at
    }

    pub(in crate::node) fn process_started_at(
        &self,
    ) -> northstar_time::DateTime<northstar_time::Utc> {
        self.process_started_at
    }

    pub(in crate::node) fn service_shutdown(&self) -> &Arc<OnceLock<CancellationToken>> {
        &self.service_shutdown
    }

    pub(in crate::node) fn control_liveness(&self) -> &Arc<()> {
        &self.runtime_control_liveness
    }

    pub(in crate::node) fn workers(&self) -> &Arc<WorkerRegistry> {
        &self.workers
    }

    pub(in crate::node) fn install_service_shutdown(
        &self,
        cancel: CancellationToken,
    ) -> anyhow::Result<()> {
        self.service_shutdown
            .set(cancel)
            .map_err(|_| anyhow::anyhow!("service shutdown control was already installed"))?;
        Ok(())
    }

    pub(in crate::node) fn service_control_available(&self, enabled: bool) -> bool {
        enabled && self.service_shutdown.get().is_some()
    }
}
