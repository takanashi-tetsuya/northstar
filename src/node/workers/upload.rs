//! Upload storage reconciliation worker composition.

use super::super::ServerNode;
use northstar_runtime::workers::{WorkerCriticality, WorkerMode};
use std::sync::Arc;
use tokio_util::sync::CancellationToken;

pub(super) fn start(state: &Arc<ServerNode>, cancel: &CancellationToken) {
    let worker_registry = &state.workers;
    if let Some(upload_context) = upload_maintenance_context(state) {
        let upload_context = Arc::new(upload_context);
        let upload_cancel = cancel.clone();
        worker_registry.supervise(
            "upload-storage-reconciliation",
            // Namespace drift can make a node write or delete objects in the
            // wrong bucket/prefix. The worker treats a proven authority mismatch
            // as fatal; transient inability to query PostgreSQL skips object I/O
            // and reports an unhealthy heartbeat without returning.
            WorkerCriticality::Critical,
            WorkerMode::Continuous,
            // One provider operation may legitimately occupy 180 seconds. Silence
            // detection therefore includes a margin and cannot kill a healthy
            // critical worker mid-operation.
            Some(std::time::Duration::from_secs(600)),
            cancel.clone(),
            move |heartbeat| {
                let upload_context = Arc::clone(&upload_context);
                let upload_cancel = upload_cancel.clone();
                async move {
                    northstar_upload_application::worker::serve(
                        upload_context,
                        upload_cancel,
                        heartbeat,
                    )
                    .await
                }
            },
        );
    }
}

fn upload_maintenance_context(
    state: &ServerNode,
) -> Option<
    northstar_upload_application::worker::UploadMaintenanceContext<
        northstar_upload_postgres::maintenance::PostgresUploadMaintenanceRepository,
    >,
> {
    Some(
        northstar_upload_application::worker::UploadMaintenanceContext::new(
            northstar_upload_postgres::maintenance::PostgresUploadMaintenanceRepository::new(
                state.upload.storage_pool.as_ref()?.clone(),
            ),
            Arc::clone(state.upload.store.as_ref()?),
            northstar_upload_application::worker::UploadMaintenancePolicy {
                max_pending_jobs: state.config.upload_storage_max_pending_jobs,
                max_retained_files: state.config.upload_storage_max_retained_files,
                max_retained_bytes: state.config.upload_storage_max_retained_bytes,
                retention_seconds: state.config.upload_retention_seconds,
                namespace_sha256: state.upload.namespace_sha256,
                generation: state.upload.authority_generation,
            },
            Arc::clone(&state.upload.safety_gate),
            Arc::clone(&state.upload.startup_audits),
            Arc::clone(&state.metrics),
        ),
    )
}
