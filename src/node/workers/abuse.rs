//! Construction and registration for the anti-abuse deployment authority guard.

use super::super::ServerNode;
use northstar_operations_application::abuse_authority_worker::{
    serve_abuse_key_authority, ABUSE_KEY_AUTHORITY_POLL_INTERVAL, ABUSE_KEY_AUTHORITY_QUERY_TIMEOUT,
};
use northstar_runtime::workers::{WorkerCriticality, WorkerMode};
use std::sync::Arc;
use tokio_util::sync::CancellationToken;

pub(super) fn start(state: &Arc<ServerNode>, cancel: &CancellationToken) {
    let worker_registry = state.runtime.workers();
    if let Some(authority_identity) = state.abuse.abuse_key_deployment.clone() {
        tracing::info!(
            poll_seconds = ABUSE_KEY_AUTHORITY_POLL_INTERVAL.as_secs(),
            query_timeout_seconds = ABUSE_KEY_AUTHORITY_QUERY_TIMEOUT.as_secs(),
            "enabled fail-closed PostgreSQL anti-abuse key authority guard"
        );
        let authority_probe = abuse_key_authority_probe(state);
        let authority_cancel = cancel.clone();
        worker_registry.supervise(
            "abuse-key-deployment-authority",
            WorkerCriticality::Critical,
            WorkerMode::Continuous,
            Some(ABUSE_KEY_AUTHORITY_POLL_INTERVAL.saturating_mul(2)),
            cancel.clone(),
            move |heartbeat| {
                let authority_probe = authority_probe.clone();
                let authority_identity = authority_identity.clone();
                let authority_cancel = authority_cancel.clone();
                async move {
                    serve_abuse_key_authority(
                        &authority_probe,
                        authority_identity,
                        authority_cancel,
                        heartbeat,
                    )
                    .await
                }
            },
        );
    }
}

fn abuse_key_authority_probe(
    state: &ServerNode,
) -> northstar_operations_application::readiness::AbuseKeyAuthorityProbe<
    northstar_workflows::readiness_repository::PostgresReadinessRepository,
> {
    state
        .operations
        .readiness_service
        .abuse_key_authority_probe()
}
