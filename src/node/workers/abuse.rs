//! Fail-closed anti-abuse deployment authority guard.

use super::super::ServerNode;
use anyhow::Context;
use northstar_runtime::workers::{WorkerCriticality, WorkerMode};
use std::sync::Arc;
use tokio_util::sync::CancellationToken;

const ABUSE_KEY_AUTHORITY_POLL_INTERVAL: std::time::Duration = std::time::Duration::from_secs(5);
const ABUSE_KEY_AUTHORITY_QUERY_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(3);

pub(super) fn start(state: &Arc<ServerNode>, cancel: &CancellationToken) {
    let worker_registry = &state.workers;
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
                    let mut interval = tokio::time::interval(ABUSE_KEY_AUTHORITY_POLL_INTERVAL);
                    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
                    loop {
                        tokio::select! {
                            _ = authority_cancel.cancelled() => return Ok(()),
                            _ = interval.tick() => {
                                let validation = tokio::time::timeout(
                                    ABUSE_KEY_AUTHORITY_QUERY_TIMEOUT,
                                    authority_probe.validate(&authority_identity),
                                ).await;
                                match validation {
                                    Ok(Ok(())) => heartbeat.ok(),
                                    Ok(Err(error)) => {
                                        heartbeat.error(&error);
                                        tracing::error!(
                                            ?error,
                                            poll_seconds = ABUSE_KEY_AUTHORITY_POLL_INTERVAL.as_secs(),
                                            "anti-abuse key authority diverged; cancelling every listener"
                                        );
                                        return Err(error).context(
                                            "PostgreSQL rejected this process's anti-abuse key generation",
                                        );
                                    }
                                    Err(error) => {
                                        heartbeat.error(&error);
                                        tracing::error!(
                                            ?error,
                                            query_timeout_seconds = ABUSE_KEY_AUTHORITY_QUERY_TIMEOUT.as_secs(),
                                            "anti-abuse key authority could not be verified in time; cancelling every listener"
                                        );
                                        anyhow::bail!(
                                            "PostgreSQL anti-abuse key authority validation exceeded the {} second fail-closed timeout",
                                            ABUSE_KEY_AUTHORITY_QUERY_TIMEOUT.as_secs(),
                                        );
                                    }
                                }
                            }
                        }
                    }
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
