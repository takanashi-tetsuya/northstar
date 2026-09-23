//! One reserved PostgreSQL connection for durable runtime policy and control.

use super::{
    report_runtime_control_health, service_control_applies, AppState, FederationWritePolicy,
    RuntimeControlDiagnostics, RuntimeControlPhase, RuntimeFederationPolicy,
};
use crate::{
    db::runtime_control_repository::PostgresRuntimeControlRepository, s2s::S2sOutboundClearance,
    services::runtime_control::RuntimeControlService, workers::WorkerHeartbeat,
};
use anyhow::Result;
use arc_swap::ArcSwap;
use sqlx::{pool::PoolConnection, Postgres};
use std::{
    sync::{atomic::AtomicBool, Arc, OnceLock, Weak},
    time::Duration,
};
use tokio::sync::Mutex;
use tokio_util::sync::CancellationToken;

pub(super) struct RuntimeControlRefreshContext {
    liveness: Weak<()>,
    connection: Arc<Mutex<Option<PostgresRuntimeControlRepository>>>,
    federation_writes: Arc<FederationWritePolicy>,
    registration_closed: Arc<AtomicBool>,
    registration_dependency_locked: bool,
    federation_rules: Arc<ArcSwap<RuntimeFederationPolicy>>,
    s2s_connections: S2sOutboundClearance,
    service_control_enabled: bool,
    service_shutdown: Arc<OnceLock<CancellationToken>>,
    process_started_at: chrono::DateTime<chrono::Utc>,
}

impl RuntimeControlRefreshContext {
    pub(super) fn from_state(state: &AppState, connection: PoolConnection<Postgres>) -> Self {
        Self {
            liveness: Arc::downgrade(&state.runtime_control_liveness),
            connection: Arc::new(Mutex::new(Some(PostgresRuntimeControlRepository::new(
                connection,
            )))),
            federation_writes: Arc::clone(&state.federation_write_policy),
            registration_closed: Arc::clone(&state.registration_closed),
            registration_dependency_locked: state.config.registration_dependency_locked(),
            federation_rules: Arc::clone(&state.federation_runtime_policy),
            s2s_connections: state.s2s_connection_registry.outbound_clearance(),
            service_control_enabled: state.config.enable_xmpp_service_control,
            service_shutdown: Arc::clone(&state.service_shutdown),
            process_started_at: state.process_started_at,
        }
    }

    pub(super) async fn run(
        &self,
        heartbeat: WorkerHeartbeat,
        diagnostic_cancel: CancellationToken,
        max_silence: Duration,
    ) -> Result<()> {
        let mut diagnostics = RuntimeControlDiagnostics::new(diagnostic_cancel, max_silence);
        let repository = self.connection.lock().await.take().ok_or_else(|| {
            anyhow::anyhow!(
                "runtime-control coordinator was restarted after its reserved connection ended"
            )
        })?;
        // The connection cannot be returned to another worker after this
        // attempt ends. Reads, application and service control stay serialized.
        let mut control = RuntimeControlService::new(repository);
        let mut interval = tokio::time::interval(Duration::from_millis(500));
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        let mut refresh_policy = true;
        let mut acted_service_control = None;
        loop {
            interval.tick().await;
            let Some(_state_alive) = self.liveness.upgrade() else {
                return Ok(());
            };

            let mut first_error = None;
            let mut observed_database = false;
            if refresh_policy {
                observed_database = true;
                match control
                    .policy_snapshot(|phase| diagnostics.database_read(phase))
                    .await
                {
                    Ok(policy) => {
                        diagnostics.enter(RuntimeControlPhase::PolicyApply);
                        let was_island = self.federation_writes.refresh(policy.island_mode).await;
                        self.registration_closed.store(
                            policy.registration_closed || self.registration_dependency_locked,
                            std::sync::atomic::Ordering::Release,
                        );
                        if policy.island_mode && !was_island {
                            self.s2s_connections.clear_for_island_mode();
                        }
                        self.federation_rules
                            .store(Arc::new(RuntimeFederationPolicy {
                                blacklist: policy.blacklist.into_iter().collect(),
                                whitelist: policy.whitelist.into_iter().collect(),
                            }));
                    }
                    Err(error) => {
                        tracing::error!(
                            ?error,
                            "could not refresh durable administration settings"
                        );
                        first_error = Some(error);
                    }
                }
            }

            // The shutdown token is installed after AppState::new returns, so
            // readiness must be read live rather than captured at construction.
            if self.service_control_enabled && self.service_shutdown.get().is_some() {
                observed_database = true;
                diagnostics.enter(RuntimeControlPhase::ServiceControlRead);
                match control.service_control().await {
                    Ok(Some(control))
                        if service_control_applies(self.process_started_at, &control)
                            && acted_service_control != Some(control.generation) =>
                    {
                        acted_service_control = Some(control.generation);
                        tracing::warn!(
                            operation = %control.action,
                            generation = %control.generation,
                            execute_at = %control.execute_at,
                            expires_at = %control.expires_at,
                            "executing durable cluster-wide service control"
                        );
                        if let Some(shutdown) = self.service_shutdown.get() {
                            shutdown.cancel();
                        }
                    }
                    Ok(_) => {}
                    Err(error) => {
                        tracing::error!(
                            ?error,
                            "could not poll durable cluster-wide service control"
                        );
                        if first_error.is_none() {
                            first_error = Some(error);
                        }
                    }
                }
            }

            report_runtime_control_health(&heartbeat, observed_database, first_error);
            diagnostics.reported();
            refresh_policy = !refresh_policy;
        }
    }
}
