//! Runtime control database connection: startup admission, pool options, diagnostics and health reporting.

use super::*;

/// Durable runtime policy is a safety boundary, not ordinary background work.
/// Reserve one runtime-role connection so traffic workers cannot prevent the
/// process from observing committed administration settings under a saturated
/// main pool. XEP-0133 uses the same control-plane capability when enabled,
/// but does not own the capability itself.
// This is an initial connection/SCRAM handshake budget, not the runtime
// policy polling interval. Repeatedly cancelling half-second handshakes under
// a cold-start cohort can prevent any of them from reaching authentication.
pub(super) const RUNTIME_CONTROL_STARTUP_CONNECT_ATTEMPT_BUDGET: Duration = Duration::from_secs(3);
/// A process has no traffic listeners while this bounded admission window is
/// active.  It exists specifically to de-correlate a cold-start cohort from a
/// short, per-attempt pool deadline; it is not a runtime worker retry policy.
pub(super) const RUNTIME_CONTROL_STARTUP_RETRY_BUDGET: Duration = Duration::from_secs(15);
pub(super) const RUNTIME_CONTROL_STARTUP_RETRY_MAX_DELAY: Duration = Duration::from_millis(500);

pub(super) fn runtime_control_pool_options(
    config: &Config,
    attempt_budget: Duration,
) -> PgPoolOptions {
    let options = PgPoolOptions::new()
        .max_connections(SERVICE_CONTROL_POOL_MAX_CONNECTIONS)
        .min_connections(SERVICE_CONTROL_POOL_MAX_CONNECTIONS)
        .acquire_timeout(attempt_budget);
    if config.database_allow_unsafe_role_for_development {
        options
    } else {
        db::pin_public_application_schema(options)
    }
}

pub(super) fn runtime_control_connect_options(
    database_url: &str,
) -> Result<PgConnectOptions, sqlx::Error> {
    Ok(database_url
        .parse::<PgConnectOptions>()?
        .application_name("northstar-runtime-control"))
}

pub(super) fn runtime_control_startup_retry_delay(attempt: u32, process_id: u32) -> Duration {
    let exponent = attempt.saturating_sub(1).min(5);
    let exponential_millis = 10_u64.saturating_mul(1_u64 << exponent);
    // A process-local deterministic spread avoids another synchronized
    // connection wave without introducing shared startup state or a random
    // source into the authority boundary.
    let jitter_millis = u64::from(process_id)
        .wrapping_mul(0x9e37_79b9)
        .wrapping_add(u64::from(attempt).wrapping_mul(0x85eb_ca6b))
        % 97;
    Duration::from_millis(
        exponential_millis
            .saturating_add(jitter_millis)
            .min(RUNTIME_CONTROL_STARTUP_RETRY_MAX_DELAY.as_millis() as u64),
    )
}

pub(super) async fn runtime_control_startup_connect<T, Connect, ConnectFuture>(
    deadline: tokio::time::Instant,
    connect: Connect,
) -> anyhow::Result<T>
where
    Connect: FnMut(Duration) -> ConnectFuture,
    ConnectFuture: std::future::Future<Output = Result<T, sqlx::Error>>,
{
    startup_database_connect(
        deadline,
        RUNTIME_CONTROL_STARTUP_CONNECT_ATTEMPT_BUDGET,
        "runtime-control",
        connect,
    )
    .await
}

pub(super) async fn startup_database_connect<T, Connect, ConnectFuture>(
    deadline: tokio::time::Instant,
    attempt_limit: Duration,
    pool_name: &'static str,
    mut connect: Connect,
) -> anyhow::Result<T>
where
    Connect: FnMut(Duration) -> ConnectFuture,
    ConnectFuture: std::future::Future<Output = Result<T, sqlx::Error>>,
{
    let mut attempts = 0_u32;
    let admission = tokio::time::timeout_at(deadline, async {
        loop {
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            if remaining.is_zero() {
                return Err(sqlx::Error::PoolTimedOut);
            }
            let attempt_budget = remaining.min(attempt_limit);
            attempts = attempts.saturating_add(1);
            let result = tokio::time::timeout(attempt_budget, connect(attempt_budget))
                .await
                .unwrap_or(Err(sqlx::Error::PoolTimedOut));
            match result {
                Ok(pool) => return Ok(pool),
                Err(sqlx::Error::PoolTimedOut) => {
                    let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
                    let delay = runtime_control_startup_retry_delay(attempts, std::process::id())
                        .min(remaining);
                    tokio::time::sleep(delay).await;
                }
                Err(error) => return Err(error),
            }
        }
    })
    .await
    .unwrap_or(Err(sqlx::Error::PoolTimedOut));
    admission.with_context(|| {
        format!("could not create isolated {pool_name} database pool after {attempts} bounded startup admission attempts")
    })
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum RuntimeControlPhase {
    Idle,
    SnapshotRead,
    PolicyApply,
    ServiceControlRead,
}

impl RuntimeControlPhase {
    pub(super) fn label(self) -> &'static str {
        match self {
            Self::Idle => "idle",
            Self::SnapshotRead => "snapshot-read",
            Self::PolicyApply => "policy-apply",
            Self::ServiceControlRead => "service-control-read",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct RuntimeControlStall {
    pub(super) phase: RuntimeControlPhase,
    pub(super) phase_elapsed: Duration,
    pub(super) heartbeat_elapsed: Duration,
}

/// Observation only: a stalled attempt is dropped before its supervisor sets
/// the root cancellation token. Normal root shutdown must not produce a warning.
pub(super) struct RuntimeControlDiagnostics {
    pub(super) phase: RuntimeControlPhase,
    pub(super) phase_started: tokio::time::Instant,
    pub(super) last_reported: tokio::time::Instant,
    pub(super) max_silence: Duration,
    pub(super) root_cancel: CancellationToken,
    #[cfg(test)]
    pub(super) captured: Option<Arc<std::sync::Mutex<Vec<RuntimeControlStall>>>>,
}

impl RuntimeControlDiagnostics {
    pub(super) fn new(root_cancel: CancellationToken, max_silence: Duration) -> Self {
        let now = tokio::time::Instant::now();
        Self {
            phase: RuntimeControlPhase::Idle,
            phase_started: now,
            last_reported: now,
            max_silence,
            root_cancel,
            #[cfg(test)]
            captured: None,
        }
    }

    pub(super) fn enter(&mut self, phase: RuntimeControlPhase) {
        self.phase = phase;
        self.phase_started = tokio::time::Instant::now();
    }

    pub(super) fn database_read(&mut self, phase: db::RuntimeControlReadPhase) {
        self.enter(match phase {
            db::RuntimeControlReadPhase::Snapshot => RuntimeControlPhase::SnapshotRead,
        });
    }

    /// Call only after the existing heartbeat report; this changes no health.
    pub(super) fn reported(&mut self) {
        let now = tokio::time::Instant::now();
        self.last_reported = now;
        self.phase = RuntimeControlPhase::Idle;
        self.phase_started = now;
    }

    pub(super) fn stalled(&self) -> Option<RuntimeControlStall> {
        if self.root_cancel.is_cancelled() {
            return None;
        }
        let now = tokio::time::Instant::now();
        let heartbeat_elapsed = now.saturating_duration_since(self.last_reported);
        (heartbeat_elapsed > self.max_silence).then(|| RuntimeControlStall {
            phase: self.phase,
            phase_elapsed: now.saturating_duration_since(self.phase_started),
            heartbeat_elapsed,
        })
    }
}

impl Drop for RuntimeControlDiagnostics {
    fn drop(&mut self) {
        let Some(stall) = self.stalled() else {
            return;
        };
        tracing::warn!(
            phase = stall.phase.label(),
            phase_elapsed_ms = stall.phase_elapsed.as_millis() as u64,
            heartbeat_elapsed_ms = stall.heartbeat_elapsed.as_millis() as u64,
            "runtime-control attempt dropped after heartbeat silence"
        );
        #[cfg(test)]
        if let Some(captured) = &self.captured {
            captured.lock().unwrap().push(stall);
        }
    }
}

pub(super) fn report_runtime_control_health(
    heartbeat: &crate::workers::WorkerHeartbeat,
    observed_database: bool,
    error: Option<anyhow::Error>,
) {
    if let Some(error) = error {
        heartbeat.error(error);
    } else if observed_database {
        heartbeat.ok();
    } else {
        // With XEP-0133 control disabled, alternate ticks perform no query.
        // They prove scheduler liveness only, never database/ownership health.
        // Clearing an error here would let a dead reserved connection alternate
        // error/ok forever, concealing loss of the standalone retention lock.
        heartbeat.pulse();
    }
}

/// Establish the one process-owned control-plane connection before the
/// traffic pool or any startup reconciliation can take database capacity.
///
/// Keeping this at the application boundary makes the ordering explicit:
/// `main` owns startup sequencing, while [`AppState`] only owns the connection
/// after startup transfers it into the coordinated runtime worker.  The
/// connection remains separate from traffic for its whole lifetime.
pub(crate) async fn reserve_runtime_control_connection(
    config: &Config,
) -> anyhow::Result<PoolConnection<Postgres>> {
    let deadline = tokio::time::Instant::now() + RUNTIME_CONTROL_STARTUP_RETRY_BUDGET;
    let connect_options = runtime_control_connect_options(&config.database_url)?;
    let runtime_control_pool = runtime_control_startup_connect(deadline, |attempt_budget| {
        runtime_control_pool_options(config, attempt_budget).connect_with(connect_options.clone())
    })
    .await?;
    // Attestation and final ownership transfer share the same absolute startup
    // deadline. A completed handshake alone never authorizes serving traffic.
    tokio::time::timeout_at(deadline, async {
        if config.database_allow_unsafe_role_for_development {
            crate::db::attest_development_database_is_loopback(&runtime_control_pool).await?;
        } else {
            crate::db::attest_runtime_role(&runtime_control_pool).await?;
        }
        runtime_control_pool
            .acquire()
            .await
            .context("could not reserve the runtime-control database connection")
    })
    .await
    .context(
        "runtime-control role attestation/reservation exceeded its startup admission deadline",
    )?
}
