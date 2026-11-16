//! Runtime control diagnostics and health reporting.

use crate::node::*;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::node) enum RuntimeControlPhase {
    Idle,
    SnapshotRead,
    PolicyApply,
    ServiceControlRead,
}

impl RuntimeControlPhase {
    pub(in crate::node) fn label(self) -> &'static str {
        match self {
            Self::Idle => "idle",
            Self::SnapshotRead => "snapshot-read",
            Self::PolicyApply => "policy-apply",
            Self::ServiceControlRead => "service-control-read",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(in crate::node) struct RuntimeControlStall {
    pub(in crate::node) phase: RuntimeControlPhase,
    pub(in crate::node) phase_elapsed: Duration,
    pub(in crate::node) heartbeat_elapsed: Duration,
}

/// Observation only: a stalled attempt is dropped before its supervisor sets
/// the root cancellation token. Normal root shutdown must not produce a warning.
pub(in crate::node) struct RuntimeControlDiagnostics {
    pub(in crate::node) phase: RuntimeControlPhase,
    pub(in crate::node) phase_started: tokio::time::Instant,
    pub(in crate::node) last_reported: tokio::time::Instant,
    pub(in crate::node) max_silence: Duration,
    pub(in crate::node) root_cancel: CancellationToken,
    #[cfg(test)]
    pub(in crate::node) captured: Option<Arc<std::sync::Mutex<Vec<RuntimeControlStall>>>>,
}

impl RuntimeControlDiagnostics {
    pub(in crate::node) fn new(root_cancel: CancellationToken, max_silence: Duration) -> Self {
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

    pub(in crate::node) fn enter(&mut self, phase: RuntimeControlPhase) {
        self.phase = phase;
        self.phase_started = tokio::time::Instant::now();
    }

    pub(in crate::node) fn database_read(
        &mut self,
        phase: northstar_operations_postgres::admin_commands::RuntimeControlReadPhase,
    ) {
        self.enter(match phase {
            northstar_operations_postgres::admin_commands::RuntimeControlReadPhase::Snapshot => {
                RuntimeControlPhase::SnapshotRead
            }
        });
    }

    /// Call only after the existing heartbeat report; this changes no health.
    pub(in crate::node) fn reported(&mut self) {
        let now = tokio::time::Instant::now();
        self.last_reported = now;
        self.phase = RuntimeControlPhase::Idle;
        self.phase_started = now;
    }

    pub(in crate::node) fn stalled(&self) -> Option<RuntimeControlStall> {
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

pub(in crate::node) fn report_runtime_control_health(
    heartbeat: &northstar_runtime::workers::WorkerHeartbeat,
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
