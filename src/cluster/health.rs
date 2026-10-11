//! Cluster health state machine: admission, failure recording, reconciliation, readiness and metrics.

use super::*;

/// Admission decisions share the live health state without Redis or publication authority.
#[derive(Clone)]
pub(crate) struct ClusterAdmission {
    pub(super) health: Arc<ClusterHealth>,
    pub(super) direct_authority: Option<ClusterReadinessAuthority>,
}
impl ClusterAdmission {
    pub(crate) fn is_enabled(&self) -> bool {
        self.direct_authority.is_some()
    }

    pub(crate) fn admit(&self, operation: ClusterOperation) -> Result<()> {
        admit_health(&self.health, operation)
    }

    pub(crate) fn direct_mode(&self) -> DirectPostCommitMode {
        match self.health.effective_state() {
            CLUSTER_DISABLED | CLUSTER_HEALTHY => DirectPostCommitMode::Live,
            CLUSTER_DURABLE_DIRECT_ONLY => DirectPostCommitMode::SpoolOnly,
            _ => DirectPostCommitMode::Rejected,
        }
    }

    /// The identity comes from this process's signing configuration and claimed
    /// instance, never from the peer cache or a previous readiness observation.
    pub(crate) fn durable_direct_authority(&self) -> Result<Option<&ClusterReadinessAuthority>> {
        self.admit(ClusterOperation::DurableDirect)?;
        if self.health.effective_state() == CLUSTER_DISABLED {
            return Ok(None);
        }
        let authority = self
            .direct_authority
            .as_ref()
            .context("cluster durable direct admission has no claimed process authority")?;
        anyhow::ensure!(
            authority.instance_epoch >= 1,
            "cluster process instance was not claimed"
        );
        Ok(Some(authority))
    }

    pub(crate) fn check_direct_eligibility(
        &self,
        eligibility: DirectSpoolEligibility,
    ) -> Result<Option<&ClusterReadinessAuthority>> {
        match self.direct_mode() {
            DirectPostCommitMode::Rejected => {
                anyhow::bail!("cluster control plane cannot admit direct messages")
            }
            DirectPostCommitMode::SpoolOnly if eligibility == DirectSpoolEligibility::LiveOnly => {
                anyhow::bail!("this direct-message operation cannot be durably spooled while cluster control is degraded")
            }
            DirectPostCommitMode::Live | DirectPostCommitMode::SpoolOnly => {}
        }
        // Re-read health while retrieving this process's exact identity. The
        // caller repeats this check with both PG rows locked near commit.
        self.durable_direct_authority()
    }

    /// Keep the final health decision ordered with the acknowledged database
    /// commit. The returned turn never covers routing or other live effects.
    pub(crate) fn begin_direct_commit_turn(
        &self,
        eligibility: DirectSpoolEligibility,
    ) -> Result<(DirectCommitTurn, Option<&ClusterReadinessAuthority>)> {
        let mut gate = self
            .health
            .direct_commit_gate
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        anyhow::ensure!(
            gate.pending.is_none(),
            "cluster health transition is pending"
        );
        let state = self.health.state.load(Ordering::Acquire);
        let mode = match state {
            CLUSTER_DISABLED | CLUSTER_HEALTHY => DirectPostCommitMode::Live,
            CLUSTER_DURABLE_DIRECT_ONLY if eligibility == DirectSpoolEligibility::Eligible => {
                DirectPostCommitMode::SpoolOnly
            }
            CLUSTER_DURABLE_DIRECT_ONLY => anyhow::bail!(
                "this direct-message operation cannot be durably spooled while cluster control is degraded"
            ),
            _ => anyhow::bail!("cluster control plane cannot admit direct messages"),
        };
        let authority = if state == CLUSTER_DISABLED {
            None
        } else {
            let authority = self
                .direct_authority
                .as_ref()
                .context("cluster durable direct admission has no claimed process authority")?;
            anyhow::ensure!(
                authority.instance_epoch >= 1,
                "cluster process instance was not claimed"
            );
            Some(authority)
        };
        gate.active = gate
            .active
            .checked_add(1)
            .context("too many direct commit turns")?;
        let turn = DirectCommitTurn {
            health: Arc::clone(&self.health),
            admitted_mode: mode,
            transition_epoch: gate.transition_epoch,
            finished: false,
        };
        Ok((turn, authority))
    }
}

pub(crate) struct DirectCommitTurn {
    pub(super) health: Arc<ClusterHealth>,
    pub(super) admitted_mode: DirectPostCommitMode,
    pub(super) transition_epoch: u64,
    pub(super) finished: bool,
}

impl DirectCommitTurn {
    pub(crate) fn admitted_mode(&self) -> DirectPostCommitMode {
        self.admitted_mode
    }

    /// A successful commit can only lose live effects; it cannot become a
    /// postcommit rejection. Capture the decision under the transition gate.
    pub(crate) fn finish(mut self) -> DirectPostCommitMode {
        let mut gate = self
            .health
            .direct_commit_gate
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let live = self.admitted_mode == DirectPostCommitMode::Live
            && gate.transition_epoch == self.transition_epoch
            && gate.pending.is_none()
            && matches!(
                self.health.state.load(Ordering::Acquire),
                CLUSTER_DISABLED | CLUSTER_HEALTHY
            );
        self.health.release_direct_commit_turn(&mut gate);
        self.finished = true;
        if live {
            DirectPostCommitMode::Live
        } else {
            DirectPostCommitMode::SpoolOnly
        }
    }
}

impl Drop for DirectCommitTurn {
    fn drop(&mut self) {
        if !self.finished {
            let mut gate = self
                .health
                .direct_commit_gate
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            self.health.release_direct_commit_turn(&mut gate);
        }
    }
}

pub(super) fn admit_health(health: &ClusterHealth, operation: ClusterOperation) -> Result<()> {
    let state = health.effective_state();
    if operation_allowed(state, operation) {
        return Ok(());
    }
    match state {
        CLUSTER_RECONCILING => anyhow::bail!("cluster control plane is reconciling"),
        CLUSTER_DURABLE_DIRECT_ONLY => anyhow::bail!(
            "cluster control plane is degraded; only PostgreSQL-spooled direct messages are accepted"
        ),
        CLUSTER_FAIL_CLOSED => anyhow::bail!("cluster control plane is unavailable"),
        CLUSTER_SHUTDOWN_REQUIRED => anyhow::bail!("cluster shutdown is required"),
        _ => anyhow::bail!("cluster control plane is in an invalid state"),
    }
}

pub(super) fn record_cluster_failure(
    health: &ClusterHealth,
    listener_rotation: &tokio::sync::Notify,
    enabled: bool,
    policy: Option<crate::cluster_security::ClusterFailurePolicy>,
    class: ClusterFailureClass,
    error: &anyhow::Error,
) {
    if !enabled {
        return;
    }
    // Serialize the failure fence with complete_reconciliation's generation
    // check and healthy commit, so an older completion cannot hide failure.
    let mut since = health
        .failure_since
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    // PostgreSQL owns the key and process-instance fences required even by
    // durable-direct fallback. Losing that authority cannot enter a mode
    // which still accepts new spool rows while the supervisor is waking up.
    let failed_state = if matches!(class, ClusterFailureClass::PostgreSqlAuthority) {
        CLUSTER_SHUTDOWN_REQUIRED
    } else {
        match policy {
            Some(crate::cluster_security::ClusterFailurePolicy::DurableDirectOnly) => {
                CLUSTER_DURABLE_DIRECT_ONLY
            }
            _ => CLUSTER_FAIL_CLOSED,
        }
    };
    let mut gate = health
        .direct_commit_gate
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    if gate.pending == Some(CLUSTER_SHUTDOWN_REQUIRED)
        || health.state.load(Ordering::Acquire) == CLUSTER_SHUTDOWN_REQUIRED
    {
        return;
    }
    let next_listener = health
        .listener_generation
        .load(Ordering::Acquire)
        .saturating_add(1);
    health
        .required_listener_generation
        .fetch_max(next_listener, Ordering::AcqRel);
    health
        .listener_rotation_epoch
        .fetch_add(1, Ordering::AcqRel);
    if since.is_none() {
        *since = Some(Instant::now());
    }
    if health.request_state_locked(&mut gate, failed_state) {
        health.degraded_transitions.fetch_add(1, Ordering::Relaxed);
    }
    drop(gate);
    listener_rotation.notify_waiters();
    drop(since);
    tracing::error!(
        ?error,
        ?class,
        ?policy,
        "cluster control plane entered a fenced failure state"
    );
}

pub(super) fn require_cluster_shutdown(health: &ClusterHealth, enabled: bool) {
    if enabled {
        let _transition = health
            .failure_since
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        health.request_state(CLUSTER_SHUTDOWN_REQUIRED);
    }
}

pub(super) fn note_incompatible_peer_version(
    health: &ClusterHealth,
    node_id: &str,
    observed: Option<&str>,
) {
    if health
        .peer_versions_compatible
        .swap(false, Ordering::AcqRel)
    {
        health
            .incompatible_peer_versions
            .fetch_add(1, Ordering::Relaxed);
    }
    tracing::error!(
        %node_id,
        observed_version = observed.unwrap_or("missing"),
        required_version = NODE_PROTOCOL_VERSION,
        "live cluster peer uses an incompatible application protocol; readiness is fail-closed"
    );
}

pub(super) fn note_cluster_authentication_failure(health: &ClusterHealth, error: &anyhow::Error) {
    health
        .authentication_failures
        .fetch_add(1, Ordering::Relaxed);
    tracing::warn!(?error, "rejected unauthenticated cluster protocol envelope");
}

pub(super) fn begin_cluster_reconciliation(
    health: &ClusterHealth,
    enabled: bool,
) -> Result<Option<u64>> {
    let _transition = health
        .failure_since
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    anyhow::ensure!(
        health.effective_state() != CLUSTER_SHUTDOWN_REQUIRED,
        "cluster shutdown is required; reconciliation cannot begin"
    );
    if enabled {
        let mut gate = health
            .direct_commit_gate
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        if gate.pending.is_some() {
            return Ok(None);
        }
        if gate.active != 0 {
            gate.pending = Some(CLUSTER_RECONCILING);
            gate.transition_epoch = gate.transition_epoch.wrapping_add(1);
            return Ok(None);
        }
        health.state.store(CLUSTER_RECONCILING, Ordering::Release);
        gate.transition_epoch = gate.transition_epoch.wrapping_add(1);
    }
    Ok(Some(health.listener_rotation_epoch.load(Ordering::Acquire)))
}

pub(super) fn complete_cluster_reconciliation(
    health: &ClusterHealth,
    rotation_epoch: u64,
) -> Result<ReconciliationOutcome> {
    let mut since = health
        .failure_since
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    complete_cluster_reconciliation_locked(health, &mut since, rotation_epoch)
}

pub(super) fn confirm_listener_generation(
    health: &ClusterHealth,
    generation: u64,
    rotation_epoch: u64,
) -> Result<()> {
    let mut since = health
        .failure_since
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    anyhow::ensure!(
        health.effective_state() != CLUSTER_SHUTDOWN_REQUIRED
            && !health.transition_pending()
            && health.listener_rotation_epoch.load(Ordering::Acquire) == rotation_epoch
            && generation == health.next_listener_generation()
            && !health.listener_requires_rotation(generation),
        "Redis PubSub listener rotation was requested before self-loop confirmation"
    );
    health
        .listener_generation
        .store(generation, Ordering::Release);
    // Only the initial self-loop may complete startup reconciliation. Later
    // recoveries still require the full maintenance pass.
    if health.effective_state() == CLUSTER_RECONCILING
        && health.degraded_transitions.load(Ordering::Acquire) == 0
    {
        let outcome = complete_cluster_reconciliation_locked(health, &mut since, rotation_epoch)?;
        anyhow::ensure!(
            outcome == ReconciliationOutcome::Complete,
            "confirmed initial listener did not complete startup reconciliation"
        );
    }
    Ok(())
}

pub(super) fn complete_cluster_reconciliation_locked(
    health: &ClusterHealth,
    since: &mut std::sync::MutexGuard<'_, Option<Instant>>,
    rotation_epoch: u64,
) -> Result<ReconciliationOutcome> {
    anyhow::ensure!(
        health.effective_state() != CLUSTER_SHUTDOWN_REQUIRED,
        "cluster shutdown is required; reconciliation cannot restore readiness"
    );
    anyhow::ensure!(
        health.listener_rotation_epoch.load(Ordering::Acquire) == rotation_epoch,
        "cluster control-plane failure invalidated this reconciliation attempt"
    );
    {
        let mut gate = health
            .direct_commit_gate
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        if gate.active != 0 || gate.pending.is_some() {
            return Ok(ReconciliationOutcome::DeferredForDirectCommits);
        }
        // Keep the gate through publication so no direct turn can enter after
        // the idle check but before health becomes live.
        if health.state.load(Ordering::Acquire) == CLUSTER_RECONCILING
            && health.listener_generation.load(Ordering::Acquire) == 0
            && health.required_listener_generation.load(Ordering::Acquire) == 1
            && rotation_epoch == 0
            && health.degraded_transitions.load(Ordering::Acquire) == 0
        {
            return Ok(ReconciliationOutcome::WaitingForInitialListener);
        }
        anyhow::ensure!(
            health.listener_generation.load(Ordering::Acquire)
                >= health.required_listener_generation.load(Ordering::Acquire),
            "cluster PubSub listener generation has not been re-established"
        );
        health.state.store(CLUSTER_HEALTHY, Ordering::Release);
        gate.transition_epoch = gate.transition_epoch.wrapping_add(1);
    }
    **since = None;
    Ok(ReconciliationOutcome::Complete)
}

pub(super) fn cluster_readiness_error(health: &ClusterHealth) -> Option<String> {
    if !health.peer_versions_compatible.load(Ordering::Acquire) {
        return Some("a live cluster peer uses an incompatible application protocol".into());
    }
    if health.transition_pending() {
        return Some("cluster health transition is waiting for direct-message commits".into());
    }
    match health.effective_state() {
        CLUSTER_DISABLED | CLUSTER_HEALTHY => None,
        CLUSTER_RECONCILING => Some("cluster ownership reconciliation is incomplete".into()),
        CLUSTER_DURABLE_DIRECT_ONLY => {
            Some("cluster is degraded to PostgreSQL-spooled direct messages".into())
        }
        CLUSTER_FAIL_CLOSED => Some("cluster control plane is fail-closed".into()),
        CLUSTER_SHUTDOWN_REQUIRED => Some("cluster shutdown is required".into()),
        _ => Some("cluster control plane has an invalid state".into()),
    }
}

#[derive(Clone, Copy, Debug)]
pub(super) enum ClusterFailureClass {
    RedisCommand,
    PubSub,
    PostgreSqlAuthority,
}

pub(super) const CLUSTER_DISABLED: u8 = 0;
pub(super) const CLUSTER_RECONCILING: u8 = 1;
pub(super) const CLUSTER_HEALTHY: u8 = 2;
pub(super) const CLUSTER_FAIL_CLOSED: u8 = 3;
pub(super) const CLUSTER_DURABLE_DIRECT_ONLY: u8 = 4;
pub(super) const CLUSTER_SHUTDOWN_REQUIRED: u8 = 5;

#[derive(Debug, Eq, PartialEq)]
pub(super) enum ReconciliationOutcome {
    Complete,
    WaitingForInitialListener,
    DeferredForDirectCommits,
}

pub(super) struct ClusterHealth {
    pub(super) state: AtomicU8,
    pub(super) direct_commit_gate: Mutex<DirectCommitGate>,
    pub(super) recovery_replay_plan: Mutex<Option<RecoveryReplayPlan>>,
    pub(super) recovery_wake_sequence: AtomicU64,
    pub(super) listener_generation: AtomicU64,
    pub(super) required_listener_generation: AtomicU64,
    pub(super) listener_rotation_epoch: AtomicU64,
    pub(super) failure_since: Mutex<Option<Instant>>,
    pub(super) authentication_failures: AtomicU64,
    pub(super) replay_rejections: AtomicU64,
    pub(super) degraded_transitions: AtomicU64,
    pub(super) peer_versions_compatible: AtomicBool,
    pub(super) incompatible_peer_versions: AtomicU64,
}

#[derive(Default)]
pub(super) struct DirectCommitGate {
    pub(super) active: usize,
    pub(super) pending: Option<u8>,
    pub(super) transition_epoch: u64,
}

impl ClusterHealth {
    pub(super) fn effective_state(&self) -> u8 {
        let gate = self
            .direct_commit_gate
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        match gate.pending {
            Some(CLUSTER_SHUTDOWN_REQUIRED) => CLUSTER_SHUTDOWN_REQUIRED,
            Some(_) => CLUSTER_RECONCILING,
            None => self.state.load(Ordering::Acquire),
        }
    }

    pub(super) fn transition_pending(&self) -> bool {
        self.direct_commit_gate
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .pending
            .is_some()
    }

    /// Called under failure_since for lifecycle transitions. No database or
    /// network wait occurs while this mutex is held.
    pub(super) fn request_state(&self, requested: u8) -> bool {
        let mut gate = self
            .direct_commit_gate
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        self.request_state_locked(&mut gate, requested)
    }

    pub(super) fn request_state_locked(&self, gate: &mut DirectCommitGate, requested: u8) -> bool {
        let previous = gate
            .pending
            .unwrap_or_else(|| self.state.load(Ordering::Acquire));
        if previous == CLUSTER_SHUTDOWN_REQUIRED {
            return false;
        }
        if previous == CLUSTER_FAIL_CLOSED && requested == CLUSTER_DURABLE_DIRECT_ONLY {
            return false;
        }
        if gate.active == 0 {
            self.state.store(requested, Ordering::Release);
        } else {
            gate.pending = Some(requested);
        }
        gate.transition_epoch = gate.transition_epoch.wrapping_add(1);
        previous != requested
    }

    pub(super) fn release_direct_commit_turn(&self, gate: &mut DirectCommitGate) {
        debug_assert!(gate.active > 0);
        gate.active -= 1;
        if gate.active == 0 {
            if let Some(state) = gate.pending.take() {
                self.state.store(state, Ordering::Release);
            }
        }
    }

    pub(super) fn disabled() -> Self {
        Self {
            state: AtomicU8::new(CLUSTER_DISABLED),
            direct_commit_gate: Mutex::new(DirectCommitGate::default()),
            recovery_replay_plan: Mutex::new(None),
            recovery_wake_sequence: AtomicU64::new(0),
            listener_generation: AtomicU64::new(0),
            required_listener_generation: AtomicU64::new(0),
            listener_rotation_epoch: AtomicU64::new(0),
            failure_since: Mutex::new(None),
            authentication_failures: AtomicU64::new(0),
            replay_rejections: AtomicU64::new(0),
            degraded_transitions: AtomicU64::new(0),
            peer_versions_compatible: AtomicBool::new(true),
            incompatible_peer_versions: AtomicU64::new(0),
        }
    }

    pub(super) fn next_listener_generation(&self) -> u64 {
        self.listener_generation
            .load(Ordering::Acquire)
            .saturating_add(1)
    }

    pub(super) fn begin_listener_attempt(&self) -> (u64, u64) {
        let _transition = self
            .failure_since
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        (
            self.next_listener_generation(),
            self.listener_rotation_epoch.load(Ordering::Acquire),
        )
    }

    pub(super) fn listener_requires_rotation(&self, candidate_generation: u64) -> bool {
        candidate_generation < self.required_listener_generation.load(Ordering::Acquire)
    }

    pub(super) fn enabled() -> Self {
        Self {
            state: AtomicU8::new(CLUSTER_RECONCILING),
            direct_commit_gate: Mutex::new(DirectCommitGate::default()),
            recovery_replay_plan: Mutex::new(None),
            recovery_wake_sequence: AtomicU64::new(0),
            listener_generation: AtomicU64::new(0),
            required_listener_generation: AtomicU64::new(1),
            listener_rotation_epoch: AtomicU64::new(0),
            failure_since: Mutex::new(Some(Instant::now())),
            authentication_failures: AtomicU64::new(0),
            replay_rejections: AtomicU64::new(0),
            degraded_transitions: AtomicU64::new(0),
            peer_versions_compatible: AtomicBool::new(true),
            incompatible_peer_versions: AtomicU64::new(0),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ClusterOperation {
    NewBinding,
    Resume,
    MucMutation,
    AdminMutation,
    VolatileDelivery,
    DurableDirect,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ClusterMetricsSnapshot {
    pub state: u8,
    pub listener_generation: u64,
    pub authentication_failures: u64,
    pub replay_rejections: u64,
    pub degraded_transitions: u64,
    pub incompatible_peer_versions: u64,
}

/// Read-only process gauges without Redis, signing, or authority mutation.
#[derive(Clone)]
pub(crate) struct ClusterMetricsProbe {
    pub(super) health: Arc<ClusterHealth>,
}

impl ClusterMetricsProbe {
    pub(crate) fn snapshot(&self) -> ClusterMetricsSnapshot {
        cluster_metrics_snapshot(&self.health)
    }
}

pub(super) fn cluster_metrics_snapshot(health: &ClusterHealth) -> ClusterMetricsSnapshot {
    ClusterMetricsSnapshot {
        state: health.effective_state(),
        listener_generation: health.listener_generation.load(Ordering::Relaxed),
        authentication_failures: health.authentication_failures.load(Ordering::Relaxed),
        replay_rejections: health.replay_rejections.load(Ordering::Relaxed),
        degraded_transitions: health.degraded_transitions.load(Ordering::Relaxed),
        incompatible_peer_versions: health.incompatible_peer_versions.load(Ordering::Relaxed),
    }
}

pub(super) fn operation_allowed(state: u8, operation: ClusterOperation) -> bool {
    matches!(state, CLUSTER_DISABLED | CLUSTER_HEALTHY)
        || (state == CLUSTER_DURABLE_DIRECT_ONLY && operation == ClusterOperation::DurableDirect)
}

pub(super) fn degraded_shutdown_required(
    policy: crate::cluster_security::ClusterFailurePolicy,
    postgres_authority_healthy: bool,
    safety_lease_expired: bool,
) -> bool {
    !postgres_authority_healthy
        || (policy == crate::cluster_security::ClusterFailurePolicy::FailClosed
            && safety_lease_expired)
}

impl ClusterManager {
    pub fn begin_shutdown(&self) {
        self.require_shutdown();
    }

    /// Wait for every already-admitted signed publication to complete and
    /// prevent any later publication while the caller releases the database
    /// instance fence. `begin_shutdown` must be called first.
    pub async fn quiesce_publication(&self) -> tokio::sync::RwLockWriteGuard<'_, ()> {
        self.publication_gate.write().await
    }

    pub fn failure_policy(&self) -> Option<crate::cluster_security::ClusterFailurePolicy> {
        self.security
            .as_ref()
            .map(|security| security.failure_policy)
    }

    pub(crate) fn admission(&self) -> ClusterAdmission {
        ClusterAdmission {
            health: Arc::clone(&self.health),
            direct_authority: self.readiness_authority_snapshot(),
        }
    }

    pub fn admit(&self, operation: ClusterOperation) -> Result<()> {
        admit_health(&self.health, operation)
    }

    #[cfg(test)]
    pub fn readiness_error(&self) -> Option<String> {
        cluster_readiness_error(&self.health)
    }

    pub(crate) fn metrics_probe(&self) -> ClusterMetricsProbe {
        ClusterMetricsProbe {
            health: Arc::clone(&self.health),
        }
    }

    pub fn record_control_plane_failure(&self, error: &anyhow::Error) {
        self.record_failure(ClusterFailureClass::RedisCommand, error);
    }

    #[cfg(test)]
    pub(super) fn record_listener_failure(&self, error: &anyhow::Error) {
        self.record_failure(ClusterFailureClass::PubSub, error);
    }

    pub(super) fn record_failure(&self, class: ClusterFailureClass, error: &anyhow::Error) {
        record_cluster_failure(
            &self.health,
            &self.listener_rotation,
            self.is_enabled(),
            self.failure_policy(),
            class,
            error,
        );
    }

    #[cfg(test)]
    pub(super) fn confirm_listener_generation(
        &self,
        generation: u64,
        rotation_epoch: u64,
    ) -> Result<()> {
        confirm_listener_generation(&self.health, generation, rotation_epoch)
    }

    #[cfg(test)]
    pub(super) fn note_listener_generation(&self) {
        let (generation, rotation_epoch) = self.health.begin_listener_attempt();
        self.confirm_listener_generation(generation, rotation_epoch)
            .unwrap();
    }

    #[cfg(test)]
    pub(super) fn begin_reconciliation(&self) -> Result<u64> {
        begin_cluster_reconciliation(&self.health, self.is_enabled())?
            .context("cluster reconciliation deferred for direct commits")
    }

    #[cfg(test)]
    pub(super) fn complete_reconciliation(
        &self,
        rotation_epoch: u64,
    ) -> Result<ReconciliationOutcome> {
        complete_cluster_reconciliation(&self.health, rotation_epoch)
    }

    #[cfg(test)]
    pub(super) fn complete_reconciliation_locked(
        &self,
        since: &mut std::sync::MutexGuard<'_, Option<Instant>>,
        rotation_epoch: u64,
    ) -> Result<ReconciliationOutcome> {
        complete_cluster_reconciliation_locked(&self.health, since, rotation_epoch)
    }

    pub(super) fn require_shutdown(&self) {
        require_cluster_shutdown(&self.health, self.is_enabled());
    }
}
