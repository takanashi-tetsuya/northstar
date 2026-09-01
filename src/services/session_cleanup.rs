//! Explicit C2S session-finalization boundary.
//!
//! A transport first calls [`SessionCleanupService::quiesce`] synchronously so
//! no new local route can observe a connection whose socket has gone away.
//! The returned work item is then completed with bounded, independently
//! observed database and network steps.  Every durable mutation uses the
//! exact connection/SM/MUC epoch captured by the protocol actor; a late
//! cleanup can therefore never remove a replacement session.

use crate::{db, state::AppState};
use anyhow::Result;
use dashmap::DashMap;
use std::{
    collections::HashMap,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    time::Duration,
};
use tokio::sync::Notify;
use tokio::time::Instant;
use uuid::Uuid;

const CLEANUP_TOTAL_BUDGET: Duration = Duration::from_secs(10);
const CLEANUP_STEP_BUDGET: Duration = Duration::from_secs(2);

#[derive(Clone, Debug)]
pub(crate) struct SessionCleanupAccount {
    pub(crate) user_id: Uuid,
    pub(crate) username: String,
    pub(crate) auth_generation: i64,
}

#[derive(Debug)]
pub(crate) enum SessionSmCleanup {
    Suspend {
        session_id: Uuid,
        snapshot: crate::services::sm::SmSessionSnapshot,
        ttl_seconds: u64,
        capacity: crate::services::sm_capacity::SmCapacityLease,
    },
    Revoke {
        session_id: Uuid,
    },
    None,
}

pub(crate) struct SessionCleanupPlan {
    pub(crate) connection_id: Uuid,
    pub(crate) account: Option<SessionCleanupAccount>,
    pub(crate) registered_key: Option<String>,
    pub(crate) full_jid: Option<String>,
    pub(crate) available: Option<Arc<AtomicBool>>,
    pub(crate) active_privacy_list: Option<String>,
    pub(crate) directed_presence: Vec<String>,
    pub(crate) joined_rooms: Arc<DashMap<String, crate::state::JoinedMucMembership>>,
    pub(crate) sm: SessionSmCleanup,
}

struct MucDeparture {
    room_jid: String,
    departed: crate::state::MucOccupant,
    remaining: Vec<(String, crate::state::MucOccupant)>,
}

struct DurableSuspension {
    session_id: Uuid,
    snapshot: crate::services::sm::SmSessionSnapshot,
    ttl_seconds: u64,
    endpoints: Vec<Arc<crate::state::SuspendedMucEndpoint>>,
    capacity: crate::services::sm_capacity::SmCapacityLease,
}

struct SuspensionRecoveryPayload {
    account: SessionCleanupAccount,
    snapshot: crate::services::sm::SmSessionSnapshot,
    ttl_seconds: u64,
}

enum SuspensionRecoveryWork {
    Suspend(Box<SuspensionRecoveryPayload>),
    Promote,
}

struct PendingSuspensionRecovery {
    connection_id: Uuid,
    session_id: Uuid,
    endpoints: Vec<Arc<crate::state::SuspendedMucEndpoint>>,
    work: SuspensionRecoveryWork,
    capacity: crate::services::sm_capacity::SmCapacityLease,
    _recovery: crate::services::sm_capacity::SmRecoveryLease,
    sequence: u64,
    first_enqueued_at: std::time::Instant,
}

/// RAII ownership for one executing recovery epoch. If the supervised worker
/// is cancelled or unwinds, Drop atomically returns the exact snapshot and
/// both capacity leases to the queue tail instead of leaving a stale marker.
struct InFlightRecoveryJob {
    queue: Arc<SmSuspensionRecoveryQueue>,
    job: Option<PendingSuspensionRecovery>,
}

impl InFlightRecoveryJob {
    fn complete(mut self) {
        let job = self.job.take().expect("in-flight recovery owns one job");
        self.queue.complete_in_flight(&job);
    }

    fn retry_later(mut self) {
        let job = self.job.take().expect("in-flight recovery owns one job");
        self.queue.requeue_in_flight(job);
    }
}

impl std::ops::Deref for InFlightRecoveryJob {
    type Target = PendingSuspensionRecovery;

    fn deref(&self) -> &Self::Target {
        self.job.as_ref().expect("in-flight recovery owns one job")
    }
}

impl std::ops::DerefMut for InFlightRecoveryJob {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.job.as_mut().expect("in-flight recovery owns one job")
    }
}

impl Drop for InFlightRecoveryJob {
    fn drop(&mut self) {
        if let Some(job) = self.job.take() {
            self.queue.requeue_in_flight(job);
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RecoveryKind {
    Suspend,
    Promote,
}

impl SuspensionRecoveryWork {
    fn kind(&self) -> RecoveryKind {
        match self {
            Self::Suspend(_) => RecoveryKind::Suspend,
            Self::Promote => RecoveryKind::Promote,
        }
    }
}

struct InFlightRecovery {
    kind: RecoveryKind,
    first_enqueued_at: std::time::Instant,
}

#[derive(Default)]
struct RecoveryQueueState {
    queued: HashMap<(Uuid, Uuid), PendingSuspensionRecovery>,
    in_flight: HashMap<(Uuid, Uuid), InFlightRecovery>,
    next_sequence: u64,
}

/// A process-owned, bounded-by-live-session recovery set. Failed or timed-out
/// SM suspension CAS operations remain here until a supervised worker can
/// establish whether PostgreSQL accepted the exact epoch. The original MUC
/// endpoints remain sealed throughout; queue ownership is never inferred from
/// a timeout.
pub(crate) struct SmSuspensionRecoveryQueue {
    state: Mutex<RecoveryQueueState>,
    wake: Notify,
    max_jobs: usize,
    max_bytes: usize,
    metrics: Arc<crate::services::sm_capacity::SmCapacityMetrics>,
    governor: Arc<crate::services::sm_capacity::SmMemoryGovernor>,
}

impl SmSuspensionRecoveryQueue {
    pub(crate) fn new(
        max_jobs: usize,
        max_bytes: usize,
        metrics: Arc<crate::services::sm_capacity::SmCapacityMetrics>,
        governor: Arc<crate::services::sm_capacity::SmMemoryGovernor>,
    ) -> Arc<Self> {
        Arc::new(Self {
            state: Mutex::new(RecoveryQueueState::default()),
            wake: Notify::new(),
            max_jobs,
            max_bytes,
            metrics,
            governor,
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn enqueue(
        &self,
        account: SessionCleanupAccount,
        connection_id: Uuid,
        session_id: Uuid,
        snapshot: crate::services::sm::SmSessionSnapshot,
        ttl_seconds: u64,
        endpoints: Vec<Arc<crate::state::SuspendedMucEndpoint>>,
        capacity: crate::services::sm_capacity::SmCapacityLease,
    ) -> bool {
        let charged_bytes = snapshot.resident_bytes().unwrap_or(usize::MAX);
        let Ok(recovery) = self.governor.try_reserve_recovery(charged_bytes) else {
            return false;
        };
        self.enqueue_job(PendingSuspensionRecovery {
            connection_id,
            session_id,
            endpoints,
            work: SuspensionRecoveryWork::Suspend(Box::new(SuspensionRecoveryPayload {
                account,
                snapshot,
                ttl_seconds,
            })),
            capacity,
            _recovery: recovery,
            sequence: 0,
            first_enqueued_at: std::time::Instant::now(),
        })
    }

    pub(crate) fn enqueue_promote(
        &self,
        connection_id: Uuid,
        session_id: Uuid,
        endpoints: Vec<Arc<crate::state::SuspendedMucEndpoint>>,
        capacity: crate::services::sm_capacity::SmCapacityLease,
    ) -> bool {
        let charged_bytes = capacity.reserved_bytes();
        let Ok(recovery) = self.governor.try_reserve_recovery(charged_bytes) else {
            return false;
        };
        self.enqueue_job(PendingSuspensionRecovery {
            connection_id,
            session_id,
            endpoints,
            work: SuspensionRecoveryWork::Promote,
            capacity,
            _recovery: recovery,
            sequence: 0,
            first_enqueued_at: std::time::Instant::now(),
        })
    }

    fn enqueue_job(&self, job: PendingSuspensionRecovery) -> bool {
        let inserted = self.insert_job(job, true);
        if inserted {
            self.wake.notify_one();
        }
        inserted
    }

    /// A worker-owned retry waits for the periodic backoff tick. Waking itself
    /// here would turn a PostgreSQL outage into a tight retry loop. An exact
    /// suspension also outranks a promotion-only hint for the same epoch: the
    /// latter may run only after durable SM ownership is established.
    fn requeue_in_flight(&self, job: PendingSuspensionRecovery) {
        let key = (job.session_id, job.connection_id);
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if state.in_flight.remove(&key).is_none() {
            self.governor.mark_invariant_failure();
            return;
        }
        let inserted = self.insert_locked(&mut state, job, false);
        if !inserted {
            self.governor.mark_invariant_failure();
        }
        self.refresh_oldest(&state);
    }

    fn insert_job(&self, job: PendingSuspensionRecovery, account: bool) -> bool {
        let key = (job.session_id, job.connection_id);
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        // One exact epoch has exactly one process owner. A request racing an
        // executing worker cannot install a second capacity/snapshot owner.
        if let Some(in_flight) = state.in_flight.get(&key) {
            if in_flight.kind != job.work.kind() {
                tracing::warn!(?key, existing = ?in_flight.kind, incoming = ?job.work.kind(),
                    "rejected a duplicate SM recovery owner while the exact epoch is in flight");
            }
            return false;
        }
        if account {
            let reserved_jobs = self.metrics.recovery_queue_jobs.load(Ordering::Acquire) as usize;
            let reserved_bytes = self.metrics.recovery_queue_bytes.load(Ordering::Acquire) as usize;
            if state.queued.len().saturating_add(state.in_flight.len()) >= self.max_jobs
                || reserved_jobs > self.max_jobs
                || reserved_bytes > self.max_bytes
            {
                self.governor.mark_invariant_failure();
                return false;
            }
        }
        let inserted = self.insert_locked(&mut state, job, account);
        self.refresh_oldest(&state);
        inserted
    }

    fn insert_locked(
        &self,
        state: &mut RecoveryQueueState,
        mut job: PendingSuspensionRecovery,
        _new_admission: bool,
    ) -> bool {
        let key = (job.session_id, job.connection_id);
        job.sequence = state.next_sequence;
        state.next_sequence = state.next_sequence.wrapping_add(1);
        match state.queued.entry(key) {
            std::collections::hash_map::Entry::Vacant(slot) => {
                slot.insert(job);
                true
            }
            std::collections::hash_map::Entry::Occupied(mut slot) => {
                let existing_is_suspend =
                    matches!(&slot.get().work, SuspensionRecoveryWork::Suspend(_));
                let incoming_is_promote = matches!(&job.work, SuspensionRecoveryWork::Promote);
                if !(existing_is_suspend && incoming_is_promote) {
                    if existing_is_suspend {
                        self.governor.mark_invariant_failure();
                        false
                    } else {
                        let previous = slot.insert(job);
                        drop(previous);
                        true
                    }
                } else {
                    false
                }
            }
        }
    }

    fn take(self: &Arc<Self>) -> Option<InFlightRecoveryJob> {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let key = state
            .queued
            .iter()
            .min_by_key(|(_, job)| job.sequence)
            .map(|(key, _)| *key)?;
        let job = state.queued.remove(&key)?;
        state.in_flight.insert(
            key,
            InFlightRecovery {
                kind: job.work.kind(),
                first_enqueued_at: job.first_enqueued_at,
            },
        );
        self.refresh_oldest(&state);
        Some(InFlightRecoveryJob {
            queue: Arc::clone(self),
            job: Some(job),
        })
    }

    fn complete_in_flight(&self, job: &PendingSuspensionRecovery) {
        let key = (job.session_id, job.connection_id);
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if state.in_flight.remove(&key).is_none() {
            self.governor.mark_invariant_failure();
        }
        self.refresh_oldest(&state);
    }

    fn refresh_oldest(&self, state: &RecoveryQueueState) {
        let oldest = state
            .queued
            .values()
            .map(|job| job.first_enqueued_at)
            .chain(state.in_flight.values().map(|job| job.first_enqueued_at))
            .min();
        self.metrics.recovery_queue_oldest_age_seconds.store(
            crate::services::sm_capacity::oldest_age_seconds(oldest),
            Ordering::Release,
        );
    }

    pub(crate) fn snapshot(&self) -> crate::services::sm_capacity::SmRecoveryQueueSnapshot {
        let state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        self.refresh_oldest(&state);
        crate::services::sm_capacity::SmRecoveryQueueSnapshot {
            jobs: self.metrics.recovery_queue_jobs.load(Ordering::Acquire) as usize,
            bytes: self.metrics.recovery_queue_bytes.load(Ordering::Acquire) as usize,
            oldest_age_seconds: self
                .metrics
                .recovery_queue_oldest_age_seconds
                .load(Ordering::Acquire),
        }
    }
}

pub(crate) struct QuiescedSessionCleanup {
    connection_id: Uuid,
    account: Option<SessionCleanupAccount>,
    registered_key: Option<String>,
    full_jid: Option<String>,
    available: Option<Arc<AtomicBool>>,
    active_privacy_list: Option<String>,
    directed_presence: Vec<String>,
    route_removed: bool,
    departures: Vec<MucDeparture>,
    durable_suspension: Option<DurableSuspension>,
    revoke_sm_session: Option<Uuid>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CleanupRecovery {
    /// An exact database lease or epoch makes a retry/expiry safe.
    LeaseOrEpoch,
    /// Periodic cluster reconciliation removes stale soft state.
    ClusterReconciliation,
    /// Presence is soft state and peers converge on reconnect/probe.
    PresenceRefresh,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct CleanupFailure {
    pub(crate) operation: &'static str,
    pub(crate) recovery: CleanupRecovery,
}

#[derive(Debug, Default)]
pub(crate) struct CleanupReport {
    pub(crate) failures: Vec<CleanupFailure>,
}

impl CleanupReport {
    pub(crate) fn is_clean(&self) -> bool {
        self.failures.is_empty()
    }

    fn failed(&mut self, operation: &'static str, recovery: CleanupRecovery) {
        self.failures.push(CleanupFailure {
            operation,
            recovery,
        });
    }
}

pub(crate) struct SessionCleanupService {
    state: Arc<AppState>,
}

async fn run_sm_suspension_recovery(
    state: Arc<AppState>,
    queue: Arc<SmSuspensionRecoveryQueue>,
    cancel: tokio_util::sync::CancellationToken,
    heartbeat: crate::workers::WorkerHeartbeat,
) -> Result<()> {
    let mut retry_tick = tokio::time::interval(Duration::from_secs(1));
    retry_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        tokio::select! {
            _ = cancel.cancelled() => return Ok(()),
            _ = queue.wake.notified() => {},
            _ = retry_tick.tick() => heartbeat.pulse(),
        }

        while let Some(mut job) = queue.take() {
            let outcome = match &job.work {
                SuspensionRecoveryWork::Suspend(payload) => tokio::time::timeout(
                    CLEANUP_STEP_BUDGET,
                    state.sm_service().suspend_exact_session(
                        job.session_id,
                        job.connection_id,
                        payload.account.user_id,
                        payload.account.auth_generation,
                        &payload.snapshot,
                        payload.ttl_seconds,
                        state.config.sm_max_unacked_stanzas,
                        state.config.sm_max_unacked_bytes,
                    ),
                )
                .await
                .map_err(|_| anyhow::anyhow!("exact SM suspension retry timed out"))
                .and_then(|result| result),
                SuspensionRecoveryWork::Promote => Ok(true),
            };

            match outcome {
                Ok(true) => {
                    job.work = SuspensionRecoveryWork::Promote;
                    match tokio::time::timeout(
                        CLEANUP_STEP_BUDGET,
                        state.mark_suspended_muc_durable(job.endpoints.clone()),
                    )
                    .await
                    {
                        Ok(true) => {
                            state
                                .retain_suspended_sm_capacity(&job.endpoints, job.capacity.clone());
                            job.complete();
                            heartbeat.ok();
                        }
                        Ok(false) | Err(_) => {
                            heartbeat.error("durable MUC handoff retry remains incomplete");
                            job.retry_later();
                            break;
                        }
                    }
                }
                Ok(false) => {
                    // This exact connection epoch no longer owns the row. A
                    // winner may already be using the same session-global Arc,
                    // so never remove it here; sealing lets that winner's
                    // Waiting->Resuming transition reconcile it exactly.
                    state.seal_suspended_muc_endpoints(&job.endpoints).await;
                    job.complete();
                    heartbeat.ok();
                }
                Err(error) => {
                    state.seal_suspended_muc_endpoints(&job.endpoints).await;
                    heartbeat.error(&error);
                    job.retry_later();
                    break;
                }
            }
        }
    }
}

pub(crate) fn start_sm_suspension_recovery(
    state: Arc<AppState>,
    queue: Arc<SmSuspensionRecoveryQueue>,
    cancel: tokio_util::sync::CancellationToken,
) {
    let registry = Arc::clone(state.worker_registry());
    registry.supervise_draining(
        "sm-suspension-recovery",
        crate::workers::WorkerCriticality::Restartable,
        crate::workers::WorkerMode::Continuous,
        Some(Duration::from_secs(30)),
        Duration::from_secs(5),
        cancel.clone(),
        move |heartbeat| {
            let state = Arc::clone(&state);
            let queue = Arc::clone(&queue);
            let cancel = cancel.clone();
            async move { run_sm_suspension_recovery(state, queue, cancel, heartbeat).await }
        },
    );
}

impl SessionCleanupService {
    pub(crate) fn new(state: Arc<AppState>) -> Self {
        Self { state }
    }

    /// Remove exact process-local ownership before any asynchronous cleanup.
    /// This method performs no database or network I/O and is also the model
    /// used by the synchronous `Drop` fallback.
    pub(crate) fn quiesce(&self, plan: SessionCleanupPlan) -> QuiescedSessionCleanup {
        let full_jid = plan.full_jid.as_deref().unwrap_or_default();
        let (durable_suspension, revoke_sm_session) = match plan.sm {
            SessionSmCleanup::Suspend {
                session_id,
                snapshot,
                ttl_seconds,
                capacity,
            } => {
                let base_stanzas = snapshot.unacked.len();
                let base_bytes = snapshot
                    .unacked
                    .iter()
                    .map(|entry| entry.stanza.len())
                    .sum();
                let endpoints = self.state.suspend_local_muc_occupants(
                    full_jid,
                    plan.connection_id,
                    session_id,
                    &plan.joined_rooms,
                    base_stanzas,
                    base_bytes,
                );
                // Transfer the live session's actual-byte reservation at the
                // same synchronous ownership boundary as the route fence.
                // From this point every volatile MUC suffix append must grow
                // this shared lease before retaining another stanza.
                self.state
                    .retain_suspended_sm_capacity(&endpoints, capacity.clone());
                plan.joined_rooms.clear();
                (
                    Some(DurableSuspension {
                        session_id,
                        snapshot,
                        ttl_seconds,
                        endpoints,
                        capacity,
                    }),
                    None,
                )
            }
            SessionSmCleanup::Revoke { session_id } => (None, Some(session_id)),
            SessionSmCleanup::None => (None, None),
        };

        let mut departures = Vec::new();
        if durable_suspension.is_none() {
            let memberships = plan
                .joined_rooms
                .iter()
                .map(|membership| (membership.key().clone(), membership.value().clone()))
                .collect::<Vec<_>>();
            for (room_jid, membership) in memberships {
                plan.joined_rooms
                    .remove_if(&room_jid, |_, current| current == &membership);
                let key = crate::xmpp::xml_util::muc_occupant_key(&room_jid, &membership.nick);
                let Some((_, departed)) = self.state.muc_occupants.remove_if(&key, |_, current| {
                    crate::state::muc_departure_identity_matches(
                        current,
                        full_jid,
                        plan.connection_id,
                        membership.cluster_epoch,
                    )
                }) else {
                    continue;
                };
                let remaining = self.state.muc_occupants_for(&room_jid);
                departures.push(MucDeparture {
                    room_jid,
                    departed,
                    remaining,
                });
            }
        }

        let route_removed = plan.registered_key.as_deref().is_some_and(|key| {
            self.state
                .remove_session_if_connection(key, plan.connection_id)
                .is_some()
        });
        if route_removed && durable_suspension.is_none() {
            if let Some(available) = &plan.available {
                available.store(false, Ordering::Release);
            }
        }

        QuiescedSessionCleanup {
            connection_id: plan.connection_id,
            account: plan.account,
            registered_key: plan.registered_key,
            full_jid: plan.full_jid,
            available: plan.available,
            active_privacy_list: plan.active_privacy_list,
            directed_presence: plan.directed_presence,
            route_removed,
            departures,
            durable_suspension,
            revoke_sm_session,
        }
    }

    /// Complete every independent cleanup step within one finite connection
    /// budget. Failure never short-circuits later security/capacity cleanup.
    /// The report names the durable recovery mechanism for each missed step.
    pub(crate) async fn finish(&self, work: QuiescedSessionCleanup) -> CleanupReport {
        let deadline = Instant::now() + CLEANUP_TOTAL_BUDGET;
        let mut report = CleanupReport::default();
        self.state
            .metrics
            .session_finalizations_total
            .fetch_add(1, Ordering::Relaxed);

        let mut suspended = false;
        if let Some(suspension) = work.durable_suspension {
            let DurableSuspension {
                session_id,
                snapshot,
                ttl_seconds,
                endpoints,
                capacity,
            } = suspension;
            let mut capacity = Some(capacity);
            if let Some(account) = &work.account {
                let mut exact_snapshot = snapshot;
                let snapshot_backed = self
                    .step(
                        deadline,
                        "snapshot-suspended-muc",
                        CleanupRecovery::LeaseOrEpoch,
                        self.state
                            .snapshot_suspended_muc_for_disconnect(&endpoints, &mut exact_snapshot),
                        &mut report,
                    )
                    .await
                    .is_some();
                if !snapshot_backed {
                    // The endpoint still owns its original FIFO because the
                    // snapshot helper validates before changing phase. Keep
                    // the legacy two-step durable fallback available for this
                    // invariant/error path rather than dropping either owner.
                    self.state.seal_suspended_muc_endpoints(&endpoints).await;
                }
                let snapshot_bytes = exact_snapshot.resident_bytes().unwrap_or(usize::MAX);
                if capacity
                    .as_ref()
                    .is_none_or(|lease| lease.try_grow_to(snapshot_bytes).is_err())
                {
                    report.failed("suspend-sm-memory-admission", CleanupRecovery::LeaseOrEpoch);
                    self.state.sm_memory_governor().mark_invariant_failure();
                    self.state.seal_suspended_muc_endpoints(&endpoints).await;
                    let _ = self
                        .step(
                            deadline,
                            "revoke-sm-after-memory-rejection",
                            CleanupRecovery::LeaseOrEpoch,
                            self.state.revoke_sm_session_with_teardown(session_id),
                            &mut report,
                        )
                        .await;
                    capacity.take();
                } else {
                    match self
                        .step(
                            deadline,
                            "suspend-sm",
                            CleanupRecovery::LeaseOrEpoch,
                            self.state.sm_service().suspend_exact_session(
                                session_id,
                                work.connection_id,
                                account.user_id,
                                account.auth_generation,
                                &exact_snapshot,
                                ttl_seconds,
                                self.state.config.sm_max_unacked_stanzas,
                                self.state.config.sm_max_unacked_bytes,
                            ),
                            &mut report,
                        )
                        .await
                    {
                        Some(true) => {
                            // PostgreSQL now owns the resumable stream and its
                            // deployment-capacity lease even if MUC soft-state
                            // promotion below needs reconciliation.
                            suspended = true;
                            let promotion_endpoints = endpoints.clone();
                            let state = Arc::clone(&self.state);
                            let promotion = self
                            .step(
                                deadline,
                                "activate-suspended-muc",
                                CleanupRecovery::LeaseOrEpoch,
                                async move {
                                    anyhow::ensure!(
                                        state.mark_suspended_muc_durable(promotion_endpoints).await,
                                        "one or more suspended MUC projections require reconciliation"
                                    );
                                    Ok(())
                                },
                                &mut report,
                            )
                            .await;
                            if promotion.is_none() {
                                let queued =
                                    self.state.sm_suspension_recovery_queue().enqueue_promote(
                                        work.connection_id,
                                        session_id,
                                        endpoints.clone(),
                                        capacity
                                            .take()
                                            .expect("SM suspension owns its capacity lease"),
                                    );
                                if !queued {
                                    suspended = false;
                                    report.failed(
                                        "queue-sm-promotion",
                                        CleanupRecovery::LeaseOrEpoch,
                                    );
                                    let _ = self
                                        .step(
                                            deadline,
                                            "revoke-sm-after-recovery-capacity",
                                            CleanupRecovery::LeaseOrEpoch,
                                            self.state.revoke_sm_session_with_teardown(session_id),
                                            &mut report,
                                        )
                                        .await;
                                }
                            } else if let Some(capacity) = capacity.take() {
                                self.state
                                    .retain_suspended_sm_capacity(&endpoints, capacity);
                            }
                            // The SM row is already durable. If promotion times
                            // out or PostgreSQL rejects a MUC suffix, state keeps
                            // the exact bounded endpoint fail-closed for retry or
                            // same-process resume. Removing it here would turn a
                            // recoverable cleanup failure into silent message
                            // loss. Expiry/revocation remains the terminal owner.
                        }
                        Some(false) => {
                            self.state.seal_suspended_muc_endpoints(&endpoints).await;
                            if !report
                                .failures
                                .iter()
                                .any(|failure| failure.operation == "suspend-sm")
                            {
                                report.failed("suspend-sm", CleanupRecovery::LeaseOrEpoch);
                            }
                        }
                        None => {
                            self.state.seal_suspended_muc_endpoints(&endpoints).await;
                            let queued = self.state.sm_suspension_recovery_queue().enqueue(
                                account.clone(),
                                work.connection_id,
                                session_id,
                                exact_snapshot,
                                ttl_seconds,
                                endpoints.clone(),
                                capacity
                                    .take()
                                    .expect("SM suspension owns its capacity lease"),
                            );
                            if !queued {
                                report.failed("queue-sm-suspension", CleanupRecovery::LeaseOrEpoch);
                                let _ = self
                                    .step(
                                        deadline,
                                        "revoke-sm-after-recovery-capacity",
                                        CleanupRecovery::LeaseOrEpoch,
                                        self.state.revoke_sm_session_with_teardown(session_id),
                                        &mut report,
                                    )
                                    .await;
                            }
                        }
                    }
                }
            } else {
                report.failed("suspend-sm-missing-account", CleanupRecovery::LeaseOrEpoch);
                self.state.seal_suspended_muc_endpoints(&endpoints).await;
            }
        }

        if let Some(session_id) = work.revoke_sm_session {
            let _ = self
                .step(
                    deadline,
                    "revoke-sm",
                    CleanupRecovery::LeaseOrEpoch,
                    db::revoke_sm_session(&self.state.pool, session_id),
                    &mut report,
                )
                .await;
        }

        // A successfully suspended stream retains its deployment capacity
        // lease across resume. Every other path releases only this connection.
        if !suspended {
            let _ = self
                .step(
                    deadline,
                    "release-live-session",
                    CleanupRecovery::LeaseOrEpoch,
                    self.state
                        .sm_service()
                        .release_live_session(work.connection_id),
                    &mut report,
                )
                .await;
        }

        if let Some(account) = &work.account {
            let _ = self
                .step(
                    deadline,
                    "clear-active-privacy",
                    CleanupRecovery::LeaseOrEpoch,
                    db::clear_active_privacy_session(
                        &self.state.pool,
                        account.user_id,
                        work.connection_id,
                    ),
                    &mut report,
                )
                .await;
        }

        if work.route_removed {
            if let Some(key) = &work.registered_key {
                let _ = self
                    .step(
                        deadline,
                        "unregister-cluster-session",
                        CleanupRecovery::ClusterReconciliation,
                        self.state
                            .cluster
                            .unregister_session(key, work.connection_id),
                        &mut report,
                    )
                    .await;
            }
        }

        self.cleanup_muc_departures(deadline, work.departures, &mut report)
            .await;

        if work.route_removed && !suspended {
            if let Some(available) = &work.available {
                available.store(false, Ordering::Release);
            }
            if let (Some(account), Some(full_jid)) = (&work.account, &work.full_jid) {
                let future = self.publish_unavailable(
                    account,
                    full_jid,
                    work.active_privacy_list.as_deref(),
                    &work.directed_presence,
                );
                let _ = self
                    .step(
                        deadline,
                        "publish-unavailable",
                        CleanupRecovery::PresenceRefresh,
                        future,
                        &mut report,
                    )
                    .await;
            }
        }

        self.complete_report(report)
    }

    /// A superseding XEP-0198 connection owns route/SM/MUC cleanup, but the
    /// old connection's privacy selection remains connection-scoped and must
    /// still be removed explicitly.
    pub(crate) async fn clear_transferred_privacy(
        &self,
        account: Option<&SessionCleanupAccount>,
        connection_id: Uuid,
    ) -> CleanupReport {
        let mut report = CleanupReport::default();
        self.state
            .metrics
            .session_finalizations_total
            .fetch_add(1, Ordering::Relaxed);
        if let Some(account) = account {
            let deadline = Instant::now() + CLEANUP_STEP_BUDGET;
            let _ = self
                .step(
                    deadline,
                    "clear-transferred-privacy",
                    CleanupRecovery::LeaseOrEpoch,
                    db::clear_active_privacy_session(
                        &self.state.pool,
                        account.user_id,
                        connection_id,
                    ),
                    &mut report,
                )
                .await;
        }
        self.complete_report(report)
    }

    fn complete_report(&self, report: CleanupReport) -> CleanupReport {
        if !report.is_clean() {
            self.state
                .metrics
                .session_finalization_failures_total
                .fetch_add(report.failures.len() as u64, Ordering::Relaxed);
            tracing::error!(
                connection_cleanup_failures = report.failures.len(),
                failures = ?report.failures,
                "C2S session cleanup completed with recoverable debt"
            );
            self.state.worker_registry().observer_error(
                "session-cleanup",
                format!("{} bounded cleanup steps failed", report.failures.len()),
            );
        } else {
            self.state.worker_registry().observer_ok("session-cleanup");
        }
        report
    }

    async fn step<T>(
        &self,
        deadline: Instant,
        operation: &'static str,
        recovery: CleanupRecovery,
        future: impl std::future::Future<Output = Result<T>>,
        report: &mut CleanupReport,
    ) -> Option<T> {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            report.failed(operation, recovery);
            tracing::warn!(
                operation,
                ?recovery,
                "session cleanup total budget exhausted"
            );
            return None;
        }
        match tokio::time::timeout(remaining.min(CLEANUP_STEP_BUDGET), future).await {
            Ok(Ok(value)) => Some(value),
            Ok(Err(error)) => {
                report.failed(operation, recovery);
                tracing::warn!(?error, operation, ?recovery, "session cleanup step failed");
                None
            }
            Err(_) => {
                report.failed(operation, recovery);
                tracing::warn!(operation, ?recovery, "session cleanup step timed out");
                None
            }
        }
    }

    async fn cleanup_muc_departures(
        &self,
        deadline: Instant,
        departures: Vec<MucDeparture>,
        report: &mut CleanupReport,
    ) {
        for departure in departures {
            let serializable = crate::state::SerializableMucOccupant::from(&departure.departed);
            let room_jid = departure.room_jid.clone();
            let nick = departure.departed.nick.clone();
            let epoch = departure.departed.cluster_epoch;
            let connection_id = departure.departed.connection_id;
            let was_last = departure.remaining.is_empty();
            let cluster = self.state.cluster.clone();
            let cluster_cleanup = async move {
                cluster
                    .unregister_muc_occupant_epoch(&room_jid, &nick, epoch, connection_id)
                    .await?;
                if was_last {
                    cluster.leave_muc(&room_jid).await?;
                }
                cluster
                    .send_muc_presence(&room_jid, &serializable, true, false, None)
                    .await
            };
            let _ = self
                .step(
                    deadline,
                    "unregister-muc-occupant",
                    CleanupRecovery::ClusterReconciliation,
                    cluster_cleanup,
                    report,
                )
                .await;

            for (_, target) in &departure.remaining {
                let presence = crate::xmpp::xml_util::muc_presence_stanza(
                    &crate::state::SerializableMucOccupant::from(&departure.departed),
                    &target.full_jid,
                    true,
                    false,
                    false,
                    None,
                    departure.departed.room_non_anonymous || target.role == "moderator",
                );
                let state = Arc::clone(&self.state);
                let target = target.clone();
                let _ = self
                    .step(
                        deadline,
                        "deliver-muc-unavailable",
                        CleanupRecovery::PresenceRefresh,
                        async move {
                            anyhow::ensure!(
                                state.deliver_to_muc_occupant(&target, presence).await,
                                "MUC departure target was unavailable"
                            );
                            Ok(())
                        },
                        report,
                    )
                    .await;
            }

            if departure.remaining.is_empty() {
                let localpart = crate::state::localpart(&departure.room_jid).to_owned();
                let pool = self.state.pool.clone();
                let delete_temporary = async move {
                    let Some(room) = db::muc_room(&pool, &localpart).await? else {
                        return Ok(());
                    };
                    let _ = db::delete_temporary_muc_room(
                        &pool,
                        room.id,
                        room.room_epoch,
                        room.config_version,
                    )
                    .await?;
                    Ok(())
                };
                let _ = self
                    .step(
                        deadline,
                        "delete-temporary-muc",
                        CleanupRecovery::LeaseOrEpoch,
                        delete_temporary,
                        report,
                    )
                    .await;
            }
        }
    }

    async fn publish_unavailable(
        &self,
        account: &SessionCleanupAccount,
        full_jid: &str,
        active_privacy_list: Option<&str>,
        directed_presence: &[String],
    ) -> Result<()> {
        let presence =
            crate::xmpp::xml_builder::XmlElement::namespaced("presence", "jabber:client")
                .attr("from", full_jid)
                .attr("type", "unavailable")
                .finish();
        for (jid, _, subscription, _) in db::roster(&self.state.pool, account.user_id).await? {
            if matches!(subscription.as_str(), "from" | "both") {
                self.state
                    .route_unavailable_with_policy(
                        account.user_id,
                        active_privacy_list,
                        full_jid,
                        &presence,
                        &jid,
                    )
                    .await?;
            }
        }
        let actor_bare = format!("{}@{}", account.username, self.state.config.domain);
        for (jid, target) in self
            .state
            .session_entries_for(&actor_bare)
            .into_iter()
            .filter(|(_, target)| target.available.load(Ordering::Relaxed))
        {
            let _ = target
                .sender
                .try_send(crate::xmpp::xml_util::set_to(&presence, &jid));
        }
        for target_jid in directed_presence {
            self.state
                .route_unavailable_with_policy(
                    account.user_id,
                    active_privacy_list,
                    full_jid,
                    &presence,
                    target_jid,
                )
                .await?;
        }
        crate::xmpp::protocol::mix::disconnect_mix_presence(
            &self.state,
            account.user_id,
            &actor_bare,
            full_jid,
        )
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::{SessionCleanupAccount, SmSuspensionRecoveryQueue, SuspensionRecoveryWork};
    use std::sync::Arc;
    use uuid::Uuid;

    fn queue() -> Arc<SmSuspensionRecoveryQueue> {
        let metrics = Arc::new(crate::services::sm_capacity::SmCapacityMetrics::default());
        let governor = crate::services::sm_capacity::SmMemoryGovernor::new(
            1024 * 1024,
            512 * 1024,
            16,
            256 * 1024,
            Arc::clone(&metrics),
        )
        .unwrap();
        SmSuspensionRecoveryQueue::new(16, 512 * 1024, metrics, governor)
    }

    fn capacity(
        queue: &SmSuspensionRecoveryQueue,
        snapshot: &crate::services::sm::SmSessionSnapshot,
    ) -> crate::services::sm_capacity::SmCapacityLease {
        queue
            .governor
            .try_reserve_live(snapshot.resident_bytes().unwrap())
            .unwrap()
    }

    fn snapshot() -> crate::services::sm::SmSessionSnapshot {
        crate::services::sm::SmSessionSnapshot {
            inbound_h: 0,
            outbound_h: 1,
            acked_h: 0,
            available: true,
            carbons: false,
            priority: 0,
            blocklist_requested: false,
            roster_requested: false,
            active_privacy_list: None,
            privacy_requested: false,
            peer_ip: std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
            user_agent_id: None,
            joined_rooms: Vec::new(),
            directed_presence: Vec::new(),
            last_presence: None,
            unacked: vec![crate::outbound::SmUnackedStanza::plain(
                "ordered".to_owned(),
            )],
        }
    }

    #[test]
    fn exact_suspension_retry_cannot_be_downgraded_to_promotion_only() {
        let queue = queue();
        let session_id = Uuid::new_v4();
        let connection_id = Uuid::new_v4();
        let endpoint = Arc::new(crate::state::SuspendedMucEndpoint::new(session_id));
        let exact = snapshot();
        assert!(queue.enqueue(
            SessionCleanupAccount {
                user_id: Uuid::new_v4(),
                username: "alice".to_owned(),
                auth_generation: 7,
            },
            connection_id,
            session_id,
            exact.clone(),
            300,
            vec![Arc::clone(&endpoint)],
            capacity(&queue, &exact),
        ));
        assert!(!queue.enqueue_promote(
            connection_id,
            session_id,
            vec![endpoint],
            queue.governor.try_reserve_live(256).unwrap(),
        ));
        let job = queue.take().expect("one exact epoch remains queued");
        assert!(matches!(&job.work, SuspensionRecoveryWork::Suspend(_)));
        job.complete();
        assert!(queue.take().is_none());
    }

    #[test]
    fn retry_moves_to_tail_and_in_flight_epoch_rejects_a_second_owner() {
        let queue = queue();
        let first_session = Uuid::new_v4();
        let second_session = Uuid::new_v4();
        let first_connection = Uuid::new_v4();
        let second_connection = Uuid::new_v4();
        let first = snapshot();
        let second = snapshot();
        assert!(queue.enqueue(
            SessionCleanupAccount {
                user_id: Uuid::new_v4(),
                username: "alice".to_owned(),
                auth_generation: 1,
            },
            first_connection,
            first_session,
            first.clone(),
            300,
            Vec::new(),
            capacity(&queue, &first),
        ));
        assert!(queue.enqueue(
            SessionCleanupAccount {
                user_id: Uuid::new_v4(),
                username: "bob".to_owned(),
                auth_generation: 1,
            },
            second_connection,
            second_session,
            second.clone(),
            300,
            Vec::new(),
            capacity(&queue, &second),
        ));
        let first_job = queue.take().unwrap();
        assert_eq!(first_job.session_id, first_session);
        assert!(!queue.enqueue_promote(
            first_connection,
            first_session,
            Vec::new(),
            queue.governor.try_reserve_live(256).unwrap(),
        ));
        first_job.retry_later();
        let second_job = queue.take().unwrap();
        assert_eq!(second_job.session_id, second_session);
        second_job.complete();
        let retried = queue.take().unwrap();
        assert_eq!(retried.session_id, first_session);
        retried.complete();
    }

    #[test]
    fn cancelled_or_panicking_worker_returns_exact_job_to_queue() {
        let queue = queue();
        let session_id = Uuid::new_v4();
        let connection_id = Uuid::new_v4();
        let exact = snapshot();
        assert!(queue.enqueue(
            SessionCleanupAccount {
                user_id: Uuid::new_v4(),
                username: "alice".to_owned(),
                auth_generation: 1,
            },
            connection_id,
            session_id,
            exact.clone(),
            300,
            Vec::new(),
            capacity(&queue, &exact),
        ));
        let in_flight = queue.take().unwrap();
        drop(in_flight);
        let recovered = queue.take().expect("RAII drop must restore exact work");
        assert_eq!(recovered.session_id, session_id);
        assert!(matches!(
            &recovered.work,
            SuspensionRecoveryWork::Suspend(_)
        ));
        recovered.complete();
    }
}
