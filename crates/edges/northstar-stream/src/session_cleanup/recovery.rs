//! Bounded recovery of SM suspensions whose durable handoff failed or timed out, and its supervised worker.

use super::suspension::{SmSuspensionCluster, SmSuspensionContext};
use super::CLEANUP_STEP_BUDGET;
use anyhow::Result;
use northstar_session_application::sm_suspension::{self, SmSuspensionRepository};
use northstar_session_application::SessionCleanupAccount;
use std::{
    collections::HashMap,
    sync::{atomic::Ordering, Arc, Mutex},
    time::Duration,
};
use tokio::sync::Notify;
use uuid::Uuid;

struct SuspensionRecoveryPayload {
    account: SessionCleanupAccount,
    snapshot: northstar_session_application::sm::SmSessionSnapshot,
    ttl_seconds: u64,
}

enum SuspensionRecoveryWork {
    Suspend(Box<SuspensionRecoveryPayload>),
    Promote,
}

struct PendingSuspensionRecovery {
    connection_id: Uuid,
    session_id: Uuid,
    endpoints: Vec<Arc<crate::local_routes::muc::SuspendedMucEndpoint>>,
    work: SuspensionRecoveryWork,
    capacity: northstar_session_application::sm_capacity::SmCapacityLease,
    _recovery: northstar_session_application::sm_capacity::SmRecoveryLease,
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
pub struct SmSuspensionRecoveryQueue {
    state: Mutex<RecoveryQueueState>,
    wake: Notify,
    max_jobs: usize,
    max_bytes: usize,
    metrics: Arc<northstar_session_application::sm_capacity::SmCapacityMetrics>,
    governor: Arc<northstar_session_application::sm_capacity::SmMemoryGovernor>,
}

impl SmSuspensionRecoveryQueue {
    pub fn new(
        max_jobs: usize,
        max_bytes: usize,
        metrics: Arc<northstar_session_application::sm_capacity::SmCapacityMetrics>,
        governor: Arc<northstar_session_application::sm_capacity::SmMemoryGovernor>,
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
    pub fn enqueue(
        &self,
        account: SessionCleanupAccount,
        connection_id: Uuid,
        session_id: Uuid,
        snapshot: northstar_session_application::sm::SmSessionSnapshot,
        ttl_seconds: u64,
        endpoints: Vec<Arc<crate::local_routes::muc::SuspendedMucEndpoint>>,
        capacity: northstar_session_application::sm_capacity::SmCapacityLease,
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

    pub fn enqueue_promote(
        &self,
        connection_id: Uuid,
        session_id: Uuid,
        endpoints: Vec<Arc<crate::local_routes::muc::SuspendedMucEndpoint>>,
        capacity: northstar_session_application::sm_capacity::SmCapacityLease,
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
            northstar_session_application::sm_capacity::oldest_age_seconds(oldest),
            Ordering::Release,
        );
    }

    pub fn snapshot(&self) -> northstar_session_application::sm_capacity::SmRecoveryQueueSnapshot {
        let state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        self.refresh_oldest(&state);
        northstar_session_application::sm_capacity::SmRecoveryQueueSnapshot {
            jobs: self.metrics.recovery_queue_jobs.load(Ordering::Acquire) as usize,
            bytes: self.metrics.recovery_queue_bytes.load(Ordering::Acquire) as usize,
            oldest_age_seconds: self
                .metrics
                .recovery_queue_oldest_age_seconds
                .load(Ordering::Acquire),
        }
    }
}

async fn run_sm_suspension_recovery<R: SmSuspensionRepository, C: SmSuspensionCluster>(
    context: Arc<SmSuspensionContext<R, C>>,
    queue: Arc<SmSuspensionRecoveryQueue>,
    cancel: tokio_util::sync::CancellationToken,
    heartbeat: northstar_runtime::workers::WorkerHeartbeat,
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
                    context.suspend_exact_session(sm_suspension::SmSuspensionRequest {
                        session_id: job.session_id,
                        connection_id: job.connection_id,
                        user_id: payload.account.user_id,
                        auth_generation: payload.account.auth_generation,
                        snapshot: &payload.snapshot,
                        ttl_seconds: payload.ttl_seconds,
                    }),
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
                        context.mark_suspended_muc_durable(job.endpoints.clone()),
                    )
                    .await
                    {
                        Ok(true) => {
                            context
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
                    context.seal_suspended_muc_endpoints(&job.endpoints).await;
                    job.complete();
                    heartbeat.ok();
                }
                Err(error) => {
                    context.seal_suspended_muc_endpoints(&job.endpoints).await;
                    heartbeat.error(&error);
                    job.retry_later();
                    break;
                }
            }
        }
    }
}

pub fn start_sm_suspension_recovery<
    R: SmSuspensionRepository + 'static,
    C: SmSuspensionCluster + 'static,
>(
    context: Arc<SmSuspensionContext<R, C>>,
    registry: Arc<northstar_runtime::workers::WorkerRegistry>,
    queue: Arc<SmSuspensionRecoveryQueue>,
    cancel: tokio_util::sync::CancellationToken,
) {
    registry.supervise_draining(
        "sm-suspension-recovery",
        northstar_runtime::workers::WorkerCriticality::Restartable,
        northstar_runtime::workers::WorkerMode::Continuous,
        Some(Duration::from_secs(30)),
        Duration::from_secs(5),
        cancel.clone(),
        move |heartbeat| {
            let context = Arc::clone(&context);
            let queue = Arc::clone(&queue);
            let cancel = cancel.clone();
            async move { run_sm_suspension_recovery(context, queue, cancel, heartbeat).await }
        },
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    fn queue() -> Arc<SmSuspensionRecoveryQueue> {
        let metrics =
            Arc::new(northstar_session_application::sm_capacity::SmCapacityMetrics::default());
        let governor = northstar_session_application::sm_capacity::SmMemoryGovernor::new(
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
        snapshot: &northstar_session_application::sm::SmSessionSnapshot,
    ) -> northstar_session_application::sm_capacity::SmCapacityLease {
        queue
            .governor
            .try_reserve_live(snapshot.resident_bytes().unwrap())
            .unwrap()
    }

    fn snapshot() -> northstar_session_application::sm::SmSessionSnapshot {
        northstar_session_application::sm::SmSessionSnapshot {
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
            unacked: vec![northstar_delivery_core::SmUnackedStanza::plain(
                "ordered".to_owned(),
            )],
        }
    }

    #[test]
    fn exact_suspension_retry_cannot_be_downgraded_to_promotion_only() {
        let queue = queue();
        let session_id = Uuid::new_v4();
        let connection_id = Uuid::new_v4();
        let endpoint = Arc::new(crate::local_routes::muc::SuspendedMucEndpoint::new(
            session_id,
        ));
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
