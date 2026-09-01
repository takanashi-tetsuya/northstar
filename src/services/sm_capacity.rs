//! Process-local capacity authority for XEP-0198 memory and recovery work.
//!
//! Live streams reserve only the bytes they actually retain and grow that
//! reservation before accepting more replay state. A cross-process resume
//! reserves one maximum snapshot before its PostgreSQL claim can materialize
//! bytes, then shrinks to the claimed size. Disconnect transfers the same
//! cloneable RAII lease into exact cleanup/MUC ownership. Recovery-queue jobs
//! acquire a separate bounded job+byte lease only when enqueued.

use std::sync::{
    atomic::{AtomicBool, AtomicU64, Ordering},
    Arc, Mutex,
};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum SmCapacityError {
    JobsExhausted,
    BytesExhausted,
    InvalidReservation,
}

impl std::fmt::Display for SmCapacityError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::JobsExhausted => formatter.write_str("SM recovery job capacity is exhausted"),
            Self::BytesExhausted => formatter.write_str("SM recovery memory capacity is exhausted"),
            Self::InvalidReservation => formatter.write_str("SM recovery reservation is invalid"),
        }
    }
}

impl std::error::Error for SmCapacityError {}

#[derive(Default)]
pub(crate) struct SmCapacityMetrics {
    pub(crate) reserved_bytes: AtomicU64,
    pub(crate) peak_reserved_bytes: AtomicU64,
    pub(crate) admission_rejections_total: AtomicU64,
    pub(crate) invariant_failures_total: AtomicU64,
    pub(crate) recovery_queue_jobs: AtomicU64,
    pub(crate) recovery_queue_bytes: AtomicU64,
    pub(crate) recovery_queue_oldest_age_seconds: AtomicU64,
}

pub(crate) struct SmMemoryGovernor {
    bytes: Arc<Semaphore>,
    recovery_bytes: Arc<Semaphore>,
    recovery_jobs: Arc<Semaphore>,
    max_bytes: usize,
    max_recovery_bytes: usize,
    max_recovery_jobs: usize,
    max_snapshot_bytes: usize,
    unhealthy: AtomicBool,
    metrics: Arc<SmCapacityMetrics>,
}

#[derive(Clone)]
pub(crate) struct SmCapacityLease {
    inner: Arc<SmCapacityLeaseInner>,
}

struct SmCapacityLeaseInner {
    governor: Arc<SmMemoryGovernor>,
    state: Mutex<LeaseState>,
}

struct LeaseState {
    permits: Vec<OwnedSemaphorePermit>,
    bytes: usize,
}

pub(crate) struct SmRecoveryLease {
    governor: Arc<SmMemoryGovernor>,
    _bytes: Vec<OwnedSemaphorePermit>,
    _job: OwnedSemaphorePermit,
    bytes: usize,
}

impl std::fmt::Debug for SmCapacityLease {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SmCapacityLease")
            .field("bytes", &self.reserved_bytes())
            .finish_non_exhaustive()
    }
}

impl SmMemoryGovernor {
    pub(crate) fn new(
        max_bytes: usize,
        max_recovery_bytes: usize,
        max_recovery_jobs: usize,
        max_snapshot_bytes: usize,
        metrics: Arc<SmCapacityMetrics>,
    ) -> anyhow::Result<Arc<Self>> {
        anyhow::ensure!(
            max_bytes >= max_snapshot_bytes,
            "SM memory budget must cover one maximum snapshot claim"
        );
        anyhow::ensure!(
            max_recovery_bytes >= max_snapshot_bytes,
            "SM recovery byte budget must cover one maximum snapshot"
        );
        anyhow::ensure!(
            max_recovery_jobs > 0,
            "SM recovery job capacity must be non-zero"
        );
        anyhow::ensure!(
            max_bytes <= Semaphore::MAX_PERMITS
                && max_recovery_bytes <= Semaphore::MAX_PERMITS
                && max_recovery_jobs <= Semaphore::MAX_PERMITS,
            "SM capacity exceeds Tokio semaphore limits"
        );
        Ok(Arc::new(Self {
            bytes: Arc::new(Semaphore::new(max_bytes)),
            recovery_bytes: Arc::new(Semaphore::new(max_recovery_bytes)),
            recovery_jobs: Arc::new(Semaphore::new(max_recovery_jobs)),
            max_bytes,
            max_recovery_bytes,
            max_recovery_jobs,
            max_snapshot_bytes,
            unhealthy: AtomicBool::new(false),
            metrics,
        }))
    }

    pub(crate) fn try_reserve_live(
        self: &Arc<Self>,
        bytes: usize,
    ) -> Result<SmCapacityLease, SmCapacityError> {
        if bytes == 0 || bytes > self.max_snapshot_bytes {
            return Err(self.reject(SmCapacityError::InvalidReservation));
        }
        let permits = acquire_many(&self.bytes, bytes)
            .map_err(|_| self.reject(SmCapacityError::BytesExhausted))?;
        self.add_reserved_bytes(bytes);
        Ok(SmCapacityLease {
            inner: Arc::new(SmCapacityLeaseInner {
                governor: Arc::clone(self),
                state: Mutex::new(LeaseState { permits, bytes }),
            }),
        })
    }

    pub(crate) fn try_reserve_claim(self: &Arc<Self>) -> Result<SmCapacityLease, SmCapacityError> {
        self.try_reserve_live(self.max_snapshot_bytes)
    }

    /// Reserve an exact process-wide transient allocation which may be larger
    /// than one legal SM snapshot (for example, bounded BOSH XML validation
    /// can temporarily own multiple copies of one response). Each individual
    /// lease remains within the per-snapshot invariant; failure drops every
    /// already acquired chunk before returning.
    pub(crate) fn try_reserve_transient(
        self: &Arc<Self>,
        bytes: usize,
    ) -> Result<Vec<SmCapacityLease>, SmCapacityError> {
        if bytes == 0 {
            return Ok(Vec::new());
        }
        let mut remaining = bytes;
        let mut leases = Vec::new();
        while remaining > 0 {
            let chunk = remaining.min(self.max_snapshot_bytes);
            leases.push(self.try_reserve_live(chunk)?);
            remaining -= chunk;
        }
        Ok(leases)
    }

    pub(crate) fn try_reserve_recovery(
        self: &Arc<Self>,
        bytes: usize,
    ) -> Result<SmRecoveryLease, SmCapacityError> {
        if bytes == 0 || bytes > self.max_snapshot_bytes {
            return Err(self.reject(SmCapacityError::InvalidReservation));
        }
        let job = Arc::clone(&self.recovery_jobs)
            .try_acquire_owned()
            .map_err(|_| self.reject(SmCapacityError::JobsExhausted))?;
        let permits = match acquire_many(&self.recovery_bytes, bytes) {
            Ok(permits) => permits,
            Err(()) => {
                drop(job);
                return Err(self.reject(SmCapacityError::BytesExhausted));
            }
        };
        self.metrics
            .recovery_queue_jobs
            .fetch_add(1, Ordering::AcqRel);
        self.metrics
            .recovery_queue_bytes
            .fetch_add(bytes as u64, Ordering::AcqRel);
        Ok(SmRecoveryLease {
            governor: Arc::clone(self),
            _bytes: permits,
            _job: job,
            bytes,
        })
    }

    fn reject(&self, error: SmCapacityError) -> SmCapacityError {
        self.metrics
            .admission_rejections_total
            .fetch_add(1, Ordering::Relaxed);
        error
    }

    fn add_reserved_bytes(&self, bytes: usize) {
        let current = self
            .metrics
            .reserved_bytes
            .fetch_add(bytes as u64, Ordering::AcqRel)
            .saturating_add(bytes as u64);
        update_peak(&self.metrics.peak_reserved_bytes, current);
    }

    pub(crate) fn mark_invariant_failure(&self) {
        self.unhealthy.store(true, Ordering::Release);
        self.metrics
            .invariant_failures_total
            .fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn is_ready(&self) -> bool {
        if self.unhealthy.load(Ordering::Acquire) {
            return false;
        }
        let bytes = self.metrics.reserved_bytes.load(Ordering::Relaxed) as usize;
        let recovery_bytes = self.metrics.recovery_queue_bytes.load(Ordering::Relaxed) as usize;
        let recovery_jobs = self.metrics.recovery_queue_jobs.load(Ordering::Relaxed) as usize;
        bytes.saturating_mul(100) < self.max_bytes.saturating_mul(85)
            && recovery_bytes.saturating_mul(100) < self.max_recovery_bytes.saturating_mul(85)
            && recovery_jobs.saturating_mul(100) < self.max_recovery_jobs.saturating_mul(85)
    }

    pub(crate) fn max_bytes(&self) -> usize {
        self.max_bytes
    }
    pub(crate) fn max_recovery_bytes(&self) -> usize {
        self.max_recovery_bytes
    }
    pub(crate) fn max_recovery_jobs(&self) -> usize {
        self.max_recovery_jobs
    }
    pub(crate) fn metrics(&self) -> &Arc<SmCapacityMetrics> {
        &self.metrics
    }
}

impl SmCapacityLease {
    pub(crate) fn reserved_bytes(&self) -> usize {
        self.inner
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .bytes
    }

    pub(crate) fn try_grow_to(&self, bytes: usize) -> Result<(), SmCapacityError> {
        self.resize_to(bytes, false)
    }

    /// Atomically add a logical resident-byte delta to a clone-shared lease.
    /// Computing `reserved_bytes() + delta` outside this lock would lose one
    /// of two concurrent MUC suffix admissions that start from the same size.
    pub(crate) fn try_grow_by(&self, delta: usize) -> Result<(), SmCapacityError> {
        if delta == 0 {
            return Ok(());
        }
        let mut state = self
            .inner
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let bytes = state
            .bytes
            .checked_add(delta)
            .filter(|bytes| *bytes <= self.inner.governor.max_snapshot_bytes)
            .ok_or_else(|| {
                self.inner
                    .governor
                    .reject(SmCapacityError::InvalidReservation)
            })?;
        let mut permits = acquire_many(&self.inner.governor.bytes, delta)
            .map_err(|_| self.inner.governor.reject(SmCapacityError::BytesExhausted))?;
        state.permits.append(&mut permits);
        state.bytes = bytes;
        self.inner.governor.add_reserved_bytes(delta);
        Ok(())
    }

    pub(crate) fn shrink_to(&self, bytes: usize) -> Result<(), SmCapacityError> {
        self.resize_to(bytes, true)
    }

    fn resize_to(&self, bytes: usize, allow_shrink: bool) -> Result<(), SmCapacityError> {
        if bytes == 0 || bytes > self.inner.governor.max_snapshot_bytes {
            return Err(self
                .inner
                .governor
                .reject(SmCapacityError::InvalidReservation));
        }
        let mut state = self
            .inner
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if bytes <= state.bytes {
            if !allow_shrink || bytes == state.bytes {
                return Ok(());
            }
            let mut release = state.bytes - bytes;
            while release > 0 {
                let Some(mut permit) = state.permits.pop() else {
                    self.inner.governor.mark_invariant_failure();
                    return Err(SmCapacityError::InvalidReservation);
                };
                let owned = permit.num_permits();
                if owned > release {
                    let released = permit
                        .split(release)
                        .ok_or(SmCapacityError::InvalidReservation)?;
                    drop(released);
                    state.permits.push(permit);
                    release = 0;
                } else {
                    drop(permit);
                    release -= owned;
                }
            }
            let delta = state.bytes - bytes;
            state.bytes = bytes;
            self.inner
                .governor
                .metrics
                .reserved_bytes
                .fetch_sub(delta as u64, Ordering::AcqRel);
            return Ok(());
        }
        let delta = bytes - state.bytes;
        let mut permits = acquire_many(&self.inner.governor.bytes, delta)
            .map_err(|_| self.inner.governor.reject(SmCapacityError::BytesExhausted))?;
        state.permits.append(&mut permits);
        state.bytes = bytes;
        self.inner.governor.add_reserved_bytes(delta);
        Ok(())
    }
}

impl Drop for SmCapacityLeaseInner {
    fn drop(&mut self) {
        let state = self
            .state
            .get_mut()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        self.governor
            .metrics
            .reserved_bytes
            .fetch_sub(state.bytes as u64, Ordering::AcqRel);
    }
}

impl Drop for SmRecoveryLease {
    fn drop(&mut self) {
        self.governor
            .metrics
            .recovery_queue_jobs
            .fetch_sub(1, Ordering::AcqRel);
        self.governor
            .metrics
            .recovery_queue_bytes
            .fetch_sub(self.bytes as u64, Ordering::AcqRel);
    }
}

fn acquire_many(semaphore: &Arc<Semaphore>, bytes: usize) -> Result<Vec<OwnedSemaphorePermit>, ()> {
    let mut remaining = bytes;
    let mut permits = Vec::new();
    while remaining > 0 {
        let chunk = remaining.min(u32::MAX as usize) as u32;
        match Arc::clone(semaphore).try_acquire_many_owned(chunk) {
            Ok(permit) => permits.push(permit),
            Err(_) => return Err(()),
        }
        remaining -= chunk as usize;
    }
    Ok(permits)
}

fn update_peak(peak: &AtomicU64, value: u64) {
    let _ = peak.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
        (value > current).then_some(value)
    });
}

pub(crate) fn oldest_age_seconds(oldest: Option<std::time::Instant>) -> u64 {
    oldest
        .map(|instant| instant.elapsed().as_secs())
        .unwrap_or(0)
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct SmRecoveryQueueSnapshot {
    pub(crate) jobs: usize,
    pub(crate) bytes: usize,
    pub(crate) oldest_age_seconds: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn one_thousand_empty_live_leases_fit_without_static_maximum_reservation() {
        let metrics = Arc::new(SmCapacityMetrics::default());
        let governor = SmMemoryGovernor::new(1_000_000, 250_000, 1_024, 4_096, metrics).unwrap();
        let leases = (0..1_000)
            .map(|_| governor.try_reserve_live(512).unwrap())
            .collect::<Vec<_>>();
        assert_eq!(leases.len(), 1_000);
    }

    #[test]
    fn live_growth_claim_shrink_and_raii_release_are_exact() {
        let metrics = Arc::new(SmCapacityMetrics::default());
        let governor =
            SmMemoryGovernor::new(10_000, 4_000, 4, 4_000, Arc::clone(&metrics)).unwrap();
        let lease = governor.try_reserve_claim().unwrap();
        assert_eq!(lease.reserved_bytes(), 4_000);
        lease.shrink_to(500).unwrap();
        lease.try_grow_to(1_000).unwrap();
        assert_eq!(metrics.reserved_bytes.load(Ordering::Relaxed), 1_000);
        drop(lease);
        assert_eq!(metrics.reserved_bytes.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn clone_shared_delta_growth_is_linearized_without_lost_capacity() {
        let metrics = Arc::new(SmCapacityMetrics::default());
        let governor =
            SmMemoryGovernor::new(10_000, 4_000, 4, 4_000, Arc::clone(&metrics)).unwrap();
        let lease = governor.try_reserve_live(500).unwrap();
        let left = lease.clone();
        let right = lease.clone();
        let barrier = Arc::new(std::sync::Barrier::new(3));
        let left_barrier = Arc::clone(&barrier);
        let left_worker = std::thread::spawn(move || {
            left_barrier.wait();
            left.try_grow_by(250).unwrap();
        });
        let right_barrier = Arc::clone(&barrier);
        let right_worker = std::thread::spawn(move || {
            right_barrier.wait();
            right.try_grow_by(250).unwrap();
        });
        barrier.wait();
        left_worker.join().unwrap();
        right_worker.join().unwrap();
        assert_eq!(lease.reserved_bytes(), 1_000);
        assert_eq!(metrics.reserved_bytes.load(Ordering::Relaxed), 1_000);
    }

    #[test]
    fn recovery_jobs_and_bytes_are_independently_bounded() {
        let metrics = Arc::new(SmCapacityMetrics::default());
        let governor =
            SmMemoryGovernor::new(20_000, 1_000, 2, 1_000, Arc::clone(&metrics)).unwrap();
        let one = governor.try_reserve_recovery(500).unwrap();
        let two = governor.try_reserve_recovery(500).unwrap();
        assert_eq!(
            governor.try_reserve_recovery(1).err(),
            Some(SmCapacityError::JobsExhausted)
        );
        drop(one);
        drop(two);
        assert_eq!(metrics.recovery_queue_jobs.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn multi_chunk_transient_reservation_is_atomic_on_failure_and_raii_release() {
        let metrics = Arc::new(SmCapacityMetrics::default());
        let governor = SmMemoryGovernor::new(1_000, 500, 2, 400, Arc::clone(&metrics)).unwrap();
        let held = governor.try_reserve_transient(500).unwrap();
        assert_eq!(held.len(), 2);
        assert_eq!(metrics.reserved_bytes.load(Ordering::Relaxed), 500);
        assert_eq!(
            governor.try_reserve_transient(600).err(),
            Some(SmCapacityError::BytesExhausted)
        );
        // The failed attempt acquired and rolled back its first 400-byte
        // chunk; only the original reservation remains.
        assert_eq!(metrics.reserved_bytes.load(Ordering::Relaxed), 500);
        drop(held);
        assert_eq!(metrics.reserved_bytes.load(Ordering::Relaxed), 0);
    }
}
