//! Admission control for password hashing and verification.
//!
//! Argon2 is intentionally expensive.  A Tokio blocking pool is not an
//! admission boundary by itself: every accepted request can enqueue another
//! closure and retain its request body and protocol state while it waits.  This
//! gate therefore bounds both running work and admitted waiters.  Callers must
//! map [`PasswordWorkError::Overloaded`] to a retryable protocol response; it
//! must never be reported as an invalid password.

use anyhow::Result;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, LazyLock};
use tokio::sync::Semaphore;

const ACTIVE_PASSWORD_WORK: usize = 8;
const TOTAL_PASSWORD_WORK: usize = 32;

static PASSWORD_WORK: LazyLock<PasswordWorkGate> =
    LazyLock::new(|| PasswordWorkGate::new(ACTIVE_PASSWORD_WORK, TOTAL_PASSWORD_WORK));
static PASSWORD_WORK_STARTED: LazyLock<std::time::Instant> = LazyLock::new(std::time::Instant::now);
static PASSWORD_WORK_WARNING_BUCKET: AtomicU64 = AtomicU64::new(0);
static PASSWORD_WORK_SUPPRESSED_WARNINGS: AtomicU64 = AtomicU64::new(0);
static PASSWORD_WORK_REJECTIONS_TOTAL: AtomicU64 = AtomicU64::new(0);
const PASSWORD_WORK_WARNING_INTERVAL_SECONDS: u64 = 10;

fn record_overload(active_limit: usize, total_limit: usize) {
    let rejections_total = PASSWORD_WORK_REJECTIONS_TOTAL.fetch_add(1, Ordering::Relaxed) + 1;
    let warning_bucket =
        PASSWORD_WORK_STARTED.elapsed().as_secs() / PASSWORD_WORK_WARNING_INTERVAL_SECONDS + 1;
    let previous_bucket = PASSWORD_WORK_WARNING_BUCKET.load(Ordering::Relaxed);
    if previous_bucket != warning_bucket
        && PASSWORD_WORK_WARNING_BUCKET
            .compare_exchange(
                previous_bucket,
                warning_bucket,
                Ordering::Relaxed,
                Ordering::Relaxed,
            )
            .is_ok()
    {
        let suppressed = PASSWORD_WORK_SUPPRESSED_WARNINGS.swap(0, Ordering::Relaxed);
        tracing::warn!(
            active_limit,
            total_limit,
            rejections_total,
            suppressed_since_previous_warning = suppressed,
            "password work admission rejected at its hard capacity boundary"
        );
    } else {
        PASSWORD_WORK_SUPPRESSED_WARNINGS.fetch_add(1, Ordering::Relaxed);
    }
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum PasswordWorkError {
    #[error("password work capacity is temporarily exhausted")]
    Overloaded,
    #[error("password work scheduler is unavailable")]
    Unavailable,
    #[error("password computation task failed")]
    Task(#[source] tokio::task::JoinError),
    #[error("password computation failed")]
    Computation(#[source] anyhow::Error),
}

impl PasswordWorkError {
    pub(crate) fn is_overloaded(&self) -> bool {
        matches!(self, Self::Overloaded)
    }
}

struct PasswordWorkGate {
    active: Arc<Semaphore>,
    admitted: Arc<Semaphore>,
    active_limit: usize,
    total_limit: usize,
}

pub(crate) struct PasswordWorkReservation {
    active: tokio::sync::OwnedSemaphorePermit,
    admitted: tokio::sync::OwnedSemaphorePermit,
}

pub(crate) struct PasswordWorkAdmission {
    active: Arc<Semaphore>,
    admitted: tokio::sync::OwnedSemaphorePermit,
}

impl PasswordWorkAdmission {
    pub(crate) async fn reserve(
        self,
    ) -> std::result::Result<PasswordWorkReservation, PasswordWorkError> {
        let active = self
            .active
            .acquire_owned()
            .await
            .map_err(|_| PasswordWorkError::Unavailable)?;
        Ok(PasswordWorkReservation {
            active,
            admitted: self.admitted,
        })
    }

    pub(crate) async fn run<T, F>(self, work: F) -> std::result::Result<T, PasswordWorkError>
    where
        T: Send + 'static,
        F: FnOnce() -> Result<T> + Send + 'static,
    {
        self.reserve().await?.run(work).await
    }
}

impl PasswordWorkReservation {
    pub(crate) async fn run<T, F>(self, work: F) -> std::result::Result<T, PasswordWorkError>
    where
        T: Send + 'static,
        F: FnOnce() -> Result<T> + Send + 'static,
    {
        let Self { active, admitted } = self;
        // Move both permits into the blocking closure.  Dropping or aborting
        // the async request does not cancel spawn_blocking work; retaining the
        // permits here prevents canceled clients from exceeding the real CPU
        // concurrency and queue limits.
        tokio::task::spawn_blocking(move || {
            let _admitted = admitted;
            let _active = active;
            work()
        })
        .await
        .map_err(PasswordWorkError::Task)?
        .map_err(PasswordWorkError::Computation)
    }
}

impl PasswordWorkGate {
    fn new(active: usize, total: usize) -> Self {
        assert!(active > 0, "password work needs at least one active slot");
        assert!(
            total >= active,
            "password work admission cannot be smaller than its active set"
        );
        Self {
            active: Arc::new(Semaphore::new(active)),
            admitted: Arc::new(Semaphore::new(total)),
            active_limit: active,
            total_limit: total,
        }
    }

    fn admit(&self) -> std::result::Result<PasswordWorkAdmission, PasswordWorkError> {
        // Fast-fail before creating an unbounded async waiter.  This permit
        // covers running and queued work, so at most TOTAL_PASSWORD_WORK
        // requests retain credentials and request state at once.
        let admitted = self
            .admitted
            .clone()
            .try_acquire_owned()
            .map_err(|error| match error {
                tokio::sync::TryAcquireError::NoPermits => {
                    record_overload(self.active_limit, self.total_limit);
                    PasswordWorkError::Overloaded
                }
                tokio::sync::TryAcquireError::Closed => PasswordWorkError::Unavailable,
            })?;
        Ok(PasswordWorkAdmission {
            active: self.active.clone(),
            admitted,
        })
    }

    async fn reserve(&self) -> std::result::Result<PasswordWorkReservation, PasswordWorkError> {
        self.admit()?.reserve().await
    }

    async fn run<T, F>(&self, work: F) -> std::result::Result<T, PasswordWorkError>
    where
        T: Send + 'static,
        F: FnOnce() -> Result<T> + Send + 'static,
    {
        self.reserve().await?.run(work).await
    }
}

pub(crate) async fn run<T, F>(work: F) -> std::result::Result<T, PasswordWorkError>
where
    T: Send + 'static,
    F: FnOnce() -> Result<T> + Send + 'static,
{
    PASSWORD_WORK.run(work).await
}

/// Acquire total admission without waiting for a CPU slot.  Login uses this
/// before its account lookup so random-username floods cannot bypass the hard
/// request-retention bound by stopping immediately before Argon2.
pub(crate) fn admit() -> std::result::Result<PasswordWorkAdmission, PasswordWorkError> {
    PASSWORD_WORK.admit()
}

/// Reserve bounded CPU capacity before opening a database transaction.  This
/// is used by the XMPP password-change flow, whose proof and credential update
/// must commit atomically without making database connections wait in the
/// password-work queue.
pub(crate) async fn reserve() -> std::result::Result<PasswordWorkReservation, PasswordWorkError> {
    PASSWORD_WORK.reserve().await
}

/// Recognize overload through `anyhow::Context` layers at protocol boundaries.
pub(crate) fn is_overloaded(error: &anyhow::Error) -> bool {
    error.chain().any(|cause| {
        cause
            .downcast_ref::<PasswordWorkError>()
            .is_some_and(PasswordWorkError::is_overloaded)
    })
}

pub(crate) fn rejections_total() -> u64 {
    PASSWORD_WORK_REJECTIONS_TOTAL.load(Ordering::Relaxed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::Context;
    use std::sync::mpsc;
    use std::time::Duration;

    #[tokio::test]
    async fn admission_bounds_running_and_waiting_work_and_fails_fast() {
        let gate = Arc::new(PasswordWorkGate::new(1, 2));
        let (first_started_tx, first_started_rx) = tokio::sync::oneshot::channel();
        let (release_first_tx, release_first_rx) = mpsc::channel();
        let first_gate = gate.clone();
        let first = tokio::spawn(async move {
            first_gate
                .run(move || {
                    let _ = first_started_tx.send(());
                    release_first_rx.recv().expect("release first password job");
                    Ok(1_u8)
                })
                .await
        });
        first_started_rx.await.expect("first password job started");

        let (second_started_tx, mut second_started_rx) = tokio::sync::oneshot::channel();
        let (release_second_tx, release_second_rx) = mpsc::channel();
        let second_gate = gate.clone();
        let second = tokio::spawn(async move {
            second_gate
                .run(move || {
                    let _ = second_started_tx.send(());
                    release_second_rx
                        .recv()
                        .expect("release second password job");
                    Ok(2_u8)
                })
                .await
        });
        tokio::time::timeout(Duration::from_secs(1), async {
            while gate.admitted.available_permits() != 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("second password job was admitted");
        assert!(
            tokio::time::timeout(Duration::from_millis(25), &mut second_started_rx)
                .await
                .is_err(),
            "queued work ran without an active slot"
        );

        let third_ran = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let third_ran_in_work = third_ran.clone();
        let overloaded = tokio::time::timeout(
            Duration::from_millis(100),
            gate.run(move || {
                third_ran_in_work.store(true, std::sync::atomic::Ordering::SeqCst);
                Ok(3_u8)
            }),
        )
        .await
        .expect("overload response must not wait")
        .expect_err("third password job must exceed total admission");
        assert!(overloaded.is_overloaded());
        assert!(!third_ran.load(std::sync::atomic::Ordering::SeqCst));

        release_first_tx.send(()).unwrap();
        assert_eq!(first.await.unwrap().unwrap(), 1);
        second_started_rx
            .await
            .expect("queued password job eventually started");
        release_second_tx.send(()).unwrap();
        assert_eq!(second.await.unwrap().unwrap(), 2);
    }

    #[tokio::test]
    async fn canceled_request_keeps_capacity_until_blocking_work_exits() {
        let gate = Arc::new(PasswordWorkGate::new(1, 1));
        let (started_tx, started_rx) = tokio::sync::oneshot::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let task_gate = gate.clone();
        let task = tokio::spawn(async move {
            task_gate
                .run(move || {
                    let _ = started_tx.send(());
                    release_rx.recv().expect("release canceled password job");
                    Ok(())
                })
                .await
        });
        started_rx.await.expect("password job started");
        task.abort();
        let error = gate
            .run(|| Ok(()))
            .await
            .expect_err("aborting the waiter must not release blocking capacity");
        assert!(error.is_overloaded());
        release_tx.send(()).unwrap();
        tokio::time::timeout(Duration::from_secs(1), async {
            while gate.admitted.available_permits() != 1 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("blocking completion released admission");
    }

    #[test]
    fn overload_survives_anyhow_context_for_protocol_mapping() {
        let error = Err::<(), _>(anyhow::Error::from(PasswordWorkError::Overloaded))
            .context("outer password operation")
            .unwrap_err();
        assert!(is_overloaded(&error));
    }
}
