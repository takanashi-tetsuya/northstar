//! Generation-fenced durable stream teardown. Persistence owns the lease;
//! transport effects must complete before the leased row is finalized.

use anyhow::{ensure, Result};
use std::{future::Future, time::Duration};
use uuid::Uuid;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct SmTeardownLease {
    pub(crate) session_id: Uuid,
    pub(crate) token: Uuid,
}

pub(crate) trait SmTeardownClaim: Send {
    fn teardown_lease(&self) -> SmTeardownLease;
}

pub(crate) struct SmTeardownBatch<S> {
    pub(crate) snapshots: Vec<S>,
    pub(crate) pending: usize,
}

pub(crate) trait SmTeardownRepository: Send + Sync {
    type Snapshot: SmTeardownClaim;

    fn take_before_generation(
        &self,
        user_id: Uuid,
        generation_exclusive: i64,
        lease_seconds: u64,
    ) -> impl Future<Output = Result<SmTeardownBatch<Self::Snapshot>>> + Send;

    fn count_before_generation(
        &self,
        user_id: Uuid,
        generation_exclusive: i64,
    ) -> impl Future<Output = Result<i64>> + Send;

    fn finalize(&self, lease: SmTeardownLease) -> impl Future<Output = Result<bool>> + Send;
}

#[derive(Clone)]
pub(crate) struct SmTeardownService<R> {
    repository: R,
    lease_seconds: u64,
}

impl<R: SmTeardownRepository> SmTeardownService<R> {
    pub(crate) fn new(repository: R, lease_seconds: u64) -> Self {
        Self {
            repository,
            lease_seconds: lease_seconds.max(1),
        }
    }

    pub(crate) async fn finish<Render, RenderFuture>(
        &self,
        snapshot: R::Snapshot,
        render: Render,
    ) -> Result<()>
    where
        Render: FnOnce(R::Snapshot) -> RenderFuture + Send,
        RenderFuture: Future<Output = Result<()>> + Send,
    {
        let lease = snapshot.teardown_lease();
        render(snapshot).await?;
        ensure!(
            self.repository.finalize(lease).await?,
            "durable SM teardown lease was lost before finalization"
        );
        Ok(())
    }

    pub(crate) async fn revoke_before_generation<Render, RenderFuture>(
        &self,
        user_id: Uuid,
        generation_exclusive: i64,
        mut render: Render,
    ) -> Result<usize>
    where
        Render: FnMut(R::Snapshot) -> RenderFuture + Send,
        RenderFuture: Future<Output = Result<()>> + Send,
    {
        ensure!(
            generation_exclusive > 0,
            "invalid SM authorization-generation teardown fence"
        );
        let deadline =
            tokio::time::Instant::now() + Duration::from_secs(self.lease_seconds.saturating_add(2));
        let mut total = 0usize;
        loop {
            let batch = self
                .repository
                .take_before_generation(user_id, generation_exclusive, self.lease_seconds)
                .await?;
            total = total.saturating_add(batch.snapshots.len());
            for snapshot in batch.snapshots {
                self.finish(snapshot, &mut render).await?;
            }
            if batch.pending == 0
                && self
                    .repository
                    .count_before_generation(user_id, generation_exclusive)
                    .await?
                    == 0
            {
                return Ok(total);
            }
            ensure!(
                tokio::time::Instant::now() < deadline,
                "generation-fenced SM teardown claims did not quiesce before the deadline"
            );
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        collections::VecDeque,
        sync::{Arc, Mutex},
    };

    #[derive(Clone)]
    struct Snapshot(SmTeardownLease);

    impl SmTeardownClaim for Snapshot {
        fn teardown_lease(&self) -> SmTeardownLease {
            self.0
        }
    }

    #[derive(Default)]
    struct Trace {
        batches: VecDeque<SmTeardownBatch<Snapshot>>,
        counts: VecDeque<i64>,
        takes: Vec<(Uuid, i64, u64)>,
        finalized: Vec<SmTeardownLease>,
        reject_finalize: bool,
    }

    #[derive(Clone)]
    struct FakeRepository(Arc<Mutex<Trace>>);

    impl SmTeardownRepository for FakeRepository {
        type Snapshot = Snapshot;

        async fn take_before_generation(
            &self,
            user_id: Uuid,
            generation_exclusive: i64,
            lease_seconds: u64,
        ) -> Result<SmTeardownBatch<Self::Snapshot>> {
            let mut trace = self.0.lock().unwrap();
            trace
                .takes
                .push((user_id, generation_exclusive, lease_seconds));
            Ok(trace.batches.pop_front().expect("fixture batch"))
        }

        async fn count_before_generation(
            &self,
            _user_id: Uuid,
            _generation_exclusive: i64,
        ) -> Result<i64> {
            Ok(self
                .0
                .lock()
                .unwrap()
                .counts
                .pop_front()
                .expect("fixture count"))
        }

        async fn finalize(&self, lease: SmTeardownLease) -> Result<bool> {
            let mut trace = self.0.lock().unwrap();
            trace.finalized.push(lease);
            Ok(!trace.reject_finalize)
        }
    }

    fn snapshot() -> Snapshot {
        Snapshot(SmTeardownLease {
            session_id: Uuid::new_v4(),
            token: Uuid::new_v4(),
        })
    }

    #[tokio::test]
    async fn pending_and_remaining_rows_prevent_early_completion() {
        let user_id = Uuid::new_v4();
        let trace = Arc::new(Mutex::new(Trace {
            batches: VecDeque::from([
                SmTeardownBatch {
                    snapshots: vec![],
                    pending: 1,
                },
                SmTeardownBatch {
                    snapshots: vec![],
                    pending: 0,
                },
                SmTeardownBatch {
                    snapshots: vec![],
                    pending: 0,
                },
            ]),
            counts: VecDeque::from([1, 0]),
            ..Trace::default()
        }));
        let service = SmTeardownService::new(FakeRepository(Arc::clone(&trace)), 0);
        let count = service
            .revoke_before_generation(user_id, 7, |_| async { Ok(()) })
            .await
            .unwrap();
        assert_eq!(count, 0);
        let trace = trace.lock().unwrap();
        assert_eq!(trace.takes, [(user_id, 7, 1); 3]);
        assert!(trace.finalized.is_empty());
    }

    #[tokio::test]
    async fn failed_effect_is_not_finalized_and_replay_can_finish() {
        let user_id = Uuid::new_v4();
        let claimed = snapshot();
        let trace = Arc::new(Mutex::new(Trace {
            batches: VecDeque::from([
                SmTeardownBatch {
                    snapshots: vec![claimed.clone()],
                    pending: 0,
                },
                SmTeardownBatch {
                    snapshots: vec![claimed.clone()],
                    pending: 0,
                },
            ]),
            counts: VecDeque::from([0]),
            ..Trace::default()
        }));
        let service = SmTeardownService::new(FakeRepository(Arc::clone(&trace)), 2);
        assert!(service
            .revoke_before_generation(user_id, 7, |_| async { anyhow::bail!("effect failed") })
            .await
            .is_err());
        assert!(trace.lock().unwrap().finalized.is_empty());
        let completed = service
            .revoke_before_generation(user_id, 7, |_| async { Ok(()) })
            .await
            .unwrap();
        assert_eq!(completed, 1);
        assert_eq!(trace.lock().unwrap().finalized, [claimed.0]);
    }

    #[tokio::test]
    async fn lost_finalize_lease_is_an_error() {
        let claimed = snapshot();
        let trace = Arc::new(Mutex::new(Trace {
            reject_finalize: true,
            ..Trace::default()
        }));
        let service = SmTeardownService::new(FakeRepository(Arc::clone(&trace)), 1);
        let rendered = Arc::new(Mutex::new(false));
        let signal = Arc::clone(&rendered);
        assert!(service
            .finish(claimed.clone(), move |_| async move {
                *signal.lock().unwrap() = true;
                Ok(())
            })
            .await
            .is_err());
        assert!(*rendered.lock().unwrap());
        assert_eq!(trace.lock().unwrap().finalized, [claimed.0]);
    }
}
