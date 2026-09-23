//! The database portion of the once-per-minute background maintenance tick.
//! Each purge is an independent committed operation. A failed step is counted
//! and logged without preventing later cleanup work from running.

use anyhow::Result;
use std::{
    future::Future,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
};

const CLEANUP_BATCH_SIZE: i64 = 1_000;

pub(crate) trait BackgroundHousekeepingRepository: Send + Sync {
    fn purge_resolved_moderation(
        &self,
        retention_days: i64,
        batch_size: i64,
    ) -> impl Future<Output = Result<u64>> + Send;
    fn cleanup_expired_sessions(&self) -> impl Future<Output = Result<u64>> + Send;
    fn cleanup_expired_idempotency(
        &self,
        batch_size: i64,
    ) -> impl Future<Output = Result<u64>> + Send;
    fn cleanup_fast_tokens(&self) -> impl Future<Output = Result<u64>> + Send;
    fn cleanup_expired_login_epoch_stages(
        &self,
        batch_size: i64,
    ) -> impl Future<Output = Result<u64>> + Send;
}

#[derive(Clone)]
pub(crate) struct BackgroundHousekeepingCounters {
    moderation_deleted: Arc<AtomicU64>,
    failures: Arc<AtomicU64>,
}

impl BackgroundHousekeepingCounters {
    pub(crate) fn new(moderation_deleted: Arc<AtomicU64>, failures: Arc<AtomicU64>) -> Self {
        Self {
            moderation_deleted,
            failures,
        }
    }

    pub(crate) fn failures_total(&self) -> u64 {
        self.failures.load(Ordering::Relaxed)
    }

    pub(crate) fn record_failure(&self) {
        self.failures.fetch_add(1, Ordering::Relaxed);
    }

    fn record_moderation_deleted(&self, count: u64) {
        self.moderation_deleted.fetch_add(count, Ordering::Relaxed);
    }
}

pub(crate) struct BackgroundHousekeepingContext<R> {
    repository: R,
    moderation_retention_days: i64,
    moderation_batch_size: i64,
    counters: BackgroundHousekeepingCounters,
}

impl<R: BackgroundHousekeepingRepository> BackgroundHousekeepingContext<R> {
    pub(crate) fn new(
        repository: R,
        moderation_retention_days: i64,
        moderation_batch_size: i64,
        counters: BackgroundHousekeepingCounters,
    ) -> Self {
        Self {
            repository,
            moderation_retention_days,
            moderation_batch_size,
            counters,
        }
    }

    pub(crate) async fn sweep_database(&self) {
        match self
            .repository
            .purge_resolved_moderation(self.moderation_retention_days, self.moderation_batch_size)
            .await
        {
            Ok(deleted) if deleted > 0 => {
                self.counters.record_moderation_deleted(deleted);
                tracing::info!(
                    deleted,
                    retention_days = self.moderation_retention_days,
                    "expired resolved moderation cases and evidence"
                );
            }
            Ok(_) => {}
            Err(error) => {
                tracing::error!(?error, "moderation retention cleanup failed");
                self.record_failure();
            }
        }
        if let Err(error) = self.repository.cleanup_expired_sessions().await {
            tracing::error!("failed to cleanup expired sessions: {error}");
            self.record_failure();
        }
        if let Err(error) = self
            .repository
            .cleanup_expired_idempotency(CLEANUP_BATCH_SIZE)
            .await
        {
            tracing::error!("failed to cleanup expired API idempotency records: {error}");
            self.record_failure();
        }
        if let Err(error) = self.repository.cleanup_fast_tokens().await {
            tracing::error!("failed to cleanup expired FAST tokens: {error}");
            self.record_failure();
        }
        if let Err(error) = self
            .repository
            .cleanup_expired_login_epoch_stages(CLEANUP_BATCH_SIZE)
            .await
        {
            tracing::error!("failed to cleanup staged user-agent login epochs: {error}");
            self.record_failure();
        }
    }

    fn record_failure(&self) {
        self.counters.record_failure();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::metrics::Metrics;
    use std::{collections::BTreeSet, sync::Mutex};

    struct RecordingRepository {
        calls: Mutex<Vec<&'static str>>,
        failures: BTreeSet<&'static str>,
        moderation_deleted: u64,
    }

    impl RecordingRepository {
        fn run(&self, step: &'static str) -> Result<u64> {
            self.calls.lock().unwrap().push(step);
            if self.failures.contains(step) {
                anyhow::bail!("injected {step} failure");
            }
            Ok(if step == "moderation" {
                self.moderation_deleted
            } else {
                0
            })
        }
    }

    impl BackgroundHousekeepingRepository for RecordingRepository {
        async fn purge_resolved_moderation(
            &self,
            retention_days: i64,
            batch_size: i64,
        ) -> Result<u64> {
            assert_eq!((retention_days, batch_size), (30, 25));
            self.run("moderation")
        }

        async fn cleanup_expired_sessions(&self) -> Result<u64> {
            self.run("sessions")
        }

        async fn cleanup_expired_idempotency(&self, batch_size: i64) -> Result<u64> {
            assert_eq!(batch_size, CLEANUP_BATCH_SIZE);
            self.run("idempotency")
        }

        async fn cleanup_fast_tokens(&self) -> Result<u64> {
            self.run("fast")
        }

        async fn cleanup_expired_login_epoch_stages(&self, batch_size: i64) -> Result<u64> {
            assert_eq!(batch_size, CLEANUP_BATCH_SIZE);
            self.run("login_epoch")
        }
    }

    #[tokio::test]
    async fn sweep_keeps_order_and_counts_each_failure_without_skipping_later_steps() {
        let metrics = Arc::new(Metrics::default());
        let repository = RecordingRepository {
            calls: Mutex::new(Vec::new()),
            failures: BTreeSet::from(["sessions", "fast"]),
            moderation_deleted: 3,
        };
        let context = BackgroundHousekeepingContext::new(
            repository,
            30,
            25,
            BackgroundHousekeepingCounters::new(
                Arc::clone(&metrics.retention_moderation_cases_deleted_total),
                Arc::clone(&metrics.background_maintenance_failures_total),
            ),
        );
        context.sweep_database().await;
        assert_eq!(
            *context.repository.calls.lock().unwrap(),
            [
                "moderation",
                "sessions",
                "idempotency",
                "fast",
                "login_epoch"
            ]
        );
        assert_eq!(
            metrics
                .background_maintenance_failures_total
                .load(std::sync::atomic::Ordering::Relaxed),
            2
        );
        assert_eq!(
            metrics
                .retention_moderation_cases_deleted_total
                .load(std::sync::atomic::Ordering::Relaxed),
            3
        );
    }
}
