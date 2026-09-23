use crate::{config::Config, metrics::Metrics};
use chrono::Utc;
use std::sync::{
    atomic::{AtomicBool, AtomicU64, Ordering},
    Arc,
};
use std::time::Duration;
use tokio_util::sync::CancellationToken;

/// A separately bounded retention source. These are intentionally the only
/// tables touched by automated history cleanup. In particular, reports,
/// appeals, copied report evidence, moderation state, and the audit log are
/// outside this enum and cannot be selected by a retention sweep.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RetentionStore {
    PersonalMam,
    MucMam,
    OfflineMessages,
    PersonalDeliveryAdmissions,
}

impl RetentionStore {
    pub fn label(self) -> &'static str {
        match self {
            Self::PersonalMam => "personal_mam",
            Self::MucMam => "muc_mam",
            Self::OfflineMessages => "offline_messages",
            Self::PersonalDeliveryAdmissions => "personal_delivery_admissions",
        }
    }
}

pub(crate) trait RetentionRepository: Send + Sync {
    fn purge_resolved_retention_batch(
        &self,
        store: RetentionStore,
        now: chrono::DateTime<Utc>,
        days: i64,
        batch_size: i64,
    ) -> impl std::future::Future<Output = anyhow::Result<u64>> + Send;
    fn purge_released_hold_snapshots_batch(
        &self,
        days: i64,
        batch_size: i64,
    ) -> impl std::future::Future<Output = anyhow::Result<u64>> + Send;
    fn purge_audit_log_batch(
        &self,
        days: i64,
        batch_size: i64,
    ) -> impl std::future::Future<Output = anyhow::Result<u64>> + Send;
    fn purge_governance_export_leases_batch(
        &self,
        days: i64,
        batch_size: i64,
    ) -> impl std::future::Future<Output = anyhow::Result<u64>> + Send;
    fn cleanup_omemo_recovery_transfers(
        &self,
        batch_size: i64,
    ) -> impl std::future::Future<Output = anyhow::Result<u64>> + Send;
    fn purge_expired_retraction_intents(
        &self,
        batch_size: i64,
    ) -> impl std::future::Future<Output = anyhow::Result<u64>> + Send;
}

/// The complete retention policy. This value carries no listener, identity,
/// cryptographic key or live-session authority.
#[derive(Clone, Debug)]
pub(crate) struct RetentionPolicy {
    pub(crate) mam_retention_days: i64,
    pub(crate) muc_mam_retention_days: i64,
    pub(crate) offline_message_ttl_days: i64,
    pub(crate) audit_log_retention_days: i64,
    pub(crate) retention_cleanup_batch_size: i64,
    pub(crate) retention_cleanup_interval_seconds: u64,
}

impl RetentionPolicy {
    pub(crate) fn from_config(config: &Config) -> Self {
        Self {
            mam_retention_days: config.mam_retention_days,
            muc_mam_retention_days: config.muc_mam_retention_days,
            offline_message_ttl_days: config.offline_message_ttl_days,
            audit_log_retention_days: config.audit_log_retention_days,
            retention_cleanup_batch_size: config.retention_cleanup_batch_size,
            retention_cleanup_interval_seconds: config.retention_cleanup_interval_seconds,
        }
    }

    pub(crate) fn validate(&self) -> anyhow::Result<()> {
        anyhow::ensure!(
            (0..=3650).contains(&self.offline_message_ttl_days)
                && (0..=36_500).contains(&self.mam_retention_days)
                && (0..=36_500).contains(&self.muc_mam_retention_days),
            "retention days must be zero (disabled) or within the documented maximum"
        );
        anyhow::ensure!(
            (30..=36_500).contains(&self.audit_log_retention_days),
            "AUDIT_LOG_RETENTION_DAYS must be between 30 and 36500"
        );
        anyhow::ensure!(
            (1..=10_000).contains(&self.retention_cleanup_batch_size)
                && (60..=86_400).contains(&self.retention_cleanup_interval_seconds),
            "retention cleanup batch size must be 1..10000 and interval 60..86400 seconds"
        );
        Ok(())
    }
}

/// Read-only process health, separate from database and cleanup authority.
/// Readiness requires a completed successful pass, including after a retry.
#[derive(Clone, Default)]
pub(crate) struct RetentionReadiness {
    ready: Arc<AtomicBool>,
}

impl RetentionReadiness {
    pub(crate) fn is_ready(&self) -> bool {
        self.ready.load(Ordering::Acquire)
    }

    pub(crate) fn begin_pass(&self) {
        self.ready.store(false, Ordering::Release);
    }

    pub(crate) fn complete_pass(&self) {
        self.ready.store(true, Ordering::Release);
    }

    #[cfg(test)]
    pub(crate) fn for_test(ready: bool) -> Self {
        let health = Self::default();
        health.set_for_test(ready);
        health
    }

    #[cfg(test)]
    pub(crate) fn set_for_test(&self, ready: bool) {
        self.ready.store(ready, Ordering::Release);
    }
}

/// Only the counter cells needed by archive retention. Clones share the
/// process metrics without granting the worker access to unrelated gauges.
#[derive(Clone)]
pub(crate) struct RetentionCounters {
    personal_mam_deleted: Arc<AtomicU64>,
    muc_mam_deleted: Arc<AtomicU64>,
    offline_messages_deleted: Arc<AtomicU64>,
    personal_delivery_admissions_deleted: Arc<AtomicU64>,
    legal_hold_snapshots_deleted: Arc<AtomicU64>,
    audit_log_deleted: Arc<AtomicU64>,
    governance_export_leases_deleted: Arc<AtomicU64>,
    omemo_recovery_transfers_deleted: Arc<AtomicU64>,
    cleanup_failures: Arc<AtomicU64>,
    background_maintenance_failures: Arc<AtomicU64>,
}

impl RetentionCounters {
    pub(crate) fn from_metrics(metrics: &Metrics) -> Self {
        Self {
            personal_mam_deleted: Arc::clone(&metrics.retention_personal_mam_deleted_total),
            muc_mam_deleted: Arc::clone(&metrics.retention_muc_mam_deleted_total),
            offline_messages_deleted: Arc::clone(&metrics.retention_offline_messages_deleted_total),
            personal_delivery_admissions_deleted: Arc::clone(
                &metrics.retention_personal_delivery_admissions_deleted_total,
            ),
            legal_hold_snapshots_deleted: Arc::clone(
                &metrics.retention_legal_hold_snapshots_deleted_total,
            ),
            audit_log_deleted: Arc::clone(&metrics.retention_audit_log_deleted_total),
            governance_export_leases_deleted: Arc::clone(
                &metrics.retention_governance_export_leases_deleted_total,
            ),
            omemo_recovery_transfers_deleted: Arc::clone(
                &metrics.retention_omemo_recovery_transfers_deleted_total,
            ),
            cleanup_failures: Arc::clone(&metrics.retention_cleanup_failures_total),
            background_maintenance_failures: Arc::clone(
                &metrics.background_maintenance_failures_total,
            ),
        }
    }

    fn failures_total(&self) -> u64 {
        self.cleanup_failures.load(Ordering::Relaxed)
    }

    fn record_failure(&self) {
        self.cleanup_failures.fetch_add(1, Ordering::Relaxed);
        self.background_maintenance_failures
            .fetch_add(1, Ordering::Relaxed);
    }

    fn record_deleted(&self, store: RetentionStore, deleted: u64) {
        let counter = match store {
            RetentionStore::PersonalMam => &self.personal_mam_deleted,
            RetentionStore::MucMam => &self.muc_mam_deleted,
            RetentionStore::OfflineMessages => &self.offline_messages_deleted,
            RetentionStore::PersonalDeliveryAdmissions => {
                &self.personal_delivery_admissions_deleted
            }
        };
        counter.fetch_add(deleted, Ordering::Relaxed);
    }
}

/// Shared by embedded and standalone retention workers. It carries no
/// listener, routing or content-key capabilities.
pub(crate) struct RetentionContext<R> {
    repository: R,
    policy: RetentionPolicy,
    counters: RetentionCounters,
    readiness: RetentionReadiness,
}

impl<R: RetentionRepository> RetentionContext<R> {
    pub(crate) fn new(repository: R, policy: RetentionPolicy, counters: RetentionCounters) -> Self {
        Self {
            repository,
            policy,
            counters,
            readiness: RetentionReadiness::default(),
        }
    }

    pub(crate) fn readiness(&self) -> RetentionReadiness {
        self.readiness.clone()
    }
}

pub(crate) async fn run_once_context<R: RetentionRepository>(
    context: &RetentionContext<R>,
) -> anyhow::Result<()> {
    context.policy.validate()?;
    run_once_with(
        &context.repository,
        &context.policy,
        &context.counters,
        Some(&context.readiness),
    )
    .await;
    Ok(())
}

pub(crate) async fn serve_context<R: RetentionRepository>(
    context: Arc<RetentionContext<R>>,
    cancel: CancellationToken,
    heartbeat: crate::workers::WorkerHeartbeat,
) -> anyhow::Result<()> {
    serve_with(
        &context.policy,
        &context.counters,
        || run_once_context(&context),
        cancel,
        heartbeat,
    )
    .await
}

#[derive(Clone, Copy)]
struct RetentionTarget {
    store: RetentionStore,
    days: i64,
}

async fn run_once_with<R: RetentionRepository>(
    repository: &R,
    policy: &RetentionPolicy,
    counters: &RetentionCounters,
    readiness: Option<&RetentionReadiness>,
) {
    // Cancellation or a panic cannot publish an unfinished pass as healthy.
    if let Some(readiness) = readiness {
        readiness.ready.store(false, Ordering::Release);
    }
    let failures_before = counters.failures_total();
    let now = Utc::now();
    let targets = [
        RetentionTarget {
            store: RetentionStore::PersonalMam,
            days: policy.mam_retention_days,
        },
        RetentionTarget {
            store: RetentionStore::MucMam,
            days: policy.muc_mam_retention_days,
        },
        RetentionTarget {
            store: RetentionStore::OfflineMessages,
            days: policy.offline_message_ttl_days,
        },
        // Delivery-only XEP-0359 tombstones retain only a purpose-separated
        // keyed content commitment. Their replay grace is fixed and must
        // remain bounded even when offline content retention is disabled.
        RetentionTarget {
            store: RetentionStore::PersonalDeliveryAdmissions,
            days: 30,
        },
    ];

    for target in targets {
        match repository
            .purge_resolved_retention_batch(
                target.store,
                now,
                target.days,
                policy.retention_cleanup_batch_size,
            )
            .await
        {
            Ok(deleted) => {
                counters.record_deleted(target.store, deleted);
                if deleted > 0 {
                    tracing::info!(
                        store = target.store.label(),
                        retention_days = target.days,
                        batch_size = policy.retention_cleanup_batch_size,
                        deleted,
                        "archive retention batch completed"
                    );
                }
            }
            Err(error) => {
                counters.record_failure();
                // Continue with the next store. Each target is independently
                // retryable on the following tick and never blocks listeners.
                tracing::error!(
                    store = target.store.label(),
                    retention_days = target.days,
                    ?error,
                    "archive retention batch failed; it will be retried"
                );
            }
        }
    }

    match repository
        .purge_released_hold_snapshots_batch(
            policy.offline_message_ttl_days,
            policy.retention_cleanup_batch_size,
        )
        .await
    {
        Ok(deleted) if deleted > 0 => {
            counters
                .legal_hold_snapshots_deleted
                .fetch_add(deleted, Ordering::Relaxed);
        }
        Ok(_) => {}
        Err(error) => {
            counters.record_failure();
            tracing::error!(?error, "released legal-hold snapshot cleanup failed");
        }
    }

    match repository
        .purge_audit_log_batch(
            policy.audit_log_retention_days,
            policy.retention_cleanup_batch_size,
        )
        .await
    {
        Ok(deleted) if deleted > 0 => {
            counters
                .audit_log_deleted
                .fetch_add(deleted, Ordering::Relaxed);
        }
        Ok(_) => {}
        Err(error) => {
            counters.record_failure();
            tracing::error!(?error, "bounded audit-log cleanup failed");
        }
    }

    match repository
        .purge_governance_export_leases_batch(
            policy.audit_log_retention_days,
            policy.retention_cleanup_batch_size,
        )
        .await
    {
        Ok(deleted) if deleted > 0 => {
            counters
                .governance_export_leases_deleted
                .fetch_add(deleted, Ordering::Relaxed);
        }
        Ok(_) => {}
        Err(error) => {
            counters.record_failure();
            tracing::error!(?error, "bounded governance-export lease cleanup failed");
        }
    }

    match repository
        .cleanup_omemo_recovery_transfers(policy.retention_cleanup_batch_size.clamp(1, 10_000))
        .await
    {
        Ok(deleted) if deleted > 0 => {
            counters
                .omemo_recovery_transfers_deleted
                .fetch_add(deleted, Ordering::Relaxed);
        }
        Ok(_) => {}
        Err(error) => {
            counters.record_failure();
            tracing::error!(?error, "bounded OMEMO recovery-transfer cleanup failed");
        }
    }

    match repository
        .purge_expired_retraction_intents(policy.retention_cleanup_batch_size.clamp(1, 10_000))
        .await
    {
        Ok(deleted) if deleted > 0 => {
            tracing::info!(deleted, "expired personal retraction intents removed");
        }
        Ok(_) => {}
        Err(error) => {
            counters.record_failure();
            tracing::error!(?error, "bounded personal-retraction intent cleanup failed");
        }
    }
    if let Some(readiness) = readiness {
        let successful = counters.failures_total() == failures_before;
        readiness.ready.store(successful, Ordering::Release);
    }
}

async fn serve_with<F, Fut>(
    policy: &RetentionPolicy,
    counters: &RetentionCounters,
    mut run_pass: F,
    cancel: CancellationToken,
    heartbeat: crate::workers::WorkerHeartbeat,
) -> anyhow::Result<()>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = anyhow::Result<()>>,
{
    policy.validate()?;
    let mut interval = tokio::time::interval(Duration::from_secs(
        policy.retention_cleanup_interval_seconds,
    ));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        tokio::select! {
            _ = cancel.cancelled() => return Ok(()),
            _ = interval.tick() => {
                let failures_before = counters.failures_total();
                run_pass().await?;
                let failures_after = counters.failures_total();
                if failures_after == failures_before {
                    heartbeat.ok();
                } else {
                    heartbeat.error("one or more archive retention targets failed");
                }
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{collections::BTreeSet, sync::Mutex};

    #[derive(Default)]
    struct RecordingRepository {
        calls: Mutex<Vec<&'static str>>,
        failures: Mutex<BTreeSet<&'static str>>,
    }

    impl RecordingRepository {
        fn record(&self, name: &'static str, deleted: u64) -> anyhow::Result<u64> {
            self.calls.lock().unwrap().push(name);
            if self.failures.lock().unwrap().contains(name) {
                anyhow::bail!("{name} failed");
            }
            Ok(deleted)
        }
    }

    impl RetentionRepository for RecordingRepository {
        async fn purge_resolved_retention_batch(
            &self,
            store: RetentionStore,
            _now: chrono::DateTime<Utc>,
            _days: i64,
            _batch_size: i64,
        ) -> anyhow::Result<u64> {
            match store {
                RetentionStore::PersonalMam => self.record("personal_mam", 1),
                RetentionStore::MucMam => self.record("muc_mam", 2),
                RetentionStore::OfflineMessages => self.record("offline", 3),
                RetentionStore::PersonalDeliveryAdmissions => self.record("admissions", 4),
            }
        }

        async fn purge_released_hold_snapshots_batch(
            &self,
            _days: i64,
            _batch_size: i64,
        ) -> anyhow::Result<u64> {
            self.record("legal_hold", 5)
        }

        async fn purge_audit_log_batch(&self, _days: i64, _batch_size: i64) -> anyhow::Result<u64> {
            self.record("audit", 6)
        }

        async fn purge_governance_export_leases_batch(
            &self,
            _days: i64,
            _batch_size: i64,
        ) -> anyhow::Result<u64> {
            self.record("export_leases", 7)
        }

        async fn cleanup_omemo_recovery_transfers(&self, _batch_size: i64) -> anyhow::Result<u64> {
            self.record("omemo", 8)
        }

        async fn purge_expired_retraction_intents(&self, _batch_size: i64) -> anyhow::Result<u64> {
            self.record("retractions", 9)
        }
    }

    #[tokio::test]
    async fn narrow_counters_keep_per_target_results_and_readiness_retry() {
        let metrics = Metrics::default();
        let repository = RecordingRepository::default();
        repository
            .failures
            .lock()
            .unwrap()
            .extend(["offline", "audit", "retractions"]);
        let context = RetentionContext::new(
            repository,
            RetentionPolicy {
                mam_retention_days: 30,
                muc_mam_retention_days: 30,
                offline_message_ttl_days: 30,
                audit_log_retention_days: 30,
                retention_cleanup_batch_size: 25,
                retention_cleanup_interval_seconds: 60,
            },
            RetentionCounters::from_metrics(&metrics),
        );

        run_once_context(&context).await.unwrap();
        assert!(!context.readiness().is_ready());
        assert_eq!(
            *context.repository.calls.lock().unwrap(),
            [
                "personal_mam",
                "muc_mam",
                "offline",
                "admissions",
                "legal_hold",
                "audit",
                "export_leases",
                "omemo",
                "retractions"
            ]
        );
        assert_eq!(
            metrics
                .retention_personal_mam_deleted_total
                .load(Ordering::Relaxed),
            1
        );
        assert_eq!(
            metrics
                .retention_muc_mam_deleted_total
                .load(Ordering::Relaxed),
            2
        );
        assert_eq!(
            metrics
                .retention_offline_messages_deleted_total
                .load(Ordering::Relaxed),
            0
        );
        assert_eq!(
            metrics
                .retention_personal_delivery_admissions_deleted_total
                .load(Ordering::Relaxed),
            4
        );
        assert_eq!(
            metrics
                .retention_legal_hold_snapshots_deleted_total
                .load(Ordering::Relaxed),
            5
        );
        assert_eq!(
            metrics
                .retention_audit_log_deleted_total
                .load(Ordering::Relaxed),
            0
        );
        assert_eq!(
            metrics
                .retention_governance_export_leases_deleted_total
                .load(Ordering::Relaxed),
            7
        );
        assert_eq!(
            metrics
                .retention_omemo_recovery_transfers_deleted_total
                .load(Ordering::Relaxed),
            8
        );
        assert_eq!(context.counters.failures_total(), 3);
        assert_eq!(
            metrics
                .background_maintenance_failures_total
                .load(Ordering::Relaxed),
            3
        );

        context.repository.failures.lock().unwrap().clear();
        run_once_context(&context).await.unwrap();
        assert!(context.readiness().is_ready());
        assert_eq!(context.counters.failures_total(), 3);
        assert_eq!(
            metrics
                .background_maintenance_failures_total
                .load(Ordering::Relaxed),
            3
        );
        assert_eq!(
            metrics
                .retention_offline_messages_deleted_total
                .load(Ordering::Relaxed),
            3
        );
        assert_eq!(
            metrics
                .retention_audit_log_deleted_total
                .load(Ordering::Relaxed),
            6
        );
    }

    #[test]
    fn all_automated_targets_exclude_evidence_and_policy_tables() {
        let labels = [
            RetentionStore::PersonalMam.label(),
            RetentionStore::MucMam.label(),
            RetentionStore::OfflineMessages.label(),
            RetentionStore::PersonalDeliveryAdmissions.label(),
        ];
        assert_eq!(
            labels,
            [
                "personal_mam",
                "muc_mam",
                "offline_messages",
                "personal_delivery_admissions"
            ]
        );
        for protected in [
            "abuse_reports",
            "abuse_report_evidence",
            "abuse_appeals",
            "audit_log",
            "mam_preferences",
        ] {
            assert!(!labels.contains(&protected));
        }
    }
}
