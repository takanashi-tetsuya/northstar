use crate::{config::Config, db, metrics::Metrics, state::AppState};
use chrono::Utc;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use std::time::Duration;
use tokio_util::sync::CancellationToken;

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

/// Independent-process dependencies. A standalone retention worker never
/// constructs AppState or receives the message/retraction secret keyrings.
pub(crate) struct RetentionContext {
    pool: sqlx::PgPool,
    policy: RetentionPolicy,
    metrics: Arc<Metrics>,
    readiness: RetentionReadiness,
}

impl RetentionContext {
    pub(crate) fn new(pool: sqlx::PgPool, policy: RetentionPolicy, metrics: Arc<Metrics>) -> Self {
        Self {
            pool,
            policy,
            metrics,
            readiness: RetentionReadiness::default(),
        }
    }

    pub(crate) fn readiness(&self) -> RetentionReadiness {
        self.readiness.clone()
    }
}

pub(crate) async fn run_once_context(context: &RetentionContext) -> anyhow::Result<()> {
    context.policy.validate()?;
    run_once_with(
        &context.pool,
        &context.policy,
        &context.metrics,
        Some(&context.readiness),
    )
    .await;
    Ok(())
}

pub async fn run_once(state: &AppState) {
    let policy = RetentionPolicy::from_config(&state.config);
    run_once_with(&state.pool, &policy, &state.metrics, None).await;
}

pub async fn serve(
    state: Arc<AppState>,
    cancel: CancellationToken,
    heartbeat: crate::workers::WorkerHeartbeat,
) -> anyhow::Result<()> {
    let policy = RetentionPolicy::from_config(&state.config);
    serve_with(
        &policy,
        &state.metrics,
        || async {
            run_once(&state).await;
            Ok(())
        },
        cancel,
        heartbeat,
    )
    .await
}

pub(crate) async fn serve_context(
    context: Arc<RetentionContext>,
    cancel: CancellationToken,
    heartbeat: crate::workers::WorkerHeartbeat,
) -> anyhow::Result<()> {
    serve_with(
        &context.policy,
        &context.metrics,
        || run_once_context(&context),
        cancel,
        heartbeat,
    )
    .await
}

#[derive(Clone, Copy)]
struct RetentionTarget {
    store: db::RetentionStore,
    days: i64,
}

async fn run_once_with(
    pool: &sqlx::PgPool,
    policy: &RetentionPolicy,
    metrics: &Metrics,
    readiness: Option<&RetentionReadiness>,
) {
    // Cancellation or a panic cannot publish an unfinished pass as healthy.
    if let Some(readiness) = readiness {
        readiness.ready.store(false, Ordering::Release);
    }
    let failures_before = metrics
        .retention_cleanup_failures_total
        .load(Ordering::Relaxed);
    let now = Utc::now();
    let targets = [
        RetentionTarget {
            store: db::RetentionStore::PersonalMam,
            days: policy.mam_retention_days,
        },
        RetentionTarget {
            store: db::RetentionStore::MucMam,
            days: policy.muc_mam_retention_days,
        },
        RetentionTarget {
            store: db::RetentionStore::OfflineMessages,
            days: policy.offline_message_ttl_days,
        },
        // Delivery-only XEP-0359 tombstones retain only a purpose-separated
        // keyed content commitment. Their replay grace is fixed and must
        // remain bounded even when offline content retention is disabled.
        RetentionTarget {
            store: db::RetentionStore::PersonalDeliveryAdmissions,
            days: 30,
        },
    ];

    for target in targets {
        match db::purge_resolved_retention_batch(
            pool,
            target.store,
            now,
            target.days,
            policy.retention_cleanup_batch_size,
        )
        .await
        {
            Ok(deleted) => {
                match target.store {
                    db::RetentionStore::PersonalMam => metrics
                        .retention_personal_mam_deleted_total
                        .fetch_add(deleted, Ordering::Relaxed),
                    db::RetentionStore::MucMam => metrics
                        .retention_muc_mam_deleted_total
                        .fetch_add(deleted, Ordering::Relaxed),
                    db::RetentionStore::OfflineMessages => metrics
                        .retention_offline_messages_deleted_total
                        .fetch_add(deleted, Ordering::Relaxed),
                    db::RetentionStore::PersonalDeliveryAdmissions => metrics
                        .retention_personal_delivery_admissions_deleted_total
                        .fetch_add(deleted, Ordering::Relaxed),
                };
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
                metrics
                    .retention_cleanup_failures_total
                    .fetch_add(1, Ordering::Relaxed);
                metrics
                    .background_maintenance_failures_total
                    .fetch_add(1, Ordering::Relaxed);
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

    match db::purge_released_hold_snapshots_batch(
        pool,
        policy.offline_message_ttl_days,
        policy.retention_cleanup_batch_size,
    )
    .await
    {
        Ok(deleted) if deleted > 0 => {
            metrics
                .retention_legal_hold_snapshots_deleted_total
                .fetch_add(deleted, Ordering::Relaxed);
        }
        Ok(_) => {}
        Err(error) => {
            metrics
                .retention_cleanup_failures_total
                .fetch_add(1, Ordering::Relaxed);
            metrics
                .background_maintenance_failures_total
                .fetch_add(1, Ordering::Relaxed);
            tracing::error!(?error, "released legal-hold snapshot cleanup failed");
        }
    }

    match db::purge_audit_log_batch(
        pool,
        policy.audit_log_retention_days,
        policy.retention_cleanup_batch_size,
    )
    .await
    {
        Ok(deleted) if deleted > 0 => {
            metrics
                .retention_audit_log_deleted_total
                .fetch_add(deleted, Ordering::Relaxed);
        }
        Ok(_) => {}
        Err(error) => {
            metrics
                .retention_cleanup_failures_total
                .fetch_add(1, Ordering::Relaxed);
            metrics
                .background_maintenance_failures_total
                .fetch_add(1, Ordering::Relaxed);
            tracing::error!(?error, "bounded audit-log cleanup failed");
        }
    }

    match db::purge_governance_export_leases_batch(
        pool,
        policy.audit_log_retention_days,
        policy.retention_cleanup_batch_size,
    )
    .await
    {
        Ok(deleted) if deleted > 0 => {
            metrics
                .retention_governance_export_leases_deleted_total
                .fetch_add(deleted, Ordering::Relaxed);
        }
        Ok(_) => {}
        Err(error) => {
            metrics
                .retention_cleanup_failures_total
                .fetch_add(1, Ordering::Relaxed);
            metrics
                .background_maintenance_failures_total
                .fetch_add(1, Ordering::Relaxed);
            tracing::error!(?error, "bounded governance-export lease cleanup failed");
        }
    }

    match db::cleanup_omemo_recovery_transfers(
        pool,
        policy.retention_cleanup_batch_size.clamp(1, 10_000),
    )
    .await
    {
        Ok(deleted) if deleted > 0 => {
            metrics
                .retention_omemo_recovery_transfers_deleted_total
                .fetch_add(deleted, Ordering::Relaxed);
        }
        Ok(_) => {}
        Err(error) => {
            metrics
                .retention_cleanup_failures_total
                .fetch_add(1, Ordering::Relaxed);
            metrics
                .background_maintenance_failures_total
                .fetch_add(1, Ordering::Relaxed);
            tracing::error!(?error, "bounded OMEMO recovery-transfer cleanup failed");
        }
    }

    match db::purge_expired_retraction_intents(
        pool,
        policy.retention_cleanup_batch_size.clamp(1, 10_000),
    )
    .await
    {
        Ok(deleted) if deleted > 0 => {
            tracing::info!(deleted, "expired personal retraction intents removed");
        }
        Ok(_) => {}
        Err(error) => {
            metrics
                .retention_cleanup_failures_total
                .fetch_add(1, Ordering::Relaxed);
            metrics
                .background_maintenance_failures_total
                .fetch_add(1, Ordering::Relaxed);
            tracing::error!(?error, "bounded personal-retraction intent cleanup failed");
        }
    }
    if let Some(readiness) = readiness {
        let successful = metrics
            .retention_cleanup_failures_total
            .load(Ordering::Relaxed)
            == failures_before;
        readiness.ready.store(successful, Ordering::Release);
    }
}

async fn serve_with<F, Fut>(
    policy: &RetentionPolicy,
    metrics: &Metrics,
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
                let failures_before = metrics
                    .retention_cleanup_failures_total
                    .load(Ordering::Relaxed);
                run_pass().await?;
                let failures_after = metrics
                    .retention_cleanup_failures_total
                    .load(Ordering::Relaxed);
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

    #[test]
    fn all_automated_targets_exclude_evidence_and_policy_tables() {
        let labels = [
            db::RetentionStore::PersonalMam.label(),
            db::RetentionStore::MucMam.label(),
            db::RetentionStore::OfflineMessages.label(),
            db::RetentionStore::PersonalDeliveryAdmissions.label(),
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
