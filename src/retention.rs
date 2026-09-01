use crate::{db, state::AppState};
use chrono::Utc;
use std::sync::{atomic::Ordering, Arc};
use std::time::Duration;
use tokio_util::sync::CancellationToken;

#[derive(Clone, Copy)]
struct RetentionTarget {
    store: db::RetentionStore,
    days: i64,
}

pub async fn run_once(state: &AppState) {
    let now = Utc::now();
    let targets = [
        RetentionTarget {
            store: db::RetentionStore::PersonalMam,
            days: state.config.mam_retention_days,
        },
        RetentionTarget {
            store: db::RetentionStore::MucMam,
            days: state.config.muc_mam_retention_days,
        },
        RetentionTarget {
            store: db::RetentionStore::OfflineMessages,
            days: state.config.offline_message_ttl_days,
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
            &state.pool,
            target.store,
            now,
            target.days,
            state.config.retention_cleanup_batch_size,
        )
        .await
        {
            Ok(deleted) => {
                match target.store {
                    db::RetentionStore::PersonalMam => state
                        .metrics
                        .retention_personal_mam_deleted_total
                        .fetch_add(deleted, Ordering::Relaxed),
                    db::RetentionStore::MucMam => state
                        .metrics
                        .retention_muc_mam_deleted_total
                        .fetch_add(deleted, Ordering::Relaxed),
                    db::RetentionStore::OfflineMessages => state
                        .metrics
                        .retention_offline_messages_deleted_total
                        .fetch_add(deleted, Ordering::Relaxed),
                    db::RetentionStore::PersonalDeliveryAdmissions => state
                        .metrics
                        .retention_personal_delivery_admissions_deleted_total
                        .fetch_add(deleted, Ordering::Relaxed),
                };
                if deleted > 0 {
                    tracing::info!(
                        store = target.store.label(),
                        retention_days = target.days,
                        batch_size = state.config.retention_cleanup_batch_size,
                        deleted,
                        "archive retention batch completed"
                    );
                }
            }
            Err(error) => {
                state
                    .metrics
                    .retention_cleanup_failures_total
                    .fetch_add(1, Ordering::Relaxed);
                state
                    .metrics
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
        &state.pool,
        state.config.offline_message_ttl_days,
        state.config.retention_cleanup_batch_size,
    )
    .await
    {
        Ok(deleted) if deleted > 0 => {
            state
                .metrics
                .retention_legal_hold_snapshots_deleted_total
                .fetch_add(deleted, Ordering::Relaxed);
        }
        Ok(_) => {}
        Err(error) => {
            state
                .metrics
                .retention_cleanup_failures_total
                .fetch_add(1, Ordering::Relaxed);
            state
                .metrics
                .background_maintenance_failures_total
                .fetch_add(1, Ordering::Relaxed);
            tracing::error!(?error, "released legal-hold snapshot cleanup failed");
        }
    }

    match db::purge_audit_log_batch(
        &state.pool,
        state.config.audit_log_retention_days,
        state.config.retention_cleanup_batch_size,
    )
    .await
    {
        Ok(deleted) if deleted > 0 => {
            state
                .metrics
                .retention_audit_log_deleted_total
                .fetch_add(deleted, Ordering::Relaxed);
        }
        Ok(_) => {}
        Err(error) => {
            state
                .metrics
                .retention_cleanup_failures_total
                .fetch_add(1, Ordering::Relaxed);
            state
                .metrics
                .background_maintenance_failures_total
                .fetch_add(1, Ordering::Relaxed);
            tracing::error!(?error, "bounded audit-log cleanup failed");
        }
    }

    match db::purge_governance_export_leases_batch(
        &state.pool,
        state.config.audit_log_retention_days,
        state.config.retention_cleanup_batch_size,
    )
    .await
    {
        Ok(deleted) if deleted > 0 => {
            state
                .metrics
                .retention_governance_export_leases_deleted_total
                .fetch_add(deleted, Ordering::Relaxed);
        }
        Ok(_) => {}
        Err(error) => {
            state
                .metrics
                .retention_cleanup_failures_total
                .fetch_add(1, Ordering::Relaxed);
            state
                .metrics
                .background_maintenance_failures_total
                .fetch_add(1, Ordering::Relaxed);
            tracing::error!(?error, "bounded governance-export lease cleanup failed");
        }
    }

    match db::cleanup_omemo_recovery_transfers(
        &state.pool,
        state.config.retention_cleanup_batch_size.clamp(1, 10_000),
    )
    .await
    {
        Ok(deleted) if deleted > 0 => {
            state
                .metrics
                .retention_omemo_recovery_transfers_deleted_total
                .fetch_add(deleted, Ordering::Relaxed);
        }
        Ok(_) => {}
        Err(error) => {
            state
                .metrics
                .retention_cleanup_failures_total
                .fetch_add(1, Ordering::Relaxed);
            state
                .metrics
                .background_maintenance_failures_total
                .fetch_add(1, Ordering::Relaxed);
            tracing::error!(?error, "bounded OMEMO recovery-transfer cleanup failed");
        }
    }

    match state
        .retraction_service()
        .purge_expired_intents(state.config.retention_cleanup_batch_size.clamp(1, 10_000))
        .await
    {
        Ok(deleted) if deleted > 0 => {
            tracing::info!(deleted, "expired personal retraction intents removed");
        }
        Ok(_) => {}
        Err(error) => {
            state
                .metrics
                .retention_cleanup_failures_total
                .fetch_add(1, Ordering::Relaxed);
            state
                .metrics
                .background_maintenance_failures_total
                .fetch_add(1, Ordering::Relaxed);
            tracing::error!(?error, "bounded personal-retraction intent cleanup failed");
        }
    }
}

pub async fn serve(
    state: Arc<AppState>,
    cancel: CancellationToken,
    heartbeat: crate::workers::WorkerHeartbeat,
) -> anyhow::Result<()> {
    let mut interval = tokio::time::interval(Duration::from_secs(
        state.config.retention_cleanup_interval_seconds,
    ));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        tokio::select! {
            _ = cancel.cancelled() => return Ok(()),
            _ = interval.tick() => {
                let failures_before = state
                    .metrics
                    .retention_cleanup_failures_total
                    .load(Ordering::Relaxed);
                run_once(&state).await;
                let failures_after = state
                    .metrics
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
