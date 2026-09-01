use crate::{db, state::AppState, workers::WorkerHeartbeat};
use anyhow::{Context, Result};
use futures::{stream, StreamExt};
use std::{
    sync::{atomic::Ordering, Arc},
    time::Duration,
};
use tokio_util::sync::CancellationToken;

const STORAGE_OPERATION_TIMEOUT: Duration = Duration::from_secs(180);
const CAPACITY_AUTHORITY_AUDIT_INTERVAL: Duration = Duration::from_secs(60);
const CAPACITY_AUTHORITY_AUDIT_RETRY_INTERVAL: Duration = Duration::from_secs(15);
const CAPACITY_LEDGER_AUDIT_INTERVAL: Duration = Duration::from_secs(60 * 60);
const CAPACITY_LEDGER_AUDIT_DEGRADED_INTERVAL: Duration = Duration::from_secs(5 * 60);
const CAPACITY_LEDGER_AUDIT_RETRY_INTERVAL: Duration = Duration::from_secs(60);

pub async fn serve(
    state: Arc<AppState>,
    cancel: CancellationToken,
    heartbeat: WorkerHeartbeat,
) -> Result<()> {
    let mut interval = tokio::time::interval(Duration::from_secs(5));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut credential_ticks = 0_u8;
    let mut next_capacity_authority_audit = tokio::time::Instant::now();
    let mut capacity_authority_violations = 0_u64;
    let mut next_capacity_ledger_audit = tokio::time::Instant::now();
    let mut capacity_ledger_mismatches = 0_u64;
    loop {
        tokio::select! {
            _ = cancel.cancelled() => return Ok(()),
            _ = interval.tick() => {}
        }
        let mut failures = 0_u64;
        state
            .metrics
            .upload_storage_safety_gate_state
            .store(state.upload_safety_gate().metric_code(), Ordering::Relaxed);
        let authority_generation = state.upload_authority_generation();
        let recovery_draining = match db::upload_storage_authority_matches(
            &state.pool,
            state.upload_store().backend(),
            state.upload_storage_namespace_sha256(),
            authority_generation.namespace,
            authority_generation.capacity_policy,
            state.config.upload_storage_max_pending_jobs,
            state.config.upload_storage_max_retained_files,
            state.config.upload_storage_max_retained_bytes,
        )
        .await
        {
            Ok(probe) if !probe.namespace_matches => {
                state.upload_safety_gate().mark_namespace_unsafe(
                    "upload namespace authority changed while this process was running",
                );
                state
                    .metrics
                    .upload_storage_safety_gate_state
                    .store(state.upload_safety_gate().metric_code(), Ordering::Relaxed);
                anyhow::bail!(
                    "upload storage authority disappeared or changed while this process was running"
                );
            }
            Ok(probe) if !probe.capacity_matches => {
                state.upload_safety_gate().mark_capacity_authority_unsafe(
                    "upload capacity policy generation changed while this process was running",
                );
                heartbeat.error("upload capacity authority changed");
                continue;
            }
            Ok(probe) => probe.recovery_draining,
            Err(error) => {
                state.upload_safety_gate().mark_capacity_authority_unsafe(
                    "upload authority could not be proved from PostgreSQL",
                );
                note_reconciliation_failure(&state);
                tracing::error!(
                    ?error,
                    "could not verify upload-storage authority; skipping object I/O"
                );
                heartbeat.error("could not verify immutable upload-storage authority");
                continue;
            }
        };
        if tokio::time::Instant::now() >= next_capacity_authority_audit {
            match db::audit_upload_capacity_authority(
                &state.pool,
                state.config.upload_storage_max_pending_jobs,
                state.config.upload_storage_max_retained_files,
                state.config.upload_storage_max_retained_bytes,
            )
            .await
            {
                Ok(audit) => {
                    capacity_authority_violations = audit.violation_count();
                    state
                        .metrics
                        .upload_storage_capacity_authority_violations
                        .store(capacity_authority_violations, Ordering::Relaxed);
                    next_capacity_authority_audit =
                        tokio::time::Instant::now() + CAPACITY_AUTHORITY_AUDIT_INTERVAL;
                    if capacity_authority_violations > 0 {
                        state.upload_safety_gate().mark_capacity_authority_unsafe(
                            "upload catalog or ACL authority audit failed",
                        );
                        note_reconciliation_failure(&state);
                        tracing::error!(
                            capacity_authority_violations,
                            relation_owner_violations = audit.relation_owner_violations,
                            relation_acl_violations = audit.relation_acl_violations,
                            function_authority_violations = audit.function_authority_violations,
                            trigger_authority_violations = audit.trigger_authority_violations,
                            policy_binding_violations = audit.policy_binding_violations,
                            "upload capacity enforcement authority changed; refusing object I/O"
                        );
                    }
                }
                Err(error) => {
                    state.upload_safety_gate().mark_capacity_authority_unsafe(
                        "upload catalog or ACL authority could not be proved",
                    );
                    capacity_authority_violations = capacity_authority_violations.max(1);
                    state
                        .metrics
                        .upload_storage_capacity_authority_violations
                        .store(capacity_authority_violations, Ordering::Relaxed);
                    next_capacity_authority_audit =
                        tokio::time::Instant::now() + CAPACITY_AUTHORITY_AUDIT_RETRY_INTERVAL;
                    note_reconciliation_failure(&state);
                    tracing::error!(
                        ?error,
                        "could not verify upload capacity enforcement authority; retrying without object I/O"
                    );
                }
            }
        }
        if capacity_authority_violations > 0 {
            heartbeat.error("upload capacity enforcement authority is unproven");
            continue;
        }
        if tokio::time::Instant::now() >= next_capacity_ledger_audit {
            match db::reconcile_upload_capacity_ledger(&state.pool).await {
                Ok(audit) => {
                    capacity_ledger_mismatches = audit.mismatch_count();
                    state
                        .metrics
                        .upload_storage_capacity_ledger_mismatches
                        .store(capacity_ledger_mismatches, Ordering::Relaxed);
                    if capacity_ledger_mismatches == 0 {
                        next_capacity_ledger_audit =
                            tokio::time::Instant::now() + CAPACITY_LEDGER_AUDIT_INTERVAL;
                    } else {
                        state.upload_safety_gate().mark_ledger_mismatch(
                            "upload capacity ledger differs from durable facts",
                        );
                        next_capacity_ledger_audit =
                            tokio::time::Instant::now() + CAPACITY_LEDGER_AUDIT_DEGRADED_INTERVAL;
                        note_reconciliation_failure(&state);
                        tracing::error!(
                            capacity_ledger_mismatches,
                            ledger_retained_files = audit.ledger_retained_files,
                            fact_retained_files = audit.fact_retained_files,
                            ledger_retained_bytes = audit.ledger_retained_bytes,
                            fact_retained_bytes = audit.fact_retained_bytes,
                            ledger_pending_jobs = audit.ledger_pending_jobs,
                            fact_pending_jobs = audit.fact_pending_jobs,
                            ledger_storage_jobs_pending = audit.ledger_storage_jobs_pending,
                            fact_storage_jobs_pending = audit.fact_storage_jobs_pending,
                            ledger_cleanup_jobs_pending = audit.ledger_cleanup_jobs_pending,
                            fact_cleanup_jobs_pending = audit.fact_cleanup_jobs_pending,
                            ledger_cleanup_obligation_debt = audit.ledger_cleanup_obligation_debt,
                            fact_cleanup_obligation_debt = audit.fact_cleanup_obligation_debt,
                            ledger_recovery_retained_files = audit.ledger_recovery_retained_files,
                            fact_recovery_retained_files = audit.fact_recovery_retained_files,
                            ledger_recovery_retained_bytes = audit.ledger_recovery_retained_bytes,
                            fact_recovery_retained_bytes = audit.fact_recovery_retained_bytes,
                            ledger_legacy_overcommit_draining =
                                audit.ledger_legacy_overcommit_draining,
                            fact_legacy_overcommit_draining = audit.fact_legacy_overcommit_draining,
                            ledger_recovery_overcommit_draining =
                                audit.ledger_recovery_overcommit_draining,
                            fact_recovery_overcommit_draining =
                                audit.fact_recovery_overcommit_draining,
                            projection_size_conflicts = audit.projection_size_conflicts,
                            "upload capacity ledger disagrees with durable row facts; refusing to self-repair"
                        );
                    }
                }
                Err(error) => {
                    state.upload_safety_gate().mark_ledger_mismatch(
                        "upload capacity ledger consistency could not be proved",
                    );
                    capacity_ledger_mismatches = capacity_ledger_mismatches.max(1);
                    state
                        .metrics
                        .upload_storage_capacity_ledger_mismatches
                        .store(capacity_ledger_mismatches, Ordering::Relaxed);
                    next_capacity_ledger_audit =
                        tokio::time::Instant::now() + CAPACITY_LEDGER_AUDIT_RETRY_INTERVAL;
                    note_reconciliation_failure(&state);
                    tracing::error!(?error, "could not prove upload capacity ledger consistency");
                }
            }
        }
        if capacity_ledger_mismatches > 0 {
            heartbeat.error("upload capacity ledger does not match durable row facts");
            continue;
        }
        state
            .upload_safety_gate()
            .establish(authority_generation, recovery_draining);
        state
            .metrics
            .upload_storage_safety_gate_state
            .store(state.upload_safety_gate().metric_code(), Ordering::Relaxed);
        if let Err(error) = db::cleanup_expired_upload_slots(&state.pool).await {
            tracing::error!(?error, "failed to queue expired upload storage cleanup");
            failures += 1;
            note_reconciliation_failure(&state);
        }

        match db::claim_upload_storage_jobs(&state.pool).await {
            Ok(jobs) => {
                let outcomes = stream::iter(jobs).map(|job| {
                    let state = Arc::clone(&state);
                    async move {
                        let result = process_storage_job(&state, &job).await;
                        (job, result)
                    }
                });
                let mut outcomes = outcomes.buffer_unordered(4);
                while let Some((job, result)) = outcomes.next().await {
                    match result {
                        Ok(StorageOutcome::Completed) => {
                            note_storage_job_success(&state, &job.action)
                        }
                        Ok(StorageOutcome::Deferred) => {}
                        Err(error) => {
                            if crate::storage::is_upload_safety_error(&error) {
                                if let Err(db_error) = db::defer_upload_storage_job(
                                    &state.pool,
                                    job.id,
                                    job.claim_token,
                                )
                                .await
                                {
                                    failures += 1;
                                    note_reconciliation_failure(&state);
                                    tracing::error!(
                                        job_id = job.id,
                                        ?db_error,
                                        "failed to defer upload storage job after authority invalidation"
                                    );
                                }
                                continue;
                            }
                            failures += 1;
                            note_storage_job_failure(&state, &job.action, &error);
                            tracing::error!(job_id=job.id, upload_id=%job.object_id, action=%job.action, ?error, "upload storage reconciliation failed");
                            if let Err(db_error) = db::fail_upload_storage_job(
                                &state.pool,
                                job.id,
                                job.claim_token,
                                &error.to_string(),
                            )
                            .await
                            {
                                failures += 1;
                                note_reconciliation_failure(&state);
                                tracing::error!(
                                    job_id = job.id,
                                    ?db_error,
                                    "failed to release upload storage job"
                                );
                            }
                        }
                    }
                }
            }
            Err(error) => {
                failures += 1;
                note_reconciliation_failure(&state);
                tracing::error!(?error, "failed to claim upload storage jobs");
            }
        }
        heartbeat.pulse();

        match db::queued_upload_cleanup(&state.pool).await {
            Ok(jobs) => {
                let outcomes = stream::iter(jobs).map(|job| {
                    let state = Arc::clone(&state);
                    async move {
                        let result = process_cleanup_job(&state, &job).await;
                        (job, result)
                    }
                });
                let mut outcomes = outcomes.buffer_unordered(4);
                while let Some((job, result)) = outcomes.next().await {
                    match result {
                        Ok(CleanupOutcome::Completed) => {
                            state
                                .metrics
                                .upload_storage_cleanup_success_total
                                .fetch_add(1, Ordering::Relaxed);
                        }
                        Ok(CleanupOutcome::Deferred) => {}
                        Err(error) => {
                            if crate::storage::is_upload_safety_error(&error) {
                                if let Err(db_error) = db::defer_queued_upload_cleanup(
                                    &state.pool,
                                    job.object_id,
                                    job.claim_token,
                                )
                                .await
                                {
                                    failures += 1;
                                    note_reconciliation_failure(&state);
                                    tracing::error!(upload_id=%job.object_id, ?db_error, "failed to defer upload cleanup after authority invalidation");
                                }
                                continue;
                            }
                            failures += 1;
                            note_reconciliation_failure(&state);
                            state
                                .metrics
                                .upload_storage_cleanup_failures_total
                                .fetch_add(1, Ordering::Relaxed);
                            if crate::storage::is_upload_integrity_error(&error) {
                                state
                                    .metrics
                                    .upload_storage_integrity_failures_total
                                    .fetch_add(1, Ordering::Relaxed);
                            }
                            tracing::error!(upload_id=%job.object_id, ?error, "upload object deletion failed");
                            if let Err(db_error) = db::fail_queued_upload_cleanup(
                                &state.pool,
                                job.object_id,
                                job.claim_token,
                                &error.to_string(),
                            )
                            .await
                            {
                                failures += 1;
                                note_reconciliation_failure(&state);
                                tracing::error!(upload_id=%job.object_id, ?db_error, "failed to release upload cleanup job");
                            }
                        }
                    }
                }
            }
            Err(error) => {
                failures += 1;
                note_reconciliation_failure(&state);
                tracing::error!(?error, "failed to claim upload cleanup jobs");
            }
        }
        heartbeat.pulse();

        credential_ticks = credential_ticks.saturating_add(1);
        if credential_ticks >= 12 {
            credential_ticks = 0;
            match state.upload_store().reload_credentials().await {
                Ok(_) => {}
                Err(error) if crate::storage::is_upload_safety_error(&error) => {
                    tracing::warn!(
                        ?error,
                        "upload credential refresh deferred by authority gate"
                    );
                }
                Err(error) => {
                    failures += 1;
                    note_reconciliation_failure(&state);
                    state
                        .metrics
                        .upload_storage_credential_refresh_failures_total
                        .fetch_add(1, Ordering::Relaxed);
                    tracing::error!(?error, "failed to refresh upload-store credentials");
                }
            }
        }
        match db::claim_upload_scrub_jobs(&state.pool).await {
            Ok(jobs) => {
                for job in jobs {
                    let verified = tokio::time::timeout(
                        STORAGE_OPERATION_TIMEOUT,
                        state.upload_store().commit(
                            &job.object_id.to_string(),
                            &job.storage_attempt.to_string(),
                            job.object_version.as_deref(),
                            job.expected_size,
                            &job.expected_sha256,
                        ),
                    )
                    .await
                    .context("upload manifest scrub timed out")
                    .and_then(|result| result);
                    match verified {
                        Ok(object)
                            if object.object_key == job.object_key
                                && object.object_version == job.object_version =>
                        {
                            match db::complete_upload_scrub(
                                &state.pool,
                                job.object_id,
                                job.claim_token,
                            )
                            .await
                            {
                                Ok(true) => {
                                    state
                                        .metrics
                                        .upload_storage_scrub_success_total
                                        .fetch_add(1, Ordering::Relaxed);
                                }
                                Ok(false) | Err(_) => {
                                    failures += 1;
                                    note_reconciliation_failure(&state);
                                    state
                                        .metrics
                                        .upload_storage_scrub_failures_total
                                        .fetch_add(1, Ordering::Relaxed);
                                }
                            }
                        }
                        Err(error) if crate::storage::is_upload_safety_error(&error) => {
                            if let Err(db_error) =
                                db::defer_upload_scrub(&state.pool, job.object_id, job.claim_token)
                                    .await
                            {
                                failures += 1;
                                note_reconciliation_failure(&state);
                                tracing::error!(upload_id=%job.object_id, ?db_error, "failed to defer upload scrub after authority invalidation");
                            }
                        }
                        Ok(_) | Err(_) => {
                            failures += 1;
                            note_reconciliation_failure(&state);
                            state
                                .metrics
                                .upload_storage_scrub_failures_total
                                .fetch_add(1, Ordering::Relaxed);
                            let _ =
                                db::fail_upload_scrub(&state.pool, job.object_id, job.claim_token)
                                    .await;
                            tracing::error!(upload_id=%job.object_id, "committed upload manifest scrub failed closed");
                        }
                    }
                    heartbeat.pulse();
                }
            }
            Err(error) => {
                failures += 1;
                note_reconciliation_failure(&state);
                tracing::error!(?error, "failed to claim upload manifest scrub jobs");
            }
        }
        match db::upload_queue_metrics(&state.pool).await {
            Ok(snapshot) => {
                state
                    .metrics
                    .upload_storage_jobs_pending
                    .store(snapshot.storage_jobs_pending, Ordering::Relaxed);
                state
                    .metrics
                    .upload_storage_cleanup_pending
                    .store(snapshot.cleanup_jobs_pending, Ordering::Relaxed);
                state
                    .metrics
                    .upload_storage_cleanup_obligation_debt
                    .store(snapshot.cleanup_obligation_debt, Ordering::Relaxed);
                state
                    .metrics
                    .upload_storage_configured_pending_limit
                    .store(snapshot.configured_pending_limit, Ordering::Relaxed);
                state
                    .metrics
                    .upload_storage_legacy_overcommit_draining
                    .store(snapshot.legacy_overcommit_draining, Ordering::Relaxed);
                state
                    .metrics
                    .upload_storage_recovery_retained_files
                    .store(snapshot.recovery_retained_files, Ordering::Relaxed);
                state
                    .metrics
                    .upload_storage_recovery_retained_bytes
                    .store(snapshot.recovery_retained_bytes, Ordering::Relaxed);
                state
                    .metrics
                    .upload_storage_recovery_overcommit_draining
                    .store(snapshot.recovery_overcommit_draining, Ordering::Relaxed);
                state
                    .metrics
                    .upload_storage_oldest_pending_age_seconds
                    .store(snapshot.oldest_pending_age_seconds, Ordering::Relaxed);
                state
                    .metrics
                    .upload_storage_dead_letter_jobs
                    .store(snapshot.dead_letter_jobs_capped, Ordering::Relaxed);
                state
                    .metrics
                    .upload_storage_scrub_failures
                    .store(snapshot.scrub_failures_capped, Ordering::Relaxed);
                state
                    .metrics
                    .upload_storage_scrub_due_capped
                    .store(snapshot.scrub_due_capped, Ordering::Relaxed);
                state
                    .metrics
                    .upload_storage_scrub_oldest_overdue_seconds
                    .store(snapshot.scrub_oldest_overdue_seconds, Ordering::Relaxed);
                state
                    .metrics
                    .upload_storage_cleanup_obligations_due_capped
                    .store(snapshot.cleanup_obligations_due_capped, Ordering::Relaxed);
                state
                    .metrics
                    .upload_storage_cleanup_oldest_overdue_seconds
                    .store(snapshot.cleanup_oldest_overdue_seconds, Ordering::Relaxed);
                let pending = snapshot
                    .storage_jobs_pending
                    .saturating_add(snapshot.cleanup_jobs_pending);
                let reserved_recovery = pending.saturating_add(snapshot.cleanup_obligation_debt);
                if snapshot.dead_letter_jobs_capped > 0
                    || snapshot.scrub_failures_capped > 0
                    || snapshot.scrub_oldest_overdue_seconds > 86_400
                    || snapshot.cleanup_oldest_overdue_seconds > 900
                    || snapshot.legacy_overcommit_draining != 0
                    || snapshot.recovery_overcommit_draining != 0
                    || reserved_recovery >= state.config.upload_storage_max_pending_jobs as u64
                    || snapshot.oldest_pending_age_seconds > 900
                {
                    failures += 1;
                    note_reconciliation_failure(&state);
                    tracing::error!(
                        pending,
                        cleanup_obligation_debt = snapshot.cleanup_obligation_debt,
                        legacy_overcommit_draining = snapshot.legacy_overcommit_draining,
                        recovery_retained_files = snapshot.recovery_retained_files,
                        recovery_retained_bytes = snapshot.recovery_retained_bytes,
                        recovery_overcommit_draining = snapshot.recovery_overcommit_draining,
                        reserved_recovery,
                        dead_letters_capped = snapshot.dead_letter_jobs_capped,
                        scrub_failures_capped = snapshot.scrub_failures_capped,
                        scrub_due_capped = snapshot.scrub_due_capped,
                        scrub_oldest_overdue_seconds = snapshot.scrub_oldest_overdue_seconds,
                        cleanup_obligations_due_capped = snapshot.cleanup_obligations_due_capped,
                        cleanup_oldest_overdue_seconds = snapshot.cleanup_oldest_overdue_seconds,
                        oldest_seconds = snapshot.oldest_pending_age_seconds,
                        "persistent upload-storage backlog makes the worker unhealthy"
                    );
                }
            }
            Err(error) => {
                failures += 1;
                note_reconciliation_failure(&state);
                tracing::error!(?error, "failed to refresh upload-storage queue metrics");
            }
        }
        if failures == 0 {
            heartbeat.ok();
        } else {
            heartbeat.error(format!(
                "{failures} storage reconciliation operations failed"
            ));
        }
    }
}

fn note_reconciliation_failure(state: &AppState) {
    state
        .metrics
        .upload_storage_reconciliation_failures_total
        .fetch_add(1, Ordering::Relaxed);
}

fn note_storage_job_success(state: &AppState, action: &str) {
    let counter = match action {
        "promote" => &state.metrics.upload_storage_promotion_success_total,
        "delete_stage" => &state.metrics.upload_storage_stage_deletion_success_total,
        "delete_object" => &state.metrics.upload_storage_object_deletion_success_total,
        _ => return,
    };
    counter.fetch_add(1, Ordering::Relaxed);
}

fn note_storage_job_failure(state: &AppState, action: &str, error: &anyhow::Error) {
    note_reconciliation_failure(state);
    let counter = match action {
        "promote" => &state.metrics.upload_storage_promotion_failures_total,
        "delete_stage" => &state.metrics.upload_storage_stage_deletion_failures_total,
        "delete_object" => &state.metrics.upload_storage_object_deletion_failures_total,
        _ => return,
    };
    counter.fetch_add(1, Ordering::Relaxed);
    if crate::storage::is_upload_integrity_error(error) {
        state
            .metrics
            .upload_storage_integrity_failures_total
            .fetch_add(1, Ordering::Relaxed);
    }
}

enum StorageOutcome {
    Completed,
    Deferred,
}

async fn process_storage_job(
    state: &AppState,
    job: &db::UploadStorageJob,
) -> Result<StorageOutcome> {
    anyhow::ensure!(
        job.storage_backend == state.upload_store().backend(),
        "job targets a different upload storage backend"
    );
    match job.action.as_str() {
        "promote" => {
            let size = u64::try_from(job.expected_size.context("promote job has no size")?)?;
            let digest = job.expected_sha256.context("promote job has no digest")?;
            if !db::begin_upload_promotion(
                &state.pool,
                job.object_id,
                job.storage_attempt,
                job.storage_fence,
                job.claim_token,
            )
            .await?
            {
                // The exact attempt is no longer authoritative. Its immutable
                // stage cannot name a replacement attempt. Never remove the
                // destination here: another reconciler may already have
                // committed this same attempt after our queue lease expired.
                if db::upload_attempt_is_committed(
                    &state.pool,
                    db::CommittedUploadIdentity {
                        id: job.object_id,
                        storage_attempt: job.storage_attempt,
                        storage_backend: &job.storage_backend,
                        object_key: job
                            .object_key
                            .as_deref()
                            .context("promote job has no object key")?,
                        object_version: job.object_version.as_deref(),
                        content_sha256: &digest,
                        size,
                        storage_fence: job.storage_fence,
                    },
                )
                .await?
                {
                    delete_distinct_stage_after_commit(state, job).await?;
                    anyhow::ensure!(
                        db::complete_upload_storage_job(&state.pool, job.id, job.claim_token)
                            .await?,
                        "upload promotion job lease changed before completion"
                    );
                    return Ok(StorageOutcome::Completed);
                }
                anyhow::ensure!(
                    db::retire_upload_promotion_for_cleanup(
                        &state.pool,
                        job.object_id,
                        job.storage_attempt,
                        job.storage_fence,
                        job.claim_token,
                    )
                    .await?,
                    "promotion lost authority without an exact committed or deleting projection"
                );
                delete_uncommitted_attempt(state, job).await?;
                return Ok(StorageOutcome::Completed);
            }
            let promoted = tokio::time::timeout(
                STORAGE_OPERATION_TIMEOUT,
                state.upload_store().commit(
                    &job.object_id.to_string(),
                    &job.storage_attempt.to_string(),
                    job.stage_version.as_deref(),
                    size,
                    &digest,
                ),
            )
            .await
            .context("upload promotion timed out")??;
            let committed = db::complete_promoted_upload(
                &state.pool,
                db::PromotedUploadProjection {
                    id: job.object_id,
                    claim_token: job.storage_attempt,
                    promotion_claim_token: job.claim_token,
                    storage_backend: &promoted.backend,
                    object_key: &promoted.object_key,
                    object_version: promoted.object_version.as_deref(),
                    content_sha256: &digest,
                    size: promoted.size,
                    retention_seconds: state.config.upload_retention_seconds,
                    storage_fence: job.storage_fence,
                },
            )
            .await?;
            if !committed {
                if db::upload_attempt_is_committed(
                    &state.pool,
                    db::CommittedUploadIdentity {
                        id: job.object_id,
                        storage_attempt: job.storage_attempt,
                        storage_backend: &promoted.backend,
                        object_key: &promoted.object_key,
                        object_version: promoted.object_version.as_deref(),
                        content_sha256: &digest,
                        size: promoted.size,
                        storage_fence: job.storage_fence,
                    },
                )
                .await?
                {
                    // A concurrent worker may have committed the same immutable
                    // destination. Stage cleanup is idempotent; destination
                    // deletion is performed only by an exact durable delete job.
                    delete_distinct_stage_after_commit(state, job).await?;
                    anyhow::ensure!(
                        db::complete_upload_storage_job(&state.pool, job.id, job.claim_token)
                            .await?,
                        "upload promotion job lease changed before completion"
                    );
                } else {
                    anyhow::ensure!(
                        db::retire_upload_promotion_for_cleanup(
                            &state.pool,
                            job.object_id,
                            job.storage_attempt,
                            job.storage_fence,
                            job.claim_token,
                        )
                        .await?,
                        "upload attempt lost authority without an exact cleanup projection"
                    );
                    delete_uncommitted_attempt(state, job).await?;
                }
            }
        }
        "delete_stage" => {
            let removed = tokio::time::timeout(
                STORAGE_OPERATION_TIMEOUT,
                state.upload_store().abort(
                    &job.object_id.to_string(),
                    &job.storage_attempt.to_string(),
                    job.stage_version.as_deref(),
                ),
            )
            .await
            .context("upload stage deletion timed out")??;
            if job.storage_backend == "s3"
                && !db::confirm_upload_stage_absence(
                    &state.pool,
                    job.id,
                    job.claim_token,
                    removed,
                    300,
                )
                .await?
            {
                return Ok(StorageOutcome::Deferred);
            }
            anyhow::ensure!(
                db::complete_upload_storage_job(&state.pool, job.id, job.claim_token).await?,
                "upload stage-deletion job lease changed before completion"
            );
        }
        "delete_object" => {
            let key = job
                .object_key
                .as_deref()
                .context("delete job has no object key")?;
            tokio::time::timeout(
                STORAGE_OPERATION_TIMEOUT,
                state
                    .upload_store()
                    .delete(key, job.object_version.as_deref()),
            )
            .await
            .context("upload object deletion timed out")??;
            anyhow::ensure!(
                db::complete_upload_storage_job(&state.pool, job.id, job.claim_token).await?,
                "upload object-deletion job lease changed before completion"
            );
        }
        _ => anyhow::bail!("unknown upload storage job action"),
    }
    Ok(StorageOutcome::Completed)
}

async fn delete_distinct_stage_after_commit(
    state: &AppState,
    job: &db::UploadStorageJob,
) -> Result<()> {
    if job.stage_key == job.object_key {
        return Ok(());
    }
    delete_uncommitted_attempt(state, job).await
}

async fn delete_uncommitted_attempt(state: &AppState, job: &db::UploadStorageJob) -> Result<()> {
    tokio::time::timeout(
        STORAGE_OPERATION_TIMEOUT,
        state.upload_store().abort(
            &job.object_id.to_string(),
            &job.storage_attempt.to_string(),
            job.stage_version.as_deref(),
        ),
    )
    .await
    .context("stale upload stage deletion timed out")??;
    Ok(())
}

enum CleanupOutcome {
    Completed,
    Deferred,
}

async fn process_cleanup_job(
    state: &AppState,
    job: &db::UploadCleanupJob,
) -> Result<CleanupOutcome> {
    anyhow::ensure!(
        job.storage_backend == state.upload_store().backend(),
        "cleanup targets a different upload storage backend"
    );
    // The generic object-store interface can delete only the current object
    // at a key; it cannot prove removal of two distinct historical versions
    // at that same key. Normal S3 admission always normalizes the staged and
    // object locator to one exact version. Preserve a corrupt/legacy
    // two-version tombstone (and its conservative capacity charge) for
    // operator repair instead of deleting one version and silently releasing
    // metadata for the other.
    anyhow::ensure!(
        !(job.storage_backend == "s3"
            && job.stage_key.as_deref() == Some(job.object_key.as_str())
            && job.stage_version.as_deref() != job.object_version.as_deref()),
        "cleanup names two object-store versions at one key; exact deletion is unsupported"
    );
    if !db::upload_cleanup_generation_is_quiescent(
        &state.pool,
        job.object_id,
        job.claim_token,
        job.storage_fence,
    )
    .await?
    {
        let _ =
            db::defer_queued_upload_cleanup(&state.pool, job.object_id, job.claim_token).await?;
        return Ok(CleanupOutcome::Deferred);
    }
    let object_removed = tokio::time::timeout(
        STORAGE_OPERATION_TIMEOUT,
        state
            .upload_store()
            .delete(&job.object_key, job.object_version.as_deref()),
    )
    .await
    .context("upload cleanup timed out")??;
    let mut removed_any = object_removed;
    if job.stage_key.as_deref() != Some(job.object_key.as_str()) {
        if let Some(attempt) = job.storage_attempt {
            let stage_removed = tokio::time::timeout(
                STORAGE_OPERATION_TIMEOUT,
                state.upload_store().abort(
                    &job.object_id.to_string(),
                    &attempt.to_string(),
                    job.stage_version.as_deref(),
                ),
            )
            .await
            .context("upload stage cleanup timed out")??;
            removed_any |= stage_removed;
        }
    }
    if job.storage_backend == "s3"
        && !db::confirm_upload_cleanup_absence(
            &state.pool,
            job.object_id,
            job.claim_token,
            removed_any,
            300,
        )
        .await?
    {
        // The durable tombstone remains queued. A later pass must observe the
        // same key absent after the quiet period before metadata can vanish.
        return Ok(CleanupOutcome::Deferred);
    }
    anyhow::ensure!(
        db::complete_queued_upload_cleanup(&state.pool, job.object_id, job.claim_token).await?,
        "upload cleanup lease changed before completion"
    );
    Ok(CleanupOutcome::Completed)
}

#[cfg(test)]
mod tests {
    #[test]
    fn storage_operation_timeout_is_bounded() {
        assert!(super::STORAGE_OPERATION_TIMEOUT.as_secs() <= 300);
    }

    #[test]
    fn late_multipart_stage_requires_a_fresh_quiet_absence_window() {
        #[derive(Default)]
        struct Tombstone {
            absence_started: bool,
            completed: bool,
        }
        fn observe(state: &mut Tombstone, removed_now: bool, quiet_elapsed: bool) {
            if removed_now {
                state.absence_started = true;
                state.completed = false;
            } else if state.absence_started && quiet_elapsed {
                state.completed = true;
            } else {
                state.absence_started = true;
            }
        }

        let mut tombstone = Tombstone::default();
        observe(&mut tombstone, false, false); // early NotFound
        assert!(!tombstone.completed);
        observe(&mut tombstone, true, false); // provider completes late, then delete
        assert!(!tombstone.completed);
        observe(&mut tombstone, false, false); // immediate absence is insufficient
        assert!(!tombstone.completed);
        observe(&mut tombstone, false, true); // quiet confirmation
        assert!(tombstone.completed);
    }
}
