use crate::services::upload_safety::{UploadAuthorityGeneration, UploadIoClass, UploadSafetyGate};
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CapacityAuditProof {
    Proven,
    ReadUnavailable,
    ViolationObserved,
}

impl CapacityAuditProof {
    fn read_unavailable(&mut self) {
        if *self != Self::ViolationObserved {
            *self = Self::ReadUnavailable;
        }
    }

    fn report_blocked(
        self,
        heartbeat: &WorkerHeartbeat,
        audit_observed: bool,
        failure: &'static str,
    ) -> bool {
        if self == Self::Proven {
            return false;
        }
        if self == Self::ReadUnavailable && !audit_observed {
            // The first failure already closed admission/readiness. Waiting
            // proves nothing new, so it must neither count nor clear errors.
            heartbeat.pulse();
        } else {
            // Real errors still reach the ordinary three-error limit. A
            // positively observed violation retains its per-tick escalation.
            heartbeat.error(failure);
        }
        true
    }
}

/// Keep failed observations distinct from ticks waiting for their retry.
/// The process-wide gate, not this scheduling state, authorizes object I/O.
struct CapacityAuthorityAuditProgress {
    next_audit: tokio::time::Instant,
    violations: u64,
    proof: CapacityAuditProof,
}

impl CapacityAuthorityAuditProgress {
    fn new(now: tokio::time::Instant) -> Self {
        Self {
            next_audit: now,
            violations: 0,
            proof: CapacityAuditProof::Proven,
        }
    }

    async fn audit_if_due<A, F>(
        &mut self,
        gate: &UploadSafetyGate,
        mut now: impl FnMut() -> tokio::time::Instant,
        audit: A,
    ) -> Option<Result<db::UploadCapacityAuthorityAudit>>
    where
        A: FnOnce() -> F,
        F: std::future::Future<Output = Result<db::UploadCapacityAuthorityAudit>>,
    {
        if now() < self.next_audit {
            return None;
        }
        let result = audit().await;
        match &result {
            Ok(audit) => {
                self.violations = audit.violation_count();
                self.next_audit = now() + CAPACITY_AUTHORITY_AUDIT_INTERVAL;
                self.proof = if self.violations == 0 {
                    CapacityAuditProof::Proven
                } else {
                    gate.mark_capacity_authority_unsafe(
                        "upload catalog or ACL authority audit failed",
                    );
                    CapacityAuditProof::ViolationObserved
                };
                // A successful catalog read alone cannot reopen the gate:
                // the caller must also prove the ledger and immutable tuple.
            }
            Err(_) => {
                gate.mark_capacity_authority_unsafe(
                    "upload catalog or ACL authority could not be proved",
                );
                self.violations = self.violations.max(1);
                self.next_audit = now() + CAPACITY_AUTHORITY_AUDIT_RETRY_INTERVAL;
                self.proof.read_unavailable();
            }
        }
        Some(result)
    }

    fn report_blocked_before_ledger(
        &self,
        ledger: &CapacityLedgerAuditProgress,
        heartbeat: &WorkerHeartbeat,
        audit_observed: bool,
    ) -> bool {
        if self.proof == CapacityAuditProof::ReadUnavailable
            && !audit_observed
            && ledger.proof == CapacityAuditProof::ViolationObserved
        {
            // A catalog retry wait must not hide a previously proved ledger
            // violation. Report once, without changing either audit deadline.
            return ledger.report_blocked(heartbeat, false);
        }
        self.proof.report_blocked(
            heartbeat,
            audit_observed,
            "upload capacity enforcement authority is unproven",
        )
    }
}

struct CapacityLedgerAuditProgress {
    next_audit: tokio::time::Instant,
    mismatches: u64,
    proof: CapacityAuditProof,
}

impl CapacityLedgerAuditProgress {
    fn new(now: tokio::time::Instant) -> Self {
        Self {
            next_audit: now,
            mismatches: 0,
            proof: CapacityAuditProof::Proven,
        }
    }

    async fn audit_if_due<A, F>(
        &mut self,
        gate: &UploadSafetyGate,
        mut now: impl FnMut() -> tokio::time::Instant,
        audit: A,
    ) -> Option<Result<db::UploadCapacityReconciliation>>
    where
        A: FnOnce() -> F,
        F: std::future::Future<Output = Result<db::UploadCapacityReconciliation>>,
    {
        if now() < self.next_audit {
            return None;
        }
        let result = audit().await;
        match &result {
            Ok(audit) => {
                self.mismatches = audit.mismatch_count();
                if self.mismatches == 0 {
                    self.next_audit = now() + CAPACITY_LEDGER_AUDIT_INTERVAL;
                    self.proof = CapacityAuditProof::Proven;
                } else {
                    gate.mark_ledger_mismatch("upload capacity ledger differs from durable facts");
                    self.next_audit = now() + CAPACITY_LEDGER_AUDIT_DEGRADED_INTERVAL;
                    self.proof = CapacityAuditProof::ViolationObserved;
                }
                // Only the caller's complete authority/probe boundary may
                // reopen the gate; a successful read does not prove all work.
            }
            Err(_) => {
                gate.mark_ledger_mismatch("upload capacity ledger consistency could not be proved");
                self.mismatches = self.mismatches.max(1);
                self.next_audit = now() + CAPACITY_LEDGER_AUDIT_RETRY_INTERVAL;
                self.proof.read_unavailable();
            }
        }
        Some(result)
    }

    fn report_blocked(&self, heartbeat: &WorkerHeartbeat, audit_observed: bool) -> bool {
        self.proof.report_blocked(
            heartbeat,
            audit_observed,
            "upload capacity ledger does not match durable row facts",
        )
    }
}

pub(crate) struct SuccessfulStartupAudits {
    generation: UploadAuthorityGeneration,
    capacity_limits: [i64; 3],
    authority_started_at: tokio::time::Instant,
    ledger_started_at: tokio::time::Instant,
}

/// One AppState may hand its successful startup observations to one worker
/// attempt. This stores no reusable health verdict: subsequent attempts and
/// invalidated gates must perform the ordinary database audits immediately.
#[derive(Default)]
pub(crate) struct StartupAuditHandoff {
    evidence: std::sync::Mutex<Option<SuccessfulStartupAudits>>,
}

impl StartupAuditHandoff {
    pub(crate) fn after_successful_audits(
        generation: UploadAuthorityGeneration,
        capacity_limits: [i64; 3],
        authority_started_at: tokio::time::Instant,
        ledger_started_at: tokio::time::Instant,
    ) -> Self {
        Self {
            evidence: std::sync::Mutex::new(Some(SuccessfulStartupAudits {
                generation,
                capacity_limits,
                authority_started_at,
                ledger_started_at,
            })),
        }
    }

    pub(crate) fn take(&self) -> Option<SuccessfulStartupAudits> {
        match self.evidence.lock() {
            Ok(mut evidence) => evidence.take(),
            Err(poisoned) => {
                poisoned.into_inner().take();
                None
            }
        }
    }
}

impl SuccessfulStartupAudits {
    fn deadlines(
        self,
        generation: UploadAuthorityGeneration,
        capacity_limits: [i64; 3],
        safety_gate: &UploadSafetyGate,
        now: tokio::time::Instant,
    ) -> (tokio::time::Instant, tokio::time::Instant) {
        // NewWrite is permitted only by a Healthy gate with this exact
        // generation. The gate checks both under the same snapshot lock.
        if self.generation != generation
            || self.capacity_limits != capacity_limits
            || !safety_gate.permits_generation(UploadIoClass::NewWrite, generation)
            || self.authority_started_at > self.ledger_started_at
            || self.ledger_started_at > now
        {
            return (now, now);
        }
        // Anchor to each database observation's START, including pool wait and
        // query/commit time. Later AppState initialization or worker scheduling
        // must never grant the old observation a fresh 60-second/hour lifetime.
        (
            self.authority_started_at + CAPACITY_AUTHORITY_AUDIT_INTERVAL,
            self.ledger_started_at + CAPACITY_LEDGER_AUDIT_INTERVAL,
        )
    }
}

pub async fn serve(
    state: Arc<AppState>,
    cancel: CancellationToken,
    heartbeat: WorkerHeartbeat,
) -> Result<()> {
    let mut interval = tokio::time::interval(Duration::from_secs(5));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut credential_ticks = 0_u8;
    let mut startup_audits = state.take_upload_startup_audits();
    let mut capacity_authority_audit =
        CapacityAuthorityAuditProgress::new(tokio::time::Instant::now());
    let mut capacity_ledger_audit =
        CapacityLedgerAuditProgress::new(capacity_authority_audit.next_audit);
    loop {
        // Consume even if the first probe fails or this attempt is cancelled.
        // A later loop or worker restart must not revive old startup evidence.
        let startup_audits = startup_audits.take();
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
        if let Some(audits) = startup_audits.filter(|_| !recovery_draining) {
            (
                capacity_authority_audit.next_audit,
                capacity_ledger_audit.next_audit,
            ) = audits.deadlines(
                authority_generation,
                [
                    state.config.upload_storage_max_pending_jobs,
                    state.config.upload_storage_max_retained_files,
                    state.config.upload_storage_max_retained_bytes,
                ],
                state.upload_safety_gate(),
                tokio::time::Instant::now(),
            );
        }
        let authority_observation = capacity_authority_audit
            .audit_if_due(
                state.upload_safety_gate(),
                tokio::time::Instant::now,
                || {
                    db::audit_upload_capacity_authority(
                        &state.pool,
                        state.config.upload_storage_max_pending_jobs,
                        state.config.upload_storage_max_retained_files,
                        state.config.upload_storage_max_retained_bytes,
                    )
                },
            )
            .await;
        let authority_audited = authority_observation.is_some();
        if let Some(observation) = authority_observation {
            let capacity_authority_violations = capacity_authority_audit.violations;
            state
                .metrics
                .upload_storage_capacity_authority_violations
                .store(capacity_authority_violations, Ordering::Relaxed);
            match observation {
                Ok(audit) => {
                    if capacity_authority_violations > 0 {
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
                    note_reconciliation_failure(&state);
                    tracing::error!(
                        ?error,
                        "could not verify upload capacity enforcement authority; retrying without object I/O"
                    );
                }
            }
        }
        if capacity_authority_audit.report_blocked_before_ledger(
            &capacity_ledger_audit,
            &heartbeat,
            authority_audited,
        ) {
            continue;
        }
        let ledger_observation = capacity_ledger_audit
            .audit_if_due(
                state.upload_safety_gate(),
                tokio::time::Instant::now,
                || db::reconcile_upload_capacity_ledger(&state.pool),
            )
            .await;
        let ledger_audited = ledger_observation.is_some();
        if let Some(observation) = ledger_observation {
            let capacity_ledger_mismatches = capacity_ledger_audit.mismatches;
            state
                .metrics
                .upload_storage_capacity_ledger_mismatches
                .store(capacity_ledger_mismatches, Ordering::Relaxed);
            match observation {
                Ok(audit) => {
                    if capacity_ledger_mismatches > 0 {
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
                    note_reconciliation_failure(&state);
                    tracing::error!(?error, "could not prove upload capacity ledger consistency");
                }
            }
        }
        if capacity_ledger_audit.report_blocked(&heartbeat, ledger_audited) {
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
    use super::{Duration, StartupAuditHandoff, UploadAuthorityGeneration, UploadSafetyGate};
    use tokio::time::Instant;

    const STARTUP_GENERATION: UploadAuthorityGeneration = UploadAuthorityGeneration {
        namespace: 7,
        capacity_policy: 11,
    };
    const STARTUP_LIMITS: [i64; 3] = [16, 32, 1024];

    fn successful_startup(start: Instant) -> StartupAuditHandoff {
        StartupAuditHandoff::after_successful_audits(
            STARTUP_GENERATION,
            STARTUP_LIMITS,
            start,
            start + Duration::from_secs(7),
        )
    }

    fn healthy_gate() -> std::sync::Arc<UploadSafetyGate> {
        let gate = UploadSafetyGate::new();
        gate.establish(STARTUP_GENERATION, false);
        gate
    }

    #[derive(Clone, Copy)]
    enum AuditKind {
        Catalog,
        Ledger,
        Both(AuditResult),
    }

    #[derive(Clone, Copy)]
    enum AuditResult {
        Unavailable,
        Clean,
        Violation,
    }

    struct AuditStep {
        calls: usize,
        worker_ready: bool,
        blocked: bool,
        gate_before_completion: crate::services::upload_safety::UploadSafetyState,
        gate_after_completion: crate::services::upload_safety::UploadSafetyState,
        next_audit: Duration,
    }

    fn reconciliation(mismatch: bool) -> crate::db::UploadCapacityReconciliation {
        crate::db::UploadCapacityReconciliation {
            ledger_retained_files: 1,
            fact_retained_files: if mismatch { 2 } else { 1 },
            ledger_retained_bytes: 2,
            fact_retained_bytes: 2,
            ledger_pending_jobs: 3,
            fact_pending_jobs: 3,
            ledger_storage_jobs_pending: 1,
            fact_storage_jobs_pending: 1,
            ledger_cleanup_jobs_pending: 2,
            fact_cleanup_jobs_pending: 2,
            ledger_cleanup_obligation_debt: 4,
            fact_cleanup_obligation_debt: 4,
            ledger_recovery_retained_files: 5,
            fact_recovery_retained_files: 5,
            ledger_recovery_retained_bytes: 6,
            fact_recovery_retained_bytes: 6,
            ledger_legacy_overcommit_draining: false,
            fact_legacy_overcommit_draining: false,
            ledger_recovery_overcommit_draining: false,
            fact_recovery_overcommit_draining: false,
            projection_size_conflicts: 0,
        }
    }

    async fn catalog_scenario(
        steps: Vec<(u64, AuditResult, bool)>,
    ) -> (
        Vec<AuditStep>,
        std::sync::Arc<crate::workers::WorkerRegistry>,
        tokio_util::sync::CancellationToken,
    ) {
        capacity_scenario(
            steps
                .into_iter()
                .map(|(at, result, complete)| (AuditKind::Catalog, at, result, complete))
                .collect(),
        )
        .await
    }

    async fn ledger_scenario(
        steps: Vec<(u64, AuditResult, bool)>,
    ) -> (
        Vec<AuditStep>,
        std::sync::Arc<crate::workers::WorkerRegistry>,
        tokio_util::sync::CancellationToken,
    ) {
        capacity_scenario(
            steps
                .into_iter()
                .map(|(at, result, complete)| (AuditKind::Ledger, at, result, complete))
                .collect(),
        )
        .await
    }

    // Drive the production audit schedulers inside a real critical worker.
    // Only the database observation and monotonic clock are controlled; gate
    // transitions, heartbeat reporting and the three-error supervisor are real.
    async fn capacity_scenario(
        steps: Vec<(AuditKind, u64, AuditResult, bool)>,
    ) -> (
        Vec<AuditStep>,
        std::sync::Arc<crate::workers::WorkerRegistry>,
        tokio_util::sync::CancellationToken,
    ) {
        use crate::workers::{WorkerCriticality, WorkerMode, WorkerRegistry};
        use std::sync::{
            atomic::{AtomicUsize, Ordering},
            Arc,
        };

        let registry = WorkerRegistry::new();
        let cancel = tokio_util::sync::CancellationToken::new();
        let gate = healthy_gate();
        let start = Instant::now();
        let count = steps.len();
        let steps = Arc::new(steps);
        let calls = Arc::new(AtomicUsize::new(0));
        let (sent, mut received) = tokio::sync::mpsc::channel(count);
        let observed_registry = Arc::clone(&registry);
        registry.supervise(
            "test-upload-capacity-audit",
            WorkerCriticality::Critical,
            WorkerMode::Continuous,
            Some(Duration::from_secs(600)),
            cancel.clone(),
            move |heartbeat| {
                let steps = Arc::clone(&steps);
                let calls = Arc::clone(&calls);
                let gate = Arc::clone(&gate);
                let sent = sent.clone();
                let observed_registry = Arc::clone(&observed_registry);
                async move {
                    let mut authority = super::CapacityAuthorityAuditProgress::new(start);
                    let mut ledger = super::CapacityLedgerAuditProgress::new(start);
                    let existing = gate
                        .permit(crate::services::upload_safety::UploadIoClass::Promotion)
                        .unwrap();
                    for &(kind, milliseconds, result, complete_safe_work) in steps.iter() {
                        let now = start + Duration::from_millis(milliseconds);
                        let mut blocked = false;
                        let mut next_audit = authority.next_audit;
                        if matches!(kind, AuditKind::Catalog | AuditKind::Both(_)) {
                            let observation = authority
                                .audit_if_due(
                                    &gate,
                                    || now,
                                    || async {
                                        calls.fetch_add(1, Ordering::SeqCst);
                                        match result {
                                            AuditResult::Unavailable => {
                                                anyhow::bail!("injected catalog statement timeout")
                                            }
                                            AuditResult::Clean => Ok(
                                                crate::db::UploadCapacityAuthorityAudit::default(),
                                            ),
                                            AuditResult::Violation => {
                                                Ok(crate::db::UploadCapacityAuthorityAudit {
                                                    trigger_authority_violations: 1,
                                                    ..Default::default()
                                                })
                                            }
                                        }
                                    },
                                )
                                .await;
                            blocked = authority.report_blocked_before_ledger(
                                &ledger,
                                &heartbeat,
                                observation.is_some(),
                            );
                            next_audit = authority.next_audit;
                        }
                        // Preserve the production catalog -> early continue ->
                        // ledger order, including when both are due this tick.
                        if !blocked {
                            let ledger_result = match kind {
                                AuditKind::Catalog => None,
                                AuditKind::Ledger => Some(result),
                                AuditKind::Both(result) => Some(result),
                            };
                            if let Some(result) = ledger_result {
                                let observation = ledger
                                    .audit_if_due(
                                        &gate,
                                        || now,
                                        || async {
                                            calls.fetch_add(1, Ordering::SeqCst);
                                            match result {
                                                AuditResult::Unavailable => anyhow::bail!(
                                                    "injected ledger statement timeout"
                                                ),
                                                AuditResult::Clean => Ok(reconciliation(false)),
                                                AuditResult::Violation => Ok(reconciliation(true)),
                                            }
                                        },
                                    )
                                    .await;
                                blocked = ledger.report_blocked(&heartbeat, observation.is_some());
                                next_audit = ledger.next_audit;
                            }
                        }
                        let gate_before_completion = gate.state();
                        if blocked {
                            for class in [
                                super::UploadIoClass::NewWrite,
                                super::UploadIoClass::Promotion,
                                super::UploadIoClass::Recovery,
                                super::UploadIoClass::CredentialRefresh,
                            ] {
                                assert!(gate.permit(class).is_err());
                            }
                            assert!(existing.ensure_current().is_err());
                            // Immutable committed reads retain their existing
                            // capacity-failure exception.
                            assert!(gate.permit(super::UploadIoClass::Read).is_ok());
                        }
                        if complete_safe_work {
                            assert!(!blocked);
                            assert_eq!(authority.proof, super::CapacityAuditProof::Proven);
                            assert_eq!(ledger.proof, super::CapacityAuditProof::Proven);
                            // The unchanged caller only does this after its
                            // immutable tuple, ledger and remaining work pass.
                            gate.establish(STARTUP_GENERATION, false);
                            heartbeat.ok();
                        }
                        sent.send(AuditStep {
                            calls: calls.load(Ordering::SeqCst),
                            worker_ready: observed_registry.readiness_error().is_none(),
                            blocked,
                            gate_before_completion,
                            gate_after_completion: gate.state(),
                            next_audit: next_audit.duration_since(start),
                        })
                        .await
                        .unwrap();
                        tokio::task::yield_now().await;
                    }
                    std::future::pending::<anyhow::Result<()>>().await
                }
            },
        );
        let mut observations = Vec::new();
        for _ in 0..count {
            observations.push(
                tokio::time::timeout(Duration::from_secs(1), received.recv())
                    .await
                    .expect("catalog step must not block")
                    .expect("worker stopped before the expected observation"),
            );
        }
        (observations, registry, cancel)
    }

    #[tokio::test]
    async fn one_failed_catalog_read_stays_closed_without_recounting_wait_ticks() {
        use crate::services::upload_safety::UploadSafetyState;
        let steps = [0, 0, 1000, 5000, 10000, 14999]
            .into_iter()
            .map(|at| (at, AuditResult::Unavailable, false))
            .collect();
        let (observations, registry, cancel) = catalog_scenario(steps).await;
        for observation in observations {
            assert_eq!(observation.calls, 1);
            assert!(observation.blocked);
            assert_eq!(observation.next_audit, Duration::from_secs(15));
            assert_eq!(
                observation.gate_after_completion,
                UploadSafetyState::CapacityAuthorityUnsafe
            );
        }
        assert!(!cancel.is_cancelled());
        assert!(registry.critical_failure().is_none());
        registry
            .shutdown_and_join(&cancel, Duration::from_secs(1))
            .await;
    }

    #[tokio::test]
    async fn waiting_pulses_preserve_three_real_catalog_failures_as_terminal() {
        let steps = [0, 5000, 10000, 15000, 20000, 29999, 30000]
            .into_iter()
            .map(|at| (at, AuditResult::Unavailable, false))
            .collect();
        let (observations, registry, cancel) = catalog_scenario(steps).await;
        assert_eq!(
            observations
                .iter()
                .map(|step| step.calls)
                .collect::<Vec<_>>(),
            [1, 1, 1, 2, 2, 2, 3]
        );
        assert!(observations.iter().all(|step| step.blocked));
        tokio::time::timeout(Duration::from_secs(1), cancel.cancelled())
            .await
            .expect("only the third real failed observation must terminate the worker");
        assert!(registry
            .critical_failure()
            .unwrap()
            .contains("3 consecutive business-health errors: upload capacity enforcement authority is unproven"));
        registry
            .shutdown_and_join(&cancel, Duration::from_secs(1))
            .await;
    }

    #[tokio::test]
    async fn clean_catalog_observation_requires_the_remaining_success_boundary_to_reopen() {
        use crate::services::upload_safety::UploadSafetyState;
        let (observations, registry, cancel) = catalog_scenario(vec![
            (0, AuditResult::Unavailable, false),
            (15000, AuditResult::Clean, false),
            (15001, AuditResult::Clean, true),
            (75000, AuditResult::Unavailable, false),
            (90000, AuditResult::Unavailable, false),
        ])
        .await;
        assert!(!observations[1].blocked);
        assert_eq!(observations[1].next_audit, Duration::from_secs(75));
        assert_eq!(
            observations[1].gate_before_completion,
            UploadSafetyState::CapacityAuthorityUnsafe
        );
        assert_eq!(
            observations[1].gate_after_completion,
            UploadSafetyState::CapacityAuthorityUnsafe
        );
        assert_eq!(observations[2].calls, 2);
        assert_eq!(
            observations[2].gate_after_completion,
            UploadSafetyState::Healthy
        );
        assert_eq!(observations[4].calls, 4);
        assert!(observations[4].blocked);
        // The full successful boundary reset the first error; the following
        // two real failures must not be mistaken for three.
        assert!(!cancel.is_cancelled());
        assert!(registry.critical_failure().is_none());
        registry
            .shutdown_and_join(&cancel, Duration::from_secs(1))
            .await;
    }

    #[tokio::test]
    async fn observed_catalog_violations_keep_the_existing_per_tick_terminal_rule() {
        for steps in [
            vec![
                (0, AuditResult::Violation, false),
                (5000, AuditResult::Clean, false),
                (10000, AuditResult::Clean, false),
            ],
            vec![
                (0, AuditResult::Violation, false),
                (60000, AuditResult::Unavailable, false),
                (60001, AuditResult::Clean, false),
            ],
        ] {
            let (observations, registry, cancel) = catalog_scenario(steps).await;
            assert!(observations.iter().all(|step| step.blocked));
            tokio::time::timeout(Duration::from_secs(1), cancel.cancelled())
                .await
                .expect("a proved violation must retain the original terminal behavior");
            assert!(registry.critical_failure().is_some());
            registry
                .shutdown_and_join(&cancel, Duration::from_secs(1))
                .await;
        }
    }

    #[tokio::test]
    async fn one_failed_ledger_read_stays_closed_without_recounting_wait_ticks() {
        use crate::services::upload_safety::UploadSafetyState;
        let steps = [0, 0, 1000, 5000, 15000, 30000, 59999]
            .into_iter()
            .map(|at| (at, AuditResult::Unavailable, false))
            .collect();
        let (observations, registry, cancel) = ledger_scenario(steps).await;
        for observation in observations {
            assert_eq!(observation.calls, 1);
            assert!(observation.blocked);
            assert_eq!(observation.next_audit, Duration::from_secs(60));
            assert_eq!(
                observation.gate_after_completion,
                UploadSafetyState::LedgerMismatch
            );
        }
        assert!(!cancel.is_cancelled());
        assert!(registry.critical_failure().is_none());
        registry
            .shutdown_and_join(&cancel, Duration::from_secs(1))
            .await;
    }

    #[tokio::test]
    async fn waiting_pulses_preserve_three_real_ledger_failures_as_terminal() {
        let steps = [0, 5000, 59999, 60000, 65000, 119999, 120000]
            .into_iter()
            .map(|at| (at, AuditResult::Unavailable, false))
            .collect();
        let (observations, registry, cancel) = ledger_scenario(steps).await;
        assert_eq!(
            observations
                .iter()
                .map(|step| step.calls)
                .collect::<Vec<_>>(),
            [1, 1, 1, 2, 2, 2, 3]
        );
        assert!(observations.iter().all(|step| step.blocked));
        tokio::time::timeout(Duration::from_secs(1), cancel.cancelled())
            .await
            .expect("only the third real failed observation must terminate the worker");
        assert!(registry
            .critical_failure()
            .unwrap()
            .contains("3 consecutive business-health errors: upload capacity ledger does not match durable row facts"));
        registry
            .shutdown_and_join(&cancel, Duration::from_secs(1))
            .await;
    }

    #[tokio::test]
    async fn clean_ledger_observation_requires_the_remaining_success_boundary_to_reopen() {
        use crate::services::upload_safety::UploadSafetyState;
        let (observations, registry, cancel) = ledger_scenario(vec![
            (0, AuditResult::Unavailable, false),
            (60000, AuditResult::Clean, false),
            (60001, AuditResult::Clean, true),
            (3660000, AuditResult::Unavailable, false),
            (3720000, AuditResult::Unavailable, false),
        ])
        .await;
        assert!(!observations[1].blocked);
        assert_eq!(observations[1].next_audit, Duration::from_secs(3660));
        assert_eq!(
            observations[1].gate_before_completion,
            UploadSafetyState::LedgerMismatch
        );
        assert_eq!(
            observations[1].gate_after_completion,
            UploadSafetyState::LedgerMismatch
        );
        assert_eq!(observations[2].calls, 2);
        assert_eq!(
            observations[2].gate_after_completion,
            UploadSafetyState::Healthy
        );
        assert_eq!(observations[4].calls, 4);
        assert!(observations[4].blocked);
        // The full successful boundary reset the first error; the following
        // two real failures must not be mistaken for three.
        assert!(!cancel.is_cancelled());
        assert!(registry.critical_failure().is_none());
        registry
            .shutdown_and_join(&cancel, Duration::from_secs(1))
            .await;
    }

    #[tokio::test]
    async fn observed_ledger_violations_keep_the_existing_per_tick_terminal_rule() {
        for steps in [
            vec![
                (0, AuditResult::Violation, false),
                (5000, AuditResult::Clean, false),
                (10000, AuditResult::Clean, false),
            ],
            vec![
                (0, AuditResult::Violation, false),
                (300000, AuditResult::Unavailable, false),
                (300001, AuditResult::Clean, false),
            ],
        ] {
            let (observations, registry, cancel) = ledger_scenario(steps).await;
            assert!(observations.iter().all(|step| step.blocked));
            tokio::time::timeout(Duration::from_secs(1), cancel.cancelled())
                .await
                .expect("a proved violation must retain the original terminal behavior");
            assert!(registry.critical_failure().is_some());
            registry
                .shutdown_and_join(&cancel, Duration::from_secs(1))
                .await;
        }
    }

    #[tokio::test]
    async fn catalog_waits_preserve_a_previous_ledger_failure_and_independent_retry_deadlines() {
        let (observations, registry, cancel) = capacity_scenario(vec![
            (AuditKind::Ledger, 0, AuditResult::Unavailable, false),
            (AuditKind::Catalog, 0, AuditResult::Unavailable, false),
            (AuditKind::Catalog, 5000, AuditResult::Clean, false),
            (AuditKind::Catalog, 14999, AuditResult::Clean, false),
            (AuditKind::Catalog, 15000, AuditResult::Clean, false),
            (AuditKind::Ledger, 15001, AuditResult::Clean, false),
            (AuditKind::Ledger, 60000, AuditResult::Unavailable, false),
        ])
        .await;
        assert_eq!(
            observations
                .iter()
                .map(|step| step.calls)
                .collect::<Vec<_>>(),
            [1, 2, 2, 2, 3, 3, 4],
        );
        assert_eq!(observations[4].next_audit, Duration::from_secs(75));
        assert!(!observations[4].blocked);
        assert!(observations[5].blocked);
        assert_eq!(observations[5].next_audit, Duration::from_secs(60));
        assert_eq!(
            observations[4].gate_after_completion,
            crate::services::upload_safety::UploadSafetyState::CapacityAuthorityUnsafe,
        );
        tokio::time::timeout(Duration::from_secs(1), cancel.cancelled())
            .await
            .expect("catalog waits and partial success must not clear the earlier ledger error");
        assert!(registry.critical_failure().unwrap().contains(
            "3 consecutive business-health errors: upload capacity ledger does not match durable row facts"
        ));
        registry
            .shutdown_and_join(&cancel, Duration::from_secs(1))
            .await;
    }

    #[tokio::test]
    async fn catalog_retry_wait_cannot_hide_a_proved_ledger_violation_or_double_count_a_tick() {
        let (observations, registry, cancel) = capacity_scenario(vec![
            (
                AuditKind::Both(AuditResult::Violation),
                0,
                AuditResult::Clean,
                false,
            ),
            (
                AuditKind::Both(AuditResult::Clean),
                60000,
                AuditResult::Unavailable,
                false,
            ),
            (
                AuditKind::Both(AuditResult::Clean),
                65000,
                AuditResult::Clean,
                false,
            ),
        ])
        .await;
        assert_eq!(
            observations
                .iter()
                .map(|step| step.calls)
                .collect::<Vec<_>>(),
            [2, 3, 3],
            "catalog failure and its wait must not start another ledger audit",
        );
        assert_eq!(
            observations
                .iter()
                .map(|step| step.worker_ready)
                .collect::<Vec<_>>(),
            [true, true, false],
            "each tick reports exactly one error; the wait retains the known violation",
        );
        assert!(observations.iter().all(|step| step.blocked));
        assert_eq!(observations[0].next_audit, Duration::from_secs(300));
        assert_eq!(observations[1].next_audit, Duration::from_secs(75));
        assert_eq!(observations[2].next_audit, Duration::from_secs(75));
        tokio::time::timeout(Duration::from_secs(1), cancel.cancelled())
            .await
            .expect("the third tick must preserve the original terminal rule");
        assert!(registry.critical_failure().unwrap().contains(
            "3 consecutive business-health errors: upload capacity ledger does not match durable row facts"
        ));
        registry
            .shutdown_and_join(&cancel, Duration::from_secs(1))
            .await;
    }

    #[test]
    fn startup_audit_deadlines_include_startup_and_first_probe_time() {
        let start = Instant::now();
        let handoff = successful_startup(start);
        let first_probe_completed = start + Duration::from_secs(23);
        let deadlines = handoff.take().expect("startup proof").deadlines(
            STARTUP_GENERATION,
            STARTUP_LIMITS,
            &healthy_gate(),
            first_probe_completed,
        );
        assert_eq!(deadlines.0, start + Duration::from_secs(60));
        assert_eq!(deadlines.1, start + Duration::from_secs(3607));
        assert!(
            handoff.take().is_none(),
            "a restarted worker must audit again"
        );
    }

    #[test]
    fn startup_audits_expire_independently_at_the_original_boundaries() {
        let start = Instant::now();
        for elapsed in [59, 60, 3606, 3607, 7200] {
            let now = start + Duration::from_secs(elapsed);
            let (authority, ledger) = successful_startup(start)
                .take()
                .expect("startup proof")
                .deadlines(STARTUP_GENERATION, STARTUP_LIMITS, &healthy_gate(), now);
            assert_eq!(now >= authority, elapsed >= 60);
            assert_eq!(now >= ledger, elapsed >= 3607);
        }
    }

    #[test]
    fn startup_evidence_cannot_cross_generation_or_policy_limits() {
        let start = Instant::now();
        let now = start + Duration::from_secs(23);
        let mut cases = vec![
            (UploadAuthorityGeneration::new(8, 11), STARTUP_LIMITS),
            (UploadAuthorityGeneration::new(7, 12), STARTUP_LIMITS),
        ];
        for index in 0..STARTUP_LIMITS.len() {
            let mut changed_limits = STARTUP_LIMITS;
            changed_limits[index] += 1;
            cases.push((STARTUP_GENERATION, changed_limits));
        }
        for (generation, limits) in cases {
            let gate = UploadSafetyGate::new();
            gate.establish(generation, false);
            assert_eq!(
                successful_startup(start)
                    .take()
                    .expect("startup proof")
                    .deadlines(generation, limits, &gate, now,),
                (now, now),
            );
        }
        let gate = UploadSafetyGate::new();
        gate.establish(UploadAuthorityGeneration::new(7, 12), false);
        assert_eq!(
            successful_startup(start)
                .take()
                .expect("startup proof")
                .deadlines(STARTUP_GENERATION, STARTUP_LIMITS, &gate, now,),
            (now, now),
            "the current gate generation must also match",
        );
    }

    #[test]
    fn startup_evidence_requires_a_still_healthy_gate_after_the_probe() {
        let start = Instant::now();
        let now = start + Duration::from_secs(23);
        let gates = [
            UploadSafetyGate::new(),
            UploadSafetyGate::disabled(),
            healthy_gate(),
            healthy_gate(),
            healthy_gate(),
            healthy_gate(),
        ];
        gates[2].establish(STARTUP_GENERATION, true);
        gates[3].mark_namespace_unsafe("changed during first probe");
        gates[4].mark_capacity_authority_unsafe("first probe failed");
        gates[5].mark_ledger_mismatch("ledger invalidated during first probe");
        for gate in gates {
            assert_eq!(
                successful_startup(start)
                    .take()
                    .expect("startup proof")
                    .deadlines(STARTUP_GENERATION, STARTUP_LIMITS, &gate, now,),
                (now, now),
            );
        }
    }

    #[test]
    fn discarded_first_attempt_cannot_reuse_startup_evidence_after_recovery() {
        let handoff = successful_startup(Instant::now());
        let gate = healthy_gate();
        {
            let _first_attempt = handoff.take().expect("startup proof");
            gate.mark_capacity_authority_unsafe("first namespace/policy probe failed");
            // A failed first probe or cancellation drops the taken evidence without
            // converting it into deadlines. Re-establishing health cannot restore it.
        }
        gate.establish(STARTUP_GENERATION, false);
        assert!(handoff.take().is_none());
        assert!(StartupAuditHandoff::default().take().is_none());
    }

    #[test]
    fn concurrent_workers_cannot_share_startup_evidence() {
        let handoff = std::sync::Arc::new(successful_startup(Instant::now()));
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(8));
        let attempts: Vec<_> = (0..8)
            .map(|_| {
                let handoff = std::sync::Arc::clone(&handoff);
                let barrier = std::sync::Arc::clone(&barrier);
                std::thread::spawn(move || {
                    barrier.wait();
                    usize::from(handoff.take().is_some())
                })
            })
            .collect();
        let proofs: usize = attempts
            .into_iter()
            .map(|attempt| attempt.join().expect("worker attempt"))
            .sum();
        assert_eq!(proofs, 1);
        assert!(handoff.take().is_none());
    }

    #[test]
    fn startup_evidence_rejects_future_or_reversed_observation_times() {
        let start = Instant::now();
        let now = start + Duration::from_secs(23);
        for (authority, ledger) in [(now, start), (start, now + Duration::from_secs(1))] {
            let handoff = StartupAuditHandoff::after_successful_audits(
                STARTUP_GENERATION,
                STARTUP_LIMITS,
                authority,
                ledger,
            );
            assert_eq!(
                handoff.take().expect("startup proof").deadlines(
                    STARTUP_GENERATION,
                    STARTUP_LIMITS,
                    &healthy_gate(),
                    now,
                ),
                (now, now),
            );
            assert!(handoff.take().is_none());
        }
    }

    #[test]
    fn poisoned_startup_handoff_discards_evidence() {
        let handoff = successful_startup(Instant::now());
        let result = std::panic::catch_unwind(|| {
            let _guard = handoff.evidence.lock().expect("unpoisoned handoff");
            panic!("interrupt startup evidence transfer");
        });
        assert!(result.is_err());
        assert!(handoff.take().is_none());
        assert!(handoff.take().is_none());
    }
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
