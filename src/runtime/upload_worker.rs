use anyhow::{Context, Result};
use futures::{stream, StreamExt};
use northstar_runtime::workers::WorkerHeartbeat;
use northstar_upload_application::maintenance::*;
use northstar_upload_application::safety::UploadSafetyGate;
use northstar_upload_application::{UploadAuthorityGeneration, UploadIoClass};
use std::{
    sync::{atomic::Ordering, Arc},
    time::Duration,
};
use tokio_util::sync::CancellationToken;

#[derive(Clone, Copy)]
pub(crate) struct UploadMaintenancePolicy {
    pub(crate) max_pending_jobs: i64,
    pub(crate) max_retained_files: i64,
    pub(crate) max_retained_bytes: i64,
    pub(crate) retention_seconds: u64,
    pub(crate) namespace_sha256: [u8; 32],
    pub(crate) generation: UploadAuthorityGeneration,
}

pub(crate) struct UploadMaintenanceContext<R> {
    repository: R,
    store: Arc<dyn northstar_upload_storage::UploadStore>,
    policy: UploadMaintenancePolicy,
    safety_gate: Arc<UploadSafetyGate>,
    startup_audits: Arc<StartupAuditHandoff>,
    metrics: Arc<northstar_telemetry::metrics::Metrics>,
}

impl<R: UploadMaintenanceRepository> UploadMaintenanceContext<R> {
    pub(crate) fn new(
        repository: R,
        store: Arc<dyn northstar_upload_storage::UploadStore>,
        policy: UploadMaintenancePolicy,
        safety_gate: Arc<UploadSafetyGate>,
        startup_audits: Arc<StartupAuditHandoff>,
        metrics: Arc<northstar_telemetry::metrics::Metrics>,
    ) -> Self {
        Self {
            repository,
            store,
            policy,
            safety_gate,
            startup_audits,
            metrics,
        }
    }
}

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
/// The process-wide gate, not this scheduling context, authorizes object I/O.
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
    ) -> Option<Result<UploadCapacityAuthorityAudit>>
    where
        A: FnOnce() -> F,
        F: std::future::Future<Output = Result<UploadCapacityAuthorityAudit>>,
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
    ) -> Option<Result<UploadCapacityReconciliation>>
    where
        A: FnOnce() -> F,
        F: std::future::Future<Output = Result<UploadCapacityReconciliation>>,
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
                // The caller reopens the gate after all authority and probe checks.
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

/// Startup may hand its successful observations to one worker
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
        // query/commit time. Later application initialization or worker scheduling
        // must never grant the old observation a fresh 60-second/hour lifetime.
        (
            self.authority_started_at + CAPACITY_AUTHORITY_AUDIT_INTERVAL,
            self.ledger_started_at + CAPACITY_LEDGER_AUDIT_INTERVAL,
        )
    }
}

pub(crate) async fn serve<R: UploadMaintenanceRepository>(
    context: Arc<UploadMaintenanceContext<R>>,
    cancel: CancellationToken,
    heartbeat: WorkerHeartbeat,
) -> Result<()> {
    let mut interval = tokio::time::interval(Duration::from_secs(5));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut credential_ticks = 0_u8;
    let mut startup_audits = context.startup_audits.take();
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
        context
            .metrics
            .upload_storage_safety_gate_state
            .store(context.safety_gate.metric_code(), Ordering::Relaxed);
        let authority_generation = context.policy.generation;
        let recovery_draining = match context
            .repository
            .upload_storage_authority_matches(
                context.store.backend(),
                &context.policy.namespace_sha256,
                authority_generation.namespace,
                authority_generation.capacity_policy,
                context.policy.max_pending_jobs,
                context.policy.max_retained_files,
                context.policy.max_retained_bytes,
            )
            .await
        {
            Ok(probe) if !probe.namespace_matches => {
                context.safety_gate.mark_namespace_unsafe(
                    "upload namespace authority changed while this process was running",
                );
                context
                    .metrics
                    .upload_storage_safety_gate_state
                    .store(context.safety_gate.metric_code(), Ordering::Relaxed);
                anyhow::bail!(
                    "upload storage authority disappeared or changed while this process was running"
                );
            }
            Ok(probe) if !probe.capacity_matches => {
                context.safety_gate.mark_capacity_authority_unsafe(
                    "upload capacity policy generation changed while this process was running",
                );
                heartbeat.error("upload capacity authority changed");
                continue;
            }
            Ok(probe) => probe.recovery_draining,
            Err(error) => {
                context.safety_gate.mark_capacity_authority_unsafe(
                    "upload authority could not be proved from PostgreSQL",
                );
                note_reconciliation_failure(&context);
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
                    context.policy.max_pending_jobs,
                    context.policy.max_retained_files,
                    context.policy.max_retained_bytes,
                ],
                &context.safety_gate,
                tokio::time::Instant::now(),
            );
        }
        let authority_observation = capacity_authority_audit
            .audit_if_due(&context.safety_gate, tokio::time::Instant::now, || {
                context.repository.audit_upload_capacity_authority(
                    context.policy.max_pending_jobs,
                    context.policy.max_retained_files,
                    context.policy.max_retained_bytes,
                )
            })
            .await;
        let authority_audited = authority_observation.is_some();
        if let Some(observation) = authority_observation {
            let capacity_authority_violations = capacity_authority_audit.violations;
            context
                .metrics
                .upload_storage_capacity_authority_violations
                .store(capacity_authority_violations, Ordering::Relaxed);
            match observation {
                Ok(audit) => {
                    if capacity_authority_violations > 0 {
                        note_reconciliation_failure(&context);
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
                    note_reconciliation_failure(&context);
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
            .audit_if_due(&context.safety_gate, tokio::time::Instant::now, || {
                context.repository.reconcile_upload_capacity_ledger()
            })
            .await;
        let ledger_audited = ledger_observation.is_some();
        if let Some(observation) = ledger_observation {
            let capacity_ledger_mismatches = capacity_ledger_audit.mismatches;
            context
                .metrics
                .upload_storage_capacity_ledger_mismatches
                .store(capacity_ledger_mismatches, Ordering::Relaxed);
            match observation {
                Ok(audit) => {
                    if capacity_ledger_mismatches > 0 {
                        note_reconciliation_failure(&context);
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
                    note_reconciliation_failure(&context);
                    tracing::error!(?error, "could not prove upload capacity ledger consistency");
                }
            }
        }
        if capacity_ledger_audit.report_blocked(&heartbeat, ledger_audited) {
            continue;
        }
        context
            .safety_gate
            .establish(authority_generation, recovery_draining);
        context
            .metrics
            .upload_storage_safety_gate_state
            .store(context.safety_gate.metric_code(), Ordering::Relaxed);
        if let Err(error) = context.repository.cleanup_expired_upload_slots().await {
            tracing::error!(?error, "failed to queue expired upload storage cleanup");
            failures += 1;
            note_reconciliation_failure(&context);
        }

        match context.repository.claim_upload_storage_jobs().await {
            Ok(jobs) => {
                let outcomes = stream::iter(jobs).map(|job| {
                    let context = Arc::clone(&context);
                    async move {
                        let result = process_storage_job(&context, &job).await;
                        (job, result)
                    }
                });
                let mut outcomes = outcomes.buffer_unordered(4);
                while let Some((job, result)) = outcomes.next().await {
                    match result {
                        Ok(StorageOutcome::Completed) => {
                            note_storage_job_success(&context, &job.action)
                        }
                        Ok(StorageOutcome::Deferred) => {}
                        Err(error) => {
                            if northstar_upload_storage::is_upload_safety_error(&error) {
                                if let Err(db_error) = context
                                    .repository
                                    .defer_upload_storage_job(job.id, job.claim_token)
                                    .await
                                {
                                    failures += 1;
                                    note_reconciliation_failure(&context);
                                    tracing::error!(
                                        job_id = job.id,
                                        ?db_error,
                                        "failed to defer upload storage job after authority invalidation"
                                    );
                                }
                                continue;
                            }
                            failures += 1;
                            note_storage_job_failure(&context, &job.action, &error);
                            tracing::error!(job_id=job.id, upload_id=%job.object_id, action=%job.action, ?error, "upload storage reconciliation failed");
                            if let Err(db_error) = context
                                .repository
                                .fail_upload_storage_job(
                                    job.id,
                                    job.claim_token,
                                    &error.to_string(),
                                )
                                .await
                            {
                                failures += 1;
                                note_reconciliation_failure(&context);
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
                note_reconciliation_failure(&context);
                tracing::error!(?error, "failed to claim upload storage jobs");
            }
        }
        heartbeat.pulse();

        match context.repository.queued_upload_cleanup().await {
            Ok(jobs) => {
                let outcomes = stream::iter(jobs).map(|job| {
                    let context = Arc::clone(&context);
                    async move {
                        let result = process_cleanup_job(&context, &job).await;
                        (job, result)
                    }
                });
                let mut outcomes = outcomes.buffer_unordered(4);
                while let Some((job, result)) = outcomes.next().await {
                    match result {
                        Ok(CleanupOutcome::Completed) => {
                            context
                                .metrics
                                .upload_storage_cleanup_success_total
                                .fetch_add(1, Ordering::Relaxed);
                        }
                        Ok(CleanupOutcome::Deferred) => {}
                        Err(error) => {
                            if northstar_upload_storage::is_upload_safety_error(&error) {
                                if let Err(db_error) = context
                                    .repository
                                    .defer_queued_upload_cleanup(job.object_id, job.claim_token)
                                    .await
                                {
                                    failures += 1;
                                    note_reconciliation_failure(&context);
                                    tracing::error!(upload_id=%job.object_id, ?db_error, "failed to defer upload cleanup after authority invalidation");
                                }
                                continue;
                            }
                            failures += 1;
                            note_reconciliation_failure(&context);
                            context
                                .metrics
                                .upload_storage_cleanup_failures_total
                                .fetch_add(1, Ordering::Relaxed);
                            if northstar_upload_storage::is_upload_integrity_error(&error) {
                                context
                                    .metrics
                                    .upload_storage_integrity_failures_total
                                    .fetch_add(1, Ordering::Relaxed);
                            }
                            tracing::error!(upload_id=%job.object_id, ?error, "upload object deletion failed");
                            if let Err(db_error) = context
                                .repository
                                .fail_queued_upload_cleanup(
                                    job.object_id,
                                    job.claim_token,
                                    &error.to_string(),
                                )
                                .await
                            {
                                failures += 1;
                                note_reconciliation_failure(&context);
                                tracing::error!(upload_id=%job.object_id, ?db_error, "failed to release upload cleanup job");
                            }
                        }
                    }
                }
            }
            Err(error) => {
                failures += 1;
                note_reconciliation_failure(&context);
                tracing::error!(?error, "failed to claim upload cleanup jobs");
            }
        }
        heartbeat.pulse();

        credential_ticks = credential_ticks.saturating_add(1);
        if credential_ticks >= 12 {
            credential_ticks = 0;
            match context.store.reload_credentials().await {
                Ok(_) => {}
                Err(error) if northstar_upload_storage::is_upload_safety_error(&error) => {
                    tracing::warn!(
                        ?error,
                        "upload credential refresh deferred by authority gate"
                    );
                }
                Err(error) => {
                    failures += 1;
                    note_reconciliation_failure(&context);
                    context
                        .metrics
                        .upload_storage_credential_refresh_failures_total
                        .fetch_add(1, Ordering::Relaxed);
                    tracing::error!(?error, "failed to refresh upload-store credentials");
                }
            }
        }
        match context.repository.claim_upload_scrub_jobs().await {
            Ok(jobs) => {
                for job in jobs {
                    let verified = tokio::time::timeout(
                        STORAGE_OPERATION_TIMEOUT,
                        context.store.commit(
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
                            match context
                                .repository
                                .complete_upload_scrub(job.object_id, job.claim_token)
                                .await
                            {
                                Ok(true) => {
                                    context
                                        .metrics
                                        .upload_storage_scrub_success_total
                                        .fetch_add(1, Ordering::Relaxed);
                                }
                                Ok(false) | Err(_) => {
                                    failures += 1;
                                    note_reconciliation_failure(&context);
                                    context
                                        .metrics
                                        .upload_storage_scrub_failures_total
                                        .fetch_add(1, Ordering::Relaxed);
                                }
                            }
                        }
                        Err(error) if northstar_upload_storage::is_upload_safety_error(&error) => {
                            if let Err(db_error) = context
                                .repository
                                .defer_upload_scrub(job.object_id, job.claim_token)
                                .await
                            {
                                failures += 1;
                                note_reconciliation_failure(&context);
                                tracing::error!(upload_id=%job.object_id, ?db_error, "failed to defer upload scrub after authority invalidation");
                            }
                        }
                        Ok(_) | Err(_) => {
                            failures += 1;
                            note_reconciliation_failure(&context);
                            context
                                .metrics
                                .upload_storage_scrub_failures_total
                                .fetch_add(1, Ordering::Relaxed);
                            let _ = context
                                .repository
                                .fail_upload_scrub(job.object_id, job.claim_token)
                                .await;
                            tracing::error!(upload_id=%job.object_id, "committed upload manifest scrub failed closed");
                        }
                    }
                    heartbeat.pulse();
                }
            }
            Err(error) => {
                failures += 1;
                note_reconciliation_failure(&context);
                tracing::error!(?error, "failed to claim upload manifest scrub jobs");
            }
        }
        match context.repository.upload_queue_metrics().await {
            Ok(snapshot) => {
                context
                    .metrics
                    .upload_storage_jobs_pending
                    .store(snapshot.storage_jobs_pending, Ordering::Relaxed);
                context
                    .metrics
                    .upload_storage_cleanup_pending
                    .store(snapshot.cleanup_jobs_pending, Ordering::Relaxed);
                context
                    .metrics
                    .upload_storage_cleanup_obligation_debt
                    .store(snapshot.cleanup_obligation_debt, Ordering::Relaxed);
                context
                    .metrics
                    .upload_storage_configured_pending_limit
                    .store(snapshot.configured_pending_limit, Ordering::Relaxed);
                context
                    .metrics
                    .upload_storage_legacy_overcommit_draining
                    .store(snapshot.legacy_overcommit_draining, Ordering::Relaxed);
                context
                    .metrics
                    .upload_storage_recovery_retained_files
                    .store(snapshot.recovery_retained_files, Ordering::Relaxed);
                context
                    .metrics
                    .upload_storage_recovery_retained_bytes
                    .store(snapshot.recovery_retained_bytes, Ordering::Relaxed);
                context
                    .metrics
                    .upload_storage_recovery_overcommit_draining
                    .store(snapshot.recovery_overcommit_draining, Ordering::Relaxed);
                context
                    .metrics
                    .upload_storage_oldest_pending_age_seconds
                    .store(snapshot.oldest_pending_age_seconds, Ordering::Relaxed);
                context
                    .metrics
                    .upload_storage_dead_letter_jobs
                    .store(snapshot.dead_letter_jobs_capped, Ordering::Relaxed);
                context
                    .metrics
                    .upload_storage_scrub_failures
                    .store(snapshot.scrub_failures_capped, Ordering::Relaxed);
                context
                    .metrics
                    .upload_storage_scrub_due_capped
                    .store(snapshot.scrub_due_capped, Ordering::Relaxed);
                context
                    .metrics
                    .upload_storage_scrub_oldest_overdue_seconds
                    .store(snapshot.scrub_oldest_overdue_seconds, Ordering::Relaxed);
                context
                    .metrics
                    .upload_storage_cleanup_obligations_due_capped
                    .store(snapshot.cleanup_obligations_due_capped, Ordering::Relaxed);
                context
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
                    || reserved_recovery >= context.policy.max_pending_jobs as u64
                    || snapshot.oldest_pending_age_seconds > 900
                {
                    failures += 1;
                    note_reconciliation_failure(&context);
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
                note_reconciliation_failure(&context);
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

fn note_reconciliation_failure<R: UploadMaintenanceRepository>(
    context: &UploadMaintenanceContext<R>,
) {
    context
        .metrics
        .upload_storage_reconciliation_failures_total
        .fetch_add(1, Ordering::Relaxed);
}

fn note_storage_job_success<R: UploadMaintenanceRepository>(
    context: &UploadMaintenanceContext<R>,
    action: &str,
) {
    let counter = match action {
        "promote" => &context.metrics.upload_storage_promotion_success_total,
        "delete_stage" => &context.metrics.upload_storage_stage_deletion_success_total,
        "delete_object" => &context.metrics.upload_storage_object_deletion_success_total,
        _ => return,
    };
    counter.fetch_add(1, Ordering::Relaxed);
}

fn note_storage_job_failure<R: UploadMaintenanceRepository>(
    context: &UploadMaintenanceContext<R>,
    action: &str,
    error: &anyhow::Error,
) {
    note_reconciliation_failure(context);
    let counter = match action {
        "promote" => &context.metrics.upload_storage_promotion_failures_total,
        "delete_stage" => &context.metrics.upload_storage_stage_deletion_failures_total,
        "delete_object" => {
            &context
                .metrics
                .upload_storage_object_deletion_failures_total
        }
        _ => return,
    };
    counter.fetch_add(1, Ordering::Relaxed);
    if northstar_upload_storage::is_upload_integrity_error(error) {
        context
            .metrics
            .upload_storage_integrity_failures_total
            .fetch_add(1, Ordering::Relaxed);
    }
}

enum StorageOutcome {
    Completed,
    Deferred,
}

async fn process_storage_job<R: UploadMaintenanceRepository>(
    context: &UploadMaintenanceContext<R>,
    job: &UploadStorageJob,
) -> Result<StorageOutcome> {
    anyhow::ensure!(
        job.storage_backend == context.store.backend(),
        "job targets a different upload storage backend"
    );
    match job.action.as_str() {
        "promote" => {
            let size = u64::try_from(job.expected_size.context("promote job has no size")?)?;
            let digest = job.expected_sha256.context("promote job has no digest")?;
            if !context
                .repository
                .begin_upload_promotion(
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
                if context
                    .repository
                    .upload_attempt_is_committed(CommittedUploadIdentity {
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
                    })
                    .await?
                {
                    delete_distinct_stage_after_commit(context, job).await?;
                    anyhow::ensure!(
                        context
                            .repository
                            .complete_upload_storage_job(job.id, job.claim_token)
                            .await?,
                        "upload promotion job lease changed before completion"
                    );
                    return Ok(StorageOutcome::Completed);
                }
                anyhow::ensure!(
                    context
                        .repository
                        .retire_upload_promotion_for_cleanup(
                            job.object_id,
                            job.storage_attempt,
                            job.storage_fence,
                            job.claim_token,
                        )
                        .await?,
                    "promotion lost authority without an exact committed or deleting projection"
                );
                delete_uncommitted_attempt(context, job).await?;
                return Ok(StorageOutcome::Completed);
            }
            let promoted = tokio::time::timeout(
                STORAGE_OPERATION_TIMEOUT,
                context.store.commit(
                    &job.object_id.to_string(),
                    &job.storage_attempt.to_string(),
                    job.stage_version.as_deref(),
                    size,
                    &digest,
                ),
            )
            .await
            .context("upload promotion timed out")??;
            let committed = context
                .repository
                .complete_promoted_upload(PromotedUploadProjection {
                    id: job.object_id,
                    claim_token: job.storage_attempt,
                    promotion_claim_token: job.claim_token,
                    storage_backend: &promoted.backend,
                    object_key: &promoted.object_key,
                    object_version: promoted.object_version.as_deref(),
                    content_sha256: &digest,
                    size: promoted.size,
                    retention_seconds: context.policy.retention_seconds,
                    storage_fence: job.storage_fence,
                })
                .await?;
            if !committed {
                if context
                    .repository
                    .upload_attempt_is_committed(CommittedUploadIdentity {
                        id: job.object_id,
                        storage_attempt: job.storage_attempt,
                        storage_backend: &promoted.backend,
                        object_key: &promoted.object_key,
                        object_version: promoted.object_version.as_deref(),
                        content_sha256: &digest,
                        size: promoted.size,
                        storage_fence: job.storage_fence,
                    })
                    .await?
                {
                    // A concurrent worker may have committed the same immutable
                    // destination. Stage cleanup is idempotent; destination
                    // deletion is performed only by an exact durable delete job.
                    delete_distinct_stage_after_commit(context, job).await?;
                    anyhow::ensure!(
                        context
                            .repository
                            .complete_upload_storage_job(job.id, job.claim_token)
                            .await?,
                        "upload promotion job lease changed before completion"
                    );
                } else {
                    anyhow::ensure!(
                        context
                            .repository
                            .retire_upload_promotion_for_cleanup(
                                job.object_id,
                                job.storage_attempt,
                                job.storage_fence,
                                job.claim_token,
                            )
                            .await?,
                        "upload attempt lost authority without an exact cleanup projection"
                    );
                    delete_uncommitted_attempt(context, job).await?;
                }
            }
        }
        "delete_stage" => {
            let removed = tokio::time::timeout(
                STORAGE_OPERATION_TIMEOUT,
                context.store.abort(
                    &job.object_id.to_string(),
                    &job.storage_attempt.to_string(),
                    job.stage_version.as_deref(),
                ),
            )
            .await
            .context("upload stage deletion timed out")??;
            if job.storage_backend == "s3"
                && !context
                    .repository
                    .confirm_upload_stage_absence(job.id, job.claim_token, removed, 300)
                    .await?
            {
                return Ok(StorageOutcome::Deferred);
            }
            anyhow::ensure!(
                context
                    .repository
                    .complete_upload_storage_job(job.id, job.claim_token)
                    .await?,
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
                context.store.delete(key, job.object_version.as_deref()),
            )
            .await
            .context("upload object deletion timed out")??;
            anyhow::ensure!(
                context
                    .repository
                    .complete_upload_storage_job(job.id, job.claim_token)
                    .await?,
                "upload object-deletion job lease changed before completion"
            );
        }
        _ => anyhow::bail!("unknown upload storage job action"),
    }
    Ok(StorageOutcome::Completed)
}

async fn delete_distinct_stage_after_commit<R: UploadMaintenanceRepository>(
    context: &UploadMaintenanceContext<R>,
    job: &UploadStorageJob,
) -> Result<()> {
    if job.stage_key == job.object_key {
        return Ok(());
    }
    delete_uncommitted_attempt(context, job).await
}

async fn delete_uncommitted_attempt<R: UploadMaintenanceRepository>(
    context: &UploadMaintenanceContext<R>,
    job: &UploadStorageJob,
) -> Result<()> {
    tokio::time::timeout(
        STORAGE_OPERATION_TIMEOUT,
        context.store.abort(
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

async fn process_cleanup_job<R: UploadMaintenanceRepository>(
    context: &UploadMaintenanceContext<R>,
    job: &UploadCleanupJob,
) -> Result<CleanupOutcome> {
    anyhow::ensure!(
        job.storage_backend == context.store.backend(),
        "cleanup targets a different upload storage backend"
    );
    // Normal S3 admission gives the stage and committed locator the same
    // version. A tombstone naming two versions at one key has ambiguous
    // database authority: deleting either one could release metadata while
    // the other remains. Preserve it, including its capacity charge, for
    // operator repair.
    anyhow::ensure!(
        !(job.storage_backend == "s3"
            && job.stage_key.as_deref() == Some(job.object_key.as_str())
            && job.stage_version.as_deref() != job.object_version.as_deref()),
        "cleanup names two object-store versions at one key; database authority is ambiguous"
    );
    if !context
        .repository
        .upload_cleanup_generation_is_quiescent(job.object_id, job.claim_token, job.storage_fence)
        .await?
    {
        let _ = context
            .repository
            .defer_queued_upload_cleanup(job.object_id, job.claim_token)
            .await?;
        return Ok(CleanupOutcome::Deferred);
    }
    let object_removed = tokio::time::timeout(
        STORAGE_OPERATION_TIMEOUT,
        context
            .store
            .delete(&job.object_key, job.object_version.as_deref()),
    )
    .await
    .context("upload cleanup timed out")??;
    let mut removed_any = object_removed;
    if job.stage_key.as_deref() != Some(job.object_key.as_str()) {
        if let Some(attempt) = job.storage_attempt {
            let stage_removed = tokio::time::timeout(
                STORAGE_OPERATION_TIMEOUT,
                context.store.abort(
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
        && !context
            .repository
            .confirm_upload_cleanup_absence(job.object_id, job.claim_token, removed_any, 300)
            .await?
    {
        // The durable tombstone remains queued. A later pass must observe the
        // same key absent after the quiet period before metadata can vanish.
        return Ok(CleanupOutcome::Deferred);
    }
    anyhow::ensure!(
        context
            .repository
            .complete_queued_upload_cleanup(job.object_id, job.claim_token)
            .await?,
        "upload cleanup lease changed before completion"
    );
    Ok(CleanupOutcome::Completed)
}

#[cfg(test)]
mod tests;
