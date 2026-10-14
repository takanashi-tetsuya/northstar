use super::{Duration, StartupAuditHandoff, UploadAuthorityGeneration, UploadSafetyGate};
use crate::services::upload_maintenance::{
    UploadCapacityAuthorityAudit, UploadCapacityReconciliation,
};
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

fn reconciliation(mismatch: bool) -> UploadCapacityReconciliation {
    UploadCapacityReconciliation {
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
    std::sync::Arc<crate::runtime::workers::WorkerRegistry>,
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
    std::sync::Arc<crate::runtime::workers::WorkerRegistry>,
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
    std::sync::Arc<crate::runtime::workers::WorkerRegistry>,
    tokio_util::sync::CancellationToken,
) {
    use crate::runtime::workers::{WorkerCriticality, WorkerMode, WorkerRegistry};
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
                                        AuditResult::Clean => {
                                            Ok(UploadCapacityAuthorityAudit::default())
                                        }
                                        AuditResult::Violation => {
                                            Ok(UploadCapacityAuthorityAudit {
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
                                            AuditResult::Unavailable => {
                                                anyhow::bail!("injected ledger statement timeout")
                                            }
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
    assert!(registry.critical_failure().unwrap().contains(
        "3 consecutive business-health errors: upload capacity enforcement authority is unproven"
    ));
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
