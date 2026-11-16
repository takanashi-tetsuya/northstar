use super::{finish_live_session_release, run_cleanup_step, CleanupRecovery, CleanupReport};
use std::sync::Arc;
use uuid::Uuid;

fn cleanup_observer() -> Arc<northstar_runtime::workers::WorkerRegistry> {
    let registry = northstar_runtime::workers::WorkerRegistry::new();
    registry.register_observer(
        "session-cleanup",
        northstar_runtime::workers::WorkerCriticality::Restartable,
    );
    registry
}

/// The exact live-session release as a closed pool answers it.
fn closed_pool_release(connection_id: Uuid) -> anyhow::Result<bool> {
    anyhow::bail!("pool closed before releasing live session {connection_id}")
}

#[test]
fn empty_reports_neither_interrupt_consecutive_errors_nor_heal_cleanup_debt() {
    let registry = cleanup_observer();
    let mut failed = CleanupReport::default();
    failed.failed("release-live-session", CleanupRecovery::LeaseOrEpoch);
    for attempt in 1..=3 {
        failed.observe(&registry);
        CleanupReport::default().observe(&registry);
        assert_eq!(registry.readiness_error().is_some(), attempt == 3);
    }
    for _ in 0..10 {
        CleanupReport::default().observe(&registry);
    }
    assert!(registry.readiness_error().is_some());
}

#[tokio::test]
async fn only_completed_steps_without_failures_can_restore_cleanup_health() {
    let registry = cleanup_observer();
    let mut mixed = CleanupReport::default();
    assert_eq!(
        run_cleanup_step(
            tokio::time::Instant::now() + std::time::Duration::from_secs(1),
            "clear-active-privacy",
            CleanupRecovery::LeaseOrEpoch,
            async { Ok(()) },
            &mut mixed,
        )
        .await,
        Some(())
    );
    mixed.failed("release-live-session", CleanupRecovery::LeaseOrEpoch);
    for _ in 0..3 {
        mixed.observe(&registry);
    }
    assert!(
        registry.readiness_error().is_some(),
        "success must not hide another failed step"
    );
    let mut recovered = CleanupReport::default();
    assert_eq!(
        run_cleanup_step(
            tokio::time::Instant::now() + std::time::Duration::from_secs(1),
            "release-live-session",
            CleanupRecovery::LeaseOrEpoch,
            async { Ok(true) },
            &mut recovered,
        )
        .await,
        Some(true)
    );
    recovered.observe(&registry);
    assert!(registry.readiness_error().is_none());
}

#[tokio::test]
async fn unowned_or_suspended_cleanup_never_polls_the_exact_database_release() {
    let registry = cleanup_observer();
    for _ in 0..3 {
        registry.observer_error("session-cleanup", "existing real cleanup debt");
    }
    // The release step fails like a closed database pool once polled. The
    // same lazy release boundary used by finish must leave it untouched.
    for (may_own, suspended) in [(false, false), (false, true), (true, true)] {
        let polled = std::cell::Cell::new(false);
        let mut report = CleanupReport::default();
        finish_live_session_release(may_own, suspended, async {
            let _ = run_cleanup_step(
                tokio::time::Instant::now() + std::time::Duration::from_secs(1),
                "release-live-session",
                CleanupRecovery::LeaseOrEpoch,
                async {
                    polled.set(true);
                    closed_pool_release(Uuid::new_v4())
                },
                &mut report,
            )
            .await;
        })
        .await;
        assert!(!polled.get());
        assert!(report.is_clean());
        assert_eq!(report.completed_steps(), 0);
        report.observe(&registry);
        assert!(
            registry.readiness_error().is_some(),
            "no-op cleanup cannot erase prior debt"
        );
    }
    let polled = std::cell::Cell::new(false);
    let mut owned = CleanupReport::default();
    finish_live_session_release(true, false, async {
        let _ = run_cleanup_step(
            tokio::time::Instant::now() + std::time::Duration::from_secs(1),
            "release-live-session",
            CleanupRecovery::LeaseOrEpoch,
            async {
                polled.set(true);
                closed_pool_release(Uuid::new_v4())
            },
            &mut owned,
        )
        .await;
    })
    .await;
    assert!(
        polled.get(),
        "attempted ownership must still execute exact release"
    );
    assert!(
        !owned.is_clean(),
        "a release failure must remain observable"
    );
    assert_eq!(owned.failures[0].operation, "release-live-session");
    assert_eq!(owned.completed_steps(), 0);
}
