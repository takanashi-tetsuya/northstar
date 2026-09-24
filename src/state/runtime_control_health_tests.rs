use super::report_runtime_control_health;
use crate::workers::{WorkerCriticality, WorkerMode, WorkerRegistry};
use std::time::Duration;
use tokio_util::sync::CancellationToken;

#[tokio::test]
async fn idle_ticks_cannot_reset_a_broken_control_connection() {
    let workers = WorkerRegistry::new();
    let cancel = CancellationToken::new();
    workers.supervise(
        "test-runtime-control-loss",
        WorkerCriticality::Critical,
        WorkerMode::Continuous,
        None,
        cancel.clone(),
        |heartbeat| async move {
            for _ in 0..3 {
                report_runtime_control_health(
                    &heartbeat,
                    true,
                    Some(anyhow::anyhow!("fixture connection closed")),
                );
                report_runtime_control_health(&heartbeat, false, None);
            }
            std::future::pending().await
        },
    );
    tokio::time::timeout(Duration::from_secs(2), cancel.cancelled())
        .await
        .expect("idle ticks concealed a broken reserved connection");
    assert!(workers.critical_failure().is_some());
    assert!(workers
        .shutdown_and_join(&cancel, Duration::from_secs(1))
        .await
        .is_clean());
}

#[tokio::test]
async fn successful_database_reads_can_restore_control_health() {
    let workers = WorkerRegistry::new();
    let cancel = CancellationToken::new();
    let (complete, mut observed) = tokio::sync::mpsc::channel(1);
    workers.supervise(
        "test-runtime-control-recovery",
        WorkerCriticality::Critical,
        WorkerMode::Continuous,
        None,
        cancel.clone(),
        move |heartbeat| {
            let complete = complete.clone();
            async move {
                for _ in 0..2 {
                    report_runtime_control_health(
                        &heartbeat,
                        true,
                        Some(anyhow::anyhow!("fixture query failed")),
                    );
                    report_runtime_control_health(&heartbeat, false, None);
                }
                report_runtime_control_health(&heartbeat, true, None);
                for _ in 0..2 {
                    report_runtime_control_health(
                        &heartbeat,
                        true,
                        Some(anyhow::anyhow!("fixture query failed")),
                    );
                    report_runtime_control_health(&heartbeat, false, None);
                }
                let _ = complete.send(()).await;
                std::future::pending().await
            }
        },
    );
    tokio::time::timeout(Duration::from_secs(2), observed.recv())
        .await
        .unwrap()
        .unwrap();
    assert!(!cancel.is_cancelled());
    assert!(workers.readiness_error().is_none());
    cancel.cancel();
    assert!(workers
        .shutdown_and_join(&cancel, Duration::from_secs(1))
        .await
        .is_clean());
}

fn diagnostic_guard(
    root_cancel: CancellationToken,
) -> (
    super::RuntimeControlDiagnostics,
    std::sync::Arc<std::sync::Mutex<Vec<super::RuntimeControlStall>>>,
) {
    let captured = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let mut guard = super::RuntimeControlDiagnostics::new(root_cancel, Duration::from_secs(5));
    guard.captured = Some(std::sync::Arc::clone(&captured));
    (guard, captured)
}

#[tokio::test]
async fn dropped_pending_control_turn_reports_its_actual_phase() {
    use super::RuntimeControlPhase;
    for phase in [
        RuntimeControlPhase::SnapshotRead,
        RuntimeControlPhase::PolicyApply,
        RuntimeControlPhase::Idle,
        RuntimeControlPhase::ServiceControlRead,
    ] {
        let (mut guard, captured) = diagnostic_guard(CancellationToken::new());
        let (entered, observed) = tokio::sync::oneshot::channel();
        let task = tokio::spawn(async move {
            match phase {
                RuntimeControlPhase::SnapshotRead => {
                    guard.database_read(crate::db::RuntimeControlReadPhase::Snapshot);
                }
                other => guard.enter(other),
            }
            guard.phase_started -= Duration::from_secs(6);
            guard.last_reported -= Duration::from_secs(6);
            entered.send(()).unwrap();
            std::future::pending::<()>().await;
            drop(guard);
        });
        observed.await.unwrap();
        task.abort();
        assert!(task.await.unwrap_err().is_cancelled());
        let reports = captured.lock().unwrap();
        assert_eq!(reports.len(), 1);
        assert_eq!(reports[0].phase, phase);
        assert!(reports[0].phase_elapsed >= Duration::from_secs(6));
        assert!(reports[0].heartbeat_elapsed >= Duration::from_secs(6));
    }
}

#[tokio::test]
async fn normal_shutdown_drops_a_stalled_control_turn_without_warning() {
    let root_cancel = CancellationToken::new();
    let (mut guard, captured) = diagnostic_guard(root_cancel.clone());
    let (entered, observed) = tokio::sync::oneshot::channel();
    let task = tokio::spawn(async move {
        guard.database_read(crate::db::RuntimeControlReadPhase::Snapshot);
        guard.phase_started -= Duration::from_secs(6);
        guard.last_reported -= Duration::from_secs(6);
        entered.send(()).unwrap();
        std::future::pending::<()>().await;
        drop(guard);
    });
    observed.await.unwrap();
    root_cancel.cancel();
    task.abort();
    assert!(task.await.unwrap_err().is_cancelled());
    assert!(captured.lock().unwrap().is_empty());
}

#[tokio::test]
async fn short_control_phases_do_not_reset_total_heartbeat_silence() {
    let (mut guard, captured) = diagnostic_guard(CancellationToken::new());
    let (entered, observed) = tokio::sync::oneshot::channel();
    let (next_phase, continue_turn) = tokio::sync::oneshot::channel();
    let (changed, change_observed) = tokio::sync::oneshot::channel();
    let task = tokio::spawn(async move {
        guard.database_read(crate::db::RuntimeControlReadPhase::Snapshot);
        guard.last_reported -= Duration::from_secs(6);
        entered.send(()).unwrap();
        continue_turn.await.unwrap();
        guard.enter(super::RuntimeControlPhase::PolicyApply);
        guard.phase_started -= Duration::from_secs(2);
        changed.send(()).unwrap();
        std::future::pending::<()>().await;
        drop(guard);
    });
    observed.await.unwrap();
    next_phase.send(()).unwrap();
    change_observed.await.unwrap();
    task.abort();
    assert!(task.await.unwrap_err().is_cancelled());
    let reports = captured.lock().unwrap();
    assert_eq!(reports.len(), 1);
    assert_eq!(reports[0].phase, super::RuntimeControlPhase::PolicyApply);
    assert!(reports[0].phase_elapsed >= Duration::from_secs(2));
    assert!(reports[0].heartbeat_elapsed >= Duration::from_secs(6));
    assert!(reports[0].heartbeat_elapsed > reports[0].phase_elapsed);
}

#[tokio::test]
async fn an_existing_health_report_resets_only_the_diagnostic_clock() {
    let (mut guard, captured) = diagnostic_guard(CancellationToken::new());
    let (entered, observed) = tokio::sync::oneshot::channel();
    let (report, continue_turn) = tokio::sync::oneshot::channel();
    let (reported, report_observed) = tokio::sync::oneshot::channel();
    let task = tokio::spawn(async move {
        guard.database_read(crate::db::RuntimeControlReadPhase::Snapshot);
        guard.last_reported -= Duration::from_secs(6);
        entered.send(()).unwrap();
        continue_turn.await.unwrap();
        guard.reported();
        reported.send(()).unwrap();
        std::future::pending::<()>().await;
        drop(guard);
    });
    observed.await.unwrap();
    report.send(()).unwrap();
    report_observed.await.unwrap();
    task.abort();
    assert!(task.await.unwrap_err().is_cancelled());
    assert!(captured.lock().unwrap().is_empty());
}
