use super::*;
use std::sync::atomic::{AtomicBool, AtomicU32};

async fn wait_for(predicate: impl Fn() -> bool) {
    tokio::time::timeout(Duration::from_secs(2), async {
        while !predicate() {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("worker test condition timed out");
}

async fn shutdown(registry: &WorkerRegistry, cancel: &CancellationToken) {
    let report = registry
        .shutdown_and_join(cancel, Duration::from_secs(1))
        .await;
    assert!(report.is_clean(), "unclean worker shutdown: {report:?}");
    assert_eq!(registry.active_supervisors(), 0);
}

#[test]
fn observed_cleanup_failures_degrade_and_success_restores_readiness() {
    let registry = WorkerRegistry::new();
    registry.register_observer("test-cleanup", WorkerCriticality::Restartable);
    for attempt in 1..=2 {
        registry.observer_error("test-cleanup", format!("failure {attempt}"));
        assert!(registry.readiness_error().is_none());
    }
    registry.observer_error("test-cleanup", "failure 3");
    assert!(registry
        .readiness_error()
        .is_some_and(|error| error.contains("test-cleanup")));
    registry.observer_ok("test-cleanup");
    assert!(registry.readiness_error().is_none());
}

#[test]
#[should_panic(expected = "worker and health-observer names must be unique")]
fn duplicate_worker_names_fail_before_a_second_boundary_is_registered() {
    let registry = WorkerRegistry::new();
    registry.register_observer("duplicate-name", WorkerCriticality::Restartable);
    registry.register_observer("duplicate-name", WorkerCriticality::Critical);
}

#[tokio::test]
async fn synchronous_factory_panic_is_caught_and_restartable_worker_recovers() {
    let registry = WorkerRegistry::new();
    let cancel = CancellationToken::new();
    let attempts = Arc::new(AtomicU32::new(0));
    registry.supervise(
        "test-factory-panic",
        WorkerCriticality::Restartable,
        WorkerMode::Continuous,
        None,
        cancel.clone(),
        {
            let attempts = Arc::clone(&attempts);
            move |_| {
                if attempts.fetch_add(1, Ordering::SeqCst) == 0 {
                    panic!("injected synchronous factory panic");
                }
                async { std::future::pending::<Result<()>>().await }
            }
        },
    );
    wait_for(|| attempts.load(Ordering::SeqCst) >= 2).await;
    shutdown(&registry, &cancel).await;
}

#[tokio::test]
async fn asynchronous_attempt_panic_is_caught_and_restartable_worker_recovers() {
    let registry = WorkerRegistry::new();
    let cancel = CancellationToken::new();
    let attempts = Arc::new(AtomicU32::new(0));
    registry.supervise(
        "test-attempt-panic",
        WorkerCriticality::Restartable,
        WorkerMode::Continuous,
        None,
        cancel.clone(),
        {
            let attempts = Arc::clone(&attempts);
            move |_| {
                let attempt = attempts.fetch_add(1, Ordering::SeqCst);
                async move {
                    if attempt == 0 {
                        panic!("injected asynchronous attempt panic");
                    }
                    std::future::pending::<Result<()>>().await
                }
            }
        },
    );
    wait_for(|| attempts.load(Ordering::SeqCst) >= 2).await;
    shutdown(&registry, &cancel).await;
}

#[tokio::test]
async fn restartable_exit_is_supervised_and_restarts() {
    let registry = WorkerRegistry::new();
    let cancel = CancellationToken::new();
    let attempts = Arc::new(AtomicU32::new(0));
    registry.supervise(
        "test-restart",
        WorkerCriticality::Restartable,
        WorkerMode::Continuous,
        None,
        cancel.clone(),
        {
            let attempts = Arc::clone(&attempts);
            move |_| {
                let attempts = Arc::clone(&attempts);
                async move {
                    attempts.fetch_add(1, Ordering::SeqCst);
                    anyhow::bail!("injected exit")
                }
            }
        },
    );
    wait_for(|| attempts.load(Ordering::SeqCst) >= 2).await;
    shutdown(&registry, &cancel).await;
}

#[tokio::test]
async fn draining_worker_observes_cancellation_before_its_future_is_dropped() {
    let registry = WorkerRegistry::new();
    let cancel = CancellationToken::new();
    let started = Arc::new(AtomicBool::new(false));
    let drained = Arc::new(AtomicBool::new(false));
    registry.supervise_draining(
        "test-draining-worker",
        WorkerCriticality::Restartable,
        WorkerMode::Continuous,
        None,
        Duration::from_millis(250),
        cancel.clone(),
        {
            let started = Arc::clone(&started);
            let drained = Arc::clone(&drained);
            let worker_cancel = cancel.clone();
            move |_| {
                let started = Arc::clone(&started);
                let drained = Arc::clone(&drained);
                let worker_cancel = worker_cancel.clone();
                async move {
                    started.store(true, Ordering::SeqCst);
                    worker_cancel.cancelled().await;
                    tokio::time::sleep(Duration::from_millis(20)).await;
                    drained.store(true, Ordering::SeqCst);
                    Ok(())
                }
            }
        },
    );
    wait_for(|| started.load(Ordering::SeqCst)).await;
    shutdown(&registry, &cancel).await;
    assert!(drained.load(Ordering::SeqCst));
}

#[tokio::test]
async fn successful_heartbeat_resets_restart_backoff() {
    let registry = WorkerRegistry::new();
    let cancel = CancellationToken::new();
    let attempts = Arc::new(AtomicU32::new(0));
    registry.supervise(
        "test-backoff-reset",
        WorkerCriticality::Restartable,
        WorkerMode::Continuous,
        None,
        cancel.clone(),
        {
            let attempts = Arc::clone(&attempts);
            move |heartbeat| {
                let attempt = attempts.fetch_add(1, Ordering::SeqCst);
                async move {
                    if attempt == 1 {
                        heartbeat.ok();
                    }
                    if attempt < 2 {
                        anyhow::bail!("injected exit")
                    }
                    std::future::pending::<Result<()>>().await
                }
            }
        },
    );
    wait_for(|| attempts.load(Ordering::SeqCst) >= 3).await;
    assert_eq!(registry.test_health("test-backoff-reset").0, 1);
    shutdown(&registry, &cancel).await;
}

#[tokio::test]
async fn critical_exit_cancels_the_service() {
    let registry = WorkerRegistry::new();
    let cancel = CancellationToken::new();
    registry.supervise(
        "test-critical",
        WorkerCriticality::Critical,
        WorkerMode::Continuous,
        None,
        cancel.clone(),
        |_| async { anyhow::bail!("injected exit") },
    );
    tokio::time::timeout(Duration::from_secs(1), cancel.cancelled())
        .await
        .expect("critical worker must fail fast");
    assert_eq!(
        registry.critical_failure().as_deref(),
        Some("critical worker test-critical failed: injected exit"),
        "the terminal cause must be committed before cancellation wakes main"
    );
    let report = registry
        .shutdown_and_join(&cancel, Duration::from_secs(1))
        .await;
    assert!(report.is_clean(), "unclean worker shutdown: {report:?}");
}

#[tokio::test]
async fn operator_cancellation_of_critical_worker_has_no_terminal_failure() {
    let registry = WorkerRegistry::new();
    let cancel = CancellationToken::new();
    let started = Arc::new(AtomicBool::new(false));
    registry.supervise(
        "test-critical-operator-cancel",
        WorkerCriticality::Critical,
        WorkerMode::Continuous,
        None,
        cancel.clone(),
        {
            let started = Arc::clone(&started);
            move |_| {
                let started = Arc::clone(&started);
                async move {
                    started.store(true, Ordering::SeqCst);
                    std::future::pending::<Result<()>>().await
                }
            }
        },
    );
    wait_for(|| started.load(Ordering::SeqCst)).await;

    shutdown(&registry, &cancel).await;

    assert!(
        registry.critical_failure().is_none(),
        "operator cancellation must remain a clean shutdown"
    );
}

#[tokio::test]
async fn critical_consecutive_business_errors_fail_closed_and_stale_success_is_ignored() {
    let registry = WorkerRegistry::new();
    let cancel = CancellationToken::new();
    let stale = Arc::new(Mutex::new(None::<WorkerHeartbeat>));
    registry.supervise(
        "test-critical-business-errors",
        WorkerCriticality::Critical,
        WorkerMode::Continuous,
        Some(Duration::from_secs(1)),
        cancel.clone(),
        {
            let stale = Arc::clone(&stale);
            move |heartbeat| {
                *stale.lock().unwrap() = Some(heartbeat.clone());
                async move {
                    for attempt in 1..=CONSECUTIVE_ERROR_THRESHOLD {
                        heartbeat.error(format!("authority failure {attempt}"));
                        tokio::task::yield_now().await;
                    }
                    std::future::pending::<Result<()>>().await
                }
            }
        },
    );
    tokio::time::timeout(Duration::from_secs(1), cancel.cancelled())
        .await
        .expect("three fast critical business errors must cancel the service");
    let before = registry
        .critical_failure()
        .expect("critical threshold preserves a terminal cause");
    assert!(before.contains("3 consecutive business-health errors"));

    stale
        .lock()
        .unwrap()
        .as_ref()
        .expect("attempt heartbeat was captured")
        .ok();
    assert_eq!(
        registry.critical_failure().as_deref(),
        Some(before.as_str())
    );

    let report = registry
        .shutdown_and_join(&cancel, Duration::from_secs(1))
        .await;
    assert!(report.is_clean(), "unclean worker shutdown: {report:?}");
}

#[tokio::test]
async fn successful_boundary_clears_isolated_critical_business_errors() {
    let registry = WorkerRegistry::new();
    let cancel = CancellationToken::new();
    let healthy = Arc::new(AtomicBool::new(false));
    registry.supervise(
        "test-critical-isolated-error",
        WorkerCriticality::Critical,
        WorkerMode::Continuous,
        Some(Duration::from_secs(1)),
        cancel.clone(),
        {
            let healthy = Arc::clone(&healthy);
            move |heartbeat| {
                let healthy = Arc::clone(&healthy);
                async move {
                    for _ in 0..CONSECUTIVE_ERROR_THRESHOLD {
                        heartbeat.error("isolated transient error");
                        heartbeat.ok();
                    }
                    healthy.store(true, Ordering::SeqCst);
                    std::future::pending::<Result<()>>().await
                }
            }
        },
    );
    wait_for(|| healthy.load(Ordering::SeqCst)).await;
    assert!(!cancel.is_cancelled());
    assert!(registry.readiness_error().is_none());
    shutdown(&registry, &cancel).await;
}

#[tokio::test]
async fn restartable_consecutive_business_errors_restart_only_the_failed_attempt() {
    let registry = WorkerRegistry::new();
    let cancel = CancellationToken::new();
    let attempts = Arc::new(AtomicU32::new(0));
    registry.supervise(
        "test-restartable-business-errors",
        WorkerCriticality::Restartable,
        WorkerMode::Continuous,
        Some(Duration::from_secs(1)),
        cancel.clone(),
        {
            let attempts = Arc::clone(&attempts);
            move |heartbeat| {
                let attempt = attempts.fetch_add(1, Ordering::SeqCst);
                async move {
                    if attempt == 0 {
                        for failure in 1..=CONSECUTIVE_ERROR_THRESHOLD {
                            heartbeat.error(format!("transient failure {failure}"));
                            tokio::task::yield_now().await;
                        }
                    } else {
                        heartbeat.ok();
                    }
                    std::future::pending::<Result<()>>().await
                }
            }
        },
    );
    wait_for(|| attempts.load(Ordering::SeqCst) >= 2).await;
    wait_for(|| registry.readiness_error().is_none()).await;
    assert!(!cancel.is_cancelled());
    shutdown(&registry, &cancel).await;
}

#[tokio::test]
async fn stale_attempt_heartbeat_cannot_keep_a_new_hung_attempt_alive() {
    let registry = WorkerRegistry::new();
    let cancel = CancellationToken::new();
    let attempts = Arc::new(AtomicU32::new(0));
    let stale = Arc::new(Mutex::new(None::<WorkerHeartbeat>));
    registry.supervise(
        "test-stale-attempt-heartbeat",
        WorkerCriticality::Restartable,
        WorkerMode::Continuous,
        Some(Duration::from_millis(30)),
        cancel.clone(),
        {
            let attempts = Arc::clone(&attempts);
            let stale = Arc::clone(&stale);
            move |heartbeat| {
                let attempt = attempts.fetch_add(1, Ordering::SeqCst);
                if attempt == 0 {
                    *stale.lock().unwrap() = Some(heartbeat.clone());
                }
                async move {
                    if attempt == 0 {
                        anyhow::bail!("advance to a new attempt")
                    }
                    std::future::pending::<Result<()>>().await
                }
            }
        },
    );
    wait_for(|| attempts.load(Ordering::SeqCst) >= 2).await;
    let stale = stale
        .lock()
        .unwrap()
        .clone()
        .expect("first attempt heartbeat was captured");
    for _ in 0..30 {
        stale.pulse();
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    wait_for(|| attempts.load(Ordering::SeqCst) >= 3).await;
    shutdown(&registry, &cancel).await;
}

#[tokio::test]
async fn delayed_watchdog_observation_preserves_expiry_and_shutdown_semantics() {
    use tracing::instrument::WithSubscriber;

    // Keep two registered dispatchers while capturing. With only one,
    // tracing's callsite cache uses the registering thread's default;
    // a parallel test without a subscriber can otherwise cache `never`.
    // This dispatch is retained locally and never installed as a default.
    let _uncaptured_dispatch = tracing::Dispatch::new(tracing::subscriber::NoSubscriber::new());

    #[derive(Clone)]
    struct LogBuffer(Arc<Mutex<Vec<u8>>>);

    impl std::io::Write for LogBuffer {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(bytes);
            Ok(bytes.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    struct DropWitness {
        cancel: CancellationToken,
        dropped: Arc<AtomicBool>,
        cancelled_at_drop: Arc<AtomicBool>,
    }

    impl Drop for DropWitness {
        fn drop(&mut self) {
            self.cancelled_at_drop
                .store(self.cancel.is_cancelled(), Ordering::SeqCst);
            self.dropped.store(true, Ordering::SeqCst);
        }
    }

    for normal_shutdown in [false, true] {
        let registry = WorkerRegistry::new();
        let cancel = CancellationToken::new();
        let dropped = Arc::new(AtomicBool::new(false));
        let cancelled_at_drop = Arc::new(AtomicBool::new(false));
        let logs = LogBuffer(Arc::new(Mutex::new(Vec::new())));
        let captured = logs.clone();
        let subscriber = tracing_subscriber::fmt()
            .json()
            .without_time()
            .with_writer(move || captured.clone())
            .finish();
        let name = "test-delayed-watchdog";
        registry.register_observer(name, WorkerCriticality::Critical);
        let factory: WorkerFactory = Arc::new({
            let cancel = cancel.clone();
            let dropped = Arc::clone(&dropped);
            let cancelled_at_drop = Arc::clone(&cancelled_at_drop);
            move |_| {
                let witness = DropWitness {
                    cancel: cancel.clone(),
                    dropped: Arc::clone(&dropped),
                    cancelled_at_drop: Arc::clone(&cancelled_at_drop),
                };
                Box::pin(async move {
                    let _witness = witness;
                    std::future::pending::<Result<()>>().await
                })
            }
        });
        let exit = async {
            let supervisor = Arc::clone(&registry).run_supervisor(
                name,
                WorkerCriticality::Critical,
                WorkerMode::Continuous,
                Some(Duration::from_millis(30)),
                WorkerShutdown::Immediate,
                cancel.clone(),
                factory,
            );
            tokio::pin!(supervisor);
            assert!(futures::poll!(&mut supervisor).is_pending());
            // Withhold polling of the real supervisor past its 10 ms tick
            // and 30 ms heartbeat bound, without blocking the executor.
            tokio::time::sleep(Duration::from_millis(40)).await;
            if normal_shutdown {
                cancel.cancel();
            }
            tokio::time::timeout(Duration::from_secs(1), supervisor)
                .await
                .expect("the delayed watchdog must keep its original expiry bound")
        }
        .with_subscriber(subscriber)
        .await;
        assert!(dropped.load(Ordering::SeqCst));
        assert_eq!(cancelled_at_drop.load(Ordering::SeqCst), normal_shutdown);
        assert!(cancel.is_cancelled());
        let events: Vec<serde_json::Value> = String::from_utf8(logs.0.lock().unwrap().clone())
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect();
        let observations: Vec<_> = events
            .iter()
            .filter(|event| {
                event["fields"]["message"] == "worker heartbeat expired at watchdog observation"
            })
            .collect();
        if normal_shutdown {
            assert_eq!(exit, SupervisorExit::Cancelled);
            assert!(observations.is_empty());
            assert!(registry.critical_failure().is_none());
        } else {
            assert_eq!(exit, SupervisorExit::TerminalFailure);
            assert_eq!(observations.len(), 1);
            let fields = &observations[0]["fields"];
            assert_eq!(fields["worker"], name);
            assert_eq!(fields["heartbeat_limit_ms"], 30);
            assert!(fields["watchdog_tick_delay_ms"].as_u64().unwrap() >= 20);
            assert_eq!(
                fields["max_attempt_watchdog_tick_delay_ms"],
                fields["watchdog_tick_delay_ms"]
            );
            assert_eq!(
                registry.critical_failure().as_deref(),
                Some("critical worker test-delayed-watchdog failed: worker heartbeat exceeded the 30 ms silence limit")
            );
        }
    }
}

#[tokio::test]
async fn critical_heartbeat_expiry_cancels_the_service() {
    let registry = WorkerRegistry::new();
    let cancel = CancellationToken::new();
    registry.supervise(
        "test-critical-hang",
        WorkerCriticality::Critical,
        WorkerMode::Continuous,
        Some(Duration::from_millis(30)),
        cancel.clone(),
        |_| async { std::future::pending::<Result<()>>().await },
    );
    tokio::time::timeout(Duration::from_secs(1), cancel.cancelled())
        .await
        .expect("silent critical worker must fail closed");
    assert!(registry.readiness_error().is_some());
    let _ = registry
        .shutdown_and_join(&cancel, Duration::from_secs(1))
        .await;
}

#[tokio::test]
async fn restartable_heartbeat_expiry_aborts_and_restarts_the_attempt() {
    let registry = WorkerRegistry::new();
    let cancel = CancellationToken::new();
    let attempts = Arc::new(AtomicU32::new(0));
    registry.supervise(
        "test-restartable-hang",
        WorkerCriticality::Restartable,
        WorkerMode::Continuous,
        Some(Duration::from_millis(30)),
        cancel.clone(),
        {
            let attempts = Arc::clone(&attempts);
            move |_| {
                let attempts = Arc::clone(&attempts);
                async move {
                    attempts.fetch_add(1, Ordering::SeqCst);
                    std::future::pending::<Result<()>>().await
                }
            }
        },
    );
    wait_for(|| attempts.load(Ordering::SeqCst) >= 2).await;
    shutdown(&registry, &cancel).await;
}

#[tokio::test]
async fn supervisor_panic_is_observed_and_restartable_guardian_recovers() {
    let registry = WorkerRegistry::new();
    let cancel = CancellationToken::new();
    let attempts = Arc::new(AtomicU32::new(0));
    let release = Arc::new(tokio::sync::Notify::new());
    registry.supervise(
        "test-supervisor-panic",
        WorkerCriticality::Restartable,
        WorkerMode::Continuous,
        None,
        cancel.clone(),
        {
            let attempts = Arc::clone(&attempts);
            let release = Arc::clone(&release);
            move |_| {
                let attempt = attempts.fetch_add(1, Ordering::SeqCst);
                let release = Arc::clone(&release);
                async move {
                    if attempt == 0 {
                        release.notified().await;
                        anyhow::bail!("advance to injected supervisor panic")
                    }
                    std::future::pending::<Result<()>>().await
                }
            }
        },
    );
    wait_for(|| attempts.load(Ordering::SeqCst) == 1).await;
    registry.inject_supervisor_panic("test-supervisor-panic");
    release.notify_one();
    wait_for(|| {
        registry.test_health("test-supervisor-panic").1 >= 1 && attempts.load(Ordering::SeqCst) >= 2
    })
    .await;
    shutdown(&registry, &cancel).await;
}

#[tokio::test]
async fn shutdown_joins_every_supervisor_and_drops_inflight_attempts() {
    struct DropSignal(Arc<AtomicBool>);
    impl Drop for DropSignal {
        fn drop(&mut self) {
            self.0.store(true, Ordering::SeqCst);
        }
    }

    let registry = WorkerRegistry::new();
    let cancel = CancellationToken::new();
    let started = Arc::new(AtomicBool::new(false));
    let dropped = Arc::new(AtomicBool::new(false));
    registry.supervise(
        "test-shutdown-drain",
        WorkerCriticality::Restartable,
        WorkerMode::Continuous,
        None,
        cancel.clone(),
        {
            let started = Arc::clone(&started);
            let dropped = Arc::clone(&dropped);
            move |_| {
                let started = Arc::clone(&started);
                let signal = DropSignal(Arc::clone(&dropped));
                async move {
                    let _signal = signal;
                    started.store(true, Ordering::SeqCst);
                    std::future::pending::<Result<()>>().await
                }
            }
        },
    );
    wait_for(|| started.load(Ordering::SeqCst)).await;
    shutdown(&registry, &cancel).await;
    assert!(dropped.load(Ordering::SeqCst));
}

#[test]
fn watchdog_polling_and_restart_backoff_are_bounded() {
    assert_eq!(
        watchdog_period(Duration::from_millis(1)),
        Duration::from_millis(10)
    );
    assert_eq!(
        watchdog_period(Duration::from_secs(20)),
        Duration::from_secs(1)
    );
    assert_eq!(
        restart_backoff(100),
        RESTART_BACKOFF_UNIT.saturating_mul(16)
    );
}
