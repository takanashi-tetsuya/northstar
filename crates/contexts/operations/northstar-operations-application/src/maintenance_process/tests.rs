use super::*;
use northstar_runtime::workers::{WorkerCriticality, WorkerMode};
use std::{
    collections::VecDeque,
    future::pending,
    sync::{Arc, Mutex},
};
use tokio::{sync::Notify, task::JoinHandle, time::Instant};

type Events = Arc<Mutex<Vec<&'static str>>>;

enum ProbeResult {
    Ok,
    Err,
    Pending,
}

struct FakeOwnership {
    events: Events,
    results: VecDeque<ProbeResult>,
    probe_started: Arc<Notify>,
    close_error: bool,
}

impl FakeOwnership {
    fn new(events: &Events, results: impl IntoIterator<Item = ProbeResult>) -> Self {
        Self {
            events: Arc::clone(events),
            results: results.into_iter().collect(),
            probe_started: Arc::new(Notify::new()),
            close_error: false,
        }
    }
}

impl MaintenanceOwnership for FakeOwnership {
    async fn probe(&mut self) -> anyhow::Result<()> {
        self.events.lock().unwrap().push("probe");
        self.probe_started.notify_one();
        match self
            .results
            .pop_front()
            .expect("unexpected ownership probe")
        {
            ProbeResult::Ok => Ok(()),
            ProbeResult::Err => Err(anyhow::anyhow!("probe failed")),
            ProbeResult::Pending => pending().await,
        }
    }

    async fn close(self) -> anyhow::Result<()> {
        self.events.lock().unwrap().push("close");
        if self.close_error {
            anyhow::bail!("ownership close failed");
        }
        Ok(())
    }
}

struct RecordOnDrop(Events, &'static str);

impl Drop for RecordOnDrop {
    fn drop(&mut self) {
        self.0.lock().unwrap().push(self.1);
    }
}

fn registry() -> Arc<WorkerRegistry> {
    let workers = WorkerRegistry::new();
    workers.register_observer("maintenance-ownership", WorkerCriticality::Critical);
    workers.observer_ok("maintenance-ownership");
    workers
}

fn health_until_cancelled(cancel: &CancellationToken) -> JoinHandle<anyhow::Result<()>> {
    let cancel = cancel.clone();
    tokio::spawn(async move {
        cancel.cancelled().await;
        Ok(())
    })
}

#[tokio::test(start_paused = true)]
async fn failed_probe_marks_the_observer_and_stops() {
    let events = Events::default();
    let ownership = FakeOwnership::new(&events, [ProbeResult::Ok, ProbeResult::Err]);
    let workers = registry();
    let cancel = CancellationToken::new();
    let started = Instant::now();
    let error = supervise_maintenance(
        ownership,
        &workers,
        &cancel,
        health_until_cancelled(&cancel),
        pending(),
    )
    .await
    .unwrap_err();

    assert_eq!(
        error.to_string(),
        "maintenance database ownership connection failed"
    );
    assert_eq!(
        workers
            .observer_last_error_for_test("maintenance-ownership")
            .as_deref(),
        Some("database ownership connection failed")
    );
    assert!(cancel.is_cancelled());
    assert_eq!(started.elapsed(), Duration::from_secs(5));
    assert_eq!(*events.lock().unwrap(), ["probe", "probe", "close"]);
}

#[tokio::test(start_paused = true)]
async fn probe_timeout_counts_as_failure() {
    let events = Events::default();
    let ownership = FakeOwnership::new(&events, [ProbeResult::Pending]);
    let workers = registry();
    let cancel = CancellationToken::new();
    let started = Instant::now();
    let error = supervise_maintenance(
        ownership,
        &workers,
        &cancel,
        health_until_cancelled(&cancel),
        pending(),
    )
    .await
    .unwrap_err();

    assert_eq!(started.elapsed(), Duration::from_secs(3));
    assert_eq!(
        error.to_string(),
        "maintenance database ownership connection failed"
    );
    assert_eq!(
        workers
            .observer_last_error_for_test("maintenance-ownership")
            .as_deref(),
        Some("database ownership connection failed")
    );
    assert_eq!(*events.lock().unwrap(), ["probe", "close"]);
}

#[tokio::test(start_paused = true)]
async fn shutdown_signal_closes_ownership_after_workers() {
    let events = Events::default();
    let ownership = FakeOwnership::new(&events, []);
    let workers = registry();
    let cancel = CancellationToken::new();
    let worker_started = Arc::new(Notify::new());
    let worker_events = Arc::clone(&events);
    let worker_cancel = cancel.clone();
    let worker_ready = Arc::clone(&worker_started);
    workers.supervise_draining(
        "draining-worker",
        WorkerCriticality::Restartable,
        WorkerMode::Continuous,
        None,
        Duration::from_secs(5),
        cancel.clone(),
        move |_| {
            let events = Arc::clone(&worker_events);
            let cancel = worker_cancel.clone();
            let ready = Arc::clone(&worker_ready);
            async move {
                ready.notify_one();
                cancel.cancelled().await;
                tokio::time::sleep(Duration::from_secs(2)).await;
                events.lock().unwrap().push("worker drain");
                Ok(())
            }
        },
    );
    worker_started.notified().await;
    let reaped = RecordOnDrop(Arc::clone(&events), "health reaped");
    let health = tokio::spawn(async move {
        let _reaped = reaped;
        pending::<anyhow::Result<()>>().await
    });
    let started = Instant::now();

    supervise_maintenance(ownership, &workers, &cancel, health, async {})
        .await
        .unwrap();

    assert!(cancel.is_cancelled());
    assert_eq!(started.elapsed(), Duration::from_secs(3));
    assert_eq!(
        *events.lock().unwrap(),
        ["worker drain", "health reaped", "close"]
    );
}

#[tokio::test(start_paused = true)]
async fn cancellation_wins_over_a_ready_shutdown_signal() {
    let events = Events::default();
    let ownership = FakeOwnership::new(&events, []);
    let workers = registry();
    let cancel = CancellationToken::new();
    cancel.cancel();

    let error = supervise_maintenance(
        ownership,
        &workers,
        &cancel,
        health_until_cancelled(&cancel),
        async {},
    )
    .await
    .unwrap_err();

    assert_eq!(error.to_string(), "maintenance worker authority failed");
    assert_eq!(*events.lock().unwrap(), ["close"]);
}

#[tokio::test(start_paused = true)]
async fn health_task_exit_is_reported_with_its_context() {
    for (case, expected) in [
        (0, "maintenance health listener failed"),
        (1, "maintenance health listener stopped unexpectedly"),
        (2, "maintenance health listener panicked"),
    ] {
        let events = Events::default();
        let ownership = FakeOwnership::new(&events, []);
        let workers = registry();
        let cancel = CancellationToken::new();
        let health: JoinHandle<anyhow::Result<()>> = match case {
            0 => tokio::spawn(async { Err(anyhow::anyhow!("health failed")) }),
            1 => tokio::spawn(async { Ok(()) }),
            _ => tokio::spawn(async { panic!("health panicked") }),
        };
        while !health.is_finished() {
            tokio::task::yield_now().await;
        }

        let error = supervise_maintenance(ownership, &workers, &cancel, health, pending())
            .await
            .unwrap_err();

        assert_eq!(error.to_string(), expected);
        if case == 0 {
            assert_eq!(
                format!("{error:#}"),
                "maintenance health listener failed: health failed"
            );
        } else if case == 2 {
            assert!(error
                .downcast_ref::<tokio::task::JoinError>()
                .unwrap()
                .is_panic());
        }
        assert!(cancel.is_cancelled());
        assert_eq!(*events.lock().unwrap(), ["close"]);
    }
}

#[tokio::test(start_paused = true)]
async fn close_error_is_returned() {
    let events = Events::default();
    let mut ownership = FakeOwnership::new(&events, [ProbeResult::Err]);
    ownership.close_error = true;
    let workers = registry();
    let cancel = CancellationToken::new();

    let error = supervise_maintenance(
        ownership,
        &workers,
        &cancel,
        health_until_cancelled(&cancel),
        pending(),
    )
    .await
    .unwrap_err();

    assert_eq!(error.to_string(), "ownership close failed");
    assert!(cancel.is_cancelled());
    assert_eq!(*events.lock().unwrap(), ["probe", "close"]);
}

#[tokio::test(start_paused = true)]
async fn successful_probe_clears_the_observer_error() {
    let events = Events::default();
    let ownership = FakeOwnership::new(&events, [ProbeResult::Ok]);
    let probe_started = Arc::clone(&ownership.probe_started);
    let workers = registry();
    workers.observer_error("maintenance-ownership", "previous ownership error");
    let cancel = CancellationToken::new();

    supervise_maintenance(
        ownership,
        &workers,
        &cancel,
        health_until_cancelled(&cancel),
        probe_started.notified(),
    )
    .await
    .unwrap();

    assert_eq!(
        workers.observer_last_error_for_test("maintenance-ownership"),
        None
    );
    assert_eq!(*events.lock().unwrap(), ["probe", "close"]);
}

#[tokio::test(start_paused = true)]
async fn missed_ticks_delay_the_next_probe() {
    let events = Events::default();
    let ownership = FakeOwnership::new(
        &events,
        [ProbeResult::Ok, ProbeResult::Ok, ProbeResult::Err],
    );
    let probe_started = Arc::clone(&ownership.probe_started);
    let workers = registry();
    let cancel = CancellationToken::new();
    let started = Instant::now();
    let monitor = tokio::spawn(async move {
        supervise_maintenance(
            ownership,
            &workers,
            &cancel,
            health_until_cancelled(&cancel),
            pending(),
        )
        .await
    });
    probe_started.notified().await;
    assert_eq!(*events.lock().unwrap(), ["probe"]);

    tokio::time::advance(Duration::from_secs(12)).await;
    probe_started.notified().await;
    assert!(!monitor.is_finished());
    assert_eq!(*events.lock().unwrap(), ["probe", "probe"]);
    tokio::time::advance(Duration::from_millis(4_999)).await;
    tokio::task::yield_now().await;
    assert!(!monitor.is_finished());
    assert_eq!(*events.lock().unwrap(), ["probe", "probe"]);
    tokio::time::advance(Duration::from_millis(1)).await;

    let error = monitor.await.unwrap().unwrap_err();
    assert_eq!(
        error.to_string(),
        "maintenance database ownership connection failed"
    );
    assert_eq!(started.elapsed(), Duration::from_secs(17));
    assert_eq!(
        *events.lock().unwrap(),
        ["probe", "probe", "probe", "close"]
    );
}
