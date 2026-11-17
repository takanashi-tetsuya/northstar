use super::*;
use crate::connection_actors::{ConnectionActorKind, ConnectionActorSpawnError};
use crate::service_tasks::spawn_service_task;
use crate::workers::{WorkerCriticality, WorkerMode};
use std::sync::{Arc, Mutex};
use std::task::{Context, Wake, Waker};
use tokio::sync::oneshot;
use tracing::instrument::WithSubscriber;

type Events = Arc<Mutex<Vec<&'static str>>>;

#[derive(Clone, Copy)]
enum ReleaseOutcome {
    Released,
    Failed,
    TimedOut,
}

struct TestPorts<'a> {
    actors: &'a ConnectionActorRegistry,
    cancel: &'a CancellationToken,
    events: Events,
    release_outcome: ReleaseOutcome,
    pending_notifications: bool,
}

impl<'a> TestPorts<'a> {
    fn new(actors: &'a ConnectionActorRegistry, cancel: &'a CancellationToken) -> Self {
        Self {
            actors,
            cancel,
            events: Arc::default(),
            release_outcome: ReleaseOutcome::Released,
            pending_notifications: false,
        }
    }
}

impl ProcessShutdownPorts for TestPorts<'_> {
    fn muc_shutdown_notifications(&self) -> impl Future<Output = usize> + '_ {
        assert!(!self.actors.is_accepting());
        assert!(!self.actors.shutdown_token().is_cancelled());
        assert!(!self.cancel.is_cancelled());
        // Record construction separately from polling: a non-graceful path
        // must not even build the context that owns the notification future.
        self.events.lock().unwrap().push("admission closed");
        self.events.lock().unwrap().push("MUC built");
        async move {
            self.events.lock().unwrap().push("MUC window");
            if self.pending_notifications {
                let _pending = PendingNotification(&self.events);
                std::future::pending::<()>().await;
            }
            3
        }
    }

    fn begin_cluster_shutdown(&self) {
        assert!(!self.actors.is_accepting());
        assert!(!self.actors.shutdown_token().is_cancelled());
        self.events.lock().unwrap().push("begin cluster");
    }

    fn release_cluster_after_publication_quiescence(
        &self,
        quiesce_timeout: Duration,
    ) -> impl Future<Output = Option<anyhow::Result<()>>> + '_ {
        assert_eq!(quiesce_timeout, Duration::from_secs(15));
        assert!(self.actors.shutdown_token().is_cancelled());
        assert!(self.cancel.is_cancelled());
        self.events.lock().unwrap().push("release");
        async move {
            match self.release_outcome {
                ReleaseOutcome::Released => Some(Ok(())),
                ReleaseOutcome::Failed => Some(Err(anyhow::anyhow!("injected release failure"))),
                ReleaseOutcome::TimedOut => None,
            }
        }
    }
}

struct PendingNotification<'a>(&'a Events);

impl Drop for PendingNotification<'_> {
    fn drop(&mut self) {
        self.0.lock().unwrap().push("MUC dropped");
    }
}

struct RecordWake {
    events: Events,
    event: &'static str,
}

impl Wake for RecordWake {
    fn wake(self: Arc<Self>) {
        self.events.lock().unwrap().push(self.event);
    }
}

#[tokio::test]
async fn graceful_shutdown_runs_effects_in_order() {
    let cancel = CancellationToken::new();
    let workers = WorkerRegistry::new();
    let actors = ConnectionActorRegistry::new(1);
    let ports = TestPorts::new(&actors, &cancel);

    // Observe the actual cancellation calls synchronously through their
    // registered wakers, so swapping actor and process cancellation fails.
    let actor_shutdown = actors.shutdown_token();
    let mut actor_cancelled = std::pin::pin!(actor_shutdown.cancelled());
    let mut process_cancelled = std::pin::pin!(cancel.cancelled());
    let actor_waker = Waker::from(Arc::new(RecordWake {
        events: Arc::clone(&ports.events),
        event: "begin actors",
    }));
    let process_waker = Waker::from(Arc::new(RecordWake {
        events: Arc::clone(&ports.events),
        event: "cancel",
    }));
    assert!(actor_cancelled
        .as_mut()
        .poll(&mut Context::from_waker(&actor_waker))
        .is_pending());
    assert!(process_cancelled
        .as_mut()
        .poll(&mut Context::from_waker(&process_waker))
        .is_pending());

    let worker_cancel = cancel.clone();
    let worker_events = Arc::clone(&ports.events);
    let (started_tx, mut started_rx) = tokio::sync::mpsc::unbounded_channel();
    workers.supervise_draining(
        "ordered worker",
        WorkerCriticality::Critical,
        WorkerMode::Continuous,
        None,
        Duration::from_secs(1),
        cancel.clone(),
        move |_| {
            let cancel = worker_cancel.clone();
            let events = Arc::clone(&worker_events);
            let started = started_tx.clone();
            async move {
                started.send(()).unwrap();
                cancel.cancelled().await;
                assert!(events.lock().unwrap().contains(&"release"));
                events.lock().unwrap().push("worker drain");
                Ok(())
            }
        },
    );
    started_rx.recv().await.unwrap();

    let actor_events = Arc::clone(&ports.events);
    let actor_cancel = actor_shutdown.clone();
    actors
        .try_spawn(ConnectionActorKind::C2sTcp, None, async move {
            actor_cancel.cancelled().await;
            assert!(actor_events.lock().unwrap().contains(&"release"));
            actor_events.lock().unwrap().push("actor drain");
        })
        .unwrap();
    let service_cancel = cancel.clone();
    let service_events = Arc::clone(&ports.events);
    let mut tasks = JoinSet::new();
    spawn_service_task(&mut tasks, "ordered listener", async move {
        service_cancel.cancelled().await;
        assert!(service_events.lock().unwrap().contains(&"release"));
        service_events.lock().unwrap().push("service drain");
        Ok(())
    });

    supervise_process_shutdown(&ports, &cancel, &workers, &actors, &mut tasks, async {})
        .await
        .unwrap();

    let events = ports.events.lock().unwrap();
    assert_eq!(
        &events[..7],
        &[
            "admission closed",
            "MUC built",
            "MUC window",
            "begin cluster",
            "begin actors",
            "cancel",
            "release",
        ]
    );
    let mut drains = events[7..].to_vec();
    drains.sort_unstable();
    assert_eq!(drains, ["actor drain", "service drain", "worker drain"]);
    assert!(tasks.is_empty());
    assert_eq!(actors.active_count(), 0);
}

#[tokio::test]
async fn cancellation_skips_the_muc_window() {
    let cancel = CancellationToken::new();
    cancel.cancel();
    let workers = WorkerRegistry::new();
    let actors = ConnectionActorRegistry::new(1);
    let ports = TestPorts::new(&actors, &cancel);
    let mut tasks = JoinSet::new();
    // Both cancellation and the graceful signal are ready. Biased selection
    // must keep cancellation first and skip notification construction.
    supervise_process_shutdown(&ports, &cancel, &workers, &actors, &mut tasks, async {})
        .await
        .unwrap();
    assert_eq!(*ports.events.lock().unwrap(), ["begin cluster", "release"]);
}

#[tokio::test]
async fn graceful_signal_preempts_a_ready_service_exit() {
    let cancel = CancellationToken::new();
    let workers = WorkerRegistry::new();
    let actors = ConnectionActorRegistry::new(1);
    let ports = TestPorts::new(&actors, &cancel);
    let mut tasks = JoinSet::new();
    let task = tasks.spawn(async {
        ServiceTaskExit::Finished {
            name: "ready listener",
            result: Err(anyhow::anyhow!("injected listener failure")),
        }
    });
    while !task.is_finished() {
        tokio::task::yield_now().await;
    }
    let error =
        supervise_process_shutdown(&ports, &cancel, &workers, &actors, &mut tasks, async {})
            .await
            .unwrap_err();
    assert_eq!(
        format!("{error:#}"),
        "ready listener task failed: injected listener failure"
    );
    // Signal selection builds the MUC future; the window then gives the
    // ready service failure priority over polling that future.
    assert_eq!(
        *ports.events.lock().unwrap(),
        ["admission closed", "MUC built", "begin cluster", "release"]
    );
    assert!(tasks.is_empty());
}

#[tokio::test(start_paused = true)]
async fn unexpected_service_exit_is_the_first_error() {
    let cancel = CancellationToken::new();
    let workers = WorkerRegistry::new();
    let actors = ConnectionActorRegistry::new(1);
    let mut ports = TestPorts::new(&actors, &cancel);
    ports.release_outcome = ReleaseOutcome::Failed;
    let mut tasks = JoinSet::new();
    spawn_service_task(&mut tasks, "first listener", async {
        anyhow::bail!("first listener failure")
    });
    spawn_service_task(&mut tasks, "stuck listener", std::future::pending());
    let error = supervise_process_shutdown(
        &ports,
        &cancel,
        &workers,
        &actors,
        &mut tasks,
        std::future::pending(),
    )
    .await
    .unwrap_err();
    assert_eq!(
        format!("{error:#}"),
        "first listener task failed: first listener failure"
    );
    assert_eq!(*ports.events.lock().unwrap(), ["begin cluster", "release"]);
    assert!(tasks.is_empty());
}

#[tokio::test]
async fn release_outcomes_do_not_change_the_result() {
    #[derive(Clone, Default)]
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

    // Keep the callsite cache scoped to the captured subscriber even when
    // another runtime test concurrently runs without a default subscriber.
    let _uncaptured_dispatch = tracing::Dispatch::new(tracing::subscriber::NoSubscriber::new());
    for release_outcome in [
        ReleaseOutcome::Released,
        ReleaseOutcome::Failed,
        ReleaseOutcome::TimedOut,
    ] {
        let cancel = CancellationToken::new();
        cancel.cancel();
        let workers = WorkerRegistry::new();
        let actors = ConnectionActorRegistry::new(1);
        let mut ports = TestPorts::new(&actors, &cancel);
        ports.release_outcome = release_outcome;
        let mut tasks = JoinSet::new();
        let logs = LogBuffer::default();
        let captured = logs.clone();
        let subscriber = tracing_subscriber::fmt()
            .without_time()
            .with_ansi(false)
            .with_writer(move || captured.clone())
            .finish();
        supervise_process_shutdown(&ports, &cancel, &workers, &actors, &mut tasks, async {})
            .with_subscriber(subscriber)
            .await
            .unwrap();
        assert_eq!(*ports.events.lock().unwrap(), ["begin cluster", "release"]);
        let rendered = String::from_utf8(logs.0.lock().unwrap().clone()).unwrap();
        assert!(rendered.contains("shutdown complete"));
        match release_outcome {
            ReleaseOutcome::Released => {
                assert!(!rendered.contains("could not audit"));
                assert!(!rendered.contains("signed cluster publications did not drain"));
            }
            ReleaseOutcome::Failed => {
                assert!(rendered.contains("WARN"));
                assert!(rendered.contains("injected release failure"));
                assert!(rendered
                    .contains("could not audit the final cluster node-instance lease release"));
            }
            ReleaseOutcome::TimedOut => {
                assert!(rendered.contains("ERROR"));
                assert!(rendered.contains("signed cluster publications did not drain; leaving the instance fenced until its database lease expires"));
            }
        }
    }
}

#[tokio::test(start_paused = true)]
async fn incomplete_drain_is_reported() {
    let cancel = CancellationToken::new();
    cancel.cancel();
    let workers = WorkerRegistry::new();
    let actors = ConnectionActorRegistry::new(1);
    let ports = TestPorts::new(&actors, &cancel);
    let mut tasks = JoinSet::new();
    spawn_service_task(&mut tasks, "stuck listener", std::future::pending());
    let error =
        supervise_process_shutdown(&ports, &cancel, &workers, &actors, &mut tasks, async {})
            .await
            .unwrap_err();
    let message = error.to_string();
    assert!(
        message.starts_with("listener shutdown was incomplete: "),
        "{message}"
    );
    assert!(message.contains("aborted: 1"), "{message}");
    assert!(tasks.is_empty());
}

#[tokio::test(start_paused = true)]
async fn drains_runtime_owners_concurrently() {
    let cancel = CancellationToken::new();
    let workers = WorkerRegistry::new();
    let actors = ConnectionActorRegistry::new(1);
    let ports = TestPorts::new(&actors, &cancel);
    let (started_tx, mut started_rx) = tokio::sync::mpsc::unbounded_channel();
    workers.supervise_draining(
        "stuck worker",
        WorkerCriticality::Critical,
        WorkerMode::Continuous,
        None,
        Duration::from_secs(60),
        cancel.clone(),
        move |_| {
            started_tx.send(()).unwrap();
            std::future::pending::<anyhow::Result<()>>()
        },
    );
    started_rx.recv().await.unwrap();
    actors
        .try_spawn(ConnectionActorKind::C2sTcp, None, std::future::pending())
        .unwrap();
    let mut tasks = JoinSet::new();
    spawn_service_task(&mut tasks, "stuck listener", std::future::pending());
    cancel.cancel();
    let started = tokio::time::Instant::now();
    let error =
        supervise_process_shutdown(&ports, &cancel, &workers, &actors, &mut tasks, async {})
            .await
            .unwrap_err();
    assert!(error
        .to_string()
        .starts_with("background worker shutdown was incomplete: "));
    assert!(started.elapsed() >= SERVICE_TASK_DRAIN_TIMEOUT);
    assert!(started.elapsed() < SERVICE_TASK_DRAIN_TIMEOUT * 2);
    assert!(tasks.is_empty());
    assert_eq!(actors.active_count(), 0);
}

#[tokio::test(start_paused = true)]
async fn notification_window_keeps_its_two_second_deadline() {
    let cancel = CancellationToken::new();
    let workers = WorkerRegistry::new();
    let actors = ConnectionActorRegistry::new(1);
    let mut ports = TestPorts::new(&actors, &cancel);
    ports.pending_notifications = true;
    let mut tasks = JoinSet::new();
    let service_cancel = cancel.clone();
    spawn_service_task(&mut tasks, "listener", async move {
        service_cancel.cancelled().await;
        Ok(())
    });
    let started = tokio::time::Instant::now();
    supervise_process_shutdown(&ports, &cancel, &workers, &actors, &mut tasks, async {})
        .await
        .unwrap();
    assert!(started.elapsed() >= Duration::from_secs(2));
    assert!(started.elapsed() < Duration::from_millis(2100));
    assert_eq!(
        *ports.events.lock().unwrap(),
        [
            "admission closed",
            "MUC built",
            "MUC window",
            "MUC dropped",
            "begin cluster",
            "release",
        ]
    );
}

#[tokio::test]
async fn critical_worker_failure_is_preserved_on_cancellation() {
    let cancel = CancellationToken::new();
    let workers = WorkerRegistry::new();
    let actors = ConnectionActorRegistry::new(1);
    let ports = TestPorts::new(&actors, &cancel);
    workers.supervise(
        "failed worker",
        WorkerCriticality::Critical,
        WorkerMode::Continuous,
        None,
        cancel.clone(),
        |_| async { anyhow::bail!("injected worker failure") },
    );
    cancel.cancelled().await;
    let mut tasks = JoinSet::new();
    let error =
        supervise_process_shutdown(&ports, &cancel, &workers, &actors, &mut tasks, async {})
            .await
            .unwrap_err();
    assert_eq!(
        error.to_string(),
        "critical worker failed worker failed: injected worker failure"
    );
    assert_eq!(*ports.events.lock().unwrap(), ["begin cluster", "release"]);
}

#[tokio::test]
async fn graceful_shutdown_resamples_critical_failure_and_drops_pending_notifications() {
    let cancel = CancellationToken::new();
    let workers = WorkerRegistry::new();
    let actors = ConnectionActorRegistry::new(1);
    let mut ports = TestPorts::new(&actors, &cancel);
    ports.pending_notifications = true;
    let failure_trigger = CancellationToken::new();
    let worker_trigger = failure_trigger.clone();
    let (started_tx, mut started_rx) = tokio::sync::mpsc::unbounded_channel();
    workers.supervise(
        "failed worker",
        WorkerCriticality::Critical,
        WorkerMode::Continuous,
        None,
        cancel.clone(),
        move |_| {
            let trigger = worker_trigger.clone();
            let started = started_tx.clone();
            async move {
                started.send(()).unwrap();
                trigger.cancelled().await;
                anyhow::bail!("injected worker failure")
            }
        },
    );
    started_rx.recv().await.unwrap();
    let mut tasks = JoinSet::new();
    let service_cancel = cancel.clone();
    spawn_service_task(&mut tasks, "listener", async move {
        service_cancel.cancelled().await;
        Ok(())
    });
    let error = supervise_process_shutdown(&ports, &cancel, &workers, &actors, &mut tasks, async {
        failure_trigger.cancel()
    })
    .await
    .unwrap_err();
    assert_eq!(
        error.to_string(),
        "critical worker failed worker failed: injected worker failure"
    );
    assert_eq!(
        *ports.events.lock().unwrap(),
        [
            "admission closed",
            "MUC built",
            "MUC window",
            "MUC dropped",
            "begin cluster",
            "release",
        ]
    );
}

#[tokio::test]
async fn closed_admission_keeps_existing_actor_alive_until_explicit_shutdown() {
    let registry = ConnectionActorRegistry::new(2);
    let shutdown = registry.shutdown_token();
    let (started_tx, started_rx) = oneshot::channel();
    let (notify_tx, notify_rx) = oneshot::channel();
    let (written_tx, written_rx) = oneshot::channel();
    let (finished_tx, finished_rx) = oneshot::channel();
    registry
        .try_spawn(ConnectionActorKind::C2sWebSocket, None, async move {
            let _ = started_tx.send(());
            notify_rx
                .await
                .expect("existing actor receives its notification");
            let _ = written_tx.send(!shutdown.is_cancelled());
            shutdown.cancelled().await;
            let _ = finished_tx.send(());
        })
        .unwrap();
    tokio::time::timeout(Duration::from_secs(2), started_rx)
        .await
        .unwrap()
        .unwrap();

    registry.close_admission();
    registry.close_admission();
    assert!(!registry.is_accepting());
    assert!(!registry.shutdown_token().is_cancelled());
    assert_eq!(
        registry.try_spawn(ConnectionActorKind::C2sWebSocket, None, async {}),
        Err(ConnectionActorSpawnError::AdmissionClosed)
    );
    notify_tx.send(()).unwrap();
    assert!(tokio::time::timeout(Duration::from_secs(2), written_rx)
        .await
        .unwrap()
        .unwrap());
    assert_eq!(registry.active_count(), 1);

    registry.begin_shutdown();
    let report = registry
        .join_or_abort(Duration::from_secs(2), Duration::from_secs(2))
        .await;
    assert!(report.graceful);
    assert_eq!(report.aborted, 0);
    assert_eq!(report.remaining, 0);
    finished_rx.await.unwrap();
    assert_eq!(registry.active_count(), 0);
}
