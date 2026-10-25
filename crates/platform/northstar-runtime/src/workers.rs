use anyhow::Result;
use futures::FutureExt;
use std::{
    any::Any,
    collections::{HashMap, HashSet},
    future::Future,
    panic::AssertUnwindSafe,
    pin::Pin,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex, RwLock,
    },
    time::{Duration, Instant},
};
use tokio::sync::Notify;
use tokio_util::sync::CancellationToken;

#[cfg(not(test))]
const RESTART_BACKOFF_UNIT: Duration = Duration::from_secs(1);
#[cfg(test)]
const RESTART_BACKOFF_UNIT: Duration = Duration::from_millis(10);
#[cfg(not(test))]
const HEALTHY_STABILITY_WINDOW: Duration = Duration::from_secs(60);
#[cfg(test)]
const HEALTHY_STABILITY_WINDOW: Duration = Duration::from_millis(50);
const MAX_BACKOFF_EXPONENT: u32 = 4;
const ABORT_DRAIN_GRACE: Duration = Duration::from_secs(1);
const CONSECUTIVE_ERROR_THRESHOLD: u32 = 3;

type WorkerFuture = Pin<Box<dyn Future<Output = Result<()>> + Send + 'static>>;
type WorkerFactory = Arc<dyn Fn(WorkerHeartbeat) -> WorkerFuture + Send + Sync + 'static>;

#[derive(Clone, Copy, Debug)]
enum WorkerShutdown {
    Immediate,
    Drain(Duration),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WorkerCriticality {
    /// A stopped worker invalidates a security or authorization boundary. The
    /// supervisor cancels the whole service rather than serving stale policy.
    Critical,
    /// A stopped worker is restarted with bounded backoff and makes readiness
    /// fail until it is running again.
    Restartable,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WorkerMode {
    Continuous,
    OneShot,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RunState {
    Running,
    Restarting,
    Completed,
    Stopped,
}

#[derive(Debug)]
enum AttemptExit {
    Finished(Result<()>),
    Panicked(String),
    HeartbeatExpired {
        limit: Duration,
        watchdog_delay: Duration,
        max_attempt_watchdog_delay: Duration,
    },
    ConsecutiveErrors {
        count: u32,
        error: String,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SupervisorExit {
    Cancelled,
    Completed,
    TerminalFailure,
}

struct WorkerHealth {
    criticality: WorkerCriticality,
    mode: WorkerMode,
    max_silence: Option<Duration>,
    state: RunState,
    last_heartbeat: Instant,
    successful_heartbeats: u64,
    consecutive_errors: u32,
    restart_failures: u32,
    supervisor_failures: u32,
    last_error: Option<String>,
    attempt_generation: u64,
    health_changed: Arc<Notify>,
}

struct SupervisorTask {
    criticality: WorkerCriticality,
    handle: tokio::task::JoinHandle<()>,
}

#[derive(Debug, Default, Eq, PartialEq)]
pub struct WorkerShutdownReport {
    pub joined: usize,
    pub aborted: usize,
    pub join_failures: Vec<String>,
}

impl WorkerShutdownReport {
    pub fn is_clean(&self) -> bool {
        self.aborted == 0 && self.join_failures.is_empty()
    }
}

#[derive(Default)]
pub struct WorkerRegistry {
    workers: Arc<RwLock<HashMap<&'static str, WorkerHealth>>>,
    supervisors: Arc<Mutex<HashMap<&'static str, SupervisorTask>>>,
    shutting_down: Arc<AtomicBool>,
    #[cfg(test)]
    supervisor_panic_injections: Mutex<HashSet<&'static str>>,
}

/// Read-only worker health capability for the private readiness endpoint.
/// The registry remains private and cannot be used to register or stop work.
#[derive(Clone)]
pub struct WorkerReadinessProbe {
    workers: Arc<RwLock<HashMap<&'static str, WorkerHealth>>>,
    supervisors: Arc<Mutex<HashMap<&'static str, SupervisorTask>>>,
    shutting_down: Arc<AtomicBool>,
}

impl WorkerReadinessProbe {
    pub fn readiness_error(&self) -> Option<String> {
        worker_readiness_error(&self.workers, &self.supervisors, &self.shutting_down)
    }
}

#[cfg(test)]
#[test]
fn readiness_probe_observes_live_registry_shutdown() {
    let registry = WorkerRegistry::new();
    let probe = registry.readiness_probe();
    assert_eq!(probe.readiness_error(), registry.readiness_error());
    registry.shutting_down.store(true, Ordering::Release);
    assert_eq!(probe.readiness_error(), registry.readiness_error());
    assert!(probe.readiness_error().is_some());
}

fn worker_readiness_error(
    workers: &RwLock<HashMap<&'static str, WorkerHealth>>,
    supervisors: &Mutex<HashMap<&'static str, SupervisorTask>>,
    shutting_down: &AtomicBool,
) -> Option<String> {
    if shutting_down.load(Ordering::Acquire) {
        return Some("background worker registry is shutting down".to_owned());
    }
    // Snapshot task completion separately: readiness never takes the
    // supervisor and health locks together.
    let finished_supervisors = supervisors
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .iter()
        .filter_map(|(name, task)| task.handle.is_finished().then_some(*name))
        .collect::<HashSet<_>>();
    let now = Instant::now();
    let workers = workers
        .read()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let mut unhealthy = workers
        .iter()
        .filter_map(|(name, health)| {
            let stale = health.max_silence.is_some_and(|limit| {
                health.state == RunState::Running
                    && now.saturating_duration_since(health.last_heartbeat) > limit
            });
            let supervisor_disappeared = finished_supervisors.contains(name)
                && !matches!(health.state, RunState::Completed | RunState::Stopped);
            if matches!(health.state, RunState::Restarting | RunState::Stopped)
                || stale
                || health.consecutive_errors >= CONSECUTIVE_ERROR_THRESHOLD
                || supervisor_disappeared
            {
                Some((
                    *name,
                    health.criticality,
                    if supervisor_disappeared {
                        Some("supervisor task exited without a terminal health transition")
                    } else {
                        health.last_error.as_deref()
                    },
                    health.restart_failures,
                    health.supervisor_failures,
                ))
            } else {
                None
            }
        })
        .collect::<Vec<_>>();
    unhealthy.sort_by_key(|(name, _, _, _, _)| *name);
    unhealthy.first().map(
        |(name, criticality, error, restart_failures, supervisor_failures)| {
            let class = criticality_name(*criticality);
            let attempts = format!(
                "restart failures={restart_failures}, supervisor failures={supervisor_failures}"
            );
            match error {
                Some(error) => format!("{class} worker {name} is unhealthy: {error} ({attempts})"),
                None => format!("{class} worker {name} is unhealthy ({attempts})"),
            }
        },
    )
}

#[derive(Clone)]
pub struct WorkerHeartbeat {
    registry: Arc<WorkerRegistry>,
    name: &'static str,
    attempt_generation: u64,
    health_changed: Arc<Notify>,
}

impl WorkerHeartbeat {
    /// Report liveness without clearing or incrementing business-health
    /// errors. Long bounded batches use this between I/O phases.
    pub fn pulse(&self) {
        self.registry.pulse(self.name, self.attempt_generation);
    }

    /// A successful health boundary also resets accumulated restart backoff.
    pub fn ok(&self) {
        self.registry
            .attempt_heartbeat(self.name, self.attempt_generation, None);
    }

    pub fn error(&self, error: impl std::fmt::Display) {
        if self.registry.attempt_heartbeat(
            self.name,
            self.attempt_generation,
            Some(error.to_string()),
        ) {
            // A stored permit closes the race where the threshold is reached
            // just before the supervisor starts waiting. The periodic
            // watchdog remains a second, bounded observation path.
            self.health_changed.notify_one();
        }
    }
}

impl WorkerRegistry {
    fn pulse(&self, name: &'static str, attempt_generation: u64) {
        self.update(name, |health| {
            if health.state == RunState::Running
                && health.attempt_generation == attempt_generation
                && health.consecutive_errors < CONSECUTIVE_ERROR_THRESHOLD
            {
                health.last_heartbeat = Instant::now();
            }
        });
    }

    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    pub fn readiness_probe(self: &Arc<Self>) -> WorkerReadinessProbe {
        WorkerReadinessProbe {
            workers: Arc::clone(&self.workers),
            supervisors: Arc::clone(&self.supervisors),
            shutting_down: Arc::clone(&self.shutting_down),
        }
    }

    pub fn readiness_error(&self) -> Option<String> {
        worker_readiness_error(&self.workers, &self.supervisors, &self.shutting_down)
    }

    /// Return only a terminal critical-worker failure. Normal service
    /// cancellation also transitions workers to `Stopped`, but carries no
    /// error and must not turn an operator-requested shutdown into a crash.
    pub fn critical_failure(&self) -> Option<String> {
        let workers = self
            .workers
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let mut failures = workers
            .iter()
            .filter_map(|(name, health)| {
                if health.criticality == WorkerCriticality::Critical
                    && health.state == RunState::Stopped
                {
                    health.last_error.as_ref().map(|error| (*name, error))
                } else {
                    None
                }
            })
            .collect::<Vec<_>>();
        failures.sort_by_key(|(name, _)| *name);
        failures
            .first()
            .map(|(name, error)| format!("critical worker {name} failed: {error}"))
    }
    /// Register a synchronous health boundary which has no long-lived task.
    pub fn register_observer(&self, name: &'static str, criticality: WorkerCriticality) {
        let _registration = self
            .supervisors
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        assert!(
            !self.shutting_down.load(Ordering::Acquire),
            "cannot register a worker health observer after shutdown began"
        );
        let mut workers = self
            .workers
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        assert!(
            workers
                .insert(
                    name,
                    WorkerHealth {
                        criticality,
                        mode: WorkerMode::Continuous,
                        max_silence: None,
                        state: RunState::Running,
                        last_heartbeat: Instant::now(),
                        successful_heartbeats: 0,
                        consecutive_errors: 0,
                        restart_failures: 0,
                        supervisor_failures: 0,
                        last_error: None,
                        attempt_generation: 0,
                        health_changed: Arc::new(Notify::new()),
                    },
                )
                .is_none(),
            "worker and health-observer names must be unique"
        );
    }

    pub fn observer_ok(&self, name: &'static str) {
        self.observer_heartbeat(name, None);
    }

    pub fn observer_error(&self, name: &'static str, error: impl std::fmt::Display) {
        self.observer_heartbeat(name, Some(error.to_string()));
    }

    pub fn supervise<F, Fut>(
        self: &Arc<Self>,
        name: &'static str,
        criticality: WorkerCriticality,
        mode: WorkerMode,
        max_silence: Option<Duration>,
        cancel: CancellationToken,
        factory: F,
    ) where
        F: Fn(WorkerHeartbeat) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<()>> + Send + 'static,
    {
        self.supervise_with_shutdown(
            name,
            criticality,
            mode,
            max_silence,
            WorkerShutdown::Immediate,
            cancel,
            factory,
        );
    }

    /// Supervise a bounded worker which must observe service cancellation and
    /// finish its own finite drain before its future is dropped. The retained
    /// guardian still enforces the registry-wide shutdown deadline, so a
    /// broken drain cannot keep the process alive indefinitely.
    #[expect(
        clippy::too_many_arguments,
        reason = "worker registration keeps criticality, restart mode, liveness, drain policy, and cancellation explicit"
    )]
    pub fn supervise_draining<F, Fut>(
        self: &Arc<Self>,
        name: &'static str,
        criticality: WorkerCriticality,
        mode: WorkerMode,
        max_silence: Option<Duration>,
        drain_grace: Duration,
        cancel: CancellationToken,
        factory: F,
    ) where
        F: Fn(WorkerHeartbeat) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<()>> + Send + 'static,
    {
        assert!(
            !drain_grace.is_zero(),
            "worker drain grace must be positive"
        );
        self.supervise_with_shutdown(
            name,
            criticality,
            mode,
            max_silence,
            WorkerShutdown::Drain(drain_grace),
            cancel,
            factory,
        );
    }

    #[expect(
        clippy::too_many_arguments,
        reason = "the internal supervisor receives the complete immutable worker registration contract"
    )]
    fn supervise_with_shutdown<F, Fut>(
        self: &Arc<Self>,
        name: &'static str,
        criticality: WorkerCriticality,
        mode: WorkerMode,
        max_silence: Option<Duration>,
        shutdown: WorkerShutdown,
        cancel: CancellationToken,
        factory: F,
    ) where
        F: Fn(WorkerHeartbeat) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<()>> + Send + 'static,
    {
        // This mutex is also the shutdown registration gate. A racing worker
        // is either rejected or its retained handle enters the drain set.
        let mut supervisors = self
            .supervisors
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        assert!(
            !self.shutting_down.load(Ordering::Acquire),
            "cannot register a worker after shutdown began"
        );
        {
            let mut workers = self
                .workers
                .write()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            assert!(
                workers
                    .insert(
                        name,
                        WorkerHealth {
                            criticality,
                            mode,
                            max_silence,
                            state: RunState::Restarting,
                            last_heartbeat: Instant::now(),
                            successful_heartbeats: 0,
                            consecutive_errors: 0,
                            restart_failures: 0,
                            supervisor_failures: 0,
                            last_error: None,
                            attempt_generation: 0,
                            health_changed: Arc::new(Notify::new()),
                        },
                    )
                    .is_none(),
                "worker and health-observer names must be unique"
            );
        }
        let factory: WorkerFactory = Arc::new(move |heartbeat| Box::pin(factory(heartbeat)));
        let registry = Arc::clone(self);
        let handle = tokio::spawn(async move {
            registry
                .run_guardian(
                    name,
                    criticality,
                    mode,
                    max_silence,
                    shutdown,
                    cancel,
                    factory,
                )
                .await;
        });
        assert!(
            supervisors
                .insert(
                    name,
                    SupervisorTask {
                        criticality,
                        handle,
                    },
                )
                .is_none(),
            "worker supervisor names must be unique"
        );
    }

    #[expect(
        clippy::too_many_arguments,
        reason = "the retained guardian owns the complete immutable worker registration contract"
    )]
    async fn run_guardian(
        self: &Arc<Self>,
        name: &'static str,
        criticality: WorkerCriticality,
        mode: WorkerMode,
        max_silence: Option<Duration>,
        shutdown: WorkerShutdown,
        cancel: CancellationToken,
        factory: WorkerFactory,
    ) {
        let mut supervisor_failures = 0_u32;
        loop {
            let healthy_at_start = self.successful_heartbeat_count(name);
            let supervisor_started = Instant::now();
            let outcome = AssertUnwindSafe(Arc::clone(self).run_supervisor(
                name,
                criticality,
                mode,
                max_silence,
                shutdown,
                cancel.clone(),
                Arc::clone(&factory),
            ))
            .catch_unwind()
            .await;
            match outcome {
                Ok(SupervisorExit::Cancelled | SupervisorExit::Completed) => return,
                Ok(SupervisorExit::TerminalFailure) => return,
                Err(panic) => {
                    let error = format!("supervisor panic: {}", panic_message(panic));
                    if supervisor_started.elapsed() >= HEALTHY_STABILITY_WINDOW
                        || self.successful_heartbeat_count(name) > healthy_at_start
                    {
                        supervisor_failures = 0;
                    }
                    supervisor_failures = supervisor_failures.saturating_add(1);
                    self.supervisor_failed(name, supervisor_failures, error.clone());
                    if criticality == WorkerCriticality::Critical {
                        tracing::error!(worker = name, %error, "critical worker supervisor panicked; shutting down");
                        cancel.cancel();
                        return;
                    }
                    let delay = restart_backoff(supervisor_failures);
                    tracing::error!(worker = name, %error, ?delay, "restartable worker supervisor panicked; rebuilding supervisor");
                    tokio::select! {
                        _ = cancel.cancelled() => {
                            self.stopped(name, None);
                            return;
                        }
                        _ = tokio::time::sleep(delay) => {}
                    }
                }
            }
        }
    }

    #[expect(
        clippy::too_many_arguments,
        reason = "each supervisor attempt receives the complete immutable worker registration contract"
    )]
    async fn run_supervisor(
        self: Arc<Self>,
        name: &'static str,
        criticality: WorkerCriticality,
        mode: WorkerMode,
        max_silence: Option<Duration>,
        shutdown: WorkerShutdown,
        cancel: CancellationToken,
        factory: WorkerFactory,
    ) -> SupervisorExit {
        let mut failures = 0_u32;
        loop {
            #[cfg(test)]
            if self.take_supervisor_panic_injection(name) {
                panic!("injected worker supervisor panic");
            }
            let (attempt_generation, health_changed) = self.started(name);
            let healthy_at_start = self.successful_heartbeat_count(name);
            let attempt_started = Instant::now();
            let result = {
                let heartbeat = WorkerHeartbeat {
                    registry: Arc::clone(&self),
                    name,
                    attempt_generation,
                    health_changed: Arc::clone(&health_changed),
                };
                // Lazy construction keeps both a synchronous factory panic and an
                // asynchronous polling panic inside this attempt boundary.
                let attempt_factory = Arc::clone(&factory);
                let attempt = AssertUnwindSafe(async move { (attempt_factory)(heartbeat).await })
                    .catch_unwind();
                tokio::pin!(attempt);
                let watchdog_period = max_silence
                    .map(watchdog_period)
                    .unwrap_or(Duration::from_secs(1));
                let mut watchdog = tokio::time::interval_at(
                    tokio::time::Instant::now() + watchdog_period,
                    watchdog_period,
                );
                watchdog.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
                // Delay schedules a fresh deadline after a late tick. Retain
                // earlier observations so a timely terminal tick cannot hide
                // a previous scheduling delay in this attempt.
                let mut max_attempt_watchdog_delay = Duration::ZERO;
                loop {
                    tokio::select! {
                        _ = cancel.cancelled() => {
                            if let WorkerShutdown::Drain(grace) = shutdown {
                                match tokio::time::timeout(grace, &mut attempt).await {
                                    Ok(Ok(Ok(()))) => {}
                                    Ok(Ok(Err(error))) => {
                                        tracing::warn!(worker = name, ?error, "worker drain returned an error during shutdown");
                                    }
                                    Ok(Err(panic)) => {
                                        tracing::warn!(worker = name, panic = %panic_message(panic), "worker drain panicked during shutdown");
                                    }
                                    Err(_) => {
                                        tracing::warn!(worker = name, ?grace, "worker drain exceeded its shutdown grace");
                                    }
                                }
                            }
                            self.stopped(name, None);
                            return SupervisorExit::Cancelled;
                        }
                        result = &mut attempt => {
                            break match result {
                                Ok(result) => AttemptExit::Finished(result),
                                Err(panic) => AttemptExit::Panicked(panic_message(panic)),
                            };
                        }
                        _ = health_changed.notified() => {
                            if let Some((count, error)) = self.consecutive_error(
                                name,
                                attempt_generation,
                            ) {
                                break AttemptExit::ConsecutiveErrors { count, error };
                            }
                        }
                        scheduled = watchdog.tick() => {
                            let watchdog_delay = tokio::time::Instant::now()
                                .saturating_duration_since(scheduled);
                            max_attempt_watchdog_delay =
                                max_attempt_watchdog_delay.max(watchdog_delay);
                            if let Some((count, error)) = self.consecutive_error(
                                name,
                                attempt_generation,
                            ) {
                                break AttemptExit::ConsecutiveErrors { count, error };
                            }
                            if let Some(limit) = max_silence {
                                if self.heartbeat_expired(name, attempt_generation, limit) {
                                    break AttemptExit::HeartbeatExpired {
                                        limit,
                                        watchdog_delay,
                                        max_attempt_watchdog_delay,
                                    };
                                }
                            }
                        }
                    }
                }
            };
            // Once an attempt reaches the business-error threshold it is
            // terminal even if the worker races to return `Ok(())` before the
            // notification branch is polled. A later success cannot erase a
            // latched authorization or persistence failure.
            let result = match result {
                AttemptExit::Finished(Ok(())) => self
                    .consecutive_error(name, attempt_generation)
                    .map_or(AttemptExit::Finished(Ok(())), |(count, error)| {
                        AttemptExit::ConsecutiveErrors { count, error }
                    }),
                result => result,
            };
            if cancel.is_cancelled() {
                self.stopped(name, None);
                return SupervisorExit::Cancelled;
            }
            let error = match result {
                AttemptExit::Finished(Ok(())) if mode == WorkerMode::OneShot => {
                    self.completed(name);
                    return SupervisorExit::Completed;
                }
                AttemptExit::Finished(Ok(())) => "worker returned unexpectedly".to_owned(),
                AttemptExit::Finished(Err(error)) => error.to_string(),
                AttemptExit::Panicked(error) => format!("panic: {error}"),
                AttemptExit::HeartbeatExpired {
                    limit,
                    watchdog_delay,
                    max_attempt_watchdog_delay,
                } => {
                    tracing::warn!(
                        worker = name,
                        heartbeat_limit_ms = limit.as_millis() as u64,
                        watchdog_tick_delay_ms = watchdog_delay.as_millis() as u64,
                        max_attempt_watchdog_tick_delay_ms =
                            max_attempt_watchdog_delay.as_millis() as u64,
                        "worker heartbeat expired at watchdog observation"
                    );
                    format!(
                        "worker heartbeat exceeded the {} ms silence limit",
                        limit.as_millis()
                    )
                }
                AttemptExit::ConsecutiveErrors { count, error } => {
                    format!("worker reported {count} consecutive business-health errors: {error}")
                }
            };
            if criticality == WorkerCriticality::Critical {
                self.terminal_failure(name, error.clone());
                tracing::error!(worker = name, %error, "critical worker stopped; shutting down");
                cancel.cancel();
                return SupervisorExit::TerminalFailure;
            }
            if attempt_started.elapsed() >= HEALTHY_STABILITY_WINDOW
                || self.successful_heartbeat_count(name) > healthy_at_start
            {
                failures = 0;
            }
            failures = failures.saturating_add(1);
            self.restarting(name, failures, error.clone());
            let delay = restart_backoff(failures);
            tracing::error!(worker = name, %error, ?delay, "worker stopped; scheduling restart");
            tokio::select! {
                _ = cancel.cancelled() => {
                    self.stopped(name, None);
                    return SupervisorExit::Cancelled;
                }
                _ = tokio::time::sleep(delay) => {}
            }
        }
    }

    /// Cancel and join every retained guardian without awaiting under a lock.
    /// Once the shared grace expires, remaining tasks are aborted and drained
    /// for one final bounded interval instead of being detached.
    pub async fn shutdown_and_join(
        &self,
        cancel: &CancellationToken,
        grace: Duration,
    ) -> WorkerShutdownReport {
        self.shutting_down.store(true, Ordering::Release);
        cancel.cancel();
        let mut pending = {
            let mut supervisors = self
                .supervisors
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            std::mem::take(&mut *supervisors)
                .into_iter()
                .map(|(name, task)| (name, task.criticality, task.handle))
                .collect::<Vec<_>>()
        };
        let deadline = tokio::time::Instant::now() + grace;
        let mut report = WorkerShutdownReport::default();
        while let Some((name, criticality, mut handle)) = pending.pop() {
            match tokio::time::timeout_at(deadline, &mut handle).await {
                Ok(Ok(())) => report.joined += 1,
                Ok(Err(error)) => report.join_failures.push(format!(
                    "{} worker supervisor {name} failed while joining: {error}",
                    criticality_name(criticality)
                )),
                Err(_) => {
                    handle.abort();
                    pending.push((name, criticality, handle));
                    // The grace deadline was exceeded. Count the complete
                    // retained set conservatively even if one task races to
                    // completion while cancellation is being delivered.
                    report.aborted = pending.len();
                    for (_, _, task) in &pending {
                        task.abort();
                    }
                    break;
                }
            }
        }
        if !pending.is_empty() {
            let deadline = tokio::time::Instant::now() + ABORT_DRAIN_GRACE;
            while let Some((name, criticality, mut handle)) = pending.pop() {
                match tokio::time::timeout_at(deadline, &mut handle).await {
                    Ok(Ok(())) => {}
                    Ok(Err(error)) if error.is_cancelled() => {}
                    Ok(Err(error)) => report.join_failures.push(format!(
                        "{} worker supervisor {name} failed after abort: {error}",
                        criticality_name(criticality)
                    )),
                    Err(_) => report.join_failures.push(format!(
                        "{} worker supervisor {name} did not terminate after abort",
                        criticality_name(criticality)
                    )),
                }
            }
        }
        report
    }

    fn started(&self, name: &'static str) -> (u64, Arc<Notify>) {
        let mut workers = self
            .workers
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let health = workers
            .get_mut(name)
            .expect("registered worker health exists before its supervisor starts");
        health.attempt_generation = health
            .attempt_generation
            .checked_add(1)
            .expect("worker attempt generation exhausted");
        health.state = RunState::Running;
        health.last_heartbeat = Instant::now();
        health.consecutive_errors = 0;
        health.last_error = None;
        (
            health.attempt_generation,
            Arc::clone(&health.health_changed),
        )
    }

    fn observer_heartbeat(&self, name: &'static str, error: Option<String>) {
        self.update(name, |health| {
            if health.state != RunState::Running || health.attempt_generation != 0 {
                return;
            }
            health.last_heartbeat = Instant::now();
            if let Some(error) = error {
                health.consecutive_errors = health.consecutive_errors.saturating_add(1);
                health.last_error = Some(error);
            } else {
                health.successful_heartbeats = health.successful_heartbeats.saturating_add(1);
                health.consecutive_errors = 0;
                health.last_error = None;
            }
        });
    }

    /// Update one exact supervised attempt. Returns true once the attempt's
    /// business-error threshold is latched and its supervisor must act.
    fn attempt_heartbeat(
        &self,
        name: &'static str,
        attempt_generation: u64,
        error: Option<String>,
    ) -> bool {
        let mut threshold_reached = false;
        self.update(name, |health| {
            if health.state != RunState::Running || health.attempt_generation != attempt_generation
            {
                return;
            }
            // The threshold is terminal for this attempt. In particular, a
            // success racing the supervisor cannot clear the stored cause.
            if health.consecutive_errors >= CONSECUTIVE_ERROR_THRESHOLD {
                threshold_reached = true;
                return;
            }
            health.last_heartbeat = Instant::now();
            if let Some(error) = error {
                health.consecutive_errors = health.consecutive_errors.saturating_add(1);
                health.last_error = Some(error);
                threshold_reached = health.consecutive_errors >= CONSECUTIVE_ERROR_THRESHOLD;
            } else {
                health.successful_heartbeats = health.successful_heartbeats.saturating_add(1);
                health.consecutive_errors = 0;
                health.last_error = None;
            }
        });
        threshold_reached
    }

    fn restarting(&self, name: &'static str, failures: u32, error: String) {
        self.update(name, |health| {
            health.state = RunState::Restarting;
            health.restart_failures = failures;
            health.last_error = Some(error);
        });
    }

    fn supervisor_failed(&self, name: &'static str, failures: u32, error: String) {
        self.update(name, |health| {
            health.state = if health.criticality == WorkerCriticality::Critical {
                RunState::Stopped
            } else {
                RunState::Restarting
            };
            health.supervisor_failures = failures;
            health.last_error = Some(error);
        });
    }

    fn terminal_failure(&self, name: &'static str, error: String) {
        self.update(name, |health| {
            health.state = RunState::Stopped;
            health.last_error = Some(error);
        });
    }

    fn stopped(&self, name: &'static str, error: Option<String>) {
        self.update(name, |health| {
            health.state = RunState::Stopped;
            health.last_error = error;
        });
    }

    fn completed(&self, name: &'static str) {
        self.update(name, |health| {
            debug_assert_eq!(health.mode, WorkerMode::OneShot);
            health.state = RunState::Completed;
            health.last_heartbeat = Instant::now();
            health.successful_heartbeats = health.successful_heartbeats.saturating_add(1);
            health.consecutive_errors = 0;
            health.restart_failures = 0;
            health.last_error = None;
        });
    }

    fn consecutive_error(
        &self,
        name: &'static str,
        attempt_generation: u64,
    ) -> Option<(u32, String)> {
        let workers = self
            .workers
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        workers.get(name).and_then(|health| {
            (health.state == RunState::Running
                && health.attempt_generation == attempt_generation
                && health.consecutive_errors >= CONSECUTIVE_ERROR_THRESHOLD)
                .then(|| {
                    (
                        health.consecutive_errors,
                        health
                            .last_error
                            .clone()
                            .unwrap_or_else(|| "worker health failed without an error".to_owned()),
                    )
                })
        })
    }

    fn heartbeat_expired(
        &self,
        name: &'static str,
        attempt_generation: u64,
        limit: Duration,
    ) -> bool {
        let workers = self
            .workers
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        workers.get(name).is_some_and(|health| {
            health.state == RunState::Running
                && health.attempt_generation == attempt_generation
                && Instant::now().saturating_duration_since(health.last_heartbeat) > limit
        })
    }

    fn successful_heartbeat_count(&self, name: &'static str) -> u64 {
        self.workers
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .get(name)
            .map_or(0, |health| health.successful_heartbeats)
    }

    fn update(&self, name: &'static str, update: impl FnOnce(&mut WorkerHealth)) {
        let mut workers = self
            .workers
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if let Some(health) = workers.get_mut(name) {
            update(health);
        }
    }

    #[cfg(test)]
    fn inject_supervisor_panic(&self, name: &'static str) {
        self.supervisor_panic_injections
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .insert(name);
    }

    #[cfg(test)]
    fn take_supervisor_panic_injection(&self, name: &'static str) -> bool {
        self.supervisor_panic_injections
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .remove(name)
    }

    #[cfg(test)]
    fn test_health(&self, name: &'static str) -> (u32, u32) {
        let workers = self
            .workers
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let health = workers.get(name).expect("test worker is registered");
        (health.restart_failures, health.supervisor_failures)
    }

    #[cfg(test)]
    fn active_supervisors(&self) -> usize {
        self.supervisors
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .len()
    }
}

fn criticality_name(criticality: WorkerCriticality) -> &'static str {
    match criticality {
        WorkerCriticality::Critical => "critical",
        WorkerCriticality::Restartable => "restartable",
    }
}

fn restart_backoff(failures: u32) -> Duration {
    RESTART_BACKOFF_UNIT.saturating_mul(2_u32.saturating_pow(failures.min(MAX_BACKOFF_EXPONENT)))
}

fn watchdog_period(limit: Duration) -> Duration {
    limit
        .checked_div(4)
        .unwrap_or_default()
        .clamp(Duration::from_millis(10), Duration::from_secs(1))
}

fn panic_message(payload: Box<dyn Any + Send>) -> String {
    if let Some(message) = payload.downcast_ref::<&str>() {
        (*message).to_owned()
    } else if let Some(message) = payload.downcast_ref::<String>() {
        message.clone()
    } else {
        "non-string panic payload".to_owned()
    }
}

#[cfg(test)]
mod tests;
