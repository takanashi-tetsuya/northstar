//! One reserved PostgreSQL connection for durable runtime policy and control.
//! Runtime control diagnostics and health reporting.

use crate::runtime_control::{
    service_control_applies, RuntimeControlRepository, RuntimeControlService,
};
use anyhow::Result;
use northstar_runtime::workers::WorkerHeartbeat;
use std::{
    future::Future,
    sync::{Arc, OnceLock, Weak},
    time::Duration,
};
use tokio::sync::Mutex;
use tokio_util::sync::CancellationToken;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RuntimeControlPhase {
    Idle,
    SnapshotRead,
    PolicyApply,
    ServiceControlRead,
}

impl RuntimeControlPhase {
    pub fn label(self) -> &'static str {
        match self {
            Self::Idle => "idle",
            Self::SnapshotRead => "snapshot-read",
            Self::PolicyApply => "policy-apply",
            Self::ServiceControlRead => "service-control-read",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RuntimeControlStall {
    pub phase: RuntimeControlPhase,
    pub phase_elapsed: Duration,
    pub heartbeat_elapsed: Duration,
}

/// Observation only: a stalled attempt is dropped before its supervisor sets
/// the root cancellation token. Normal root shutdown must not produce a warning.
pub struct RuntimeControlDiagnostics {
    pub phase: RuntimeControlPhase,
    pub phase_started: tokio::time::Instant,
    pub last_reported: tokio::time::Instant,
    pub max_silence: Duration,
    pub root_cancel: CancellationToken,
    #[cfg(test)]
    pub captured: Option<Arc<std::sync::Mutex<Vec<RuntimeControlStall>>>>,
}

impl RuntimeControlDiagnostics {
    pub fn new(root_cancel: CancellationToken, max_silence: Duration) -> Self {
        let now = tokio::time::Instant::now();
        Self {
            phase: RuntimeControlPhase::Idle,
            phase_started: now,
            last_reported: now,
            max_silence,
            root_cancel,
            #[cfg(test)]
            captured: None,
        }
    }

    pub fn enter(&mut self, phase: RuntimeControlPhase) {
        self.phase = phase;
        self.phase_started = tokio::time::Instant::now();
    }

    pub fn database_read(&mut self, phase: crate::runtime_control::RuntimeControlReadPhase) {
        self.enter(match phase {
            crate::runtime_control::RuntimeControlReadPhase::Snapshot => {
                RuntimeControlPhase::SnapshotRead
            }
        });
    }

    /// Call only after the existing heartbeat report; this changes no health.
    pub fn reported(&mut self) {
        let now = tokio::time::Instant::now();
        self.last_reported = now;
        self.phase = RuntimeControlPhase::Idle;
        self.phase_started = now;
    }

    pub fn stalled(&self) -> Option<RuntimeControlStall> {
        if self.root_cancel.is_cancelled() {
            return None;
        }
        let now = tokio::time::Instant::now();
        let heartbeat_elapsed = now.saturating_duration_since(self.last_reported);
        (heartbeat_elapsed > self.max_silence).then(|| RuntimeControlStall {
            phase: self.phase,
            phase_elapsed: now.saturating_duration_since(self.phase_started),
            heartbeat_elapsed,
        })
    }
}

impl Drop for RuntimeControlDiagnostics {
    fn drop(&mut self) {
        let Some(stall) = self.stalled() else {
            return;
        };
        tracing::warn!(
            phase = stall.phase.label(),
            phase_elapsed_ms = stall.phase_elapsed.as_millis() as u64,
            heartbeat_elapsed_ms = stall.heartbeat_elapsed.as_millis() as u64,
            "runtime-control attempt dropped after heartbeat silence"
        );
        #[cfg(test)]
        if let Some(captured) = &self.captured {
            captured.lock().unwrap().push(stall);
        }
    }
}

pub fn report_runtime_control_health(
    heartbeat: &northstar_runtime::workers::WorkerHeartbeat,
    observed_database: bool,
    error: Option<anyhow::Error>,
) {
    if let Some(error) = error {
        heartbeat.error(error);
    } else if observed_database {
        heartbeat.ok();
    } else {
        // With XEP-0133 control disabled, alternate ticks perform no query.
        // They prove scheduler liveness only, never database/ownership health.
        // Clearing an error here would let a dead reserved connection alternate
        // error/ok forever, concealing loss of the standalone retention lock.
        heartbeat.pulse();
    }
}

/// Effects of one durable runtime policy snapshot, applied in this order by the coordinator.
pub trait RuntimePolicyEffects: Send + Sync {
    /// Returns whether island mode was already active.
    fn refresh_island_mode(&self, island_mode: bool) -> impl Future<Output = bool> + Send;
    fn apply_registration_closed(&self, closed: bool);
    fn clear_for_island_mode(&self);
    fn store_federation_rules(&self, blacklist: Vec<String>, whitelist: Vec<String>);
}

pub struct RuntimeControlCoordinator<R, E> {
    liveness: Weak<()>,
    connection: Arc<Mutex<Option<R>>>,
    effects: E,
    service_control_enabled: bool,
    service_shutdown: Arc<OnceLock<CancellationToken>>,
    process_started_at: chrono::DateTime<chrono::Utc>,
}

impl<R: RuntimeControlRepository, E: RuntimePolicyEffects> RuntimeControlCoordinator<R, E> {
    pub fn new(
        liveness: Weak<()>,
        repository: R,
        effects: E,
        service_control_enabled: bool,
        service_shutdown: Arc<OnceLock<CancellationToken>>,
        process_started_at: chrono::DateTime<chrono::Utc>,
    ) -> Self {
        Self {
            liveness,
            connection: Arc::new(Mutex::new(Some(repository))),
            effects,
            service_control_enabled,
            service_shutdown,
            process_started_at,
        }
    }

    pub async fn run(
        &self,
        heartbeat: WorkerHeartbeat,
        diagnostic_cancel: CancellationToken,
        max_silence: Duration,
    ) -> Result<()> {
        let mut diagnostics = RuntimeControlDiagnostics::new(diagnostic_cancel, max_silence);
        let repository = self.connection.lock().await.take().ok_or_else(|| {
            anyhow::anyhow!(
                "runtime-control coordinator was restarted after its reserved connection ended"
            )
        })?;
        // The connection cannot be returned to another worker after this
        // attempt ends. Reads, application and service control stay serialized.
        let mut control = RuntimeControlService::new(repository);
        let mut interval = tokio::time::interval(Duration::from_millis(500));
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        let mut refresh_policy = true;
        let mut acted_service_control = None;
        loop {
            interval.tick().await;
            let Some(_state_alive) = self.liveness.upgrade() else {
                return Ok(());
            };

            let mut first_error = None;
            let mut observed_database = false;
            if refresh_policy {
                observed_database = true;
                match control
                    .policy_snapshot(|phase| diagnostics.database_read(phase))
                    .await
                {
                    Ok(policy) => {
                        diagnostics.enter(RuntimeControlPhase::PolicyApply);
                        let was_island = self.effects.refresh_island_mode(policy.island_mode).await;
                        self.effects
                            .apply_registration_closed(policy.registration_closed);
                        if policy.island_mode && !was_island {
                            self.effects.clear_for_island_mode();
                        }
                        self.effects
                            .store_federation_rules(policy.blacklist, policy.whitelist);
                    }
                    Err(error) => {
                        tracing::error!(
                            ?error,
                            "could not refresh durable administration settings"
                        );
                        first_error = Some(error);
                    }
                }
            }

            // The shutdown token is installed after ServerNode::new returns, so
            // readiness must be read live rather than captured at construction.
            if self.service_control_enabled && self.service_shutdown.get().is_some() {
                observed_database = true;
                diagnostics.enter(RuntimeControlPhase::ServiceControlRead);
                match control.service_control().await {
                    Ok(Some(control))
                        if service_control_applies(self.process_started_at, &control)
                            && acted_service_control != Some(control.generation) =>
                    {
                        acted_service_control = Some(control.generation);
                        tracing::warn!(
                            operation = %control.action,
                            generation = %control.generation,
                            execute_at = %control.execute_at,
                            expires_at = %control.expires_at,
                            "executing durable cluster-wide service control"
                        );
                        if let Some(shutdown) = self.service_shutdown.get() {
                            shutdown.cancel();
                        }
                    }
                    Ok(_) => {}
                    Err(error) => {
                        tracing::error!(
                            ?error,
                            "could not poll durable cluster-wide service control"
                        );
                        if first_error.is_none() {
                            first_error = Some(error);
                        }
                    }
                }
            }

            report_runtime_control_health(&heartbeat, observed_database, first_error);
            diagnostics.reported();
            refresh_policy = !refresh_policy;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::report_runtime_control_health;
    use super::{RuntimeControlCoordinator, RuntimeControlRepository, RuntimePolicyEffects};
    use crate::runtime_control::{
        DurableServiceControl, RuntimeControlReadPhase, RuntimePolicySnapshot,
    };
    use anyhow::Result;
    use northstar_runtime::workers::WorkerCriticality;
    use northstar_runtime::workers::WorkerHeartbeat;
    use northstar_runtime::workers::WorkerMode;
    use northstar_runtime::workers::WorkerRegistry;
    use std::collections::VecDeque;
    use std::future::Future;
    use std::pin::Pin;
    use std::sync::{Arc, Mutex, OnceLock};
    use std::time::Duration;
    use tokio_util::sync::CancellationToken;

    struct FakeRepository {
        policies: VecDeque<RuntimePolicySnapshot>,
        controls: VecDeque<Option<DurableServiceControl>>,
        reads: tokio::sync::mpsc::UnboundedSender<()>,
    }

    impl RuntimeControlRepository for FakeRepository {
        async fn policy_snapshot(
            &mut self,
            mut read_phase: impl FnMut(RuntimeControlReadPhase) + Send,
        ) -> Result<RuntimePolicySnapshot> {
            read_phase(RuntimeControlReadPhase::Snapshot);
            Ok(self.policies.pop_front().unwrap_or_else(|| policy(false)))
        }

        async fn service_control(&mut self) -> Result<Option<DurableServiceControl>> {
            self.reads.send(()).unwrap();
            Ok(self.controls.pop_front().flatten())
        }
    }

    #[derive(Debug, PartialEq, Eq)]
    enum PolicyEffect {
        Refresh(bool),
        Registration(bool),
        Clear,
        Rules(Vec<String>, Vec<String>),
    }

    #[derive(Clone, Default)]
    struct FakeEffects {
        state: Arc<Mutex<(bool, Vec<PolicyEffect>)>>,
    }

    impl RuntimePolicyEffects for FakeEffects {
        async fn refresh_island_mode(&self, island_mode: bool) -> bool {
            let mut state = self.state.lock().unwrap();
            state.1.push(PolicyEffect::Refresh(island_mode));
            std::mem::replace(&mut state.0, island_mode)
        }

        fn apply_registration_closed(&self, closed: bool) {
            self.state
                .lock()
                .unwrap()
                .1
                .push(PolicyEffect::Registration(closed));
        }

        fn clear_for_island_mode(&self) {
            self.state.lock().unwrap().1.push(PolicyEffect::Clear);
        }

        fn store_federation_rules(&self, blacklist: Vec<String>, whitelist: Vec<String>) {
            self.state
                .lock()
                .unwrap()
                .1
                .push(PolicyEffect::Rules(blacklist, whitelist));
        }
    }

    fn policy(island_mode: bool) -> RuntimePolicySnapshot {
        RuntimePolicySnapshot {
            island_mode,
            registration_closed: island_mode,
            blacklist: vec!["blocked.example".to_owned()],
            whitelist: vec!["allowed.example".to_owned()],
        }
    }

    async fn test_heartbeat() -> (Arc<WorkerRegistry>, CancellationToken, WorkerHeartbeat) {
        let workers = WorkerRegistry::new();
        let cancel = CancellationToken::new();
        let (sender, mut receiver) = tokio::sync::mpsc::unbounded_channel();
        workers.supervise(
            "test-runtime-control-coordinator",
            WorkerCriticality::Critical,
            WorkerMode::Continuous,
            None,
            cancel.clone(),
            move |heartbeat| {
                sender.send(heartbeat).unwrap();
                std::future::pending()
            },
        );
        let heartbeat = receiver.recv().await.unwrap();
        (workers, cancel, heartbeat)
    }

    async fn observe_control_read(
        run: Pin<&mut impl Future<Output = Result<()>>>,
        reads: &mut tokio::sync::mpsc::UnboundedReceiver<()>,
    ) {
        tokio::select! {
            biased;
            result = run => panic!("coordinator ended before its control read: {result:?}"),
            read = reads.recv() => read.unwrap(),
            _ = tokio::time::sleep(Duration::from_secs(1)) => {
                panic!("coordinator did not read service control within two ticks");
            }
        }
    }

    // The execution warning is emitted once per action, immediately before
    // cancellation. Counting it detects duplicate actions on an already-cancelled token.
    struct ControlActions(Arc<std::sync::atomic::AtomicUsize>);

    impl tracing::Subscriber for ControlActions {
        fn enabled(&self, _: &tracing::Metadata<'_>) -> bool {
            true
        }

        fn new_span(&self, _: &tracing::span::Attributes<'_>) -> tracing::span::Id {
            tracing::span::Id::from_u64(1)
        }

        fn record(&self, _: &tracing::span::Id, _: &tracing::span::Record<'_>) {}

        fn record_follows_from(&self, _: &tracing::span::Id, _: &tracing::span::Id) {}

        fn event(&self, event: &tracing::Event<'_>) {
            if event.metadata().fields().field("generation").is_some() {
                self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            }
        }

        fn enter(&self, _: &tracing::span::Id) {}

        fn exit(&self, _: &tracing::span::Id) {}
    }

    #[tokio::test]
    async fn policy_effects_apply_in_order_and_clear_only_on_island_entry() {
        tokio::time::pause();
        let (workers, cancel, heartbeat) = test_heartbeat().await;
        let liveness = Arc::new(());
        let shutdown = Arc::new(OnceLock::new());
        shutdown.set(CancellationToken::new()).unwrap();
        let (sender, mut reads) = tokio::sync::mpsc::unbounded_channel();
        let effects = FakeEffects::default();
        let coordinator = RuntimeControlCoordinator::new(
            Arc::downgrade(&liveness),
            FakeRepository {
                policies: [policy(true), policy(true), policy(false), policy(true)].into(),
                controls: VecDeque::new(),
                reads: sender,
            },
            effects.clone(),
            true,
            shutdown,
            chrono::Utc::now(),
        );
        let mut run = Box::pin(coordinator.run(heartbeat, cancel.clone(), Duration::from_secs(5)));
        for (index, (island_mode, clear)) in
            [(true, true), (true, false), (false, false), (true, true)]
                .into_iter()
                .enumerate()
        {
            if index > 0 {
                tokio::time::advance(Duration::from_millis(500)).await;
                observe_control_read(run.as_mut(), &mut reads).await;
                assert!(effects.state.lock().unwrap().1.is_empty());
                tokio::time::advance(Duration::from_millis(500)).await;
            }
            observe_control_read(run.as_mut(), &mut reads).await;
            let mut expected = vec![
                PolicyEffect::Refresh(island_mode),
                PolicyEffect::Registration(island_mode),
            ];
            if clear {
                expected.push(PolicyEffect::Clear);
            }
            expected.push(PolicyEffect::Rules(
                vec!["blocked.example".to_owned()],
                vec!["allowed.example".to_owned()],
            ));
            assert_eq!(
                std::mem::take(&mut effects.state.lock().unwrap().1),
                expected
            );
        }
        drop(liveness);
        tokio::time::advance(Duration::from_millis(500)).await;
        run.await.unwrap();
        assert!(workers
            .shutdown_and_join(&cancel, Duration::from_secs(1))
            .await
            .is_clean());
    }

    #[tokio::test]
    async fn fired_generation_cancels_shutdown_once() {
        tokio::time::pause();
        let actions = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let _subscriber = tracing::subscriber::set_default(ControlActions(Arc::clone(&actions)));
        for fired_after_start in [true, false] {
            actions.store(0, std::sync::atomic::Ordering::SeqCst);
            let (workers, cancel, heartbeat) = test_heartbeat().await;
            let liveness = Arc::new(());
            let shutdown = CancellationToken::new();
            let installed = Arc::new(OnceLock::new());
            installed.set(shutdown.clone()).unwrap();
            let process_started_at = chrono::Utc::now();
            let fired_at = if fired_after_start {
                process_started_at + chrono::Duration::seconds(1)
            } else {
                process_started_at - chrono::Duration::seconds(1)
            };
            let control = DurableServiceControl {
                generation: uuid::Uuid::new_v4(),
                action: "restart".to_owned(),
                execute_at: fired_at - chrono::Duration::seconds(1),
                fired_at: Some(fired_at),
                expires_at: fired_at + chrono::Duration::minutes(5),
            };
            let (sender, mut reads) = tokio::sync::mpsc::unbounded_channel();
            let coordinator = RuntimeControlCoordinator::new(
                Arc::downgrade(&liveness),
                FakeRepository {
                    policies: VecDeque::new(),
                    controls: [Some(control.clone()), Some(control)].into(),
                    reads: sender,
                },
                FakeEffects::default(),
                true,
                installed,
                process_started_at,
            );
            let mut run =
                Box::pin(coordinator.run(heartbeat, cancel.clone(), Duration::from_secs(5)));
            observe_control_read(run.as_mut(), &mut reads).await;
            assert_eq!(shutdown.is_cancelled(), fired_after_start);
            assert_eq!(
                actions.load(std::sync::atomic::Ordering::SeqCst),
                usize::from(fired_after_start)
            );
            tokio::time::advance(Duration::from_millis(500)).await;
            observe_control_read(run.as_mut(), &mut reads).await;
            assert_eq!(shutdown.is_cancelled(), fired_after_start);
            assert_eq!(
                actions.load(std::sync::atomic::Ordering::SeqCst),
                usize::from(fired_after_start)
            );
            drop(liveness);
            tokio::time::advance(Duration::from_millis(500)).await;
            run.await.unwrap();
            assert!(workers
                .shutdown_and_join(&cancel, Duration::from_secs(1))
                .await
                .is_clean());
        }
    }

    #[tokio::test]
    async fn restarted_coordinator_fails_after_the_reserved_connection_was_taken() {
        tokio::time::pause();
        let (workers, cancel, heartbeat) = test_heartbeat().await;
        let liveness = Arc::new(());
        let (sender, mut reads) = tokio::sync::mpsc::unbounded_channel();
        let shutdown = Arc::new(OnceLock::new());
        shutdown.set(CancellationToken::new()).unwrap();
        let coordinator = RuntimeControlCoordinator::new(
            Arc::downgrade(&liveness),
            FakeRepository {
                policies: VecDeque::new(),
                controls: VecDeque::new(),
                reads: sender,
            },
            FakeEffects::default(),
            true,
            shutdown,
            chrono::Utc::now(),
        );
        let mut run =
            Box::pin(coordinator.run(heartbeat.clone(), cancel.clone(), Duration::from_secs(5)));
        observe_control_read(run.as_mut(), &mut reads).await;
        assert!(coordinator.connection.lock().await.is_none());
        drop(run);
        let error = coordinator
            .run(heartbeat, cancel.clone(), Duration::from_secs(5))
            .await
            .unwrap_err();
        assert_eq!(
            error.to_string(),
            "runtime-control coordinator was restarted after its reserved connection ended"
        );
        assert!(workers
            .shutdown_and_join(&cancel, Duration::from_secs(1))
            .await
            .is_clean());
    }

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

    #[tokio::test(start_paused = true)]
    async fn control_requires_installed_shutdown_and_matching_generation() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        let actions = Arc::new(AtomicUsize::new(0));
        let _subscriber = tracing::subscriber::set_default(ControlActions(Arc::clone(&actions)));
        let process_started_at = chrono::DateTime::from_timestamp(1_700_000_000, 0).unwrap();
        for (label, enabled, initially_installed, install_later) in [
            ("disabled control", false, true, false),
            ("missing shutdown", true, false, false),
            ("live shutdown installation", true, false, true),
            ("installed shutdown", true, true, false),
        ] {
            actions.store(0, Ordering::SeqCst);
            let (workers, cancel, heartbeat) = test_heartbeat().await;
            let liveness = Arc::new(());
            let shutdown = CancellationToken::new();
            let installed = Arc::new(OnceLock::new());
            if initially_installed {
                installed.set(shutdown.clone()).unwrap();
            }
            let command = |generation, fired_at| {
                Some(DurableServiceControl {
                    generation: uuid::Uuid::from_u128(generation),
                    action: "restart".to_owned(),
                    execute_at: process_started_at,
                    fired_at,
                    expires_at: process_started_at + chrono::Duration::minutes(5),
                })
            };
            let fired_at = process_started_at + chrono::Duration::seconds(1);
            let (sender, mut reads) = tokio::sync::mpsc::unbounded_channel();
            let coordinator = RuntimeControlCoordinator::new(
                Arc::downgrade(&liveness),
                FakeRepository {
                    policies: VecDeque::new(),
                    controls: [
                        command(1, None),
                        command(1, Some(process_started_at - chrono::Duration::seconds(1))),
                        command(1, Some(process_started_at)),
                        command(1, Some(fired_at)),
                        command(1, Some(fired_at)),
                        command(2, Some(fired_at)),
                    ]
                    .into(),
                    reads: sender,
                },
                FakeEffects::default(),
                enabled,
                Arc::clone(&installed),
                process_started_at,
            );
            let mut run =
                Box::pin(coordinator.run(heartbeat, cancel.clone(), Duration::from_secs(5)));
            if !initially_installed {
                for _ in 0..2 {
                    std::future::poll_fn(|cx| {
                        assert!(run.as_mut().poll(cx).is_pending(), "{label}");
                        std::task::Poll::Ready(())
                    })
                    .await;
                    assert!(
                        reads.try_recv().is_err(),
                        "{label}: read before installation"
                    );
                    assert!(!shutdown.is_cancelled(), "{label}");
                    assert_eq!(actions.load(Ordering::SeqCst), 0, "{label}");
                    tokio::time::advance(Duration::from_millis(500)).await;
                }
            }
            if install_later {
                installed.set(shutdown.clone()).unwrap();
            }
            let can_act = enabled && (initially_installed || install_later);
            for (step_label, expected_actions) in [
                ("unfired command", 0),
                ("fire predates process", 0),
                ("fire equals process start", 0),
                ("new fired generation", 1),
                ("repeated generation", 1),
                ("different fired generation", 2),
            ] {
                std::future::poll_fn(|cx| {
                    assert!(run.as_mut().poll(cx).is_pending(), "{label}");
                    std::task::Poll::Ready(())
                })
                .await;
                assert_eq!(reads.try_recv().is_ok(), can_act, "{label}: {step_label}");
                assert!(
                    reads.try_recv().is_err(),
                    "{label}: {step_label}: duplicate read"
                );
                let expected = if can_act { expected_actions } else { 0 };
                assert_eq!(
                    actions.load(Ordering::SeqCst),
                    expected,
                    "{label}: {step_label}"
                );
                assert_eq!(
                    shutdown.is_cancelled(),
                    expected > 0,
                    "{label}: {step_label}"
                );
                tokio::time::advance(Duration::from_millis(500)).await;
            }
            drop(liveness);
            run.await.unwrap();
            assert!(workers
                .shutdown_and_join(&cancel, Duration::from_secs(1))
                .await
                .is_clean());
        }
    }

    struct HealthRepository {
        policies: VecDeque<Result<RuntimePolicySnapshot>>,
        controls: VecDeque<Result<Option<DurableServiceControl>>>,
        calls: Arc<Mutex<Vec<&'static str>>>,
    }

    impl RuntimeControlRepository for HealthRepository {
        async fn policy_snapshot(
            &mut self,
            mut read_phase: impl FnMut(RuntimeControlReadPhase) + Send,
        ) -> Result<RuntimePolicySnapshot> {
            self.calls.lock().unwrap().push("snapshot");
            read_phase(RuntimeControlReadPhase::Snapshot);
            self.policies.pop_front().expect("unexpected snapshot read")
        }

        async fn service_control(&mut self) -> Result<Option<DurableServiceControl>> {
            self.calls.lock().unwrap().push("service control");
            self.controls.pop_front().expect("unexpected control read")
        }
    }

    #[tokio::test(start_paused = true)]
    async fn coordinator_health_preserves_idle_errors_and_recovers_only_after_reads() {
        for enabled in [false, true] {
            let label = if enabled {
                "service control reads"
            } else {
                "idle ticks"
            };
            let (workers, cancel, heartbeat) = test_heartbeat().await;
            let liveness = Arc::new(());
            let installed = Arc::new(OnceLock::new());
            installed.set(CancellationToken::new()).unwrap();
            let calls = Arc::new(Mutex::new(Vec::new()));
            let coordinator = RuntimeControlCoordinator::new(
                Arc::downgrade(&liveness),
                HealthRepository {
                    policies: [Err(anyhow::anyhow!("snapshot failed")), Ok(policy(false))].into(),
                    controls: [
                        Err(anyhow::anyhow!("control failed too")),
                        Ok(None),
                        Err(anyhow::anyhow!("control failed")),
                        Ok(None),
                    ]
                    .into(),
                    calls: Arc::clone(&calls),
                },
                FakeEffects::default(),
                enabled,
                installed,
                chrono::DateTime::from_timestamp(1_700_000_000, 0).unwrap(),
            );
            let mut run =
                Box::pin(coordinator.run(heartbeat, cancel.clone(), Duration::from_secs(5)));
            let expected_errors = if enabled {
                [
                    ("snapshot error wins", Some("snapshot failed")),
                    ("control read recovers", None),
                    (
                        "control error survives policy success",
                        Some("control failed"),
                    ),
                    ("control read restores health", None),
                ]
            } else {
                [
                    ("snapshot failure", Some("snapshot failed")),
                    ("idle retains failure", Some("snapshot failed")),
                    ("snapshot read recovers", None),
                    ("idle retains health", None),
                ]
            };
            for ((step_label, expected_error), snapshot_read) in
                expected_errors.into_iter().zip([true, false, true, false])
            {
                std::future::poll_fn(|cx| {
                    assert!(run.as_mut().poll(cx).is_pending(), "{label}");
                    std::task::Poll::Ready(())
                })
                .await;
                let mut expected_calls = Vec::new();
                if snapshot_read {
                    expected_calls.push("snapshot");
                }
                if enabled {
                    expected_calls.push("service control");
                }
                assert_eq!(
                    std::mem::take(&mut *calls.lock().unwrap()),
                    expected_calls,
                    "{label}: {step_label}"
                );
                assert_eq!(
                    workers
                        .observer_last_error_for_test("test-runtime-control-coordinator")
                        .as_deref(),
                    expected_error,
                    "{label}: {step_label}"
                );
                assert!(!cancel.is_cancelled(), "{label}: {step_label}");
                tokio::time::advance(Duration::from_millis(500)).await;
            }
            drop(liveness);
            run.await.unwrap();
            assert!(workers
                .shutdown_and_join(&cancel, Duration::from_secs(1))
                .await
                .is_clean());
        }
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
                        guard.database_read(
                            crate::runtime_control::RuntimeControlReadPhase::Snapshot,
                        );
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
            guard.database_read(crate::runtime_control::RuntimeControlReadPhase::Snapshot);
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
            guard.database_read(crate::runtime_control::RuntimeControlReadPhase::Snapshot);
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
            guard.database_read(crate::runtime_control::RuntimeControlReadPhase::Snapshot);
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
}
