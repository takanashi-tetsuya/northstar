use super::*;

struct ChildDrop {
    index: usize,
    events: Arc<std::sync::Mutex<Vec<usize>>>,
}

impl Drop for ChildDrop {
    fn drop(&mut self) {
        self.events.lock().unwrap().push(self.index);
    }
}

#[tokio::test(start_paused = true)]
async fn shutdown_drains_every_bounded_child_before_finalization() {
    for label in ["running children", "pending children", "abort before drain"] {
        let metrics = northstar_telemetry::metrics::Metrics::default();
        let telemetry = PostActionTelemetry::new(
            &metrics.post_action_tasks_started_total,
            &metrics.post_action_tasks_completed_total,
            &metrics.post_action_tasks_panicked_total,
            &metrics.post_action_tasks_aborted_total,
            &metrics.post_action_capacity_rejections_total,
        );
        let handle = PostActionHandle::default();
        let events = Arc::new(std::sync::Mutex::new(Vec::new()));
        let (started, mut starts) = tokio::sync::mpsc::unbounded_channel();
        assert_eq!(MAX_POST_ACTION_TASKS_PER_SESSION, 16);
        for index in 0..16 {
            let child = ChildDrop {
                index,
                events: Arc::clone(&events),
            };
            let started = started.clone();
            handle
                .defer(
                    "controlled child",
                    async move {
                        let _child = child;
                        started.send(index).unwrap();
                        std::future::pending::<()>().await;
                    },
                    &telemetry,
                )
                .unwrap();
        }
        drop(started);
        let error = handle
            .defer("over capacity", async {}, &telemetry)
            .unwrap_err();
        assert_eq!(
            error.to_string(),
            "per-session post-action task capacity was exhausted",
            "{label}"
        );
        assert!(events.lock().unwrap().is_empty(), "{label}");
        if label != "pending children" {
            handle.start(&telemetry);
            tokio::time::timeout(std::time::Duration::from_secs(1), async {
                for _ in 0..16 {
                    starts
                        .recv()
                        .await
                        .expect("child must start before shutdown");
                }
            })
            .await
            .expect("all controlled children must start");
            assert_eq!(
                metrics
                    .post_action_tasks_started_total
                    .load(Ordering::Relaxed),
                16,
                "{label}"
            );
            let error = handle
                .defer("running capacity", async {}, &telemetry)
                .unwrap_err();
            assert_eq!(
                error.to_string(),
                "per-session post-action task capacity was exhausted",
                "{label}"
            );
        }
        if label == "abort before drain" {
            handle.abort_now(&telemetry);
        }
        let mut supervisor = handle.take_for_shutdown();
        assert!(
            handle
                .defer("after shutdown", async {}, &telemetry)
                .is_err(),
            "{label}"
        );
        supervisor.abort_and_drain(&telemetry).await;

        // This marker is the caller's finalization boundary, reached only
        // after the real supervisor has returned all child ownership.
        let mut recorded = events.lock().unwrap();
        recorded.sort_unstable();
        assert_eq!(
            *recorded,
            (0..16).collect::<Vec<_>>(),
            "{label}: child survived drain"
        );
        recorded.push(16);
        assert!(supervisor.running.is_empty(), "{label}");
        assert!(supervisor.pending.is_empty(), "{label}");
        assert_eq!(
            metrics
                .post_action_tasks_completed_total
                .load(Ordering::Relaxed),
            0,
            "{label}"
        );
        assert_eq!(
            metrics
                .post_action_tasks_panicked_total
                .load(Ordering::Relaxed),
            0,
            "{label}"
        );
        assert_eq!(
            metrics
                .post_action_capacity_rejections_total
                .load(Ordering::Relaxed),
            if label == "pending children" { 1 } else { 2 },
            "{label}"
        );
        assert!(
            metrics
                .post_action_tasks_aborted_total
                .load(Ordering::Relaxed)
                >= 16,
            "{label}"
        );
    }
}

#[tokio::test]
async fn post_transport_resume_publication_cannot_run_while_replay_is_pending() {
    let metrics = northstar_telemetry::metrics::Metrics::default();
    let telemetry = PostActionTelemetry::new(
        &metrics.post_action_tasks_started_total,
        &metrics.post_action_tasks_completed_total,
        &metrics.post_action_tasks_panicked_total,
        &metrics.post_action_tasks_aborted_total,
        &metrics.post_action_capacity_rejections_total,
    );
    let published = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let task_published = std::sync::Arc::clone(&published);
    let mut supervisor = PostActionSupervisor::default();
    supervisor
        .defer(
            "resume-route-publication",
            async move {
                task_published.store(true, std::sync::atomic::Ordering::Release);
            },
            &telemetry,
        )
        .unwrap();

    tokio::task::yield_now().await;
    assert!(!published.load(std::sync::atomic::Ordering::Acquire));
    supervisor.start(&telemetry);
    assert_eq!(
        metrics
            .post_action_tasks_started_total
            .load(std::sync::atomic::Ordering::Relaxed),
        1
    );
    tokio::time::timeout(std::time::Duration::from_secs(1), async {
        while !published.load(std::sync::atomic::Ordering::Acquire) {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    supervisor.reap(&telemetry);
}

#[tokio::test]
async fn external_recovery_task_waits_for_current_transport_action() {
    let metrics = northstar_telemetry::metrics::Metrics::default();
    let telemetry = PostActionTelemetry::new(
        &metrics.post_action_tasks_started_total,
        &metrics.post_action_tasks_completed_total,
        &metrics.post_action_tasks_panicked_total,
        &metrics.post_action_tasks_aborted_total,
        &metrics.post_action_capacity_rejections_total,
    );
    let handle = PostActionHandle::default();
    handle.begin_action();
    let (published, receiver) = tokio::sync::oneshot::channel();
    handle
        .defer_recovery(
            "recovered-offline-test",
            async move {
                let _ = published.send(());
            },
            &telemetry,
        )
        .unwrap();
    tokio::task::yield_now().await;
    assert_eq!(
        metrics
            .post_action_tasks_started_total
            .load(std::sync::atomic::Ordering::Acquire),
        0
    );
    handle.start(&telemetry);
    tokio::time::timeout(std::time::Duration::from_secs(1), receiver)
        .await
        .expect("recovery task should start after transport")
        .expect("task should publish after transport");
    assert_eq!(
        metrics
            .post_action_tasks_started_total
            .load(std::sync::atomic::Ordering::Acquire),
        1
    );
}
