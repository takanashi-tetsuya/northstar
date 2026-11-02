use super::*;

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
