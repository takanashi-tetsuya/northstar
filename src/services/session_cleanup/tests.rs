use super::{
    finish_live_session_release, run_cleanup_step, CleanupRecovery, CleanupReport,
    SessionCleanupAccount, SmSuspensionRecoveryQueue, SuspensionRecoveryWork,
};
use std::sync::Arc;
use uuid::Uuid;

fn cleanup_observer() -> Arc<crate::platform::workers::WorkerRegistry> {
    let registry = crate::platform::workers::WorkerRegistry::new();
    registry.register_observer(
        "session-cleanup",
        crate::platform::workers::WorkerCriticality::Restartable,
    );
    registry
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
    let pool = sqlx::postgres::PgPoolOptions::new()
        .connect_lazy("postgresql://localhost/unused_cleanup_test")
        .unwrap();
    pool.close().await;
    let registry = cleanup_observer();
    for _ in 0..3 {
        registry.observer_error("session-cleanup", "existing real cleanup debt");
    }
    // A closed pool would reject every real acquire. The same lazy
    // release boundary used by finish must leave it entirely untouched.
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
                    crate::db::release_live_session(&pool, Uuid::new_v4()).await
                },
                &mut report,
            )
            .await;
        })
        .await;
        assert!(!polled.get());
        assert!(report.is_clean());
        assert_eq!(report.completed_steps, 0);
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
                crate::db::release_live_session(&pool, Uuid::new_v4()).await
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
        "a real database failure must remain observable"
    );
    assert_eq!(owned.failures[0].operation, "release-live-session");
    assert_eq!(owned.completed_steps, 0);
}

fn queue() -> Arc<SmSuspensionRecoveryQueue> {
    let metrics = Arc::new(crate::services::sm_capacity::SmCapacityMetrics::default());
    let governor = crate::services::sm_capacity::SmMemoryGovernor::new(
        1024 * 1024,
        512 * 1024,
        16,
        256 * 1024,
        Arc::clone(&metrics),
    )
    .unwrap();
    SmSuspensionRecoveryQueue::new(16, 512 * 1024, metrics, governor)
}

fn capacity(
    queue: &SmSuspensionRecoveryQueue,
    snapshot: &crate::services::sm::SmSessionSnapshot,
) -> crate::services::sm_capacity::SmCapacityLease {
    queue
        .governor
        .try_reserve_live(snapshot.resident_bytes().unwrap())
        .unwrap()
}

fn snapshot() -> crate::services::sm::SmSessionSnapshot {
    crate::services::sm::SmSessionSnapshot {
        inbound_h: 0,
        outbound_h: 1,
        acked_h: 0,
        available: true,
        carbons: false,
        priority: 0,
        blocklist_requested: false,
        roster_requested: false,
        active_privacy_list: None,
        privacy_requested: false,
        peer_ip: std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
        user_agent_id: None,
        joined_rooms: Vec::new(),
        directed_presence: Vec::new(),
        last_presence: None,
        unacked: vec![crate::xmpp::outbound::SmUnackedStanza::plain(
            "ordered".to_owned(),
        )],
    }
}

#[test]
fn exact_suspension_retry_cannot_be_downgraded_to_promotion_only() {
    let queue = queue();
    let session_id = Uuid::new_v4();
    let connection_id = Uuid::new_v4();
    let endpoint = Arc::new(crate::state::SuspendedMucEndpoint::new(session_id));
    let exact = snapshot();
    assert!(queue.enqueue(
        SessionCleanupAccount {
            user_id: Uuid::new_v4(),
            username: "alice".to_owned(),
            auth_generation: 7,
        },
        connection_id,
        session_id,
        exact.clone(),
        300,
        vec![Arc::clone(&endpoint)],
        capacity(&queue, &exact),
    ));
    assert!(!queue.enqueue_promote(
        connection_id,
        session_id,
        vec![endpoint],
        queue.governor.try_reserve_live(256).unwrap(),
    ));
    let job = queue.take().expect("one exact epoch remains queued");
    assert!(matches!(&job.work, SuspensionRecoveryWork::Suspend(_)));
    job.complete();
    assert!(queue.take().is_none());
}

#[test]
fn retry_moves_to_tail_and_in_flight_epoch_rejects_a_second_owner() {
    let queue = queue();
    let first_session = Uuid::new_v4();
    let second_session = Uuid::new_v4();
    let first_connection = Uuid::new_v4();
    let second_connection = Uuid::new_v4();
    let first = snapshot();
    let second = snapshot();
    assert!(queue.enqueue(
        SessionCleanupAccount {
            user_id: Uuid::new_v4(),
            username: "alice".to_owned(),
            auth_generation: 1,
        },
        first_connection,
        first_session,
        first.clone(),
        300,
        Vec::new(),
        capacity(&queue, &first),
    ));
    assert!(queue.enqueue(
        SessionCleanupAccount {
            user_id: Uuid::new_v4(),
            username: "bob".to_owned(),
            auth_generation: 1,
        },
        second_connection,
        second_session,
        second.clone(),
        300,
        Vec::new(),
        capacity(&queue, &second),
    ));
    let first_job = queue.take().unwrap();
    assert_eq!(first_job.session_id, first_session);
    assert!(!queue.enqueue_promote(
        first_connection,
        first_session,
        Vec::new(),
        queue.governor.try_reserve_live(256).unwrap(),
    ));
    first_job.retry_later();
    let second_job = queue.take().unwrap();
    assert_eq!(second_job.session_id, second_session);
    second_job.complete();
    let retried = queue.take().unwrap();
    assert_eq!(retried.session_id, first_session);
    retried.complete();
}

#[test]
fn cancelled_or_panicking_worker_returns_exact_job_to_queue() {
    let queue = queue();
    let session_id = Uuid::new_v4();
    let connection_id = Uuid::new_v4();
    let exact = snapshot();
    assert!(queue.enqueue(
        SessionCleanupAccount {
            user_id: Uuid::new_v4(),
            username: "alice".to_owned(),
            auth_generation: 1,
        },
        connection_id,
        session_id,
        exact.clone(),
        300,
        Vec::new(),
        capacity(&queue, &exact),
    ));
    let in_flight = queue.take().unwrap();
    drop(in_flight);
    let recovered = queue.take().expect("RAII drop must restore exact work");
    assert_eq!(recovered.session_id, session_id);
    assert!(matches!(
        &recovered.work,
        SuspensionRecoveryWork::Suspend(_)
    ));
    recovered.complete();
}
