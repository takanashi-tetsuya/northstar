use super::*;
use chrono::Utc;
use std::sync::atomic::Ordering;
use tokio::sync::mpsc;

#[tokio::test]
async fn elapsed_recovery_deadline_never_schedules_another_retry() {
    let (sender, _receiver) = mpsc::channel(1);
    let outbound = crate::outbound::OutboundSender::new(sender);
    let busy = ReplayBusyUntil {
        expires_at: Utc::now() + chrono::Duration::seconds(30),
        retry_after: Duration::from_secs(30),
    };
    let elapsed = tokio::time::Instant::now()
        .checked_sub(Duration::from_millis(1))
        .expect("a one-millisecond monotonic subtraction is representable");

    assert!(!wait_for_replay_retry(&busy, &outbound, None, elapsed).await);
}

#[tokio::test]
async fn already_invalid_availability_fence_cancels_without_waiting() {
    let (sender, _receiver) = mpsc::channel(1);
    let outbound = crate::outbound::OutboundSender::new(sender);
    let available = Arc::new(AtomicBool::new(true));
    let generation = Arc::new(AtomicU64::new(12));
    let availability = AvailabilityFence {
        available,
        generation,
        expected_generation: 11,
    };
    let busy = ReplayBusyUntil {
        expires_at: Utc::now() + chrono::Duration::seconds(30),
        retry_after: Duration::from_secs(30),
    };

    assert!(
        !wait_for_replay_retry(
            &busy,
            &outbound,
            Some(&availability),
            tokio::time::Instant::now() + Duration::from_secs(30),
        )
        .await
    );
}

#[tokio::test]
async fn availability_generation_change_cancels_busy_wait() {
    let (sender, _receiver) = mpsc::channel(1);
    let outbound = crate::outbound::OutboundSender::new(sender);
    let available = Arc::new(AtomicBool::new(true));
    let generation = Arc::new(AtomicU64::new(7));
    let availability = AvailabilityFence {
        available,
        generation: Arc::clone(&generation),
        expected_generation: 7,
    };
    let busy = ReplayBusyUntil {
        expires_at: Utc::now() + chrono::Duration::seconds(30),
        retry_after: Duration::from_secs(30),
    };

    let wait = wait_for_replay_retry(
        &busy,
        &outbound,
        Some(&availability),
        tokio::time::Instant::now() + Duration::from_secs(2),
    );
    let invalidate = async {
        tokio::time::sleep(Duration::from_millis(10)).await;
        generation.store(8, Ordering::Release);
    };
    let (result, ()) = tokio::time::timeout(Duration::from_secs(1), async {
        tokio::join!(wait, invalidate)
    })
    .await
    .expect("availability changes must cancel a busy replay wait promptly");

    assert!(!result);
}

#[tokio::test]
#[ignore = "requires an isolated TEST_DATABASE_URL PostgreSQL database"]
async fn busy_resource_lease_retries_without_second_availability_transition() {
    let url = std::env::var("TEST_DATABASE_URL")
        .expect("set TEST_DATABASE_URL to an isolated PostgreSQL database");
    let (service, recipient, full_jid, message_id) =
        ReplayService::busy_retry_test_fixture(&url).await.unwrap();
    let stale_session = match service.start(recipient, &full_jid, None).await.unwrap() {
        ReplayStartOutcome::Acquired(session) => session,
        ReplayStartOutcome::BusyUntil(_) => panic!("initial replay lease must be available"),
    };
    let (sender, _receiver) = mpsc::channel(1);
    let outbound = crate::outbound::OutboundSender::new(sender);
    let available = Arc::new(AtomicBool::new(true));
    let generation = Arc::new(AtomicU64::new(11));
    let availability = AvailabilityFence {
        available,
        generation,
        expected_generation: 11,
    };

    // The current resource starts while an unexpired lease from its previous
    // replay task still exists. Releasing that stale lease must wake the same
    // availability task; no second presence/generation transition is needed.
    let retrying = acquire_replay_session(
        &service,
        &outbound,
        recipient,
        &full_jid,
        None,
        Some(&availability),
        tokio::time::Instant::now() + Duration::from_secs(3),
    );
    let release_stale = async {
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert!(service.finish(&stale_session).await.unwrap());
    };
    let (session, ()) = tokio::time::timeout(Duration::from_secs(4), async {
        tokio::join!(retrying, release_stale)
    })
    .await
    .expect("busy replay must retry within its bounded recovery window");
    let session = session
        .unwrap()
        .expect("unchanged availability must acquire after stale lease release");

    let page = match service.claim_page(&session, None, false).await.unwrap() {
        ReplayPageOutcome::Claimed(page) => page,
        other => panic!("expected resource-affine replay page, got {other:?}"),
    };
    assert_eq!(
        page.messages
            .iter()
            .map(|message| message.id)
            .collect::<Vec<_>>(),
        vec![message_id]
    );
    service
        .release_unsent(
            &session,
            page.claim_token,
            &page
                .messages
                .iter()
                .map(|message| message.id)
                .collect::<Vec<_>>(),
        )
        .await
        .unwrap();
    assert!(service.finish(&session).await.unwrap());
    service.remove_test_recipient(recipient).await.unwrap();
}
