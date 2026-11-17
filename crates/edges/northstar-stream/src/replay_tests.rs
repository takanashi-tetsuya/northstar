use super::*;
use chrono::Utc;
use northstar_session_postgres::replay_repository::ReplayServiceTestFixture;
use std::sync::atomic::Ordering;
use tokio::sync::mpsc;

#[test]
fn recovery_account_lock_is_shorter_than_revocation_budget() {
    assert!(RECOVERY_AUTHORITY_HOLD_TIMEOUT <= Duration::from_secs(1));
}

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
        current_route: None,
        recovery_authority: None,
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
        current_route: None,
        recovery_authority: None,
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
        current_route: None,
        recovery_authority: None,
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

#[derive(Default)]
struct ReplayCalls {
    busy_remaining: usize,
    acquisitions: Vec<tokio::time::Instant>,
    page_claims: usize,
    releases: usize,
}

#[derive(Clone)]
struct ReplayRepositoryFake(Arc<std::sync::Mutex<ReplayCalls>>);

impl northstar_session_application::replay::ReplayLeaseRepository for ReplayRepositoryFake {
    async fn username(&self, recipient: Uuid) -> Result<Option<String>> {
        assert_eq!(recipient, Uuid::from_u128(901));
        Ok(Some("alice".to_owned()))
    }

    async fn acquire_lease(
        &self,
        recipient_id: Uuid,
        resource: &str,
        owner_token: Uuid,
        cutoff: Option<chrono::DateTime<Utc>>,
        lease_seconds: i64,
    ) -> Result<northstar_session_application::replay::OfflineReplayLeaseAcquire> {
        use northstar_session_application::replay::{
            OfflineReplayBusyUntil, OfflineReplayLease, OfflineReplayLeaseAcquire,
        };
        assert_eq!(recipient_id, Uuid::from_u128(901));
        assert_eq!(resource, "Phone");
        assert!(!owner_token.is_nil());
        assert_eq!(cutoff, None);
        assert_eq!(lease_seconds, 90);
        let mut calls = self.0.lock().unwrap();
        calls.acquisitions.push(tokio::time::Instant::now());
        if calls.busy_remaining > 0 {
            calls.busy_remaining -= 1;
            Ok(OfflineReplayLeaseAcquire::BusyUntil(
                OfflineReplayBusyUntil {
                    expires_at: chrono::DateTime::from_timestamp(1_700_000_000, 0).unwrap(),
                    retry_after: Duration::from_secs(30),
                },
            ))
        } else {
            Ok(OfflineReplayLeaseAcquire::Acquired(OfflineReplayLease {
                recipient_id,
                resource: resource.to_owned(),
                owner_token,
                replay_started_at: chrono::DateTime::from_timestamp(1_700_000_000, 0).unwrap(),
            }))
        }
    }
}

impl ReplayRepository for ReplayRepositoryFake {
    async fn claim_page(
        &self,
        session: &ReplaySession,
        privacy: Option<&str>,
        bind2: bool,
        ttl: i64,
    ) -> Result<ReplayPageOutcome> {
        assert_eq!(session.recipient_id(), Uuid::from_u128(901));
        assert_eq!(session.owner_full_jid(), "alice@example.test/Phone");
        assert_eq!(privacy, None);
        assert!(bind2);
        assert_eq!(ttl, 30);
        self.0.lock().unwrap().page_claims += 1;
        Ok(ReplayPageOutcome::Empty)
    }
    async fn finish(&self, session: &ReplaySession) -> Result<bool> {
        assert_eq!(session.recipient_id(), Uuid::from_u128(901));
        assert_eq!(session.lease().resource, "Phone");
        self.0.lock().unwrap().releases += 1;
        Ok(true)
    }
    async fn renew_before_send(&self, _: &ReplaySession, _: Uuid, _: &[Uuid]) -> Result<bool> {
        panic!("empty replay must not renew a page")
    }
    async fn release_unsent(&self, _: &ReplaySession, _: Uuid, _: &[Uuid]) -> Result<u64> {
        panic!("empty replay must not release a suffix")
    }
    async fn pending_presence_page(
        &self,
        _: Uuid,
        _: &str,
        _: Option<&str>,
        _: Option<&northstar_session_application::replay::PendingPresenceCursor>,
        _: &str,
    ) -> Result<northstar_session_application::replay::PendingPresencePage> {
        panic!("Bind 2 offline replay must not replay pending presence")
    }
    async fn fence_socket_write(
        &self,
        _: northstar_delivery_core::DurableDelivery,
    ) -> Result<northstar_delivery_core::DurableDelivery> {
        panic!("empty replay must not fence a socket write")
    }
    async fn acknowledge_socket_write(
        &self,
        _: northstar_delivery_core::DurableDelivery,
        _: Option<&northstar_delivery_core::native_write::AckRequest>,
    ) -> Result<()> {
        panic!("empty replay must not acknowledge a socket write")
    }
    async fn renew_bosh_fences(
        &self,
        _: &northstar_delivery_core::bosh_ownership::response::RenewRequest,
    ) -> Result<()> {
        panic!("offline replay must not renew a BOSH response")
    }
    async fn acknowledge_bosh_responses(
        &self,
        _: &northstar_delivery_core::bosh_ownership::response::AckRequest,
    ) -> Result<()> {
        panic!("offline replay must not acknowledge a BOSH response")
    }
    async fn bind_bosh_response_sources(
        &self,
        _: &northstar_delivery_core::bosh_ownership::response::BindRequest,
    ) -> Result<northstar_delivery_core::bosh_ownership::BoshResponseOwnership> {
        panic!("offline replay must not bind a BOSH response")
    }
    async fn release_bosh_fences(&self, _: Uuid) -> Result<()> {
        panic!("offline replay must not release BOSH fences")
    }
}

#[tokio::test(start_paused = true)]
async fn replay_busy_deadline_is_absolute_across_retries_and_success_can_precede_it() {
    for (label, busy_remaining) in [
        ("expires while busy", usize::MAX),
        ("acquired before deadline", 2),
    ] {
        let calls = Arc::new(std::sync::Mutex::new(ReplayCalls {
            busy_remaining,
            ..ReplayCalls::default()
        }));
        let service =
            ReplayService::new(ReplayRepositoryFake(Arc::clone(&calls)), "example.test", 30);
        let (sender, _receiver) = mpsc::channel(1);
        let outbound = crate::outbound::OutboundSender::new(sender);
        let start = tokio::time::Instant::now();
        let mut acquiring = Box::pin(acquire_replay_session(
            &service,
            &outbound,
            Uuid::from_u128(901),
            "alice@example.test/Phone",
            None,
            None,
            start + Duration::from_secs(2),
        ));
        assert!(futures::poll!(&mut acquiring).is_pending(), "{label}");
        for step in 1..=4 {
            tokio::time::advance(Duration::from_millis(500)).await;
            let result = futures::poll!(&mut acquiring);
            if label == "acquired before deadline" && step == 2 {
                let std::task::Poll::Ready(Ok(Some(session))) = result else {
                    panic!("{label}: busy retry did not return the acquired lease");
                };
                assert_eq!(session.recipient_id(), Uuid::from_u128(901));
                assert_eq!(session.owner_full_jid(), "alice@example.test/Phone");
                break;
            }
            if step == 4 {
                assert!(
                    matches!(result, std::task::Poll::Ready(Ok(None))),
                    "{label}: deadline was reset"
                );
            } else {
                assert!(result.is_pending(), "{label}");
            }
        }
        drop(acquiring);
        let recorded = calls.lock().unwrap();
        let expected_calls = if busy_remaining == 2 { 3 } else { 4 };
        assert_eq!(recorded.acquisitions.len(), expected_calls, "{label}");
        for (ordinal, at) in recorded.acquisitions.iter().enumerate() {
            assert_eq!(
                *at,
                start + Duration::from_millis(500 * ordinal as u64),
                "{label}"
            );
            assert!(
                *at < start + Duration::from_secs(2),
                "{label}: claim after deadline"
            );
        }
        assert_eq!(recorded.page_claims, 0, "{label}");
    }
}

#[tokio::test(start_paused = true)]
async fn bind2_busy_recovery_retries_then_claims_and_releases_the_same_resource() {
    for (label, busy_remaining) in [
        ("eventual acquisition", 2),
        ("bounded busy recovery", usize::MAX),
    ] {
        let calls = Arc::new(std::sync::Mutex::new(ReplayCalls {
            busy_remaining,
            ..ReplayCalls::default()
        }));
        let service =
            ReplayService::new(ReplayRepositoryFake(Arc::clone(&calls)), "example.test", 30);
        let (sender, mut receiver) = mpsc::channel(1);
        let outbound = crate::outbound::OutboundSender::new(sender);
        let start = tokio::time::Instant::now();
        let mut replay = Box::pin(replay_bind2_offline(
            service,
            outbound,
            Uuid::from_u128(901),
            "alice@example.test/Phone".to_owned(),
        ));
        assert!(futures::poll!(&mut replay).is_pending(), "{label}");
        tokio::time::advance(Duration::from_millis(500)).await;
        assert!(futures::poll!(&mut replay).is_pending(), "{label}");
        tokio::time::advance(Duration::from_millis(500)).await;
        if busy_remaining == 2 {
            assert!(futures::poll!(&mut replay).is_ready(), "{label}");
        } else {
            assert!(futures::poll!(&mut replay).is_pending(), "{label}");
            // The 120-second recovery budget reserves two seconds for cleanup.
            tokio::time::advance(Duration::from_secs(117)).await;
            assert!(
                futures::poll!(&mut replay).is_ready(),
                "{label}: original work deadline was reset"
            );
        }
        drop(replay);
        let recorded = calls.lock().unwrap();
        assert_eq!(recorded.acquisitions.len(), 3, "{label}");
        assert!(
            recorded
                .acquisitions
                .iter()
                .all(|at| *at < start + Duration::from_secs(118)),
            "{label}"
        );
        assert_eq!(
            recorded.page_claims,
            usize::from(busy_remaining == 2),
            "{label}"
        );
        assert_eq!(
            recorded.releases,
            usize::from(busy_remaining == 2),
            "{label}"
        );
        assert!(
            receiver.try_recv().is_err(),
            "{label}: empty replay emitted bytes"
        );
    }
}
