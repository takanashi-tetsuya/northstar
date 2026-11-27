use super::*;
use crate::local_routes::{
    pending_subscription::{deliver_pending_subscription, PendingSubscriptionKey},
    session::{test_online_session, OnlineSession},
};
use crate::outbound::OutboundItem;
use northstar_session_application::replay::{
    pending_presence::PendingPresenceRepository, PendingPresenceCursor, PendingPresencePage,
    PendingPresenceReplay,
};
use std::{future::Future, sync::Mutex, task::Poll};

impl PendingPresenceRepository for ReplayRepositoryFake {
    async fn pending_presence_page(
        &self,
        _: PendingPresenceAuthority<'_>,
        _: Option<&PendingPresenceCursor>,
        _: &str,
    ) -> Result<PendingPresencePage> {
        panic!("unexpected pending presence page")
    }

    async fn pending_presence_is_current(
        &self,
        _: PendingPresenceAuthority<'_>,
        _: &PendingPresenceReplay,
        _: &str,
    ) -> Result<bool> {
        self.0.lock().unwrap().pending_rechecks += 1;
        Ok(true)
    }
}

fn pending_request() -> PendingPresenceReplay {
    PendingPresenceReplay {
        requester: "bob@example.test".to_owned(),
        requester_auth_generation: Some(0),
        stanza: None,
        cursor: PendingPresenceCursor {
            created_at: Utc::now(),
            source: 0,
            key: Uuid::from_u128(17).to_string(),
        },
    }
}

fn resource(
    name: &str,
    current: Arc<Mutex<Uuid>>,
) -> (
    OnlineSession,
    ReplayTarget,
    AvailabilityFence,
    mpsc::Receiver<OutboundItem>,
) {
    let route = replay_route(Uuid::from_u128(901), &format!("alice@example.test/{name}"));
    let (session, receiver) =
        test_online_session(route.recipient_id, 0, route.connection_id, name, 1);
    session.available.store(true, Ordering::Release);
    session.availability_generation.store(1, Ordering::Release);
    let availability = AvailabilityFence {
        available: session.available.clone(),
        generation: session.availability_generation.clone(),
        expected_generation: 1,
    };
    let connection = route.connection_id;
    *current.lock().unwrap() = connection;
    let mut target = ReplayTarget::new(
        route,
        Arc::default(),
        Arc::new(move || *current.lock().unwrap() == connection),
    );
    target.pending_route = Some(session.clone());
    (session, target, availability, receiver)
}

#[tokio::test]
async fn saturated_pending_handoff_rejects_a_replaced_connection() {
    let current = Arc::new(Mutex::new(Uuid::nil()));
    let (session, target, availability, mut receiver) = resource("Phone", current.clone());
    session.sender.try_send("queued".to_owned()).unwrap();
    let repository = ReplayRepositoryFake(Arc::default());
    let service = ReplayService::new(repository.clone(), "example.test", 30);
    let pending = pending_request();
    let mut replay = std::pin::pin!(handoff_pending(
        &service,
        &session.sender,
        &target,
        &availability,
        &None,
        &pending,
        "subscribe".to_owned(),
    ));
    std::future::poll_fn(|cx| {
        assert!(replay.as_mut().poll(cx).is_pending());
        Poll::Ready(())
    })
    .await;
    assert_eq!(repository.0.lock().unwrap().pending_rechecks, 0);
    let (_replacement, _, _, mut replacement_receiver) = resource("Phone", current);
    assert_eq!(receiver.try_recv().unwrap().stanza, "queued");
    replay.await.unwrap();
    assert_eq!(repository.0.lock().unwrap().pending_rechecks, 0);
    assert_eq!(
        receiver.try_recv().unwrap_err(),
        mpsc::error::TryRecvError::Empty
    );
    assert_eq!(
        replacement_receiver.try_recv().unwrap_err(),
        mpsc::error::TryRecvError::Empty,
    );
}

#[tokio::test]
async fn live_then_replay_delivers_each_request_once_per_resource_epoch() {
    let (phone, phone_target, phone_epoch, mut phone_queue) = resource("Phone", Arc::default());
    let (desk, desk_target, desk_epoch, mut desk_queue) = resource("Desk", Arc::default());
    let pending = pending_request();
    let service = ReplayService::new(ReplayRepositoryFake(Arc::default()), "example.test", 30);
    let key = PendingSubscriptionKey::local(
        Uuid::from_u128(17),
        pending.cursor.created_at.timestamp_micros(),
    );
    assert!(deliver_pending_subscription(&phone, 1, key.clone(), || {
        phone.sender.try_send("live".to_owned()).is_ok()
    }));
    assert_eq!(phone_queue.try_recv().unwrap().stanza, "live");
    handoff_pending(
        &service,
        &phone.sender,
        &phone_target,
        &phone_epoch,
        &None,
        &pending,
        "replay".to_owned(),
    )
    .await
    .unwrap();
    assert!(phone_queue.try_recv().is_err());

    handoff_pending(
        &service,
        &desk.sender,
        &desk_target,
        &desk_epoch,
        &None,
        &pending,
        "replay".to_owned(),
    )
    .await
    .unwrap();
    assert_eq!(desk_queue.try_recv().unwrap().stanza, "replay");
    assert!(!deliver_pending_subscription(&desk, 1, key.clone(), || {
        panic!("replay already delivered this request")
    }));
    assert!(desk_queue.try_recv().is_err());

    let replacement = PendingSubscriptionKey::local(
        Uuid::from_u128(17),
        pending.cursor.created_at.timestamp_micros() + 1,
    );
    assert!(deliver_pending_subscription(&phone, 1, replacement, || {
        phone.sender.try_send("new request".to_owned()).is_ok()
    }));
    assert_eq!(phone_queue.try_recv().unwrap().stanza, "new request");

    phone.availability_generation.store(3, Ordering::Release);
    assert!(deliver_pending_subscription(&phone, 3, key, || {
        phone.sender.try_send("new epoch".to_owned()).is_ok()
    }));
    assert_eq!(phone_queue.try_recv().unwrap().stanza, "new epoch");
}
