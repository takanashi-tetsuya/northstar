use super::enqueue_notice;
use northstar_roster_application::presence::ServiceMessageRoute;
use northstar_stream::local_routes::session::test_online_session;
use std::future::{poll_fn, Future};
use std::pin::pin;
use std::sync::Mutex;
use std::task::Poll;
use tokio::sync::oneshot;
use uuid::Uuid;

#[tokio::test]
async fn service_message_handoff_rejects_replaced_connection() {
    let route = ServiceMessageRoute {
        account_id: Uuid::new_v4(),
        auth_generation: 2,
        connection_id: Uuid::new_v4(),
        full_jid: "alice@example.test/Phone".to_owned(),
    };
    let (original, mut original_queue) = test_online_session(
        route.account_id,
        route.auth_generation,
        route.connection_id,
        "Phone",
        1,
    );
    let (replacement, mut replacement_queue) = test_online_session(
        route.account_id,
        route.auth_generation,
        Uuid::new_v4(),
        "Phone",
        1,
    );
    let published = Mutex::new(original.clone());
    let (allow, decision) = oneshot::channel();
    let mut handoff = pin!(enqueue_notice(
        &original.sender,
        "notice".to_owned(),
        &route,
        |jid| vec![(jid.to_owned(), published.lock().unwrap().clone())],
        async { Ok(decision.await.unwrap()) },
    ));
    poll_fn(|context| {
        assert!(handoff.as_mut().poll(context).is_pending());
        Poll::Ready(())
    })
    .await;
    assert!(original
        .sender
        .try_send("queue reserved".to_owned())
        .is_err());

    *published.lock().unwrap() = replacement;
    allow.send(true).unwrap();

    assert!(!handoff.await.unwrap());
    assert!(original_queue.try_recv().is_err());
    assert!(replacement_queue.try_recv().is_err());
    original
        .sender
        .try_send("slot released".to_owned())
        .unwrap();
    assert_eq!(original_queue.try_recv().unwrap().stanza, "slot released");
}
