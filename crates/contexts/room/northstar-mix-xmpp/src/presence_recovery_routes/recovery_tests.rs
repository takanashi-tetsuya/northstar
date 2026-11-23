use super::*;
use northstar_stream::local_routes::session::test_online_session;

#[tokio::test]
async fn recovery_rechecks_account_after_the_route_gate() {
    let source = RecoveryPresenceSource::parse("alice@example.test/fixture").unwrap();
    let channel = MixChannelAddress::parse("room@mix.example.test").unwrap();
    let account = Uuid::new_v4();
    let connection = Uuid::new_v4();
    let sessions = Arc::new(DashMap::new());
    let (mut session, _receiver) = test_online_session(account, 1, connection, "fixture", 1);
    session.routable.store(true, Ordering::Release);
    session.available.store(true, Ordering::Release);
    let gate = Arc::clone(&session.mix_presence_gate);
    let routes = MixPresenceRecoveryRoutes::new(Arc::clone(&sessions));
    let key = source.full().to_string();
    sessions.insert(key.clone(), session.clone());
    assert_eq!(
        routes.recovery_epoch_state(&source, account, connection, 0, &gate, &channel),
        Some((true, false))
    );

    let held = Arc::clone(&gate).lock_owned().await;
    let (waiting_tx, waiting_rx) = tokio::sync::oneshot::channel();
    let task = tokio::spawn(async move {
        waiting_tx.send(()).unwrap();
        let _held = Arc::clone(&gate).lock_owned().await;
        routes.recovery_epoch_state(&source, account, connection, 0, &gate, &channel)
    });
    waiting_rx.await.unwrap();
    session.user_id = Uuid::new_v4();
    sessions.insert(key, session);
    drop(held);
    assert_eq!(task.await.unwrap(), Some((false, false)));
}
