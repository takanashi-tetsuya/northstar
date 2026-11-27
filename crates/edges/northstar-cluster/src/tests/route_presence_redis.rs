use crate::{ClusterManager, ClusterSessionRouteOwner, ClusterSessionStore, SESSION_TTL_SECONDS};
use northstar_security::cluster_bus::SignedClusterEnvelope;
use northstar_security::cluster_keys::ClusterNodeInstance;
use northstar_session_application::cluster_session_store::ClusterStoreFuture;
use northstar_session_application::session_termination_authority::SessionRouteAuthority;
use northstar_session_core::SessionRouteClaimProof;
use redis::AsyncCommands;
use std::{collections::BTreeMap, sync::Arc, time::Duration};
use uuid::Uuid;

const BARE: &str = "alice@example.test";
const FULL: &str = "alice@example.test/Home";

#[derive(Default)]
struct RouteAuthority(BTreeMap<String, SessionRouteAuthority>);

impl ClusterSessionStore for RouteAuthority {
    fn claim_node_instance<'a>(
        &'a self,
        _: &'a str,
        _: &'a str,
        _: Uuid,
        _: &'a str,
        _: i64,
        _: Duration,
    ) -> ClusterStoreFuture<'a, ClusterNodeInstance> {
        unreachable!()
    }

    fn admit_envelope_replay<'a>(
        &'a self,
        _: &'a str,
        _: &'a SignedClusterEnvelope,
    ) -> ClusterStoreFuture<'a, bool> {
        unreachable!()
    }

    fn is_replay_validation_rejection(&self, _: &anyhow::Error) -> bool {
        unreachable!()
    }

    fn claim_session_route<'a>(
        &'a self,
        _: ClusterSessionRouteOwner<'a>,
        _: &'a str,
        _: SessionRouteClaimProof,
        _: Duration,
    ) -> ClusterStoreFuture<'a, bool> {
        Box::pin(async { Ok(true) })
    }

    fn refresh_session_route<'a>(
        &'a self,
        _: ClusterSessionRouteOwner<'a>,
        _: Duration,
    ) -> ClusterStoreFuture<'a, bool> {
        unreachable!()
    }

    fn release_session_route<'a>(
        &'a self,
        _: ClusterSessionRouteOwner<'a>,
    ) -> ClusterStoreFuture<'a, bool> {
        Box::pin(async { Ok(true) })
    }

    fn session_route_authority<'a>(
        &'a self,
        _: &'a str,
        full_jid: &'a str,
    ) -> ClusterStoreFuture<'a, Option<SessionRouteAuthority>> {
        Box::pin(async move { Ok(self.0.get(full_jid).cloned()) })
    }

    fn session_nodes_for_bare<'a>(
        &'a self,
        _: &'a str,
        _: &'a str,
    ) -> ClusterStoreFuture<'a, Vec<String>> {
        unreachable!()
    }
}

async fn managers() -> (ClusterManager, ClusterManager) {
    let redis_url =
        std::env::var("TEST_REDIS_URL").expect("set TEST_REDIS_URL to a disposable Redis instance");
    let namespace = format!("presence-{}.test", Uuid::new_v4().simple());
    let (owner_security, peer_security) =
        northstar_security::cluster_bus::test_configuration_pair(&namespace);
    let owner = ClusterManager::new(
        Some(&redis_url),
        &namespace,
        None,
        None,
        None,
        Some(owner_security),
    )
    .await
    .unwrap();
    let peer = ClusterManager::new(
        Some(&redis_url),
        &namespace,
        None,
        None,
        None,
        Some(peer_security),
    )
    .await
    .unwrap();
    for manager in [&owner, &peer] {
        manager.install_instance_epoch(1).unwrap();
        manager.note_listener_generation();
    }
    (owner, peer)
}

async fn cleanup(manager: &ClusterManager) {
    let mut conn = manager.pool.as_ref().unwrap().get().await.unwrap();
    let keys: Vec<String> = redis::cmd("KEYS")
        .arg(format!("{}:*", manager.key_prefix))
        .query_async(&mut *conn)
        .await
        .unwrap();
    if !keys.is_empty() {
        let _: usize = conn.del(keys).await.unwrap();
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires TEST_REDIS_URL; uses and removes a unique key namespace"]
async fn redis_message_route_presence_rejects_wrong_owner_instance_and_nonadvancing_sequence() {
    let (owner, peer) = managers().await;
    owner
        .configure_session_store(Arc::new(RouteAuthority::default()))
        .unwrap();
    let connection = Uuid::new_v4();
    assert!(owner
        .try_register_session(FULL, connection, SessionRouteClaimProof::Binding)
        .await
        .unwrap());
    let mut conn = owner.pool.as_ref().unwrap().get().await.unwrap();
    let key = owner.key(format!("session_presence:{FULL}"));

    owner
        .publish_route_presence(FULL, Uuid::new_v4(), true, 8, 4)
        .await
        .unwrap();
    peer.publish_route_presence(FULL, connection, true, 8, 4)
        .await
        .unwrap();
    let absent: Option<String> = conn.get(&key).await.unwrap();
    assert_eq!(absent, None);

    let prior_seq = 1_u64 << 53;
    let latest_seq = prior_seq + 1;
    owner
        .publish_route_presence("ALICE@Example.test/Home", connection, true, 7, prior_seq)
        .await
        .unwrap();
    owner
        .publish_route_presence(FULL, connection, false, -1, latest_seq)
        .await
        .unwrap();
    owner
        .publish_route_presence(FULL, connection, true, 9, prior_seq)
        .await
        .unwrap();
    owner
        .publish_route_presence(FULL, connection, true, 10, latest_seq)
        .await
        .unwrap();
    let record: String = conn.get(&key).await.unwrap();
    assert_eq!(record, format!("{connection}|0|-1|{latest_seq}"));
    let ttl: u64 = conn.ttl(&key).await.unwrap();
    assert!((1..=SESSION_TTL_SECONDS).contains(&ttl));

    let eligible_seq = latest_seq + 2;
    owner
        .publish_route_presence(FULL, connection, true, 0, eligible_seq)
        .await
        .unwrap();
    owner
        .publish_route_presence(FULL, connection, true, -1, eligible_seq - 1)
        .await
        .unwrap();
    let record: String = conn.get(&key).await.unwrap();
    assert_eq!(record, format!("{connection}|1|0|{eligible_seq}"));
    cleanup(&owner).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires TEST_REDIS_URL; uses and removes a unique key namespace"]
async fn redis_message_route_presence_follows_exact_refresh_release_and_takeover() {
    let (owner, peer) = managers().await;
    for manager in [&owner, &peer] {
        manager
            .configure_session_store(Arc::new(RouteAuthority::default()))
            .unwrap();
    }
    let connection = Uuid::new_v4();
    let replacement = Uuid::new_v4();
    assert!(owner
        .try_register_session(FULL, connection, SessionRouteClaimProof::Binding)
        .await
        .unwrap());
    owner
        .publish_route_presence(FULL, connection, true, 7, 4)
        .await
        .unwrap();
    let mut conn = owner.pool.as_ref().unwrap().get().await.unwrap();
    let key = owner.key(format!("session_presence:{FULL}"));
    let expected = format!("{connection}|1|7|4");
    let shortened: bool = conn.expire(&key, 60).await.unwrap();
    assert!(shortened);

    assert!(!owner
        .maintenance_redis()
        .refresh_session_projection(FULL, 0, replacement)
        .await
        .unwrap());
    let ttl: u64 = conn.ttl(&key).await.unwrap();
    assert!(ttl <= 60);
    assert!(owner
        .maintenance_redis()
        .refresh_session_projection(FULL, 0, connection)
        .await
        .unwrap());
    let ttl: u64 = conn.ttl(&key).await.unwrap();
    assert!((61..=SESSION_TTL_SECONDS).contains(&ttl));

    owner.unregister_session(FULL, replacement).await.unwrap();
    assert!(owner
        .try_register_session(FULL, connection, SessionRouteClaimProof::Binding)
        .await
        .unwrap());
    let record: String = conn.get(&key).await.unwrap();
    assert_eq!(record, expected);
    assert!(peer
        .try_register_session(FULL, replacement, SessionRouteClaimProof::Binding)
        .await
        .unwrap());
    let absent: Option<String> = conn.get(&key).await.unwrap();
    assert_eq!(absent, None);

    peer.publish_route_presence(FULL, replacement, true, 2, 1)
        .await
        .unwrap();
    owner.unregister_session(FULL, connection).await.unwrap();
    let record: String = conn.get(&key).await.unwrap();
    assert_eq!(record, format!("{replacement}|1|2|1"));
    peer.unregister_session(FULL, replacement).await.unwrap();
    let absent: Option<String> = conn.get(&key).await.unwrap();
    assert_eq!(absent, None);
    cleanup(&owner).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires TEST_REDIS_URL; uses and removes a unique key namespace"]
async fn redis_message_route_capture_uses_presence_only_for_the_captured_connection() {
    let (owner, peer) = managers().await;
    let account = Uuid::new_v4();
    let connection = Uuid::new_v4();
    let legacy = "alice@example.test/Legacy";
    let stale = "alice@example.test/Stale";
    let routes = [FULL, legacy, stale];
    let authorities = routes
        .into_iter()
        .map(|jid| {
            let authority = SessionRouteAuthority {
                owner_node_id: owner.node_id.clone(),
                owner_instance_uuid: owner.connection_uuid,
                owner_instance_epoch: 1,
                connection_uuid: connection,
            };
            (jid.to_owned(), authority)
        })
        .collect();
    peer.configure_session_store(Arc::new(RouteAuthority(authorities)))
        .unwrap();
    let mut conn = owner.pool.as_ref().unwrap().get().await.unwrap();
    let _: usize = conn
        .sadd(
            owner.key(format!("user_sessions:{BARE}")),
            routes.as_slice(),
        )
        .await
        .unwrap();
    let _: () = conn
        .set(
            owner.key(format!("session_presence:{FULL}")),
            format!("{connection}|1|8|1"),
        )
        .await
        .unwrap();
    let _: () = conn
        .set(
            owner.key(format!("session_presence:{stale}")),
            format!("{}|0|4|10", Uuid::new_v4()),
        )
        .await
        .unwrap();
    let mut captured = peer
        .capture_remote_message_routes(BARE, account, 42)
        .await
        .unwrap();
    captured.sort_by(|left, right| left.full_jid.cmp(&right.full_jid));
    assert_eq!(captured.len(), 3);
    for (route, jid) in captured.iter().zip(routes) {
        assert_eq!(route.full_jid, jid);
        assert_eq!(route.connection_id, connection);
        assert_eq!(route.account_id, account);
        assert_eq!(route.auth_generation, 42);
        assert_eq!(route.node_id.as_deref(), Some(owner.node_id.as_str()));
        let expected = if jid == FULL {
            (Some(true), Some(8))
        } else {
            (None, None)
        };
        assert_eq!((route.available, route.priority), expected);
    }
    cleanup(&owner).await;
}
