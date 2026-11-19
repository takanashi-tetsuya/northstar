use super::*;
use northstar_room_core::occupancy::{MucRegistration, MucRename, MucRoleChange};

#[test]
fn muc_soft_state_lease_survives_multiple_refresh_and_node_lease_windows() {
    const {
        assert!(
            MUC_SOFT_STATE_TTL_SECONDS >= CLUSTER_MAINTENANCE_INTERVAL_SECONDS * 8,
            "a live room needs several maintenance retries before its soft-state expires"
        );
        assert!(
            MUC_SOFT_STATE_TTL_SECONDS >= NODE_TTL_SECONDS * 3,
            "room cleanup must not race a single missed node-heartbeat window"
        );
    }
}

#[derive(Clone, Debug, Default)]
struct NeverConnectManager {
    attempts: Arc<std::sync::atomic::AtomicUsize>,
}

impl bb8::ManageConnection for NeverConnectManager {
    type Connection = ();
    type Error = std::io::Error;

    async fn connect(&self) -> std::result::Result<Self::Connection, Self::Error> {
        self.attempts
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        std::future::pending().await
    }

    async fn is_valid(&self, _: &mut Self::Connection) -> std::result::Result<(), Self::Error> {
        Ok(())
    }

    fn has_broken(&self, _: &mut Self::Connection) -> bool {
        false
    }
}

#[test]
fn redis_pool_checkout_accepts_only_a_master_role_response() {
    use redis::Value;

    assert!(pool::redis_role_is_master(&Value::Array(vec![
        Value::BulkString(b"master".to_vec()),
        Value::Int(0),
        Value::Array(vec![]),
    ])));
    for response in [
        Value::Array(vec![
            Value::BulkString(b"slave".to_vec()),
            Value::BulkString(b"primary.internal".to_vec()),
            Value::Int(6379),
        ]),
        Value::Array(vec![
            Value::SimpleString("sentinel".to_owned()),
            Value::Array(vec![]),
            Value::Array(vec![]),
        ]),
        Value::Array(vec![Value::BulkString(b"master".to_vec())]),
        Value::SimpleString("master".to_owned()),
    ] {
        assert!(!pool::redis_role_is_master(&response));
    }
}

#[tokio::test]
async fn three_failed_cluster_pool_acquisitions_finish_inside_two_seconds() {
    let manager = NeverConnectManager::default();
    let attempts = manager.attempts.clone();
    let pool = cluster_pool_builder().build_unchecked(manager);

    tokio::time::timeout(Duration::from_secs(2), async {
        for _ in 0..3 {
            assert!(matches!(pool.get().await, Err(bb8::RunError::TimedOut)));
        }
    })
    .await
    .expect("three serial Redis pool acquisition failures exceeded two seconds");

    // bb8 coalesces concurrent/serial waiters behind the same in-flight
    // connection attempt. The callers must still receive their own hard
    // deadline instead of waiting for that attempt to finish or retry.
    assert_eq!(attempts.load(std::sync::atomic::Ordering::SeqCst), 1);
}

#[tokio::test]
async fn single_node_muc_rename_requires_the_exact_non_nil_occupancy_epoch() {
    let cluster = ClusterManager::new(None, "example.test", None, None, None, None)
        .await
        .unwrap();
    let epoch = uuid::Uuid::new_v4();
    let old = rename_occupant(epoch, "Old");
    let mut new = old.clone();
    new.nick = "New".to_owned();
    assert_eq!(
        cluster
            .rename_muc_occupant(
                &old.room_jid,
                &old.nick,
                &new.nick,
                epoch,
                &serde_json::to_string(&old).unwrap(),
                &serde_json::to_string(&new).unwrap(),
            )
            .await
            .unwrap(),
        MucRename::Renamed
    );

    let stale = rename_occupant(uuid::Uuid::new_v4(), "Old");
    assert!(cluster
        .rename_muc_occupant(
            &old.room_jid,
            &old.nick,
            &new.nick,
            epoch,
            &serde_json::to_string(&stale).unwrap(),
            &serde_json::to_string(&new).unwrap(),
        )
        .await
        .is_err());
    let nil_old = rename_occupant(uuid::Uuid::nil(), "Old");
    let nil_new = rename_occupant(uuid::Uuid::nil(), "New");
    assert!(cluster
        .rename_muc_occupant(
            &nil_old.room_jid,
            &nil_old.nick,
            &nil_new.nick,
            uuid::Uuid::nil(),
            &serde_json::to_string(&nil_old).unwrap(),
            &serde_json::to_string(&nil_new).unwrap(),
        )
        .await
        .is_err());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires TEST_REDIS_URL; uses and removes a unique key namespace"]
async fn redis_muc_nickname_and_voice_mutations_reject_conflicts_and_aba() {
    let redis_url =
        std::env::var("TEST_REDIS_URL").expect("set TEST_REDIS_URL to a disposable Redis instance");
    let namespace = format!("muc-{}.test", uuid::Uuid::new_v4().simple());
    let (first_security, second_security) =
        northstar_security::cluster_bus::test_configuration_pair(&namespace);
    let first = ClusterManager::new(
        Some(&redis_url),
        &namespace,
        None,
        None,
        None,
        Some(first_security),
    )
    .await
    .unwrap();
    let second = ClusterManager::new(
        Some(&redis_url),
        &namespace,
        None,
        None,
        None,
        Some(second_security),
    )
    .await
    .unwrap();
    for cluster in [&first, &second] {
        cluster.install_instance_epoch(1).unwrap();
        cluster.touch_node().await.unwrap();
        cluster.note_listener_generation();
    }
    seed_test_peer_authority(&first, &second);
    seed_test_peer_authority(&second, &first);
    let second_channel = second.key(format!("node:{}", second.node_id));
    let mut second_pubsub = open_pubsub(second.client.as_ref().unwrap()).await.unwrap();
    subscribe_pubsub(&mut second_pubsub, &second_channel)
        .await
        .unwrap();
    let mut second_messages = second_pubsub.on_message();
    let room = "room@conference.example.test";
    let original_epoch = uuid::Uuid::new_v4();
    let original = rename_occupant(original_epoch, "Old");
    let original_json = serde_json::to_string(&original).unwrap();
    assert_eq!(
        first
            .try_register_muc_occupant(room, "Old", &original_json, 100)
            .await
            .unwrap(),
        MucRegistration::Joined
    );
    assert_eq!(
        first
            .try_register_muc_occupant(room, "Old", &original_json, 100)
            .await
            .unwrap(),
        MucRegistration::Joined,
        "an exact registration retry must be idempotent and renew its lease"
    );
    {
        let mut connection = first.pool.as_ref().unwrap().get().await.unwrap();
        for key in [
            first.key(format!("muc_occupants:{room}")),
            first.key(format!("muc_occupant_nodes:{room}")),
            first.key(format!("muc_nodes:{room}")),
            first.key(format!("muc_occupant_instances:{room}")),
            first.key(format!("muc_node_counts:{room}")),
        ] {
            let ttl: i64 = connection.ttl(key).await.unwrap();
            assert!((1..=MUC_SOFT_STATE_TTL_SECONDS as i64).contains(&ttl));
        }
    }

    let occupied = rename_occupant(uuid::Uuid::new_v4(), "Taken");
    assert_eq!(
        second
            .try_register_muc_occupant(
                room,
                "Taken",
                &serde_json::to_string(&occupied).unwrap(),
                100,
            )
            .await
            .unwrap(),
        MucRegistration::Joined
    );
    {
        let Some(pool) = &first.pool else {
            panic!("Redis-backed cluster expected");
        };
        let mut connection = pool.get().await.unwrap();
        let occupants_key = first.key(format!("muc_occupants:{room}"));
        let owners_key = first.key(format!("muc_occupant_nodes:{room}"));
        let nodes_key = first.key(format!("muc_nodes:{room}"));
        let _: usize = connection
            .hset(&occupants_key, "Ghost", "{}")
            .await
            .unwrap();
        let _: usize = connection
            .hset(&owners_key, "Ghost", "crashed-node")
            .await
            .unwrap();
        let _: usize = connection.sadd(&nodes_key, "crashed-node").await.unwrap();
        drop(connection);
        let visible = first.get_muc_occupants(room).await.unwrap();
        assert!(!visible.contains_key("Ghost"));
        let mut connection = pool.get().await.unwrap();
        let nodes: Vec<String> = connection.smembers(nodes_key).await.unwrap();
        assert!(!nodes.iter().any(|node| node == "crashed-node"));
    }
    let mut conflicting = original.clone();
    conflicting.nick = "Taken".to_owned();
    assert_eq!(
        first
            .rename_muc_occupant(
                room,
                "Old",
                "Taken",
                original_epoch,
                &original_json,
                &serde_json::to_string(&conflicting).unwrap(),
            )
            .await
            .unwrap(),
        MucRename::Conflict
    );
    assert!(first
        .get_muc_occupants(room)
        .await
        .unwrap()
        .contains_key("Old"));

    assert!(first
        .unregister_muc_occupant_epoch(room, "Old", original_epoch, original.connection_id,)
        .await
        .unwrap());
    let replacement_epoch = uuid::Uuid::new_v4();
    let replacement = rename_occupant(replacement_epoch, "Old");
    let replacement_json = serde_json::to_string(&replacement).unwrap();
    assert_eq!(
        first
            .try_register_muc_occupant(room, "Old", &replacement_json, 100)
            .await
            .unwrap(),
        MucRegistration::Joined
    );
    let mut delayed_target = original.clone();
    delayed_target.nick = "Late".to_owned();
    assert_eq!(
        first
            .rename_muc_occupant(
                room,
                "Old",
                "Late",
                original_epoch,
                &original_json,
                &serde_json::to_string(&delayed_target).unwrap(),
            )
            .await
            .unwrap(),
        MucRename::Stale
    );
    assert_eq!(
        first.get_muc_occupants(room).await.unwrap().get("Old"),
        Some(&replacement_json)
    );
    assert!(!first
        .unregister_muc_occupant_epoch(room, "Old", original_epoch, original.connection_id,)
        .await
        .unwrap());
    assert!(!first
        .evict_muc_occupant(&original, 307, Some("Moderator"), Some("delayed"))
        .await
        .unwrap());
    assert_eq!(
        first.get_muc_occupants(room).await.unwrap().get("Old"),
        Some(&replacement_json)
    );
    assert!(matches!(
        first
            .change_muc_occupant_role(room, &original, "participant")
            .await
            .unwrap(),
        MucRoleChange::Stale
    ));
    let changed = first
        .change_muc_occupant_role(room, &replacement, "visitor")
        .await
        .unwrap();
    let signed_role_change: String = tokio::time::timeout(REDIS_IO_TIMEOUT, second_messages.next())
        .await
        .expect("remote role change publication timed out")
        .expect("remote role change subscription ended")
        .get_payload()
        .unwrap();
    second
        .verify_signed_payload(&signed_role_change, &second_channel, Some(&first.node_id))
        .unwrap();
    assert!(matches!(
        changed,
        MucRoleChange::Changed(ref occupant) if occupant.role == "visitor"
    ));
    let changed = match changed {
        MucRoleChange::Changed(occupant) => occupant,
        MucRoleChange::Stale => unreachable!(),
    };
    let policy_changed = first
        .change_muc_occupant_policy(room, &changed, "participant", true)
        .await
        .unwrap();
    let signed_policy_change: String =
        tokio::time::timeout(REDIS_IO_TIMEOUT, second_messages.next())
            .await
            .expect("remote policy change publication timed out")
            .expect("remote policy change subscription ended")
            .get_payload()
            .unwrap();
    second
        .verify_signed_payload(&signed_policy_change, &second_channel, Some(&first.node_id))
        .unwrap();
    assert!(matches!(
        policy_changed,
        MucRoleChange::Changed(ref occupant)
            if occupant.role == "participant" && occupant.room_non_anonymous
    ));
    let persisted: northstar_room_application::muc_service::SerializableMucOccupant =
        serde_json::from_str(
            first
                .get_muc_occupants(room)
                .await
                .unwrap()
                .get("Old")
                .unwrap(),
        )
        .unwrap();
    assert_eq!(persisted.role, "participant");
    assert!(persisted.room_non_anonymous);
    // A policy write is a full serialized-value compare-and-set, not only
    // an epoch check. `changed` still describes the preceding visitor
    // state for this exact connection and must not overwrite the newer
    // participant/non-anonymous policy.
    assert!(matches!(
        first
            .change_muc_occupant_policy(room, &changed, "visitor", false)
            .await
            .unwrap(),
        MucRoleChange::Stale
    ));

    assert!(first
        .unregister_muc_occupant_epoch(room, "Old", replacement_epoch, replacement.connection_id,)
        .await
        .unwrap());
    assert!(second
        .unregister_muc_occupant_epoch(
            room,
            "Taken",
            occupied.cluster_epoch,
            occupied.connection_id,
        )
        .await
        .unwrap());
    assert!(first.get_muc_occupants(room).await.unwrap().is_empty());

    let Some(pool) = &first.pool else {
        panic!("Redis-backed cluster expected");
    };
    let mut connection = pool.get().await.unwrap();
    for key in [
        first.key(format!("muc_occupants:{room}")),
        first.key(format!("muc_occupant_nodes:{room}")),
        first.key(format!("muc_nodes:{room}")),
        first.key(format!("muc_occupant_instances:{room}")),
        first.key(format!("muc_node_counts:{room}")),
    ] {
        let exists: bool = connection.exists(key).await.unwrap();
        assert!(!exists, "last occupant cleanup left a room soft-state key");
    }
    let prefix = format!("{}*", first.key_prefix);
    let keys: Vec<String> = redis::cmd("KEYS")
        .arg(prefix)
        .query_async(&mut *connection)
        .await
        .unwrap();
    if !keys.is_empty() {
        let _: usize = redis::cmd("DEL")
            .arg(&keys)
            .query_async(&mut *connection)
            .await
            .unwrap();
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires TEST_REDIS_URL; exercises 10,000 disposable MUC room lifecycles"]
async fn redis_ten_thousand_temporary_muc_rooms_leave_no_soft_state_keys() {
    use futures::StreamExt as _;

    let redis_url =
        std::env::var("TEST_REDIS_URL").expect("set TEST_REDIS_URL to a disposable Redis instance");
    let namespace = format!("muc-churn-{}.test", uuid::Uuid::new_v4().simple());
    let (security, _) = northstar_security::cluster_bus::test_configuration_pair(&namespace);
    let cluster = ClusterManager::new(
        Some(&redis_url),
        &namespace,
        None,
        None,
        None,
        Some(security),
    )
    .await
    .unwrap();
    cluster.install_instance_epoch(1).unwrap();
    cluster.touch_node().await.unwrap();
    cluster.note_listener_generation();

    futures::stream::iter(0..10_000_u32)
        .map(|index| {
            let cluster = cluster.clone();
            async move {
                let room = format!("churn-{index}@conference.example.test");
                let mut occupant = rename_occupant(uuid::Uuid::new_v4(), "Only");
                occupant.room_jid.clone_from(&room);
                let json = serde_json::to_string(&occupant).unwrap();
                assert_eq!(
                    cluster
                        .try_register_muc_occupant(&room, "Only", &json, 1)
                        .await
                        .unwrap(),
                    MucRegistration::Joined
                );
                assert!(cluster
                    .unregister_muc_occupant_epoch(
                        &room,
                        "Only",
                        occupant.cluster_epoch,
                        occupant.connection_id,
                    )
                    .await
                    .unwrap());
            }
        })
        .buffer_unordered(16)
        .collect::<Vec<_>>()
        .await;

    let mut connection = cluster.pool.as_ref().unwrap().get().await.unwrap();
    for kind in [
        "muc_occupants",
        "muc_occupant_nodes",
        "muc_nodes",
        "muc_occupant_instances",
        "muc_node_counts",
    ] {
        let pattern = cluster.key(format!("{kind}:*"));
        let mut cursor = 0_u64;
        let mut found = Vec::new();
        loop {
            let (next, keys): (u64, Vec<String>) = redis::cmd("SCAN")
                .arg(cursor)
                .arg("MATCH")
                .arg(&pattern)
                .arg("COUNT")
                .arg(1_000)
                .query_async(&mut *connection)
                .await
                .unwrap();
            found.extend(keys);
            cursor = next;
            if cursor == 0 {
                break;
            }
        }
        assert!(found.is_empty(), "temporary room churn leaked {kind} keys");
    }
}

#[test]
fn redis_session_routes_keep_opaque_resource_case() {
    let upper = session_route_keys("ALICE@Example.test/Phone").unwrap();
    let lower = session_route_keys("alice@example.test/phone").unwrap();
    assert_eq!(upper.0, "alice@example.test/Phone");
    assert_eq!(lower.0, "alice@example.test/phone");
    assert_ne!(upper.0, lower.0);
    assert_eq!(upper.1, lower.1);
    assert_eq!(
        session_route_keys("ÅLICE@BÜCHER.example/DeviceÅ").unwrap(),
        (
            "ålice@bücher.example/DeviceÅ".to_owned(),
            "ålice@bücher.example".to_owned()
        )
    );
    assert!(session_route_keys("alice@example..test/Phone").is_err());
    assert!(session_route_keys("alice@example.test/bad\u{0007}resource").is_err());
}
