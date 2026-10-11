use super::*;
use std::panic::AssertUnwindSafe;

struct RoutingFixture {
    first: ClusterManager,
    second: ClusterManager,
}

impl RoutingFixture {
    async fn new() -> Self {
        let redis_url = std::env::var("TEST_REDIS_URL")
            .expect("set TEST_REDIS_URL to a disposable Redis instance");
        let namespace = format!("muc-routing-{}.test", uuid::Uuid::new_v4().simple());
        let (first_security, second_security) =
            crate::cluster_security::test_configuration_pair(&namespace);
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
        for manager in [&first, &second] {
            manager.install_instance_epoch(1).unwrap();
            manager.touch_node().await.unwrap();
            manager.note_listener_generation();
        }
        super::tests::seed_test_peer_authority(&first, &second);
        super::tests::seed_test_peer_authority(&second, &first);
        Self { first, second }
    }

    async fn finish(self, result: std::thread::Result<()>) {
        // Delete only keys from this test's random namespace, including after
        // an assertion fails. SCAN is bounded by this tiny disposable fixture.
        let mut conn = self.first.pool.as_ref().unwrap().get().await.unwrap();
        let mut cursor = 0_u64;
        let mut keys = Vec::<String>::new();
        loop {
            let (next, found): (u64, Vec<String>) = redis::cmd("SCAN")
                .arg(cursor)
                .arg("MATCH")
                .arg(format!("{}*", self.first.key_prefix))
                .arg("COUNT")
                .arg(100)
                .query_async(&mut *conn)
                .await
                .unwrap();
            keys.extend(found);
            assert!(
                keys.len() <= 512,
                "routing fixture namespace unexpectedly grew"
            );
            cursor = next;
            if cursor == 0 {
                break;
            }
        }
        if !keys.is_empty() {
            let _: usize = redis::cmd("DEL")
                .arg(&keys)
                .query_async(&mut *conn)
                .await
                .unwrap();
        }
        if let Err(panic) = result {
            std::panic::resume_unwind(panic);
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires TEST_REDIS_URL; uses and removes a unique key namespace"]
async fn redis_muc_routing_prunes_only_dead_node_hints_until_explicit_room_read() {
    let fixture = RoutingFixture::new().await;
    let result = AssertUnwindSafe(async {
        let manager = &fixture.first;
        let room = "room@conference.example.test";
        let occupant = super::tests::rename_occupant(uuid::Uuid::new_v4(), "Live");
        assert_eq!(
            manager
                .try_register_muc_occupant(
                    room,
                    "Live",
                    &serde_json::to_string(&occupant).unwrap(),
                    100,
                )
                .await
                .unwrap(),
            MucRegistration::Joined
        );
        let occupants = manager.key(format!("muc_occupants:{room}"));
        let owners = manager.key(format!("muc_occupant_nodes:{room}"));
        let nodes = manager.key(format!("muc_nodes:{room}"));
        let instances = manager.key(format!("muc_occupant_instances:{room}"));
        let counts = manager.key(format!("muc_node_counts:{room}"));
        let mut conn = manager.pool.as_ref().unwrap().get().await.unwrap();
        // A legacy three-key ghost has no stable liveness. A five-key ghost
        // can also have a live stable node but a dead process incarnation.
        let _: () = redis::pipe()
            .hset(&occupants, "Ghost", "{}")
            .ignore()
            .hset(&owners, "Ghost", "crashed-node")
            .ignore()
            .sadd(&nodes, "crashed-node")
            .ignore()
            .hset(&occupants, "OldProcess", "{}")
            .ignore()
            .hset(&owners, "OldProcess", "restarted-node")
            .ignore()
            .hset(&instances, "OldProcess", uuid::Uuid::new_v4().to_string())
            .ignore()
            .hset(&counts, "restarted-node", 1)
            .ignore()
            .sadd(&nodes, "restarted-node")
            .ignore()
            .set(manager.key("node:restarted-node:alive".to_owned()), "1")
            .ignore()
            .query_async(&mut *conn)
            .await
            .unwrap();
        let active = manager.active_muc_nodes(room).await.unwrap();
        assert_eq!(active.len(), 2);
        assert!(active.contains(&manager.node_id));
        assert!(active.contains(&"restarted-node".to_owned()));
        let dead_hint: bool = conn.sismember(&nodes, "crashed-node").await.unwrap();
        assert!(!dead_hint);
        for nick in ["Ghost", "OldProcess"] {
            let remains: bool = conn.hexists(&occupants, nick).await.unwrap();
            assert!(remains, "hot routing must not sweep occupants");
            let remains: bool = conn.hexists(&owners, nick).await.unwrap();
            assert!(remains, "hot routing must not mutate occupant ownership");
        }
        let remains: bool = conn.hexists(&instances, "OldProcess").await.unwrap();
        assert!(remains);
        let count: i64 = conn.hget(&counts, "restarted-node").await.unwrap();
        assert_eq!(count, 1);

        let visible = manager.get_muc_occupants(room).await.unwrap();
        assert_eq!(visible.len(), 1);
        assert!(visible.contains_key("Live"));
        for nick in ["Ghost", "OldProcess"] {
            for key in [&occupants, &owners, &instances] {
                let remains: bool = conn.hexists(key, nick).await.unwrap();
                assert!(
                    !remains,
                    "explicit room read must reconcile stale incarnations"
                );
            }
        }
        let remaining: Vec<String> = conn.smembers(&nodes).await.unwrap();
        assert_eq!(remaining, vec![manager.node_id.clone()]);
        let remains: bool = conn.hexists(&counts, "restarted-node").await.unwrap();
        assert!(!remains);
    })
    .catch_unwind()
    .await;
    fixture.finish(result).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires TEST_REDIS_URL; uses and removes a unique key namespace"]
async fn redis_muc_routing_bounds_node_hints_and_propagates_invalid_redis_state() {
    let fixture = RoutingFixture::new().await;
    let result = AssertUnwindSafe(async {
        let manager = &fixture.first;
        let room = "bounded@conference.example.test";
        let nodes = manager.key(format!("muc_nodes:{room}"));
        let limit = crate::cluster_security::MAX_PEERS + 1;
        let mut conn = manager.pool.as_ref().unwrap().get().await.unwrap();
        let mut seed = redis::pipe();
        for index in 0..limit {
            let node = format!("bounded-{index}");
            seed.sadd(&nodes, &node)
                .ignore()
                .set(manager.key(format!("node:{node}:alive")), "1")
                .ignore();
        }
        let _: () = seed.query_async(&mut *conn).await.unwrap();
        assert_eq!(manager.active_muc_nodes(room).await.unwrap().len(), 129);
        let _: usize = conn.sadd(&nodes, "over-limit").await.unwrap();
        let error = manager.active_muc_nodes(room).await.unwrap_err();
        assert!(format!("{error:#}").contains("node hint limit exceeded"));
        let count: usize = conn.scard(&nodes).await.unwrap();
        assert_eq!(
            count, 130,
            "over-limit failure must not silently truncate hints"
        );
        // Full read reconciliation remains able to recover an overfull hint
        // set; none of these synthetic hints has a real occupant authority.
        assert!(manager.get_muc_occupants(room).await.unwrap().is_empty());
        assert!(manager.active_muc_nodes(room).await.unwrap().is_empty());

        for invalid in [
            String::new(),
            "x".repeat(crate::cluster_security::MAX_NODE_ID_BYTES + 1),
        ] {
            let _: usize = conn.sadd(&nodes, &invalid).await.unwrap();
            let error = manager.active_muc_nodes(room).await.unwrap_err();
            assert!(format!("{error:#}").contains("invalid length"));
            let _: usize = conn.del(&nodes).await.unwrap();
        }
        let _: usize = conn.sadd(&nodes, "wrong-type").await.unwrap();
        let _: usize = conn
            .hset(
                manager.key("node:wrong-type:alive".to_owned()),
                "field",
                "value",
            )
            .await
            .unwrap();
        let error = manager.active_muc_nodes(room).await.unwrap_err();
        assert!(format!("{error:#}").contains("WRONGTYPE"));
        let remains: bool = conn.sismember(&nodes, "wrong-type").await.unwrap();
        assert!(
            remains,
            "a malformed liveness value must not be treated as absent"
        );
    })
    .catch_unwind()
    .await;
    fixture.finish(result).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires TEST_REDIS_URL; uses and removes a unique key namespace"]
async fn redis_muc_fan_out_keeps_destination_errors_without_bypassing_global_admission() {
    let fixture = RoutingFixture::new().await;
    let result = AssertUnwindSafe(async {
        let first = &fixture.first;
        let second = &fixture.second;
        let channel = second.key(format!("node:{}", second.node_id));
        let mut subscription = open_pubsub(second.client.as_ref().unwrap()).await.unwrap();
        subscribe_pubsub(&mut subscription, &channel).await.unwrap();
        let mut messages = subscription.on_message();
        let room = "broadcast@conference.example.test";
        let nodes_key = first.key(format!("muc_nodes:{room}"));
        let unknown = "unknown-live-node".to_owned();
        let mut conn = first.pool.as_ref().unwrap().get().await.unwrap();
        let _: () = redis::pipe()
            .sadd(&nodes_key, &unknown).ignore()
            .sadd(&nodes_key, &second.node_id).ignore()
            .set(first.key(format!("node:{unknown}:alive")), "1").ignore()
            .query_async(&mut *conn).await.unwrap();
        assert!(first.active_muc_nodes(room).await.unwrap().contains(&unknown));
        let payload = serde_json::json!({
            "target": room, "stanza": "<message type='groupchat'><body>bounded fan-out</body></message>",
            "muc_broadcast": true, "real_sender": null,
        });
        let error = first.publish_muc_fan_out(
            &mut conn, vec![unknown.clone(), second.node_id.clone()], payload.clone(),
        ).await.unwrap_err();
        assert!(format!("{error:#}").contains(&unknown));
        assert_eq!(first.health.state.load(Ordering::Acquire), CLUSTER_HEALTHY,
            "one unknown destination must not manufacture a global Redis failure");
        let raw: String = tokio::time::timeout(REDIS_IO_TIMEOUT, messages.next())
            .await.expect("trusted destination did not receive the later fan-out")
            .expect("trusted subscriber ended").get_payload().unwrap();
        let verified = second.verify_signed_payload_inner(
            &raw, &channel, Some(&first.node_id), true,
        ).unwrap();
        assert_eq!(verified.payload, payload);

        first.record_control_plane_failure(&anyhow::anyhow!("fixture global Redis fault"));
        let error = first.publish_muc_fan_out(
            &mut conn, vec![unknown, second.node_id.clone()], payload,
        ).await.unwrap_err();
        assert!(!format!("{error:#}").is_empty());
        // A publish on the same connection after the failed call fences the
        // Redis stream. The next received item must be this marker, proving
        // fan-out did not emit a signed message after global admission failed.
        let _: i32 = conn.publish(&channel, "fixture-stream-fence").await.unwrap();
        let next: String = tokio::time::timeout(REDIS_IO_TIMEOUT, messages.next())
            .await.unwrap().unwrap().get_payload().unwrap();
        assert_eq!(next, "fixture-stream-fence");
    }).catch_unwind().await;
    fixture.finish(result).await;
}
