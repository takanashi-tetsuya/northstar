use super::*;
use crate::db::room::PostgresMucRepository;

#[tokio::test]
async fn committed_wake_failures_preserve_success_and_record_degradation() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    struct Wake {
        calls: AtomicUsize,
        failures: AtomicUsize,
        operation_id: Uuid,
    }
    impl MucWakePort for Wake {
        async fn wake(&self, descriptor: &ClusterMucWakeDescriptor) -> Result<()> {
            assert_eq!(descriptor.operation_id, self.operation_id);
            self.calls.fetch_add(1, Ordering::SeqCst);
            anyhow::bail!("injected Redis failure")
        }
        fn record_failure(&self, _: &anyhow::Error) {
            self.failures.fetch_add(1, Ordering::SeqCst);
        }
    }
    let operation_id = Uuid::new_v4();
    let wake = Wake {
        calls: AtomicUsize::new(0),
        failures: AtomicUsize::new(0),
        operation_id,
    };
    notify_committed_operation(
        async { anyhow::bail!("descriptor lookup failed") },
        &wake,
        operation_id,
    )
    .await;
    assert_eq!(wake.calls.load(Ordering::SeqCst), 0);
    assert_eq!(wake.failures.load(Ordering::SeqCst), 1);
    notify_committed_operation(async { Ok(None) }, &wake, operation_id).await;
    assert_eq!(wake.calls.load(Ordering::SeqCst), 0);
    assert_eq!(wake.failures.load(Ordering::SeqCst), 1);
    let descriptor = ClusterMucWakeDescriptor {
        operation_id,
        room_id: Uuid::new_v4(),
        event_id: Uuid::new_v4(),
        event_sequence: 1,
        target_nodes: vec!["node-a".to_owned()],
    };
    notify_committed_operation(async { Ok(Some(descriptor)) }, &wake, operation_id).await;
    assert_eq!(wake.calls.load(Ordering::SeqCst), 1);
    assert_eq!(wake.failures.load(Ordering::SeqCst), 2);
}

#[tokio::test(start_paused = true)]
async fn local_room_mutation_gate_serializes_one_room_without_a_growing_registry() {
    let pool = sqlx::postgres::PgPoolOptions::new()
        .connect_lazy("postgres://northstar@localhost/northstar")
        .expect("lazy test pool");
    let service = MucService::new(PostgresMucRepository::new(pool), "local.test");
    let room_id = Uuid::from_u128(7);
    let first = service.lock_local_room_mutation(room_id).await;
    assert!(tokio::time::timeout(
        Duration::from_millis(10),
        service.lock_local_room_mutation(room_id)
    )
    .await
    .is_err());
    drop(first);
    tokio::time::timeout(
        Duration::from_millis(100),
        service.lock_local_room_mutation(room_id),
    )
    .await
    .expect("room gate released");
    assert_eq!(service.local_join_gates.len(), LOCAL_JOIN_GATE_SHARDS);
}

#[tokio::test(start_paused = true)]
async fn local_room_mutation_gate_does_not_serialize_different_fixed_shards() {
    let pool = sqlx::postgres::PgPoolOptions::new()
        .connect_lazy("postgres://northstar@localhost/northstar")
        .expect("lazy test pool");
    let service = MucService::new(PostgresMucRepository::new(pool), "local.test");
    let first_room = Uuid::from_bytes([1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
    // The shard is derived from the first little-endian u64. These two
    // UUIDs therefore select different fixed gates deterministically.
    let other_room = Uuid::from_bytes([2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
    let first = service.lock_local_room_mutation(first_room).await;
    tokio::time::timeout(
        Duration::from_millis(100),
        service.lock_local_room_mutation(other_room),
    )
    .await
    .expect("an unrelated room shard must remain independently writable");
    drop(first);
}

#[tokio::test]
async fn local_actor_scope_requires_the_configured_domain_at_the_service_boundary() {
    let pool = sqlx::postgres::PgPoolOptions::new()
        .connect_lazy("postgres://northstar@localhost/northstar")
        .expect("lazy test pool");
    let service = MucService::new(PostgresMucRepository::new(pool), "local.test");
    let admission = service
        .admit_local_discussion(MucDiscussion {
            id: Uuid::nil(),
            room_id: Uuid::nil(),
            actor_scope: "alice@evil.test".to_owned(),
            origin_id: None,
            sender_jid: "alice@evil.test/Phone".to_owned(),
            nick: "Alice".to_owned(),
            stanza: "<message/>".to_owned(),
            encrypted: false,
            archive: false,
            retention_days: 0,
            authority: MucActorAuthority {
                clustered: false,
                expected_room_epoch: Uuid::nil(),
                principal: MucActorPrincipal::Local {
                    user_id: Uuid::nil(),
                    // Attacker-controlled command fields agree with each
                    // other, but not with MucService's server-owned domain.
                    local_domain: "evil.test".to_owned(),
                },
                actor_scope: "alice@evil.test".to_owned(),
                full_jid: "alice@evil.test/Phone".to_owned(),
                nick: "Alice".to_owned(),
                occupant_incarnation: Uuid::nil(),
                connection_uuid: Uuid::nil(),
                expected_role: "participant".to_owned(),
                expected_affiliation: "none".to_owned(),
                cluster_target: None,
            },
        })
        .await
        .expect("forged domain is rejected before the lazy pool connects");
    assert_eq!(admission, MucDiscussionAdmission::Unauthorized);
}
