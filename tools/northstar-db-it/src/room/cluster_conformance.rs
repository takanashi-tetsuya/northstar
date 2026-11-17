use northstar_room_application::{
    cluster_muc_outbox_preclaim::ClusterMucOutboxPreclaimService,
    cluster_muc_outbox_settlement::{AckOutcome, ClusterMucOutboxSettlementService},
};
use northstar_room_postgres::{
    cluster_muc::claim_cluster_muc_outbox,
    cluster_muc_outbox_preclaim_repository::PostgresClusterMucOutboxPreclaimRepository,
    cluster_muc_outbox_settlement_repository::PostgresClusterMucOutboxSettlementRepository,
};
use sqlx::PgPool;
use uuid::Uuid;

async fn room(pool: &PgPool, ordinal: u128) -> (Uuid, Uuid) {
    let user = Uuid::from_u128(0x573_480100 + ordinal);
    let room = Uuid::from_u128(0x573_480200 + ordinal);
    sqlx::query("INSERT INTO users(id,username,password_hash) VALUES($1,$2,'test-only')")
        .bind(user)
        .bind(format!("cluster-conformance-{ordinal}"))
        .execute(pool)
        .await
        .unwrap();
    let epoch: Uuid = sqlx::query_scalar("INSERT INTO muc_rooms(id,localpart,owner_id,occupant_id_secret) VALUES($1,$2,$3,$4) RETURNING room_epoch")
        .bind(room).bind(format!("cluster-conformance-{ordinal}")).bind(user).bind(vec![9_u8; 32]).fetch_one(pool).await.unwrap();
    (room, epoch)
}

async fn outbox(pool: &PgPool, room: Uuid, epoch: Uuid, ordinal: u128, expired: bool) -> Uuid {
    let operation = Uuid::from_u128(0x573_480300 + ordinal);
    let delivery = Uuid::from_u128(0x573_480400 + ordinal);
    sqlx::query(
        "INSERT INTO cluster_muc_operations(operation_id,room_id,room_epoch,operation_kind,request_digest,authorization_source,actor_authorization_snapshot,
         config_version_before,config_version_after,event_sequence,event_id,audience_snapshot)
         VALUES($1,$2,$3,'expire',$4,'system','{}',1,1,$5,$1,'[]')",
    ).bind(operation).bind(room).bind(epoch).bind(vec![7_u8; 32]).bind(100 + ordinal as i64).execute(pool).await.unwrap();
    sqlx::query(
        "INSERT INTO cluster_muc_event_outbox(delivery_id,operation_id,room_id,room_epoch,event_sequence,event_id,audience_kind,target_node_id,
         payload,payload_digest,capacity_shard,created_at,expires_at)
         VALUES($1,$2,$3,$4,$5,$2,'node_pull','conformance-node','<presence/>',$6,0,
         clock_timestamp()-INTERVAL '2 minutes',clock_timestamp()+CASE WHEN $7 THEN INTERVAL '-1 minute' ELSE INTERVAL '1 hour' END)",
    ).bind(delivery).bind(operation).bind(room).bind(epoch).bind(100 + ordinal as i64).bind(vec![8_u8; 32]).bind(expired).execute(pool).await.unwrap();
    delivery
}

#[tokio::test]
#[ignore = "requires the ordinary-role random schema and TEST_DATABASE_URL"]
async fn preclaim_adapter_expires_occupancies_and_dead_letters_with_original_limits() {
    let pool = crate::support::operation_mutation_pool().await;
    let mut rooms = Vec::new();
    for ordinal in 0..2 {
        let (room, epoch) = room(&pool, ordinal).await;
        sqlx::query(
            "INSERT INTO cluster_muc_occupancies(room_id,room_epoch,occupant_incarnation,occupancy_epoch,config_version,identity_kind,local_user_id,
             bare_jid,full_jid,nick,owner_node_id,connection_uuid,connection_epoch,state,role,affiliation,lease_until)
             VALUES($1,$2,$3,1,1,'local',$4,$5,$6,'Expired','conformance-node',$7,1,'active','participant','none',clock_timestamp()-INTERVAL '1 second')",
        ).bind(room).bind(epoch).bind(Uuid::from_u128(0x573_480500 + ordinal)).bind(Uuid::from_u128(0x573_480100 + ordinal))
            .bind(format!("cluster-conformance-{ordinal}@example.test")).bind(format!("cluster-conformance-{ordinal}@example.test/phone"))
            .bind(Uuid::from_u128(0x573_480600 + ordinal)).execute(&pool).await.unwrap();
        rooms.push((room, epoch));
    }
    let first = outbox(&pool, rooms[0].0, rooms[0].1, 0, true).await;
    let second = outbox(&pool, rooms[0].0, rooms[0].1, 1, true).await;
    let service = ClusterMucOutboxPreclaimService::new(
        PostgresClusterMucOutboxPreclaimRepository::new(pool.clone()),
    );
    service.prepare_pass(1, 1).await.unwrap();
    let mut observer = pool.acquire().await.unwrap();
    let occupancies: Vec<(Uuid, String)> = sqlx::query_as("SELECT room_id,state FROM cluster_muc_occupancies WHERE room_id=ANY($1::uuid[]) ORDER BY room_id")
        .bind(vec![rooms[0].0, rooms[1].0]).fetch_all(&mut *observer).await.unwrap();
    assert_eq!(
        occupancies,
        vec![
            (rooms[0].0, "expired".into()),
            (rooms[1].0, "active".into())
        ],
        "original room limit"
    );
    let dead: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM cluster_muc_event_dead_letters WHERE delivery_id IN ($1,$2) AND terminal_reason='expired'")
        .bind(first).bind(second).fetch_one(&mut *observer).await.unwrap();
    let queued: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM cluster_muc_event_outbox WHERE delivery_id IN ($1,$2)",
    )
    .bind(first)
    .bind(second)
    .fetch_one(&mut *observer)
    .await
    .unwrap();
    assert_eq!(
        (dead, queued),
        (1, 1),
        "original outbox limit and committed move"
    );
    drop(observer);
    service.prepare_pass(1, 1).await.unwrap();
    pool.close().await;
}

#[tokio::test]
#[ignore = "requires the ordinary-role random schema and TEST_DATABASE_URL"]
async fn cluster_settlement_rejects_the_old_claim_and_preserves_the_replacement() {
    let pool = crate::support::operation_mutation_pool().await;
    let (room, epoch) = room(&pool, 10).await;
    let delivery = outbox(&pool, room, epoch, 10, false).await;
    let mut claimed = claim_cluster_muc_outbox(
        &pool,
        "conformance-node",
        128,
        std::time::Duration::from_secs(30),
    )
    .await
    .unwrap();
    let claimed = claimed.remove(
        claimed
            .iter()
            .position(|row| row.delivery_id == delivery)
            .expect("fixture delivery was not claimed"),
    );
    let replacement_token = Uuid::from_u128(0x573_5201);
    sqlx::query("UPDATE cluster_muc_event_outbox SET claim_token=$2 WHERE delivery_id=$1")
        .bind(delivery)
        .bind(replacement_token)
        .execute(&pool)
        .await
        .unwrap();
    let service = ClusterMucOutboxSettlementService::new(
        PostgresClusterMucOutboxSettlementRepository::new(pool.clone()),
    );
    assert_eq!(
        service.acknowledge(&claimed).await.unwrap(),
        AckOutcome::LostClaim,
        "stale acknowledgement"
    );
    service.retry(&claimed, "stale retry").await.unwrap();
    let mut observer = pool.acquire().await.unwrap();
    let remaining: (Uuid, Option<String>) = sqlx::query_as(
        "SELECT claim_token,last_error FROM cluster_muc_event_outbox WHERE delivery_id=$1",
    )
    .bind(delivery)
    .fetch_one(&mut *observer)
    .await
    .unwrap();
    assert_eq!(
        remaining,
        (replacement_token, None),
        "old settlement cannot mutate replacement"
    );
    drop(observer);
    let replacement = northstar_room_core::ClusterMucOutboxDelivery {
        claim_token: replacement_token,
        ..claimed
    };
    assert_eq!(
        service.acknowledge(&replacement).await.unwrap(),
        AckOutcome::Acknowledged
    );
    let remaining: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM cluster_muc_event_outbox WHERE delivery_id=$1)",
    )
    .bind(delivery)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert!(!remaining, "matching token committed deletion");
    pool.close().await;
}
