use super::muc::create_harness_owned_schema;
use northstar_room_application::muc_service::{CommittedRoomRetirement, MucRoomIncarnation};
use northstar_room_core::{occupancy::MucOccupantRoute, ClusterMucAudienceSnapshot};
use northstar_room_postgres::cluster_muc::{
    claim_cluster_muc_occupancy, system_tombstone_cluster_muc_room_in_tx,
    transition_cluster_muc_occupancy, ClusterMucJoin, ClusterMucJoinOutcome, ClusterMucOccupancy,
    ClusterMucOccupancyTarget, ClusterMucPrincipal, ClusterMucTransitionOutcome,
};
use northstar_room_postgres::muc::{
    cancel_locked_muc_room, delete_expired_locked_muc_room, delete_expired_locked_muc_rooms,
    delete_temporary_muc_room, get_or_create_muc_room, muc_departed_room, muc_room,
    sm_teardown_muc_observers, MucRoom,
};
use serde_json::{json, Value};
use sqlx::{postgres::PgPoolOptions, PgPool, Row};
use std::time::Duration;
use uuid::Uuid;

const LOCALPART: &str = "retirement";
const OWNER: &str = "effect-owner@local.test/Phone";
const NODE: &str = "retirement-node";

struct Fixture {
    admin: PgPool,
    pool: PgPool,
    schema: String,
    owner: Uuid,
}

impl Fixture {
    async fn new() -> Self {
        let url = std::env::var("TEST_DATABASE_URL")
            .expect("set TEST_DATABASE_URL to an isolated PostgreSQL database");
        let admin = PgPoolOptions::new()
            .max_connections(1)
            .acquire_timeout(Duration::from_secs(60))
            .connect(&url)
            .await
            .unwrap();
        let schema = format!("muc_lifecycle_test_{}", Uuid::new_v4().simple());
        create_harness_owned_schema(&admin, &schema).await;
        let connection_schema = schema.clone();
        let pool = PgPoolOptions::new()
            .max_connections(6)
            .acquire_timeout(Duration::from_secs(60))
            .after_connect(move |connection, _| {
                let statement = format!("SET search_path TO {connection_schema}");
                Box::pin(async move {
                    sqlx::query(sqlx::AssertSqlSafe(statement.as_str()))
                        .execute(connection)
                        .await?;
                    Ok(())
                })
            })
            .connect(&url)
            .await
            .unwrap();
        crate::support::migrate(&pool).await.unwrap();
        let owner = Uuid::new_v4();
        sqlx::query(
            "INSERT INTO users(id,username,password_hash) VALUES($1,'effect-owner','test')",
        )
        .bind(owner)
        .execute(&pool)
        .await
        .unwrap();
        Self {
            admin,
            pool,
            schema,
            owner,
        }
    }

    async fn create(&self) -> MucRoom {
        let (room, created) = get_or_create_muc_room(&self.pool, LOCALPART, self.owner, OWNER)
            .await
            .unwrap();
        assert!(created);
        room
    }

    async fn join(
        &self,
        room: &MucRoom,
        connection_uuid: Uuid,
        sm_session_id: Option<Uuid>,
    ) -> ClusterMucOccupancy {
        let outcome = claim_cluster_muc_occupancy(
            &self.pool,
            ClusterMucJoin {
                operation_id: Uuid::new_v4(),
                room_id: room.id,
                expected_room_epoch: room.room_epoch,
                expected_config_version: room.config_version,
                principal: ClusterMucPrincipal::Local {
                    user_id: self.owner,
                    bare_jid: "effect-owner@local.test".to_owned(),
                },
                full_jid: OWNER,
                nick: "Creator",
                owner_node_id: NODE,
                connection_uuid,
                connection_epoch: 1,
                sm_session_id,
                occupant_incarnation: Uuid::new_v4(),
                presence_payload: "",
                lease: Duration::from_secs(90),
            },
        )
        .await
        .unwrap();
        let ClusterMucJoinOutcome::Joined(occupant) = outcome else {
            panic!("the creator could not join the locked room: {outcome:?}");
        };
        occupant
    }

    async fn end_creation_window(&self, room: &MucRoom) {
        sqlx::query(
            "UPDATE muc_rooms SET configuration_expires_at=NOW()-INTERVAL '1 second' WHERE id=$1",
        )
        .bind(room.id)
        .execute(&self.pool)
        .await
        .unwrap();
    }

    async fn state(&self, occupant: &ClusterMucOccupancy) -> String {
        sqlx::query_scalar("SELECT state FROM cluster_muc_occupancies WHERE room_id=$1 AND occupant_incarnation=$2")
            .bind(occupant.room_id)
            .bind(occupant.occupant_incarnation)
            .fetch_one(&self.pool)
            .await
            .unwrap()
    }

    async fn finish(self) {
        self.pool.close().await;
        sqlx::query(sqlx::AssertSqlSafe(format!(
            "DROP SCHEMA {} CASCADE",
            self.schema
        )))
        .execute(&self.admin)
        .await
        .unwrap();
        self.admin.close().await;
    }
}

fn incarnation(room: &MucRoom) -> MucRoomIncarnation {
    MucRoomIncarnation {
        room_id: room.id,
        room_epoch: room.room_epoch,
    }
}

fn route(occupancy: &ClusterMucOccupancy) -> MucOccupantRoute {
    MucOccupantRoute {
        nick: occupancy.nick.clone(),
        full_jid: occupancy.full_jid.clone(),
        connection_id: occupancy.connection_uuid,
        cluster_epoch: occupancy.occupant_incarnation,
    }
}

async fn assert_expiry_event(
    pool: &PgPool,
    effects: &CommittedRoomRetirement,
    audience: Option<&ClusterMucOccupancy>,
) {
    let operation = sqlx::query(
        "SELECT o.room_id,o.room_epoch,o.operation_kind,o.authorization_source,
                o.actor_authorization_snapshot,o.audience_snapshot,o.details,o.event_sequence,
                r.destroyed_operation_id,r.destroyed_by,r.destroy_reason
           FROM cluster_muc_operations o JOIN muc_rooms r ON r.id=o.room_id
          WHERE o.operation_id=$1 AND r.destroyed_at IS NOT NULL",
    )
    .bind(effects.operation_id)
    .fetch_one(pool)
    .await
    .unwrap();
    let reason = "initial room configuration lease expired";
    assert_eq!(operation.get::<Uuid, _>("room_id"), effects.room.room_id);
    assert_eq!(
        operation.get::<Uuid, _>("room_epoch"),
        effects.room.room_epoch
    );
    assert_eq!(
        operation.get::<Uuid, _>("destroyed_operation_id"),
        effects.operation_id
    );
    assert_eq!(operation.get::<String, _>("destroyed_by"), "system");
    assert_eq!(operation.get::<String, _>("destroy_reason"), reason);
    assert_eq!(
        operation.get::<String, _>("operation_kind"),
        "locked_expiry"
    );
    assert_eq!(operation.get::<String, _>("authorization_source"), "system");
    assert_eq!(
        operation.get::<Value, _>("details"),
        json!({"reason":reason,"render_policy":{"non_anonymous":true}})
    );
    assert_eq!(
        operation.get::<Value, _>("actor_authorization_snapshot"),
        json!({"lifecycle":"locked_room_lease_expired","clock":"postgresql"})
    );
    let expected_audience: Vec<_> = audience
        .into_iter()
        .map(ClusterMucAudienceSnapshot::from)
        .collect();
    assert_eq!(
        operation.get::<Value, _>("audience_snapshot"),
        serde_json::to_value(expected_audience).unwrap()
    );
    let deliveries = sqlx::query(
        "SELECT target_node_id,audience_kind,recipient_occupant_incarnation,recipient_nick,
                recipient_full_jid,recipient_connection_uuid,recipient_occupancy_epoch,
                recipient_connection_epoch,payload
           FROM cluster_muc_event_outbox WHERE operation_id=$1",
    )
    .bind(effects.operation_id)
    .fetch_all(pool)
    .await
    .unwrap();
    if let Some(occupant) = audience {
        let [delivery] = deliveries.as_slice() else {
            panic!("expected one exact delivery")
        };
        assert_eq!(delivery.get::<String, _>("target_node_id"), NODE);
        assert_eq!(delivery.get::<String, _>("audience_kind"), "occupant");
        assert_eq!(
            delivery.get::<Uuid, _>("recipient_occupant_incarnation"),
            occupant.occupant_incarnation
        );
        assert_eq!(delivery.get::<String, _>("recipient_nick"), occupant.nick);
        assert_eq!(
            delivery.get::<String, _>("recipient_full_jid"),
            occupant.full_jid
        );
        assert_eq!(
            delivery.get::<Uuid, _>("recipient_connection_uuid"),
            occupant.connection_uuid
        );
        assert_eq!(
            delivery.get::<i64, _>("recipient_occupancy_epoch"),
            occupant.occupancy_epoch
        );
        assert_eq!(
            delivery.get::<i64, _>("recipient_connection_epoch"),
            occupant.connection_epoch
        );
        assert_eq!(
            delivery.get::<String, _>("payload"),
            json!({
                "schema":"northstar.cluster-muc-event.v1",
                "operation_id":effects.operation_id,
                "room_id":effects.room.room_id,
                "room_epoch":effects.room.room_epoch,
                "kind":"locked_expiry",
                "event_id":effects.operation_id,
                "event_sequence":operation.get::<i64, _>("event_sequence"),
                "original_audience":ClusterMucAudienceSnapshot::from(occupant),
            })
            .to_string()
        );
    } else {
        assert!(deliveries.is_empty());
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires TEST_DATABASE_URL; uses and removes a random isolated schema"]
async fn occupied_locked_room_expiry_revokes_the_creator_and_returns_exact_effects() {
    let fixture = Fixture::new().await;
    let room = fixture.create().await;
    let creator = fixture.join(&room, Uuid::new_v4(), None).await;
    fixture.end_creation_window(&room).await;
    let effects = delete_expired_locked_muc_room(&fixture.pool, room.id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(effects.room, incarnation(&room));
    assert_eq!(effects.localpart, LOCALPART);
    let [revoked] = effects.occupants.as_slice() else {
        panic!("creator was not retired")
    };
    assert_eq!(revoked.route, route(&creator));
    assert!(revoked.status_codes.is_empty());
    assert_eq!(fixture.state(&creator).await, "revoked");
    assert!(muc_room(&fixture.pool, LOCALPART).await.unwrap().is_none());
    assert_expiry_event(&fixture.pool, &effects, Some(&creator)).await;
    fixture.finish().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires TEST_DATABASE_URL; uses and removes a random isolated schema"]
async fn expiry_effects_do_not_touch_a_replacement_room() {
    let fixture = Fixture::new().await;
    let old = fixture.create().await;
    let sm_session_id = Some(Uuid::new_v4());
    let original = fixture.join(&old, Uuid::new_v4(), sm_session_id).await;
    fixture.end_creation_window(&old).await;
    let effects = delete_expired_locked_muc_rooms(&fixture.pool, 1)
        .await
        .unwrap();
    let original_route = route(&original);
    let legacy = MucOccupantRoute {
        connection_id: Uuid::nil(),
        ..original_route.clone()
    };
    assert_eq!(
        muc_departed_room(&fixture.pool, LOCALPART, &legacy, sm_session_id)
            .await
            .unwrap(),
        Some(incarnation(&old)),
    );
    let replacement = fixture.create().await;
    let newcomer = fixture
        .join(&replacement, original.connection_uuid, sm_session_id)
        .await;
    let [retired] = effects.as_slice() else {
        panic!("expected only the original room")
    };
    assert_eq!(retired.room, incarnation(&old));
    let newcomer_route = route(&newcomer);
    assert_eq!(retired.occupants[0].route.nick, newcomer_route.nick);
    assert_eq!(retired.occupants[0].route.full_jid, newcomer_route.full_jid);
    assert!(retired
        .occupants
        .iter()
        .all(|effect| effect.route != newcomer_route));
    assert_eq!(
        muc_departed_room(&fixture.pool, LOCALPART, &original_route, sm_session_id)
            .await
            .unwrap(),
        Some(retired.room)
    );
    assert!(
        muc_departed_room(&fixture.pool, LOCALPART, &legacy, sm_session_id)
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        sm_teardown_muc_observers(&fixture.pool, retired.room, "Other")
            .await
            .unwrap()
            .is_empty()
    );
    assert_eq!(fixture.state(&newcomer).await, "active");
    assert_eq!(
        muc_room(&fixture.pool, LOCALPART)
            .await
            .unwrap()
            .unwrap()
            .id,
        replacement.id
    );
    fixture.finish().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires TEST_DATABASE_URL; uses and removes a random isolated schema"]
async fn owner_cancel_returns_the_cancelled_incarnation_only() {
    let fixture = Fixture::new().await;
    let old = fixture.create().await;
    let creator = fixture.join(&old, Uuid::new_v4(), None).await;
    assert!(
        cancel_locked_muc_room(&fixture.pool, old.id, "effect-owner@local.test/Tablet")
            .await
            .unwrap()
            .is_none()
    );
    let effects = cancel_locked_muc_room(&fixture.pool, old.id, OWNER)
        .await
        .unwrap()
        .unwrap();
    let replacement = fixture.create().await;
    let newcomer = fixture
        .join(&replacement, creator.connection_uuid, None)
        .await;
    assert_eq!(effects.room, incarnation(&old));
    let [revoked] = effects.occupants.as_slice() else {
        panic!("expected only the cancelled creator")
    };
    assert_eq!(revoked.route, route(&creator));
    assert_ne!(revoked.route, route(&newcomer));
    assert!(cancel_locked_muc_room(&fixture.pool, old.id, OWNER)
        .await
        .unwrap()
        .is_none());
    assert_eq!(fixture.state(&creator).await, "revoked");
    assert_eq!(fixture.state(&newcomer).await, "active");
    fixture.finish().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires TEST_DATABASE_URL; uses and removes a random isolated schema"]
async fn temporary_room_cleanup_deletes_only_the_departed_incarnation() {
    let fixture = Fixture::new().await;
    let old = fixture.create().await;
    let creator = fixture.join(&old, Uuid::new_v4(), None).await;
    assert_eq!(
        transition_cluster_muc_occupancy(
            &fixture.pool,
            Uuid::new_v4(),
            &ClusterMucOccupancyTarget::from(&creator),
            northstar_room_core::muc_authority::MucOccupancyTransition::Leave,
            NODE,
            None,
            None,
            None,
            Duration::from_secs(90),
        )
        .await
        .unwrap(),
        ClusterMucTransitionOutcome::Applied
    );

    let mut barrier = fixture.pool.begin().await.unwrap();
    let blocker: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(&mut *barrier)
        .await
        .unwrap();
    sqlx::query("SELECT id FROM muc_rooms WHERE id=$1 FOR UPDATE")
        .bind(old.id)
        .fetch_one(&mut *barrier)
        .await
        .unwrap();
    let pool = fixture.pool.clone();
    let departed = muc_departed_room(&fixture.pool, LOCALPART, &route(&creator), None)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(departed, incarnation(&old));
    let delayed =
        tokio::spawn(async move { delete_temporary_muc_room(&pool, departed, None).await });
    crate::support::blocked_backend(&fixture.pool, blocker).await;
    assert!(system_tombstone_cluster_muc_room_in_tx(
        &mut barrier,
        Uuid::new_v4(),
        old.id,
        "destroy",
        &json!({}),
        "already retired",
    )
    .await
    .unwrap()
    .is_some());
    barrier.commit().await.unwrap();
    let replacement = fixture.create().await;
    assert!(delayed.await.unwrap().unwrap().is_none());
    assert_eq!(
        muc_departed_room(&fixture.pool, LOCALPART, &route(&creator), None)
            .await
            .unwrap(),
        Some(departed)
    );
    assert!(delete_temporary_muc_room(&fixture.pool, departed, None)
        .await
        .unwrap()
        .is_none());
    assert_eq!(
        muc_room(&fixture.pool, LOCALPART)
            .await
            .unwrap()
            .unwrap()
            .id,
        replacement.id
    );
    let removed = delete_temporary_muc_room(&fixture.pool, incarnation(&replacement), None)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(removed.room, incarnation(&replacement));
    assert!(removed.occupants.is_empty());
    fixture.finish().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires TEST_DATABASE_URL; uses and removes a random isolated schema"]
async fn idle_locked_room_expiry_is_unchanged() {
    let fixture = Fixture::new().await;
    let room = fixture.create().await;
    fixture.end_creation_window(&room).await;
    let effects = delete_expired_locked_muc_rooms(&fixture.pool, 100)
        .await
        .unwrap();
    let [retired] = effects.as_slice() else {
        panic!("expected one idle expiry")
    };
    assert_eq!(retired.room, incarnation(&room));
    assert!(retired.occupants.is_empty());
    assert_expiry_event(&fixture.pool, retired, None).await;
    assert!(muc_room(&fixture.pool, LOCALPART).await.unwrap().is_none());
    assert!(delete_expired_locked_muc_rooms(&fixture.pool, 100)
        .await
        .unwrap()
        .is_empty());
    fixture.finish().await;
}
