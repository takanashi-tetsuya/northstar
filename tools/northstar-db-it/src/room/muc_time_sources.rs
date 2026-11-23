use super::muc::create_harness_owned_schema;
use crate::support::blocked_backend;
use northstar_room_application::muc_service::{
    ClusterMucConfigurationOutcome, ClusterMucJoin, ClusterMucJoinOutcome,
    ClusterMucOccupancyTarget, ClusterMucPrincipal, MucAdminSnapshot, MucConfigUpdate,
    MucConfigurationOutcome, MucJoinCommitOutcome, MucJoinProjectionRequest, MucManagementViewer,
    MucReadPrincipal, MucRoom, MucRoomRead, MucService,
};
use northstar_room_core::{FixedMucClock, MucTimeSources, SequentialMucIds};
use northstar_time::{DateTime, TimeDelta, Utc};
use northstar_workflows::room_effects::PostgresMucRepository;
use sqlx::{postgres::PgPoolOptions, PgPool};
use std::{sync::Arc, time::Duration};
use uuid::Uuid;

const DOMAIN: &str = "local.test";
const OWNER: &str = "owner@local.test/phone";
const BARE_OWNER: &str = "owner@local.test";

struct Fixture {
    admin: PgPool,
    pool: PgPool,
    schema: String,
    owner: Uuid,
    database_at: DateTime<Utc>,
    ids: Arc<SequentialMucIds>,
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
        let schema = format!("muc_history_test_{}", Uuid::new_v4().simple());
        create_harness_owned_schema(&admin, &schema).await;
        let connection_schema = schema.clone();
        let pool = PgPoolOptions::new()
            .max_connections(8)
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
        sqlx::query("INSERT INTO users(id,username,password_hash) VALUES($1,'owner','test')")
            .bind(owner)
            .execute(&pool)
            .await
            .unwrap();
        let database_at = sqlx::query_scalar("SELECT clock_timestamp()")
            .fetch_one(&pool)
            .await
            .unwrap();
        Self {
            admin,
            pool,
            schema,
            owner,
            database_at,
            ids: Arc::new(SequentialMucIds::default()),
        }
    }

    fn service(&self, database_expired: bool) -> MucService<PostgresMucRepository> {
        // The application clock is on the other side of the database deadline.
        let skew = TimeDelta::seconds(if database_expired { -600 } else { 600 });
        let at = self.database_at.checked_add_signed(skew).unwrap();
        let time_sources = MucTimeSources::new(Arc::new(FixedMucClock(at)), self.ids.clone());
        MucService::new_with_time_sources(
            PostgresMucRepository::new(self.pool.clone()),
            DOMAIN,
            time_sources,
        )
    }

    fn principal(&self) -> ClusterMucPrincipal {
        ClusterMucPrincipal::Local {
            user_id: self.owner,
            bare_jid: BARE_OWNER.to_owned(),
        }
    }

    async fn reserve(
        &self,
        service: &MucService<PostgresMucRepository>,
        localpart: &str,
    ) -> MucRoomRead {
        let (view, created) = service
            .get_or_create_local_room(localpart, self.owner, OWNER)
            .await
            .unwrap();
        assert!(created);
        assert!(view.room.is_locked());
        view
    }

    async fn expire(&self, room: &MucRoom) {
        assert_eq!(
            sqlx::query(
                "UPDATE muc_rooms SET configuration_expires_at=clock_timestamp() WHERE id=$1",
            )
            .bind(room.id)
            .execute(&self.pool)
            .await
            .unwrap()
            .rows_affected(),
            1,
        );
    }

    async fn join(
        &self,
        service: &MucService<PostgresMucRepository>,
        room: &MucRoom,
    ) -> MucJoinCommitOutcome {
        let facts = service.time_sources().prepare_request();
        let address = format!("{}@conference.{DOMAIN}", room.localpart);
        service
            .commit_muc_join(
                ClusterMucJoin {
                    operation_id: service.time_sources().new_uuid(),
                    room_id: room.id,
                    expected_room_epoch: room.room_epoch,
                    expected_config_version: room.config_version,
                    principal: self.principal(),
                    full_jid: OWNER,
                    nick: "Owner",
                    owner_node_id: "test-node",
                    connection_uuid: Uuid::new_v4(),
                    connection_epoch: 1,
                    sm_session_id: None,
                    occupant_incarnation: facts.id,
                    presence_payload: "",
                    lease: Duration::from_secs(120),
                },
                MucJoinProjectionRequest {
                    room_jid: &address,
                    verified_password_hash: None,
                    include_history: false,
                    history_since: None,
                },
            )
            .await
            .unwrap()
    }

    async fn cleanup(self) {
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

fn config() -> MucConfigUpdate<'static> {
    MucConfigUpdate {
        title: Some("Accepted"),
        description: None,
        persistent: true,
        members_only: false,
        public: false,
        moderated: false,
        non_anonymous: false,
        max_occupants: 20,
        password_hash: None,
        allow_subject_change: false,
        allow_invites: true,
        allow_private_messages: true,
        logging_enabled: true,
        allow_registration: false,
    }
}

fn skewed_deadline(
    service: &MucService<PostgresMucRepository>,
    view: &MucRoomRead,
    database_expired: bool,
) {
    let application_at = service.time_sources().now();
    assert_eq!(
        view.room.configuration_expires_at.unwrap() <= application_at,
        !database_expired
    );
    assert_eq!(view.configuration_expired, database_expired);
    assert_eq!(view.can_configure_locked_room(OWNER), !database_expired);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires TEST_DATABASE_URL; uses and removes a random isolated schema"]
async fn locked_room_join_uses_the_database_deadline_under_clock_skew() {
    let fixture = Fixture::new().await;
    let ahead = fixture.service(false);
    let behind = fixture.service(true);
    let first = fixture.reserve(&ahead, "join-open-window").await;
    assert_eq!(first.room.id, Uuid::from_u128(1));
    skewed_deadline(&ahead, &first, false);
    assert!(matches!(
        fixture.join(&ahead, &first.room).await,
        MucJoinCommitOutcome::Committed(_)
    ));

    let second = fixture.reserve(&behind, "join-closed-window").await;
    fixture.expire(&second.room).await;
    let (view, created) = behind
        .get_or_create_local_room(&second.room.localpart, fixture.owner, OWNER)
        .await
        .unwrap();
    assert!(!created);
    assert_eq!(view.room.id, second.room.id);
    skewed_deadline(&behind, &view, true);
    assert!(matches!(
        fixture.join(&behind, &view.room).await,
        MucJoinCommitOutcome::Claim(outcome) if matches!(*outcome, ClusterMucJoinOutcome::RoomLocked)
    ));
    fixture.cleanup().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires TEST_DATABASE_URL; uses and removes a random isolated schema"]
async fn owner_configuration_uses_the_database_deadline_under_clock_skew() {
    let fixture = Fixture::new().await;
    let ahead = fixture.service(false);
    let behind = fixture.service(true);
    // Open both occupancies under the same source before either owner SET.
    let first = fixture.reserve(&ahead, "owner-open-window").await;
    let second = fixture.reserve(&ahead, "owner-closed-window").await;
    for view in [first, second] {
        let MucJoinCommitOutcome::Committed(join) = fixture.join(&ahead, &view.room).await else {
            panic!("owner could not join within the database window");
        };
        let expired = view.room.localpart == "owner-closed-window";
        let service = if expired { &behind } else { &ahead };
        if expired {
            fixture.expire(&view.room).await;
        }
        let view = service
            .room_for_command(&view.room.localpart)
            .await
            .unwrap()
            .unwrap();
        skewed_deadline(service, &view, expired);
        let form = service
            .owner_form(
                &view.room.localpart,
                MucManagementViewer {
                    principal: MucReadPrincipal::Local {
                        user_id: fixture.owner,
                        bare_jid: BARE_OWNER,
                    },
                    full_jid: OWNER,
                    occupancy: None,
                },
            )
            .await
            .unwrap();
        assert!(matches!(
            (expired, form),
            (false, MucAdminSnapshot::Authorized(_)) | (true, MucAdminSnapshot::Stale)
        ));
        let target = ClusterMucOccupancyTarget::from(&join.actor);
        assert_eq!(
            service
                .update_local_cluster_config(
                    service.time_sources().new_uuid(),
                    view.room.id,
                    view.room.room_epoch,
                    view.room.config_version,
                    &target,
                    &fixture.principal(),
                    OWNER,
                    config(),
                )
                .await
                .unwrap(),
            if expired {
                ClusterMucConfigurationOutcome::Expired
            } else {
                ClusterMucConfigurationOutcome::Applied
            },
        );
        assert_eq!(
            service
                .read_room(&view.room.localpart)
                .await
                .unwrap()
                .unwrap()
                .room
                .is_locked(),
            expired,
        );
    }
    fixture.cleanup().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires TEST_DATABASE_URL; uses and removes a random isolated schema"]
async fn legacy_owner_configuration_checks_deadline_after_the_room_row_wait() {
    let fixture = Fixture::new().await;
    let service = fixture.service(true);
    let view = fixture.reserve(&service, "owner-wait").await;
    let mut blocker = fixture.pool.begin().await.unwrap();
    sqlx::query("SELECT id FROM muc_rooms WHERE id=$1 FOR UPDATE")
        .bind(view.room.id)
        .fetch_one(&mut *blocker)
        .await
        .unwrap();
    let blocker_pid = sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(&mut *blocker)
        .await
        .unwrap();
    let room_id = view.room.id;
    let setter = tokio::spawn(async move {
        service
            .update_local_legacy_config(room_id, OWNER, config())
            .await
            .unwrap()
    });
    let setter_pid = blocked_backend(&fixture.pool, blocker_pid).await;
    let deadline_is_after_setter_start: bool = sqlx::query_scalar(
        "UPDATE muc_rooms SET configuration_expires_at=clock_timestamp() WHERE id=$1
         RETURNING configuration_expires_at > (SELECT xact_start FROM pg_stat_activity WHERE pid=$2)",
    )
    .bind(room_id)
    .bind(setter_pid)
    .fetch_one(&mut *blocker)
    .await
    .unwrap();
    assert!(deadline_is_after_setter_start);
    blocker.commit().await.unwrap();
    assert_eq!(setter.await.unwrap(), MucConfigurationOutcome::Expired,);
    let room = fixture
        .service(true)
        .read_room("owner-wait")
        .await
        .unwrap()
        .unwrap();
    assert!(room.configuration_expired);
    assert!(room.room.is_locked());
    assert_ne!(room.room.title.as_deref(), Some("Accepted"));
    fixture.cleanup().await;
}
