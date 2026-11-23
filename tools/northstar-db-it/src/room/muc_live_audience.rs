use super::muc::create_harness_owned_schema;
use crate::support::blocked_backend;
use northstar_room_application::{
    muc_service::{DiscussionCommit, LiveAudience, MucService, RetractionCommit},
    MucRetractionCommand,
};
use northstar_room_core::{
    occupancy::MucOccupantRoute, MucActorAuthority, MucActorPrincipal, MucDiscussion,
    MucDiscussionAdmission, MucRetractionKind, MucRetractionMutation, MucRetractionOutcome,
};
use northstar_room_postgres::{
    cluster_muc::{
        claim_cluster_muc_occupancy, kick_cluster_muc_occupancy, transition_cluster_muc_occupancy,
        ClusterMucJoin, ClusterMucJoinOutcome, ClusterMucOccupancy, ClusterMucOccupancyTarget,
        ClusterMucPrincipal, ClusterMucTransitionOutcome,
    },
    muc::{
        get_or_create_muc_room, muc_room, update_muc_config, MucConfigUpdate,
        MucConfigurationOutcome, MucRoom,
    },
};
use northstar_workflows::{
    account_lifecycle::delete_user_with_roster_locked_in_transaction,
    room_effects::PostgresMucRepository, roster::WorkflowRosterEffects,
};
use sqlx::{postgres::PgPoolOptions, PgPool, Postgres, Transaction};
use std::{collections::HashSet, time::Duration};
use tokio::task::JoinHandle;
use uuid::Uuid;

const DOMAIN: &str = "local.test";
const LOCALPART: &str = "live-audience";
const STANZA: &str = "<message><body>original</body></message>";
const TOMBSTONE: &str = "<message><body>retracted</body></message>";
const LEASE: Duration = Duration::from_secs(120);

struct Fixture {
    admin: PgPool,
    pool: PgPool,
    schema: String,
    room: MucRoom,
    user: Uuid,
    auth_generation: i64,
    actor: MucActorAuthority,
    owner: ClusterMucOccupancy,
    service: MucService<PostgresMucRepository>,
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

        let (user, auth_generation) = account(&pool, "alice").await;
        let full_jid = "alice@local.test/phone";
        let (room, created) = get_or_create_muc_room(&pool, LOCALPART, user, full_jid)
            .await
            .unwrap();
        assert!(created);
        let configured = update_muc_config(
            &pool,
            room.id,
            full_jid,
            MucConfigUpdate {
                title: None,
                description: None,
                persistent: true,
                members_only: false,
                public: false,
                moderated: false,
                non_anonymous: false,
                max_occupants: 20,
                password_hash: None,
                allow_subject_change: true,
                allow_invites: true,
                allow_private_messages: true,
                logging_enabled: true,
                allow_registration: false,
            },
        )
        .await
        .unwrap();
        assert_eq!(configured, MucConfigurationOutcome::Applied);
        let room = muc_room(&pool, LOCALPART).await.unwrap().unwrap();
        let owner = join(&pool, &room, "alice", "alice", DOMAIN, "node-a", Some(user)).await;
        let actor = MucActorAuthority {
            clustered: true,
            expected_room_epoch: room.room_epoch,
            principal: MucActorPrincipal::Local {
                user_id: user,
                local_domain: DOMAIN.to_owned(),
            },
            actor_scope: owner.bare_jid.clone(),
            full_jid: owner.full_jid.clone(),
            nick: owner.nick.clone(),
            occupant_incarnation: owner.occupant_incarnation,
            connection_uuid: owner.connection_uuid,
            expected_role: owner.role.clone(),
            expected_affiliation: owner.affiliation.clone(),
            cluster_target: Some(ClusterMucOccupancyTarget::from(&owner)),
        };
        let service = MucService::new(PostgresMucRepository::new(pool.clone()), DOMAIN);
        Self {
            admin,
            pool,
            schema,
            room,
            user,
            auth_generation,
            actor,
            owner,
            service,
        }
    }

    fn discussion(&self, archived: bool) -> MucDiscussion {
        MucDiscussion {
            id: Uuid::new_v4(),
            room_id: self.room.id,
            actor_scope: self.actor.actor_scope.clone(),
            origin_id: None,
            sender_jid: self.actor.full_jid.clone(),
            nick: self.actor.nick.clone(),
            stanza: STANZA.to_owned(),
            encrypted: false,
            archive_eligible: archived,
            unarchived_stanza_bytes: None,
            retention_days: 0,
            authority: self.actor.clone(),
        }
    }

    fn start_discussion(&self, discussion: MucDiscussion) -> JoinHandle<DiscussionCommit> {
        let service = self.service.clone();
        tokio::spawn(async move {
            service
                .execute_muc_live_discussion(&discussion)
                .await
                .unwrap()
        })
    }

    fn start_retraction(&self, target_id: Uuid) -> JoinHandle<RetractionCommit> {
        let actor = self.actor.clone();
        let service = self.service.clone();
        let room_id = self.room.id;
        tokio::spawn(async move {
            let mutation = MucRetractionMutation {
                action_id: Uuid::new_v4(),
                room_id,
                target_id,
                expected_stanza: STANZA,
                actor_scope: &actor.actor_scope,
                sender_jid: &actor.full_jid,
                nick: &actor.nick,
                tombstone: TOMBSTONE,
                action_stanza: "<message><retracted/></message>",
                reason: None,
                kind: MucRetractionKind::Moderator,
                authority: actor.clone(),
            };
            service
                .execute_muc_live_retraction(MucRetractionCommand { mutation })
                .await
                .unwrap()
        })
    }

    async fn seed_archive(&self) -> Uuid {
        let command = self.discussion(true);
        let commit = self
            .service
            .execute_muc_live_discussion(&command)
            .await
            .unwrap();
        assert_eq!(
            commit.outcome,
            MucDiscussionAdmission::Stored {
                id: command.id,
                archived: true,
            }
        );
        command.id
    }

    async fn archived_stanzas(&self) -> Vec<String> {
        sqlx::query_scalar("SELECT stanza FROM muc_messages WHERE room_id=$1 ORDER BY id")
            .bind(self.room.id)
            .fetch_all(&self.pool)
            .await
            .unwrap()
    }

    async fn assert_user_removed(&self) {
        let present: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM users WHERE id=$1)")
            .bind(self.user)
            .fetch_one(&self.pool)
            .await
            .unwrap();
        assert!(!present);
        let state: String = sqlx::query_scalar(
            "SELECT state FROM cluster_muc_occupancies WHERE room_id=$1 AND occupant_incarnation=$2",
        )
        .bind(self.room.id)
        .bind(self.owner.occupant_incarnation)
        .fetch_one(&self.pool)
        .await
        .unwrap();
        assert_eq!(state, "revoked");
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

async fn account(pool: &PgPool, username: &str) -> (Uuid, i64) {
    let user = Uuid::new_v4();
    let generation = sqlx::query_scalar(
        "INSERT INTO users(id,username,password_hash) VALUES($1,$2,'test') RETURNING auth_generation",
    )
    .bind(user)
    .bind(username)
    .fetch_one(pool)
    .await
    .unwrap();
    (user, generation)
}

async fn join(
    pool: &PgPool,
    room: &MucRoom,
    name: &str,
    nick: &str,
    domain: &str,
    node: &str,
    user: Option<Uuid>,
) -> ClusterMucOccupancy {
    let bare_jid = format!("{name}@{domain}");
    let full_jid = format!("{bare_jid}/phone");
    let principal = match user {
        Some(user_id) => ClusterMucPrincipal::Local { user_id, bare_jid },
        None => ClusterMucPrincipal::Federated {
            bare_jid,
            authenticated_domain: domain.to_owned(),
        },
    };
    let joined = claim_cluster_muc_occupancy(
        pool,
        ClusterMucJoin {
            operation_id: Uuid::new_v4(),
            room_id: room.id,
            expected_room_epoch: room.room_epoch,
            expected_config_version: room.config_version,
            principal,
            full_jid: &full_jid,
            nick,
            owner_node_id: node,
            connection_uuid: Uuid::new_v4(),
            connection_epoch: 1,
            sm_session_id: None,
            occupant_incarnation: Uuid::new_v4(),
            presence_payload: "<presence/>",
            lease: LEASE,
        },
    )
    .await
    .unwrap();
    let ClusterMucJoinOutcome::Joined(occupant) = joined else {
        panic!("fixture join: {joined:?}")
    };
    occupant
}

fn route(occupant: &ClusterMucOccupancy) -> (String, MucOccupantRoute) {
    (
        occupant.owner_node_id.clone(),
        MucOccupantRoute {
            nick: occupant.nick.clone(),
            full_jid: occupant.full_jid.clone(),
            connection_id: occupant.connection_uuid,
            cluster_epoch: occupant.occupant_incarnation,
        },
    )
}

async fn lock_user(tx: &mut Transaction<'_, Postgres>, user: Uuid) {
    let locked: Uuid = sqlx::query_scalar("SELECT id FROM northstar_lock_user_rows_update($1)")
        .bind(&[user][..])
        .fetch_one(&mut **tx)
        .await
        .unwrap();
    assert_eq!(locked, user);
}

async fn backend(tx: &mut Transaction<'_, Postgres>) -> i32 {
    sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(&mut **tx)
        .await
        .unwrap()
}

async fn assert_room_locks(fixture: &Fixture, pid: i32, expected: bool) {
    let (namespace, room, occupancy): (bool, bool, bool) = sqlx::query_as(
        "SELECT
            COALESCE(bool_or(locktype='advisory' AND objsubid=1
                AND classid::bigint=((hashtextextended($2::text,29) >> 32) & 4294967295)
                AND objid::bigint=(hashtextextended($2::text,29) & 4294967295)), false),
            COALESCE(bool_or(relation='muc_rooms'::regclass), false),
            COALESCE(bool_or(relation='cluster_muc_occupancies'::regclass), false)
          FROM pg_locks WHERE pid=$1 AND granted",
    )
    .bind(pid)
    .bind(fixture.room.id.to_string())
    .fetch_one(&fixture.pool)
    .await
    .unwrap();
    assert_eq!((namespace, room, occupancy), (expected, expected, false));
}

async fn completed<T>(task: JoinHandle<T>) -> T {
    tokio::time::timeout(Duration::from_secs(5), task)
        .await
        .expect("transaction did not complete")
        .unwrap()
}

async fn audience_at_admission(retract: bool) {
    let fixture = Fixture::new().await;
    let victim = join(
        &fixture.pool,
        &fixture.room,
        "bob",
        "bob",
        "remote.test",
        "node-a",
        None,
    )
    .await;
    let federated = join(
        &fixture.pool,
        &fixture.room,
        "eve",
        "eve",
        "remote.test",
        "node-b",
        None,
    )
    .await;
    let (sleeping_user, _) = account(&fixture.pool, "sleeping").await;
    let sleeping = join(
        &fixture.pool,
        &fixture.room,
        "sleeping",
        "sleeping",
        DOMAIN,
        "node-b",
        Some(sleeping_user),
    )
    .await;
    assert_eq!(
        transition_cluster_muc_occupancy(
            &fixture.pool,
            Uuid::new_v4(),
            &ClusterMucOccupancyTarget::from(&sleeping),
            "suspend",
            "node-b",
            None,
            None,
            Some(Uuid::new_v4()),
            LEASE,
        )
        .await
        .unwrap(),
        ClusterMucTransitionOutcome::Applied
    );
    let target_id = if retract {
        Some(fixture.seed_archive().await)
    } else {
        None
    };

    let mut fence = fixture.pool.begin().await.unwrap();
    lock_user(&mut fence, fixture.user).await;
    let blocker = backend(&mut fence).await;
    let (discussion, retraction) = match target_id {
        Some(target_id) => (None, Some(fixture.start_retraction(target_id))),
        None => (
            Some(fixture.start_discussion(fixture.discussion(true))),
            None,
        ),
    };
    let waiter = blocked_backend(&fixture.pool, blocker).await;
    assert_room_locks(&fixture, waiter, false).await;
    let kicked = tokio::time::timeout(
        Duration::from_secs(5),
        kick_cluster_muc_occupancy(
            &fixture.pool,
            Uuid::new_v4(),
            &ClusterMucOccupancyTarget::from(&fixture.owner),
            &ClusterMucOccupancyTarget::from(&victim),
            None,
        ),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(kicked, ClusterMucTransitionOutcome::Applied);
    fence.commit().await.unwrap();

    let audience: LiveAudience = match (discussion, retraction) {
        (Some(task), None) => {
            let result = completed(task).await;
            assert!(matches!(
                result.outcome,
                MucDiscussionAdmission::Stored { archived: true, .. }
            ));
            result.audience.unwrap()
        }
        (None, Some(task)) => {
            let result = completed(task).await;
            assert_eq!(result.outcome, MucRetractionOutcome::Applied);
            result.audience.unwrap()
        }
        _ => unreachable!(),
    };
    let newcomer = join(
        &fixture.pool,
        &fixture.room,
        "bob",
        "bob",
        "remote.test",
        "node-a",
        None,
    )
    .await;
    let routes: HashSet<_> = audience.routes().iter().cloned().collect();
    assert_eq!(audience.routes().len(), 3);
    assert!(audience.routes().iter().all(|(_, route)| route.is_exact()));
    assert_eq!(
        routes,
        HashSet::from([route(&fixture.owner), route(&federated), route(&sleeping)])
    );
    assert!(!routes.contains(&route(&victim)));
    assert!(!routes.contains(&route(&newcomer)));
    fixture.cleanup().await;
}

async fn begin_delete(pool: &PgPool) -> Transaction<'static, Postgres> {
    let mut tx = pool.begin().await.unwrap();
    for statement in [
        "SET TRANSACTION ISOLATION LEVEL SERIALIZABLE",
        "SELECT northstar_upload_capacity_lock()",
        "SET LOCAL lock_timeout='2s'",
    ] {
        sqlx::query(statement).execute(&mut *tx).await.unwrap();
    }
    tx
}

async fn quiesce(tx: &mut Transaction<'_, Postgres>, user: Uuid, generation: i64) {
    let disabled: bool = sqlx::query_scalar("SELECT northstar_user_quiesce_deletion($1,$2)")
        .bind(user)
        .bind(generation)
        .fetch_one(&mut **tx)
        .await
        .unwrap();
    assert!(disabled);
}

async fn finish_delete(mut tx: Transaction<'_, Postgres>, user: Uuid, generation: i64) {
    quiesce(&mut tx, user, generation).await;
    delete_user_with_roster_locked_in_transaction(
        &WorkflowRosterEffects,
        &mut tx,
        user,
        DOMAIN,
        Default::default(),
        Some((
            user,
            "user.account.remove",
            serde_json::json!({"source":"test"}),
        )),
        None,
    )
    .await
    .unwrap();
    tx.commit().await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires TEST_DATABASE_URL; uses and removes a random isolated schema"]
async fn discussion_audience_is_the_occupancy_at_admission() {
    audience_at_admission(false).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires TEST_DATABASE_URL; uses and removes a random isolated schema"]
async fn retraction_audience_is_the_occupancy_at_admission() {
    audience_at_admission(true).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires TEST_DATABASE_URL; uses and removes a random isolated schema"]
async fn account_deletion_then_groupchat_admission_completes_in_one_order() {
    let fixture = Fixture::new().await;
    let mut deletion = begin_delete(&fixture.pool).await;
    lock_user(&mut deletion, fixture.user).await;
    let blocker = backend(&mut deletion).await;
    let admission = fixture.start_discussion(fixture.discussion(true));
    let waiter = blocked_backend(&fixture.pool, blocker).await;
    assert_room_locks(&fixture, waiter, false).await;
    finish_delete(deletion, fixture.user, fixture.auth_generation).await;
    let result = completed(admission).await;
    assert_eq!(result.outcome, MucDiscussionAdmission::Unauthorized);
    assert!(result.audience.is_none());
    assert!(fixture.archived_stanzas().await.is_empty());
    fixture.assert_user_removed().await;
    fixture.cleanup().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires TEST_DATABASE_URL; uses and removes a random isolated schema"]
async fn groupchat_admission_then_account_deletion_completes_in_one_order() {
    let fixture = Fixture::new().await;
    let mut room_guard = fixture.pool.begin().await.unwrap();
    sqlx::query("SELECT id FROM muc_rooms WHERE id=$1 FOR UPDATE")
        .bind(fixture.room.id)
        .fetch_one(&mut *room_guard)
        .await
        .unwrap();
    let room_blocker = backend(&mut room_guard).await;
    let command = fixture.discussion(false);
    let id = command.id;
    let admission = fixture.start_discussion(command);
    let admission_pid = blocked_backend(&fixture.pool, room_blocker).await;
    assert_room_locks(&fixture, admission_pid, true).await;
    let pool = fixture.pool.clone();
    let user = fixture.user;
    let generation = fixture.auth_generation;
    let deletion = tokio::spawn(async move {
        let mut tx = begin_delete(&pool).await;
        lock_user(&mut tx, user).await;
        finish_delete(tx, user, generation).await;
    });
    let delete_pid = blocked_backend(&fixture.pool, admission_pid).await;
    assert_room_locks(&fixture, delete_pid, false).await;
    room_guard.commit().await.unwrap();

    let result = completed(admission).await;
    assert_eq!(
        result.outcome,
        MucDiscussionAdmission::Stored {
            id,
            archived: false
        }
    );
    assert_eq!(result.audience.unwrap().routes(), &[route(&fixture.owner)]);
    completed(deletion).await;
    fixture.assert_user_removed().await;
    let late = completed(fixture.start_discussion(fixture.discussion(true))).await;
    assert_eq!(late.outcome, MucDiscussionAdmission::Unauthorized);
    assert!(late.audience.is_none());
    assert!(fixture.archived_stanzas().await.is_empty());
    fixture.cleanup().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires TEST_DATABASE_URL; uses and removes a random isolated schema"]
async fn retraction_and_account_deletion_take_user_before_room() {
    let fixture = Fixture::new().await;
    let target = fixture.seed_archive().await;
    let mut deletion = begin_delete(&fixture.pool).await;
    lock_user(&mut deletion, fixture.user).await;
    let blocker = backend(&mut deletion).await;
    let retraction = fixture.start_retraction(target);
    let waiter = blocked_backend(&fixture.pool, blocker).await;
    assert_room_locks(&fixture, waiter, false).await;
    finish_delete(deletion, fixture.user, fixture.auth_generation).await;
    let result = completed(retraction).await;
    assert_eq!(result.outcome, MucRetractionOutcome::Unauthorized);
    assert!(result.audience.is_none());
    assert_eq!(fixture.archived_stanzas().await, [STANZA]);
    fixture.assert_user_removed().await;
    fixture.cleanup().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires TEST_DATABASE_URL; uses and removes a random isolated schema"]
async fn disabled_account_is_rejected_under_the_user_fence() {
    let fixture = Fixture::new().await;
    let mut disabling = fixture.pool.begin().await.unwrap();
    lock_user(&mut disabling, fixture.user).await;
    let blocker = backend(&mut disabling).await;
    let admission = fixture.start_discussion(fixture.discussion(true));
    let waiter = blocked_backend(&fixture.pool, blocker).await;
    assert_room_locks(&fixture, waiter, false).await;
    quiesce(&mut disabling, fixture.user, fixture.auth_generation).await;
    disabling.commit().await.unwrap();
    let result = completed(admission).await;
    assert_eq!(result.outcome, MucDiscussionAdmission::Unauthorized);
    assert!(result.audience.is_none());
    let disabled: bool = sqlx::query_scalar("SELECT is_disabled FROM users WHERE id=$1")
        .bind(fixture.user)
        .fetch_one(&fixture.pool)
        .await
        .unwrap();
    assert!(disabled);
    assert!(fixture.archived_stanzas().await.is_empty());
    fixture.cleanup().await;
}
