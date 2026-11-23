use northstar_room_application::muc_service::{
    ClusterMucJoin, ClusterMucOccupancy, ClusterMucOccupancyTarget, ClusterMucPrincipal,
    ClusterMucTransitionOutcome, MucJoinCommitOutcome, MucJoinContinuityRepository,
    MucJoinProjection, MucJoinProjectionRequest, SmMucResume,
};
use northstar_room_core::muc_authority::MucOccupancyTransition;
use northstar_room_postgres::{cluster_muc, muc};
use northstar_time::{DateTime, Utc};
use northstar_workflows::room_effects::PostgresMucRepository;
use sqlx::{postgres::PgPoolOptions, PgPool, Postgres, Transaction};
use std::time::Duration;
use uuid::Uuid;

const OWNER: &str = "continuity-owner@local.test/Phone";
const GUEST: &str = "continuity-guest@local.test/Phone";
const NODE: &str = "continuity-node";
const LEASE: Duration = Duration::from_secs(90);
const ROOM_JID: &str = "continuity@conference.local.test";

struct Fixture {
    admin: PgPool,
    pool: PgPool,
    schema: String,
    room: muc::MucRoom,
    owner: Uuid,
    guest: Uuid,
}

impl Fixture {
    async fn new(activate: bool) -> Self {
        let url = std::env::var("TEST_DATABASE_URL")
            .expect("set TEST_DATABASE_URL to an isolated PostgreSQL database");
        let admin = PgPoolOptions::new()
            .max_connections(1)
            .acquire_timeout(Duration::from_secs(60))
            .connect(&url)
            .await
            .unwrap();
        let schema = format!("muc_lifecycle_test_{}", Uuid::new_v4().simple());
        super::muc::create_harness_owned_schema(&admin, &schema).await;
        let connection_schema = schema.clone();
        let pool = PgPoolOptions::new()
            .max_connections(4)
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
        let guest = Uuid::new_v4();
        sqlx::query(
            "INSERT INTO users(id,username,password_hash) VALUES
                     ($1,'continuity-owner','test'),($2,'continuity-guest','test')",
        )
        .bind(owner)
        .bind(guest)
        .execute(&pool)
        .await
        .unwrap();
        let (mut room, created) = muc::get_or_create_muc_room(&pool, "continuity", owner, OWNER)
            .await
            .unwrap();
        assert!(created);
        if activate {
            sqlx::query(
                "UPDATE muc_rooms SET configuration_state='active',
                         configuration_owner_jid=NULL,configuration_expires_at=NULL WHERE id=$1",
            )
            .bind(room.id)
            .execute(&pool)
            .await
            .unwrap();
            room = muc::muc_room(&pool, "continuity").await.unwrap().unwrap();
        }
        Self {
            admin,
            pool,
            schema,
            room,
            owner,
            guest,
        }
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

    fn join(&self, owner: bool) -> ClusterMucJoin<'static> {
        let (user_id, bare_jid, full_jid, nick) = if owner {
            (self.owner, "continuity-owner@local.test", OWNER, "Owner")
        } else {
            (self.guest, "continuity-guest@local.test", GUEST, "Guest")
        };
        ClusterMucJoin {
            operation_id: Uuid::new_v4(),
            room_id: self.room.id,
            expected_room_epoch: self.room.room_epoch,
            expected_config_version: self.room.config_version,
            principal: ClusterMucPrincipal::Local {
                user_id,
                bare_jid: bare_jid.to_owned(),
            },
            full_jid,
            nick,
            owner_node_id: NODE,
            connection_uuid: Uuid::new_v4(),
            connection_epoch: 1,
            sm_session_id: None,
            occupant_incarnation: Uuid::new_v4(),
            presence_payload: "<show>away</show>",
            lease: LEASE,
        }
    }

    async fn locked_room(&self) -> (Transaction<'_, Postgres>, i32) {
        let mut guard = self.pool.begin().await.unwrap();
        sqlx::query("SELECT id FROM muc_rooms WHERE id=$1 FOR UPDATE")
            .bind(self.room.id)
            .execute(&mut *guard)
            .await
            .unwrap();
        let pid = sqlx::query_scalar("SELECT pg_backend_pid()")
            .fetch_one(&mut *guard)
            .await
            .unwrap();
        (guard, pid)
    }

    async fn associated_actor(&self) -> (ClusterMucOccupancyTarget, Uuid) {
        let actor = claim(
            PostgresMucRepository::new(self.pool.clone()),
            self.join(true),
        )
        .await;
        let target = ClusterMucOccupancyTarget::from(&actor.actor);
        let session = Uuid::new_v4();
        assert!(
            cluster_muc::associate_cluster_muc_sm_session(&self.pool, &target, NODE, session)
                .await
                .unwrap()
        );
        (target, session)
    }
}

fn projection_request() -> MucJoinProjectionRequest<'static> {
    MucJoinProjectionRequest {
        room_jid: ROOM_JID,
        verified_password_hash: None,
        include_history: true,
        history_since: None,
    }
}

async fn claim(
    repository: PostgresMucRepository,
    request: ClusterMucJoin<'_>,
) -> Box<MucJoinProjection> {
    let MucJoinCommitOutcome::Committed(projection) = repository
        .commit_muc_join(request, projection_request())
        .await
        .unwrap()
    else {
        panic!("join refused in continuity fixture");
    };
    projection
}

async fn subject_and_history(tx: &mut Transaction<'_, Postgres>, room_id: Uuid, value: &str) {
    sqlx::query("UPDATE muc_rooms SET subject=$2,subject_changed_at=clock_timestamp() WHERE id=$1")
        .bind(room_id)
        .bind(value)
        .execute(&mut **tx)
        .await
        .unwrap();
    sqlx::query(
        "INSERT INTO muc_messages(id,room_id,sender_jid,nick,stanza,encrypted)
                 VALUES($1,$2,$3,'Owner',$4,FALSE)",
    )
    .bind(Uuid::new_v4())
    .bind(room_id)
    .bind(OWNER)
    .bind(format!("<message><body>{value}</body></message>"))
    .execute(&mut **tx)
    .await
    .unwrap();
}

async fn expire(
    tx: &mut Transaction<'_, Postgres>,
    target: &ClusterMucOccupancyTarget,
) -> DateTime<Utc> {
    sqlx::query_scalar(
        "UPDATE cluster_muc_occupancies SET lease_until=clock_timestamp()-interval '1 second'
                        WHERE room_id=$1 AND occupant_incarnation=$2 RETURNING lease_until",
    )
    .bind(target.room_id)
    .bind(target.occupant_incarnation)
    .fetch_one(&mut **tx)
    .await
    .unwrap()
}

async fn pending_routes(
    pool: &PgPool,
    target: &ClusterMucOccupancyTarget,
) -> Vec<(Uuid, String, Uuid, i64)> {
    sqlx::query_as("SELECT delivery_id,target_node_id,recipient_connection_uuid,recipient_connection_epoch
                      FROM cluster_muc_event_outbox WHERE room_id=$1 AND recipient_occupant_incarnation=$2
                     ORDER BY delivery_id")
        .bind(target.room_id).bind(target.occupant_incarnation).fetch_all(pool).await.unwrap()
}

async fn handoff_count(pool: &PgPool, target: &ClusterMucOccupancyTarget) -> i64 {
    sqlx::query_scalar(
        "SELECT COUNT(*) FROM cluster_muc_delivery_handoffs handoff
                         JOIN cluster_muc_event_outbox delivery USING (delivery_id)
                        WHERE delivery.room_id=$1 AND delivery.recipient_occupant_incarnation=$2",
    )
    .bind(target.room_id)
    .bind(target.occupant_incarnation)
    .fetch_one(pool)
    .await
    .unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires TEST_DATABASE_URL; uses and removes a random isolated schema"]
async fn join_commit_returns_the_affiliation_committed_with_the_claim() {
    let fixture = Fixture::new(true).await;
    let repository = PostgresMucRepository::new(fixture.pool.clone());
    let before: Option<String> = sqlx::query_scalar(
        "SELECT affiliation FROM muc_affiliations WHERE room_id=$1 AND user_id=$2",
    )
    .bind(fixture.room.id)
    .bind(fixture.guest)
    .fetch_optional(&fixture.pool)
    .await
    .unwrap();
    assert_eq!(before, None);
    let (mut guard, pid) = fixture.locked_room().await;
    let join = fixture.join(false);
    let waiter = tokio::spawn(claim(repository, join));
    crate::support::blocked_backend(&fixture.pool, pid).await;
    sqlx::query("INSERT INTO muc_affiliations(room_id,user_id,affiliation) VALUES($1,$2,'admin')")
        .bind(fixture.room.id)
        .bind(fixture.guest)
        .execute(&mut *guard)
        .await
        .unwrap();
    guard.commit().await.unwrap();
    let joined = waiter.await.unwrap();
    assert_eq!(
        (
            joined.actor.affiliation.as_str(),
            joined.actor.role.as_str()
        ),
        ("admin", "moderator")
    );
    fixture.cleanup().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires TEST_DATABASE_URL; uses and removes a random isolated schema"]
async fn join_projection_reads_subject_and_history_at_the_claim_boundary() {
    let fixture = Fixture::new(true).await;
    let repository = PostgresMucRepository::new(fixture.pool.clone());
    let owner = claim(repository.clone(), fixture.join(true)).await;
    let (mut before, _) = fixture.locked_room().await;
    subject_and_history(&mut before, fixture.room.id, "before").await;
    before.commit().await.unwrap();

    let mut history_guard = fixture.pool.begin().await.unwrap();
    sqlx::query("LOCK TABLE muc_messages IN ACCESS EXCLUSIVE MODE")
        .execute(&mut *history_guard)
        .await
        .unwrap();
    let guard_pid = sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(&mut *history_guard)
        .await
        .unwrap();
    let guest = fixture.join(false);
    let (incarnation, connection) = (guest.occupant_incarnation, guest.connection_uuid);
    let waiter = tokio::spawn(claim(repository, guest));
    let claim_pid = crate::support::blocked_backend(&fixture.pool, guard_pid).await;
    assert!(
        cluster_muc::cluster_muc_occupancy_target(
            &fixture.pool,
            fixture.room.id,
            incarnation,
            connection
        )
        .await
        .unwrap()
        .is_none(),
        "claim committed before reading history"
    );

    let pool = fixture.pool.clone();
    let room_id = fixture.room.id;
    let writer = tokio::spawn(async move {
        let mut later = pool.begin().await.unwrap();
        subject_and_history(&mut later, room_id, "after").await;
        later.commit().await.unwrap();
    });
    crate::support::blocked_backend(&fixture.pool, claim_pid).await;
    history_guard.commit().await.unwrap();
    let joined = waiter.await.unwrap();
    writer.await.unwrap();
    assert_eq!(joined.subject.as_deref(), Some("before"));
    assert_eq!(joined.history.len(), 1);
    assert!(joined.history[0].stanza.contains("<body>before</body>"));
    let [roster_owner] = joined.roster.as_slice() else {
        panic!("expected one prior actor");
    };
    assert_eq!(
        (
            &roster_owner.full_jid,
            &roster_owner.occupant_id,
            &roster_owner.payload
        ),
        (
            &owner.actor.full_jid,
            &owner.occupant_id,
            &owner.actor.presence_payload
        )
    );
    assert_eq!(
        muc::muc_room(&fixture.pool, "continuity")
            .await
            .unwrap()
            .unwrap()
            .subject
            .as_deref(),
        Some("after")
    );
    assert_eq!(
        muc::muc_history_since(&fixture.pool, fixture.room.id, 100, None)
            .await
            .unwrap()
            .len(),
        2
    );
    fixture.cleanup().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires TEST_DATABASE_URL; uses and removes a random isolated schema"]
async fn refused_first_join_keeps_the_locked_reservation() {
    let fixture = Fixture::new(false).await;
    let repository = PostgresMucRepository::new(fixture.pool.clone());
    let (mut guard, pid) = fixture.locked_room().await;
    let join = fixture.join(true);
    let waiter = tokio::spawn(async move {
        repository
            .commit_muc_join(join, projection_request())
            .await
            .unwrap()
    });
    crate::support::blocked_backend(&fixture.pool, pid).await;
    sqlx::query("UPDATE muc_rooms SET password_hash='replacement' WHERE id=$1")
        .bind(fixture.room.id)
        .execute(&mut *guard)
        .await
        .unwrap();
    guard.commit().await.unwrap();
    assert!(matches!(
        waiter.await.unwrap(),
        MucJoinCommitOutcome::PasswordChanged
    ));
    let reserved = muc::muc_room(&fixture.pool, "continuity")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        (reserved.id, reserved.room_epoch),
        (fixture.room.id, fixture.room.room_epoch)
    );
    assert_eq!(reserved.configuration_owner_jid.as_deref(), Some(OWNER));
    assert!(
        cluster_muc::cluster_muc_room_is_empty(&fixture.pool, reserved.id)
            .await
            .unwrap()
    );
    fixture.cleanup().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires TEST_DATABASE_URL; uses and removes a random isolated schema"]
async fn suspend_and_resume_reject_a_lease_that_expired_after_lookup() {
    let fixture = Fixture::new(true).await;
    let (active, active_session) = fixture.associated_actor().await;
    let pool = fixture.pool.clone();
    let guest = claim(
        PostgresMucRepository::new(pool.clone()),
        fixture.join(false),
    )
    .await;
    let suspended = ClusterMucOccupancyTarget::from(&guest.actor);
    let suspended_session = Uuid::new_v4();
    assert!(cluster_muc::associate_cluster_muc_sm_session(
        &pool,
        &suspended,
        NODE,
        suspended_session
    )
    .await
    .unwrap());
    assert!(cluster_muc::suspend_cluster_muc_authority(
        &pool,
        Uuid::new_v4(),
        &suspended,
        NODE,
        suspended_session,
        LEASE
    )
    .await
    .unwrap()
    .is_some());
    for (target, session, transition, state) in [
        (
            active,
            active_session,
            MucOccupancyTransition::Suspend,
            "active",
        ),
        (
            suspended,
            suspended_session,
            MucOccupancyTransition::Resume,
            "suspended",
        ),
    ] {
        assert_eq!(
            cluster_muc::cluster_muc_occupancy_target(
                &pool,
                target.room_id,
                target.occupant_incarnation,
                target.connection_uuid
            )
            .await
            .unwrap()
            .as_ref(),
            Some(&target)
        );
        let routes = pending_routes(&pool, &target).await;
        assert!(!routes.is_empty());
        let handoffs = handoff_count(&pool, &target).await;
        let (mut guard, pid) = fixture.locked_room().await;
        let attempt = target.clone();
        let connection_pool = pool.clone();
        let waiter = tokio::spawn(async move {
            let resume = transition == MucOccupancyTransition::Resume;
            cluster_muc::transition_cluster_muc_occupancy(
                &connection_pool,
                Uuid::new_v4(),
                &attempt,
                transition,
                NODE,
                resume.then(Uuid::new_v4),
                resume.then_some(attempt.connection_epoch + 1),
                Some(session),
                LEASE,
            )
            .await
            .unwrap()
        });
        crate::support::blocked_backend(&pool, pid).await;
        let expired_at = expire(&mut guard, &target).await;
        guard.commit().await.unwrap();
        assert_eq!(waiter.await.unwrap(), ClusterMucTransitionOutcome::Stale);
        let row = cluster_muc::cluster_muc_exact_occupancy_snapshot(&pool, &target)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            (row.state.as_str(), row.lease_until, row.sm_session_id),
            (state, expired_at, Some(session))
        );
        assert_eq!(pending_routes(&pool, &target).await, routes);
        assert_eq!(handoff_count(&pool, &target).await, handoffs);
    }
    fixture.cleanup().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires TEST_DATABASE_URL; uses and removes a random isolated schema"]
async fn elapsed_exact_departure_still_removes_its_row() {
    let fixture = Fixture::new(true).await;
    let (target, _) = fixture.associated_actor().await;
    let (mut guard, _) = fixture.locked_room().await;
    expire(&mut guard, &target).await;
    guard.commit().await.unwrap();
    let lookup = cluster_muc::cluster_muc_occupancy_target_for_disconnect(
        &fixture.pool,
        "continuity",
        OWNER,
        "Owner",
        target.occupant_incarnation,
        target.connection_uuid,
        NODE,
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(lookup, target);
    assert_eq!(
        cluster_muc::transition_cluster_muc_occupancy(
            &fixture.pool,
            Uuid::new_v4(),
            &lookup,
            MucOccupancyTransition::Leave,
            NODE,
            None,
            None,
            None,
            LEASE,
        )
        .await
        .unwrap(),
        ClusterMucTransitionOutcome::Applied
    );
    let ended = cluster_muc::cluster_muc_exact_occupancy_snapshot(&fixture.pool, &target)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(ended.state, "left");
    assert!(
        cluster_muc::cluster_muc_room_is_empty(&fixture.pool, fixture.room.id)
            .await
            .unwrap()
    );
    fixture.cleanup().await;
}

async fn resume(
    pool: &PgPool,
    target: &ClusterMucOccupancyTarget,
    session: Uuid,
    connection_id: Uuid,
) -> Option<ClusterMucOccupancy> {
    PostgresMucRepository::new(pool.clone())
        .resume_muc_authority(SmMucResume {
            operation_id: Uuid::new_v4(),
            target,
            owner_node_id: NODE,
            connection_id,
            sm_session_id: session,
            lease: LEASE,
        })
        .await
        .unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires TEST_DATABASE_URL; uses and removes a random isolated schema"]
async fn standalone_resume_replaces_the_postgres_connection_and_fences_the_old_one() {
    let fixture = Fixture::new(true).await;
    let pool = &fixture.pool;
    let (target, session) = fixture.associated_actor().await;
    let suspend =
        northstar_workflows::sm_suspension::PostgresSmSuspensionRepository::new(pool.clone());
    use northstar_session_application::sm_suspension::{
        MucSuspensionRequest, SmSuspensionRepository,
    };
    let route = northstar_room_core::occupancy::MucOccupantRoute {
        nick: target.nick.clone(),
        full_jid: target.full_jid.clone(),
        connection_id: target.connection_uuid,
        cluster_epoch: target.occupant_incarnation,
    };
    let suspended = suspend
        .suspend_muc_occupant(MucSuspensionRequest {
            operation_id: Uuid::new_v4(),
            room_localpart: "continuity",
            occupant: &route,
            sm_session_id: session,
            node_id: NODE,
            lease: LEASE,
        })
        .await
        .unwrap()
        .unwrap();
    assert_eq!(suspended.state, "suspended");
    let retry = suspend
        .suspend_muc_occupant(MucSuspensionRequest {
            operation_id: Uuid::new_v4(),
            room_localpart: "continuity",
            occupant: &route,
            sm_session_id: session,
            node_id: NODE,
            lease: LEASE,
        })
        .await
        .unwrap()
        .unwrap();
    assert_eq!(retry.lease_until, suspended.lease_until);
    let restart = cluster_muc::suspended_cluster_muc_occupancy(
        pool,
        target.room_id,
        target.room_epoch,
        session,
        OWNER,
        "Owner",
    )
    .await
    .unwrap()
    .unwrap();
    let new_connection = Uuid::new_v4();
    let restored = resume(
        pool,
        &ClusterMucOccupancyTarget::from(&restart),
        session,
        new_connection,
    )
    .await
    .unwrap();
    assert_eq!(
        (
            restored.role.as_str(),
            restored.affiliation.as_str(),
            restored.state.as_str()
        ),
        ("moderator", "owner", "active")
    );
    assert_eq!(restored.connection_epoch, target.connection_epoch + 1);
    assert_eq!(
        cluster_muc::cluster_muc_occupancy_target(
            pool,
            target.room_id,
            target.occupant_incarnation,
            new_connection
        )
        .await
        .unwrap(),
        Some(ClusterMucOccupancyTarget::from(&restored))
    );
    assert!(cluster_muc::cluster_muc_occupancy_target(
        pool,
        target.room_id,
        target.occupant_incarnation,
        target.connection_uuid
    )
    .await
    .unwrap()
    .is_none());
    fixture.cleanup().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires TEST_DATABASE_URL; uses and removes a random isolated schema"]
async fn resume_without_suspended_authority_fails_closed() {
    let fixture = Fixture::new(true).await;
    let pool = &fixture.pool;
    let (target, session) = fixture.associated_actor().await;
    let new_connection = Uuid::new_v4();
    let mut missing = target.clone();
    missing.occupant_incarnation = Uuid::new_v4();
    assert!(resume(pool, &missing, session, new_connection)
        .await
        .is_none());
    assert!(resume(pool, &target, session, new_connection)
        .await
        .is_none());
    assert!(cluster_muc::suspend_cluster_muc_authority(
        pool,
        Uuid::new_v4(),
        &target,
        NODE,
        session,
        LEASE
    )
    .await
    .unwrap()
    .is_some());
    assert!(resume(pool, &target, Uuid::new_v4(), new_connection)
        .await
        .is_none());
    let row = cluster_muc::cluster_muc_exact_occupancy_snapshot(pool, &target)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        (row.state.as_str(), row.connection_uuid, row.sm_session_id),
        ("suspended", target.connection_uuid, Some(session))
    );
    fixture.cleanup().await;
}
