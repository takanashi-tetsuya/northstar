use super::muc::{await_authorization_pause, create_harness_owned_schema};
use northstar_room_application::muc_service::{
    MucAdminList, MucAdminListKind, MucAdminSnapshot, MucManagementViewer, MucOccupancyProof,
    MucOccupantIdSecretState, MucReadPrincipal, MucReadRepository, MucRoomView, MucRoomViewKind,
    MucRoomViewer,
};
use northstar_room_core::occupancy::MucOccupantRoute;
use northstar_room_postgres::cluster_muc::{
    claim_cluster_muc_occupancy, ClusterMucJoin, ClusterMucJoinOutcome, ClusterMucPrincipal,
};
use northstar_room_postgres::muc::{
    delete_muc_room, get_or_create_muc_room, install_muc_authorization_test_pause, muc_room,
    register_local_muc_member, set_federated_muc_affiliation, set_muc_affiliation,
    update_muc_config, MucConfigUpdate, MucConfigurationOutcome, MucRoom,
};
use northstar_workflows::room_effects::PostgresMucRepository;
use sqlx::{postgres::PgPoolOptions, PgPool};
use std::time::Duration;
use uuid::Uuid;

const ROOM: &str = "snapshot";
const NODE: &str = "snapshot-node";
const OWNER: &str = "owner@local.test/phone";
const REMOTE: &str = "mod@remote.test/phone";
static PAUSES: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

struct Harness {
    admin: PgPool,
    pool: PgPool,
    schema: String,
    owner: Uuid,
    member: Uuid,
}

impl Harness {
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
        let member = Uuid::new_v4();
        sqlx::query("INSERT INTO users(id,username,password_hash) VALUES ($1,'owner','test'),($2,'member','test')")
            .bind(owner).bind(member).execute(&pool).await.unwrap();
        Self {
            admin,
            pool,
            schema,
            owner,
            member,
        }
    }

    async fn room(&self, configure: bool) -> MucRoom {
        let (room, created) = get_or_create_muc_room(&self.pool, ROOM, self.owner, OWNER)
            .await
            .unwrap();
        assert!(created);
        if !configure {
            return room;
        }
        let config = MucConfigUpdate {
            title: Some("Snapshot"),
            description: None,
            persistent: true,
            members_only: false,
            public: true,
            moderated: false,
            non_anonymous: false,
            max_occupants: 100,
            password_hash: None,
            allow_subject_change: false,
            allow_invites: true,
            allow_private_messages: true,
            logging_enabled: true,
            allow_registration: true,
        };
        assert_eq!(
            update_muc_config(&self.pool, room.id, OWNER, config)
                .await
                .unwrap(),
            MucConfigurationOutcome::Applied
        );
        muc_room(&self.pool, ROOM).await.unwrap().unwrap()
    }

    async fn owner_route(&self, room: &MucRoom, nick: &str) -> MucOccupantRoute {
        self.join(
            room,
            ClusterMucPrincipal::Local {
                user_id: self.owner,
                bare_jid: "owner@local.test".to_owned(),
            },
            OWNER,
            nick,
        )
        .await
    }

    async fn remote_route(&self, room: &MucRoom, nick: &str) -> MucOccupantRoute {
        self.join(
            room,
            ClusterMucPrincipal::Federated {
                bare_jid: "mod@remote.test".to_owned(),
                authenticated_domain: "remote.test".to_owned(),
            },
            REMOTE,
            nick,
        )
        .await
    }

    async fn join(
        &self,
        room: &MucRoom,
        principal: ClusterMucPrincipal,
        full_jid: &str,
        nick: &str,
    ) -> MucOccupantRoute {
        let route = MucOccupantRoute {
            full_jid: full_jid.to_owned(),
            nick: nick.to_owned(),
            connection_id: Uuid::new_v4(),
            cluster_epoch: Uuid::new_v4(),
        };
        let outcome = claim_cluster_muc_occupancy(
            &self.pool,
            ClusterMucJoin {
                operation_id: Uuid::new_v4(),
                room_id: room.id,
                expected_room_epoch: room.room_epoch,
                expected_config_version: room.config_version,
                principal,
                full_jid,
                nick,
                owner_node_id: NODE,
                connection_uuid: route.connection_id,
                connection_epoch: 1,
                sm_session_id: None,
                occupant_incarnation: route.cluster_epoch,
                presence_payload: "<presence/>",
                lease: Duration::from_secs(30),
            },
        )
        .await
        .unwrap();
        assert!(
            matches!(outcome, ClusterMucJoinOutcome::Joined(_)),
            "{outcome:?}"
        );
        route
    }

    async fn revoke(&self, route: &MucOccupantRoute) {
        assert_eq!(sqlx::query("UPDATE cluster_muc_occupancies SET state='revoked',ended_at=clock_timestamp() WHERE occupant_incarnation=$1")
            .bind(route.cluster_epoch).execute(&self.pool).await.unwrap().rows_affected(), 1);
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
    }
}

fn local_viewer<'a>(user_id: Uuid, bare_jid: &'a str, full_jid: &'a str) -> MucRoomViewer<'a> {
    MucRoomViewer {
        full_jid: Some(full_jid),
        principal: Some(MucReadPrincipal::Local { user_id, bare_jid }),
        federated: false,
        occupancy: None,
    }
}

fn owner_viewer(user_id: Uuid) -> MucManagementViewer<'static> {
    MucManagementViewer {
        principal: MucReadPrincipal::Local {
            user_id,
            bare_jid: "owner@local.test",
        },
        full_jid: OWNER,
        occupancy: None,
    }
}

fn proof<'a>(route: &'a MucOccupantRoute, domain: Option<&'a str>) -> MucOccupancyProof<'a> {
    MucOccupancyProof {
        route,
        authenticated_domain: domain,
        node_id: NODE,
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires TEST_DATABASE_URL; uses and removes a random isolated schema"]
async fn room_reads_do_not_write() {
    let _pauses = PAUSES.lock().await;
    let harness = Harness::new().await;
    let room = harness.room(false).await;
    let route = harness.owner_route(&room, "Owner").await;
    sqlx::query("UPDATE muc_rooms SET occupant_id_secret=NULL,configuration_expires_at=clock_timestamp()-interval '1 minute' WHERE id=$1")
        .bind(room.id).execute(&harness.pool).await.unwrap();
    let versions = || async {
        let room_version: (String, i64, bool, bool) = sqlx::query_as(
            "SELECT xmin::text,config_version,occupant_id_secret IS NULL,destroyed_at IS NULL FROM muc_rooms WHERE id=$1",
        ).bind(room.id).fetch_one(&harness.pool).await.unwrap();
        let occupancy: (String, String, String) = sqlx::query_as(
            "SELECT xmin::text,lease_until::text,state FROM cluster_muc_occupancies WHERE occupant_incarnation=$1",
        ).bind(route.cluster_epoch).fetch_one(&harness.pool).await.unwrap();
        (room_version, occupancy)
    };
    let before = versions().await;
    let repo = PostgresMucRepository::new(harness.pool.clone());
    let read = repo.read_room(ROOM).await.unwrap().unwrap();
    assert_eq!(
        read.occupant_id_secret_state,
        MucOccupantIdSecretState::AbsentLegacy
    );
    assert!(read.configuration_expired);
    let viewer = local_viewer(harness.owner, "owner@local.test", OWNER);
    for kind in [
        MucRoomViewKind::Info {
            include_mirror: true,
        },
        MucRoomViewKind::Items,
        MucRoomViewKind::Registration,
    ] {
        assert!(matches!(repo.room_view(ROOM, viewer, kind).await.unwrap(),
            MucRoomView::Found { room, .. } if room.room.id == read.room.id));
    }
    assert!(matches!(
        repo.owner_form(ROOM, owner_viewer(harness.owner), "local.test")
            .await
            .unwrap(),
        MucAdminSnapshot::Stale
    ));
    assert_eq!(versions().await, before);
    harness.finish().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires TEST_DATABASE_URL; uses and removes a random isolated schema"]
async fn room_items_snapshot_binds_one_room_incarnation() {
    let _pauses = PAUSES.lock().await;
    let harness = Harness::new().await;
    let old_room = harness.room(true).await;
    harness.owner_route(&old_room, "Before").await;
    let repo = PostgresMucRepository::new(harness.pool.clone());
    let (entered, resume) = install_muc_authorization_test_pause("room_items_snapshot");
    let reader = repo.clone();
    let owner = harness.owner;
    let read = tokio::spawn(async move {
        reader
            .room_view(
                ROOM,
                local_viewer(owner, "owner@local.test", OWNER),
                MucRoomViewKind::Items,
            )
            .await
            .unwrap()
    });
    await_authorization_pause(&entered, "items visibility before roster").await;
    delete_muc_room(&harness.pool, old_room.id).await.unwrap();
    let new_room = harness.room(true).await;
    assert_ne!(new_room.room_epoch, old_room.room_epoch);
    harness.owner_route(&new_room, "After").await;
    resume.notify_one();
    assert!(
        matches!(read.await.unwrap(), MucRoomView::Found { room, nicks, .. }
        if room.room.id == old_room.id && nicks == ["Before"])
    );
    assert!(
        matches!(repo.room_view(ROOM, local_viewer(owner, "owner@local.test", OWNER), MucRoomViewKind::Items).await.unwrap(),
        MucRoomView::Found { room, nicks, .. } if room.room.id == new_room.id && nicks == ["After"])
    );
    harness.finish().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires TEST_DATABASE_URL; uses and removes a random isolated schema"]
async fn registration_view_serializes_against_unregister() {
    let _pauses = PAUSES.lock().await;
    let harness = Harness::new().await;
    let room = harness.room(true).await;
    register_local_muc_member(&harness.pool, room.id, harness.member, "Reserved")
        .await
        .unwrap();
    let repo = PostgresMucRepository::new(harness.pool.clone());
    let viewer = local_viewer(
        harness.member,
        "member@local.test",
        "member@local.test/phone",
    );
    let (entered, resume) = install_muc_authorization_test_pause("registration_snapshot");
    let reader = repo.clone();
    let read = tokio::spawn(async move {
        reader
            .room_view(ROOM, viewer, MucRoomViewKind::Registration)
            .await
            .unwrap()
    });
    await_authorization_pause(&entered, "registration room before reservation").await;
    let mut writer = harness.pool.begin().await.unwrap();
    sqlx::query("UPDATE muc_rooms SET allow_registration=false WHERE id=$1")
        .bind(room.id)
        .execute(&mut *writer)
        .await
        .unwrap();
    assert_eq!(
        sqlx::query(
            "DELETE FROM muc_affiliations WHERE room_id=$1 AND user_id=$2 AND affiliation='member'"
        )
        .bind(room.id)
        .bind(harness.member)
        .execute(&mut *writer)
        .await
        .unwrap()
        .rows_affected(),
        1
    );
    writer.commit().await.unwrap();
    resume.notify_one();
    assert!(
        matches!(read.await.unwrap(), MucRoomView::Found { room, reserved_nick: Some(nick), .. }
        if room.room.allow_registration && nick == "Reserved")
    );
    assert!(
        matches!(repo.room_view(ROOM, viewer, MucRoomViewKind::Registration).await.unwrap(),
        MucRoomView::Found { room, reserved_nick: None, .. } if !room.room.allow_registration)
    );
    harness.finish().await;
}

fn federated_manager(route: &MucOccupantRoute) -> MucManagementViewer<'_> {
    MucManagementViewer {
        principal: MucReadPrincipal::Federated {
            bare_jid: "mod@remote.test",
            domain: "remote.test",
        },
        full_jid: REMOTE,
        occupancy: Some(proof(route, Some("remote.test"))),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires TEST_DATABASE_URL; uses and removes a random isolated schema"]
async fn federated_admin_list_uses_committed_requester_authority() {
    let _pauses = PAUSES.lock().await;
    let harness = Harness::new().await;
    let room = harness.room(true).await;
    set_federated_muc_affiliation(&harness.pool, room.id, "mod@remote.test", "admin")
        .await
        .unwrap();
    let route = harness.remote_route(&room, "Moderator").await;
    let repo = PostgresMucRepository::new(harness.pool.clone());
    let kind = MucAdminListKind::Role("moderator");
    assert!(
        matches!(repo.admin_list(ROOM, federated_manager(&route), "local.test", kind).await.unwrap(),
        MucAdminSnapshot::Authorized(MucAdminList::Roles(list)) if list.entries.len() == 1)
    );
    let (entered, resume) = install_muc_authorization_test_pause("federated_admin_snapshot");
    let old_proof = route.clone();
    let read = tokio::spawn(async move {
        repo.admin_list(ROOM, federated_manager(&old_proof), "local.test", kind)
            .await
            .unwrap()
    });
    await_authorization_pause(&entered, "federated admin before authority").await;
    set_federated_muc_affiliation(&harness.pool, room.id, "mod@remote.test", "member")
        .await
        .unwrap();
    sqlx::query("UPDATE cluster_muc_occupancies SET role='participant',affiliation='member' WHERE occupant_incarnation=$1")
        .bind(route.cluster_epoch).execute(&harness.pool).await.unwrap();
    resume.notify_one();
    assert!(matches!(
        read.await.unwrap(),
        MucAdminSnapshot::Unauthorized
    ));
    harness.finish().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires TEST_DATABASE_URL; uses and removes a random isolated schema"]
async fn owner_form_rejects_a_requester_who_lost_ownership() {
    let _pauses = PAUSES.lock().await;
    let harness = Harness::new().await;
    let room = harness.room(true).await;
    set_muc_affiliation(&harness.pool, room.id, "member", "owner")
        .await
        .unwrap();
    let repo = PostgresMucRepository::new(harness.pool.clone());
    let viewer = owner_viewer(harness.owner);
    assert!(matches!(
        repo.owner_form(ROOM, viewer, "local.test").await.unwrap(),
        MucAdminSnapshot::Authorized(_)
    ));
    let (entered, resume) = install_muc_authorization_test_pause("owner_form_snapshot");
    let read =
        tokio::spawn(async move { repo.owner_form(ROOM, viewer, "local.test").await.unwrap() });
    await_authorization_pause(&entered, "owner form before authority").await;
    set_muc_affiliation(&harness.pool, room.id, "owner", "member")
        .await
        .unwrap();
    resume.notify_one();
    assert!(matches!(
        read.await.unwrap(),
        MucAdminSnapshot::Unauthorized
    ));
    harness.finish().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires TEST_DATABASE_URL; uses and removes a random isolated schema"]
async fn occupant_iq_authority_names_the_exact_target() {
    let harness = Harness::new().await;
    let room = harness.room(true).await;
    let sender = harness.owner_route(&room, "Sender").await;
    let target = harness.remote_route(&room, "Target").await;
    let repo = PostgresMucRepository::new(harness.pool.clone());
    let first = repo
        .occupant_iq(ROOM, Some(proof(&sender, None)), "Target", NODE, None)
        .await
        .unwrap();
    assert_eq!(first.sender.as_ref(), Some(&sender));
    assert_eq!(first.target.as_ref(), Some(&target));
    harness.revoke(&target).await;
    let replacement = harness.remote_route(&room, "Target").await;
    let second = repo
        .occupant_iq(ROOM, Some(proof(&sender, None)), "Target", NODE, None)
        .await
        .unwrap();
    assert_eq!(second.target.as_ref(), Some(&replacement));
    assert_eq!(target.full_jid, replacement.full_jid);
    assert_ne!(first.target, second.target);
    harness.finish().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires TEST_DATABASE_URL; uses and removes a random isolated schema"]
async fn self_ping_activity_requires_the_exact_own_occupancy() {
    let harness = Harness::new().await;
    let room = harness.room(true).await;
    let route = harness.remote_route(&room, "Moderator").await;
    let repo = PostgresMucRepository::new(harness.pool.clone());
    let lease = || async {
        sqlx::query_scalar::<_, f64>("SELECT extract(epoch FROM lease_until)::float8 FROM cluster_muc_occupancies WHERE occupant_incarnation=$1")
            .bind(route.cluster_epoch).fetch_one(&harness.pool).await.unwrap()
    };
    let before = lease().await;
    assert!(repo
        .refresh_muc_occupant_activity(ROOM, proof(&route, Some("other.test")))
        .await
        .unwrap()
        .is_none());
    assert_eq!(lease().await, before);
    assert_eq!(
        repo.refresh_muc_occupant_activity(ROOM, proof(&route, Some("remote.test")))
            .await
            .unwrap(),
        Some(route.clone())
    );
    assert!(lease().await > before);
    sqlx::query("UPDATE cluster_muc_occupancies SET lease_until=clock_timestamp()-interval '1 second' WHERE occupant_incarnation=$1")
        .bind(route.cluster_epoch).execute(&harness.pool).await.unwrap();
    assert!(repo
        .refresh_muc_occupant_activity(ROOM, proof(&route, Some("remote.test")))
        .await
        .unwrap()
        .is_none());
    harness.revoke(&route).await;
    let replacement = harness.remote_route(&room, "Moderator").await;
    assert!(repo
        .refresh_muc_occupant_activity(ROOM, proof(&route, Some("remote.test")))
        .await
        .unwrap()
        .is_none());
    assert_eq!(
        repo.refresh_muc_occupant_activity(ROOM, proof(&replacement, Some("remote.test")))
            .await
            .unwrap(),
        Some(replacement)
    );
    harness.finish().await;
}
