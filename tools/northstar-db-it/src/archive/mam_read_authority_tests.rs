//! PostgreSQL coverage for the account, room and occupancy in a MAM snapshot.

use northstar_archive_application::{
    FederatedMamAdmissionOutcome, FederatedMamMetadataCommand, FederatedMamOutboxLimits,
    FederatedMamStreamRequest, FederatedMamStreamWriter, MamAccountOutcome, MamArchiveQuery,
    MamDbRoomReadOutcome, MamLocalAuthority, MamMetadataCommand, MamMetadataResult,
    MamOccupancyProof, MamPreferences, MamPreferencesGetCommand, MamPreferencesSetCommand,
    MamPreferencesWriter, MamQueryCommand, MamQueryRepository, MamQueryResult, MamQueryScope,
    MamRoomAccessOutcome, MamRoomReadAuthority, MamRsmPage,
};
use northstar_workflows::mam_repository::PostgresMamRepository;
use northstar_workflows::mam_room::{
    mam_federated_room_archive_page_authorized, mam_room_archive_page_authorized,
};
use sqlx::{postgres::PgPoolOptions, PgConnection, PgPool};
use std::time::Duration;
use uuid::Uuid;

pub(super) struct Fixture {
    url: String,
    schema: String,
    admin: PgPool,
    pub(super) pool: PgPool,
}

impl Fixture {
    pub(super) async fn new() -> Self {
        let url = std::env::var("TEST_DATABASE_URL")
            .expect("set TEST_DATABASE_URL to an isolated PostgreSQL database");
        let admin = PgPoolOptions::new()
            .max_connections(1)
            .acquire_timeout(Duration::from_secs(60))
            .connect(&url)
            .await
            .unwrap();
        let schema = format!("history_identity_test_{}", Uuid::new_v4().simple());
        sqlx::query(sqlx::AssertSqlSafe(format!("CREATE SCHEMA {schema}")))
            .execute(&admin)
            .await
            .unwrap();
        eprintln!("isolated_schema_created={schema}");
        let pool = Self::connect(&url, &schema, false).await;
        crate::support::migrate(&pool).await.unwrap();
        Self {
            url,
            schema,
            admin,
            pool,
        }
    }

    async fn connect(url: &str, schema: &str, read_only: bool) -> PgPool {
        let statement = format!("SET search_path TO {schema}");
        PgPoolOptions::new()
            .max_connections(8)
            .acquire_timeout(Duration::from_secs(60))
            .after_connect(move |connection, _| {
                let statement = statement.clone();
                Box::pin(async move {
                    sqlx::query(sqlx::AssertSqlSafe(statement.as_str()))
                        .execute(&mut *connection)
                        .await?;
                    if read_only {
                        sqlx::query("SET default_transaction_read_only = on")
                            .execute(&mut *connection)
                            .await?;
                    }
                    Ok(())
                })
            })
            .connect(url)
            .await
            .unwrap()
    }

    pub(super) async fn cleanup(self) {
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

async fn account(pool: &PgPool, username: &str) -> MamLocalAuthority {
    let id = Uuid::new_v4();
    let auth_generation = sqlx::query_scalar(
        "INSERT INTO users(id,username,password_hash) VALUES($1,$2,'test')
         RETURNING auth_generation",
    )
    .bind(id)
    .bind(username)
    .fetch_one(pool)
    .await
    .unwrap();
    MamLocalAuthority {
        id,
        username: username.to_owned(),
        auth_generation,
    }
}

pub(super) fn viewer(full_jid: &str, occupancy: Option<MamOccupancyProof>) -> MamRoomReadAuthority {
    MamRoomReadAuthority {
        full_jid: full_jid.to_owned(),
        occupancy,
    }
}

pub(super) fn query() -> MamArchiveQuery {
    MamArchiveQuery {
        with_jid: None,
        start: None,
        end: None,
        before_id: None,
        after_id: None,
        ids: Vec::new(),
        page: MamRsmPage::First,
        max: 50,
    }
}

fn room_scope(
    room: &str,
    account: &MamLocalAuthority,
    authority: &MamRoomReadAuthority,
) -> MamQueryScope {
    MamQueryScope::Room {
        localpart: room.to_owned(),
        account: account.clone(),
        authority: authority.clone(),
    }
}

async fn password_room(pool: &PgPool, name: &str) -> Uuid {
    sqlx::query_scalar(
        "INSERT INTO muc_rooms(id,localpart,password_hash,occupant_id_secret)
         VALUES(gen_random_uuid(),$1,'test-password',$2) RETURNING id",
    )
    .bind(name)
    .bind(vec![7_u8; 32])
    .fetch_one(pool)
    .await
    .unwrap()
}

async fn occupancy(
    pool: &PgPool,
    room: Uuid,
    occupancy_epoch: i64,
    full_jid: &str,
    local_user_id: Option<Uuid>,
    lease_seconds: i32,
) -> MamOccupancyProof {
    let proof = MamOccupancyProof {
        occupant_incarnation: Uuid::new_v4(),
        connection_uuid: Uuid::new_v4(),
    };
    let (identity_kind, domain) = if local_user_id.is_some() {
        ("local", None)
    } else {
        ("federated", Some("remote.test"))
    };
    sqlx::query(
        "INSERT INTO cluster_muc_occupancies(
             room_id,room_epoch,occupant_incarnation,occupancy_epoch,config_version,
             identity_kind,local_user_id,bare_jid,full_jid,nick,authenticated_domain,
             owner_node_id,connection_uuid,connection_epoch,state,role,affiliation,lease_until)
         SELECT id,room_epoch,$2,$3,config_version,$4,$5,$6,$7,$3::bigint::text,$8,
                'mam-test-node',$9,1,'active','participant','none',
                clock_timestamp()+($10::int*INTERVAL '1 second')
           FROM muc_rooms WHERE id=$1",
    )
    .bind(room)
    .bind(proof.occupant_incarnation)
    .bind(occupancy_epoch)
    .bind(identity_kind)
    .bind(local_user_id)
    .bind(full_jid.split_once('/').unwrap().0)
    .bind(full_jid)
    .bind(domain)
    .bind(proof.connection_uuid)
    .bind(lease_seconds)
    .execute(pool)
    .await
    .unwrap();
    proof
}

async fn leave(connection: &mut PgConnection, room: Uuid, proof: MamOccupancyProof) {
    assert_eq!(
        sqlx::query(
            "UPDATE cluster_muc_occupancies SET state='left',ended_at=clock_timestamp()
              WHERE room_id=$1 AND occupant_incarnation=$2",
        )
        .bind(room)
        .bind(proof.occupant_incarnation)
        .execute(connection)
        .await
        .unwrap()
        .rows_affected(),
        1,
    );
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RoomReply {
    Allowed,
    Missing,
    Forbidden,
}

async fn assert_room_replies(
    repository: &PostgresMamRepository,
    room: &str,
    account: Option<&MamLocalAuthority>,
    authority: &MamRoomReadAuthority,
    expected: RoomReply,
) {
    let (form, metadata, page) = if let Some(account) = account {
        let scope = room_scope(room, account, authority);
        let form = repository
            .authorize_room(room, account, authority)
            .await
            .unwrap();
        let metadata = repository
            .get_boundaries(MamMetadataCommand {
                scope: scope.clone(),
            })
            .await
            .unwrap();
        let page = match repository
            .query_archive(MamQueryCommand {
                scope,
                query: query(),
            })
            .await
            .unwrap()
        {
            MamQueryResult::Page { room: Some(_), .. } => RoomReply::Allowed,
            MamQueryResult::ItemNotFound => RoomReply::Missing,
            MamQueryResult::Forbidden => RoomReply::Forbidden,
            other => panic!("unexpected local room page: {other:?}"),
        };
        (form, metadata, page)
    } else {
        let form = repository
            .authorize_federated_room(room, authority)
            .await
            .unwrap();
        let command = FederatedMamMetadataCommand::from_authenticated_actor(
            room.to_owned(),
            "remote.test",
            &authority.full_jid,
            authority.occupancy,
        )
        .unwrap();
        let metadata = repository.get_federated_boundaries(command).await.unwrap();
        let page = match repository
            .admit_federated_room_stream(
                FederatedMamOutboxLimits {
                    ttl_seconds: 300,
                    max_rows: 100,
                    max_bytes: 1024 * 1024,
                    max_per_domain: 100,
                },
                FederatedMamStreamRequest::new("remote.test", room, authority, &query()),
                |_| {
                    assert_eq!(
                        expected,
                        RoomReply::Allowed,
                        "unauthorized page reached rendering"
                    );
                    Ok(vec![
                        "<iq xmlns='jabber:server' type='result' id='mam-test'/>".to_owned(),
                    ])
                },
            )
            .await
            .unwrap()
        {
            FederatedMamAdmissionOutcome::Queued => RoomReply::Allowed,
            FederatedMamAdmissionOutcome::Missing => RoomReply::Missing,
            FederatedMamAdmissionOutcome::Forbidden => RoomReply::Forbidden,
            other => panic!("unexpected federated room page: {other:?}"),
        };
        (form, metadata, page)
    };
    let form = match form {
        MamRoomAccessOutcome::Allowed(_) => RoomReply::Allowed,
        MamRoomAccessOutcome::Missing => RoomReply::Missing,
        MamRoomAccessOutcome::Forbidden => RoomReply::Forbidden,
        other => panic!("unexpected room form: {other:?}"),
    };
    let metadata = match metadata {
        MamMetadataResult::Boundaries { room: Some(_), .. } => RoomReply::Allowed,
        MamMetadataResult::ItemNotFound => RoomReply::Missing,
        MamMetadataResult::Forbidden => RoomReply::Forbidden,
        other => panic!("unexpected room metadata: {other:?}"),
    };
    assert_eq!(
        (form, metadata, page),
        (expected, expected, expected),
        "{authority:?}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires TEST_DATABASE_URL; uses and removes a random isolated schema"]
async fn muc_mam_requires_the_exact_live_occupancy_on_all_read_surfaces() {
    let fixture = Fixture::new().await;
    let pool = &fixture.pool;
    let repository = PostgresMamRepository::new(pool.clone());
    let account = account(pool, "viewer").await;
    let room = password_room(pool, "password-room").await;
    let mut connection = pool.acquire().await.unwrap();

    for (index, local, full_jid, other_resource) in [
        (
            1,
            Some(&account),
            "viewer@local.test/Phone",
            "viewer@local.test/Tablet",
        ),
        (
            2,
            None,
            "viewer@remote.test/Phone",
            "viewer@remote.test/Tablet",
        ),
    ] {
        let local_id = local.map(|account| account.id);
        let valid = occupancy(pool, room, index, full_jid, local_id, 600).await;
        let expires = occupancy(pool, room, index + 2, other_resource, local_id, -60).await;
        for (authority, expected) in [
            (viewer(full_jid, Some(valid)), RoomReply::Allowed),
            (viewer(full_jid, None), RoomReply::Forbidden),
            (
                viewer(
                    full_jid,
                    Some(MamOccupancyProof {
                        connection_uuid: Uuid::new_v4(),
                        ..valid
                    }),
                ),
                RoomReply::Forbidden,
            ),
            (
                viewer(
                    full_jid,
                    Some(MamOccupancyProof {
                        occupant_incarnation: Uuid::new_v4(),
                        ..valid
                    }),
                ),
                RoomReply::Forbidden,
            ),
            (viewer(other_resource, Some(valid)), RoomReply::Forbidden),
            (viewer(other_resource, Some(expires)), RoomReply::Forbidden),
        ] {
            assert_room_replies(&repository, "password-room", local, &authority, expected).await;
        }
        sqlx::query(
            "UPDATE cluster_muc_occupancies SET state='suspended'
              WHERE room_id=$1 AND occupant_incarnation=$2",
        )
        .bind(room)
        .bind(valid.occupant_incarnation)
        .execute(&mut *connection)
        .await
        .unwrap();
        assert_room_replies(
            &repository,
            "password-room",
            local,
            &viewer(full_jid, Some(valid)),
            RoomReply::Allowed,
        )
        .await;
        leave(&mut connection, room, valid).await;
        assert_room_replies(
            &repository,
            "password-room",
            local,
            &viewer(full_jid, Some(valid)),
            RoomReply::Forbidden,
        )
        .await;
    }
    drop(connection);
    fixture.cleanup().await;
}

pub(super) async fn room_message(connection: &mut PgConnection, room: Uuid) -> Uuid {
    sqlx::query_scalar(
        "INSERT INTO muc_messages(id,room_id,sender_jid,nick,stanza,encrypted,message_kind,actor_scope)
         VALUES(gen_random_uuid(),$1,'sender@remote.test/Phone','Sender','<message/>',
                FALSE,'discussion','sender@remote.test')
         RETURNING id",
    )
    .bind(room)
    .fetch_one(connection)
    .await
    .unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires TEST_DATABASE_URL; uses and removes a random isolated schema"]
async fn muc_mam_leave_during_page_read_keeps_a_serial_result() {
    let fixture = Fixture::new().await;
    let pool = &fixture.pool;
    let account = account(pool, "viewer").await;
    let room = password_room(pool, "leave-race").await;
    let local = occupancy(
        pool,
        room,
        1,
        "viewer@local.test/Phone",
        Some(account.id),
        600,
    )
    .await;
    let remote = occupancy(pool, room, 2, "viewer@remote.test/Phone", None, 600).await;
    let mut connection = pool.acquire().await.unwrap();
    let mut visible_ids = vec![room_message(&mut connection, room).await];
    drop(connection);

    for (proof, authority, federated) in [
        (local, viewer("viewer@local.test/Phone", Some(local)), false),
        (
            remote,
            viewer("viewer@remote.test/Phone", Some(remote)),
            true,
        ),
    ] {
        let mut leave_transaction = pool.begin().await.unwrap();
        sqlx::query("LOCK TABLE muc_messages IN ACCESS EXCLUSIVE MODE")
            .execute(&mut *leave_transaction)
            .await
            .unwrap();
        let blocker = sqlx::query_scalar("SELECT pg_backend_pid()")
            .fetch_one(&mut *leave_transaction)
            .await
            .unwrap();
        let reader = {
            let pool = pool.clone();
            let account = account.clone();
            let authority = authority.clone();
            tokio::spawn(async move {
                if federated {
                    mam_federated_room_archive_page_authorized(
                        &pool,
                        "leave-race",
                        &authority,
                        &query(),
                    )
                    .await
                } else {
                    mam_room_archive_page_authorized(
                        &pool,
                        "leave-race",
                        &account,
                        &authority,
                        &query(),
                    )
                    .await
                }
            })
        };
        // The page only touches the locked table after the room and proof reads.
        crate::support::blocked_backend(pool, blocker).await;
        leave(&mut leave_transaction, room, proof).await;
        let after_leave = room_message(&mut leave_transaction, room).await;
        leave_transaction.commit().await.unwrap();

        let MamDbRoomReadOutcome::Allowed {
            value: Some(page), ..
        } = reader.await.unwrap().unwrap()
        else {
            panic!("the page must use its already-established pre-leave snapshot");
        };
        assert_eq!(page.total, i64::try_from(visible_ids.len()).unwrap());
        for id in &visible_ids {
            assert!(page.rows.iter().any(|row| row.id == *id));
        }
        assert!(page.rows.iter().all(|row| row.id != after_leave));
        visible_ids.push(after_leave);
        // A fresh read with the same cached proof cannot observe post-leave rows.
        let repository = PostgresMamRepository::new(pool.clone());
        let local_account = (!federated).then_some(&account);
        assert_room_replies(
            &repository,
            "leave-race",
            local_account,
            &authority,
            RoomReply::Forbidden,
        )
        .await;
    }
    fixture.cleanup().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires TEST_DATABASE_URL; uses and removes a random isolated schema"]
async fn muc_mam_hides_locked_rooms_without_initializing_their_secret() {
    let fixture = Fixture::new().await;
    let pool = &fixture.pool;
    let repository = PostgresMamRepository::new(pool.clone());
    let owner_account = account(pool, "owner").await;
    let other_account = account(pool, "outsider").await;
    for (room, domain, local_owner, local_other) in [
        (
            "locked-local",
            "local.test",
            Some(&owner_account),
            Some(&other_account),
        ),
        ("locked-remote", "remote.test", None, None),
    ] {
        let owner = viewer(&format!("owner@{domain}/Phone"), None);
        let other_resource = viewer(&format!("owner@{domain}/Tablet"), None);
        let outsider = viewer(&format!("outsider@{domain}/Phone"), None);
        sqlx::query(
            "INSERT INTO muc_rooms(id,localpart,configuration_state,configuration_owner_jid,
                                   configuration_expires_at,occupant_id_secret)
             VALUES(gen_random_uuid(),$1,'locked',$2,clock_timestamp()+INTERVAL '10 minutes',NULL)",
        )
        .bind(room)
        .bind(&owner.full_jid)
        .execute(pool)
        .await
        .unwrap();
        let secret = || {
            sqlx::query_scalar::<_, Option<Vec<u8>>>(
                "SELECT occupant_id_secret FROM muc_rooms WHERE localpart=$1",
            )
            .bind(room)
            .fetch_one(pool)
        };
        if local_owner.is_none() {
            assert!(!repository
                .federated_room_visible(room, &outsider.full_jid)
                .await
                .unwrap());
            assert_eq!(secret().await.unwrap(), None);
        }
        for (actor, account) in [(&outsider, local_other), (&other_resource, local_owner)] {
            assert_room_replies(&repository, room, account, actor, RoomReply::Missing).await;
            assert_eq!(secret().await.unwrap(), None);
        }
        assert_room_replies(&repository, room, local_owner, &owner, RoomReply::Allowed).await;
        assert_eq!(secret().await.unwrap().unwrap().len(), 32);
        sqlx::query(
            "UPDATE muc_rooms SET configuration_expires_at=clock_timestamp()-INTERVAL '1 second',
                                  occupant_id_secret=NULL WHERE localpart=$1",
        )
        .bind(room)
        .execute(pool)
        .await
        .unwrap();
        for (actor, account) in [
            (&owner, local_owner),
            (&outsider, local_other),
            (&other_resource, local_owner),
        ] {
            assert_room_replies(&repository, room, account, actor, RoomReply::Missing).await;
            assert_eq!(secret().await.unwrap(), None);
        }
    }
    fixture.cleanup().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires TEST_DATABASE_URL; uses and removes a random isolated schema"]
async fn federated_mam_keeps_the_visible_legacy_repair_when_response_admission_fails() {
    let fixture = Fixture::new().await;
    let pool = &fixture.pool;
    let repository = PostgresMamRepository::new(pool.clone());
    let room = "visible-legacy-room";
    let authority = viewer("viewer@remote.test/Phone", None);
    sqlx::query(
        "INSERT INTO muc_rooms(id,localpart,occupant_id_secret)
         VALUES(gen_random_uuid(),$1,NULL)",
    )
    .bind(room)
    .execute(pool)
    .await
    .unwrap();
    let outcome = repository
        .admit_federated_room_stream(
            FederatedMamOutboxLimits {
                ttl_seconds: 300,
                max_rows: 1,
                max_bytes: 1024 * 1024,
                max_per_domain: 1,
            },
            FederatedMamStreamRequest::new("remote.test", room, &authority, &query()),
            |_| {
                Ok(vec![
                    "<message xmlns='jabber:server' from='visible-legacy-room@conference.local.test' to='viewer@remote.test/Phone' id='first'/>".to_owned(),
                    "<iq xmlns='jabber:server' type='result' id='fin'/>".to_owned(),
                ])
            },
        )
        .await
        .unwrap();
    assert_eq!(outcome, FederatedMamAdmissionOutcome::OutboxRejected);
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM s2s_outbox")
            .fetch_one(pool)
            .await
            .unwrap(),
        0
    );
    assert_eq!(
        sqlx::query_scalar::<_, Vec<u8>>(
            "SELECT occupant_id_secret FROM muc_rooms WHERE localpart=$1",
        )
        .bind(room)
        .fetch_one(pool)
        .await
        .unwrap()
        .len(),
        32
    );
    fixture.cleanup().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires TEST_DATABASE_URL; uses and removes a random isolated schema"]
async fn mam_stale_local_account_denies_reads_and_preference_writes() {
    let fixture = Fixture::new().await;
    let pool = &fixture.pool;
    let repository = PostgresMamRepository::new(pool.clone());
    sqlx::query(
        "INSERT INTO muc_rooms(id,localpart,occupant_id_secret)
         VALUES(gen_random_uuid(),'account-room',NULL)",
    )
    .execute(pool)
    .await
    .unwrap();
    for (username, mutation) in [
        ("disabled", "UPDATE users SET is_disabled=TRUE WHERE id=$1"),
        (
            "rotated",
            "UPDATE users SET auth_generation=auth_generation+1 WHERE id=$1",
        ),
        ("deleted", "DELETE FROM users WHERE id=$1"),
        (
            "renamed",
            "UPDATE users SET username='new-name' WHERE id=$1",
        ),
    ] {
        let account = account(pool, username).await;
        let previous = MamPreferences {
            default_policy: "never".to_owned(),
            always: vec!["kept@remote.test".to_owned()],
            never: Vec::new(),
        };
        assert_eq!(
            repository
                .set_preferences(MamPreferencesSetCommand {
                    authority: account.clone(),
                    preferences: previous,
                })
                .await
                .unwrap(),
            MamAccountOutcome::Authorized(())
        );
        sqlx::query(mutation)
            .bind(account.id)
            .execute(pool)
            .await
            .unwrap();
        let before = preference_rows(pool, account.id).await;
        let personal = MamQueryScope::Personal {
            authority: account.clone(),
        };
        let authority = viewer(&format!("{username}@local.test/Phone"), None);
        let local_room = room_scope("account-room", &account, &authority);
        for scope in [personal, local_room] {
            assert_eq!(
                repository
                    .query_archive(MamQueryCommand {
                        scope: scope.clone(),
                        query: query(),
                    })
                    .await
                    .unwrap(),
                MamQueryResult::StaleAccount
            );
            assert_eq!(
                repository
                    .get_boundaries(MamMetadataCommand { scope })
                    .await
                    .unwrap(),
                MamMetadataResult::StaleAccount
            );
        }
        assert_eq!(
            repository.authorize_personal(&account).await.unwrap(),
            MamAccountOutcome::StaleAccount
        );
        assert_eq!(
            repository
                .authorize_room("account-room", &account, &authority)
                .await
                .unwrap(),
            MamRoomAccessOutcome::StaleAccount
        );
        assert_eq!(
            repository
                .get_preferences(MamPreferencesGetCommand {
                    authority: account.clone(),
                })
                .await
                .unwrap(),
            MamAccountOutcome::StaleAccount
        );
        assert_eq!(
            repository
                .set_preferences(MamPreferencesSetCommand {
                    authority: account.clone(),
                    preferences: MamPreferences::default(),
                })
                .await
                .unwrap(),
            MamAccountOutcome::StaleAccount
        );
        assert_eq!(preference_rows(pool, account.id).await, before);
    }
    // A preference writer waiting on an account mutation must recheck the
    // winning account state before touching the preferences.
    let writer = account(pool, "waiting-writer").await;
    let mut disable = pool.begin().await.unwrap();
    sqlx::query("UPDATE users SET is_disabled=TRUE WHERE id=$1")
        .bind(writer.id)
        .execute(&mut *disable)
        .await
        .unwrap();
    let blocker = sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(&mut *disable)
        .await
        .unwrap();
    let command = MamPreferencesSetCommand {
        authority: writer.clone(),
        preferences: MamPreferences::default(),
    };
    let waiting_write = tokio::spawn(async move { repository.set_preferences(command).await });
    crate::support::blocked_backend(pool, blocker).await;
    disable.commit().await.unwrap();
    assert_eq!(
        waiting_write.await.unwrap().unwrap(),
        MamAccountOutcome::StaleAccount
    );
    assert_eq!(preference_rows(pool, writer.id).await, (None, Vec::new()));

    assert_eq!(
        sqlx::query_scalar::<_, Option<Vec<u8>>>(
            "SELECT occupant_id_secret FROM muc_rooms WHERE localpart='account-room'",
        )
        .fetch_one(pool)
        .await
        .unwrap(),
        None
    );
    fixture.cleanup().await;
}

async fn preference_rows(pool: &PgPool, owner: Uuid) -> (Option<String>, Vec<String>) {
    let header = sqlx::query_scalar(
        "SELECT to_jsonb(prefs)::text FROM mam_preferences prefs WHERE user_id=$1",
    )
    .bind(owner)
    .fetch_optional(pool)
    .await
    .unwrap();
    let jids = sqlx::query_scalar(
        "SELECT to_jsonb(entry)::text FROM mam_preference_jids entry WHERE user_id=$1 ORDER BY jid",
    )
    .bind(owner)
    .fetch_all(pool)
    .await
    .unwrap();
    (header, jids)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires TEST_DATABASE_URL; uses and removes a random isolated schema"]
async fn personal_mam_reads_work_on_read_only_connections() {
    let fixture = Fixture::new().await;
    let account = account(&fixture.pool, "reader").await;
    let id: Uuid = sqlx::query_scalar(
        "INSERT INTO message_archive(id,owner_id,peer_jid,peer_full_jid,stanza,encrypted)
         VALUES(gen_random_uuid(),$1,'peer@remote.test','peer@remote.test/Phone','<message/>',FALSE)
         RETURNING id",
    )
    .bind(account.id)
    .fetch_one(&fixture.pool)
    .await
    .unwrap();
    let read_pool = Fixture::connect(&fixture.url, &fixture.schema, true).await;
    assert_eq!(
        sqlx::query_scalar::<_, String>("SHOW default_transaction_read_only")
            .fetch_one(&read_pool)
            .await
            .unwrap(),
        "on"
    );
    let repository = PostgresMamRepository::new(read_pool.clone());
    let scope = MamQueryScope::Personal {
        authority: account.clone(),
    };
    let page = repository
        .query_archive(MamQueryCommand {
            scope: scope.clone(),
            query: query(),
        })
        .await
        .unwrap();
    assert!(matches!(page, MamQueryResult::Page { room: None, page }
        if page.rows.len() == 1 && page.rows[0].id == id));
    let boundaries = repository
        .get_boundaries(MamMetadataCommand { scope })
        .await
        .unwrap();
    assert!(matches!(boundaries, MamMetadataResult::Boundaries {
        room: None, start: Some(start), end: Some(end),
    } if start.id == id && end.id == id));
    assert_eq!(
        repository.authorize_personal(&account).await.unwrap(),
        MamAccountOutcome::Authorized(())
    );
    assert_eq!(
        repository
            .get_preferences(MamPreferencesGetCommand { authority: account })
            .await
            .unwrap(),
        MamAccountOutcome::Authorized(MamPreferences::default())
    );
    read_pool.close().await;
    fixture.cleanup().await;
}
