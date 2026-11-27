//! Actor and topology races for the PostgreSQL repositories behind policy IQs.

use super::presence_service::IsolatedDatabase;
use crate::support::blocked_backend;
use northstar_auth_postgres::users::{create_user, lock_auth_generation, User};
use northstar_roster_application::privacy::{
    commands::{
        ActorOutcome, PolicyCommandRepository, PrivacyListName, PrivacyOverviewSnapshot,
        TopologyResource,
    },
    PrivacyItem, PrivacyListMutationOutcome, PrivacySelectionOutcome,
};
use northstar_roster_core::RosterActor;
use northstar_roster_postgres::privacy::{
    set_active_privacy_list, set_active_privacy_list_in_transaction, PostgresPrivacyRepository,
};
use northstar_roster_postgres::roster::{block_jids, BlockJidsUpdate};
use northstar_session_postgres::capacity::{
    publish_binding_live_session_in_transaction, release_live_session,
    reserve_live_session_in_transaction, LiveSessionReservation,
};
use northstar_workflows::sm::{self, SmClaimStatus, SmSessionSnapshot};
use northstar_xep_0016::PrivacyAction;
use sqlx::{PgConnection, PgPool};
use std::time::Duration;
use uuid::Uuid;

struct Fixture {
    database: IsolatedDatabase,
    repository: PostgresPrivacyRepository,
}

impl Fixture {
    async fn new() -> Self {
        let database = IsolatedDatabase::create("privacy_commands").await;
        let repository = PostgresPrivacyRepository::new(database.pool.clone());
        Self {
            database,
            repository,
        }
    }

    fn pool(&self) -> &PgPool {
        &self.database.pool
    }

    async fn actor(&self, username: &str) -> RosterActor {
        let user = create_account(self.pool(), username).await;
        RosterActor {
            account_id: user.id,
            auth_generation: user.auth_generation,
            connection_id: Uuid::new_v4(),
            full_jid: format!("{username}@example.test/Requester"),
        }
    }

    async fn store(&self, actor: &RosterActor, list: &str, item: PrivacyItem) {
        assert_eq!(
            self.repository
                .replace_privacy_list(actor, &name(list), &[item])
                .await
                .unwrap(),
            ActorOutcome::Current(PrivacyListMutationOutcome::Stored)
        );
    }
}

async fn create_account(pool: &PgPool, username: &str) -> User {
    create_user(
        pool,
        username,
        &format!("Fixture password for {username} 42!"),
        false,
        true,
        4096,
        false,
    )
    .await
    .unwrap()
}

fn name(text: &str) -> PrivacyListName {
    PrivacyListName::parse(text).unwrap()
}

fn item(order: u32, action: PrivacyAction) -> PrivacyItem {
    PrivacyItem {
        order,
        action,
        match_type: None,
        match_value: None,
        message: false,
        iq: false,
        presence_in: false,
        presence_out: false,
    }
}

fn current<T>(outcome: ActorOutcome<T>) -> T {
    match outcome {
        ActorOutcome::Current(value) => value,
        ActorOutcome::Stale => panic!("fixture actor should still be current"),
    }
}

async fn backend(connection: &mut PgConnection) -> i32 {
    sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(connection)
        .await
        .unwrap()
}

async fn waiting_query(pool: &PgPool, blocker: i32) -> String {
    let reader = blocked_backend(pool, blocker).await;
    sqlx::query_scalar("SELECT query FROM pg_stat_activity WHERE pid=$1")
        .bind(reader)
        .fetch_one(pool)
        .await
        .unwrap()
}

#[tokio::test]
#[ignore = "requires a random-schema TEST_DATABASE_URL"]
async fn named_get_is_one_snapshot_during_delete_recreate_and_edit() {
    let fixture = Fixture::new().await;
    let pool = fixture.pool();
    let actor = fixture.actor("alice").await;
    for change in ["delete", "recreate", "edit"] {
        let before = vec![item(1, PrivacyAction::Allow)];
        fixture.store(&actor, "work", before[0].clone()).await;
        let mut writer = pool.begin().await.unwrap();
        sqlx::query("LOCK TABLE privacy_list_items IN ACCESS EXCLUSIVE MODE")
            .execute(&mut *writer)
            .await
            .unwrap();
        let blocker = backend(&mut writer).await;
        let repo = fixture.repository.clone();
        let request = actor.clone();
        let reader =
            tokio::spawn(async move { repo.read_privacy_list(&request, &name("work")).await });
        let query = waiting_query(pool, blocker).await;
        assert!(
            query.contains("LEFT JOIN privacy_lists")
                && query.contains("LEFT JOIN privacy_list_items")
        );
        if change != "edit" {
            sqlx::query("DELETE FROM privacy_lists WHERE owner_id=$1 AND name='work'")
                .bind(actor.account_id)
                .execute(&mut *writer)
                .await
                .unwrap();
        }
        if change == "recreate" {
            sqlx::query("INSERT INTO privacy_lists(owner_id,name) VALUES($1,'work')")
                .bind(actor.account_id)
                .execute(&mut *writer)
                .await
                .unwrap();
            sqlx::query(
                "INSERT INTO privacy_list_items(owner_id,list_name,item_order,action) VALUES($1,'work',9,'deny')",
            )
            .bind(actor.account_id)
            .execute(&mut *writer)
            .await
            .unwrap();
        } else if change == "edit" {
            sqlx::query(
                "UPDATE privacy_list_items SET item_order=9, action='deny' WHERE owner_id=$1 AND list_name='work'",
            )
            .bind(actor.account_id)
            .execute(&mut *writer)
            .await
            .unwrap();
        }
        writer.commit().await.unwrap();
        let after = (change != "delete").then(|| vec![item(9, PrivacyAction::Deny)]);
        let actual = current(reader.await.unwrap().unwrap());
        assert!(
            actual == Some(before) || actual == after,
            "{change}: {actual:?}"
        );
        assert_eq!(
            current(
                fixture
                    .repository
                    .read_privacy_list(&actor, &name("work"))
                    .await
                    .unwrap()
            ),
            after
        );
    }
    fixture.database.finish().await;
}

#[tokio::test]
#[ignore = "requires a random-schema TEST_DATABASE_URL"]
async fn overview_is_coherent_during_switch_delete_and_selection_expiry() {
    let fixture = Fixture::new().await;
    let pool = fixture.pool();
    let actor = fixture.actor("alice").await;
    fixture
        .store(&actor, "old", item(1, PrivacyAction::Allow))
        .await;
    fixture
        .store(&actor, "new", item(1, PrivacyAction::Deny))
        .await;
    assert_eq!(
        current(
            fixture
                .repository
                .select_default_privacy_list(&actor, Some(&name("old")))
                .await
                .unwrap()
        )
        .0,
        PrivacySelectionOutcome::Updated
    );
    assert!(
        set_active_privacy_list(pool, actor.account_id, actor.connection_id, Some("old"))
            .await
            .unwrap()
    );
    let before = current(
        fixture
            .repository
            .read_privacy_overview(&actor)
            .await
            .unwrap(),
    );
    assert_eq!(before.active, Some(name("old")));
    assert_eq!(before.default, Some(name("old")));
    assert_eq!(before.names, [name("new"), name("old")]);
    let different_connection = RosterActor {
        connection_id: Uuid::new_v4(),
        ..actor.clone()
    };
    assert_eq!(
        current(
            fixture
                .repository
                .read_privacy_overview(&different_connection)
                .await
                .unwrap()
        )
        .active,
        None
    );

    let mut writer = pool.begin().await.unwrap();
    sqlx::query("LOCK TABLE privacy_active_sessions IN ACCESS EXCLUSIVE MODE")
        .execute(&mut *writer)
        .await
        .unwrap();
    let blocker = backend(&mut writer).await;
    let repo = fixture.repository.clone();
    let request = actor.clone();
    let reader = tokio::spawn(async move { repo.read_privacy_overview(&request).await });
    let query = waiting_query(pool, blocker).await;
    assert!(query.contains("privacy_lists") && query.contains("privacy_default_lists"));
    for statement in [
        "UPDATE privacy_active_sessions SET list_name='new' WHERE owner_id=$1",
        "UPDATE privacy_default_lists SET list_name='new' WHERE owner_id=$1",
        "DELETE FROM privacy_lists WHERE owner_id=$1 AND name='old'",
    ] {
        sqlx::query(statement)
            .bind(actor.account_id)
            .execute(&mut *writer)
            .await
            .unwrap();
    }
    writer.commit().await.unwrap();
    let after = current(
        fixture
            .repository
            .read_privacy_overview(&actor)
            .await
            .unwrap(),
    );
    assert_eq!(after.active, Some(name("new")));
    assert_eq!(after.default, Some(name("new")));
    assert_eq!(after.names, [name("new")]);
    let actual = current(reader.await.unwrap().unwrap());
    assert!(actual == before || actual == after);

    sqlx::query(
        "UPDATE privacy_active_sessions SET expires_at=clock_timestamp()-interval '1 minute' \
         WHERE owner_id=$1 AND connection_id=$2",
    )
    .bind(actor.account_id)
    .bind(actor.connection_id)
    .execute(pool)
    .await
    .unwrap();
    let expired = current(
        fixture
            .repository
            .read_privacy_overview(&actor)
            .await
            .unwrap(),
    );
    assert_eq!(expired.active, None);
    assert_eq!(expired.default, after.default);
    assert_eq!(expired.names, after.names);
    fixture.database.finish().await;
}

#[derive(Clone, Copy, Debug)]
enum Revocation {
    Password,
    Disable,
    Delete,
}

const REVOCATIONS: [Revocation; 3] = [
    Revocation::Password,
    Revocation::Disable,
    Revocation::Delete,
];

async fn revoke(connection: &mut PgConnection, actor: &RosterActor, revocation: Revocation) {
    if matches!(revocation, Revocation::Password) {
        // Each source account owns valid credentials generated by the production repository.
        let changed: bool = sqlx::query_scalar(
            "SELECT northstar_user_change_password_stream($1,$2,password_hash, \
                scram_sha256_salt,scram_sha256_iterations,scram_sha256_stored_key,scram_sha256_server_key, \
                scram_sha1_salt,scram_sha1_iterations,scram_sha1_stored_key,scram_sha1_server_key) \
             FROM users WHERE username='replacement'",
        )
        .bind(actor.account_id)
        .bind(actor.auth_generation)
        .fetch_one(connection)
        .await
        .unwrap();
        assert!(changed);
        return;
    }
    let disabled: bool = sqlx::query_scalar("SELECT northstar_user_quiesce_deletion($1,$2)")
        .bind(actor.account_id)
        .bind(actor.auth_generation)
        .fetch_one(&mut *connection)
        .await
        .unwrap();
    assert!(disabled);
    if matches!(revocation, Revocation::Delete) {
        // Clear the default pointer before the owner cascade removes lists.
        sqlx::query("DELETE FROM privacy_default_lists WHERE owner_id=$1")
            .bind(actor.account_id)
            .execute(&mut *connection)
            .await
            .unwrap();
        let username = actor.bare_jid().split_once('@').unwrap().0;
        let deleted: bool = sqlx::query_scalar("SELECT northstar_user_delete_quiesced($1,$2)")
            .bind(actor.account_id)
            .bind(username)
            .fetch_one(connection)
            .await
            .unwrap();
        assert!(deleted);
    }
}

#[derive(Clone, Copy, Debug)]
enum Write {
    Create,
    Edit,
    SetDefault,
    DeclineDefault,
    Remove,
}

#[tokio::test]
#[ignore = "requires a random-schema TEST_DATABASE_URL"]
async fn privacy_writes_reject_an_actor_revoked_while_waiting_on_the_owner() {
    let fixture = Fixture::new().await;
    let pool = fixture.pool();
    create_account(pool, "replacement").await;
    for (revocation_index, revocation) in REVOCATIONS.into_iter().enumerate() {
        for (write_index, write) in [
            Write::Create,
            Write::Edit,
            Write::SetDefault,
            Write::DeclineDefault,
            Write::Remove,
        ]
        .into_iter()
        .enumerate()
        {
            let actor = fixture
                .actor(&format!("writer-{revocation_index}-{write_index}"))
                .await;
            fixture
                .store(&actor, "work", item(1, PrivacyAction::Allow))
                .await;
            if matches!(write, Write::DeclineDefault) {
                assert_eq!(
                    current(
                        fixture
                            .repository
                            .select_default_privacy_list(&actor, Some(&name("work")))
                            .await
                            .unwrap()
                    )
                    .0,
                    PrivacySelectionOutcome::Updated
                );
            }
            let mut writer = pool.begin().await.unwrap();
            let blocker = backend(&mut writer).await;
            lock_owner(&mut writer, actor.account_id).await;
            let repo = fixture.repository.clone();
            let request = actor.clone();
            let operation = tokio::spawn(async move {
                let work = name("work");
                match write {
                    Write::Create | Write::Edit => {
                        let target = if matches!(write, Write::Create) {
                            name("new")
                        } else {
                            work
                        };
                        let outcome = repo
                            .replace_privacy_list(
                                &request,
                                &target,
                                &[item(2, PrivacyAction::Deny)],
                            )
                            .await
                            .unwrap();
                        matches!(outcome, ActorOutcome::Stale)
                    }
                    Write::SetDefault | Write::DeclineDefault => {
                        let selection = matches!(write, Write::SetDefault).then_some(&work);
                        let outcome = repo
                            .select_default_privacy_list(&request, selection)
                            .await
                            .unwrap();
                        matches!(outcome, ActorOutcome::Stale)
                    }
                    Write::Remove => {
                        let outcome = repo.remove_privacy_list(&request, &work).await.unwrap();
                        matches!(outcome, ActorOutcome::Stale)
                    }
                }
            });
            assert!(waiting_query(pool, blocker)
                .await
                .contains("northstar_lock_user_rows_update"));
            revoke(&mut writer, &actor, revocation).await;
            writer.commit().await.unwrap();
            assert!(operation.await.unwrap(), "{write:?} after {revocation:?}");
        }
    }
    fixture.database.finish().await;
}

#[derive(Debug, Eq, PartialEq)]
enum ReadValue {
    Named(Option<Vec<PrivacyItem>>),
    Overview(PrivacyOverviewSnapshot),
    Blocklist(Vec<String>),
}

#[derive(Clone, Copy, Debug)]
enum Read {
    Named,
    Overview,
    Blocklist,
}

impl Read {
    async fn execute(
        self,
        repo: &PostgresPrivacyRepository,
        actor: &RosterActor,
    ) -> ActorOutcome<ReadValue> {
        match self {
            Self::Named => match repo.read_privacy_list(actor, &name("work")).await.unwrap() {
                ActorOutcome::Current(items) => ActorOutcome::Current(ReadValue::Named(items)),
                ActorOutcome::Stale => ActorOutcome::Stale,
            },
            Self::Overview => match repo.read_privacy_overview(actor).await.unwrap() {
                ActorOutcome::Current(overview) => {
                    ActorOutcome::Current(ReadValue::Overview(overview))
                }
                ActorOutcome::Stale => ActorOutcome::Stale,
            },
            Self::Blocklist => match repo.read_blocklist(actor).await.unwrap() {
                ActorOutcome::Current(items) => ActorOutcome::Current(ReadValue::Blocklist(items)),
                ActorOutcome::Stale => ActorOutcome::Stale,
            },
        }
    }
}

#[tokio::test]
#[ignore = "requires a random-schema TEST_DATABASE_URL"]
async fn privacy_and_blocklist_gets_follow_one_account_snapshot_during_revocation() {
    let fixture = Fixture::new().await;
    let pool = fixture.pool();
    create_account(pool, "replacement").await;
    for (revocation_index, revocation) in REVOCATIONS.into_iter().enumerate() {
        for (read_index, (read, table_lock)) in [
            (
                Read::Named,
                "LOCK TABLE privacy_list_items IN ACCESS EXCLUSIVE MODE",
            ),
            (
                Read::Overview,
                "LOCK TABLE privacy_active_sessions IN ACCESS EXCLUSIVE MODE",
            ),
            (
                Read::Blocklist,
                "LOCK TABLE blocked_jids IN ACCESS EXCLUSIVE MODE",
            ),
        ]
        .into_iter()
        .enumerate()
        {
            let actor = fixture
                .actor(&format!("reader-{revocation_index}-{read_index}"))
                .await;
            fixture
                .store(&actor, "work", item(1, PrivacyAction::Allow))
                .await;
            assert!(matches!(
                block_jids(pool, actor.account_id, &["peer@example.test".to_owned()]).await.unwrap(),
                BlockJidsUpdate::Changed(keys) if keys == ["peer@example.test"]
            ));
            let before = read.execute(&fixture.repository, &actor).await;
            assert!(matches!(&before, ActorOutcome::Current(_)));
            let mut writer = pool.begin().await.unwrap();
            let blocker = backend(&mut writer).await;
            sqlx::query(table_lock).execute(&mut *writer).await.unwrap();
            let repo = fixture.repository.clone();
            let request = actor.clone();
            let operation = tokio::spawn(async move { read.execute(&repo, &request).await });
            let query = waiting_query(pool, blocker).await;
            assert!(query.contains("auth_generation") && query.contains("is_disabled"));
            revoke(&mut writer, &actor, revocation).await;
            writer.commit().await.unwrap();
            let actual = operation.await.unwrap();
            assert!(
                actual == before || actual == ActorOutcome::Stale,
                "{read:?} during {revocation:?}: {actual:?}"
            );
            assert_eq!(
                read.execute(&fixture.repository, &actor).await,
                ActorOutcome::Stale
            );
        }
    }
    fixture.database.finish().await;
}

async fn lock_owner(connection: &mut PgConnection, owner: Uuid) {
    sqlx::query_scalar::<_, Uuid>(
        "SELECT id FROM northstar_lock_user_rows_update(ARRAY[$1::uuid])",
    )
    .bind(owner)
    .fetch_one(connection)
    .await
    .unwrap();
}

const LEASE_SECONDS: u64 = 300;

async fn lock_lease(connection: &mut PgConnection, connection_id: Uuid) {
    sqlx::query("SELECT lease_id FROM deployment_session_leases WHERE connection_id=$1 FOR UPDATE")
        .bind(connection_id)
        .fetch_one(connection)
        .await
        .unwrap();
}

async fn reserve(pool: &PgPool, actor: &RosterActor, connection: Uuid, full_jid: &str) {
    let mut tx = pool.begin().await.unwrap();
    let result = reserve_live_session_in_transaction(
        &mut tx,
        connection,
        actor.account_id,
        full_jid,
        LEASE_SECONDS,
        false,
    )
    .await
    .unwrap();
    assert_eq!(result, LiveSessionReservation::Reserved);
    tx.commit().await.unwrap();
}

async fn assert_topology_conflict(
    repository: &PostgresPrivacyRepository,
    actor: &RosterActor,
    connection_id: Uuid,
    effective_list: &str,
    removal: &str,
) {
    let expected = [TopologyResource {
        connection_id,
        effective_list: Some(name(effective_list)),
    }];
    let (outcome, proof) = current(
        repository
            .select_default_privacy_list(actor, None)
            .await
            .unwrap(),
    );
    assert_eq!(outcome, PrivacySelectionOutcome::Conflict);
    assert_eq!(proof.other_resources, expected);
    let (outcome, proof) = current(
        repository
            .remove_privacy_list(actor, &name(removal))
            .await
            .unwrap(),
    );
    assert_eq!(outcome, PrivacyListMutationOutcome::Conflict);
    assert_eq!(proof.other_resources, expected);
}

#[tokio::test]
#[ignore = "requires a random-schema TEST_DATABASE_URL"]
async fn default_and_remove_serialize_with_binding_publication_and_release() {
    let fixture = Fixture::new().await;
    let pool = fixture.pool();
    let actor = fixture.actor("alice").await;
    fixture
        .store(&actor, "home", item(1, PrivacyAction::Allow))
        .await;
    fixture
        .store(&actor, "spare", item(1, PrivacyAction::Allow))
        .await;
    let home = name("home");
    reserve(pool, &actor, actor.connection_id, &actor.full_jid).await;
    let (outcome, proof) = current(
        fixture
            .repository
            .select_default_privacy_list(&actor, Some(&home))
            .await
            .unwrap(),
    );
    assert_eq!(outcome, PrivacySelectionOutcome::Updated);
    assert!(proof.other_resources.is_empty());

    // Reservation cannot insert past the same owner lock the policy commands take.
    let mut owner_lock = pool.begin().await.unwrap();
    let blocker = backend(&mut owner_lock).await;
    lock_owner(&mut owner_lock, actor.account_id).await;
    let other = Uuid::new_v4();
    let other_jid = "alice@example.test/Other";
    let binder_pool = pool.clone();
    let binder_actor = actor.clone();
    let bind =
        tokio::spawn(async move { reserve(&binder_pool, &binder_actor, other, other_jid).await });
    assert!(waiting_query(pool, blocker)
        .await
        .contains("northstar_session_reserve_live"));
    owner_lock.rollback().await.unwrap();
    bind.await.unwrap();
    assert_topology_conflict(&fixture.repository, &actor, other, "home", "home").await;
    assert!(release_live_session(pool, other).await.unwrap());

    // A reservation that reached the owner first holds KEY SHARE until the lease is visible.
    for remove in [false, true] {
        let mut reservation = pool.begin().await.unwrap();
        assert_eq!(
            reserve_live_session_in_transaction(
                &mut reservation,
                other,
                actor.account_id,
                other_jid,
                LEASE_SECONDS,
                false,
            )
            .await
            .unwrap(),
            LiveSessionReservation::Reserved
        );
        let blocker = backend(&mut reservation).await;
        let repo = fixture.repository.clone();
        let request = actor.clone();
        let command = tokio::spawn(async move {
            if remove {
                let (outcome, proof) = current(
                    repo.remove_privacy_list(&request, &name("spare"))
                        .await
                        .unwrap(),
                );
                assert_eq!(outcome, PrivacyListMutationOutcome::Removed);
                proof
            } else {
                let (outcome, proof) = current(
                    repo.select_default_privacy_list(&request, None)
                        .await
                        .unwrap(),
                );
                assert_eq!(outcome, PrivacySelectionOutcome::Conflict);
                proof
            }
        });
        assert!(waiting_query(pool, blocker)
            .await
            .contains("northstar_lock_user_rows_update"));
        reservation.commit().await.unwrap();
        assert_eq!(
            command.await.unwrap().other_resources,
            [TopologyResource {
                connection_id: other,
                effective_list: Some(home.clone())
            }]
        );
        if !remove {
            assert!(release_live_session(pool, other).await.unwrap());
        }
    }

    let mut lease_lock = pool.begin().await.unwrap();
    let blocker = backend(&mut lease_lock).await;
    lock_lease(&mut lease_lock, other).await;
    let publish_pool = pool.clone();
    let user = actor.account_id;
    let publish = tokio::spawn(async move {
        let mut tx = publish_pool.begin().await.unwrap();
        assert!(publish_binding_live_session_in_transaction(
            &mut tx,
            other,
            user,
            other_jid,
            LEASE_SECONDS
        )
        .await
        .unwrap());
        tx.commit().await.unwrap();
    });
    assert!(waiting_query(pool, blocker)
        .await
        .contains("northstar_session_publish_binding"));
    tokio::time::timeout(
        Duration::from_secs(5),
        assert_topology_conflict(&fixture.repository, &actor, other, "home", "home"),
    )
    .await
    .expect("commands must read the reserved lease without locking its row");
    lease_lock.rollback().await.unwrap();
    publish.await.unwrap();

    let mut lease_lock = pool.begin().await.unwrap();
    let blocker = backend(&mut lease_lock).await;
    lock_lease(&mut lease_lock, other).await;
    let release_pool = pool.clone();
    let release =
        tokio::spawn(async move { release_live_session(&release_pool, other).await.unwrap() });
    assert!(waiting_query(pool, blocker)
        .await
        .contains("northstar_session_release_live"));
    tokio::time::timeout(
        Duration::from_secs(5),
        assert_topology_conflict(&fixture.repository, &actor, other, "home", "home"),
    )
    .await
    .expect("commands must see the lease while release is waiting");
    lease_lock.rollback().await.unwrap();
    assert!(release.await.unwrap());
    let (outcome, proof) = current(
        fixture
            .repository
            .select_default_privacy_list(&actor, None)
            .await
            .unwrap(),
    );
    assert_eq!(outcome, PrivacySelectionOutcome::Updated);
    assert!(proof.other_resources.is_empty());
    let (outcome, proof) = current(
        fixture
            .repository
            .remove_privacy_list(&actor, &home)
            .await
            .unwrap(),
    );
    assert_eq!(outcome, PrivacyListMutationOutcome::Removed);
    assert!(proof.other_resources.is_empty());
    fixture.database.finish().await;
}

#[tokio::test]
#[ignore = "requires a random-schema TEST_DATABASE_URL"]
async fn remote_active_selection_blocks_removal_and_expired_selection_uses_default() {
    let fixture = Fixture::new().await;
    let pool = fixture.pool();
    let actor = fixture.actor("alice").await;
    fixture
        .store(&actor, "work", item(1, PrivacyAction::Allow))
        .await;
    fixture
        .store(&actor, "home", item(1, PrivacyAction::Deny))
        .await;
    assert_eq!(
        current(
            fixture
                .repository
                .select_default_privacy_list(&actor, Some(&name("home")))
                .await
                .unwrap()
        )
        .0,
        PrivacySelectionOutcome::Updated
    );
    let remote = Uuid::new_v4();
    // The durable lease is node-agnostic. Hold the requester's connection so
    // the remote reservation and selection must come from another backend.
    let requester = pool.acquire().await.unwrap();
    reserve(pool, &actor, remote, "alice@example.test/Remote").await;
    assert!(
        set_active_privacy_list(pool, actor.account_id, remote, Some("work"))
            .await
            .unwrap()
    );
    drop(requester);
    assert_topology_conflict(&fixture.repository, &actor, remote, "work", "work").await;
    sqlx::query(
        "UPDATE privacy_active_sessions SET expires_at=clock_timestamp()-interval '1 minute' \
         WHERE connection_id=$1",
    )
    .bind(remote)
    .execute(pool)
    .await
    .unwrap();
    let (outcome, proof) = current(
        fixture
            .repository
            .remove_privacy_list(&actor, &name("work"))
            .await
            .unwrap(),
    );
    assert_eq!(outcome, PrivacyListMutationOutcome::Removed);
    assert_eq!(
        proof.other_resources,
        [TopologyResource {
            connection_id: remote,
            effective_list: Some(name("home"))
        }]
    );
    fixture.database.finish().await;
}

#[tokio::test]
#[ignore = "requires a random-schema TEST_DATABASE_URL"]
async fn default_and_remove_observe_suspended_lease_and_sm_transfer() {
    let fixture = Fixture::new().await;
    let pool = fixture.pool();
    let actor = fixture.actor("alice").await;
    fixture
        .store(&actor, "home", item(1, PrivacyAction::Allow))
        .await;
    fixture
        .store(&actor, "sm-list", item(1, PrivacyAction::Deny))
        .await;
    assert_eq!(
        current(
            fixture
                .repository
                .select_default_privacy_list(&actor, Some(&name("home")))
                .await
                .unwrap()
        )
        .0,
        PrivacySelectionOutcome::Updated
    );
    let old = Uuid::new_v4();
    let new = Uuid::new_v4();
    let full = "alice@example.test/Resume";
    reserve(pool, &actor, old, full).await;
    let snapshot = SmSessionSnapshot {
        inbound_h: 0,
        outbound_h: 0,
        acked_h: 0,
        available: false,
        carbons: false,
        priority: 0,
        blocklist_requested: false,
        roster_requested: false,
        active_privacy_list: Some("sm-list".into()),
        privacy_requested: true,
        peer_ip: "192.0.2.57".parse().unwrap(),
        user_agent_id: None,
        joined_rooms: Vec::new(),
        directed_presence: Vec::new(),
        last_presence: None,
        unacked: Vec::new(),
    };
    let token_hash = [17; 32];
    let session = sm::create_sm_session(
        pool,
        &token_hash,
        actor.account_id,
        actor.auth_generation,
        full,
        "Resume",
        "example.test",
        old,
        &snapshot,
        300,
        30,
        8,
        100,
    )
    .await
    .unwrap();
    assert!(
        sm::suspend_sm_session(pool, session, old, &snapshot, 300, 64, 65_536)
            .await
            .unwrap()
    );
    assert_topology_conflict(&fixture.repository, &actor, old, "home", "sm-list").await;
    let SmClaimStatus::Claimed(claim) = sm::claim_sm_session_status(
        pool,
        &token_hash,
        actor.account_id,
        snapshot.peer_ip,
        None,
        sm::SmIpPolicy::Exact,
        false,
        120,
    )
    .await
    .unwrap() else {
        panic!("suspended session should be claimable");
    };
    let mut lease_lock = pool.begin().await.unwrap();
    let blocker = backend(&mut lease_lock).await;
    lock_lease(&mut lease_lock, old).await;
    let resume_pool = pool.clone();
    let user = actor.account_id;
    let generation = actor.auth_generation;
    let resume = tokio::spawn(async move {
        let mut tx = lock_auth_generation(&resume_pool, user, generation)
            .await
            .unwrap()
            .unwrap();
        let activated = sm::activate_claimed_sm_session_in_transaction(
            &mut tx,
            session,
            claim.claim_token,
            new,
            0,
            0,
            snapshot.peer_ip,
            None,
            300,
            LEASE_SECONDS,
            64,
            65_536,
        )
        .await
        .unwrap();
        assert!(activated.is_some());
        assert!(set_active_privacy_list_in_transaction(
            &mut tx,
            user,
            new,
            claim.active_privacy_list.as_deref(),
        )
        .await
        .unwrap());
        tx.commit().await.unwrap();
    });
    let resume_backend = blocked_backend(pool, blocker).await;
    let repo = fixture.repository.clone();
    let request = actor.clone();
    let commands = tokio::spawn(async move {
        assert_topology_conflict(&repo, &request, new, "sm-list", "sm-list").await;
    });
    assert!(waiting_query(pool, resume_backend)
        .await
        .contains("northstar_lock_user_rows_update"));
    lease_lock.rollback().await.unwrap();
    resume.await.unwrap();
    commands.await.unwrap();
    fixture.database.finish().await;
}
