//! Deterministic authority and outbox interleavings for MIX MAM.

use northstar_room_application::mix_service::{
    MamArchiveQuery, MamRsmPage, MixMamAdmissionOutcome, MixMamPage, MixMamReadActor,
    MixMamReadCommand, MixMamReadOperation, MixMamReadOutcome, MixMamReadRepository,
    MixMamReadResult, MixMamReadTarget, MixPayloads, S2sOutboxPolicy,
};
use northstar_room_postgres::{
    effects::RoomEffects,
    mix::{create_mix_channel, CreateChannelOutcome, NODE_MESSAGES},
};
use northstar_workflows::room_effects::{PostgresMixRepository, WorkflowRoomEffects};
use sqlx::{postgres::PgPoolOptions, PgPool, Postgres, Transaction};
use std::time::Duration;
use uuid::Uuid;

const SERVICE: &str = "mix.example.test";
const OWNER: &str = "owner@example.test";
const PUBLISHER: &str = "publisher@example.test";
const BLOCKED: &str = "blocked@example.test";
const STORED_PAYLOAD: &str = "<message><mix xmlns='urn:xmpp:mix:core:1'><jid>publisher@example.test</jid></mix><body>history</body></message>";

struct Fixture {
    pool: PgPool,
    repository: PostgresMixRepository,
    channel_id: Uuid,
    localpart: String,
    channel_jid: String,
    remote_domain: String,
    remote_jid: String,
}

impl Fixture {
    async fn new() -> Self {
        let url = std::env::var("TEST_DATABASE_URL")
            .expect("set TEST_DATABASE_URL to an isolated PostgreSQL database");
        let pool = PgPoolOptions::new()
            .max_connections(8)
            .connect(&url)
            .await
            .unwrap();
        crate::support::migrate(&pool).await.unwrap();
        let suffix = Uuid::new_v4().simple().to_string();
        let localpart = format!("mam-authority-{suffix}");
        let remote_domain = format!("remote-{suffix}.test");
        let channel_id = create_channel(&pool, &localpart).await;
        let repository = PostgresMixRepository::new(pool.clone());
        Self {
            pool,
            repository,
            channel_id,
            channel_jid: format!("{localpart}@{SERVICE}"),
            localpart,
            remote_jid: format!("reader@{remote_domain}"),
            remote_domain,
        }
    }

    fn command(&self, actor: MixMamReadActor, query: MamArchiveQuery) -> MixMamReadCommand {
        MixMamReadCommand {
            target: MixMamReadTarget {
                service_domain: SERVICE.to_owned(),
                localpart: self.localpart.clone(),
            },
            actor,
            operation: MixMamReadOperation::Query(query),
        }
    }

    fn federated_command(&self) -> MixMamReadCommand {
        self.command(
            MixMamReadActor::Federated {
                bare_jid: self.remote_jid.clone(),
            },
            query(),
        )
    }

    async fn local_actor(&self) -> (Uuid, String, i64) {
        let id = Uuid::new_v4();
        let username = format!("mam-reader-{}", id.simple());
        let generation = sqlx::query_scalar(
            "INSERT INTO users(id,username,password_hash) VALUES($1,$2,'test-only')
             RETURNING auth_generation",
        )
        .bind(id)
        .bind(&username)
        .fetch_one(&self.pool)
        .await
        .unwrap();
        self.participant(&format!("{username}@example.test")).await;
        (id, username, generation)
    }

    async fn participant(&self, jid: &str) {
        let id = Uuid::new_v4();
        let mut tx = self.pool.begin().await.unwrap();
        sqlx::query(
            "INSERT INTO mix_participant_identities(channel_id,participant_id,jid) VALUES($1,$2,$3)",
        )
        .bind(self.channel_id)
        .bind(id)
        .bind(jid)
        .execute(&mut *tx)
        .await
        .unwrap();
        sqlx::query("INSERT INTO mix_participants(channel_id,participant_id,jid) VALUES($1,$2,$3)")
            .bind(self.channel_id)
            .bind(id)
            .bind(jid)
            .execute(&mut *tx)
            .await
            .unwrap();
        tx.commit().await.unwrap();
    }

    async fn block_publisher(&self, account_id: Uuid) {
        sqlx::query("INSERT INTO blocked_jids(owner_id,blocked_jid) VALUES($1,$2)")
            .bind(account_id)
            .bind(BLOCKED)
            .execute(&self.pool)
            .await
            .unwrap();
    }

    async fn queued(&self) -> Vec<String> {
        sqlx::query_scalar(
            "SELECT stanza FROM s2s_outbox WHERE target_domain=$1 ORDER BY enqueue_sequence",
        )
        .bind(&self.remote_domain)
        .fetch_all(&self.pool)
        .await
        .unwrap()
    }

    async fn close(self) {
        sqlx::query("DELETE FROM s2s_outbox WHERE target_domain=$1")
            .bind(&self.remote_domain)
            .execute(&self.pool)
            .await
            .unwrap();
        delete_channel(&self.pool, self.channel_id).await;
        self.pool.close().await;
    }
}

fn query() -> MamArchiveQuery {
    MamArchiveQuery {
        with_jid: None,
        start: None,
        end: None,
        before_id: None,
        after_id: None,
        ids: vec![],
        page: MamRsmPage::First,
        max: 10,
    }
}

fn local_actor(id: Uuid, username: &str, generation: i64) -> MixMamReadActor {
    MixMamReadActor::Local {
        account_id: id,
        username: username.to_owned(),
        auth_generation: generation,
        local_domain: "example.test".to_owned(),
    }
}

fn page(outcome: MixMamReadOutcome) -> MixMamPage {
    let MixMamReadOutcome::Authorized {
        result: MixMamReadResult::Page(page),
        ..
    } = outcome
    else {
        panic!("expected an authorized MAM page, got {outcome:?}");
    };
    page
}

async fn create_channel(pool: &PgPool, localpart: &str) -> Uuid {
    let (outcome, _) = create_mix_channel(
        &WorkflowRoomEffects,
        pool,
        SERVICE,
        Some(localpart),
        OWNER,
        100,
        &MixPayloads,
        None,
    )
    .await
    .unwrap();
    let CreateChannelOutcome::Created(id) = outcome else {
        panic!("expected a unique MIX channel");
    };
    id
}

async fn delete_channel(pool: &PgPool, id: Uuid) {
    sqlx::query("DELETE FROM mix_channels WHERE id=$1")
        .bind(id)
        .execute(pool)
        .await
        .unwrap();
}

async fn delete_account(pool: &PgPool, id: Uuid) {
    sqlx::query("DELETE FROM users WHERE id=$1")
        .bind(id)
        .execute(pool)
        .await
        .unwrap();
}

async fn insert_event<'e>(
    executor: impl sqlx::Executor<'e, Database = Postgres>,
    channel_id: Uuid,
    publisher: &str,
) -> Uuid {
    sqlx::query_scalar(
        "INSERT INTO mix_events(id,channel_id,node,item_id,publisher_jid,payload)
         VALUES($1,$2,$3,$4,$5,$6) RETURNING authoritative_id",
    )
    .bind(Uuid::new_v4())
    .bind(channel_id)
    .bind(NODE_MESSAGES)
    .bind(Uuid::new_v4().to_string())
    .bind(publisher)
    .bind(STORED_PAYLOAD)
    .fetch_one(executor)
    .await
    .unwrap()
}

async fn backend(tx: &mut Transaction<'_, Postgres>) -> i32 {
    sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(&mut **tx)
        .await
        .unwrap()
}

async fn wait_for_blocked_statement(
    pool: &PgPool,
    blocker: i32,
    statement: &str,
    wait_events: &[&str],
) -> i32 {
    let waiter = crate::support::blocked_backend(pool, blocker).await;
    let (query, event): (String, String) =
        sqlx::query_as("SELECT query, wait_event FROM pg_stat_activity WHERE pid=$1")
            .bind(waiter)
            .fetch_one(pool)
            .await
            .unwrap();
    assert!(
        query.contains(statement),
        "unexpected waiting statement: {query}"
    );
    assert!(
        wait_events.contains(&event.as_str()),
        "unexpected lock wait: {event}"
    );
    waiter
}

#[tokio::test]
#[ignore = "requires an isolated TEST_DATABASE_URL PostgreSQL database"]
async fn local_mix_mam_uses_the_same_snapshot_after_disable_or_generation_change() {
    for (disable, pause_after_account) in [(true, false), (false, false), (true, true)] {
        let fixture = Fixture::new().await;
        let (id, username, generation) = fixture.local_actor().await;
        fixture.block_publisher(id).await;
        let visible = insert_event(&fixture.pool, fixture.channel_id, PUBLISHER).await;
        insert_event(&fixture.pool, fixture.channel_id, BLOCKED).await;

        let (entered, resume) =
            PostgresMixRepository::install_local_mix_mam_test_pause(id, pause_after_account);
        let repository = fixture.repository.clone();
        let command = fixture.command(local_actor(id, &username, generation), query());
        let reader = tokio::spawn(async move { repository.read_mix_mam(command).await.unwrap() });
        tokio::time::timeout(Duration::from_secs(5), entered)
            .await
            .expect("local MAM did not reach the test pause")
            .unwrap();
        let mut barrier = fixture.pool.begin().await.unwrap();
        sqlx::query(
            "UPDATE users SET is_disabled=$2,auth_generation=auth_generation+$3 WHERE id=$1",
        )
        .bind(id)
        .bind(disable)
        .bind(if disable { 0_i64 } else { 1_i64 })
        .execute(&mut *barrier)
        .await
        .unwrap();
        insert_event(&mut *barrier, fixture.channel_id, PUBLISHER).await;
        barrier.commit().await.unwrap();
        resume.send(()).unwrap();

        let old = page(reader.await.unwrap());
        assert_eq!(old.total, 1);
        assert_eq!(old.events[0].id, visible);
        for operation in [
            MixMamReadOperation::Query(query()),
            MixMamReadOperation::Form,
            MixMamReadOperation::Metadata,
        ] {
            let mut command = fixture.command(local_actor(id, &username, generation), query());
            command.operation = operation;
            assert!(matches!(
                fixture.repository.read_mix_mam(command).await.unwrap(),
                MixMamReadOutcome::StaleAccount
            ));
        }
        delete_account(&fixture.pool, id).await;
        fixture.close().await;
    }
}

#[derive(Clone, Copy, Debug)]
enum Revocation {
    Leave,
    Ban,
    Destroy,
}

async fn lock_channel(tx: &mut Transaction<'_, Postgres>, channel_id: Uuid) {
    sqlx::query("SELECT id FROM mix_channels WHERE id=$1 FOR UPDATE")
        .bind(channel_id)
        .fetch_one(&mut **tx)
        .await
        .unwrap();
}

async fn stage_outbox_stanza(tx: &mut Transaction<'_, Postgres>, domain: &str, stanza: &str) {
    WorkflowRoomEffects
        .enqueue_federated_stanza(
            tx,
            domain,
            stanza,
            None,
            S2sOutboxPolicy::new(60, 1_000, 1_000_000, 2),
        )
        .await
        .unwrap();
}

async fn revoke(tx: &mut Transaction<'_, Postgres>, fixture: &Fixture, action: Revocation) {
    match action {
        Revocation::Leave => {
            sqlx::query("DELETE FROM mix_participants WHERE channel_id=$1 AND jid=$2")
                .bind(fixture.channel_id)
                .bind(&fixture.remote_jid)
                .execute(&mut **tx)
                .await
        }
        Revocation::Ban => {
            sqlx::query("INSERT INTO mix_banned(channel_id,jid_pattern,added_by) VALUES($1,$2,$3)")
                .bind(fixture.channel_id)
                .bind(&fixture.remote_jid)
                .bind(OWNER)
                .execute(&mut **tx)
                .await
        }
        Revocation::Destroy => {
            sqlx::query("DELETE FROM mix_channels WHERE id=$1")
                .bind(fixture.channel_id)
                .execute(&mut **tx)
                .await
        }
    }
    .unwrap();
}

fn spawn_federated_read(
    fixture: &Fixture,
    max_per_domain: i64,
) -> tokio::task::JoinHandle<anyhow::Result<MixMamAdmissionOutcome>> {
    let command = fixture.federated_command();
    let repository = fixture.repository.clone();
    let domain = fixture.remote_domain.clone();
    let from = fixture.channel_jid.clone();
    tokio::spawn(async move {
        repository
            .admit_federated_mix_mam(
                command,
                &domain,
                S2sOutboxPolicy::new(60, 1_000, 1_000_000, max_per_domain),
                |outcome| {
                    Ok(match outcome {
                        MixMamReadOutcome::Authorized {
                            result: MixMamReadResult::Page(page), ..
                        } => {
                            let mut stanzas = page.events.iter().map(|event| {
                                format!("<message from='{from}'><result xmlns='urn:xmpp:mam:2' id='{}'/></message>", event.id)
                            }).collect::<Vec<_>>();
                            stanzas.push("<iq type='result' id='mam'><fin xmlns='urn:xmpp:mam:2'/></iq>".to_owned());
                            stanzas
                        }
                        MixMamReadOutcome::MissingChannel => vec![
                            "<iq type='error' id='mam'><error type='cancel'><item-not-found/></error></iq>".to_owned(),
                        ],
                        MixMamReadOutcome::NotAuthorized { .. } => vec![
                            "<iq type='error' id='mam'><error type='auth'><forbidden/></error></iq>".to_owned(),
                        ],
                        _ => panic!("unexpected federated MAM outcome: {outcome:?}"),
                    })
                },
            )
            .await
    })
}

#[tokio::test]
#[ignore = "requires an isolated TEST_DATABASE_URL PostgreSQL database"]
async fn federated_mix_mam_denies_revocation_committed_while_waiting_for_channel() {
    for action in [Revocation::Leave, Revocation::Ban, Revocation::Destroy] {
        let fixture = Fixture::new().await;
        fixture.participant(&fixture.remote_jid).await;
        insert_event(&fixture.pool, fixture.channel_id, PUBLISHER).await;
        let mut writer = fixture.pool.begin().await.unwrap();
        let blocker = backend(&mut writer).await;
        lock_channel(&mut writer, fixture.channel_id).await;
        let read = spawn_federated_read(&fixture, 10);
        wait_for_blocked_statement(
            &fixture.pool,
            blocker,
            "FROM mix_channels WHERE id = $1 FOR SHARE",
            &["transactionid", "tuple"],
        )
        .await;
        revoke(&mut writer, &fixture, action).await;
        writer.commit().await.unwrap();
        assert!(matches!(
            read.await.unwrap().unwrap(),
            MixMamAdmissionOutcome::Queued
        ));

        let queued = fixture.queued().await;
        assert_eq!(queued.len(), 1, "{action:?}");
        let condition = if matches!(action, Revocation::Destroy) {
            "item-not-found"
        } else {
            "forbidden"
        };
        assert!(queued[0].contains(condition), "{action:?}: {queued:?}");
        fixture.close().await;
    }
}

#[tokio::test]
#[ignore = "requires an isolated TEST_DATABASE_URL PostgreSQL database"]
async fn federated_mix_mam_revocation_after_channel_fence_sees_whole_batch() {
    for action in [Revocation::Leave, Revocation::Ban, Revocation::Destroy] {
        let fixture = Fixture::new().await;
        fixture.participant(&fixture.remote_jid).await;
        let id = insert_event(&fixture.pool, fixture.channel_id, PUBLISHER).await;
        let other_channel =
            create_channel(&fixture.pool, &format!("{}-other", fixture.localpart)).await;
        // The reader reaches the advisory lock only after reading and
        // rendering under the channel share lock.
        let mut barrier = fixture.pool.begin().await.unwrap();
        stage_outbox_stanza(
            &mut barrier,
            &fixture.remote_domain,
            "<iq type='result' id='barrier'/>",
        )
        .await;
        let blocker = backend(&mut barrier).await;
        let read = spawn_federated_read(&fixture, 10);
        let reader = wait_for_blocked_statement(
            &fixture.pool,
            blocker,
            "pg_advisory_xact_lock",
            &["advisory"],
        )
        .await;

        let mut other_writer = fixture.pool.begin().await.unwrap();
        tokio::time::timeout(
            Duration::from_secs(5),
            lock_channel(&mut other_writer, other_channel),
        )
        .await
        .expect("MAM admission on one channel blocked a different channel");
        other_writer.rollback().await.unwrap();

        let writer_pool = fixture.pool.clone();
        let channel_id = fixture.channel_id;
        let domain = fixture.remote_domain.clone();
        let writer = tokio::spawn(async move {
            let mut writer = writer_pool.begin().await.unwrap();
            lock_channel(&mut writer, channel_id).await;
            let queued: Vec<String> = sqlx::query_scalar(
                "SELECT stanza FROM s2s_outbox WHERE target_domain=$1 ORDER BY enqueue_sequence",
            )
            .bind(domain)
            .fetch_all(&mut *writer)
            .await
            .unwrap();
            (writer, queued)
        });
        wait_for_blocked_statement(
            &fixture.pool,
            reader,
            "FROM mix_channels WHERE id=$1 FOR UPDATE",
            &["transactionid", "tuple"],
        )
        .await;
        barrier.rollback().await.unwrap();
        assert!(matches!(
            read.await.unwrap().unwrap(),
            MixMamAdmissionOutcome::Queued
        ));
        let (mut writer, queued) = writer.await.unwrap();
        assert_eq!(queued.len(), 2, "{action:?}");
        assert!(queued[0].contains(&id.to_string()), "{queued:?}");
        assert!(queued[1].contains("<fin"), "{queued:?}");
        revoke(&mut writer, &fixture, action).await;
        writer.commit().await.unwrap();
        assert_eq!(fixture.queued().await, queued);
        delete_channel(&fixture.pool, other_channel).await;
        fixture.close().await;
    }
}

#[tokio::test]
#[ignore = "requires an isolated TEST_DATABASE_URL PostgreSQL database"]
async fn federated_mix_mam_quota_rejection_rolls_back_the_result_prefix() {
    let fixture = Fixture::new().await;
    fixture.participant(&fixture.remote_jid).await;
    insert_event(&fixture.pool, fixture.channel_id, PUBLISHER).await;

    let outcome = spawn_federated_read(&fixture, 1).await.unwrap().unwrap();
    let MixMamAdmissionOutcome::OutboxRejected(error) = outcome else {
        panic!("expected quota rejection, got {outcome:?}");
    };
    assert!(
        error.to_string().contains("per-domain capacity"),
        "{error:#}"
    );
    assert!(fixture.queued().await.is_empty());

    // The quota reads run after the advisory lock and must see the prior
    // enqueuer's commit even though MAM has already read the archive.
    let prior = "<iq type='result' id='earlier'/>";
    let mut writer = fixture.pool.begin().await.unwrap();
    stage_outbox_stanza(&mut writer, &fixture.remote_domain, prior).await;
    let blocker = backend(&mut writer).await;
    let read = spawn_federated_read(&fixture, 2);
    wait_for_blocked_statement(
        &fixture.pool,
        blocker,
        "pg_advisory_xact_lock",
        &["advisory"],
    )
    .await;
    writer.commit().await.unwrap();
    assert!(matches!(
        read.await.unwrap().unwrap(),
        MixMamAdmissionOutcome::OutboxRejected(_)
    ));
    assert_eq!(fixture.queued().await, vec![prior.to_owned()]);
    fixture.close().await;
}

#[tokio::test]
#[ignore = "requires an isolated TEST_DATABASE_URL PostgreSQL database"]
async fn mix_mam_ids_resolve_in_visible_scope_before_filters() {
    let fixture = Fixture::new().await;
    let (account_id, username, generation) = fixture.local_actor().await;
    fixture.block_publisher(account_id).await;
    let visible = insert_event(&fixture.pool, fixture.channel_id, PUBLISHER).await;
    let blocked = insert_event(&fixture.pool, fixture.channel_id, BLOCKED).await;
    let deleted = insert_event(&fixture.pool, fixture.channel_id, PUBLISHER).await;
    sqlx::query("DELETE FROM mix_events WHERE channel_id=$1 AND authoritative_id=$2")
        .bind(fixture.channel_id)
        .bind(deleted)
        .execute(&fixture.pool)
        .await
        .unwrap();
    let other_channel =
        create_channel(&fixture.pool, &format!("{}-other", fixture.localpart)).await;
    let other = insert_event(&fixture.pool, other_channel, PUBLISHER).await;
    let read = |query| {
        fixture
            .repository
            .read_mix_mam(fixture.command(local_actor(account_id, &username, generation), query))
    };

    let mut filtered = query();
    filtered.with_jid = Some(PUBLISHER.to_owned());
    filtered.ids = vec![visible, visible];
    let matched = page(read(filtered.clone()).await.unwrap());
    assert_eq!(matched.total, 1);
    assert_eq!(matched.events[0].id, visible);

    for with in ["other@example.test", "publisher@example.test/resource"] {
        filtered.with_jid = Some(with.to_owned());
        let empty = page(read(filtered.clone()).await.unwrap());
        assert!(empty.events.is_empty());
        assert_eq!(empty.total, 0);
        assert!(empty.complete);
    }
    filtered.ids.clear();
    let full_jid_only = page(read(filtered).await.unwrap());
    assert!(full_jid_only.events.is_empty());
    assert_eq!(full_jid_only.total, 0);
    assert!(full_jid_only.complete);

    for id in [blocked, other, deleted] {
        let mut requested = query();
        requested.ids = vec![visible, id];
        assert!(
            matches!(
                read(requested).await.unwrap(),
                MixMamReadOutcome::Authorized {
                    result: MixMamReadResult::MissingReference,
                    ..
                }
            ),
            "ID {id} is outside the visible base scope"
        );
    }
    delete_channel(&fixture.pool, other_channel).await;
    delete_account(&fixture.pool, account_id).await;
    fixture.close().await;
}

#[tokio::test]
#[ignore = "requires an isolated TEST_DATABASE_URL PostgreSQL database"]
async fn mix_mam_keeps_the_stored_publisher_identity_after_visibility_changes() {
    let fixture = Fixture::new().await;
    let (account_id, username, generation) = fixture.local_actor().await;
    let id = insert_event(&fixture.pool, fixture.channel_id, PUBLISHER).await;
    sqlx::query("UPDATE mix_channels SET jid_visibility='hidden' WHERE id=$1")
        .bind(fixture.channel_id)
        .execute(&fixture.pool)
        .await
        .unwrap();

    let command = fixture.command(local_actor(account_id, &username, generation), query());
    let result = page(fixture.repository.read_mix_mam(command).await.unwrap());
    assert_eq!(result.total, 1);
    assert_eq!(result.events[0].id, id);
    assert_eq!(result.events[0].payload, STORED_PAYLOAD);
    delete_account(&fixture.pool, account_id).await;
    fixture.close().await;
}
