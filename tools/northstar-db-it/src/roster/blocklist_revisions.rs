use super::presence_service::IsolatedDatabase;
use northstar_auth_postgres::users::create_user;
use northstar_roster_application::blocklist_revisions::{
    BlocklistAction, BlocklistRevisionRepository,
};
use northstar_roster_core::RosterActor;
use northstar_roster_postgres::roster::{block_jids, unblock_jids, PostgresBlockingRepository};
use northstar_stream::local_routes::session::test_online_session;
use sqlx::PgPool;
use std::sync::atomic::Ordering;
use tokio::sync::oneshot;
use uuid::Uuid;

const PEER: &str = "bob@example.test";

async fn owner(pool: &PgPool) -> RosterActor {
    let user = create_user(
        pool,
        "alice",
        "Initial password for test!42",
        false,
        true,
        4096,
        false,
    )
    .await
    .unwrap();
    RosterActor {
        account_id: user.id,
        auth_generation: user.auth_generation,
        connection_id: Uuid::new_v4(),
        full_jid: "alice@example.test/Desk".into(),
    }
}

async fn head(repository: &PostgresBlockingRepository, actor: &RosterActor) -> i64 {
    repository
        .blocklist_journal(actor, None)
        .await
        .unwrap()
        .unwrap()
        .revision
}

#[tokio::test]
#[ignore = "requires a random-schema TEST_DATABASE_URL"]
async fn block_mutations_fanned_out_in_inverse_order_are_delivered_in_revision_order() {
    let database = IsolatedDatabase::create("blocklist_inverse").await;
    let actor = owner(&database.pool).await;
    let repository = PostgresBlockingRepository::new(database.pool.clone());
    let (session, mut output) = test_online_session(
        actor.account_id,
        actor.auth_generation,
        actor.connection_id,
        "Desk",
        4,
    );
    let epoch = session.blocklist_observation.begin_snapshot();
    session.blocklist_requested.store(true, Ordering::Release);
    assert!(session
        .blocklist_observation
        .finish_snapshot(epoch, head(&repository, &actor).await));
    let (committed_tx, committed_rx) = oneshot::channel();
    let (resume_tx, resume_rx) = oneshot::channel();
    let first_pool = database.pool.clone();
    let first_actor = actor.clone();
    let first_repo = repository.clone();
    let first = tokio::spawn(async move {
        block_jids(&first_pool, first_actor.account_id, &[PEER.to_owned()])
            .await
            .unwrap();
        let revision = head(&first_repo, &first_actor).await;
        committed_tx.send(()).unwrap();
        resume_rx.await.unwrap();
        revision
    });
    committed_rx.await.unwrap();
    unblock_jids(&database.pool, actor.account_id, None)
        .await
        .unwrap();
    let high = head(&repository, &actor).await;
    assert_eq!(high, 2);
    assert!(session.signal_blocklist_revision(high));
    let mut actions = Vec::new();
    let mut revisions = Vec::new();
    for change in repository
        .blocklist_journal(&actor, Some(0))
        .await
        .unwrap()
        .unwrap()
        .changes
    {
        assert_eq!(change.patterns, [PEER.to_owned()]);
        actions.push(change.action);
        revisions.push(change.revision);
        session
            .blocklist_observation
            .enqueue_next(epoch, change.revision, |fence| {
                session
                    .sender
                    .try_send_snapshot_push(change.revision.to_string(), fence)
            })
            .unwrap()
            .unwrap();
    }
    assert_eq!(revisions, [1, 2]);
    assert_eq!(
        actions,
        [BlocklistAction::Block, BlocklistAction::UnblockAll]
    );
    resume_tx.send(()).unwrap();
    let low = first.await.unwrap();
    assert_eq!(low, 1);
    assert!(session.signal_blocklist_revision(low));
    assert!(repository
        .blocklist_journal(&actor, session.blocklist_observation.cursor(epoch))
        .await
        .unwrap()
        .unwrap()
        .changes
        .is_empty());
    assert_eq!(output.try_recv().unwrap().stanza, "1");
    assert_eq!(output.try_recv().unwrap().stanza, "2");
    assert!(output.try_recv().is_err());
    database.finish().await;
}

#[tokio::test]
#[ignore = "requires a random-schema TEST_DATABASE_URL"]
async fn no_op_does_not_append_or_advance_the_counter() {
    let database = IsolatedDatabase::create("blocklist_no_op").await;
    let actor = owner(&database.pool).await;
    let repository = PostgresBlockingRepository::new(database.pool.clone());
    unblock_jids(&database.pool, actor.account_id, None)
        .await
        .unwrap();
    assert_eq!(head(&repository, &actor).await, 0);
    block_jids(&database.pool, actor.account_id, &[PEER.to_owned()])
        .await
        .unwrap();
    block_jids(&database.pool, actor.account_id, &[PEER.to_owned()])
        .await
        .unwrap();
    unblock_jids(
        &database.pool,
        actor.account_id,
        Some(&["other.test".into()]),
    )
    .await
    .unwrap();
    let journal = repository
        .blocklist_journal(&actor, Some(0))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(journal.revision, 1);
    assert_eq!(journal.changes.len(), 1);
    assert_eq!(journal.changes[0].patterns, [PEER.to_owned()]);
    database.finish().await;
}

#[tokio::test]
#[ignore = "requires a random-schema TEST_DATABASE_URL"]
async fn a_commit_failure_rolls_back_the_delta_counter_and_list() {
    let database = IsolatedDatabase::create("blocklist_rollback").await;
    let actor = owner(&database.pool).await;
    let repository = PostgresBlockingRepository::new(database.pool.clone());
    block_jids(&database.pool, actor.account_id, &[PEER.to_owned()])
        .await
        .unwrap();
    sqlx::query(
        "CREATE FUNCTION refuse_second_revision() RETURNS trigger LANGUAGE plpgsql AS $$
        BEGIN RAISE EXCEPTION 'intentional journal rollback'; END; $$",
    )
    .execute(&database.pool)
    .await
    .unwrap();
    sqlx::query(
        "CREATE CONSTRAINT TRIGGER refuse_second_revision AFTER INSERT ON blocklist_change_log
        DEFERRABLE INITIALLY DEFERRED FOR EACH ROW WHEN (NEW.revision = 2)
        EXECUTE FUNCTION refuse_second_revision()",
    )
    .execute(&database.pool)
    .await
    .unwrap();
    let error = unblock_jids(&database.pool, actor.account_id, None)
        .await
        .unwrap_err();
    assert!(error.to_string().contains("intentional journal rollback"));
    assert_eq!(head(&repository, &actor).await, 1);
    let snapshot = repository
        .blocklist_snapshot(&actor)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(snapshot.patterns, [PEER.to_owned()]);
    assert!(repository
        .blocklist_journal(&actor, Some(1))
        .await
        .unwrap()
        .unwrap()
        .changes
        .is_empty());
    database.finish().await;
}

#[tokio::test]
#[ignore = "requires a random-schema TEST_DATABASE_URL"]
async fn journal_repairs_a_lost_final_push_without_another_mutation() {
    let database = IsolatedDatabase::create("blocklist_lost_push").await;
    let actor = owner(&database.pool).await;
    let repository = PostgresBlockingRepository::new(database.pool.clone());
    let before = repository
        .blocklist_snapshot(&actor)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(before.revision, 0);
    assert!(before.patterns.is_empty());
    block_jids(&database.pool, actor.account_id, &[PEER.to_owned()])
        .await
        .unwrap();
    let recovered = repository
        .blocklist_journal(&actor, Some(before.revision))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(recovered.revision, 1);
    assert_eq!(recovered.changes.len(), 1);
    assert_eq!(recovered.changes[0].revision, 1);
    assert_eq!(recovered.changes[0].patterns, [PEER.to_owned()]);
    assert_eq!(recovered.changes[0].action, BlocklistAction::Block);
    database.finish().await;
}

#[tokio::test]
#[ignore = "requires a random-schema TEST_DATABASE_URL"]
async fn recreated_account_has_an_independent_revision_journal() {
    let database = IsolatedDatabase::create("blocklist_recreated").await;
    let original = owner(&database.pool).await;
    let repository = PostgresBlockingRepository::new(database.pool.clone());
    block_jids(&database.pool, original.account_id, &[PEER.to_owned()])
        .await
        .unwrap();
    sqlx::query("DELETE FROM users WHERE id = $1")
        .bind(original.account_id)
        .execute(&database.pool)
        .await
        .unwrap();
    let recreated = owner(&database.pool).await;
    assert_ne!(original.account_id, recreated.account_id);
    assert_eq!(head(&repository, &recreated).await, 0);
    assert!(repository
        .blocklist_journal(&original, Some(0))
        .await
        .unwrap()
        .is_none());
    let retained: i64 =
        sqlx::query_scalar("SELECT count(*) FROM blocklist_change_log WHERE owner_id = $1")
            .bind(original.account_id)
            .fetch_one(&database.pool)
            .await
            .unwrap();
    assert_eq!(retained, 0);
    block_jids(&database.pool, recreated.account_id, &[PEER.to_owned()])
        .await
        .unwrap();
    assert_eq!(head(&repository, &recreated).await, 1);
    database.finish().await;
}
