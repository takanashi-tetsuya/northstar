use super::presence_service::IsolatedDatabase;
use northstar_message_application::messaging::MessageService;
use northstar_roster_postgres::privacy::{
    clear_active_privacy_session, renew_active_privacy_selection, replace_privacy_list,
    session_privacy_denies, set_active_privacy_list, set_default_privacy_list,
};
use northstar_workflows::message_repository::PostgresMessageRepository;
use northstar_xep_0016::{PrivacyAction, PrivacyItem, PrivacyList, PrivacyStanzaKind};
use sqlx::PgPool;
use std::time::Duration;
use uuid::Uuid;

const PEER: &str = "alice@example.test/Phone";

async fn setup() -> (
    IsolatedDatabase,
    Uuid,
    Uuid,
    MessageService<PostgresMessageRepository>,
) {
    let database = IsolatedDatabase::create("privacy_decision").await;
    let pool = &database.pool;
    let owner = northstar_auth_postgres::users::create_user(
        pool,
        "bob",
        "Initial password for test!42",
        false,
        true,
        4096,
        false,
    )
    .await
    .unwrap()
    .id;
    let connection = Uuid::new_v4();
    for (name, action) in [
        ("allow", PrivacyAction::Allow),
        ("deny", PrivacyAction::Deny),
    ] {
        replace_privacy_list(
            pool,
            owner,
            &PrivacyList {
                name: name.to_owned(),
                items: vec![PrivacyItem {
                    order: 10,
                    action,
                    match_type: None,
                    match_value: None,
                    message: true,
                    iq: false,
                    presence_in: false,
                    presence_out: false,
                }],
            },
        )
        .await
        .unwrap();
    }
    assert!(set_default_privacy_list(pool, owner, Some("allow"))
        .await
        .unwrap());
    assert!(
        set_active_privacy_list(pool, owner, connection, Some("allow"))
            .await
            .unwrap()
    );
    let service = MessageService::new(
        PostgresMessageRepository::new(
            pool.clone(),
            northstar_abuse_application::guard::test_personal_message_content_keyring(),
            "example.test",
            100,
            8_000_000,
            30,
        ),
        false,
    );
    (database, owner, connection, service)
}

async fn lease(pool: &PgPool, connection: Uuid) -> (String, String) {
    sqlx::query_as(
        "SELECT updated_at::text, expires_at::text FROM privacy_active_sessions WHERE connection_id=$1",
    )
    .bind(connection)
    .fetch_one(pool)
    .await
    .unwrap()
}

#[tokio::test]
#[ignore = "requires a random-schema TEST_DATABASE_URL"]
async fn session_privacy_is_read_only_even_with_the_lease_row_locked() {
    let (database, owner, connection, service) = setup().await;
    let before = lease(&database.pool, connection).await;
    let mut writer = database.pool.begin().await.unwrap();
    sqlx::query("SELECT owner_id FROM privacy_active_sessions WHERE connection_id=$1 FOR UPDATE")
        .bind(connection)
        .fetch_one(&mut *writer)
        .await
        .unwrap();
    let result = tokio::time::timeout(
        Duration::from_secs(5),
        service.privacy_allows_session(
            owner,
            connection,
            Some("allow"),
            PEER,
            PrivacyStanzaKind::Message,
        ),
    )
    .await;
    writer.rollback().await.unwrap();
    assert!(result
        .expect("decision should not wait for the lease row")
        .unwrap());

    let mut reader = database.pool.begin().await.unwrap();
    sqlx::query("SET TRANSACTION READ ONLY")
        .execute(&mut *reader)
        .await
        .unwrap();
    assert!(!session_privacy_denies(
        &mut *reader,
        owner,
        Some(connection),
        true,
        PEER,
        PrivacyStanzaKind::Message,
    )
    .await
    .unwrap());
    let takes_policy_locks: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM pg_locks WHERE pid=pg_backend_pid()
           AND (locktype IN ('tuple','advisory') OR (locktype='relation' AND mode<>'AccessShareLock')))",
    ).fetch_one(&mut *reader).await.unwrap();
    reader.commit().await.unwrap();
    assert!(!takes_policy_locks);
    assert_eq!(lease(&database.pool, connection).await, before);
    database.finish().await;
}

#[tokio::test]
#[ignore = "requires a random-schema TEST_DATABASE_URL"]
async fn session_privacy_honors_switches_and_does_not_resurrect_a_lost_selection() {
    let (database, owner, connection, service) = setup().await;
    let pool = &database.pool;
    assert!(
        set_active_privacy_list(pool, owner, connection, Some("deny"))
            .await
            .unwrap()
    );
    assert!(!service
        .privacy_allows_session(
            owner,
            connection,
            Some("allow"),
            PEER,
            PrivacyStanzaKind::Message
        )
        .await
        .unwrap());
    assert!(
        set_active_privacy_list(pool, owner, connection, Some("allow"))
            .await
            .unwrap()
    );
    sqlx::query("UPDATE privacy_active_sessions SET expires_at=statement_timestamp()+INTERVAL '1 hour' WHERE connection_id=$1")
        .bind(connection).execute(pool).await.unwrap();
    let before = lease(pool, connection).await;
    renew_active_privacy_selection(pool, &[connection])
        .await
        .unwrap();
    let leased_for_another_day: bool = sqlx::query_scalar(
        "SELECT expires_at>statement_timestamp()+INTERVAL '23 hours'
           FROM privacy_active_sessions WHERE connection_id=$1",
    )
    .bind(connection)
    .fetch_one(pool)
    .await
    .unwrap();
    assert!(leased_for_another_day);
    assert_ne!(lease(pool, connection).await, before);
    assert!(service
        .privacy_allows_session(
            owner,
            connection,
            Some("allow"),
            PEER,
            PrivacyStanzaKind::Message
        )
        .await
        .unwrap());
    sqlx::query("UPDATE privacy_active_sessions SET expires_at=statement_timestamp()-INTERVAL '1 second' WHERE connection_id=$1")
        .bind(connection).execute(pool).await.unwrap();
    let expired = lease(pool, connection).await;
    renew_active_privacy_selection(pool, &[connection])
        .await
        .unwrap();
    assert!(!service
        .privacy_allows_session(
            owner,
            connection,
            Some("allow"),
            PEER,
            PrivacyStanzaKind::Message
        )
        .await
        .unwrap());
    assert_eq!(lease(pool, connection).await, expired);
    clear_active_privacy_session(pool, owner, connection)
        .await
        .unwrap();
    assert!(!service
        .privacy_allows_session(
            owner,
            connection,
            Some("allow"),
            PEER,
            PrivacyStanzaKind::Message
        )
        .await
        .unwrap());
    assert!(service
        .privacy_allows_session(owner, connection, None, PEER, PrivacyStanzaKind::Message)
        .await
        .unwrap());
    database.finish().await;
}
