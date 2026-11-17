use std::time::Duration;
use uuid::Uuid;

#[tokio::test]
#[ignore = "requires the ordinary-role random schema and TEST_DATABASE_URL"]
async fn recovery_poll_statement_timeout_rolls_back_and_does_not_leak_to_the_pool() {
    let pool = crate::support::operation_mutation_pool().await;
    let mut blocker = pool.begin().await.unwrap();
    sqlx::query("LOCK TABLE omemo_recovery_poll_capabilities IN ACCESS EXCLUSIVE MODE")
        .execute(&mut *blocker)
        .await
        .unwrap();
    let blocker_pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(&mut *blocker)
        .await
        .unwrap();
    let polling_pool = pool.clone();
    let poll = tokio::spawn(async move {
        northstar_auth_postgres::omemo_recovery::poll_omemo_recovery_transfer(
            &polling_pool,
            "example.test",
            Uuid::from_u128(0x573_9501),
            &[7; 32],
        )
        .await
    });
    let pid = crate::support::blocked_backend(&pool, blocker_pid).await;
    let result = tokio::time::timeout(Duration::from_secs(5), poll)
        .await
        .unwrap()
        .unwrap();
    let Err(error) = result else {
        panic!("poll succeeded through an exclusive table lock");
    };
    assert_eq!(
        error
            .downcast_ref::<sqlx::Error>()
            .and_then(sqlx::Error::as_database_error)
            .and_then(|error| error.code())
            .as_deref(),
        Some("57014"),
        "database statement timeout"
    );
    blocker.rollback().await.unwrap();
    // Reserve every connection, including the one that ran the timed-out
    // transaction; inspect its session setting after SQLx rolls it back.
    let mut connections = Vec::new();
    for _ in 0..4 {
        connections.push(pool.acquire().await.unwrap());
    }
    let mut original_seen = false;
    for connection in &mut connections {
        let (current_pid, timeout): (i32, String) =
            sqlx::query_as("SELECT pg_backend_pid(),current_setting('statement_timeout')")
                .fetch_one(&mut **connection)
                .await
                .unwrap();
        if current_pid == pid {
            original_seen = true;
            assert_ne!(
                timeout, "1500ms",
                "transaction-local timeout escaped into a pooled session"
            );
        }
    }
    assert!(
        original_seen,
        "timed-out poll backend remains reusable after rollback"
    );
    drop(connections);
    assert!(
        northstar_auth_postgres::omemo_recovery::poll_omemo_recovery_transfer(
            &pool,
            "example.test",
            Uuid::from_u128(0x573_9501),
            &[7; 32],
        )
        .await
        .unwrap()
        .is_none()
    );
    pool.close().await;
}
