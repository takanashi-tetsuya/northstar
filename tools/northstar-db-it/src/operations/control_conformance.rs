use northstar_operations_application::runtime_control::{
    RuntimeControlReadPhase, RuntimeControlRepository,
};
use northstar_operations_postgres::runtime_control_repository::PostgresRuntimeControlRepository;
use std::time::Duration;

#[tokio::test]
#[ignore = "requires the ordinary-role random schema and TEST_DATABASE_URL"]
async fn control_reads_keep_the_reserved_backend_under_pool_exhaustion() {
    let pool = crate::support::operation_mutation_pool().await;
    northstar_operations_postgres::admin_commands::initialize_admin_runtime_settings(
        &pool, false, false, false,
    )
    .await
    .unwrap();
    let mut connection = pool.acquire().await.unwrap();
    let (pid, schema): (i32, String) = sqlx::query_as("SELECT pg_backend_pid(),current_schema()")
        .fetch_one(&mut *connection)
        .await
        .unwrap();
    // The policy reader must resolve this connection-local relation. Its
    // returned domain records the backend and original application schema.
    sqlx::query("CREATE TEMP VIEW federation_runtime_rules AS SELECT 'blacklist'::text AS kind,pg_backend_pid()::text || ':' || current_schema()::text AS domain")
        .execute(&mut *connection).await.unwrap();
    let mut repository = PostgresRuntimeControlRepository::new(connection);
    let held = [
        pool.acquire().await.unwrap(),
        pool.acquire().await.unwrap(),
        pool.acquire().await.unwrap(),
    ];
    assert!(
        tokio::time::timeout(Duration::from_millis(20), pool.acquire())
            .await
            .is_err(),
        "traffic acquisitions exhaust the pool"
    );
    for _ in 0..2 {
        let mut phases = Vec::new();
        let snapshot = tokio::time::timeout(
            Duration::from_secs(2),
            repository.policy_snapshot(|phase| phases.push(phase)),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(snapshot.blacklist, vec![format!("{pid}:{schema}")]);
        assert!(matches!(
            phases.as_slice(),
            [RuntimeControlReadPhase::Snapshot]
        ));
        let _ = tokio::time::timeout(Duration::from_secs(2), repository.service_control())
            .await
            .unwrap()
            .unwrap();
    }
    drop(held);
    let mut blocker = pool.begin().await.unwrap();
    let blocker_pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(&mut *blocker)
        .await
        .unwrap();
    sqlx::query("LOCK TABLE admin_runtime_settings IN ACCESS EXCLUSIVE MODE")
        .execute(&mut *blocker)
        .await
        .unwrap();
    let reader = tokio::spawn(async move {
        let snapshot = repository.policy_snapshot(|_| {}).await.unwrap();
        (repository, snapshot)
    });
    assert_eq!(
        crate::support::blocked_backend(&pool, blocker_pid).await,
        pid,
        "policy uses the originally reserved backend"
    );
    blocker.rollback().await.unwrap();
    let (mut repository, _) = reader.await.unwrap();

    let mut blocker = pool.begin().await.unwrap();
    sqlx::query("LOCK TABLE admin_service_control IN ACCESS EXCLUSIVE MODE")
        .execute(&mut *blocker)
        .await
        .unwrap();
    let blocker_pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(&mut *blocker)
        .await
        .unwrap();
    let reader = tokio::spawn(async move {
        let result = repository.service_control().await;
        (repository, result)
    });
    assert_eq!(
        crate::support::blocked_backend(&pool, blocker_pid).await,
        pid,
        "service control uses the same reserved backend"
    );
    blocker.rollback().await.unwrap();
    let (mut repository, result) = reader.await.unwrap();
    let _ = result.unwrap();
    assert_eq!(
        repository.policy_snapshot(|_| {}).await.unwrap().blacklist,
        vec![format!("{pid}:{schema}")]
    );
    drop(repository);
    pool.close().await;
}
