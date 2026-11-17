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

#[tokio::test]
#[ignore = "requires the ordinary-role random schema and TEST_DATABASE_URL"]
async fn runtime_control_reservation_holds_one_pinned_backend() {
    use northstar_config::Config;
    use northstar_operations_postgres::runtime_control_connection::reserve_runtime_control_connection;

    async fn control_backends(pool: &sqlx::PgPool, label: &str) -> Vec<i32> {
        sqlx::query_scalar(
            "SELECT pid FROM pg_catalog.pg_stat_activity
             WHERE datname=current_database() AND application_name=$1 ORDER BY pid",
        )
        .bind("northstar-runtime-control")
        .fetch_all(pool)
        .await
        .unwrap_or_else(|error| panic!("{label}: inspect control backends: {error}"))
    }

    async fn wait_for_control_backends_to_close(pool: &sqlx::PgPool, label: &str) {
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                if control_backends(pool, label).await.is_empty() {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap_or_else(|_| panic!("{label}: private control pool leaked a backend"));
    }

    let pool = crate::support::operation_mutation_pool().await;
    let database_url = std::env::var("TEST_DATABASE_URL").expect("TEST_DATABASE_URL is required");
    let expected_schema =
        std::env::var("TEST_DATABASE_SCHEMA").expect("TEST_DATABASE_SCHEMA is required");
    // The development override accepts only a server that sees a loopback
    // (or Unix-socket) connection. A containerised server sees its bridge
    // address instead, so that environment must observe the refusal.
    let server_address: Option<String> =
        sqlx::query_scalar("SELECT pg_catalog.inet_server_addr()::text")
            .fetch_one(&pool)
            .await
            .unwrap();
    let loopback_server = server_address.is_none_or(|address| {
        address
            .split_once('/')
            .map_or(address.as_str(), |(address, _)| address)
            .parse::<std::net::IpAddr>()
            .unwrap()
            .is_loopback()
    });

    for (label, unsafe_development) in [
        ("development reservation", true),
        ("production attestation", false),
    ] {
        assert!(
            control_backends(&pool, label).await.is_empty(),
            "{label}: fixture starts without a control backend"
        );
        // All other settings use Config's defaults. These opt-ins avoid secret
        // files, and loopback binds make the reserved localhost domain valid.
        let mut variables = vec![
            ("DATABASE_URL", database_url.as_str()),
            (
                "DATABASE_ALLOW_UNSAFE_ROLE_FOR_DEVELOPMENT",
                if unsafe_development { "true" } else { "false" },
            ),
            ("XMPP_BIND", "127.0.0.1:5222"),
            ("XMPPS_BIND", "127.0.0.1:5223"),
            ("S2S_BIND", "127.0.0.1:5269"),
            ("S2S_TLS_BIND", "127.0.0.1:5270"),
            ("FAST_TOKEN_ALLOW_EPHEMERAL_FOR_DEVELOPMENT", "true"),
            ("DUMMY_SCRAM_ALLOW_EPHEMERAL_FOR_DEVELOPMENT", "true"),
            ("ABUSE_STATE_ALLOW_EPHEMERAL", "true"),
            ("UPLOAD_MODE", "disabled"),
        ];
        if !unsafe_development {
            // Config validates this URL's presence; reservation opens only
            // DATABASE_URL and must attest the suite's actual control login.
            variables.push(("ADMIN_COMMAND_DATABASE_URL", database_url.as_str()));
        }
        let config = Config::from_variables(&variables)
            .unwrap_or_else(|error| panic!("{label}: configuration failed: {error:#}"));
        let result = tokio::time::timeout(
            Duration::from_secs(5),
            reserve_runtime_control_connection(&config),
        )
        .await
        .unwrap_or_else(|_| {
            panic!("{label}: reservation must finish well inside startup admission")
        });

        if unsafe_development && !loopback_server {
            let Err(error) = result else {
                panic!("{label}: a non-loopback server must refuse the development override");
            };
            assert_eq!(
                format!("{error:#}"),
                "the unsafe development database-role override is restricted to loopback PostgreSQL",
                "{label}"
            );
        } else if unsafe_development {
            let mut connection =
                result.unwrap_or_else(|error| panic!("{label}: reservation failed: {error:#}"));
            let (pid, schema): (i32, String) =
                sqlx::query_as("SELECT pg_backend_pid(),current_schema()")
                    .fetch_one(&mut *connection)
                    .await
                    .unwrap_or_else(|error| {
                        panic!("{label}: inspect reserved connection: {error}")
                    });
            assert_eq!(schema, expected_schema, "{label}: preserve the URL schema");
            assert_eq!(
                control_backends(&pool, label).await,
                vec![pid],
                "{label}: one reserved backend and no spare control connections"
            );
            drop(connection);
        } else {
            let Err(error) = result else {
                panic!("{label}: the suite control login must fail runtime role attestation");
            };
            let text = format!("{error:#}");
            // The first failing attestation depends on the database's public
            // migration/catalog state. All prefixes originate after connect.
            let attestation_errors = [
                "could not attest the repository migration ledger",
                "PostgreSQL migration ledger drifted:",
                "could not attest the shared PostgreSQL role/object capability catalog",
                "shared PostgreSQL capability catalog drifted:",
                "could not attest the PostgreSQL SECURITY DEFINER capability ACL manifest",
                "PostgreSQL SECURITY DEFINER capability ACL manifest drifted:",
                "could not attest the PostgreSQL runtime relation capability manifest",
                "PostgreSQL runtime relation capability manifest drifted:",
                "could not inspect runtime PostgreSQL role",
                "PostgreSQL runtime role attestation failed:",
            ];
            assert!(
                attestation_errors
                    .iter()
                    .any(|prefix| text.starts_with(*prefix)),
                "{label}: expected an attestation error, got {text}"
            );
        }
        wait_for_control_backends_to_close(&pool, label).await;
    }
    pool.close().await;
}
