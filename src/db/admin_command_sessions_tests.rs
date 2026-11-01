use sha2::{Digest, Sha256};
use sqlx::Acquire;

const ONLINE_LIST: &str = "http://jabber.org/protocol/admin#get-online-users-list";
const REGISTERED_LIST: &str = "http://jabber.org/protocol/admin#get-registered-users-list";

#[tokio::test]
#[ignore = "requires an isolated TEST_DATABASE_URL PostgreSQL database"]
async fn postgres_command_sessions_are_cross_node_atomic() {
    let url = std::env::var("TEST_DATABASE_URL")
        .expect("set TEST_DATABASE_URL to an isolated PostgreSQL database");
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(8)
        .connect(&url)
        .await
        .unwrap();
    crate::db::migrate(&pool).await.unwrap();
    let admin = uuid::Uuid::new_v4();
    let username = "cmd";
    sqlx::query(
        "INSERT INTO users(id,username,password_hash,is_admin)
             VALUES($1,$2,'test-only',TRUE)",
    )
    .bind(admin)
    .bind(username)
    .execute(&pool)
    .await
    .unwrap();
    let owner = "cmd@example.test/Console";
    let command = northstar_operations_postgres::admin_commands::create_admin_command_session(
        &pool,
        admin,
        owner,
        "example.test",
        0,
        REGISTERED_LIST,
        "form",
    )
    .await
    .unwrap()
    .unwrap();

    let first_pool = pool.clone();
    let second_pool = pool.clone();
    let first_bearer = command.to_string();
    let second_bearer = command.to_string();
    let first = tokio::spawn(async move {
        northstar_operations_postgres::admin_commands::finish_admin_command_session(
            &first_pool,
            &first_bearer,
            admin,
            owner,
            0,
            REGISTERED_LIST,
            "canceled",
        )
        .await
        .unwrap()
    });
    let second = tokio::spawn(async move {
        northstar_operations_postgres::admin_commands::finish_admin_command_session(
            &second_pool,
            &second_bearer,
            admin,
            owner,
            0,
            REGISTERED_LIST,
            "canceled",
        )
        .await
        .unwrap()
    });
    let outcomes = [first.await.unwrap(), second.await.unwrap()];
    assert_eq!(
        outcomes
            .iter()
            .filter(|state| **state == northstar_operations_postgres::admin_commands::AdminCommandSessionState::Finished)
            .count(),
        1
    );
    assert_eq!(
        outcomes
            .iter()
            .filter(|state| **state
                == northstar_operations_postgres::admin_commands::AdminCommandSessionState::Invalid)
            .count(),
        1
    );

    let demoted = northstar_operations_postgres::admin_commands::create_admin_command_session(
        &pool,
        admin,
        owner,
        "example.test",
        0,
        ONLINE_LIST,
        "form",
    )
    .await
    .unwrap()
    .unwrap();
    sqlx::query("UPDATE users SET is_admin=FALSE WHERE id=$1")
        .bind(admin)
        .execute(&pool)
        .await
        .unwrap();
    assert_eq!(
        northstar_operations_postgres::admin_commands::finish_admin_command_session(
            &pool,
            demoted.as_str(),
            admin,
            owner,
            0,
            ONLINE_LIST,
            "canceled",
        )
        .await
        .unwrap(),
        northstar_operations_postgres::admin_commands::AdminCommandSessionState::Invalid
    );
    sqlx::query("UPDATE users SET is_admin=TRUE WHERE id=$1")
        .bind(admin)
        .execute(&pool)
        .await
        .unwrap();

    let expired = northstar_operations_postgres::admin_commands::create_admin_command_session(
        &pool,
        admin,
        owner,
        "example.test",
        0,
        ONLINE_LIST,
        "form",
    )
    .await
    .unwrap()
    .unwrap();
    sqlx::query(
        "UPDATE admin_command_sessions
                SET expires_at=NOW()-INTERVAL '1 second'
              WHERE owner_id=$1 AND node=$2 AND completed_at IS NULL",
    )
    .bind(admin)
    .bind(ONLINE_LIST)
    .execute(&pool)
    .await
    .unwrap();
    assert_eq!(
        northstar_operations_postgres::admin_commands::finish_admin_command_session(
            &pool,
            expired.as_str(),
            admin,
            owner,
            0,
            ONLINE_LIST,
            "canceled",
        )
        .await
        .unwrap(),
        northstar_operations_postgres::admin_commands::AdminCommandSessionState::Expired
    );

    let execution = northstar_operations_postgres::admin_commands::create_admin_command_session(
        &pool,
        admin,
        owner,
        "example.test",
        0,
        REGISTERED_LIST,
        "form",
    )
    .await
    .unwrap()
    .unwrap();
    let digest = Sha256::digest(b"validated-request").to_vec();
    let first_pool = pool.clone();
    let second_pool = pool.clone();
    let first_bearer = execution.to_string();
    let second_bearer = execution.to_string();
    let first_digest = digest.clone();
    let second_digest = digest.clone();
    let first = tokio::spawn(async move {
        northstar_operations_postgres::admin_commands::begin_admin_command_execution(
            &first_pool,
            &first_bearer,
            admin,
            owner,
            0,
            REGISTERED_LIST,
            &first_digest,
        )
        .await
        .unwrap()
    });
    let second = tokio::spawn(async move {
        northstar_operations_postgres::admin_commands::begin_admin_command_execution(
            &second_pool,
            &second_bearer,
            admin,
            owner,
            0,
            REGISTERED_LIST,
            &second_digest,
        )
        .await
        .unwrap()
    });
    let outcomes = [first.await.unwrap(), second.await.unwrap()];
    let mut claim = None;
    let mut busy = 0;
    for outcome in outcomes {
        match outcome {
            northstar_operations_postgres::admin_commands::AdminCommandExecutionState::Started(
                started,
            ) => claim = Some(started),
            northstar_operations_postgres::admin_commands::AdminCommandExecutionState::Busy => {
                busy += 1
            }
            other => panic!("unexpected concurrent execution state: {other:?}"),
        }
    }
    let claim = claim.expect("one concurrent claimant must win");
    assert_eq!(busy, 1);
    // A semantic validation failure releases only its own incarnation and
    // leaves the XEP-0050 session reusable.
    assert!(
        northstar_operations_postgres::admin_commands::release_admin_command_execution(
            &pool,
            claim.token.as_str(),
            admin,
            username,
            0,
            REGISTERED_LIST,
            &digest,
        )
        .await
        .unwrap()
    );
    let claim = match northstar_operations_postgres::admin_commands::begin_admin_command_execution(
        &pool,
        execution.as_str(),
        admin,
        owner,
        0,
        REGISTERED_LIST,
        &digest,
    )
    .await
    .unwrap()
    {
        northstar_operations_postgres::admin_commands::AdminCommandExecutionState::Started(
            claim,
        ) => claim,
        other => panic!("unexpected execution state: {other:?}"),
    };
    let payload = "<x xmlns='jabber:x:data' type='result'/>";
    assert!(
        northstar_operations_postgres::admin_commands::complete_admin_command_read_execution(
            &pool,
            claim.token.as_str(),
            admin,
            username,
            0,
            REGISTERED_LIST,
            &digest,
            payload,
        )
        .await
        .unwrap()
    );
    assert_eq!(
        northstar_operations_postgres::admin_commands::begin_admin_command_execution(
            &pool,
            execution.as_str(),
            admin,
            owner,
            0,
            REGISTERED_LIST,
            &digest,
        )
        .await
        .unwrap(),
        northstar_operations_postgres::admin_commands::AdminCommandExecutionState::Completed(
            payload.to_owned()
        )
    );
    let different_digest = Sha256::digest(b"different-request").to_vec();
    assert_eq!(
        northstar_operations_postgres::admin_commands::begin_admin_command_execution(
            &pool,
            execution.as_str(),
            admin,
            owner,
            0,
            REGISTERED_LIST,
            &different_digest,
        )
        .await
        .unwrap(),
        northstar_operations_postgres::admin_commands::AdminCommandExecutionState::Invalid
    );

    let member = uuid::Uuid::new_v4();
    sqlx::query(
        "INSERT INTO users(id,username,password_hash,is_admin)
             VALUES($1,$2,'test-only',FALSE)",
    )
    .bind(member)
    .bind(format!("member-{}", &member.simple().to_string()[..12]))
    .execute(&pool)
    .await
    .unwrap();
    northstar_workflows::account_lifecycle::replace_admins(&pool, admin, &[admin, member])
        .await
        .unwrap();
    assert!(
        northstar_auth_postgres::users::find_user_by_id(&pool, member)
            .await
            .unwrap()
            .unwrap()
            .is_admin
    );

    northstar_operations_postgres::admin_commands::set_admin_service_message(
        &pool,
        admin,
        0,
        "welcome",
        Some("Welcome"),
    )
    .await
    .unwrap();
    northstar_operations_postgres::admin_commands::set_admin_service_message(
        &pool,
        admin,
        0,
        "motd",
        Some("Daily"),
    )
    .await
    .unwrap();
    let first_pool = pool.clone();
    let second_pool = pool.clone();
    let first = tokio::spawn(async move {
        northstar_operations_postgres::admin_commands::claim_admin_service_messages(
            &first_pool,
            member,
        )
        .await
        .unwrap()
    });
    let second = tokio::spawn(async move {
        northstar_operations_postgres::admin_commands::claim_admin_service_messages(
            &second_pool,
            member,
        )
        .await
        .unwrap()
    });
    let mut claims = first.await.unwrap();
    claims.extend(second.await.unwrap());
    let mut claimed = claims
        .iter()
        .map(|claim| (claim.kind.clone(), claim.body.clone()))
        .collect::<Vec<_>>();
    claimed.sort();
    assert_eq!(
        claimed,
        vec![
            ("motd".to_owned(), "Daily".to_owned()),
            ("welcome".to_owned(), "Welcome".to_owned())
        ]
    );
    assert!(
        northstar_operations_postgres::admin_commands::claim_admin_service_messages(&pool, member)
            .await
            .unwrap()
            .is_empty()
    );
    let motd_claim = claims.iter().find(|claim| claim.kind == "motd").unwrap();
    sqlx::query(
        "UPDATE admin_service_message_deliveries
             SET claim_expires_at=clock_timestamp()-INTERVAL '1 second'
             WHERE claim_id=$1",
    )
    .bind(motd_claim.claim_id)
    .execute(&pool)
    .await
    .unwrap();
    let reclaimed =
        northstar_operations_postgres::admin_commands::claim_admin_service_messages(&pool, member)
            .await
            .unwrap();
    assert_eq!(reclaimed.len(), 1);
    assert_eq!(reclaimed[0].kind, "motd");
    assert!(
        northstar_operations_postgres::admin_commands::complete_admin_service_message_claim(
            &pool,
            member,
            &reclaimed[0]
        )
        .await
        .unwrap()
    );
    let welcome_claim = claims.iter().find(|claim| claim.kind == "welcome").unwrap();
    assert!(
        northstar_operations_postgres::admin_commands::complete_admin_service_message_claim(
            &pool,
            member,
            welcome_claim
        )
        .await
        .unwrap()
    );
    northstar_operations_postgres::admin_commands::set_admin_service_message(
        &pool, admin, 0, "welcome", None,
    )
    .await
    .unwrap();
    northstar_operations_postgres::admin_commands::set_admin_service_message(
        &pool,
        admin,
        0,
        "welcome",
        Some("New welcome"),
    )
    .await
    .unwrap();
    assert!(
        northstar_operations_postgres::admin_commands::claim_admin_service_messages(&pool, member)
            .await
            .unwrap()
            .is_empty()
    );
    northstar_operations_postgres::admin_commands::set_admin_service_message(
        &pool,
        admin,
        0,
        "motd",
        Some("Corrected"),
    )
    .await
    .unwrap();
    let corrected =
        northstar_operations_postgres::admin_commands::claim_admin_service_messages(&pool, member)
            .await
            .unwrap()
            .into_iter()
            .map(|claim| (claim.kind, claim.body))
            .collect::<Vec<_>>();
    assert_eq!(corrected, vec![("motd".to_owned(), "Corrected".to_owned())]);

    northstar_operations_postgres::admin_commands::initialize_admin_runtime_settings(
        &pool, false, false, false,
    )
    .await
    .unwrap();
    assert_eq!(
        northstar_operations_postgres::admin_commands::admin_runtime_settings(&pool)
            .await
            .unwrap(),
        (false, false)
    );
    let mut control_connection = pool.acquire().await.unwrap();
    assert_eq!(
        northstar_operations_postgres::admin_commands::runtime_control_snapshot(
            &mut control_connection,
            |_| {}
        )
        .await
        .unwrap(),
        (false, false, Vec::<String>::new(), Vec::<String>::new())
    );
    drop(control_connection);
    assert!(
        northstar_operations_postgres::admin_commands::set_admin_runtime_setting(
            &pool,
            admin,
            0,
            "registration_closed",
            true,
        )
        .await
        .unwrap()
    );
    let observer_pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(2)
        .connect(&url)
        .await
        .unwrap();
    assert_eq!(
        northstar_operations_postgres::admin_commands::admin_runtime_settings(&observer_pool)
            .await
            .unwrap(),
        (false, true)
    );

    let mut entities = vec![
        "blocked.example".to_owned(),
        "alice@remote.example".to_owned(),
        "bob@remote.example/Phone".to_owned(),
    ];
    entities.sort();
    assert!(
        northstar_operations_postgres::admin_commands::replace_federation_runtime_rules(
            &pool,
            admin,
            0,
            "blacklist",
            &entities,
        )
        .await
        .unwrap()
    );
    assert_eq!(
        northstar_operations_postgres::admin_commands::federation_runtime_rules(&observer_pool)
            .await
            .unwrap()
            .0,
        entities
    );

    // The reserved connection reads both projections, including empty
    // rule lists, without losing either flag or rule ordering. Corruption
    // of a required setting must still fail instead of reopening service.
    let mut control_connection = observer_pool.acquire().await.unwrap();
    assert_eq!(
        northstar_operations_postgres::admin_commands::runtime_control_snapshot(
            &mut control_connection,
            |_| {}
        )
        .await
        .unwrap(),
        (false, true, entities.clone(), Vec::<String>::new())
    );
    let mut control_tx = control_connection.begin().await.unwrap();
    sqlx::query(
        "INSERT INTO federation_runtime_rules(kind,domain)
             VALUES('whitelist','z.example'),('whitelist','a.example')",
    )
    .execute(&mut *control_tx)
    .await
    .unwrap();
    assert_eq!(
        northstar_operations_postgres::admin_commands::runtime_control_snapshot(
            &mut control_tx,
            |_| {}
        )
        .await
        .unwrap(),
        (
            false,
            true,
            entities,
            vec!["a.example".to_owned(), "z.example".to_owned()]
        )
    );
    sqlx::query("DELETE FROM admin_runtime_settings WHERE key='registration_closed'")
        .execute(&mut *control_tx)
        .await
        .unwrap();
    assert!(
        northstar_operations_postgres::admin_commands::runtime_control_snapshot(
            &mut control_tx,
            |_| {}
        )
        .await
        .unwrap_err()
        .to_string()
        .contains("registration_closed runtime setting is missing")
    );
    control_tx.rollback().await.unwrap();
    drop(control_connection);

    let scheduled = northstar_operations_postgres::admin_commands::schedule_admin_service_control(
        &pool,
        admin,
        0,
        "restart",
        5,
        Some("Maintenance"),
    )
    .await
    .unwrap()
    .unwrap();
    assert!(
        northstar_operations_postgres::admin_commands::schedule_admin_service_control(
            &observer_pool,
            admin,
            0,
            "shutdown",
            5,
            None,
        )
        .await
        .unwrap()
        .is_none()
    );
    assert_eq!(
        northstar_operations_postgres::admin_commands::cancel_admin_service_control(
            &observer_pool,
            admin,
            0
        )
        .await
        .unwrap(),
        Some(scheduled.generation)
    );
    let scheduled = northstar_operations_postgres::admin_commands::schedule_admin_service_control(
        &observer_pool,
        admin,
        0,
        "shutdown",
        5,
        None,
    )
    .await
    .unwrap()
    .unwrap();
    sqlx::query(
        "UPDATE admin_service_control SET execute_at=clock_timestamp()-INTERVAL '1 second'",
    )
    .execute(&pool)
    .await
    .unwrap();
    let mut control_connection = pool.acquire().await.unwrap();
    let mut observer_control_connection = observer_pool.acquire().await.unwrap();
    let fired = northstar_operations_postgres::admin_commands::poll_admin_service_control(
        &mut control_connection,
    )
    .await
    .unwrap()
    .unwrap();
    let observed = northstar_operations_postgres::admin_commands::poll_admin_service_control(
        &mut observer_control_connection,
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(fired.generation, scheduled.generation);
    assert_eq!(observed.generation, scheduled.generation);
    assert_eq!(fired.fired_at, observed.fired_at);
    assert!(
        northstar_operations_postgres::admin_commands::schedule_admin_service_control(
            &pool, admin, 0, "restart", 5, None,
        )
        .await
        .unwrap()
        .is_none()
    );
    assert!(
        northstar_operations_postgres::admin_commands::cancel_admin_service_control(
            &pool, admin, 0
        )
        .await
        .unwrap()
        .is_none()
    );

    let before = northstar_auth_postgres::users::find_user_by_id(&pool, member)
        .await
        .unwrap()
        .unwrap()
        .auth_generation;
    assert!(
        northstar_workflows::account_lifecycle::end_user_sessions(&pool, admin, member)
            .await
            .unwrap()
    );
    assert_eq!(
        northstar_auth_postgres::users::find_user_by_id(&pool, member)
            .await
            .unwrap()
            .unwrap()
            .auth_generation,
        before + 1
    );
}
