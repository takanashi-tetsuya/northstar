use super::*;
use crate::db;
use roxmltree::Document;
use sqlx::Acquire;

#[test]
fn uses_the_registered_xep_0133_nodes() {
    assert!(is_command(ONLINE_COUNT));
    assert!(is_command(ONLINE_LIST));
    assert!(is_command(REGISTERED_COUNT));
    assert!(is_command(REGISTERED_LIST));
    assert!(is_command(ADD_USER));
    assert!(is_command(EDIT_ADMIN));
    assert!(!is_command(
        "http://jabber.org/protocol/admin#get-user-password"
    ));
    assert!(!is_command(
        "http://jabber.org/protocol/admin#get-online-users"
    ));
}

#[test]
fn command_bearers_are_opaque_fixed_size_values() {
    assert!(valid_command_bearer(&"A1".repeat(32)));
    assert!(!valid_command_bearer(&"A1".repeat(31)));
    assert!(!valid_command_bearer(&format!("{}-", "A".repeat(63))));
}

#[test]
fn command_target_digest_is_field_order_independent_but_value_order_sensitive() {
    let first = Submission {
        fields: HashMap::from([
            (
                "accountjids".to_owned(),
                vec!["a@example.test".to_owned(), "b@example.test".to_owned()],
            ),
            ("confirm".to_owned(), vec!["1".to_owned()]),
        ]),
    };
    let reordered_fields = Submission {
        fields: HashMap::from([
            ("confirm".to_owned(), vec!["1".to_owned()]),
            (
                "accountjids".to_owned(),
                vec!["a@example.test".to_owned(), "b@example.test".to_owned()],
            ),
        ]),
    };
    let reordered_values = Submission {
        fields: HashMap::from([
            ("confirm".to_owned(), vec!["1".to_owned()]),
            (
                "accountjids".to_owned(),
                vec!["b@example.test".to_owned(), "a@example.test".to_owned()],
            ),
        ]),
    };
    assert_eq!(
        command_target_digest(DELETE_USER, &first),
        command_target_digest(DELETE_USER, &reordered_fields)
    );
    assert_ne!(
        command_target_digest(DELETE_USER, &first),
        command_target_digest(DELETE_USER, &reordered_values)
    );
    assert_ne!(
        command_target_digest(DELETE_USER, &first),
        command_target_digest(DISABLE_USER, &first)
    );
}

#[test]
fn parses_a_bounded_list_submission_and_rejects_duplicate_fields() {
    let good_xml = format!(
        "<command xmlns='{COMMANDS_NS}'><x xmlns='{DATA_NS}' type='submit'><field var='FORM_TYPE'><value>{ADMIN_FORM_TYPE}</value></field><field var='max_items'><value>150</value></field><field var='start'><value>25</value></field></x></command>"
    );
    let good = Document::parse(&good_xml).unwrap();
    let parsed = parse_submission(good.root_element(), REGISTERED_LIST).unwrap();
    assert_eq!(parsed.one("max_items"), Ok("150"));
    assert_eq!(parsed.one("start"), Ok("25"));

    let duplicate_xml = format!(
        "<command xmlns='{COMMANDS_NS}'><x xmlns='{DATA_NS}' type='submit'><field var='FORM_TYPE'><value>{ADMIN_FORM_TYPE}</value></field><field var='max_items'><value>25</value></field><field var='max_items'><value>50</value></field><field var='start'><value>0</value></field></x></command>"
    );
    let duplicate = Document::parse(&duplicate_xml).unwrap();
    assert_eq!(
        parse_submission(duplicate.root_element(), REGISTERED_LIST),
        Err(())
    );
}

#[test]
fn rejects_wrong_form_namespaces_unknown_fields_and_oversized_lists() {
    for xml in [
        format!(
            "<command xmlns='{COMMANDS_NS}'><x xmlns='urn:wrong' type='submit'/></command>"
        ),
        format!(
            "<command xmlns='{COMMANDS_NS}'><x xmlns='{DATA_NS}' type='submit'><field var='FORM_TYPE'><value>{ADMIN_FORM_TYPE}</value></field><field var='unknown'><value>1</value></field><field var='max_items'><value>25</value></field><field var='start'><value>0</value></field></x></command>"
        ),
        format!(
            "<command xmlns='{COMMANDS_NS}'><x xmlns='{DATA_NS}' type='submit'><field var='FORM_TYPE'><value>{ADMIN_FORM_TYPE}</value></field><field var='max_items'><value>201</value></field><field var='start'><value>0</value></field></x></command>"
        ),
    ] {
        let document = Document::parse(&xml).unwrap();
        let parsed = parse_submission(document.root_element(), REGISTERED_LIST);
        if let Ok(parsed) = parsed {
            assert!(
                parsed
                    .one("max_items")
                    .ok()
                    .and_then(|value| value.parse::<usize>().ok())
                    .is_none_or(|value| !(1..=MAX_LIST_ITEMS).contains(&value))
            );
        }
    }
}

#[test]
fn command_errors_use_xep_0050_error_types_and_escape_input() {
    let error = command_error(
        "id'1",
        "example.test",
        "node&x",
        "bad-request",
        "modify",
        Some("bad-sessionid"),
    );
    assert!(error.contains("type='modify'"));
    assert!(error.contains("<bad-sessionid xmlns='http://jabber.org/protocol/commands'/"));
    assert!(error.contains("id='id&apos;1'"));
    assert!(error.contains("node='node&amp;x'"));
    Document::parse(&error).unwrap();
}

#[test]
fn command_output_builder_contains_hostile_runtime_values() {
    let hostile = "x'&<injected xmlns='urn:evil'/>\r\n🙂";
    let result = command_result(hostile, hostile, hostile, hostile, hostile, "");
    let document = Document::parse(&result).unwrap();
    let iq = document.root_element();
    let command = iq.children().find(|child| child.is_element()).unwrap();
    assert_eq!(iq.attribute("id"), Some(hostile));
    assert_eq!(iq.attribute("from"), Some(hostile));
    assert_eq!(command.attribute("node"), Some(hostile));
    assert_eq!(command.attribute("sessionid"), Some(hostile));
    assert_eq!(command.attribute("status"), Some(hostile));
    assert_eq!(
        document
            .descendants()
            .filter(|node| node.is_element() && node.tag_name().name() == "injected")
            .count(),
        0
    );

    let field = field(
        "runtime",
        "text-single",
        hostile,
        true,
        &[hostile.to_owned()],
    );
    let field_xml = field.finish();
    let document = Document::parse(&field_xml).unwrap();
    let field = document.root_element();
    assert_eq!(field.attribute("label"), Some(hostile));
    assert_eq!(
        field
            .children()
            .find(|node| node.is_element() && node.tag_name().name() == "value")
            .and_then(|node| node.text()),
        Some(hostile)
    );
}

#[test]
fn malformed_cached_command_payload_fails_closed_without_panicking() {
    let result = command_result(
        "request-id",
        "example.test",
        REGISTERED_LIST,
        "session-id",
        "completed",
        "<x><broken></x>",
    );
    let document = Document::parse(&result).unwrap();
    let iq = document.root_element();
    assert_eq!(iq.attribute("type"), Some("error"));
    assert!(document.descendants().any(|node| {
        node.is_element()
            && node.tag_name().name() == "internal-server-error"
            && node.tag_name().namespace() == Some("urn:ietf:params:xml:ns:xmpp-stanzas")
    }));
}

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
    let command = db::create_admin_command_session(
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
        crate::db::finish_admin_command_session(
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
        crate::db::finish_admin_command_session(
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
            .filter(|state| **state == crate::db::AdminCommandSessionState::Finished)
            .count(),
        1
    );
    assert_eq!(
        outcomes
            .iter()
            .filter(|state| **state == crate::db::AdminCommandSessionState::Invalid)
            .count(),
        1
    );

    let demoted = db::create_admin_command_session(
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
        crate::db::finish_admin_command_session(
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
        crate::db::AdminCommandSessionState::Invalid
    );
    sqlx::query("UPDATE users SET is_admin=TRUE WHERE id=$1")
        .bind(admin)
        .execute(&pool)
        .await
        .unwrap();

    let expired = db::create_admin_command_session(
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
        crate::db::finish_admin_command_session(
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
        crate::db::AdminCommandSessionState::Expired
    );

    let execution = db::create_admin_command_session(
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
        crate::db::begin_admin_command_execution(
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
        crate::db::begin_admin_command_execution(
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
            crate::db::AdminCommandExecutionState::Started(started) => claim = Some(started),
            crate::db::AdminCommandExecutionState::Busy => busy += 1,
            other => panic!("unexpected concurrent execution state: {other:?}"),
        }
    }
    let claim = claim.expect("one concurrent claimant must win");
    assert_eq!(busy, 1);
    // A semantic validation failure releases only its own incarnation and
    // leaves the XEP-0050 session reusable.
    assert!(crate::db::release_admin_command_execution(
        &pool,
        claim.token.as_str(),
        admin,
        username,
        0,
        REGISTERED_LIST,
        &digest,
    )
    .await
    .unwrap());
    let claim = match crate::db::begin_admin_command_execution(
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
        crate::db::AdminCommandExecutionState::Started(claim) => claim,
        other => panic!("unexpected execution state: {other:?}"),
    };
    let payload = "<x xmlns='jabber:x:data' type='result'/>";
    assert!(crate::db::complete_admin_command_read_execution(
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
    .unwrap());
    assert_eq!(
        crate::db::begin_admin_command_execution(
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
        crate::db::AdminCommandExecutionState::Completed(payload.to_owned())
    );
    let different_digest = Sha256::digest(b"different-request").to_vec();
    assert_eq!(
        crate::db::begin_admin_command_execution(
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
        crate::db::AdminCommandExecutionState::Invalid
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
    db::replace_admins(&pool, admin, &[admin, member])
        .await
        .unwrap();
    assert!(
        db::find_user_by_id(&pool, member)
            .await
            .unwrap()
            .unwrap()
            .is_admin
    );

    db::set_admin_service_message(&pool, admin, 0, "welcome", Some("Welcome"))
        .await
        .unwrap();
    db::set_admin_service_message(&pool, admin, 0, "motd", Some("Daily"))
        .await
        .unwrap();
    let first_pool = pool.clone();
    let second_pool = pool.clone();
    let first = tokio::spawn(async move {
        db::claim_admin_service_messages(&first_pool, member)
            .await
            .unwrap()
    });
    let second = tokio::spawn(async move {
        db::claim_admin_service_messages(&second_pool, member)
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
    assert!(db::claim_admin_service_messages(&pool, member)
        .await
        .unwrap()
        .is_empty());
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
    let reclaimed = db::claim_admin_service_messages(&pool, member)
        .await
        .unwrap();
    assert_eq!(reclaimed.len(), 1);
    assert_eq!(reclaimed[0].kind, "motd");
    assert!(
        db::complete_admin_service_message_claim(&pool, member, &reclaimed[0])
            .await
            .unwrap()
    );
    let welcome_claim = claims.iter().find(|claim| claim.kind == "welcome").unwrap();
    assert!(
        db::complete_admin_service_message_claim(&pool, member, welcome_claim)
            .await
            .unwrap()
    );
    db::set_admin_service_message(&pool, admin, 0, "welcome", None)
        .await
        .unwrap();
    db::set_admin_service_message(&pool, admin, 0, "welcome", Some("New welcome"))
        .await
        .unwrap();
    assert!(db::claim_admin_service_messages(&pool, member)
        .await
        .unwrap()
        .is_empty());
    db::set_admin_service_message(&pool, admin, 0, "motd", Some("Corrected"))
        .await
        .unwrap();
    let corrected = db::claim_admin_service_messages(&pool, member)
        .await
        .unwrap()
        .into_iter()
        .map(|claim| (claim.kind, claim.body))
        .collect::<Vec<_>>();
    assert_eq!(corrected, vec![("motd".to_owned(), "Corrected".to_owned())]);

    db::initialize_admin_runtime_settings(&pool, false, false, false)
        .await
        .unwrap();
    assert_eq!(
        db::admin_runtime_settings(&pool).await.unwrap(),
        (false, false)
    );
    let mut control_connection = pool.acquire().await.unwrap();
    assert_eq!(
        db::runtime_control_snapshot(&mut control_connection, |_| {})
            .await
            .unwrap(),
        (false, false, Vec::<String>::new(), Vec::<String>::new())
    );
    drop(control_connection);
    assert!(
        db::set_admin_runtime_setting(&pool, admin, 0, "registration_closed", true,)
            .await
            .unwrap()
    );
    let observer_pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(2)
        .connect(&url)
        .await
        .unwrap();
    assert_eq!(
        db::admin_runtime_settings(&observer_pool).await.unwrap(),
        (false, true)
    );

    let mut entities = vec![
        "blocked.example".to_owned(),
        "alice@remote.example".to_owned(),
        "bob@remote.example/Phone".to_owned(),
    ];
    entities.sort();
    assert!(
        db::replace_federation_runtime_rules(&pool, admin, 0, "blacklist", &entities,)
            .await
            .unwrap()
    );
    assert_eq!(
        db::federation_runtime_rules(&observer_pool)
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
        db::runtime_control_snapshot(&mut control_connection, |_| {})
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
        db::runtime_control_snapshot(&mut control_tx, |_| {})
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
    assert!(db::runtime_control_snapshot(&mut control_tx, |_| {})
        .await
        .unwrap_err()
        .to_string()
        .contains("registration_closed runtime setting is missing"));
    control_tx.rollback().await.unwrap();
    drop(control_connection);

    let scheduled =
        db::schedule_admin_service_control(&pool, admin, 0, "restart", 5, Some("Maintenance"))
            .await
            .unwrap()
            .unwrap();
    assert!(
        db::schedule_admin_service_control(&observer_pool, admin, 0, "shutdown", 5, None,)
            .await
            .unwrap()
            .is_none()
    );
    assert_eq!(
        db::cancel_admin_service_control(&observer_pool, admin, 0)
            .await
            .unwrap(),
        Some(scheduled.generation)
    );
    let scheduled =
        db::schedule_admin_service_control(&observer_pool, admin, 0, "shutdown", 5, None)
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
    let fired = db::poll_admin_service_control(&mut control_connection)
        .await
        .unwrap()
        .unwrap();
    let observed = db::poll_admin_service_control(&mut observer_control_connection)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(fired.generation, scheduled.generation);
    assert_eq!(observed.generation, scheduled.generation);
    assert_eq!(fired.fired_at, observed.fired_at);
    assert!(
        db::schedule_admin_service_control(&pool, admin, 0, "restart", 5, None,)
            .await
            .unwrap()
            .is_none()
    );
    assert!(db::cancel_admin_service_control(&pool, admin, 0)
        .await
        .unwrap()
        .is_none());

    let before = db::find_user_by_id(&pool, member)
        .await
        .unwrap()
        .unwrap()
        .auth_generation;
    assert!(db::end_user_sessions(&pool, admin, member).await.unwrap());
    assert_eq!(
        db::find_user_by_id(&pool, member)
            .await
            .unwrap()
            .unwrap()
            .auth_generation,
        before + 1
    );
}
