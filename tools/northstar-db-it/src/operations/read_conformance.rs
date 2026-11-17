use northstar_operations_application::admin_commands::{
    AdminActor, AdminCommandRepository, AdminExecutionClaim,
};
use northstar_workflows::{
    admin_command_repository::WorkflowAdminCommandRepository, roster::WorkflowRosterEffects,
};
use uuid::Uuid;

async fn read(
    repository: &WorkflowAdminCommandRepository,
    actor: &AdminActor,
    label: &str,
) -> bool {
    match label {
        "registered count" => repository
            .registered_account_count(actor)
            .await
            .unwrap()
            .is_some(),
        "disabled count" => repository
            .disabled_account_count(actor)
            .await
            .unwrap()
            .is_some(),
        "registered names" => repository
            .registered_account_usernames(actor, 10, 0)
            .await
            .unwrap()
            .is_some(),
        "disabled names" => repository
            .disabled_account_usernames(actor, 10, 0)
            .await
            .unwrap()
            .is_some(),
        "announcement page" => repository
            .announcement_account_page(actor, None)
            .await
            .unwrap()
            .is_some(),
        "administrator names" => repository
            .administrator_usernames(actor)
            .await
            .unwrap()
            .is_some(),
        "last login" => repository
            .account_last_login(actor, &actor.username)
            .await
            .unwrap()
            .is_some(),
        "account roster" => repository
            .account_roster(actor, &actor.username)
            .await
            .unwrap()
            .is_some(),
        "account statistics" => repository
            .account_statistics(actor, &actor.username)
            .await
            .unwrap()
            .is_some(),
        "service message" => repository
            .service_message_body(actor, "motd")
            .await
            .unwrap()
            .is_some(),
        "federation rules" => repository
            .federation_rule_domains(actor, "blacklist")
            .await
            .unwrap()
            .is_some(),
        _ => panic!("unknown sensitive read: {label}"),
    }
}

#[tokio::test]
#[ignore = "requires the ordinary-role random schema and TEST_DATABASE_URL"]
async fn sensitive_reads_recheck_changed_actors_and_hold_authority_through_the_projection() {
    let pool = crate::support::operation_mutation_pool().await;
    let user = Uuid::from_u128(0x573_3901);
    sqlx::query("INSERT INTO users(id,username,password_hash,is_admin) VALUES($1,'admin-read-conformance','test-only',TRUE)")
        .bind(user).execute(&pool).await.unwrap();
    sqlx::query("INSERT INTO admin_service_messages(kind,body,revision) VALUES('motd','original service message',$1) ON CONFLICT(kind) DO UPDATE SET body=EXCLUDED.body,revision=EXCLUDED.revision")
        .bind(Uuid::from_u128(0x573_3902)).execute(&pool).await.unwrap();
    let actor = AdminActor::new(user, "admin-read-conformance".into(), 0);
    let repository =
        WorkflowAdminCommandRepository::new(pool.clone(), pool.clone(), WorkflowRosterEffects);
    for label in [
        "registered count",
        "disabled count",
        "registered names",
        "disabled names",
        "announcement page",
        "administrator names",
        "last login",
        "account roster",
        "account statistics",
        "service message",
        "federation rules",
    ] {
        for (change, mutation) in [
            ("demotion", "UPDATE users SET is_admin=FALSE WHERE id=$1"),
            (
                "disablement",
                "UPDATE users SET is_disabled=TRUE WHERE id=$1",
            ),
            (
                "generation rotation",
                "UPDATE users SET auth_generation=1 WHERE id=$1",
            ),
        ] {
            sqlx::query(
                "UPDATE users SET is_admin=TRUE,is_disabled=FALSE,auth_generation=0 WHERE id=$1",
            )
            .bind(user)
            .execute(&pool)
            .await
            .unwrap();
            assert!(
                read(&repository, &actor, label).await,
                "{label}: positive control"
            );
            let mut blocker = pool.begin().await.unwrap();
            sqlx::query("SELECT id FROM users WHERE id=$1 FOR UPDATE")
                .bind(user)
                .fetch_one(&mut *blocker)
                .await
                .unwrap();
            let blocker_pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
                .fetch_one(&mut *blocker)
                .await
                .unwrap();
            let reader = repository.clone();
            let reader_actor = actor.clone();
            let task = tokio::spawn(async move { read(&reader, &reader_actor, label).await });
            crate::support::blocked_backend(&pool, blocker_pid).await;
            sqlx::query(mutation)
                .bind(user)
                .execute(&mut *blocker)
                .await
                .unwrap();
            blocker.commit().await.unwrap();
            assert!(
                !task.await.unwrap(),
                "{label}: {change} that wins authorization cannot return protected data"
            );
        }
    }
    sqlx::query("UPDATE users SET is_admin=TRUE,is_disabled=FALSE,auth_generation=0 WHERE id=$1")
        .bind(user)
        .execute(&pool)
        .await
        .unwrap();
    for (label, table) in [
        ("account roster", "roster_items"),
        ("account statistics", "message_archive"),
        ("service message", "admin_service_messages"),
        ("federation rules", "federation_runtime_rules"),
    ] {
        let mut blocker = pool.begin().await.unwrap();
        sqlx::query(sqlx::AssertSqlSafe(format!(
            "LOCK TABLE {table} IN ACCESS EXCLUSIVE MODE"
        )))
        .execute(&mut *blocker)
        .await
        .unwrap();
        let blocker_pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
            .fetch_one(&mut *blocker)
            .await
            .unwrap();
        let reader = repository.clone();
        let reader_actor = actor.clone();
        let task = tokio::spawn(async move { read(&reader, &reader_actor, label).await });
        crate::support::blocked_backend(&pool, blocker_pid).await;
        let mut mutation = pool.begin().await.unwrap();
        let Err(error) = sqlx::query("SELECT id FROM users WHERE id=$1 FOR UPDATE NOWAIT")
            .bind(user)
            .fetch_one(&mut *mutation)
            .await
        else {
            panic!("{label}: authorization lock was released before the protected projection");
        };
        assert_eq!(
            error
                .as_database_error()
                .and_then(|error| error.code())
                .as_deref(),
            Some("55P03"),
            "{label}"
        );
        mutation.rollback().await.unwrap();
        blocker.rollback().await.unwrap();
        assert!(
            task.await.unwrap(),
            "{label}: authorized projection completes"
        );
    }
    sqlx::query("DELETE FROM users WHERE id=$1")
        .bind(user)
        .execute(&pool)
        .await
        .unwrap();
    pool.close().await;
}

#[tokio::test]
#[ignore = "requires the ordinary-role random schema and TEST_DATABASE_URL"]
async fn federation_replacement_returns_the_cache_image_committed_with_the_exact_command() {
    use northstar_operations_postgres::admin_commands as db;
    let pool = crate::support::operation_mutation_pool().await;
    let user = Uuid::from_u128(0x573_3911);
    sqlx::query("INSERT INTO users(id,username,password_hash,is_admin) VALUES($1,'admin-rules-conformance','test-only',TRUE)")
        .bind(user).execute(&pool).await.unwrap();
    let actor = AdminActor::new(user, "admin-rules-conformance".into(), 0);
    let node = "http://jabber.org/protocol/admin#edit-blacklist";
    let full = "admin-rules-conformance@example.test/console";
    let bearer =
        db::create_admin_command_session(&pool, user, full, "example.test", 0, node, "form")
            .await
            .unwrap()
            .unwrap();
    let digest = [17_u8; 32];
    let db::AdminCommandExecutionState::Started(claim) =
        db::begin_admin_command_execution(&pool, bearer.as_str(), user, full, 0, node, &digest)
            .await
            .unwrap()
    else {
        panic!("command claim was not created");
    };
    let claim = AdminExecutionClaim::new(
        claim.operation_id,
        claim.token,
        &actor,
        node.to_owned(),
        digest,
    );
    let repository =
        WorkflowAdminCommandRepository::new(pool.clone(), pool.clone(), WorkflowRosterEffects);
    let entities = vec![
        "a.conformance.test".to_owned(),
        "z.conformance.test".to_owned(),
    ];
    let returned = repository
        .replace_federation_rules(
            &actor,
            &claim,
            node,
            "blacklist",
            &entities,
            "<iq type='result'/>",
        )
        .await
        .unwrap()
        .unwrap();
    let mut observer = pool.acquire().await.unwrap();
    let blacklist: Vec<String> = sqlx::query_scalar(
        "SELECT domain FROM federation_runtime_rules WHERE kind='blacklist' ORDER BY domain",
    )
    .fetch_all(&mut *observer)
    .await
    .unwrap();
    let whitelist: Vec<String> = sqlx::query_scalar(
        "SELECT domain FROM federation_runtime_rules WHERE kind='whitelist' ORDER BY domain",
    )
    .fetch_all(&mut *observer)
    .await
    .unwrap();
    assert_eq!(returned.blacklist, entities);
    assert_eq!(returned.blacklist, blacklist);
    assert_eq!(returned.whitelist, whitelist);
    drop(observer);
    sqlx::query("DELETE FROM users WHERE id=$1")
        .bind(user)
        .execute(&pool)
        .await
        .unwrap();
    pool.close().await;
}
