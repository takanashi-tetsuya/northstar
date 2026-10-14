use super::*;

async fn route_recovery_test_pool() -> (PgPool, PgPool, String) {
    let url = std::env::var("TEST_DATABASE_URL")
        .expect("set TEST_DATABASE_URL to an isolated PostgreSQL database");
    let admin = sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .connect(&url)
        .await
        .unwrap();
    let schema = format!("s2s_route_recovery_test_{}", Uuid::new_v4().simple());
    sqlx::query(&format!("CREATE SCHEMA {schema}"))
        .execute(&admin)
        .await
        .unwrap();
    eprintln!("isolated_schema_created={schema}");
    let connection_schema = schema.clone();
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(6)
        .after_connect(move |connection, _| {
            let statement = format!("SET search_path TO {connection_schema}");
            Box::pin(async move {
                sqlx::query(&statement).execute(connection).await?;
                Ok(())
            })
        })
        .connect(&url)
        .await
        .unwrap();
    crate::db::migrate(&pool).await.unwrap();
    (admin, pool, schema)
}

async fn close_route_recovery_test_pool(admin: PgPool, pool: PgPool, schema: String) {
    pool.close().await;
    sqlx::query(&format!("DROP SCHEMA {schema} CASCADE"))
        .execute(&admin)
        .await
        .unwrap();
    admin.close().await;
}

async fn recovery_row_except_due(pool: &PgPool, id: Uuid) -> String {
    sqlx::query_scalar(
        "SELECT (to_jsonb(outbox) - 'next_attempt_at')::TEXT
             FROM s2s_outbox AS outbox WHERE id = $1",
    )
    .bind(id)
    .fetch_one(pool)
    .await
    .unwrap()
}

#[tokio::test(flavor = "current_thread")]
#[ignore = "requires TEST_DATABASE_URL; uses and removes a random isolated schema"]
async fn sm_ack_accepts_terminal_pam_cleanup_without_losing_other_claim_fences() {
    let (admin, pool, schema) = route_recovery_test_pool().await;
    let user_id = Uuid::new_v4();
    let username = format!("pam-sm-{}", Uuid::new_v4().simple());
    sqlx::query("INSERT INTO users(id,username,password_hash) VALUES($1,$2,'test-only')")
        .bind(user_id)
        .bind(&username)
        .execute(&pool)
        .await
        .unwrap();

    let request_id = enqueue_s2s_outbox(
        &pool,
        "remote.test",
        "<iq from='user@local.test/device' to='remote.test' id='pam-request'/>",
        None,
        300,
        100,
        1_000_000,
        100,
    )
    .await
    .unwrap();
    let claim = claim_due_s2s_outbox(&pool, 1, 120).await.unwrap().remove(0);
    assert_eq!(claim.id, request_id);
    sqlx::query(
        "INSERT INTO mix_pam_operations(
                 operation_id,user_id,channel_jid,remote_domain,operation,
                 remote_request_id,client_request_id,requester_full_jid,
                 request_digest,request_outbox_id,deadline_at,expires_at
             ) VALUES($1,$2,'room@remote.test','remote.test','join',$3,
                      'client-request',$4,$5,$6,
                      clock_timestamp()+INTERVAL '1 hour',clock_timestamp()+INTERVAL '8 days')",
    )
    .bind(Uuid::new_v4())
    .bind(user_id)
    .bind(format!("request-{}", Uuid::new_v4().simple()))
    .bind(format!("{username}@local.test/device"))
    .bind(vec![7_u8; 32])
    .bind(request_id)
    .execute(&pool)
    .await
    .unwrap();

    assert!(
        !complete_s2s_outbox_for_sm(&pool, request_id, Uuid::new_v4())
            .await
            .unwrap(),
        "a live claim still requires its exact lock token"
    );
    let mut transaction = pool.begin().await.unwrap();
    sqlx::query("DELETE FROM s2s_outbox WHERE id=$1")
        .bind(request_id)
        .execute(&mut *transaction)
        .await
        .unwrap();
    sqlx::query(
        "UPDATE mix_pam_operations SET state='terminal',
                remote_response_digest=$2,response_xml='<iq type=\"result\"/>'
             WHERE request_outbox_id=$1",
    )
    .bind(request_id)
    .bind(vec![9_u8; 32])
    .execute(&mut *transaction)
    .await
    .unwrap();
    transaction.commit().await.unwrap();
    assert!(
        complete_s2s_outbox_for_sm(&pool, request_id, claim.lock_token)
            .await
            .unwrap(),
        "a terminal PAM response already settled this exact request"
    );
    assert!(
        !complete_s2s_outbox_for_sm(&pool, Uuid::new_v4(), claim.lock_token)
            .await
            .unwrap(),
        "an unrelated missing row is still a lost lease"
    );

    close_route_recovery_test_pool(admin, pool, schema).await;
}

#[tokio::test(flavor = "current_thread")]
#[ignore = "requires TEST_DATABASE_URL; uses and removes a random isolated schema"]
async fn route_recovery_wakes_only_the_observed_fifo_head_and_attempt() {
    let (admin, pool, schema) = route_recovery_test_pool().await;
    let target = "recovery.remote.test";
    assert!(s2s_route_recovery_head(&pool, target)
        .await
        .unwrap()
        .is_none());
    let head_id = enqueue_s2s_outbox(
        &pool,
        target,
        "<message from='sender@local.test' to='peer@recovery.remote.test' id='head'/>",
        None,
        300,
        100,
        1_000_000,
        100,
    )
    .await
    .unwrap();
    let successor_id = enqueue_s2s_outbox(
        &pool,
        target,
        "<message from='sender@local.test' to='peer@recovery.remote.test' id='successor'/>",
        None,
        300,
        100,
        1_000_000,
        100,
    )
    .await
    .unwrap();
    // Make the successor independently eligible for a wake except for
    // FIFO. An already-due successor would not exercise that predicate.
    sqlx::query("UPDATE s2s_outbox SET next_attempt_at=NOW()+INTERVAL '10 minutes' WHERE id=$1")
        .bind(successor_id)
        .execute(&pool)
        .await
        .unwrap();
    let domains = vec![target.to_owned()];
    let mut claimed = claim_due_s2s_outbox_for_domains(&pool, 10, 120, &domains)
        .await
        .unwrap();
    assert_eq!(claimed.len(), 1);
    let first = claimed.remove(0);
    assert_eq!(first.id, head_id);
    assert_eq!(
        fail_s2s_outbox(&pool, &first, "injected route outage", 60, 60, 200, false)
            .await
            .unwrap(),
        S2sFailureDisposition::RetryScheduled
    );
    let observed = s2s_route_recovery_head(&pool, target)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(observed.id, head_id);
    assert_eq!(observed.target_domain, target);
    assert!(observed.stanza.contains("id='head'"));
    assert_eq!(observed.attempt_count, first.attempt_count);
    assert!(!observed.retry_due);
    assert!(!observed.claim_in_flight);
    assert!(claim_due_s2s_outbox_for_domains(&pool, 10, 120, &domains)
        .await
        .unwrap()
        .is_empty());
    assert!(!wake_s2s_route_recovery_head(
        &pool,
        head_id,
        "other.remote.test",
        first.attempt_count
    )
    .await
    .unwrap());
    assert!(
        !wake_s2s_route_recovery_head(&pool, head_id, target, first.attempt_count + 1)
            .await
            .unwrap()
    );
    assert!(
        !wake_s2s_route_recovery_head(&pool, successor_id, target, 0)
            .await
            .unwrap()
    );
    let protected = recovery_row_except_due(&pool, head_id).await;
    assert!(
        wake_s2s_route_recovery_head(&pool, head_id, target, first.attempt_count)
            .await
            .unwrap()
    );
    assert_eq!(
        recovery_row_except_due(&pool, head_id).await,
        protected,
        "recovery must change only the due timestamp"
    );
    assert!(
        !wake_s2s_route_recovery_head(&pool, head_id, target, first.attempt_count)
            .await
            .unwrap(),
        "the same due head must not consume a second recovery write"
    );
    let mut claimed = claim_due_s2s_outbox_for_domains(&pool, 10, 120, &domains)
        .await
        .unwrap();
    assert_eq!(claimed.len(), 1);
    let recovered = claimed.remove(0);
    assert_eq!(recovered.id, head_id);
    assert_eq!(recovered.attempt_count, first.attempt_count + 1);
    assert_ne!(recovered.lock_token, first.lock_token);
    assert!(!complete_s2s_outbox(&pool, first.id, first.lock_token)
        .await
        .unwrap());
    assert_eq!(
        fail_s2s_outbox(&pool, &first, "stale owner", 60, 60, 200, false)
            .await
            .unwrap(),
        S2sFailureDisposition::LeaseLost
    );
    assert_eq!(
        fail_s2s_outbox(
            &pool,
            &recovered,
            "later independent failure",
            60,
            60,
            200,
            false
        )
        .await
        .unwrap(),
        S2sFailureDisposition::RetryScheduled
    );
    assert!(
        !wake_s2s_route_recovery_head(&pool, head_id, target, first.attempt_count)
            .await
            .unwrap(),
        "an old observation must not override a later attempt's backoff"
    );
    assert!(
        !s2s_route_recovery_head(&pool, target)
            .await
            .unwrap()
            .unwrap()
            .retry_due
    );
    // Only a new observation may authorize a new recovery opportunity.
    assert!(
        wake_s2s_route_recovery_head(&pool, head_id, target, recovered.attempt_count)
            .await
            .unwrap()
    );
    let mut claimed = claim_due_s2s_outbox_for_domains(&pool, 10, 120, &domains)
        .await
        .unwrap();
    assert_eq!(claimed.len(), 1);
    let final_head = claimed.remove(0);
    assert_eq!(final_head.id, head_id);
    assert!(
        complete_s2s_outbox(&pool, final_head.id, final_head.lock_token)
            .await
            .unwrap()
    );
    assert!(
        !wake_s2s_route_recovery_head(&pool, head_id, target, recovered.attempt_count)
            .await
            .unwrap(),
        "a completed head's hint must not move to its successor"
    );
    assert_eq!(
        s2s_route_recovery_head(&pool, target)
            .await
            .unwrap()
            .unwrap()
            .id,
        successor_id
    );
    assert!(wake_s2s_route_recovery_head(&pool, successor_id, target, 0)
        .await
        .unwrap());
    let mut claimed = claim_due_s2s_outbox_for_domains(&pool, 10, 120, &domains)
        .await
        .unwrap();
    assert_eq!(claimed.len(), 1);
    let successor = claimed.remove(0);
    assert_eq!(successor.id, successor_id);
    assert!(
        complete_s2s_outbox(&pool, successor.id, successor.lock_token)
            .await
            .unwrap()
    );
    assert!(s2s_route_recovery_head(&pool, target)
        .await
        .unwrap()
        .is_none());
    close_route_recovery_test_pool(admin, pool, schema).await;
}

#[tokio::test(flavor = "current_thread")]
#[ignore = "requires TEST_DATABASE_URL; uses and removes a random isolated schema"]
async fn route_recovery_waits_for_lease_failure_commit_and_preserves_fencing() {
    let (admin, pool, schema) = route_recovery_test_pool().await;
    let target = "leased-recovery.remote.test";
    let head_id = enqueue_s2s_outbox(
        &pool, target,
        "<message from='sender@local.test' to='peer@leased-recovery.remote.test' id='leased-head'/>",
        None, 300, 100, 1_000_000, 100,
    ).await.unwrap();
    let domains = vec![target.to_owned()];
    let mut claimed = claim_due_s2s_outbox_for_domains(&pool, 10, 120, &domains)
        .await
        .unwrap();
    assert_eq!(claimed.len(), 1);
    let first = claimed.remove(0);
    let mut blocker = pool.begin().await.unwrap();
    let locked: Uuid = sqlx::query_scalar("SELECT id FROM s2s_outbox WHERE id=$1 FOR UPDATE")
        .bind(head_id)
        .fetch_one(&mut *blocker)
        .await
        .unwrap();
    assert_eq!(locked, head_id);
    let fail_pool = pool.clone();
    let failing_item = first.clone();
    let (started_tx, started_rx) = tokio::sync::oneshot::channel();
    let failing = tokio::spawn(async move {
        started_tx.send(()).unwrap();
        fail_s2s_outbox(
            &fail_pool,
            &failing_item,
            "failure commit held by row lock",
            60,
            60,
            200,
            false,
        )
        .await
    });
    started_rx.await.unwrap();
    // The row lock makes it impossible for the real failure operation to
    // commit before this route-recovery observation, without a sleep or
    // a test-only replacement for the production failure SQL.
    let observed = s2s_route_recovery_head(&pool, target)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(observed.id, head_id);
    assert_eq!(observed.attempt_count, first.attempt_count);
    assert!(observed.claim_in_flight);
    assert!(!failing.is_finished());
    assert!(!tokio::time::timeout(
        std::time::Duration::from_secs(5),
        wake_s2s_route_recovery_head(&pool, head_id, target, observed.attempt_count),
    )
    .await
    .expect("a leased head must be rejected without waiting for its blocked failure")
    .unwrap());
    let token_before_commit: Uuid =
        sqlx::query_scalar("SELECT lock_token FROM s2s_outbox WHERE id=$1")
            .bind(head_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(token_before_commit, first.lock_token);
    blocker.commit().await.unwrap();
    assert_eq!(
        tokio::time::timeout(std::time::Duration::from_secs(5), failing)
            .await
            .expect("releasing the blocker must let the real failure commit")
            .unwrap()
            .unwrap(),
        S2sFailureDisposition::RetryScheduled
    );
    let after_commit = s2s_route_recovery_head(&pool, target)
        .await
        .unwrap()
        .unwrap();
    assert!(!after_commit.claim_in_flight);
    assert!(!after_commit.retry_due);
    assert_eq!(after_commit.attempt_count, observed.attempt_count);
    let protected = recovery_row_except_due(&pool, head_id).await;
    assert!(
        wake_s2s_route_recovery_head(&pool, head_id, target, observed.attempt_count)
            .await
            .unwrap(),
        "a retained hint must work after the old lease's failure commits"
    );
    assert_eq!(recovery_row_except_due(&pool, head_id).await, protected);
    let mut claimed = claim_due_s2s_outbox_for_domains(&pool, 10, 120, &domains)
        .await
        .unwrap();
    assert_eq!(claimed.len(), 1);
    let recovered = claimed.remove(0);
    assert_eq!(recovered.id, head_id);
    assert_ne!(recovered.lock_token, first.lock_token);
    assert!(!complete_s2s_outbox(&pool, first.id, first.lock_token)
        .await
        .unwrap());
    // Even an expired timestamp is not permission to clear an old token.
    // Keep due in the future so this exercises fencing, not the no-op
    // guard for rows that are already eligible for an ordinary claim.
    sqlx::query("UPDATE s2s_outbox SET locked_until=NOW()-INTERVAL '1 second', next_attempt_at=NOW()+INTERVAL '10 minutes' WHERE id=$1")
        .bind(head_id).execute(&pool).await.unwrap();
    let expired_claim = s2s_route_recovery_head(&pool, target)
        .await
        .unwrap()
        .unwrap();
    assert!(expired_claim.claim_in_flight);
    assert!(!expired_claim.retry_due);
    let protected = recovery_row_except_due(&pool, head_id).await;
    assert!(
        !wake_s2s_route_recovery_head(&pool, head_id, target, recovered.attempt_count)
            .await
            .unwrap()
    );
    assert_eq!(recovery_row_except_due(&pool, head_id).await, protected);
    assert_eq!(
        fail_s2s_outbox(
            &pool,
            &recovered,
            "clear only the owning expired token",
            60,
            60,
            200,
            false
        )
        .await
        .unwrap(),
        S2sFailureDisposition::RetryScheduled
    );
    // A fully unleased but expired row must remain invisible and cannot
    // be revived by an otherwise matching recovery observation.
    sqlx::query("UPDATE s2s_outbox SET created_at=NOW()-INTERVAL '2 hours', expires_at=NOW()-INTERVAL '1 hour' WHERE id=$1")
        .bind(head_id).execute(&pool).await.unwrap();
    assert!(s2s_route_recovery_head(&pool, target)
        .await
        .unwrap()
        .is_none());
    assert!(
        !wake_s2s_route_recovery_head(&pool, head_id, target, recovered.attempt_count)
            .await
            .unwrap()
    );
    close_route_recovery_test_pool(admin, pool, schema).await;
}

#[test]
fn durable_message_retries_keep_one_authoritative_identity() {
    let outbox_id = Uuid::from_u128(0x1234);
    let input = "<message from='Alice@Example.COM/Phone' to='bob@remote.test'><stanza-id xmlns='urn:xmpp:sid:0' by='alice@example.com' id='forged'/><stanza-id xmlns='urn:xmpp:sid:0' by='mallory@example.com' id='same-domain-forged'/><stanza-id xmlns='urn:xmpp:sid:0' by='remote.test' id='peer-id'/><body>hello</body></message>";

    let first = durable_federation_stanza(input, outbox_id).unwrap();
    let retry = durable_federation_stanza(input, outbox_id).unwrap();
    assert_eq!(first, retry, "the same outbox row must retry identically");

    let document = roxmltree::Document::parse(&first).unwrap();
    let ids = document
        .root_element()
        .children()
        .filter(|child| {
            child.is_element()
                && child.tag_name().namespace() == Some("urn:xmpp:sid:0")
                && child.tag_name().name() == "stanza-id"
        })
        .map(|child| {
            (
                child.attribute("by").unwrap().to_owned(),
                child.attribute("id").unwrap().to_owned(),
            )
        })
        .collect::<Vec<_>>();
    assert_eq!(ids.len(), 2);
    assert!(ids.contains(&("remote.test".to_owned(), "peer-id".to_owned())));
    assert!(ids.contains(&("alice@example.com".to_owned(), outbox_id.to_string())));
    assert!(!first.contains("forged"));
    assert!(!first.contains("same-domain-forged"));
}

#[test]
fn non_message_outbox_stanzas_are_not_rewritten() {
    let iq = "<iq from='alice@example.com' to='remote.test' type='get' id='one'/>";
    assert_eq!(
        durable_federation_stanza(iq, Uuid::from_u128(7)).unwrap(),
        iq
    );
}

#[test]
fn durable_messages_require_an_identity_authority() {
    let error = durable_federation_stanza("<message><body>hello</body></message>", Uuid::nil())
        .unwrap_err();
    assert!(error.to_string().contains("missing its from address"));
}

#[test]
fn retry_delay_is_bounded_exponential_with_jitter() {
    let id = Uuid::from_u128(0x1234);
    let one = retry_delay_seconds(1, 5, 3600, id);
    let two = retry_delay_seconds(2, 5, 3600, id);
    let ten = retry_delay_seconds(20, 5, 3600, id);
    assert!((5..=6).contains(&one));
    assert!((10..=12).contains(&two));
    assert!(two > one);
    assert_eq!(ten, 3600);
}

#[test]
fn utf8_error_truncation_does_not_split_a_character() {
    let error = "x".repeat(2047) + "界";
    let truncated = truncate_utf8(&error, 2048);
    assert_eq!(truncated.len(), 2047);
    assert!(std::str::from_utf8(truncated.as_bytes()).is_ok());
}

#[tokio::test]
#[ignore = "requires an isolated TEST_DATABASE_URL PostgreSQL database"]
async fn claim_preserves_mam_results_before_fin() {
    use std::time::Duration;

    let url = std::env::var("TEST_DATABASE_URL")
        .expect("set TEST_DATABASE_URL to an isolated PostgreSQL database");
    let admin = sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .acquire_timeout(Duration::from_secs(60))
        .connect(&url)
        .await
        .unwrap();
    let schema = format!("s2s_ordering_test_{}", Uuid::new_v4().simple());
    sqlx::query(&format!("CREATE SCHEMA {schema}"))
        .execute(&admin)
        .await
        .unwrap();
    eprintln!("isolated_schema_created={schema}");
    let connection_schema = schema.clone();
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(4)
        .acquire_timeout(Duration::from_secs(60))
        .after_connect(move |connection, _| {
            let statement = format!("SET search_path TO {connection_schema}");
            Box::pin(async move {
                sqlx::query(&statement).execute(connection).await?;
                Ok(())
            })
        })
        .connect(&url)
        .await
        .unwrap();
    crate::db::migrate(&pool).await.unwrap();
    let domain = format!("ordering-{}.invalid", Uuid::new_v4());
    let admitted = [
        "<message from='archive@local.test' id='mam-result-1'/>",
        "<message from='archive@local.test' id='mam-result-2'/>",
        "<iq from='local.test' id='mam-fin'/>",
    ];
    for stanza in admitted {
        enqueue_s2s_outbox(&pool, &domain, stanza, None, 300, 100, 1024 * 1024, 100)
            .await
            .unwrap();
    }
    for expected_id in ["mam-result-1", "mam-result-2", "mam-fin"] {
        let claimed = claim_due_s2s_outbox(&pool, 10_000, 60).await.unwrap();
        let ours = claimed
            .into_iter()
            .filter(|item| item.target_domain == domain)
            .collect::<Vec<_>>();
        assert_eq!(ours.len(), 1, "only the domain head may be leased");
        assert!(ours[0].stanza.contains(&format!("id='{expected_id}'")));
        assert!(complete_s2s_outbox(&pool, ours[0].id, ours[0].lock_token)
            .await
            .unwrap());
    }
    pool.close().await;
    sqlx::query(&format!("DROP SCHEMA {schema} CASCADE"))
        .execute(&admin)
        .await
        .unwrap();
    admin.close().await;
}

#[tokio::test(flavor = "current_thread")]
#[ignore = "requires TEST_DATABASE_URL; uses and removes a random isolated schema"]
async fn scoped_claims_are_cross_worker_ordered_and_component_safe() {
    use std::time::Duration;

    let url = std::env::var("TEST_DATABASE_URL")
        .expect("set TEST_DATABASE_URL to an isolated PostgreSQL database");
    let admin = sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .acquire_timeout(Duration::from_secs(60))
        .connect(&url)
        .await
        .unwrap();
    let schema = format!("s2s_outbox_test_{}", Uuid::new_v4().simple());
    sqlx::query(&format!("CREATE SCHEMA {schema}"))
        .execute(&admin)
        .await
        .unwrap();
    eprintln!("isolated_schema_created={schema}");
    let connection_schema = schema.clone();
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(6)
        .acquire_timeout(Duration::from_secs(60))
        .after_connect(move |connection, _| {
            let statement = format!("SET search_path TO {connection_schema}");
            Box::pin(async move {
                sqlx::query(&statement).execute(connection).await?;
                Ok(())
            })
        })
        .connect(&url)
        .await
        .unwrap();
    crate::db::migrate(&pool).await.unwrap();
    let policy = S2sOutboxPolicy {
        ttl_seconds: 300,
        max_rows: 100,
        max_bytes: 1_000_000,
        max_per_domain: 100,
    };
    for (domain, stanza) in [
        (
            "a.remote.test",
            "<message from='sender@local.test' id='a1'/>",
        ),
        (
            "a.remote.test",
            "<message from='sender@local.test' id='a2'/>",
        ),
        (
            "b.remote.test",
            "<message from='sender@local.test' id='b1'/>",
        ),
        (
            "gateway.local.test",
            "<message from='sender@local.test' id='component'/>",
        ),
    ] {
        let mut transaction = pool.begin().await.unwrap();
        enqueue_s2s_outbox_in_transaction(&mut transaction, domain, stanza, None, policy)
            .await
            .unwrap();
        transaction.commit().await.unwrap();
    }

    let component_domains = vec!["gateway.local.test".to_owned()];
    let snapshot = s2s_outbox_snapshot(&pool, &component_domains)
        .await
        .unwrap();
    assert_eq!(snapshot.pending_rows, 4);
    assert!(snapshot.pending_bytes > 0);
    assert!(snapshot.oldest_age_seconds >= 0.0);
    assert_eq!(snapshot.due_rows, 3, "only one head per domain is due");
    assert_eq!(snapshot.locked_rows, 0);
    assert_eq!(snapshot.component_pending_rows, 1);
    let federated = claim_due_s2s_outbox_excluding_domains(&pool, 10, 60, &component_domains)
        .await
        .unwrap();
    assert_eq!(federated.len(), 2, "one head from each remote domain");
    assert!(federated.iter().any(|item| item.stanza.contains("id='a1'")));
    assert!(federated.iter().any(|item| item.stanza.contains("id='b1'")));
    assert!(!federated.iter().any(|item| item.stanza.contains("id='a2'")));
    assert!(!federated
        .iter()
        .any(|item| item.target_domain == "gateway.local.test"));

    let competing = claim_due_s2s_outbox_excluding_domains(&pool, 10, 60, &component_domains)
        .await
        .unwrap();
    assert!(
        competing.is_empty(),
        "another cluster worker must not overtake leased domain heads"
    );

    let a1 = federated
        .iter()
        .find(|item| item.target_domain == "a.remote.test")
        .unwrap();
    assert!(
        renew_s2s_outbox_lease(&pool, a1.id, a1.lock_token, 120)
            .await
            .unwrap(),
        "the owning worker must be able to fence and renew its lease"
    );
    assert!(
        !renew_s2s_outbox_lease(&pool, a1.id, Uuid::new_v4(), 120)
            .await
            .unwrap(),
        "a stale worker token must not revive another worker's lease"
    );
    sqlx::query("UPDATE s2s_outbox SET locked_until = NOW() - INTERVAL '1 second' WHERE id = $1")
        .bind(a1.id)
        .execute(&pool)
        .await
        .unwrap();
    assert!(
        !renew_s2s_outbox_lease(&pool, a1.id, a1.lock_token, 120)
            .await
            .unwrap(),
        "an expired claim must not be revived even when its old fencing token remains"
    );
    assert_eq!(
        fail_s2s_outbox(&pool, a1, "injected outage", 60, 60, 5, false)
            .await
            .unwrap(),
        S2sFailureDisposition::RetryScheduled
    );
    let b1 = federated
        .iter()
        .find(|item| item.target_domain == "b.remote.test")
        .unwrap();
    assert!(complete_s2s_outbox(&pool, b1.id, b1.lock_token)
        .await
        .unwrap());

    let component = claim_due_s2s_outbox_for_domains(&pool, 10, 60, &component_domains)
        .await
        .unwrap();
    assert_eq!(component.len(), 1);
    assert_eq!(component[0].target_domain, "gateway.local.test");
    assert!(
        complete_s2s_outbox(&pool, component[0].id, component[0].lock_token)
            .await
            .unwrap()
    );

    // A scheduled retry is the domain head and therefore blocks a2.
    assert!(
        claim_due_s2s_outbox_excluding_domains(&pool, 10, 60, &component_domains,)
            .await
            .unwrap()
            .is_empty()
    );
    sqlx::query("UPDATE s2s_outbox SET next_attempt_at=NOW() WHERE target_domain='a.remote.test'")
        .execute(&pool)
        .await
        .unwrap();
    let retried = claim_due_s2s_outbox_excluding_domains(&pool, 10, 60, &component_domains)
        .await
        .unwrap();
    assert_eq!(retried.len(), 1);
    assert!(retried[0].stanza.contains("id='a1'"));
    assert!(
        complete_s2s_outbox(&pool, retried[0].id, retried[0].lock_token)
            .await
            .unwrap()
    );
    let successor = claim_due_s2s_outbox_excluding_domains(&pool, 10, 60, &component_domains)
        .await
        .unwrap();
    assert_eq!(successor.len(), 1);
    assert!(successor[0].stanza.contains("id='a2'"));
    assert!(
        complete_s2s_outbox(&pool, successor[0].id, successor[0].lock_token)
            .await
            .unwrap()
    );

    // Two user actions can legally produce byte-identical XML (including
    // stanzas without an id). They are two admissions, not a dedupe key.
    for _ in 0..2 {
        let mut transaction = pool.begin().await.unwrap();
        enqueue_s2s_outbox_in_transaction(
            &mut transaction,
            "duplicates.remote.test",
            "<message from='sender@local.test'><body>same</body></message>",
            None,
            policy,
        )
        .await
        .unwrap();
        transaction.commit().await.unwrap();
    }
    let duplicates: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM s2s_outbox WHERE target_domain='duplicates.remote.test'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(
        duplicates, 2,
        "byte-identical stanzas must not be collapsed"
    );

    let rejected_before = s2s_outbox_capacity_rejections_total();
    let mut transaction = pool.begin().await.unwrap();
    let rejected = enqueue_s2s_outbox_in_transaction(
        &mut transaction,
        "capacity.remote.test",
        "<message from='sender@local.test'/>",
        None,
        S2sOutboxPolicy {
            max_rows: 0,
            ..policy
        },
    )
    .await;
    assert!(rejected.is_err());
    transaction.rollback().await.unwrap();
    assert!(s2s_outbox_capacity_rejections_total() > rejected_before);

    // A claimed head remains durable across a process/pool restart. Once
    // its lease expires, a new worker receives the same row with a fresh
    // fencing token; a stale pre-crash token can no longer complete it.
    let mut transaction = pool.begin().await.unwrap();
    enqueue_s2s_outbox_in_transaction(
        &mut transaction,
        "restart.remote.test",
        "<message from='sender@local.test' id='restart-head'/>",
        None,
        policy,
    )
    .await
    .unwrap();
    transaction.commit().await.unwrap();
    let before_restart = claim_due_s2s_outbox_excluding_domains(&pool, 10, 1, &component_domains)
        .await
        .unwrap()
        .into_iter()
        .find(|item| item.target_domain == "restart.remote.test")
        .expect("restart test head was not claimed");
    pool.close().await;
    tokio::time::sleep(Duration::from_millis(1_100)).await;

    let restart_schema = schema.clone();
    let restarted_pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(6)
        .acquire_timeout(Duration::from_secs(60))
        .after_connect(move |connection, _| {
            let statement = format!("SET search_path TO {restart_schema}");
            Box::pin(async move {
                sqlx::query(&statement).execute(connection).await?;
                Ok(())
            })
        })
        .connect(&url)
        .await
        .unwrap();
    let after_restart =
        claim_due_s2s_outbox_excluding_domains(&restarted_pool, 10, 60, &component_domains)
            .await
            .unwrap()
            .into_iter()
            .find(|item| item.target_domain == "restart.remote.test")
            .expect("expired pre-restart lease was not reclaimed");
    assert_eq!(after_restart.id, before_restart.id);
    assert_ne!(after_restart.lock_token, before_restart.lock_token);
    assert!(
        !complete_s2s_outbox(
            &restarted_pool,
            before_restart.id,
            before_restart.lock_token,
        )
        .await
        .unwrap(),
        "a pre-restart fencing token completed a reclaimed row"
    );
    assert!(
        complete_s2s_outbox(&restarted_pool, after_restart.id, after_restart.lock_token)
            .await
            .unwrap()
    );
    restarted_pool.close().await;

    sqlx::query(&format!("DROP SCHEMA {schema} CASCADE"))
        .execute(&admin)
        .await
        .unwrap();
    admin.close().await;
}
