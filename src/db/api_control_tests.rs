use super::*;

fn request<'a>(key: &'a str, body: &[u8]) -> IdempotencyRequest<'a> {
    IdempotencyRequest {
        request_id: Uuid::new_v4(),
        actor_id: Some(Uuid::nil()),
        principal_scope: b"user:00000000-0000-0000-0000-000000000000",
        capacity_scope: b"user:00000000-0000-0000-0000-000000000000",
        target_scope: b"",
        principal_kind: ApiPrincipalKind::User,
        method: "POST",
        route: "/api/v1/example",
        idempotency_key: key,
        request_fingerprint: api_request_fingerprint("application/json", body),
        ttl_seconds: 3600,
        lease_seconds: 30,
    }
}

fn admin_request<'a>(
    actor_id: &'a Uuid,
    key: &'a str,
    target_scope: &'a [u8],
    method: &'a str,
    route: &'a str,
    body: &[u8],
) -> IdempotencyRequest<'a> {
    IdempotencyRequest {
        request_id: Uuid::new_v4(),
        actor_id: Some(*actor_id),
        principal_scope: actor_id.as_bytes(),
        capacity_scope: actor_id.as_bytes(),
        target_scope,
        principal_kind: ApiPrincipalKind::Admin,
        method,
        route,
        idempotency_key: key,
        request_fingerprint: api_request_fingerprint("application/json", body),
        ttl_seconds: 3600,
        lease_seconds: 30,
    }
}

fn acquired(outcome: IdempotencyAcquire) -> IdempotencyLease {
    match outcome {
        IdempotencyAcquire::Acquired(lease) => lease,
        other => panic!("expected a new idempotency lease, got {other:?}"),
    }
}

#[test]
fn scope_and_keyed_fingerprint_bind_request_without_persisting_raw_identity() {
    let keys = ApiControlKeyring::new(b"0123456789abcdef0123456789abcdef", None).unwrap();
    let first = request("request-key-0001", br#"{"value":1}"#);
    let second = request("request-key-0002", br#"{"value":1}"#);
    let first_hash = keys.scope_hashes(&first).0;
    assert_ne!(first_hash, keys.scope_hashes(&second).0);

    let mut other_route = request("request-key-0001", br#"{"value":1}"#);
    other_route.route = "/api/v1/other";
    assert_ne!(first_hash, keys.scope_hashes(&other_route).0);

    let first_fingerprint = keys.request_fingerprints(&first).0;
    assert_ne!(first_fingerprint, first.request_fingerprint);
    let different_body = request("request-key-0001", br#"{"value":2}"#);
    assert_ne!(
        first_fingerprint,
        keys.request_fingerprints(&different_body).0
    );
    let mut different_target = request("request-key-0001", br#"{"value":1}"#);
    different_target.target_scope = b"report:00000000-0000-0000-0000-000000000001";
    assert_eq!(first_hash, keys.scope_hashes(&different_target).0);
    assert_ne!(
        first_fingerprint,
        keys.request_fingerprints(&different_target).0
    );
}

#[test]
fn replay_aead_detects_ciphertext_and_context_tampering() {
    let keys = ApiControlKeyring::new(b"0123456789abcdef0123456789abcdef", None).unwrap();
    let id = Uuid::new_v4();
    let scope = [1_u8; 32];
    let fingerprint = [2_u8; 32];
    let nonce = [3_u8; 12];
    let aad = replay_aad(id, &scope, &fingerprint, 201);
    let mut ciphertext = br#"{"token":"secret"}"#.to_vec();
    seal_replay(&keys.current, nonce, aad.clone(), &mut ciphertext).unwrap();
    assert!(!String::from_utf8_lossy(&ciphertext).contains("secret"));
    let mut valid = ciphertext.clone();
    open_replay(&keys.current, nonce, aad, &mut valid).unwrap();
    assert_eq!(valid, br#"{"token":"secret"}"#);

    ciphertext[0] ^= 1;
    assert!(open_replay(
        &keys.current,
        nonce,
        replay_aad(id, &scope, &fingerprint, 201),
        &mut ciphertext,
    )
    .is_err());
}

#[tokio::test]
#[ignore = "requires an isolated TEST_DATABASE_URL PostgreSQL database"]
async fn capacity_lock_contention_fails_fast_without_starving_pool() {
    use std::sync::Arc;
    use std::time::Duration;
    use tokio::sync::Barrier;

    let url = std::env::var("TEST_DATABASE_URL")
        .expect("set TEST_DATABASE_URL to an isolated PostgreSQL database");
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(4)
        .connect(&url)
        .await
        .unwrap();
    crate::db::migrate(&pool).await.unwrap();

    let keys =
        Arc::new(ApiControlKeyring::new(b"capacity-lock-test-secret-000000001", None).unwrap());
    let mut holder = pool.begin().await.unwrap();
    let _: i64 = sqlx::query_scalar(
        "SELECT active_records FROM api_idempotency_capacity
         WHERE singleton=TRUE FOR UPDATE",
    )
    .fetch_one(&mut *holder)
    .await
    .unwrap();

    // The holder plus these three transactions occupy all four pool
    // connections before they race the singleton. With a blocking
    // `FOR UPDATE`, an unrelated query could never obtain a connection.
    let ready = Arc::new(Barrier::new(4));
    let contender = |number: u8| {
        let pool = pool.clone();
        let keys = Arc::clone(&keys);
        let ready = Arc::clone(&ready);
        tokio::spawn(async move {
            let key = format!("capacity-busy-key-{number:04}");
            let body = format!(r#"{{"contender":{number}}}"#);
            let mut request = request(&key, body.as_bytes());
            request.actor_id = None;
            request.principal_kind = ApiPrincipalKind::Anonymous;
            request.principal_scope = b"capacity-lock-test:anonymous";
            request.capacity_scope = b"capacity-lock-test:anonymous";
            let mut tx = pool.begin().await.unwrap();
            ready.wait().await;
            let retry_after = match acquire_idempotency_in_tx(&keys, &mut tx, &request)
                .await
                .unwrap()
            {
                IdempotencyAcquire::Busy {
                    retry_after_seconds,
                } => retry_after_seconds,
                other => panic!("expected busy capacity admission, got {other:?}"),
            };
            // Production callers have the same explicit rollback branch;
            // the connection must return to the pool before any retry.
            tx.rollback().await.unwrap();
            retry_after
        })
    };
    let first = contender(1);
    let second = contender(2);
    let third = contender(3);
    ready.wait().await;

    let unrelated: i32 = tokio::time::timeout(
        Duration::from_secs(2),
        sqlx::query_scalar("SELECT 1").fetch_one(&pool),
    )
    .await
    .expect("idempotency lock waiters starved an unrelated pool query")
    .unwrap();
    assert_eq!(unrelated, 1);

    let (first, second, third) = tokio::time::timeout(Duration::from_secs(2), async {
        tokio::join!(first, second, third)
    })
    .await
    .expect("busy idempotency admissions did not return promptly");
    assert_eq!(first.unwrap(), 1);
    assert_eq!(second.unwrap(), 1);
    assert_eq!(third.unwrap(), 1);
    holder.rollback().await.unwrap();

    let mut recovered = pool.begin().await.unwrap();
    let mut recovered_request = request("capacity-recovered-key", br#"{"recovered":true}"#);
    recovered_request.actor_id = None;
    recovered_request.principal_kind = ApiPrincipalKind::Anonymous;
    recovered_request.principal_scope = b"capacity-lock-test:anonymous";
    recovered_request.capacity_scope = b"capacity-lock-test:anonymous";
    assert!(matches!(
        acquire_idempotency_in_tx(&keys, &mut recovered, &recovered_request)
            .await
            .unwrap(),
        IdempotencyAcquire::Acquired(_)
    ));
    recovered.rollback().await.unwrap();

    let mut missing_authority = pool.begin().await.unwrap();
    sqlx::query("DELETE FROM api_idempotency_capacity WHERE singleton=TRUE")
        .execute(&mut *missing_authority)
        .await
        .unwrap();
    let mut missing_request = request("capacity-missing-key", br#"{"missing":true}"#);
    missing_request.actor_id = None;
    missing_request.principal_kind = ApiPrincipalKind::Anonymous;
    missing_request.principal_scope = b"capacity-lock-test:anonymous";
    missing_request.capacity_scope = b"capacity-lock-test:anonymous";
    let error = acquire_idempotency_in_tx(&keys, &mut missing_authority, &missing_request)
        .await
        .expect_err("a missing capacity authority row must fail closed");
    assert!(
        error
            .to_string()
            .contains("API idempotency capacity authority row is missing"),
        "unexpected missing-authority error: {error:#}"
    );
    missing_authority.rollback().await.unwrap();
}

#[tokio::test]
#[ignore = "requires an isolated TEST_DATABASE_URL PostgreSQL database"]
async fn failed_login_penalty_and_replay_are_one_transaction() {
    use crate::abuse::{AbuseAction, AbuseConfig, AbuseGuard};
    use std::time::Duration;

    let url = std::env::var("TEST_DATABASE_URL")
        .expect("set TEST_DATABASE_URL to an isolated PostgreSQL database");
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(4)
        .connect(&url)
        .await
        .unwrap();
    crate::db::migrate(&pool).await.unwrap();

    let keys = ApiControlKeyring::new(b"login-idempotency-secret-0000000001", None).unwrap();
    let guard = AbuseGuard::new_persistent(
        AbuseConfig {
            base_work_factor: 2,
            max_work_factor: 1_000_000,
            window: Duration::from_secs(300),
            cooldown_step: Duration::from_secs(60),
            max_wait: Duration::from_secs(8),
            message_free_burst: 5,
            approximate_max_device_seconds: 8,
        },
        pool.clone(),
        Some(b"login-abuse-state-secret-00000000001"),
        None,
    );
    let raw_body = br#"{"username":"missing","password":"wrong"}"#;
    let request = IdempotencyRequest {
        request_id: Uuid::new_v4(),
        actor_id: None,
        principal_scope: b"login:missing",
        capacity_scope: b"ip:192.0.2.7",
        target_scope: b"",
        principal_kind: ApiPrincipalKind::Anonymous,
        method: "POST",
        route: "/api/v1/login",
        idempotency_key: "failed-login-key-0001",
        request_fingerprint: api_request_fingerprint("application/json", raw_body),
        ttl_seconds: 3600,
        lease_seconds: 30,
    };
    let actors = vec!["ip:192.0.2.7".to_owned(), "account:missing".to_owned()];

    let mut reserve_tx = pool.begin().await.unwrap();
    let lease = acquired(
        acquire_idempotency_in_tx(&keys, &mut reserve_tx, &request)
            .await
            .unwrap(),
    );
    reserve_tx.commit().await.unwrap();

    // A backend failure after recording the penalty but before commit must
    // leave neither a penalty nor a terminal replay behind. The original
    // lease remains retryable with the same fencing token.
    let mut failed_tx = pool.begin().await.unwrap();
    assert!(resume_idempotency_lease_in_tx(&mut failed_tx, &lease, 30)
        .await
        .unwrap());
    crate::db::abuse_transaction_repository::record_failure_in_tx(
        &mut failed_tx,
        &guard,
        AbuseAction::Login,
        &actors,
    )
    .await
    .unwrap();
    assert!(
        mark_idempotency_guard_verified_in_tx(&mut failed_tx, &lease)
            .await
            .unwrap()
    );
    let mut headers = BTreeMap::new();
    headers.insert("content-type".to_owned(), "application/json".to_owned());
    headers.insert(
        "www-authenticate".to_owned(),
        "Bearer realm=\"northstar\"".to_owned(),
    );
    let body = br#"{"error":{"code":"unauthorized","message":"authentication required"}}"#;
    assert!(
        complete_idempotency_in_tx(&keys, &mut failed_tx, &lease, 401, &headers, body,)
            .await
            .unwrap()
    );
    failed_tx.rollback().await.unwrap();

    let (state, guard_verified): (String, bool) = sqlx::query_as(
        "SELECT state,guard_verified_at IS NOT NULL FROM api_idempotency_records WHERE id=$1",
    )
    .bind(lease.record_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(state, "started");
    assert!(!guard_verified);
    let rolled_back_events: i64 = sqlx::query_scalar(
        "SELECT COALESCE(SUM(cardinality(event_times)),0)::bigint FROM abuse_actor_states",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(rolled_back_events, 0);

    let mut retry_tx = pool.begin().await.unwrap();
    assert!(resume_idempotency_lease_in_tx(&mut retry_tx, &lease, 30)
        .await
        .unwrap());
    crate::db::abuse_transaction_repository::record_failure_in_tx(
        &mut retry_tx,
        &guard,
        AbuseAction::Login,
        &actors,
    )
    .await
    .unwrap();
    assert!(mark_idempotency_guard_verified_in_tx(&mut retry_tx, &lease)
        .await
        .unwrap());
    assert!(
        complete_idempotency_in_tx(&keys, &mut retry_tx, &lease, 401, &headers, body,)
            .await
            .unwrap()
    );
    retry_tx.commit().await.unwrap();

    let committed_events: i64 = sqlx::query_scalar(
        "SELECT COALESCE(SUM(cardinality(event_times)),0)::bigint FROM abuse_actor_states",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    // Login records both the account identity and the shared source-IP
    // signal. They are distinct bounded actor states, each advanced once.
    assert_eq!(committed_events, 2);
    let mut replay_tx = pool.begin().await.unwrap();
    let replay = match acquire_idempotency_in_tx(&keys, &mut replay_tx, &request)
        .await
        .unwrap()
    {
        IdempotencyAcquire::Replay(replay) => replay,
        other => panic!("expected terminal failed-login replay, got {other:?}"),
    };
    replay_tx.commit().await.unwrap();
    assert_eq!(replay.status, 401);
    assert_eq!(replay.headers, headers);
    assert_eq!(replay.body, body);
    let replay_events: i64 = sqlx::query_scalar(
        "SELECT COALESCE(SUM(cardinality(event_times)),0)::bigint FROM abuse_actor_states",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(replay_events, 2);

    pool.close().await;
}

#[tokio::test]
#[ignore = "requires an isolated TEST_DATABASE_URL PostgreSQL database"]
async fn yielded_lease_preserves_guard_marker_and_fences_old_worker() {
    let url = std::env::var("TEST_DATABASE_URL")
        .expect("set TEST_DATABASE_URL to an isolated PostgreSQL database");
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(4)
        .connect(&url)
        .await
        .unwrap();
    crate::db::migrate(&pool).await.unwrap();

    let keys = ApiControlKeyring::new(b"yield-idempotency-key-00000000001", None).unwrap();
    let raw_body = br#"{"username":"yield-test","password":"not-persisted"}"#;
    let request = IdempotencyRequest {
        request_id: Uuid::new_v4(),
        actor_id: None,
        principal_scope: b"registration:192.0.2.40",
        capacity_scope: b"ip:192.0.2.40",
        target_scope: b"",
        principal_kind: ApiPrincipalKind::Anonymous,
        method: "POST",
        route: "/api/v1/register",
        idempotency_key: "yielded-registration-work-0001",
        request_fingerprint: api_request_fingerprint("application/json", raw_body),
        ttl_seconds: 3_600,
        lease_seconds: 30,
    };
    let mut reserve = pool.begin().await.unwrap();
    let lease = acquired(
        acquire_idempotency_in_tx(&keys, &mut reserve, &request)
            .await
            .unwrap(),
    );
    assert!(mark_idempotency_guard_verified_in_tx(&mut reserve, &lease)
        .await
        .unwrap());
    reserve.commit().await.unwrap();

    assert!(yield_idempotency_lease(&pool, &lease).await.unwrap());
    let mut stale = pool.begin().await.unwrap();
    assert!(!resume_idempotency_lease_in_tx(&mut stale, &lease, 30)
        .await
        .unwrap());
    stale.rollback().await.unwrap();

    let mut takeover = pool.begin().await.unwrap();
    let replacement = acquired(
        acquire_idempotency_in_tx(&keys, &mut takeover, &request)
            .await
            .unwrap(),
    );
    assert!(replacement.guard_verified);
    assert_ne!(replacement.lease_token(), lease.lease_token());
    takeover.rollback().await.unwrap();
}

#[tokio::test]
#[ignore = "requires an isolated TEST_DATABASE_URL PostgreSQL database"]
async fn postgres_idempotency_is_atomic_rotatable_and_tamper_evident() {
    let url = std::env::var("TEST_DATABASE_URL")
        .expect("set TEST_DATABASE_URL to an isolated PostgreSQL database");
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(8)
        .connect(&url)
        .await
        .unwrap();
    crate::db::migrate(&pool).await.unwrap();
    crate::db::migrate(&pool).await.unwrap();
    let actor_id = Uuid::new_v4();
    sqlx::query("INSERT INTO users(id,username,password_hash) VALUES($1,$2,'test-only-invalid')")
        .bind(actor_id)
        .bind(format!("api{}", &Uuid::new_v4().simple().to_string()[..12]))
        .execute(&pool)
        .await
        .unwrap();

    let old_secret = b"old-api-control-secret-000000000001";
    let new_secret = b"new-api-control-secret-000000000002";
    let old_keys = ApiControlKeyring::new(old_secret, None).unwrap();
    let raw_request = br#"{"username":"alice","password":"not-a-database-verifier"}"#;
    let fingerprint = api_request_fingerprint("application/json", raw_request);
    let make_request = |key: &'static str| IdempotencyRequest {
        request_id: Uuid::new_v4(),
        actor_id: Some(actor_id),
        principal_scope: actor_id.as_bytes(),
        capacity_scope: actor_id.as_bytes(),
        target_scope: b"",
        principal_kind: ApiPrincipalKind::Admin,
        method: "POST",
        route: "/api/v1/admin/example",
        idempotency_key: key,
        request_fingerprint: fingerprint,
        ttl_seconds: 3600,
        lease_seconds: 30,
    };

    // The idempotency reservation is part of the caller's transaction;
    // rolling the mutation back must not leave a phantom in-progress key.
    let mut rollback_tx = pool.begin().await.unwrap();
    assert!(matches!(
        acquire_idempotency_in_tx(
            &old_keys,
            &mut rollback_tx,
            &make_request("rollback-key-0001")
        )
        .await
        .unwrap(),
        IdempotencyAcquire::Acquired(_)
    ));
    rollback_tx.rollback().await.unwrap();
    let rollback_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM api_idempotency_records WHERE request_actor_id=$1",
    )
    .bind(actor_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(rollback_count, 0);

    let mut tx = pool.begin().await.unwrap();
    let lease =
        match acquire_idempotency_in_tx(&old_keys, &mut tx, &make_request("rotation-key-0001"))
            .await
            .unwrap()
        {
            IdempotencyAcquire::Acquired(lease) => lease,
            other => panic!("unexpected first acquire: {other:?}"),
        };
    let mut headers = BTreeMap::new();
    headers.insert("content-type".to_owned(), "application/json".to_owned());
    let response = br#"{"token":"only-visible-after-aead"}"#;
    assert!(
        complete_idempotency_in_tx(&old_keys, &mut tx, &lease, 201, &headers, response,)
            .await
            .unwrap()
    );
    tx.commit().await.unwrap();

    let raw_key_stored: bool = sqlx::query_scalar(
        "SELECT EXISTS(
            SELECT 1 FROM api_idempotency_records
            WHERE position($1::bytea in scope_hash) > 0
               OR position($1::bytea in response_ciphertext) > 0
         )",
    )
    .bind(b"rotation-key-0001".as_slice())
    .fetch_one(&pool)
    .await
    .unwrap();
    assert!(!raw_key_stored);
    let plaintext_stored: bool = sqlx::query_scalar(
        "SELECT EXISTS(
            SELECT 1 FROM api_idempotency_records
            WHERE position($1::bytea in response_ciphertext) > 0
         )",
    )
    .bind(b"only-visible-after-aead".as_slice())
    .fetch_one(&pool)
    .await
    .unwrap();
    assert!(!plaintext_stored);
    let raw_fingerprint_stored: bool = sqlx::query_scalar(
        "SELECT EXISTS(
            SELECT 1 FROM api_idempotency_records
            WHERE request_fingerprint=$1
         )",
    )
    .bind(fingerprint.as_slice())
    .fetch_one(&pool)
    .await
    .unwrap();
    assert!(!raw_fingerprint_stored);

    // A rotating process recognizes the old scope HMAC, authenticates the
    // old replay, then atomically rewrites both scope and response under
    // the current key before returning it.
    let rotating_keys = ApiControlKeyring::new(new_secret, Some(old_secret)).unwrap();
    let mut rotate_tx = pool.begin().await.unwrap();
    let replay = match acquire_idempotency_in_tx(
        &rotating_keys,
        &mut rotate_tx,
        &make_request("rotation-key-0001"),
    )
    .await
    .unwrap()
    {
        IdempotencyAcquire::Replay(replay) => replay,
        other => panic!("unexpected rotating acquire: {other:?}"),
    };
    assert_eq!(replay.status, 201);
    assert_eq!(replay.headers, headers);
    assert_eq!(replay.body, response);
    rotate_tx.commit().await.unwrap();
    let (scope_key_id, response_key_id): (String, String) = sqlx::query_as(
        "SELECT scope_key_id,response_key_id FROM api_idempotency_records
         WHERE id=$1",
    )
    .bind(lease.record_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(scope_key_id, rotating_keys.current.id);
    assert_eq!(response_key_id, rotating_keys.current.id);
    let rotated_fingerprint: Vec<u8> =
        sqlx::query_scalar("SELECT request_fingerprint FROM api_idempotency_records WHERE id=$1")
            .bind(lease.record_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(
        rotated_fingerprint,
        rotating_keys
            .request_fingerprints(&make_request("rotation-key-0001"))
            .0
    );

    // Once rebound, removing the previous key cannot turn the same raw key
    // into a new mutation.
    let new_keys = ApiControlKeyring::new(new_secret, None).unwrap();
    let mut replay_tx = pool.begin().await.unwrap();
    assert!(matches!(
        acquire_idempotency_in_tx(
            &new_keys,
            &mut replay_tx,
            &make_request("rotation-key-0001")
        )
        .await
        .unwrap(),
        IdempotencyAcquire::Replay(_)
    ));
    replay_tx.commit().await.unwrap();

    let conflict_request = IdempotencyRequest {
        request_fingerprint: api_request_fingerprint(
            "application/json",
            br#"{"action":"different"}"#,
        ),
        ..make_request("rotation-key-0001")
    };
    let mut conflict_tx = pool.begin().await.unwrap();
    assert!(matches!(
        acquire_idempotency_in_tx(&new_keys, &mut conflict_tx, &conflict_request)
            .await
            .unwrap(),
        IdempotencyAcquire::FingerprintConflict
    ));
    conflict_tx.rollback().await.unwrap();

    let target_conflict_request = IdempotencyRequest {
        target_scope: b"report:00000000-0000-0000-0000-000000000001",
        ..make_request("rotation-key-0001")
    };
    let mut target_conflict_tx = pool.begin().await.unwrap();
    assert!(matches!(
        acquire_idempotency_in_tx(&new_keys, &mut target_conflict_tx, &target_conflict_request)
            .await
            .unwrap(),
        IdempotencyAcquire::FingerprintConflict
    ));
    target_conflict_tx.rollback().await.unwrap();

    // If an incorrectly staged rotation already created both HMAC rows,
    // fail closed instead of choosing either mutation/replay implicitly.
    for keys in [&old_keys, &new_keys] {
        let mut double_tx = pool.begin().await.unwrap();
        let double_lease = match acquire_idempotency_in_tx(
            keys,
            &mut double_tx,
            &make_request("double-row-key-0001"),
        )
        .await
        .unwrap()
        {
            IdempotencyAcquire::Acquired(lease) => lease,
            other => panic!("unexpected double-row setup: {other:?}"),
        };
        assert!(complete_idempotency_in_tx(
            keys,
            &mut double_tx,
            &double_lease,
            200,
            &headers,
            br#"{"ok":true}"#,
        )
        .await
        .unwrap());
        double_tx.commit().await.unwrap();
    }
    let mut double_tx = pool.begin().await.unwrap();
    assert!(matches!(
        acquire_idempotency_in_tx(
            &rotating_keys,
            &mut double_tx,
            &make_request("double-row-key-0001")
        )
        .await
        .unwrap(),
        IdempotencyAcquire::RotationConflict
    ));
    double_tx.rollback().await.unwrap();

    // Any database-side change to the encrypted headers/body bundle is
    // detected before a replay is returned.
    sqlx::query(
        "UPDATE api_idempotency_records
         SET response_ciphertext=set_byte(response_ciphertext,0,
             get_byte(response_ciphertext,0) # 1)
         WHERE id=$1",
    )
    .bind(lease.record_id)
    .execute(&pool)
    .await
    .unwrap();
    let mut tamper_tx = pool.begin().await.unwrap();
    assert!(acquire_idempotency_in_tx(
        &new_keys,
        &mut tamper_tx,
        &make_request("rotation-key-0001")
    )
    .await
    .is_err());
    tamper_tx.rollback().await.unwrap();

    // Anonymous callers cannot fill PostgreSQL with random 24-hour
    // reservations. Distinct account scopes share the coarser capacity
    // scope, are serialized, and expire after five minutes unless they
    // complete.
    let capacity_scope = b"ip:198.51.100.44";
    for index in 0..MAX_STARTED_PER_PRINCIPAL {
        let key = format!("capacity-key-{index:04}");
        let principal = format!("login:198.51.100.44:account-{index}");
        let capacity_request = IdempotencyRequest {
            request_id: Uuid::new_v4(),
            actor_id: None,
            principal_scope: principal.as_bytes(),
            capacity_scope,
            target_scope: b"",
            principal_kind: ApiPrincipalKind::Anonymous,
            method: "POST",
            route: "/api/v1/login",
            idempotency_key: &key,
            request_fingerprint: fingerprint,
            ttl_seconds: 3600,
            lease_seconds: 180,
        };
        let mut capacity_tx = pool.begin().await.unwrap();
        assert!(matches!(
            acquire_idempotency_in_tx(&new_keys, &mut capacity_tx, &capacity_request)
                .await
                .unwrap(),
            IdempotencyAcquire::Acquired(_)
        ));
        capacity_tx.commit().await.unwrap();
    }
    let overflow_key = "capacity-overflow-key";
    let overflow_request = IdempotencyRequest {
        request_id: Uuid::new_v4(),
        actor_id: None,
        principal_scope: b"login:198.51.100.44:overflow",
        capacity_scope,
        target_scope: b"",
        principal_kind: ApiPrincipalKind::Anonymous,
        method: "POST",
        route: "/api/v1/login",
        idempotency_key: overflow_key,
        request_fingerprint: fingerprint,
        ttl_seconds: 3600,
        lease_seconds: 180,
    };
    let mut overflow_tx = pool.begin().await.unwrap();
    assert!(matches!(
        acquire_idempotency_in_tx(&new_keys, &mut overflow_tx, &overflow_request)
            .await
            .unwrap(),
        IdempotencyAcquire::CapacityLimited { .. }
    ));
    overflow_tx.rollback().await.unwrap();
    let maximum_started_lifetime: f64 = sqlx::query_scalar(
        "SELECT MAX(EXTRACT(EPOCH FROM (expires_at-created_at)))::double precision
         FROM api_idempotency_records WHERE state='started'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert!(maximum_started_lifetime <= 301.0);

    sqlx::query(
        "UPDATE api_idempotency_records
         SET created_at=clock_timestamp()-INTERVAL '10 minutes',
             expires_at=clock_timestamp()-INTERVAL '1 second'
         WHERE state='started' AND ownership_actor_id IS NULL",
    )
    .execute(&pool)
    .await
    .unwrap();
    cleanup_expired_idempotency(&pool, 10_000).await.unwrap();

    // Successful anonymous registration/login records are rebound to an
    // authenticated owner and must not exhaust a shared-NAT IP quota.
    // They remain globally bounded and login sessions retain their own
    // independent 32-session account bound.
    for index in 0..1000 {
        let key = format!("owned-success-{index:04}");
        let principal = format!("registration:203.0.113.9:account-{index}");
        let owned_request = IdempotencyRequest {
            request_id: Uuid::new_v4(),
            actor_id: None,
            principal_scope: principal.as_bytes(),
            capacity_scope: b"ip:203.0.113.9",
            target_scope: b"",
            principal_kind: ApiPrincipalKind::Anonymous,
            method: "POST",
            route: "/api/v1/register",
            idempotency_key: &key,
            request_fingerprint: fingerprint,
            ttl_seconds: 3600,
            lease_seconds: 180,
        };
        let mut owned_tx = pool.begin().await.unwrap();
        let owned_lease = match acquire_idempotency_in_tx(&new_keys, &mut owned_tx, &owned_request)
            .await
            .unwrap()
        {
            IdempotencyAcquire::Acquired(lease) => lease,
            other => panic!("shared NAT success {index} was rejected: {other:?}"),
        };
        assert!(
            bind_idempotency_actor_in_tx(&mut owned_tx, &owned_lease, actor_id)
                .await
                .unwrap()
        );
        assert!(complete_idempotency_in_tx(
            &new_keys,
            &mut owned_tx,
            &owned_lease,
            201,
            &headers,
            br#"{"created":true}"#,
        )
        .await
        .unwrap());
        owned_tx.commit().await.unwrap();
    }

    // Completed public rejections stay replayable for only minutes and
    // still count against the anonymous principal's total hard bound.
    for index in 0..MAX_RECORDS_PER_PRINCIPAL {
        let key = format!("rejected-request-{index:04}");
        let rejected_request = IdempotencyRequest {
            request_id: Uuid::new_v4(),
            actor_id: None,
            principal_scope: b"registration:203.0.113.10",
            capacity_scope: b"ip:203.0.113.10",
            target_scope: b"",
            principal_kind: ApiPrincipalKind::Anonymous,
            method: "POST",
            route: "/api/v1/register",
            idempotency_key: &key,
            request_fingerprint: fingerprint,
            ttl_seconds: 3600,
            lease_seconds: 180,
        };
        let mut rejected_tx = pool.begin().await.unwrap();
        let rejected_lease =
            match acquire_idempotency_in_tx(&new_keys, &mut rejected_tx, &rejected_request)
                .await
                .unwrap()
            {
                IdempotencyAcquire::Acquired(lease) => lease,
                other => panic!("rejection setup {index} failed: {other:?}"),
            };
        assert!(complete_idempotency_in_tx(
            &new_keys,
            &mut rejected_tx,
            &rejected_lease,
            400,
            &headers,
            br#"{"rejected":true}"#,
        )
        .await
        .unwrap());
        rejected_tx.commit().await.unwrap();
    }
    let rejected_overflow_key = "rejected-request-overflow";
    let rejected_overflow = IdempotencyRequest {
        request_id: Uuid::new_v4(),
        actor_id: None,
        principal_scope: b"registration:203.0.113.10",
        capacity_scope: b"ip:203.0.113.10",
        target_scope: b"",
        principal_kind: ApiPrincipalKind::Anonymous,
        method: "POST",
        route: "/api/v1/register",
        idempotency_key: rejected_overflow_key,
        request_fingerprint: fingerprint,
        ttl_seconds: 3600,
        lease_seconds: 180,
    };
    let mut rejected_overflow_tx = pool.begin().await.unwrap();
    assert!(matches!(
        acquire_idempotency_in_tx(&new_keys, &mut rejected_overflow_tx, &rejected_overflow)
            .await
            .unwrap(),
        IdempotencyAcquire::CapacityLimited { .. }
    ));
    rejected_overflow_tx.rollback().await.unwrap();
    let maximum_rejection_lifetime: f64 = sqlx::query_scalar(
        "SELECT MAX(EXTRACT(EPOCH FROM (expires_at-completed_at)))::double precision
         FROM api_idempotency_records WHERE response_status >= 400",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert!(maximum_rejection_lifetime <= 301.0);

    let actual_records: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM api_idempotency_records")
        .fetch_one(&pool)
        .await
        .unwrap();
    let tracked_records: i64 = sqlx::query_scalar(
        "SELECT active_records FROM api_idempotency_capacity WHERE singleton=TRUE",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(tracked_records, actual_records);
    sqlx::query("UPDATE api_idempotency_capacity SET active_records=$1 WHERE singleton=TRUE")
        .bind(MAX_GLOBAL_RECORDS)
        .execute(&pool)
        .await
        .unwrap();
    let global_key = "global-waterline-key";
    let global_request = IdempotencyRequest {
        request_id: Uuid::new_v4(),
        actor_id: Some(actor_id),
        principal_scope: b"global-waterline-principal",
        capacity_scope: b"global-waterline-principal",
        target_scope: b"",
        principal_kind: ApiPrincipalKind::User,
        method: "POST",
        route: "/api/v1/example",
        idempotency_key: global_key,
        request_fingerprint: fingerprint,
        ttl_seconds: 3600,
        lease_seconds: 180,
    };
    let mut global_tx = pool.begin().await.unwrap();
    assert!(matches!(
        acquire_idempotency_in_tx(&new_keys, &mut global_tx, &global_request)
            .await
            .unwrap(),
        IdempotencyAcquire::CapacityLimited { .. }
    ));
    global_tx.rollback().await.unwrap();
    sqlx::query("UPDATE api_idempotency_capacity SET active_records=$1 WHERE singleton=TRUE")
        .bind(actual_records)
        .execute(&pool)
        .await
        .unwrap();

    // Lease fencing prevents a PASSWORD_WORK waiter whose bounded lease
    // expired from committing after a retry recovered the reservation.
    let stale_request = IdempotencyRequest {
        request_id: Uuid::new_v4(),
        actor_id: Some(actor_id),
        principal_scope: b"stale-worker-principal",
        capacity_scope: b"stale-worker-capacity",
        target_scope: b"",
        principal_kind: ApiPrincipalKind::Admin,
        method: "POST",
        route: "/api/v1/admin/example",
        idempotency_key: "stale-worker-key-0001",
        request_fingerprint: fingerprint,
        ttl_seconds: 3600,
        lease_seconds: 5,
    };
    let mut stale_tx = pool.begin().await.unwrap();
    let stale_lease = match acquire_idempotency_in_tx(&new_keys, &mut stale_tx, &stale_request)
        .await
        .unwrap()
    {
        IdempotencyAcquire::Acquired(lease) => lease,
        other => panic!("unexpected stale worker acquire: {other:?}"),
    };
    stale_tx.commit().await.unwrap();
    sqlx::query(
        "UPDATE api_idempotency_records
         SET lease_expires_at=clock_timestamp()-INTERVAL '1 second'
         WHERE id=$1",
    )
    .bind(stale_lease.record_id)
    .execute(&pool)
    .await
    .unwrap();
    let mut recovered_tx = pool.begin().await.unwrap();
    let recovered_lease =
        match acquire_idempotency_in_tx(&new_keys, &mut recovered_tx, &stale_request)
            .await
            .unwrap()
        {
            IdempotencyAcquire::Acquired(lease) => lease,
            other => panic!("unexpected recovered acquire: {other:?}"),
        };
    recovered_tx.commit().await.unwrap();
    let mut stale_commit_tx = pool.begin().await.unwrap();
    assert!(!complete_idempotency_in_tx(
        &new_keys,
        &mut stale_commit_tx,
        &stale_lease,
        200,
        &headers,
        br#"{"stale":true}"#,
    )
    .await
    .unwrap());
    stale_commit_tx.rollback().await.unwrap();
    let mut recovered_commit_tx = pool.begin().await.unwrap();
    assert!(complete_idempotency_in_tx(
        &new_keys,
        &mut recovered_commit_tx,
        &recovered_lease,
        200,
        &headers,
        br#"{"recovered":true}"#,
    )
    .await
    .unwrap());
    recovered_commit_tx.commit().await.unwrap();
}

#[tokio::test]
#[ignore = "requires an isolated TEST_DATABASE_URL PostgreSQL database"]
async fn concurrent_register_and_login_execute_once_per_idempotency_key() {
    let url = std::env::var("TEST_DATABASE_URL")
        .expect("set TEST_DATABASE_URL to an isolated PostgreSQL database");
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(8)
        .connect(&url)
        .await
        .unwrap();
    crate::db::migrate(&pool).await.unwrap();
    crate::db::initialize_admin_runtime_settings(&pool, false, false, false)
        .await
        .unwrap();

    let suffix = Uuid::new_v4().simple().to_string();
    let username = format!("idem{}", &suffix[..10]);
    let password = "idempotent-registration-password";
    let invitation = format!("invite-{suffix}");
    let invitation_id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO invitation_tokens
         (id,token_hash,label,max_uses) VALUES($1,$2,'idempotency-test',1)",
    )
    .bind(invitation_id)
    .bind(crate::auth::token_hash(&invitation))
    .execute(&pool)
    .await
    .unwrap();
    let prepared_a = crate::db::prepare_registration(
        &username,
        password,
        crate::auth::MIN_SCRAM_ITERATIONS,
        false,
    )
    .await
    .unwrap();
    let prepared_b = crate::db::prepare_registration(
        &username,
        password,
        crate::auth::MIN_SCRAM_ITERATIONS,
        false,
    )
    .await
    .unwrap();
    let register_fingerprint = api_request_fingerprint(
        "application/json",
        format!("{{\"username\":\"{username}\"}}").as_bytes(),
    );
    let register_once = |prepared: crate::db::PreparedRegistration| {
        let pool = pool.clone();
        let username = username.clone();
        let invitation = invitation.clone();
        async move {
            let keys =
                ApiControlKeyring::new(b"route-integration-secret-0000000001", None).unwrap();
            let request = IdempotencyRequest {
                request_id: Uuid::new_v4(),
                actor_id: None,
                principal_scope: b"registration:192.0.2.1",
                capacity_scope: b"registration:192.0.2.1",
                target_scope: b"",
                principal_kind: ApiPrincipalKind::Anonymous,
                method: "POST",
                route: "/api/v1/register",
                idempotency_key: "register-concurrent-key-0001",
                request_fingerprint: register_fingerprint,
                ttl_seconds: 3600,
                lease_seconds: 30,
            };
            let mut prepared = Some(prepared);
            for attempt in 0..40 {
                let mut tx = pool.begin().await.unwrap();
                match acquire_idempotency_in_tx(&keys, &mut tx, &request)
                    .await
                    .unwrap()
                {
                    IdempotencyAcquire::Acquired(lease) => {
                        let user = crate::db::create_user_with_invitation_in_tx(
                            &mut tx,
                            prepared
                                .take()
                                .expect("registration credentials were consumed twice"),
                            Some(&invitation),
                            true,
                            100,
                            Some(lease.request_id),
                        )
                        .await
                        .unwrap();
                        assert!(bind_idempotency_actor_in_tx(&mut tx, &lease, user.id)
                            .await
                            .unwrap());
                        let body = serde_json::to_vec(&serde_json::json!({
                            "jid": format!("{}@example.test", username)
                        }))
                        .unwrap();
                        let headers = BTreeMap::from([
                            ("cache-control".to_owned(), "no-store, max-age=0".to_owned()),
                            ("content-type".to_owned(), "application/json".to_owned()),
                        ]);
                        assert!(complete_idempotency_in_tx(
                            &keys, &mut tx, &lease, 201, &headers, &body
                        )
                        .await
                        .unwrap());
                        tx.commit().await.unwrap();
                        return (true, body);
                    }
                    IdempotencyAcquire::Replay(replay) => {
                        tx.commit().await.unwrap();
                        return (false, replay.body);
                    }
                    IdempotencyAcquire::Busy {
                        retry_after_seconds,
                    } => {
                        assert_eq!(retry_after_seconds, 1);
                        tx.rollback().await.unwrap();
                        assert!(attempt < 39, "registration admission stayed busy");
                        tokio::time::sleep(std::time::Duration::from_millis(25)).await;
                    }
                    other => panic!("unexpected concurrent registration result: {other:?}"),
                }
            }
            unreachable!("bounded registration retry loop returned no outcome")
        }
    };
    let (registered_a, registered_b) =
        tokio::join!(register_once(prepared_a), register_once(prepared_b));
    assert_eq!(usize::from(registered_a.0) + usize::from(registered_b.0), 1);
    assert_eq!(registered_a.1, registered_b.1);
    let user = crate::db::find_user(&pool, &username)
        .await
        .unwrap()
        .unwrap();
    let invitation_uses: i32 =
        sqlx::query_scalar("SELECT use_count FROM invitation_tokens WHERE id=$1")
            .bind(invitation_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(invitation_uses, 1);
    let registrations: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM audit_log
         WHERE actor_id=$1 AND action='user.register' AND request_id IS NOT NULL",
    )
    .bind(user.id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(registrations, 1);

    let prepared_login_a = crate::db::prepare_login(
        &pool,
        &username,
        password,
        crate::auth::MIN_SCRAM_ITERATIONS,
        false,
    )
    .await
    .unwrap()
    .unwrap();
    let prepared_login_b = crate::db::prepare_login(
        &pool,
        &username,
        password,
        crate::auth::MIN_SCRAM_ITERATIONS,
        false,
    )
    .await
    .unwrap()
    .unwrap();
    let login_fingerprint = api_request_fingerprint(
        "application/json",
        format!("{{\"username\":\"{username}\"}}").as_bytes(),
    );
    let login_once = |prepared: crate::db::PreparedLogin| {
        let pool = pool.clone();
        async move {
            let keys =
                ApiControlKeyring::new(b"route-integration-secret-0000000001", None).unwrap();
            let request = IdempotencyRequest {
                request_id: Uuid::new_v4(),
                actor_id: None,
                principal_scope: b"login:192.0.2.1:account-digest",
                capacity_scope: b"ip:192.0.2.1",
                target_scope: b"",
                principal_kind: ApiPrincipalKind::Anonymous,
                method: "POST",
                route: "/api/v1/login",
                idempotency_key: "login-concurrent-key-0000001",
                request_fingerprint: login_fingerprint,
                ttl_seconds: 3600,
                lease_seconds: 30,
            };
            let mut prepared = Some(prepared);
            for attempt in 0..40 {
                let mut tx = pool.begin().await.unwrap();
                match acquire_idempotency_in_tx(&keys, &mut tx, &request)
                    .await
                    .unwrap()
                {
                    IdempotencyAcquire::Acquired(lease) => {
                        assert!(crate::db::apply_prepared_login_in_tx(
                            &mut tx,
                            prepared
                                .take()
                                .expect("login credentials were consumed twice"),
                        )
                        .await
                        .unwrap());
                        assert!(bind_idempotency_actor_in_tx(&mut tx, &lease, user.id)
                            .await
                            .unwrap());
                        let session = crate::db::create_api_session_in_tx(
                            &mut tx,
                            user.id,
                            1,
                            Some(lease.request_id),
                        )
                        .await
                        .unwrap();
                        assert!(bind_idempotency_session_in_tx(
                            &mut tx,
                            &lease,
                            session.id,
                            &session.token_hash,
                            user.auth_generation,
                            session.expires_at,
                        )
                        .await
                        .unwrap());
                        let body = serde_json::to_vec(&serde_json::json!({"token":session.token}))
                            .unwrap();
                        let headers = BTreeMap::from([
                            ("cache-control".to_owned(), "no-store, max-age=0".to_owned()),
                            ("content-type".to_owned(), "application/json".to_owned()),
                        ]);
                        assert!(complete_idempotency_in_tx(
                            &keys, &mut tx, &lease, 200, &headers, &body
                        )
                        .await
                        .unwrap());
                        tx.commit().await.unwrap();
                        return (true, body);
                    }
                    IdempotencyAcquire::Replay(replay) => {
                        tx.commit().await.unwrap();
                        return (false, replay.body);
                    }
                    IdempotencyAcquire::Busy {
                        retry_after_seconds,
                    } => {
                        assert_eq!(retry_after_seconds, 1);
                        tx.rollback().await.unwrap();
                        assert!(attempt < 39, "login admission stayed busy");
                        tokio::time::sleep(std::time::Duration::from_millis(25)).await;
                    }
                    other => panic!("unexpected concurrent login result: {other:?}"),
                }
            }
            unreachable!("bounded login retry loop returned no outcome")
        }
    };
    let (login_a, login_b) =
        tokio::join!(login_once(prepared_login_a), login_once(prepared_login_b));
    assert_eq!(usize::from(login_a.0) + usize::from(login_b.0), 1);
    assert_eq!(login_a.1, login_b.1);
    let sessions: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM api_sessions WHERE user_id=$1")
        .bind(user.id)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(sessions, 1);
    let login_audits: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM audit_log
         WHERE actor_id=$1 AND action='user.session.login' AND request_id IS NOT NULL",
    )
    .bind(user.id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(login_audits, 1);
    let replay_request = IdempotencyRequest {
        request_id: Uuid::new_v4(),
        actor_id: None,
        principal_scope: b"login:192.0.2.1:account-digest",
        capacity_scope: b"ip:192.0.2.1",
        target_scope: b"",
        principal_kind: ApiPrincipalKind::Anonymous,
        method: "POST",
        route: "/api/v1/login",
        idempotency_key: "login-concurrent-key-0000001",
        request_fingerprint: login_fingerprint,
        ttl_seconds: 3600,
        lease_seconds: 30,
    };
    let replay_keys = ApiControlKeyring::new(b"route-integration-secret-0000000001", None).unwrap();
    let mut valid_replay_tx = pool.begin().await.unwrap();
    assert!(matches!(
        acquire_idempotency_in_tx(&replay_keys, &mut valid_replay_tx, &replay_request)
            .await
            .unwrap(),
        IdempotencyAcquire::Replay(_)
    ));
    valid_replay_tx.commit().await.unwrap();
    let replay_outlives_session: bool = sqlx::query_scalar(
        "SELECT idem.expires_at > session.expires_at
         FROM api_idempotency_records idem
         JOIN api_sessions session ON session.id=idem.replay_session_id
         WHERE idem.request_id IN (
            SELECT request_id FROM audit_log
            WHERE actor_id=$1 AND action='user.session.login'
         )",
    )
    .bind(user.id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert!(!replay_outlives_session);
    sqlx::query("DELETE FROM api_sessions WHERE user_id=$1")
        .bind(user.id)
        .execute(&pool)
        .await
        .unwrap();
    let mut invalidated_tx = pool.begin().await.unwrap();
    assert!(matches!(
        acquire_idempotency_in_tx(&replay_keys, &mut invalidated_tx, &replay_request)
            .await
            .unwrap(),
        IdempotencyAcquire::ReplayInvalidated
    ));
    invalidated_tx.rollback().await.unwrap();

    // Registration and the durable control toggle serialize on the same
    // setting row. A close that begins while an admitted registration is
    // still uncommitted must wait, yielding a deterministic before/after
    // boundary rather than a one-second cache race.
    let race_name = format!("race{}", &suffix[..8]);
    let race_prepared = crate::db::prepare_registration(
        &race_name,
        "registration-toggle-race-password",
        crate::auth::MIN_SCRAM_ITERATIONS,
        false,
    )
    .await
    .unwrap();
    let race_keys = ApiControlKeyring::new(b"route-integration-secret-0000000001", None).unwrap();
    let race_request = IdempotencyRequest {
        request_id: Uuid::new_v4(),
        actor_id: None,
        principal_scope: b"registration:192.0.2.3",
        capacity_scope: b"registration:192.0.2.3",
        target_scope: b"",
        principal_kind: ApiPrincipalKind::Anonymous,
        method: "POST",
        route: "/api/v1/register",
        idempotency_key: "registration-toggle-race-0001",
        request_fingerprint: api_request_fingerprint("application/json", b"race"),
        ttl_seconds: 3600,
        lease_seconds: 30,
    };
    let mut race_tx = pool.begin().await.unwrap();
    let race_lease = match acquire_idempotency_in_tx(&race_keys, &mut race_tx, &race_request)
        .await
        .unwrap()
    {
        IdempotencyAcquire::Acquired(lease) => lease,
        other => panic!("unexpected toggle-race acquire: {other:?}"),
    };
    let race_user = crate::db::create_user_with_invitation_in_tx(
        &mut race_tx,
        race_prepared,
        None,
        false,
        100,
        Some(race_lease.request_id),
    )
    .await
    .unwrap();
    assert!(
        bind_idempotency_actor_in_tx(&mut race_tx, &race_lease, race_user.id)
            .await
            .unwrap()
    );
    let headers = BTreeMap::from([
        ("cache-control".to_owned(), "no-store, max-age=0".to_owned()),
        ("content-type".to_owned(), "application/json".to_owned()),
    ]);
    assert!(complete_idempotency_in_tx(
        &race_keys,
        &mut race_tx,
        &race_lease,
        201,
        &headers,
        br#"{"created":true}"#,
    )
    .await
    .unwrap());
    let close_pool = pool.clone();
    let close = tokio::spawn(async move {
        sqlx::query(
            "UPDATE admin_runtime_settings SET enabled=TRUE
             WHERE key='registration_closed'",
        )
        .execute(&close_pool)
        .await
        .unwrap();
    });
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    assert!(!close.is_finished());
    race_tx.commit().await.unwrap();
    close.await.unwrap();
    assert!(crate::db::find_user(&pool, &race_name)
        .await
        .unwrap()
        .is_some());

    sqlx::query(
        "UPDATE admin_runtime_settings SET enabled=TRUE
         WHERE key='registration_closed'",
    )
    .execute(&pool)
    .await
    .unwrap();
    let blocked_name = format!("closed{}", &suffix[..8]);
    let blocked = crate::db::prepare_registration(
        &blocked_name,
        "closed-registration-password",
        crate::auth::MIN_SCRAM_ITERATIONS,
        false,
    )
    .await
    .unwrap();
    let mut blocked_tx = pool.begin().await.unwrap();
    let blocked_keys =
        ApiControlKeyring::new(b"route-integration-secret-0000000001", None).unwrap();
    let blocked_request = IdempotencyRequest {
        request_id: Uuid::new_v4(),
        actor_id: None,
        principal_scope: b"registration:192.0.2.2",
        capacity_scope: b"registration:192.0.2.2",
        target_scope: b"",
        principal_kind: ApiPrincipalKind::Anonymous,
        method: "POST",
        route: "/api/v1/register",
        idempotency_key: "closed-registration-key-0001",
        request_fingerprint: api_request_fingerprint("application/json", b"closed"),
        ttl_seconds: 3600,
        lease_seconds: 30,
    };
    assert!(matches!(
        acquire_idempotency_in_tx(&blocked_keys, &mut blocked_tx, &blocked_request)
            .await
            .unwrap(),
        IdempotencyAcquire::Acquired(_)
    ));
    assert!(matches!(
        crate::db::create_user_with_invitation_in_tx(
            &mut blocked_tx,
            blocked,
            None,
            false,
            100,
            Some(blocked_request.request_id),
        )
        .await,
        Err(crate::db::RegistrationError::Closed)
    ));
    blocked_tx.rollback().await.unwrap();
    assert!(crate::db::find_user(&pool, &blocked_name)
        .await
        .unwrap()
        .is_none());

    // Missing durable control state is database corruption, not an
    // implicit request to reopen public registration.
    sqlx::query("DELETE FROM admin_runtime_settings WHERE key='registration_closed'")
        .execute(&pool)
        .await
        .unwrap();
    let missing_name = format!("missing{}", &suffix[..7]);
    let missing = crate::db::create_user_with_invitation(
        &pool,
        &missing_name,
        "missing-control-row-password",
        None,
        false,
        100,
        crate::auth::MIN_SCRAM_ITERATIONS,
    )
    .await;
    assert!(matches!(
        missing,
        Err(crate::db::RegistrationError::Internal(_))
    ));
    assert!(crate::db::find_user(&pool, &missing_name)
        .await
        .unwrap()
        .is_none());
}

#[tokio::test]
#[ignore = "requires an isolated TEST_DATABASE_URL PostgreSQL database"]
async fn admin_sync_mutations_are_authorized_atomic_replay_safe_and_queue_serialized() {
    let url = std::env::var("TEST_DATABASE_URL")
        .expect("set TEST_DATABASE_URL to an isolated PostgreSQL database");
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(12)
        .connect(&url)
        .await
        .unwrap();
    crate::db::migrate(&pool).await.unwrap();
    crate::db::initialize_admin_runtime_settings(&pool, false, false, false)
        .await
        .unwrap();
    // A prior test may deliberately remove this fail-closed row.
    sqlx::query(
        "INSERT INTO admin_runtime_settings(key,enabled)
         VALUES('registration_closed',FALSE) ON CONFLICT(key) DO NOTHING",
    )
    .execute(&pool)
    .await
    .unwrap();

    let suffix = Uuid::new_v4().simple().to_string();
    let admin_id = Uuid::new_v4();
    let reporter_id = Uuid::new_v4();
    for (id, prefix, is_admin) in [
        (admin_id, "syncadmin", true),
        (reporter_id, "syncreporter", false),
    ] {
        sqlx::query(
            "INSERT INTO users(id,username,password_hash,is_admin)
             VALUES($1,$2,'test-only-invalid',$3)",
        )
        .bind(id)
        .bind(format!("{prefix}-{}", &suffix[..10]))
        .bind(is_admin)
        .execute(&pool)
        .await
        .unwrap();
    }
    let admin_session = crate::db::create_api_session(&pool, admin_id, 1)
        .await
        .unwrap();
    let keys = ApiControlKeyring::new(b"admin-sync-api-control-key-000000001", None).unwrap();
    let headers = BTreeMap::from([
        ("cache-control".to_owned(), "no-store, max-age=0".to_owned()),
        ("content-type".to_owned(), "application/json".to_owned()),
    ]);

    // Registration toggle: bearer reauthorization, setting, audit and
    // replay response share one transaction and one request UUID.
    let close_body = br#"{"enabled":false}"#;
    let close_request = admin_request(
        &admin_id,
        "admin-registration-close-0001",
        b"registration_closed",
        "POST",
        "/api/v1/admin/registration",
        close_body,
    );
    let mut close_tx = pool.begin().await.unwrap();
    assert!(
        crate::db::authorize_admin_in_tx(&mut close_tx, admin_id, 0, &admin_session)
            .await
            .unwrap()
    );
    let close_lease = acquired(
        acquire_idempotency_in_tx(&keys, &mut close_tx, &close_request)
            .await
            .unwrap(),
    );
    let close_request_id = close_lease.request_id;
    crate::db::set_admin_runtime_setting_in_tx(
        &mut close_tx,
        admin_id,
        "registration_closed",
        true,
        Some(close_request_id),
    )
    .await
    .unwrap();
    assert!(complete_idempotency_in_tx(
        &keys,
        &mut close_tx,
        &close_lease,
        200,
        &headers,
        br#"{"open_registration":false}"#,
    )
    .await
    .unwrap());
    close_tx.commit().await.unwrap();
    assert!(sqlx::query_scalar::<_, bool>(
        "SELECT enabled FROM admin_runtime_settings WHERE key='registration_closed'"
    )
    .fetch_one(&pool)
    .await
    .unwrap());
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM audit_log
             WHERE request_id=$1 AND action='admin.runtime_setting.set'"
        )
        .bind(close_request_id)
        .fetch_one(&pool)
        .await
        .unwrap(),
        1
    );
    let mut close_replay_tx = pool.begin().await.unwrap();
    assert!(
        crate::db::authorize_admin_in_tx(&mut close_replay_tx, admin_id, 0, &admin_session)
            .await
            .unwrap()
    );
    assert!(matches!(
        acquire_idempotency_in_tx(&keys, &mut close_replay_tx, &close_request)
            .await
            .unwrap(),
        IdempotencyAcquire::Replay(IdempotentResponse { status: 200, .. })
    ));
    close_replay_tx.commit().await.unwrap();

    // A later request reopens registration. Replaying the historical
    // close cannot mutate the durable setting again.
    let open_request = admin_request(
        &admin_id,
        "admin-registration-open-0002",
        b"registration_closed",
        "POST",
        "/api/v1/admin/registration",
        br#"{"enabled":true}"#,
    );
    let mut open_tx = pool.begin().await.unwrap();
    assert!(
        crate::db::authorize_admin_in_tx(&mut open_tx, admin_id, 0, &admin_session)
            .await
            .unwrap()
    );
    let open_lease = acquired(
        acquire_idempotency_in_tx(&keys, &mut open_tx, &open_request)
            .await
            .unwrap(),
    );
    crate::db::set_admin_runtime_setting_in_tx(
        &mut open_tx,
        admin_id,
        "registration_closed",
        false,
        Some(open_lease.request_id),
    )
    .await
    .unwrap();
    assert!(complete_idempotency_in_tx(
        &keys,
        &mut open_tx,
        &open_lease,
        200,
        &headers,
        br#"{"open_registration":true}"#,
    )
    .await
    .unwrap());
    open_tx.commit().await.unwrap();
    let mut historical_tx = pool.begin().await.unwrap();
    assert!(
        crate::db::authorize_admin_in_tx(&mut historical_tx, admin_id, 0, &admin_session)
            .await
            .unwrap()
    );
    assert!(matches!(
        acquire_idempotency_in_tx(&keys, &mut historical_tx, &close_request)
            .await
            .unwrap(),
        IdempotencyAcquire::Replay(_)
    ));
    historical_tx.commit().await.unwrap();
    assert!(!sqlx::query_scalar::<_, bool>(
        "SELECT enabled FROM admin_runtime_settings WHERE key='registration_closed'"
    )
    .fetch_one(&pool)
    .await
    .unwrap());

    // The raw invitation secret is only present in the AEAD response.
    // Its replay lifetime is capped by PostgreSQL's resource expiry and
    // every replay revalidates revocation and remaining uses.
    let invitation_id = Uuid::new_v4();
    let invitation_token = crate::auth::new_session_token();
    let invitation_body = serde_json::to_vec(&serde_json::json!({
        "id": invitation_id,
        "token": invitation_token,
        "shown_once": true
    }))
    .unwrap();
    let invite_request = admin_request(
        &admin_id,
        "admin-invitation-create-0001",
        b"invitation:create",
        "POST",
        "/api/v1/admin/invitations",
        br#"{"label":"integration","max_uses":2,"expires_in_hours":1}"#,
    );
    let mut invite_tx = pool.begin().await.unwrap();
    assert!(
        crate::db::authorize_admin_in_tx(&mut invite_tx, admin_id, 0, &admin_session)
            .await
            .unwrap()
    );
    let invite_lease = acquired(
        acquire_idempotency_in_tx(&keys, &mut invite_tx, &invite_request)
            .await
            .unwrap(),
    );
    let invite_request_id = invite_lease.request_id;
    crate::db::create_invitation_in_tx(
        &mut invite_tx,
        admin_id,
        invitation_id,
        &invitation_token,
        "integration",
        2,
        Some(1),
        Some(invite_request_id),
    )
    .await
    .unwrap();
    assert!(complete_idempotency_with_resource_in_tx(
        &keys,
        &mut invite_tx,
        &invite_lease,
        201,
        &headers,
        &invitation_body,
        Some(invitation_id),
    )
    .await
    .unwrap());
    invite_tx.commit().await.unwrap();
    let stored = sqlx::query(
        "SELECT response_ciphertext,expires_at,
                (SELECT expires_at FROM invitation_tokens WHERE id=$1) AS invitation_expiry
         FROM api_idempotency_records WHERE request_id=$2",
    )
    .bind(invitation_id)
    .bind(invite_request_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    let ciphertext: Vec<u8> = stored.get("response_ciphertext");
    assert!(!ciphertext
        .windows(invitation_token.len())
        .any(|window| window == invitation_token.as_bytes()));
    assert!(
        stored.get::<DateTime<Utc>, _>("expires_at")
            <= stored.get::<DateTime<Utc>, _>("invitation_expiry")
    );
    let audit_details: serde_json::Value = sqlx::query_scalar(
        "SELECT details FROM audit_log
         WHERE request_id=$1 AND action='admin.invitation.create'",
    )
    .bind(invite_request_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert!(!audit_details.to_string().contains(&invitation_token));
    let mut invite_replay_tx = pool.begin().await.unwrap();
    assert!(
        crate::db::authorize_admin_in_tx(&mut invite_replay_tx, admin_id, 0, &admin_session)
            .await
            .unwrap()
    );
    match acquire_idempotency_in_tx(&keys, &mut invite_replay_tx, &invite_request)
        .await
        .unwrap()
    {
        IdempotencyAcquire::Replay(replay) => assert_eq!(replay.body, invitation_body),
        other => panic!("expected invitation replay, got {other:?}"),
    }
    invite_replay_tx.commit().await.unwrap();

    let revoke_request = admin_request(
        &admin_id,
        "admin-invitation-revoke-0001",
        invitation_id.as_bytes(),
        "DELETE",
        "/api/v1/admin/invitations/{id}",
        b"",
    );
    let mut revoke_tx = pool.begin().await.unwrap();
    assert!(
        crate::db::authorize_admin_in_tx(&mut revoke_tx, admin_id, 0, &admin_session)
            .await
            .unwrap()
    );
    let revoke_lease = acquired(
        acquire_idempotency_in_tx(&keys, &mut revoke_tx, &revoke_request)
            .await
            .unwrap(),
    );
    assert_eq!(
        crate::db::revoke_invitation_in_tx(
            &mut revoke_tx,
            admin_id,
            invitation_id,
            Some(revoke_lease.request_id),
        )
        .await
        .unwrap(),
        crate::db::InvitationRevokeOutcome::Revoked
    );
    assert!(complete_idempotency_in_tx(
        &keys,
        &mut revoke_tx,
        &revoke_lease,
        200,
        &headers,
        br#"{"revoked":true,"already_revoked":false}"#,
    )
    .await
    .unwrap());
    revoke_tx.commit().await.unwrap();
    let mut invalid_secret_replay_tx = pool.begin().await.unwrap();
    assert!(crate::db::authorize_admin_in_tx(
        &mut invalid_secret_replay_tx,
        admin_id,
        0,
        &admin_session
    )
    .await
    .unwrap());
    assert!(matches!(
        acquire_idempotency_in_tx(&keys, &mut invalid_secret_replay_tx, &invite_request)
            .await
            .unwrap(),
        IdempotencyAcquire::ReplayInvalidated
    ));
    invalid_secret_replay_tx.rollback().await.unwrap();
    sqlx::query(
        "UPDATE invitation_tokens
         SET revoked_at=NULL,expires_at=clock_timestamp()-INTERVAL '1 second'
         WHERE id=$1",
    )
    .bind(invitation_id)
    .execute(&pool)
    .await
    .unwrap();
    let mut expired_secret_replay_tx = pool.begin().await.unwrap();
    assert!(crate::db::authorize_admin_in_tx(
        &mut expired_secret_replay_tx,
        admin_id,
        0,
        &admin_session
    )
    .await
    .unwrap());
    assert!(matches!(
        acquire_idempotency_in_tx(&keys, &mut expired_secret_replay_tx, &invite_request)
            .await
            .unwrap(),
        IdempotencyAcquire::ReplayInvalidated
    ));
    expired_secret_replay_tx.rollback().await.unwrap();
    sqlx::query(
        "UPDATE invitation_tokens
         SET expires_at=clock_timestamp()+INTERVAL '1 hour',use_count=max_uses
         WHERE id=$1",
    )
    .bind(invitation_id)
    .execute(&pool)
    .await
    .unwrap();
    let mut exhausted_secret_replay_tx = pool.begin().await.unwrap();
    assert!(crate::db::authorize_admin_in_tx(
        &mut exhausted_secret_replay_tx,
        admin_id,
        0,
        &admin_session
    )
    .await
    .unwrap());
    assert!(matches!(
        acquire_idempotency_in_tx(&keys, &mut exhausted_secret_replay_tx, &invite_request)
            .await
            .unwrap(),
        IdempotencyAcquire::ReplayInvalidated
    ));
    exhausted_secret_replay_tx.rollback().await.unwrap();
    sqlx::query(
        "UPDATE invitation_tokens SET use_count=0,revoked_at=clock_timestamp() WHERE id=$1",
    )
    .bind(invitation_id)
    .execute(&pool)
    .await
    .unwrap();
    let second_revoke = admin_request(
        &admin_id,
        "admin-invitation-revoke-0002",
        invitation_id.as_bytes(),
        "DELETE",
        "/api/v1/admin/invitations/{id}",
        b"",
    );
    let mut second_revoke_tx = pool.begin().await.unwrap();
    assert!(
        crate::db::authorize_admin_in_tx(&mut second_revoke_tx, admin_id, 0, &admin_session)
            .await
            .unwrap()
    );
    let second_revoke_lease = acquired(
        acquire_idempotency_in_tx(&keys, &mut second_revoke_tx, &second_revoke)
            .await
            .unwrap(),
    );
    assert_eq!(
        crate::db::revoke_invitation_in_tx(
            &mut second_revoke_tx,
            admin_id,
            invitation_id,
            Some(second_revoke_lease.request_id),
        )
        .await
        .unwrap(),
        crate::db::InvitationRevokeOutcome::AlreadyRevoked
    );
    assert!(complete_idempotency_in_tx(
        &keys,
        &mut second_revoke_tx,
        &second_revoke_lease,
        200,
        &headers,
        br#"{"revoked":true,"already_revoked":true}"#,
    )
    .await
    .unwrap());
    second_revoke_tx.commit().await.unwrap();

    // Report and appeal updates use UUID-bound fingerprints, serialize
    // their rows, and keep the moderation audit in the same commit.
    let report_id = Uuid::new_v4();
    let appeal_id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO abuse_reports(id,reporter_id,reported_jid,category)
         VALUES($1,$2,'peer@example.test','spam')",
    )
    .bind(report_id)
    .bind(reporter_id)
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO abuse_appeals(id,report_id,appellant_id,reason)
         VALUES($1,$2,$3,'sufficiently long test appeal reason')",
    )
    .bind(appeal_id)
    .bind(report_id)
    .bind(reporter_id)
    .execute(&pool)
    .await
    .unwrap();
    for (kind, id, route, key) in [
        (
            "report",
            report_id,
            "/api/v1/admin/reports/{id}",
            "admin-report-review-0001",
        ),
        (
            "appeal",
            appeal_id,
            "/api/v1/admin/appeals/{id}",
            "admin-appeal-review-0001",
        ),
    ] {
        let mutation = admin_request(
            &admin_id,
            key,
            id.as_bytes(),
            "PATCH",
            route,
            br#"{"status":"reviewing"}"#,
        );
        let mut tx = pool.begin().await.unwrap();
        assert!(
            crate::db::authorize_admin_in_tx(&mut tx, admin_id, 0, &admin_session)
                .await
                .unwrap()
        );
        let lease = acquired(
            acquire_idempotency_in_tx(&keys, &mut tx, &mutation)
                .await
                .unwrap(),
        );
        if kind == "report" {
            crate::db::admin_update_report_in_tx(
                &mut tx,
                id,
                admin_id,
                "reviewing",
                "",
                lease.request_id,
            )
            .await
            .unwrap();
        } else {
            crate::db::admin_update_appeal_in_tx(
                &mut tx,
                id,
                admin_id,
                "reviewing",
                "",
                lease.request_id,
            )
            .await
            .unwrap();
        }
        assert!(complete_idempotency_in_tx(
            &keys,
            &mut tx,
            &lease,
            200,
            &headers,
            br#"{"updated":true}"#,
        )
        .await
        .unwrap());
        tx.commit().await.unwrap();
        assert_eq!(
            sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM audit_log WHERE request_id=$1")
                .bind(lease.request_id)
                .fetch_one(&pool)
                .await
                .unwrap(),
            1
        );
        let mut replay_tx = pool.begin().await.unwrap();
        assert!(
            crate::db::authorize_admin_in_tx(&mut replay_tx, admin_id, 0, &admin_session)
                .await
                .unwrap()
        );
        assert!(matches!(
            acquire_idempotency_in_tx(&keys, &mut replay_tx, &mutation)
                .await
                .unwrap(),
            IdempotencyAcquire::Replay(_)
        ));
        replay_tx.commit().await.unwrap();
    }

    // Clear takes the exclusive queue gate. Enqueues already committed
    // are removed; a production enqueue beginning afterwards blocks and
    // then survives the completed clear snapshot.
    assert_eq!(
        crate::db::store_offline(
            &pool,
            reporter_id,
            "sender@example.test",
            "<message><body>before</body></message>",
            false,
            crate::db::OfflineStorePolicy {
                max_messages: 100,
                max_bytes: 1_000_000,
                ttl_days: 30,
                mam_backed: false,
            },
        )
        .await
        .unwrap(),
        crate::db::OfflineStoreOutcome::Stored
    );
    let clear_request = admin_request(
        &admin_id,
        "admin-offline-clear-0001",
        b"offline_messages",
        "DELETE",
        "/api/v1/admin/offline_messages",
        b"",
    );
    let mut clear_tx = pool.begin().await.unwrap();
    assert!(
        crate::db::authorize_admin_in_tx(&mut clear_tx, admin_id, 0, &admin_session)
            .await
            .unwrap()
    );
    let clear_lease = acquired(
        acquire_idempotency_in_tx(&keys, &mut clear_tx, &clear_request)
            .await
            .unwrap(),
    );
    assert_eq!(
        crate::db::clear_offline_messages_in_tx(
            &mut clear_tx,
            admin_id,
            Some(clear_lease.request_id),
        )
        .await
        .unwrap(),
        1
    );
    let enqueue_pool = pool.clone();
    let enqueue = tokio::spawn(async move {
        crate::db::store_offline(
            &enqueue_pool,
            reporter_id,
            "sender@example.test",
            "<message><body>after</body></message>",
            false,
            crate::db::OfflineStorePolicy {
                max_messages: 100,
                max_bytes: 1_000_000,
                ttl_days: 30,
                mam_backed: false,
            },
        )
        .await
    });
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    assert!(!enqueue.is_finished());
    assert!(complete_idempotency_in_tx(
        &keys,
        &mut clear_tx,
        &clear_lease,
        200,
        &headers,
        br#"{"cleared":true,"removed":1}"#,
    )
    .await
    .unwrap());
    clear_tx.commit().await.unwrap();
    assert_eq!(
        enqueue.await.unwrap().unwrap(),
        crate::db::OfflineStoreOutcome::Stored
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM offline_messages")
            .fetch_one(&pool)
            .await
            .unwrap(),
        1
    );
    let mut clear_replay_tx = pool.begin().await.unwrap();
    assert!(
        crate::db::authorize_admin_in_tx(&mut clear_replay_tx, admin_id, 0, &admin_session)
            .await
            .unwrap()
    );
    assert!(matches!(
        acquire_idempotency_in_tx(&keys, &mut clear_replay_tx, &clear_request)
            .await
            .unwrap(),
        IdempotencyAcquire::Replay(_)
    ));
    clear_replay_tx.commit().await.unwrap();
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM offline_messages")
            .fetch_one(&pool)
            .await
            .unwrap(),
        1
    );

    // Demotion after completion denies access before an encrypted replay
    // can be inspected. The idempotency row remains untouched.
    sqlx::query("UPDATE users SET is_admin=FALSE WHERE id=$1")
        .bind(admin_id)
        .execute(&pool)
        .await
        .unwrap();
    let mut denied_tx = pool.begin().await.unwrap();
    assert!(
        !crate::db::authorize_admin_in_tx(&mut denied_tx, admin_id, 0, &admin_session)
            .await
            .unwrap()
    );
    denied_tx.rollback().await.unwrap();
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM audit_log WHERE request_id=$1
             AND action='admin.offline_messages.clear'"
        )
        .bind(clear_lease.request_id)
        .fetch_one(&pool)
        .await
        .unwrap(),
        1
    );

    pool.close().await;
}
