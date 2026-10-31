use super::*;
use sqlx::PgPool;
use std::sync::Arc;
use tokio::sync::Barrier;

include!("../api_operations_idle_tests.rs");

#[test]
fn muc_operation_jids_must_be_canonical_bare_room_keys() {
    assert!(validate_operation_payload(
        "admin.muc_destroy",
        1,
        &json!({
            "room_jid": "room@conference.example.test",
            "alternate_jid": "alternate@conference.example.test"
        }),
    )
    .is_ok());
    assert!(validate_operation_identity_keys(
        "admin.muc_destroy",
        Some("room@conference.example.test"),
        &json!({"room_jid":"room@conference.example.test"}),
    )
    .is_ok());
    assert!(validate_operation_identity_keys(
        "admin.muc_destroy",
        Some("Room@conference.example.test"),
        &json!({"room_jid":"room@conference.example.test"}),
    )
    .is_err());
    for payload in [
        json!({"room_jid":"Room@conference.example.test"}),
        json!({"room_jid":"room@BÜCHER.example"}),
        json!({"room_jid":"room@conference.example.test/Phone"}),
        json!({"room_jid":"conference.example.test"}),
        json!({
            "room_jid":"room@conference.example.test",
            "alternate_jid":"Alternate@conference.example.test"
        }),
        json!({
            "room_jid":"room@conference.example.test",
            "alternate_jid":"alternate@conference.example.test/Phone"
        }),
    ] {
        assert!(validate_operation_payload("admin.muc_destroy", 1, &payload).is_err());
    }
}

fn test_pool_options() -> sqlx::postgres::PgPoolOptions {
    let role = std::env::var("TEST_DATABASE_ROLE").ok();
    let expected_schema = std::env::var("TEST_DATABASE_SCHEMA")
        .expect("set TEST_DATABASE_SCHEMA to the isolated API operation fixture schema");
    assert!(expected_schema
        .strip_prefix("northstar_api_operations_it_")
        .is_some_and(
            |suffix| suffix.len() == 32 && suffix.bytes().all(|byte| byte.is_ascii_hexdigit())
        ));
    sqlx::postgres::PgPoolOptions::new().after_connect(move |connection, _| {
        let role = role.clone();
        let expected_schema = expected_schema.clone();
        Box::pin(async move {
            if let Some(role) = role {
                sqlx::query("SELECT pg_catalog.set_config('role',$1,FALSE)")
                    .bind(role)
                    .execute(&mut *connection)
                    .await?;
            }
            let schema: Option<String> = sqlx::query_scalar("SELECT current_schema()")
                .fetch_one(&mut *connection)
                .await?;
            if schema.as_deref() != Some(expected_schema.as_str()) {
                return Err(sqlx::Error::Protocol(
                    "API operation tests require their random isolated schema on every connection"
                        .into(),
                ));
            }
            Ok(())
        })
    })
}

async fn test_pool() -> PgPool {
    let url = std::env::var("TEST_DATABASE_URL")
        .expect("set TEST_DATABASE_URL to a random isolated PostgreSQL schema");
    let pool = test_pool_options()
        .max_connections(12)
        .connect(&url)
        .await
        .unwrap();
    crate::db::migrate(&pool).await.unwrap();
    // Cases share one isolated schema. Keep audit history immutable under
    // migration 0087; fresh request/operation IDs isolate each assertion.
    sqlx::query("DELETE FROM api_operation_journal")
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("DELETE FROM api_idempotency_records")
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("DELETE FROM users WHERE username LIKE 'operation-%'")
        .execute(&pool)
        .await
        .unwrap();
    pool
}

async fn actor_and_reservation(pool: &PgPool) -> (Uuid, Uuid, Uuid, Uuid) {
    let actor = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO users(id,username,password_hash,is_admin)
             VALUES($1,$2,'test-only',TRUE)",
    )
    .bind(actor)
    .bind(format!("operation-{}", &actor.simple().to_string()[..12]))
    .execute(pool)
    .await
    .unwrap();
    let idempotency = Uuid::new_v4();
    let request = Uuid::new_v4();
    let token = Uuid::new_v4();
    let digest: Vec<u8> = idempotency
        .as_bytes()
        .iter()
        .copied()
        .cycle()
        .take(32)
        .collect();
    sqlx::query(
        "INSERT INTO api_idempotency_records
             (id,scope_hash,principal_hash,scope_key_id,request_actor_id,ownership_actor_id,
              principal_kind,method,route,request_fingerprint,request_id,state,
              lease_token,lease_expires_at,expires_at)
             VALUES($1,$2,$3,'0011223344556677',$4,$4,'admin','POST',
                    '/api/v1/admin/broadcast',$5,$6,'started',$7,
                    clock_timestamp()+INTERVAL '5 minutes',
                    clock_timestamp()+INTERVAL '1 hour')",
    )
    .bind(idempotency)
    .bind(&digest)
    .bind(vec![8_u8; 32])
    .bind(actor)
    .bind(vec![9_u8; 32])
    .bind(request)
    .bind(token)
    .execute(pool)
    .await
    .unwrap();
    (actor, idempotency, request, token)
}

async fn enqueue_broadcast(pool: &PgPool, max_attempts: i32) -> OperationRecord {
    let (actor, idempotency, request, token) = actor_and_reservation(pool).await;
    let mut tx = pool.begin().await.unwrap();
    let operation = enqueue_operation_in_tx(
        &mut tx,
        &EnqueueOperation {
            request_id: request,
            idempotency_id: idempotency,
            idempotency_lease_token: token,
            actor_id: actor,
            actor_auth_generation: 0,
            authorization_policy: AuthorizationPolicy::ReauthorizeUntilEffect,
            kind: "admin.broadcast",
            target: None,
            payload_version: 1,
            payload: &json!({"message":"maintenance"}),
            max_attempts,
            deadline_seconds: 3600,
        },
    )
    .await
    .unwrap();
    tx.commit().await.unwrap();
    operation
}

#[tokio::test]
#[ignore = "requires a random isolated TEST_DATABASE_URL PostgreSQL schema"]
async fn command_port_rolls_back_without_response_and_reauthorizes_replays() {
    use crate::services::operations::OperationAdminService;
    use northstar_auth_core::api_session::ApiReadAuthority;
    use northstar_operations_core::api_mutations::{
        AdminMutationAdmission, ApiMutationOutcome, ApiMutationRejection, ApiPrincipalKind,
        IdempotencyRequest,
    };
    use std::sync::Arc;

    let pool = test_pool().await;
    let operation = enqueue_broadcast(&pool, 4).await;
    let token = crate::db::create_api_session(&pool, operation.actor_subject_id, 1)
        .await
        .unwrap();
    let request_id = Uuid::new_v4();
    let key = Uuid::new_v4().to_string();
    let admission = || AdminMutationAdmission {
        authority: ApiReadAuthority {
            user_id: operation.actor_subject_id,
            auth_generation: operation.actor_auth_generation,
            session_token: &token,
        },
        idempotency: IdempotencyRequest {
            request_id,
            actor_id: Some(operation.actor_subject_id),
            principal_scope: operation.actor_subject_id.as_bytes(),
            capacity_scope: operation.actor_subject_id.as_bytes(),
            target_scope: operation.id.as_bytes(),
            principal_kind: ApiPrincipalKind::Admin,
            method: "POST",
            route: "/api/v1/admin/operations/{id}/cancel",
            idempotency_key: &key,
            request_fingerprint: crate::db::api_request_fingerprint("", b""),
            ttl_seconds: 3600,
            lease_seconds: 30,
        },
    };
    let cluster =
        crate::cluster::ClusterManager::new(None, "operation-ports.test", None, None, None, None)
            .await
            .unwrap();
    let key_material = Uuid::new_v4().simple().to_string();
    let service = OperationAdminService::new(
        crate::db::operation_admin_repository::PostgresOperationAdminRepository::new(
            crate::db::admin_mutations::AdminMutationStore::new(
                pool.clone(),
                Arc::new(crate::db::ApiControlKeyring::new(key_material.as_bytes(), None).unwrap()),
                cluster.admission(),
            ),
        ),
    );
    // A response-storage failure must roll back both cancellation and its audit entry.
    sqlx::raw_sql(
        "CREATE FUNCTION reject_operation_test_response() RETURNS trigger LANGUAGE plpgsql AS $$
            BEGIN
                IF NEW.route='/api/v1/admin/operations/{id}/cancel' AND NEW.state='completed' THEN
                    RAISE EXCEPTION 'injected operation response failure';
                END IF;
                RETURN NEW;
            END $$;
            CREATE TRIGGER reject_operation_test_response BEFORE UPDATE ON api_idempotency_records
            FOR EACH ROW EXECUTE FUNCTION reject_operation_test_response();",
    )
    .execute(&pool)
    .await
    .unwrap();
    assert!(service.cancel(admission(), operation.id).await.is_err());
    assert_eq!(
        sqlx::query_scalar::<_, String>("SELECT status FROM api_operation_journal WHERE id=$1")
            .bind(operation.id)
            .fetch_one(&pool)
            .await
            .unwrap(),
        "pending"
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM audit_log WHERE request_id=$1")
            .bind(request_id)
            .fetch_one(&pool)
            .await
            .unwrap(),
        0
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM api_idempotency_records WHERE request_id=$1"
        )
        .bind(request_id)
        .fetch_one(&pool)
        .await
        .unwrap(),
        0
    );
    sqlx::raw_sql(
        "DROP TRIGGER reject_operation_test_response ON api_idempotency_records;
            DROP FUNCTION reject_operation_test_response();",
    )
    .execute(&pool)
    .await
    .unwrap();

    let ApiMutationOutcome::Committed(first) =
        service.cancel(admission(), operation.id).await.unwrap()
    else {
        panic!("cancellation did not commit after response storage recovered");
    };
    assert_eq!(first.status, 200);
    assert_eq!(
        serde_json::from_slice::<Value>(&first.body).unwrap(),
        json!({"outcome":"canceled"})
    );
    let ApiMutationOutcome::Replay(replay) =
        service.cancel(admission(), operation.id).await.unwrap()
    else {
        panic!("cancellation did not replay");
    };
    assert_eq!(replay.request_id, request_id);
    assert_eq!(replay.status, first.status);
    assert_eq!(replay.headers, first.headers);
    assert_eq!(replay.body, first.body);

    sqlx::query("UPDATE users SET is_admin=FALSE WHERE id=$1")
        .bind(operation.actor_subject_id)
        .execute(&pool)
        .await
        .unwrap();
    assert!(matches!(
        service.cancel(admission(), operation.id).await.unwrap(),
        ApiMutationOutcome::Rejected(ApiMutationRejection::Forbidden)
    ));
    sqlx::query("UPDATE users SET is_admin=TRUE WHERE id=$1")
        .bind(operation.actor_subject_id)
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("DELETE FROM api_sessions WHERE user_id=$1")
        .bind(operation.actor_subject_id)
        .execute(&pool)
        .await
        .unwrap();
    assert!(matches!(
        service.cancel(admission(), operation.id).await.unwrap(),
        ApiMutationOutcome::Rejected(ApiMutationRejection::Forbidden)
    ));
    pool.close().await;
}

#[tokio::test]
#[ignore = "requires a random isolated TEST_DATABASE_URL PostgreSQL schema"]
async fn query_ports_preserve_target_scope_and_authorization_denials() {
    use crate::services::api_queries::{ApiQueryService, ApiReadDenial};
    use northstar_auth_core::api_session::ApiReadAuthority;

    let pool = test_pool().await;
    let operation = enqueue_broadcast(&pool, 4).await;
    let token = crate::db::create_api_session(&pool, operation.actor_subject_id, 1)
        .await
        .unwrap();
    let principal = crate::db::user_for_token(&pool, &token)
        .await
        .unwrap()
        .unwrap();
    let actor = || ApiReadAuthority {
        user_id: principal.id,
        auth_generation: principal.auth_generation,
        session_token: &token,
    };
    let mut setup = pool.begin().await.unwrap();
    let parent = claim_operation_in_tx(&mut setup, Uuid::new_v4(), 120)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(parent.operation.id, operation.id);
    let target = enqueue_operation_target_in_tx(
        &mut setup,
        &EnqueueOperationTarget {
            operation_id: operation.id,
            target_key: "test-target",
            ordinal: 0,
            payload: &json!({}),
            max_attempts: 3,
            deadline_seconds: 3600,
        },
    )
    .await
    .unwrap();
    setup.commit().await.unwrap();

    let service = ApiQueryService::new(crate::db::api_queries::PostgresApiQueryRepository::new(
        pool.clone(),
    ));
    let page = service
        .operations(actor(), Some("running"), Some("admin.broadcast"), None, 25)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(page.items.len(), 1);
    assert_eq!(page.items[0].id, operation.id);
    assert_eq!(
        service
            .operation(actor(), operation.id)
            .await
            .unwrap()
            .unwrap()
            .unwrap()
            .id,
        operation.id
    );
    let targets = service
        .operation_targets(actor(), operation.id, None, None, 25)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(targets.items.len(), 1);
    assert_eq!(targets.items[0].id, target.id);
    assert_eq!(
        service
            .operation_target(actor(), operation.id, target.id)
            .await
            .unwrap()
            .unwrap()
            .unwrap()
            .id,
        target.id
    );
    let absent = Uuid::new_v4();
    assert!(service
        .operation_target(actor(), absent, target.id)
        .await
        .unwrap()
        .unwrap()
        .is_none());
    assert!(service
        .operation_targets(actor(), absent, None, None, 25)
        .await
        .unwrap()
        .unwrap()
        .is_none());

    sqlx::query("UPDATE users SET is_admin=FALSE WHERE id=$1")
        .bind(principal.id)
        .execute(&pool)
        .await
        .unwrap();
    assert_eq!(
        service
            .operations(actor(), None, None, None, 25)
            .await
            .unwrap()
            .unwrap_err(),
        ApiReadDenial::Forbidden
    );
    assert_eq!(
        service
            .operation_target(actor(), operation.id, target.id)
            .await
            .unwrap()
            .unwrap_err(),
        ApiReadDenial::Forbidden
    );
    sqlx::query("DELETE FROM api_sessions WHERE user_id=$1")
        .bind(principal.id)
        .execute(&pool)
        .await
        .unwrap();
    assert_eq!(
        service
            .operation(actor(), operation.id)
            .await
            .unwrap()
            .unwrap_err(),
        ApiReadDenial::Unauthorized
    );
    assert_eq!(
        service
            .operation_targets(actor(), operation.id, None, None, 25)
            .await
            .unwrap()
            .unwrap_err(),
        ApiReadDenial::Unauthorized
    );
    pool.close().await;
}

#[tokio::test]
#[ignore = "requires a random isolated TEST_DATABASE_URL PostgreSQL schema"]
async fn two_workers_crash_reclaim_and_stale_fencing_are_exact() {
    let pool = test_pool().await;
    let operation = enqueue_broadcast(&pool, 4).await;
    let queued_snapshot = api_operation_snapshot(&pool).await.unwrap();
    assert_eq!(queued_snapshot.pending, 1);
    assert_eq!(queued_snapshot.running, 0);
    assert_eq!(queued_snapshot.indeterminate, 0);
    assert!(queued_snapshot.oldest_active_age_seconds >= 0.0);
    let barrier = Arc::new(Barrier::new(3));
    let mut tasks = Vec::new();
    for _ in 0..2 {
        let pool = pool.clone();
        let barrier = Arc::clone(&barrier);
        tasks.push(tokio::spawn(async move {
            let mut tx = pool.begin().await.unwrap();
            barrier.wait().await;
            let claim = claim_operation_in_tx(&mut tx, Uuid::new_v4(), 30)
                .await
                .unwrap();
            tx.commit().await.unwrap();
            claim
        }));
    }
    barrier.wait().await;
    let claims = [
        tasks.remove(0).await.unwrap(),
        tasks.remove(0).await.unwrap(),
    ];
    assert_eq!(claims.iter().filter(|claim| claim.is_some()).count(), 1);
    let stale = claims.into_iter().flatten().next().unwrap();
    assert_eq!(stale.operation.id, operation.id);

    sqlx::query(
        "UPDATE api_operation_journal SET lease_expires_at=clock_timestamp()-INTERVAL '1 second'
             WHERE id=$1",
    )
    .bind(operation.id)
    .execute(&pool)
    .await
    .unwrap();
    let mut tx = pool.begin().await.unwrap();
    let recovered = claim_operation_in_tx(&mut tx, Uuid::new_v4(), 30)
        .await
        .unwrap()
        .unwrap();
    tx.commit().await.unwrap();

    let mut stale_tx = pool.begin().await.unwrap();
    assert!(
        !succeed_operation_in_tx(&mut stale_tx, &stale, &json!({"sent":1}))
            .await
            .unwrap()
    );
    stale_tx.rollback().await.unwrap();
    let mut recovered_tx = pool.begin().await.unwrap();
    assert!(
        mark_operation_point_of_no_return_in_tx(&mut recovered_tx, &recovered)
            .await
            .unwrap()
    );
    assert!(
        succeed_operation_in_tx(&mut recovered_tx, &recovered, &json!({"sent":1}))
            .await
            .unwrap()
    );
    recovered_tx.commit().await.unwrap();
    assert_eq!(
        api_operation_snapshot(&pool).await.unwrap(),
        ApiOperationSnapshot::default()
    );
    pool.close().await;
}

#[tokio::test]
#[ignore = "requires a random isolated TEST_DATABASE_URL PostgreSQL schema"]
async fn cancellation_pnr_targets_and_idempotency_retention_are_strict() {
    let pool = test_pool().await;
    let canceled = enqueue_broadcast(&pool, 4).await;
    let actor = canceled.actor_subject_id;
    let idempotency = canceled.idempotency_id.unwrap();
    let cancel_request_id = Uuid::new_v4();
    let mut cancel_tx = pool.begin().await.unwrap();
    assert_eq!(
        request_operation_cancel_in_tx(&mut cancel_tx, canceled.id, actor, cancel_request_id,)
            .await
            .unwrap(),
        CancelOutcome::Canceled
    );
    cancel_tx.commit().await.unwrap();
    let cancel_audit = sqlx::query(
        "SELECT actor_id,request_id,details FROM audit_log
             WHERE operation_id=$1 AND details->>'phase'='canceled'
             ORDER BY id DESC LIMIT 1",
    )
    .bind(canceled.id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(cancel_audit.get::<Uuid, _>("actor_id"), actor);
    assert_eq!(cancel_audit.get::<Uuid, _>("request_id"), cancel_request_id);
    assert_eq!(
        cancel_audit
            .get::<Value, _>("details")
            .pointer("/details/original_operation_request_id")
            .and_then(Value::as_str)
            .map(str::to_owned),
        Some(canceled.request_id.to_string())
    );

    let running = enqueue_broadcast(&pool, 4).await;
    let mut claim_tx = pool.begin().await.unwrap();
    let lease = claim_operation_in_tx(&mut claim_tx, Uuid::new_v4(), 30)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(lease.operation.id, running.id);
    enqueue_operation_target_in_tx(
        &mut claim_tx,
        &EnqueueOperationTarget {
            operation_id: running.id,
            target_key: "alice@example.test/Phone#connection-1",
            ordinal: 0,
            payload: &json!({}),
            max_attempts: 3,
            deadline_seconds: 3600,
        },
    )
    .await
    .unwrap();
    assert!(
        mark_operation_point_of_no_return_in_tx(&mut claim_tx, &lease)
            .await
            .unwrap()
    );
    assert_eq!(
        request_operation_cancel_in_tx(&mut claim_tx, running.id, actor, Uuid::new_v4())
            .await
            .unwrap(),
        CancelOutcome::PastPointOfNoReturn
    );
    claim_tx.commit().await.unwrap();

    // A nonterminal operation suppresses idempotency cleanup. Once its
    // canceled peer is terminal, the completed association may detach.
    sqlx::query("DELETE FROM api_idempotency_records WHERE id=$1")
        .bind(running.idempotency_id.unwrap())
        .execute(&pool)
        .await
        .unwrap();
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM api_idempotency_records WHERE id=$1")
            .bind(running.idempotency_id.unwrap())
            .fetch_one(&pool)
            .await
            .unwrap(),
        1
    );
    sqlx::query("DELETE FROM api_idempotency_records WHERE id=$1")
        .bind(idempotency)
        .execute(&pool)
        .await
        .unwrap();
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM api_idempotency_records WHERE id=$1")
            .bind(idempotency)
            .fetch_one(&pool)
            .await
            .unwrap(),
        0
    );
    pool.close().await;
}

#[tokio::test]
#[ignore = "requires a random isolated TEST_DATABASE_URL PostgreSQL schema"]
async fn retry_budget_deadline_and_transaction_rollback_are_durable() {
    let pool = test_pool().await;
    let operation = enqueue_broadcast(&pool, 1).await;
    let mut claim_tx = pool.begin().await.unwrap();
    let lease = claim_operation_in_tx(&mut claim_tx, Uuid::new_v4(), 30)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(lease.operation.id, operation.id);
    assert_eq!(
        retry_operation_in_tx(&mut claim_tx, &lease, "redis_unavailable")
            .await
            .unwrap(),
        RetryOutcome::Failed
    );
    claim_tx.commit().await.unwrap();

    let (actor, idempotency, request, token) = actor_and_reservation(&pool).await;
    let rolled_back_id = {
        let mut tx = pool.begin().await.unwrap();
        let op = enqueue_operation_in_tx(
            &mut tx,
            &EnqueueOperation {
                request_id: request,
                idempotency_id: idempotency,
                idempotency_lease_token: token,
                actor_id: actor,
                actor_auth_generation: 0,
                authorization_policy: AuthorizationPolicy::CommittedConsequence,
                kind: "admin.user_session_cleanup",
                target: Some("user-generation-2"),
                payload_version: 1,
                payload: &json!({"user_id":Uuid::new_v4(),"auth_generation":2}),
                max_attempts: 5,
                deadline_seconds: 3600,
            },
        )
        .await
        .unwrap();
        tx.rollback().await.unwrap();
        op.id
    };
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM api_operation_journal WHERE id=$1")
            .bind(rolled_back_id)
            .fetch_one(&pool)
            .await
            .unwrap(),
        0
    );
    pool.close().await;
}

#[tokio::test]
#[ignore = "requires a random isolated TEST_DATABASE_URL PostgreSQL schema"]
async fn authorization_policy_and_database_payload_schema_are_enforced() {
    let pool = test_pool().await;
    let revoked = enqueue_broadcast(&pool, 3).await;
    sqlx::query("UPDATE users SET auth_generation=auth_generation+1 WHERE id=$1")
        .bind(revoked.actor_subject_id)
        .execute(&pool)
        .await
        .unwrap();
    let mut revoked_tx = pool.begin().await.unwrap();
    assert!(claim_operation_in_tx(&mut revoked_tx, Uuid::new_v4(), 30)
        .await
        .unwrap()
        .is_none());
    revoked_tx.commit().await.unwrap();
    assert_eq!(
        sqlx::query_scalar::<_, String>("SELECT status FROM api_operation_journal WHERE id=$1")
            .bind(revoked.id)
            .fetch_one(&pool)
            .await
            .unwrap(),
        "failed"
    );

    let (actor, idempotency, request, token) = actor_and_reservation(&pool).await;
    let user_id = Uuid::new_v4();
    let mut tx = pool.begin().await.unwrap();
    let committed = enqueue_operation_in_tx(
        &mut tx,
        &EnqueueOperation {
            request_id: request,
            idempotency_id: idempotency,
            idempotency_lease_token: token,
            actor_id: actor,
            actor_auth_generation: 0,
            authorization_policy: AuthorizationPolicy::CommittedConsequence,
            kind: "admin.user_session_cleanup",
            target: Some("user-generation-0"),
            payload_version: 1,
            payload: &json!({"user_id":user_id,"auth_generation":0}),
            max_attempts: 3,
            deadline_seconds: 3600,
        },
    )
    .await
    .unwrap();
    tx.commit().await.unwrap();
    sqlx::query("UPDATE users SET auth_generation=auth_generation+1 WHERE id=$1")
        .bind(actor)
        .execute(&pool)
        .await
        .unwrap();
    let mut claim_tx = pool.begin().await.unwrap();
    let committed_lease = claim_operation_in_tx(&mut claim_tx, Uuid::new_v4(), 30)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(committed_lease.operation.id, committed.id);
    assert!(
        mark_operation_point_of_no_return_in_tx(&mut claim_tx, &committed_lease)
            .await
            .unwrap()
    );
    assert!(
        succeed_operation_in_tx(&mut claim_tx, &committed_lease, &json!({"cleaned":true}))
            .await
            .unwrap()
    );
    claim_tx.commit().await.unwrap();

    let forbidden = sqlx::query(
        "UPDATE api_operation_journal
             SET payload=jsonb_build_object('message','safe','bearer_token','credential')
             WHERE id=$1",
    )
    .bind(committed.id)
    .execute(&pool)
    .await;
    assert!(forbidden.is_err());
    for key in [
        "password",
        "passwd",
        "passphrase",
        "secret",
        "private-key",
        "api_key",
        "apikey",
        "access-token",
        "refresh_token",
        "session-token",
        "client_secret",
        "bearer-token",
        "token",
        "authorization",
        "cookie",
        "set-cookie",
    ] {
        assert!(
            sqlx::query_scalar::<_, bool>(
                "SELECT api_json_contains_secret_key(jsonb_build_object($1,'credential'))",
            )
            .bind(key)
            .fetch_one(&pool)
            .await
            .unwrap(),
            "database credential guard did not reject {key}"
        );
    }
    assert!(!sqlx::query_scalar::<_, bool>(
        "SELECT api_json_contains_secret_key(
                    jsonb_build_object('nested',jsonb_build_array(
                        jsonb_build_object('message','safe')
                    ))
                 )",
    )
    .fetch_one(&pool)
    .await
    .unwrap());
    for safe_key in ["apiXkey", "privateXkey", "accessXtoken"] {
        assert!(
            !sqlx::query_scalar::<_, bool>(
                "SELECT api_json_contains_secret_key(jsonb_build_object($1,'safe'))",
            )
            .bind(safe_key)
            .fetch_one(&pool)
            .await
            .unwrap(),
            "database credential guard overmatched {safe_key}"
        );
    }

    let revoked_after_claim = enqueue_broadcast(&pool, 3).await;
    let mut claim = pool.begin().await.unwrap();
    let revoked_lease = claim_operation_in_tx(&mut claim, Uuid::new_v4(), 30)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(revoked_lease.operation.id, revoked_after_claim.id);
    claim.commit().await.unwrap();
    sqlx::query("UPDATE users SET auth_generation=auth_generation+1 WHERE id=$1")
        .bind(revoked_after_claim.actor_subject_id)
        .execute(&pool)
        .await
        .unwrap();
    let mut effect = pool.begin().await.unwrap();
    assert!(
        !mark_operation_point_of_no_return_in_tx(&mut effect, &revoked_lease)
            .await
            .unwrap()
    );
    effect.rollback().await.unwrap();
    sqlx::query(
        "UPDATE api_operation_journal
             SET lease_expires_at=clock_timestamp()-INTERVAL '1 millisecond' WHERE id=$1",
    )
    .bind(revoked_after_claim.id)
    .execute(&pool)
    .await
    .unwrap();
    let mut reject = pool.begin().await.unwrap();
    assert!(claim_operation_in_tx(&mut reject, Uuid::new_v4(), 30)
        .await
        .unwrap()
        .is_none());
    reject.commit().await.unwrap();
    assert_eq!(
        sqlx::query_scalar::<_, String>("SELECT status FROM api_operation_journal WHERE id=$1")
            .bind(revoked_after_claim.id)
            .fetch_one(&pool)
            .await
            .unwrap(),
        "failed"
    );

    let (actor, idempotency, request, token) = actor_and_reservation(&pool).await;
    let mut mismatch_tx = pool.begin().await.unwrap();
    assert!(enqueue_operation_in_tx(
        &mut mismatch_tx,
        &EnqueueOperation {
            request_id: request,
            idempotency_id: idempotency,
            idempotency_lease_token: token,
            actor_id: actor,
            actor_auth_generation: 0,
            authorization_policy: AuthorizationPolicy::CommittedConsequence,
            kind: "admin.broadcast",
            target: None,
            payload_version: 1,
            payload: &json!({"message":"must reauthorize"}),
            max_attempts: 3,
            deadline_seconds: 3600,
        },
    )
    .await
    .is_err());
    mismatch_tx.rollback().await.unwrap();
    pool.close().await;
}

#[tokio::test]
#[ignore = "requires a random isolated TEST_DATABASE_URL PostgreSQL schema"]
async fn fanout_cancel_propagates_and_last_target_ack_terminalizes_parent() {
    let pool = test_pool().await;
    let operation = enqueue_broadcast(&pool, 4).await;
    let mut setup = pool.begin().await.unwrap();
    let _parent = claim_operation_in_tx(&mut setup, Uuid::new_v4(), 120)
        .await
        .unwrap()
        .unwrap();
    for ordinal in 0..2 {
        enqueue_operation_target_in_tx(
            &mut setup,
            &EnqueueOperationTarget {
                operation_id: operation.id,
                target_key: &format!("connection-{ordinal}"),
                ordinal,
                payload: &json!({}),
                max_attempts: 3,
                deadline_seconds: 3600,
            },
        )
        .await
        .unwrap();
    }
    setup.commit().await.unwrap();

    let mut target_leases = Vec::new();
    for _ in 0..2 {
        let mut tx = pool.begin().await.unwrap();
        target_leases.push(
            claim_operation_target_in_tx(&mut tx, operation.id, Uuid::new_v4(), 120)
                .await
                .unwrap()
                .unwrap(),
        );
        tx.commit().await.unwrap();
    }
    let mut cancel = pool.begin().await.unwrap();
    assert_eq!(
        request_operation_cancel_in_tx(
            &mut cancel,
            operation.id,
            operation.actor_subject_id,
            Uuid::new_v4(),
        )
        .await
        .unwrap(),
        CancelOutcome::Requested
    );
    cancel.commit().await.unwrap();

    let mut first = pool.begin().await.unwrap();
    assert!(
        acknowledge_operation_target_cancel_in_tx(&mut first, &target_leases[0])
            .await
            .unwrap()
    );
    first.commit().await.unwrap();
    assert_eq!(
        sqlx::query_scalar::<_, String>("SELECT status FROM api_operation_journal WHERE id=$1")
            .bind(operation.id)
            .fetch_one(&pool)
            .await
            .unwrap(),
        "running"
    );
    let mut second = pool.begin().await.unwrap();
    assert!(
        acknowledge_operation_target_cancel_in_tx(&mut second, &target_leases[1])
            .await
            .unwrap()
    );
    second.commit().await.unwrap();
    assert_eq!(
        sqlx::query_scalar::<_, String>("SELECT status FROM api_operation_journal WHERE id=$1")
            .bind(operation.id)
            .fetch_one(&pool)
            .await
            .unwrap(),
        "canceled"
    );
    pool.close().await;
}

#[tokio::test]
#[ignore = "requires a random isolated TEST_DATABASE_URL PostgreSQL schema"]
async fn post_pnr_crash_is_indeterminate_until_manual_reconciliation() {
    let pool = test_pool().await;
    let operation = enqueue_broadcast(&pool, 4).await;
    let mut claim = pool.begin().await.unwrap();
    let stale = claim_operation_in_tx(&mut claim, Uuid::new_v4(), 30)
        .await
        .unwrap()
        .unwrap();
    assert!(mark_operation_point_of_no_return_in_tx(&mut claim, &stale)
        .await
        .unwrap());
    claim.commit().await.unwrap();
    sqlx::query(
        "UPDATE api_operation_journal
             SET lease_expires_at=clock_timestamp()-INTERVAL '1 millisecond' WHERE id=$1",
    )
    .bind(operation.id)
    .execute(&pool)
    .await
    .unwrap();
    let mut recovery = pool.begin().await.unwrap();
    assert!(claim_operation_in_tx(&mut recovery, Uuid::new_v4(), 30)
        .await
        .unwrap()
        .is_none());
    recovery.commit().await.unwrap();
    assert_eq!(
        sqlx::query_scalar::<_, String>("SELECT status FROM api_operation_journal WHERE id=$1")
            .bind(operation.id)
            .fetch_one(&pool)
            .await
            .unwrap(),
        "indeterminate"
    );
    let mut stale_tx = pool.begin().await.unwrap();
    assert!(
        !succeed_operation_in_tx(&mut stale_tx, &stale, &json!({"sent":1}))
            .await
            .unwrap()
    );
    stale_tx.rollback().await.unwrap();

    let reconciliation_request_id = Uuid::new_v4();
    let mut reconcile = pool.begin().await.unwrap();
    assert_eq!(
        reconcile_indeterminate_operation_in_tx(
            &mut reconcile,
            operation.id,
            &ManualReconciliation {
                reconciled_by: operation.actor_subject_id,
                reconciler_auth_generation: operation.actor_auth_generation,
                request_id: reconciliation_request_id,
                succeeded: false,
                result: None,
                error_code: Some("operator_confirmed_not_applied"),
                evidence_note: "Checked the external delivery ledger; no effect was applied.",
            },
        )
        .await
        .unwrap(),
        ManualReconcileOutcome::Failed
    );
    reconcile.commit().await.unwrap();
    let audit = sqlx::query(
        "SELECT actor_id,request_id,details FROM audit_log
             WHERE operation_id=$1 AND details->>'phase'='manually_reconciled'
             ORDER BY id DESC LIMIT 1",
    )
    .bind(operation.id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(audit.get::<Uuid, _>("actor_id"), operation.actor_subject_id);
    assert_eq!(
        audit.get::<Uuid, _>("request_id"),
        reconciliation_request_id
    );
    assert_eq!(
        audit
            .get::<Value, _>("details")
            .pointer("/details/original_operation_request_id")
            .and_then(Value::as_str)
            .map(str::to_owned),
        Some(operation.request_id.to_string())
    );
    pool.close().await;
}

#[tokio::test]
#[ignore = "requires a random isolated TEST_DATABASE_URL PostgreSQL schema"]
async fn post_pnr_effect_error_is_immediately_indeterminate() {
    let pool = test_pool().await;
    let operation = enqueue_broadcast(&pool, 4).await;
    let worker_id = Uuid::new_v4();
    let mut setup = pool.begin().await.unwrap();
    let parent = claim_operation_in_tx(&mut setup, worker_id, 120)
        .await
        .unwrap()
        .unwrap();
    for ordinal in 0..2 {
        enqueue_operation_target_in_tx(
            &mut setup,
            &EnqueueOperationTarget {
                operation_id: operation.id,
                target_key: &format!("recipient-{ordinal}"),
                ordinal,
                payload: &json!({"ordinal":ordinal}),
                max_attempts: 3,
                deadline_seconds: 3600,
            },
        )
        .await
        .unwrap();
    }
    setup.commit().await.unwrap();

    let mut claim = pool.begin().await.unwrap();
    let target = claim_operation_target_in_tx(&mut claim, operation.id, worker_id, 60)
        .await
        .unwrap()
        .unwrap();
    assert!(
        mark_operation_target_point_of_no_return_in_tx(&mut claim, &target)
            .await
            .unwrap()
    );
    claim.commit().await.unwrap();

    let details = json!({"message":"the executor lost its acknowledgement"});
    let mut finish = pool.begin().await.unwrap();
    assert!(mark_operation_target_indeterminate_in_tx(
        &mut finish,
        &parent,
        &target,
        "effect_outcome_unprovable",
        Some(&details),
    )
    .await
    .unwrap());
    finish.commit().await.unwrap();

    let mut read_parent = pool.begin().await.unwrap();
    let parent = operation_by_id(&mut read_parent, operation.id)
        .await
        .unwrap()
        .unwrap();
    read_parent.rollback().await.unwrap();
    assert_eq!(parent.status, OperationStatus::Indeterminate);
    assert_eq!(
        parent.error_code.as_deref(),
        Some("effect_outcome_unprovable")
    );
    assert!(parent.point_of_no_return_at.is_some());
    assert_eq!(parent.result, Some(details));
    let statuses = sqlx::query_as::<_, (String, Option<String>)>(
        "SELECT status,error_code FROM api_operation_targets
             WHERE operation_id=$1 ORDER BY ordinal",
    )
    .bind(operation.id)
    .fetch_all(&pool)
    .await
    .unwrap();
    assert_eq!(
        statuses,
        vec![
            (
                "indeterminate".to_owned(),
                Some("effect_outcome_unprovable".to_owned()),
            ),
            (
                "failed".to_owned(),
                Some("parent_outcome_indeterminate".to_owned()),
            ),
        ]
    );
    assert_eq!(
        api_operation_snapshot(&pool).await.unwrap(),
        ApiOperationSnapshot {
            indeterminate: 1,
            ..ApiOperationSnapshot::default()
        }
    );
    let audit_phase: String = sqlx::query_scalar(
        "SELECT details->>'phase' FROM audit_log
             WHERE operation_id=$1 ORDER BY id DESC LIMIT 1",
    )
    .bind(operation.id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(audit_phase, "indeterminate");
    pool.close().await;
}

#[tokio::test]
#[ignore = "requires a random isolated TEST_DATABASE_URL PostgreSQL schema"]
async fn target_pnr_crash_and_database_deadline_are_closed() {
    let pool = test_pool().await;
    let operation = enqueue_broadcast(&pool, 4).await;
    let mut setup = pool.begin().await.unwrap();
    let _parent = claim_operation_in_tx(&mut setup, Uuid::new_v4(), 120)
        .await
        .unwrap()
        .unwrap();
    enqueue_operation_target_in_tx(
        &mut setup,
        &EnqueueOperationTarget {
            operation_id: operation.id,
            target_key: "recipient-0",
            ordinal: 0,
            payload: &json!({}),
            max_attempts: 3,
            deadline_seconds: 3600,
        },
    )
    .await
    .unwrap();
    setup.commit().await.unwrap();
    let mut claim = pool.begin().await.unwrap();
    let target = claim_operation_target_in_tx(&mut claim, operation.id, Uuid::new_v4(), 30)
        .await
        .unwrap()
        .unwrap();
    assert!(
        mark_operation_target_point_of_no_return_in_tx(&mut claim, &target)
            .await
            .unwrap()
    );
    claim.commit().await.unwrap();
    sqlx::query(
        "UPDATE api_operation_targets
             SET lease_expires_at=clock_timestamp()-INTERVAL '1 millisecond' WHERE id=$1",
    )
    .bind(target.target.id)
    .execute(&pool)
    .await
    .unwrap();
    let mut maintenance = pool.begin().await.unwrap();
    assert!(
        claim_operation_target_in_tx(&mut maintenance, operation.id, Uuid::new_v4(), 30)
            .await
            .unwrap()
            .is_none()
    );
    maintenance.commit().await.unwrap();
    assert_eq!(
        sqlx::query_scalar::<_, String>("SELECT status FROM api_operation_targets WHERE id=$1")
            .bind(target.target.id)
            .fetch_one(&pool)
            .await
            .unwrap(),
        "indeterminate"
    );
    assert_eq!(
        sqlx::query_scalar::<_, String>("SELECT status FROM api_operation_journal WHERE id=$1")
            .bind(operation.id)
            .fetch_one(&pool)
            .await
            .unwrap(),
        "indeterminate"
    );

    let target_reconciliation_request_id = Uuid::new_v4();
    let mut reconcile = pool.begin().await.unwrap();
    let target_result = json!({"confirmed":"delivered"});
    assert_eq!(
        reconcile_indeterminate_target_in_tx(
            &mut reconcile,
            target.target.id,
            &ManualReconciliation {
                reconciled_by: operation.actor_subject_id,
                reconciler_auth_generation: operation.actor_auth_generation,
                request_id: target_reconciliation_request_id,
                succeeded: true,
                result: Some(&target_result),
                error_code: None,
                evidence_note: "Confirmed the recipient ledger contains exactly one delivery.",
            },
        )
        .await
        .unwrap(),
        ManualReconcileOutcome::Succeeded
    );
    let operation_result = json!({"confirmed_targets":1});
    assert_eq!(
        reconcile_indeterminate_operation_in_tx(
            &mut reconcile,
            operation.id,
            &ManualReconciliation {
                reconciled_by: operation.actor_subject_id,
                reconciler_auth_generation: operation.actor_auth_generation,
                request_id: Uuid::new_v4(),
                succeeded: true,
                result: Some(&operation_result),
                error_code: None,
                evidence_note: "All recipient outcomes were checked against the delivery ledger.",
            },
        )
        .await
        .unwrap(),
        ManualReconcileOutcome::Succeeded
    );
    reconcile.commit().await.unwrap();
    let target_audit = sqlx::query(
        "SELECT request_id,details FROM audit_log
             WHERE operation_id=$1 AND action='api.operation.target_reconciled'
             ORDER BY id DESC LIMIT 1",
    )
    .bind(operation.id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(
        target_audit.get::<Uuid, _>("request_id"),
        target_reconciliation_request_id
    );
    assert_eq!(
        target_audit
            .get::<Value, _>("details")
            .get("original_operation_request_id")
            .and_then(Value::as_str)
            .map(str::to_owned),
        Some(operation.request_id.to_string())
    );

    let (actor, idempotency, request, token) = actor_and_reservation(&pool).await;
    let mut enqueue = pool.begin().await.unwrap();
    let expired = enqueue_operation_in_tx(
        &mut enqueue,
        &EnqueueOperation {
            request_id: request,
            idempotency_id: idempotency,
            idempotency_lease_token: token,
            actor_id: actor,
            actor_auth_generation: 0,
            authorization_policy: AuthorizationPolicy::ReauthorizeUntilEffect,
            kind: "admin.broadcast",
            target: None,
            payload_version: 1,
            payload: &json!({"message":"short deadline"}),
            max_attempts: 4,
            deadline_seconds: 1,
        },
    )
    .await
    .unwrap();
    enqueue.commit().await.unwrap();
    sqlx::query("SELECT pg_sleep(1.05)")
        .execute(&pool)
        .await
        .unwrap();
    let mut deadline = pool.begin().await.unwrap();
    assert!(claim_operation_in_tx(&mut deadline, Uuid::new_v4(), 30)
        .await
        .unwrap()
        .is_none());
    deadline.commit().await.unwrap();
    assert_eq!(
        sqlx::query_scalar::<_, String>("SELECT status FROM api_operation_journal WHERE id=$1")
            .bind(expired.id)
            .fetch_one(&pool)
            .await
            .unwrap(),
        "failed"
    );
    pool.close().await;
}
