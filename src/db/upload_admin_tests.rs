//! PostgreSQL contracts of the upload dead-letter retry: replay, fencing and authorization through the
//! root crate's idempotency store and API sessions.

use axum::body::to_bytes;
use axum::http::StatusCode;
use chrono::{DateTime, Utc};
use northstar_upload_application::admin::{UploadDeadLetterId, UploadDeadLetterKind};
use northstar_upload_postgres::admin::{
    retry_upload_dead_letter_in_tx, upload_dead_letters_page_in_tx, RetryUploadDeadLetter,
};
use sqlx::PgPool;
use std::collections::HashSet;
use std::sync::Arc;
use tokio::sync::Barrier;
use uuid::Uuid;

async fn insert_user(pool: &PgPool, admin: bool) -> (Uuid, String) {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO users(id,username,password_hash,is_admin)
         VALUES($1,$2,'test-only',$3)",
    )
    .bind(id)
    .bind(format!("dead-letter-{}", id.simple()))
    .bind(admin)
    .execute(pool)
    .await
    .unwrap();
    let token = northstar_auth_postgres::users::create_api_session(pool, id, 1)
        .await
        .unwrap();
    (id, token)
}

async fn insert_storage_dead_letter(pool: &PgPool, claim_expires_at: Option<DateTime<Utc>>) -> i64 {
    let object_id = Uuid::new_v4();
    sqlx::query_scalar(
        "INSERT INTO upload_storage_jobs(
             object_id,storage_attempt,action,storage_backend,object_key,
             expected_size,storage_fence,attempts,dead_lettered_at,last_error,
             claim_token,claim_expires_at)
         VALUES($1,$2,'delete_object','local',$1::text,1,0,12,
                clock_timestamp(),'fixture failure',$3,$4)
         RETURNING id",
    )
    .bind(object_id)
    .bind(Uuid::new_v4())
    .bind(claim_expires_at.map(|_| Uuid::new_v4()))
    .bind(claim_expires_at)
    .fetch_one(pool)
    .await
    .unwrap()
}

fn retry_idempotency_request<'a>(
    actor_id: Uuid,
    actor_scope: &'a [u8],
    target_scope: &'a [u8],
    key: &'a str,
    auth_generation: i64,
    request_id: Uuid,
) -> crate::db::IdempotencyRequest<'a> {
    let base = crate::db::api_request_fingerprint("", b"");
    crate::db::IdempotencyRequest {
        request_id,
        actor_id: Some(actor_id),
        principal_scope: actor_scope,
        capacity_scope: actor_scope,
        target_scope,
        principal_kind: crate::db::ApiPrincipalKind::Admin,
        method: "POST",
        route: "/api/v1/admin/upload-dead-letters/{kind}/{id}/retry",
        idempotency_key: key,
        request_fingerprint: crate::api::upload_admin::admin_generation_bound_request_fingerprint(
            base,
            auth_generation,
        ),
        ttl_seconds: 86_400,
        lease_seconds: 30,
    }
}

#[tokio::test]
#[ignore = "requires an isolated TEST_DATABASE_URL PostgreSQL database"]
async fn postgres_retry_idempotency_replay_target_generation_and_not_found_contract() {
    let url = std::env::var("TEST_DATABASE_URL")
        .expect("set TEST_DATABASE_URL to an isolated PostgreSQL database");
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(4)
        .connect(&url)
        .await
        .unwrap();
    crate::db::migrate(&pool).await.unwrap();
    northstar_upload_postgres::validate_upload_capacity_policy(
        &pool,
        10_000,
        1_000_000,
        1_099_511_627_776,
    )
    .await
    .unwrap();
    let (admin_id, admin_token) = insert_user(&pool, true).await;
    let actor_scope = admin_id.as_bytes();
    let keys =
        crate::db::ApiControlKeyring::new(b"upload-dead-letter-idempotency-test-key-0001", None)
            .unwrap();

    let job = insert_storage_dead_letter(&pool, None).await;
    let target = format!("storage_job\0{job}");
    let key = "upload-retry-success-0001";
    let original_request_id = Uuid::new_v4();
    let original = retry_idempotency_request(
        admin_id,
        actor_scope,
        target.as_bytes(),
        key,
        0,
        original_request_id,
    );
    let mut tx = pool.begin().await.unwrap();
    let lease = match crate::db::acquire_idempotency_in_tx(&keys, &mut tx, &original)
        .await
        .unwrap()
    {
        crate::db::IdempotencyAcquire::Acquired(lease) => lease,
        other => panic!("unexpected first idempotency outcome: {other:?}"),
    };
    assert_eq!(
        retry_upload_dead_letter_in_tx(
            &mut tx,
            admin_id,
            0,
            &admin_token,
            UploadDeadLetterId::StorageJob(job),
            lease.request_id,
        )
        .await
        .unwrap(),
        RetryUploadDeadLetter::Retried
    );
    let response_body = format!(r#"{{"kind":"storage_job","id":"{job}","state":"queued"}}"#);
    assert!(crate::db::complete_idempotency_in_tx(
        &keys,
        &mut tx,
        &lease,
        StatusCode::ACCEPTED.as_u16(),
        &northstar_operations_core::api_mutations::json_replay_headers(),
        response_body.as_bytes(),
    )
    .await
    .unwrap());
    tx.commit().await.unwrap();

    let replay_request = retry_idempotency_request(
        admin_id,
        actor_scope,
        target.as_bytes(),
        key,
        0,
        Uuid::new_v4(),
    );
    let mut replay_tx = pool.begin().await.unwrap();
    let replay = match crate::db::acquire_idempotency_in_tx(&keys, &mut replay_tx, &replay_request)
        .await
        .unwrap()
    {
        crate::db::IdempotencyAcquire::Replay(replay) => replay,
        other => panic!("unexpected replay outcome: {other:?}"),
    };
    replay_tx.commit().await.unwrap();
    let response = crate::api::idempotency_replay_response(replay).unwrap();
    assert_eq!(response.status(), StatusCode::ACCEPTED);
    assert_eq!(
        response
            .headers()
            .get("idempotency-replayed")
            .and_then(|value| value.to_str().ok()),
        Some("true")
    );
    let original_request_id_text = original_request_id.to_string();
    assert_eq!(
        response
            .headers()
            .get("idempotency-original-request-id")
            .and_then(|value| value.to_str().ok()),
        Some(original_request_id_text.as_str())
    );
    assert_eq!(
        to_bytes(response.into_body(), 1024).await.unwrap(),
        response_body.as_bytes()
    );

    let different_target = format!("storage_job\0{}", job.saturating_add(1));
    let target_conflict = retry_idempotency_request(
        admin_id,
        actor_scope,
        different_target.as_bytes(),
        key,
        0,
        Uuid::new_v4(),
    );
    let mut conflict_tx = pool.begin().await.unwrap();
    assert!(matches!(
        crate::db::acquire_idempotency_in_tx(&keys, &mut conflict_tx, &target_conflict)
            .await
            .unwrap(),
        crate::db::IdempotencyAcquire::FingerprintConflict
    ));
    conflict_tx.rollback().await.unwrap();

    let generation_conflict = retry_idempotency_request(
        admin_id,
        actor_scope,
        target.as_bytes(),
        key,
        1,
        Uuid::new_v4(),
    );
    let mut generation_tx = pool.begin().await.unwrap();
    assert!(matches!(
        crate::db::acquire_idempotency_in_tx(&keys, &mut generation_tx, &generation_conflict)
            .await
            .unwrap(),
        crate::db::IdempotencyAcquire::FingerprintConflict
    ));
    generation_tx.rollback().await.unwrap();

    let missing_id = i64::MAX;
    let missing_target = format!("storage_job\0{missing_id}");
    let missing_key = "upload-retry-missing-0001";
    let missing_original_request_id = Uuid::new_v4();
    let missing_request = retry_idempotency_request(
        admin_id,
        actor_scope,
        missing_target.as_bytes(),
        missing_key,
        0,
        missing_original_request_id,
    );
    let mut missing_tx = pool.begin().await.unwrap();
    let missing_lease =
        match crate::db::acquire_idempotency_in_tx(&keys, &mut missing_tx, &missing_request)
            .await
            .unwrap()
        {
            crate::db::IdempotencyAcquire::Acquired(lease) => lease,
            other => panic!("unexpected missing-row admission: {other:?}"),
        };
    assert_eq!(
        retry_upload_dead_letter_in_tx(
            &mut missing_tx,
            admin_id,
            0,
            &admin_token,
            UploadDeadLetterId::StorageJob(missing_id),
            missing_lease.request_id,
        )
        .await
        .unwrap(),
        RetryUploadDeadLetter::Unavailable
    );
    let missing_body =
        br#"{"error":{"code":"not_found","message":"upload dead-letter entry is unavailable"}}"#;
    assert!(crate::db::complete_idempotency_in_tx(
        &keys,
        &mut missing_tx,
        &missing_lease,
        StatusCode::NOT_FOUND.as_u16(),
        &northstar_operations_core::api_mutations::json_replay_headers(),
        missing_body,
    )
    .await
    .unwrap());
    missing_tx.commit().await.unwrap();

    let missing_replay = retry_idempotency_request(
        admin_id,
        actor_scope,
        missing_target.as_bytes(),
        missing_key,
        0,
        Uuid::new_v4(),
    );
    let mut missing_replay_tx = pool.begin().await.unwrap();
    let replay =
        crate::db::acquire_idempotency_in_tx(&keys, &mut missing_replay_tx, &missing_replay)
            .await
            .unwrap();
    let replay = match replay {
        crate::db::IdempotencyAcquire::Replay(replay) => replay,
        other => panic!("unexpected stored-404 replay outcome: {other:?}"),
    };
    missing_replay_tx.commit().await.unwrap();
    let response = crate::api::idempotency_replay_response(replay).unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    assert_eq!(
        response
            .headers()
            .get("idempotency-replayed")
            .and_then(|value| value.to_str().ok()),
        Some("true")
    );
    let missing_original_request_id_text = missing_original_request_id.to_string();
    assert_eq!(
        response
            .headers()
            .get("idempotency-original-request-id")
            .and_then(|value| value.to_str().ok()),
        Some(missing_original_request_id_text.as_str())
    );
    assert_eq!(
        to_bytes(response.into_body(), 1024).await.unwrap().as_ref(),
        missing_body.as_slice()
    );

    let successful_audits: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM audit_log
          WHERE request_id=$1 AND action='admin.upload_dead_letter.retry'",
    )
    .bind(original_request_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(successful_audits, 1);
    pool.close().await;
}

#[tokio::test]
#[ignore = "requires an isolated TEST_DATABASE_URL PostgreSQL database"]
async fn postgres_retry_authorization_pagination_concurrency_and_fencing() {
    let url = std::env::var("TEST_DATABASE_URL")
        .expect("set TEST_DATABASE_URL to an isolated PostgreSQL database");
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(8)
        .connect(&url)
        .await
        .unwrap();
    crate::db::migrate(&pool).await.unwrap();
    northstar_upload_postgres::validate_upload_capacity_policy(
        &pool,
        10_000,
        1_000_000,
        1_099_511_627_776,
    )
    .await
    .unwrap();
    let (admin_id, admin_token) = insert_user(&pool, true).await;
    let (user_id, user_token) = insert_user(&pool, false).await;

    let unauthorized_job = insert_storage_dead_letter(&pool, None).await;
    let mut unauthorized_tx = pool.begin().await.unwrap();
    assert_eq!(
        retry_upload_dead_letter_in_tx(
            &mut unauthorized_tx,
            user_id,
            0,
            &user_token,
            UploadDeadLetterId::StorageJob(unauthorized_job),
            Uuid::new_v4(),
        )
        .await
        .unwrap(),
        RetryUploadDeadLetter::Unauthorized
    );
    unauthorized_tx.rollback().await.unwrap();

    let active_claim =
        insert_storage_dead_letter(&pool, Some(Utc::now() + chrono::Duration::minutes(5))).await;
    let mut fenced_tx = pool.begin().await.unwrap();
    assert_eq!(
        retry_upload_dead_letter_in_tx(
            &mut fenced_tx,
            admin_id,
            0,
            &admin_token,
            UploadDeadLetterId::StorageJob(active_claim),
            Uuid::new_v4(),
        )
        .await
        .unwrap(),
        RetryUploadDeadLetter::Unavailable
    );
    fenced_tx.commit().await.unwrap();
    sqlx::query(
        "UPDATE upload_storage_jobs
            SET claim_expires_at=clock_timestamp()-INTERVAL '1 second'
          WHERE id=$1",
    )
    .bind(active_claim)
    .execute(&pool)
    .await
    .unwrap();
    let mut retry_tx = pool.begin().await.unwrap();
    assert_eq!(
        retry_upload_dead_letter_in_tx(
            &mut retry_tx,
            admin_id,
            0,
            &admin_token,
            UploadDeadLetterId::StorageJob(active_claim),
            Uuid::new_v4(),
        )
        .await
        .unwrap(),
        RetryUploadDeadLetter::Retried
    );
    retry_tx.commit().await.unwrap();
    let preserved: (i64, Option<String>, Option<Uuid>) = sqlx::query_as(
        "SELECT attempts,last_error,claim_token
           FROM upload_storage_jobs WHERE id=$1",
    )
    .bind(active_claim)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(preserved, (0, Some("fixture failure".into()), None));

    let raced = insert_storage_dead_letter(&pool, None).await;
    let barrier = Arc::new(Barrier::new(3));
    let mut tasks = Vec::new();
    for _ in 0..2 {
        let pool = pool.clone();
        let barrier = Arc::clone(&barrier);
        let token = admin_token.clone();
        tasks.push(tokio::spawn(async move {
            let mut tx = pool.begin().await.unwrap();
            barrier.wait().await;
            let result = retry_upload_dead_letter_in_tx(
                &mut tx,
                admin_id,
                0,
                &token,
                UploadDeadLetterId::StorageJob(raced),
                Uuid::new_v4(),
            )
            .await
            .unwrap();
            tx.commit().await.unwrap();
            result
        }));
    }
    barrier.wait().await;
    let results = futures::future::join_all(tasks)
        .await
        .into_iter()
        .map(|result| result.unwrap())
        .collect::<Vec<_>>();
    assert_eq!(
        results
            .iter()
            .filter(|result| **result == RetryUploadDeadLetter::Retried)
            .count(),
        1
    );
    assert_eq!(
        results
            .iter()
            .filter(|result| **result == RetryUploadDeadLetter::Unavailable)
            .count(),
        1
    );

    let tied: DateTime<Utc> = sqlx::query_scalar("SELECT date_trunc('second',clock_timestamp())")
        .fetch_one(&pool)
        .await
        .unwrap();
    let mut fixture_ids = Vec::new();
    for _ in 0..5 {
        let object_id = Uuid::new_v4();
        let recovery_id: Uuid = sqlx::query_scalar(
            "INSERT INTO upload_cleanup_queue(
                 object_id,storage_backend,object_key,expected_size,
                 storage_fence,attempts,dead_lettered_at,last_error)
             VALUES($1,'local',$1::text,1,0,12,$2,'cleanup fixture')
             RETURNING recovery_id",
        )
        .bind(object_id)
        .bind(tied)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_ne!(recovery_id, object_id);
        let recovery_text = recovery_id.hyphenated().to_string();
        assert_eq!(&recovery_text[14..15], "4");
        assert!(matches!(&recovery_text[19..20], "8" | "9" | "a" | "b"));
        fixture_ids.push((object_id, recovery_id));
    }
    let mut page_tx = pool.begin().await.unwrap();
    let first =
        upload_dead_letters_page_in_tx(&mut page_tx, UploadDeadLetterKind::Cleanup, None, 2)
            .await
            .unwrap();
    page_tx.commit().await.unwrap();
    assert_eq!(first.rows.len(), 2);
    let first_ids = first.rows.iter().map(|row| row.id).collect::<HashSet<_>>();
    let mut next_tx = pool.begin().await.unwrap();
    let second = upload_dead_letters_page_in_tx(
        &mut next_tx,
        UploadDeadLetterKind::Cleanup,
        first.next,
        100,
    )
    .await
    .unwrap();
    next_tx.commit().await.unwrap();
    assert!(second.rows.iter().all(|row| !first_ids.contains(&row.id)));
    assert_eq!(first.rows.len() + second.rows.len(), fixture_ids.len());

    let (cleanup_object_id, cleanup_recovery_id) = fixture_ids[0];
    let immutable_error =
        sqlx::query("UPDATE upload_cleanup_queue SET recovery_id=$2 WHERE object_id=$1")
            .bind(cleanup_object_id)
            .bind(Uuid::new_v4())
            .execute(&pool)
            .await
            .unwrap_err();
    assert_eq!(
        immutable_error
            .as_database_error()
            .and_then(|error| error.code().map(|code| code.into_owned()))
            .as_deref(),
        Some("55000")
    );
    let cleanup_request_id = Uuid::new_v4();
    let mut cleanup_retry_tx = pool.begin().await.unwrap();
    assert_eq!(
        retry_upload_dead_letter_in_tx(
            &mut cleanup_retry_tx,
            admin_id,
            0,
            &admin_token,
            UploadDeadLetterId::Cleanup(cleanup_recovery_id),
            cleanup_request_id,
        )
        .await
        .unwrap(),
        RetryUploadDeadLetter::Retried
    );
    cleanup_retry_tx.commit().await.unwrap();
    let cleanup_preserved: (i64, Option<String>, Option<DateTime<Utc>>) = sqlx::query_as(
        "SELECT attempts,last_error,dead_lettered_at
           FROM upload_cleanup_queue WHERE object_id=$1",
    )
    .bind(cleanup_object_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(cleanup_preserved, (0, Some("cleanup fixture".into()), None));
    let (audit_target, audit_details): (String, serde_json::Value) =
        sqlx::query_as("SELECT target,details FROM audit_log WHERE request_id=$1")
            .bind(cleanup_request_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(audit_target, format!("cleanup:{cleanup_recovery_id}"));
    assert!(!audit_target.contains(&cleanup_object_id.to_string()));
    let audit_json = serde_json::to_string(&audit_details).unwrap();
    for forbidden in [
        "last_error_sha256",
        "last_error_bytes",
        "last_error_length",
        "last_error_text",
        "object_id",
        "object_key",
        "stage_key",
        "cleanup fixture",
    ] {
        assert!(!audit_json.contains(forbidden), "audit leaked {forbidden}");
    }

    let audits: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM audit_log
          WHERE actor_id=$1 AND action='admin.upload_dead_letter.retry'",
    )
    .bind(admin_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(audits, 3, "only successful retries create immutable audits");
    pool.close().await;
}
