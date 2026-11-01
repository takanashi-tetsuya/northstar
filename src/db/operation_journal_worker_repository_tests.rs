use northstar_operations_application::operation_journal_worker::OperationJournalWorkerService;
use northstar_operations_application::operation_journal_worker::TargetSeed;
use northstar_operations_postgres::operation_journal_worker_repository::*;
use serde_json::json;
use sqlx::PgPool;
use uuid::Uuid;

async fn enqueue_broadcast(pool: &PgPool) -> Uuid {
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
    let mut tx = pool.begin().await.unwrap();
    let operation = northstar_operations_postgres::api_operations::enqueue_operation_in_tx(
        &mut tx,
        &northstar_operations_postgres::api_operations::EnqueueOperation {
            request_id: request,
            idempotency_id: idempotency,
            idempotency_lease_token: token,
            actor_id: actor,
            actor_auth_generation: 0,
            authorization_policy: northstar_operations_postgres::api_operations::AuthorizationPolicy::ReauthorizeUntilEffect,
            kind: "admin.broadcast",
            target: None,
            payload_version: 1,
            payload: &json!({"message":"maintenance"}),
            max_attempts: 3,
            deadline_seconds: 3600,
        },
    )
    .await
    .unwrap();
    tx.commit().await.unwrap();
    operation.id
}

async fn assert_unclaimed_without_targets(pool: &PgPool, operation_id: Uuid) {
    let (status, attempts): (String, i32) =
        sqlx::query_as("SELECT status,attempts FROM api_operation_journal WHERE id=$1")
            .bind(operation_id)
            .fetch_one(pool)
            .await
            .unwrap();
    let targets: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM api_operation_targets WHERE operation_id=$1")
            .bind(operation_id)
            .fetch_one(pool)
            .await
            .unwrap();
    assert_eq!((status.as_str(), attempts, targets), ("pending", 0, 0));
}

#[tokio::test]
#[ignore = "requires a random isolated TEST_DATABASE_URL PostgreSQL schema"]
async fn claim_and_target_plan_commit_or_roll_back_together() {
    let pool = crate::db::test_support::operation_mutation_pool().await;
    let operation_id = enqueue_broadcast(&pool).await;
    let service = OperationJournalWorkerService::new(
        PostgresOperationJournalWorkerRepository::new(pool.clone()),
    );
    let worker_id = Uuid::new_v4();

    let error = service
        .claim_parent_with_targets(worker_id, 60, |operation| {
            assert_eq!(operation.kind, "admin.broadcast");
            assert_eq!(operation.payload, &json!({"message":"maintenance"}));
            anyhow::bail!("injected target snapshot failure")
        })
        .await
        .expect_err("planner failure must abort the claim");
    assert!(error
        .to_string()
        .contains("injected target snapshot failure"));
    assert_unclaimed_without_targets(&pool, operation_id).await;

    assert!(service
        .claim_parent_with_targets(worker_id, 60, |_| {
            Ok(vec![
                TargetSeed {
                    target_key: "connection:first".to_owned(),
                    ordinal: 0,
                    payload: json!({"message":"maintenance"}),
                },
                TargetSeed {
                    target_key: String::new(),
                    ordinal: 1,
                    payload: json!({"message":"maintenance"}),
                },
            ])
        })
        .await
        .is_err());
    assert_unclaimed_without_targets(&pool, operation_id).await;

    let lease = service
        .claim_parent_with_targets(worker_id, 60, |_| {
            Ok(vec![TargetSeed {
                target_key: "connection:first".to_owned(),
                ordinal: 0,
                payload: json!({"message":"maintenance"}),
            }])
        })
        .await
        .unwrap()
        .expect("the valid plan must commit its claim");
    assert_eq!(lease.operation.id, operation_id);
    let (status, attempts): (String, i32) =
        sqlx::query_as("SELECT status,attempts FROM api_operation_journal WHERE id=$1")
            .bind(operation_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!((status.as_str(), attempts), ("running", 1));
    let (target_key, ordinal, max_attempts): (String, i64, i32) = sqlx::query_as(
        "SELECT target_key,ordinal,max_attempts FROM api_operation_targets WHERE operation_id=$1",
    )
    .bind(operation_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(
        (target_key.as_str(), ordinal, max_attempts),
        ("connection:first", 0, 3)
    );

    let none = service
        .claim_parent_with_targets(worker_id, 60, |_| {
            panic!("a claim without a candidate must not take a new snapshot")
        })
        .await
        .unwrap();
    assert!(none.is_none());
    pool.close().await;
}
