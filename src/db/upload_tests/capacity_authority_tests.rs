//! Capacity authority audit and ledger reconciliation tests.

use super::*;

async fn test_capacity_authority(pool: &PgPool) -> UploadCapacityAuthorityAudit {
    audit_upload_capacity_authority(
        pool,
        TEST_UPLOAD_PENDING_LIMIT,
        TEST_UPLOAD_RETAINED_FILES_LIMIT,
        TEST_UPLOAD_RETAINED_BYTES_LIMIT,
    )
    .await
    .unwrap()
}

#[test]
fn capacity_reconciliation_counts_each_counter_and_projection_conflict() {
    let consistent = UploadCapacityReconciliation {
        ledger_retained_files: 1,
        fact_retained_files: 1,
        ledger_retained_bytes: 2,
        fact_retained_bytes: 2,
        ledger_pending_jobs: 3,
        fact_pending_jobs: 3,
        ledger_storage_jobs_pending: 1,
        fact_storage_jobs_pending: 1,
        ledger_cleanup_jobs_pending: 2,
        fact_cleanup_jobs_pending: 2,
        ledger_cleanup_obligation_debt: 4,
        fact_cleanup_obligation_debt: 4,
        ledger_recovery_retained_files: 5,
        fact_recovery_retained_files: 5,
        ledger_recovery_retained_bytes: 6,
        fact_recovery_retained_bytes: 6,
        ledger_legacy_overcommit_draining: false,
        fact_legacy_overcommit_draining: false,
        ledger_recovery_overcommit_draining: false,
        fact_recovery_overcommit_draining: false,
        projection_size_conflicts: 0,
    };
    assert_eq!(consistent.mismatch_count(), 0);

    let inconsistent = UploadCapacityReconciliation {
        fact_pending_jobs: 30,
        fact_recovery_retained_bytes: 60,
        fact_legacy_overcommit_draining: true,
        fact_recovery_overcommit_draining: true,
        projection_size_conflicts: 2,
        ..consistent
    };
    assert_eq!(inconsistent.mismatch_count(), 6);
}

#[test]
fn capacity_authority_audit_counts_each_independent_boundary() {
    let clean = UploadCapacityAuthorityAudit::default();
    assert_eq!(clean.violation_count(), 0);
    let drifted = UploadCapacityAuthorityAudit {
        relation_owner_violations: 1,
        relation_acl_violations: 5,
        function_authority_violations: 2,
        trigger_authority_violations: 3,
        policy_binding_violations: 4,
    };
    assert_eq!(drifted.violation_count(), 15);
}

#[tokio::test]
#[ignore = "requires an isolated TEST_DATABASE_URL PostgreSQL database"]
async fn capacity_reconciliation_reads_bigint_facts_and_detects_ledger_drift() {
    let url = std::env::var("TEST_DATABASE_URL")
        .expect("set TEST_DATABASE_URL to an isolated PostgreSQL database");
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(4)
        .connect(&url)
        .await
        .unwrap();
    db::migrate(&pool).await.unwrap();
    validate_upload_capacity_policy(
        &pool,
        TEST_UPLOAD_PENDING_LIMIT,
        TEST_UPLOAD_RETAINED_FILES_LIMIT,
        TEST_UPLOAD_RETAINED_BYTES_LIMIT,
    )
    .await
    .unwrap();

    let baseline = reconcile_upload_capacity_ledger(&pool).await.unwrap();
    assert_eq!(baseline.mismatch_count(), 0);
    let retained_files: i64 = sqlx::query_scalar(
        "UPDATE upload_storage_capacity_ledger
                SET retained_files=retained_files+1
              WHERE singleton
              RETURNING retained_files-1",
    )
    .fetch_one(&pool)
    .await
    .unwrap();

    let drifted = reconcile_upload_capacity_ledger(&pool).await.unwrap();
    sqlx::query(
        "UPDATE upload_storage_capacity_ledger
                SET retained_files=$1
              WHERE singleton",
    )
    .bind(retained_files)
    .execute(&pool)
    .await
    .unwrap();
    assert_eq!(drifted.ledger_retained_files, retained_files + 1);
    assert_eq!(drifted.fact_retained_files, retained_files);
    assert_eq!(drifted.mismatch_count(), 1);
}

#[tokio::test]
#[ignore = "requires an isolated TEST_DATABASE_URL PostgreSQL database"]
async fn capacity_authority_audit_detects_trigger_function_acl_and_policy_drift() {
    let url = std::env::var("TEST_DATABASE_URL")
        .expect("set TEST_DATABASE_URL to an isolated PostgreSQL database");
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(4)
        .connect(&url)
        .await
        .unwrap();
    db::migrate(&pool).await.unwrap();
    validate_upload_capacity_policy(
        &pool,
        TEST_UPLOAD_PENDING_LIMIT,
        TEST_UPLOAD_RETAINED_FILES_LIMIT,
        TEST_UPLOAD_RETAINED_BYTES_LIMIT,
    )
    .await
    .unwrap();
    let clean = test_capacity_authority(&pool).await;
    assert_eq!(clean.violation_count(), 0);
    assert_eq!(clean.policy_binding_violations, 0);

    let policy_drift = audit_upload_capacity_authority(
        &pool,
        TEST_UPLOAD_PENDING_LIMIT + 1,
        TEST_UPLOAD_RETAINED_FILES_LIMIT,
        TEST_UPLOAD_RETAINED_BYTES_LIMIT,
    )
    .await
    .unwrap();
    assert_eq!(policy_drift.policy_binding_violations, 1);
    assert_eq!(policy_drift.violation_count(), 1);

    sqlx::query(
        "ALTER TABLE upload_storage_jobs
             DISABLE TRIGGER upload_job_capacity_insert",
    )
    .execute(&pool)
    .await
    .unwrap();
    let disabled = test_capacity_authority(&pool).await;
    sqlx::query(
        "ALTER TABLE upload_storage_jobs
             ENABLE TRIGGER upload_job_capacity_insert",
    )
    .execute(&pool)
    .await
    .unwrap();
    assert!(disabled.trigger_authority_violations > 0);

    sqlx::query("GRANT EXECUTE ON FUNCTION account_upload_storage_job_capacity() TO PUBLIC")
        .execute(&pool)
        .await
        .unwrap();
    let public_execute = test_capacity_authority(&pool).await;
    sqlx::query("REVOKE ALL ON FUNCTION account_upload_storage_job_capacity() FROM PUBLIC")
        .execute(&pool)
        .await
        .unwrap();
    assert!(public_execute.function_authority_violations > 0);

    sqlx::query("ALTER FUNCTION account_upload_storage_job_capacity() SECURITY INVOKER")
        .execute(&pool)
        .await
        .unwrap();
    let invoker = test_capacity_authority(&pool).await;
    sqlx::query("ALTER FUNCTION account_upload_storage_job_capacity() SECURITY DEFINER")
        .execute(&pool)
        .await
        .unwrap();
    assert!(invoker.function_authority_violations > 0);

    let mut unbound = pool.begin().await.unwrap();
    sqlx::query(
        "ALTER TABLE upload_storage_capacity_ledger
             DISABLE TRIGGER upload_capacity_policy_guard",
    )
    .execute(&mut *unbound)
    .await
    .unwrap();
    sqlx::query(
        "UPDATE upload_storage_capacity_ledger
                SET configured_pending_limit=NULL,
                    configured_retained_files_limit=NULL,
                    configured_retained_bytes_limit=NULL
              WHERE singleton",
    )
    .execute(&mut *unbound)
    .await
    .unwrap();
    sqlx::query(
        "ALTER TABLE upload_storage_capacity_ledger
             ENABLE TRIGGER upload_capacity_policy_guard",
    )
    .execute(&mut *unbound)
    .await
    .unwrap();
    let object_id = Uuid::new_v4();
    let storage_attempt = Uuid::new_v4();
    let unbound_error = sqlx::query(
        "INSERT INTO upload_storage_jobs(
                 object_id,storage_attempt,action,storage_backend,stage_key,
                 storage_fence,expected_size
             ) VALUES($1,$2,'delete_stage','local',$3,0,1)",
    )
    .bind(object_id)
    .bind(storage_attempt)
    .bind(format!("staging/{object_id}/{storage_attempt}"))
    .execute(&mut *unbound)
    .await
    .unwrap_err();
    unbound.rollback().await.unwrap();
    assert!(matches!(&unbound_error,sqlx::Error::Database(error)
            if error.code().as_deref()==Some("55000")));
    assert!(unbound_error
        .to_string()
        .contains("capacity policy is not fully bound"));

    let mut unbound_cleanup = pool.begin().await.unwrap();
    sqlx::query(
        "ALTER TABLE upload_storage_capacity_ledger
             DISABLE TRIGGER upload_capacity_policy_guard",
    )
    .execute(&mut *unbound_cleanup)
    .await
    .unwrap();
    sqlx::query(
        "UPDATE upload_storage_capacity_ledger
                SET configured_pending_limit=NULL,
                    configured_retained_files_limit=NULL,
                    configured_retained_bytes_limit=NULL
              WHERE singleton",
    )
    .execute(&mut *unbound_cleanup)
    .await
    .unwrap();
    sqlx::query(
        "ALTER TABLE upload_storage_capacity_ledger
             ENABLE TRIGGER upload_capacity_policy_guard",
    )
    .execute(&mut *unbound_cleanup)
    .await
    .unwrap();
    let cleanup_id = Uuid::new_v4();
    let unbound_cleanup_error = sqlx::query(
        "INSERT INTO upload_cleanup_queue(
                 object_id,storage_backend,object_key,expected_size,storage_fence
             ) VALUES($1,'local',$2,1,0)",
    )
    .bind(cleanup_id)
    .bind(cleanup_id.to_string())
    .execute(&mut *unbound_cleanup)
    .await
    .unwrap_err();
    unbound_cleanup.rollback().await.unwrap();
    assert!(matches!(&unbound_cleanup_error,sqlx::Error::Database(error)
            if error.code().as_deref()==Some("55000")));
    assert!(unbound_cleanup_error
        .to_string()
        .contains("capacity policy is not fully bound"));
    assert_eq!(test_capacity_authority(&pool).await.violation_count(), 0);
}

#[tokio::test]
#[ignore = "requires an isolated TEST_DATABASE_URL PostgreSQL database"]
async fn capacity_reconciliation_detects_rows_written_while_trigger_was_bypassed() {
    let url = std::env::var("TEST_DATABASE_URL")
        .expect("set TEST_DATABASE_URL to an isolated PostgreSQL database");
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(4)
        .connect(&url)
        .await
        .unwrap();
    db::migrate(&pool).await.unwrap();
    validate_upload_capacity_policy(
        &pool,
        TEST_UPLOAD_PENDING_LIMIT,
        TEST_UPLOAD_RETAINED_FILES_LIMIT,
        TEST_UPLOAD_RETAINED_BYTES_LIMIT,
    )
    .await
    .unwrap();
    let before = reconcile_upload_capacity_ledger(&pool).await.unwrap();
    assert_eq!(before.mismatch_count(), 0);

    let object_id = Uuid::new_v4();
    let storage_attempt = Uuid::new_v4();
    let mut bypass = pool.begin().await.unwrap();
    sqlx::query(
        "ALTER TABLE upload_storage_jobs
             DISABLE TRIGGER upload_job_capacity_insert",
    )
    .execute(&mut *bypass)
    .await
    .unwrap();
    let job_id: i64 = sqlx::query_scalar(
        "INSERT INTO upload_storage_jobs(
                 object_id,storage_attempt,action,storage_backend,stage_key,
                 storage_fence,expected_size
             ) VALUES($1,$2,'delete_stage','local',$3,0,1)
             RETURNING id",
    )
    .bind(object_id)
    .bind(storage_attempt)
    .bind(format!("staging/{object_id}/{storage_attempt}"))
    .fetch_one(&mut *bypass)
    .await
    .unwrap();
    sqlx::query(
        "ALTER TABLE upload_storage_jobs
             ENABLE TRIGGER upload_job_capacity_insert",
    )
    .execute(&mut *bypass)
    .await
    .unwrap();
    bypass.commit().await.unwrap();

    let drifted = reconcile_upload_capacity_ledger(&pool).await.unwrap();
    let mut cleanup = pool.begin().await.unwrap();
    sqlx::query(
        "ALTER TABLE upload_storage_jobs
             DISABLE TRIGGER upload_job_capacity_delete",
    )
    .execute(&mut *cleanup)
    .await
    .unwrap();
    sqlx::query("DELETE FROM upload_storage_jobs WHERE id=$1")
        .bind(job_id)
        .execute(&mut *cleanup)
        .await
        .unwrap();
    sqlx::query(
        "ALTER TABLE upload_storage_jobs
             ENABLE TRIGGER upload_job_capacity_delete",
    )
    .execute(&mut *cleanup)
    .await
    .unwrap();
    cleanup.commit().await.unwrap();

    assert!(drifted.fact_pending_jobs > drifted.ledger_pending_jobs);
    assert!(drifted.fact_storage_jobs_pending > drifted.ledger_storage_jobs_pending);
    assert!(drifted.fact_recovery_retained_files > drifted.ledger_recovery_retained_files);
    assert!(drifted.mismatch_count() >= 4);
    assert_eq!(
        reconcile_upload_capacity_ledger(&pool)
            .await
            .unwrap()
            .mismatch_count(),
        0
    );
}

#[tokio::test]
#[ignore = "requires an isolated TEST_DATABASE_URL PostgreSQL database"]
async fn upload_capacity_migration_rejects_disabled_or_reused_trigger_authority() {
    let url = std::env::var("TEST_DATABASE_URL")
        .expect("set TEST_DATABASE_URL to an isolated PostgreSQL database");
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(2)
        .connect(&url)
        .await
        .unwrap();
    db::migrate(&pool).await.unwrap();
    let migration = include_str!("../../../migrations/0105_upload_cascade_cleanup_capacity.sql");
    let marker = "$northstar_upload_delete_trigger_precondition$;";
    let start = migration
        .find("DO $northstar_upload_delete_trigger_precondition$")
        .expect("0105 trigger precondition start");
    let relative_end = migration[start..]
        .find(marker)
        .expect("0105 trigger precondition end");
    let precondition = &migration[start..start + relative_end + marker.len()];

    sqlx::query(
        "ALTER TABLE upload_cleanup_queue
             DISABLE TRIGGER upload_cleanup_identity_guard",
    )
    .execute(&pool)
    .await
    .unwrap();
    let disabled_error = sqlx::query(precondition).execute(&pool).await.unwrap_err();
    sqlx::query(
        "ALTER TABLE upload_cleanup_queue
             ENABLE TRIGGER upload_cleanup_identity_guard",
    )
    .execute(&pool)
    .await
    .unwrap();
    assert!(
        matches!(&disabled_error,sqlx::Error::Database(error)
                if error.code().as_deref()==Some("55000")),
        "disabled identity guard must fail migration preconditions: {disabled_error}"
    );

    sqlx::query(
        "ALTER TABLE upload_storage_jobs
             DISABLE TRIGGER upload_job_capacity_insert",
    )
    .execute(&pool)
    .await
    .unwrap();
    let disabled_capacity_error = sqlx::query(precondition).execute(&pool).await.unwrap_err();
    sqlx::query(
        "ALTER TABLE upload_storage_jobs
             ENABLE TRIGGER upload_job_capacity_insert",
    )
    .execute(&pool)
    .await
    .unwrap();
    assert!(
        matches!(&disabled_capacity_error,sqlx::Error::Database(error)
                if error.code().as_deref()==Some("55000")),
        "disabled capacity trigger must fail migration preconditions: {disabled_capacity_error}"
    );

    sqlx::query("CREATE TABLE upload_cleanup_trigger_probe (LIKE upload_cleanup_queue)")
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query(
        "CREATE TRIGGER forged_upload_cleanup_identity_guard
             BEFORE UPDATE ON upload_cleanup_trigger_probe
             FOR EACH ROW EXECUTE FUNCTION protect_upload_cleanup_identity()",
    )
    .execute(&pool)
    .await
    .unwrap();
    let reused_error = sqlx::query(precondition).execute(&pool).await.unwrap_err();
    sqlx::query("DROP TABLE upload_cleanup_trigger_probe")
        .execute(&pool)
        .await
        .unwrap();
    assert!(
            matches!(&reused_error,sqlx::Error::Database(error)
                if error.code().as_deref()==Some("55000")),
            "reusing an identity function OID on another table must fail migration preconditions: {reused_error}"
        );

    sqlx::query("CREATE TABLE upload_job_capacity_trigger_probe (LIKE upload_storage_jobs)")
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query(
        "CREATE TRIGGER forged_upload_job_capacity_insert
             AFTER INSERT ON upload_job_capacity_trigger_probe
             FOR EACH ROW EXECUTE FUNCTION account_upload_storage_job_capacity()",
    )
    .execute(&pool)
    .await
    .unwrap();
    let reused_capacity_error = sqlx::query(precondition).execute(&pool).await.unwrap_err();
    sqlx::query("DROP TABLE upload_job_capacity_trigger_probe")
        .execute(&pool)
        .await
        .unwrap();
    assert!(
            matches!(&reused_capacity_error,sqlx::Error::Database(error)
                if error.code().as_deref()==Some("55000")),
            "reusing a capacity function OID on another table must fail migration preconditions: {reused_capacity_error}"
        );
}
