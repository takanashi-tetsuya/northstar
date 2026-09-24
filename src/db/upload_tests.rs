use super::{
    audit_upload_capacity_authority, claim_upload_slot, cleanup_expired_upload_slots,
    cleanup_object_version, complete_queued_upload_cleanup, complete_upload, create_upload_slot,
    defer_queued_upload_cleanup, is_retryable_upload_capacity_lock, queue_user_upload_delete,
    queue_user_upload_delete_authorized, queued_upload_cleanup, reconcile_upload_capacity_ledger,
    record_upload_replay, release_upload_claim, renew_upload_claim,
    upload_cleanup_generation_is_quiescent, upload_queue_metrics, uploaded_file,
    validate_upload_capacity_policy, UploadCapacityAuthorityAudit, UploadCapacityReconciliation,
    UploadClaimOutcome, UploadRenewOutcome, UploadReservation, UserUploadDeleteOutcome,
    MAX_UPLOAD_ATTEMPTS, MAX_UPLOAD_REPLAYS, TEST_UPLOAD_PENDING_LIMIT,
    TEST_UPLOAD_RETAINED_BYTES_LIMIT, TEST_UPLOAD_RETAINED_FILES_LIMIT,
};
use crate::db;
use sqlx::{PgPool, Row};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Barrier;
use uuid::Uuid;

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
fn s3_same_key_cleanup_uses_the_exact_stage_version() {
    assert_eq!(
        cleanup_object_version(
            "s3",
            "objects/id/attempt",
            None,
            Some("objects/id/attempt"),
            Some("version-7"),
        )
        .as_deref(),
        Some("version-7")
    );
    assert_eq!(
        cleanup_object_version(
            "local",
            "id",
            None,
            Some("staging/id/attempt"),
            Some("ignored-stage-version"),
        ),
        None
    );
}

#[test]
fn admission_and_account_delete_share_capacity_then_user_lock_order() {
    #[derive(Debug, Eq, PartialEq)]
    enum LockClass {
        CapacityLedger,
        User,
    }
    let admission = [LockClass::CapacityLedger, LockClass::User];
    let account_delete = [LockClass::CapacityLedger, LockClass::User];
    assert_eq!(admission, account_delete);
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

#[test]
fn cleanup_debt_converts_once_and_survives_every_slot_lifecycle() {
    #[derive(Default, Debug, Eq, PartialEq)]
    struct Ledger {
        pending: u64,
        debt: u64,
    }
    fn locator_first_materializes(ledger: &mut Ledger, reserved: &mut bool) {
        if !*reserved {
            ledger.debt += 1;
            *reserved = true;
        }
    }
    fn enqueue_cleanup(ledger: &mut Ledger, reserved: &mut bool, inserted: bool) {
        if !inserted {
            return;
        }
        ledger.pending += 1;
        if *reserved {
            ledger.debt -= 1;
            *reserved = false;
        }
    }
    fn finish_cleanup(ledger: &mut Ledger) {
        ledger.pending -= 1;
    }

    for _state in [
        "writing",
        "committed",
        "legacy_committed",
        "retention",
        "account-delete",
    ] {
        let mut ledger = Ledger::default();
        let mut reserved = false;
        locator_first_materializes(&mut ledger, &mut reserved);
        locator_first_materializes(&mut ledger, &mut reserved); // replay
        assert_eq!(
            ledger,
            Ledger {
                pending: 0,
                debt: 1
            }
        );
        enqueue_cleanup(&mut ledger, &mut reserved, true);
        enqueue_cleanup(&mut ledger, &mut reserved, false); // ON CONFLICT replay
        assert_eq!(
            ledger,
            Ledger {
                pending: 1,
                debt: 0
            }
        );
        finish_cleanup(&mut ledger);
        assert_eq!(ledger, Ledger::default());
    }

    // A migration orphan already has a pending projection and therefore
    // backfills no slot debt.
    let orphan = Ledger {
        pending: 1,
        debt: 0,
    };
    assert_eq!(orphan.pending + orphan.debt, 1);

    // Migration backfill reserves one cleanup debt for a legacy committed
    // locator. Exact cleanup admission converts it and confirmed removal
    // releases the sole pending projection.
    let mut legacy_committed = Ledger {
        pending: 0,
        debt: 1,
    };
    let mut legacy_reserved = true;
    enqueue_cleanup(&mut legacy_committed, &mut legacy_reserved, true);
    assert_eq!(
        legacy_committed,
        Ledger {
            pending: 1,
            debt: 0
        }
    );
    finish_cleanup(&mut legacy_committed);
    assert_eq!(legacy_committed, Ledger::default());

    // Staged/promoting deletion is represented by one cleanup row even
    // when local storage has distinct stage/object locators. S3's equal
    // stage/object key is likewise owned and released exactly once.
    for (backend, stage_equals_object) in [("local", false), ("s3", true)] {
        let mut ledger = Ledger {
            pending: 0,
            debt: 1,
        };
        let mut reserved = true;
        enqueue_cleanup(&mut ledger, &mut reserved, true);
        assert_eq!(
            ledger,
            Ledger {
                pending: 1,
                debt: 0
            },
            "{backend}"
        );
        assert_eq!(stage_equals_object, backend == "s3");
        finish_cleanup(&mut ledger);
        assert_eq!(ledger, Ledger::default(), "{backend}");
    }

    // A legacy migration may start above both the requested and absolute
    // ceilings. Debt conversion is net-zero and must remain possible;
    // only fresh work is rejected while deletion monotonically drains.
    let requested = 128_u64;
    let absolute = 100_000_u64;
    let mut legacy = Ledger {
        pending: 100_000,
        debt: 7,
    };
    let mut reserved = true;
    let before = legacy.pending + legacy.debt;
    enqueue_cleanup(&mut legacy, &mut reserved, true);
    assert_eq!(legacy.pending + legacy.debt, before);
    assert!(legacy.pending + legacy.debt > requested);
    assert!(legacy.pending + legacy.debt > absolute);
    while legacy.debt > 0 {
        reserved = true;
        enqueue_cleanup(&mut legacy, &mut reserved, true);
        finish_cleanup(&mut legacy);
    }
    while legacy.pending > 0 {
        finish_cleanup(&mut legacy);
    }
    assert_eq!(legacy, Ledger::default());
}

#[test]
fn shared_storage_migration_contains_cleanup_debt_atomicity_guards() {
    let sql = include_str!("../../migrations/0091_shared_upload_storage.sql");
    for required in [
        "storage_cleanup_debt_reserved BOOLEAN NOT NULL DEFAULT FALSE",
        "cleanup_obligation_debt BIGINT NOT NULL CHECK(cleanup_obligation_debt>=0)",
        "legacy_overcommit_draining BOOLEAN NOT NULL DEFAULT FALSE",
        "CREATE TRIGGER upload_slot_cleanup_debt_reserve BEFORE UPDATE ON upload_slots",
        "cleanup_obligation_debt=cleanup_obligation_debt-",
        "AND cleanup_obligation_debt>=CASE WHEN converts_debt THEN 1 ELSE 0 END",
        "pending_jobs+cleanup_obligation_debt+",
        "IF OLD.storage_state='writing'",
        "AND (converts_debt OR (",
        "legacy_overcommit_draining=(pending_jobs-1+cleanup_obligation_debt>",
        "'committed','legacy_committed','deleting'",
    ] {
        assert!(sql.contains(required), "missing debt invariant: {required}");
    }

    // A job insertion converts a reserved obligation in the same ledger
    // UPDATE; there must be no second statement that creates a crash gap.
    let storage_capacity_fn = sql
        .split("CREATE FUNCTION account_upload_storage_job_capacity()")
        .nth(1)
        .and_then(|tail| tail.split("$$ LANGUAGE plpgsql SECURITY DEFINER").next())
        .expect("storage job capacity trigger function");
    assert_eq!(
        storage_capacity_fn
            .matches("cleanup_obligation_debt=cleanup_obligation_debt-")
            .count(),
        1
    );
    assert!(!storage_capacity_fn.contains("TG_TABLE_NAME"));
    let cleanup_capacity_fn = sql
        .split("CREATE FUNCTION account_upload_cleanup_capacity()")
        .nth(1)
        .and_then(|tail| tail.split("$$ LANGUAGE plpgsql SECURITY DEFINER").next())
        .expect("cleanup capacity trigger function");
    assert!(!cleanup_capacity_fn.contains(".action"));
    assert!(!cleanup_capacity_fn.contains("TG_TABLE_NAME"));
    for exact_identity in [
        "storage_backend=NEW.storage_backend",
        "storage_attempt IS NOT DISTINCT FROM NEW.storage_attempt",
        "storage_fence=NEW.storage_fence",
        "storage_stage_version IS NOT DISTINCT FROM NEW.stage_version",
        "storage_object_version IS NOT DISTINCT FROM NEW.object_version",
        "storage_sha256 IS NOT DISTINCT FROM NEW.expected_sha256",
        "COALESCE(storage_size,size)=NEW.expected_size",
    ] {
        assert!(
            sql.contains(exact_identity),
            "missing exact debt authority: {exact_identity}"
        );
    }
    assert_eq!(
        sql.matches("SECURITY DEFINER SET search_path=pg_catalog,pg_temp")
            .count(),
        3
    );
    let lowercase_sql = sql.to_ascii_lowercase();
    for invalid_alias in ["pg_catalog.bigint", "pg_catalog.boolean"] {
        assert!(
            !lowercase_sql.contains(invalid_alias),
            "schema-qualified PostgreSQL aliases do not resolve through pg_type: {invalid_alias}"
        );
    }
    assert_eq!(lowercase_sql.matches("pg_catalog.int8").count(), 1);
    assert_eq!(lowercase_sql.matches("pg_catalog.bool").count(), 2);
    assert!(!sql.contains("SECURITY DEFINER SET search_path=pg_catalog,public"));
    assert!(!sql.contains("SET search_path FROM CURRENT"));
    assert!(!lowercase_sql.contains("public."));
    assert!(sql.contains("migration_schema pg_catalog.text := pg_catalog.current_schema()"));
    assert_eq!(
        sql.matches("SET search_path TO pg_catalog, %I, pg_temp'")
            .count(),
        3
    );
    for secured_function in [
        "offline_upgrade_upload_storage_authority_v1_to_v2(",
        "account_upload_storage_job_capacity()",
        "account_upload_cleanup_capacity()",
    ] {
        assert!(
            sql.contains(&format!("ALTER FUNCTION %I.{secured_function}")),
            "missing fixed schema binding for {secured_function}"
        );
    }
    for rejected_schema in [
        "'pg_catalog','information_schema'",
        "LIKE 'pg_temp_%'",
        "LIKE 'pg_toast_temp_%'",
    ] {
        assert!(sql.contains(rejected_schema));
    }
    for prerequisite in [
        "'upload_slots'",
        "'upload_cleanup_queue'",
        "'upload_cleanup_queue_order_idx'",
    ] {
        assert!(
            sql.contains(&format!(
                "pg_catalog.to_regclass(pg_catalog.format('%I.%I',target_schema,{prerequisite}))"
            )),
            "migration schema guard is missing {prerequisite}"
        );
    }
    assert!(storage_capacity_fn.contains("UPDATE upload_storage_capacity_ledger"));
    assert!(cleanup_capacity_fn.contains("UPDATE upload_storage_capacity_ledger"));
    assert!(sql.contains(
        "REVOKE INSERT,UPDATE,DELETE ON upload_storage_jobs,upload_cleanup_queue FROM PUBLIC"
    ));

    let authority_position = sql
        .find("CREATE FUNCTION offline_upgrade_upload_storage_authority_v1_to_v2(")
        .expect("offline upload authority function");
    for relation in [
        "CREATE TABLE upload_storage_jobs (",
        "ALTER TABLE upload_cleanup_queue ADD CONSTRAINT upload_cleanup_queue_state_check",
    ] {
        assert!(
            sql.find(relation).expect("offline authority dependency") < authority_position,
            "offline authority function was created before dependency: {relation}"
        );
    }
    let fixed_path_position = sql
        .find("$northstar_upload_function_paths$;")
        .expect("completed SECURITY DEFINER path binding");
    for trigger in [
        "CREATE TRIGGER upload_job_capacity_insert",
        "CREATE TRIGGER upload_job_capacity_delete",
        "CREATE TRIGGER upload_cleanup_capacity_insert",
        "CREATE TRIGGER upload_cleanup_capacity_delete",
    ] {
        assert!(
            sql.find(trigger).expect("capacity trigger") > fixed_path_position,
            "capacity trigger was attached before its function had a fixed schema: {trigger}"
        );
    }

    let cascade_fn = sql
        .split("CREATE FUNCTION queue_upload_storage_delete()")
        .nth(1)
        .and_then(|tail| tail.split("$$ LANGUAGE plpgsql;").next())
        .expect("cascade cleanup trigger function");
    assert!(cascade_fn.contains("IF OLD.storage_state='writing'"));
    assert_eq!(
        cascade_fn
            .matches("INSERT INTO upload_storage_jobs")
            .count(),
        1
    );
    assert_eq!(
        cascade_fn
            .matches("INSERT INTO upload_cleanup_queue")
            .count(),
        1
    );
    assert!(cascade_fn.contains("RETURN OLD;"));
}

#[test]
fn upload_cascade_capacity_requires_explicit_immutable_provenance() {
    let migration = include_str!("../../migrations/0105_upload_cascade_cleanup_capacity.sql");
    for required in [
        "ADD COLUMN slot_delete_projection pg_catalog.bool NOT NULL DEFAULT FALSE",
        "ADD COLUMN recovery_retained_files pg_catalog.int8 NOT NULL DEFAULT 0",
        "ADD COLUMN recovery_retained_bytes pg_catalog.int8 NOT NULL DEFAULT 0",
        "ADD COLUMN configured_retained_files_limit pg_catalog.int8",
        "ADD COLUMN configured_retained_bytes_limit pg_catalog.int8",
        "ADD COLUMN recovery_overcommit_draining pg_catalog.bool NOT NULL DEFAULT FALSE",
        "ALTER TABLE upload_storage_jobs ALTER COLUMN expected_size SET NOT NULL",
        "matching_triggers<>1",
        "trigger_row.tgname='upload_storage_delete_queue'",
        "function_row.proname='queue_upload_storage_delete'",
        "trigger_row.tgenabled IN ('O','A')",
        "trigger_row.tgqual IS NULL",
        "trigger_row.tgtype::pg_catalog.int4=11",
        "'upload_storage_job_identity_guard'",
        "'upload_cleanup_identity_guard'",
        "'upload_capacity_policy_guard'",
        "must have one exact attachment in the installation schema",
        "must have exactly one INSERT and one DELETE attachment",
        "ON CONFLICT(object_id) DO NOTHING",
        "IF OLD.storage_cleanup_debt_reserved THEN",
        "NEW.slot_delete_projection IS DISTINCT FROM OLD.slot_delete_projection",
        "IF pg_catalog.pg_trigger_depth()<=1 THEN",
        "IF NOT converts_debt THEN",
        "IF converts_debt AND NOT NEW.slot_delete_projection THEN",
        "recovery_retained_files=recovery_retained_files+1",
        "recovery_retained_files=recovery_retained_files+locator_units",
        "recovery_retained_files=recovery_retained_files-1",
        "recovery_retained_files=recovery_retained_files-locator_units",
        "hand ownership back to",
        "requested_retained_files_limit pg_catalog.int8",
        "requested_retained_bytes_limit pg_catalog.int8",
        "upload retained-file and retained-byte limits must also be bound",
        "upload storage capacity policy is not fully bound",
        "COALESCE(OLD.storage_object_version,OLD.storage_stage_version)",
        "SECURITY DEFINER",
        "SET search_path TO pg_catalog, %I, pg_temp",
        "REVOKE ALL ON FUNCTION %I.%I() FROM PUBLIC",
        "pg_catalog.count(*)=11",
        "'reserve_upload_cleanup_debt'",
    ] {
        assert!(
            migration.contains(required),
            "missing cascade-capacity invariant: {required}"
        );
    }
    assert_eq!(
        migration
            .matches("ADD COLUMN slot_delete_projection")
            .count(),
        1
    );
    assert_eq!(
        migration
            .matches("NEW.slot_delete_projection IS DISTINCT FROM OLD.slot_delete_projection")
            .count(),
        1
    );
    assert_eq!(
        migration
            .matches("IF pg_catalog.pg_trigger_depth()<=1 THEN")
            .count(),
        1
    );
    let delete_trigger = migration
        .split("CREATE OR REPLACE FUNCTION queue_upload_storage_delete()")
        .nth(1)
        .and_then(|tail| tail.split("$$ LANGUAGE plpgsql;").next())
        .expect("replacement upload delete trigger");
    assert!(delete_trigger.contains("TRUE"));
    assert!(!delete_trigger.contains("INSERT INTO upload_storage_jobs"));
    assert!(!delete_trigger.contains("DO UPDATE SET"));
    assert_eq!(
        delete_trigger
            .matches("GET DIAGNOSTICS inserted_count=ROW_COUNT")
            .count(),
        1
    );
    assert_eq!(delete_trigger.matches("existing upload ").count(), 1);
    assert!(delete_trigger.contains("queue.storage_fence=OLD.storage_fence"));
    assert_eq!(
        migration
            .matches("RAISE EXCEPTION 'upload storage capacity policy is not fully bound'")
            .count(),
        3
    );

    let storage_capacity = migration
        .split("CREATE OR REPLACE FUNCTION account_upload_storage_job_capacity()")
        .nth(1)
        .and_then(|tail| tail.split("$$ LANGUAGE plpgsql;").next())
        .expect("replacement storage-job capacity trigger");
    assert!(!storage_capacity.contains("slot_delete_projection"));
    assert!(storage_capacity.contains("IF NOT policy_bound THEN"));
    assert!(!storage_capacity.contains("AND configured_pending_limit IS NOT NULL"));
    let cleanup_capacity = migration
        .split("CREATE OR REPLACE FUNCTION account_upload_cleanup_capacity()")
        .nth(1)
        .and_then(|tail| tail.split("$$ LANGUAGE plpgsql;").next())
        .expect("replacement cleanup capacity trigger");
    assert!(cleanup_capacity.contains("locator_units"));
    assert!(cleanup_capacity.contains("IF NOT policy_bound THEN"));
    assert!(!cleanup_capacity.contains("AND configured_pending_limit IS NOT NULL"));

    // Deletion has exactly one queue authority. Neither application path
    // may race it by pre-inserting a second cleanup projection.
    for source in [
        include_str!("users.rs"),
        include_str!("../pie.rs"),
        include_str!("pie.rs"),
    ] {
        assert!(!source.contains("INSERT INTO upload_cleanup_queue"));
    }
    let account_delete = include_str!("users.rs")
        .split("async fn delete_user_with_roster_inner(")
        .nth(1)
        .and_then(|tail| {
            tail.split("pub(super) async fn delete_user_with_roster_locked_in_transaction(")
                .next()
        })
        .expect("self-service account deletion implementation");
    let capacity_lock = account_delete
        .find("SELECT northstar_upload_capacity_lock()")
        .expect("account deletion capacity lock");
    let mutation_timeout = account_delete
        .find("SET LOCAL lock_timeout='2s'")
        .expect("account deletion post-admission mutation timeout");
    assert!(
            !account_delete.contains("SET LOCAL lock_timeout='50ms'")
                && capacity_lock < mutation_timeout,
            "account deletion must use SQL-native NOWAIT capacity admission before its normal mutation bound"
        );
    let pie = include_str!("pie.rs");
    let capacity_lock = pie
        .find("SELECT northstar_upload_capacity_lock()")
        .expect("PIE replacement capacity lock");
    let domain_lock = pie
        .find("pg_advisory_xact_lock(hashtextextended($1, 227))")
        .expect("PIE domain lock");
    let user_lock = pie
        .find("SELECT id,is_admin FROM users WHERE username=$1 FOR UPDATE")
        .expect("PIE user lock");
    assert!(
        !pie.contains("SET LOCAL lock_timeout='50ms'")
            && capacity_lock < domain_lock
            && domain_lock < user_lock,
        "PIE must use SQL-native NOWAIT admission without shortening replacement work"
    );

    let upload_source = include_str!("upload.rs");
    let authority = include_str!("../../migrations/0113_upload_authority_capabilities.sql");
    for capability in [
        "northstar_upload_reserve_slot(",
        "northstar_upload_claim_slot(",
        "northstar_upload_record_stage(",
        "northstar_upload_complete_promotion(",
        "northstar_upload_admit_expired_cleanup(",
        "northstar_upload_delete_owned(",
    ] {
        assert!(
            authority.contains(&format!("CREATE FUNCTION {capability}")),
            "missing owner-held upload capability: {capability}"
        );
    }
    for invariant in [
        "ON CONFLICT(object_id,storage_attempt,action) DO NOTHING",
        "ON CONFLICT(object_id) DO NOTHING",
        "existing upload promotion projection has different identity",
        "existing upload cleanup projection differs or retained debt",
        "REVOKE ALL ON TABLE upload_storage_authority",
    ] {
        assert!(
            authority.contains(invariant),
            "missing upload invariant: {invariant}"
        );
    }
    // `upload_slots.content_type` is VARCHAR(255), while the public
    // capabilities intentionally expose TEXT. PL/pgSQL RETURN QUERY does
    // not apply that conversion implicitly, so every projection must keep
    // an explicit cast or the first PUT fails at runtime.
    assert_eq!(
        authority
            .matches("slot_row.content_type::pg_catalog.text")
            .count(),
        2,
        "upload claim replay/acquire projections must cast VARCHAR to TEXT"
    );
    assert!(
        authority.contains("slot.content_type::pg_catalog.text"),
        "public upload-file projection must cast VARCHAR to TEXT"
    );
    for (function_name, terminator) in [
        (
            "northstar_upload_confirm_cleanup_absence",
            "$northstar_upload_confirm_cleanup_absence$;",
        ),
        (
            "northstar_upload_confirm_stage_absence",
            "$northstar_upload_confirm_stage_absence$;",
        ),
    ] {
        let body = authority
            .split(&format!("CREATE FUNCTION {function_name}("))
            .nth(1)
            .and_then(|tail| tail.split(terminator).next())
            .expect("absence-fence capability");
        assert_eq!(
            body.matches("attempts=GREATEST(attempts-1,0)").count(),
            1,
            "a successful quiet-window observation must preserve retry capacity"
        );
    }
    let authorized_delete = upload_source
        .split("pub async fn queue_user_upload_delete_authorized(")
        .nth(1)
        .and_then(|tail| tail.split("#[cfg(test)]").next())
        .expect("authorized upload-delete implementation");
    let input_validation = authorized_delete
        .find("presented_session.len() != 64")
        .expect("authorized upload-delete bearer validation");
    let session_hash = authorized_delete
        .find("crate::auth::token_hash(presented_session)")
        .expect("authorized upload-delete bearer hashing");
    let capability = authorized_delete
        .find("northstar_upload_delete_owned")
        .expect("authorized upload-delete typed capability");
    assert!(input_validation < capability && capability < session_hash);
}

#[test]
fn upload_capability_lock_scope_matches_cleanup_debt_invariant() {
    let source = include_str!("upload.rs");
    let authority = include_str!("../../migrations/0113_upload_authority_capabilities.sql");
    let nowait = include_str!("../../migrations/0131_upload_capacity_nowait.sql");
    let trigger = nowait
        .split("CREATE OR REPLACE FUNCTION reserve_upload_cleanup_debt()")
        .nth(1)
        .and_then(|tail| {
            tail.split("$northstar_reserve_upload_cleanup_debt$;")
                .next()
        })
        .expect("cleanup-debt trigger definition");
    for condition in [
        "NOT OLD.storage_cleanup_debt_reserved",
        "(NEW.storage_object_key IS NOT NULL OR NEW.storage_stage_key IS NOT NULL)",
        "NOT EXISTS(",
        "PERFORM northstar_upload_require_capacity_lock()",
    ] {
        assert!(
            trigger.contains(condition),
            "cleanup-debt trigger must retain its precise admission condition: {condition}"
        );
    }
    let capacity_primitive = nowait
        .split("CREATE FUNCTION northstar_upload_require_capacity_lock()")
        .nth(1)
        .and_then(|tail| {
            tail.split("$northstar_upload_require_capacity_lock$;")
                .next()
        })
        .expect("private SQL-native capacity primitive");
    assert!(capacity_primitive.contains("FOR UPDATE NOWAIT"));
    assert!(capacity_primitive.contains("ERRCODE='55000'"));
    assert!(nowait.contains("CREATE FUNCTION guard_upload_capacity_nowait()"));
    for trigger_name in [
        "northstar_upload_capacity_nowait_slots_insert_delete",
        "northstar_upload_capacity_nowait_slot_locator_update",
        "northstar_upload_capacity_nowait_storage_job_insert_delete",
        "northstar_upload_capacity_nowait_cleanup_insert_delete",
    ] {
        assert!(
            nowait.contains(&format!("CREATE TRIGGER {trigger_name}")),
            "implicit capacity mutator must take the NOWAIT guard first: {trigger_name}"
        );
    }

    let claim_capability = authority
        .split("CREATE FUNCTION northstar_upload_claim_slot(")
        .nth(1)
        .and_then(|tail| tail.split("$northstar_upload_claim_slot$;").next())
        .expect("claim capability definition");
    let capacity_lock = claim_capability
        .find("FROM upload_storage_capacity_ledger")
        .expect("claim capability capacity lock");
    let first_debt_transition = claim_capability
        .find("SET uploading=TRUE,claim_token=new_claim")
        .expect("claim capability writes new attempt locators");
    assert!(
        capacity_lock < first_debt_transition
            && claim_capability.contains("storage_stage_key=new_stage_key")
            && claim_capability.contains("storage_object_key=new_object_key"),
        "only claim may introduce new locators, and it must acquire capacity first"
    );

    // Reservation and claim have no Rust lock-timeout wrapper. Their SQL
    // contracts preserve `false` and `in_progress` for both ledger and
    // later user/slot contention.
    for (name, next) in [
        (
            "create_upload_slot_bounded",
            "pub async fn validate_upload_storage_backend(",
        ),
        ("claim_upload_slot", "pub async fn renew_upload_claim("),
    ] {
        let body = source
            .split(&format!("pub async fn {name}("))
            .nth(1)
            .and_then(|tail| tail.split(next).next())
            .unwrap_or_else(|| panic!("{name} implementation"));
        assert!(
            !body.contains("lock_timeout") && !body.contains("northstar_upload_capacity_lock"),
            "{name} must rely exclusively on its typed SQL NOWAIT capability"
        );
    }

    let reserve = nowait
        .split("CREATE OR REPLACE FUNCTION northstar_upload_reserve_slot(")
        .nth(1)
        .and_then(|tail| tail.split("$northstar_upload_reserve_slot$;").next())
        .expect("replacement reserve capability");
    let reserve_ledger = reserve
        .find("FROM upload_storage_capacity_ledger\n         WHERE singleton FOR UPDATE NOWAIT")
        .expect("reserve capacity acquisition");
    let reserve_owner = reserve
        .find("users WHERE id=requested_user_id FOR UPDATE NOWAIT")
        .expect("reserve owner acquisition");
    let reserve_handler = reserve
        .find("WHEN lock_not_available THEN")
        .expect("reserve subtransaction contention handler");
    assert!(
            reserve_ledger < reserve_owner && reserve_owner < reserve_handler,
            "reserve must place ledger and owner NOWAIT acquisitions in one rollback-capable subtransaction"
        );
    assert!(
            reserve.contains("northstar_upload_reserve_slot_not_admitted")
                && reserve.contains("WHEN SQLSTATE 'P0001' THEN")
                && reserve.contains("GET STACKED DIAGNOSTICS caught_message = MESSAGE_TEXT"),
            "typed false outcomes must abort the capacity-acquiring subtransaction rather than retain its ledger lock"
        );
    let claim = nowait
        .split("CREATE OR REPLACE FUNCTION northstar_upload_claim_slot(")
        .nth(1)
        .and_then(|tail| tail.split("$northstar_upload_claim_slot$;").next())
        .expect("replacement claim capability");
    let claim_ledger = claim
        .find("FROM upload_storage_capacity_ledger\n       WHERE singleton FOR UPDATE NOWAIT")
        .expect("claim capacity acquisition");
    let claim_ledger_lock = claim[claim_ledger..]
        .find("FOR UPDATE NOWAIT;")
        .map(|offset| claim_ledger + offset)
        .expect("claim capacity lock clause");
    let claim_slot = claim[claim_ledger_lock + "FOR UPDATE NOWAIT;".len()..]
        .find("FOR UPDATE NOWAIT;")
        .map(|offset| claim_ledger_lock + "FOR UPDATE NOWAIT;".len() + offset)
        .expect("claim target-slot acquisition");
    let claim_handler = claim
        .find("WHEN lock_not_available THEN")
        .expect("claim subtransaction contention handler");
    assert!(
        claim_ledger < claim_ledger_lock
            && claim_ledger_lock < claim_slot
            && claim_slot < claim_handler,
        "claim must put ledger and slot NOWAIT acquisitions in one rollback-capable subtransaction"
    );
    assert!(
            claim.contains("northstar_upload_claim_slot_not_admitted")
                && claim.contains("WHEN SQLSTATE 'P0001' THEN")
                && claim.contains("RETURN NEXT;\n        RETURN;"),
            "typed claim outcomes must be emitted after rolling back the capacity-acquiring subtransaction"
        );

    // These state-only paths run only after claim established debt (or
    // while an exact same-slot cleanup projection exists).  They must stay
    // independent of unrelated capacity work.
    for (name, next) in [
        ("renew_upload_claim", "pub async fn release_upload_claim("),
        (
            "begin_upload_promotion",
            "pub async fn claim_upload_promotion_job(",
        ),
        ("record_upload_replay", "pub async fn uploaded_file("),
        (
            "claim_upload_scrub_jobs",
            "pub async fn complete_upload_scrub(",
        ),
        ("finish_upload_scrub", "#[cfg(test)]"),
    ] {
        let prefix = if name == "finish_upload_scrub" {
            "async fn"
        } else {
            "pub async fn"
        };
        let body = source
            .split(&format!("{prefix} {name}("))
            .nth(1)
            .and_then(|tail| tail.split(next).next())
            .unwrap_or_else(|| panic!("{name} implementation"));
        assert!(
            !body.contains("lock_timeout") && !body.contains("northstar_upload_capacity_lock"),
            "healthy {name} must not serialize on the global capacity ledger"
        );
    }

    for (function_name, terminator, proof) in [
        (
            "northstar_upload_renew_claim",
            "$northstar_upload_renew_claim$;",
            "storage_cleanup_debt_reserved",
        ),
        (
            "northstar_upload_begin_promotion",
            "$northstar_upload_begin_promotion$;",
            "storage_state IN ('staged','promoting')",
        ),
        (
            "northstar_upload_record_replay",
            "$northstar_upload_record_replay$;",
            "AND uploaded",
        ),
        (
            "northstar_upload_claim_scrub",
            "$northstar_upload_claim_scrub$;",
            "storage_state='committed'",
        ),
        (
            "northstar_upload_finish_scrub",
            "$northstar_upload_finish_scrub$;",
            "storage_scrub_claim_token=requested_claim",
        ),
    ] {
        let body = authority
            .split(&format!("CREATE FUNCTION {function_name}("))
            .nth(1)
            .and_then(|tail| tail.split(terminator).next())
            .unwrap_or_else(|| panic!("{function_name} definition"));
        assert!(
            body.contains(proof),
            "{function_name} must retain its state fence proving no new cleanup debt"
        );
    }

    for (name, next, capability) in [
        (
            "release_upload_claim",
            "/// Used by startup recovery",
            "northstar_upload_release_claim",
        ),
        (
            "record_upload_stage",
            "pub async fn begin_upload_promotion",
            "northstar_upload_record_stage",
        ),
        (
            "complete_promoted_upload",
            "/// Resolve the only benign",
            "northstar_upload_complete_promotion",
        ),
        (
            "retire_upload_promotion_for_cleanup",
            "#[cfg(test)]",
            "northstar_upload_retire_promotion_for_cleanup",
        ),
        (
            "cleanup_expired_upload_slots",
            "pub async fn queued_upload_cleanup",
            "northstar_upload_admit_expired_cleanup",
        ),
        (
            "complete_queued_upload_cleanup",
            "/// A deletion claimant",
            "northstar_upload_complete_cleanup",
        ),
        (
            "complete_upload_storage_job",
            "pub async fn confirm_upload_stage_absence",
            "northstar_upload_complete_storage_job",
        ),
        (
            "queue_user_upload_delete_authorized",
            "#[cfg(test)]",
            "northstar_upload_delete_owned",
        ),
    ] {
        let body = source
            .split(&format!("pub async fn {name}("))
            .nth(1)
            .and_then(|tail| tail.split(next).next())
            .unwrap_or_else(|| panic!("{name} implementation"));
        assert!(
            !body.contains("lock_timeout"),
            "{name} must rely on SQL-native NOWAIT capacity admission"
        );
        let definition = nowait
            .split(&format!("CREATE OR REPLACE FUNCTION {capability}("))
            .nth(1)
            .unwrap_or_else(|| panic!("{capability} migration definition"));
        assert!(
            definition.contains("PERFORM northstar_upload_require_capacity_lock();"),
            "{capability} must acquire the SQL-native capacity primitive first"
        );
    }
    let cleanup_completion = source
        .split("pub async fn complete_queued_upload_cleanup(")
        .nth(1)
        .and_then(|tail| {
            tail.split("pub async fn upload_cleanup_generation_is_quiescent(")
                .next()
        })
        .expect("upload cleanup completion implementation");
    assert!(
        cleanup_completion.contains("fetch_one(pool)")
            && !cleanup_completion.contains("lock_timeout"),
        "Run70 cleanup completion must expose SQL-native NOWAIT contention"
    );
    // Inspect the production portion only. The test's own literal
    // assertion names must not make a source-wide containment check
    // self-referential.
    let runtime_source = source
        .split("#[cfg(test)]\nmod tests")
        .next()
        .expect("production upload source before its test module");
    assert!(!runtime_source.contains("begin_bounded_upload_admission"));
    assert!(!runtime_source.contains("finish_retryable_upload_capacity_mutation"));
}

#[test]
fn upload_projection_release_migration_uses_predelete_last_owner_cas() {
    let migration = include_str!("../../migrations/0140_upload_projection_release_order.sql");
    for trigger in [
            "DROP TRIGGER upload_job_capacity_delete ON upload_storage_jobs;\nCREATE TRIGGER upload_job_capacity_delete\nBEFORE DELETE ON upload_storage_jobs",
            "DROP TRIGGER upload_cleanup_capacity_delete ON upload_cleanup_queue;\nCREATE TRIGGER upload_cleanup_capacity_delete\nBEFORE DELETE ON upload_cleanup_queue",
        ] {
            assert!(
                migration.contains(trigger),
                "upload projection release must make its delete trigger BEFORE DELETE: {trigger}"
            );
        }
    let storage_delete = migration
        .split("-- This is a BEFORE DELETE trigger.")
        .nth(1)
        .and_then(|tail| tail.split("$account_upload_storage_job_capacity$;").next())
        .expect("storage-job BEFORE DELETE body");
    assert!(storage_delete.contains("id<>OLD.id"));
    assert!(storage_delete
        .contains("recovery_retained_bytes=recovery_retained_bytes-OLD.expected_size"));
    let cleanup_delete = migration
        .split("-- `upload_cleanup_queue.object_id` is the primary key")
        .nth(1)
        .and_then(|tail| tail.split("$account_upload_cleanup_capacity$;").next())
        .expect("cleanup BEFORE DELETE body");
    assert!(cleanup_delete.contains("NOT EXISTS(SELECT 1 FROM upload_storage_jobs"));
    assert!(cleanup_delete.contains("locator_units*OLD.expected_size"));
    assert!(migration.contains(
        "upload projection delete triggers were not converted to exact BEFORE DELETE authority"
    ));
}

#[test]
fn upload_runtime_health_scans_are_bounded_and_timeout_fail_closed() {
    let migration = include_str!("../../migrations/0115_upload_runtime_reconciliation_bounds.sql");
    assert!(!migration.contains("public."));
    assert_eq!(migration.matches("LIMIT 1001").count(), 4);
    for invariant in [
        "CREATE INDEX IF NOT EXISTS upload_storage_jobs_dead_idx",
        "CREATE INDEX IF NOT EXISTS upload_cleanup_queue_recovery_dead_idx",
        "CREATE INDEX IF NOT EXISTS upload_slots_storage_scrub_failures_idx",
        "bounded_dead_letters",
        "bounded_scrub_failures",
        "1001 means at least 1001",
        "routine.proowner=migration_owner",
    ] {
        assert!(
            migration.contains(invariant),
            "missing runtime reconciliation bound: {invariant}"
        );
    }
    for invariant in [
        "REVOKE ALL ON FUNCTION %I.northstar_upload_queue_snapshot() FROM PUBLIC CASCADE",
        "WHERE routine.oid=routine_oid)<>1",
        "privilege.grantee<>routine.proowner",
        "privilege.grantor<>routine.proowner",
        "bounded upload queue snapshot has unsafe owner, language, search_path, or non-owner ACL",
    ] {
        assert!(
            migration.contains(invariant),
            "missing fail-closed runtime snapshot ACL guard: {invariant}"
        );
    }

    let source = include_str!("upload.rs");
    let reconciliation = source
        .split("pub async fn reconcile_upload_capacity_ledger(")
        .nth(1)
        .and_then(|tail| tail.split("/// Return a bounded snapshot").next())
        .expect("exact upload reconciliation implementation");
    for bound in [
        "SET TRANSACTION READ ONLY",
        "SET LOCAL lock_timeout='2s'",
        "SET LOCAL statement_timeout='15s'",
    ] {
        assert!(
            reconciliation.contains(bound),
            "missing exact-scan bound: {bound}"
        );
    }
    let snapshot = source
        .split("pub async fn upload_queue_metrics(")
        .nth(1)
        .and_then(|tail| tail.split("fn upload_queue_metrics_from_row").next())
        .expect("bounded upload metrics implementation");
    for bound in [
        "SET TRANSACTION READ ONLY",
        "SET LOCAL lock_timeout='1s'",
        "SET LOCAL statement_timeout='2s'",
    ] {
        assert!(
            snapshot.contains(bound),
            "missing health-scan bound: {bound}"
        );
    }
    let worker = include_str!("../upload_worker.rs");
    assert!(worker.contains("snapshot.dead_letter_jobs_capped"));
    assert!(worker.contains("snapshot.scrub_failures_capped"));
}

async fn insert_user(pool: &PgPool) -> Uuid {
    let id = Uuid::new_v4();
    let username = format!("upload-{}", &id.simple().to_string()[..16]);
    sqlx::query(
        "INSERT INTO users (id, username, password_hash, is_admin)
             VALUES ($1, $2, 'test-only', FALSE)",
    )
    .bind(id)
    .bind(username)
    .execute(pool)
    .await
    .unwrap();
    id
}

#[tokio::test]
#[ignore = "requires an isolated TEST_DATABASE_URL PostgreSQL database"]
async fn upload_queue_snapshot_reads_committed_changes_on_the_same_backend() {
    let url = std::env::var("TEST_DATABASE_URL").expect("set TEST_DATABASE_URL");
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
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
    sqlx::query("CREATE TEMP TABLE upload_storage_capacity_ledger(singleton bool)")
        .execute(&pool)
        .await
        .unwrap();
    let before = upload_queue_metrics(&pool).await.unwrap();
    let user_id = insert_user(&pool).await;
    let token = b"snapshot-current-data";
    let slot_id = create_upload_slot(
        &pool,
        UploadReservation {
            user_id,
            filename: "snapshot.bin",
            content_type: "application/octet-stream",
            size: 4,
            token_hash: token,
            max_files_per_user: 100,
            max_bytes_per_user: 1_000,
            storage_backend: "local",
        },
    )
    .await
    .unwrap()
    .unwrap();
    let lease = match claim_upload_slot(&pool, slot_id, token, 90).await.unwrap() {
        UploadClaimOutcome::Acquired(lease) => lease,
        other => panic!("unexpected upload claim outcome: {other:?}"),
    };
    let claimed = upload_queue_metrics(&pool).await.unwrap();
    assert_eq!(
        claimed.cleanup_obligation_debt,
        before.cleanup_obligation_debt + 1
    );
    assert!(release_upload_claim(&pool, slot_id, lease.claim_token)
        .await
        .unwrap());
    let released = upload_queue_metrics(&pool).await.unwrap();
    assert_eq!(
        released.cleanup_obligation_debt,
        before.cleanup_obligation_debt
    );
    assert_eq!(
        released.storage_jobs_pending,
        before.storage_jobs_pending + 1
    );
    sqlx::query("DELETE FROM upload_storage_jobs WHERE object_id=$1")
        .bind(slot_id)
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("DELETE FROM users WHERE id=$1")
        .bind(user_id)
        .execute(&pool)
        .await
        .unwrap();
    pool.close().await;
}

#[tokio::test]
#[ignore = "requires an isolated TEST_DATABASE_URL PostgreSQL database"]
async fn upload_claim_is_atomic_and_cleanup_is_retryable() {
    let url = std::env::var("TEST_DATABASE_URL")
        .expect("set TEST_DATABASE_URL to an isolated PostgreSQL database");
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(16)
        .connect(&url)
        .await
        .unwrap();
    db::migrate(&pool).await.unwrap();
    // Production binds this durable deployment authority in AppState
    // before opening any listener. Mirror that startup boundary here: an
    // unbound policy intentionally rejects every new cleanup obligation.
    validate_upload_capacity_policy(
        &pool,
        TEST_UPLOAD_PENDING_LIMIT,
        TEST_UPLOAD_RETAINED_FILES_LIMIT,
        TEST_UPLOAD_RETAINED_BYTES_LIMIT,
    )
    .await
    .unwrap();

    let user_id = insert_user(&pool).await;
    let token_hash = b"concurrent-test-token-hash".to_vec();
    let slot_id = create_upload_slot(
        &pool,
        UploadReservation {
            user_id,
            filename: "concurrent.bin",
            content_type: "application/octet-stream",
            size: 4,
            token_hash: &token_hash,
            max_files_per_user: 100,
            max_bytes_per_user: 1_000,
            storage_backend: "local",
        },
    )
    .await
    .unwrap()
    .unwrap();
    assert!(matches!(
        claim_upload_slot(&pool, slot_id, b"wrong-token", 90)
            .await
            .unwrap(),
        UploadClaimOutcome::Rejected
    ));

    let competitors = 12;
    let barrier = Arc::new(Barrier::new(competitors + 1));
    let mut tasks = Vec::with_capacity(competitors);
    for _ in 0..competitors {
        let pool = pool.clone();
        let barrier = barrier.clone();
        let token_hash = token_hash.clone();
        tasks.push(tokio::spawn(async move {
            barrier.wait().await;
            match claim_upload_slot(&pool, slot_id, &token_hash, 90)
                .await
                .unwrap()
            {
                UploadClaimOutcome::Acquired(lease) => Some(lease),
                _ => None,
            }
        }));
    }
    barrier.wait().await;
    let mut winners = Vec::new();
    for task in tasks {
        if let Some(lease) = task.await.unwrap() {
            winners.push(lease);
        }
    }
    assert_eq!(
        winners.len(),
        1,
        "exactly one concurrent PUT may claim a slot"
    );
    assert!(uploaded_file(&pool, slot_id).await.unwrap().is_none());
    let before_forgery: (i64, i64) = sqlx::query_as(
        "SELECT pending_jobs,cleanup_obligation_debt
             FROM upload_storage_capacity_ledger WHERE singleton",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    let forged_stage = format!("staging/{slot_id}/{}", winners[0].claim_token);
    let forged_error = sqlx::query(
        "INSERT INTO upload_cleanup_queue(
                 object_id,storage_backend,object_key,stage_key,storage_attempt,
                 expected_size,storage_fence,slot_delete_projection)
             VALUES($1,'local',$1::text,$3,$2,4,$4,TRUE)",
    )
    .bind(slot_id)
    .bind(winners[0].claim_token)
    .bind(&forged_stage)
    .bind(winners[0].storage_fence)
    .execute(&pool)
    .await
    .unwrap_err();
    assert!(
        matches!(&forged_error,sqlx::Error::Database(error)
                if error.code().as_deref()==Some("42501")),
        "direct writers must not forge slot-delete provenance: {forged_error}"
    );
    let after_forgery: (i64, i64) = sqlx::query_as(
        "SELECT pending_jobs,cleanup_obligation_debt
             FROM upload_storage_capacity_ledger WHERE singleton",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(after_forgery, before_forgery);

    // A mandatory retry-cleanup projection temporarily converts the
    // slot's debt. If cleanup completes before a replacement writer is
    // admitted, the DELETE trigger must hand that obligation back to the
    // still-live writing slot instead of leaving an unaccounted locator.
    sqlx::query(
        "INSERT INTO upload_storage_jobs(
                 object_id,storage_attempt,action,storage_backend,stage_key,
                 storage_fence,expected_size)
             VALUES($1,$2,'delete_stage','local',$3,$4,4)",
    )
    .bind(slot_id)
    .bind(winners[0].claim_token)
    .bind(&forged_stage)
    .bind(winners[0].storage_fence)
    .execute(&pool)
    .await
    .unwrap();
    let converted: (i64, i64, bool) = sqlx::query_as(
        "SELECT ledger.pending_jobs,ledger.cleanup_obligation_debt,
                    slot.storage_cleanup_debt_reserved
               FROM upload_storage_capacity_ledger ledger
               JOIN upload_slots slot ON slot.id=$1
              WHERE ledger.singleton",
    )
    .bind(slot_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(
        (converted.0, converted.1),
        (before_forgery.0 + 1, before_forgery.1 - 1)
    );
    assert!(!converted.2);
    sqlx::query(
        "DELETE FROM upload_storage_jobs
             WHERE object_id=$1 AND storage_attempt=$2 AND action='delete_stage'",
    )
    .bind(slot_id)
    .bind(winners[0].claim_token)
    .execute(&pool)
    .await
    .unwrap();
    let rearmed: (i64, i64, bool) = sqlx::query_as(
        "SELECT ledger.pending_jobs,ledger.cleanup_obligation_debt,
                    slot.storage_cleanup_debt_reserved
               FROM upload_storage_capacity_ledger ledger
               JOIN upload_slots slot ON slot.id=$1
              WHERE ledger.singleton",
    )
    .bind(slot_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!((rearmed.0, rearmed.1), before_forgery);
    assert!(rearmed.2);
    assert!(release_upload_claim(&pool, slot_id, winners[0].claim_token)
        .await
        .unwrap());
    let lease = match claim_upload_slot(&pool, slot_id, &token_hash, 90)
        .await
        .unwrap()
    {
        UploadClaimOutcome::Acquired(lease) => lease,
        other => panic!("unexpected upload claim outcome: {other:?}"),
    };
    let digest = [9_u8; 32];
    assert!(
        complete_upload(&pool, slot_id, lease.claim_token, &digest, 3_600)
            .await
            .unwrap()
    );
    assert!(uploaded_file(&pool, slot_id).await.unwrap().is_some());
    let expiry = sqlx::query(
        "SELECT EXTRACT(EPOCH FROM (put_expires_at-clock_timestamp()))::bigint AS put_seconds,
                    EXTRACT(EPOCH FROM (expires_at-clock_timestamp()))::bigint AS object_seconds
             FROM upload_slots WHERE id=$1",
    )
    .bind(slot_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    let put_seconds: i64 = expiry.get("put_seconds");
    let object_seconds: i64 = expiry.get("object_seconds");
    assert!((295..=300).contains(&put_seconds));
    assert!((3_590..=3_600).contains(&object_seconds));
    assert!(matches!(
        claim_upload_slot(&pool, slot_id, &token_hash, 90)
            .await
            .unwrap(),
        UploadClaimOutcome::Replay { content_sha256, .. } if content_sha256 == digest
    ));
    assert!(!release_upload_claim(&pool, slot_id, lease.claim_token)
        .await
        .unwrap());
    assert!(record_upload_replay(&pool, slot_id, &token_hash, &digest)
        .await
        .unwrap());
    assert!(
        !record_upload_replay(&pool, slot_id, &token_hash, &[8_u8; 32])
            .await
            .unwrap()
    );
    let replay_count: i64 = sqlx::query_scalar("SELECT replay_count FROM upload_slots WHERE id=$1")
        .bind(slot_id)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(replay_count, 1);
    for expected_count in 2..=3_i64 {
        assert!(matches!(
            claim_upload_slot(&pool, slot_id, &token_hash, 90)
                .await
                .unwrap(),
            UploadClaimOutcome::Replay { content_sha256, .. } if content_sha256 == digest
        ));
        assert!(record_upload_replay(&pool, slot_id, &token_hash, &digest)
            .await
            .unwrap());
        let count: i64 = sqlx::query_scalar("SELECT replay_count FROM upload_slots WHERE id=$1")
            .bind(slot_id)
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(count, expected_count);
    }
    assert!(matches!(
        claim_upload_slot(&pool, slot_id, &token_hash, 90)
            .await
            .unwrap(),
        UploadClaimOutcome::Rejected
    ));

    let legacy = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO upload_slots
             (id,user_id,filename,content_type,size,token_hash,expires_at,put_expires_at)
             VALUES($1,$2,'legacy.bin','application/octet-stream',4,$3,
                    clock_timestamp()+INTERVAL '1 hour',
                    clock_timestamp()+INTERVAL '5 minutes')",
    )
    .bind(legacy)
    .bind(user_id)
    .bind(b"legacy-token")
    .execute(&pool)
    .await
    .unwrap();
    // Materialize a schema-valid pre-digest legacy object through UPDATE,
    // so the cleanup-debt trigger reserves its eventual deletion exactly
    // as the 0091 backfill does. It remains unclaimable without a digest.
    sqlx::query(
        "UPDATE upload_slots
             SET uploaded=TRUE,storage_state='legacy_committed',
                 storage_object_key=id::text,storage_size=size
             WHERE id=$1",
    )
    .bind(legacy)
    .execute(&pool)
    .await
    .unwrap();
    assert!(matches!(
        claim_upload_slot(&pool, legacy, b"legacy-token", 90)
            .await
            .unwrap(),
        UploadClaimOutcome::Rejected
    ));

    let exhausted = create_upload_slot(
        &pool,
        UploadReservation {
            user_id,
            filename: "attempts.bin",
            content_type: "application/octet-stream",
            size: 4,
            token_hash: b"attempt-token",
            max_files_per_user: 100,
            max_bytes_per_user: 1_000,
            storage_backend: "local",
        },
    )
    .await
    .unwrap()
    .unwrap();
    for _ in 0..MAX_UPLOAD_ATTEMPTS {
        let lease = match claim_upload_slot(&pool, exhausted, b"attempt-token", 90)
            .await
            .unwrap()
        {
            UploadClaimOutcome::Acquired(lease) => lease,
            other => panic!("unexpected bounded-attempt outcome: {other:?}"),
        };
        assert!(release_upload_claim(&pool, exhausted, lease.claim_token)
            .await
            .unwrap());
    }
    assert!(matches!(
        claim_upload_slot(&pool, exhausted, b"attempt-token", 90)
            .await
            .unwrap(),
        UploadClaimOutcome::Rejected
    ));

    let fenced = create_upload_slot(
        &pool,
        UploadReservation {
            user_id,
            filename: "fenced.bin",
            content_type: "application/octet-stream",
            size: 4,
            token_hash: b"fenced-token",
            max_files_per_user: 100,
            max_bytes_per_user: 1_000,
            storage_backend: "local",
        },
    )
    .await
    .unwrap()
    .unwrap();
    let stale = match claim_upload_slot(&pool, fenced, b"fenced-token", 90)
        .await
        .unwrap()
    {
        UploadClaimOutcome::Acquired(lease) => lease,
        other => panic!("unexpected first fenced claim: {other:?}"),
    };
    assert!(matches!(
        claim_upload_slot(&pool, fenced, b"fenced-token", 90)
            .await
            .unwrap(),
        UploadClaimOutcome::InProgress { .. }
    ));
    sqlx::query(
        "UPDATE upload_slots SET claim_expires_at=clock_timestamp()-INTERVAL '1 second'
             WHERE id=$1",
    )
    .bind(fenced)
    .execute(&pool)
    .await
    .unwrap();
    let replacement = match claim_upload_slot(&pool, fenced, b"fenced-token", 90)
        .await
        .unwrap()
    {
        UploadClaimOutcome::Acquired(lease) => lease,
        other => panic!("unexpected replacement claim: {other:?}"),
    };
    assert_ne!(stale.claim_token, replacement.claim_token);
    assert_eq!(
        renew_upload_claim(&pool, fenced, stale.claim_token, 90)
            .await
            .unwrap(),
        UploadRenewOutcome::Lost
    );
    assert!(!release_upload_claim(&pool, fenced, stale.claim_token)
        .await
        .unwrap());
    assert!(
        !complete_upload(&pool, fenced, stale.claim_token, &[1_u8; 32], 3_600,)
            .await
            .unwrap()
    );
    assert!(
        complete_upload(&pool, fenced, replacement.claim_token, &[2_u8; 32], 3_600,)
            .await
            .unwrap()
    );

    let authorized_deletable = create_upload_slot(
        &pool,
        UploadReservation {
            user_id,
            filename: "authorized-delete.bin",
            content_type: "application/octet-stream",
            size: 7,
            token_hash: b"authorized-delete-token",
            max_files_per_user: 100,
            max_bytes_per_user: 1_000,
            storage_backend: "local",
        },
    )
    .await
    .unwrap()
    .unwrap();
    let live_session = db::create_api_session(&pool, user_id, 1).await.unwrap();
    assert_eq!(
        queue_user_upload_delete_authorized(
            &pool,
            user_id,
            0,
            &live_session,
            authorized_deletable,
            Uuid::new_v4(),
        )
        .await
        .unwrap(),
        UserUploadDeleteOutcome::Accepted
    );

    let stale_deletable = create_upload_slot(
        &pool,
        UploadReservation {
            user_id,
            filename: "stale-delete.bin",
            content_type: "application/octet-stream",
            size: 7,
            token_hash: b"stale-delete-token",
            max_files_per_user: 100,
            max_bytes_per_user: 1_000,
            storage_backend: "local",
        },
    )
    .await
    .unwrap()
    .unwrap();
    let stale_session = db::create_api_session(&pool, user_id, 1).await.unwrap();
    let mut logout = pool.begin().await.unwrap();
    assert!(
        db::delete_api_session_audited_in_tx(&mut logout, &stale_session, Uuid::new_v4(),)
            .await
            .unwrap()
    );
    logout.commit().await.unwrap();
    assert_eq!(
        queue_user_upload_delete_authorized(
            &pool,
            user_id,
            0,
            &stale_session,
            stale_deletable,
            Uuid::new_v4(),
        )
        .await
        .unwrap(),
        UserUploadDeleteOutcome::Unauthorized
    );
    assert!(sqlx::query("SELECT 1 FROM upload_slots WHERE id=$1")
        .bind(stale_deletable)
        .fetch_optional(&pool)
        .await
        .unwrap()
        .is_some());

    let deletable = create_upload_slot(
        &pool,
        UploadReservation {
            user_id,
            filename: "delete-me.bin",
            content_type: "application/octet-stream",
            size: 7,
            token_hash: b"delete-token",
            max_files_per_user: 100,
            max_bytes_per_user: 1_000,
            storage_backend: "local",
        },
    )
    .await
    .unwrap()
    .unwrap();
    let other_user = insert_user(&pool).await;
    assert!(
        !queue_user_upload_delete(&pool, other_user, deletable, Uuid::new_v4())
            .await
            .unwrap()
    );
    let delete_request = Uuid::new_v4();
    assert!(
        queue_user_upload_delete(&pool, user_id, deletable, delete_request)
            .await
            .unwrap()
    );
    assert!(
        !queue_user_upload_delete(&pool, user_id, deletable, Uuid::new_v4())
            .await
            .unwrap()
    );
    let delete_projection: (i64, i64) = sqlx::query_as(
        "SELECT
                 (SELECT COUNT(*) FROM upload_cleanup_queue WHERE object_id=$1),
                 (SELECT COUNT(*) FROM audit_log
                   WHERE actor_id=$2 AND action='user.upload.delete'
                     AND target=$1::text AND request_id=$3)",
    )
    .bind(deletable)
    .bind(user_id)
    .bind(delete_request)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(delete_projection, (0, 1));
    assert!(sqlx::query("SELECT 1 FROM upload_slots WHERE id=$1")
        .bind(deletable)
        .fetch_optional(&pool)
        .await
        .unwrap()
        .is_none());

    let expired = create_upload_slot(
        &pool,
        UploadReservation {
            user_id,
            filename: "expired.bin",
            content_type: "application/octet-stream",
            size: 1,
            token_hash: b"expired",
            max_files_per_user: 100,
            max_bytes_per_user: 1_000,
            storage_backend: "local",
        },
    )
    .await
    .unwrap()
    .unwrap();
    let active_expired = create_upload_slot(
        &pool,
        UploadReservation {
            user_id,
            filename: "active.bin",
            content_type: "application/octet-stream",
            size: 1,
            token_hash: b"active",
            max_files_per_user: 100,
            max_bytes_per_user: 1_000,
            storage_backend: "local",
        },
    )
    .await
    .unwrap()
    .unwrap();
    let abandoned = create_upload_slot(
        &pool,
        UploadReservation {
            user_id,
            filename: "abandoned.bin",
            content_type: "application/octet-stream",
            size: 1,
            token_hash: b"abandoned",
            max_files_per_user: 100,
            max_bytes_per_user: 1_000,
            storage_backend: "local",
        },
    )
    .await
    .unwrap()
    .unwrap();
    let active_claim = Uuid::new_v4();
    let abandoned_claim = Uuid::new_v4();
    let active_stage = format!("staging/{active_expired}/{active_claim}");
    let active_object = format!("objects/{active_expired}/{active_claim}");
    let abandoned_stage = format!("staging/{abandoned}/{abandoned_claim}");
    let abandoned_object = format!("objects/{abandoned}/{abandoned_claim}");
    sqlx::query(
        "UPDATE upload_slots
             SET expires_at = CASE
                 WHEN id = $1 THEN NOW() - INTERVAL '1 minute'
                 WHEN id = $2 THEN NOW() - INTERVAL '1 minute'
                 WHEN id = $3 THEN NOW() - INTERVAL '10 minutes'
                 ELSE expires_at
             END,
             uploading = id IN ($2, $3),
             claim_token = CASE
                 WHEN id = $2 THEN $4
                 WHEN id = $3 THEN $5
                 ELSE NULL
             END,
             claim_expires_at = CASE
                 WHEN id = $2 THEN clock_timestamp() + INTERVAL '1 minute'
                 WHEN id = $3 THEN clock_timestamp() - INTERVAL '9 minutes'
                 ELSE NULL
             END,
             storage_state = CASE WHEN id IN ($2,$3) THEN 'writing' ELSE 'reserved' END,
             storage_attempt = CASE WHEN id=$2 THEN $4 WHEN id=$3 THEN $5 ELSE NULL END,
             storage_stage_key = CASE WHEN id=$2 THEN $6 WHEN id=$3 THEN $8 ELSE NULL END,
             storage_object_key = CASE WHEN id=$2 THEN $7 WHEN id=$3 THEN $9 ELSE NULL END,
             storage_fence = CASE WHEN id IN ($2,$3) THEN storage_fence+1 ELSE storage_fence END
             WHERE id IN ($1, $2, $3)",
    )
    .bind(expired)
    .bind(active_expired)
    .bind(abandoned)
    .bind(active_claim)
    .bind(abandoned_claim)
    .bind(active_stage)
    .bind(active_object)
    .bind(abandoned_stage)
    .bind(abandoned_object)
    .execute(&pool)
    .await
    .unwrap();
    assert!(matches!(
        claim_upload_slot(&pool, expired, b"expired", 90)
            .await
            .unwrap(),
        UploadClaimOutcome::Rejected
    ));

    let candidates = cleanup_expired_upload_slots(&pool).await.unwrap();
    assert!(candidates.contains(&expired));
    assert!(candidates.contains(&abandoned));
    assert!(!candidates.contains(&active_expired));
    assert!(sqlx::query("SELECT 1 FROM upload_slots WHERE id=$1")
        .bind(expired)
        .fetch_optional(&pool)
        .await
        .unwrap()
        .is_none());
    let abandoned_quiet_period: bool = sqlx::query_scalar(
        "SELECT available_at>clock_timestamp()
             FROM upload_cleanup_queue WHERE object_id=$1",
    )
    .bind(abandoned)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert!(
        abandoned_quiet_period,
        "an expired in-flight writer keeps a durable delayed tombstone"
    );
    // Advance only this fixture past the external-I/O quiet period. The
    // worker must then be able to claim and complete the same tombstone.
    sqlx::query(
        "UPDATE upload_cleanup_queue SET available_at=clock_timestamp()
             WHERE object_id=$1",
    )
    .bind(abandoned)
    .execute(&pool)
    .await
    .unwrap();
    let cleanup = queued_upload_cleanup(&pool).await.unwrap();
    let abandoned_job = cleanup
        .iter()
        .find(|job| job.object_id == abandoned)
        .expect("abandoned upload has durable cleanup work");
    assert!(complete_queued_upload_cleanup(
        &pool,
        abandoned_job.object_id,
        abandoned_job.claim_token,
    )
    .await
    .unwrap());
    let active_still_exists: bool = sqlx::query("SELECT id FROM upload_slots WHERE id = $1")
        .bind(active_expired)
        .fetch_optional(&pool)
        .await
        .unwrap()
        .is_some();
    assert!(active_still_exists);

    let uploaded_still_exists: bool =
        sqlx::query("SELECT uploaded FROM upload_slots WHERE id = $1")
            .bind(slot_id)
            .fetch_one(&pool)
            .await
            .unwrap()
            .get("uploaded");
    assert!(uploaded_still_exists);

    sqlx::query("UPDATE upload_slots SET expires_at = NOW() - INTERVAL '1 second' WHERE id = $1")
        .bind(slot_id)
        .execute(&pool)
        .await
        .unwrap();
    assert!(uploaded_file(&pool, slot_id).await.unwrap().is_none());
    assert!(cleanup_expired_upload_slots(&pool)
        .await
        .unwrap()
        .contains(&slot_id));
    let cleanup = queued_upload_cleanup(&pool).await.unwrap();
    let uploaded_job = cleanup
        .iter()
        .find(|job| job.object_id == slot_id)
        .expect("uploaded object has durable cleanup work");
    assert!(complete_queued_upload_cleanup(
        &pool,
        uploaded_job.object_id,
        uploaded_job.claim_token,
    )
    .await
    .unwrap());

    let cascade_states: Vec<String> = sqlx::query_scalar(
        "SELECT storage_state FROM upload_slots
             WHERE id=ANY($1) ORDER BY storage_state",
    )
    .bind([active_expired, fenced, legacy])
    .fetch_all(&pool)
    .await
    .unwrap();
    assert_eq!(
        cascade_states,
        ["committed", "legacy_committed", "writing"],
        "account cascade fixture must cover every locator lifecycle"
    );
    let before_rollback: (i64, i64, i64, i64) = sqlx::query_as(
        "SELECT pending_jobs,cleanup_obligation_debt,
                    storage_jobs_pending,cleanup_jobs_pending
             FROM upload_storage_capacity_ledger WHERE singleton",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    let mut rolled_back_delete = pool.begin().await.unwrap();
    sqlx::query("DELETE FROM users WHERE id=$1")
        .bind(user_id)
        .execute(&mut *rolled_back_delete)
        .await
        .unwrap();
    rolled_back_delete.rollback().await.unwrap();
    let after_rollback: (i64, i64, i64, i64) = sqlx::query_as(
        "SELECT pending_jobs,cleanup_obligation_debt,
                    storage_jobs_pending,cleanup_jobs_pending
             FROM upload_storage_capacity_ledger WHERE singleton",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(after_rollback, before_rollback);

    sqlx::query("DELETE FROM users WHERE id = $1")
        .bind(user_id)
        .execute(&pool)
        .await
        .unwrap();
    let cascade_projection: (i64, i64, i64, i64, i64, i64, i64) = sqlx::query_as(
        "SELECT ledger.pending_jobs,ledger.cleanup_obligation_debt,
                    ledger.storage_jobs_pending,ledger.cleanup_jobs_pending,
                    (SELECT COUNT(*) FROM upload_storage_jobs),
                    (SELECT COUNT(*) FROM upload_cleanup_queue),
                    (SELECT COUNT(*) FROM upload_slots WHERE user_id=$1)
             FROM upload_storage_capacity_ledger ledger WHERE singleton",
    )
    .bind(user_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(
        cascade_projection.0,
        cascade_projection.4 + cascade_projection.5
    );
    assert_eq!(cascade_projection.1, 0);
    assert_eq!(cascade_projection.2, cascade_projection.4);
    assert_eq!(cascade_projection.3, cascade_projection.5);
    assert_eq!(cascade_projection.6, 0);
}

#[tokio::test]
#[ignore = "requires an isolated TEST_DATABASE_URL PostgreSQL database"]
async fn upload_cascade_converts_reserved_debt_at_the_hard_limit() {
    let url = std::env::var("TEST_DATABASE_URL")
        .expect("set TEST_DATABASE_URL to an isolated PostgreSQL database");
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(16)
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
    let baseline: (i64, i64) = sqlx::query_as(
        "SELECT pending_jobs,cleanup_obligation_debt
             FROM upload_storage_capacity_ledger WHERE singleton",
    )
    .fetch_one(&pool)
    .await
    .unwrap();

    let mut tx = pool.begin().await.unwrap();
    let user_id = Uuid::new_v4();
    let username = format!("upload-cascade-{}", &user_id.simple().to_string()[..12]);
    sqlx::query(
        "INSERT INTO users(id,username,password_hash,is_admin)
             VALUES($1,$2,'test-only',FALSE)",
    )
    .bind(user_id)
    .bind(username)
    .execute(&mut *tx)
    .await
    .unwrap();
    let slot_id = Uuid::new_v4();
    let attempt = Uuid::new_v4();
    let stage_key = format!("staging/{slot_id}/{attempt}");
    sqlx::query(
        "INSERT INTO upload_slots(
                 id,user_id,filename,content_type,size,token_hash,
                 expires_at,put_expires_at)
             VALUES($1,$2,'cascade.bin','application/octet-stream',1,$3,
                    clock_timestamp()+INTERVAL '1 hour',
                    clock_timestamp()+INTERVAL '5 minutes')",
    )
    .bind(slot_id)
    .bind(user_id)
    .bind(b"cascade-token")
    .execute(&mut *tx)
    .await
    .unwrap();
    sqlx::query(
        "UPDATE upload_slots
             SET uploading=TRUE,claim_token=$2,
                 claim_expires_at=clock_timestamp()+INTERVAL '1 minute',
                 storage_state='writing',storage_attempt=$2,
                 storage_stage_key=$3,storage_object_key=id::text,
                 storage_fence=storage_fence+1
             WHERE id=$1",
    )
    .bind(slot_id)
    .bind(attempt)
    .bind(&stage_key)
    .execute(&mut *tx)
    .await
    .unwrap();
    let before_fill: (i64, i64) = sqlx::query_as(
        "SELECT pending_jobs,cleanup_obligation_debt
             FROM upload_storage_capacity_ledger WHERE singleton",
    )
    .fetch_one(&mut *tx)
    .await
    .unwrap();
    assert_eq!(before_fill.1, baseline.1 + 1);
    let fill_count = TEST_UPLOAD_PENDING_LIMIT - before_fill.0 - before_fill.1;
    assert!(
        fill_count > 0,
        "test fixture unexpectedly starts over capacity"
    );
    for _ in 0..fill_count {
        let object_id = Uuid::new_v4();
        let filler_attempt = Uuid::new_v4();
        let filler_stage = format!("staging/{object_id}/{filler_attempt}");
        sqlx::query(
            "INSERT INTO upload_storage_jobs(
                     object_id,storage_attempt,action,storage_backend,
                     stage_key,storage_fence,expected_size)
                 VALUES($1,$2,'delete_stage','local',$3,0,1)",
        )
        .bind(object_id)
        .bind(filler_attempt)
        .bind(filler_stage)
        .execute(&mut *tx)
        .await
        .unwrap();
    }
    let at_limit: (i64, i64) = sqlx::query_as(
        "SELECT pending_jobs,cleanup_obligation_debt
             FROM upload_storage_capacity_ledger WHERE singleton",
    )
    .fetch_one(&mut *tx)
    .await
    .unwrap();
    assert_eq!(at_limit.0 + at_limit.1, TEST_UPLOAD_PENDING_LIMIT);

    sqlx::query("DELETE FROM users WHERE id=$1")
        .bind(user_id)
        .execute(&mut *tx)
        .await
        .unwrap();
    let converted: (i64, i64) = sqlx::query_as(
        "SELECT pending_jobs,cleanup_obligation_debt
             FROM upload_storage_capacity_ledger WHERE singleton",
    )
    .fetch_one(&mut *tx)
    .await
    .unwrap();
    assert_eq!(converted.0, at_limit.0 + 1);
    assert_eq!(converted.1, at_limit.1 - 1);
    assert_eq!(converted.0 + converted.1, TEST_UPLOAD_PENDING_LIMIT);
    assert!(sqlx::query_scalar::<_, bool>(
        "SELECT slot_delete_projection FROM upload_cleanup_queue
             WHERE object_id=$1 AND storage_attempt=$2
               AND object_key=$1::text AND stage_key=$3",
    )
    .bind(slot_id)
    .bind(attempt)
    .bind(&stage_key)
    .fetch_one(&mut *tx)
    .await
    .unwrap());

    let extra_id = Uuid::new_v4();
    let extra_attempt = Uuid::new_v4();
    let extra_stage = format!("staging/{extra_id}/{extra_attempt}");
    let capacity_error = sqlx::query(
        "INSERT INTO upload_storage_jobs(
                 object_id,storage_attempt,action,storage_backend,
                 stage_key,storage_fence,expected_size)
             VALUES($1,$2,'delete_stage','local',$3,0,1)",
    )
    .bind(extra_id)
    .bind(extra_attempt)
    .bind(extra_stage)
    .execute(&mut *tx)
    .await
    .unwrap_err();
    assert!(
        matches!(&capacity_error,sqlx::Error::Database(error)
                if error.code().as_deref()==Some("53300")),
        "fresh recovery admission must fail at the hard limit: {capacity_error}"
    );
    tx.rollback().await.unwrap();
    let after_rollback: (i64, i64) = sqlx::query_as(
        "SELECT pending_jobs,cleanup_obligation_debt
             FROM upload_storage_capacity_ledger WHERE singleton",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(after_rollback, baseline);
}

#[tokio::test]
#[ignore = "requires an isolated TEST_DATABASE_URL PostgreSQL database"]
async fn upload_recovery_capacity_counts_every_locator_and_releases_last_owner() {
    let url = std::env::var("TEST_DATABASE_URL")
        .expect("set TEST_DATABASE_URL to an isolated PostgreSQL database");
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(16)
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
    let baseline: (i64, i64, i64, i64, i64, i64, bool) = sqlx::query_as(
        "SELECT retained_files,retained_bytes,
                    recovery_retained_files,recovery_retained_bytes,
                    pending_jobs,cleanup_obligation_debt,recovery_overcommit_draining
               FROM upload_storage_capacity_ledger WHERE singleton",
    )
    .fetch_one(&pool)
    .await
    .unwrap();

    // Eight failed attempts for one object are eight possible physical
    // stages, even though the logical object owner remains exactly one.
    let object_id = Uuid::new_v4();
    let attempt_size = 25_i64 * 1024 * 1024;
    let mut attempts = Vec::new();
    for _ in 0..MAX_UPLOAD_ATTEMPTS {
        let attempt = Uuid::new_v4();
        let stage = format!("staging/{object_id}/{attempt}");
        sqlx::query(
            "INSERT INTO upload_storage_jobs(
                     object_id,storage_attempt,action,storage_backend,
                     stage_key,storage_fence,expected_size)
                 VALUES($1,$2,'delete_stage','local',$3,0,$4)",
        )
        .bind(object_id)
        .bind(attempt)
        .bind(stage)
        .bind(attempt_size)
        .execute(&pool)
        .await
        .unwrap();
        attempts.push(attempt);
    }
    let after_attempts: (i64, i64, i64, i64) = sqlx::query_as(
        "SELECT retained_files,retained_bytes,
                    recovery_retained_files,recovery_retained_bytes
               FROM upload_storage_capacity_ledger WHERE singleton",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(after_attempts.0, baseline.0 + 1);
    assert_eq!(after_attempts.1, baseline.1 + attempt_size);
    assert_eq!(after_attempts.2, baseline.2 + MAX_UPLOAD_ATTEMPTS);
    assert_eq!(
        after_attempts.3,
        baseline.3 + MAX_UPLOAD_ATTEMPTS * attempt_size
    );

    // Dead-lettering retains the exact physical obligation. It is not a
    // release event and cannot manufacture capacity for another upload.
    sqlx::query(
        "UPDATE upload_storage_jobs SET dead_lettered_at=clock_timestamp()
             WHERE object_id=$1 AND storage_attempt=$2 AND action='delete_stage'",
    )
    .bind(object_id)
    .bind(attempts[0])
    .execute(&pool)
    .await
    .unwrap();
    let after_dead_letter: (i64, i64) = sqlx::query_as(
        "SELECT recovery_retained_files,recovery_retained_bytes
               FROM upload_storage_capacity_ledger WHERE singleton",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(after_dead_letter, (after_attempts.2, after_attempts.3));

    // A local cleanup tombstone names a distinct object and stage: two
    // physical locator units. Since jobs already own the logical object,
    // inserting it must not add a second logical retained unit.
    let stage = format!("staging/{object_id}/{}", attempts[0]);
    sqlx::query(
        "INSERT INTO upload_cleanup_queue(
                 object_id,storage_backend,object_key,stage_key,storage_attempt,
                 expected_size,storage_fence)
             VALUES($1,'local',$1::text,$2,$3,$4,0)",
    )
    .bind(object_id)
    .bind(&stage)
    .bind(attempts[0])
    .bind(attempt_size)
    .execute(&pool)
    .await
    .unwrap();
    let with_cleanup: (i64, i64, i64) = sqlx::query_as(
        "SELECT retained_files,recovery_retained_files,recovery_retained_bytes
               FROM upload_storage_capacity_ledger WHERE singleton",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(with_cleanup.0, baseline.0 + 1);
    assert_eq!(with_cleanup.1, baseline.2 + MAX_UPLOAD_ATTEMPTS + 2);
    assert_eq!(
        with_cleanup.2,
        baseline.3 + (MAX_UPLOAD_ATTEMPTS + 2) * attempt_size
    );

    // Complete cleanup first and storage attempts in reverse order. The
    // logical retained unit stays until the final projection disappears.
    sqlx::query("DELETE FROM upload_cleanup_queue WHERE object_id=$1")
        .bind(object_id)
        .execute(&pool)
        .await
        .unwrap();
    for (index, attempt) in attempts.iter().rev().enumerate() {
        sqlx::query(
            "DELETE FROM upload_storage_jobs
                 WHERE object_id=$1 AND storage_attempt=$2 AND action='delete_stage'",
        )
        .bind(object_id)
        .bind(attempt)
        .execute(&pool)
        .await
        .unwrap();
        let logical: i64 = sqlx::query_scalar(
            "SELECT retained_files FROM upload_storage_capacity_ledger WHERE singleton",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(
            logical,
            baseline.0 + if index + 1 < attempts.len() { 1 } else { 0 },
            "only the last physical projection may release logical ownership"
        );
    }

    // Reverse admission/completion order on another object, and verify an
    // S3 same-key tombstone with the same exact version counts once.
    let reverse_id = Uuid::new_v4();
    let reverse_attempt = Uuid::new_v4();
    let reverse_stage = format!("staging/{reverse_id}/{reverse_attempt}");
    sqlx::query(
        "INSERT INTO upload_cleanup_queue(
                 object_id,storage_backend,object_key,stage_key,storage_attempt,
                 expected_size,storage_fence)
             VALUES($1,'local',$1::text,$2,$3,$4,0)",
    )
    .bind(reverse_id)
    .bind(&reverse_stage)
    .bind(reverse_attempt)
    .bind(attempt_size)
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO upload_storage_jobs(
                 object_id,storage_attempt,action,storage_backend,
                 stage_key,storage_fence,expected_size)
             VALUES($1,$2,'delete_stage','local',$3,0,$4)",
    )
    .bind(reverse_id)
    .bind(reverse_attempt)
    .bind(&reverse_stage)
    .bind(attempt_size)
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query("DELETE FROM upload_storage_jobs WHERE object_id=$1")
        .bind(reverse_id)
        .execute(&pool)
        .await
        .unwrap();
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT retained_files FROM upload_storage_capacity_ledger WHERE singleton"
        )
        .fetch_one(&pool)
        .await
        .unwrap(),
        baseline.0 + 1
    );
    sqlx::query("DELETE FROM upload_cleanup_queue WHERE object_id=$1")
        .bind(reverse_id)
        .execute(&pool)
        .await
        .unwrap();

    let s3_id = Uuid::new_v4();
    let s3_attempt = Uuid::new_v4();
    let s3_key = format!("objects/{s3_id}/{s3_attempt}");
    sqlx::query(
        "INSERT INTO upload_cleanup_queue(
                 object_id,storage_backend,object_key,object_version,
                 stage_key,stage_version,storage_attempt,expected_size,storage_fence)
             VALUES($1,'s3',$2,'version-1',$2,'version-1',$3,$4,0)",
    )
    .bind(s3_id)
    .bind(s3_key)
    .bind(s3_attempt)
    .bind(attempt_size)
    .execute(&pool)
    .await
    .unwrap();
    let s3_recovery_files: i64 = sqlx::query_scalar(
        "SELECT recovery_retained_files FROM upload_storage_capacity_ledger WHERE singleton",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(s3_recovery_files, baseline.2 + 1);
    sqlx::query("DELETE FROM upload_cleanup_queue WHERE object_id=$1")
        .bind(s3_id)
        .execute(&pool)
        .await
        .unwrap();

    // A promotion which appears after cleanup selection is a normal
    // quiescence race. Deferring releases the lease and restores attempts;
    // while the promotion exists the candidate query does not reclaim it.
    let quiet_id = Uuid::new_v4();
    let quiet_attempt = Uuid::new_v4();
    let quiet_stage = format!("staging/{quiet_id}/{quiet_attempt}");
    let quiet_digest = vec![7_u8; 32];
    sqlx::query(
        "INSERT INTO upload_cleanup_queue(
                 object_id,storage_backend,object_key,stage_key,storage_attempt,
                 expected_size,expected_sha256,storage_fence,available_at)
             VALUES($1,'local',$1::text,$2,$3,$4,$5,7,
                    clock_timestamp()-INTERVAL '100 years')",
    )
    .bind(quiet_id)
    .bind(&quiet_stage)
    .bind(quiet_attempt)
    .bind(attempt_size)
    .bind(&quiet_digest)
    .execute(&pool)
    .await
    .unwrap();
    let first_claim = queued_upload_cleanup(&pool)
        .await
        .unwrap()
        .into_iter()
        .find(|job| job.object_id == quiet_id)
        .expect("quiescence fixture cleanup claim");
    sqlx::query(
        "INSERT INTO upload_storage_jobs(
                 object_id,storage_attempt,action,storage_backend,
                 stage_key,object_key,expected_size,expected_sha256,storage_fence)
             VALUES($1,$2,'promote','local',$3,$1::text,$4,$5,7)",
    )
    .bind(quiet_id)
    .bind(quiet_attempt)
    .bind(&quiet_stage)
    .bind(attempt_size)
    .bind(&quiet_digest)
    .execute(&pool)
    .await
    .unwrap();
    assert!(
        !upload_cleanup_generation_is_quiescent(&pool, quiet_id, first_claim.claim_token, 7,)
            .await
            .unwrap()
    );
    assert!(
        defer_queued_upload_cleanup(&pool, quiet_id, first_claim.claim_token)
            .await
            .unwrap()
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT attempts FROM upload_cleanup_queue WHERE object_id=$1"
        )
        .bind(quiet_id)
        .fetch_one(&pool)
        .await
        .unwrap(),
        0
    );
    assert!(
        queued_upload_cleanup(&pool)
            .await
            .unwrap()
            .iter()
            .all(|job| job.object_id != quiet_id),
        "an exact promotion must keep cleanup out of the claimed batch"
    );
    sqlx::query("DELETE FROM upload_storage_jobs WHERE object_id=$1")
        .bind(quiet_id)
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query(
        "UPDATE upload_cleanup_queue
             SET available_at=clock_timestamp()-INTERVAL '100 years'
             WHERE object_id=$1",
    )
    .bind(quiet_id)
    .execute(&pool)
    .await
    .unwrap();
    let final_claim = queued_upload_cleanup(&pool)
        .await
        .unwrap()
        .into_iter()
        .find(|job| job.object_id == quiet_id)
        .expect("cleanup becomes claimable after promotion completion");
    assert!(
        complete_queued_upload_cleanup(&pool, quiet_id, final_claim.claim_token,)
            .await
            .unwrap()
    );

    // Mandatory recovery projections remain insertable above the byte
    // ceiling, enter draining, and block a fresh reservation. This models
    // eight maximum-size failed attempts without losing cleanup authority.
    let capacity_id = Uuid::new_v4();
    let capacity_size = TEST_UPLOAD_RETAINED_BYTES_LIMIT / MAX_UPLOAD_ATTEMPTS;
    for _ in 0..MAX_UPLOAD_ATTEMPTS {
        let attempt = Uuid::new_v4();
        sqlx::query(
            "INSERT INTO upload_storage_jobs(
                     object_id,storage_attempt,action,storage_backend,
                     stage_key,storage_fence,expected_size)
                 VALUES($1,$2,'delete_stage','local',$3,0,$4)",
        )
        .bind(capacity_id)
        .bind(attempt)
        .bind(format!("staging/{capacity_id}/{attempt}"))
        .bind(capacity_size)
        .execute(&pool)
        .await
        .unwrap();
    }
    assert!(sqlx::query_scalar::<_, bool>(
        "SELECT recovery_overcommit_draining
               FROM upload_storage_capacity_ledger WHERE singleton",
    )
    .fetch_one(&pool)
    .await
    .unwrap());
    let user_id = insert_user(&pool).await;
    assert!(
        create_upload_slot(
            &pool,
            UploadReservation {
                user_id,
                filename: "blocked-by-recovery.bin",
                content_type: "application/octet-stream",
                size: 1,
                token_hash: b"recovery-capacity",
                max_files_per_user: 10,
                max_bytes_per_user: 10,
                storage_backend: "local",
            },
        )
        .await
        .unwrap()
        .is_none(),
        "physical recovery debt must block fresh upload admission"
    );
    sqlx::query("DELETE FROM upload_storage_jobs WHERE object_id=$1")
        .bind(capacity_id)
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("DELETE FROM users WHERE id=$1")
        .bind(user_id)
        .execute(&pool)
        .await
        .unwrap();

    let final_ledger: (i64, i64, i64, i64, i64, i64, bool) = sqlx::query_as(
        "SELECT retained_files,retained_bytes,
                    recovery_retained_files,recovery_retained_bytes,
                    pending_jobs,cleanup_obligation_debt,recovery_overcommit_draining
               FROM upload_storage_capacity_ledger WHERE singleton",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(final_ledger, baseline);
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
    let migration = include_str!("../../migrations/0105_upload_cascade_cleanup_capacity.sql");
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

#[tokio::test]
#[ignore = "requires an isolated TEST_DATABASE_URL PostgreSQL database"]
async fn account_delete_and_upload_mutations_share_retryable_ledger_first_order() {
    let url = std::env::var("TEST_DATABASE_URL")
        .expect("set TEST_DATABASE_URL to an isolated PostgreSQL database");
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(8)
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
    let user_id = insert_user(&pool).await;
    let token = b"lock-order-token";
    let slot_id = create_upload_slot(
        &pool,
        UploadReservation {
            user_id,
            filename: "lock-order.bin",
            content_type: "application/octet-stream",
            size: 1,
            token_hash: token,
            max_files_per_user: 10,
            max_bytes_per_user: 10,
            storage_backend: "local",
        },
    )
    .await
    .unwrap()
    .unwrap();
    let active_lease = match claim_upload_slot(&pool, slot_id, token, 90).await.unwrap() {
        UploadClaimOutcome::Acquired(lease) => lease,
        other => panic!("unexpected initial upload claim outcome: {other:?}"),
    };

    // Model the prefix of account deletion: global ledger, then user.
    // Claim's SQL capability has a NOWAIT ledger admission; ordinary lease
    // renewal does not touch capacity authority. Generic capacity paths
    // and implicit trigger accounting must return SQLSTATE 55P03 without
    // waiting behind this owner.
    let mut account_tx = pool.begin().await.unwrap();
    sqlx::query("SELECT singleton FROM upload_storage_capacity_ledger WHERE singleton FOR UPDATE")
        .fetch_one(&mut *account_tx)
        .await
        .unwrap();
    sqlx::query("SELECT id FROM users WHERE id=$1 FOR UPDATE")
        .bind(user_id)
        .fetch_one(&mut *account_tx)
        .await
        .unwrap();
    assert!(matches!(
        claim_upload_slot(&pool, slot_id, token, 90).await.unwrap(),
        UploadClaimOutcome::InProgress { .. }
    ));
    assert_eq!(
        renew_upload_claim(&pool, slot_id, active_lease.claim_token, 90)
            .await
            .unwrap(),
        UploadRenewOutcome::Renewed,
        "a healthy lease renewal must remain independent of unrelated capacity work"
    );
    let queue_error = queue_user_upload_delete(&pool, user_id, slot_id, Uuid::new_v4())
        .await
        .unwrap_err();
    assert!(queue_error
        .to_string()
        .contains("upload storage capacity busy; retry"));
    let trigger_error = tokio::time::timeout(
        Duration::from_secs(1),
        sqlx::query(
            "INSERT INTO upload_cleanup_queue(
                     object_id,storage_backend,object_key,expected_size,storage_fence)
                 VALUES($1,'local',$1::text,1,0)",
        )
        .bind(Uuid::new_v4())
        .execute(&pool),
    )
    .await
    .expect("implicit cleanup accounting must reject a held ledger promptly")
    .unwrap_err();
    assert!(
        is_retryable_upload_capacity_lock(&trigger_error),
        "implicit upload cleanup accounting must expose SQLSTATE 55P03: {trigger_error}"
    );
    let completion_error = tokio::time::timeout(
        Duration::from_secs(1),
        complete_queued_upload_cleanup(&pool, Uuid::new_v4(), Uuid::new_v4()),
    )
    .await
    .expect("cleanup completion must reject ledger contention without waiting for the outer test")
    .unwrap_err();
    assert!(
            completion_error
                .chain()
                .filter_map(|cause| cause.downcast_ref::<sqlx::Error>())
                .any(is_retryable_upload_capacity_lock),
            "generic cleanup completion must preserve SQLSTATE 55P03 for central retry mapping: {completion_error:#}"
        );
    account_tx.rollback().await.unwrap();

    // A committed replay cannot establish another cleanup obligation: it
    // must remain available while unrelated work holds the singleton.
    let replay_digest = [7_u8; 32];
    assert!(complete_upload(
        &pool,
        slot_id,
        active_lease.claim_token,
        &replay_digest,
        600,
    )
    .await
    .unwrap());
    let mut healthy_tx = pool.begin().await.unwrap();
    sqlx::query("SELECT singleton FROM upload_storage_capacity_ledger WHERE singleton FOR UPDATE")
        .fetch_one(&mut *healthy_tx)
        .await
        .unwrap();
    assert!(
        tokio::time::timeout(
            Duration::from_secs(1),
            record_upload_replay(&pool, slot_id, token, &replay_digest),
        )
        .await
        .expect("committed replay must not wait for unrelated capacity authority")
        .unwrap(),
        "committed replay must retain normal dedupe accounting"
    );
    healthy_tx.rollback().await.unwrap();

    // `reserve_slot` takes ledger then user internally. Both acquisitions
    // are SQL NOWAIT, so user-row contention preserves the established
    // unavailable result and releases the singleton with no Rust-side
    // timeout or pre-acquisition.
    let mut user_tx = pool.begin().await.unwrap();
    sqlx::query("SELECT id FROM users WHERE id=$1 FOR UPDATE")
        .bind(user_id)
        .fetch_one(&mut *user_tx)
        .await
        .unwrap();
    let reservation = tokio::time::timeout(
        Duration::from_secs(1),
        create_upload_slot(
            &pool,
            UploadReservation {
                user_id,
                filename: "user-row-contention.bin",
                content_type: "application/octet-stream",
                size: 1,
                token_hash: b"user-row-contention",
                max_files_per_user: 10,
                max_bytes_per_user: 10,
                storage_backend: "local",
            },
        ),
    )
    .await
    .expect("reservation must not retain the ledger behind a user-row lock")
    .unwrap();
    assert!(reservation.is_none());
    sqlx::query(
        "SELECT singleton FROM upload_storage_capacity_ledger WHERE singleton FOR UPDATE NOWAIT",
    )
    .fetch_one(&pool)
    .await
    .expect("reservation contention must release the global ledger");
    user_tx.rollback().await.unwrap();

    // The same requirement applies to the sole debt-creating claim
    // transition: its SQL capability uses NOWAIT for both the ledger and
    // target slot, returning the established retry result without holding
    // the capability transaction behind either owner.
    let contention_slot = create_upload_slot(
        &pool,
        UploadReservation {
            user_id,
            filename: "slot-row-contention.bin",
            content_type: "application/octet-stream",
            size: 1,
            token_hash: b"slot-row-contention",
            max_files_per_user: 10,
            max_bytes_per_user: 10,
            storage_backend: "local",
        },
    )
    .await
    .unwrap()
    .unwrap();
    let mut slot_tx = pool.begin().await.unwrap();
    sqlx::query("SELECT id FROM upload_slots WHERE id=$1 FOR UPDATE")
        .bind(contention_slot)
        .fetch_one(&mut *slot_tx)
        .await
        .unwrap();
    let claim = tokio::time::timeout(
        Duration::from_secs(1),
        claim_upload_slot(&pool, contention_slot, b"slot-row-contention", 90),
    )
    .await
    .expect("claim must not retain the ledger behind a slot-row lock")
    .unwrap();
    assert!(matches!(
        claim,
        UploadClaimOutcome::InProgress {
            retry_after_seconds: 1
        }
    ));
    sqlx::query(
        "SELECT singleton FROM upload_storage_capacity_ledger WHERE singleton FOR UPDATE NOWAIT",
    )
    .fetch_one(&pool)
    .await
    .expect("claim contention must release the global ledger");
    slot_tx.rollback().await.unwrap();

    // Reverse pressure: a cleanup owner holds ledger then its queue row.
    // Account deletion must surface the SQL-native 55P03 before it locks
    // the user and can form a cycle.
    let cleanup_id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO upload_cleanup_queue(
                 object_id,storage_backend,object_key,expected_size,storage_fence)
             VALUES($1,'local',$1::text,1,0)",
    )
    .bind(cleanup_id)
    .execute(&pool)
    .await
    .unwrap();
    let mut cleanup_tx = pool.begin().await.unwrap();
    sqlx::query("SELECT singleton FROM upload_storage_capacity_ledger WHERE singleton FOR UPDATE")
        .fetch_one(&mut *cleanup_tx)
        .await
        .unwrap();
    sqlx::query("SELECT object_id FROM upload_cleanup_queue WHERE object_id=$1 FOR UPDATE")
        .bind(cleanup_id)
        .fetch_one(&mut *cleanup_tx)
        .await
        .unwrap();
    let delete_error = crate::db::users::delete_user_with_roster(&pool, user_id, "example.test")
        .await
        .unwrap_err();
    assert!(delete_error
        .to_string()
        .contains("upload storage capacity busy; retry account deletion"));
    cleanup_tx.rollback().await.unwrap();

    sqlx::query("DELETE FROM upload_cleanup_queue WHERE object_id=$1")
        .bind(cleanup_id)
        .execute(&pool)
        .await
        .unwrap();
    assert!(
        crate::db::users::delete_user_with_roster(&pool, user_id, "example.test",)
            .await
            .unwrap()
            .is_some()
    );
}

#[tokio::test]
#[ignore = "requires an isolated TEST_DATABASE_URL PostgreSQL database"]
async fn typed_upload_admission_results_release_capacity_lock_from_outer_transaction() {
    let url = std::env::var("TEST_DATABASE_URL")
        .expect("set TEST_DATABASE_URL to an isolated PostgreSQL database");
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(8)
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
    let user_id = insert_user(&pool).await;

    // Reserve obtains the ledger before it attempts the owner row.  Hold
    // that owner on one connection, retain the caller transaction after
    // its typed `false`, and prove another connection can still acquire
    // the ledger before either transaction completes.
    let mut owner_tx = pool.begin().await.unwrap();
    sqlx::query("SELECT id FROM users WHERE id=$1 FOR UPDATE")
        .bind(user_id)
        .fetch_one(&mut *owner_tx)
        .await
        .unwrap();
    let mut reserve_outer_tx = pool.begin().await.unwrap();
    let reserved: bool = sqlx::query_scalar(
        "SELECT northstar_upload_reserve_slot(
                 $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12
             )",
    )
    .bind(Uuid::new_v4())
    .bind(user_id)
    .bind("outer-transaction-reserve.bin")
    .bind("application/octet-stream")
    .bind(1_i64)
    .bind(b"outer-transaction-reserve".as_slice())
    .bind(10_i64)
    .bind(10_i64)
    .bind("local")
    .bind(TEST_UPLOAD_RETAINED_FILES_LIMIT)
    .bind(TEST_UPLOAD_RETAINED_BYTES_LIMIT)
    .bind(TEST_UPLOAD_PENDING_LIMIT)
    .fetch_one(&mut *reserve_outer_tx)
    .await
    .unwrap();
    assert!(
        !reserved,
        "owner-row NOWAIT contention must retain the established typed false result"
    );
    sqlx::query(
        "SELECT singleton FROM upload_storage_capacity_ledger
             WHERE singleton FOR UPDATE NOWAIT",
    )
    .fetch_one(&pool)
    .await
    .expect("typed reserve false must not retain the ledger in its outer transaction");
    reserve_outer_tx.rollback().await.unwrap();
    owner_tx.rollback().await.unwrap();

    // The same savepoint rollback is required for an ordinary quota
    // refusal, where the capacity and owner rows were both acquired but
    // no reservation was admitted.
    let slot_id = create_upload_slot(
        &pool,
        UploadReservation {
            user_id,
            filename: "outer-transaction-claim.bin",
            content_type: "application/octet-stream",
            size: 1,
            token_hash: b"outer-transaction-claim",
            max_files_per_user: 10,
            max_bytes_per_user: 10,
            storage_backend: "local",
        },
    )
    .await
    .unwrap()
    .unwrap();
    let mut reserve_quota_outer_tx = pool.begin().await.unwrap();
    let quota_reserved: bool = sqlx::query_scalar(
        "SELECT northstar_upload_reserve_slot(
                 $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12
             )",
    )
    .bind(Uuid::new_v4())
    .bind(user_id)
    .bind("outer-transaction-quota.bin")
    .bind("application/octet-stream")
    .bind(1_i64)
    .bind(b"outer-transaction-quota".as_slice())
    .bind(1_i64)
    .bind(10_i64)
    .bind("local")
    .bind(TEST_UPLOAD_RETAINED_FILES_LIMIT)
    .bind(TEST_UPLOAD_RETAINED_BYTES_LIMIT)
    .bind(TEST_UPLOAD_PENDING_LIMIT)
    .fetch_one(&mut *reserve_quota_outer_tx)
    .await
    .unwrap();
    assert!(
        !quota_reserved,
        "quota refusal must retain the established typed false result"
    );
    sqlx::query(
        "SELECT singleton FROM upload_storage_capacity_ledger
             WHERE singleton FOR UPDATE NOWAIT",
    )
    .fetch_one(&pool)
    .await
    .expect("ordinary reserve false must not retain the ledger in its outer transaction");
    reserve_quota_outer_tx.rollback().await.unwrap();

    // Claim follows the same ledger-then-slot order.  The slot owner and
    // caller remain open while a third pooled connection verifies that the
    // typed `in_progress` response rolled the capacity lock back.
    let mut slot_tx = pool.begin().await.unwrap();
    sqlx::query("SELECT id FROM upload_slots WHERE id=$1 FOR UPDATE")
        .bind(slot_id)
        .fetch_one(&mut *slot_tx)
        .await
        .unwrap();
    let mut claim_outer_tx = pool.begin().await.unwrap();
    let claim_outcome: String = sqlx::query_scalar(
        "SELECT outcome
               FROM northstar_upload_claim_slot($1,$2,$3,$4,$5)",
    )
    .bind(slot_id)
    .bind(b"outer-transaction-claim".as_slice())
    .bind(90_i64)
    .bind(MAX_UPLOAD_ATTEMPTS)
    .bind(MAX_UPLOAD_REPLAYS)
    .fetch_one(&mut *claim_outer_tx)
    .await
    .unwrap();
    assert_eq!(claim_outcome, "in_progress");
    sqlx::query(
        "SELECT singleton FROM upload_storage_capacity_ledger
             WHERE singleton FOR UPDATE NOWAIT",
    )
    .fetch_one(&pool)
    .await
    .expect("typed claim in_progress must not retain the ledger in its outer transaction");
    claim_outer_tx.rollback().await.unwrap();
    slot_tx.rollback().await.unwrap();

    // Finally, verify the ordinary live-lease `in_progress` result.  It
    // is not a lock conflict, but it must take the same rollback path
    // rather than keeping the global authority for the caller's outer
    // transaction.
    let active_lease = match claim_upload_slot(&pool, slot_id, b"outer-transaction-claim", 90)
        .await
        .unwrap()
    {
        UploadClaimOutcome::Acquired(lease) => lease,
        other => panic!("unexpected initial claim outcome: {other:?}"),
    };
    let mut live_claim_outer_tx = pool.begin().await.unwrap();
    let live_claim_outcome: String = sqlx::query_scalar(
        "SELECT outcome
               FROM northstar_upload_claim_slot($1,$2,$3,$4,$5)",
    )
    .bind(slot_id)
    .bind(b"outer-transaction-claim".as_slice())
    .bind(90_i64)
    .bind(MAX_UPLOAD_ATTEMPTS)
    .bind(MAX_UPLOAD_REPLAYS)
    .fetch_one(&mut *live_claim_outer_tx)
    .await
    .unwrap();
    assert_eq!(live_claim_outcome, "in_progress");
    sqlx::query(
        "SELECT singleton FROM upload_storage_capacity_ledger
             WHERE singleton FOR UPDATE NOWAIT",
    )
    .fetch_one(&pool)
    .await
    .expect("ordinary claim in_progress must not retain the ledger in its outer transaction");
    live_claim_outer_tx.rollback().await.unwrap();
    assert!(
        release_upload_claim(&pool, slot_id, active_lease.claim_token)
            .await
            .unwrap()
    );
}

#[tokio::test]
#[ignore = "requires an isolated TEST_DATABASE_URL PostgreSQL database"]
async fn upload_quota_reservation_is_serialized_and_expiry_releases_capacity() {
    let url = std::env::var("TEST_DATABASE_URL")
        .expect("set TEST_DATABASE_URL to an isolated PostgreSQL database");
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(16)
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
    let user_id = insert_user(&pool).await;

    let competitors = 12;
    let barrier = Arc::new(Barrier::new(competitors + 1));
    let mut tasks = Vec::with_capacity(competitors);
    for attempt in 0..competitors {
        let pool = pool.clone();
        let barrier = barrier.clone();
        tasks.push(tokio::spawn(async move {
            barrier.wait().await;
            create_upload_slot(
                &pool,
                UploadReservation {
                    user_id,
                    filename: &format!("quota-{attempt}.bin"),
                    content_type: "application/octet-stream",
                    size: 6,
                    token_hash: format!("token-{attempt}").as_bytes(),
                    max_files_per_user: 100,
                    max_bytes_per_user: 10,
                    storage_backend: "local",
                },
            )
            .await
            .unwrap()
        }));
    }
    barrier.wait().await;
    let mut winners = Vec::new();
    for task in tasks {
        if let Some(id) = task.await.unwrap() {
            winners.push(id);
        }
    }
    assert_eq!(
        winners.len(),
        1,
        "quota check and reservation must be atomic"
    );
    assert!(
        create_upload_slot(
            &pool,
            UploadReservation {
                user_id,
                filename: "blocked.bin",
                content_type: "application/octet-stream",
                size: 4,
                token_hash: b"blocked",
                max_files_per_user: 1,
                max_bytes_per_user: 100,
                storage_backend: "local",
            },
        )
        .await
        .unwrap()
        .is_none(),
        "an active reservation consumes the file-count quota",
    );

    sqlx::query("UPDATE upload_slots SET expires_at=NOW()-INTERVAL '1 second' WHERE id=$1")
        .bind(winners[0])
        .execute(&pool)
        .await
        .unwrap();
    assert!(
        create_upload_slot(
            &pool,
            UploadReservation {
                user_id,
                filename: "released.bin",
                content_type: "application/octet-stream",
                size: 10,
                token_hash: b"released",
                max_files_per_user: 1,
                max_bytes_per_user: 10,
                storage_backend: "local",
            },
        )
        .await
        .unwrap()
        .is_none(),
        "expired rows continue consuming physical quota until durable cleanup completes",
    );

    sqlx::query("DELETE FROM users WHERE id = $1")
        .bind(user_id)
        .execute(&pool)
        .await
        .unwrap();
}
