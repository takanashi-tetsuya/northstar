//! Upload capacity authority audit, ledger reconciliation and queue metrics.

use super::*;

/// Verify the live PostgreSQL authority which makes the O(1) capacity ledger
/// trustworthy. This is intentionally observation-only: a mismatch is
/// evidence to preserve, never permission for the online worker to repair DDL
/// or rewrite counters.
pub async fn audit_upload_capacity_authority(
    pool: &PgPool,
    pending_limit: i64,
    retained_files_limit: i64,
    retained_bytes_limit: i64,
) -> Result<UploadCapacityAuthorityAudit> {
    let mut tx = pool.begin().await?;
    sqlx::query("SET TRANSACTION READ ONLY")
        .execute(&mut *tx)
        .await?;
    sqlx::query("SET LOCAL statement_timeout='5s'")
        .execute(&mut *tx)
        .await?;
    let row = sqlx::query(
        r#"WITH installation AS (
             SELECT pg_catalog.current_schema() AS schema_name
           ), expected_relations(relation_name) AS (
             VALUES ('upload_slots'),('upload_storage_authority'),
                    ('upload_storage_jobs'),('upload_cleanup_queue'),
                    ('upload_storage_capacity_ledger')
           ), relation_state AS (
             SELECT expected.relation_name,relation_row.oid,
                    relation_row.relowner,relation_schema.nspowner
               FROM installation
               CROSS JOIN expected_relations expected
               LEFT JOIN pg_catalog.pg_namespace relation_schema
                 ON relation_schema.nspname=installation.schema_name
               LEFT JOIN pg_catalog.pg_class relation_row
                 ON relation_row.relnamespace=relation_schema.oid
                AND relation_row.relname=expected.relation_name
                AND relation_row.relkind IN ('r','p')
           ), expected_functions(function_name,security_definer) AS (
             VALUES
               ('queue_upload_storage_delete',TRUE),
               ('reserve_upload_cleanup_debt',TRUE),
               ('account_upload_slot_capacity',TRUE),
               ('account_upload_storage_job_capacity',TRUE),
               ('account_upload_cleanup_capacity',TRUE),
               ('guard_upload_capacity_nowait',TRUE),
               ('protect_upload_storage_job_identity',FALSE),
               ('protect_upload_cleanup_identity',FALSE),
               ('protect_upload_capacity_policy',FALSE)
           ), function_state AS (
             SELECT expected.function_name,expected.security_definer,
                    function_row.oid,function_row.proowner,function_row.prosecdef,
                    function_row.prorettype,language_row.lanname,
                    relation_schema.nspowner,
                    COALESCE(function_row.proconfig,ARRAY[]::pg_catalog.text[])=
                      ARRAY[pg_catalog.format(
                        'search_path=pg_catalog, %I, pg_temp',
                        installation.schema_name
                      )]::pg_catalog.text[] AS search_path_exact,
                    CASE WHEN function_row.oid IS NULL THEN FALSE ELSE NOT EXISTS(
                      SELECT 1
                        FROM pg_catalog.aclexplode(COALESCE(
                          function_row.proacl,
                          pg_catalog.acldefault('f',function_row.proowner)
                        )) privilege
                       WHERE privilege.grantee=0
                         AND privilege.privilege_type='EXECUTE'
                    ) END AS public_execute_revoked
               FROM installation
               CROSS JOIN expected_functions expected
               LEFT JOIN pg_catalog.pg_namespace relation_schema
                 ON relation_schema.nspname=installation.schema_name
               LEFT JOIN pg_catalog.pg_proc function_row
                 ON function_row.pronamespace=relation_schema.oid
                AND function_row.proname=expected.function_name
                AND function_row.pronargs=0
               LEFT JOIN pg_catalog.pg_language language_row
                 ON language_row.oid=function_row.prolang
           ), expected_triggers(
                relation_name,trigger_name,function_name,function_signature,trigger_type,
                attachment_count
           ) AS (
             VALUES
               ('upload_slots','upload_storage_delete_queue',
                'queue_upload_storage_delete','queue_upload_storage_delete()',11,1),
               ('upload_slots','upload_slot_cleanup_debt_reserve',
                'reserve_upload_cleanup_debt','reserve_upload_cleanup_debt()',19,1),
               ('upload_slots','upload_slot_capacity_insert',
                'account_upload_slot_capacity','account_upload_slot_capacity()',5,2),
               ('upload_slots','upload_slot_capacity_delete',
                'account_upload_slot_capacity','account_upload_slot_capacity()',9,2),
               ('upload_slots','northstar_upload_capacity_nowait_slots_insert_delete',
                'guard_upload_capacity_nowait','guard_upload_capacity_nowait()',15,4),
               ('upload_slots','northstar_upload_capacity_nowait_slot_locator_update',
                'guard_upload_capacity_nowait','guard_upload_capacity_nowait()',19,4),
               ('upload_storage_jobs','upload_job_capacity_insert',
                'account_upload_storage_job_capacity','account_upload_storage_job_capacity()',5,2),
               ('upload_storage_jobs','upload_job_capacity_delete',
                'account_upload_storage_job_capacity','account_upload_storage_job_capacity()',11,2),
               ('upload_storage_jobs','northstar_upload_capacity_nowait_storage_job_insert_delete',
                'guard_upload_capacity_nowait','guard_upload_capacity_nowait()',15,4),
               ('upload_cleanup_queue','upload_cleanup_capacity_insert',
                'account_upload_cleanup_capacity','account_upload_cleanup_capacity()',5,2),
               ('upload_cleanup_queue','upload_cleanup_capacity_delete',
                'account_upload_cleanup_capacity','account_upload_cleanup_capacity()',11,2),
               ('upload_cleanup_queue','northstar_upload_capacity_nowait_cleanup_insert_delete',
                'guard_upload_capacity_nowait','guard_upload_capacity_nowait()',15,4),
               ('upload_storage_jobs','upload_storage_job_identity_guard',
                'protect_upload_storage_job_identity','protect_upload_storage_job_identity()',19,1),
               ('upload_cleanup_queue','upload_cleanup_identity_guard',
                'protect_upload_cleanup_identity','protect_upload_cleanup_identity()',19,1),
               ('upload_storage_capacity_ledger','upload_capacity_policy_guard',
                'protect_upload_capacity_policy','protect_upload_capacity_policy()',19,1)
           ), trigger_state AS (
             SELECT expected.*,
                    (SELECT pg_catalog.count(*)
                       FROM pg_catalog.pg_trigger trigger_row
                       JOIN pg_catalog.pg_class relation_row
                         ON relation_row.oid=trigger_row.tgrelid
                       JOIN pg_catalog.pg_namespace relation_schema
                         ON relation_schema.oid=relation_row.relnamespace
                       JOIN pg_catalog.pg_proc function_row
                         ON function_row.oid=trigger_row.tgfoid
                       JOIN pg_catalog.pg_namespace function_schema
                         ON function_schema.oid=function_row.pronamespace
                      WHERE relation_schema.nspname=installation.schema_name
                        AND relation_row.relname=expected.relation_name
                        AND trigger_row.tgname=expected.trigger_name
                        AND NOT trigger_row.tgisinternal
                        AND trigger_row.tgenabled IN ('O','A')
                        AND trigger_row.tgqual IS NULL
                        AND trigger_row.tgtype::pg_catalog.int4=
                            expected.trigger_type
                        AND function_schema.nspname=installation.schema_name
                        AND function_row.oid=pg_catalog.to_regprocedure(
                          pg_catalog.format('%I.%s',
                            installation.schema_name,expected.function_signature)
                        )
                        AND function_row.prorettype=
                            'pg_catalog.trigger'::pg_catalog.regtype
                    ) AS exact_matches,
                    (SELECT pg_catalog.count(*)
                       FROM pg_catalog.pg_trigger attachment
                       JOIN pg_catalog.pg_proc attached_function
                         ON attached_function.oid=attachment.tgfoid
                       JOIN pg_catalog.pg_namespace function_schema
                         ON function_schema.oid=attached_function.pronamespace
                      WHERE function_schema.nspname=installation.schema_name
                        AND attached_function.oid=pg_catalog.to_regprocedure(
                          pg_catalog.format('%I.%s',
                            installation.schema_name,expected.function_signature)
                        )
                        AND NOT attachment.tgisinternal
                    ) AS actual_attachments
               FROM installation
               CROSS JOIN expected_triggers expected
           )
           SELECT
             (SELECT pg_catalog.count(*) FILTER (
                       WHERE oid IS NULL
                          OR relowner IS DISTINCT FROM nspowner
                     ) FROM relation_state) AS relation_owner_violations,
             (SELECT pg_catalog.count(*) FILTER (
                       WHERE oid IS NULL OR EXISTS(
                         SELECT 1 FROM pg_catalog.aclexplode(COALESCE(
                           (SELECT relation_acl.relacl
                              FROM pg_catalog.pg_class relation_acl
                             WHERE relation_acl.oid=relation_state.oid),
                           pg_catalog.acldefault('r',relation_state.relowner)
                         )) privilege
                          WHERE privilege.grantee=0
                       )
                     ) FROM relation_state) AS relation_acl_violations,
             ((SELECT pg_catalog.count(*) FILTER (
                       WHERE oid IS NULL
                          OR proowner IS DISTINCT FROM nspowner
                          OR prosecdef IS DISTINCT FROM security_definer
                          OR prorettype IS DISTINCT FROM
                              'pg_catalog.trigger'::pg_catalog.regtype
                          OR lanname IS DISTINCT FROM 'plpgsql'
                          OR NOT search_path_exact
                          OR NOT public_execute_revoked
                     ) FROM function_state)
               +(CASE WHEN northstar_upload_capability_catalog_healthy(
                    (SELECT schema_name FROM installation)
                  ) THEN 0 ELSE 1 END)::pg_catalog.int8)
                AS function_authority_violations,
             (SELECT pg_catalog.count(*) FILTER (
                       WHERE exact_matches<>1
                          OR actual_attachments<>attachment_count
                     ) FROM trigger_state) AS trigger_authority_violations,
             (CASE WHEN northstar_upload_policy_binding_matches($1,$2,$3)
                   THEN 0 ELSE 1 END)::pg_catalog.int8
               AS policy_binding_violations"#,
    )
    .bind(pending_limit)
    .bind(retained_files_limit)
    .bind(retained_bytes_limit)
    .fetch_one(&mut *tx)
    .await?;
    let audit = UploadCapacityAuthorityAudit {
        relation_owner_violations: row.try_get("relation_owner_violations")?,
        relation_acl_violations: row.try_get("relation_acl_violations")?,
        function_authority_violations: row.try_get("function_authority_violations")?,
        trigger_authority_violations: row.try_get("trigger_authority_violations")?,
        policy_binding_violations: row.try_get("policy_binding_violations")?,
    };
    tx.commit().await?;
    Ok(audit)
}

/// Recompute every mutable upload-capacity counter from immutable row facts in
/// one PostgreSQL statement snapshot. A mismatch is evidence of trigger/ACL
/// bypass or corruption and must make readiness unhealthy; automatic repair
/// would erase the evidence and can under-account physical object debt.
pub async fn reconcile_upload_capacity_ledger(
    pool: &PgPool,
) -> Result<UploadCapacityReconciliation> {
    let mut tx = pool.begin().await?;
    sqlx::query("SET TRANSACTION READ ONLY")
        .execute(&mut *tx)
        .await?;
    // This exact fact scan is deliberately low-frequency, but it must still
    // relinquish its pool connection under DDL contention or a pathological
    // plan. The caller treats either timeout as an unsafe ledger and closes
    // readiness/object I/O rather than silently keeping the previous result.
    sqlx::query("SET LOCAL lock_timeout='2s'")
        .execute(&mut *tx)
        .await?;
    sqlx::query("SET LOCAL statement_timeout='15s'")
        .execute(&mut *tx)
        .await?;
    let row = sqlx::query("SELECT * FROM northstar_upload_capacity_reconciliation()")
        .fetch_one(&mut *tx)
        .await?;
    let reconciliation = UploadCapacityReconciliation {
        ledger_retained_files: row.try_get("ledger_retained_files")?,
        fact_retained_files: row.try_get("fact_retained_files")?,
        ledger_retained_bytes: row.try_get("ledger_retained_bytes")?,
        fact_retained_bytes: row.try_get("fact_retained_bytes")?,
        ledger_pending_jobs: row.try_get("ledger_pending_jobs")?,
        fact_pending_jobs: row.try_get("fact_pending_jobs")?,
        ledger_storage_jobs_pending: row.try_get("ledger_storage_jobs_pending")?,
        fact_storage_jobs_pending: row.try_get("fact_storage_jobs_pending")?,
        ledger_cleanup_jobs_pending: row.try_get("ledger_cleanup_jobs_pending")?,
        fact_cleanup_jobs_pending: row.try_get("fact_cleanup_jobs_pending")?,
        ledger_cleanup_obligation_debt: row.try_get("ledger_cleanup_obligation_debt")?,
        fact_cleanup_obligation_debt: row.try_get("fact_cleanup_obligation_debt")?,
        ledger_recovery_retained_files: row.try_get("ledger_recovery_retained_files")?,
        fact_recovery_retained_files: row.try_get("fact_recovery_retained_files")?,
        ledger_recovery_retained_bytes: row.try_get("ledger_recovery_retained_bytes")?,
        fact_recovery_retained_bytes: row.try_get("fact_recovery_retained_bytes")?,
        ledger_legacy_overcommit_draining: row.try_get("ledger_legacy_overcommit_draining")?,
        fact_legacy_overcommit_draining: row.try_get("fact_legacy_overcommit_draining")?,
        ledger_recovery_overcommit_draining: row.try_get("ledger_recovery_overcommit_draining")?,
        fact_recovery_overcommit_draining: row.try_get("fact_recovery_overcommit_draining")?,
        projection_size_conflicts: row.try_get("projection_size_conflicts")?,
    };
    tx.commit().await?;
    Ok(reconciliation)
}

/// Return a bounded snapshot of durable upload work. The two potentially large
/// exceptional populations saturate at 1001. The worker refreshes these
/// gauges; the metrics HTTP handler never queries PostgreSQL.
pub async fn upload_queue_metrics(pool: &PgPool) -> Result<UploadQueueMetrics> {
    let mut tx = pool.begin().await?;
    sqlx::query("SET TRANSACTION READ ONLY")
        .execute(&mut *tx)
        .await?;
    sqlx::query("SET LOCAL lock_timeout='1s'")
        .execute(&mut *tx)
        .await?;
    sqlx::query("SET LOCAL statement_timeout='2s'")
        .execute(&mut *tx)
        .await?;
    let row = sqlx::query("SELECT * FROM northstar_upload_queue_snapshot()")
        .fetch_one(&mut *tx)
        .await?;
    let snapshot = upload_queue_metrics_from_row(&row)?;
    tx.commit().await?;
    Ok(snapshot)
}

pub(super) fn upload_queue_metrics_from_row(
    row: &sqlx::postgres::PgRow,
) -> Result<UploadQueueMetrics> {
    Ok(UploadQueueMetrics {
        storage_jobs_pending: row.try_get::<i64, _>("storage_jobs_pending")?.max(0) as u64,
        cleanup_jobs_pending: row.try_get::<i64, _>("cleanup_jobs_pending")?.max(0) as u64,
        cleanup_obligation_debt: row.try_get::<i64, _>("cleanup_obligation_debt")?.max(0) as u64,
        configured_pending_limit: row.try_get::<i64, _>("configured_pending_limit")?.max(0) as u64,
        legacy_overcommit_draining: u64::from(
            row.try_get::<bool, _>("legacy_overcommit_draining")?,
        ),
        recovery_retained_files: row.try_get::<i64, _>("recovery_retained_files")?.max(0) as u64,
        recovery_retained_bytes: row.try_get::<i64, _>("recovery_retained_bytes")?.max(0) as u64,
        recovery_overcommit_draining: u64::from(
            row.try_get::<bool, _>("recovery_overcommit_draining")?,
        ),
        oldest_pending_age_seconds: row.try_get::<i64, _>("oldest_pending_age_seconds")?.max(0)
            as u64,
        dead_letter_jobs_capped: row
            .try_get::<i64, _>("dead_letter_jobs")?
            .clamp(0, UPLOAD_HEALTH_COUNT_SATURATION) as u64,
        scrub_failures_capped: row
            .try_get::<i64, _>("scrub_failures")?
            .clamp(0, UPLOAD_HEALTH_COUNT_SATURATION) as u64,
        scrub_due_capped: row.try_get::<i64, _>("scrub_due_capped")?.max(0) as u64,
        scrub_oldest_overdue_seconds: row
            .try_get::<i64, _>("scrub_oldest_overdue_seconds")?
            .max(0) as u64,
        cleanup_obligations_due_capped: row
            .try_get::<i64, _>("cleanup_obligations_due_capped")?
            .max(0) as u64,
        cleanup_oldest_overdue_seconds: row
            .try_get::<i64, _>("cleanup_oldest_overdue_seconds")?
            .max(0) as u64,
    })
}
