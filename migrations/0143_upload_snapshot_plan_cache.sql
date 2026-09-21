-- Reuse the snapshot query plan on each backend. PostgreSQL 17 replans the
-- SQL-language body on every call; the PL/pgSQL query keeps the same bounds
-- and reads current data on every execution.
CREATE OR REPLACE FUNCTION northstar_upload_queue_snapshot()
RETURNS TABLE(
  storage_jobs_pending pg_catalog.int8,cleanup_jobs_pending pg_catalog.int8,
  cleanup_obligation_debt pg_catalog.int8,configured_pending_limit pg_catalog.int8,
  legacy_overcommit_draining pg_catalog.bool,recovery_retained_files pg_catalog.int8,
  recovery_retained_bytes pg_catalog.int8,recovery_overcommit_draining pg_catalog.bool,
  dead_letter_jobs pg_catalog.int8,scrub_failures pg_catalog.int8,
  scrub_due_capped pg_catalog.int8,scrub_oldest_overdue_seconds pg_catalog.int8,
  cleanup_obligations_due_capped pg_catalog.int8,
  cleanup_oldest_overdue_seconds pg_catalog.int8,
  oldest_pending_age_seconds pg_catalog.int8
)
LANGUAGE plpgsql
SECURITY DEFINER
AS $northstar_upload_queue_snapshot_cached$
BEGIN
RETURN QUERY
SELECT ledger.storage_jobs_pending,ledger.cleanup_jobs_pending,
       ledger.cleanup_obligation_debt,ledger.configured_pending_limit,
       ledger.legacy_overcommit_draining,ledger.recovery_retained_files,
       ledger.recovery_retained_bytes,ledger.recovery_overcommit_draining,
       (SELECT pg_catalog.count(*) FROM (
          SELECT 1 AS marker FROM upload_storage_jobs
           WHERE dead_lettered_at IS NOT NULL
          UNION ALL
          SELECT 1 AS marker FROM upload_cleanup_queue
           WHERE dead_lettered_at IS NOT NULL
          LIMIT 1001
        ) bounded_dead_letters),
       (SELECT pg_catalog.count(*) FROM (
          SELECT 1 FROM upload_slots
           WHERE storage_backend='s3' AND storage_state='committed'
             AND storage_scrub_failures>0
          LIMIT 1001
        ) bounded_scrub_failures),
       (SELECT pg_catalog.count(*) FROM (
          SELECT 1 FROM upload_slots WHERE storage_backend='s3'
            AND storage_state='committed'
            AND storage_scrub_next_at<=pg_catalog.clock_timestamp()
          ORDER BY storage_scrub_next_at,id LIMIT 1001
        ) bounded_due),
       COALESCE((SELECT pg_catalog.floor(GREATEST(0,EXTRACT(EPOCH FROM
          pg_catalog.clock_timestamp()-storage_scrub_next_at)))::pg_catalog.int8
          FROM upload_slots WHERE storage_backend='s3'
            AND storage_state='committed'
            AND storage_scrub_next_at<=pg_catalog.clock_timestamp()
          ORDER BY storage_scrub_next_at,id LIMIT 1),0),
       (SELECT pg_catalog.count(*) FROM (
          SELECT 1 FROM upload_slots
           WHERE expires_at<=pg_catalog.clock_timestamp() AND storage_state<>'deleting'
           ORDER BY expires_at,id LIMIT 1001
        ) due_slots),
       COALESCE((SELECT pg_catalog.floor(GREATEST(0,EXTRACT(EPOCH FROM
          pg_catalog.clock_timestamp()-expires_at)))::pg_catalog.int8
          FROM upload_slots WHERE expires_at<=pg_catalog.clock_timestamp()
            AND storage_state<>'deleting'
          ORDER BY expires_at,id LIMIT 1),0),
       pg_catalog.floor(GREATEST(0,EXTRACT(EPOCH FROM
         pg_catalog.clock_timestamp()-LEAST(
           COALESCE((SELECT pg_catalog.min(created_at) FROM upload_storage_jobs),
                    pg_catalog.clock_timestamp()),
           COALESCE((SELECT pg_catalog.min(queued_at) FROM upload_cleanup_queue),
                    pg_catalog.clock_timestamp())
         ))))::pg_catalog.int8
  FROM upload_storage_capacity_ledger ledger WHERE ledger.singleton;
END;
$northstar_upload_queue_snapshot_cached$;

DO $northstar_upload_snapshot_plan_cache$
DECLARE
    migration_schema pg_catalog.text := pg_catalog.current_schema();
    routine_signature pg_catalog.text;
    routine_oid pg_catalog.oid;
    expected_path pg_catalog.text;
BEGIN
    expected_path := pg_catalog.format(
        'search_path=pg_catalog, %I, pg_temp', migration_schema
    );

    FOREACH routine_signature IN ARRAY ARRAY[
        'northstar_upload_queue_snapshot()'
    ] LOOP
        routine_oid := pg_catalog.to_regprocedure(
            pg_catalog.format('%I.%s', migration_schema, routine_signature)
        );
        IF routine_oid IS NULL THEN
            RAISE EXCEPTION 'upload queue snapshot capability % is absent', routine_signature
                USING ERRCODE='42883';
        END IF;

        EXECUTE pg_catalog.format(
            'ALTER FUNCTION %I.%s RESET ALL', migration_schema, routine_signature
        );
        EXECUTE pg_catalog.format(
            'ALTER FUNCTION %I.%s SECURITY DEFINER SET search_path TO pg_catalog, %I, pg_temp',
            migration_schema, routine_signature, migration_schema
        );
        EXECUTE pg_catalog.format(
            'REVOKE ALL ON FUNCTION %I.%s FROM PUBLIC', migration_schema, routine_signature
        );

        IF NOT EXISTS(
            SELECT 1
              FROM pg_catalog.pg_proc routine
             WHERE routine.oid=routine_oid
               AND routine.prosecdef
               AND routine.proconfig=ARRAY[expected_path]::pg_catalog.text[]
               AND NOT pg_catalog.has_function_privilege('public', routine.oid, 'EXECUTE')
        ) THEN
            RAISE EXCEPTION 'upload queue snapshot capability % has unsafe authority', routine_signature
                USING ERRCODE='55000';
        END IF;
    END LOOP;
END;
$northstar_upload_snapshot_plan_cache$;
