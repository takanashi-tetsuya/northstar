-- Runtime observability must not turn a Prometheus refresh into a full-table
-- rescan.  Exact ledger/fact reconciliation remains a separate low-frequency
-- operation; these queue gauges deliberately saturate at 1001 (meaning
-- "at least 1001") and exist only for health/alerting decisions.

DO $northstar_upload_runtime_bounds_precondition$
DECLARE
    migration_schema pg_catalog.text := pg_catalog.current_schema();
    migration_owner pg_catalog.oid;
    relation_name pg_catalog.text;
    qualified_relation pg_catalog.regclass;
BEGIN
    IF migration_schema IS NULL
       OR migration_schema IN ('pg_catalog','information_schema','pg_toast')
       OR migration_schema LIKE 'pg_temp_%'
       OR migration_schema LIKE 'pg_toast_temp_%' THEN
        RAISE EXCEPTION 'unsafe migration schema for upload runtime bounds: %',
            migration_schema USING ERRCODE='3F000';
    END IF;
    SELECT namespace.nspowner INTO migration_owner
      FROM pg_catalog.pg_namespace namespace
     WHERE namespace.nspname=migration_schema;
    IF migration_owner IS NULL
       OR migration_owner<>(
            SELECT role.oid FROM pg_catalog.pg_roles role
             WHERE role.rolname=CURRENT_USER
          ) THEN
        RAISE EXCEPTION 'upload runtime-bounds schema must exist and be owned by the migration session'
            USING ERRCODE='42501';
    END IF;
    EXECUTE pg_catalog.format(
      'ALTER DEFAULT PRIVILEGES IN SCHEMA %I REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC CASCADE',
      migration_schema
    );
    FOREACH relation_name IN ARRAY ARRAY[
        'upload_slots','upload_storage_jobs','upload_cleanup_queue',
        'upload_storage_capacity_ledger'
    ] LOOP
        qualified_relation:=pg_catalog.to_regclass(
            pg_catalog.format('%I.%I',migration_schema,relation_name)
        );
        IF qualified_relation IS NULL
           OR pg_catalog.to_regclass(pg_catalog.format('%I',relation_name))
                IS DISTINCT FROM qualified_relation
           OR NOT EXISTS(
                SELECT 1 FROM pg_catalog.pg_class relation
                 WHERE relation.oid=qualified_relation
                   AND relation.relnamespace=(
                       SELECT namespace.oid FROM pg_catalog.pg_namespace namespace
                        WHERE namespace.nspname=migration_schema
                   )
                   AND relation.relowner=migration_owner
                   AND relation.relkind IN ('r','p')
           ) THEN
            RAISE EXCEPTION 'upload runtime-bounds relation % is absent, shadowed, or has the wrong owner',
                relation_name USING ERRCODE='42P01';
        END IF;
    END LOOP;
END;
$northstar_upload_runtime_bounds_precondition$;

-- The first two names are historical indexes. IF NOT EXISTS repairs a missing
-- legitimate index on upgrade, while the catalog postcondition below rejects
-- a same-name object with a different table/key/predicate. The scrub-failure
-- index is new and prevents the healthy zero-failure case from scanning every
-- committed upload.
CREATE INDEX IF NOT EXISTS upload_storage_jobs_dead_idx
    ON upload_storage_jobs(id) WHERE dead_lettered_at IS NOT NULL;
CREATE INDEX IF NOT EXISTS upload_cleanup_queue_recovery_dead_idx
    ON upload_cleanup_queue(recovery_id) WHERE dead_lettered_at IS NOT NULL;
CREATE INDEX IF NOT EXISTS upload_slots_storage_scrub_failures_idx
    ON upload_slots(id)
    WHERE storage_backend='s3' AND storage_state='committed'
      AND storage_scrub_failures>0;

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
LANGUAGE sql
SECURITY DEFINER
AS $northstar_upload_queue_snapshot_bounded$
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
  FROM upload_storage_capacity_ledger ledger WHERE ledger.singleton
$northstar_upload_queue_snapshot_bounded$;

DO $northstar_upload_runtime_bounds_postcondition$
DECLARE
    migration_schema pg_catalog.text := pg_catalog.current_schema();
    migration_owner pg_catalog.oid;
    routine_oid pg_catalog.oid;
    stale_grantee pg_catalog.text;
    expected pg_catalog.record;
    exact_index pg_catalog.bool;
BEGIN
    SELECT namespace.nspowner INTO migration_owner
      FROM pg_catalog.pg_namespace namespace
     WHERE namespace.nspname=migration_schema;
    routine_oid:=pg_catalog.to_regprocedure(
        pg_catalog.format('%I.northstar_upload_queue_snapshot()',migration_schema)
    );
    IF routine_oid IS NULL THEN
        RAISE EXCEPTION 'bounded upload queue snapshot is absent'
            USING ERRCODE='42883';
    END IF;
    EXECUTE pg_catalog.format(
        'ALTER FUNCTION %I.northstar_upload_queue_snapshot() SECURITY DEFINER '
        'SET search_path TO pg_catalog, %I, pg_temp',
        migration_schema,migration_schema
    );
    EXECUTE pg_catalog.format(
        'REVOKE ALL ON FUNCTION %I.northstar_upload_queue_snapshot() FROM PUBLIC CASCADE',
        migration_schema
    );
    -- CREATE OR REPLACE preserves the old ACL.  An upgrade can therefore
    -- inherit a retired workload or compromised ad-hoc grantee even though
    -- PUBLIC was revoked.  Return the replacement to owner-only here; the
    -- canonical post-migration grant reconciler adds exactly northstar_runtime
    -- back.  Runtime startup attestation intentionally fails until that
    -- reconciliation has happened.
    FOR stale_grantee IN
        SELECT DISTINCT role.rolname
          FROM pg_catalog.pg_proc routine
         CROSS JOIN LATERAL pg_catalog.aclexplode(COALESCE(
           routine.proacl,pg_catalog.acldefault('f',routine.proowner)
         )) privilege
          JOIN pg_catalog.pg_roles role ON role.oid=privilege.grantee
         WHERE routine.oid=routine_oid
           AND privilege.grantee<>routine.proowner
           AND privilege.grantee<>0
    LOOP
        EXECUTE pg_catalog.format(
          'REVOKE ALL PRIVILEGES ON FUNCTION %I.northstar_upload_queue_snapshot() FROM %I CASCADE',
          migration_schema,stale_grantee
        );
    END LOOP;
    -- Normalize the explicit owner ACL too.  Ownership gives implicit authority,
    -- but an historical REVOKE from the owner can remove the catalog ACL row
    -- which the canonical manifest intentionally requires.  CASCADE is safe
    -- here because every non-owner edge was removed above and the exact runtime
    -- edge is rebuilt only by the post-migration grant reconciler.
    EXECUTE pg_catalog.format(
      'REVOKE ALL PRIVILEGES ON FUNCTION %I.northstar_upload_queue_snapshot() FROM %I CASCADE',
      migration_schema,pg_catalog.pg_get_userbyid(migration_owner)
    );
    EXECUTE pg_catalog.format(
      'GRANT EXECUTE ON FUNCTION %I.northstar_upload_queue_snapshot() TO %I',
      migration_schema,pg_catalog.pg_get_userbyid(migration_owner)
    );
    IF NOT EXISTS(
        SELECT 1 FROM pg_catalog.pg_proc routine
        JOIN pg_catalog.pg_language language ON language.oid=routine.prolang
         WHERE routine.oid=routine_oid
           AND routine.proowner=migration_owner
           AND routine.prosecdef
           AND routine.prokind='f'
           AND routine.pronargs=0
           AND routine.pronargdefaults=0
           AND routine.provariadic=0
           AND routine.prorettype='pg_catalog.record'::pg_catalog.regtype
           AND routine.proretset
           AND routine.proargnames=ARRAY[
             'storage_jobs_pending','cleanup_jobs_pending',
             'cleanup_obligation_debt','configured_pending_limit',
             'legacy_overcommit_draining','recovery_retained_files',
             'recovery_retained_bytes','recovery_overcommit_draining',
             'dead_letter_jobs','scrub_failures','scrub_due_capped',
             'scrub_oldest_overdue_seconds','cleanup_obligations_due_capped',
             'cleanup_oldest_overdue_seconds','oldest_pending_age_seconds'
           ]::pg_catalog.text[]
           AND routine.proargmodes=ARRAY[
             't','t','t','t','t','t','t','t','t','t','t','t','t','t','t'
           ]::pg_catalog."char"[]
           AND routine.proallargtypes=ARRAY[
             'pg_catalog.int8'::pg_catalog.regtype,
             'pg_catalog.int8'::pg_catalog.regtype,
             'pg_catalog.int8'::pg_catalog.regtype,
             'pg_catalog.int8'::pg_catalog.regtype,
             'pg_catalog.bool'::pg_catalog.regtype,
             'pg_catalog.int8'::pg_catalog.regtype,
             'pg_catalog.int8'::pg_catalog.regtype,
             'pg_catalog.bool'::pg_catalog.regtype,
             'pg_catalog.int8'::pg_catalog.regtype,
             'pg_catalog.int8'::pg_catalog.regtype,
             'pg_catalog.int8'::pg_catalog.regtype,
             'pg_catalog.int8'::pg_catalog.regtype,
             'pg_catalog.int8'::pg_catalog.regtype,
             'pg_catalog.int8'::pg_catalog.regtype,
             'pg_catalog.int8'::pg_catalog.regtype
           ]::pg_catalog.oid[]
           AND language.lanname='sql'
           AND routine.proconfig=ARRAY[
             pg_catalog.format('search_path=pg_catalog, %I, pg_temp',migration_schema)
           ]::pg_catalog.text[]
    ) OR (SELECT pg_catalog.count(*)
            FROM pg_catalog.pg_proc routine
           CROSS JOIN LATERAL pg_catalog.aclexplode(COALESCE(
             routine.proacl,pg_catalog.acldefault('f',routine.proowner)
           )) privilege
           WHERE routine.oid=routine_oid)<>1
      OR EXISTS(
        SELECT 1 FROM pg_catalog.pg_proc routine
        CROSS JOIN LATERAL pg_catalog.aclexplode(
          COALESCE(routine.proacl,pg_catalog.acldefault('f',routine.proowner))
        ) privilege
         WHERE routine.oid=routine_oid
           AND (privilege.grantee<>routine.proowner
             OR privilege.grantor<>routine.proowner
             OR privilege.privilege_type<>'EXECUTE'
             OR privilege.is_grantable)
    ) THEN
        RAISE EXCEPTION 'bounded upload queue snapshot has unsafe owner, language, search_path, or non-owner ACL'
            USING ERRCODE='55000';
    END IF;

    FOR expected IN
        SELECT * FROM (VALUES
          ('upload_storage_jobs_dead_idx','upload_storage_jobs','id',
           'dead_lettered_atisnotnull'),
          ('upload_cleanup_queue_recovery_dead_idx','upload_cleanup_queue','recovery_id',
           'dead_lettered_atisnotnull'),
          ('upload_slots_storage_scrub_failures_idx','upload_slots','id',
           'storage_backend=''s3''::textandstorage_state=''committed''::textandstorage_scrub_failures>0')
        ) AS manifest(index_name,table_name,column_name,normalized_predicate)
    LOOP
        SELECT pg_catalog.count(*)=1 AND pg_catalog.bool_and(
                   index_row.indisvalid AND index_row.indisready AND index_row.indislive
                   AND NOT index_row.indisunique
                   AND index_row.indnkeyatts=1 AND index_row.indnatts=1
                   AND access_method.amname='btree'
                   AND pg_catalog.pg_get_indexdef(index_row.indexrelid,1,TRUE)
                         =expected.column_name
                   AND pg_catalog.lower(pg_catalog.regexp_replace(
                         pg_catalog.pg_get_expr(index_row.indpred,index_row.indrelid),
                         '[[:space:]()]','','g'
                       ))=expected.normalized_predicate
                   AND index_relation.relowner=migration_owner
               )
          INTO exact_index
          FROM pg_catalog.pg_index index_row
          JOIN pg_catalog.pg_class index_relation
            ON index_relation.oid=index_row.indexrelid
          JOIN pg_catalog.pg_namespace index_schema
            ON index_schema.oid=index_relation.relnamespace
          JOIN pg_catalog.pg_class table_relation
            ON table_relation.oid=index_row.indrelid
          JOIN pg_catalog.pg_namespace table_schema
            ON table_schema.oid=table_relation.relnamespace
          JOIN pg_catalog.pg_am access_method
            ON access_method.oid=index_relation.relam
         WHERE index_schema.nspname=migration_schema
           AND index_relation.relname=expected.index_name
           AND table_schema.nspname=migration_schema
           AND table_relation.relname=expected.table_name;
        IF NOT COALESCE(exact_index,FALSE) THEN
            RAISE EXCEPTION 'upload observability index % is absent or not exact',
                expected.index_name USING ERRCODE='55000';
        END IF;
    END LOOP;
END;
$northstar_upload_runtime_bounds_postcondition$;

COMMENT ON FUNCTION northstar_upload_queue_snapshot() IS
    'Bounded health snapshot: dead_letter_jobs, scrub_failures, scrub_due_capped and cleanup_obligations_due_capped saturate at 1001 (1001 means at least 1001); exact ledger/fact reconciliation is separate';
