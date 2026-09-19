-- 0139 replaced this established capability to resolve a PL/pgSQL conflict
-- target ambiguity.  Keep the prior migration immutable: re-assert the full
-- authority contract here so upgrades preserve a complete, auditable security
-- boundary for both existing and clean installations.
DO $northstar_upload_cleanup_capability_rehardening$
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
        'northstar_upload_admit_expired_cleanup()'
    ] LOOP
        routine_oid := pg_catalog.to_regprocedure(
            pg_catalog.format('%I.%s', migration_schema, routine_signature)
        );
        IF routine_oid IS NULL THEN
            RAISE EXCEPTION 'upload cleanup capability % is absent', routine_signature
                USING ERRCODE='42883';
        END IF;

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
            RAISE EXCEPTION 'upload cleanup capability % has unsafe authority', routine_signature
                USING ERRCODE='55000';
        END IF;
    END LOOP;
END;
$northstar_upload_cleanup_capability_rehardening$;
