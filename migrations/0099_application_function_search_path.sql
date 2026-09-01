-- Pin every application-owned SQL/PLpgSQL function to the exact schema in
-- which Northstar is installed. Earlier migrations created ordinary trigger
-- and helper functions with an implicit caller search_path; a schema-qualified
-- table mutation could therefore make a trigger fail closed or resolve a
-- same-named relation outside its own installation schema.
--
-- Audit result before introducing this migration: no selected application
-- function intentionally creates or addresses a temporary relation, and none
-- uses caller-selected schemas as an API. `pg_temp` remains last only for
-- PostgreSQL's normal runtime scratch resolution. Consequently there is no
-- exemption list: any future application SQL/PLpgSQL function left unpinned is
-- a migration-test failure.

DO $northstar_application_function_paths$
DECLARE
    migration_schema pg_catalog.text := pg_catalog.current_schema();
    migration_owner pg_catalog.oid;
    routine pg_catalog.record;
    expected_path pg_catalog.text;
    postconditions pg_catalog.bool;
    pinned_count pg_catalog.int8 := 0;
BEGIN
    IF migration_schema IS NULL
       OR migration_schema IN ('pg_catalog','information_schema')
       OR migration_schema LIKE 'pg_temp_%'
       OR migration_schema LIKE 'pg_toast_temp_%' THEN
        RAISE EXCEPTION 'migration 0099 requires a dedicated application schema first in search_path'
            USING ERRCODE='3F000';
    END IF;
    SELECT role_row.oid INTO migration_owner
      FROM pg_catalog.pg_roles role_row
     WHERE role_row.rolname=CURRENT_USER;
    IF migration_owner IS NULL THEN
        RAISE EXCEPTION 'migration 0099 cannot resolve its migration owner'
            USING ERRCODE='42704';
    END IF;
    expected_path := pg_catalog.format(
        'search_path=pg_catalog, %I, pg_temp',migration_schema
    );

    FOR routine IN
        SELECT proc_row.oid,
               proc_row.proname,
               proc_row.proowner,
               proc_row.prosecdef,
               proc_row.proacl,
               pg_catalog.pg_get_function_identity_arguments(proc_row.oid)
                   AS identity_arguments,
               ARRAY(
                   SELECT config.setting
                     FROM pg_catalog.unnest(
                              COALESCE(
                                  proc_row.proconfig,
                                  ARRAY[]::pg_catalog.text[]
                              )
                          ) WITH ORDINALITY AS config(setting,position)
                    WHERE config.setting NOT LIKE 'search_path=%'
                    ORDER BY config.position
               ) AS non_path_config
          FROM pg_catalog.pg_proc proc_row
          JOIN pg_catalog.pg_namespace proc_namespace
            ON proc_namespace.oid=proc_row.pronamespace
          JOIN pg_catalog.pg_language proc_language
            ON proc_language.oid=proc_row.prolang
         WHERE proc_namespace.nspname=migration_schema
           AND proc_row.prokind='f'
           AND proc_language.lanname IN ('plpgsql','sql')
           AND NOT EXISTS (
               SELECT 1
                 FROM pg_catalog.pg_depend dependency
                WHERE dependency.classid='pg_catalog.pg_proc'::pg_catalog.regclass
                  AND dependency.objid=proc_row.oid
                  AND dependency.deptype='e'
           )
         ORDER BY proc_row.oid
    LOOP
        IF routine.proowner<>migration_owner THEN
            RAISE EXCEPTION 'application function %.%(%) is not owned by migration role %',
                migration_schema,routine.proname,routine.identity_arguments,CURRENT_USER
                USING ERRCODE='42501';
        END IF;

        EXECUTE pg_catalog.format(
            'ALTER FUNCTION %I.%I(%s) SET search_path TO pg_catalog, %I, pg_temp',
            migration_schema,
            routine.proname,
            routine.identity_arguments,
            migration_schema
        );

        SELECT proc_row.proowner=routine.proowner
           AND proc_row.prosecdef=routine.prosecdef
           AND proc_row.proacl IS NOT DISTINCT FROM routine.proacl
           AND ARRAY(
                   SELECT config.setting
                     FROM pg_catalog.unnest(
                              COALESCE(
                                  proc_row.proconfig,
                                  ARRAY[]::pg_catalog.text[]
                              )
                          ) WITH ORDINALITY AS config(setting,position)
                    WHERE config.setting NOT LIKE 'search_path=%'
                    ORDER BY config.position
               )=routine.non_path_config
           AND expected_path=ANY(
                   COALESCE(proc_row.proconfig,ARRAY[]::pg_catalog.text[])
               )
           AND (
               SELECT pg_catalog.count(*)=1
                 FROM pg_catalog.unnest(
                          COALESCE(
                              proc_row.proconfig,
                              ARRAY[]::pg_catalog.text[]
                          )
                      ) AS config(setting)
                WHERE config.setting LIKE 'search_path=%'
           )
          INTO postconditions
          FROM pg_catalog.pg_proc proc_row
         WHERE proc_row.oid=routine.oid;
        IF NOT COALESCE(postconditions,FALSE) THEN
            RAISE EXCEPTION 'application function %.%(%) changed authority metadata or was not pinned',
                migration_schema,routine.proname,routine.identity_arguments
                USING ERRCODE='55000';
        END IF;
        pinned_count := pinned_count+1;
    END LOOP;

    IF pinned_count=0 THEN
        RAISE EXCEPTION 'migration 0099 found no application functions to pin in schema %',
            migration_schema
            USING ERRCODE='42883';
    END IF;
END;
$northstar_application_function_paths$;
