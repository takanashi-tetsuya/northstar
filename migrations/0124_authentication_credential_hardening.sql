-- Authentication credential hardening.
--
-- SCRAM-SHA-256 and the optional compatibility-only SCRAM-SHA-1 verifier
-- have independent work-factor histories.  A rolling deployment may prepare
-- a login with an older configuration and publish it after a newer node has
-- already raised one family, so PostgreSQL must enforce monotonicity while it
-- holds the account row lock.  The original 0108 capability coupled the two
-- iteration counts and protected only SHA-256.

ALTER TABLE users
    ADD COLUMN scram_sha256_iteration_floor INTEGER NOT NULL DEFAULT 4096,
    ADD COLUMN scram_sha1_iteration_floor INTEGER NOT NULL DEFAULT 4096;

-- Adopt only structurally valid verifier histories. Corrupt/incomplete rows
-- remain repairable from the protocol floor instead of turning an arbitrary
-- integer into a permanent denial of service.
UPDATE users SET
    scram_sha256_iteration_floor=CASE WHEN
        pg_catalog.octet_length(scram_sha256_salt) BETWEEN 16 AND 128
        AND scram_sha256_iterations BETWEEN 4096 AND 10000000
        AND pg_catalog.octet_length(scram_sha256_stored_key)=32
        AND pg_catalog.octet_length(scram_sha256_server_key)=32
      THEN scram_sha256_iterations ELSE 4096 END,
    scram_sha1_iteration_floor=CASE WHEN
        pg_catalog.octet_length(scram_sha1_salt) BETWEEN 16 AND 128
        AND scram_sha1_iterations BETWEEN 4096 AND 10000000
        AND pg_catalog.octet_length(scram_sha1_stored_key)=20
        AND pg_catalog.octet_length(scram_sha1_server_key)=20
      THEN scram_sha1_iterations ELSE 4096 END;

ALTER TABLE users
    ADD CONSTRAINT users_scram_sha256_iteration_floor_check
      CHECK (scram_sha256_iteration_floor BETWEEN 4096 AND 10000000),
    ADD CONSTRAINT users_scram_sha1_iteration_floor_check
      CHECK (scram_sha1_iteration_floor BETWEEN 4096 AND 10000000);

-- Every credential writer, including password reset capabilities, passes this
-- schema-local invoker trigger. Valid verifier work factors can only increase;
-- clearing compatibility SHA-1 retains its high-water mark so an older node
-- cannot recreate it below the strongest value seen before the clear.
CREATE FUNCTION northstar_enforce_scram_iteration_floors() RETURNS TRIGGER
LANGUAGE plpgsql
SET search_path FROM CURRENT
AS $$
DECLARE
    sha256_valid BOOLEAN;
    sha1_valid BOOLEAN;
    sha256_floor INTEGER;
    sha1_floor INTEGER;
BEGIN
    IF TG_OP='INSERT' THEN
        sha256_floor := COALESCE(NEW.scram_sha256_iteration_floor,4096);
        sha1_floor := COALESCE(NEW.scram_sha1_iteration_floor,4096);
    ELSE
        IF NEW.scram_sha256_iteration_floor IS NULL
           OR NEW.scram_sha256_iteration_floor<OLD.scram_sha256_iteration_floor
           OR NEW.scram_sha1_iteration_floor IS NULL
           OR NEW.scram_sha1_iteration_floor<OLD.scram_sha1_iteration_floor THEN
            RAISE EXCEPTION 'SCRAM iteration high-water mark cannot decrease'
              USING ERRCODE='22023';
        END IF;
        sha256_floor := GREATEST(
            OLD.scram_sha256_iteration_floor,
            NEW.scram_sha256_iteration_floor
        );
        sha1_floor := GREATEST(
            OLD.scram_sha1_iteration_floor,
            NEW.scram_sha1_iteration_floor
        );
    END IF;
    IF sha256_floor NOT BETWEEN 4096 AND 10000000
       OR sha1_floor NOT BETWEEN 4096 AND 10000000 THEN
        RAISE EXCEPTION 'SCRAM iteration high-water mark is invalid'
          USING ERRCODE='22023';
    END IF;

    sha256_valid := COALESCE(
        pg_catalog.octet_length(NEW.scram_sha256_salt) BETWEEN 16 AND 128
        AND NEW.scram_sha256_iterations BETWEEN 4096 AND 10000000
        AND pg_catalog.octet_length(NEW.scram_sha256_stored_key)=32
        AND pg_catalog.octet_length(NEW.scram_sha256_server_key)=32,
        FALSE
    );
    sha1_valid := COALESCE(
        pg_catalog.octet_length(NEW.scram_sha1_salt) BETWEEN 16 AND 128
        AND NEW.scram_sha1_iterations BETWEEN 4096 AND 10000000
        AND pg_catalog.octet_length(NEW.scram_sha1_stored_key)=20
        AND pg_catalog.octet_length(NEW.scram_sha1_server_key)=20,
        FALSE
    );
    IF sha256_valid THEN
        IF TG_OP='UPDATE'
           AND NEW.scram_sha256_iterations<OLD.scram_sha256_iteration_floor THEN
            RAISE EXCEPTION 'SCRAM-SHA-256 iteration count cannot decrease'
              USING ERRCODE='22023';
        END IF;
        sha256_floor := GREATEST(
            sha256_floor,NEW.scram_sha256_iterations
        );
    END IF;
    IF sha1_valid THEN
        IF TG_OP='UPDATE'
           AND NEW.scram_sha1_iterations<OLD.scram_sha1_iteration_floor THEN
            RAISE EXCEPTION 'SCRAM-SHA-1 iteration count cannot decrease'
              USING ERRCODE='22023';
        END IF;
        sha1_floor := GREATEST(
            sha1_floor,NEW.scram_sha1_iterations
        );
    END IF;
    NEW.scram_sha256_iteration_floor := sha256_floor;
    NEW.scram_sha1_iteration_floor := sha1_floor;
    RETURN NEW;
END;
$$;

CREATE TRIGGER users_scram_iteration_floors_insert
BEFORE INSERT ON users
FOR EACH ROW EXECUTE FUNCTION northstar_enforce_scram_iteration_floors();
CREATE TRIGGER users_scram_iteration_floors_update
BEFORE UPDATE OF password_hash,
                 scram_sha256_salt,scram_sha256_iterations,
                 scram_sha256_stored_key,scram_sha256_server_key,
                 scram_sha1_salt,scram_sha1_iterations,
                 scram_sha1_stored_key,scram_sha1_server_key,
                 scram_sha256_iteration_floor,scram_sha1_iteration_floor
ON users
FOR EACH ROW EXECUTE FUNCTION northstar_enforce_scram_iteration_floors();

REVOKE ALL ON FUNCTION northstar_enforce_scram_iteration_floors() FROM PUBLIC;

CREATE OR REPLACE FUNCTION northstar_user_credentials_valid(
    requested_password_hash TEXT,
    requested_sha256_salt BYTEA,
    requested_iterations INTEGER,
    requested_sha256_stored_key BYTEA,
    requested_sha256_server_key BYTEA,
    requested_sha1_salt BYTEA,
    requested_sha1_iterations INTEGER,
    requested_sha1_stored_key BYTEA,
    requested_sha1_server_key BYTEA
) RETURNS BOOLEAN
LANGUAGE sql
IMMUTABLE
SET search_path FROM CURRENT
AS $$
    SELECT COALESCE(
      requested_password_hash LIKE '$argon2id$%'
       AND pg_catalog.octet_length(requested_password_hash) BETWEEN 32 AND 1024
       AND pg_catalog.octet_length(requested_sha256_salt) BETWEEN 16 AND 128
       AND requested_iterations BETWEEN 4096 AND 10000000
       AND pg_catalog.octet_length(requested_sha256_stored_key)=32
       AND pg_catalog.octet_length(requested_sha256_server_key)=32
       AND (
          (requested_sha1_salt IS NULL
           AND requested_sha1_iterations IS NULL
           AND requested_sha1_stored_key IS NULL
           AND requested_sha1_server_key IS NULL)
          OR
          (pg_catalog.octet_length(requested_sha1_salt) BETWEEN 16 AND 128
           AND requested_sha1_iterations BETWEEN 4096 AND 10000000
           AND pg_catalog.octet_length(requested_sha1_stored_key)=20
           AND pg_catalog.octet_length(requested_sha1_server_key)=20)
       ), FALSE)
$$;

CREATE OR REPLACE FUNCTION northstar_user_apply_login(
    requested_id UUID,
    expected_password_hash TEXT,
    expected_auth_generation BIGINT,
    requested_sha256_salt BYTEA,
    requested_iterations INTEGER,
    requested_sha256_stored_key BYTEA,
    requested_sha256_server_key BYTEA,
    requested_sha1_salt BYTEA,
    requested_sha1_iterations INTEGER,
    requested_sha1_stored_key BYTEA,
    requested_sha1_server_key BYTEA
) RETURNS BOOLEAN
LANGUAGE plpgsql SECURITY DEFINER SET search_path FROM CURRENT
AS $$
DECLARE
    current_sha256_floor INTEGER;
    current_sha1_floor INTEGER;
BEGIN
    SELECT scram_sha256_iteration_floor,scram_sha1_iteration_floor
      INTO current_sha256_floor,current_sha1_floor
      FROM users
     WHERE id=requested_id AND password_hash=expected_password_hash
       AND auth_generation=expected_auth_generation AND NOT is_disabled
     FOR UPDATE;
    IF NOT FOUND THEN
        RETURN FALSE;
    END IF;

    IF requested_sha256_salt IS NOT NULL THEN
        IF NOT northstar_user_credentials_valid(
             expected_password_hash,requested_sha256_salt,requested_iterations,
             requested_sha256_stored_key,requested_sha256_server_key,
             requested_sha1_salt,requested_sha1_iterations,
             requested_sha1_stored_key,requested_sha1_server_key
           )
           OR requested_iterations<current_sha256_floor
           OR (requested_sha1_salt IS NOT NULL
               AND requested_sha1_iterations<current_sha1_floor) THEN
            RAISE EXCEPTION 'invalid or downgraded SCRAM login upgrade'
              USING ERRCODE='22023';
        END IF;
        UPDATE users
           SET scram_sha256_salt=requested_sha256_salt,
               scram_sha256_iterations=requested_iterations,
               scram_sha256_stored_key=requested_sha256_stored_key,
               scram_sha256_server_key=requested_sha256_server_key,
               scram_sha1_salt=requested_sha1_salt,
               scram_sha1_iterations=requested_sha1_iterations,
               scram_sha1_stored_key=requested_sha1_stored_key,
               scram_sha1_server_key=requested_sha1_server_key,
               last_login_at=pg_catalog.clock_timestamp()
         WHERE id=requested_id;
    ELSE
        IF requested_iterations IS NOT NULL
           OR requested_sha256_stored_key IS NOT NULL
           OR requested_sha256_server_key IS NOT NULL
           OR requested_sha1_salt IS NOT NULL
           OR requested_sha1_iterations IS NOT NULL
           OR requested_sha1_stored_key IS NOT NULL
           OR requested_sha1_server_key IS NOT NULL THEN
            RAISE EXCEPTION 'partial SCRAM login upgrade' USING ERRCODE='22023';
        END IF;
        UPDATE users SET last_login_at=pg_catalog.clock_timestamp()
         WHERE id=requested_id;
    END IF;
    RETURN TRUE;
END;
$$;

-- CREATE OR REPLACE retains the existing owner/ACL, but its SET clause would
-- otherwise capture an operator-supplied migration search_path. Re-assert the
-- 0108 capability boundary for the replaced definer and both helpers without
-- assuming any particular deployment schema.
DO $northstar_authentication_capability_metadata$
DECLARE
    migration_schema pg_catalog.text := pg_catalog.current_schema();
    signature pg_catalog.text;
    routine_oid pg_catalog.oid;
BEGIN
    IF migration_schema IS NULL
       OR migration_schema IN ('pg_catalog','information_schema')
       OR migration_schema LIKE 'pg_temp_%'
       OR migration_schema LIKE 'pg_toast_temp_%' THEN
        RAISE EXCEPTION 'migration 0124 requires a dedicated application schema first in search_path'
          USING ERRCODE='3F000';
    END IF;

    FOREACH signature IN ARRAY ARRAY[
      'northstar_user_apply_login(uuid,text,int8,bytea,int4,bytea,bytea,bytea,int4,bytea,bytea)'
    ] LOOP
      routine_oid := pg_catalog.to_regprocedure(
        pg_catalog.format('%I.%s',migration_schema,signature));
      IF routine_oid IS NULL THEN
        RAISE EXCEPTION 'authentication capability % is absent',signature
          USING ERRCODE='42883';
      END IF;
      IF pg_catalog.pg_get_userbyid(
           (SELECT proowner FROM pg_catalog.pg_proc WHERE oid=routine_oid))
         <>CURRENT_USER THEN
        RAISE EXCEPTION 'authentication capability % is not migrator-owned',signature
          USING ERRCODE='42501';
      END IF;
      EXECUTE pg_catalog.format(
        'ALTER FUNCTION %I.%s SECURITY DEFINER SET search_path TO pg_catalog, %I, pg_temp',
        migration_schema,signature,migration_schema);
      EXECUTE pg_catalog.format(
        'REVOKE ALL ON FUNCTION %I.%s FROM PUBLIC',migration_schema,signature);
    END LOOP;

    FOREACH signature IN ARRAY ARRAY[
      'northstar_user_credentials_valid(text,bytea,int4,bytea,bytea,bytea,int4,bytea,bytea)',
      'northstar_enforce_scram_iteration_floors()'
    ] LOOP
      routine_oid := pg_catalog.to_regprocedure(
        pg_catalog.format('%I.%s',migration_schema,signature));
      IF routine_oid IS NULL THEN
        RAISE EXCEPTION 'authentication helper % is absent',signature
          USING ERRCODE='42883';
      END IF;
      IF pg_catalog.pg_get_userbyid(
           (SELECT proowner FROM pg_catalog.pg_proc WHERE oid=routine_oid))
         <>CURRENT_USER THEN
        RAISE EXCEPTION 'authentication helper % is not migrator-owned',signature
          USING ERRCODE='42501';
      END IF;
      EXECUTE pg_catalog.format(
        'ALTER FUNCTION %I.%s SECURITY INVOKER SET search_path TO pg_catalog, %I, pg_temp',
        migration_schema,signature,migration_schema);
      EXECUTE pg_catalog.format(
        'REVOKE ALL ON FUNCTION %I.%s FROM PUBLIC',migration_schema,signature);
    END LOOP;
END;
$northstar_authentication_capability_metadata$;

-- Migrations after 0099 introduced additional invoker trigger helpers and
-- capacity-accounting functions. Reconcile the complete application routine
-- catalog again so no later function retains a caller-selected, catalog-only,
-- or incompletely captured search_path. Runtime never starts between SQLx
-- migrations, and this block preserves owner, SECURITY mode, ACLs, and every
-- non-search_path setting while making the final catalog invariant explicit.
DO $northstar_application_function_paths_v2$
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
        RAISE EXCEPTION 'migration 0124 requires a dedicated application schema before routine reconciliation'
          USING ERRCODE='3F000';
    END IF;
    SELECT role_row.oid INTO migration_owner
      FROM pg_catalog.pg_roles role_row
     WHERE role_row.rolname=CURRENT_USER;
    IF migration_owner IS NULL THEN
        RAISE EXCEPTION 'migration 0124 cannot resolve its migration owner'
          USING ERRCODE='42704';
    END IF;
    expected_path := pg_catalog.format(
        'search_path=pg_catalog, %I, pg_temp',migration_schema
    );

    FOR routine IN
        SELECT proc_row.oid,proc_row.proname,proc_row.proowner,
               proc_row.prosecdef,proc_row.proacl,
               pg_catalog.pg_get_function_identity_arguments(proc_row.oid)
                 AS identity_arguments,
               ARRAY(
                 SELECT config.setting
                   FROM pg_catalog.unnest(COALESCE(
                          proc_row.proconfig,ARRAY[]::pg_catalog.text[]
                        )) WITH ORDINALITY AS config(setting,position)
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
             SELECT 1 FROM pg_catalog.pg_depend dependency
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
          migration_schema,routine.proname,routine.identity_arguments,migration_schema
        );

        SELECT proc_row.proowner=routine.proowner
           AND proc_row.prosecdef=routine.prosecdef
           AND proc_row.proacl IS NOT DISTINCT FROM routine.proacl
           AND ARRAY(
                 SELECT config.setting
                   FROM pg_catalog.unnest(COALESCE(
                          proc_row.proconfig,ARRAY[]::pg_catalog.text[]
                        )) WITH ORDINALITY AS config(setting,position)
                  WHERE config.setting NOT LIKE 'search_path=%'
                  ORDER BY config.position
               )=routine.non_path_config
           AND expected_path=ANY(COALESCE(
                 proc_row.proconfig,ARRAY[]::pg_catalog.text[]
               ))
           AND (
             SELECT pg_catalog.count(*)=1
               FROM pg_catalog.unnest(COALESCE(
                      proc_row.proconfig,ARRAY[]::pg_catalog.text[]
                    )) AS config(setting)
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
        RAISE EXCEPTION 'migration 0124 found no application functions to reconcile in schema %',
          migration_schema USING ERRCODE='42883';
    END IF;
END;
$northstar_application_function_paths_v2$;
