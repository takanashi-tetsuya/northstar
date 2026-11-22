-- Let the runtime role take the account row locks its transactions already
-- depend on without granting it UPDATE on users.
--
-- PostgreSQL requires UPDATE on a relation (or on one of its columns) for
-- every SELECT ... FOR KEY SHARE / FOR SHARE / FOR NO KEY UPDATE / FOR UPDATE
-- that locks it.  The runtime manifest deliberately keeps users read-only, so
-- each lock strength the runtime uses gets one fixed SECURITY DEFINER
-- capability.  The capabilities change no data and disclose no column the
-- runtime cannot already SELECT; they lock exactly the requested existing rows
-- in id order (the order every multi-account caller already uses) and return
-- the locked row versions so callers apply their own authorization predicates
-- to the values that the lock now fences.
CREATE FUNCTION northstar_lock_user_rows_key_share(requested_users UUID[])
RETURNS TABLE(
    id UUID,
    username TEXT,
    auth_generation BIGINT,
    is_admin BOOLEAN,
    is_disabled BOOLEAN
)
LANGUAGE plpgsql VOLATILE SECURITY DEFINER
AS $northstar_lock_user_rows_key_share$
BEGIN
    IF requested_users IS NULL THEN
        RETURN;
    END IF;
    RETURN QUERY
    SELECT account.id,
           account.username::TEXT,
           account.auth_generation,
           account.is_admin,
           account.is_disabled
      FROM users account
     WHERE account.id = ANY(requested_users)
     ORDER BY account.id
     FOR KEY SHARE OF account;
END;
$northstar_lock_user_rows_key_share$;

CREATE FUNCTION northstar_lock_user_rows_share(requested_users UUID[])
RETURNS TABLE(
    id UUID,
    username TEXT,
    auth_generation BIGINT,
    is_admin BOOLEAN,
    is_disabled BOOLEAN
)
LANGUAGE plpgsql VOLATILE SECURITY DEFINER
AS $northstar_lock_user_rows_share$
BEGIN
    IF requested_users IS NULL THEN
        RETURN;
    END IF;
    RETURN QUERY
    SELECT account.id,
           account.username::TEXT,
           account.auth_generation,
           account.is_admin,
           account.is_disabled
      FROM users account
     WHERE account.id = ANY(requested_users)
     ORDER BY account.id
     FOR SHARE OF account;
END;
$northstar_lock_user_rows_share$;

CREATE FUNCTION northstar_lock_user_rows_update(requested_users UUID[])
RETURNS TABLE(
    id UUID,
    username TEXT,
    auth_generation BIGINT,
    is_admin BOOLEAN,
    is_disabled BOOLEAN
)
LANGUAGE plpgsql VOLATILE SECURITY DEFINER
AS $northstar_lock_user_rows_update$
BEGIN
    IF requested_users IS NULL THEN
        RETURN;
    END IF;
    RETURN QUERY
    SELECT account.id,
           account.username::TEXT,
           account.auth_generation,
           account.is_admin,
           account.is_disabled
      FROM users account
     WHERE account.id = ANY(requested_users)
     ORDER BY account.id
     FOR UPDATE OF account;
END;
$northstar_lock_user_rows_update$;

DO $pin_user_row_lock_capabilities$
DECLARE
    migration_schema pg_catalog.text := pg_catalog.current_schema();
    routine_signature pg_catalog.text;
BEGIN
    FOREACH routine_signature IN ARRAY ARRAY[
        'northstar_lock_user_rows_key_share(uuid[])',
        'northstar_lock_user_rows_share(uuid[])',
        'northstar_lock_user_rows_update(uuid[])'
    ] LOOP
        EXECUTE pg_catalog.format(
            'ALTER FUNCTION %I.%s RESET ALL',migration_schema,routine_signature
        );
        EXECUTE pg_catalog.format(
            'ALTER FUNCTION %I.%s SECURITY DEFINER SET search_path TO pg_catalog, %I, pg_temp',
            migration_schema,routine_signature,migration_schema
        );
        EXECUTE pg_catalog.format(
            'REVOKE ALL ON FUNCTION %I.%s FROM PUBLIC',migration_schema,routine_signature
        );
    END LOOP;
END;
$pin_user_row_lock_capabilities$;
