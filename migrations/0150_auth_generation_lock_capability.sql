-- A runtime SELECT on users cannot take a row lock. Keep the account
-- generation fence in the current transaction without granting account writes.
CREATE FUNCTION northstar_lock_auth_generation(
    requested_user UUID,
    expected_generation BIGINT
) RETURNS BOOLEAN
LANGUAGE plpgsql VOLATILE SECURITY DEFINER
AS $northstar_lock_auth_generation$
BEGIN
    IF requested_user IS NULL OR expected_generation IS NULL THEN
        RETURN FALSE;
    END IF;
    PERFORM 1 FROM users
     WHERE id=requested_user
       AND auth_generation=expected_generation
       AND NOT is_disabled
     FOR SHARE;
    RETURN FOUND;
END;
$northstar_lock_auth_generation$;

DO $pin_auth_generation_lock$
DECLARE
    migration_schema pg_catalog.text := pg_catalog.current_schema();
    routine_signature pg_catalog.text;
BEGIN
    FOREACH routine_signature IN ARRAY ARRAY[
        'northstar_lock_auth_generation(uuid,int8)'
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
$pin_auth_generation_lock$;
