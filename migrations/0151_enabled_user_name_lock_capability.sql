-- Bind a JID to an enabled account under the caller's transaction without
-- granting the runtime role UPDATE for a direct SELECT FOR SHARE row lock.
CREATE FUNCTION northstar_lock_enabled_user_name(
    requested_user UUID,
    expected_username TEXT
) RETURNS BOOLEAN
LANGUAGE plpgsql VOLATILE SECURITY DEFINER
AS $northstar_lock_enabled_user_name$
BEGIN
    IF requested_user IS NULL OR expected_username IS NULL OR expected_username = '' THEN
        RETURN FALSE;
    END IF;
    PERFORM 1 FROM users
     WHERE id=requested_user
       AND username=expected_username
       AND NOT is_disabled
     FOR SHARE;
    RETURN FOUND;
END;
$northstar_lock_enabled_user_name$;

DO $pin_enabled_user_name_lock$
DECLARE
    migration_schema pg_catalog.text := pg_catalog.current_schema();
    routine_signature pg_catalog.text;
BEGIN
    FOREACH routine_signature IN ARRAY ARRAY[
        'northstar_lock_enabled_user_name(uuid,text)'
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
$pin_enabled_user_name_lock$;
