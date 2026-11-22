CREATE SEQUENCE archive_display_change_seq
    AS BIGINT
    INCREMENT BY 1
    START WITH 1
    CACHE 1
    NO CYCLE;

CREATE TABLE personal_archive_display_changes (
    archive_id UUID PRIMARY KEY REFERENCES message_archive(id) ON DELETE CASCADE,
    display_stanza TEXT NOT NULL CHECK (display_stanza <> ''),
    change_kind TEXT NOT NULL CHECK (change_kind IN ('personal_retraction')),
    actor_bare_jid TEXT NOT NULL CHECK (
        pg_catalog.octet_length(actor_bare_jid) BETWEEN 1 AND 3071
    ),
    action_id TEXT NOT NULL CHECK (action_id <> ''),
    changed_at TIMESTAMPTZ NOT NULL DEFAULT pg_catalog.clock_timestamp(),
    display_sequence BIGINT NOT NULL
        DEFAULT pg_catalog.nextval('archive_display_change_seq'::pg_catalog.regclass)
        CHECK (display_sequence > 0)
);

CREATE TABLE muc_archive_display_changes (
    message_id UUID PRIMARY KEY REFERENCES muc_messages(id) ON DELETE CASCADE,
    display_stanza TEXT NOT NULL CHECK (display_stanza <> ''),
    change_kind TEXT NOT NULL CHECK (change_kind IN ('muc_retraction', 'muc_moderation')),
    actor_bare_jid TEXT NOT NULL CHECK (
        pg_catalog.octet_length(actor_bare_jid) BETWEEN 1 AND 3071
    ),
    action_id UUID NOT NULL,
    reason TEXT CHECK (pg_catalog.octet_length(reason) <= 4096),
    changed_at TIMESTAMPTZ NOT NULL DEFAULT pg_catalog.clock_timestamp(),
    display_sequence BIGINT NOT NULL
        DEFAULT pg_catalog.nextval('archive_display_change_seq'::pg_catalog.regclass)
        CHECK (display_sequence > 0)
);

CREATE TABLE legal_hold_export_display_cutoffs (
    export_id UUID PRIMARY KEY REFERENCES governance_export_leases(id) ON DELETE CASCADE,
    max_display_sequence BIGINT NOT NULL CHECK (max_display_sequence >= 0)
);

ALTER TABLE mix_source_retractions
    ADD COLUMN display_sequence BIGINT NOT NULL
        DEFAULT pg_catalog.nextval('archive_display_change_seq'::pg_catalog.regclass)
        CHECK (display_sequence > 0);

REVOKE ALL ON TABLE
    personal_archive_display_changes,
    muc_archive_display_changes,
    legal_hold_export_display_cutoffs
    FROM PUBLIC;
REVOKE ALL ON SEQUENCE archive_display_change_seq FROM PUBLIC;

-- A read/insert-only grant cannot acquire SHARE on the fact table or
-- FOR UPDATE on the hold header. Keep both locks behind a narrow capability.
CREATE FUNCTION northstar_lock_legal_hold_export(
    requested_actor UUID, requested_hold UUID, first_page BOOLEAN
) RETURNS BOOLEAN
LANGUAGE plpgsql
AS $$
DECLARE
    released TIMESTAMPTZ;
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM users
         WHERE id=requested_actor AND is_admin AND NOT is_disabled
    ) THEN
        RETURN FALSE;
    END IF;
    IF pg_catalog.current_setting('transaction_isolation') <> 'read committed' THEN
        RAISE EXCEPTION 'legal hold export requires READ COMMITTED' USING ERRCODE='25000';
    END IF;
    SELECT released_at INTO released FROM legal_holds
     WHERE id=requested_hold FOR UPDATE;
    IF NOT FOUND THEN
        RETURN FALSE;
    END IF;
    IF first_page AND released IS NULL THEN
        LOCK TABLE mix_source_retractions IN SHARE MODE;
    END IF;
    RETURN TRUE;
END;
$$;

DO $northstar_display_export_security$
DECLARE
    migration_schema TEXT := pg_catalog.current_schema();
    routine_signature TEXT;
BEGIN
    FOREACH routine_signature IN ARRAY ARRAY[
        'northstar_lock_legal_hold_export(uuid,uuid,bool)'
    ] LOOP
        EXECUTE pg_catalog.format(
            'ALTER FUNCTION %I.%s SECURITY DEFINER SET search_path TO pg_catalog, %I, pg_temp',
            migration_schema,routine_signature,migration_schema
        );
        EXECUTE pg_catalog.format(
            'REVOKE ALL ON FUNCTION %I.%s FROM PUBLIC',
            migration_schema,routine_signature
        );
    END LOOP;
END;
$northstar_display_export_security$;
