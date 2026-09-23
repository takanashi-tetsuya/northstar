-- Offline, migrator-owned upload backend migration. Runtime roles have no
-- table capability. A run snapshots every source locator before copying; a
-- final transaction must compare that snapshot with current slots.
CREATE TABLE upload_storage_migration_runs (
    run_id UUID PRIMARY KEY,
    source_backend TEXT NOT NULL CHECK (source_backend IN ('local','s3')),
    target_backend TEXT NOT NULL CHECK (target_backend IN ('local','s3')),
    source_namespace_sha256 BYTEA NOT NULL CHECK (octet_length(source_namespace_sha256)=32),
    target_namespace_sha256 BYTEA NOT NULL CHECK (octet_length(target_namespace_sha256)=32),
    source_generation BIGINT NOT NULL CHECK (source_generation>0),
    source_slot_count BIGINT NOT NULL CHECK (source_slot_count>=0),
    state TEXT NOT NULL DEFAULT 'copying' CHECK (state IN ('copying','cutover','aborted')),
    manifest_sha256 BYTEA CHECK (manifest_sha256 IS NULL OR octet_length(manifest_sha256)=32),
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    CHECK (source_backend<>target_backend),
    CHECK ((state='cutover')=(manifest_sha256 IS NOT NULL))
);
CREATE UNIQUE INDEX upload_storage_migration_one_active_run
    ON upload_storage_migration_runs ((TRUE)) WHERE state='copying';

-- Runtime startup can detect an unfinished switch without reading the journal.
CREATE FUNCTION northstar_storage_migration_active()
RETURNS BOOLEAN
LANGUAGE sql STABLE SECURITY DEFINER
AS $northstar_storage_migration_active$
    SELECT EXISTS(
        SELECT 1 FROM upload_storage_migration_runs WHERE state='copying'
    );
$northstar_storage_migration_active$;
DO $pin_storage_migration_probe$
DECLARE
    migration_schema pg_catalog.text := pg_catalog.current_schema();
    routine_signature pg_catalog.text;
BEGIN
    FOREACH routine_signature IN ARRAY ARRAY[
        'northstar_storage_migration_active()'
    ] LOOP
        EXECUTE pg_catalog.format('ALTER FUNCTION %I.%s RESET ALL',migration_schema,routine_signature);
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
$pin_storage_migration_probe$;

CREATE TABLE upload_storage_migration_items (
    run_id UUID NOT NULL REFERENCES upload_storage_migration_runs(run_id),
    object_id UUID NOT NULL,
    source_backend TEXT NOT NULL CHECK (source_backend IN ('local','s3')),
    source_key TEXT NOT NULL,
    source_version TEXT,
    source_fence BIGINT NOT NULL CHECK (source_fence>=0),
    source_size BIGINT NOT NULL CHECK (source_size>=0),
    source_catalog_sha256 BYTEA CHECK (source_catalog_sha256 IS NULL OR octet_length(source_catalog_sha256)=32),
    source_sha256 BYTEA CHECK (source_sha256 IS NULL OR octet_length(source_sha256)=32),
    current_attempt UUID,
    claim_token UUID,
    claim_expires_at TIMESTAMPTZ,
    verified_at TIMESTAMPTZ,
    dest_key TEXT,
    dest_version TEXT,
    dest_size BIGINT CHECK (dest_size IS NULL OR dest_size>=0),
    dest_sha256 BYTEA CHECK (dest_sha256 IS NULL OR octet_length(dest_sha256)=32),
    PRIMARY KEY (run_id,object_id),
    CHECK ((claim_token IS NULL)=(claim_expires_at IS NULL)),
    CHECK (verified_at IS NULL OR
           (current_attempt IS NOT NULL AND claim_token IS NULL AND
            source_sha256 IS NOT NULL AND dest_key IS NOT NULL AND
            dest_size IS NOT NULL AND dest_sha256 IS NOT NULL)),
    CHECK (verified_at IS NOT NULL OR
           (dest_key IS NULL AND dest_version IS NULL AND dest_size IS NULL AND dest_sha256 IS NULL))
);
CREATE INDEX upload_storage_migration_items_claimable
    ON upload_storage_migration_items(run_id,object_id) WHERE verified_at IS NULL;

-- A retired attempt is never reused after an ambiguous object-store result.
-- The old key remains recorded until an operator proves exact cleanup.
CREATE TABLE upload_storage_migration_attempts (
    run_id UUID NOT NULL,
    object_id UUID NOT NULL,
    attempt_id UUID NOT NULL,
    dest_key TEXT NOT NULL,
    dest_version TEXT,
    state TEXT NOT NULL CHECK (state IN ('active','retired','verified','cleaned')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    retired_at TIMESTAMPTZ,
    cleaned_at TIMESTAMPTZ,
    PRIMARY KEY (run_id,object_id,attempt_id),
    FOREIGN KEY (run_id,object_id)
      REFERENCES upload_storage_migration_items(run_id,object_id),
    CHECK ((state='cleaned')=(cleaned_at IS NOT NULL))
);
CREATE INDEX upload_storage_migration_attempts_cleanup
    ON upload_storage_migration_attempts(run_id,object_id)
    WHERE state='retired';

-- This row is inserted in the same transaction as a restore replacement.
-- Recovery accepts only an exact restore/manifest/database/outcome tuple.
CREATE TABLE northstar_restore_outcome_markers (
    restore_id TEXT NOT NULL CHECK (restore_id ~ '^[0-9a-f]{32}$'),
    manifest_sha256 BYTEA NOT NULL CHECK (octet_length(manifest_sha256)=32),
    target_database_oid OID NOT NULL,
    outcome TEXT NOT NULL CHECK (outcome IN ('incoming','rollback')),
    transaction_xid XID8 NOT NULL,
    recorded_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (restore_id,outcome)
);

REVOKE ALL ON upload_storage_migration_runs,
    upload_storage_migration_items,
    upload_storage_migration_attempts,
    northstar_restore_outcome_markers FROM PUBLIC;
