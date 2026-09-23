-- Reader-first support for atomic MUC administrative batches. Existing
-- operations remain valid; writers are enabled only after every node can
-- render the new immutable event kind. The subject writer already emits its
-- own durable kind, which the original constraint inadvertently omitted.
DO $cluster_muc_admin_batch_prerequisites$
DECLARE
    migration_schema pg_catalog.text := pg_catalog.current_schema();
BEGIN
    IF migration_schema IS NULL
       OR migration_schema = 'information_schema'
       OR pg_catalog.left(migration_schema, 3) = 'pg_'
       OR pg_catalog.to_regclass(pg_catalog.format(
           '%I.%I', migration_schema, 'cluster_muc_operations'
       )) IS NULL THEN
        RAISE EXCEPTION 'cluster MUC operations are absent from a safe migration schema'
            USING ERRCODE = '42P01';
    END IF;
END;
$cluster_muc_admin_batch_prerequisites$;

ALTER TABLE cluster_muc_operations
    DROP CONSTRAINT cluster_muc_operations_operation_kind_check;
ALTER TABLE cluster_muc_operations
    ADD CONSTRAINT cluster_muc_operations_operation_kind_check CHECK (operation_kind IN (
        'join', 'rename', 'resume', 'suspend', 'leave', 'expire',
        'config', 'affiliation', 'role', 'ban', 'kick', 'destroy',
        'locked_expiry', 'account_delete', 'subject', 'admin_batch'
    ));
