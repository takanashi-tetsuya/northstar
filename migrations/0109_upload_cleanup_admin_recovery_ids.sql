-- Separate the administrator-facing cleanup recovery identity from the
-- physical upload/object identity.  `object_id` remains the worker authority;
-- an independently random UUID is the only value exposed by the control
-- plane, cursors, idempotency targets and audit records.

DO $northstar_upload_cleanup_recovery_id_precondition$
DECLARE
    migration_schema pg_catalog.text := pg_catalog.current_schema();
    cleanup_relation pg_catalog.oid;
BEGIN
    IF migration_schema IS NULL
       OR migration_schema IN ('pg_catalog','information_schema')
       OR migration_schema LIKE 'pg_temp_%'
       OR migration_schema LIKE 'pg_toast_temp_%' THEN
        RAISE EXCEPTION 'migration 0109 requires a dedicated application schema first in search_path'
            USING ERRCODE='3F000';
    END IF;

    cleanup_relation := pg_catalog.to_regclass(
        pg_catalog.format('%I.upload_cleanup_queue',migration_schema)
    );
    IF cleanup_relation IS NULL THEN
        RAISE EXCEPTION 'upload cleanup queue is absent from migration schema %',migration_schema
            USING ERRCODE='42P01';
    END IF;
    IF EXISTS (
        SELECT 1 FROM pg_catalog.pg_attribute
         WHERE attrelid=cleanup_relation AND attname='recovery_id' AND NOT attisdropped
    ) THEN
        RAISE EXCEPTION 'upload cleanup recovery identity already exists before migration 0109'
            USING ERRCODE='42701';
    END IF;
END;
$northstar_upload_cleanup_recovery_id_precondition$;

ALTER TABLE upload_cleanup_queue
    ADD COLUMN recovery_id pg_catalog.uuid;

-- PostgreSQL 14-17 provide gen_random_uuid() in pg_catalog.  The UNIQUE
-- constraint is installed only after the one-time backfill; the entire SQLx
-- migration is transactional, so the astronomically unlikely collision fails
-- closed and a clean replay generates a new set.
UPDATE upload_cleanup_queue
   SET recovery_id=pg_catalog.gen_random_uuid()
 WHERE recovery_id IS NULL;

ALTER TABLE upload_cleanup_queue
    ALTER COLUMN recovery_id SET DEFAULT pg_catalog.gen_random_uuid(),
    ALTER COLUMN recovery_id SET NOT NULL,
    ADD CONSTRAINT upload_cleanup_queue_recovery_id_key UNIQUE(recovery_id),
    ADD CONSTRAINT upload_cleanup_queue_recovery_id_non_nil
        CHECK(recovery_id<>'00000000-0000-0000-0000-000000000000'::pg_catalog.uuid),
    ADD CONSTRAINT upload_cleanup_queue_recovery_id_v4_variant
        CHECK(
            pg_catalog.substring(recovery_id::pg_catalog.text,15,1)='4'
            AND pg_catalog.substring(recovery_id::pg_catalog.text,20,1)
                IN ('8','9','a','b')
        ),
    ADD CONSTRAINT upload_cleanup_queue_recovery_id_not_object
        CHECK(recovery_id<>object_id);

CREATE INDEX upload_cleanup_queue_recovery_dead_idx
    ON upload_cleanup_queue(recovery_id)
    WHERE dead_lettered_at IS NOT NULL;

COMMENT ON COLUMN upload_cleanup_queue.recovery_id IS
    'Random immutable administrator recovery handle; never a storage object identity or locator';

-- Preserve every immutable projection field introduced through migration
-- 0105 and add the new external recovery identity to the same trigger fence.
CREATE OR REPLACE FUNCTION protect_upload_cleanup_identity()
RETURNS pg_catalog.trigger
LANGUAGE plpgsql
AS $northstar_upload_cleanup_identity$
BEGIN
    IF NEW.object_id IS DISTINCT FROM OLD.object_id
       OR NEW.recovery_id IS DISTINCT FROM OLD.recovery_id
       OR NEW.queued_at IS DISTINCT FROM OLD.queued_at
       OR NEW.storage_backend IS DISTINCT FROM OLD.storage_backend
       OR NEW.object_key IS DISTINCT FROM OLD.object_key
       OR NEW.object_version IS DISTINCT FROM OLD.object_version
       OR NEW.stage_key IS DISTINCT FROM OLD.stage_key
       OR NEW.stage_version IS DISTINCT FROM OLD.stage_version
       OR NEW.storage_attempt IS DISTINCT FROM OLD.storage_attempt
       OR NEW.expected_size IS DISTINCT FROM OLD.expected_size
       OR NEW.expected_sha256 IS DISTINCT FROM OLD.expected_sha256
       OR NEW.storage_fence IS DISTINCT FROM OLD.storage_fence
       OR NEW.slot_delete_projection IS DISTINCT FROM OLD.slot_delete_projection THEN
        RAISE EXCEPTION 'upload cleanup identity is immutable' USING ERRCODE='55000';
    END IF;
    RETURN NEW;
END;
$northstar_upload_cleanup_identity$;

-- Migration 0099 established an invariant that every application function is
-- pinned to its exact installation schema.  CREATE OR REPLACE must not weaken
-- that boundary, even though this particular trigger currently references
-- only NEW/OLD records.
DO $northstar_upload_cleanup_recovery_function_path$
DECLARE
    migration_schema pg_catalog.text := pg_catalog.current_schema();
BEGIN
    EXECUTE pg_catalog.format(
        'ALTER FUNCTION %I.protect_upload_cleanup_identity() RESET ALL',
        migration_schema
    );
    EXECUTE pg_catalog.format(
        'ALTER FUNCTION %I.protect_upload_cleanup_identity() '
        'SECURITY INVOKER SET search_path TO pg_catalog, %I, pg_temp',
        migration_schema,migration_schema
    );
END;
$northstar_upload_cleanup_recovery_function_path$;

-- Fresh-install/upgrade postcondition: validate the exact installation schema, type,
-- default, uniqueness and immutable-trigger attachment before SQLx may record
-- this migration as complete.
DO $northstar_upload_cleanup_recovery_id_postcondition$
DECLARE
    migration_schema pg_catalog.text := pg_catalog.current_schema();
    cleanup_relation pg_catalog.oid;
    recovery_attribute pg_catalog.record;
    unique_exact pg_catalog.bool;
    non_nil_exact pg_catalog.bool;
    v4_variant_exact pg_catalog.bool;
    distinct_from_object pg_catalog.bool;
    dead_index_exact pg_catalog.bool;
    trigger_exact pg_catalog.bool;
    expected_path pg_catalog.text;
BEGIN
    expected_path := pg_catalog.format(
        'search_path=pg_catalog, %I, pg_temp',migration_schema
    );
    cleanup_relation := pg_catalog.to_regclass(
        pg_catalog.format('%I.upload_cleanup_queue',migration_schema)
    );
    IF cleanup_relation IS NULL THEN
        RAISE EXCEPTION 'upload cleanup queue disappeared during migration 0109'
            USING ERRCODE='42P01';
    END IF;

    SELECT attribute.attnum,attribute.attnotnull,attribute.atttypid,
           pg_catalog.pg_get_expr(default_value.adbin,default_value.adrelid) AS default_expression
      INTO recovery_attribute
      FROM pg_catalog.pg_attribute attribute
      LEFT JOIN pg_catalog.pg_attrdef default_value
        ON default_value.adrelid=attribute.attrelid
       AND default_value.adnum=attribute.attnum
     WHERE attribute.attrelid=cleanup_relation
       AND attribute.attname='recovery_id'
       AND NOT attribute.attisdropped;
    IF NOT FOUND
       OR NOT COALESCE(recovery_attribute.attnotnull,FALSE)
       OR recovery_attribute.atttypid IS DISTINCT FROM
            'pg_catalog.uuid'::pg_catalog.regtype
       OR COALESCE(recovery_attribute.default_expression,'')
             NOT LIKE '%gen_random_uuid()%'
       OR EXISTS(
            SELECT 1
              FROM upload_cleanup_queue
             WHERE recovery_id IS NULL
                OR recovery_id='00000000-0000-0000-0000-000000000000'::pg_catalog.uuid
                OR pg_catalog.substring(recovery_id::pg_catalog.text,15,1)<>'4'
                OR pg_catalog.substring(recovery_id::pg_catalog.text,20,1)
                    NOT IN ('8','9','a','b')
          ) THEN
        RAISE EXCEPTION 'upload cleanup recovery identity column is not exact'
            USING ERRCODE='55000';
    END IF;

    SELECT pg_catalog.count(*)=1 AND pg_catalog.bool_and(
               constraint_row.contype='u'
               AND constraint_row.convalidated
               AND constraint_row.conkey=ARRAY[recovery_attribute.attnum]
           )
      INTO unique_exact
      FROM pg_catalog.pg_constraint constraint_row
     WHERE constraint_row.conrelid=cleanup_relation
       AND constraint_row.conname='upload_cleanup_queue_recovery_id_key';
    IF NOT COALESCE(unique_exact,FALSE) THEN
        RAISE EXCEPTION 'upload cleanup recovery identity uniqueness is not exact'
            USING ERRCODE='55000';
    END IF;

    SELECT pg_catalog.count(*)=1 AND pg_catalog.bool_and(
               constraint_row.contype='c'
               AND constraint_row.convalidated
               AND constraint_row.conkey=ARRAY[recovery_attribute.attnum]
               AND pg_catalog.pg_get_constraintdef(constraint_row.oid)
                   LIKE '%00000000-0000-0000-0000-000000000000%'
           )
      INTO non_nil_exact
      FROM pg_catalog.pg_constraint constraint_row
     WHERE constraint_row.conrelid=cleanup_relation
       AND constraint_row.conname='upload_cleanup_queue_recovery_id_non_nil';
    IF NOT COALESCE(non_nil_exact,FALSE) THEN
        RAISE EXCEPTION 'upload cleanup recovery identity permits the nil UUID'
            USING ERRCODE='55000';
    END IF;

    SELECT pg_catalog.count(*)=1 AND pg_catalog.bool_and(
               constraint_row.contype='c'
               AND constraint_row.convalidated
               AND constraint_row.conkey=ARRAY[recovery_attribute.attnum]
               AND pg_catalog.pg_get_constraintdef(constraint_row.oid) LIKE '%15%''4''%'
               AND pg_catalog.pg_get_constraintdef(constraint_row.oid) LIKE '%20%''8''%'
               AND pg_catalog.pg_get_constraintdef(constraint_row.oid) LIKE '%''9''%'
               AND pg_catalog.pg_get_constraintdef(constraint_row.oid) LIKE '%''a''%'
               AND pg_catalog.pg_get_constraintdef(constraint_row.oid) LIKE '%''b''%'
           )
      INTO v4_variant_exact
      FROM pg_catalog.pg_constraint constraint_row
     WHERE constraint_row.conrelid=cleanup_relation
       AND constraint_row.conname='upload_cleanup_queue_recovery_id_v4_variant';
    IF NOT COALESCE(v4_variant_exact,FALSE) THEN
        RAISE EXCEPTION 'upload cleanup recovery identity is not an RFC 4122 UUIDv4'
            USING ERRCODE='55000';
    END IF;

    SELECT pg_catalog.count(*)=1 AND pg_catalog.bool_and(
               constraint_row.contype='c'
               AND constraint_row.convalidated
               AND pg_catalog.pg_get_constraintdef(constraint_row.oid)
                   LIKE 'CHECK%recovery_id%<>%object_id%'
           )
      INTO distinct_from_object
      FROM pg_catalog.pg_constraint constraint_row
     WHERE constraint_row.conrelid=cleanup_relation
       AND constraint_row.conname='upload_cleanup_queue_recovery_id_not_object';
    IF NOT COALESCE(distinct_from_object,FALSE) THEN
        RAISE EXCEPTION 'upload cleanup recovery identity can alias its object identity'
            USING ERRCODE='55000';
    END IF;

    SELECT pg_catalog.count(*)=1 AND pg_catalog.bool_and(
               index_row.indisvalid
               AND index_row.indisready
               AND pg_catalog.pg_get_indexdef(index_row.indexrelid)
                   LIKE '%(recovery_id)%'
               AND pg_catalog.pg_get_expr(index_row.indpred,index_row.indrelid)
                   IN ('(dead_lettered_at IS NOT NULL)','dead_lettered_at IS NOT NULL')
           )
      INTO dead_index_exact
      FROM pg_catalog.pg_index index_row
      JOIN pg_catalog.pg_class index_relation
        ON index_relation.oid=index_row.indexrelid
      JOIN pg_catalog.pg_namespace index_schema
        ON index_schema.oid=index_relation.relnamespace
     WHERE index_schema.nspname=migration_schema
       AND index_relation.relname='upload_cleanup_queue_recovery_dead_idx'
       AND index_row.indrelid=cleanup_relation;
    IF NOT COALESCE(dead_index_exact,FALSE) THEN
        RAISE EXCEPTION 'upload cleanup recovery dead-letter index is not exact'
            USING ERRCODE='55000';
    END IF;

    SELECT pg_catalog.count(*)=1 AND pg_catalog.bool_and(
               NOT trigger_row.tgisinternal
                AND trigger_row.tgenabled IN ('O','A')
                AND trigger_row.tgqual IS NULL
                AND trigger_row.tgtype::pg_catalog.int4=19
                AND function_row.proname='protect_upload_cleanup_identity'
                AND function_schema.nspname=migration_schema
                AND function_row.pronargs=0
                AND function_row.prorettype='pg_catalog.trigger'::pg_catalog.regtype
                AND NOT function_row.prosecdef
                AND function_row.proowner=(
                    SELECT role_row.oid
                      FROM pg_catalog.pg_roles role_row
                     WHERE role_row.rolname=CURRENT_USER
                )
                AND function_row.prosrc LIKE '%NEW.recovery_id IS DISTINCT FROM OLD.recovery_id%'
                AND COALESCE(function_row.proconfig,ARRAY[]::pg_catalog.text[])=
                    ARRAY[expected_path]::pg_catalog.text[]
                AND (
                    SELECT pg_catalog.count(*)
                      FROM pg_catalog.pg_trigger attachment
                     WHERE attachment.tgfoid=function_row.oid
                       AND NOT attachment.tgisinternal
                )=1
            )
      INTO trigger_exact
      FROM pg_catalog.pg_trigger trigger_row
      JOIN pg_catalog.pg_proc function_row ON function_row.oid=trigger_row.tgfoid
      JOIN pg_catalog.pg_namespace function_schema ON function_schema.oid=function_row.pronamespace
     WHERE trigger_row.tgrelid=cleanup_relation
       AND trigger_row.tgname='upload_cleanup_identity_guard';
    IF NOT COALESCE(trigger_exact,FALSE) THEN
        RAISE EXCEPTION 'upload cleanup recovery identity is not protected by the exact immutable trigger'
            USING ERRCODE='55000';
    END IF;
END;
$northstar_upload_cleanup_recovery_id_postcondition$;
