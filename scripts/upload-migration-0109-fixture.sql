\set ON_ERROR_STOP on
SET search_path TO :"recovery_schema";

-- Minimal 0108-compatible cleanup queue.  This fixture deliberately creates
-- the identity function and its sole trigger before applying 0109 so the test
-- proves CREATE OR REPLACE preserves the attachment while strengthening it.
CREATE TABLE upload_cleanup_queue (
    object_id UUID PRIMARY KEY,
    queued_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    storage_backend TEXT NOT NULL DEFAULT 'local',
    object_key TEXT NOT NULL,
    object_version TEXT,
    stage_key TEXT,
    stage_version TEXT,
    storage_attempt UUID,
    expected_size BIGINT NOT NULL,
    expected_sha256 BYTEA,
    storage_fence BIGINT NOT NULL DEFAULT 0,
    slot_delete_projection BOOLEAN NOT NULL DEFAULT FALSE,
    dead_lettered_at TIMESTAMPTZ
);

CREATE FUNCTION protect_upload_cleanup_identity()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $fixture_old_upload_cleanup_identity$
BEGIN
    IF NEW.object_id IS DISTINCT FROM OLD.object_id THEN
        RAISE EXCEPTION 'upload cleanup identity is immutable' USING ERRCODE='55000';
    END IF;
    RETURN NEW;
END;
$fixture_old_upload_cleanup_identity$;
ALTER FUNCTION protect_upload_cleanup_identity()
    SECURITY INVOKER
    SET search_path TO pg_catalog, :"recovery_schema", pg_temp;

CREATE TRIGGER upload_cleanup_identity_guard
BEFORE UPDATE ON upload_cleanup_queue
FOR EACH ROW EXECUTE FUNCTION protect_upload_cleanup_identity();

INSERT INTO upload_cleanup_queue(object_id,object_key,expected_size,dead_lettered_at)
VALUES
    ('10000000-0000-4000-8000-000000000001',
     '10000000-0000-4000-8000-000000000001',1,clock_timestamp()),
    ('10000000-0000-4000-8000-000000000002',
     '10000000-0000-4000-8000-000000000002',2,clock_timestamp()),
    ('10000000-0000-4000-8000-000000000003',
     '10000000-0000-4000-8000-000000000003',3,clock_timestamp());

\ir ../migrations/0109_upload_cleanup_admin_recovery_ids.sql

DO $fixture_upload_cleanup_recovery_assertions$
DECLARE
    generated_recovery_id pg_catalog.uuid;
    default_expression pg_catalog.text;
    expected_path pg_catalog.text := pg_catalog.format(
        'search_path=pg_catalog, %I, pg_temp',pg_catalog.current_schema()
    );
    function_oid pg_catalog.oid;
    function_owner pg_catalog.text;
    function_security_definer pg_catalog.bool;
    function_config pg_catalog.text[];
    attachment_count pg_catalog.int8;
    exact_attachment_count pg_catalog.int8;
BEGIN
    IF (SELECT pg_catalog.count(*) FROM upload_cleanup_queue)<>3
       OR (SELECT pg_catalog.count(DISTINCT recovery_id) FROM upload_cleanup_queue)<>3
       OR EXISTS(
            SELECT 1
              FROM upload_cleanup_queue
             WHERE recovery_id IS NULL
                OR recovery_id=object_id
                OR recovery_id='00000000-0000-0000-0000-000000000000'::pg_catalog.uuid
                OR pg_catalog.substring(recovery_id::pg_catalog.text,15,1)<>'4'
                OR pg_catalog.substring(recovery_id::pg_catalog.text,20,1)
                    NOT IN ('8','9','a','b')
          ) THEN
        RAISE EXCEPTION '0109 did not backfill unique independent RFC 4122 UUIDv4 recovery IDs';
    END IF;

    SELECT pg_catalog.pg_get_expr(default_value.adbin,default_value.adrelid)
      INTO default_expression
      FROM pg_catalog.pg_attribute attribute
      JOIN pg_catalog.pg_attrdef default_value
        ON default_value.adrelid=attribute.attrelid
       AND default_value.adnum=attribute.attnum
     WHERE attribute.attrelid='upload_cleanup_queue'::pg_catalog.regclass
       AND attribute.attname='recovery_id'
       AND attribute.attnotnull
       AND attribute.atttypid='pg_catalog.uuid'::pg_catalog.regtype;
    IF COALESCE(default_expression,'') NOT LIKE '%gen_random_uuid()%' THEN
        RAISE EXCEPTION '0109 recovery UUID default is absent or not gen_random_uuid()';
    END IF;

    INSERT INTO upload_cleanup_queue(object_id,object_key,expected_size)
    VALUES(
        '10000000-0000-4000-8000-000000000004',
        '10000000-0000-4000-8000-000000000004',4
    )
    RETURNING recovery_id INTO generated_recovery_id;
    IF generated_recovery_id IS NULL
       OR generated_recovery_id='00000000-0000-0000-0000-000000000000'::pg_catalog.uuid
       OR generated_recovery_id='10000000-0000-4000-8000-000000000004'::pg_catalog.uuid
       OR pg_catalog.substring(generated_recovery_id::pg_catalog.text,15,1)<>'4'
       OR pg_catalog.substring(generated_recovery_id::pg_catalog.text,20,1)
            NOT IN ('8','9','a','b') THEN
        RAISE EXCEPTION '0109 default did not generate an independent RFC 4122 UUIDv4';
    END IF;

    BEGIN
        INSERT INTO upload_cleanup_queue(object_id,object_key,expected_size,recovery_id)
        VALUES(
            '10000000-0000-4000-8000-000000000005',
            '10000000-0000-4000-8000-000000000005',5,
            '00000000-0000-0000-0000-000000000000'
        );
        RAISE EXCEPTION '0109 accepted the nil recovery UUID';
    EXCEPTION WHEN check_violation THEN
        NULL;
    END;

    BEGIN
        INSERT INTO upload_cleanup_queue(object_id,object_key,expected_size,recovery_id)
        VALUES(
            '10000000-0000-4000-8000-000000000006',
            '10000000-0000-4000-8000-000000000006',6,
            '11111111-1111-1111-8111-111111111111'
        );
        RAISE EXCEPTION '0109 accepted a non-v4 recovery UUID';
    EXCEPTION WHEN check_violation THEN
        NULL;
    END;

    BEGIN
        INSERT INTO upload_cleanup_queue(object_id,object_key,expected_size,recovery_id)
        VALUES(
            '10000000-0000-4000-8000-000000000007',
            '10000000-0000-4000-8000-000000000007',7,
            '11111111-1111-4111-7111-111111111111'
        );
        RAISE EXCEPTION '0109 accepted a UUIDv4 with a non-RFC variant';
    EXCEPTION WHEN check_violation THEN
        NULL;
    END;

    BEGIN
        UPDATE upload_cleanup_queue
           SET recovery_id=pg_catalog.gen_random_uuid()
         WHERE object_id='10000000-0000-4000-8000-000000000001';
        RAISE EXCEPTION '0109 recovery identity remained mutable';
    EXCEPTION WHEN SQLSTATE '55000' THEN
        NULL;
    END;

    SELECT routine.oid,pg_catalog.pg_get_userbyid(routine.proowner),routine.prosecdef,
           COALESCE(routine.proconfig,ARRAY[]::pg_catalog.text[])
      INTO function_oid,function_owner,function_security_definer,function_config
      FROM pg_catalog.pg_proc routine
      JOIN pg_catalog.pg_namespace namespace ON namespace.oid=routine.pronamespace
     WHERE namespace.nspname=pg_catalog.current_schema()
       AND routine.proname='protect_upload_cleanup_identity'
       AND routine.pronargs=0;
    IF function_oid IS NULL
       OR function_owner<>CURRENT_USER
       OR function_security_definer
       OR function_config<>ARRAY[expected_path]::pg_catalog.text[] THEN
        RAISE EXCEPTION '0109 identity trigger function owner/authority/search_path is not exact';
    END IF;

    SELECT pg_catalog.count(*)
      INTO attachment_count
      FROM pg_catalog.pg_trigger trigger_row
     WHERE trigger_row.tgfoid=function_oid
       AND NOT trigger_row.tgisinternal;
    SELECT pg_catalog.count(*)
      INTO exact_attachment_count
      FROM pg_catalog.pg_trigger trigger_row
     WHERE trigger_row.tgfoid=function_oid
       AND trigger_row.tgrelid='upload_cleanup_queue'::pg_catalog.regclass
       AND trigger_row.tgname='upload_cleanup_identity_guard'
       AND trigger_row.tgtype::pg_catalog.int4=19
       AND trigger_row.tgenabled IN ('O','A')
       AND trigger_row.tgqual IS NULL
       AND NOT trigger_row.tgisinternal;
    IF attachment_count<>1 OR exact_attachment_count<>1 THEN
        RAISE EXCEPTION '0109 identity function does not have one exact trigger attachment';
    END IF;
END;
$fixture_upload_cleanup_recovery_assertions$;
