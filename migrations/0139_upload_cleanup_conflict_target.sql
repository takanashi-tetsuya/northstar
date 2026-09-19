-- `northstar_upload_admit_expired_cleanup` returns a column named object_id.
-- In PL/pgSQL that output variable and an unqualified conflict-inference
-- column are ambiguous.  Keep the output contract while naming the immutable
-- primary-key constraint explicitly, so cleanup admission remains a single
-- fail-closed storage transaction.
CREATE OR REPLACE FUNCTION northstar_upload_admit_expired_cleanup()
RETURNS TABLE(object_id pg_catalog.uuid)
LANGUAGE plpgsql
SECURITY DEFINER
AS $northstar_upload_admit_expired_cleanup$
DECLARE slot_row pg_catalog.record;
DECLARE effective_object_version pg_catalog.text;
DECLARE effective_size pg_catalog.int8;
DECLARE inserted_rows pg_catalog.int8;
BEGIN
  PERFORM northstar_upload_require_capacity_lock();
  FOR slot_row IN
    SELECT slot.* FROM upload_slots slot
     WHERE slot.expires_at<=pg_catalog.clock_timestamp()
       AND slot.storage_state<>'deleting'
       AND (slot.uploaded OR NOT slot.uploading OR
            (slot.storage_state='writing' AND
             slot.claim_expires_at<=pg_catalog.clock_timestamp()-INTERVAL '5 minutes'))
     ORDER BY slot.expires_at,slot.id
     FOR UPDATE SKIP LOCKED LIMIT 32
  LOOP
    IF slot_row.storage_object_key IS NULL AND slot_row.storage_stage_key IS NULL THEN
      DELETE FROM upload_slots slot WHERE slot.id=slot_row.id
        AND slot.storage_object_key IS NULL AND slot.storage_stage_key IS NULL
        AND NOT slot.uploaded;
      object_id := slot_row.id;
      RETURN NEXT;
      CONTINUE;
    END IF;
    IF slot_row.storage_object_key IS NULL THEN
      RAISE EXCEPTION 'upload cleanup has a stage but no object key'
        USING ERRCODE='55000';
    END IF;
    effective_object_version := slot_row.storage_object_version;
    IF slot_row.storage_backend='s3'
       AND slot_row.storage_stage_key=slot_row.storage_object_key THEN
      effective_object_version := COALESCE(
        slot_row.storage_object_version,slot_row.storage_stage_version
      );
    END IF;
    effective_size := COALESCE(slot_row.storage_size,slot_row.size);
    INSERT INTO upload_cleanup_queue(
      object_id,storage_backend,object_key,object_version,stage_key,stage_version,
      storage_attempt,expected_size,expected_sha256,storage_fence,available_at
    ) VALUES(
      slot_row.id,slot_row.storage_backend,slot_row.storage_object_key,
      effective_object_version,slot_row.storage_stage_key,slot_row.storage_stage_version,
      slot_row.storage_attempt,effective_size,slot_row.storage_sha256,
      slot_row.storage_fence,CASE WHEN slot_row.storage_state='writing'
        THEN pg_catalog.clock_timestamp()+INTERVAL '16 minutes'
        ELSE pg_catalog.clock_timestamp() END
    ) ON CONFLICT ON CONSTRAINT upload_cleanup_queue_pkey DO NOTHING;
    GET DIAGNOSTICS inserted_rows=ROW_COUNT;
    IF inserted_rows=0 THEN
      IF NOT EXISTS(
        SELECT 1 FROM upload_cleanup_queue queue
         WHERE queue.object_id=slot_row.id
           AND queue.storage_backend=slot_row.storage_backend
           AND queue.object_key=slot_row.storage_object_key
           AND queue.object_version IS NOT DISTINCT FROM effective_object_version
           AND queue.stage_key IS NOT DISTINCT FROM slot_row.storage_stage_key
           AND queue.stage_version IS NOT DISTINCT FROM slot_row.storage_stage_version
           AND queue.storage_attempt IS NOT DISTINCT FROM slot_row.storage_attempt
           AND queue.expected_size=effective_size
           AND queue.expected_sha256 IS NOT DISTINCT FROM slot_row.storage_sha256
           AND queue.storage_fence=slot_row.storage_fence
           AND NOT queue.slot_delete_projection
      ) OR slot_row.storage_cleanup_debt_reserved THEN
        RAISE EXCEPTION 'existing upload cleanup projection differs or retained debt'
          USING ERRCODE='55000';
      END IF;
    END IF;
    UPDATE upload_slots slot
       SET storage_state='deleting',uploaded=FALSE,uploading=FALSE,
           claim_token=NULL,claim_expires_at=NULL,content_sha256=NULL,
           completed_at=NULL,storage_cleanup_debt_reserved=FALSE,
           storage_updated_at=pg_catalog.clock_timestamp()
     WHERE slot.id=slot_row.id;
    object_id := slot_row.id;
    RETURN NEXT;
  END LOOP;
END;
$northstar_upload_admit_expired_cleanup$;

-- Replacing a SECURITY DEFINER routine must never inherit a session search
-- path.  Bind the replacement to the current installation schema and attest
-- the complete function configuration immediately.
DO $northstar_upload_cleanup_conflict_target_path$
DECLARE migration_schema pg_catalog.text := pg_catalog.current_schema();
DECLARE expected_path pg_catalog.text;
BEGIN
  expected_path := pg_catalog.format(
    'search_path=pg_catalog, %I, pg_temp',migration_schema
  );
  EXECUTE pg_catalog.format(
    'ALTER FUNCTION %I.northstar_upload_admit_expired_cleanup() RESET ALL',
    migration_schema
  );
  EXECUTE pg_catalog.format(
    'ALTER FUNCTION %I.northstar_upload_admit_expired_cleanup() '
    'SECURITY DEFINER SET search_path TO pg_catalog, %I, pg_temp',
    migration_schema,migration_schema
  );
  IF NOT EXISTS(
    SELECT 1
      FROM pg_catalog.pg_proc routine
      JOIN pg_catalog.pg_namespace namespace ON namespace.oid=routine.pronamespace
     WHERE namespace.nspname=migration_schema
       AND routine.oid=pg_catalog.to_regprocedure(
         pg_catalog.format('%I.northstar_upload_admit_expired_cleanup()',migration_schema)
       )
       AND routine.prosecdef
       AND routine.proconfig=ARRAY[expected_path]::pg_catalog.text[]
  ) THEN
    RAISE EXCEPTION 'upload cleanup capability path was not rebound safely'
      USING ERRCODE='55000';
  END IF;
END;
$northstar_upload_cleanup_conflict_target_path$;
