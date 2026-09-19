-- SQL-native NOWAIT admission for upload capacity mutations.
--
-- Upload capacity is represented by one authoritative ledger row.  Waiting
-- behind an owner of that row while holding an application-pool connection is
-- not useful work: callers can retry after the current durable transition has
-- completed.  The older runtime wrappers used a short transaction-local
-- timeout to contain that wait.  This migration moves the decision to the
-- owner-held SQL capability itself: capacity contention is SQLSTATE 55P03,
-- while established `FALSE` / `in_progress` outcomes retain their meanings.

DO $northstar_upload_capacity_nowait_precondition$
DECLARE
    migration_schema pg_catalog.text := pg_catalog.current_schema();
    relation_name pg_catalog.text;
BEGIN
    IF migration_schema IS NULL
       OR migration_schema IN ('pg_catalog','information_schema')
       OR migration_schema LIKE 'pg_temp_%'
       OR migration_schema LIKE 'pg_toast_temp_%' THEN
        RAISE EXCEPTION 'migration 0131 requires a dedicated application schema first in search_path'
            USING ERRCODE='3F000';
    END IF;
    FOREACH relation_name IN ARRAY ARRAY[
        'upload_slots','upload_storage_capacity_ledger',
        'upload_storage_jobs','upload_cleanup_queue'
    ] LOOP
        IF pg_catalog.to_regclass(
            pg_catalog.format('%I.%I',migration_schema,relation_name)
        ) IS NULL THEN
            RAISE EXCEPTION 'upload capacity relation %.% is absent',
                migration_schema,relation_name USING ERRCODE='42P01';
        END IF;
    END LOOP;
END;
$northstar_upload_capacity_nowait_precondition$;

-- Private, owner-only primitive.  Do not turn this into `FALSE`: generic
-- capability `FALSE` results mean a stale/no-op/unauthorized request, whereas
-- 55P03 means that a retry against the same durable authority is appropriate.
CREATE FUNCTION northstar_upload_require_capacity_lock()
RETURNS pg_catalog.void
LANGUAGE plpgsql
SECURITY DEFINER
AS $northstar_upload_require_capacity_lock$
BEGIN
    PERFORM 1
      FROM upload_storage_capacity_ledger
     WHERE singleton
     FOR UPDATE NOWAIT;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'upload storage capacity authority is missing'
            USING ERRCODE='55000';
    END IF;
END;
$northstar_upload_require_capacity_lock$;

-- Triggers introduced before the legacy AFTER capacity-accounting triggers
-- make all table-mutator paths take the canonical lock first.  Their names
-- intentionally sort before the established `upload_*` trigger names.
CREATE FUNCTION guard_upload_capacity_nowait()
RETURNS pg_catalog.trigger
LANGUAGE plpgsql
SECURITY DEFINER
AS $guard_upload_capacity_nowait$
BEGIN
    PERFORM northstar_upload_require_capacity_lock();
    IF TG_OP='DELETE' THEN
        RETURN OLD;
    END IF;
    RETURN NEW;
END;
$guard_upload_capacity_nowait$;

DROP TRIGGER IF EXISTS northstar_upload_capacity_nowait_slots_insert_delete
    ON upload_slots;
CREATE TRIGGER northstar_upload_capacity_nowait_slots_insert_delete
BEFORE INSERT OR DELETE ON upload_slots
FOR EACH ROW EXECUTE FUNCTION guard_upload_capacity_nowait();

DROP TRIGGER IF EXISTS northstar_upload_capacity_nowait_slot_locator_update
    ON upload_slots;
CREATE TRIGGER northstar_upload_capacity_nowait_slot_locator_update
BEFORE UPDATE OF storage_object_key,storage_stage_key ON upload_slots
FOR EACH ROW EXECUTE FUNCTION guard_upload_capacity_nowait();

DROP TRIGGER IF EXISTS northstar_upload_capacity_nowait_storage_job_insert_delete
    ON upload_storage_jobs;
CREATE TRIGGER northstar_upload_capacity_nowait_storage_job_insert_delete
BEFORE INSERT OR DELETE ON upload_storage_jobs
FOR EACH ROW EXECUTE FUNCTION guard_upload_capacity_nowait();

DROP TRIGGER IF EXISTS northstar_upload_capacity_nowait_cleanup_insert_delete
    ON upload_cleanup_queue;
CREATE TRIGGER northstar_upload_capacity_nowait_cleanup_insert_delete
BEFORE INSERT OR DELETE ON upload_cleanup_queue
FOR EACH ROW EXECUTE FUNCTION guard_upload_capacity_nowait();

-- The cleanup-debt trigger is the only slot update that may first introduce a
-- physical locator on a debt-free row.  It now uses the same typed admission
-- primitive directly; a prior locator trigger lock is re-entrant.
CREATE OR REPLACE FUNCTION reserve_upload_cleanup_debt()
RETURNS pg_catalog.trigger
LANGUAGE plpgsql
SECURITY DEFINER
AS $northstar_reserve_upload_cleanup_debt$
DECLARE
    policy_is_bound pg_catalog.bool;
BEGIN
    IF NOT OLD.storage_cleanup_debt_reserved
       AND (NEW.storage_object_key IS NOT NULL OR NEW.storage_stage_key IS NOT NULL)
       AND NOT EXISTS(
           SELECT 1 FROM upload_cleanup_queue WHERE object_id=NEW.id
       ) THEN
        PERFORM northstar_upload_require_capacity_lock();
        SELECT configured_pending_limit IS NOT NULL
               AND configured_retained_files_limit IS NOT NULL
               AND configured_retained_bytes_limit IS NOT NULL
          INTO policy_is_bound
          FROM upload_storage_capacity_ledger
         WHERE singleton;
        IF NOT COALESCE(policy_is_bound,FALSE) THEN
            RAISE EXCEPTION 'upload capacity authority is not fully bound'
                USING ERRCODE='55000';
        END IF;
        UPDATE upload_storage_capacity_ledger
           SET cleanup_obligation_debt=cleanup_obligation_debt+1,
               updated_at=pg_catalog.clock_timestamp()
         WHERE singleton
           AND pending_jobs+cleanup_obligation_debt<
               LEAST(configured_pending_limit,absolute_disaster_limit)
           AND retained_files+recovery_retained_files<=
               configured_retained_files_limit
           AND retained_bytes+recovery_retained_bytes<=
               configured_retained_bytes_limit;
        IF NOT FOUND THEN
            RAISE EXCEPTION 'upload cleanup capacity is exhausted'
                USING ERRCODE='53300';
        END IF;
        NEW.storage_cleanup_debt_reserved:=TRUE;
    END IF;
    RETURN NEW;
END;
$northstar_reserve_upload_cleanup_debt$;

CREATE OR REPLACE FUNCTION northstar_upload_bind_capacity_policy(
    requested_pending_limit pg_catalog.int8,
    requested_retained_files_limit pg_catalog.int8,
    requested_retained_bytes_limit pg_catalog.int8
) RETURNS TABLE(
    policy_generation pg_catalog.int8,
    recovery_draining pg_catalog.bool
)
LANGUAGE plpgsql
SECURITY DEFINER
AS $northstar_upload_bind_capacity_policy$
DECLARE
    current_pending_limit pg_catalog.int8;
    current_retained_files_limit pg_catalog.int8;
    current_retained_bytes_limit pg_catalog.int8;
BEGIN
    IF requested_pending_limit NOT BETWEEN 128 AND 100000
       OR requested_retained_files_limit NOT BETWEEN 1000 AND 100000000
       OR requested_retained_bytes_limit NOT BETWEEN 1 AND 1125899906842624 THEN
        RAISE EXCEPTION 'invalid upload storage capacity policy'
            USING ERRCODE='22023';
    END IF;
    PERFORM northstar_upload_require_capacity_lock();
    SELECT configured_pending_limit,configured_retained_files_limit,
           configured_retained_bytes_limit
      INTO current_pending_limit,current_retained_files_limit,
           current_retained_bytes_limit
      FROM upload_storage_capacity_ledger
     WHERE singleton;
    IF (current_pending_limit IS NOT NULL
            AND current_pending_limit<>requested_pending_limit)
       OR (current_retained_files_limit IS NOT NULL
            AND current_retained_files_limit<>requested_retained_files_limit)
       OR (current_retained_bytes_limit IS NOT NULL
            AND current_retained_bytes_limit<>requested_retained_bytes_limit) THEN
        RAISE EXCEPTION 'upload capacity policy differs from durable deployment authority'
            USING ERRCODE='55000';
    END IF;
    UPDATE upload_storage_capacity_ledger
       SET configured_pending_limit=COALESCE(
               configured_pending_limit,requested_pending_limit),
           configured_retained_files_limit=COALESCE(
               configured_retained_files_limit,requested_retained_files_limit),
           configured_retained_bytes_limit=COALESCE(
               configured_retained_bytes_limit,requested_retained_bytes_limit),
           legacy_overcommit_draining=(pending_jobs+cleanup_obligation_debt>
               LEAST(requested_pending_limit,absolute_disaster_limit)),
           recovery_overcommit_draining=(
               retained_files+recovery_retained_files>
                   requested_retained_files_limit
               OR retained_bytes+recovery_retained_bytes>
                   requested_retained_bytes_limit),
           updated_at=pg_catalog.clock_timestamp()
     WHERE singleton
     RETURNING upload_storage_capacity_ledger.policy_generation,
               upload_storage_capacity_ledger.legacy_overcommit_draining
                 OR upload_storage_capacity_ledger.recovery_overcommit_draining
      INTO policy_generation,recovery_draining;
    RETURN NEXT;
END;
$northstar_upload_bind_capacity_policy$;

-- Preserve the existing runtime callable identity used by account deletion,
-- PIE, and command paths, but give it the same typed NOWAIT behavior.
CREATE OR REPLACE FUNCTION northstar_upload_capacity_lock()
RETURNS pg_catalog.bool
LANGUAGE plpgsql
SECURITY DEFINER
AS $northstar_upload_capacity_lock$
BEGIN
    PERFORM northstar_upload_require_capacity_lock();
    RETURN TRUE;
END;
$northstar_upload_capacity_lock$;

CREATE OR REPLACE FUNCTION northstar_upload_complete_cleanup(
    requested_id pg_catalog.uuid,requested_claim_token pg_catalog.uuid
) RETURNS pg_catalog.bool
LANGUAGE plpgsql
SECURITY DEFINER
AS $northstar_upload_complete_cleanup$
DECLARE slot_removed pg_catalog.bool;
DECLARE slot_still_exists pg_catalog.bool;
BEGIN
    PERFORM northstar_upload_require_capacity_lock();
    PERFORM 1 FROM upload_cleanup_queue
     WHERE object_id=requested_id AND claim_token=requested_claim_token
       AND claim_expires_at>pg_catalog.clock_timestamp() FOR UPDATE;
    IF NOT FOUND THEN RETURN FALSE; END IF;
    DELETE FROM upload_slots slot USING upload_cleanup_queue queue
     WHERE slot.id=requested_id AND slot.storage_state='deleting'
       AND queue.object_id=slot.id AND queue.claim_token=requested_claim_token
       AND queue.storage_backend=slot.storage_backend
       AND queue.storage_fence=slot.storage_fence
       AND queue.object_key=slot.storage_object_key
       AND queue.object_version IS NOT DISTINCT FROM
         CASE WHEN slot.storage_backend='s3'
                    AND slot.storage_stage_key=slot.storage_object_key
              THEN COALESCE(slot.storage_object_version,slot.storage_stage_version)
              ELSE slot.storage_object_version END
       AND queue.stage_key IS NOT DISTINCT FROM slot.storage_stage_key
       AND queue.stage_version IS NOT DISTINCT FROM slot.storage_stage_version
       AND queue.storage_attempt IS NOT DISTINCT FROM slot.storage_attempt;
    slot_removed:=FOUND;
    IF NOT slot_removed THEN
        SELECT EXISTS(SELECT 1 FROM upload_slots WHERE id=requested_id)
          INTO slot_still_exists;
        IF slot_still_exists THEN RETURN FALSE; END IF;
    END IF;
    DELETE FROM upload_cleanup_queue
     WHERE object_id=requested_id AND claim_token=requested_claim_token;
    RETURN FOUND;
END;
$northstar_upload_complete_cleanup$;

CREATE OR REPLACE FUNCTION northstar_upload_complete_storage_job(
    requested_id pg_catalog.int8,requested_claim_token pg_catalog.uuid
) RETURNS pg_catalog.bool
LANGUAGE plpgsql
SECURITY DEFINER
AS $northstar_upload_complete_storage_job$
BEGIN
    PERFORM northstar_upload_require_capacity_lock();
    DELETE FROM upload_storage_jobs
     WHERE id=requested_id AND claim_token=requested_claim_token;
    RETURN FOUND;
END;
$northstar_upload_complete_storage_job$;

CREATE OR REPLACE FUNCTION northstar_upload_retire_promotion_for_cleanup(
    requested_id pg_catalog.uuid,requested_attempt pg_catalog.uuid,
    requested_fence pg_catalog.int8,requested_claim_token pg_catalog.uuid
) RETURNS pg_catalog.bool
LANGUAGE plpgsql
SECURITY DEFINER
AS $northstar_upload_retire_promotion_for_cleanup$
BEGIN
    PERFORM northstar_upload_require_capacity_lock();
    IF NOT EXISTS(
      SELECT 1 FROM upload_cleanup_queue
       WHERE object_id=requested_id AND storage_attempt=requested_attempt
         AND storage_fence=requested_fence
    ) THEN RETURN FALSE; END IF;
    DELETE FROM upload_storage_jobs
     WHERE object_id=requested_id AND storage_attempt=requested_attempt
       AND action='promote' AND storage_fence=requested_fence
       AND claim_token=requested_claim_token;
    RETURN FOUND;
END;
$northstar_upload_retire_promotion_for_cleanup$;

CREATE OR REPLACE FUNCTION northstar_upload_record_stage(
    requested_id pg_catalog.uuid,requested_claim_token pg_catalog.uuid,
    requested_backend pg_catalog.text,requested_stage_key pg_catalog.text,
    requested_stage_version pg_catalog.text,requested_object_key pg_catalog.text,
    requested_sha256 pg_catalog.bytea,requested_size pg_catalog.int8,
    requested_fence pg_catalog.int8
) RETURNS pg_catalog.bool
LANGUAGE plpgsql
SECURITY DEFINER
AS $northstar_upload_record_stage$
DECLARE durable_fence pg_catalog.int8;
DECLARE inserted_rows pg_catalog.int8;
BEGIN
    IF requested_size<=0 OR pg_catalog.octet_length(requested_sha256)<>32 THEN
        RAISE EXCEPTION 'invalid upload stage projection' USING ERRCODE='22023';
    END IF;
    PERFORM northstar_upload_require_capacity_lock();
    UPDATE upload_slots
       SET storage_state='staged',storage_stage_version=requested_stage_version,
           storage_sha256=requested_sha256,storage_size=requested_size,
           storage_updated_at=pg_catalog.clock_timestamp()
     WHERE id=requested_id AND claim_token=requested_claim_token
       AND uploading AND NOT uploaded AND storage_state='writing'
       AND storage_attempt=requested_claim_token
       AND storage_backend=requested_backend
       AND storage_stage_key=requested_stage_key
       AND storage_object_key=requested_object_key
       AND size=requested_size AND storage_fence=requested_fence
     RETURNING storage_fence INTO durable_fence;
    IF NOT FOUND THEN RETURN FALSE; END IF;
    INSERT INTO upload_storage_jobs(
        object_id,storage_attempt,action,storage_backend,stage_key,
        stage_version,object_key,expected_size,expected_sha256,storage_fence
    ) VALUES(
        requested_id,requested_claim_token,'promote',requested_backend,
        requested_stage_key,requested_stage_version,requested_object_key,
        requested_size,requested_sha256,durable_fence
    ) ON CONFLICT(object_id,storage_attempt,action) DO NOTHING;
    GET DIAGNOSTICS inserted_rows=ROW_COUNT;
    IF inserted_rows=0 AND NOT EXISTS(
      SELECT 1 FROM upload_storage_jobs
       WHERE object_id=requested_id AND storage_attempt=requested_claim_token
         AND action='promote' AND storage_backend=requested_backend
         AND stage_key=requested_stage_key
         AND stage_version IS NOT DISTINCT FROM requested_stage_version
         AND object_key=requested_object_key AND object_version IS NULL
         AND expected_size=requested_size AND expected_sha256=requested_sha256
         AND storage_fence=durable_fence
    ) THEN
        RAISE EXCEPTION 'existing upload promotion projection has different identity'
            USING ERRCODE='55000';
    END IF;
    RETURN TRUE;
END;
$northstar_upload_record_stage$;

CREATE OR REPLACE FUNCTION northstar_upload_release_claim(
    requested_id pg_catalog.uuid,requested_claim_token pg_catalog.uuid
) RETURNS pg_catalog.bool
LANGUAGE plpgsql
SECURITY DEFINER
AS $northstar_upload_release_claim$
DECLARE slot_row pg_catalog.record;
DECLARE inserted_rows pg_catalog.int8;
BEGIN
    PERFORM northstar_upload_require_capacity_lock();
    SELECT storage_backend,storage_stage_key,storage_stage_version,
           storage_fence,size,storage_state,storage_cleanup_debt_reserved
      INTO slot_row FROM upload_slots
     WHERE id=requested_id AND claim_token=requested_claim_token
       AND uploading AND NOT uploaded AND storage_attempt=requested_claim_token
       AND storage_stage_key IS NOT NULL FOR UPDATE;
    IF NOT FOUND THEN RETURN FALSE; END IF;
    INSERT INTO upload_storage_jobs(
        object_id,storage_attempt,action,storage_backend,stage_key,
        stage_version,storage_fence,expected_size,available_at
    ) VALUES(
        requested_id,requested_claim_token,'delete_stage',slot_row.storage_backend,
        slot_row.storage_stage_key,slot_row.storage_stage_version,
        slot_row.storage_fence,slot_row.size,
        CASE WHEN slot_row.storage_backend='s3' AND slot_row.storage_state='writing'
             THEN pg_catalog.clock_timestamp()+INTERVAL '16 minutes'
             ELSE pg_catalog.clock_timestamp() END
    ) ON CONFLICT(object_id,storage_attempt,action) DO NOTHING;
    GET DIAGNOSTICS inserted_rows=ROW_COUNT;
    IF inserted_rows=0 THEN
        IF NOT EXISTS(
          SELECT 1 FROM upload_storage_jobs
           WHERE object_id=requested_id AND storage_attempt=requested_claim_token
             AND action='delete_stage' AND storage_backend=slot_row.storage_backend
             AND stage_key=slot_row.storage_stage_key
             AND stage_version IS NOT DISTINCT FROM slot_row.storage_stage_version
             AND object_key IS NULL AND object_version IS NULL
             AND expected_size=slot_row.size AND expected_sha256 IS NULL
             AND storage_fence=slot_row.storage_fence
        ) OR slot_row.storage_cleanup_debt_reserved THEN
            RAISE EXCEPTION 'existing released-upload cleanup has different identity or debt'
                USING ERRCODE='55000';
        END IF;
    END IF;
    UPDATE upload_slots
       SET uploading=FALSE,claim_token=NULL,claim_expires_at=NULL,
           storage_state='reserved',storage_attempt=NULL,
           storage_stage_key=NULL,storage_stage_version=NULL,
           storage_object_key=NULL,storage_object_version=NULL,
           storage_sha256=NULL,storage_size=NULL,
           storage_cleanup_debt_reserved=FALSE,
           storage_updated_at=pg_catalog.clock_timestamp()
     WHERE id=requested_id AND claim_token=requested_claim_token
       AND uploading AND NOT uploaded;
    RETURN FOUND;
END;
$northstar_upload_release_claim$;

CREATE OR REPLACE FUNCTION northstar_upload_complete_promotion(
    requested_id pg_catalog.uuid,requested_claim_token pg_catalog.uuid,
    requested_promotion_claim_token pg_catalog.uuid,
    requested_backend pg_catalog.text,requested_object_key pg_catalog.text,
    requested_object_version pg_catalog.text,requested_sha256 pg_catalog.bytea,
    requested_size pg_catalog.int8,requested_retention_seconds pg_catalog.int8,
    requested_fence pg_catalog.int8
) RETURNS pg_catalog.bool
LANGUAGE plpgsql
SECURITY DEFINER
AS $northstar_upload_complete_promotion$
DECLARE slot_row pg_catalog.record;
DECLARE inserted_rows pg_catalog.int8;
BEGIN
    IF requested_size<=0 OR requested_retention_seconds<=0
       OR pg_catalog.octet_length(requested_sha256)<>32 THEN
        RAISE EXCEPTION 'invalid promoted upload projection' USING ERRCODE='22023';
    END IF;
    PERFORM northstar_upload_require_capacity_lock();
    SELECT storage_stage_key,storage_stage_version,storage_fence
      INTO slot_row FROM upload_slots
     WHERE id=requested_id AND claim_token=requested_claim_token
       AND storage_attempt=requested_claim_token AND uploading AND NOT uploaded
       AND storage_state IN ('staged','promoting')
       AND storage_backend=requested_backend
       AND storage_object_key=requested_object_key
       AND storage_sha256=requested_sha256 AND storage_size=requested_size
       AND storage_fence=requested_fence FOR UPDATE;
    IF NOT FOUND THEN RETURN FALSE; END IF;
    PERFORM 1 FROM upload_storage_jobs
     WHERE object_id=requested_id AND storage_attempt=requested_claim_token
       AND action='promote' AND storage_fence=requested_fence
       AND claim_token=requested_promotion_claim_token
       AND claim_expires_at>pg_catalog.clock_timestamp()
     FOR UPDATE;
    IF NOT FOUND THEN RETURN FALSE; END IF;
    IF requested_backend='s3' THEN
        IF slot_row.storage_stage_key<>requested_object_key
           OR slot_row.storage_stage_version IS DISTINCT FROM requested_object_version THEN
            RAISE EXCEPTION 'S3 promoted projection differs from exact stage'
                USING ERRCODE='55000';
        END IF;
    ELSIF requested_backend='local' THEN
        IF slot_row.storage_stage_key=requested_object_key THEN
            RAISE EXCEPTION 'local stage and immutable destination must differ'
                USING ERRCODE='55000';
        END IF;
    ELSE
        RAISE EXCEPTION 'invalid upload backend' USING ERRCODE='22023';
    END IF;
    UPDATE upload_slots
       SET uploaded=TRUE,uploading=FALSE,claim_token=NULL,claim_expires_at=NULL,
           content_sha256=requested_sha256,completed_at=pg_catalog.clock_timestamp(),
           put_expires_at=pg_catalog.clock_timestamp()+INTERVAL '5 minutes',
           expires_at=pg_catalog.clock_timestamp()
             +(requested_retention_seconds*INTERVAL '1 second'),
           storage_state='committed',storage_stage_key=NULL,
           storage_stage_version=NULL,storage_object_version=requested_object_version,
           storage_updated_at=pg_catalog.clock_timestamp()
     WHERE id=requested_id AND storage_attempt=requested_claim_token
       AND claim_token=requested_claim_token AND storage_fence=requested_fence
       AND storage_state IN ('staged','promoting');
    IF NOT FOUND THEN
        RAISE EXCEPTION 'locked upload stage changed before completion'
            USING ERRCODE='40001';
    END IF;
    DELETE FROM upload_storage_jobs
     WHERE object_id=requested_id AND storage_attempt=requested_claim_token
       AND action='promote' AND storage_fence=requested_fence
       AND claim_token=requested_promotion_claim_token
       AND claim_expires_at>pg_catalog.clock_timestamp();
    IF NOT FOUND THEN
        RAISE EXCEPTION 'promotion lease changed before metadata completion'
            USING ERRCODE='40001';
    END IF;
    IF slot_row.storage_stage_key<>requested_object_key THEN
        INSERT INTO upload_storage_jobs(
            object_id,storage_attempt,action,storage_backend,stage_key,
            stage_version,storage_fence,expected_size
        ) VALUES(
            requested_id,requested_claim_token,'delete_stage',requested_backend,
            slot_row.storage_stage_key,slot_row.storage_stage_version,
            slot_row.storage_fence,requested_size
        ) ON CONFLICT(object_id,storage_attempt,action) DO NOTHING;
        GET DIAGNOSTICS inserted_rows=ROW_COUNT;
        IF inserted_rows=0 AND NOT EXISTS(
          SELECT 1 FROM upload_storage_jobs
           WHERE object_id=requested_id AND storage_attempt=requested_claim_token
             AND action='delete_stage' AND storage_backend=requested_backend
             AND stage_key=slot_row.storage_stage_key
             AND stage_version IS NOT DISTINCT FROM slot_row.storage_stage_version
             AND object_key IS NULL AND object_version IS NULL
             AND expected_size=requested_size AND expected_sha256 IS NULL
             AND storage_fence=slot_row.storage_fence
        ) THEN
            RAISE EXCEPTION 'post-promotion cleanup has different identity'
                USING ERRCODE='55000';
        END IF;
    END IF;
    RETURN TRUE;
END;
$northstar_upload_complete_promotion$;

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
    ) ON CONFLICT(object_id) DO NOTHING;
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

CREATE OR REPLACE FUNCTION northstar_upload_delete_owned(
  requested_user_id pg_catalog.uuid,expected_auth_generation pg_catalog.int8,
  presented_session_hash pg_catalog.bytea,requested_id pg_catalog.uuid,
  requested_request_id pg_catalog.uuid
) RETURNS pg_catalog.text
LANGUAGE plpgsql
SECURITY DEFINER
AS $northstar_upload_delete_owned$
DECLARE slot_row pg_catalog.record;
DECLARE effective_object_key pg_catalog.text;
DECLARE effective_object_version pg_catalog.text;
DECLARE effective_size pg_catalog.int8;
DECLARE cleanup_queued pg_catalog.bool;
DECLARE inserted_rows pg_catalog.int8;
BEGIN
  IF pg_catalog.octet_length(presented_session_hash)<>32 THEN
    RETURN 'unauthorized';
  END IF;
  PERFORM northstar_upload_require_capacity_lock();
  PERFORM 1 FROM users
   WHERE id=requested_user_id AND auth_generation=expected_auth_generation
     AND NOT is_disabled FOR SHARE;
  IF NOT FOUND THEN RETURN 'unauthorized'; END IF;
  PERFORM 1 FROM api_sessions
   WHERE user_id=requested_user_id AND token_hash=presented_session_hash
     AND expires_at>pg_catalog.clock_timestamp() FOR SHARE;
  IF NOT FOUND THEN RETURN 'unauthorized'; END IF;
  SELECT slot.* INTO slot_row FROM upload_slots slot
   WHERE slot.id=requested_id AND slot.user_id=requested_user_id FOR UPDATE;
  IF NOT FOUND THEN RETURN 'accepted'; END IF;
  cleanup_queued := slot_row.storage_object_key IS NOT NULL
    OR slot_row.storage_stage_key IS NOT NULL OR slot_row.uploaded;
  IF NOT cleanup_queued THEN
    DELETE FROM upload_slots slot
     WHERE slot.id=requested_id AND slot.user_id=requested_user_id;
    IF NOT FOUND THEN
      RAISE EXCEPTION 'locked upload reservation disappeared before deletion'
        USING ERRCODE='40001';
    END IF;
  ELSE
    effective_object_key := COALESCE(
      slot_row.storage_object_key,
      CASE WHEN slot_row.uploaded THEN slot_row.id::pg_catalog.text ELSE NULL END
    );
    IF effective_object_key IS NULL THEN
      RAISE EXCEPTION 'upload deletion has a stage but no object key'
        USING ERRCODE='55000';
    END IF;
    effective_object_version := slot_row.storage_object_version;
    IF slot_row.storage_backend='s3'
       AND slot_row.storage_stage_key=effective_object_key THEN
      effective_object_version := COALESCE(
        slot_row.storage_object_version,slot_row.storage_stage_version
      );
    END IF;
    effective_size := COALESCE(slot_row.storage_size,slot_row.size);
    INSERT INTO upload_cleanup_queue(
      object_id,storage_backend,object_key,object_version,stage_key,stage_version,
      storage_attempt,expected_size,expected_sha256,storage_fence,available_at
    ) VALUES(
      slot_row.id,slot_row.storage_backend,effective_object_key,
      effective_object_version,slot_row.storage_stage_key,slot_row.storage_stage_version,
      slot_row.storage_attempt,effective_size,slot_row.storage_sha256,
      slot_row.storage_fence,CASE WHEN slot_row.storage_state='writing'
        THEN pg_catalog.clock_timestamp()+INTERVAL '16 minutes'
        ELSE pg_catalog.clock_timestamp() END
    ) ON CONFLICT(object_id) DO NOTHING;
    GET DIAGNOSTICS inserted_rows=ROW_COUNT;
    IF inserted_rows=0 THEN
      IF NOT EXISTS(
        SELECT 1 FROM upload_cleanup_queue queue
         WHERE queue.object_id=slot_row.id
           AND queue.storage_backend=slot_row.storage_backend
           AND queue.object_key=effective_object_key
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
    UPDATE upload_slots slot SET storage_state='deleting',uploaded=FALSE,
      uploading=FALSE,claim_token=NULL,claim_expires_at=NULL,content_sha256=NULL,
      completed_at=NULL,storage_cleanup_debt_reserved=FALSE,
      expires_at=pg_catalog.clock_timestamp(),
      storage_updated_at=pg_catalog.clock_timestamp()
     WHERE slot.id=requested_id AND slot.user_id=requested_user_id;
    IF NOT FOUND THEN
      RAISE EXCEPTION 'locked upload row disappeared before deletion'
        USING ERRCODE='40001';
    END IF;
  END IF;
  INSERT INTO audit_log(actor_id,action,target,details,request_id)
  VALUES(requested_user_id,'user.upload.delete',requested_id::pg_catalog.text,
    pg_catalog.jsonb_build_object(
      'size',slot_row.size,'uploaded',slot_row.uploaded,
      'uploading',slot_row.uploading,'cleanup_queued',cleanup_queued
    ),requested_request_id);
  RETURN 'accepted';
END;
$northstar_upload_delete_owned$;

CREATE OR REPLACE FUNCTION northstar_upload_capability_catalog_healthy(
  requested_schema pg_catalog.text
) RETURNS pg_catalog.bool
LANGUAGE sql
SECURITY DEFINER
STABLE
AS $northstar_upload_capability_catalog_healthy$
WITH namespace AS (
  SELECT oid,nspowner FROM pg_catalog.pg_namespace
   WHERE nspname=requested_schema
), upload_relations AS (
  SELECT relation.oid,relation.relowner,relation.relacl,namespace.nspowner
    FROM namespace
    JOIN pg_catalog.pg_class relation ON relation.relnamespace=namespace.oid
   WHERE relation.relname IN (
     'upload_storage_authority','upload_storage_capacity_ledger','upload_slots',
     'upload_storage_jobs','upload_cleanup_queue'
   ) AND relation.relkind IN ('r','p')
), upload_routines AS (
  SELECT routine.oid,routine.proname,routine.proowner,routine.prosecdef,routine.proconfig,
         routine.proacl,namespace.nspowner
    FROM namespace
    JOIN pg_catalog.pg_proc routine ON routine.pronamespace=namespace.oid
   WHERE routine.proname LIKE 'northstar_upload_%'
), public_relation_acl AS (
  SELECT 1 FROM upload_relations relation
  CROSS JOIN LATERAL pg_catalog.aclexplode(COALESCE(
    relation.relacl,pg_catalog.acldefault('r',relation.relowner)
  )) privilege WHERE privilege.grantee=0
), public_routine_acl AS (
  SELECT 1 FROM upload_routines routine
  CROSS JOIN LATERAL pg_catalog.aclexplode(COALESCE(
    routine.proacl,pg_catalog.acldefault('f',routine.proowner)
  )) privilege
  WHERE privilege.grantee=0 AND privilege.privilege_type='EXECUTE'
), runtime_relation_acl AS (
  SELECT 1 FROM upload_relations relation
   WHERE SESSION_USER<>pg_catalog.pg_get_userbyid(relation.relowner)
     AND (
       pg_catalog.has_table_privilege(SESSION_USER,relation.oid,'SELECT')
       OR pg_catalog.has_table_privilege(SESSION_USER,relation.oid,'INSERT')
       OR pg_catalog.has_table_privilege(SESSION_USER,relation.oid,'UPDATE')
       OR pg_catalog.has_table_privilege(SESSION_USER,relation.oid,'DELETE')
       OR pg_catalog.has_table_privilege(SESSION_USER,relation.oid,'TRUNCATE')
       OR pg_catalog.has_table_privilege(SESSION_USER,relation.oid,'REFERENCES')
       OR pg_catalog.has_table_privilege(SESSION_USER,relation.oid,'TRIGGER')
       OR pg_catalog.has_any_column_privilege(SESSION_USER,relation.oid,'SELECT')
       OR pg_catalog.has_any_column_privilege(SESSION_USER,relation.oid,'INSERT')
       OR pg_catalog.has_any_column_privilege(SESSION_USER,relation.oid,'UPDATE')
       OR pg_catalog.has_any_column_privilege(SESSION_USER,relation.oid,'REFERENCES')
     )
), runtime_routine_acl_mismatch AS (
  SELECT 1 FROM upload_routines routine
   WHERE SESSION_USER<>pg_catalog.pg_get_userbyid(routine.proowner)
     AND pg_catalog.has_function_privilege(
           SESSION_USER,routine.oid,'EXECUTE'
         ) IS DISTINCT FROM
         (routine.proname NOT IN (
           'northstar_upload_offline_bootstrap_authority',
           'northstar_upload_require_capacity_lock'
         ))
)
SELECT (SELECT pg_catalog.count(*)=1 FROM namespace)
  AND (SELECT pg_catalog.count(*)=5 AND pg_catalog.bool_and(
         relowner=nspowner
       ) FROM upload_relations)
  AND NOT EXISTS(SELECT 1 FROM public_relation_acl)
  AND NOT EXISTS(SELECT 1 FROM runtime_relation_acl)
  AND (SELECT pg_catalog.count(*)=43 AND pg_catalog.bool_and(
         proowner=nspowner AND prosecdef
         AND proconfig=ARRAY[
           pg_catalog.format('search_path=pg_catalog, %I, pg_temp',requested_schema)
         ]::pg_catalog.text[]
       ) FROM upload_routines)
  AND NOT EXISTS(SELECT 1 FROM public_routine_acl)
  AND NOT EXISTS(SELECT 1 FROM runtime_routine_acl_mismatch)
$northstar_upload_capability_catalog_healthy$;

-- Reservation and claim have long-established non-error contention results.
-- Keep those result contracts at the SQL boundary while eliminating the final
-- application-side timeout: both the capacity ledger and their subsequent
-- owner/slot row use NOWAIT.
CREATE OR REPLACE FUNCTION northstar_upload_reserve_slot(
    requested_id pg_catalog.uuid,requested_user_id pg_catalog.uuid,
    requested_filename pg_catalog.text,requested_content_type pg_catalog.text,
    requested_size pg_catalog.int8,requested_token_hash pg_catalog.bytea,
    requested_user_file_limit pg_catalog.int8,
    requested_user_byte_limit pg_catalog.int8,
    requested_backend pg_catalog.text,
    expected_retained_file_limit pg_catalog.int8,
    expected_retained_byte_limit pg_catalog.int8,
    expected_pending_limit pg_catalog.int8
) RETURNS pg_catalog.bool
LANGUAGE plpgsql
SECURITY DEFINER
AS $northstar_upload_reserve_slot$
DECLARE ledger_row pg_catalog.record;
DECLARE current_files pg_catalog.int8;
DECLARE current_bytes pg_catalog.int8;
DECLARE admission_job_ceiling pg_catalog.int8;
DECLARE caught_message pg_catalog.text;
BEGIN
    IF requested_size<=0 OR requested_backend NOT IN ('local','s3')
       OR requested_user_file_limit<=0 OR requested_user_byte_limit<=0
       OR expected_retained_file_limit<=0 OR expected_retained_byte_limit<=0
       OR expected_pending_limit<=0 THEN
        RAISE EXCEPTION 'invalid upload reservation policy' USING ERRCODE='22023';
    END IF;

    -- This exception block is deliberately a single SQL subtransaction.  A
    -- successful reservation promotes the ledger lock to the caller's
    -- transaction with its INSERT.  Every typed non-admission result instead
    -- raises the private sentinel, rolls this savepoint back, and therefore
    -- cannot leave the singleton locked while an outer request transaction
    -- continues to do unrelated work.
    BEGIN
        SELECT * INTO ledger_row FROM upload_storage_capacity_ledger
         WHERE singleton FOR UPDATE NOWAIT;
        IF NOT FOUND THEN
            RAISE EXCEPTION 'upload storage capacity authority is missing'
                USING ERRCODE='55000';
        END IF;
        IF ledger_row.configured_pending_limit IS DISTINCT FROM expected_pending_limit
           OR ledger_row.configured_retained_files_limit IS DISTINCT FROM expected_retained_file_limit
           OR ledger_row.configured_retained_bytes_limit IS DISTINCT FROM expected_retained_byte_limit THEN
            RAISE EXCEPTION 'upload admission limits differ from durable deployment authority'
                USING ERRCODE='55000';
        END IF;
        PERFORM 1 FROM users WHERE id=requested_user_id FOR UPDATE NOWAIT;
        IF NOT FOUND THEN
            RAISE EXCEPTION 'upload reservation owner does not exist' USING ERRCODE='23503';
        END IF;
        SELECT pg_catalog.count(*)::pg_catalog.int8,
               COALESCE(pg_catalog.sum(size),0)::pg_catalog.int8
          INTO current_files,current_bytes
          FROM upload_slots WHERE user_id=requested_user_id;
        IF current_files>=requested_user_file_limit
           OR current_bytes::pg_catalog.numeric+requested_size::pg_catalog.numeric>
              requested_user_byte_limit::pg_catalog.numeric THEN
            RAISE EXCEPTION 'northstar_upload_reserve_slot_not_admitted'
                USING ERRCODE='P0001';
        END IF;
        admission_job_ceiling := expected_pending_limit*3/4;
        IF ledger_row.retained_files::pg_catalog.numeric
             +ledger_row.recovery_retained_files::pg_catalog.numeric+1>
             expected_retained_file_limit::pg_catalog.numeric
           OR ledger_row.retained_bytes::pg_catalog.numeric
             +ledger_row.recovery_retained_bytes::pg_catalog.numeric
             +requested_size::pg_catalog.numeric>
             expected_retained_byte_limit::pg_catalog.numeric
           OR ledger_row.pending_jobs::pg_catalog.numeric
             +ledger_row.cleanup_obligation_debt::pg_catalog.numeric>=
             admission_job_ceiling::pg_catalog.numeric THEN
            RAISE EXCEPTION 'northstar_upload_reserve_slot_not_admitted'
                USING ERRCODE='P0001';
        END IF;
        INSERT INTO upload_slots(
            id,user_id,filename,content_type,size,token_hash,expires_at,
            put_expires_at,storage_backend
        ) VALUES(
            requested_id,requested_user_id,requested_filename,requested_content_type,
            requested_size,requested_token_hash,
            pg_catalog.clock_timestamp()+INTERVAL '15 minutes',
            pg_catalog.clock_timestamp()+INTERVAL '15 minutes',requested_backend
        );
        RETURN TRUE;
    EXCEPTION
        WHEN lock_not_available THEN
            RETURN FALSE;
        WHEN SQLSTATE 'P0001' THEN
            GET STACKED DIAGNOSTICS caught_message = MESSAGE_TEXT;
            IF caught_message <> 'northstar_upload_reserve_slot_not_admitted' THEN
                RAISE;
            END IF;
            RETURN FALSE;
    END;
END;
$northstar_upload_reserve_slot$;

CREATE OR REPLACE FUNCTION northstar_upload_claim_slot(
    requested_id pg_catalog.uuid,requested_token_hash pg_catalog.bytea,
    requested_lease_seconds pg_catalog.int8,requested_max_attempts pg_catalog.int8,
    requested_max_replays pg_catalog.int8
) RETURNS TABLE(
    outcome pg_catalog.text,id pg_catalog.uuid,content_type pg_catalog.text,
    size pg_catalog.int8,object_remaining_seconds pg_catalog.int8,
    storage_backend pg_catalog.text,storage_object_key pg_catalog.text,
    storage_object_version pg_catalog.text,content_sha256 pg_catalog.bytea,
    claim_token pg_catalog.uuid,storage_fence pg_catalog.int8,
    retry_after_seconds pg_catalog.int8
)
LANGUAGE plpgsql
SECURITY DEFINER
AS $northstar_upload_claim_slot$
DECLARE slot_row pg_catalog.record;
DECLARE existing_job pg_catalog.record;
DECLARE ledger_row pg_catalog.record;
DECLARE inserted_rows pg_catalog.int8;
DECLARE new_claim pg_catalog.uuid;
DECLARE new_object_key pg_catalog.text;
DECLARE new_stage_key pg_catalog.text;
DECLARE claimed_row pg_catalog.record;
DECLARE caught_message pg_catalog.text;
BEGIN
    IF requested_lease_seconds<15 OR requested_lease_seconds>300
       OR requested_max_attempts<=0 OR requested_max_replays<=0 THEN
        RAISE EXCEPTION 'invalid upload claim policy' USING ERRCODE='22023';
    END IF;
    IF NOT EXISTS(
      SELECT 1 FROM upload_slots slot
       WHERE slot.id=requested_id AND slot.token_hash=requested_token_hash
         AND slot.put_expires_at>pg_catalog.clock_timestamp()
         AND (slot.uploaded OR slot.expires_at>pg_catalog.clock_timestamp())
    ) THEN
      RETURN QUERY SELECT 'rejected'::pg_catalog.text,NULL::pg_catalog.uuid,
        NULL::pg_catalog.text,NULL::pg_catalog.int8,NULL::pg_catalog.int8,
        NULL::pg_catalog.text,NULL::pg_catalog.text,NULL::pg_catalog.text,
        NULL::pg_catalog.bytea,NULL::pg_catalog.uuid,NULL::pg_catalog.int8,
        NULL::pg_catalog.int8;
      RETURN;
    END IF;
    -- Keep the ledger and target-slot acquisition in one exception-backed
    -- subtransaction.  A typed result below intentionally aborts that
    -- savepoint, releasing the ledger before an outer caller transaction can
    -- continue.  The sole acquired path returns normally and therefore keeps
    -- both locks with its durable state transition.
    BEGIN
      SELECT * INTO ledger_row FROM upload_storage_capacity_ledger
       WHERE singleton FOR UPDATE NOWAIT;
      IF NOT FOUND THEN
          RAISE EXCEPTION 'upload storage capacity authority is missing'
              USING ERRCODE='55000';
      END IF;
      SELECT slot.*,
             GREATEST(0,pg_catalog.ceil(EXTRACT(EPOCH FROM
               slot.expires_at-pg_catalog.clock_timestamp())))::pg_catalog.int8
               AS remaining_seconds,
             GREATEST(0,pg_catalog.ceil(EXTRACT(EPOCH FROM
               slot.claim_expires_at-pg_catalog.clock_timestamp())))::pg_catalog.int8
               AS claim_retry_seconds
        INTO slot_row FROM upload_slots slot
       WHERE slot.id=requested_id AND slot.token_hash=requested_token_hash
         AND slot.put_expires_at>pg_catalog.clock_timestamp()
         AND (slot.uploaded OR slot.expires_at>pg_catalog.clock_timestamp())
       FOR UPDATE NOWAIT;
      IF NOT FOUND THEN
        outcome:='rejected';
        id:=NULL; content_type:=NULL; size:=NULL; object_remaining_seconds:=NULL;
        storage_backend:=NULL; storage_object_key:=NULL; storage_object_version:=NULL;
        content_sha256:=NULL; claim_token:=NULL; storage_fence:=NULL;
        retry_after_seconds:=NULL;
        RAISE EXCEPTION 'northstar_upload_claim_slot_not_admitted'
          USING ERRCODE='P0001';
      END IF;
      IF slot_row.uploaded THEN
        IF slot_row.replay_count>=requested_max_replays
           OR slot_row.content_sha256 IS NULL
           OR pg_catalog.octet_length(slot_row.content_sha256)<>32 THEN
          outcome:='rejected';
          id:=NULL; content_type:=NULL; size:=NULL; object_remaining_seconds:=NULL;
          storage_backend:=NULL; storage_object_key:=NULL; storage_object_version:=NULL;
          content_sha256:=NULL; claim_token:=NULL; storage_fence:=NULL;
          retry_after_seconds:=NULL;
        ELSE
          outcome:='replay';
          id:=slot_row.id; content_type:=slot_row.content_type::pg_catalog.text;
          size:=slot_row.size; object_remaining_seconds:=slot_row.remaining_seconds;
          storage_backend:=slot_row.storage_backend;
          storage_object_key:=slot_row.storage_object_key;
          storage_object_version:=slot_row.storage_object_version;
          content_sha256:=slot_row.content_sha256; claim_token:=NULL;
          storage_fence:=slot_row.storage_fence; retry_after_seconds:=NULL;
        END IF;
        RAISE EXCEPTION 'northstar_upload_claim_slot_not_admitted'
          USING ERRCODE='P0001';
      END IF;
      IF slot_row.upload_attempts>=requested_max_attempts THEN
        outcome:='rejected';
        id:=NULL; content_type:=NULL; size:=NULL; object_remaining_seconds:=NULL;
        storage_backend:=NULL; storage_object_key:=NULL; storage_object_version:=NULL;
        content_sha256:=NULL; claim_token:=NULL; storage_fence:=NULL;
        retry_after_seconds:=NULL;
        RAISE EXCEPTION 'northstar_upload_claim_slot_not_admitted'
          USING ERRCODE='P0001';
      END IF;
      IF slot_row.storage_state IN ('staged','promoting') THEN
        outcome:='in_progress';
        id:=NULL; content_type:=NULL; size:=NULL; object_remaining_seconds:=NULL;
        storage_backend:=NULL; storage_object_key:=NULL; storage_object_version:=NULL;
        content_sha256:=NULL; claim_token:=NULL; storage_fence:=NULL;
        retry_after_seconds:=1;
        RAISE EXCEPTION 'northstar_upload_claim_slot_not_admitted'
          USING ERRCODE='P0001';
      END IF;
      IF slot_row.uploading AND slot_row.claim_expires_at>pg_catalog.clock_timestamp() THEN
        outcome:='in_progress';
        id:=NULL; content_type:=NULL; size:=NULL; object_remaining_seconds:=NULL;
        storage_backend:=NULL; storage_object_key:=NULL; storage_object_version:=NULL;
        content_sha256:=NULL; claim_token:=NULL; storage_fence:=NULL;
        retry_after_seconds:=GREATEST(1,slot_row.claim_retry_seconds)::pg_catalog.int8;
        RAISE EXCEPTION 'northstar_upload_claim_slot_not_admitted'
          USING ERRCODE='P0001';
      END IF;
      IF slot_row.storage_attempt IS NOT NULL AND slot_row.storage_stage_key IS NOT NULL THEN
        SELECT
          EXISTS(SELECT 1 FROM upload_storage_jobs job
            WHERE job.object_id=requested_id
              AND job.storage_attempt=slot_row.storage_attempt
              AND job.action='delete_stage') AS conflict_exists,
          EXISTS(SELECT 1 FROM upload_storage_jobs job
            WHERE job.object_id=requested_id
              AND job.storage_attempt=slot_row.storage_attempt
              AND job.action='delete_stage'
              AND job.storage_backend=slot_row.storage_backend
              AND job.stage_key=slot_row.storage_stage_key
              AND job.stage_version IS NOT DISTINCT FROM slot_row.storage_stage_version
              AND job.object_key IS NULL AND job.object_version IS NULL
              AND job.storage_fence=slot_row.storage_fence
              AND job.expected_size=slot_row.size AND job.expected_sha256 IS NULL)
            AS exact_exists
          INTO existing_job;
        IF existing_job.conflict_exists AND NOT existing_job.exact_exists THEN
          RAISE EXCEPTION 'conflicting upload attempt cleanup projection has different identity'
            USING ERRCODE='55000';
        END IF;
        IF existing_job.exact_exists AND slot_row.storage_cleanup_debt_reserved THEN
          RAISE EXCEPTION 'existing upload cleanup did not convert reserved debt'
            USING ERRCODE='55000';
        END IF;
        INSERT INTO upload_storage_jobs(
          object_id,storage_attempt,action,storage_backend,stage_key,
          stage_version,storage_fence,expected_size
        ) VALUES(
          requested_id,slot_row.storage_attempt,'delete_stage',slot_row.storage_backend,
          slot_row.storage_stage_key,slot_row.storage_stage_version,
          slot_row.storage_fence,slot_row.size
        ) ON CONFLICT(object_id,storage_attempt,action) DO NOTHING;
        GET DIAGNOSTICS inserted_rows=ROW_COUNT;
        IF inserted_rows=0 AND NOT existing_job.exact_exists THEN
          RAISE EXCEPTION 'conflicting upload attempt cleanup projection has different identity'
            USING ERRCODE='55000';
        END IF;
        SELECT * INTO ledger_row FROM upload_storage_capacity_ledger
         WHERE singleton;
        IF ledger_row.configured_pending_limit IS NULL
           OR ledger_row.configured_retained_files_limit IS NULL
           OR ledger_row.configured_retained_bytes_limit IS NULL THEN
          RAISE EXCEPTION 'upload capacity policy is not bound' USING ERRCODE='55000';
        END IF;
        IF ledger_row.retained_files::pg_catalog.numeric
             +ledger_row.recovery_retained_files::pg_catalog.numeric>
             ledger_row.configured_retained_files_limit::pg_catalog.numeric
           OR ledger_row.retained_bytes::pg_catalog.numeric
             +ledger_row.recovery_retained_bytes::pg_catalog.numeric>
             ledger_row.configured_retained_bytes_limit::pg_catalog.numeric
           OR ledger_row.pending_jobs::pg_catalog.numeric
             +ledger_row.cleanup_obligation_debt::pg_catalog.numeric>=
             LEAST(ledger_row.configured_pending_limit,
                   ledger_row.absolute_disaster_limit)::pg_catalog.numeric THEN
          outcome:='in_progress';
          id:=NULL; content_type:=NULL; size:=NULL; object_remaining_seconds:=NULL;
          storage_backend:=NULL; storage_object_key:=NULL; storage_object_version:=NULL;
          content_sha256:=NULL; claim_token:=NULL; storage_fence:=NULL;
          retry_after_seconds:=5;
          RAISE EXCEPTION 'northstar_upload_claim_slot_not_admitted'
            USING ERRCODE='P0001';
        END IF;
      END IF;
      new_claim := gen_random_uuid();
      IF slot_row.storage_backend='local' THEN
        new_object_key := requested_id::pg_catalog.text;
        new_stage_key := pg_catalog.format('staging/%s/%s',requested_id,new_claim);
      ELSIF slot_row.storage_backend='s3' THEN
        new_object_key := pg_catalog.format('objects/%s/%s',requested_id,new_claim);
        new_stage_key := new_object_key;
      ELSE
        RAISE EXCEPTION 'invalid upload backend' USING ERRCODE='55000';
      END IF;
      UPDATE upload_slots slot
         SET uploading=TRUE,claim_token=new_claim,
             claim_expires_at=LEAST(slot.put_expires_at,
               pg_catalog.clock_timestamp()
               +(requested_lease_seconds*INTERVAL '1 second')),
             upload_attempts=slot.upload_attempts+1,storage_state='writing',
             storage_attempt=new_claim,storage_stage_key=new_stage_key,
             storage_stage_version=NULL,storage_object_key=new_object_key,
             storage_object_version=NULL,storage_sha256=NULL,storage_size=NULL,
             storage_fence=slot.storage_fence+1,
             storage_updated_at=pg_catalog.clock_timestamp()
       WHERE slot.id=requested_id AND NOT slot.uploaded
         AND slot.upload_attempts<requested_max_attempts
         AND slot.put_expires_at>pg_catalog.clock_timestamp()
         AND slot.expires_at>pg_catalog.clock_timestamp()
       RETURNING slot.storage_fence,
         GREATEST(0,pg_catalog.ceil(EXTRACT(EPOCH FROM
           slot.put_expires_at-pg_catalog.clock_timestamp())))::pg_catalog.int8
           AS remaining_seconds
         INTO claimed_row;
      IF NOT FOUND THEN
        outcome:='rejected';
        id:=NULL; content_type:=NULL; size:=NULL; object_remaining_seconds:=NULL;
        storage_backend:=NULL; storage_object_key:=NULL; storage_object_version:=NULL;
        content_sha256:=NULL; claim_token:=NULL; storage_fence:=NULL;
        retry_after_seconds:=NULL;
        RAISE EXCEPTION 'northstar_upload_claim_slot_not_admitted'
          USING ERRCODE='P0001';
      END IF;
      RETURN QUERY SELECT 'acquired'::pg_catalog.text,slot_row.id,
        slot_row.content_type::pg_catalog.text,slot_row.size,slot_row.remaining_seconds,
        slot_row.storage_backend,slot_row.storage_object_key,
        slot_row.storage_object_version,NULL::pg_catalog.bytea,new_claim,
        claimed_row.storage_fence,claimed_row.remaining_seconds;
    EXCEPTION
      WHEN lock_not_available THEN
        RETURN QUERY SELECT 'in_progress'::pg_catalog.text,NULL::pg_catalog.uuid,
          NULL::pg_catalog.text,NULL::pg_catalog.int8,NULL::pg_catalog.int8,
          NULL::pg_catalog.text,NULL::pg_catalog.text,NULL::pg_catalog.text,
          NULL::pg_catalog.bytea,NULL::pg_catalog.uuid,NULL::pg_catalog.int8,
          1::pg_catalog.int8;
        RETURN;
      WHEN SQLSTATE 'P0001' THEN
        GET STACKED DIAGNOSTICS caught_message = MESSAGE_TEXT;
        IF caught_message <> 'northstar_upload_claim_slot_not_admitted' THEN
          RAISE;
        END IF;
        RETURN NEXT;
        RETURN;
    END;
END;
$northstar_upload_claim_slot$;

DO $northstar_upload_capacity_nowait_security$
DECLARE
    migration_schema pg_catalog.text := pg_catalog.current_schema();
    routine_signature pg_catalog.text;
    routine_oid pg_catalog.oid;
    role_name pg_catalog.text;
BEGIN
    FOREACH routine_signature IN ARRAY ARRAY[
        'northstar_upload_require_capacity_lock()',
        'guard_upload_capacity_nowait()',
        'reserve_upload_cleanup_debt()',
        'northstar_upload_bind_capacity_policy(int8,int8,int8)',
        'northstar_upload_capacity_lock()',
        'northstar_upload_complete_cleanup(uuid,uuid)',
        'northstar_upload_complete_storage_job(int8,uuid)',
        'northstar_upload_retire_promotion_for_cleanup(uuid,uuid,int8,uuid)',
        'northstar_upload_record_stage(uuid,uuid,text,text,text,text,bytea,int8,int8)',
        'northstar_upload_release_claim(uuid,uuid)',
        'northstar_upload_complete_promotion(uuid,uuid,uuid,text,text,text,bytea,int8,int8,int8)',
        'northstar_upload_reserve_slot(uuid,uuid,text,text,int8,bytea,int8,int8,text,int8,int8,int8)',
        'northstar_upload_claim_slot(uuid,bytea,int8,int8,int8)',
        'northstar_upload_admit_expired_cleanup()',
        'northstar_upload_delete_owned(uuid,int8,bytea,uuid,uuid)',
        'northstar_upload_capability_catalog_healthy(text)'
    ] LOOP
        routine_oid:=pg_catalog.to_regprocedure(
            pg_catalog.format('%I.%s',migration_schema,routine_signature)
        );
        IF routine_oid IS NULL THEN
            RAISE EXCEPTION 'upload capacity routine % is absent',routine_signature
                USING ERRCODE='42883';
        END IF;
        EXECUTE pg_catalog.format(
            'ALTER FUNCTION %I.%s SECURITY DEFINER SET search_path TO pg_catalog, %I, pg_temp',
            migration_schema,routine_signature,migration_schema
        );
        EXECUTE pg_catalog.format(
            'REVOKE ALL ON FUNCTION %I.%s FROM PUBLIC',
            migration_schema,routine_signature
        );
        IF NOT EXISTS(
            SELECT 1 FROM pg_catalog.pg_proc routine
             WHERE routine.oid=routine_oid
               AND routine.prosecdef
               AND routine.proowner=(
                    SELECT relation.relowner FROM pg_catalog.pg_class relation
                     WHERE relation.oid=pg_catalog.to_regclass(
                         pg_catalog.format('%I.upload_storage_capacity_ledger',migration_schema)
                     )
               )
               AND pg_catalog.array_to_string(routine.proconfig,', ') IS NOT DISTINCT FROM
                   'search_path=pg_catalog, ' || pg_catalog.quote_ident(migration_schema) ||
                   ', pg_temp'
        ) THEN
            RAISE EXCEPTION 'upload capacity routine % has unsafe owner/security/search_path',
                routine_signature USING ERRCODE='55000';
        END IF;
    END LOOP;

    -- The manifest/reconciliation layer grants runtime capabilities.  These
    -- two helper identities must remain owner-only even on installations
    -- where the standard Northstar roles already exist during migration.
    FOREACH role_name IN ARRAY ARRAY[
        'northstar_runtime','northstar_commands','northstar_backup'
    ] LOOP
        IF EXISTS(SELECT 1 FROM pg_catalog.pg_roles WHERE rolname=role_name) THEN
            EXECUTE pg_catalog.format(
                'REVOKE ALL ON FUNCTION %I.northstar_upload_require_capacity_lock() FROM %I',
                migration_schema,role_name
            );
            EXECUTE pg_catalog.format(
                'REVOKE ALL ON FUNCTION %I.guard_upload_capacity_nowait() FROM %I',
                migration_schema,role_name
            );
        END IF;
    END LOOP;
END;
$northstar_upload_capacity_nowait_security$;
