-- Upload object authority capabilities and fail-closed capacity admission.
--
-- The long-lived runtime role must not mutate the namespace singleton,
-- capacity ledger, or recovery queues directly.  Every elevated routine in
-- this migration has a fixed installation-schema search path, no dynamic SQL,
-- an owner-held SECURITY DEFINER boundary and no PUBLIC execution grant.

DO $northstar_upload_capability_precondition$
DECLARE
    migration_schema pg_catalog.text := pg_catalog.current_schema();
    relation_name pg_catalog.text;
BEGIN
    IF migration_schema IS NULL
       OR migration_schema IN ('pg_catalog','information_schema')
       OR migration_schema LIKE 'pg_temp_%'
       OR migration_schema LIKE 'pg_toast_temp_%' THEN
        RAISE EXCEPTION 'migration 0113 requires a dedicated application schema first in search_path'
            USING ERRCODE='3F000';
    END IF;
    FOREACH relation_name IN ARRAY ARRAY[
        'upload_slots','upload_storage_authority',
        'upload_storage_capacity_ledger','upload_storage_jobs',
        'upload_cleanup_queue'
    ] LOOP
        IF pg_catalog.to_regclass(
            pg_catalog.format('%I.%I',migration_schema,relation_name)
        ) IS NULL THEN
            RAISE EXCEPTION 'upload authority relation %.% is absent',
                migration_schema,relation_name USING ERRCODE='42P01';
        END IF;
    END LOOP;
END;
$northstar_upload_capability_precondition$;

-- The 0091 rolling-upgrade function checked only the pending-job policy.
-- A transition from reserved to writing owns a future cleanup obligation and
-- is therefore forbidden until all three capacity authorities are bound.
CREATE OR REPLACE FUNCTION reserve_upload_cleanup_debt()
RETURNS pg_catalog.trigger
LANGUAGE plpgsql
AS $northstar_reserve_upload_cleanup_debt$
DECLARE
    policy_is_bound pg_catalog.bool;
BEGIN
    IF NOT OLD.storage_cleanup_debt_reserved
       AND (NEW.storage_object_key IS NOT NULL OR NEW.storage_stage_key IS NOT NULL)
       AND NOT EXISTS(
           SELECT 1 FROM upload_cleanup_queue WHERE object_id=NEW.id
       ) THEN
        SELECT configured_pending_limit IS NOT NULL
               AND configured_retained_files_limit IS NOT NULL
               AND configured_retained_bytes_limit IS NOT NULL
          INTO policy_is_bound
          FROM upload_storage_capacity_ledger
         WHERE singleton
         FOR UPDATE;
        IF NOT FOUND OR NOT COALESCE(policy_is_bound,FALSE) THEN
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

CREATE FUNCTION northstar_upload_bootstrap_authority(
    requested_backend pg_catalog.text,
    requested_namespace_sha256 pg_catalog.bytea
) RETURNS TABLE(namespace_generation pg_catalog.int8)
LANGUAGE plpgsql
SECURITY DEFINER
AS $northstar_upload_bootstrap_authority$
DECLARE
    mismatched_locators pg_catalog.int8;
    physical_locators pg_catalog.int8;
    durable_backend pg_catalog.text;
    durable_namespace pg_catalog.bytea;
    durable_generation pg_catalog.int8;
BEGIN
    IF requested_backend NOT IN ('local','s3')
       OR pg_catalog.octet_length(requested_namespace_sha256)<>32 THEN
        RAISE EXCEPTION 'invalid upload namespace authority'
            USING ERRCODE='22023';
    END IF;
    SELECT pg_catalog.count(*) INTO mismatched_locators FROM (
        SELECT 1 FROM upload_slots
         WHERE storage_backend<>requested_backend
           AND (expires_at>pg_catalog.clock_timestamp()
                OR storage_object_key IS NOT NULL
                OR storage_stage_key IS NOT NULL
                OR storage_state='deleting')
        UNION ALL
        SELECT 1 FROM upload_cleanup_queue
         WHERE storage_backend<>requested_backend
        UNION ALL
        SELECT 1 FROM upload_storage_jobs
         WHERE storage_backend<>requested_backend
    ) mismatches;
    IF mismatched_locators<>0 THEN
        RAISE EXCEPTION 'upload locators belong to a different storage backend'
            USING ERRCODE='55000';
    END IF;
    SELECT pg_catalog.count(*) INTO physical_locators FROM (
        SELECT 1 FROM upload_slots
         WHERE storage_object_key IS NOT NULL OR storage_stage_key IS NOT NULL
        UNION ALL SELECT 1 FROM upload_cleanup_queue
        UNION ALL SELECT 1 FROM upload_storage_jobs
    ) locators;
    IF physical_locators<>0
       AND NOT EXISTS(SELECT 1 FROM upload_storage_authority WHERE singleton) THEN
        RAISE EXCEPTION 'existing upload locators have no namespace authority; use the offline namespace bootstrap procedure'
            USING ERRCODE='55000';
    END IF;
    INSERT INTO upload_storage_authority(
        singleton,storage_backend,namespace_sha256
    ) VALUES(TRUE,requested_backend,requested_namespace_sha256)
    ON CONFLICT(singleton) DO NOTHING;
    SELECT storage_backend,namespace_sha256,generation
      INTO durable_backend,durable_namespace,durable_generation
      FROM upload_storage_authority
     WHERE singleton
     FOR UPDATE;
    IF NOT FOUND
       OR durable_backend<>requested_backend
       OR durable_namespace<>requested_namespace_sha256 THEN
        RAISE EXCEPTION 'upload namespace differs from immutable database authority'
            USING ERRCODE='55000';
    END IF;
    RETURN QUERY SELECT durable_generation;
END;
$northstar_upload_bootstrap_authority$;

-- Migrator/operator-only recovery for an upgrade that already contains
-- physical locators but predates the namespace singleton.  This routine is
-- intentionally omitted from the runtime capability grant manifest.
CREATE FUNCTION northstar_upload_offline_bootstrap_authority(
    requested_backend pg_catalog.text,
    requested_namespace_sha256 pg_catalog.bytea,
    operator_confirmation pg_catalog.text
) RETURNS pg_catalog.int8
LANGUAGE plpgsql
SECURITY DEFINER
AS $northstar_upload_offline_bootstrap_authority$
DECLARE
    locator_mismatches pg_catalog.int8;
    new_generation pg_catalog.int8;
BEGIN
    IF operator_confirmation<>'ALL_NORTHSTAR_NODES_STOPPED_AND_EXISTING_UPLOAD_NAMESPACE_VERIFIED' THEN
        RAISE EXCEPTION 'explicit offline namespace bootstrap confirmation is required'
            USING ERRCODE='42501';
    END IF;
    IF requested_backend NOT IN ('local','s3')
       OR pg_catalog.octet_length(requested_namespace_sha256)<>32 THEN
        RAISE EXCEPTION 'invalid upload namespace authority'
            USING ERRCODE='22023';
    END IF;
    IF EXISTS(SELECT 1 FROM upload_storage_authority WHERE singleton) THEN
        RAISE EXCEPTION 'upload namespace authority already exists'
            USING ERRCODE='55000';
    END IF;
    SELECT pg_catalog.count(*) INTO locator_mismatches FROM (
        SELECT storage_backend FROM upload_slots
         WHERE storage_object_key IS NOT NULL OR storage_stage_key IS NOT NULL
        UNION ALL SELECT storage_backend FROM upload_cleanup_queue
        UNION ALL SELECT storage_backend FROM upload_storage_jobs
    ) locators WHERE storage_backend<>requested_backend;
    IF locator_mismatches<>0 THEN
        RAISE EXCEPTION 'existing upload locators do not share the verified backend'
            USING ERRCODE='55000';
    END IF;
    INSERT INTO upload_storage_authority(
        singleton,storage_backend,namespace_sha256
    ) VALUES(TRUE,requested_backend,requested_namespace_sha256)
    RETURNING generation INTO new_generation;
    RETURN new_generation;
END;
$northstar_upload_offline_bootstrap_authority$;

CREATE FUNCTION northstar_upload_bind_capacity_policy(
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
    -- Deployment limits are immutable once bound. A policy change requires a
    -- reviewed migration which advances policy_generation and proves the
    -- existing retained/recovery facts against the replacement envelope.
    IF requested_pending_limit NOT BETWEEN 128 AND 100000
       OR requested_retained_files_limit NOT BETWEEN 1000 AND 100000000
       OR requested_retained_bytes_limit NOT BETWEEN 1 AND 1125899906842624 THEN
        RAISE EXCEPTION 'invalid upload storage capacity policy'
            USING ERRCODE='22023';
    END IF;
    SELECT configured_pending_limit,configured_retained_files_limit,
           configured_retained_bytes_limit
      INTO current_pending_limit,current_retained_files_limit,
           current_retained_bytes_limit
      FROM upload_storage_capacity_ledger
     WHERE singleton
     FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'upload storage capacity authority is missing'
            USING ERRCODE='55000';
    END IF;
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

-- Acquires the singleton row lock in the caller's transaction.  Callers set a
-- bounded LOCAL lock_timeout first; no table identity or ledger value leaks.
CREATE FUNCTION northstar_upload_capacity_lock()
RETURNS pg_catalog.bool
LANGUAGE sql
SECURITY DEFINER
AS $northstar_upload_capacity_lock$
    SELECT singleton
      FROM upload_storage_capacity_ledger
     WHERE singleton
     FOR UPDATE
$northstar_upload_capacity_lock$;

CREATE FUNCTION northstar_upload_active_slot_count(requested_user_id pg_catalog.uuid)
RETURNS pg_catalog.int8
LANGUAGE sql
SECURITY DEFINER
AS $northstar_upload_active_slot_count$
    SELECT pg_catalog.count(*)
      FROM upload_slots
     WHERE user_id=requested_user_id
       AND expires_at>pg_catalog.clock_timestamp()
$northstar_upload_active_slot_count$;

CREATE FUNCTION northstar_upload_public_slot_count()
RETURNS pg_catalog.int8
LANGUAGE sql
SECURITY DEFINER
AS $northstar_upload_public_slot_count$
    SELECT pg_catalog.count(*)
      FROM upload_slots
     WHERE uploaded AND expires_at>pg_catalog.clock_timestamp()
$northstar_upload_public_slot_count$;

-- Renewal deliberately does not acquire the global ledger.  It changes no
-- retained-capacity projection.  NOWAIT distinguishes transient row
-- contention from a lost/expired fencing token without occupying a pool
-- connection behind an unbounded lock wait.
CREATE FUNCTION northstar_upload_renew_claim(
    requested_id pg_catalog.uuid,
    requested_claim_token pg_catalog.uuid,
    requested_lease_seconds pg_catalog.int8
) RETURNS pg_catalog.text
LANGUAGE plpgsql
SECURITY DEFINER
AS $northstar_upload_renew_claim$
BEGIN
    IF requested_lease_seconds NOT BETWEEN 15 AND 300 THEN
        RAISE EXCEPTION 'invalid upload lease' USING ERRCODE='22023';
    END IF;
    BEGIN
        PERFORM 1 FROM upload_slots
         WHERE id=requested_id
         FOR UPDATE NOWAIT;
    EXCEPTION WHEN lock_not_available THEN
        RETURN 'busy';
    END;
    UPDATE upload_slots
       SET claim_expires_at=LEAST(
               put_expires_at,
               pg_catalog.clock_timestamp()
                 +(requested_lease_seconds*INTERVAL '1 second'))
     WHERE id=requested_id
       AND claim_token=requested_claim_token
       AND storage_attempt=requested_claim_token
       AND uploading AND NOT uploaded
       AND storage_state='writing'
       AND storage_cleanup_debt_reserved
       AND claim_expires_at>pg_catalog.clock_timestamp()
       AND put_expires_at>pg_catalog.clock_timestamp()
       AND expires_at>pg_catalog.clock_timestamp();
    IF FOUND THEN
        RETURN 'renewed';
    END IF;
    RETURN 'lost';
END;
$northstar_upload_renew_claim$;

CREATE FUNCTION northstar_upload_authority_probe(
    requested_backend pg_catalog.text,
    requested_namespace_sha256 pg_catalog.bytea,
    requested_namespace_generation pg_catalog.int8,
    requested_policy_generation pg_catalog.int8,
    requested_pending_limit pg_catalog.int8,
    requested_retained_files_limit pg_catalog.int8,
    requested_retained_bytes_limit pg_catalog.int8
) RETURNS TABLE(
    namespace_matches pg_catalog.bool,
    capacity_matches pg_catalog.bool,
    recovery_draining pg_catalog.bool
)
LANGUAGE sql
STABLE
SECURITY DEFINER
AS $northstar_upload_authority_probe$
    SELECT
      EXISTS(
        SELECT 1 FROM upload_storage_authority
         WHERE singleton
           AND storage_backend=requested_backend
           AND namespace_sha256=requested_namespace_sha256
           AND generation=requested_namespace_generation
      ),
      EXISTS(
        SELECT 1 FROM upload_storage_capacity_ledger
         WHERE singleton
           AND policy_generation=requested_policy_generation
           AND configured_pending_limit=requested_pending_limit
           AND configured_retained_files_limit=requested_retained_files_limit
           AND configured_retained_bytes_limit=requested_retained_bytes_limit
      ),
      COALESCE((
        SELECT legacy_overcommit_draining OR recovery_overcommit_draining
          FROM upload_storage_capacity_ledger WHERE singleton
      ),TRUE)
$northstar_upload_authority_probe$;

CREATE FUNCTION northstar_upload_dead_letters_page(
    requested_kind pg_catalog.text,
    after_storage_job_id pg_catalog.int8,
    after_cleanup_recovery_id pg_catalog.uuid,
    requested_limit pg_catalog.int4
) RETURNS TABLE(
    storage_job_id pg_catalog.int8,
    cleanup_recovery_id pg_catalog.uuid,
    operation pg_catalog.text,
    attempts pg_catalog.int8,
    dead_lettered_at pg_catalog.timestamptz,
    available_at pg_catalog.timestamptz,
    created_at pg_catalog.timestamptz,
    error_class pg_catalog.text
)
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
AS $northstar_upload_dead_letters_page$
BEGIN
    IF requested_limit NOT BETWEEN 1 AND 101 THEN
        RAISE EXCEPTION 'invalid upload dead-letter page limit'
            USING ERRCODE='22023';
    END IF;
    IF requested_kind='storage_job' THEN
        IF after_cleanup_recovery_id IS NOT NULL THEN
            RAISE EXCEPTION 'cleanup cursor used for storage-job dead letters'
                USING ERRCODE='22023';
        END IF;
        IF after_storage_job_id IS NULL THEN
            RETURN QUERY
            SELECT job.id,NULL::pg_catalog.uuid,job.action,job.attempts,
                   job.dead_lettered_at,job.available_at,job.created_at,
                   CASE
                     WHEN job.last_error IS NULL THEN NULL
                     WHEN pg_catalog.lower(job.last_error) LIKE '%timeout%'
                       OR pg_catalog.lower(job.last_error) LIKE '%timed out%'
                       THEN 'storage operation timed out'
                     WHEN pg_catalog.lower(job.last_error) LIKE '%permission denied%'
                       OR pg_catalog.lower(job.last_error) LIKE '%access denied%'
                       OR pg_catalog.lower(job.last_error) LIKE '%unauthorized%'
                       OR pg_catalog.lower(job.last_error) LIKE '%forbidden%'
                       THEN 'storage backend denied the operation'
                     WHEN pg_catalog.lower(job.last_error) LIKE '%checksum%'
                       OR pg_catalog.lower(job.last_error) LIKE '%digest%'
                       OR pg_catalog.lower(job.last_error) LIKE '%integrity%'
                       OR pg_catalog.lower(job.last_error) LIKE '%size mismatch%'
                       THEN 'storage integrity verification failed'
                     WHEN pg_catalog.lower(job.last_error) LIKE '%not found%'
                       OR pg_catalog.lower(job.last_error) LIKE '%absent%'
                       THEN 'storage object was not found'
                     WHEN pg_catalog.lower(job.last_error) LIKE '%connect%'
                       OR pg_catalog.lower(job.last_error) LIKE '%network%'
                       OR pg_catalog.lower(job.last_error) LIKE '%dns%'
                       THEN 'storage backend is unreachable'
                     ELSE 'storage reconciliation failed'
                   END
              FROM upload_storage_jobs job
             WHERE job.dead_lettered_at IS NOT NULL
             ORDER BY job.id DESC
             LIMIT requested_limit;
            RETURN;
        END IF;
        RETURN QUERY
        SELECT job.id,NULL::pg_catalog.uuid,job.action,job.attempts,
               job.dead_lettered_at,job.available_at,job.created_at,
               CASE
                 WHEN job.last_error IS NULL THEN NULL
                 WHEN pg_catalog.lower(job.last_error) LIKE '%timeout%'
                   OR pg_catalog.lower(job.last_error) LIKE '%timed out%'
                   THEN 'storage operation timed out'
                 WHEN pg_catalog.lower(job.last_error) LIKE '%permission denied%'
                   OR pg_catalog.lower(job.last_error) LIKE '%access denied%'
                   OR pg_catalog.lower(job.last_error) LIKE '%unauthorized%'
                   OR pg_catalog.lower(job.last_error) LIKE '%forbidden%'
                   THEN 'storage backend denied the operation'
                 WHEN pg_catalog.lower(job.last_error) LIKE '%checksum%'
                   OR pg_catalog.lower(job.last_error) LIKE '%digest%'
                   OR pg_catalog.lower(job.last_error) LIKE '%integrity%'
                   OR pg_catalog.lower(job.last_error) LIKE '%size mismatch%'
                   THEN 'storage integrity verification failed'
                 WHEN pg_catalog.lower(job.last_error) LIKE '%not found%'
                   OR pg_catalog.lower(job.last_error) LIKE '%absent%'
                   THEN 'storage object was not found'
                 WHEN pg_catalog.lower(job.last_error) LIKE '%connect%'
                   OR pg_catalog.lower(job.last_error) LIKE '%network%'
                   OR pg_catalog.lower(job.last_error) LIKE '%dns%'
                   THEN 'storage backend is unreachable'
                 ELSE 'storage reconciliation failed'
               END
          FROM upload_storage_jobs job
         WHERE job.dead_lettered_at IS NOT NULL
           AND job.id<after_storage_job_id
         ORDER BY job.id DESC
         LIMIT requested_limit;
        RETURN;
    END IF;
    IF requested_kind='cleanup' THEN
        IF after_storage_job_id IS NOT NULL THEN
            RAISE EXCEPTION 'storage-job cursor used for cleanup dead letters'
                USING ERRCODE='22023';
        END IF;
        IF after_cleanup_recovery_id IS NULL THEN
            RETURN QUERY
            SELECT NULL::pg_catalog.int8,queue.recovery_id,'cleanup'::pg_catalog.text,
                   queue.attempts,queue.dead_lettered_at,queue.available_at,
                   queue.queued_at,
                   CASE
                     WHEN queue.last_error IS NULL THEN NULL
                     WHEN pg_catalog.lower(queue.last_error) LIKE '%timeout%'
                       OR pg_catalog.lower(queue.last_error) LIKE '%timed out%'
                       THEN 'storage operation timed out'
                     WHEN pg_catalog.lower(queue.last_error) LIKE '%permission denied%'
                       OR pg_catalog.lower(queue.last_error) LIKE '%access denied%'
                       OR pg_catalog.lower(queue.last_error) LIKE '%unauthorized%'
                       OR pg_catalog.lower(queue.last_error) LIKE '%forbidden%'
                       THEN 'storage backend denied the operation'
                     WHEN pg_catalog.lower(queue.last_error) LIKE '%checksum%'
                       OR pg_catalog.lower(queue.last_error) LIKE '%digest%'
                       OR pg_catalog.lower(queue.last_error) LIKE '%integrity%'
                       OR pg_catalog.lower(queue.last_error) LIKE '%size mismatch%'
                       THEN 'storage integrity verification failed'
                     WHEN pg_catalog.lower(queue.last_error) LIKE '%not found%'
                       OR pg_catalog.lower(queue.last_error) LIKE '%absent%'
                       THEN 'storage object was not found'
                     WHEN pg_catalog.lower(queue.last_error) LIKE '%connect%'
                       OR pg_catalog.lower(queue.last_error) LIKE '%network%'
                       OR pg_catalog.lower(queue.last_error) LIKE '%dns%'
                       THEN 'storage backend is unreachable'
                     ELSE 'storage reconciliation failed'
                   END
              FROM upload_cleanup_queue queue
             WHERE queue.dead_lettered_at IS NOT NULL
             ORDER BY queue.recovery_id DESC
             LIMIT requested_limit;
            RETURN;
        END IF;
        RETURN QUERY
        SELECT NULL::pg_catalog.int8,queue.recovery_id,'cleanup'::pg_catalog.text,
               queue.attempts,queue.dead_lettered_at,queue.available_at,
               queue.queued_at,
               CASE
                 WHEN queue.last_error IS NULL THEN NULL
                 WHEN pg_catalog.lower(queue.last_error) LIKE '%timeout%'
                   OR pg_catalog.lower(queue.last_error) LIKE '%timed out%'
                   THEN 'storage operation timed out'
                 WHEN pg_catalog.lower(queue.last_error) LIKE '%permission denied%'
                   OR pg_catalog.lower(queue.last_error) LIKE '%access denied%'
                   OR pg_catalog.lower(queue.last_error) LIKE '%unauthorized%'
                   OR pg_catalog.lower(queue.last_error) LIKE '%forbidden%'
                   THEN 'storage backend denied the operation'
                 WHEN pg_catalog.lower(queue.last_error) LIKE '%checksum%'
                   OR pg_catalog.lower(queue.last_error) LIKE '%digest%'
                   OR pg_catalog.lower(queue.last_error) LIKE '%integrity%'
                   OR pg_catalog.lower(queue.last_error) LIKE '%size mismatch%'
                   THEN 'storage integrity verification failed'
                 WHEN pg_catalog.lower(queue.last_error) LIKE '%not found%'
                   OR pg_catalog.lower(queue.last_error) LIKE '%absent%'
                   THEN 'storage object was not found'
                 WHEN pg_catalog.lower(queue.last_error) LIKE '%connect%'
                   OR pg_catalog.lower(queue.last_error) LIKE '%network%'
                   OR pg_catalog.lower(queue.last_error) LIKE '%dns%'
                   THEN 'storage backend is unreachable'
                 ELSE 'storage reconciliation failed'
               END
          FROM upload_cleanup_queue queue
         WHERE queue.dead_lettered_at IS NOT NULL
           AND queue.recovery_id<after_cleanup_recovery_id
         ORDER BY queue.recovery_id DESC
         LIMIT requested_limit;
        RETURN;
    END IF;
    RAISE EXCEPTION 'invalid upload dead-letter kind' USING ERRCODE='22023';
END;
$northstar_upload_dead_letters_page$;

CREATE FUNCTION northstar_upload_retry_dead_letter(
    requested_actor_id pg_catalog.uuid,
    requested_actor_generation pg_catalog.int8,
    presented_session_hash pg_catalog.bytea,
    requested_kind pg_catalog.text,
    requested_storage_job_id pg_catalog.int8,
    requested_cleanup_recovery_id pg_catalog.uuid,
    requested_request_id pg_catalog.uuid
) RETURNS pg_catalog.text
LANGUAGE plpgsql
SECURITY DEFINER
AS $northstar_upload_retry_dead_letter$
DECLARE
    previous_attempts pg_catalog.int8;
    previous_dead_lettered_at pg_catalog.timestamptz;
    had_stored_error pg_catalog.bool;
    had_expired_claim pg_catalog.bool;
    claim_active pg_catalog.bool;
    audit_target pg_catalog.text;
BEGIN
    IF pg_catalog.octet_length(presented_session_hash)<>32
       OR requested_request_id IS NULL
       OR (requested_kind='storage_job') IS DISTINCT FROM
          (requested_storage_job_id IS NOT NULL
             AND requested_cleanup_recovery_id IS NULL)
       OR (requested_kind='cleanup') IS DISTINCT FROM
          (requested_storage_job_id IS NULL
             AND requested_cleanup_recovery_id IS NOT NULL) THEN
        RETURN 'invalid';
    END IF;
    -- Lock both sides of the bearer proof in the global users -> api_sessions
    -- order.  A concurrent logout/session revocation or auth-generation
    -- change must serialize before or after the queue mutation; a marked JOIN
    -- would leave PostgreSQL free to choose the opposite row-lock order.
    PERFORM 1 FROM users actor
     WHERE actor.id=requested_actor_id
       AND actor.auth_generation=requested_actor_generation
       AND actor.is_admin AND NOT actor.is_disabled
     FOR SHARE;
    IF NOT FOUND THEN
        RETURN 'unauthorized';
    END IF;
    PERFORM 1 FROM api_sessions session
     WHERE session.user_id=requested_actor_id
       AND session.token_hash=presented_session_hash
       AND session.expires_at>pg_catalog.clock_timestamp()
     FOR SHARE;
    IF NOT FOUND THEN
        RETURN 'unauthorized';
    END IF;
    IF requested_kind='storage_job' THEN
        SELECT job.attempts,job.dead_lettered_at,
               job.last_error IS NOT NULL,
               job.claim_token IS NOT NULL
                 AND job.claim_expires_at<=pg_catalog.clock_timestamp(),
               job.claim_token IS NOT NULL
                 AND job.claim_expires_at>pg_catalog.clock_timestamp()
          INTO previous_attempts,previous_dead_lettered_at,
               had_stored_error,had_expired_claim,claim_active
          FROM upload_storage_jobs job
         WHERE job.id=requested_storage_job_id
           AND job.dead_lettered_at IS NOT NULL
         FOR UPDATE;
        IF NOT FOUND OR claim_active THEN RETURN 'unavailable'; END IF;
        UPDATE upload_storage_jobs
           SET dead_lettered_at=NULL,claim_token=NULL,claim_expires_at=NULL,
               attempts=0,available_at=pg_catalog.clock_timestamp(),
               updated_at=pg_catalog.clock_timestamp()
         WHERE id=requested_storage_job_id
           AND dead_lettered_at=previous_dead_lettered_at
           AND (claim_token IS NULL
                OR claim_expires_at<=pg_catalog.clock_timestamp());
        audit_target:='storage_job:' || requested_storage_job_id::pg_catalog.text;
    ELSIF requested_kind='cleanup' THEN
        SELECT queue.attempts,queue.dead_lettered_at,
               queue.last_error IS NOT NULL,
               queue.claim_token IS NOT NULL
                 AND queue.claim_expires_at<=pg_catalog.clock_timestamp(),
               queue.claim_token IS NOT NULL
                 AND queue.claim_expires_at>pg_catalog.clock_timestamp()
          INTO previous_attempts,previous_dead_lettered_at,
               had_stored_error,had_expired_claim,claim_active
          FROM upload_cleanup_queue queue
         WHERE queue.recovery_id=requested_cleanup_recovery_id
           AND queue.dead_lettered_at IS NOT NULL
         FOR UPDATE;
        IF NOT FOUND OR claim_active THEN RETURN 'unavailable'; END IF;
        UPDATE upload_cleanup_queue
           SET dead_lettered_at=NULL,claim_token=NULL,claim_expires_at=NULL,
               attempts=0,available_at=pg_catalog.clock_timestamp()
         WHERE recovery_id=requested_cleanup_recovery_id
           AND dead_lettered_at=previous_dead_lettered_at
           AND (claim_token IS NULL
                OR claim_expires_at<=pg_catalog.clock_timestamp());
        audit_target:='cleanup:' || requested_cleanup_recovery_id::pg_catalog.text;
    ELSE
        RETURN 'invalid';
    END IF;
    IF NOT FOUND THEN RETURN 'unavailable'; END IF;
    INSERT INTO audit_log(actor_id,action,target,details,request_id)
    VALUES(
        requested_actor_id,'admin.upload_dead_letter.retry',audit_target,
        pg_catalog.jsonb_build_object(
            'kind',requested_kind,
            'previous_attempts',previous_attempts,
            'previous_dead_lettered_at',previous_dead_lettered_at,
            'had_expired_claim',had_expired_claim,
            'had_stored_error',had_stored_error,
            'original_error_retained_on_recovery_row',had_stored_error
        ),requested_request_id
    );
    RETURN 'retried';
END;
$northstar_upload_retry_dead_letter$;

CREATE FUNCTION northstar_upload_claim_cleanup(requested_claim_token pg_catalog.uuid)
RETURNS TABLE(
    object_id pg_catalog.uuid,storage_backend pg_catalog.text,
    object_key pg_catalog.text,object_version pg_catalog.text,
    stage_key pg_catalog.text,stage_version pg_catalog.text,
    storage_attempt pg_catalog.uuid,storage_fence pg_catalog.int8,
    claim_token pg_catalog.uuid
)
LANGUAGE sql
SECURITY DEFINER
AS $northstar_upload_claim_cleanup$
    WITH candidates AS (
      SELECT queue.object_id FROM upload_cleanup_queue queue
       WHERE queue.available_at<=pg_catalog.clock_timestamp()
         AND queue.dead_lettered_at IS NULL AND queue.attempts<24
         AND (queue.claim_token IS NULL
              OR queue.claim_expires_at<=pg_catalog.clock_timestamp())
         AND NOT EXISTS(
           SELECT 1 FROM upload_storage_jobs job
            WHERE job.object_id=queue.object_id
              AND job.storage_attempt IS NOT DISTINCT FROM queue.storage_attempt
              AND job.storage_fence=queue.storage_fence
              AND job.action='promote'
         )
       ORDER BY queue.available_at,queue.queued_at,queue.object_id
       FOR UPDATE SKIP LOCKED LIMIT 4
    )
    UPDATE upload_cleanup_queue queue
       SET claim_token=requested_claim_token,
           claim_expires_at=pg_catalog.clock_timestamp()+INTERVAL '240 seconds',
           attempts=queue.attempts+1
      FROM candidates WHERE queue.object_id=candidates.object_id
    RETURNING queue.object_id,queue.storage_backend,queue.object_key,
      CASE WHEN queue.storage_backend='s3' AND queue.stage_key=queue.object_key
           THEN COALESCE(queue.object_version,queue.stage_version)
           ELSE queue.object_version END,
      queue.stage_key,queue.stage_version,queue.storage_attempt,
      queue.storage_fence,queue.claim_token
$northstar_upload_claim_cleanup$;

CREATE FUNCTION northstar_upload_cleanup_quiescent(
    requested_id pg_catalog.uuid,requested_claim_token pg_catalog.uuid,
    requested_storage_fence pg_catalog.int8
) RETURNS pg_catalog.bool
LANGUAGE sql
SECURITY DEFINER
AS $northstar_upload_cleanup_quiescent$
    SELECT EXISTS(
      SELECT 1 FROM upload_cleanup_queue queue
       WHERE queue.object_id=requested_id
         AND queue.claim_token=requested_claim_token
         AND queue.storage_fence=requested_storage_fence
         AND queue.claim_expires_at>pg_catalog.clock_timestamp()
         AND NOT EXISTS(
           SELECT 1 FROM upload_storage_jobs job
            WHERE job.object_id=queue.object_id
              AND job.storage_attempt IS NOT DISTINCT FROM queue.storage_attempt
              AND job.storage_fence=queue.storage_fence
              AND job.action='promote'
         )
    )
$northstar_upload_cleanup_quiescent$;

CREATE FUNCTION northstar_upload_defer_cleanup(
    requested_id pg_catalog.uuid,requested_claim_token pg_catalog.uuid
) RETURNS pg_catalog.bool
LANGUAGE sql
SECURITY DEFINER
AS $northstar_upload_defer_cleanup$
    WITH changed AS (
      UPDATE upload_cleanup_queue
         SET claim_token=NULL,claim_expires_at=NULL,
             attempts=GREATEST(attempts-1,0),
             available_at=pg_catalog.clock_timestamp()+INTERVAL '1 second'
       WHERE object_id=requested_id AND claim_token=requested_claim_token
      RETURNING 1
    ) SELECT EXISTS(SELECT 1 FROM changed)
$northstar_upload_defer_cleanup$;

CREATE FUNCTION northstar_upload_confirm_cleanup_absence(
    requested_id pg_catalog.uuid,requested_claim_token pg_catalog.uuid,
    removed_now pg_catalog.bool,quiet_seconds pg_catalog.int8
) RETURNS pg_catalog.bool
LANGUAGE plpgsql
SECURITY DEFINER
AS $northstar_upload_confirm_cleanup_absence$
DECLARE quiet pg_catalog.bool;
BEGIN
    IF quiet_seconds NOT BETWEEN 60 AND 3600 THEN
        RAISE EXCEPTION 'invalid cleanup quiet period' USING ERRCODE='22023';
    END IF;
    SELECT COALESCE(absence_observed_at<=pg_catalog.clock_timestamp()
                    -(quiet_seconds*INTERVAL '1 second'),FALSE)
      INTO quiet FROM upload_cleanup_queue
     WHERE object_id=requested_id AND claim_token=requested_claim_token
       AND claim_expires_at>pg_catalog.clock_timestamp()
       AND dead_lettered_at IS NULL FOR UPDATE;
    IF NOT FOUND THEN RETURN FALSE; END IF;
    IF NOT removed_now AND quiet THEN RETURN TRUE; END IF;
    UPDATE upload_cleanup_queue
       SET absence_observed_at=CASE
             WHEN removed_now OR absence_observed_at IS NULL
             THEN pg_catalog.clock_timestamp() ELSE absence_observed_at END,
           absence_observations=absence_observations+1,
           -- An expected two-observation absence fence is not a failed
           -- provider attempt. Return the claim-side increment so a row at
           -- attempts=23 can still be reclaimed after the quiet window.
           attempts=GREATEST(attempts-1,0),
           claim_token=NULL,claim_expires_at=NULL,
           available_at=pg_catalog.clock_timestamp()
             +(quiet_seconds*INTERVAL '1 second')
     WHERE object_id=requested_id AND claim_token=requested_claim_token;
    RETURN FALSE;
END;
$northstar_upload_confirm_cleanup_absence$;

CREATE FUNCTION northstar_upload_fail_cleanup(
    requested_id pg_catalog.uuid,requested_claim_token pg_catalog.uuid,
    sanitized_error pg_catalog.text
) RETURNS pg_catalog.bool
LANGUAGE sql
SECURITY DEFINER
AS $northstar_upload_fail_cleanup$
    WITH changed AS (
      UPDATE upload_cleanup_queue
         SET claim_token=NULL,claim_expires_at=NULL,
             last_error=pg_catalog.left(sanitized_error,2048),
             dead_lettered_at=CASE WHEN attempts>=24
                 THEN pg_catalog.clock_timestamp() ELSE dead_lettered_at END,
             available_at=pg_catalog.clock_timestamp()+
               (LEAST(3600,POWER(2,LEAST(attempts,11))::pg_catalog.int8)
                 *INTERVAL '1 second')
       WHERE object_id=requested_id AND claim_token=requested_claim_token
      RETURNING 1
    ) SELECT EXISTS(SELECT 1 FROM changed)
$northstar_upload_fail_cleanup$;

CREATE FUNCTION northstar_upload_complete_cleanup(
    requested_id pg_catalog.uuid,requested_claim_token pg_catalog.uuid
) RETURNS pg_catalog.bool
LANGUAGE plpgsql
SECURITY DEFINER
AS $northstar_upload_complete_cleanup$
DECLARE slot_removed pg_catalog.bool;
DECLARE slot_still_exists pg_catalog.bool;
BEGIN
    PERFORM 1 FROM upload_storage_capacity_ledger WHERE singleton FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'upload storage capacity authority is missing'
            USING ERRCODE='55000';
    END IF;
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

CREATE FUNCTION northstar_upload_claim_storage_jobs(requested_claim_token pg_catalog.uuid)
RETURNS TABLE(
    id pg_catalog.int8,object_id pg_catalog.uuid,storage_attempt pg_catalog.uuid,
    action pg_catalog.text,storage_backend pg_catalog.text,
    stage_key pg_catalog.text,stage_version pg_catalog.text,
    object_key pg_catalog.text,object_version pg_catalog.text,
    expected_size pg_catalog.int8,expected_sha256 pg_catalog.bytea,
    storage_fence pg_catalog.int8,claim_token pg_catalog.uuid
)
LANGUAGE sql
SECURITY DEFINER
AS $northstar_upload_claim_storage_jobs$
    WITH candidates AS (
      SELECT job.id FROM upload_storage_jobs job
       WHERE job.available_at<=pg_catalog.clock_timestamp()
         AND job.dead_lettered_at IS NULL AND job.attempts<24
         AND (job.claim_token IS NULL
              OR job.claim_expires_at<=pg_catalog.clock_timestamp())
       ORDER BY job.available_at,job.id FOR UPDATE SKIP LOCKED LIMIT 4
    )
    UPDATE upload_storage_jobs job
       SET claim_token=requested_claim_token,
           claim_expires_at=pg_catalog.clock_timestamp()+INTERVAL '240 seconds',
           attempts=job.attempts+1,updated_at=pg_catalog.clock_timestamp()
      FROM candidates WHERE job.id=candidates.id
    RETURNING job.id,job.object_id,job.storage_attempt,job.action,
      job.storage_backend,job.stage_key,job.stage_version,job.object_key,
      job.object_version,job.expected_size,job.expected_sha256,
      job.storage_fence,job.claim_token
$northstar_upload_claim_storage_jobs$;

CREATE FUNCTION northstar_upload_complete_storage_job(
    requested_id pg_catalog.int8,requested_claim_token pg_catalog.uuid
) RETURNS pg_catalog.bool
LANGUAGE plpgsql
SECURITY DEFINER
AS $northstar_upload_complete_storage_job$
BEGIN
    PERFORM 1 FROM upload_storage_capacity_ledger WHERE singleton FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'upload storage capacity authority is missing'
            USING ERRCODE='55000';
    END IF;
    DELETE FROM upload_storage_jobs
     WHERE id=requested_id AND claim_token=requested_claim_token;
    RETURN FOUND;
END;
$northstar_upload_complete_storage_job$;

CREATE FUNCTION northstar_upload_confirm_stage_absence(
    requested_id pg_catalog.int8,requested_claim_token pg_catalog.uuid,
    removed_now pg_catalog.bool,quiet_seconds pg_catalog.int8
) RETURNS pg_catalog.bool
LANGUAGE plpgsql
SECURITY DEFINER
AS $northstar_upload_confirm_stage_absence$
DECLARE quiet pg_catalog.bool;
BEGIN
    IF quiet_seconds NOT BETWEEN 60 AND 3600 THEN
        RAISE EXCEPTION 'invalid stage quiet period' USING ERRCODE='22023';
    END IF;
    SELECT COALESCE(absence_observed_at<=pg_catalog.clock_timestamp()
                    -(quiet_seconds*INTERVAL '1 second'),FALSE)
      INTO quiet FROM upload_storage_jobs
     WHERE id=requested_id AND action='delete_stage'
       AND claim_token=requested_claim_token
       AND claim_expires_at>pg_catalog.clock_timestamp()
       AND dead_lettered_at IS NULL FOR UPDATE;
    IF NOT FOUND THEN RETURN FALSE; END IF;
    IF NOT removed_now AND quiet THEN RETURN TRUE; END IF;
    UPDATE upload_storage_jobs
       SET absence_observed_at=CASE
             WHEN removed_now OR absence_observed_at IS NULL
             THEN pg_catalog.clock_timestamp() ELSE absence_observed_at END,
           absence_observations=absence_observations+1,
           -- Quiet-window confirmation is successful recovery progress, not
           -- an error-budget event. Preserve the final reclaim opportunity.
           attempts=GREATEST(attempts-1,0),
           claim_token=NULL,claim_expires_at=NULL,
           available_at=pg_catalog.clock_timestamp()
             +(quiet_seconds*INTERVAL '1 second'),
           updated_at=pg_catalog.clock_timestamp()
     WHERE id=requested_id AND claim_token=requested_claim_token;
    RETURN FALSE;
END;
$northstar_upload_confirm_stage_absence$;

CREATE FUNCTION northstar_upload_fail_storage_job(
    requested_id pg_catalog.int8,requested_claim_token pg_catalog.uuid,
    sanitized_error pg_catalog.text
) RETURNS pg_catalog.bool
LANGUAGE sql
SECURITY DEFINER
AS $northstar_upload_fail_storage_job$
    WITH changed AS (
      UPDATE upload_storage_jobs
         SET last_error=pg_catalog.left(sanitized_error,2048),
             dead_lettered_at=CASE WHEN attempts>=24
                 THEN pg_catalog.clock_timestamp() ELSE dead_lettered_at END,
             available_at=GREATEST(claim_expires_at,
               pg_catalog.clock_timestamp()+
               (LEAST(3600,POWER(2,LEAST(attempts,11))::pg_catalog.int8)
                 *INTERVAL '1 second')),
             updated_at=pg_catalog.clock_timestamp()
       WHERE id=requested_id AND claim_token=requested_claim_token
      RETURNING 1
    ) SELECT EXISTS(SELECT 1 FROM changed)
$northstar_upload_fail_storage_job$;

CREATE FUNCTION northstar_upload_defer_storage_job(
    requested_id pg_catalog.int8,requested_claim_token pg_catalog.uuid
) RETURNS pg_catalog.bool
LANGUAGE sql
SECURITY DEFINER
AS $northstar_upload_defer_storage_job$
    WITH changed AS (
      UPDATE upload_storage_jobs
         SET claim_token=NULL,claim_expires_at=NULL,
             attempts=GREATEST(attempts-1,0),
             available_at=pg_catalog.clock_timestamp()+INTERVAL '1 second',
             updated_at=pg_catalog.clock_timestamp()
       WHERE id=requested_id AND claim_token=requested_claim_token
      RETURNING 1
    ) SELECT EXISTS(SELECT 1 FROM changed)
$northstar_upload_defer_storage_job$;

CREATE FUNCTION northstar_upload_claim_promotion_job(
    requested_id pg_catalog.uuid,requested_attempt pg_catalog.uuid,
    requested_fence pg_catalog.int8,requested_claim_token pg_catalog.uuid
) RETURNS pg_catalog.bool
LANGUAGE sql
SECURITY DEFINER
AS $northstar_upload_claim_promotion_job$
    WITH changed AS (
      UPDATE upload_storage_jobs
         SET claim_token=requested_claim_token,
             claim_expires_at=pg_catalog.clock_timestamp()+INTERVAL '240 seconds',
             attempts=attempts+1,updated_at=pg_catalog.clock_timestamp()
       WHERE object_id=requested_id AND storage_attempt=requested_attempt
         AND action='promote' AND storage_fence=requested_fence
         AND (claim_token IS NULL
              OR claim_expires_at<=pg_catalog.clock_timestamp())
      RETURNING 1
    ) SELECT EXISTS(SELECT 1 FROM changed)
$northstar_upload_claim_promotion_job$;

CREATE FUNCTION northstar_upload_defer_promotion_job(
    requested_id pg_catalog.uuid,requested_attempt pg_catalog.uuid,
    requested_fence pg_catalog.int8,requested_claim_token pg_catalog.uuid
) RETURNS pg_catalog.bool
LANGUAGE sql
SECURITY DEFINER
AS $northstar_upload_defer_promotion_job$
    WITH changed AS (
      UPDATE upload_storage_jobs
         SET claim_token=NULL,claim_expires_at=NULL,
             attempts=GREATEST(attempts-1,0),
             available_at=pg_catalog.clock_timestamp()+INTERVAL '1 second',
             updated_at=pg_catalog.clock_timestamp()
       WHERE object_id=requested_id AND storage_attempt=requested_attempt
         AND action='promote' AND storage_fence=requested_fence
         AND claim_token=requested_claim_token
      RETURNING 1
    ) SELECT EXISTS(SELECT 1 FROM changed)
$northstar_upload_defer_promotion_job$;

CREATE FUNCTION northstar_upload_retire_promotion_for_cleanup(
    requested_id pg_catalog.uuid,requested_attempt pg_catalog.uuid,
    requested_fence pg_catalog.int8,requested_claim_token pg_catalog.uuid
) RETURNS pg_catalog.bool
LANGUAGE plpgsql
SECURITY DEFINER
AS $northstar_upload_retire_promotion_for_cleanup$
BEGIN
    PERFORM 1 FROM upload_storage_capacity_ledger WHERE singleton FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'upload storage capacity authority is missing'
            USING ERRCODE='55000';
    END IF;
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

CREATE FUNCTION northstar_upload_record_stage(
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
    PERFORM 1 FROM upload_storage_capacity_ledger WHERE singleton FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'upload storage capacity authority is missing'
            USING ERRCODE='55000';
    END IF;
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

CREATE FUNCTION northstar_upload_release_claim(
    requested_id pg_catalog.uuid,requested_claim_token pg_catalog.uuid
) RETURNS pg_catalog.bool
LANGUAGE plpgsql
SECURITY DEFINER
AS $northstar_upload_release_claim$
DECLARE slot_row pg_catalog.record;
DECLARE inserted_rows pg_catalog.int8;
BEGIN
    PERFORM 1 FROM upload_storage_capacity_ledger WHERE singleton FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'upload storage capacity authority is missing'
            USING ERRCODE='55000';
    END IF;
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

CREATE FUNCTION northstar_upload_complete_promotion(
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
    PERFORM 1 FROM upload_storage_capacity_ledger WHERE singleton FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'upload storage capacity authority is missing'
            USING ERRCODE='55000';
    END IF;
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

CREATE FUNCTION northstar_upload_reserve_slot(
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
BEGIN
    IF requested_size<=0 OR requested_backend NOT IN ('local','s3')
       OR requested_user_file_limit<=0 OR requested_user_byte_limit<=0
       OR expected_retained_file_limit<=0 OR expected_retained_byte_limit<=0
       OR expected_pending_limit<=0 THEN
        RAISE EXCEPTION 'invalid upload reservation policy' USING ERRCODE='22023';
    END IF;
    BEGIN
        SELECT * INTO ledger_row FROM upload_storage_capacity_ledger
         WHERE singleton FOR UPDATE NOWAIT;
    EXCEPTION WHEN lock_not_available THEN
        RETURN FALSE;
    END;
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
    PERFORM 1 FROM users WHERE id=requested_user_id FOR UPDATE;
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
        RETURN FALSE;
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
        RETURN FALSE;
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
END;
$northstar_upload_reserve_slot$;

CREATE FUNCTION northstar_upload_claim_is_live(
    requested_id pg_catalog.uuid,requested_claim_token pg_catalog.uuid
) RETURNS pg_catalog.bool
LANGUAGE sql
SECURITY DEFINER
AS $northstar_upload_claim_is_live$
    SELECT COALESCE((
      SELECT uploading AND NOT uploaded AND storage_attempt=requested_claim_token
             AND (storage_state IN ('staged','promoting') OR
                  (claim_expires_at>pg_catalog.clock_timestamp()
                   AND put_expires_at>pg_catalog.clock_timestamp()
                   AND expires_at>pg_catalog.clock_timestamp()))
        FROM upload_slots
       WHERE id=requested_id AND claim_token=requested_claim_token
    ),FALSE)
$northstar_upload_claim_is_live$;

CREATE FUNCTION northstar_upload_begin_promotion(
    requested_id pg_catalog.uuid,requested_claim_token pg_catalog.uuid,
    requested_fence pg_catalog.int8,requested_promotion_claim_token pg_catalog.uuid
) RETURNS pg_catalog.bool
LANGUAGE plpgsql
SECURITY DEFINER
AS $northstar_upload_begin_promotion$
BEGIN
    PERFORM 1 FROM upload_slots
     WHERE id=requested_id AND storage_attempt=requested_claim_token
       AND claim_token=requested_claim_token AND storage_fence=requested_fence
       AND uploading AND NOT uploaded AND storage_state IN ('staged','promoting')
     FOR UPDATE;
    IF NOT FOUND THEN RETURN FALSE; END IF;
    -- Refresh, but never steal, the exact queue lease immediately before the
    -- bounded 180-second provider operation.  The 240-second fence therefore
    -- remains live for the whole external-I/O budget without incrementing the
    -- retry counter.
    UPDATE upload_storage_jobs
       SET claim_expires_at=pg_catalog.clock_timestamp()+INTERVAL '240 seconds',
           updated_at=pg_catalog.clock_timestamp()
     WHERE object_id=requested_id AND storage_attempt=requested_claim_token
       AND action='promote' AND storage_fence=requested_fence
       AND claim_token=requested_promotion_claim_token
       AND claim_expires_at>pg_catalog.clock_timestamp();
    IF NOT FOUND THEN RETURN FALSE; END IF;
    UPDATE upload_slots
       SET storage_state='promoting',storage_updated_at=pg_catalog.clock_timestamp()
     WHERE id=requested_id AND storage_attempt=requested_claim_token
       AND claim_token=requested_claim_token AND storage_fence=requested_fence
       AND uploading AND NOT uploaded AND storage_state IN ('staged','promoting');
    RETURN FOUND;
END;
$northstar_upload_begin_promotion$;

CREATE FUNCTION northstar_upload_attempt_committed(
    requested_id pg_catalog.uuid,requested_attempt pg_catalog.uuid,
    requested_backend pg_catalog.text,requested_object_key pg_catalog.text,
    requested_object_version pg_catalog.text,requested_sha256 pg_catalog.bytea,
    requested_size pg_catalog.int8,requested_fence pg_catalog.int8
) RETURNS pg_catalog.bool
LANGUAGE sql
SECURITY DEFINER
AS $northstar_upload_attempt_committed$
    SELECT EXISTS(
      SELECT 1 FROM upload_slots
       WHERE id=requested_id AND uploaded AND NOT uploading
         AND storage_state='committed' AND storage_attempt=requested_attempt
         AND storage_backend=requested_backend
         AND storage_object_key=requested_object_key
         AND (requested_object_version IS NULL OR
              storage_object_version IS NOT DISTINCT FROM requested_object_version)
         AND storage_sha256=requested_sha256 AND content_sha256=requested_sha256
         AND storage_size=requested_size AND size=requested_size
         AND storage_fence=requested_fence
    )
$northstar_upload_attempt_committed$;

CREATE FUNCTION northstar_upload_record_replay(
    requested_id pg_catalog.uuid,requested_token_hash pg_catalog.bytea,
    requested_sha256 pg_catalog.bytea,requested_max_replays pg_catalog.int8
) RETURNS pg_catalog.bool
LANGUAGE plpgsql
SECURITY DEFINER
AS $northstar_upload_record_replay$
BEGIN
    UPDATE upload_slots
       SET replay_count=replay_count+1,last_replayed_at=pg_catalog.clock_timestamp()
     WHERE id=requested_id AND token_hash=requested_token_hash AND uploaded
       AND replay_count<requested_max_replays AND content_sha256=requested_sha256
       AND put_expires_at>pg_catalog.clock_timestamp()
       AND expires_at>pg_catalog.clock_timestamp();
    RETURN FOUND;
END;
$northstar_upload_record_replay$;

CREATE FUNCTION northstar_upload_public_file(requested_id pg_catalog.uuid)
RETURNS TABLE(
    id pg_catalog.uuid,content_type pg_catalog.text,size pg_catalog.int8,
    storage_backend pg_catalog.text,storage_object_key pg_catalog.text,
    storage_object_version pg_catalog.text,object_remaining_seconds pg_catalog.int8
)
LANGUAGE sql
SECURITY DEFINER
AS $northstar_upload_public_file$
    SELECT slot.id,slot.content_type::pg_catalog.text,slot.size,slot.storage_backend,
           slot.storage_object_key,slot.storage_object_version,
           GREATEST(0,pg_catalog.ceil(EXTRACT(
             EPOCH FROM slot.expires_at-pg_catalog.clock_timestamp()
           )))::pg_catalog.int8
      FROM upload_slots slot
     WHERE slot.id=requested_id AND slot.uploaded
       AND slot.storage_state IN ('committed','legacy_committed')
       AND slot.expires_at>pg_catalog.clock_timestamp()
$northstar_upload_public_file$;

CREATE FUNCTION northstar_upload_claim_scrub()
RETURNS TABLE(
    object_id pg_catalog.uuid,storage_attempt pg_catalog.uuid,
    object_key pg_catalog.text,object_version pg_catalog.text,
    expected_size pg_catalog.int8,expected_sha256 pg_catalog.bytea,
    claim_token pg_catalog.uuid
)
LANGUAGE plpgsql
SECURITY DEFINER
AS $northstar_upload_claim_scrub$
BEGIN
    RETURN QUERY
    WITH due AS (
      SELECT slot.id FROM upload_slots slot
       WHERE slot.storage_backend='s3' AND slot.storage_state='committed'
         AND slot.storage_attempt IS NOT NULL
         AND slot.storage_object_key IS NOT NULL
         AND slot.storage_sha256 IS NOT NULL AND slot.storage_size IS NOT NULL
         AND slot.storage_scrub_next_at<=pg_catalog.clock_timestamp()
         AND (slot.storage_scrub_claim_token IS NULL OR
              slot.storage_scrub_claim_expires_at<=pg_catalog.clock_timestamp())
       ORDER BY slot.storage_scrub_next_at,slot.id
       LIMIT 2 FOR UPDATE SKIP LOCKED
    ), claimed AS (
      UPDATE upload_slots slot
         SET storage_scrub_claim_token=gen_random_uuid(),
             storage_scrub_claim_expires_at=pg_catalog.clock_timestamp()+INTERVAL '240 seconds'
        FROM due WHERE slot.id=due.id
      RETURNING slot.id,slot.storage_attempt,slot.storage_object_key,
                slot.storage_object_version,slot.storage_size,slot.storage_sha256,
                slot.storage_scrub_claim_token
    ) SELECT claimed.* FROM claimed;
END;
$northstar_upload_claim_scrub$;

CREATE FUNCTION northstar_upload_finish_scrub(
    requested_id pg_catalog.uuid,requested_claim pg_catalog.uuid,
    requested_outcome pg_catalog.text
) RETURNS pg_catalog.bool
LANGUAGE plpgsql
SECURITY DEFINER
AS $northstar_upload_finish_scrub$
BEGIN
    IF requested_outcome NOT IN ('complete','fail','defer') THEN
        RAISE EXCEPTION 'invalid scrub outcome' USING ERRCODE='22023';
    END IF;
    IF requested_outcome='complete' THEN
      UPDATE upload_slots SET storage_scrubbed_at=pg_catalog.clock_timestamp(),
             storage_scrub_next_at=pg_catalog.clock_timestamp()+INTERVAL '24 hours',
             storage_scrub_failures=0,storage_scrub_claim_token=NULL,
             storage_scrub_claim_expires_at=NULL
       WHERE id=requested_id AND storage_state='committed'
         AND storage_scrub_claim_token=requested_claim
         AND storage_scrub_claim_expires_at>pg_catalog.clock_timestamp();
    ELSIF requested_outcome='fail' THEN
      UPDATE upload_slots SET storage_scrub_failures=storage_scrub_failures+1,
             storage_scrub_next_at=pg_catalog.clock_timestamp()+INTERVAL '1 hour',
             storage_scrub_claim_token=NULL,storage_scrub_claim_expires_at=NULL
       WHERE id=requested_id AND storage_scrub_claim_token=requested_claim;
    ELSE
      UPDATE upload_slots SET storage_scrub_claim_token=NULL,
             storage_scrub_claim_expires_at=NULL,
             storage_scrub_next_at=pg_catalog.clock_timestamp()+INTERVAL '1 minute',
             storage_updated_at=pg_catalog.clock_timestamp()
       WHERE id=requested_id AND storage_scrub_claim_token=requested_claim;
    END IF;
    RETURN FOUND;
END;
$northstar_upload_finish_scrub$;

CREATE FUNCTION northstar_upload_claim_slot(
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
    BEGIN
      SELECT * INTO ledger_row FROM upload_storage_capacity_ledger
       WHERE singleton FOR UPDATE NOWAIT;
    EXCEPTION WHEN lock_not_available THEN
      RETURN QUERY SELECT 'in_progress'::pg_catalog.text,NULL::pg_catalog.uuid,
        NULL::pg_catalog.text,NULL::pg_catalog.int8,NULL::pg_catalog.int8,
        NULL::pg_catalog.text,NULL::pg_catalog.text,NULL::pg_catalog.text,
        NULL::pg_catalog.bytea,NULL::pg_catalog.uuid,NULL::pg_catalog.int8,
        1::pg_catalog.int8;
      RETURN;
    END;
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
     FOR UPDATE;
    IF NOT FOUND THEN
      RETURN QUERY SELECT 'rejected'::pg_catalog.text,NULL::pg_catalog.uuid,
        NULL::pg_catalog.text,NULL::pg_catalog.int8,NULL::pg_catalog.int8,
        NULL::pg_catalog.text,NULL::pg_catalog.text,NULL::pg_catalog.text,
        NULL::pg_catalog.bytea,NULL::pg_catalog.uuid,NULL::pg_catalog.int8,
        NULL::pg_catalog.int8;
      RETURN;
    END IF;
    IF slot_row.uploaded THEN
      IF slot_row.replay_count>=requested_max_replays
         OR slot_row.content_sha256 IS NULL
         OR pg_catalog.octet_length(slot_row.content_sha256)<>32 THEN
        RETURN QUERY SELECT 'rejected'::pg_catalog.text,NULL::pg_catalog.uuid,
          NULL::pg_catalog.text,NULL::pg_catalog.int8,NULL::pg_catalog.int8,
          NULL::pg_catalog.text,NULL::pg_catalog.text,NULL::pg_catalog.text,
          NULL::pg_catalog.bytea,NULL::pg_catalog.uuid,NULL::pg_catalog.int8,
          NULL::pg_catalog.int8;
      ELSE
        RETURN QUERY SELECT 'replay'::pg_catalog.text,slot_row.id,
          slot_row.content_type::pg_catalog.text,slot_row.size,slot_row.remaining_seconds,
          slot_row.storage_backend,slot_row.storage_object_key,
          slot_row.storage_object_version,slot_row.content_sha256,
          NULL::pg_catalog.uuid,slot_row.storage_fence,NULL::pg_catalog.int8;
      END IF;
      RETURN;
    END IF;
    IF slot_row.upload_attempts>=requested_max_attempts THEN
      RETURN QUERY SELECT 'rejected'::pg_catalog.text,NULL::pg_catalog.uuid,
        NULL::pg_catalog.text,NULL::pg_catalog.int8,NULL::pg_catalog.int8,
        NULL::pg_catalog.text,NULL::pg_catalog.text,NULL::pg_catalog.text,
        NULL::pg_catalog.bytea,NULL::pg_catalog.uuid,NULL::pg_catalog.int8,
        NULL::pg_catalog.int8;
      RETURN;
    END IF;
    IF slot_row.storage_state IN ('staged','promoting') THEN
      RETURN QUERY SELECT 'in_progress'::pg_catalog.text,NULL::pg_catalog.uuid,
        NULL::pg_catalog.text,NULL::pg_catalog.int8,NULL::pg_catalog.int8,
        NULL::pg_catalog.text,NULL::pg_catalog.text,NULL::pg_catalog.text,
        NULL::pg_catalog.bytea,NULL::pg_catalog.uuid,NULL::pg_catalog.int8,
        1::pg_catalog.int8;
      RETURN;
    END IF;
    IF slot_row.uploading AND slot_row.claim_expires_at>pg_catalog.clock_timestamp() THEN
      RETURN QUERY SELECT 'in_progress'::pg_catalog.text,NULL::pg_catalog.uuid,
        NULL::pg_catalog.text,NULL::pg_catalog.int8,NULL::pg_catalog.int8,
        NULL::pg_catalog.text,NULL::pg_catalog.text,NULL::pg_catalog.text,
        NULL::pg_catalog.bytea,NULL::pg_catalog.uuid,NULL::pg_catalog.int8,
        GREATEST(1,slot_row.claim_retry_seconds)::pg_catalog.int8;
      RETURN;
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
        RETURN QUERY SELECT 'in_progress'::pg_catalog.text,NULL::pg_catalog.uuid,
          NULL::pg_catalog.text,NULL::pg_catalog.int8,NULL::pg_catalog.int8,
          NULL::pg_catalog.text,NULL::pg_catalog.text,NULL::pg_catalog.text,
          NULL::pg_catalog.bytea,NULL::pg_catalog.uuid,NULL::pg_catalog.int8,
          5::pg_catalog.int8;
        RETURN;
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
      RETURN QUERY SELECT 'rejected'::pg_catalog.text,NULL::pg_catalog.uuid,
        NULL::pg_catalog.text,NULL::pg_catalog.int8,NULL::pg_catalog.int8,
        NULL::pg_catalog.text,NULL::pg_catalog.text,NULL::pg_catalog.text,
        NULL::pg_catalog.bytea,NULL::pg_catalog.uuid,NULL::pg_catalog.int8,
        NULL::pg_catalog.int8;
      RETURN;
    END IF;
    RETURN QUERY SELECT 'acquired'::pg_catalog.text,slot_row.id,
      slot_row.content_type::pg_catalog.text,slot_row.size,slot_row.remaining_seconds,
      slot_row.storage_backend,slot_row.storage_object_key,
      slot_row.storage_object_version,NULL::pg_catalog.bytea,new_claim,
      claimed_row.storage_fence,claimed_row.remaining_seconds;
END;
$northstar_upload_claim_slot$;

CREATE FUNCTION northstar_upload_capacity_reconciliation()
RETURNS TABLE(
  ledger_retained_files pg_catalog.int8,fact_retained_files pg_catalog.int8,
  ledger_retained_bytes pg_catalog.int8,fact_retained_bytes pg_catalog.int8,
  ledger_pending_jobs pg_catalog.int8,fact_pending_jobs pg_catalog.int8,
  ledger_storage_jobs_pending pg_catalog.int8,fact_storage_jobs_pending pg_catalog.int8,
  ledger_cleanup_jobs_pending pg_catalog.int8,fact_cleanup_jobs_pending pg_catalog.int8,
  ledger_cleanup_obligation_debt pg_catalog.int8,fact_cleanup_obligation_debt pg_catalog.int8,
  ledger_recovery_retained_files pg_catalog.int8,fact_recovery_retained_files pg_catalog.int8,
  ledger_recovery_retained_bytes pg_catalog.int8,fact_recovery_retained_bytes pg_catalog.int8,
  ledger_legacy_overcommit_draining pg_catalog.bool,
  fact_legacy_overcommit_draining pg_catalog.bool,
  ledger_recovery_overcommit_draining pg_catalog.bool,
  fact_recovery_overcommit_draining pg_catalog.bool,
  projection_size_conflicts pg_catalog.int8
)
LANGUAGE sql
SECURITY DEFINER
AS $northstar_upload_capacity_reconciliation$
WITH projection_rows AS (
  SELECT object_id,expected_size FROM upload_storage_jobs
  UNION ALL SELECT object_id,expected_size FROM upload_cleanup_queue
), projection_summary AS (
  SELECT projection.object_id,
         pg_catalog.min(projection.expected_size)::pg_catalog.int8 AS expected_size,
         pg_catalog.count(DISTINCT projection.expected_size)::pg_catalog.int8 AS size_variants
    FROM projection_rows projection GROUP BY projection.object_id
), orphan_projection AS (
  SELECT projection.* FROM projection_summary projection
   WHERE NOT EXISTS(SELECT 1 FROM upload_slots slot
                     WHERE slot.id=projection.object_id)
), facts AS (
  SELECT
    (SELECT pg_catalog.count(*) FROM upload_slots)+
      (SELECT pg_catalog.count(*) FROM orphan_projection) AS retained_files,
    (COALESCE((SELECT pg_catalog.sum(size) FROM upload_slots),0)+
      COALESCE((SELECT pg_catalog.sum(expected_size) FROM orphan_projection),0))::pg_catalog.int8
      AS retained_bytes,
    (SELECT pg_catalog.count(*) FROM upload_storage_jobs)+
      (SELECT pg_catalog.count(*) FROM upload_cleanup_queue) AS pending_jobs,
    (SELECT pg_catalog.count(*) FROM upload_storage_jobs) AS storage_jobs_pending,
    (SELECT pg_catalog.count(*) FROM upload_cleanup_queue) AS cleanup_jobs_pending,
    (SELECT pg_catalog.count(*) FROM upload_slots
      WHERE storage_cleanup_debt_reserved) AS cleanup_obligation_debt,
    (SELECT pg_catalog.count(*) FROM upload_storage_jobs)+
      COALESCE((SELECT pg_catalog.sum(CASE
        WHEN stage_key IS NULL OR (stage_key=object_key AND
             stage_version IS NOT DISTINCT FROM object_version)
        THEN 1 ELSE 2 END) FROM upload_cleanup_queue),0) AS recovery_retained_files,
    (COALESCE((SELECT pg_catalog.sum(expected_size) FROM upload_storage_jobs),0)+
      COALESCE((SELECT pg_catalog.sum(expected_size*CASE
        WHEN stage_key IS NULL OR (stage_key=object_key AND
             stage_version IS NOT DISTINCT FROM object_version)
        THEN 1 ELSE 2 END) FROM upload_cleanup_queue),0))::pg_catalog.int8
      AS recovery_retained_bytes,
    (SELECT pg_catalog.count(*) FROM projection_summary projection
      LEFT JOIN upload_slots slot ON slot.id=projection.object_id
     WHERE projection.size_variants<>1 OR
           (slot.id IS NOT NULL AND slot.size<>projection.expected_size))
      AS projection_size_conflicts
)
SELECT ledger.retained_files,facts.retained_files,
       ledger.retained_bytes,facts.retained_bytes,
       ledger.pending_jobs,facts.pending_jobs,
       ledger.storage_jobs_pending,facts.storage_jobs_pending,
       ledger.cleanup_jobs_pending,facts.cleanup_jobs_pending,
       ledger.cleanup_obligation_debt,facts.cleanup_obligation_debt,
       ledger.recovery_retained_files,facts.recovery_retained_files,
       ledger.recovery_retained_bytes,facts.recovery_retained_bytes,
       ledger.legacy_overcommit_draining,
       (facts.pending_jobs::pg_catalog.numeric+facts.cleanup_obligation_debt::pg_catalog.numeric>
         LEAST(ledger.configured_pending_limit,ledger.absolute_disaster_limit)::pg_catalog.numeric),
       ledger.recovery_overcommit_draining,
       (facts.retained_files::pg_catalog.numeric+facts.recovery_retained_files::pg_catalog.numeric>
          ledger.configured_retained_files_limit::pg_catalog.numeric OR
        facts.retained_bytes::pg_catalog.numeric+facts.recovery_retained_bytes::pg_catalog.numeric>
          ledger.configured_retained_bytes_limit::pg_catalog.numeric),
       facts.projection_size_conflicts
  FROM upload_storage_capacity_ledger ledger CROSS JOIN facts
 WHERE ledger.singleton
$northstar_upload_capacity_reconciliation$;

CREATE FUNCTION northstar_upload_queue_snapshot()
RETURNS TABLE(
  storage_jobs_pending pg_catalog.int8,cleanup_jobs_pending pg_catalog.int8,
  cleanup_obligation_debt pg_catalog.int8,configured_pending_limit pg_catalog.int8,
  legacy_overcommit_draining pg_catalog.bool,recovery_retained_files pg_catalog.int8,
  recovery_retained_bytes pg_catalog.int8,recovery_overcommit_draining pg_catalog.bool,
  dead_letter_jobs pg_catalog.int8,scrub_failures pg_catalog.int8,
  scrub_due_capped pg_catalog.int8,scrub_oldest_overdue_seconds pg_catalog.int8,
  cleanup_obligations_due_capped pg_catalog.int8,
  cleanup_oldest_overdue_seconds pg_catalog.int8,
  oldest_pending_age_seconds pg_catalog.int8
)
LANGUAGE sql
SECURITY DEFINER
AS $northstar_upload_queue_snapshot$
SELECT ledger.storage_jobs_pending,ledger.cleanup_jobs_pending,
       ledger.cleanup_obligation_debt,ledger.configured_pending_limit,
       ledger.legacy_overcommit_draining,ledger.recovery_retained_files,
       ledger.recovery_retained_bytes,ledger.recovery_overcommit_draining,
       ((SELECT pg_catalog.count(*) FROM upload_storage_jobs WHERE dead_lettered_at IS NOT NULL)+
        (SELECT pg_catalog.count(*) FROM upload_cleanup_queue WHERE dead_lettered_at IS NOT NULL)),
       (SELECT pg_catalog.count(*) FROM upload_slots
         WHERE storage_backend='s3' AND storage_state='committed'
           AND storage_scrub_failures>0),
       (SELECT pg_catalog.count(*) FROM (
          SELECT 1 FROM upload_slots WHERE storage_backend='s3'
            AND storage_state='committed'
            AND storage_scrub_next_at<=pg_catalog.clock_timestamp()
          ORDER BY storage_scrub_next_at,id LIMIT 1001
        ) bounded_due),
       COALESCE((SELECT pg_catalog.floor(GREATEST(0,EXTRACT(EPOCH FROM
          pg_catalog.clock_timestamp()-storage_scrub_next_at)))::pg_catalog.int8
          FROM upload_slots WHERE storage_backend='s3'
            AND storage_state='committed'
            AND storage_scrub_next_at<=pg_catalog.clock_timestamp()
          ORDER BY storage_scrub_next_at,id LIMIT 1),0),
       (SELECT pg_catalog.count(*) FROM (
          SELECT 1 FROM upload_slots
           WHERE expires_at<=pg_catalog.clock_timestamp() AND storage_state<>'deleting'
           ORDER BY expires_at,id LIMIT 1001
        ) due_slots),
       COALESCE((SELECT pg_catalog.floor(GREATEST(0,EXTRACT(EPOCH FROM
          pg_catalog.clock_timestamp()-expires_at)))::pg_catalog.int8
          FROM upload_slots WHERE expires_at<=pg_catalog.clock_timestamp()
            AND storage_state<>'deleting'
          ORDER BY expires_at,id LIMIT 1),0),
       pg_catalog.floor(GREATEST(0,EXTRACT(EPOCH FROM
         pg_catalog.clock_timestamp()-LEAST(
           COALESCE((SELECT pg_catalog.min(created_at) FROM upload_storage_jobs),
                    pg_catalog.clock_timestamp()),
           COALESCE((SELECT pg_catalog.min(queued_at) FROM upload_cleanup_queue),
                    pg_catalog.clock_timestamp())
         ))))::pg_catalog.int8
  FROM upload_storage_capacity_ledger ledger WHERE ledger.singleton
$northstar_upload_queue_snapshot$;

CREATE FUNCTION northstar_upload_policy_binding_matches(
  expected_pending pg_catalog.int8,expected_files pg_catalog.int8,
  expected_bytes pg_catalog.int8
) RETURNS pg_catalog.bool
LANGUAGE sql
SECURITY DEFINER
STABLE
AS $northstar_upload_policy_binding_matches$
  SELECT pg_catalog.count(*)=1 AND COALESCE(pg_catalog.bool_and(
    configured_pending_limit=expected_pending
    AND configured_retained_files_limit=expected_files
    AND configured_retained_bytes_limit=expected_bytes
    AND absolute_disaster_limit=100000 AND recovery_reserve_percent=25
    AND policy_generation>0
  ),FALSE) FROM upload_storage_capacity_ledger WHERE singleton
$northstar_upload_policy_binding_matches$;

CREATE FUNCTION northstar_upload_admit_expired_cleanup()
RETURNS TABLE(object_id pg_catalog.uuid)
LANGUAGE plpgsql
SECURITY DEFINER
AS $northstar_upload_admit_expired_cleanup$
DECLARE slot_row pg_catalog.record;
DECLARE effective_object_version pg_catalog.text;
DECLARE effective_size pg_catalog.int8;
DECLARE inserted_rows pg_catalog.int8;
BEGIN
  PERFORM 1 FROM upload_storage_capacity_ledger WHERE singleton FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'upload storage capacity authority is missing'
      USING ERRCODE='55000';
  END IF;
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

CREATE FUNCTION northstar_upload_delete_owned(
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
  PERFORM 1 FROM upload_storage_capacity_ledger WHERE singleton FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'upload storage capacity authority is missing'
      USING ERRCODE='55000';
  END IF;
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

CREATE FUNCTION northstar_upload_capability_catalog_healthy(
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
         (routine.proname<>'northstar_upload_offline_bootstrap_authority')
)
SELECT (SELECT pg_catalog.count(*)=1 FROM namespace)
  AND (SELECT pg_catalog.count(*)=5 AND pg_catalog.bool_and(
         relowner=nspowner
       ) FROM upload_relations)
  AND NOT EXISTS(SELECT 1 FROM public_relation_acl)
  AND NOT EXISTS(SELECT 1 FROM runtime_relation_acl)
  AND (SELECT pg_catalog.count(*)=42 AND pg_catalog.bool_and(
         proowner=nspowner AND prosecdef
         AND proconfig=ARRAY[
           pg_catalog.format('search_path=pg_catalog, %I, pg_temp',requested_schema)
         ]::pg_catalog.text[]
       ) FROM upload_routines)
  AND NOT EXISTS(SELECT 1 FROM public_routine_acl)
  AND NOT EXISTS(SELECT 1 FROM runtime_routine_acl_mismatch)
$northstar_upload_capability_catalog_healthy$;

DO $northstar_upload_capability_security$
DECLARE
    migration_schema pg_catalog.text := pg_catalog.current_schema();
    routine_signature pg_catalog.text;
    routine_oid pg_catalog.oid;
BEGIN
    FOREACH routine_signature IN ARRAY ARRAY[
        'queue_upload_storage_delete()',
        'reserve_upload_cleanup_debt()',
        'account_upload_slot_capacity()',
        'northstar_upload_bootstrap_authority(text,bytea)',
        'northstar_upload_offline_bootstrap_authority(text,bytea,text)',
        'northstar_upload_bind_capacity_policy(int8,int8,int8)',
        'northstar_upload_capacity_lock()',
        'northstar_upload_active_slot_count(uuid)',
        'northstar_upload_public_slot_count()',
        'northstar_upload_renew_claim(uuid,uuid,int8)',
        'northstar_upload_authority_probe(text,bytea,int8,int8,int8,int8,int8)'
        ,'northstar_upload_dead_letters_page(text,int8,uuid,int4)'
        ,'northstar_upload_retry_dead_letter(uuid,int8,bytea,text,int8,uuid,uuid)'
        ,'northstar_upload_claim_cleanup(uuid)'
        ,'northstar_upload_cleanup_quiescent(uuid,uuid,int8)'
        ,'northstar_upload_defer_cleanup(uuid,uuid)'
        ,'northstar_upload_confirm_cleanup_absence(uuid,uuid,bool,int8)'
        ,'northstar_upload_fail_cleanup(uuid,uuid,text)'
        ,'northstar_upload_complete_cleanup(uuid,uuid)'
        ,'northstar_upload_claim_storage_jobs(uuid)'
        ,'northstar_upload_complete_storage_job(int8,uuid)'
        ,'northstar_upload_confirm_stage_absence(int8,uuid,bool,int8)'
        ,'northstar_upload_fail_storage_job(int8,uuid,text)'
        ,'northstar_upload_defer_storage_job(int8,uuid)'
        ,'northstar_upload_claim_promotion_job(uuid,uuid,int8,uuid)'
        ,'northstar_upload_defer_promotion_job(uuid,uuid,int8,uuid)'
        ,'northstar_upload_retire_promotion_for_cleanup(uuid,uuid,int8,uuid)'
        ,'northstar_upload_record_stage(uuid,uuid,text,text,text,text,bytea,int8,int8)'
        ,'northstar_upload_release_claim(uuid,uuid)'
        ,'northstar_upload_complete_promotion(uuid,uuid,uuid,text,text,text,bytea,int8,int8,int8)'
        ,'northstar_upload_reserve_slot(uuid,uuid,text,text,int8,bytea,int8,int8,text,int8,int8,int8)'
        ,'northstar_upload_claim_is_live(uuid,uuid)'
        ,'northstar_upload_begin_promotion(uuid,uuid,int8,uuid)'
        ,'northstar_upload_attempt_committed(uuid,uuid,text,text,text,bytea,int8,int8)'
        ,'northstar_upload_record_replay(uuid,bytea,bytea,int8)'
        ,'northstar_upload_public_file(uuid)'
        ,'northstar_upload_claim_scrub()'
        ,'northstar_upload_finish_scrub(uuid,uuid,text)'
        ,'northstar_upload_claim_slot(uuid,bytea,int8,int8,int8)'
        ,'northstar_upload_capacity_reconciliation()'
        ,'northstar_upload_queue_snapshot()'
        ,'northstar_upload_policy_binding_matches(int8,int8,int8)'
        ,'northstar_upload_admit_expired_cleanup()'
        ,'northstar_upload_delete_owned(uuid,int8,bytea,uuid,uuid)'
        ,'northstar_upload_capability_catalog_healthy(text)'
    ] LOOP
        routine_oid:=pg_catalog.to_regprocedure(
            pg_catalog.format('%I.%s',migration_schema,routine_signature)
        );
        IF routine_oid IS NULL THEN
            RAISE EXCEPTION 'upload capability % is absent',routine_signature
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
            RAISE EXCEPTION 'upload capability % has unsafe owner/security/search_path',
                routine_signature USING ERRCODE='55000';
        END IF;
        IF EXISTS(
            SELECT 1 FROM pg_catalog.pg_proc routine
            CROSS JOIN LATERAL pg_catalog.aclexplode(
              COALESCE(routine.proacl,pg_catalog.acldefault('f',routine.proowner))
            ) privilege
             WHERE routine.oid=routine_oid AND privilege.grantee=0
               AND privilege.privilege_type='EXECUTE'
        ) THEN
            RAISE EXCEPTION 'PUBLIC can execute upload capability %',routine_signature
                USING ERRCODE='42501';
        END IF;
    END LOOP;
END;
$northstar_upload_capability_security$;

-- PUBLIC is never an application identity.  Runtime/backup grants are
-- reconciled by the deployment role manifest, which can name the concrete
-- login roles and is validated transactionally after migrations.
REVOKE ALL ON TABLE upload_storage_authority,
    upload_storage_capacity_ledger,upload_slots,upload_storage_jobs,upload_cleanup_queue
    FROM PUBLIC;
