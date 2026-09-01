-- Account deletion removes upload_slots through an FK cascade. The slot's
-- sole BEFORE DELETE trigger first materializes its exact storage cleanup
-- projection. Migration 0091 then converted cleanup debt to pending work in a
-- nested queue-capacity trigger and UPDATEd the same slot to clear its marker.
-- PostgreSQL rejects that self-update because the outer command is already
-- deleting the tuple (SQLSTATE 27000).
--
-- Give the delete trigger an explicit, immutable provenance bit. The bit is
-- accepted only while its INSERT is nested below another trigger and only
-- when the exact live slot owns reserved cleanup debt. Ledger conversion
-- remains one UPDATE in the queue INSERT transaction; only that explicitly
-- authenticated cascade path omits the redundant write to the disappearing
-- slot tuple. Ordinary application admission keeps the 0091 strict behavior.

ALTER TABLE upload_cleanup_queue
    ADD COLUMN slot_delete_projection pg_catalog.bool NOT NULL DEFAULT FALSE;

COMMENT ON COLUMN upload_cleanup_queue.slot_delete_projection IS
    'Immutable provenance: admitted only by the sole upload_slots BEFORE DELETE trigger';

-- `retained_*` is the logical ownership ledger: one unit follows an object
-- from its live slot through the last durable recovery projection.  It cannot
-- also describe physical recovery amplification.  One object may have up to
-- eight immutable failed-attempt stage jobs, and one cleanup tombstone may
-- name both a final object and a distinct stage.  Account those locators
-- independently and conservatively.  Double-counting a live slot and its
-- recovery projection is intentional; under-counting object-store bytes is
-- not permitted.
ALTER TABLE upload_storage_capacity_ledger
    ADD COLUMN recovery_retained_files pg_catalog.int8 NOT NULL DEFAULT 0
        CHECK(recovery_retained_files>=0),
    ADD COLUMN recovery_retained_bytes pg_catalog.int8 NOT NULL DEFAULT 0
        CHECK(recovery_retained_bytes>=0),
    ADD COLUMN configured_retained_files_limit pg_catalog.int8
        CHECK(configured_retained_files_limit BETWEEN 1000 AND 100000000),
    ADD COLUMN configured_retained_bytes_limit pg_catalog.int8
        CHECK(configured_retained_bytes_limit BETWEEN 1 AND 1125899906842624),
    ADD COLUMN recovery_overcommit_draining pg_catalog.bool NOT NULL DEFAULT FALSE;

-- Every durable storage job represents a possible retained object.  Older
-- `delete_object` rows were schema-permitted to omit their size, but such a
-- row cannot be accounted without guessing.  Fail the upgrade closed and
-- require an operator to repair the authoritative projection first.
DO $northstar_upload_recovery_size_precondition$
BEGIN
    IF EXISTS(SELECT 1 FROM upload_storage_jobs WHERE expected_size IS NULL) THEN
        RAISE EXCEPTION 'upload storage job has unknown recovery size; repair it before migration 0105'
            USING ERRCODE='55000';
    END IF;
END;
$northstar_upload_recovery_size_precondition$;

ALTER TABLE upload_storage_jobs ALTER COLUMN expected_size SET NOT NULL;

-- Backfill exact physical-recovery obligations before replacing the trigger
-- functions.  A cleanup row owns two units only when its stage locator is
-- distinguishable by key or exact version from its final-object locator.
UPDATE upload_storage_capacity_ledger
   SET recovery_retained_files=
           (SELECT pg_catalog.count(*) FROM upload_storage_jobs)+
           (SELECT COALESCE(pg_catalog.sum(
               CASE WHEN stage_key IS NULL
                          OR (stage_key=object_key
                              AND stage_version IS NOT DISTINCT FROM object_version)
                    THEN 1 ELSE 2 END),0)
              FROM upload_cleanup_queue),
       recovery_retained_bytes=
           (SELECT COALESCE(pg_catalog.sum(expected_size),0)
              FROM upload_storage_jobs)+
           (SELECT COALESCE(pg_catalog.sum(expected_size*
               CASE WHEN stage_key IS NULL
                          OR (stage_key=object_key
                              AND stage_version IS NOT DISTINCT FROM object_version)
                    THEN 1 ELSE 2 END),0)
              FROM upload_cleanup_queue),
       updated_at=pg_catalog.clock_timestamp()
 WHERE singleton;

-- A depth check is safe only while one reviewed application trigger can start
-- a slot deletion projection. Fail migration if another user trigger has
-- entered that boundary; internal FK triggers are deliberately excluded.
DO $northstar_upload_delete_trigger_precondition$
DECLARE
    migration_schema pg_catalog.text:=pg_catalog.current_schema();
    upload_slots_relation pg_catalog.oid;
    matching_triggers pg_catalog.int8;
    exact_trigger pg_catalog.bool;
    expected_trigger pg_catalog.record;
    exact_attachment pg_catalog.bool;
BEGIN
    IF migration_schema IS NULL
       OR migration_schema IN ('pg_catalog','information_schema')
       OR migration_schema LIKE 'pg_temp_%'
       OR migration_schema LIKE 'pg_toast_temp_%' THEN
        RAISE EXCEPTION 'unsafe migration schema for upload cascade capacity: %',
            migration_schema USING ERRCODE='3F000';
    END IF;
    SELECT pg_catalog.to_regclass(
               pg_catalog.format('%I.upload_slots',migration_schema)
           )::pg_catalog.oid
      INTO upload_slots_relation;
    IF upload_slots_relation IS NULL THEN
        RAISE EXCEPTION 'upload_slots is missing from migration schema %',migration_schema
            USING ERRCODE='42P01';
    END IF;
    SELECT pg_catalog.count(*),
           pg_catalog.bool_and(
               trigger_row.tgname='upload_storage_delete_queue'
               AND trigger_row.tgenabled IN ('O','A')
               AND trigger_row.tgqual IS NULL
               AND trigger_row.tgtype::pg_catalog.int4=11
               AND function_row.proname='queue_upload_storage_delete'
               AND function_schema.nspname=migration_schema
           )
      INTO matching_triggers,exact_trigger
      FROM pg_catalog.pg_trigger trigger_row
      JOIN pg_catalog.pg_proc function_row
        ON function_row.oid=trigger_row.tgfoid
      JOIN pg_catalog.pg_namespace function_schema
        ON function_schema.oid=function_row.pronamespace
     WHERE trigger_row.tgrelid=upload_slots_relation
       AND NOT trigger_row.tgisinternal
       AND (trigger_row.tgtype::pg_catalog.int4 & 1)=1
       AND (trigger_row.tgtype::pg_catalog.int4 & 2)=2
       AND (trigger_row.tgtype::pg_catalog.int4 & 8)=8;
    IF matching_triggers<>1 OR NOT COALESCE(exact_trigger,FALSE) THEN
        RAISE EXCEPTION 'upload_slots must have exactly one reviewed BEFORE DELETE row trigger'
            USING ERRCODE='55000';
    END IF;
    -- A disabled, replica-only, conditional, mistimed, or misattached ledger
    -- trigger is equivalent to no accounting trigger at all. Verify every
    -- projection edge before replacing any function body.
    FOR expected_trigger IN
        SELECT * FROM (VALUES
            ('upload_slots','upload_storage_delete_queue',
             'queue_upload_storage_delete',11),
            ('upload_slots','upload_slot_cleanup_debt_reserve',
             'reserve_upload_cleanup_debt',19),
            ('upload_slots','upload_slot_capacity_insert',
             'account_upload_slot_capacity',5),
            ('upload_slots','upload_slot_capacity_delete',
             'account_upload_slot_capacity',9),
            ('upload_storage_jobs','upload_job_capacity_insert',
             'account_upload_storage_job_capacity',5),
            ('upload_storage_jobs','upload_job_capacity_delete',
             'account_upload_storage_job_capacity',9),
            ('upload_cleanup_queue','upload_cleanup_capacity_insert',
             'account_upload_cleanup_capacity',5),
            ('upload_cleanup_queue','upload_cleanup_capacity_delete',
             'account_upload_cleanup_capacity',9),
            ('upload_storage_jobs','upload_storage_job_identity_guard',
             'protect_upload_storage_job_identity',19),
            ('upload_cleanup_queue','upload_cleanup_identity_guard',
             'protect_upload_cleanup_identity',19),
            ('upload_storage_capacity_ledger','upload_capacity_policy_guard',
             'protect_upload_capacity_policy',19)
        ) AS expected(
            relation_name,trigger_name,function_name,trigger_type
        )
    LOOP
        SELECT pg_catalog.count(*)=1 AND pg_catalog.bool_and(
                   NOT trigger_row.tgisinternal
                   AND trigger_row.tgenabled IN ('O','A')
                   AND trigger_row.tgqual IS NULL
                   AND trigger_row.tgtype::pg_catalog.int4=
                       expected_trigger.trigger_type
                   AND function_row.proname=expected_trigger.function_name
                   AND function_schema.nspname=migration_schema
                   AND function_row.pronargs=0
                   AND function_row.prorettype='pg_catalog.trigger'::pg_catalog.regtype
               )
          INTO exact_attachment
          FROM pg_catalog.pg_trigger trigger_row
          JOIN pg_catalog.pg_class relation_row
            ON relation_row.oid=trigger_row.tgrelid
          JOIN pg_catalog.pg_namespace relation_schema
            ON relation_schema.oid=relation_row.relnamespace
          JOIN pg_catalog.pg_proc function_row
            ON function_row.oid=trigger_row.tgfoid
          JOIN pg_catalog.pg_namespace function_schema
            ON function_schema.oid=function_row.pronamespace
         WHERE relation_schema.nspname=migration_schema
           AND relation_row.relname=expected_trigger.relation_name
           AND trigger_row.tgname=expected_trigger.trigger_name;
        IF NOT COALESCE(exact_attachment,FALSE) THEN
            RAISE EXCEPTION 'upload capacity trigger % is disabled, conditional, or misattached',
                expected_trigger.trigger_name USING ERRCODE='55000';
        END IF;
    END LOOP;
    -- Trigger depth and immutable-identity guards are safe only if each
    -- reviewed function OID has exactly one attachment in the complete
    -- installation schema. A second attachment to another compatible table
    -- must not acquire provenance merely by reusing the function.
    FOR expected_trigger IN
        SELECT * FROM (VALUES
            ('upload_slots','upload_storage_delete_queue',
             'queue_upload_storage_delete',11),
            ('upload_storage_jobs','upload_storage_job_identity_guard',
             'protect_upload_storage_job_identity',19),
            ('upload_cleanup_queue','upload_cleanup_identity_guard',
             'protect_upload_cleanup_identity',19),
            ('upload_storage_capacity_ledger','upload_capacity_policy_guard',
             'protect_upload_capacity_policy',19)
        ) AS expected(
            relation_name,trigger_name,function_name,trigger_type
        )
    LOOP
        SELECT pg_catalog.count(*),pg_catalog.bool_and(
                   relation_schema.nspname=migration_schema
                   AND relation_row.relname=expected_trigger.relation_name
                   AND trigger_row.tgname=expected_trigger.trigger_name
                   AND trigger_row.tgenabled IN ('O','A')
                   AND trigger_row.tgqual IS NULL
                   AND trigger_row.tgtype::pg_catalog.int4=
                       expected_trigger.trigger_type
               )
          INTO matching_triggers,exact_trigger
          FROM pg_catalog.pg_trigger trigger_row
          JOIN pg_catalog.pg_class relation_row
            ON relation_row.oid=trigger_row.tgrelid
          JOIN pg_catalog.pg_namespace relation_schema
            ON relation_schema.oid=relation_row.relnamespace
          JOIN pg_catalog.pg_proc function_row
            ON function_row.oid=trigger_row.tgfoid
          JOIN pg_catalog.pg_namespace function_schema
            ON function_schema.oid=function_row.pronamespace
         WHERE NOT trigger_row.tgisinternal
           AND function_schema.nspname=migration_schema
           AND function_row.proname=expected_trigger.function_name
           AND function_row.pronargs=0;
        IF matching_triggers<>1 OR NOT COALESCE(exact_trigger,FALSE) THEN
            RAISE EXCEPTION 'trigger function % must have one exact attachment in the installation schema',
                expected_trigger.function_name USING ERRCODE='55000';
        END IF;
    END LOOP;
    -- Capacity functions intentionally have two attachments each: one AFTER
    -- INSERT and one AFTER DELETE on their authoritative relation.  Merely
    -- proving that the two well-known trigger names exist is insufficient: an
    -- extra attachment of the same function OID would double-account a
    -- projection (or make every write fail a ledger CHECK).  Reject every
    -- additional attachment anywhere in the database before replacing these
    -- SECURITY DEFINER bodies.
    FOR expected_trigger IN
        SELECT * FROM (VALUES
            ('upload_slots','account_upload_slot_capacity',
             'upload_slot_capacity_insert','upload_slot_capacity_delete'),
            ('upload_storage_jobs','account_upload_storage_job_capacity',
             'upload_job_capacity_insert','upload_job_capacity_delete'),
            ('upload_cleanup_queue','account_upload_cleanup_capacity',
             'upload_cleanup_capacity_insert','upload_cleanup_capacity_delete')
        ) AS expected(
            relation_name,function_name,insert_trigger_name,delete_trigger_name
        )
    LOOP
        SELECT pg_catalog.count(*),
               pg_catalog.bool_and(
                   relation_schema.nspname=migration_schema
                   AND relation_row.relname=expected_trigger.relation_name
                   AND trigger_row.tgenabled IN ('O','A')
                   AND trigger_row.tgqual IS NULL
                   AND ((trigger_row.tgname=expected_trigger.insert_trigger_name
                         AND trigger_row.tgtype::pg_catalog.int4=5)
                        OR
                        (trigger_row.tgname=expected_trigger.delete_trigger_name
                         AND trigger_row.tgtype::pg_catalog.int4=9))
               )
               AND pg_catalog.count(*) FILTER(
                   WHERE trigger_row.tgname=expected_trigger.insert_trigger_name
                     AND trigger_row.tgtype::pg_catalog.int4=5)=1
               AND pg_catalog.count(*) FILTER(
                   WHERE trigger_row.tgname=expected_trigger.delete_trigger_name
                     AND trigger_row.tgtype::pg_catalog.int4=9)=1
          INTO matching_triggers,exact_trigger
          FROM pg_catalog.pg_trigger trigger_row
          JOIN pg_catalog.pg_class relation_row
            ON relation_row.oid=trigger_row.tgrelid
          JOIN pg_catalog.pg_namespace relation_schema
            ON relation_schema.oid=relation_row.relnamespace
          JOIN pg_catalog.pg_proc function_row
            ON function_row.oid=trigger_row.tgfoid
          JOIN pg_catalog.pg_namespace function_schema
            ON function_schema.oid=function_row.pronamespace
         WHERE NOT trigger_row.tgisinternal
           AND function_schema.nspname=migration_schema
           AND function_row.proname=expected_trigger.function_name
           AND function_row.pronargs=0;
        IF matching_triggers<>2 OR NOT COALESCE(exact_trigger,FALSE) THEN
            RAISE EXCEPTION 'capacity trigger function % must have exactly one INSERT and one DELETE attachment',
                expected_trigger.function_name USING ERRCODE='55000';
        END IF;
    END LOOP;
END;
$northstar_upload_delete_trigger_precondition$;

CREATE OR REPLACE FUNCTION queue_upload_storage_delete()
RETURNS pg_catalog.TRIGGER AS $$
DECLARE inserted_count pg_catalog.int8:=0;
BEGIN
    -- Empty reservations own no external object. Cascading account deletion
    -- removes only their metadata and must not invent a storage locator.
    IF OLD.storage_object_key IS NULL AND OLD.storage_stage_key IS NULL
       AND NOT OLD.uploaded THEN
        RETURN OLD;
    END IF;
    -- One cleanup tombstone owns both locators. This is required for migrated
    -- pre-0091 writers: the old writer may have materialized the bare-UUID
    -- final object before setting `uploaded`, while its distinct staging path
    -- can also still exist. A delete-stage-only projection would leak the
    -- possible final object. Current local writers are safe because deletion
    -- of an as-yet absent final key is idempotent; S3 uses one attempt key and
    -- retains its delayed two-observation absence fence.
    INSERT INTO upload_cleanup_queue(
        object_id,storage_backend,object_key,object_version,
        stage_key,stage_version,storage_attempt,expected_size,expected_sha256,
        storage_fence,available_at,slot_delete_projection
    ) VALUES(
        OLD.id,OLD.storage_backend,COALESCE(OLD.storage_object_key,OLD.id::text),
        CASE WHEN OLD.storage_backend='s3'
                       AND OLD.storage_stage_key=OLD.storage_object_key
             THEN COALESCE(OLD.storage_object_version,OLD.storage_stage_version)
             ELSE OLD.storage_object_version END,
        OLD.storage_stage_key,OLD.storage_stage_version,
        OLD.storage_attempt,COALESCE(OLD.storage_size,OLD.size),OLD.storage_sha256,
        OLD.storage_fence,
        CASE WHEN OLD.storage_state='writing'
             THEN clock_timestamp()+INTERVAL '16 minutes'
             ELSE clock_timestamp() END,
        TRUE
    ) ON CONFLICT(object_id) DO NOTHING;
    GET DIAGNOSTICS inserted_count=ROW_COUNT;
    IF inserted_count=0 THEN
        IF OLD.storage_cleanup_debt_reserved THEN
            RAISE EXCEPTION 'upload cleanup projection conflicts with reserved cleanup debt'
                USING ERRCODE='55000';
        END IF;
        IF NOT EXISTS(
            SELECT 1 FROM upload_cleanup_queue queue
             WHERE queue.object_id=OLD.id
               AND queue.storage_backend=OLD.storage_backend
               AND queue.object_key=COALESCE(OLD.storage_object_key,OLD.id::text)
               AND queue.object_version IS NOT DISTINCT FROM
                   CASE WHEN OLD.storage_backend='s3'
                                  AND OLD.storage_stage_key=OLD.storage_object_key
                        THEN COALESCE(OLD.storage_object_version,OLD.storage_stage_version)
                        ELSE OLD.storage_object_version END
               AND queue.stage_key IS NOT DISTINCT FROM OLD.storage_stage_key
               AND queue.stage_version IS NOT DISTINCT FROM OLD.storage_stage_version
               AND queue.storage_attempt IS NOT DISTINCT FROM OLD.storage_attempt
               AND queue.expected_size=COALESCE(OLD.storage_size,OLD.size)
               AND queue.expected_sha256 IS NOT DISTINCT FROM OLD.storage_sha256
               AND queue.storage_fence=OLD.storage_fence
        ) THEN
            RAISE EXCEPTION 'existing upload cleanup projection has different identity'
                USING ERRCODE='55000';
        END IF;
    END IF;
    RETURN OLD;
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION protect_upload_storage_job_identity()
RETURNS pg_catalog.TRIGGER AS $$
BEGIN
    IF NEW.object_id IS DISTINCT FROM OLD.object_id
       OR NEW.storage_attempt IS DISTINCT FROM OLD.storage_attempt
       OR NEW.action IS DISTINCT FROM OLD.action
       OR NEW.storage_backend IS DISTINCT FROM OLD.storage_backend
       OR NEW.stage_key IS DISTINCT FROM OLD.stage_key
       OR NEW.stage_version IS DISTINCT FROM OLD.stage_version
       OR NEW.object_key IS DISTINCT FROM OLD.object_key
       OR NEW.object_version IS DISTINCT FROM OLD.object_version
       OR NEW.expected_size IS DISTINCT FROM OLD.expected_size
       OR NEW.expected_sha256 IS DISTINCT FROM OLD.expected_sha256
       OR NEW.storage_fence IS DISTINCT FROM OLD.storage_fence
       OR NEW.created_at IS DISTINCT FROM OLD.created_at THEN
        RAISE EXCEPTION 'upload storage job identity is immutable' USING ERRCODE='55000';
    END IF;
    NEW.updated_at:=clock_timestamp();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION protect_upload_cleanup_identity()
RETURNS pg_catalog.TRIGGER AS $$
BEGIN
    IF NEW.object_id IS DISTINCT FROM OLD.object_id
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
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION account_upload_slot_capacity()
RETURNS pg_catalog.TRIGGER AS $$
DECLARE
    policy_bound pg_catalog.bool:=FALSE;
BEGIN
    SELECT configured_pending_limit IS NOT NULL
           AND configured_retained_files_limit IS NOT NULL
           AND configured_retained_bytes_limit IS NOT NULL
      INTO policy_bound
      FROM upload_storage_capacity_ledger WHERE singleton FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'upload storage capacity authority is missing'
            USING ERRCODE='55000';
    END IF;
    IF TG_OP='INSERT' THEN
        IF NOT policy_bound THEN
            RAISE EXCEPTION 'upload storage capacity policy is not fully bound'
                USING ERRCODE='55000';
        END IF;
        IF EXISTS(SELECT 1 FROM upload_cleanup_queue WHERE object_id=NEW.id)
           OR EXISTS(SELECT 1 FROM upload_storage_jobs WHERE object_id=NEW.id) THEN
            IF EXISTS(SELECT 1 FROM upload_cleanup_queue
                       WHERE object_id=NEW.id AND expected_size<>NEW.size)
               OR EXISTS(SELECT 1 FROM upload_storage_jobs
                          WHERE object_id=NEW.id
                            AND expected_size IS DISTINCT FROM NEW.size) THEN
                RAISE EXCEPTION 'upload slot size conflicts with retained projection authority'
                    USING ERRCODE='55000';
            END IF;
            UPDATE upload_storage_capacity_ledger
               SET updated_at=pg_catalog.clock_timestamp() WHERE singleton;
        ELSE
            UPDATE upload_storage_capacity_ledger SET retained_files=retained_files+1,
                retained_bytes=retained_bytes+NEW.size,
                recovery_overcommit_draining=(
                    configured_retained_files_limit IS NOT NULL
                    AND configured_retained_bytes_limit IS NOT NULL
                    AND (retained_files+1+recovery_retained_files>
                            configured_retained_files_limit
                         OR retained_bytes+NEW.size+recovery_retained_bytes>
                            configured_retained_bytes_limit)),
                updated_at=pg_catalog.clock_timestamp() WHERE singleton;
        END IF;
        RETURN NEW;
    END IF;
    -- A slot owns exactly one retained-file unit. Keep that unit while any
    -- durable recovery projection for the object survives; the last projection
    -- deletion releases it. Checking every storage-job action avoids the old
    -- delete_stage-only accounting hole.
    IF EXISTS(SELECT 1 FROM upload_cleanup_queue WHERE object_id=OLD.id)
       OR EXISTS(SELECT 1 FROM upload_storage_jobs WHERE object_id=OLD.id) THEN
        UPDATE upload_storage_capacity_ledger
           SET updated_at=pg_catalog.clock_timestamp() WHERE singleton;
    ELSE
        UPDATE upload_storage_capacity_ledger SET retained_files=retained_files-1,
            retained_bytes=retained_bytes-OLD.size,
            recovery_overcommit_draining=(
                configured_retained_files_limit IS NOT NULL
                AND configured_retained_bytes_limit IS NOT NULL
                AND (retained_files-1+recovery_retained_files>
                        configured_retained_files_limit
                     OR retained_bytes-OLD.size+recovery_retained_bytes>
                        configured_retained_bytes_limit)),
            updated_at=pg_catalog.clock_timestamp() WHERE singleton;
    END IF;
    RETURN OLD;
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION account_upload_storage_job_capacity()
RETURNS pg_catalog.TRIGGER AS $$
DECLARE
    converts_debt pg_catalog.bool:=FALSE;
    acquires_retained pg_catalog.bool:=FALSE;
    releases_retained pg_catalog.bool:=FALSE;
    policy_bound pg_catalog.bool:=FALSE;
BEGIN
    SELECT configured_pending_limit IS NOT NULL
           AND configured_retained_files_limit IS NOT NULL
           AND configured_retained_bytes_limit IS NOT NULL
      INTO policy_bound
      FROM upload_storage_capacity_ledger WHERE singleton FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'upload storage capacity authority is missing'
            USING ERRCODE='55000';
    END IF;
    IF TG_OP='INSERT' THEN
        IF NOT policy_bound THEN
            RAISE EXCEPTION 'upload storage capacity policy is not fully bound'
                USING ERRCODE='55000';
        END IF;
        IF EXISTS(SELECT 1 FROM upload_slots
                   WHERE id=NEW.object_id AND size<>NEW.expected_size)
           OR EXISTS(SELECT 1 FROM upload_cleanup_queue
                      WHERE object_id=NEW.object_id
                        AND expected_size<>NEW.expected_size)
           OR EXISTS(SELECT 1 FROM upload_storage_jobs
                      WHERE object_id=NEW.object_id AND id<>NEW.id
                        AND expected_size<>NEW.expected_size) THEN
            RAISE EXCEPTION 'upload storage projection size conflicts with object authority'
                USING ERRCODE='55000';
        END IF;
        IF NEW.action='delete_stage' THEN
            SELECT EXISTS(SELECT 1 FROM upload_slots WHERE id=NEW.object_id
                AND storage_state='writing' AND storage_cleanup_debt_reserved
                AND storage_backend=NEW.storage_backend
                AND storage_attempt=NEW.storage_attempt
                AND storage_fence=NEW.storage_fence
                AND storage_stage_key=NEW.stage_key
                AND storage_stage_version IS NOT DISTINCT FROM NEW.stage_version
                AND COALESCE(storage_size,size)=NEW.expected_size)
              INTO converts_debt;
        END IF;
        SELECT NOT EXISTS(SELECT 1 FROM upload_slots WHERE id=NEW.object_id)
           AND NOT EXISTS(SELECT 1 FROM upload_cleanup_queue
                           WHERE object_id=NEW.object_id)
           AND NOT EXISTS(SELECT 1 FROM upload_storage_jobs
                           WHERE object_id=NEW.object_id AND id<>NEW.id)
          INTO acquires_retained;
        IF acquires_retained AND NEW.expected_size IS NULL THEN
            RAISE EXCEPTION 'first orphan upload storage projection has unknown retained size'
                USING ERRCODE='55000';
        END IF;
        UPDATE upload_storage_capacity_ledger SET pending_jobs=pending_jobs+1,
            cleanup_obligation_debt=cleanup_obligation_debt-
                CASE WHEN converts_debt THEN 1 ELSE 0 END,
            storage_jobs_pending=storage_jobs_pending+1,
            retained_files=retained_files+CASE WHEN acquires_retained THEN 1 ELSE 0 END,
            retained_bytes=retained_bytes+CASE WHEN acquires_retained
                THEN NEW.expected_size ELSE 0 END,
            recovery_retained_files=recovery_retained_files+1,
            recovery_retained_bytes=recovery_retained_bytes+NEW.expected_size,
            recovery_overcommit_draining=(
                configured_retained_files_limit IS NOT NULL
                AND configured_retained_bytes_limit IS NOT NULL
                AND (
                    retained_files+CASE WHEN acquires_retained THEN 1 ELSE 0 END+
                        recovery_retained_files+1>configured_retained_files_limit
                    OR retained_bytes+CASE WHEN acquires_retained
                           THEN NEW.expected_size ELSE 0 END+
                        recovery_retained_bytes+NEW.expected_size>
                            configured_retained_bytes_limit
                )),
            updated_at=pg_catalog.clock_timestamp() WHERE singleton
              AND cleanup_obligation_debt>=CASE WHEN converts_debt THEN 1 ELSE 0 END
              AND (converts_debt OR (
                  pending_jobs+cleanup_obligation_debt+1<=configured_pending_limit
                  AND pending_jobs+cleanup_obligation_debt+1<=absolute_disaster_limit));
        IF NOT FOUND THEN
            RAISE EXCEPTION 'upload recovery queue hard limit reached' USING ERRCODE='53300';
        END IF;
        IF converts_debt THEN
            UPDATE upload_slots SET storage_cleanup_debt_reserved=FALSE
             WHERE id=NEW.object_id AND storage_cleanup_debt_reserved
               AND storage_state='writing'
               AND storage_backend=NEW.storage_backend
               AND storage_attempt=NEW.storage_attempt
               AND storage_fence=NEW.storage_fence
               AND storage_stage_key=NEW.stage_key
               AND storage_stage_version IS NOT DISTINCT FROM NEW.stage_version
               AND COALESCE(storage_size,size)=NEW.expected_size;
            IF NOT FOUND THEN
                RAISE EXCEPTION 'upload cleanup debt authority changed during job admission'
                    USING ERRCODE='40001';
            END IF;
        END IF;
        RETURN NEW;
    ELSE
        -- AFTER DELETE no longer sees OLD in upload_storage_jobs. Release the
        -- slot's single retained unit only when this was the last projection
        -- for an already-removed slot, regardless of completion order.
        SELECT NOT EXISTS(SELECT 1 FROM upload_slots WHERE id=OLD.object_id)
           AND NOT EXISTS(SELECT 1 FROM upload_cleanup_queue
                           WHERE object_id=OLD.object_id)
           AND NOT EXISTS(SELECT 1 FROM upload_storage_jobs
                           WHERE object_id=OLD.object_id)
          INTO releases_retained;
        IF releases_retained AND OLD.expected_size IS NULL THEN
            RAISE EXCEPTION 'last upload storage projection has unknown retained size'
                USING ERRCODE='55000';
        END IF;
        UPDATE upload_storage_capacity_ledger SET pending_jobs=pending_jobs-1,
            storage_jobs_pending=storage_jobs_pending-1,
            legacy_overcommit_draining=(pending_jobs-1+cleanup_obligation_debt>
                LEAST(COALESCE(configured_pending_limit,absolute_disaster_limit),
                      absolute_disaster_limit)),
            retained_files=retained_files-CASE WHEN releases_retained THEN 1 ELSE 0 END,
            retained_bytes=retained_bytes-CASE WHEN releases_retained
                THEN OLD.expected_size ELSE 0 END,
            recovery_retained_files=recovery_retained_files-1,
            recovery_retained_bytes=recovery_retained_bytes-OLD.expected_size,
            recovery_overcommit_draining=(
                configured_retained_files_limit IS NOT NULL
                AND configured_retained_bytes_limit IS NOT NULL
                AND (
                    retained_files-CASE WHEN releases_retained THEN 1 ELSE 0 END+
                        recovery_retained_files-1>configured_retained_files_limit
                    OR retained_bytes-CASE WHEN releases_retained
                           THEN OLD.expected_size ELSE 0 END+
                        recovery_retained_bytes-OLD.expected_size>
                            configured_retained_bytes_limit
                )),
            updated_at=pg_catalog.clock_timestamp() WHERE singleton;
        -- A retry can persist the cleanup projection and then refuse a new
        -- writer because the now-truthful physical ledger is over its bound.
        -- If the worker completes that exact stage deletion while the slot is
        -- still parked on the expired writing attempt, hand ownership back to
        -- cleanup debt.  The existing reserve trigger performs the increment
        -- under the already-held ledger lock; a later retry must atomically
        -- convert it into a fresh idempotent deletion projection before it can
        -- replace the locator.
        IF OLD.action='delete_stage' THEN
            UPDATE upload_slots SET storage_cleanup_debt_reserved=FALSE
             WHERE id=OLD.object_id AND storage_state='writing'
               AND NOT storage_cleanup_debt_reserved
               AND storage_backend=OLD.storage_backend
               AND storage_attempt=OLD.storage_attempt
               AND storage_fence=OLD.storage_fence
               AND storage_stage_key=OLD.stage_key
               AND storage_stage_version IS NOT DISTINCT FROM OLD.stage_version
               AND COALESCE(storage_size,size)=OLD.expected_size;
        END IF;
        RETURN OLD;
    END IF;
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION account_upload_cleanup_capacity()
RETURNS pg_catalog.TRIGGER AS $$
DECLARE
    converts_debt pg_catalog.bool:=FALSE;
    acquires_retained pg_catalog.bool:=FALSE;
    releases_retained pg_catalog.bool:=FALSE;
    locator_units pg_catalog.int8:=1;
    policy_bound pg_catalog.bool:=FALSE;
BEGIN
    SELECT configured_pending_limit IS NOT NULL
           AND configured_retained_files_limit IS NOT NULL
           AND configured_retained_bytes_limit IS NOT NULL
      INTO policy_bound
      FROM upload_storage_capacity_ledger WHERE singleton FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'upload storage capacity authority is missing'
            USING ERRCODE='55000';
    END IF;
    IF TG_OP='INSERT' THEN
        IF NOT policy_bound THEN
            RAISE EXCEPTION 'upload storage capacity policy is not fully bound'
                USING ERRCODE='55000';
        END IF;
        locator_units:=CASE WHEN NEW.stage_key IS NULL
                              OR (NEW.stage_key=NEW.object_key
                                  AND NEW.stage_version IS NOT DISTINCT FROM NEW.object_version)
                            THEN 1 ELSE 2 END;
        IF EXISTS(SELECT 1 FROM upload_slots
                   WHERE id=NEW.object_id AND size<>NEW.expected_size)
           OR EXISTS(SELECT 1 FROM upload_storage_jobs
                      WHERE object_id=NEW.object_id
                        AND expected_size<>NEW.expected_size) THEN
            RAISE EXCEPTION 'upload cleanup projection size conflicts with object authority'
                USING ERRCODE='55000';
        END IF;
        SELECT EXISTS(SELECT 1 FROM upload_slots WHERE id=NEW.object_id
            AND storage_cleanup_debt_reserved
            AND storage_state IN ('writing','staged','promoting','committed','legacy_committed','deleting')
            AND storage_backend=NEW.storage_backend
            AND storage_object_key=NEW.object_key
            AND (CASE WHEN storage_backend='s3'
                                AND storage_stage_key=storage_object_key
                      THEN COALESCE(storage_object_version,storage_stage_version)
                      ELSE storage_object_version END)
                    IS NOT DISTINCT FROM NEW.object_version
            AND storage_stage_key IS NOT DISTINCT FROM NEW.stage_key
            AND storage_stage_version IS NOT DISTINCT FROM NEW.stage_version
            AND storage_attempt IS NOT DISTINCT FROM NEW.storage_attempt
            AND storage_fence=NEW.storage_fence
            AND COALESCE(storage_size,size)=NEW.expected_size
            AND storage_sha256 IS NOT DISTINCT FROM NEW.expected_sha256)
          INTO converts_debt;
        SELECT NOT EXISTS(SELECT 1 FROM upload_slots WHERE id=NEW.object_id)
           AND NOT EXISTS(SELECT 1 FROM upload_storage_jobs
                           WHERE object_id=NEW.object_id)
          INTO acquires_retained;
        IF NEW.slot_delete_projection THEN
            IF pg_catalog.pg_trigger_depth()<=1 THEN
                RAISE EXCEPTION 'slot-delete upload cleanup provenance requires nested trigger admission'
                    USING ERRCODE='42501';
            END IF;
            IF NOT converts_debt THEN
                RAISE EXCEPTION 'slot-delete upload cleanup lacks exact reserved cleanup debt'
                    USING ERRCODE='55000';
            END IF;
        END IF;
        UPDATE upload_storage_capacity_ledger SET pending_jobs=pending_jobs+1,
            cleanup_obligation_debt=cleanup_obligation_debt-
                CASE WHEN converts_debt THEN 1 ELSE 0 END,
            cleanup_jobs_pending=cleanup_jobs_pending+1,
            retained_files=retained_files+CASE WHEN acquires_retained THEN 1 ELSE 0 END,
            retained_bytes=retained_bytes+CASE WHEN acquires_retained
                THEN NEW.expected_size ELSE 0 END,
            recovery_retained_files=recovery_retained_files+locator_units,
            recovery_retained_bytes=recovery_retained_bytes+
                locator_units*NEW.expected_size,
            recovery_overcommit_draining=(
                configured_retained_files_limit IS NOT NULL
                AND configured_retained_bytes_limit IS NOT NULL
                AND (
                    retained_files+CASE WHEN acquires_retained THEN 1 ELSE 0 END+
                        recovery_retained_files+locator_units>
                            configured_retained_files_limit
                    OR retained_bytes+CASE WHEN acquires_retained
                           THEN NEW.expected_size ELSE 0 END+
                        recovery_retained_bytes+locator_units*NEW.expected_size>
                            configured_retained_bytes_limit
                )),
            updated_at=pg_catalog.clock_timestamp() WHERE singleton
              AND cleanup_obligation_debt>=CASE WHEN converts_debt THEN 1 ELSE 0 END
              AND (converts_debt OR (
                  pending_jobs+cleanup_obligation_debt+1<=configured_pending_limit
                  AND pending_jobs+cleanup_obligation_debt+1<=absolute_disaster_limit));
        IF NOT FOUND THEN
            RAISE EXCEPTION 'upload recovery queue hard limit reached' USING ERRCODE='53300';
        END IF;
        IF converts_debt AND NOT NEW.slot_delete_projection THEN
            UPDATE upload_slots SET storage_cleanup_debt_reserved=FALSE
             WHERE id=NEW.object_id AND storage_cleanup_debt_reserved
               AND storage_state IN ('writing','staged','promoting','committed','legacy_committed','deleting')
               AND storage_backend=NEW.storage_backend
               AND storage_object_key=NEW.object_key
               AND (CASE WHEN storage_backend='s3'
                                   AND storage_stage_key=storage_object_key
                         THEN COALESCE(storage_object_version,storage_stage_version)
                         ELSE storage_object_version END)
                       IS NOT DISTINCT FROM NEW.object_version
               AND storage_stage_key IS NOT DISTINCT FROM NEW.stage_key
               AND storage_stage_version IS NOT DISTINCT FROM NEW.stage_version
               AND storage_attempt IS NOT DISTINCT FROM NEW.storage_attempt
               AND storage_fence=NEW.storage_fence
               AND COALESCE(storage_size,size)=NEW.expected_size
               AND storage_sha256 IS NOT DISTINCT FROM NEW.expected_sha256;
            IF NOT FOUND THEN
                RAISE EXCEPTION 'upload cleanup debt authority changed during cleanup admission'
                    USING ERRCODE='40001';
            END IF;
        END IF;
        RETURN NEW;
    ELSE
        locator_units:=CASE WHEN OLD.stage_key IS NULL
                              OR (OLD.stage_key=OLD.object_key
                                  AND OLD.stage_version IS NOT DISTINCT FROM OLD.object_version)
                            THEN 1 ELSE 2 END;
        SELECT NOT EXISTS(SELECT 1 FROM upload_slots WHERE id=OLD.object_id)
           AND NOT EXISTS(SELECT 1 FROM upload_cleanup_queue
                           WHERE object_id=OLD.object_id)
           AND NOT EXISTS(SELECT 1 FROM upload_storage_jobs
                           WHERE object_id=OLD.object_id)
          INTO releases_retained;
        UPDATE upload_storage_capacity_ledger SET pending_jobs=pending_jobs-1,
            cleanup_jobs_pending=cleanup_jobs_pending-1,
            legacy_overcommit_draining=(pending_jobs-1+cleanup_obligation_debt>
                LEAST(COALESCE(configured_pending_limit,absolute_disaster_limit),
                      absolute_disaster_limit)),
            retained_files=retained_files-CASE WHEN releases_retained THEN 1 ELSE 0 END,
            retained_bytes=retained_bytes-CASE WHEN releases_retained
                THEN OLD.expected_size ELSE 0 END,
            recovery_retained_files=recovery_retained_files-locator_units,
            recovery_retained_bytes=recovery_retained_bytes-
                locator_units*OLD.expected_size,
            recovery_overcommit_draining=(
                configured_retained_files_limit IS NOT NULL
                AND configured_retained_bytes_limit IS NOT NULL
                AND (
                    retained_files-CASE WHEN releases_retained THEN 1 ELSE 0 END+
                        recovery_retained_files-locator_units>
                            configured_retained_files_limit
                    OR retained_bytes-CASE WHEN releases_retained
                           THEN OLD.expected_size ELSE 0 END+
                        recovery_retained_bytes-locator_units*OLD.expected_size>
                            configured_retained_bytes_limit
                )),
            updated_at=pg_catalog.clock_timestamp() WHERE singleton;
        RETURN OLD;
    END IF;
END;
$$ LANGUAGE plpgsql;

-- A pending-job ceiling alone is no longer a complete capacity authority.
-- Keep the old signature as an explicit fail-closed rolling-upgrade barrier;
-- every process built for schema 0105 must bind all three durable limits.
CREATE OR REPLACE FUNCTION bind_upload_storage_capacity_policy(
    requested_limit pg_catalog.int8
) RETURNS pg_catalog.void AS $$
BEGIN
    RAISE EXCEPTION 'upload retained-file and retained-byte limits must also be bound'
        USING ERRCODE='55000';
END;
$$ LANGUAGE plpgsql;

CREATE FUNCTION bind_upload_storage_capacity_policy(
    requested_pending_limit pg_catalog.int8,
    requested_retained_files_limit pg_catalog.int8,
    requested_retained_bytes_limit pg_catalog.int8
) RETURNS pg_catalog.void AS $$
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
    SELECT configured_pending_limit,configured_retained_files_limit,
           configured_retained_bytes_limit
      INTO current_pending_limit,current_retained_files_limit,
           current_retained_bytes_limit
      FROM upload_storage_capacity_ledger WHERE singleton FOR UPDATE;
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
     WHERE singleton;
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION protect_upload_capacity_policy()
RETURNS pg_catalog.TRIGGER AS $$
BEGIN
    IF (OLD.configured_pending_limit IS NOT NULL
            AND NEW.configured_pending_limit IS DISTINCT FROM OLD.configured_pending_limit)
       OR (OLD.configured_retained_files_limit IS NOT NULL
            AND NEW.configured_retained_files_limit IS DISTINCT FROM
                OLD.configured_retained_files_limit)
       OR (OLD.configured_retained_bytes_limit IS NOT NULL
            AND NEW.configured_retained_bytes_limit IS DISTINCT FROM
                OLD.configured_retained_bytes_limit)
       OR NEW.absolute_disaster_limit IS DISTINCT FROM OLD.absolute_disaster_limit
       OR NEW.recovery_reserve_percent IS DISTINCT FROM OLD.recovery_reserve_percent
       OR NEW.policy_generation IS DISTINCT FROM OLD.policy_generation THEN
        RAISE EXCEPTION 'upload capacity policy is immutable; use an offline migration'
            USING ERRCODE='55000';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- CREATE OR REPLACE defaults to invoker authority. Restore the two reviewed
-- capacity routines to SECURITY DEFINER, keep all other upload trigger routines at
-- invoker authority, and bind every replacement to the exact installation
-- schema before the migration can commit.
DO $northstar_upload_cascade_capacity_paths$
DECLARE
    migration_schema pg_catalog.text:=pg_catalog.current_schema();
    expected_path pg_catalog.text;
    postconditions pg_catalog.bool;
    relation_postconditions pg_catalog.bool;
    trigger_postconditions pg_catalog.bool;
    routine_name pg_catalog.text;
BEGIN
    IF migration_schema IS NULL
       OR migration_schema IN ('pg_catalog','information_schema')
       OR migration_schema LIKE 'pg_temp_%'
       OR migration_schema LIKE 'pg_toast_temp_%' THEN
        RAISE EXCEPTION 'unsafe migration schema for upload capacity functions: %',
            migration_schema USING ERRCODE='3F000';
    END IF;
    FOR routine_name IN
        SELECT pg_catalog.unnest(ARRAY[
            'queue_upload_storage_delete',
            'protect_upload_storage_job_identity',
            'protect_upload_cleanup_identity',
            'account_upload_slot_capacity',
            'reserve_upload_cleanup_debt',
            'protect_upload_capacity_policy'
        ]::pg_catalog.text[])
    LOOP
        EXECUTE pg_catalog.format(
            'ALTER FUNCTION %I.%I() RESET ALL',migration_schema,routine_name
        );
        EXECUTE pg_catalog.format(
            'ALTER FUNCTION %I.%I() SECURITY INVOKER',migration_schema,routine_name
        );
        EXECUTE pg_catalog.format(
            'ALTER FUNCTION %I.%I() SET search_path TO pg_catalog, %I, pg_temp',
            migration_schema,routine_name,migration_schema
        );
        EXECUTE pg_catalog.format(
            'REVOKE ALL ON FUNCTION %I.%I() FROM PUBLIC',
            migration_schema,routine_name
        );
    END LOOP;
    FOR routine_name IN
        SELECT pg_catalog.unnest(ARRAY[
            'account_upload_storage_job_capacity',
            'account_upload_cleanup_capacity'
        ]::pg_catalog.text[])
    LOOP
        EXECUTE pg_catalog.format(
            'ALTER FUNCTION %I.%I() RESET ALL',migration_schema,routine_name
        );
        EXECUTE pg_catalog.format(
            'ALTER FUNCTION %I.%I() SECURITY DEFINER',migration_schema,routine_name
        );
        EXECUTE pg_catalog.format(
            'ALTER FUNCTION %I.%I() SET search_path TO pg_catalog, %I, pg_temp',
            migration_schema,routine_name,migration_schema
        );
        EXECUTE pg_catalog.format(
            'REVOKE ALL ON FUNCTION %I.%I() FROM PUBLIC',
            migration_schema,routine_name
        );
    END LOOP;
    expected_path:=pg_catalog.format(
        'search_path=pg_catalog, %I, pg_temp',migration_schema
    );
    SELECT pg_catalog.count(*)=8
       AND pg_catalog.bool_and(
               proc_row.prosecdef=(proc_row.proname IN (
                   'account_upload_storage_job_capacity',
                   'account_upload_cleanup_capacity'
               )))
       AND pg_catalog.bool_and(proc_row.proowner=(
               SELECT role_row.oid
                 FROM pg_catalog.pg_roles role_row
                WHERE role_row.rolname=CURRENT_USER
           ))
       AND pg_catalog.bool_and(
               COALESCE(proc_row.proconfig,ARRAY[]::pg_catalog.text[])=
               ARRAY[expected_path]::pg_catalog.text[])
       AND pg_catalog.bool_and(NOT EXISTS(
               SELECT 1
                 FROM pg_catalog.aclexplode(COALESCE(
                     proc_row.proacl,
                     pg_catalog.acldefault('f',proc_row.proowner)
                 )) privilege
                WHERE privilege.grantee=0
                  AND privilege.privilege_type='EXECUTE'
           ))
      INTO postconditions
      FROM pg_catalog.pg_proc proc_row
      JOIN pg_catalog.pg_namespace proc_namespace
        ON proc_namespace.oid=proc_row.pronamespace
     WHERE proc_namespace.nspname=migration_schema
       AND proc_row.proname IN (
            'queue_upload_storage_delete',
            'protect_upload_storage_job_identity',
             'protect_upload_cleanup_identity',
             'account_upload_slot_capacity',
             'reserve_upload_cleanup_debt',
             'protect_upload_capacity_policy',
            'account_upload_storage_job_capacity',
           'account_upload_cleanup_capacity'
       )
       AND pg_catalog.pg_get_function_identity_arguments(proc_row.oid)='';

    SELECT pg_catalog.count(*)=4
       AND pg_catalog.bool_and(relation_row.relowner=(
               SELECT role_row.oid
                 FROM pg_catalog.pg_roles role_row
                WHERE role_row.rolname=CURRENT_USER
           ))
      INTO relation_postconditions
      FROM pg_catalog.pg_class relation_row
      JOIN pg_catalog.pg_namespace relation_schema
        ON relation_schema.oid=relation_row.relnamespace
     WHERE relation_schema.nspname=migration_schema
       AND relation_row.relkind IN ('r','p')
       AND relation_row.relname IN (
           'upload_slots','upload_storage_jobs','upload_cleanup_queue',
           'upload_storage_capacity_ledger'
       );

    SELECT pg_catalog.count(*)=11
       AND pg_catalog.bool_and(
               NOT trigger_row.tgisinternal
               AND trigger_row.tgenabled IN ('O','A')
               AND trigger_row.tgqual IS NULL
               AND trigger_row.tgtype::pg_catalog.int4=expected.trigger_type
               AND function_row.proname=expected.function_name
               AND function_schema.nspname=migration_schema
               AND function_row.pronargs=0
               AND function_row.prorettype=
                   'pg_catalog.trigger'::pg_catalog.regtype
               AND (
                   SELECT pg_catalog.count(*)
                     FROM pg_catalog.pg_trigger attachment
                    WHERE attachment.tgfoid=function_row.oid
                      AND NOT attachment.tgisinternal
               )=expected.attachment_count
           )
      INTO trigger_postconditions
      FROM (VALUES
          ('upload_slots','upload_storage_delete_queue',
           'queue_upload_storage_delete',11,1),
          ('upload_slots','upload_slot_cleanup_debt_reserve',
           'reserve_upload_cleanup_debt',19,1),
          ('upload_slots','upload_slot_capacity_insert',
           'account_upload_slot_capacity',5,2),
          ('upload_slots','upload_slot_capacity_delete',
           'account_upload_slot_capacity',9,2),
          ('upload_storage_jobs','upload_job_capacity_insert',
           'account_upload_storage_job_capacity',5,2),
          ('upload_storage_jobs','upload_job_capacity_delete',
           'account_upload_storage_job_capacity',9,2),
          ('upload_cleanup_queue','upload_cleanup_capacity_insert',
           'account_upload_cleanup_capacity',5,2),
          ('upload_cleanup_queue','upload_cleanup_capacity_delete',
           'account_upload_cleanup_capacity',9,2),
          ('upload_storage_jobs','upload_storage_job_identity_guard',
           'protect_upload_storage_job_identity',19,1),
          ('upload_cleanup_queue','upload_cleanup_identity_guard',
           'protect_upload_cleanup_identity',19,1),
          ('upload_storage_capacity_ledger','upload_capacity_policy_guard',
           'protect_upload_capacity_policy',19,1)
      ) AS expected(
          relation_name,trigger_name,function_name,trigger_type,attachment_count
      )
      JOIN pg_catalog.pg_namespace relation_schema
        ON relation_schema.nspname=migration_schema
      JOIN pg_catalog.pg_class relation_row
        ON relation_row.relnamespace=relation_schema.oid
       AND relation_row.relname=expected.relation_name
      JOIN pg_catalog.pg_trigger trigger_row
        ON trigger_row.tgrelid=relation_row.oid
       AND trigger_row.tgname=expected.trigger_name
      JOIN pg_catalog.pg_proc function_row
        ON function_row.oid=trigger_row.tgfoid
      JOIN pg_catalog.pg_namespace function_schema
        ON function_schema.oid=function_row.pronamespace;

    IF NOT COALESCE(postconditions,FALSE)
       OR NOT COALESCE(relation_postconditions,FALSE)
       OR NOT COALESCE(trigger_postconditions,FALSE) THEN
        RAISE EXCEPTION 'upload cascade trigger authority was not restored safely'
            USING ERRCODE='55000';
    END IF;
END;
$northstar_upload_cascade_capacity_paths$;

DO $northstar_upload_capacity_binding_paths$
DECLARE
    migration_schema pg_catalog.text:=pg_catalog.current_schema();
    expected_path pg_catalog.text;
    postconditions pg_catalog.bool;
BEGIN
    expected_path:=pg_catalog.format(
        'search_path=pg_catalog, %I, pg_temp',migration_schema
    );
    EXECUTE pg_catalog.format(
        'ALTER FUNCTION %I.bind_upload_storage_capacity_policy(pg_catalog.int8) '
        'RESET ALL',migration_schema
    );
    EXECUTE pg_catalog.format(
        'ALTER FUNCTION %I.bind_upload_storage_capacity_policy(pg_catalog.int8) '
        'SECURITY INVOKER SET search_path TO pg_catalog, %I, pg_temp',
        migration_schema,migration_schema
    );
    EXECUTE pg_catalog.format(
        'ALTER FUNCTION %I.bind_upload_storage_capacity_policy('
        'pg_catalog.int8,pg_catalog.int8,pg_catalog.int8) RESET ALL',
        migration_schema
    );
    EXECUTE pg_catalog.format(
        'ALTER FUNCTION %I.bind_upload_storage_capacity_policy('
        'pg_catalog.int8,pg_catalog.int8,pg_catalog.int8) '
        'SECURITY INVOKER SET search_path TO pg_catalog, %I, pg_temp',
        migration_schema,migration_schema
    );
    SELECT pg_catalog.count(*)=2
       AND pg_catalog.bool_and(NOT proc_row.prosecdef)
       AND pg_catalog.bool_and(proc_row.proowner=(
               SELECT role_row.oid
                 FROM pg_catalog.pg_roles role_row
                WHERE role_row.rolname=CURRENT_USER
           ))
       AND pg_catalog.bool_and(
               COALESCE(proc_row.proconfig,ARRAY[]::pg_catalog.text[])=
               ARRAY[expected_path]::pg_catalog.text[])
      INTO postconditions
      FROM pg_catalog.pg_proc proc_row
      JOIN pg_catalog.pg_namespace proc_namespace
        ON proc_namespace.oid=proc_row.pronamespace
     WHERE proc_namespace.nspname=migration_schema
       AND proc_row.proname='bind_upload_storage_capacity_policy'
       AND pg_catalog.pg_get_function_identity_arguments(proc_row.oid) IN (
           'requested_limit bigint',
           'requested_pending_limit bigint, requested_retained_files_limit bigint, requested_retained_bytes_limit bigint'
       );
    IF NOT COALESCE(postconditions,FALSE) THEN
        RAISE EXCEPTION 'upload capacity binding functions lack fixed schema authority'
            USING ERRCODE='55000';
    END IF;
END;
$northstar_upload_capacity_binding_paths$;
