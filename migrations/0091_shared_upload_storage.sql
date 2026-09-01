-- Shared HTTP Upload storage state machine. Object-store network I/O is never
-- performed while holding a PostgreSQL transaction. Every external effect is
-- represented by an immutable create-only key and a bounded durable job. S3
-- uses attempt-qualified keys; local storage retains its historical UUID key.

-- This migration is also exercised in disposable schemas. Require its
-- prerequisite relations and replaced index to exist in exactly the first
-- schema selected by the migration connection. This prevents a search_path
-- such as test_schema,public from silently falling through to an unrelated
-- historical public table. The
-- definer functions are bound to this schema explicitly farther below.
DO $northstar_upload_schema$
DECLARE target_schema pg_catalog.text := pg_catalog.current_schema();
BEGIN
    IF target_schema IS NULL
       OR target_schema IN ('pg_catalog','information_schema')
       OR target_schema LIKE 'pg_temp_%'
       OR target_schema LIKE 'pg_toast_temp_%' THEN
        RAISE EXCEPTION 'migration 0091 requires a dedicated application schema first in search_path'
            USING ERRCODE='3F000';
    END IF;
    IF pg_catalog.to_regclass(pg_catalog.format('%I.%I',target_schema,'upload_slots')) IS NULL
       OR pg_catalog.to_regclass(pg_catalog.format('%I.%I',target_schema,'upload_cleanup_queue')) IS NULL
       OR pg_catalog.to_regclass(pg_catalog.format('%I.%I',target_schema,'upload_cleanup_queue_order_idx')) IS NULL THEN
        RAISE EXCEPTION 'migration 0091 prerequisites are not installed in schema %',
            target_schema
            USING ERRCODE='42P01';
    END IF;
END;
$northstar_upload_schema$ LANGUAGE plpgsql;

ALTER TABLE upload_slots
    ADD COLUMN storage_backend TEXT NOT NULL DEFAULT 'local',
    ADD COLUMN storage_state TEXT NOT NULL DEFAULT 'reserved',
    ADD COLUMN storage_attempt UUID,
    ADD COLUMN storage_stage_key TEXT,
    ADD COLUMN storage_stage_version TEXT,
    ADD COLUMN storage_object_key TEXT,
    ADD COLUMN storage_object_version TEXT,
    ADD COLUMN storage_sha256 BYTEA CHECK (
        storage_sha256 IS NULL OR octet_length(storage_sha256)=32
    ),
    ADD COLUMN storage_size BIGINT CHECK (storage_size IS NULL OR storage_size >= 0),
    ADD COLUMN storage_fence BIGINT NOT NULL DEFAULT 0 CHECK (storage_fence >= 0),
    ADD COLUMN storage_updated_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    ADD COLUMN storage_scrubbed_at TIMESTAMPTZ,
    ADD COLUMN storage_scrub_next_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    ADD COLUMN storage_scrub_failures INTEGER NOT NULL DEFAULT 0 CHECK (storage_scrub_failures>=0),
    ADD COLUMN storage_scrub_claim_token UUID,
    ADD COLUMN storage_scrub_claim_expires_at TIMESTAMPTZ,
    ADD COLUMN storage_cleanup_debt_reserved BOOLEAN NOT NULL DEFAULT FALSE,
    ADD CONSTRAINT upload_slots_scrub_claim_pair CHECK (
        (storage_scrub_claim_token IS NULL)=(storage_scrub_claim_expires_at IS NULL));

-- Old local objects remain addressable by their historical bare UUID. Pending
-- attempts are reclaimed normally; no historical partial is represented as a
-- committed object.
UPDATE upload_slots
SET storage_state = CASE WHEN uploaded AND content_sha256 IS NULL THEN 'legacy_committed'
                         WHEN uploaded THEN 'committed'
                         WHEN uploading THEN 'writing'
                         ELSE 'reserved' END,
    storage_attempt = CASE WHEN uploading THEN claim_token ELSE NULL END,
    storage_stage_key = CASE WHEN uploading AND claim_token IS NOT NULL
        THEN 'staging/' || id::text || '/' || claim_token::text ELSE NULL END,
    -- Every pre-0091 row is local. A crashed old writer may already have
    -- created the historical bare-UUID destination before the database flag
    -- changed, so cleanup must name that destination rather than inventing an
    -- attempt-qualified local object which never existed.
    storage_object_key = CASE WHEN uploaded OR (uploading AND claim_token IS NOT NULL)
        THEN id::text ELSE NULL END,
    storage_sha256 = CASE WHEN uploaded THEN content_sha256 ELSE NULL END,
    storage_size = CASE WHEN uploaded THEN size ELSE NULL END;

ALTER TABLE upload_slots ADD CONSTRAINT upload_slots_storage_backend_check CHECK (
    storage_backend IN ('local','s3')
);
ALTER TABLE upload_slots ADD CONSTRAINT upload_slots_storage_key_check CHECK (
    (storage_stage_key IS NULL OR (storage_attempt IS NOT NULL AND (
        (storage_backend='local' AND storage_stage_key=
            'staging/' || id::text || '/' || storage_attempt::text)
        OR (storage_backend='s3' AND storage_stage_key=
            'objects/' || id::text || '/' || storage_attempt::text
            AND storage_stage_key=storage_object_key))))
    AND
    (storage_object_key IS NULL OR
        (storage_object_key ~
            '^objects/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
         AND storage_attempt IS NOT NULL
         AND storage_object_key='objects/' || id::text || '/' || storage_attempt::text)
        OR (storage_backend='local' AND storage_object_key=id::text))
    AND (storage_stage_version IS NULL OR
         (length(storage_stage_version) BETWEEN 1 AND 1024
          AND storage_stage_version !~ '[[:cntrl:]]'))
    AND (storage_object_version IS NULL OR
         (length(storage_object_version) BETWEEN 1 AND 1024
          AND storage_object_version !~ '[[:cntrl:]]'))
);
ALTER TABLE upload_slots ADD CONSTRAINT upload_slots_storage_state_check CHECK (
    (storage_state='reserved' AND NOT uploaded AND NOT uploading
        AND storage_attempt IS NULL AND storage_stage_key IS NULL
        AND storage_stage_version IS NULL AND storage_object_key IS NULL
        AND storage_object_version IS NULL AND storage_sha256 IS NULL
        AND storage_size IS NULL)
    OR
    (storage_state='writing' AND NOT uploaded AND uploading
        AND storage_attempt=claim_token AND storage_stage_key IS NOT NULL
        AND storage_object_key IS NOT NULL AND storage_sha256 IS NULL
        AND storage_size IS NULL
        AND ((storage_backend='local' AND storage_stage_key<>storage_object_key)
             OR (storage_backend='s3' AND storage_stage_key=storage_object_key)))
    OR
    (storage_state IN ('staged','promoting') AND NOT uploaded AND uploading
        AND storage_attempt=claim_token AND storage_stage_key IS NOT NULL
        AND storage_object_key IS NOT NULL AND storage_sha256 IS NOT NULL
        AND storage_size=size
        AND ((storage_backend='local' AND storage_stage_key<>storage_object_key)
             OR (storage_backend='s3' AND storage_stage_key=storage_object_key)))
    OR
    (storage_state='committed' AND uploaded AND NOT uploading
        AND storage_stage_key IS NULL AND storage_stage_version IS NULL
        AND storage_object_key IS NOT NULL AND storage_sha256 IS NOT NULL
        AND storage_size=size)
    OR
    (storage_state='legacy_committed' AND uploaded AND NOT uploading
        AND storage_stage_key IS NULL AND storage_object_key=id::text
        AND storage_size=size)
    OR
    (storage_state='deleting' AND NOT uploaded AND NOT uploading
        AND (storage_object_key IS NOT NULL OR storage_stage_key IS NOT NULL))
);

CREATE INDEX upload_slots_storage_reconcile_idx
    ON upload_slots(storage_updated_at,id)
    WHERE storage_state IN ('writing','staged','promoting','deleting');
CREATE INDEX upload_slots_storage_backend_idx
    ON upload_slots(storage_backend,storage_state,id);
CREATE INDEX upload_slots_storage_scrub_idx
    ON upload_slots(storage_scrub_next_at,id)
    WHERE storage_backend='s3' AND storage_state='committed';

-- Bind every process to the same non-secret object namespace. The digest is
-- derived from endpoint/region/bucket/prefix/addressing mode, never from
-- credentials. A deployment may change it only after every external locator
-- and reconciliation row has been drained or migrated deliberately.
CREATE TABLE upload_storage_authority (
    singleton BOOLEAN PRIMARY KEY DEFAULT TRUE CHECK (singleton),
    storage_backend TEXT NOT NULL CHECK (storage_backend IN ('local','s3')),
    namespace_sha256 BYTEA NOT NULL CHECK (octet_length(namespace_sha256)=32),
    generation BIGINT NOT NULL DEFAULT 1 CHECK (generation > 0),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
);

-- Runtime configuration may bootstrap this singleton once, but may never
-- retarget it.  An empty queue is not proof that another live node has stopped
-- using the old namespace.  Namespace changes therefore require all nodes to
-- be stopped and an explicit schema/object/locator migration by the trusted
-- maintenance role (which must deliberately replace this guard).
CREATE FUNCTION forbid_upload_storage_authority_mutation() RETURNS TRIGGER AS $$
BEGIN
    RAISE EXCEPTION 'upload storage authority is immutable; use the offline migration procedure'
        USING ERRCODE='55000';
END;
$$ LANGUAGE plpgsql;
CREATE TRIGGER upload_storage_authority_immutable
BEFORE UPDATE OR DELETE ON upload_storage_authority
FOR EACH ROW EXECUTE FUNCTION forbid_upload_storage_authority_mutation();

CREATE TABLE upload_storage_jobs (
    id BIGSERIAL PRIMARY KEY,
    object_id UUID NOT NULL,
    storage_attempt UUID NOT NULL,
    action TEXT NOT NULL CHECK (action IN ('promote','delete_stage','delete_object')),
    storage_backend TEXT NOT NULL CHECK (storage_backend IN ('local','s3')),
    stage_key TEXT,
    stage_version TEXT,
    object_key TEXT,
    object_version TEXT,
    expected_size BIGINT CHECK (expected_size IS NULL OR expected_size >= 0),
    expected_sha256 BYTEA CHECK (
        expected_sha256 IS NULL OR octet_length(expected_sha256)=32
    ),
    storage_fence BIGINT NOT NULL CHECK (storage_fence >= 0),
    available_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    claim_token UUID,
    claim_expires_at TIMESTAMPTZ,
    attempts BIGINT NOT NULL DEFAULT 0 CHECK (attempts >= 0),
    absence_observed_at TIMESTAMPTZ,
    absence_observations INTEGER NOT NULL DEFAULT 0 CHECK (absence_observations>=0),
    dead_lettered_at TIMESTAMPTZ,
    last_error TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    CHECK ((claim_token IS NULL)=(claim_expires_at IS NULL)),
    CHECK (last_error IS NULL OR
           (length(last_error) BETWEEN 1 AND 2048 AND last_error !~ '[[:cntrl:]]')),
    CHECK (
        (action='promote' AND stage_key IS NOT NULL AND object_key IS NOT NULL
            AND expected_size IS NOT NULL AND expected_sha256 IS NOT NULL)
        OR (action='delete_stage' AND stage_key IS NOT NULL AND expected_size IS NOT NULL)
        OR (action='delete_object' AND object_key IS NOT NULL)
    ),
    CHECK (stage_key IS NULL OR
           (storage_backend='local' AND stage_key=
                'staging/' || object_id::text || '/' || storage_attempt::text)
           OR (storage_backend='s3' AND stage_key=
                'objects/' || object_id::text || '/' || storage_attempt::text
                AND (object_key IS NULL OR stage_key=object_key))),
    CHECK (object_key IS NULL OR
           object_key='objects/' || object_id::text || '/' || storage_attempt::text
           OR (storage_backend='local' AND object_key=object_id::text)),
    UNIQUE(object_id,storage_attempt,action)
);
CREATE INDEX upload_storage_jobs_ready_idx
    ON upload_storage_jobs(available_at,id)
    WHERE claim_token IS NULL AND dead_lettered_at IS NULL;
CREATE INDEX upload_storage_jobs_lease_idx
    ON upload_storage_jobs(claim_expires_at,id)
    WHERE claim_token IS NOT NULL;
CREATE INDEX upload_storage_jobs_created_idx ON upload_storage_jobs(created_at,id);
CREATE INDEX upload_storage_jobs_dead_idx ON upload_storage_jobs(id)
    WHERE dead_lettered_at IS NOT NULL;

-- Extend the historical account-deletion queue with the exact immutable
-- locator. Existing rows refer to pre-0091 local UUID objects.
ALTER TABLE upload_cleanup_queue
    ADD COLUMN storage_backend TEXT NOT NULL DEFAULT 'local',
    ADD COLUMN object_key TEXT,
    ADD COLUMN object_version TEXT,
    ADD COLUMN stage_key TEXT,
    ADD COLUMN stage_version TEXT,
    ADD COLUMN storage_attempt UUID,
    ADD COLUMN expected_size BIGINT,
    ADD COLUMN expected_sha256 BYTEA,
    ADD COLUMN storage_fence BIGINT NOT NULL DEFAULT 0,
    ADD COLUMN claim_token UUID,
    ADD COLUMN claim_expires_at TIMESTAMPTZ,
    ADD COLUMN attempts BIGINT NOT NULL DEFAULT 0,
    ADD COLUMN absence_observed_at TIMESTAMPTZ,
    ADD COLUMN absence_observations INTEGER NOT NULL DEFAULT 0,
    ADD COLUMN dead_lettered_at TIMESTAMPTZ,
    ADD COLUMN available_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    ADD COLUMN last_error TEXT;
UPDATE upload_cleanup_queue SET object_key=object_id::text WHERE object_key IS NULL;
UPDATE upload_cleanup_queue q SET expected_size=s.size
  FROM upload_slots s WHERE q.object_id=s.id AND q.expected_size IS NULL;
DO $$
BEGIN
    IF EXISTS(SELECT 1 FROM upload_cleanup_queue WHERE expected_size IS NULL) THEN
        RAISE EXCEPTION 'legacy upload cleanup rows have unknown size; restore/repair their manifest before migration 0091';
    END IF;
END;
$$;
ALTER TABLE upload_cleanup_queue ALTER COLUMN object_key SET NOT NULL;
ALTER TABLE upload_cleanup_queue ALTER COLUMN expected_size SET NOT NULL;
ALTER TABLE upload_cleanup_queue ADD CONSTRAINT upload_cleanup_queue_state_check CHECK (
    storage_backend IN ('local','s3')
    AND (claim_token IS NULL)=(claim_expires_at IS NULL)
    AND attempts >= 0
    AND absence_observations >= 0
    AND storage_fence >= 0
    AND (expected_size IS NULL OR expected_size >= 0)
    AND (expected_sha256 IS NULL OR octet_length(expected_sha256)=32)
    AND (last_error IS NULL OR
         (length(last_error) BETWEEN 1 AND 2048 AND last_error !~ '[[:cntrl:]]'))
    AND (stage_key IS NULL OR (storage_attempt IS NOT NULL AND (
         (storage_backend='local' AND stage_key=
              'staging/' || object_id::text || '/' || storage_attempt::text)
         OR (storage_backend='s3' AND stage_key=
              'objects/' || object_id::text || '/' || storage_attempt::text
              AND stage_key=object_key))))
    AND (object_key=object_id::text OR
         (storage_attempt IS NOT NULL AND
          object_key='objects/' || object_id::text || '/' || storage_attempt::text))
    AND (storage_backend<>'s3' OR object_key<>object_id::text)
);
DROP INDEX upload_cleanup_queue_order_idx;
CREATE INDEX upload_cleanup_queue_order_idx
    ON upload_cleanup_queue(available_at,queued_at,object_id)
    WHERE claim_token IS NULL AND dead_lettered_at IS NULL;
CREATE INDEX upload_cleanup_queue_lease_idx
    ON upload_cleanup_queue(claim_expires_at,object_id)
    WHERE claim_token IS NOT NULL;
CREATE INDEX upload_cleanup_queue_dead_idx ON upload_cleanup_queue(object_id)
    WHERE dead_lettered_at IS NOT NULL;
CREATE INDEX upload_cleanup_queue_queued_idx ON upload_cleanup_queue(queued_at,object_id);

-- Keep the administrative function after all of its relation dependencies so
-- the migration order is auditable and its first-execution SPI preparation
-- cannot observe a partially-installed schema. (PL/pgSQL does not resolve
-- these internal relation references while CREATE FUNCTION runs.)
CREATE FUNCTION offline_upgrade_upload_storage_authority_v1_to_v2(
    expected_backend pg_catalog.TEXT, expected_v1 pg_catalog.BYTEA,
    replacement_v2 pg_catalog.BYTEA, operator_confirmation pg_catalog.TEXT
) RETURNS pg_catalog.VOID AS $$
DECLARE locator_mismatches pg_catalog.int8;
BEGIN
    IF operator_confirmation<>'ALL_NORTHSTAR_NODES_STOPPED_AND_NAMESPACE_VERIFIED' THEN
        RAISE EXCEPTION 'explicit offline authority confirmation is required' USING ERRCODE='42501';
    END IF;
    IF pg_catalog.octet_length(expected_v1)<>32 OR pg_catalog.octet_length(replacement_v2)<>32
       OR expected_v1=replacement_v2 THEN
        RAISE EXCEPTION 'authority digests must be distinct SHA-256 values' USING ERRCODE='22023';
    END IF;
    IF NOT EXISTS(SELECT 1 FROM upload_storage_authority WHERE singleton
                  AND storage_backend=expected_backend AND namespace_sha256=expected_v1) THEN
        RAISE EXCEPTION 'current upload authority does not match supplied v1 digest' USING ERRCODE='55000';
    END IF;
    SELECT pg_catalog.COUNT(*) INTO locator_mismatches FROM (
        SELECT storage_backend FROM upload_slots WHERE storage_object_key IS NOT NULL OR storage_stage_key IS NOT NULL
        UNION ALL SELECT storage_backend FROM upload_storage_jobs
        UNION ALL SELECT storage_backend FROM upload_cleanup_queue
    ) locators WHERE storage_backend<>expected_backend;
    IF locator_mismatches<>0 THEN
        RAISE EXCEPTION 'upload locators do not all belong to the expected backend' USING ERRCODE='55000';
    END IF;
    EXECUTE 'ALTER TABLE upload_storage_authority DISABLE TRIGGER upload_storage_authority_immutable';
    UPDATE upload_storage_authority SET namespace_sha256=replacement_v2,
        generation=generation+1,updated_at=pg_catalog.clock_timestamp()
      WHERE singleton AND storage_backend=expected_backend AND namespace_sha256=expected_v1;
    IF NOT FOUND THEN RAISE EXCEPTION 'upload authority changed during offline upgrade' USING ERRCODE='40001'; END IF;
    EXECUTE 'ALTER TABLE upload_storage_authority ENABLE TRIGGER upload_storage_authority_immutable';
END;
$$ LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp;

CREATE FUNCTION queue_upload_storage_delete() RETURNS TRIGGER AS $$
BEGIN
    -- A writing attempt has no stable final projection. Preserve its exact
    -- attempt tombstone and let that one row own retained-capacity release.
    IF OLD.storage_state='writing'
       AND OLD.storage_attempt IS NOT NULL AND OLD.storage_stage_key IS NOT NULL THEN
        INSERT INTO upload_storage_jobs(
            object_id,storage_attempt,action,storage_backend,stage_key,
            stage_version,storage_fence,expected_size,available_at
        ) VALUES(
            OLD.id,OLD.storage_attempt,'delete_stage',OLD.storage_backend,
            OLD.storage_stage_key,OLD.storage_stage_version,OLD.storage_fence,
            COALESCE(OLD.storage_size,OLD.size),
            CASE WHEN OLD.storage_backend='s3' AND OLD.storage_state='writing'
                 THEN clock_timestamp()+INTERVAL '16 minutes'
                 ELSE clock_timestamp() END
        ) ON CONFLICT(object_id,storage_attempt,action) DO NOTHING;
        RETURN OLD;
    END IF;
    -- Staged/promoting/deleting/committed rows use exactly one cleanup_queue
    -- projection. That row contains both stage and object locators, so local
    -- storage can remove two distinct keys without creating two retained
    -- owners, while S3 direct-final never deletes the same key twice.
    -- Empty reservations own no external object. Cascading account deletion
    -- can therefore remove their metadata directly without manufacturing a
    -- non-canonical object-store key.
    IF OLD.storage_object_key IS NULL AND OLD.storage_stage_key IS NULL
       AND NOT OLD.uploaded THEN
        RETURN OLD;
    END IF;
    INSERT INTO upload_cleanup_queue(
        object_id,storage_backend,object_key,object_version,
        stage_key,stage_version,storage_attempt,expected_size,expected_sha256,
        storage_fence,available_at
    ) VALUES(
        OLD.id,OLD.storage_backend,COALESCE(OLD.storage_object_key,OLD.id::text),
        OLD.storage_object_version,OLD.storage_stage_key,OLD.storage_stage_version,
        OLD.storage_attempt,COALESCE(OLD.storage_size,OLD.size),OLD.storage_sha256,OLD.storage_fence,
        CASE WHEN OLD.storage_state='writing'
             THEN clock_timestamp()+INTERVAL '16 minutes'
             ELSE clock_timestamp() END
    )
    ON CONFLICT(object_id) DO UPDATE SET
        storage_backend=EXCLUDED.storage_backend,
        object_key=EXCLUDED.object_key,
        object_version=EXCLUDED.object_version,
        stage_key=EXCLUDED.stage_key,
        stage_version=EXCLUDED.stage_version,
        storage_attempt=EXCLUDED.storage_attempt,
        expected_size=EXCLUDED.expected_size,
        expected_sha256=EXCLUDED.expected_sha256,
        storage_fence=EXCLUDED.storage_fence,
        available_at=GREATEST(upload_cleanup_queue.available_at,EXCLUDED.available_at);
    RETURN OLD;
END;
$$ LANGUAGE plpgsql;
CREATE TRIGGER upload_storage_delete_queue
BEFORE DELETE ON upload_slots
FOR EACH ROW EXECUTE FUNCTION queue_upload_storage_delete();

-- The promotion queue is append-only except for its lease/retry lifecycle.
-- A forged application update cannot retarget a job after admission.
CREATE FUNCTION protect_upload_storage_job_identity() RETURNS TRIGGER AS $$
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
    NEW.updated_at := clock_timestamp();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;
CREATE TRIGGER upload_storage_job_identity_guard
BEFORE UPDATE ON upload_storage_jobs
FOR EACH ROW EXECUTE FUNCTION protect_upload_storage_job_identity();

-- A claimed cleanup row can change only scheduling/lease/error fields. Its
-- backend locator and fencing generation are immutable, so an expired worker
-- can never be silently retargeted to a later object.
CREATE FUNCTION protect_upload_cleanup_identity() RETURNS TRIGGER AS $$
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
       OR NEW.storage_fence IS DISTINCT FROM OLD.storage_fence THEN
        RAISE EXCEPTION 'upload cleanup identity is immutable' USING ERRCODE='55000';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;
CREATE TRIGGER upload_cleanup_identity_guard
BEFORE UPDATE ON upload_cleanup_queue
FOR EACH ROW EXECUTE FUNCTION protect_upload_cleanup_identity();

-- O(1) physical-capacity ledger. Hot admission locks this single row with a
-- short timeout instead of scanning object/queue tables or taking an advisory
-- lock. Trigger order is deterministic inside the mutating transaction.
CREATE TABLE upload_storage_capacity_ledger (
    singleton BOOLEAN PRIMARY KEY DEFAULT TRUE CHECK(singleton),
    retained_files BIGINT NOT NULL CHECK(retained_files>=0),
    retained_bytes BIGINT NOT NULL CHECK(retained_bytes>=0),
    pending_jobs BIGINT NOT NULL CHECK(pending_jobs>=0),
    storage_jobs_pending BIGINT NOT NULL CHECK(storage_jobs_pending>=0),
    cleanup_jobs_pending BIGINT NOT NULL CHECK(cleanup_jobs_pending>=0),
    cleanup_obligation_debt BIGINT NOT NULL CHECK(cleanup_obligation_debt>=0),
    legacy_overcommit_draining BOOLEAN NOT NULL DEFAULT FALSE,
    configured_pending_limit BIGINT CHECK(configured_pending_limit BETWEEN 128 AND 100000),
    absolute_disaster_limit BIGINT NOT NULL DEFAULT 100000 CHECK(absolute_disaster_limit=100000),
    recovery_reserve_percent SMALLINT NOT NULL DEFAULT 25 CHECK(recovery_reserve_percent=25),
    policy_generation BIGINT NOT NULL DEFAULT 1 CHECK(policy_generation>0),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
);
UPDATE upload_slots s SET storage_cleanup_debt_reserved=TRUE
 WHERE (storage_object_key IS NOT NULL OR storage_stage_key IS NOT NULL)
   AND NOT EXISTS(SELECT 1 FROM upload_cleanup_queue q WHERE q.object_id=s.id)
   AND NOT EXISTS(SELECT 1 FROM upload_storage_jobs j WHERE j.object_id=s.id
       AND j.storage_attempt IS NOT DISTINCT FROM s.storage_attempt
       AND j.action='delete_stage' AND s.storage_state='writing');

INSERT INTO upload_storage_capacity_ledger(singleton,retained_files,retained_bytes,pending_jobs,storage_jobs_pending,cleanup_jobs_pending,cleanup_obligation_debt)
SELECT TRUE,(SELECT COUNT(*) FROM upload_slots)+
       (SELECT COUNT(*) FROM upload_cleanup_queue q WHERE NOT EXISTS
          (SELECT 1 FROM upload_slots s WHERE s.id=q.object_id)),
       COALESCE((SELECT SUM(size) FROM upload_slots),0)+
       COALESCE((SELECT SUM(expected_size) FROM upload_cleanup_queue q WHERE NOT EXISTS
          (SELECT 1 FROM upload_slots s WHERE s.id=q.object_id)),0),
       (SELECT COUNT(*) FROM upload_storage_jobs)+(SELECT COUNT(*) FROM upload_cleanup_queue),
       (SELECT COUNT(*) FROM upload_storage_jobs),(SELECT COUNT(*) FROM upload_cleanup_queue),
       (SELECT COUNT(*) FROM upload_slots WHERE storage_cleanup_debt_reserved);

CREATE FUNCTION account_upload_slot_capacity() RETURNS TRIGGER AS $$
BEGIN
    IF TG_OP='INSERT' THEN
        UPDATE upload_storage_capacity_ledger SET retained_files=retained_files+1,
            retained_bytes=retained_bytes+NEW.size,updated_at=clock_timestamp() WHERE singleton;
        RETURN NEW;
    ELSE
        IF EXISTS(SELECT 1 FROM upload_cleanup_queue WHERE object_id=OLD.id)
           OR EXISTS(SELECT 1 FROM upload_storage_jobs WHERE object_id=OLD.id
                     AND action='delete_stage') THEN
            UPDATE upload_storage_capacity_ledger SET updated_at=clock_timestamp() WHERE singleton;
        ELSE
            UPDATE upload_storage_capacity_ledger SET retained_files=retained_files-1,
                retained_bytes=retained_bytes-OLD.size,updated_at=clock_timestamp() WHERE singleton;
        END IF;
        RETURN OLD;
    END IF;
END;
$$ LANGUAGE plpgsql;
CREATE TRIGGER upload_slot_capacity_insert AFTER INSERT ON upload_slots
FOR EACH ROW EXECUTE FUNCTION account_upload_slot_capacity();
CREATE TRIGGER upload_slot_capacity_delete AFTER DELETE ON upload_slots
FOR EACH ROW EXECUTE FUNCTION account_upload_slot_capacity();

CREATE FUNCTION reserve_upload_cleanup_debt() RETURNS TRIGGER AS $$
BEGIN
    IF NOT OLD.storage_cleanup_debt_reserved
       AND (NEW.storage_object_key IS NOT NULL OR NEW.storage_stage_key IS NOT NULL)
       AND NOT EXISTS(SELECT 1 FROM upload_cleanup_queue WHERE object_id=NEW.id) THEN
        UPDATE upload_storage_capacity_ledger
           SET cleanup_obligation_debt=cleanup_obligation_debt+1,
               updated_at=clock_timestamp()
         WHERE singleton AND configured_pending_limit IS NOT NULL
           AND pending_jobs+cleanup_obligation_debt<configured_pending_limit
           AND pending_jobs+cleanup_obligation_debt<absolute_disaster_limit;
        IF NOT FOUND THEN
            RAISE EXCEPTION 'upload cleanup obligation hard limit reached' USING ERRCODE='53300';
        END IF;
        NEW.storage_cleanup_debt_reserved:=TRUE;
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;
CREATE TRIGGER upload_slot_cleanup_debt_reserve BEFORE UPDATE ON upload_slots
FOR EACH ROW EXECUTE FUNCTION reserve_upload_cleanup_debt();

CREATE FUNCTION account_upload_storage_job_capacity() RETURNS pg_catalog.TRIGGER AS $$
DECLARE converts_debt pg_catalog.bool:=FALSE;
BEGIN
    IF TG_OP='INSERT' THEN
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
        UPDATE upload_storage_capacity_ledger SET pending_jobs=pending_jobs+1,
            cleanup_obligation_debt=cleanup_obligation_debt-
                CASE WHEN converts_debt THEN 1 ELSE 0 END,
            storage_jobs_pending=storage_jobs_pending+1,
            updated_at=pg_catalog.clock_timestamp() WHERE singleton
              AND configured_pending_limit IS NOT NULL
              AND cleanup_obligation_debt>=CASE WHEN converts_debt THEN 1 ELSE 0 END
              AND (converts_debt OR (
                  pending_jobs+cleanup_obligation_debt+1<=configured_pending_limit
                  AND pending_jobs+cleanup_obligation_debt+1<=absolute_disaster_limit));
        IF NOT FOUND THEN RAISE EXCEPTION 'upload recovery queue hard limit reached' USING ERRCODE='53300'; END IF;
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
        UPDATE upload_storage_capacity_ledger SET pending_jobs=pending_jobs-1,
            storage_jobs_pending=storage_jobs_pending-1,
            legacy_overcommit_draining=(pending_jobs-1+cleanup_obligation_debt>
                LEAST(COALESCE(configured_pending_limit,absolute_disaster_limit),
                      absolute_disaster_limit)),
            retained_files=retained_files-CASE WHEN OLD.action='delete_stage'
                AND NOT EXISTS(SELECT 1 FROM upload_slots WHERE id=OLD.object_id)
                THEN 1 ELSE 0 END,
            retained_bytes=retained_bytes-CASE WHEN OLD.action='delete_stage'
                AND NOT EXISTS(SELECT 1 FROM upload_slots WHERE id=OLD.object_id)
                THEN OLD.expected_size ELSE 0 END,
            updated_at=pg_catalog.clock_timestamp() WHERE singleton;
        RETURN OLD;
    END IF;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp;

CREATE FUNCTION account_upload_cleanup_capacity() RETURNS pg_catalog.TRIGGER AS $$
DECLARE converts_debt pg_catalog.bool:=FALSE;
BEGIN
    IF TG_OP='INSERT' THEN
        SELECT EXISTS(SELECT 1 FROM upload_slots WHERE id=NEW.object_id
            AND storage_cleanup_debt_reserved
            AND storage_state IN ('writing','staged','promoting','committed','legacy_committed','deleting')
            AND storage_backend=NEW.storage_backend
            AND storage_object_key=NEW.object_key
            AND storage_object_version IS NOT DISTINCT FROM NEW.object_version
            AND storage_stage_key IS NOT DISTINCT FROM NEW.stage_key
            AND storage_stage_version IS NOT DISTINCT FROM NEW.stage_version
            AND storage_attempt IS NOT DISTINCT FROM NEW.storage_attempt
            AND storage_fence=NEW.storage_fence
            AND COALESCE(storage_size,size)=NEW.expected_size
            AND storage_sha256 IS NOT DISTINCT FROM NEW.expected_sha256)
          INTO converts_debt;
        UPDATE upload_storage_capacity_ledger SET pending_jobs=pending_jobs+1,
            cleanup_obligation_debt=cleanup_obligation_debt-
                CASE WHEN converts_debt THEN 1 ELSE 0 END,
            cleanup_jobs_pending=cleanup_jobs_pending+1,
            retained_files=retained_files+CASE WHEN NOT EXISTS(
                SELECT 1 FROM upload_slots WHERE id=NEW.object_id) THEN 1 ELSE 0 END,
            retained_bytes=retained_bytes+CASE WHEN NOT EXISTS(
                SELECT 1 FROM upload_slots WHERE id=NEW.object_id)
                THEN COALESCE(NEW.expected_size,0) ELSE 0 END,
            updated_at=pg_catalog.clock_timestamp() WHERE singleton
              AND configured_pending_limit IS NOT NULL
              AND cleanup_obligation_debt>=CASE WHEN converts_debt THEN 1 ELSE 0 END
              AND (converts_debt OR (
                  pending_jobs+cleanup_obligation_debt+1<=configured_pending_limit
                  AND pending_jobs+cleanup_obligation_debt+1<=absolute_disaster_limit));
        IF NOT FOUND THEN RAISE EXCEPTION 'upload recovery queue hard limit reached' USING ERRCODE='53300'; END IF;
        IF converts_debt THEN
            UPDATE upload_slots SET storage_cleanup_debt_reserved=FALSE
             WHERE id=NEW.object_id AND storage_cleanup_debt_reserved
               AND storage_state IN ('writing','staged','promoting','committed','legacy_committed','deleting')
               AND storage_backend=NEW.storage_backend
               AND storage_object_key=NEW.object_key
               AND storage_object_version IS NOT DISTINCT FROM NEW.object_version
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
        UPDATE upload_storage_capacity_ledger SET pending_jobs=pending_jobs-1,
            cleanup_jobs_pending=cleanup_jobs_pending-1,
            legacy_overcommit_draining=(pending_jobs-1+cleanup_obligation_debt>
                LEAST(COALESCE(configured_pending_limit,absolute_disaster_limit),
                      absolute_disaster_limit)),
            retained_files=retained_files-CASE WHEN NOT EXISTS(
                SELECT 1 FROM upload_slots WHERE id=OLD.object_id) THEN 1 ELSE 0 END,
            retained_bytes=retained_bytes-CASE WHEN NOT EXISTS(
                SELECT 1 FROM upload_slots WHERE id=OLD.object_id)
                THEN COALESCE(OLD.expected_size,0) ELSE 0 END,
            updated_at=pg_catalog.clock_timestamp() WHERE singleton;
        RETURN OLD;
    END IF;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp;

-- Bind every definer function to the exact installation schema after all
-- three definitions exist. The fixed catalog-first path survives commit and
-- never depends on a caller-controlled search_path or a shared public schema.
DO $northstar_upload_function_paths$
DECLARE migration_schema pg_catalog.text := pg_catalog.current_schema();
BEGIN
    IF migration_schema IS NULL
       OR migration_schema IN ('pg_catalog','information_schema')
       OR migration_schema LIKE 'pg_temp_%'
       OR migration_schema LIKE 'pg_toast_temp_%' THEN
        RAISE EXCEPTION 'unsafe migration schema for upload SECURITY DEFINER functions: %',
            migration_schema
            USING ERRCODE='3F000';
    END IF;

    EXECUTE pg_catalog.format(
        'ALTER FUNCTION %I.offline_upgrade_upload_storage_authority_v1_to_v2('
        'pg_catalog.text,pg_catalog.bytea,pg_catalog.bytea,pg_catalog.text) '
        'SET search_path TO pg_catalog, %I, pg_temp',
        migration_schema,migration_schema
    );
    EXECUTE pg_catalog.format(
        'ALTER FUNCTION %I.account_upload_storage_job_capacity() '
        'SET search_path TO pg_catalog, %I, pg_temp',
        migration_schema,migration_schema
    );
    EXECUTE pg_catalog.format(
        'ALTER FUNCTION %I.account_upload_cleanup_capacity() '
        'SET search_path TO pg_catalog, %I, pg_temp',
        migration_schema,migration_schema
    );
END;
$northstar_upload_function_paths$;

REVOKE ALL ON FUNCTION offline_upgrade_upload_storage_authority_v1_to_v2(
    pg_catalog.TEXT,pg_catalog.BYTEA,pg_catalog.BYTEA,pg_catalog.TEXT) FROM PUBLIC;
CREATE TRIGGER upload_job_capacity_insert AFTER INSERT ON upload_storage_jobs
FOR EACH ROW EXECUTE FUNCTION account_upload_storage_job_capacity();
CREATE TRIGGER upload_job_capacity_delete AFTER DELETE ON upload_storage_jobs
FOR EACH ROW EXECUTE FUNCTION account_upload_storage_job_capacity();
CREATE TRIGGER upload_cleanup_capacity_insert AFTER INSERT ON upload_cleanup_queue
FOR EACH ROW EXECUTE FUNCTION account_upload_cleanup_capacity();
REVOKE ALL ON FUNCTION account_upload_storage_job_capacity() FROM PUBLIC;
REVOKE ALL ON FUNCTION account_upload_cleanup_capacity() FROM PUBLIC;
REVOKE INSERT,UPDATE,DELETE ON upload_storage_jobs,upload_cleanup_queue FROM PUBLIC;
CREATE TRIGGER upload_cleanup_capacity_delete AFTER DELETE ON upload_cleanup_queue
FOR EACH ROW EXECUTE FUNCTION account_upload_cleanup_capacity();

CREATE FUNCTION bind_upload_storage_capacity_policy(requested_limit BIGINT) RETURNS VOID AS $$
DECLARE current_limit BIGINT;
BEGIN
    IF requested_limit NOT BETWEEN 128 AND 100000 THEN
        RAISE EXCEPTION 'invalid upload pending limit' USING ERRCODE='22023';
    END IF;
    SELECT configured_pending_limit INTO current_limit
      FROM upload_storage_capacity_ledger WHERE singleton FOR UPDATE;
    IF current_limit IS NULL THEN
        UPDATE upload_storage_capacity_ledger
           SET configured_pending_limit=requested_limit,
               legacy_overcommit_draining=(pending_jobs+cleanup_obligation_debt>
                    LEAST(requested_limit,absolute_disaster_limit)),
               updated_at=clock_timestamp()
         WHERE singleton AND configured_pending_limit IS NULL;
    ELSIF current_limit<>requested_limit THEN
        RAISE EXCEPTION 'upload pending limit differs from durable deployment authority'
            USING ERRCODE='55000';
    END IF;
END;
$$ LANGUAGE plpgsql;

CREATE FUNCTION protect_upload_capacity_policy() RETURNS TRIGGER AS $$
BEGIN
    IF OLD.configured_pending_limit IS NOT NULL AND (
       NEW.configured_pending_limit IS DISTINCT FROM OLD.configured_pending_limit OR
       NEW.absolute_disaster_limit IS DISTINCT FROM OLD.absolute_disaster_limit OR
       NEW.recovery_reserve_percent IS DISTINCT FROM OLD.recovery_reserve_percent OR
       NEW.policy_generation IS DISTINCT FROM OLD.policy_generation) THEN
        RAISE EXCEPTION 'upload capacity policy is immutable; use an offline migration'
            USING ERRCODE='55000';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;
CREATE TRIGGER upload_capacity_policy_guard BEFORE UPDATE ON upload_storage_capacity_ledger
FOR EACH ROW EXECUTE FUNCTION protect_upload_capacity_policy();
