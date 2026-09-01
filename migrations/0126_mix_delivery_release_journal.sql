-- Decouple durable MIX delivery completion from capacity admission.  The
-- migration-0120 delete triggers updated hot capacity buckets while an ACK
-- transaction owned its delivery lease, so a non-waiting advisory-lock miss
-- could turn an already accepted socket delivery into a 90-second ordered
-- outbox stall.  Deletes now append immutable release facts; the next producer
-- folds those facts into the exact ledger under the producer-only fence.

CREATE TABLE mix_delivery_capacity_releases (
    release_id UUID PRIMARY KEY DEFAULT pg_catalog.gen_random_uuid(),
    release_kind SMALLINT NOT NULL CHECK (release_kind IN (1, 2)),
    object_id UUID NOT NULL,
    parent_event_id UUID,
    capacity_bucket SMALLINT NOT NULL CHECK (capacity_bucket BETWEEN 0 AND 63),
    released_rows BIGINT NOT NULL,
    released_bytes BIGINT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    CHECK (
        capacity_bucket =
            (get_byte(uuid_send(object_id), 0) % 64)::smallint
    ),
    CHECK (
        (release_kind = 1 AND parent_event_id IS NOT NULL)
        OR (release_kind = 2 AND parent_event_id IS NULL)
    ),
    CHECK (
        (release_kind = 1
         AND released_rows = 1
         AND released_bytes BETWEEN 131 AND 3199)
        OR
        (release_kind = 2
         AND released_rows = 0
         AND released_bytes BETWEEN 1 AND 2097152)
    )
);
CREATE INDEX mix_delivery_capacity_releases_parent_idx
    ON mix_delivery_capacity_releases(parent_event_id)
    WHERE release_kind = 1;

-- Replacing the trigger bodies and auditing the ledger must be one atomic
-- cut-over. ACCESS EXCLUSIVE does not stop an old binary after this transaction
-- commits: migration 0126 is intentionally a stopped-writer upgrade. The
-- repository-authenticated SQLx ledger prevents an old binary from restarting
-- against the new schema, but operators must stop every existing writer first.
LOCK TABLE mix_delivery_recipients,
           mix_delivery_events,
           mix_delivery_capacity
    IN ACCESS EXCLUSIVE MODE;

-- Prove the old ledger before changing its accounting protocol. Silently
-- rebuilding a drifted ledger would hide an earlier trigger bypass or manual
-- authority mutation. ACCESS EXCLUSIVE keeps this snapshot stable.
DO $mix_delivery_cutover_audit$
DECLARE
    ledger_buckets BIGINT;
    ledger_rows BIGINT;
    ledger_bytes BIGINT;
    mismatch_buckets BIGINT;
BEGIN
    WITH recipient_facts AS (
        SELECT (get_byte(uuid_send(delivery_id), 0) % 64)::smallint AS bucket,
               COUNT(*)::bigint AS queued_rows,
               SUM(octet_length(recipient_jid) + 128)::bigint AS queued_bytes
          FROM mix_delivery_recipients
         GROUP BY bucket
    ), event_facts AS (
        SELECT (get_byte(uuid_send(event_id), 0) % 64)::smallint AS bucket,
               SUM(octet_length(stanza_template))::bigint AS queued_bytes
          FROM mix_delivery_events
         GROUP BY bucket
    ), expected AS (
        SELECT generated.bucket::smallint AS bucket,
               COALESCE(recipient.queued_rows, 0) AS queued_rows,
               COALESCE(recipient.queued_bytes, 0)
                 + COALESCE(event.queued_bytes, 0) AS queued_bytes
          FROM generate_series(0, 63) AS generated(bucket)
          LEFT JOIN recipient_facts recipient USING(bucket)
          LEFT JOIN event_facts event USING(bucket)
    )
    SELECT (SELECT COUNT(*) FROM mix_delivery_capacity)::bigint,
           (SELECT COALESCE(SUM(queued_rows), 0)::bigint
              FROM mix_delivery_capacity),
           (SELECT COALESCE(SUM(queued_bytes), 0)::bigint
              FROM mix_delivery_capacity),
           COUNT(*) FILTER (
               WHERE capacity.bucket IS NULL
                  OR capacity.queued_rows <> expected.queued_rows
                  OR capacity.queued_bytes <> expected.queued_bytes
           )::bigint
      INTO ledger_buckets, ledger_rows, ledger_bytes, mismatch_buckets
      FROM expected
      LEFT JOIN mix_delivery_capacity capacity USING(bucket);

    IF ledger_buckets <> 64
       OR mismatch_buckets <> 0
       OR ledger_rows NOT BETWEEN 0 AND 100000
       OR ledger_bytes NOT BETWEEN 0 AND 268435456
    THEN
        RAISE EXCEPTION
            'MIX delivery capacity cut-over audit failed: % buckets, % mismatches, % rows, % bytes',
            ledger_buckets, mismatch_buckets, ledger_rows, ledger_bytes;
    END IF;
END;
$mix_delivery_cutover_audit$;

CREATE OR REPLACE FUNCTION northstar_mix_delivery_recipient_capacity_delete()
RETURNS TRIGGER
LANGUAGE plpgsql
SET search_path FROM CURRENT
AS $$
BEGIN
    INSERT INTO mix_delivery_capacity_releases(
        release_kind, object_id, parent_event_id, capacity_bucket,
        released_rows, released_bytes
    ) VALUES (
        1,
        OLD.delivery_id,
        OLD.event_id,
        (get_byte(uuid_send(OLD.delivery_id), 0) % 64)::smallint,
        1,
        octet_length(OLD.recipient_jid) + 128
    );
    RETURN OLD;
END;
$$;

CREATE OR REPLACE FUNCTION northstar_mix_delivery_event_capacity_delete()
RETURNS TRIGGER
LANGUAGE plpgsql
SET search_path FROM CURRENT
AS $$
BEGIN
    INSERT INTO mix_delivery_capacity_releases(
        release_kind, object_id, parent_event_id, capacity_bucket,
        released_rows, released_bytes
    ) VALUES (
        2,
        OLD.event_id,
        NULL,
        (get_byte(uuid_send(OLD.event_id), 0) % 64)::smallint,
        0,
        octet_length(OLD.stanza_template)
    );
    RETURN OLD;
END;
$$;

-- Runtime may observe release facts, but only this owner-held capability may
-- consume them. It repeats the schema-local producer fence so a direct caller
-- cannot bypass admission serialization; the normal application transaction
-- already owns the same transaction-level advisory lock before taking any
-- business row lock.
CREATE FUNCTION northstar_mix_delivery_capacity_drain()
RETURNS BIGINT
LANGUAGE plpgsql
AS $$
DECLARE
    drained_count BIGINT;
    bucket_count BIGINT;
    applied_count BIGINT;
BEGIN
    PERFORM pg_advisory_xact_lock(
        hashtextextended(
            'mix-delivery-capacity-v3:' ||
            ('mix_delivery_capacity'::regclass)::oid::text,
            0
        )
    );
    WITH released AS (
        DELETE FROM mix_delivery_capacity_releases release
         WHERE NOT (
             release.release_kind = 1
             AND EXISTS (
                 SELECT 1 FROM mix_delivery_events event
                  WHERE event.event_id = release.parent_event_id
             )
             AND NOT EXISTS (
                 SELECT 1 FROM mix_delivery_recipients recipient
                  WHERE recipient.event_id = release.parent_event_id
             )
         )
        RETURNING capacity_bucket, released_rows, released_bytes
    ), deltas AS (
        SELECT capacity_bucket,
               SUM(released_rows)::bigint AS released_rows,
               SUM(released_bytes)::bigint AS released_bytes
          FROM released
         GROUP BY capacity_bucket
    ), applied AS (
        UPDATE mix_delivery_capacity capacity
           SET queued_rows = capacity.queued_rows - delta.released_rows,
               queued_bytes = capacity.queued_bytes - delta.released_bytes,
               updated_at = clock_timestamp()
          FROM deltas delta
         WHERE capacity.bucket = delta.capacity_bucket
           AND capacity.queued_rows >= delta.released_rows
           AND capacity.queued_bytes >= delta.released_bytes
        RETURNING capacity.bucket
    )
    SELECT (SELECT COUNT(*) FROM released)::bigint,
           (SELECT COUNT(*) FROM deltas)::bigint,
           (SELECT COUNT(*) FROM applied)::bigint
      INTO drained_count, bucket_count, applied_count;
    IF bucket_count <> applied_count THEN
        RAISE EXCEPTION
            'MIX delivery capacity release ledger underflow after % facts',
            drained_count
            USING ERRCODE = '55000';
    END IF;
    RETURN drained_count;
END;
$$;

-- Migration 0120 could leave an event behind when its final recipients were
-- acknowledged concurrently. The new event trigger journals each repaired
-- template credit; the unchanged ledger therefore remains exactly equal to
-- live facts plus pending credits at commit.
DELETE FROM mix_delivery_events event
 WHERE NOT EXISTS (
     SELECT 1 FROM mix_delivery_recipients recipient
      WHERE recipient.event_id = event.event_id
 );

-- Pin all three owner-held routines to this migration's actual schema. The
-- trigger functions are private capabilities; only the drain routine is later
-- granted to the runtime role by the canonical capability manifest.
DO $northstar_mix_release_capability_security$
DECLARE
    migration_schema TEXT := pg_catalog.current_schema();
    routine_signature TEXT;
    routine_oid OID;
BEGIN
    IF migration_schema IS NULL THEN
        RAISE EXCEPTION 'MIX release capability migration requires a current schema'
          USING ERRCODE = '3F000';
    END IF;
    FOREACH routine_signature IN ARRAY ARRAY[
      'northstar_mix_delivery_recipient_capacity_delete()',
      'northstar_mix_delivery_event_capacity_delete()',
      'northstar_mix_delivery_capacity_drain()'
    ] LOOP
      routine_oid := pg_catalog.to_regprocedure(
        pg_catalog.format('%I.%s', migration_schema, routine_signature));
      IF routine_oid IS NULL THEN
        RAISE EXCEPTION 'MIX release capability % is absent', routine_signature
          USING ERRCODE = '42883';
      END IF;
      EXECUTE pg_catalog.format(
        'ALTER FUNCTION %I.%s SECURITY DEFINER SET search_path TO pg_catalog, %I, pg_temp',
        migration_schema, routine_signature, migration_schema);
      EXECUTE pg_catalog.format(
        'REVOKE ALL ON FUNCTION %I.%s FROM PUBLIC',
        migration_schema, routine_signature);
      IF NOT EXISTS (
        SELECT 1 FROM pg_catalog.pg_proc routine
         WHERE routine.oid = routine_oid
           AND routine.prokind = 'f'
           AND routine.prosecdef
           AND routine.proowner = (
               SELECT namespace.nspowner
                 FROM pg_catalog.pg_namespace namespace
                WHERE namespace.nspname = migration_schema
           )
           AND routine.proconfig = ARRAY[
               pg_catalog.format(
                 'search_path=pg_catalog, %I, pg_temp', migration_schema
               )
           ]::TEXT[]
      ) THEN
        RAISE EXCEPTION
          'MIX release capability % has unsafe owner/security/search_path',
          routine_signature USING ERRCODE = '55000';
      END IF;
    END LOOP;
END;
$northstar_mix_release_capability_security$;

REVOKE ALL ON TABLE mix_delivery_capacity_releases FROM PUBLIC;

COMMENT ON TABLE mix_delivery_capacity_releases IS
    'Crash-safe write-once capacity release facts consumed atomically by admission; object IDs remain non-unique evidence because dead-letter recovery may re-admit and delete the same projection again';
COMMENT ON FUNCTION northstar_mix_delivery_recipient_capacity_delete() IS
    'Records one recipient capacity release without acquiring the admission fence or a shared capacity row';
COMMENT ON FUNCTION northstar_mix_delivery_event_capacity_delete() IS
    'Records one event-template capacity release without acquiring the admission fence or a shared capacity row';
COMMENT ON FUNCTION northstar_mix_delivery_capacity_drain() IS
    'Consumes authentic release facts and applies their capacity credits atomically under the schema-local producer fence';
