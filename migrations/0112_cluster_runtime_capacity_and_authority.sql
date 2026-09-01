-- Bound the durable signed-envelope replay authority.  A Redis publisher can
-- otherwise force one PostgreSQL row per command and per acknowledgement
-- until storage is exhausted.  Sixty-four independently locked shards avoid
-- turning normal cluster traffic into a singleton-row lock convoy while the
-- per-shard ceiling provides a hard, deterministic upper bound.

ALTER TABLE cluster_signed_envelope_replays
    ADD COLUMN capacity_shard SMALLINT;

UPDATE cluster_signed_envelope_replays
   SET capacity_shard=(pg_catalog.get_byte(pg_catalog.uuid_send(event_id),0) % 64)::SMALLINT;

ALTER TABLE cluster_signed_envelope_replays
    ALTER COLUMN capacity_shard SET NOT NULL,
    ADD CONSTRAINT cluster_signed_envelope_replay_capacity_shard_check
        CHECK (capacity_shard BETWEEN 0 AND 63);

CREATE INDEX cluster_signed_envelope_replays_capacity_shard_idx
    ON cluster_signed_envelope_replays(capacity_shard);

CREATE TABLE cluster_signed_envelope_replay_capacity (
    capacity_shard SMALLINT PRIMARY KEY CHECK (capacity_shard BETWEEN 0 AND 63),
    active_rows BIGINT NOT NULL CHECK (active_rows BETWEEN 0 AND 8192)
);

INSERT INTO cluster_signed_envelope_replay_capacity(capacity_shard,active_rows)
SELECT shard,
       (SELECT pg_catalog.count(*)
          FROM cluster_signed_envelope_replays replay
         WHERE replay.capacity_shard=shard)::BIGINT
  FROM pg_catalog.generate_series(0,63) AS shard;

DO $northstar_replay_initial_capacity$
BEGIN
    IF EXISTS (
        SELECT 1 FROM cluster_signed_envelope_replay_capacity WHERE active_rows>8192
    ) THEN
        RAISE EXCEPTION 'existing cluster replay authority exceeds the hard shard capacity'
            USING ERRCODE='54000';
    END IF;
END;
$northstar_replay_initial_capacity$;

CREATE OR REPLACE FUNCTION northstar_account_cluster_envelope_replay_capacity()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY DEFINER
AS $$
DECLARE
    expected_relation OID := 'cluster_signed_envelope_replays'::REGCLASS;
BEGIN
    IF TG_RELID<>expected_relation THEN
        RAISE EXCEPTION 'cluster replay capacity guard invoked for an unexpected relation'
            USING ERRCODE='55000';
    END IF;
    IF TG_OP='INSERT' THEN
        IF TG_WHEN='BEFORE' THEN
            NEW.capacity_shard :=
                (pg_catalog.get_byte(pg_catalog.uuid_send(NEW.event_id),0) % 64)::SMALLINT;
            RETURN NEW;
        END IF;
        IF NEW.capacity_shard<>
           (pg_catalog.get_byte(pg_catalog.uuid_send(NEW.event_id),0) % 64)::SMALLINT THEN
            RAISE EXCEPTION 'cluster replay capacity shard identity mismatch'
                USING ERRCODE='55000';
        END IF;
        UPDATE cluster_signed_envelope_replay_capacity
           SET active_rows=active_rows+1
         WHERE capacity_shard=NEW.capacity_shard AND active_rows<8192;
        IF NOT FOUND THEN
            RAISE EXCEPTION 'cluster replay authority capacity is exhausted'
                USING ERRCODE='54000';
        END IF;
        RETURN NEW;
    END IF;
    IF TG_OP='DELETE' THEN
        UPDATE cluster_signed_envelope_replay_capacity
           SET active_rows=active_rows-1
         WHERE capacity_shard=OLD.capacity_shard AND active_rows>0;
        IF NOT FOUND THEN
            RAISE EXCEPTION 'cluster replay authority capacity underflow'
                USING ERRCODE='55000';
        END IF;
        RETURN OLD;
    END IF;
    RAISE EXCEPTION 'unsupported cluster replay capacity transition'
        USING ERRCODE='55000';
END;
$$;

CREATE TRIGGER trg_cluster_envelope_replay_capacity_assign
BEFORE INSERT ON cluster_signed_envelope_replays
FOR EACH ROW EXECUTE FUNCTION northstar_account_cluster_envelope_replay_capacity();

CREATE TRIGGER trg_cluster_envelope_replay_capacity_insert
AFTER INSERT ON cluster_signed_envelope_replays
FOR EACH ROW EXECUTE FUNCTION northstar_account_cluster_envelope_replay_capacity();

CREATE TRIGGER trg_cluster_envelope_replay_capacity_delete
AFTER DELETE ON cluster_signed_envelope_replays
FOR EACH ROW EXECUTE FUNCTION northstar_account_cluster_envelope_replay_capacity();

-- Recreate admission with an explicit column list.  The new capacity shard is
-- assigned only by the owner-executed trigger; callers cannot select a less
-- busy shard.  Existing event identities retain the original conflict rules.
CREATE OR REPLACE FUNCTION northstar_admit_cluster_envelope_replay(
 p_namespace TEXT,p_source_node TEXT,p_source_uuid UUID,p_source_epoch BIGINT,
 p_source_key_id TEXT,p_source_key_epoch BIGINT,p_destination_node TEXT,
 p_destination_uuid UUID,p_destination_epoch BIGINT,p_destination_key_id TEXT,
 p_destination_key_epoch BIGINT,p_event_id UUID,p_channel_sha256 BYTEA,
 p_payload_sha256 TEXT,p_expires_at TIMESTAMPTZ) RETURNS BOOLEAN
LANGUAGE plpgsql
SECURITY DEFINER
AS $$
DECLARE existing cluster_signed_envelope_replays%ROWTYPE;
BEGIN
 IF p_expires_at<=clock_timestamp()-INTERVAL '5 seconds'
    OR p_expires_at>clock_timestamp()+INTERVAL '30 seconds' THEN
  RAISE EXCEPTION 'cluster replay validity window rejected';
 END IF;
 PERFORM 1 FROM cluster_node_instances i
   WHERE i.xmpp_domain=p_namespace AND i.node_id=p_source_node
    AND i.instance_uuid=p_source_uuid AND i.instance_epoch=p_source_epoch
    AND i.signing_key_id=p_source_key_id AND i.signing_key_epoch=p_source_key_epoch
    AND i.lease_until>clock_timestamp() FOR SHARE;
 IF NOT FOUND THEN RAISE EXCEPTION 'cluster replay source instance is not authoritative'; END IF;
 PERFORM 1 FROM cluster_node_instances i
   WHERE i.xmpp_domain=p_namespace AND i.node_id=p_destination_node
    AND i.instance_uuid=p_destination_uuid AND i.instance_epoch=p_destination_epoch
    AND i.signing_key_id=p_destination_key_id AND i.signing_key_epoch=p_destination_key_epoch
    AND i.lease_until>clock_timestamp() FOR SHARE;
 IF NOT FOUND THEN RAISE EXCEPTION 'cluster replay destination instance is not authoritative'; END IF;
 INSERT INTO cluster_signed_envelope_replays(
  namespace,source_node,source_instance_uuid,source_instance_epoch,
  source_key_id,source_key_epoch,destination_node,destination_instance_uuid,
  destination_instance_epoch,destination_key_id,destination_key_epoch,event_id,
  channel_sha256,payload_sha256,expires_at,received_at)
 VALUES(
  p_namespace,p_source_node,p_source_uuid,p_source_epoch,p_source_key_id,p_source_key_epoch,
  p_destination_node,p_destination_uuid,p_destination_epoch,p_destination_key_id,
  p_destination_key_epoch,p_event_id,p_channel_sha256,p_payload_sha256,p_expires_at,
  clock_timestamp())
 ON CONFLICT DO NOTHING;
 IF FOUND THEN RETURN TRUE; END IF;
 SELECT * INTO existing FROM cluster_signed_envelope_replays
  WHERE namespace=p_namespace AND source_node=p_source_node
   AND source_instance_uuid=p_source_uuid AND source_instance_epoch=p_source_epoch
   AND destination_node=p_destination_node AND event_id=p_event_id FOR UPDATE;
 IF existing.payload_sha256<>p_payload_sha256
    OR existing.channel_sha256<>p_channel_sha256
    OR existing.source_key_id<>p_source_key_id
    OR existing.source_key_epoch<>p_source_key_epoch
    OR existing.destination_instance_uuid<>p_destination_uuid
    OR existing.destination_instance_epoch<>p_destination_epoch
    OR existing.destination_key_id<>p_destination_key_id
    OR existing.destination_key_epoch<>p_destination_key_epoch THEN
  RAISE EXCEPTION 'cluster replay identity conflict';
 END IF;
 RETURN FALSE;
END;
$$;

CREATE OR REPLACE FUNCTION northstar_cleanup_cluster_envelope_replays(p_limit INTEGER)
RETURNS BIGINT
LANGUAGE SQL
SECURITY DEFINER
AS $$
WITH expired AS MATERIALIZED (
 SELECT namespace,source_node,source_instance_uuid,source_instance_epoch,destination_node,
        destination_instance_uuid,destination_instance_epoch,event_id
 FROM cluster_signed_envelope_replays
 WHERE expires_at<clock_timestamp()-INTERVAL '30 seconds'
 ORDER BY expires_at,event_id LIMIT LEAST(GREATEST(p_limit,1),10000)
 FOR UPDATE SKIP LOCKED
), removed AS (
 DELETE FROM cluster_signed_envelope_replays replay USING expired
 WHERE (replay.namespace,replay.source_node,replay.source_instance_uuid,
        replay.source_instance_epoch,replay.destination_node,
        replay.destination_instance_uuid,replay.destination_instance_epoch,replay.event_id)=
       (expired.namespace,expired.source_node,expired.source_instance_uuid,
        expired.source_instance_epoch,expired.destination_node,
        expired.destination_instance_uuid,expired.destination_instance_epoch,expired.event_id)
 RETURNING 1)
SELECT COUNT(*) FROM removed
$$;

CREATE FUNCTION northstar_cluster_replay_capacity_healthy()
RETURNS BOOLEAN
LANGUAGE SQL
STABLE
SECURITY DEFINER
AS $$
SELECT pg_catalog.count(*)=64
   AND pg_catalog.bool_and(
       capacity.active_rows=COALESCE(actual.active_rows,0)
       AND capacity.active_rows BETWEEN 0 AND 8192
   )
   AND (
       SELECT pg_catalog.count(*)=3
          FROM pg_catalog.pg_trigger trigger_row
         WHERE trigger_row.tgrelid='cluster_signed_envelope_replays'::REGCLASS
           AND trigger_row.tgname IN (
               'trg_cluster_envelope_replay_capacity_assign',
               'trg_cluster_envelope_replay_capacity_insert',
               'trg_cluster_envelope_replay_capacity_delete'
           )
           AND trigger_row.tgenabled='O'
           AND (SELECT routine.proowner FROM pg_catalog.pg_proc routine
                 WHERE routine.oid=trigger_row.tgfoid)=
               (SELECT relation.relowner FROM pg_catalog.pg_class relation
                 WHERE relation.oid=trigger_row.tgrelid)
   )
   AND NOT EXISTS (
       SELECT 1
         FROM pg_catalog.pg_class relation
         CROSS JOIN LATERAL pg_catalog.aclexplode(
             COALESCE(relation.relacl,
                      pg_catalog.acldefault('r',relation.relowner))
         ) acl
        WHERE relation.oid IN (
                  'cluster_signed_envelope_replays'::REGCLASS,
                  'cluster_signed_envelope_replay_capacity'::REGCLASS
              )
          AND acl.grantee=0
   )
  FROM cluster_signed_envelope_replay_capacity capacity
  LEFT JOIN (
      SELECT capacity_shard,pg_catalog.count(*)::BIGINT AS active_rows
        FROM cluster_signed_envelope_replays GROUP BY capacity_shard
  ) actual USING(capacity_shard)
$$;

-- PostgreSQL-authoritative exact C2S ownership. Redis remains a disposable
-- fan-out index, but an administrative teardown or restarted-node recovery
-- never retargets an old connection UUID through a mutable Redis full-JID key.
CREATE TABLE cluster_session_routes (
    namespace TEXT NOT NULL,
    full_jid VARCHAR(3071) NOT NULL,
    bare_jid VARCHAR(3071) NOT NULL,
    owner_node_id VARCHAR(128) NOT NULL
        CHECK (owner_node_id ~ '^[A-Za-z0-9._-]{1,128}$'),
    owner_instance_uuid UUID NOT NULL,
    owner_instance_epoch BIGINT NOT NULL CHECK (owner_instance_epoch>=1),
    connection_uuid UUID NOT NULL,
    claim_proof_kind TEXT NOT NULL
        CHECK (claim_proof_kind IN ('lease','binding_claim','sm_claim')),
    sm_session_id UUID,
    sm_claim_token UUID,
    lease_until TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY(namespace,full_jid),
    CHECK (octet_length(namespace) BETWEEN 1 AND 255),
    CHECK (octet_length(full_jid) BETWEEN 3 AND 3071),
    CHECK (octet_length(bare_jid) BETWEEN 3 AND 3071),
    CHECK (pg_catalog.strpos(full_jid,'/')>0),
    CHECK (pg_catalog.split_part(full_jid,'/',1)=bare_jid),
    CHECK (pg_catalog.strpos(bare_jid,'@')>1),
    CHECK (pg_catalog.split_part(bare_jid,'@',2)=namespace),
    CHECK (
        (claim_proof_kind='sm_claim' AND sm_session_id IS NOT NULL AND sm_claim_token IS NOT NULL)
        OR
        (claim_proof_kind<>'sm_claim' AND sm_session_id IS NULL AND sm_claim_token IS NULL)
    )
);

CREATE INDEX cluster_session_routes_bare_live_idx
    ON cluster_session_routes(namespace,bare_jid,lease_until,full_jid);
CREATE INDEX cluster_session_routes_expiry_idx
    ON cluster_session_routes(lease_until,namespace,full_jid);

-- This private predicate is shared by lookup, reconciliation and cleanup.  A
-- route is usable only while its exact deployment lease has already moved to
-- the advertised connection, or while one of the two bounded two-phase
-- publication claims is still backed by the incumbent lease.  The SM claim
-- token is deliberately stored only in this owner-only relation and is never
-- returned by a runtime capability.
CREATE FUNCTION northstar_cluster_session_route_authorized(
    p_full_jid TEXT,p_connection_uuid UUID,p_claim_proof_kind TEXT,
    p_sm_session_id UUID,p_sm_claim_token UUID
) RETURNS BOOLEAN
LANGUAGE SQL
STABLE
SECURITY DEFINER
AS $$
SELECT
    EXISTS (
        SELECT 1 FROM deployment_session_leases lease
         WHERE lease.full_jid=p_full_jid
           AND lease.connection_id=p_connection_uuid
           AND lease.lease_until>clock_timestamp()
    )
    OR (
        p_claim_proof_kind='binding_claim'
        AND EXISTS (
            SELECT 1
              FROM deployment_session_binding_claims claim
              JOIN deployment_session_leases incumbent
                ON incumbent.connection_id=claim.replaced_connection_id
               AND incumbent.user_id=claim.user_id
               AND incumbent.full_jid=claim.full_jid
               AND incumbent.lease_until>clock_timestamp()
              JOIN sm_resume_sessions stream
                ON stream.connection_id=incumbent.connection_id
               AND stream.user_id=incumbent.user_id
               AND stream.full_jid=incumbent.full_jid
               AND stream.resumable
               AND stream.expires_at>clock_timestamp()
               AND (stream.claim_token IS NULL
                    OR stream.claimed_until<=clock_timestamp())
             WHERE claim.connection_id=p_connection_uuid
               AND claim.full_jid=p_full_jid
               AND claim.expires_at>clock_timestamp()
        )
    )
    OR (
        p_claim_proof_kind='sm_claim'
        AND p_sm_session_id IS NOT NULL
        AND p_sm_claim_token IS NOT NULL
        AND EXISTS (
            SELECT 1
              FROM sm_resume_sessions stream
              JOIN users user_row
                ON user_row.id=stream.user_id
               AND NOT user_row.is_disabled
               AND user_row.auth_generation=stream.auth_generation
              JOIN deployment_session_leases incumbent
                ON incumbent.connection_id=stream.connection_id
               AND incumbent.user_id=stream.user_id
               AND incumbent.full_jid=stream.full_jid
               AND incumbent.lease_until>clock_timestamp()
             WHERE stream.id=p_sm_session_id
               AND stream.claim_token=p_sm_claim_token
               AND stream.claimed_until>clock_timestamp()
               AND stream.expires_at>clock_timestamp()
               AND (stream.resumable OR stream.live_lease_until<=clock_timestamp())
               AND stream.full_jid=p_full_jid
        )
    )
$$;

CREATE FUNCTION northstar_claim_cluster_session_route(
    p_namespace TEXT,p_full_jid TEXT,p_bare_jid TEXT,p_owner_node_id TEXT,
    p_owner_instance_uuid UUID,p_owner_instance_epoch BIGINT,
    p_connection_uuid UUID,p_sm_session_id UUID,p_sm_claim_token UUID,
    p_lease_seconds INTEGER
) RETURNS TEXT
LANGUAGE plpgsql
SECURITY DEFINER
AS $$
DECLARE
    existing cluster_session_routes%ROWTYPE;
    route_found BOOLEAN := FALSE;
    existing_owner_live BOOLEAN := FALSE;
    live_connection_uuid UUID;
    live_user_id UUID;
    claim_proof_kind TEXT;
    now_at TIMESTAMPTZ := clock_timestamp();
BEGIN
    IF p_lease_seconds<30 OR p_lease_seconds>1800
       OR p_owner_instance_epoch<1 OR p_owner_instance_uuid='00000000-0000-0000-0000-000000000000'
       OR p_connection_uuid='00000000-0000-0000-0000-000000000000'
       OR octet_length(p_namespace) NOT BETWEEN 1 AND 255
       OR octet_length(p_full_jid) NOT BETWEEN 3 AND 3071
       OR octet_length(p_bare_jid) NOT BETWEEN 3 AND 3071
       OR pg_catalog.strpos(p_full_jid,'/')=0
       OR pg_catalog.split_part(p_full_jid,'/',1)<>p_bare_jid
       OR pg_catalog.strpos(p_bare_jid,'@')<=1
       OR pg_catalog.split_part(p_bare_jid,'@',2)<>p_namespace
       OR ((p_sm_session_id IS NULL)<>(p_sm_claim_token IS NULL)) THEN
        RAISE EXCEPTION 'invalid cluster session route claim' USING ERRCODE='22023';
    END IF;
    PERFORM 1 FROM cluster_node_instances instance
     WHERE instance.xmpp_domain=p_namespace AND instance.node_id=p_owner_node_id
       AND instance.instance_uuid=p_owner_instance_uuid
       AND instance.instance_epoch=p_owner_instance_epoch
       AND instance.lease_until>now_at FOR SHARE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'cluster session owner process is not authoritative'
            USING ERRCODE='55000';
    END IF;

    -- Take the live-session row first.  This matches the lease-before-claim
    -- publication order and prevents a route claim racing the authoritative
    -- lease transfer.  Merely possessing EXECUTE on this function is not a
    -- capability to invent a connection identity.
    SELECT lease.connection_id,lease.user_id
      INTO live_connection_uuid,live_user_id
      FROM deployment_session_leases lease
     WHERE lease.full_jid=p_full_jid AND lease.lease_until>now_at
     FOR SHARE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'cluster session route is not backed by a live deployment lease'
            USING ERRCODE='55000';
    END IF;

    IF p_sm_session_id IS NULL THEN
        IF live_connection_uuid=p_connection_uuid THEN
            claim_proof_kind := 'lease';
        ELSE
            PERFORM 1
              FROM deployment_session_binding_claims claim
              JOIN sm_resume_sessions stream
                ON stream.connection_id=live_connection_uuid
               AND stream.user_id=live_user_id
               AND stream.full_jid=p_full_jid
               AND stream.resumable
               AND stream.expires_at>now_at
               AND (stream.claim_token IS NULL OR stream.claimed_until<=now_at)
             WHERE claim.connection_id=p_connection_uuid
               AND claim.user_id=live_user_id
               AND claim.full_jid=p_full_jid
               AND claim.replaced_connection_id=live_connection_uuid
               AND claim.expires_at>now_at
             FOR SHARE OF claim,stream;
            IF NOT FOUND THEN
                RAISE EXCEPTION 'cluster session binding claim is not authoritative'
                    USING ERRCODE='55000';
            END IF;
            claim_proof_kind := 'binding_claim';
        END IF;
    ELSE
        PERFORM 1
          FROM sm_resume_sessions stream
          JOIN users user_row
            ON user_row.id=stream.user_id
           AND NOT user_row.is_disabled
           AND user_row.auth_generation=stream.auth_generation
         WHERE stream.id=p_sm_session_id
           AND stream.claim_token=p_sm_claim_token
           AND stream.claimed_until>now_at
           AND stream.expires_at>now_at
           AND (stream.resumable OR stream.live_lease_until<=now_at)
           AND stream.connection_id=live_connection_uuid
           AND stream.user_id=live_user_id
           AND stream.full_jid=p_full_jid
         FOR SHARE OF stream,user_row;
        IF NOT FOUND THEN
            RAISE EXCEPTION 'cluster session SM claim is not authoritative'
                USING ERRCODE='55000';
        END IF;
        claim_proof_kind := 'sm_claim';
    END IF;

    SELECT * INTO existing FROM cluster_session_routes route
     WHERE route.namespace=p_namespace AND route.full_jid=p_full_jid FOR UPDATE;
    route_found := FOUND;
    IF route_found THEN
        SELECT EXISTS(
            SELECT 1 FROM cluster_node_instances instance
             WHERE instance.xmpp_domain=existing.namespace
               AND instance.node_id=existing.owner_node_id
               AND instance.instance_uuid=existing.owner_instance_uuid
               AND instance.instance_epoch=existing.owner_instance_epoch
               AND instance.lease_until>now_at
        ) INTO existing_owner_live;
    END IF;
    IF route_found AND existing.lease_until>now_at AND existing_owner_live
       AND ROW(existing.owner_node_id,existing.owner_instance_uuid,
               existing.owner_instance_epoch,existing.connection_uuid,
               existing.bare_jid)
           IS DISTINCT FROM
           ROW(p_owner_node_id,p_owner_instance_uuid,p_owner_instance_epoch,
               p_connection_uuid,p_bare_jid) THEN
        RETURN 'conflict';
    END IF;
    INSERT INTO cluster_session_routes(
        namespace,full_jid,bare_jid,owner_node_id,owner_instance_uuid,
        owner_instance_epoch,connection_uuid,claim_proof_kind,
        sm_session_id,sm_claim_token,lease_until,updated_at)
    VALUES(
        p_namespace,p_full_jid,p_bare_jid,p_owner_node_id,p_owner_instance_uuid,
        p_owner_instance_epoch,p_connection_uuid,claim_proof_kind,
        p_sm_session_id,p_sm_claim_token,
        now_at+pg_catalog.make_interval(secs=>p_lease_seconds),now_at)
    ON CONFLICT(namespace,full_jid) DO UPDATE SET
        bare_jid=EXCLUDED.bare_jid,
        owner_node_id=EXCLUDED.owner_node_id,
        owner_instance_uuid=EXCLUDED.owner_instance_uuid,
        owner_instance_epoch=EXCLUDED.owner_instance_epoch,
        connection_uuid=EXCLUDED.connection_uuid,
        claim_proof_kind=EXCLUDED.claim_proof_kind,
        sm_session_id=EXCLUDED.sm_session_id,
        sm_claim_token=EXCLUDED.sm_claim_token,
        lease_until=EXCLUDED.lease_until,
        updated_at=EXCLUDED.updated_at;
    RETURN 'claimed';
END;
$$;

CREATE FUNCTION northstar_refresh_cluster_session_route(
    p_namespace TEXT,p_full_jid TEXT,p_owner_node_id TEXT,
    p_owner_instance_uuid UUID,p_owner_instance_epoch BIGINT,
    p_connection_uuid UUID,p_lease_seconds INTEGER
) RETURNS BOOLEAN
LANGUAGE plpgsql
SECURITY DEFINER
AS $$
DECLARE now_at TIMESTAMPTZ := clock_timestamp();
BEGIN
    IF p_lease_seconds<30 OR p_lease_seconds>1800 THEN
        RAISE EXCEPTION 'invalid cluster session route lease' USING ERRCODE='22023';
    END IF;
    PERFORM 1 FROM cluster_node_instances instance
     WHERE instance.xmpp_domain=p_namespace AND instance.node_id=p_owner_node_id
       AND instance.instance_uuid=p_owner_instance_uuid
       AND instance.instance_epoch=p_owner_instance_epoch
       AND instance.lease_until>now_at FOR SHARE;
    IF NOT FOUND THEN RETURN FALSE; END IF;
    PERFORM 1 FROM deployment_session_leases lease
     WHERE lease.full_jid=p_full_jid
       AND lease.connection_id=p_connection_uuid
       AND lease.lease_until>now_at FOR SHARE;
    IF NOT FOUND THEN RETURN FALSE; END IF;
    UPDATE cluster_session_routes SET
        claim_proof_kind='lease',sm_session_id=NULL,sm_claim_token=NULL,
        lease_until=now_at+pg_catalog.make_interval(secs=>p_lease_seconds),
        updated_at=now_at
     WHERE namespace=p_namespace AND full_jid=p_full_jid
       AND owner_node_id=p_owner_node_id
       AND owner_instance_uuid=p_owner_instance_uuid
       AND owner_instance_epoch=p_owner_instance_epoch
       AND connection_uuid=p_connection_uuid AND lease_until>now_at;
    RETURN FOUND;
END;
$$;

CREATE FUNCTION northstar_release_cluster_session_route(
    p_namespace TEXT,p_full_jid TEXT,p_owner_node_id TEXT,
    p_owner_instance_uuid UUID,p_owner_instance_epoch BIGINT,p_connection_uuid UUID
) RETURNS BOOLEAN
LANGUAGE plpgsql
SECURITY DEFINER
AS $$
BEGIN
    DELETE FROM cluster_session_routes
     WHERE namespace=p_namespace AND full_jid=p_full_jid
       AND owner_node_id=p_owner_node_id
       AND owner_instance_uuid=p_owner_instance_uuid
       AND owner_instance_epoch=p_owner_instance_epoch
       AND connection_uuid=p_connection_uuid;
    RETURN FOUND;
END;
$$;

CREATE FUNCTION northstar_cluster_session_route(
    p_namespace TEXT,p_full_jid TEXT
) RETURNS TABLE(
    owner_node_id TEXT,owner_instance_uuid UUID,owner_instance_epoch BIGINT,
    connection_uuid UUID
)
LANGUAGE SQL
STABLE
SECURITY DEFINER
AS $$
SELECT route.owner_node_id,route.owner_instance_uuid,
       route.owner_instance_epoch,route.connection_uuid
  FROM cluster_session_routes route
  JOIN cluster_node_instances instance
    ON instance.xmpp_domain=route.namespace
   AND instance.node_id=route.owner_node_id
   AND instance.instance_uuid=route.owner_instance_uuid
   AND instance.instance_epoch=route.owner_instance_epoch
   AND instance.lease_until>clock_timestamp()
 WHERE route.namespace=p_namespace AND route.full_jid=p_full_jid
   AND route.lease_until>clock_timestamp()
   AND northstar_cluster_session_route_authorized(
           route.full_jid,route.connection_uuid,route.claim_proof_kind,
           route.sm_session_id,route.sm_claim_token)
$$;

CREATE FUNCTION northstar_cluster_session_nodes_for_bare(
    p_namespace TEXT,p_bare_jid TEXT
) RETURNS TABLE(owner_node_id TEXT)
LANGUAGE SQL
STABLE
SECURITY DEFINER
AS $$
SELECT DISTINCT route.owner_node_id
  FROM cluster_session_routes route
  JOIN cluster_node_instances instance
    ON instance.xmpp_domain=route.namespace
   AND instance.node_id=route.owner_node_id
   AND instance.instance_uuid=route.owner_instance_uuid
   AND instance.instance_epoch=route.owner_instance_epoch
   AND instance.lease_until>clock_timestamp()
 WHERE route.namespace=p_namespace AND route.bare_jid=p_bare_jid
   AND route.lease_until>clock_timestamp()
   AND northstar_cluster_session_route_authorized(
           route.full_jid,route.connection_uuid,route.claim_proof_kind,
           route.sm_session_id,route.sm_claim_token)
 ORDER BY route.owner_node_id LIMIT 256
$$;

CREATE FUNCTION northstar_cleanup_cluster_session_routes(p_limit INTEGER)
RETURNS BIGINT
LANGUAGE SQL
SECURITY DEFINER
AS $$
WITH victims AS MATERIALIZED (
    SELECT namespace,full_jid FROM cluster_session_routes
     WHERE lease_until<=clock_timestamp()
        OR NOT northstar_cluster_session_route_authorized(
                   full_jid,connection_uuid,claim_proof_kind,
                   sm_session_id,sm_claim_token)
     ORDER BY lease_until,namespace,full_jid
     LIMIT LEAST(GREATEST(p_limit,1),10000) FOR UPDATE SKIP LOCKED
), removed AS (
    DELETE FROM cluster_session_routes route USING victims
     WHERE (route.namespace,route.full_jid)=(victims.namespace,victims.full_jid)
     RETURNING 1
)
SELECT pg_catalog.count(*) FROM removed
$$;

-- A cheap deterministic authority probe used by the maintenance supervisor.
-- It does not expose route identities.  Any owner/ACL drift or a malformed
-- route is a safety violation and must make the cluster fail closed.
CREATE FUNCTION northstar_cluster_session_authority_healthy()
RETURNS BOOLEAN
LANGUAGE SQL
STABLE
SECURITY DEFINER
AS $$
SELECT
    (SELECT relation.relowner=routine.proowner
       FROM pg_catalog.pg_class relation
       CROSS JOIN pg_catalog.pg_proc routine
      WHERE relation.oid='cluster_session_routes'::REGCLASS
        AND routine.oid='northstar_cluster_session_authority_healthy()'::REGPROCEDURE)
    AND NOT EXISTS (
        SELECT 1
          FROM pg_catalog.pg_class relation
          CROSS JOIN LATERAL pg_catalog.aclexplode(
              COALESCE(relation.relacl,
                       pg_catalog.acldefault('r',relation.relowner))
          ) acl
         WHERE relation.oid='cluster_session_routes'::REGCLASS
           AND acl.grantee=0
    )
    AND NOT EXISTS (
        SELECT 1 FROM cluster_session_routes route
         WHERE octet_length(route.namespace) NOT BETWEEN 1 AND 255
            OR octet_length(route.full_jid) NOT BETWEEN 3 AND 3071
            OR octet_length(route.bare_jid) NOT BETWEEN 3 AND 3071
            OR pg_catalog.strpos(route.full_jid,'/')=0
            OR pg_catalog.split_part(route.full_jid,'/',1)<>route.bare_jid
            OR pg_catalog.strpos(route.bare_jid,'@')<=1
            OR pg_catalog.split_part(route.bare_jid,'@',2)<>route.namespace
            OR route.owner_instance_epoch<1
            OR route.owner_instance_uuid='00000000-0000-0000-0000-000000000000'
            OR route.connection_uuid='00000000-0000-0000-0000-000000000000'
            OR NOT northstar_cluster_session_route_authorized(
                       route.full_jid,route.connection_uuid,route.claim_proof_kind,
                       route.sm_session_id,route.sm_claim_token)
    )
$$;

-- These routines are narrow runtime capabilities.  Pin resolution to the
-- migration schema, remove PUBLIC execution and verify trigger/owner metadata
-- before allowing the migration to commit.
DO $northstar_cluster_runtime_authority$
DECLARE
    migration_schema pg_catalog.text := pg_catalog.current_schema();
    migration_owner pg_catalog.oid;
    signature pg_catalog.text;
    routine_oid pg_catalog.oid;
    expected_path pg_catalog.text;
BEGIN
    IF migration_schema IS NULL
       OR migration_schema IN ('pg_catalog','information_schema')
       OR migration_schema LIKE 'pg_temp_%'
       OR migration_schema LIKE 'pg_toast_temp_%' THEN
        RAISE EXCEPTION 'migration 0112 requires a dedicated application schema first in search_path'
            USING ERRCODE='3F000';
    END IF;
    SELECT role.oid INTO migration_owner FROM pg_catalog.pg_roles role
     WHERE role.rolname=CURRENT_USER;
    expected_path := pg_catalog.format('search_path=pg_catalog, %I, pg_temp',migration_schema);
    FOREACH signature IN ARRAY ARRAY[
        'northstar_account_cluster_envelope_replay_capacity()',
        'northstar_admit_cluster_envelope_replay(text,text,uuid,int8,text,int8,text,uuid,int8,text,int8,uuid,bytea,text,timestamptz)',
        'northstar_cleanup_cluster_envelope_replays(int4)',
        'northstar_cluster_replay_capacity_healthy()',
        'northstar_cluster_session_route_authorized(text,uuid,text,uuid,uuid)',
        'northstar_claim_cluster_session_route(text,text,text,text,uuid,int8,uuid,uuid,uuid,int4)',
        'northstar_refresh_cluster_session_route(text,text,text,uuid,int8,uuid,int4)',
        'northstar_release_cluster_session_route(text,text,text,uuid,int8,uuid)',
        'northstar_cluster_session_route(text,text)',
        'northstar_cluster_session_nodes_for_bare(text,text)',
        'northstar_cleanup_cluster_session_routes(int4)',
        'northstar_cluster_session_authority_healthy()'
    ] LOOP
        routine_oid := pg_catalog.to_regprocedure(
            pg_catalog.format('%I.%s',migration_schema,signature)
        );
        IF routine_oid IS NULL THEN
            RAISE EXCEPTION 'cluster runtime capability % is absent',signature
                USING ERRCODE='42883';
        END IF;
        IF (SELECT routine.proowner FROM pg_catalog.pg_proc routine WHERE routine.oid=routine_oid)
           <>migration_owner THEN
            RAISE EXCEPTION 'cluster runtime capability % has an unexpected owner',signature
                USING ERRCODE='42501';
        END IF;
        EXECUTE pg_catalog.format(
            'ALTER FUNCTION %I.%s SECURITY DEFINER SET search_path TO pg_catalog, %I, pg_temp',
            migration_schema,signature,migration_schema
        );
        EXECUTE pg_catalog.format(
            'REVOKE ALL ON FUNCTION %I.%s FROM PUBLIC',migration_schema,signature
        );
        IF NOT EXISTS (
            SELECT 1 FROM pg_catalog.pg_proc routine
             WHERE routine.oid=routine_oid AND routine.prosecdef
               AND expected_path=ANY(COALESCE(routine.proconfig,ARRAY[]::pg_catalog.text[]))
        ) THEN
            RAISE EXCEPTION 'cluster runtime capability % was not pinned',signature
                USING ERRCODE='55000';
        END IF;
    END LOOP;

    IF (SELECT relation.relowner FROM pg_catalog.pg_class relation
         WHERE relation.oid='cluster_signed_envelope_replays'::REGCLASS)<>migration_owner
       OR (SELECT relation.relowner FROM pg_catalog.pg_class relation
            WHERE relation.oid='cluster_signed_envelope_replay_capacity'::REGCLASS)<>migration_owner
       OR (SELECT relation.relowner FROM pg_catalog.pg_class relation
            WHERE relation.oid='cluster_session_routes'::REGCLASS)<>migration_owner THEN
        RAISE EXCEPTION 'cluster replay authority tables have an unexpected owner'
            USING ERRCODE='42501';
    END IF;
    REVOKE ALL ON TABLE cluster_signed_envelope_replays,
                        cluster_signed_envelope_replay_capacity,
                        cluster_session_routes FROM PUBLIC;
    IF (SELECT pg_catalog.count(*) FROM pg_catalog.pg_trigger trigger_row
         WHERE trigger_row.tgrelid='cluster_signed_envelope_replays'::REGCLASS
           AND trigger_row.tgname IN (
               'trg_cluster_envelope_replay_capacity_assign',
               'trg_cluster_envelope_replay_capacity_insert',
               'trg_cluster_envelope_replay_capacity_delete'
           ) AND trigger_row.tgenabled='O')<>3 THEN
        RAISE EXCEPTION 'cluster replay capacity triggers are absent or disabled'
            USING ERRCODE='55000';
    END IF;
    IF NOT northstar_cluster_replay_capacity_healthy() THEN
        RAISE EXCEPTION 'cluster replay capacity ledger failed migration reconciliation'
            USING ERRCODE='55000';
    END IF;
    IF NOT northstar_cluster_session_authority_healthy() THEN
        RAISE EXCEPTION 'cluster session authority failed migration reconciliation'
            USING ERRCODE='55000';
    END IF;
END;
$northstar_cluster_runtime_authority$;

COMMENT ON TABLE cluster_signed_envelope_replay_capacity IS
    'Hard sharded capacity authority for short-lived signed cluster replay identities; runtime DML is capability-only';
