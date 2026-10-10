-- Retain only the exact existing capacity binding of a recoverable SM owner.
-- STOPPED-WRITER ROLLOUT REQUIRED: stop claim writers AND old startup binaries.
-- Under the migration authority lock, every legacy claim pair, including an
-- expired pair, must already have been resolved by its existing owner. This
-- migration never clears, labels, renews or drains a legacy claim. Restart only
-- after exact schema/capability/migration attestation and approved binary
-- identity verification; old startup reconciliation remains forbidden after
-- this migration. There is no permissive rolling-upgrade fallback.
-- SQLx applies this file atomically. Real PostgreSQL migration/MVCC/clock and
-- stopped-writer rollout qualification remain separate deployment gates.

DO $northstar_sm_retention_precondition$
DECLARE
    migration_schema pg_catalog.text := pg_catalog.current_schema();
    migration_namespace pg_catalog.oid;
    migration_owner pg_catalog.oid;
    relation_name pg_catalog.text;
    qualified_relation pg_catalog.regclass;
BEGIN
    IF migration_schema IS NULL
       OR migration_schema IN ('pg_catalog','information_schema','pg_toast')
       OR migration_schema LIKE 'pg_temp_%'
       OR migration_schema LIKE 'pg_toast_temp_%' THEN
        RAISE EXCEPTION 'unsafe migration schema for session capabilities: %',
            migration_schema USING ERRCODE='3F000';
    END IF;
    SELECT namespace.oid,namespace.nspowner
      INTO migration_namespace,migration_owner
      FROM pg_catalog.pg_namespace namespace
     WHERE namespace.nspname=migration_schema;
    IF migration_namespace IS NULL
       OR migration_owner<>(
            SELECT role.oid FROM pg_catalog.pg_roles role
             WHERE role.rolname=CURRENT_USER
          ) THEN
        RAISE EXCEPTION 'session capability schema must exist and be owned by the migration session'
            USING ERRCODE='42501';
    END IF;
    -- Prevent a future migration statement in this schema from publishing a
    -- just-created routine through PostgreSQL's default PUBLIC EXECUTE grant.
    -- SQLx runs each migration transactionally and each routine below is also
    -- locally revoked, so no observable migration-before-reconciliation gap
    -- remains even when the deployment grant job has never run.
    EXECUTE pg_catalog.format(
      'ALTER DEFAULT PRIVILEGES IN SCHEMA %I REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC CASCADE',
      migration_schema
    );
    FOREACH relation_name IN ARRAY ARRAY[
      'users','muc_rooms','sm_resume_sessions','deployment_session_leases',
      'deployment_session_binding_claims','deployment_capacity_limits',
      'deployment_capacity_shards','deployment_capacity_allocations',
      'deployment_account_capacity'
    ] LOOP
      qualified_relation:=pg_catalog.to_regclass(
        pg_catalog.format('%I.%I',migration_schema,relation_name));
      IF qualified_relation IS NULL OR NOT EXISTS(
        SELECT 1 FROM pg_catalog.pg_class relation
         WHERE relation.oid=qualified_relation
           AND relation.relnamespace=migration_namespace
           AND relation.relowner=migration_owner
           AND relation.relkind IN ('r','p')
      ) THEN
        RAISE EXCEPTION 'session capability prerequisite relation % is absent, outside the installation schema, or has the wrong owner',
          relation_name USING ERRCODE='42P01';
      END IF;
    END LOOP;
END;
$northstar_sm_retention_precondition$;

-- Share the existing deployment authority gate, then exclude all SM writers
-- through the schema transition. Stopping old binaries is an external rollout
-- prerequisite: this lock alone cannot stop one from starting after COMMIT.
SELECT pg_catalog.pg_advisory_xact_lock(1314079572,3);
LOCK TABLE sm_resume_sessions IN ACCESS EXCLUSIVE MODE;
DO $northstar_sm_retention_legacy_gate$
BEGIN
    IF EXISTS(SELECT 1 FROM sm_resume_sessions
               WHERE claim_token IS NOT NULL OR claimed_until IS NOT NULL) THEN
        RAISE EXCEPTION 'SM retention migration requires zero unresolved legacy claim pairs; stopped writers must resolve them through their existing owners'
            USING ERRCODE='55000';
    END IF;
END;
$northstar_sm_retention_legacy_gate$;

ALTER TABLE sm_resume_sessions
    ADD COLUMN claim_purpose TEXT,
    ADD CONSTRAINT sm_resume_sessions_claim_purpose_pair
        CHECK ((claim_purpose IS NULL) = (claim_token IS NULL)),
    ADD CONSTRAINT sm_resume_sessions_claim_purpose_value
        CHECK (claim_purpose IS NULL OR claim_purpose IN ('resume','teardown'));
CREATE INDEX sm_resume_sessions_connection_id_idx
    ON sm_resume_sessions(connection_id,id);

-- Read-only classification, not a receipt or an activation capability. Every
-- mutating caller owns account/SM authority locks (or startup table locks).
-- Several SM rows can name one connection; examine every row, never pick one.
CREATE FUNCTION northstar_session_recovery_retention(
    requested_lease UUID,observed_at TIMESTAMPTZ
) RETURNS TEXT
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path FROM CURRENT
AS $$
DECLARE binding deployment_session_leases%ROWTYPE;
BEGIN
    IF requested_lease IS NULL
       OR requested_lease='00000000-0000-0000-0000-000000000000'
       OR observed_at IS NULL OR NOT pg_catalog.isfinite(observed_at) THEN
        RAISE EXCEPTION 'invalid SM recovery retention observation' USING ERRCODE='22023';
    END IF;
    SELECT lease.* INTO binding FROM deployment_session_leases lease
     WHERE lease.lease_id=requested_lease;
    IF NOT FOUND THEN RETURN 'none'; END IF;
    IF EXISTS(
        SELECT 1 FROM sm_resume_sessions stream
         WHERE stream.connection_id=binding.connection_id
           AND ((stream.claim_token IS NULL)<>(stream.claimed_until IS NULL)
             OR (stream.claim_purpose IS NULL)<>(stream.claim_token IS NULL)
             OR stream.claim_purpose NOT IN ('resume','teardown'))
    ) THEN
        RAISE EXCEPTION 'malformed durable SM claim purpose' USING ERRCODE='55000';
    END IF;
    IF EXISTS(
        SELECT 1 FROM sm_resume_sessions stream JOIN users account ON account.id=stream.user_id
         WHERE stream.connection_id=binding.connection_id
           AND stream.user_id=binding.user_id AND stream.full_jid=binding.full_jid
           AND NOT account.is_disabled AND stream.auth_generation=account.auth_generation
           AND stream.claim_purpose='resume' AND stream.claim_token IS NOT NULL
           AND stream.claimed_until>observed_at
    ) THEN RETURN 'resume_claim'; END IF;
    IF EXISTS(
        SELECT 1 FROM sm_resume_sessions stream JOIN users account ON account.id=stream.user_id
         WHERE stream.connection_id=binding.connection_id
           AND stream.user_id=binding.user_id AND stream.full_jid=binding.full_jid
           AND NOT account.is_disabled AND stream.auth_generation=account.auth_generation
           AND stream.claim_purpose IS DISTINCT FROM 'teardown'
           AND stream.expires_at>observed_at
    ) THEN RETURN 'opportunity'; END IF;
    RETURN 'none';
END;
$$;

CREATE OR REPLACE FUNCTION northstar_session_cleanup_live(requested_limit BIGINT)
RETURNS BIGINT
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path FROM CURRENT
AS $$
DECLARE
    candidate deployment_session_leases%ROWTYPE;
    current_binding deployment_session_leases%ROWTYPE;
    doomed_binding deployment_session_leases%ROWTYPE;
    doomed deployment_session_leases[] := ARRAY[]::deployment_session_leases[];
    entries JSONB;
    scan_at TIMESTAMPTZ;
    decision_at TIMESTAMPTZ;
    affected BIGINT;
    removed BIGINT := 0;
BEGIN
    IF pg_catalog.current_setting('transaction_isolation')<>'read committed' THEN
        RAISE EXCEPTION 'SM retention cleanup requires READ COMMITTED' USING ERRCODE='25001';
    END IF;
    DELETE FROM deployment_session_binding_claims claim
     WHERE claim.connection_id IN (
         SELECT candidate.connection_id
           FROM deployment_session_binding_claims candidate
          WHERE candidate.expires_at<=clock_timestamp()
          ORDER BY candidate.expires_at,candidate.connection_id
          LIMIT LEAST(GREATEST(requested_limit,1),10000)
          FOR UPDATE SKIP LOCKED
     );
    scan_at := pg_catalog.clock_timestamp();
    -- Filter before LIMIT so a protected prefix does not consume the selected
    -- tuples. LIMIT bounds candidates/deletions, not physical scan, classifier,
    -- duplicate-row, sort, buffer or CPU work. Do not refill skipped candidates.
    FOR candidate IN
        SELECT lease.* FROM deployment_session_leases lease
         WHERE lease.lease_until<=scan_at
           AND northstar_session_recovery_retention(lease.lease_id,scan_at)='none'
         ORDER BY lease.lease_until,lease.connection_id
         LIMIT LEAST(GREATEST(requested_limit,1),10000)
         FOR UPDATE OF lease SKIP LOCKED
    LOOP
        -- Only account/SM lock contention may skip a candidate. In particular,
        -- capacity/trigger/timeout/deadlock failures below abort the whole call.
        BEGIN
            PERFORM 1 FROM users account WHERE account.id=candidate.user_id
             FOR SHARE NOWAIT;
            IF NOT FOUND THEN CONTINUE; END IF;
            PERFORM 1 FROM sm_resume_sessions stream
             WHERE stream.connection_id=candidate.connection_id
             ORDER BY stream.id FOR UPDATE NOWAIT;
        EXCEPTION WHEN lock_not_available THEN
            CONTINUE;
        END;
        decision_at := pg_catalog.clock_timestamp();
        -- A fresh READ COMMITTED statement after the authority locks must see
        -- a claim won between screening and locking; outer-query values are
        -- only the exact tuple to revalidate, never final deletion authority.
        SELECT lease.* INTO current_binding FROM deployment_session_leases lease
         WHERE lease.lease_id=candidate.lease_id;
        IF NOT FOUND OR current_binding IS DISTINCT FROM candidate
           OR current_binding.lease_until>decision_at THEN CONTINUE; END IF;
        IF northstar_session_recovery_retention(candidate.lease_id,decision_at)<>'none' THEN
            CONTINUE;
        END IF;
        doomed := pg_catalog.array_append(doomed,current_binding);
    END LOOP;
    IF pg_catalog.cardinality(doomed)=0 THEN RETURN 0; END IF;
    SELECT pg_catalog.jsonb_agg(pg_catalog.jsonb_build_object(
               'resource_kind','live_session','entity_id',binding.lease_id))
      INTO entries FROM pg_catalog.unnest(doomed) binding;
    -- Canonical global (kind,shard,entity) locking precedes account counters.
    -- The helper's existing bounded deadlock retry is not a zero-wait promise.
    IF northstar_capacity_lock_batch(entries)<>pg_catalog.cardinality(doomed) THEN
        RAISE EXCEPTION 'SM retention cleanup lost an exact capacity allocation'
            USING ERRCODE='55000';
    END IF;
    PERFORM 1 FROM deployment_account_capacity counter
     WHERE counter.resource_kind='live_session'
       AND counter.owner_id IN (SELECT binding.user_id FROM pg_catalog.unnest(doomed) binding)
     ORDER BY counter.owner_id FOR UPDATE;
    IF EXISTS(
        SELECT 1 FROM (
            SELECT binding.user_id,pg_catalog.count(*) AS required
              FROM pg_catalog.unnest(doomed) binding GROUP BY binding.user_id
        ) expected LEFT JOIN deployment_account_capacity counter
          ON counter.resource_kind='live_session' AND counter.owner_id=expected.user_id
         WHERE counter.owner_id IS NULL OR counter.used<expected.required
    ) OR EXISTS(
        SELECT 1 FROM (
            SELECT allocation.shard,pg_catalog.count(*) AS required
              FROM pg_catalog.unnest(doomed) binding
              JOIN deployment_capacity_allocations allocation
                ON allocation.resource_kind='live_session' AND allocation.entity_id=binding.lease_id
             GROUP BY allocation.shard
        ) expected JOIN deployment_capacity_shards shard
          ON shard.resource_kind='live_session' AND shard.shard=expected.shard
         WHERE shard.used<expected.required OR shard.used>shard.capacity
    ) THEN
        RAISE EXCEPTION 'SM retention cleanup has insufficient exact capacity charge'
            USING ERRCODE='55000';
    END IF;
    FOREACH doomed_binding IN ARRAY doomed LOOP
        DELETE FROM deployment_session_leases lease
         WHERE lease.lease_id=doomed_binding.lease_id
           AND lease.connection_id=doomed_binding.connection_id
           AND lease.user_id=doomed_binding.user_id AND lease.full_jid=doomed_binding.full_jid
           AND lease.lease_until=doomed_binding.lease_until
           AND lease.created_at=doomed_binding.created_at AND lease.updated_at=doomed_binding.updated_at;
        GET DIAGNOSTICS affected = ROW_COUNT;
        IF affected<>1 THEN
            RAISE EXCEPTION 'SM retention cleanup binding changed under authority locks'
                USING ERRCODE='55000';
        END IF;
        removed := removed+affected;
    END LOOP;
    RETURN removed;
END;
$$;

CREATE OR REPLACE FUNCTION northstar_session_delete_expired_live_leases()
RETURNS BIGINT
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path FROM CURRENT
AS $$
DECLARE removed BIGINT;
BEGIN
    IF pg_catalog.current_setting('transaction_isolation')<>'read committed' THEN
        RAISE EXCEPTION 'SM retention startup cleanup requires READ COMMITTED' USING ERRCODE='25001';
    END IF;
    -- Enforce the locking prerequisite even for a direct granted call. This
    -- locked deletion alone does not attest full startup accounting integrity.
    PERFORM northstar_session_capacity_reconcile_lock();
    WITH deleted AS (
        DELETE FROM deployment_session_leases lease
         WHERE lease.lease_until<=pg_catalog.transaction_timestamp()
           AND northstar_session_recovery_retention(
                 lease.lease_id,pg_catalog.transaction_timestamp())='none'
         RETURNING 1
    ) SELECT pg_catalog.count(*) INTO removed FROM deleted;
    RETURN removed;
END;
$$;

CREATE OR REPLACE FUNCTION northstar_sm_claim(
    requested_token_hash BYTEA,requested_user UUID,requested_claimant_ip INET,
    requested_device UUID,requested_ip_policy TEXT,require_same_device BOOLEAN,
    requested_claim_token UUID,requested_claim_lease BIGINT
) RETURNS TABLE(
    status TEXT,session_id UUID,claim_token UUID,full_jid TEXT,resource TEXT,
    resume_timeout_seconds BIGINT,inbound_h BIGINT,acked_h BIGINT,
    available BOOLEAN,carbons BOOLEAN,priority SMALLINT,
    blocklist_requested BOOLEAN,roster_requested BOOLEAN,
    active_privacy_list TEXT,privacy_requested BOOLEAN,user_agent_id UUID,
    joined_rooms JSONB,directed_presence JSONB,last_presence TEXT,
    old_connection_id UUID,state_version BIGINT,pending_reason TEXT,
    retry_at TIMESTAMPTZ,authority_now TIMESTAMPTZ,claimed_until TIMESTAMPTZ
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path FROM CURRENT
AS $$
DECLARE
    stream RECORD;
    ip_matches BOOLEAN;
    live_pending BOOLEAN;
    claim_pending BOOLEAN;
BEGIN
    IF pg_catalog.octet_length(requested_token_hash)<>32
       OR requested_claim_token='00000000-0000-0000-0000-000000000000'
       OR requested_claim_lease NOT BETWEEN 1 AND 300
       OR requested_ip_policy NOT IN ('none','exact','subnet')
       OR (requested_ip_policy<>'none' AND requested_claimant_ip IS NULL) THEN
        status:='rejected'; RETURN NEXT; RETURN;
    END IF;
    SELECT s.* INTO stream FROM sm_resume_sessions s
      JOIN users account ON account.id=s.user_id
     WHERE s.token_hash=requested_token_hash AND s.user_id=requested_user
       AND NOT account.is_disabled AND s.auth_generation=account.auth_generation
       AND s.expires_at>pg_catalog.clock_timestamp()
     FOR UPDATE OF s FOR KEY SHARE OF account;
    IF NOT FOUND THEN status:='rejected'; RETURN NEXT; RETURN; END IF;
    ip_matches := requested_ip_policy='none'
      OR (stream.peer_ip IS NOT NULL AND requested_claimant_ip IS NOT NULL AND (
          (requested_ip_policy='exact' AND stream.peer_ip=requested_claimant_ip)
          OR (requested_ip_policy='subnet'
              AND pg_catalog.family(stream.peer_ip)=pg_catalog.family(requested_claimant_ip)
              AND pg_catalog.set_masklen(
                    stream.peer_ip,
                    CASE WHEN pg_catalog.family(stream.peer_ip)=4 THEN 24 ELSE 64 END
                  ) >>= requested_claimant_ip)
      ));
    IF NOT COALESCE(ip_matches,FALSE)
       OR (require_same_device AND (
              stream.user_agent_id IS NULL
              OR requested_device IS NULL
              OR stream.user_agent_id IS DISTINCT FROM requested_device
          )) THEN
        status:='rejected'; RETURN NEXT; RETURN;
    END IF;

    authority_now := pg_catalog.clock_timestamp();
    -- The initial lookup and this decision use wall-clock time at different
    -- points while holding the row lock.  A row may cross its expiry in that
    -- interval; reject it here instead of projecting a retry boundary that is
    -- already behind authority_now.
    IF stream.expires_at<=authority_now THEN
        status:='rejected'; RETURN NEXT; RETURN;
    END IF;
    live_pending := NOT stream.resumable
        AND stream.live_lease_until>authority_now;
    claim_pending := stream.claimed_until IS NOT NULL
        AND stream.claimed_until>authority_now;
    IF live_pending OR claim_pending THEN
        status := 'pending';
        session_id := stream.id;
        old_connection_id := stream.connection_id;
        full_jid := stream.full_jid;
        state_version := stream.state_version;
        pending_reason := CASE
          WHEN live_pending AND claim_pending THEN 'live-and-claim-owner'
          WHEN live_pending THEN 'live-owner'
          ELSE 'claim-owner'
        END;
        -- Eligibility needs both the live-owner and claim-owner boundaries to
        -- pass. Expiry is an earlier terminal boundary and must also wake the
        -- waiter so it can return a protocol rejection immediately.
        retry_at := least(
            stream.expires_at,
            greatest(
                CASE WHEN live_pending THEN stream.live_lease_until ELSE authority_now END,
                CASE WHEN claim_pending THEN stream.claimed_until ELSE authority_now END
            )
        );
        RETURN NEXT; RETURN;
    END IF;

    UPDATE sm_resume_sessions s SET
        claim_token=requested_claim_token,claim_purpose='resume',
        claimed_until=authority_now+pg_catalog.make_interval(
            secs=>requested_claim_lease::DOUBLE PRECISION),
        updated_at=authority_now
     WHERE s.id=stream.id
       AND (s.claim_token IS NULL OR s.claimed_until<=authority_now)
     RETURNING s.state_version,s.claimed_until
          INTO state_version,claimed_until;
    IF NOT FOUND THEN
        -- The row lock makes this unreachable for a healthy catalog. Fail
        -- closed rather than inventing a retry time outside the authority row.
        RAISE EXCEPTION 'SM claim authority changed under its row lock'
            USING ERRCODE='40001';
    END IF;
    status:='claimed'; session_id:=stream.id; claim_token:=requested_claim_token;
    old_connection_id:=stream.connection_id;
    full_jid:=stream.full_jid; resource:=stream.resource;
    resume_timeout_seconds:=stream.resume_timeout_seconds;
    inbound_h:=stream.inbound_h; acked_h:=stream.acked_h;
    available:=stream.available; carbons:=stream.carbons; priority:=stream.priority;
    blocklist_requested:=stream.blocklist_requested;
    roster_requested:=stream.roster_requested;
    active_privacy_list:=stream.active_privacy_list;
    privacy_requested:=stream.privacy_requested; user_agent_id:=stream.user_agent_id;
    joined_rooms:=stream.joined_rooms; directed_presence:=stream.directed_presence;
    last_presence:=stream.last_presence;
    RETURN NEXT;
END;
$$;

CREATE OR REPLACE FUNCTION northstar_sm_take_teardown(
    requested_scope TEXT,requested_id UUID,requested_user UUID,
    requested_generation BIGINT,requested_full_jid TEXT,
    requested_token UUID,requested_lease BIGINT
) RETURNS TABLE(
    id UUID,teardown_token UUID,user_id UUID,username TEXT,full_jid TEXT,
    available BOOLEAN,active_privacy_list TEXT,joined_rooms JSONB,
    directed_presence JSONB
)
LANGUAGE plpgsql
SECURITY DEFINER
AS $$
BEGIN
    IF requested_scope NOT IN ('single','user','before_generation','full','all','expired')
       OR requested_token='00000000-0000-0000-0000-000000000000'
       OR requested_lease NOT BETWEEN 1 AND 300
       OR (requested_scope='single' AND requested_id IS NULL)
       OR (requested_scope IN ('user','before_generation') AND requested_user IS NULL)
       OR (requested_scope='before_generation' AND requested_generation<=0)
       OR (requested_scope='full' AND requested_full_jid IS NULL) THEN
        RAISE EXCEPTION 'invalid SM teardown capability request' USING ERRCODE='22023';
    END IF;
    RETURN QUERY
    WITH candidates AS MATERIALIZED (
      SELECT stream.id
        FROM sm_resume_sessions stream
       WHERE (stream.claim_token IS NULL OR stream.claimed_until<=clock_timestamp())
         AND (CASE requested_scope
           WHEN 'single' THEN stream.id=requested_id
           WHEN 'user' THEN stream.user_id=requested_user
           WHEN 'before_generation' THEN stream.user_id=requested_user
                                      AND stream.auth_generation<requested_generation
           WHEN 'full' THEN stream.full_jid=requested_full_jid
           WHEN 'all' THEN TRUE
           WHEN 'expired' THEN stream.expires_at<=clock_timestamp()
           ELSE FALSE END)
       ORDER BY stream.expires_at,stream.id
       LIMIT CASE WHEN requested_scope='single' THEN 1 ELSE 256 END
       FOR UPDATE SKIP LOCKED
    ), claimed AS (
      UPDATE sm_resume_sessions stream SET
        resumable=FALSE,live_lease_until=clock_timestamp(),
        expires_at=CASE WHEN requested_scope='expired' THEN stream.expires_at
                        ELSE clock_timestamp() END,
        claim_token=requested_token,claim_purpose='teardown',
        claimed_until=clock_timestamp()+pg_catalog.make_interval(
            secs=>requested_lease::DOUBLE PRECISION),
        updated_at=clock_timestamp()
       FROM candidates
      WHERE stream.id=candidates.id
      RETURNING stream.id,stream.claim_token,stream.user_id,stream.full_jid,
                stream.available,stream.active_privacy_list,
                stream.joined_rooms,stream.directed_presence
    )
    SELECT claimed.id,claimed.claim_token,claimed.user_id,
           account.username::pg_catalog.text,
           claimed.full_jid,claimed.available,
           claimed.active_privacy_list::pg_catalog.text,
           claimed.joined_rooms,claimed.directed_presence
      FROM claimed JOIN users account ON account.id=claimed.user_id;
END;
$$;

CREATE OR REPLACE FUNCTION northstar_sm_activate(
    requested_id UUID,requested_claim_token UUID,requested_connection UUID,
    requested_client_h BIGINT,requested_peer_ip INET,requested_device UUID,
    requested_live_lease BIGINT,requested_ttl BIGINT
) RETURNS BIGINT
LANGUAGE plpgsql
SECURITY DEFINER
AS $$
DECLARE
    result BIGINT;
    hinted_user UUID;
    hinted_full_jid TEXT;
    target_lease UUID;
BEGIN
    IF requested_client_h NOT BETWEEN 0 AND 4294967295
       OR requested_live_lease NOT BETWEEN 1 AND 86400
       OR requested_ttl NOT BETWEEN 1 AND 86400 THEN RETURN NULL; END IF;
    -- Lookup hints only: repeat every authority predicate after the target
    -- binding SHARE fence, before any SM UPDATE lock can be taken.
    SELECT stream.user_id,stream.full_jid INTO hinted_user,hinted_full_jid
      FROM sm_resume_sessions stream
     WHERE stream.id=requested_id AND stream.claim_token=requested_claim_token
       AND stream.claim_purpose='resume';
    IF NOT FOUND THEN RETURN NULL; END IF;
    SELECT lease.lease_id INTO target_lease FROM deployment_session_leases lease
     WHERE lease.connection_id=requested_connection AND lease.user_id=hinted_user
       AND lease.full_jid=hinted_full_jid AND lease.lease_until>clock_timestamp()
     FOR SHARE;
    IF NOT FOUND THEN RETURN NULL; END IF;
    UPDATE sm_resume_sessions stream SET
        connection_id=requested_connection,acked_h=requested_client_h,
        peer_ip=requested_peer_ip,
        user_agent_id=COALESCE(requested_device,stream.user_agent_id),
        resumable=FALSE,
        live_lease_until=clock_timestamp()+pg_catalog.make_interval(
            secs=>requested_live_lease::DOUBLE PRECISION),
        expires_at=clock_timestamp()+pg_catalog.make_interval(
            secs=>requested_ttl::DOUBLE PRECISION),
        claim_token=NULL,claimed_until=NULL,claim_purpose=NULL,updated_at=clock_timestamp()
      FROM users account
     WHERE stream.id=requested_id AND stream.claim_token=requested_claim_token
       AND stream.claim_purpose='resume'
       AND stream.claimed_until>clock_timestamp() AND account.id=stream.user_id
       AND stream.user_id=hinted_user AND stream.full_jid=hinted_full_jid
       AND EXISTS(
           SELECT 1 FROM deployment_session_leases lease
            WHERE lease.lease_id=target_lease AND lease.connection_id=requested_connection
              AND lease.user_id=hinted_user AND lease.full_jid=hinted_full_jid
              AND lease.lease_until>clock_timestamp()
       )
       AND NOT account.is_disabled
       AND stream.auth_generation=account.auth_generation
     RETURNING stream.outbound_h INTO result;
    RETURN result;
END;
$$;

CREATE OR REPLACE FUNCTION northstar_sm_release_claim(
    requested_id UUID,requested_claim_token UUID
) RETURNS BOOLEAN
LANGUAGE plpgsql
SECURITY DEFINER
AS $$
BEGIN
    UPDATE sm_resume_sessions SET claim_token=NULL,claimed_until=NULL,claim_purpose=NULL,
        updated_at=clock_timestamp()
     WHERE id=requested_id AND claim_token=requested_claim_token;
    RETURN FOUND;
END;
$$;

CREATE OR REPLACE FUNCTION northstar_sm_claim_authority(
    requested_id UUID,requested_claim_token UUID
) RETURNS TABLE(
    auth_generation BIGINT,old_connection_id UUID,user_id UUID,full_jid TEXT
)
LANGUAGE sql
SECURITY DEFINER
AS $$
SELECT account.auth_generation,stream.connection_id,stream.user_id,stream.full_jid
  FROM sm_resume_sessions stream JOIN users account ON account.id=stream.user_id
 WHERE stream.id=requested_id AND stream.claim_token=requested_claim_token
   AND stream.claim_purpose='resume'
   AND stream.claimed_until>clock_timestamp() AND NOT account.is_disabled
   AND stream.auth_generation=account.auth_generation
 FOR KEY SHARE OF account
$$;

CREATE OR REPLACE FUNCTION northstar_session_transfer_sm(
    requested_sm_session UUID,requested_claim_token UUID,
    requested_old_connection UUID,requested_new_connection UUID,
    requested_user UUID,requested_full_jid TEXT,requested_lease_seconds BIGINT
) RETURNS TEXT
LANGUAGE plpgsql
SECURITY DEFINER
AS $$
DECLARE current_row deployment_session_leases%ROWTYPE;
BEGIN
    IF requested_claim_token='00000000-0000-0000-0000-000000000000'
       OR requested_new_connection='00000000-0000-0000-0000-000000000000'
       OR requested_lease_seconds NOT BETWEEN 1 AND 86400 THEN
        RAISE EXCEPTION 'invalid SM live-session transfer' USING ERRCODE='22023';
    END IF;
    PERFORM pg_catalog.pg_advisory_xact_lock(
        1314079573,pg_catalog.hashtext(requested_full_jid));
    SELECT * INTO current_row FROM deployment_session_leases
     WHERE full_jid=requested_full_jid FOR UPDATE;
    IF NOT FOUND OR current_row.user_id<>requested_user THEN RETURN 'conflict'; END IF;
    PERFORM 1 FROM sm_resume_sessions stream
     WHERE stream.id=requested_sm_session
       AND stream.claim_token=requested_claim_token
       AND stream.claim_purpose='resume'
       AND stream.claimed_until>clock_timestamp()
       AND stream.connection_id=requested_old_connection
       AND stream.user_id=requested_user
       AND stream.full_jid=requested_full_jid
     FOR SHARE;
    IF NOT FOUND THEN RETURN 'conflict'; END IF;
    IF current_row.connection_id=requested_new_connection THEN
        UPDATE deployment_session_leases SET
            lease_until=GREATEST(
                lease_until,
                clock_timestamp()+pg_catalog.make_interval(
                    secs=>requested_lease_seconds::DOUBLE PRECISION)),
            updated_at=clock_timestamp()
         WHERE lease_id=current_row.lease_id;
        RETURN 'reserved';
    END IF;
    IF current_row.connection_id<>requested_old_connection THEN RETURN 'conflict'; END IF;
    UPDATE deployment_session_leases SET
        connection_id=requested_new_connection,
        lease_until=GREATEST(
            lease_until,
            clock_timestamp()+pg_catalog.make_interval(
                secs=>requested_lease_seconds::DOUBLE PRECISION)),
        updated_at=clock_timestamp()
     WHERE lease_id=current_row.lease_id
       AND connection_id=requested_old_connection
       AND user_id=requested_user AND full_jid=requested_full_jid;
    IF NOT FOUND THEN RETURN 'conflict'; END IF;
    RETURN 'replaced_resumable';
END;
$$;

CREATE OR REPLACE FUNCTION northstar_session_capability_catalog_healthy(
    requested_schema TEXT
) RETURNS BOOLEAN
LANGUAGE sql
SECURITY DEFINER
SET search_path FROM CURRENT
AS $$
WITH namespace AS (
  SELECT oid,nspowner FROM pg_catalog.pg_namespace WHERE nspname=requested_schema
), retention_relation AS (
  SELECT relation.oid,namespace.nspowner FROM namespace
    JOIN pg_catalog.pg_class relation ON relation.relnamespace=namespace.oid
   WHERE relation.relname='sm_resume_sessions' AND relation.relkind='r'
), expected_purpose_constraint(name,expression) AS (
  VALUES
    ('sm_resume_sessions_claim_purpose_pair',
     '((claim_purpose IS NULL) = (claim_token IS NULL))'),
    ('sm_resume_sessions_claim_purpose_value',
     '((claim_purpose IS NULL) OR (claim_purpose = ANY (ARRAY[''resume''::text, ''teardown''::text])))')
), retention_shape AS (
  SELECT EXISTS(
    SELECT 1 FROM retention_relation relation
      JOIN pg_catalog.pg_attribute attribute ON attribute.attrelid=relation.oid
     WHERE attribute.attname='claim_purpose' AND attribute.attnum>0
       AND NOT attribute.attisdropped AND NOT attribute.attnotnull
       AND attribute.atttypid='pg_catalog.text'::pg_catalog.regtype
       AND attribute.atttypmod=-1 AND NOT attribute.atthasdef
       AND attribute.attgenerated='' AND attribute.attidentity=''
  ) AND NOT EXISTS(
    SELECT 1 FROM expected_purpose_constraint expected
     WHERE NOT EXISTS(
       SELECT 1 FROM retention_relation relation
         JOIN pg_catalog.pg_constraint constraint_row ON constraint_row.conrelid=relation.oid
        WHERE constraint_row.conname=expected.name AND constraint_row.contype='c'
          AND constraint_row.convalidated AND NOT constraint_row.connoinherit
          AND NOT constraint_row.condeferrable AND NOT constraint_row.condeferred
          AND constraint_row.conislocal AND constraint_row.coninhcount=0
          AND pg_catalog.pg_get_expr(constraint_row.conbin,constraint_row.conrelid)=expected.expression
     )
  ) AND EXISTS(
    SELECT 1 FROM retention_relation relation
      JOIN pg_catalog.pg_index index_row ON index_row.indrelid=relation.oid
      JOIN pg_catalog.pg_class index_relation ON index_relation.oid=index_row.indexrelid
      JOIN pg_catalog.pg_am method ON method.oid=index_relation.relam
      JOIN namespace ON index_relation.relnamespace=namespace.oid
     WHERE index_relation.relname='sm_resume_sessions_connection_id_idx'
       AND index_relation.relowner=namespace.nspowner AND index_relation.relkind='i'
       AND method.amname='btree' AND index_row.indisvalid AND index_row.indisready
       AND index_row.indislive AND NOT index_row.indisunique
       AND NOT index_row.indisprimary AND NOT index_row.indisexclusion
       AND index_row.indnkeyatts=2 AND index_row.indnatts=2
       AND index_row.indpred IS NULL AND index_row.indexprs IS NULL
       AND ARRAY(
         SELECT attribute.attname::pg_catalog.text
           FROM pg_catalog.unnest(index_row.indkey::pg_catalog.int2[])
                WITH ORDINALITY key(attnum,position)
           JOIN pg_catalog.pg_attribute attribute
             ON attribute.attrelid=relation.oid AND attribute.attnum=key.attnum
          ORDER BY key.position
       )=ARRAY['connection_id','id']::pg_catalog.text[]
       AND NOT EXISTS(
         SELECT 1 FROM pg_catalog.unnest(index_row.indoption::pg_catalog.int2[]) option_value
          WHERE option_value<>0
       )
       AND NOT EXISTS(
         SELECT 1 FROM pg_catalog.unnest(index_row.indcollation::pg_catalog.oid[]) collation_oid
          WHERE collation_oid<>0
       )
       AND NOT EXISTS(
         SELECT 1 FROM pg_catalog.unnest(index_row.indclass::pg_catalog.oid[]) opclass_oid
           LEFT JOIN pg_catalog.pg_opclass opclass ON opclass.oid=opclass_oid
          WHERE opclass.oid IS NULL OR opclass.opcmethod<>method.oid
             OR opclass.opcnamespace<>'pg_catalog'::pg_catalog.regnamespace
             OR opclass.opcname<>'uuid_ops'
       )
  ) AND EXISTS(
    SELECT 1 FROM namespace JOIN pg_catalog.pg_proc routine ON routine.pronamespace=namespace.oid
     WHERE routine.oid=pg_catalog.to_regprocedure(
       pg_catalog.format('%I.northstar_session_recovery_retention(uuid,timestamptz)',requested_schema))
       AND routine.prorettype='pg_catalog.text'::pg_catalog.regtype
       AND NOT routine.proretset AND routine.provolatile='v'
  ) AS healthy
), protected_relations AS (
  SELECT relation.oid,relation.relname,relation.relowner,relation.relacl,
         namespace.nspowner
    FROM namespace JOIN pg_catalog.pg_class relation
      ON relation.relnamespace=namespace.oid
   WHERE relation.relname IN (
     'deployment_session_leases','deployment_session_binding_claims','sm_resume_sessions'
   ) AND relation.relkind IN ('r','p')
), expected_routine(signature,workload) AS (
  VALUES
    ('northstar_session_delete_expired_live_leases()','runtime'),
    ('northstar_session_capacity_reconcile_lock()','runtime'),
    ('northstar_session_reserve_live(uuid,uuid,text,int8,bool)','runtime'),
    ('northstar_session_finalize_binding(uuid,uuid,text)','runtime'),
    ('northstar_session_publish_binding(uuid,uuid,text,int8)','runtime'),
    ('northstar_session_transfer_sm(uuid,uuid,uuid,uuid,uuid,text,int8)','runtime'),
    ('northstar_session_release_live(uuid)','runtime'),
    ('northstar_session_refresh_live(uuid[],int8)','runtime'),
    ('northstar_session_cleanup_live(int8)','runtime'),
    ('northstar_session_recovery_retention(uuid,timestamptz)','runtime'),
    ('northstar_session_extend_live(uuid,int8)','runtime'),
    ('northstar_sm_create(uuid,bytea,uuid,int8,text,text,text,uuid,int8,int8,int8,int8,bool,bool,int2,bool,bool,text,bool,inet,uuid,jsonb,jsonb,text,int8,int8)','runtime'),
    ('northstar_sm_update_snapshot(uuid,uuid,int8,int8,int8,bool,bool,int2,bool,bool,text,bool,inet,uuid,jsonb,jsonb,text,bool,int8,int8)','runtime'),
    ('northstar_sm_remove_memberships(uuid,uuid,jsonb)','runtime'),
    ('northstar_sm_exact_owner_state(uuid,uuid,uuid,int8)','runtime'),
    ('northstar_sm_claim(bytea,uuid,inet,uuid,text,bool,uuid,int8)','runtime'),
    ('northstar_sm_claim_authority(uuid,uuid)','runtime'),
    ('northstar_sm_activate(uuid,uuid,uuid,int8,inet,uuid,int8,int8)','runtime'),
    ('northstar_sm_release_claim(uuid,uuid)','runtime'),
    ('northstar_sm_revoke(uuid)','runtime'),
    ('northstar_sm_take_teardown(text,uuid,uuid,int8,text,uuid,int8)','runtime'),
    ('northstar_sm_teardown_pending(text,uuid,uuid,int8,text,uuid)','runtime'),
    ('northstar_sm_count(text,uuid,int8,text)','runtime'),
    ('northstar_sm_finalize_teardown(uuid,uuid)','runtime'),
    ('northstar_sm_lock_suspended(uuid)','runtime'),
    ('northstar_sm_advance_suspended(uuid,int8,int8)','runtime'),
    ('northstar_sm_expire_before_generation(uuid,int8)','runtime'),
    ('northstar_sm_privacy_list_in_use(uuid,text)','runtime'),
    ('northstar_sm_privacy_state(uuid)','runtime'),
    ('northstar_session_capability_catalog_healthy(text)','runtime'),
    ('northstar_sm_state_version()','private'),
    ('northstar_sm_state_notify()','private')
), resolved_routine AS (
  SELECT expected.*,
         pg_catalog.to_regprocedure(
           pg_catalog.format('%I.',requested_schema)||expected.signature
         ) AS oid
    FROM expected_routine expected
), protected_routines AS (
  SELECT expected.signature,expected.workload,expected.oid AS expected_oid,
         routine.oid,routine.proowner,routine.prosecdef,routine.prokind,
         routine.proconfig,routine.proacl,namespace.nspowner
    FROM namespace CROSS JOIN resolved_routine expected
    LEFT JOIN pg_catalog.pg_proc routine
      ON routine.oid=expected.oid AND routine.pronamespace=namespace.oid
), unexpected_session_routine AS (
  SELECT 1 FROM namespace
    JOIN pg_catalog.pg_proc routine ON routine.pronamespace=namespace.oid
   WHERE routine.prosecdef
     AND routine.proname IN (
       SELECT pg_catalog.split_part(expected.signature,'(',1)
         FROM expected_routine expected
     )
     AND routine.oid NOT IN (
       SELECT resolved.oid FROM resolved_routine resolved
        WHERE resolved.oid IS NOT NULL
     )
), expected_trigger(
  table_name,trigger_name,function_signature,expected_tgtype,
  expected_update_columns,security_definer
) AS (
  VALUES
    ('deployment_session_leases','deployment_session_leases_capacity_insert',
     'northstar_session_capacity_insert()',5::pg_catalog.int2,
     ARRAY[]::pg_catalog.text[],FALSE),
    ('deployment_session_leases','deployment_session_leases_capacity_delete',
     'northstar_session_capacity_delete()',9::pg_catalog.int2,
     ARRAY[]::pg_catalog.text[],FALSE),
    ('deployment_session_leases','deployment_session_leases_capacity_update',
     'northstar_session_capacity_update()',17::pg_catalog.int2,
     ARRAY['lease_id','connection_id','user_id','full_jid']::pg_catalog.text[],FALSE),
    ('sm_resume_sessions','sm_resume_sessions_deployment_capacity_insert',
     'northstar_sm_capacity_insert()',5::pg_catalog.int2,
     ARRAY[]::pg_catalog.text[],FALSE),
    ('sm_resume_sessions','sm_resume_sessions_deployment_capacity_delete',
     'northstar_sm_capacity_delete()',9::pg_catalog.int2,
     ARRAY[]::pg_catalog.text[],FALSE),
    -- This must stay BEFORE DELETE (tgtype 11) so the source queue's exact
    -- rotated lease is released before PostgreSQL cascades it away.
    ('sm_resume_sessions','sm_resume_sessions_release_mix_delivery_owners',
     'northstar_release_sm_session_mix_delivery_owners()',11::pg_catalog.int2,
     ARRAY[]::pg_catalog.text[],FALSE),
    ('sm_resume_sessions','sm_resume_sessions_authority_version',
     'northstar_sm_state_version()',19::pg_catalog.int2,
     ARRAY[]::pg_catalog.text[],TRUE),
    ('sm_resume_sessions','sm_resume_sessions_authority_notify',
     'northstar_sm_state_notify()',29::pg_catalog.int2,
     ARRAY[]::pg_catalog.text[],TRUE)
), protected_triggers AS (
  SELECT expected.*,trigger.oid,trigger.tgfoid,trigger.tgtype,
         trigger.tgenabled,trigger.tgqual,trigger.tgnargs,trigger.tgargs,
         trigger.tgconstraint,trigger.tgdeferrable,trigger.tginitdeferred,
         trigger.tgparentid,routine.proowner,routine.prokind,
         routine.prosecdef,routine.proconfig,routine.prorettype,
         routine.pronargs,routine.provariadic,
         ARRAY(
           SELECT attribute.attname::pg_catalog.text
             FROM pg_catalog.unnest(trigger.tgattr::pg_catalog.int2[])
                  WITH ORDINALITY selected(attnum,position)
             JOIN pg_catalog.pg_attribute attribute
               ON attribute.attrelid=relation.oid
              AND attribute.attnum=selected.attnum
            ORDER BY selected.position
         ) AS update_columns,
         pg_catalog.to_regprocedure(
           pg_catalog.format('%I.',requested_schema)||expected.function_signature
         ) AS expected_function_oid,namespace.nspowner
    FROM namespace CROSS JOIN expected_trigger expected
    LEFT JOIN pg_catalog.pg_class relation
      ON relation.relnamespace=namespace.oid
     AND relation.relname=expected.table_name AND relation.relkind IN ('r','p')
    LEFT JOIN pg_catalog.pg_trigger trigger
      ON trigger.tgrelid=relation.oid AND trigger.tgname=expected.trigger_name
     AND NOT trigger.tgisinternal
    LEFT JOIN pg_catalog.pg_proc routine ON routine.oid=trigger.tgfoid
), unexpected_trigger AS (
  SELECT 1 FROM namespace
    JOIN pg_catalog.pg_class relation ON relation.relnamespace=namespace.oid
    JOIN pg_catalog.pg_trigger trigger ON trigger.tgrelid=relation.oid
    LEFT JOIN expected_trigger expected
      ON expected.table_name=relation.relname
     AND expected.trigger_name=trigger.tgname
   WHERE relation.relname IN ('deployment_session_leases','sm_resume_sessions')
     AND NOT trigger.tgisinternal AND expected.trigger_name IS NULL
), unexpected_relation_acl AS (
  SELECT 1 FROM protected_relations relation
  CROSS JOIN LATERAL pg_catalog.aclexplode(COALESCE(
    relation.relacl,pg_catalog.acldefault('r',relation.relowner)
  )) privilege
  WHERE privilege.grantee<>relation.relowner
    AND NOT COALESCE(
      SESSION_USER<>pg_catalog.pg_get_userbyid(relation.nspowner)
      AND privilege.grantor=relation.relowner
      AND privilege.privilege_type='SELECT' AND NOT privilege.is_grantable AND (
        (relation.relname IN (
           'deployment_session_leases','deployment_session_binding_claims'
         ) AND privilege.grantee=(
           SELECT oid FROM pg_catalog.pg_roles WHERE rolname='northstar_runtime'
         ))
        OR (relation.relname IN (
           'deployment_session_leases','deployment_session_binding_claims',
           'sm_resume_sessions'
         ) AND privilege.grantee=(
           SELECT oid FROM pg_catalog.pg_roles WHERE rolname='northstar_backup'
         ))
      ),FALSE
    )
), unexpected_column_acl AS (
  SELECT 1 FROM protected_relations relation
  JOIN pg_catalog.pg_attribute attribute ON attribute.attrelid=relation.oid
    AND attribute.attnum>0 AND NOT attribute.attisdropped
  CROSS JOIN LATERAL pg_catalog.aclexplode(attribute.attacl) privilege
  WHERE privilege.grantee<>relation.relowner
    AND NOT COALESCE(
      SESSION_USER<>pg_catalog.pg_get_userbyid(relation.nspowner)
      AND relation.relname='sm_resume_sessions'
      AND privilege.grantor=relation.relowner
      AND privilege.grantee=(
        SELECT oid FROM pg_catalog.pg_roles WHERE rolname='northstar_runtime'
      ) AND privilege.privilege_type='SELECT' AND NOT privilege.is_grantable
      AND attribute.attname IN (
        'id','user_id','auth_generation','full_jid','resource','connection_id',
        'resume_timeout_seconds','inbound_h','outbound_h','acked_h','available',
        'carbons','priority','blocklist_requested','roster_requested',
        'active_privacy_list','privacy_requested','user_agent_id','joined_rooms',
        'directed_presence','last_presence','resumable','live_lease_until',
        'expires_at','claimed_until','created_at','updated_at'
      ),FALSE
    )
), routine_acl_drift AS (
  SELECT 1 FROM protected_routines routine
   WHERE routine.oid IS NULL OR routine.expected_oid IS NULL
      OR routine.proowner<>routine.nspowner OR NOT routine.prosecdef
      OR routine.prokind<>'f'
      OR routine.proconfig IS DISTINCT FROM ARRAY[
           pg_catalog.format('search_path=pg_catalog, %I, pg_temp',requested_schema)
         ]::pg_catalog.text[]
      OR (SELECT pg_catalog.count(*)
            FROM pg_catalog.aclexplode(COALESCE(
              routine.proacl,pg_catalog.acldefault('f',routine.proowner)
            )) privilege)<>CASE
              WHEN routine.workload='private'
                OR SESSION_USER=pg_catalog.pg_get_userbyid(routine.nspowner)
                THEN 1 ELSE 2 END
      OR EXISTS(
           SELECT 1 FROM pg_catalog.aclexplode(COALESCE(
             routine.proacl,pg_catalog.acldefault('f',routine.proowner)
           )) privilege
            WHERE privilege.privilege_type<>'EXECUTE' OR privilege.is_grantable
               OR privilege.grantor<>routine.proowner
               OR (privilege.grantee<>routine.proowner AND (
                    routine.workload='private'
                    OR SESSION_USER=pg_catalog.pg_get_userbyid(routine.nspowner)
                    OR privilege.grantee IS DISTINCT FROM (
                         SELECT role.oid FROM pg_catalog.pg_roles role
                          WHERE role.rolname='northstar_runtime'
                    )))
      )
      OR NOT EXISTS(
           SELECT 1 FROM pg_catalog.aclexplode(COALESCE(
             routine.proacl,pg_catalog.acldefault('f',routine.proowner)
           )) privilege
            WHERE privilege.grantee=routine.proowner
              AND privilege.grantor=routine.proowner
              AND privilege.privilege_type='EXECUTE'
              AND NOT privilege.is_grantable
      )
      OR (routine.workload='runtime'
          AND SESSION_USER<>pg_catalog.pg_get_userbyid(routine.nspowner)
          AND NOT EXISTS(
            SELECT 1 FROM pg_catalog.aclexplode(COALESCE(
              routine.proacl,pg_catalog.acldefault('f',routine.proowner)
            )) privilege
             WHERE privilege.grantee=(
                     SELECT role.oid FROM pg_catalog.pg_roles role
                      WHERE role.rolname='northstar_runtime'
                   )
               AND privilege.grantor=routine.proowner
               AND privilege.privilege_type='EXECUTE'
               AND NOT privilege.is_grantable
          ))
), runtime_dml_acl AS (
  SELECT 1 FROM protected_relations relation
   WHERE SESSION_USER<>pg_catalog.pg_get_userbyid(relation.relowner)
     AND (pg_catalog.has_table_privilege(SESSION_USER,relation.oid,'INSERT')
       OR pg_catalog.has_table_privilege(SESSION_USER,relation.oid,'UPDATE')
       OR pg_catalog.has_table_privilege(SESSION_USER,relation.oid,'DELETE')
       OR pg_catalog.has_table_privilege(SESSION_USER,relation.oid,'TRUNCATE')
       OR pg_catalog.has_table_privilege(SESSION_USER,relation.oid,'REFERENCES')
       OR pg_catalog.has_table_privilege(SESSION_USER,relation.oid,'TRIGGER')
       OR pg_catalog.has_any_column_privilege(SESSION_USER,relation.oid,'INSERT')
       OR pg_catalog.has_any_column_privilege(SESSION_USER,relation.oid,'UPDATE')
       OR pg_catalog.has_any_column_privilege(SESSION_USER,relation.oid,'REFERENCES'))
), sensitive_sm_acl AS (
  SELECT 1 FROM namespace
   WHERE SESSION_USER<>pg_catalog.pg_get_userbyid(namespace.nspowner)
     AND (pg_catalog.has_column_privilege(
            SESSION_USER,pg_catalog.format('%I.sm_resume_sessions',requested_schema),
            'token_hash','SELECT')
       OR pg_catalog.has_column_privilege(
            SESSION_USER,pg_catalog.format('%I.sm_resume_sessions',requested_schema),
            'claim_token','SELECT')
       OR pg_catalog.has_column_privilege(
            SESSION_USER,pg_catalog.format('%I.sm_resume_sessions',requested_schema),
            'peer_ip','SELECT')
       OR pg_catalog.has_column_privilege(
            SESSION_USER,pg_catalog.format('%I.sm_resume_sessions',requested_schema),
            'state_version','SELECT')
       OR pg_catalog.has_column_privilege(
            SESSION_USER,pg_catalog.format('%I.sm_resume_sessions',requested_schema),
            'claim_purpose','SELECT'))
)
SELECT (SELECT pg_catalog.count(*)=1 FROM namespace)
  AND (SELECT pg_catalog.count(*)=3 AND pg_catalog.bool_and(relowner=nspowner)
         FROM protected_relations)
  AND (SELECT healthy FROM retention_shape)
  AND NOT EXISTS(SELECT 1 FROM unexpected_relation_acl)
  AND NOT EXISTS(SELECT 1 FROM unexpected_column_acl)
  AND NOT EXISTS(SELECT 1 FROM routine_acl_drift)
  AND NOT EXISTS(SELECT 1 FROM unexpected_session_routine)
  AND NOT EXISTS(SELECT 1 FROM runtime_dml_acl)
  AND NOT EXISTS(SELECT 1 FROM sensitive_sm_acl)
  AND NOT EXISTS(SELECT 1 FROM unexpected_trigger)
  AND (SELECT pg_catalog.count(*)=8 AND pg_catalog.bool_and(
         oid IS NOT NULL AND expected_function_oid IS NOT NULL
          AND tgfoid=expected_function_oid AND tgtype=expected_tgtype
          AND update_columns=expected_update_columns
          AND tgenabled='O' AND tgqual IS NULL
          AND tgnargs=0 AND pg_catalog.octet_length(tgargs)=0
          AND tgconstraint=0 AND NOT tgdeferrable AND NOT tginitdeferred
          AND tgparentid=0 AND proowner=nspowner AND prokind='f'
          AND prosecdef=security_definer
          AND proconfig IS NOT DISTINCT FROM ARRAY[
            pg_catalog.format('search_path=pg_catalog, %I, pg_temp',requested_schema)
          ]::pg_catalog.text[]
          AND prorettype='pg_catalog.trigger'::pg_catalog.regtype
          AND pronargs=0 AND provariadic=0
       ) FROM protected_triggers)
  AND (SELECT pg_catalog.count(*)=(SELECT pg_catalog.count(*) FROM expected_routine)
         AND pg_catalog.bool_and(oid IS NOT NULL) FROM protected_routines)
$$;

DO $northstar_sm_retention_security$
DECLARE
    migration_schema TEXT:=pg_catalog.current_schema();
    routine_signature TEXT;
    routine_oid OID;
BEGIN
    IF migration_schema IS NULL THEN
        RAISE EXCEPTION 'session capability migration requires a current schema'
          USING ERRCODE='3F000';
    END IF;
    FOREACH routine_signature IN ARRAY ARRAY[
      'northstar_session_recovery_retention(uuid,timestamptz)',
      'northstar_session_delete_expired_live_leases()',
      'northstar_session_cleanup_live(int8)',
      'northstar_sm_claim(bytea,uuid,inet,uuid,text,bool,uuid,int8)',
      'northstar_sm_take_teardown(text,uuid,uuid,int8,text,uuid,int8)',
      'northstar_sm_activate(uuid,uuid,uuid,int8,inet,uuid,int8,int8)',
      'northstar_sm_release_claim(uuid,uuid)',
      'northstar_sm_claim_authority(uuid,uuid)',
      'northstar_session_transfer_sm(uuid,uuid,uuid,uuid,uuid,text,int8)',
      'northstar_session_capability_catalog_healthy(text)'
    ] LOOP
      routine_oid:=pg_catalog.to_regprocedure(
        pg_catalog.format('%I.%s',migration_schema,routine_signature));
      IF routine_oid IS NULL THEN
        RAISE EXCEPTION 'session capability % is absent',routine_signature
          USING ERRCODE='42883';
      END IF;
      EXECUTE pg_catalog.format(
        'ALTER FUNCTION %I.%s SECURITY DEFINER SET search_path TO pg_catalog, %I, pg_temp',
        migration_schema,routine_signature,migration_schema);
      EXECUTE pg_catalog.format(
        'REVOKE ALL ON FUNCTION %I.%s FROM PUBLIC',
        migration_schema,routine_signature);
      IF NOT EXISTS(
        SELECT 1 FROM pg_catalog.pg_proc routine
         WHERE routine.oid=routine_oid AND routine.prosecdef
           AND routine.prokind='f'
           AND routine.proowner=(SELECT namespace.nspowner
             FROM pg_catalog.pg_namespace namespace
            WHERE namespace.nspname=migration_schema)
           AND routine.proconfig=ARRAY[
             pg_catalog.format('search_path=pg_catalog, %I, pg_temp',migration_schema)
           ]::TEXT[]
      ) THEN
        RAISE EXCEPTION 'session capability % has unsafe owner/security/search_path',
          routine_signature USING ERRCODE='55000';
      END IF;
      IF EXISTS(
        SELECT 1 FROM pg_catalog.pg_proc routine
        CROSS JOIN LATERAL pg_catalog.aclexplode(COALESCE(
          routine.proacl,pg_catalog.acldefault('f',routine.proowner))) privilege
         WHERE routine.oid=routine_oid AND privilege.grantee=0
           AND privilege.privilege_type='EXECUTE'
      ) THEN
        RAISE EXCEPTION 'PUBLIC can execute session capability %',routine_signature
          USING ERRCODE='42501';
      END IF;
    END LOOP;
END;
$northstar_sm_retention_security$;
