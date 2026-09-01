-- Make live C2S capacity and XEP-0198 resume state owner-held authorities.
-- The long-lived runtime role receives only the capabilities reconciled by
-- deploy/postgres-init/lib/apply-northstar-grants.sql.  Every function below
-- is schema-local, SECURITY DEFINER, PUBLIC-revoked and postcondition checked
-- at the end of this migration.

DO $northstar_session_capability_precondition$
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
$northstar_session_capability_precondition$;

CREATE FUNCTION northstar_session_delete_expired_live_leases()
RETURNS BIGINT
LANGUAGE SQL
SECURITY DEFINER
AS $$
WITH removed AS (
    DELETE FROM deployment_session_leases
     WHERE lease_until<=clock_timestamp()
     RETURNING 1
)
SELECT pg_catalog.count(*) FROM removed
$$;

CREATE FUNCTION northstar_session_capacity_reconcile_lock()
RETURNS BOOLEAN
LANGUAGE plpgsql
SECURITY DEFINER
AS $$
BEGIN
    LOCK TABLE users,muc_rooms,sm_resume_sessions,deployment_session_leases,
        deployment_capacity_limits,deployment_capacity_shards,
        deployment_capacity_allocations,deployment_account_capacity
      IN SHARE ROW EXCLUSIVE MODE;
    RETURN TRUE;
END;
$$;

CREATE FUNCTION northstar_session_reserve_live(
    requested_connection UUID,requested_user UUID,requested_full_jid TEXT,
    requested_lease_seconds BIGINT,allow_resumable_replacement BOOLEAN
) RETURNS TEXT
LANGUAGE plpgsql
SECURITY DEFINER
AS $$
DECLARE
    current_row deployment_session_leases%ROWTYPE;
    claim_rows BIGINT;
    replacement_allowed BOOLEAN := FALSE;
BEGIN
    IF requested_connection='00000000-0000-0000-0000-000000000000'
       OR requested_user='00000000-0000-0000-0000-000000000000'
       OR octet_length(requested_full_jid) NOT BETWEEN 3 AND 3071
       OR pg_catalog.strpos(requested_full_jid,'/')=0
       OR requested_lease_seconds NOT BETWEEN 1 AND 86400 THEN
        RAISE EXCEPTION 'invalid live-session reservation' USING ERRCODE='22023';
    END IF;
    PERFORM 1 FROM users account
     WHERE account.id=requested_user
       AND NOT account.is_disabled
       AND pg_catalog.split_part(
             pg_catalog.split_part(requested_full_jid,'/',1),'@',1
           )=account.username
       AND pg_catalog.octet_length(pg_catalog.split_part(
             pg_catalog.split_part(requested_full_jid,'/',1),'@',2
           )) BETWEEN 1 AND 253
       AND pg_catalog.split_part(
             pg_catalog.split_part(requested_full_jid,'/',1),'@',3
           )=''
     FOR KEY SHARE;
    IF NOT FOUND THEN RETURN 'conflict'; END IF;
    PERFORM pg_catalog.pg_advisory_xact_lock(
        1314079573,pg_catalog.hashtext(requested_full_jid));
    SELECT * INTO current_row FROM deployment_session_leases
     WHERE full_jid=requested_full_jid FOR UPDATE;
    IF FOUND THEN
        IF current_row.connection_id=requested_connection
           AND current_row.user_id=requested_user THEN
            UPDATE deployment_session_leases
               SET lease_until=GREATEST(
                       lease_until,
                       clock_timestamp()+pg_catalog.make_interval(
                           secs=>requested_lease_seconds::DOUBLE PRECISION)),
                   updated_at=clock_timestamp()
             WHERE connection_id=requested_connection;
            RETURN 'reserved';
        END IF;
        IF current_row.user_id=requested_user THEN
            PERFORM 1 FROM deployment_session_binding_claims claim
             WHERE claim.connection_id=requested_connection
               AND claim.user_id=requested_user
               AND claim.full_jid=requested_full_jid
               AND claim.replaced_connection_id=current_row.connection_id
               AND claim.expires_at>clock_timestamp()
             FOR UPDATE;
            IF FOUND THEN RETURN 'reserved'; END IF;
        END IF;
        IF allow_resumable_replacement
           AND current_row.user_id=requested_user THEN
            PERFORM 1 FROM sm_resume_sessions stream
             WHERE stream.connection_id=current_row.connection_id
               AND stream.user_id=requested_user
               AND stream.full_jid=requested_full_jid
               AND stream.resumable
               AND stream.expires_at>clock_timestamp()
               AND (stream.claim_token IS NULL
                    OR stream.claimed_until<=clock_timestamp())
             FOR SHARE;
            replacement_allowed := FOUND;
        END IF;
        IF replacement_allowed THEN
            INSERT INTO deployment_session_binding_claims(
                connection_id,user_id,full_jid,replaced_connection_id,expires_at)
            VALUES(
                requested_connection,requested_user,requested_full_jid,
                current_row.connection_id,
                clock_timestamp()+pg_catalog.make_interval(
                    secs=>requested_lease_seconds::DOUBLE PRECISION))
            ON CONFLICT(connection_id) DO UPDATE SET
                expires_at=EXCLUDED.expires_at
            WHERE deployment_session_binding_claims.user_id=EXCLUDED.user_id
              AND deployment_session_binding_claims.full_jid=EXCLUDED.full_jid
              AND deployment_session_binding_claims.replaced_connection_id=
                  EXCLUDED.replaced_connection_id;
            GET DIAGNOSTICS claim_rows = ROW_COUNT;
            IF claim_rows=1 THEN RETURN 'replaced_resumable'; END IF;
            RETURN 'conflict';
        END IF;
        IF current_row.lease_until>clock_timestamp() THEN RETURN 'conflict'; END IF;
        DELETE FROM deployment_session_leases
         WHERE connection_id=current_row.connection_id;
    END IF;
    BEGIN
        INSERT INTO deployment_session_leases(
            lease_id,connection_id,user_id,full_jid,lease_until)
        VALUES(
            requested_connection,requested_connection,requested_user,
            requested_full_jid,
            clock_timestamp()+pg_catalog.make_interval(
                secs=>requested_lease_seconds::DOUBLE PRECISION));
    EXCEPTION
        WHEN unique_violation THEN RETURN 'conflict';
        WHEN SQLSTATE 'P0001' THEN RETURN 'capacity_exhausted';
    END;
    RETURN 'reserved';
END;
$$;

CREATE FUNCTION northstar_session_finalize_binding(
    requested_connection UUID,requested_user UUID,requested_full_jid TEXT
) RETURNS BOOLEAN
LANGUAGE plpgsql
SECURITY DEFINER
AS $$
DECLARE current_row deployment_session_leases%ROWTYPE;
BEGIN
    IF requested_connection='00000000-0000-0000-0000-000000000000'
       OR requested_user='00000000-0000-0000-0000-000000000000'
       OR octet_length(requested_full_jid) NOT BETWEEN 3 AND 3071 THEN
        RAISE EXCEPTION 'invalid binding finalization' USING ERRCODE='22023';
    END IF;
    PERFORM pg_catalog.pg_advisory_xact_lock(
        1314079573,pg_catalog.hashtext(requested_full_jid));
    SELECT * INTO current_row FROM deployment_session_leases
     WHERE full_jid=requested_full_jid FOR UPDATE;
    IF NOT FOUND OR current_row.user_id<>requested_user THEN RETURN FALSE; END IF;
    IF current_row.connection_id=requested_connection
       AND current_row.lease_until>clock_timestamp() THEN RETURN TRUE; END IF;
    PERFORM 1
      FROM deployment_session_binding_claims claim
      JOIN sm_resume_sessions stream
        ON stream.connection_id=current_row.connection_id
       AND stream.user_id=current_row.user_id
       AND stream.full_jid=current_row.full_jid
       AND stream.resumable
       AND stream.expires_at>clock_timestamp()
       AND (stream.claim_token IS NULL OR stream.claimed_until<=clock_timestamp())
     WHERE claim.connection_id=requested_connection
       AND claim.user_id=requested_user
       AND claim.full_jid=requested_full_jid
       AND claim.replaced_connection_id=current_row.connection_id
       AND claim.expires_at>clock_timestamp()
     FOR UPDATE OF claim FOR SHARE OF stream;
    RETURN FOUND;
END;
$$;

CREATE FUNCTION northstar_session_publish_binding(
    requested_connection UUID,requested_user UUID,requested_full_jid TEXT,
    requested_lease_seconds BIGINT
) RETURNS BOOLEAN
LANGUAGE plpgsql
SECURITY DEFINER
AS $$
DECLARE current_row deployment_session_leases%ROWTYPE;
DECLARE consumed BIGINT;
BEGIN
    IF requested_lease_seconds NOT BETWEEN 1 AND 86400 THEN
        RAISE EXCEPTION 'invalid binding publication lease' USING ERRCODE='22023';
    END IF;
    PERFORM pg_catalog.pg_advisory_xact_lock(
        1314079573,pg_catalog.hashtext(requested_full_jid));
    SELECT * INTO current_row FROM deployment_session_leases
     WHERE full_jid=requested_full_jid FOR UPDATE;
    IF NOT FOUND OR current_row.user_id<>requested_user THEN RETURN FALSE; END IF;
    IF current_row.connection_id=requested_connection THEN
        RETURN current_row.lease_until>clock_timestamp();
    END IF;
    PERFORM 1
      FROM deployment_session_binding_claims claim
      JOIN sm_resume_sessions stream
        ON stream.connection_id=current_row.connection_id
       AND stream.user_id=current_row.user_id
       AND stream.full_jid=current_row.full_jid
       AND stream.resumable
       AND stream.expires_at>clock_timestamp()
       AND (stream.claim_token IS NULL OR stream.claimed_until<=clock_timestamp())
     WHERE claim.connection_id=requested_connection
       AND claim.user_id=requested_user
       AND claim.full_jid=requested_full_jid
       AND claim.replaced_connection_id=current_row.connection_id
       AND claim.expires_at>clock_timestamp()
     FOR UPDATE OF claim FOR SHARE OF stream;
    IF NOT FOUND THEN RETURN FALSE; END IF;
    UPDATE deployment_session_leases SET
        connection_id=requested_connection,
        lease_until=GREATEST(
            lease_until,
            clock_timestamp()+pg_catalog.make_interval(
                secs=>requested_lease_seconds::DOUBLE PRECISION)),
        updated_at=clock_timestamp()
     WHERE lease_id=current_row.lease_id
       AND connection_id=current_row.connection_id
       AND user_id=requested_user AND full_jid=requested_full_jid;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'binding publication lost its exact incumbent lease'
            USING ERRCODE='55000';
    END IF;
    DELETE FROM deployment_session_binding_claims
     WHERE connection_id=requested_connection
       AND user_id=requested_user AND full_jid=requested_full_jid
       AND replaced_connection_id=current_row.connection_id;
    GET DIAGNOSTICS consumed = ROW_COUNT;
    IF consumed<>1 THEN
        RAISE EXCEPTION 'binding publication lost its exact replacement claim'
            USING ERRCODE='55000';
    END IF;
    RETURN TRUE;
END;
$$;

CREATE FUNCTION northstar_session_transfer_sm(
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

CREATE FUNCTION northstar_session_release_live(requested_connection UUID)
RETURNS BOOLEAN
LANGUAGE plpgsql
SECURITY DEFINER
AS $$
DECLARE claim_rows BIGINT; DECLARE lease_rows BIGINT;
BEGIN
    DELETE FROM deployment_session_binding_claims
     WHERE connection_id=requested_connection;
    GET DIAGNOSTICS claim_rows = ROW_COUNT;
    DELETE FROM deployment_session_leases
     WHERE connection_id=requested_connection;
    GET DIAGNOSTICS lease_rows = ROW_COUNT;
    RETURN claim_rows=1 OR lease_rows=1;
END;
$$;

CREATE FUNCTION northstar_session_refresh_live(
    requested_connections UUID[],requested_lease_seconds BIGINT
) RETURNS TABLE(connection_id UUID)
LANGUAGE SQL
SECURITY DEFINER
AS $$
UPDATE deployment_session_leases lease SET
    lease_until=clock_timestamp()+pg_catalog.make_interval(
        secs=>requested_lease_seconds::DOUBLE PRECISION),
    updated_at=clock_timestamp()
 WHERE lease.connection_id=ANY(requested_connections)
   AND lease.lease_until>clock_timestamp()
   AND requested_lease_seconds BETWEEN 1 AND 86400
RETURNING lease.connection_id
$$;

CREATE FUNCTION northstar_session_cleanup_live(requested_limit BIGINT)
RETURNS BIGINT
LANGUAGE plpgsql
SECURITY DEFINER
AS $$
DECLARE removed BIGINT;
BEGIN
    DELETE FROM deployment_session_binding_claims claim
     WHERE claim.connection_id IN (
         SELECT candidate.connection_id
           FROM deployment_session_binding_claims candidate
          WHERE candidate.expires_at<=clock_timestamp()
          ORDER BY candidate.expires_at,candidate.connection_id
          LIMIT LEAST(GREATEST(requested_limit,1),10000)
          FOR UPDATE SKIP LOCKED
     );
    WITH expired AS MATERIALIZED (
        SELECT lease.connection_id FROM deployment_session_leases lease
         WHERE lease.lease_until<=clock_timestamp()
         ORDER BY lease.lease_until,lease.connection_id
         LIMIT LEAST(GREATEST(requested_limit,1),10000)
         FOR UPDATE SKIP LOCKED
    ), deleted AS (
        DELETE FROM deployment_session_leases lease USING expired
         WHERE lease.connection_id=expired.connection_id RETURNING 1
    ) SELECT pg_catalog.count(*) INTO removed FROM deleted;
    RETURN removed;
END;
$$;

CREATE FUNCTION northstar_session_extend_live(
    requested_connection UUID,requested_lease_seconds BIGINT
) RETURNS BOOLEAN
LANGUAGE plpgsql
SECURITY DEFINER
AS $$
BEGIN
    IF requested_lease_seconds NOT BETWEEN 1 AND 86400 THEN RETURN FALSE; END IF;
    UPDATE deployment_session_leases lease SET
        lease_until=GREATEST(
            lease.lease_until,
            clock_timestamp()+pg_catalog.make_interval(
                secs=>requested_lease_seconds::DOUBLE PRECISION)),
        updated_at=clock_timestamp()
     WHERE lease.connection_id=requested_connection
       AND lease.lease_until>clock_timestamp();
    RETURN FOUND;
END
$$;

CREATE FUNCTION northstar_sm_create(
    requested_id UUID,requested_token_hash BYTEA,requested_user UUID,
    requested_auth_generation BIGINT,requested_full_jid TEXT,
    requested_resource TEXT,requested_server_domain TEXT,
    requested_connection UUID,requested_resume_timeout BIGINT,
    requested_inbound_h BIGINT,requested_outbound_h BIGINT,
    requested_acked_h BIGINT,requested_available BOOLEAN,
    requested_carbons BOOLEAN,requested_priority SMALLINT,
    requested_blocklist BOOLEAN,requested_roster BOOLEAN,
    requested_privacy_list TEXT,requested_privacy BOOLEAN,
    requested_peer_ip INET,requested_device UUID,requested_joined_rooms JSONB,
    requested_directed_presence JSONB,requested_last_presence TEXT,
    requested_live_lease BIGINT,requested_ttl BIGINT
) RETURNS BOOLEAN
LANGUAGE plpgsql
SECURITY DEFINER
AS $$
DECLARE account_username TEXT;
BEGIN
    IF requested_id='00000000-0000-0000-0000-000000000000'
       OR requested_connection='00000000-0000-0000-0000-000000000000'
       OR pg_catalog.octet_length(requested_token_hash)<>32
       OR requested_resume_timeout NOT BETWEEN 1 AND 86400
       OR requested_live_lease NOT BETWEEN 1 AND 86400
       OR requested_ttl NOT BETWEEN 1 AND 86400
       OR requested_inbound_h NOT BETWEEN 0 AND 4294967295
       OR requested_outbound_h NOT BETWEEN 0 AND 4294967295
       OR requested_acked_h NOT BETWEEN 0 AND 4294967295
       OR (CASE pg_catalog.jsonb_typeof(requested_joined_rooms)
             WHEN 'array' THEN pg_catalog.jsonb_array_length(requested_joined_rooms)>256
             ELSE TRUE
          END)
       OR (CASE pg_catalog.jsonb_typeof(requested_directed_presence)
             WHEN 'array' THEN pg_catalog.jsonb_array_length(requested_directed_presence)>1024
             ELSE TRUE
          END)
       OR (requested_last_presence IS NOT NULL AND (
             pg_catalog.octet_length(requested_last_presence) NOT BETWEEN 1 AND 1048576
          )) THEN
        RAISE EXCEPTION 'invalid SM creation request' USING ERRCODE='22023';
    END IF;
    SELECT username INTO account_username FROM users
     WHERE id=requested_user AND auth_generation=requested_auth_generation
       AND NOT is_disabled FOR KEY SHARE;
    IF NOT FOUND
       OR pg_catalog.split_part(requested_full_jid,'/',1)
            <>account_username || '@' || requested_server_domain
       OR pg_catalog.substr(
            requested_full_jid,pg_catalog.strpos(requested_full_jid,'/')+1
          )<>requested_resource THEN
        RETURN FALSE;
    END IF;
    PERFORM 1 FROM deployment_session_leases lease
     WHERE lease.connection_id=requested_connection
       AND lease.user_id=requested_user
       AND lease.full_jid=requested_full_jid
       AND lease.lease_until>clock_timestamp()
     FOR SHARE;
    IF NOT FOUND THEN RETURN FALSE; END IF;
    INSERT INTO sm_resume_sessions(
        id,token_hash,user_id,auth_generation,full_jid,resource,connection_id,
        resume_timeout_seconds,inbound_h,outbound_h,acked_h,available,carbons,
        priority,blocklist_requested,roster_requested,active_privacy_list,
        privacy_requested,peer_ip,user_agent_id,joined_rooms,directed_presence,
        last_presence,live_lease_until,expires_at
    ) VALUES(
        requested_id,requested_token_hash,requested_user,requested_auth_generation,
        requested_full_jid,requested_resource,requested_connection,
        requested_resume_timeout,requested_inbound_h,requested_outbound_h,
        requested_acked_h,requested_available,requested_carbons,requested_priority,
        requested_blocklist,requested_roster,requested_privacy_list,
        requested_privacy,requested_peer_ip,requested_device,requested_joined_rooms,
        requested_directed_presence,requested_last_presence,
        clock_timestamp()+pg_catalog.make_interval(
            secs=>requested_live_lease::DOUBLE PRECISION),
        clock_timestamp()+pg_catalog.make_interval(
            secs=>requested_ttl::DOUBLE PRECISION)
    );
    RETURN TRUE;
END;
$$;

CREATE FUNCTION northstar_sm_update_snapshot(
    requested_id UUID,requested_connection UUID,
    requested_inbound_h BIGINT,requested_outbound_h BIGINT,
    requested_acked_h BIGINT,requested_available BOOLEAN,
    requested_carbons BOOLEAN,requested_priority SMALLINT,
    requested_blocklist BOOLEAN,requested_roster BOOLEAN,
    requested_privacy_list TEXT,requested_privacy BOOLEAN,
    requested_peer_ip INET,requested_device UUID,requested_joined_rooms JSONB,
    requested_directed_presence JSONB,requested_last_presence TEXT,
    requested_suspend BOOLEAN,requested_live_lease BIGINT,requested_ttl BIGINT
) RETURNS BOOLEAN
LANGUAGE plpgsql
SECURITY DEFINER
AS $$
BEGIN
    IF requested_live_lease NOT BETWEEN 0 AND 86400
       OR requested_ttl NOT BETWEEN 1 AND 86400
       OR requested_inbound_h NOT BETWEEN 0 AND 4294967295
       OR requested_outbound_h NOT BETWEEN 0 AND 4294967295
       OR requested_acked_h NOT BETWEEN 0 AND 4294967295
       OR (CASE pg_catalog.jsonb_typeof(requested_joined_rooms)
             WHEN 'array' THEN pg_catalog.jsonb_array_length(requested_joined_rooms)>256
             ELSE TRUE
          END)
       OR (CASE pg_catalog.jsonb_typeof(requested_directed_presence)
             WHEN 'array' THEN pg_catalog.jsonb_array_length(requested_directed_presence)>1024
             ELSE TRUE
          END)
       OR (requested_last_presence IS NOT NULL AND (
             pg_catalog.octet_length(requested_last_presence) NOT BETWEEN 1 AND 1048576
          )) THEN
        RETURN FALSE;
    END IF;
    UPDATE sm_resume_sessions stream SET
        inbound_h=requested_inbound_h,outbound_h=requested_outbound_h,
        acked_h=requested_acked_h,available=requested_available,
        carbons=requested_carbons,priority=requested_priority,
        blocklist_requested=requested_blocklist,roster_requested=requested_roster,
        active_privacy_list=requested_privacy_list,
        privacy_requested=requested_privacy,peer_ip=requested_peer_ip,
        user_agent_id=requested_device,joined_rooms=requested_joined_rooms,
        directed_presence=requested_directed_presence,
        last_presence=requested_last_presence,resumable=requested_suspend,
        live_lease_until=clock_timestamp()+pg_catalog.make_interval(
            secs=>requested_live_lease::DOUBLE PRECISION),
        expires_at=clock_timestamp()+pg_catalog.make_interval(
            secs=>requested_ttl::DOUBLE PRECISION),updated_at=clock_timestamp()
     WHERE stream.id=requested_id AND stream.connection_id=requested_connection
       AND stream.claim_token IS NULL AND NOT stream.resumable;
    RETURN FOUND;
END;
$$;

CREATE FUNCTION northstar_sm_remove_memberships(
    requested_id UUID,requested_connection UUID,requested_removals JSONB
) RETURNS BOOLEAN
LANGUAGE plpgsql
SECURITY DEFINER
AS $$
BEGIN
    IF pg_catalog.jsonb_typeof(requested_removals)<>'array'
       OR pg_catalog.jsonb_array_length(requested_removals)>256 THEN RETURN FALSE; END IF;
    UPDATE sm_resume_sessions stream SET
        joined_rooms=COALESCE((
          SELECT pg_catalog.jsonb_agg(entries.value ORDER BY entries.ordinal)
            FROM pg_catalog.jsonb_array_elements(stream.joined_rooms)
                 WITH ORDINALITY AS entries(value,ordinal)
           WHERE NOT EXISTS(
             SELECT 1 FROM pg_catalog.jsonb_array_elements(requested_removals) removal(value)
              WHERE removal.value->>'room_jid'=entries.value->>'room_jid'
                AND removal.value->>'nick'=entries.value->>'nick'
           )
        ),'[]'::JSONB),updated_at=clock_timestamp()
     WHERE stream.id=requested_id AND stream.connection_id=requested_connection
       AND stream.claim_token IS NULL AND NOT stream.resumable;
    RETURN FOUND;
END;
$$;

CREATE FUNCTION northstar_sm_exact_owner_state(
    requested_id UUID,requested_connection UUID,requested_user UUID,
    requested_auth_generation BIGINT
) RETURNS TEXT
LANGUAGE plpgsql
SECURITY DEFINER
AS $$
DECLARE current_resumable BOOLEAN;
BEGIN
    PERFORM 1 FROM users account
     WHERE account.id=requested_user
       AND account.auth_generation=requested_auth_generation
       AND NOT account.is_disabled FOR SHARE;
    IF NOT FOUND THEN RETURN 'missing'; END IF;
    SELECT stream.resumable INTO current_resumable FROM sm_resume_sessions stream
     WHERE stream.id=requested_id AND stream.connection_id=requested_connection
       AND stream.user_id=requested_user
       AND stream.auth_generation=requested_auth_generation
       AND stream.claim_token IS NULL FOR UPDATE;
    IF NOT FOUND THEN RETURN 'missing'; END IF;
    IF current_resumable THEN RETURN 'resumable'; END IF;
    RETURN 'active';
END;
$$;

CREATE FUNCTION northstar_sm_claim(
    requested_token_hash BYTEA,requested_user UUID,requested_claimant_ip INET,
    requested_device UUID,requested_ip_policy TEXT,require_same_device BOOLEAN,
    requested_claim_token UUID,requested_claim_lease BIGINT
) RETURNS TABLE(
    status TEXT,session_id UUID,claim_token UUID,full_jid TEXT,resource TEXT,
    resume_timeout_seconds BIGINT,inbound_h BIGINT,acked_h BIGINT,
    available BOOLEAN,carbons BOOLEAN,priority SMALLINT,
    blocklist_requested BOOLEAN,roster_requested BOOLEAN,
    active_privacy_list TEXT,privacy_requested BOOLEAN,user_agent_id UUID,
    joined_rooms JSONB,directed_presence JSONB,last_presence TEXT
)
LANGUAGE plpgsql
SECURITY DEFINER
AS $$
DECLARE stream RECORD;
DECLARE ip_matches BOOLEAN;
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
       AND s.expires_at>clock_timestamp()
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
    -- `require_same_device` is deliberately fail-closed. Legacy snapshots
    -- without a recorded user_agent_id cannot prove device continuity and a
    -- claimant without an identifier cannot satisfy the policy either.
    -- Operators needing compatibility with those rows must leave the policy
    -- disabled instead of receiving silently weaker strict-mode semantics.
    IF NOT COALESCE(ip_matches,FALSE)
       OR (require_same_device AND (
              stream.user_agent_id IS NULL
              OR requested_device IS NULL
              OR stream.user_agent_id IS DISTINCT FROM requested_device
          )) THEN
        status:='rejected'; RETURN NEXT; RETURN;
    END IF;
    IF NOT (stream.resumable OR stream.live_lease_until<=clock_timestamp())
       OR (stream.claimed_until IS NOT NULL
           AND stream.claimed_until>clock_timestamp()) THEN
        status:='pending'; RETURN NEXT; RETURN;
    END IF;
    UPDATE sm_resume_sessions s SET
        claim_token=requested_claim_token,
        claimed_until=clock_timestamp()+pg_catalog.make_interval(
            secs=>requested_claim_lease::DOUBLE PRECISION),
        updated_at=clock_timestamp()
     WHERE s.id=stream.id
       AND (s.claim_token IS NULL OR s.claimed_until<=clock_timestamp());
    IF NOT FOUND THEN status:='pending'; RETURN NEXT; RETURN; END IF;
    status:='claimed'; session_id:=stream.id; claim_token:=requested_claim_token;
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

CREATE FUNCTION northstar_sm_claim_authority(
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
   AND stream.claimed_until>clock_timestamp() AND NOT account.is_disabled
   AND stream.auth_generation=account.auth_generation
 FOR KEY SHARE OF account
$$;

CREATE FUNCTION northstar_sm_activate(
    requested_id UUID,requested_claim_token UUID,requested_connection UUID,
    requested_client_h BIGINT,requested_peer_ip INET,requested_device UUID,
    requested_live_lease BIGINT,requested_ttl BIGINT
) RETURNS BIGINT
LANGUAGE plpgsql
SECURITY DEFINER
AS $$
DECLARE result BIGINT;
BEGIN
    IF requested_client_h NOT BETWEEN 0 AND 4294967295
       OR requested_live_lease NOT BETWEEN 1 AND 86400
       OR requested_ttl NOT BETWEEN 1 AND 86400 THEN RETURN NULL; END IF;
    UPDATE sm_resume_sessions stream SET
        connection_id=requested_connection,acked_h=requested_client_h,
        peer_ip=requested_peer_ip,
        user_agent_id=COALESCE(requested_device,stream.user_agent_id),
        resumable=FALSE,
        live_lease_until=clock_timestamp()+pg_catalog.make_interval(
            secs=>requested_live_lease::DOUBLE PRECISION),
        expires_at=clock_timestamp()+pg_catalog.make_interval(
            secs=>requested_ttl::DOUBLE PRECISION),
        claim_token=NULL,claimed_until=NULL,updated_at=clock_timestamp()
      FROM users account
     WHERE stream.id=requested_id AND stream.claim_token=requested_claim_token
       AND stream.claimed_until>clock_timestamp() AND account.id=stream.user_id
       AND NOT account.is_disabled
       AND stream.auth_generation=account.auth_generation
     RETURNING stream.outbound_h INTO result;
    RETURN result;
END;
$$;

CREATE FUNCTION northstar_sm_release_claim(
    requested_id UUID,requested_claim_token UUID
) RETURNS BOOLEAN
LANGUAGE plpgsql
SECURITY DEFINER
AS $$
BEGIN
    UPDATE sm_resume_sessions SET claim_token=NULL,claimed_until=NULL,
        updated_at=clock_timestamp()
     WHERE id=requested_id AND claim_token=requested_claim_token;
    RETURN FOUND;
END;
$$;

CREATE FUNCTION northstar_sm_revoke(requested_id UUID)
RETURNS BOOLEAN
LANGUAGE plpgsql
SECURITY DEFINER
AS $$
BEGIN
    DELETE FROM sm_resume_sessions
     WHERE id=requested_id AND (claim_token IS NULL OR claimed_until<=clock_timestamp());
    RETURN FOUND;
END;
$$;

CREATE FUNCTION northstar_sm_take_teardown(
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
        claim_token=requested_token,
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

CREATE FUNCTION northstar_sm_teardown_pending(
    requested_scope TEXT,requested_id UUID,requested_user UUID,
    requested_generation BIGINT,requested_full_jid TEXT,requested_token UUID
) RETURNS BIGINT
LANGUAGE sql
SECURITY DEFINER
AS $$
SELECT pg_catalog.count(*) FROM sm_resume_sessions stream
 WHERE stream.claim_token IS DISTINCT FROM requested_token
   AND (CASE requested_scope
     WHEN 'single' THEN stream.id=requested_id
     WHEN 'user' THEN stream.user_id=requested_user
     WHEN 'before_generation' THEN stream.user_id=requested_user
                                AND stream.auth_generation<requested_generation
     WHEN 'full' THEN stream.full_jid=requested_full_jid
     WHEN 'all' THEN TRUE
     WHEN 'expired' THEN stream.expires_at<=clock_timestamp()
     ELSE FALSE END)
$$;

CREATE FUNCTION northstar_sm_count(
    requested_scope TEXT,requested_user UUID,
    requested_generation BIGINT,requested_full_jid TEXT
) RETURNS BIGINT
LANGUAGE sql
SECURITY DEFINER
AS $$
SELECT pg_catalog.count(*) FROM sm_resume_sessions stream
 WHERE CASE requested_scope
   WHEN 'user' THEN stream.user_id=requested_user
   WHEN 'before_generation' THEN stream.user_id=requested_user
                              AND stream.auth_generation<requested_generation
   WHEN 'full' THEN stream.full_jid=requested_full_jid
   WHEN 'all' THEN TRUE
   WHEN 'active' THEN stream.expires_at>clock_timestamp()
   ELSE FALSE END
$$;

CREATE FUNCTION northstar_sm_finalize_teardown(
    requested_id UUID,requested_token UUID
) RETURNS BOOLEAN
LANGUAGE plpgsql
SECURITY DEFINER
AS $$
BEGIN
    DELETE FROM sm_resume_sessions
     WHERE id=requested_id AND claim_token=requested_token
       AND expires_at<=clock_timestamp();
    IF FOUND THEN RETURN TRUE; END IF;
    RETURN NOT EXISTS(SELECT 1 FROM sm_resume_sessions WHERE id=requested_id);
END;
$$;

CREATE FUNCTION northstar_sm_lock_suspended(requested_id UUID)
RETURNS BIGINT
LANGUAGE sql
SECURITY DEFINER
AS $$
SELECT stream.outbound_h FROM sm_resume_sessions stream
 WHERE stream.id=requested_id AND stream.resumable
   AND stream.expires_at>clock_timestamp()
 FOR UPDATE
$$;

CREATE FUNCTION northstar_sm_advance_suspended(
    requested_id UUID,expected_outbound BIGINT,next_outbound BIGINT
) RETURNS BOOLEAN
LANGUAGE plpgsql
SECURITY DEFINER
AS $$
BEGIN
    IF expected_outbound NOT BETWEEN 0 AND 4294967295
       OR next_outbound NOT BETWEEN 0 AND 4294967295 THEN RETURN FALSE; END IF;
    UPDATE sm_resume_sessions SET outbound_h=next_outbound,
        updated_at=clock_timestamp()
     WHERE id=requested_id AND outbound_h=expected_outbound
       AND resumable AND expires_at>clock_timestamp();
    RETURN FOUND;
END;
$$;

CREATE FUNCTION northstar_sm_expire_before_generation(
    requested_user UUID,requested_generation BIGINT
) RETURNS BIGINT
LANGUAGE plpgsql
SECURITY DEFINER
AS $$
DECLARE affected BIGINT;
BEGIN
    IF requested_generation<=0 THEN RETURN 0; END IF;
    UPDATE sm_resume_sessions SET resumable=FALSE,
        live_lease_until=clock_timestamp(),expires_at=clock_timestamp(),
        updated_at=clock_timestamp()
     WHERE user_id=requested_user AND auth_generation<requested_generation;
    GET DIAGNOSTICS affected=ROW_COUNT;
    RETURN affected;
END;
$$;

CREATE FUNCTION northstar_sm_privacy_list_in_use(
    requested_user UUID,requested_list TEXT
) RETURNS BOOLEAN
LANGUAGE sql
SECURITY DEFINER
AS $$
SELECT EXISTS(
  SELECT 1 FROM sm_resume_sessions stream
   WHERE stream.user_id=requested_user
     AND stream.active_privacy_list=requested_list
     AND stream.expires_at>clock_timestamp()
)
$$;

CREATE FUNCTION northstar_sm_privacy_state(requested_id UUID)
RETURNS TABLE(user_id UUID,active_privacy_list TEXT)
LANGUAGE sql
SECURITY DEFINER
AS $$
SELECT stream.user_id,stream.active_privacy_list::pg_catalog.text
  FROM sm_resume_sessions stream
 WHERE stream.id=requested_id AND stream.expires_at>clock_timestamp()
$$;

CREATE FUNCTION northstar_session_capability_catalog_healthy(
    requested_schema TEXT
) RETURNS BOOLEAN
LANGUAGE sql
SECURITY DEFINER
STABLE
AS $$
WITH namespace AS (
  SELECT oid,nspowner FROM pg_catalog.pg_namespace WHERE nspname=requested_schema
), protected_relations AS (
  SELECT relation.oid,relation.relname,relation.relowner,relation.relacl,
         namespace.nspowner
    FROM namespace JOIN pg_catalog.pg_class relation
      ON relation.relnamespace=namespace.oid
   WHERE relation.relname IN (
     'deployment_session_leases','deployment_session_binding_claims','sm_resume_sessions'
   ) AND relation.relkind IN ('r','p')
), expected_routine(signature) AS (
  VALUES
    ('northstar_session_delete_expired_live_leases()'),
    ('northstar_session_capacity_reconcile_lock()'),
    ('northstar_session_reserve_live(uuid,uuid,text,int8,bool)'),
    ('northstar_session_finalize_binding(uuid,uuid,text)'),
    ('northstar_session_publish_binding(uuid,uuid,text,int8)'),
    ('northstar_session_transfer_sm(uuid,uuid,uuid,uuid,uuid,text,int8)'),
    ('northstar_session_release_live(uuid)'),
    ('northstar_session_refresh_live(uuid[],int8)'),
    ('northstar_session_cleanup_live(int8)'),
    ('northstar_session_extend_live(uuid,int8)'),
    ('northstar_sm_create(uuid,bytea,uuid,int8,text,text,text,uuid,int8,int8,int8,int8,bool,bool,int2,bool,bool,text,bool,inet,uuid,jsonb,jsonb,text,int8,int8)'),
    ('northstar_sm_update_snapshot(uuid,uuid,int8,int8,int8,bool,bool,int2,bool,bool,text,bool,inet,uuid,jsonb,jsonb,text,bool,int8,int8)'),
    ('northstar_sm_remove_memberships(uuid,uuid,jsonb)'),
    ('northstar_sm_exact_owner_state(uuid,uuid,uuid,int8)'),
    ('northstar_sm_claim(bytea,uuid,inet,uuid,text,bool,uuid,int8)'),
    ('northstar_sm_claim_authority(uuid,uuid)'),
    ('northstar_sm_activate(uuid,uuid,uuid,int8,inet,uuid,int8,int8)'),
    ('northstar_sm_release_claim(uuid,uuid)'),
    ('northstar_sm_revoke(uuid)'),
    ('northstar_sm_take_teardown(text,uuid,uuid,int8,text,uuid,int8)'),
    ('northstar_sm_teardown_pending(text,uuid,uuid,int8,text,uuid)'),
    ('northstar_sm_count(text,uuid,int8,text)'),
    ('northstar_sm_finalize_teardown(uuid,uuid)'),
    ('northstar_sm_lock_suspended(uuid)'),
    ('northstar_sm_advance_suspended(uuid,int8,int8)'),
    ('northstar_sm_expire_before_generation(uuid,int8)'),
    ('northstar_sm_privacy_list_in_use(uuid,text)'),
    ('northstar_sm_privacy_state(uuid)'),
    ('northstar_session_capability_catalog_healthy(text)')
), resolved_routine AS (
  SELECT expected.signature,
         pg_catalog.to_regprocedure(
           pg_catalog.format('%I.',requested_schema)||expected.signature
         ) AS oid
    FROM expected_routine expected
), protected_routines AS (
  SELECT expected.signature,expected.oid AS expected_oid,
          routine.oid,routine.proname,routine.proowner,routine.prosecdef,
          routine.prokind,
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
  table_name,trigger_name,function_signature,expected_tgtype,expected_update_columns
) AS (
  VALUES
    ('deployment_session_leases','deployment_session_leases_capacity_insert',
     'northstar_session_capacity_insert()',5::pg_catalog.int2,
     ARRAY[]::pg_catalog.text[]),
    ('deployment_session_leases','deployment_session_leases_capacity_delete',
     'northstar_session_capacity_delete()',9::pg_catalog.int2,
     ARRAY[]::pg_catalog.text[]),
    ('deployment_session_leases','deployment_session_leases_capacity_update',
     'northstar_session_capacity_update()',17::pg_catalog.int2,
     ARRAY['lease_id','connection_id','user_id','full_jid']::pg_catalog.text[]),
    ('sm_resume_sessions','sm_resume_sessions_deployment_capacity_insert',
     'northstar_sm_capacity_insert()',5::pg_catalog.int2,
     ARRAY[]::pg_catalog.text[]),
    ('sm_resume_sessions','sm_resume_sessions_deployment_capacity_delete',
     'northstar_sm_capacity_delete()',9::pg_catalog.int2,
     ARRAY[]::pg_catalog.text[])
), protected_triggers AS (
  SELECT expected.*,trigger.oid,trigger.tgfoid,trigger.tgtype,
         trigger.tgenabled,trigger.tgqual,trigger.tgnargs,trigger.tgargs,
         trigger.tgconstraint,trigger.tgdeferrable,trigger.tginitdeferred,
          trigger.tgparentid,routine.proowner,routine.prokind,
          routine.prosecdef,routine.proconfig,routine.prorettype,
          routine.pronargs,routine.provariadic,
         ARRAY(
           SELECT attribute.attname::pg_catalog.text
             FROM pg_catalog.unnest(
                    trigger.tgattr::pg_catalog.int2[]
                  ) WITH ORDINALITY selected(attnum,position)
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
     AND relation.relname=expected.table_name
     AND relation.relkind IN ('r','p')
    LEFT JOIN pg_catalog.pg_trigger trigger
      ON trigger.tgrelid=relation.oid
     AND trigger.tgname=expected.trigger_name
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
), public_relation_acl AS (
  SELECT 1 FROM protected_relations relation
  CROSS JOIN LATERAL pg_catalog.aclexplode(COALESCE(
    relation.relacl,pg_catalog.acldefault('r',relation.relowner)
  )) privilege WHERE privilege.grantee=0
), unexpected_relation_acl AS (
  -- Inspect the ACL catalog itself, rather than only SESSION_USER's effective
  -- privileges.  Otherwise an obsolete or compromised auxiliary role could
  -- retain DML or a table-wide SM SELECT while runtime startup still reported
  -- this authority boundary as healthy. A deliberately owner-reused localhost
  -- development process has no workload roles, so its catalog must instead be
  -- owner-only: any non-owner grant is drift in that mode.
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
        OR
        (relation.relname IN (
           'deployment_session_leases','deployment_session_binding_claims',
           'sm_resume_sessions'
         ) AND privilege.grantee=(
           SELECT oid FROM pg_catalog.pg_roles WHERE rolname='northstar_backup'
         ))
      ),FALSE
    )
), unexpected_column_acl AS (
  -- Runtime's non-secret SM projection is the only non-owner column ACL.  In
  -- particular token_hash, claim_token and peer_ip must never be inherited by
  -- an arbitrary grantee. Backup uses one canonical table SELECT instead.
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
      )
      AND privilege.privilege_type='SELECT' AND NOT privilege.is_grantable
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
   WHERE routine.oid IS NULL
      OR routine.expected_oid IS NULL
       OR routine.proowner<>routine.nspowner
       OR NOT routine.prosecdef
       OR routine.prokind<>'f'
       OR routine.proconfig IS DISTINCT FROM ARRAY[
            pg_catalog.format('search_path=pg_catalog, %I, pg_temp',requested_schema)
          ]::pg_catalog.text[]
       OR (SELECT pg_catalog.count(*)
             FROM pg_catalog.aclexplode(COALESCE(
               routine.proacl,pg_catalog.acldefault('f',routine.proowner)
             )) privilege)<>CASE
               WHEN SESSION_USER=pg_catalog.pg_get_userbyid(routine.nspowner)
                 THEN 1
               ELSE 2
             END
       OR EXISTS(
            SELECT 1 FROM pg_catalog.aclexplode(COALESCE(
              routine.proacl,pg_catalog.acldefault('f',routine.proowner)
            )) privilege
              WHERE privilege.privilege_type<>'EXECUTE'
                 OR privilege.is_grantable
                 OR privilege.grantor<>routine.proowner
                 OR (
                   SESSION_USER=pg_catalog.pg_get_userbyid(routine.nspowner)
                   AND privilege.grantee<>routine.proowner
                 )
                 OR (
                   SESSION_USER<>pg_catalog.pg_get_userbyid(routine.nspowner)
                   AND privilege.grantee<>routine.proowner
                   AND privilege.grantee IS DISTINCT FROM (
                         SELECT role.oid FROM pg_catalog.pg_roles role
                          WHERE role.rolname='northstar_runtime'
                       )
                 )
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
       OR (SESSION_USER<>pg_catalog.pg_get_userbyid(routine.nspowner) AND NOT EXISTS(
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
            'peer_ip','SELECT'))
)
SELECT (SELECT pg_catalog.count(*)=1 FROM namespace)
  AND (SELECT pg_catalog.count(*)=3 AND pg_catalog.bool_and(relowner=nspowner)
         FROM protected_relations)
  AND NOT EXISTS(SELECT 1 FROM public_relation_acl)
  AND NOT EXISTS(SELECT 1 FROM unexpected_relation_acl)
  AND NOT EXISTS(SELECT 1 FROM unexpected_column_acl)
  AND NOT EXISTS(SELECT 1 FROM routine_acl_drift)
  AND NOT EXISTS(SELECT 1 FROM unexpected_session_routine)
  AND NOT EXISTS(SELECT 1 FROM runtime_dml_acl)
  AND NOT EXISTS(SELECT 1 FROM sensitive_sm_acl)
  AND NOT EXISTS(SELECT 1 FROM unexpected_trigger)
  AND (SELECT pg_catalog.count(*)=5 AND pg_catalog.bool_and(
         oid IS NOT NULL AND expected_function_oid IS NOT NULL
          AND tgfoid=expected_function_oid AND tgtype=expected_tgtype
          AND update_columns=expected_update_columns
          AND tgenabled='O' AND tgqual IS NULL
          AND tgnargs=0 AND pg_catalog.octet_length(tgargs)=0
          AND tgconstraint=0 AND NOT tgdeferrable AND NOT tginitdeferred
           AND tgparentid=0 AND proowner=nspowner
           AND prokind='f' AND NOT prosecdef
           AND proconfig IS NOT DISTINCT FROM ARRAY[
             pg_catalog.format(
               'search_path=pg_catalog, %I, pg_temp',requested_schema
             )
           ]::pg_catalog.text[]
           AND prorettype='pg_catalog.trigger'::pg_catalog.regtype
           AND pronargs=0 AND provariadic=0
       ) FROM protected_triggers)
  AND (SELECT pg_catalog.count(*)=(SELECT pg_catalog.count(*) FROM expected_routine)
         AND pg_catalog.bool_and(oid IS NOT NULL) FROM protected_routines)
$$;

DO $northstar_session_capability_security$
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
      'northstar_session_delete_expired_live_leases()',
      'northstar_session_capacity_reconcile_lock()',
      'northstar_session_reserve_live(uuid,uuid,text,int8,bool)',
      'northstar_session_finalize_binding(uuid,uuid,text)',
      'northstar_session_publish_binding(uuid,uuid,text,int8)',
      'northstar_session_transfer_sm(uuid,uuid,uuid,uuid,uuid,text,int8)',
      'northstar_session_release_live(uuid)',
      'northstar_session_refresh_live(uuid[],int8)',
      'northstar_session_cleanup_live(int8)',
      'northstar_session_extend_live(uuid,int8)',
      'northstar_sm_create(uuid,bytea,uuid,int8,text,text,text,uuid,int8,int8,int8,int8,bool,bool,int2,bool,bool,text,bool,inet,uuid,jsonb,jsonb,text,int8,int8)',
      'northstar_sm_update_snapshot(uuid,uuid,int8,int8,int8,bool,bool,int2,bool,bool,text,bool,inet,uuid,jsonb,jsonb,text,bool,int8,int8)',
      'northstar_sm_remove_memberships(uuid,uuid,jsonb)',
      'northstar_sm_exact_owner_state(uuid,uuid,uuid,int8)',
      'northstar_sm_claim(bytea,uuid,inet,uuid,text,bool,uuid,int8)',
      'northstar_sm_claim_authority(uuid,uuid)',
      'northstar_sm_activate(uuid,uuid,uuid,int8,inet,uuid,int8,int8)',
      'northstar_sm_release_claim(uuid,uuid)',
      'northstar_sm_revoke(uuid)',
      'northstar_sm_take_teardown(text,uuid,uuid,int8,text,uuid,int8)',
      'northstar_sm_teardown_pending(text,uuid,uuid,int8,text,uuid)',
      'northstar_sm_count(text,uuid,int8,text)',
      'northstar_sm_finalize_teardown(uuid,uuid)',
      'northstar_sm_lock_suspended(uuid)',
      'northstar_sm_advance_suspended(uuid,int8,int8)',
      'northstar_sm_expire_before_generation(uuid,int8)',
      'northstar_sm_privacy_list_in_use(uuid,text)',
      'northstar_sm_privacy_state(uuid)',
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
    IF EXISTS(
      SELECT 1 FROM (VALUES
        ('deployment_session_leases'),('deployment_session_binding_claims'),
        ('sm_resume_sessions')
      ) protected(name)
      LEFT JOIN pg_catalog.pg_class relation
        ON relation.oid=pg_catalog.to_regclass(
          pg_catalog.format('%I.%I',migration_schema,protected.name))
      LEFT JOIN pg_catalog.pg_namespace namespace
        ON namespace.oid=relation.relnamespace
      WHERE relation.oid IS NULL OR relation.relowner<>namespace.nspowner
    ) THEN
      RAISE EXCEPTION 'session authority tables are absent or not migration-owner held'
        USING ERRCODE='55000';
    END IF;
    IF EXISTS(
      WITH expected(
        table_name,trigger_name,function_signature,expected_tgtype,
        expected_update_columns
      ) AS (
        VALUES
          ('deployment_session_leases','deployment_session_leases_capacity_insert',
           'northstar_session_capacity_insert()',5::pg_catalog.int2,
           ARRAY[]::pg_catalog.text[]),
          ('deployment_session_leases','deployment_session_leases_capacity_delete',
           'northstar_session_capacity_delete()',9::pg_catalog.int2,
           ARRAY[]::pg_catalog.text[]),
          ('deployment_session_leases','deployment_session_leases_capacity_update',
           'northstar_session_capacity_update()',17::pg_catalog.int2,
           ARRAY['lease_id','connection_id','user_id','full_jid']::pg_catalog.text[]),
          ('sm_resume_sessions','sm_resume_sessions_deployment_capacity_insert',
           'northstar_sm_capacity_insert()',5::pg_catalog.int2,
           ARRAY[]::pg_catalog.text[]),
          ('sm_resume_sessions','sm_resume_sessions_deployment_capacity_delete',
           'northstar_sm_capacity_delete()',9::pg_catalog.int2,
           ARRAY[]::pg_catalog.text[])
      )
      SELECT 1 FROM expected
      LEFT JOIN pg_catalog.pg_class relation
        ON relation.oid=pg_catalog.to_regclass(
             pg_catalog.format('%I.%I',migration_schema,expected.table_name))
      LEFT JOIN pg_catalog.pg_trigger trigger
        ON trigger.tgrelid=relation.oid
       AND trigger.tgname=expected.trigger_name
       AND NOT trigger.tgisinternal
      LEFT JOIN pg_catalog.pg_proc routine ON routine.oid=trigger.tgfoid
       WHERE trigger.oid IS NULL
          OR trigger.tgfoid IS DISTINCT FROM pg_catalog.to_regprocedure(
               pg_catalog.format('%I.',migration_schema)||expected.function_signature)
          OR trigger.tgtype<>expected.expected_tgtype
          OR ARRAY(
               SELECT attribute.attname::pg_catalog.text
                 FROM pg_catalog.unnest(
                        trigger.tgattr::pg_catalog.int2[]
                      ) WITH ORDINALITY selected(attnum,position)
                 JOIN pg_catalog.pg_attribute attribute
                   ON attribute.attrelid=relation.oid
                  AND attribute.attnum=selected.attnum
                ORDER BY selected.position
             )<>expected.expected_update_columns
          OR trigger.tgenabled<>'O' OR trigger.tgqual IS NOT NULL
          OR trigger.tgnargs<>0 OR pg_catalog.octet_length(trigger.tgargs)<>0
           OR trigger.tgconstraint<>0 OR trigger.tgdeferrable
           OR trigger.tginitdeferred OR trigger.tgparentid<>0
           OR routine.prokind<>'f' OR routine.prosecdef
           OR routine.proconfig IS DISTINCT FROM ARRAY[
                pg_catalog.format(
                  'search_path=pg_catalog, %I, pg_temp',migration_schema
                )
              ]::pg_catalog.text[]
           OR routine.prorettype<>'pg_catalog.trigger'::pg_catalog.regtype
           OR routine.pronargs<>0 OR routine.provariadic<>0
           OR routine.proowner<>(SELECT namespace.nspowner
               FROM pg_catalog.pg_namespace namespace
              WHERE namespace.nspname=migration_schema)
    ) OR EXISTS(
      SELECT 1 FROM pg_catalog.pg_trigger trigger
      JOIN pg_catalog.pg_class relation ON relation.oid=trigger.tgrelid
      JOIN pg_catalog.pg_namespace namespace ON namespace.oid=relation.relnamespace
      LEFT JOIN (VALUES
        ('deployment_session_leases','deployment_session_leases_capacity_insert'),
        ('deployment_session_leases','deployment_session_leases_capacity_delete'),
        ('deployment_session_leases','deployment_session_leases_capacity_update'),
        ('sm_resume_sessions','sm_resume_sessions_deployment_capacity_insert'),
        ('sm_resume_sessions','sm_resume_sessions_deployment_capacity_delete')
      ) expected(table_name,trigger_name)
        ON expected.table_name=relation.relname
       AND expected.trigger_name=trigger.tgname
       WHERE namespace.nspname=migration_schema
         AND relation.relname IN ('deployment_session_leases','sm_resume_sessions')
         AND NOT trigger.tgisinternal AND expected.trigger_name IS NULL
    ) THEN
      RAISE EXCEPTION 'session authority trigger manifest is missing, substituted, disabled, conditional, or contains extras'
        USING ERRCODE='55000';
    END IF;
END;
$northstar_session_capability_security$;

REVOKE ALL ON TABLE deployment_session_leases,
    deployment_session_binding_claims,sm_resume_sessions FROM PUBLIC;
