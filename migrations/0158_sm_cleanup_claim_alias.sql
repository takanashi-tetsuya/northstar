-- Forward-only correction for 0157's PL/pgSQL record/SQL alias collision.
-- Only the first binding-claims DELETE subquery alias changes. Retention,
-- limits, lock order, READ COMMITTED revalidation and capacity accounting are
-- unchanged; candidate remains the exact lease loop record.
-- This does not relax 0157's stopped-writer rollout prerequisites. SQLx applies
-- the replacement and its schema-local security assertions atomically.

DO $northstar_sm_cleanup_claim_alias_precondition$
DECLARE
    migration_schema pg_catalog.text := pg_catalog.current_schema();
    migration_namespace pg_catalog.oid;
    migration_owner pg_catalog.oid;
    routine_oid pg_catalog.oid;
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
    routine_oid:=pg_catalog.to_regprocedure(
        pg_catalog.format('%I.northstar_session_cleanup_live(int8)',migration_schema));
    IF routine_oid IS NULL OR NOT EXISTS(
        SELECT 1 FROM pg_catalog.pg_proc routine
         WHERE routine.oid=routine_oid
           AND routine.pronamespace=migration_namespace
           AND routine.proowner=migration_owner
           AND routine.prokind='f'
    ) THEN
        RAISE EXCEPTION 'session cleanup capability is absent, outside the installation schema, or has the wrong owner'
            USING ERRCODE='42883';
    END IF;
END;
$northstar_sm_cleanup_claim_alias_precondition$;

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
         SELECT expired_claim.connection_id
           FROM deployment_session_binding_claims expired_claim
          WHERE expired_claim.expires_at<=clock_timestamp()
          ORDER BY expired_claim.expires_at,expired_claim.connection_id
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

DO $northstar_sm_cleanup_claim_alias_security$
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
      'northstar_session_cleanup_live(int8)'
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
$northstar_sm_cleanup_claim_alias_security$;
