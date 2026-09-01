-- Replace fixed application-side polling for a competing XEP-0198 resume
-- with a transactionally ordered PostgreSQL authority stream. The upgrade is
-- stopped-writer: northstar_sm_claim keeps its input signature but receives a
-- richer TABLE projection, so the old routine is dropped and recreated in the
-- same migration transaction.

ALTER TABLE sm_resume_sessions
    ADD COLUMN state_version BIGINT NOT NULL DEFAULT 1,
    ADD CONSTRAINT sm_resume_sessions_state_version_positive
        CHECK (state_version > 0);

CREATE FUNCTION northstar_sm_state_version()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path FROM CURRENT
AS $$
BEGIN
    IF OLD.state_version = 9223372036854775807 THEN
        RAISE EXCEPTION 'SM authority state version exhausted'
            USING ERRCODE = '54000';
    END IF;
    NEW.state_version := OLD.state_version + 1;
    RETURN NEW;
END;
$$;

CREATE FUNCTION northstar_sm_state_notify()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path FROM CURRENT
AS $$
DECLARE
    changed_id UUID;
    changed_version BIGINT;
BEGIN
    IF TG_OP = 'DELETE' THEN
        changed_id := OLD.id;
        IF OLD.state_version = 9223372036854775807 THEN
            RAISE EXCEPTION 'SM authority state version exhausted'
                USING ERRCODE = '54000';
        END IF;
        changed_version := OLD.state_version + 1;
    ELSE
        changed_id := NEW.id;
        changed_version := NEW.state_version;
    END IF;
    PERFORM pg_catalog.pg_notify(
        'northstar_sm_authority_v1',
        pg_catalog.json_build_object(
            'schema', TG_TABLE_SCHEMA,
            'session_id', changed_id,
            'state_version', changed_version
        )::TEXT
    );
    IF TG_OP = 'DELETE' THEN
        RETURN OLD;
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER sm_resume_sessions_authority_version
BEFORE UPDATE ON sm_resume_sessions
FOR EACH ROW EXECUTE FUNCTION northstar_sm_state_version();

CREATE TRIGGER sm_resume_sessions_authority_notify
AFTER INSERT OR UPDATE OR DELETE ON sm_resume_sessions
FOR EACH ROW EXECUTE FUNCTION northstar_sm_state_notify();

DROP FUNCTION northstar_sm_claim(BYTEA,UUID,INET,UUID,TEXT,BOOLEAN,UUID,BIGINT);

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
        claim_token=requested_claim_token,
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

-- Replace migration 0114's exact catalog health function so the two new
-- owner-held trigger capabilities and triggers are part of (not exceptions
-- to) the session authority manifest.
CREATE OR REPLACE FUNCTION northstar_session_capability_catalog_healthy(
    requested_schema TEXT
) RETURNS BOOLEAN
LANGUAGE sql
SECURITY DEFINER
SET search_path FROM CURRENT
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
            'state_version','SELECT'))
)
SELECT (SELECT pg_catalog.count(*)=1 FROM namespace)
  AND (SELECT pg_catalog.count(*)=3 AND pg_catalog.bool_and(relowner=nspowner)
         FROM protected_relations)
  AND NOT EXISTS(SELECT 1 FROM unexpected_relation_acl)
  AND NOT EXISTS(SELECT 1 FROM unexpected_column_acl)
  AND NOT EXISTS(SELECT 1 FROM routine_acl_drift)
  AND NOT EXISTS(SELECT 1 FROM unexpected_session_routine)
  AND NOT EXISTS(SELECT 1 FROM runtime_dml_acl)
  AND NOT EXISTS(SELECT 1 FROM sensitive_sm_acl)
  AND NOT EXISTS(SELECT 1 FROM unexpected_trigger)
  AND (SELECT pg_catalog.count(*)=7 AND pg_catalog.bool_and(
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

DO $northstar_sm_event_authority_security$
DECLARE
    migration_schema TEXT := pg_catalog.current_schema();
    routine_signature TEXT;
    routine_oid OID;
BEGIN
    IF migration_schema IS NULL THEN
        RAISE EXCEPTION 'SM authority event migration requires a current schema'
            USING ERRCODE='3F000';
    END IF;
    FOREACH routine_signature IN ARRAY ARRAY[
      'northstar_sm_claim(bytea,uuid,inet,uuid,text,bool,uuid,int8)',
      'northstar_session_capability_catalog_healthy(text)',
      'northstar_sm_state_version()',
      'northstar_sm_state_notify()'
    ] LOOP
      routine_oid := pg_catalog.to_regprocedure(
        pg_catalog.format('%I.%s',migration_schema,routine_signature));
      IF routine_oid IS NULL THEN
        RAISE EXCEPTION 'SM authority event capability % is absent',routine_signature
            USING ERRCODE='42883';
      END IF;
      EXECUTE pg_catalog.format(
        'ALTER FUNCTION %I.%s SECURITY DEFINER SET search_path TO pg_catalog, %I, pg_temp',
        migration_schema,routine_signature,migration_schema);
      EXECUTE pg_catalog.format(
        'REVOKE ALL ON FUNCTION %I.%s FROM PUBLIC CASCADE',
        migration_schema,routine_signature);
    END LOOP;

    IF NOT EXISTS (
      SELECT 1 FROM pg_catalog.pg_proc routine
       WHERE routine.oid=pg_catalog.to_regprocedure(pg_catalog.format(
               '%I.northstar_sm_claim(bytea,uuid,inet,uuid,text,bool,uuid,int8)',
               migration_schema))
         AND routine.proretset
         AND routine.proargnames=ARRAY[
           'requested_token_hash','requested_user','requested_claimant_ip',
           'requested_device','requested_ip_policy','require_same_device',
           'requested_claim_token','requested_claim_lease','status','session_id',
           'claim_token','full_jid','resource','resume_timeout_seconds','inbound_h',
           'acked_h','available','carbons','priority','blocklist_requested',
           'roster_requested','active_privacy_list','privacy_requested',
           'user_agent_id','joined_rooms','directed_presence','last_presence',
           'old_connection_id','state_version','pending_reason','retry_at',
           'authority_now','claimed_until'
         ]::TEXT[]
         AND routine.proargmodes=ARRAY[
           'i','i','i','i','i','i','i','i',
           't','t','t','t','t','t','t','t','t','t','t','t','t','t','t','t','t',
           't','t','t','t','t','t','t','t'
         ]::pg_catalog."char"[]
    ) THEN
      RAISE EXCEPTION 'SM claim event projection ABI is inconsistent'
        USING ERRCODE='55000';
    END IF;
END;
$northstar_sm_event_authority_security$;

REVOKE ALL ON TABLE sm_resume_sessions FROM PUBLIC;

COMMENT ON COLUMN sm_resume_sessions.state_version IS
  'Monotonic per-session authority epoch used only for exact LISTEN/NOTIFY wake validation';
COMMENT ON FUNCTION northstar_sm_state_version() IS
  'Advances the durable XEP-0198 authority epoch for every session row transition';
COMMENT ON FUNCTION northstar_sm_state_notify() IS
  'Emits a commit-ordered non-secret schema/session/version wake notification';
COMMENT ON FUNCTION northstar_sm_claim(BYTEA,UUID,INET,UUID,TEXT,BOOLEAN,UUID,BIGINT) IS
  'Claims or returns the exact durable reason, version and next authority boundary for an XEP-0198 resume';
