-- XEP-0133 account mutations are authoritative PostgreSQL transactions, but
-- their live-session teardown used to be an untracked post-commit side
-- effect.  A Redis interruption could therefore leave an administrator with
-- a successful result while an old credential incarnation remained online.
--
-- This bounded outbox is intentionally separate from the REST operation
-- journal: session teardown is idempotent and must keep retrying, whereas an
-- ambiguous external REST effect becomes terminally indeterminate.  Effect
-- identity has no user foreign key so delete/recreate cannot erase or retarget
-- committed cleanup work.

CREATE TABLE admin_session_cleanup_capacity (
    singleton pg_catalog.bool PRIMARY KEY DEFAULT TRUE CHECK(singleton),
    queued pg_catalog.int8 NOT NULL DEFAULT 0 CHECK(queued BETWEEN 0 AND 100000),
    maximum pg_catalog.int8 NOT NULL DEFAULT 100000 CHECK(maximum=100000),
    updated_at pg_catalog.timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp()
);
INSERT INTO admin_session_cleanup_capacity(singleton) VALUES(TRUE);

CREATE TABLE admin_session_cleanup_effects (
    id pg_catalog.uuid PRIMARY KEY DEFAULT pg_catalog.gen_random_uuid()
        CHECK(id<>'00000000-0000-0000-0000-000000000000'::pg_catalog.uuid),
    command_operation_id pg_catalog.uuid NOT NULL
        CHECK(command_operation_id<>'00000000-0000-0000-0000-000000000000'::pg_catalog.uuid),
    effect_key pg_catalog.text NOT NULL CHECK(octet_length(effect_key) BETWEEN 1 AND 256),
    kind pg_catalog.text NOT NULL CHECK(kind IN ('account_generation','exact_connection')),
    user_id pg_catalog.uuid NOT NULL
        CHECK(user_id<>'00000000-0000-0000-0000-000000000000'::pg_catalog.uuid),
    auth_generation pg_catalog.int8 NOT NULL CHECK(auth_generation>=0),
    bare_jid pg_catalog.text,
    full_jid pg_catalog.text,
    connection_id pg_catalog.uuid,
    status pg_catalog.text NOT NULL DEFAULT 'pending' CHECK(status IN ('pending','running')),
    attempts pg_catalog.int8 NOT NULL DEFAULT 0 CHECK(attempts>=0),
    next_attempt_at pg_catalog.timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
    worker_id pg_catalog.uuid,
    lease_token pg_catalog.uuid,
    lease_expires_at pg_catalog.timestamptz,
    last_error_code pg_catalog.text CHECK(last_error_code IS NULL OR octet_length(last_error_code) BETWEEN 1 AND 128),
    created_at pg_catalog.timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
    updated_at pg_catalog.timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
    CONSTRAINT admin_session_cleanup_effect_identity UNIQUE(command_operation_id,effect_key),
    CONSTRAINT admin_session_cleanup_effect_target_shape CHECK(
      (kind='account_generation'
       AND bare_jid IS NOT NULL AND octet_length(bare_jid) BETWEEN 3 AND 3071
       AND position('/' IN bare_jid)=0
       AND full_jid IS NULL AND connection_id IS NULL)
      OR
      (kind='exact_connection'
       AND bare_jid IS NULL
       AND full_jid IS NOT NULL AND octet_length(full_jid) BETWEEN 3 AND 3071
       AND position('/' IN full_jid)>0
       AND connection_id IS NOT NULL
       AND connection_id<>'00000000-0000-0000-0000-000000000000'::pg_catalog.uuid)
    ),
    CONSTRAINT admin_session_cleanup_effect_lease_shape CHECK(
      (status='pending' AND worker_id IS NULL AND lease_token IS NULL AND lease_expires_at IS NULL)
      OR
      (status='running' AND worker_id IS NOT NULL AND lease_token IS NOT NULL
       AND lease_expires_at IS NOT NULL
       AND worker_id<>'00000000-0000-0000-0000-000000000000'::pg_catalog.uuid
       AND lease_token<>'00000000-0000-0000-0000-000000000000'::pg_catalog.uuid)
    )
);
CREATE INDEX admin_session_cleanup_effects_claim_idx
    ON admin_session_cleanup_effects(next_attempt_at,created_at,id)
    WHERE status='pending';
CREATE INDEX admin_session_cleanup_effects_expired_lease_idx
    ON admin_session_cleanup_effects(lease_expires_at,id)
    WHERE status='running';

CREATE FUNCTION northstar_protect_admin_session_cleanup_identity()
RETURNS pg_catalog.trigger
LANGUAGE plpgsql
SET search_path FROM CURRENT
AS $northstar_admin_cleanup_identity$
BEGIN
    IF NEW.id IS DISTINCT FROM OLD.id
       OR NEW.command_operation_id IS DISTINCT FROM OLD.command_operation_id
       OR NEW.effect_key IS DISTINCT FROM OLD.effect_key
       OR NEW.kind IS DISTINCT FROM OLD.kind
       OR NEW.user_id IS DISTINCT FROM OLD.user_id
       OR NEW.auth_generation IS DISTINCT FROM OLD.auth_generation
       OR NEW.bare_jid IS DISTINCT FROM OLD.bare_jid
       OR NEW.full_jid IS DISTINCT FROM OLD.full_jid
       OR NEW.connection_id IS DISTINCT FROM OLD.connection_id
       OR NEW.created_at IS DISTINCT FROM OLD.created_at THEN
        RAISE EXCEPTION 'administrator session cleanup identity is immutable'
            USING ERRCODE='55000';
    END IF;
    RETURN NEW;
END;
$northstar_admin_cleanup_identity$;

CREATE TRIGGER admin_session_cleanup_effect_identity_guard
BEFORE UPDATE ON admin_session_cleanup_effects
FOR EACH ROW EXECUTE FUNCTION northstar_protect_admin_session_cleanup_identity();

-- Internal issuer.  It is never granted to an application identity; the
-- reviewed XEP-0133 wrappers below call it while holding the command claim and
-- target account locks.
CREATE FUNCTION northstar_enqueue_admin_generation_cleanup(
    requested_command_session_id pg_catalog.uuid,
    requested_user_id pg_catalog.uuid,
    requested_auth_generation_exclusive pg_catalog.int8,
    requested_bare_jid pg_catalog.text
) RETURNS pg_catalog.uuid
LANGUAGE plpgsql
SET search_path FROM CURRENT
AS $northstar_enqueue_admin_generation_cleanup$
DECLARE
    requested_operation_id pg_catalog.uuid;
    requested_effect_key pg_catalog.text;
    existing admin_session_cleanup_effects%ROWTYPE;
    inserted_id pg_catalog.uuid;
    capacity_row admin_session_cleanup_capacity%ROWTYPE;
BEGIN
    IF requested_command_session_id IS NULL OR requested_user_id IS NULL
       OR requested_auth_generation_exclusive<=0
       OR requested_bare_jid IS NULL
       OR octet_length(requested_bare_jid) NOT BETWEEN 3 AND 3071
       OR position('@' IN requested_bare_jid)<=1
       OR pg_catalog.split_part(requested_bare_jid,'@',2)=''
       OR pg_catalog.split_part(requested_bare_jid,'@',3)<>''
       OR position('/' IN requested_bare_jid)<>0 THEN
        RAISE EXCEPTION 'invalid administrator generation-cleanup identity'
            USING ERRCODE='22023';
    END IF;
    SELECT operation_id INTO requested_operation_id
      FROM admin_command_sessions
     WHERE id=requested_command_session_id AND stage='executing'
       AND completed_at IS NULL AND operation_id IS NOT NULL
       -- Bind the durable target to the authenticated administrator's local
       -- XMPP domain. This is a second authority boundary behind Rust JID
       -- canonicalization and prevents a malformed caller from persisting a
       -- cross-domain teardown signal through this privileged issuer.
       AND pg_catalog.split_part(
             pg_catalog.split_part(owner_full_jid,'/',1),'@',2
           )=pg_catalog.split_part(requested_bare_jid,'@',2);
    IF NOT FOUND THEN
        RAISE EXCEPTION 'administrator command operation identity is unavailable'
            USING ERRCODE='40001';
    END IF;
    requested_effect_key := 'generation:' || requested_user_id::pg_catalog.text
                            || ':' || requested_auth_generation_exclusive::pg_catalog.text;
    SELECT * INTO existing FROM admin_session_cleanup_effects
     WHERE command_operation_id=requested_operation_id AND effect_key=requested_effect_key
     FOR UPDATE;
    IF FOUND THEN
        IF existing.kind<>'account_generation'
           OR existing.user_id<>requested_user_id
           OR existing.auth_generation<>requested_auth_generation_exclusive
           OR existing.bare_jid<>requested_bare_jid THEN
            RAISE EXCEPTION 'administrator cleanup replay identity changed'
                USING ERRCODE='40001';
        END IF;
        RETURN existing.id;
    END IF;
    SELECT * INTO capacity_row FROM admin_session_cleanup_capacity
     WHERE singleton FOR UPDATE;
    IF NOT FOUND OR capacity_row.queued>=capacity_row.maximum THEN
        RAISE EXCEPTION 'administrator session cleanup queue is full'
            USING ERRCODE='53300';
    END IF;
    INSERT INTO admin_session_cleanup_effects(
      command_operation_id,effect_key,kind,user_id,auth_generation,bare_jid
    ) VALUES(
      requested_operation_id,requested_effect_key,'account_generation',
      requested_user_id,requested_auth_generation_exclusive,requested_bare_jid
    ) RETURNING id INTO inserted_id;
    UPDATE admin_session_cleanup_capacity
       SET queued=queued+1,updated_at=pg_catalog.clock_timestamp()
     WHERE singleton;
    RETURN inserted_id;
END;
$northstar_enqueue_admin_generation_cleanup$;

CREATE FUNCTION northstar_enqueue_admin_exact_session_cleanup(
    requested_command_session_id pg_catalog.uuid,
    requested_user_id pg_catalog.uuid,
    requested_auth_generation pg_catalog.int8,
    requested_full_jid pg_catalog.text,
    requested_connection_id pg_catalog.uuid
) RETURNS pg_catalog.uuid
LANGUAGE plpgsql
SET search_path FROM CURRENT
AS $northstar_enqueue_admin_exact_session_cleanup$
DECLARE
    requested_operation_id pg_catalog.uuid;
    requested_effect_key pg_catalog.text;
    existing admin_session_cleanup_effects%ROWTYPE;
    inserted_id pg_catalog.uuid;
    capacity_row admin_session_cleanup_capacity%ROWTYPE;
BEGIN
    IF requested_command_session_id IS NULL OR requested_user_id IS NULL
       OR requested_auth_generation<0 OR requested_full_jid IS NULL
       OR octet_length(requested_full_jid) NOT BETWEEN 3 AND 3071
       OR position('/' IN requested_full_jid)=0
       OR position('@' IN pg_catalog.split_part(requested_full_jid,'/',1))<=1
       OR pg_catalog.split_part(
            pg_catalog.split_part(requested_full_jid,'/',1),'@',2
          )=''
       OR pg_catalog.split_part(
            pg_catalog.split_part(requested_full_jid,'/',1),'@',3
          )<>''
       OR requested_connection_id IS NULL
       OR requested_connection_id='00000000-0000-0000-0000-000000000000'::pg_catalog.uuid THEN
        RAISE EXCEPTION 'invalid administrator exact-session cleanup identity'
            USING ERRCODE='22023';
    END IF;
    SELECT operation_id INTO requested_operation_id
      FROM admin_command_sessions
     WHERE id=requested_command_session_id AND stage='executing'
       AND completed_at IS NULL AND operation_id IS NOT NULL
       AND pg_catalog.split_part(
             pg_catalog.split_part(owner_full_jid,'/',1),'@',2
           )=pg_catalog.split_part(
             pg_catalog.split_part(requested_full_jid,'/',1),'@',2
           );
    IF NOT FOUND THEN
        RAISE EXCEPTION 'administrator command operation identity is unavailable'
            USING ERRCODE='40001';
    END IF;
    requested_effect_key := 'connection:' || requested_connection_id::pg_catalog.text;
    SELECT * INTO existing FROM admin_session_cleanup_effects
     WHERE command_operation_id=requested_operation_id AND effect_key=requested_effect_key
     FOR UPDATE;
    IF FOUND THEN
        IF existing.kind<>'exact_connection'
           OR existing.user_id<>requested_user_id
           OR existing.auth_generation<>requested_auth_generation
           OR existing.full_jid<>requested_full_jid
           OR existing.connection_id<>requested_connection_id THEN
            RAISE EXCEPTION 'administrator cleanup replay identity changed'
                USING ERRCODE='40001';
        END IF;
        RETURN existing.id;
    END IF;
    SELECT * INTO capacity_row FROM admin_session_cleanup_capacity
     WHERE singleton FOR UPDATE;
    IF NOT FOUND OR capacity_row.queued>=capacity_row.maximum THEN
        RAISE EXCEPTION 'administrator session cleanup queue is full'
            USING ERRCODE='53300';
    END IF;
    INSERT INTO admin_session_cleanup_effects(
      command_operation_id,effect_key,kind,user_id,auth_generation,full_jid,connection_id
    ) VALUES(
      requested_operation_id,requested_effect_key,'exact_connection',
      requested_user_id,requested_auth_generation,requested_full_jid,requested_connection_id
    ) RETURNING id INTO inserted_id;
    UPDATE admin_session_cleanup_capacity
       SET queued=queued+1,updated_at=pg_catalog.clock_timestamp()
     WHERE singleton;
    RETURN inserted_id;
END;
$northstar_enqueue_admin_exact_session_cleanup$;

-- The runtime receives only these lease-fenced capabilities.  It cannot
-- inspect, forge, retarget or directly delete an effect row.
CREATE FUNCTION northstar_claim_admin_session_cleanup(
    requested_worker_id pg_catalog.uuid,
    requested_lease_seconds pg_catalog.int4
) RETURNS TABLE(
    id pg_catalog.uuid,
    command_operation_id pg_catalog.uuid,
    kind pg_catalog.text,
    user_id pg_catalog.uuid,
    auth_generation pg_catalog.int8,
    bare_jid pg_catalog.text,
    full_jid pg_catalog.text,
    connection_id pg_catalog.uuid,
    lease_token pg_catalog.uuid,
    attempts pg_catalog.int8
)
LANGUAGE plpgsql SECURITY DEFINER
SET search_path FROM CURRENT
AS $northstar_claim_admin_session_cleanup$
DECLARE
    claimed_id pg_catalog.uuid;
    claimed_token pg_catalog.uuid := pg_catalog.gen_random_uuid();
BEGIN
    IF requested_worker_id IS NULL
       OR requested_worker_id='00000000-0000-0000-0000-000000000000'::pg_catalog.uuid
       OR requested_lease_seconds NOT BETWEEN 15 AND 300 THEN
        RAISE EXCEPTION 'invalid administrator cleanup lease request'
            USING ERRCODE='22023';
    END IF;
    SELECT effect.id INTO claimed_id
      FROM admin_session_cleanup_effects effect
     WHERE (effect.status='pending' AND effect.next_attempt_at<=pg_catalog.clock_timestamp())
        OR (effect.status='running' AND effect.lease_expires_at<=pg_catalog.clock_timestamp())
     ORDER BY
       CASE WHEN effect.status='running' THEN effect.lease_expires_at
            ELSE effect.next_attempt_at END,
       effect.created_at,effect.id
     LIMIT 1 FOR UPDATE SKIP LOCKED;
    IF claimed_id IS NULL THEN RETURN; END IF;
    RETURN QUERY
      UPDATE admin_session_cleanup_effects effect
         SET status='running',worker_id=requested_worker_id,lease_token=claimed_token,
             lease_expires_at=pg_catalog.clock_timestamp()
                 + pg_catalog.make_interval(secs=>requested_lease_seconds),
             attempts=CASE WHEN effect.attempts=9223372036854775807
                           THEN effect.attempts ELSE effect.attempts+1 END,
             updated_at=pg_catalog.clock_timestamp()
       WHERE effect.id=claimed_id
       RETURNING effect.id,effect.command_operation_id,effect.kind,effect.user_id,
                 effect.auth_generation,effect.bare_jid,effect.full_jid,
                 effect.connection_id,effect.lease_token,effect.attempts;
END;
$northstar_claim_admin_session_cleanup$;

CREATE FUNCTION northstar_renew_admin_session_cleanup(
    requested_id pg_catalog.uuid,
    requested_worker_id pg_catalog.uuid,
    requested_lease_token pg_catalog.uuid,
    requested_lease_seconds pg_catalog.int4
) RETURNS pg_catalog.bool
LANGUAGE plpgsql SECURITY DEFINER
SET search_path FROM CURRENT
AS $northstar_renew_admin_session_cleanup$
BEGIN
    IF requested_lease_seconds NOT BETWEEN 15 AND 300 THEN RETURN FALSE; END IF;
    UPDATE admin_session_cleanup_effects
       SET lease_expires_at=pg_catalog.clock_timestamp()
             + pg_catalog.make_interval(secs=>requested_lease_seconds),
           updated_at=pg_catalog.clock_timestamp()
     WHERE id=requested_id AND status='running'
       AND worker_id=requested_worker_id AND lease_token=requested_lease_token
       AND lease_expires_at>pg_catalog.clock_timestamp();
    RETURN FOUND;
END;
$northstar_renew_admin_session_cleanup$;

CREATE FUNCTION northstar_retry_admin_session_cleanup(
    requested_id pg_catalog.uuid,
    requested_worker_id pg_catalog.uuid,
    requested_lease_token pg_catalog.uuid,
    requested_error_code pg_catalog.text
) RETURNS pg_catalog.bool
LANGUAGE plpgsql SECURITY DEFINER
SET search_path FROM CURRENT
AS $northstar_retry_admin_session_cleanup$
DECLARE retry_seconds pg_catalog.int4;
BEGIN
    IF requested_error_code IS NULL
       OR octet_length(requested_error_code) NOT BETWEEN 1 AND 128 THEN RETURN FALSE; END IF;
    SELECT LEAST(300,pg_catalog.power(2,LEAST(attempts,8)::pg_catalog.float8)::pg_catalog.int4)
      INTO retry_seconds FROM admin_session_cleanup_effects
     WHERE id=requested_id AND status='running'
       AND worker_id=requested_worker_id AND lease_token=requested_lease_token
       AND lease_expires_at>pg_catalog.clock_timestamp() FOR UPDATE;
    IF NOT FOUND THEN RETURN FALSE; END IF;
    UPDATE admin_session_cleanup_effects
       SET status='pending',worker_id=NULL,lease_token=NULL,lease_expires_at=NULL,
           next_attempt_at=pg_catalog.clock_timestamp()
             + pg_catalog.make_interval(secs=>retry_seconds),
           last_error_code=requested_error_code,updated_at=pg_catalog.clock_timestamp()
     WHERE id=requested_id;
    RETURN TRUE;
END;
$northstar_retry_admin_session_cleanup$;

CREATE FUNCTION northstar_complete_admin_session_cleanup(
    requested_id pg_catalog.uuid,
    requested_worker_id pg_catalog.uuid,
    requested_lease_token pg_catalog.uuid
) RETURNS pg_catalog.bool
LANGUAGE plpgsql SECURITY DEFINER
SET search_path FROM CURRENT
AS $northstar_complete_admin_session_cleanup$
DECLARE removed pg_catalog.int8;
BEGIN
    DELETE FROM admin_session_cleanup_effects
     WHERE id=requested_id AND status='running'
       AND worker_id=requested_worker_id AND lease_token=requested_lease_token
       AND lease_expires_at>pg_catalog.clock_timestamp();
    GET DIAGNOSTICS removed=ROW_COUNT;
    IF removed<>1 THEN RETURN FALSE; END IF;
    UPDATE admin_session_cleanup_capacity
       SET queued=queued-1,updated_at=pg_catalog.clock_timestamp()
     WHERE singleton AND queued>0;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'administrator cleanup capacity ledger underflow'
            USING ERRCODE='55000';
    END IF;
    RETURN TRUE;
END;
$northstar_complete_admin_session_cleanup$;

CREATE FUNCTION northstar_admin_session_cleanup_target_current(
    requested_id pg_catalog.uuid,
    requested_worker_id pg_catalog.uuid,
    requested_lease_token pg_catalog.uuid
) RETURNS pg_catalog.bool
LANGUAGE plpgsql SECURITY DEFINER
SET search_path FROM CURRENT
AS $northstar_admin_session_cleanup_target_current$
DECLARE effect admin_session_cleanup_effects%ROWTYPE;
BEGIN
    SELECT * INTO effect FROM admin_session_cleanup_effects
     WHERE id=requested_id AND status='running'
       AND worker_id=requested_worker_id AND lease_token=requested_lease_token
       AND lease_expires_at>pg_catalog.clock_timestamp() FOR SHARE;
    IF NOT FOUND OR effect.kind<>'exact_connection' THEN RETURN FALSE; END IF;
    RETURN EXISTS(
      SELECT 1 FROM deployment_session_leases lease
      JOIN users account ON account.id=lease.user_id
       WHERE lease.connection_id=effect.connection_id
         AND lease.user_id=effect.user_id
         AND lease.full_jid=effect.full_jid
         AND lease.lease_until>pg_catalog.clock_timestamp()
         AND account.auth_generation=effect.auth_generation
    );
END;
$northstar_admin_session_cleanup_target_current$;

CREATE FUNCTION northstar_admin_session_cleanup_snapshot()
RETURNS TABLE(
    pending pg_catalog.int8,
    running pg_catalog.int8,
    oldest_age_seconds pg_catalog.float8,
    maximum_attempts pg_catalog.int8,
    queued pg_catalog.int8,
    capacity pg_catalog.int8
)
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path FROM CURRENT
AS $northstar_admin_session_cleanup_snapshot$
  SELECT snapshot.pending,snapshot.running,snapshot.oldest_age_seconds,
         snapshot.maximum_attempts,ledger.queued,ledger.maximum
    FROM admin_session_cleanup_capacity ledger
   CROSS JOIN LATERAL (
     SELECT pg_catalog.count(*) FILTER(WHERE effect.status='pending') AS pending,
            pg_catalog.count(*) FILTER(WHERE effect.status='running') AS running,
            COALESCE(EXTRACT(EPOCH FROM pg_catalog.statement_timestamp()-MIN(effect.created_at)),0)::pg_catalog.float8
              AS oldest_age_seconds,
            COALESCE(MAX(effect.attempts),0) AS maximum_attempts
       FROM admin_session_cleanup_effects effect
   ) snapshot
   WHERE ledger.singleton
$northstar_admin_session_cleanup_snapshot$;

-- Replace the two business wrappers so the authorization mutation, command
-- completion and cleanup effect share one PostgreSQL commit.
DROP FUNCTION northstar_admin_command_reset_user_password(
  pg_catalog.text,pg_catalog.uuid,pg_catalog.text,pg_catalog.int8,pg_catalog.text,
  pg_catalog.bytea,pg_catalog.uuid,pg_catalog.text,pg_catalog.text,pg_catalog.bytea,
  pg_catalog.int4,pg_catalog.bytea,pg_catalog.bytea,pg_catalog.bytea,pg_catalog.int4,
  pg_catalog.bytea,pg_catalog.bytea,pg_catalog.text
);
CREATE FUNCTION northstar_admin_command_reset_user_password(
    requested_claim_token pg_catalog.text, requested_actor_id pg_catalog.uuid,
    requested_actor_username pg_catalog.text, expected_actor_generation pg_catalog.int8,
    requested_node pg_catalog.text, requested_target_digest pg_catalog.bytea,
    requested_target_id pg_catalog.uuid, expected_target_username pg_catalog.text,
    requested_password_hash pg_catalog.text, requested_sha256_salt pg_catalog.bytea,
    requested_iterations pg_catalog.int4, requested_sha256_stored_key pg_catalog.bytea,
    requested_sha256_server_key pg_catalog.bytea, requested_sha1_salt pg_catalog.bytea,
    requested_sha1_iterations pg_catalog.int4, requested_sha1_stored_key pg_catalog.bytea,
    requested_sha1_server_key pg_catalog.bytea, requested_bare_jid pg_catalog.text,
    requested_payload pg_catalog.text
) RETURNS pg_catalog.text
LANGUAGE plpgsql SECURITY DEFINER SET search_path FROM CURRENT
AS $northstar_admin_command_reset_user_password$
DECLARE locked_id pg_catalog.uuid; command_outcome pg_catalog.text;
        next_generation pg_catalog.int8;
BEGIN
    IF requested_node<>'http://jabber.org/protocol/admin#change-user-password'
       OR pg_catalog.split_part(requested_bare_jid,'@',1)<>expected_target_username
       OR position('@' IN requested_bare_jid)<=1
       OR pg_catalog.split_part(requested_bare_jid,'@',2)=''
       OR pg_catalog.split_part(requested_bare_jid,'@',3)<>''
       OR position('/' IN requested_bare_jid)<>0 THEN RETURN 'unauthorized'; END IF;
    locked_id := northstar_admin_command_lock_claim(
      requested_claim_token,requested_actor_id,requested_actor_username,
      expected_actor_generation,requested_node,requested_target_digest);
    IF locked_id IS NULL THEN RETURN 'unauthorized'; END IF;
    command_outcome := northstar_admin_reset_user_password(
      requested_actor_id,requested_actor_username,expected_actor_generation,
      requested_target_id,expected_target_username,requested_password_hash,
      requested_sha256_salt,requested_iterations,requested_sha256_stored_key,
      requested_sha256_server_key,requested_sha1_salt,requested_sha1_iterations,
      requested_sha1_stored_key,requested_sha1_server_key);
    IF command_outcome='applied' THEN
      SELECT auth_generation INTO STRICT next_generation FROM users
       WHERE id=requested_target_id AND username=expected_target_username;
      PERFORM northstar_enqueue_admin_generation_cleanup(
        locked_id,requested_target_id,next_generation,requested_bare_jid);
      IF NOT northstar_admin_command_complete_locked(
         locked_id,requested_actor_id,requested_node,requested_payload,
         'admin.command.execute') THEN
        RAISE EXCEPTION 'command completion fence changed' USING ERRCODE='40001';
      END IF;
    END IF;
    RETURN command_outcome;
END;
$northstar_admin_command_reset_user_password$;

DROP FUNCTION northstar_admin_command_user_lifecycle(
  pg_catalog.text,pg_catalog.uuid,pg_catalog.text,pg_catalog.int8,pg_catalog.text,
  pg_catalog.bytea,pg_catalog.uuid,pg_catalog.text,pg_catalog.text,pg_catalog.text,
  pg_catalog.bool,pg_catalog.text
);
CREATE FUNCTION northstar_admin_command_user_lifecycle(
    requested_claim_token pg_catalog.text, requested_actor_id pg_catalog.uuid,
    requested_actor_username pg_catalog.text, expected_actor_generation pg_catalog.int8,
    requested_node pg_catalog.text, requested_target_digest pg_catalog.bytea,
    requested_target_id pg_catalog.uuid, expected_target_username pg_catalog.text,
    requested_action pg_catalog.text, requested_bare_jid pg_catalog.text,
    requested_exact_full_jid pg_catalog.text, complete_command pg_catalog.bool,
    requested_payload pg_catalog.text
) RETURNS pg_catalog.text
LANGUAGE plpgsql SECURITY DEFINER SET search_path FROM CURRENT
AS $northstar_admin_command_user_lifecycle$
DECLARE locked_id pg_catalog.uuid; command_outcome pg_catalog.text;
        expected_node pg_catalog.text; previous_generation pg_catalog.int8;
        next_generation pg_catalog.int8; exact_connection pg_catalog.uuid;
BEGIN
    expected_node := CASE requested_action
      WHEN 'disable' THEN 'http://jabber.org/protocol/admin#disable-user'
      WHEN 'reenable' THEN 'http://jabber.org/protocol/admin#reenable-user'
      WHEN 'end_sessions' THEN 'http://jabber.org/protocol/admin#end-user-session'
      ELSE NULL END;
    IF expected_node IS NULL OR requested_node<>expected_node
       OR pg_catalog.split_part(requested_bare_jid,'@',1)<>expected_target_username
       OR position('@' IN requested_bare_jid)<=1
       OR pg_catalog.split_part(requested_bare_jid,'@',2)=''
       OR pg_catalog.split_part(requested_bare_jid,'@',3)<>''
       OR position('/' IN requested_bare_jid)<>0 THEN RETURN 'unauthorized'; END IF;
    locked_id := northstar_admin_command_lock_claim(
      requested_claim_token,requested_actor_id,requested_actor_username,
      expected_actor_generation,requested_node,requested_target_digest);
    IF locked_id IS NULL THEN RETURN 'unauthorized'; END IF;
    SELECT auth_generation INTO previous_generation FROM users
     WHERE id=requested_target_id AND username=expected_target_username FOR UPDATE;
    IF NOT FOUND THEN RETURN 'target_changed'; END IF;
    IF requested_action='end_sessions' AND requested_exact_full_jid IS NOT NULL THEN
      IF pg_catalog.split_part(requested_exact_full_jid,'/',1)<>requested_bare_jid
         OR position('/' IN requested_exact_full_jid)=0 THEN RETURN 'target_changed'; END IF;
      SELECT lease.connection_id INTO exact_connection
        FROM deployment_session_leases lease
       WHERE lease.user_id=requested_target_id
         AND lease.full_jid=requested_exact_full_jid FOR UPDATE;
      UPDATE sm_resume_sessions SET
        resumable=FALSE,live_lease_until=pg_catalog.clock_timestamp(),
        expires_at=pg_catalog.clock_timestamp(),updated_at=pg_catalog.clock_timestamp()
       WHERE user_id=requested_target_id AND full_jid=requested_exact_full_jid;
      IF exact_connection IS NOT NULL THEN
        PERFORM northstar_enqueue_admin_exact_session_cleanup(
          locked_id,requested_target_id,previous_generation,
          requested_exact_full_jid,exact_connection);
      END IF;
      INSERT INTO audit_log(actor_id,action,target,details)
      VALUES(requested_actor_id,'admin.user.sessions.end',requested_target_id::pg_catalog.text,
        pg_catalog.jsonb_build_object(
          'source','xep-0133','username',expected_target_username,
          'scope','full','full_jid',requested_exact_full_jid,
          'connection_snapshotted',exact_connection IS NOT NULL));
      command_outcome := 'applied';
    ELSE
      command_outcome := northstar_admin_user_lifecycle(
        requested_actor_id,requested_actor_username,expected_actor_generation,
        requested_target_id,expected_target_username,requested_action);
      IF command_outcome='applied' AND requested_action<>'reenable' THEN
        SELECT auth_generation INTO STRICT next_generation FROM users
         WHERE id=requested_target_id AND username=expected_target_username;
        IF next_generation=previous_generation THEN
          next_generation := next_generation+1;
          UPDATE sm_resume_sessions SET
            resumable=FALSE,live_lease_until=pg_catalog.clock_timestamp(),
            expires_at=pg_catalog.clock_timestamp(),updated_at=pg_catalog.clock_timestamp()
           WHERE user_id=requested_target_id AND auth_generation<next_generation;
        END IF;
        PERFORM northstar_enqueue_admin_generation_cleanup(
          locked_id,requested_target_id,next_generation,requested_bare_jid);
      END IF;
    END IF;
    IF command_outcome='applied' AND complete_command
       AND NOT northstar_admin_command_complete_locked(
         locked_id,requested_actor_id,requested_node,requested_payload,
         'admin.command.execute') THEN
      RAISE EXCEPTION 'command completion fence changed' USING ERRCODE='40001';
    END IF;
    RETURN command_outcome;
END;
$northstar_admin_command_user_lifecycle$;

CREATE FUNCTION northstar_admin_command_issue_delete_cleanup(
    requested_claim_token pg_catalog.text, requested_actor_id pg_catalog.uuid,
    requested_actor_username pg_catalog.text, expected_actor_generation pg_catalog.int8,
    requested_node pg_catalog.text, requested_target_digest pg_catalog.bytea,
    requested_target_id pg_catalog.uuid, expected_target_username pg_catalog.text,
    requested_bare_jid pg_catalog.text
) RETURNS pg_catalog.bool
LANGUAGE plpgsql SECURITY DEFINER SET search_path FROM CURRENT
AS $northstar_admin_command_issue_delete_cleanup$
DECLARE locked_id pg_catalog.uuid; target_generation pg_catalog.int8;
BEGIN
    IF requested_node<>'http://jabber.org/protocol/admin#delete-user'
       OR pg_catalog.split_part(requested_bare_jid,'@',1)<>expected_target_username
       OR position('@' IN requested_bare_jid)<=1
       OR pg_catalog.split_part(requested_bare_jid,'@',2)=''
       OR pg_catalog.split_part(requested_bare_jid,'@',3)<>''
       OR position('/' IN requested_bare_jid)<>0 THEN RETURN FALSE; END IF;
    locked_id := northstar_admin_command_lock_claim(
      requested_claim_token,requested_actor_id,requested_actor_username,
      expected_actor_generation,requested_node,requested_target_digest);
    IF locked_id IS NULL THEN RETURN FALSE; END IF;
    SELECT auth_generation INTO target_generation FROM users
     WHERE id=requested_target_id AND username=expected_target_username FOR UPDATE;
    IF NOT FOUND THEN RETURN FALSE; END IF;
    PERFORM northstar_enqueue_admin_generation_cleanup(
      locked_id,requested_target_id,target_generation+1,requested_bare_jid);
    RETURN TRUE;
END;
$northstar_admin_command_issue_delete_cleanup$;

-- Pin every new or replaced routine to the exact installation schema and
-- remove PostgreSQL's default PUBLIC execution grant.  Deployment grants
-- expose only the lease-fenced worker/observability routines and reviewed
-- XEP-0133 issuers.
DO $northstar_admin_session_cleanup_metadata$
DECLARE
    migration_schema pg_catalog.text := pg_catalog.current_schema();
    signature pg_catalog.text;
BEGIN
    IF migration_schema IS NULL
       OR migration_schema IN ('pg_catalog','information_schema')
       OR migration_schema LIKE 'pg_temp_%' THEN
      RAISE EXCEPTION 'migration 0111 requires a dedicated application schema first in search_path'
        USING ERRCODE='3F000';
    END IF;
    FOREACH signature IN ARRAY ARRAY[
      'northstar_protect_admin_session_cleanup_identity()',
      'northstar_enqueue_admin_generation_cleanup(uuid,uuid,int8,text)',
      'northstar_enqueue_admin_exact_session_cleanup(uuid,uuid,int8,text,uuid)',
      'northstar_claim_admin_session_cleanup(uuid,int4)',
      'northstar_renew_admin_session_cleanup(uuid,uuid,uuid,int4)',
      'northstar_retry_admin_session_cleanup(uuid,uuid,uuid,text)',
      'northstar_complete_admin_session_cleanup(uuid,uuid,uuid)',
      'northstar_admin_session_cleanup_target_current(uuid,uuid,uuid)',
      'northstar_admin_session_cleanup_snapshot()',
      'northstar_admin_command_reset_user_password(text,uuid,text,int8,text,bytea,uuid,text,text,bytea,int4,bytea,bytea,bytea,int4,bytea,bytea,text,text)',
      'northstar_admin_command_user_lifecycle(text,uuid,text,int8,text,bytea,uuid,text,text,text,text,bool,text)',
      'northstar_admin_command_issue_delete_cleanup(text,uuid,text,int8,text,bytea,uuid,text,text)'
    ] LOOP
      EXECUTE pg_catalog.format(
        'ALTER FUNCTION %I.%s SET search_path TO pg_catalog, %I, pg_temp',
        migration_schema,signature,migration_schema);
      EXECUTE pg_catalog.format('REVOKE ALL ON FUNCTION %I.%s FROM PUBLIC',
        migration_schema,signature);
    END LOOP;
END;
$northstar_admin_session_cleanup_metadata$;

COMMENT ON TABLE admin_session_cleanup_effects IS
  'Bounded lease-fenced XEP-0133 session cleanup effects; identities survive account deletion and complete by physical deletion';
COMMENT ON FUNCTION northstar_claim_admin_session_cleanup(pg_catalog.uuid,pg_catalog.int4) IS
  'Claims one due or expired XEP-0133 cleanup effect with a bounded fencing lease';
