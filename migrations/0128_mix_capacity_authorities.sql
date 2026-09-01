-- Make both MIX capacity protocols exact under ordinary contention.
--
-- Delivery reclamation is a separately committed authority phase: a producer
-- never rolls orphan cleanup back merely because its later reservation is
-- full. MIX-PAM uses durable global/per-account counters maintained by
-- owner-held triggers instead of COUNT(*) plus a non-waiting advisory lock.

LOCK TABLE mix_pam_operations IN ACCESS EXCLUSIVE MODE;

DO $northstar_mix_pam_capacity_cutover$
DECLARE
    operation_count BIGINT;
    largest_account_count BIGINT;
BEGIN
    SELECT COALESCE(SUM(account_count), 0)::BIGINT,
           COALESCE(MAX(account_count), 0)::BIGINT
      INTO operation_count, largest_account_count
      FROM (
          SELECT user_id, COUNT(*)::BIGINT AS account_count
            FROM mix_pam_operations
           GROUP BY user_id
      ) accounts;
    IF operation_count > 10000 OR largest_account_count > 64 THEN
        RAISE EXCEPTION
          'MIX-PAM capacity cut-over exceeds policy: % operations, % largest account',
          operation_count, largest_account_count
          USING ERRCODE = '54000';
    END IF;
END;
$northstar_mix_pam_capacity_cutover$;

CREATE TABLE mix_pam_operation_capacity (
    singleton BOOLEAN PRIMARY KEY DEFAULT TRUE CHECK (singleton),
    max_operations BIGINT NOT NULL CHECK (max_operations = 10000),
    max_per_user BIGINT NOT NULL CHECK (max_per_user = 64),
    operation_count BIGINT NOT NULL CHECK (operation_count BETWEEN 0 AND max_operations)
);
INSERT INTO mix_pam_operation_capacity(
    singleton, operation_count, max_operations, max_per_user
)
SELECT TRUE, COUNT(*)::BIGINT, 10000, 64 FROM mix_pam_operations;

-- Deliberately no users FK: an account delete cascades operation rows, whose
-- owner-held delete trigger removes the last counter row. A counter FK could
-- delete that row before the operation triggers have accounted their releases.
CREATE TABLE mix_pam_operation_user_capacity (
    user_id UUID PRIMARY KEY,
    operation_count BIGINT NOT NULL CHECK (operation_count BETWEEN 1 AND 64)
);
INSERT INTO mix_pam_operation_user_capacity(user_id, operation_count)
SELECT user_id, COUNT(*)::BIGINT
  FROM mix_pam_operations
 GROUP BY user_id;

-- Runtime calls this immediately after locking the authenticated account and
-- before taking any membership/client/operation lock. The clone-shared
-- application gate permits at most one such database waiter per process.
CREATE FUNCTION northstar_mix_pam_capacity_lock()
RETURNS VOID
LANGUAGE plpgsql
SET search_path FROM CURRENT
AS $$
BEGIN
    PERFORM 1 FROM mix_pam_operation_capacity
     WHERE singleton
     FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'MIX-PAM global capacity authority is missing'
          USING ERRCODE = '55000';
    END IF;
END;
$$;

-- Runtime has read-only access to users and therefore cannot take a row lock
-- directly. This narrow capability proves the authenticated account identity,
-- holds it against deletion or a concurrent disable/rename, and only then
-- takes the global PAM authority.
CREATE FUNCTION northstar_mix_pam_account_capacity_lock(
    requested_user_id UUID,
    expected_username TEXT
)
RETURNS BOOLEAN
LANGUAGE plpgsql
SET search_path FROM CURRENT
AS $$
BEGIN
    PERFORM 1 FROM users
     WHERE id = requested_user_id
       AND username = expected_username
       AND NOT is_disabled
     FOR UPDATE;
    IF NOT FOUND THEN
        RETURN FALSE;
    END IF;
    PERFORM northstar_mix_pam_capacity_lock();
    RETURN TRUE;
END;
$$;

CREATE FUNCTION northstar_mix_pam_operation_capacity_insert()
RETURNS TRIGGER
LANGUAGE plpgsql
SET search_path FROM CURRENT
AS $$
DECLARE
    account_limit BIGINT;
    account_count BIGINT;
BEGIN
    -- Fixed database lock order: singleton first, then the exact user counter.
    UPDATE mix_pam_operation_capacity
       SET operation_count = operation_count + 1
     WHERE singleton AND operation_count < max_operations
     RETURNING max_per_user INTO account_limit;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'MIX-PAM operation journal capacity exceeded'
          USING ERRCODE = '54000';
    END IF;

    INSERT INTO mix_pam_operation_user_capacity(user_id, operation_count)
    VALUES (NEW.user_id, 1)
    ON CONFLICT (user_id) DO UPDATE
       SET operation_count = mix_pam_operation_user_capacity.operation_count + 1
     WHERE mix_pam_operation_user_capacity.operation_count < account_limit
    RETURNING operation_count INTO account_count;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'MIX-PAM per-account operation journal capacity exceeded'
          USING ERRCODE = '54000';
    END IF;
    RETURN NEW;
END;
$$;

CREATE FUNCTION northstar_mix_pam_operation_capacity_delete()
RETURNS TRIGGER
LANGUAGE plpgsql
SET search_path FROM CURRENT
AS $$
DECLARE
    account_count BIGINT;
BEGIN
    -- Match the insert path exactly: singleton first, then the exact user row.
    UPDATE mix_pam_operation_capacity
       SET operation_count = operation_count - 1
     WHERE singleton AND operation_count > 0;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'MIX-PAM global capacity authority underflow'
          USING ERRCODE = '55000';
    END IF;

    SELECT operation_count INTO account_count
      FROM mix_pam_operation_user_capacity
     WHERE user_id = OLD.user_id
     FOR UPDATE;
    IF NOT FOUND OR account_count < 1 THEN
        RAISE EXCEPTION 'MIX-PAM account capacity authority underflow'
          USING ERRCODE = '55000';
    ELSIF account_count = 1 THEN
        DELETE FROM mix_pam_operation_user_capacity
         WHERE user_id = OLD.user_id;
    ELSE
        UPDATE mix_pam_operation_user_capacity
           SET operation_count = operation_count - 1
         WHERE user_id = OLD.user_id;
    END IF;
    RETURN OLD;
END;
$$;

-- Account deletion locks the same singleton before FK cascades can delete PAM
-- operations. A concurrent admission first holds FOR KEY SHARE on this user,
-- then the singleton, so account deletion and admission cannot invert locks.
CREATE FUNCTION northstar_mix_pam_user_predelete_lock()
RETURNS TRIGGER
LANGUAGE plpgsql
SET search_path FROM CURRENT
AS $$
BEGIN
    IF EXISTS (SELECT 1 FROM mix_pam_operations WHERE user_id = OLD.id) THEN
        PERFORM northstar_mix_pam_capacity_lock();
    END IF;
    RETURN OLD;
END;
$$;

-- Runtime cannot insert/delete journal rows directly. These owner-held entry
-- points preserve trigger execution while keeping the durable capacity tables
-- and their transition surface outside the application role.
CREATE FUNCTION northstar_mix_pam_operation_insert(
    requested_operation_id UUID,
    requested_user_id UUID,
    requested_channel_jid TEXT,
    requested_remote_domain TEXT,
    requested_operation TEXT,
    requested_remote_request_id TEXT,
    requested_client_request_id TEXT,
    requested_requester_full_jid TEXT,
    requested_request_digest BYTEA,
    requested_request_outbox_id UUID,
    requested_prior_joined BOOLEAN,
    requested_prior_participant_id TEXT,
    requested_prior_nick TEXT,
    requested_prior_subscriptions TEXT[],
    requested_deadline_seconds BIGINT,
    expected_username TEXT
)
RETURNS VOID
LANGUAGE plpgsql
SET search_path FROM CURRENT
AS $$
DECLARE
    expected_membership_state TEXT;
    requester_bare TEXT;
BEGIN
    IF requested_deadline_seconds NOT BETWEEN 30 AND 86400 THEN
        RAISE EXCEPTION 'invalid MIX-PAM operation deadline'
          USING ERRCODE = '22023';
    END IF;
    IF requested_operation NOT IN ('join', 'leave') THEN
        RAISE EXCEPTION 'invalid MIX-PAM operation kind'
          USING ERRCODE = '22023';
    END IF;
    IF requested_remote_request_id IS NULL
       OR octet_length(requested_remote_request_id) NOT BETWEEN 1 AND 128
       OR requested_client_request_id IS NULL
       OR octet_length(requested_client_request_id) NOT BETWEEN 1 AND 1024 THEN
        RAISE EXCEPTION 'invalid MIX-PAM request identity'
          USING ERRCODE = '22023';
    END IF;
    requester_bare := split_part(requested_requester_full_jid, '/', 1);
    IF expected_username IS NULL
       OR octet_length(expected_username) NOT BETWEEN 1 AND 64
       OR split_part(requester_bare, '@', 1)
            IS DISTINCT FROM expected_username
       OR position('@' IN requester_bare) <= 1
       OR position(
            '@' IN substring(
                requester_bare FROM position('@' IN requester_bare) + 1
            )
          ) <> 0
       OR position('/' IN requested_requester_full_jid)
            <= position('@' IN requester_bare) + 1 THEN
        RAISE EXCEPTION 'MIX-PAM requester does not match the account identity'
          USING ERRCODE = '42501';
    END IF;
    IF requested_remote_domain IS NULL
       OR octet_length(requested_remote_domain) NOT BETWEEN 1 AND 253
       OR requested_remote_domain <> lower(requested_remote_domain)
       OR position('@' IN requested_remote_domain) <> 0
       OR position('/' IN requested_remote_domain) <> 0
       OR requested_channel_jid IS NULL
       OR octet_length(requested_channel_jid) NOT BETWEEN 3 AND 3071
       OR requested_channel_jid <> lower(requested_channel_jid)
       OR position('@' IN requested_channel_jid) <= 1
       OR position('/' IN requested_channel_jid) <> 0
       OR position(
            '@' IN substring(
                requested_channel_jid
                FROM position('@' IN requested_channel_jid) + 1
            )
          ) <> 0
       OR right(
            requested_channel_jid,
            octet_length(requested_remote_domain) + 1
          ) IS DISTINCT FROM '@' || requested_remote_domain THEN
        RAISE EXCEPTION 'MIX-PAM channel is not owned by the remote domain'
          USING ERRCODE = '22023';
    END IF;

    -- This capability is self-authorizing. The earlier account-capacity call
    -- establishes the lock order before business rows are touched; repeating
    -- it here makes a direct EXECUTE prove the same account identity instead
    -- of relying on a typed-call ordering convention.
    IF northstar_mix_pam_account_capacity_lock(
           requested_user_id, expected_username
       ) IS DISTINCT FROM TRUE THEN
        RAISE EXCEPTION 'MIX-PAM account identity is not authorized'
          USING ERRCODE = '42501';
    END IF;

    expected_membership_state := CASE requested_operation
        WHEN 'join' THEN 'pending_join'
        ELSE 'pending_leave'
    END;
    PERFORM 1
      FROM mix_pam_memberships
     WHERE user_id = requested_user_id
       AND channel_jid = requested_channel_jid
       AND state = expected_membership_state
       AND request_id = requested_remote_request_id
       AND client_request_id = requested_client_request_id
       AND requester_full_jid = requested_requester_full_jid
     FOR KEY SHARE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'MIX-PAM pending membership does not match the operation'
          USING ERRCODE = '55000';
    END IF;

    PERFORM 1
      FROM s2s_outbox
     WHERE id = requested_request_outbox_id
       AND target_domain = requested_remote_domain
       AND expires_at > clock_timestamp()
     FOR KEY SHARE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'MIX-PAM durable outbox projection is missing or inconsistent'
          USING ERRCODE = '55000';
    END IF;

    INSERT INTO mix_pam_operations(
        operation_id,user_id,channel_jid,remote_domain,operation,
        remote_request_id,client_request_id,requester_full_jid,
        request_digest,request_outbox_id,prior_joined,
        prior_participant_id,prior_nick,prior_subscriptions,
        deadline_at,expires_at
    ) VALUES (
        requested_operation_id,requested_user_id,requested_channel_jid,
        requested_remote_domain,requested_operation,requested_remote_request_id,
        requested_client_request_id,requested_requester_full_jid,
        requested_request_digest,requested_request_outbox_id,
        requested_prior_joined,requested_prior_participant_id,
        requested_prior_nick,requested_prior_subscriptions,
        clock_timestamp()+make_interval(secs=>requested_deadline_seconds),
        clock_timestamp()+make_interval(secs=>requested_deadline_seconds)
          + INTERVAL '7 days'
    );
END;
$$;

CREATE FUNCTION northstar_mix_pam_operation_prune(requested_limit BIGINT)
RETURNS BIGINT
LANGUAGE plpgsql
SET search_path FROM CURRENT
AS $$
DECLARE
    removed_count BIGINT;
BEGIN
    IF requested_limit NOT BETWEEN 1 AND 2048 THEN
        RAISE EXCEPTION 'invalid MIX-PAM prune limit'
          USING ERRCODE = '22023';
    END IF;
    PERFORM northstar_mix_pam_capacity_lock();
    WITH expired AS (
        SELECT operation_id FROM mix_pam_operations
         WHERE state='terminal' AND expires_at<=clock_timestamp()
           AND (delivered_at IS NOT NULL OR dead_lettered_at IS NOT NULL)
         ORDER BY expires_at,operation_id
         LIMIT requested_limit FOR UPDATE SKIP LOCKED
    ), removed AS (
        DELETE FROM mix_pam_operations operation USING expired
         WHERE operation.operation_id=expired.operation_id
        RETURNING operation.operation_id
    )
    SELECT COUNT(*)::BIGINT INTO removed_count FROM removed;
    RETURN removed_count;
END;
$$;

-- Correctness does not depend on the bounded maintenance worker. Before a new
-- producer transaction starts, this capability reclaims every committed,
-- retention-expired terminal row (the hard authority caps the scan at 10,000)
-- and commits that progress independently of the later admission result.
CREATE FUNCTION northstar_mix_pam_capacity_reconcile()
RETURNS BIGINT
LANGUAGE plpgsql
SET search_path FROM CURRENT
AS $$
DECLARE
    removed_count BIGINT;
BEGIN
    PERFORM northstar_mix_pam_capacity_lock();
    WITH removed AS (
        DELETE FROM mix_pam_operations operation
         WHERE operation.state='terminal'
           AND operation.expires_at<=clock_timestamp()
           AND (operation.delivered_at IS NOT NULL
                OR operation.dead_lettered_at IS NOT NULL)
        RETURNING operation.operation_id
    )
    SELECT COUNT(*)::BIGINT INTO removed_count FROM removed;
    RETURN removed_count;
END;
$$;

CREATE TRIGGER trg_mix_pam_operation_capacity_insert
BEFORE INSERT ON mix_pam_operations
FOR EACH ROW EXECUTE FUNCTION northstar_mix_pam_operation_capacity_insert();

CREATE TRIGGER trg_mix_pam_operation_capacity_delete
AFTER DELETE ON mix_pam_operations
FOR EACH ROW EXECUTE FUNCTION northstar_mix_pam_operation_capacity_delete();

CREATE TRIGGER users_mix_pam_capacity_predelete_lock
BEFORE DELETE ON users
FOR EACH ROW EXECUTE FUNCTION northstar_mix_pam_user_predelete_lock();

-- This owner-held capability is the complete, unbounded-by-page reconciliation
-- phase. The hard delivery ledger still caps work at 100,000 rows; there is no
-- arbitrary retry count or worker cadence on the correctness path.
CREATE FUNCTION northstar_mix_delivery_capacity_reconcile()
RETURNS BIGINT
LANGUAGE plpgsql
SET search_path FROM CURRENT
AS $$
DECLARE
    reconciled_events BIGINT;
BEGIN
    PERFORM pg_advisory_xact_lock(
        hashtextextended(
            'mix-delivery-capacity-v3:' ||
            ('mix_delivery_capacity'::regclass)::oid::text,
            0
        )
    );
    DELETE FROM mix_delivery_events event
     WHERE NOT EXISTS (
         SELECT 1 FROM mix_delivery_recipients recipient
          WHERE recipient.event_id = event.event_id
     );
    GET DIAGNOSTICS reconciled_events = ROW_COUNT;
    PERFORM northstar_mix_delivery_capacity_drain();
    RETURN reconciled_events;
END;
$$;

-- Pin every capability to this migration's actual schema. Trigger routines are
-- private; runtime receives only the reviewed account-lock, operation mutation
-- and committed-reconciliation entry points via the repository-authenticated
-- capability manifest.
DO $northstar_mix_capacity_capability_security$
DECLARE
    migration_schema TEXT := pg_catalog.current_schema();
    routine_signature TEXT;
    routine_oid OID;
BEGIN
    IF migration_schema IS NULL THEN
        RAISE EXCEPTION 'MIX capacity migration requires a current schema'
          USING ERRCODE = '3F000';
    END IF;
    FOREACH routine_signature IN ARRAY ARRAY[
      'northstar_mix_pam_capacity_lock()',
      'northstar_mix_pam_account_capacity_lock(uuid,text)',
      'northstar_mix_pam_operation_capacity_insert()',
      'northstar_mix_pam_operation_capacity_delete()',
      'northstar_mix_pam_user_predelete_lock()',
      'northstar_mix_pam_operation_insert(uuid,uuid,text,text,text,text,text,text,bytea,uuid,bool,text,text,text[],int8,text)',
      'northstar_mix_pam_operation_prune(int8)',
      'northstar_mix_pam_capacity_reconcile()',
      'northstar_mix_delivery_capacity_reconcile()'
    ] LOOP
      routine_oid := pg_catalog.to_regprocedure(
        pg_catalog.format('%I.%s', migration_schema, routine_signature));
      IF routine_oid IS NULL THEN
        RAISE EXCEPTION 'MIX capacity capability % is absent', routine_signature
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
          'MIX capacity capability % has unsafe owner/security/search_path',
          routine_signature USING ERRCODE = '55000';
      END IF;
    END LOOP;
END;
$northstar_mix_capacity_capability_security$;

REVOKE ALL ON TABLE mix_pam_operation_capacity,
                    mix_pam_operation_user_capacity
FROM PUBLIC;

COMMENT ON TABLE mix_pam_operation_capacity IS
    'Owner-maintained exact global MIX-PAM operation capacity authority';
COMMENT ON TABLE mix_pam_operation_user_capacity IS
    'Owner-maintained exact per-account MIX-PAM operation capacity authority without a cascade-order-sensitive user foreign key';
COMMENT ON FUNCTION northstar_mix_pam_capacity_lock() IS
    'Blocking global MIX-PAM admission fence acquired after account identity and before all operation locks';
COMMENT ON FUNCTION northstar_mix_delivery_capacity_reconcile() IS
    'Independently committed orphan-event reclamation and release-ledger drain used before producer admission';
