-- PostgreSQL-authoritative deployment-wide capacity accounting.
--
-- Four independent resource classes deliberately use 64 fixed shards rather
-- than one global counter row. Every allocation starts at a stable UUID-byte
-- shard and probes a deterministic ring until one shard can accept it. Failed
-- UPDATE predicates retain no row lock; success stops immediately. The sum of
-- shard capacities is the exact deployment ceiling, while unrelated creates
-- normally lock different rows. Allocation and the authoritative object row live in the
-- same transaction through AFTER triggers, so a crash cannot commit only one
-- side of the reservation.

CREATE TABLE deployment_capacity_limits (
    singleton BOOLEAN PRIMARY KEY DEFAULT TRUE CHECK (singleton),
    configuration_epoch BIGINT NOT NULL DEFAULT 0 CHECK (configuration_epoch >= 0),
    shard_count SMALLINT NOT NULL DEFAULT 64 CHECK (shard_count = 64),
    account_limit BIGINT NOT NULL CHECK (account_limit >= 1),
    muc_room_limit BIGINT NOT NULL CHECK (muc_room_limit >= 1),
    muc_rooms_per_owner_limit BIGINT NOT NULL CHECK (muc_rooms_per_owner_limit >= 1),
    live_session_limit BIGINT NOT NULL CHECK (live_session_limit >= 1),
    sessions_per_account_limit BIGINT NOT NULL CHECK (sessions_per_account_limit >= 1),
    resumable_session_limit BIGINT NOT NULL CHECK (resumable_session_limit >= 1),
    configured_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
);

CREATE TABLE deployment_capacity_shards (
    resource_kind TEXT NOT NULL CHECK (
        resource_kind IN ('account','muc_room','live_session','sm_session')
    ),
    shard SMALLINT NOT NULL CHECK (shard BETWEEN 0 AND 63),
    capacity BIGINT NOT NULL CHECK (capacity >= 0),
    used BIGINT NOT NULL DEFAULT 0 CHECK (used >= 0 AND used <= capacity),
    PRIMARY KEY (resource_kind, shard)
);

CREATE TABLE deployment_capacity_allocations (
    resource_kind TEXT NOT NULL CHECK (
        resource_kind IN ('account','muc_room','live_session','sm_session')
    ),
    entity_id UUID NOT NULL,
    shard SMALLINT NOT NULL CHECK (shard BETWEEN 0 AND 63),
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (resource_kind, entity_id),
    FOREIGN KEY (resource_kind, shard)
        REFERENCES deployment_capacity_shards(resource_kind, shard)
        DEFERRABLE INITIALLY IMMEDIATE
);
CREATE INDEX deployment_capacity_allocations_shard_idx
    ON deployment_capacity_allocations(resource_kind, shard);

-- Bulk maintenance must predeclare every allocation it will mutate. This
-- helper locks the canonical (resource_kind,shard,entity) order in one SQL
-- statement; deadlock retry is bounded and only defensive.
CREATE OR REPLACE FUNCTION northstar_capacity_lock_batch(p_entries JSONB)
RETURNS INTEGER LANGUAGE plpgsql AS $$
DECLARE locked_count INTEGER; attempt INTEGER := 0;
BEGIN
 IF jsonb_typeof(p_entries)<>'array' OR jsonb_array_length(p_entries)>10000 THEN
  RAISE EXCEPTION 'invalid capacity lock batch';
 END IF;
 LOOP
  BEGIN
   WITH requested AS MATERIALIZED (
    SELECT value->>'resource_kind' AS resource_kind,
           (value->>'entity_id')::UUID AS entity_id
      FROM jsonb_array_elements(p_entries)
   ), ordered AS MATERIALIZED (
    SELECT a.resource_kind,a.shard,a.entity_id
      FROM deployment_capacity_allocations a JOIN requested r
       ON r.resource_kind=a.resource_kind AND r.entity_id=a.entity_id
     ORDER BY a.resource_kind,a.shard,a.entity_id
   )
   SELECT COUNT(*) INTO locked_count FROM (
    SELECT a.resource_kind FROM deployment_capacity_allocations a JOIN ordered o
      ON (a.resource_kind,a.shard,a.entity_id)=(o.resource_kind,o.shard,o.entity_id)
      JOIN deployment_capacity_shards s
       ON (s.resource_kind,s.shard)=(a.resource_kind,a.shard)
     ORDER BY a.resource_kind,a.shard,a.entity_id FOR UPDATE OF s,a
   ) locked;
   RETURN locked_count;
  EXCEPTION WHEN deadlock_detected THEN
   attempt := attempt+1;
   IF attempt>=3 THEN RAISE; END IF;
   PERFORM pg_sleep(0.005*attempt);
  END;
 END LOOP;
END $$;

-- Per-owner rows serialize only one account's own admission.  They prevent a
-- single account from consuming the deployment ceiling without introducing a
-- shared-NAT/global row-lock convoy.
CREATE TABLE deployment_account_capacity (
    resource_kind TEXT NOT NULL CHECK (resource_kind IN ('muc_room','live_session','sm_session')),
    owner_id UUID NOT NULL,
    used BIGINT NOT NULL CHECK (used >= 0),
    PRIMARY KEY (resource_kind, owner_id)
);

-- A bound C2S route owns exactly one leased row.  Suspended XEP-0198 routes
-- extend this lease to their negotiated expiry and resume transfers the same
-- row to the new connection UUID.  Expiry is conservative: counters are not
-- decremented until maintenance actually deletes the row.
CREATE TABLE deployment_session_leases (
    -- Stable allocation identity. It is initialized from the first connection
    -- UUID but does not change when XEP-0198 transfers the route.
    lease_id UUID PRIMARY KEY,
    connection_id UUID NOT NULL UNIQUE,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    full_jid TEXT NOT NULL UNIQUE CHECK (octet_length(full_jid) BETWEEN 3 AND 3071),
    lease_until TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
);
CREATE INDEX deployment_session_leases_expiry_idx
    ON deployment_session_leases(lease_until, lease_id);
CREATE INDEX deployment_session_leases_user_idx
    ON deployment_session_leases(user_id, lease_until);

CREATE OR REPLACE FUNCTION northstar_capacity_limit(p_kind TEXT)
RETURNS BIGINT
LANGUAGE SQL
STABLE
STRICT
AS $$
    SELECT CASE p_kind
        WHEN 'account' THEN account_limit
        WHEN 'muc_room' THEN muc_room_limit
        WHEN 'live_session' THEN live_session_limit
        WHEN 'sm_session' THEN resumable_session_limit
        ELSE NULL
    END
    FROM deployment_capacity_limits WHERE singleton
$$;

-- Do not depend on PostgreSQL's version-specific hash functions for persisted
-- placement. XORing the RFC 4122 bytes is immutable across PostgreSQL majors.
CREATE OR REPLACE FUNCTION northstar_capacity_start_shard(p_entity UUID)
RETURNS SMALLINT
LANGUAGE SQL
IMMUTABLE
STRICT
PARALLEL SAFE
AS $$
    SELECT ((get_byte(uuid_send(p_entity),0) # get_byte(uuid_send(p_entity),1)
           # get_byte(uuid_send(p_entity),2) # get_byte(uuid_send(p_entity),3)
           # get_byte(uuid_send(p_entity),4) # get_byte(uuid_send(p_entity),5)
           # get_byte(uuid_send(p_entity),6) # get_byte(uuid_send(p_entity),7)
           # get_byte(uuid_send(p_entity),8) # get_byte(uuid_send(p_entity),9)
           # get_byte(uuid_send(p_entity),10) # get_byte(uuid_send(p_entity),11)
           # get_byte(uuid_send(p_entity),12) # get_byte(uuid_send(p_entity),13)
           # get_byte(uuid_send(p_entity),14) # get_byte(uuid_send(p_entity),15)) % 64)::SMALLINT
$$;

CREATE OR REPLACE FUNCTION northstar_capacity_acquire(p_kind TEXT, p_entity UUID)
RETURNS SMALLINT
LANGUAGE plpgsql
AS $$
DECLARE
    existing_shard SMALLINT;
    selected_shard SMALLINT;
    start_shard SMALLINT;
    probe INTEGER;
BEGIN
    SELECT shard INTO existing_shard
      FROM deployment_capacity_allocations
     WHERE resource_kind=p_kind AND entity_id=p_entity;
    IF FOUND THEN
        RETURN existing_shard;
    END IF;

    start_shard := northstar_capacity_start_shard(p_entity);
    FOR probe IN 0..63 LOOP
        selected_shard := ((start_shard+probe) % 64)::SMALLINT;
        -- A full shard does not satisfy the UPDATE predicate and therefore
        -- leaves no row lock behind. The first successful row remains the
        -- sole global lock held by this allocation.
        UPDATE deployment_capacity_shards
           SET used=used+1
         WHERE resource_kind=p_kind AND shard=selected_shard AND used < capacity;
        IF FOUND THEN
            INSERT INTO deployment_capacity_allocations(resource_kind,entity_id,shard)
            VALUES(p_kind,p_entity,selected_shard);
            RETURN selected_shard;
        END IF;
    END LOOP;
    RETURN NULL;
END
$$;

CREATE OR REPLACE FUNCTION northstar_capacity_release(p_kind TEXT, p_entity UUID)
RETURNS BOOLEAN
LANGUAGE plpgsql
AS $$
DECLARE
    released_shard SMALLINT;
BEGIN
    -- Discover without locking the allocation, then take the global shard
    -- first. Every create/delete path therefore uses shard -> allocation ->
    -- owner ordering and cannot form a reverse-order cycle.
    SELECT shard INTO released_shard
      FROM deployment_capacity_allocations
     WHERE resource_kind=p_kind AND entity_id=p_entity;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'deployment capacity allocation is missing for %/%', p_kind, p_entity
            USING ERRCODE='P0001';
    END IF;
    PERFORM 1 FROM deployment_capacity_shards
     WHERE resource_kind=p_kind AND shard=released_shard FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'deployment capacity shard is missing for %/%', p_kind, p_entity
            USING ERRCODE='P0001';
    END IF;
    DELETE FROM deployment_capacity_allocations
     WHERE resource_kind=p_kind AND entity_id=p_entity AND shard=released_shard;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'deployment capacity allocation changed during release for %/%', p_kind, p_entity
            USING ERRCODE='P0001';
    END IF;
    UPDATE deployment_capacity_shards
       SET used=used-1
     WHERE resource_kind=p_kind AND shard=released_shard AND used > 0;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'deployment capacity counter underflow for %/%', p_kind, p_entity
            USING ERRCODE='P0001';
    END IF;
    RETURN TRUE;
END
$$;

CREATE OR REPLACE FUNCTION northstar_account_capacity_acquire(p_kind TEXT, p_owner UUID)
RETURNS VOID
LANGUAGE plpgsql
AS $$
DECLARE
    owner_limit BIGINT;
BEGIN
    SELECT CASE p_kind
        WHEN 'muc_room' THEN muc_rooms_per_owner_limit
        WHEN 'live_session' THEN sessions_per_account_limit
        WHEN 'sm_session' THEN sessions_per_account_limit
    END INTO owner_limit
    FROM deployment_capacity_limits WHERE singleton;
    IF owner_limit IS NULL THEN
        RAISE EXCEPTION 'unknown per-account capacity kind %', p_kind USING ERRCODE='P0001';
    END IF;
    INSERT INTO deployment_account_capacity(resource_kind,owner_id,used)
    VALUES(p_kind,p_owner,1)
    ON CONFLICT(resource_kind,owner_id) DO UPDATE SET used=deployment_account_capacity.used+1
      WHERE deployment_account_capacity.used < owner_limit;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'account capacity exhausted for %', p_kind
            USING ERRCODE='P0001', HINT='raise the matching per-account limit with a higher DEPLOYMENT_CAPACITY_EPOCH';
    END IF;
END
$$;

CREATE OR REPLACE FUNCTION northstar_account_capacity_release(p_kind TEXT, p_owner UUID)
RETURNS VOID
LANGUAGE plpgsql
AS $$
BEGIN
    UPDATE deployment_account_capacity SET used=used-1
     WHERE resource_kind=p_kind AND owner_id=p_owner AND used > 0;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'account capacity counter missing or underflowed for %/%', p_kind, p_owner
            USING ERRCODE='P0001';
    END IF;
    DELETE FROM deployment_account_capacity
     WHERE resource_kind=p_kind AND owner_id=p_owner AND used=0;
END
$$;

CREATE OR REPLACE FUNCTION northstar_account_capacity_transfer(
    p_kind TEXT, p_old_owner UUID, p_new_owner UUID
)
RETURNS VOID
LANGUAGE plpgsql
AS $$
DECLARE
    owner_limit BIGINT;
    first_owner UUID;
    second_owner UUID;
    old_used BIGINT;
    new_used BIGINT;
BEGIN
    IF p_old_owner IS NOT DISTINCT FROM p_new_owner THEN
        RETURN;
    END IF;
    SELECT muc_rooms_per_owner_limit INTO owner_limit
      FROM deployment_capacity_limits WHERE singleton;
    first_owner := LEAST(p_old_owner,p_new_owner);
    second_owner := GREATEST(p_old_owner,p_new_owner);
    INSERT INTO deployment_account_capacity(resource_kind,owner_id,used)
    VALUES(p_kind,first_owner,0) ON CONFLICT DO NOTHING;
    INSERT INTO deployment_account_capacity(resource_kind,owner_id,used)
    VALUES(p_kind,second_owner,0) ON CONFLICT DO NOTHING;
    -- UUID order is identical for every concurrent ownership swap.
    PERFORM 1 FROM deployment_account_capacity
     WHERE resource_kind=p_kind AND owner_id IN(first_owner,second_owner)
     ORDER BY owner_id FOR UPDATE;
    SELECT used INTO old_used FROM deployment_account_capacity
     WHERE resource_kind=p_kind AND owner_id=p_old_owner;
    SELECT used INTO new_used FROM deployment_account_capacity
     WHERE resource_kind=p_kind AND owner_id=p_new_owner;
    IF old_used IS NULL OR old_used < 1 THEN
        RAISE EXCEPTION 'account capacity counter missing or underflowed for %/%', p_kind, p_old_owner
            USING ERRCODE='P0001';
    END IF;
    IF new_used >= owner_limit THEN
        RAISE EXCEPTION 'account capacity exhausted for %', p_kind USING ERRCODE='P0001';
    END IF;
    UPDATE deployment_account_capacity SET used=used+1
     WHERE resource_kind=p_kind AND owner_id=p_new_owner;
    UPDATE deployment_account_capacity SET used=used-1
     WHERE resource_kind=p_kind AND owner_id=p_old_owner;
    DELETE FROM deployment_account_capacity
     WHERE resource_kind=p_kind AND owner_id=p_old_owner AND used=0;
END
$$;

CREATE OR REPLACE FUNCTION northstar_users_capacity_insert()
RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN
    IF northstar_capacity_acquire('account',NEW.id) IS NULL THEN
        RAISE EXCEPTION 'deployment capacity exhausted for account'
            USING ERRCODE='P0001', HINT='raise MAX_ACCOUNTS_TOTAL with a higher DEPLOYMENT_CAPACITY_EPOCH or delete an account';
    END IF;
    RETURN NEW;
END
$$;
CREATE OR REPLACE FUNCTION northstar_users_capacity_delete()
RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN
    PERFORM northstar_capacity_release('account',OLD.id);
    RETURN OLD;
END
$$;

CREATE OR REPLACE FUNCTION northstar_users_capacity_predelete_lock()
RETURNS TRIGGER LANGUAGE plpgsql AS $$
DECLARE entries JSONB;
BEGIN
 SELECT COALESCE(jsonb_agg(entry ORDER BY entry->>'resource_kind',entry->>'entity_id'),'[]'::JSONB)
 INTO entries FROM (
  SELECT jsonb_build_object('resource_kind','account','entity_id',OLD.id) entry
  UNION ALL SELECT jsonb_build_object('resource_kind','muc_room','entity_id',r.id)
    FROM muc_rooms r WHERE r.owner_id=OLD.id AND r.destroyed_at IS NULL
  UNION ALL SELECT jsonb_build_object('resource_kind','live_session','entity_id',l.lease_id)
    FROM deployment_session_leases l WHERE l.user_id=OLD.id
  UNION ALL SELECT jsonb_build_object('resource_kind','sm_session','entity_id',s.id)
    FROM sm_resume_sessions s WHERE s.user_id=OLD.id
 ) requested;
 PERFORM northstar_capacity_lock_batch(entries);
 RETURN OLD;
END $$;

CREATE OR REPLACE FUNCTION northstar_muc_capacity_insert()
RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.destroyed_at IS NOT NULL THEN
        RETURN NEW;
    END IF;
    IF northstar_capacity_acquire('muc_room',NEW.id) IS NULL THEN
        RAISE EXCEPTION 'deployment capacity exhausted for muc_room'
            USING ERRCODE='P0001', HINT='raise MAX_MUC_ROOMS_TOTAL with a higher DEPLOYMENT_CAPACITY_EPOCH or destroy a room';
    END IF;
    IF NEW.owner_id IS NOT NULL THEN
        PERFORM northstar_account_capacity_acquire('muc_room',NEW.owner_id);
    END IF;
    RETURN NEW;
END
$$;
CREATE OR REPLACE FUNCTION northstar_muc_capacity_delete()
RETURNS TRIGGER LANGUAGE plpgsql AS $$
DECLARE
    allocation_exists BOOLEAN;
BEGIN
    SELECT EXISTS(
        SELECT 1 FROM deployment_capacity_allocations
         WHERE resource_kind='muc_room' AND entity_id=OLD.id
    ) INTO allocation_exists;
    IF allocation_exists THEN
        PERFORM northstar_capacity_release('muc_room',OLD.id);
        IF OLD.owner_id IS NOT NULL THEN
            PERFORM northstar_account_capacity_release('muc_room',OLD.owner_id);
        END IF;
    ELSIF OLD.destroyed_at IS NULL THEN
        RAISE EXCEPTION 'live MUC room capacity allocation is missing for %', OLD.id
            USING ERRCODE='P0001';
    END IF;
    RETURN OLD;
END
$$;
CREATE OR REPLACE FUNCTION northstar_muc_capacity_destroy_update()
RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN
    IF OLD.destroyed_at IS NULL AND NEW.destroyed_at IS NOT NULL THEN
        -- The room stops consuming live deployment capacity in the same
        -- transaction as its authoritative tombstone.  A later physical
        -- retention delete sees no allocation and therefore cannot double
        -- decrement either counter.
        PERFORM northstar_capacity_release('muc_room',OLD.id);
        IF OLD.owner_id IS NOT NULL THEN
            PERFORM northstar_account_capacity_release('muc_room',OLD.owner_id);
        END IF;
    END IF;
    RETURN NEW;
END
$$;
CREATE OR REPLACE FUNCTION northstar_muc_capacity_owner_update()
RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN
    IF OLD.owner_id IS NOT DISTINCT FROM NEW.owner_id THEN
        RETURN NEW;
    END IF;
    IF OLD.destroyed_at IS NULL AND NEW.destroyed_at IS NOT NULL THEN
        -- The destroyed_at trigger releases the allocation and OLD owner.
        -- Do not transfer/release that owner a second time when one direct
        -- maintenance statement also clears owner_id.
        RETURN NEW;
    END IF;
    -- A destroyed room released both counters at its tombstone transition.
    -- Account deletion may subsequently clear its owner FK without changing
    -- capacity authority.
    IF OLD.destroyed_at IS NOT NULL THEN
        RETURN NEW;
    END IF;
    IF OLD.owner_id IS NULL THEN
        PERFORM northstar_account_capacity_acquire('muc_room',NEW.owner_id);
    ELSIF NEW.owner_id IS NULL THEN
        PERFORM northstar_account_capacity_release('muc_room',OLD.owner_id);
    ELSE
        PERFORM northstar_account_capacity_transfer('muc_room',OLD.owner_id,NEW.owner_id);
    END IF;
    RETURN NEW;
END
$$;

CREATE OR REPLACE FUNCTION northstar_session_capacity_insert()
RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN
    IF northstar_capacity_acquire('live_session',NEW.lease_id) IS NULL THEN
        RAISE EXCEPTION 'deployment capacity exhausted for live_session'
            USING ERRCODE='P0001', HINT='raise MAX_LIVE_SESSIONS_TOTAL with a higher DEPLOYMENT_CAPACITY_EPOCH';
    END IF;
    PERFORM northstar_account_capacity_acquire('live_session',NEW.user_id);
    RETURN NEW;
END
$$;
CREATE OR REPLACE FUNCTION northstar_session_capacity_delete()
RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN
    PERFORM northstar_capacity_release('live_session',OLD.lease_id);
    PERFORM northstar_account_capacity_release('live_session',OLD.user_id);
    RETURN OLD;
END
$$;
CREATE OR REPLACE FUNCTION northstar_session_capacity_update()
RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN
    IF OLD.lease_id IS DISTINCT FROM NEW.lease_id THEN
        RAISE EXCEPTION 'live-session capacity lease identity is immutable' USING ERRCODE='P0001';
    END IF;
    IF OLD.user_id IS DISTINCT FROM NEW.user_id THEN
        RAISE EXCEPTION 'live-session capacity owner is immutable' USING ERRCODE='P0001';
    END IF;
    IF OLD.full_jid IS DISTINCT FROM NEW.full_jid THEN
        RAISE EXCEPTION 'live-session capacity JID is immutable' USING ERRCODE='P0001';
    END IF;
    RETURN NEW;
END
$$;

CREATE OR REPLACE FUNCTION northstar_sm_capacity_insert()
RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN
    IF northstar_capacity_acquire('sm_session',NEW.id) IS NULL THEN
        RAISE EXCEPTION 'deployment capacity exhausted for sm_session'
            USING ERRCODE='P0001', HINT='raise SM_MAX_RESUMABLE_SESSIONS with a higher DEPLOYMENT_CAPACITY_EPOCH';
    END IF;
    PERFORM northstar_account_capacity_acquire('sm_session',NEW.user_id);
    RETURN NEW;
END
$$;
CREATE OR REPLACE FUNCTION northstar_sm_capacity_delete()
RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN
    DELETE FROM deployment_session_leases WHERE connection_id=OLD.connection_id;
    PERFORM northstar_capacity_release('sm_session',OLD.id);
    PERFORM northstar_account_capacity_release('sm_session',OLD.user_id);
    RETURN OLD;
END
$$;

-- Bootstrap defaults are deliberately above the single-node 1,000-session
-- design envelope and are raised, never lowered, for pre-existing rows.  The
-- process reconciler replaces epoch 0 with the explicit environment values
-- before any listener starts.
INSERT INTO deployment_capacity_limits(
    singleton,configuration_epoch,account_limit,muc_room_limit,
    muc_rooms_per_owner_limit,live_session_limit,sessions_per_account_limit,
    resumable_session_limit
)
SELECT TRUE,0,
       GREATEST(100000,(SELECT COUNT(*) FROM users)),
       GREATEST(10000,(SELECT COUNT(*) FROM muc_rooms WHERE destroyed_at IS NULL)),
       GREATEST(100,COALESCE((SELECT MAX(n) FROM (SELECT COUNT(*) n FROM muc_rooms WHERE destroyed_at IS NULL AND owner_id IS NOT NULL GROUP BY owner_id) q),0)),
       GREATEST(4096,(SELECT COUNT(*) FROM sm_resume_sessions WHERE expires_at>clock_timestamp())),
       GREATEST(64,COALESCE((SELECT MAX(n) FROM (SELECT COUNT(*) n FROM sm_resume_sessions GROUP BY user_id) q),0)),
       GREATEST(4096,(SELECT COUNT(*) FROM sm_resume_sessions));

INSERT INTO deployment_capacity_shards(resource_kind,shard,capacity,used)
SELECT kind, shard,
       (northstar_capacity_limit(kind) / 64)
         + CASE WHEN shard < (northstar_capacity_limit(kind) % 64) THEN 1 ELSE 0 END,
       0
FROM unnest(ARRAY['account','muc_room','live_session','sm_session']) AS k(kind)
CROSS JOIN generate_series(0,63) AS s(shard);

DO $$
DECLARE
    entity RECORD;
BEGIN
    FOR entity IN SELECT id FROM users ORDER BY id LOOP
        IF northstar_capacity_acquire('account',entity.id) IS NULL THEN
            RAISE EXCEPTION 'cannot backfill account capacity allocation for %',entity.id;
        END IF;
    END LOOP;
    FOR entity IN SELECT id FROM muc_rooms WHERE destroyed_at IS NULL ORDER BY id LOOP
        IF northstar_capacity_acquire('muc_room',entity.id) IS NULL THEN
            RAISE EXCEPTION 'cannot backfill MUC-room capacity allocation for %',entity.id;
        END IF;
    END LOOP;
    IF EXISTS (
        SELECT 1 FROM sm_resume_sessions WHERE expires_at>clock_timestamp()
        GROUP BY full_jid HAVING COUNT(*) > 1
    ) THEN
        RAISE EXCEPTION 'cannot initialize capacity ledger: multiple unexpired SM rows own one full JID; revoke duplicates before migration';
    END IF;
    IF EXISTS (
        SELECT 1 FROM sm_resume_sessions WHERE expires_at>clock_timestamp()
        GROUP BY connection_id HAVING COUNT(*) > 1
    ) THEN
        RAISE EXCEPTION 'cannot initialize capacity ledger: multiple unexpired SM rows own one connection ID; revoke duplicates before migration';
    END IF;
END
$$;

INSERT INTO deployment_session_leases(lease_id,connection_id,user_id,full_jid,lease_until)
SELECT connection_id,connection_id,user_id,full_jid,
       CASE WHEN resumable THEN expires_at ELSE GREATEST(live_lease_until,clock_timestamp()+INTERVAL '120 seconds') END
FROM sm_resume_sessions WHERE expires_at>clock_timestamp();

DO $$
DECLARE
    entity RECORD;
BEGIN
    FOR entity IN SELECT lease_id FROM deployment_session_leases ORDER BY lease_id LOOP
        IF northstar_capacity_acquire('live_session',entity.lease_id) IS NULL THEN
            RAISE EXCEPTION 'cannot backfill live-session capacity allocation for %',entity.lease_id;
        END IF;
    END LOOP;
    FOR entity IN SELECT id FROM sm_resume_sessions ORDER BY id LOOP
        IF northstar_capacity_acquire('sm_session',entity.id) IS NULL THEN
            RAISE EXCEPTION 'cannot backfill SM-session capacity allocation for %',entity.id;
        END IF;
    END LOOP;
END
$$;

INSERT INTO deployment_account_capacity(resource_kind,owner_id,used)
SELECT 'muc_room',owner_id,COUNT(*) FROM muc_rooms
 WHERE destroyed_at IS NULL AND owner_id IS NOT NULL GROUP BY owner_id;
INSERT INTO deployment_account_capacity(resource_kind,owner_id,used)
SELECT 'live_session',user_id,COUNT(*) FROM deployment_session_leases GROUP BY user_id;
INSERT INTO deployment_account_capacity(resource_kind,owner_id,used)
SELECT 'sm_session',user_id,COUNT(*) FROM sm_resume_sessions GROUP BY user_id;

CREATE TRIGGER users_deployment_capacity_insert
AFTER INSERT ON users FOR EACH ROW EXECUTE FUNCTION northstar_users_capacity_insert();
CREATE TRIGGER users_deployment_capacity_predelete_lock
BEFORE DELETE ON users FOR EACH ROW EXECUTE FUNCTION northstar_users_capacity_predelete_lock();
CREATE TRIGGER users_deployment_capacity_delete
AFTER DELETE ON users FOR EACH ROW EXECUTE FUNCTION northstar_users_capacity_delete();
CREATE TRIGGER muc_rooms_deployment_capacity_insert
AFTER INSERT ON muc_rooms FOR EACH ROW EXECUTE FUNCTION northstar_muc_capacity_insert();
CREATE TRIGGER muc_rooms_deployment_capacity_delete
AFTER DELETE ON muc_rooms FOR EACH ROW EXECUTE FUNCTION northstar_muc_capacity_delete();
CREATE TRIGGER muc_rooms_deployment_capacity_destroy_update
AFTER UPDATE OF destroyed_at ON muc_rooms FOR EACH ROW
EXECUTE FUNCTION northstar_muc_capacity_destroy_update();
CREATE TRIGGER muc_rooms_deployment_capacity_owner_update
AFTER UPDATE OF owner_id ON muc_rooms FOR EACH ROW EXECUTE FUNCTION northstar_muc_capacity_owner_update();
CREATE TRIGGER deployment_session_leases_capacity_insert
AFTER INSERT ON deployment_session_leases FOR EACH ROW EXECUTE FUNCTION northstar_session_capacity_insert();
CREATE TRIGGER deployment_session_leases_capacity_delete
AFTER DELETE ON deployment_session_leases FOR EACH ROW EXECUTE FUNCTION northstar_session_capacity_delete();
CREATE TRIGGER deployment_session_leases_capacity_update
AFTER UPDATE OF lease_id,connection_id,user_id,full_jid ON deployment_session_leases
FOR EACH ROW EXECUTE FUNCTION northstar_session_capacity_update();
CREATE TRIGGER sm_resume_sessions_deployment_capacity_insert
AFTER INSERT ON sm_resume_sessions FOR EACH ROW EXECUTE FUNCTION northstar_sm_capacity_insert();
CREATE TRIGGER sm_resume_sessions_deployment_capacity_delete
AFTER DELETE ON sm_resume_sessions FOR EACH ROW EXECUTE FUNCTION northstar_sm_capacity_delete();
