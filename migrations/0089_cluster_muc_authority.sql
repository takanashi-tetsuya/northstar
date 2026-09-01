-- PostgreSQL authority for experimental clustered XEP-0045 rooms.
--
-- Redis Pub/Sub is deliberately absent from this schema.  It may carry a
-- signed, short-lived pull hint, but room mutations, occupant ownership and
-- notification recovery are fenced here using the PostgreSQL clock.

ALTER TABLE muc_rooms
    ADD COLUMN room_epoch UUID NOT NULL DEFAULT gen_random_uuid(),
    ADD COLUMN config_version BIGINT NOT NULL DEFAULT 1
        CHECK (config_version >= 1),
    ADD COLUMN next_occupancy_epoch BIGINT NOT NULL DEFAULT 1
        CHECK (next_occupancy_epoch >= 1),
    ADD COLUMN next_event_sequence BIGINT NOT NULL DEFAULT 1
        CHECK (next_event_sequence >= 1),
    ADD COLUMN destroyed_at TIMESTAMPTZ,
    ADD COLUMN destroyed_operation_id UUID,
    ADD COLUMN destroyed_by VARCHAR(3071),
    ADD COLUMN destroy_reason TEXT,
    ADD COLUMN destroy_alternate_jid VARCHAR(3071),
    ADD CONSTRAINT muc_rooms_cluster_epoch_unique UNIQUE (id, room_epoch),
    ADD CONSTRAINT muc_rooms_destroy_fence_check CHECK (
        (destroyed_at IS NULL
            AND destroyed_operation_id IS NULL
            AND destroyed_by IS NULL
            AND destroy_reason IS NULL
            AND destroy_alternate_jid IS NULL)
        OR
        (destroyed_at IS NOT NULL AND destroyed_operation_id IS NOT NULL)
    ),
    ADD CONSTRAINT muc_rooms_destroy_reason_size_check CHECK (
        destroy_reason IS NULL OR octet_length(destroy_reason) <= 4096
    );

-- Destruction creates an immutable incarnation tombstone, not a permanent
-- reservation of the human-readable room name.  A later room with the same
-- localpart receives a fresh UUID and room_epoch, so an old node/cache cannot
-- address or authorize mutations against the new incarnation.
ALTER TABLE muc_rooms
    DROP CONSTRAINT IF EXISTS muc_rooms_localpart_key;
CREATE UNIQUE INDEX muc_rooms_live_localpart_unique
    ON muc_rooms (localpart)
    WHERE destroyed_at IS NULL;

CREATE INDEX muc_rooms_live_public_idx
    ON muc_rooms (localpart)
    WHERE destroyed_at IS NULL AND public AND configuration_state = 'active';
CREATE INDEX muc_rooms_destroyed_retention_idx
    ON muc_rooms (destroyed_at, id)
    WHERE destroyed_at IS NOT NULL;

COMMENT ON COLUMN muc_rooms.room_epoch IS
    'Immutable room incarnation fence; a tombstoned room is never revived from Redis cache';
COMMENT ON COLUMN muc_rooms.config_version IS
    'Monotonic PostgreSQL-authoritative room configuration generation';
COMMENT ON COLUMN muc_rooms.destroyed_at IS
    'Incarnation tombstone fence retained for bounded recovery/audit; a same-localpart replacement always receives a fresh room UUID and room_epoch.';

CREATE OR REPLACE FUNCTION fence_cluster_muc_room_authority()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
DECLARE
    authority_changed BOOLEAN;
BEGIN
    IF NEW.room_epoch <> OLD.room_epoch THEN
        RAISE EXCEPTION 'MUC room_epoch is immutable';
    END IF;
    IF NEW.next_occupancy_epoch < OLD.next_occupancy_epoch
       OR NEW.next_event_sequence < OLD.next_event_sequence THEN
        RAISE EXCEPTION 'MUC room authority counters cannot move backwards';
    END IF;
    IF OLD.destroyed_at IS NOT NULL AND NEW IS DISTINCT FROM OLD THEN
        -- ON DELETE SET NULL for a deleted local owner is the sole permitted
        -- tombstone rewrite.  It removes a live account FK, not room authority.
        IF NOT (OLD.owner_id IS NOT NULL
                AND NEW.owner_id IS NULL
                AND (to_jsonb(NEW) - 'owner_id') = (to_jsonb(OLD) - 'owner_id')) THEN
            RAISE EXCEPTION 'a destroyed MUC room incarnation is fenced';
        END IF;
    END IF;
    IF OLD.destroyed_at IS NULL AND NEW.destroyed_at IS NOT NULL
       AND NEW.destroyed_operation_id IS NULL THEN
        RAISE EXCEPTION 'MUC room destruction requires an operation UUID';
    END IF;

    authority_changed :=
        ROW(NEW.title, NEW.description, NEW.persistent, NEW.members_only,
            NEW.public, NEW.moderated, NEW.non_anonymous,
            NEW.max_occupants, NEW.password_hash, NEW.allow_subject_change,
            NEW.allow_invites, NEW.allow_private_messages,
            NEW.logging_enabled, NEW.allow_registration,
            NEW.configuration_state, NEW.configuration_owner_jid,
            NEW.configuration_expires_at, NEW.destroyed_at)
        IS DISTINCT FROM
        ROW(OLD.title, OLD.description, OLD.persistent, OLD.members_only,
            OLD.public, OLD.moderated, OLD.non_anonymous,
            OLD.max_occupants, OLD.password_hash, OLD.allow_subject_change,
            OLD.allow_invites, OLD.allow_private_messages,
            OLD.logging_enabled, OLD.allow_registration,
            OLD.configuration_state, OLD.configuration_owner_jid,
            OLD.configuration_expires_at, OLD.destroyed_at);

    IF authority_changed THEN
        IF NEW.config_version = OLD.config_version THEN
            NEW.config_version := OLD.config_version + 1;
        ELSIF NEW.config_version <> OLD.config_version + 1 THEN
            RAISE EXCEPTION 'MUC config_version must advance by exactly one';
        END IF;
    ELSIF NEW.config_version <> OLD.config_version THEN
        RAISE EXCEPTION 'MUC config_version changed without an authority mutation';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER trg_muc_rooms_cluster_authority_fence
BEFORE UPDATE ON muc_rooms
FOR EACH ROW EXECUTE FUNCTION fence_cluster_muc_room_authority();

CREATE OR REPLACE FUNCTION remove_destroyed_muc_live_associations()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    IF OLD.destroyed_at IS NULL AND NEW.destroyed_at IS NOT NULL THEN
        -- A MIX mirror is live routing configuration, not immutable history.
        -- Keeping it attached to a tombstone would block a fresh room
        -- incarnation from linking to the same-address MIX channel.
        DELETE FROM mix_muc_mirrors WHERE muc_room_id=OLD.id;
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER trg_muc_rooms_destroy_live_associations
AFTER UPDATE OF destroyed_at ON muc_rooms
FOR EACH ROW EXECUTE FUNCTION remove_destroyed_muc_live_associations();

-- One row is one stable room membership incarnation.  Nick and full-JID
-- uniqueness apply to live/suspended rows after the transaction has expired
-- stale leases using database time.  Exact UUID/epoch predicates fence stale
-- nodes and nickname ABA reuse.
CREATE TABLE cluster_muc_occupancies (
    room_id UUID NOT NULL,
    room_epoch UUID NOT NULL,
    occupant_incarnation UUID NOT NULL,
    occupancy_epoch BIGINT NOT NULL CHECK (occupancy_epoch >= 1),
    config_version BIGINT NOT NULL CHECK (config_version >= 1),
    identity_kind VARCHAR(16) NOT NULL
        CHECK (identity_kind IN ('local', 'federated')),
    local_user_id UUID,
    bare_jid VARCHAR(3071) NOT NULL,
    full_jid VARCHAR(3071) NOT NULL,
    nick VARCHAR(128) NOT NULL CHECK (octet_length(nick) BETWEEN 1 AND 128),
    authenticated_domain VARCHAR(1023),
    owner_node_id VARCHAR(128) NOT NULL
        CHECK (owner_node_id ~ '^[A-Za-z0-9._-]{1,128}$'),
    connection_uuid UUID NOT NULL,
    connection_epoch BIGINT NOT NULL CHECK (connection_epoch >= 1),
    sm_session_id UUID,
    state VARCHAR(16) NOT NULL
        CHECK (state IN ('active', 'suspended', 'left', 'revoked', 'expired')),
    role VARCHAR(16) NOT NULL
        CHECK (role IN ('moderator', 'participant', 'visitor', 'none')),
    affiliation VARCHAR(16) NOT NULL
        CHECK (affiliation IN ('owner', 'admin', 'member', 'outcast', 'none')),
    presence_payload TEXT NOT NULL DEFAULT ''
        CHECK (octet_length(presence_payload) <= 1048576),
    lease_until TIMESTAMPTZ NOT NULL,
    joined_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    ended_at TIMESTAMPTZ,
    PRIMARY KEY (room_id, occupant_incarnation),
    UNIQUE (room_id, occupancy_epoch),
    FOREIGN KEY (room_id, room_epoch)
        REFERENCES muc_rooms (id, room_epoch) ON DELETE RESTRICT,
    CHECK (
        (identity_kind = 'local'
            AND local_user_id IS NOT NULL
            AND authenticated_domain IS NULL)
        OR
        (identity_kind = 'federated'
            AND local_user_id IS NULL
            AND authenticated_domain IS NOT NULL)
    ),
    CHECK (
        (state IN ('active', 'suspended') AND ended_at IS NULL)
        OR
        (state IN ('left', 'revoked', 'expired') AND ended_at IS NOT NULL)
    )
);

CREATE UNIQUE INDEX cluster_muc_live_nick_unique
    ON cluster_muc_occupancies (room_id, nick)
    WHERE state IN ('active', 'suspended');
CREATE UNIQUE INDEX cluster_muc_live_full_jid_unique
    ON cluster_muc_occupancies (room_id, full_jid)
    WHERE state IN ('active', 'suspended');
CREATE INDEX cluster_muc_occupancy_owner_idx
    ON cluster_muc_occupancies (owner_node_id, lease_until)
    WHERE state IN ('active', 'suspended');
CREATE INDEX cluster_muc_occupancy_expiry_idx
    ON cluster_muc_occupancies (lease_until, room_id, occupancy_epoch)
    WHERE state IN ('active', 'suspended');
CREATE INDEX cluster_muc_occupancy_sm_idx
    ON cluster_muc_occupancies (sm_session_id)
    WHERE state = 'suspended' AND sm_session_id IS NOT NULL;

COMMENT ON TABLE cluster_muc_occupancies IS
    'PostgreSQL-clock fenced MUC occupancy authority; Redis copies are non-authoritative soft state';
COMMENT ON COLUMN cluster_muc_occupancies.local_user_id IS
    'Immutable account UUID snapshot, intentionally not a cascading FK so account erasure cannot erase the audit identity';
COMMENT ON COLUMN cluster_muc_occupancies.authenticated_domain IS
    'S2S-authenticated remote domain snapshot; PostgreSQL never infers remote ownership from a JID alone';
COMMENT ON COLUMN cluster_muc_occupancies.nick IS
    'Rename is an in-place transition only under the room lock and an exact operation tuple; occupant_incarnation and occupancy_epoch remain stable, so a later nickname reuse cannot satisfy a delayed target';

CREATE OR REPLACE FUNCTION fence_cluster_muc_occupancy_identity()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    IF ROW(NEW.room_id, NEW.room_epoch, NEW.occupant_incarnation,
           NEW.occupancy_epoch, NEW.identity_kind, NEW.local_user_id,
           NEW.bare_jid, NEW.full_jid, NEW.authenticated_domain,
           NEW.joined_at)
       IS DISTINCT FROM
       ROW(OLD.room_id, OLD.room_epoch, OLD.occupant_incarnation,
           OLD.occupancy_epoch, OLD.identity_kind, OLD.local_user_id,
           OLD.bare_jid, OLD.full_jid, OLD.authenticated_domain,
           OLD.joined_at) THEN
        RAISE EXCEPTION 'MUC occupancy principal/incarnation identity is immutable';
    END IF;
    IF OLD.state IN ('left', 'revoked', 'expired') AND NEW IS DISTINCT FROM OLD THEN
        RAISE EXCEPTION 'terminal MUC occupancy cannot be revived';
    END IF;
    IF NEW.connection_epoch < OLD.connection_epoch THEN
        RAISE EXCEPTION 'MUC connection_epoch cannot move backwards';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER trg_cluster_muc_occupancy_identity_fence
BEFORE UPDATE ON cluster_muc_occupancies
FOR EACH ROW EXECUTE FUNCTION fence_cluster_muc_occupancy_identity();

-- Every authoritative state transition has one immutable operation UUID and
-- one per-room event sequence.  actor_authorization_snapshot records the
-- exact authorization fact used inside the transaction; it is evidence, not
-- a capability that can be replayed later.
CREATE TABLE cluster_muc_operations (
    operation_id UUID PRIMARY KEY,
    room_id UUID NOT NULL,
    room_epoch UUID NOT NULL,
    operation_kind VARCHAR(32) NOT NULL CHECK (operation_kind IN (
        'join', 'rename', 'resume', 'suspend', 'leave', 'expire',
        'config', 'affiliation', 'role', 'ban', 'kick', 'destroy',
        'locked_expiry', 'account_delete'
    )),
    request_digest BYTEA NOT NULL CHECK (octet_length(request_digest) = 32),
    actor_bare_jid VARCHAR(3071),
    actor_full_jid VARCHAR(3071),
    actor_affiliation VARCHAR(16),
    authorization_source VARCHAR(24) NOT NULL CHECK (authorization_source IN (
        'local_database', 'federated_verified', 'system', 'admin_control'
    )),
    actor_authorization_snapshot JSONB NOT NULL
        CHECK (jsonb_typeof(actor_authorization_snapshot) = 'object')
        CHECK (octet_length(actor_authorization_snapshot::TEXT) <= 1048576),
    target_occupant_incarnation UUID,
    target_occupancy_epoch BIGINT,
    target_full_jid VARCHAR(3071),
    target_nick VARCHAR(128),
    target_connection_uuid UUID,
    target_connection_epoch BIGINT,
    target_snapshot JSONB,
    config_version_before BIGINT NOT NULL CHECK (config_version_before >= 1),
    config_version_after BIGINT NOT NULL CHECK (config_version_after >= config_version_before),
    event_sequence BIGINT NOT NULL CHECK (event_sequence >= 1),
    event_id UUID NOT NULL,
    audience_snapshot JSONB NOT NULL
        CHECK (jsonb_typeof(audience_snapshot) = 'array')
        CHECK (octet_length(audience_snapshot::TEXT) <= 16777216)
        CHECK (NOT (
            jsonb_path_exists(audience_snapshot, '$[*].presence_payload')
            OR jsonb_path_exists(audience_snapshot, '$[*].stanza')
            OR jsonb_path_exists(audience_snapshot, '$[*].body')
            OR jsonb_path_exists(audience_snapshot, '$[*].password')
            OR jsonb_path_exists(audience_snapshot, '$[*].secret')
            OR jsonb_path_exists(audience_snapshot, '$[*].private_key')
            OR jsonb_path_exists(audience_snapshot, '$[*].signing_key')
        )),
    details JSONB NOT NULL DEFAULT '{}'::jsonb
        CHECK (jsonb_typeof(details) = 'object')
        CHECK (octet_length(details::TEXT) <= 16777216),
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    UNIQUE (room_id, event_sequence),
    UNIQUE (room_id, event_id),
    CHECK (event_id = operation_id),
    CHECK (
        (target_occupant_incarnation IS NULL
            AND target_occupancy_epoch IS NULL
            AND target_full_jid IS NULL
            AND target_nick IS NULL
            AND target_connection_uuid IS NULL
            AND target_connection_epoch IS NULL
            AND target_snapshot IS NULL)
        OR
        (target_occupant_incarnation IS NOT NULL
            AND target_occupancy_epoch IS NOT NULL
            AND target_full_jid IS NOT NULL
            AND target_nick IS NOT NULL
            AND target_connection_uuid IS NOT NULL
            AND target_connection_epoch IS NOT NULL
            AND jsonb_typeof(target_snapshot) = 'object')
    )
);

CREATE INDEX cluster_muc_operations_room_time_idx
    ON cluster_muc_operations (room_id, event_sequence DESC);
CREATE INDEX cluster_muc_operations_actor_idx
    ON cluster_muc_operations (actor_bare_jid, created_at DESC)
    WHERE actor_bare_jid IS NOT NULL;
CREATE INDEX cluster_muc_operations_retention_idx
    ON cluster_muc_operations (created_at, operation_id);

CREATE OR REPLACE FUNCTION reject_cluster_muc_operation_mutation()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    IF TG_OP = 'DELETE'
       AND current_setting('northstar.cluster_muc_retention_cleanup', TRUE) = 'bounded-v1' THEN
        IF EXISTS (
            SELECT 1 FROM legal_holds hold
             WHERE hold.released_at IS NULL AND (
                EXISTS (
                    SELECT 1 FROM legal_hold_scopes scope_link
                     WHERE scope_link.hold_id=hold.id
                       AND scope_link.scope_type='muc_archive_room'
                       AND scope_link.subject_id=OLD.room_id
                ) OR EXISTS (
                    SELECT 1 FROM legal_hold_muc_archives exact_link
                     WHERE exact_link.hold_id=hold.id
                       AND exact_link.room_id=OLD.room_id
                )
             )
        ) THEN
            RAISE EXCEPTION 'cluster MUC operation is protected by an active legal hold'
                USING ERRCODE='55000';
        END IF;
        RETURN OLD;
    END IF;
    RAISE EXCEPTION 'cluster MUC operations are append-only';
END;
$$;

CREATE TRIGGER trg_cluster_muc_operations_immutable
BEFORE UPDATE OR DELETE ON cluster_muc_operations
FOR EACH ROW EXECUTE FUNCTION reject_cluster_muc_operation_mutation();

-- Bounded durable audience delivery.  Repeated delivery is allowed, but the
-- operation/event ID and immutable payload remain identical across retries.
CREATE TABLE cluster_muc_outbox_capacity (
    shard SMALLINT PRIMARY KEY CHECK (shard BETWEEN 0 AND 63),
    queued_rows BIGINT NOT NULL DEFAULT 0 CHECK (queued_rows BETWEEN 0 AND 2048)
);
INSERT INTO cluster_muc_outbox_capacity(shard)
SELECT generate_series(0, 63);

CREATE TABLE cluster_muc_room_outbox_capacity (
    room_id UUID PRIMARY KEY,
    queued_rows BIGINT NOT NULL CHECK (queued_rows BETWEEN 0 AND 10000)
);

CREATE TABLE cluster_muc_event_outbox (
    delivery_id UUID PRIMARY KEY,
    operation_id UUID NOT NULL REFERENCES cluster_muc_operations(operation_id) ON DELETE RESTRICT,
    room_id UUID NOT NULL,
    room_epoch UUID NOT NULL,
    event_sequence BIGINT NOT NULL CHECK (event_sequence >= 1),
    event_id UUID NOT NULL,
    audience_kind VARCHAR(16) NOT NULL CHECK (audience_kind IN ('occupant', 'node_pull')),
    target_node_id VARCHAR(128) NOT NULL
        CHECK (target_node_id ~ '^[A-Za-z0-9._-]{1,128}$'),
    recipient_full_jid VARCHAR(3071),
    recipient_nick VARCHAR(128),
    recipient_occupant_incarnation UUID,
    recipient_occupancy_epoch BIGINT,
    recipient_connection_uuid UUID,
    recipient_connection_epoch BIGINT,
    payload TEXT NOT NULL CHECK (octet_length(payload) BETWEEN 1 AND 1048576),
    payload_digest BYTEA NOT NULL CHECK (octet_length(payload_digest) = 32),
    capacity_shard SMALLINT NOT NULL CHECK (capacity_shard BETWEEN 0 AND 63),
    attempt_count INTEGER NOT NULL DEFAULT 0 CHECK (attempt_count BETWEEN 0 AND 32),
    next_attempt_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    claim_token UUID,
    lease_until TIMESTAMPTZ,
    last_error TEXT CHECK (last_error IS NULL OR octet_length(last_error) <= 4096),
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    expires_at TIMESTAMPTZ NOT NULL DEFAULT (clock_timestamp() + INTERVAL '7 days'),
    UNIQUE (operation_id, target_node_id, audience_kind,
            recipient_occupant_incarnation),
    FOREIGN KEY (room_id, event_id)
        REFERENCES cluster_muc_operations (room_id, event_id) ON DELETE RESTRICT,
    CHECK ((claim_token IS NULL) = (lease_until IS NULL)),
    CHECK (expires_at > created_at),
    CHECK (
        (audience_kind = 'node_pull'
            AND recipient_full_jid IS NULL
            AND recipient_nick IS NULL
            AND recipient_occupant_incarnation IS NULL
            AND recipient_occupancy_epoch IS NULL
            AND recipient_connection_uuid IS NULL
            AND recipient_connection_epoch IS NULL)
        OR
        (audience_kind = 'occupant'
            AND recipient_full_jid IS NOT NULL
            AND recipient_nick IS NOT NULL
            AND recipient_occupant_incarnation IS NOT NULL
            AND recipient_occupancy_epoch IS NOT NULL
            AND recipient_connection_uuid IS NOT NULL
            AND recipient_connection_epoch IS NOT NULL)
    )
);

CREATE UNIQUE INDEX cluster_muc_event_outbox_node_pull_unique
    ON cluster_muc_event_outbox (operation_id, target_node_id)
    WHERE audience_kind = 'node_pull';
CREATE UNIQUE INDEX cluster_muc_event_outbox_occupant_unique
    ON cluster_muc_event_outbox
        (operation_id, target_node_id, recipient_occupant_incarnation)
    WHERE audience_kind = 'occupant';

CREATE INDEX cluster_muc_event_outbox_due_idx
    ON cluster_muc_event_outbox
        (target_node_id, next_attempt_at, room_id, event_sequence, delivery_id);
CREATE INDEX cluster_muc_event_outbox_lease_idx
    ON cluster_muc_event_outbox (lease_until)
    WHERE claim_token IS NOT NULL;
CREATE INDEX cluster_muc_event_outbox_expiry_idx
    ON cluster_muc_event_outbox (expires_at);

CREATE TABLE cluster_muc_event_dead_letters (
    delivery_id UUID PRIMARY KEY,
    operation_id UUID NOT NULL,
    room_id UUID NOT NULL,
    room_epoch UUID NOT NULL,
    event_sequence BIGINT NOT NULL,
    event_id UUID NOT NULL,
    target_node_id VARCHAR(128) NOT NULL,
    recipient_occupant_incarnation UUID,
    payload_digest BYTEA NOT NULL CHECK (octet_length(payload_digest) = 32),
    capacity_shard SMALLINT NOT NULL CHECK (capacity_shard BETWEEN 0 AND 63),
    attempt_count INTEGER NOT NULL,
    terminal_reason TEXT NOT NULL CHECK (octet_length(terminal_reason) <= 4096),
    created_at TIMESTAMPTZ NOT NULL,
    dead_lettered_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    purge_after TIMESTAMPTZ NOT NULL DEFAULT (clock_timestamp() + INTERVAL '30 days')
);

CREATE INDEX cluster_muc_event_dead_letters_purge_idx
    ON cluster_muc_event_dead_letters (purge_after);

CREATE TABLE cluster_muc_dead_letter_capacity (
    shard SMALLINT PRIMARY KEY CHECK (shard BETWEEN 0 AND 63),
    retained_rows BIGINT NOT NULL DEFAULT 0 CHECK (retained_rows BETWEEN 0 AND 2048)
);
INSERT INTO cluster_muc_dead_letter_capacity(shard)
SELECT generate_series(0, 63);

CREATE OR REPLACE FUNCTION account_cluster_muc_outbox_capacity()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    IF TG_OP = 'INSERT' THEN
        UPDATE cluster_muc_outbox_capacity
           SET queued_rows = queued_rows + 1
         WHERE shard = NEW.capacity_shard AND queued_rows < 2048;
        IF NOT FOUND THEN
            RAISE EXCEPTION 'cluster_muc_outbox_capacity';
        END IF;
        INSERT INTO cluster_muc_room_outbox_capacity(room_id, queued_rows)
        VALUES (NEW.room_id, 1)
        ON CONFLICT (room_id) DO UPDATE
            SET queued_rows = cluster_muc_room_outbox_capacity.queued_rows + 1
          WHERE cluster_muc_room_outbox_capacity.queued_rows < 10000;
        IF NOT FOUND THEN
            RAISE EXCEPTION 'cluster_muc_room_outbox_capacity';
        END IF;
        RETURN NEW;
    END IF;

    UPDATE cluster_muc_outbox_capacity
       SET queued_rows = queued_rows - 1
     WHERE shard = OLD.capacity_shard AND queued_rows > 0;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'cluster_muc_outbox_capacity_underflow';
    END IF;
    UPDATE cluster_muc_room_outbox_capacity
       SET queued_rows = queued_rows - 1
     WHERE room_id = OLD.room_id AND queued_rows > 0;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'cluster_muc_room_outbox_capacity_underflow';
    END IF;
    DELETE FROM cluster_muc_room_outbox_capacity
     WHERE room_id = OLD.room_id AND queued_rows = 0;
    RETURN OLD;
END;
$$;

CREATE TRIGGER trg_cluster_muc_outbox_capacity_insert
BEFORE INSERT ON cluster_muc_event_outbox
FOR EACH ROW EXECUTE FUNCTION account_cluster_muc_outbox_capacity();
CREATE TRIGGER trg_cluster_muc_outbox_capacity_delete
AFTER DELETE ON cluster_muc_event_outbox
FOR EACH ROW EXECUTE FUNCTION account_cluster_muc_outbox_capacity();

CREATE OR REPLACE FUNCTION fence_cluster_muc_outbox_identity()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    IF ROW(NEW.delivery_id, NEW.operation_id, NEW.room_id, NEW.room_epoch,
           NEW.event_sequence, NEW.event_id, NEW.audience_kind,
           NEW.target_node_id, NEW.recipient_full_jid, NEW.recipient_nick,
           NEW.recipient_occupant_incarnation, NEW.recipient_occupancy_epoch,
           NEW.recipient_connection_uuid, NEW.recipient_connection_epoch,
           NEW.payload, NEW.payload_digest, NEW.capacity_shard,
           NEW.created_at, NEW.expires_at)
       IS DISTINCT FROM
       ROW(OLD.delivery_id, OLD.operation_id, OLD.room_id, OLD.room_epoch,
           OLD.event_sequence, OLD.event_id, OLD.audience_kind,
           OLD.target_node_id, OLD.recipient_full_jid, OLD.recipient_nick,
           OLD.recipient_occupant_incarnation, OLD.recipient_occupancy_epoch,
           OLD.recipient_connection_uuid, OLD.recipient_connection_epoch,
           OLD.payload, OLD.payload_digest, OLD.capacity_shard,
           OLD.created_at, OLD.expires_at) THEN
        RAISE EXCEPTION 'cluster MUC outbox delivery identity is immutable';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER trg_cluster_muc_outbox_identity_fence
BEFORE UPDATE ON cluster_muc_event_outbox
FOR EACH ROW EXECUTE FUNCTION fence_cluster_muc_outbox_identity();

CREATE OR REPLACE FUNCTION account_cluster_muc_dead_letter_capacity()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    IF TG_OP = 'INSERT' THEN
        UPDATE cluster_muc_dead_letter_capacity
           SET retained_rows = retained_rows + 1
         WHERE shard = NEW.capacity_shard AND retained_rows < 2048;
        IF NOT FOUND THEN
            RAISE EXCEPTION 'cluster_muc_dead_letter_capacity';
        END IF;
        RETURN NEW;
    END IF;
    UPDATE cluster_muc_dead_letter_capacity
       SET retained_rows = retained_rows - 1
     WHERE shard = OLD.capacity_shard AND retained_rows > 0;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'cluster_muc_dead_letter_capacity_underflow';
    END IF;
    RETURN OLD;
END;
$$;

CREATE TRIGGER trg_cluster_muc_dead_letter_capacity_insert
BEFORE INSERT ON cluster_muc_event_dead_letters
FOR EACH ROW EXECUTE FUNCTION account_cluster_muc_dead_letter_capacity();
CREATE TRIGGER trg_cluster_muc_dead_letter_capacity_delete
AFTER DELETE ON cluster_muc_event_dead_letters
FOR EACH ROW EXECUTE FUNCTION account_cluster_muc_dead_letter_capacity();

COMMENT ON TABLE cluster_muc_operations IS
    'Mutation-immutable MUC operation journal and stable XEP-0359 event identity, retained through the bounded hold-aware online recovery horizon';
COMMENT ON TABLE cluster_muc_event_outbox IS
    'Bounded at-least-once MUC audience delivery; duplicate retries retain one stable event ID; claim scans lock outbox rows before capacity triggers lock shard then room counters';
COMMENT ON TABLE cluster_muc_event_dead_letters IS
    'Capacity-bounded, 30-day terminal MUC deliveries; a full dead-letter shard fails closed and leaves the source outbox row retryable until cleanup frees capacity';

-- The mutation journal and room-incarnation tombstones have a finite online
-- recovery horizon.  This database-clock cleanup is the only operation-delete
-- path accepted by the guard above.  It will not remove an operation while an
-- outbox/dead-letter projection exists, and it will not purge a room protected
-- by an active legal hold.  Old signed commands remain fenced after purge by
-- the protocol time window, the authoritative node-instance lease, and the
-- replacement room's new UUID/room_epoch.
CREATE OR REPLACE FUNCTION northstar_purge_cluster_muc_history(
    retention_days INTEGER,
    batch_size INTEGER
) RETURNS TABLE(operations_removed BIGINT, rooms_removed BIGINT)
LANGUAGE plpgsql
AS $$
DECLARE
    operation_count BIGINT := 0;
    room_operation_count BIGINT := 0;
    room_count BIGINT := 0;
    doomed_rooms UUID[];
BEGIN
    IF retention_days < 30 OR retention_days > 36500 THEN
        RAISE EXCEPTION 'cluster MUC history retention must be between 30 and 36500 days';
    END IF;
    PERFORM set_config('northstar.cluster_muc_retention_cleanup','bounded-v1',TRUE);

    WITH expired AS MATERIALIZED (
        SELECT operation.operation_id
          FROM cluster_muc_operations operation
         WHERE operation.created_at < clock_timestamp()
                 -(retention_days::BIGINT * INTERVAL '1 day')
           AND NOT EXISTS (
                SELECT 1 FROM cluster_muc_event_outbox delivery
                 WHERE delivery.operation_id=operation.operation_id
           )
           AND NOT EXISTS (
                SELECT 1 FROM cluster_muc_event_dead_letters dead
                 WHERE dead.operation_id=operation.operation_id
           )
           AND NOT EXISTS (
                SELECT 1 FROM legal_holds hold
                 WHERE hold.released_at IS NULL AND (
                    EXISTS (
                        SELECT 1 FROM legal_hold_scopes scope_link
                         WHERE scope_link.hold_id=hold.id
                           AND scope_link.scope_type='muc_archive_room'
                           AND scope_link.subject_id=operation.room_id
                    ) OR EXISTS (
                        SELECT 1 FROM legal_hold_muc_archives exact_link
                         WHERE exact_link.hold_id=hold.id
                           AND exact_link.room_id=operation.room_id
                    )
                 )
           )
         ORDER BY operation.created_at,operation.operation_id
         LIMIT LEAST(GREATEST(batch_size,1),10000)
         FOR UPDATE SKIP LOCKED
    ), removed AS (
        DELETE FROM cluster_muc_operations operation USING expired
         WHERE operation.operation_id=expired.operation_id
        RETURNING operation.operation_id
    ) SELECT COUNT(*) INTO operation_count FROM removed;

    WITH terminal AS MATERIALIZED (
        SELECT occupancy.room_id,occupancy.occupant_incarnation
          FROM cluster_muc_occupancies occupancy
         WHERE occupancy.state IN ('left','revoked','expired')
           AND occupancy.ended_at < clock_timestamp()
                 -(retention_days::BIGINT * INTERVAL '1 day')
           AND NOT EXISTS (
                SELECT 1 FROM cluster_muc_event_outbox delivery
                 WHERE delivery.room_id=occupancy.room_id
                   AND delivery.recipient_occupant_incarnation=occupancy.occupant_incarnation)
           AND NOT EXISTS (
                SELECT 1 FROM cluster_muc_event_dead_letters dead
                 WHERE dead.room_id=occupancy.room_id
                   AND dead.recipient_occupant_incarnation=occupancy.occupant_incarnation)
           AND NOT EXISTS (
                SELECT 1 FROM legal_holds hold
                 WHERE hold.released_at IS NULL AND (
                    EXISTS (SELECT 1 FROM legal_hold_scopes scope_link
                             WHERE scope_link.hold_id=hold.id
                               AND scope_link.scope_type='muc_archive_room'
                               AND scope_link.subject_id=occupancy.room_id)
                    OR EXISTS (SELECT 1 FROM legal_hold_muc_archives exact_link
                               WHERE exact_link.hold_id=hold.id
                                 AND exact_link.room_id=occupancy.room_id)))
         ORDER BY occupancy.ended_at,occupancy.room_id,occupancy.occupant_incarnation
         LIMIT LEAST(GREATEST(batch_size,1),10000)
         FOR UPDATE SKIP LOCKED
    )
    DELETE FROM cluster_muc_occupancies occupancy USING terminal
     WHERE occupancy.room_id=terminal.room_id
       AND occupancy.occupant_incarnation=terminal.occupant_incarnation;

    SELECT COALESCE(array_agg(candidate.id),'{}'::UUID[]) INTO doomed_rooms
      FROM (
        SELECT room.id
          FROM muc_rooms room
         WHERE room.destroyed_at IS NOT NULL
           AND room.destroyed_at < clock_timestamp()
                 -(retention_days::BIGINT * INTERVAL '1 day')
           AND NOT EXISTS (
                SELECT 1 FROM cluster_muc_event_outbox delivery
                 WHERE delivery.room_id=room.id
           )
           AND NOT EXISTS (
                SELECT 1 FROM cluster_muc_event_dead_letters dead
                 WHERE dead.room_id=room.id
           )
           AND NOT EXISTS (
                SELECT 1 FROM legal_holds hold
                 WHERE hold.released_at IS NULL AND (
                    EXISTS (
                        SELECT 1 FROM legal_hold_scopes scope_link
                         WHERE scope_link.hold_id=hold.id
                           AND scope_link.scope_type='muc_archive_room'
                           AND scope_link.subject_id=room.id
                    ) OR EXISTS (
                        SELECT 1 FROM legal_hold_muc_archives exact_link
                         WHERE exact_link.hold_id=hold.id
                           AND exact_link.room_id=room.id
                    )
                 )
           )
         ORDER BY room.destroyed_at,room.id
         LIMIT LEAST(GREATEST(batch_size,1),1000)
         FOR UPDATE SKIP LOCKED
      ) candidate;

    DELETE FROM cluster_muc_occupancies
     WHERE room_id=ANY(doomed_rooms)
       AND state IN ('left','revoked','expired');
    IF EXISTS (
        SELECT 1 FROM cluster_muc_occupancies
         WHERE room_id=ANY(doomed_rooms)
    ) THEN
        RAISE EXCEPTION 'cluster MUC tombstone cleanup found a non-terminal occupancy';
    END IF;
    DELETE FROM cluster_muc_operations WHERE room_id=ANY(doomed_rooms);
    GET DIAGNOSTICS room_operation_count = ROW_COUNT;
    operation_count := operation_count + room_operation_count;
    DELETE FROM muc_rooms
     WHERE id=ANY(doomed_rooms) AND destroyed_at IS NOT NULL;
    GET DIAGNOSTICS room_count = ROW_COUNT;

    operations_removed := operation_count;
    rooms_removed := room_count;
    RETURN NEXT;
END;
$$;
