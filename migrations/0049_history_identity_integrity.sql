-- Stable history identities and atomic MUC history mutations.
--
-- Legacy rows deliberately remain readable: identity metadata is nullable for
-- history written before this migration.  Every new admission primitive fills
-- the metadata and enforces the stricter invariants below.

ALTER TABLE muc_messages
    ADD COLUMN message_kind VARCHAR(16) NOT NULL DEFAULT 'discussion'
        CHECK (message_kind IN ('discussion', 'subject', 'retraction', 'moderation')),
    ADD COLUMN actor_scope VARCHAR(3071),
    ADD COLUMN origin_id VARCHAR(128),
    ADD COLUMN origin_digest BYTEA,
    ADD COLUMN retraction_action_id UUID,
    ADD CONSTRAINT muc_messages_actor_scope_bound_check
        CHECK (actor_scope IS NULL OR octet_length(actor_scope) BETWEEN 1 AND 3071),
    ADD CONSTRAINT muc_messages_origin_identity_check
        CHECK (
            (origin_id IS NULL AND origin_digest IS NULL)
            OR (
                origin_id IS NOT NULL
                AND octet_length(origin_id) BETWEEN 1 AND 128
                AND origin_digest IS NOT NULL
                AND octet_length(origin_digest) = 32
            )
        ),
    ADD CONSTRAINT muc_messages_action_kind_check
        CHECK (
            retraction_action_id IS NULL
            OR retracted_at IS NOT NULL
        );

-- The digest is only an index key.  Admission always compares the persisted
-- actor_scope and origin_id byte-for-byte before classifying a conflict as a
-- replay, so a SHA-256 collision cannot suppress another actor's message.
CREATE UNIQUE INDEX muc_messages_origin_admission_key
    ON muc_messages (room_id, origin_digest)
    WHERE message_kind = 'discussion' AND origin_id IS NOT NULL;

CREATE UNIQUE INDEX muc_messages_retraction_action_key
    ON muc_messages (room_id, retraction_action_id)
    WHERE retraction_action_id IS NOT NULL;

-- Admission identity is separate from archived content so XEP-0334 no-store
-- messages are still idempotent without retaining their payload.
CREATE TABLE muc_origin_admissions (
    room_id UUID NOT NULL REFERENCES muc_rooms(id) ON DELETE CASCADE,
    origin_digest BYTEA NOT NULL CHECK (octet_length(origin_digest) = 32),
    actor_scope VARCHAR(3071) NOT NULL
        CHECK (octet_length(actor_scope) BETWEEN 1 AND 3071),
    origin_id VARCHAR(128) NOT NULL
        CHECK (octet_length(origin_id) BETWEEN 1 AND 128),
    stanza_id UUID NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (room_id, origin_digest),
    UNIQUE (room_id, stanza_id)
);

CREATE INDEX muc_origin_admissions_retention_idx
    ON muc_origin_admissions (room_id, created_at, origin_digest);

ALTER TABLE muc_rooms
    ADD COLUMN subject_set_by VARCHAR(3071),
    ADD COLUMN subject_stanza_id UUID,
    ADD COLUMN subject_changed_at TIMESTAMPTZ,
    ADD CONSTRAINT muc_rooms_subject_actor_bound_check
        CHECK (subject_set_by IS NULL OR octet_length(subject_set_by) BETWEEN 1 AND 3071);

-- A message-node item ID is the channel authority's stable history identity.
-- Keep the existing UUID primary key as a storage surrogate for old/non-message
-- events, but expose one automatically derived UUID for every row.  A strict
-- canonical UUID item ID is used for messages; legacy malformed IDs safely fall
-- back to their immutable row ID until protocol admission rejects them.
ALTER TABLE mix_events
    ADD COLUMN authoritative_id UUID GENERATED ALWAYS AS (
        CASE
            WHEN node = 'urn:xmpp:mix:nodes:messages'
             AND item_id ~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
            THEN item_id::UUID
            ELSE id
        END
    ) STORED;

CREATE UNIQUE INDEX mix_events_authoritative_history_key
    ON mix_events (channel_id, node, authoritative_id);

-- Personal archives retain the source MIX authority and stanza identity.  The
-- partial unique key makes remote retries idempotent per account while keeping
-- unrelated ordinary messages unchanged.
ALTER TABLE message_archive
    ADD COLUMN source_by VARCHAR(3071),
    ADD COLUMN source_stanza_id UUID,
    ADD COLUMN source_payload_digest BYTEA,
    ADD CONSTRAINT message_archive_source_identity_check
        CHECK (
            (source_by IS NULL AND source_stanza_id IS NULL AND source_payload_digest IS NULL)
            OR (
                source_by IS NOT NULL
                AND octet_length(source_by) BETWEEN 1 AND 3071
                AND source_stanza_id IS NOT NULL
                AND source_payload_digest IS NOT NULL
                AND octet_length(source_payload_digest) = 32
            )
        );

CREATE UNIQUE INDEX message_archive_source_history_key
    ON message_archive (owner_id, source_by, source_stanza_id)
    WHERE source_stanza_id IS NOT NULL;
