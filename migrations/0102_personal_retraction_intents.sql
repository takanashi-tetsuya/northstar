-- Durable XEP-0424/XEP-0444 replay identity independent of optional MAM.
--
-- A retraction can be accepted while personal archiving is disabled. The
-- tombstone alone records only the action id and therefore cannot distinguish
-- an exact replay from reuse of that id with a changed fallback or target.
-- Do not persist the canonical XML itself: a fallback body can be plaintext
-- even when MAM is disabled by policy. Independent domain-separated SHA-256
-- and SHA-512 commitments plus the exact canonical length provide durable
-- replay evidence without creating a second plaintext history store.

CREATE TABLE personal_retraction_intents (
    id UUID PRIMARY KEY,
    sender_bare_jid VARCHAR(3071) NOT NULL,
    action_id VARCHAR(1024) NOT NULL,
    action_digest BYTEA NOT NULL,
    target_id VARCHAR(1024) NOT NULL,
    semantic_sha256 BYTEA NOT NULL,
    semantic_sha512 BYTEA NOT NULL,
    semantic_length BIGINT NOT NULL,
    owner_projection_sha256 BYTEA NOT NULL,
    owner_projection_sha512 BYTEA NOT NULL,
    owner_projection_length BIGINT NOT NULL,
    outbound_requested BOOLEAN NOT NULL,
    s2s_outbox_id UUID,
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    expires_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp() + INTERVAL '30 days',
    CONSTRAINT personal_retraction_intent_sender_check
        CHECK (octet_length(sender_bare_jid) BETWEEN 1 AND 3071),
    CONSTRAINT personal_retraction_intent_action_check
        CHECK (octet_length(action_id) BETWEEN 1 AND 1024),
    CONSTRAINT personal_retraction_intent_target_check
        CHECK (octet_length(target_id) BETWEEN 1 AND 1024),
    CONSTRAINT personal_retraction_intent_digest_check
        CHECK (
            octet_length(action_digest) = 32
            AND octet_length(semantic_sha256) = 32
            AND octet_length(semantic_sha512) = 64
            AND octet_length(owner_projection_sha256) = 32
            AND octet_length(owner_projection_sha512) = 64
        ),
    CONSTRAINT personal_retraction_intent_length_check
        CHECK (
            semantic_length BETWEEN 1 AND 2097152
            AND owner_projection_length BETWEEN 1 AND 16384
        ),
    CONSTRAINT personal_retraction_intent_outbox_check
        CHECK (outbound_requested OR s2s_outbox_id IS NULL),
    CONSTRAINT personal_retraction_intent_outbox_fk
        FOREIGN KEY (s2s_outbox_id) REFERENCES s2s_outbox(id)
        ON DELETE SET NULL DEFERRABLE INITIALLY DEFERRED
);

CREATE UNIQUE INDEX personal_retraction_intent_identity_key
    ON personal_retraction_intents(sender_bare_jid, action_digest);

-- Archive policy is deliberately not part of the idempotency identity: it can
-- change between an accepted action and its retry. Instead, retain the exact
-- projection plan committed by the first admission. A retry verifies this
-- immutable snapshot and ignores a newly computed 0/1/2-write plan. The
-- archive foreign key may later become NULL through legitimate MAM retention;
-- the projection row still records that side of the original plan, while any
-- surviving non-NULL archive remains subject to strict content verification.
CREATE TABLE personal_retraction_action_projections (
    intent_id UUID NOT NULL REFERENCES personal_retraction_intents(id)
        ON DELETE CASCADE,
    ordinal SMALLINT NOT NULL CHECK (ordinal BETWEEN 0 AND 1),
    owner_id UUID NOT NULL,
    peer_bare_jid VARCHAR(3071) NOT NULL
        CHECK (octet_length(peer_bare_jid) BETWEEN 1 AND 3071),
    archive_id UUID,
    PRIMARY KEY (intent_id, ordinal),
    UNIQUE (intent_id, owner_id),
    CONSTRAINT personal_retraction_projection_archive_fk
        FOREIGN KEY (archive_id) REFERENCES message_archive(id)
        ON DELETE SET NULL DEFERRABLE INITIALLY DEFERRED
);

CREATE INDEX personal_retraction_projection_archive_idx
    ON personal_retraction_action_projections(archive_id)
    WHERE archive_id IS NOT NULL;

-- Intent records are a bounded replay window rather than permanent message
-- history. The retention worker deletes them after 30 days, but never while a
-- durable federation projection still owns the operation.
CREATE INDEX personal_retraction_intent_expiry_idx
    ON personal_retraction_intents(expires_at, id)
    WHERE s2s_outbox_id IS NULL;
