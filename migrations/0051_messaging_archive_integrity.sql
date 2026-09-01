-- Stage 16: personal messaging/archive identity and offline recovery.

-- Bind 2 clients use MAM for permanently archived messages, but XEP-0334
-- no-permanent-store still permits temporary offline delivery.  This marker
-- distinguishes the recoverable duplicate from the only remaining copy.
ALTER TABLE offline_messages
    ADD COLUMN mam_backed BOOLEAN NOT NULL DEFAULT FALSE;

CREATE INDEX offline_messages_bind2_recovery_idx
    ON offline_messages (recipient_id, mam_backed, created_at, id);

-- A raw identity and its digest are stored together: the digest makes the
-- unique key bounded, while an exact raw comparison makes a cryptographic
-- collision fail closed rather than misclassifying a different stanza as a
-- replay.  Local origin-id and authenticated remote stanza-id admissions use
-- distinct kinds and authority scopes.
CREATE TABLE personal_message_admissions (
    id UUID PRIMARY KEY,
    identity_kind VARCHAR(32) NOT NULL,
    actor_scope_raw VARCHAR(3071) NOT NULL,
    actor_scope VARCHAR(3071) NOT NULL,
    target_scope VARCHAR(3071) NOT NULL,
    identity_value VARCHAR(1024) NOT NULL,
    identity_digest BYTEA NOT NULL,
    payload_value TEXT NOT NULL,
    payload_digest BYTEA NOT NULL,
    sender_archive_id UUID,
    recipient_archive_id UUID,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT personal_message_admission_kind_check
        CHECK (identity_kind IN ('local-origin', 'remote-stanza')),
    CONSTRAINT personal_message_admission_actor_check
        CHECK (
            octet_length(actor_scope_raw) BETWEEN 1 AND 3071
            AND octet_length(actor_scope) BETWEEN 1 AND 3071
        ),
    CONSTRAINT personal_message_admission_target_check
        CHECK (octet_length(target_scope) BETWEEN 1 AND 3071),
    CONSTRAINT personal_message_admission_identity_check
        CHECK (octet_length(identity_value) BETWEEN 1 AND 1024),
    CONSTRAINT personal_message_admission_payload_check
        CHECK (octet_length(payload_value) BETWEEN 1 AND 1048576),
    CONSTRAINT personal_message_admission_digest_check
        CHECK (octet_length(identity_digest) = 32 AND octet_length(payload_digest) = 32),
    CONSTRAINT personal_message_admission_archive_check
        CHECK (sender_archive_id IS NOT NULL OR recipient_archive_id IS NOT NULL)
);

CREATE UNIQUE INDEX personal_message_admission_identity_key
    ON personal_message_admissions
       (identity_kind, actor_scope, target_scope, identity_digest);
