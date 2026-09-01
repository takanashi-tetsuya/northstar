-- Durable content identity must never become a second plaintext archive.
--
-- Historical personal-message rows already carry SHA-256 payload evidence.
-- Preserve only that irreversible legacy digest, then drop the exact stanza.
-- New application writes use a purpose-separated HMAC derived from the
-- mounted anti-abuse key generation; the raw secret never enters PostgreSQL.

ALTER TABLE personal_message_admissions
    ADD COLUMN payload_key_id VARCHAR(16),
    ADD COLUMN payload_mac BYTEA;

ALTER TABLE personal_message_admissions
    DROP CONSTRAINT personal_message_admission_payload_check,
    DROP CONSTRAINT personal_message_admission_digest_check,
    ALTER COLUMN payload_digest DROP NOT NULL,
    DROP COLUMN payload_value,
    ADD CONSTRAINT personal_message_admission_identity_digest_check
        CHECK (octet_length(identity_digest) = 32),
    ADD CONSTRAINT personal_message_admission_payload_evidence_check
        CHECK (
            (
                payload_key_id IS NULL
                AND payload_mac IS NULL
                AND payload_digest IS NOT NULL
                AND octet_length(payload_digest) = 32
            )
            OR
            (
                payload_key_id IS NOT NULL
                AND payload_key_id ~ '^[A-Za-z0-9_-]{16}$'
                AND payload_mac IS NOT NULL
                AND octet_length(payload_mac) = 32
                AND payload_digest IS NULL
            )
        );

COMMENT ON COLUMN personal_message_admissions.payload_digest IS
    'Legacy unkeyed SHA-256 evidence retained only for rows predating migration 0104';
COMMENT ON COLUMN personal_message_admissions.payload_key_id IS
    'Non-secret anti-abuse key generation ID for the purpose-separated content MAC';

CREATE INDEX personal_message_admission_payload_key_idx
    ON personal_message_admissions(payload_key_id)
    WHERE payload_key_id IS NOT NULL;

-- Retraction intents were introduced without storing canonical XML, but an
-- unkeyed double digest still lets an attacker with a known candidate perform
-- offline confirmation. Existing rows remain verifiable during migration;
-- every exact replay upgrades its evidence to the keyed form atomically.

ALTER TABLE personal_retraction_intents
    ADD COLUMN semantic_key_id VARCHAR(16),
    ADD COLUMN semantic_mac BYTEA,
    DROP CONSTRAINT personal_retraction_intent_digest_check,
    DROP CONSTRAINT personal_retraction_intent_length_check,
    ALTER COLUMN semantic_sha256 DROP NOT NULL,
    ALTER COLUMN semantic_sha512 DROP NOT NULL,
    ALTER COLUMN semantic_length DROP NOT NULL,
    ADD CONSTRAINT personal_retraction_intent_fixed_digest_check
        CHECK (
            octet_length(action_digest) = 32
            AND octet_length(owner_projection_sha256) = 32
            AND octet_length(owner_projection_sha512) = 64
        ),
    ADD CONSTRAINT personal_retraction_intent_length_check
        CHECK (owner_projection_length BETWEEN 1 AND 16384),
    ADD CONSTRAINT personal_retraction_intent_semantic_evidence_check
        CHECK (
            (
                semantic_key_id IS NULL
                AND semantic_mac IS NULL
                AND semantic_sha256 IS NOT NULL
                AND semantic_sha512 IS NOT NULL
                AND semantic_length IS NOT NULL
                AND octet_length(semantic_sha256) = 32
                AND octet_length(semantic_sha512) = 64
                AND semantic_length BETWEEN 1 AND 2097152
            )
            OR
            (
                semantic_key_id IS NOT NULL
                AND semantic_key_id ~ '^[A-Za-z0-9_-]{16}$'
                AND semantic_mac IS NOT NULL
                AND octet_length(semantic_mac) = 32
                AND semantic_sha256 IS NULL
                AND semantic_sha512 IS NULL
                AND semantic_length IS NULL
            )
        );

COMMENT ON COLUMN personal_retraction_intents.semantic_sha256 IS
    'Legacy compatibility evidence; new and upgraded rows use semantic_key_id/semantic_mac';
COMMENT ON COLUMN personal_retraction_intents.semantic_key_id IS
    'Non-secret anti-abuse key generation ID for the purpose-separated retraction MAC';

CREATE INDEX personal_retraction_intent_semantic_key_idx
    ON personal_retraction_intents(semantic_key_id)
    WHERE semantic_key_id IS NOT NULL;
