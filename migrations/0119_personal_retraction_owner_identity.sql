-- Remove the last unkeyed/plaintext copy of personal-retraction owner
-- topology from the replay authority.
--
-- Existing rows remain readable in their legacy double-digest form. An exact
-- authorized replay upgrades one locked row to the current purpose-separated
-- HMAC generation. New rows use only keyed evidence. The redundant peer JID
-- in the action-projection table is unnecessary once the authenticated owner
-- commitment is authoritative; the live message_archive row remains the
-- payload-bearing projection for as long as policy retains it.
--
-- This is a coordinated-binary migration: binaries predating 0119 assume the
-- three legacy owner columns are NOT NULL and must be drained before a new
-- binary is allowed to create keyed-only rows.

ALTER TABLE personal_retraction_intents
    ADD COLUMN owner_projection_key_id VARCHAR(16),
    ADD COLUMN owner_projection_mac BYTEA,
    DROP CONSTRAINT personal_retraction_intent_fixed_digest_check,
    DROP CONSTRAINT personal_retraction_intent_length_check,
    ALTER COLUMN owner_projection_sha256 DROP NOT NULL,
    ALTER COLUMN owner_projection_sha512 DROP NOT NULL,
    ALTER COLUMN owner_projection_length DROP NOT NULL,
    ADD CONSTRAINT personal_retraction_intent_action_digest_check
        CHECK (octet_length(action_digest) = 32),
    ADD CONSTRAINT personal_retraction_intent_owner_evidence_check
        CHECK (
            (
                owner_projection_key_id IS NULL
                AND owner_projection_mac IS NULL
                AND owner_projection_sha256 IS NOT NULL
                AND octet_length(owner_projection_sha256) = 32
                AND owner_projection_sha512 IS NOT NULL
                AND octet_length(owner_projection_sha512) = 64
                AND owner_projection_length BETWEEN 1 AND 16384
            )
            OR
            (
                owner_projection_key_id IS NOT NULL
                AND owner_projection_key_id ~ '^[A-Za-z0-9_-]{16}$'
                AND owner_projection_mac IS NOT NULL
                AND octet_length(owner_projection_mac) = 32
                AND owner_projection_sha256 IS NULL
                AND owner_projection_sha512 IS NULL
                AND owner_projection_length IS NULL
            )
        );

COMMENT ON COLUMN personal_retraction_intents.owner_projection_sha256 IS
    'Legacy owner-topology evidence; keyed rows leave every legacy owner column NULL';
COMMENT ON COLUMN personal_retraction_intents.owner_projection_key_id IS
    'Non-secret anti-abuse key generation ID for the purpose-separated owner-topology MAC';
COMMENT ON COLUMN personal_retraction_intents.owner_projection_mac IS
    'Keyed commitment to the sorted authorized owner UUID and peer bare-JID topology';

CREATE INDEX personal_retraction_intent_owner_key_idx
    ON personal_retraction_intents(owner_projection_key_id)
    WHERE owner_projection_key_id IS NOT NULL;

-- A 1024-character XMPP stanza ID can exceed PostgreSQL's B-tree entry-size
-- limit when encoded as UTF-8. Use a fixed-size bucket for lookup acceleration
-- and retain full stanza_id plus peer_jid equality in every query, so the MD5
-- value is never an authorization or correctness decision.
CREATE INDEX message_archive_retraction_stanza_bucket_idx
    ON message_archive(
        owner_id,
        pg_catalog.md5(peer_jid),
        pg_catalog.md5(stanza_id),
        created_at DESC,
        id DESC
    )
    WHERE stanza_id IS NOT NULL;

ALTER TABLE personal_retraction_action_projections
    DROP COLUMN peer_bare_jid;

-- Keyed owner evidence is immutable. The only permitted transition is the
-- complete legacy shape to the complete keyed shape during an exact replay.
CREATE FUNCTION fence_personal_retraction_owner_identity() RETURNS TRIGGER AS $$
DECLARE
    old_is_legacy BOOLEAN;
    new_is_keyed BOOLEAN;
BEGIN
    IF NEW.owner_projection_key_id IS NOT DISTINCT FROM OLD.owner_projection_key_id
       AND NEW.owner_projection_mac IS NOT DISTINCT FROM OLD.owner_projection_mac
       AND NEW.owner_projection_sha256 IS NOT DISTINCT FROM OLD.owner_projection_sha256
       AND NEW.owner_projection_sha512 IS NOT DISTINCT FROM OLD.owner_projection_sha512
       AND NEW.owner_projection_length IS NOT DISTINCT FROM OLD.owner_projection_length THEN
        RETURN NEW;
    END IF;

    old_is_legacy := OLD.owner_projection_key_id IS NULL
        AND OLD.owner_projection_mac IS NULL
        AND OLD.owner_projection_sha256 IS NOT NULL
        AND OLD.owner_projection_sha512 IS NOT NULL
        AND OLD.owner_projection_length IS NOT NULL;
    new_is_keyed := NEW.owner_projection_key_id IS NOT NULL
        AND NEW.owner_projection_mac IS NOT NULL
        AND NEW.owner_projection_sha256 IS NULL
        AND NEW.owner_projection_sha512 IS NULL
        AND NEW.owner_projection_length IS NULL;

    IF old_is_legacy AND new_is_keyed THEN
        RETURN NEW;
    END IF;
    RAISE EXCEPTION 'personal retraction owner identity is immutable';
END;
$$ LANGUAGE plpgsql SET search_path=pg_catalog,pg_temp;

CREATE TRIGGER personal_retraction_owner_identity_fence
BEFORE UPDATE OF owner_projection_key_id,owner_projection_mac,
                 owner_projection_sha256,owner_projection_sha512,
                 owner_projection_length
ON personal_retraction_intents
FOR EACH ROW EXECUTE FUNCTION fence_personal_retraction_owner_identity();
