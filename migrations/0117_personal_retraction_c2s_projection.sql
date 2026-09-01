-- A personal retraction must not become observable before its authorization,
-- replay identity, history tombstones, optional action MAM projections, and
-- recoverable C2S delivery have committed together. The transient
-- offline_messages row is the delivery outbox for online and offline
-- recipients; its foreign key is deferred so the intent can be bound before
-- the outbox row is inserted in the same transaction.

ALTER TABLE personal_retraction_intents
    ADD COLUMN c2s_delivery_requested BOOLEAN NOT NULL DEFAULT FALSE,
    ADD COLUMN c2s_delivery_id UUID,
    ADD COLUMN c2s_projection_key_id VARCHAR(16),
    ADD COLUMN c2s_projection_mac BYTEA,
    ADD CONSTRAINT personal_retraction_intent_c2s_check
        CHECK (
            (
                NOT c2s_delivery_requested
                AND c2s_delivery_id IS NULL
                AND c2s_projection_key_id IS NULL
                AND c2s_projection_mac IS NULL
            )
            OR
            (
                c2s_delivery_requested
                AND c2s_projection_key_id IS NOT NULL
                AND c2s_projection_key_id ~ '^[A-Za-z0-9_-]{16}$'
                AND c2s_projection_mac IS NOT NULL
                AND octet_length(c2s_projection_mac) = 32
            )
        ),
    ADD CONSTRAINT personal_retraction_intent_c2s_fk
        FOREIGN KEY (c2s_delivery_id) REFERENCES offline_messages(id)
        ON DELETE SET NULL DEFERRABLE INITIALLY DEFERRED;

CREATE INDEX personal_retraction_intent_c2s_idx
    ON personal_retraction_intents(c2s_delivery_id)
    WHERE c2s_delivery_id IS NOT NULL;
CREATE INDEX personal_retraction_intent_c2s_key_idx
    ON personal_retraction_intents(c2s_projection_key_id)
    WHERE c2s_projection_key_id IS NOT NULL;

-- Intent retention begins only after every recoverable projection has
-- completed. ON DELETE SET NULL preserves the compact replay tombstone after
-- a transport acknowledges and removes the payload-bearing delivery row.
DROP INDEX personal_retraction_intent_expiry_idx;
CREATE INDEX personal_retraction_intent_expiry_idx
    ON personal_retraction_intents(expires_at, id)
    WHERE s2s_outbox_id IS NULL AND c2s_delivery_id IS NULL;

COMMENT ON COLUMN personal_retraction_intents.c2s_delivery_requested IS
    'Immutable operation-shape bit: the accepted action requested one durable local delivery';
COMMENT ON COLUMN personal_retraction_intents.c2s_delivery_id IS
    'Live transient C2S/offline outbox projection; cleared by the deferred FK after delivery';
COMMENT ON COLUMN personal_retraction_intents.c2s_projection_mac IS
    'Purpose-separated keyed commitment to recipient/actor/JIDs/content flags and delivery policy';

-- The live delivery FK may be cleared by acknowledgement, but the operation
-- shape and its keyed evidence are immutable replay authority.
CREATE FUNCTION fence_personal_retraction_c2s_identity() RETURNS TRIGGER AS $$
BEGIN
    IF NEW.c2s_delivery_requested IS DISTINCT FROM OLD.c2s_delivery_requested
       OR NEW.c2s_projection_key_id IS DISTINCT FROM OLD.c2s_projection_key_id
       OR NEW.c2s_projection_mac IS DISTINCT FROM OLD.c2s_projection_mac THEN
        RAISE EXCEPTION 'personal retraction C2S identity is immutable';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql SET search_path=pg_catalog,pg_temp;

CREATE TRIGGER personal_retraction_c2s_identity_fence
BEFORE UPDATE OF c2s_delivery_requested,c2s_projection_key_id,c2s_projection_mac
ON personal_retraction_intents
FOR EACH ROW EXECUTE FUNCTION fence_personal_retraction_c2s_identity();
