-- Preserve the exact resource selected by an explicit full-JID `normal`
-- message across a crash or a transport handoff. Bare-JID traffic and chat
-- full-JID fallback remain account scoped and therefore keep this column NULL.
ALTER TABLE offline_messages
    ADD COLUMN target_resource VARCHAR(1023),
    ADD CONSTRAINT offline_message_target_resource_shape CHECK (
        target_resource IS NULL
        OR octet_length(target_resource) BETWEEN 1 AND 1023
    );

-- The ordinary replay index remains optimal for account-scoped rows. This
-- partial index gives resource-affine workers a bounded, recipient-first path
-- without inflating every legacy/bare delivery entry.
CREATE INDEX offline_messages_target_resource_replay_idx
    ON offline_messages(recipient_id, target_resource, created_at, id)
    WHERE target_resource IS NOT NULL;

COMMENT ON COLUMN offline_messages.target_resource IS
    'Canonical RFC 7622 resourcepart affinity for explicit full-JID normal messages; NULL means account-scoped replay';

-- Resource affinity is part of the accepted delivery projection. It must not
-- be retargeted after admission. The recipient UUID already binds account
-- ownership; persisting only the canonical resourcepart avoids a redundant
-- domain/localpart authority which could drift from that UUID.
CREATE FUNCTION fence_offline_message_target_resource() RETURNS TRIGGER AS $$
BEGIN
    IF NEW.recipient_id IS DISTINCT FROM OLD.recipient_id THEN
        RAISE EXCEPTION 'offline message recipient ownership is immutable';
    END IF;
    IF NEW.target_resource IS DISTINCT FROM OLD.target_resource THEN
        RAISE EXCEPTION 'offline message target resource affinity is immutable';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql
SET search_path = pg_catalog, pg_temp;

CREATE TRIGGER offline_message_target_resource_fence
    BEFORE UPDATE OF recipient_id, target_resource
    ON offline_messages
    FOR EACH ROW EXECUTE FUNCTION fence_offline_message_target_resource();
