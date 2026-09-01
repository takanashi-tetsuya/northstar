-- Evolve offline replay ownership from an account-level exclusivity to a
-- resource-scoped fence (recipient_id, resource). Distinct bound resources
-- (such as Phone and Tablet) can replay offline messages in parallel without
-- starving each other's resource-affine durable messages.

DELETE FROM offline_replay_leases;

ALTER TABLE offline_replay_leases
    DROP CONSTRAINT IF EXISTS offline_replay_leases_pkey;

ALTER TABLE offline_replay_leases
    ADD COLUMN resource VARCHAR(1023) NOT NULL,
    ADD CONSTRAINT offline_replay_lease_resource_shape CHECK (
        octet_length(resource) BETWEEN 1 AND 1023
    ),
    ADD PRIMARY KEY (recipient_id, resource);

DROP INDEX IF EXISTS offline_replay_leases_expiry;

CREATE INDEX offline_replay_leases_expiry
    ON offline_replay_leases (expires_at, recipient_id, resource);

COMMENT ON COLUMN offline_replay_leases.resource IS
    'Canonical RFC 7622 resourcepart owning this offline replay lease fence';

-- The resource identity is part of the lease fence. An update cannot retarget
-- recipient_id or resource.
CREATE FUNCTION fence_offline_replay_lease_identity() RETURNS TRIGGER AS $$
BEGIN
    IF NEW.recipient_id IS DISTINCT FROM OLD.recipient_id THEN
        RAISE EXCEPTION 'offline replay lease recipient ownership is immutable';
    END IF;
    IF NEW.resource IS DISTINCT FROM OLD.resource THEN
        RAISE EXCEPTION 'offline replay lease resource identity is immutable';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql
SET search_path = pg_catalog, pg_temp;

CREATE TRIGGER offline_replay_lease_identity_fence
    BEFORE UPDATE OF recipient_id, resource
    ON offline_replay_leases
    FOR EACH ROW EXECUTE FUNCTION fence_offline_replay_lease_identity();
