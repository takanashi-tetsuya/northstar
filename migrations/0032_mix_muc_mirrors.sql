-- XEP-0408 MIX/MUC co-existence (partial-mirror deployment model).
--
-- The XEP does not define a stanza-conversion protocol.  This table therefore
-- records only an operator-enabled, one-to-one association between a local MIX
-- channel and a local MUC room.  Both foreign keys cascade so discovery can
-- never advertise a mirror whose counterpart has already been deleted.
ALTER TABLE mix_pam_memberships
    DROP CONSTRAINT mix_pam_memberships_client_request_id_check,
    ALTER COLUMN client_request_id TYPE VARCHAR(1024),
    ADD CONSTRAINT mix_pam_memberships_client_request_id_check
        CHECK (
            client_request_id IS NULL
            OR octet_length(client_request_id) BETWEEN 1 AND 1024
        );

-- Early development builds hashed Allowed/Banned item IDs even though
-- XEP-0406 defines the canonical bare JID/domain itself as the PubSub item ID.
-- Current values live in mix_allowed/mix_banned, so discard only the optional
-- event-history copies before widening future item IDs to the RFC 7622 bound.
DELETE FROM mix_events
WHERE node IN ('urn:xmpp:mix:nodes:allowed', 'urn:xmpp:mix:nodes:banned');

ALTER TABLE mix_events
    ALTER COLUMN item_id TYPE VARCHAR(3071);

-- XEP-0406 names Information/Configuration items with the date-time of their
-- update. Preserve payloads while normalizing fixed early-development IDs.
UPDATE mix_events
SET item_id = to_char(created_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"')
WHERE node IN ('urn:xmpp:mix:nodes:info', 'urn:xmpp:mix:nodes:config')
  AND item_id IN ('info', 'config');

CREATE TABLE mix_muc_mirrors (
    mix_channel_id UUID PRIMARY KEY
        REFERENCES mix_channels(id) ON DELETE CASCADE,
    muc_room_id UUID NOT NULL UNIQUE
        REFERENCES muc_rooms(id) ON DELETE CASCADE,
    created_by VARCHAR(3071) NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CHECK (
        octet_length(created_by) BETWEEN 3 AND 3071
        AND position('@' IN created_by) > 1
        AND position('/' IN created_by) = 0
    )
);

CREATE INDEX mix_muc_mirrors_created_at_idx
    ON mix_muc_mirrors(created_at, mix_channel_id);
