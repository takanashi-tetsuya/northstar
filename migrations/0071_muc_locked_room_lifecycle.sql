-- XEP-0045 section 10.1: a newly-created room is locked until its initial
-- owner accepts the instant defaults or completes the owner configuration
-- form.  Existing rooms predate this lifecycle and are therefore backfilled
-- as active, preserving their availability during upgrade.
ALTER TABLE muc_rooms
    ADD COLUMN configuration_state VARCHAR(16) NOT NULL DEFAULT 'active',
    ADD COLUMN configuration_owner_jid VARCHAR(3071),
    ADD COLUMN configuration_expires_at TIMESTAMPTZ,
    ADD CONSTRAINT muc_room_configuration_state_check CHECK (
        (configuration_state = 'active'
            AND configuration_owner_jid IS NULL
            AND configuration_expires_at IS NULL)
        OR
        (configuration_state = 'locked'
            AND configuration_owner_jid IS NOT NULL
            AND configuration_expires_at IS NOT NULL)
    );

CREATE INDEX muc_rooms_locked_expiry_idx
    ON muc_rooms(configuration_expires_at)
    WHERE configuration_state = 'locked';
