-- Persistent affiliations for federated MUC participants. Remote JIDs are
-- deliberately kept separate from local user foreign keys so an authenticated
-- federation domain can never manufacture a local account identity.
CREATE TABLE muc_external_affiliations (
    room_id UUID NOT NULL REFERENCES muc_rooms(id) ON DELETE CASCADE,
    jid VARCHAR(3071) NOT NULL,
    affiliation VARCHAR(16) NOT NULL
        CHECK (affiliation IN ('owner', 'admin', 'member', 'outcast')),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (room_id, jid),
    CHECK (jid = lower(jid) AND position('@' IN jid) > 1 AND position('/' IN jid) = 0)
);

CREATE INDEX muc_external_affiliations_lookup_idx
    ON muc_external_affiliations(jid, room_id);
