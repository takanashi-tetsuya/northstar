ALTER TABLE muc_rooms
    ADD COLUMN public BOOLEAN NOT NULL DEFAULT TRUE,
    ADD COLUMN moderated BOOLEAN NOT NULL DEFAULT FALSE,
    ADD COLUMN non_anonymous BOOLEAN NOT NULL DEFAULT TRUE,
    ADD COLUMN max_occupants INTEGER NOT NULL DEFAULT 100 CHECK (max_occupants BETWEEN 2 AND 1000),
    ADD COLUMN subject TEXT;

CREATE TABLE muc_affiliations (
    room_id UUID NOT NULL REFERENCES muc_rooms(id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    affiliation VARCHAR(16) NOT NULL CHECK (affiliation IN ('owner', 'admin', 'member', 'outcast')),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (room_id, user_id)
);

CREATE TABLE muc_messages (
    id UUID PRIMARY KEY,
    room_id UUID NOT NULL REFERENCES muc_rooms(id) ON DELETE CASCADE,
    sender_jid VARCHAR(3071) NOT NULL,
    nick VARCHAR(128) NOT NULL,
    stanza TEXT NOT NULL,
    encrypted BOOLEAN NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX muc_messages_room_time_idx ON muc_messages(room_id, created_at DESC, id DESC);
