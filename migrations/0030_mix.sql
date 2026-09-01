-- XEP-0369 MIX Core, XEP-0405 MIX-PAM, and XEP-0406 MIX Administration.
-- MIX identities are bare JIDs and deliberately do not reference local users:
-- an authenticated remote domain must never manufacture a local account.

CREATE TABLE mix_channels (
    id UUID PRIMARY KEY,
    service_domain VARCHAR(1023) NOT NULL,
    localpart VARCHAR(1023) NOT NULL,
    creator_jid VARCHAR(3071) NOT NULL,
    name VARCHAR(512),
    description VARCHAR(4096),
    contacts JSONB NOT NULL DEFAULT '[]'::jsonb,
    access_model VARCHAR(16) NOT NULL DEFAULT 'open'
        CHECK (access_model IN ('open', 'allowlist')),
    jid_visibility VARCHAR(16) NOT NULL DEFAULT 'visible'
        CHECK (jid_visibility IN ('visible', 'hidden')),
    nick_required BOOLEAN NOT NULL DEFAULT TRUE,
    max_participants INTEGER NOT NULL DEFAULT 1000
        CHECK (max_participants BETWEEN 2 AND 5000),
    max_events INTEGER NOT NULL DEFAULT 10000
        CHECK (max_events BETWEEN 100 AND 100000),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (service_domain, localpart),
    CHECK (service_domain = lower(service_domain)),
    CHECK (localpart = lower(localpart) AND position('@' IN localpart) = 0 AND position('/' IN localpart) = 0),
    CHECK (creator_jid = lower(creator_jid) AND position('@' IN creator_jid) > 1 AND position('/' IN creator_jid) = 0),
    CHECK (jsonb_typeof(contacts) = 'array' AND octet_length(contacts::text) <= 32768)
);

-- Kept after leave so the same bare JID receives the same opaque Stable
-- Participant ID when rejoining a channel.
CREATE TABLE mix_participant_identities (
    channel_id UUID NOT NULL REFERENCES mix_channels(id) ON DELETE CASCADE,
    jid VARCHAR(3071) NOT NULL,
    participant_id UUID NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (channel_id, jid),
    UNIQUE (channel_id, participant_id),
    CHECK (jid = lower(jid) AND position('@' IN jid) > 1 AND position('/' IN jid) = 0)
);

CREATE TABLE mix_participants (
    channel_id UUID NOT NULL REFERENCES mix_channels(id) ON DELETE CASCADE,
    participant_id UUID NOT NULL,
    jid VARCHAR(3071) NOT NULL,
    nick VARCHAR(1023),
    role VARCHAR(16) NOT NULL DEFAULT 'participant'
        CHECK (role IN ('owner', 'administrator', 'participant')),
    joined_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (channel_id, participant_id),
    UNIQUE (channel_id, jid),
    FOREIGN KEY (channel_id, jid)
        REFERENCES mix_participant_identities(channel_id, jid),
    CHECK (jid = lower(jid) AND position('@' IN jid) > 1 AND position('/' IN jid) = 0),
    CHECK (nick IS NULL OR (octet_length(nick) BETWEEN 1 AND 1023))
);

-- Administrative roles are independent from participation. XEP-0369 allows
-- a channel owner to destroy/configure a channel without being joined.
CREATE TABLE mix_channel_roles (
    channel_id UUID NOT NULL REFERENCES mix_channels(id) ON DELETE CASCADE,
    jid VARCHAR(3071) NOT NULL,
    role VARCHAR(16) NOT NULL CHECK (role IN ('owner', 'administrator')),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (channel_id, jid),
    CHECK (jid = lower(jid) AND position('@' IN jid) > 1 AND position('/' IN jid) = 0)
);

CREATE TABLE mix_subscriptions (
    channel_id UUID NOT NULL,
    participant_id UUID NOT NULL,
    node VARCHAR(64) NOT NULL CHECK (node IN (
        'urn:xmpp:mix:nodes:messages',
        'urn:xmpp:mix:nodes:presence',
        'urn:xmpp:mix:nodes:participants',
        'urn:xmpp:mix:nodes:info',
        'urn:xmpp:mix:nodes:config',
        'urn:xmpp:mix:nodes:allowed',
        'urn:xmpp:mix:nodes:banned'
    )),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (channel_id, participant_id, node),
    FOREIGN KEY (channel_id, participant_id)
        REFERENCES mix_participants(channel_id, participant_id) ON DELETE CASCADE
);

CREATE TABLE mix_allowed (
    channel_id UUID NOT NULL REFERENCES mix_channels(id) ON DELETE CASCADE,
    jid_pattern VARCHAR(3071) NOT NULL,
    added_by VARCHAR(3071) NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (channel_id, jid_pattern),
    CHECK (jid_pattern = lower(jid_pattern) AND position('/' IN jid_pattern) = 0),
    CHECK (added_by = lower(added_by) AND position('@' IN added_by) > 1 AND position('/' IN added_by) = 0)
);

CREATE TABLE mix_banned (
    channel_id UUID NOT NULL REFERENCES mix_channels(id) ON DELETE CASCADE,
    jid_pattern VARCHAR(3071) NOT NULL,
    added_by VARCHAR(3071) NOT NULL,
    reason VARCHAR(1024),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (channel_id, jid_pattern),
    CHECK (jid_pattern = lower(jid_pattern) AND position('/' IN jid_pattern) = 0),
    CHECK (added_by = lower(added_by) AND position('@' IN added_by) > 1 AND position('/' IN added_by) = 0)
);

CREATE TABLE mix_events (
    id UUID PRIMARY KEY,
    channel_id UUID NOT NULL REFERENCES mix_channels(id) ON DELETE CASCADE,
    node VARCHAR(64) NOT NULL CHECK (node IN (
        'urn:xmpp:mix:nodes:messages',
        'urn:xmpp:mix:nodes:presence',
        'urn:xmpp:mix:nodes:participants',
        'urn:xmpp:mix:nodes:info',
        'urn:xmpp:mix:nodes:config',
        'urn:xmpp:mix:nodes:allowed',
        'urn:xmpp:mix:nodes:banned'
    )),
    item_id VARCHAR(1023) NOT NULL,
    publisher_id UUID,
    publisher_jid VARCHAR(3071),
    payload TEXT NOT NULL CHECK (octet_length(payload) <= 1048576),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (channel_id, node, item_id),
    CHECK (publisher_jid IS NULL OR (publisher_jid = lower(publisher_jid) AND position('@' IN publisher_jid) > 1 AND position('/' IN publisher_jid) = 0))
);

-- Durable per-account PAM state. A remote join may be pending until its IQ
-- result arrives; local channel joins transition atomically to 'joined'.
CREATE TABLE mix_pam_memberships (
    id UUID PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    channel_jid VARCHAR(3071) NOT NULL,
    -- Remote MIX services choose their own opaque Stable Participant IDs; the
    -- value is not required to be a UUID even though this server uses UUIDs
    -- for participants in channels it hosts locally.
    participant_id VARCHAR(1023),
    nick VARCHAR(1023),
    state VARCHAR(16) NOT NULL CHECK (state IN ('pending_join', 'joined', 'pending_leave')),
    request_id VARCHAR(128),
    client_request_id VARCHAR(128),
    -- Retained only while a federated PAM IQ is outstanding.  This lets the
    -- result be delivered to the requesting resource without making a remote
    -- channel create a local participant/account record.
    requester_full_jid VARCHAR(4095),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (user_id, channel_jid),
    CHECK (channel_jid = lower(channel_jid) AND position('@' IN channel_jid) > 1 AND position('/' IN channel_jid) = 0),
    CHECK (nick IS NULL OR octet_length(nick) BETWEEN 1 AND 1023),
    CHECK (participant_id IS NULL OR (
        octet_length(participant_id) BETWEEN 1 AND 1023
        AND position('@' IN participant_id) = 0
        AND position('/' IN participant_id) = 0
        AND position('#' IN participant_id) = 0
    )),
    CHECK (client_request_id IS NULL OR octet_length(client_request_id) BETWEEN 1 AND 128),
    CHECK (requester_full_jid IS NULL OR (position('@' IN requester_full_jid) > 1 AND position('/' IN requester_full_jid) > position('@' IN requester_full_jid)))
);

CREATE TABLE mix_pam_subscriptions (
    membership_id UUID NOT NULL REFERENCES mix_pam_memberships(id) ON DELETE CASCADE,
    node VARCHAR(64) NOT NULL CHECK (node IN (
        'urn:xmpp:mix:nodes:messages',
        'urn:xmpp:mix:nodes:presence',
        'urn:xmpp:mix:nodes:participants',
        'urn:xmpp:mix:nodes:info'
    )),
    PRIMARY KEY (membership_id, node)
);

CREATE INDEX mix_channels_creator_idx ON mix_channels(creator_jid, created_at);
CREATE INDEX mix_channels_public_idx ON mix_channels(service_domain, localpart);
CREATE INDEX mix_participants_jid_idx ON mix_participants(jid, channel_id);
CREATE UNIQUE INDEX mix_participants_nick_idx ON mix_participants(channel_id, nick)
    WHERE nick IS NOT NULL;
CREATE INDEX mix_channel_roles_jid_idx ON mix_channel_roles(jid, channel_id);
CREATE INDEX mix_subscriptions_node_idx ON mix_subscriptions(channel_id, node);
CREATE INDEX mix_events_page_idx ON mix_events(channel_id, node, created_at DESC, id DESC);
CREATE INDEX mix_pam_user_state_idx ON mix_pam_memberships(user_id, state, updated_at);
CREATE UNIQUE INDEX mix_pam_request_idx ON mix_pam_memberships(request_id)
    WHERE request_id IS NOT NULL;
