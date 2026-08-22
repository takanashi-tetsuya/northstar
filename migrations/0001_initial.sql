CREATE TABLE users (
    id UUID PRIMARY KEY,
    username VARCHAR(64) NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    display_name VARCHAR(128),
    is_admin BOOLEAN NOT NULL DEFAULT FALSE,
    is_disabled BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_login_at TIMESTAMPTZ
);

CREATE TABLE api_sessions (
    id UUID PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash BYTEA NOT NULL UNIQUE,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX api_sessions_user_idx ON api_sessions(user_id);
CREATE INDEX api_sessions_expiry_idx ON api_sessions(expires_at);

CREATE TABLE roster_items (
    owner_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    contact_jid VARCHAR(3071) NOT NULL,
    display_name VARCHAR(128),
    subscription VARCHAR(16) NOT NULL DEFAULT 'none',
    ask VARCHAR(16),
    groups JSONB NOT NULL DEFAULT '[]'::jsonb,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (owner_id, contact_jid)
);

CREATE TABLE offline_messages (
    id UUID PRIMARY KEY,
    recipient_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    sender_jid VARCHAR(3071) NOT NULL,
    stanza TEXT NOT NULL,
    encrypted BOOLEAN NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX offline_messages_recipient_idx ON offline_messages(recipient_id, created_at);

CREATE TABLE message_archive (
    id UUID PRIMARY KEY,
    owner_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    peer_jid VARCHAR(3071) NOT NULL,
    stanza TEXT NOT NULL,
    encrypted BOOLEAN NOT NULL,
    stanza_id VARCHAR(128),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX message_archive_owner_time_idx ON message_archive(owner_id, created_at DESC);
CREATE INDEX message_archive_owner_peer_idx ON message_archive(owner_id, peer_jid, created_at DESC);

CREATE TABLE pep_items (
    owner_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    node TEXT NOT NULL,
    item_id TEXT NOT NULL,
    payload TEXT NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (owner_id, node, item_id)
);

CREATE TABLE muc_rooms (
    id UUID PRIMARY KEY,
    localpart VARCHAR(255) NOT NULL UNIQUE,
    title VARCHAR(255),
    owner_id UUID REFERENCES users(id) ON DELETE SET NULL,
    persistent BOOLEAN NOT NULL DEFAULT FALSE,
    members_only BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE audit_log (
    id BIGSERIAL PRIMARY KEY,
    actor_id UUID REFERENCES users(id) ON DELETE SET NULL,
    action VARCHAR(128) NOT NULL,
    target TEXT,
    details JSONB NOT NULL DEFAULT '{}'::jsonb,
    ip_address INET,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX audit_log_time_idx ON audit_log(created_at DESC);

