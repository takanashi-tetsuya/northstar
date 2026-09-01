-- Durable XEP-0198 stream-management state.  The resume credential itself is
-- never stored: token_hash is SHA-256 over a 256-bit random bearer token.
ALTER TABLE users
    ADD COLUMN auth_generation BIGINT NOT NULL DEFAULT 0 CHECK (auth_generation >= 0);

CREATE TABLE sm_resume_sessions (
    id UUID PRIMARY KEY,
    token_hash BYTEA NOT NULL UNIQUE CHECK (octet_length(token_hash) = 32),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    auth_generation BIGINT NOT NULL CHECK (auth_generation >= 0),
    full_jid TEXT NOT NULL CHECK (octet_length(full_jid) BETWEEN 3 AND 3071),
    resource TEXT NOT NULL CHECK (octet_length(resource) BETWEEN 1 AND 1023),
    connection_id UUID NOT NULL,
    resume_timeout_seconds BIGINT NOT NULL CHECK (resume_timeout_seconds BETWEEN 1 AND 86400),
    inbound_h BIGINT NOT NULL DEFAULT 0 CHECK (inbound_h BETWEEN 0 AND 4294967295),
    outbound_h BIGINT NOT NULL DEFAULT 0 CHECK (outbound_h BETWEEN 0 AND 4294967295),
    acked_h BIGINT NOT NULL DEFAULT 0 CHECK (acked_h BETWEEN 0 AND 4294967295),
    available BOOLEAN NOT NULL DEFAULT FALSE,
    carbons BOOLEAN NOT NULL DEFAULT FALSE,
    priority SMALLINT NOT NULL DEFAULT 0,
    blocklist_requested BOOLEAN NOT NULL DEFAULT FALSE,
    peer_ip INET,
    user_agent_id UUID,
    joined_rooms JSONB NOT NULL DEFAULT '[]'::jsonb
        CHECK (jsonb_typeof(joined_rooms) = 'array'),
    resumable BOOLEAN NOT NULL DEFAULT FALSE,
    live_lease_until TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    claim_token UUID,
    claimed_until TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CHECK ((claim_token IS NULL) = (claimed_until IS NULL))
);

CREATE INDEX sm_resume_sessions_user_idx
    ON sm_resume_sessions (user_id, expires_at);
CREATE INDEX sm_resume_sessions_cleanup_idx
    ON sm_resume_sessions (expires_at);
CREATE INDEX sm_resume_sessions_claim_idx
    ON sm_resume_sessions (resumable, live_lease_until, claimed_until);

CREATE TABLE sm_resume_stanzas (
    session_id UUID NOT NULL REFERENCES sm_resume_sessions(id) ON DELETE CASCADE,
    position INTEGER NOT NULL CHECK (position >= 0),
    stanza TEXT NOT NULL CHECK (octet_length(stanza) BETWEEN 1 AND 1048576),
    byte_count INTEGER GENERATED ALWAYS AS (octet_length(stanza)) STORED,
    PRIMARY KEY (session_id, position)
);
