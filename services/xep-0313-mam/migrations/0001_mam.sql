-- Northstar XEP-0313 MAM Archive Service Exclusive Database Schema (northstar_xep_0313)
-- Defined per northstar_microservices_deep_audit_2026-09-03.md (Section 8, 19.4).

CREATE TABLE IF NOT EXISTS consumer_inbox (
    consumer_name VARCHAR(128) NOT NULL,
    event_id UUID NOT NULL,
    processed_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (consumer_name, event_id)
);

CREATE TABLE IF NOT EXISTS archive_messages (
    archive_id BIGSERIAL PRIMARY KEY,
    owner_bare_jid VARCHAR(1024) NOT NULL,
    with_bare_jid VARCHAR(1024) NOT NULL,
    server_message_id VARCHAR(255) NOT NULL,
    stanza_id VARCHAR(255),
    stanza BYTEA NOT NULL,
    timestamp_ms BIGINT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT uq_archive_owner_msg UNIQUE (owner_bare_jid, server_message_id)
);

CREATE INDEX IF NOT EXISTS idx_mam_owner_timestamp 
    ON archive_messages(owner_bare_jid, timestamp_ms);

CREATE INDEX IF NOT EXISTS idx_mam_owner_with_timestamp 
    ON archive_messages(owner_bare_jid, with_bare_jid, timestamp_ms);

CREATE TABLE IF NOT EXISTS mam_preferences (
    owner_bare_jid VARCHAR(1024) PRIMARY KEY,
    default_policy VARCHAR(32) NOT NULL DEFAULT 'always', -- always, never, roster
    always_jids TEXT[] NOT NULL DEFAULT '{}',
    never_jids TEXT[] NOT NULL DEFAULT '{}',
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);
