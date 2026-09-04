-- Northstar Identity Service Exclusive Database Schema (northstar_identity)
-- Defined per northstar_microservices_deep_audit_2026-09-03.md (Section 8, 19.4).

CREATE TABLE IF NOT EXISTS accounts (
    account_id UUID PRIMARY KEY,
    username VARCHAR(255) NOT NULL UNIQUE,
    canonical_jid VARCHAR(1024) NOT NULL UNIQUE,
    credential_generation BIGINT NOT NULL DEFAULT 1,
    status VARCHAR(32) NOT NULL DEFAULT 'active',
    home_region VARCHAR(64) NOT NULL DEFAULT 'local',
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS scram_credentials (
    account_id UUID PRIMARY KEY REFERENCES accounts(account_id) ON DELETE CASCADE,
    scram_salt BYTEA NOT NULL,
    scram_iterations INTEGER NOT NULL DEFAULT 4096,
    stored_key BYTEA NOT NULL,
    server_key BYTEA NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS outbox_events (
    event_id UUID PRIMARY KEY,
    aggregate_type VARCHAR(64) NOT NULL,
    aggregate_id VARCHAR(255) NOT NULL,
    aggregate_version BIGINT NOT NULL,
    event_type VARCHAR(128) NOT NULL,
    payload BYTEA NOT NULL,
    staged_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    published_at TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_identity_outbox_unpublished 
    ON outbox_events(staged_at) 
    WHERE published_at IS NULL;
