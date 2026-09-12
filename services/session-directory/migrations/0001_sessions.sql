-- Northstar Session Directory Service Exclusive Database Schema (northstar_session)
-- Defined per northstar_microservices_deep_audit_2026-09-03.md (Section 8, 19.4).

CREATE TABLE IF NOT EXISTS session_epoch_counters (
    full_jid VARCHAR(1024) PRIMARY KEY,
    last_epoch BIGINT NOT NULL DEFAULT 0,
    closed_at TIMESTAMPTZ,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS active_sessions (
    full_jid VARCHAR(1024) PRIMARY KEY REFERENCES session_epoch_counters(full_jid),
    bare_jid VARCHAR(1024) NOT NULL,
    account_id UUID NOT NULL,
    resource VARCHAR(255) NOT NULL,
    edge_instance_id VARCHAR(128) NOT NULL,
    connection_id VARCHAR(128) NOT NULL,
    session_epoch BIGINT NOT NULL,
    bound_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    heartbeat_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_active_sessions_bare_jid ON active_sessions(bare_jid);

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

CREATE INDEX IF NOT EXISTS idx_session_outbox_unpublished 
    ON outbox_events(staged_at) 
    WHERE published_at IS NULL;
