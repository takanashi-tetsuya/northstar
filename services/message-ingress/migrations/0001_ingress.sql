-- Northstar Message Ingress Service Exclusive Database Schema (northstar_message_ingress)
-- Defined per northstar_microservices_deep_audit_2026-09-03.md (Section 8, 19.4).

CREATE TABLE IF NOT EXISTS accepted_messages (
    server_message_id UUID PRIMARY KEY,
    from_full_jid VARCHAR(1024) NOT NULL,
    to_jid VARCHAR(1024) NOT NULL,
    stanza_id VARCHAR(255) NOT NULL,
    message_type VARCHAR(32) NOT NULL,
    raw_stanza BYTEA NOT NULL,
    admission_timestamp_ms BIGINT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS ingress_idempotency (
    idempotency_key VARCHAR(512) PRIMARY KEY,
    server_message_id UUID NOT NULL REFERENCES accepted_messages(server_message_id),
    admitted_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
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

CREATE INDEX IF NOT EXISTS idx_ingress_outbox_unpublished 
    ON outbox_events(staged_at) 
    WHERE published_at IS NULL;
