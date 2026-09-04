-- Northstar Delivery Router Service Exclusive Database Schema (northstar_delivery)
-- Defined per northstar_microservices_deep_audit_2026-09-03.md (Section 8, 19.4).

CREATE TABLE IF NOT EXISTS consumer_inbox (
    consumer_name VARCHAR(128) NOT NULL,
    event_id UUID NOT NULL,
    processed_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (consumer_name, event_id)
);

CREATE TABLE IF NOT EXISTS offline_spool (
    offline_id BIGSERIAL PRIMARY KEY,
    recipient_bare_jid VARCHAR(1024) NOT NULL,
    server_message_id VARCHAR(255) NOT NULL,
    stanza BYTEA NOT NULL,
    timestamp_ms BIGINT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_offline_spool_recipient ON offline_spool(recipient_bare_jid);

CREATE TABLE IF NOT EXISTS delivery_attempts (
    attempt_id BIGSERIAL PRIMARY KEY,
    server_message_id VARCHAR(255) NOT NULL,
    target_full_jid VARCHAR(1024) NOT NULL,
    connection_id VARCHAR(128) NOT NULL,
    session_epoch BIGINT NOT NULL,
    status VARCHAR(32) NOT NULL, -- Pushed, Acked, Spooled, DeadLettered
    attempted_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);
