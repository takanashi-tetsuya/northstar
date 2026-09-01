-- Credential epochs and bounded FAST rotation for XEP-0484.  The command
-- session table is also reserved here for the durable XEP-0050/XEP-0133
-- implementation completed by the same release migration.

CREATE INDEX IF NOT EXISTS users_created_at_idx ON users (created_at, id);

ALTER TABLE fast_tokens
    ADD COLUMN auth_generation BIGINT,
    ADD COLUMN strong_auth_at TIMESTAMPTZ,
    ADD COLUMN chain_expires_at TIMESTAMPTZ;

UPDATE fast_tokens AS token
SET auth_generation = users.auth_generation,
    strong_auth_at = token.created_at,
    chain_expires_at = token.expires_at
FROM users
WHERE users.id = token.user_id;

ALTER TABLE fast_tokens
    ALTER COLUMN auth_generation SET NOT NULL,
    ALTER COLUMN strong_auth_at SET NOT NULL,
    ALTER COLUMN chain_expires_at SET NOT NULL,
    ADD CONSTRAINT fast_tokens_chain_order_check
        CHECK (strong_auth_at <= expires_at AND expires_at <= chain_expires_at),
    DROP CONSTRAINT IF EXISTS fast_tokens_user_id_device_id_mechanism_slot_key;

-- Older releases allocated two slots per mechanism.  Keep only the newest
-- credential in each global device slot before tightening the invariant.
DELETE FROM fast_tokens AS stale
USING fast_tokens AS retained
WHERE stale.user_id = retained.user_id
  AND stale.device_id = retained.device_id
  AND stale.slot = retained.slot
  AND (stale.created_at, stale.id) < (retained.created_at, retained.id);

ALTER TABLE fast_tokens
    ADD CONSTRAINT fast_tokens_user_device_slot_key
        UNIQUE (user_id, device_id, slot);

DROP INDEX IF EXISTS fast_tokens_lookup_idx;
CREATE INDEX fast_tokens_lookup_idx
    ON fast_tokens (user_id, device_id, mechanism)
    WHERE revoked_at IS NULL;
CREATE INDEX fast_tokens_chain_expiry_idx ON fast_tokens (chain_expires_at);

CREATE TABLE user_agent_login_epochs (
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    device_id UUID NOT NULL,
    epoch BIGINT NOT NULL CHECK (epoch > 0),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (user_id, device_id)
);

CREATE TABLE admin_command_sessions (
    id UUID PRIMARY KEY,
    owner_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    owner_full_jid TEXT NOT NULL,
    owner_auth_generation BIGINT NOT NULL CHECK (owner_auth_generation >= 0),
    node TEXT NOT NULL,
    stage TEXT NOT NULL,
    state JSONB NOT NULL DEFAULT '{}'::jsonb,
    expires_at TIMESTAMPTZ NOT NULL,
    completed_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX admin_command_sessions_owner_idx
    ON admin_command_sessions (owner_id, expires_at DESC);
CREATE INDEX admin_command_sessions_expiry_idx
    ON admin_command_sessions (expires_at)
    WHERE completed_at IS NULL;

CREATE TABLE admin_service_messages (
    kind TEXT PRIMARY KEY CHECK (kind IN ('motd','welcome')),
    body TEXT NOT NULL CHECK (octet_length(body) BETWEEN 1 AND 65536),
    revision UUID NOT NULL,
    updated_by UUID REFERENCES users(id) ON DELETE SET NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Welcome messages are delivered once per account/revision.  MOTD messages
-- are delivered once per account/revision/calendar day so multiple resources
-- and multiple cluster nodes cannot duplicate the operator notice.
CREATE TABLE admin_service_message_deliveries (
    kind TEXT NOT NULL CHECK (kind IN ('motd','welcome')),
    revision UUID NOT NULL,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    delivery_date DATE NOT NULL,
    delivered_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (kind, revision, user_id, delivery_date)
);
CREATE INDEX admin_service_message_deliveries_retention_idx
    ON admin_service_message_deliveries (delivered_at);
CREATE UNIQUE INDEX admin_service_welcome_once_idx
    ON admin_service_message_deliveries (kind, user_id)
    WHERE kind='welcome';

CREATE TABLE federation_runtime_rules (
    kind TEXT NOT NULL CHECK (kind IN ('blacklist','whitelist')),
    domain TEXT NOT NULL,
    updated_by UUID REFERENCES users(id) ON DELETE SET NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (kind, domain)
);
