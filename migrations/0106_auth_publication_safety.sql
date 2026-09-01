-- Authentication publication safety.
--
-- Credential changes (notably FAST rotation/invalidation) are committed before
-- the terminal SASL2 success can be written.  A user-agent replacement epoch,
-- however, must remain invisible to cluster maintenance until that first
-- success/resumed frame has crossed the transport boundary.  These two small
-- durable claim tables provide the required operation/connection fences.

CREATE TABLE user_agent_login_epoch_sequences (
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    device_id UUID NOT NULL,
    allocated_epoch BIGINT NOT NULL CHECK (allocated_epoch > 0),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (user_id, device_id)
);

INSERT INTO user_agent_login_epoch_sequences(user_id,device_id,allocated_epoch,updated_at)
SELECT user_id,device_id,epoch,updated_at FROM user_agent_login_epochs
ON CONFLICT (user_id,device_id) DO UPDATE
SET allocated_epoch=GREATEST(user_agent_login_epoch_sequences.allocated_epoch,
                             EXCLUDED.allocated_epoch),
    updated_at=clock_timestamp();

CREATE TABLE user_agent_login_epoch_stages (
    operation_id UUID PRIMARY KEY,
    connection_id UUID NOT NULL,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    device_id UUID NOT NULL,
    auth_generation BIGINT NOT NULL CHECK (auth_generation >= 0),
    epoch BIGINT NOT NULL CHECK (epoch > 0),
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    UNIQUE (connection_id, operation_id),
    UNIQUE (user_id, device_id, epoch)
);

CREATE INDEX user_agent_login_epoch_stages_expiry_idx
    ON user_agent_login_epoch_stages(expires_at);

-- A replacement bind for an exact full JID must not steal the stable capacity
-- lease from an older resumable XEP-0198 stream during phase one.  The old
-- lease remains authoritative until the post-transport publication transaction
-- atomically consumes this claim and transfers it. Crash/failure before that
-- publication therefore leaves the old stream resumable; expired claims are
-- harmless and bounded by cleanup.
CREATE TABLE deployment_session_binding_claims (
    connection_id UUID PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    full_jid TEXT NOT NULL,
    replaced_connection_id UUID NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    UNIQUE (full_jid)
);

CREATE INDEX deployment_session_binding_claims_expiry_idx
    ON deployment_session_binding_claims(expires_at);

REVOKE ALL ON user_agent_login_epoch_sequences FROM PUBLIC;
REVOKE ALL ON user_agent_login_epoch_stages FROM PUBLIC;
REVOKE ALL ON deployment_session_binding_claims FROM PUBLIC;
