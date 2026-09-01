-- Durable XEP-0050/XEP-0133 execution and cluster-wide administration.
-- Existing completed command sessions and service-message deliveries remain
-- valid during an in-place upgrade.

ALTER TABLE admin_command_sessions
    ADD COLUMN operation_id UUID,
    ADD COLUMN request_digest BYTEA,
    ADD COLUMN execution_started_at TIMESTAMPTZ,
    ADD COLUMN result_payload TEXT;

CREATE UNIQUE INDEX admin_command_sessions_operation_idx
    ON admin_command_sessions (operation_id)
    WHERE operation_id IS NOT NULL;

ALTER TABLE admin_service_message_deliveries
    ALTER COLUMN delivered_at DROP NOT NULL,
    ALTER COLUMN delivered_at DROP DEFAULT,
    ADD COLUMN claim_id UUID,
    ADD COLUMN claim_expires_at TIMESTAMPTZ,
    ADD CONSTRAINT admin_service_message_delivery_claim_check CHECK (
        (delivered_at IS NOT NULL AND claim_id IS NULL AND claim_expires_at IS NULL)
        OR
        (delivered_at IS NULL AND claim_id IS NOT NULL AND claim_expires_at IS NOT NULL)
    );

DROP INDEX admin_service_message_deliveries_retention_idx;
CREATE INDEX admin_service_message_deliveries_retention_idx
    ON admin_service_message_deliveries (COALESCE(delivered_at, claim_expires_at));

CREATE TABLE admin_runtime_settings (
    key TEXT PRIMARY KEY CHECK (key IN ('island_mode','registration_closed')),
    enabled BOOLEAN NOT NULL,
    revision BIGINT NOT NULL DEFAULT 1 CHECK (revision > 0),
    updated_by UUID REFERENCES users(id) ON DELETE SET NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- One durable service-control generation may be active at a time.  Every
-- process which started before fired_at observes the generation and exits;
-- this avoids relying on lossy Redis pub/sub for restart/shutdown.
CREATE TABLE admin_service_control (
    singleton BOOLEAN PRIMARY KEY DEFAULT TRUE CHECK (singleton),
    generation UUID NOT NULL,
    action TEXT NOT NULL CHECK (action IN ('restart','shutdown')),
    status TEXT NOT NULL CHECK (status IN ('scheduled','canceled','fired')),
    execute_at TIMESTAMPTZ NOT NULL,
    fired_at TIMESTAMPTZ,
    expires_at TIMESTAMPTZ NOT NULL,
    requested_by UUID REFERENCES users(id) ON DELETE SET NULL,
    requested_generation BIGINT NOT NULL CHECK (requested_generation >= 0),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CHECK (execute_at < expires_at),
    CHECK ((status='fired') = (fired_at IS NOT NULL))
);

CREATE INDEX admin_service_control_due_idx
    ON admin_service_control (execute_at)
    WHERE status='scheduled';
