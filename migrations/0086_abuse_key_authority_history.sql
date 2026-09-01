-- Preserve the anti-abuse key-generation authority across application bugs
-- and operator mistakes.  A missing authority row would otherwise allow the
-- next process to bootstrap an unrelated epoch/key ID and silently partition
-- actor identities.  Destructive recovery remains possible to a database
-- owner by disabling the guard trigger explicitly, which is intentionally an
-- out-of-band disaster-recovery action rather than an application operation.
CREATE TABLE abuse_key_deployment_history (
    sequence BIGSERIAL PRIMARY KEY,
    xmpp_domain TEXT NOT NULL,
    epoch BIGINT NOT NULL CHECK (epoch >= 1),
    phase TEXT NOT NULL CHECK (phase IN ('stable', 'overlap', 'retiring')),
    current_key_id TEXT NOT NULL
        CHECK (current_key_id ~ '^[A-Za-z0-9_-]{16}$'),
    previous_key_id TEXT
        CHECK (previous_key_id IS NULL OR previous_key_id ~ '^[A-Za-z0-9_-]{16}$'),
    transition_started_at TIMESTAMPTZ,
    retirement_started_at TIMESTAMPTZ,
    retire_not_before TIMESTAMPTZ,
    authority_updated_at TIMESTAMPTZ NOT NULL,
    recorded_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    operation TEXT NOT NULL CHECK (operation IN ('migration-snapshot', 'insert', 'update')),
    CHECK (previous_key_id IS NULL OR previous_key_id <> current_key_id)
);

COMMENT ON TABLE abuse_key_deployment_history IS
    'Append-only non-secret snapshots of anti-abuse key deployment authority transitions';

INSERT INTO abuse_key_deployment_history (
    xmpp_domain, epoch, phase, current_key_id, previous_key_id,
    transition_started_at, retirement_started_at, retire_not_before,
    authority_updated_at, operation
)
SELECT xmpp_domain, epoch, phase, current_key_id, previous_key_id,
       transition_started_at, retirement_started_at, retire_not_before,
       updated_at, 'migration-snapshot'
FROM abuse_key_deployments;

CREATE OR REPLACE FUNCTION record_abuse_key_deployment_history()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    INSERT INTO abuse_key_deployment_history (
        xmpp_domain, epoch, phase, current_key_id, previous_key_id,
        transition_started_at, retirement_started_at, retire_not_before,
        authority_updated_at, operation
    ) VALUES (
        NEW.xmpp_domain, NEW.epoch, NEW.phase, NEW.current_key_id,
        NEW.previous_key_id, NEW.transition_started_at,
        NEW.retirement_started_at, NEW.retire_not_before, NEW.updated_at,
        CASE WHEN TG_OP = 'INSERT' THEN 'insert' ELSE 'update' END
    );
    RETURN NEW;
END;
$$;

CREATE TRIGGER abuse_key_deployment_history_record
AFTER INSERT OR UPDATE ON abuse_key_deployments
FOR EACH ROW EXECUTE FUNCTION record_abuse_key_deployment_history();

CREATE OR REPLACE FUNCTION reject_abuse_key_authority_delete()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION
        'anti-abuse key deployment authority is append-only; use documented out-of-band disaster recovery';
END;
$$;

CREATE TRIGGER abuse_key_deployment_delete_guard
BEFORE DELETE ON abuse_key_deployments
FOR EACH ROW EXECUTE FUNCTION reject_abuse_key_authority_delete();

CREATE TRIGGER abuse_key_deployment_history_update_guard
BEFORE UPDATE OR DELETE ON abuse_key_deployment_history
FOR EACH ROW EXECUTE FUNCTION reject_abuse_key_authority_delete();

CREATE INDEX abuse_key_deployment_history_domain_sequence
    ON abuse_key_deployment_history (xmpp_domain, sequence DESC);
