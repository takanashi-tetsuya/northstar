-- PostgreSQL is the authority for the anti-abuse HMAC key generation used by
-- every process serving one XMPP domain.  Only irreversible, purpose-separated
-- 96-bit key identifiers are stored here; the HMAC keys remain mounted secrets.
CREATE TABLE abuse_key_deployments (
    xmpp_domain TEXT PRIMARY KEY,
    epoch BIGINT NOT NULL CHECK (epoch >= 1),
    phase TEXT NOT NULL CHECK (phase IN ('stable', 'overlap', 'retiring')),
    current_key_id TEXT NOT NULL
        CHECK (current_key_id ~ '^[A-Za-z0-9_-]{16}$'),
    previous_key_id TEXT
        CHECK (previous_key_id IS NULL OR previous_key_id ~ '^[A-Za-z0-9_-]{16}$'),
    transition_started_at TIMESTAMPTZ,
    retirement_started_at TIMESTAMPTZ,
    retire_not_before TIMESTAMPTZ,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    CHECK (previous_key_id IS NULL OR previous_key_id <> current_key_id),
    CHECK (
        (phase = 'stable'
            AND previous_key_id IS NULL
            AND transition_started_at IS NULL
            AND retirement_started_at IS NULL
            AND retire_not_before IS NULL)
        OR
        (phase = 'overlap'
            AND previous_key_id IS NOT NULL
            AND transition_started_at IS NOT NULL
            AND retirement_started_at IS NULL
            AND retire_not_before IS NULL)
        OR
        (phase = 'retiring'
            AND previous_key_id IS NOT NULL
            AND transition_started_at IS NOT NULL
            AND retirement_started_at IS NOT NULL
            AND retire_not_before IS NOT NULL
            AND retirement_started_at >= transition_started_at
            AND retire_not_before >= retirement_started_at)
    )
);

COMMENT ON TABLE abuse_key_deployments IS
    'Deployment-wide anti-abuse HMAC generation authority; contains key IDs only, never key material';
COMMENT ON COLUMN abuse_key_deployments.epoch IS
    'Operator-controlled monotonic generation incremented exactly once per current-key rotation';
COMMENT ON COLUMN abuse_key_deployments.retire_not_before IS
    'Earliest removal time measured from sealing out every previous-generation node; active durable references can extend retirement';

-- Final retirement performs a fail-closed reference fence while holding the
-- deployment authority lock. Keep those rare checks index-bounded even on a
-- large queue/admission installation.
CREATE INDEX abuse_pow_challenges_key_expiry
    ON abuse_pow_challenges (key_id, expires_at);
CREATE INDEX abuse_message_admissions_key_expiry
    ON abuse_message_admissions (key_id, expires_at);
CREATE INDEX offline_message_admissions_key_expiry
    ON offline_message_admissions (payload_key_id, expires_at);
