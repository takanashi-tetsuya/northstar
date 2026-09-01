-- Durable, cross-process anti-abuse state.  Event timestamps are bounded by
-- the configured window during every mutation; the arrays therefore cannot
-- grow without limit.  `state_key` already includes the action except for the
-- deliberately shared `behavior:*` actors.
CREATE TABLE abuse_actor_states (
    state_key TEXT PRIMARY KEY,
    event_times TIMESTAMPTZ[] NOT NULL DEFAULT '{}',
    penalty_level INTEGER NOT NULL DEFAULT 0 CHECK (penalty_level BETWEEN 0 AND 10),
    last_activity TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    blocked_until TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    sequence BIGINT NOT NULL DEFAULT 0 CHECK (sequence >= 0)
);
CREATE INDEX abuse_actor_states_stale_idx
    ON abuse_actor_states (GREATEST(last_activity, blocked_until));

CREATE TABLE abuse_pow_challenges (
    id UUID PRIMARY KEY,
    action VARCHAR(32) NOT NULL,
    subject_hash BYTEA NOT NULL,
    prefix TEXT NOT NULL,
    work_factor BIGINT NOT NULL CHECK (work_factor > 0),
    not_before TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    actor_sequences JSONB NOT NULL,
    requirement JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (action, subject_hash)
);
CREATE INDEX abuse_pow_challenges_expiry_idx ON abuse_pow_challenges (expires_at);

CREATE TABLE abuse_challenge_issue_windows (
    actor_key TEXT PRIMARY KEY,
    event_times TIMESTAMPTZ[] NOT NULL DEFAULT '{}',
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Historical rows remain explicitly unverified.  New reports bind every
-- copied item to an archive row owned by the reporter.  The FK is deliberately
-- SET NULL so retention can delete MAM while preserving the immutable digest
-- and the moderation record.
ALTER TABLE abuse_report_evidence
    ADD COLUMN archive_id UUID REFERENCES message_archive(id) ON DELETE SET NULL,
    ADD COLUMN archive_stanza_hash BYTEA,
    ADD COLUMN evidence_source VARCHAR(40) NOT NULL DEFAULT 'legacy_client_submitted_unverified'
        CHECK (evidence_source IN (
            'legacy_client_submitted_unverified',
            'server_verified_plaintext',
            'user_decrypted_omemo_unverified'
        ));
CREATE INDEX abuse_report_evidence_archive_idx
    ON abuse_report_evidence (archive_id) WHERE archive_id IS NOT NULL;
