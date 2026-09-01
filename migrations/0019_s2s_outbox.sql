CREATE TABLE s2s_outbox (
    id UUID PRIMARY KEY,
    target_domain VARCHAR(253) NOT NULL,
    bounce_to VARCHAR(3071),
    stanza TEXT NOT NULL,
    dedupe_hash BYTEA NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ NOT NULL,
    next_attempt_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    attempt_count INTEGER NOT NULL DEFAULT 0,
    locked_until TIMESTAMPTZ,
    lock_token UUID,
    last_error TEXT,
    CONSTRAINT s2s_outbox_nonempty_stanza CHECK (octet_length(stanza) BETWEEN 1 AND 1048576),
    CONSTRAINT s2s_outbox_sha256_hash CHECK (octet_length(dedupe_hash) = 32),
    CONSTRAINT s2s_outbox_valid_expiry CHECK (expires_at > created_at),
    CONSTRAINT s2s_outbox_nonnegative_attempts CHECK (attempt_count >= 0),
    CONSTRAINT s2s_outbox_lock_pair CHECK (
        (locked_until IS NULL AND lock_token IS NULL)
        OR (locked_until IS NOT NULL AND lock_token IS NOT NULL)
    ),
    UNIQUE (target_domain, dedupe_hash)
);

CREATE INDEX s2s_outbox_ready_idx
    ON s2s_outbox (next_attempt_at, created_at)
    WHERE lock_token IS NULL;

CREATE INDEX s2s_outbox_expired_lease_idx
    ON s2s_outbox (locked_until)
    WHERE lock_token IS NOT NULL;

CREATE INDEX s2s_outbox_domain_idx
    ON s2s_outbox (target_domain, created_at);
