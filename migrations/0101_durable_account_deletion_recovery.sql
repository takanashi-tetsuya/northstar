-- XEP-0077 account removal intentionally commits a fail-closed quiesce before
-- tearing down resumable sessions and deleting the account. A process crash in
-- that interval must not leave the account permanently disabled with no
-- recovery owner. This row is created in the same transaction as the quiesce
-- and cascades only after the user deletion has committed.
CREATE TABLE account_deletion_requests (
    user_id UUID PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    requested_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    recovery_after TIMESTAMPTZ NOT NULL
        DEFAULT (clock_timestamp() + INTERVAL '5 minutes'),
    attempts INTEGER NOT NULL DEFAULT 0 CHECK (attempts >= 0),
    claim_token UUID,
    claim_until TIMESTAMPTZ,
    last_error_code TEXT,
    CHECK ((claim_token IS NULL) = (claim_until IS NULL)),
    CHECK (last_error_code IS NULL OR (
        length(last_error_code) BETWEEN 1 AND 128
        AND last_error_code !~ '[[:cntrl:]]'
    ))
);

CREATE INDEX account_deletion_requests_due_idx
    ON account_deletion_requests (recovery_after, requested_at, user_id);

REVOKE ALL ON TABLE account_deletion_requests FROM PUBLIC;
