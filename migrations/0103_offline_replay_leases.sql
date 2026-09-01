-- XEP-0160 replay ownership must survive process crashes without retaining a
-- PostgreSQL connection while a slow client applies socket backpressure.
--
-- `owner_token` is an unguessable fencing token.  An expired owner can never
-- renew or delete a replacement lease because every mutation matches both the
-- account and the exact current token.  Delivery-row claims remain separate:
-- once a stanza enters SM/BOSH/socket ownership its per-page claim continues
-- to fence the durable row independently of this short account coordinator.

CREATE TABLE offline_replay_leases (
    recipient_id UUID PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    owner_token UUID NOT NULL UNIQUE,
    acquired_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    renewed_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    expires_at TIMESTAMPTZ NOT NULL,
    CONSTRAINT offline_replay_lease_time_order CHECK (
        -- Page claims live for 60 seconds.  The logical owner must outlive
        -- that fence plus scheduling/clock jitter so crash takeover can see
        -- every abandoned page in its first pass.
        expires_at >= renewed_at + INTERVAL '75 seconds'
        AND renewed_at >= acquired_at
    )
);

CREATE INDEX offline_replay_leases_expiry
    ON offline_replay_leases (expires_at, recipient_id);
