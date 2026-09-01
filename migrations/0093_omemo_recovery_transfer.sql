-- One-time, server-blind coordination for encrypted browser OMEMO device
-- transfer packages. PostgreSQL stores only package digests and monotonic
-- generations; passphrases, derived keys and encrypted/private state never
-- cross this boundary.

CREATE TABLE omemo_recovery_counters (
    user_id UUID PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    next_generation BIGINT NOT NULL DEFAULT 1
        CHECK (next_generation BETWEEN 1 AND 9007199254740991),
    latest_consumed_generation BIGINT NOT NULL DEFAULT 0
        CHECK (latest_consumed_generation BETWEEN 0 AND 9007199254740990),
    latest_consumed_transfer_id UUID,
    latest_consumer_commitment BYTEA CHECK (
        latest_consumer_commitment IS NULL
        OR octet_length(latest_consumer_commitment) = 32
    ),
    latest_consumed_auth_generation BIGINT NOT NULL DEFAULT 0
        CHECK (latest_consumed_auth_generation >= 0),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    CHECK (
        (latest_consumed_generation = 0
            AND latest_consumed_transfer_id IS NULL
            AND latest_consumer_commitment IS NULL
            AND latest_consumed_auth_generation = 0)
        OR
        (latest_consumed_generation > 0
            AND latest_consumed_transfer_id IS NOT NULL
            AND latest_consumer_commitment IS NOT NULL
            AND latest_consumed_auth_generation > 0
            AND latest_consumed_generation < next_generation)
    )
);

CREATE TABLE omemo_recovery_transfers (
    id UUID PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    generation BIGINT NOT NULL
        CHECK (generation BETWEEN 1 AND 9007199254740990),
    source_device_id BIGINT NOT NULL CHECK (source_device_id BETWEEN 1 AND 2147483647),
    package_sha256 BYTEA CHECK (
        package_sha256 IS NULL OR octet_length(package_sha256) = 32
    ),
    state VARCHAR(16) NOT NULL CHECK (
        state IN ('preparing', 'prepared', 'consumed', 'revoked')
    ),
    consumer_commitment BYTEA CHECK (
        consumer_commitment IS NULL OR octet_length(consumer_commitment) = 32
    ),
    consumed_auth_generation BIGINT CHECK (consumed_auth_generation > 0),
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    prepared_at TIMESTAMPTZ,
    consumed_at TIMESTAMPTZ,
    revoked_at TIMESTAMPTZ,
    expires_at TIMESTAMPTZ NOT NULL,
    UNIQUE (user_id, generation),
    CHECK (expires_at > created_at AND expires_at <= created_at + INTERVAL '7 days'),
    CHECK (
        (state = 'preparing'
            AND package_sha256 IS NULL
            AND prepared_at IS NULL
            AND consumer_commitment IS NULL
            AND consumed_auth_generation IS NULL
            AND consumed_at IS NULL
            AND revoked_at IS NULL)
        OR
        (state = 'prepared'
            AND package_sha256 IS NOT NULL
            AND prepared_at IS NOT NULL
            AND consumer_commitment IS NULL
            AND consumed_auth_generation IS NULL
            AND consumed_at IS NULL
            AND revoked_at IS NULL)
        OR
        (state = 'consumed'
            AND package_sha256 IS NOT NULL
            AND prepared_at IS NOT NULL
            AND consumer_commitment IS NOT NULL
            AND consumed_auth_generation IS NOT NULL
            AND consumed_at IS NOT NULL
            AND revoked_at IS NULL)
        OR
        (state = 'revoked'
            AND consumer_commitment IS NULL
            AND consumed_auth_generation IS NULL
            AND consumed_at IS NULL
            AND revoked_at IS NOT NULL)
    )
);

-- The source device must be able to learn a terminal result after consume has
-- atomically invalidated its ordinary bearer.  This capability is deliberately
-- separate from both API sessions and the encrypted transfer package: only a
-- keyed digest is persisted, it is read-only, and terminal results remain
-- idempotently observable for at most 24 hours.
CREATE TABLE omemo_recovery_poll_capabilities (
    transfer_id UUID PRIMARY KEY
        REFERENCES omemo_recovery_transfers(id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    secret_hash BYTEA NOT NULL UNIQUE CHECK (octet_length(secret_hash) = 32),
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    expires_at TIMESTAMPTZ NOT NULL,
    UNIQUE (user_id, transfer_id),
    CHECK (expires_at > created_at AND expires_at <= created_at + INTERVAL '8 days')
);

CREATE INDEX omemo_recovery_poll_capabilities_expiry_idx
    ON omemo_recovery_poll_capabilities (expires_at);

CREATE INDEX omemo_recovery_transfers_user_recent_idx
    ON omemo_recovery_transfers (user_id, generation DESC);
CREATE INDEX omemo_recovery_transfers_expiry_idx
    ON omemo_recovery_transfers (expires_at)
    WHERE state IN ('preparing', 'prepared');

CREATE UNIQUE INDEX omemo_recovery_transfers_one_active_idx
    ON omemo_recovery_transfers (user_id)
    WHERE state IN ('preparing', 'prepared');

CREATE OR REPLACE FUNCTION fence_omemo_recovery_transfer()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    IF ROW(NEW.id, NEW.user_id, NEW.generation, NEW.source_device_id,
           NEW.created_at, NEW.expires_at)
       IS DISTINCT FROM
       ROW(OLD.id, OLD.user_id, OLD.generation, OLD.source_device_id,
           OLD.created_at, OLD.expires_at) THEN
        RAISE EXCEPTION 'OMEMO recovery transfer identity is immutable';
    END IF;

    IF OLD.state = 'preparing' THEN
        IF NEW.state NOT IN ('preparing', 'prepared', 'revoked') THEN
            RAISE EXCEPTION 'invalid OMEMO recovery preparing transition';
        END IF;
    ELSIF OLD.state = 'prepared' THEN
        IF NEW.state NOT IN ('prepared', 'consumed', 'revoked') THEN
            RAISE EXCEPTION 'invalid OMEMO recovery prepared transition';
        END IF;
    ELSIF NEW IS DISTINCT FROM OLD THEN
        RAISE EXCEPTION 'terminal OMEMO recovery transfer is immutable';
    END IF;

    IF OLD.package_sha256 IS NOT NULL
       AND NEW.package_sha256 IS DISTINCT FROM OLD.package_sha256 THEN
        RAISE EXCEPTION 'OMEMO recovery package digest is immutable';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER trg_omemo_recovery_transfer_fence
BEFORE UPDATE ON omemo_recovery_transfers
FOR EACH ROW EXECUTE FUNCTION fence_omemo_recovery_transfer();

CREATE OR REPLACE FUNCTION fence_omemo_recovery_counter()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    IF NEW.user_id IS DISTINCT FROM OLD.user_id
       OR NEW.next_generation < OLD.next_generation
       OR NEW.next_generation > OLD.next_generation + 1
       OR NEW.latest_consumed_generation < OLD.latest_consumed_generation
       OR NEW.latest_consumed_auth_generation < OLD.latest_consumed_auth_generation
       OR (NEW.latest_consumed_generation > OLD.latest_consumed_generation
           AND NEW.latest_consumed_auth_generation
               <= OLD.latest_consumed_auth_generation) THEN
        RAISE EXCEPTION 'invalid OMEMO recovery authority transition';
    END IF;
    IF NEW.latest_consumed_generation = OLD.latest_consumed_generation
       AND ROW(NEW.latest_consumed_transfer_id, NEW.latest_consumer_commitment,
               NEW.latest_consumed_auth_generation)
           IS DISTINCT FROM
           ROW(OLD.latest_consumed_transfer_id, OLD.latest_consumer_commitment,
               OLD.latest_consumed_auth_generation) THEN
        RAISE EXCEPTION 'OMEMO recovery consumer fence is immutable at one generation';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER trg_omemo_recovery_counter_fence
BEFORE UPDATE ON omemo_recovery_counters
FOR EACH ROW EXECUTE FUNCTION fence_omemo_recovery_counter();

COMMENT ON TABLE omemo_recovery_transfers IS
    'Server-blind one-time coordination for locally encrypted OMEMO device transfer packages';
COMMENT ON COLUMN omemo_recovery_transfers.package_sha256 IS
    'SHA-256 of the encrypted package; never a passphrase, KDF output or plaintext/private key digest';
COMMENT ON COLUMN omemo_recovery_transfers.consumer_commitment IS
    'SHA-256 commitment to the 256-bit destination secret, account and transfer; the secret is never stored';
COMMENT ON TABLE omemo_recovery_poll_capabilities IS
    'Read-only source completion capabilities; only an account/transfer-bound SHA-256 digest is stored';
COMMENT ON TABLE omemo_recovery_counters IS
    'Permanent per-account high-water fence preventing a consumed OMEMO device transfer from being rolled back after terminal rows are cleaned';
