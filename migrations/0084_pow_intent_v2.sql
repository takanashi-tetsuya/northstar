-- Bind one-use proof-of-work challenges to the exact operation intent. Legacy
-- rows remain protocol_version=1 for an explicit, operator-bounded migration
-- window; every newly issued v2 row has a complete method/path/body commitment.
ALTER TABLE abuse_pow_challenges
    ADD COLUMN protocol_version SMALLINT NOT NULL DEFAULT 1
        CHECK (protocol_version IN (1, 2)),
    ADD COLUMN intent_method VARCHAR(8),
    ADD COLUMN intent_path TEXT,
    ADD COLUMN body_sha256 BYTEA,
    ADD COLUMN server_nonce TEXT,
    ADD COLUMN issued_at TIMESTAMPTZ;

ALTER TABLE abuse_pow_challenges
    ADD CONSTRAINT abuse_pow_challenge_intent_shape CHECK (
        (protocol_version = 1
            AND intent_method IS NULL
            AND intent_path IS NULL
            AND body_sha256 IS NULL)
        OR
        (protocol_version = 2
            AND intent_method IN ('POST', 'PATCH', 'XMPP')
            AND octet_length(intent_path) BETWEEN 1 AND 512
            AND left(intent_path, 1) = '/'
            AND octet_length(body_sha256) = 32
            AND server_nonce IS NOT NULL
            AND issued_at IS NOT NULL)
    ),
    ADD CONSTRAINT abuse_pow_challenge_nonce_shape CHECK (
        server_nonce IS NULL
        OR (
            octet_length(server_nonce) BETWEEN 16 AND 64
            AND server_nonce !~ '[^A-Za-z0-9_-]'
        )
    ),
    ADD CONSTRAINT abuse_pow_challenge_issued_time CHECK (
        issued_at IS NULL OR (issued_at <= not_before AND issued_at < expires_at)
    );

-- New code always writes both values. Nullable columns are retained solely so
-- an online migration can drain v1 rows created by the previous binary.
CREATE INDEX abuse_pow_challenges_version_expiry_idx
    ON abuse_pow_challenges (protocol_version, expires_at);
