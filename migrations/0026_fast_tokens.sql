-- XEP-0484 FAST credentials. Token material is never stored: the token is
-- derived from an operator-held master key and the public 256-bit nonce, and
-- only its SHA-256 digest is persisted for integrity/revocation checks.
CREATE TABLE fast_tokens (
    id UUID PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    device_id UUID NOT NULL,
    mechanism TEXT NOT NULL CHECK (mechanism IN (
        'HT-SHA-256-ENDP', 'HT-SHA-256-EXPR', 'HT-SHA-256-NONE'
    )),
    channel_binding TEXT NOT NULL CHECK (channel_binding IN (
        'tls-server-end-point', 'tls-exporter', 'none'
    )),
    slot TEXT NOT NULL CHECK (slot IN ('current', 'new')),
    derivation_nonce BYTEA NOT NULL CHECK (octet_length(derivation_nonce) = 32),
    token_hash BYTEA NOT NULL CHECK (octet_length(token_hash) = 32),
    last_counter BIGINT NOT NULL DEFAULT -1 CHECK (last_counter >= -1),
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    used_at TIMESTAMPTZ,
    revoked_at TIMESTAMPTZ,
    UNIQUE (user_id, device_id, mechanism, slot),
    CHECK (
        (mechanism = 'HT-SHA-256-ENDP' AND channel_binding = 'tls-server-end-point') OR
        (mechanism = 'HT-SHA-256-EXPR' AND channel_binding = 'tls-exporter') OR
        (mechanism = 'HT-SHA-256-NONE' AND channel_binding = 'none')
    )
);

CREATE INDEX fast_tokens_lookup_idx
    ON fast_tokens (user_id, device_id, mechanism)
    WHERE revoked_at IS NULL;
CREATE INDEX fast_tokens_expiry_idx ON fast_tokens (expires_at);
