-- A signed Redis request is an authenticated routing hint, not durable
-- ownership of a MIX recipient row. Before a remote node may enqueue a
-- claimed source to one of its local transports, rotate the worker lease into
-- this bounded database fence. If the source node times out or retries, its
-- previous token is already invalid; if the target node exits, the fence can
-- release the same ordered head without reconstructing a message from Redis.

CREATE TABLE mix_cluster_delivery_fences (
    delivery_id UUID PRIMARY KEY
        REFERENCES mix_delivery_recipients(delivery_id)
        ON DELETE CASCADE DEFERRABLE INITIALLY DEFERRED,
    lease_token UUID NOT NULL,
    node_id TEXT NOT NULL,
    request_id UUID NOT NULL,
    first_owned_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    expires_at TIMESTAMPTZ NOT NULL,
    CHECK (node_id <> '' AND octet_length(node_id) <= 128),
    CHECK (expires_at <= first_owned_at + INTERVAL '5 minutes')
);

CREATE UNIQUE INDEX mix_cluster_delivery_fence_request
    ON mix_cluster_delivery_fences (node_id, request_id);
CREATE INDEX mix_cluster_delivery_fence_expiry
    ON mix_cluster_delivery_fences (expires_at, delivery_id);

COMMENT ON TABLE mix_cluster_delivery_fences IS
    'Typed remote-node hand-off for leased MIX recipient rows; Redis ACK alone never owns a source';
COMMENT ON COLUMN mix_cluster_delivery_fences.lease_token IS
    'Rotated MIX lease owned only by the named remote node until socket/SM/BOSH transfer or release';
