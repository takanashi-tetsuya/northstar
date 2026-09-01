-- Bind replayable secret-bearing responses to the durable resource whose
-- current state authorizes disclosure.  The raw invitation token remains
-- only inside the AEAD response envelope.

ALTER TABLE api_idempotency_records
    ADD COLUMN replay_resource_id UUID;

-- Builds that briefly ran 0057 before this binding existed cannot prove
-- which invitation authorized an older encrypted response. Drop only those
-- replay caches; the invitation resources and audit trail remain untouched.
DELETE FROM api_idempotency_records
WHERE route = '/api/v1/admin/invitations' AND method = 'POST';

ALTER TABLE api_idempotency_records
    ADD CONSTRAINT api_idempotency_replay_resource_route_check CHECK (
        (
            route = '/api/v1/admin/invitations'
            AND method = 'POST'
            AND (
                (state = 'started' AND replay_resource_id IS NULL)
                OR (state = 'completed' AND replay_resource_id IS NOT NULL)
            )
        )
        OR (
            NOT (route = '/api/v1/admin/invitations' AND method = 'POST')
            AND replay_resource_id IS NULL
        )
    );

CREATE INDEX api_idempotency_replay_resource_idx
    ON api_idempotency_records (replay_resource_id)
    WHERE replay_resource_id IS NOT NULL;
