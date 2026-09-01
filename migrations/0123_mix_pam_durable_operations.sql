-- Durable MIX-PAM federation operations and exact client IQ results.
--
-- The migration never assumes `public`. Its trigger resolves only pg_catalog
-- and pg_temp names, while unqualified table DDL follows the migration
-- connection's isolated deployment schema.

CREATE TABLE mix_pam_operations (
    operation_id UUID PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    channel_jid VARCHAR(3071) NOT NULL,
    remote_domain VARCHAR(1023) NOT NULL,
    operation VARCHAR(16) NOT NULL CHECK (operation IN ('join', 'leave')),
    remote_request_id VARCHAR(128) NOT NULL UNIQUE,
    client_request_id VARCHAR(1024) NOT NULL,
    requester_full_jid VARCHAR(3071) NOT NULL,
    request_digest BYTEA NOT NULL CHECK (octet_length(request_digest)=32),
    request_outbox_id UUID NOT NULL UNIQUE,
    -- A PAM join also updates subscriptions/nick. Preserve the previous
    -- joined projection so an authenticated remote error can roll back the
    -- attempted update instead of deleting a pre-existing membership.
    prior_joined BOOLEAN NOT NULL DEFAULT FALSE,
    prior_participant_id VARCHAR(1023),
    prior_nick VARCHAR(1023),
    prior_subscriptions TEXT[] NOT NULL DEFAULT ARRAY[]::TEXT[],
    state VARCHAR(24) NOT NULL DEFAULT 'pending'
        CHECK (state IN ('pending', 'terminal', 'reconciliation')),
    remote_response_digest BYTEA
        CHECK (remote_response_digest IS NULL OR octet_length(remote_response_digest)=32),
    response_xml TEXT
        CHECK (response_xml IS NULL OR octet_length(response_xml) BETWEEN 1 AND 2097152),
    delivery_attempt_count INTEGER NOT NULL DEFAULT 0
        CHECK (delivery_attempt_count BETWEEN 0 AND 20),
    next_delivery_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    lease_token UUID,
    lease_until TIMESTAMPTZ,
    delivered_at TIMESTAMPTZ,
    dead_lettered_at TIMESTAMPTZ,
    last_error TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    deadline_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    UNIQUE (user_id, requester_full_jid, client_request_id),
    CHECK (channel_jid=lower(channel_jid)
       AND position('@' IN channel_jid)>1
       AND position('/' IN channel_jid)=0),
    CHECK (remote_domain=lower(remote_domain)
       AND position('@' IN remote_domain)=0
       AND position('/' IN remote_domain)=0),
    CHECK (octet_length(client_request_id) BETWEEN 1 AND 1024),
    CHECK (
        (NOT prior_joined
            AND prior_participant_id IS NULL
            AND prior_nick IS NULL
            AND cardinality(prior_subscriptions)=0)
        OR
        (prior_joined
            AND operation='join'
            AND prior_participant_id IS NOT NULL
            AND octet_length(prior_participant_id) BETWEEN 1 AND 1023
            AND position('@' IN prior_participant_id)=0
            AND position('/' IN prior_participant_id)=0
            AND position('#' IN prior_participant_id)=0
            AND (prior_nick IS NULL OR octet_length(prior_nick) BETWEEN 1 AND 1023)
            AND cardinality(prior_subscriptions) BETWEEN 0 AND 4
            AND array_position(prior_subscriptions,NULL) IS NULL
            AND prior_subscriptions <@ ARRAY[
                'urn:xmpp:mix:nodes:messages',
                'urn:xmpp:mix:nodes:presence',
                'urn:xmpp:mix:nodes:participants',
                'urn:xmpp:mix:nodes:info'
            ]::TEXT[])
    ),
    CHECK (position('@' IN requester_full_jid)>1
       AND position('/' IN requester_full_jid)>position('@' IN requester_full_jid)),
    CHECK ((lease_token IS NULL)=(lease_until IS NULL)),
    CHECK (delivered_at IS NULL OR dead_lettered_at IS NULL),
    CHECK (
        lease_token IS NULL
        OR (
            response_xml IS NOT NULL
            AND delivered_at IS NULL
            AND dead_lettered_at IS NULL
            AND state IN ('terminal','reconciliation')
        )
    ),
    CHECK (deadline_at>created_at AND expires_at>deadline_at),
    CHECK (
        (state='pending' AND response_xml IS NULL AND remote_response_digest IS NULL)
        OR
        (state='reconciliation' AND response_xml IS NOT NULL
                                AND remote_response_digest IS NULL)
        OR
        (state='terminal' AND response_xml IS NOT NULL
                          AND remote_response_digest IS NOT NULL)
    )
);

CREATE INDEX mix_pam_operations_remote_result_idx
    ON mix_pam_operations(remote_request_id, remote_domain);
CREATE INDEX mix_pam_operations_pending_deadline_idx
    ON mix_pam_operations(deadline_at, operation_id)
    WHERE state='pending';
CREATE INDEX mix_pam_operations_delivery_due_idx
    ON mix_pam_operations(next_delivery_at, created_at, operation_id)
    WHERE response_xml IS NOT NULL
      AND delivered_at IS NULL
      AND dead_lettered_at IS NULL;
CREATE INDEX mix_pam_operations_expiry_idx
    ON mix_pam_operations(expires_at, operation_id);

CREATE OR REPLACE FUNCTION reject_mix_pam_operation_identity_update()
RETURNS TRIGGER
LANGUAGE plpgsql
SET search_path=pg_catalog,pg_temp
AS $$
BEGIN
    IF NEW.operation_id IS DISTINCT FROM OLD.operation_id
       OR NEW.user_id IS DISTINCT FROM OLD.user_id
       OR NEW.channel_jid IS DISTINCT FROM OLD.channel_jid
       OR NEW.remote_domain IS DISTINCT FROM OLD.remote_domain
       OR NEW.operation IS DISTINCT FROM OLD.operation
       OR NEW.remote_request_id IS DISTINCT FROM OLD.remote_request_id
       OR NEW.client_request_id IS DISTINCT FROM OLD.client_request_id
       OR NEW.requester_full_jid IS DISTINCT FROM OLD.requester_full_jid
       OR NEW.request_digest IS DISTINCT FROM OLD.request_digest
       OR NEW.request_outbox_id IS DISTINCT FROM OLD.request_outbox_id
       OR NEW.prior_joined IS DISTINCT FROM OLD.prior_joined
       OR NEW.prior_participant_id IS DISTINCT FROM OLD.prior_participant_id
       OR NEW.prior_nick IS DISTINCT FROM OLD.prior_nick
       OR NEW.prior_subscriptions IS DISTINCT FROM OLD.prior_subscriptions
       OR NEW.created_at IS DISTINCT FROM OLD.created_at
       OR NEW.deadline_at IS DISTINCT FROM OLD.deadline_at
       OR NEW.expires_at IS DISTINCT FROM OLD.expires_at THEN
        RAISE EXCEPTION 'MIX-PAM operation identity is immutable';
    END IF;
    IF OLD.response_xml IS NOT NULL THEN
        IF OLD.state='reconciliation'
           AND NEW.state='terminal'
           AND NEW.response_xml IS NOT DISTINCT FROM OLD.response_xml
           AND OLD.remote_response_digest IS NULL
           AND NEW.remote_response_digest IS NOT NULL THEN
            -- A late authenticated remote result resolves uncertain business
            -- state while preserving the already-journaled timeout IQ bytes.
            NULL;
        ELSIF NEW.response_xml IS DISTINCT FROM OLD.response_xml
           OR NEW.remote_response_digest IS DISTINCT FROM OLD.remote_response_digest
           OR NEW.state IS DISTINCT FROM OLD.state THEN
            RAISE EXCEPTION 'MIX-PAM terminal result is immutable';
        END IF;
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER trg_mix_pam_operations_immutable
BEFORE UPDATE ON mix_pam_operations
FOR EACH ROW EXECUTE FUNCTION reject_mix_pam_operation_identity_update();

COMMENT ON TABLE mix_pam_operations IS
    'Durable remote MIX-PAM request correlation, terminal result journal and exact full-JID delivery authority';
COMMENT ON COLUMN mix_pam_operations.request_outbox_id IS
    'Immutable identity of the S2S outbox admission. It is intentionally not a foreign key because successful delivery or an authenticated terminal response deletes the outbox row while this replay journal remains retained.';
