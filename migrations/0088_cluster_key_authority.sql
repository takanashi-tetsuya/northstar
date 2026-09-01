-- Non-secret deployment authority for the experimental cluster bus. Private
-- Ed25519 material is never stored in PostgreSQL; only derived key IDs and
-- SHA-256 public-key fingerprints cross this boundary.
CREATE TABLE cluster_key_deployments (
    xmpp_domain TEXT NOT NULL,
    node_id TEXT NOT NULL
        CHECK (node_id ~ '^[A-Za-z0-9._-]{1,128}$'),
    epoch BIGINT NOT NULL CHECK (epoch >= 1),
    current_key_id TEXT NOT NULL
        CHECK (current_key_id ~ '^[A-Za-z0-9_-]{16}$'),
    current_public_key_sha256 TEXT NOT NULL
        CHECK (current_public_key_sha256 ~ '^[A-Za-z0-9_-]{43}$'),
    previous_key_id TEXT
        CHECK (previous_key_id IS NULL OR previous_key_id ~ '^[A-Za-z0-9_-]{16}$'),
    previous_public_key_sha256 TEXT
        CHECK (previous_public_key_sha256 IS NULL OR previous_public_key_sha256 ~ '^[A-Za-z0-9_-]{43}$'),
    staged_next_key_id TEXT
        CHECK (staged_next_key_id IS NULL OR staged_next_key_id ~ '^[A-Za-z0-9_-]{16}$'),
    staged_next_public_key_sha256 TEXT
        CHECK (staged_next_public_key_sha256 IS NULL OR staged_next_public_key_sha256 ~ '^[A-Za-z0-9_-]{43}$'),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (xmpp_domain, node_id),
    CHECK ((previous_key_id IS NULL) = (previous_public_key_sha256 IS NULL)),
    CHECK ((staged_next_key_id IS NULL) = (staged_next_public_key_sha256 IS NULL)),
    CHECK (previous_key_id IS NULL OR previous_key_id <> current_key_id),
    CHECK (previous_public_key_sha256 IS NULL OR previous_public_key_sha256 <> current_public_key_sha256),
    CHECK (staged_next_key_id IS NULL OR staged_next_key_id <> current_key_id),
    CHECK (staged_next_key_id IS NULL OR staged_next_key_id <> previous_key_id),
    CHECK (staged_next_public_key_sha256 IS NULL OR staged_next_public_key_sha256 <> current_public_key_sha256),
    CHECK (staged_next_public_key_sha256 IS NULL OR staged_next_public_key_sha256 <> previous_public_key_sha256)
);

COMMENT ON TABLE cluster_key_deployments IS
    'Per-node Ed25519 generation authority for the experimental Redis bus; fingerprints only, never private keys';

CREATE TABLE cluster_key_deployment_history (
    sequence BIGSERIAL PRIMARY KEY,
    xmpp_domain TEXT NOT NULL,
    node_id TEXT NOT NULL,
    epoch BIGINT NOT NULL CHECK (epoch >= 1),
    current_key_id TEXT NOT NULL,
    current_public_key_sha256 TEXT NOT NULL,
    previous_key_id TEXT,
    previous_public_key_sha256 TEXT,
    staged_next_key_id TEXT,
    staged_next_public_key_sha256 TEXT,
    authority_updated_at TIMESTAMPTZ NOT NULL,
    recorded_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    operation TEXT NOT NULL CHECK (operation IN ('insert', 'update'))
);

COMMENT ON TABLE cluster_key_deployment_history IS
    'Append-only non-secret audit trail for cluster signing-key generations';

CREATE OR REPLACE FUNCTION record_cluster_key_deployment_history()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    INSERT INTO cluster_key_deployment_history (
        xmpp_domain, node_id, epoch, current_key_id,
        current_public_key_sha256, previous_key_id,
        previous_public_key_sha256, staged_next_key_id,
        staged_next_public_key_sha256, authority_updated_at, operation
    ) VALUES (
        NEW.xmpp_domain, NEW.node_id, NEW.epoch, NEW.current_key_id,
        NEW.current_public_key_sha256, NEW.previous_key_id,
        NEW.previous_public_key_sha256, NEW.staged_next_key_id,
        NEW.staged_next_public_key_sha256, NEW.updated_at,
        CASE WHEN TG_OP = 'INSERT' THEN 'insert' ELSE 'update' END
    );
    RETURN NEW;
END;
$$;

CREATE TRIGGER cluster_key_deployment_history_record
AFTER INSERT OR UPDATE ON cluster_key_deployments
FOR EACH ROW EXECUTE FUNCTION record_cluster_key_deployment_history();

CREATE OR REPLACE FUNCTION reject_cluster_key_authority_mutation()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION
        'cluster key authority history is append-only; use documented out-of-band disaster recovery';
END;
$$;

CREATE TRIGGER cluster_key_deployment_delete_guard
BEFORE DELETE ON cluster_key_deployments
FOR EACH ROW EXECUTE FUNCTION reject_cluster_key_authority_mutation();

CREATE TRIGGER cluster_key_deployment_history_mutation_guard
BEFORE UPDATE OR DELETE ON cluster_key_deployment_history
FOR EACH ROW EXECUTE FUNCTION reject_cluster_key_authority_mutation();

CREATE INDEX cluster_key_deployment_history_node_sequence
    ON cluster_key_deployment_history (xmpp_domain, node_id, sequence DESC);

-- A signing key identifies an allowed node, not the one live process which
-- currently owns that node ID. This independent monotonic lease prevents a
-- stale or accidentally duplicated process with the same mounted key from
-- issuing otherwise valid signed commands.
CREATE TABLE cluster_node_instances (
    xmpp_domain TEXT NOT NULL,
    node_id TEXT NOT NULL,
    instance_uuid UUID NOT NULL,
    instance_epoch BIGINT NOT NULL CHECK (instance_epoch >= 1),
    signing_key_id TEXT NOT NULL
        CHECK (signing_key_id ~ '^[A-Za-z0-9_-]{16}$'),
    signing_key_epoch BIGINT NOT NULL CHECK (signing_key_epoch >= 1),
    lease_until TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (xmpp_domain, node_id),
    FOREIGN KEY (xmpp_domain, node_id)
        REFERENCES cluster_key_deployments (xmpp_domain, node_id)
        ON DELETE RESTRICT
);

COMMENT ON TABLE cluster_node_instances IS
    'Database-clock fenced unique live process for each signed cluster node identity';

CREATE TABLE cluster_node_instance_history (
    sequence BIGSERIAL PRIMARY KEY,
    xmpp_domain TEXT NOT NULL,
    node_id TEXT NOT NULL,
    instance_uuid UUID NOT NULL,
    instance_epoch BIGINT NOT NULL,
    signing_key_id TEXT NOT NULL,
    signing_key_epoch BIGINT NOT NULL,
    lease_until TIMESTAMPTZ NOT NULL,
    recorded_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    operation TEXT NOT NULL CHECK (operation IN ('claim', 'release'))
);

CREATE INDEX cluster_node_instance_history_node_sequence
    ON cluster_node_instance_history (xmpp_domain, node_id, sequence DESC);

CREATE OR REPLACE FUNCTION reject_cluster_node_instance_history_mutation()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION
        'cluster node instance history is append-only; use documented out-of-band disaster recovery';
END;
$$;

CREATE TRIGGER cluster_node_instance_history_mutation_guard
BEFORE UPDATE OR DELETE ON cluster_node_instance_history
FOR EACH ROW EXECUTE FUNCTION reject_cluster_node_instance_history_mutation();
