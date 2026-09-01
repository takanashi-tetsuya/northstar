-- RFC 7622 JID identity migration handshake.
--
-- PostgreSQL cannot reproduce the PRECIS and IDNA processing implemented by
-- `crate::jid`, so the SQL migration deliberately does not approximate it
-- with LOWER().  `db::jid_identity::canonicalize_identity_storage` locks and
-- scans the identity-bearing PubSub/PEP tables, rejects canonical collisions,
-- applies only unambiguous rewrites in one transaction, and records completion
-- here.  An empty table means that the exact Rust migration has not completed.

CREATE TABLE jid_identity_migrations (
    migration TEXT PRIMARY KEY,
    canonicalizer_version INTEGER NOT NULL CHECK (canonicalizer_version > 0),
    transformed_rows BIGINT NOT NULL CHECK (transformed_rows >= 0),
    completed_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
);
