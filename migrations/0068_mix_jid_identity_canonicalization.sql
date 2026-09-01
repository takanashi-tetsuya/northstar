-- RFC 7622 MIX identity-graph migration handshake.
--
-- Exact PRECIS/IDNA processing is performed by `db::mix_identity`.  The Rust
-- migration locks and validates the complete live MIX authorization graph,
-- rejects every canonical collision before writing, rewrites it atomically,
-- validates its participant FK again, and records a completion marker in the
-- same transaction.  Historical event publishers, audit attribution and XML
-- payloads are deliberately outside this migration.

DO $$
BEGIN
    IF to_regclass('jid_identity_migrations') IS NULL THEN
        RAISE EXCEPTION '0068 requires jid_identity_migrations from migration 0063';
    END IF;
END
$$;
