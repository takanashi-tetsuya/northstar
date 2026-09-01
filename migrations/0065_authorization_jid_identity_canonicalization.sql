-- RFC 7622 authorization-key identity migration handshake.
--
-- PostgreSQL LOWER() cannot implement the PRECIS and IDNA processing used by
-- XMPP and would corrupt case-sensitive resourceparts.  After sqlx records
-- this schema migration, `db::authorization_identity` takes exclusive locks,
-- scans every affected key space, rejects all canonical collisions before the
-- first write, performs the exact Rust rewrites in one transaction, and only
-- then inserts the `authorization-keys-rfc7622-v1` completion marker into
-- `jid_identity_migrations`.  A missing marker therefore always means the
-- exact migration did not commit and must be retried on the next startup.

DO $$
BEGIN
    IF to_regclass('jid_identity_migrations') IS NULL THEN
        RAISE EXCEPTION '0065 requires jid_identity_migrations from migration 0063';
    END IF;
END
$$;
