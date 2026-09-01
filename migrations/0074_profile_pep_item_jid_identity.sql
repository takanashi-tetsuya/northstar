-- RFC 7622 identity handshake for JID-keyed profile PEP items.
--
-- PostgreSQL LOWER() cannot reproduce PRECIS/IDNA.  The exact, fail-closed
-- transformation is implemented by `db::profile_identity`: it locks the PEP
-- item table, validates the complete contacts/bookmarks key set and payload
-- root IDs, rejects every canonical collision before writing, then rewrites
-- the primary key and XML root ID in one transaction.

DO $$
BEGIN
    IF to_regclass('jid_identity_migrations') IS NULL THEN
        RAISE EXCEPTION '0074 requires jid_identity_migrations from migration 0063';
    END IF;
END
$$;
