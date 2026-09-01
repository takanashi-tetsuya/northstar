-- Exact RFC 7622 migration handshake for durable session authorization keys.
--
-- `db::session_identity` receives the configured XMPP domain from startup,
-- proves every SM/admin owner against users, validates MUC destroy intents
-- against their immutable operation payloads, rejects canonical collisions,
-- and commits exact Rust rewrites plus its domain-scoped marker atomically.

DO $$
BEGIN
    IF to_regclass('jid_identity_migrations') IS NULL THEN
        RAISE EXCEPTION '0069 requires jid_identity_migrations from migration 0063';
    END IF;
END
$$;
