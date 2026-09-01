-- RFC 7622 push service identity migration handshake.
--
-- The exact transformation is implemented in Rust because PostgreSQL case
-- folding cannot reproduce PRECIS/IDNA.  `db::push_identity` treats
-- push_subscriptions and push_delivery_attempts as one FK graph, rejects
-- canonical parent-key collisions before writing, and records its completion
-- marker in the same transaction as every staged parent/child rewrite.

DO $$
BEGIN
    IF to_regclass('jid_identity_migrations') IS NULL THEN
        RAISE EXCEPTION '0066 requires jid_identity_migrations from migration 0063';
    END IF;
END
$$;
