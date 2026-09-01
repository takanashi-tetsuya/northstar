-- RFC 6121 section 3.1.3 requires an offline subscription request to retain
-- and redeliver the complete original presence stanza, including extensions.
-- NULL remains accepted only for rows created by older Northstar versions;
-- all new local writes persist a bounded, server-stamped stanza.

ALTER TABLE pending_presence_subscriptions
    ADD COLUMN stanza TEXT,
    ADD CONSTRAINT pending_presence_stanza_size
        CHECK (stanza IS NULL OR octet_length(stanza) BETWEEN 1 AND 65536);

ALTER TABLE federated_presence_pending
    ADD COLUMN stanza TEXT,
    ADD CONSTRAINT federated_presence_stanza_size
        CHECK (stanza IS NULL OR octet_length(stanza) BETWEEN 1 AND 65536);
