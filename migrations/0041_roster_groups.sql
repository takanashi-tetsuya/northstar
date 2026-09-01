-- Roster items have stored RFC 6121 group names since the initial schema,
-- but the XEP-0237 delta journal must retain them as well or an incremental
-- roster sync silently loses user organization.
ALTER TABLE roster_change_log
    ADD COLUMN groups JSONB NOT NULL DEFAULT '[]'::jsonb
        CHECK (jsonb_typeof(groups) = 'array');

ALTER TABLE roster_items
    ADD COLUMN approved BOOLEAN NOT NULL DEFAULT FALSE;

ALTER TABLE roster_change_log
    ADD COLUMN approved BOOLEAN NOT NULL DEFAULT FALSE;
