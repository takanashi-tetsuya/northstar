ALTER TABLE pep_nodes
    DROP CONSTRAINT IF EXISTS pep_nodes_access_model_check;

ALTER TABLE pep_nodes
    ADD CONSTRAINT pep_nodes_access_model_check
    CHECK (access_model IN ('open', 'presence', 'whitelist'));

ALTER TABLE pep_nodes
    ADD COLUMN persist_items BOOLEAN NOT NULL DEFAULT TRUE,
    ADD COLUMN send_last_published_item VARCHAR(32) NOT NULL DEFAULT 'on_sub'
        CHECK (send_last_published_item IN ('never', 'on_sub', 'on_sub_and_presence'));
