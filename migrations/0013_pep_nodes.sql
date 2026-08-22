CREATE TABLE pep_nodes (
    owner_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    node TEXT NOT NULL,
    access_model VARCHAR(16) NOT NULL,
    max_items INTEGER NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (owner_id, node),
    CONSTRAINT pep_nodes_access_model_check
        CHECK (access_model IN ('open', 'presence')),
    CONSTRAINT pep_nodes_max_items_check
        CHECK (max_items BETWEEN 1 AND 100)
);

INSERT INTO pep_nodes (owner_id, node, access_model, max_items)
SELECT DISTINCT
    owner_id,
    node,
    CASE
        WHEN node IN ('urn:xmpp:omemo:2:devices', 'urn:xmpp:omemo:2:bundles', 'eu.siacs.conversations.axolotl.devicelist')
            OR node LIKE 'eu.siacs.conversations.axolotl.bundles%'
            THEN 'open'
        ELSE 'presence'
    END,
    CASE
        WHEN node = 'urn:xmpp:omemo:2:devices' THEN 1
        WHEN node = 'eu.siacs.conversations.axolotl.devicelist' THEN 1
        WHEN node = 'urn:xmpp:omemo:2:bundles' THEN 100
        WHEN node LIKE 'eu.siacs.conversations.axolotl.bundles%' THEN 100
        ELSE 100
    END
FROM pep_items;

ALTER TABLE pep_items
    ADD CONSTRAINT pep_items_node_fk
    FOREIGN KEY (owner_id, node)
    REFERENCES pep_nodes(owner_id, node)
    ON DELETE CASCADE;
