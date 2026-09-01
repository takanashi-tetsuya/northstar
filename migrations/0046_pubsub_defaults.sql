-- XEP-0060 `last-published` describes the service default as sending the
-- cached item both to a new subscriber and when an existing subscriber sends
-- available presence.  Preserve explicitly configured existing nodes while
-- making all newly-created generic PubSub nodes match the advertised feature.
ALTER TABLE pubsub_nodes
    ALTER COLUMN send_last_published_item SET DEFAULT 'on_sub_and_presence';
