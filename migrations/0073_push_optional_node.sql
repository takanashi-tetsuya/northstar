-- XEP-0357 defines the Push Service JID as mandatory but the PubSub node as
-- optional.  An empty stored value is Northstar's internal sentinel for an
-- omitted XML attribute; protocol parsing still rejects an explicitly empty
-- `node=''`, and notification serialization omits the attribute entirely.
ALTER TABLE push_subscriptions
    DROP CONSTRAINT IF EXISTS push_subscriptions_nonempty_node;
