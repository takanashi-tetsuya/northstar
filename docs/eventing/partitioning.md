# Event topic and partition policy

`catalog/topics.yaml` is the source of truth for event topics, producer and
consumer ACLs, retention, replication, and ordering keys. Run
`kafka-policy-generator` to render broker configuration; hand-edited ACLs are
not release evidence.

Ordering keys follow the aggregate that owns the semantic order: direct
messages use a recipient/conversation key, rooms use `room_id`, PubSub uses
`node_id`, and session/edge events use `full_jid`. Message bodies and private
JIDs never enter Kafka headers or metrics; the payload is the bounded event
envelope and sensitive fields remain protected by the eventing/key boundary.

Replication factor and partition count are deployment inputs. The catalog
requires RF >= 3 and min ISR >= 2 for production profiles, but the partition
count must be re-benchmarked for the target broker size. Each region owns a
Kafka quorum; cross-region replication is explicit and does not stretch one
quorum across WAN links. Hot-key alerts and a versioned shard-key migration
are required before changing an ordering key.
