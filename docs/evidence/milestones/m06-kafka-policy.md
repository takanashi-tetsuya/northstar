# M06-06 Kafka policy evidence

Status: **catalog and generator implemented; broker enforcement pending**.

`catalog/topics.yaml` declares eight bounded event topics with explicit
ordering keys, producers, consumers, retention, RF/min-ISR, and message-size
limits. `kafka-policy-generator` rejects wildcard ACLs, RF/min-ISR below the
production floor, unbounded partitions/messages/retention, unsupported key
strategies, and payload-in-header attempts, then renders deterministic JSON.

The CI quality job executes this generator together with `db-bootstrap` and
`restore-verifier`, so policy artifacts are checked on every change.

The remaining evidence is broker-backed: ACL negative tests, hot-key/shard
benchmarking, regional quorum/replication drills, and applying the rendered
policy to Kafka. No broker or cross-region claim is made by the catalog alone.
