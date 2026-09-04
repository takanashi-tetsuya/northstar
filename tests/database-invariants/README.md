# Database invariant test suite

The integration harness runs the `foundation-db-test` invariants against an
isolated PostgreSQL database. Each service supplies its own migration/schema
fixture; tests never connect to the shared development database.

Required scenarios:

- concurrent inserts prove unique authority keys and internal-only foreign
  keys;
- lease/session CAS rejects stale epochs and sequences never regress;
- injected serialization failures/deadlocks are retried only before a visible
  side effect commits;
- migration checksum drift, missing indexes, long transactions, and query-plan
  regressions fail the job;
- 100–1000 concurrent bind, ingress, and outbox-claim operations leave one
  authoritative result per idempotency key.

The current crate contains deterministic unit models. Live PostgreSQL,
property-load, and EXPLAIN artifact jobs remain required evidence for M05-04.
