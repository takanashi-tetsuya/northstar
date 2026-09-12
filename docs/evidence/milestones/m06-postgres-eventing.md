# M06-02 PostgreSQL eventing evidence

Status: **transactional adapter implemented; live migration/Kafka evidence pending**.

`foundation-eventing-postgres` implements append, claim-lease, owner-fenced
publish acknowledgement, inbox single-winner claim, and inbox completion. All
operations accept the caller-owned `&mut Transaction<Postgres>` and never open
or commit a second transaction. Payloads, field sizes, claim limits, and lease
owners are bounded before SQL execution. `MIGRATION_SQL` is a migrator-only
artifact and is not executed by runtime code.

The adapter guarantees at-least-once transport with idempotent visible side
effects; it does not claim exactly-once delivery. A real service migration,
PostgreSQL concurrent claim test, Kafka producer/consumer, DLQ, and
reconciliation job remain M06-03 through M06-06 acceptance work.
