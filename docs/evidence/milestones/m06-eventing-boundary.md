# M06-01 eventing boundary evidence

Status: **contract boundary tightened; PostgreSQL/Kafka implementation pending**.

`foundation-eventing` now makes its in-memory repositories an explicit
`test-support` feature (and keeps them available to unit tests). The default
crate build does not pull a memory outbox/inbox into a production dependency;
service fixtures that still use the prototype explicitly opt in. This makes
the eventual PostgreSQL repository cutover visible in Cargo metadata instead
of silently retaining an in-process queue.

The existing `OutboxRepository` and `ConsumerInboxRepository` ports remain
storage-neutral. Their production implementation must accept the caller's
`&mut Transaction<Postgres>`, claim/complete inbox work in that same business
transaction, and expose at-least-once transport plus idempotent visible side
effects. No exactly-once guarantee is made.

Live PostgreSQL outbox/inbox tables, claim leases, Kafka producer/consumer,
DLQ/reconciliation, and concurrent single-winner evidence are M06-02 through
M06-06 work and are not claimed here.
