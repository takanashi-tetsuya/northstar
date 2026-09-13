# ADR-0004: PostgreSQL Outbox + Inbox Processing Model

## Context

The previous architecture mixed in-memory queues and ad-hoc maps with protocol handlers.
Without durable message intent persistence, failures and process restarts can cause lost, duplicated,
or partially acknowledged message effects.

## Decision

All message acceptance paths must follow this invariant:

- business state write and outbound outbox write must happen in one PostgreSQL transaction.
- consumer handlers that materialize side effects must also write inbox and side effects in one transaction.
- delivery and event transport are at-least-once.
- idempotency is enforced at the business-visible edge via identity tokens.

Kafka (or equivalent transport) is used for asynchronous fanout after durable persistence.

## Alternatives

- **Direct in-memory queue**: low latency initially, poor crash consistency.
- **Two-phase commit distributed**: stronger delivery illusion but heavy operational overhead and broader failure modes.

We choose local-transaction outbox/inbox with at-least-once semantics and idempotent handlers.

## Consequences

- Temporary duplication is tolerated but must be visibly idempotent.
- Reconciliation jobs are required for stuck/stale inflight messages.
- Consumers must expose structured errors and deterministic retry policy.

## Security / Privacy

- Outbox payloads include only required fields; large or sensitive content requires explicit policy gate.
- Inbox records include trace keys for audit and replay analysis without storing plaintext secrets.

## Migration

- Introduce outbox/inbox tables per authoritative unit first as "scaffold".
- Move handlers to durable path only after integration tests pass with intentional crash/restart injection.
- Keep in-memory implementation temporarily behind compatibility flag until strict mode.

## Status

Accepted.

