# Deployment-wide capacity authority

Northstar treats PostgreSQL, not one Rust process, as the authority for account,
MUC-room, live-binding and XEP-0198 state ceilings. Migration
`0090_deployment_capacity_ledger.sql` installs four independent ledgers and the
foreign-key/trigger boundaries that cover ordinary APIs, XMPP registration,
federated room creation, administrator operations, direct row-level
`INSERT`/`UPDATE`/`DELETE` maintenance and cascading deletion.

## Configuration and rollout

The capacity snapshot consists of:

- `DEPLOYMENT_CAPACITY_EPOCH`
- `MAX_ACCOUNTS_TOTAL`
- `MAX_MUC_ROOMS_TOTAL`
- `MAX_MUC_ROOMS_PER_OWNER`
- `MAX_LIVE_SESSIONS_TOTAL`
- `MAX_SESSIONS_PER_ACCOUNT`
- `SM_MAX_RESUMABLE_SESSIONS`

Every node must present byte-for-byte equivalent numeric values at one epoch.
The first post-migration start replaces bootstrap epoch zero. A later change
must advance the PostgreSQL epoch by exactly one. An older epoch, a skipped
epoch, or different values at the current epoch fails startup before bootstrap
account creation or listener activation. This makes the database snapshot the
authority rather than allowing each node's `.env` to make an independent
admission decision.

Reconciliation takes an advisory deployment gate plus short table locks. It
removes expired live leases, checks authoritative object and per-account usage,
preserves every existing allocation-to-shard mapping, removes only stale
mappings and backfills only missing mappings. Lowering a limit below total,
per-account or per-shard committed usage fails closed. It never deletes an
account, room or non-expired session to make a new policy fit.

## Contention model

Each global ledger has 64 fixed counter rows. Capacity is divided with
`base + remainder`, so the 64 hard budgets sum to the configured ceiling
exactly. A new UUID starts at a stable shard derived from its RFC 4122 bytes and
probes the ring in deterministic order. A full shard's conditional update does
not retain a row lock; the first successful update stops the probe. Runtime
admission neither scans an authoritative table nor computes `COUNT(*)`/`SUM()`.

The allocation row records the chosen shard permanently. Startup does not
re-hash it, including after a PostgreSQL major upgrade. Per-owner room and
per-account session rows serialize only work for that account. Create and
delete triggers use the same global-then-owner lock order; room ownership
transfer locks the two UUIDs in sorted order.

Bulk deletion and other multi-resource maintenance paths predeclare their
allocation set and acquire PostgreSQL row locks in the single canonical order
`(resource_kind, shard, entity_id)`. The helper bounds both batch size and
defensive deadlock retries; account deletion invokes it before cascades release
room, live-session, and resumable-session allocations. Retry is therefore a
last-resort guard, not a substitute for one global lock order.

## Transaction and crash invariants

- `users` and `muc_rooms` acquire capacity in an `AFTER INSERT` trigger. An
  exhausted trigger aborts the object insert; `ON CONFLICT DO NOTHING` does not
  create a phantom reservation. A room's live allocation is released in the
  same transaction as its first `destroyed_at` transition. A later physical
  tombstone-retention delete releases only when an allocation is still present,
  preventing a double decrement; a live row with a missing allocation still
  fails closed. Startup/backfill and per-owner counters count only live room
  incarnations. Recreating a destroyed localpart inserts a fresh room UUID and
  therefore reserves capacity again. Missing allocations and counter underflow
  are errors, not silently repaired on a hot path.
- A C2S bind inserts one `deployment_session_leases` row inside the same
  authorization transaction that publishes the route. The stable `lease_id`
  owns the shard; `connection_id` is unique but can change on XEP-0198 resume
  without moving or double-counting the allocation.
- The critical supervised heartbeat refreshes only committed/routable local
  sessions. Three missed heartbeat intervals expire the default lease. A
  database error stops the critical worker and therefore the service; an exact
  local route whose row has expired is disconnected fail closed.
- Expiry alone does not decrement a counter. Bounded `SKIP LOCKED` maintenance
  deletes the authoritative lease; its trigger releases the shard exactly
  once. Clean Drop is an optimization and repeated release is harmless because
  the second delete finds no authoritative lease row.
- SM suspension extends the same live lease in the snapshot transaction.
  Resume verifies the exact SM claim and transfers the stable lease in the
  activation transaction. A missing lease is a fail-closed conflict, never a
  release/new-acquire fallback. Revocation, account deletion and expired-SM
  teardown delete the SM row; its trigger also removes the corresponding live lease.
- `sm_resume_sessions` has its own sharded ledger. Migration and startup count
  **all physically retained SM rows, including expired rows awaiting fenced
  teardown**, rather than pretending an expired-but-not-yet-deleted row is
  free. This is deliberately conservative. If historic expired rows exceed a
  desired limit, temporarily raise the limit with the next epoch, start the
  service so normal teardown can drain them, then lower it in another epoch.

PostgreSQL superuser operations can deliberately bypass this boundary:
`TRUNCATE`, disabling triggers, restoring only a subset of related tables, or
setting `session_replication_role=replica` is not an online maintenance API.
Perform such work only while every Northstar node is stopped, restore the
authoritative object and ledger tables as one backup unit, and run startup
reconciliation before reopening listeners.

## Observability and evidence level

The private metrics listener exports the PostgreSQL authority epoch, both
per-owner limits, used/limit gauges for all four ledgers, plus
`xmpp_capacity_reservations_rejected_total` and
`xmpp_capacity_session_lease_losses_total`. Alert before a ledger approaches
its limit and investigate any lease loss.

Pure unit tests cover exact 64-shard budget distribution, authority epoch
transitions and error classification. An ignored isolated-PostgreSQL fixture
covers global account rejection, account/room triggers, per-account rejection,
stable lease transfer, expiry, zero-counter cleanup and duplicate release. It is
an explicit release gate and counts as evidence only when its result, exact
artifact and isolated environment are recorded. The fixture's presence does not
claim that it or a multi-node crash test has run. A rolling upgrade from a binary that
does not write live-session leases must drain old C2S connections before the
new quota is treated as complete cluster evidence.
