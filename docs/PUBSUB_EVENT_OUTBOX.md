# Durable PubSub and PEP event delivery

Northstar projects every immediate XEP-0060 and XEP-0163 notification into
PostgreSQL in the same transaction as the mutation which created the event.
The authoritative tables are introduced by migration `0085`:

- `pubsub_event_outbox` stores one immutable row per recipient;
- `pubsub_event_streams` assigns a monotonic sequence to each
  source/recipient stream;
- sharded and per-domain capacity tables fail the originating mutation closed
  before an unbounded queue can be accepted;
- `pubsub_event_dead_letters` retains terminal metadata and the SHA-256 payload
  digest, but deliberately does not retain another copy of the stanza body.

Each delivery row contains a stable event ID and delivery ID, exact payload
bytes plus their SHA-256 digest, canonical recipient and target domain, source
and delivery kind, event-time subscription options, expiry, and a monotonic
source-plus-recipient ordering key/sequence. The recipient component is a
SHA-256 scope, so an offline subscriber cannot head-of-line block every other
subscriber of the node. The worker verifies the payload binding before routing. Local
socket, cluster and federated S2S retries reuse the same stanza/event ID, so an
acknowledgement race may duplicate an ID but cannot silently create a different
event. XMPP still has at-least-once edges; clients should deduplicate stable
IDs where duplicate presentation matters.

## Commit and subscription ordering

The recipient and option snapshot is frozen while the request is evaluated,
then stored by the mutation transaction. That snapshot is the event's audience
and is never re-resolved by a retry worker. A later unsubscribe, affiliation
change, node delete, presence change, or capability change does not
retroactively cancel an already accepted event. Conversely, a later subscribe
does not receive earlier events except through the separately specified
last-item behavior. Optimistic snapshots whose exact generated identity or
compatibility projection can race (subscription SubIDs, affiliation-driven
transitions, legacy bookmark projection) are revalidated while the mutation is
locked; a changed snapshot aborts instead of committing mismatched event bytes.

This gives concurrent requests a clear order: event snapshot/acceptance first,
later subscription mutation second. It does not claim that PostgreSQL commit
timestamps form a user-visible total order across unrelated nodes.

## Worker and failure behavior

Workers claim bounded batches using `FOR UPDATE SKIP LOCKED`. Only the head of
a source/recipient ordering stream is eligible, and candidates are interleaved by target domain
to prevent a large domain from monopolizing a batch. Claims have fenced UUID
leases. An expired lease can be taken over by another process; an obsolete
worker cannot acknowledge it. Routing failures use bounded exponential backoff.
Expired rows and rows reaching the attempt limit move to dead-letter metadata.
Payload-binding failures are terminal immediately.

Digest subscriptions remain a distinct mechanism. The immediate outbox
atomically preserves the event first, then idempotently projects it into the
digest queue using the source delivery ID. The digest queue stores the
event-time `show_values` snapshot and does not re-resolve or cancel it after a
later unsubscribe. Existing legacy digest rows retain their compatibility
live-subscription check.

Redis is only a live-routing/wakeup optimization. Losing Redis cannot delete or
acknowledge a PostgreSQL event row.

## Capacity, retention and coalescing

The schema bounds each of 64 uniformly selected shards to 10,000 rows and
64 MiB. Per-domain accounting uses the same 64 shards with 781 rows each, for
a hard 49,984-row target-domain maximum without forcing every concurrent
publisher to wait on one domain-wide PostgreSQL row lock. A capacity error
rolls back the originating mutation. Event payloads are capped at 4 MiB and
default to a seven-day TTL. Dead-letter metadata is purged after 30 days.
Idle ordering-stream counters with no queued recipient are likewise removed
after 30 days, so churn through deleted node names cannot grow metadata forever.

No node is coalesced by default. A future coalescing policy must opt in a
specific node and preserve its XEP semantics. Node identifiers associated with
OMEMO device lists, bundles, prekeys or legacy Axolotl are classified as
security-sensitive in both application and database state; they cannot carry a
coalescing key.

## Operations

Alert on any dead letter or capacity rejection. A sustained pending row/byte
increase indicates downstream socket, cluster, federation, policy or database
health trouble. Relevant metrics are:

- `xmpp_pubsub_event_outbox_pending_rows`;
- `xmpp_pubsub_event_outbox_pending_bytes`;
- `xmpp_pubsub_event_outbox_dead_letter_rows`;
- `xmpp_pubsub_event_outbox_retries_total`;
- `xmpp_pubsub_event_outbox_dead_letters_total`;
- `xmpp_pubsub_event_outbox_lease_lost_total`;
- `xmpp_pubsub_event_outbox_capacity_rejections_total`.

The ignored isolated-PostgreSQL test and `scripts/pubsub-outbox-db-wsl.sh`
exercise commit, claim, payload binding, lease takeover, stale-token rejection
and exact acknowledgement. Runtime transport validation remains a release gate;
the implementation work which introduced this document intentionally ran only
static, unit and isolated database checks.
