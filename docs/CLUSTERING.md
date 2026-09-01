# Experimental same-domain clustering

Northstar's supported baseline remains one application process plus PostgreSQL.
Setting `REDIS_URL`/`REDIS_URL_FILE` opts into an **Experimental** same-domain
control plane. It is not a production scaling claim. Redis is ephemeral routing
transport; PostgreSQL is the durable and security authority.

No cluster signing configuration is required in single-node mode. Redis mode
fails startup unless every node has a stable, unique `CLUSTER_NODE_ID`, a
file-only Ed25519 signing key, and an explicit peer public-key/command ACL file.
TLS and Redis ACLs remain required deployment controls, but they are not treated
as application authentication.

## Security boundary

Every node command and acknowledgement is a signed protocol-v8 envelope. The
signature binds all of the following fields exactly:

- protocol version and canonical XMPP-domain namespace;
- source and destination node IDs and the exact Redis channel;
- command kind and the event/request ID;
- issue/expiry time (10-second lifetime, with at most five seconds of clock
  skew accepted at either edge);
- SHA-256 digest of the canonical JSON payload;
- source and destination signing-key IDs/epochs;
- source and destination random process-instance UUIDs with independent
  monotonic instance epochs.

The receiver rejects an unknown node, unauthorized command kind, wrong channel,
wrong destination/source, malformed ID, payload/kind mismatch, invalid time
window, bad signature, replay, retired key, or stale process instance. Replays
are first admitted to the PostgreSQL source+destination process/key fence and
expire through bounded database-clock cleanup. The secondary in-process cache
is capacity bounded and fails closed rather than evicting live evidence.

The peer JSON is an allowlist and least-privilege ACL. It accepts at most 128
peers and requires a non-empty, bounded `allowed_kinds` set for each peer. See
`deploy/cluster-peers.example.json`; its placeholder public key must never be
used. A private key is never accepted inline and is never stored in PostgreSQL.
Generate a new pair into non-existing files with:

```text
node scripts/generate-cluster-signing-key.mjs \
  /run/secrets/node-a.pkcs8.b64 \
  /run/secrets/node-a.public.b64
```

The generator prints only the derived key ID and public-key fingerprint. Both
outputs are created owner-only because Northstar applies the protected-file
loader to rotation public-key files as well as private material.

## PostgreSQL authority and process fencing

Migration 0088 stores only public, non-secret authority:

- current, previous and staged-next key IDs/fingerprints with an append-only
  deployment history;
- one `(domain, node_id)` process-instance row with UUID, monotonic instance
  epoch, the exact signing key ID/epoch, database-clock lease and append-only
  claim/release ownership history. Routine heartbeats update only the current
  lease row so the append-only audit cannot grow without bound.

Claim is serialized with the key-authority transition. It succeeds only for the
database's current signing key. A live duplicate node ID fails startup. An
expired or cleanly released owner can be replaced and increments the instance
epoch. Heartbeat and release require the exact UUID, instance epoch, key ID and
key epoch. Clean shutdown first blocks new signed publication, drains admitted
publication, and then expires the database lease immediately. If publication
cannot drain within 15 seconds, the process deliberately leaves the lease to
expire rather than releasing a fence while an old command may still publish.

Receivers refresh all peer authorities in bounded batches. PostgreSQL returns
remaining lease lifetime using `clock_timestamp()`; the receiving process turns
that duration into a monotonic `Instant` deadline with a one-second safety
margin. Database and host wall clocks are never compared for the lease. Both
key and instance caches have a ten-second refresh ceiling; unknown, expired or
missing entries fail closed and never perform one PostgreSQL query per command.

A copied UUID/instance epoch is insufficient: the envelope key generation must
also equal the signing key bound to that authoritative instance row. This
prevents holders of previous or staged private keys from copying an observable
instance tuple and issuing valid commands.

## Signing-key rotation

Rotation is a deliberate `prepare -> activate -> retire` protocol. Epochs can
advance by exactly one; skipped and reverse generations fail startup.

1. **Prepare.** Generate the next pair. Keep the old private key as the signer.
   Add the next raw public key as `staged_next` to the owning node and to every
   peer allowlist, then restart/reconcile all nodes. PostgreSQL records the
   staged fingerprint without changing current authority. A staged key is not
   accepted for wire commands, even if its holder copies the live instance
   tuple.
2. **Activate.** Quiesce and stop the owning node. Configure the new private key,
   increment `CLUSTER_SIGNING_KEY_EPOCH` by one, configure the old public key as
   `previous`, and clear local staged-next. On startup PostgreSQL atomically
   promotes staged-next to current and current to previous; the process then
   claims a new key-bound instance lease. Peers may still have the prepared
   public-key layout, but final wire authorization comes from PostgreSQL current
   or previous state, not the static staged label.
3. **Roll peer configuration.** Update every peer allowlist to name the new
   current generation and old previous key. Confirm all nodes remain ready and
   authentication/replay rejection counters are stable.
4. **Retire.** After the activation/grace interval, remove previous from peer and
   owner configuration. Retirement is allowed only after the new current key
   owns a live fenced instance and the activation authority is at least 20
   seconds old. Startup defers retirement until after it claims that instance,
   so a duplicate-node claim failure cannot strand the still-running old node.

Do not delete or edit authority/history rows manually. Lost-key disaster
recovery is an explicit out-of-band operation and is not automated by Northstar.

## Failure-policy state machine

`CLUSTER_FAILURE_POLICY` is required to be one of the following values:

| State/policy | New bind/resume | MUC join or mutation | Admin mutation/control | `no-store`/transient | Storage-eligible direct message | Readiness | Shutdown |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `healthy` | allow | allow | allow | allow | normal live/durable path | ready | no |
| `fail_closed` after Redis/control failure | reject | reject | reject | reject | reject | 503 | after safety lease |
| `durable_direct_only` after Redis/control failure | reject | reject | reject | reject | accept only as bounded PostgreSQL recipient spool; no Redis live acceptance | 503 | wait indefinitely while PostgreSQL authority is healthy |
| PostgreSQL key/instance authority unavailable | reject | reject | reject | reject | reject | 503 | immediate supervised fail-fast for either policy |
| `reconciling` / safety lease expired | reject | reject | reject | reject | reject | 503 | expired fail-closed lease requests shutdown |

`CLUSTER_SAFETY_LEASE_SECONDS` is 90..3600 (default 120). It bounds only the
`fail_closed` Redis/control-plane outage. `durable_direct_only` can remain in
its restricted PostgreSQL-spool mode while PostgreSQL fencing stays healthy.
It does not silently re-enable a live route when Redis merely reconnects.

Recovery becomes healthy only after this ordered reconciliation succeeds:

1. refresh peer signing-key and process-instance authority from PostgreSQL;
2. reacquire the local Redis node lease;
3. refresh every full-JID owner and immutable connection lease, disconnecting a
   local socket that lost ownership;
4. refresh every local MUC occupant/epoch, removing and disconnecting a stale
   occupant;
5. observe a new subscribed Pub/Sub listener generation;
6. atomically clear degradation and report ready.

## Reliability classes

| Class | Failure behavior |
| --- | --- |
| Storage-eligible local-account `normal`/`chat` | PostgreSQL recipient spool exists before cluster routing. Protocol v8 names and verifies its exact row/payload fence. In `durable_direct_only`, the row remains for replay and no live Redis acceptance is claimed |
| Explicit `no-store` and signal-only direct messages | Ephemeral only; rejected while degraded rather than being silently stored |
| MUC, ordinary presence, Carbons, roster/presence controls | Ephemeral cross-node transport; mutation/join is rejected while degraded and individual pre-failure notifications can remain ambiguous |
| PubSub/PEP mutation events | PostgreSQL event outbox remains authoritative; Redis is only a live same-domain attempt |
| S2S and external components | Separate bounded PostgreSQL outboxes; not made durable by Redis |

Post-write/pre-ACK process death is still an at-least-once ambiguity. Stable
XEP-0359/event IDs allow downstream deduplication, but no distributed
transaction spans Redis, a TCP socket and PostgreSQL.

## PostgreSQL-authoritative MUC control plane (CLU-MUC)

The second delivery-fencing revision adds `0094_cluster_muc_delivery_receipts.sql`.
Multi-stanza audience rows have stable ordinal identities; an ordinal advances
only after XEP-0198/BOSH/suspended storage owns it or a non-SM/federation
socket write completes. Merely entering the bounded process channel never
ACKs the PostgreSQL outbox. SM resume transfers the unfinished exact-occupant
audience and completed ordinal progress under the occupancy transaction to the
new node, while the room-plus-recipient sequence gate prevents a later event
for that same recipient passing it without freezing unrelated occupants.

Voice approval and subject changes use the same exact actor/target authority
as role/kick/config changes. Subject state, optional archive row, immutable
authorization/audience snapshot and outbox commit atomically. Temporary-room
deletion expires due leases and proves no active/suspended occupancy under the
room lock before tombstoning. Policy snapshots omit arbitrary presence XML.

Admin IQs support an atomic multi-affiliation batch or one exact role/kick.
Mixed affiliation+role and multi-role shapes are rejected before any write.

The handoff projection is versioned rather than rewriting the original
operation audience: PostgreSQL first proves the replacement occupancy tuple is
the current leased owner, appends an immutable version to
`cluster_muc_delivery_handoffs`, and then retargets only matching unfinished
rows. Ordering is scoped to the same room plus occupant incarnation (or the
same node-pull consumer), so a dead unrelated recipient cannot freeze the whole
room.

Signed protocol replay admission is persisted by migration 0095. Its unique
identity binds source process/key, destination process/key, channel, event ID
and payload digest. Receiver restart therefore does not reopen the wire
validity window; expired rows are removed in bounded database-clock batches.

BOSH receipts remain attached to the cached RID until client ACK. While
waiting, the worker renews its exact PostgreSQL claim every ten seconds; cache
capacity is checked before bytes are exposed, so an entry carrying ownership is
never silently evicted. Termination closes the receipt and causes a stable-ID
retry rather than completion.
Completion and renewal revalidate the immutable delivery ID, handoff version,
claim token, unexpired database-clock lease, room/recipient incarnation, owner
node and connection tuple in one SQL statement. Thus a late receipt from the
old node cannot complete or renew a delivery after SM handoff clears its claim.
BOSH also imposes hard per-session unacknowledged response-count, byte and
five-minute age limits; exceeding one terminates the session and releases its
recoverable fences instead of renewing ownership forever.

The handoff trigger does not trust a caller-set PostgreSQL GUC. It accepts a
route change only when the latest immutable handoff history maps the exact old
tuple to the exact new tuple and that destination is still an active leased
occupancy. Migration 0094 revokes public table/function access and installs the
controlled handoff/trigger functions with a fixed `search_path`. Production
deployments should use separate migration-owner and runtime roles, granting the
runtime role only `EXECUTE` on the handoff function and the minimum `SELECT`
needed by delivery readers; it must not receive `INSERT`, `UPDATE`, or `DELETE`
on the handoff history table.

Migration 0089 makes PostgreSQL the authority for clustered room management.
Redis may wake a worker and may hold disposable roster/presence acceleration,
but a Redis value is never sufficient authorization to join, rename, resume,
configure, change an affiliation or role, kick, destroy, expire, or revive a
room. Protocol-v8 listeners reject the legacy executable Redis MUC controls.

Each room has an immutable `room_epoch`, a monotonic `config_version` and a
destruction fence for that incarnation. A destroyed localpart can be created
again immediately, but only as a fresh room UUID/`room_epoch`; the old row is
never updated back to live state. A live MIX mirror is detached atomically at
destruction so it cannot pin the old incarnation or block a fresh same-address
link. Each membership incarnation has an immutable
`occupant_incarnation` plus monotonic `occupancy_epoch`; its exact full JID,
nickname, connection UUID/epoch, owning node and PostgreSQL-clock lease are
checked under the room lock. A rename changes the nickname in place only in
that exact operation, preserving the incarnation and occupancy epoch. A later
user of the old nickname therefore cannot satisfy a delayed kick or policy
operation. Terminal occupancy rows cannot be revived.

The join transaction checks the room epoch/config version, lock owner, ban or
membership rule, reserved nickname, live nickname/full-JID uniqueness and
maximum occupancy before inserting one incarnation. Resume/suspend/leave and
lease expiry use the same exact tuple and database clock. A remote occupant is
accepted only when its bare-JID domain equals the authenticated S2S domain;
uncertain remote ownership fails closed. SM suspension preserves the stable
incarnation for its bounded lease. Account deletion revokes every exact local
incarnation in the account-deletion transaction before the user row is erased.

Configuration, affiliation/ban, role, kick and destruction operations carry a
caller-generated operation UUID. The transaction re-reads the exact active
actor occupancy and durable affiliation, applies the requested revision once,
records the actor authorization snapshot, exact target tuple/result and an
immutable audience snapshot, then inserts the notification outbox before
commit. Configuration status 104 and all affected occupant presences are
rendered from that one committed revision. A destroyed-room cache cannot clear
the tombstone or reuse its room epoch.

XEP-0045 self registration and unregistration use the same authority path:
the room/configuration epoch, `allow_registration`, cross-local/federated nick
reservation and every exact live occupancy are checked under the room lock,
then the affiliation/reserved nick and immutable notification audience commit
together. A members-only mediated invitation likewise grants `member` in the
same transaction as its local offline row or federated S2S outbox row. Its
authorization snapshot binds the inviter's exact occupancy; a local direct
invitation may instead use the authenticated account's durable member/admin/
owner affiliation, while remote direct authority without an exact S2S-owned
occupancy fails closed. Replays retain the original operation/event UUID and
cannot grant membership twice or rebuild the audience.

The caller operation UUID is also the XEP-0359 event UUID and is allocated once.
The per-room event sequence is monotonic. Outbox
retries keep the same event ID and process one room in sequence for each target
node. Claims use tokens, PostgreSQL-clock leases, bounded exponential retry,
seven-day TTL and bounded 30-day dead letters. Global shards and per-room
counters fail closed on missing rows or underflow. An immutable audience row is
not recomputed after later joins/leaves; after a crash, the worker reconstructs
only the exact live, SM-suspended or authenticated federated delivery endpoint
and never restores membership from Redis. Duplicate socket delivery remains
possible, but it repeats the same stable event ID. The audience projection is
bounded to 16 MiB and contains only delivery identity/route/role facts: it
excludes stanza bodies, message content, presence payloads, room passwords and
signing material. Authorization evidence is separately bounded to 1 MiB. If an
operation, audience or outbox limit cannot be reserved, the whole PostgreSQL
mutation transaction rolls back before any state becomes visible.

Completed operation rows and destroyed-room tombstones have a 90-day online
recovery/idempotency horizon. The supervised worker uses the bounded,
database-clock cleanup function; it skips any operation with an outbox or
dead-letter projection and any room covered by an active legal hold. A room
tombstone is physically removed only after terminal occupancies and operation
history are removed in the same cleanup transaction. This does not weaken an
old-node fence: signed commands also require a current process-instance lease,
and a same-localpart replacement has unrelated room UUID/epoch values.

Recovery order is: refresh signing-key and process-instance authority; validate
the local instance lease; load unexpired MUC occupancies owned by this node from
PostgreSQL; remove/disconnect any local cache actor which does not match its
exact tuple; repopulate disposable Redis roster state; start the subscribed
listener generation; then drain the PostgreSQL MUC outbox. A signed Redis wake
contains only an operation/event locator. Every consequence is pulled back from
PostgreSQL and digest checked.

Ordinary groupchat content remains the pre-existing PostgreSQL archive plus
best-effort Redis real-time fan-out; this CLU-MUC slice does not claim a durable
per-recipient queue for ordinary room messages. Ordinary presence and typing
are explicitly bounded soft state. During either degraded failure policy, new
MUC joins and management mutations fail closed until full reconciliation.
Legal hold governs retained message/audit data through the data-lifecycle
service; it does not convert ephemeral presence into evidence or permit mutation
of CLU-MUC operation history outside its hold-aware bounded cleanup gate.

## Observability and operations

`/readyz` validates PostgreSQL, key authority and cluster state. Prometheus
exports:

- `xmpp_cluster_operational_state` (`0` disabled, `1` reconciling, `2` healthy,
  `3` fail-closed, `4` durable-direct-only, `5` shutdown-required);
- `xmpp_cluster_listener_generation`;
- `xmpp_cluster_authentication_failures_total`;
- `xmpp_cluster_replay_rejections_total`;
- `xmpp_cluster_degraded_transitions_total`.

CLU-MUC additionally exports:

- `xmpp_cluster_muc_outbox_deliveries_total` and
  `xmpp_cluster_muc_outbox_retries_total`;
- `xmpp_cluster_muc_outbox_queued`,
  `xmpp_cluster_muc_outbox_oldest_age_seconds` and
  `xmpp_cluster_muc_outbox_dead_letters`;
- `xmpp_cluster_muc_pg_reconciliations_total` and
  `xmpp_cluster_muc_authority_rejections_total`.

Alert immediately on a state above 2, any sustained authentication/replay
rejection increase, or a listener generation which stops advancing through a
documented recovery. Do not make a degraded node ready at the load balancer.

## Evidence and remaining limits

Pure unit/static models cover policy classes; wrong version/source/node/channel;
expired, malformed, tampered and replayed envelopes; one-generation key
overlap; staged/previous tuple-copy rejection; duplicate instance ownership;
lease takeover; and recovery ordering. PostgreSQL/Redis runtime fixtures are
kept ignored for later disposable-environment execution in this audit phase.

The cluster remains Experimental because there is no consensus protocol. A
simultaneous Redis/PostgreSQL partition fails closed, but an already-published
command can remain ambiguous until its short envelope/cache windows close.
Managed-Redis failover, arbitrary asymmetric partitions, real rolling binaries,
schema expand/contract, the implemented shared upload store on the chosen
provider, and representative capacity still need operator validation. The
upload state machine and its unexecuted two-node/provider release gates are
documented in [UPLOAD_STORAGE.md](UPLOAD_STORAGE.md). The bounded authority cache intentionally leaves at
most a short revocation delay; immediate revocation requires stopping consumers
or an authenticated invalidation mechanism outside this implementation.
