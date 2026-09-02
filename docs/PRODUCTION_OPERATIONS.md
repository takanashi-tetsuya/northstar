# Northstar production operations

This runbook covers the single-node deployment target. It deliberately keeps
database credentials out of command-line arguments and treats PostgreSQL plus
the immutable upload store as one recoverable service state.

Read every verification statement at its evidence level:

- **Implemented** means the behavior exists in the current source and migration
  set.
- **Automated local evidence** means a repository test or isolated validation
  script exercises it; it is not a statement that every script passed against
  the final release artifact.
- **Manual client evidence** is recorded separately with its client, date and
  environment and must not be generalized to other releases.
- **Operator validation required** covers the real public DNS, certificates,
  CRLs, reverse proxy, hardware, network, backup destination and monitoring
  receiver. Repository fixtures cannot validate those deployment facts.

## Health model

- `/healthz` is a liveness probe. It answers while the HTTP process can serve.
- `/readyz` queries PostgreSQL and checks the supervised worker registry.
  Restartable workers are aborted and restarted when their heartbeat expires;
  a security-critical heartbeat expiry cancels the service instead of allowing
  established sessions to continue indefinitely with stale authority. A
  stopped, restarting or repeatedly failing worker makes the instance unready
  even when PostgreSQL still responds. It is an
  internal orchestration endpoint: the default Caddy route returns 404 for
  public `/readyz`. Internal duplicates share a two-second success/failure
  cache and one single-flight probe with a 200 ms queue wait and 1.5 second
  persistence deadline, so probe floods cannot each hold an application pool
  connection.
- `/metrics` is absent from the public `HTTP_BIND` router. It is served on
  `METRICS_BIND` (`127.0.0.1:9091` by default) and remains available when
  PostgreSQL is down. It exports
  `xmpp_database_up=0` and the measured database probe duration instead of
  failing the scrape.
- A non-loopback metrics listener requires a permission-checked
  `METRICS_BEARER_TOKEN_FILE`. Collection is single-flight, reuses a five-second
  cache and has a total database deadline. Compose mounts owner-specific,
  byte-identical copies of the same independent token into Northstar and
  Prometheus and scrapes `xmpp:9091`; Caddy still
  returns 404 for a public `/metrics` request as defense in depth.
- C2S, S2S, HTTP, and metrics listeners are separate tasks. If any listener exits, the
  process initiates shutdown rather than silently running a partial service.
- Every background-worker guardian and listener task is retained by the main
  process. Shutdown closes registration, cancels the shared token, and waits
  for both sets to finish within a bounded grace period; overdue tasks are
  aborted and reaped, and an incomplete drain is reported as a process error.
  Synchronous worker-factory panics, asynchronous attempt panics, and guardian
  failures are observable through readiness. Restartable workers are rebuilt
  with bounded backoff that resets after a healthy heartbeat or stable run;
  critical failures cancel the entire service.

The metrics registry also exports fixed-bucket duration histograms for
authentication, instrumented database service boundaries, message-routing
admission, durable-outbox delivery attempts, Redis control-plane operations and
HTTP Upload operations. Their names are
`xmpp_<operation>_duration_seconds_{bucket,sum,count}`. Bounds are compile-time
constants, every series is label-free, and JIDs, usernames, domains, node names,
request IDs and trace IDs are deliberately excluded. This keeps memory and
Prometheus cardinality bounded and avoids turning operational telemetry into an
identity side channel. The supplied Grafana dashboard graphs p95 values and the
Prometheus rules alert only when the corresponding counter has traffic; tune
thresholds against a measured deployment baseline rather than adding identity
labels. OpenMetrics exemplars are not emitted by the current text endpoint.

Do not use `/healthz` as the load-balancer readiness check. An internal load
balancer or container orchestrator should reach `/readyz` directly on the
private application network; never publish that database-backed path through
the public Caddy virtual host.

## WebSocket reverse proxy

RFC 7395 authentication must run over WSS. The application HTTP listener is
plaintext, so a production proxy whose address is in `TRUSTED_PROXY_IPS` must
remove client forwarding headers and set exactly one
`X-Forwarded-Proto: https`. Northstar rejects a public/plaintext upgrade and
also rejects a loopback proxy that omits the HTTPS assertion when `PUBLIC_URL`
is a production HTTPS URL. Plain `ws://` remains available only for a direct
loopback development setup whose `PUBLIC_URL` is an HTTP loopback URL.

Native XMPP clients may omit `Origin`. Browser clients must use the normalized
origin of `PUBLIC_URL`; delegated or hosted clients must be explicitly listed
as exact origins in `WEBSOCKET_ALLOWED_ORIGINS`. Ambiguous, opaque, user-info,
invalid-port and non-HTTP(S) origins are rejected, and an HTTP origin is
accepted only for loopback development. This policy limits cross-site
WebSocket hijacking and browser-assisted login abuse even though the endpoint
does not use a cookie-authenticated XMPP session.
Both WebSocket frames and reassembled messages are capped at 1 MiB.
Native C2S TCP and WebSocket streams advertise and enforce XEP-0478's 1 MiB
first-level XML limit plus a 15-second pre-authentication and five-minute
post-authentication byte-idle window. Only bytes received from the peer refresh
that window; local delivery and timer work do not. BOSH deliberately omits the
feature because its independently configurable HTTP request and XEP-0124
inactivity limits include body-envelope overhead and are authoritative.

## BOSH reverse proxy

XEP-0124/XEP-0206 is disabled by default. When it is required, set
`BOSH_ENABLED=true`, configure an HTTPS `PUBLIC_URL`, and put the HTTP listener
behind a reverse proxy whose address is present in `TRUSTED_PROXY_IPS`. The
proxy must remove any client-supplied forwarding headers and set
`X-Forwarded-Proto: https` itself. Do not publish the application's plaintext
HTTP listener as a BOSH endpoint: Northstar deliberately rejects BOSH requests
that do not arrive through a trusted HTTPS proxy.

The canonical endpoint is `/http-bind`; `/bosh` is an equivalent alias. CORS is
enabled only on those paths. Session count, concurrent request-body reads,
body-read time, request and response sizes, stanza counts, queued output, wait,
inactivity, polling and pause are all separately bounded with the `BOSH_*`
settings in `.env.example`. Monitor
`xmpp_bosh_sessions_active` and `xmpp_bosh_sessions_total`, and alert before the
active count approaches `BOSH_MAX_SESSIONS`. Host-meta advertises the endpoint
only when BOSH is enabled and `PUBLIC_URL` is HTTPS.

## Connection, cache and storage bounds

The single-node defaults reject new work rather than allowing unbounded memory
growth: 4,096 C2S connections globally, 512 from one IP, 64 resources for one
account, a 30-second unauthenticated deadline, and 512 total inbound/outbound S2S streams.
Entity-capability, pending push and DNS maps are bounded or periodically pruned.
Changing a password or disabling an account revokes API tokens and cancels live
and resumable XMPP sessions. Sensitive API responses are emitted with
`Cache-Control: no-store`.

Accounts, MUC rooms, live bindings and retained SM rows additionally use the
PostgreSQL-authoritative capacity snapshot described in
[DEPLOYMENT_CAPACITY.md](DEPLOYMENT_CAPACITY.md). Keep every node on the exact
same values at one `DEPLOYMENT_CAPACITY_EPOCH`; increment the epoch once for a
policy change. Startup refuses an inconsistent or unsafe reduction. Monitor the
`xmpp_capacity_*_{used,limit}` gauges, reservation rejections and lease losses.
Drain connections from pre-ledger binaries before a rolling upgrade.

Offline delivery is capped per account by count, total bytes and TTL. Personal
and MUC MAM and completed moderation evidence default to 365 days; undelivered
offline messages default to 30 days. `MAM_RETENTION_DAYS`,
`MUC_MAM_RETENTION_DAYS`, `MODERATION_RETENTION_DAYS`, and
`OFFLINE_MESSAGE_TTL_DAYS` accept `0` to disable their automated deletion. Zero
never means "delete immediately". XEP-0441 preferences decide what is archived;
retention places an independent upper bound on how long accepted messages stay.
`AUDIT_LOG_RETENTION_DAYS` is separate, defaults to 730, and must remain in the
finite 30-to-36,500-day range.

The retention worker runs every `RETENTION_CLEANUP_INTERVAL_SECONDS` and removes
at most `RETENTION_CLEANUP_BATCH_SIZE` rows from each enabled store per pass.
Every batch is a short, chronological `SKIP LOCKED` transaction backed by a
global `(created_at, id)` index, so concurrent workers and restarts are safe and
do not require an offset or persistent cursor. A failed store is logged and
retried on the next pass without preventing the other stores or listeners from
running. A separate bounded moderation batch deletes only terminal reports whose
latest appeal resolution is also older than `MODERATION_RETENTION_DAYS`; copied
evidence and appeals cascade. Submitted/reviewing reports or appeals are never
eligible. Optional user and room policies can only shorten these operator
ceilings; only an administrator can authorize an extension back toward the
ceiling. Audit rows are insert-only and are removed through their dedicated
bounded cleanup gate.

Typed exact-record and controlled-scope legal holds cover personal/MUC archive,
offline, and report evidence. Active holds are excluded in the candidate-lock
transaction. Account deletion and room destruction fail closed. Held offline
rows remain deliverable because deletion atomically preserves the exact
server-visible stanza in immutable hold storage. Create/list/export/release are
administrator-authorized, idempotent where applicable, and access-audited;
release cannot rewrite the target manifest. Export roots are SHA-256 chains,
not independent signatures: anchor/sign them with an organizational KMS/HSM and
retain them on access-controlled WORM storage. See
[DATA_LIFECYCLE.md](DATA_LIFECYCLE.md) before reducing policy values or handling
a deletion blocked by a hold.

## Durable anti-abuse state and calibration

Actor windows, penalties, issue windows and one-use PoW challenges are durable
PostgreSQL state and use `clock_timestamp()` as the authority. Maintenance
deletes no more than 1,000 stale rows from each abuse table per minute. A normal
free message decision is one short transaction with batched actor insert/update;
the WSL debug integration gate accepted 1,000 independent durable actor decisions
in 1.89 seconds (528/s) on the validation host. This is evidence for the 1,000
session design, not a latency or production-capacity guarantee.

The default free bursts are: registration 1/IP, SASL/REST login 5/account,
password or account change 3/account, and messages 60/account/window. Reports
and appeals require PoW immediately; appeal work has the stricter base and a
minimum 15-second wait. Authenticated shared-IP message/login activity is a
20:1 high-volume signal and cannot inherit account penalties or invalidate a
different NAT peer's challenge. After the free burst, step `n` uses `n²` times
the configured base; later steps introduce 2/10/30/120-second waits before
penalty multipliers and `ABUSE_MAX_WAIT_SECONDS` are applied.

Actor-state transactions use two contention boundaries. On one process, fixed
striped gates queue a shared NAT/account before the task acquires a PgPool
connection. Across processes, transaction-scoped advisory try-locks cover both
the first row insertion and later updates, followed by `FOR UPDATE NOWAIT` as a
rolling-upgrade guard. Cross-node contention therefore fails closed with a
retryable resource constraint instead of parking pool connections on one hot
row. Repeated contention is a capacity signal; it is not logged as a database
outage.

`POW_MAX_DEVICE_SECONDS=8` is an operator calibration target, not a wall-clock
guarantee. Benchmark the browser solver on representative mid-range phones,
then choose `POW_BASE_WORK_FACTOR`/`POW_MAX_WORK_FACTOR` without raising the
advertised target. Thermal throttling, browser engines and hardware vary. The
fixed maximum work factor is the actual enforced ceiling. Standards-only XMPP
clients use the 60-message burst and receive retryable `wait/resource-constraint`
after it; Northstar does not claim its PoW extension is an XMPP standard.

PoW intent v2 is the production default. It commits every capable challenge to
the method/XMPP action, canonical path and SHA-256 of the pow-less mutation
body; the challenge API receives only that digest. If an old client must be
drained, set `POW_V1_COMPATIBILITY_UNTIL` to a short canonical UTC RFC 3339
deadline. An unset or expired value rejects v1 issuance and consumption. Allow
at least the two-minute challenge lifetime between the last v1 issuance and
cutover, then remove the setting. The exact canonicalization and legacy XMPP
boundary are documented in [`POW_INTENT_V2.md`](POW_INTENT_V2.md).

Production must mount an independent `ABUSE_STATE_HMAC_KEY_FILE`; startup also
requires it whenever any listener is non-loopback or Redis is enabled. A random
process-local key is available only for a reserved development domain when all
listeners are loopback and `ABUSE_STATE_ALLOW_EPHEMERAL=true` is explicitly set.
Never reuse FAST or Dialback secrets.

Migration `0082` makes PostgreSQL authoritative for the deployment key
generation. It stores only a purpose-separated 96-bit identifier for each key,
never the mounted key material. `ABUSE_STATE_HMAC_KEY_EPOCH` starts at `1` and
must increase by exactly one whenever the current key changes. Every persistent
node reconciles this record before listeners start. A security-critical worker
then validates it every five seconds with a three-second database timeout;
an unrelated current/previous key, skipped epoch, unavailable authority or
prematurely retired key cancels the whole service and closes its listeners, not
only `/readyz`. The normal detection boundary is one poll interval plus the
query timeout (scheduler/OS stalls can add delay). `/readyz` independently
checks the same authority. The explicit ephemeral loopback development mode
skips this database authority so disposable tests are not blocked.

Use this three-phase rolling rotation; never replace the current secret in
place without retaining the old value:

1. Create the new secret. Configure `current=new`, `previous=old`, increment
   `ABUSE_STATE_HMAC_KEY_EPOCH` by one, and keep
   `ABUSE_STATE_HMAC_RETIRE_PREVIOUS=false`. Roll every node. The first new node
   atomically opens the PostgreSQL `overlap` phase. Both the old generation and
   the exact new current/previous pair pass validation. During this phase the
   dual-key nodes still issue challenges and create message/offline admissions
   with `previous=old` as the primary key, while mirroring actor state under
   both keys. This is what makes their new durable artifacts verifiable by an
   old-only node; the new key is not primary yet.
2. Confirm that every node has the new pair. Keep both files mounted, set
   `ABUSE_STATE_HMAC_RETIRE_PREVIOUS=true`, and roll every node again. The first
   node atomically changes the authority to `retiring`; dual-key nodes switch
   primary writes to `current=new`, and previous-generation processes are
   cancelled by their authority worker on its next bounded poll. This
   moment—not the start of phase 1—is the beginning of the enforced safety
   horizon.
3. Inspect `retire_not_before` in `abuse_key_deployments`. Until that database
   timestamp, keep both files and the retiring flag on every node. The horizon
   is the maximum of the abuse window, maximum wait plus challenge margin, full
   ten-level exponential cooldown decay, accepted message-admission TTL, and
   the fixed 30-day delivered-offline tombstone. The timestamp is only the
   earliest possible removal: finalization also fails closed while any live
   old-key challenge, abuse message admission, queued offline admission
   (including a `NULL` expiry), personal-message content identity, retraction
   identity, or unexpired offline tombstone remains. After the timestamp
   and only after the reference query below reports zero, remove the previous
   file, set `ABUSE_STATE_HMAC_RETIRE_PREVIOUS=false`, retain the same
   epoch/current key, and roll every node. The first node finalizes `stable`.

Inspect the retirement fence without exposing key material (replace the domain
literal):

```sql
SELECT d.xmpp_domain, d.phase, d.previous_key_id, d.retire_not_before,
       (SELECT count(*) FROM abuse_pow_challenges c
         WHERE c.key_id=d.previous_key_id
           AND c.expires_at > clock_timestamp()) AS active_challenges,
       (SELECT count(*) FROM abuse_message_admissions a
         WHERE a.key_id=d.previous_key_id
           AND a.expires_at > clock_timestamp()) AS active_message_admissions,
       (SELECT count(*) FROM offline_message_admissions o
         WHERE o.payload_key_id=d.previous_key_id
           AND (o.offline_message_id IS NOT NULL OR o.expires_at IS NULL
                OR o.expires_at > clock_timestamp())) AS active_offline_admissions,
       (SELECT count(*) FROM personal_message_admissions p
         WHERE p.payload_key_id=d.previous_key_id) AS active_personal_message_identities,
       (SELECT count(*) FROM personal_retraction_intents r
         WHERE r.semantic_key_id=d.previous_key_id
            OR r.c2s_projection_key_id=d.previous_key_id
            OR r.owner_projection_key_id=d.previous_key_id) AS active_retraction_identities
  FROM abuse_key_deployments d
 WHERE d.xmpp_domain='example.com';
```

Do not delete live rows to force rotation. Let challenges/admissions expire and
normal bounded cleanup remove them; deliver or expire linked offline content.
Personal-message identity rows remain live while any MAM/C2S/S2S projection
owns them and then for the configured replay grace. Retraction identities use a
fixed 30-day replay window. A retraction row already keyed by the retiring
generation remains immutable and therefore keeps that generation fenced until
ordinary retention removes the row; replay never silently rewrites accepted
operation identity. Migration `0104` cannot key old SHA-256 commitments without
recovering the stanza that it deliberately drops; those legacy commitments are
read-only compatibility evidence until an authorized exact replay upgrades
them to the deployment-authorized primary generation or ordinary retention
deletes them. No new
write uses the legacy shape.

Migration `0119` applies the same rule to retraction owner topology. It removes
the redundant peer JID from the replay projection table, writes new owner plans
only as a purpose-separated HMAC, and lazily upgrades an old SHA-256/SHA-512
owner commitment after an authorized exact replay. Previous-key retirement is
blocked by semantic, C2S-delivery, or owner-topology commitments. Migration
`0119` requires a coordinated binary rollout: drain binaries which predate the
migration before allowing the new binary to write keyed-only owner rows, because
the old binary assumes the three legacy owner fields are non-null.

Personal-retraction replay identity is account scoped across sender resources.
For outbound S2S, the first committed outbox row preserves the original full
recipient JID and exact routed stanza. For inbound S2S, the first committed
C2S/offline row likewise preserves the original full local target. A retry
addressed to another resource of the same recipient bare JID is classified as
the same account-level action and does not create, replace or wake a second
projection. Changing the recipient bare JID or domain is a conflict. Locally
authenticated C2S delivery is intentionally stricter: an explicitly selected
full recipient resource is included in its projection MAC, while an omitted
C2S `to` is internally equivalent to the sender's bare JID without rewriting
the delivered XML. Inbound S2S never receives that omission rule and fails
closed without an explicit `to`.
If offline retention is unlimited, a queued old-key message can intentionally
keep the previous secret required until it is delivered or administratively
removed through the ordinary message-retention workflow.

The database row must be backed up and restored with the secret files. Never
decrement or reuse an epoch after restore. A database administrator can inspect
`xmpp_domain`, `epoch`, `phase`, the short key IDs and retirement timestamps;
none of those values can be used as the HMAC secret. A readiness failure is not
permission to overwrite this row manually—restore the matching files or resume
the documented next phase.

Migrations `0077` and `0078` add database-enforced capacity for issued
challenges and crash-recoverable message admission. Admission keys and payload
comparisons are keyed digests; the anti-abuse tables do not retain the plaintext
stanza or an unkeyed content hash. A 64-shard capacity ledger, single-consumer
lease token and explicit pending/accepted state prevent two concurrent workers
from independently consuming the same retry identity. Capacity is released in
the same transaction as deletion, including account cascade. Alert on admission
capacity, cleanup failures and backend errors: fail-closed admission protects
correctness but can deny messages while PostgreSQL is unavailable.

## Online message acceptance and crash semantics

RFC 6120/6121 do not acknowledge application processing, but Northstar no
longer treats an in-memory enqueue as the only recoverable copy of a
storage-eligible ordinary direct message to a locally hosted account. Admission
commits the trusted XEP-0359 identity, enabled MAM rows and a transient recipient
spool row in one PostgreSQL transaction before local or Redis-backed queueing.
When XEP-0198 is negotiated, TCP, WebSocket and BOSH persist the exact spool
fence in the counted unacknowledged entry before transport output and delete it
only when client `h` advances, including during resume. Without SM,
TCP/WebSocket take or renew an exact short-lived claim immediately before the
bounded socket write and complete only that claim after a successful write. A
timeout or crash leaves it available after lease expiry. BOSH binds the fence to the
exact response RID before exposing the HTTP response and completes it only
after a later authenticated client response `ack`; duplicate RID replay returns
the byte-identical cached body. Disconnect, actor crash and lease expiry release
unacknowledged ownership for retry instead of deleting the spool row.

Each runtime also reserves one PostgreSQL connection, separate from the
configured application pool, for the supervised `sm-authority-listener`.
Migration `0127` publishes only `{schema, session_id, state_version}` on the
fixed `northstar_sm_authority_v1` channel after a durable SM row transaction
commits. The notification is a wake hint, never claim authority: after initial
subscription, reconnect, failover or any matching event, the C2S actor repeats
`northstar_sm_claim` and uses its exact Pending reason and `retry_at` boundary.
Each accepted notification advances a one-shot process-local sequence; the
payload version is used only to avoid an unnecessary second read when it
exactly matches the just-probed row. A stale or forged high version is consumed
once and cannot leave a waiter permanently ahead of PostgreSQL or mask a later
real edge.
There is no periodic resume-contention query. Size database connection limits
for this additional connection per Northstar process and treat a repeatedly
restarting listener as a readiness failure; its supervisor rebuilds the
dedicated listener without borrowing a request-pool connection.

Entity-capability processing has a separate in-memory authority model. Every
accepted available full JID owns one exact XEP-0115 observation; verified MIX
flags and the complete bounded `+notify` node list stay with that observation.
The raw disco response and cross-resource summary cache are optional
accelerators, so cache TTL/eviction can cause a new query or proxy miss but
cannot suppress OMEMO/PEP/MIX interest. Pending effect bits likewise remain on
the observation. The bounded dispatcher carries deduplicated wake hints only;
on hint saturation, task failure or worker restart it reconstructs due work
from those bits, alternating local and federated queues. Saturation and restart
set an immediate rescan event; failed effects retain an exact exponential
`retry_at`, and the worker sleeps until the earliest retry or pending-IQ expiry
instead of polling. These deadlines affect latency, not ownership or the number
of retained attempts.

Federated observation admission is enforced before routing the remote
presence: at most 8,192 remote resources globally and 2,048 per domain are
accepted by one process, with independent byte budgets for current summaries
and optional cache material. The current code budgets 64 MiB for
observation-owned summaries, 16 MiB for cached semantic summaries and 16 MiB
for optional raw disco XML (up to 4,096 cache keys). Over-budget remote
presence receives `resource-constraint`; summary pressure retains pending
verification rather
than recording a negative capability answer. Local observations are bounded by
the C2S connection admission. Monitor
`xmpp_caps_effect_queue_saturated_total`,
`xmpp_caps_effect_failures_total` and
`xmpp_caps_effect_latency_seconds`; sustained growth indicates scheduler,
transport, database or peer pressure even though a saturated hint is not a
lost semantic operation. A full exact local output queue disconnects that
transport, allowing normal XMPP recovery instead of reporting a successful
disco or PEP delivery that never entered the socket path.

An explicit XEP-0334 `no-store` message to a local recipient bypasses MAM,
transient spool and offline storage. Northstar attempts volatile local and
cross-node online delivery and returns `wait/service-unavailable` only if no
online route accepts it. A members-only direct MUC invitation still rejects the
hint because affiliation and invitation delivery require one durable state
transition. Cross-domain `no-store` requires an existing authenticated
S2S/bidirectional route, waits for its bounded socket write and never enters the
durable S2S outbox; absence, saturation or timeout fails closed with
`wait/service-unavailable`.

`xmpp_online_queue_durable_acceptances_total` counts messages crossing that
database-fenced queue path, including delivery performed by a cluster receiver.
`xmpp_online_queue_volatile_acceptances_total` counts local volatile queue paths
such as explicit `no-store`, headlines, Carbons and post-commit notifications.
These are path counters rather than persistence proofs. Cluster protocol v9
carries the exact durable fence and receiver-side payload binding explicitly;
unsafe volatile/durable combinations from legacy peers fail closed instead of
inferring ownership from a stanza ID. Both are cumulative acceptance counters,
not loss counters; correlate them with
unclean exits, replay volume, receipts and Stream Management acknowledgements.
Members-only direct and mediated MUC invitations use the same durable handoff:
affiliation and the pending local row, or affiliation and the federated outbox
row, commit together. A crash can duplicate the stable ID at least once, but
cannot deliver an invitation without its matching membership permission.

Retention and foreground TTL/capacity cleanup lock candidate offline rows and
skip every replay claim, SM sequence owner and BOSH response owner, including
an expired BOSH lease until replay performs its atomic handoff. The generic
offline-spool admin clear returns `409 Conflict` while such ownership exists;
end or recover the owning sessions and retry. Account deletion is a separate,
explicit destructive lifecycle and may cascade its owned delivery state.

Migration `0079` binds an offline queue row to a keyed XEP-0359/fallback
identity and payload MAC. While content is queued, its admission marker follows
the configured offline retention; after delivery, the database trigger replaces
that deadline with an exact 30-day replay-grace tombstone. This blocks an
ordinary client retry from creating a second offline row, but it does not turn
the later socket write, Carbon fanout or recipient processing into exactly-once
delivery. Clients should preserve `origin-id` and deduplicate where the user
experience requires it.

Migration `0080` extends that identity graph to the transient C2S spool. Its
foreign key and delete trigger ensure there is always either a pending row or a
completion tombstone; a crash cannot leave an accepted identity with neither
recovery route. Migration `0104` irreversibly drops the historical exact
payload column: a delivery-only tombstone now retains a purpose-separated HMAC
and non-secret key-generation ID for collision-resistant replay comparison. It
is purged after a fixed 30-day grace even when MAM/offline retention is
disabled. The remaining write-before-delete ambiguity can produce a duplicate
with the same stanza ID, never a newly minted identity.

Migration `0097` makes independently retained sender and recipient MAM copies
members of that same recovery graph. Expiring one account's archive now clears
only that projection; it cannot cascade-delete the admission while the other
MAM copy, transient C2S row or S2S outbox still exists. Every projection-ending
trigger refreshes `delivery_completed_at`, and admission cleanup requires all
four projection references to be `NULL`. Consequently only the bounded keyed
content identity is retained while a recovery owner exists and for the fixed
30-day replay grace after the final owner ends; plaintext is not copied into
the admission table, and the identity is not retained indefinitely after all
delivery/history state is gone.

Migration `0098` repairs and pins the legal-hold trigger boundary introduced
by `0087`. Permitted `UPDATE` operations now return PostgreSQL's `NEW` row
instead of silently replacing it with `OLD`; this is required for offline/SM/
BOSH delivery claims and every other mutable operational fence. Deletes still
return `OLD`, protected payload changes still fail with SQLSTATE `55000`, and
all legal-hold/retention and offline-admission trigger routines remain
`SECURITY INVOKER` while resolving application relations only through their
quoted installation schema. The migration changes neither routine ownership
nor ACLs.

Migration `0099` applies the same caller-independent rule to every
application-owned SQL/PL/pgSQL function present in the installation schema.
It excludes PostgreSQL system/extension objects, fails if an application
function is not migrator-owned, and verifies that `SECURITY DEFINER`, ACL,
owner and non-path configuration are unchanged after pinning. No current
Northstar function intentionally addresses a caller-selected or temporary
schema, so the release has no search-path exemption list. A future function
that lacks the fixed catalog/application/temporary order fails the isolated
migration catalog gate.

PubSub and PEP independently cap nodes and total persisted payload bytes per
owner. These defaults protect service availability; tune them only with
PostgreSQL and disk alerts in place. A retention change applies to existing data
on the next pass, so take and verify a backup before reducing retention days.

## Authentication key separation

Normal and clustered deployments require two distinct owner-only authentication
key files. `FAST_TOKEN_SECRET_FILE` authenticates and encrypts XEP-0484 token
state. `DUMMY_SCRAM_SECRET_FILE` independently derives stable, account- and
mechanism-specific dummy salt/verifier material for unknown or unusable accounts,
so those clients complete the same SCRAM wire shape and work factor before the
uniform authentication failure. Dummy credentials can never authenticate.

Generate both with `scripts/create-production-secrets.sh` and mount the same
pair on every node serving one XMPP domain. Never copy, reuse, or derive either
file from the other, from a database password, or from another capability. The
generator and production preflight reject exact reuse. Rotating the FAST key
revokes issued FAST tokens. Rotating only the dummy-SCRAM key changes synthetic
failure transcripts and has no user credential or token migration effect.

There are separate explicit development-only ephemeral switches. Each is
accepted only without Redis, with every listener on loopback and a reserved
`localhost`, `*.localhost`, or `*.test` domain. Enabling one switch does not
authorize or generate the other capability. Do not use either ephemeral mode
for persistent or externally reachable deployments.

## Federation credentials

SASL EXTERNAL with PKIX domain verification is preferred. XEP-0220 Dialback is
an interoperability fallback and still requires TLS plus a fresh authoritative
callback. Generate `/etc/northstar/secrets/dialback_secret` (or the selected
external equivalent) with `scripts/create-production-secrets.sh` and mount the
same value on every node serving one XMPP domain. Rotating it can invalidate in-flight Dialback
verification, so rotate during a controlled reconnect window.

Federation discovery bounds every DNS lookup, SRV answer, address set and final
candidate list. Northstar preserves SRV priority/weight ordering, races IPv6 and
IPv4 addresses within the selected endpoint group with a 250 ms stagger, and
caps both per-worker and process-wide connection attempts. Authenticated inbound
streams have a five-minute idle-read deadline; negotiated XEP-0478 limits expose
that deadline and the enforced serialized-stanza limit. A peer stream error is
consumed and logged even on a unidirectional outbound stream, while a stanza sent
in the reverse direction without negotiated XEP-0288 terminates that stream.

The PostgreSQL S2S outbox survives worker and process restart, preserves the
head-of-line order for each remote domain, and retries expired claims. At first
admission every message receives one server-authoritative XEP-0359 `stanza-id`
derived from its outbox UUID; the stored bytes, including that identity, are
reused unchanged on every retry. Northstar inbound admission suppresses exact
replay of this identity. RFC 6120 does not acknowledge application stanzas:
Northstar completes a row after its socket write succeeds, and a crash after
that write but before database completion can still deliver it again to an
arbitrary peer. This is deliberately at-least-once, not exactly-once. Make
downstream processing idempotent and monitor expiry/permanent-failure metrics;
no server-side ID proves that an unacknowledged peer processed a write.

### DNSSEC and DANE

`FEDERATION_DANE_MODE` accepts `off` (the default), `opportunistic` or
`required`. Northstar's Hickory resolver performs local DNSSEC validation; it
does not trust an upstream AD bit. A DANE policy is bound to the exact secure
SRV relationship, terminal A/AAAA address selected for the socket and TLSA
owner at the selected target and port. Only DNSSEC-secure TLSA usage 1
(PKIX-EE) and usage 3 (DANE-EE), with full-certificate or SPKI selection and
exact/SHA-256/SHA-512 matching, enter the implemented RFC 7712 profile.

Usage 1 retains ordinary PKIX path, time, EKU and XMPP reference-identity
validation in addition to the TLSA match. Usage 3 uses the secure TLSA record as
the identity and validity authority, but still rejects malformed or weak leaf
keys and requires a successful TLS `CertificateVerify` signature. A secure
positive TLSA RRset containing only unsupported usage/selector/matching data is
an error rather than a silent PKIX downgrade. `required` rejects insecure or
missing SRV/address/TLSA proof and cannot be combined with test address
overrides or XEP-0487 endpoint discovery.

The repository contains deterministic policy/unit fixtures. That is automated
local evidence only. Before enabling `required`, run
`scripts/federation-external-preflight.sh` from an independent network and
verify the authoritative DNSSEC chain, both XMPP SRV services, every TLSA owner,
served certificate and IPv4/IPv6 path. Do not enable it on the strength of a
local resolver cache or a hosts-file test.

### Certificate revocation lists

`FEDERATION_CRL_PATH` applies one bounded local PEM CRL bundle to outbound S2S,
inbound S2S client-certificate verification and XEP-0487 HTTPS. The separate
`C2S_CLIENT_CRL_PATH` protects SASL EXTERNAL client certificates and requires
`C2S_CLIENT_TRUST_ROOT_CERT_PATH`. For each concrete presented chain, every
non-root certificate must have a known, correctly signed and unexpired
authoritative CRL; incomplete coverage, a bad signature or stale applicable CRL
fails that chain closed. Malformed, duplicate, same-issuer ambiguous or oversized
PEM/DER is rejected at load: publish exactly one current full CRL per issuer.
The bundle is limited to 64 CRLs and an 8 MiB file.

Northstar never downloads a certificate-supplied CRL URL and does not implement
OCSP or AIA fetching. Replace CRLs as protected regular files and invoke the
same authenticated atomic TLS reload used for certificate rotation. A rejected
reload leaves the complete prior TLS/CRL snapshot active; an accepted reload
increments a process-local monotonic TLS generation and gives all new handshakes
the new snapshot. It also re-evaluates the complete DER chain retained for each
live C2S SASL EXTERNAL, inbound S2S SASL EXTERNAL and outbound S2S SASL EXTERNAL
session. Only the exact `webpki::Error::CertRevoked` classification from the
new applicable CRL policy cancels that connection. Certificate expiry, normal
renewal, changed roots, missing/inapplicable CRLs and every other validation
failure do not cause a blanket kick. A C2S password/SCRAM/FAST session and an
S2S Dialback session are not added to the registry merely because a certificate
was presented during TLS.

The material-swap/registration edge is serialized. An EXTERNAL authentication
which completes after activation evaluates the new snapshot before it can enter
the registry; the reload sweep therefore handles only entries which were live
at activation. Chain verification runs outside the registry mutex so a large
sweep does not block unrelated connection teardown.

The CRL parser validates bounded RFC 5280 structure at load. Signature,
authority, freshness, chain and EKU are validated when an applicable peer chain
is checked; do not describe reload as globally proving every CRL against every
possible issuer. XEP-0487 SPKI pins cannot override a configured federation CRL
failure. RFC 7673 DANE-EE deliberately replaces PKIX, so a pure DANE-EE chain
does not acquire CA-CRL semantics; PKIX-EE continues through the CRL-aware PKIX
path. Test renewal and explicit revocation with the deployment CA before relying
on it—generated fixtures do not prove that an operator's CRL publication or
rotation works.

Per-drain audit fields identify the peer leaf certificate retained for that
connection. Because the configured policy checks the complete non-root chain,
an explicit `CertRevoked` can instead refer to an intermediate; webpki does not
expose which chain member caused that classification. Use the CA's CRL and the
retained leaf issuer/serial/fingerprint correlation rather than interpreting
the logged leaf serial as proof that the leaf itself was listed.

XEP-0487 host metadata remains experimental even though candidates are fetched
over bounded HTTPS and selected only after IP/SNI/pin, certificate and
XMPP-stream validation. Remaining federation assurance boundaries include
broad independent-server interoperability, live public IPv6, OCSP/AIA and
general multi-domain stream multiplexing.

## Experimental Redis control plane

Redis is optional and is not part of the single-node trust base. Configure
exactly one of `REDIS_URL` and `REDIS_URL_FILE`; the file-backed form avoids
placing credentials in ordinary environment configuration. Plain `redis://` is
accepted only for loopback. Any remote Redis endpoint must use `rediss://` with
hostname verification. `REDIS_TLS_CA_CERT_PATH` installs a bounded private CA;
`REDIS_TLS_CLIENT_CERT_PATH` and `REDIS_TLS_CLIENT_KEY_PATH` must be supplied as
a pair when mTLS is required. URL fragments, insecure remote schemes and TLS
files paired with a non-TLS URL are rejected at startup.

TLS authenticates and encrypts the Redis connection; it does not authenticate
the process which authored a Pub/Sub value and does not make Pub/Sub durable.
Redis mode therefore also requires a stable `CLUSTER_NODE_ID`, a protected
file-only Ed25519 private key and an exact peer public-key/command ACL. Protocol
v8 signs the namespace, source/destination/channel, command kind, IDs, time
window, payload digest, key generation and the independent process-instance
fence. PostgreSQL authorizes current/previous keys and the single live
key-bound UUID/instance epoch. A Redis-only publisher cannot inject a command.
See [CLUSTERING.md](CLUSTERING.md) for configuration and the mandatory
prepare/activate/retire key rotation.

Choose `CLUSTER_FAILURE_POLICY=fail_closed` or `durable_direct_only`. Both make
readiness fail and reject bind/resume, MUC/admin mutation and transient traffic
after a control-plane failure. `fail_closed` rejects every new cluster
operation and requests supervised shutdown after the bounded safety lease.
`durable_direct_only` may continue only bounded PostgreSQL-spooled ordinary
direct admission while PostgreSQL key/instance authority remains healthy; it
does not exit merely because a Redis outage outlasts the safety lease.
PostgreSQL authority loss is an immediate fail-fast condition for either
policy. Redis recovery is insufficient by itself: peer authority, node lease,
full-JID ownership, MUC occupant epochs and a newer listener generation must
reconcile in order before readiness returns.

Classify failure behavior before setting an availability objective:

- storage-eligible ordinary direct messages have a PostgreSQL recipient
  spool/offline fallback; the remote node reconstructs the durable fence before
  its socket write;
- explicit `no-store`, signal-only messages, MUC messages/presence, ordinary
  presence and Carbons use volatile cross-node delivery and can fail, be lost,
  or converge only after later state;
- mutation-caused PubSub/PEP notifications use the PostgreSQL recipient-snapshot
  outbox; PubSub digests and S2S/component deliveries retain their own durable
  projections;
- Generic PubSub routes same-domain remote-node subscribers through Redis and
  remote-domain subscribers through authenticated S2S. Redis is not the
  federation transport.

Alert on every non-healthy cluster state and signed-envelope authentication or
replay rejection. During clean shutdown Northstar stops and drains signed
publication before expiring its exact database instance lease. If draining
times out, it leaves the lease to expire naturally rather than release a fence
under a possibly in-flight command. The feature remains Experimental until the
target Redis/PostgreSQL topology passes asymmetric partition, managed failover,
rolling-version and capacity qualification.

## External components

External components are disabled by default and bind to `127.0.0.1:5347` when
enabled. Copy `deploy/components.example.json` to the ignored
`deploy/components.json`, assign each component an exact domain/alias list, and
set exactly one of `secret_file` or `secret`. The configuration and mounted
secret must both be non-symlink regular files, owned by the Northstar process,
with mode `0400` or `0600`; `secret_file` is the production choice and must
contain 32–4096 random bytes. An inline secret is accepted for protected local
or test configuration and is retained only in zeroizing memory. Configure
`COMPONENTS_CONFIG_FILE` and then set `COMPONENTS_ENABLED=true`. Restart
Northstar to activate secret rotation.

Prefer the TLS-required XEP-0225 compatibility profile only when the component
actually supports it, and remember that XEP-0225 is Deferred and not a
recommended production replacement. XEP-0114 has no transport encryption: keep
its accept listener on loopback or carry it over a separate mutually
authenticated private transport. Connect mode is also XEP-0114; use a trusted
private endpoint. Public resolved addresses are rejected unless that profile
sets `allow_public_connect=true`, which is an explicit operator risk decision.
Never publish port 5347 directly.
Duplicate domains, unconfigured aliases, forged stanza origins, oversized XML
and excessive connections are rejected rather than forwarded. Component-bound
stanzas enter the same bounded PostgreSQL outbox as federation traffic before
the client operation is accepted. The node owning a component socket claims
only that socket's bound domains, in per-domain order; an offline component, a
full wake queue, process termination or component disconnect therefore leaves
the row available for retry until its configured expiry. The maintained
`component-runtime-wsl` suite kills Northstar after admission, restarts it on
the same schema, and drains through both XEP-0114 and XEP-0225.

Neither component protocol provides an application-stanza acknowledgement.
Northstar completes a row after the socket write succeeds. A failed write
releases the current and remaining claimed rows for retry, but a process or
network failure around a successful write is inherently ambiguous and can
duplicate delivery. Message rows keep one server-authoritative XEP-0359 ID on
every retry. This is not an end-to-end exactly-once or acknowledged delivery
guarantee. Monitor outbox expiry/permanent-failure counters and make component
handlers deduplicate that stable ID.
Client-originated routes to configured component domains remain available when
Internet federation is disabled, but component credentials never grant an
inbound S2S peer authority for that domain.

## TLS certificate and reload operations

For local development only, `scripts/generate-development-certificate.sh`
creates a 30-day, visibly development-only self-signed localhost certificate at
the application's default certificate paths. A public deployment must use a
non-self-signed certificate for the real XMPP domain. On WSL paths under
`/mnt/c`, `stat` can report permissive modes because DrvFS maps Windows ACLs;
that is not acceptable evidence for a Linux production host. The production
preflight requires a native Linux key file with mode `0400` or `0600`.

Northstar explicitly enables only TLS 1.2 and TLS 1.3 using rustls' modern
AEAD/forward-secret suites. At startup and reload it bounds and strictly parses
the PEM files, rejects symlinks, multiple/private PEM objects in the wrong file,
duplicate or oversized chains, expired/not-yet-valid certificates, CA leaves,
wrong key usage or EKU, missing/wrong SANs, weak RSA/EC keys, weak signatures,
key mismatch, and an untrusted public-domain chain. RSA, supported ECDSA and
Ed25519 leaf keys are accepted after the same chain/profile validation. Trust
validation is deliberately independent from channel-binding capability: when
the certificate signature has no single RFC 5929 digest (for example
Ed25519), Northstar omits `tls-server-end-point` and advertises only the live
connection's `tls-exporter` when rustls successfully derives it. SCRAM-PLUS and
FAST never advertise or substitute a binding which is unavailable.

Self-signed trust is confined to IANA-reserved development names (`localhost`,
`*.test`, `*.invalid`, and example names). Production uses the WebPKI root set;
an explicitly configured `FEDERATION_EXTRA_ROOT_CERT_PATH` is loaded into the
same atomic TLS snapshot for controlled private-PKI federation. Its certificates
must be currently valid CA certificates with certificate-signing key usage.

Certificate reload is fail-safe and atomic across C2S STARTTLS, C2S Direct TLS,
S2S STARTTLS, S2S Direct TLS, outbound S2S client authentication, federation
trust roots, and RFC 5929 channel-binding data. Build the new full chain and key
as protected regular temporary files, validate them with:

```sh
sh scripts/verify-production-certificate.sh /secure/new-fullchain.pem /secure/new-key.pem example.org
```

Then replace the configured regular files with same-filesystem renames and call
the authenticated `POST /api/v1/admin/tls/reload` endpoint. Concurrent reloads
are serialized. A read race, mismatch, or validation failure increments
`xmpp_tls_reload_failures_total` and leaves the complete previous in-memory
identity active. Monitor `xmpp_tls_certificate_seconds_until_expiry`; the
included alert fires at 14 days. Existing connections keep the cryptographic
keys negotiated at their handshake. Reload does not attempt an impossible
in-place TLS rekey, but it does close the exact registered SASL EXTERNAL
connection when the new applicable CRL explicitly revokes its retained peer
chain. The durable operation target result records previous/current generation,
number checked and per-direction drain counts; structured security logs add the
connection UUID, leaf issuer, serial, SHA-256 fingerprint and handshake
generation for each drain.

The verifier uses the host trust store and requires at least 30 days remaining.
It never accepts encrypted key files (which could open an interactive prompt),
never includes key bytes in diagnostics, and is covered by generated bad-chain,
wrong-domain, weak-key, mismatch, permission and symlink regression cases.
For the supplied Compose deployment, install the private key as a regular file
owned by `10001:10001` with mode `0400` or `0600`; file-backed Compose secrets
and bind mounts cannot remap a host file's ownership. The certificate chain may
be root-owned and readable, but must not be group/world writable.

## Metrics and alerts

The base counters cover connection totals, active client resources, stanza
traffic, authentication failures, routing, federation, abuse controls,
moderation, and PEP item activity. Runtime gauges additionally expose:

- PostgreSQL availability, probe duration, pool size, idle connections, and
  configured maximum;
- resumable Stream Management sessions and current MUC occupants;
- active inbound federation streams and outbound federation workers;
- current TLS generation and active certificate-authenticated sessions split
  across C2S, inbound S2S and outbound S2S, plus cumulative CRL rechecks and
  exact revoked-session drains. A non-zero
  `xmpp_tls_revocation_recheck_inconclusive_total` means the new snapshot could
  not prove an active chain revoked or valid (for example, changed trust or a
  bad/inapplicable CRL); that stream is deliberately retained, while new
  handshakes continue to fail closed under the configured policy;
- durable federation/component outbox rows, bytes, due heads, leases, oldest
  age, configured capacity, retry/loss counters, and component backlog;
- challenge and message-admission capacity, cleanup/backend failures, accepted
  offline retry identities, durable and volatile online queue acceptances, and
  slow-client disconnects caused by durable outbound queue saturation;
- PubSub/PEP event-outbox rows/bytes, retries, lease loss, dead letters and
  capacity rejections. Any dead letter or capacity rejection is release- and
  operations-significant; see `PUBSUB_EVENT_OUTBOX.md`;
- shared-upload promotion, stage deletion, object deletion and terminal
  cleanup outcomes; credential-refresh, manifest-scrub and integrity failures;
  and the durable storage/cleanup queue depths, dead-letter count, persistent
  scrub-failure count, capped due cleanup/scrub obligations and their oldest
  overdue age. These gauges are
  refreshed by the supervised worker rather than by `/metrics`. Any integrity
  failure is critical: preserve the PostgreSQL locator and immutable object
  evidence, stop promotion for the affected namespace and investigate before
  retrying or deleting anything. A nonzero dead-letter or persistent scrub
  failure also degrades readiness and requires fenced reconciliation rather
  than a blind queue reset;
- pending reports, appeals and invitations, including stricter appeal abuse
  decisions, so moderation queues and deliberately delayed work are visible;
- Redis connection/maintenance failures and legacy cross-node payload use when
  the experimental control plane is enabled;
- pending, running, and indeterminate administrator operations plus the age of
  the oldest active operation. An indeterminate operation has crossed its point
  of no return and then either lost its worker lease or received an executor
  error whose post-effect outcome could not be proved. It must be reconciled
  from external evidence, never blindly retried or reported as a definite
  failure;
- process uptime and background-maintenance failures;
- rows deleted from personal MAM, MUC MAM, and offline queues, plus dedicated
  retention-cleanup failures;
- TLS certificate expiry and rejected atomic reloads.

Start the optional local monitoring stack with:

```sh
sudo install -d -o root -g root -m 0700 /etc/northstar
sudo env NORTHSTAR_SECRET_DIR=/etc/northstar/secrets \
  sh scripts/create-production-secrets.sh
sudo docker compose --profile monitoring up -d
```

The root-only generator is deliberate. Its pre-created parent and every
ancestor must be non-symlink, root-owned and non-replaceable; it locks the
parent before creating or validating anything below it. Compose uses bind mounts for file-backed
secrets and cannot remap ownership, so it installs each mode-`0600` secret with
the numeric owner of its pinned consumer image: Northstar `10001:10001`,
PostgreSQL `70:70`, and Grafana `472:0`. Review those identities whenever an
image digest changes. Do not relax the files to `0644` to make a container start.

Prometheus and Grafana bind only to host loopback by default. Publishing either
UI through Caddy requires a separate authentication and authorization decision.
The included Prometheus rules have no receiver; configure Alertmanager or a
managed alert receiver before relying on them.

## Release artifacts and Compose image selection

Linux AMD64 is the supported production baseline. The tag workflow prepares a
complete `northstar-0.2.0-linux-amd64.tar.gz` distribution and a raw
`northstar-0.2.0-linux-amd64` ELF binary. It also prepares a complete
`northstar-0.2.0-windows-amd64.zip` and raw
`northstar-0.2.0-windows-amd64.exe`, but Windows is a development/evaluation
target, not a production baseline. A raw binary lacks the matching Web client,
Swagger UI, configuration example and license notices; operate from a complete
archive or place those matching-tag files beside it.

A successful version-tag run publishes the three GHCR images, generates
`SHA256SUMS`, GitHub build provenance and `IMAGE_DIGESTS`, then creates or
updates a **draft** GitHub Release. Pushing the tag is therefore
publication-sensitive even though the GitHub Release remains private. Do not
treat an unreviewed draft, a dry-run artifact, or a hash from a different run as
release evidence. The exact values exist only after the tag workflow succeeds.

For a source build, set `NORTHSTAR_VERSION=0.2.0` and set
`NORTHSTAR_VCS_REF` to the exact release commit in the ignored `.env` before
invoking the base Compose file. The build installs OCI
source/revision/version/license labels and copies `LICENSE` plus
`THIRD_PARTY_NOTICES.md` into every Northstar image. The default `unknown`
revision is development-only and must fail the operator's artifact review.

For registry deployment, use Docker Compose `2.24.4` or newer and merge
`deploy/docker-compose.release.yml`. It removes the local `build:` definitions
with `!reset` and maps five services to three Linux AMD64 GHCR images:

| Services | Version-tag reference |
|---|---|
| `migrate`, `xmpp` | `ghcr.io/takanashi-tetsuya/northstar:0.2.0` |
| `database-grants` | `ghcr.io/takanashi-tetsuya/northstar-database-grants:0.2.0` |
| `backup`, `restore` | `ghcr.io/takanashi-tetsuya/northstar-backup:0.2.0` |

Tags select a version but are registry references, not retained deployment
evidence. After reviewing the successful tag run, copy the three exact
`name@sha256:digest` lines from `IMAGE_DIGESTS` into the corresponding
`NORTHSTAR_SERVER_IMAGE_REF`, `NORTHSTAR_DATABASE_GRANTS_IMAGE_REF`, and
`NORTHSTAR_BACKUP_IMAGE_REF` values in the protected deployment `.env`.

```sh
docker compose -f docker-compose.yml -f deploy/docker-compose.release.yml \
  --profile backup --profile restore config --quiet
docker compose -f docker-compose.yml -f deploy/docker-compose.release.yml \
  --profile backup --profile restore pull
docker compose -f docker-compose.yml -f deploy/docker-compose.release.yml up -d
```

Inspect the rendered configuration before pulling: every Northstar service must
have the reviewed digest reference and no `build:` key. Re-run the render after
any `.env`, Compose or digest change.

## PostgreSQL privilege separation

The production Compose topology never runs the application as the PostgreSQL
image superuser:

| Identity | Lifetime and capability |
|---|---|
| `northstar_bootstrap` | PostgreSQL-container trust boundary only; the sole Northstar superuser. It creates/reconciles workload roles and is never mounted into `migrate`, `xmpp`, `backup`, or `restore`. |
| `northstar_migrator` | One-shot schema owner. It is `NOSUPERUSER`, `NOCREATEDB`, `NOCREATEROLE`, `NOREPLICATION`, and `NOBYPASSRLS`; only `xmpp-server migrate` and an explicitly stopped restore receive its URL. |
| `northstar_runtime` | Long-lived, non-owner application identity. It has no database/schema `CREATE`, cannot alter ownership or disable triggers, and has SELECT-only access to `users`; all account-authority writes use the exact migration-0108 command allowlist. It starts only after a read-only migration/checksum, RFC 7622 marker, role and ACL attestation. |
| `northstar_commands` | Long-lived, non-owner command identity with `CONNECTION LIMIT 8`. It has no relation or sequence privileges and may execute only the canonical owner-held XEP-0133 command-session functions. The server gives it an isolated four-connection pool so command work cannot consume the runtime pool. |
| `northstar_backup` | Read-only logical-backup identity. It can connect and select tables/sequences, but cannot write, allocate sequences, execute application routines, create objects, change roles, or terminate sessions. |

On an empty `postgres-data` volume, the official image executes
`deploy/postgres-init/010-northstar-roles.sh`. The script reads independent
password files, transfers database/schema ownership to the migrator, and enters
the empty-database `bootstrap` phase: `PUBLIC` and every workload have zero
capability, and global plus schema-local future-object defaults are owner-only.
The one-shot Compose `migrate` service then applies SQLx and RFC 7622 migrations.
For this release the exact manifest contains 127 files from `0001` through
`0128`, with `0021` as the sole intentional numbering gap. `0114` and `0115`
remain the stopped-upgrade privilege-separation boundary, but they are not the
end of the accepted ledger: `database-grants` requires every checked-in row
through `0128`, with the exact SQLx description and SHA-384 checksum, before it
grants reviewed current objects. The `xmpp` service receives independent
`runtime_database_url` and `command_database_url` secrets; neither identity may
attempt DDL. Pending, failed, unknown, duplicated, missing or checksum-drifted
migrations and incomplete identity canonicalization all stop startup before
listeners open.

Migration `0126` changes the transaction protocol used by MIX outbox writers.
It is a **stopped-writer migration**, not a rolling-upgrade boundary. Before the
migrator begins `0126`, stop and verify the absence of every Northstar runtime,
MIX delivery worker and maintenance process that can write the application
schema. Do not run a pre-`0126` and post-`0126` binary concurrently. The
migration takes table locks and fails closed if the old capacity ledger has
drifted; those locks protect the cut-over transaction, but cannot prevent an old
process from issuing new transactions after the migration commits. Repository
ledger attestation prevents that old binary from starting again against the new
schema. It does not make a still-running old process safe.

Migration `0127` is also a stopped-writer boundary. It replaces the SM claim
projection, installs the monotonic authority triggers and extends the exact
session capability manifest in one transaction. Keep every pre-`0127` runtime
stopped until migration and exact grant reconciliation complete; do not treat
LISTEN/NOTIFY compatibility as permission for a rolling upgrade. The two new
trigger routines are owner-only private capabilities, and `state_version`
remains unreadable to the runtime role except through the existing allowlisted
SM claim capability.

Migration `0128` completes the stopped-writer sequence by replacing MIX-PAM
`COUNT(*)`/try-lock admission with exact owner-maintained global and per-account
counters, and by adding independently committed MIX delivery reclamation.
Keep every older runtime stopped until `0128` and exact grant reconciliation
both commit. The runtime role then has read-only counter access, no direct MIX-
PAM operation INSERT/DELETE authority, and may mutate those rows only through
the reviewed SECURITY DEFINER capabilities. Startup compares every counter to
the operation journal and fails closed on drift.

Before each delivery-producing transaction, complete orphan-event reclamation
and release-journal folding commit in their own authority transaction. Before a
new remote PAM operation, complete retention-eligible terminal reconciliation
does the same for its exact counters. Bounded background GC/pruning reduces
latency and retained rows, but neither worker page size nor cadence is required
to make a later admission correct. If a completion commits after the
reconciliation boundary, it is a later state transition and the following
admission observes it. Do not raise capacity limits to hide a repeatable
false-full condition: fail startup on counter drift, retain the evidence and
repair the authority invariant before accepting new writes.

After the cut-over, every delivery-producing MIX application-service operation
enters one FIFO gate before checking out a PgPool connection. Its database
transaction then takes the schema-local blocking admission fence as its first
statement, before any channel, participant, event or sequence lock. This is a
correctness boundary, not a traffic throttle: same-process producers wait
fairly without exhausting the connection pool, and experimental multi-process
writers serialize in PostgreSQL without a reverse lock order. Delivery ACKs do
not use either producer gate; they delete only the leased recipient and append
an immutable release fact. The runtime role has SELECT-only access to that
journal: owner-held trigger functions append facts and the allowlisted drain
capability atomically applies and deletes them, raising inside PostgreSQL on an
underflow. The event-leading recipient uniqueness index keeps the drain/GC
parent probes indexed. The architecture CI gate rejects new production callers
that bypass `MixService` for any delivery-producing operation.

The delivery limits (`100,000` queued recipients and `256 MiB`) and PAM limits
(`10,000` global operations and `64` per account) are deliberate hard resource
ceilings. They may reject genuinely new work after exact reconciliation; they
do not determine ACK success, release visibility, lock ownership or retry
completion. Size deployment and alerts around those explicit bounds rather
than treating timeout, `55P03`, a bounded loop or a cache TTL as overload.

PostgreSQL executes `/docker-entrypoint-initdb.d` only for a new `PGDATA`.
Existing installations created with the former `POSTGRES_USER=xmpp` superuser
must not switch Compose files in place. Use this stopped upgrade boundary:

1. create and verify a signed, age-encrypted backup with the existing release;
2. stop every Northstar runtime, MIX delivery worker, backup, restore, and
   maintenance client; verify that no application-schema writer remains before
   migration `0126` and remains stopped through `0128`, and retain the old
   superuser secret until rollback is no longer needed;
3. generate the new independent secrets, then run
   `scripts/reconcile-database-roles.sh --audit` with the existing superuser;
4. review the findings and run the same tool with explicit `--apply`; it creates
   the new bootstrap/workload identities, transfers application-object
   ownership, revokes all workload and `PUBLIC` capability under one advisory
   fence, and accepts only an intact stopped migration-0113 ledger;
5. run the one-shot migration job through the complete `0001`-`0128` manifest
   (excluding the intentional `0021` gap), run exact grant reconciliation,
   rerun role/grant audit, and prove positive
   runtime behavior plus negative DDL/write tests from an isolated copy;
6. reconnect as the verified `northstar_bootstrap` identity and use the tool's
   separate `--demote-legacy-xmpp` switch. It refuses to demote the current or
   last login superuser. Keep the former role `NOLOGIN` for one rollback window
   before deciding whether to remove it.

The role tool defaults to audit and never guesses an old password. Connection
credentials and the new bootstrap credential are separate file arguments; see
`scripts/reconcile-database-roles.sh --help`. A managed PostgreSQL service that
forbids role creation needs an administrator to reproduce the same catalog
attributes and ACLs, followed by the repository audit. Never give the runtime
or backup role owner membership as a workaround.

## Online backup

Production backup is fail-closed by default: it requires the read-only database
URL file, Ed25519 signing key, age recipients, persistent sequence state, and a
private plaintext scratch directory before it contacts PostgreSQL. The base
Compose profile supplies these separated capabilities. For direct use:

```sh
bash scripts/backup.sh \
  --database-url-file /etc/northstar/secrets/backup_database_url \
  --upload-dir data/uploads \
  --output /srv/northstar-backups \
  --sequence-state-file /var/lib/northstar-backup/sequence \
  --signing-key-file /etc/northstar/secrets/backup_signing_ed25519.pem \
  --age-recipient-file /etc/northstar/secrets/backup_age_recipients.txt \
  --plaintext-staging-dir /run/northstar-backup
```

The backup script:

1. creates a restrictive, atomic staging directory;
2. acquires the maintenance and database-policy fences and proves the complete
   version/description/SHA-384 migration ledger against the release manifest;
3. writes a PostgreSQL custom-format dump and validates its table of contents;
4. archives immutable completed upload files while excluding `.part` files;
5. starts a one-shot PostgreSQL cluster on a private Unix socket in the
   container scratch area, restores the dump there, and checks every live
   upload reference against the captured archive's size and stored digest;
6. records format/version metadata and SHA-256 checksums; and
7. flushes every artifact, writes and flushes `READY`, atomically renames the
   directory, then flushes the backup root.

Backup and restore hold the same PostgreSQL advisory maintenance fence in the
target database, so the two jobs cannot overlap. Backup also holds the database
policy fence used by schema migration and ACL reconciliation from before its
exact migration-ledger attestation until canonical backup publication has
completed. A backup can
therefore never authenticate one release ledger and then race a different
schema or grant policy into the captured archive. Ordinary Northstar writers
do not acquire the maintenance lock;
online backup consistency still depends on the completed-upload ordering below
and on dump-to-archive verification rather than claiming a distributed
snapshot across PostgreSQL and the filesystem.

`run-postgres.py` parses the URL for each PostgreSQL client, removes the URL
from the child environment, and places any password in a mode-0600 temporary
passfile. Production should prefer `--database-url-file`; the direct
`DATABASE_URL` form exists only under the explicit
`BACKUP_SECURITY_POLICY=development-legacy` compatibility policy and may itself
be visible in the wrapper process environment on operating systems that expose
it. The local validation cluster does not listen on TCP and never receives the
production URL, so `northstar_backup` needs no `CREATEDB` or write privilege.

For the Docker Compose deployment, the same operation is wired to the named
upload volume and internal PostgreSQL network. The backup/restore image also
runs as UID/GID `10001:10001`; prepare the bind-mounted host directory without
making it world-writable:

```sh
sudo install -d -m 0700 -o 10001 -g 10001 ./backups
sudo docker compose --profile backup run --rm backup
```

Northstar renames a complete upload into place before marking its database row
as uploaded. Completed files are immutable. Consequently, a live backup can
contain harmless extra files completed after the database snapshot, but every
`uploaded=true` row visible to the dump must already have a final file. The
producer restores the dump and verifies this database-to-file direction inside
the archive before `READY`; restore repeats it after authentication/decryption.

Copy each already encrypted, signed backup off-host and optionally wrap it with
the organization's independent backup/KMS layer. The local generator creates a
default age identity, but high-assurance deployments should place the restore
identity off-host or in a dedicated recovery trust boundary; the online backup
job receives only public recipients. Test retention with `--retention-days`
only after an off-host copy policy is operating; that option deletes expired
backup directories beneath the exact output directory.

## Backup verification

```sh
sudo docker compose --profile restore run --rm --entrypoint bash restore \
  /opt/northstar/verify-backup.sh \
  /backups/northstar-YYYYMMDDTHHMMSSZ --metadata-only
```

Verification first authenticates the signed manifest and monotonic restore
floor, then checks the `READY` marker, format version, all recorded hashes,
PostgreSQL archive readability, archive member type/path safety and the strict
UUID upload namespace. Run it again after transfer to off-host storage. These
checks detect accidental corruption; an attacker able to replace the backup and
rewrite its checksum manifest but not the separately protected verification
key and restore-floor state is detected. Store backups in an authenticated,
access-controlled off-host system. A verified
archive is not yet a proven recovery; schedule a restore drill.

Use a restore image containing the same repository migration manifest as the
backup. Local dump validation creates production-shaped unprivileged workload
roles, restores as the migrator in a private PostgreSQL instance, executes the
same exact grant reconciliation, and checks upload metadata against the
extracted objects. An older or newer SQLx ledger, an unregistered `public`
relation, or a drifted capability is therefore rejected before the target
cutover. To recover an older backup, restore it with that release's signed
image first, then run the documented one-shot migration and exact grant
reconciliation with the newer release.

## Restore drill

Stop Northstar first. Restore into an isolated database and upload path whenever
possible. The restore requires a separate, pre-created mode-`0700` rollback
root containing only its mode-`0600` marker; it must not overlap the backup,
upload path, project root or home directory. The upload root must likewise be a
mode-`0700` strict UUID namespace with its `.northstar-upload-root` marker. For
the packaged numeric user (substitute the exact native service account when it
is not UID/GID 10001, and run the restore as that same account):

```sh
sudo install -d -m 0700 -o 10001 -g 10001 /srv/northstar-restore/rollback
printf '%s\n' northstar-restore-rollback-v1 | \
  sudo tee /srv/northstar-restore/rollback/.northstar-rollback-root >/dev/null
sudo chown 10001:10001 /srv/northstar-restore/rollback/.northstar-rollback-root
sudo chmod 0600 /srv/northstar-restore/rollback/.northstar-rollback-root
```

Then run:

```sh
bash scripts/restore-backup.sh /srv/northstar-backups/northstar-... \
  --confirm-restore NORTHSTAR-RESTORE \
  --database-url-file /srv/northstar-secrets/restore-database-url \
  --upload-dir /srv/northstar-restore/uploads \
  --rollback-dir /srv/northstar-restore/rollback \
  --plaintext-staging-dir /run/northstar-restore
```

Mount `/run/northstar-restore` as a private tmpfs sized for the materialized
database archive plus expanded uploads. Compose supplies `/scratch` for this
purpose. `RESTORE_MAX_UPLOAD_OBJECT_BYTES`,
`RESTORE_MAX_UPLOAD_TOTAL_BYTES`, and `RESTORE_RESERVE_FREE_BYTES` bound archive
expansion and reserve free space. Filesystem quotas and free-space alerts are
still required because another process can consume capacity after preflight.

For Compose, stop `xmpp` first and pass the backup directory explicitly. The
restore service has no usable default command and still requires the same
confirmation phrase:

```sh
sudo docker compose stop xmpp
sudo docker compose --profile restore run --rm restore \
  /backups/northstar-YYYYMMDDTHHMMSSZ \
  --confirm-restore NORTHSTAR-RESTORE \
  --database-url-file /run/secrets/migrator_database_url \
  --upload-dir /uploads \
  --rollback-dir /rollback
```

The explicit phrase is required because the operation replaces the target
database. Before cutover, Northstar restores the dump into a private,
Unix-socket-only temporary PostgreSQL instance under the plaintext scratch
root; it never creates or drops a validation database in the target cluster.
It validates the archive and checks every live `uploaded=true` row
against a regular UUID-named file with the exact size and, for current rows, the
database-stored SHA-256 digest. The disposable instance also recreates the four
bounded workload roles and applies the repository migration, capability and
relation manifests as the non-superuser migrator. Thus even a same-size upload
changed together with the archive checksum is rejected when it disagrees with
authoritative database metadata, and a structurally restorable but
noncanonical database never reaches the target cutover.

Before it creates the rollback dump or installs the connection fence, restore
also proves that the current target can be reconstructed under the canonical
grant authority. The proof runs transactionally and is rolled back: a genuinely
empty database resolves to bootstrap, migration `0113` resolves to prepare, and
the complete current repository ledger resolves to exact. An unknown or partial
 ledger, or any noncanonical relation in the closed-world `public` schema, stops
 the restore while the current database and live UUID upload namespace remain
 unchanged. Incoming objects may already exist only in the private hidden
 staging directory and are removed by ordinary cleanup. Keep deployment-specific
 extensions in a separately owned schema with an explicit backup and ACL
 contract; do not add them to Northstar's `public` schema.

The cutover creates a private directory inside the upload volume, copies and
verifies incoming objects there, and keeps old objects there while switching
with same-filesystem atomic renames. A durable journal records each exact UUID,
size and digest before its rename; compensation consumes only those intents, so
an old and new object with the same UUID are not confused. Old objects remain in
that atomic rollback source until a complete verified and flushed copy exists
under the dedicated rollback root.

Immediately before database replacement, restore keeps exactly its three
pre-opened target backends (control, primary replacement and compensation) and
sets the database to `ALLOW_CONNECTIONS=false`. It does not require
`pg_signal_backend` and does not terminate peers: if any other target session
remains, restore rejects the cutover and reopens the unchanged database. Stop
Northstar and every other database client before retrying. Once only those
three verified backend PIDs remain, no new target connection can enter; a crash
therefore fails closed instead of admitting clients to a half-switched data
plane. The replacement
transaction recreates `public` as the verified migrator owner and applies the
same PUBLIC/runtime/backup ACL and default-privilege policy used after
migrations before committing. Incoming data always uses exact reconciliation
against the current release ledger/schema. If an ordinary post-cutover failure
requires database compensation, the pre-restore dump instead uses the
canonical automatic lifecycle resolver so an empty/bootstrap, migration-`0113`
prepare, or exact-current predecessor can be reconstructed without weakening
the incoming-payload contract. Exact old/new manifests before and after upload
activation detect a late filesystem mutation and prevent commit.

Database control and replacement use separate failure domains. The persistent
control backend alone owns the advisory lock, changes the database connection
fence and reads the authoritative outcome. The primary replacement backend and
an independently pre-opened compensation backend execute incoming and rollback
SQL respectively. Any session beyond those three recorded backends aborts
cutover without being terminated. Each
replacement transaction writes a unique database-level
`northstar.restore_commit` marker before a synchronous `COMMIT`. After new
connections are disabled, the control backend verifies that these three
recorded PIDs are the only remaining sessions; PostgreSQL is not configured
with a PID allowlist. A READY phase
first proves that the worker owns a unique transaction-level advisory lock and
that the prior marker still matches. Destructive replacement SQL is not sent
before READY. The control backend must acquire that same transaction lock before
it reads the catalog marker, so EOF is never treated as evidence either way. If
cleanup interrupts an incomplete command stream, it closes and drains the exact
active worker first: PostgreSQL either finishes an already-buffered commit or
rolls back on disconnect, after which the barrier and marker give one
authoritative outcome. A missing marker means the incoming replacement did not
commit, the incoming marker authorizes exact rollback compensation, and an
unknown marker keeps PostgreSQL closed for operator recovery. After the restore
replay floor is durable, the fence still cannot reopen until the exact incoming
marker is cleared; interruption during marker clearing is reconciled explicitly.

`SIGINT`, `SIGTERM`, shell errors and ordinary exits use one compensation path.
If pre-commit compensation or connection re-enable is incomplete, the script
does not delete its plaintext work directory or cutover journal and leaves the
database closed. Preserve every printed recovery path and do not blindly enable
connections. `SIGKILL`, host reset and power loss cannot run shell traps; a
remaining cutover directory intentionally blocks the next normal restore and
requires an operator-reviewed recovery drill. Automatic hard-crash journal
replay is not implemented in this release.

The unique rollback set contains a pre-restore database dump and verified old
uploads. These retained artifacts are plaintext by default even when the source
backup used age. Put the rollback root on encrypted, access-controlled storage
or transfer the complete set into the organization's encryption system. Retain
it until application validation succeeds.

Restore is intentionally not a backup-role operation: it receives the migrator
owner URL only in this stopped, explicit profile. After a successful restore,
run the one-shot `migrate` job and database-role audit before returning
production traffic:

1. run the server on isolated bind addresses with federation disabled;
2. run `sudo docker compose run --rm migrate` followed by
   `sudo docker compose run --rm database-grants`, verify the role/grant audit, then
   verify internal `/readyz` and ensure migrations are current;
3. test SCRAM login, roster, PEP device lists and bundles, encrypted MAM, MUC,
   HTTP Upload, and administration;
4. decrypt sampled history with a retained client device—server backups never
   contain OMEMO private keys;
5. record recovery-point and recovery-time results.

## OMEMO multi-device operational checks

The server stores the OMEMO 2 devices node as a single `current` item and the
bundle node as multiple device-ID items. Both nodes default to open access as
required for first contact and group chat. Other PEP nodes default to presence
access. Publish-options are treated as preconditions, malformed OMEMO payloads
are rejected before an atomic batch write, and device bundle items can be
retracted. PEP headline events are addressed to each subscriber and cross the
S2S router for remote roster subscribers instead of relying on polling.

The browser client reacts to its own device-list notifications. If two devices
publish concurrently and one overwrites the other, the missing device re-reads
the list and reannounces itself, as required by XEP-0384. Consumed one-time
prekeys are replenished with new monotonically rotating IDs rather than reused
IDs. Monitor PEP publication/retraction/retrieval rates when diagnosing device
initialization.

The recorded manual Gajim observation is deliberately narrow. On August 25,
2026, against localhost with the development certificate, `test1`, `test2` and
`test3` authenticated and joined an existing members-only, non-anonymous room;
`test2` sent one message that Gajim displayed as end-to-end encrypted, and the
archive probe contained encrypted content without a plaintext sibling. The
Gajim version was not recorded. This is point-in-time troubleshooting evidence,
not validation of the final release binary, public TLS, every Gajim release or
all OMEMO trust/multi-device transitions. Repeat the client matrix with recorded
versions and retained evidence on the release candidate.

### Browser device-transfer drill

The bundled browser's recovery control is a one-time device move, not a backup.
Before enabling it for users, complete the two-profile and crash-point drill in
[OMEMO_DEVICE_TRANSFER.md](OMEMO_DEVICE_TRANSFER.md): export on profile A,
verify A freezes and disconnects, import on profile B, verify every live/SM path
is cut, and prove A erases and cannot republish after the consumed high-water
generation. Repeat uncertain HTTP responses around prepare, seal and consume;
only the exact transfer/digest/consumer replay may succeed. Test expiry,
revocation, wrong account/passphrase, altered header/ciphertext, rollback to an
older package and loss of the destination during installation. Confirm that B
requires explicit contact re-verification and that no package bytes,
passphrase, derived key or private-state digest appear in PostgreSQL, logs,
metrics, traces or backups. The user must delete every package copy after a
successful import.

## Release checks

Static verification remains:

```sh
bash scripts/release-preflight.sh
```

Static preflight checks formatting, all targets, unit tests, Clippy with warnings
denied, migration-version immutability, Compose/config mapping, dependency
advisories and policy. Its existence is not a statement that it passed for the
current checkout; retain the output and exact commit when cutting a release.

### Tag artifact verification

Pushing the reviewed `v0.2.0` tag runs the release-preparation workflow. Wait
for all binary, image, checksum and attestation jobs to pass. The workflow must
leave a draft GitHub Release containing these files—this list describes the
expected output and is not a claim that it has already been published:

- `northstar-0.2.0-linux-amd64.tar.gz` and the raw
  `northstar-0.2.0-linux-amd64` binary;
- `northstar-0.2.0-windows-amd64.zip` and the raw
  `northstar-0.2.0-windows-amd64.exe` executable;
- `SHA256SUMS` and `IMAGE_DIGESTS`.

Download the complete draft asset set into an empty review directory and run:

```sh
sha256sum --check SHA256SUMS
```

For Windows review, independently compare
`(Get-FileHash -Algorithm SHA256 <file>).Hash` with the applicable entry. Then
verify the GitHub build provenance for every package, `IMAGE_DIGESTS`, and
`SHA256SUMS`; a checksum downloaded beside an asset proves integrity relative
to that file, not build identity by itself.

Extract each complete archive into an empty directory. Confirm the runtime and
license inventory, compare the extracted executable with its raw counterpart,
and run `xmpp-server --version` or `xmpp-server.exe --version`. The result must
be exactly the `0.2.0` build. Windows success is development/evaluation evidence
only and does not change the Linux AMD64 production baseline.

`IMAGE_DIGESTS` must contain exactly the `northstar`, `northstar-backup`, and
`northstar-database-grants` GHCR repositories. Pull each exact digest and verify
its Linux/AMD64 platform, manifest digest, GitHub provenance/SBOM, OCI
source/revision/version/license labels and expected non-root identity. Render
the release Compose override with those digest refs and confirm no Northstar
service retains a local build fallback. Only after these checks and the release
checklist pass may a maintainer publish the draft.

Runtime validation is not an unattended aggregate release command. After
authorization to start disposable isolated services, select each applicable
harness from [the release checklist](RELEASE_CHECKLIST.md) and
[the manual security plan](MANUAL_SECURITY_VALIDATION.md), review its target and
side effects, authorize it separately, and run it alone. Database/wire,
federation, component, browser, backup/restore, cluster, 1,000-resource,
fault-injection and adversarial checks must not share an operator database or be
silently chained by `scripts/release-runtime-validation.sh`. Record the exact
commit/artifact, configuration, environment and result for every selected
harness; the existence of a runner is not execution evidence.

The 1,000-resource harness uses authenticated sessions without initial
presence. When separately authorized, it covers connection/authentication,
addressed full-JID delivery, a bounded SM resume sample, overload recovery and
process/database resource bounds. It is a design/regression envelope, not a
model of 1,000 active users or a production capacity SLA.

DANE public DNS and CA-specific CRL rotation are intentionally operator checks,
not facts established by the isolated runtime gate. Record external preflight,
served-chain, revocation/reload and third-party-client evidence separately.

Run `sudo sh scripts/release-preflight.sh --production` against the real ignored
`.env` and protected external secret root before exposing traffic. In addition to DNS name, expiry and key-match
checks it rejects self-signed/SHA-1/weak-key certificates and private-key modes
other than `0400`/`0600`. It also rejects mutable GitHub Action references,
unpinned container images, secret symlinks and mismatched Compose database
credentials. This is a local gate, not a substitute for testing the served
chain, CRL rotation, DNSSEC/SRV/TLSA, SNI and reverse proxy from an external
network. OCSP/AIA retrieval is not implemented.

The runtime container is UID/GID `10001:10001`, has a read-only root filesystem,
all Linux capabilities dropped, `no-new-privileges`, a PID limit, bounded tmpfs,
and a binary `/readyz` health probe that does not require adding curl or a shell
tool. Caddy, Prometheus and Grafana have corresponding read-only/capability/PID
bounds where their writable named volumes permit it. All Dockerfile bases and
third-party images in the base Compose file are pinned by manifest digest. The
release override defaults to exact `0.2.0` selection tags so it can be rendered
before per-run digests exist; production must replace all three Northstar refs
with the reviewed values from `IMAGE_DIGESTS`. Dependabot or a scheduled
operator review must deliberately update both a human-readable tag and its
digest so security fixes are not silently missed.

Northstar, the backup/restore jobs, and Grafana run as explicit non-root numeric
users. The official PostgreSQL image retains its root entrypoint only long enough
to initialize volume ownership and then drops to its `postgres` user. The
official Caddy image retains UID 0 so it can bind host-facing ports 80/443, but
Compose drops every capability except `NET_BIND_SERVICE`, enables
`no-new-privileges`, and makes its root filesystem read-only. Treat the Docker
daemon and these two audited image entrypoints as part of the host trust boundary;
operators requiring rootless containers should move the proxy to unprivileged
container ports and pre-provision writable Caddy volume ownership.

Every GitHub Action is pinned to a full commit SHA with its release in a comment,
which is the immutable form enforced by GitHub's Actions policy. Review upstream
release notes and update the SHA/comment together; never replace it with a moving
major tag. CI and the digest-pinned builder both assert Rust `1.97.1`; update the
compiler, builder digest and lockfile as one reviewed change. CI generates all
certificate and secret fixtures under `/tmp`, checks
that failures never echo a private-key fragment, and deletes the fixtures on
exit.

## REST history, API documentation and ambiguous operations

`GET /api/v1/history` is an HTTP projection of the same `MamArchiveQuery` used
by XMPP MAM. Bare and full `with` filters, inclusive `start`/`end`, extended
`before_id`/`after_id`/`ids`, and bounded XEP-0059 first/last/before/after/index
pages are evaluated with XEP-0191 visibility and cursor ownership inside one
repeatable-read PostgreSQL snapshot. Direct MAM pages are chronological unless
`flip=true`; `first`, `last` and `first_index` remain chronological regardless
of response order. Existing `with`/`limit`/opaque-`cursor` callers remain
newest-first. Do not add a direction filter until archive admission persists an
authoritative direction and an upgrade can represent old rows honestly; the
current API rejects that unknown parameter.

The exact reviewed `docs/openapi.yaml` is served at `/api/openapi.yaml`.
`/api/docs` serves only local, SHA-256-checked Swagger UI 5.32.14 assets. Its
initializer disables authorization controls, every submit method, credential
persistence and the external validator; its HTML uses a documentation-specific
CSP with `default-src 'none'` and only same-origin script/style/connect access.
Treat it as a read-only reference. Use a separately controlled client for API
mutations and never weaken this policy merely to obtain a convenient Try button.

For a durable administrator mutation, retain the caller-chosen
`Idempotency-Key` and the returned operation ID. If the HTTP response is lost,
retry the exact same method, route, target, media type and body with that key;
the stored response returns the original operation ID and does not enqueue a
second effect. `GET /api/v1/admin/operations/{id}` is the authoritative final
state. The web console also supports exact-ID lookup. For a fan-out operation,
filter `/targets` by `status=indeterminate`, inspect each target's full payload
and result, record secret-free external evidence for each target, then reconcile
the parent. Attempting the parent too early is a stored `409 Conflict`, never an
internal error. Manual success is refused while any target did not succeed;
manual failure may be recorded only after every indeterminate target has been
resolved. Every reconciliation is reauthorized, idempotent and audited with its
own request ID. `indeterminate` never proves success or failure and must not be
used as permission to retry the external effect blindly.

## XMPP administration control plane

XEP-0050 command sessions and the advertised XEP-0133 administration state
are durable in PostgreSQL. An administrator is reauthorized against the
current account status and credential generation when a form is submitted;
demotion, disablement or password-driven session revocation therefore closes
stale command sessions on every node. Invalid form semantics release the
execution claim so the same form session can be corrected. Successful results
are cached for safe IQ retry. An ambiguous crash after a separately committed
business mutation is fail-stop: the server does not automatically replay the
operation, and the audit log plus target state must be inspected.

The REST registration switch and island-mode switch are PostgreSQL settings.
Nodes refresh them once per second; entering island mode stops new federation,
clears local outbound routes and rejects stanzas on already-authenticated S2S
connections. Federation command rules accept domain, bare-JID and full-JID
entities. Domain rules apply to the whole peer, bare rules to all resources of
that account, and full rules to exactly one resource. Static environment
allow/deny policy remains the outer ceiling.

`ENABLE_XMPP_SERVICE_CONTROL=false` remains the safe default. When enabled,
restart/shutdown requires the exact confirmation phrase and a 5–3600 second
delay. PostgreSQL admits only one active generation; every process started
before its database-clock fire epoch observes it and exits. A replacement
service manager must be configured if `restart` is expected to start a new
process—Northstar intentionally cannot override systemd, Docker or Kubernetes
restart policy. Announcements are routed to currently available sessions and
are not persisted in the service-control row.

Welcome/MOTD delivery uses a 30-second PostgreSQL lease. The ledger is marked
delivered only after the stanza enters the connection queue. A crash before
that point is retried after lease expiry; a crash after queue acceptance but
before the database acknowledgement can produce a duplicate, so this path is
at-least-once rather than falsely claiming exactly-once socket delivery.
