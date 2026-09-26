# Northstar Modularization Execution Plan

## 1. Objective

Northstar is being decomposed into capability-free protocol libraries, narrow
application services, repository adapters and separately owned network/HTTP
surfaces. The split is by authority and transaction ownership, not file size.
The root binary remains the composition root and process supervisor.

The target dependency direction is:

```text
composition root
  -> listener / HTTP / protocol adapters
  -> application services and ports
  -> domain policy and XEP wire libraries

PostgreSQL / Redis / object storage / push providers
  -> repository or provider ports
  -> application services
```

No protocol or domain library may depend on the root binary, global state or
an infrastructure adapter.

## 2. Lessons now enforced

1. Extraction and integration are different states. A copied parser is not a
   boundary until root callers use it and the old implementation is deleted.
2. Pure libraries receive prepared facts, clocks and random values; they do
   not acquire capabilities.
3. Cross-feature dependencies belong in the extension graph. For example,
   disabling XEP-0059 disables XEP-0060 and XEP-0313 rather than leaving a
   partial paging surface.
4. Disabled behavior disappears from route ownership, discovery, companion
   HTTP surfaces and workers. Rejecting only after a handler begins is not
   sufficient.
5. One user-visible operation has one authoritative transaction owner.
   Admission, stable identity, archive/offline/outbox projections and recovery
   fences must not be split into independently committed pseudo-services.
6. Queries and mutations use different command types. Read commands never
   enter a post-commit mutation-effect planner.
7. A strong shared type supplies safe projections itself. Callers do not
   serialize and reparse JIDs or encode authority into arbitrary strings.
8. Slow-client, CSI, SM and transport queues use loss-explicit outcomes. A
   library never silently evicts a stanza.
9. A compatibility facade delegates to one implementation. It is not a second
   source of parsing, cryptography or policy truth.
10. Generated or externally contributed code is accepted only after root
    format, test, strict-Clippy and architecture gates.
11. Architecture checks follow ownership when code moves. They inspect the
    owning crate rather than requiring security logic to remain in an obsolete
    root file.
12. Static source parsers used by CI must understand the exact syntax boundary
    they validate. Fixed-length slices are not acceptable route or authority
    evidence.

## 3. Current state

### Completed foundation and XEP integration

The root workspace now consumes all 38 `northstar-*` libraries. Completed
cohorts are:

- foundations: XEP core, XMPP types, XML framing, authentication core, abuse
  policy and web-surface capability resolution;
- message metadata: XEP-0085, 0184, 0308, 0333, 0359, 0380, 0444 and 0461;
- general IQ/discovery: XEP-0092, 0199, 0202 and 0215;
- session features: XEP-0115, 0198 and 0352;
- policy/durable features: XEP-0191, 0357 and 0313;
- paging and services: XEP-0059, 0060 and 0045.
- upload protocol: XEP-0363;
- application command foundations: personal-message command, destination,
  identity-authority and commit-result types.
- safe XML output: typed serialization and bounded validated fragments;
- message synchronization: XEP-0280 controls, copy policy and wrappers.
- privacy and visibility: XEP-0016 first-match policy plus presence-session
  and directed-visibility rules;
- session/delivery foundations: stream-negotiation epochs and durable
  C2S/XEP-0198 fence values.
- room application foundations: owned local/federated discussion commands,
  authenticated actor snapshots, repository injection and ordered bounded
  post-commit effect plans.

The root extension resolver currently owns 24 concrete protocol descriptors
and 56 exclusive wire routes. The leaf crates have no server, database, HTTP
or raw-socket capability imports.

### Completed HTTP-surface separation

Public client/API, loopback administration and private observability are
separate listener tasks. The administration surface is enabled independently
and is validated as loopback-only. Registration capability resolution locks
invitation registration off when its required public web client is disabled.
Upload advertisement, XMPP slot handling and HTTP upload admission are resolved
as one companion capability.

### Remaining structural debt

Leaf extraction is no longer the main risk. The remaining debt is concentrated
in large root orchestration modules and infrastructure ownership:

- messaging still coordinates several delivery/persistence effects through a
  large protocol adapter;
- MUC, federated MUC, MIX and PubSub retain large command dispatch modules;
- cluster/federation code combines transport, lease, cache and recovery
  orchestration;
- upload HTTP, object I/O and reconciliation are separated by fences but not
  yet by crate/port ownership;
- several services still call concrete database modules instead of repository
  traits;
- transport actors still reach a broad protocol session object.

`AppState` now has no public fields, and protocol modules have no
direct `db::`, `PgPool`, SQLx or `state.pool` authority according to the
architecture gate. This is an intermediate boundary, not the final service
graph.

## 4. Target responsibilities

### 4.1 Session kernel

Owns stream phase, authenticated identity, resource binding, route incarnation,
SM state, CSI state and extension slots. It may request authentication/session
services but cannot query PostgreSQL directly. Transport adapters own bytes,
deadlines and socket closure; the kernel owns protocol order.

Required interfaces:

- `AuthenticationPort`: password/SCRAM/FAST verification and generation fence;
- `ResourceBindingPort`: atomic resource claim/replacement;
- `ResumeStore`: create, suspend, claim, acknowledge and teardown SM state;
- `OutboundSink`: ordered send outcome with explicit backpressure state;
- `SessionPublication`: publish/remove exact route incarnation.

### 4.2 Messaging service

Owns the complete personal-message use case: abuse admission, origin identity,
archive policy, local durable delivery, offline spool, S2S/component outbox,
Carbons plan and Push plan. Protocol adapters supply a validated typed message
and map the result to XMPP.

Required transaction result:

```text
MessageCommit
  stable identity
  sender/recipient archive projections
  local delivery records or offline spool
  federation/component outbox records
  post-commit Carbon and Push plans
  recovery/fencing metadata
```

No socket send or provider call occurs while this transaction is open.

### 4.3 Roster and visibility service

Owns roster mutations, subscription state, blocking/privacy precedence,
presence visibility and multi-resource push generations. All local, clustered
and federated presence paths consume the same immutable authorization snapshot.

### 4.4 Room service

Owns neutral room/channel identity, affiliation/role policy, occupant epochs,
room event sequence and durable fan-out plans. XEP-0045, federated MUC and MIX
are separate adapters over this authority. The MUC/MIX bridge is an optional
adapter, never an import from one protocol implementation into the other.

### 4.5 PubSub/PEP service

Owns node/item/subscription mutations, canonical XEP-0059 paging, recipient
snapshots and event outbox. PEP is an account-scoped adapter over PubSub ports.
OMEMO device/bundle nodes retain non-coalescing delivery semantics.

### 4.6 Archive service

Owns personal, MUC and MIX visibility snapshots, MAM preferences, paging,
tombstones and correction/reaction/reply metadata projections. Wire XEP crates
do not rewrite stored XML or decide authorization.

### 4.7 Upload service

Owns slot reservation, capacity, object lifecycle, locator/version/digest
authority, cleanup and reconciliation. XMPP and HTTP are companion adapters.
Object stores implement a versioned byte-store port and never receive account
or database authority.

### 4.8 Federation/component service

Owns authenticated-domain policy, DNS/TLS discovery decisions, durable outbox
leases and route plans. S2S and external components have distinct grants;
connect-mode components never inherit remote-relay authority from transport
connectivity.

### 4.9 Administration service

Owns authenticated commands, runtime settings, service control, idempotency,
operation journal and audit facts. Its HTTP adapter is loopback-only by default
and cannot share the public browser-session audience.

## 5. Ordered execution

### Phase A — Stabilize the integrated leaf graph (current pass)

- keep every leaf crate in the root workspace and lockfile;
- make every registered optional XEP operator-selectable;
- declare real cross-XEP dependencies;
- reject disabled message namespaces at shared ingress;
- maintain unique route ownership and capability scans;
- keep format, all-feature check, root tests and strict Clippy green.

Exit: no extracted-but-unused crate, no duplicate pure implementation and no
unconfigurable optional descriptor.

### Phase B — Messaging command boundary

1. Define `ValidatedPersonalMessage`, `MessageAdmission`, `MessageCommit` and
   typed post-commit effects in `src/services/message` without moving SQL.
2. Make C2S, S2S and component entry points call one service method.
3. Move transaction composition from protocol handlers into the service.
4. Introduce repository traits only after the transaction boundary is stable.
5. Add failure-injection tests for every commit/effect boundary.

Exit: protocol messaging contains parsing/error mapping only; all personal
message persistence paths share one transaction owner.

Current progress: steps 1 through 4 are integrated for the authoritative
commit path. C2S, authenticated S2S and
component-originated personal messages construct the same
`ValidatedPersonalMessage` command and receive the same `MessageCommit`
result. A capability-injected repository port owns the atomic PostgreSQL
adapter, while the application library validates cross-adapter authority
before invoking it. Local durable delivery and federation outbox remain
distinct typed destinations and produce explicit post-commit plans. Remaining
work is failure-injection coverage for provider execution and moving Carbon,
Push and route execution out of the protocol adapter; the existing PostgreSQL
atomic operations have deliberately not been split during this convergence.

### Phase C — Room and PubSub command/query separation

1. Split MUC and PubSub request parsing from command/query application.
2. Introduce bounded command enums and immutable authorization snapshots.
3. Move post-commit fan-out into explicit effect plans.
4. Reuse the same room service from federated MUC and later MIX adapters.
5. Move PEP operations behind the PubSub service without collapsing account
   privacy rules into generic service access.

Exit: large handlers have no transaction composition and no cross-protocol
imports.

Current progress: room discussion admission is the first integrated vertical
slice. Local C2S and authenticated federated MUC paths build the same owned
command. A capability-free authority object binds the canonical bare/full JID,
authenticated local or remote domain, nickname, room epoch, connection and
optional cluster occupancy target. The application layer rejects inconsistent
commands before repository invocation; PostgreSQL remains the final authority
under its existing transaction locks. Request-owned MUC post-commit effects
also moved out of the protocol module into a bounded, sealed, order-preserving
application plan. Subject, moderation/retraction, affiliation, configuration
and registration use typed application commands and atomic service methods.
Remaining room work is to verify any residual join/leave or adapter-specific
path against the same authority and post-commit boundaries.
PubSub/PEP already has core/application crates, typed commands, a service and
repository ports. Its remaining work is a complete command/query boundary and
consolidation of the PostgreSQL adapter, while preserving the transactional
audience snapshot and outbox.

### Phase D — Session kernel and transport ports

1. Separate stream/auth/bind state from SM and CSI extension state.
2. Replace concrete outbound channels with an ordered `OutboundSink` result.
3. Move TCP, direct TLS, WebSocket and BOSH lifetime/framing to transport
   adapters over the same kernel.
4. Preserve BOSH response fences and SM replay ownership during cancellation.

Exit: transports import no concrete XEP handler and the session kernel imports
no socket implementation.

Current progress: the stream-open/SASL/registration epoch is now one
`StreamNegotiation` state machine rather than independent booleans and option
fields. Durable delivery fences, SM unacked entries and recipient-authority
recovery are in a transport-neutral delivery library. The session-facing
sender now owns an injected `OrderedOutboundSink` rather than a concrete Tokio
channel; the Tokio queue is a transport adapter and returns every rejected or
stale item through the loss-explicit port. Resume-store orchestration,
transport action execution, SM/CSI substate isolation and the remaining broad
`ProtocolSession` capability set still need separation.

### Phase E — Infrastructure ports

1. Define repository traits at application-service boundaries, not table
   boundaries.
2. Implement PostgreSQL adapters with explicit runtime/command roles.
3. Define Redis soft-state/cache ports with fail-closed degradation classes.
4. Define local/S3 object ports with exact version/delete semantics.
5. Move provider-specific push clients behind the XEP-0357 delivery port.

Exit: services can be unit-tested with fault-injecting ports and runtime
database credentials cannot perform DDL.

### Phase F — Final composition and release evidence

- make all service handles private and expose narrow accessors;
- remove obsolete compatibility facades;
- update `.env`, README, architecture and XEP matrix from one capability list;
- run PostgreSQL/Redis integration, browser, federation, component, transport,
  load, fuzz, backup/restore and release packaging gates;
- record remaining deliberate compromises in `KNOWN_ISSUES.md`.

Exit: source graph, runtime switches, documentation and artifacts describe the
same system.

## 6. Work-packet acceptance criteria

Every packet must identify owners for authorization, persistence, time,
randomness, delivery and background work. It must also prove:

- no reverse dependency or forbidden capability import;
- bounded byte/collection/depth/work inputs;
- strict duplicate/ambiguity validation and structural XML output;
- typed errors with no production `unwrap`, `expect`, `panic`, `todo` or
  `unimplemented` escape;
- commit-before-effect ordering and recoverable indeterminate effects;
- disabled routes/features/workers/HTTP companions fail closed;
- no nested `Cargo.lock`, `[workspace]` or tracked `target` directory;
- root format, tests, all-feature check and strict all-target Clippy pass;
- architecture and plugin-manifest gates pass;
- documents and configuration are updated in the same packet.

Environment-dependent tests are required before release, but they are not
replaced by static/unit evidence.

## 7. Ordered service, role and recovery work

The next work follows four stages on `dev`. Each stage preserves existing
transaction guarantees and must pass its regression and CI gates before the
next stage changes runtime behavior. The issue ledger remains
[KNOWN_ISSUES.md](KNOWN_ISSUES.md).

| Stage | Deliverable | Exit evidence |
| --- | --- | --- |
| 1 — ARCH-SVC | Inject existing use-case repository ports, move persistence adapters into `src/db`, and replace broad business HTTP route and background-worker state with narrow contexts | No raw SQL or transaction handles in application services or transport adapters; no broad state hidden in business API/worker contexts; AppState public capabilities reach zero; rollback and post-commit failures retain their existing semantics |
| 2 — ARCH-DB-ROLE | Separate database identities and pools by transaction responsibility | Per-role negative SQL tests, exact routine/ACL attestation, bounded aggregate connection budgets, and existing-volume upgrade/restore rehearsals |
| 3 — ARCH-CLU-MUC | Atomic legal batches of role and affiliation operations | Consistent single-node/cluster authorization, exact occupant generations, final-owner protection, stable events/audiences and whole-batch rollback/retry tests |
| 4 — storage and restore | Resumable offline Local/S3 migration, verifiable S3 backup/restore, and independently restartable restore recovery | Exact object-version manifests, fenced cutover, durable commit evidence, retained rollback data, and interruption tests at every durable transition |

Stage 1's business HTTP and background-worker boundary is complete.
Application services keep SQL and transactions in database adapters, and
startup metadata queries follow the same boundary.
`AppState` has no public fields, and protocol handlers have no direct database
authority. Local and federated MUC use scoped operations. HTTP registration,
login, Passkeys, OMEMO recovery and upload routes use narrow contexts.
Post-commit password, Passkey-removal and OMEMO-recovery teardown uses typed
local-route, durable-SM, generation-read and cluster-notification capabilities.
Failures after the credential commit are logged without undoing that commit.

Session cleanup stores only typed handles, though its constructor still takes
`Arc<AppState>` to assemble them. The cluster listener separates admission,
signed ACKs, local dispatch and exact session/MUC effects. Its failure
supervisor and maintenance paths have separate authority and Redis handles.
The ordinary operation worker claims, renews and fences work through
`OperationWorkerControl`; session, TLS, island, MUC-destroy and panic effects
have dedicated handles. The composition root builds `OperationWorkerRuntime`
before `serve` starts. Roster's deferred flush retains one failure counter;
the S2S outbox worker uses a dispatch context for claims, policy, retry and
bounce. New outbound connections still enter the broad TLS/DNS/SM transport
actor. HTTP transport rejection, OMEMO recovery polling, account-deletion
roster push and local session cleanup now retain only their required shared
counters. Background maintenance, durable-SM expiry, locked-room expiry,
runtime-control refresh, CAPS effects, MIX relay/recovery/outbox, and PubSub
digest/event outbox delivery now use purpose-built worker contexts. They keep
the existing claim, lease and post-commit ordering. Transport actors still
share broader state; their session-kernel and transport-port split belongs to
Phase D. The Stage 1 architecture checks and all jobs in CI run #318 passed
for commit `15aa311`.

Stage 2 assigns upload lifecycle SQL to a separate `northstar_storage` role and
two-connection pool. The runtime role retains only its upload-disabled probe
and administrator dead-letter commands. Fresh and existing PostgreSQL volumes,
negative privilege probes, and backup/restore rehearsal passed locally. All 30
jobs in [CI run #320](https://github.com/takanashi-tetsuya/northstar/actions/runs/35906755288)
passed for the storage-role fixture fix at `a49b846`.

Stage 3 routes local and federated MUC administration through one ordered,
bounded PostgreSQL batch. Its transaction checks actor and occupant generations,
permissions and the final owner before writing every change with one immutable
event and audience. Both standalone and clustered servers use PostgreSQL room
authority; Redis remains a cross-node transport cache. Standalone occupancy
renewal uses exact batches of at most 128 local actors and removes their local
authority if a full verification cannot complete within the 90-second lease.
Maintenance removes only the MUC projection after a committed room departure;
an expired lease or ownership mismatch still disconnects the C2S session.
Exact disconnect cleanup leaves the PostgreSQL occupancy without duplicating
the committed outbox presence. Five isolated PostgreSQL fixtures and the
standalone and two-node protocol suites passed locally. All 31 jobs in
[CI run #328](https://github.com/takanashi-tetsuya/northstar/actions/runs/35924924937)
passed for commit `61ee355`.

Stage 4 adds an offline Local ↔ S3 migration command with a durable attempt
journal. It verifies source bytes, pins S3 versions, rereads every destination
before the atomic locator and authority switch, and retains source objects and
retired attempts. Runtime startup rejects an active migration, while stopping
already-running nodes remains an operator precondition. S3 backup format v3
binds an exact-version inventory to the signed archive; restore writes fresh
keys and remaps locators in one database transaction. A separate recovery
command uses the fsynced journal, transaction status and same-transaction
outcome marker to decide whether to complete or compensate a crashed restore.
The isolated PostgreSQL 17 and versioned MinIO migration fixture passed both
directions, ambiguous-write retry and missing-version rejection locally.

### Transaction and authority map

A repository operation represents a complete use case rather than one table.
The application owns the transaction intent; the PostgreSQL adapter owns the
connection, locks and commit. Neither SQLx transactions nor a general pool
cross the application port. Network and object-store I/O occur outside database
transactions. Cross-domain atomic operations retain one database transaction.

| Use case | Must commit together | Authority needed before splitting roles |
| --- | --- | --- |
| Personal message admission | Stable identity, archive projections, C2S/offline delivery or federation outbox | Current account and privacy policy, message/archive admission and bounded delivery queues |
| Roster mutation | Credential-generation check, roster/version changes and removal notifications | Account fence, roster state, local presence or exact federation outbox admission |
| MUC discussion/administration | Actor/occupant checks, room changes, sequence, audience and event outbox | Room policy, account/occupancy generations and per-room delivery records |
| PubSub/PEP mutation | Account/node policy, items or subscriptions, recipient snapshot and event outbox | Narrow account/roster visibility plus node/item/outbox writes; OMEMO events remain non-coalescing |
| Upload reservation | Account eligibility, quota/capacity ledger and bearer hash | Narrow account admission, storage namespace generation and upload reservation capability |
| Upload reconciliation | Exact object/fence/job transition and capacity obligations | Storage queue leases and locator metadata; object bytes stay outside SQL transactions |
| Passkey login | Credential revision/counter acceptance, generation-bound FAST issuance and API session creation | Authentication/session capabilities, with no transaction returned to HTTP code |
| REST administrator mutation | Session/generation authorization, idempotency journal, business change and result | Purpose-specific command capability rather than a generic administrator pool |
| Account revocation/deletion | Authority generation/revocation record and required durable cleanup intents | Reviewed cross-domain mutation capability; do not replace it with independently committed service calls |
| Retention and background delivery | Exact claim/fence completion and cleanup obligations | Dedicated worker operations, not every table in the associated foreground domain |

Repository ports now cover Roster, upload reservation, Messaging, MAM, Passkeys,
MUC, MIX, Profile, PubSub/PEP, Blocking, Privacy, Push, private XML storage, Presence,
offline/BOSH replay, stream management, account lifecycle, authentication, administrator commands
and personal-message retractions. Their PostgreSQL adapters live in
`src/db`; retention and subscription cleanup use narrow repository-backed
contexts. Upload reconciliation also has a dedicated context and repository
with the same storage fences and one-use startup audit handoff.
SM suspension recovery has a separate context sharing the existing MUC endpoint
maps and capacity leases. Its port exposes only suspension, suffix append and
exact MUC suspension transitions. Session cleanup retains typed delivery and
teardown handles after construction, without direct database calls.
Existing cross-table transactions, admission permits, account
fences and post-commit recovery behavior remain intact.

REST identity, history, user/report/invitation/dead-letter collections and
server statistics and operation-journal reads use complete query transactions. Those handlers receive
shared projections and a query context with live policy flags, without an
open transaction or AppState.
OMEMO transfer lifecycle operations and authorized recovery reads also use
repository ports. Public completion polling has a separate service/context
with shared bounded admission and its dedicated connection pool. Authenticated
recovery handlers use a separate post-commit account teardown context.
Report and appeal writes now use complete repository transactions, including
one-use proof admission and idempotent responses. Their HTTP context exposes
only identity lookup, submissions, trusted proxies and commit counters. Shared
mutation values preserve the same initial and replayed responses.
Operation cancellation/reconciliation, moderation decisions, invitation
management and upload retry now use complete command ports and service-only
HTTP contexts. Their shared database admission receives live cluster health
without Redis publication authority. User/MUC retention policy endpoints use
a dedicated policy context; policy reads now hold exact bearer/account locks
through the snapshot. TLS reload, panic disconnect, island mode, room
destruction and broadcast use an administrative dispatch service and a single
repository transaction for their operation and side records. User status,
registration, session kick and offline clearing now use narrow command ports;
the repositories retain cleanup intents and transport-owned queue checks in
their transactions. Deployment capacity renewal and expiry cleanup use a typed
maintenance service and PostgreSQL repository. The renewal context
keeps only the shared route map needed to snapshot exact cancellation tokens;
the reaper has no session-map authority. Legal holds and governance exports
now use complete repository operations, including cursor validation on the
owned transaction and bounded response replay before commit. Remaining
runtime commands still need their own boundaries.
Public configuration and host metadata now read a narrow discovery context;
transport and administrator gateway middleware receive only their required
policy and verifier. The discovery context shares the live registration and
island-mode flags, so administrative changes remain visible without broad state.
The database-backed metrics collector now calls a snapshot service; one
repository transaction reads all gauges, while the endpoint retains its
existing deadline and failure response. Process and stream-recovery gauges
are copied into narrow snapshots before rendering; the HTTP adapter no longer
reads the corresponding public state fields.
HTTP registration now routes reservation, the pre-hash PoW/idempotency guard,
account publication and exact 201/400 response replay through `AccountService`
and its PostgreSQL repository. Reservation and guard each commit before password
derivation; publication runs in a new transaction, and a retryable worker or
database failure yields the lease without erasing the committed guard marker.
REST login retains pre-hash abuse admission, credential verification on replay,
and atomic API-session creation behind a dedicated service and repository. Its
HTTP handler now receives that service, trusted-proxy policy and only the two
outcome counters it can update, without the application-wide state.
Logout has its own audited session command. Upload claim, staged promotion,
replay, public read and deletion now pass through the upload lifecycle port;
the service is available in drain-read-only mode for historical reads and
deletion, while new reservations remain disabled by the route policy. Public
GET has a read-only HTTP context sharing the existing download admission and
guarded object store; the body task retains its permit until streaming ends.
REST password changes now use a dedicated command service and PostgreSQL
repository for replay lookup, bearer and generation locks, proof admission,
password preparation and conditional credential publication. The HTTP adapter
maps typed outcomes and performs local session disconnection after commit.
The administrator MUC-destroy worker now validates its room command in an
application service and commits the exact intent, room mutation, intent removal
and audit fact through one repository transaction. The signed wake and local
occupant cleanup still run only after that commit.
Readiness persistence checks use an immutable cluster-instance snapshot. The
`/readyz` endpoint receives read-only runtime probes and the persistence
service rather than `AppState`; its cache, deadlines and live rechecks stay at
the HTTP boundary. Inbound S2S roster visibility reads use a scoped
authorization port.
Inbound S2S presence, IQ and message adapters also use the existing presence,
messaging, profile and PubSub ports for recipient and policy reads. S2S stream
management and outbound/component dispatch use fenced outbox services for
renewal, acknowledgement, claims and retries. Administrator session-cleanup
leases and the operation point-of-no-return transaction use separate worker
services; effects still start after the durable fence commits. XEP-0215
service selection and authorization now belong to the ExtDisco service.
Background housekeeping retains five independent database cleanup steps behind
a worker context. The account-revocation worker receives a typed consumer,
local route revocation handle and narrow cluster failure reporter rather than
`Arc<AppState>`. It reads the current cluster-instance epoch for each batch
and uses that identity through read, local fencing and exact revision
acknowledgement.
Message admission, challenge issuance/cleanup, SASL penalties and Passkey proof
checks now expose separate grants over the anti-abuse owner, removing the
public `AppState.abuse` field. Inbound S2S offline admission and best-effort
history now use the message service. Administrator target claim, lease renewal,
settlement and parent terminalization use a journal worker service. Its
initial claim and target snapshot now share one repository transaction;
the live-session snapshot is taken only after a successful claim.
The signed cluster session-termination listener reads durable route authority
through a dedicated service and repository. It checks the live local instance
after that read, then retains connection fencing and acknowledgement ownership.
Peer-key and node-instance refresh use a separate cluster authority service;
the PostgreSQL validation and cache reads finish before the Redis maintenance
touch, and the failure supervisor retains its existing short-circuit order.
The failure supervisor runs bounded session-route cleanup and authority
validation through one ordered maintenance port. Replay cleanup and capacity
validation use a separate ordered port before the route check. C2S post-action supervision
receives only its five counters, including the abort and drop paths; the
unused broad C2S runtime wrapper has been removed.
Clustered-MUC audience delivery keeps its network timeout, database admission
turn and result counters in the worker, while ordered preclaim maintenance,
atomic node-scoped claims and exact ACK/retry settlement use dedicated
repository ports. Locked-room expiry
also commits tombstones and terminal outbox records through one service port;
the worker cleans up local occupants only after that transaction succeeds.
Node-local MUC occupancy reconciliation reads one purpose-specific PostgreSQL
snapshot and renews each exact actor with the same 90-second lease before
refreshing Redis soft state. Room destruction validates the local domain held
by its service before committing the operation; post-commit wake and occupant
cleanup remain in the worker.
MUC outbox dead-letter cleanup, history cleanup and snapshot remain three
separate database turns behind a housekeeping port. Each stable delivery item
checks completion before transport and commits completion only after its
receipt. Shutdown releases the exact node-instance lease through a separate
command service while the signed-publication fence is held.
Cluster message contracts now verify their C2S or MIX source through a
repository port; volatile and identity-free legacy messages avoid database
reads. The shared PostgreSQL pool is private to `AppState`.
Message admission finalization now passes only the issued lease's acceptance
fence to its repository. The repository owns the advisory lock, row lock,
constant-time payload check and commit after delivery. The initial admission,
one-use challenge consumption, capacity reservation and challenge issuance
also commit through database adapters; the guard retains policy and signing.
S2S ingress now reads the validated local domain through a narrow state method
rather than the application configuration.
Component transports receive only active-connection and outbox-duration metric
cells. Session presence and binding paths release map guards before awaiting
privacy checks or lease cleanup, then recheck the exact connection before
delivery.
The private metrics endpoint now receives a read-only MetricsContext for
authorization, bounded database snapshots and live gauges. Administrator
broadcast target capture and exact delivery use LocalBroadcastRoutes; the
session-kick effect has a separate exact-incarnation cancellation handle. The
user-session-cleanup effect can cancel only matching account and credential
generation routes. Emergency disconnect cancels all local routes before its
separate durable SM teardown. The operation worker assembles its effect handles
from broad state at startup; its claim loop and effect execution use those
handles.
Background housekeeping receives only its two shared counters. Archive
retention holds ten shared counter cells rather than the metrics registry.
The periodic anti-abuse key guard calls a single validation probe under its
existing timeout. Background housekeeping receives its repository and policy
through a state-owned factory instead of taking the shared pool from main.
Archive retention and subscription cleanup each receive their own repository
context from the same private pool owner, preserving separate workers and
readiness checks.
S2S ingress/egress, C2S stream/authentication and SM resume,
roster/privacy/blocking side-effect reporting, registration/account abuse,
Push, component transport, and PEP/PubSub delivery use borrowed counters and
timers instead of the complete registry. Caps effect admission and completion
also receive only their four counters/timer; cross-node presence replay failures
receive one counter. MUC authority and post-commit delivery reporting use a
MUC-specific set of counters; MIX post-commit delivery reports its two counters
through a separate port.
Passkey login completion receives its service without the broader HTTP state;
it checks the live allowed origin before consuming the challenge.
Account-deletion recovery reports successful completion, failure and lost
leases through three borrowed counters.
Remaining work includes broad transport entry points.
TLS now sits behind a private context with immutable handshake snapshots and
the existing current-CRL registration check. Federation outbox admission now
uses an application service and a database repository; callers receive a
copied policy and post-commit wake capability. Metrics updates now pass through
event-specific state methods while observability rendering retains its private
registry. The cluster manager is private to `AppState`. Transport actors that
still receive broad state are tracked by Phase D.
Clustered-MUC delivery now obtains its committed event and audience projections
through a read port while keeping the cached-recipient fast path and three
independently admitted database reads in the transport worker.
Administrator room destruction now clears only the committed audience's exact
local occupant incarnations, so delayed cleanup cannot erase a recreated room.
Abuse admission transactions now remain inside PostgreSQL adapters rather than
passing SQLx transactions through the policy guard. XMPP extension and stream
management policy reads use narrow state methods or immutable snapshots.
Registration, voice and administrator MUC updates compare the exact occupant
connection and epoch before changing the local projection. Presence refresh
and nickname changes now use the same exact identity boundary. Join, departure
and clustered projection updates also compare the occupant incarnation;
an unpublished committed join receives a targeted compensating leave.
The abuse guard's persistent operations now use a typed PostgreSQL port that
owns its pool. BOSH, component transport, upload HTTP, session cleanup and
additional protocol adapters read subsystem policy snapshots rather than the
application configuration directly.
Presence, personal-message and MIX transport adapters now use purpose-specific
cluster routes. Resource binding, SM resume and administrator teardown use
exact session-route commands; MUC join and leave use exact Redis projection
operations. The cluster listener now has separate admission, signed-ACK and
dispatch capabilities. MUC command adapters and other worker composition
paths still need narrower runtime ownership.

Role names follow this map after the transaction boundaries are stable. Each
cross-domain operation must either have one narrowly authorized transaction
owner or a reviewed typed routine. Pools must not regain union privileges
through role inheritance or unrestricted role switching. Capacity includes all
nodes, background observers and rolling-upgrade overlap. Separate credentials
inside one OS process limit SQL authority but do not isolate a compromised
process.

MUC batching continues to reject an individual item containing both `role` and
`affiliation`, as required by XEP-0045. Legal batches need explicit duplicate
and conflicting-target rules, authorization against the original authority,
final-state validation and consistent room/occupancy lock order. Repeatable
read alone is not an authorization or serialization guarantee. Single-node
in-memory role updates must converge with the durable cluster model before a
SQL transaction can cover the complete operation. A batch's operation identity
must depend on the authenticated stream and IQ identity, not on a nickname's
current occupant; the canonical request digest detects reuse with new content.

Storage migration first requires maintenance mode, bounded copying to immutable
destination keys, a durable manifest/checkpoint and complete version/size/SHA-256
verification. Locator and namespace activation share a database cutover; object
copying is not part of that atomic commit. Source cleanup is a later explicit
operation. S3-to-Local migration requires a single-node destination. Backups
must include an independently protected, version-pinned S3 object manifest and
verify every object on restore; a database dump alone is not a complete S3
backup. After new writes begin, rollback requires a fresh reverse migration.

Restore recovery reuses the existing fsynced XID intent and transaction barrier.
A restartable tool must verify database identity/lineage, restore generation,
journal and exact object locations before resuming or compensating. It must
also support controlled maintenance reconnection while the workload fence is
active. Each replacement transaction needs a durable marker binding the exact
restore ID and manifest digest to its outcome, and trusted restore state must
record that digest independently of its monotonic rollback floor. A missing or
old XID outcome without matching transaction evidence, a damaged journal, or
conflicting evidence keeps the fence and recovery artifacts intact.

## 8. Next execution plan: domain convergence and release qualification

This plan extends Phases C–F without restarting completed extraction. The
`northstar-pubsub-*` and `northstar-archive-*` crates already exist; the
`StreamNegotiation` state machine and `OrderedOutboundSink` are already used.
The work is to finish their call paths and remove duplicate policy, not to add
another set of crates. Track implementation and external evidence separately in
[KNOWN_ISSUES.md](KNOWN_ISSUES.md). A green CI run cannot close an external gate.

### 8.1 Ordered implementation packets

| Order | Packet and change | Exit evidence |
| --- | --- | --- |
| C1 | PubSub/PEP: give read queries and mutations separate application methods and repository capabilities; move pure node policy and bounded traversal to the existing core/application crates; consolidate duplicate adapter logic in `src/db/pubsub.rs` and `src/db/pubsub_repository.rs` only after callers move | Publish, subscribe, node mutation and query paths use the service; no protocol SQL; lock-order and concurrent privacy/roster/access-change tests pass; query paths cause no mutation effects |
| C2 | Archive/MAM: move pure scope authorization and RSM validation/projection into the existing archive crates; keep SQL execution in the PostgreSQL adapter | Personal, MUC and MIX MAM queries preserve exact visibility, stable page ordering/count/first/last, tombstone behavior and bounded result sets; failure and concurrent-authority tests pass |
| D1 | Session/transport: narrow `ProtocolSession` capabilities, move transport action execution to TCP, direct TLS, WebSocket and BOSH adapters, and isolate SM/CSI substates around the existing ordered outbound port | Each transport passes stream/auth/bind, cancellation, backpressure, reconnect and SM replay tests; BOSH response fences and exact route incarnation remain intact; the kernel imports no socket implementation |
| R1 | Restore and backup hardening: make interrupted restore recovery restartable, bind journal, database lineage, restore ID and manifest digest to durable commit evidence, and protect rollback material | Hard-kill tests at each durable boundary resolve to safe resume/compensation or retain the fence; encrypted rollback backup and key recovery are drilled; ambiguous or old XID status fails closed |
| R2 | Certificate revocation: specify PKIX/DANE and inbound/outbound trust policy first; prototype operator-supplied, freshness-checked OCSP stapling before considering bounded online retrieval | Valid, revoked, stale, unavailable and malformed responses have documented fail policy and TLS interoperability tests; no certificate-provided URL is fetched without explicit source and network policy |
| R3 | WASM provenance: reproduce the deployed `libomemo.js` and `hash-wasm` bytes from pinned source and toolchains in isolated builders | Two independent builds match the shipped bytes, with recorded source/toolchain digests, SBOM and offline verification; until then the status remains `provenance-traced-not-reproducible` |

C1 uses one authorized root-discovery query instead of repeated per-node reads.
Node, item, subscription and affiliation queries have separate repository
capabilities from their mutations, and service reads require only those query
capabilities. Subscription expiry policy receives the observation time from its
caller. Service prechecks and the PostgreSQL transaction share subscription
admission policy; the transaction still re-reads affiliation before commit.
PEP node, item and subscription reads now have separate repository capabilities
from their mutations. PEP access checks require only the node query capability,
and the durable event/digest methods require the outbox capability. PubSub and
PEP commands require their respective query and mutation ports; the obsolete
aggregate repository trait has been removed. The isolated PubSub fixture now
exercises node, discovery, item, subscription, affiliation and PEP queries on a
connection with PostgreSQL's default transaction mode set to read-only. The
existing concurrent authority tests still apply to their mutation paths.
C1 passed the read-only PostgreSQL fixture and full CI on `a7859ed`
([run 36219774226](https://github.com/takanashi-tetsuya/northstar/actions/runs/36219774226)).
Pure publish-option and payload admission now lives in the PubSub application
crate; the service still checks authorization first for existing nodes before
exposing policy errors. The apparent base/`with_renderer` pairs in
`src/db/pubsub.rs` are test-only entry points over the production transaction
functions. `src/db/pubsub_repository.rs` supplies the application port and
error mapping, not a second SQL implementation, so merging those layers would
remove a useful boundary without eliminating production queries.

C2 shares MAM page-size and filter limits across the wire parser, application
service and PostgreSQL adapter. Archive core now plans the RSM window for
personal, MUC and MIX queries and applies one completion/order rule to their
fetched pages. MIX uses the selected row's timestamp and ID to compute its
first index without re-reading that row. Cursor resolution, authorization,
counting and page execution remain in the same database snapshot. Archive
queries, preference updates and atomic federated outbox admission now require
separate repository capabilities. Local and federated room readers share a pure
visibility decision while retaining their distinct locks. Legacy room reads
can still initialize a missing occupant-ID secret; the query capability is
therefore not a claim that every SQL statement is read-only.
D1 no longer stores a second WebSocket flag alongside the transport kind. The
TCP and WebSocket action executors now have separate adapters. Plain TCP and
direct TLS share the TCP adapter; both adapters retain their existing write,
authentication-publication and SM replay order. BOSH still executes its
transport-specific actions in its own adapter module, with RID ordering and
response fences retained by the actor. CSI now owns its state machine and
deferred outbound queue as one private session substate. SM counters, leases,
the replay queue and resumption state share a private session substate.
Transport adapters can forbid resumption or check whether an SM session exists
without editing those fields directly. Direct TLS and STARTTLS now build
channel-binding and client-certificate evidence before atomically activating
the secure session state. The C2S wire suite checks SM replay of an
unacknowledged IQ reply in both directions between Direct TLS and STARTTLS.
These are completed slices, not packet exit claims.

Federated MUC now rebinds an existing local occupant to a new authenticated
S2S connection through an exact PostgreSQL occupancy transition. The
transaction rechecks the remote affiliation, advances the connection fence and
transfers pending delivery before the local projection changes. This covers a
reconnect to the same owning node; cross-node recovery and third-party
interoperability remain part of `EXT-CLUSTER` and `EXT-FEDERATION`.

R1 already has a restartable local/S3 recovery command, durable XID and
same-transaction markers, and isolated pre/post-commit hard-kill drills. Its
remaining work is protected rollback storage, independent key/state recovery
and target-environment drills; an expired or ambiguous XID remains fail-closed.

C1 and C2 precede D1 because they close application authority boundaries before
the wider transport split. R1–R3 are independent hardening packets and can run
after their own test fixtures are ready; they need not hold up unrelated code
refactoring. Every runtime-changing packet must meet section 6's checks before
the next packet changes the same authority path. Record baseline query latency,
lock wait, outbox lag and transport cancellation behavior before changing them.

**PubSub transaction rule.** A publish mutation must capture authorization,
audience and durable outbox intents under the existing PostgreSQL transaction
and lock order. The post-commit plan may dispatch the committed intents; it
must not recalculate the authorized recipients from newer state. Otherwise an
unsubscribe, block or policy change racing a publish changes who receives that
event. Do not claim that CQRS alone removes lock contention: measure and
optimize bounded work within the transaction without moving authority outside
it. Commands and queries may share the same PostgreSQL database and do not
imply eventually consistent replicas.

**Archive consistency rule.** Admission, visibility and the rows forming one
MAM page must use the same authorized query snapshot where the existing path
requires it, including federated room streams. Extracting pure RSM policy must
not turn a page into separate, inconsistent database reads.

**Restore rule.** `pg_xact_status(xid8)` reports recent transaction outcome;
it does not reconstruct replaced data and may return `NULL` after status
retention expires. Keep protected rollback data and durable same-transaction
markers. If the journal, lineage or outcome is ambiguous, preserve the fence
for operator recovery rather than promising unconditional roll-forward.

**R2 revocation profile.** The first OCSP mode is an operator-supplied response
for Northstar's own TLS certificate. Before rustls staples its bytes, reload
must verify the response signature and responder authority, exact issuer and
serial, `good` status, and a bounded `thisUpdate`–`nextUpdate` interval. A
configured response that is revoked, stale, malformed or for another leaf is
rejected; the last valid TLS snapshot remains active, and a strict stapling
profile stops new handshakes when that snapshot's response expires. Outbound
S2S may later require a verified stapled response under an explicit strict
PKIX profile, including PKIX-EE. DANE-EE does not inherit CA revocation. An
XEP-0487 pin must not bypass an enabled PKIX revocation rule; C2S client
certificate authentication keeps its separate CRL policy. No mode may fetch a
URL supplied by a peer certificate. Any future online source needs an operator
allowlist, address and redirect controls, bounded time/size/cache, and a stated
policy for missing responses. Test `good`, `revoked`, `unknown`, missing, stale,
wrong-issuer and invalid-signature responses against TLS 1.2 and 1.3 before
advertising support. See [RFC 6960](https://www.rfc-editor.org/rfc/rfc6960),
[RFC 6066](https://www.rfc-editor.org/rfc/rfc6066) and
[RFC 7673](https://www.rfc-editor.org/rfc/rfc7673).

### 8.2 Isolated VM qualification on a frozen release candidate

Freeze the candidate commit and record the binary/container digest, schema,
configuration, topology, dependency/client versions and raw logs for every
run. Set pass thresholds and RPO/RTO targets before running tests. A failure
creates a code or operations packet, followed by a new candidate and a rerun
of affected gates. Run the federation and infrastructure tests on an isolated
libvirt network with no route to the public Internet. Use separate VMs for
Northstar nodes and independently implemented XMPP peers; two Northstar VMs
alone do not establish interoperability. The lab layout and evidence format
are in [LOCAL_VM_QUALIFICATION.md](LOCAL_VM_QUALIFICATION.md). Close each of
the seven existing evidence rows only for the tested lab profile:

| Gate | Required target-environment evidence |
| --- | --- |
| `EXT-CLUSTER` | PostgreSQL, Redis and S3/MinIO multi-node tests with asymmetric partition, failover, lease loss, rolling upgrade and hard-kill; verify MUC occupancy, presence, delivery and measured RPO/RTO. Keep multi-node `Experimental` until this passes. |
| `EXT-FEDERATION` | In isolated VMs, run an authoritative DNSSEC/SRV/TLSA zone, an IPv4/IPv6 network and a lab PKI; test PKIX/DANE and bidirectional S2S against fixed Prosody and ejabberd versions, including certificate rotation and negative cases. |
| `EXT-COMPONENT` | Real XEP-0114 accept/connect and XEP-0225 peers; exercise STARTTLS where applicable, restart, backpressure, retries and duplicate boundaries. |
| `EXT-CLIENT` | Run fixed browser, Gajim and Dino versions on the lab network with a trusted lab CA. Run Conversations in an Android VM if available. Record Monal as untested until an Apple device can join the isolated network; check supported login, OMEMO 2/trust, Carbons, CSI/SM and MAM with explicit deviations. |
| `EXT-OPERATIONS` | Exercise alert delivery, encrypted backup, restore, upgrade and rollback in the lab with named operators and measured recovery times. A backup on another VM on the same host is not off-site evidence. |
| `EXT-CAPACITY` | Run representative presence, OMEMO, MUC, MAM, upload, Push and S2S workloads in the lab, including a 24–72 hour soak; capture RSS, queue lag, database WAL/IOPS, p95/p99 and saturation limits. Qualify only this host and VM allocation. |
| `EXT-SECURITY` | Give an independent reviewer the frozen candidate, threat model, privileges, browser crypto and exposed protocol topology for review and a lab penetration test; triage and retest findings. Internal tests do not close this gate. |

These gates qualify only the tested VM topology and feature profile. The lab
does not validate public DNS propagation, public CA issuance, Internet routing
or real off-site disaster independence. Record these as untested deployment
boundaries, not as failed lab tests or completed production evidence. Closure
of all seven does not silently close separate product gaps such as
`PROFILE-REVOCATION`, `SUPPLY-WASM`, `OPS-BACKUP-COMPAT` or provider-specific S3
limits. A production-readiness claim must name its supported deployment mode
and remaining exceptions.

### 8.3 Optional product expansion after core qualification

1. Finish the XEP-0357 **server role** first: publish bounded notifications to
   client-selected XMPP push services and verify registration, retry, privacy
   and offline-spool behavior. An FCM/APNs/WebPush gateway is a separate,
   opt-in service requiring client-provider credentials; push wakeups do not
   replace durable message storage.
2. Complete XEP-0447/0448 metadata, encrypted-source and S3 interoperability
   tests. Treat resumable chunked upload as a separate transport feature with
   its own integrity, quota and cleanup design. Validate provider versioning,
   retention and legal holds before promising exact expiry deletion.
3. Qualify the existing XEP-0487 JSON host metadata endpoint and S2S consumer
   with public deployment URLs and real clients. Preserve existing DNS and TLS
   fallbacks and security checks; do not count endpoint presence as adoption.

The XEP-0357 specification is Deferred, while XEP-0447/0448 and XEP-0487 are
Experimental. Keep their advertised support and production claims matched to
the implemented profile and interoperability evidence.
