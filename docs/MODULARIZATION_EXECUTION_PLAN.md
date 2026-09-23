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

`AppState` has been reduced to nine public fields and protocol modules have no
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
application plan. Subject, moderation, affiliation, join/leave and room
configuration mutations still need to converge on the same repository port;
PubSub/PEP command/query separation has not started.

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
| 1 — ARCH-SVC | Inject existing use-case repository ports, move persistence adapters into `src/db`, and replace broad API/worker state with narrow contexts | No raw SQL or transaction handles in application services or transport adapters; no broad state hidden in contexts; AppState public capabilities reach zero; rollback and post-commit failures retain their existing semantics |
| 2 — ARCH-DB-ROLE | Separate database identities and pools by transaction responsibility | Per-role negative SQL tests, exact routine/ACL attestation, bounded aggregate connection budgets, and existing-volume upgrade/restore rehearsals |
| 3 — ARCH-CLU-MUC | Atomic legal batches of role and affiliation operations | Consistent single-node/cluster authorization, exact occupant generations, final-owner protection, stable events/audiences and whole-batch rollback/retry tests |
| 4 — storage and restore | Resumable offline Local/S3 migration and independently restartable restore diagnosis/recovery | Full manifest verification, fenced cutover, retained rollback data, and interruption tests at every durable transition |

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
exact MUC suspension transitions. Session cleanup no longer calls the database
directly, but still needs a narrower runtime context for delivery and teardown.
Existing cross-table transactions, admission permits, account
fences and post-commit recovery behavior remain intact.

REST identity, history, user/report/invitation/dead-letter collections and
server statistics and operation-journal reads use complete query transactions. Those handlers receive
shared projections and a query context with live policy flags, without an
open transaction or AppState.
OMEMO transfer lifecycle operations and authorized recovery reads also use
repository ports. Public completion polling has a separate service/context
with shared bounded admission and its dedicated connection pool. Authenticated
recovery handlers still need a narrower runtime context for account teardown.
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
existing deadline and failure response. Its remaining process gauges still
use broader state.
Remaining work covers the other REST reads and mutations, their HTTP contexts,
and live-session/account-recovery workers.
AppState still has nine public fields, so stage 1 remains open. Changing field
visibility alone does not demonstrate reduced authority.

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
SQL transaction can cover the complete operation.

Storage migration first requires maintenance mode, bounded copying to immutable
destination keys, a durable manifest/checkpoint and complete version/size/SHA-256
verification. Locator and namespace activation share a database cutover; object
copying is not part of that atomic commit. Source cleanup is a later explicit
operation. S3-to-Local migration requires a single-node destination.

Restore recovery reuses the existing fsynced XID intent and transaction barrier.
A restartable tool must verify database identity/lineage, restore generation,
journal and exact object locations before resuming or compensating. It must
also support controlled maintenance reconnection while the workload fence is
active. A missing/old XID outcome, damaged journal or conflicting evidence keeps
the fence and recovery artifacts intact; it must not guess or promise universal
automatic recovery.
