# Program responsibility and authority model

This document defines which Northstar program, module, task and database
identity owns each capability. It describes the current implementation. A
statement such as "must not" is paired with the mechanism that enforces it;
where no hard isolation exists, the remaining shared authority is stated
explicitly.

## Enforcement vocabulary

| Level | Meaning | What it protects against | What it does not protect against |
| --- | --- | --- | --- |
| PostgreSQL ACL/owner | Separate login, ownership, relation/routine grants and role attributes enforced by PostgreSQL | ordinary runtime code or a leaked low-privilege credential crossing a database capability boundary | compromise of bootstrap/migrator or the PostgreSQL server |
| Child process/session | Different PID, file descriptors, command stream and exit status under one parent | lifecycle attribution, accidental command crossover and some failure propagation | secret, address-space ancestry, container, credential or restart-domain separation |
| Separate container/credential | Different environment, mounted secrets, database identity and independently started container/job | accidental secret/authority sharing and failure propagation between deployment jobs | host/root compromise or compromise of a shared database/object store |
| Rust visibility and typed port | private fields, narrow service methods and typed outcomes | accidental call paths and transaction composition in protocol code | arbitrary-code execution in the server process |
| Supervised Tokio task | registered identity, heartbeat, restart/fail-fast policy and bounded shutdown | silent worker death and discarded task handles | corruption of the shared process or database identity |
| Static CI gate | source-shape, dependency and responsibility invariants checked before merge | architectural drift visible in source | runtime equivalence, unreachable code or a compromised CI system |
| Runtime state-machine check | identity epochs, leases, fences, markers and explicit transition ordering | stale actors, retries and ordinary process interruption | a fully compromised authority holding the same credential |
| Documented convention | review rule without an independent technical boundary | reviewer/operator mistakes when followed | malicious or buggy code that ignores it |

## Executable programs and deployment identities

| Program or mode | Inputs and secrets | Owned capability | Explicitly forbidden | Transaction/failure boundary | Supervision and isolation | Residual authority |
| --- | --- | --- | --- | --- | --- | --- |
| `xmpp-server migrate` | migrator URL and XMPP domain | verify migrator identity and apply the embedded SQLx migration chain | network listeners, runtime/backup credentials and normal message processing | one-shot process; migration transactions are owned by SQLx/PostgreSQL | separate Compose job and exit code | migrator owns the application database/schema |
| `database-grants` | migrator URL, migration ledger and capability manifest | converge exact database/schema/default ACL and reviewed routine grants | application traffic, bootstrap password and backup reads | one policy transaction guarded by a target-local advisory lock | separate image/job | shares the migrator identity with migration and stopped restore |
| `xmpp-server` runtime | runtime URL, command URL, TLS/cluster/abuse secrets and service configuration | C2S/S2S/components, HTTP, routing, domain services and supervised workers | bootstrap/migrator/backup credentials and schema DDL | listener failure cancels the service; new business transactions belong to services/repositories, while tracked API/cluster/federation legacy paths still own direct persistence | one OS process with supervised top-level and worker tasks | runtime services share one address space and mostly one runtime DB role |
| online backup | backup URL, completed upload objects, signing key and age recipients | consistent read-only dump, object manifest, lineage, signature and encryption | database mutation, restore and migrator/runtime secrets | one-shot job; an artifact becomes valid only after its final `READY` publication | separate backup container and backup DB role | database snapshot and object capture are coordinated by completed-upload ordering, not one distributed transaction |
| stopped restore parent | verified archive, migrator URL, rollback roots and decryption material | cutover state machine, child registry, journal, connection fence and compensation decision | treating child exit/EOF as commit evidence | catchable failures converge on compensation; hard kill/power loss retains recovery evidence | separate one-shot restore container | holds the broad migrator credential and can bypass child routing if compromised |
| role bootstrap/reconciliation | audit uses only the selected connection/bootstrap credential; initialization/apply additionally receives all workload password files | audit or create/repair roles, owner and cluster/database ACL policy | application serving and long-lived secret exposure | guarded one-shot operation and post-apply audit | PostgreSQL init process or explicit maintenance job | bootstrap is a superuser and is a break-glass authority |

The bootstrap credential is never mounted into migration, runtime, backup or
restore. The runtime process receives two database credentials: the ordinary
runtime pool and a command-only pool. They are separate PostgreSQL authorities
but still exist in the same OS process.

## Runtime layers

| Layer | Accepted input | Owned capability | Explicitly forbidden | Transaction or failure boundary | Supervisor | Actual isolation | Remaining shared authority |
| --- | --- | --- | --- | --- | --- | --- | --- |
| configuration/secret loader | CLI, environment, `.env` and secret files | syntax/semantic validation, file checks, single ownership transfer and zeroization | logging, cloning or leaving raw secret values in shared configuration | failure precedes every listener | top-level `main` | initialization phase in runtime process | secrets coexist briefly while state is constructed |
| `AppState` assembly | validated configuration, pools, routers, stores and key owners | compose services and process-local routing capabilities | becoming an unconstrained public service locator | construction is all-or-nothing before listener start | top-level `main` | Rust private fields/accessors | nine reviewed public capabilities remain listed below |
| XMPP/BOSH/WebSocket transport adapters | untrusted TCP/TLS bytes, XMPP HTTP frames, peer/proxy identity | framing, size/depth/time budgets, TLS provenance and connection lifetime | business SQL, archive policy and account authorization | per-connection failure closes that connection; listener exit is service-fatal | top-level listener set plus connection actor registry | Tokio tasks in runtime process | shares memory with protocol and services; the REST edge is tracked separately because legacy routes still own direct database access |
| protocol session | framed XML plus authenticated transport state | stream/SASL/bind/SM state machine, stanza parsing, XMPP errors and resource-ordering | production `db::*` authority, SQLx, `PgPool` and `state.pool` | one connection actor; durable resume is delegated to SM service | connection actor registry | Rust module/static gate | may call typed `AppState` services and live routing; `#[cfg(test)]` is outside zero-reference count |
| application service | prepared identities/commands from protocol or HTTP | authorization snapshot, policy, transaction intent and typed result | parsing raw transport frames or exposing raw transactions upward | service method defines one business operation and its commit-before-side-effect rule | caller task or dedicated worker | private Rust capability | several services still embed SQLx/`PgPool` transaction work that should move into repository ports; services share the runtime role/pool |
| database repository responsibility | typed service or legacy runtime request | SQL, lock order, transaction, durable identity, admission/outbox invariant | XML/HTTP parsing, socket delivery and retry policy | PostgreSQL transaction/routine/constraint | caller plus PostgreSQL | mostly `src/db/*`, migration constraints and PostgreSQL ACL | repository responsibility is not yet a universal directory boundary: some services, API, cluster, federation and worker paths still contain direct persistence |
| live routing/outbound | authorized delivery plan and exact route incarnation | bounded queues, route ABA fence, SM/BOSH/socket ownership transfer and slow-peer disconnect | re-deciding privacy/blocking or claiming a DB transaction committed | ownership moves only at an explicit transfer point | connection actors | process-local data plane | online sessions and MUC maps are volatile by design |
| worker registry | worker closure, criticality, mode and heartbeat | unique registration, restart/backoff, readiness degradation and fatal cancellation | detached `JoinHandle`, unreported exit or infinite silent retry | one supervised attempt at a time | `WorkerRegistry` | supervised Tokio tasks | several closures still receive broader `Arc<AppState>` access than their target ports |
| observability | internal health/metrics request | bounded cached readiness and metrics rendering | business mutation or anonymous public DB amplification | read-only probe deadline; readiness can degrade independently of commits | HTTP/metrics top-level tasks | separate listener, same process | readiness uses bounded runtime DB access |

### Reviewed public `AppState` capabilities

The architecture gate now checks the names, not only the count. Replacing one
field with a different public capability fails CI even if the total stays nine.

| Public field | Why it remains public | Target direction |
| --- | --- | --- |
| `config` | broad read-only protocol/runtime policy is still consumed across many modules | split immutable transport, protocol and worker policy views |
| `pool` | legacy API/operation/background paths still require the runtime pool | move every caller behind a domain service/repository port |
| `cluster` | routing and clustered ownership share one manager | expose route, lease and publication ports separately |
| `sessions` | exact local-resource routing table | hide behind a live-session registry API |
| `muc_occupants` | process-local MUC route/occupancy projection | hide behind a MUC live-routing port |
| `metrics` | fixed-cardinality counters are updated across hot paths | pass narrow metric handles or event sinks |
| `federation` | authenticated domain routing and durable outbox coordination | separate connection routing from durable federation admission |
| `abuse` | pre-pool admission and action policy spans multiple ingress paths | expose action-specific admission ports |
| `tls` | listeners and reload control need the current certificate set | provide listener snapshot and reload-admin ports |

Private `AppState` fields include database keyrings, FAST/Dialback material,
stores, component credentials, service objects and worker registry. Protocol
handlers access them through purpose-specific methods rather than field access.

## Source ownership map

This map answers where a change belongs. “Must not call” is a design boundary;
the enforcement column distinguishes a hard gate from a remaining review rule.

| Path | Owns | May call | Must not own or call | Enforcement and current exception |
| --- | --- | --- | --- | --- |
| `src/main.rs` | CLI mode selection, process composition, pool construction/attestation, listener and worker startup, coordinated shutdown | configuration, `AppState`, listener factories, worker registry and one-shot migration/audit modes | stanza policy, business SQL or domain transaction composition | review plus top-level failure tests; it is the only runtime composition root |
| `src/config.rs` | parsing, normalization, deployment-mode validation, secret-file/value exclusivity and transfer into typed configuration | filesystem metadata and pure validation helpers | opening network listeners, querying application data or logging secret values | typed configuration and tests; secret consumers remain in the same process after transfer |
| `src/state.rs` | construction of domain capabilities and process-local registries; private capability accessors | services, stores, routers, key owners and worker registry | becoming an unrestricted global service locator or exposing new raw key/pool fields | Rust visibility plus an exact-name CI gate for the nine legacy public capabilities |
| `src/xmpp/framing.rs`, `src/transport_parsing.rs`, `src/bosh.rs`, WebSocket/C2S entry code | bytes-to-frame conversion, transport provenance, per-connection budgets, BOSH RID/response ownership and connection lifetime | parser utilities, connection actors and `ProtocolSession` | authorization, archive decisions or business database transactions | parser/transport tests and bounded actors; BOSH persistence calls are transport-specific fence bookkeeping, not general business authority |
| `src/xmpp/protocol.rs`, `src/xmpp/protocol/*` | stream/session state, RFC/XEP parsing, canonical protocol errors and ordered invocation of typed capabilities | `AppState` service methods, XML builders and live-delivery interfaces | `db::*`, SQLx, `PgPool`, `state.pool` or composing archive/offline/outbox transactions | production-tree CI ceiling is exactly zero for every forbidden database reference; test-only fixtures are excluded |
| `src/services/*` | business authorization, one-snapshot policy, transaction intent, commit/side-effect ordering and typed outcomes | domain repositories, PostgreSQL for the still-embedded repository paths, and narrow runtime ports | raw socket/framing parsing or returning an open transaction to protocol code | Rust visibility and semantic source gates; several services still embed SQLx/`PgPool` work and must be split without moving that authority upward |
| `src/db/*` | SQL, routines, lock order, isolation level, durable identities, capacity ledgers, claims and outbox/admission atomicity | SQLx/PostgreSQL and typed persistence models | XML/HTTP parsing, socket backpressure or retrying external effects while a transaction is held | module boundary, migration constraints and exact PostgreSQL capability manifest |
| `src/api/*`, `src/operation_runtime.rs` | HTTP routing, authentication, request/idempotency context, admin operation journal and response mapping | API services, repositories, command/runtime capability pools and operation workers | bootstrap/migrator/backup credentials or unaudited external effects | middleware, DB ACLs and operation journal; many API modules retain direct persistence (`mod.rs` and `reports.rs` are representative) that must move behind services |
| `src/outbound.rs`, `src/connection_actors.rs` | exact live-route incarnation, bounded queue ownership, socket/SM/BOSH transfer and slow-peer action | session/MUC registries, metrics and typed delivery plans | deciding privacy/block policy or claiming persistence before PostgreSQL commits | route generations, bounded channels and actor registry; volatile signals retain their documented best-effort semantics |
| `src/s2s/*`, `src/components.rs` | remote/component authentication, domain authority, discovery/TLS/Dialback and delivery attempts | federation policy, DNS/TLS, durable outbox repositories and outbound transport | asserting local identity from an unauthenticated stream or treating socket write as universal exactly-once ACK | authenticated stream state plus stable IDs/outbox; XMPP delivery remains at-least-once at defined retry boundaries |
| `src/cluster.rs`, `src/cluster_security.rs`, `src/db/cluster_*` | signed Redis control envelopes, node/route epochs, PostgreSQL leases and degraded-mode decisions | live registries, PostgreSQL authority and Redis transport | making Redis durable truth or authorization authority | signature/replay checks and PostgreSQL revalidation; multi-node behavior remains experimental |
| `src/workers.rs`, `src/retention.rs`, `src/upload_worker.rs` | named task lifecycle, heartbeat, restart/fail-fast class, bounded retry and shutdown joining | narrow service/repository capabilities and readiness reporting | detached `JoinHandle`, invisible permanent exit or holding a DB transaction during external I/O/backoff | `WorkerRegistry`; some closures still receive a broader `Arc<AppState>` than the target design |
| `src/storage.rs`, `src/storage/*` | object locator validation and local/S3 byte operations | bounded object-store APIs and hashing/I/O permits | account authorization, SQL transaction ownership or interpreting an object write as a committed slot | typed store interface; claim/fence/finalize remains split across upload service/repository/worker |
| `src/metrics.rs`, health routes | fixed-cardinality counters, cached/single-flight bounded health rendering | narrow snapshots and bounded database probes | business mutation, secrets/high-cardinality labels or public unbounded query amplification | private observability listener policy and source/tests |
| `web/*` | UI state, browser XMPP transport, SASL2/FAST/SM, endpoint OMEMO keys/trust and IndexedDB | server public APIs and browser cryptographic/runtime APIs | sending private OMEMO keys to the server; the current protocol/API also contains no required-encryption downgrade path | browser tests and no server key API; same-origin code delivery remains a permanent trust boundary |
| `migrations/*`, `deploy/postgres-init/*`, `scripts/*` | schema evolution, role/ACL convergence, backup/restore/release operations and offline acceptance fixtures | migrator/bootstrap/backup identities according to the exact job | being imported into the long-lived runtime or weakening a production boundary to simplify a fixture | migration ledger, capability manifest and operational static/dynamic CI |

## End-to-end authority hand-offs

The important boundary is the point where responsibility changes hands. A
caller receives a typed result; it does not retain the callee's transaction or
secret authority.

1. **C2S, WebSocket or BOSH stanza.** A listener/HTTP adapter authenticates the
   transport and gives bounded frames to a connection actor. The actor invokes
   `ProtocolSession` dispatch in `src/xmpp/protocol/dispatch.rs`. The protocol
   handler validates XMPP shape and calls a typed `AppState` service; the
   service authorizes and delegates to `src/db/*`, or to its explicitly tracked
   embedded repository path, to commit the durable operation. Only
   the resulting delivery plan reaches `src/outbound.rs`, SM/BOSH fencing or a
   socket. Socket backpressure never holds the business transaction open.
2. **REST or administrator request.** The router establishes transport and
   request identity; authentication, authorization and idempotency middleware
   create the request context. A service/repository or operation-journal
   transition commits before the HTTP response or external effect is reported.
   Many `src/api/*` modules still have direct persistence; `mod.rs` and
   `reports.rs` are representative pool/transaction paths. They are explicit
   extraction debt, not a model for new endpoints.
3. **Background work.** `WorkerRegistry` owns one named attempt, heartbeat,
   criticality and cancellation. The attempt calls a service/repository, which
   claims or commits durable work before performing a bounded external effect.
   A wake notification is only an optimization; a failed wake cannot erase the
   PostgreSQL claim/outbox that periodic recovery will find.
4. **Durable/storage-eligible S2S or component delivery.** An authenticated
   stream establishes exact remote-domain/component authority. Policy and
   admission commit a stable identity/outbox before the network attempt.
   Completion advances only at the documented peer/write boundary; a crash
   before durable completion may retry, so clients/components must deduplicate
   stable IDs. Volatile presence, `no-store` and equivalent signals use only an
   authenticated live route and retain their documented explicit-failure or
   best-effort semantics instead of being silently persisted.
5. **Upload/object I/O.** The upload service authorizes a slot and persists a
   lease/claim. Storage code performs bounded I/O without an open PostgreSQL
   transaction. A fenced finalize transaction verifies locator, version, size
   and digest; cleanup/reconciliation owns interrupted projections.
6. **Stopped restore.** The parent state machine validates artifacts and starts
   PostgreSQL clients through `scripts/run-postgres.py`, which replaces itself
   with the real client. Controller, coordinator, primary and compensation
   receive disjoint command streams. Connection fence, transaction barrier and
   synchronous catalog marker—not EOF or exit code alone—decide the outcome.

## Process and operation lifecycles

### Runtime startup

1. CLI mode and configuration are parsed before listeners exist.
2. Runtime and command pools connect with different PostgreSQL credentials;
   role identity, migration/schema state and required capacity authorities are
   attested before service construction.
3. `AppState` assembles services, stores, routers, registries, key owners and
   metrics. Failure is still startup-fatal.
4. Security-critical and restartable background tasks are registered with the
   worker supervisor; no detached task is part of the accepted architecture.
5. C2S, direct TLS, S2S, component, HTTP and observability listeners start under
   top-level supervision. Readiness becomes healthy only after its dependencies
   and critical workers are healthy.

### One request or stanza

1. Enforce byte/frame/concurrency budgets before expensive parsing or pool use.
2. Authenticate the transport/principal and canonicalize JIDs/identifiers once.
3. Authorize inside the application service using one explicit database
   snapshot when a decision spans mutable rows.
4. Commit durable identity, mutation and required outbox/admission projections
   atomically; return a typed outcome.
5. Perform live routing or external I/O after commit. Transfer to SM, BOSH,
   socket or outbox must have an explicit owner and replay rule.
6. Map the typed result to XMPP/HTTP without exposing database errors or secret
   material. Metrics/logs use bounded labels and public identifiers only.

### Shutdown and failure

1. Stop new admission and mark readiness unhealthy.
2. Cancel listeners and connection acceptance, then request supervised workers
   and actors to quiesce through their owned cancellation path.
3. Publish/retire cluster route and lease state according to the component's
   fence rules; never infer durable completion from task disappearance.
4. Join listeners, workers and connection actors within the configured shutdown
   budget. A critical task exit before shutdown remains process-fatal.
5. PostgreSQL transactions roll back on lost owners; durable claims, outboxes,
   SM state and operation journals define what the next process recovers.

### Secret lifecycle

Secret value and secret-file forms are mutually exclusive. Startup reads a
bounded regular file or environment value, validates it, moves it to the narrow
owner and removes avoidable inherited variables. Key/password bytes are never
rendered into logs or normal command arguments and are zeroized where the Rust
or browser platform permits. File descriptors and child environments are
explicitly closed/scrubbed before executing maintenance clients.

## Domain responsibility matrix

| Domain | Service owner | Durable authority | Volatile authority | Forbidden crossing | Commit/side-effect rule |
| --- | --- | --- | --- | --- | --- |
| authentication/account | `AuthenticationService`, `AccountService` | user identity, credential generation, SCRAM/FAST rows and lifecycle routines | exact authenticated connection state | protocol code cannot query credentials directly; password bytes cannot enter logs | account/credential mutation commits before route/token revocation is published |
| XEP-0198 session management | `SmService`, session-cleanup and capacity services | resume session, ordered stanza suffix, capacity and teardown claims | exact socket/route incarnation and per-session memory budget | transport cannot mint durable resume state; stale connection cannot tear down replacement | DB ownership/fence commits before route activation; replay transfer is explicit |
| personal messaging | `MessageService`, replay/retraction services | origin/admission identity, archives, offline/C2S/S2S outboxes and tombstones | online route and transient signal delivery | protocol must not compose archive/offline/outbox writes or hold a DB connection during socket backpressure | durable admission commits first; live delivery consumes a typed delivery plan |
| roster/presence/privacy/blocking | roster, presence, privacy and blocking services | roster versions, subscriptions, privacy lists, block list and offline claims | interest flags, directed presence and current availability | socket pressure cannot retain a database transaction; account generations fence replay | claim/snapshot transaction ends before transport transfer; untransferred suffix remains recoverable |
| PubSub/PEP/MAM/profile/private XML | PubSub, MAM, profile and private-storage services | nodes/items/subscriptions/outbox, archive visibility, vCard/avatar metadata and private XML | verified capability cache and bounded digest work | cache is never authorization; protocol has no repository authority | when a mutation emits an event, its authoritative mutation and outbox commit atomically; non-event writes need no synthetic outbox; reads use one authorization snapshot |
| MUC/MIX | MUC and MIX services | rooms/channels, affiliations, PAM, normalized events, durable management/MIX outboxes and capacity ledgers | local occupant routes, ordinary MUC groupchat/presence/typing and presentation state | Redis cannot be durable truth; protocol cannot directly mutate room/channel tables | durable management and MIX operations commit before fan-out; ordinary groupchat is archived plus best-effort live Redis fan-out, while presence/typing is intentionally volatile |
| upload/object store | upload services, safety gate and upload worker | slot/lease, object identity, capacity, cleanup/reconciliation jobs | in-flight HTTP and bounded hashing/I/O permits | arbitrary paths, unbounded bodies and PG transactions across external object I/O | claim, object I/O and finalize are separate fenced stages; reconciliation repairs interrupted projections |
| abuse/moderation | `AbuseGuard` and report/appeal API/repository paths (service extraction pending) | keyed actor state, challenge, cooldown, report evidence and appeal state | pre-pool striped admission permits | one NAT actor cannot queue while holding general pool connections; HMAC keys never leave owner | admission state changes in PostgreSQL; critical key-authority drift cancels listeners |
| S2S/components | federation router, S2S registry and component registry | outbox, domain policy and component delivery state | authenticated streams, DNS/TLS results and connection attempts | remote stream cannot claim local domain; socket write is not durable ACK | outbox is at-least-once and acknowledged only after the defined completion boundary |
| cluster control plane | cluster manager and security verifier | PostgreSQL leases, keys, epochs and durable business rows | signed Redis envelopes and route hints | Redis cannot authorize identity, delete durable work or become message truth | verify envelope, then re-read/claim PostgreSQL authority; degraded modes are explicit |
| REST/admin operations | API middleware and operation runtime | sessions, idempotency records, operation journal, leases and audit facts | HTTP request context and worker attempt | no bootstrap/migrator credential; command pool cannot read business tables | journal/lease defines retry and point-of-no-return; ambiguous external effect becomes indeterminate |
| browser OMEMO | browser JS/WASM and IndexedDB | endpoint-persistent keys, sessions, trust and queued encrypted payloads | page/UI state | the current server protocol/API has no private-key or plaintext-downgrade path | browser-local state is outside server DB transactions but can be cleared/evicted by the platform; the same-origin publisher can replace future client code |

## Database identities

| Identity | May do | Must not do | Mounted into |
| --- | --- | --- | --- |
| `northstar_bootstrap` | create/repair roles, owner and exact ACL policy | serve traffic, migrate normally, back up or restore application data | PostgreSQL initialization or explicit break-glass role reconciliation only |
| `northstar_migrator` | own application DB/schema, migrate, reconcile grants and perform stopped restore; connect to maintenance DB for restore control | superuser, role/database creation, replication, bypass RLS or maintenance `TEMPORARY` | migration, database-grants and restore jobs |
| `northstar_runtime` | execute runtime routine/table capability manifest | DDL, ownership, trigger disable, direct account-authority DML or command-only routines | long-lived server primary pool |
| `northstar_commands` | execute the exact command-session routine manifest | relation/sequence reads, general runtime DML or migration | isolated command pool inside long-lived server |
| `northstar_backup` | read the exact backup surface | write, execute business routines, allocate sequences, restore or use maintenance DB | backup job only |

Every protected role, including bootstrap, is rejected in either side of a
role-membership edge. Reconciliation uses cascading membership revocation so a
delegated `WITH ADMIN OPTION` chain cannot block convergence. Unknown
superusers are an audit failure even when `NOLOGIN`; the only exception is an
explicitly named dedicated-cluster/isolated-CI controller. A staged legacy
`xmpp` role reports its remaining superuser, login and membership authority
until guarded demotion completes.

## Restore child-session responsibilities

All four sessions authenticate as migrator. Their separation is program
routing and lifecycle containment, not four independent database ACLs.

| Child/session | Database | Owned commands | Commands it never receives | Failure evidence | Parent supervision |
| --- | --- | --- | --- | --- | --- |
| maintenance controller | `postgres` | target `ALLOW_CONNECTIONS`, exact target PID census, target-OID outcome read/clear | backup/restore advisory lock, dump replay, schema/grant body and compensation | shared catalog state only | exact PID/FD registration; child is reaped, not independently restarted |
| target coordinator | target | backup/restore session lock and replacement-transaction barrier | connection fence, dump/schema replay and marker arbitration | same-database advisory barrier proves the worker transaction ended | exact PID/FD registration; kept until workers close |
| primary executor | target | pre-fence policy lock, current-target preflight and incoming replacement | compensation and connection-fence control | READY plus synchronous transactional incoming marker | exact PID/FD registration; active input is closed/drained on interruption |
| compensation executor | target | rollback replacement after outcome arbitration | incoming replacement and connection-fence control | READY plus synchronous transactional rollback marker | pre-opened before fence; invoked only by compensation state |

The controller is outside the target because PostgreSQL refuses changing
`ALLOW_CONNECTIONS` for the current database. The coordinator stays inside the
target because advisory locks include the database OID. The primary holds the
policy lock across preflight and rollback-dump capture; only after the hard
fence proves that coordinator, primary and compensation are the exact three
remaining target PIDs may it release that lock. No new target connection can
then enter.

The PostgreSQL wrapper stores the password in a `0600` anonymous Linux memfd,
sets `PGPASSFILE` to `/proc/self/fd/<n>` and `exec`s the client in place. The
registered child PID is therefore the actual `psql`, `pg_dump` or `pg_restore`
process rather than a Python parent. An offline CI test verifies PID identity,
descriptor type/mode, environment scrubbing and absence of a disk passfile.

## Placement rules for new work

Use these rules before adding a module, dependency or public field:

| Change | Required owner | Required companion work | Rejected shortcut |
| --- | --- | --- | --- |
| wire grammar, stanza shape or protocol error | XMPP protocol module, transport parser or API edge | parser/error tests; XEP/OpenAPI documentation when public | SQL, raw pool or business transaction in protocol code |
| authorization, policy or multi-row transaction shape | application service | typed inputs/outcomes and race/rollback tests | duplicating the decision in protocol, API and worker callers |
| SQL, lock order, routine or persistence mapping | domain repository plus migration when schema changes | isolation/concurrency test and capability-manifest/grant update | dynamic SQL or open transaction escaping to transport code |
| required durable side effect | same-transaction outbox/admission plus supervised consumer | stable ID, retry/ACK boundary, recovery and quota policy | fire-and-forget task after a mutation |
| live session/MUC delivery | outbound or registry port after authorization/commit | exact route generation, bounded backpressure and fallback semantics | using a volatile map as durable truth |
| external object/network I/O | bounded adapter/worker outside the database transaction | claim/fence/finalize or outbox state and reconciliation | holding a pool connection while waiting on a peer/object store |
| long-running or periodic work | `WorkerRegistry` | unique name, criticality, heartbeat, restart/backoff and shutdown test | discarded `JoinHandle` or silent infinite loop |
| configuration or secret | typed `Config` plus narrow owner | startup validation, file form, redaction/zeroization and deployment docs | new global environment reads throughout business code |
| database authority | exact PostgreSQL role/capability manifest | init/reconcile SQL, static gate, isolated ACL test and operational docs | granting table-wide/runtime-owner rights because one call is missing |
| process-global state | private `AppState` capability or dedicated registry | accessor/port and exact architecture budget update only when it narrows authority | new public raw pool, key bytes or generic service locator field |

Every public feature also updates the smallest applicable set of tests,
metrics, logs, README/operations, OpenAPI and `XEP_MATRIX.md`. The current
exception classes—nine public `AppState` capabilities, direct REST persistence
and embedded service/runtime repository work—must decrease over time and may
not be copied into new work.

## Residual coupling and reduction order

These are current architecture debts, not hidden isolation claims:

1. The nine public `AppState` fields still form a broad same-process authority.
2. Operation/background paths still hold `Arc<AppState>` where narrower ports
   would make transaction and failure ownership clearer.
3. Some REST routes still own direct pool/transaction access instead of a
   service port; the XMPP protocol tree's zero-database boundary does not yet
   extend to the entire HTTP tree.
4. Several application services, cluster/federation/component paths and workers
   still embed repository work instead of depending on a narrow persistence
   port; `src/db/*` is not yet a universal physical repository boundary.
5. Most domain repositories share `northstar_runtime`; Rust service separation
   is stronger than the current per-domain PostgreSQL separation.
6. REST, XMPP, S2S, components and workers share one process. A memory-safety or
   arbitrary-code-execution failure crosses those Rust module boundaries.
7. Redis clustering is an optimization/control channel, not a consensus or
   durable authority system; multi-node mode remains experimental.
8. Restore child sessions share one parent, credential, container and database
   cluster. Their split contains ordinary failures but not parent/credential
   compromise.

Further reduction should proceed in this order: move direct REST transactions
behind application services, extract embedded service/runtime persistence into
repository ports, remove raw `AppState.pool`, replace the session/MUC public
maps with registries, split operation workers into narrow capability structs,
then consider per-domain PostgreSQL roles only after the service transaction
boundaries are stable. CI treats the current field
identities and zero protocol/database dependency counts as monotonic ceilings:
a new feature must not widen them.
