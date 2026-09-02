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

## Responsibility dimensions

“Owns a feature” is too broad to be a useful security statement. Every request,
stanza, worker attempt and maintenance operation is therefore divided into the
following responsibilities. One component may own more than one adjacent
responsibility, but the transfer point and enforcement mechanism must remain
explicit.

| Responsibility | Question it answers | Owner may return | Owner must not assume |
| --- | --- | --- | --- |
| admission | May this byte stream, request or attempt consume resources now? | bounded permit, rejection or retry instruction | authenticated identity, business authorization or successful persistence |
| parsing and canonicalization | What exact typed command did the peer send? | validated frame/stanza/request and canonical identifiers | permission to execute it or a database transaction |
| authentication | Which account, domain, component, node or administrator controls this connection? | principal plus transport/channel-binding evidence | permission for a particular mutation |
| authorization and policy | May this principal perform this command against this target in this snapshot? | authorized command/plan or typed denial | that a later commit or external effect succeeded |
| durable transaction | Which rows, locks, identities, claims and outboxes change atomically? | committed typed result, replay/conflict or rollback/error | socket/object-store delivery after commit |
| external execution | Which bounded socket, Redis or object-store action is attempted? | transfer acknowledgement, retryable failure or indeterminate result | authority to rewrite the committed business decision |
| publication | Which peer, route, cache, metric or HTTP/XMPP response observes the result? | protocol response, route event or observation | durable truth merely because publication succeeded |
| recovery and reconciliation | What must happen after interruption or an indeterminate effect? | recovered, retried, compensated, quarantined or fail-closed state | permission to guess an ambiguous commit/effect outcome |
| audit and observation | What bounded evidence proves health, policy and transition history? | fixed-cardinality metrics, health state and redacted audit facts | mutation authority or access to secret/plaintext payloads |

Authority does not flow back to a caller with a result. A protocol handler that
receives `Committed` does not gain the repository transaction; an executor that
emits `DONE` does not gain outcome-arbitration authority; a worker that claims
an outbox row does not gain authorization-policy ownership. Retries re-enter at
the responsibility that owns the durable identity or claim rather than
re-running all earlier decisions informally.

## Executable programs and deployment identities

| Program or mode | Inputs and secrets | Owned capability | Explicitly forbidden | Transaction/failure boundary | Supervision and isolation | Residual authority |
| --- | --- | --- | --- | --- | --- | --- |
| `xmpp-server migrate` | migrator URL and XMPP domain | verify migrator identity and apply the embedded SQLx migration chain | network listeners, runtime/backup credentials and normal message processing | one-shot process; migration transactions are owned by SQLx/PostgreSQL | separate Compose job and exit code | migrator owns the application database/schema |
| `database-grants` | migrator URL, migration ledger and capability manifest | converge exact database/schema/default ACL and reviewed routine grants | application traffic, bootstrap password and backup reads | one policy transaction guarded by a target-local advisory lock | separate image/job | shares the migrator identity with migration and stopped restore |
| `xmpp-server` runtime | runtime URL, command URL, TLS/cluster/abuse secrets, optional application bootstrap-admin password and service configuration | one startup-only administrator ensure step, then C2S/S2S/components, HTTP, routing, domain services and supervised workers | PostgreSQL bootstrap/migrator/backup credentials and schema DDL | the bootstrap-admin password is consumed before `AppState`; listener failure then cancels the service; new business transactions belong to services/repositories, while tracked API/cluster/federation legacy paths still own direct persistence | one OS process with supervised top-level and worker tasks | runtime services share one address space and mostly one runtime DB role; startup still temporarily holds an account-creation secret |
| online backup | backup URL, completed upload objects, signing key and age recipients | consistent read-only dump, object manifest, lineage, signature and encryption | database mutation, restore and migrator/runtime secrets | one-shot job; an artifact becomes valid only after its final `READY` publication | separate backup container and backup DB role | database snapshot and object capture are coordinated by completed-upload ordering, not one distributed transaction |
| stopped restore parent | verified archive, migrator URL, rollback roots and decryption material | cutover state machine, child registry, journal, connection fence and compensation decision | treating child exit/EOF as commit evidence | catchable failures converge on compensation; hard kill/power loss retains recovery evidence | separate one-shot restore container | holds the broad migrator credential and can bypass child routing if compromised |
| role bootstrap/reconciliation | audit uses only the selected connection/bootstrap credential; initialization/apply additionally receives all workload password files | audit or create/repair roles, owner and cluster/database ACL policy | application serving and long-lived secret exposure | guarded one-shot operation and post-apply audit | PostgreSQL init process or explicit maintenance job | bootstrap is a superuser and is a break-glass authority |

The PostgreSQL bootstrap/superuser credential is never mounted into migration,
runtime, backup or restore. This is distinct from the optional application
bootstrap-admin password: the runtime loader receives that password, uses the
ordinary runtime capability to ensure the configured administrator, and only
then clears the configuration field while constructing `AppState`. The runtime
process also receives ordinary and command-only database credentials. They are
separate PostgreSQL authorities but still exist in the same OS process.

### Binary mode matrix

| Invocation | Database identity and access | Server must be stopped | Output/data sensitivity | Failure boundary |
| --- | --- | --- | --- | --- |
| `xmpp-server --version` | none | no | public version line | one-shot, no configuration or logging initialization |
| `xmpp-server --healthcheck [IP:PORT]` | none directly; before loading `Config`, probes the explicit literal address or the fixed default `127.0.0.1:8080` | no | HTTP status only | literal-address bounded one-shot network probe; it does not discover a configured non-default HTTP bind |
| `xmpp-server audit-identities --dry-run` | one caller-supplied connection; the tool enforces a repeatable-read read-only transaction but does not attest the PostgreSQL role name/capability manifest | no, but a quiet snapshot improves operational interpretation | report-local pseudonyms by default; raw identity values only with explicit sensitive-output option | operator must supply the runtime/read-only identity; the tool never migrates or repairs, and nonempty findings return failure after the JSON report |
| `xmpp-server migrate` | migrator, maximum two connections | yes for production schema transition | migration identifiers/errors, no business export | one-shot SQLx migration/verification process |
| `xmpp-server pie export` | bounded runtime-role pool | no business-data mutation, but it appends an `audit_log` record after publishing the export file | owner-only portable account data; may contain archives, never plaintext password export | file publication and audit insertion are not one atomic boundary: audit failure returns an error but can leave the completed file, an explicit operational debt |
| `xmpp-server pie import` | migrator in production; serializable write transaction and audit record | **yes** | reads an operator-supplied bounded PIE tree; plaintext password import requires explicit opt-in | dry-run executes then rolls back; normal import commits all selected users atomically |
| `xmpp-server` | runtime plus command-only pool and auxiliary runtime-identity pools | n/a | long-lived protocol/HTTP service | startup attestation precedes listeners; listener/critical-worker failure coordinates shutdown |

The Cargo target is named `rust-xmpp-server`; the installed release executable
is `xmpp-server`. This naming difference does not create separate programs or
authorities.

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

## Runtime process topology and failure ownership

The long-lived server is one OS process but has two distinct supervision
planes. Top-level service tasks are availability-critical listeners/engines: an
unexpected return cancels the whole process. Registry workers have a declared
criticality, heartbeat contract and restart policy. Neither plane may detach a
task whose disappearance would change accepted behavior.

### Top-level service tasks

| Registered task | Entry point | Owns | Unexpected exit | Does not own |
| --- | --- | --- | --- | --- |
| `XMPP` | `xmpp::serve_tcp` | STARTTLS C2S accept loop and connection-actor admission | process-fatal | session business transactions |
| `XMPPS` | `xmpp::serve_xmpps_tcp` | direct-TLS C2S accept loop | process-fatal | certificate policy mutation or account authorization |
| `S2S` | `s2s::serve` | inbound STARTTLS plus outbound STARTTLS/direct-TLS federation actors and durable-outbox attempts | process-fatal | local account identity or message commit arbitration |
| `S2S TLS` | `s2s::serve_s2s_tls` | inbound direct-TLS federation accept loop | process-fatal | outbound transport selection or DNS/federation policy authority outside its typed inputs |
| `external component` | `components::serve` | component stream authentication, route registration and delivery attempts | process-fatal | granting a component unconfigured domains |
| `durable operation worker` | `operation_runtime::serve` | administrator operation journal claims and bounded execution | unexpected task exit is process-fatal; repeated in-loop database/business errors currently log and sleep without WorkerRegistry heartbeat, an explicit supervision debt | HTTP authentication or inventing completion after an indeterminate effect |
| `HTTP` | `api::serve` | REST/static/BOSH/WebSocket/upload request admission and response lifecycle | process-fatal | bootstrap/migrator access or XMPP session state-machine shortcuts |
| `metrics` | `api::serve_metrics` | private observability listener and cached bounded snapshots | process-fatal | business mutation or unrestricted database probing |

Long-lived C2S, BOSH, WebSocket, S2S and external-component actors are
registered in the connection-actor registry. Listener shutdown first closes
their admission; actor shutdown then drains or aborts those registered actors.
Ordinary REST, upload and metrics HTTP connections are not actor-registry
members: their sockets and in-flight requests belong to Axum's graceful-server
shutdown and request/body-sidecar lifetimes.

### Supervised registry workers

| Worker name | Registration owner | Criticality / mode | Stall watchdog | Shutdown | Owned recovery/work | Failure effect |
| --- | --- | --- | --- | --- | --- | --- |
| `abuse-key-deployment-authority` | `main` | critical / continuous | `2 ×` authority poll interval | immediate | verify active HMAC key deployment/generation authority | the first returned validation error/timeout, panic or watchdog expiry terminates the critical attempt and cancels the service |
| `deployment-capacity-session-leases` | `main` | critical / continuous | `2 ×` lease interval | immediate | renew and audit deployment-wide session-capacity leases | terminal attempt/liveness failure cancels the service |
| `background-maintenance` | `main` | restartable / continuous | 180 s | immediate | bounded expiry/cleanup for sessions, FAST, SM, admin and auxiliary state | readiness degrades and the guardian rebuilds the attempt with backoff |
| `account-deletion-recovery` | `main` | restartable / continuous | 1,200 s | immediate | resume fenced account deletion, SM teardown and storage reconciliation | readiness degrades and the durable claim is retried by a rebuilt attempt |
| `upload-storage-reconciliation` | `main` | critical / continuous | 600 s | immediate | reconcile slot/object/cleanup authority and storage namespace | proven authority drift, watchdog expiry, or the critical business-health error threshold (currently three consecutive DB/provider/backlog reports) cancels the service; an individual transient report marks health before object I/O |
| `archive-retention` | `main` | restartable / continuous | derived retention maximum-silence interval | immediate | claim and apply archive lifecycle policy in bounded batches | readiness degrades and the claim-safe attempt restarts |
| `admin-session-cleanup` | `main` | critical / continuous | 90 s | immediate | revoke credential generations and exact live connections | failure or silence cancels the service rather than delaying security revocation |
| `redis-pubsub` | `main`, cluster only | restartable / continuous | 45 s | immediate | receive authenticated route/control hints | cluster readiness degrades and the listener restarts; Redis never becomes durable authority |
| `cluster-maintenance` | `main`, cluster only | restartable / continuous | 90 s | immediate | renew/reconcile PostgreSQL node/route leases and disconnect sessions whose authentication or user-agent login generation is stale | cluster readiness degrades and lease-safe work restarts; failure also removes this secondary credential-revocation reconciliation path |
| `cluster-failure-policy` | `main`, cluster only | critical / continuous | 15 s | immediate | enforce fail-closed cluster policy when authority is lost | any terminal attempt or silence cancels the service |

Workers are also registered by the capability that constructs their narrow
inputs. They use the same registry and shutdown token; being registered outside
`main.rs` does not make them detached or less important.

| Worker/observer name | Registration owner | Criticality / mode | Stall watchdog | Shutdown | Owned recovery/work | Forbidden shortcut |
| --- | --- | --- | --- | --- | --- | --- |
| `session-cleanup` | `AppState` observer registration | restartable health observer; **no task/factory** | none | not applicable | synchronous per-session cleanup reports success/error into readiness | describing it as a restartable loop or hiding repeated cleanup errors |
| `sm-authority-listener` | `SmService` startup | restartable / continuous | 15 s, fed by a 5 s liveness tick even when LISTEN is quiet | immediate | consume durable SM authority changes and fence local resume state | treating notification silence as failure or a notification as authority without the durable generation |
| `sm-suspension-recovery` | session-cleanup service startup | restartable / continuous | 30 s | drain up to 5 s | recover suspended SM/MUC endpoint teardown and replay ownership | dropping a claimed suffix on cancellation |
| `caps-side-effects` | Caps subsystem startup | restartable / continuous | 60 s | bounded `CAPS_EFFECT_DRAIN_GRACE` | execute pending verified capability/PEP/MIX effects with no-lost-wakeup rescan | declaring work complete because a bounded hint queue filled |
| `mix-iq-relay-expiry` | MIX protocol capability startup | restartable / continuous | 10 s | immediate | expire exact pending IQ relays and route generations | expiring a replacement relay by stale timer identity |
| `mix-delivery-outbox` | MIX capability startup | restartable / continuous | 30 s | bounded `MIX_OUTBOX_DRAIN_GRACE` | claim and deliver durable MIX event outbox rows | treating live fan-out as outbox acknowledgement |
| `mix-presence-recovery` | MIX capability startup | restartable / one-shot | 90 s | immediate | rebuild eligible MIX presence after startup | running indefinitely or inventing participants absent durable authority |
| `pubsub-digest-delivery` | PubSub capability startup | restartable / continuous | 5 s | immediate | deliver due digest batches from durable queue state | losing work when an in-memory wake is dropped |
| `pubsub-event-outbox-delivery` | PubSub capability startup | restartable / continuous | 30 s | immediate | deliver/retry durable PubSub/PEP mutation events | publishing before the mutation/outbox transaction commits |
| `cluster-muc-outbox` | cluster MUC startup, unconditionally registered | restartable / continuous | 30 s | immediate | in every mode expire/recover PostgreSQL MUC occupancy, dead-letter/history and metric state; with clustering also bridge durable MUC outbox events to authenticated cluster delivery | making Redis publication the durable completion record or skipping single-node PostgreSQL maintenance |
| `locked-muc-expiry` | `AppState` MUC startup | restartable / continuous | 20 s | immediate | expire locked empty-room creation windows | deleting an occupied/replacement room from a stale observation |
| `federation-policy-refresh` | `AppState` federation startup | critical / continuous | 10 s | immediate | refresh the runtime projection of durable federation rules | continuing with silently stale allow/deny authority |
| `administration-setting-refresh` | `AppState` administration startup | critical / continuous | 5 s | immediate | refresh security-relevant runtime administration settings | silently retaining a superseded security setting |
| `service-control-watcher` | `AppState` service-control startup | critical / continuous | 3 s | immediate | observe committed service disable/shutdown authority | keeping listeners available after durable shutdown control changes |

Criticality is a semantic declaration, not a performance tuning knob. A worker
is critical only when continuing without it would violate an authority or
security invariant. A critical attempt error, panic, configured-watchdog expiry
or unexpected return is terminal; it does not wait for a second failure.
Restartable workers degrade readiness and rebuild with backoff because their
durable claims make repetition safe. `None` disables only the silence watchdog,
not error/return supervision. An observer has health state but no spawned
attempt to stall or restart. Adding a worker requires a unique name, heartbeat
source, maximum-silence rationale, shutdown behavior and a statement of what
durable state makes restart correct.

### Asynchronous ownership tree

| Task class | Handle owner | Cancellation/join owner | Panic or stall effect | Restart and durable recovery rule |
| --- | --- | --- | --- | --- |
| top-level service `JoinSet` | `main` | `main` cancellation and bounded drain | unexpected exit/panic is process-fatal | restart only by process supervisor; listeners do not own durable work |
| `WorkerRegistry` guardian | registry supervisor map | registry shutdown gate and retained `JoinHandle` | critical cancels process; restartable degrades readiness and is rebuilt with backoff | claim/lease/outbox makes a new attempt safe; heartbeat proves business progress |
| connection actor | `ConnectionActorRegistry` | admission-close, per-actor cancellation and bounded reap | affects exact connection; leaked/unfinished actor fails shutdown accounting | protocol reconnect, SM/BOSH replay and route generation define recovery |
| protocol post-action task | owning `ProtocolSession`/connection actor | session-local `JoinSet` before teardown | connection-scoped error; may close session when ordering cannot be preserved | must not outlive or mutate a replacement connection generation |
| request-scoped sidecar | HTTP/BOSH/upload/operation request owner | request/body cancellation and explicit local join/guard drop | request fails or durable claim remains recoverable | upload lease renewer, body pump and operation lease use exact claim/epoch |
| blocking/CPU work | bounded semaphore plus caller | caller cancellation/result collection | caller receives failure; permit bounds process-wide pressure | no implicit retry and no open DB transaction across blocking work |

Any future `tokio::spawn` must belong to one of these classes and make its
handle owner visible. A task whose handle is discarded is a defect, not a new
class.

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
   a durably journaled PostgreSQL `xid8` queried with `pg_xact_status()`—not EOF,
   a READY/DONE token or exit code—decide the outcome.

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

Where a setting offers value and secret-file forms, those forms are mutually
exclusive. Startup reads a bounded regular file or environment/config value,
validates it and moves or copies it into the narrow owner; owned Rust buffers
are zeroized where implemented. The process does **not** globally erase the
original OS environment, so directly supplied environment secrets can remain
observable through the host/process boundary for the process lifetime. Prefer
file-mounted secrets. Key/password bytes must never be rendered into logs or
normal command arguments. Maintenance wrappers explicitly close inherited file
descriptors and scrub the child environment before executing database clients;
that child-specific guarantee is not a claim that the parent environment was
cleared.

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

## Application-service capability registry

`AppState` constructs these services and exposes crate-private accessors. The
accessor is the capability boundary: callers receive a specific domain service,
not a generic database handle or keyring. “Persistence today” records whether
the service still embeds repository work; it is not permission for callers to
copy that coupling.

| Capability/accessor | Decision responsibility | Persistence/side-effect responsibility today | Explicitly outside the capability |
| --- | --- | --- | --- |
| `authentication_service()` | SCRAM/SASL2/FAST credential-family selection, account status and authentication-generation checks | authentication repository calls and token lifecycle | stream framing, TLS establishment and resource binding |
| `account_service()` | registration mode, invitation/account lifecycle and password-change authorization | user/credential mutations and account-operation transitions | session socket closure, which is requested only after commit |
| `admin_command_service()` | command session authorization and command semantics | command-role routines and command-session cleanup | general runtime table access or HTTP administrator authentication |
| `message_service()` | canonical message admission, storage policy, recipient visibility and delivery-plan construction | personal-history/admission/archive/offline/C2S/S2S atomic paths | socket queue ownership and protocol error serialization |
| `retraction_service()` | who may retract which stable message identity | tombstone/archive/outbox transaction | editing already delivered client state directly |
| `replay_service()` | replay eligibility, ordering and durable delivery-fence transfer | offline/C2S claim and acknowledgement transitions | creating new business messages during replay |
| `sm_service()` | XEP-0198 enable/resume/ack/teardown state transitions | durable resume suffix, capacity and teardown routines | owning the current TCP socket before explicit transfer |
| `roster_service()` | roster mutation, subscription and version semantics | roster/version/change-log transaction | presence socket fan-out before commit |
| `presence_service()` | subscription/service-message policy and delivery plan | durable pending/service-message claims | treating current availability maps as persisted truth |
| `privacy_service()` | active/default list evaluation from one snapshot | list/session persistence and activation transitions | blocking-list semantics or transport termination |
| `blocking_service()` | XEP-0191 block/unblock authorization and affected-route plan | block-list and roster/presence-related atomic mutation | directly iterating sockets while the transaction is open |
| `mam_service()` | archive preference and visibility policy | MAM preference/query repository work | decrypting OMEMO payloads or claiming client trust decisions |
| `pubsub_service()` | node access model, publish/retract/subscription and event projection | PubSub/PEP mutation plus required outbox atomicity | using cache or disco data as authorization truth |
| `profile_service()` | vCard/avatar ownership, normalization and visibility | profile/avatar metadata persistence | image decoding/cropping in the server or OMEMO identity binding |
| `private_storage_service()` | owner-only private XML semantics | private-XML repository transaction | exposing stored XML to another principal |
| `muc_service()` | room/affiliation/configuration/occupancy authorization | durable room management and archive/event projections; live occupancy via a narrow route path | allowing Redis or a nickname map to override durable affiliation |
| `mix_service()` | channel, participant, PAM, subscription and event authorization | MIX/PAM repositories and durable event outboxes | treating MUC mirroring or remote delivery as an implicit commit |
| `push_service()` | push-enable/disable policy and payload eligibility | subscription/delivery-attempt persistence | claiming a push provider accepted a message without its completion boundary |
| `upload_service()` | slot reservation ownership, quota, MIME/size and locator policy | currently only `reserve_slot`; HTTP claim/stage/promotion/finalize/delete orchestration remains in `src/api/upload.rs` and is explicit extraction debt | holding a PostgreSQL transaction during upload/download bytes or copying the HTTP orchestration into another caller |
| `extdisco_service()` | TURN credential eligibility, per-account/IP issuance windows and time-bounded credential derivation | privately owns the TURN shared secret and returns derived credentials for records selected by the XEP-0215 protocol handler | enumerating configured service records, operating the advertised service or exposing the long-term secret |
| `SessionCleanupService` | exact expired/revoked session teardown plan | cleanup claims and capacity release; currently constructed per `ProtocolSession` with `Arc<AppState>` rather than exposed by an `AppState` accessor | deleting a replacement connection that has a newer generation or becoming a pattern for new broad-state services |

Except for the explicitly identified `SessionCleanupService` construction debt,
the listed accessors are constructed by `AppState` and are crate-private.
Services return typed domain outcomes. Transport-specific XML/JSON, SQL row
types, raw `PgPool`, open transactions, secret bytes and live socket senders
must not cross these accessors. The remaining services that contain SQLx calls
own that repository work temporarily; the reduction path is to introduce a
domain repository port underneath the service, never to move persistence back
into protocol or API handlers.

## State classes and single sources of truth

| State class | Examples | Authoritative owner | Recovery rule | Forbidden inference |
| --- | --- | --- | --- | --- |
| durable business truth | users, roster, blocks, MAM, MUC/MIX configuration, PubSub items | PostgreSQL transaction and constraints | replay migrations/transactions from committed database state | Redis/cache/socket state cannot override it |
| durable work intent | outboxes, admissions, cleanup claims, operation journal, upload jobs | PostgreSQL row plus lease/epoch/fence | another supervised attempt reclaims after expiry/fencing | a wake notification or task exit is not completion |
| durable protocol replay | SM suffix, BOSH response fence, stable stanza/origin IDs | protocol-specific repository plus exact connection/session generation | transfer or replay only after generation/ack checks | current socket presence is not an acknowledgement |
| volatile route state | online sessions, occupants, authenticated S2S/component streams | exact in-process connection actor/registry incarnation | remove by compare-and-generation; reconstruct through reconnect/presence | a stale disconnect cannot delete a replacement incarnation |
| derived cache | caps/disco summaries, runtime federation cache, readiness snapshot | source-specific cache owner with expiry/version | recompute from authenticated observation or durable policy | cache miss is not a negative authorization answer |
| external object state | completed upload bytes, temporary objects and cleanup tombstones | object store coordinated by PostgreSQL locator/version/digest | claim, verify, finalize or reconcile in separate stages | object existence alone does not prove a committed slot |
| cluster soft state | Redis envelopes, route hints and local node observations | signed envelope plus PostgreSQL lease revalidation | discard/rebuild from PostgreSQL and live connections | Redis delivery/order is not consensus or durable truth |
| endpoint-only secret state | OMEMO identity/session keys and device trust | browser/client device | client export/transfer/recovery only | server archive or account password cannot reconstruct it |

## Failure ownership matrix

| Failure point | Component that detects it | Component that decides recovery | Durable evidence | Required terminal behavior |
| --- | --- | --- | --- | --- |
| malformed/oversized frame | transport framer | connection actor | none by design | reject/close only that connection |
| authorization conflict or replay | application service/repository | same service from typed DB result | stable identity, version or idempotency row | return deterministic conflict/replay without duplicate effect |
| database unavailable before commit | repository/service | caller plus worker/listener policy | no commit; PostgreSQL rollback | typed temporary failure; never publish success |
| socket backpressure after commit | outbound connection actor | delivery plan fallback/SM/offline owner | committed delivery projection or explicit volatile classification | disconnect/fallback/recover without reordering newer traffic |
| external effect ambiguous | bounded adapter/operation worker | operation journal or domain reconciler | claim, attempt ID, epoch and indeterminate state | retry only when idempotent; otherwise quarantine/manual decision |
| restartable worker error/panic/unexpected return, or configured-watchdog expiry | worker guardian; watchdog only when `max_silence` is present | `WorkerRegistry` | durable claims plus health generation | degrade readiness, back off and rebuild supervisor; a worker with no silence watchdog is still restarted on returned error/panic |
| synchronous health observer error | the operation that reports `observer_error` | `WorkerRegistry` health projection; there is no worker task to restart | observer health generation/error text | degrade readiness until a later synchronous success report; never claim that a guardian restarted work |
| critical worker failure | worker guardian/watchdog | top-level cancellation path | critical failure reason and authority state | stop all listeners; do not continue in a weaker mode |
| listener/service task exit | `JoinSet` supervisor | top-level shutdown | task identity/exit cause | process-wide coordinated shutdown |
| cluster/Redis partition | cluster failure policy | configured fail-closed/degraded state machine | PostgreSQL node/route leases and signed epochs | never promote Redis observations to authority |
| restore transaction acknowledgement loss | restore coordinator | PostgreSQL transaction-status arbiter | fsynced restore journal, xid8 and advisory barrier | accept only committed/aborted; unknown keeps hard fence |
| restore parent hard crash | next operator/recovery invocation | documented offline recovery procedure | hard connection fence, cutover journal, rollback dump/object set | normal restore refuses to erase evidence or reopen blindly |

## Database identities

| Identity | May do | Must not do | Mounted into |
| --- | --- | --- | --- |
| `northstar_bootstrap` | create/repair roles, owner and exact ACL policy | serve traffic, migrate normally, back up or restore application data | PostgreSQL initialization or explicit break-glass role reconciliation only |
| `northstar_migrator` | own application DB/schema, migrate, reconcile grants and perform stopped restore; connect to maintenance DB for restore control | superuser, role/database creation, replication, bypass RLS or maintenance `TEMPORARY` | migration, database-grants and restore jobs |
| `northstar_runtime` | execute runtime routine/table capability manifest | DDL, ownership, trigger disable, direct account-authority DML or command-only routines | long-lived server primary pool |
| `northstar_commands` | execute the exact command-session routine manifest | relation/sequence reads, general runtime DML or migration | isolated command pool inside long-lived server |
| `northstar_backup` | read the exact backup surface | write, execute business routines, allocate sequences, restore or use maintenance DB | backup job only |

### PostgreSQL connection and pool responsibilities

| Connection/pool | Role identity | Capacity | Consumers | Failure scope and restriction |
| --- | --- | --- | --- | --- |
| primary runtime pool | `northstar_runtime` | configured min/max, production maximum 64 | application services, repositories and legacy tracked runtime paths | shared workload pool; pre-pool gates must prevent one actor/NAT from occupying it while waiting |
| command pool | `northstar_commands` | maximum 4 | XEP-0133/admin command service only | command-routine manifest only; no relation/sequence privileges |
| OMEMO recovery polling pool | `northstar_runtime` | maximum 2 | bounded browser OMEMO recovery polling | isolates long polls from the primary pool but does not create a new DB authority |
| SM authority listener pool | `northstar_runtime` | maximum 1 | PostgreSQL LISTEN/revalidation for SM authority | notification is a wake hint; durable row/generation remains authority |
| identity audit pool | caller-supplied identity, operationally required to be runtime/read-only but not role-attested by the tool | maximum 1 | `audit-identities` only | default-read-only plus repeatable-read snapshot; never migrates; deployment wrapper/operator owns credential correctness |
| migration pool | `northstar_migrator` | maximum 2 | `migrate` only | one-shot owner capability; never mounted into runtime |
| PIE pool | runtime for export; migrator for import | configured value clamped to 1..8 | offline portability tool | import must be stopped and serializable; export does not gain migrator rights |
| backup connection | `northstar_backup` | one-shot client(s) | dump/manifest job | exact read-only backup surface; no application writes |
| restore sessions | `northstar_migrator` | four pre-opened sessions plus bounded dump tools | controller, coordinator, primary, compensation | one credential split by command routing; hard connection fence before replacement |
| bootstrap/reconcile connection | `northstar_bootstrap` | one-shot | fresh init or explicit role reconciliation | superuser break-glass boundary; absent from every long-lived service |

Pool separation is useful only where it prevents resource starvation or carries
a different PostgreSQL role. The OMEMO and SM pools are resource partitions,
not additional authorization boundaries.

## Private process-capability inventory

| Private capability family | Primary writer/owner | Readers/consumers | Persistence and expiry | Shutdown behavior |
| --- | --- | --- | --- | --- |
| BOSH manager and delivery fences | BOSH transport/runtime | exact BOSH requests and SM handoff | PostgreSQL fence plus bounded in-memory RID/session projection | rejects admission, completes/cancels registered requests, preserves replay rows |
| component and S2S registries | authenticated stream actors | outbound/router lookup | live route is volatile; durable delivery lives in outbox | compare-remove exact connection and leave durable retries claimed/recoverable |
| suspended MUC/SM endpoints | suspension coordinator | resume/teardown/recovery worker | durable SM/MUC projection plus bounded in-memory endpoint state | seal endpoints, persist suffix/teardown and prevent newer-generation deletion |
| Caps cache, gates and effect dispatcher | authenticated presence observation | disco/PEP/MIX capability decisions | bounded derived cache; current observation owns semantic projection | restore in-flight effect bits before cancellation/reconstruction |
| pending MIX IQ relay registry | MIX relay owner | exact reply/expiry route | volatile, generation/expiry bounded | expire/cancel exact relay only |
| upload store and safety authority | upload adapter/reconciler | HTTP transfer and upload worker | external bytes fenced by durable locator/version/digest | stop admission; leases/jobs recover incomplete transfer |
| worker and connection registries | composition root/registry methods | readiness and coordinated shutdown | process-local identity/generation | close registration gates, cancel, drain and report unreaped entries |
| runtime federation/admin policy cache | critical refresh workers | request/session policy evaluation | PostgreSQL authoritative, cache versioned/replaceable | critical staleness/failure cancels service |
| admission governors | `AppState` bounded semaphores/per-IP maps and `AbuseGuard` | C2S, upload, polling and action ingress | process-local permits plus PostgreSQL durable actor/cooldown state | permits drop; durable penalties survive restart |
| secret/key authorities | private typed owners described below | purpose-specific service/adapter only | memory-zeroized where supported; selected generations durable by ID | no secret logging; process memory is discarded on exit |

`state.rs` currently combines construction, live session/MUC registries,
SM/MUC suspension coordination, runtime policy caches, admission governors and
secret accessors. The target decomposition is `StateBuilder`,
`LiveSessionRegistry`, `MucLiveRegistry`, `SmMucSuspensionCoordinator`,
`RuntimePolicyCache`, `AdmissionGovernors` and `SecretAuthorities`, with
`AppState` retaining only composition and narrow read-only capability access.

## Secret and key authority ledger

| Secret/key | Runtime owner and purpose | Source/rotation | Loss or compromise effect | Never allowed |
| --- | --- | --- | --- | --- |
| TLS private key | reloadable TLS owner for C2S, S2S and XEP-0225 external-component TLS | permission-checked certificate/key files; atomic reload policy | loss blocks restart/reload; compromise permits those XMPP endpoint impersonations | logs, API responses or general service access; Northstar's Axum HTTP/metrics listeners are plaintext and production HTTPS belongs to the reverse proxy |
| application bootstrap-admin password | startup-only account bootstrap call before `AppState` construction | optional environment/secret-file input; it creates the configured administrator only when the users table is empty, leaves an existing administrator/password unchanged, and clears the configuration field after use | loss prevents first-account creation; compromise can choose that first administrator password only during empty-database startup and is **not** a password-rotation path | confusion with the PostgreSQL bootstrap superuser, retention in `AppState`, logs or child arguments |
| abuse HMAC current/previous generations | `AbuseGuard`; actor pseudonyms and purpose-derived durable message/retraction identity keys | required protected file in production; controlled generation overlap | loss breaks stable mapping/recovery; compromise weakens privacy and durable identity integrity | reuse as FAST/API/cluster key or expose derived content keyrings to protocol code |
| FAST master key | authentication service/token keyring | protected file; current issuance plus bounded prior-token lifetime | loss invalidates FAST chains; compromise permits token forgery within policy | reuse as dummy SCRAM or log token/key material |
| dummy SCRAM key | authentication anti-enumeration path | independent protected file | loss changes dummy verifier behavior; compromise only weakens that masking boundary | equality with FAST or user credential material |
| Dialback secret | S2S Dialback verifier | protected shared file is mandatory with Redis clustering; without one, single-node startup currently generates a process-local random secret in every environment | restart with a generated value invalidates outstanding/stable Dialback proofs; compromise permits forged callback proofs within other checks | process-local random value in clustered mode or an assumption that single-node production is restart-stable without a configured file |
| API control/cursor current/previous keys | API operation/idempotency/cursor key owner | protected files with bounded overlap | loss invalidates control tokens/records; compromise permits forgery/tampering attempts | exposure through general config, logs or client JS |
| cluster Ed25519 private key | cluster envelope signer | protected key file with key-ID deployment authority | loss isolates node; compromise permits signed control-envelope forgery until revoked | Redis storage or treating possession as DB lease authority |
| component credentials | private `AppState.component_credentials` map; the handshake receives only an exact credential clone while the separate component registry owns live routes | protected components JSON may contain an inline secret or a `secret_file`; file form is preferred and provenance is hashed | loss breaks component auth; compromise grants only configured component/domain scope | plaintext logs, protocol-wide map access, or implicit wildcard domains |
| TURN shared secret | `ExtDiscoService` credential derivation | mutually exclusive inline environment value or protected file; derived credentials have bounded TTL | loss breaks issued credentials; compromise permits TURN credential minting | returning the long-term secret to clients |
| metrics bearer | metrics listener authentication | protected file; required for non-loopback bind | loss blocks scraper; compromise exposes bounded operational telemetry | URL/query string or metric label |
| PostgreSQL URLs/passwords | pool/client wrapper owners | mutually exclusive value/file; mounted role-specific secret | compromise grants exactly that role's capabilities | PostgreSQL bootstrap URL in runtime, command URL in protocol, or command-line password |
| Redis URL/authentication material | `ClusterManager` transport connector | protected value/file configuration associated only with cluster mode | loss disables cluster transport; compromise grants the configured Redis authority but not PostgreSQL business authority | protocol/service exposure, logs, or treating Redis authentication as message/account authorization |
| Redis mTLS client private key | `ClusterManager` TLS connector | permission-checked protected key file with configured client certificate/CA | loss prevents Redis TLS authentication; compromise permits client impersonation to the configured Redis trust domain | reuse as the XMPP TLS identity, general `AppState` exposure or logging |
| S3 credentials/KMS identifier | object-store adapter | atomic credential bundle or ambient workload identity | loss blocks object I/O/reconciliation; compromise reaches configured bucket/prefix | embedded public config, logs or unbounded provider scope |
| backup signing/age keys | separate backup/restore jobs | offline/mounted signer, recipients and restore identities | loss blocks authenticity/decryption; compromise affects backup trust/confidentiality | runtime container mount or repurposing restore identity as rollback encryption |

## Configuration authority classes

| Class | Examples | Update owner | Runtime interpretation |
| --- | --- | --- | --- |
| immutable startup configuration | binds, domain, pool sizes, feature enablement, storage backend | environment/secret files before `AppState` | validated once; change requires controlled restart |
| durable runtime policy | federation rules, administration settings, service control | PostgreSQL command/admin transaction | critical watcher refreshes a versioned cache; database remains source of truth |
| cluster notification/soft state | Redis route and invalidation envelopes | authenticated publishing node | wake/hint only; recipient revalidates PostgreSQL generation/lease |
| local derived cache | Caps/disco, readiness and policy projections | owning cache/worker | bounded and replaceable; miss/staleness cannot silently authorize |
| durable stop authority | service-control generation/state | PostgreSQL plus critical watcher | can cancel the process; Redis/environment cannot revoke that committed decision |

## Observability and audit responsibilities

| Surface | Owner | May reveal | Must not reveal/do | Failure meaning |
| --- | --- | --- | --- | --- |
| `/healthz` | HTTP process probe | process liveness only | database queries, secrets or business health claims | failure means process/HTTP path is unavailable |
| `/readyz` | cached bounded readiness aggregator | dependency/worker class and bounded reason | unbounded anonymous DB work or mutation | failure removes instance from traffic; it is not a data-integrity repair |
| `/metrics` | private metrics listener | fixed-cardinality counters/gauges and bounded cached DB snapshot | public exposure without loopback/private ACL or bearer; usernames/JIDs/stanza bodies as labels | scrape failure is observability loss; alerts decide operator action |
| tracing logs | component that detects an event | redacted operational identifiers, bounded errors and state transitions | passwords, tokens, keys, full private stanzas or attacker-controlled high-cardinality fields | diagnostic evidence; log write is never business acknowledgement |
| PostgreSQL `audit_log`/operation journal | committing service/repository | actor/action/target/result facts required for administration and recovery | secret values or a claim that an external effect completed before its boundary | committed audit/journal row is durable control-plane evidence |
| release/test artifacts | CI or explicit operator fixture | checksums, summaries, sanitized failure logs and conformance evidence | production secrets/data or claims beyond the executed fixture | gates the tested artifact only; skipped suites remain explicitly unproven |

Readiness aggregates critical worker health, database/security authorities and
enabled cluster/upload/SM dependencies. A cache/single-flight bounds probe
cost; a public request cannot create a fresh set of unrestricted database
queries. Alerting policy belongs to monitoring configuration, not to a request
handler that mutates service state.

## Verification responsibility matrix

| Verification layer | Owns evidence for | Does not prove | Required when changing |
| --- | --- | --- | --- |
| Rust unit/property tests | pure policy, parser/state transition, serialization and bounded concurrency helpers | PostgreSQL ACL/locking, real sockets or client interoperability | every changed local invariant |
| architecture/document gates | forbidden dependencies, exact capability/task inventory, ledger/doc consistency | runtime reachability or behavioral equivalence | responsibility, module, worker, service or public-support changes |
| isolated PostgreSQL tests | migrations, routines, constraints, transactions, locks and exact role grants | Internet federation, object provider or browser behavior | schema/repository/role/restore changes |
| protocol/runtime fixtures | C2S/BOSH/WebSocket stanzas, SM, MUC/MIX/PubSub and transport ordering | arbitrary third-party client coverage or public network conditions | wire behavior and end-to-end routing changes |
| federation/component/cluster fixtures | authenticated multi-process domain/component/Redis interactions and degraded modes | production DNS/CA/Redis failover topology | S2S, component or cluster changes |
| browser/OMEMO tests | SASL2/FAST/SM browser flow, OMEMO multi-device state and no-downgrade behavior | security of browser extensions/host or every upstream crypto implementation | web auth, storage, OMEMO and asset changes |
| backup/restore drills | artifact verification, role boundary, cutover, compensation and interruption state machine | operator site encryption, hardware failure and infinite XID status retention | backup, migration, roles, uploads or restore logic |
| load tests | configured 1,000-session fixture, queue/backpressure and admission behavior | universal production capacity/SLA | hot-path, pool, queue and routing changes |
| parser fuzzing | panic/memory-safety regressions over generated framing inputs | complete semantic protocol conformance | parser/framer/tokenizer changes |
| Gajim/manual interoperability | observed behavior for the recorded client/build/scenario | certification or all-client compatibility | release candidate OMEMO/MUC flows when an operator environment is available |
| deployment validation | real DNS, public CA, firewall/proxy, remote S2S, monitoring and restore exercise | source-level correctness by itself | every production site before traffic |

Tests own evidence, not product authority. A fixture may receive a dedicated
isolated role or database, but production code must never weaken an ACL,
timeout, transaction or parser boundary merely to make the fixture convenient.

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
| maintenance controller | `postgres` | target `ALLOW_CONNECTIONS`, exact `pg_database.datallowconn` read-back and target PID census | backup/restore advisory lock, target transaction-status query, dump replay, schema/grant body and compensation | shared connection-fence/catalog state only | exact PID/FD registration; child is reaped, not independently restarted |
| target coordinator | target | backup/restore session lock, replacement-transaction barrier and post-barrier `pg_xact_status(xid8)` query | connection fence, dump/schema replay and deciding status before the barrier | same-database barrier proves the executor transaction ended before status arbitration | exact PID/FD registration; kept until workers close |
| primary executor | target | pre-fence policy lock, current-target preflight, allocate/publish the incoming `xid8` and execute incoming replacement | compensation, connection-fence control and declaring its own commit successful | transaction XID emitted before READY; PostgreSQL status after settlement | exact PID/FD registration; active input is closed/drained on interruption |
| compensation executor | target | allocate a distinct rollback `xid8` and replay the retained rollback dump after outcome arbitration | incoming replacement, connection-fence control and declaring its own commit successful | distinct rollback XID plus PostgreSQL status after settlement | pre-opened before fence; invoked only by compensation state |
| restore parent journal | local private filesystem | bind restore ID, target DB, transaction kind, worker PID, barrier key and XID; fsync before destructive SQL | interpreting COMMIT, changing target data or inventing a missing XID | append-only intent/outcome records and directory/file fsync | parent state machine; retained after unknown/hard-crash outcomes |

The controller is outside the target because PostgreSQL refuses changing
`ALLOW_CONNECTIONS` for the current database. The coordinator stays inside the
target because advisory locks include the database OID. The primary holds the
policy lock across preflight and rollback-dump capture; only after the hard
fence proves that coordinator, primary and compensation are the exact three
remaining target PIDs may it release that lock. No new target connection can
then enter.

Each executor starts its transaction, acquires its unique transaction-level
advisory lock and calls `pg_current_xact_id()` before it emits READY. The parent
strictly parses exactly one nonzero `xid8`, binds it to the exact worker and
barrier in the cutover journal, and fsyncs that intent before sending any
schema drop, dump replay or grant SQL. If journaling fails, the executor input
is closed and PostgreSQL rolls back a transaction that has not received a
destructive command.

After worker input is closed/drained or COMMIT acknowledgement is received, the
coordinator acquires the same transaction advisory lock and only then calls
`pg_xact_status(xid8)`. `committed` and `aborted` are the only automatic
outcomes. `in progress`, `NULL`, malformed/multiple output or a query failure
are unknown and keep `ALLOW_CONNECTIONS=false` with the journal and rollback
materials retained. The function reports only recent XIDs; a hard-crash
journal left until PostgreSQL discards that status therefore requires manual
recovery. Incoming and compensation transactions always have different XIDs.
This model grants no new PostgreSQL privilege and does not use a custom GUC as
a substitute database marker.

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
9. The durable operation loop is a top-level service task rather than a
   `WorkerRegistry` member. Its task exit is fatal, but persistent handled
   database errors do not currently degrade readiness. It should become a
   restartable continuous worker with lease-aware heartbeat reporting.
10. `background-maintenance` serializes cleanup for several unrelated domains.
    Durable idempotence makes restart safe, but one slow/failing domain can
    delay the others and produce an imprecise health signal. Split it by
    recovery/criticality domain before adding more maintenance work.
11. Long-lived Caps, MIX and PubSub workers are still registered from protocol
    modules. Their stanza parsing belongs there; their claim/retry/runtime
    loops should move to domain runtime modules that depend on service ports.
12. Runtime startup still receives the application bootstrap-admin password and
    performs the one-time administrator ensure operation before `AppState`.
    Moving that operation to a distinct one-shot bootstrap job would remove the
    secret and account-creation responsibility from the long-lived executable.
13. PIE export publishes the completed file before appending its audit row. A
    database failure can therefore return an error while leaving the file. A
    future export journal should represent intent, publication and audit
    completion explicitly instead of implying cross-filesystem/DB atomicity.
14. `audit-identities` makes its transaction read-only but does not attest that
    the supplied URL maps to the runtime/read-only role. Deployment wrappers
    currently own that credential boundary; the tool should gain an explicit
    role/capability attestation.
15. File-backed secrets are preferred, but inline environment secrets are not
    removed from the parent OS environment after parsing. Eliminating that
    exposure requires a launcher/exec handoff or file-only production policy,
    not a documentation claim that Rust zeroization can erase inherited env.

Further reduction should proceed in this order: move direct REST transactions
behind application services, extract embedded service/runtime persistence into
repository ports, remove raw `AppState.pool`, replace the session/MUC public
maps with registries, split operation workers into narrow capability structs,
then consider per-domain PostgreSQL roles only after the service transaction
boundaries are stable. CI treats the current field
identities and zero protocol/database dependency counts as monotonic ceilings:
a new feature must not widen them.
