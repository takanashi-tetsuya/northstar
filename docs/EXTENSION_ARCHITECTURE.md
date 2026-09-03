# Extension and deployment-surface architecture

Northstar uses **statically linked extensions with a frozen runtime registry**.
An operator can enable or disable an extension in configuration, but changing
the active graph requires a process restart. This is intentional: unloading a
dynamic library while a stream, database transaction, background job, or
delivery acknowledgement still refers to it would make protocol behaviour and
recovery authority ambiguous.

This document is a design and enforcement contract. It defines what a library
may own, what it must not own, how configuration is resolved, and how support
is removed from discovery when a component is unavailable. Protocol support
claims remain in [../XEP_MATRIX.md](../XEP_MATRIX.md).

## 1. Dependency direction

The allowed dependency direction is:

```text
northstar-server (composition root)
  -> transports / HTTP surfaces / XEP adapters / storage adapters
  -> runtime and domain APIs
  -> plugin API / XML / common types
```

Dependencies must never point back toward the composition root. In
particular, a reusable crate must not import `AppState`, a raw `PgPool`, an
Axum router, or a transport socket merely to obtain a service.

The intended workspace responsibilities are:

| Library family | Owns | Explicitly does not own |
| --- | --- | --- |
| common types | JIDs, IDs, qualified names, value objects, protocol/domain errors | I/O, SQL, sockets, global configuration |
| XML | bounded framing, parsing and typed stanza construction | authorization, persistence, routing policy |
| extension API | manifests, dependency graph, route keys, discovery contributions, worker declarations | concrete XEP behaviour, SQL, HTTP |
| runtime | immutable registry snapshot, ordered hook execution, session/routing kernel, readiness aggregation | concrete plugin configuration, database implementation |
| domain services | authorization snapshots and complete transactional use cases | XML, XEP namespaces, Axum, sockets |
| PostgreSQL adapter | domain-port implementations, migrations, lock order and durable invariants | stanza parsing and transport behaviour |
| storage adapter | local/object-store byte persistence behind the upload port | XMPP and HTTP request policy |
| XEP libraries | wire validation/mapping, manifest, discovery declaration and exact typed ports | `AppState`, generic service lookup, raw SQL and arbitrary spawning |
| transport libraries | C2S/S2S/component/WS/BOSH framing and connection lifetime | concrete XEP and repository implementations |
| HTTP surface libraries | one bounded router surface and its middleware contract | routes belonging to another surface, raw cross-surface session state |
| server binary | configuration composition, concrete provider selection, registry freeze and listener supervision | reusable protocol/domain behaviour |

The first extraction steps retain the existing server package as the
composition root. A legacy handler may temporarily serve routes that have not
yet crossed a crate boundary. Every migrated route must be deleted from that
fallback and from hard-coded service discovery in the same change.

## 2. What “pluggable XEP” means

In Northstar, XEP extensions are **statically-linked, capability-isolated, configurable built-in modules** rather than dynamically-loaded (dlopen/WASM) external plugins. File separation alone is not an extension boundary. A Northstar XEP extension is modularly isolated because:

1. Its wire behaviour is compiled in a dedicated crate.
2. Its manifest has a stable extension ID and declares dependencies,
   conflicts, discovery features, routes, workers and companion HTTP surfaces.
3. The configuration resolver can include or exclude it before listeners
   start.
4. A disabled extension registers no exclusive route, discovery feature,
   worker, HTTP route, or database capability.
5. The extension receives only its exact typed domain ports. It cannot reach a
   global state object or database pool.
6. Route, worker, HTTP surface and singleton-provider conflicts fail startup.
7. Tests prove that its disabled state is absent from both dispatch and
   discovery, not merely hidden in the UI.

XEP crates are protocol adapters, not miniature applications. For example,
XEP-0313 maps MAM IQs to an archive query port; it does not open its own SQL
transaction. XEP-0363 has an XMPP adapter and an HTTP companion, both of which
use the same upload-domain service. XEP-0060 and XEP-0163 share PubSub-domain
ports without importing each other.

## 3. Manifest contract

Each extension descriptor is immutable and includes, as applicable:

- stable plugin and XEP identifiers;
- implementation/API version;
- maturity and default activation state;
- provided capabilities;
- required and optional dependencies;
- conflicts and singleton-provider groups;
- exact IQ route keys;
- ordered message/presence hook phases;
- service-discovery identities, features and forms;
- required database/domain capabilities;
- worker specifications and readiness impact;
- companion HTTP routes and their surface;
- redacted configuration namespace.

An IQ route key is more specific than an XML namespace. It contains the
session phase, addressed entity class, IQ type and qualified payload name.
Duplicate exclusive keys are a startup error. Message and presence extensions
run through declared phases:

```text
validate -> authorize/policy -> plan -> commit -> publish -> observe
```

Plugins cannot invent a new order by calling one another. Same-phase handlers
with an ambiguous priority are rejected when the registry is built.

## 4. Configuration graph

Activation is resolved before database preflight or network listeners:

1. validate the compiled catalog and reject duplicate plugin IDs;
2. parse core and plugin namespaces and reject unknown keys;
3. expand dependencies of explicitly enabled plugins;
4. reject an explicitly disabled required dependency;
5. choose exactly one implementation for singleton capabilities;
6. reject route, hook, HTTP path, worker, config-prefix and migration conflicts;
7. reject dependency cycles and print the complete cycle;
8. load secrets only for active plugins;
9. attest their database/domain capabilities;
10. construct handlers and workers, then freeze one registry snapshot;
11. start supervised workers in dependency order;
12. bind listeners only after required capabilities are ready.

The first implementation uses explicit booleans for deployment surfaces and
the migrated extensions. Future namespaced configuration may offer the three
states `auto`, `enabled`, and `disabled`; an explicit enable of a plugin absent
from the binary must always fail. It must never silently pretend the feature
exists.

Configuration changes are restart-required. Active streams share an
`Arc<RegistrySnapshot>` so one session cannot observe half of an old graph and
half of a new graph.

## 5. Dependency and conflict policy

The resolver distinguishes a dependency from an operational convenience:

- **required dependency**: disabling it while its consumer is enabled is an
  error, unless the dependent surface is explicitly documented to become
  ineffective as one unit;
- **optional dependency**: may add behaviour but must not weaken an
  authorization or encryption policy when absent;
- **conflict**: both cannot be active; startup reports both owners and the
  contested capability;
- **provider choice**: multiple compiled implementations require an explicit
  provider selection;
- **effective disable**: a user-facing feature whose only entry point is
  disabled becomes disabled too, and the effective configuration reports the
  reason.

Invitation-only browser registration is an effective-disable case. When the
Web client surface is disabled, its invitation-registration workflow is also
disabled even if the invitation switch remains present in an old environment
file. Native XEP-0077/open-registration policy is evaluated separately; the
operator must not accidentally expose or advertise a browser workflow with no
client surface.

## 6. Service discovery and entity capabilities

XEP-0030 is the only feature aggregator. An extension contributes declarative
identities, features and forms to the resolved registry. It does not mutate a
global feature list.

The same canonical resolved projection feeds both disco responses and
XEP-0115 capability hashing. Therefore an extension that is disabled,
uninitialized, missing a required domain capability, or degraded by a failed
required worker cannot continue advertising support.

Dynamic contributions such as PEP `+notify` interests use typed capability
providers. XEP-0030, XEP-0115 and XEP-0163 must not import each other's
implementations. Cache/Redis state can accelerate a lookup but cannot decide
authoritative support.

## 7. Workers and persistence

An extension returns worker declarations; it does not call `tokio::spawn`.
The declaration contains a globally unique `plugin-id/worker-name`, criticality,
restart mode, watchdog policy, readiness class, cancellation/drain contract,
required ports and durable recovery statement.

The runtime starts workers after registry and database preflight and shuts
them down in reverse dependency order. A required security worker can fail the
service closed. A restartable optional worker can make only its owning feature
unready; discovery must follow that readiness state.

XEP wire crates never receive a SQL transaction. A domain service opens and
commits the transaction for one complete semantic command. External delivery
begins only after commit. Cross-XEP atomic operations remain in a shared domain
service: personal-message admission, MAM projection, offline delivery, S2S
outbox and replay identity are one messaging transaction rather than five
plugins attempting to coordinate transactions.

Disabling an extension never drops stored data. Schema removal is a separate,
explicit maintenance operation. Runtime database identities cannot execute
DDL; migrations remain a one-shot composition-root responsibility.

## 8. Web and HTTP isolation

The HTTP deployment model has four independently enabled listeners:

| Surface | Contains | Default exposure |
| --- | --- | --- |
| XMPP HTTP | WebSocket, BOSH, host-meta and protocol companion routes | loopback behind a trusted reverse proxy |
| Web client | end-user static assets and end-user REST API | loopback behind a trusted reverse proxy |
| Web administration | administrator assets and administrator REST API | loopback only |
| observability | health/readiness/metrics according to the endpoint policy | loopback/private monitoring network |

Each surface has its own router, bind address, body limits, CSP, authentication
audience, cookies/headers, OpenAPI scope and static fallback. A route manifest
names its surface; the same method/path cannot be registered on two surfaces.
Public discovery never exposes the administration URL.

The administration listener defaults to a different loopback port. A
non-loopback bind requires an explicit opt-in and an authenticated secure
transport policy; being on a separate port is not itself an authorization
boundary. Client and administrator frontends do not share a service worker,
local storage, runtime session state, or static fallback.

Longer term, the admin surface can become a separate process. Live operations
then use a durable command/control port instead of direct access to in-memory
server state.

## 9. Extension classes and migration order

Not every XEP has the same privilege. Migration follows these classes:

| Class | Examples | Boundary |
| --- | --- | --- |
| stateless IQ | XEP-0199, XEP-0202, XEP-0092 | ordinary exclusive IQ plugin |
| message metadata | XEP-0184, XEP-0085, XEP-0333, XEP-0359, XEP-0380, XEP-0444 | ordered validation/policy hook; no direct persistence |
| account-backed IQ | XEP-0049, XEP-0054, XEP-0292 | typed account/profile domain port |
| policy | XEP-0191, XEP-0016 | shared contacts-policy snapshot port |
| history/push/upload | XEP-0313, XEP-0357, XEP-0363 | domain query/command port plus supervised workers or HTTP companion |
| eventing | XEP-0060, XEP-0163, XEP-0115 | shared PubSub and canonical discovery ports |
| rooms | XEP-0045 and MIX family | shared room identity/authorization domain; bridge is a separate plugin |
| privileged session extension | XEP-0198, XEP-0352, XEP-0386, XEP-0388, XEP-0484, IBR family | typed session-extension slot in the stream kernel, not an ordinary stanza plugin |

Privileged session extensions move only after `ProtocolSession` is decomposed
into core stream state and typed extension slots. Treating SASL, bind, SM or
CSI as an ordinary message handler would be a misleading and unsafe boundary.

The extraction order is deliberately vertical: route, discovery contribution,
configuration, tests and legacy deletion move together. Stateless IQ and
message-metadata extensions validate the registry first; stateful and
cross-surface extensions follow after typed domain ports exist.

## 10. Forbidden dependency cycles

Architecture checks reject or reviewers must reject these patterns:

- discovery importing concrete plugins (plugins contribute to discovery);
- PubSub, PEP and caps importing one another (use shared ports);
- MUC and MIX importing one another (use a bridge plugin);
- message extensions directly coordinating MAM/offline/S2S/push transactions;
- roster/presence/privacy/blocking maintaining separate authorization truth;
- SM and routing/replay/MUC cleanup owning one another's state;
- XEP-0363 importing HTTP or object-store adapters;
- admin code importing runtime state for live effects;
- configuration importing concrete plugins;
- plugins spawning unsupervised workers;
- domain crates importing PostgreSQL implementations;
- transports importing concrete XEP crates;
- frontend assets sharing authentication/session/OMEMO runtime state across
  client and admin surfaces.

## 11. Acceptance gates

Each extraction must pass all of these checks:

- no unexpected change to the support matrix;
- an XEP crate has no dependency on the server package, SQLx, Axum,
  `AppState`, `PgPool`, or raw sockets;
- plugin IDs, route keys, worker names and HTTP surface routes are unique;
- disabled extensions have no route, discovery entry, worker or companion
  endpoint;
- a migrated route no longer exists in the legacy dispatch match or hard-coded
  discovery list;
- workers start only through the worker registry;
- feature advertisements follow resolved readiness;
- an HTTP route belongs to exactly one declared surface;
- unit, PostgreSQL, protocol, browser and multi-process evidence remains green
  for the behaviours affected by the slice.

Static gates enforce dependency direction and obvious authority leaks.
Protocol and integration tests remain necessary to prove behaviour; neither
kind of evidence substitutes for the other.
