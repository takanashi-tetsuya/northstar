# Northstar modularization progress and remaining work

## 1. Executive status

Northstar currently builds as one deployable server binary over 49 internal
`northstar-*` libraries. The extraction is no longer experimental: all 49
libraries are root workspace members, direct runtime dependencies where
applicable, and covered by the same lockfile and strict workspace Clippy gate.

The protocol leaf layer is substantially separated. The application and
infrastructure layers are not. The current work should therefore be described
as **an integrated modular monolith with several real ports**, not as a set of
fully independent services.

Evidence from the current pass:

| Gate | Result |
| --- | --- |
| Root unit suite | passed |
| Workspace strict Clippy | passed with all targets and all features |
| Root all-feature check | passed |
| XEP plugin gate | 24 plugins, 56 exclusive routes, no forbidden capabilities |
| Program architecture gate | 9 public `AppState` capabilities; protocol has zero DB/SQLx/pool references |
| Library inventory | 49 integrated libraries; no nested workspace or library-local lockfile |

This is static/unit evidence only. PostgreSQL, Redis, browser, Gajim,
federation, load, fuzz, backup/restore and packaging qualification remain part
of the release gates and are not implied by this report.

## 2. What is now genuinely separated

| Boundary | Current owner | What the root binary still owns |
| --- | --- | --- |
| canonical JIDs | `northstar-xmpp-types` | route lookup and authorization effects |
| XML framing | `northstar-xml-framing` | transport buffers, timeouts and closure |
| XML output | `northstar-xml-builder` | selection of protocol payloads |
| authentication algorithms | `northstar-auth-core` | account lookup, credential transactions and TLS facts |
| abuse policy | `northstar-abuse-policy` | persistent actor state, locks, clocks and challenges |
| XEP wire/pure policy | 24 `northstar-xep-*` crates | application authorization, transactions and delivery |
| personal messages | `northstar-message-core` + `northstar-message-application` | PostgreSQL adapter and post-commit Carbon/Push/route executors |
| room / MUC domain & application commands | `northstar-room-core` + `northstar-room-application` | PostgreSQL repository adapter and cluster outbox coordination |
| PubSub / PEP | `northstar-pubsub-core` + `northstar-pubsub-application` | PostgreSQL repository adapter and audience projection |
| roster & subscription | `northstar-roster-core` + `northstar-roster-application` | PostgreSQL repository adapter and outbox delivery |
| archive / MAM (XEP-0313 & 0059) | `northstar-archive-core` + `northstar-archive-application` | PostgreSQL repository adapter and outbox delivery |
| upload (XEP-0363) | `northstar-upload-core` + `northstar-upload-application` | PostgreSQL reservation and object store I/O gates |
| S2S federation & outbox (RFC 6120 & XEP-0220) | `northstar-federation-core` + `northstar-federation-application` | PostgreSQL outbox repository adapter, TLS handshake and socket loop |
| stream opening & session routing | `northstar-session-core` + `northstar-session-application` | authenticated/bound/SM/CSI state and transport actions |
| ordered outbound contract | `northstar-delivery-core` | Tokio sink adapter, BOSH/SM/socket acknowledgement execution |
| presence session policy | `northstar-presence-core` | roster/privacy snapshots and live fan-out |
| HTTP surface capability graph | `northstar-web-surface` | Axum routers, assets and listener supervision |

The message and room slices are important because they cross all four layers:
protocol command, application validation, injected repository, and typed
post-commit result/effect plan. A parser copied to a crate without these call
paths is not counted as completed separation.

## 3. Current dependency direction

```text
main / composition root
  -> listeners, HTTP and XMPP adapters
  -> application services and injected ports
  -> domain and XEP libraries

PostgreSQL / Redis / object store / push / sockets
  -> root adapters implementing those ports
  -> never imported by domain or XEP libraries
```

The architecture checks enforce the bottom half of this direction. The top
half still contains broad root capabilities, especially in API, cluster,
federation, upload, PubSub, MIX and worker orchestration.

## 4. Remaining library forecast

The expected final count is **50–56 internal libraries**, so approximately
**12–18 additional libraries** remain. The range is intentional: a library is
created only when it owns a stable authority/transaction boundary. Tiny helper
crates and one-crate-per-file extraction are explicitly rejected.

| Proposed library or convergence target | Responsibility | Depends on | Estimated effort |
| --- | --- | --- | ---: |
| `northstar-pubsub-core` | owned node/item/subscription commands, immutable authorization/audience snapshots and typed outcomes | XEP-0060, XMPP types | 5–8 d |
| `northstar-pubsub-application` | repository ports for atomic node/item/audience/outbox mutations; PEP account adapter | PubSub core | 7–12 d |
| `northstar-roster-core` | roster/subscription/visibility commands and immutable generation snapshots | XMPP types, presence core | 3–5 d |
| `northstar-roster-application` | atomic roster mutation, subscription transition and push plan repositories | roster core | 5–8 d |
| `northstar-archive-core` | personal/MUC/MIX visibility facts, query commands, tombstone/correction/reaction projections | XEP-0059/0313 | 4–7 d |
| `northstar-archive-application` | MAM query and retention repository ports without XML rewriting | archive core | 5–9 d |
| `northstar-upload-core` | slot/object locator/version/digest lifecycle and reconciliation commands | XEP-0363 | 4–7 d |
| `northstar-upload-application` | atomic capacity/slot/cleanup authority plus versioned object-store effects | upload core | 7–12 d |
| `northstar-object-store-port` | exact put/get/delete-version contract for local and S3 adapters | upload core | 2–4 d |
| `northstar-federation-core` | authenticated-domain grants, route plans, outbox lease and retry values | XMPP types | 4–7 d |
| `northstar-federation-application` | DNS/TLS decision inputs, durable S2S/component outbox repositories and relay authorization | federation core | 7–11 d |
| `northstar-session-application` | authentication, bind, resume-store, publication and ordered-output ports around one kernel | session/delivery/auth cores | 7–12 d |
| `northstar-live-routing` | exact route incarnation, resource selection and replacement outcomes | session core, presence core | 3–6 d |
| `northstar-administration-core` | typed commands, operation identity, audit facts and runtime-setting policy | XMPP types | 3–5 d |
| `northstar-administration-application` | command-role repository, idempotency journal and effect arbitration | administration core | 5–9 d |
| optional `northstar-worker-runtime` | executor-neutral worker registration, health and restart/fatal policy | no domain capability | 3–5 d |
| optional `northstar-cluster-application` | PostgreSQL lease authority and Redis soft-state adapter split | routing/federation/room ports | 8–14 d |
| optional `northstar-push-provider` | provider-neutral XEP-0357 delivery attempt and retry port | XEP-0357 | 2–4 d |

“Optional” means the boundary may remain a root module if extraction would
only wrap an implementation without reducing authority. The responsibility
must still be narrowed even if no new crate is created.

## 5. Ordered implementation packets

### Packet 1 — PubSub/PEP command boundary

Completed in this packet: the PEP publish flow now uses
`northstar_pubsub_application::PepPublishItemsCommand` and
`PepPublishItemsResult`. `PubSubService::publish_pep_items` now validates command
input in the application layer, keeps the existing atomic DB transaction path, and
returns a typed outcome + `content_changed` flag. `src/xmpp/protocol/pep.rs`
now maps that typed result to protocol outcomes and does not own a publish DB
pipeline.

Remaining for Packet 1: convert remaining PubSub mutation operations (including
all subscription mutation adapters and remaining fan-out planning points) to the
same command/result boundary so XML handlers have zero commit composition.

### Packet 2 — Complete room convergence

Completed: Subject, moderation/retraction, affiliation, configuration and registration commands
now run behind typed application commands (`MucSubjectCommand`, `MucRetractionCommand`,
`MucAffiliationBatchCommand`, `MucConfigurationCommand`, `MucRegistrationCommand`) in
`northstar-room-application` and pure domain types in `northstar-room-core`. `src/services/muc.rs`
provides unified `execute_muc_*` atomic methods, and `src/xmpp/protocol/muc.rs` exclusively dispatches
typed commands without ad-hoc transaction composition.

### Packet 3 — Session kernel

Group authenticated identity, bind/route incarnation, SM and CSI into explicit
substates. Inject authentication, bind, resume-store, publication and outbound
ports. Move TCP, direct TLS, WebSocket and BOSH action execution outside the
kernel while preserving BOSH response fences and XEP-0198 replay ownership.
Exit when the session kernel imports no Tokio channel, socket or root service.

### Packet 4 — Roster/visibility and archive

Completed for Roster: Extracted capability-free RFC 6121 domain entities (`RosterChange`, `RosterReadSnapshot`,
`RosterRemovalTransition`, `SubscriptionType`, `LocalPresenceTransition`, etc.) into `northstar-roster-core`.
Extracted typed commands (`RosterGetCommand`, `RosterUpsertCommand`, `RosterRemoveCommand`), pure validation
rules, and the memory-pure `RosterSyncGate` push fence into `northstar-roster-application`.
`src/services/roster.rs` now provides atomic `execute_roster_*` methods, and `src/xmpp/protocol/roster.rs`
dispatches typed commands without manual parameter passing or database coupling.

Remaining for Packet 4: Archive / MAM domain extraction (`northstar-archive-core`, `northstar-archive-application`).

### Packet 5 — Upload/object lifecycle

Separate XMPP/HTTP adapters, capacity/slot authority, object bytes and
reconciliation. Local and S3 adapters must implement exact version/delete
semantics. Exit when no HTTP handler can independently modify slot/object
state and crash recovery is fault-injectable through ports.

### Packet 6 — Federation, components and cluster

Separate transport connectivity from relay grants. S2S and components receive
distinct authenticated-domain capabilities; Redis remains a hint/cache plane
and PostgreSQL remains the lease/outbox authority. Exit when connect-mode
components cannot inherit federation relay and Redis loss has an explicit
durable fallback result.

### Packet 7 — Administration and final composition

Move REST/admin operation transactions behind command-role ports, privatize
the remaining nine `AppState` capabilities, regenerate configuration/docs from
the effective capability graph, and remove obsolete facades. Then execute the
complete environment-dependent release matrix.

## 6. Time forecast

Based on the completed message, delivery and first room slices, the remaining
work is approximately **70–110 focused developer-days** including unit and
fault-injection tests, but excluding waiting for third-party interoperability
feedback. A realistic solo calendar is **14–24 weeks**. Two developers who
divide by authority boundary rather than editing the same root modules can
reduce calendar time to roughly **9–15 weeks**; the work does not scale
linearly because every packet shares integration and release gates.

The largest uncertainty is not writing structs or moving files. It is proving
that cancellation, crash recovery, authorization snapshots and transaction /
external-effect boundaries remain correct across MUC, PubSub, upload and
cluster modes.

## 7. Completion definition

Modularization is complete only when all of the following hold:

1. protocol and HTTP adapters parse/map only and own no business transaction;
2. every user-visible mutation has one application owner and one repository
   transaction owner;
3. every external effect starts after commit and has explicit retry or
   indeterminate recovery semantics;
4. all service handles and infrastructure capabilities in `AppState` are
   private and exposed through narrow ports;
5. optional XEP, web, admin and worker capabilities disappear coherently from
   routes, discovery, listeners and configuration when disabled;
6. strict format/check/test/Clippy and architecture gates pass;
7. isolated PostgreSQL/Redis, transport, browser/Gajim, federation/component,
   load, fuzz, backup/restore and release packaging gates pass for the exact
   candidate artifact;
8. `KNOWN_ISSUES.md` contains only deliberate, justified compromises rather
   than untracked architecture debt.
