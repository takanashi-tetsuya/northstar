# Northstar Library-Split Ledger

This document records the current crate boundary after the modularization
integration pass. It is an implementation ledger, not a roadmap or a protocol
support claim. Protocol coverage remains documented in `XEP_MATRIX.md`.

## 1. Boundary rules

Every crate under `crates/northstar-*` is a leaf library. A leaf library may
own bounded parsing, validation, serialization, value types, pure state
machines, immutable extension metadata and deterministic policy calculation.
It must not own or import:

- `AppState`, SQLx, PostgreSQL, Redis or migrations;
- Axum routers, HTTP requests, listeners, sockets or TLS streams;
- filesystem/object-store access, process environment or global mutable state;
- clocks, random-number acquisition or background task spawning;
- application authorization or a user-visible multi-store transaction.

The root package is the composition adapter. It supplies facts to leaf crates,
maps typed results to protocol errors, invokes application services and owns
all external effects. The allowed dependency direction is therefore:

```text
rust-xmpp-server
  -> application services / transport adapters
  -> northstar-* leaf libraries
  -> northstar-xep-core / northstar-xmpp-types
```

The reverse direction is forbidden. `scripts/check-plugin-architecture.mjs`
enforces the capability boundary, unique route ownership and descriptor
consistency.

## 2. Current inventory

All listed crates are root workspace members, direct root dependencies and
used by runtime code. There are no extracted-but-unintegrated crates in the
tree.

| Crate | Runtime responsibility | Tests | Operator switch |
| --- | --- | ---: | --- |
| `northstar-xep-core` | descriptor model, dependency/conflict resolution and exact route ownership | 6 | built-in foundation |
| `northstar-xmpp-types` | prepared/canonical JIDs and shared bounded identity values | 24 | built-in foundation |
| `northstar-session-core` | stream-open epochs, session routing models, staged route checks, and route priority algorithms | 5 | built-in session foundation |
| `northstar-session-application` | typed session commands, incarnation removal watch signals, and cleanup models | 2 | session application foundation |
| `northstar-delivery-core` | durable C2S fences, SM entries, recipient-authoritative stanza identity and loss-explicit ordered-output port | 3 | built-in delivery foundation |
| `northstar-presence-core` | presence-session transitions, directed visibility and offline-replay eligibility | 4 | built-in presence foundation |
| `northstar-xml-framing` | incremental byte/XML framing with depth and UTF-8 boundary tracking | 27 | selected by transport |
| `northstar-xml-builder` | typed XML serialization, one-time escaping and bounded validated-fragment insertion | 6 | built-in foundation |
| `northstar-auth-core` | password/SCRAM/SASL/FAST cryptographic state machines and channel binding | 27 | authentication configuration |
| `northstar-abuse-policy` | pure actor identity, PoW, cooldown, escalation and admission calculations | 26 | abuse configuration |
| `northstar-web-surface` | requested/effective web capability graph and companion-surface dependencies | 17 | `WEB_*`, registration and upload switches |
| `northstar-message-core` | capability-free personal-message commands, routing policy, stable identity authority, destinations and commit/effect results | 6 | application foundation |
| `northstar-message-application` | authority validation and capability-injected personal-message commit orchestration | 4 | application foundation |
| `northstar-room-core` | pure room domain types, policy models, cluster occupancy targets and authority verification | 3 | room application foundation |
| `northstar-room-application` | typed room mutation commands, pure command validation, capability-injected discussion admission, and bounded ordered post-commit effect plans | 7 | room application foundation |
| `northstar-pubsub-core` | pure PubSub/PEP node, item, and audience access models | 0 | pubsub application foundation |
| `northstar-pubsub-application` | typed PEP publish commands, payload bounds, and audience projection logic | 0 | pubsub application foundation |
| `northstar-roster-core` | capability-free RFC 6121 roster domain entities, subscription state machines, presence effect definitions, and snapshot models | 4 | roster application foundation |
| `northstar-roster-application` | typed roster commands, pure validation rules, and in-memory push synchronization gate | 2 | roster application foundation |
| `northstar-archive-core` | capability-free XEP-0313 MAM domain entities, boundary models, and RSM paging boundaries | 3 | archive application foundation |
| `northstar-archive-application` | typed MAM query/preferences commands, pure validation rules, and scope projections | 2 | archive application foundation |
| `northstar-upload-core` | capability-free XEP-0363 upload domain entities, safety state, and IO classifications | 3 | upload application foundation |
| `northstar-upload-application` | typed upload slot reservation commands and pure validation rules | 3 | upload application foundation |
| `northstar-federation-core` | capability-free RFC 6120/XEP-0220/XEP-0185 S2S outbox domain entities, Dialback HMAC keys and constant-time verification | 3 | federation application foundation |
| `northstar-federation-application` | typed S2S federation commands, envelopes (durable & volatile), and validation boundaries | 2 | federation application foundation |
| `northstar-xep-0045` | MUC wire values, room/nick validation and pure role/affiliation policy | 47 | `XEP_0045_ENABLED` |
| `northstar-xep-0016` | privacy-list domain types, first-match evaluation and scoped JID rules | 4 | `XEP_0016_ENABLED` |
| `northstar-xep-0059` | canonical Result Set Management request/result/cursor types | 49 | `XEP_0059_ENABLED` |
| `northstar-xep-0060` | PubSub wire operations, configuration, builders, paging and pure authorization decisions | 31 | `XEP_0060_ENABLED` |
| `northstar-xep-0085` | chat-state parsing, classification and builders | 12 | `XEP_0085_ENABLED` |
| `northstar-xep-0092` | software-version request/response wire support | 12 | `XEP_0092_ENABLED` |
| `northstar-xep-0115` | capability hashes, canonical forms and scoped observation/cache policy | 31 | `XEP_0115_ENABLED` |
| `northstar-xep-0184` | delivery-receipt request/received wire support | 4 | `XEP_0184_ENABLED` |
| `northstar-xep-0191` | blocking commands, typed mutations and post-commit effect plans | 15 | `XEP_0191_ENABLED` |
| `northstar-xep-0198` | stream-management counters, acknowledgements, replay and resume state transitions | 35 | `XEP_0198_ENABLED` |
| `northstar-xep-0199` | XMPP Ping request/response wire support | 10 | `XEP_0199_ENABLED` |
| `northstar-xep-0202` | entity-time request/response validation and formatting | 10 | `XEP_0202_ENABLED` |
| `northstar-xep-0215` | external-service discovery models and credential-response policy | 15 | `XEP_0215_ENABLED` |
| `northstar-xep-0280` | Carbons controls, copy/resource policy, peer extraction and safe wrapper construction | 5 | `XEP_0280_ENABLED` |
| `northstar-xep-0308` | last-message-correction reference metadata | 15 | `XEP_0308_ENABLED` |
| `northstar-xep-0313` | MAM queries/forms/pages over canonical XEP-0059 types | 25 | `XEP_0313_ENABLED` |
| `northstar-xep-0333` | all four chat-marker forms and routing classification | 14 | `XEP_0333_ENABLED` |
| `northstar-xep-0352` | CSI commands, queue/coalescing policy and loss-explicit overflow outcomes | 14 | `XEP_0352_ENABLED` |
| `northstar-xep-0357` | push enable/disable wire types, privacy-safe notification facts and provider-independent retry policy | 73 | `XEP_0357_ENABLED` |
| `northstar-xep-0359` | origin/stanza identifiers, canonical issuer validation and replay identity inputs | 19 | `XEP_0359_ENABLED` |
| `northstar-xep-0363` | upload request parsing, filename/media validation and safe slot response builders | 8 | `XEP_0363_ENABLED` |
| `northstar-xep-0380` | explicit-encryption metadata | 16 | `XEP_0380_ENABLED` |
| `northstar-xep-0444` | bounded reactions metadata | 20 | `XEP_0444_ENABLED` |
| `northstar-xep-0461` | reply references and fallback-related identity validation | 18 | `XEP_0461_ENABLED` |

Test counts include crate unit and crate-local integration tests marked with
`#[test]`; documentation tests are additional.

## 3. Runtime composition

`src/xmpp/extensions.rs` is the single built-in XEP registry. It resolves
operator selection before listeners start. The resolved projection owns:

- whether an extension is effective;
- exact stanza route ownership;
- discovery features contributed by enabled extensions;
- fail-closed dependency and conflict outcomes.

XEP-0030 remains a built-in server foundation. XEP-0059 is independently
selectable and is a declared dependency of XEP-0060 and XEP-0313. Disabling
XEP-0059 therefore disables PubSub and MAM rather than leaving their paging
contracts partly active. Message metadata extensions are checked at the shared
ingress boundary, so a disabled namespace cannot bypass the switch through
C2S, S2S, federated MUC or MIX.

Service-specific discovery remains owned by the matching service adapter:
MUC features belong to the conference domain, PubSub features to the PubSub
domain, and client message metadata is not falsely advertised as a server-root
handler capability.

## 4. Compatibility facades and retained authorities

Some root modules intentionally remain as compatibility facades while callers
are migrated independently:

| Root facade/adapter | Leaf crate | Authority intentionally retained in root |
| --- | --- | --- |
| `src/auth.rs`, `src/scram.rs` | `northstar-auth-core` | account lookup, password-work admission, credential persistence and TLS facts |
| `src/jid.rs` | `northstar-xmpp-types` | route authorization and external effects |
| `src/xmpp/framing.rs` | `northstar-xml-framing` | transport buffers, deadlines and socket closure |
| `src/abuse.rs` | `northstar-abuse-policy` | actor-state storage, database locks, clock, randomness and challenge lifecycle |
| `src/xmpp/protocol/*` | matching XEP crates | authentication, application authorization, transactions, delivery and error mapping |
| `src/api/mod.rs`, `src/config.rs`, `src/main.rs` | `northstar-web-surface` | listener binding, Axum routing, static assets and supervised task lifetime |

A facade must delegate security-sensitive pure logic; it may not keep a second
implementation. Architecture checks are updated when ownership legitimately
moves (for example, credential zeroization now lives in
`northstar-auth-core/src/password.rs`).

## 5. Integration completed in this pass

- Removed nested crate workspaces and made every crate part of the root lock
  graph.
- Replaced duplicate JID, XML framing, authentication and abuse-policy logic
  with leaf-crate APIs.
- Replaced root message-extension validators with XEP crate parsers.
- Unified MAM, PubSub and discovery paging on XEP-0059 types.
- Integrated XEP-0198 and XEP-0352 state/policy engines without giving either
  persistence or socket authority.
- Integrated XEP-0045 and XEP-0060 pure validation/policy helpers while
  retaining their application transactions in root services.
- Split public-client and loopback administration surfaces in the web
  capability plan. Invitation registration is locked off when its required
  public client surface is disabled.
- Added explicit `.env` switches for every currently registered optional XEP,
  including XEP-0059, XEP-0184 and XEP-0359.
- Added route/manifest checks which reject duplicate plugin ownership and
  capability imports.
- Added XEP-0363 as the shared XMPP/HTTP upload protocol contract. Disabling
  it prevents new slot and PUT admission while retaining read-only historical
  retrieval and cleanup authority.
- Replaced separate local, federation-ingress and federation-egress personal
  message admission methods with one typed `ValidatedPersonalMessage`
  command and one `MessageCommit` result. The PostgreSQL transactions remain
  intact in the root adapter while every protocol origin now uses the same
  application entry point.
- Moved the typed XML serializer out of the binary. Root code now uses a thin
  compatibility facade over the same independently tested escaping and
  raw-fragment resource boundary.
- Converted XEP-0280 from hard-coded dispatch/discovery behavior into a
  runtime-resolved plugin. Disabled Carbons lose their IQ routes, discovery
  features and every local/cluster fan-out path.
- Added an injected personal-message commit repository. The application crate
  rejects origin-authority and actor/destination mismatches before PostgreSQL
  can run, and successful commits return an explicit local-route or federation
  outbox-wake plan.
- Moved XEP-0016 rule types and first-match evaluation out of PostgreSQL. The
  plugin switch removes management routes/discovery while already stored
  privacy rules continue to be enforced fail-closed.
- Replaced five loosely coupled stream-negotiation fields with one session
  state machine. STARTTLS now clears stream identity/language and renews the
  SASL budget as one transition.
- Split durable delivery/SM fence values and presence-session policy from the
  Tokio and protocol adapters. Recipient stanza-id recovery, directed
  presence capacity and offline replay eligibility are independently tested.
- Replaced the session layer's concrete Tokio sender ownership with a
  transport-neutral ordered-output port. The Tokio adapter retains the exact
  disconnect latch and FIFO behavior, while backpressure, closure and stale
  routing are now loss-explicit results which return the unaccepted item.
- Added the first complete room-application slice. Local C2S and authenticated
  federated MUC discussion messages now construct the same owned command,
  validate domain/JID/nickname/occupancy authority before pool acquisition and
  enter one injected PostgreSQL repository operation. Ordered MUC post-commit
  plans are owned by the application library rather than the XML handler.

## 6. Verification state

The current local static/unit gate after integration is:

- root unit tests: 959 passed, 167 environment-dependent tests ignored;
- root `cargo check --all-features`: passed;
- root strict Clippy (`--all-targets --all-features -- -D warnings`): passed;
- plugin architecture self-test and live manifest check: passed;
- program architecture-boundary check: passed after moving ownership checks to
  their new crate locations.

Environment-dependent PostgreSQL, Redis, transport, browser, federation,
load, fuzzing and deployment gates are not evidence from this pass.

## 7. Remaining split debt

The leaf-crate graph is integrated, but the application server is not yet a
set of independently deployable services. The remaining work is authority
decomposition rather than more copies of parsers:

1. Move complete messaging, room, PubSub, archive, upload and federation use
   cases behind application-service interfaces.
2. Replace remaining concrete `AppState` access in orchestration modules with
   narrow capability handles.
3. Split large protocol modules by command/query/effect ownership, not by line
   count.
4. Move PostgreSQL implementations behind repository ports while keeping one
   transaction owner for every user-visible operation.
5. Extract transport lifetimes only after protocol handlers no longer depend
   on concrete global state.
6. Preserve separate public-client, administration and observability listener
   origins and authentication audiences.

The detailed order and acceptance criteria are maintained in
`MODULARIZATION_EXECUTION_PLAN.md`.
