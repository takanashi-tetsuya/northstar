# Northstar Library-Split Ledger

This ledger maps each crate tier to what it owns and lists the operator switch
for each XEP library. It describes the current tree; the tier rules, the
bounded contexts and the migration history are recorded in the
[target architecture](architecture/target-architecture.zh-TW.md) (§4 and §5)
and the [engineering structure record](architecture/engineering-structure.zh-TW.md).
Protocol coverage is documented in [`XEP_MATRIX.md`](XEP_MATRIX.md).

## 1. Tiers

Every workspace crate is listed in `catalog/crates.yaml` with its tier. The
architecture validator (`tools/architecture-validator`) rejects a normal or
build dependency that breaks the tier rules in target architecture §4.1 and
limits external dependencies by tier (for example, core crates may not depend
on SQLx, async runtimes or network crates, and application crates may not
depend on SQLx or network crates).

| Tier | Location | Owns |
| --- | --- | --- |
| kernel | `crates/kernel/*` | JIDs (`northstar-xmpp-types`), XML framing and output, timestamps (`northstar-time`), avatar values, the XEP descriptor model (`northstar-xep-core`), the built-in XEP registry (`northstar-xep-catalog`) and the 24 `northstar-xep-*` wire and pure-policy libraries |
| platform | `crates/platform/*` | configuration, the PostgreSQL pool and migrator, process runtime and shutdown, TLS and OCSP, telemetry, and the web capability graph |
| context: core | `northstar-<context>-core` and the other `-core`/`-policy` crates under `crates/contexts/` | capability-free domain types, state machines and policy |
| context: application | `northstar-<context>-application` | typed commands, validation, transaction ordering and post-commit effect plans behind repository ports |
| context: adapters | `-postgres`, `-xmpp` and `northstar-upload-storage` | PostgreSQL repositories, XMPP protocol mapping and object storage for one context |
| context: workflows | `crates/contexts/workflows/*` | use cases that span contexts (administration, data tools) |
| edges | `crates/edges/*` | the stream engine (`northstar-stream`), C2S, BOSH, HTTP, S2S and cluster transports |
| composition root | `src/` (package `northstar-server`) | process startup, `ServerNode` construction, worker registration and wiring adapters to edges |
| tooling | `tools/*` | the architecture validator, the saved-replay test harness and the PostgreSQL integration tests |

The contexts are abuse, archive, auth, federation, message, operations,
pubsub, room, roster, session, upload and workflows. Dependencies point from
adapters and edges toward application, core, platform and kernel crates;
adapters do not depend on other adapters, and edges do not depend on adapters.
The exact rules are in target architecture §4.1 and the validator.

Only the kernel XEP libraries are pure leaves in the sense of owning no
transport, database, clock or task authority. Platform crates, adapters, edges
and the composition root own those effects by design.

## 2. XEP libraries and switches

`crates/kernel/northstar-xep-catalog` is the single built-in XEP registry.
`ExtensionRuntime::resolve` turns the operator switches into one resolved
projection before listeners start. That projection owns:

- whether an extension is effective;
- exact stanza route ownership;
- discovery features contributed by enabled extensions;
- fail-closed dependency and conflict outcomes.

XEP-0030 is a built-in server foundation. XEP-0059 is independently
selectable and is a declared dependency of XEP-0060 and XEP-0313, so disabling
it disables PubSub and MAM instead of leaving their paging partly active.
Service-specific discovery belongs to the matching service adapter: MUC
features to the conference domain and PubSub features to the PubSub domain.
`scripts/check-plugin-architecture.mjs` checks that the XEP libraries stay
capability-free and that the catalog, the root dependencies and the manifests
agree.

| Crate | Responsibility | Switch |
| --- | --- | --- |
| `northstar-xep-0016` | privacy-list domain types, first-match evaluation and scoped JID rules | `XEP_0016_ENABLED` |
| `northstar-xep-0045` | MUC wire values, room/nick validation and pure role/affiliation policy | `XEP_0045_ENABLED` |
| `northstar-xep-0059` | Result Set Management request/result/cursor types | `XEP_0059_ENABLED` |
| `northstar-xep-0060` | PubSub wire operations, configuration, builders, paging and pure authorization decisions | `XEP_0060_ENABLED` |
| `northstar-xep-0085` | chat-state parsing, classification and builders | `XEP_0085_ENABLED` |
| `northstar-xep-0092` | software-version request/response wire support | `XEP_0092_ENABLED` |
| `northstar-xep-0115` | capability hashes, canonical forms and observation/cache policy | `XEP_0115_ENABLED` |
| `northstar-xep-0184` | delivery-receipt request/received wire support | `XEP_0184_ENABLED` |
| `northstar-xep-0191` | blocking commands, typed mutations and post-commit effect plans | `XEP_0191_ENABLED` |
| `northstar-xep-0198` | stream-management counters, acknowledgements, replay and resume state transitions | `XEP_0198_ENABLED` |
| `northstar-xep-0199` | XMPP Ping request/response wire support | `XEP_0199_ENABLED` |
| `northstar-xep-0202` | entity-time request/response validation and formatting | `XEP_0202_ENABLED` |
| `northstar-xep-0215` | external-service discovery models and credential-response policy | `XEP_0215_ENABLED` |
| `northstar-xep-0280` | Carbons controls, copy/resource policy and safe wrapper construction | `XEP_0280_ENABLED` |
| `northstar-xep-0308` | last-message-correction reference metadata | `XEP_0308_ENABLED` |
| `northstar-xep-0313` | MAM queries, forms and pages over the XEP-0059 types | `XEP_0313_ENABLED` |
| `northstar-xep-0333` | chat-marker forms and routing classification | `XEP_0333_ENABLED` |
| `northstar-xep-0352` | CSI commands, queue/coalescing policy and loss-explicit overflow outcomes | `XEP_0352_ENABLED` |
| `northstar-xep-0357` | push enable/disable wire types, notification facts and retry policy | `XEP_0357_ENABLED` |
| `northstar-xep-0359` | origin/stanza identifiers, issuer validation and replay identity inputs | `XEP_0359_ENABLED` |
| `northstar-xep-0363` | upload request parsing, filename/media validation and slot response builders | `XEP_0363_ENABLED` |
| `northstar-xep-0380` | explicit-encryption metadata | `XEP_0380_ENABLED` |
| `northstar-xep-0444` | bounded reactions metadata | `XEP_0444_ENABLED` |
| `northstar-xep-0461` | reply references and fallback-related identity validation | `XEP_0461_ENABLED` |

## 3. Where tests live

Each crate's unit tests sit next to its code. Protocol regression tests that
exercise one context live in that context's `-xmpp` or application crate (for
example `northstar-muc-xmpp/src/protocol_regression_tests/`). Saved-case
replays and the Stage 4 harnesses that wire several contexts together are one
integration target, `tools/northstar-test-harness/tests/saved_replay/`.
PostgreSQL adapter tests are in `tools/northstar-db-it` and run in the database
CI suites. The root package keeps only the tests of the composition root.

## 4. Historical integration checkpoint

The [2026-09-03 repository record](https://github.com/takanashi-tetsuya/northstar/blob/94b7d9d5ea100a176d010f0bd42a7ad8f5b1080f/docs/LIBRARY_SPLIT_LEDGER.md)
contains these local results from the library integration:

- root unit tests: 959 passed, 167 environment-dependent tests ignored;
- root `cargo check --all-features`: passed;
- root strict Clippy (`--all-targets --all-features -- -D warnings`): passed;
- plugin architecture self-test and live manifest check: passed;
- program architecture-boundary check: passed after moving ownership checks to
  their new crate locations.

This checkpoint covers static and unit checks at that commit. Subsequent CI
results are recorded in the [CI validation log](handoff/2026-09-12/CI-PERFORMANCE-FOLLOWUP.md);
release validation follows the [release checklist](RELEASE_CHECKLIST.md). The
[2026-11-19 version of this ledger](https://github.com/takanashi-tetsuya/northstar/blob/880b48ebed4b19f2d42b050ffcd873de2b1b2fe1/docs/LIBRARY_SPLIT_LEDGER.md)
is the last one written before the S16–S41 restructure was reflected here.
