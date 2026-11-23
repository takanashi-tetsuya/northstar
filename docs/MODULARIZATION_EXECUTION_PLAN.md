# Northstar Modularization Execution Plan

This guide covers semantic boundary work and release qualification that are
still open after the S16–S45 restructure. Each item links to the document that
owns it, so facts are not repeated here. The order of the next stages, their
work-package split and the working rules are in the
[restructure roadmap](architecture/next-steps-roadmap.zh-TW.md). The original
1,027-line plan (its 2026 baseline, Phases A–F, the service and role stages,
the authority map and the C1/C2/D1/R1–R3 packet log) is kept as history at
[commit 25e6c3c](https://github.com/takanashi-tetsuya/northstar/blob/25e6c3c9640f7458acb1abaf82dda537f566e8f7/docs/MODULARIZATION_EXECUTION_PLAN.md).
Older records that cite its sections, including the frozen handoffs, should be
read against that version.

## Purpose and current ownership

Northstar is split into protocol libraries that hold no capabilities, narrow
application services, repository adapters and network or HTTP edges that each
own their surface. The split follows authority and transaction ownership, not
file size. The root binary is the composition root and process supervisor.

```text
composition root
  -> listener / HTTP / protocol edges
  -> application services and ports
  -> domain policy and XEP wire libraries

PostgreSQL / Redis / object storage / push providers
  -> repository or provider ports
  -> application services
```

No protocol or domain library may depend on the root binary, global state or
an infrastructure adapter. These documents own the current state:

| Topic | Authority |
| --- | --- |
| Workspace layers, context boundaries and the S16-on stage order | [Target architecture](architecture/target-architecture.zh-TW.md) |
| Source layout, line budgets, structure gates and each structural work package | [Engineering structure](architecture/engineering-structure.zh-TW.md) |
| Crate tiers and XEP switches | [Library split ledger](LIBRARY_SPLIT_LEDGER.md) |
| Modularization status and evidence levels | [Progress report](MODULARIZATION_PROGRESS_REPORT.md) |
| Capability, transaction and authority descriptions per program | [Program responsibilities](PROGRAM_RESPONSIBILITIES.md) |
| Product limits and release gates, by stable issue ID | [Known issues](KNOWN_ISSUES.md) |
| Implementation and test evidence | [Traceability](TRACEABILITY.md) |

## Boundary rules

These rules apply to every packet that changes runtime behavior. Most of them
are also enforced by gates or stated in the documents above. They are listed
here because several of them have no other general statement.

1. Extraction is not integration. A copied parser becomes a boundary only
   when root callers use it and the old implementation is deleted.
2. Pure libraries receive prepared facts, clocks and random values. They do
   not acquire capabilities.
3. Cross-feature dependencies belong in the extension graph. For example,
   disabling XEP-0059 also disables XEP-0060 and XEP-0313 instead of leaving
   a partial paging surface.
4. A disabled feature disappears from route ownership, discovery, companion
   HTTP surfaces and workers. Rejecting a request after its handler starts is
   not enough.
5. One user-visible operation has one authoritative transaction owner.
   Admission, stable identity, archive/offline/outbox projections and recovery
   fences are not split into separately committed pseudo-services.
6. Queries and mutations use different command types. A read command never
   enters a post-commit mutation-effect planner.
7. A strong shared type supplies its own safe projections. Callers do not
   serialize and reparse JIDs or encode authority in arbitrary strings.
8. Slow-client, CSI, SM and transport queues return loss-explicit outcomes. A
   library never silently evicts a stanza.
9. A compatibility facade delegates to one implementation. It is never a
   second source of parsing, cryptography or policy.
10. Generated or externally contributed code is accepted only after the root
    format, test, strict Clippy and architecture gates.
11. Architecture checks follow ownership when code moves. They inspect the
    owning crate instead of requiring logic to stay in an obsolete file.
12. Static source parsers used by CI must understand the exact syntax they
    validate. Fixed-length slices are not route or authority evidence.

Each packet names the owners of authorization, persistence, time, randomness,
delivery and background work. It must also show:

- no reverse dependency or forbidden capability import;
- bounded byte, collection, depth and work inputs;
- strict duplicate and ambiguity validation, and structurally built XML;
- typed errors, with no production `unwrap`, `expect`, `panic`, `todo` or
  `unimplemented` escape;
- commit-before-effect ordering, and recoverable indeterminate effects;
- disabled routes, features, workers and HTTP companions fail closed;
- no nested `Cargo.lock`, `[workspace]` or tracked `target` directory (the
  separate `fuzz/` workspace is the documented exception);
- the root format, test, all-feature check and strict all-target Clippy runs
  pass, as do the architecture and plugin-manifest gates;
- documents and configuration change in the same packet as the code;
- query latency, lock wait, outbox lag and transport cancellation are measured
  before a packet changes them.

Static and unit evidence never replaces the environment tests required before
release.

## Remaining semantic work

The structural moves are finished; the stage records are in the engineering
structure document. The items below are semantic or evidence work. Each one
is tracked by the document named in its row.

| Item | Done | Still open | Tracker |
| --- | --- | --- | --- |
| C1 PubSub/PEP | Query and mutation capabilities, typed commands and context owners (S21, S25). The two-layer SQL and workflow adapter split is intended. S44 (audit WP-643) answers service item, options and discovery reads, PEP reads, private XML reads and the MIX profile relay from one read-only snapshot each, makes auto-create publish one transaction and fences PEP create and private XML writes by account generation. S46 replays generic presence and PEP last items from one read-only snapshot per bounded page behind an explicit privacy-lease admission, decides subscription commands, publish policy and owner writes on the locked rows, keeps PEP form policy in one core module, fences the cached avatar presence per owner, admits mutations by typed keys and draws time and event IDs from one injected source. | Nothing from the C1 audit: all 16 findings are closed. | [Target architecture](architecture/target-architecture.zh-TW.md), [traceability](TRACEABILITY.md), [PubSub event outbox](PUBSUB_EVENT_OUTBOX.md) |
| C2 Archive/MAM | Shared RSM planning, scoped application ports and owned SQL (S20, S26). S44 audited the context (WP-644, 15 findings). S45 proves MUC occupancy, room lock state and account authority in the MAM snapshot, routes local and federated MIX MAM through one authority snapshot each, samples archive preferences, MIX publisher identity and MUC logging inside the writing transaction, hides companion surfaces when MAM is off, and pins paging across deletion with database tests. S47 implements the four product decisions: personal MIX copies converge to the channel retraction through a durable source fact (C2-08), retraction and moderation succeed under legal hold through a display overlay while export keeps the original (C2-09), a generation row fences the federated outbox quota (C2-10), and local and federated MUC MAM share one projection (C2-13). | Nothing from the C2 audit: all 15 findings are closed. Peer interop evidence for the unified federated MUC MAM format is an `EXT-FEDERATION` release-gate item. | [Target architecture](architecture/target-architecture.zh-TW.md), [data lifecycle](DATA_LIFECYCLE.md), `ARCH-MUC-MAM-PROJECTION` and `EXT-FEDERATION` in [known issues](KNOWN_ISSUES.md) |
| C3 Room/MUC | S48 audited the room context (C3 MUC and C4 MIX, 19 findings each) and fixed C3. Joins and SM resumes render from committed authority and fail closed; groupchat, retractions, private messages, voice requests and invitations reach the exact occupancies committed with the command, carried by version 2 cluster envelopes; room retirement returns its exact effects; delayed management events render with committed facts under the stricter real-JID policy; room reads answer from one read-only snapshot without writing; command time and IDs are injected and PostgreSQL decides locked-room deadlines; occupancy transitions and actor authority are typed. | Nothing from the C3 audit: all 19 findings are closed. The C4 MIX findings are fixed in S49. Exact audiences hold once every node runs the new version. | [Target architecture](architecture/target-architecture.zh-TW.md), [clustering](CLUSTERING.md), `ARCH-MUC-EXACT-ROUTE` in [known issues](KNOWN_ISSUES.md) |
| C4 Room/MIX | S49 fixed the C4 findings of the S48 room audit, after a move-only split of the large MIX modules and typed MIX addresses. PAM projections and roster deltas commit with the Core membership change; reflected traffic is admitted from one PAM snapshot; startup presence recovery drains every stale row against the database clock; administration forms apply sparse patches under the channel lock; hosted discovery answers from one snapshot and hides hidden channels; the MUC mirror links after create, fenced by the channel UUID; relay replies and timeouts return only to the admitted route, with one consumer; durable deliveries are bound to the recipient account (migration 0163); federated invitation results commit atomically. | Nothing from the C4 audit: all 19 findings are closed, which completes the room context. Migration 0163 needs MIX writers stopped while every node is upgraded. | [Target architecture](architecture/target-architecture.zh-TW.md), `ARCH-MIX-COMMITTED-AUTHORITY` in [known issues](KNOWN_ISSUES.md) |
| D1 Session/transport | Structurally absorbed by S18 and S30, then narrowed in S33 and S38. | Transport release evidence and any remaining scoped grants. | `ARCH-SVC`, `EXT-CLIENT` in [known issues](KNOWN_ISSUES.md) |
| Service capabilities | Narrow HTTP, worker and host capabilities; root composition. | Audit of the remaining worker and transport grants. | `ARCH-SVC` |
| Database roles | Separate storage, runtime/migrator and typed command roles. | Per-service privilege separation; upgrade and restore acceptance on the target. | `ARCH-DB-ROLE`, [database roles](DATABASE_ROLES.md) |
| Cluster and projections | Atomic legal MUC batches; shared local and federated PostgreSQL application. | Fault matrix across nodes and projections. | `ARCH-CLU-DEGRADE`, `EXT-CLUSTER` |
| R1 Restore/backup | Recovery command, journal and recorded fixture and VM slices. | Encrypted old objects and cutover storage, independent key and off-site recovery, target layout, interruption evidence on the final candidate. | `ARCH-RESTORE`, `OPS-BACKUP-COMPAT`, [local VM qualification](LOCAL_VM_QUALIFICATION.md) |
| R2 Revocation | Operator-supplied stapling for Northstar's own certificate; strict outbound PKIX staple checks. | Full interop with independent peers in VMs. | `PROFILE-REVOCATION`, [OCSP matrix](LOCAL_VM_OCSP_MATRIX.md) |
| R3 WASM provenance | Deployed-byte and package verification. | Two isolated, pinned builds from source that reproduce the deployed bytes. Signature, SBOM and package matching do not satisfy this. | `SUPPLY-WASM`, [web crypto supply chain](WEB_CRYPTO_SUPPLY_CHAIN.md) |

These rules constrain the open packets. They are kept here because no other
document states them in full:

- **PubSub.** A publish captures authorization, audience and durable outbox
  intents inside its PostgreSQL transaction and lock order. The post-commit
  plan dispatches those intents and never recomputes recipients from newer
  state. Measure before changing lock or work bounds; CQRS alone does not
  remove contention, and commands and queries may share one database.
- **Archive.** Admission, visibility and the rows of one MAM page use the same
  authorized snapshot where the path requires it, including federated room
  streams. Pure RSM policy must not turn a page into separate reads. Keep the
  legacy occupant-ID secret initialization and the federated outbox behavior.
- **MUC batches.** An item that carries both `role` and `affiliation` is still
  rejected (XEP-0045). Legal batches need duplicate and conflicting-target
  rules, authorization against the original authority, final-state validation
  and a consistent room/occupancy lock order. The operation identity depends
  on the authenticated stream and IQ identity, and the canonical request digest
  detects a reused identity with new content.
- **Storage migration.** After new writes begin on the destination, rolling
  back requires a fresh reverse migration.
- **Restore.** An old or missing XID outcome without matching transaction
  evidence, a damaged journal or conflicting evidence keeps the fence and the
  recovery artifacts in place.
- **Revocation.** No mode fetches a URL supplied by a peer certificate, and the
  documented operating profile fetches no OCSP responses at all. An online
  source would be a separate decision. It would need an operator allowlist,
  address and redirect controls, bounded time, size and cache, and a stated
  policy for missing responses.

## Release qualification

The next heading keeps its original number so links into it still resolve.

### 8.2 Isolated VM qualification on a frozen release candidate

Freeze the candidate commit. For every run, record the binary or container
digest, schema, configuration, topology, dependency and client versions, and
raw logs. Set pass thresholds and RPO/RTO targets before testing. A failure
opens a code or operations packet, followed by a new candidate and a rerun of
the affected gates. Federation and infrastructure tests run on an isolated
libvirt network with no route to the public Internet. Northstar nodes and
independently implemented XMPP peers run in separate VMs; two Northstar VMs
alone do not establish interoperability.

The lab layout and evidence format are in
[LOCAL_VM_QUALIFICATION.md](LOCAL_VM_QUALIFICATION.md). The test cases are in
the [federation matrix](LOCAL_VM_FEDERATION_MATRIX.md), the
[client matrix](LOCAL_VM_CLIENT_MATRIX.md) and the
[OCSP matrix](LOCAL_VM_OCSP_MATRIX.md). Current status and remaining work for
each gate are in its [known issues](KNOWN_ISSUES.md) row and the
[release checklist](RELEASE_CHECKLIST.md). A gate closes only for the tested
lab profile:

| Gate | Required target-environment evidence |
| --- | --- |
| `EXT-CLUSTER` | PostgreSQL, Redis and S3/MinIO multi-node tests with asymmetric partition, failover, lease loss, rolling upgrade and hard kill; verify MUC occupancy, presence, delivery and measured RPO/RTO. Multi-node stays `Experimental` until this passes. |
| `EXT-FEDERATION` | An authoritative DNSSEC/SRV/TLSA zone, an IPv4/IPv6 network and a lab PKI; PKIX/DANE and bidirectional S2S against fixed Prosody and ejabberd versions, including certificate rotation and negative cases. |
| `EXT-COMPONENT` | Real XEP-0114 accept/connect and XEP-0225 peers, with STARTTLS where it applies, restart, backpressure, retries and duplicate boundaries. |
| `EXT-CLIENT` | Fixed browser, Gajim and Dino versions on the lab network with a trusted lab CA, and Conversations in an Android VM if available. Monal stays untested until an Apple device can join the isolated network. Check the supported login, OMEMO 2 and trust, Carbons, CSI/SM and MAM, recording each deviation. |
| `EXT-OPERATIONS` | Alert delivery, encrypted backup, restore, upgrade and rollback in the lab, with named operators and measured recovery times. A backup on another VM of the same host is not off-site evidence. |
| `EXT-CAPACITY` | Representative presence, OMEMO, MUC, MAM, upload, Push and S2S workloads, including a 24–72 hour soak; capture RSS, queue lag, database WAL/IOPS, p95/p99 and saturation limits. The result qualifies only that host and VM allocation. |
| `EXT-SECURITY` | An independent reviewer receives the frozen candidate, threat model, privileges, browser crypto and exposed protocol topology for review and a lab penetration test; findings are triaged and retested. Internal tests do not close this gate. |

These gates qualify only the tested VM topology and feature profile. The lab
does not validate public DNS propagation, public CA issuance, Internet routing
or real off-site disaster independence; record those as untested deployment
boundaries. Closing all seven gates does not close separate product gaps such
as `PROFILE-REVOCATION`, `SUPPLY-WASM`, `OPS-BACKUP-COMPAT` or `PROVIDER-S3`.
A production-readiness claim names its supported deployment mode and its
remaining exceptions.

## Optional product scope

These profiles come after core qualification. Their advertised support must
match the implemented profile and its interop evidence; the
[XEP matrix](XEP_MATRIX.md) and `PROFILE-XEP` govern the claims.

- **XEP-0357.** The server role publishes to client-selected XMPP push
  services. End-to-end registration, retry, privacy and offline-spool evidence
  is still open. An FCM/APNs/WebPush gateway is a separate, opt-in product,
  and push wakeups never replace durable message storage.
- **XEP-0447/0448.** The browser, slot and ciphertext subset is implemented.
  Broader source, client and S3 provider interop is open (`PROVIDER-S3`).
  Resumable chunked upload is a separate transport feature that needs its own
  integrity, quota and cleanup design.
- **XEP-0487.** The host-metadata endpoint and S2S consumer exist. Qualify
  them with public deployment URLs and real clients, keeping the existing DNS
  and TLS fallbacks. Endpoint presence does not count as adoption.
