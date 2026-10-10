# Stage 0 authority audit of the recovered baseline

Audit date: 2026-10-03. Scope: read-only source inspection of this repository, branch `recovery/experimental-architecture-20261003`, commit `4f1b3b9032b98004eec2160172d5af3acbcc16b8`, tree `5f9d26383daa2b6bc467966a84df74c756f94e37`. The initial working tree was clean. Line references below refer to that baseline, not to later rebuild edits.

This is the recovered old 1,618-file source baseline, published with four recovery files (1,622 tracked files), not the lost October 2 Stage 0–4 implementation. The original research and phase-result reports were read as design/history inputs. None of their test counts, fingerprints, accepted archives, SQL results, stock-wire results, or stage acceptances qualifies this checkout. No build, test, service, fault injection, installation, push, or production edit was performed for this audit. The source audit is retained with the rebuild ledger.

Repository guidance inspected: README, `.github/CONTRIBUTING.md`, and `docs/architecture/message-execution.md`. No `AGENTS.md` or repository `SKILL.md` was found by the repository file inventory. Existing guidance preserves protocol/error mapping in `src/xmpp`, transaction/application ownership in services, SQL in repositories, immutable published migrations, bounded queues, deadlines, and fail-closed fences.

## Executive finding

The baseline has valuable real production seams: rated-admission leases, atomic personal-message persistence, mode-aware clustered commit fencing, a shared typed direct router, exact claim rearm, ordered transport fencing, durable SM/BOSH owners, and conditional replay. It does **not** yet have the later report's common admission/direct lifecycle coordinator, explicit commit knowledge/witness, positive reconciliation protocol, operation/effect completion validation, or consuming write-result capability.

The first rebuild must connect these retained owners without replacing their authority. A generic `MessageApplication` extraction alone cannot cover normal local durable C2S because that production route deliberately uses `admit_personal_message_with_mode`/`commit_direct`. `DirectWritePort` is downstream record/fence/settlement around a routed item; it is not the initial durable-message commit port.

## 1. Real call path and success vocabulary

| Fact | Current production owner and source anchor | Meaning and boundary |
|---|---|---|
| Protocol processing | `src/xmpp/protocol.rs:699–712`; `src/xmpp/protocol/dispatch.rs:301–324` | TCP/WS/BOSH enter `process_frame`, which observes `handle`. `message` is directly dispatched. Successful handler return is an `Action`, not delivery |
| Rated guard/admission | `src/xmpp/protocol/messaging.rs:244–302`; `src/services/message_admission.rs:10–44` | The protocol calls the admission service only for abuse-rated messages; the service currently forwards `begin`/`accept` |
| Durable reservation | `src/db/message_admission_repository.rs:29–274` | Only committed `Proceed { lease: Some(..) }` establishes the per-operation pending reservation |
| Guard-only proceed | `src/abuse.rs:647–661,1683–1730` | No origin/proof identity, or absent persistence, can produce `Proceed { lease: None }`. It grants guard permission, not a reservation receipt |
| Durable message commit | `src/services/messaging.rs:474–482`; `src/db/messaging.rs:46–170,266–272`; `src/db/archive.rs:363–444` | Archive/identity/delivery or outbox writes commit atomically; clustered mode and initial claim accompany the result. No queue/write/peer fact follows from this alone |
| Admission finalization | `src/xmpp/protocol/messaging.rs:1503–1528`; `src/db/message_admission_repository.rs:280–336` | Separate transaction accepts the rated replay record. It is not atomic with durable message persistence |
| Queue accepted | `src/services/messaging/direct_route.rs:90–108,147–231`; `src/state/message_cluster_routing.rs:17–30` | `Routed` means local/remote ordered queue handoff accepted; it does not mean socket completion |
| Native write completed | `src/xmpp/mod.rs:882–915,1232–1278`; `src/xmpp/direct_delivery.rs:82–140` | Prepare record/fence, await actual transport write, then call consuming `written`. This is a call-order contract in this baseline |
| Non-SM settled | `src/db/replay.rs:1231–1333` | Exact current source claim is validated and the row deleted in a transaction. Missing claimed rows are errors; an unclaimed missing row is an idempotent no-op |
| Inbound SM handled | `src/xmpp/protocol/dispatch.rs:319–323` | Counted inbound stanza's handler returned, then inbound counter/checkpoint is advanced. This is distinct from outbound peer `h` |
| Outbound SM ownership/settlement | `src/xmpp/protocol.rs:1077–1185`; `src/xmpp/protocol/sm.rs:1357–1427`; `src/db/sm.rs:419–457,1583–1644` | Recording checkpoints the outgoing sequence/source before write. Peer `h` selects an exact prefix; owner-fenced transaction updates checkpoint and settles its sources |
| BOSH exposure | `src/bosh.rs:1129–1242` | Selected response sources are bound to SID/RID before successful HTTP responder handoff. The responder accepting bytes is not client acknowledgement |
| BOSH settled | `src/bosh.rs:989–1006`; `src/db/replay.rs:2121–2220` | Valid authenticated request/RID ACK, current SID and active source fences authorize deletion. SM-managed sources are excluded from this authority |

`AcceptedForRecovery`, `Unrouted`, retained row, and returned `rearm` are not interchangeable with recovery scheduled, delivery completed, or settlement confirmed.

## 2. Rated reservation and separate finalization

`MessageAdmissionLease` has private admission-key/MAC/token fields and an owner-produced acceptance view (`src/abuse.rs:757–809`). It is currently `Clone`, while `MessageAdmissionStart` has `Proceed`, `ReplayAccepted`, `InProgress`, `Denied`, `Conflict`, and `CapacityLimited` but no `Unknown` (`812–824`). The common service has no state machine or reconcile effect.

Actual reservation transaction:

1. Sort/deduplicate candidate key advisory locks, begin transaction, take locks, read `clock_timestamp()` (`message_admission_repository.rs:38–58`)
2. Delete expired exact-key rows (`expires_at <= now`), lock candidate rows, compare actor, key and payload MAC exactly (`59–101`)
3. Accepted exact row returns replay after COMMIT; active pending lease returns in-progress; expired pending lease receives a new random lease token and COMMIT before `Proceed(Some)` (`103–164`)
4. New identity verifies/consumes proof and mutates actor state in the same transaction (`167–198`). A guard denial deliberately commits those guard effects. Per-actor serialization remains in sorted transaction actor locks (`src/db/abuse_actor_state_repository.rs:25–79`); preserve that path
5. Bounded shard cleanup, actor count `expires_at > now`, shard allocation, and pending-row insertion precede COMMIT (`204–273`)

The product constants remain actor cap 4,096, pending lease 60s, pending retention 30m, accepted retention 6h; direct/MUC/MIX rated inputs share this admission budget (`crates/northstar-abuse-policy/src/model.rs:18–28`; the common rated entry runs before MIX/MUC branching in `messaging.rs:244–343`). Completed delivery does not itself free this replay budget.

Finalization locks the exact admission key and payload, returns idempotent success for an already accepted matching row, otherwise requires the exact lease token, then sets accepted expiry to DB-now + 6h (`message_admission_repository.rs:287–335`). Two subtleties matter:

- The accepted-state branch precedes lease-token comparison (`309–315`); describing every successful accepted replay as a fresh exact-token transition would overstate the predicate
- Pending finalization does not require unexpired `expires_at` or `lease_expires_at` and does not repeat actor-cap admission. An existing expired pending row with its still-matching token can be accepted late if it survives cleanup. The report's 4,097 candidate is therefore relevant to model design, but this read-only audit neither reproduces it nor establishes ordinary live-caller reachability or a policy violation

`finalize_message_admission` takes the optional lease before the await and returns unit. Failure only logs and increments telemetry (`messaging.rs:1508–1526`). There is no retained finalization receipt, explicit unknown state, reconciliation job, or durable retry mechanism in this helper. A pending finalization transaction might roll back, remain in progress, or commit without caller confirmation; do not equate a finalization failure with a proven recovery outcome.

The current begin error comment says proof/actor/reservation “all roll back” (`messaging.rs:287–290`). Its `Result` contains no COMMIT-issued distinction, and repository COMMIT awaits use ordinary `?`. That blanket statement is too strong as a lifecycle contract. It must not be copied into the rebuilt oracle.

## 3. Durable persistence: generic and mode-aware are distinct entries

Generic route:

`MessageService::admit_personal_message` (`services/messaging.rs:611–625`) → `MessageApplication::commit` (`crates/northstar-message-application/src/lib.rs:52–60`) → `PersonalMessageCommitRepository::commit` → `PostgresMessageRepository::commit_with_mode(..., LiveOnly)` (`db/messaging.rs:31–42`). Generic commit validates identity authority and returns only `MessageCommit`, discarding the mode/initial-claim wrapper at that entry. The federation caller uses this route (`xmpp/protocol/messaging.rs:612–640`).

Normal local durable C2S route:

`ProtocolSession::message` prepares sender/recipient identities and random stanza IDs, privacy-approved route snapshot, archive writes, origin identity and delayed stanza (`messaging.rs:705–925`) → `admit_personal_message_with_mode` (`927–932`) → common `validate_authority`, then direct `repository.commit_direct` (`services/messaging.rs:474–482`) → `commit_with_mode` (`db/messaging.rs:266–272`). This path bypasses `MessageApplication::commit`; preserve that distinction in production-wiring tests.

The durable transaction's retained authority:

- Enabled accounts are locked within persistence (`archive.rs:527–539`)
- Exact canonical identity scope, identity value and payload authentication are checked under the replay row lock; identity insert/replay and projection writes remain one transaction (`574–800`)
- C2S recipient name/ID/domain and persisted stanza target/resource affinity are revalidated; recipient quota lock/count and insertion stay in this transaction (`805–918`, `921` onward)
- Clustered paths acquire existing instance-claim locks and authority fence, then the final direct-commit turn and second DB fence (`378–405`). A newly stored Live C2S row receives its message UUID as initial claim and a durable recipient wake in the same transaction (`406–428`)
- COMMIT occurs at `430` (clustered) or `440` (standalone). The returned mode may be demoted to SpoolOnly after health changes (`431–438`); routing lies outside the short commit turn
- The initial clustered claim is `delivery_claim_id = message_id` with 60s expiry (`449–469`). Exact release/rearm compares recipient/message/token, writes a wake only if released, then commits (`475–508`)

Privacy/blocking checks are separate reads, not a newly atomic privacy authorization guarantee. Outbound authorization calls blocking/privacy queries (`db/messaging.rs:288–308`), recipient lookup/blocking is separate (`316–333`), and session/default privacy checks occur before durable admission (`xmpp/protocol/messaging.rs:801–850`). Account locking inside archive commit does not revalidate all those prior facts. A shared core must record this limitation rather than silently claiming every policy snapshot is transaction-authoritative.

On Stored, the protocol copies `archive_written`, delivery ID and claim into independent mutable locals, awaits finalization, rechecks mode and may rearm (`messaging.rs:933–986`). On Replay, it finalizes and returns without re-routing (`988–994`). Commit Err maps to a retry-style resource error (`999–1001`). There is no explicit Unknown/receipt witness in these entries. `DirectPersonalMessageAdmission` is a public-in-crate, `Copy` data result (`services/messaging.rs:61–69`), not an unforgeable persistence capability.

Origin-backed durable replay and proof-only rated admission must remain distinct. Normal durable identity uses only `origin_id` (`messaging.rs:894–905`); proof-derived `offline_dedupe` is used by the later legacy offline branch (`1382–1385`). Do not infer stronger durable dedupe for a proof-only normal direct message merely from the earlier rated lease. Failure/uncertainty in independent finalization retains the existing at-least-once duplicate window.

## 4. Real router and recovery ownership

The production caller constructs `DirectRouteDelivery::Committed(DurableDelivery { recipient_id, message_id, claim_id })` or `Volatile`, then invokes the actual shared router (`messaging.rs:1260–1290`). The AppState adapter's local result comes from `try_send_durable(...).is_ok()` (`state/message_cluster_routing.rs:20–30`). This is queue admission only.

`DirectMessageRouter` already narrows live-handoff authority:

- `reservation_gate` rejects missing initial clustered reservation as `AcceptedForRecovery`, without pretending a route happened (`direct_route.rs:398–419`)
- Health checks, ordered primary/fallback routing and outcomes are shared production logic (`147–231`)
- `UnroutedClaim(Option<DurableDelivery>)` consumes its local token before one best-effort `rearm` await (`132–141`). It cannot ACK or re-admit. A successful queue handoff suppresses rearm, even if final health degrades (`210–224`, `480–505`)
- The rearm port returns `()` (`16–22`), service ignores the CAS bool and logs only errors (`services/messaging.rs:500–518`). Returned rearm therefore does not prove release succeeded or a retry was scheduled
- Cancellation dropping a route attempt does not asynchronously rearm or ACK. Source rows and the existing expiry/claim rules remain the authority
- Federation shares lower helpers but intentionally has different health checkpoints and a separate committed-history flag (`233–395`). Do not normalize that behavior during the first direct slice

`DurableDelivery` itself is `Clone + Copy` with public fields (`crates/northstar-delivery-core/src/lib.rs:54–59`). It is a transport/source identity tuple whose final authority is SQL; it is not an opaque proof of commitment. A rebuilt coordinator can use private consuming wrappers while keeping the final SQL fence.

Recovery is conditional and already has different owners:

- Clustered commit/rearm writes a durable wake. `DirectSpoolWakeConsumer::drive_once` claims only in Live mode and defers on loss/errors (`state/direct_spool_wake.rs:101–122`); per-route completion/eligibility controls requests (`178–215`)
- Standalone delivery has no clustered claim/wake in the commit result (`db/messaging.rs:146–159`). Subsequent newly available/nonnegative presence can defer an offline replay task (`xmpp/protocol/presence.rs:755–813`), which checks availability and drains (`protocol/replay.rs:527–552`); SM resume has a separate eligible replay trigger (`protocol/sm.rs:1323` onward)
- A retained row alone does not prove a future eligible session, resumed owner, healthy dependency, fair worker scheduling, or eventual delivery. No new retry daemon should be inferred from the source or introduced under a refactor label

## 5. Post-route native transport, SM, and BOSH

### TCP/WebSocket

`DirectWritePort` exposes record, C2S/MIX fence, C2S/MIX acknowledgement and connection identity (`xmpp/direct_delivery.rs:14–24`). It has no admission or archive commit operation. The actual order is:

1. `record_outbound_item` may durably transfer source ownership to SM
2. If not SM-managed, fence C2S/MIX before any bytes (`direct_delivery.rs:90–113`)
3. The transport awaits `send`/`websocket_send_live` (`xmpp/mod.rs:913`, `1268–1275`)
4. Only a successful write call reaches consuming `lease.written` (`914`, `1277`)
5. `written` confirms transport write, confirms non-SM ownership, then attempts durable acknowledgements (`direct_delivery.rs:119–139`)

The baseline has a consuming `written(self)` method but no write method consuming the prepared lease and yielding a `WrittenDirectLease`. Calling `written` is therefore guarded by actual production call order, not by a type that contains a successful write result. The later phase-report capability is missing here.

The socket fence locks exact recipient/message, compares the prior claim, rejects SM/BOSH ownership, rotates only the initial message-ID reservation, extends the claim and commits (`db/replay.rs:1342–1419`). ACK locks/validates the exact claim; unclaimed ACK additionally rejects SM/BOSH ownership; then the transaction deletes (`1235–1333`). Claimed ACK uses exact claim equality, **not an unexpired lease predicate**. Expired-but-unreplaced and replaced tokens are different cases. Cancellation/write failure leaves the row and never ACKs on Drop, but a partial write cannot be labeled “no bytes sent.” An ACK failure after successful write preserves the write fact while settlement is unconfirmed.

### Stream Management

Inbound handler completion/checkpoint (`dispatch.rs:319–323`) and outbound peer prefix acknowledgement (`protocol/sm.rs:1357–1427`) are separate flows. Recording appends/counts the outbound stanza and checkpoints before write (`protocol.rs:1118–1176`). For SM-managed C2S, `record_outbound_item` confirms transport ownership after checkpoint; direct socket ACK is skipped (`1089–1109`, `direct_delivery.rs:91–95,121–125`).

The repository updates the current session/connection snapshot and replaces the queue/acknowledges sources atomically (`db/sm.rs:419–457`). Newly transferred C2S sources require exact prior claim and no BOSH/SM owner, then clear the socket claim in the transaction (`1201–1263`). Existing queue sources, next sources and completed sources must agree exactly; no existing source can disappear without acknowledgement (`1583–1644`). These authority checks must remain the adapter contract. A model cannot promote an arbitrary injected `true` to current-owner settlement.

### BOSH

Recording SM-managed items clears their BOSH durable source so a RID ACK cannot settle before SM `h` (`bosh.rs:1009–1025`). Non-SM MIX transfers to a typed BOSH fence before FIFO retention (`1026–1058`). Selected C2S/MIX sources are bound atomically to a response RID before responder exposure (`1129–1242`; `db/replay.rs:1422` onward). Failed responder exposure is not a peer ACK.

The request validates SID/key/shape before renew/ACK (`bosh.rs:821–847`); renewal rejects expired fences and, on cached replay, verifies exact source sets (`db/replay.rs:1999–2115`). ACK validates SID/RID and active C2S/BOSH ownership; MIX also matches its exact rotated token (`2121–2220`). It commits before in-memory cached receipts are sent/pruned (`bosh.rs:989–1006`). Cancellation between server COMMIT and the caller's observed result cannot be collapsed into either “nothing settled” or “caller knows settled.”

The later phase report's exact-auth-control marker is absent. Current `finish_pending` uses the actor-wide `auth_publication_pending` bool and any successful response exposure (`bosh.rs:1243–1254`), while terminal paths can select no queued payloads (`1140–1159`). Record this as a concrete Stage 4 rebuild target with separate behavior-change evidence; do not inherit the historical fix or its tests.

## 6. Cancellation and Unknown matrix for the rebuilt contract

| Cut | What can currently be asserted from source | Required explicit contract |
|---|---|---|
| Before operation/effect starts | No authority requested by that effect | No fabricated pending COMMIT/recovery obligation |
| During reservation work before COMMIT is issued | Work is inside a transaction; no reservation receipt observed | Distinguish known pre-COMMIT cancellation from COMMIT-in-flight; verify actual adapter cancellation separately |
| Reservation COMMIT issued, no receipt | Result-only API loses this distinction | Reservation Unknown; do not infer rollback or repeat proof consumption blindly |
| Reservation receipt known, before durable commit | Pending rated lease exists, durable content may not | Retain lease identity and pending responsibility; do not claim durable message committed |
| Durable COMMIT issued, no receipt | Transaction may have committed despite dropped/failed result | PersistenceUnconfirmed/Unknown tied to exact identity/payload and effect; no unconditional route/re-admission |
| Durable receipt known, during separate finalization/mode/rearm | Message already committed; finalization may be unknown or pending | Preserve known durable receipt even if later continuation is cancelled; classify finalization independently |
| Queue accepted, transport not yet fenced/written | A queue owns the item; still no wire fact | No re-admission or old-owner settlement; retain source and queue/transport obligations |
| Fenced, write pending/failed/partially completed | Fence may exist; no successful full-write receipt | Do not ACK; classify transport uncertainty and conditional expiry/replay without claiming zero exposure |
| Write returned successfully, settlement pending/unknown | Write success is already known | Never erase write fact; distinguish exact settlement confirmed, lost fence, and unconfirmed settlement |
| SM/BOSH owner replaced | Newer exact authority may own the same source | Old checkpoint/ACK/completion fails closed; missing/expired/deleted/mismatched row is not automatic rollback proof |

Current `FrameExecution` creates UUID, global sequence and Tokio timestamp (`frame_execution.rs:273–282`), times out the whole handler (`310–329`), and records Drop cancellation/unwind (`413–421`). It is observation, not a commit witness or controller. `ProtocolSession` still holds `Arc<AppState>` (`protocol.rs:594–603`). A stage label does not identify which external effect completed, and a timed-out inner future loses local direct lease/receipt variables. A shared outer workflow owner must outlive that inner future if it is to retain already-observed knowledge at cancellation cuts.

Positive reconciliation must be intentionally narrow: exact operation identity/payload and correct owner can establish a positive fact; absence cannot prove rollback. A read fact must be saved before a subsequent cleanup await. Any reconciliation design that reads a replacement owner and then routes/ACKs with the old owner violates the required boundary. No such general direct reconciliation operation was found in the audited admission/message/transport source.

## 7. Source-level SM capacity concern to retain for later conformance

The reported old SM crash-resume diagnosis cannot be imported as a fresh result. However, the relevant conflicting predicates are present in this source:

- `northstar_session_transfer_sm` requires the existing full-JID binding row, same account and old connection, plus a current exact SM claim; missing binding returns conflict (`migrations/0114_session_authority_capabilities.sql:305–356`; Rust adapter `db/capacity.rs:703–731`)
- `northstar_session_cleanup_live` deletes expired binding rows solely by live lease expiry (`same migration:393–419`); runtime maintenance calls it under the elected transaction (`db/capacity.rs:766–788`)

This supports retaining a source-level cross-domain contract concern and targeted conformance requirement. It does not independently establish the exact cause of the historical stock-wire failure or qualify any fix. Preserving SM-backed stable allocations across the recovery window changes capacity retention. The exact existing-binding retention policy was approved on 2026-10-03; it remains unimplemented and requires new validation. Do not solve it by recreating missing bindings, raising caps, extending general live authority, or disabling maintenance in fixtures.

## 8. Meaningful rebuild exit criteria

### Stage 0 exit

- Freeze this recovered source identity and authority map; label historical outputs as unavailable/references only
- Choose exact first-slice scope: normal local durable direct, guard-only/rated branches, origin/proof distinction, mode-aware commit, independent finalization, real router, native transport and separate SM/BOSH owners
- Adopt the success/Unknown/cancellation vocabulary above and retain explicit exclusions (volatile semantics, other domains, privacy snapshot atomicity, cross-process recovery, eventual delivery)
- Inventory existing baseline tests without claiming execution. Useful retained tests are `src/services/messaging/direct_route_tests.rs`, `src/xmpp/direct_delivery.rs:234–351`, and real repository test files; later validation must use a newly built, source-bound executable

### Stage 1 executable experiment specification

- Version concrete initial state, commands, ordinary correlation IDs, effect/fault order, authority time, expected semantic outcome, stop condition and cleanup/evidence status
- Preflight actor-window occupancy using existing 4,096/6h/30m/60s semantics and shared direct/MUC/MIX rated budget; separate physical rows from active occupancy and conservative reused-state late-finalization exposure
- Boundary cases: 4,095→4,096→4,097, exact identity replay, changed payload, before/at/after expiry, pending lease reclaim, late finalization candidate, and invalid normal workload
- Separate execution status, domain outcome, experiment verdict and cleanup. Preflight-only is NotStarted, not workload Pass; setup error/EINTR are not automatically invariant/user cancellation

### Stage 2 admission core

- Production admission service and controlled runner actually call the same state transitions, including GuardOnly and separate Begin/Finalize/Reconcile semantics
- Correlate completions by operation/effect/kind/version; reject wrong, duplicate, stale and late completions without consuming the valid outstanding effect
- Retain SQL locks, actor guard/proof mutation, DB clock, cap, TTL, payload/fence predicates; no pure snapshot can replace transaction authority
- Capture no-COMMIT/COMMIT-issued/receipt-known cuts at the real repository boundary; adapters may conservatively preserve Unknown where evidence is insufficient
- Preserve concrete five-category scenarios plus the declared late-finalization candidate; mutate oracle inputs and require exact invariant/class/cut/projection agreement

### Stage 3 direct lifecycle

- Wire normal C2S into the shared owner through the **mode-aware** commit entry, not just the generic application route; keep identity/full-target/payload continuity
- Outer owner survives inner cancellation and preserves positive commit knowledge before any later await; independent finalization never erases durable receipt
- Invoke existing `DirectMessageRouter`/`UnroutedClaim`, not a second route simulation; queue outcome must not authorize write or settlement
- Encode the actual prepare→write→written→settle transition with consuming capabilities, preserving TCP/WS order and SM/BOSH-specific ownership
- Counterexamples: stale claim after rotate/reclaim, queue accepted then cancel, missing clustered reservation, finalization failure after known commit, unknown commit with replacement owner, write failure vs write-success/ACK-loss, inbound vs outbound SM, BOSH exposure vs RID ACK, SM-managed BOSH exclusion
- Saved-input replay must run the real shared Rust core, retain full concrete input and compare projections; wrong-source/schema refusal cannot count as the target negative. Shrink only while preserving the same invariant/class/cut and use matching positive controls

### Later qualification boundary

Controlled cases cannot qualify SQLx COMMIT-response loss, SQL lock/MVCC/cancellation, socket partial writes, independent peer behavior, hard process loss, startup recovery or long-period resource/retention behavior. Stage 5 must bind those assumptions to new exact SQL/stock executable/schema/config/fixture identities and separately preserved cleanup. Stage 6 must provide actual bounded execution and observation/resource evidence before any accepted status. The historical Stage 4 archive, test totals, 38/104 SQL run and 10/11 stock-wire outcome are not substitute evidence for the recovered rebuild.

## Audit disposition

Stage 0 source authority map: complete for the requested direct/admission/transport ownership slice. Implementation qualification: not attempted. Current runtime behavior: not freshly executed. The recoverable seams are sufficient to start a narrow shared-core rebuild; all new stages require their own evidence and review.
