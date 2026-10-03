# Message execution and fault localization

This map describes the executable C2S path, the explicit federated routing
policy, room fan-out and their fault experiments. The whole-system ownership
and evidence index is [Runtime experiment map](runtime-experiments.md).
Existing domain transactions and transport-specific actions remain separate.

## Read the path in this order

1. `src/xmpp/mod.rs` (TCP/WebSocket) or `src/bosh.rs` owns framing, ordered reads,
   transport cancellation, terminal wire responses, and the finalizer
2. `ProtocolSession::process_frame` is the production ingress into
   `src/xmpp/frame_execution.rs`: one policy table, typed backend/timeout result,
   and an owned observation whose Drop records cancellation or unwind
3. `src/xmpp/protocol/dispatch.rs` owns validation, negotiation, authoritative
   sender/language materialization, extension dispatch, and the inbound SM
   checkpoint. It never obtains new persistence authority from observation
4. `src/xmpp/protocol/messaging.rs` owns message XML, PoW, recipient/policy
   preparation, command construction and protocol error mapping
5. Existing `MessageService` / `northstar-message-application` /
   `northstar-message-core` / repository operations still own authoritative
   admission. MAM, identity replay, spool/outbox projections and transaction
   fences have not moved
6. `src/services/messaging/direct_route.rs` owns the C2S local live-handoff
   lifecycle after those decisions. `src/state/message_cluster_routing.rs`
   adapts its narrow port to the existing live/cluster routing and rearm service
7. The protocol caller owns remaining offline policy, accepted PoW finalization,
   Push and Carbons. The transport owns actual completion via the existing
   `DirectWriteLease`, SM sequence or BOSH response-ack boundary

A completed handler, accepted queue, written socket and acknowledged durable
row are four different facts. The types and experiment assertions must not
substitute one for another.

## The live-handoff owner

Previously the protocol handler interleaved three health rechecks, local/remote
routing, full-resource fallback, claim rearm and many early returns. Mutable
`delivered`, `live_claim_id` and optional delivery IDs made the accepted/retry
boundary difficult to inspect independently.

`DirectMessageRouter::route` now receives:

- An explicit `Volatile` or `Committed(DurableDelivery)` delivery state; the
  existing delivery-core tuple is reused, not copied into another identity model
- A typed bare or full target, sender and privacy-approved local target snapshot
- The existing rendered stanza and the policy deciding whether direct health
  applies to this target
- `DirectMessageRoutePort`, extending the existing fallback/routing ports with
  current mode, clustered-fence policy and exact-claim rearm only

Its result is `Routed`, `Unrouted`, `AcceptedForRecovery`,
`AcceptedBeforeDegradation`, `Dropped` or `Rejected`. `Routed` means queue
acceptance. A stage/reason accompanies recovery, and a pre-accept fallback error
retains its error source. No post-commit failure is converted into a client retry
that could duplicate an accepted stanza.

The initial `UnroutedClaim` is a consumed capability: one attempt can request
rearm at most once. The repository still owns the exact compare-and-set against
its original claim; a newer transport fence wins. Dropping the routing future
never acknowledges the row, and durable lease recovery remains authoritative.
A successful queue handoff suppresses rearm even if the final health check
changes mode. There is no async work in a Drop implementation.

The router cannot perform a new admission, acknowledge a row, parse XML, emit
protocol errors, or invoke Push/Carbons. These restrictions keep tests meaningful:
a mock route result cannot pretend a database commit or socket write happened.

## Frame budgets and observation ownership

`FrameExecution` observes the actual handler future with its existing deadline.
The table deliberately preserves the previous behavior:

| Transport and operation | Frame budget | Other authority |
| --- | --- | --- |
| TCP and direct TLS | 5 seconds | Native actor/write/finalization rules |
| WebSocket ordinary frame | 5 seconds | WebSocket cancellation and terminal sequence |
| WebSocket inline SASL2 bind/resume | 8 seconds | Same guarded classifier as before |
| BOSH payload | 5 seconds | Enclosing request budget also covers ack/cache/fence work |
| Post-write authentication publication | No new deadline | BOSH outer budget may still cancel it |

The TCP/BOSH versus WebSocket inline difference remains explicit policy debt.
This refactor does not normalize it or claim an end-to-end five-second bound.
Post-write publication already occurs after authentication bytes can reach a
client; changing its recovery deadline requires a separate protocol decision.
The observer makes that gap visible without silently changing it.

`SessionExecutions` retains current-frame and pending-publication ownership
separately. BOSH may handle another payload before it publishes the response;
publication must remain associated with the action that requested activation,
not whichever payload most recently ran. This association has its own regression
test. It adds no actor, task, queue, database connection or lock across an await.

## Trace contract

Enable only the sanitized target when reproducing:

```sh
RUST_LOG='rust_xmpp_server=info,rust_xmpp_server::xmpp::frame_execution=debug'
```

`rust_xmpp_server::xmpp::frame_execution` emits `C2S execution started`,
`C2S execution advanced` and `C2S execution finished` records. The identity is a
new ephemeral operation UUID plus process-local sequence. It is not a JID,
message/room/archive identifier, session token, credential or metric label.
These new events never capture XML, payloads, IPs, user IDs or backend errors.
Existing unrelated log targets retain their own policies.

Fixed fields are `operation_id`, `sequence`, `transport`, `operation`, `phase`,
`stage`, `outcome`, `elapsed_ms`, `bounded`, and `budget_ms`. Stages include
validation, handler, message policy/admission/routing/followup, inbound SM
checkpoint, authentication publication, caps publication and replacement
notification. Room stages are `muc_policy`, `muc_gate_wait`, `muc_authority`,
`muc_admission`, `muc_cluster_fanout`, `muc_local_fanout`, `mix_policy` and
`mix_admission`. These describe real owning sections, not individual SQL
statements. Background MIX workers and S2S frames do not inherit a C2S trace
identity; their distinct owner/lease/settlement evidence remains separate.

Frame and publication are separate phases, paired by operation UUID, sequence
and phase. Elapsed time is cumulative from operation creation, so publication
can begin with a nonzero value. `bounded=false` / `budget_ms=0` means this runner
adds no deadline, not that all enclosing operations are unlimited.

Frame outcomes are completed, backend_failure, timed_out, cancelled and
panicked. Publication also distinguishes integrity_rejected,
credential_rejected, route_rejected and completed_with_deferred_notification.
The last outcome preserves successful authoritative publication while the
best-effort replacement notification is left to maintenance. A missing principal
also maps to route_rejected. The summarizer accepts historical rejected records
for compatibility. Success/start/stage records are DEBUG; abnormal or degraded
completion is WARN.
`completed` means a protocol Action was produced, including Close/CloseWith; it
is not a business success or delivery acknowledgement. `cancelled` records a
future dropped by an enclosing budget or owner, without guessing which external
cause won. `panicked` observes unwind; aborting the process cannot run Drop.
The bounded logger can lose events, so a missing completion is incomplete
evidence, never proof of deadlock or evidence of success.

## Reproducible experiments

Fast deterministic checks, with no database or network:

```sh
cargo test --locked --bin rust-xmpp-server frame_execution::tests
cargo test --locked --bin rust-xmpp-server messaging::direct_route::tests
python3 scripts/test-frame-trace.py
python3 scripts/test-mixed-traffic-soak.py
```

Frame tests use Tokio's paused clock (dev-only test-util feature) to make timeout
and cancellation reproducible instead of waiting for an overloaded machine.
Routing tests inject a scripted health sequence and queue/fallback behavior;
they check exact claims, pre/post-accept errors, no double rearm and no rearm
after an accepted queue. They exercise production orchestration, not a second
simulation of its state machine.

Real wire/DB observation uses the existing owned mixed-traffic fixture:

```sh
cargo build --locked --bin rust-xmpp-server
python3 scripts/mixed-traffic-soak.py \
  --binary target/debug/rust-xmpp-server --duration-seconds 600 \
  --trace-frames --output-dir /tmp/northstar-message-experiment
python3 scripts/summarize-frame-trace.py \
  /tmp/northstar-message-experiment/server.log --require-complete
```

Use a fresh output directory. See [bounded mixed traffic](../testing/bounded-mixed-traffic.md)
for fixture ownership, dependencies, cleanup and evidence rules. The new flag
only enables the sanitized DEBUG target; it does not widen receive/shutdown
budgets, inherit arbitrary ambient logging, retry failures or alter workload.

The summarizer exports fixed vocabulary and aggregates only. It reads bounded
input, limits tracked operations and refuses malformed event evidence. It
retains up to 50 unfinished operation identities and their last observed stage;
unknown strings and payload fields are not reflected into its output.
`--require-complete` checks paired observation only. Always inspect the fixture's
`result.json` separately: perfect tracing can accompany an authoritative workload
failure, and warn-only logs cannot establish complete observation.

## Locating the next failure

- Last stage `message_policy`: inspect policy/recipient/service reads before
  admission; do not infer that a durable row was committed
- Last stage `message_admission`: inspect the authoritative admission/PoW or
  retraction transaction and DB wait evidence
- Last stage `message_routing`: inspect the injected route, health checkpoint,
  full-JID fallback and exact-claim release; queue acceptance is still distinct
  from the later transport boundary
- Last stage `muc_gate_wait`: inspect the existing room serialization owner;
  the guard intentionally spans admission and fan-out
- Last stage `muc_admission` or `mix_admission`: inspect authoritative room/channel
  transaction and DB waits; a later fan-out stage is separate evidence
- Last stage `muc_cluster_fanout` or `muc_local_fanout`: inspect post-commit
  routing/filtering/queue progress without retrying admission
- Frame completed but no expected wire delivery: inspect the outbound/CSI
  channel, direct fence/write/ack or BOSH/SM acknowledgement path
- Publication started but unfinished: the authentication response may already
  own the transport; inspect the exact publication fence and caps/replacement
  stages instead of reclassifying it as a failed login attempt
- Any timeout or unfinished record: retain process/thread, DB activity/locks,
  readiness and shutdown evidence from the existing failure observer

## Explicit next boundaries

`DirectMessageRouter::route_federated` now owns the S2S live-routing sequence.
It shares local/remote/fallback phase helpers while explicitly retaining extra
health checkpoints after local routing, after fallback privacy awaits and before
remote fallback. Its final health gate runs only after acceptance; unrouted
results return to the original caller's offline policy. The dedicated
`src/s2s/inbound/direct_route.rs` adapter retains S2S telemetry and remote
methods. `history_committed` stays separate from delivery commitment.
No C2S frame timeout was added to S2S application handling.

MUC's `services/muc/fanout.rs` owns the actual accepted post-commit sequence:
cluster attempt, owned recipient snapshot, fail-closed blocklist and ordered
local attempts. Replay performs none of those effects. Its report describes
attempts, not acknowledgement. The standalone authority guard stays alive across
the same sequence. MIX settlement constructs the worker ACK only for
`CompletedByClaimingWorker`; transfer to a recoverable transport never constructs
an old-token ACK. Room transactions, durable claims and transport receipts stay
with their existing owners. Ordinary MUC discussion fan-out does not acquire the
durability guarantees of clustered policy events or MIX.

No generic experiment engine or replacement event bus was added. Action
interpreters remain transport-specific because BOSH atomic FIFO/cache/RID
semantics differ from direct socket writes. The execution gate checks concrete
wiring/ordering mutations; it is not a proof of arbitrary source semantics or a
replacement for real socket/database tests.

The historical non-SM MUC timeout at round 73 remains unresolved. The earlier
SM DashMap guard fix is independent. New traceability and passing bounded runs
must not be described as proving either the historical root cause or production
endurance. This change also does not claim representative load, real-client
OMEMO cryptography, federation qualification, or a fully modular whole system.
