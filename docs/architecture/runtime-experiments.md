# Runtime ownership and experiment map

Start with `catalog/runtime-experiments.json` when localizing a problem. It
indexes the supported in-process runtime, not the service prototypes in
`catalog/services.yaml`. Sixteen families account for all 71 identities from
the already-validated production inventory: 27 role-qualified workers, two
health observers, nine top-level tasks and 33 AppState service accessors.

## How to use the map

1. Find the family and production owner for the failed operation
2. Read the distinct commit, handoff and completion facts; never infer client
   acknowledgement from a successful queue or worker wake
3. Read the fault list and existing budget owner before adding a timeout or retry
4. Run the declared narrow experiment with a fresh evidence directory and the
   stated dependencies, then retain exact command, source fingerprint, exit
   status, actual test counts and cleanup outcome
5. Escalate to the appropriate isolated DB, wire or operator fixture if the
   narrower evidence cannot settle the question

The 23 indexed experiments remain `declared`. Catalog v2 additionally names an
executable Stage 1 admission fixture contract and its 11 concrete synthetic
cases. The validator never executes commands or changes a declaration to
`passed`. Each mapped runtime identity is only
`static_boundary` coverage: generic supervisor tests do not prove a worker's
business logic. Fresh run results live in the delivered evidence package and
completion matrix, never masquerade as evergreen source facts.

```sh
node scripts/check-runtime-experiments.mjs
node --test scripts/test-runtime-experiments.mjs
node scripts/check-execution-boundaries.mjs
node --test scripts/test-execution-boundaries.mjs
```

The first validator imports the exact source inventory that the existing
architecture gate already checks. Deleting an identity, changing its owner,
duplicating a mapping, removing a required family, or leaving a stale source/test
anchor fails. Mutation tests also reject catalog entries that claim an executed
result. `catalog/runtime-experiments.schema.json` is the portable shape contract;
the dependency-free Node validator enforces shape plus repository semantics.
These source-shape checks are drift detectors, not a general Rust parser or a
runtime semantic-equivalence proof.

## Executable fixture contract

`scripts/lib/experiment_contract.py` defines bounded, versioned concrete actor,
row, command, time, effect-cut, expectation, budget, provenance and cleanup
inputs. `scripts/test-experiment-contract.py` supplies independently written
golden projections. Its pure tests do not start services, sockets or child
processes. Save a new corpus and replay it from the same scoped source bytes:

```sh
python3 -B scripts/test-experiment-contract.py --evidence-dir /tmp/northstar-stage1-cases
python3 -B scripts/test-experiment-contract.py --replay-corpus /tmp/northstar-stage1-cases/synthetic-cases.json
```

The output directory must not exist. A changed source map, concrete case,
projection, expected outcome or cleanup contract fails replay. Recalculating a
damaged observation's embedded evaluation does not make it a valid baseline.
`saved-counterexample.json` separately records a deliberate synthetic
projection mismatch, manually reduced from six commands to the causal
reserve/finalize pair with a passing positive control. This is an oracle probe,
not an automatic shrinker or production-shared Rust replay.

The model preserves the current 4,096 per-actor active admission limit,
six-hour accepted retention, 30-minute pending retention and 60-second lease.
Direct, MUC and MIX share actor occupancy. Cases cover capacity refusal,
replay/payload/actor conflicts, expiry before/at/after its boundary, lease
replacement, late finalization, reservation-commit uncertainty and cancellation
before an effect. The late-finalization 4,097 case describes a source-predicate
candidate conditional on an expired pending row surviving cleanup; it neither
proves a live caller can reach it nor changes retention policy.

The real `mixed-traffic-soak.py` entry point now runs the fresh two-sender offered
workload through preflight before source queries, output creation, listener
selection or fixture startup. Initial pending occupancy is conservatively held
through the declared run because a later finalization can extend retention.
Expected capacity refusal belongs in an explicitly declared capacity scenario;
it cannot convert an invalid normal workload into a pass. Preflight does not
prove all proof/rate, queue, archive or shard limits are satisfied.

The existing fixture emits separate execution, domain, evidence and cleanup
fields. Explicit operator cancellation remains `Cancelled`; ordinary EINTR or
setup interruption is `EnvironmentInterrupted`. Typed observed contract
violations retain the first invariant. Unclassified failures, source drift,
missing terminal evidence or incomplete cleanup cannot qualify as `Pass`.
Legacy `passed`/`failed` fields remain compatibility fields, not independent
qualification. Pure mocks exercise those real fixture entry points; they do not
constitute a live fixture run or Stage 6 resource enforcement.

Only the explicit model domain clock is controlled. Synthetic keys, payload
tags and leases do not establish production MAC compatibility, proof/rate state,
locking, shard cleanup, durable-message commit or real adapter conformance.
Reservation `Unknown` is not a durable-message receipt. Each saved run must bind
its result to stable source hashes before and after the command; a post-run hash
alone cannot establish which bytes were loaded. The rebuilding ledger records
which new scope was actually accepted and which remains open.

## Families and evidence boundaries

| Family | First owner | Narrow evidence | What remains separate |
| --- | --- | --- | --- |
| Startup and roles | main/config/migration preflight | minimal-env/role/registration gates | production ACL deployment |
| C2S and publication | ProtocolSession/frame_execution | real observer futures, typed result and wiring mutations | actual socket failure injection |
| Direct messages | MessageService/DirectMessageRouter | injected production routing and exact claims | transport delivery/ACK |
| Session and SM | SmService and transport actor | exact ownership/claim/ACK tests | crash and cross-transport resume |
| Federation/components | S2S ingress and dedicated route adapter | checkpoint parity and domain policy | independent peer, public DNS/TLS |
| MUC | MucService and accepted fan-out owner | fault/cancellation tests, owned DB and wire | historical timeout root cause, Redis |
| MIX | MixService and outbox attempt | handed-off versus worker settlement tests, DB suite | MIX client/federation wire |
| Roster/privacy/presence | narrow services/version gate | races, overflow and policy tests | client interoperability |
| PubSub/PEP/archive | repositories and immutable audience outbox | query/mutation authority tests | full ignored DB/provider fixtures |
| Upload/storage | UploadService/UploadStore | exact stage and compensation tests | external S3 deployment |
| REST/admin/operations | contexts and operation runtime | cancel/renewal/idempotency tests | real external admin effects |
| Cluster | signed bus and PostgreSQL authority | signature/lease and source gates | deployed Redis TLS/failover |
| Workers/maintenance | WorkerRegistry and role composition | panic, silence, restart, drain | each business worker's own proof |
| Diagnostics | read-only probes and failure observer | bounded failure/cleanup tests | log loss/hard-kill evidence |
| Recovery | migrator/restore state machine | local recovery and authority tests | production restore drill |
| Browser crypto | browser OMEMO owner | security static checks | actual encryption/device interoperability |

## Explicit limitations that must stay visible

- Native post-write publication has no new independent deadline; BOSH retains
  its outer request budget. A pending native publication is observable policy
  debt, not evidence that the frame budget covers all continuation work
- S2S application-handler work has no new C2S five-second deadline. S2S I/O,
  idle and SM timers are different owners
- Standalone MUC intentionally holds its room mutation gate through admission
  and fan-out. The earlier DashMap snapshot fix addresses a different guard
- Clustered MUC's five-second delivery timeout does not cover every preclaim,
  claim, settlement or housekeeping DB turn. A receipt/renewal scheduling nuance
  is not claimed as a reproduced bug or silently fixed
- The durable operation worker is a top-level task, not a WorkerRegistry
  heartbeat. Repeated in-loop errors do not acquire generic worker-health proof
- Legacy HTTP spans may include URI paths. Only the dedicated execution target
  has the payload-free contract described in [Message execution](message-execution.md)
- Historical non-SM MUC round-73 failure remains unlocalized unless new evidence
  reproduces and causally explains it; later passing runs cannot close it

## Owned database reproduction

Run `python3 scripts/room-db-experiments.py --output-dir /tmp/northstar-room-db-proof`
with PostgreSQL server/client tools, OpenSSL and the repository Rust toolchain
on PATH. The output directory must be new and outside the source checkout.
The wrapper does not attach to an existing database: it starts an owned
loopback-only PostgreSQL with disposable identity and runs the existing MUC,
MIX and authentication suites serially. It requires exact successful execution
of 6 + 11 + 10 named ignored tests, not only a zero shell exit status. Source,
command and script fingerprints accompany each result. Uncertain or forced
shutdown fails cleanup and retains private runtime state; that retained data
must not be packaged as evidence.
