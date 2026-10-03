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

Every catalog experiment is `declared`. The validator never executes commands
or changes that value to `passed`. Each mapped runtime identity is only
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
