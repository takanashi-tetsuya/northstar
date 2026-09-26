# Northstar script guide

Scripts are grouped by purpose through their names. Many runtime scripts start
temporary services, create isolated PostgreSQL schemas or deliberately exercise
failure/security boundaries; read the script before running it.

## Safe default quality gates

These are static or deterministic local checks and do not target a running
service:

```sh
cargo fmt --all -- --check
cargo check --all-targets --all-features --locked
cargo test --all-targets --all-features --locked
cargo clippy --all-targets --all-features --locked -- -D warnings
node scripts/check-architecture-boundaries.mjs
node scripts/check-subserver-boundaries.mjs
node scripts/check-documentation-consistency.mjs
node scripts/check-outbound-xml-construction.mjs
node scripts/check-parser-fuzz-coverage.mjs
node scripts/test-parser-fuzz-coverage.mjs
node scripts/check-ci-required.mjs --workflow-only
node --test scripts/test-ci-release-gates.mjs
node scripts/check-tracked-sensitive-files.mjs --include-untracked
node scripts/verify-crypto-artifacts.mjs
bash scripts/test-contract-compatibility.sh # requires the CI-pinned Buf 1.50.0
```

`check-contract-compatibility.sh` compares existing Protobuf modules against the
immutable event baseline with Buf's `FILE` breaking rules. A baseline without
`contracts/proto` is accepted only for a first introduction: it must be an
ancestor in a complete checkout, with no module or `.proto` files anywhere in
its history. That case compiles the new module because Buf 1.50 rejects empty
comparison images. Formatting, lint and generated-code drift remain mandatory
in the separate contract quality job. Missing history, removed or relocated
older contracts, and invalid or removed current modules fail the check.

`check-*`, `verify-*` and `audit-*` are not automatically safe merely because
of their names: inspect whether they invoke Docker, WSL, a database, a network
peer or an external toolchain.

`maintenance-subserver-wsl.py --server /absolute/path/to/rust-xmpp-server`
tests an existing Linux binary using its own temporary Unix-socket PostgreSQL
cluster and real runtime grants. It starts core and maintenance against the
same database, checks simultaneous readiness and restarts core without taking
maintenance ownership. It also covers secret/configuration separation,
bounded expiry, legal holds, first-failure readiness, exclusive ownership,
loss of the locked connection and maintenance restart. It does not build the
binary, connect to an existing database or replace client protocol tests. See
[subserver deployment](../docs/SUBSERVERS.md) for the process contract.

`test-restore-session-protocol.py` checks bounded restore-session markers;
the full isolated `backup-restore-wsl.sh` drill also runs its generated SQL
against PostgreSQL, including a SIGKILL recovery after the first new object
move. The same drill backs up and restores exact S3 versions against a
disposable MinIO bucket, rejects a missing version, and recovers a committed
restore after SIGKILL. `test-restore-recovery.py` checks exact local-object
replay and rejects damaged journals without a database. `test-listener-stress-phases.py` exercises
fixture synchronization and identity checks without starting Northstar.

`test-storage-migration-wsl.sh` uses a disposable PostgreSQL 17 schema and a
versioned loopback MinIO bucket from `lib/isolated-minio-fixture.sh` to check
both migration directions and interruption recovery. `test-backup-inventory.py`
checks the S3 backup inventory and fresh restore locator mapping offline.

`listener-readiness-stress-wsl.sh` runs 2 × 50 for pushes, PRs and ordinary
manual CI, and 20 × 50 for scheduled CI. Select `extended_stress` to run
100 × 50. Every round exercises the complete fixture at 50-pair concurrency;
round counts control repetition rather than protocol coverage. The regular
matrix retains its PostgreSQL observer and verifies the diagnostic artifacts.
Each pair owns two migrated database copies, certificates,
listeners and separate log directories. All pairs finish certificate, secret,
binary/database preparation and all four relay readiness checks before any
server starts. Relay readiness does not depend on a server target, avoiding a
dependency cycle at this barrier. Federation waits for both servers in every
pair to be ready before protocol activity, then for all pairs to finish the
four transport-boundary probe groups before registration and password work.
Those probes keep their original order, assertions and cross-pair concurrency;
the waiting Python process holds no authentication slot. Its phase record is
bound to the round, nonce, pair and actual PID, whose ancestry must reach the
assigned worker leader. Phase releases enforce preparation → live → transport.
MIX retains its
signed all-pair setup barrier. Both families share the fixture's bounded
authentication admission lanes, with CPU sizing based on process affinity and
cgroup quota. A failed or missing pair fails the round; preparation never
extends the worker supervisor or a server's readiness deadline. Smaller local
runs diagnose failures and do not replace evidence from the complete CI matrix.
The MIX restart recovery window begins once the pair acquires its authentication
lane. Authentication and all four recovery events share the same 150 seconds;
waiting behind other pairs remains subject to the existing worker deadline.
Federation registers both accounts before admitting its initial two client
connections together. Later Carbon/reconnect admission sends WebSocket Ping
to existing clients at most once per minute while waiting, so fixture queueing
does not leave them idle past the unchanged 300-second server limit. Waiting
callbacks hold no admission slot or metadata descriptor; send failures fail the fixture.
Pong frames remain outside XMPP assertions and do not restart receive budgets.
Live-child checks read the current process state and birth time together on
every pass; they do not cache identities or relax phase ownership checks.

The required PostgreSQL observer prepares its query once, then samples fresh
backend state on the same attested connection. It retains the 3-second sample
budget, bounded late-response drain and consecutive-error policy described in
[subserver diagnostics](../docs/SUBSERVERS.md). CI preflight runs both unit and
private PostgreSQL regressions before starting the pressure matrix.

Capacity runs explicitly build the `runtime-test` Cargo profile and use
`$CARGO_TARGET_DIR/runtime-test/rust-xmpp-server`. This profile inherits `dev`,
uses optimization level 2, and keeps debug assertions, integer overflow checks
and panic unwinding. Ordinary unit tests and direct federation integrations
retain their existing debug builds. The parent passes
`NORTHSTAR_RUNTIME_TEST_PROFILE=runtime-test` to both child fixtures; they never
fall back to a binary in `debug`. Before any fixture database work, the parent
checks the manifest, refuses external compiler/profile overrides, and verifies
Cargo's current artifact path, workspace source and effective optimization and
assertion settings. The runtime connection-budget manifest is still read from
that same binary. These runs keep password costs, protocol assertions, the
15 second startup and 900 second worker deadlines, and the full pair matrices.
An optimized run is capacity evidence for its recorded host and profile, not
a production throughput guarantee. `test-runtime-test-profile.py` checks this
contract without building or starting the server.

For the two federation fixtures, a server's nonce-bound listener record and
healthy HTTP responses from its backend and relay share one monotonic 15 second
startup deadline. Bound sockets alone do not establish HTTP readiness. Startup
observations retain the first or changed failure reason with bounded output;
they never retry a business operation or extend a runtime health deadline.

## Release and operations

| Entry point | Purpose |
| --- | --- |
| `release-preflight.sh` | Full repository quality/dependency policy plus optional Compose production certificate, secret, role and image checks; `--production` requires Docker |
| `.github/workflows/release.yml` | `main` / `codex/release-*` pushes and manual runs build a preview. A qualified version tag publishes three GHCR images, generates packages, `SHA256SUMS`, `IMAGE_DIGESTS`, `RELEASE-EVIDENCE.json` and provenance, and prepares a draft Release |
| `release-runtime-validation.sh` | Umbrella runtime suite; do not run unattended in a sensitive environment |
| `create-production-secrets.sh` | Create the file-backed production secret set in a protected external directory |
| `reconcile-database-roles.sh` / `reconcile-database-grants.sh` | Bootstrap and attest PostgreSQL role separation |
| `backup.sh`, `verify-backup.sh`, `restore-backup.sh` | Signed/encrypted backup lifecycle |
| `generate-development-certificate.sh` | Localhost-only development certificate; never a public certificate |
| `verify-production-certificate.sh` | Production certificate/key policy checks |

Follow [the release checklist](../docs/RELEASE_CHECKLIST.md), [production
operations](../docs/PRODUCTION_OPERATIONS.md) and [backup security
policy](../docs/BACKUP_SECURITY.md). Never place real credentials in a command
line, log or committed file.

The `0.2.0` workflow names its complete packages
`northstar-0.2.0-linux-amd64.tar.gz` and
`northstar-0.2.0-windows-amd64.zip`; it also emits raw
`northstar-0.2.0-linux-amd64` and
`northstar-0.2.0-windows-amd64.exe` binaries. A successful tag run creates or
updates a draft Release and publishes the three GHCR images. Fresh Windows and
Linux jobs download all seven draft assets and verify checksums, attestations
and native executables. Review `RELEASE-EVIDENCE.json`, the three exact image
references in `IMAGE_DIGESTS`, and the successful workflow before publishing
the draft. `SHA256SUMS` covers the four binary assets and both evidence files.
The maintainer performs the final Publish release action.

Draft preparation searches the paginated Release list, which includes drafts
for maintainers. Authentication, server and network errors stop the job.
Retries can update an existing draft; they cannot overwrite a published release.

If a tag run passed every build, native runtime, image and attestation check but
failed during draft preparation, run `Release preparation` from `main` with
`resume_tag` and the original `artifact_run_id`. Recovery verifies that run's
identity, successful build checks and artifact provenance, then resumes upload
and fresh Windows/Linux downloads. It preserves the signed tag, packages and
published images. Leave both inputs empty for a normal build preview.

The helpers in [`dev/`](dev/) build or start a local development instance.
For example, run `bash scripts/dev/start_server.sh` or `scripts\dev\start.bat`
from the checkout root. They locate the checkout themselves and read its `.env`.
The root `Makefile` also provides `check`, `test`, `format` and `run` targets.
Set up PostgreSQL and apply migrations using the steps in the project README
before starting the server.

## Isolated database/runtime families

- `local-vm-lab-network.sh`, `local-vm-lab-guest.sh`,
  `local-vm-lab-install-package.sh`, `local-vm-lab-dns.sh`,
  `local-vm-lab-client-dns.sh`, `local-vm-lab-certs.sh`,
  `local-vm-lab-database.sh`, `local-vm-lab-node.sh`,
  `local-vm-lab-peers.sh`, `local-vm-lab-preflight.sh`,
  `local-vm-lab-minio.sh`, `local-vm-lab-minio-bucket.sh`,
  `local-vm-lab-redis.sh`, `local-vm-lab-cluster.sh`,
  `local-vm-lab-cluster-delivery.py`, `local-vm-lab-upload.py`,
  `local-vm-lab-soak.py`,
  `local-vm-lab-federation.py` and
  `local-vm-lab-peer-recovery.sh`: create and check the non-forwarding libvirt
  network, checksum-pinned Debian guests, signed lab DNS zone, lab PKI,
  PostgreSQL roles, versioned S3 storage and signed two-node Redis control
  plane; then send messages across nodes and to fixed Prosody and ejabberd
  peers. See
  [the VM qualification guide](../docs/LOCAL_VM_QUALIFICATION.md) for the
  sequence and evidence limits. The guest helper requires a lab-only SSH
  public key and leaves existing VMs untouched. Package installation uses a
  temporary NAT interface that is removed before qualification.
- `*-db-wsl.sh`: PostgreSQL-backed domain invariants using an isolated database
  or random schema.
- `integration-wsl.*`: broad C2S/REST/XMPP integration.
- `federation-wsl.*`, `s2s-db-wsl.sh`: two-domain federation and outbox.
- `component-runtime-wsl.*`: XEP-0114/XEP-0225 component profiles.
- `local-vm-lab-component*.py`: bounded Slixmpp XEP-0114 accept and XMPP
  client probes for the isolated VM lab; see
  [component lab procedure](../docs/LOCAL_VM_COMPONENT_PROBE.md).
- `cluster-wsl.*`, `muc-cluster-wsl.sh`: experimental Redis/multi-process paths.
  `cluster-wsl.sh` accepts `NORTHSTAR_CLUSTER_DATABASE_PORT` (default `5432`)
  for a disposable PostgreSQL fixture on `127.0.0.1`; the server and all shell
  and Python database probes use this same endpoint.
- `mix-*`, `pubsub-*`, `muc-*`, `mam-*`, `sm-*`: protocol-family fixtures.
- `browser-e2e-*`, `web-e2e.cjs`, `omemo-runtime-wsl.*`: browser and OMEMO
  runtime evidence.
- `load-1000-*`: capacity-envelope tests, not a production SLA.

Use disposable credentials, loopback/isolated ports and a database that the
script accepts as a test target. Record the tested commit, environment and result.

## Cybersecurity-sensitive and destructive validation

Fuzzing, malformed transport frames, Slowloris/churn, abuse/PoW attack matrices,
SIGKILL/disk-full/power-loss points, PostgreSQL/Redis/object-store chaos,
extreme load, public federation probes and penetration tests are intentionally
documented separately in [MANUAL_SECURITY_VALIDATION.md](../docs/MANUAL_SECURITY_VALIDATION.md).
Run them only with explicit authorization in a disposable, resource-limited
environment. Do not aim them at production, third parties or a shared developer
database.

## Process-safety convention

Runtime helpers must record the exact PID they create, verify that PID's
executable/working context before stopping it, and remove only their own state.
Broad process-name termination is prohibited. The static
`check-process-isolation.mjs` gate enforces the current baseline.
