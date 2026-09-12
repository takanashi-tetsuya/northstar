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
against PostgreSQL. `test-listener-stress-phases.py` exercises the small
fixture synchronization and identity checks without starting Northstar.

`listener-readiness-stress-wsl.sh` keeps the regular 20 × 50 and scheduled
100 × 50 matrices. Each pair owns two migrated database copies, certificates,
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
| `.github/workflows/release.yml` | On ordinary `main` pushes, builds dry-run Linux/Windows AMD64 packages; on an exact version tag, publishes three GHCR images, generates `SHA256SUMS`, `IMAGE_DIGESTS` and provenance, and prepares a draft GitHub Release for manual review |
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
updates a draft Release—it does not authorize or perform final GitHub Release
publication. The tag run does push the three GHCR images, so pushing the tag is
itself a publication-sensitive action. Review the four package checksums, the
three exact GHCR references in `IMAGE_DIGESTS`, and the GitHub provenance before
publishing the draft. Never invent or copy a hash from a different workflow run.

The root `build.sh`, `build_and_start.sh`, `start_server.sh`, `start.bat` and
`Makefile` targets are compatibility wrappers for local development. They do
not provision PostgreSQL, apply migrations, install a supervisor or qualify a
production deployment. Follow the explicit migration and foreground-start
steps in the repository README instead.

## Isolated database/runtime families

- `*-db-wsl.sh`: PostgreSQL-backed domain invariants using an isolated database
  or random schema.
- `integration-wsl.*`: broad C2S/REST/XMPP integration.
- `federation-wsl.*`, `s2s-db-wsl.sh`: two-domain federation and outbox.
- `component-runtime-wsl.*`: XEP-0114/XEP-0225 component profiles.
- `cluster-wsl.*`, `muc-cluster-wsl.sh`: experimental Redis/multi-process paths.
  `cluster-wsl.sh` accepts `NORTHSTAR_CLUSTER_DATABASE_PORT` (default `5432`)
  for a disposable PostgreSQL fixture on `127.0.0.1`; the server and all shell
  and Python database probes use this same endpoint.
- `mix-*`, `pubsub-*`, `muc-*`, `mam-*`, `sm-*`: protocol-family fixtures.
- `browser-e2e-*`, `web-e2e.cjs`, `omemo-runtime-wsl.*`: browser and OMEMO
  runtime evidence.
- `load-1000-*`: capacity-envelope tests, not a production SLA.

Use disposable credentials, loopback/isolated ports and a database that the
script explicitly accepts as a test target. A script's existence is not evidence
that it passed for the current release artifact.

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
