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
node scripts/check-documentation-consistency.mjs
node scripts/check-outbound-xml-construction.mjs
node scripts/check-parser-fuzz-coverage.mjs
node scripts/check-tracked-sensitive-files.mjs --include-untracked
node scripts/verify-crypto-artifacts.mjs
```

`check-*`, `verify-*` and `audit-*` are not automatically safe merely because
of their names: inspect whether they invoke Docker, WSL, a database, a network
peer or an external toolchain.

## Release and operations

| Entry point | Purpose |
| --- | --- |
| `release-preflight.sh` | Full repository quality/dependency policy plus optional Compose production certificate, secret, role and image checks; `--production` requires Docker |
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
