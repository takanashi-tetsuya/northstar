# Northstar release checklist

This checklist prepares one exact Northstar artifact for one target deployment.
It does not turn repository-local test coverage into a public production
guarantee. Record every result against the commit, binary/image digest,
configuration generation and environment.

## 1. Freeze and identify the artifact

- [ ] Working tree changes have been reviewed and intentionally included or
  excluded; no unrelated local file is mistaken for release content.
- [ ] Every required new `src/`, `migrations/`, `scripts/`, `deploy/`, `docs/`,
  `third_party/`, `web/` and `fuzz/` file is tracked; a clean clone builds and
  passes the same gates. Do not create a release from only the repository's
  previously tracked subset.
- [ ] `Cargo.toml`, OpenAPI and release notes use the intended version.
- [ ] `Cargo.lock` is committed and the release build uses `--locked`.
- [ ] Record commit ID, source archive SHA-256, image digest, Rust version,
  target triple and SBOM/provenance artifacts.
- [ ] Set `NORTHSTAR_VCS_REF` to that exact commit before the production Compose
  build and verify the OCI source, revision, version and license labels. Each
  distributed image contains `LICENSE` and `THIRD_PARTY_NOTICES.md` under
  `/usr/share/licenses/northstar/`.
- [ ] `LICENSE`, `THIRD_PARTY_NOTICES.md` and dependency policy agree.
- [ ] `docs/KNOWN_ISSUES.md` and `XEP_MATRIX.md` have been reviewed for this
  exact artifact.

## 2. Protect secrets and database authority

- [ ] No `.env`, private certificate/key, secret, database dump, upload, log,
  PID file or generated credential is tracked.
- [ ] Production uses mounted `*_FILE` secrets outside the source checkout.
- [ ] PostgreSQL bootstrap superuser, migrator owner, runtime, command and
  backup identities are distinct as described in `DATABASE_ROLES.md`.
- [ ] The long-running process cannot create/alter schema, disable triggers or
  write command-authority tables directly.
- [ ] `DIALBACK_SECRET_FILE`, `FAST_TOKEN_SECRET_FILE`,
  `DUMMY_SCRAM_SECRET_FILE`, `ABUSE_STATE_HMAC_KEY_FILE` and
  `API_CONTROL_SECRET_FILE` are independent, backed up and rotation-ready.
- [ ] Bootstrap administrator credentials are removed from the runtime stack
  immediately after first-login rotation.

## 3. Rehearse migration and rollback

- [ ] Restore a recent production-shaped backup into an isolated environment.
- [ ] Run `cargo run --release --locked -- migrate` using only the migrator
  identity and verify all 123 migrations from `0001` through the current
  repository maximum `0124`, with `0021` as the sole intentional gap.
- [ ] Start the final runtime identity and prove startup performs only ledger,
  checksum and authority verification.
- [ ] Exercise the documented rollback/forward-fix decision; never rewrite a
  migration that has been published or applied.
- [ ] Preserve pre-migration backup, encryption/signature keys and recovery
  evidence until the rollout observation window closes.

## 4. TLS, DNS and network exposure

- [ ] Public certificate SAN covers the XMPP domain and served chain/key pass
  `verify-production-certificate.sh`.
- [ ] Certificate renewal and atomic reload have an owner and alert.
- [ ] A/AAAA plus `_xmpp-client._tcp` and `_xmpp-server._tcp` SRV records are
  correct; Direct TLS/DANE records are published only when actually supported.
- [ ] Public firewall exposes only intended client/federation/HTTPS ports.
- [ ] PostgreSQL, Redis, metrics, readiness, Grafana and component listeners
  remain private or explicitly authenticated.
- [ ] Caddy/proxy preserves the reviewed WebSocket/BOSH HTTPS assertion and
  blocks public `/readyz` and `/metrics`.

## 5. Capacity, storage and recovery

- [ ] Capacity ledger epoch/limits match the target database and do not create
  an overcommit that cannot drain.
- [ ] Local upload storage is used only for one process; a cluster uses the
  qualified shared object-store profile.
- [ ] Backups fail closed without signing and age encryption; off-host copies
  include PostgreSQL, required local upload bytes or the S3 provider snapshot,
  key-generation state and restore-floor state.
- [ ] A clean-machine restore drill verifies every object version/size/SHA-256
  and records RPO/RTO.
- [ ] Monitoring covers queue capacity, worker health, database pool, outbox,
  abuse-key authority, TLS expiry/reload, storage cleanup and backup age.

## 6. Repository-local gates

Run the non-adversarial baseline:

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

- [ ] Save complete output and record ignored tests separately; ignored is not
  equivalent to passed.
- [ ] Install reviewed `cargo-audit` and `cargo-deny` binaries, then run
  `release-preflight.sh --production` only after supplying the intended
  production paths. This is the Compose production profile and fails if Docker
  or a required certificate, secret, role URL or policy tool is unavailable.

## 7. Authorized manual gates

- [ ] Do not use `scripts/release-runtime-validation.sh` as an unattended
  aggregate. Review, authorize and execute each applicable runtime harness
  separately in a disposable isolated environment, then record its exact target,
  side effects, artifact, configuration and result.
- [ ] Complete the applicable isolated items in
  `MANUAL_SECURITY_VALIDATION.md`; do not run its cybersecurity-sensitive
  commands against production or an unauthorized target.
- [ ] On staging, test at least two independent native clients plus the browser
  client: registration/login, roster, OMEMO single/MUC/multi-device trust,
  Carbons, CSI, SM resume, MAM, upload, reports/appeals and account revocation.
- [ ] Test federation with authorized independent implementations and record
  DNS, certificate, implementation/version and stable stanza IDs.
- [ ] Verify the actual alert receiver, escalation path, backup destination and
  restore operator—not only the local Prometheus rules.
- [ ] Treat experimental Redis clustering as blocked unless every applicable
  `EXT-CLUSTER` condition in `KNOWN_ISSUES.md` is closed for this artifact.

## 8. Rollout and abort criteria

- [ ] Deploy migrations first, then one final release binary/image; do not run
  an old binary against a schema outside its documented compatibility window.
- [ ] Keep the service attached to the supervisor and confirm `/healthz`, the
  private `/readyz`, private metrics and critical-worker readiness.
- [ ] Observe authentication failures, queue growth, database saturation,
  outbox retries, storage reconciliation and TLS/federation errors before
  opening registration or broad federation.
- [ ] Abort on migration/checksum/authority drift, missing secret files,
  unexpected public listener, critical worker failure, unbounded backlog,
  unexplained message loss/duplication, or inability to restore the backup.
- [ ] Rollback follows the recorded data-compatible procedure; never bypass a
  fail-closed check merely to make readiness green.

## 9. Ship decision

Release only when all required boxes have evidence. Single-node deployment is
the supported baseline. Remaining standard/platform/cryptographic trust
boundaries may be accepted only with the exact wording in `KNOWN_ISSUES.md`;
missing target-environment or external evidence must remain an explicit release
exception signed by the operator.
