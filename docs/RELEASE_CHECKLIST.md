# Northstar release checklist

This checklist prepares one exact Northstar artifact for one target deployment.
It does not turn repository-local test coverage into a public production
guarantee. Record every result against the commit, binary/image digest,
configuration generation and environment.

The current development line is `0.2.0`. Do not assign `1.0.0` until one exact
artifact and target environment have completed every applicable checkbox in
this document, all release-blocking known issues are closed, and the retained
evidence has been reviewed.

The tag workflow prepares artifacts and a **draft** GitHub Release. It does not
make that draft a reviewed public release. Linux AMD64 is the supported
production baseline; Windows AMD64 artifacts are for development and evaluation.

## 1. Freeze and identify the artifact

- [ ] Working tree changes have been reviewed and intentionally included or
  excluded; no unrelated local file is mistaken for release content.
- [ ] Every required new `src/`, `migrations/`, `scripts/`, `deploy/`, `docs/`,
  `third_party/`, `web/` and `fuzz/` file is tracked; a clean clone builds and
  passes the same gates. Do not create a release from only the repository's
  previously tracked subset.
- [ ] `Cargo.toml`, `Cargo.lock`, OpenAPI, Docker/Compose defaults, README files,
  security policy and both changelogs consistently use `0.2.0`; the stable tag
  is exactly `v0.2.0`, while file and OCI versions omit the leading `v`.
- [ ] `Cargo.lock` is committed and the release build uses `--locked`.
- [ ] Record the exact tag commit, Rust `1.97.1`, the package target triples
  `x86_64-unknown-linux-gnu` and `x86_64-pc-windows-msvc`, and the workflow run
  URL. Do not place a guessed hash or a different run's hash in release notes.
- [ ] The workflow produced exactly these four `0.2.0` binary assets:
  `northstar-0.2.0-linux-amd64.tar.gz`,
  `northstar-0.2.0-linux-amd64`,
  `northstar-0.2.0-windows-amd64.zip`, and
  `northstar-0.2.0-windows-amd64.exe`.
- [ ] The complete Linux tarball and Windows ZIP contain the matching
  `xmpp-server`/`xmpp-server.exe`, `web/`, `third_party/swagger-ui/dist/`,
  `.env.example`, `README.md`, `LICENSE`, `THIRD_PARTY_NOTICES.md`, and the
  Swagger UI `LICENSE`/`NOTICE`. Raw binaries are not described as complete
  standalone distributions.
- [ ] `SHA256SUMS` verifies all four binary assets and `IMAGE_DIGESTS`; the
  checksum file and packages have GitHub build-provenance attestations. Record
  checksums only from the successful tag run.
- [ ] `IMAGE_DIGESTS` contains exactly one immutable `name@sha256:digest`
  reference for each Linux AMD64 image:
  `ghcr.io/takanashi-tetsuya/northstar`,
  `ghcr.io/takanashi-tetsuya/northstar-backup`, and
  `ghcr.io/takanashi-tetsuya/northstar-database-grants`.
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
- [ ] Treat migration `0126` as a stopped-writer boundary: stop and verify the
  absence of every runtime, MIX worker and maintenance writer before migration;
  never roll pre-`0126` and post-`0126` processes together. Startup ledger
  attestation blocks an old binary from restarting, not one left running.
- [ ] Keep all runtimes stopped through migration `0127`, which atomically
  replaces the SM claim projection and installs its version/notification
  authority. Reconcile exact grants before starting the new binary.
- [ ] Keep all runtimes stopped through migration `0128`, which installs exact
  owner-maintained MIX-PAM counters/capabilities and independently committed
  MIX delivery reclamation. Verify the startup counter audit and exact grants.
- [ ] Run `cargo run --release --locked -- migrate` using only the migrator
  identity and verify all 127 migrations from `0001` through the current
  repository maximum `0128`, with `0021` as the sole intentional gap.
- [ ] Start the final runtime identity and prove startup performs only ledger,
  checksum and authority verification.
- [ ] Budget one additional PostgreSQL connection per process for the
  supervised `sm-authority-listener`; verify listener restart makes readiness
  degrade and recovery wakes Pending resume claims for an authoritative
  recheck without periodic polling.
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

- [ ] MIX delivery and PAM capacity audits match the target database. Prove an
  actual hard-cap rejection is distinct from lock contention and that complete,
  independently committed reconciliation makes released capacity visible
  without a fixed retry count, GC page size or worker interval.
- [ ] Exercise XEP-0115 exact-owner replacement/teardown, cache eviction,
  complete `+notify` projection, hint-queue saturation, failed-effect recovery
  and local/federated fairness. A cache or hint limit may affect latency only;
  federated resource exhaustion must reject presence before routing instead of
  silently accepting incomplete PEP/OMEMO/MIX work.
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
- [ ] A normal `main`-push dry run of `.github/workflows/release.yml` built both
  AMD64 targets without publishing GHCR images or creating a GitHub Release.
  Dry-run workflow artifacts are evidence for that commit only and are not
  public release downloads.

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

- [ ] Deploy migrations first, then one final release binary or exact
  `name@sha256:digest` image; do not run an old binary against a schema outside
  its documented compatibility window.
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

## 9. Tag, draft and publication

- [ ] Treat pushing `v0.2.0` as an external publication action: the tag workflow
  pushes the three GHCR images before it prepares the draft GitHub Release. Do
  not push the tag merely to discover whether the release is ready.
- [ ] Only after ship approval, replace the `Unreleased` markers in
  `CHANGELOG.md` and `changelog/v0.2.md` with the real release date/status and
  identify `0.2.0` as the current release in `README.md`. The tag workflow
  rejects a commit that still carries development-state release markers; do not
  make these claims early merely to satisfy the gate.
- [ ] Confirm the reviewed release commit is the intended protected-branch
  commit, create the immutable `v0.2.0` tag at that commit, verify
  `v0.2.0^{commit}`, and push only that tag. Never move or reuse a published tag.
- [ ] Wait for the complete tag-triggered `Release preparation` workflow. It
  must finish successfully and create or update a **draft**, not an already
  public GitHub Release.
- [ ] From a clean machine, download the draft's four binary assets,
  `SHA256SUMS`, and `IMAGE_DIGESTS`. Run `sha256sum --check SHA256SUMS` over the
  complete set; on Windows independently compare `Get-FileHash -Algorithm
  SHA256` output with each applicable checksum entry.
- [ ] Verify GitHub build provenance for the four packages, `IMAGE_DIGESTS`, and
  `SHA256SUMS`. Provenance is not replaced by downloading a checksum from the
  same Release.
- [ ] Extract both complete archives into empty directories, confirm their
  required runtime/license contents, confirm the extracted executable matches
  the corresponding raw asset, and run `xmpp-server --version` or
  `xmpp-server.exe --version`; each must report `0.2.0`.
- [ ] Pull all three `IMAGE_DIGESTS` references by digest. Verify architecture,
  image digest, SBOM/provenance, source/revision/version/license labels,
  non-root user, health check/entrypoint where applicable, and anonymous pull
  visibility if public access is intended.
- [ ] Render `docker-compose.yml` with `deploy/docker-compose.release.yml` using
  Docker Compose `2.24.4` or newer and all three digest refs. Confirm `migrate`
  and `xmpp` use `northstar`, `backup` and `restore` use `northstar-backup`,
  `database-grants` uses `northstar-database-grants`, and none retains `build:`.
- [ ] Review the draft title/body and generated notes. They must state that
  Linux AMD64 is the production baseline, Windows AMD64 is development/evaluation
  only, raw binaries require the matching runtime assets, and no unverified
  checksum, digest or test result is presented as fact.
- [ ] Publish the draft manually only after every required gate is approved.
  Record the publication URL/date, exact tag commit, workflow run, package
  checksums, image digests, attestations, exceptions and approver.
- [ ] After publication, repeat fresh public download, checksum/provenance and
  intended GHCR pull checks. If any gate fails, keep the draft unpublished; do
  not move the tag or silently replace evidence from the failed run.

## 10. Ship decision

Release only when all required boxes have evidence. Single-node Linux AMD64 is
the supported production baseline. Remaining standard/platform/cryptographic
trust boundaries may be accepted only with the exact wording in
`KNOWN_ISSUES.md`; missing target-environment or external evidence must remain
an explicit release exception signed by the operator.
