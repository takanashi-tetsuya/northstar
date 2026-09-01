# Changelog

All notable Northstar changes are documented here. Protocol support claims are
normative only in [XEP_MATRIX.md](XEP_MATRIX.md), and unresolved release
boundaries are normative only in [docs/KNOWN_ISSUES.md](docs/KNOWN_ISSUES.md).

## [0.2.0] - 2026-09-01

- The complete change set from the previous committed `0.1.0` baseline is
  recorded in the [0.2 development changelog](changelog/v0.2.md).
- Cargo, Compose, OCI, backup and OpenAPI metadata now identify the current
  pre-1.0 development line as `0.2.0`. Version `1.0.0` is reserved until one
  exact artifact and target environment satisfy every applicable production
  qualification gate in the release checklist.
- Rebuilt the current documentation set around one compatibility matrix, one
  known-issues register, an operations manual, a release checklist and an
  explicitly historical archive; added a loopback-only development profile and
  contributor/security policies.
- Pinned the release Rust toolchain, added Cargo repository metadata, and added
  OCI source/revision/version/license labels plus project license notices to all
  Northstar images.
- Added tag-driven release preparation for `0.2.0`. It builds a complete Linux
  AMD64 tarball plus raw ELF binary and a complete Windows AMD64 ZIP plus raw
  executable, generates `SHA256SUMS` and GitHub build provenance, publishes the
  `northstar`, `northstar-backup` and `northstar-database-grants` Linux AMD64
  images to GHCR, records their exact refs in `IMAGE_DIGESTS`, and prepares a
  draft GitHub Release for manual review. This changelog does not claim that the
  draft has been published or predeclare hashes from a run that has not occurred.
- Added `deploy/docker-compose.release.yml` for deploying the three release
  images without a local build. It requires Docker Compose `2.24.4` or newer;
  production operators replace the convenient `:0.2.0` defaults with the exact
  digest refs from the successful tag run.
- Added a side-effect-free `xmpp-server --version` identity check. Linux AMD64
  remains the production baseline; the Windows AMD64 package is for development
  and evaluation.
- Production preflight now validates the independent command database role and
  fails closed when its Compose/Docker validation cannot run. Parser fuzzing now
  joins the heavy runtime envelopes as a scheduled/manual-only CI job instead
  of running on ordinary push or pull-request events.
- Hardened incremental XML framing against stale UTF-8 byte offsets when a
  defensive adapter replaces a rejected incomplete buffer. RFC 7395 parsing now
  explicitly resets pending per-message scan state without discarding the XML
  entity's declaration state.
- PubSub Atom notification summaries now enforce their byte ceiling at a UTF-8
  character boundary instead of panicking when the limit intersects a
  multibyte character.
- Registration now fails closed if its durable runtime control row is missing;
  migration `0125` replaces the capability without weakening schema or role
  isolation. `INVITATION_REQUIRED` is documented as the shared REST/XEP-0077
  invitation-policy switch.
- CI now hashes canonical LF-only migration bytes, pins the exact Rust 1.97.1
  builder digest, uses a genuinely loopback PostgreSQL runtime fixture, and
  exercises production-shaped upload capacity and disaster-recovery rollback.
- CI runtime fixtures now emit redacted, fixture-specific failure annotations,
  so failures remain diagnosable without replaying privileged or adversarial
  network tests on a developer workstation. The two-domain federation fixture
  also retries harmless duplicate ephemeral-port selections while keeping
  explicit operator-supplied port collisions fatal.
- Runtime schema attestation now follows the connection's already pinned
  schema, so privilege-separated and isolated-schema deployments cannot read a
  different `public` migration ledger. Authentication database fixtures also
  use one fresh schema per exact test.
- Strict XEP-0198 same-device policy no longer issues an unusable resume bearer
  to legacy SASL clients that cannot present a SASL2/XEP-0388 device UUID; they
  retain ordinary Stream Management with `resume=false`.
- Counted durable stanzas on connections without active Stream Management now
  remain owned by the socket write-boundary completion path. A debug-only
  assertion previously treated this valid path as impossible and could panic a
  C2S WebSocket actor during ordinary durable delivery.
- Upload capability projections now explicitly convert the historical
  `VARCHAR(255)` content type to their declared PostgreSQL `TEXT` return type,
  preventing first PUT and public-file retrieval failures.
- Upload database fixtures now isolate incompatible immutable capacity-policy
  profiles in separate schemas. Authentication publication tests also verify
  that expiry cleanup uses `SKIP LOCKED` without deleting a protected lease,
  then reclaims it after the publication transaction releases the lock.
- Production qualification still requires the target-environment and external
  gates in [the release checklist](docs/RELEASE_CHECKLIST.md).

## [0.1.0] - Historical baseline

- Initial pre-1.0 Northstar baseline at Git commit
  `998396915ab38a9deadf47ae871be561e11f7ef2`, with migrations `0001`–`0013`.
- The complete delta from this baseline to `0.2.0` is maintained in
  [the 0.2 development changelog](changelog/v0.2.md).

## Historical development snapshots

Point-in-time handoff, validation and planning reports are retained under
[`docs/archive/`](docs/archive/). They are evidence of prior work, not current
feature or security declarations.

[0.2.0]: https://github.com/takanashi-tetsuya/northstar/releases/tag/v0.2.0
[0.1.0]: https://github.com/takanashi-tetsuya/northstar/commit/998396915ab38a9deadf47ae871be561e11f7ef2
