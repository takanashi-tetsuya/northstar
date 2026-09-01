# Contributing to Northstar

Northstar is an early-stage, security-sensitive XMPP server. Contributions are
welcome, but protocol claims, migrations and reliability guarantees must remain
traceable to code and evidence. Read [SECURITY.md](SECURITY.md) before reporting
a vulnerability and [docs/README.md](docs/README.md) before changing behavior.

## Development setup

The release toolchain is pinned by `rust-toolchain.toml`. For a localhost-only
source build, copy `.env.development.example` to `.env`, replace its two local
PostgreSQL URL placeholders, generate a development certificate and run the
explicit migration command described in [README.md](README.md). Never commit
`.env`, credentials, certificates, keys, logs, database files, uploads or
backups.

## Change boundaries

- Keep protocol parsing and error mapping in `src/xmpp/`; application services
  own transaction and side-effect boundaries; repositories under `src/db/` own
  SQL and database DTOs.
- Published files in `migrations/` are immutable. Add a new monotonically
  numbered migration and update the migration/capability manifests instead of
  editing an applied migration.
- Update `XEP_MATRIX.md` whenever advertised RFC/XEP behavior changes, and
  update `docs/openapi.yaml` with every REST wire-contract change.
- Add unresolved compromises only to `docs/KNOWN_ISSUES.md`. Point-in-time
  handoff or validation reports belong in `docs/archive/` with a historical
  banner.
- Preserve bounded queues, deadlines, payload limits and fail-closed secret,
  TLS and database-role checks. A compatibility exception must be explicit,
  narrowly scoped and documented.

## Safe default checks

Run the non-adversarial baseline before submitting a change:

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

Run `cargo audit` and `cargo deny --all-features --locked check` for dependency
changes. The release preflight requires both tools; install them from their
official Rust packages using a reviewed, pinned version.

Fuzzing, malformed/adversarial transport traffic, abuse attack matrices,
extreme load, process/dependency termination, resource exhaustion and public
federation probing are not default contributor checks. Follow
`docs/MANUAL_SECURITY_VALIDATION.md`, obtain explicit authorization and use a
disposable isolated environment.

## Pull-request evidence

Describe the observable behavior, standards clauses or threat model affected,
the tests actually run, tests intentionally not run, schema/operations impact
and rollback or forward-fix plan. Do not call an ignored test passed, and do not
present the existence of a harness as evidence that it ran for the submitted
commit.
