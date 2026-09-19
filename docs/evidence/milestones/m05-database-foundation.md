# M05-01 database foundation evidence

Status: **foundation implemented; service cutover pending**.

The new `foundation-postgres` crate centralizes the parts that were previously
repeated by services:

- pool construction with application name, TLS mode, bounded acquire/connect
  timeouts, idle/lifetime limits, statement/lock/idle-transaction timeouts;
- non-secret connection attestation (`current_user`, `session_user`, logical
  database, schema, and `search_path`), with optional fail-closed policy checks;
- explicit transaction isolation/read-only/deferrable options;
- SQLSTATE-to-typed repository error mapping;
- migration-ledger verification by exact version, description, ordering,
  success flag, and SHA-384 checksum. Verification never applies migrations.

The role model and expand/backfill/switch/contract policy are documented in
`docs/database/role-model.md` and `docs/database/migration-policy.md`.
Existing PostgreSQL bootstrap/reconciliation scripts remain the authoritative
deployment path for the current monolith and already create separate
bootstrap, migrator, runtime, command, and backup identities. The new
`db-bootstrap` tool now generates deterministic per-service database/role
bootstrap SQL from the ownership catalog without embedding passwords. Real
database execution and cross-database negative tests are still pending; this
evidence file does not represent those checks as complete.

## Local evidence

- `cargo check --workspace --all-targets --all-features` passed.
- `cargo test --locked -p foundation-postgres --all-targets` passed (3 tests).
- `cargo clippy --locked -p foundation-postgres --all-targets -- -D warnings`
  passed.
- crate catalog generation records 81 workspace packages, including the
  catalog-driven `db-bootstrap`, `restore-verifier`, and
  `kafka-policy-generator` tools.
- documentation, service catalog, and architecture-boundary validators passed.

External PostgreSQL integration, migration replay, role negative tests, and
HA/failover evidence require the isolated CI/WSL harness and remain pending.
