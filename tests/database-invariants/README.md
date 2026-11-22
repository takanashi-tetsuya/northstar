# Database invariant tests

This directory holds no tests. Database invariants are tested where the
code that owns them lives, against isolated PostgreSQL databases. No test
connects to a shared development database.

## Where each invariant is tested

**Migration ledger and schema drift**

- The `northstar-postgres` unit tests reject a migration that is pending,
  failed, duplicated, unknown or has drifted from its checksum.
- `scripts/check-database-capability-manifest.py` checks the generated
  SHA-384 ledger manifest.
- `scripts/migration-upgrade-wsl.sh` and `scripts/migration-0056-db-wsl.sh`
  upgrade real databases.

See [migration policy](../../docs/database/migration-policy.md).

**Role and privilege boundaries**

- `scripts/check-database-role-boundaries.sh` checks the role boundaries
  statically. It runs `scripts/check-runtime-row-locks.py`, which rejects a
  production SQL row lock on any relation the runtime role cannot `UPDATE`.
- The `database-role-boundary` CI job runs
  `scripts/database-role-boundary-db-ci.sh` against a live database. It
  replays every production statement that calls a runtime account lock
  capability as the reconciled runtime login.

See [database roles](../../docs/DATABASE_ROLES.md).

**Repository behaviour shared by adapters**

`scripts/repository-conformance-db-wsl.sh` runs the `northstar-db-it`
conformance suite. Each run uses its own `northstar_conformance_it_` schema.

**Per-context concurrency, CAS, idempotency and outbox rules**

The `*-db-wsl.sh` suites run the ignored database tests of each adapter
crate. Two examples are `muc-db-wsl.sh` and `pubsub-outbox-db-wsl.sh`.

## How CI runs them

`scripts/stateful-database-ci.sh` groups most of these suites into shards.
The `stateful-database-integration` CI job gives each shard its own runner
and a loopback-only PostgreSQL fixture, and each suite creates its own
schema. The MAM and MIX database suites run in the MIX validation job
instead.

## Adding an invariant

Write the test next to the repository code that owns the rule.

1. Mark it `#[ignore]` when it needs PostgreSQL.
2. Add it to the suite of that context, or to the conformance suite when
   every adapter must satisfy it.
3. Make sure the suite is listed in a shard of
   `scripts/stateful-database-ci.sh`. `scripts/check-stateful-database-ci.mjs`
   keeps that shard manifest exact, so a suite cannot drop out unnoticed.
