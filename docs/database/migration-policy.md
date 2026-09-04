# PostgreSQL migration policy

Northstar applies schema changes outside the service process. A dedicated
migrator job, using the service's `*_migrator` role, runs the checked-in SQL
migrations before the runtime deployment is made ready. Runtime roles never
call `sqlx::migrate!`, create tables, or alter grants during request handling.

## Migration ledger

Each logical service database owns its own `_sqlx_migrations` table and ledger.
The release pipeline generates a version, description, ordering, and SHA-384
checksum manifest from the exact migration directory. The deployment passes
that manifest to `foundation-postgres::verify_migrations`; startup fails closed
when the table is absent, an entry is unsuccessful, or any version,
description, order, or checksum differs. This makes a manually modified
database visible before traffic is accepted.

## Expand, backfill, switch, contract

Changes use four separately reviewed phases:

1. **Expand** — add nullable columns, new tables, or compatible indexes. Old
   binaries continue to work.
2. **Backfill** — run a bounded, resumable migrator job. It records progress
   and throttles work so it cannot consume the request pool.
3. **Switch** — deploy code that reads/writes the new representation and
   verify invariants and outbox/reconciliation counts.
4. **Contract** — only after the compatibility window, remove old columns or
   constraints in a separately approved migration.

Destructive or irreversible changes require an explicit rollback decision,
backup/restore evidence, and an operator approval. A service restart is never
treated as a migration rollback.

## Transaction discipline

`foundation-postgres` exposes explicit transaction options for isolation,
read-only mode, and deferrability. Callers must choose locking semantics at
the repository boundary; helpers do not silently upgrade isolation or hide
long-running locks. SQLSTATE values are mapped to typed repository errors so
serialization conflicts, deadlocks, timeouts, constraint failures, and
permission failures can be retried or surfaced intentionally.

## Release checks

Every release must show:

- generated ledger matches the migration directory;
- migrator completed successfully in the target database;
- runtime connection attestation reports the expected role, database, and
  fixed service search path;
- migration drift, missing table, unique violation, timeout, and serialization
  conflict tests pass;
- no request handler or runtime binary can apply schema changes.

