# PostgreSQL migration policy

Northstar changes its schema only through the explicit `xmpp-server migrate`
command. The long-running server processes never run migrations, create
tables or alter grants. At startup they verify the migration ledger
read-only and refuse to serve when it differs from the binary.

## One embedded migration set

The repository's `migrations/` directory is the only migration source.
`northstar_postgres::MIGRATOR` embeds it at build time with `sqlx::migrate!`.
The migrator and every verifier therefore use the bytes compiled into the
release binary, not a mutable `migrations/` tree on the host.

Migration files are named `NNNN_description.sql`. A version is an identity,
not a counter: `scripts/check-migration-versions.sh` rejects duplicate
versions, and 0021 is the one deliberate hole.

`deploy/postgres-init/lib/northstar-migration-ledger-manifest.sql` lists the
version, description and SHA-384 checksum of every migration. It is
generated with `scripts/generate-database-migration-ledger.py --write`.
CI runs `scripts/check-database-capability-manifest.py`, which fails if:

- the manifest differs from the directory in version, description, order
  or checksum;
- any version gap other than 0021 appears.

## Applying migrations

`xmpp-server migrate` reads `MIGRATOR_DATABASE_URL_FILE` (or
`MIGRATOR_DATABASE_URL`) and opens a pool of at most two connections. Before
it changes anything, it runs three checks:

1. It pins `search_path` to `public` and runs `attest_migrator_role`. That
   check requires that the login is `northstar_migrator` and that it:
   - owns the database and the `public` schema;
   - is not a superuser;
   - inherits no role and is a member of no role;
   - has a connection limit of 4.

   The loopback-only development override skips this attestation and
   instead proves that the database is on loopback.
2. It takes the `northstar-database-role-policy-v1` advisory lock, which
   serializes migration with privilege reconciliation.
3. On the connection that will apply the migrations, it runs
   `migration_preflight::attest_schema_owner`. This requires that the
   current schema is not a system schema and is directly owned by the
   migration login.

It then runs `MIGRATOR` on that connection. Still under the lock, it runs
the RFC 7622 identity canonicalizers in one transaction
(`northstar_workflows::identity_migration`). The lock is released whether or
not either phase succeeds.

## Startup verification

Every server process connects with its runtime role and runs two
independent checks before it serves.

### `role_attestation::attest_runtime_role`

This check compares `public._sqlx_migrations` with the embedded ledger
manifest. Each ledger row must:

- be successful;
- be unique;
- have a positive version and a non-empty description;
- carry a 96-hex-digit SHA-384 checksum.

The set of (version, description, checksum) rows must equal the manifest
exactly. The same function then attests the capability catalog, the
SECURITY DEFINER ACLs and the runtime relation manifest.

### `schema::verify_schema`

This check reads the ledger in a `REPEATABLE READ READ ONLY` transaction and
compares it with `MIGRATOR`. Startup fails if any migration is pending,
failed, recorded twice, unknown to the binary or has a different checksum.

It also requires:

- every required row in the identity-canonicalizer ledger
  (`jid_identity_migrations`);
- a healthy session capability catalog.

These requirements cover a migrator that crashed between the SQLx phase and
canonicalization: the server still cannot start.

A manually modified database therefore becomes visible before any listener
accepts traffic. The loopback-only development override skips
`attest_runtime_role`, but `verify_schema` always runs.

## Expand, backfill, switch, contract

Changes use four separately reviewed phases:

1. **Expand**: add nullable columns, new tables or compatible indexes. Old
   binaries continue to work.
2. **Backfill**: run a bounded, resumable migrator job. It records progress
   and throttles work so it cannot consume the request pool.
3. **Switch**: deploy code that reads and writes the new representation,
   then verify invariants and outbox and reconciliation counts.
4. **Contract**: only after the compatibility window, remove old columns or
   constraints in a separately approved migration.

Destructive or irreversible changes require all of the following:

- an explicit rollback decision;
- backup and restore evidence;
- operator approval.

A service restart is never treated as a migration rollback.

## Transaction discipline

Repositories own their transactions and choose isolation and locking
explicitly. No shared helper upgrades isolation or hides a long-running
lock.

Every pool starts from `northstar_postgres::pool::options`. A connection
that is returned to the pool while still inside a transaction is closed
instead of reused.

SQLSTATE handling is shared:

- `retryable_contention_sqlstate` treats only three SQLSTATEs as retryable
  scheduling outcomes: serialization failure (`40001`), deadlock (`40P01`)
  and lock not available (`55P03`). `is_retryable_contention` finds one of
  them anywhere in an error chain.
- `is_capacity_exhausted` recognizes the `P0001` rejection raised by a
  capacity trigger.

Constraint and permission failures are never retried; callers surface them.

## Release checks

Every release must show:

- the generated ledger manifest matches the migration directory;
- `xmpp-server migrate` completed in the target database with the attested
  migrator role;
- every server process passed `attest_runtime_role` and `verify_schema`;
- the migration-upgrade suites pass: `scripts/migration-upgrade-wsl.sh` and
  `scripts/migration-0056-db-wsl.sh`;
- the ledger-drift unit tests in `northstar-postgres` pass;
- no production code path outside the `migrate` command calls
  `MIGRATOR.run`.
