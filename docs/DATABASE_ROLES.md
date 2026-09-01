# PostgreSQL Role and Privilege Model

Northstar separates database bootstrap, schema migration, application runtime,
and backup into different credentials. The long-lived XMPP process is neither a
PostgreSQL superuser nor the database/schema owner.

## Roles

| Role | Login | Ownership/capability | Cluster attributes | Intended exposure |
| --- | --- | --- | --- | --- |
| `northstar_bootstrap` | yes | Creates/reconciles roles and repairs an existing volume | `SUPERUSER`, `CREATEDB`, `CREATEROLE` | PostgreSQL container and explicit break-glass maintenance only |
| `northstar_migrator` | yes | Owns the application database/schema; migration DDL only | non-superuser, no role memberships, `CONNECTION LIMIT 4` | One-shot migration job |
| `northstar_runtime` | yes | Application DML except account authority; `users` is SELECT-only and all account writes use an exact reviewed command-capability allowlist | non-owner/non-superuser, no CREATE/TEMP, `CONNECTION LIMIT 64` | Long-lived server |
| `northstar_commands` | yes | No relation or sequence access; may only create/claim/finalize bounded XEP-0133 command sessions through eight typed owner-held functions | non-owner/non-superuser, no CREATE/TEMP, `CONNECTION LIMIT 8` | Isolated four-connection command pool in the long-lived server |
| `northstar_backup` | yes | `SELECT` only, no routine execution or sequence allocation | same non-privileged attributes, `CONNECTION LIMIT 2` | Backup job only |

The four workload roles use `NOINHERIT` and are not allowed to participate in
any direct role membership, in either direction. The bootstrap role must never
be mounted into the Northstar, backup, migration, or restore containers.
Role reconciliation also fixes `VALID UNTIL 'infinity'` and executes
`ALTER ROLE ... RESET ALL`; a stale role-level `search_path`, timeout or other
GUC is catalog drift, not an accepted operator override.

`CONNECTION LIMIT` is cluster-wide per PostgreSQL role, not per Northstar
process. `DATABASE_MAX_CONNECTIONS` is therefore capped at 64, and every node
sharing `northstar_runtime` must keep the sum of its pool maxima below 64 with
headroom for rolling overlap. Larger/multi-tenant deployments need separately
attested runtime roles and an explicit capacity plan; raising the role limit to
unbounded is not a supported scaling mechanism.

## Localhost owner-only development mode

The production role table above does not describe the explicit localhost
source-development exception. On an all-loopback reserved-domain instance, the
development flags may reuse one local PostgreSQL owner login for migration,
runtime and command execution. This changes only the number of identities:
migration and startup still verify an owner-only catalog and ACL shape and
reject authorization granted to `PUBLIC` or any third-party principal.

This local workflow does not create the production workload roles and does not
run production grant reconciliation, which would intentionally install
workload ACLs instead of preserving the owner-only development shape. It is not
a deployment shortcut. Production must provision separate migrator, runtime,
command and backup identities and run the exact post-migration grant
reconciliation described below before starting the long-lived server.

## Secret files

The deployment uses five password files and four URL files:

- `postgres_bootstrap_password`
- `northstar_migrator_password`
- `northstar_runtime_password`
- `northstar_command_password`
- `northstar_backup_password`
- `migrator_database_url`
- `runtime_database_url`
- `command_database_url`
- `backup_database_url`

The password files are consumed by fresh-volume initialization. Each URL embeds
only the password of the role named by the URL. A service receives one URL file
for its capability; it never receives all database passwords. Restore is an
explicitly privileged maintenance action and therefore uses the migrator URL,
not the read-only backup URL.

`runtime_database_url` is the ordinary application identity. The independent
`command_database_url` is used only by the XEP-0133 command-session service. It
cannot read or write any table or execute a business mutation capability. The
runtime role can consume a valid claim only after that isolated pool has minted
it, but cannot create, inspect, renew, release, or complete a command session.

## Fresh volumes

The production Compose deployment sets `POSTGRES_USER=northstar_bootstrap` and
mounts the complete `deploy/postgres-init` directory read-only at
`/docker-entrypoint-initdb.d`. On the first initialization only,
`010-northstar-roles.sh`:

1. validates all five file-backed password secrets without printing them;
2. verifies that it is connected as the dedicated bootstrap superuser;
3. creates the migrator, runtime, command, and backup roles with independent
   SCRAM-SHA-256 passwords;
4. removes cluster privileges, inheritance, and role memberships;
5. assigns database and schema ownership to the migrator; and
6. revokes PostgreSQL's permissive `PUBLIC` defaults and installs workload ACLs.

Fresh initialization uses SCRAM-SHA-256 for both host and local database
authentication. Peer authentication is intentionally not used: the container's
operating-system user is `postgres`, while the database bootstrap identity is
`northstar_bootstrap`, so peer name matching would reject initialization.

PostgreSQL init scripts do not rerun when a data volume already exists. Never
assume that changing Compose retrofits an old volume.

## Existing volumes

The upgrade tool defaults to a read-only audit:

```text
bash scripts/reconcile-database-roles.sh --audit
```

For an old deployment whose only superuser is `xmpp`, perform the first explicit
apply while connecting as that existing role:

```text
bash scripts/reconcile-database-roles.sh --apply \
  --connect-as xmpp \
  --connection-password-file /root/northstar-legacy/postgres_password \
  --bootstrap-password-file /etc/northstar/secrets/postgres_bootstrap_password
```

The connection password is the **old** `xmpp` credential; the bootstrap password
is the **new** `northstar_bootstrap` credential. They are intentionally separate
and are never copied from one identity to the other. That pass creates
`northstar_bootstrap`, reconciles workload roles, transfers
application relations, routines and explicit types/domains (including
standalone composite types) in schema `public`
to the migrator, and repairs grants. It
orders relation ownership changes so tables move before their `OWNED BY`
sequences, avoiding PostgreSQL's same-owner constraint. It does **not** disable
the old login. Update deployment URLs, stop processes using the legacy role,
verify the new bootstrap credential through a protected administrative path,
reconnect as `northstar_bootstrap`, and only then run:

```text
bash scripts/reconcile-database-roles.sh --apply --demote-legacy-xmpp
```

The demotion is fail-closed: it refuses to demote the current role or the last
remaining login superuser. It makes the legacy role `NOLOGIN` and removes its
cluster privileges, removes its role memberships, and erases its stored password
verifier. The tool never drops a role or deletes application data.

Connection endpoints are supplied separately (`--host`, `--port`, and
`--connect-as`); passwords are accepted only through named secret files. The
tool rejects symlinks, short values, control characters, and multi-line secret
contents, disables shell tracing before reading them, and never places a secret
in process arguments. Audit mode reads only the connection credential; apply
mode additionally reads the five destination-role password files.

## Every migration

Migrations create new objects, so the one-shot migrator must finish with:

```text
bash scripts/reconcile-database-grants.sh \
  --database-url-file /run/secrets/migrator_database_url
```

When a numbered migration is added or its pre-release bytes change, regenerate
the repository ledger before building either the application or operations
images:

```text
python3 scripts/generate-database-migration-ledger.py --write
python3 scripts/generate-database-migration-ledger.py --check
```

The independent database-capability checker recomputes every digest, so hand
editing the generated SQL cannot make a modified migration pass CI.

This script has no bootstrap secret. It refuses to continue unless:

- the current connection is the migrator (or an explicit bootstrap session);
- all workload roles have the required non-privileged attributes;
- no workload role membership exists;
- connection limits are migrator=4, runtime=64, command=8 and backup=2;
- the migrator owns the database, schema, application relations, routines, and
  non-extension explicit types/domains; and
- it is connected to database `xmpp`.

Grant application is ledger-gated. The exact manifest for this release contains
123 migrations from `0001` through `0124`; `0021` is the sole intentional gap.
Every listed row is identified by version, SQLx description and SHA-384 checksum.
`bootstrap` accepts only a genuinely empty
database with no sqlx ledger or application object. `auto` accepts either that
shape, a stopped migration-0113 installation (the `prepare` phase), or a fully
migrated installation. Both non-empty shapes must match the checked-in manifest
by exact version, SQLx description and SHA-384 checksum; the intentional `0021`
gap is part of that set. Missing, unknown, failed, duplicated or modified rows,
one-sided 0114/0115, and post-0115-without-boundary ledgers fail closed. `exact`
requires the complete checked-in `0001`-`0124` manifest, not merely the
`0114`/`0115` transition boundary. Bootstrap and prepare
leave runtime, command, and backup with **zero** database, schema, object, type,
or routine capability. Only post-migration exact reconciliation installs the
current-object workload grants.

Exact reconciliation atomically revokes `PUBLIC`, refreshes current object
grants, and makes future objects owner-only. Every revocation that can remove a grant
option uses `CASCADE`, so a retired role's downstream grants cannot make
reconciliation abort in `RESTRICT` mode. Relation, column, sequence and type
ACLs are reduced to the complete owner/runtime/backup identity, privilege,
grantor and grant-option sets. Explicit type/domain owner ACL rows are also
normalized before `USAGE` is rebuilt. Global and schema-local default ACLs for
tables, sequences, functions, types and PostgreSQL 17 schemas are emptied for every non-owner
grantee—including unknown roles, delegated chains, workload roles and
`PUBLIC`. PostgreSQL combines those two scopes additively, so checking only the
schema row is insufficient. No future workload grant is installed: after a
migration, exact reconciliation grants each reviewed current object. Default
ACL rows owned by any identity other than the migrator are
rejected: the ordinary non-superuser reconciler cannot safely rewrite another
role's defaults, so an operator must clear that drift through explicit
bootstrap maintenance before ordinary reconciliation.

PostgreSQL may remove a `pg_default_acl` row when an `ALTER DEFAULT
PRIVILEGES` operation restores its built-in value. That absence is unsafe for
functions and types because the built-ins grant `PUBLIC` EXECUTE/USAGE. Exact
reconciliation therefore materializes owner-only global overrides for both
object kinds, and audit/startup checks require those rows to remain present.

Routine execution is rebuilt from an empty set. The owner `EXECUTE` row is
explicitly normalized as well; relying on implicit ownership would let a prior
owner `REVOKE` produce a different catalog shape with the same effective power.
The version-controlled, full-signature capability manifest assigns every
`SECURITY DEFINER` routine to exactly one of `runtime`, `command`, or `private`;
there is no name-only or numeric-count allowlist. The command role receives only
its session-lifecycle capabilities and no relation, column, sequence, or other
routine authority. Private definers remain owner-only. Backup and `PUBLIC`
receive no definer execution. Reconciliation removes every explicit stale
grantee and grant option before rebuilding the exact owner-plus-workload ACL.
Future functions receive no default runtime or `PUBLIC` `EXECUTE` and become available only
after their complete normalized signature enters the reviewed manifest. The
cluster MUC handoff-history table is explicitly
reduced to runtime `SELECT`, so only the owner-executed transfer function can
append a handoff. A migration that accidentally creates an object under another
owner causes the step to fail instead of silently widening the boundary.
Capability migrations also revoke default `PUBLIC EXECUTE` for their actual,
identifier-quoted installation schema before creating routines, and harden each
new definer inside the same SQLx transaction. This closes the observable
migration-before-grant-job interval while retaining isolated-schema tests.

Compose runs this as the separate one-shot `database-grants` service after
`migrate` and before `xmpp`. Its image contains the migration tree solely as a
release-generation input, ensuring a migration change also changes the ACL-job
image; it does not execute those files. The long-lived application image does
not contain `psql` or the grant wrapper.

Restore reuses the same checked-in boundary assertions and grant body. Dump
validation runs in a private temporary PostgreSQL instance rather than asking
the `NOCREATEDB` migrator to create a database in the target cluster. At
cutover, `ALLOW_CONNECTIONS=false` prevents new peers; restore refuses to
proceed while any existing peer remains instead of requiring
`pg_signal_backend`. The dump, migrator-owned `public` schema, current-object
ACLs, and default privileges commit in one replacement transaction before the
database is reopened. Operators must therefore stop Northstar and all other
database clients before invoking restore.

Online backup independently compares every SQLx version, description and
SHA-384 checksum with the same checked-in migration manifest before `pg_dump`.
It keeps both the backup/restore maintenance fence and the migration/ACL policy
fence in one persistent database session through capture, so a migration or
grant reconciliation cannot race the ledger check. Missing, unknown, failed,
duplicated or modified ledger rows refuse the backup before any canonical
artifact is published.

Restore likewise requires the dump ledger to match its image manifest before
the replacement transaction can commit. Historical backups must first be
restored by their matching release; only then may the normal one-shot migrator
and exact grant job advance the recovered database.

## Release gates

`scripts/check-database-role-boundaries.sh` checks the Compose service/secret
mapping, required role attributes, fresh-volume mount, PUBLIC revocations, and
the runtime/backup/migrator secret separation without starting PostgreSQL. Run
it with `bash scripts/check-database-role-boundaries.sh` in CI and during release
preflight.

The dedicated `database-role-boundary` GitHub Actions job runs
`scripts/database-role-boundary-db-ci.sh` against a disposable PostgreSQL 17
service. The script refuses non-CI and non-loopback targets, refuses pre-existing
Northstar roles or database `xmpp`, marks the database it creates, and verifies
that marker before cleanup. It then:

1. creates a legacy `xmpp` login superuser, applies the real migration chain
   through 0113 with sqlx-compatible checksums, and adds separately-owned probes;
2. performs the explicit stopped `prepare` reconciliation through that old role
   and proves all workload capabilities remain absent;
3. reconnects as `northstar_bootstrap`, exercises guarded legacy-role demotion,
   and separately proves empty bootstrap plus partial/tampered-ledger rejection;
   demotion;
4. runs Northstar's real `migrate` command as `northstar_migrator`, comparing
   the successful sqlx ledger with all 123 checked-in migrations from `0001`
   through `0124` (including the intentional numbering gap at `0021`);
5. reapplies the shared `exact` post-migration ACL policy;
6. removes the function/type override rows and injects missing, unknown, failed,
   and checksum/description-tampered ledger states to prove every audit fails
   closed; and
7. performs live positive and negative privilege probes, including PostgreSQL
   17 schema default privileges.

Those probes assert that:

- runtime cannot create a table, alter an owner, change a schema, disable a
  trigger, create temporary objects, or use `SET ROLE` to reach another
  Northstar identity;
- runtime cannot directly update/delete immutable audit, legal-hold and cluster
  MUC histories; setting a cleanup GUC does not grant authority;
- every reviewed definer's full normalized signature is present in the
  independent manifest, migrator-owned, and fixed to the
  catalog/application-schema/temporary-schema path; its direct ACL contains
  exactly the owner and its one authorized workload, with no grant option and
  with the owner as grantor;
- startup repeats that catalog-wide comparison and also attests all four
  workload-role attributes/memberships, database/schema and application-object
  ownership, relation/column/sequence/type/default ACL grantee sets, global
  runtime dangerous privileges, and backup read-only completeness. It fails
  for `PUBLIC`, backup,
  command/runtime crossover, unknown or retired grantees, and unmanifested
  overloaded helpers; session trigger health additionally checks exact table,
  trigger name, function OID/signature, event bitmask, enabled state, absence of
  a `WHEN` predicate, `UPDATE OF` column numbers/order, argument count/bytes,
  constraint/deferrability flags, parent-trigger OID, trigger-function ABI,
  fixed path, required `SECURITY INVOKER` mode, and absence of extra triggers;
- runtime can select `users` but cannot insert, update, delete, truncate,
  reference, attach triggers, or retain column-level write grants; negative
  probes cover direct DML, forged/cross-target/expired/replayed claims and old
  generations, while positive probes exercise typed commands and a concurrent
  single-winner claim;
- neither runtime nor the command role can read or write the command-session or
  keyed-authority tables; the command role has no application relation access;
- backup can read all required tables but cannot write, call application
  routines, advance sequences, or create temporary objects;
- migrator can apply the real migration chain but remains non-superuser;
- stale grants with dependent downstream grants are removed with `CASCADE`,
  missing owner ACLs are reconstructed, and newly-created probe objects inherit
  only the canonical defaults; and
- the complete migration chain succeeds in a real schema containing whitespace
  and an embedded quote while a populated `public` installation acts as a
  decoy, proving identifier-safe isolated-schema behavior rather than merely
  testing `format('%I', ...)`.

Passing this job proves separation from superuser/owner/DDL powers, exact
immutable-history/capability manifests, and a table-level account-authority
boundary. It does not claim subsystem-specific least privilege for every other
mutable application table.

## Deliberate residual limitations

This boundary removes superuser, DDL, trigger-disable, ownership, role
escalation, and direct account-authority DML from the long-lived application.
Migration `0108` owns registration, bootstrap administration, login-verifier
upgrade, password rotation, administrator lifecycle, account deletion, roster
versioning and recovery-generation writes behind fixed typed commands. Those
commands validate exact actor/account generations or bearer hashes where the
transport provides them, enforce self/last-administrator rules, revoke stale
sessions and FAST tokens, and write audit records in the same transaction.

The boundary does **not** yet give every other application subsystem a
separate database role: the runtime role still has broad DML on mutable
non-`users` tables because current protocol modules share one connection pool.
Ordinary invoker routines are available to runtime except for private command
helpers, all future functions default denied, and the runtime definer allowlist
is the exact full-signature `runtime` partition of the canonical manifest.

Credential rotation, disablement and deletion commit the new
`auth_generation`, FAST/API revocation, durable SM revocation and audit record
before the XEP-0133 result is completed. Local live routes are canceled
immediately. In Experimental multi-node mode, Redis normally propagates the
same generation fence immediately; if Redis control delivery fails while
PostgreSQL remains healthy, the next 30-second cluster maintenance sweep closes
generation-stale sockets. A simultaneous PostgreSQL outage can extend that
window, so this design is not advertised as a consensus-grade synchronous
cross-node revocation acknowledgement.

The ownership transfer covers non-extension relations, routines and explicit
types/domains, including standalone composite types, in schema `public`.
Deployments with custom application schemas or
additional extensions must audit and reconcile those objects explicitly. The bootstrap
role also remains a true superuser by design; isolation depends on keeping its
secret inside the PostgreSQL/bootstrap trust boundary and using it only for
explicit maintenance.

The `0001`-`0124` migration SQL and checksums used by both the one-shot migrator
and normal startup verifier are embedded in the release binary. The checked-in
migration directory remains an auditable source/build input, but replacing
files beside an installed binary cannot redefine the schema that binary accepts.
