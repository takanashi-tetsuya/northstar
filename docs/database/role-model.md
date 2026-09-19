# PostgreSQL role model

Every stateful Northstar service has an independent logical database and a
five-role set. Role names are generated from `catalog/data-ownership.yaml`:

| Role | Login | Responsibility |
| --- | --- | --- |
| `<service>_owner` | `NOLOGIN` | Owns service schema objects; never used by a process. |
| `<service>_migrator` | Yes, short-lived | Applies that service's migrations and grants; no other database access. |
| `<service>_runtime` | Yes | Request-time DML/sequence access only to tables owned by the service. |
| `<service>_ops` | Yes, controlled | Low-cardinality diagnostics and approved operational commands. |
| `<service>_backup` | Yes, controlled | Read-only backup/export; cannot create, alter, or disable triggers. |

`tools/db-bootstrap` reads the ownership catalog and emits deterministic role
and database ACL SQL. The deployment bootstrap job creates the database,
revokes `CONNECT`/`CREATE` from
`PUBLIC`, sets a service-specific schema and fixed `search_path`, and grants
only the generated table/sequence privileges. The runtime URL is never a
superuser URL and is not reused by migrations or backups.

## Object and schema boundaries

Objects are created in the service schema, not in `public`. Security-definer
functions use the service schema explicitly and set a safe search path of
`pg_catalog, pg_temp` plus the immutable service schema where required. They
must not resolve an object from an untrusted `public` path. Cross-service
foreign keys, views, FDW, and shared schemas are prohibited; collaboration is
through authenticated RPC/events and immutable identifiers.

## Attestation and negative tests

At startup the runtime records a non-secret attestation containing
`current_user`, `session_user`, database, schema, and `search_path`. CI then
proves that:

- owner cannot log in;
- runtime cannot `CREATE`, `ALTER`, `DROP`, disable triggers, write another
  service's authority tables, or connect to another service database;
- migrator is the only role that can apply the service ledger;
- backup is read-only and cannot mutate legal-hold, outbox, or audit tables;
- a pre-existing object in `public` cannot shadow a service object.

Credentials are supplied through secret files or an external secret manager;
they are not committed to the repository or printed in attestation logs.
