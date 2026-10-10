# Install Northstar 0.2.0

Packages become available on [GitHub Releases](https://github.com/takanashi-tetsuya/northstar/releases)
when the maintainer publishes the Release.

Use the complete archive for your platform: `northstar-0.2.0-linux-amd64.tar.gz`
or `northstar-0.2.0-windows-amd64.zip`. Both include the Web client, Swagger UI,
configuration examples and license notices. The raw executable requires these
same files beside it. Run Northstar with the extracted directory as its working
directory. Windows x64 is a development/evaluation target; Linux x64 and the
Linux AMD64 Docker images are the production baseline.

Download `SHA256SUMS` with the archive and verify its matching SHA-256 entry
before extracting. With GitHub CLI installed, verify build provenance using
`gh attestation verify <archive> --repo takanashi-tetsuya/northstar`. The included
`PACKAGE-MANIFEST.json` identifies the source commit, version, target and every
distributed file's checksum. It complements the signed build provenance.
`RELEASE-EVIDENCE.json` records the exact build run and package/container
verification; `SHA256SUMS` covers that evidence alongside the downloads.

On Linux, extract into a new directory and run `./xmpp-server --version`. On
Windows, extract the ZIP and run `.\xmpp-server.exe --version` in PowerShell.
The output must be `xmpp-server 0.2.0`. Linux packages target x86-64 GNU/Linux
with glibc 2.35 or newer. A native Windows installation requires Windows x64;
the release workflow verifies the archive on Windows Server 2022.

For a local evaluation, install PostgreSQL 15 or newer and follow the explicit
[local database bootstrap](DATABASE_ROLES.md#localhost-owner-only-development-mode).
The dedicated local login must directly own both the database and `public`
schema: PostgreSQL 15+ normally gives `public` to `pg_database_owner`, so creating
a database with `OWNER` alone does not satisfy the migration contract.
Copy `.env.development.example` to `.env` and replace both database URL
placeholders with that local owner/database. Configure a localhost TLS certificate
and matching private key through `TLS_CERT_PATH` and `TLS_KEY_PATH`. Never use
the development profile or its ephemeral secrets for a public deployment.
Run `xmpp-server migrate` with the migrator configuration, then `xmpp-server` in
the foreground. On Linux prefix those commands with `./`; on Windows use
`.\xmpp-server.exe`. The local Web client is at `http://127.0.0.1:8080`.

The foreground server and migration command look for an optional `.env` in the
working directory, then its parents. Existing process environment variables take
precedence. Quote values containing spaces, such as
`SERVER_NAME="Northstar Development"`. A malformed or unreadable file stops
startup with a `.env` configuration error before database configuration is used;
diagnostics omit setting values. A missing file is allowed when configuration
comes from the process environment. Set `NORTHSTAR_DISABLE_DOTENV=true` in that
environment to disable this lookup. The isolated maintenance process never
loads `.env`.

For production, configure independent PostgreSQL roles, mounted secrets and a
publicly trusted TLS certificate using `.env.example` and the matching version
of the [production operations guide](https://github.com/takanashi-tetsuya/northstar/blob/v0.2.0/docs/PRODUCTION_OPERATIONS.md).
Migration is an explicit stopped-writer operation where required by that guide;
starting the application never silently upgrades the database.

## Docker

First obtain the matching repository checkout. The Compose files and deployment
scripts are in the repository, not in the native archives:

```sh
git clone --branch v0.2.0 --depth 1 \
  https://github.com/takanashi-tetsuya/northstar.git
cd northstar
```

Configure the deployment using `.env.example` and the production operations
guide above. Run Docker Compose from this checkout, with both `docker-compose.yml`
and `deploy/docker-compose.release.yml`.

Docker deployments use the three immutable image references in `IMAGE_DIGESTS`
with [the release Compose override](https://github.com/takanashi-tetsuya/northstar/blob/v0.2.0/deploy/docker-compose.release.yml)
and this checkout's deployment configuration. Verify image provenance
and replace the convenient version tags with those exact digest references.
Application, backup and database-grants images have separate responsibilities;
the application container does not receive migration or bootstrap credentials.
