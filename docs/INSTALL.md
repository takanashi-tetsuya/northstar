# Install Northstar 0.2.0

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

For a local evaluation, install PostgreSQL 15 or newer, create a local database
and owner, and copy `.env.development.example` to `.env`. Replace both database
URL placeholders with that local database. Configure a localhost TLS certificate
and matching private key through `TLS_CERT_PATH` and `TLS_KEY_PATH`. Never use
the development profile or its ephemeral secrets for a public deployment.
Run `xmpp-server migrate` with the migrator configuration, then `xmpp-server` in
the foreground. On Linux prefix those commands with `./`; on Windows use
`.\xmpp-server.exe`. The local Web client is at `http://127.0.0.1:8080`.

For production, configure independent PostgreSQL roles, mounted secrets and a
publicly trusted TLS certificate using `.env.example` and the matching version
of the [production operations guide](https://github.com/takanashi-tetsuya/northstar/blob/v0.2.0/docs/PRODUCTION_OPERATIONS.md).
Migration is an explicit stopped-writer operation where required by that guide;
starting the application never silently upgrades the database.

Docker deployments use the three immutable image references in `IMAGE_DIGESTS`
with [the release Compose override](https://github.com/takanashi-tetsuya/northstar/blob/v0.2.0/deploy/docker-compose.release.yml)
and the matching repository deployment configuration. Verify image provenance
and replace the convenient version tags with those exact digest references.
Application, backup and database-grants images have separate responsibilities;
the application container does not receive migration or bootstrap credentials.
