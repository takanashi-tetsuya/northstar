**English** | [繁體中文](README.zh-TW.md)

# Northstar XMPP Server

Northstar is a standards-oriented XMPP server written in Rust for Linux and
PostgreSQL. It provides XMPP over TCP, Direct TLS, WebSocket and optional BOSH,
along with federation, group chat, OMEMO-compatible services, a browser client,
REST administration, anti-abuse controls, logging and metrics.

The current release is `0.2.0` and remains pre-1.0. It has not received an
independent security audit. Review the [XEP support matrix](XEP_MATRIX.md) and
[known limitations](docs/KNOWN_ISSUES.md) before public deployment.

See the [documentation index](docs/README.md), [security policy](SECURITY.md),
[production operations guide](docs/PRODUCTION_OPERATIONS.md) and
[contribution guide](CONTRIBUTING.md).

## How to use

### Release packages

Northstar `0.2.0` is distributed through
[GitHub Releases](https://github.com/takanashi-tetsuya/northstar/releases) with
the following files:

| Asset | Intended use |
|---|---|
| `northstar-0.2.0-linux-amd64.tar.gz` | Complete Linux AMD64 distribution with `xmpp-server`, the Web client, Swagger UI, `.env.example`, and license notices |
| `northstar-0.2.0-linux-amd64` | Raw Linux AMD64 ELF binary |
| `northstar-0.2.0-windows-amd64.zip` | Complete Windows AMD64 development/evaluation distribution with `xmpp-server.exe` and the same runtime assets and notices |
| `northstar-0.2.0-windows-amd64.exe` | Raw Windows AMD64 executable for development/evaluation |
| `SHA256SUMS` | SHA-256 checksums for the four packages and `IMAGE_DIGESTS` |
| `IMAGE_DIGESTS` | Exact `name@sha256:digest` references produced for the three GHCR images by a successful tag run |

`AMD64` means the Rust `x86_64` targets. Linux AMD64 is the production
baseline; the Windows build is for development and evaluation, not a supported
production deployment. The raw binaries do not contain the runtime Web,
Swagger UI, configuration, or license files. Use the complete archive, or keep
the raw binary beside the matching-tag archive contents and run it from that
directory.

Download all required files, verify the matching entries in `SHA256SUMS`, and
verify the GitHub build provenance before execution. On Linux, for example:

```sh
mkdir northstar-0.2.0
sha256sum --check SHA256SUMS
tar -xzf northstar-0.2.0-linux-amd64.tar.gz -C northstar-0.2.0
cd northstar-0.2.0
./xmpp-server --version
```

On Windows, compare `(Get-FileHash -Algorithm SHA256 <file>).Hash` with the
corresponding `SHA256SUMS` entry before extracting the ZIP. A checksum obtained
from the same Release detects corruption; provenance verification is the
separate source/build-identity check.

### Requirements

- Linux AMD64 for the supported production baseline. WSL2 and the Windows
  AMD64 package are supported for development and evaluation.
- Rust `1.97.1` for release-equivalent source builds (pinned by
  `rust-toolchain.toml`; `Cargo.toml` declares the minimum supported version).
- PostgreSQL 15 or newer (the Compose deployment uses PostgreSQL 17).
- A DNS name and a publicly trusted certificate for Internet-facing use.
- Optional: Docker Compose, Caddy, Prometheus/Grafana, and Redis for the experimental multi-node path.


### Local development

This example starts a loopback-only development instance. Create a local
PostgreSQL database and role, then update both database URLs in the copied file:

```sh
cp .env.development.example .env
# Edit DATABASE_URL and MIGRATOR_DATABASE_URL.
bash scripts/generate-development-certificate.sh
cargo run --release --locked -- migrate
cargo run --release --locked
```

The development profile uses disposable local keys and a self-signed certificate.
It must not be exposed publicly or reused for production. For production, start
from [.env.example](.env.example) and follow
[Production operations](docs/PRODUCTION_OPERATIONS.md), including separate
database roles, protected secret files and a publicly trusted certificate.

### Default ports

| Port | Purpose | Default exposure |
| ---: | --- | --- |
| `5222/tcp` | XMPP client STARTTLS | Public |
| `5223/tcp` | XMPP client Direct TLS | Public |
| `5269/tcp` | XMPP federation STARTTLS | Public when federation is enabled |
| `5270/tcp` | XMPP federation Direct TLS | Public when federation is enabled |
| `5347/tcp` | External components | Disabled; loopback by default |
| `8080/tcp` | REST, WebSocket, health and web UI | Loopback behind a TLS proxy |
| `9091/tcp` | Prometheus metrics | Loopback/private only |

Do not expose PostgreSQL, Redis, Prometheus or Grafana directly to the Internet.


## What privacy means here

OMEMO encryption is performed by compatible clients. For a correctly encrypted message, Northstar routes and archives the encrypted XMPP envelope and does not possess the clients' OMEMO private keys. The default `REQUIRE_ENCRYPTED_ARCHIVE=true` policy rejects plaintext bodies from personal and room archives and strips accidental plaintext siblings from OMEMO stanzas before persistence.

This is not an absolute “zero-knowledge” guarantee. The server necessarily sees routing metadata, account and room membership data, message timing and size, any plaintext that a client intentionally sends, and evidence a user deliberately attaches to an abuse report. Administrators with database or host access can inspect that server-visible information. End-to-end privacy therefore depends on the client, its device-key verification, endpoint security, and correct TLS deployment as well as Northstar.


## Features

- XMPP client connections over mandatory STARTTLS, Direct TLS, WebSocket and
  optional HTTPS-proxied BOSH.
- SCRAM-SHA-256/PLUS, optional compatibility mechanisms, SASL2, FAST, Bind2,
  roster, presence, privacy lists, blocking, Carbons and Stream Management.
- Direct and group messaging with offline delivery, MAM, vCard, Private XML and
  HTTP Upload.
- MUC and MIX with invitations, moderation, access controls and encrypted
  history support.
- PEP and PubSub capabilities used by OMEMO device lists, bundles, avatars and
  general publish/subscribe clients.
- Certificate-authenticated federation, optional DANE/CRL validation and
  external components.
- REST registration, administration, reports and appeals, invitation tokens,
  adaptive rate limits, proof of work, logs and Prometheus metrics.
- Optional Redis routing and S3-compatible shared upload storage. Multi-process
  deployment remains experimental; a single Northstar process is the supported
  production baseline.

See [XEP_MATRIX.md](XEP_MATRIX.md) for the exact protocol support boundary.



## Configuration

Configuration is supplied through environment variables or `.env`. The
canonical, commented reference is [.env.example](.env.example).

- **Identity and listeners:** `XMPP_DOMAIN`, `PUBLIC_URL`, client, federation,
  HTTP, component and metrics bind addresses.
- **TLS:** certificate and private-key paths, plus optional federation and client
  trust roots or CRLs.
- **Database:** separate migrator, runtime and administrator-command PostgreSQL
  identities are required in production; see [Database roles](docs/DATABASE_ROLES.md).
- **Registration:** `OPEN_REGISTRATION` controls public registration;
  `INVITATION_REQUIRED` decides whether every registration needs an invitation.
- **Authentication:** configure SCRAM cost and protected FAST/dummy-SCRAM secret
  files. Benchmark SCRAM settings on the deployment host.
- **Storage and capacity:** local or S3-compatible uploads, upload/archive/offline
  limits, connection limits and Stream Management recovery bounds.
- **Federation and components:** federation policy, DANE mode, Dialback, domain
  allow/deny lists and the protected external-component configuration file.
- **Browser transports:** public HTTPS URL, WebSocket origins and optional BOSH
  limits.
- **Abuse controls:** message/registration limits, proof-of-work calibration and
  `ABUSE_STATE_HMAC_KEY_FILE` for persistent production state.
- **Observability:** log format/rotation and a private metrics listener. A
  non-loopback metrics bind requires a bearer-token file.
- **Clustering:** setting `REDIS_URL(_FILE)` enables the experimental multi-process
  path; single-host deployments should leave it unset.

Long-lived credentials should use protected `*_FILE` settings. Never commit
`.env`, certificates, private keys, generated secrets, logs, uploads or backups.

## Client setup and OMEMO

Use a compatible client such as Gajim or Conversations and sign in as
`user@your-domain`. Port `5222` uses STARTTLS; use `5223` only when the
client explicitly supports XMPP Direct TLS. The certificate must be valid for
the XMPP domain.

Northstar provides the PEP, discovery and non-anonymous room information needed
by OMEMO clients. Device trust and key verification remain client decisions. If
a contact's trust list is empty, confirm that both clients published their
device bundles and refresh discovery before clearing client caches.

The browser client stores OMEMO private state in the browser profile. Removing
that profile may permanently lose keys and access to old ciphertext; the server
does not escrow recovery keys. Its encrypted device-transfer package is local,
one-time and passphrase-protected, is never uploaded, and resets contact trust
when imported. See [the device-transfer guide](docs/OMEMO_DEVICE_TRANSFER.md).

## Registration, anti-abuse and reports

Registration is available through XEP-0077 and `POST /api/v1/register` when
enabled. Depending on policy, the request may require an invitation and a
proof-of-work challenge from `POST /api/v1/anti-abuse/challenge`.

Repeated registration, messaging, reporting or appeal activity raises the
required work and may add enforced waits. Restrictions fall gradually after a
cooldown, and configured limits prevent unbounded client computation. Shared-IP
handling is designed to reduce collateral impact on users behind the same NAT.

Users can select archived messages as report evidence. Submitting a report
deliberately shares that material with the server and authorized moderators.
OMEMO plaintext supplied by a reporter cannot be independently verified by the
server. Appeals have stricter limits than initial reports.

## REST and operations

The HTTP service provides account management, history, reports and appeals,
uploads, XMPP WebSocket/BOSH, health endpoints and administrator functions. The
machine-readable API is [docs/openapi.yaml](docs/openapi.yaml) and is also served
at `/api/openapi.yaml`; a read-only Swagger UI is available at `/api/docs`.

Long-running administrative changes support `Idempotency-Key` and return an
operation URL that can be polled for completion.

- `/healthz` reports that the HTTP process is alive.
- `/readyz` checks the database and critical workers and should remain private
  to the deployment platform.
- `/metrics` is served only by the separate private metrics listener.

See [Production operations](docs/PRODUCTION_OPERATIONS.md) for monitoring,
upgrades and recovery, and [Backup security](docs/BACKUP_SECURITY.md) before
creating or restoring production backups.

## Docker images and Compose deployment

Northstar builds three non-root images. Docker Compose is the recommended
deployment method and manages service ordering, secrets, private networks and
persistent volumes.

| Dockerfile | Release image | Compose services | Purpose |
|---|---|---|---|
| `Dockerfile` | `ghcr.io/takanashi-tetsuya/northstar:0.2.0` | `migrate`, `xmpp` | Database migrations and the XMPP/HTTP server |
| `deploy/database-grants.Dockerfile` | `ghcr.io/takanashi-tetsuya/northstar-database-grants:0.2.0` | `database-grants` | Post-migration PostgreSQL grant reconciliation |
| `deploy/backup.Dockerfile` | `ghcr.io/takanashi-tetsuya/northstar-backup:0.2.0` | `backup`, `restore` | Signed/encrypted backup, verification and stopped restore |

The complete production procedure is in
[Production operations](docs/PRODUCTION_OPERATIONS.md). Database capabilities
are documented in [Database roles](docs/DATABASE_ROLES.md), and backup/restore
trust boundaries are in [Backup security](docs/BACKUP_SECURITY.md).

### Requirements

Use a current Docker Engine with Linux containers, BuildKit and Docker Compose
`2.24.4` or newer. The release-image override uses Compose's `!reset` merge tag.
Docker Desktop with WSL2 is suitable for Windows development, while production
deployments should use native Linux.

Run from the repository root and verify the active engine:

```sh
docker version
docker compose version
docker info --format '{{.OSType}}/{{.Architecture}}'
```

The last command must identify Linux and the intended target architecture.

### Configure and build

Create the ignored configuration file:

```sh
cp .env.example .env
```

For a release build, set the real domain and certificate paths, then set
`NORTHSTAR_VERSION` to the release version and `NORTHSTAR_VCS_REF` to the exact
full commit. `unknown` is development-only.

```dotenv
NORTHSTAR_VERSION=0.2.0
NORTHSTAR_VCS_REF=<full-release-commit>
XMPP_DOMAIN=chat.example.org
TLS_CERT_HOST_PATH=/etc/northstar/tls/fullchain.pem
TLS_KEY_HOST_PATH=/etc/northstar/tls/privkey.pem
```

Validate the required profiles and build all Northstar images:

```sh
docker compose config --quiet
docker compose -f docker-compose.yml -f deploy/docker-compose.bootstrap.yml config --quiet
docker compose --profile monitoring config --quiet
docker compose --profile backup --profile restore config --quiet

docker compose build --pull migrate database-grants xmpp
docker compose --profile backup --profile restore build --pull backup restore
```

The first Rust release build can take several minutes; later builds normally use
BuildKit cache. `NORTHSTAR_VERSION` and `NORTHSTAR_VCS_REF` populate OCI labels.

To create explicitly tagged single-platform images outside Compose:

```sh
northstar_version=0.2.0
northstar_revision="$(git rev-parse HEAD)"

docker build --pull \
  --build-arg NORTHSTAR_VERSION="$northstar_version" \
  --build-arg VCS_REF="$northstar_revision" \
  --tag "northstar:$northstar_version" .

docker build --pull --file deploy/database-grants.Dockerfile \
  --build-arg NORTHSTAR_VERSION="$northstar_version" \
  --build-arg VCS_REF="$northstar_revision" \
  --tag "northstar-database-grants:$northstar_version" .

docker build --pull --file deploy/backup.Dockerfile \
  --build-arg NORTHSTAR_VERSION="$northstar_version" \
  --build-arg VCS_REF="$northstar_revision" \
  --tag "northstar-backup:$northstar_version" .
```

Manual tags are for registry publication or offline transfer. The supplied base
Compose file uses `build:` and does not automatically select those tags.

### Use release images

The three Linux AMD64 release images listed above have immutable references in
the release's `IMAGE_DIGESTS` file. Copy `.env.example` to `.env`, configure the
deployment, and set all three image variables to the matching
`name@sha256:digest` values. The `:0.2.0` tags select the release conveniently,
but a digest is the production identity.

```dotenv
NORTHSTAR_SERVER_IMAGE_REF=ghcr.io/takanashi-tetsuya/northstar@sha256:<digest>
NORTHSTAR_DATABASE_GRANTS_IMAGE_REF=ghcr.io/takanashi-tetsuya/northstar-database-grants@sha256:<digest>
NORTHSTAR_BACKUP_IMAGE_REF=ghcr.io/takanashi-tetsuya/northstar-backup@sha256:<digest>
```

Render the merged configuration before pulling. Enable the backup and restore
profiles when verifying all three images:

```sh
docker compose -f docker-compose.yml -f deploy/docker-compose.release.yml \
  --profile backup --profile restore config --quiet
docker compose -f docker-compose.yml -f deploy/docker-compose.release.yml \
  --profile backup --profile restore pull
docker compose -f docker-compose.yml -f deploy/docker-compose.release.yml up -d
```

The override removes the local `build:` definitions; it must never silently
fall back to the checkout. Confirm the rendered `image:` values match the three
reviewed digests before exposing traffic.

### First production start

Install the real TLS certificate/key and create the protected external secret
tree. The generator assigns mode-`0600` files to their numeric container
consumers; do not copy secrets into the source checkout or relax their modes.

```sh
sudo install -d -o root -g root -m 0700 /etc/northstar
sudo env NORTHSTAR_SECRET_DIR=/etc/northstar/secrets \
  sh scripts/create-production-secrets.sh
sudo sh scripts/release-preflight.sh --production
```

Use the bootstrap overlay only for the first administrator:

```sh
sudo docker compose \
  -f docker-compose.yml \
  -f deploy/docker-compose.bootstrap.yml \
  up -d postgres migrate database-grants xmpp caddy

sudo docker compose ps --all
sudo docker compose logs --tail=200 migrate database-grants xmpp caddy
curl -fsS http://127.0.0.1:8080/healthz
curl -fsS http://127.0.0.1:8080/readyz
```

Immediately change the bootstrap administrator password, recreate `xmpp` using
the base Compose file, and securely remove the host
`bootstrap_admin_password` file:

```sh
sudo docker compose up -d --force-recreate xmpp caddy
```

Existing databases created with an older PostgreSQL superuser layout require the
stopped role-migration procedure in
[Production operations](docs/PRODUCTION_OPERATIONS.md); replacing only the
Compose file is not an upgrade.

### Use the images

Common commands:

```sh
sudo docker compose ps --all
sudo docker compose logs --follow --tail=200 xmpp caddy
sudo docker compose restart xmpp
sudo docker compose --profile monitoring up -d
```

`restart` does not apply a changed image, environment, mount or secret. Use
`docker compose up -d --force-recreate xmpp` after configuration changes.

Do not improvise the migration and database-grant order during upgrades. Follow
the versioned procedure in
[Production operations](docs/PRODUCTION_OPERATIONS.md).

Create a production backup with the configured backup image:

```sh
sudo install -d -m 0700 -o 10001 -g 10001 ./backups
sudo docker compose --profile backup run --rm backup
```

Verification and restore require the controlled procedure in
[Backup security](docs/BACKUP_SECURITY.md). Restore is destructive; do not
improvise a `docker run` command.

### Important parameters

The canonical, commented parameter reference is [.env.example](.env.example).
The most commonly changed Compose inputs are:

| Area | Parameters |
|---|---|
| Release | `NORTHSTAR_VERSION`, `NORTHSTAR_VCS_REF` |
| Identity/TLS | `XMPP_DOMAIN`, `SERVER_NAME`, `TLS_CERT_HOST_PATH`, `TLS_KEY_HOST_PATH` |
| Registration | `OPEN_REGISTRATION`, `INVITATION_REQUIRED`, `REGISTRATION_RATE_PER_HOUR` |
| Authentication | `SCRAM_ITERATIONS`, `SCRAM_SHA1_ENABLED`, FAST secret-file selectors |
| Capacity | `MAX_CLIENT_CONNECTIONS`, `MAX_CONNECTIONS_PER_IP`, `MAX_SESSIONS_PER_ACCOUNT` |
| Storage | `UPLOAD_STORAGE_BACKEND`, upload limits, S3 file-backed credentials |
| Federation | `FEDERATION_ENABLED`, allow/deny lists, DANE and trust/CRL paths |
| Logging | `LOG_FORMAT`, `LOG_ROTATION`, `LOG_RETENTION_FILES`, `RUST_LOG` |

`OPEN_REGISTRATION=false` closes public REST and XEP-0077 registration.
`INVITATION_REQUIRED=true` requires a valid invitation while retaining PoW and
rate limits. Long-lived credentials belong in protected `*_FILE` inputs, not
inline in `.env`. Compose passes only explicitly mapped variables; verify any
custom override with `docker compose config --quiet` so rendered environment
values are not printed into logs.

`docker compose down` retains named volumes. Do not use
`docker compose down --volumes` as routine cleanup because it deletes database,
uploads and recovery state.


## Known limitations

Northstar remains pre-1.0. Multi-process Redis routing is experimental, several
optional XMPP profiles are not implemented, and broad public federation
interoperability has not yet been established. Review
[docs/KNOWN_ISSUES.md](docs/KNOWN_ISSUES.md) before deployment.

## License

Northstar's original code is licensed under
[AGPL-3.0-only](LICENSE). Third-party notices are in
[THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).
