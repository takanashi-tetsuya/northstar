# Northstar XMPP Server

English (primary) | [简体中文](#简体中文)

Northstar is a from-scratch, standards-oriented XMPP server written in Rust for a single Linux node. One process provides native XMPP client access, XMPP federation, XMPP over WebSocket, a standalone browser client, an administration console, a REST API, PostgreSQL persistence, Prometheus metrics, and rolling logs.

The design target is approximately 1,000 simultaneously authenticated users on one appropriately sized server. A 1,000-session fixture has passed in the current development environment, but this is a design validation—not a capacity guarantee for different hardware, traffic patterns, database latency, or retention policies.

> **Maturity and scope:** Northstar 0.1.0 is a tested implementation profile and an extensible foundation. It does not implement every XMPP Extension Protocol (XEP); the XMPP Standards Foundation publishes hundreds of optional extensions. Features marked `Partial` need broader interoperability or omit parts of their specification. Review [XEP_MATRIX.md](XEP_MATRIX.md), the [known limits](#known-limits-and-non-goals), and the security model before exposing the server to the public Internet.

> **Production warning:** the repository's local `localhost` certificate and development database password are not production credentials. Public deployment requires a real domain, a publicly trusted certificate covering that domain, newly generated secrets, backups, monitoring, and an operator security review.

## English

### Contents

- [Project goals](#project-goals)
- [Implemented feature map](#implemented-feature-map)
- [Architecture](#architecture)
- [How a connection and message move through the server](#how-a-connection-and-message-move-through-the-server)
- [OMEMO, encrypted history, and trust](#omemo-encrypted-history-and-trust)
- [Anti-abuse, proof of work, invitations, reports, and appeals](#anti-abuse-proof-of-work-invitations-reports-and-appeals)
- [Requirements](#requirements)
- [Native Linux and WSL quick start](#native-linux-and-wsl-quick-start)
- [Client configuration](#client-configuration)
- [Production Docker deployment](#production-docker-deployment)
- [Configuration reference](#configuration-reference)
- [REST API reference](#rest-api-reference)
- [XMPP compatibility summary](#xmpp-compatibility-summary)
- [Web client and administration console](#web-client-and-administration-console)
- [Database model](#database-model)
- [Files, avatars, and HTTP Upload](#files-avatars-and-http-upload)
- [Federation](#federation)
- [Metrics and logs](#metrics-and-logs)
- [Testing and release validation](#testing-and-release-validation)
- [Backup, restore, upgrade, and certificate rotation](#backup-restore-upgrade-and-certificate-rotation)
- [Repository layout](#repository-layout)
- [Troubleshooting](#troubleshooting)
- [Known limits and non-goals](#known-limits-and-non-goals)
- [License and third-party code](#license-and-third-party-code)

### Project goals

Northstar is built around the following operational profile:

- A normal XMPP server for standards-compatible desktop and mobile clients.
- Rust 2021, Tokio asynchronous I/O, rustls TLS, Axum HTTP/WebSocket, and SQLx/PostgreSQL.
- Standard client-to-server port `5222`, server-to-server port `5269`, and internal HTTP port `8080`.
- Mandatory STARTTLS before TCP client authentication.
- `SCRAM-SHA-256` and `PLAIN` SASL; PLAIN is only available after transport encryption.
- A browser client that speaks XMPP over WebSocket directly and performs OMEMO encryption locally.
- Encrypted-only persistent history by default: plaintext may be delivered live, but it is not archived or queued offline when `REQUIRE_ENCRYPTED_ARCHIVE=true`.
- Single-node deployment with PostgreSQL as the durable system of record and local disk as the replaceable upload backend.
- Open registration by default, with optional administrator-issued invitation tokens.
- Layered abuse controls across source IP, account, and cross-action behavior.
- An administration UI and bearer-authenticated REST API for account, invitation, report, appeal, TLS, and operational tasks.
- Public liveness/readiness checks, internal Prometheus scraping, and rolling text or JSON logs.

Northstar is not a re-skinned copy of Converse.js and does not contain sponsor panels, advertising, or remote UI resources. Its interface, XMPP-over-WebSocket state machine, application state, and OMEMO orchestration live in this repository. The cryptographic Double Ratchet/X3DH core under `web/crypto/` is vendored third-party GPL-3.0 software; see [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).

### Implemented feature map

#### Transport, streams, and authentication

- RFC 6120-style XML streams over TCP.
- Incremental, quote-aware XML token framing with balanced element tracking, a 256-element nesting cap, and DTD rejection; nested forwarded/Carbon/MAM stanzas remain one outer frame.
- Mandatory STARTTLS on the native C2S listener.
- RFC 7395 XMPP framing over WebSocket at `/xmpp-websocket`, requiring the `xmpp` subprotocol.
- Incremental UTF-8 handling when a multibyte character is split across network reads.
- A 1 MiB maximum buffered XMPP frame and a 1 MiB WebSocket message limit.
- SASL `SCRAM-SHA-256` with stored salt, iteration count, stored key, and server key.
- SASL `PLAIN` only inside TLS/WSS.
- Resource binding, full-JID conflict detection, session establishment, and graceful shutdown.
- Usernames normalized to lowercase ASCII, 3–64 characters, using letters, digits, `.`, `_`, or `-`.
- Passwords 10–1,024 bytes; Argon2 password hashes are retained for REST/PLAIN verification.
- Disabled accounts cannot authenticate.

#### One-to-one messaging, presence, roster, and blocking

- Local full-JID and bare-JID message routing.
- Bare-JID routing chooses the available non-negative-priority resource with the highest priority; ties are deterministic.
- Persistent rosters, roster pushes, presence subscription transitions, and pending subscription delivery.
- Local and federated presence routing.
- Offline queueing and MAM storage, encrypted-only under the default policy.
- XEP-0334 `no-store` and `no-permanent-store` prevent archive and offline persistence.
- Per-resource Message Carbons with sent and received copies.
- Persistent blocklists, block/unblock/unblock-all, multi-resource pushes, and inbound/outbound enforcement.
- Receipts, chat markers, reactions, and other client payloads can be routed; only features listed as `Core` or `Partial` are interpreted by the server.

#### Archive, offline delivery, and continuity

- Persistent message archive with per-owner copies.
- XEP-0313 MAM query form, peer/start/end filters, UUID cursors, stable result ordering, and XEP-0059 `before`/`after` pagination.
- Latest-page MAM queries return at most 100 stanzas per XMPP request.
- REST history returns at most 200 rows; the default is 100.
- Offline messages are delivered when a resource becomes available or resumes.
- Offline rows expire after `OFFLINE_MESSAGE_TTL_DAYS` and are cleaned every minute.
- XEP-0198 counters, acknowledgements, in-memory resumption, and replay of unacknowledged stanzas.
- Stream resumption survives a transport interruption for `SM_RESUME_TIMEOUT_SECONDS`, but not a process restart.

#### PEP, OMEMO, avatars, vCards, and private XML

- Persistent PEP item publish/retrieve for the nodes used by OMEMO and avatars.
- Multiple `<item>` elements in one publish request are persisted.
- A UUID item ID is generated when the publisher omits `id`, and the normalized item is stored with that ID.
- Empty/nonexistent PEP nodes return `item-not-found`, which allows clients such as Gajim to initialize new OMEMO device lists correctly.
- PEP responses for another account carry the correct owner in the IQ `from` attribute.
- Account discovery dynamically advertises stored PEP nodes and their `+notify` features.
- PEP event fan-out to the owner's resources and subscribed roster contacts, subject to blocklists.
- Durable `vcard-temp` storage and avatar data/metadata PEP nodes.
- XEP-0049 private XML storage, limited to one namespaced child per request and 512 KiB per item.

#### Multi-user chat

- Local `conference.<domain>` MUC service discovery and public room listing.
- Room creation, join, leave, nickname conflict checking, occupant presence, and room history.
- Group messages, occupant private messages/IQs, subjects, mediated invitations, and direct invitations.
- Owner room configuration for title, persistence, members-only, public/hidden, moderated/unmoderated, anonymity mode, and maximum occupancy from 2 to 1,000.
- Owner destroy with optional alternate room and reason.
- Owner/admin/member/outcast affiliations; moderator/participant/visitor/no-role behavior.
- Affiliation lists and administrative updates, including kick and ban flows.
- New rooms are non-anonymous by default so OMEMO clients can map occupants to real JIDs.
- Real JIDs are included in MUC user presence when policy permits. In a members-only, non-anonymous room, members may retrieve owner/admin/member affiliation lists needed to construct the OMEMO recipient set; they may not retrieve the outcast list.
- Encrypted room history is stored only when archive policy permits it; clients joining later can only decrypt messages whose key envelopes included one of their devices at send time.

Password-protected rooms, federated MUC, the complete XEP-0045 status/error matrix, and every room-configuration field are not implemented.

#### HTTP Upload, files, and avatars

- XEP-0363 upload service at `upload.<domain>`.
- Discovery advertises the configured maximum size.
- Authenticated, expiring, one-use PUT slots with opaque bearer tokens stored only as SHA-256 digests.
- Exact content type and exact byte-length checks.
- Atomic local writes through a `.part` file followed by rename.
- Immutable GET responses with `Content-Disposition: attachment`, `nosniff`, and a sandboxed `default-src 'none'` CSP.
- Browser attachments are AES-GCM encrypted before upload; the file key, IV, name, media type, and size travel inside the OMEMO/SCE message.
- Avatar source files up to 50 MiB are decoded locally, previewed, panned, zoomed, rotated, cropped, converted to JPEG, and compressed below 256 KiB before XMPP publication.

#### Federation

- Inbound and outbound S2S on port `5269` when enabled.
- `_xmpp-server._tcp` SRV lookup with direct `<domain>:5269` fallback.
- One-hour endpoint cache.
- Mandatory STARTTLS, public-root validation plus an optional additional root, DNS-domain certificate verification, and SASL EXTERNAL.
- Exact and `*.` wildcard allow/deny policies; deny rules take priority.
- Private, loopback, link-local, multicast, documentation, unspecified, and other special-use targets are rejected by default.
- Controlled DNS overrides for tests/private deployments.
- Bounded queues: 10,000 federation router entries and 100 entries per outbound domain worker.
- Federated messages, IQ forwarding, presence/subscription state, PEP/vCard requests, blocking enforcement, and metadata-minimized push routing within the implemented profile.

Server Dialback, durable retry spooling, multi-hop delivery guarantees, and federated MUC are not implemented. An in-memory outbound failure can be bounced to an online origin, but queued federation work does not survive restart.

#### REST, administration, reporting, and operations

- REST registration, login, current-account lookup, password change, and encrypted history access.
- Random 64-character REST tokens; only SHA-256 token digests are stored.
- Administrator user list, disable/enable, promote/demote, and self-lockout protection.
- One-time-visible invitation secrets with expiration, revocation, and atomic maximum-use accounting.
- User reports containing 1–20 explicitly selected decrypted records.
- Categories: `spam`, `harassment`, `threat`, `impersonation`, `illegal`, and `other`.
- Report workflow: `submitted` → `reviewing` → `actioned`, `rejected`, or `closed`.
- At most one appeal per report; appeal workflow: `submitted` → `reviewing` → `upheld` or `denied`.
- Administrator TLS reload for new handshakes without restarting the process.
- Audit records for registrations, password changes, user moderation, reports, appeals, invitations, and TLS reloads.
- `/healthz`, `/readyz`, `/metrics`, rolling logs, and an administrator statistics view.

### Architecture

```text
Native clients                         Browser clients
Gajim / Conversations / others         Northstar Web client
          |                                      |
          | TCP 5222 + STARTTLS                   | HTTPS/WSS 443
          |                                      |
          +------------------+-------------------+
                             |
                    Northstar Rust process
        +--------------------+-------------------------+
        | C2S XML streams / WebSocket state machine    |
        | routing, roster, presence, PEP, MAM, MUC     |
        | REST API, admin UI, upload API, metrics      |
        | anti-abuse state, SM state, MUC occupancy    |
        | S2S TLS/SASL EXTERNAL on TCP 5269            |
        +---------------+------------------------------+
                        |
             +----------+-----------+
             |                      |
       PostgreSQL               Upload directory
       durable metadata         opaque file bytes
       and XMPP stanzas         (ciphertext in Web flow)
```

The single Tokio process owns three listeners:

| Listener | Default | Responsibility |
| --- | ---: | --- |
| C2S TCP | `0.0.0.0:5222` | Native XMPP streams and STARTTLS |
| S2S TCP | `0.0.0.0:5269` | Authenticated federation |
| HTTP | `0.0.0.0:8080` | Static Web UI, REST, upload/download, WebSocket, health, readiness, metrics |

Durable state is stored in PostgreSQL. Online sessions, Stream Management resumption state, room occupants, abuse counters/challenges, federation workers, and the DNS cache are in memory. This separation is why the current architecture is intentionally single-node.

Startup proceeds in this order:

1. Load `.env` when present, then map environment variables into a validated configuration.
2. Read `DATABASE_URL_FILE` or bootstrap-password files if configured.
3. Initialize console and rolling-file logging.
4. Install the rustls AWS-LC cryptographic provider.
5. Connect the PostgreSQL pool.
6. Load and apply SQL migrations from the `migrations/` directory.
7. Ensure the optional bootstrap administrator exists. An existing administrator is left unchanged; an existing non-admin with the same name is rejected.
8. Parse the PEM certificate chain and private key and reject an empty chain or mismatched key.
9. Create in-memory routers, stores, metrics, and abuse state.
10. Start cleanup tasks and the C2S, S2S, and HTTP listeners.
11. On `Ctrl+C` or `SIGTERM`, cancel listeners, drain HTTP work, and exit cleanly.

Because migrations and Web assets are loaded from relative paths, run the native binary with the project directory as its working directory. The Docker image copies `migrations/` and `web/` into `/app` and uses `/app` as its working directory.

### How a connection and message move through the server

#### Native C2S connection

1. The client opens an XML stream on port 5222.
2. Before encryption, the server advertises only required STARTTLS.
3. After TLS succeeds, the stream restarts and the server advertises `SCRAM-SHA-256`, `PLAIN`, and eligible in-band registration.
4. After SASL succeeds, the stream restarts and resource binding plus Stream Management are advertised.
5. The bound full JID is inserted into the in-memory session map. Duplicate full JIDs are rejected with `conflict`.
6. Initial available presence updates resource priority, broadcasts to authorized roster contacts, and drains offline messages.

WebSocket connections start in an already encrypted state from the XMPP layer's perspective. In production, Caddy must provide HTTPS/WSS; direct unencrypted `ws://` is only acceptable for local development.

#### Direct message

1. The server requires an authenticated bound resource and a valid destination JID.
2. Content messages pass through the source-IP, user, and behavioral anti-abuse guard. The Northstar PoW element is removed before delivery or persistence.
3. Blocklists are checked in both directions.
4. Remote domains are handed to the S2S router after federation policy checks.
5. Local encrypted messages are archived for sender and recipient unless a no-store hint is present. With the default encrypted-only policy, plaintext is not archived.
6. For a bare local JID, the best eligible resource receives the original message. Other eligible resources receive Carbons when enabled.
7. If no resource accepts delivery, encrypted content is queued offline and push summaries are attempted. Plaintext is rejected instead of queued under the default archive policy.

#### MUC message

The sender must be an occupant. The room enforces role and affiliation rules, rewrites the sender as `room@conference.domain/nick`, broadcasts to occupant resources, and stores permitted history. OMEMO encryption is client-side: the browser builds the recipient device set from the real JIDs of current occupants; the server never creates group keys.

### OMEMO, encrypted history, and trust

#### What “only users can decrypt history” means

When every sender uses OMEMO 2, the server stores public device metadata and encrypted message envelopes but does not receive browser private identity/session keys. The included browser client also avoids persisting decrypted message bodies in IndexedDB; it reloads ciphertext from MAM and decrypts it in memory.

This statement has precise boundaries:

- The server can always inspect plaintext that a client sends as plaintext.
- `REQUIRE_ENCRYPTED_ARCHIVE=true` prevents plaintext persistence; it does not make a live plaintext stanza invisible while the server routes it.
- The server sees routing metadata: JIDs, timestamps, online state, room membership, device IDs, stanza shape, and approximate sizes.
- Browser private keys are protected by the browser origin and local operating-system account, not by a separate Northstar key-encryption password. Malware or a compromised browser profile is outside this protection.
- No OMEMO backup/export UI is currently implemented. Clearing site data, losing the browser profile, or losing every device key can make old history permanently unreadable.
- A newly added group member cannot decrypt earlier messages unless an earlier envelope was already encrypted to one of that member's devices.
- Reports deliberately cross the E2EE boundary: only messages the reporting user selects are submitted as plaintext evidence to moderators.

#### Browser OMEMO flow

1. The browser creates an identity key, signed prekey, one-time prekeys, and a numeric device ID.
2. Private state is stored in IndexedDB under the site origin.
3. Public device lists and bundles are published through PEP using `urn:xmpp:omemo:2` nodes.
4. The sender retrieves recipient bundles, creates or resumes Double Ratchet sessions, and wraps the content key for every recipient device and the sender's other devices.
5. The payload is carried in an OMEMO 2 encrypted element plus Stanza Content Encryption metadata.
6. The recipient locates the key for its device, advances the local ratchet, validates the protected sender metadata, and decrypts in memory.
7. Fingerprints are shown in the security dialog. The browser uses trust-on-first-use (TOFU); an identity-key change is displayed as changed and is not silently treated as the same identity.

The server stores normalized PEP items and returns `item-not-found` for a missing device node. That distinction is important: clients such as Gajim use it to decide that they must create their own initial device list rather than interpreting an empty successful node as a deliberately cleared list.

### Anti-abuse, proof of work, invitations, reports, and appeals

Northstar layers limits rather than relying on a single request counter.

#### Actors and state

- Registration is keyed by source IP and also has a database-wide registrations-per-hour cap.
- Login failure state is keyed by source IP.
- Message, report, and appeal actions use source IP, account ID, and a shared `behavior:<account>` actor. The shared behavioral actor lets abusive activity in one action affect another action.
- In-memory event windows, penalty levels, hard blocks, challenge issuance, and challenge replay protection reset when the process restarts. Durable reports, invitations, and accounts do not.
- `X-Forwarded-For` is accepted only when the directly connected peer IP is listed in `TRUSTED_PROXY_IPS`.

#### Work formula

For a work-bearing action, after its free burst:

```text
step        = max(events_in_window + 1 - free_burst, 0)
work_factor = min(action_base × step² × 2^penalty, POW_MAX_WORK_FACTOR)
```

Default action policy:

| Action | Free burst | Action base | Additional rule |
| --- | ---: | ---: | --- |
| Registration | 1 | no computational work in the current policy | IP/window state plus hard cooldown and global hourly cap |
| Login | 5 failed attempts | `POW_BASE_WORK_FACTOR` | successful attempts do not add failure events |
| Message | 6 content messages | `POW_BASE_WORK_FACTOR` | receipts, presence, and chat-state traffic are not content messages |
| Report | 0 | `2 × POW_BASE_WORK_FACTOR` | proof is required immediately |
| Appeal | 0 | `8 × POW_BASE_WORK_FACTOR` | proof plus at least 15 seconds hard wait |

Default hard-wait tiers are 0 seconds for steps 0–3, 2 seconds for 4–7, 10 seconds for 8–11, 30 seconds for 12–15, and 120 seconds thereafter. Penalties multiply waits exponentially, bounded by `ABUSE_MAX_WAIT_SECONDS`. A penalty level decays one step per `ABUSE_COOLDOWN_SECONDS` without activity.

The advertised maximum-device estimate is eight seconds, but this is UI guidance rather than hardware calibration. Actual solve time depends on the browser, CPU, battery policy, and configured maximum work factor.

#### Challenge verification

- Challenges contain a UUID, random URL-safe prefix, action, subject, requirement, and expiration.
- The newest challenge for an action/subject invalidates the preceding one.
- A challenge is one-use, action-bound, subject-bound, actor-sequence-bound, and not usable before its hard-wait deadline.
- The decimal nonce is at most 64 digits.
- Verification computes SHA-256 over `prefix || nonce`; the first 64 bits must be no greater than `u64::MAX / work_factor`.
- Invalid, replayed, mismatched, or insufficient proofs increase the penalty.
- More than 30 challenge requests for an actor in one abuse window also trigger punishment.
- The browser computes work in a dedicated worker and displays the current work, maximum work, wait, and cooldown notice.
- Standards clients that do not understand Northstar PoW still work during the free burst. When limited, they receive a standard `resource-constraint` stanza with Northstar retry metadata and can wait for cooldown.

#### Invitations

When `INVITATION_REQUIRED=true`, REST registration must include a valid invitation. The token secret is returned only once when an administrator creates it; listings contain metadata, never the secret. PostgreSQL atomically checks revocation, expiration, and remaining uses while creating the user. XEP-0077/XEP-0389 registration is not advertised in invitation-required mode because those implemented forms do not carry an invitation token.

#### Reports and appeals

- A user selects 1–20 messages and submits their decrypted text intentionally.
- Each evidence body is 1–8,000 characters; the optional description is at most 4,000 characters.
- Moderators see the selected evidence, report status, resolution, and any appeal.
- A terminal report resolution requires text.
- Only one appeal can exist for a report, and it is accepted only through the stricter appeal guard.
- Appeal reasons are 20–4,000 characters; terminal appeal decisions require resolution text.
- Administrative changes are audit logged.

### Requirements

#### Native development

- Linux, or Ubuntu 24.04 under WSL2.
- Current stable Rust toolchain compatible with Rust 2021.
- PostgreSQL. The container profile uses PostgreSQL 17; development can use a compatible currently supported PostgreSQL release.
- OpenSSL command-line tools for generating development/test certificates and running certificate checks.
- Python 3, `psql`, and `curl` for integration fixtures.
- Node.js plus Chromium/Chrome for browser end-to-end tests.

#### Container deployment

- Linux server with Docker Engine and Docker Compose v2.
- Public DNS name pointing to the server.
- A certificate/private key pair whose SAN covers `XMPP_DOMAIN` for C2S/S2S.
- TCP 80/443 for Caddy, 5222 for clients, and 5269 for federation. PostgreSQL must remain private.

### Native Linux and WSL quick start

These steps create a local development deployment. They do not create production secrets or a publicly trusted certificate.

#### 1. Create PostgreSQL role and database

```bash
sudo -u postgres createuser --login --pwprompt northstar
sudo -u postgres createdb --owner northstar northstar
```

Use the chosen password in the development `DATABASE_URL`. Avoid putting production passwords in shell history.

#### 2. Create a local certificate

```bash
mkdir -p certs
openssl req -x509 -newkey rsa:2048 -nodes -days 30 \
  -subj "/CN=localhost" \
  -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" \
  -keyout certs/server.key \
  -out certs/server.crt
chmod 600 certs/server.key
```

Self-signed certificates are for local testing only. Never train users to bypass certificate errors on a public service.

#### 3. Configure

```bash
cp .env.example .env
```

For local native execution, edit at least:

```dotenv
XMPP_DOMAIN=localhost
PUBLIC_URL=http://localhost:8080
DATABASE_URL=postgres://northstar:YOUR_DEVELOPMENT_PASSWORD@127.0.0.1:5432/northstar
TLS_CERT_PATH=certs/server.crt
TLS_KEY_PATH=certs/server.key
```

Do not commit `.env`; it is ignored intentionally.

#### 4. Compile, test, and start in the foreground

```bash
cargo fmt --all -- --check
cargo check --all-targets --locked
cargo test --all-targets --locked
cargo run --locked
```

No source-file argument is required. Keep the terminal open; press `Ctrl+C` for a graceful shutdown. The standard listeners are now:

- XMPP C2S: `localhost:5222`
- XMPP S2S: `localhost:5269`
- Web/REST/WebSocket: `http://localhost:8080`

#### 5. Verify

```bash
curl --fail http://localhost:8080/healthz
curl --fail http://localhost:8080/readyz
curl --fail http://localhost:8080/api/v1/config
```

`healthz` means the HTTP event loop is responding. `readyz` additionally runs `SELECT 1` against PostgreSQL.

#### WSL path

From Windows PowerShell, the repository can be verified in Ubuntu WSL with:

```powershell
wsl.exe -d Ubuntu-24.04 -- bash /mnt/c/Users/Admin/Documents/XMPP/scripts/verify-wsl.sh all
```

Start the server yourself in a visible WSL terminal:

```bash
cd /mnt/c/Users/Admin/Documents/XMPP
cargo run --locked
```

### Client configuration

| Setting | Value |
| --- | --- |
| Account/JID | `username@XMPP_DOMAIN` |
| Host | `XMPP_DOMAIN` |
| C2S port | `5222` |
| Transport security | STARTTLS required |
| Authentication | Prefer `SCRAM-SHA-256`; `PLAIN` is protected by TLS |
| WebSocket URL | `wss://XMPP_DOMAIN/xmpp-websocket` |
| WebSocket subprotocol | `xmpp` |
| MUC service | `conference.XMPP_DOMAIN` |
| Upload service | `upload.XMPP_DOMAIN` |

#### Gajim and OMEMO

Northstar has been manually exercised with Gajim for encrypted direct and group messages. For a new account:

1. Connect through port 5222 and accept only the expected certificate.
2. Enable OMEMO in Gajim and let it publish its device list and bundle.
3. Add/authorize contacts as required by the client.
4. In a non-anonymous MUC, wait until the occupant list contains real JIDs.
5. Open **Manage Trust** and verify fingerprints before sending sensitive content.

If Gajim says that trust must be decided but its device list is empty, see [OMEMO device/trust list is empty](#omemo-devicetrust-list-is-empty). Do not assume every failure is a client cache problem; confirm the server's PEP responses and room affiliation visibility first.

### Production Docker deployment

#### 1. DNS and firewall

Create `A`/`AAAA` records for `XMPP_DOMAIN`. Recommended SRV records on default ports are:

```dns
_xmpp-client._tcp.example.com. 3600 IN SRV 0 5 5222 example.com.
_xmpp-server._tcp.example.com. 3600 IN SRV 0 5 5269 example.com.
```

Open TCP 80, 443, 5222, and 5269. Do not expose PostgreSQL or the application's loopback-only port 8080.

#### 2. Prepare non-secret configuration

```bash
cp .env.example .env
```

Set at least:

```dotenv
XMPP_DOMAIN=example.com
PUBLIC_URL=https://example.com
TLS_CERT_HOST_PATH=/etc/letsencrypt/live/example.com/fullchain.pem
TLS_KEY_HOST_PATH=/etc/letsencrypt/live/example.com/privkey.pem
```

The XMPP container runs as UID 10001 and needs read access to those two files. Mount only the exact certificate and key. Caddy manages the HTTPS certificate it uses for the Web endpoint independently; the explicitly mounted certificate is used by XMPP C2S/S2S.

#### 3. Generate service secrets

```bash
bash scripts/create-production-secrets.sh
```

The script creates mode-0600 files without printing their values:

- `deploy/secrets/postgres_password`
- `deploy/secrets/database_url`
- `deploy/secrets/bootstrap_admin_password`

It refuses to overwrite an existing secret. The password embedded in `database_url` matches `postgres_password`.

#### 4. Run production preflight

```bash
bash scripts/release-preflight.sh --production
```

The preflight checks formatting, compilation, tests, tracked sensitive files when Git is available, certificate expiration/SAN/key matching, secret presence/mode, HTTPS configuration, and merged Compose syntax when Docker is available.

#### 5. Bootstrap once

```bash
docker compose \
  -f docker-compose.yml \
  -f deploy/docker-compose.bootstrap.yml \
  up --build -d
```

Log in as the configured bootstrap administrator (default username `admin`), retrieve the password through a secure local channel, and change it immediately.

#### 6. Remove the bootstrap secret from the running service

```bash
docker compose up -d --force-recreate xmpp
```

After confirming the new password works, securely remove `deploy/secrets/bootstrap_admin_password`. Keep the database secret files for normal runtime.

#### 7. Inspect service state

```bash
docker compose ps
docker compose logs --tail=200 xmpp
curl --fail https://example.com/healthz
curl --fail https://example.com/readyz
```

The base Compose profile provides:

- PostgreSQL on an internal-only backend network.
- XMPP with a read-only root filesystem, a small `/tmp` tmpfs, all Linux capabilities dropped, and `no-new-privileges`.
- Exact read-only TLS file mounts.
- Caddy on a pinned frontend address so only that proxy is trusted for `X-Forwarded-For`.
- Host ports 5222/5269, Caddy ports 80/443, and application port 8080 bound only to `127.0.0.1`.
- External `/metrics` returns 404; Prometheus can scrape `xmpp:8080/metrics` from an authorized internal network.

### Configuration reference

Runtime configuration is loaded from environment variables. A project-root `.env` is loaded for native execution. If a variable is absent, the code default is used except that a database URL is mandatory.

#### Core, network, and database

| Variable | Default/example | Meaning and validation |
| --- | --- | --- |
| `XMPP_DOMAIN` | `localhost` | Lowercased server domain; DNS-label syntax, maximum 253 characters |
| `PUBLIC_URL` | `http://localhost:<HTTP port>` locally, otherwise `https://<domain>` | Absolute HTTP(S) base used in upload URLs; no trailing slash is retained |
| `XMPP_BIND` | `0.0.0.0:5222` | Native C2S listener |
| `S2S_BIND` | `0.0.0.0:5269` | Federation listener |
| `HTTP_BIND` | `0.0.0.0:8080` | Web, REST, WebSocket, upload, and observability listener |
| `TRUSTED_PROXY_IPS` | `127.0.0.1,::1` | Comma-separated direct peer IPs permitted to supply `X-Forwarded-For` |
| `DATABASE_URL` | required for native execution | PostgreSQL connection URL; mutually exclusive with `DATABASE_URL_FILE` |
| `DATABASE_URL_FILE` | unset | File containing the complete URL; regular file under 64 KiB; trailing CR/LF removed |
| `DATABASE_MAX_CONNECTIONS` | `32` | Positive SQLx pool maximum |
| `DATABASE_MIN_CONNECTIONS` | `2` | Pool minimum; cannot exceed maximum |
| `SCRAM_ITERATIONS` | `600000` | PBKDF2-HMAC-SHA-256 work factor for new/upgraded SCRAM verifiers; allowed range `4096..=10000000` |

#### Accounts, sessions, and persistence

| Variable | Default | Meaning and validation |
| --- | ---: | --- |
| `OPEN_REGISTRATION` | `true` | Enables REST and eligible in-band registration |
| `INVITATION_REQUIRED` | `false` | Requires an administrator token for REST registration and hides incompatible IBR forms |
| `REGISTRATION_RATE_PER_HOUR` | `20` | Database-wide completed-registration ceiling per rolling hour; IP abuse state is additional |
| `SESSION_TTL_HOURS` | `168` | REST bearer-token lifetime; 1–8,760 |
| `SM_RESUME_TIMEOUT_SECONDS` | `300` | In-memory XEP-0198 resumption window; 1–86,400 |
| `OFFLINE_MESSAGE_TTL_DAYS` | `30` | Offline queue retention; 1–3,650 |
| `REQUIRE_ENCRYPTED_ARCHIVE` | `true` | Persist only server-recognized encrypted messages; reject plaintext offline queueing |
| `BOOTSTRAP_ADMIN_USERNAME` | unset | Optional initial administrator; must be set with a password |
| `BOOTSTRAP_ADMIN_PASSWORD` | unset | Direct bootstrap secret; prefer the file form in production |
| `BOOTSTRAP_ADMIN_PASSWORD_FILE` | unset | Mutually exclusive password file; regular file under 64 KiB |

#### TLS, uploads, federation, and anti-abuse

| Variable | Default | Meaning and validation |
| --- | --- | --- |
| `TLS_CERT_PATH` | `certs/server.crt` | PEM certificate chain read at startup/reload |
| `TLS_KEY_PATH` | `certs/server.key` | PEM private key; must match the certificate |
| `UPLOAD_DIR` | `data/uploads` | Local upload object root |
| `UPLOAD_MAX_BYTES` | `26214400` (25 MiB) | XEP-0363 maximum; positive and within signed 64-bit range |
| `FEDERATION_ENABLED` | `true` | Starts/permits S2S behavior |
| `FEDERATION_ALLOWLIST` | empty | Comma-separated exact domains or `*.suffix`; empty allows all not denied |
| `FEDERATION_DENYLIST` | empty | Comma-separated exact/wildcard domains; evaluated before allowlist |
| `FEDERATION_ALLOW_PRIVATE_IPS` | `false` | Allow private/special-use S2S endpoints; use only in controlled networks/tests |
| `FEDERATION_DNS_OVERRIDES` | empty | Comma-separated `domain=IP:port` endpoints |
| `FEDERATION_EXTRA_ROOT_CERT_PATH` | unset | Optional PEM CA added to public trust roots |
| `POW_BASE_WORK_FACTOR` | `1024` | Base work for login/message; must be positive |
| `POW_MAX_WORK_FACTOR` | `524288` | Hard work cap; cannot be below base |
| `ABUSE_WINDOW_SECONDS` | `60` | Event-count window; positive |
| `ABUSE_COOLDOWN_SECONDS` | `60` | One penalty-decay step; positive |
| `ABUSE_MAX_WAIT_SECONDS` | `900` | Hard-wait cap; positive |

#### Logging

| Variable | Default | Meaning |
| --- | --- | --- |
| `LOG_DIR` | `logs` | Rolling log directory |
| `LOG_ROTATION` | `daily` | `minutely`, `hourly`, `daily`, or `never` |
| `LOG_FORMAT` | `text` | `text` or structured `json` |
| `LOG_RETENTION_FILES` | `30` | Positive maximum number of rolled files |
| `RUST_LOG` | `info` fallback | `tracing` filter, for example `rust_xmpp_server=debug,tower_http=info` |

#### Compose-only host settings

| Variable | Default | Meaning |
| --- | --- | --- |
| `FRONTEND_SUBNET` | `172.31.240.0/24` | Pinned Caddy/XMPP frontend network |
| `CADDY_PROXY_IP` | `172.31.240.2` | Only trusted proxy inside Compose |
| `XMPP_HTTP_IP` | `172.31.240.3` | XMPP service address on frontend network |
| `TLS_CERT_HOST_PATH` | `certs/server.crt` | Host certificate file mounted read-only |
| `TLS_KEY_HOST_PATH` | `certs/server.key` | Host private-key file mounted read-only |
| `POSTGRES_PASSWORD_SECRET_FILE` | `deploy/secrets/postgres_password` | Compose secret source |
| `DATABASE_URL_SECRET_FILE` | `deploy/secrets/database_url` | Compose database URL secret source |
| `BOOTSTRAP_ADMIN_PASSWORD_SECRET_FILE` | `deploy/secrets/bootstrap_admin_password` | Bootstrap-only Compose secret source |

Never set both a direct secret and its `_FILE` alternative. Secret files must be regular files below 64 KiB and cannot be empty or contain NUL. Only line endings—not surrounding spaces—are removed.

### REST API reference

The authoritative machine-readable contract is [docs/openapi.yaml](docs/openapi.yaml). JSON errors use an `error` object; rate-limit errors also return a structured work/wait requirement.

#### Authentication classes

| Class | Header | Used by |
| --- | --- | --- |
| Public | none | health, readiness, public config, registration, login, registration challenges |
| User bearer | `Authorization: Bearer <REST token>` | account, history, reports, appeals, authenticated challenges |
| Administrator bearer | same header, account must have `is_admin=true` | all `/api/v1/admin/*` endpoints |
| Upload-slot bearer | one-use token from XMPP slot response | `PUT /api/v1/upload/{id}` only |

#### Endpoints

| Method and path | Purpose |
| --- | --- |
| `GET /healthz` | Process liveness |
| `GET /readyz` | PostgreSQL readiness |
| `GET /metrics` | Prometheus text; block externally in production |
| `GET /api/v1/config` | Domain, registration, archive, services, federation, and PoW public settings |
| `POST /api/v1/register` | Create an account when open registration/policy permits |
| `POST /api/v1/login` | Create a REST bearer session |
| `POST /api/v1/anti-abuse/challenge` | Issue one-use challenge for registration/login/message/report/appeal |
| `GET /api/v1/me` | Current account identity |
| `PATCH /api/v1/me/password` | Verify current password, change it, revoke all REST sessions |
| `GET /api/v1/history` | Current user's archived stanzas; optional `with` and `limit` |
| `GET /api/v1/reports` | Current user's reports, evidence, outcomes, and appeals |
| `POST /api/v1/reports` | Submit report and selected evidence with report PoW |
| `POST /api/v1/reports/{id}/appeals` | Submit the report's single appeal with stricter PoW/wait |
| `PUT /api/v1/upload/{id}` | Fill an XEP-0363 slot with exact type/length |
| `GET /uploads/{id}` | Download immutable bytes by possession of opaque URL |
| `GET /api/v1/admin/stats` | Counts and in-memory operational statistics |
| `GET /api/v1/admin/users` | Paginated account list, limit 1–200 |
| `PATCH /api/v1/admin/users/{id}` | Enable/disable/promote/demote |
| `GET /api/v1/admin/reports` | Moderation queue with evidence and appeals |
| `PATCH /api/v1/admin/reports/{id}` | Update report status/resolution |
| `PATCH /api/v1/admin/appeals/{id}` | Update appeal status/resolution |
| `GET /api/v1/admin/invitations` | Invitation metadata, never token secrets |
| `POST /api/v1/admin/invitations` | Create token; secret shown once |
| `DELETE /api/v1/admin/invitations/{id}` | Revoke token |
| `POST /api/v1/admin/tls/reload` | Atomically load certificate/key for new handshakes |

#### Minimal REST example

```bash
BASE=http://localhost:8080

curl --fail-with-body -X POST "$BASE/api/v1/register" \
  -H 'Content-Type: application/json' \
  --data '{"username":"alice","password":"correct-horse-battery-staple"}'

curl --fail-with-body -X POST "$BASE/api/v1/login" \
  -H 'Content-Type: application/json' \
  --data '{"username":"alice","password":"correct-horse-battery-staple"}'
```

Copy the returned token without writing it into source files:

```bash
TOKEN='paste-the-returned-token-for-this-shell-only'
curl --fail "$BASE/api/v1/me" -H "Authorization: Bearer $TOKEN"
curl --fail "$BASE/api/v1/history?with=bob@localhost&limit=100" \
  -H "Authorization: Bearer $TOKEN"
```

For a limited action, request a challenge, solve the nonce requirement, then include:

```json
{
  "pow": {
    "challenge_id": "00000000-0000-0000-0000-000000000000",
    "nonce": "12345"
  }
}
```

The bundled browser performs this automatically. An XMPP message carries the equivalent extension as `<pow xmlns='urn:northstar:pow:1' challenge='…' nonce='…'/>`; the server strips it before routing.

### XMPP compatibility summary

The detailed normative boundary is [XEP_MATRIX.md](XEP_MATRIX.md). Status means:

- `Core`: the implemented profile has automated protocol coverage and is suitable for its described use.
- `Partial`: a useful subset is implemented; do not assume every clause of the RFC/XEP.
- `Pass-through`: the payload can travel, but the server does not maintain its higher-level semantic state.

| Standard | Status | Northstar profile |
| --- | --- | --- |
| RFC 6120 | Partial | Streams, STARTTLS, SCRAM-SHA-256/PLAIN, binding, stanzas, limits |
| RFC 6121 | Partial | Routing, roster, subscriptions, presence, priority selection |
| RFC 7395 | Core | XMPP over WebSocket and framing |
| XEP-0030 | Core | Server/account/MUC/room/upload discovery |
| XEP-0045 | Partial | Local MUC profile described above |
| XEP-0049 | Partial | Durable private XML item get/set |
| XEP-0054 | Partial | Durable vCard locally and across federation |
| XEP-0059 | Partial | Stable MAM paging/count/index |
| XEP-0060 / 0163 | Partial | PEP profile for OMEMO/avatar events, not general PubSub |
| XEP-0077 / 0389 | Partial | Open registration and password change; policy limitations apply |
| XEP-0084 | Partial | Avatar data/metadata plus vCard fallback |
| XEP-0092 | Core | Software version |
| XEP-0160 | Partial | Local/federated offline behavior, encrypted-only by default |
| XEP-0184 | Pass-through | Client receipts are routed |
| XEP-0191 | Partial | Durable blocking and enforcement |
| XEP-0198 | Partial | In-memory counters/resume/replay |
| XEP-0199 | Core | Ping |
| XEP-0202 | Core | UTC entity time |
| XEP-0203 | Partial | Delay stamps on stored/history delivery |
| XEP-0280 | Partial | Per-resource sent/received Carbons |
| XEP-0313 | Partial | Encrypted archive, filters, stable RSM paging |
| XEP-0333 | Pass-through | Chat markers |
| XEP-0334 | Partial | No-store persistence hints |
| XEP-0357 | Partial | Enable/disable and count-only push summaries |
| XEP-0363 | Core | Upload discovery, slot, exact PUT, immutable GET |
| XEP-0384 | Partial | Browser OMEMO 2 plus PEP server support |
| XEP-0420 | Partial | Browser SCE-protected content |
| XEP-0444 | Pass-through | Reactions inside client payloads |

Northstar intentionally does not advertise unsupported IQs: unknown requests receive `feature-not-implemented` rather than a fabricated success.

### Web client and administration console

#### User client (`/client.html`)

- REST registration/login followed by direct XMPP-over-WebSocket authentication.
- Reconnect with bounded exponential delay while the password remains only in memory.
- Roster/contact management, presence, search, block/unblock, and contact removal.
- Direct chats, room creation/join/leave, occupant list, and group encryption.
- OMEMO device publication, bundle retrieval, TOFU fingerprint display, direct/group encryption, and MAM decryption.
- No durable plaintext chat cache; messages are decrypted into memory after MAM retrieval.
- Message Carbons and multi-device recipient encryption.
- Client-side encrypted attachments.
- Report selection UI, result history, and appeal UI.
- Avatar editor with local decode/crop/rotate/convert/compress.
- Responsive desktop/mobile layout.

#### Localization

- English is the default language.
- The Recommended group contains English, Simplified Chinese, `中華民國語 (Traditional Chinese)`, Korean, Japanese, Spanish, French, and German.
- The full picker is searchable and sorted by English display name.
- The current catalog contains 84 retained languages, including Esperanto and Latin.
- Eight core locales are directly maintained. The remaining complete static packs were generated locally using the open-source MADLAD-400 3B-MT model.
- Machine-generated locales show a persistent notice that translation errors may exist.
- No interface text is sent to an online translation service at runtime.
- See [docs/LOCALIZATION.md](docs/LOCALIZATION.md) for generation and validation.

#### Administration console (`/` → Administration)

- Uses the same REST login endpoint and rejects non-admin sessions.
- Shows users, online resources, archive/offline counts, rooms/occupants, uploads, push subscriptions, federation counters, reports, appeals, invitations, anti-abuse counters, and uptime.
- Creates/revokes invitation tokens.
- Reviews report evidence and appeal state.
- Enables/disables and promotes/demotes accounts while preventing the current administrator from disabling or demoting itself.
- The API also exposes TLS reload; operators may integrate it into certificate-renewal hooks.

Static assets are local. The application adds CSP, `nosniff`, and no-referrer headers. Caddy adds HSTS, a stricter referrer policy, and a restrictive permissions policy in production.

### Database model

SQL migrations are applied in filename order from `migrations/` at startup. Do not edit an already-applied migration on a live installation; add a new numbered migration.

| Table | Durable responsibility |
| --- | --- |
| `users` | Account identity, Argon2 hash, SCRAM verifier material, admin/disabled state, timestamps |
| `api_sessions` | SHA-256 token digests and expiration |
| `roster_items` | Contact names, subscription/ask state, groups |
| `pending_presence_subscriptions` | Local pending requests |
| `federated_presence_pending` | Remote pending requests |
| `blocked_jids` | Persistent block rules |
| `message_archive` | Per-user MAM stanza copy, peer, encryption marker, stanza ID, time |
| `offline_messages` | Pending stanza delivery and encryption marker |
| `pep_items` | PEP owner/node/item XML |
| `private_xml` | Per-user namespaced private XML |
| `vcards` | `vcard-temp` payload |
| `muc_rooms` | Room policy, title, owner, subject, capacity |
| `muc_affiliations` | Owner/admin/member/outcast state |
| `muc_messages` | Room history and encryption marker |
| `upload_slots` | File metadata, token digest, expiration, completion state |
| `push_subscriptions` | Push service JID/node/options |
| `invitation_tokens` | Token digest, label, creator, usage/expiration/revocation |
| `abuse_reports` | Reporter, target, category, workflow, resolution |
| `abuse_report_evidence` | Explicitly submitted plaintext evidence in stable order |
| `abuse_appeals` | One appeal per report, workflow, resolution |
| `audit_log` | Actor, action, target, JSON details, optional IP, timestamp |

Foreign keys generally cascade user-owned data on account deletion. The current public administration API disables accounts but does not expose destructive account deletion.

### Files, avatars, and HTTP Upload

An XMPP client requests a slot from `upload.<domain>` with a filename, media type, and exact size. The server creates a 15-minute slot and returns:

- A PUT URL under `/api/v1/upload/{uuid}`.
- A one-use bearer header.
- A GET URL under `/uploads/{uuid}`.

The PUT handler validates the bearer digest, slot expiration/use state, content type, request body limit, and exact bytes written. It streams to a temporary file and renames only after a complete upload. The GET URL is bearer-by-possession and intentionally needs no REST login. Treat it as public ciphertext capability; the browser's AES-GCM key remains inside OMEMO.

Database cleanup removes expired slot metadata every minute. Operators should also monitor the upload directory for orphaned files caused by abnormal host failure; automated orphan reconciliation is not implemented.

The 50 MiB avatar source limit is a browser preprocessing limit, not the XEP-0363 attachment limit. Only the resulting JPEG below 256 KiB is published through PEP/vCard.

### Federation

For an outbound remote domain:

1. Apply enable/deny/allow policy.
2. Use an explicit override if configured.
3. Resolve `_xmpp-server._tcp`; otherwise try port 5269 on the domain.
4. Reject non-public targets unless explicitly allowed.
5. Open TCP with a 10-second connect timeout.
6. Require STARTTLS.
7. Validate the certificate chain and asserted remote DNS name.
8. Require SASL EXTERNAL and authenticate the local domain.
9. Reuse one bounded worker/connection for that remote domain.

Inbound connections similarly require TLS and possession of a certificate valid for the asserted domain before stanzas are accepted. There is no Dialback downgrade path.

Operational cautions:

- Publish correct DNS and keep port 5269 reachable in both directions.
- The certificate SAN must cover the XMPP domain, not merely the host's internal name.
- Keep `FEDERATION_ALLOW_PRIVATE_IPS=false` on public servers.
- An allowlist is safer for a private community; an empty allowlist accepts all domains except deny rules.
- Monitor `xmpp_federation_failures_total` and warning logs.
- There is no durable S2S spool. A restart or extended remote outage can lose pending remote delivery.

### Metrics and logs

`GET /metrics` returns Prometheus text with these names:

| Metric | Type | Meaning |
| --- | --- | --- |
| `xmpp_tcp_connections_total` | counter | Accepted native C2S connections |
| `xmpp_websocket_connections_total` | counter | Accepted WebSocket connections |
| `xmpp_active_sessions` | gauge | Currently bound resources |
| `xmpp_stanzas_in_total` | counter | Parsed IQ/message/presence/control inputs |
| `xmpp_stanzas_out_total` | counter | Written/replayed outbound stanzas |
| `xmpp_registrations_total` | counter | Accounts created since process start |
| `xmpp_authentication_failures_total` | counter | XMPP authentication failures |
| `xmpp_authentication_backend_failures_total` | counter | Database/backend failures during XMPP authentication |
| `xmpp_messages_routed_total` | counter | Accepted routed messages |
| `xmpp_federation_inbound_connections_total` | counter | Accepted S2S connections |
| `xmpp_federation_outbound_deliveries_total` | counter | Stanzas written to outbound S2S |
| `xmpp_federation_failures_total` | counter | Outbound connection/stream failures |
| `xmpp_anti_abuse_challenges_total` | counter | Challenges issued |
| `xmpp_rate_limited_total` | counter | Operations rejected/held by abuse policy |
| `xmpp_reports_total` | counter | Reports created since process start |
| `xmpp_appeals_total` | counter | Appeals created since process start |

Counters are in memory and reset on restart. Database-backed totals are available from the administrator statistics endpoint.

Logs are written to stderr and to rolling `server.log.*` files. Use JSON in production for ingestion. Logs intentionally report protocol/operational events, but operators must still treat logs as sensitive metadata. `.gitignore` and `.dockerignore` exclude logs.

### Testing and release validation

#### Fast static verification

```bash
make format
make check
make test
```

or:

```bash
cargo fmt --all -- --check
cargo check --all-targets --locked
cargo test --all-targets --locked
cargo clippy --all-targets --locked -- -D warnings
```

The same four gates run automatically for every push and pull request in `.github/workflows/ci.yml`. Separate least-privilege jobs check `Cargo.lock` against the RustSec advisory database with the repository's `.cargo/audit.toml` policy and run the JavaScript/i18n static invariants. CI also verifies that Cargo metadata and the full license text remain AGPL-3.0-only/AGPLv3-consistent.

#### WSL offline verification

```powershell
wsl.exe -d Ubuntu-24.04 -- bash /mnt/c/Users/Admin/Documents/XMPP/scripts/verify-wsl.sh all
```

The project-local WSL toolchain/cache is used with `--locked --offline` after dependencies have been fetched.

#### Test database

```bash
sudo -u postgres createuser --login xmpp_test
sudo -u postgres createdb --owner xmpp_test xmpp_test
sudo -u postgres psql -c "ALTER ROLE xmpp_test PASSWORD 'xmpp-test-password'"
```

These are test-only credentials. The fixtures use isolated PostgreSQL schemas and dedicated ports.

| Script | Coverage | Default isolated ports |
| --- | --- | --- |
| `scripts/integration-wsl.sh` | REST, STARTTLS/SASL, WebSocket, roster, PEP, vCard, routing, SM, Carbons, blocking, MUC, upload, push, MAM, metrics | C2S 16422, S2S 16425, HTTP 18480 |
| `scripts/federation-wsl.sh` | Two domains, private DNS overrides, CA/SAN checks, SASL EXTERNAL, PEP/vCard IQ, addressed PEP notifications, bidirectional/offline behavior | 15223/15224, S2S 15268/15269, HTTP 18081/18082 |
| `scripts/load-1000-wsl.sh` | 1,000 authenticated WebSocket resources, active-session metric, pings | C2S 16222, S2S 16269, HTTP 18280 |
| `scripts/backup-restore-wsl.sh` | Private SCRAM PostgreSQL cluster, backup hashes, confirmation guard, database/upload restore, rollback retention | Private Unix socket only |
| `scripts/browser-e2e-wsl.sh` | Three isolated browser contexts: two devices for one account plus a peer, multi-device direct/group OMEMO, encrypted attachment, avatar, admin, mobile layout | C2S 16322, S2S 16326, HTTP 18380 |

The isolated ports are test fixtures, not product defaults. Product defaults remain 5222/5269/8080.

JavaScript static checks:

```bash
node scripts/check-abuse.mjs
node scripts/check-avatar-editor.mjs
node scripts/check-omemo.mjs
node scripts/check-i18n.mjs
node scripts/check-locales.mjs
```

Full release runtime validation:

```bash
bash scripts/release-runtime-validation.sh
```

On Windows, use the PowerShell orchestrator below. It also works when WSL cannot execute Windows binaries: WSL owns only the isolated server processes, while Windows launches and closes its own headless Chrome instance.

```powershell
powershell -ExecutionPolicy Bypass -File scripts/release-runtime-validation.ps1
```

To rerun only the browser matrix, use `scripts/browser-e2e-windows.ps1`. Both PowerShell scripts stop only the exact temporary Northstar PID recorded by `browser-e2e-server-wsl.sh`; they never use broad process-name termination.

It performs shell/Python syntax checks, Rust formatting/check/test/clippy, integration, two-domain federation, 1,000 sessions, a private backup/restore drill, and browser E2E. It is intentionally expensive and requires the prepared PostgreSQL/WSL/browser environment.

Last full runtime verification in this workspace on 2026-08-22 passed all 25 Rust tests, full integration, two-domain federation, 1,000 simultaneous authenticated sessions with sample pings, a private PostgreSQL backup/verification/restore drill, and browser E2E covering two concurrent devices for one account plus a peer, multi-device direct/group OMEMO, encrypted upload/download, avatar processing, administration, and mobile layout. Repeat runtime tests after protocol/security changes and on the deployment host; results are not transferable capacity guarantees.

### Backup, restore, upgrade, and certificate rotation

#### Backup

Back up PostgreSQL and upload bytes as one consistency set. OMEMO browser keys are not on the server and cannot be included in a server backup.

The repository now includes `scripts/backup.sh`, `scripts/verify-backup.sh`, and
the deliberately guarded `scripts/restore-backup.sh`. See
[`docs/PRODUCTION_OPERATIONS.md`](docs/PRODUCTION_OPERATIONS.md) for the exact
online consistency model, off-host encryption responsibility, restore checks,
Prometheus alerts, and the provisioned Grafana dashboard.

For a simple single-node maintenance backup:

1. Stop or quiesce the XMPP service so database metadata and upload files do not change.
2. Create a PostgreSQL custom-format dump with `pg_dump -Fc`.
3. Snapshot/copy the upload volume.
4. Store both with encryption, access control, retention, and an off-host copy.
5. Restart the service and verify readiness.

For zero-downtime backups, use PostgreSQL-native physical backup/snapshot tooling and a storage snapshot procedure that gives a documented consistency point. Merely copying a live upload directory and taking an unrelated database dump can produce slot/file mismatches.

#### Restore drill

1. Restore into an isolated PostgreSQL instance and upload directory.
2. Use the same application version first.
3. Start with federation disabled and non-public bind addresses.
4. Verify migrations, users, MAM rows, PEP device bundles, rooms, reports, and sampled upload sizes.
5. Test login and decrypt history with a retained client device.
6. Only then switch DNS/traffic.

#### Upgrade

1. Read migration and compatibility changes.
2. Back up database and uploads.
3. Run static and runtime release validation.
4. Build with `Cargo.lock` using `--locked`.
5. Deploy one single-node process; migrations run before listeners start.
6. Verify `/readyz`, logs, Gajim login, PEP/OMEMO, MAM, upload, MUC, and federation.
7. Roll back the binary only if the database migration is backward compatible; otherwise restore the coordinated backup.

#### Certificate rotation

1. Atomically replace the configured certificate and key files while preserving ownership/readability.
2. Confirm SAN, expiration, and key match with the production preflight.
3. Call `POST /api/v1/admin/tls/reload` with an administrator bearer token, or restart gracefully.
4. New TLS handshakes use the new config; existing connections continue until they reconnect.
5. Test C2S and S2S externally.

### Repository layout

```text
src/main.rs                 startup, migrations, tasks, shutdown
src/config.rs               environment mapping, defaults, validation, secret files
src/state.rs                shared in-memory state and service construction
src/auth.rs                 Argon2, SCRAM verifier creation, PLAIN/SCRAM SASL
src/abuse.rs                stepped rate limits, PoW, cooldown, challenge lifecycle
src/api/                    REST, WebSocket upgrade, admin, reports, uploads
src/db/                     PostgreSQL queries grouped by domain
src/xmpp/                   C2S/WebSocket framing and protocol session
src/xmpp/protocol/          roster, presence, messaging, PEP, MAM, MUC, SM, etc.
src/s2s/                    DNS, TLS verification, inbound/outbound federation
src/storage.rs              replaceable upload-store trait and local implementation
src/metrics.rs              Prometheus counters/gauge
migrations/                 ordered PostgreSQL schema migrations
web/                        standalone user/admin UI and local language packs
web/crypto/                 vendored GPL-3.0 OMEMO cryptographic core
docs/openapi.yaml           OpenAPI 3.1 REST contract
docs/LOCALIZATION.md        localization source/generation policy
ARCHITECTURE.md             focused architecture/security model
XEP_MATRIX.md               exact protocol compatibility boundary
monitoring/prometheus.yml   sample Prometheus scrape configuration
deploy/                     Caddy, bootstrap Compose override, secret instructions
scripts/                    verification, integration, load, E2E, and release tools
docker-compose.yml          hardened single-node container stack
Dockerfile                  locked multi-stage Rust build and non-root runtime
```

Local certificates, private keys, `.env`, secrets, uploads, logs, database files, build targets, translation tools, and test state are excluded from source control/build context. Before publishing, run the release preflight in a real Git worktree; if the directory is not a Git worktree, tracked-file leak checks cannot run.

### Troubleshooting

#### `failed to load TLS certificate and key`

The server validates TLS before opening listeners. Check:

```bash
ls -l certs/server.crt certs/server.key
openssl x509 -in certs/server.crt -noout -subject -issuer -dates
openssl pkey -in certs/server.key -check -noout
```

Confirm paths are relative to the process working directory, the certificate contains at least one PEM certificate, and the key matches. Generate a temporary self-signed pair only for local testing.

#### Port 5222/5269/8080 is already in use

Identify the exact listener before stopping anything. Do not use broad process-kill commands. Stop the process through the terminal or service manager that owns it. Test fixtures deliberately use other ports to avoid the main service.

#### PostgreSQL connection or migration failure

- Confirm `DATABASE_URL` and `DATABASE_URL_FILE` are not both set.
- Verify host, port, database, role, password, and network policy.
- Run `psql` with the same connection details.
- Start from the repository/application working directory so `migrations/` exists.
- Do not drop the public schema of a production database. Integration scripts use named test schemas.

#### OMEMO device/trust list is empty

Check in this order:

1. Both accounts completed SASL, resource binding, and OMEMO initialization.
2. The publishing account has a device-list PEP item and a bundle item.
3. A request for a genuinely missing node returns `item-not-found`, not an empty successful list.
4. A PEP response for another user carries that user's bare JID in `from`.
5. Account disco info contains the relevant node and `+notify` feature.
6. In group chat, the room is non-anonymous and presence contains real JIDs.
7. Members of a members-only non-anonymous room can retrieve owner/admin/member affiliation lists.
8. Refresh Gajim's trust view. Only after the server responses are correct should you consider removing/re-adding the test account or clearing stale client capability/device cache.

Enable targeted logs temporarily:

```dotenv
RUST_LOG=rust_xmpp_server=debug
```

Never log private keys or decrypted message bodies.

#### Browser says a message was not encrypted to this device

The device may have been created after the message, removed from the sender's cached device list, or lost its local key state. Refresh device lists and verify fingerprints. If the browser profile was erased and no other recipient device was included, the server cannot recover the content.

#### Upload returns 401, 409, or size/type errors

- Use the upload-slot bearer, not a REST login token.
- Use the exact `Content-Type` and exact length requested in XMPP.
- Slots are expiring and one-use.
- A failed/partial write is not committed; request a new slot.
- Compare database metadata with the file size if GET returns an internal error.

#### Wrong client IP in abuse controls

Do not trust arbitrary proxies. The direct proxy IP must exactly match `TRUSTED_PROXY_IPS`. In Compose, keep `CADDY_PROXY_IP`, `FRONTEND_SUBNET`, and `TRUSTED_PROXY_IPS` aligned. Requests from every other peer ignore `X-Forwarded-For`.

#### Federation cannot connect

- Verify allow/deny policy and `FEDERATION_ENABLED`.
- Query `_xmpp-server._tcp` and test port 5269 from outside.
- Verify both certificate chains and SANs.
- Ensure the remote advertises STARTTLS and SASL EXTERNAL.
- Private/special-use DNS results are rejected unless explicitly allowed.
- Review federation counters and warning logs; there is no Dialback fallback.

#### Web UI loads but WebSocket fails

- The endpoint is exactly `/xmpp-websocket` and requires subprotocol `xmpp`.
- Production must use `wss://` through HTTPS.
- Preserve WebSocket upgrade headers in any replacement reverse proxy.
- Check the browser CSP/network console and `/api/v1/config`.

### Known limits and non-goals

- Not every XEP is implemented; transparent routing is not semantic support.
- No multi-node session bus, distributed presence, shared room-occupancy state, or shared object storage.
- Stream Management resumption and abuse state do not survive restart.
- MUC occupancy is not restored by SM resumption.
- No Server Dialback, durable S2S spool, or federated MUC.
- PEP is an OMEMO/avatar-oriented profile, not general-purpose PubSub.
- MUC is a useful local profile, not the complete XEP-0045 matrix.
- No server-side OMEMO private keys, key escrow, or browser key backup/export.
- No automated upload orphan reconciliation or per-user upload quota.
- No per-user private XML quota beyond per-item size.
- No public account-deletion/admin audit-log browsing endpoint in the current REST API.
- Accounts created before migration `0011_scram_credentials.sql` may lack a SCRAM verifier. A successful TLS-protected PLAIN or REST password login creates it; a later password-based login also upgrades a verifier below `SCRAM_ITERATIONS`. A SCRAM-only login cannot upgrade itself because the server never receives the password.
- The PoW eight-second statement is an approximate advertised cap, not dynamic device benchmarking.
- The 1,000-session fixture validates connection retention and sample pings, not 1,000 users continuously sending large encrypted messages.
- Production security and client interoperability require independent review.

### License and third-party code

The Rust server and Northstar-owned interface code are distributed under [GNU AGPL v3 only (`AGPL-3.0-only`)](LICENSE). In particular, operators who modify Northstar and let users interact with that modified version over a network must provide those users access to the corresponding source as required by AGPL section 13. This is a strong network-copyleft license; there is no `or later` option.

`web/crypto/libomemo.js` and its Curve25519 WebAssembly module retain their GPL-3.0 license in `web/crypto/LICENSE-GPL-3.0.txt`. Their source provenance and boundary are described in [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md). Northstar's AGPL license does not replace the third-party component's license. Review both sets of obligations before network deployment or redistribution.

---

## 简体中文

Northstar 是一个使用 Rust 从零开发、面向标准兼容性的单机 XMPP 服务器。一个 Tokio 进程同时提供原生 XMPP 客户端接入、服务器互联、XMPP over WebSocket、独立网页客户端、管理控制台、REST API、PostgreSQL 持久化、Prometheus 指标和滚动日志。

设计目标是在配置合适的单台 Linux 服务器上容纳约 1,000 个同时完成认证的在线用户。当前开发环境已经通过 1,000 会话测试，但这只是设计验证，不能替代在真实硬件、真实消息频率、数据库延迟和历史保留策略下的容量测试。

> **成熟度与范围：** Northstar 0.1.0 是一个经过测试的实现配置和可扩展基础，不代表支持所有 XEP。标记为 `Partial` 的功能仍缺少标准中的部分行为或更广泛的第三方客户端互操作验证。公网部署前请阅读 [XEP_MATRIX.md](XEP_MATRIX.md)、[已知限制](#已知限制与非目标)和安全模型。

> **上线警告：** 仓库中的 `localhost` 证书和开发数据库密码不能用于公网。正式上线必须使用真实域名、覆盖该域名的受信任证书、重新生成的密钥、备份、监控和独立安全审查。

### 中文目录

- [项目目标](#项目目标)
- [功能总览](#功能总览)
- [架构与数据流](#架构与数据流)
- [OMEMO、只有用户能解密的历史与信任](#omemo只有用户能解密的历史与信任)
- [限流、PoW、邀请码、举报和申诉](#限流pow邀请码举报和申诉)
- [本地 Linux/WSL 启动](#本地-linuxwsl-启动)
- [客户端参数](#客户端参数)
- [Docker 正式部署](#docker-正式部署)
- [配置说明](#配置说明)
- [REST API](#rest-api)
- [网页端和多语言](#网页端和多语言)
- [数据库](#数据库)
- [监控与日志](#监控与日志)
- [测试与发布验证](#测试与发布验证)
- [备份、恢复、升级和证书轮换](#备份恢复升级和证书轮换)
- [故障排查](#故障排查)
- [已知限制与非目标](#已知限制与非目标)
- [许可证](#许可证)

### 项目目标

- 标准端口：客户端 `5222`、服务器互联 `5269`、内部网页/API `8080`。
- 原生 TCP 客户端必须先完成 STARTTLS，之后才能认证。
- 同时支持 `SCRAM-SHA-256` 和 TLS 内的 `PLAIN`；建议客户端优先选择 SCRAM。
- 网页端通过 WebSocket 直接使用 XMPP，并在浏览器本地完成 OMEMO 加密。
- 默认只持久化加密历史；明文可以在线转发，但默认不写入 MAM 或离线队列。
- PostgreSQL 保存持久状态，本地目录保存可替换的上传对象。
- 默认开放注册，也可以要求管理员签发邀请码。
- 对 IP、账号和跨操作行为实行分层限流、PoW、硬等待和冷却。
- 提供用户网页端、管理后台、REST API、健康检查、监控和日志。
- 单进程单节点优先；目前不假装已经实现分布式集群。

Northstar 网页界面不是 Converse.js 的换皮版本，也没有赞助商、广告或远程 UI 资源。界面、WebSocket XMPP 状态机和 OMEMO 编排由本仓库实现；`web/crypto/` 中的 X3DH/Double Ratchet 核心是 GPL-3.0 第三方组件。

### 功能总览

#### 连接、TLS 与认证

- 端口 5222 上的 XML 流和强制 STARTTLS。
- `/xmpp-websocket` 上的 RFC 7395 WebSocket 帧，子协议必须为 `xmpp`。
- 正确处理被网络分片拆开的 UTF-8 字符。
- XMPP 缓冲帧和 WebSocket 单消息最大 1 MiB。
- XML 增量分帧会识别引号、注释和 CDATA，并按标签栈平衡元素；嵌套的 Forwarding/Carbons/MAM stanza 不会被内层 `</message>` 截断，同时拒绝 DTD 和超过 256 层的嵌套。
- `SCRAM-SHA-256` 保存盐、迭代次数、stored key 和 server key。
- `PLAIN` 仅在 TLS/WSS 后公布。
- 资源绑定、完整 JID 冲突检测、会话建立、优雅退出。
- 用户名自动转为小写，只允许 3–64 个 ASCII 字母、数字、点、下划线和连字符。
- 密码长度 10–1,024 字节；Argon2 用于 REST/PLAIN 密码验证。
- 被禁用账号无法认证。

#### 单聊、在线状态、联系人和屏蔽

- 完整 JID 与 bare JID 路由。
- bare JID 会选择“在线、优先级非负、优先级最高”的资源；相同优先级采用稳定顺序。
- 联系人列表、订阅状态、待处理订阅和多资源 roster push 持久化。
- 本地与跨服务器 presence 路由。
- 默认只把加密消息写入离线队列和 MAM。
- `no-store`、`no-permanent-store` 会阻止持久化。
- 每个资源独立启用/关闭 Message Carbons。
- 屏蔽列表持久化，并在本地、联邦、消息和 presence 路径双向检查。
- 回执、聊天标记和反应可以透传，但透传不代表服务器维护了它们的完整语义状态。

#### 历史、离线与断线续传

- 发送方和接收方各自拥有 MAM 历史副本。
- 支持 `with`、`start`、`end`、稳定 UUID 游标以及 RSM `before`/`after` 翻页。
- XMPP MAM 每页最多 100 条；REST 历史最多 200 条，默认 100 条。
- 资源上线或成功恢复时投递离线消息。
- 离线消息按 `OFFLINE_MESSAGE_TTL_DAYS` 过期，每分钟清理。
- XEP-0198 计数、确认、内存恢复和未确认消息重放。
- 恢复状态只在当前进程内保存，重启后失效。

#### PEP、OMEMO、头像、vCard 与私有 XML

- 持久化 OMEMO/头像所需的 PEP 节点。
- 一次发布中的多个 `<item>` 会逐个保存。
- 缺少 item ID 时由服务器生成 UUID，并把补全后的 item 保存下来。
- 不存在的 PEP 节点返回 `item-not-found`，而不是“成功但空列表”。这会正确触发 Gajim 初始化自己的设备列表。
- 代答其他用户 PEP 数据时，IQ `from` 是数据所有者的 bare JID。
- disco#info 动态加入已经发布的节点和 `+notify` 特征。
- 向用户自己的其他资源和有订阅权限的联系人发送 PEP 事件，同时检查屏蔽关系。
- 保存 `vcard-temp`、头像 data/metadata PEP 和每项不超过 512 KiB 的私有 XML。

#### 群聊 MUC

- `conference.<域名>` 本地群聊服务发现和公开房间列表。
- 创建、加入、离开、昵称冲突、成员 presence、群历史。
- 群消息、成员私聊/IQ、主题、受控邀请和直接邀请。
- 房主可以配置房间标题、持久/临时、成员制、公开/隐藏、主持模式、匿名性和 2–1,000 人上限。
- 房主可以销毁房间；支持 owner/admin/member/outcast affiliation、角色变更、踢出和封禁。
- 新房间默认 non-anonymous，方便 OMEMO 把房间昵称映射为真实 JID。
- 在成员制、非匿名房间中，普通 member 可以读取 owner/admin/member 名单以建立 OMEMO 接收设备集合，但不能读取 outcast 名单。
- 群历史只保存策略允许的内容；后来加入的人不能解密发送时没有加密给其设备的旧消息。

尚未实现密码房间、跨服务器 MUC、完整 XEP-0045 状态/错误矩阵和全部房间配置字段。

#### HTTP 上传、文件和头像

- `upload.<域名>` XEP-0363 服务发现和上传槽位。
- 槽位带过期时间、只能 PUT 一次，Bearer 密钥在数据库只保存 SHA-256 摘要。
- Content-Type 和最终字节数必须与申请一致。
- 文件先写入 `.part`，完整后原子重命名。
- 下载响应强制 attachment、`nosniff` 和沙箱 CSP，避免把用户上传内容作为同源活动网页执行。
- 网页附件上传前使用 AES-GCM 加密；密钥、IV、名称、类型和大小放入 OMEMO/SCE 密文。
- 头像原图最大 50 MiB，只在浏览器本地解码、预览、拖动、缩放、旋转、裁切和压缩；最终只发布小于 256 KiB 的 JPEG。

#### 服务器互联

- 默认监听 5269。
- 查询 `_xmpp-server._tcp`，没有可用 SRV 时回退到域名的 5269。
- DNS 结果缓存一小时。
- 强制 STARTTLS，校验证书链、远端域名和 SASL EXTERNAL。
- 支持精确域名和 `*.` 通配 allow/deny；deny 优先。
- 默认拒绝私网、回环、链路本地、多播、文档地址、未指定地址等特殊目标，减少 SSRF 风险。
- 支持测试/受控网络的 DNS override 和额外 CA。
- 联邦总路由队列上限 10,000，每个远端域工作队列 100。

没有 Server Dialback、持久重试队列和跨服务器 MUC。进程重启或远端长时间故障可能丢失尚未完成的跨服投递。

#### 管理、举报与运行维护

- REST 注册、登录、当前用户、修改密码、读取加密历史。
- REST token 为随机 64 字符，数据库只保存 SHA-256 摘要。
- 管理员查看账号、禁用/启用、提升/取消管理员，并防止当前管理员禁用或降级自己。
- 邀请码只在创建响应中显示一次，支持到期、撤销和原子使用次数。
- 用户可以明确选择 1–20 条已解密聊天记录提交举报。
- 举报类别为垃圾信息、骚扰、威胁、冒充、违法内容或其他。
- 举报状态：`submitted`、`reviewing`、`actioned`、`rejected`、`closed`。
- 每个举报最多一次申诉；申诉状态：`submitted`、`reviewing`、`upheld`、`denied`。
- 管理员可以热加载证书，用于之后的新 TLS 握手。
- 注册、改密、用户管理、举报、申诉、邀请和证书重载写入审计表。
- 提供健康、就绪、Prometheus 指标和管理统计。

### 架构与数据流

单个进程有三个监听器：

| 监听器 | 默认地址 | 用途 |
| --- | ---: | --- |
| C2S TCP | `0.0.0.0:5222` | 原生 XMPP 与 STARTTLS |
| S2S TCP | `0.0.0.0:5269` | 经过认证的服务器互联 |
| HTTP | `0.0.0.0:8080` | 网页、REST、WebSocket、上传、健康和指标 |

PostgreSQL 保存账号、联系人、屏蔽、历史、离线、PEP、vCard、群、槽位、推送、邀请、举报和审计。在线资源、SM 恢复、房间在线成员、PoW 状态、联邦连接和 DNS 缓存保存在内存中，因此当前设计是单节点。

启动顺序：读取 `.env` 和环境变量 → 读取可选 secret 文件 → 初始化日志 → 安装 TLS 加密提供者 → 连接 PostgreSQL → 从 `migrations/` 执行迁移 → 创建可选初始管理员 → 校验证书和私钥 → 创建共享状态 → 启动清理任务和三个监听器。`Ctrl+C`/`SIGTERM` 会关闭监听器、等待 HTTP 收尾并正常退出。

原生运行时必须把项目目录作为工作目录，因为程序会从相对路径读取 `migrations/` 和 `web/`。Docker 镜像已经把它们复制到 `/app`。

#### 原生客户端连接流程

1. 客户端连接 5222 并打开 XML stream。
2. 加密前服务器只公布“必须 STARTTLS”。
3. TLS 成功后重开 stream，公布 SCRAM-SHA-256、PLAIN 和符合策略的带内注册。
4. SASL 成功后再次重开 stream，公布资源绑定和 Stream Management。
5. 完整 JID 写入内存 session map；重复完整 JID 返回 `conflict`。
6. 首个 available presence 设置资源优先级、向授权联系人广播并取出离线消息。

WebSocket 在 XMPP 层被视为已经由外层保护；正式环境必须由 Caddy 提供 HTTPS/WSS，明文 `ws://` 只适用于本地测试。

#### 单聊消息路径

1. 验证已经认证、绑定资源并且目标 JID 合法。
2. 内容消息经过 IP、账号和行为限流；Northstar PoW XML 在转发前删除。
3. 双向检查屏蔽规则。
4. 远端域交给 S2S 路由器。
5. 本地加密消息在没有 no-store 时分别写入双方历史；默认不保存明文。
6. bare JID 选择最佳资源，其他启用 Carbons 的资源获得副本。
7. 没有在线资源时，加密消息进入离线队列并尝试发送最小化 push；默认拒绝离线明文。

群消息要求发送方已经在房间内，房间检查 affiliation/role，把来源改写为 `房间@conference.域名/昵称`，广播给成员并按策略保存历史。OMEMO 群密钥完全由客户端为当前成员设备构造，服务器不会生成群密钥。

### OMEMO、只有用户能解密的历史与信任

当发送方确实使用 OMEMO 2 时，服务器只保存公开设备资料和加密信封，不拥有浏览器私钥。网页客户端也不会把已解密聊天正文持久保存到 IndexedDB，而是从 MAM 重新取回密文并在内存解密。

必须理解以下边界：

- 客户端发送明文时服务器当然能看到明文。
- `REQUIRE_ENCRYPTED_ARCHIVE=true` 只禁止明文落盘，并不能让正在转发的明文对服务器不可见。
- 服务器仍能看到 JID、时间、在线状态、房间成员、设备 ID、结构和近似大小等元数据。
- 浏览器私钥依赖同源隔离和本机操作系统账户，不存在额外的 Northstar 私钥密码层。
- 当前没有 OMEMO 密钥备份/导出界面。清除站点数据、丢失浏览器配置或丢失所有设备私钥后，旧历史可能永久无法恢复。
- 新加入群聊的成员不能解密之前没有包含其设备 key envelope 的消息。
- 举报是有意跨越端到端加密边界的操作：只有用户明确选中的明文证据才会提交给管理员。

网页端流程是：生成身份密钥/签名预密钥/一次性预密钥/设备 ID → 私钥写入 IndexedDB → 公钥列表与 bundle 发布到 PEP → 获取对方设备 → 为对方所有设备和自己的其他设备建立 Double Ratchet 会话 → 构造 OMEMO 2/SCE 密文 → 接收设备在本地推进 ratchet 并解密。

网页端采用 TOFU。首次看到的身份会记录；之后身份密钥发生变化时界面会显示为 changed，不会默认为同一身份。敏感通信前仍应当通过其他可信渠道核对指纹。

### 限流、PoW、邀请码、举报和申诉

#### 限制对象

- 注册：源 IP 加全站每小时成功注册总量。
- 登录失败：源 IP。
- 消息、举报、申诉：源 IP、用户 ID、共享的 `behavior:<用户>`；一种行为上的处罚可以影响其他行为。
- 这些计数、PoW challenge 和冷却状态位于内存，重启会清空；账号、邀请和举报不会清空。
- 只有直接连接 IP 在 `TRUSTED_PROXY_IPS` 内时，才采用 `X-Forwarded-For`。

#### 工作量公式

```text
step = max(窗口内事件数 + 1 - 免费次数, 0)
work_factor = min(操作基础量 × step² × 2^处罚等级, 最大工作量)
```

| 操作 | 免费次数 | 基础工作量 | 额外规则 |
| --- | ---: | ---: | --- |
| 注册 | 1 | 当前策略不要求常规计算 PoW | IP 台阶/硬等待 + 全站每小时上限 |
| 登录 | 5 次失败 | `POW_BASE_WORK_FACTOR` | 成功登录不增加失败事件 |
| 发消息 | 6 条内容消息 | `POW_BASE_WORK_FACTOR` | presence、回执和聊天状态不算内容消息 |
| 举报 | 0 | 基础量的 2 倍 | 第一份举报立即要求 PoW |
| 申诉 | 0 | 基础量的 8 倍 | 立即 PoW，且至少硬等待 15 秒 |

默认硬等待台阶：step 0–3 为 0 秒、4–7 为 2 秒、8–11 为 10 秒、12–15 为 30 秒、之后为 120 秒。处罚等级会指数放大工作量和等待，但不超过 `ABUSE_MAX_WAIT_SECONDS`。停止活动后，每经过一个 `ABUSE_COOLDOWN_SECONDS` 降低一级处罚。

“中端手机最多约八秒”是界面提示和设计目标，并不是针对当前设备实时标定。真实耗时取决于 CPU、浏览器、电源策略和配置的最大工作量。

Challenge 具有 UUID、随机前缀、操作、主体、要求和有效期；只使用一次；最新 challenge 会作废同一操作/主体的旧 challenge；不能跨操作、跨账号使用；不能在硬等待结束前使用；事件台阶变化后也会失效。nonce 只能是最多 64 位十进制数字。服务器计算 `SHA-256(prefix || nonce)`，其前 64 位必须不大于 `u64::MAX / work_factor`。错误、重放、不足的 proof 或在一个窗口内申请超过 30 次 challenge 会增加处罚。

不理解扩展的标准客户端在免费次数内正常工作。被限制后会收到标准 `resource-constraint` 加 Northstar 重试信息，可以等待冷却；网页端会自动在 Worker 中计算并向用户显示工作量和等待。

邀请码启用后，REST 注册必须提供有效 token。列表永不返回 token 明文，创建响应只显示一次。数据库在创建用户的同一事务中检查是否撤销、过期和超过使用次数。由于当前 XEP-0077/0389 表单没有邀请码字段，邀请码模式下不会公布这些注册方式。

举报必须选择 1–20 条消息，每条正文 1–8,000 字符，补充说明最多 4,000 字符。管理员处理到终态时必须写处理说明。每个举报最多申诉一次；申诉理由 20–4,000 字符，采用更严格的 PoW 和硬等待。

### 本地 Linux/WSL 启动

#### 创建开发数据库

```bash
sudo -u postgres createuser --login --pwprompt northstar
sudo -u postgres createdb --owner northstar northstar
```

#### 创建仅供本地使用的自签证书

```bash
mkdir -p certs
openssl req -x509 -newkey rsa:2048 -nodes -days 30 \
  -subj "/CN=localhost" \
  -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" \
  -keyout certs/server.key \
  -out certs/server.crt
chmod 600 certs/server.key
```

公网服务绝不能让用户忽略证书警告。

#### 配置并启动

```bash
cp .env.example .env
```

至少修改开发数据库连接，然后在项目根目录前台启动：

```bash
cargo fmt --all -- --check
cargo check --all-targets --locked
cargo test --all-targets --locked
cargo run --locked
```

不需要向 `cargo run` 传入源文件名。按 `Ctrl+C` 正常停止。启动后：

- Gajim/原生客户端：`localhost:5222`
- 服务器互联：`localhost:5269`
- 网页和 API：`http://localhost:8080`

```bash
curl --fail http://localhost:8080/healthz
curl --fail http://localhost:8080/readyz
curl --fail http://localhost:8080/api/v1/config
```

WSL 可以完整验证：

```powershell
wsl.exe -d Ubuntu-24.04 -- bash /mnt/c/Users/Admin/Documents/XMPP/scripts/verify-wsl.sh all
```

并在可见的 WSL 终端中由你自己启动：

```bash
cd /mnt/c/Users/Admin/Documents/XMPP
cargo run --locked
```

### 客户端参数

| 项目 | 值 |
| --- | --- |
| JID | `用户名@XMPP_DOMAIN` |
| 主机/端口 | `XMPP_DOMAIN:5222` |
| TLS | 必须 STARTTLS |
| SASL | 优先 `SCRAM-SHA-256` |
| WebSocket | `wss://XMPP_DOMAIN/xmpp-websocket`，子协议 `xmpp` |
| 群聊服务 | `conference.XMPP_DOMAIN` |
| 上传服务 | `upload.XMPP_DOMAIN` |

Gajim 新账号应先连接、启用 OMEMO、等待其发布设备列表/bundle，再添加联系人和加入群聊。敏感消息发送前在 Manage Trust 中核对指纹。群聊必须能够看到成员真实 JID，服务器才有条件让客户端建立完整接收设备集合。

### Docker 正式部署

1. 为真实域名设置 A/AAAA，建议同时发布 `_xmpp-client._tcp` 的 5222 和 `_xmpp-server._tcp` 的 5269 SRV。
2. 开放 TCP 80、443、5222、5269；不要暴露 PostgreSQL 和内部 8080。
3. 复制 `.env.example` 为 `.env`，设置真实 `XMPP_DOMAIN`、`PUBLIC_URL=https://域名`、证书和私钥的宿主机绝对路径。
4. XMPP 容器使用 UID 10001，必须能只读访问两个 TLS 文件。证书 SAN 必须覆盖 XMPP 域名。
5. 生成密钥：

```bash
bash scripts/create-production-secrets.sh
```

它会生成权限 0600 的 PostgreSQL 密码、数据库 URL 和初始管理员密码，并拒绝覆盖已有文件，也不会把明文打印到日志。

6. 运行上线检查：

```bash
bash scripts/release-preflight.sh --production
```

7. 首次启动时挂载 bootstrap override：

```bash
docker compose -f docker-compose.yml -f deploy/docker-compose.bootstrap.yml up --build -d
```

8. 以初始管理员登录并立刻修改密码，然后只用基础 Compose 重新创建 XMPP 服务：

```bash
docker compose up -d --force-recreate xmpp
```

确认新密码有效后，安全删除 `deploy/secrets/bootstrap_admin_password`。数据库运行密钥继续保留。

Compose 中 PostgreSQL 只在 internal backend 网络；XMPP 根文件系统只读、全部 capability 被移除、启用 no-new-privileges；TLS 只挂载两个指定文件；Caddy 使用固定私网地址；8080 只绑定宿主机回环；公网 `/metrics` 返回 404。

### 配置说明

完整默认模板位于 [.env.example](.env.example)。运行时从环境变量读取；原生启动会自动加载项目根目录的 `.env`。除数据库 URL 必填外，未设置的项目使用代码默认值。

#### 核心、网络与数据库

| 变量 | 默认值 | 中文说明 |
| --- | --- | --- |
| `XMPP_DOMAIN` | `localhost` | 服务域名，转小写并验证 DNS label，总长最多 253 |
| `PUBLIC_URL` | 本地 `http://localhost:8080`，公网默认 HTTPS 域名 | 生成上传 URL 的 HTTP(S) 基址 |
| `XMPP_BIND` | `0.0.0.0:5222` | 原生客户端监听 |
| `S2S_BIND` | `0.0.0.0:5269` | 服务器互联监听 |
| `HTTP_BIND` | `0.0.0.0:8080` | 网页、API、WebSocket、上传和指标 |
| `TRUSTED_PROXY_IPS` | `127.0.0.1,::1` | 允许提供 `X-Forwarded-For` 的直接代理 IP |
| `DATABASE_URL` | 必填 | PostgreSQL URL；与文件形式二选一 |
| `DATABASE_URL_FILE` | 未设置 | 保存完整 URL 的 secret 文件 |
| `DATABASE_MAX_CONNECTIONS` | `32` | 连接池最大值，必须大于 0 |
| `DATABASE_MIN_CONNECTIONS` | `2` | 连接池最小值，不能大于最大值 |
| `SCRAM_ITERATIONS` | `600000` | 新建或升级 SCRAM verifier 的 PBKDF2-HMAC-SHA-256 工作因子；允许范围 `4096..=10000000` |

#### 注册、会话和持久化

| 变量 | 默认值 | 中文说明 |
| --- | ---: | --- |
| `OPEN_REGISTRATION` | `true` | 允许符合策略的 REST/带内注册 |
| `INVITATION_REQUIRED` | `false` | REST 注册要求管理员邀请码，并隐藏不兼容的 IBR |
| `REGISTRATION_RATE_PER_HOUR` | `20` | 全站滚动一小时成功注册上限；IP 限制另算 |
| `SESSION_TTL_HOURS` | `168` | REST token 有效期，范围 1–8,760 |
| `SM_RESUME_TIMEOUT_SECONDS` | `300` | 内存 SM 恢复时间，范围 1–86,400 |
| `OFFLINE_MESSAGE_TTL_DAYS` | `30` | 离线消息保留，范围 1–3,650 |
| `REQUIRE_ENCRYPTED_ARCHIVE` | `true` | 只持久化识别为加密的消息，默认拒绝离线明文 |
| `BOOTSTRAP_ADMIN_USERNAME` | 未设置 | 可选初始管理员名，必须与密码同时设置 |
| `BOOTSTRAP_ADMIN_PASSWORD` | 未设置 | 直接密码；生产优先使用文件 |
| `BOOTSTRAP_ADMIN_PASSWORD_FILE` | 未设置 | 初始管理员密码 secret 文件 |

#### TLS、上传、联邦与反滥用

| 变量 | 默认值 | 中文说明 |
| --- | --- | --- |
| `TLS_CERT_PATH` | `certs/server.crt` | 启动/热重载读取的 PEM 证书链 |
| `TLS_KEY_PATH` | `certs/server.key` | 与证书匹配的 PEM 私钥 |
| `UPLOAD_DIR` | `data/uploads` | 本地上传对象目录 |
| `UPLOAD_MAX_BYTES` | `26214400` | XEP-0363 上限，默认 25 MiB |
| `FEDERATION_ENABLED` | `true` | 启用 S2S |
| `FEDERATION_ALLOWLIST` | 空 | 精确域名或 `*.后缀`；空表示除 deny 外都允许 |
| `FEDERATION_DENYLIST` | 空 | 精确/通配拒绝项，优先于 allow |
| `FEDERATION_ALLOW_PRIVATE_IPS` | `false` | 是否允许私网/特殊 S2S 目标，公网不要开启 |
| `FEDERATION_DNS_OVERRIDES` | 空 | `域名=IP:端口`，多项逗号分隔 |
| `FEDERATION_EXTRA_ROOT_CERT_PATH` | 未设置 | 额外受信任 CA |
| `POW_BASE_WORK_FACTOR` | `1024` | 登录/消息基础工作量 |
| `POW_MAX_WORK_FACTOR` | `524288` | 工作量硬上限，不能小于基础量 |
| `ABUSE_WINDOW_SECONDS` | `60` | 事件统计窗口 |
| `ABUSE_COOLDOWN_SECONDS` | `60` | 处罚下降一级所需静默时间 |
| `ABUSE_MAX_WAIT_SECONDS` | `900` | 硬等待上限 |

#### 日志与 Compose

日志默认写入 `logs`，按天轮转，文本格式，最多保留 30 个文件。`LOG_ROTATION` 只接受 `minutely/hourly/daily/never`，`LOG_FORMAT` 只接受 `text/json`。`RUST_LOG` 控制 tracing 过滤器。

Compose 额外使用 `FRONTEND_SUBNET`、`CADDY_PROXY_IP`、`XMPP_HTTP_IP`、两个 TLS 宿主机路径和三个 secret 文件路径。这些是容器编排参数，不是 Rust `RawConfig` 的业务字段。

直接 secret 与对应 `_FILE` 不能同时设置。secret 文件必须是小于 64 KiB 的普通文件，不能空、不能含 NUL；只删除末尾换行，不删除 secret 两侧的普通空格。

### REST API

权威契约位于 [docs/openapi.yaml](docs/openapi.yaml)。接口分为公开、普通用户 Bearer、管理员 Bearer 和上传槽位 Bearer 四种认证级别。

| 方法与路径 | 用途 |
| --- | --- |
| `GET /healthz` | 进程存活 |
| `GET /readyz` | PostgreSQL 可用 |
| `GET /metrics` | Prometheus 文本；生产公网应屏蔽 |
| `GET /api/v1/config` | 公开域名、注册、历史、服务和 PoW 配置 |
| `POST /api/v1/register` | 按开放注册/邀请/限流策略创建账号 |
| `POST /api/v1/login` | 创建 REST Bearer session |
| `POST /api/v1/anti-abuse/challenge` | 获取注册/登录/消息/举报/申诉 challenge |
| `GET /api/v1/me` | 当前账号 |
| `PATCH /api/v1/me/password` | 验证旧密码、修改并撤销全部 REST session |
| `GET /api/v1/history` | 读取当前用户历史，可带 `with`、`limit` |
| `GET/POST /api/v1/reports` | 查看或提交举报 |
| `POST /api/v1/reports/{id}/appeals` | 对一份已处理举报提交一次申诉 |
| `PUT /api/v1/upload/{id}` | 精确填充 XEP-0363 槽位 |
| `GET /uploads/{id}` | 通过不透明 URL 下载不可变字节 |
| `GET /api/v1/admin/stats` | 运行统计 |
| `GET /api/v1/admin/users` | 账号分页列表，每页 1–200 |
| `PATCH /api/v1/admin/users/{id}` | 启用、禁用、提升、降级 |
| `GET /api/v1/admin/reports` | 举报、证据和申诉队列 |
| `PATCH /api/v1/admin/reports/{id}` | 更新举报状态/结果 |
| `PATCH /api/v1/admin/appeals/{id}` | 更新申诉状态/结果 |
| `GET/POST /api/v1/admin/invitations` | 列出元数据或创建一次性显示的 token |
| `DELETE /api/v1/admin/invitations/{id}` | 撤销邀请 |
| `POST /api/v1/admin/tls/reload` | 原子加载证书/私钥供新握手使用 |

REST 登录返回的 token 通过 `Authorization: Bearer <token>` 使用。上传 PUT 的 Bearer 是 XMPP 槽位返回的一次性 token，不能拿 REST 登录 token 代替。

最小示例：

```bash
BASE=http://localhost:8080
curl --fail-with-body -X POST "$BASE/api/v1/register" \
  -H 'Content-Type: application/json' \
  --data '{"username":"alice","password":"correct-horse-battery-staple"}'

curl --fail-with-body -X POST "$BASE/api/v1/login" \
  -H 'Content-Type: application/json' \
  --data '{"username":"alice","password":"correct-horse-battery-staple"}'
```

### 网页端和多语言

`/client.html` 提供注册/登录、联系人、presence、搜索、屏蔽、单聊、群聊、OMEMO 设备、指纹、MAM、Carbons、自动重连、加密附件、举报、申诉和头像裁切。退出后密码从内存删除，OMEMO 私钥仍保留在当前浏览器；已解密聊天正文不持久缓存。

默认语言是英语。Recommend 区包含 English、简体中文、`中華民國語 (Traditional Chinese)`、한국어、日本語、Español、Français、Deutsch。完整列表按英文名排序并可搜索，目前保留 84 种资料足够的语言，包括世界语和拉丁语。8 种核心语言人工维护，其余静态包由本地开源 MADLAD-400 3B-MT 生成；选择机器翻译语言时持续显示“可能有错误”的提示。运行时不会把界面文本发给在线翻译服务。

首页的管理区可查看账号、在线资源、历史/离线、房间/成员、上传、push、联邦、举报、申诉、邀请、限流和运行时间；还可以创建/撤销邀请、处理举报/申诉和修改账号状态。REST API 另外提供证书热重载。

网页静态资源全部本地提供。应用层设置 CSP、`nosniff` 和 no-referrer；生产 Caddy 进一步设置 HSTS、referrer policy 和 permissions policy。

### 数据库

程序启动时按文件名顺序执行 `migrations/`。已经上线并执行过的迁移不能直接修改，应当新增下一编号迁移。

| 表 | 持久责任 |
| --- | --- |
| `users` | 账号、Argon2、SCRAM verifier、管理员/禁用状态 |
| `api_sessions` | token SHA-256 摘要和过期时间 |
| `roster_items` | 联系人、订阅、ask、分组 |
| `pending_presence_subscriptions` | 本地待处理订阅 |
| `federated_presence_pending` | 跨服待处理订阅 |
| `blocked_jids` | 屏蔽规则 |
| `message_archive` | 每用户 MAM stanza、peer、加密标记、时间 |
| `offline_messages` | 待投递 stanza |
| `pep_items` | 用户/node/item XML |
| `private_xml` | 按命名空间保存的私有 XML |
| `vcards` | vCard payload |
| `muc_rooms` | 房间策略、标题、房主、主题、人数 |
| `muc_affiliations` | owner/admin/member/outcast |
| `muc_messages` | 群历史 |
| `upload_slots` | 文件元数据、token 摘要、过期/完成状态 |
| `push_subscriptions` | push 服务 JID/node/options |
| `invitation_tokens` | 摘要、标签、次数、过期、撤销 |
| `abuse_reports` | 举报目标、类型、流程、结果 |
| `abuse_report_evidence` | 用户明确提交的明文证据 |
| `abuse_appeals` | 每举报一次申诉及其处理 |
| `audit_log` | 操作者、动作、目标、JSON 详情和时间 |

外键通常会在删除用户时级联清理用户所属数据。当前公开管理 API 以禁用账号为主，没有提供破坏性的账号删除接口。

### 上传文件和头像

客户端向 `upload.<域名>` 申请包含文件名、类型和精确大小的槽位。服务器返回 PUT URL、一次性 Bearer 和 GET URL。PUT 会检查 token 摘要、有效期、是否已用、Content-Type、HTTP body 上限和最终字节数；只有完整写入才把临时文件原子重命名。

GET URL 是“持有链接即可下载”，不要求 REST 登录。网页端上传的是 AES-GCM 密文，解密 key 在 OMEMO 消息中，所以链接应被视为公开密文 capability。每分钟清理过期槽位元数据；异常主机故障可能留下孤儿文件，目前没有自动对账清理。

50 MiB 是头像原图在浏览器中的预处理上限，不是附件上限；最终只把小于 256 KiB 的 JPEG 发布到 PEP/vCard。

### 服务器互联细节

出站顺序：应用 enable/deny/allow → 使用 override 或查 SRV → 拒绝不允许的特殊地址 → 10 秒内建立 TCP → 要求 STARTTLS → 验证证书链和远端 DNS 域名 → 要求 SASL EXTERNAL → 为该远端域复用一个有界 worker/连接。

入站同样要求 TLS 和覆盖声明域名的证书，在域名认证前不接受业务 stanza。没有 Dialback 降级路径。公网应保持 `FEDERATION_ALLOW_PRIVATE_IPS=false`，监控 `xmpp_federation_failures_total`；由于没有持久 S2S spool，重启和长故障可能丢失待投递消息。

### 监控与日志

Prometheus 指标包括：

- `xmpp_tcp_connections_total`、`xmpp_websocket_connections_total`
- `xmpp_active_sessions`
- `xmpp_stanzas_in_total`、`xmpp_stanzas_out_total`
- `xmpp_registrations_total`、`xmpp_authentication_failures_total`、`xmpp_authentication_backend_failures_total`
- `xmpp_messages_routed_total`
- `xmpp_federation_inbound_connections_total`
- `xmpp_federation_outbound_deliveries_total`
- `xmpp_federation_failures_total`
- `xmpp_anti_abuse_challenges_total`、`xmpp_rate_limited_total`
- `xmpp_reports_total`、`xmpp_appeals_total`

这些进程内计数重启后清零；数据库累计数量可通过管理员统计获得。

日志同时输出到 stderr 和滚动 `server.log.*`。生产建议使用 JSON。日志即使不含明文正文，也可能含账号、域名和错误等敏感元数据，必须限制访问并避免上传到源码仓库。

### 测试与发布验证

快速检查：

```bash
cargo fmt --all -- --check
cargo check --all-targets --locked
cargo test --all-targets --locked
cargo clippy --all-targets --locked -- -D warnings
```

`.github/workflows/ci.yml` 会在每次 push 和 pull request 自动执行上述四项门禁；独立的最小权限 job 会按 `.cargo/audit.toml` 策略使用 RustSec 检查 `Cargo.lock`，并运行 JavaScript/i18n 静态约束，同时验证 Cargo 元数据与完整许可证文本仍一致为 `AGPL-3.0-only`/AGPLv3。

完整验证：

```bash
bash scripts/release-runtime-validation.sh
```

Windows 环境建议从 PowerShell 运行下列编排器；即使 WSL 禁止直接执行 Windows `.exe`，它仍可让 WSL 只负责隔离测试服务，再由 Windows 启动并关闭独立的无头 Chrome：

```powershell
powershell -ExecutionPolicy Bypass -File scripts/release-runtime-validation.ps1
```

只重跑网页矩阵可使用 `scripts/browser-e2e-windows.ps1`。清理逻辑只终止 `browser-e2e-server-wsl.sh` 记录且验证过可执行文件路径的临时 Northstar PID，不使用按进程名批量终止。

测试矩阵：

| 脚本 | 覆盖内容 | 隔离端口 |
| --- | --- | --- |
| `integration-wsl.sh` | REST、TLS/SASL、WebSocket、roster、PEP、vCard、SM、Carbons、MUC、上传、push、MAM、指标 | 16422/16425/18480 |
| `federation-wsl.sh` | 两个域、私有 DNS override、CA/SAN、EXTERNAL、PEP/vCard IQ、带地址的 PEP 通知、双向与离线 | 15223/15224、15268/15269、18081/18082 |
| `load-1000-wsl.sh` | 1,000 认证 WebSocket 资源、指标、ping | 16222/16269/18280 |
| `backup-restore-wsl.sh` | 私有 SCRAM PostgreSQL、备份哈希、确认保护、数据库/上传恢复、旧文件保留 | 仅私有 Unix socket |
| `browser-e2e-wsl.sh` | 三个隔离网页上下文：同一账号双设备加一个通信方，多设备 OMEMO 单聊/群聊、附件、头像、管理、手机布局 | 16322/16326/18380 |

测试脚本使用独立 schema 和测试端口，不是产品默认端口，也不会抢占正式 5222/5269/8080。

2026-08-22 在当前环境最后一次完整运行时验证通过：25/25 个 Rust 测试、完整协议集成、双域联邦、1,000 个同时认证会话与抽样 ping、私有 PostgreSQL 备份/校验/恢复演练，以及覆盖同一账号两个并发设备和一个通信方、多设备 OMEMO 加密单聊/群聊、加密附件、头像、管理后台和移动布局的浏览器 E2E。协议或安全代码变更后必须重跑运行时矩阵，上线机器也必须重跑，不能把这次结果当作其他硬件的容量保证。

### 备份、恢复、升级和证书轮换

服务器备份必须把 PostgreSQL 与上传目录作为同一个一致性集合。服务器不拥有浏览器 OMEMO 私钥，因此无法替用户备份或恢复这些私钥。

简单维护备份应当：停止或暂停写入 → 使用 `pg_dump -Fc` → 快照/复制上传卷 → 对两者加密和异地保存 → 重启并验证 ready。直接复制正在变化的上传目录，再在另一个时间点导出数据库，可能造成槽位元数据与文件不一致。

恢复演练应在隔离数据库、隔离上传目录和非公网端口完成；先用相同程序版本，关闭联邦，验证迁移、账号、MAM、PEP bundle、群、举报和上传，再用仍保留私钥的真实客户端抽样解密历史，最后才切换流量。

升级前先备份、运行完整验证并使用 `Cargo.lock`/`--locked` 构建。迁移在监听器启动前执行。上线后验证 ready、日志、Gajim、PEP/OMEMO、MAM、上传、MUC 和联邦。数据库迁移不向后兼容时不能只回退二进制，必须恢复协调备份。

证书更新后，先检查 SAN、到期时间和公私钥匹配，再调用管理员 `POST /api/v1/admin/tls/reload` 或正常重启。新握手使用新证书，已经建立的连接继续使用原会话直到重连。

### 故障排查

#### 找不到 TLS 证书/私钥

服务器会在打开端口前校验证书。确认 `.env` 路径、工作目录、文件权限、PEM 内容和公私钥匹配。自签证书只能用于本地。

#### 端口占用

先确认具体监听进程，再通过它所属的终端或服务管理器停止。不要使用范围过大的 kill 命令。集成测试已经使用独立端口。

#### 数据库/迁移失败

确认 `DATABASE_URL` 与 `DATABASE_URL_FILE` 没有同时设置，连接信息和权限正确，并从包含 `migrations/` 的应用工作目录启动。绝不能在正式库中执行测试脚本的 schema 删除操作。

#### Gajim Manage Trust 为空

按顺序检查：双方完成认证和 OMEMO 初始化 → 发布者有 device list 和 bundle → 不存在节点返回 `item-not-found` → 读取他人 PEP 的 IQ `from` 正确 → disco 中有节点和 `+notify` → 群为非匿名且 presence 带真实 JID → 成员制房间的 member 可读 owner/admin/member 名单。服务器响应全部正确后，才考虑刷新 Gajim、移除后重新添加测试账号或清理陈旧 capability/device 缓存。

临时开启：

```dotenv
RUST_LOG=rust_xmpp_server=debug
```

不得记录私钥或已解密正文。

#### 浏览器提示没有加密给本设备

该设备可能在消息发送后才创建、当时不在对方设备列表，或者本地私钥已经丢失。刷新设备列表并检查指纹。如果原浏览器数据被删除且没有其他被包含的设备，服务器无法恢复正文。

#### 上传失败

PUT 必须使用槽位 token、完全一致的 Content-Type 和字节数；槽位过期且只能使用一次。部分写入不会提交，应重新申请槽位。

#### IP 限流不正确

只有直接代理 IP 精确位于 `TRUSTED_PROXY_IPS` 时才信任转发头。Compose 中必须同时调整 Caddy 固定 IP、frontend 子网和 trusted proxy，不能直接信任任意来源的 `X-Forwarded-For`。

#### 联邦失败

检查 enable/allow/deny、SRV、外部 5269 连通性、双方证书链和 SAN、STARTTLS、SASL EXTERNAL，以及 DNS 是否解析到默认会拒绝的私网/特殊地址。Northstar 不会降级到 Dialback。

#### 网页能打开但 WebSocket 失败

确认路径为 `/xmpp-websocket`、子协议为 `xmpp`、公网使用 `wss://`，并确保替换的反向代理保留 WebSocket upgrade 头。查看浏览器 CSP/Network 和 `/api/v1/config`。

### 已知限制与非目标

- 不支持所有 XEP；只透传 XML 不等于语义支持。
- 没有多节点 session bus、分布式 presence、共享群成员状态或共享对象存储。
- SM 恢复和反滥用状态重启后失效。
- SM 恢复不会恢复 MUC 在线成员状态。
- 没有 Server Dialback、持久 S2S 重试队列和跨服 MUC。
- PEP 面向 OMEMO/头像，不是通用 PubSub。
- MUC 是可用的本地子集，不是完整 XEP-0045。
- 服务器没有 OMEMO 私钥、托管解密或浏览器密钥导出/备份。
- 没有自动清理上传孤儿文件和每用户上传配额。
- 私有 XML 只有单项大小限制，没有每用户总配额。
- 当前 REST 没有公开账号删除和审计日志浏览接口。
- “最大约八秒 PoW”是近似设计提示，不是动态硬件标定。
- 1,000 会话测试主要验证连接保持和抽样 ping，不代表 1,000 人持续发送大体积密文时仍满足同样指标。
- 公网上线仍需要独立安全审查和目标客户端互操作测试。

### 许可证

Rust 服务端和 Northstar 自有界面代码严格使用 [GNU AGPL v3 only（`AGPL-3.0-only`）](LICENSE)，不包含 `or later` 选项。特别是：修改 Northstar 后通过网络向用户提供服务的运营者，必须依照 AGPL 第 13 条向这些用户提供相应源码。`web/crypto/libomemo.js` 与 Curve25519 WebAssembly 模块保留 GPL-3.0，许可证位于 `web/crypto/LICENSE-GPL-3.0.txt`，来源和边界见 [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md)。Northstar 的 AGPL 不会替代第三方组件许可证；上线或分发修改版前应同时审查两者义务。
