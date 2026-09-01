**English** | [繁體中文](README.zh-TW.md)

# Northstar XMPP Server

Northstar is a standards-oriented XMPP server written from scratch in Rust. Its primary deployment target is a single Linux host with PostgreSQL. The repository includes a 1,000-authenticated-session/resource design envelope, but that is neither a model of 1,000 simultaneously active users nor a production capacity SLA. Northstar includes TCP, WebSocket and optional HTTPS-proxied BOSH clients, certificate-authenticated federation, MUC, encrypted archives, PEP support required by OMEMO clients, a browser client, a REST administration API, anti-abuse controls, logs, and Prometheus metrics.

Northstar is an early-stage server. Version 1.1 has automated protocol and integration coverage, but it has not received an independent security audit and is not claimed to implement every clause of every advertised XEP. Read [XEP_MATRIX.md](XEP_MATRIX.md) before choosing it for a public deployment.

**Naming:** Northstar is the product name. The Cargo package and source-build
binary target are named `rust-xmpp-server`; release containers install that
binary as `xmpp-server`, which is the command name used in production examples.

Documentation uses four evidence levels deliberately:

- **Implemented** means the behavior exists in the current source and migrations.
- **Automated local evidence** means an isolated unit, PostgreSQL, two-process, browser, federation or load fixture exercises that behavior on a development/CI host.
- **Manual Gajim evidence** means the point-in-time localhost observation described below; it is not a compatibility certification.
- **Operator validation required** means evidence that depends on the real host, public DNS, CA chain, firewall, reverse proxy, external peers, monitoring and backup system. Repository tests cannot supply it.

Start with the [documentation index](docs/README.md), read the
[security policy](SECURITY.md) before reporting or testing a vulnerability, and
use the [release checklist](docs/RELEASE_CHECKLIST.md) for every production
artifact and target environment. Development contributions follow
[CONTRIBUTING.md](CONTRIBUTING.md).

## What privacy means here

OMEMO encryption is performed by compatible clients. For a correctly encrypted message, Northstar routes and archives the encrypted XMPP envelope and does not possess the clients' OMEMO private keys. The default `REQUIRE_ENCRYPTED_ARCHIVE=true` policy rejects plaintext bodies from personal and room archives and strips accidental plaintext siblings from OMEMO stanzas before persistence.

This is not an absolute “zero-knowledge” guarantee. The server necessarily sees routing metadata, account and room membership data, message timing and size, any plaintext that a client intentionally sends, and evidence a user deliberately attaches to an abuse report. Administrators with database or host access can inspect that server-visible information. End-to-end privacy therefore depends on the client, its device-key verification, endpoint security, and correct TLS deployment as well as Northstar.

## Implemented profile

- XMPP client connections using mandatory STARTTLS on `5222`, Direct TLS on `5223`, RFC 7395 WebSocket framing, or the opt-in XEP-0124/XEP-0206 endpoint at `/http-bind` (`/bosh` alias).
- SASL SCRAM-SHA-1/SHA-256 and `-PLUS`, TLS-protected PLAIN, configured client-certificate EXTERNAL, SASL2, FAST, Bind2, resource binding, presence, roster/privacy/blocking, offline delivery, Carbons, Stream Management, MAM, vCard, Private XML and HTTP Upload.
- Local and federated MUC/MIX profiles with configuration, invitations, moderation, encrypted history and access-controlled archives. Two-domain automated fixtures are local evidence; broad independent-server interoperability remains an operator boundary.
- PEP behavior needed by OMEMO 2 device lists/bundles and avatars. Generic `pubsub.<domain>` implements the advertised XEP-0060 leaf and collection profile: configuration/default forms, publish-options, affiliations/access/subscriptions/options/leases, RSM, last-item, durable digests, bounded XEP-0248 collection graphs and local/federated event routing. Mutation-caused immediate notifications and their immutable recipient snapshots commit to a bounded PostgreSQL outbox with the mutation, then retry with a stable event ID. The final socket/S2S boundary remains at-least-once rather than a distributed transaction.
- TLS-authenticated S2S using STARTTLS or Direct TLS, bounded DNS SRV/Happy-Eyeballs discovery, domain certificate verification and preferred SASL EXTERNAL, with TLS-protected authoritative XEP-0220 Dialback as a configurable compatibility fallback. Optional local DNSSEC validation supports bounded DANE usage 1/3 policies, and optional local PEM CRLs cover federation, XEP-0487 HTTPS and C2S client-certificate chains.
- Durable, bounded PostgreSQL S2S and component delivery with expiry, per-domain/global backpressure, strict per-domain head-of-line ordering, unique admission keys and exponential retry; negotiated XEP-0288 streams can safely carry traffic in both directions after exact domain authentication.
- Opt-in external-component support for both XEP-0114 `jabber:component:accept` and server-initiated `jabber:component:connect`, plus an experimental XEP-0225 compatibility profile. Component domains are explicitly allowlisted, cannot originate stanzas for any other domain, and recover queued delivery after a component or Northstar restart.
- HTTP registration/login, user history and reports, appeals, invitation tokens, adaptive rate limits and proof-of-work challenges, plus a protected administration API.
- Optional experimental Redis routing for sessions and MUC occupants across multiple Northstar processes. Remote Redis requires `rediss://` hostname verification and supports a private CA and client certificate authentication. PostgreSQL still fences storage-eligible ordinary direct messages and owns S2S/component outboxes, PubSub/PEP mutation-event outboxes, PubSub digests and recoverable state; Redis Pub/Sub remains an ephemeral hop for MUC/presence/Carbons. Shared S3-compatible HTTP Upload storage is implemented with a PostgreSQL-fenced recovery queue, but the supported production baseline remains one Northstar process until the remaining ephemeral cluster classes and a target object provider pass their runtime release gates.

The precise feature boundary is maintained in [XEP_MATRIX.md](XEP_MATRIX.md). `Core` there means Northstar's documented profile is covered by automated tests; it does not mean every optional feature in the standard exists. The machine-checked [implementation and evidence traceability index](docs/TRACEABILITY.md) links each current issue and every Core profile to code, schema, test harnesses and authoritative documentation.

## Prerequisites

- Linux for deployment. WSL2 is supported for development and the supplied integration suites.
- Rust `1.97.1` for release-equivalent source builds (pinned by
  `rust-toolchain.toml`; `Cargo.toml` declares the minimum supported version).
- PostgreSQL 15 or newer (the Compose deployment uses PostgreSQL 17).
- A DNS name and a publicly trusted certificate for Internet-facing use.
- Optional: Docker Compose, Caddy, Prometheus/Grafana, and Redis for the experimental multi-node path.

## Quick start from source

This path is only for a single-process localhost development instance. Create a
local PostgreSQL database/role, then copy the loopback-only profile and replace
both database URL placeholders with that local role's URL:

```sh
cp .env.development.example .env
# Edit DATABASE_URL and MIGRATOR_DATABASE_URL before continuing.
bash scripts/generate-development-certificate.sh
cargo run --release --locked -- migrate
cargo run --release --locked
```

The development profile binds every listener to loopback, disables Redis and
Dialback, and explicitly opts into independent process-local FAST, dummy-SCRAM,
anti-abuse and API-control keys. It also permits the one local PostgreSQL owner
role to be reused for migration, runtime and command execution. Those keys are
discarded at restart, so FAST credentials, API replay state and keyed
anti-abuse identities deliberately do not survive as stable deployment
authorities. None of these exceptions is accepted for a public listener,
non-reserved domain or clustered deployment.

This localhost exception changes the role topology, not the database integrity
checks. Migration and startup still require an owner-only catalog and ACL shape
and fail if `PUBLIC` or any third-party grantee has been authorized. The local
workflow neither creates the production workload roles nor runs production
grant reconciliation; the single development owner remains the only database
principal with application authority. Production must instead use separate
migrator, runtime, command and backup roles and complete exact grant
reconciliation before starting Northstar.

The generated RSA-3072 localhost certificate is ignored by Git and has
`CA:FALSE`, strict key usage and local service SANs. It is still a development
self-signed certificate and must not be used publicly.

For production, start from [.env.example](.env.example), use the separated
database roles and mounted secret files described in
[Production operations](docs/PRODUCTION_OPERATIONS.md), and install a publicly
trusted certificate whose `subjectAltName` covers the XMPP domain. Production
must configure an independent bounded command identity through
`ADMIN_COMMAND_DATABASE_URL_FILE` (preferred) or
`ADMIN_COMMAND_DATABASE_URL`; it must not reuse the runtime or migrator URL.

The migration command reads `MIGRATOR_DATABASE_URL` or
`MIGRATOR_DATABASE_URL_FILE`. Normal startup reads `DATABASE_URL` or
`DATABASE_URL_FILE`, verifies the migration ledger and RFC 7622 canonicalization
markers without changing schema, loads TLS material, starts each enabled
listener and remains attached to the terminal. Pending, failed, unknown or
checksum-drifted migrations make startup fail closed. A listener that
unexpectedly exits causes an orderly server shutdown rather than leaving a
partially running process.

### Default ports

| Port | Purpose | TLS behavior |
| ---: | --- | --- |
| `5222/tcp` | XMPP client-to-server | STARTTLS is mandatory |
| `5223/tcp` | XMPP client Direct TLS | TLS before the XML stream; ALPN `xmpp-client` when offered |
| `5269/tcp` | XMPP server-to-server | STARTTLS and SASL EXTERNAL |
| `5270/tcp` | XMPP server Direct TLS | TLS before the XML stream; ALPN `xmpp-server` when offered |
| `5347/tcp` | External components (disabled) | Loopback-only by default; XEP-0114 is plaintext, XEP-0225 requires STARTTLS |
| `8080/tcp` | REST, WebSocket, health and static web UI | Loopback/plain HTTP by default; normally placed behind Caddy/another TLS proxy |
| `9091/tcp` | Private Prometheus metrics | Loopback-only by default; a non-loopback bind requires a mounted bearer token |

Any listener can be disabled for an isolated test by binding it to port `0`. Do not expose PostgreSQL, Redis, Prometheus or Grafana directly to the Internet.

## Configuration

Configuration is supplied through environment variables or `.env`; committed defaults live in [.env.example](.env.example). Important groups are:

- Identity/network: `XMPP_DOMAIN`, `PUBLIC_URL`, `XMPP_BIND`, `XMPPS_BIND`, `S2S_BIND`, `S2S_TLS_BIND`, `HTTP_BIND`, and the independently bound `METRICS_BIND`.
- Experimental XEP-0487 discovery: set `XEP_0487_IPS` only when every advertised WebSocket/Direct-TLS endpoint is reachable on those literal public addresses; optional `XEP_0487_TTL_SECONDS`, `XEP_0487_PRIORITY`, and `XEP_0487_WEIGHT` tune the document. If the IP list is empty, Northstar deliberately keeps the legacy XEP-0156 response so clients and servers continue DNS/SRV fallback.
- TLS: `TLS_CERT_PATH`, `TLS_KEY_PATH`, and optionally `FEDERATION_EXTRA_ROOT_CERT_PATH` for a controlled private PKI. `FEDERATION_CRL_PATH` applies local CRLs to outbound server-auth, inbound S2S client-auth and XEP-0487 HTTPS; `C2S_CLIENT_CRL_PATH` requires the configured C2S client trust root. TLS 1.2/1.3 are explicit; public domains require a trusted, domain-matching server-authentication chain and strong regular-file key material, while self-signed certificates are limited to reserved development domains. Atomic reload gives new handshakes the new snapshot and rechecks live SASL EXTERNAL C2S/inbound-S2S/outbound-S2S certificate chains. Only an exact, applicable `CertRevoked` result drains that connection; renewal, expiry, trust-root changes and unrelated validation failures never cause a blanket kick.
- PostgreSQL: normal runtime accepts exactly one of `DATABASE_URL` and
  `DATABASE_URL_FILE`; the explicit migration command separately accepts
  exactly one of `MIGRATOR_DATABASE_URL` and `MIGRATOR_DATABASE_URL_FILE`.
  Production additionally requires exactly one of
  `ADMIN_COMMAND_DATABASE_URL` and `ADMIN_COMMAND_DATABASE_URL_FILE` for the
  separately bounded command role. Only the all-loopback reserved-domain
  development profile may explicitly reuse `DATABASE_URL` by setting
  `DATABASE_ALLOW_UNSAFE_ROLE_FOR_DEVELOPMENT=true`. File-backed secrets avoid
  putting credentials in Compose files or the process environment.
- Registration: `OPEN_REGISTRATION`, `INVITATION_REQUIRED` and `REGISTRATION_RATE_PER_HOUR`. HTTP, XEP-0077 data forms and XEP-0389 expose invitation/body-bound PoW v2 fields. XMPP sends the challenge only after a metered submission is known, then atomically verifies it, performs bounded password work and creates the account; standards-only clients retain the strict first-attempt IP burst and receive a normal `resource-constraint` when further work is required.
- Authentication: `SCRAM_ITERATIONS` applies to newly created or upgraded SCRAM verifiers. The default is 600,000; benchmark it on the deployment host. XEP-0484 FAST keeps only one current and one pending token per user-agent UUID across all mechanisms; `FAST_STRONG_REAUTH_MAX_DAYS` (90 by default) is an absolute password/SCRAM reauthentication deadline that token rotation cannot extend. Normal startup requires two distinct protected files: `FAST_TOKEN_SECRET_FILE` is the FAST token authority, while `DUMMY_SCRAM_SECRET_FILE` independently derives account- and mechanism-specific dummy credentials for enumeration-resistant SCRAM exchanges. Never copy or derive one from the other. Each capability has a separate explicit Redis-free, all-loopback reserved-domain development opt-in that generates an independent process-local key; FAST tokens then intentionally stop working after restart.
- Storage/privacy: `UPLOAD_STORAGE_BACKEND=local|s3`, local `UPLOAD_DIR`, protected S3 credential-file or workload-provider settings, `UPLOAD_MAX_BYTES`, bounded offline queue count/bytes/TTL, bounded PubSub/PEP node and storage quotas, `SM_RESUME_TIMEOUT_SECONDS`, and the process-wide actual-byte XEP-0198 budgets `SM_MEMORY_BUDGET_BYTES` / `SM_RECOVERY_MAX_BYTES` / `SM_RECOVERY_MAX_JOBS`, plus `REQUIRE_ENCRYPTED_ARCHIVE`. Public Redis clusters require shared S3-compatible upload storage; see the [upload storage and recovery contract](docs/UPLOAD_STORAGE.md).
- Connections and deployment capacity: global/per-IP C2S limits, per-account resource limits, `UNAUTHENTICATED_TIMEOUT_SECONDS`, and the post-SASL `RESOURCE_BIND_TIMEOUT_SECONDS` resource-bind deadline, plus a shared inbound/outbound S2S limit and separate component connection/queue limits. Accounts, MUC rooms, live bindings and retained SM rows use a PostgreSQL-authoritative 64-shard ledger; changing its limits requires the next `DEPLOYMENT_CAPACITY_EPOCH` and never deletes resources to fit. See [docs/DEPLOYMENT_CAPACITY.md](docs/DEPLOYMENT_CAPACITY.md). SASL2 Bind 2 and successful inline SM resume are already bound and do not enter the bind deadline; a legacy or unbound SASL session that misses it is terminated with `policy-violation` and cannot be resumed.
- BOSH: `BOSH_ENABLED` exposes `/http-bind` and `/bosh`; session, wait/inactivity/pause, request/response, stanza and queued-output bounds are independently configurable. Authentication is accepted only when `X-Forwarded-Proto: https` comes from `TRUSTED_PROXY_IPS`, and discovery is emitted only when `PUBLIC_URL` is HTTPS. A direct plaintext request is never treated as a secure XMPP stream.
- WebSocket: `/xmpp-websocket` requires the exact `xmpp` subprotocol and, in production, a trusted proxy assertion of HTTPS. Direct `ws://` is accepted only from loopback when `PUBLIC_URL` is also an explicit loopback HTTP development URL. Native clients may omit `Origin`; browser origins must match the normalized origin of `PUBLIC_URL` or an exact entry in `WEBSOCKET_ALLOWED_ORIGINS`, with plaintext origins limited to loopback. Text messages and frames are capped at 1 MiB.
- Federation: enable/disable, preferred SASL EXTERNAL, optional XEP-0220 Dialback with `DIALBACK_SECRET_FILE`, allow/deny lists, test-only private-address permission and explicit DNS overrides. Redis multi-node startup fails closed without both `FAST_TOKEN_SECRET_FILE` and the independent `DUMMY_SCRAM_SECRET_FILE`, and, when Dialback is enabled, `DIALBACK_SECRET_FILE`; inline or process-random keys cannot provide cross-node verification authority. `FEDERATION_DANE_MODE=off|opportunistic|required` controls local DNSSEC/TLSA validation; required mode deliberately rejects overrides, XEP-0487 and insecure fallback. `xmpps://` selects Direct TLS; `starttls://` or an unprefixed address selects STARTTLS. Public authoritative DNS and TLSA publication remain operator validation.
- External components: `COMPONENTS_ENABLED`, the loopback-default `COMPONENT_BIND`, bounded connection/queue settings, and `COMPONENTS_CONFIG_FILE`. The protected JSON file maps each component domain and optional aliases to exactly one `secret_file` (recommended) or inline `secret`, and selects inbound `accept` or outbound `connect`; see `deploy/components.example.json`. Mounted secrets are fingerprinted at startup and re-read at authentication, while an inline value is retained only in zeroizing memory. Outbound public endpoints require the explicit `allow_public_connect` opt-in.
- Discovery: XEP-0157 contact URIs and optional STUN/TURN endpoints for XEP-0215. With a mounted coturn shared secret Northstar mints short-lived, privacy-preserving TURN REST credentials; operating STUN/TURN remains the administrator's responsibility.
- Abuse controls: the base/maximum proof-of-work factor, normal message burst, escalation window, cooldown, maximum enforced delay and the operator's device-time calibration target. `ABUSE_STATE_HMAC_KEY_FILE` is mandatory unless every listener is loopback-only, Redis is disabled, the domain is reserved for development, and `ABUSE_STATE_ALLOW_EPHEMERAL=true` explicitly opts into disposable state. PostgreSQL stores a monotonic `ABUSE_STATE_HMAC_KEY_EPOCH` plus irreversible current/previous key IDs: startup fails on drift, `/readyz` checks it, and a critical five-second guard cancels the whole service if authority later diverges. Rotation keeps old-key writes interoperable during overlap, switches primary writes only after fencing old nodes, and prevents removal until the minimum 30-day horizon and every live durable old-key reference are clear.
- Observability: `/metrics` exists only on `METRICS_BIND`. Loopback scraping needs no credential; every non-loopback bind requires `METRICS_BEARER_TOKEN_FILE`. Collection is single-flight, cached for five seconds and bounded by a total database deadline. The public HTTP router and Caddy do not expose this path.
- Data retention: bounded personal MAM, MUC MAM, offline-message and resolved-moderation lifetimes plus cleanup batch/interval controls. A retention value of `0` disables that automated content deletion rather than purging immediately; delivery-only replay tombstones still have a fixed 30-day bound. Pending moderation/appeals and the content-free audit trail are never removed by the moderation sweep.
- Logging: directory, rotation, retention, text/JSON format and `RUST_LOG` filtering.
- Experimental cluster: setting `REDIS_URL` or `REDIS_URL_FILE` enables cross-process session and MUC routing. Plain `redis://` is restricted to loopback. Remote Redis must use `rediss://`; optional custom CA and mTLS certificate/key paths are accepted only in valid pairs. Leave Redis unset for the supported single-node mode.

Configuration rejects conflicting value/file secret sources and malformed addresses before listeners start. Password changes and administrative account disables revoke REST tokens and immediately disconnect live/resumable XMPP sessions. API responses carry `Cache-Control: no-store`. Never commit `.env`, certificates, private keys, generated secrets, logs, uploads or database dumps; the repository `.gitignore` covers the standard locations, but operators must also protect external paths and backups.

XEP-0114 has no TLS negotiation. Keep an accept listener on loopback or a mutually authenticated private transport, and point connect mode only at a trusted private endpoint unless its public-address opt-in is a deliberate risk decision. The XEP-0225 compatibility path requires STARTTLS and SASL PLAIN before any hostname can be bound, but XEP-0225 is Deferred and is therefore marked experimental rather than presented as a recommended replacement. A bound component can route only from configured domains; duplicate bindings and oversized stanzas fail closed. An offline or back-pressured component leaves accepted rows in the bounded PostgreSQL outbox for retry until expiry. Each durable message is stamped once with a server-authoritative XEP-0359 `stanza-id` derived from its outbox UUID, so every socket retry is byte-identical and gives an idempotent component a stable key. Neither component protocol acknowledges application stanzas: a failed write is retried, but a disconnect or process failure around a successful socket write is ambiguous and can duplicate delivery, so component handlers must deduplicate that ID.

## Client setup and OMEMO

For Gajim, Conversations and similar clients, use `user@your-domain` as the account JID and connect to `5222` with STARTTLS (or `5223` when the client explicitly supports XMPP Direct TLS). The certificate must validate for `your-domain`.

OMEMO devices publish their device list and bundles through PEP. Northstar returns `item-not-found` for a missing PEP node, preserves multi-item bundles, adds generated item IDs when needed, advertises node notifications through service discovery, and includes real JIDs in non-anonymous MUC presence so group participants can resolve device keys. Trust decisions remain client-side. If a client reports an empty trust list, confirm that both users have published bundles, refresh service discovery, and only then clear that client's stale capability cache.

The built-in browser client stores its private OMEMO state in the browser. Losing the browser profile can lose access to keys and to ciphertext that was encrypted only for those keys. Northstar does not escrow recovery keys. Browser authentication requires SASL2 SCRAM-SHA-256, verifies the server proof, immediately clears the transient password and form field, and reconnects with inline XEP-0198 resumption plus an in-memory XEP-0484 FAST credential. It does not implement SASL PLAIN. Web browser APIs do not expose a TLS exporter, so SCRAM-SHA-256-PLUS remains available to native clients rather than being falsely emulated in JavaScript.

The browser can move one exact OMEMO device to another browser with a locally downloaded, one-time package encrypted by an independent passphrase using Argon2id and AES-256-GCM. The package is never uploaded; PostgreSQL retains only its SHA-256, a monotonic generation and an opaque single-consumer fence. The source is frozen as soon as the package is created, every XMPP session is disconnected when import commits, and an old source must erase itself before publishing again. Import deliberately resets all contact trust decisions. This is a device move, not a reusable backup or server escrow; see [the complete threat model and failure contract](docs/OMEMO_DEVICE_TRANSFER.md).

The browser profile implements OMEMO 2 device lists/bundles, X3DH and Double Ratchet sessions, explicit trust/TOFU decisions, multi-device repair and retirement, one-to-one and group encryption, Stanza Content Encryption, encrypted XEP-0447/0448 file sharing, XEP-0454 compatibility, and trust-message/automatic-trust-management handling. Those cryptographic endpoint behaviors have automated local browser coverage; the server remains unable to decrypt their payloads.

Manual evidence is narrower. During the August 25 localhost validation, after accepting the development certificate, Gajim accounts `test1`, `test2` and `test3` authenticated and joined an existing members-only, non-anonymous room; `test2` sent one message that Gajim displayed as end-to-end encrypted, and the accompanying archive probe found only the encrypted envelope. The Gajim version was not recorded. This observation does not prove compatibility with every Gajim release, one-to-one OMEMO, public certificates/DNS, or the final binary after later changes; rerun those cases on staging.

## Registration and anti-abuse behavior

HTTP registration is available at `POST /api/v1/register`. Depending on policy it may require an invitation token and/or a proof-of-work solution obtained from `POST /api/v1/anti-abuse/challenge`. PoW v2 commits the one-use challenge to the method/XMPP action, canonical path and a local SHA-256 of the final pow-less body; sensitive bodies are never sent to the challenge endpoint. The same extension is available to capable XMPP clients; it is a Northstar extension, not an XMPP-standard proof-of-work claim. The secure default rejects unbound v1 challenges; `POW_V1_COMPATIBILITY_UNTIL` opens only an explicit, expiring migration window. See [the v2 intent contract](docs/POW_INTENT_V2.md).

Decisions, one-use challenges, replay state and penalties are stored in PostgreSQL and use the database clock. Registration has one strict IP-only free attempt per window. Login has five account-primary attempts, password/account changes have three, and normal messages default to 60 (`ABUSE_MESSAGE_FREE_BURST`). Reports and appeals require work immediately; appeals use a higher base and at least a 15-second hard-wait step. After a free burst, short-window operation number `n` uses `n² × base work`; later steps add hard waits so parallel compute cannot bypass throttling. Penalties and waits rise exponentially and fall one cooldown step at a time. Authenticated shared-IP activity is diluted 20:1 and cannot copy an account penalty or invalidate another NAT user's challenge, while still acting as a high-volume source circuit breaker. Hot actor keys, including a carrier-grade NAT address, are serialized on fixed in-process gates before a PostgreSQL connection is acquired. Cross-process actor locks are non-blocking; contention fails closed with a retryable resource constraint instead of allowing lock waiters to occupy the entire connection pool.

Standards-only XMPP clients do not need a PoW solver for normal conversation. Once their configurable message burst is exhausted they receive the standard retryable `wait/resource-constraint` error and recover after cooldown. Capable HTTP/browser/XMPP clients may prefetch a challenge, observe its maximum and wait notice, solve it once, and continue. `POW_MAX_DEVICE_SECONDS=8` is an operator calibration target: hardware, thermal state and implementation vary, so it is not a guaranteed eight-second runtime. `POW_MAX_WORK_FACTOR` remains the enforced fixed ceiling.

Message admission uses opaque HMAC actor/subject keys, a payload MAC, XEP-0359 `origin-id` or a one-use challenge identity, fencing leases, bounded pending/accepted rows and key-rotation overlap. Exact replay is suppressed and a changed payload conflicts while its tombstone remains. For storage-eligible `normal`/`chat` delivery and members-only direct or mediated MUC invitations to an account hosted by this deployment, Northstar commits the trusted identity/history or affiliation plus a transient recipient spool row before any connection queue is touched. With XEP-0198, TCP, WebSocket and BOSH bind that exact row to the persisted unacknowledged sequence entry and remove it only when client `h` advances, including during resume. Without SM, TCP/WebSocket complete at successful socket write; BOSH binds the row to a response RID before exposing the response and completes it only after an authenticated client response `ack`. Duplicate BOSH RIDs replay the same cached bytes, while disconnect or lease expiry releases unacknowledged rows for retry. Offline delivery retains a 30-day post-delivery admission tombstone.

For a locally hosted recipient, an explicit XEP-0334 `no-store` direct message instead bypasses MAM, the transient spool and offline storage, then attempts only volatile local and cross-node online routes. For a remote recipient, it may use only an already authenticated writable S2S or XEP-0288 bidi stream, waits for the bounded socket write, and never falls back to the PostgreSQL S2S outbox. It succeeds when that live route accepts the stanza and returns `wait/service-unavailable` when none does, the queue is saturated, or the write deadline expires. The remote stanza retains its XEP-0334 hint. A personal-history retraction and a members-only direct MUC invitation are rejected with explicit `no-store` because each requires a durable history or authorization mutation. These semantics do not constitute end-to-end exactly-once delivery.

This closes the former queue-to-socket **loss** window for storage-eligible ordinary direct messages, but it is not an end-to-end exactly-once claim. A crash after successful output but before the applicable client acknowledgement or spool completion can replay the same stable XEP-0359 ID, and the server cannot prove that an unacknowledged client processed the bytes. If a slow client's bounded outbound queue fills, the durable enqueue failure latches that transport closed: all later sends to the old connection are rejected, the connection is terminated without revoking an otherwise resumable XEP-0198 stream, and the retained rows are replayed after SM recovery or the next eligible initial presence. This prevents a recovered socket from silently receiving newer messages across an older gap. Explicit `no-store`, transient signal-only messages, headline fan-out, Carbons and immediate post-commit notifications use volatile/best-effort paths. Monitor `xmpp_online_queue_durable_acceptances_total`, `xmpp_online_queue_volatile_acceptances_total`, and `xmpp_c2s_backpressure_disconnects_total`, and keep receipt/deduplication policy at endpoints where duplicate presentation matters.

Reports must reference 1–20 archive rows owned by the reporter and associated with the reported bare JID. Plaintext evidence is copied from the authoritative archived stanza, not trusted from client fields. For OMEMO, the submitted decrypted text is explicitly labeled `user_decrypted_omemo_unverified`; Northstar preserves the archived ciphertext reference and SHA-256 digest but cannot verify the user's plaintext. One appeal is allowed after a terminal result, and administrator transitions/audits are serialized in the same database transaction. Resolved cases and copied evidence expire after `MODERATION_RETENTION_DAYS` (365 by default), counted from the latest appeal resolution; pending cases are retained.

Data lifecycle controls include operator retention ceilings, user/room-owner
shortening, typed legal holds, fail-closed account/room deletion, bounded
insert-only audit retention, and tamper-evident exports. Held-data and audit
exports use signed scope-bound keyset cursors, fixed non-renewable 15-minute
database snapshot leases, and one continuous SHA-256 chain across every page.
OMEMO hold export keeps only server-visible ciphertext. See [Data lifecycle, legal hold, and audit
evidence](docs/DATA_LIFECYCLE.md) for exact concurrency, authorization,
idempotency, restore, monitoring, and external legal/KMS/WORM boundaries.

## REST and operations

Public and user endpoints include health/readiness, public configuration, account registration/login, password changes, history, reports/appeals, upload transfer, XMPP WebSocket, and optional XMPP over BOSH. Prometheus metrics use a separate private listener. Admin endpoints cover statistics, users, sessions, registration/federation emergency controls, invitations, reports/appeals, rooms, offline spools, broadcasts and TLS reload. REST history reuses the same repeatable-read MAM query and visibility boundary as XMPP, including bare/full `with`, time/UID filters and XEP-0059 pages; the original newest-first opaque cursor remains compatible. Direction is intentionally not advertised because legacy rows have no authoritative direction column. The machine-readable contract is [docs/openapi.yaml](docs/openapi.yaml), served unchanged at `/api/openapi.yaml`; `/api/docs` hosts pinned Swagger UI 5.32.14 under a strict same-origin CSP with authorization and all request submission disabled.

Every accepted long-running administrator mutation returns an operation ID and `Location`. Keep the caller-chosen `Idempotency-Key`: an exact retry after a lost HTTP response recovers the original operation ID instead of applying the action again. Administrators can look up that ID in the web console or REST API, inspect fan-out targets, reconcile indeterminate targets from external evidence, and only then reconcile the parent outcome. Reconciliation decisions are themselves authenticated, idempotent and audited.

BOSH uses a 256-bit CSPRNG SID as a bearer secret, but stores only a keyed lookup digest. One actor serializes each XMPP `ProtocolSession`; up to two HTTP requests can be outstanding, one in-window request may arrive before its predecessor, and completed non-pause responses are replayed only for a byte-identical duplicate RID with a two-retry amplification cap. Client response acknowledgements cannot discard a response that has not actually been sent; durable fences are applied only after RID/shape and optional key-sequence authentication, and an expired response lease cannot be resurrected. The optional XEP-0124 SHA-1 `key`/`newkey` sequence is verified in RID order with constant-time comparison; it is retained solely for standards interoperability and does not replace HTTPS. Concurrent request-body reads, body-read time, response replay, pending requests, wait time, inactivity, pause, input, output and stanza counts are all bounded. CORS is attached to the two BOSH paths rather than the REST API globally. Request `Content-Type` is intentionally ignored as required by XEP-0124 while the body remains strict, bounded XML. Optional BOSH multi-stream sessions, compressed HTTP bodies, active response media types such as `text/html`, obsolete non-SASL `authid`, and HTTP-authenticated SASL EXTERNAL are not implemented or advertised.

- `/healthz` is a process liveness probe.
- `/readyz` checks PostgreSQL and the supervised background-worker registry. A restartable worker whose heartbeat expires is aborted and restarted with bounded backoff, while a security-critical worker whose heartbeat expires triggers service shutdown; repeated business-health errors keep the instance unready. It is an internal orchestration endpoint: the default Caddy policy returns 404 for public `/readyz`, and duplicate probes share a two-second cache plus one bounded single-flight database check.
- `/metrics` is served only on the private metrics listener. It remains available during a database outage and reports database readiness separately.
- JSON logs can be shipped to a central log service; do not enable stanza payload logging in production.

See [docs/PRODUCTION_OPERATIONS.md](docs/PRODUCTION_OPERATIONS.md) for monitoring and restore drills, and [docs/BACKUP_SECURITY.md](docs/BACKUP_SECURITY.md) for authenticated manifests, mandatory production age encryption, rollback protection and key separation. Compose uses mounted secrets, a dedicated PostgreSQL bootstrap superuser, a one-shot non-superuser migration owner, separate non-owner runtime and command identities, a read-only backup identity, a read-only application filesystem, dropped Linux capabilities, an internal database network and loopback-only monitoring ports.

Before upgrading an old database that may contain pre-RFC-7622 identity spellings, run the maintenance command `xmpp-server audit-identities --dry-run --xmpp-domain example.org`. It executes before normal startup/migrations, uses one read-only repeatable snapshot and emits a redacted JSON report of malformed values, canonical collisions and their reference graph. It never repairs or merges principals; see [docs/IDENTITY_AUDIT.md](docs/IDENTITY_AUDIT.md) for its privacy boundary and isolated-copy repair workflow.

## Docker Compose deployment

Pre-create the protected external secret parent, generate the root-owned runtime
secret files, install the certificate/key at the paths selected in `.env`, then
start the core services:

Before building, set `NORTHSTAR_VERSION=1.1.0` and set
`NORTHSTAR_VCS_REF` to the exact release commit in the ignored production
`.env`. These values populate the OCI image metadata; `unknown` is acceptable
only for a local development image.

```sh
sudo install -d -o root -g root -m 0700 /etc/northstar
sudo env NORTHSTAR_SECRET_DIR=/etc/northstar/secrets \
  sh scripts/create-production-secrets.sh
sudo docker compose -f docker-compose.yml -f deploy/docker-compose.bootstrap.yml up -d postgres migrate database-grants xmpp caddy
```

The generator refuses a user-writable/symlinked parent and malformed, weak,
reused, or mismatched existing secrets. Compose defaults to
`/etc/northstar/secrets`; keep real secret files outside the source checkout.

Only the one-shot `migrate` and `database-grants` jobs receive the database-owner URL. They exit after applying migrations and reconciling ACLs; the long-lived `xmpp` process receives only the non-owner runtime URL and performs a read-only migration/checksum verification before opening listeners. Runtime has SELECT-only access to the `users` authority table: registration, credential rotation/upgrades, administrator lifecycle, deletion, roster versions and recovery generations execute through typed, owner-held, schema-pinned commands with generation/actor/session fences and same-transaction audit/session revocation. The command issuer and `backup` profile each receive their own restricted URL. Existing deployments created with the former `xmpp` PostgreSQL superuser must follow the stopped, audited role-upgrade procedure in [Production operations](docs/PRODUCTION_OPERATIONS.md); changing only the Compose file is not an upgrade.

Log in as the bootstrap administrator, change that password immediately, then recreate `xmpp` from the base Compose file and securely delete the host `bootstrap_admin_password` file. The bootstrap override is intentionally not part of ordinary restarts.

Optional monitoring:

```sh
sudo docker compose --profile monitoring up -d
```

Before first public use, replace every example domain and secret, validate DNS A/AAAA plus `_xmpp-client`, `_xmpps-client`, `_xmpp-server` and `_xmpps-server` SRV records as appropriate, verify ports from an external network, configure off-host encrypted backups, and test at least two independent clients. `scripts/release-preflight.sh --production` rejects an expiring, wrong-SAN, mismatched, self-signed, SHA-1-signed or weak-key certificate and requires private-key mode `0400` or `0600`.

## Verification

### Safe repository-local evidence

The latest completed non-adversarial verification of this working tree recorded
`1167` Rust tests in total: `1002 passed`, `165 ignored`, and `0 failed`.
Formatting, all-target/all-feature compilation, Clippy with warnings denied and
the static architecture, XML, parser-coverage, secret-tracking, web-auth and
artifact-integrity gates also passed. An ignored test was not executed, and
these numbers are development evidence rather than certification of a future
commit or release image.

Re-run the safe baseline after every release change:

```sh
cargo fmt --all -- --check
cargo check --all-targets --all-features --locked
cargo test --all-targets --all-features --locked
cargo clippy --all-targets --all-features --locked -- -D warnings
node scripts/check-architecture-boundaries.mjs
node scripts/check-documentation-consistency.mjs
node scripts/check-outbound-xml-construction.mjs
node scripts/check-parser-fuzz-coverage.mjs
node scripts/check-tracked-sensitive-files.mjs --include-untracked
node scripts/verify-crypto-artifacts.mjs
```

### Operator-controlled isolated harnesses

The repository also contains WSL/PostgreSQL wire integration, BOSH/WebSocket
transport conformance, parser fuzzing, federation/component fixtures, Redis
cluster exercises, backup/restore drills, fault-injection procedures and two
different 1,000-session load envelopes. Their presence is not evidence that
they ran for the current artifact. Some generate malformed traffic, impose
extreme load, stop dependencies or exercise crash/recovery boundaries and must
therefore run only with explicit authorization in a disposable isolated
environment. See [the manual security validation guide](docs/MANUAL_SECURITY_VALIDATION.md)
for prerequisites, commands, stop conditions and expected results, then record
the applicable results in the [release checklist](docs/RELEASE_CHECKLIST.md).

The 1,000-session fixtures are connection and scheduling design envelopes, not
a model of 1,000 simultaneously active users, a capacity SLA or an independent
security audit. Their load resources deliberately omit initial presence to
avoid treating the roughly one-million-stanza presence pattern from 1,000
simultaneously available resources on one account as normal traffic.

Local DANE unit/fixture coverage does not prove the public authoritative DNS chain or a real peer's TLSA deployment. The repository includes `scripts/federation-external-preflight.sh` for an operator-authorized public check; its existence is not evidence that it was run. Local CRL validation, exact live-session drain and atomic reload coverage likewise do not prove that an operator refreshes CRLs on time. S2S and component delivery remain at-least-once around socket-write/database-completion crashes, but durable message retries now preserve one server-authoritative XEP-0359 identity. Storage-eligible ordinary direct C2S messages use the transient spool boundary described above; explicit `no-store` and best-effort fan-out remain volatile.

Historical handoff and validation narratives are retained in [docs/archive/](docs/archive/). Those point-in-time reports do not override the current evidence levels, compatibility matrix or known-issues file.

## Architecture and known limits

Protocol code is split by domain under `src/xmpp/protocol/`; PostgreSQL access is split under `src/db/`; `src/s2s/` owns federation, `src/cluster.rs` owns optional Redis routing, and `src/api/` owns HTTP. XML stream framing uses an incremental tokenizer with nesting-depth tracking and size/depth limits, so nested forwarded/MAM/Carbons stanzas are not truncated at the first inner closing tag. Security-critical TCP/WebSocket/BOSH, S2S and component envelopes use a structural XML builder whose element/attribute names are static and whose runtime values are escaped exactly once; embedded stanza fragments must parse successfully before insertion.

Important remaining limits include the need for independent RFC/XEP and security review, no OCSP or online CRL/AIA retrieval, no optional BOSH multi-stream profile, no general S2S multi-domain multiplex/additional-domain piggyback, Deferred/experimental XEP-0225 and XEP-0487 profiles, no public DNS/DANE or broad third-party federation evidence, and experimental rather than production-qualified Redis clustering. See [docs/KNOWN_ISSUES.md](docs/KNOWN_ISSUES.md).

## License

Northstar's original code is licensed under [AGPL-3.0-only](LICENSE). Dependency licenses and notices are listed in [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).
