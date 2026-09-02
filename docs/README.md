# Northstar documentation index

This directory separates current contracts from historical evidence. A file's
existence does not by itself prove that its runtime test was executed for the
current commit.

## Authoritative current documents

Read these in order before deploying or changing protocol behavior:

1. [Repository README](../README.md) — supported deployment, quick start and
   evidence vocabulary.
2. [XMPP compatibility matrix](../XEP_MATRIX.md) — normative RFC/XEP scope and
   `Core`/`Partial`/`Pass-through`/`Experimental` labels.
3. [Known issues and accepted boundaries](KNOWN_ISSUES.md) — the only current
   backlog and compromise register.
4. [Internal architecture](ARCHITECTURE.md) — ownership, persistence and
   delivery boundaries.
5. [Program responsibility model](PROGRAM_RESPONSIBILITIES.md) — exact process,
   task, module, database and restore-session authority boundaries.
6. [Production operations](PRODUCTION_OPERATIONS.md) — deployment, monitoring,
   backup, recovery, TLS and database-role procedures.
7. [Release checklist](RELEASE_CHECKLIST.md) — evidence required for one exact
   release artifact and target environment.
8. [OpenAPI contract](openapi.yaml) — REST wire contract served by the binary.

Repository contributions and safe default checks are described in
[CONTRIBUTING.md](../CONTRIBUTING.md); vulnerability reporting uses
[SECURITY.md](../SECURITY.md).

The shorter root [architecture and security model](../ARCHITECTURE.md) is the
public overview; this directory's architecture document is the implementation
map.

## Repository map

| Path | Ownership |
| --- | --- |
| `src/` | Rust runtime; protocol adapters, application services, repositories, workers and transports |
| `migrations/` | Immutable, monotonically numbered PostgreSQL schema and capability history |
| `web/` | Self-hosted browser client and generated static locale packs |
| `third_party/` | Vendored browser artifacts, source/provenance records, notices and SBOMs |
| `deploy/` | Compose overlays, proxy policy, container helpers and PostgreSQL role/grant bootstrap |
| `monitoring/` | Prometheus/Grafana configuration, alerts and alerting runbook |
| `scripts/` | Static gates, operations, isolated integration harnesses and release tooling; see [the script guide](../scripts/README.md) |
| `fuzz/` | Separate pinned cargo-fuzz crate, corpora and production-parser targets |
| `docs/` | Current technical/operations contracts; point-in-time reports live only in `docs/archive/` |
| `changelog/` | Detailed release notes indexed by the root `CHANGELOG.md` |

Root build/start wrappers remain only for local-development compatibility. They
do not run migrations or replace the production supervisor and operations
procedure.

## Security, identity and data governance

- [Database roles](DATABASE_ROLES.md)
- [Data lifecycle, legal hold and audit evidence](DATA_LIFECYCLE.md)
- [Identity audit](IDENTITY_AUDIT.md)
- [Anti-abuse and moderation audit](ABUSE_AND_MODERATION_PRODUCTION_AUDIT.md)
- [PoW action intent v2](POW_INTENT_V2.md)
- [Backup security](BACKUP_SECURITY.md)
- [Manual security and extreme validation](MANUAL_SECURITY_VALIDATION.md)
- [Browser cryptography supply chain](WEB_CRYPTO_SUPPLY_CHAIN.md)
- [OMEMO one-time device transfer](OMEMO_DEVICE_TRANSFER.md)

Security-sensitive validation in `MANUAL_SECURITY_VALIDATION.md` must run only
against an explicitly authorized disposable environment. It is intentionally
not part of an unattended default command.

## Reliability and deployment design

- [Experimental clustering](CLUSTERING.md)
- [Deployment capacity authority](DEPLOYMENT_CAPACITY.md)
- [HTTP upload storage and recovery](UPLOAD_STORAGE.md)
- [Durable PubSub/PEP event outbox](PUBSUB_EVENT_OUTBOX.md)
- [SASL2, FAST and Bind2 evidence](SASL2_FAST_BIND2_EVIDENCE.md)
- [External component evidence](COMPONENT_PROTOCOL_EVIDENCE.md)
- [Implementation/evidence traceability](TRACEABILITY.md)

## Web client

- [Localization policy](LOCALIZATION.md)
- [Browser cryptography supply chain](WEB_CRYPTO_SUPPLY_CHAIN.md)
- [OMEMO one-time device transfer](OMEMO_DEVICE_TRANSFER.md)

## Release history

- [Project changelog](../CHANGELOG.md)
- [Northstar 0.2.0 development and release-preparation record](../changelog/v0.2.md)
- [GitHub Releases](https://github.com/takanashi-tetsuya/northstar/releases)
  contains public downloads only after a maintainer reviews and publishes the
  draft created by the tag workflow. The repository does not predeclare hashes
  or image digests for an unbuilt release.
- [Release checklist](RELEASE_CHECKLIST.md) defines tag, draft review, package,
  checksum, provenance, GHCR digest and publication gates.
- [`archive/`](archive/) contains point-in-time handoff, validation and planning
  reports. These files are historical evidence, not current capability or
  release claims.

## Evidence vocabulary

- **Implemented**: code/schema exists in this checkout.
- **Verified locally**: a named deterministic/static or isolated harness was
  actually run for the recorded commit.
- **External/operator validation required**: public DNS/PKI, target hardware,
  third-party interoperability, alert delivery and off-host recovery evidence.
- **Accepted boundary**: a deliberate standards, privacy, platform or upstream
  constraint documented in `KNOWN_ISSUES.md`.

## Maintenance rules

1. Update `XEP_MATRIX.md` whenever an advertised protocol profile changes.
2. Update `openapi.yaml` in the same change as REST routing or response shape.
3. Add unresolved compromises only to `KNOWN_ISSUES.md`; do not recreate a
   second backlog in a validation report.
4. Put point-in-time audit/agent handoff reports in `docs/archive/` and add a
   visible historical banner.
5. Keep example commands secret-free and use placeholders for domains, tokens,
   database URLs and key paths.
6. Run `node scripts/check-documentation-consistency.mjs` before release.
