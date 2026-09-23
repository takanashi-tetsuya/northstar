# Northstar documentation

Start with the [installation guide](INSTALL.md) for release packages or the
[project README](../README.md) for a source checkout.

## Deployment

- [Production operations](PRODUCTION_OPERATIONS.md): configuration, TLS, migrations and recovery.
- [Database roles](DATABASE_ROLES.md): migrator, runtime, storage, command and backup permissions.
- [Known limitations](KNOWN_ISSUES.md): current issues and deployment constraints.
- [Core and maintenance processes](SUBSERVERS.md): separate processes over shared PostgreSQL.
- [Monitoring](../deploy/monitoring/README.md) and [alert delivery](../deploy/monitoring/ALERTING_RUNBOOK.md).
- [Experimental clustering](CLUSTERING.md), [capacity limits](DEPLOYMENT_CAPACITY.md) and [upload storage](UPLOAD_STORAGE.md).

## Architecture and protocols

- [Architecture overview](architecture/overview.md): deployment, authentication and message delivery.
- [Implementation architecture](ARCHITECTURE.md): module ownership and persistence boundaries.
- [Process responsibilities](PROGRAM_RESPONSIBILITIES.md): runtime, worker and database ownership.
- [XMPP compatibility matrix](XEP_MATRIX.md): supported RFC and XEP profiles.
- [OpenAPI specification](openapi.yaml): the HTTP API served by the binary.
- [PubSub event delivery](PUBSUB_EVENT_OUTBOX.md), [SASL2/FAST/Bind2](SASL2_FAST_BIND2_EVIDENCE.md) and [external components](COMPONENT_PROTOCOL_EVIDENCE.md).

## Repository layout

| Directory | Contents |
| --- | --- |
| `src/` | Main Rust server |
| `crates/` | Shared workspace libraries and protocol modules |
| `services/` | Experimental service processes |
| `web/` | Browser client, administration UI and translations |
| `migrations/` | Versioned PostgreSQL migrations |
| `contracts/`, `catalog/` | Protocol contracts, service definitions and data policies |
| `deploy/` | Containers, Compose overlays, proxy and monitoring configuration |
| `scripts/` | Development, operations and validation scripts; see [the script guide](../scripts/README.md) |
| `tools/` | Rust validation and administration tools |
| `tests/`, `fuzz/` | Test fixtures and parser fuzzing |
| `third_party/` | Vendored dependencies, licenses and provenance |
| `docs/` | Guides, release notes and historical records |

Local startup helpers live in `scripts/dev/`. Run them from any directory; they
use the checkout's `.env` and run in the foreground. Database setup and migrations
remain explicit steps in the project README.

Build output belongs in `target/`; local maintenance records belong in the
ignored `.local/` directory. Keep private configuration and runtime data out of Git.

## Security and data

- [Security policy](../.github/SECURITY.md) and vulnerability reporting.
- [Identity](IDENTITY_AUDIT.md), [anti-abuse and moderation](ABUSE_AND_MODERATION_PRODUCTION_AUDIT.md), and [PoW action intent](POW_INTENT_V2.md).
- [Data lifecycle and legal hold](DATA_LIFECYCLE.md).
- [Backup and restore security](BACKUP_SECURITY.md).
- [Manual security validation](MANUAL_SECURITY_VALIDATION.md): tests requiring an authorized disposable environment.

## Browser client

- [Localization](LOCALIZATION.md).
- [Browser cryptography dependencies](WEB_CRYPTO_SUPPLY_CHAIN.md).
- [OMEMO device transfer](OMEMO_DEVICE_TRANSFER.md).

## Development and releases

- [Contributing](../.github/CONTRIBUTING.md): setup, checks and pull requests.
- [Library split](LIBRARY_SPLIT_LEDGER.md), [modularization progress](MODULARIZATION_PROGRESS_REPORT.md) and [remaining work](MODULARIZATION_EXECUTION_PLAN.md).
- [Implementation and test coverage](TRACEABILITY.md).
- [Release checklist](RELEASE_CHECKLIST.md) and [release responsibilities](governance/release-roles.md).
- [Changelog](../CHANGELOG.md), [detailed 0.2 history](changelog/v0.2.md) and [0.2.0 release notes](releases/0.2.0.md).
- [Published releases](https://github.com/takanashi-tetsuya/northstar/releases).

Update the compatibility matrix when protocol behavior changes and the OpenAPI
specification when the HTTP API changes. Record current issues in
`KNOWN_ISSUES.md` and run `node scripts/check-documentation-consistency.mjs`
after editing documentation.

## Historical records

Validation records in [`evidence/`](evidence/) identify the commit and environment
tested. Dated handoffs live in [`handoff/`](handoff/); retired reports and plans
live in [`archive/`](archive/). They describe the state at the time they were
written. Use the current guides above for deployment decisions.
