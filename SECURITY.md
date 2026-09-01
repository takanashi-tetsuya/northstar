# Security policy

## Project status

Northstar is an early-stage XMPP server. It has extensive repository-local
tests and explicit security boundaries, but it has not completed an independent
security audit and must not be presented as certified or universally
production-safe. The supported deployment baseline is one Linux host and one
Northstar process with PostgreSQL; multi-node Redis mode remains experimental.

See [the known-issues register](docs/KNOWN_ISSUES.md), [security and architecture
model](ARCHITECTURE.md), [production operations](docs/PRODUCTION_OPERATIONS.md)
and [release checklist](docs/RELEASE_CHECKLIST.md).

## Supported versions

Security fixes are developed for the current pre-1.0 `0.2.x` line. The `0.1.0`
baseline and point-in-time validation reports are historical records, not
supported release contracts.

## Reporting a vulnerability

Do not include exploit code, credentials, private keys, real user data or an
unpatched vulnerability in a public issue. Prefer GitHub private vulnerability
reporting/security advisories for this repository. If that facility is not
available, open a minimal non-sensitive issue asking the maintainer for a
private contact channel.

Include, when safe:

- affected commit/version and deployment mode;
- prerequisite privileges and configuration;
- impact and the smallest non-destructive reproduction;
- relevant logs with secrets, JIDs, IPs and message content removed;
- whether the issue affects confidentiality, integrity, availability or
  protocol interoperability.

Do not test against public Northstar deployments, third-party XMPP servers or
accounts you do not control. Security testing must use an explicitly authorized
isolated environment.

## Deployment responsibilities

Operators remain responsible for DNS/PKI, host hardening, database superuser and
KMS control, secret rotation, external STUN/TURN and push services, object-store
lifecycle, alert delivery, signed/encrypted off-host backups, restore drills and
client key verification. Web OMEMO also trusts the server/static-resource
delivery chain; high-risk environments should provide an independently signed
client.
