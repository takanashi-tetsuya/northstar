# ADR-0003: Logical Database Ownership Per Stateful Deployment Unit

## Context

Current code has a mixture of in-memory state, monolithic schema coupling patterns, and planned
distributed modules. Industrial deployment requires clear authority boundaries and repeatable DB
maintenance.

## Decision

Each stateful deployment unit owns exactly one logical database namespace (or scoped schema set)
for its authoritative data. The following roles are required:

- `owner` (no login)
- `runtime`
- `migrator`
- `ops_readonly`
- `backup`
- `security_admin` (when needed by operation policy)

No deployment unit may execute business writes into another unit's logical owner data.

## Alternatives

- **Single shared DB**: simpler operations early but blurs boundaries and increases blast radius.
- **Cross-service views/FDW**: convenient shortcuts but violates ownership proof and isolation goals.

We adopt per-unit logical DB ownership with role-based access contracts.

## Consequences

- Migration ownership, retention, and restore responsibilities are explicit and auditable.
- Catalog and validators can enforce "no cross-owner table access".
- Cross-unit communication uses explicit events/contracts, never direct table reads.

## Security / Privacy

- Role minimization is mandatory; `runtime` cannot have schema-altering privileges.
- Sensitive columns require declared data class and retention/retention override declarations in catalog.
- Recovery and backup identity are separate to reduce accidental privilege overlap.

## Migration

- Existing monolith-owned tables move via controlled cutover paths only when a service reaches
  integrated state and evidence is available.
- Shared historical paths are treated as compatibility snapshots only until replaced.

## Status

Accepted.

