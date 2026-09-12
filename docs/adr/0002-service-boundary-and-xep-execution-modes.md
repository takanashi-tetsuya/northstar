# ADR-0002: Service Boundaries and XEP Execution Modes

## Context

There is confusion between "semantic owner", "deployment unit", and "database owner" for XEP features.
Only some XEPs require independent service/runtime/process isolation; others are better kept as local SDKs or
local modules inside Edge/authority services.

## Decision

Each XEP is assigned two labels:

- **Semantic owner**: module/owner responsible for spec interpretation, versioning, and tests.
- **Execution mode**: how that semantic owner runs in production.

Execution modes:

- `remote-authority`: owns authoritative state, persistence, and policy decisions.
- `remote-worker`: background processing for durable tasks with authoritative inputs.
- `transport`: in-process with connection ownership and strict lifecycle.
- `control-plane`: out-of-band governance metadata and snapshots.
- `local-sdk`: deterministic parser/builder modules with no side effects.
- `signed-policy-snapshot`: policy/config delivered as signed snapshot to edge.
- `pass-through-codec`: parser only; business semantics handled by upstream owners.

## Alternatives

- **One service per XEP**: maximal isolation but excessive RPC churn and ownership drift.
- **All XEP logic in monolith**: low cost initially, no decomposition readiness and poor fault-domain boundaries.

The chosen model balances protocol purity with operational realism.

## Consequences

- Protocol modules may have independent owners without creating dedicated deployment units unless justified.
- RPC is only added where durability, security domain, or failure isolation requires it.
- Ownership changes require ADR or catalog updates rather than ad-hoc handler edits.

## Security / Privacy

- Ownership boundaries must not permit cross-service SQL access or privilege inheritance.
- Untrusted inbound edge traffic may only execute approved route contracts and snapshot-derived permissions.
- Local SDKs may parse/serialize XEP fields but must not bypass authoritative validation.

## Migration

- Convert existing XEP handlers in batches:
  1) clarify owner in catalog and tests,
  2) create contract,
  3) generate route table,
  4) move to execution mode with canary traffic.

## Status

Accepted.

