# ADR-0001: Modular Monolith as Reference Baseline

## Context

The project currently delivers substantial XMPP protocol behavior in a single Rust monolith, while
prototype services and service catalogs are already prepared to enable staged decomposition.
The team needs a governance rule that prevents premature service split from breaking protocol
compatibility and allows safe staged migration.

## Decision

We define a two-phase architecture:

1. The existing monolith remains the **reference baseline** and protocol conformance oracle.
2. New external services are introduced gradually, but only for domains that require independent
   state, resilience boundaries, independent scaling, or explicit security isolation.

Monolith decomposition work will therefore be staged by capability slices rather than file-by-file refactor.

## Alternatives

- **Full rewrite first**: high risk, no stable oracle, no fallback for protocol regressions.
- **Immediate microservice split everywhere**: high operational complexity and coupling risks without
  validated ownership boundaries.
- **Do nothing**: no path to industrial scale, observability, and security hardening.

We choose staged decomposition with the monolith preserved as behavioral gold.

## Consequences

- Monolith behavior can be used for differential testing and incident comparison.
- New services must expose explicit contracts before receiving traffic.
- Integration milestones are measurable against documented cutover evidence.
- Rollback remains possible at service level through routing controls.

## Security / Privacy

- Monolith retains no new protocol trust assumptions during transition.
- All new service boundaries must pass through contract-defined assertions before being considered authoritative.
- Sensitive data handling in transitional services must match monolith policy defaults until formal
  migration evidence is collected.

## Migration

- Add routing indirection gradually (read/write split, shadow mode, then cutover).
- Gate each service migration by evidence state and explicit acceptance tests.
- Keep at-least-once processing semantics with idempotent effects until strong
  distributed invariants are proven.

## Status

Accepted.

