# ADR-0005: Home Region Single Writer and Region Fencing

## Context

Real-world multi-region deployment requires high availability without split-brain authority.
Without explicit write fences, duplicate writers can cause stale session assertions, duplicate
message acceptance, and inconsistent policy outcomes.

## Decision

Each logical aggregate family uses exactly one **home region writer** at a time.
Write operations must carry a region epoch/lease check and are rejected when stale.

Fencing semantics:

- epoch increments on failover or explicit promotion.
- stale writers are denied at service and DB boundaries.
- claims and resumes include region epoch fields verified at every acceptance boundary.

## Alternatives

- **Multi-writer from day one**: easier initial availability claim, but hard to keep strong invariants.
- **Strictly single cluster forever**: simpler but does not meet regional scaling targets.

We adopt single-writer home-region with explicit, durable fencing and controlled failover.

## Consequences

- Cross-region reads remain possible for discovery and cache warm paths.
- Write failures during region transitions are explicit and visible; they are considered expected.
- Failover tooling is required for normal operations and test drills.

## Security / Privacy

- Region identity is part of trust proof for sensitive identity/session decisions.
- Replay of stale artifacts is denied by epoch checks and auditable rejection logs.

## Migration

- Stage by deployment unit: add epoch/lease columns, then integrate fencing checks on all write and resume paths.
- Validate with chaos drills (partition, node restart, lag simulation).

## Status

Accepted.

