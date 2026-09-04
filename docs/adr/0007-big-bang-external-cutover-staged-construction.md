# ADR-0007: Staged Cutover from In-Process Baseline to Externalized Services

## Context

Teams tend to break system behavior when moving from monolithic execution directly to
full externalized services. A controlled "big-bang" at service boundaries would reduce
understanding and recovery options in production.

## Decision

The project follows staged cutover:

1. define authoritative contracts and evidence,
2. implement one authoritative slice end-to-end in monolith+service side-by-side,
3. dark-run and reconcile outputs,
4. enable controlled traffic for non-critical subsets,
5. promote to production candidate only after evidence gates.

Evidence gates include CI checks, chaos/recovery tests, and protocol interoperability tests.

## Alternatives

- **Full parallel deploy all services at once**: fast but too high blast radius.
- **No external cutover (all in monolith)**: avoids cutover risk but never reaches target architecture.

This staged model balances continuity and safety.

## Consequences

- Delivery of new services is slower but predictable and reversible.
- Compatibility matrix grows as each slice publishes evidence.
- Regression risk is localized by migration domain.

## Security / Privacy

- During staged coexistence, monolith and service behavior must be compared and suspicious deltas triaged.
- Secrets and DB roles remain separated before cutover to avoid mixed trust in transitional period.

## Migration

- Track each slice in catalog maturity state and evidence.
- Do not mark `integrated` until cutover reconciliation and rollback validation are complete.

## Status

Accepted.

