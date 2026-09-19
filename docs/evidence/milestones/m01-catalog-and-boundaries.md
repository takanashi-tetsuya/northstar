# M01 catalog and boundary checkpoint

This checkpoint records the completed catalog work for the current source
tree. It is evidence of repository structure, not a production certification.

## Delivered

- Eight accepted ADRs freeze the modular-monolith reference baseline, service
  ownership, outbox/inbox delivery, home-region writes, workload identity,
  staged cutover, and privacy/retention decisions.
- `catalog/services.yaml` describes 51 services with explicit execution mode,
  semantic owner, deployment unit, criticality, data classes, region mode,
  runtime/image identity, and maturity evidence.
- `catalog/routes.yaml` describes 38 routes with principal/scope, deadlines,
  payload limits, retry/idempotency, ordering, fanout, failure mode, and
  observability requirements.
- `catalog/data-ownership.yaml` describes 77 exclusively owned tables with
  table-level privacy, content/secret flags, retention, legal hold, deletion
  and export owners, key class, residency, backup objectives, and restore order.
- Database cluster, data-class, retention-class, crate-policy, service schema,
  route schema, ownership schema, evidence schema, and crate schema assets are
  checked into the repository.
- `catalog-validator` is the structured Rust validator used by CI. The legacy
  JavaScript entry point is only a compatibility wrapper.
- `architecture-validator` generates compile-time, runtime, and data-access
  graphs in DOT, Mermaid, and JSON and rejects forbidden core/edge dependencies.

## Verification at this checkpoint

```text
cargo fmt --all -- --check
cargo check --workspace --all-targets --locked
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo run --locked -p catalog-validator -- validate --strict
cargo run --locked -p architecture-validator -- validate --check
node scripts/check-documentation-consistency.mjs
```

The current catalog reports 51 services, 38 routes, 77 tables, 1,629
compile-time edges, 26 runtime edges, and 75 data-access edges. M02 contract
hardening and runtime service cutover remain separate milestones and are not
claimed by this checkpoint.
