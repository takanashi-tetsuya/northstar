# Architecture assets

Structural work (file placement, module boundaries, line budgets, gate source
lookup and the structural work-package ledger) is governed by the
[engineering structure blueprint](engineering-structure.zh-TW.md).

The [target architecture](target-architecture.zh-TW.md) defines the workspace
structure that the restructure from S16 on moves toward. The current structure
is described by two machine-readable catalogs:

- `catalog/crates.yaml` — every workspace crate with its tier (from its
  directory), owner and stability, generated from Cargo metadata; the
  [crate policy](crate-policy.md) lists the dependencies each tier may have.
- `catalog/data-ownership.yaml` — exclusive logical database and table
  ownership, privacy, retention and recovery metadata.

Run the checks from the repository root:

```text
node scripts/generate-crate-catalog.mjs
cargo run --locked -p architecture-validator -- validate --write
```

The second command regenerates `docs/architecture/generated/` in DOT, Mermaid
and JSON formats. These artifacts are committed and CI rejects drift. The
compile-time graph is derived from Cargo metadata and the data-access graph
from the ownership catalog. A graph is evidence of a boundary; it is not a
substitute for an integration test.

For the supported runtime's diagnostic ownership and reproducible experiments,
start with [Runtime experiment map](runtime-experiments.md) and the separate
`catalog/runtime-experiments.json`. It consumes the production identity inventory
already checked by the architecture gate; declared experiments are never
reported as executed results. The [execution plan](experimental-clarity-plan.zh-TW.md)
records this phase's original acceptance criteria.

The [resource ownership and bounds review](resource-bounds.zh-TW.md) summarizes
admission limits, backpressure, release paths, verified test scope and remaining
gaps across connections, input, outbound queues, stream management and workers.
It distinguishes the 16 selected local BOSH checks from full actor, SQL and
wire-protocol acceptance, and tracks the new checkpoint's publication separately.
