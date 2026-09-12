# Architecture assets

The architecture is described by three machine-readable catalogs:

- `catalog/services.yaml` — service identity, execution mode, deployment unit,
  semantic owner, data classes and evidence status.
- `catalog/routes.yaml` — the authenticated route contract used to derive edge
  dispatch metadata.
- `catalog/data-ownership.yaml` — exclusive logical database and table
  ownership, privacy, retention and recovery metadata.

The contract crate follows the same separation: `src/generated/` is the only
wire-facing Protobuf/Tonic surface, while `src/adapters/` contains temporary
domain values and checked `TryFrom`/`From` conversions. Protocol handlers and
repositories should accept adapters, never deserialize trusted identity data
directly from JSON or from a handwritten RPC DTO.

Common request metadata is intentionally non-authoritative. Account and
session authority is represented by the versioned `northstar.security.v1`
`AuthGrant`/`SessionAssertion` messages; adapters enforce audience, validity,
signature-size and key-ID invariants, while cryptographic verification and key
rotation live in the security runtime.

Run the checks from the repository root:

```text
cargo run --locked -p catalog-validator -- validate --strict
cargo run --locked -p architecture-validator -- validate --write
```

The second command regenerates `docs/architecture/generated/` in DOT, Mermaid
and JSON formats. These artifacts are committed and CI rejects drift. The
compile-time graph is derived from Cargo metadata, the runtime graph from
route ownership, and the data-access graph from the ownership catalog. A graph
is evidence of a boundary; it is not a substitute for an integration test.
