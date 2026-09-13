# Crate ownership and dependency policy

`catalog/crates.yaml` is generated from `cargo metadata` by
`scripts/generate-crate-catalog.mjs`. It records why each workspace crate
exists, who owns it, and the dependency budget that applies to its layer.

## Layers

- `foundation`: shared contracts, security, eventing, telemetry, and runtime
  primitives. Foundation code must not depend on SQL, network clients, or an
  asynchronous runtime implementation.
- `domain`: deterministic XMPP and business rules. Domain crates may depend on
  foundation and protocol types, but never on a database or transport adapter.
- `application`: use cases and ports. Application crates may compose domain
  crates and foundation contracts; adapters are injected through ports.
- `xep`: one semantic owner per XEP. XEP crates contain parsing, validation,
  and policy mapping, not direct database access.
- `adapter`: network, persistence, web, and process integration boundaries.
- `service`: executable deployment units that wire application ports to
  adapters.
- `tooling`: validators and migration tools; they are never runtime
  dependencies.

The catalog is intentionally conservative: all crates are private to this
repository (`publish_policy: never`) until a stable public API and semver
compatibility process is approved. New crates require a catalog entry and a
clear layer/owner; extracting a small DTO alone is not sufficient justification.
