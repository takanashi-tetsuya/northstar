# Crate tiers and dependency policy

`catalog/crates.yaml` is generated from `cargo metadata` by
`scripts/generate-crate-catalog.mjs`; CI regenerates it and rejects drift.
Each record names the crate's tier (and, for a context crate, its context and
role), its owner and its API stability. The tier comes from the crate
directory, so moving a crate is the only way to change it. `architecture-validator`
checks every record against its path and rejects every normal or build
dependency that the rules below forbid; dev-dependencies are not checked. The
tiers are those of the [target architecture](target-architecture.zh-TW.md),
section 4.1.

## Tiers

| Directory | Tier | May depend on (workspace crates) |
| --- | --- | --- |
| `crates/kernel/<crate>` | kernel | kernel |
| `crates/platform/<crate>` | platform | kernel, platform |
| `crates/contexts/<context>/<crate>` | context | see the roles below |
| `crates/edges/<crate>` | edge | kernel, platform, any context's core or application, the edge `northstar-stream` |
| `.` (`rust-xmpp-server`) | composition | any runtime crate |
| `tools/<crate>` | tooling | anything; only tooling may depend on tooling |

A context crate's role follows its name: `application` for `*-application` and
`northstar-protocol-runtime`, `adapter` for `*-postgres`, `*-xmpp`, `*-http`
and `*-storage` (object storage), `core` otherwise.

| Role | May depend on (workspace crates) |
| --- | --- |
| core | kernel; any context's core |
| application | kernel, platform; any context's core; an application of the same context |
| adapter | kernel, platform; any context's core; the same context's application; the edge `northstar-stream` |

No runtime crate may depend on a tooling crate.

## External crates

The validator keeps three lists of exact crate names: asynchronous runtimes
(`tokio`, `futures` and their kin), SQL and storage clients (`sqlx`,
`redis`, ...) and network stacks (`axum`, `hyper`, `reqwest`, `rustls`, ...).

- kernel and context core crates use none of them: they stay deterministic
  and synchronous;
- context application crates may use an asynchronous runtime, but no SQL or
  network crate; adapters are injected through ports;
- edge crates may not use SQL;
- platform, adapter, composition and tooling crates may use any external crate.

## Publishing

All crates are private to this repository (`publish_policy: never`) until a
stable public API and semver compatibility process is approved. A new crate
needs a tier directory and an owner; extracting a small DTO alone is not a
reason for a new crate.
