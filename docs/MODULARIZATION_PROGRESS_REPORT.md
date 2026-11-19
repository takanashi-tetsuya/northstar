# Northstar modularization status

## 1. Status

Northstar builds as one deployable server binary, `northstar-server`. Its
`src/` is the composition root: process startup, `ServerNode` construction,
worker registration and the wiring of context adapters to the transport
edges. Domain logic, application services, PostgreSQL repositories, protocol
mapping and transports live in workspace crates under `crates/`, arranged in
the tiers and bounded contexts described in the
[target architecture](architecture/target-architecture.zh-TW.md) §4. The crate
graph is enforced by the architecture validator (`tools/architecture-validator`);
the [library-split ledger](LIBRARY_SPLIT_LEDGER.md) summarizes what each tier
owns and the XEP operator switches.

The structural migration ran as stages S16–S42. Each stage, its work packages
and its verification are recorded in the
[engineering structure record](architecture/engineering-structure.zh-TW.md)
§5; target architecture §5 gives the stage table. After S41 the root package
contains only the composition root and its own tests.

## 2. What this status does not claim

The structural migration is verified by the workspace build, Clippy, the
workspace tests, the database CI suites and the source gates. It does not
qualify runtime behaviour in a target environment. PostgreSQL role separation,
object-storage providers, cluster partitions, component interoperability,
capacity and independent security review each have their own evidence
requirements:

| Area | Where it is tracked |
| --- | --- |
| database role separation | [`KNOWN_ISSUES.md`](KNOWN_ISSUES.md) `ARCH-DB-ROLE` |
| object-storage providers (conditional delete, versioning) | `KNOWN_ISSUES.md` `PROVIDER-S3` |
| cluster, shared storage and partitions | `KNOWN_ISSUES.md` `EXT-CLUSTER`, `ARCH-CLU-VOLATILE`; [local VM qualification](LOCAL_VM_QUALIFICATION.md) |
| external components (XEP-0114, XEP-0225) | `KNOWN_ISSUES.md` `EXT-COMPONENT`, `STD-COMPONENT` |
| capacity and soak | `KNOWN_ISSUES.md` `EXT-CAPACITY` |
| independent review | `KNOWN_ISSUES.md` `EXT-SECURITY` |
| release candidate qualification | [release checklist](RELEASE_CHECKLIST.md); [execution plan](MODULARIZATION_EXECUTION_PLAN.md#82-isolated-vm-qualification-on-a-frozen-release-candidate) §8.2 |
| implementation and test coverage | [`TRACEABILITY.md`](TRACEABILITY.md) |

Third-party interoperability, independent security review and a 24–72 hour
soak need separate calendar time on a frozen candidate; they cannot be
inferred from code structure.

## 3. Completion criteria

Modularization is complete when all of the following hold for a release
candidate:

1. protocol and HTTP adapters parse and map only, and own no business
   transaction;
2. every user-visible mutation has one application owner and one repository
   transaction owner;
3. every external effect starts after commit and has explicit retry or
   indeterminate-recovery semantics;
4. the composition root exposes services and infrastructure capabilities only
   through narrow ports;
5. optional XEP, web, admin and worker capabilities disappear coherently from
   routes, discovery, listeners and configuration when disabled;
6. format, check, test, Clippy, crate-graph and source gates pass;
7. the isolated PostgreSQL/Redis, transport, browser and client, federation
   and component, load, fuzz, backup/restore and release-packaging gates pass
   for the exact candidate artifact;
8. `KNOWN_ISSUES.md` contains only deliberate, justified compromises.

Criteria 1–6 concern the code and its gates; criteria 7 and 8 belong to
release qualification.

## 4. History

The [2026-11-19 version of this report](https://github.com/takanashi-tetsuya/northstar/blob/880b48ebed4b19f2d42b050ffcd873de2b1b2fe1/docs/MODULARIZATION_PROGRESS_REPORT.md)
is the last one written before the restructure: it lists the
pre-restructure ownership table and the seven implementation packets that
stages S16–S41 replaced. Dated handoffs under [`handoff/`](handoff/) keep their
original wording.
