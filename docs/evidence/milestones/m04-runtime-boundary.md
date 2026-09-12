# M04-01 runtime boundary checkpoint

This checkpoint is an incremental runtime foundation. It does not claim that
all service binaries are already connected to production gRPC, PostgreSQL,
Kafka or workload-mTLS.

## Delivered

- `ServiceConfig::load` now has an explicit development/production profile,
  rejects direct-secret plus secret-file conflicts, invalid ports and invalid
  drain windows, and never creates a production secret fallback. The older
  `ServiceConfig::new` remains a compatibility constructor for reference
  callers; executable service binaries use the checked loader.
- All seven executable service entry points now use the profile-aware loader,
  so configuration errors are returned before service initialization.
- `DependencyRegistry` is fail-closed: an empty, unknown, degraded or failed
  dependency set cannot make a service ready.
- `WorkerGroup` provides structured JoinSet ownership with worker names and
  criticality, plus explicit shutdown/drain hooks.
- `RequestLimits` and `ConcurrencyGate` provide bounded payload/deadline and
  fail-fast concurrency primitives for protocol adapters.
- `GrpcServerOptions` validates and applies a bounded Tonic transport builder;
  `RequestContext` carries a bounded request ID and optional deadline without
  allowing an untrusted handler to invent identity claims.
- Method-level authorization primitives now live in the runtime and use the
  verified workload/principal types; the authoritative method inventory is
  tracked separately in `catalog/rpc-authorization.yaml`.
- `RetryPolicy` and `CircuitBreaker` provide capped exponential retry and
  fail-fast recovery for internal clients; the backoff cannot grow without
  bound.
- The private health listener exposes bounded `/livez`, `/readyz` and static
  low-cardinality `/metrics` responses without probing a database on every
  request. It is supplied a pre-bound
  listener and shutdown signal, making its address and lifecycle test-owned.

## Evidence

```text
cargo check --locked -p foundation-service-runtime --all-targets
cargo test --locked -p foundation-service-runtime --all-targets  # 17 passed
cargo clippy --locked -p foundation-service-runtime --all-targets -- -D warnings
cargo check --locked -p service-identity -p service-session-directory \
  -p service-xmpp-edge -p service-message-ingress -p service-delivery-router \
  -p service-protocol-registry -p service-xep-0313-mam --bins
```

Generated service registration, live mTLS transport/channel rotation, OTel
exporters and production task watchdog are subsequent M04 tasks. Until those
are wired,
the catalog status of the remote services remains `executable-prototype`.
