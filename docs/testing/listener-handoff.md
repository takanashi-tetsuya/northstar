# Listener handoff and activation protocol

## Scope

This document describes the deterministic handoff contract used by test
and process orchestration:

- The test harness pre-binds listeners in the parent process.
- The parent keeps each listener open until the child/server task has taken
  ownership.
- Server readiness is reported through a one-shot control channel carrying
  the effective `SocketAddr` actually bound by the listener.

## Why

Previous bind-close-launch behavior could produce transient `EADDRINUSE`
and flappy failures when multiple suites or processes raced for the same
ports. By keeping descriptors open in the parent, listen ownership is
concrete and test orchestration no longer depends on ad hoc retry windows.

## Contract

- Parent:
  - Calls `tokio::net::TcpListener::bind` (or equivalent `PreboundListener`).
  - Creates `(Activation, Readiness)` pairs for each service (`east`, `west`,
    `admin`, `metrics`, etc.).
  - Passes the listener to the service entrypoint.
  - Records each `local_addr()` (after conversion to async listener if needed).
- Child/server:
  - Accepts a listener by value and serves directly from it.
  - Calls `Activation::announce(address)` once after binding/initialization.
  - Does not perform any further bind on the same `(ip,port)` pair.
- Test/launcher:
  - Awaits `Readiness::wait()` and uses returned bound address for probing.

## Operational rules

1. Disable `SO_REUSEPORT` for test listeners.
2. Keep `SO_REUSEADDR` for expected local restart behavior.
3. Port selection is deterministic per harness process lifetime to avoid
   non-reproducible collisions and reduce CI flake.
4. `ManagedProcess::stop` must use terminate-first semantics:
   terminate request → wait → force kill on timeout.

## Migration checklist

- `crates/northstar-test-harness/src/listener.rs`
  - remove `SO_REUSEPORT`.
  - deterministic port cursor scanning.
- `crates/northstar-test-harness/src/process.rs`
  - terminate-first + forced shutdown fallback.
- `crates/northstar-test-harness/src/activation.rs`
  - readiness sender/receiver helper.
- `scripts/allocate-test-ports.py`
  - deterministic ascending scan (no random shuffle).

## CI proof

- `cargo test -p northstar-test-harness --all-targets`
- Relevant suites that use listener handoff must request readiness before probing.
