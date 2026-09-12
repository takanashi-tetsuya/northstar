# Northstar Microservices Protobuf Wire Contracts

This directory contains the canonical Protocol Buffers (v3) wire definitions for Northstar Microservices.
All synchronous RPCs and asynchronous event envelopes across service boundaries MUST be defined here.

## 1. Directory Structure

```text
contracts/proto/
└── northstar/
    ├── common/v1/
    │   └── common.proto        # Shared types: ErrorDetail, AuthContext, SessionAssertion, TraceContext
    ├── identity/v1/
    │   └── identity.proto      # SCRAM authentication, credential generation, and account life-cycle RPCs
    ├── session/v1/
    │   └── session.proto       # Resource binding, monotonic session epoch fencing, target resolution RPCs
    ├── ingress/v1/
    │   └── ingress.proto       # Message admission and authority ingress RPCs with idempotency keys
    ├── delivery/v1/
    │   └── delivery.proto      # Bi-directional Edge streaming, per-target tasks, and socket delivery RPCs
    ├── registry/v1/
    │   └── registry.proto      # Signed route catalog snapshots, protocol features, and discovery RPCs
    └── events/v1/
        └── events.proto        # Canonical Transactional Outbox and Consumer Inbox event envelopes
```

## 2. Standards & Governance Invariants

1. **Sole Source of Truth**: `.proto` files are the authoritative wire contract source for all cross-service communication.
2. **Backward Compatibility & Field Reservation**:
   - Field tags MUST NOT be renumbered or altered.
   - Deleted or deprecated fields MUST be marked with `reserved` tags and names to prevent future reuse.
   - Field additions MUST be optional/backward-compatible.
3. **Buf Lint & Breaking Gates**:
   - Schemas must pass `buf lint` against the `STANDARD` and `SERVICE` rule categories.
   - Breaking changes are strictly checked using `buf breaking --against <baseline>`.
4. **Security & Data Isolation**:
   - Internal database IDs (e.g. autoincrement sequence numbers) MUST NOT be exposed across service boundaries.
   - Plaintext passwords, unencrypted secret keys, and internal database details are strictly forbidden in wire definitions.
   - Sensitive fields MUST be redacted in logs and debug traces.
5. **Session Assertions & Principal Identity**:
   - Internal RPCs carrying user context MUST provide cryptographically verifiable `SessionAssertion` tokens signed by authority services (Session Directory / Identity), containing account ID, canonical bare JID, full JID, connection ID, session epoch, and expiration.
6. **Event Envelopes & Partitioning**:
   - All asynchronous Kafka events MUST use the standardized `events.v1.EventEnvelope` with UUIDv7 `event_id`, source service, aggregate type/ID, partition key (derived from account/room home region), and trace context.

## 3. Code Generation Workflow

Code generation is managed via Buf using the root [buf.gen.yaml](../../buf.gen.yaml):

```bash
# Lint all proto files
buf lint

# Detect breaking wire contract changes
buf breaking --against ".git#branch=main"

# Generate Rust Prost types and Tonic gRPC client/server code
buf generate
```

Generated code is placed in `crates/foundation-contracts/src/generated/` and re-exported through typed modules.
