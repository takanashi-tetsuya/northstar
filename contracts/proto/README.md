# Northstar Microservices Protobuf Wire Contracts

This directory contains the canonical Protocol Buffers (v3) wire definitions for Northstar Microservices.
All synchronous RPCs and asynchronous event envelopes across service boundaries MUST be defined here.

## Structure
- 
orthstar/common/v1/: Shared types (ErrorDetail, AuthContext, TraceContext).
- 
orthstar/identity/v1/: User credential, SCRAM challenge, and account life-cycle RPCs.
- 
orthstar/session/v1/: Resource binding, session epoch fencing, and target resolution RPCs.
- 
orthstar/ingress/v1/: Message admission and authority ingress RPCs.
- 
orthstar/delivery/v1/: Bi-directional Edge streaming and socket delivery RPCs.
- 
orthstar/registry/v1/: Signed route catalog snapshots and protocol discovery RPCs.
- 
orthstar/events/v1/: Canonical Transactional Outbox and Consumer Inbox event payloads.

## Standards & Invariants
1. **Source of Truth**: .proto files are the sole wire contract source.
2. **Backward Compatibility**: Fields must not be renumbered or removed without deprecation cycles.
3. **Buf Validation**: Schemas must pass uf lint and uf breaking.
4. **Strict Isolation**: No service-internal database implementation details or sensitive unencrypted credentials may appear in public message definitions.
