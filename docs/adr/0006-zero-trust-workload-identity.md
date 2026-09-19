# ADR-0006: Zero Trust Workload Identity and Signed Assertions

## Context

Internal service callers currently may pass user/session identity payloads directly,
which risks trusting unverified caller-provided context and broadens privilege abuse surface.

## Decision

Workload-to-workload calls must authenticate by workload identity (mTLS/Trust Domain identity)
and verify signed assertions for delegated user scope.

- Internal RPC trust root is **workload identity + signed assertion**.
- User-level authorization is derived from verified assertions and deployment-time policy,
  never from raw request fields.
- Unverified identity context is rejected with fail-closed behavior.

## Alternatives

- **Caller-provided plaintext user context**: simpler, but not secure.
- **Full external IdP mediation for all calls**: stronger but heavier and unnecessary for internal service mesh.

We choose signed assertions over raw context with workload identity binding.

## Consequences

- Service entry points must validate claims, expiry, nonce/audience and audience-scoped keys.
- Audit logs include assertion IDs and principal mapping.
- Replay and replay-window handling become part of transport-level policy.

## Security / Privacy

- Principle: user identity is never trusted unless cryptographically verified.
- Assertion payload is minimized to authorization intent and session/lease fields.
- Failed verification is logged with structured redaction.

## Migration

- Introduce auth context verifier wrapper in `foundation-service-runtime`.
- Replace direct `AuthContext` propagation with internal verified principal types.
- Keep transition via compatibility adapters for non-critical paths only under explicit temporary flag.

## Status

Accepted.

