# M02 contract boundary checkpoint

This checkpoint records the first deterministic contract-boundary increment. It
does not claim that the remote services are integrated or production-ready.

## Delivered

- `crates/foundation-contracts/src/generated` remains the only generated
  Protobuf/Tonic wire surface.
- Handwritten request/response and event payloads were moved under
  `foundation_contracts::adapters`; the old root modules were removed.
- `adapters::conversions` provides explicit checked conversions for the
  identity, session, ingress, delivery and registry messages. Required
  principals and identifiers are validated before a domain value is created.
- Conversion tests round-trip an actual Protobuf binary payload, reject a
  missing authenticated principal, and verify bounded error-duration mapping.
- Service prototypes now import adapters explicitly, making the remaining
  migration surface visible instead of silently treating domain DTOs as wire
  messages.
- The common contract now defines bounded `RequestMetadata`, opaque
  `IdempotencyKey`, and opaque `PageToken` messages. Their adapters reject
  empty or oversized values before they reach a service boundary.
- `ErrorDetail` has additive canonical `reason`, `domain`, and
  `correlation_id` fields. The legacy `code` field remains a compatibility
  alias during the v1 transition; adapter conversion derives a safe reason
  and redacts connection strings, SQL fragments, credential assignments, and
  raw JID-like tokens from `safe_message`.
- `northstar.security.v1` now owns versioned `AuthGrant` and `SessionAssertion`
  wire messages. Checked adapters enforce required claims, audience matching,
  one-time identifier presence, signature bounds, schema version, and a
  five-minute maximum validity window. Canonical unsigned bytes are produced
  by clearing only the signature field before Protobuf encoding; key lookup and
  cryptographic verification remain in the security runtime. Identity and
  session responses carry these assertions as additive transition fields so
  existing prototype callers can be migrated without silently changing the
  old wire numbers.
- Identity now exposes a bounded Start/Continue/Abort SCRAM exchange. The
  first leg carries only the decoded client-first message, the exchange id is
  opaque and single-use, pending state expires after 60 seconds and is capped
  at 1,024 entries, and unknown accounts use deterministic dummy verifiers.
  The continuation path consumes the exchange before proof verification and
  emits a signed, five-minute AuthGrant on success. Registration and password
  change contracts have SecretBytes-compatible fields while retaining their
  legacy string fields only for the migration window.
- The XMPP Edge adapter now builds the password-free StartAuthentication
  request and accepts a grant-bearing continuation response; the old
  one-shot Authenticate adapter remains available only for compatibility.
- Ingress now carries a bounded canonical-message projection, an idempotency
  key and an optional signed session assertion.  Its adapter validates size,
  schema and field consistency; the executable prototype deduplicates exact
  retries and returns a conflict for a changed payload under the same key.
- Delivery stream contracts now distinguish edge registration, heartbeat and
  acknowledgement payloads and carry the target connection/full-JID/session
  fence plus delivery attempt metadata.  Registry snapshots expose a digest
  and validity metadata instead of treating a checksum as a signature;
  instance registration requires an operator assertion.  EventEnvelope adds
  producer, aggregate, partition, causation/correlation, classification and
  payload-type fields while deliberately avoiding arbitrary type URLs.
- Contract versioning rules, immutable fixture guidance and a pinned Buf CI
  workflow were added under `docs/contracts/versioning.md` and
  `.github/workflows/contracts.yml`.

## M03-01 threat and privacy model

The security design authority is now recorded in
`docs/security/threat-model.md`, `data-flow.md`, `privacy-model.md` and
`abuse-cases.md`.  They enumerate assets, service and storage boundaries,
attacker classes, STRIDE/LINDDUN controls, abuse mitigations, data classes,
retention expectations and residual risks.  Security-path changes must cite a
threat ID and attach test evidence; no boundary is treated as trusted merely
because it is internal.

## M03-02 security foundation increment

`foundation-security` now contains a transport-neutral `AssertionClaims`
canonicalization/validation model, an Ed25519-only `VerifyKeyRing` with
activation/retirement grace handling, an opaque `VerifiedPrincipal` that
cannot be deserialized, scope/role authorization helpers, and a bounded
expiry-aware replay cache. Tests cover valid signatures, bit flips, algorithm
confusion, unknown/retired keys, clock skew and replay-capacity behavior.
SecretString, SecretBytes and OpaqueToken also expose short-lived closure APIs
and class-bound pseudonymization helpers for JID/IP/token/content log fields;
the older reference-returning methods remain a compatibility bridge.
These primitives are deliberately not yet wired into every handler: the
identity/session vertical slices still use their transition adapters, and key
material must be supplied by the future KMS/SPIFFE integration.

## M03-05 key-management boundary

`crates/foundation-kms` defines provider-neutral `Signer`, `AeadKeyProvider`
and `HmacKeyProvider` interfaces plus a monotonic key lifecycle.  Metadata is
kept separate from key bytes and includes class, owner service, region,
environment, algorithm and rotation deadline.  The six required key classes
are recorded in `catalog/key-classes.yaml`; protocol and service crates do not
depend on a cloud-specific KMS SDK.  A development-only in-memory HMAC
provider is feature-gated and stores test bytes in `Zeroizing` memory.  The
production path intentionally remains an external KMS/HSM or workload-
identity signer and is not represented as complete until a deployment adapter
and rotation evidence exist.

## M02-05 session contract progress

`session.proto` declares the lease renewal, prepare/commit resume, assertion
validation and account-session revocation RPCs. Their requests carry expected
session/region or credential epochs and bounded idempotency keys; resume carries
only a token hash, and target responses include route incarnation and expiry
metadata. The checked Prost structs, bidirectional adapters and generated Tonic
client/server routes contain the same additive fields. The executable session
prototype now enforces lease/epoch fences, single-use resume authority,
idempotent close, assertion lifetime/audience validation and account-wide
revocation, with tests for stale epochs, route metadata and token replay.
PostgreSQL persistence, signature/key verification and production gRPC startup
remain later vertical-slice work; this checkpoint does not claim those are
complete.

## Verification

```text
cargo test --locked -p foundation-contracts
cargo test --locked -p service-identity --lib
cargo test --locked -p service-xmpp-edge --lib
cargo clippy --locked -p foundation-contracts --all-targets -- -D warnings
cargo check --workspace --all-targets --locked
```

The common-contract conversion tests also cover Protobuf binary round trips,
opaque metadata bounds, canonical error fields, safe-message redaction and
SCRAM exchange payload bounds. Identity tests cover successful exchange setup,
uniform unknown-account failures, single-use replay rejection, exchange
capacity/expiry policy and idempotent abort. Edge tests cover the existing
session lifecycle and the password-free request builder.

The local Windows checkout does not include the Buf CLI, so Buf format/lint/
breaking/generate were not executed here. The checked generated files were
updated alongside the schemas; the Linux `contracts-quality` job remains the
authoritative generated-drift and compatibility gate for this checkpoint.

## Remaining M02 work

The next contract tasks still require the Buf toolchain and a compatibility
window: replacing compatibility `AuthContext` with signed assertion metadata
on every RPC, wiring the session prototype to its PostgreSQL authority and
cryptographic key verifier, completing ingress/delivery/registry/event
contracts, and adding binary golden fixtures plus the contract-versioning
workflow. The generated files in this checkout are kept in sync manually
because the local Windows environment does not include Buf; Linux CI remains
authoritative for generated drift and breaking-change checks.
Until those tasks are complete, services remain
`executable-prototype`/`prototype` in the catalog.
