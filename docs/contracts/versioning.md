# Wire contract versioning

Northstar's internal RPC and event contracts are Protobuf modules under
`contracts/proto`.  The generated Rust files in
`crates/foundation-contracts/src/generated` are build inputs, not a second
source of truth.  A contract change is complete only when Buf generation and
the Rust adapter tests agree on the same commit.

## Rules for `v1`

1. Existing field numbers and meanings are immutable.  Removed fields are
   marked `reserved`; numbers are never recycled.
2. Additive fields must be optional/repeated or have a safe zero-value and
   must remain compatible with older readers.
3. A security assertion, event envelope, and idempotency key must not be
   weakened to an untyped string or arbitrary `Any` payload.  Consumers use an
   explicit payload allow-list.
4. Generated code is updated with the pinned Buf toolchain in `buf.gen.yaml`.
   Hand edits to generated output are permitted only as a temporary Windows
   fallback when Buf is unavailable; Linux CI is the authoritative drift gate.
5. Every security-sensitive or cross-service change adds a Protobuf binary
   fixture and a domain-adapter test.  Fixtures are immutable once published.

## Breaking changes

An incompatible semantic or wire change creates a new package (`v2`) and a
documented dual-stack window.  The old package remains available until all
consumers have migrated and the deprecation date is recorded.  A PR must show
the Buf breaking report and the generated-file diff; a local Rust build alone
is not sufficient evidence.

## Release artifacts

Contract releases publish the `foundation-contracts` crate, the Buf descriptor
image, the generated-source checksum, and the fixture checksum.  Signing is a
release-pipeline responsibility; runtime services must verify the configured
key and reject unknown schema versions rather than silently accepting them.
