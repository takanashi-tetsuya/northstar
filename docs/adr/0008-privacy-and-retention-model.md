# ADR-0008: Privacy and Retention Model

## Context

The system stores credentials, messages, presence metadata, reports, policy decisions, and audit trails.
Without a single retention model, data cleanup, legal hold, and export behavior are inconsistent.

## Decision

Adopt a catalog-driven classification model:

- Every authoritative table/field belongs to a `data_class` and `retention_class`.
- Each item has explicit legal_hold policy, delete/export owner, residency and encryption class.
- Retention and deletion operations are part of authoritative service logic and audited.

Privacy-sensitive fields are minimized and should be encrypted/obfuscated where feasible.

## Alternatives

- **Uniform retention defaults**: simple, but violates jurisdiction and risk requirements.
- **Per-service ad-hoc TTL**: operationally inconsistent and unprovable.

We adopt shared retention/PII classification as a first-class contract.

## Consequences

- Compliance and operational scripts can be generated from catalog and migration manifests.
- Incident response and deletion requests need deterministic ownership and evidence records.
- Data migration tools must preserve audit obligations and legal hold invariants.

## Security / Privacy

- Encryption key class is declared for each data class.
- Sensitive exports include redaction policy and retention state snapshot.
- Deletion and retention jobs must not silently drop audit-critical control metadata.

## Migration

- Backfill class and retention metadata for existing tables into catalog manifests.
- Add migration enforcement checks that reject schema additions without declared classes.
- Introduce privacy regression tests for legal hold and retention transitions.

## Status

Accepted.

