# Migration Ledger: `northstar-auth-core`

## 1. Executive Summary & Purpose

`northstar-auth-core` is a capability-free, zero-IO Rust library crate extracted from `src/auth.rs`. It encapsulates pure cryptographic operations, SASL/SCRAM state machines, Argon2id password verification, channel-binding negotiation, and FAST (XEP-0484) token derivations for the Northstar XMPP server.

### Crate Specifications
- **Package Name**: `northstar-auth-core`
- **Path**: `crates/northstar-auth-core`
- **Edition**: Rust 2021
- **MSRV**: 1.97
- **License**: AGPL-3.0-only
- **Safety Policy**: `#![forbid(unsafe_code)]`
- **Publish**: `false`
- **Dependencies Allowed & Used**: `anyhow`, `argon2`, `base64`, `hmac`, `pbkdf2`, `rand`, `sha1`, `sha2`, `uuid`, `zeroize`, and `northstar-xmpp-types`.
- **Capability Isolation**: Absolutely no database (PgPool/SQLx), network (Tokio/Axum), filesystem, environment, logging/tracing, AppState, or server runtime types.

---

## 2. Module Map & Extracted Symbols

The monolithic structure of `src/auth.rs` has been decomposed into five coherent modules with full re-exports at the crate root (`lib.rs`):

| Module | Source File | Extracted Symbols & Types | Purpose |
|---|---|---|---|
| `channel_binding` | `src/channel_binding.rs` | `ChannelBindings` | RFC 5929 (`tls-server-end-point`) and RFC 9266 (`tls-exporter`) channel binding encapsulation, XML feature generation, and FAST mechanism binding resolution. |
| `fast` | `src/fast.rs` | `FAST_MECHANISMS`, `is_fast_mechanism`, `fast_channel_binding_name`, `derive_fast_token`, `fast_proof`, `verify_fast_proof` | XEP-0484 FAST (Hash-Token) mechanism validation, token derivation from master key, and directional initiator/responder proof verification. |
| `password` | `src/password.rs` | `normalize_username`, `validate_password`, `PasswordCredentials`, `hash_password`, `PasswordVerifierError`, `is_password_verifier_integrity_error`, `verify_password`, `verify_against_dummy_hash`, `new_session_token`, `token_hash`, `constant_time_bytes_eq` | Argon2id password hashing and bounded verification, username normalization via PRECIS, session token generation/hashing, and constant-time buffer equality checks. |
| `scram` | `src/scram.rs` | `MIN_SCRAM_ITERATIONS`, `DEFAULT_SCRAM_ITERATIONS`, `MAX_SCRAM_ITERATIONS`, `generate_scram_salt`, `compute_scram_sha256`, `compute_scram_sha1`, `ScramAlgorithm`, `dummy_scram_iterations`, `dummy_scram_credentials`, `scram_hmac` | PBKDF2-HMAC SCRAM-SHA-256 and SCRAM-SHA-1 credential computation, iteration bounds, and account-enumeration resistant dummy credential derivation. |
| `sasl` | `src/sasl.rs` | `SaslFailure`, `SaslStep`, `SaslMechanism` (trait), `PlainMechanism`, `ExternalMechanism`, `ScramSha256Mechanism` | SASL state machines for PLAIN (RFC 4616), EXTERNAL (RFC 4422 mTLS bare JID), and SCRAM-SHA-256 / SCRAM-SHA-1 (RFC 5802 / RFC 7677) including channel-bound PLUS variants. |

---

## 3. Callers in `src/` (Migration Ledger)

The following existing callers in `src/` reference `crate::auth` and will cleanly consume `northstar_auth_core` once root integration is unified:

| Caller File | Referenced Symbols | Usage Description |
|---|---|---|
| `src/abuse.rs` | `MIN_SCRAM_ITERATIONS` | Work factor validation for abuse rate-limiting thresholds. |
| `src/api/admin.rs` | `new_session_token` | Admin session token generation. |
| `src/api/auth_routes.rs` | `normalize_username`, `validate_password`, `is_password_verifier_integrity_error` | HTTP REST authentication endpoint input validation and integrity classification. |
| `src/api/mod.rs` | `normalize_username`, `token_hash` | REST API authentication header handling and token digests. |
| `src/api/upload.rs` | `token_hash` | File upload bearer token hashing. |
| `src/api/users.rs` | `validate_password`, `is_password_verifier_integrity_error` | User registration and password modification API. |
| `src/config.rs` | `DEFAULT_SCRAM_ITERATIONS`, `MIN_SCRAM_ITERATIONS`, `MAX_SCRAM_ITERATIONS`, `constant_time_bytes_eq` | Configuration validation for SCRAM iteration settings and constant-time secret comparison. |
| `src/db/admin_commands.rs` | `normalize_username`, `hash_password`, `new_session_token` | Admin CLI user creation and password resets. |
| `src/db/api_control.rs` | `MIN_SCRAM_ITERATIONS`, `token_hash`, `new_session_token` | API key and invitation token generation and verification. |
| `src/db/fast.rs` | `derive_fast_token`, `fast_channel_binding_name`, `token_hash`, `is_fast_mechanism`, `constant_time_bytes_eq`, `verify_fast_proof`, `fast_proof` | Database layer storage and validation of FAST token proofs. |
| `src/db/omemo_recovery.rs` | `token_hash`, `new_session_token` | OMEMO emergency recovery tokens. |
| `src/db/reports.rs` | `normalize_username` | Normalizing reported user identities. |
| `src/db/roster.rs` | `normalize_username` | Normalizing roster contact usernames. |
| `src/db/upload.rs` | `token_hash`, `new_session_token` | HTTP upload slot token generation and validation. |
| `src/db/upload_admin.rs` | `token_hash` | Admin upload verification. |
| `src/pie.rs` | `normalize_username`, `hash_password` | Account import/export handling. |
| `src/services/sm.rs` | `new_session_token` | Stream management resumption token generation. |
| `src/state.rs` | `DEFAULT_SCRAM_ITERATIONS`, `MIN_SCRAM_ITERATIONS`, `MAX_SCRAM_ITERATIONS` | Server runtime state configuration defaults. |
| `src/xmpp/mod.rs` | `ChannelBindings`, `SaslMechanism`, `PlainMechanism`, `ExternalMechanism`, `ScramSha256Mechanism`, `SaslStep` | C2S TLS handshake and SASL mechanism initialization. |
| `src/xmpp/protocol.rs` | `ChannelBindings`, `SaslMechanism`, `PlainMechanism`, `ExternalMechanism`, `ScramSha256Mechanism` | XMPP stream feature negotiation and SASL stanzas. |
| `src/xmpp/protocol/commands.rs` | `normalize_username`, `hash_password`, `validate_password` | Ad-hoc commands password changes. |
| `src/xmpp/protocol/ibr.rs` | `normalize_username`, `hash_password`, `validate_password` | In-Band Registration (XEP-0077) validation and hashing. |
| `src/xmpp/protocol/sasl2.rs` | `ChannelBindings`, `SaslMechanism`, `PlainMechanism`, `ExternalMechanism`, `ScramSha256Mechanism`, `SaslStep`, `is_fast_mechanism`, `fast_channel_binding_name`, `verify_fast_proof`, `fast_proof` | SASL2 (XEP-0388) and FAST inline token authentication. |

---

## 4. Root Integration

The root workspace now owns this crate and `src/auth.rs` is the following
minimal compatibility facade:

```rust
//! Cryptographic authentication and SASL state-machines for Northstar.
//!
//! Re-exported from the capability-free `northstar-auth-core` crate.

pub use northstar_auth_core::*;
```

All existing `crate::auth::*` callers therefore execute this crate's
implementation. The former monolithic duplicate was deleted.

---

## 6. Security Invariants Preserved

1. **Argon2 Work Factor Ceilings**:
   `verify_password` strictly rejects stored PHC parameters with `m_cost > 64MiB`, `t_cost > 8`, `p_cost > 4`, or `output_len != 32`. This prevents malicious or corrupted database entries from mounting denial-of-service or memory-exhaustion attacks on password verification threads.
2. **Integrity Error Distinction**:
   `is_password_verifier_integrity_error` guarantees that malformed PHC hashes are distinguished from standard password mismatches, preventing silent corruption masking while presenting uniform rejection to unauthenticated clients.
3. **Zeroization of Sensitive Material**:
   - `PasswordCredentials` zeroes PHC hashes, SCRAM salts, stored keys, and server keys upon `Drop`.
   - `ChannelBindings` zeroes TLS endpoint and exporter channel binding buffers upon `Drop`.
   - `ScramSha256Mechanism` zeroes nonce, bare client/server messages, auth message, and HMAC keys upon `Drop`.
4. **Account-Enumeration Resistance (Dummy SCRAM)**:
   `dummy_scram_iterations` and `dummy_scram_credentials` derive deterministic, account-specific, secret-keyed dummy verifiers and iterations matching the real wire shape so missing/disabled accounts cannot be enumerated via timing or error responses.
5. **Channel-Binding Downgrade Protection**:
   `ScramSha256Mechanism` terminates with a failure if a client sends the `y` GS2 header flag when channel binding was advertised by the server.
6. **Length-Delimited FAST Token Derivations**:
   `derive_fast_token` encodes each identity component (UUIDs, mechanism length prefix, mechanism bytes, nonce) unambiguously into HMAC-SHA256, eliminating delimiter collision attacks.
7. **Canonical JID Verification**:
   Username normalization and authorization identity (`authzid`) matching delegate strictly to `northstar-xmpp-types::CanonicalJid` and `prepare_localpart` (RFC 7622 PRECIS profiles).

---

## 7. Dependency Order & Workspace Integration

1. `crates/northstar-xmpp-types` (Base JID, PRECIS profiles, IDNA)
2. `crates/northstar-auth-core` (Depends on `northstar-xmpp-types`)
3. `crates/northstar-xep-*`
4. `rust-xmpp-server` (Root binary and integration)

In root `Cargo.toml`, add:
```toml
[workspace]
members = [
    ".",
    "crates/northstar-auth-core",
    "crates/northstar-xmpp-types",
    # ...
]
```

---

## 8. Remaining Migration Work

- Application services still refer to the compatibility facade instead of
  importing `northstar-auth-core` directly. This is intentional while service
  crates are extracted; it is no longer an implementation duplication.
