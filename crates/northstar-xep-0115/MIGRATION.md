# Migration & Architecture Guide: `northstar-xep-0115`

This document records the extraction of pure XEP-0115 Entity Capabilities (v1.5) protocol models, canonical verification string generation, cryptographic hash algorithms, strict wire parsing/building, and capability verification from the monolithic Northstar server into the standalone, capability-free library crate `northstar-xep-0115`.

---

## 1. Executive Summary & Design Invariants

- **Crate Name**: `northstar-xep-0115`
- **Location**: `crates/northstar-xep-0115`
- **Policy**: Pure capability-free library crate (`#![forbid(unsafe_code)]`, Rust 2021, `rust-version = "1.97"`, `publish = false`, `license = "AGPL-3.0-only"`).
- **Dependencies**: `northstar-xep-core`, `roxmltree = "0.20"`, `thiserror = "2.0"`, `base64 = "0.22"`, `sha1 = "0.10"`, `sha2 = "0.10"`, `serde = { version = "1.0", optional = true }`.
- **Forbidden Capabilities**: No database engines (`sqlx`, `PgPool`), caches (`redis`, `DashMap`, LRU stores), async runtimes (`tokio`), networking/sockets, filesystem, environment access, logging engines (`tracing`/`log`), delivery routing, wall-clock/randomness, or global state (`AppState`).

---

## 2. Extraction & Symbol Mapping

| Legacy Source Location | Legacy Symbol / Function | New Crate Location | Architectural Description |
| :--- | :--- | :--- | :--- |
| `src/xmpp/protocol/caps.rs` | `CAPS_NS`, `DISCO_INFO_NS`, byte & item bounds | `constants.rs` | Extracted namespaces (`CAPS_NS`, `DISCO_INFO_NS`, `DATA_NS`, `XML_NS`), byte limits (`MAX_DISCO_PAYLOAD_BYTES`), item limits (`MAX_DISCO_CHILDREN`, `MAX_IDENTITIES`, `MAX_FEATURES`, `MAX_FORMS`), string length bounds, and static `DESCRIPTOR: ExtensionDescriptor`. |
| `src/xmpp/protocol/caps.rs` | `()` unit error types | `error.rs` | Pure deterministic error conditions represented by `CapsError` (syntax errors, oversized payloads, duplicate identity/feature/form errors, missing/ambiguous `FORM_TYPE`, unsupported algorithms, verification mismatches). |
| `src/state/caps.rs` & `src/xmpp/protocol/caps.rs` | `CapsKey`, identity/feature representations | `model.rs` | Strongly typed domain inputs: `Identity`, `Feature`, `FormField`, `ExtendedForm`, `DiscoInfo`, `CapsAdvertisement`, `CapsKey`, and `CapsValidationResult`. |
| `src/xmpp/protocol/caps.rs` | `verification_string`, `canonical_form` | `canonical.rs` | Spec-compliant XEP-0115 Section 5 canonical string construction (`generate_canonical_verification_string`, `generate_canonical_form_string`) with exact i;octet sorting, `<` delimiters, and duplicate rejection. |
| `src/xmpp/protocol/caps.rs` | `Sha1::digest`, `scoped_algorithm` | `hash.rs` | Cryptographic hash algorithm representation (`CapsHashAlgorithm` supporting SHA-1, SHA-256, SHA-512, SHA-384, SHA-224), Base64 digest computation, and advertisement verification (`verify_caps_advertisement`). |
| `src/xmpp/protocol/caps.rs` | `observed_caps_key`, `caps_disco_request` | `wire.rs` | Strict wire XML parsing and building for presence `<c>` elements (`parse_caps_from_presence`, `build_caps_element`), disco#info query parsing (`parse_disco_info_element`), request builders, and XML escaping helpers. |

---

## 3. Temporary Workspace Header & Local Verification

- **Workspace Header Notice**: The `Cargo.toml` in `crates/northstar-xep-0115` contains a temporary `[workspace]` declaration to permit crate-local validation (`cargo check`, `cargo test`, `cargo clippy`, `cargo fmt`) without altering root workspace files.
- **Integration Requirement**: During root workspace integration, the `[workspace]` table in `crates/northstar-xep-0115/Cargo.toml` MUST be removed, and `crates/northstar-xep-0115` registered in the root workspace `Cargo.toml` members list.
- **Lockfile Policy**: Any temporary nested `Cargo.lock` and `target/` directory generated during verification will be removed upon completion.

---

## 4. Legacy Inconsistencies & Technical Debt Resolved

1. **Deterministic Error Handling**:
   - In legacy `src/xmpp/protocol/caps.rs`, verification string generation and form parsing returned anonymous unit `Err(())` values.
   - `northstar-xep-0115` replaces this with structured, auditable `CapsError` variants distinguishing between duplicate features, duplicate identities, ambiguous `FORM_TYPE` fields, oversized payloads, and invalid characters.
2. **Multi-Hash Algorithm Support**:
   - Legacy server only natively hashed `sha-1`. Other algorithms fell back to JID-scoped caching without verification.
   - `northstar-xep-0115` introduces typed `CapsHashAlgorithm` with native support for `SHA-256`, `SHA-512`, `SHA-384`, and `SHA-224`, while retaining SHA-1 for backward compatibility and providing the typed `CapsScope` boundary through `CapsKey::scoped` for unsupported algorithms.
3. **Decoupling of Verification and Cache Storage**:
   - Legacy code coupled verification calculation directly to `DashMap` storage, `AppState`, `Instant` timestamps, and network concurrency gates.
   - `northstar-xep-0115` isolates verification as pure mathematical and syntactic transformations (`verify_caps_advertisement`), leaving caching and eviction policy to the server orchestration layer.
4. **Strict Form Validation**:
   - Forms without hidden `FORM_TYPE` or non-result forms are safely ignored per XEP-0115 Section 5.3. Forms with duplicate `var` attributes or conflicting `FORM_TYPE` values are rejected fail-closed.

---

## 5. Algorithm Deprecation & Security Policy

- **SHA-1 Deprecation Policy**:
  - XEP-0115 Section 5 specifies SHA-1 as the mandatory-to-implement baseline for historical interoperability.
  - However, SHA-1 is cryptographically broken with respect to collision resistance (SHAttered attack).
  - `CapsHashAlgorithm::is_deprecated(&self)` returns `true` for `Sha1`.
  - Modern clients and servers SHOULD advertise and verify `sha-256`.
  - Unrecognized or weak algorithms (e.g. MD5) MUST NOT be verified globally; if stored, they MUST use `CapsScope::FullJid` to prevent cross-resource cache poisoning attacks. The extracted model deliberately avoids encoding the scope into the algorithm string with control-character delimiters.

---

## 6. Separation from XEP-0390 (Entity Capabilities 2.0)

- **Differences**:
  - XEP-0390 introduces a new namespace (`urn:xmpp:caps`), a root element `<caps>`, and a redesigned verification algorithm based on RFC 8949 CBOR / XML normalization without legacy `<` string concatenation.
  - XEP-0390 eliminates legacy sorting quirks and standardizes on modern hashes (BLAKE2b, SHA-256, SHA-512).
- **Separation Invariant**:
  - XEP-0390 canonicalization is deliberately NOT included in `northstar-xep-0115`.
  - XEP-0390 will be implemented in a dedicated crate `northstar-xep-0390`.
  - The server disco and presence handlers can inspect whether a presence contains `<c xmlns='http://jabber.org/protocol/caps'/>` (XEP-0115) or `<caps xmlns='urn:xmpp:caps'/>` (XEP-0390) and dispatch to the appropriate crate without coupling.

---

## 7. Future Adapter Steps for Server Integration

During root integration:
1. Register `"crates/northstar-xep-0115"` in root `Cargo.toml` workspace members and remove `[workspace]` from `crates/northstar-xep-0115/Cargo.toml`.
2. Add `northstar-xep-0115 = { path = "crates/northstar-xep-0115" }` to root `dependencies`.
3. In `src/xmpp/protocol/caps.rs`:
   - Replace local `verification_string` and `canonical_form` with `northstar_xep_0115::canonical::generate_canonical_verification_string`.
   - Replace raw presence `<c>` parsing with `northstar_xep_0115::wire::parse_caps_from_presence`.
   - Use `northstar_xep_0115::hash::verify_caps_advertisement` for validating incoming disco responses.
