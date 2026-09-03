# Migration Ledger: `northstar-xmpp-types`

## 1. Source File
- **Source**: `src/jid.rs` (root crate `rust-xmpp-server`)
- **Target**: `crates/northstar-xmpp-types` (`src/lib.rs`, `src/jid.rs`)

---

## 2. Exported Public API
The crate exports the following capability-free types and canonicalization functions:

### Types
- `pub struct CanonicalJid`
  - `pub fn parse(value: &str) -> Result<Self>`
  - `pub fn parse_bare(value: &str) -> Result<Self>`
  - `pub fn localpart(&self) -> Option<&str>`
  - `pub fn domainpart(&self) -> &str`
  - `pub fn resourcepart(&self) -> Option<&str>`
  - `pub fn bare(&self) -> String`
  - Implements: `Clone`, `Debug`, `Display`, `Eq`, `Hash`, `PartialEq`, `Send`, `Sync`

### Preparation and Canonicalization Functions
- `pub fn prepare_localpart(value: &str) -> Result<String>`
- `pub fn prepare_resourcepart(value: &str) -> Result<String>`
- `pub fn prepare_domainpart(value: &str) -> Result<String>`
- `pub fn domain_to_ascii(value: &str) -> Result<String>`
- `pub fn canonicalize(value: &str) -> Result<String>`
- `pub fn canonicalize_bare(value: &str) -> Result<String>`
- `pub fn canonical_bare_key(value: &str) -> Result<String>`
- `pub fn canonical_session_key(value: &str) -> Result<String>`

---

## 3. Dependencies
The crate adheres strictly to the minimal dependency policy:
- `anyhow = "1.0"`: Context-rich error propagation.
- `idna = "1.1"`: RFC 7622 domainpart UTS #46 / IDNA2008 processing.
- `precis-profiles = "0.1.13"`: RFC 8265 PRECIS `UsernameCaseMapped` (localpart) and `OpaqueString` (resourcepart) profiles.

No I/O, async runtime, database, network, logging framework, or global mutable state is introduced. `#![forbid(unsafe_code)]` is enforced at the crate root.

---

## 4. Temporary Duplication
During this phase of parallel modularization:
- `crates/northstar-xmpp-types` has been created in isolation.
- `src/jid.rs` in the root crate is left untouched to prevent build disruption while parallel workers edit other workspace crates.
- The two implementations are algorithmically identical and functionally interchangeable.

---

## 5. Exact Future Root Adapter
Once workspace-wide lock synchronization is completed, integration requires two steps:

### A. Add dependency and workspace member to root `Cargo.toml`
```toml
[workspace]
members = [
    ".",
    "crates/northstar-xmpp-types",
    # ... other crates
]

[dependencies]
northstar-xmpp-types = { path = "crates/northstar-xmpp-types" }
```

### B. Replace `src/jid.rs` with the thin re-export adapter
```rust
//! RFC 7622 JID parsing, preparation, and canonical comparison.
//!
//! Re-exported from `northstar-xmpp-types`.

pub use northstar_xmpp_types::{
    canonical_bare_key, canonical_session_key, canonicalize, canonicalize_bare, domain_to_ascii,
    prepare_domainpart, prepare_localpart, prepare_resourcepart, CanonicalJid,
};
```

---

## 6. Consumers to Migrate
The following modules and crates directly depend on JID canonicalization and parsing:

1. **Authentication & Identity**:
   - `src/auth.rs`: SASL PLAIN / SCRAM authorization identity (`authzid`) and authentication identity (`authcid`) normalization.
   - `src/account_recovery.rs`: Address validation for recovery tokens.
   - `src/db/authorization_identity.rs`: Canonical bare JID extraction.

2. **Cluster & Routing**:
   - `src/cluster.rs`: Inter-node packet routing and session targets.
   - `src/components.rs`: External component domain routing.

3. **HTTP API Surfaces**:
   - `src/api/admin.rs`: MUC room destroy/query JID normalization.
   - `src/api/auth_routes.rs`: Registration / login response JID serialization.
   - `src/api/models.rs`: Admin / user report models.
   - `src/api/reports.rs`: Reported account bare JID canonicalization.
   - `src/api/users.rs`: MAM query `with` filter canonicalization.

4. **Database Repositories**:
   - `src/db/archive.rs`: MAM archive queries (viewer bare JID, target JID).
   - `src/db/admin_commands.rs`: Ad-hoc command account lookups.
   - `src/db/cluster_muc.rs`: MUC room and participant JID keys.
   - `src/db/mix.rs`: MIX channel and participant JID resolution.
   - `src/db/api_operations.rs`: Idempotency keys by account bare JID.

5. **Existing & Future XEP Crates**:
   - `crates/northstar-xep-0461`: Message fast replies routing.
   - `crates/northstar-xep-core`: Future core type sharing.

---

## 7. Behavior Invariants
The extracted crate strictly preserves the following invariants:
1. **Separator Discovery Precedes Normalization (RFC 7622 §3.1)**:
   - Resource delimiter `/` is matched before localpart delimiter `@`.
   - Splitting occurs before Unicode normalization to prevent decomposition characters from introducing artificial delimiters.
2. **Localpart Preparation (PRECIS `UsernameCaseMapped` + RFC 7622 Exclusions)**:
   - Case mapping applied (e.g. `ALICE` -> `alice`).
   - Disallowed characters rejected: `"`, `&`, `'`, `/`, `:`, `<`, `>`, `@`.
   - Max 1023 UTF-8 octets.
3. **Resourcepart Preparation (PRECIS `OpaqueString`)**:
   - Case preserved (e.g. `Mobile` != `mobile`).
   - Spaces and `/`, `@` characters permitted in resources.
   - Control characters and unassigned codepoints rejected.
   - Max 1023 UTF-8 octets.
4. **Domainpart Preparation (IDNA/UTS #46 + IP Literals)**:
   - Trailing label separators (`.`, `\u{3002}`, `\u{ff0e}`, `\u{ff61}`) stripped.
   - Validated via strict UTS #46 ASCII/Unicode round-trip.
   - IPv4 addresses formatted standardly.
   - IPv6 addresses required in `[...]` with RFC 6874 `%25` zone escaping validation.
   - Max 1023 UTF-8 octets.
5. **Total JID Length**:
   - Max 3071 UTF-8 octets enforced both before and after canonical transformations.
6. **Pure Determinism**:
   - Zero side-effects, zero allocations in lookup-only paths where possible, completely thread-safe (`Send + Sync`).

---

## 8. Known Risks & Mitigation
- **Case Preservation Pitfall**:
  - *Risk*: Upstream code lowercasing full JIDs (e.g. `jid.to_lowercase()`) destroys case sensitivity of resourceparts.
  - *Mitigation*: Enforce use of `CanonicalJid::parse` and `canonical_bare_key` vs `canonical_session_key`.
- **IDNA Transition Nuances**:
  - *Risk*: Different IDNA library releases may alter STD3 or context rule processing.
  - *Mitigation*: Pinned `idna = "1.1"` dependency in sync with workspace root.
