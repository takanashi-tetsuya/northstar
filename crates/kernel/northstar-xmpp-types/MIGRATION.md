# Migration Ledger: `northstar-xmpp-types`

## 1. Source File
- **Source**: `src/jid.rs` (root crate `rust-xmpp-server`)
- **Target**: `crates/kernel/northstar-xmpp-types` (`src/lib.rs`, `src/jid.rs`)

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

## 4. Root Integration
S17 (WP-171) removed the `src/jid.rs` compatibility facade. Root modules import
`northstar_xmpp_types::jid` directly; the crate is the only JID implementation.

---

## 5. Behavior Invariants
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

## 6. Known Risks & Mitigation
- **Case Preservation Pitfall**:
  - *Risk*: Upstream code lowercasing full JIDs (e.g. `jid.to_lowercase()`) destroys case sensitivity of resourceparts.
  - *Mitigation*: Enforce use of `CanonicalJid::parse` and `canonical_bare_key` vs `canonical_session_key`.
- **IDNA Transition Nuances**:
  - *Risk*: Different IDNA library releases may alter STD3 or context rule processing.
  - *Mitigation*: Pinned `idna = "1.1"` dependency in sync with workspace root.
