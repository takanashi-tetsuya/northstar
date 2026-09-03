# Migration & Architecture Guide: `northstar-xep-0313`

This document records the extraction of pure XEP-0313 Message Archive Management (MAM) protocol models, XML wire parsing, safe serialization, configuration and preference validation, pure preference decision logic, and Result Set Management (XEP-0059) integration from the monolithic Northstar server into the standalone, capability-free library crate `northstar-xep-0313`.

---

## 1. Executive Summary & Design Invariants

- **Crate Name**: `northstar-xep-0313`
- **Location**: `crates/northstar-xep-0313`
- **Policy**: Pure capability-free library crate (`#![forbid(unsafe_code)]`, Rust 2021, `rust-version = "1.97"`, `publish = false`, `license = "AGPL-3.0-only"`).
- **Dependencies**: `northstar-xep-core`, canonical `northstar-xep-0059`, `northstar-xmpp-types`, `roxmltree = "0.20"`, `thiserror = "2.0"`, optional `serde = "1.0"`.
- **Forbidden Capabilities**: No database engines (`sqlx`, `PgPool`), caches (`redis`), async runtimes (`tokio`), networking/sockets, filesystem, environment access, logging engines (`tracing`/`log`), delivery routing, clock/randomness access, or global state (`AppState`).

---

## 2. Extraction & Symbol Mapping

| Legacy Source Location | Legacy Symbol / Function | New Crate Location | Architectural Description |
| :--- | :--- | :--- | :--- |
| `src/mam_pubsub_parsing.rs` & `src/xmpp/protocol/mam.rs` | `MAM_NS`, `RSM_NS`, `MAX_MAM_RESULTS`, bounds | `constants.rs` | Protocol namespaces (`XMLNS_MAM`, `XMLNS_RSM`, `XMLNS_DATA`, `XMLNS_FORWARD`, `XMLNS_DELAY`, `XMLNS_SID`), bounds (`MAX_MAM_RESULTS`, `MAX_MAM_IDS`, `MAX_MAM_RSM_INDEX`, `MAX_PREFS_JIDS`, `MAX_QUERY_ID_BYTES`, `MAX_ARCHIVE_ID_BYTES`), and static `DESCRIPTOR: ExtensionDescriptor`. |
| `src/mam_pubsub_parsing.rs` & `src/xmpp/protocol/mam.rs` | `Result<T, &'static str>` error conditions | `error.rs` | Typed `MamError` enum with automated RFC 6120 error condition (`as_stanza_error_condition`) and type categorization (`stanza_error_type`). |
| `src/mam_pubsub_parsing.rs` | `parse_archive_id`, `MamRsmPage`, `ParsedMamQuery` | `query.rs` | Typed domain models `ArchiveId` (UUID validation & canonicalization), `UtcTimestamp` (pure RFC 3339 parsing and conversion), `MamRsmPage`, `MamFilter`, and `MamQuery`. |
| `src/xmpp/protocol/mam.rs` & `src/db/archive.rs` | `MamPreferences`, `parse_mam_preferences`, `archive_allowed` | `prefs.rs` | Typed `DefaultPolicy` and `MamPreferences` with strict disjointness validation, canonical JID preparation, and capability-free pure decision evaluation (`evaluate_preference`, `evaluate_preference_with_canonical`). |
| `src/xmpp/protocol/mam.rs` & `src/db/archive.rs` | `ArchiveRow`, `ArchivePage`, `ArchiveBoundary` | `result_fin.rs` | Capability-free wire representations `MamResult`, `MamFin`, `MamMetadataBoundary`, and `MamMetadata`. |
| `src/xmpp/xml_util.rs` & `src/xmpp/protocol/mam.rs` | `mam_extended_form`, `mam_preferences_xml`, `add_stanza_id`, fin/result building | `builder.rs` | Safe XML builders for data forms (`build_extended_form`), metadata (`build_metadata`), preferences (`build_preferences`), forwarded wrapper (`build_forwarded`), results (`build_result_payload`, `build_result_message`), and fin envelopes (`build_fin`, `build_fin_from_model`). Pure `reassert_archive_stanza_id` strips forged account claims and asserts authoritative stanza-id. |
| `src/mam_pubsub_parsing.rs` & `src/xmpp/protocol/mam.rs` | `parse_mam_query`, `parse_mam_form`, `parse_mam_rsm`, `parse_mam_preferences`, `empty_mam_command` | `parser.rs` | Deterministic, strictly bounded XML parsers for queries, forms, preferences, metadata, fin responses, and empty GET commands. RSM envelopes are delegated to `northstar-xep-0059`. |
| (Internal server utility) | XML text & attribute escaping | `xml.rs` | Lightweight XML building primitives (`XmlElement`, `escape_xml_text`, `escape_xml_attr`, `attr_escape`, `xml_escape`, `validate_qname`). |

---

## 3. Temporary Workspace Header & Local Verification

- **Workspace Header Notice**: The `Cargo.toml` in `crates/northstar-xep-0313` contains a temporary `[workspace]` declaration to allow crate-local builds and checks (`cargo test`, `cargo clippy`, `cargo fmt`) without touching or modifying the repository root `Cargo.toml` or `Cargo.lock`.
- **Integration Requirement**: When integrating this crate into the root workspace during the integration phase, the `[workspace]` table in `crates/northstar-xep-0313/Cargo.toml` MUST be removed, and `crates/northstar-xep-0313` must be registered in the root workspace `Cargo.toml` members list.
- **Lockfile Policy**: Any temporary nested `Cargo.lock` created during local check execution has been removed.

---

## 4. Forbidden Authority & Capability Separation

1. **Storage & Database Decoupling**:
   - Legacy `src/db/archive.rs` executed SQL queries (`SELECT default_policy FROM mam_preferences`, `WITH effective AS ... SELECT CASE ...`) to evaluate message archiving preferences and perform keyset paging against PostgreSQL.
   - In `northstar-xep-0313`, all preference decision logic (`prefs::evaluate_preference`, `prefs::evaluate_preference_with_canonical`) operates purely in memory on typed models and explicit inputs (`prefs`, `peer_jid`, `is_in_roster`).
2. **Clock Decoupling**:
   - Legacy code called `chrono::Utc::now()` directly inside timestamp assertions.
   - In `northstar-xep-0313`, timestamps are represented by the pure `UtcTimestamp` model, which validates and formats RFC 3339 timestamps using pure integer civil calendar calculations without querying system time or accessing global clocks.
3. **Authorization & Room Access Isolation**:
   - Room membership, affiliation checks, MUC occupant ID generation, and encryption decisions remain server-owned in server service adapters (`src/services/mam.rs`).
   - `northstar-xep-0313` accepts only already-authorized stanzas and clean inputs.

---

## 5. Result Set Management (XEP-0059) Integration

- **Canonical sibling**: `northstar-xep-0313` now directly depends on
  `northstar-xep-0059`; its descriptor declares XEP-0059 as a real dependency.
- **Request path**: the MAM parser delegates the complete `<set/>` envelope,
  duplicate detection, numeric parsing, cursor exclusivity and operational
  bounds to `parse_rsm_element_with_bounds`. It then performs only the
  MAM-specific UUID cursor conversion and page-size policy.
- **Response path**: MAM fin parsing uses the canonical `RsmResponse` parser and
  validates returned cursor values as `ArchiveId`. Fin construction uses the
  canonical XEP-0059 response builder.
- **Remaining MAM projection**: `MamRsmPage` is intentionally retained as an
  archive-domain projection because its before/after values are validated
  `ArchiveId` objects, not arbitrary RSM strings. It no longer parses or renders
  RSM XML.

---

## 6. Future Adapter Steps for Server Integration

During the server root integration phase, the following steps will link the server handlers to `northstar-xep-0313`:

1. **Workspace Registration**: Add `"crates/northstar-xep-0313"` to the root `Cargo.toml` workspace members list and remove `[workspace]` from `crates/northstar-xep-0313/Cargo.toml`.
2. **Import Replacement**: Replace internal MAM protocol types in `src/xmpp/protocol/mam.rs` and `src/mam_pubsub_parsing.rs` with `northstar_xep_0313::*`.
3. **Handler Adapter**: Refactor MAM IQ handlers to:
   - Call `parse_mam_query`, `parse_mam_preferences`, and `is_empty_mam_command`.
   - Use `evaluate_preference` in message pipeline filters.
   - Use `build_result_message`, `build_fin`, `build_metadata`, `build_preferences`, and `reassert_archive_stanza_id` to generate outbound wire XML.

---

## 7. Known Correction Debt & Legacy Inconsistencies

1. **UUID Format Strictness vs Opaque Archive IDs**:
   - XEP-0313 specifies that archive IDs are opaque string tokens. In Northstar's Postgres backend, archive IDs are 128-bit UUIDs stored as UUID columns and formatted as standard 36-character hyphenated hexadecimal strings. Legacy `src/mam_pubsub_parsing.rs` used `Uuid::parse_str(value).map_err(|_| "item-not-found")`. `northstar-xep-0313::ArchiveId` preserves this exact validation behavior, normalizing to lowercase hex and returning `MamError::ItemNotFound` on invalid syntax.
2. **Whitespace in JID Filters**:
   - In legacy XML parsing, leading or trailing whitespace around a JID in `<field var='with'><value> alice@example.test </value></field>` caused `jid-malformed` errors because PRECIS username profiles disallow surrounding whitespace. `northstar-xep-0313` strictly preserves this behavior through `northstar-xmpp-types`.
3. **Empty vs Missing Preference Lists**:
   - XEP-0313 recommends always returning both `<always/>` and `<never/>` containers in `<prefs>` query results even if one or both are empty. The legacy builder did this, and `northstar-xep-0313::build_preferences` continues to enforce this invariant.
