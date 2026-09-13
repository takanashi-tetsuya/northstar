# Migration & Architecture Guide: `northstar-xep-0060`

This document records the extraction of pure XEP-0060 Publish-Subscribe protocol models, XML wire parsing, safe serialization, configuration validation, access model rules, and Result Set Management (XEP-0059) logic from the monolithic Northstar server into the standalone, capability-free library crate `northstar-xep-0060`.

---

## 1. Executive Summary & Design Invariants

- **Crate Name**: `northstar-xep-0060`
- **Location**: `crates/northstar-xep-0060`
- **Policy**: Pure capability-free library crate (`#![forbid(unsafe_code)]`, Rust 2021, `rust-version = "1.97"`, `publish = false`, `license = "AGPL-3.0-only"`).
- **Dependencies**: `northstar-xep-core`, `northstar-xmpp-types`, `roxmltree = "0.20"`, `thiserror = "2.0"`.
- **Forbidden Capabilities**: No database engines (`sqlx`, `PgPool`), caches (`redis`), async runtimes (`tokio`), networking/sockets, filesystem, environment access, logging engines (`tracing`/`log`), delivery routing, or global state (`AppState`).

---

## 2. Extraction & Symbol Mapping

| Legacy Source Location | Legacy Symbol / Function | New Crate Location | Architectural Description |
| :--- | :--- | :--- | :--- |
| `src/xmpp/protocol/pubsub.rs` | Protocol Constants & XML Namespaces | `constants.rs` | Extracted namespaces (`NS_PUBSUB`, `NS_PUBSUB_OWNER`, `NS_PUBSUB_EVENT`, `NS_PUBSUB_ERRORS`, `NS_DATA`, `NS_RSM`, `NS_SHIM`, `NS_DELAY`), form types (`NODE_CONFIG_FORM`, `PUBLISH_OPTIONS_FORM`, `SUBSCRIBE_AUTH_FORM`, `SUBSCRIBE_OPTIONS_FORM`, `NODE_METADATA_FORM`), structural byte/item limits, and static `DESCRIPTOR: ExtensionDescriptor`. |
| `src/xmpp/protocol/pubsub.rs` | `PubSubError` | `error.rs` | Pure RFC 6120 and XEP-0060 application-specific error condition representations with automatic `StanzaErrorType` category derivation and XML building (`build_iq_error`, `build_s2s_iq_error`). |
| `src/services/pubsub.rs` | `AccessModel`, `PublishModel`, `Affiliation`, `SubscriptionState`, `NodeType`, `SendLastPublishedItem`, `ChildrenAssociationPolicy` | `models.rs` | Enums with canonical XML wire representations, `FromStr` parsers, Display formatting, and validation helpers (`valid_node_id`, `required_node_id`, `valid_item_id`, `valid_redirect_uri`, `valid_language_tag`, `valid_bare_jid`). |
| `src/services/pubsub.rs` & `src/xmpp/protocol/pubsub.rs` | `PubSubNodeConfig`, `PubSubSubscriptionOptions`, form builders & parsers | `config.rs` | Full typed `NodeConfig` and `SubscriptionOptions` with constraint enforcement (`validate_and_normalize`), semantic equivalence (`config_equivalent`), and `jabber:x:data` form parsing/building (`parse_node_config_form`, `build_node_config_form`, `build_subscription_options_form`, `build_node_metadata_form`). |
| `src/xmpp/protocol/pubsub.rs` & `src/mam_pubsub_parsing.rs` | `PubSubRsmRequest`, `parse_pubsub_rsm`, `rsm_set_element` | `rsm.rs` | Pure XEP-0059 Result Set Management wire model (`RsmRequest`, `RsmResponse`), parser (`parse_rsm_element`), safe XML builder (`build_rsm_set`), and deterministic in-memory slicing function (`paginate_items`). |
| `src/xmpp/protocol/pubsub.rs` | `item_retrieval_access`, access check logic | `auth.rs` | Pure capability-free access decision rules (`item_retrieval_access`, `can_retrieve_pure`, `can_publish_pure`, `subscription_initial_state`, `pubsub_policy_suppression_is_terminal`) detached from database/session lookups. |
| `src/xmpp/protocol/pubsub.rs` | Wire structs & dispatch types | `wire.rs` | Typed wire request/response models for entity, owner, and event notifications (`CreateNodeRequest`, `PublishRequest`, `RetractRequest`, `SubscribeRequest`, `UnsubscribeRequest`, `GetItemsRequest`, `GetSubscriptionsRequest`, `GetAffiliationsRequest`, owner operations, and `SubscriptionAuthResponse`). |
| `src/xmpp/protocol/pubsub.rs` & `src/mam_pubsub_parsing.rs` | `parse_pubsub_envelope`, operation parsers, `serialize_pubsub_item`, `extract_atom_event_body` | `parser.rs` | Deterministic, strictly bounded XML parsers, item normalization and namespace cleaning (`serialize_pubsub_item`), and UTF-8-safe Atom entry body text extraction. |
| `src/xmpp/protocol/pubsub.rs` | XML response generators & event packet constructors | `builder.rs` | Safe XML builders for IQ results, subscription messages with SHIM headers, delete/purge/config events, and disco info/items queries. |
| (Internal server utility) | XML text & attribute escaping | `xml.rs` | Lightweight, allocation-conscious XML building and escaping primitives (`XmlElement`, `escape_xml_text`, `escape_xml_attr`, `attr_escape`, `xml_escape`, `validate_qname`) to eliminate dependencies on server internal XML utilities. |

---

## 3. Temporary Workspace Header & Local Verification

- **Workspace Header Notice**: The `Cargo.toml` in `crates/northstar-xep-0060` contains a temporary `[workspace]` declaration to allow crate-local builds (`cargo check`, `cargo test`, `cargo clippy`, `cargo fmt`) without touching or perturbing the repository root `Cargo.toml` or `Cargo.lock`.
- **Integration Requirement**: When integrating this crate into the root workspace during the integration phase, the `[workspace]` table in `crates/northstar-xep-0060/Cargo.toml` MUST be removed, and `crates/northstar-xep-0060` must be registered in the root workspace `Cargo.toml` members list.
- **Lockfile Policy**: Any temporary nested `Cargo.lock` created during local check execution has been removed.

---

## 4. Forbidden Authority & Capability Separation

1. **Pure Access Control Inputs**:
   - Legacy `src/xmpp/protocol/pubsub.rs` intermingled database queries (`get_node_affiliation`, `is_node_owner`, `get_node_subscriptions`) with request parsing and validation.
   - In `northstar-xep-0060`, all access decision functions (`auth::item_retrieval_access`, `auth::can_retrieve_pure`, `auth::can_publish_pure`, `auth::subscription_initial_state`) operate strictly on pure, typed inputs (`AccessModel`, `Option<Affiliation>`, `active_subscription_subids: &[&str]`, `supplied_subid: Option<&str>`).
2. **Clock Decoupling**:
   - Legacy subscription parsing called `chrono::Utc::now()` directly inside form parsing to calculate 365-day lease caps.
   - In `northstar-xep-0060`, `SubscriptionOptions::expire` preserves and validates standard RFC 3339 / ISO 8601 timestamps as structured strings, leaving clock evaluation to the runtime/adapter layer.
3. **Storage & Delivery Isolation**:
   - Crate contains zero storage adapters (no SQL, Postgres, Redis, or memory caching).
   - Event delivery, presence subscriptions, and roster broadcasts remain the responsibility of the server orchestration layer.

---

## 5. Future Adapter Steps for Server Integration

During root integration, the following steps will link the server handlers to `northstar-xep-0060`:

1. **Workspace Registration**: Add `"crates/northstar-xep-0060"` to root `Cargo.toml` workspace members and remove `[workspace]` from `crates/northstar-xep-0060/Cargo.toml`.
2. **Import Replacement**: Replace internal pubsub types in `src/services/pubsub.rs` and `src/xmpp/protocol/pubsub.rs` with `northstar_xep_0060::*`.
3. **Handler Adapter**: Refactor `handle_pubsub_iq` and `handle_pubsub_owner_iq` to:
   - Call `parse_pubsub_envelope` and the respective `parse_*_operation` to obtain typed request structs.
   - Execute database queries and authorization via `auth::item_retrieval_access` / `auth::can_publish_pure`.
   - Call `builder::*` to construct responses.

---

## 6. Known Correction Debt & Suspected Legacy Errors

1. **Implicit Namespace Declaration Stripping Invariant**:
   - In legacy `serialize_pubsub_item`, if a client submitted `<item xmlns='http://jabber.org/protocol/pubsub' ...>`, the default namespace was stripped so that it would adopt `pubsub#event` in event stanzas. However, if a client used a prefixed binding (`xmlns:p='...'`), stripping was inconsistent. The new parser uniformly cleans the root namespace binding while strictly preserving and validating inner child namespaces.
2. **Atom Event Body UTF-8 Truncation**:
   - Legacy Atom body extraction clamped character boundaries by slicing bytes directly or through multi-stage substring operations that could risk character boundary panics under malformed multi-byte sequences. The new implementation enforces safe UTF-8 code point boundary truncation (`truncate_utf8_to_bytes`).
3. **Empty Before RSM Tag**:
   - In XEP-0059 Section 2.5, `<before/>` without text requests the last page of results, whereas `<before>id</before>` requests the page before `id`. Legacy parsing did not consistently distinguish between missing before and empty before. In `northstar-xep-0060`, `RsmRequest::before` is typed as `Option<Option<String>>`, accurately representing `None` (no before), `Some(None)` (empty `<before/>`), and `Some(Some("id"))` (`<before>id</before>`).
