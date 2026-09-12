# Migration & Architecture Guide: `northstar-xep-0357`

This document records the extraction of pure XEP-0357 Push Notifications protocol models,
XML wire parsing, safe serialization, subscription identity/configuration validation,
notification summary types, disclosure privacy policies, eligibility evaluation,
coalescing/deduplication keys, and delivery-attempt response types from the monolithic
Northstar server into the standalone, capability-free library crate `northstar-xep-0357`.

---

## 1. Executive Summary & Design Invariants

- **Crate Name**: `northstar-xep-0357`
- **Location**: `crates/northstar-xep-0357`
- **Policy**: Pure capability-free library crate (`#![forbid(unsafe_code)]`, Rust 2021, `rust-version = "1.97"`, `publish = false`, `license = "AGPL-3.0-only"`).
- **Dependencies**: `northstar-xep-core`, `northstar-xmpp-types`, `roxmltree = "0.20"`, `thiserror = "2.0"`, optional `serde = "1.0"`.
- **Forbidden Capabilities**: No database engines (`sqlx`, `PgPool`), caches (`redis`), async runtimes (`tokio`), networking/sockets, filesystem, environment access, logging engines (`tracing`/`log`), delivery routing, clock/randomness access, push provider credentials, persistence, retry workers, actual pubsub/S2S delivery, transport routing, or global state (`AppState`).

---

## 2. Extraction & Symbol Mapping

| Legacy Source Location | Legacy Symbol / Function | New Crate Location | Architectural Description |
| :--- | :--- | :--- | :--- |
| `src/xmpp/protocol/misc.rs` | `parse_push_enable()`, bare JID enforcement, node bounds | `wire.rs` + `subscription.rs` | Strict `parse_enable()` returning typed `PushEnableRequest` with `PushNode`, `PushSubscriptionKey`, and `PublishOptions`. |
| `src/xmpp/protocol/misc.rs` | `parse_push_disable()` | `wire.rs` + `subscription.rs` | Strict `parse_disable()` returning typed `PushDisableRequest`. |
| `src/xmpp/protocol/misc.rs` | `valid_push_node()` | `subscription.rs` | `validate_push_node()` with `PushNode` newtype (non-empty, ≤ 1024, no control chars). |
| `src/xmpp/protocol/misc.rs` | `valid_push_options()` | `subscription.rs` | `PublishOptions::parse()` — full data form validation with duplicate detection. |
| `src/xmpp/protocol/misc.rs` | `push_iq_targets_account()` | `wire.rs` | `iq_targets_own_account()`. |
| `src/xmpp/protocol/misc.rs` | `send_push_notification()` summary construction | `summary.rs` | `PushSummary` typed model with `to_data_form_xml()` / `to_notification_xml()`. |
| `src/xmpp/protocol/misc.rs` | pubsub notification IQ construction | `builder.rs` | `build_notification_iq()` safe XML builder. |
| `src/xmpp/protocol/misc.rs` | `handle_push_delivery_response()` response classification | `policy.rs` | `DeliveryResponseKind` / `DeliveryResponseOutcome` typed enums. |
| `src/services/push.rs` | `PushBatch` / `PushDelivery` / `PushEnableOutcome` / `PushResponseKind` / `PushResponseOutcome` | `policy.rs` + `subscription.rs` | Typed enums without database/service coupling. |
| `src/db/push.rs` | `MAX_PUSH_SUBSCRIPTIONS_PER_USER`, coalesce/delivery constants | `constants.rs` | Exported bounds as `MAX_SUBSCRIPTIONS_PER_USER`, `NOTIFICATION_COALESCE_SECONDS`, `DELIVERY_CORRELATION_SECONDS`, `MAX_ENABLE_ATTEMPTS_PER_MINUTE`. |
| `src/xmpp/protocol/discovery.rs` | `"urn:xmpp:push:0"` disco feature | `constants.rs` | `DISCO_FEATURE_PUSH` and `DESCRIPTOR` static. |
| *(new pure logic)* | *(none; previously hardcoded in stanza handler)* | `policy.rs` | `evaluate_eligibility()` — pure input/output notification eligibility for offline, CSI inactive, mention/priority, encrypted, and error conditions. |
| *(new pure logic)* | *(none; previously implicit)* | `policy.rs` | `DisclosurePolicy` / `apply_disclosure_policy()` — explicit privacy controls ensuring default never leaks plaintext/body. |
| *(new pure logic)* | *(none; implicit in SQL)* | `policy.rs` | `PushCoalesceKey` — deterministic coalescing/deduplication key with round-trip serialization. |

---

## 3. Temporary Workspace Header & Local Verification

- **Workspace Header Notice**: The `Cargo.toml` in `crates/northstar-xep-0357` contains a temporary `[workspace]` declaration to allow crate-local builds and checks without touching the root `Cargo.toml` or `Cargo.lock`.
- **Integration Requirement**: When integrating, remove `[workspace]` from `crates/northstar-xep-0357/Cargo.toml` and add `"crates/northstar-xep-0357"` to the root workspace members list.
- **Lockfile Policy**: Any temporary nested `Cargo.lock` created during local check execution has been removed.

---

## 4. Forbidden Authority & Capability Separation

1. **Storage & Database Decoupling**: Legacy `src/db/push.rs` executed SQL queries for subscription CRUD, rate limiting, coalescing windows, and delivery correlation. In `northstar-xep-0357`, all subscription models are pure typed data; persistence, rate limiting, and advisory locking remain server-owned.

2. **Clock Decoupling**: Legacy coalescing used `chrono::Utc::now()` for next-notification-at windowing and delivery correlation expiry. In `northstar-xep-0357`, coalescing and correlation are expressed as duration constants and typed keys; actual clock reads remain server-side.

3. **Authorization & Routing Isolation**: Account authentication, session presence routing, local/cluster delivery, S2S federation, and push provider credential handling remain in server service adapters.

4. **Push Provider Credentials**: Provider-specific secrets (APNs tokens, FCM keys, etc.) are never handled by this crate. The `PublishOptions` pass-through preserves them opaquely for the server to relay without extraction.

---

## 5. Known Correction Debt & Legacy Ambiguities

1. **Rate Limiting Window Semantics**: Legacy `src/db/push.rs` implements a sliding-window rate limit using `push_enable_rate_limits` PostgreSQL table with `window_started_at` and `attempts` counter. The exact window reset behavior (whether the window resets on the first attempt after expiry or only after commit) is PostgreSQL-transaction dependent. The crate exports the constant `MAX_ENABLE_ATTEMPTS_PER_MINUTE = 30` but defers window implementation authority to the server adapter.

2. **Subscription Quota Enforcement Ordering**: Legacy code checks quota *after* rate limiting within the same advisory lock. Whether quota errors should take precedence over rate-limit errors (or vice versa) when both apply simultaneously is unspecified in XEP-0357. The crate provides the constant `MAX_SUBSCRIPTIONS_PER_USER = 16` without prescribing evaluation order.

3. **Notification Coalescing Window**: Legacy uses `NOTIFICATION_COALESCE_SECONDS = 15` with `GREATEST(next_notification_at, NOW() + INTERVAL '15 seconds')`. Whether this window should be configurable per-account or globally adjustable is unspecified. The crate exports it as a constant.

4. **Delivery Correlation Expiry**: Legacy uses `DELIVERY_CORRELATION_SECONDS = 300` (5 minutes). Whether expired correlation tokens should be garbage-collected eagerly or lazily is an implementation detail. The crate only defines the duration constant.

5. **Consecutive Failure Threshold for Automatic Unsubscription**: Legacy `src/db/push.rs` disables subscriptions on the first permanent error (`PushResponseKind::PermanentError`). Whether transient errors should accumulate consecutive failures toward automatic unsubscription (and at what threshold) is unspecified. The crate provides the `DeliveryResponseKind::TransientError` variant but does not prescribe failure accumulation policy.

6. **Service-Initiated Disable Message Format**: Legacy `handle_push_disable()` in `misc.rs` expects a very specific message format: `<message>` containing a single `<pubsub xmlns='http://jabber.org/protocol/pubsub'>` child with exactly one `<affiliation>` child having `affiliation='none'` and `jid` matching the message `to`. This format is not standardized by XEP-0357 and appears to be a Northstar-specific convention derived from XEP-0060 affiliation notifications. The crate does not model this service-initiated disable path; it remains in the server adapter.

7. **Privacy of Summary in Cluster Forwarding**: When a push notification is forwarded between cluster nodes, the summary payload is transmitted in cleartext between nodes. Whether the disclosure policy should be re-evaluated per cluster hop is unspecified.

8. **Node Attribute Omission vs Empty String**: Legacy code treats `node=""` as an error but omitted `node` attribute as "empty node" (`String::new()`). XEP-0357 §3.2 says "optionally, a 'node' attribute". The crate models this as `Option<PushNode>` where `PushNode` is always non-empty.

---

## 6. Future Adapter Steps for Server Integration

1. **Workspace Registration**: Add `"crates/northstar-xep-0357"` to the root `Cargo.toml` workspace members list and remove `[workspace]` from `crates/northstar-xep-0357/Cargo.toml`.
2. **Import Replacement**: Replace internal push protocol types in `src/xmpp/protocol/misc.rs`, `src/services/push.rs`, and `src/db/push.rs` with `northstar_xep_0357::*`.
3. **Handler Adapter**: Refactor push IQ handlers to call `parse_enable()`, `parse_disable()`, and `iq_targets_own_account()` from this crate instead of local `parse_push_enable()`, `parse_push_disable()`, and `push_iq_targets_account()`.
4. **Notification Builder**: Replace inline XmlElement construction in `send_push_notification()` with `build_notification_iq()` and `PushSummary`.
5. **Disclosure Policy Integration**: Configure `DisclosurePolicy` from server configuration and apply it via `apply_disclosure_policy()` before generating notification payloads.
6. **Eligibility Integration**: Optionally use `evaluate_eligibility()` as a pre-filter in the message fanout path, replacing hardcoded offline/CSI checks.
